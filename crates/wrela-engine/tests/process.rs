#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

use wrela_build_model::{Sha256Digest, TargetIdentity};
use wrela_compiler::PipelineLimits;
use wrela_driver::engine::{
    CheckDiagnosticPolicy, CheckRequest, CheckRequestFields, CheckResponseStream, ClientHello,
    ENGINE_FRAME_HEADER_BYTES, EngineFrame, EngineMessage, EnginePath, EngineProtocolLimits,
    EngineResourcePolicy, ResponseStreamProgress, TerminalStatus, TreeMode, TreeRecord,
    decode_frame, decode_frame_header, empty_tree_measurement, encode_frame, measure_tree, sha256,
};
use wrela_package::{
    PackageIdentity, PackageLocator, PackageManifest, PackageName, PackageVersion,
};
use wrela_package_loader::{
    CanonicalPackageCodec, CanonicalTreeLimits, CanonicalTreeRecord, ContentHasher,
    LockfileCodecLimits, ManifestCodecLimits, PackageCodec, PackageContentKind,
    PackageContentRecord, SoftwareSha256, canonical_tree_digest, package_content_digest,
};
use wrela_toolchain::{
    CanonicalToolchainManifestCodec, ComponentKind, ComponentPath, REQUIRED_LLVM_PROJECT_REVISION,
    ShippedComponent, ShippedStandardLibraryPackage, ShippedTarget, ShippedTargetFile,
    TOOLCHAIN_MANIFEST_SCHEMA, ToolchainCompatibility, ToolchainManifest, ToolchainManifestCodec,
    current_host_identity,
};

const CORE_MANIFEST: &[u8] = include_bytes!("../../../std/wrela-core-0.1/wrela.toml");
const CORE_SOURCE: &[u8] = include_bytes!("../../../std/wrela-core-0.1/src/image.wr");
const CORE_RESULT_SOURCE: &[u8] = include_bytes!("../../../std/wrela-core-0.1/src/result.wr");
const CORE_TIME_SOURCE: &[u8] = include_bytes!("../../../std/wrela-core-0.1/src/time.wr");
const APPLICATION_MANIFEST: &[u8] =
    include_bytes!("../../../std/examples/minimal-image/wrela.toml");
const APPLICATION_SOURCE: &[u8] =
    include_bytes!("../../../std/examples/minimal-image/src/bootstrap/image.wr");
const APPLICATION_LOCKFILE: &[u8] =
    include_bytes!("../../../std/examples/minimal-image/wrela.lock");
const TARGET_MANIFEST: &[u8] =
    include_bytes!("../../../toolchain/targets/aarch64-qemu-virt-uefi/target.toml");
const BACKEND_BYTES: &[u8] = b"headless engine fixture backend";
const EMULATOR_BYTES: &[u8] = b"headless engine fixture emulator";
const FIRMWARE_CODE: &[u8] = b"headless engine fixture firmware";
const FIRMWARE_VARIABLES: &[u8] = b"headless engine fixture variables";
const RUNTIME_OBJECT: &[u8] = b"headless engine fixture runtime";
const MAX_FIXTURE_FILE_BYTES: usize = 1024 * 1024;

static HASHER: SoftwareSha256 = SoftwareSha256;
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
struct Identities {
    launcher: Sha256Digest,
    engine: Sha256Digest,
    payload: Sha256Digest,
}

struct CapturedRequest {
    request: CheckRequest,
    hello: ClientHello,
    frames: Vec<Vec<u8>>,
}

impl CapturedRequest {
    fn new(
        manifest: &[u8],
        lockfile: &[u8],
        source: &[u8],
        identities: Identities,
        nonce_byte: u8,
    ) -> Self {
        let limits = EngineProtocolLimits::standard();
        let files = [
            ("src/bootstrap/image.wr", source),
            ("wrela.lock", lockfile),
            ("wrela.toml", manifest),
        ];
        let records = files
            .iter()
            .map(|(path, bytes)| TreeRecord {
                path: EnginePath::new(*path).expect("portable captured path"),
                mode: TreeMode::Data,
                bytes: bytes.len() as u64,
                digest: digest(bytes),
            })
            .collect::<Vec<_>>();
        let input = measure_tree(&records, limits, &|| false).expect("captured tree measurement");
        let request = CheckRequest::seal(
            CheckRequestFields {
                engine_identity: identities.engine,
                payload_identity: identities.payload,
                manifest: EnginePath::new("wrela.toml").expect("manifest path"),
                lockfile: EnginePath::new("wrela.lock").expect("lockfile path"),
                image: "bootstrap".to_owned(),
                target: TargetIdentity::aarch64_qemu_virt_uefi(),
                profile: "development".to_owned(),
                diagnostics: CheckDiagnosticPolicy {
                    warnings_as_errors: false,
                    maximum_diagnostics: 100_000,
                },
                resources: EngineResourcePolicy {
                    comptime_steps: 1024,
                    comptime_memory_bytes: 1024 * 1024,
                    comptime_call_depth: 64,
                    ..EngineResourcePolicy::check_standard()
                },
                input,
            },
            limits,
            &|| false,
        )
        .expect("sealed captured request");
        let hello = ClientHello {
            launcher_identity: identities.launcher,
            payload_identity: identities.payload,
            nonce: [nonce_byte; 32],
        };
        let mut messages = vec![
            EngineMessage::ClientHello(hello),
            EngineMessage::RequestHeader(Box::new(request.clone())),
        ];
        for (index, ((_, bytes), record)) in files.iter().zip(&records).enumerate() {
            messages.push(EngineMessage::InputRecord {
                index: index as u32,
                record: record.clone(),
            });
            messages.push(EngineMessage::InputChunk {
                record: index as u32,
                offset: 0,
                bytes: bytes.to_vec(),
            });
        }
        messages.push(EngineMessage::InputFinish(input));
        let frames = messages
            .into_iter()
            .enumerate()
            .map(|(sequence, message)| {
                encode_frame(
                    &EngineFrame {
                        sequence: sequence as u64,
                        request_identity: request.identity(),
                        message,
                    },
                    limits,
                    &|| false,
                )
                .expect("captured request frame")
            })
            .collect();
        Self {
            request,
            hello,
            frames,
        }
    }

    fn bytes(&self) -> Vec<u8> {
        concatenate(&self.frames)
    }
}

#[test]
fn real_process_consumes_sealed_source_for_success_and_diagnostic_rejection() {
    let fixture = ProcessFixture::new();
    let current_lock = current_application_lockfile(APPLICATION_SOURCE);
    let passing = CapturedRequest::new(
        APPLICATION_MANIFEST,
        &current_lock,
        APPLICATION_SOURCE,
        fixture.identities,
        1,
    );
    let pass = fixture.run("pass", &passing.bytes(), fixture.identities);
    assert!(
        pass.status.success(),
        "passing process stderr: {:?}",
        pass.stderr
    );
    assert!(pass.stderr.is_empty());
    let pass_response = validate_response(&passing, &pass.stdout);
    assert_eq!(pass_response.status, TerminalStatus::Success);

    let invalid_source = b"module bootstrap.image\n\nthis is not valid Wrela source\n";
    let invalid_lock = current_application_lockfile(invalid_source);
    let rejected = CapturedRequest::new(
        APPLICATION_MANIFEST,
        &invalid_lock,
        invalid_source,
        fixture.identities,
        2,
    );
    let rejection = fixture.run("rejected", &rejected.bytes(), fixture.identities);
    assert!(
        rejection.status.success(),
        "rejected check is a valid transport response: {:?}",
        rejection.stderr
    );
    assert!(rejection.stderr.is_empty());
    let rejected_response = validate_response(&rejected, &rejection.stdout);
    assert_eq!(rejected_response.status, TerminalStatus::Rejected);
    assert!(rejected_response.messages.iter().any(|message| matches!(
        message,
        EngineMessage::Event(wrela_driver::engine::EngineEvent::Diagnostic {
            code,
            path: Some(path),
            line,
            column,
            ..
        }) if code == "syntax-unsupported-declaration"
            && path.as_str().ends_with("/src/bootstrap/image.wr")
            && *line > 0
            && *column > 0
    )));
}

#[test]
fn exact_request_bound_cancel_is_terminal_with_an_empty_output_tree() {
    let fixture = ProcessFixture::new();
    let lockfile = current_application_lockfile(APPLICATION_SOURCE);
    let captured = CapturedRequest::new(
        APPLICATION_MANIFEST,
        &lockfile,
        APPLICATION_SOURCE,
        fixture.identities,
        3,
    );
    let limits = EngineProtocolLimits::standard();
    let mut frames = captured.frames[..3].to_vec();
    frames.push(
        encode_frame(
            &EngineFrame {
                sequence: 3,
                request_identity: captured.request.identity(),
                message: EngineMessage::Cancel,
            },
            limits,
            &|| false,
        )
        .expect("request-bound cancellation frame"),
    );
    let cancelled = fixture.run("cancelled", &concatenate(&frames), fixture.identities);
    assert!(
        cancelled.status.success(),
        "cancel stderr: {:?}",
        cancelled.stderr
    );
    assert!(cancelled.stderr.is_empty());
    let response = validate_response(&captured, &cancelled.stdout);
    assert_eq!(response.status, TerminalStatus::Cancelled);
    let empty = empty_tree_measurement(&|| false).expect("empty output measurement");
    assert!(response.messages.iter().any(
        |message| matches!(message, EngineMessage::OutputHeader(measurement) if *measurement == empty)
    ));
    assert!(response.messages.iter().any(
        |message| matches!(message, EngineMessage::OutputFinish(measurement) if *measurement == empty)
    ));
    assert!(!response.messages.iter().any(|message| matches!(
        message,
        EngineMessage::OutputRecord { .. } | EngineMessage::OutputChunk { .. }
    )));
    assert_eq!(response.output_bytes, 0);
}

#[test]
fn process_rejects_nonnormalized_or_reordered_authority_arguments() {
    let fixture = ProcessFixture::new();
    let staging = fixture.root.join("argument-staging");
    fs::create_dir(&staging).expect("argument staging directory");
    #[cfg(unix)]
    {
        let mut permissions = fs::metadata(&staging)
            .expect("argument staging metadata")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&staging, permissions).expect("argument staging permissions");
    }
    let nonnormalized = staging.join("..").join("argument-staging");
    let mut arguments = engine_arguments(&nonnormalized, &fixture.toolchain, fixture.identities);
    let nonnormal = Command::new(&fixture.binary)
        .args(&arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run nonnormalized engine arguments");
    assert_eq!(nonnormal.status.code(), Some(2));
    assert!(nonnormal.stdout.is_empty());
    assert!(!nonnormal.stderr.is_empty());

    arguments.swap(0, 2);
    let reordered = Command::new(&fixture.binary)
        .args(&arguments)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run reordered engine arguments");
    assert_eq!(reordered.status.code(), Some(2));
    assert!(reordered.stdout.is_empty());
    assert!(!reordered.stderr.is_empty());
}

#[test]
#[cfg(not(all(target_os = "linux", target_arch = "aarch64", target_env = "musl")))]
fn direct_child_refuses_unsupported_host_before_argument_or_path_observation() {
    let binary = fs::canonicalize(env!("CARGO_BIN_EXE_wrela-engine"))
        .expect("engine process fixture binary");
    let output = Command::new(binary)
        .args([
            "direct-child",
            "--payload-authority",
            "/this/path/must/not/be-observed",
        ])
        .output()
        .expect("run unsupported direct child");
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).expect("bounded path-free stderr"),
        "wrela-engine: invalid normalized engine argument direct-child host\n"
    );
}

#[test]
fn corrupt_limit_version_sequence_and_identity_mutations_publish_no_response() {
    let fixture = ProcessFixture::new();
    let lockfile = current_application_lockfile(APPLICATION_SOURCE);
    let captured = CapturedRequest::new(
        APPLICATION_MANIFEST,
        &lockfile,
        APPLICATION_SOURCE,
        fixture.identities,
        4,
    );

    let mut mutations: Vec<(&str, Vec<u8>, Identities)> = Vec::new();

    let mut corrupt = captured.frames.clone();
    *corrupt[3].last_mut().expect("chunk payload") ^= 1;
    mutations.push(("corrupt-payload", concatenate(&corrupt), fixture.identities));

    let mut truncated = captured.bytes();
    truncated.pop().expect("nonempty request corpus");
    mutations.push(("truncated", truncated, fixture.identities));

    let mut oversized = captured.frames[0][..ENGINE_FRAME_HEADER_BYTES].to_vec();
    oversized[24..28]
        .copy_from_slice(&(EngineProtocolLimits::standard().frame_payload_bytes + 1).to_le_bytes());
    mutations.push(("oversized", oversized, fixture.identities));

    for (label, version) in [("stale-version", 0u32), ("future-version", 2u32)] {
        let mut frame = captured.frames[0].clone();
        frame[8..12].copy_from_slice(&version.to_le_bytes());
        mutations.push((label, frame, fixture.identities));
    }

    let mut sequence = captured.frames.clone();
    sequence[1][16..24].copy_from_slice(&7u64.to_le_bytes());
    mutations.push(("sequence", concatenate(&sequence), fixture.identities));

    let mut request_substitution = captured.frames.clone();
    request_substitution[2][28..60].copy_from_slice(digest(b"substituted request").as_bytes());
    mutations.push((
        "request-substitution",
        concatenate(&request_substitution),
        fixture.identities,
    ));

    let mut trailing = captured.bytes();
    trailing.push(0);
    mutations.push(("trailing-partial-header", trailing, fixture.identities));

    mutations.push((
        "launcher-substitution",
        captured.bytes(),
        Identities {
            launcher: digest(b"wrong launcher"),
            ..fixture.identities
        },
    ));
    mutations.push((
        "payload-substitution",
        captured.bytes(),
        Identities {
            payload: digest(b"wrong payload"),
            ..fixture.identities
        },
    ));
    mutations.push((
        "engine-argument-substitution",
        captured.bytes(),
        Identities {
            engine: digest(b"wrong engine argument"),
            ..fixture.identities
        },
    ));

    let wrong_request_identities = Identities {
        engine: digest(b"wrong request engine"),
        ..fixture.identities
    };
    let wrong_engine_request = CapturedRequest::new(
        APPLICATION_MANIFEST,
        &lockfile,
        APPLICATION_SOURCE,
        wrong_request_identities,
        5,
    );
    mutations.push((
        "request-engine-substitution",
        wrong_engine_request.bytes(),
        fixture.identities,
    ));

    let mut wrong_cancel = captured.frames[..3].to_vec();
    wrong_cancel.push(
        encode_frame(
            &EngineFrame {
                sequence: 3,
                request_identity: digest(b"wrong cancel request"),
                message: EngineMessage::Cancel,
            },
            EngineProtocolLimits::standard(),
            &|| false,
        )
        .expect("wrong-request cancellation frame"),
    );
    mutations.push((
        "cancel-request-substitution",
        concatenate(&wrong_cancel),
        fixture.identities,
    ));

    let mut duplicate_cancel = captured.frames.clone();
    duplicate_cancel.push(
        encode_frame(
            &EngineFrame {
                sequence: captured.frames.len() as u64,
                request_identity: captured.request.identity(),
                message: EngineMessage::Cancel,
            },
            EngineProtocolLimits::standard(),
            &|| false,
        )
        .expect("first pre-execution cancel"),
    );
    duplicate_cancel.push(
        encode_frame(
            &EngineFrame {
                sequence: captured.frames.len() as u64 + 1,
                request_identity: captured.request.identity(),
                message: EngineMessage::Cancel,
            },
            EngineProtocolLimits::standard(),
            &|| false,
        )
        .expect("duplicate pre-execution cancel"),
    );
    mutations.push((
        "duplicate-late-control",
        concatenate(&duplicate_cancel),
        fixture.identities,
    ));

    for (label, bytes, arguments) in mutations {
        let output = fixture.run(label, &bytes, arguments);
        assert!(
            !output.status.success(),
            "mutation {label} unexpectedly passed"
        );
        assert!(
            output.stdout.is_empty(),
            "mutation {label} published a partial response"
        );
        assert!(
            !output.stderr.is_empty() && output.stderr.len() < 2048,
            "mutation {label} did not produce one bounded process diagnostic"
        );
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains(&fixture.root.to_string_lossy()[..]),
            "mutation {label} leaked a private host path"
        );
    }
}

struct ParsedResponse {
    status: TerminalStatus,
    output_bytes: u64,
    messages: Vec<EngineMessage>,
}

fn validate_response(captured: &CapturedRequest, bytes: &[u8]) -> ParsedResponse {
    let limits = EngineProtocolLimits::standard();
    let frames = split_frames(bytes);
    let mut validator =
        CheckResponseStream::new(&captured.request, captured.hello, limits, &|| false)
            .expect("response validator");
    let mut progress = ResponseStreamProgress::Pending;
    let mut messages = Vec::new();
    for frame in &frames {
        progress = validator
            .accept(frame, &|| false)
            .expect("canonical response frame");
        messages.push(
            decode_frame(frame, limits, &|| false)
                .expect("decoded canonical response")
                .message,
        );
    }
    assert_eq!(progress, ResponseStreamProgress::Complete);
    assert!(validator.is_complete());
    let terminal = validator.terminal().expect("terminal response");
    ParsedResponse {
        status: terminal.status,
        output_bytes: terminal.usage.output_bytes,
        messages,
    }
}

fn split_frames(bytes: &[u8]) -> Vec<Vec<u8>> {
    let limits = EngineProtocolLimits::standard();
    let mut remaining = bytes;
    let mut frames = Vec::new();
    while !remaining.is_empty() {
        assert!(remaining.len() >= ENGINE_FRAME_HEADER_BYTES);
        let header =
            decode_frame_header(&remaining[..ENGINE_FRAME_HEADER_BYTES], limits, &|| false)
                .expect("canonical response header");
        let length =
            usize::try_from(header.encoded_frame_bytes()).expect("frame length fits usize");
        assert!(remaining.len() >= length);
        frames.push(remaining[..length].to_vec());
        remaining = &remaining[length..];
    }
    assert!(!frames.is_empty());
    frames
}

fn concatenate(frames: &[Vec<u8>]) -> Vec<u8> {
    let length = frames
        .iter()
        .try_fold(0usize, |total, frame| total.checked_add(frame.len()))
        .expect("fixture frame length");
    let mut bytes = Vec::with_capacity(length);
    for frame in frames {
        bytes.extend_from_slice(frame);
    }
    bytes
}

struct ProcessFixture {
    root: PathBuf,
    binary: PathBuf,
    toolchain: PathBuf,
    identities: Identities,
}

impl ProcessFixture {
    fn new() -> Self {
        let base = fs::canonicalize(std::env::temp_dir()).expect("canonical temporary directory");
        let root = (0..128)
            .find_map(|_| {
                let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let root = base.join(format!(
                    "wrela-engine-process-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&root) {
                    Ok(()) => Some(root),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                    Err(error) => panic!("create process fixture: {error}"),
                }
            })
            .expect("allocate process fixture root");
        let root = fs::canonicalize(root).expect("canonical process fixture root");
        let binary = fs::canonicalize(env!("CARGO_BIN_EXE_wrela-engine"))
            .expect("canonical real engine binary");
        let binary_bytes = fs::read(&binary).expect("real engine binary bytes");
        install_toolchain(&root, &binary_bytes);
        let toolchain = fs::canonicalize(root.join("toolchain")).expect("fixture toolchain root");
        Self {
            root,
            binary,
            toolchain,
            identities: Identities {
                launcher: digest(b"engine-process-launcher"),
                engine: digest(&binary_bytes),
                payload: digest(b"engine-process-payload"),
            },
        }
    }

    fn run(&self, label: &str, input: &[u8], identities: Identities) -> Output {
        let staging = self.root.join(format!("staging-{label}"));
        fs::create_dir(&staging).expect("private staging parent");
        #[cfg(unix)]
        {
            let mut permissions = fs::metadata(&staging)
                .expect("staging metadata")
                .permissions();
            permissions.set_mode(0o700);
            fs::set_permissions(&staging, permissions).expect("private staging permissions");
        }
        let staging = fs::canonicalize(staging).expect("canonical staging parent");
        let ambient = self.root.join("hostile-ambient");
        if !ambient.exists() {
            fs::create_dir(&ambient).expect("hostile ambient directory");
            fs::write(ambient.join("wrela.toml"), b"must never be discovered")
                .expect("hostile ambient manifest");
        }
        let arguments = engine_arguments(&staging, &self.toolchain, identities);
        let mut child = Command::new(&self.binary)
            .args(arguments)
            .current_dir(&ambient)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn real engine process");
        let write = child.stdin.take().expect("engine stdin").write_all(input);
        if let Err(error) = write {
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe,
                "write bounded request corpus"
            );
        }
        let output = child.wait_with_output().expect("reap real engine process");
        assert!(
            fs::read_dir(&staging)
                .expect("staging residue inventory")
                .next()
                .is_none(),
            "engine left request materialization residue for {label}"
        );
        output
    }
}

impl Drop for ProcessFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn engine_arguments(staging: &Path, toolchain: &Path, identities: Identities) -> Vec<OsString> {
    vec![
        OsString::from("--staging-parent"),
        staging.as_os_str().to_owned(),
        OsString::from("--toolchain-root"),
        toolchain.as_os_str().to_owned(),
        OsString::from("--launcher-sha256"),
        OsString::from(identities.launcher.to_hex()),
        OsString::from("--engine-sha256"),
        OsString::from(identities.engine.to_hex()),
        OsString::from("--payload-sha256"),
        OsString::from(identities.payload.to_hex()),
    ]
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    sha256(bytes, &|| false).expect("fixture digest")
}

fn current_core_identity() -> PackageIdentity {
    let codec = CanonicalPackageCodec::new();
    let core = codec
        .decode_manifest(CORE_MANIFEST, manifest_limits(), &|| false)
        .expect("checked-in core manifest");
    let canonical_manifest = codec
        .canonical_manifest(&core, manifest_limits(), &|| false)
        .expect("canonical core manifest");
    package_identity(
        &core,
        &canonical_manifest,
        &[
            ("image.wr", CORE_SOURCE),
            ("result.wr", CORE_RESULT_SOURCE),
            ("time.wr", CORE_TIME_SOURCE),
        ],
    )
}

fn current_application_lockfile(source: &[u8]) -> Vec<u8> {
    let codec = CanonicalPackageCodec::new();
    let limits = lockfile_limits();
    let mut lockfile = codec
        .decode_lockfile(APPLICATION_LOCKFILE, limits, &|| false)
        .expect("checked-in minimal-image lockfile");
    let core = current_core_identity();
    let application_digest = package_content_digest(
        APPLICATION_MANIFEST,
        &[PackageContentRecord {
            kind: PackageContentKind::Source,
            path: "bootstrap/image.wr",
            digest: HASHER.sha256(source),
        }],
        &HASHER,
        &|| false,
    )
    .expect("application source digest");
    lockfile.root.source_digest = application_digest;
    for package in &mut lockfile.packages {
        if package.identity.name == lockfile.root.name
            && package.identity.version == lockfile.root.version
        {
            package.identity.source_digest = application_digest;
        }
        if package.identity.name == core.name && package.identity.version == core.version {
            package.identity.source_digest = core.source_digest;
        }
        for dependency in &mut package.dependencies {
            if dependency.identity.name == core.name && dependency.identity.version == core.version
            {
                dependency.identity.source_digest = core.source_digest;
            }
        }
    }
    codec
        .canonical_lockfile(&lockfile, limits, &|| false)
        .expect("canonical application lockfile")
}

fn install_toolchain(root: &Path, frontend_bytes: &[u8]) {
    let write = |relative: &str, bytes: &[u8]| {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("toolchain fixture parent");
        }
        fs::write(&path, bytes).expect("toolchain fixture write");
        path
    };
    let core_identity = current_core_identity();
    write(
        "toolchain/share/wrela/std/wrela-core-0.1/wrela.toml",
        CORE_MANIFEST,
    );
    write(
        "toolchain/share/wrela/std/wrela-core-0.1/src/image.wr",
        CORE_SOURCE,
    );
    write(
        "toolchain/share/wrela/std/wrela-core-0.1/src/result.wr",
        CORE_RESULT_SOURCE,
    );
    write(
        "toolchain/share/wrela/std/wrela-core-0.1/src/time.wr",
        CORE_TIME_SOURCE,
    );
    let frontend = write(&format!("toolchain/{}", frontend_path()), frontend_bytes);
    let backend = write(&format!("toolchain/{}", backend_path()), BACKEND_BYTES);
    let emulator = write(&format!("toolchain/{}", emulator_path()), EMULATOR_BYTES);
    set_executable(&frontend);
    set_executable(&backend);
    set_executable(&emulator);

    let target_root = "toolchain/share/wrela/targets/aarch64-qemu-virt-uefi";
    write(&format!("{target_root}/target.toml"), TARGET_MANIFEST);
    write(
        &format!("{target_root}/firmware/QEMU_EFI.fd"),
        FIRMWARE_CODE,
    );
    write(
        &format!("{target_root}/firmware/QEMU_VARS.fd"),
        FIRMWARE_VARIABLES,
    );
    write(
        &format!("{target_root}/runtime/wrela-runtime-aarch64.obj"),
        RUNTIME_OBJECT,
    );

    let standard_library = tree_measurement(&[
        tree_record("wrela-core-0.1/src/image.wr", CORE_SOURCE),
        tree_record("wrela-core-0.1/src/result.wr", CORE_RESULT_SOURCE),
        tree_record("wrela-core-0.1/src/time.wr", CORE_TIME_SOURCE),
        tree_record("wrela-core-0.1/wrela.toml", CORE_MANIFEST),
    ]);
    let target = tree_measurement(&[
        tree_record("firmware/QEMU_EFI.fd", FIRMWARE_CODE),
        tree_record("firmware/QEMU_VARS.fd", FIRMWARE_VARIABLES),
        tree_record("runtime/wrela-runtime-aarch64.obj", RUNTIME_OBJECT),
        tree_record("target.toml", TARGET_MANIFEST),
    ]);
    let target_path = "share/wrela/targets/aarch64-qemu-virt-uefi";
    let manifest = ToolchainManifest {
        schema: TOOLCHAIN_MANIFEST_SCHEMA,
        release: "0.1.0-engine-process-test".to_owned(),
        host: current_host_identity()
            .expect("supported engine host")
            .to_owned(),
        llvm_project_revision: REQUIRED_LLVM_PROJECT_REVISION.to_owned(),
        compatibility: ToolchainCompatibility::current(),
        standard_library_packages: vec![ShippedStandardLibraryPackage {
            identity: core_identity,
            locator: PackageLocator::Toolchain {
                component: "wrela-core-0.1".to_owned(),
            },
            manifest_digest: HASHER.sha256(CORE_MANIFEST),
        }],
        components: vec![
            shipped_component(ComponentKind::Frontend, frontend_path(), frontend_bytes),
            shipped_component(ComponentKind::Backend, backend_path(), BACKEND_BYTES),
            ShippedComponent {
                kind: ComponentKind::StandardLibrary,
                path: ComponentPath::new("share/wrela/std").expect("standard-library path"),
                digest: standard_library.digest,
                bytes: standard_library.content_bytes,
            },
            shipped_component(
                ComponentKind::Aarch64Emulator,
                emulator_path(),
                EMULATOR_BYTES,
            ),
        ],
        targets: vec![ShippedTarget {
            identity: TargetIdentity::aarch64_qemu_virt_uefi(),
            path: ComponentPath::new(target_path).expect("target path"),
            digest: target.digest,
            bytes: target.content_bytes,
            files: vec![
                shipped_target_file("firmware/QEMU_EFI.fd", FIRMWARE_CODE),
                shipped_target_file("firmware/QEMU_VARS.fd", FIRMWARE_VARIABLES),
                shipped_target_file("runtime/wrela-runtime-aarch64.obj", RUNTIME_OBJECT),
            ],
        }],
    };
    let bytes = CanonicalToolchainManifestCodec::new()
        .encode_canonical(
            &manifest,
            PipelineLimits::standard().toolchain_decode,
            &|| false,
        )
        .expect("canonical fixture toolchain manifest");
    write("toolchain/share/wrela/toolchain.toml", &bytes);
}

fn package_identity(
    manifest: &PackageManifest,
    manifest_bytes: &[u8],
    sources: &[(&str, &[u8])],
) -> PackageIdentity {
    let mut records = sources
        .iter()
        .map(|(path, bytes)| PackageContentRecord {
            kind: PackageContentKind::Source,
            path,
            digest: HASHER.sha256(bytes),
        })
        .collect::<Vec<_>>();
    records.sort_by_key(|record| (record.kind, record.path));
    let source_digest = package_content_digest(manifest_bytes, &records, &HASHER, &|| false)
        .expect("canonical package digest");
    PackageIdentity {
        name: PackageName::new(manifest.name.as_str()).expect("package name"),
        version: PackageVersion::new(manifest.version.as_str()).expect("package version"),
        source_digest,
    }
}

fn shipped_component(kind: ComponentKind, path: &str, bytes: &[u8]) -> ShippedComponent {
    ShippedComponent {
        kind,
        path: ComponentPath::new(path).expect("component path"),
        digest: HASHER.sha256(bytes),
        bytes: bytes.len() as u64,
    }
}

fn shipped_target_file(path: &str, bytes: &[u8]) -> ShippedTargetFile {
    ShippedTargetFile {
        path: ComponentPath::new(path).expect("target file path"),
        digest: HASHER.sha256(bytes),
        bytes: bytes.len() as u64,
    }
}

fn tree_record<'a>(path: &'a str, bytes: &[u8]) -> CanonicalTreeRecord<'a> {
    CanonicalTreeRecord {
        path,
        bytes: bytes.len() as u64,
        digest: HASHER.sha256(bytes),
    }
}

fn tree_measurement(
    records: &[CanonicalTreeRecord<'_>],
) -> wrela_package_loader::CanonicalTreeMeasurement {
    canonical_tree_digest(records, &HASHER, CanonicalTreeLimits::standard(), &|| false)
        .expect("canonical tree measurement")
}

fn manifest_limits() -> ManifestCodecLimits {
    ManifestCodecLimits {
        bytes: MAX_FIXTURE_FILE_BYTES as u64,
        string_bytes: MAX_FIXTURE_FILE_BYTES as u64,
        modules: 16,
        dependencies: 16,
        profiles: 16,
        images: 16,
        image_tests: 16,
    }
}

fn lockfile_limits() -> LockfileCodecLimits {
    LockfileCodecLimits {
        bytes: MAX_FIXTURE_FILE_BYTES as u64,
        string_bytes: MAX_FIXTURE_FILE_BYTES as u64,
        packages: 16,
        dependencies: 16,
    }
}

#[cfg(windows)]
const fn frontend_path() -> &'static str {
    "bin/wrela.exe"
}

#[cfg(not(windows))]
const fn frontend_path() -> &'static str {
    "bin/wrela"
}

#[cfg(windows)]
const fn backend_path() -> &'static str {
    "libexec/wrela/wrela-backend.exe"
}

#[cfg(not(windows))]
const fn backend_path() -> &'static str {
    "libexec/wrela/wrela-backend"
}

#[cfg(windows)]
const fn emulator_path() -> &'static str {
    "libexec/wrela/qemu-system-aarch64.exe"
}

#[cfg(not(windows))]
const fn emulator_path() -> &'static str {
    "libexec/wrela/qemu-system-aarch64"
}

#[cfg(unix)]
fn set_executable(path: &Path) {
    let mut permissions = fs::metadata(path)
        .expect("executable metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("executable permissions");
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) {}
