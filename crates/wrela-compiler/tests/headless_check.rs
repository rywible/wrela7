#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use wrela_build_model::{Sha256Digest, TargetIdentity};
use wrela_compiler::{
    HeadlessCheckError, HeadlessCheckExecutor, HeadlessCheckFrameStreamError,
    HeadlessCheckResponse, LateCancelDisposition, PipelineLimits,
};
use wrela_driver::engine::{
    CheckDiagnosticPolicy, CheckRequest, CheckRequestFields, CheckResponseStream, ClientHello,
    EngineFrame, EngineMessage, EnginePath, EngineProtocolLimits, EngineResourcePolicy,
    RequestStreamProgress, ResponseStreamProgress, TerminalStatus, TreeMode, TreeRecord,
    encode_frame, measure_tree, sha256,
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
    TOOLCHAIN_MANIFEST_SCHEMA, Toolchain, ToolchainCompatibility, ToolchainManifest,
    ToolchainManifestCodec, current_host_identity,
};

const CORE_MANIFEST: &[u8] = include_bytes!("../../../std/wrela-core-0.1/wrela.toml");
const CORE_SOURCE: &[u8] = include_bytes!("../../../std/wrela-core-0.1/src/image.wr");
const CORE_OPS_SOURCE: &[u8] = include_bytes!("../../../std/wrela-core-0.1/src/ops.wr");
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
const BACKEND_BYTES: &[u8] = b"headless check fixture backend";
const RUNTIME_OBJECT: &[u8] = b"headless check fixture runtime";
const MAX_FIXTURE_FILE_BYTES: usize = 1024 * 1024;

static HASHER: SoftwareSha256 = SoftwareSha256;
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

fn exact_resources() -> EngineResourcePolicy {
    EngineResourcePolicy {
        comptime_steps: 1024,
        comptime_memory_bytes: 1024 * 1024,
        comptime_call_depth: 64,
        ..EngineResourcePolicy::check_standard()
    }
}

fn install_current_toolchain(fixture: &TestDirectory) -> Toolchain {
    let frontend = fs::read(std::env::current_exe().expect("headless test executable path"))
        .expect("read headless test executable");
    install_toolchain(fixture, &frontend);
    Toolchain::at(fixture.root.join("toolchain"))
}

#[test]
fn real_headless_workspace_accepts_the_exact_declared_comptime_bound_deterministically() {
    let fixture = TestDirectory::new();
    let toolchain = install_current_toolchain(&fixture);
    let staging = fixture.private_directory("staging");
    let identities = Identities::new();
    let lockfile = current_application_lockfile(APPLICATION_SOURCE);
    let passing = CapturedRequest::new(
        APPLICATION_MANIFEST,
        &lockfile,
        APPLICATION_SOURCE,
        exact_resources(),
        identities,
        1,
    );
    let first = execute_captured(&staging, toolchain.clone(), &passing, &|| false);
    let second = execute_captured(&staging, toolchain, &passing, &|| false);
    assert_eq!(first.terminal().status, TerminalStatus::Success);
    assert_eq!(first, second);
    assert_eq!(
        first
            .encode_frames(EngineProtocolLimits::standard(), &|| false)
            .expect("first canonical response bytes"),
        second
            .encode_frames(EngineProtocolLimits::standard(), &|| false)
            .expect("second canonical response bytes")
    );
    let expected = first
        .encode_frames(EngineProtocolLimits::standard(), &|| false)
        .expect("aggregated response frames");
    let mut streamed = Vec::new();
    first
        .stream_encoded_frames(EngineProtocolLimits::standard(), &|| false, |frame| {
            streamed.push(frame);
            Ok::<(), ()>(())
        })
        .expect("streamed response frames");
    assert_eq!(streamed, expected);

    let mut delivered = 0u32;
    let stopped = first.stream_encoded_frames(EngineProtocolLimits::standard(), &|| false, |_| {
        delivered += 1;
        Err("sink stopped")
    });
    assert!(matches!(
        stopped,
        Err(HeadlessCheckFrameStreamError::Sink("sink stopped"))
    ));
    assert_eq!(delivered, 1);
    assert!(first.terminal().usage.comptime.is_none());
}

#[test]
fn frozen_minimal_image_lockfile_matches_the_derived_current_identity_exactly() {
    let derived = current_application_lockfile(APPLICATION_SOURCE);
    assert_eq!(derived, APPLICATION_LOCKFILE);
    assert_eq!(
        digest(&derived).to_hex(),
        "29ebae766554f7cff30229a4b21f28a9cf8d3ec8b3bc7adaf75b90050c690ceb"
    );
}

#[test]
fn real_headless_source_rejection_retains_stable_source_location() {
    let fixture = TestDirectory::new();
    let toolchain = install_current_toolchain(&fixture);
    let staging = fixture.private_directory("staging");
    let identities = Identities::new();
    let invalid_source = b"module bootstrap.image\n\nthis is not valid Wrela source\n";
    let lockfile = current_application_lockfile(invalid_source);
    let rejected = CapturedRequest::new(
        APPLICATION_MANIFEST,
        &lockfile,
        invalid_source,
        exact_resources(),
        identities,
        2,
    );
    let first = execute_captured(&staging, toolchain.clone(), &rejected, &|| false);
    let second = execute_captured(&staging, toolchain, &rejected, &|| false);
    assert_eq!(first.terminal().status, TerminalStatus::Rejected);
    assert_eq!(first, second);
    assert_eq!(
        first
            .encode_frames(EngineProtocolLimits::standard(), &|| false)
            .expect("first rejection response bytes"),
        second
            .encode_frames(EngineProtocolLimits::standard(), &|| false)
            .expect("second rejection response bytes")
    );
    let diagnostic = first
        .events()
        .iter()
        .find_map(|event| match event {
            wrela_driver::engine::EngineEvent::Diagnostic {
                code,
                path,
                line,
                column,
                ..
            } => Some((code, path, line, column)),
            _ => None,
        })
        .expect("source rejection diagnostic");
    assert_eq!(diagnostic.0, "syntax-unsupported-declaration");
    assert_eq!(
        diagnostic
            .1
            .as_ref()
            .expect("portable source path")
            .as_str(),
        qualified_application_source_path(invalid_source)
    );
    assert!(*diagnostic.2 > 0 && *diagnostic.3 > 0);
}

#[test]
fn callback_cancellation_returns_a_canonical_terminal_without_toolchain_io() {
    let fixture = TestDirectory::new();
    let staging = fixture.private_directory("staging");
    let identities = Identities::new();
    let lockfile = current_application_lockfile(APPLICATION_SOURCE);
    let cancelled = CapturedRequest::new(
        APPLICATION_MANIFEST,
        &lockfile,
        APPLICATION_SOURCE,
        exact_resources(),
        identities,
        3,
    );
    let response = execute_captured(
        &staging,
        Toolchain::at(fixture.root.join("toolchain-that-must-not-be-read")),
        &cancelled,
        &|| true,
    );
    assert_eq!(response.terminal().status, TerminalStatus::Cancelled);
}

#[test]
fn sealed_execution_and_exact_late_cancel_control_are_independent() {
    let fixture = TestDirectory::new();
    let staging = fixture.private_directory("staging");
    let identities = Identities::new();
    let lockfile = current_application_lockfile(APPLICATION_SOURCE);
    let captured = CapturedRequest::new(
        APPLICATION_MANIFEST,
        &lockfile,
        APPLICATION_SOURCE,
        exact_resources(),
        identities,
        6,
    );
    let limits = EngineProtocolLimits::standard();
    let mut executor = HeadlessCheckExecutor::new(
        &staging,
        Toolchain::at(fixture.root.join("toolchain-that-must-not-be-read")),
        identities.launcher,
        identities.engine,
        identities.payload,
        PipelineLimits::standard(),
        limits,
    )
    .expect("headless executor");
    for frame in &captured.frames {
        executor
            .accept_request_frame(frame, &|| false)
            .expect("complete captured request");
    }
    let (execution, mut control) = executor
        .into_execution()
        .expect("split sealed execution and late control");
    assert!(!control.is_cancelled());
    let cancel = encode_frame(
        &EngineFrame {
            sequence: captured.frames.len() as u64,
            request_identity: captured.request.identity(),
            message: EngineMessage::Cancel,
        },
        limits,
        &|| false,
    )
    .expect("exact late cancel frame");
    assert_eq!(
        control
            .accept_cancel_frame(&cancel, &|| false)
            .expect("validated late cancel"),
        LateCancelDisposition::Requested
    );
    assert!(control.is_cancelled());
    let response = execution
        .execute(&|| false)
        .expect("late-cancelled execution response");
    assert_eq!(response.terminal().status, TerminalStatus::Cancelled);
    assert!(control.is_cancelled());
    validate_response(&captured, &response);
    assert!(
        fs::read_dir(staging)
            .expect("private staging inventory")
            .next()
            .is_none()
    );
}

#[test]
fn one_step_below_the_declared_profile_bound_is_a_resource_limit() {
    let fixture = TestDirectory::new();
    let staging = fixture.private_directory("staging");
    let identities = Identities::new();
    let lockfile = current_application_lockfile(APPLICATION_SOURCE);
    let exact = exact_resources();
    let over_bound = CapturedRequest::new(
        APPLICATION_MANIFEST,
        &lockfile,
        APPLICATION_SOURCE,
        EngineResourcePolicy {
            comptime_steps: exact.comptime_steps - 1,
            ..exact
        },
        identities,
        4,
    );
    let response = execute_captured(
        &staging,
        Toolchain::at(fixture.root.join("toolchain-that-must-not-be-read")),
        &over_bound,
        &|| false,
    );
    assert_eq!(response.terminal().status, TerminalStatus::ResourceLimit);
}

#[test]
fn deliberately_stale_canonical_lockfile_fails_closed_as_workspace_input() {
    let fixture = TestDirectory::new();
    let toolchain = install_current_toolchain(&fixture);
    let staging = fixture.private_directory("staging");
    let identities = Identities::new();
    let stale_lockfile = deliberately_stale_application_lockfile(APPLICATION_SOURCE);
    let captured = CapturedRequest::new(
        APPLICATION_MANIFEST,
        &stale_lockfile,
        APPLICATION_SOURCE,
        exact_resources(),
        identities,
        5,
    );
    let response = execute_captured(&staging, toolchain, &captured, &|| false);
    assert_eq!(response.terminal().status, TerminalStatus::Rejected);
    let diagnostic = response
        .events()
        .iter()
        .find_map(|event| match event {
            wrela_driver::engine::EngineEvent::Diagnostic {
                code,
                path,
                line,
                column,
                ..
            } => Some((code, path, line, column)),
            _ => None,
        })
        .expect("stale lockfile diagnostic");
    assert_eq!(diagnostic.0, "engine-workspace-input");
    assert!(diagnostic.1.is_none());
    assert_eq!((*diagnostic.2, *diagnostic.3), (0, 0));
}

#[test]
fn mid_input_protocol_cancel_discards_partial_tree_and_returns_canonical_terminal() {
    let fixture = TestDirectory::new();
    let staging = fixture.private_directory("staging");
    let identities = Identities::new();
    let lockfile = current_application_lockfile(APPLICATION_SOURCE);
    let captured = CapturedRequest::new(
        APPLICATION_MANIFEST,
        &lockfile,
        APPLICATION_SOURCE,
        EngineResourcePolicy::check_standard(),
        identities,
        9,
    );
    let limits = EngineProtocolLimits::standard();
    let mut executor = HeadlessCheckExecutor::new(
        &staging,
        Toolchain::at(fixture.root.join("toolchain-that-must-not-be-read")),
        identities.launcher,
        identities.engine,
        identities.payload,
        PipelineLimits::standard(),
        limits,
    )
    .expect("headless executor");
    for frame in &captured.frames[..3] {
        assert_eq!(
            executor
                .accept_request_frame(frame, &|| false)
                .expect("request prefix"),
            RequestStreamProgress::Pending
        );
    }
    let cancel = encode_frame(
        &EngineFrame {
            sequence: 3,
            request_identity: captured.request.identity(),
            message: EngineMessage::Cancel,
        },
        limits,
        &|| false,
    )
    .expect("cancel frame");
    assert_eq!(
        executor
            .accept_request_frame(&cancel, &|| false)
            .expect("accepted cancel"),
        RequestStreamProgress::Cancelled
    );
    let response = executor
        .execute(&|| false)
        .expect("canonical cancellation response");
    assert_eq!(response.terminal().status, TerminalStatus::Cancelled);
    assert!(response.events().is_empty());
    validate_response(&captured, &response);
    assert!(
        fs::read_dir(staging)
            .expect("private staging inventory")
            .next()
            .is_none()
    );
}

#[test]
fn corrupt_input_frame_poisoning_cleans_the_partial_private_tree() {
    let fixture = TestDirectory::new();
    let staging = fixture.private_directory("staging");
    let identities = Identities::new();
    let lockfile = current_application_lockfile(APPLICATION_SOURCE);
    let captured = CapturedRequest::new(
        APPLICATION_MANIFEST,
        &lockfile,
        APPLICATION_SOURCE,
        exact_resources(),
        identities,
        10,
    );
    let mut executor = HeadlessCheckExecutor::new(
        &staging,
        Toolchain::at(fixture.root.join("toolchain-that-must-not-be-read")),
        identities.launcher,
        identities.engine,
        identities.payload,
        PipelineLimits::standard(),
        EngineProtocolLimits::standard(),
    )
    .expect("headless executor");
    for frame in &captured.frames[..3] {
        executor
            .accept_request_frame(frame, &|| false)
            .expect("request prefix");
    }
    let mut corrupt = captured.frames[3].clone();
    let last = corrupt.last_mut().expect("nonempty chunk frame");
    *last ^= 0x01;
    assert!(matches!(
        executor.accept_request_frame(&corrupt, &|| false),
        Err(HeadlessCheckError::Protocol(
            wrela_driver::engine::EngineProtocolError::PayloadDigestMismatch
        ))
    ));
    drop(executor);
    assert!(
        fs::read_dir(staging)
            .expect("private staging inventory")
            .next()
            .is_none()
    );
}

#[cfg(unix)]
#[test]
fn staging_root_must_be_engine_private() {
    let fixture = TestDirectory::new();
    let identities = Identities::new();
    for (name, mode) in [
        ("world-staging", 0o755),
        ("group-staging", 0o750),
        ("read-staging", 0o500),
    ] {
        let staging = fixture.root.join(name);
        fs::create_dir(&staging).expect("nonprivate staging directory");
        let mut permissions = fs::metadata(&staging)
            .expect("nonprivate metadata")
            .permissions();
        permissions.set_mode(mode);
        fs::set_permissions(&staging, permissions).expect("nonprivate permissions");
        assert!(matches!(
            HeadlessCheckExecutor::new(
                fs::canonicalize(staging).expect("canonical nonprivate staging"),
                Toolchain::at(fixture.root.join("unused-toolchain")),
                identities.launcher,
                identities.engine,
                identities.payload,
                PipelineLimits::standard(),
                EngineProtocolLimits::standard(),
            ),
            Err(HeadlessCheckError::InvalidStagingRoot(_))
        ));
    }
}

fn execute_captured(
    staging: &Path,
    toolchain: Toolchain,
    captured: &CapturedRequest,
    execute_cancelled: &dyn Fn() -> bool,
) -> HeadlessCheckResponse {
    let limits = EngineProtocolLimits::standard();
    let mut executor = HeadlessCheckExecutor::new(
        staging,
        toolchain,
        captured.identities.launcher,
        captured.identities.engine,
        captured.identities.payload,
        PipelineLimits::standard(),
        limits,
    )
    .expect("headless executor");
    for frame in &captured.frames {
        executor
            .accept_request_frame(frame, &|| false)
            .expect("validated captured request frame");
    }
    let response = executor
        .execute(execute_cancelled)
        .expect("canonical headless response");
    assert_eq!(
        validate_response(captured, &response),
        response.terminal().status
    );
    response
}

fn validate_response(
    captured: &CapturedRequest,
    response: &HeadlessCheckResponse,
) -> TerminalStatus {
    let limits = EngineProtocolLimits::standard();
    let mut validator =
        CheckResponseStream::new(&captured.request, captured.hello, limits, &|| false)
            .expect("response validator");
    let frames = response
        .encode_frames(limits, &|| false)
        .expect("canonical response frames");
    let mut progress = ResponseStreamProgress::Pending;
    for frame in frames {
        progress = validator
            .accept(&frame, &|| false)
            .expect("validated headless response frame");
    }
    assert_eq!(progress, ResponseStreamProgress::Complete);
    validator.terminal().expect("terminal response").status
}

#[derive(Clone, Copy)]
struct Identities {
    launcher: Sha256Digest,
    engine: Sha256Digest,
    payload: Sha256Digest,
}

impl Identities {
    fn new() -> Self {
        Self {
            launcher: digest(b"headless-test-launcher"),
            engine: digest(b"headless-test-engine"),
            payload: digest(b"headless-test-payload"),
        }
    }
}

struct CapturedRequest {
    request: CheckRequest,
    hello: ClientHello,
    identities: Identities,
    frames: Vec<Vec<u8>>,
}

impl CapturedRequest {
    fn new(
        manifest: &[u8],
        lockfile: &[u8],
        source: &[u8],
        resources: EngineResourcePolicy,
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
                lockfile: EnginePath::new("wrela.lock").expect("lock path"),
                image: "bootstrap".to_owned(),
                target: TargetIdentity::aarch64_qemu_virt_uefi(),
                profile: "development".to_owned(),
                diagnostics: CheckDiagnosticPolicy {
                    warnings_as_errors: false,
                    maximum_diagnostics: 100_000,
                },
                resources,
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
            identities,
            frames,
        }
    }
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    sha256(bytes, &|| false).expect("fixture digest")
}

#[derive(Debug)]
struct TestDirectory {
    root: PathBuf,
}

impl TestDirectory {
    fn new() -> Self {
        let base = fs::canonicalize(std::env::temp_dir()).expect("canonical temporary directory");
        for _ in 0..128 {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let root = base.join(format!(
                "wrela-headless-check-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => {
                    return Self {
                        root: fs::canonicalize(root).expect("canonical fixture root"),
                    };
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("cannot create headless-check fixture: {error}"),
            }
        }
        panic!("cannot allocate headless-check fixture")
    }

    fn write(&self, relative: &str, bytes: &[u8]) -> PathBuf {
        assert!(bytes.len() <= MAX_FIXTURE_FILE_BYTES);
        self.write_trusted(relative, bytes)
    }

    fn write_trusted(&self, relative: &str, bytes: &[u8]) -> PathBuf {
        let path = self.root.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("fixture parent directory");
        }
        fs::write(&path, bytes).expect("bounded fixture write");
        path
    }

    fn private_directory(&self, relative: &str) -> PathBuf {
        let path = self.root.join(relative);
        fs::create_dir(&path).expect("private staging directory");
        #[cfg(unix)]
        {
            let mut permissions = fs::metadata(&path).expect("staging metadata").permissions();
            permissions.set_mode(0o700);
            fs::set_permissions(&path, permissions).expect("private staging permissions");
        }
        fs::canonicalize(path).expect("canonical staging path")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Re-encode a checked-in manifest to its canonical bytes. These fixtures
/// declare only `[[profile]]` overrides and no `[[module]]` block (modules
/// are derived, not decoded), so they are not necessarily byte-canonical
/// themselves; every package or manifest digest must bind the same
/// canonical bytes the production loader hashes, never the raw checked-in
/// TOML.
fn canonical_manifest_bytes(raw: &[u8]) -> Vec<u8> {
    let codec = CanonicalPackageCodec::new();
    let manifest = codec
        .decode_manifest(raw, manifest_limits(), &|| false)
        .expect("checked-in manifest");
    codec
        .canonical_manifest(&manifest, manifest_limits(), &|| false)
        .expect("canonical manifest identity bytes")
}

fn current_core_identity() -> PackageIdentity {
    let codec = CanonicalPackageCodec::new();
    let core = codec
        .decode_manifest(CORE_MANIFEST, manifest_limits(), &|| false)
        .expect("checked-in core manifest");
    let canonical_core_manifest = canonical_manifest_bytes(CORE_MANIFEST);
    package_identity(
        &core,
        &canonical_core_manifest,
        &[
            ("image.wr", CORE_SOURCE),
            ("ops.wr", CORE_OPS_SOURCE),
            ("result.wr", CORE_RESULT_SOURCE),
            ("time.wr", CORE_TIME_SOURCE),
        ],
    )
}

fn current_application_lockfile(source: &[u8]) -> Vec<u8> {
    let codec = CanonicalPackageCodec::new();
    let limits = LockfileCodecLimits {
        bytes: MAX_FIXTURE_FILE_BYTES as u64,
        string_bytes: MAX_FIXTURE_FILE_BYTES as u64,
        packages: 16,
        dependencies: 16,
    };
    let mut lockfile = codec
        .decode_lockfile(APPLICATION_LOCKFILE, limits, &|| false)
        .expect("checked-in application lockfile");
    let core = current_core_identity();
    let application_digest = application_source_digest(source);
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
    let bytes = codec
        .canonical_lockfile(&lockfile, limits, &|| false)
        .expect("current canonical application lockfile");
    let decoded = codec
        .decode_lockfile(&bytes, limits, &|| false)
        .expect("decode derived application lockfile");
    assert_eq!(
        codec
            .canonical_lockfile(&decoded, limits, &|| false)
            .expect("re-encode derived application lockfile"),
        bytes
    );
    bytes
}

fn deliberately_stale_application_lockfile(source: &[u8]) -> Vec<u8> {
    let codec = CanonicalPackageCodec::new();
    let limits = LockfileCodecLimits {
        bytes: MAX_FIXTURE_FILE_BYTES as u64,
        string_bytes: MAX_FIXTURE_FILE_BYTES as u64,
        packages: 16,
        dependencies: 16,
    };
    let current = current_application_lockfile(source);
    let mut lockfile = codec
        .decode_lockfile(&current, limits, &|| false)
        .expect("current application lockfile");
    let stale = digest(b"deliberately stale application source identity");
    lockfile.root.source_digest = stale;
    for package in &mut lockfile.packages {
        if package.identity.name == lockfile.root.name
            && package.identity.version == lockfile.root.version
        {
            package.identity.source_digest = stale;
        }
    }
    let bytes = codec
        .canonical_lockfile(&lockfile, limits, &|| false)
        .expect("deliberately stale canonical lockfile");
    assert_eq!(
        codec
            .canonical_lockfile(
                &codec
                    .decode_lockfile(&bytes, limits, &|| false)
                    .expect("decode deliberately stale lockfile"),
                limits,
                &|| false,
            )
            .expect("re-encode deliberately stale lockfile"),
        bytes
    );
    bytes
}

fn application_source_digest(source: &[u8]) -> Sha256Digest {
    package_content_digest(
        &canonical_manifest_bytes(APPLICATION_MANIFEST),
        &[PackageContentRecord {
            kind: PackageContentKind::Source,
            path: "bootstrap/image.wr",
            digest: HASHER.sha256(source),
        }],
        &HASHER,
        &|| false,
    )
    .expect("application source identity")
}

fn qualified_application_source_path(source: &[u8]) -> String {
    format!(
        "packages/{}/{}/{}/src/bootstrap/image.wr",
        hex(b"bootstrap-image"),
        hex(b"0.1.0"),
        application_source_digest(source).to_hex()
    )
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn install_toolchain(directory: &TestDirectory, frontend_bytes: &[u8]) {
    let core_identity = current_core_identity();
    directory.write(
        "toolchain/share/wrela/std/wrela-core-0.1/wrela.toml",
        CORE_MANIFEST,
    );
    directory.write(
        "toolchain/share/wrela/std/wrela-core-0.1/src/image.wr",
        CORE_SOURCE,
    );
    directory.write(
        "toolchain/share/wrela/std/wrela-core-0.1/src/ops.wr",
        CORE_OPS_SOURCE,
    );
    directory.write(
        "toolchain/share/wrela/std/wrela-core-0.1/src/result.wr",
        CORE_RESULT_SOURCE,
    );
    directory.write(
        "toolchain/share/wrela/std/wrela-core-0.1/src/time.wr",
        CORE_TIME_SOURCE,
    );

    let frontend =
        directory.write_trusted(&format!("toolchain/{}", frontend_path()), frontend_bytes);
    let backend = directory.write(&format!("toolchain/{}", backend_path()), BACKEND_BYTES);
    set_executable(&frontend);
    set_executable(&backend);

    let target_root = "toolchain/share/wrela/targets/aarch64-qemu-virt-uefi";
    directory.write(&format!("{target_root}/target.toml"), TARGET_MANIFEST);
    directory.write(
        &format!("{target_root}/runtime/wrela-runtime-aarch64.obj"),
        RUNTIME_OBJECT,
    );

    let standard_library = tree_measurement(&[
        tree_record("wrela-core-0.1/src/image.wr", CORE_SOURCE),
        tree_record("wrela-core-0.1/src/ops.wr", CORE_OPS_SOURCE),
        tree_record("wrela-core-0.1/src/result.wr", CORE_RESULT_SOURCE),
        tree_record("wrela-core-0.1/src/time.wr", CORE_TIME_SOURCE),
        tree_record("wrela-core-0.1/wrela.toml", CORE_MANIFEST),
    ]);
    let target = tree_measurement(&[
        tree_record("runtime/wrela-runtime-aarch64.obj", RUNTIME_OBJECT),
        tree_record("target.toml", TARGET_MANIFEST),
    ]);
    let target_path = "share/wrela/targets/aarch64-qemu-virt-uefi";
    let manifest = ToolchainManifest {
        schema: TOOLCHAIN_MANIFEST_SCHEMA,
        release: "0.1.0-headless-check-test".to_owned(),
        host: current_host_identity()
            .expect("supported compiler host")
            .to_owned(),
        llvm_project_revision: REQUIRED_LLVM_PROJECT_REVISION.to_owned(),
        compatibility: ToolchainCompatibility::current(),
        standard_library_packages: vec![ShippedStandardLibraryPackage {
            identity: core_identity,
            locator: PackageLocator::Toolchain {
                component: "wrela-core-0.1".to_owned(),
            },
            manifest_digest: HASHER.sha256(&canonical_manifest_bytes(CORE_MANIFEST)),
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
        ],
        targets: vec![ShippedTarget {
            identity: TargetIdentity::aarch64_qemu_virt_uefi(),
            path: ComponentPath::new(target_path).expect("target path"),
            digest: target.digest,
            bytes: target.content_bytes,
            files: vec![shipped_target_file(
                "runtime/wrela-runtime-aarch64.obj",
                RUNTIME_OBJECT,
            )],
        }],
    };
    let bytes = CanonicalToolchainManifestCodec::new()
        .encode_canonical(
            &manifest,
            PipelineLimits::standard().toolchain_decode,
            &|| false,
        )
        .expect("canonical toolchain manifest");
    directory.write("toolchain/share/wrela/toolchain.toml", &bytes);
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
