#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

use wrela_build_model::{Sha256Digest, TargetIdentity};
use wrela_package_loader::{ContentHasher, SoftwareSha256};
use wrela_test_model::{
    CanonicalTestReportCodec, GuestTestOutcome, LanguageFatalCause, TEST_PROTOCOL_VERSION,
    TEST_REPORT_SCHEMA, TestEventKind, TestKind, TestOutcome, TestReport, TestReportCodec,
};
use wrela_test_protocol::{CanonicalTestEventCodec, ProtocolLimits, seal_encoded_event};
use wrela_test_runner::{
    CanonicalImageHarness, ImageHarness, LocalProcessExecutor, ProcessExecutor,
    ProcessSpecification,
};
use wrela_toolchain::{
    ComponentKind, LocalToolchainVerificationLimits, LocalToolchainVerifier, Toolchain,
};

const TOOLCHAIN_ROOT_ENV: &str = "WRELA_STDLIB_TIME_TOOLCHAIN_ROOT";
const RUN_ROOT_ENV: &str = "WRELA_STDLIB_TIME_RUN_ROOT";
const EVIDENCE_ROOT_ENV: &str = "WRELA_STDLIB_TIME_EVIDENCE_ROOT";
const CHILD_TOOLCHAIN_ROOT_ENV: &str = "WRELA_TOOLCHAIN_ROOT";
const IMAGE_NAME: &str = "stdlib-time-runtime";
const PASS_SELECTOR: &str = "installed_core_time_executes_in_qemu";
const FAILURE_SELECTOR: &str = "typed_checked_failure_reaches_qemu";
const WORKSPACE_MANIFEST: &[u8] =
    include_bytes!("../../../std/examples/stdlib-time-runtime/wrela.toml");
const WORKSPACE_LOCKFILE: &[u8] =
    include_bytes!("../../../std/examples/stdlib-time-runtime/wrela.lock");
const APPLICATION_SOURCE: &[u8] =
    include_bytes!("../../../std/examples/stdlib-time-runtime/src/runtime/time_test.wr");
const MAXIMUM_REPORT_BYTES: u64 = 16 * 1024 * 1024;
const MAXIMUM_IMAGE_BYTES: u64 = 256 * 1024 * 1024;
const MAXIMUM_PROCESS_OUTPUT_BYTES: u64 = 16 * 1024 * 1024;
const MAXIMUM_EVENT_PREIMAGE_BYTES: usize = 16 * 1024 * 1024;
const MAXIMUM_EVIDENCE_LINE_BYTES: usize = 4096;
const MAXIMUM_DIAGNOSTIC_BYTES: usize = 4096;
const MAXIMUM_DIAGNOSTIC_FIELD_BYTES: usize = 768;
const MAXIMUM_OUTPUT_ENTRIES: usize = 4096;
const PROCESS_TIMEOUT_NS: u64 = 60 * 60 * 1_000_000_000;

static HASHER: SoftwareSha256 = SoftwareSha256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedOutcome {
    Passed,
    InvalidShiftCount,
}

impl ExpectedOutcome {
    fn guest(self) -> GuestTestOutcome {
        match self {
            Self::Passed => GuestTestOutcome::Passed,
            Self::InvalidShiftCount => GuestTestOutcome::LanguageFatal {
                cause: LanguageFatalCause::InvalidShiftCount,
            },
        }
    }

    fn host_matches(self, outcome: &TestOutcome) -> bool {
        matches!(
            (self, outcome),
            (Self::Passed, TestOutcome::Passed)
                | (
                    Self::InvalidShiftCount,
                    TestOutcome::LanguageFatal {
                        cause: LanguageFatalCause::InvalidShiftCount,
                    },
                )
        )
    }

    const fn evidence_name(self) -> &'static str {
        match self {
            Self::Passed => "pass",
            Self::InvalidShiftCount => "invalid-count",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileEvidence {
    sha256: Sha256Digest,
    bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EventEvidence {
    sha256: Sha256Digest,
    bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CaseEvidence {
    image: FileEvidence,
    report: FileEvidence,
    events: EventEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StdlibTimeEvidence {
    source: FileEvidence,
    manifest: FileEvidence,
    lock: FileEvidence,
    pass: CaseEvidence,
    invalid_count: CaseEvidence,
}

impl StdlibTimeEvidence {
    fn canonical_line(self) -> String {
        let line = format!(
            "WRELA_STDLIB_TIME_QEMU_EVIDENCE schema=1 source_sha256={} source_bytes={} manifest_sha256={} manifest_bytes={} lock_sha256={} lock_bytes={} pass_image_sha256={} pass_image_bytes={} pass_report_sha256={} pass_report_bytes={} pass_event_stream_sha256={} pass_event_stream_bytes={} invalid_count_image_sha256={} invalid_count_image_bytes={} invalid_count_report_sha256={} invalid_count_report_bytes={} invalid_count_event_stream_sha256={} invalid_count_event_stream_bytes={}",
            self.source.sha256.to_hex(),
            self.source.bytes,
            self.manifest.sha256.to_hex(),
            self.manifest.bytes,
            self.lock.sha256.to_hex(),
            self.lock.bytes,
            self.pass.image.sha256.to_hex(),
            self.pass.image.bytes,
            self.pass.report.sha256.to_hex(),
            self.pass.report.bytes,
            self.pass.events.sha256.to_hex(),
            self.pass.events.bytes,
            self.invalid_count.image.sha256.to_hex(),
            self.invalid_count.image.bytes,
            self.invalid_count.report.sha256.to_hex(),
            self.invalid_count.report.bytes,
            self.invalid_count.events.sha256.to_hex(),
            self.invalid_count.events.bytes,
        );
        assert!(line.len() <= MAXIMUM_EVIDENCE_LINE_BYTES);
        assert!(!line.contains('/') && !line.contains('\\'));
        line
    }
}

/// Executes checked-in source with the installed frontend/backend/runtime and
/// enrolled QEMU. Ordinary package gates compile this contract; the enrolled
/// distribution gate supplies both absolute roots and opts in with
/// `--ignored --exact`.
#[test]
#[ignore = "requires an enrolled toolchain with real AArch64 QEMU and firmware"]
fn installed_core_time_source_executes_under_enrolled_qemu() {
    let toolchain_root = required_absent_or_existing_root(TOOLCHAIN_ROOT_ENV, true);
    let run_root = required_absent_or_existing_root(RUN_ROOT_ENV, false);
    let evidence_root = required_absent_or_existing_root(EVIDENCE_ROOT_ENV, false);
    assert_ne!(run_root, evidence_root);
    let cleanup = RunRootGuard::create(&run_root);
    let export = EvidenceRootGuard::create(&evidence_root);

    let target_identity = TargetIdentity::aarch64_qemu_virt_uefi();
    let verification = LocalToolchainVerifier::new(Toolchain::at(&toolchain_root))
        .verify(
            &target_identity,
            LocalToolchainVerificationLimits::standard(),
            &never_cancelled,
        )
        .expect("verify exact enrolled stdlib-time toolchain");
    assert_eq!(verification.toolchain().root(), toolchain_root);
    assert_eq!(verification.target().identity(), &target_identity);
    let frontend = verification
        .toolchain()
        .component(ComponentKind::Frontend)
        .expect("verified frontend");
    let standard_library = verification
        .toolchain()
        .component(ComponentKind::StandardLibrary)
        .expect("verified standard library");
    let emulator = verification
        .toolchain()
        .component(ComponentKind::Aarch64Emulator)
        .expect("verified AArch64 emulator");
    let target = verification
        .toolchain()
        .target(&target_identity)
        .expect("verified target package");

    let cases = [
        (PASS_SELECTOR, ExpectedOutcome::Passed),
        (FAILURE_SELECTOR, ExpectedOutcome::InvalidShiftCount),
    ];
    let mut pass_evidence = None;
    let mut invalid_count_evidence = None;
    for (selector, expected) in cases {
        let case_root = run_root.join(selector);
        create_private_directory(&case_root);
        let workspace = case_root.join("workspace");
        create_private_directory(&workspace);
        create_private_directory(&workspace.join("src"));
        create_private_directory(&workspace.join("src/runtime"));
        write_new(&workspace.join("wrela.toml"), WORKSPACE_MANIFEST);
        write_new(&workspace.join("wrela.lock"), WORKSPACE_LOCKFILE);
        write_new(
            &workspace.join("src/runtime/time_test.wr"),
            APPLICATION_SOURCE,
        );
        let temporary = case_root.join("tmp");
        create_private_directory(&temporary);
        let output = case_root.join("output");

        let specification = ProcessSpecification {
            program: frontend.clone(),
            arguments: vec![
                OsString::from("test"),
                workspace.join("wrela.toml").into_os_string(),
                OsString::from(IMAGE_NAME),
                output.as_os_str().to_owned(),
                OsString::from("--name-contains"),
                OsString::from(selector),
            ],
            current_directory: workspace.clone(),
            environment: vec![
                (OsString::from("HOME"), case_root.as_os_str().to_owned()),
                (OsString::from("LC_ALL"), OsString::from("C")),
                (OsString::from("PATH"), OsString::new()),
                (OsString::from("SOURCE_DATE_EPOCH"), OsString::from("0")),
                (OsString::from("TMPDIR"), temporary.as_os_str().to_owned()),
                (OsString::from("TZ"), OsString::from("UTC")),
                (
                    OsString::from(CHILD_TOOLCHAIN_ROOT_ENV),
                    toolchain_root.as_os_str().to_owned(),
                ),
            ],
            timeout_ns: PROCESS_TIMEOUT_NS,
            protocol_limits: ProtocolLimits::standard(),
            maximum_output_bytes: MAXIMUM_PROCESS_OUTPUT_BYTES,
            shutdown_control: None,
            inputs: Vec::new(),
        };
        let completion = LocalProcessExecutor::new()
            .execute(&specification, None, &never_cancelled)
            .unwrap_or_else(|error| {
                panic!("{selector} bounded frontend execution failed: {error:?}")
            });
        let process_diagnostic = bounded_path_free_bytes(
            format!(
                "process_exit={:?} timed_out={} stdout_bytes={} stdout={} stderr_bytes={} stderr={}",
                completion.exit_code,
                completion.timed_out,
                completion.stdout.len(),
                bounded_path_free_bytes(&completion.stdout, MAXIMUM_DIAGNOSTIC_FIELD_BYTES),
                completion.stderr.len(),
                bounded_path_free_bytes(&completion.stderr, MAXIMUM_DIAGNOSTIC_FIELD_BYTES),
            )
            .as_bytes(),
            MAXIMUM_DIAGNOSTIC_BYTES,
        );
        assert!(
            !completion.timed_out,
            "{selector} frontend timed out; {process_diagnostic}"
        );

        // A public test command intentionally exits nonzero when a generated
        // image reports a failed case. Decode and canonically re-encode that
        // report before checking the process status so an unexpected outcome
        // retains the producer's decisive, independently validated detail.
        let report_path = output.join("test-report.bin");
        let report_bytes = read_bounded_file(&report_path, MAXIMUM_REPORT_BYTES);
        let report_limit = u64::try_from(report_bytes.len()).expect("report length fits u64");
        let codec = CanonicalTestReportCodec::new();
        let report = codec
            .decode(&report_bytes, report_limit, &never_cancelled)
            .unwrap_or_else(|error| panic!("{selector} canonical report decode failed: {error}"));
        assert_eq!(
            codec
                .encode(&report, report_limit, &never_cancelled)
                .expect("canonical report re-encoding"),
            report_bytes
        );
        let diagnostic = bounded_path_free_bytes(
            format!(
                "{process_diagnostic}; {}",
                canonical_report_diagnostic(&report_bytes, &report)
            )
            .as_bytes(),
            MAXIMUM_DIAGNOSTIC_BYTES,
        );
        assert!(
            completion.stderr.is_empty(),
            "{selector} wrote {} stderr byte(s); {diagnostic}",
            completion.stderr.len(),
        );
        match expected {
            ExpectedOutcome::Passed => {
                assert_eq!(
                    completion.exit_code,
                    Some(0),
                    "{selector} process status did not match passed report contract; {diagnostic}"
                );
                assert_eq!(
                    completion.stdout, b"test passed\n",
                    "{selector} stdout did not match passed report contract; {diagnostic}"
                );
            }
            ExpectedOutcome::InvalidShiftCount => {
                assert!(
                    completion.exit_code.is_some_and(|code| code != 0),
                    "{selector} process status did not match failed report contract; {diagnostic}"
                );
                assert_eq!(
                    completion.stdout, b"test failed\n",
                    "{selector} stdout did not match failed report contract; {diagnostic}"
                );
            }
        }

        assert_eq!(report.schema, TEST_REPORT_SCHEMA);
        assert_eq!(report.build.compiler, frontend.digest());
        assert_eq!(report.build.target, target_identity);
        assert_eq!(report.build.target_package, target.digest());
        assert_eq!(report.build.standard_library, standard_library.digest());
        assert!(report.unit.is_empty());
        let [image] = report.images.as_slice() else {
            panic!("{selector} must execute exactly one image group");
        };
        assert!(image.infrastructure_failure.is_none());
        let [case] = image.cases.as_slice() else {
            panic!("{selector} must produce exactly one runtime case");
        };
        assert_eq!(case.descriptor.id.0, 0);
        assert_eq!(case.descriptor.kind, TestKind::IntegrationImage);
        assert_eq!(case.descriptor.timeout_ns, 30_000_000_000);
        assert_eq!(
            case.descriptor.name,
            format!("{IMAGE_NAME}@0.1.0::runtime.time_test::{selector}")
        );
        assert!(expected.host_matches(&case.outcome));
        assert_eq!(image.evidence.target_digest, target.digest());
        assert_eq!(image.evidence.emulator_digest, Some(emulator.digest()));
        assert_eq!(image.evidence.exit_code, Some(0));
        assert!(image.evidence.stderr.is_empty());
        validate_four_event_lifecycle(&image.events, case.descriptor.id, &expected.guest());
        let (event_preimage, event_evidence) = canonical_event_stream_preimage(&image.events);
        assert_eq!(
            image.evidence.event_stream_digest,
            Some(event_evidence.sha256)
        );
        assert_eq!(
            event_evidence.sha256,
            CanonicalImageHarness::new()
                .event_stream_digest(&image.events, &never_cancelled)
                .expect("real event stream digest")
        );

        let images = find_efi_images(&output);
        let [published_image] = images.as_slice() else {
            panic!("{selector} must publish exactly one generated EFI image");
        };
        let image_bytes = read_bounded_file(published_image, MAXIMUM_IMAGE_BYTES);
        assert_eq!(
            image.evidence.image_digest,
            Some(HASHER.sha256(&image_bytes)),
            "typed report must bind the exact QEMU-executed producer output"
        );
        let case_evidence = CaseEvidence {
            image: file_evidence(&image_bytes),
            report: file_evidence(&report_bytes),
            events: event_evidence,
        };
        let evidence_name = expected.evidence_name();
        write_new(
            &evidence_root.join(format!("{evidence_name}.efi")),
            &image_bytes,
        );
        write_new(
            &evidence_root.join(format!("{evidence_name}.report")),
            &report_bytes,
        );
        write_new(
            &evidence_root.join(format!("{evidence_name}.events")),
            &event_preimage,
        );
        match expected {
            ExpectedOutcome::Passed => pass_evidence = Some(case_evidence),
            ExpectedOutcome::InvalidShiftCount => {
                invalid_count_evidence = Some(case_evidence);
            }
        }

        fs::remove_dir_all(&case_root).expect("remove completed real-QEMU case root");
        assert!(!case_root.exists());
    }

    cleanup.cleanup();
    assert!(!run_root.exists());
    let evidence = StdlibTimeEvidence {
        source: file_evidence(APPLICATION_SOURCE),
        manifest: file_evidence(WORKSPACE_MANIFEST),
        lock: file_evidence(WORKSPACE_LOCKFILE),
        pass: pass_evidence.expect("pass selector evidence"),
        invalid_count: invalid_count_evidence.expect("typed invalid-count selector evidence"),
    };
    export.publish();
    println!("\n{}", evidence.canonical_line());
}

fn canonical_report_diagnostic(report_bytes: &[u8], report: &TestReport) -> String {
    let mut diagnostic = format!(
        "report_sha256={} report_bytes={} schema={} unit_cases={} image_groups={}",
        HASHER.sha256(report_bytes).to_hex(),
        report_bytes.len(),
        report.schema,
        report.unit.len(),
        report.images.len(),
    );
    if let Some(image) = report.images.first() {
        diagnostic.push_str(&format!(
            " first_group={} cases={} events={} execution_exit={:?} execution_stderr_bytes={} execution_stderr={} infrastructure={}",
            image.group.0,
            image.cases.len(),
            image.events.len(),
            image.evidence.exit_code,
            image.evidence.stderr.len(),
            bounded_path_free_bytes(
                &image.evidence.stderr,
                MAXIMUM_DIAGNOSTIC_FIELD_BYTES,
            ),
            image
                .infrastructure_failure
                .as_ref()
                .map(outcome_diagnostic)
                .unwrap_or_else(|| "none".to_owned()),
        ));
        if let Some(case) = image.cases.first() {
            diagnostic.push_str(&format!(
                " first_case_name={} first_case_outcome={}",
                bounded_path_free_bytes(
                    case.descriptor.name.as_bytes(),
                    MAXIMUM_DIAGNOSTIC_FIELD_BYTES,
                ),
                outcome_diagnostic(&case.outcome),
            ));
        }
        if !image.events.is_empty() {
            let (preimage, evidence) = canonical_event_stream_preimage(&image.events);
            diagnostic.push_str(&format!(
                " event_preimage_sha256={} event_frame_bytes={} event_preimage_bytes={}",
                evidence.sha256.to_hex(),
                evidence.bytes,
                preimage.len(),
            ));
        }
    }
    bounded_path_free_bytes(diagnostic.as_bytes(), MAXIMUM_DIAGNOSTIC_BYTES)
}

fn outcome_diagnostic(outcome: &TestOutcome) -> String {
    let diagnostic = match outcome {
        TestOutcome::Passed => "Passed".to_owned(),
        TestOutcome::Failed { phase, message } => format!(
            "Failed(phase={phase:?},message={})",
            bounded_path_free_bytes(message.as_bytes(), MAXIMUM_DIAGNOSTIC_FIELD_BYTES),
        ),
        TestOutcome::TimedOut { phase, timeout_ns } => {
            format!("TimedOut(phase={phase:?},timeout_ns={timeout_ns})")
        }
        TestOutcome::Crashed { code, message } => format!(
            "Crashed(code={code:?},message={})",
            bounded_path_free_bytes(message.as_bytes(), MAXIMUM_DIAGNOSTIC_FIELD_BYTES),
        ),
        TestOutcome::LanguageFatal { cause } => format!("LanguageFatal(cause={cause:?})"),
    };
    bounded_path_free_bytes(diagnostic.as_bytes(), MAXIMUM_DIAGNOSTIC_FIELD_BYTES)
}

fn bounded_path_free_bytes(bytes: &[u8], maximum_output_bytes: usize) -> String {
    const TRUNCATED: &str = "<TRUNCATED>";
    let content_limit = maximum_output_bytes.saturating_sub(TRUNCATED.len());
    let mut rendered = String::new();
    let mut truncated = false;
    for byte in bytes {
        let required = match byte {
            b'\n' | b'\r' | b'\t' => 4,
            b' '..=b'~' => 1,
            _ => 4,
        };
        if rendered.len().saturating_add(required) > content_limit {
            truncated = true;
            break;
        }
        match byte {
            b'\n' => rendered.push_str("<LF>"),
            b'\r' => rendered.push_str("<CR>"),
            b'\t' => rendered.push_str("<HT>"),
            b'/' | b'\\' => rendered.push('?'),
            b' '..=b'~' => rendered.push(char::from(*byte)),
            _ => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                rendered.push('<');
                rendered.push(char::from(HEX[usize::from(*byte >> 4)]));
                rendered.push(char::from(HEX[usize::from(*byte & 0x0f)]));
                rendered.push('>');
            }
        }
    }
    if truncated {
        rendered.push_str(TRUNCATED);
    }
    assert!(rendered.len() <= maximum_output_bytes);
    assert!(!rendered.contains('/') && !rendered.contains('\\'));
    rendered
}

#[test]
fn failure_diagnostics_are_bounded_and_path_free() {
    let rendered = bounded_path_free_bytes(b"/p\\q\n\xff0123456789abcdefghijklmnopqrstuvwxyz", 40);
    assert!(rendered.len() <= 40);
    assert!(!rendered.contains('/') && !rendered.contains('\\'));
    assert!(rendered.contains('?'));
    assert!(rendered.contains("<LF>"));
    assert!(rendered.ends_with("<TRUNCATED>"));
}

fn file_evidence(bytes: &[u8]) -> FileEvidence {
    FileEvidence {
        sha256: HASHER.sha256(bytes),
        bytes: u64::try_from(bytes.len()).expect("bounded evidence length fits u64"),
    }
}

fn canonical_event_stream_preimage(
    events: &[wrela_test_model::TestEvent],
) -> (Vec<u8>, EventEvidence) {
    let event_count = u32::try_from(events.len().max(1)).expect("bounded event count fits u32");
    let limits = ProtocolLimits {
        events: event_count,
        ..ProtocolLimits::standard()
    };
    let mut preimage = Vec::new();
    preimage.extend_from_slice(b"WRELEVS\0");
    preimage.extend_from_slice(&1_u32.to_le_bytes());
    preimage.extend_from_slice(
        &u64::try_from(events.len())
            .expect("bounded event count fits u64")
            .to_le_bytes(),
    );
    let mut event_bytes = 0_u64;
    for event in events {
        let encoded = seal_encoded_event(&CanonicalTestEventCodec, event, limits, &never_cancelled)
            .expect("canonical real event frame");
        let bytes = u64::try_from(encoded.bytes().len()).expect("bounded event frame fits u64");
        event_bytes = event_bytes
            .checked_add(bytes)
            .expect("bounded event stream length");
        preimage.extend_from_slice(&bytes.to_le_bytes());
        preimage.extend_from_slice(encoded.bytes());
        assert!(preimage.len() <= MAXIMUM_EVENT_PREIMAGE_BYTES);
    }
    assert!(event_bytes > 0);
    let sha256 = HASHER.sha256(&preimage);
    (
        preimage,
        EventEvidence {
            sha256,
            bytes: event_bytes,
        },
    )
}

fn validate_four_event_lifecycle(
    events: &[wrela_test_model::TestEvent],
    test: wrela_test_model::TestId,
    expected: &GuestTestOutcome,
) {
    assert_eq!(events.len(), 4);
    for (sequence, event) in events.iter().enumerate() {
        assert_eq!(event.protocol, TEST_PROTOCOL_VERSION);
        assert_eq!(
            event.sequence,
            u64::try_from(sequence).expect("four-event sequence fits u64")
        );
    }
    assert!(matches!(
        events[0].kind,
        TestEventKind::RunStarted { test_count: 1 }
    ));
    assert!(matches!(
        events[1].kind,
        TestEventKind::TestStarted { test: actual } if actual == test
    ));
    assert!(matches!(
        &events[2].kind,
        TestEventKind::TestFinished { test: actual, outcome }
            if *actual == test && outcome == expected
    ));
    let summary = if matches!(expected, GuestTestOutcome::Passed) {
        (1, 0)
    } else {
        (0, 1)
    };
    assert!(matches!(
        events[3].kind,
        TestEventKind::RunFinished { passed, failed } if (passed, failed) == summary
    ));
}

fn find_efi_images(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_owned()];
    let mut images = Vec::new();
    let mut entries = 0_usize;
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).expect("read bounded output directory") {
            let entry = entry.expect("read output entry");
            entries = entries.checked_add(1).expect("output entry count overflow");
            assert!(entries <= MAXIMUM_OUTPUT_ENTRIES);
            let path = entry.path();
            let kind = entry.file_type().expect("output entry type");
            assert!(!kind.is_symlink());
            if kind.is_dir() {
                pending.push(path);
            } else {
                assert!(kind.is_file());
                if path.extension().and_then(|extension| extension.to_str()) == Some("efi") {
                    images.push(path);
                }
            }
        }
    }
    images.sort();
    images
}

fn read_bounded_file(path: &Path, maximum_bytes: u64) -> Vec<u8> {
    let metadata = fs::symlink_metadata(path).expect("bounded file metadata");
    assert!(metadata.is_file());
    assert!(!metadata.file_type().is_symlink());
    assert!(metadata.len() > 0 && metadata.len() <= maximum_bytes);
    let bytes = fs::read(path).expect("bounded file read");
    assert_eq!(
        u64::try_from(bytes.len()).expect("bounded file length fits u64"),
        metadata.len()
    );
    bytes
}

fn required_absent_or_existing_root(name: &'static str, existing: bool) -> PathBuf {
    let value = std::env::var_os(name).unwrap_or_else(|| panic!("missing explicit {name}"));
    let path = PathBuf::from(value);
    assert!(
        normal_absolute_path(&path),
        "{name} must be normalized and absolute"
    );
    if existing {
        assert!(path.is_dir(), "{name} must name an existing directory");
    } else {
        assert!(
            !path.exists(),
            "{name} must name an absent dedicated directory"
        );
    }
    path
}

fn normal_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path.components().count() > 1
        && path
            .components()
            .all(|component| !matches!(component, Component::CurDir | Component::ParentDir))
        && path.components().collect::<PathBuf>() == path
}

fn create_private_directory(path: &Path) {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    builder.mode(0o700);
    builder
        .create(path)
        .expect("create private QEMU fixture directory");
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .expect("seal private QEMU fixture permissions");
}

fn write_new(path: &Path, bytes: &[u8]) {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).expect("create exact QEMU fixture file");
    file.write_all(bytes)
        .expect("write exact QEMU fixture file");
    file.sync_all().expect("sync exact QEMU fixture file");
}

struct RunRootGuard {
    root: PathBuf,
    armed: bool,
}

struct EvidenceRootGuard {
    root: PathBuf,
    armed: bool,
}

impl EvidenceRootGuard {
    fn create(root: &Path) -> Self {
        create_private_directory(root);
        assert_eq!(
            fs::canonicalize(root).expect("canonical evidence root"),
            root
        );
        Self {
            root: root.to_owned(),
            armed: true,
        }
    }

    fn publish(mut self) {
        fs::File::open(&self.root)
            .and_then(|directory| directory.sync_all())
            .expect("sync complete evidence export");
        self.armed = false;
    }
}

impl Drop for EvidenceRootGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

impl RunRootGuard {
    fn create(root: &Path) -> Self {
        create_private_directory(root);
        assert_eq!(fs::canonicalize(root).expect("canonical run root"), root);
        Self {
            root: root.to_owned(),
            armed: true,
        }
    }

    fn cleanup(mut self) {
        fs::remove_dir_all(&self.root).expect("remove complete real-QEMU run root");
        self.armed = false;
    }
}

impl Drop for RunRootGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

const fn never_cancelled() -> bool {
    false
}
