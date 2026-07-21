#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use wrela_build_model::{Sha256Digest, TargetIdentity};
use wrela_package_loader::{
    CanonicalPackageCodec, ContentHasher, ManifestCodecLimits, PackageCodec, PackageContentKind,
    PackageContentRecord, SoftwareSha256, package_content_digest,
};
use wrela_test_model::{
    CanonicalTestReportCodec, FailurePhase, GuestTestOutcome, LanguageFatalCause,
    TEST_PROTOCOL_VERSION, TEST_REPORT_SCHEMA, TestEventKind, TestKind, TestOutcome,
    TestReportCodec,
};
use wrela_test_protocol::{CanonicalTestEventCodec, ProtocolLimits, seal_encoded_event};
use wrela_test_runner::{CanonicalImageHarness, ImageHarness};
use wrela_toolchain::{
    ComponentKind, LocalToolchainVerification, LocalToolchainVerificationLimits,
    LocalToolchainVerifier, Toolchain, VerifiedPath,
};

const HARNESS_TOOLCHAIN_ROOT_ENV: &str = "WRELA_SMOKE_TOOLCHAIN_ROOT";
const RUN_ROOT_ENV: &str = "WRELA_SMOKE_RUN_ROOT";
const RUNTIME_TIMEOUT_RUN_BINDING_ENV: &str = "WRELA_RUNTIME_TIMEOUT_RUN_BINDING";
const CHILD_TOOLCHAIN_ROOT_ENV: &str = "WRELA_TOOLCHAIN_ROOT";
const MAX_SMOKE_ARGUMENTS: usize = 5;
const MAX_SELECTED_SMOKE_ARGUMENTS: usize = 6;
const MAX_SMOKE_ENVIRONMENT_VARIABLES: usize = 7;
const MAX_SMOKE_COMMAND_BYTES: usize = 1024 * 1024;
const MAX_SMOKE_PATH_BYTES: usize = 64 * 1024;
const MAX_SMOKE_REPORT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SMOKE_IMAGE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SMOKE_OUTPUT_ENTRIES: usize = 4096;
const MAX_SMOKE_PROCESS_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const MAX_SUPERVISED_PROCESS_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
const SMOKE_PROCESS_WALL_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const SMOKE_PROCESS_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const PROCESS_STATUS_POLL_INTERVAL: Duration = Duration::from_millis(20);
const MAX_SUPERVISED_PROCESS_TIMEOUT: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcessStream {
    Stdout,
    Stderr,
}

impl fmt::Display for ProcessStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum BoundedProcessFailureKind {
    #[cfg(not(unix))]
    UnsupportedHost,
    InvalidPolicy,
    Spawn(std::io::ErrorKind),
    MissingPipe(ProcessStream),
    ReaderSpawn {
        stream: ProcessStream,
        kind: std::io::ErrorKind,
    },
    Wait(std::io::ErrorKind),
    Read {
        stream: ProcessStream,
        kind: std::io::ErrorKind,
    },
    ReaderAllocation(ProcessStream),
    ReaderState(ProcessStream),
    ReaderPanicked(ProcessStream),
    TimedOut {
        milliseconds: u64,
    },
    OutputLimit {
        bytes: usize,
    },
    Exit {
        code: Option<i32>,
    },
    CleanupTimedOut {
        milliseconds: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BoundedProcessFailure {
    kind: BoundedProcessFailureKind,
    process_group: Option<u32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl fmt::Display for BoundedProcessFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "bounded process {:?} (", self.kind)?;
        if let BoundedProcessFailureKind::OutputLimit { bytes } = &self.kind {
            write!(formatter, "aggregate_output_limit={bytes} bytes reached",)?;
        } else {
            write_bounded_process_output(formatter, ProcessStream::Stdout, &self.stdout)?;
            formatter.write_str(", ")?;
            write_bounded_process_output(formatter, ProcessStream::Stderr, &self.stderr)?;
        }
        formatter.write_str(")")
    }
}

fn write_bounded_process_output(
    formatter: &mut fmt::Formatter<'_>,
    stream: ProcessStream,
    bytes: &[u8],
) -> fmt::Result {
    let class = if bytes.is_empty() {
        "empty"
    } else if stream == ProcessStream::Stdout && bytes == b"test failed\n" {
        "public-test-failed"
    } else {
        "opaque-nonempty"
    };
    write!(formatter, "{stream}={class} bytes={}", bytes.len())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BoundedProcessPolicy {
    wall_timeout: Duration,
    cleanup_timeout: Duration,
    output_bytes: usize,
}

impl BoundedProcessPolicy {
    const fn real_smoke() -> Self {
        Self {
            wall_timeout: SMOKE_PROCESS_WALL_TIMEOUT,
            cleanup_timeout: SMOKE_PROCESS_CLEANUP_TIMEOUT,
            output_bytes: MAX_SMOKE_PROCESS_OUTPUT_BYTES,
        }
    }

    fn validate(self) -> Result<Self, BoundedProcessFailure> {
        if self.wall_timeout.is_zero()
            || self.wall_timeout > MAX_SUPERVISED_PROCESS_TIMEOUT
            || self.cleanup_timeout.is_zero()
            || self.cleanup_timeout > MAX_SUPERVISED_PROCESS_TIMEOUT
            || self.output_bytes == 0
            || self.output_bytes > MAX_SUPERVISED_PROCESS_OUTPUT_BYTES
        {
            return Err(BoundedProcessFailure {
                kind: BoundedProcessFailureKind::InvalidPolicy,
                process_group: None,
                stdout: Vec::new(),
                stderr: Vec::new(),
            });
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BoundedProcessOutput {
    process_group: u32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailedReportScope {
    UnitCase { index: usize },
    ImageCase { group: u32, index: usize },
    ImageInfrastructure { group: u32 },
}

impl fmt::Display for FailedReportScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnitCase { index } => write!(formatter, "unit-case[{index}]"),
            Self::ImageCase { group, index } => {
                write!(formatter, "image-group[{group}].case[{index}]")
            }
            Self::ImageInfrastructure { group } => {
                write!(formatter, "image-group[{group}].infrastructure")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BoundedFailureMessage {
    bytes: u64,
}

impl BoundedFailureMessage {
    fn observe(message: &str) -> Result<Self, FailedReportObservation> {
        let bytes = u64::try_from(message.len())
            .map_err(|_| FailedReportObservation::DiagnosticResourceLimit)?;
        Ok(Self { bytes })
    }
}

impl fmt::Display for BoundedFailureMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "message=opaque-nonempty message_bytes={}",
            self.bytes,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FailedOutcomeDiagnostic {
    Failed {
        phase: FailurePhase,
        message: BoundedFailureMessage,
    },
    TimedOut {
        phase: FailurePhase,
        timeout_ns: u64,
    },
    Crashed {
        code: Option<i32>,
        message: BoundedFailureMessage,
    },
    LanguageFatal {
        cause: LanguageFatalCause,
    },
}

impl FailedOutcomeDiagnostic {
    fn observe_nonpassing(outcome: &TestOutcome) -> Result<Self, FailedReportObservation> {
        Ok(match outcome {
            TestOutcome::Passed => return Err(FailedReportObservation::SemanticallyInvalid),
            TestOutcome::Failed { phase, message } => Self::Failed {
                phase: *phase,
                message: BoundedFailureMessage::observe(message)?,
            },
            TestOutcome::TimedOut { phase, timeout_ns } => Self::TimedOut {
                phase: *phase,
                timeout_ns: *timeout_ns,
            },
            TestOutcome::Crashed { code, message } => Self::Crashed {
                code: *code,
                message: BoundedFailureMessage::observe(message)?,
            },
            TestOutcome::LanguageFatal { cause } => Self::LanguageFatal { cause: *cause },
        })
    }
}

fn outcome_is_semantically_valid(scope: FailedReportScope, outcome: &TestOutcome) -> bool {
    let message_has_content =
        |message: &str| message.chars().any(|character| !character.is_whitespace());
    match (scope, outcome) {
        (FailedReportScope::UnitCase { .. }, TestOutcome::Passed)
        | (FailedReportScope::ImageCase { .. }, TestOutcome::Passed) => true,
        (FailedReportScope::ImageCase { .. }, TestOutcome::LanguageFatal { .. }) => true,
        (
            FailedReportScope::UnitCase { .. },
            TestOutcome::Failed {
                phase: FailurePhase::Comptime,
                message,
            },
        )
        | (
            FailedReportScope::ImageCase { .. },
            TestOutcome::Failed {
                phase: FailurePhase::Runtime,
                message,
            },
        ) => message_has_content(message),
        (
            FailedReportScope::UnitCase { .. },
            TestOutcome::TimedOut {
                phase: FailurePhase::Comptime,
                timeout_ns,
            },
        )
        | (
            FailedReportScope::ImageCase { .. },
            TestOutcome::TimedOut {
                phase: FailurePhase::Runtime,
                timeout_ns,
            },
        ) => *timeout_ns != 0,
        (FailedReportScope::ImageInfrastructure { .. }, TestOutcome::Failed { phase, message }) => {
            *phase != FailurePhase::Comptime && message_has_content(message)
        }
        (
            FailedReportScope::ImageInfrastructure { .. },
            TestOutcome::TimedOut { phase, timeout_ns },
        ) => *phase != FailurePhase::Comptime && *timeout_ns != 0,
        (FailedReportScope::ImageInfrastructure { .. }, TestOutcome::Crashed { message, .. }) => {
            message_has_content(message)
        }
        (
            FailedReportScope::UnitCase { .. } | FailedReportScope::ImageCase { .. },
            TestOutcome::Failed { .. } | TestOutcome::TimedOut { .. } | TestOutcome::Crashed { .. },
        )
        | (
            FailedReportScope::UnitCase { .. } | FailedReportScope::ImageInfrastructure { .. },
            TestOutcome::LanguageFatal { .. },
        )
        | (FailedReportScope::ImageInfrastructure { .. }, TestOutcome::Passed) => false,
    }
}

impl fmt::Display for FailedOutcomeDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Failed { phase, message } => {
                write!(
                    formatter,
                    "class=failed phase={} {message}",
                    failure_phase_name(*phase)
                )
            }
            Self::TimedOut { phase, timeout_ns } => write!(
                formatter,
                "class=timed-out phase={} timeout_ns={timeout_ns}",
                failure_phase_name(*phase)
            ),
            Self::Crashed { code, message } => {
                write!(formatter, "class=crashed code={code:?} {message}")
            }
            Self::LanguageFatal { cause } => write!(
                formatter,
                "class=language-fatal cause={}",
                language_fatal_cause_name(*cause)
            ),
        }
    }
}

const fn language_fatal_cause_name(cause: LanguageFatalCause) -> &'static str {
    match cause {
        LanguageFatalCause::CheckedShiftResultLoss => "checked-shift-result-loss",
        LanguageFatalCause::InvalidShiftCount => "invalid-shift-count",
    }
}

const fn failure_phase_name(phase: FailurePhase) -> &'static str {
    match phase {
        FailurePhase::Discovery => "discovery",
        FailurePhase::Comptime => "comptime",
        FailurePhase::Compile => "compile",
        FailurePhase::Link => "link",
        FailurePhase::Boot => "boot",
        FailurePhase::Runtime => "runtime",
        FailurePhase::Shutdown => "shutdown",
        FailurePhase::Protocol => "protocol",
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CanonicalFailedReportDiagnostic {
    bytes: u64,
    failed_outcomes: u64,
    first_scope: FailedReportScope,
    first_outcome: FailedOutcomeDiagnostic,
}

impl fmt::Display for CanonicalFailedReportDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "canonical-report bytes={} failed_outcomes={}",
            self.bytes, self.failed_outcomes,
        )?;
        write!(
            formatter,
            " first={} {}",
            self.first_scope, self.first_outcome
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FailedReportObservation {
    Missing,
    UnreadableOrUnsafe,
    InvalidLength,
    DecodeFailed,
    ReencodeFailed,
    NonCanonical,
    UnsupportedSchema(u32),
    SemanticallyInvalid,
    DiagnosticResourceLimit,
    Canonical(Box<CanonicalFailedReportDiagnostic>),
}

impl fmt::Display for FailedReportObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => formatter.write_str("report=missing"),
            Self::UnreadableOrUnsafe => formatter.write_str("report=unreadable-or-unsafe"),
            Self::InvalidLength => formatter.write_str("report=invalid-length"),
            Self::DecodeFailed => formatter.write_str("report=decode-failed"),
            Self::ReencodeFailed => formatter.write_str("report=reencode-failed"),
            Self::NonCanonical => formatter.write_str("report=non-canonical"),
            Self::UnsupportedSchema(schema) => {
                write!(formatter, "report=unsupported-schema({schema})")
            }
            Self::SemanticallyInvalid => formatter.write_str("report=semantically-invalid"),
            Self::DiagnosticResourceLimit => {
                formatter.write_str("report=diagnostic-resource-limit")
            }
            Self::Canonical(diagnostic) => write!(formatter, "report={diagnostic}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SmokeFailure {
    MissingEnvironment(&'static str),
    MissingEnvironmentDigest(&'static str),
    InvalidEnvironmentPath(&'static str),
    InvalidEnvironmentDigest(&'static str),
    InvalidRunRoot(&'static str),
    RunRootExists(PathBuf),
    SymlinkPath(PathBuf),
    Io {
        operation: &'static str,
        path: PathBuf,
        kind: std::io::ErrorKind,
    },
    InvalidBundle(&'static str),
    InvalidLaunch(&'static str),
    InvalidReport(&'static str),
    FailedTestProcess {
        process: Box<BoundedProcessFailure>,
        report: Box<FailedReportObservation>,
    },
}

impl fmt::Display for SmokeFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEnvironment(name) => write!(
                formatter,
                "ignored real-QEMU smoke requires explicit absolute {name}"
            ),
            Self::MissingEnvironmentDigest(name) => {
                write!(
                    formatter,
                    "ignored real-QEMU smoke requires explicit {name}"
                )
            }
            Self::InvalidEnvironmentPath(name) => {
                write!(formatter, "{name} must be a normalized absolute path")
            }
            Self::InvalidEnvironmentDigest(name) => {
                write!(
                    formatter,
                    "{name} must be one canonical nonzero SHA-256 digest"
                )
            }
            Self::InvalidRunRoot(reason) => write!(formatter, "invalid smoke run root: {reason}"),
            Self::RunRootExists(path) => write!(
                formatter,
                "{RUN_ROOT_ENV} must name an absent, dedicated smoke directory: {}",
                path.display()
            ),
            Self::SymlinkPath(path) => {
                write!(
                    formatter,
                    "smoke path traverses a symlink: {}",
                    path.display()
                )
            }
            Self::Io {
                operation,
                path,
                kind,
            } => write!(
                formatter,
                "smoke {operation} failed for {}: {kind}",
                path.display()
            ),
            Self::InvalidBundle(reason) => {
                write!(formatter, "invalid enrolled smoke bundle: {reason}")
            }
            Self::InvalidLaunch(reason) => {
                write!(formatter, "invalid real-QEMU smoke launch: {reason}")
            }
            Self::InvalidReport(reason) => {
                write!(formatter, "invalid real-QEMU smoke report: {reason}")
            }
            Self::FailedTestProcess { process, report } => {
                write!(formatter, "real-QEMU smoke {process}; {report}")
            }
        }
    }
}

impl std::error::Error for SmokeFailure {}

fn smoke_io(operation: &'static str, path: &Path, error: &std::io::Error) -> SmokeFailure {
    SmokeFailure::Io {
        operation,
        path: path.to_owned(),
        kind: error.kind(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PinnedPath {
    path: PathBuf,
    digest: Sha256Digest,
    bytes: u64,
}

impl From<VerifiedPath> for PinnedPath {
    fn from(path: VerifiedPath) -> Self {
        Self {
            path: path.path().to_owned(),
            digest: path.digest(),
            bytes: path.bytes(),
        }
    }
}

/// Self-measure one ambient system path (the system QEMU binary or its EDK2
/// firmware) that is no longer tracked by the toolchain manifest. Mirrors
/// `wrela_test_runner::VerifiedProcessFile::from_system_path`.
fn pinned_system_path(path: PathBuf) -> Result<PinnedPath, SmokeFailure> {
    let bytes = fs::read(&path).map_err(|error| smoke_io("system component", &path, &error))?;
    let byte_count = u64::try_from(bytes.len())
        .map_err(|_| SmokeFailure::InvalidBundle("system component exceeds u64 bytes"))?;
    Ok(PinnedPath {
        digest: HASHER.sha256(&bytes),
        bytes: byte_count,
        path,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EnrolledBundle {
    root: PathBuf,
    frontend: PinnedPath,
    backend: PinnedPath,
    standard_library: PinnedPath,
    emulator: PinnedPath,
    target_package: PinnedPath,
    firmware_code: PinnedPath,
    firmware_variables: PinnedPath,
}

impl EnrolledBundle {
    fn from_verification(
        verification: &LocalToolchainVerification,
        target: &TargetIdentity,
    ) -> Result<Self, SmokeFailure> {
        if verification.target().identity() != target {
            return Err(SmokeFailure::InvalidBundle(
                "selected target identity differs from the decoded target package",
            ));
        }
        let toolchain = verification.toolchain();
        let component = |kind| {
            toolchain
                .component(kind)
                .map(PinnedPath::from)
                .map_err(|_| SmokeFailure::InvalidBundle("missing verified component"))
        };
        let bundle = Self {
            root: toolchain.root().to_owned(),
            frontend: component(ComponentKind::Frontend)?,
            backend: component(ComponentKind::Backend)?,
            standard_library: component(ComponentKind::StandardLibrary)?,
            emulator: pinned_system_path(wrela_toolchain::system_qemu())?,
            target_package: toolchain
                .target(target)
                .map(PinnedPath::from)
                .map_err(|_| SmokeFailure::InvalidBundle("missing verified target package"))?,
            firmware_code: pinned_system_path(wrela_toolchain::system_firmware_code())?,
            firmware_variables: pinned_system_path(wrela_toolchain::system_firmware_vars())?,
        };
        bundle.validate(true)?;
        if bundle.target_package.digest != verification.target().semantic().content_digest() {
            return Err(SmokeFailure::InvalidBundle(
                "target tree digest differs from the decoded target package",
            ));
        }
        Ok(bundle)
    }

    fn validate(&self, inspect_filesystem: bool) -> Result<(), SmokeFailure> {
        if !normal_absolute_path(&self.root) || self.root.components().count() <= 1 {
            return Err(SmokeFailure::InvalidBundle(
                "toolchain root is not a normalized absolute directory",
            ));
        }
        let paths = [
            ("frontend", &self.frontend, true, true),
            ("backend", &self.backend, true, true),
            ("standard library", &self.standard_library, false, true),
            ("emulator", &self.emulator, true, false),
            ("target package", &self.target_package, false, true),
            ("firmware code", &self.firmware_code, true, false),
            ("firmware variables", &self.firmware_variables, true, false),
        ];
        let mut identities = Vec::with_capacity(paths.len());
        for (label, pinned, regular_file, under_root) in paths {
            if (under_root && !strict_descendant(&pinned.path, &self.root))
                || (!under_root && !normal_absolute_path(&pinned.path))
                || pinned.bytes == 0
                || pinned.digest.as_bytes().iter().all(|byte| *byte == 0)
            {
                return Err(SmokeFailure::InvalidBundle(label));
            }
            if inspect_filesystem {
                reject_symlink_ancestors(&pinned.path)?;
                let metadata = fs::symlink_metadata(&pinned.path)
                    .map_err(|error| smoke_io("component metadata", &pinned.path, &error))?;
                let expected_kind = if regular_file {
                    metadata.is_file() && metadata.len() == pinned.bytes
                } else {
                    metadata.is_dir()
                };
                if metadata.file_type().is_symlink() || !expected_kind {
                    return Err(SmokeFailure::InvalidBundle(label));
                }
            }
            identities.push(&pinned.path);
        }
        identities.sort_unstable();
        if identities.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(SmokeFailure::InvalidBundle(
                "verified component paths are not distinct",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SmokeLaunch {
    program: PinnedPath,
    arguments: Vec<OsString>,
    current_directory: PathBuf,
    environment: Vec<(OsString, OsString)>,
}

impl SmokeLaunch {
    fn new(
        bundle: &EnrolledBundle,
        run_root: &Path,
        workspace: &Path,
        output_directory: &Path,
        temporary_directory: &Path,
    ) -> Result<Self, SmokeFailure> {
        Self::new_with_selection(
            bundle,
            run_root,
            workspace,
            output_directory,
            temporary_directory,
            "bootstrap",
            None,
        )
    }

    fn new_selected(
        bundle: &EnrolledBundle,
        run_root: &Path,
        workspace: &Path,
        output_directory: &Path,
        temporary_directory: &Path,
        image: &str,
        selector: &str,
    ) -> Result<Self, SmokeFailure> {
        Self::new_with_selection(
            bundle,
            run_root,
            workspace,
            output_directory,
            temporary_directory,
            image,
            Some(selector),
        )
    }

    fn new_with_selection(
        bundle: &EnrolledBundle,
        run_root: &Path,
        workspace: &Path,
        output_directory: &Path,
        temporary_directory: &Path,
        image: &str,
        selector: Option<&str>,
    ) -> Result<Self, SmokeFailure> {
        bundle.validate(false)?;
        if !normal_absolute_path(run_root)
            || run_root.components().count() <= 1
            || !strict_descendant(workspace, run_root)
            || !strict_descendant(output_directory, run_root)
            || !strict_descendant(temporary_directory, run_root)
            || run_root.starts_with(&bundle.root)
            || bundle.root.starts_with(run_root)
        {
            return Err(SmokeFailure::InvalidLaunch(
                "toolchain and private run paths overlap or escape",
            ));
        }
        for path in [
            run_root,
            workspace,
            output_directory,
            temporary_directory,
            bundle.frontend.path.as_path(),
        ] {
            if path.as_os_str().as_encoded_bytes().len() > MAX_SMOKE_PATH_BYTES {
                return Err(SmokeFailure::InvalidLaunch("path byte limit exceeded"));
            }
        }
        if image.is_empty() || selector.is_some_and(str::is_empty) {
            return Err(SmokeFailure::InvalidLaunch(
                "image and optional test selector must be nonempty",
            ));
        }
        let mut arguments = vec![
            OsString::from("test"),
            workspace.join("wrela.toml").into_os_string(),
            OsString::from(image),
            output_directory.as_os_str().to_owned(),
        ];
        if let Some(selector) = selector {
            arguments.push(OsString::from("--name-contains"));
            arguments.push(OsString::from(selector));
        } else {
            arguments.push(OsString::from("--integration"));
        }
        let environment = vec![
            (OsString::from("HOME"), run_root.as_os_str().to_owned()),
            (OsString::from("LC_ALL"), OsString::from("C")),
            (OsString::from("PATH"), OsString::new()),
            (OsString::from("SOURCE_DATE_EPOCH"), OsString::from("0")),
            (
                OsString::from("TMPDIR"),
                temporary_directory.as_os_str().to_owned(),
            ),
            (OsString::from("TZ"), OsString::from("UTC")),
            (
                OsString::from(CHILD_TOOLCHAIN_ROOT_ENV),
                bundle.root.as_os_str().to_owned(),
            ),
        ];
        let launch = Self {
            program: bundle.frontend.clone(),
            arguments,
            current_directory: workspace.to_owned(),
            environment,
        };
        launch.validate(
            bundle,
            run_root,
            output_directory,
            temporary_directory,
            image,
            selector,
        )?;
        Ok(launch)
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.program.path);
        command
            .args(&self.arguments)
            .current_dir(&self.current_directory)
            .env_clear()
            .envs(self.environment.iter().cloned());
        command
    }

    fn verify_private_layout(
        &self,
        run_root: &Path,
        output_directory: &Path,
        temporary_directory: &Path,
    ) -> Result<(), SmokeFailure> {
        for (label, path) in [
            ("run root", run_root),
            ("workspace", self.current_directory.as_path()),
            ("temporary directory", temporary_directory),
        ] {
            reject_symlink_ancestors(path)?;
            let metadata = fs::symlink_metadata(path)
                .map_err(|error| smoke_io("private directory metadata", path, &error))?;
            let canonical = fs::canonicalize(path)
                .map_err(|error| smoke_io("private directory canonicalization", path, &error))?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() || canonical != path {
                return Err(SmokeFailure::InvalidLaunch(label));
            }
            #[cfg(unix)]
            if metadata.permissions().mode() & 0o777 != 0o700 {
                return Err(SmokeFailure::InvalidLaunch(label));
            }
        }
        match fs::symlink_metadata(output_directory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(SmokeFailure::InvalidLaunch(
                    "output directory must be absent before publication",
                ));
            }
            Err(error) => {
                return Err(smoke_io(
                    "output directory metadata",
                    output_directory,
                    &error,
                ));
            }
        }
        Ok(())
    }

    fn validate(
        &self,
        bundle: &EnrolledBundle,
        run_root: &Path,
        output_directory: &Path,
        temporary_directory: &Path,
        image: &str,
        selector: Option<&str>,
    ) -> Result<(), SmokeFailure> {
        let mut expected_arguments = vec![
            OsString::from("test"),
            self.current_directory.join("wrela.toml").into_os_string(),
            OsString::from(image),
            output_directory.as_os_str().to_owned(),
        ];
        if let Some(selector) = selector {
            expected_arguments.push(OsString::from("--name-contains"));
            expected_arguments.push(OsString::from(selector));
        } else {
            expected_arguments.push(OsString::from("--integration"));
        }
        let expected_argument_count = if selector.is_some() {
            MAX_SELECTED_SMOKE_ARGUMENTS
        } else {
            MAX_SMOKE_ARGUMENTS
        };
        if self.program != bundle.frontend
            || self.arguments.len() != expected_argument_count
            || self.arguments != expected_arguments
            || self.environment.len() != MAX_SMOKE_ENVIRONMENT_VARIABLES
            || self.current_directory != run_root.join("workspace")
            || output_directory != run_root.join("output")
            || temporary_directory != run_root.join("tmp")
        {
            return Err(SmokeFailure::InvalidLaunch(
                "command identity differs from the sealed smoke recipe",
            ));
        }
        if self
            .environment
            .windows(2)
            .any(|pair| pair[0].0 >= pair[1].0)
            || self.environment.iter().any(|(name, value)| {
                name.as_os_str() == HARNESS_TOOLCHAIN_ROOT_ENV
                    || name.as_encoded_bytes().contains(&0)
                    || value.as_encoded_bytes().contains(&0)
            })
            || self
                .program
                .path
                .as_os_str()
                .as_encoded_bytes()
                .contains(&0)
            || self
                .arguments
                .iter()
                .any(|argument| argument.as_encoded_bytes().contains(&0))
        {
            return Err(SmokeFailure::InvalidLaunch(
                "environment is not exact and strictly sorted",
            ));
        }
        let lookup = |name: &str| {
            self.environment
                .iter()
                .find(|(candidate, _)| candidate == name)
                .map(|(_, value)| value.as_os_str())
        };
        if lookup("PATH") != Some(OsString::new().as_os_str())
            || lookup(CHILD_TOOLCHAIN_ROOT_ENV) != Some(bundle.root.as_os_str())
            || lookup("HOME") != Some(run_root.as_os_str())
            || lookup("TMPDIR") != Some(temporary_directory.as_os_str())
        {
            return Err(SmokeFailure::InvalidLaunch(
                "child environment differs from the public compiler contract",
            ));
        }
        let command_bytes = self
            .program
            .path
            .as_os_str()
            .as_encoded_bytes()
            .len()
            .checked_add(
                self.arguments
                    .iter()
                    .map(|argument| argument.as_encoded_bytes().len())
                    .sum::<usize>(),
            )
            .and_then(|bytes| {
                self.environment
                    .iter()
                    .try_fold(bytes, |total, (name, value)| {
                        total
                            .checked_add(name.as_encoded_bytes().len())?
                            .checked_add(value.as_encoded_bytes().len())
                    })
            })
            .ok_or(SmokeFailure::InvalidLaunch("command byte length overflow"))?;
        if command_bytes > MAX_SMOKE_COMMAND_BYTES {
            return Err(SmokeFailure::InvalidLaunch("command byte limit exceeded"));
        }
        Ok(())
    }
}

#[derive(Debug)]
enum ReaderFailure {
    Io(std::io::ErrorKind),
    Allocation,
    State,
}

#[derive(Debug)]
enum ReaderTaskFailure {
    Reader(ReaderFailure),
    TimedOut,
    Panicked,
}

#[derive(Debug)]
enum SupervisorEvent {
    OutputLimit,
    ReaderFailure,
}

#[derive(Debug)]
struct AggregateOutputBudget {
    limit: usize,
    used: usize,
    exceeded: bool,
}

impl AggregateOutputBudget {
    fn retain(&mut self, requested: usize) -> (usize, bool, bool) {
        if self.exceeded {
            return (0, true, false);
        }
        let remaining = self.limit.saturating_sub(self.used);
        let retained = remaining.min(requested);
        self.used = self.used.saturating_add(retained);
        if retained != requested {
            self.exceeded = true;
            (retained, true, true)
        } else {
            (retained, false, false)
        }
    }
}

struct ReaderTask {
    receiver: mpsc::Receiver<Result<Vec<u8>, ReaderFailure>>,
    handle: Option<thread::JoinHandle<()>>,
}

impl ReaderTask {
    fn finish(mut self, deadline: Instant) -> Result<Vec<u8>, ReaderTaskFailure> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ReaderTaskFailure::TimedOut);
        }
        let result = self
            .receiver
            .recv_timeout(remaining)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => ReaderTaskFailure::TimedOut,
                mpsc::RecvTimeoutError::Disconnected => ReaderTaskFailure::Panicked,
            })?;
        let handle = self.handle.take().ok_or(ReaderTaskFailure::Panicked)?;
        if handle.join().is_err() {
            return Err(ReaderTaskFailure::Panicked);
        }
        result.map_err(ReaderTaskFailure::Reader)
    }
}

fn spawn_bounded_reader(
    mut reader: impl Read + Send + 'static,
    stream: ProcessStream,
    budget: Arc<Mutex<AggregateOutputBudget>>,
    events: mpsc::SyncSender<SupervisorEvent>,
) -> Result<ReaderTask, std::io::Error> {
    let (sender, receiver) = mpsc::sync_channel(1);
    let handle = thread::Builder::new()
        .name(format!("wrela-smoke-{stream}"))
        .spawn(move || {
            let result = (|| {
                let mut captured = Vec::new();
                let mut buffer = [0u8; 16 * 1024];
                loop {
                    let read = reader
                        .read(&mut buffer)
                        .map_err(|error| ReaderFailure::Io(error.kind()))?;
                    if read == 0 {
                        break;
                    }
                    let (retained, stop, notify_limit) = budget
                        .lock()
                        .map_err(|_| ReaderFailure::State)?
                        .retain(read);
                    if retained != 0 {
                        captured
                            .try_reserve(retained)
                            .map_err(|_| ReaderFailure::Allocation)?;
                        captured.extend_from_slice(&buffer[..retained]);
                    }
                    if notify_limit {
                        let _ = events.send(SupervisorEvent::OutputLimit);
                    }
                    if stop {
                        break;
                    }
                }
                Ok(captured)
            })();
            if result.is_err() {
                let _ = events.send(SupervisorEvent::ReaderFailure);
            }
            let _ = sender.send(result);
        })?;
    Ok(ReaderTask {
        receiver,
        handle: Some(handle),
    })
}

#[cfg(unix)]
struct ProcessGroupGuard {
    child: Child,
    process_group: u32,
}

#[cfg(unix)]
impl ProcessGroupGuard {
    fn new(child: Child) -> Self {
        let process_group = child.id();
        Self {
            child,
            process_group,
        }
    }

    fn try_wait(&mut self) -> Result<Option<ExitStatus>, std::io::ErrorKind> {
        self.child.try_wait().map_err(|error| error.kind())
    }

    fn terminate_and_reap(&mut self) -> Result<ExitStatus, std::io::ErrorKind> {
        terminate_process_group(self.process_group);
        let _ = self.child.kill();
        self.child.wait().map_err(|error| error.kind())
    }
}

#[cfg(unix)]
impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        terminate_process_group(self.process_group);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(unix)]
fn terminate_process_group(process_group: u32) {
    let group = format!("-{process_group}");
    let _ = Command::new("/bin/kill")
        .args(["-KILL", &group])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(unix)]
fn configure_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt as _;

    command.process_group(0);
}

fn duration_milliseconds(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn bounded_process_failure(
    kind: BoundedProcessFailureKind,
    process_group: Option<u32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
) -> BoundedProcessFailure {
    BoundedProcessFailure {
        kind,
        process_group,
        stdout,
        stderr,
    }
}

fn reader_failure_kind(
    stream: ProcessStream,
    failure: ReaderTaskFailure,
    cleanup_timeout: Duration,
) -> BoundedProcessFailureKind {
    match failure {
        ReaderTaskFailure::Reader(ReaderFailure::Io(kind)) => {
            BoundedProcessFailureKind::Read { stream, kind }
        }
        ReaderTaskFailure::Reader(ReaderFailure::Allocation) => {
            BoundedProcessFailureKind::ReaderAllocation(stream)
        }
        ReaderTaskFailure::Reader(ReaderFailure::State) => {
            BoundedProcessFailureKind::ReaderState(stream)
        }
        ReaderTaskFailure::TimedOut => BoundedProcessFailureKind::CleanupTimedOut {
            milliseconds: duration_milliseconds(cleanup_timeout),
        },
        ReaderTaskFailure::Panicked => BoundedProcessFailureKind::ReaderPanicked(stream),
    }
}

#[cfg(unix)]
fn run_bounded_process(
    mut command: Command,
    policy: BoundedProcessPolicy,
) -> Result<BoundedProcessOutput, BoundedProcessFailure> {
    let policy = policy.validate()?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_process_group(&mut command);
    let child = command.spawn().map_err(|error| {
        bounded_process_failure(
            BoundedProcessFailureKind::Spawn(error.kind()),
            None,
            Vec::new(),
            Vec::new(),
        )
    })?;
    let mut process = ProcessGroupGuard::new(child);
    let process_group = process.process_group;
    let stdout = process.child.stdout.take().ok_or_else(|| {
        bounded_process_failure(
            BoundedProcessFailureKind::MissingPipe(ProcessStream::Stdout),
            Some(process_group),
            Vec::new(),
            Vec::new(),
        )
    })?;
    let stderr = process.child.stderr.take().ok_or_else(|| {
        bounded_process_failure(
            BoundedProcessFailureKind::MissingPipe(ProcessStream::Stderr),
            Some(process_group),
            Vec::new(),
            Vec::new(),
        )
    })?;
    let budget = Arc::new(Mutex::new(AggregateOutputBudget {
        limit: policy.output_bytes,
        used: 0,
        exceeded: false,
    }));
    let (event_sender, event_receiver) = mpsc::sync_channel(4);
    let stdout_task = spawn_bounded_reader(
        stdout,
        ProcessStream::Stdout,
        budget.clone(),
        event_sender.clone(),
    )
    .map_err(|error| {
        bounded_process_failure(
            BoundedProcessFailureKind::ReaderSpawn {
                stream: ProcessStream::Stdout,
                kind: error.kind(),
            },
            Some(process_group),
            Vec::new(),
            Vec::new(),
        )
    })?;
    let stderr_task = match spawn_bounded_reader(
        stderr,
        ProcessStream::Stderr,
        budget.clone(),
        event_sender.clone(),
    ) {
        Ok(task) => task,
        Err(error) => {
            let _ = process.terminate_and_reap();
            let deadline = Instant::now()
                .checked_add(policy.cleanup_timeout)
                .unwrap_or_else(Instant::now);
            let stdout = stdout_task.finish(deadline).unwrap_or_default();
            return Err(bounded_process_failure(
                BoundedProcessFailureKind::ReaderSpawn {
                    stream: ProcessStream::Stderr,
                    kind: error.kind(),
                },
                Some(process_group),
                stdout,
                Vec::new(),
            ));
        }
    };
    let _event_sender = event_sender;
    let deadline = Instant::now()
        .checked_add(policy.wall_timeout)
        .ok_or_else(|| {
            bounded_process_failure(
                BoundedProcessFailureKind::InvalidPolicy,
                Some(process_group),
                Vec::new(),
                Vec::new(),
            )
        })?;
    enum Trigger {
        Exit(ExitStatus),
        Wait(std::io::ErrorKind),
        TimedOut,
        OutputLimit,
        ReaderFailure,
    }
    let trigger = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break Trigger::TimedOut;
        }
        match process.try_wait() {
            Ok(Some(status)) => break Trigger::Exit(status),
            Ok(None) => {}
            Err(kind) => break Trigger::Wait(kind),
        }
        match event_receiver.recv_timeout(remaining.min(PROCESS_STATUS_POLL_INTERVAL)) {
            Ok(SupervisorEvent::OutputLimit) => break Trigger::OutputLimit,
            Ok(SupervisorEvent::ReaderFailure) => break Trigger::ReaderFailure,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break Trigger::ReaderFailure,
        }
    };
    let reaped = process.terminate_and_reap();
    let cleanup_deadline = Instant::now()
        .checked_add(policy.cleanup_timeout)
        .unwrap_or_else(Instant::now);
    let stdout_result = stdout_task.finish(cleanup_deadline);
    let stderr_result = stderr_task.finish(cleanup_deadline);
    let (stdout, stdout_failure) = match stdout_result {
        Ok(stdout) => (stdout, None),
        Err(failure) => (Vec::new(), Some(failure)),
    };
    let (stderr, stderr_failure) = match stderr_result {
        Ok(stderr) => (stderr, None),
        Err(failure) => (Vec::new(), Some(failure)),
    };
    if let Some(failure) = stdout_failure {
        return Err(bounded_process_failure(
            reader_failure_kind(ProcessStream::Stdout, failure, policy.cleanup_timeout),
            Some(process_group),
            stdout,
            stderr,
        ));
    }
    if let Some(failure) = stderr_failure {
        return Err(bounded_process_failure(
            reader_failure_kind(ProcessStream::Stderr, failure, policy.cleanup_timeout),
            Some(process_group),
            stdout,
            stderr,
        ));
    }
    if let Err(kind) = reaped {
        return Err(bounded_process_failure(
            BoundedProcessFailureKind::Wait(kind),
            Some(process_group),
            stdout,
            stderr,
        ));
    }
    let exceeded = budget.lock().map_or(true, |budget| budget.exceeded);
    let kind = if exceeded {
        Some(BoundedProcessFailureKind::OutputLimit {
            bytes: policy.output_bytes,
        })
    } else {
        match trigger {
            Trigger::Wait(kind) => Some(BoundedProcessFailureKind::Wait(kind)),
            Trigger::TimedOut => Some(BoundedProcessFailureKind::TimedOut {
                milliseconds: duration_milliseconds(policy.wall_timeout),
            }),
            Trigger::OutputLimit => Some(BoundedProcessFailureKind::ReaderState(
                ProcessStream::Stdout,
            )),
            Trigger::ReaderFailure => Some(BoundedProcessFailureKind::ReaderState(
                ProcessStream::Stdout,
            )),
            Trigger::Exit(status) if !status.success() => Some(BoundedProcessFailureKind::Exit {
                code: status.code(),
            }),
            Trigger::Exit(_) => None,
        }
    };
    if let Some(kind) = kind {
        return Err(bounded_process_failure(
            kind,
            Some(process_group),
            stdout,
            stderr,
        ));
    }
    Ok(BoundedProcessOutput {
        process_group,
        stdout,
        stderr,
    })
}

#[cfg(not(unix))]
fn run_bounded_process(
    _command: Command,
    policy: BoundedProcessPolicy,
) -> Result<BoundedProcessOutput, BoundedProcessFailure> {
    policy.validate()?;
    Err(bounded_process_failure(
        BoundedProcessFailureKind::UnsupportedHost,
        None,
        Vec::new(),
        Vec::new(),
    ))
}

const APPLICATION_MANIFEST: &[u8] = br#"schema = 1
language = "0.1-design"

[package]
name = "runner-smoke"
version = "0.1.0"
source_root = "src"

[[dependency]]
alias = "core"
package = "wrela-core"
requirement = "=0.1.0"

[[profile]]
name = "development"
mode = "development"
comptime_steps = 1024
comptime_memory_bytes = 1048576
comptime_call_depth = 64
static_bytes = 1048576
peak_bytes = 1048576
event_log_bytes = 0
dma_coherent = false
require_iommu = false
reset_timeout_ns = 1
quarantine_bytes = 0
recording = "disabled"
optimization = "none"
sealed_deployment = false
warnings_as_errors = false
watchdogs = false

[[image]]
name = "bootstrap"
module = "bootstrap.image"
entry = "boot"
target = "aarch64-qemu-virt-uefi"
profile = "development"
"#;

const APPLICATION_SOURCE: &[u8] = br#"module bootstrap.image

from core.image import Image, Target

@image
pub fn boot() -> Image:
    return Image(name="bootstrap", target=Target.aarch64_qemu_virt_uefi)

@test
fn runtime_case():
    # A bounded `while` is outside the comptime evaluator's supported
    # subset, so this keeps the test in the runtime/image tier
    # deterministically (every function is otherwise phase-neutral and
    # would be comptime-legal on its own).
    guard: u32 = 0
    while guard < 1:
        guard += 1
"#;
const APPLICATION_TEST_NAME: &str = "runner-smoke@0.1.0::bootstrap.image::runtime_case";
const APPLICATION_TEST_TIMEOUT_NS: u64 = 30_000_000_000;

const CHECKED_SHIFT_MANIFEST: &[u8] =
    include_bytes!("../../../std/examples/checked-shift-runtime/wrela.toml");
const CHECKED_SHIFT_SOURCE: &[u8] =
    include_bytes!("../../../std/examples/checked-shift-runtime/src/checked_shift/image.wr");
const CHECKED_SHIFT_IMAGE: &str = "checked-shift-runtime";
const CHECKED_SHIFT_TEST_PREFIX: &str = "checked-shift-runtime@0.1.0::checked_shift.image::";
const CHECKED_SHIFT_EVIDENCE_PREFIX: &str = "WRELA_CHECKED_SHIFT_QEMU_EVIDENCE";

const RUNTIME_RESULT_MANIFEST: &[u8] =
    include_bytes!("../../../std/examples/runtime-result/wrela.toml");
const RUNTIME_RESULT_SOURCE: &[u8] =
    include_bytes!("../../../std/examples/runtime-result/src/runtime_result/image.wr");
const RUNTIME_RESULT_IMAGE: &str = "runtime-result";
const RUNTIME_RESULT_TEST_PREFIX: &str = "runtime-result@0.1.0::runtime_result.image::";
const RUNTIME_RESULT_EVIDENCE_PREFIX: &str = "WRELA_RUNTIME_RESULT_QEMU_EVIDENCE";

const RUNTIME_TIMEOUT_MANIFEST: &[u8] =
    include_bytes!("../../../std/examples/runtime-timeout/wrela.toml");
const RUNTIME_TIMEOUT_SOURCE: &[u8] =
    include_bytes!("../../../std/examples/runtime-timeout/src/runtime_timeout/image.wr");
const RUNTIME_TIMEOUT_IMAGE: &str = "runtime-timeout";
const RUNTIME_TIMEOUT_SELECTOR: &str = "checked_arithmetic_fatal_times_out";
const RUNTIME_TIMEOUT_GROUP_TIMEOUT_NS: u64 = 65_000_000_000;
const RUNTIME_TIMEOUT_EVIDENCE_PREFIX: &str = "WRELA_RUNTIME_TIMEOUT_QEMU_EVIDENCE";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CheckedShiftSmokeCase {
    selector: &'static str,
    test_id: u32,
    expected: ExpectedSmokeOutcome,
}

impl CheckedShiftSmokeCase {
    fn qualified_name(self) -> String {
        format!("{CHECKED_SHIFT_TEST_PREFIX}{}", self.selector)
    }
}

const ASSERTION_FAILURE_EXPRESSION: &str = "false";
const ASSERTION_FAILURE_MESSAGE: &str = "intentional runtime assertion failure";
const ASSERTION_FAILURE_FILE: u32 = 0;
const ASSERTION_FAILURE_START: u32 = 493;
const ASSERTION_FAILURE_END: u32 = 498;

const CHECKED_SHIFT_CASES: [CheckedShiftSmokeCase; 4] = [
    // `--name-contains` filters before descriptor creation, so every fresh
    // one-case execution plan assigns its selected runtime test dense id zero.
    CheckedShiftSmokeCase {
        selector: "modular_shift_passes",
        test_id: 0,
        expected: ExpectedSmokeOutcome::Passed,
    },
    CheckedShiftSmokeCase {
        selector: "runtime_assertion_fails",
        test_id: 0,
        expected: ExpectedSmokeOutcome::AssertionFailed,
    },
    CheckedShiftSmokeCase {
        selector: "checked_shift_result_loss",
        test_id: 0,
        expected: ExpectedSmokeOutcome::LanguageFatal(LanguageFatalCause::CheckedShiftResultLoss),
    },
    CheckedShiftSmokeCase {
        selector: "invalid_shift_count",
        test_id: 0,
        expected: ExpectedSmokeOutcome::LanguageFatal(LanguageFatalCause::InvalidShiftCount),
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuntimeResultSmokeCase {
    selector: &'static str,
    test_id: u32,
}

impl RuntimeResultSmokeCase {
    fn qualified_name(self) -> String {
        format!("{RUNTIME_RESULT_TEST_PREFIX}{}", self.selector)
    }
}

const RUNTIME_RESULT_CASES: [RuntimeResultSmokeCase; 2] = [
    // Selection occurs before descriptor construction, so each private
    // one-case plan has the canonical dense test id zero.
    RuntimeResultSmokeCase {
        selector: "result_try_ok_yields_payload",
        test_id: 0,
    },
    RuntimeResultSmokeCase {
        selector: "result_try_err_propagates_exact_error",
        test_id: 0,
    },
];

const REAL_QEMU_EVIDENCE_PREFIX: &str = "WRELA_REAL_QEMU_EVIDENCE";

static HASHER: SoftwareSha256 = SoftwareSha256;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ValidatedSmokeReportEvidence {
    image_digest: Sha256Digest,
    event_stream_digest: Sha256Digest,
    event_stream_bytes: u64,
    canonical_event_stream: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedSmokeOutcome {
    Passed,
    AssertionFailed,
    LanguageFatal(LanguageFatalCause),
}

impl ExpectedSmokeOutcome {
    fn matches_host(self, outcome: &TestOutcome) -> bool {
        match (self, outcome) {
            (Self::Passed, TestOutcome::Passed) => true,
            (
                Self::AssertionFailed,
                TestOutcome::Failed {
                    phase: FailurePhase::Runtime,
                    message,
                },
            ) => message == ASSERTION_FAILURE_MESSAGE,
            (
                Self::LanguageFatal(LanguageFatalCause::CheckedShiftResultLoss),
                TestOutcome::LanguageFatal {
                    cause: LanguageFatalCause::CheckedShiftResultLoss,
                },
            )
            | (
                Self::LanguageFatal(LanguageFatalCause::InvalidShiftCount),
                TestOutcome::LanguageFatal {
                    cause: LanguageFatalCause::InvalidShiftCount,
                },
            ) => true,
            _ => false,
        }
    }

    fn guest(self) -> GuestTestOutcome {
        match self {
            Self::Passed => GuestTestOutcome::Passed,
            Self::AssertionFailed => GuestTestOutcome::Failed {
                message: ASSERTION_FAILURE_MESSAGE.to_owned(),
            },
            Self::LanguageFatal(cause) => GuestTestOutcome::LanguageFatal { cause },
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::AssertionFailed => "assertion-failed",
            Self::LanguageFatal(cause) => language_fatal_cause_name(cause),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CanonicalSmokeEvidence {
    image_digest: Sha256Digest,
    image_bytes: u64,
    report_digest: Sha256Digest,
    report_bytes: u64,
    event_stream_digest: Sha256Digest,
    event_stream_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CheckedShiftExecution {
    evidence: CanonicalSmokeEvidence,
    image: Vec<u8>,
    report: Vec<u8>,
    canonical_event_stream: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeTimeoutExecution {
    evidence: CanonicalSmokeEvidence,
}

impl CanonicalSmokeEvidence {
    fn line(self) -> Result<String, SmokeFailure> {
        if self.image_bytes == 0
            || self.report_bytes == 0
            || self.event_stream_bytes == 0
            || [
                self.image_digest,
                self.report_digest,
                self.event_stream_digest,
            ]
            .iter()
            .any(|digest| digest.as_bytes().iter().all(|byte| *byte == 0))
        {
            return Err(SmokeFailure::InvalidReport(
                "canonical smoke evidence contains a zero identity or extent",
            ));
        }
        Ok(format!(
            "{REAL_QEMU_EVIDENCE_PREFIX} schema=1 image_sha256={} image_bytes={} report_sha256={} report_bytes={} event_stream_sha256={} event_stream_bytes={}",
            self.image_digest.to_hex(),
            self.image_bytes,
            self.report_digest.to_hex(),
            self.report_bytes,
            self.event_stream_digest.to_hex(),
            self.event_stream_bytes,
        ))
    }
}

/// Explicit real-system smoke. Ordinary package gates compile this test but
/// do not run it. Invocation must inject both absolute roots and opt in with
/// `--ignored`; absence is a hard failure rather than a skipped success.
#[test]
#[ignore = "requires an enrolled production toolchain with real QEMU and firmware"]
fn enrolled_bundle_executes_real_qemu_lifecycle() {
    let toolchain_root = required_absolute_environment_path(HARNESS_TOOLCHAIN_ROOT_ENV);
    let run_root = required_absolute_environment_path(RUN_ROOT_ENV);
    let cleanup = RunRootGuard::create(&run_root).unwrap_or_else(|error| panic!("{error}"));

    let target_identity = TargetIdentity::aarch64_qemu_virt_uefi();
    let verification = LocalToolchainVerifier::new(Toolchain::at(&toolchain_root))
        .verify(
            &target_identity,
            LocalToolchainVerificationLimits::standard(),
            &never_cancelled,
        )
        .expect("verify the exact enrolled smoke toolchain");
    assert_eq!(verification.toolchain().root(), toolchain_root);
    let bundle = EnrolledBundle::from_verification(&verification, &target_identity)
        .expect("copy exact verified smoke component identities");

    let workspace = run_root.join("workspace");
    create_private_directory(&workspace);
    create_private_directory(&workspace.join("src"));
    create_private_directory(&workspace.join("src/bootstrap"));
    write_new(&workspace.join("wrela.toml"), APPLICATION_MANIFEST);
    write_new(
        &workspace.join("src/bootstrap/image.wr"),
        APPLICATION_SOURCE,
    );
    let temporary_directory = run_root.join("tmp");
    create_private_directory(&temporary_directory);

    let output_directory = run_root.join("output");
    let launch = SmokeLaunch::new(
        &bundle,
        &run_root,
        &workspace,
        &output_directory,
        &temporary_directory,
    )
    .expect("seal exact production frontend launch");
    launch
        .verify_private_layout(&run_root, &output_directory, &temporary_directory)
        .expect("verify exact private launch filesystem layout");
    let process = match run_bounded_process(launch.command(), BoundedProcessPolicy::real_smoke()) {
        Ok(process) => process,
        Err(process) => {
            let report = observe_failed_test_report(&output_directory.join("test-report.bin"));
            panic!(
                "{}",
                SmokeFailure::FailedTestProcess {
                    process: Box::new(process),
                    report: Box::new(report),
                }
            );
        }
    };
    assert_eq!(process.stdout, b"test passed\n");
    assert!(process.stderr.is_empty());

    let report_path = output_directory.join("test-report.bin");
    let report_bytes = read_bounded_file(&report_path, MAX_SMOKE_REPORT_BYTES)
        .expect("read bounded atomically published test report");
    assert_eq!(
        bundle.target_package.digest,
        verification.target().semantic().content_digest(),
        "selected target model differs from its verified package tree"
    );
    let report_evidence = validate_canonical_smoke_report(&report_bytes, &bundle)
        .expect("validate canonical real-QEMU report and lifecycle");

    let images = find_efi_images(&output_directory).expect("enumerate bounded smoke output tree");
    let [published_image] = images.as_slice() else {
        panic!("real integration smoke must publish exactly one EFI image");
    };
    let image_bytes = read_bounded_file(published_image, MAX_SMOKE_IMAGE_BYTES)
        .expect("read bounded published EFI image");
    let image_digest = HASHER.sha256(&image_bytes);
    assert_eq!(
        report_evidence.image_digest, image_digest,
        "report evidence must bind the exact published EFI image"
    );
    let evidence = CanonicalSmokeEvidence {
        image_digest,
        image_bytes: u64::try_from(image_bytes.len())
            .expect("bounded EFI image byte length must fit u64"),
        report_digest: HASHER.sha256(&report_bytes),
        report_bytes: u64::try_from(report_bytes.len())
            .expect("bounded canonical report byte length must fit u64"),
        event_stream_digest: report_evidence.event_stream_digest,
        event_stream_bytes: report_evidence.event_stream_bytes,
    };
    let evidence_line = evidence
        .line()
        .expect("format canonical real-QEMU evidence");
    // libtest writes `test <name> ... ` without a newline before executing a
    // `--nocapture` test. Terminate that harness-owned progress line first so
    // the machine-consumed evidence has a stable line boundary of its own.
    println!("\n{evidence_line}");
    cleanup
        .cleanup()
        .expect("remove the complete private real-QEMU smoke root");
    assert!(
        !run_root.exists(),
        "smoke cleanup left the private run root"
    );
}

/// Real source-triggered timeout contract. The selected ordinary test executes
/// an existing checked `u8` addition overflow after the generated harness has
/// emitted RunStarted/TestStarted. Arithmetic fatal code 1 is deliberately not
/// promoted into a typed shift fatal by the target runtime, so the guest halts
/// and the production executor must enforce the sealed group timeout.
#[test]
#[ignore = "requires an enrolled production toolchain with real QEMU and firmware"]
fn enrolled_bundle_executes_runtime_timeout_contract() {
    let run_binding = required_runtime_timeout_run_binding();
    let toolchain_root = required_absolute_environment_path(HARNESS_TOOLCHAIN_ROOT_ENV);
    let run_root = required_absolute_environment_path(RUN_ROOT_ENV);
    let cleanup = RunRootGuard::create(&run_root).unwrap_or_else(|error| panic!("{error}"));

    let target_identity = TargetIdentity::aarch64_qemu_virt_uefi();
    let verification = LocalToolchainVerifier::new(Toolchain::at(&toolchain_root))
        .verify(
            &target_identity,
            LocalToolchainVerificationLimits::standard(),
            &never_cancelled,
        )
        .expect("verify the exact enrolled runtime-timeout toolchain");
    let bundle = EnrolledBundle::from_verification(&verification, &target_identity)
        .expect("copy exact verified runtime-timeout component identities");

    let execution = execute_runtime_timeout_case(&bundle, &run_root)
        .unwrap_or_else(|error| panic!("runtime-timeout case: {error}"));
    let evidence_line = runtime_timeout_evidence_line(execution.evidence, &run_binding)
        .expect("format canonical runtime-timeout QEMU evidence");
    cleanup
        .cleanup()
        .expect("remove the complete private runtime-timeout root");
    assert!(
        !run_root.exists(),
        "runtime-timeout cleanup left the private run root"
    );
    println!("\n{evidence_line}");
}

fn execute_runtime_timeout_case(
    bundle: &EnrolledBundle,
    run_root: &Path,
) -> Result<RuntimeTimeoutExecution, SmokeFailure> {
    let workspace = run_root.join("workspace");
    create_private_directory(&workspace);
    create_private_directory(&workspace.join("src"));
    create_private_directory(&workspace.join("src/runtime_timeout"));
    write_new(&workspace.join("wrela.toml"), RUNTIME_TIMEOUT_MANIFEST);
    write_new(
        &workspace.join("src/runtime_timeout/image.wr"),
        RUNTIME_TIMEOUT_SOURCE,
    );
    let temporary_directory = run_root.join("tmp");
    create_private_directory(&temporary_directory);
    let output_directory = run_root.join("output");
    let launch = SmokeLaunch::new_selected(
        bundle,
        run_root,
        &workspace,
        &output_directory,
        &temporary_directory,
        RUNTIME_TIMEOUT_IMAGE,
        RUNTIME_TIMEOUT_SELECTOR,
    )?;
    launch.verify_private_layout(run_root, &output_directory, &temporary_directory)?;

    let completion = run_bounded_process(launch.command(), BoundedProcessPolicy::real_smoke());
    let report_path = output_directory.join("test-report.bin");
    let report_bytes = match read_bounded_file(&report_path, MAX_SMOKE_REPORT_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            return match completion {
                Err(process) => Err(SmokeFailure::FailedTestProcess {
                    process: Box::new(process),
                    report: Box::new(observe_failed_test_report(&report_path)),
                }),
                Ok(_) => Err(error),
            };
        }
    };
    let report_evidence = validate_canonical_runtime_timeout_report(&report_bytes, bundle)?;
    if !completion_matches_runtime_timeout(&completion) {
        return match completion {
            Err(process) => Err(SmokeFailure::FailedTestProcess {
                process: Box::new(process),
                report: Box::new(observe_failed_test_report(&report_path)),
            }),
            Ok(_) => Err(SmokeFailure::InvalidReport(
                "frontend completion differs from the canonical runtime-timeout report",
            )),
        };
    }

    let images = find_efi_images(&output_directory)?;
    let [published_image] = images.as_slice() else {
        return Err(SmokeFailure::InvalidReport(
            "runtime-timeout case did not publish exactly one EFI image",
        ));
    };
    let image_bytes = read_bounded_file(published_image, MAX_SMOKE_IMAGE_BYTES)?;
    let image_digest = HASHER.sha256(&image_bytes);
    if report_evidence.image_digest != image_digest {
        return Err(SmokeFailure::InvalidReport(
            "runtime-timeout report does not bind the published EFI image",
        ));
    }
    Ok(RuntimeTimeoutExecution {
        evidence: CanonicalSmokeEvidence {
            image_digest,
            image_bytes: u64::try_from(image_bytes.len()).map_err(|_| {
                SmokeFailure::InvalidReport("EFI image byte length does not fit u64")
            })?,
            report_digest: HASHER.sha256(&report_bytes),
            report_bytes: u64::try_from(report_bytes.len())
                .map_err(|_| SmokeFailure::InvalidReport("report byte length does not fit u64"))?,
            event_stream_digest: report_evidence.event_stream_digest,
            event_stream_bytes: report_evidence.event_stream_bytes,
        },
    })
}

fn completion_matches_runtime_timeout(
    completion: &Result<BoundedProcessOutput, BoundedProcessFailure>,
) -> bool {
    matches!(
        completion,
        Err(BoundedProcessFailure {
            kind: BoundedProcessFailureKind::Exit { code: Some(code) },
            stdout,
            stderr,
            ..
        }) if *code != 0 && stdout == b"test failed\n" && stderr.is_empty()
    )
}

/// Real checked-shift execution contract. Each selector receives a fresh
/// private workspace/output/tmp root and must consume the checked-in source,
/// installed frontend/backend, published EFI, QEMU event stream, and
/// atomically published canonical report. A nonzero public command result is
/// accepted only after the typed report proves the exact language-fatal cause.
#[test]
#[ignore = "requires an enrolled production toolchain with checked-shift runtime support"]
fn enrolled_bundle_executes_checked_shift_runtime_contract() {
    execute_checked_shift_runtime_contract(true);
}

/// Current development-tranche consumer. It executes the current assertion,
/// checked-shift, and recoverable Result cases once each. Path-distinct replay
/// remains confined to the historical reproducibility consumer above.
#[test]
#[ignore = "requires an enrolled production toolchain with checked-shift runtime support"]
fn enrolled_bundle_executes_current_tranche_runtime_contract() {
    execute_checked_shift_runtime_contract(false);
}

fn execute_checked_shift_runtime_contract(replay_passing_case: bool) {
    let toolchain_root = required_absolute_environment_path(HARNESS_TOOLCHAIN_ROOT_ENV);
    let run_root = required_absolute_environment_path(RUN_ROOT_ENV);
    let cleanup = RunRootGuard::create(&run_root).unwrap_or_else(|error| panic!("{error}"));

    let target_identity = TargetIdentity::aarch64_qemu_virt_uefi();
    let verification = LocalToolchainVerifier::new(Toolchain::at(&toolchain_root))
        .verify(
            &target_identity,
            LocalToolchainVerificationLimits::standard(),
            &never_cancelled,
        )
        .expect("verify the exact enrolled checked-shift toolchain");
    let bundle = EnrolledBundle::from_verification(&verification, &target_identity)
        .expect("copy exact verified checked-shift component identities");

    let mut evidence_lines = Vec::new();
    for case in CHECKED_SHIFT_CASES {
        let case_root = run_root.join(case.selector);
        let execution = execute_checked_shift_case(&bundle, &case_root, case)
            .unwrap_or_else(|error| panic!("checked-shift case {}: {error}", case.selector));
        assert!(
            !case_root.exists(),
            "checked-shift case cleanup left private residue"
        );
        if replay_passing_case && case.expected == ExpectedSmokeOutcome::Passed {
            let replay_root = run_root.join(format!("{}-replay", case.selector));
            let replay = execute_checked_shift_case(&bundle, &replay_root, case)
                .unwrap_or_else(|error| panic!("checked-shift replay {}: {error}", case.selector));
            assert!(
                !replay_root.exists(),
                "checked-shift replay cleanup left private residue"
            );
            assert_eq!(
                replay.image, execution.image,
                "path-distinct checked-shift replay changed the generated EFI bytes"
            );
            assert_eq!(
                replay.report, execution.report,
                "path-distinct checked-shift replay changed the canonical report bytes"
            );
            assert_eq!(
                replay.canonical_event_stream, execution.canonical_event_stream,
                "path-distinct checked-shift replay changed the canonical public event-stream bytes"
            );
            assert_eq!(
                replay.evidence, execution.evidence,
                "path-distinct checked-shift replay changed an artifact identity or extent"
            );
        }
        evidence_lines.push(
            checked_shift_evidence_line(case, execution.evidence)
                .expect("format canonical checked-shift QEMU evidence"),
        );
    }
    if !replay_passing_case {
        for case in RUNTIME_RESULT_CASES {
            let case_root = run_root.join(case.selector);
            let execution = execute_runtime_result_case(&bundle, &case_root, case)
                .unwrap_or_else(|error| panic!("runtime-result case {}: {error}", case.selector));
            assert!(
                !case_root.exists(),
                "runtime-result case cleanup left private residue"
            );
            evidence_lines.push(
                runtime_result_evidence_line(case, execution.evidence)
                    .expect("format canonical runtime-result QEMU evidence"),
            );
        }
    }
    cleanup
        .cleanup()
        .expect("remove every private checked-shift QEMU run");
    assert!(
        !run_root.exists(),
        "checked-shift cleanup left the private run root"
    );
    println!();
    for line in evidence_lines {
        println!("{line}");
    }
}

fn execute_checked_shift_case(
    bundle: &EnrolledBundle,
    case_root: &Path,
    case: CheckedShiftSmokeCase,
) -> Result<CheckedShiftExecution, SmokeFailure> {
    let cleanup = RunRootGuard::create(case_root)?;
    let workspace = case_root.join("workspace");
    create_private_directory(&workspace);
    create_private_directory(&workspace.join("src"));
    create_private_directory(&workspace.join("src/checked_shift"));
    write_new(&workspace.join("wrela.toml"), CHECKED_SHIFT_MANIFEST);
    write_new(
        &workspace.join("src/checked_shift/image.wr"),
        CHECKED_SHIFT_SOURCE,
    );
    let temporary_directory = case_root.join("tmp");
    create_private_directory(&temporary_directory);
    let output_directory = case_root.join("output");
    let launch = SmokeLaunch::new_selected(
        bundle,
        case_root,
        &workspace,
        &output_directory,
        &temporary_directory,
        CHECKED_SHIFT_IMAGE,
        case.selector,
    )?;
    launch.verify_private_layout(case_root, &output_directory, &temporary_directory)?;

    let completion = run_bounded_process(launch.command(), BoundedProcessPolicy::real_smoke());
    let report_path = output_directory.join("test-report.bin");
    let report_bytes = match read_bounded_file(&report_path, MAX_SMOKE_REPORT_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            return match completion {
                Err(process) => Err(SmokeFailure::FailedTestProcess {
                    process: Box::new(process),
                    report: Box::new(observe_failed_test_report(&report_path)),
                }),
                Ok(_) => Err(error),
            };
        }
    };
    let report_evidence = validate_canonical_runtime_report(
        &report_bytes,
        bundle,
        case.test_id,
        &case.qualified_name(),
        case.expected,
    )?;

    if !completion_matches_expected(case.expected, &completion) {
        return match completion {
            Err(process) => Err(SmokeFailure::FailedTestProcess {
                process: Box::new(process),
                report: Box::new(observe_failed_test_report(&report_path)),
            }),
            Ok(_) => Err(SmokeFailure::InvalidReport(
                "frontend completion differs from the canonical typed report",
            )),
        };
    }

    let images = find_efi_images(&output_directory)?;
    let [published_image] = images.as_slice() else {
        return Err(SmokeFailure::InvalidReport(
            "checked-shift case did not publish exactly one EFI image",
        ));
    };
    let image_bytes = read_bounded_file(published_image, MAX_SMOKE_IMAGE_BYTES)?;
    let image_digest = HASHER.sha256(&image_bytes);
    if report_evidence.image_digest != image_digest {
        return Err(SmokeFailure::InvalidReport(
            "checked-shift report does not bind the published EFI image",
        ));
    }
    let evidence = CanonicalSmokeEvidence {
        image_digest,
        image_bytes: u64::try_from(image_bytes.len())
            .map_err(|_| SmokeFailure::InvalidReport("EFI image byte length does not fit u64"))?,
        report_digest: HASHER.sha256(&report_bytes),
        report_bytes: u64::try_from(report_bytes.len())
            .map_err(|_| SmokeFailure::InvalidReport("report byte length does not fit u64"))?,
        event_stream_digest: report_evidence.event_stream_digest,
        event_stream_bytes: report_evidence.event_stream_bytes,
    };
    let execution = CheckedShiftExecution {
        evidence,
        image: image_bytes,
        report: report_bytes,
        canonical_event_stream: report_evidence.canonical_event_stream,
    };
    cleanup.cleanup()?;
    Ok(execution)
}

fn execute_runtime_result_case(
    bundle: &EnrolledBundle,
    case_root: &Path,
    case: RuntimeResultSmokeCase,
) -> Result<CheckedShiftExecution, SmokeFailure> {
    let cleanup = RunRootGuard::create(case_root)?;
    let workspace = case_root.join("workspace");
    create_private_directory(&workspace);
    create_private_directory(&workspace.join("src"));
    create_private_directory(&workspace.join("src/runtime_result"));
    write_new(&workspace.join("wrela.toml"), RUNTIME_RESULT_MANIFEST);
    write_new(
        &workspace.join("src/runtime_result/image.wr"),
        RUNTIME_RESULT_SOURCE,
    );
    let temporary_directory = case_root.join("tmp");
    create_private_directory(&temporary_directory);
    let output_directory = case_root.join("output");
    let launch = SmokeLaunch::new_selected(
        bundle,
        case_root,
        &workspace,
        &output_directory,
        &temporary_directory,
        RUNTIME_RESULT_IMAGE,
        case.selector,
    )?;
    launch.verify_private_layout(case_root, &output_directory, &temporary_directory)?;

    let completion = run_bounded_process(launch.command(), BoundedProcessPolicy::real_smoke());
    let report_path = output_directory.join("test-report.bin");
    let report_bytes = match read_bounded_file(&report_path, MAX_SMOKE_REPORT_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            return match completion {
                Err(process) => Err(SmokeFailure::FailedTestProcess {
                    process: Box::new(process),
                    report: Box::new(observe_failed_test_report(&report_path)),
                }),
                Ok(_) => Err(error),
            };
        }
    };
    let expected = ExpectedSmokeOutcome::Passed;
    let report_evidence = validate_canonical_runtime_report(
        &report_bytes,
        bundle,
        case.test_id,
        &case.qualified_name(),
        expected,
    )?;
    if !completion_matches_expected(expected, &completion) {
        return match completion {
            Err(process) => Err(SmokeFailure::FailedTestProcess {
                process: Box::new(process),
                report: Box::new(observe_failed_test_report(&report_path)),
            }),
            Ok(_) => Err(SmokeFailure::InvalidReport(
                "frontend completion differs from the canonical runtime-result report",
            )),
        };
    }

    let images = find_efi_images(&output_directory)?;
    let [published_image] = images.as_slice() else {
        return Err(SmokeFailure::InvalidReport(
            "runtime-result case did not publish exactly one EFI image",
        ));
    };
    let image_bytes = read_bounded_file(published_image, MAX_SMOKE_IMAGE_BYTES)?;
    let image_digest = HASHER.sha256(&image_bytes);
    if report_evidence.image_digest != image_digest {
        return Err(SmokeFailure::InvalidReport(
            "runtime-result report does not bind the published EFI image",
        ));
    }
    let evidence = CanonicalSmokeEvidence {
        image_digest,
        image_bytes: u64::try_from(image_bytes.len())
            .map_err(|_| SmokeFailure::InvalidReport("EFI image byte length does not fit u64"))?,
        report_digest: HASHER.sha256(&report_bytes),
        report_bytes: u64::try_from(report_bytes.len())
            .map_err(|_| SmokeFailure::InvalidReport("report byte length does not fit u64"))?,
        event_stream_digest: report_evidence.event_stream_digest,
        event_stream_bytes: report_evidence.event_stream_bytes,
    };
    let execution = CheckedShiftExecution {
        evidence,
        image: image_bytes,
        report: report_bytes,
        canonical_event_stream: report_evidence.canonical_event_stream,
    };
    cleanup.cleanup()?;
    Ok(execution)
}

fn completion_matches_expected(
    expected: ExpectedSmokeOutcome,
    completion: &Result<BoundedProcessOutput, BoundedProcessFailure>,
) -> bool {
    match (expected, completion) {
        (ExpectedSmokeOutcome::Passed, Ok(process)) => {
            process.stdout == b"test passed\n" && process.stderr.is_empty()
        }
        (
            ExpectedSmokeOutcome::AssertionFailed | ExpectedSmokeOutcome::LanguageFatal(_),
            Err(BoundedProcessFailure {
                kind: BoundedProcessFailureKind::Exit { code: Some(code) },
                stdout,
                stderr,
                ..
            }),
        ) => *code != 0 && stdout == b"test failed\n" && stderr.is_empty(),
        _ => false,
    }
}

fn checked_shift_evidence_line(
    case: CheckedShiftSmokeCase,
    evidence: CanonicalSmokeEvidence,
) -> Result<String, SmokeFailure> {
    let _ = evidence.line()?;
    Ok(format!(
        "{CHECKED_SHIFT_EVIDENCE_PREFIX} schema=1 selector={} outcome={} image_sha256={} image_bytes={} report_sha256={} report_bytes={} event_stream_sha256={} event_stream_bytes={}",
        case.selector,
        case.expected.label(),
        evidence.image_digest.to_hex(),
        evidence.image_bytes,
        evidence.report_digest.to_hex(),
        evidence.report_bytes,
        evidence.event_stream_digest.to_hex(),
        evidence.event_stream_bytes,
    ))
}

fn runtime_result_evidence_line(
    case: RuntimeResultSmokeCase,
    evidence: CanonicalSmokeEvidence,
) -> Result<String, SmokeFailure> {
    let _ = evidence.line()?;
    Ok(format!(
        "{RUNTIME_RESULT_EVIDENCE_PREFIX} schema=1 selector={} outcome=passed image_sha256={} image_bytes={} report_sha256={} report_bytes={} event_stream_sha256={} event_stream_bytes={}",
        case.selector,
        evidence.image_digest.to_hex(),
        evidence.image_bytes,
        evidence.report_digest.to_hex(),
        evidence.report_bytes,
        evidence.event_stream_digest.to_hex(),
        evidence.event_stream_bytes,
    ))
}

fn runtime_timeout_evidence_line(
    evidence: CanonicalSmokeEvidence,
    run_binding: &str,
) -> Result<String, SmokeFailure> {
    let _ = evidence.line()?;
    if decode_runtime_timeout_run_binding(Some(OsString::from(run_binding))).as_deref()
        != Ok(run_binding)
        || evidence.image_bytes > MAX_SMOKE_IMAGE_BYTES
        || evidence.report_bytes > MAX_SMOKE_REPORT_BYTES
        || evidence.event_stream_bytes > MAX_SMOKE_REPORT_BYTES
    {
        return Err(SmokeFailure::InvalidReport(
            "runtime-timeout evidence exceeds a semantic bound or has an invalid run binding",
        ));
    }
    let line = format!(
        "{RUNTIME_TIMEOUT_EVIDENCE_PREFIX} schema=1 outcome=runtime-timeout timeout_ns={RUNTIME_TIMEOUT_GROUP_TIMEOUT_NS} run_binding_sha256={run_binding} image_sha256={} image_bytes={} report_sha256={} report_bytes={} event_stream_sha256={} event_stream_bytes={}",
        evidence.image_digest.to_hex(),
        evidence.image_bytes,
        evidence.report_digest.to_hex(),
        evidence.report_bytes,
        evidence.event_stream_digest.to_hex(),
        evidence.event_stream_bytes,
    );
    if line.len() > 1024 || line.contains(['/', '\\', '\n', '\r']) {
        return Err(SmokeFailure::InvalidReport(
            "runtime-timeout evidence is oversized or path-bearing",
        ));
    }
    Ok(line)
}

fn validate_canonical_smoke_report(
    bytes: &[u8],
    bundle: &EnrolledBundle,
) -> Result<ValidatedSmokeReportEvidence, SmokeFailure> {
    validate_canonical_runtime_report(
        bytes,
        bundle,
        0,
        APPLICATION_TEST_NAME,
        ExpectedSmokeOutcome::Passed,
    )
}

fn validate_canonical_runtime_report(
    bytes: &[u8],
    bundle: &EnrolledBundle,
    expected_test_id: u32,
    expected_test_name: &str,
    expected_outcome: ExpectedSmokeOutcome,
) -> Result<ValidatedSmokeReportEvidence, SmokeFailure> {
    let report_limit = u64::try_from(bytes.len())
        .map_err(|_| SmokeFailure::InvalidReport("report byte length does not fit u64"))?;
    if report_limit == 0 || report_limit > MAX_SMOKE_REPORT_BYTES {
        return Err(SmokeFailure::InvalidReport(
            "report byte length exceeds the smoke policy",
        ));
    }
    let codec = CanonicalTestReportCodec::new();
    let report = codec
        .decode(bytes, report_limit, &never_cancelled)
        .map_err(|_| SmokeFailure::InvalidReport("canonical decoding failed"))?;
    let canonical = codec
        .encode(&report, report_limit, &never_cancelled)
        .map_err(|_| SmokeFailure::InvalidReport("canonical re-encoding failed"))?;
    if canonical != bytes {
        return Err(SmokeFailure::InvalidReport(
            "decoded report bytes are not canonical",
        ));
    }
    if report.schema != TEST_REPORT_SCHEMA
        || report.started_unix_ns.is_some()
        || report.duration_ns.is_some()
        || !report.unit.is_empty()
        || report.images.len() != 1
        || report.build.compiler != bundle.frontend.digest
        || report.build.language != wrela_build_model::LanguageRevision::Design0_1
        || report.build.target != TargetIdentity::aarch64_qemu_virt_uefi()
        || report.build.target_package != bundle.target_package.digest
        || report.build.standard_library != bundle.standard_library.digest
        || [
            report.build.source_graph,
            report.build.request,
            report.build.profile,
        ]
        .iter()
        .any(|digest| digest.as_bytes().iter().all(|byte| *byte == 0))
    {
        return Err(SmokeFailure::InvalidReport(
            "report build identity differs from the verified smoke inputs",
        ));
    }
    let image = report
        .images
        .first()
        .ok_or(SmokeFailure::InvalidReport("missing image result"))?;
    if image.group.0 != 0 || image.infrastructure_failure.is_some() || image.cases.len() != 1 {
        return Err(SmokeFailure::InvalidReport(
            "real integration smoke did not publish one successful image group",
        ));
    }
    let case = image
        .cases
        .first()
        .ok_or(SmokeFailure::InvalidReport("missing runtime test result"))?;
    if case.descriptor.id.0 != expected_test_id
        || case.descriptor.name != expected_test_name
        || case.descriptor.kind != TestKind::IntegrationImage
        || case.descriptor.timeout_ns != APPLICATION_TEST_TIMEOUT_NS
        || !expected_outcome.matches_host(&case.outcome)
    {
        return Err(SmokeFailure::InvalidReport(
            "runtime test result differs from the enrolled smoke source",
        ));
    }
    let evidence = &image.evidence;
    if evidence.target_digest != bundle.target_package.digest
        || evidence.emulator_digest != Some(bundle.emulator.digest)
        || evidence.scenario_digest.is_some()
        || evidence.exit_code != Some(0)
        || !evidence.stderr.is_empty()
    {
        return Err(SmokeFailure::InvalidReport(
            "execution evidence differs from the verified emulator and target",
        ));
    }
    let image_digest = evidence.image_digest.ok_or(SmokeFailure::InvalidReport(
        "execution evidence omitted the image digest",
    ))?;
    let command_digest = evidence.command_digest.ok_or(SmokeFailure::InvalidReport(
        "execution evidence omitted the command digest",
    ))?;
    let event_stream_digest = evidence
        .event_stream_digest
        .ok_or(SmokeFailure::InvalidReport(
            "execution evidence omitted the event-stream digest",
        ))?;
    let recomputed_event_stream = CanonicalImageHarness::new()
        .event_stream_digest(&image.events, &never_cancelled)
        .map_err(|_| SmokeFailure::InvalidReport("event-stream digest recomputation failed"))?;
    if event_stream_digest != recomputed_event_stream {
        return Err(SmokeFailure::InvalidReport(
            "event-stream digest differs from the canonical lifecycle",
        ));
    }
    let canonical_event_stream = canonical_event_stream_encoding(&image.events)?;
    let event_stream_bytes = u64::try_from(canonical_event_stream.len()).map_err(|_| {
        SmokeFailure::InvalidReport("canonical event-stream length does not fit u64")
    })?;
    for digest in [image_digest, command_digest, event_stream_digest] {
        if digest.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(SmokeFailure::InvalidReport(
                "execution evidence contains an all-zero digest",
            ));
        }
    }
    if expected_outcome == ExpectedSmokeOutcome::AssertionFailed {
        validate_real_assertion_failure_lifecycle(&image.events, case.descriptor.id)?;
    } else {
        validate_real_producer_lifecycle(
            &image.events,
            case.descriptor.id,
            &expected_outcome.guest(),
        )?;
    }
    Ok(ValidatedSmokeReportEvidence {
        image_digest,
        event_stream_digest,
        event_stream_bytes,
        canonical_event_stream,
    })
}

fn validate_canonical_runtime_timeout_report(
    bytes: &[u8],
    bundle: &EnrolledBundle,
) -> Result<ValidatedSmokeReportEvidence, SmokeFailure> {
    let report_limit = u64::try_from(bytes.len())
        .map_err(|_| SmokeFailure::InvalidReport("report byte length does not fit u64"))?;
    if report_limit == 0 || report_limit > MAX_SMOKE_REPORT_BYTES {
        return Err(SmokeFailure::InvalidReport(
            "report byte length exceeds the smoke policy",
        ));
    }
    let codec = CanonicalTestReportCodec::new();
    let report = codec
        .decode(bytes, report_limit, &never_cancelled)
        .map_err(|_| SmokeFailure::InvalidReport("canonical decoding failed"))?;
    let canonical = codec
        .encode(&report, report_limit, &never_cancelled)
        .map_err(|_| SmokeFailure::InvalidReport("canonical re-encoding failed"))?;
    if canonical != bytes {
        return Err(SmokeFailure::InvalidReport(
            "decoded report bytes are not canonical",
        ));
    }
    if report.schema != TEST_REPORT_SCHEMA
        || report.started_unix_ns.is_some()
        || report.duration_ns.is_some()
        || !report.unit.is_empty()
        || report.images.len() != 1
        || report.build.compiler != bundle.frontend.digest
        || report.build.language != wrela_build_model::LanguageRevision::Design0_1
        || report.build.target != TargetIdentity::aarch64_qemu_virt_uefi()
        || report.build.target_package != bundle.target_package.digest
        || report.build.standard_library != bundle.standard_library.digest
        || [
            report.build.source_graph,
            report.build.request,
            report.build.profile,
        ]
        .iter()
        .any(|digest| digest.as_bytes().iter().all(|byte| *byte == 0))
    {
        return Err(SmokeFailure::InvalidReport(
            "runtime-timeout build identity differs from the verified inputs",
        ));
    }
    let image = report
        .images
        .first()
        .ok_or(SmokeFailure::InvalidReport("missing image result"))?;
    if image.group.0 != 0
        || !image.cases.is_empty()
        || !matches!(
            &image.infrastructure_failure,
            Some(TestOutcome::TimedOut {
                phase: FailurePhase::Runtime,
                timeout_ns,
            }) if *timeout_ns == RUNTIME_TIMEOUT_GROUP_TIMEOUT_NS
        )
    {
        return Err(SmokeFailure::InvalidReport(
            "runtime-timeout outcome is not the exact runtime infrastructure timeout",
        ));
    }
    if image.events.len() != 2
        || image.events.iter().enumerate().any(|(sequence, event)| {
            event.protocol != TEST_PROTOCOL_VERSION
                || u64::try_from(sequence).ok() != Some(event.sequence)
        })
        || !matches!(
            &image.events[0].kind,
            TestEventKind::RunStarted { test_count: 1 }
        )
        || !matches!(
            &image.events[1].kind,
            TestEventKind::TestStarted {
                test: wrela_test_model::TestId(0)
            }
        )
    {
        return Err(SmokeFailure::InvalidReport(
            "runtime-timeout lifecycle is not the exact complete two-event prefix",
        ));
    }
    let evidence = &image.evidence;
    if evidence.target_digest != bundle.target_package.digest
        || evidence.emulator_digest != Some(bundle.emulator.digest)
        || evidence.scenario_digest.is_some()
        || evidence.exit_code.is_some()
        || !evidence.stderr.is_empty()
    {
        return Err(SmokeFailure::InvalidReport(
            "runtime-timeout evidence differs from the verified emulator and target",
        ));
    }
    let image_digest = evidence.image_digest.ok_or(SmokeFailure::InvalidReport(
        "runtime-timeout evidence omitted the image digest",
    ))?;
    let command_digest = evidence.command_digest.ok_or(SmokeFailure::InvalidReport(
        "runtime-timeout evidence omitted the command digest",
    ))?;
    let event_stream_digest = evidence
        .event_stream_digest
        .ok_or(SmokeFailure::InvalidReport(
            "runtime-timeout evidence omitted the event-stream digest",
        ))?;
    if [image_digest, command_digest, event_stream_digest]
        .iter()
        .any(|digest| digest.as_bytes().iter().all(|byte| *byte == 0))
    {
        return Err(SmokeFailure::InvalidReport(
            "runtime-timeout execution evidence contains an all-zero digest",
        ));
    }
    let recomputed_event_stream = CanonicalImageHarness::new()
        .event_stream_digest(&image.events, &never_cancelled)
        .map_err(|_| SmokeFailure::InvalidReport("event-stream digest recomputation failed"))?;
    if event_stream_digest != recomputed_event_stream {
        return Err(SmokeFailure::InvalidReport(
            "runtime-timeout event-stream digest differs from its complete prefix",
        ));
    }
    let canonical_event_stream = canonical_event_stream_encoding(&image.events)?;
    let event_stream_bytes = u64::try_from(canonical_event_stream.len()).map_err(|_| {
        SmokeFailure::InvalidReport("canonical event-stream length does not fit u64")
    })?;
    if event_stream_bytes == 0 {
        return Err(SmokeFailure::InvalidReport(
            "runtime-timeout event-stream prefix is empty",
        ));
    }
    Ok(ValidatedSmokeReportEvidence {
        image_digest,
        event_stream_digest,
        event_stream_bytes,
        canonical_event_stream,
    })
}

fn observe_failed_test_report(path: &Path) -> FailedReportObservation {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return FailedReportObservation::Missing;
        }
        Err(_) => return FailedReportObservation::UnreadableOrUnsafe,
    };
    if !bounded_regular_file_observation(&metadata) {
        return FailedReportObservation::UnreadableOrUnsafe;
    }
    if metadata.len() == 0 || metadata.len() > MAX_SMOKE_REPORT_BYTES {
        return FailedReportObservation::InvalidLength;
    }
    let bytes = match read_bounded_file(path, MAX_SMOKE_REPORT_BYTES) {
        Ok(bytes) => bytes,
        Err(_) => return FailedReportObservation::UnreadableOrUnsafe,
    };
    diagnose_canonical_failed_report(&bytes)
}

fn diagnose_canonical_failed_report(bytes: &[u8]) -> FailedReportObservation {
    let report_limit = match u64::try_from(bytes.len()) {
        Ok(report_limit) if report_limit != 0 && report_limit <= MAX_SMOKE_REPORT_BYTES => {
            report_limit
        }
        _ => return FailedReportObservation::InvalidLength,
    };
    let codec = CanonicalTestReportCodec::new();
    let report = match codec.decode(bytes, report_limit, &never_cancelled) {
        Ok(report) => report,
        Err(_) => return FailedReportObservation::DecodeFailed,
    };
    let canonical = match codec.encode(&report, report_limit, &never_cancelled) {
        Ok(canonical) => canonical,
        Err(_) => return FailedReportObservation::ReencodeFailed,
    };
    if canonical != bytes {
        return FailedReportObservation::NonCanonical;
    }
    if report.schema != TEST_REPORT_SCHEMA {
        return FailedReportObservation::UnsupportedSchema(report.schema);
    }

    let mut failed_outcomes = 0_u64;
    let mut first_failure = None;
    for (index, case) in report.unit.iter().enumerate() {
        let scope = FailedReportScope::UnitCase { index };
        if case.descriptor.kind != TestKind::ComptimeUnit
            || !outcome_is_semantically_valid(scope, &case.outcome)
        {
            return FailedReportObservation::SemanticallyInvalid;
        }
        if !matches!(case.outcome, TestOutcome::Passed) {
            failed_outcomes = match failed_outcomes.checked_add(1) {
                Some(count) => count,
                None => return FailedReportObservation::DiagnosticResourceLimit,
            };
            if first_failure.is_none() {
                let outcome = match FailedOutcomeDiagnostic::observe_nonpassing(&case.outcome) {
                    Ok(outcome) => outcome,
                    Err(error) => return error,
                };
                first_failure = Some((scope, outcome));
            }
        }
    }
    for image in &report.images {
        if let Some(outcome) = &image.infrastructure_failure {
            let scope = FailedReportScope::ImageInfrastructure {
                group: image.group.0,
            };
            if !outcome_is_semantically_valid(scope, outcome) {
                return FailedReportObservation::SemanticallyInvalid;
            }
            failed_outcomes = match failed_outcomes.checked_add(1) {
                Some(count) => count,
                None => return FailedReportObservation::DiagnosticResourceLimit,
            };
            if first_failure.is_none() {
                let outcome = match FailedOutcomeDiagnostic::observe_nonpassing(outcome) {
                    Ok(outcome) => outcome,
                    Err(error) => return error,
                };
                first_failure = Some((scope, outcome));
            }
        }
        for (index, case) in image.cases.iter().enumerate() {
            let scope = FailedReportScope::ImageCase {
                group: image.group.0,
                index,
            };
            if !matches!(
                case.descriptor.kind,
                TestKind::IntegrationImage | TestKind::DeclaredImage
            ) || !outcome_is_semantically_valid(scope, &case.outcome)
            {
                return FailedReportObservation::SemanticallyInvalid;
            }
            if !matches!(case.outcome, TestOutcome::Passed) {
                failed_outcomes = match failed_outcomes.checked_add(1) {
                    Some(count) => count,
                    None => return FailedReportObservation::DiagnosticResourceLimit,
                };
                if first_failure.is_none() {
                    let outcome = match FailedOutcomeDiagnostic::observe_nonpassing(&case.outcome) {
                        Ok(outcome) => outcome,
                        Err(error) => return error,
                    };
                    first_failure = Some((scope, outcome));
                }
            }
        }
    }

    let Some((first_scope, first_outcome)) = first_failure else {
        return FailedReportObservation::SemanticallyInvalid;
    };

    FailedReportObservation::Canonical(Box::new(CanonicalFailedReportDiagnostic {
        bytes: report_limit,
        failed_outcomes,
        first_scope,
        first_outcome,
    }))
}

fn canonical_event_stream_encoding(
    events: &[wrela_test_model::TestEvent],
) -> Result<Vec<u8>, SmokeFailure> {
    let event_limit = u32::try_from(events.len().max(1)).map_err(|_| {
        SmokeFailure::InvalidReport("event-stream count does not fit protocol limits")
    })?;
    let limits = ProtocolLimits {
        events: event_limit,
        ..ProtocolLimits::standard()
    };
    let maximum_bytes = usize::try_from(MAX_SMOKE_REPORT_BYTES).map_err(|_| {
        SmokeFailure::InvalidReport("event-stream byte limit does not fit host usize")
    })?;
    events.iter().try_fold(Vec::new(), |mut stream, event| {
        let encoded = seal_encoded_event(&CanonicalTestEventCodec, event, limits, &never_cancelled)
            .map_err(|_| {
                SmokeFailure::InvalidReport("canonical event-stream byte measurement failed")
            })?;
        let new_length = stream
            .len()
            .checked_add(encoded.bytes().len())
            .filter(|length| *length <= maximum_bytes)
            .ok_or(SmokeFailure::InvalidReport(
                "canonical event-stream byte limit exceeded",
            ))?;
        stream
            .try_reserve_exact(new_length.saturating_sub(stream.len()))
            .map_err(|_| {
                SmokeFailure::InvalidReport("cannot allocate canonical event-stream buffer")
            })?;
        stream.extend_from_slice(encoded.bytes());
        Ok(stream)
    })
}

fn validate_real_producer_lifecycle(
    events: &[wrela_test_model::TestEvent],
    test: wrela_test_model::TestId,
    expected_outcome: &GuestTestOutcome,
) -> Result<(), SmokeFailure> {
    if events.len() != 4 {
        return Err(SmokeFailure::InvalidReport(
            "guest lifecycle does not contain exactly four events",
        ));
    }
    for (sequence, event) in events.iter().enumerate() {
        let expected = u64::try_from(sequence).map_err(|_| {
            SmokeFailure::InvalidReport("guest lifecycle sequence does not fit u64")
        })?;
        if event.protocol != TEST_PROTOCOL_VERSION || event.sequence != expected {
            return Err(SmokeFailure::InvalidReport(
                "guest lifecycle protocol or sequence differs",
            ));
        }
    }
    let finished_matches = matches!(
        &events[2].kind,
        TestEventKind::TestFinished {
            test: actual,
            outcome,
        } if *actual == test && outcome == expected_outcome
    );
    let expected_summary = if matches!(expected_outcome, GuestTestOutcome::Passed) {
        (1, 0)
    } else {
        (0, 1)
    };
    let summary_matches = matches!(
        events[3].kind,
        TestEventKind::RunFinished { passed, failed }
            if (passed, failed) == expected_summary
    );
    if !matches!(events[0].kind, TestEventKind::RunStarted { test_count: 1 })
        || !matches!(
            events[1].kind,
            TestEventKind::TestStarted { test: actual } if actual == test
        )
        || !finished_matches
        || !summary_matches
    {
        return Err(SmokeFailure::InvalidReport(
            "guest lifecycle shape differs from the real producer contract",
        ));
    }
    Ok(())
}

fn validate_real_assertion_failure_lifecycle(
    events: &[wrela_test_model::TestEvent],
    test: wrela_test_model::TestId,
) -> Result<(), SmokeFailure> {
    if events.len() != 5 {
        return Err(SmokeFailure::InvalidReport(
            "assertion lifecycle does not contain exactly five events",
        ));
    }
    for (sequence, event) in events.iter().enumerate() {
        let expected = u64::try_from(sequence).map_err(|_| {
            SmokeFailure::InvalidReport("assertion lifecycle sequence does not fit u64")
        })?;
        if event.protocol != TEST_PROTOCOL_VERSION || event.sequence != expected {
            return Err(SmokeFailure::InvalidReport(
                "assertion lifecycle protocol or sequence differs",
            ));
        }
    }
    let assertion_matches = matches!(
        &events[2].kind,
        TestEventKind::AssertionFailed { test: actual, failure }
            if *actual == test
                && failure.expression == ASSERTION_FAILURE_EXPRESSION
                && failure.message.as_deref() == Some(ASSERTION_FAILURE_MESSAGE)
                && failure.expected.is_none()
                && failure.actual.is_none()
                && failure.source.is_some_and(|source| {
                    source.file.0 == ASSERTION_FAILURE_FILE
                        && source.range.start == ASSERTION_FAILURE_START
                        && source.range.end == ASSERTION_FAILURE_END
                })
    );
    let finished_matches = matches!(
        &events[3].kind,
        TestEventKind::TestFinished {
            test: actual,
            outcome: GuestTestOutcome::Failed { message },
        } if *actual == test && message == ASSERTION_FAILURE_MESSAGE
    );
    if !matches!(events[0].kind, TestEventKind::RunStarted { test_count: 1 })
        || !matches!(
            events[1].kind,
            TestEventKind::TestStarted { test: actual } if actual == test
        )
        || !assertion_matches
        || !finished_matches
        || !matches!(
            events[4].kind,
            TestEventKind::RunFinished {
                passed: 0,
                failed: 1,
            }
        )
    {
        return Err(SmokeFailure::InvalidReport(
            "assertion lifecycle differs from the exact source-bound producer contract",
        ));
    }
    Ok(())
}

fn find_efi_images(root: &Path) -> Result<Vec<PathBuf>, SmokeFailure> {
    if !normal_absolute_path(root) {
        return Err(SmokeFailure::InvalidReport(
            "output root is not normalized and absolute",
        ));
    }
    let mut pending = vec![root.to_owned()];
    let mut images = Vec::new();
    let mut entries = 0usize;
    while let Some(directory) = pending.pop() {
        let directory_entries = fs::read_dir(&directory)
            .map_err(|error| smoke_io("output directory read", &directory, &error))?;
        for entry in directory_entries {
            let entry = entry.map_err(|error| smoke_io("output entry read", &directory, &error))?;
            entries = entries
                .checked_add(1)
                .filter(|count| *count <= MAX_SMOKE_OUTPUT_ENTRIES)
                .ok_or(SmokeFailure::InvalidReport(
                    "output tree entry limit exceeded",
                ))?;
            let path = entry.path();
            if !strict_descendant(&path, root) {
                return Err(SmokeFailure::InvalidReport(
                    "output entry escaped its private root",
                ));
            }
            let file_type = entry
                .file_type()
                .map_err(|error| smoke_io("output entry metadata", &path, &error))?;
            if file_type.is_symlink() {
                return Err(SmokeFailure::InvalidReport(
                    "output tree contains a symlink",
                ));
            }
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file()
                && path.extension().and_then(|value| value.to_str()) == Some("efi")
            {
                images.push(path);
            } else if !file_type.is_file() {
                return Err(SmokeFailure::InvalidReport(
                    "output tree contains a nonregular entry",
                ));
            }
        }
    }
    images.sort();
    Ok(images)
}

fn read_bounded_file(path: &Path, maximum_bytes: u64) -> Result<Vec<u8>, SmokeFailure> {
    if maximum_bytes == 0 || !normal_absolute_path(path) {
        return Err(SmokeFailure::InvalidReport(
            "bounded file request is invalid",
        ));
    }
    reject_symlink_ancestors(path)?;
    let before = fs::symlink_metadata(path)
        .map_err(|error| smoke_io("bounded file metadata", path, &error))?;
    if !bounded_regular_file_observation(&before)
        || before.len() == 0
        || before.len() > maximum_bytes
    {
        return Err(SmokeFailure::InvalidReport(
            "bounded file shape or byte length is invalid",
        ));
    }
    let file = File::open(path).map_err(|error| smoke_io("bounded file open", path, &error))?;
    let opened_before = file
        .metadata()
        .map_err(|error| smoke_io("bounded open-file metadata", path, &error))?;
    if !bounded_regular_file_observation(&opened_before)
        || !same_file_observation(&before, &opened_before)
    {
        return Err(SmokeFailure::InvalidReport(
            "bounded file changed before observation",
        ));
    }
    let capacity = usize::try_from(before.len())
        .map_err(|_| SmokeFailure::InvalidReport("bounded file length does not fit host usize"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| SmokeFailure::InvalidReport("cannot allocate the bounded file buffer"))?;
    let mut limited = file.take(maximum_bytes.saturating_add(1));
    limited
        .read_to_end(&mut bytes)
        .map_err(|error| smoke_io("bounded file read", path, &error))?;
    let opened_after = limited
        .get_ref()
        .metadata()
        .map_err(|error| smoke_io("bounded open-file metadata", path, &error))?;
    reject_symlink_ancestors(path)?;
    let after = fs::symlink_metadata(path)
        .map_err(|error| smoke_io("bounded file metadata", path, &error))?;
    if u64::try_from(bytes.len()).ok() != Some(before.len())
        || !bounded_regular_file_observation(&opened_after)
        || !bounded_regular_file_observation(&after)
        || !same_file_observation(&before, &opened_after)
        || !same_file_observation(&before, &after)
    {
        return Err(SmokeFailure::InvalidReport(
            "bounded file changed during observation",
        ));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn bounded_regular_file_observation(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    metadata.is_file() && !metadata.file_type().is_symlink() && metadata.nlink() == 1
}

#[cfg(not(unix))]
fn bounded_regular_file_observation(metadata: &fs::Metadata) -> bool {
    metadata.is_file() && !metadata.file_type().is_symlink()
}

#[cfg(unix)]
fn same_file_observation(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt as _;

    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
        && before.nlink() == after.nlink()
}

#[cfg(not(unix))]
fn same_file_observation(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.len() == after.len()
        && before.modified().ok() == after.modified().ok()
        && before.permissions().readonly() == after.permissions().readonly()
}

fn required_absolute_environment_path(name: &str) -> PathBuf {
    let name = match name {
        HARNESS_TOOLCHAIN_ROOT_ENV => HARNESS_TOOLCHAIN_ROOT_ENV,
        RUN_ROOT_ENV => RUN_ROOT_ENV,
        _ => panic!("unsupported smoke environment input"),
    };
    decode_required_environment_path(name, std::env::var_os(name))
        .unwrap_or_else(|error| panic!("{error}"))
}

fn required_runtime_timeout_run_binding() -> String {
    decode_runtime_timeout_run_binding(std::env::var_os(RUNTIME_TIMEOUT_RUN_BINDING_ENV))
        .unwrap_or_else(|error| panic!("{error}"))
}

fn decode_runtime_timeout_run_binding(value: Option<OsString>) -> Result<String, SmokeFailure> {
    let value = value.ok_or(SmokeFailure::MissingEnvironmentDigest(
        RUNTIME_TIMEOUT_RUN_BINDING_ENV,
    ))?;
    let value = value
        .into_string()
        .map_err(|_| SmokeFailure::InvalidEnvironmentDigest(RUNTIME_TIMEOUT_RUN_BINDING_ENV))?;
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        || value.bytes().all(|byte| byte == b'0')
    {
        return Err(SmokeFailure::InvalidEnvironmentDigest(
            RUNTIME_TIMEOUT_RUN_BINDING_ENV,
        ));
    }
    Ok(value)
}

fn decode_required_environment_path(
    name: &'static str,
    value: Option<OsString>,
) -> Result<PathBuf, SmokeFailure> {
    let value = value.ok_or(SmokeFailure::MissingEnvironment(name))?;
    let path = PathBuf::from(value);
    if !normal_absolute_path(&path)
        || path.components().count() <= 1
        || path.as_os_str().as_encoded_bytes().len() > MAX_SMOKE_PATH_BYTES
    {
        return Err(SmokeFailure::InvalidEnvironmentPath(name));
    }
    Ok(path)
}

fn normal_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path.components().count() > 0
        && path
            .components()
            .all(|component| !matches!(component, Component::CurDir | Component::ParentDir))
        && path.components().collect::<PathBuf>() == path
}

fn strict_descendant(path: &Path, root: &Path) -> bool {
    normal_absolute_path(path) && path != root && path.starts_with(root)
}

fn reject_symlink_ancestors(path: &Path) -> Result<(), SmokeFailure> {
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)
            .map_err(|error| smoke_io("path metadata", ancestor, &error))?;
        if metadata.file_type().is_symlink() {
            return Err(SmokeFailure::SymlinkPath(ancestor.to_owned()));
        }
    }
    Ok(())
}

fn create_private_directory(path: &Path) {
    fs::create_dir(path).unwrap_or_else(|error| panic!("create {}: {error}", path.display()));
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .unwrap_or_else(|error| panic!("restrict {}: {error}", path.display()));
}

fn write_new(path: &Path, bytes: &[u8]) {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(path)
        .unwrap_or_else(|error| panic!("create {}: {error}", path.display()));
    file.write_all(bytes)
        .unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
    file.sync_all()
        .unwrap_or_else(|error| panic!("sync {}: {error}", path.display()));
    #[cfg(unix)]
    File::open(path.parent().expect("smoke file has parent"))
        .and_then(|directory| directory.sync_all())
        .unwrap_or_else(|error| panic!("sync parent of {}: {error}", path.display()));
}

#[derive(Debug)]
struct RunRootGuard {
    path: Option<PathBuf>,
}

impl RunRootGuard {
    fn create(path: &Path) -> Result<Self, SmokeFailure> {
        if !normal_absolute_path(path) || path.components().count() <= 1 {
            return Err(SmokeFailure::InvalidRunRoot(
                "path is not normalized and absolute",
            ));
        }
        match fs::symlink_metadata(path) {
            Ok(_) => return Err(SmokeFailure::RunRootExists(path.to_owned())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(smoke_io("run-root metadata", path, &error)),
        }
        let parent = path
            .parent()
            .ok_or(SmokeFailure::InvalidRunRoot("absolute path has no parent"))?;
        reject_symlink_ancestors(parent)?;
        fs::create_dir(path).map_err(|error| smoke_io("run-root creation", path, &error))?;
        #[cfg(unix)]
        if let Err(error) = fs::set_permissions(path, fs::Permissions::from_mode(0o700)) {
            let _ = fs::remove_dir(path);
            return Err(smoke_io("run-root permission", path, &error));
        }
        let result = (|| {
            reject_symlink_ancestors(path)?;
            let metadata = fs::symlink_metadata(path)
                .map_err(|error| smoke_io("run-root metadata", path, &error))?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err(SmokeFailure::InvalidRunRoot(
                    "created path is not a regular directory",
                ));
            }
            #[cfg(unix)]
            if metadata.permissions().mode() & 0o777 != 0o700 {
                return Err(SmokeFailure::InvalidRunRoot(
                    "created directory is not mode 0700",
                ));
            }
            let canonical = fs::canonicalize(path)
                .map_err(|error| smoke_io("run-root canonicalization", path, &error))?;
            if canonical != path {
                return Err(SmokeFailure::InvalidRunRoot(
                    "created directory identity differs from requested path",
                ));
            }
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(path);
        }
        result?;
        Ok(Self {
            path: Some(path.to_owned()),
        })
    }

    fn cleanup(mut self) -> Result<(), SmokeFailure> {
        let path = self.path.take().ok_or(SmokeFailure::InvalidRunRoot(
            "cleanup was requested more than once",
        ))?;
        remove_run_root(&path)
    }
}

fn remove_run_root(path: &Path) -> Result<(), SmokeFailure> {
    reject_symlink_ancestors(path)?;
    let metadata =
        fs::symlink_metadata(path).map_err(|error| smoke_io("cleanup metadata", path, &error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(SmokeFailure::InvalidRunRoot(
            "run-root identity changed before cleanup",
        ));
    }
    fs::remove_dir_all(path).map_err(|error| smoke_io("cleanup removal", path, &error))?;
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(SmokeFailure::InvalidRunRoot(
            "run root remained after cleanup",
        )),
        Err(error) => Err(smoke_io("cleanup verification", path, &error)),
    }
}

impl Drop for RunRootGuard {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = remove_run_root(&path);
        }
    }
}

const fn never_cancelled() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    use wrela_build_model::{BuildIdentity, LanguageRevision};
    use wrela_test_model::{
        ImageExecutionEvidence, ImageGroupId, ImageGroupResult, TestCaseResult, TestDescriptor,
        TestEvent, TestId, TestReport,
    };

    use super::*;

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    fn unique_root(label: &str) -> PathBuf {
        let base = fs::canonicalize(std::env::temp_dir()).expect("canonical temporary directory");
        let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        base.join(format!(
            "wrela-real-qemu-smoke-{label}-{}-{sequence}",
            std::process::id()
        ))
    }

    #[cfg(unix)]
    fn shell_command(script: &str) -> Command {
        let mut command = Command::new("/bin/sh");
        command.env_clear().args(["-c", script]);
        command
    }

    #[cfg(unix)]
    fn fixture_process_policy() -> BoundedProcessPolicy {
        BoundedProcessPolicy {
            wall_timeout: Duration::from_secs(5),
            cleanup_timeout: Duration::from_secs(2),
            output_bytes: 1024 * 1024,
        }
    }

    #[cfg(unix)]
    fn process_group_exists(process_group: u32) -> bool {
        Command::new("/bin/kill")
            .args(["-0", &format!("-{process_group}")])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn pinned(root: &Path, relative: &str, byte: u8) -> PinnedPath {
        PinnedPath {
            path: root.join(relative),
            digest: digest(byte),
            bytes: u64::from(byte).saturating_add(1),
        }
    }

    fn fixture_bundle(root: &Path) -> EnrolledBundle {
        EnrolledBundle {
            root: root.to_owned(),
            frontend: pinned(root, "bin/wrela", 1),
            backend: pinned(root, "libexec/wrela/wrela-backend", 2),
            standard_library: pinned(root, "share/wrela/std", 3),
            emulator: pinned(root, "libexec/wrela/qemu-system-aarch64", 4),
            target_package: pinned(root, "share/wrela/targets/aarch64-qemu-virt-uefi", 5),
            firmware_code: pinned(
                root,
                "share/wrela/targets/aarch64-qemu-virt-uefi/firmware/QEMU_EFI.fd",
                6,
            ),
            firmware_variables: pinned(
                root,
                "share/wrela/targets/aarch64-qemu-virt-uefi/firmware/QEMU_VARS.fd",
                7,
            ),
        }
    }

    fn fixture_report(bundle: &EnrolledBundle) -> TestReport {
        let test = TestId(0);
        let events = vec![
            TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 0,
                kind: TestEventKind::RunStarted { test_count: 1 },
            },
            TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 1,
                kind: TestEventKind::TestStarted { test },
            },
            TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 2,
                kind: TestEventKind::TestFinished {
                    test,
                    outcome: GuestTestOutcome::Passed,
                },
            },
            TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 3,
                kind: TestEventKind::RunFinished {
                    passed: 1,
                    failed: 0,
                },
            },
        ];
        let event_stream_digest = CanonicalImageHarness::new()
            .event_stream_digest(&events, &never_cancelled)
            .expect("canonical fixture event-stream digest");
        TestReport {
            schema: TEST_REPORT_SCHEMA,
            build: BuildIdentity {
                compiler: bundle.frontend.digest,
                language: LanguageRevision::Design0_1,
                target: TargetIdentity::aarch64_qemu_virt_uefi(),
                target_package: bundle.target_package.digest,
                standard_library: bundle.standard_library.digest,
                source_graph: digest(0x31),
                request: digest(0x32),
                profile: digest(0x33),
            },
            started_unix_ns: None,
            duration_ns: None,
            unit: Vec::new(),
            images: vec![ImageGroupResult {
                group: ImageGroupId(0),
                cases: vec![TestCaseResult {
                    descriptor: TestDescriptor {
                        id: test,
                        name: APPLICATION_TEST_NAME.to_owned(),
                        kind: TestKind::IntegrationImage,
                        source: None,
                        timeout_ns: APPLICATION_TEST_TIMEOUT_NS,
                    },
                    outcome: TestOutcome::Passed,
                    duration_ns: None,
                }],
                events,
                evidence: ImageExecutionEvidence {
                    image_digest: Some(digest(0x41)),
                    target_digest: bundle.target_package.digest,
                    emulator_digest: Some(bundle.emulator.digest),
                    scenario_digest: None,
                    command_digest: Some(digest(0x42)),
                    event_stream_digest: Some(event_stream_digest),
                    exit_code: Some(0),
                    stderr: Vec::new(),
                },
                infrastructure_failure: None,
            }],
        }
    }

    fn fixture_language_fatal_report(
        bundle: &EnrolledBundle,
        cause: LanguageFatalCause,
    ) -> TestReport {
        let mut report = fixture_report(bundle);
        report.images[0].cases[0].outcome = TestOutcome::LanguageFatal { cause };
        report.images[0].events[2].kind = TestEventKind::TestFinished {
            test: TestId(0),
            outcome: GuestTestOutcome::LanguageFatal { cause },
        };
        report.images[0].events[3].kind = TestEventKind::RunFinished {
            passed: 0,
            failed: 1,
        };
        let event_stream_digest = CanonicalImageHarness::new()
            .event_stream_digest(&report.images[0].events, &never_cancelled)
            .expect("canonical typed-fatal fixture event-stream digest");
        report.images[0].evidence.event_stream_digest = Some(event_stream_digest);
        report
    }

    fn fixture_checked_shift_report(
        bundle: &EnrolledBundle,
        case: CheckedShiftSmokeCase,
    ) -> TestReport {
        let mut report = match case.expected {
            ExpectedSmokeOutcome::Passed => fixture_report(bundle),
            ExpectedSmokeOutcome::AssertionFailed => {
                let mut report = fixture_report(bundle);
                report.images[0].cases[0].outcome = TestOutcome::Failed {
                    phase: FailurePhase::Runtime,
                    message: ASSERTION_FAILURE_MESSAGE.to_owned(),
                };
                report.images[0].events.insert(
                    2,
                    TestEvent {
                        protocol: TEST_PROTOCOL_VERSION,
                        sequence: 2,
                        kind: TestEventKind::AssertionFailed {
                            test: TestId(0),
                            failure: wrela_test_model::AssertionFailure {
                                expression: ASSERTION_FAILURE_EXPRESSION.to_owned(),
                                message: Some(ASSERTION_FAILURE_MESSAGE.to_owned()),
                                source: None,
                                expected: None,
                                actual: None,
                            },
                        },
                    },
                );
                report.images[0].events[3].sequence = 3;
                report.images[0].events[4].sequence = 4;
                report.images[0].events[4].kind = TestEventKind::RunFinished {
                    passed: 0,
                    failed: 1,
                };
                report
            }
            ExpectedSmokeOutcome::LanguageFatal(cause) => {
                fixture_language_fatal_report(bundle, cause)
            }
        };
        let test = TestId(case.test_id);
        report.images[0].cases[0].descriptor.id = test;
        report.images[0].cases[0].descriptor.name = case.qualified_name();
        report.images[0].events[1].kind = TestEventKind::TestStarted { test };
        let finished_index = if case.expected == ExpectedSmokeOutcome::AssertionFailed {
            3
        } else {
            2
        };
        report.images[0].events[finished_index].kind = TestEventKind::TestFinished {
            test,
            outcome: case.expected.guest(),
        };
        let event_stream_digest = CanonicalImageHarness::new()
            .event_stream_digest(&report.images[0].events, &never_cancelled)
            .expect("canonical checked-shift fixture event-stream digest");
        report.images[0].evidence.event_stream_digest = Some(event_stream_digest);
        report
    }

    fn fixture_runtime_timeout_report(bundle: &EnrolledBundle) -> TestReport {
        let mut report = fixture_report(bundle);
        report.images[0].cases.clear();
        report.images[0].events.truncate(2);
        report.images[0].evidence.event_stream_digest = Some(
            CanonicalImageHarness::new()
                .event_stream_digest(&report.images[0].events, &never_cancelled)
                .expect("canonical runtime-timeout prefix digest"),
        );
        report.images[0].evidence.exit_code = None;
        report.images[0].infrastructure_failure = Some(TestOutcome::TimedOut {
            phase: FailurePhase::Runtime,
            timeout_ns: RUNTIME_TIMEOUT_GROUP_TIMEOUT_NS,
        });
        report
    }

    fn encode_report(report: &TestReport) -> Vec<u8> {
        CanonicalTestReportCodec::new()
            .encode(report, MAX_SMOKE_REPORT_BYTES, &never_cancelled)
            .expect("canonical fixture report")
    }

    #[test]
    fn harness_inputs_are_required_normalized_and_distinct_from_the_child_contract() {
        assert_ne!(HARNESS_TOOLCHAIN_ROOT_ENV, CHILD_TOOLCHAIN_ROOT_ENV);
        assert_eq!(
            decode_required_environment_path(HARNESS_TOOLCHAIN_ROOT_ENV, None),
            Err(SmokeFailure::MissingEnvironment(HARNESS_TOOLCHAIN_ROOT_ENV))
        );
        assert_eq!(
            decode_required_environment_path(
                HARNESS_TOOLCHAIN_ROOT_ENV,
                Some(OsString::from("relative/toolchain")),
            ),
            Err(SmokeFailure::InvalidEnvironmentPath(
                HARNESS_TOOLCHAIN_ROOT_ENV
            ))
        );
        assert_eq!(
            decode_required_environment_path(RUN_ROOT_ENV, Some(OsString::from("/"))),
            Err(SmokeFailure::InvalidEnvironmentPath(RUN_ROOT_ENV))
        );
        let base = fs::canonicalize(std::env::temp_dir()).expect("canonical temporary directory");
        assert_eq!(
            decode_required_environment_path(
                RUN_ROOT_ENV,
                Some(base.join("one/../two").into_os_string()),
            ),
            Err(SmokeFailure::InvalidEnvironmentPath(RUN_ROOT_ENV))
        );
        let valid = unique_root("environment");
        assert_eq!(
            decode_required_environment_path(
                HARNESS_TOOLCHAIN_ROOT_ENV,
                Some(valid.clone().into_os_string()),
            ),
            Ok(valid)
        );
    }

    #[test]
    fn run_root_is_private_exclusive_and_removed_on_explicit_or_drop_cleanup() {
        let root = unique_root("cleanup");
        let guard = RunRootGuard::create(&root).expect("create private run root");
        let metadata = fs::metadata(&root).expect("private root metadata");
        assert!(metadata.is_dir());
        #[cfg(unix)]
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        assert_eq!(
            RunRootGuard::create(&root).expect_err("existing run root must fail"),
            SmokeFailure::RunRootExists(root.clone())
        );
        create_private_directory(&root.join("residue"));
        write_new(&root.join("residue/file"), b"private residue");
        guard.cleanup().expect("explicit private-root cleanup");
        assert!(!root.exists());

        let dropped = unique_root("drop-cleanup");
        {
            let _guard = RunRootGuard::create(&dropped).expect("create drop-cleanup root");
            write_new(&dropped.join("file"), b"private residue");
        }
        assert!(!dropped.exists(), "drop cleanup left private residue");

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let parent = unique_root("symlink-parent");
            let parent_cleanup =
                RunRootGuard::create(&parent).expect("create symlink-parent fixture");
            create_private_directory(&parent.join("real"));
            let alias = parent.join("alias");
            symlink(parent.join("real"), &alias).expect("create hostile parent symlink");
            assert_eq!(
                RunRootGuard::create(&alias.join("run"))
                    .expect_err("symlinked run-root parent must fail"),
                SmokeFailure::SymlinkPath(alias)
            );
            parent_cleanup
                .cleanup()
                .expect("cleanup symlink-parent fixture");
        }
    }

    #[test]
    fn launch_is_exact_bounded_and_carries_verified_component_identity() {
        let toolchain_root = unique_root("launch-toolchain");
        let toolchain_cleanup =
            RunRootGuard::create(&toolchain_root).expect("create fixture toolchain root");
        create_private_directory(&toolchain_root.join("bin"));
        let frontend_path = toolchain_root.join("bin/wrela");
        write_new(&frontend_path, b"fixture frontend");
        #[cfg(unix)]
        fs::set_permissions(&frontend_path, fs::Permissions::from_mode(0o700))
            .expect("make fixture frontend executable");

        let bundle = fixture_bundle(&toolchain_root);
        bundle.validate(false).expect("valid pinned fixture bundle");
        let run_root = unique_root("launch-run");
        let run_cleanup = RunRootGuard::create(&run_root).expect("create fixture run root");
        let workspace = run_root.join("workspace");
        let temporary = run_root.join("tmp");
        create_private_directory(&workspace);
        create_private_directory(&temporary);
        let output = run_root.join("output");
        let launch = SmokeLaunch::new(&bundle, &run_root, &workspace, &output, &temporary)
            .expect("seal fixture launch");
        launch
            .verify_private_layout(&run_root, &output, &temporary)
            .expect("verify fixture private layout");

        assert_eq!(launch.program.path, bundle.frontend.path);
        assert_eq!(launch.program.digest, bundle.frontend.digest);
        assert_eq!(launch.program.bytes, bundle.frontend.bytes);
        assert_eq!(launch.arguments.len(), MAX_SMOKE_ARGUMENTS);
        assert_eq!(launch.environment.len(), MAX_SMOKE_ENVIRONMENT_VARIABLES);
        let command = launch.command();
        assert_eq!(command.get_program(), bundle.frontend.path.as_os_str());
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            launch
                .arguments
                .iter()
                .map(OsString::as_os_str)
                .collect::<Vec<_>>()
        );
        assert_eq!(command.get_current_dir(), Some(workspace.as_path()));
        let environment = command.get_envs().collect::<Vec<_>>();
        assert_eq!(environment.len(), MAX_SMOKE_ENVIRONMENT_VARIABLES);
        assert_eq!(
            environment
                .iter()
                .find(|(name, _)| *name == "PATH")
                .and_then(|(_, value)| *value),
            Some(OsString::new().as_os_str())
        );
        assert_eq!(
            environment
                .iter()
                .find(|(name, _)| *name == CHILD_TOOLCHAIN_ROOT_ENV)
                .and_then(|(_, value)| *value),
            Some(toolchain_root.as_os_str())
        );
        assert!(
            environment
                .iter()
                .all(|(name, _)| *name != HARNESS_TOOLCHAIN_ROOT_ENV)
        );
        create_private_directory(&output);
        assert_eq!(
            launch.verify_private_layout(&run_root, &output, &temporary),
            Err(SmokeFailure::InvalidLaunch(
                "output directory must be absent before publication"
            ))
        );

        run_cleanup.cleanup().expect("cleanup fixture run root");
        toolchain_cleanup
            .cleanup()
            .expect("cleanup fixture toolchain root");
    }

    #[test]
    fn checked_shift_selected_launch_and_nonzero_completion_contract_are_exact() {
        let toolchain_root = unique_root("checked-shift-selected-toolchain");
        let run_root = unique_root("checked-shift-selected-run");
        let workspace = run_root.join("workspace");
        let output = run_root.join("output");
        let temporary = run_root.join("tmp");
        let bundle = fixture_bundle(&toolchain_root);
        let launch = SmokeLaunch::new_selected(
            &bundle,
            &run_root,
            &workspace,
            &output,
            &temporary,
            CHECKED_SHIFT_IMAGE,
            "checked_shift_result_loss",
        )
        .expect("seal selected checked-shift launch");
        assert_eq!(launch.arguments.len(), MAX_SELECTED_SMOKE_ARGUMENTS);
        assert_eq!(
            launch.arguments,
            [
                OsString::from("test"),
                workspace.join("wrela.toml").into_os_string(),
                OsString::from(CHECKED_SHIFT_IMAGE),
                output.as_os_str().to_owned(),
                OsString::from("--name-contains"),
                OsString::from("checked_shift_result_loss"),
            ]
        );
        assert_eq!(
            SmokeLaunch::new_selected(
                &bundle,
                &run_root,
                &workspace,
                &output,
                &temporary,
                CHECKED_SHIFT_IMAGE,
                "",
            ),
            Err(SmokeFailure::InvalidLaunch(
                "image and optional test selector must be nonempty"
            ))
        );

        let opaque_nonzero = Err(bounded_process_failure(
            BoundedProcessFailureKind::Exit { code: Some(1) },
            Some(41),
            b"opaque frontend output".to_vec(),
            b"opaque frontend diagnostic".to_vec(),
        ));
        assert!(!completion_matches_expected(
            ExpectedSmokeOutcome::LanguageFatal(LanguageFatalCause::CheckedShiftResultLoss),
            &opaque_nonzero,
        ));
        assert!(!completion_matches_expected(
            ExpectedSmokeOutcome::Passed,
            &opaque_nonzero,
        ));
        assert!(!completion_matches_expected(
            ExpectedSmokeOutcome::LanguageFatal(LanguageFatalCause::InvalidShiftCount),
            &Err(bounded_process_failure(
                BoundedProcessFailureKind::TimedOut { milliseconds: 1 },
                Some(42),
                Vec::new(),
                Vec::new(),
            )),
        ));
        assert!(completion_matches_expected(
            ExpectedSmokeOutcome::Passed,
            &Ok(BoundedProcessOutput {
                process_group: 43,
                stdout: b"test passed\n".to_vec(),
                stderr: Vec::new(),
            }),
        ));
        let exact_failure = Err(bounded_process_failure(
            BoundedProcessFailureKind::Exit { code: Some(1) },
            Some(44),
            b"test failed\n".to_vec(),
            Vec::new(),
        ));
        assert!(completion_matches_expected(
            ExpectedSmokeOutcome::AssertionFailed,
            &exact_failure,
        ));
        assert!(completion_matches_expected(
            ExpectedSmokeOutcome::LanguageFatal(LanguageFatalCause::InvalidShiftCount),
            &exact_failure,
        ));
    }

    #[test]
    fn runtime_timeout_fixture_launch_and_public_failure_contract_are_exact() {
        let codec = CanonicalPackageCodec::new();
        let manifest_limits = ManifestCodecLimits {
            bytes: 1024 * 1024,
            string_bytes: 1024 * 1024,
            modules: 16,
            dependencies: 16,
            profiles: 16,
            images: 16,
            image_tests: 16,
        };
        let manifest = codec
            .decode_manifest(RUNTIME_TIMEOUT_MANIFEST, manifest_limits, &never_cancelled)
            .expect("decode canonical runtime-timeout manifest");
        // This checked-in manifest declares only `[[profile]]` overrides and
        // no `[[module]]` block (modules are derived, not decoded), so it is
        // valid schema-1 input without being byte-identical to its own
        // canonical re-encoding. Round-tripping through decode -> canonical
        // -> decode must still be a fixed point, and every digest below
        // binds the canonical bytes, matching what the production loader
        // hashes.
        let canonical_manifest = codec
            .canonical_manifest(&manifest, manifest_limits, &never_cancelled)
            .expect("encode canonical runtime-timeout manifest");
        assert_eq!(
            codec
                .decode_manifest(&canonical_manifest, manifest_limits, &never_cancelled)
                .expect("redecode canonical runtime-timeout manifest"),
            manifest,
        );
        // There is no lockfile to cross-check this package's identity
        // against; computing its content digest still exercises that the
        // checked-in manifest and source hash without error, exactly as the
        // production loader independently does when it computes and trusts
        // this as the package's identity.
        let _source_digest = package_content_digest(
            &canonical_manifest,
            &[PackageContentRecord {
                kind: PackageContentKind::Source,
                path: "runtime_timeout/image.wr",
                digest: HASHER.sha256(RUNTIME_TIMEOUT_SOURCE),
            }],
            &HASHER,
            &never_cancelled,
        )
        .expect("measure runtime-timeout source package");
        assert_eq!(manifest.name.as_str(), RUNTIME_TIMEOUT_IMAGE);
        let source = std::str::from_utf8(RUNTIME_TIMEOUT_SOURCE).expect("UTF-8 timeout source");
        assert!(source.contains("@test\nfn checked_arithmetic_fatal_times_out():"));
        assert!(source.contains("return left + right"));

        let toolchain_root = unique_root("runtime-timeout-selected-toolchain");
        let run_root = unique_root("runtime-timeout-selected-run");
        let workspace = run_root.join("workspace");
        let output = run_root.join("output");
        let temporary = run_root.join("tmp");
        let bundle = fixture_bundle(&toolchain_root);
        let launch = SmokeLaunch::new_selected(
            &bundle,
            &run_root,
            &workspace,
            &output,
            &temporary,
            RUNTIME_TIMEOUT_IMAGE,
            RUNTIME_TIMEOUT_SELECTOR,
        )
        .expect("seal selected runtime-timeout launch");
        assert_eq!(
            launch.arguments,
            [
                OsString::from("test"),
                workspace.join("wrela.toml").into_os_string(),
                OsString::from(RUNTIME_TIMEOUT_IMAGE),
                output.as_os_str().to_owned(),
                OsString::from("--name-contains"),
                OsString::from(RUNTIME_TIMEOUT_SELECTOR),
            ]
        );
        let exact_failure = Err(bounded_process_failure(
            BoundedProcessFailureKind::Exit { code: Some(1) },
            Some(41),
            b"test failed\n".to_vec(),
            Vec::new(),
        ));
        assert!(completion_matches_runtime_timeout(&exact_failure));
        for malformed in [
            Err(bounded_process_failure(
                BoundedProcessFailureKind::Exit { code: Some(0) },
                Some(41),
                b"test failed\n".to_vec(),
                Vec::new(),
            )),
            Err(bounded_process_failure(
                BoundedProcessFailureKind::Exit { code: Some(1) },
                Some(41),
                b"test passed\n".to_vec(),
                Vec::new(),
            )),
            Err(bounded_process_failure(
                BoundedProcessFailureKind::TimedOut { milliseconds: 1 },
                Some(41),
                Vec::new(),
                Vec::new(),
            )),
        ] {
            assert!(!completion_matches_runtime_timeout(&malformed));
        }
    }

    #[cfg(unix)]
    #[test]
    fn launch_clears_ambient_environment_and_executes_with_an_empty_path() {
        let toolchain_root = unique_root("environment-toolchain");
        let toolchain_cleanup =
            RunRootGuard::create(&toolchain_root).expect("create fixture toolchain root");
        create_private_directory(&toolchain_root.join("bin"));
        let frontend_path = toolchain_root.join("bin/wrela");
        let excluded = [
            "HOME",
            "LC_ALL",
            "PATH",
            "PWD",
            "SHLVL",
            "SOURCE_DATE_EPOCH",
            "TMPDIR",
            "TZ",
            "_",
            CHILD_TOOLCHAIN_ROOT_ENV,
        ];
        let ambient = std::env::vars_os()
            .filter_map(|(name, _)| name.into_string().ok())
            .find(|name| {
                !excluded.contains(&name.as_str())
                    && name.bytes().enumerate().all(|(index, byte)| {
                        byte == b'_'
                            || byte.is_ascii_uppercase()
                            || (index > 0 && byte.is_ascii_digit())
                    })
            })
            .expect("test process exposes one safe ambient sentinel");
        let script = format!(
            "#!/bin/sh\nif [ \"${{{ambient}+present}}\" = present ]; then exit 71; fi\nif [ -n \"$PATH\" ]; then exit 72; fi\nexit 0\n"
        );
        write_new(&frontend_path, script.as_bytes());
        fs::set_permissions(&frontend_path, fs::Permissions::from_mode(0o700))
            .expect("make fixture frontend executable");

        let bundle = fixture_bundle(&toolchain_root);
        let run_root = unique_root("environment-run");
        let run_cleanup = RunRootGuard::create(&run_root).expect("create fixture run root");
        let workspace = run_root.join("workspace");
        let temporary = run_root.join("tmp");
        create_private_directory(&workspace);
        create_private_directory(&temporary);
        let launch = SmokeLaunch::new(
            &bundle,
            &run_root,
            &workspace,
            &run_root.join("output"),
            &temporary,
        )
        .expect("seal environment launch");
        launch
            .verify_private_layout(&run_root, &run_root.join("output"), &temporary)
            .expect("verify environment fixture layout");
        let child = run_bounded_process(launch.command(), fixture_process_policy())
            .expect("run bounded fixture frontend");
        assert!(child.stdout.is_empty());
        assert!(child.stderr.is_empty());
        assert!(!process_group_exists(child.process_group));

        run_cleanup.cleanup().expect("cleanup fixture run root");
        toolchain_cleanup
            .cleanup()
            .expect("cleanup fixture toolchain root");
    }

    #[cfg(unix)]
    #[test]
    fn supervised_process_timeout_is_finite_structured_and_reaped() {
        let policy = BoundedProcessPolicy {
            wall_timeout: Duration::from_millis(100),
            cleanup_timeout: Duration::from_secs(2),
            output_bytes: 64 * 1024,
        };
        let failure = run_bounded_process(
            shell_command("printf 'ready\\n'; while :; do :; done"),
            policy,
        )
        .expect_err("busy child must reach the finite wall deadline");
        assert_eq!(
            failure.kind,
            BoundedProcessFailureKind::TimedOut { milliseconds: 100 }
        );
        assert_eq!(failure.stdout, b"ready\n");
        assert!(failure.stderr.is_empty());
        let group = failure
            .process_group
            .expect("spawned timeout process group");
        assert!(!process_group_exists(group), "timeout left a process group");
    }

    #[cfg(unix)]
    #[test]
    fn supervised_process_enforces_one_aggregate_output_budget() {
        let policy = BoundedProcessPolicy {
            wall_timeout: Duration::from_secs(5),
            cleanup_timeout: Duration::from_secs(2),
            output_bytes: 4096,
        };
        let failure = run_bounded_process(
            shell_command(
                "while :; do printf '0123456789abcdef'; printf 'fedcba9876543210' >&2; done",
            ),
            policy,
        )
        .expect_err("output bomb must exhaust the aggregate budget");
        assert_eq!(
            failure.kind,
            BoundedProcessFailureKind::OutputLimit { bytes: 4096 }
        );
        assert_eq!(failure.stdout.len() + failure.stderr.len(), 4096);
        let group = failure.process_group.expect("spawned output-bomb group");
        assert!(
            !process_group_exists(group),
            "output bomb left a process group"
        );
    }

    #[test]
    fn bounded_process_diagnostics_are_opaque_and_output_limit_is_aggregate_only() {
        let public_failure = bounded_process_failure(
            BoundedProcessFailureKind::Exit { code: Some(1) },
            Some(17),
            b"test failed\n".to_vec(),
            b"/private/volatile/run-root".to_vec(),
        )
        .to_string();
        assert!(public_failure.contains("stdout=public-test-failed bytes=12"));
        assert!(public_failure.contains("stderr=opaque-nonempty bytes=26"));
        assert!(!public_failure.contains("/private"));
        assert!(!public_failure.contains("sha256"));
        assert!(!public_failure.contains("Some(17)"));

        let left = bounded_process_failure(
            BoundedProcessFailureKind::OutputLimit { bytes: 8 },
            Some(18),
            b"12345678".to_vec(),
            Vec::new(),
        )
        .to_string();
        let right = bounded_process_failure(
            BoundedProcessFailureKind::OutputLimit { bytes: 8 },
            Some(19),
            Vec::new(),
            b"87654321".to_vec(),
        )
        .to_string();
        assert_eq!(left, right);
        assert_eq!(
            left,
            "bounded process OutputLimit { bytes: 8 } (aggregate_output_limit=8 bytes reached)"
        );
    }

    #[cfg(unix)]
    #[test]
    fn supervised_success_closes_pipe_holding_descendants() {
        let output = run_bounded_process(
            shell_command("(while :; do :; done) & printf 'spawned\\n'; exit 0"),
            fixture_process_policy(),
        )
        .expect("successful parent must terminate its pipe-holding descendant");
        assert_eq!(output.stdout, b"spawned\n");
        assert!(output.stderr.is_empty());
        assert!(
            !process_group_exists(output.process_group),
            "successful parent left a pipe-holding process group"
        );
    }

    #[cfg(unix)]
    #[test]
    fn supervised_exit_failure_preserves_bounded_exact_diagnostics() {
        let failure = run_bounded_process(
            shell_command("printf 'failure-out'; printf 'failure-err' >&2; exit 23"),
            fixture_process_policy(),
        )
        .expect_err("nonzero child status must be structured failure");
        assert_eq!(
            failure.kind,
            BoundedProcessFailureKind::Exit { code: Some(23) }
        );
        assert_eq!(failure.stdout, b"failure-out");
        assert_eq!(failure.stderr, b"failure-err");
        let group = failure.process_group.expect("spawned failed process group");
        assert!(
            !process_group_exists(group),
            "failed child left a process group"
        );
    }

    #[cfg(unix)]
    #[test]
    fn process_group_guard_drop_is_cancellation_safe_and_leaves_no_residue() {
        let mut command = shell_command("while :; do :; done");
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_process_group(&mut command);
        let guard =
            ProcessGroupGuard::new(command.spawn().expect("spawn guarded cancellation child"));
        let process_group = guard.process_group;
        drop(guard);
        assert!(
            !process_group_exists(process_group),
            "guard drop left a live process group"
        );
    }

    #[test]
    fn bundle_and_launch_reject_identity_aliases_overlap_and_path_overflow() {
        let toolchain_root = unique_root("invalid-toolchain");
        let mut bundle = fixture_bundle(&toolchain_root);
        bundle.backend.path = bundle.frontend.path.clone();
        assert_eq!(
            bundle.validate(false),
            Err(SmokeFailure::InvalidBundle(
                "verified component paths are not distinct"
            ))
        );

        let mut bundle = fixture_bundle(&toolchain_root);
        bundle.firmware_code.digest = Sha256Digest::from_bytes([0; 32]);
        assert_eq!(
            bundle.validate(false),
            Err(SmokeFailure::InvalidBundle("firmware code"))
        );

        let bundle = fixture_bundle(&toolchain_root);
        let nested_run = toolchain_root.join("private-run");
        assert_eq!(
            SmokeLaunch::new(
                &bundle,
                &nested_run,
                &nested_run.join("workspace"),
                &nested_run.join("output"),
                &nested_run.join("tmp"),
            ),
            Err(SmokeFailure::InvalidLaunch(
                "toolchain and private run paths overlap or escape"
            ))
        );

        let run_root = unique_root("overflow-run");
        let hostile = run_root.join("x".repeat(MAX_SMOKE_PATH_BYTES));
        assert_eq!(
            SmokeLaunch::new(
                &bundle,
                &run_root,
                &hostile,
                &run_root.join("output"),
                &run_root.join("tmp"),
            ),
            Err(SmokeFailure::InvalidLaunch("path byte limit exceeded"))
        );
    }

    #[test]
    fn canonical_report_and_real_lifecycle_fail_closed_deterministically() {
        let bundle = fixture_bundle(&unique_root("report-toolchain"));
        let report = fixture_report(&bundle);
        let expected_event_stream_digest = report.images[0]
            .evidence
            .event_stream_digest
            .expect("fixture event-stream digest");
        let expected_event_stream = canonical_event_stream_encoding(&report.images[0].events)
            .expect("fixture canonical event stream");
        let expected_event_stream_bytes = u64::try_from(expected_event_stream.len())
            .expect("fixture canonical event-stream extent");
        let encoded = encode_report(&report);
        assert_eq!(
            validate_canonical_smoke_report(&encoded, &bundle),
            Ok(ValidatedSmokeReportEvidence {
                image_digest: digest(0x41),
                event_stream_digest: expected_event_stream_digest,
                event_stream_bytes: expected_event_stream_bytes,
                canonical_event_stream: expected_event_stream,
            })
        );

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            validate_canonical_smoke_report(&trailing, &bundle),
            Err(SmokeFailure::InvalidReport("canonical decoding failed"))
        );

        let mut wrong_build = report.clone();
        wrong_build.build.compiler = digest(0x61);
        assert_eq!(
            validate_canonical_smoke_report(&encode_report(&wrong_build), &bundle),
            Err(SmokeFailure::InvalidReport(
                "report build identity differs from the verified smoke inputs"
            ))
        );

        let mut wrong_evidence = report.clone();
        wrong_evidence.images[0].evidence.emulator_digest = Some(digest(0x62));
        assert_eq!(
            validate_canonical_smoke_report(&encode_report(&wrong_evidence), &bundle),
            Err(SmokeFailure::InvalidReport(
                "execution evidence differs from the verified emulator and target"
            ))
        );

        let mut wrong_event_digest = report.clone();
        wrong_event_digest.images[0].evidence.event_stream_digest = Some(digest(0x63));
        assert_eq!(
            validate_canonical_smoke_report(&encode_report(&wrong_event_digest), &bundle),
            Err(SmokeFailure::InvalidReport(
                "event-stream digest differs from the canonical lifecycle"
            ))
        );

        let mut unqualified_test_name = report.clone();
        unqualified_test_name.images[0].cases[0].descriptor.name = "runtime_case".to_owned();
        assert_eq!(
            validate_canonical_smoke_report(&encode_report(&unqualified_test_name), &bundle),
            Err(SmokeFailure::InvalidReport(
                "runtime test result differs from the enrolled smoke source"
            ))
        );

        let mut wrong_test_timeout = report.clone();
        wrong_test_timeout.images[0].cases[0].descriptor.timeout_ns = 1;
        assert_eq!(
            validate_canonical_smoke_report(&encode_report(&wrong_test_timeout), &bundle),
            Err(SmokeFailure::InvalidReport(
                "runtime test result differs from the enrolled smoke source"
            ))
        );

        let mut wrong_sequence = report;
        wrong_sequence.images[0].events[2].sequence = 3;
        wrong_sequence.images[0].evidence.event_stream_digest = Some(
            CanonicalImageHarness::new()
                .event_stream_digest(&wrong_sequence.images[0].events, &never_cancelled)
                .expect("digest malformed fixture lifecycle"),
        );
        assert_eq!(
            validate_canonical_smoke_report(&encode_report(&wrong_sequence), &bundle),
            Err(SmokeFailure::InvalidReport(
                "guest lifecycle protocol or sequence differs"
            ))
        );
        assert_eq!(
            validate_canonical_smoke_report(&[], &bundle),
            Err(SmokeFailure::InvalidReport(
                "report byte length exceeds the smoke policy"
            ))
        );
    }

    #[test]
    fn checked_shift_canonical_report_requires_exact_typed_outcome_and_complete_publication() {
        let bundle = fixture_bundle(&unique_root("checked-shift-report-toolchain"));
        for case in CHECKED_SHIFT_CASES {
            let report = fixture_checked_shift_report(&bundle, case);
            let image = &report.images[0];
            let expected_event_stream_digest = image
                .evidence
                .event_stream_digest
                .expect("checked-shift fixture event-stream digest");
            let expected_event_stream = canonical_event_stream_encoding(&image.events)
                .expect("checked-shift fixture canonical event stream");
            let expected_event_stream_bytes = u64::try_from(expected_event_stream.len())
                .expect("checked-shift fixture event-stream extent");
            let encoded = encode_report(&report);
            if case.expected == ExpectedSmokeOutcome::AssertionFailed {
                assert_eq!(
                    validate_canonical_runtime_report(
                        &encoded,
                        &bundle,
                        case.test_id,
                        &case.qualified_name(),
                        case.expected,
                    ),
                    Err(SmokeFailure::InvalidReport(
                        "assertion lifecycle differs from the exact source-bound producer contract"
                    )),
                    "an assertion lifecycle without its exact source must fail closed",
                );
                continue;
            }
            assert_eq!(
                validate_canonical_runtime_report(
                    &encoded,
                    &bundle,
                    case.test_id,
                    &case.qualified_name(),
                    case.expected,
                ),
                Ok(ValidatedSmokeReportEvidence {
                    image_digest: digest(0x41),
                    event_stream_digest: expected_event_stream_digest,
                    event_stream_bytes: expected_event_stream_bytes,
                    canonical_event_stream: expected_event_stream,
                }),
                "selector {} must consume its exact typed canonical report",
                case.selector,
            );

            let mut truncated = encoded;
            truncated.pop().expect("canonical fixture is nonempty");
            assert_eq!(
                validate_canonical_runtime_report(
                    &truncated,
                    &bundle,
                    case.test_id,
                    &case.qualified_name(),
                    case.expected,
                ),
                Err(SmokeFailure::InvalidReport("canonical decoding failed")),
                "selector {} must reject a partially published report",
                case.selector,
            );

            let ExpectedSmokeOutcome::LanguageFatal(expected_cause) = case.expected else {
                continue;
            };
            let wrong_cause = match expected_cause {
                LanguageFatalCause::CheckedShiftResultLoss => LanguageFatalCause::InvalidShiftCount,
                LanguageFatalCause::InvalidShiftCount => LanguageFatalCause::CheckedShiftResultLoss,
            };

            let mut wrong_host = report.clone();
            wrong_host.images[0].cases[0].outcome =
                TestOutcome::LanguageFatal { cause: wrong_cause };
            assert_eq!(
                validate_canonical_runtime_report(
                    &encode_report(&wrong_host),
                    &bundle,
                    case.test_id,
                    &case.qualified_name(),
                    case.expected,
                ),
                Err(SmokeFailure::InvalidReport(
                    "runtime test result differs from the enrolled smoke source"
                )),
                "selector {} must reject the wrong host-side fatal cause",
                case.selector,
            );

            let mut wrong_guest = report;
            wrong_guest.images[0].events[2].kind = TestEventKind::TestFinished {
                test: TestId(case.test_id),
                outcome: GuestTestOutcome::LanguageFatal { cause: wrong_cause },
            };
            wrong_guest.images[0].evidence.event_stream_digest = Some(
                CanonicalImageHarness::new()
                    .event_stream_digest(&wrong_guest.images[0].events, &never_cancelled)
                    .expect("digest wrong-cause checked-shift fixture lifecycle"),
            );
            assert_eq!(
                validate_canonical_runtime_report(
                    &encode_report(&wrong_guest),
                    &bundle,
                    case.test_id,
                    &case.qualified_name(),
                    case.expected,
                ),
                Err(SmokeFailure::InvalidReport(
                    "guest lifecycle shape differs from the real producer contract"
                )),
                "selector {} must reject the wrong guest-side fatal cause",
                case.selector,
            );
        }
    }

    #[test]
    fn runtime_timeout_report_requires_exact_prefix_failure_and_evidence() {
        let bundle = fixture_bundle(&unique_root("runtime-timeout-report-toolchain"));
        let report = fixture_runtime_timeout_report(&bundle);
        let image = &report.images[0];
        let expected_event_stream_digest = image
            .evidence
            .event_stream_digest
            .expect("runtime-timeout fixture event-stream digest");
        let expected_event_stream = canonical_event_stream_encoding(&image.events)
            .expect("runtime-timeout fixture canonical event stream");
        let expected_event_stream_bytes = u64::try_from(expected_event_stream.len())
            .expect("runtime-timeout fixture event-stream extent");
        let encoded = encode_report(&report);
        assert_eq!(
            validate_canonical_runtime_timeout_report(&encoded, &bundle),
            Ok(ValidatedSmokeReportEvidence {
                image_digest: digest(0x41),
                event_stream_digest: expected_event_stream_digest,
                event_stream_bytes: expected_event_stream_bytes,
                canonical_event_stream: expected_event_stream,
            })
        );

        let mut wrong_timeout = report.clone();
        wrong_timeout.images[0].infrastructure_failure = Some(TestOutcome::TimedOut {
            phase: FailurePhase::Runtime,
            timeout_ns: RUNTIME_TIMEOUT_GROUP_TIMEOUT_NS - 1,
        });
        assert_eq!(
            validate_canonical_runtime_timeout_report(&encode_report(&wrong_timeout), &bundle),
            Err(SmokeFailure::InvalidReport(
                "runtime-timeout outcome is not the exact runtime infrastructure timeout"
            ))
        );

        let mut wrong_phase = report.clone();
        wrong_phase.images[0].infrastructure_failure = Some(TestOutcome::TimedOut {
            phase: FailurePhase::Boot,
            timeout_ns: RUNTIME_TIMEOUT_GROUP_TIMEOUT_NS,
        });
        assert_eq!(
            validate_canonical_runtime_timeout_report(&encode_report(&wrong_phase), &bundle),
            Err(SmokeFailure::InvalidReport(
                "runtime-timeout outcome is not the exact runtime infrastructure timeout"
            ))
        );

        let mut terminal = report.clone();
        terminal.images[0].events.push(TestEvent {
            protocol: TEST_PROTOCOL_VERSION,
            sequence: 2,
            kind: TestEventKind::RunFinished {
                passed: 0,
                failed: 1,
            },
        });
        terminal.images[0].evidence.event_stream_digest = Some(
            CanonicalImageHarness::new()
                .event_stream_digest(&terminal.images[0].events, &never_cancelled)
                .expect("digest malformed timeout terminal"),
        );
        assert_eq!(
            validate_canonical_runtime_timeout_report(&encode_report(&terminal), &bundle),
            Err(SmokeFailure::InvalidReport(
                "runtime-timeout lifecycle is not the exact complete two-event prefix"
            ))
        );

        let mut completed = report.clone();
        completed.images[0].cases = fixture_report(&bundle).images[0].cases.clone();
        assert_eq!(
            validate_canonical_runtime_timeout_report(&encode_report(&completed), &bundle),
            Err(SmokeFailure::InvalidReport(
                "runtime-timeout outcome is not the exact runtime infrastructure timeout"
            ))
        );

        let mut wrong_digest = report.clone();
        wrong_digest.images[0].evidence.event_stream_digest = Some(digest(0x99));
        assert_eq!(
            validate_canonical_runtime_timeout_report(&encode_report(&wrong_digest), &bundle),
            Err(SmokeFailure::InvalidReport(
                "runtime-timeout event-stream digest differs from its complete prefix"
            ))
        );

        let mut wrong_exit = report;
        wrong_exit.images[0].evidence.exit_code = Some(0);
        assert_eq!(
            validate_canonical_runtime_timeout_report(&encode_report(&wrong_exit), &bundle),
            Err(SmokeFailure::InvalidReport(
                "runtime-timeout evidence differs from the verified emulator and target"
            ))
        );

        let mut truncated = encoded;
        truncated
            .pop()
            .expect("canonical timeout report is nonempty");
        assert_eq!(
            validate_canonical_runtime_timeout_report(&truncated, &bundle),
            Err(SmokeFailure::InvalidReport("canonical decoding failed"))
        );
    }

    #[test]
    fn runtime_timeout_evidence_line_is_bounded_canonical_and_path_free() {
        let run_binding = "ab".repeat(32);
        let evidence = CanonicalSmokeEvidence {
            image_digest: digest(0x11),
            image_bytes: 4096,
            report_digest: digest(0x22),
            report_bytes: 512,
            event_stream_digest: digest(0x33),
            event_stream_bytes: 128,
        };
        let line = runtime_timeout_evidence_line(evidence, &run_binding)
            .expect("canonical runtime-timeout evidence");
        assert!(line.starts_with(concat!(
            "WRELA_RUNTIME_TIMEOUT_QEMU_EVIDENCE schema=1 ",
            "outcome=runtime-timeout timeout_ns=65000000000 "
        )));
        assert!(line.len() <= 1024);
        assert!(!line.contains(['/', '\\', '\n', '\r']));
        assert_eq!(line.matches(RUNTIME_TIMEOUT_EVIDENCE_PREFIX).count(), 1);
        assert!(line.contains(&format!("run_binding_sha256={run_binding}")));
        let mut zero = evidence;
        zero.event_stream_bytes = 0;
        assert!(runtime_timeout_evidence_line(zero, &run_binding).is_err());
        for malformed_binding in [
            "00".repeat(32),
            "AB".repeat(32),
            "ab".repeat(31),
            format!("{}g0", "ab".repeat(31)),
        ] {
            assert!(runtime_timeout_evidence_line(evidence, &malformed_binding).is_err());
        }
        let mut oversized_image = evidence;
        oversized_image.image_bytes = MAX_SMOKE_IMAGE_BYTES + 1;
        assert!(runtime_timeout_evidence_line(oversized_image, &run_binding).is_err());
        let mut oversized_report = evidence;
        oversized_report.report_bytes = MAX_SMOKE_REPORT_BYTES + 1;
        assert!(runtime_timeout_evidence_line(oversized_report, &run_binding).is_err());
        let mut oversized_events = evidence;
        oversized_events.event_stream_bytes = MAX_SMOKE_REPORT_BYTES + 1;
        assert!(runtime_timeout_evidence_line(oversized_events, &run_binding).is_err());
        assert_eq!(
            decode_runtime_timeout_run_binding(Some(OsString::from(run_binding.clone())))
                .expect("canonical run binding"),
            run_binding
        );
        assert_eq!(
            decode_runtime_timeout_run_binding(None),
            Err(SmokeFailure::MissingEnvironmentDigest(
                RUNTIME_TIMEOUT_RUN_BINDING_ENV
            ))
        );
    }

    #[test]
    fn runtime_result_evidence_lines_are_ordered_canonical_and_selector_exact() {
        let evidence = CanonicalSmokeEvidence {
            image_digest: digest(0x41),
            image_bytes: 4096,
            report_digest: digest(0x42),
            report_bytes: 512,
            event_stream_digest: digest(0x43),
            event_stream_bytes: 128,
        };
        let lines = RUNTIME_RESULT_CASES.map(|case| {
            runtime_result_evidence_line(case, evidence).expect("canonical runtime-result evidence")
        });
        assert!(lines[0].starts_with(concat!(
            "WRELA_RUNTIME_RESULT_QEMU_EVIDENCE schema=1 ",
            "selector=result_try_ok_yields_payload outcome=passed "
        )));
        assert!(lines[1].starts_with(concat!(
            "WRELA_RUNTIME_RESULT_QEMU_EVIDENCE schema=1 ",
            "selector=result_try_err_propagates_exact_error outcome=passed "
        )));
        assert_ne!(lines[0], lines[1]);
        for line in lines {
            assert_eq!(line.matches(RUNTIME_RESULT_EVIDENCE_PREFIX).count(), 1);
            assert!(!line.contains(['/', '\\', '\n', '\r']));
            assert_eq!(line.split_whitespace().count(), 10);
        }
        let mut zero = evidence;
        zero.report_bytes = 0;
        assert!(runtime_result_evidence_line(RUNTIME_RESULT_CASES[0], zero).is_err());
    }

    #[test]
    fn typed_language_fatal_failed_report_preserves_exact_cause_and_counts() {
        let bundle = fixture_bundle(&unique_root("typed-fatal-toolchain"));
        let mut encodings = Vec::new();
        for (cause, label) in [
            (
                LanguageFatalCause::CheckedShiftResultLoss,
                "checked-shift-result-loss",
            ),
            (LanguageFatalCause::InvalidShiftCount, "invalid-shift-count"),
        ] {
            let report = fixture_language_fatal_report(&bundle, cause);
            let image = &report.images[0];
            assert_eq!(image.evidence.exit_code, Some(0));
            validate_real_producer_lifecycle(
                &image.events,
                image.cases[0].descriptor.id,
                &GuestTestOutcome::LanguageFatal { cause },
            )
            .expect("validate exact four-event typed-fatal lifecycle");

            let encoded = encode_report(&report);
            let diagnostic = CanonicalFailedReportDiagnostic {
                bytes: u64::try_from(encoded.len()).expect("fixture report length fits u64"),
                failed_outcomes: 1,
                first_scope: FailedReportScope::ImageCase { group: 0, index: 0 },
                first_outcome: FailedOutcomeDiagnostic::LanguageFatal { cause },
            };
            assert_eq!(
                diagnose_canonical_failed_report(&encoded),
                FailedReportObservation::Canonical(Box::new(diagnostic.clone()))
            );
            let rendered = diagnostic.to_string();
            assert!(rendered.contains("failed_outcomes=1"));
            assert!(rendered.contains("first=image-group[0].case[0]"));
            assert!(rendered.contains("class=language-fatal"));
            assert!(rendered.contains(label));
            assert!(!rendered.contains("message="));
            encodings.push(encoded);
        }
        assert_ne!(encodings[0], encodings[1]);

        let result_loss =
            fixture_language_fatal_report(&bundle, LanguageFatalCause::CheckedShiftResultLoss);
        assert!(
            validate_real_producer_lifecycle(
                &result_loss.images[0].events,
                result_loss.images[0].cases[0].descriptor.id,
                &GuestTestOutcome::LanguageFatal {
                    cause: LanguageFatalCause::InvalidShiftCount,
                },
            )
            .is_err()
        );
    }

    #[test]
    fn failed_test_process_observes_canonical_report_before_private_cleanup() {
        let root = unique_root("failed-report-diagnostic");
        let cleanup = RunRootGuard::create(&root).expect("create private diagnostic root");
        let output = root.join("output");
        create_private_directory(&output);

        let bundle = fixture_bundle(&unique_root("failed-report-toolchain"));
        let mut report = fixture_report(&bundle);
        let private_path = "/private/volatile/run-root/backend-output";
        let message = format!("{private_path}: image entry failed before the guest lifecycle");
        report.images[0].infrastructure_failure = Some(TestOutcome::Failed {
            phase: FailurePhase::Boot,
            message: message.clone(),
        });
        let encoded = encode_report(&report);
        let report_path = output.join("test-report.bin");
        write_new(&report_path, &encoded);

        let expected_message =
            BoundedFailureMessage::observe(&message).expect("observe bounded fixture message");
        assert_eq!(
            observe_failed_test_report(&report_path),
            FailedReportObservation::Canonical(Box::new(CanonicalFailedReportDiagnostic {
                bytes: u64::try_from(encoded.len()).expect("fixture report length fits u64"),
                failed_outcomes: 1,
                first_scope: FailedReportScope::ImageInfrastructure { group: 0 },
                first_outcome: FailedOutcomeDiagnostic::Failed {
                    phase: FailurePhase::Boot,
                    message: expected_message,
                },
            }))
        );

        let failure = SmokeFailure::FailedTestProcess {
            process: Box::new(bounded_process_failure(
                BoundedProcessFailureKind::Exit { code: Some(1) },
                Some(42),
                b"test failed\n".to_vec(),
                Vec::new(),
            )),
            report: Box::new(observe_failed_test_report(&report_path)),
        }
        .to_string();
        assert!(failure.contains("Exit { code: Some(1) }"));
        assert!(failure.contains("stdout=public-test-failed bytes=12"));
        assert!(failure.contains("stderr=empty bytes=0"));
        assert!(failure.contains("first=image-group[0].infrastructure"));
        assert!(failure.contains("class=failed phase=boot"));
        assert!(failure.contains("message=opaque-nonempty"));
        assert!(!failure.contains(private_path));
        assert!(!failure.contains("sha256"));
        assert!(!failure.contains("Some(42)"));
        assert!(failure.len() < 2_048, "diagnostic expansion is not bounded");

        cleanup.cleanup().expect("cleanup private diagnostic root");
        assert!(!root.exists());
    }

    #[test]
    fn failed_report_observation_classifies_missing_empty_and_malformed_inputs() {
        let root = unique_root("failed-report-shapes");
        let cleanup = RunRootGuard::create(&root).expect("create private diagnostic root");
        assert_eq!(
            observe_failed_test_report(&root.join("missing.bin")),
            FailedReportObservation::Missing
        );

        let empty = root.join("empty.bin");
        write_new(&empty, &[]);
        assert_eq!(
            observe_failed_test_report(&empty),
            FailedReportObservation::InvalidLength
        );

        let malformed = root.join("malformed.bin");
        write_new(&malformed, &[0]);
        assert_eq!(
            observe_failed_test_report(&malformed),
            FailedReportObservation::DecodeFailed
        );

        let bundle = fixture_bundle(&unique_root("invalid-failed-report-toolchain"));
        let mut invalid_outcome = fixture_report(&bundle);
        invalid_outcome.images[0].infrastructure_failure = Some(TestOutcome::Passed);
        assert_eq!(
            diagnose_canonical_failed_report(&encode_report(&invalid_outcome)),
            FailedReportObservation::SemanticallyInvalid
        );
        cleanup.cleanup().expect("cleanup private diagnostic root");
        assert!(!root.exists());
    }

    #[cfg(unix)]
    #[test]
    fn failed_report_observation_rejects_hardlinks() {
        let root = unique_root("failed-report-hardlink");
        let cleanup = RunRootGuard::create(&root).expect("create private hardlink root");
        let original = root.join("original.bin");
        let linked = root.join("test-report.bin");
        write_new(&original, b"not a report");
        fs::hard_link(&original, &linked).expect("create hostile report hardlink");

        assert_eq!(
            observe_failed_test_report(&linked),
            FailedReportObservation::UnreadableOrUnsafe
        );
        assert_eq!(
            read_bounded_file(&linked, MAX_SMOKE_REPORT_BYTES),
            Err(SmokeFailure::InvalidReport(
                "bounded file shape or byte length is invalid"
            ))
        );

        cleanup.cleanup().expect("cleanup private hardlink root");
        assert!(!root.exists());
    }

    #[test]
    fn real_qemu_evidence_line_is_stable_canonical_and_path_free() {
        let line = CanonicalSmokeEvidence {
            image_digest: digest(0x11),
            image_bytes: 4096,
            report_digest: digest(0x22),
            report_bytes: 512,
            event_stream_digest: digest(0x33),
            event_stream_bytes: 128,
        }
        .line()
        .expect("canonical evidence line");
        assert_eq!(
            line,
            concat!(
                "WRELA_REAL_QEMU_EVIDENCE schema=1 ",
                "image_sha256=1111111111111111111111111111111111111111111111111111111111111111 ",
                "image_bytes=4096 ",
                "report_sha256=2222222222222222222222222222222222222222222222222222222222222222 ",
                "report_bytes=512 ",
                "event_stream_sha256=3333333333333333333333333333333333333333333333333333333333333333 ",
                "event_stream_bytes=128",
            )
        );
        assert!(!line.contains(['/', '\\', '\n', '\r']));
        assert_eq!(line.matches(REAL_QEMU_EVIDENCE_PREFIX).count(), 1);
    }

    #[test]
    fn bounded_output_observation_rejects_symlinks_and_nonregular_entries() {
        let root = unique_root("bounded-output");
        let cleanup = RunRootGuard::create(&root).expect("create bounded-output root");
        let output = root.join("output");
        create_private_directory(&output);
        let image = output.join("bootstrap.efi");
        write_new(&image, b"efi image");
        assert_eq!(
            find_efi_images(&output).expect("bounded EFI enumeration"),
            vec![image.clone()]
        );
        assert_eq!(
            read_bounded_file(&image, 9).expect("bounded EFI read"),
            b"efi image"
        );
        assert_eq!(
            read_bounded_file(&image, 8),
            Err(SmokeFailure::InvalidReport(
                "bounded file shape or byte length is invalid"
            ))
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let alias = output.join("alias.efi");
            symlink(&image, &alias).expect("create hostile output symlink");
            assert_eq!(
                find_efi_images(&output),
                Err(SmokeFailure::InvalidReport(
                    "output tree contains a symlink"
                ))
            );
        }
        cleanup.cleanup().expect("cleanup bounded-output root");
    }
}
