//! Host orchestration for AArch64 QEMU full-image tests.
//!
//! The runner does not execute Wrela functions on the host. It launches an
//! emitted UEFI image under the target-owned machine profile and consumes the
//! structured guest test protocol.

#![forbid(unsafe_code)]

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};

use wrela_build_model::{BuildIdentity, Sha256Digest};
use wrela_target::TargetPackage;
use wrela_test_model::{
    FullImageTestGroup, ImageGroupId, ImageGroupResult, ImageRoot, ImageScenario, TestCaseResult,
    TestEvent, TestModelError, TestReport, ValidatedTestPlan, ValidatedTestReport,
};
use wrela_toolchain::{VerifiedPath, VerifiedToolchain};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunnerLimits {
    pub arguments: u32,
    pub environment_variables: u32,
    pub command_bytes: u64,
    pub path_bytes: u64,
}

impl RunnerLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            arguments: 4096,
            environment_variables: 1024,
            command_bytes: 16 * 1024 * 1024,
            path_bytes: 1024 * 1024,
        }
    }

    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.arguments > 0
            && self.environment_variables > 0
            && self.command_bytes > 0
            && self.path_bytes > 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageArtifact {
    path: PathBuf,
    digest: Sha256Digest,
    bytes: u64,
    group: ImageGroupId,
    build: BuildIdentity,
}

impl ImageArtifact {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        self.digest
    }

    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    #[must_use]
    pub fn group(&self) -> ImageGroupId {
        self.group
    }

    #[must_use]
    pub fn build(&self) -> &BuildIdentity {
        &self.build
    }
}

#[derive(Debug)]
pub struct ImageArtifactRequest<'a> {
    pub plan: &'a ValidatedTestPlan,
    pub group: ImageGroupId,
    pub path: PathBuf,
    pub digest: Sha256Digest,
    pub bytes: u64,
    pub maximum_bytes: u64,
    pub build: BuildIdentity,
}

pub fn seal_image_artifact(
    request: ImageArtifactRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ImageArtifact, RunError> {
    if is_cancelled() {
        return Err(RunError::Cancelled);
    }
    if request.plan.group(request.group).is_none()
        || request.build != *request.plan.build()
        || !normal_absolute_path(&request.path)
        || request.path.components().count() <= 1
        || request.bytes == 0
        || request.digest.as_bytes().iter().all(|byte| *byte == 0)
        || request.maximum_bytes == 0
        || request.bytes > request.maximum_bytes
    {
        return Err(RunError::ArtifactSetMismatch);
    }
    if is_cancelled() {
        return Err(RunError::Cancelled);
    }
    Ok(ImageArtifact {
        path: request.path,
        digest: request.digest,
        bytes: request.bytes,
        group: request.group,
        build: request.build,
    })
}

#[derive(Debug)]
pub struct RunRequest<'a> {
    pub plan: &'a ValidatedTestPlan,
    pub artifacts: &'a [ImageArtifact],
    /// Compiler-evaluated unit results produced by semantic analysis.
    pub comptime_results: &'a [TestCaseResult],
    pub target: &'a TargetPackage,
    pub toolchain: &'a VerifiedToolchain,
    pub working_directory: &'a Path,
    pub limits: RunnerLimits,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSpecification {
    pub program: VerifiedPath,
    pub arguments: Vec<OsString>,
    pub current_directory: PathBuf,
    /// Environment is exact and sorted; the ambient host environment is not
    /// inherited by an executor.
    pub environment: Vec<(OsString, OsString)>,
    pub timeout_ns: u64,
    /// Aggregate child stdout and stderr ceiling. The executor must terminate
    /// collection before either allocation or their sum can exceed it.
    pub maximum_output_bytes: u64,
    /// Exact EFI and firmware sources that the executor must hash while copying
    /// into private per-run destinations before launch. Arguments may reference
    /// only the materialized destinations, never the installation templates.
    pub inputs: Vec<ProcessInput>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInput {
    pub source: VerifiedProcessFile,
    pub destination: PathBuf,
    /// Only the copied UEFI variable store is writable by the child.
    pub writable: bool,
}

/// Exact source identity allowed to cross into the process executor. It can be
/// derived only from a verified installation path or a sealed image artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedProcessFile {
    path: PathBuf,
    digest: Sha256Digest,
    bytes: u64,
}

impl VerifiedProcessFile {
    #[must_use]
    pub fn from_toolchain(path: &VerifiedPath) -> Self {
        Self {
            path: path.path().to_owned(),
            digest: path.digest(),
            bytes: path.bytes(),
        }
    }

    #[must_use]
    pub fn from_image(artifact: &ImageArtifact) -> Self {
        Self {
            path: artifact.path().to_owned(),
            digest: artifact.digest(),
            bytes: artifact.bytes(),
        }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessOutput {
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub duration_ns: u64,
}

/// Least-authority toolchain view required to construct one target-owned QEMU
/// command. The harness cannot reach the compiler backend, standard library,
/// or any undeclared installation path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageExecutionComponents {
    pub emulator: VerifiedPath,
    pub target_package: VerifiedPath,
    pub firmware_code: VerifiedPath,
    pub firmware_variables: VerifiedPath,
}

/// The only process-launch capability. Production uses a bounded child-process
/// implementation; tests inject a fake without needing QEMU. Before spawning,
/// it must reverify the program and hash each source while copying exactly the
/// declared byte count into its private destination, then apply read-only/
/// writable permissions as declared. A mismatch removes staged files and never
/// launches the child.
pub trait ProcessExecutor {
    fn execute(
        &self,
        specification: &ProcessSpecification,
        // Declared image scenarios may drive and observe the live PL011
        // session. `None` is a generated integration harness.
        scenario: Option<&ImageScenario>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ProcessOutput, ExecuteError>;
}

/// Target-specific invocation construction and structured event decoding are
/// separately injectable, allowing the orchestration contract to be tested
/// independently of emulator availability.
pub struct ImageCommandRequest<'a> {
    pub group: &'a FullImageTestGroup,
    pub artifact: &'a ImageArtifact,
    pub target: &'a TargetPackage,
    pub components: &'a ImageExecutionComponents,
    pub working_directory: &'a Path,
    pub scenario: Option<&'a ImageScenario>,
}

pub struct ImageSummaryRequest<'a> {
    pub group: &'a FullImageTestGroup,
    pub artifact: &'a ImageArtifact,
    pub command: &'a ProcessSpecification,
    pub output: ProcessOutput,
    pub events: &'a [TestEvent],
    pub scenario: Option<&'a ImageScenario>,
}

pub trait ImageHarness {
    fn command(
        &self,
        request: ImageCommandRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ProcessSpecification, RunError>;

    fn decode_events(
        &self,
        group: &FullImageTestGroup,
        output: &ProcessOutput,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<TestEvent>, RunError>;

    /// Digest the canonical executable/argument/environment/limit encoding
    /// used in reproducibility evidence.
    fn command_digest(
        &self,
        command: &ProcessSpecification,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Sha256Digest, RunError>;

    /// Digest the canonical re-encoding of the complete decoded event stream.
    fn event_stream_digest(
        &self,
        events: &[TestEvent],
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Sha256Digest, RunError>;

    fn summarize(
        &self,
        request: ImageSummaryRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ImageGroupResult, RunError>;
}

pub struct TestRunner<'a> {
    pub executor: &'a dyn ProcessExecutor,
    pub harness: &'a dyn ImageHarness,
}

impl TestRunner<'_> {
    pub fn run(
        &self,
        request: RunRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ValidatedTestReport, RunError> {
        let plan = request.plan.as_plan();
        if !request.limits.is_valid()
            || !normal_absolute_path(request.working_directory)
            || request.working_directory.components().count() <= 1
        {
            return Err(RunError::InvalidInvocation(
                "test working directory must be a normalized absolute private directory".to_owned(),
            ));
        }
        request
            .target
            .validate()
            .map_err(|error| RunError::Target(error.to_string()))?;
        if request.target.identity() != &plan.target {
            return Err(RunError::TargetMismatch);
        }
        let installed_target = request
            .toolchain
            .target(&plan.target)
            .map_err(|error| RunError::Toolchain(error.to_string()))?;
        if installed_target.digest() != request.target.semantic().content_digest() {
            return Err(RunError::TargetPackageDigestMismatch);
        }
        let emulator = request
            .toolchain
            .aarch64_emulator()
            .map_err(|error| RunError::Toolchain(error.to_string()))?;
        let firmware_code = request
            .toolchain
            .target_file(&plan.target, request.target.runner().firmware_code())
            .map_err(|error| RunError::Toolchain(error.to_string()))?;
        let firmware_variables = request
            .toolchain
            .target_file(
                &plan.target,
                request.target.runner().firmware_variables_template(),
            )
            .map_err(|error| RunError::Toolchain(error.to_string()))?;
        let execution_components = ImageExecutionComponents {
            emulator: emulator.clone(),
            target_package: installed_target.clone(),
            firmware_code,
            firmware_variables,
        };
        let frontend = request
            .toolchain
            .component(wrela_toolchain::ComponentKind::Frontend)
            .map_err(|error| RunError::Toolchain(error.to_string()))?;
        let standard_library = request
            .toolchain
            .standard_library()
            .map_err(|error| RunError::Toolchain(error.to_string()))?;
        if request.toolchain.manifest().compatibility.language != plan.build.language {
            return Err(RunError::ToolchainLanguageMismatch);
        }
        if frontend.digest() != plan.build.compiler {
            return Err(RunError::CompilerDigestMismatch);
        }
        if standard_library.digest() != plan.build.standard_library {
            return Err(RunError::StandardLibraryDigestMismatch);
        }
        let planned_groups: std::collections::BTreeSet<_> =
            plan.image_groups.iter().map(|group| group.id).collect();
        let artifact_groups: std::collections::BTreeSet<_> =
            request.artifacts.iter().map(ImageArtifact::group).collect();
        let artifact_paths: std::collections::BTreeSet<_> =
            request.artifacts.iter().map(ImageArtifact::path).collect();
        let artifacts_by_group: std::collections::BTreeMap<_, _> = request
            .artifacts
            .iter()
            .map(|artifact| (artifact.group(), artifact))
            .collect();
        if request.artifacts.len() != plan.image_groups.len()
            || artifact_groups != planned_groups
            || artifact_paths.len() != request.artifacts.len()
            || artifacts_by_group.len() != request.artifacts.len()
            || request.artifacts.iter().any(|artifact| {
                !normal_absolute_path(artifact.path()) || artifact.build() != &plan.build
            })
        {
            return Err(RunError::ArtifactSetMismatch);
        }
        if request.comptime_results.len() != plan.unit_tests.len()
            || !request
                .comptime_results
                .iter()
                .zip(&plan.unit_tests)
                .all(|(result, planned)| result.descriptor == planned.descriptor)
        {
            return Err(RunError::InvalidReport(TestModelError::ResultSetMismatch(
                "comptime".to_owned(),
            )));
        }
        let mut images = Vec::with_capacity(plan.image_groups.len());
        for group in &plan.image_groups {
            if is_cancelled() {
                return Err(RunError::Cancelled);
            }
            let artifact = artifacts_by_group
                .get(&group.id)
                .copied()
                .ok_or_else(|| RunError::MissingArtifact(group.name.clone()))?;
            let scenario = match &group.root {
                ImageRoot::GeneratedHarness { .. } => None,
                ImageRoot::Declared { scenario, .. } => plan
                    .scenarios
                    .get(scenario.0 as usize)
                    .ok_or(RunError::InvalidPlan(TestModelError::InvalidScenario(
                        *scenario,
                    )))
                    .map(Some)?,
            };
            let command = self.harness.command(
                ImageCommandRequest {
                    group,
                    artifact,
                    target: request.target,
                    components: &execution_components,
                    working_directory: request.working_directory,
                    scenario,
                },
                is_cancelled,
            )?;
            let expected_timeout = group
                .execution_timeout_ns(scenario)
                .ok_or_else(|| RunError::InvalidInvocation("timeout budget overflow".to_owned()))?;
            if command.program != emulator
                || command.timeout_ns != expected_timeout
                || command.maximum_output_bytes != group.maximum_output_bytes
                || !safe_working_directory(request.working_directory, &command.current_directory)
                || !valid_process_inputs(
                    request.working_directory,
                    &command.inputs,
                    artifact,
                    &execution_components,
                )
                || !command
                    .environment
                    .windows(2)
                    .all(|pair| pair[0].0 < pair[1].0)
                || !valid_process_shape(&command, request.limits)
            {
                return Err(RunError::InvalidInvocation(format!(
                    "group {:?} command violates the verified emulator, directory, environment, timeout, or output contract",
                    group.name
                )));
            }
            let output = self
                .executor
                .execute(&command, scenario, is_cancelled)
                .map_err(RunError::Execute)?;
            if is_cancelled() {
                return Err(RunError::Cancelled);
            }
            if output.duration_ns > command.timeout_ns {
                return Err(RunError::InvalidInvocation(format!(
                    "group {:?} executor exceeded its sealed timeout",
                    group.name
                )));
            }
            let output_bytes = output
                .stdout
                .len()
                .checked_add(output.stderr.len())
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or(RunError::OutputLimitExceeded(group.name.clone()))?;
            if output_bytes > group.maximum_output_bytes {
                return Err(RunError::OutputLimitExceeded(group.name.clone()));
            }
            let events = self.harness.decode_events(group, &output, is_cancelled)?;
            if events.len() > group.maximum_events as usize {
                return Err(RunError::EventLimitExceeded(group.name.clone()));
            }
            let result = self.harness.summarize(
                ImageSummaryRequest {
                    group,
                    artifact,
                    command: &command,
                    output,
                    events: &events,
                    scenario,
                },
                is_cancelled,
            )?;
            let command_digest = self.harness.command_digest(&command, is_cancelled)?;
            let event_stream_digest = self.harness.event_stream_digest(&events, is_cancelled)?;
            if result.evidence.image_digest != Some(artifact.digest())
                || result.evidence.target_digest != plan.build.target_package
                || result.evidence.emulator_digest != Some(emulator.digest())
                || result.evidence.scenario_digest != scenario.map(|item| item.digest)
                || result.evidence.command_digest != Some(command_digest)
                || result.evidence.event_stream_digest != Some(event_stream_digest)
                || result.events != events
            {
                return Err(RunError::EvidenceMismatch(group.name.clone()));
            }
            images.push(result);
        }
        let report = TestReport {
            schema: wrela_test_model::TEST_REPORT_SCHEMA,
            build: plan.build.clone(),
            started_unix_ns: None,
            duration_ns: None,
            unit: request.comptime_results.to_vec(),
            images,
        };
        report
            .seal_against(request.plan)
            .map_err(RunError::InvalidReport)
    }
}

fn valid_process_shape(command: &ProcessSpecification, limits: RunnerLimits) -> bool {
    if command.arguments.len() > limits.arguments as usize
        || command.environment.len() > limits.environment_variables as usize
    {
        return false;
    }
    let path_bytes = [command.program.path(), &command.current_directory]
        .into_iter()
        .chain(
            command
                .inputs
                .iter()
                .flat_map(|input| [input.source.path(), &input.destination]),
        )
        .try_fold(0u64, |total, path| {
            total.checked_add(u64::try_from(path.as_os_str().as_encoded_bytes().len()).ok()?)
        });
    let command_bytes = command
        .arguments
        .iter()
        .chain(
            command
                .environment
                .iter()
                .flat_map(|(name, value)| [name, value]),
        )
        .try_fold(0u64, |total, value| {
            total.checked_add(u64::try_from(value.as_encoded_bytes().len()).ok()?)
        });
    path_bytes.is_some_and(|bytes| bytes <= limits.path_bytes)
        && command_bytes.is_some_and(|bytes| bytes <= limits.command_bytes)
        && command
            .environment
            .iter()
            .all(|(name, _)| !name.is_empty() && !name.as_encoded_bytes().contains(&0))
        && command
            .arguments
            .iter()
            .all(|argument| !argument.as_encoded_bytes().contains(&0))
}

fn valid_process_inputs(
    working_directory: &Path,
    inputs: &[ProcessInput],
    artifact: &ImageArtifact,
    components: &ImageExecutionComponents,
) -> bool {
    let expected = [
        (VerifiedProcessFile::from_image(artifact), false),
        (
            VerifiedProcessFile::from_toolchain(&components.firmware_code),
            false,
        ),
        (
            VerifiedProcessFile::from_toolchain(&components.firmware_variables),
            true,
        ),
    ];
    valid_exact_process_inputs(working_directory, inputs, &expected)
}

fn valid_exact_process_inputs(
    working_directory: &Path,
    inputs: &[ProcessInput],
    expected: &[(VerifiedProcessFile, bool)],
) -> bool {
    let source_paths: std::collections::BTreeSet<_> =
        inputs.iter().map(|input| input.source.path()).collect();
    if inputs.len() != expected.len()
        || !inputs
            .windows(2)
            .all(|pair| pair[0].destination < pair[1].destination)
        || inputs.iter().any(|input| {
            !normal_absolute_path(input.source.path())
                || input.source.bytes() == 0
                || !private_child(working_directory, &input.destination)
                || input.source.path() == input.destination
        })
        || source_paths.len() != inputs.len()
    {
        return false;
    }
    expected.iter().all(|(source, writable)| {
        inputs
            .iter()
            .any(|input| &input.source == source && input.writable == *writable)
    })
}

fn private_child(root: &Path, candidate: &Path) -> bool {
    safe_working_directory(root, candidate)
        && candidate.components().count() > root.components().count()
}

fn safe_working_directory(root: &Path, candidate: &Path) -> bool {
    normal_absolute_path(root)
        && root.components().count() > 1
        && normal_absolute_path(candidate)
        && candidate.starts_with(root)
}

fn normal_absolute_path(path: &Path) -> bool {
    let normalized: PathBuf = path.components().collect();
    path.is_absolute()
        && !path.as_os_str().is_empty()
        && normalized.as_os_str() == path.as_os_str()
        && !path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
}

#[derive(Debug)]
pub enum ExecuteError {
    Spawn(std::io::Error),
    Wait(std::io::Error),
    Cancelled,
    OutputLimit { stream: &'static str, limit: u64 },
}

#[derive(Debug)]
pub enum RunError {
    Cancelled,
    InvalidPlan(TestModelError),
    InvalidReport(TestModelError),
    Target(String),
    TargetMismatch,
    TargetPackageDigestMismatch,
    ToolchainLanguageMismatch,
    CompilerDigestMismatch,
    StandardLibraryDigestMismatch,
    Toolchain(String),
    ArtifactSetMismatch,
    MissingArtifact(String),
    MissingEmulator,
    MissingFirmware,
    InvalidInvocation(String),
    OutputLimitExceeded(String),
    EventLimitExceeded(String),
    Execute(ExecuteError),
    GuestProtocol(TestModelError),
    MissingTerminalEvent,
    DuplicateTerminalEvent,
    EventSequence { expected: u64, actual: u64 },
    UnexpectedTestEvent(String),
    EvidenceMismatch(String),
}

impl fmt::Display for RunError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("test execution was cancelled"),
            Self::InvalidPlan(error) => error.fmt(formatter),
            Self::InvalidReport(error) => error.fmt(formatter),
            Self::Target(message) => write!(formatter, "invalid test target: {message}"),
            Self::TargetMismatch => formatter.write_str("test plan and selected target differ"),
            Self::TargetPackageDigestMismatch => formatter.write_str(
                "selected target package digest differs from the verified toolchain target",
            ),
            Self::ToolchainLanguageMismatch => {
                formatter.write_str("test plan language differs from the verified toolchain")
            }
            Self::CompilerDigestMismatch => {
                formatter.write_str("test plan compiler differs from the verified frontend")
            }
            Self::StandardLibraryDigestMismatch => formatter
                .write_str("test plan standard library differs from the verified toolchain"),
            Self::Toolchain(message) => write!(formatter, "invalid test toolchain: {message}"),
            Self::ArtifactSetMismatch => {
                formatter.write_str("test artifact set does not match full-image groups")
            }
            Self::MissingArtifact(group) => {
                write!(formatter, "missing image artifact for test group {group}")
            }
            Self::MissingEmulator => {
                formatter.write_str("the selected toolchain has no AArch64 emulator")
            }
            Self::MissingFirmware => {
                formatter.write_str("the selected target has no UEFI firmware image")
            }
            Self::InvalidInvocation(message) => {
                write!(formatter, "invalid emulator invocation: {message}")
            }
            Self::OutputLimitExceeded(group) => {
                write!(formatter, "image group {group:?} exceeded its output limit")
            }
            Self::EventLimitExceeded(group) => {
                write!(formatter, "image group {group:?} exceeded its event limit")
            }
            Self::Execute(error) => write!(formatter, "emulator execution failed: {error:?}"),
            Self::GuestProtocol(error) => error.fmt(formatter),
            Self::MissingTerminalEvent => {
                formatter.write_str("guest test stream ended without RunFinished")
            }
            Self::DuplicateTerminalEvent => {
                formatter.write_str("guest emitted more than one RunFinished event")
            }
            Self::EventSequence { expected, actual } => write!(
                formatter,
                "guest test event sequence gap: expected {expected}, got {actual}"
            ),
            Self::UnexpectedTestEvent(message) => {
                write!(formatter, "unexpected guest test event: {message}")
            }
            Self::EvidenceMismatch(group) => {
                write!(
                    formatter,
                    "execution evidence does not match test group {group}"
                )
            }
        }
    }
}

impl std::error::Error for RunError {}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::{
        ImageArtifact, ProcessInput, VerifiedProcessFile, safe_working_directory,
        valid_exact_process_inputs,
    };
    use wrela_build_model::{BuildIdentity, LanguageRevision, Sha256Digest, TargetIdentity};
    use wrela_test_model::ImageGroupId;

    #[test]
    fn emulator_working_directories_cannot_escape_or_alias() {
        assert!(safe_working_directory(
            Path::new("/private/wrela/tests"),
            Path::new("/private/wrela/tests/group")
        ));
        assert!(!safe_working_directory(Path::new("/"), Path::new("/tmp")));
        assert!(!safe_working_directory(
            Path::new("/private/wrela/tests"),
            Path::new("/private/wrela/tests/../escape")
        ));
        assert!(!safe_working_directory(
            Path::new("/private/./wrela/tests"),
            Path::new("/private/wrela/tests/group")
        ));
    }

    #[test]
    fn process_inputs_stage_exact_artifact_and_firmware_set() {
        let digest = Sha256Digest::from_bytes([7; 32]);
        let verified = |path: &str, byte: u8| VerifiedProcessFile {
            path: PathBuf::from(path),
            digest: Sha256Digest::from_bytes([byte; 32]),
            bytes: 64,
        };
        let artifact = ImageArtifact {
            path: PathBuf::from("/build/appliance.efi"),
            digest,
            bytes: 128,
            group: ImageGroupId(0),
            build: BuildIdentity {
                compiler: digest,
                language: LanguageRevision::Design0_1,
                target: TargetIdentity::aarch64_qemu_virt_uefi(),
                target_package: digest,
                standard_library: digest,
                source_graph: digest,
                request: digest,
                profile: digest,
            },
        };
        let firmware_code = verified("/toolchain/firmware/code.fd", 3);
        let firmware_variables = verified("/toolchain/firmware/vars.fd", 4);
        let root = Path::new("/private/wrela/tests/group-0");
        let mut inputs = vec![
            ProcessInput {
                source: VerifiedProcessFile::from_image(&artifact),
                destination: root.join("appliance.efi"),
                writable: false,
            },
            ProcessInput {
                source: firmware_code.clone(),
                destination: root.join("code.fd"),
                writable: false,
            },
            ProcessInput {
                source: firmware_variables.clone(),
                destination: root.join("vars.fd"),
                writable: true,
            },
        ];
        inputs.sort_by(|left, right| left.destination.cmp(&right.destination));
        let expected = [
            (VerifiedProcessFile::from_image(&artifact), false),
            (firmware_code, false),
            (firmware_variables, true),
        ];
        assert!(valid_exact_process_inputs(root, &inputs, &expected));
        inputs
            .iter_mut()
            .find(|input| input.writable)
            .expect("writable variables")
            .writable = false;
        assert!(!valid_exact_process_inputs(root, &inputs, &expected));
    }
}
