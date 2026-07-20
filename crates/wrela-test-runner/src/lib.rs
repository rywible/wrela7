//! Host orchestration for AArch64 QEMU full-image tests.
//!
//! The runner does not execute Wrela functions on the host. It launches an
//! emitted UEFI image under the target-owned machine profile and consumes the
//! structured guest test protocol.

#![forbid(unsafe_code)]

mod harness;
mod local;
mod sha256;

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};

use wrela_build_model::{BuildIdentity, Sha256Digest};
use wrela_target::TargetPackage;
use wrela_test_model::{
    FailurePhase, FullImageTestGroup, ImageGroupId, ImageGroupResult, ImageRoot, ImageScenario,
    TestCaseResult, TestEvent, TestModelError, TestOutcome, TestReport, ValidatedTestPlan,
    ValidatedTestReport,
};
use wrela_test_protocol::ProtocolLimits;
use wrela_toolchain::{VerifiedPath, VerifiedToolchain};

pub use harness::CanonicalImageHarness;
pub use local::LocalProcessExecutor;

/// Conservative cross-Unix pathname ceiling for the private QMP socket.
/// Darwin's `sockaddr_un.sun_path` is 104 bytes and requires a trailing NUL,
/// so at most 103 encoded pathname bytes may cross the sealed process boundary.
pub const MAX_QMP_UNIX_PATH_BYTES: usize = 103;

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
    /// Exact compile/link failures produced before a runnable image existed.
    /// Their groups must be disjoint from `artifacts`; together the two sets
    /// must cover every planned image group exactly once.
    pub preexecution_results: &'a [ImageGroupResult],
    /// Compiler-evaluated unit results produced by semantic analysis.
    pub comptime_results: &'a [TestCaseResult],
    pub target: &'a TargetPackage,
    pub toolchain: &'a VerifiedToolchain,
    pub working_directory: &'a Path,
    pub limits: RunnerLimits,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessSpecification {
    pub program: PathBuf,
    pub arguments: Vec<OsString>,
    pub current_directory: PathBuf,
    /// Environment is exact and sorted; the ambient host environment is not
    /// inherited by an executor.
    pub environment: Vec<(OsString, OsString)>,
    pub timeout_ns: u64,
    /// Exact frame/string/event policy used by both live serial observation
    /// and the final canonical protocol decode.
    pub protocol_limits: ProtocolLimits,
    /// Aggregate child stdout and stderr ceiling. The executor must terminate
    /// collection before either allocation or their sum can exceed it.
    pub maximum_output_bytes: u64,
    /// Optional private, command-bound control channel used only by an
    /// explicit `request-shutdown` scenario step. The harness declares the
    /// endpoint and matching emulator arguments; the executor may not invent
    /// or discover a monitor channel.
    pub shutdown_control: Option<ProcessShutdownControl>,
    /// Exact EFI and firmware sources that the executor must hash while copying
    /// into private per-run destinations before launch. Arguments may reference
    /// only the materialized destinations, never the installation templates.
    pub inputs: Vec<ProcessInput>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessShutdownControl {
    /// QEMU Machine Protocol server on a private Unix-domain socket. The
    /// executor negotiates QMP and issues the canonical `quit` command.
    QmpUnix { path: PathBuf },
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

    /// Construct from an ambient system path that is not tracked by any
    /// verified toolchain manifest (the system QEMU binary or its EDK2
    /// firmware). The exact bytes are measured once, immediately, by this
    /// process capability itself rather than trusted from a prior
    /// verification.
    pub fn from_system_path(path: PathBuf) -> Result<Self, std::io::Error> {
        let (digest, bytes) = crate::sha256::digest_file(&path)?;
        Ok(Self {
            path,
            digest,
            bytes,
        })
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
    /// System QEMU binary, self-measured from `wrela_toolchain::system_qemu()`.
    pub emulator: VerifiedProcessFile,
    pub target_package: VerifiedPath,
    /// System EDK2 firmware code, self-measured from
    /// `wrela_toolchain::system_firmware_code()`.
    pub firmware_code: VerifiedProcessFile,
    /// System EDK2 firmware variable-store template, self-measured from
    /// `wrela_toolchain::system_firmware_vars()`.
    pub firmware_variables: VerifiedProcessFile,
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
    pub components: &'a ImageExecutionComponents,
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
        components: &ImageExecutionComponents,
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
        enum GroupInput<'a> {
            Artifact(&'a ImageArtifact),
            Preexecution(&'a ImageGroupResult),
        }
        let mut groups = try_runner_vec(plan.image_groups.len(), "group index")?;
        groups.resize_with(plan.image_groups.len(), || None::<GroupInput<'_>>);
        let mut artifact_paths = try_runner_vec(request.artifacts.len(), "artifact paths")?;
        let mut invalid_groups = false;
        for artifact in request.artifacts {
            let Some(slot) = groups.get_mut(artifact.group().0 as usize) else {
                invalid_groups = true;
                continue;
            };
            if slot.is_some()
                || !normal_absolute_path(artifact.path())
                || artifact.build() != &plan.build
            {
                invalid_groups = true;
                continue;
            }
            *slot = Some(GroupInput::Artifact(artifact));
            artifact_paths.push(artifact.path());
        }
        for result in request.preexecution_results {
            let Some(group) = plan.image_groups.get(result.group.0 as usize) else {
                invalid_groups = true;
                continue;
            };
            let Some(slot) = groups.get_mut(result.group.0 as usize) else {
                invalid_groups = true;
                continue;
            };
            if group.id != result.group
                || slot.is_some()
                || !valid_preexecution_result(result, group, plan)
            {
                invalid_groups = true;
                continue;
            }
            *slot = Some(GroupInput::Preexecution(result));
        }
        artifact_paths.sort_unstable();
        if request
            .artifacts
            .len()
            .checked_add(request.preexecution_results.len())
            != Some(plan.image_groups.len())
            || invalid_groups
            || groups.iter().any(Option::is_none)
            || artifact_paths.windows(2).any(|pair| pair[0] == pair[1])
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
        let mut unit = try_runner_vec(request.comptime_results.len(), "comptime results")?;
        unit.extend_from_slice(request.comptime_results);
        let mut images = try_runner_vec(plan.image_groups.len(), "image results")?;
        if request.artifacts.is_empty() {
            for (index, group) in plan.image_groups.iter().enumerate() {
                let Some(GroupInput::Preexecution(result)) =
                    groups.get(index).and_then(Option::as_ref)
                else {
                    return Err(RunError::MissingArtifact(group.name.clone()));
                };
                images.push((*result).clone());
            }
            return seal_report(
                TestReport {
                    schema: wrela_test_model::TEST_REPORT_SCHEMA,
                    build: plan.build.clone(),
                    started_unix_ns: None,
                    duration_ns: None,
                    unit,
                    images,
                },
                request.plan,
                is_cancelled,
            );
        }

        // Emulator and firmware are execution capabilities, so resolve them
        // only when at least one group produced a runnable image. Neither is
        // tracked by the toolchain manifest; each is self-measured from its
        // ambient system location immediately before use.
        let emulator = VerifiedProcessFile::from_system_path(wrela_toolchain::system_qemu())
            .map_err(|error| RunError::Toolchain(format!("system qemu binary: {error}")))?;
        let firmware_code =
            VerifiedProcessFile::from_system_path(wrela_toolchain::system_firmware_code())
                .map_err(|error| {
                    RunError::Toolchain(format!("system qemu firmware code: {error}"))
                })?;
        let firmware_variables =
            VerifiedProcessFile::from_system_path(wrela_toolchain::system_firmware_vars())
                .map_err(|error| {
                    RunError::Toolchain(format!("system qemu firmware variables: {error}"))
                })?;
        let execution_components = ImageExecutionComponents {
            emulator: emulator.clone(),
            target_package: installed_target.clone(),
            firmware_code,
            firmware_variables,
        };
        for (index, group) in plan.image_groups.iter().enumerate() {
            if is_cancelled() {
                return Err(RunError::Cancelled);
            }
            let supplied = groups
                .get(index)
                .and_then(Option::as_ref)
                .ok_or_else(|| RunError::MissingArtifact(group.name.clone()))?;
            if let GroupInput::Preexecution(result) = supplied {
                images.push((*result).clone());
                continue;
            }
            let GroupInput::Artifact(artifact) = supplied else {
                return Err(RunError::ArtifactSetMismatch);
            };
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
            let execution_policy = protocol_execution_policy(group)?;
            let expected_timeout = group
                .execution_timeout_ns(scenario)
                .ok_or_else(|| RunError::InvalidInvocation("timeout budget overflow".to_owned()))?;
            if command.program.as_path() != emulator.path()
                || command.timeout_ns != expected_timeout
                || command.protocol_limits != execution_policy.limits
                || command.maximum_output_bytes != execution_policy.maximum_output_bytes
                || !safe_working_directory(request.working_directory, &command.current_directory)
                || !valid_process_inputs(
                    request.working_directory,
                    &command.inputs,
                    artifact,
                    &execution_components,
                )
                || !valid_shutdown_control(
                    request.working_directory,
                    &command.shutdown_control,
                    scenario,
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
            if output_bytes > execution_policy.maximum_output_bytes {
                return Err(RunError::OutputLimitExceeded(group.name.clone()));
            }
            let events = self.harness.decode_events(group, &output, is_cancelled)?;
            if events.len() > group.maximum_events as usize {
                return Err(RunError::EventLimitExceeded(group.name.clone()));
            }
            validate_decoded_group_prefix(group, &events, is_cancelled)?;
            let result = self.harness.summarize(
                ImageSummaryRequest {
                    group,
                    artifact,
                    command: &command,
                    components: &execution_components,
                    output,
                    events: &events,
                    scenario,
                },
                is_cancelled,
            )?;
            let command_digest =
                self.harness
                    .command_digest(&command, &execution_components, is_cancelled)?;
            let event_stream_digest = self.harness.event_stream_digest(&events, is_cancelled)?;
            if result.group != group.id
                || result.evidence.image_digest != Some(artifact.digest())
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
            unit,
            images,
        };
        seal_report(report, request.plan, is_cancelled)
    }
}

fn try_runner_vec<T>(capacity: usize, resource: &'static str) -> Result<Vec<T>, RunError> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| RunError::ResourceExhausted(resource))?;
    Ok(output)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProtocolExecutionPolicy {
    pub(crate) limits: ProtocolLimits,
    pub(crate) maximum_output_bytes: u64,
}

pub(crate) fn protocol_execution_policy(
    group: &FullImageTestGroup,
) -> Result<ProtocolExecutionPolicy, RunError> {
    let limits = ProtocolLimits {
        events: group.maximum_events,
        ..ProtocolLimits::standard()
    };
    let protocol_stream_bytes = limits
        .maximum_stream_bytes()
        .map_err(|error| RunError::Protocol(error.to_string()))?;
    let maximum_output_bytes = group.maximum_output_bytes.min(protocol_stream_bytes);
    if maximum_output_bytes == 0 {
        return Err(RunError::Protocol(
            "protocol execution output limit must be nonzero".to_owned(),
        ));
    }
    Ok(ProtocolExecutionPolicy {
        limits,
        maximum_output_bytes,
    })
}

fn validate_decoded_group_prefix(
    group: &FullImageTestGroup,
    events: &[TestEvent],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), RunError> {
    if is_cancelled() {
        return Err(RunError::Cancelled);
    }
    if events.is_empty() {
        return Ok(());
    }
    let first_test = group.tests.first().map(|test| test.descriptor.id.0);
    let is_planned = |test: wrela_test_model::TestId| {
        let Some(first_test) = first_test else {
            return false;
        };
        test.0
            .checked_sub(first_test)
            .and_then(|offset| usize::try_from(offset).ok())
            .and_then(|index| group.tests.get(index))
            .is_some_and(|planned| planned.descriptor.id == test)
    };
    let planned_count = u32::try_from(group.tests.len()).map_err(|_| {
        RunError::UnexpectedTestEvent("planned test count does not fit the protocol".to_owned())
    })?;
    for (index, event) in events.iter().enumerate() {
        if index & 1023 == 0 && is_cancelled() {
            return Err(RunError::Cancelled);
        }
        match &event.kind {
            wrela_test_model::TestEventKind::RunStarted { test_count } => {
                if index != 0 || *test_count != planned_count {
                    return Err(RunError::UnexpectedTestEvent(format!(
                        "RunStarted count {test_count} differs from selected group count {planned_count}"
                    )));
                }
            }
            wrela_test_model::TestEventKind::TestStarted { test }
            | wrela_test_model::TestEventKind::AssertionFailed { test, .. }
            | wrela_test_model::TestEventKind::TestFinished { test, .. } => {
                if !is_planned(*test) {
                    return Err(RunError::UnexpectedTestEvent(format!(
                        "event references test id {} outside the selected group",
                        test.0
                    )));
                }
            }
            wrela_test_model::TestEventKind::Log {
                test: Some(test), ..
            } => {
                if !is_planned(*test) {
                    return Err(RunError::UnexpectedTestEvent(format!(
                        "log references test id {} outside the selected group",
                        test.0
                    )));
                }
            }
            wrela_test_model::TestEventKind::Log { test: None, .. }
            | wrela_test_model::TestEventKind::Heartbeat { .. }
            | wrela_test_model::TestEventKind::RunFinished { .. } => {}
        }
    }
    if is_cancelled() {
        return Err(RunError::Cancelled);
    }
    Ok(())
}

fn seal_report(
    report: TestReport,
    plan: &ValidatedTestPlan,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ValidatedTestReport, RunError> {
    report
        .seal_against_with_cancellation(plan, is_cancelled)
        .map_err(RunError::InvalidReport)
}

fn valid_preexecution_result(
    result: &ImageGroupResult,
    group: &FullImageTestGroup,
    plan: &wrela_test_model::TestPlan,
) -> bool {
    let expected_scenario = match group.root {
        ImageRoot::GeneratedHarness { .. } => None,
        ImageRoot::Declared { scenario, .. } => plan
            .scenarios
            .get(scenario.0 as usize)
            .map(|item| item.digest),
    };
    matches!(
        result.infrastructure_failure,
        Some(TestOutcome::Failed {
            phase: FailurePhase::Discovery | FailurePhase::Compile | FailurePhase::Link,
            ..
        }) | Some(TestOutcome::TimedOut {
            phase: FailurePhase::Discovery | FailurePhase::Compile | FailurePhase::Link,
            ..
        })
    ) && result.cases.is_empty()
        && result.events.is_empty()
        && result.evidence.image_digest.is_none()
        && result.evidence.target_digest == plan.build.target_package
        && result.evidence.emulator_digest.is_none()
        && result.evidence.scenario_digest == expected_scenario
        && result.evidence.command_digest.is_none()
        && result.evidence.event_stream_digest.is_none()
        && result.evidence.exit_code.is_none()
        && result.evidence.stderr.len() as u64 <= group.maximum_output_bytes
}

fn valid_process_shape(command: &ProcessSpecification, limits: RunnerLimits) -> bool {
    if command.arguments.len() > limits.arguments as usize
        || command.environment.len() > limits.environment_variables as usize
    {
        return false;
    }
    let path_bytes = [command.program.as_path(), &command.current_directory]
        .into_iter()
        .chain(
            command
                .shutdown_control
                .iter()
                .map(|control| match control {
                    ProcessShutdownControl::QmpUnix { path } => path.as_path(),
                }),
        )
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

fn valid_shutdown_control(
    working_directory: &Path,
    control: &Option<ProcessShutdownControl>,
    scenario: Option<&ImageScenario>,
) -> bool {
    let required = scenario.is_some_and(|scenario| {
        scenario.steps.iter().any(|step| {
            matches!(
                step,
                wrela_test_model::ImageScenarioStep::RequestShutdown { .. }
            )
        })
    });
    match (required, control) {
        (false, None) => true,
        (true, Some(ProcessShutdownControl::QmpUnix { path })) => {
            private_child(working_directory, path)
                && path.file_name().and_then(|name| name.to_str()) == Some("qmp.sock")
                && valid_qmp_unix_path(path)
        }
        (false, Some(_)) | (true, None) => false,
    }
}

/// Returns whether an absolute QMP Unix-socket pathname fits the sealed
/// cross-Unix kernel boundary and contains no embedded NUL byte.
#[must_use]
pub fn valid_qmp_unix_path(path: &Path) -> bool {
    let bytes = path.as_os_str().as_encoded_bytes();
    normal_absolute_path(path) && bytes.len() <= MAX_QMP_UNIX_PATH_BYTES && !bytes.contains(&0)
}

fn valid_process_inputs(
    working_directory: &Path,
    inputs: &[ProcessInput],
    artifact: &ImageArtifact,
    components: &ImageExecutionComponents,
) -> bool {
    let expected = [
        (VerifiedProcessFile::from_image(artifact), false),
        (components.firmware_code.clone(), false),
        (components.firmware_variables.clone(), true),
    ];
    valid_exact_process_inputs(working_directory, inputs, &expected)
}

fn valid_exact_process_inputs(
    working_directory: &Path,
    inputs: &[ProcessInput],
    expected: &[(VerifiedProcessFile, bool)],
) -> bool {
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
        || inputs.iter().enumerate().any(|(index, input)| {
            inputs[..index]
                .iter()
                .any(|prior| prior.source.path() == input.source.path())
        })
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
    if !path.is_absolute() || path.as_os_str().is_empty() {
        return false;
    }
    #[cfg(unix)]
    {
        let bytes = path.as_os_str().as_encoded_bytes();
        bytes.first() == Some(&b'/')
            && (bytes.len() == 1 || bytes.last() != Some(&b'/'))
            && bytes
                .split(|byte| *byte == b'/')
                .enumerate()
                .all(|(index, component)| {
                    (index == 0 && component.is_empty())
                        || (!component.is_empty() && component != b"." && component != b"..")
                })
    }
    #[cfg(not(unix))]
    {
        !path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    }
}

#[derive(Debug)]
pub enum ExecuteError {
    InvalidSpecification(&'static str),
    Verification {
        path: PathBuf,
        reason: &'static str,
    },
    Stage {
        path: PathBuf,
        error: std::io::Error,
    },
    Cleanup {
        path: PathBuf,
        error: std::io::Error,
    },
    Spawn(std::io::Error),
    Wait(std::io::Error),
    Scenario(String),
    Cancelled,
    OutputLimit {
        stream: &'static str,
        limit: u64,
    },
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
    ResourceExhausted(&'static str),
    OutputLimitExceeded(String),
    EventLimitExceeded(String),
    Execute(ExecuteError),
    GuestProtocol(TestModelError),
    Protocol(String),
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
            Self::ResourceExhausted(resource) => {
                write!(formatter, "cannot allocate bounded test-runner {resource}")
            }
            Self::OutputLimitExceeded(group) => {
                write!(formatter, "image group {group:?} exceeded its output limit")
            }
            Self::EventLimitExceeded(group) => {
                write!(formatter, "image group {group:?} exceeded its event limit")
            }
            Self::Execute(error) => write!(formatter, "emulator execution failed: {error:?}"),
            Self::GuestProtocol(error) => error.fmt(formatter),
            Self::Protocol(message) => write!(formatter, "invalid guest test protocol: {message}"),
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
        ImageArtifact, MAX_QMP_UNIX_PATH_BYTES, ProcessInput, VerifiedProcessFile,
        protocol_execution_policy, safe_working_directory, seal_report, valid_exact_process_inputs,
        valid_preexecution_result, valid_qmp_unix_path, validate_decoded_group_prefix,
    };
    use wrela_build_model::{BuildIdentity, LanguageRevision, Sha256Digest, TargetIdentity};
    use wrela_test_model::{
        FailurePhase, FullImageTestGroup, FunctionKey, ImageExecutionEvidence, ImageGroupId,
        ImageGroupResult, ImageRoot, ImageTest, ImageTestInvocation, TEST_PLAN_SCHEMA,
        TEST_PROTOCOL_VERSION, TEST_REPORT_SCHEMA, TestDescriptor, TestEvent, TestEventKind,
        TestId, TestKind, TestOutcome, TestPlan, TestPlanLimits, TestReport,
    };

    fn build_identity(digest: Sha256Digest) -> BuildIdentity {
        BuildIdentity {
            compiler: digest,
            language: LanguageRevision::Design0_1,
            target: TargetIdentity::aarch64_qemu_virt_uefi(),
            target_package: digest,
            standard_library: digest,
            source_graph: digest,
            request: digest,
            profile: digest,
        }
    }

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
        assert!(!safe_working_directory(
            Path::new("/private//wrela/tests"),
            Path::new("/private/wrela/tests/group")
        ));
        assert!(!safe_working_directory(
            Path::new("/private/wrela/tests/"),
            Path::new("/private/wrela/tests/group")
        ));
    }

    #[test]
    fn qmp_unix_path_contract_accepts_103_and_rejects_104_bytes() {
        let exact = PathBuf::from(format!(
            "/{}/qmp.sock",
            "a".repeat(MAX_QMP_UNIX_PATH_BYTES - 10)
        ));
        let over = PathBuf::from(format!(
            "/{}/qmp.sock",
            "a".repeat(MAX_QMP_UNIX_PATH_BYTES - 9)
        ));
        assert_eq!(exact.as_os_str().as_encoded_bytes().len(), 103);
        assert_eq!(over.as_os_str().as_encoded_bytes().len(), 104);
        assert!(valid_qmp_unix_path(&exact));
        assert!(!valid_qmp_unix_path(&over));
        assert!(!valid_qmp_unix_path(Path::new("/private/qmp\0.sock")));
        assert!(!valid_qmp_unix_path(Path::new("relative/qmp.sock")));
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
            build: build_identity(digest),
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

    #[test]
    fn preexecution_results_are_limited_to_unrun_compile_and_link_failures() {
        let digest = Sha256Digest::from_bytes([9; 32]);
        let group = FullImageTestGroup {
            id: ImageGroupId(0),
            name: "integration".to_owned(),
            root: ImageRoot::GeneratedHarness {
                harness_name: "generated".to_owned(),
            },
            tests: Vec::new(),
            deterministic_seed: None,
            boot_timeout_ns: 1,
            shutdown_timeout_ns: 1,
            maximum_events: 1,
            maximum_output_bytes: 16,
        };
        let plan = TestPlan {
            schema: TEST_PLAN_SCHEMA,
            build: build_identity(digest),
            target: TargetIdentity::aarch64_qemu_virt_uefi(),
            scenarios: Vec::new(),
            unit_tests: Vec::new(),
            image_groups: vec![group.clone()],
        };
        let mut result = ImageGroupResult {
            group: group.id,
            cases: Vec::new(),
            events: Vec::new(),
            evidence: ImageExecutionEvidence {
                image_digest: None,
                target_digest: digest,
                emulator_digest: None,
                scenario_digest: None,
                command_digest: None,
                event_stream_digest: None,
                exit_code: None,
                stderr: Vec::new(),
            },
            infrastructure_failure: Some(TestOutcome::Failed {
                phase: FailurePhase::Compile,
                message: "compile failed".to_owned(),
            }),
        };
        assert!(valid_preexecution_result(&result, &group, &plan));
        result.infrastructure_failure = Some(TestOutcome::Failed {
            phase: FailurePhase::Runtime,
            message: "runtime failed".to_owned(),
        });
        assert!(!valid_preexecution_result(&result, &group, &plan));
        result.infrastructure_failure = Some(TestOutcome::Failed {
            phase: FailurePhase::Link,
            message: "link failed".to_owned(),
        });
        result.evidence.image_digest = Some(digest);
        assert!(!valid_preexecution_result(&result, &group, &plan));
    }

    #[test]
    fn report_sealing_preserves_plan_policy_and_cancellation() {
        let digest = Sha256Digest::from_bytes([0x41; 32]);
        let mut plan_limits = TestPlanLimits::standard();
        plan_limits.report_bytes = 1;
        let plan = TestPlan {
            schema: TEST_PLAN_SCHEMA,
            build: build_identity(digest),
            target: TargetIdentity::aarch64_qemu_virt_uefi(),
            scenarios: Vec::new(),
            unit_tests: Vec::new(),
            image_groups: Vec::new(),
        }
        .seal_with_limits(plan_limits)
        .expect("empty plan seals under an explicit retained policy");
        assert_eq!(plan.limits(), plan_limits);
        let report = TestReport {
            schema: TEST_REPORT_SCHEMA,
            build: plan.as_plan().build.clone(),
            started_unix_ns: None,
            duration_ns: None,
            unit: Vec::new(),
            images: Vec::new(),
        };
        assert!(matches!(
            seal_report(report, &plan, &|| true),
            Err(super::RunError::InvalidReport(
                wrela_test_model::TestModelError::Cancelled
            ))
        ));
    }

    #[test]
    fn decoded_lifecycle_is_bound_to_the_selected_compiled_group() {
        let digest = Sha256Digest::from_bytes([0x51; 32]);
        let group = FullImageTestGroup {
            id: ImageGroupId(0),
            name: "selected".to_owned(),
            root: ImageRoot::GeneratedHarness {
                harness_name: "generated".to_owned(),
            },
            tests: vec![ImageTest {
                descriptor: TestDescriptor {
                    id: TestId(7),
                    name: "selected test".to_owned(),
                    kind: TestKind::IntegrationImage,
                    source: None,
                    timeout_ns: 1,
                },
                invocation: ImageTestInvocation::GeneratedFunction {
                    function_key: FunctionKey(digest),
                },
                assertions: Vec::new(),
            }],
            deterministic_seed: None,
            boot_timeout_ns: 1,
            shutdown_timeout_ns: 1,
            maximum_events: 4,
            maximum_output_bytes: 1024,
        };
        let stale_count = [TestEvent {
            protocol: TEST_PROTOCOL_VERSION,
            sequence: 0,
            kind: TestEventKind::RunStarted { test_count: 2 },
        }];
        assert!(matches!(
            validate_decoded_group_prefix(&group, &stale_count, &|| false),
            Err(super::RunError::UnexpectedTestEvent(_))
        ));

        let foreign_test = [
            TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 0,
                kind: TestEventKind::RunStarted { test_count: 1 },
            },
            TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 1,
                kind: TestEventKind::TestStarted { test: TestId(8) },
            },
        ];
        assert!(matches!(
            validate_decoded_group_prefix(&group, &foreign_test, &|| false),
            Err(super::RunError::UnexpectedTestEvent(_))
        ));
        assert!(matches!(
            validate_decoded_group_prefix(&group, &[], &|| true),
            Err(super::RunError::Cancelled)
        ));

        let mut protocol_capped = group;
        protocol_capped.maximum_events = 1;
        protocol_capped.maximum_output_bytes = u64::MAX;
        let policy = protocol_execution_policy(&protocol_capped).expect("bounded protocol policy");
        assert_eq!(
            policy.maximum_output_bytes,
            policy
                .limits
                .maximum_stream_bytes()
                .expect("maximum protocol stream")
        );
    }
}
