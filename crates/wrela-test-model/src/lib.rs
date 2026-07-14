//! Shared contracts for compiler-evaluated unit tests and AArch64 full-image
//! integration/image tests.

#![forbid(unsafe_code)]

use std::fmt;

use wrela_build_model::{BuildIdentity, Sha256Digest, TargetIdentity};
use wrela_source::Span;

pub const TEST_PROTOCOL_VERSION: u32 = 2;
pub const TEST_PLAN_SCHEMA: u32 = 1;
pub const TEST_REPORT_SCHEMA: u32 = 1;
pub const IMAGE_SCENARIO_SCHEMA: u32 = 1;
pub const MAX_TEST_EVENT_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TestPlanLimits {
    pub tests: u32,
    pub groups: u32,
    pub scenarios: u32,
    pub scenario_steps: u32,
    pub payload_bytes: u64,
    pub report_bytes: u64,
    pub events_per_group: u32,
    pub output_bytes_per_group: u64,
    pub execution_timeout_ns_per_group: u64,
}

impl TestPlanLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            tests: 1_000_000,
            groups: 100_000,
            scenarios: 100_000,
            scenario_steps: 1_000_000,
            payload_bytes: 64 * 1024 * 1024,
            report_bytes: 1024 * 1024 * 1024,
            events_per_group: 10_000_000,
            output_bytes_per_group: 1024 * 1024 * 1024,
            execution_timeout_ns_per_group: 24 * 60 * 60 * 1_000_000_000,
        }
    }

    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.tests > 0
            && self.groups > 0
            && self.scenarios > 0
            && self.scenario_steps > 0
            && self.payload_bytes > 0
            && self.report_bytes > 0
            && self.events_per_group > 0
            && self.output_bytes_per_group > 0
            && self.execution_timeout_ns_per_group > 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TestId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ScenarioId(pub u32);

/// Dense identity of one independently compiled full-image test group in a
/// sealed [`TestPlan`]. The ID is stable only within the plan's build identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ImageGroupId(pub u32);

/// Content-addressed identity of one concrete monomorphized function. Keeping
/// this fixed-width prevents test plans from smuggling unbounded compiler keys
/// or relying on process-local arena IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FunctionKey(pub Sha256Digest);

impl FunctionKey {
    #[must_use]
    pub fn is_valid(self) -> bool {
        self.0.as_bytes().iter().any(|byte| *byte != 0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpectedScenarioEvent {
    RunStarted,
    TestStarted,
    Log,
    AssertionFailed,
    TestFinished,
    Heartbeat,
    RunFinished,
}

/// Bounded host actions supported by revision 0.1 image scenarios. Serial
/// bytes use the target's framed PL011 channel; waits consume host deadlines
/// and never alter guest language time semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageScenarioStep {
    SendSerial {
        bytes: Vec<u8>,
    },
    ExpectSerial {
        bytes: Vec<u8>,
        timeout_ns: u64,
    },
    ExpectTestEvent {
        kind: ExpectedScenarioEvent,
        test: Option<TestId>,
        message_contains: Option<String>,
        timeout_ns: u64,
    },
    ExpectExit {
        code: Option<i32>,
        timeout_ns: u64,
    },
    RequestShutdown {
        timeout_ns: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageScenario {
    pub id: ScenarioId,
    pub schema: u32,
    pub name: String,
    pub source_path: String,
    pub digest: Sha256Digest,
    pub steps: Vec<ImageScenarioStep>,
}

impl ImageScenario {
    /// Sum of all sequential host waits. `None` means the declared nanosecond
    /// budget overflows and the scenario cannot be executed safely.
    #[must_use]
    pub fn wait_budget_ns(&self) -> Option<u64> {
        self.steps.iter().try_fold(0_u64, |total, step| {
            total.checked_add(match step {
                ImageScenarioStep::SendSerial { .. } => 0,
                ImageScenarioStep::ExpectSerial { timeout_ns, .. }
                | ImageScenarioStep::ExpectTestEvent { timeout_ns, .. }
                | ImageScenarioStep::ExpectExit { timeout_ns, .. }
                | ImageScenarioStep::RequestShutdown { timeout_ns } => *timeout_ns,
            })
        })
    }

    pub fn validate_shape(&self) -> Result<(), TestModelError> {
        if self.schema != IMAGE_SCENARIO_SCHEMA
            || self.name.trim().is_empty()
            || self.source_path.trim().is_empty()
            || self.steps.is_empty()
            || self.steps.iter().any(invalid_scenario_step)
            || !valid_scenario_sequence(self)
            || self.wait_budget_ns().is_none()
        {
            Err(TestModelError::InvalidScenario(self.id))
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
pub struct ScenarioDecodeRequest<'a> {
    pub id: ScenarioId,
    pub name: &'a str,
    pub source_path: &'a str,
    pub bytes: &'a [u8],
    pub verified_digest: Sha256Digest,
    pub maximum_bytes: u64,
    pub maximum_steps: u32,
    pub maximum_step_bytes: u64,
}

pub trait ImageScenarioCodec {
    fn decode(
        &self,
        request: ScenarioDecodeRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ImageScenario, TestModelError>;

    fn encode_canonical(
        &self,
        scenario: &ImageScenario,
        maximum_bytes: u64,
        maximum_steps: u32,
        maximum_step_bytes: u64,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, TestModelError>;
}

pub fn decode_and_verify_image_scenario(
    codec: &dyn ImageScenarioCodec,
    request: ScenarioDecodeRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ImageScenario, TestModelError> {
    if is_cancelled() {
        return Err(TestModelError::Cancelled);
    }
    if request.maximum_bytes == 0 || request.maximum_steps == 0 || request.maximum_step_bytes == 0 {
        return Err(TestModelError::InvalidLimits);
    }
    let bytes = u64::try_from(request.bytes.len()).map_err(|_| TestModelError::ResourceLimit {
        resource: "image scenario bytes",
        limit: request.maximum_bytes,
    })?;
    if bytes > request.maximum_bytes {
        return Err(TestModelError::ResourceLimit {
            resource: "image scenario bytes",
            limit: request.maximum_bytes,
        });
    }
    let input = request.bytes;
    let id = request.id;
    let name = request.name.to_owned();
    let source_path = request.source_path.to_owned();
    let digest = request.verified_digest;
    let maximum_bytes = request.maximum_bytes;
    let maximum_steps = request.maximum_steps;
    let maximum_step_bytes = request.maximum_step_bytes;
    let scenario = codec.decode(request, is_cancelled)?;
    if scenario.id != id
        || scenario.name != name
        || scenario.source_path != source_path
        || scenario.digest != digest
        || scenario.steps.len() > maximum_steps as usize
        || scenario.steps.iter().any(|step| {
            scenario_step_payload_bytes(step).is_none_or(|bytes| bytes > maximum_step_bytes)
        })
    {
        return Err(TestModelError::ScenarioIdentityMismatch(id));
    }
    scenario.validate_shape()?;
    if codec.encode_canonical(
        &scenario,
        maximum_bytes,
        maximum_steps,
        maximum_step_bytes,
        is_cancelled,
    )? != input
    {
        return Err(TestModelError::NonCanonicalScenario(id));
    }
    Ok(scenario)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestKind {
    /// Pure `comptime` function evaluated by the compiler.
    ComptimeUnit,
    /// Runtime function linked into a generated bootable test image.
    IntegrationImage,
    /// Manifest scenario run against a declared bootable image root.
    DeclaredImage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestDescriptor {
    pub id: TestId,
    pub name: String,
    pub kind: TestKind,
    pub source: Option<Span>,
    pub timeout_ns: u64,
}

/// Unit test selected for the compiler evaluator. `function_key` is the
/// stable monomorphized semantic identity, never a host function pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComptimeTest {
    pub descriptor: TestDescriptor,
    pub function_key: FunctionKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageRoot {
    /// Compiler-generated image containing selected integration functions.
    GeneratedHarness { harness_name: String },
    /// User-declared `@image` root and manifest scenario.
    Declared {
        image_name: String,
        scenario: ScenarioId,
    },
}

/// Manifest-declared test input supplied to semantic test discovery. Test IDs
/// are assigned only when the complete plan is assembled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredImageTest {
    pub name: String,
    pub image_name: String,
    pub scenario: ImageScenario,
    pub boot_timeout_ns: u64,
    pub shutdown_timeout_ns: u64,
    pub maximum_events: u32,
    pub maximum_output_bytes: u64,
    pub deterministic_seed: Option<u64>,
}

/// Exact invocation selected by the compiler for one test in an image group.
/// Function keys are stable monomorphized semantic identities, not host or
/// target addresses. Declared scenarios execute the image root itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageTestInvocation {
    GeneratedFunction { function_key: FunctionKey },
    DeclaredScenario,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageTest {
    pub descriptor: TestDescriptor,
    pub invocation: ImageTestInvocation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullImageTestGroup {
    pub id: ImageGroupId,
    pub name: String,
    pub root: ImageRoot,
    pub tests: Vec<ImageTest>,
    pub deterministic_seed: Option<u64>,
    pub boot_timeout_ns: u64,
    pub shutdown_timeout_ns: u64,
    pub maximum_events: u32,
    pub maximum_output_bytes: u64,
}

impl FullImageTestGroup {
    /// Hard wall-clock budget passed to the process executor. Boot and
    /// shutdown are always included. Generated harnesses then receive the sum
    /// of per-test budgets; declared images receive the sum of scenario waits.
    #[must_use]
    pub fn execution_timeout_ns(&self, scenario: Option<&ImageScenario>) -> Option<u64> {
        let base = self.boot_timeout_ns.checked_add(self.shutdown_timeout_ns)?;
        let body = match (&self.root, scenario) {
            (ImageRoot::GeneratedHarness { .. }, None) => {
                self.tests.iter().try_fold(0_u64, |total, test| {
                    total.checked_add(test.descriptor.timeout_ns)
                })?
            }
            (ImageRoot::Declared { .. }, Some(scenario)) => scenario.wait_budget_ns()?,
            _ => return None,
        };
        base.checked_add(body)
    }
}

/// Complete discovery output. Test builds use the same target and build
/// semantics as production images; only the generated root/harness differs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestPlan {
    pub schema: u32,
    pub build: BuildIdentity,
    pub target: TargetIdentity,
    pub scenarios: Vec<ImageScenario>,
    pub unit_tests: Vec<ComptimeTest>,
    pub image_groups: Vec<FullImageTestGroup>,
}

impl TestPlan {
    /// Validate and seal a discovery result before it is used as a compilation
    /// or runner input.
    pub fn seal(self) -> Result<ValidatedTestPlan, TestModelError> {
        self.seal_with_limits(TestPlanLimits::standard())
    }

    pub fn seal_with_limits(
        self,
        limits: TestPlanLimits,
    ) -> Result<ValidatedTestPlan, TestModelError> {
        self.validate_with_limits(limits)?;
        Ok(ValidatedTestPlan { plan: self, limits })
    }

    pub fn validate(&self) -> Result<(), TestModelError> {
        self.validate_with_limits(TestPlanLimits::standard())
    }

    pub fn validate_with_limits(&self, limits: TestPlanLimits) -> Result<(), TestModelError> {
        if !limits.is_valid() {
            return Err(TestModelError::InvalidLimits);
        }
        if self.schema != TEST_PLAN_SCHEMA {
            return Err(TestModelError::UnsupportedPlanSchema(self.schema));
        }
        if self.target != self.build.target {
            return Err(TestModelError::TargetMismatch);
        }
        if !self
            .scenarios
            .windows(2)
            .all(|pair| pair[0].name < pair[1].name)
        {
            return Err(TestModelError::NonCanonicalScenarios);
        }
        if !self
            .image_groups
            .windows(2)
            .all(|pair| pair[0].name < pair[1].name)
        {
            return Err(TestModelError::NonCanonicalImageGroups);
        }
        let total_tests = self.unit_tests.len()
            + self
                .image_groups
                .iter()
                .map(|group| group.tests.len())
                .sum::<usize>();
        let scenario_steps = self.scenarios.iter().try_fold(0usize, |total, scenario| {
            total.checked_add(scenario.steps.len())
        });
        let payload_bytes = test_plan_payload_bytes(self);
        if total_tests > limits.tests as usize
            || self.image_groups.len() > limits.groups as usize
            || self.scenarios.len() > limits.scenarios as usize
            || scenario_steps.is_none_or(|count| count > limits.scenario_steps as usize)
            || payload_bytes.is_none_or(|bytes| bytes > limits.payload_bytes)
        {
            return Err(TestModelError::ResourceLimit {
                resource: "test plan",
                limit: limits.payload_bytes,
            });
        }
        if total_tests > u32::MAX as usize {
            return Err(TestModelError::TooManyTests(total_tests));
        }
        for (expected, scenario) in self.scenarios.iter().enumerate() {
            if scenario.id.0 as usize != expected
                || scenario.validate_shape().is_err()
                || scenario.steps.iter().any(|step| {
                    matches!(
                        step,
                        ImageScenarioStep::ExpectTestEvent {
                            test: Some(test),
                            ..
                        } if test.0 as usize >= total_tests
                    )
                })
            {
                return Err(TestModelError::InvalidScenario(scenario.id));
            }
        }
        let descriptors = self.unit_tests.iter().map(|test| &test.descriptor).chain(
            self.image_groups
                .iter()
                .flat_map(|group| group.tests.iter().map(|test| &test.descriptor)),
        );
        for (expected, descriptor) in descriptors.enumerate() {
            if descriptor.id.0 as usize != expected {
                return Err(TestModelError::NonDenseTestId {
                    expected,
                    actual: descriptor.id,
                });
            }
            if descriptor.name.trim().is_empty() || descriptor.timeout_ns == 0 {
                return Err(TestModelError::InvalidDescriptor(descriptor.id));
            }
        }
        let mut group_names = std::collections::BTreeSet::new();
        let mut function_keys = std::collections::BTreeSet::new();
        for test in &self.unit_tests {
            if test.descriptor.kind != TestKind::ComptimeUnit
                || !test.function_key.is_valid()
                || !function_keys.insert(test.function_key)
            {
                return Err(TestModelError::InvalidDescriptor(test.descriptor.id));
            }
        }
        for (expected, group) in self.image_groups.iter().enumerate() {
            let group_test_ids: std::collections::BTreeSet<_> =
                group.tests.iter().map(|test| test.descriptor.id).collect();
            if group.id.0 as usize != expected
                || group.name.trim().is_empty()
                || !group_names.insert(group.name.as_str())
                || group.tests.is_empty()
                || group.boot_timeout_ns == 0
                || group.shutdown_timeout_ns == 0
                || group.maximum_events == 0
                || group.maximum_output_bytes == 0
                || group.maximum_events > limits.events_per_group
                || group.maximum_output_bytes > limits.output_bytes_per_group
            {
                return Err(TestModelError::InvalidImageGroup(group.name.clone()));
            }
            let root_valid = match &group.root {
                ImageRoot::GeneratedHarness { harness_name } => !harness_name.trim().is_empty(),
                ImageRoot::Declared {
                    image_name,
                    scenario,
                } => {
                    !image_name.trim().is_empty()
                        && group.tests.len() == 1
                        && (scenario.0 as usize) < self.scenarios.len()
                        && self.scenarios[scenario.0 as usize]
                            .steps
                            .iter()
                            .all(|step| {
                                !matches!(
                                    step,
                                    ImageScenarioStep::ExpectTestEvent {
                                        test: Some(id),
                                        ..
                                    } if !group_test_ids.contains(id)
                                )
                            })
                }
            };
            let scenario = match &group.root {
                ImageRoot::GeneratedHarness { .. } => None,
                ImageRoot::Declared { scenario, .. } => self.scenarios.get(scenario.0 as usize),
            };
            if !root_valid
                || group
                    .execution_timeout_ns(scenario)
                    .is_none_or(|timeout| timeout > limits.execution_timeout_ns_per_group)
            {
                return Err(TestModelError::InvalidImageGroup(group.name.clone()));
            }
            for test in &group.tests {
                let valid = match (&group.root, &test.invocation, test.descriptor.kind) {
                    (
                        ImageRoot::GeneratedHarness { .. },
                        ImageTestInvocation::GeneratedFunction { function_key },
                        TestKind::IntegrationImage,
                    ) => function_key.is_valid() && function_keys.insert(*function_key),
                    (
                        ImageRoot::Declared { .. },
                        ImageTestInvocation::DeclaredScenario,
                        TestKind::DeclaredImage,
                    ) => true,
                    _ => false,
                };
                if !valid {
                    return Err(TestModelError::WrongGroup(test.descriptor.id));
                }
            }
        }
        Ok(())
    }
}

fn test_plan_payload_bytes(plan: &TestPlan) -> Option<u64> {
    let mut bytes = 0u64;
    let mut add = |length: usize| -> Option<()> {
        bytes = bytes.checked_add(u64::try_from(length).ok()?)?;
        Some(())
    };
    for scenario in &plan.scenarios {
        add(scenario.name.len())?;
        add(scenario.source_path.len())?;
        for step in &scenario.steps {
            match step {
                ImageScenarioStep::SendSerial { bytes: value }
                | ImageScenarioStep::ExpectSerial { bytes: value, .. } => add(value.len())?,
                ImageScenarioStep::ExpectTestEvent {
                    message_contains, ..
                } => add(message_contains.as_ref().map_or(0, String::len))?,
                ImageScenarioStep::ExpectExit { .. }
                | ImageScenarioStep::RequestShutdown { .. } => {}
            }
        }
    }
    for test in &plan.unit_tests {
        add(test.descriptor.name.len())?;
    }
    for group in &plan.image_groups {
        add(group.name.len())?;
        match &group.root {
            ImageRoot::GeneratedHarness { harness_name } => add(harness_name.len())?,
            ImageRoot::Declared { image_name, .. } => add(image_name.len())?,
        }
        for test in &group.tests {
            add(test.descriptor.name.len())?;
        }
    }
    Some(bytes)
}

/// Structurally valid, identity-bound test discovery output. Consumers borrow
/// groups from this wrapper so a group cannot be compiled independently of the
/// plan and build identity that assigned its test/function IDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedTestPlan {
    plan: TestPlan,
    limits: TestPlanLimits,
}

impl ValidatedTestPlan {
    #[must_use]
    pub fn as_plan(&self) -> &TestPlan {
        &self.plan
    }

    #[must_use]
    pub fn into_plan(self) -> TestPlan {
        self.plan
    }

    #[must_use]
    pub const fn limits(&self) -> TestPlanLimits {
        self.limits
    }

    #[must_use]
    pub fn group(&self, id: ImageGroupId) -> Option<&FullImageTestGroup> {
        self.plan
            .image_groups
            .get(id.0 as usize)
            .filter(|group| group.id == id)
    }

    #[must_use]
    pub fn build(&self) -> &BuildIdentity {
        &self.plan.build
    }

    #[must_use]
    pub fn target(&self) -> &TargetIdentity {
        &self.plan.target
    }

    #[must_use]
    pub fn scenarios(&self) -> &[ImageScenario] {
        &self.plan.scenarios
    }

    #[must_use]
    pub fn unit_tests(&self) -> &[ComptimeTest] {
        &self.plan.unit_tests
    }

    #[must_use]
    pub fn image_groups(&self) -> &[FullImageTestGroup] {
        &self.plan.image_groups
    }

    #[must_use]
    pub fn payload_bytes(&self) -> u64 {
        test_plan_payload_bytes(&self.plan)
            .expect("validated test-plan payload size cannot overflow")
    }

    #[must_use]
    pub fn scenario_step_count(&self) -> usize {
        self.plan
            .scenarios
            .iter()
            .map(|scenario| scenario.steps.len())
            .sum()
    }
}

fn invalid_scenario_step(step: &ImageScenarioStep) -> bool {
    match step {
        ImageScenarioStep::SendSerial { bytes } => bytes.is_empty(),
        ImageScenarioStep::ExpectSerial { bytes, timeout_ns } => {
            bytes.is_empty() || *timeout_ns == 0
        }
        ImageScenarioStep::ExpectTestEvent {
            kind,
            test,
            message_contains,
            timeout_ns,
        } => {
            *timeout_ns == 0
                || message_contains
                    .as_ref()
                    .is_some_and(|message| message.is_empty())
                || matches!(
                    kind,
                    ExpectedScenarioEvent::RunStarted
                        | ExpectedScenarioEvent::Heartbeat
                        | ExpectedScenarioEvent::RunFinished
                ) && (test.is_some() || message_contains.is_some())
                || matches!(
                    kind,
                    ExpectedScenarioEvent::TestStarted | ExpectedScenarioEvent::TestFinished
                ) && message_contains.is_some()
        }
        ImageScenarioStep::ExpectExit { timeout_ns, .. }
        | ImageScenarioStep::RequestShutdown { timeout_ns } => *timeout_ns == 0,
    }
}

fn scenario_step_payload_bytes(step: &ImageScenarioStep) -> Option<u64> {
    let bytes = match step {
        ImageScenarioStep::SendSerial { bytes } | ImageScenarioStep::ExpectSerial { bytes, .. } => {
            bytes.len()
        }
        ImageScenarioStep::ExpectTestEvent {
            message_contains, ..
        } => message_contains.as_ref().map_or(0, String::len),
        ImageScenarioStep::ExpectExit { .. } | ImageScenarioStep::RequestShutdown { .. } => 0,
    };
    u64::try_from(bytes).ok()
}

fn valid_scenario_sequence(scenario: &ImageScenario) -> bool {
    let mut shutdown_requested = false;
    let mut saw_exit = false;
    let mut saw_run_finished = false;
    for (index, step) in scenario.steps.iter().enumerate() {
        match step {
            ImageScenarioStep::RequestShutdown { .. } => {
                if shutdown_requested || saw_exit {
                    return false;
                }
                shutdown_requested = true;
            }
            ImageScenarioStep::ExpectExit { .. } => {
                if saw_exit || index + 1 != scenario.steps.len() {
                    return false;
                }
                saw_exit = true;
            }
            ImageScenarioStep::ExpectTestEvent {
                kind: ExpectedScenarioEvent::RunFinished,
                ..
            } => {
                if saw_run_finished || saw_exit || shutdown_requested {
                    return false;
                }
                saw_run_finished = true;
            }
            _ if saw_exit || shutdown_requested => return false,
            _ => {}
        }
    }
    saw_exit || saw_run_finished
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailurePhase {
    Discovery,
    Comptime,
    Compile,
    Link,
    Boot,
    Runtime,
    Shutdown,
    Protocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warning,
    Error,
}

/// Outcomes a running guest can legitimately emit. Host discovery, compile,
/// link, boot, shutdown, and process-crash failures are report infrastructure
/// outcomes and cannot be forged as guest test-finished events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestTestOutcome {
    Passed,
    Failed { message: String },
    TimedOut { timeout_ns: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssertionFailure {
    pub expression: String,
    pub message: Option<String>,
    pub source: Option<Span>,
    pub expected: Option<String>,
    pub actual: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestEventKind {
    RunStarted {
        test_count: u32,
    },
    TestStarted {
        test: TestId,
    },
    Log {
        test: Option<TestId>,
        level: LogLevel,
        message: String,
    },
    AssertionFailed {
        test: TestId,
        failure: AssertionFailure,
    },
    TestFinished {
        test: TestId,
        outcome: GuestTestOutcome,
    },
    Heartbeat {
        monotonic_ticks: u64,
    },
    RunFinished {
        passed: u32,
        failed: u32,
    },
}

/// Monotonically sequenced guest/compiler event. Image transports encode one
/// event per bounded, checksummed frame and reject gaps or duplicates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestEvent {
    pub protocol: u32,
    pub sequence: u64,
    pub kind: TestEventKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestOutcome {
    Passed,
    Failed {
        phase: FailurePhase,
        message: String,
    },
    TimedOut {
        phase: FailurePhase,
        timeout_ns: u64,
    },
    Crashed {
        code: Option<i32>,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestCaseResult {
    pub descriptor: TestDescriptor,
    pub outcome: TestOutcome,
    pub duration_ns: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageExecutionEvidence {
    /// Absent only when discovery, compilation, or linking failed before a
    /// runnable image existed.
    pub image_digest: Option<Sha256Digest>,
    /// Digest of the complete target package, including firmware, runtime,
    /// target manifest, and boot policy.
    pub target_digest: Sha256Digest,
    /// Absent when no emulator invocation was attempted.
    pub emulator_digest: Option<Sha256Digest>,
    pub scenario_digest: Option<Sha256Digest>,
    pub command_digest: Option<Sha256Digest>,
    pub event_stream_digest: Option<Sha256Digest>,
    pub exit_code: Option<i32>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageGroupResult {
    pub group: ImageGroupId,
    pub cases: Vec<TestCaseResult>,
    /// Exact decoded group stream in sequence order. Per-case views are
    /// derived from this stream rather than storing contradictory copies.
    pub events: Vec<TestEvent>,
    pub evidence: ImageExecutionEvidence,
    pub infrastructure_failure: Option<TestOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestReport {
    pub schema: u32,
    pub build: BuildIdentity,
    pub started_unix_ns: Option<u64>,
    pub duration_ns: Option<u64>,
    pub unit: Vec<TestCaseResult>,
    pub images: Vec<ImageGroupResult>,
}

impl TestReport {
    pub fn seal_against(
        self,
        plan: &ValidatedTestPlan,
    ) -> Result<ValidatedTestReport, TestModelError> {
        self.validate_against(plan)?;
        Ok(ValidatedTestReport(self))
    }

    #[must_use]
    pub fn passed(&self) -> bool {
        self.unit
            .iter()
            .chain(self.images.iter().flat_map(|image| image.cases.iter()))
            .all(|case| matches!(case.outcome, TestOutcome::Passed))
            && self
                .images
                .iter()
                .all(|image| image.infrastructure_failure.is_none())
    }

    /// Verify that a report describes exactly the plan that was executed. A
    /// group with infrastructure failure may contain a completed prefix; an
    /// otherwise successful group must contain every planned case in order.
    pub fn validate_against(&self, validated: &ValidatedTestPlan) -> Result<(), TestModelError> {
        let plan = validated.as_plan();
        let limits = validated.limits();
        plan.validate_with_limits(limits)?;
        if self.schema != TEST_REPORT_SCHEMA {
            return Err(TestModelError::UnsupportedReportSchema(self.schema));
        }
        if self.build != plan.build {
            return Err(TestModelError::BuildMismatch);
        }
        if self.unit.len() != plan.unit_tests.len()
            || !self
                .unit
                .iter()
                .zip(&plan.unit_tests)
                .all(|(result, planned)| result.descriptor == planned.descriptor)
            || self.unit.iter().any(|result| {
                !matches!(
                    &result.outcome,
                    TestOutcome::Passed
                        | TestOutcome::Failed {
                            phase: FailurePhase::Comptime,
                            ..
                        }
                        | TestOutcome::TimedOut {
                            phase: FailurePhase::Comptime,
                            ..
                        }
                ) || invalid_host_outcome(&result.outcome)
            })
        {
            return Err(TestModelError::ResultSetMismatch("comptime".to_owned()));
        }
        if self.images.len() != plan.image_groups.len() {
            return Err(TestModelError::ResultSetMismatch("image groups".to_owned()));
        }
        for (result, group) in self.images.iter().zip(&plan.image_groups) {
            if result.group != group.id || result.cases.len() > group.tests.len() {
                return Err(TestModelError::ResultSetMismatch(group.name.clone()));
            }
            let expected_scenario = match group.root {
                ImageRoot::GeneratedHarness { .. } => None,
                ImageRoot::Declared { scenario, .. } => plan
                    .scenarios
                    .get(scenario.0 as usize)
                    .map(|item| item.digest),
            };
            if result.evidence.target_digest != plan.build.target_package
                || result.evidence.scenario_digest != expected_scenario
            {
                return Err(TestModelError::ResultSetMismatch(group.name.clone()));
            }
            if result.infrastructure_failure.is_none() && result.cases.len() != group.tests.len() {
                return Err(TestModelError::ResultSetMismatch(group.name.clone()));
            }
            if result
                .infrastructure_failure
                .as_ref()
                .is_some_and(|outcome| {
                    matches!(outcome, TestOutcome::Passed) || invalid_host_outcome(outcome)
                })
                || result.events.len() > group.maximum_events as usize
                || result.evidence.stderr.len() as u64 > group.maximum_output_bytes
                || image_transport_payload_bytes(result)
                    .is_none_or(|bytes| bytes > group.maximum_output_bytes)
            {
                return Err(TestModelError::ResultSetMismatch(group.name.clone()));
            }
            validate_evidence_phase(result, group)?;
            if !result
                .cases
                .iter()
                .zip(&group.tests)
                .all(|(case, planned)| case.descriptor == planned.descriptor)
            {
                return Err(TestModelError::ResultSetMismatch(group.name.clone()));
            }
            validate_image_events(result, group)?;
        }
        if test_report_payload_bytes(self).is_none_or(|bytes| bytes > limits.report_bytes) {
            return Err(TestModelError::ResourceLimit {
                resource: "test report payload",
                limit: limits.report_bytes,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedTestReport(TestReport);

impl ValidatedTestReport {
    #[must_use]
    pub fn as_report(&self) -> &TestReport {
        &self.0
    }

    #[must_use]
    pub fn into_report(self) -> TestReport {
        self.0
    }

    #[must_use]
    pub fn passed(&self) -> bool {
        self.0.passed()
    }
}

/// Canonical external representation for a test report. Implementations must
/// consume the complete input, reject duplicate/noncanonical fields, and apply
/// `maximum_bytes` before allocating attacker-controlled lengths.
pub trait TestReportCodec {
    fn encode(
        &self,
        report: &TestReport,
        maximum_bytes: u64,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, TestReportCodecError>;

    fn decode(
        &self,
        bytes: &[u8],
        maximum_bytes: u64,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<TestReport, TestReportCodecError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedTestReport {
    report: ValidatedTestReport,
    bytes: Vec<u8>,
}

impl EncodedTestReport {
    #[must_use]
    pub fn report(&self) -> &ValidatedTestReport {
        &self.report
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    #[must_use]
    pub fn into_parts(self) -> (ValidatedTestReport, Vec<u8>) {
        (self.report, self.bytes)
    }
}

/// Encode, decode, compare, and re-encode before bytes can be published as a
/// canonical report. This catches schema loss, trailing-input acceptance, and
/// nondeterministic encoders at the producer/consumer boundary.
pub fn seal_test_report_encoding(
    codec: &dyn TestReportCodec,
    report: ValidatedTestReport,
    maximum_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<EncodedTestReport, TestReportCodecError> {
    if is_cancelled() {
        return Err(TestReportCodecError::Cancelled);
    }
    if maximum_bytes == 0 {
        return Err(TestReportCodecError::InvalidLimit);
    }
    let bytes = codec.encode(report.as_report(), maximum_bytes, is_cancelled)?;
    let length = u64::try_from(bytes.len()).map_err(|_| TestReportCodecError::OutputTooLarge {
        limit: maximum_bytes,
    })?;
    if length > maximum_bytes {
        return Err(TestReportCodecError::OutputTooLarge {
            limit: maximum_bytes,
        });
    }
    let decoded = codec.decode(&bytes, maximum_bytes, is_cancelled)?;
    if decoded != *report.as_report()
        || codec.encode(&decoded, maximum_bytes, is_cancelled)? != bytes
    {
        return Err(TestReportCodecError::NonCanonical);
    }
    Ok(EncodedTestReport { report, bytes })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestReportCodecError {
    Cancelled,
    InvalidLimit,
    OutputTooLarge { limit: u64 },
    Encode(String),
    Decode(String),
    NonCanonical,
}

impl fmt::Display for TestReportCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("test report codec operation was cancelled"),
            Self::InvalidLimit => formatter.write_str("test report codec limit must be nonzero"),
            Self::OutputTooLarge { limit } => {
                write!(formatter, "encoded test report exceeds {limit} bytes")
            }
            Self::Encode(message) => write!(formatter, "cannot encode test report: {message}"),
            Self::Decode(message) => write!(formatter, "cannot decode test report: {message}"),
            Self::NonCanonical => formatter.write_str("test report codec is lossy or noncanonical"),
        }
    }
}

impl std::error::Error for TestReportCodecError {}

fn validate_evidence_phase(
    result: &ImageGroupResult,
    group: &FullImageTestGroup,
) -> Result<(), TestModelError> {
    let present = |value: &Option<Sha256Digest>| value.is_some();
    let valid = match &result.infrastructure_failure {
        None => {
            present(&result.evidence.image_digest)
                && present(&result.evidence.emulator_digest)
                && present(&result.evidence.command_digest)
                && present(&result.evidence.event_stream_digest)
        }
        Some(TestOutcome::Failed { phase, .. }) | Some(TestOutcome::TimedOut { phase, .. }) => {
            match phase {
                FailurePhase::Discovery | FailurePhase::Compile | FailurePhase::Link => {
                    result.evidence.image_digest.is_none()
                        && result.evidence.emulator_digest.is_none()
                        && result.evidence.command_digest.is_none()
                        && result.evidence.event_stream_digest.is_none()
                        && result.evidence.exit_code.is_none()
                        && result.events.is_empty()
                        && result.cases.is_empty()
                }
                FailurePhase::Boot
                | FailurePhase::Runtime
                | FailurePhase::Shutdown
                | FailurePhase::Protocol => {
                    present(&result.evidence.image_digest)
                        && present(&result.evidence.emulator_digest)
                        && present(&result.evidence.command_digest)
                        && present(&result.evidence.event_stream_digest)
                }
                FailurePhase::Comptime => false,
            }
        }
        Some(TestOutcome::Crashed { .. }) => {
            present(&result.evidence.image_digest)
                && present(&result.evidence.emulator_digest)
                && present(&result.evidence.command_digest)
                && present(&result.evidence.event_stream_digest)
        }
        Some(TestOutcome::Passed) => false,
    };
    if valid {
        Ok(())
    } else {
        Err(TestModelError::InvalidEvidence(group.name.clone()))
    }
}

fn validate_image_events(
    result: &ImageGroupResult,
    group: &FullImageTestGroup,
) -> Result<(), TestModelError> {
    if result.events.is_empty() {
        return if result.infrastructure_failure.is_some() && result.cases.is_empty() {
            Ok(())
        } else {
            Err(TestModelError::InvalidEventStream(group.name.clone()))
        };
    }
    let planned: std::collections::BTreeSet<_> =
        group.tests.iter().map(|test| test.descriptor.id).collect();
    let mut active = std::collections::BTreeSet::new();
    let mut finished = std::collections::BTreeMap::new();
    let mut terminal = None;
    let mut last_heartbeat = None;
    for (index, event) in result.events.iter().enumerate() {
        if event.protocol != TEST_PROTOCOL_VERSION
            || event.sequence != index as u64
            || event_payload_bytes(event).is_none_or(|bytes| bytes > MAX_TEST_EVENT_BYTES as u64)
        {
            return Err(TestModelError::InvalidEventStream(group.name.clone()));
        }
        match &event.kind {
            TestEventKind::RunStarted { test_count } => {
                if index != 0 || *test_count as usize != group.tests.len() {
                    return Err(TestModelError::InvalidEventStream(group.name.clone()));
                }
            }
            TestEventKind::TestStarted { test } => {
                if index == 0
                    || terminal.is_some()
                    || !planned.contains(test)
                    || finished.contains_key(test)
                    || !active.insert(*test)
                {
                    return Err(TestModelError::InvalidEventStream(group.name.clone()));
                }
            }
            TestEventKind::Log {
                test: Some(test),
                message,
                ..
            } => {
                if terminal.is_some() || !active.contains(test) || message.is_empty() {
                    return Err(TestModelError::InvalidEventStream(group.name.clone()));
                }
            }
            TestEventKind::Log {
                test: None,
                message,
                ..
            } => {
                if index == 0 || terminal.is_some() || message.is_empty() {
                    return Err(TestModelError::InvalidEventStream(group.name.clone()));
                }
            }
            TestEventKind::AssertionFailed { test, failure } => {
                if terminal.is_some()
                    || !active.contains(test)
                    || failure.expression.trim().is_empty()
                {
                    return Err(TestModelError::InvalidEventStream(group.name.clone()));
                }
            }
            TestEventKind::TestFinished { test, outcome } => {
                if terminal.is_some()
                    || !active.remove(test)
                    || invalid_guest_outcome(outcome)
                    || finished.insert(*test, outcome.clone()).is_some()
                {
                    return Err(TestModelError::InvalidEventStream(group.name.clone()));
                }
            }
            TestEventKind::Heartbeat { monotonic_ticks } => {
                if index == 0
                    || terminal.is_some()
                    || last_heartbeat.is_some_and(|previous| previous >= *monotonic_ticks)
                {
                    return Err(TestModelError::InvalidEventStream(group.name.clone()));
                }
                last_heartbeat = Some(*monotonic_ticks);
            }
            TestEventKind::RunFinished { passed, failed } => {
                if terminal.is_some()
                    || index + 1 != result.events.len()
                    || result.infrastructure_failure.is_some()
                    || !active.is_empty()
                {
                    return Err(TestModelError::InvalidEventStream(group.name.clone()));
                }
                terminal = Some((*passed, *failed));
            }
        }
    }
    for case in &result.cases {
        if finished
            .get(&case.descriptor.id)
            .and_then(guest_case_outcome)
            .as_ref()
            != Some(&case.outcome)
        {
            return Err(TestModelError::InvalidEventStream(group.name.clone()));
        }
    }
    if result.infrastructure_failure.is_some() {
        if terminal.is_some() || finished.len() != result.cases.len() {
            return Err(TestModelError::InvalidEventStream(group.name.clone()));
        }
    } else {
        let passed = result
            .cases
            .iter()
            .filter(|case| matches!(case.outcome, TestOutcome::Passed))
            .count() as u32;
        let failed = result.cases.len() as u32 - passed;
        if terminal != Some((passed, failed)) || finished.len() != group.tests.len() {
            return Err(TestModelError::InvalidEventStream(group.name.clone()));
        }
    }
    Ok(())
}

fn test_report_payload_bytes(report: &TestReport) -> Option<u64> {
    let unit = report
        .unit
        .iter()
        .try_fold(0u64, |total, result| result_payload_bytes(result, total))?;
    report.images.iter().try_fold(unit, |total, result| {
        total.checked_add(image_result_payload_bytes(result)?)
    })
}

fn image_result_payload_bytes(result: &ImageGroupResult) -> Option<u64> {
    let mut bytes = u64::try_from(result.evidence.stderr.len()).ok()?;
    for case in &result.cases {
        bytes = result_payload_bytes(case, bytes)?;
    }
    if let Some(outcome) = &result.infrastructure_failure {
        bytes = outcome_payload_bytes(outcome, bytes)?;
    }
    result.events.iter().try_fold(bytes, |total, event| {
        total.checked_add(event_payload_bytes(event)?)
    })
}

fn image_transport_payload_bytes(result: &ImageGroupResult) -> Option<u64> {
    result.events.iter().try_fold(
        u64::try_from(result.evidence.stderr.len()).ok()?,
        |total, event| total.checked_add(event_payload_bytes(event)?),
    )
}

fn result_payload_bytes(result: &TestCaseResult, initial: u64) -> Option<u64> {
    let bytes = initial.checked_add(u64::try_from(result.descriptor.name.len()).ok()?)?;
    outcome_payload_bytes(&result.outcome, bytes)
}

fn outcome_payload_bytes(outcome: &TestOutcome, initial: u64) -> Option<u64> {
    match outcome {
        TestOutcome::Failed { message, .. } | TestOutcome::Crashed { message, .. } => {
            initial.checked_add(u64::try_from(message.len()).ok()?)
        }
        TestOutcome::Passed | TestOutcome::TimedOut { .. } => Some(initial),
    }
}

fn event_payload_bytes(event: &TestEvent) -> Option<u64> {
    let mut bytes = 0u64;
    let mut add = |value: &str| -> Option<()> {
        bytes = bytes.checked_add(u64::try_from(value.len()).ok()?)?;
        Some(())
    };
    match &event.kind {
        TestEventKind::Log { message, .. } => add(message)?,
        TestEventKind::AssertionFailed { failure, .. } => {
            add(&failure.expression)?;
            if let Some(value) = &failure.message {
                add(value)?;
            }
            if let Some(value) = &failure.expected {
                add(value)?;
            }
            if let Some(value) = &failure.actual {
                add(value)?;
            }
        }
        TestEventKind::TestFinished {
            outcome: GuestTestOutcome::Failed { message },
            ..
        } => add(message)?,
        TestEventKind::RunStarted { .. }
        | TestEventKind::TestStarted { .. }
        | TestEventKind::TestFinished { .. }
        | TestEventKind::Heartbeat { .. }
        | TestEventKind::RunFinished { .. } => {}
    }
    Some(bytes)
}

fn invalid_guest_outcome(outcome: &GuestTestOutcome) -> bool {
    match outcome {
        GuestTestOutcome::Passed => false,
        GuestTestOutcome::Failed { message } => message.trim().is_empty(),
        GuestTestOutcome::TimedOut { timeout_ns } => *timeout_ns == 0,
    }
}

fn guest_case_outcome(outcome: &GuestTestOutcome) -> Option<TestOutcome> {
    if invalid_guest_outcome(outcome) {
        return None;
    }
    Some(match outcome {
        GuestTestOutcome::Passed => TestOutcome::Passed,
        GuestTestOutcome::Failed { message } => TestOutcome::Failed {
            phase: FailurePhase::Runtime,
            message: message.clone(),
        },
        GuestTestOutcome::TimedOut { timeout_ns } => TestOutcome::TimedOut {
            phase: FailurePhase::Runtime,
            timeout_ns: *timeout_ns,
        },
    })
}

fn invalid_host_outcome(outcome: &TestOutcome) -> bool {
    match outcome {
        TestOutcome::Passed => false,
        TestOutcome::Failed { message, .. } | TestOutcome::Crashed { message, .. } => {
            message.trim().is_empty()
        }
        TestOutcome::TimedOut { timeout_ns, .. } => *timeout_ns == 0,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestModelError {
    Cancelled,
    InvalidLimits,
    ResourceLimit { resource: &'static str, limit: u64 },
    UnsupportedPlanSchema(u32),
    UnsupportedReportSchema(u32),
    TargetMismatch,
    BuildMismatch,
    TooManyTests(usize),
    NonDenseTestId { expected: usize, actual: TestId },
    InvalidDescriptor(TestId),
    InvalidImageGroup(String),
    WrongGroup(TestId),
    ResultSetMismatch(String),
    InvalidScenario(ScenarioId),
    ScenarioIdentityMismatch(ScenarioId),
    NonCanonicalScenario(ScenarioId),
    NonCanonicalScenarios,
    NonCanonicalImageGroups,
    InvalidEventStream(String),
    InvalidEvidence(String),
    UnsupportedProtocol(u32),
    FrameTooLarge(usize),
    CorruptFrame(String),
}

impl fmt::Display for TestModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("test-model operation was cancelled"),
            Self::InvalidLimits => formatter.write_str("test-model limits must be nonzero"),
            Self::ResourceLimit { resource, limit } => {
                write!(formatter, "{resource} exceeded limit {limit}")
            }
            Self::UnsupportedPlanSchema(schema) => {
                write!(formatter, "unsupported test plan schema {schema}")
            }
            Self::UnsupportedReportSchema(schema) => {
                write!(formatter, "unsupported test report schema {schema}")
            }
            Self::TargetMismatch => formatter.write_str("test plan and build target differ"),
            Self::BuildMismatch => formatter.write_str("test report and plan builds differ"),
            Self::TooManyTests(count) => {
                write!(
                    formatter,
                    "test plan contains {count} tests, exceeding u32 IDs"
                )
            }
            Self::NonDenseTestId { expected, actual } => write!(
                formatter,
                "test IDs must be dense: expected {expected}, got {}",
                actual.0
            ),
            Self::InvalidDescriptor(id) => {
                write!(formatter, "invalid descriptor for test {}", id.0)
            }
            Self::InvalidImageGroup(group) => {
                write!(formatter, "invalid full-image test group {group:?}")
            }
            Self::WrongGroup(id) => write!(
                formatter,
                "test {} is assigned to the wrong execution group",
                id.0
            ),
            Self::ResultSetMismatch(group) => {
                write!(
                    formatter,
                    "test results do not match planned group {group:?}"
                )
            }
            Self::InvalidScenario(id) => {
                write!(formatter, "invalid image scenario {}", id.0)
            }
            Self::ScenarioIdentityMismatch(id) => write!(
                formatter,
                "decoded image scenario {} differs from its request identity or limits",
                id.0
            ),
            Self::NonCanonicalScenario(id) => write!(
                formatter,
                "image scenario {} is not canonically encoded",
                id.0
            ),
            Self::NonCanonicalScenarios => {
                formatter.write_str("image scenarios are not strictly ordered by name")
            }
            Self::NonCanonicalImageGroups => {
                formatter.write_str("image test groups are not strictly ordered by name")
            }
            Self::InvalidEventStream(group) => {
                write!(formatter, "invalid event stream for image group {group:?}")
            }
            Self::InvalidEvidence(group) => {
                write!(
                    formatter,
                    "invalid execution evidence for image group {group:?}"
                )
            }
            Self::UnsupportedProtocol(version) => {
                write!(formatter, "unsupported test protocol {version}")
            }
            Self::FrameTooLarge(bytes) => {
                write!(formatter, "test event frame contains {bytes} bytes")
            }
            Self::CorruptFrame(message) => write!(formatter, "corrupt test event frame: {message}"),
        }
    }
}

impl std::error::Error for TestModelError {}

#[cfg(test)]
mod tests {
    use super::*;
    use wrela_build_model::{LanguageRevision, TargetIdentity};

    fn fixture() -> (TestPlan, Sha256Digest) {
        let digest = Sha256Digest::from_bytes([7; 32]);
        let descriptor = TestDescriptor {
            id: TestId(0),
            name: "boots".to_owned(),
            kind: TestKind::DeclaredImage,
            source: None,
            timeout_ns: 10,
        };
        let plan = TestPlan {
            schema: TEST_PLAN_SCHEMA,
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
            target: TargetIdentity::aarch64_qemu_virt_uefi(),
            scenarios: vec![ImageScenario {
                id: ScenarioId(0),
                schema: IMAGE_SCENARIO_SCHEMA,
                name: "boots".to_owned(),
                source_path: "fixtures/boots.toml".to_owned(),
                digest,
                steps: vec![ImageScenarioStep::ExpectExit {
                    code: Some(0),
                    timeout_ns: 10,
                }],
            }],
            unit_tests: Vec::new(),
            image_groups: vec![FullImageTestGroup {
                id: ImageGroupId(0),
                name: "boots".to_owned(),
                root: ImageRoot::Declared {
                    image_name: "appliance".to_owned(),
                    scenario: ScenarioId(0),
                },
                tests: vec![ImageTest {
                    descriptor,
                    invocation: ImageTestInvocation::DeclaredScenario,
                }],
                deterministic_seed: Some(1),
                boot_timeout_ns: 10,
                shutdown_timeout_ns: 10,
                maximum_events: 16,
                maximum_output_bytes: 1024,
            }],
        };
        (plan, digest)
    }

    fn evidence(digest: Sha256Digest) -> ImageExecutionEvidence {
        ImageExecutionEvidence {
            image_digest: Some(digest),
            target_digest: digest,
            emulator_digest: Some(digest),
            scenario_digest: Some(digest),
            command_digest: Some(digest),
            event_stream_digest: Some(digest),
            exit_code: Some(0),
            stderr: Vec::new(),
        }
    }

    fn sealed_failure_report() -> ValidatedTestReport {
        let (plan, digest) = fixture();
        let validated = plan.clone().seal().expect("valid plan");
        TestReport {
            schema: TEST_REPORT_SCHEMA,
            build: plan.build,
            started_unix_ns: None,
            duration_ns: None,
            unit: Vec::new(),
            images: vec![ImageGroupResult {
                group: ImageGroupId(0),
                cases: Vec::new(),
                events: Vec::new(),
                evidence: ImageExecutionEvidence {
                    image_digest: None,
                    target_digest: digest,
                    emulator_digest: None,
                    scenario_digest: Some(digest),
                    command_digest: None,
                    event_stream_digest: None,
                    exit_code: None,
                    stderr: Vec::new(),
                },
                infrastructure_failure: Some(TestOutcome::Failed {
                    phase: FailurePhase::Compile,
                    message: "compile failed".to_owned(),
                }),
            }],
        }
        .seal_against(&validated)
        .expect("valid failure report")
    }

    struct FixtureReportCodec {
        report: TestReport,
    }

    struct FixtureScenarioCodec {
        scenario: ImageScenario,
    }

    impl ImageScenarioCodec for FixtureScenarioCodec {
        fn decode(
            &self,
            _request: ScenarioDecodeRequest<'_>,
            _is_cancelled: &dyn Fn() -> bool,
        ) -> Result<ImageScenario, TestModelError> {
            Ok(self.scenario.clone())
        }

        fn encode_canonical(
            &self,
            _scenario: &ImageScenario,
            _maximum_bytes: u64,
            _maximum_steps: u32,
            _maximum_step_bytes: u64,
            _is_cancelled: &dyn Fn() -> bool,
        ) -> Result<Vec<u8>, TestModelError> {
            Ok(b"scenario-v1".to_vec())
        }
    }

    impl TestReportCodec for FixtureReportCodec {
        fn encode(
            &self,
            report: &TestReport,
            maximum_bytes: u64,
            _is_cancelled: &dyn Fn() -> bool,
        ) -> Result<Vec<u8>, TestReportCodecError> {
            if report != &self.report {
                return Err(TestReportCodecError::Encode("wrong report".to_owned()));
            }
            let bytes = b"test-report-v1".to_vec();
            if bytes.len() as u64 > maximum_bytes {
                return Err(TestReportCodecError::OutputTooLarge {
                    limit: maximum_bytes,
                });
            }
            Ok(bytes)
        }

        fn decode(
            &self,
            bytes: &[u8],
            maximum_bytes: u64,
            _is_cancelled: &dyn Fn() -> bool,
        ) -> Result<TestReport, TestReportCodecError> {
            if bytes != b"test-report-v1" || bytes.len() as u64 > maximum_bytes {
                return Err(TestReportCodecError::Decode("invalid bytes".to_owned()));
            }
            Ok(self.report.clone())
        }
    }

    #[test]
    fn seals_only_bounded_round_tripped_report_encoding() {
        let report = sealed_failure_report();
        let codec = FixtureReportCodec {
            report: report.as_report().clone(),
        };
        let encoded = seal_test_report_encoding(&codec, report.clone(), 64, &|| false)
            .expect("canonical encoding");
        assert_eq!(encoded.bytes(), b"test-report-v1");
        assert!(matches!(
            seal_test_report_encoding(&codec, report, 1, &|| false),
            Err(TestReportCodecError::OutputTooLarge { limit: 1 })
        ));
    }

    #[test]
    fn report_codec_honors_cancellation_before_encoding() {
        let report = sealed_failure_report();
        let codec = FixtureReportCodec {
            report: report.as_report().clone(),
        };
        assert_eq!(
            seal_test_report_encoding(&codec, report, 64, &|| true),
            Err(TestReportCodecError::Cancelled)
        );
    }

    #[test]
    fn decoded_scenario_is_bound_to_complete_canonical_input() {
        let (plan, digest) = fixture();
        let scenario = plan.scenarios[0].clone();
        let codec = FixtureScenarioCodec {
            scenario: scenario.clone(),
        };
        let request = |bytes| ScenarioDecodeRequest {
            id: scenario.id,
            name: &scenario.name,
            source_path: &scenario.source_path,
            bytes,
            verified_digest: digest,
            maximum_bytes: 1024,
            maximum_steps: 16,
            maximum_step_bytes: 256,
        };
        decode_and_verify_image_scenario(&codec, request(b"scenario-v1"), &|| false)
            .expect("canonical scenario");
        assert_eq!(
            decode_and_verify_image_scenario(&codec, request(b"scenario-v1\nignored"), &|| false,),
            Err(TestModelError::NonCanonicalScenario(scenario.id))
        );
    }

    #[test]
    fn validates_complete_declared_image_lifecycle() {
        let (plan, digest) = fixture();
        let validated = plan.clone().seal().expect("valid plan");
        let descriptor = plan.image_groups[0].tests[0].descriptor.clone();
        let report = TestReport {
            schema: TEST_REPORT_SCHEMA,
            build: plan.build.clone(),
            started_unix_ns: None,
            duration_ns: Some(3),
            unit: Vec::new(),
            images: vec![ImageGroupResult {
                group: ImageGroupId(0),
                cases: vec![TestCaseResult {
                    descriptor,
                    outcome: TestOutcome::Passed,
                    duration_ns: Some(1),
                }],
                events: vec![
                    TestEvent {
                        protocol: TEST_PROTOCOL_VERSION,
                        sequence: 0,
                        kind: TestEventKind::RunStarted { test_count: 1 },
                    },
                    TestEvent {
                        protocol: TEST_PROTOCOL_VERSION,
                        sequence: 1,
                        kind: TestEventKind::TestStarted { test: TestId(0) },
                    },
                    TestEvent {
                        protocol: TEST_PROTOCOL_VERSION,
                        sequence: 2,
                        kind: TestEventKind::TestFinished {
                            test: TestId(0),
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
                ],
                evidence: evidence(digest),
                infrastructure_failure: None,
            }],
        };
        report.validate_against(&validated).expect("valid report");
        assert!(report.passed());
    }

    #[test]
    fn rejects_scenario_actions_after_exit() {
        let (mut plan, _) = fixture();
        plan.scenarios[0]
            .steps
            .push(ImageScenarioStep::SendSerial { bytes: vec![1] });
        assert!(matches!(
            plan.validate(),
            Err(TestModelError::InvalidScenario(ScenarioId(0)))
        ));
    }

    #[test]
    fn rejects_forged_group_identity() {
        let (mut plan, _) = fixture();
        plan.image_groups[0].id = ImageGroupId(9);
        assert!(matches!(
            plan.seal(),
            Err(TestModelError::InvalidImageGroup(_))
        ));
    }

    #[test]
    fn enforces_plan_payload_ceiling_before_sealing() {
        let (plan, _) = fixture();
        let limits = TestPlanLimits {
            payload_bytes: 1,
            ..TestPlanLimits::standard()
        };
        assert!(matches!(
            plan.seal_with_limits(limits),
            Err(TestModelError::ResourceLimit {
                resource: "test plan",
                ..
            })
        ));
    }

    #[test]
    fn sealed_plan_retains_its_exact_resource_policy() {
        let (plan, _) = fixture();
        let limits = TestPlanLimits {
            report_bytes: 4096,
            ..TestPlanLimits::standard()
        };
        let validated = plan.seal_with_limits(limits).expect("valid bounded plan");
        assert_eq!(validated.limits(), limits);
    }

    #[test]
    fn rejects_group_output_above_plan_policy() {
        let (plan, _) = fixture();
        let limits = TestPlanLimits {
            output_bytes_per_group: 1023,
            ..TestPlanLimits::standard()
        };
        assert!(matches!(
            plan.seal_with_limits(limits),
            Err(TestModelError::InvalidImageGroup(_))
        ));
    }

    #[test]
    fn rejects_zero_generated_function_identity() {
        let (mut plan, digest) = fixture();
        plan.scenarios.clear();
        plan.image_groups[0].root = ImageRoot::GeneratedHarness {
            harness_name: "generated-tests".to_owned(),
        };
        plan.image_groups[0].tests[0].descriptor.kind = TestKind::IntegrationImage;
        plan.image_groups[0].tests[0].invocation = ImageTestInvocation::GeneratedFunction {
            function_key: FunctionKey(Sha256Digest::from_bytes([0; 32])),
        };
        plan.image_groups[0].deterministic_seed = Some(u64::from(digest.as_bytes()[0]));
        assert!(matches!(
            plan.seal(),
            Err(TestModelError::WrongGroup(TestId(0)))
        ));
    }

    #[test]
    fn permits_phase_accurate_prelink_failure_without_fabricated_evidence() {
        let (plan, digest) = fixture();
        let validated = plan.clone().seal().expect("valid plan");
        let report = TestReport {
            schema: TEST_REPORT_SCHEMA,
            build: plan.build.clone(),
            started_unix_ns: None,
            duration_ns: None,
            unit: Vec::new(),
            images: vec![ImageGroupResult {
                group: ImageGroupId(0),
                cases: Vec::new(),
                events: Vec::new(),
                evidence: ImageExecutionEvidence {
                    image_digest: None,
                    target_digest: digest,
                    emulator_digest: None,
                    scenario_digest: Some(digest),
                    command_digest: None,
                    event_stream_digest: None,
                    exit_code: None,
                    stderr: Vec::new(),
                },
                infrastructure_failure: Some(TestOutcome::Failed {
                    phase: FailurePhase::Compile,
                    message: "compile failed".to_owned(),
                }),
            }],
        };
        report
            .validate_against(&validated)
            .expect("phase-accurate failure report");
        assert!(!report.passed());
    }
}
