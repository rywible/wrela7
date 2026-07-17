//! Shared contracts for compiler-evaluated unit tests and AArch64 full-image
//! integration/image tests.

#![forbid(unsafe_code)]

mod codec;
mod scenario;

use std::fmt;

use wrela_build_model::{BuildIdentity, Sha256Digest, TargetIdentity};
use wrela_source::Span;

pub use codec::CanonicalTestReportCodec;
pub use scenario::CanonicalImageScenarioCodec;

pub const TEST_PROTOCOL_VERSION: u32 = 3;
pub const TEST_PLAN_SCHEMA: u32 = 2;
pub const MAX_PLANNED_ASSERTION_TEXT_BYTES: usize = 4096;
pub const TEST_REPORT_SCHEMA: u32 = 2;
pub const IMAGE_SCENARIO_SCHEMA: u32 = 1;
pub const MAX_TEST_EVENT_BYTES: usize = 1024 * 1024;
/// Runtime ABI v1 dense sequence capacity. The target runtime rejects a test
/// event once this many events have been emitted, so no sealed plan may promise
/// a larger per-image stream.
pub const MAX_RUNTIME_TEST_EVENTS: u32 = 1_000_000;

fn cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), TestModelError> {
    if is_cancelled() {
        Err(TestModelError::Cancelled)
    } else {
        Ok(())
    }
}

fn copy_bounded_text(
    value: &str,
    resource: &'static str,
    maximum_bytes: u64,
) -> Result<String, TestModelError> {
    let length = u64::try_from(value.len()).map_err(|_| TestModelError::ResourceLimit {
        resource,
        limit: maximum_bytes,
    })?;
    if length > maximum_bytes {
        return Err(TestModelError::ResourceLimit {
            resource,
            limit: maximum_bytes,
        });
    }
    let mut output = String::new();
    output
        .try_reserve_exact(value.len())
        .map_err(|_| TestModelError::ResourceLimit {
            resource,
            limit: maximum_bytes,
        })?;
    output.push_str(value);
    Ok(output)
}

fn text_has_content(value: &str, is_cancelled: &dyn Fn() -> bool) -> Result<bool, TestModelError> {
    for (index, character) in value.chars().enumerate() {
        if index % 1024 == 0 {
            cancelled(is_cancelled)?;
        }
        if !character.is_whitespace() {
            return Ok(true);
        }
    }
    cancelled(is_cancelled)?;
    Ok(false)
}

fn text_is_less(
    left: &str,
    right: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, TestModelError> {
    for (index, (left, right)) in left.bytes().zip(right.bytes()).enumerate() {
        if index % 4096 == 0 {
            cancelled(is_cancelled)?;
        }
        match left.cmp(&right) {
            std::cmp::Ordering::Less => return Ok(true),
            std::cmp::Ordering::Greater => return Ok(false),
            std::cmp::Ordering::Equal => {}
        }
    }
    cancelled(is_cancelled)?;
    Ok(left.len() < right.len())
}

fn text_is_equal(
    left: &str,
    right: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, TestModelError> {
    if left.len() != right.len() {
        return Ok(false);
    }
    for (index, (left, right)) in left.bytes().zip(right.bytes()).enumerate() {
        if index % 4096 == 0 {
            cancelled(is_cancelled)?;
        }
        if left != right {
            return Ok(false);
        }
    }
    cancelled(is_cancelled)?;
    Ok(true)
}

fn invalid_image_group<T>(name: &str, maximum_bytes: u64) -> Result<T, TestModelError> {
    Err(TestModelError::InvalidImageGroup(copy_bounded_text(
        name,
        "test-model error context",
        maximum_bytes,
    )?))
}

fn result_set_mismatch<T>(name: &str, maximum_bytes: u64) -> Result<T, TestModelError> {
    Err(TestModelError::ResultSetMismatch(copy_bounded_text(
        name,
        "test-model error context",
        maximum_bytes,
    )?))
}

fn invalid_event_stream<T>(name: &str, maximum_bytes: u64) -> Result<T, TestModelError> {
    Err(TestModelError::InvalidEventStream(copy_bounded_text(
        name,
        "test-model error context",
        maximum_bytes,
    )?))
}

fn invalid_evidence<T>(name: &str, maximum_bytes: u64) -> Result<T, TestModelError> {
    Err(TestModelError::InvalidEvidence(copy_bounded_text(
        name,
        "test-model error context",
        maximum_bytes,
    )?))
}

fn cancellable_sort<T: Copy + Ord>(
    values: &mut [T],
    maximum_entries: u64,
    resource: &'static str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), TestModelError> {
    cancelled(is_cancelled)?;
    let length = u64::try_from(values.len()).map_err(|_| TestModelError::ResourceLimit {
        resource,
        limit: maximum_entries,
    })?;
    if length > maximum_entries {
        return Err(TestModelError::ResourceLimit {
            resource,
            limit: maximum_entries,
        });
    }
    let Some(first) = values.first().copied() else {
        return Ok(());
    };
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(values.len())
        .map_err(|_| TestModelError::ResourceLimit {
            resource,
            limit: maximum_entries,
        })?;
    buffer.resize(values.len(), first);
    let mut width = 1_usize;
    let mut source_is_values = true;
    while width < values.len() {
        if source_is_values {
            cancellable_merge_pass(values, &mut buffer, width, is_cancelled)?;
        } else {
            cancellable_merge_pass(&buffer, values, width, is_cancelled)?;
        }
        source_is_values = !source_is_values;
        width = width.checked_mul(2).unwrap_or(values.len());
    }
    if !source_is_values {
        for (destination, source) in values.iter_mut().zip(buffer) {
            cancelled(is_cancelled)?;
            *destination = source;
        }
    }
    cancelled(is_cancelled)
}

fn cancellable_merge_pass<T: Copy + Ord>(
    source: &[T],
    destination: &mut [T],
    width: usize,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), TestModelError> {
    let mut start = 0_usize;
    while start < source.len() {
        let middle = start
            .checked_add(width)
            .unwrap_or(source.len())
            .min(source.len());
        let end = middle
            .checked_add(width)
            .unwrap_or(source.len())
            .min(source.len());
        let (mut left, mut right) = (start, middle);
        for output in &mut destination[start..end] {
            cancelled(is_cancelled)?;
            let take_left = right >= end || left < middle && source[left] <= source[right];
            if take_left {
                *output = source[left];
                left += 1;
            } else {
                *output = source[right];
                right += 1;
            }
        }
        start = end;
    }
    Ok(())
}

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
            events_per_group: MAX_RUNTIME_TEST_EVENTS,
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
        self.validate_shape_with_cancellation(&|| false)
    }

    pub fn validate_shape_with_cancellation(
        &self,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), TestModelError> {
        cancelled(is_cancelled)?;
        let mut wait_budget = Some(0_u64);
        for step in &self.steps {
            cancelled(is_cancelled)?;
            if invalid_scenario_step(step) {
                return Err(TestModelError::InvalidScenario(self.id));
            }
            wait_budget = wait_budget.and_then(|total| {
                total.checked_add(match step {
                    ImageScenarioStep::SendSerial { .. } => 0,
                    ImageScenarioStep::ExpectSerial { timeout_ns, .. }
                    | ImageScenarioStep::ExpectTestEvent { timeout_ns, .. }
                    | ImageScenarioStep::ExpectExit { timeout_ns, .. }
                    | ImageScenarioStep::RequestShutdown { timeout_ns } => *timeout_ns,
                })
            });
        }
        if self.schema != IMAGE_SCENARIO_SCHEMA
            || !text_has_content(&self.name, is_cancelled)?
            || !text_has_content(&self.source_path, is_cancelled)?
            || self.steps.is_empty()
            || !valid_scenario_sequence_with_cancellation(self, is_cancelled)?
            || wait_budget.is_none()
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
    let identity_bytes = u64::try_from(request.name.len())
        .ok()
        .and_then(|name| {
            u64::try_from(request.source_path.len())
                .ok()
                .and_then(|path| name.checked_add(path))
        })
        .filter(|total| *total <= request.maximum_bytes)
        .ok_or(TestModelError::ResourceLimit {
            resource: "image scenario identity bytes",
            limit: request.maximum_bytes,
        })?;
    let input = request.bytes;
    let id = request.id;
    let name = copy_bounded_text(
        request.name,
        "image scenario identity bytes",
        identity_bytes,
    )?;
    let source_path = copy_bounded_text(
        request.source_path,
        "image scenario identity bytes",
        identity_bytes,
    )?;
    let digest = request.verified_digest;
    let maximum_bytes = request.maximum_bytes;
    let maximum_steps = request.maximum_steps;
    let maximum_step_bytes = request.maximum_step_bytes;
    let scenario = codec.decode(request, is_cancelled)?;
    let mut step_payloads_valid = true;
    for step in &scenario.steps {
        cancelled(is_cancelled)?;
        step_payloads_valid &=
            scenario_step_payload_bytes(step).is_some_and(|bytes| bytes <= maximum_step_bytes);
    }
    if scenario.id != id
        || !text_is_equal(&scenario.name, &name, is_cancelled)?
        || !text_is_equal(&scenario.source_path, &source_path, is_cancelled)?
        || scenario.digest != digest
        || scenario.steps.len() > maximum_steps as usize
        || !step_payloads_valid
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

/// Exact source assertion allowed to fail from one selected generated test or
/// its sealed helper closure. This is the host-side authority used to reject a
/// substituted but otherwise canonical guest assertion event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedAssertionDescriptor {
    pub source: Span,
    pub expression: String,
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageTest {
    pub descriptor: TestDescriptor,
    pub invocation: ImageTestInvocation,
    pub assertions: Vec<PlannedAssertionDescriptor>,
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
    /// Validate the self-contained portion of a compiled group binding.
    ///
    /// Plan-wide density, scenario lookup, and cross-group function-key
    /// uniqueness remain [`TestPlan`] invariants. WIR and image-report model
    /// validators use this after copying a group from a sealed plan and then
    /// enforce their own executable/root relationships.
    pub fn validate_compiled_binding(&self) -> Result<(), TestModelError> {
        self.validate_compiled_binding_with_limits(TestPlanLimits::standard(), &|| false)
    }

    /// Validate a copied compiled-group binding under the same finite policy as
    /// its originating plan. This is used by WIR and report boundaries, where
    /// the complete plan is intentionally unavailable.
    pub fn validate_compiled_binding_with_limits(
        &self,
        limits: TestPlanLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), TestModelError> {
        cancelled(is_cancelled)?;
        if !limits.is_valid() {
            return Err(TestModelError::InvalidLimits);
        }
        if self.tests.len() > limits.tests as usize {
            return Err(TestModelError::ResourceLimit {
                resource: "compiled test-group tests",
                limit: u64::from(limits.tests),
            });
        }
        let mut payload_bytes = 0_u64;
        let mut charge_text = |text: &str| -> Result<(), TestModelError> {
            payload_bytes = payload_bytes
                .checked_add(u64::try_from(text.len()).map_err(|_| {
                    TestModelError::ResourceLimit {
                        resource: "compiled test-group payload bytes",
                        limit: limits.payload_bytes,
                    }
                })?)
                .filter(|total| *total <= limits.payload_bytes)
                .ok_or(TestModelError::ResourceLimit {
                    resource: "compiled test-group payload bytes",
                    limit: limits.payload_bytes,
                })?;
            Ok(())
        };
        charge_text(&self.name)?;
        match &self.root {
            ImageRoot::GeneratedHarness { harness_name } => charge_text(harness_name)?,
            ImageRoot::Declared { image_name, .. } => charge_text(image_name)?,
        }
        for test in &self.tests {
            cancelled(is_cancelled)?;
            charge_text(&test.descriptor.name)?;
            for assertion in &test.assertions {
                charge_text(&assertion.expression)?;
                if let Some(message) = &assertion.message {
                    charge_text(message)?;
                }
            }
        }
        if !text_has_content(&self.name, is_cancelled)?
            || self.tests.is_empty()
            || self.boot_timeout_ns == 0
            || self.shutdown_timeout_ns == 0
            || self.maximum_events == 0
            || self.maximum_output_bytes == 0
            || self.maximum_events > limits.events_per_group
            || self.maximum_output_bytes > limits.output_bytes_per_group
            || self
                .boot_timeout_ns
                .checked_add(self.shutdown_timeout_ns)
                .is_none_or(|timeout| timeout > limits.execution_timeout_ns_per_group)
        {
            return invalid_image_group(&self.name, limits.payload_bytes);
        }
        for pair in self.tests.windows(2) {
            cancelled(is_cancelled)?;
            if pair[0].descriptor.id.0.checked_add(1) != Some(pair[1].descriptor.id.0) {
                return invalid_image_group(&self.name, limits.payload_bytes);
            }
        }
        let mut function_keys = Vec::new();
        function_keys
            .try_reserve_exact(self.tests.len())
            .map_err(|_| TestModelError::ResourceLimit {
                resource: "compiled test-group function keys",
                limit: u64::from(limits.tests),
            })?;
        for test in &self.tests {
            cancelled(is_cancelled)?;
            if !text_has_content(&test.descriptor.name, is_cancelled)?
                || test.descriptor.timeout_ns == 0
            {
                return Err(TestModelError::InvalidDescriptor(test.descriptor.id));
            }
            for assertion in &test.assertions {
                cancelled(is_cancelled)?;
                let message_valid = match &assertion.message {
                    Some(message) => {
                        text_has_content(message, is_cancelled)?
                            && message.len() <= MAX_PLANNED_ASSERTION_TEXT_BYTES
                    }
                    None => true,
                };
                if !text_has_content(&assertion.expression, is_cancelled)?
                    || assertion.expression.len() > MAX_PLANNED_ASSERTION_TEXT_BYTES
                    || !message_valid
                    || assertion.source.range.start > assertion.source.range.end
                {
                    return invalid_image_group(&self.name, limits.payload_bytes);
                }
            }
            for pair in test.assertions.windows(2) {
                let ordering = (
                    pair[0].source.file.0,
                    pair[0].source.range.start,
                    pair[0].source.range.end,
                )
                    .cmp(&(
                        pair[1].source.file.0,
                        pair[1].source.range.start,
                        pair[1].source.range.end,
                    ))
                    .then_with(|| pair[0].expression.cmp(&pair[1].expression))
                    .then_with(|| pair[0].message.cmp(&pair[1].message));
                if ordering != std::cmp::Ordering::Less {
                    return invalid_image_group(&self.name, limits.payload_bytes);
                }
            }
            let valid = match (&self.root, &test.invocation, test.descriptor.kind) {
                (
                    ImageRoot::GeneratedHarness { .. },
                    ImageTestInvocation::GeneratedFunction { function_key },
                    TestKind::IntegrationImage,
                ) if function_key.is_valid() => {
                    function_keys.push(*function_key);
                    test.descriptor.source.is_some()
                }
                (
                    ImageRoot::Declared { .. },
                    ImageTestInvocation::DeclaredScenario,
                    TestKind::DeclaredImage,
                ) => test.descriptor.source.is_none() && test.assertions.is_empty(),
                _ => false,
            };
            if !valid {
                return Err(TestModelError::WrongGroup(test.descriptor.id));
            }
        }
        cancellable_sort(
            &mut function_keys,
            u64::from(limits.tests),
            "compiled test-group function keys",
            is_cancelled,
        )?;
        for pair in function_keys.windows(2) {
            cancelled(is_cancelled)?;
            if pair[0] == pair[1] {
                return invalid_image_group(&self.name, limits.payload_bytes);
            }
        }
        let root_valid = match &self.root {
            ImageRoot::GeneratedHarness { harness_name } => {
                let expected_events = u32::try_from(self.tests.len())
                    .ok()
                    .and_then(|count| count.checked_mul(2))
                    .and_then(|count| count.checked_add(3));
                text_has_content(harness_name, is_cancelled)?
                    && expected_events == Some(self.maximum_events)
                    && (!self.tests.iter().any(|test| !test.assertions.is_empty())
                        || self.tests.len() == 1)
                    && self
                        .execution_timeout_ns_with_cancellation(None, is_cancelled)?
                        .is_some_and(|timeout| timeout <= limits.execution_timeout_ns_per_group)
            }
            ImageRoot::Declared { image_name, .. } => {
                text_has_content(image_name, is_cancelled)? && self.tests.len() == 1
            }
        };
        if !root_valid {
            return invalid_image_group(&self.name, limits.payload_bytes);
        }
        Ok(())
    }

    /// Hard wall-clock budget passed to the process executor. Boot and
    /// shutdown are always included. Generated harnesses then receive the sum
    /// of per-test budgets; declared images receive the sum of scenario waits.
    #[must_use]
    pub fn execution_timeout_ns(&self, scenario: Option<&ImageScenario>) -> Option<u64> {
        self.execution_timeout_ns_with_cancellation(scenario, &|| false)
            .ok()
            .flatten()
    }

    pub fn execution_timeout_ns_with_cancellation(
        &self,
        scenario: Option<&ImageScenario>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Option<u64>, TestModelError> {
        cancelled(is_cancelled)?;
        let Some(base) = self.boot_timeout_ns.checked_add(self.shutdown_timeout_ns) else {
            return Ok(None);
        };
        let body = match (&self.root, scenario) {
            (ImageRoot::GeneratedHarness { .. }, None) => {
                let mut total = Some(0_u64);
                for test in &self.tests {
                    cancelled(is_cancelled)?;
                    total = total.and_then(|value| value.checked_add(test.descriptor.timeout_ns));
                }
                let Some(total) = total else {
                    return Ok(None);
                };
                total
            }
            (ImageRoot::Declared { .. }, Some(scenario)) => {
                let mut total = Some(0_u64);
                for step in &scenario.steps {
                    cancelled(is_cancelled)?;
                    total = total.and_then(|value| {
                        value.checked_add(match step {
                            ImageScenarioStep::SendSerial { .. } => 0,
                            ImageScenarioStep::ExpectSerial { timeout_ns, .. }
                            | ImageScenarioStep::ExpectTestEvent { timeout_ns, .. }
                            | ImageScenarioStep::ExpectExit { timeout_ns, .. }
                            | ImageScenarioStep::RequestShutdown { timeout_ns } => *timeout_ns,
                        })
                    });
                }
                let Some(total) = total else {
                    return Ok(None);
                };
                total
            }
            _ => return Ok(None),
        };
        Ok(base.checked_add(body))
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
        self.seal_with_limits_and_cancellation(limits, &|| false)
    }

    /// Validate and seal without publishing a stale success after cancellation.
    pub fn seal_with_limits_and_cancellation(
        self,
        limits: TestPlanLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ValidatedTestPlan, TestModelError> {
        let metrics = self.validate_and_measure(limits, is_cancelled)?;
        cancelled(is_cancelled)?;
        Ok(ValidatedTestPlan {
            plan: self,
            limits,
            payload_bytes: metrics.payload_bytes,
            scenario_steps: metrics.scenario_steps,
        })
    }

    pub fn validate(&self) -> Result<(), TestModelError> {
        self.validate_with_limits(TestPlanLimits::standard())
    }

    pub fn validate_with_limits(&self, limits: TestPlanLimits) -> Result<(), TestModelError> {
        self.validate_with_limits_and_cancellation(limits, &|| false)
    }

    pub fn validate_with_limits_and_cancellation(
        &self,
        limits: TestPlanLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), TestModelError> {
        self.validate_and_measure(limits, is_cancelled).map(|_| ())
    }

    fn validate_and_measure(
        &self,
        limits: TestPlanLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<TestPlanMetrics, TestModelError> {
        cancelled(is_cancelled)?;
        if !limits.is_valid() {
            return Err(TestModelError::InvalidLimits);
        }
        if self.schema != TEST_PLAN_SCHEMA {
            return Err(TestModelError::UnsupportedPlanSchema(self.schema));
        }
        if self.target != self.build.target {
            return Err(TestModelError::TargetMismatch);
        }
        for pair in self.scenarios.windows(2) {
            if !text_is_less(&pair[0].name, &pair[1].name, is_cancelled)? {
                return Err(TestModelError::NonCanonicalScenarios);
            }
        }
        for pair in self.image_groups.windows(2) {
            if !text_is_less(&pair[0].name, &pair[1].name, is_cancelled)? {
                return Err(TestModelError::NonCanonicalImageGroups);
            }
        }
        let total_tests =
            self.image_groups
                .iter()
                .try_fold(self.unit_tests.len(), |total, group| {
                    cancelled(is_cancelled)?;
                    total
                        .checked_add(group.tests.len())
                        .ok_or(TestModelError::ResourceLimit {
                            resource: "test plan tests",
                            limit: u64::from(limits.tests),
                        })
                })?;
        let scenario_steps = self.scenarios.iter().try_fold(0usize, |total, scenario| {
            cancelled(is_cancelled)?;
            total
                .checked_add(scenario.steps.len())
                .ok_or(TestModelError::ResourceLimit {
                    resource: "test plan scenario steps",
                    limit: u64::from(limits.scenario_steps),
                })
        })?;
        let payload_bytes =
            test_plan_payload_bytes_with_cancellation(self, limits.payload_bytes, is_cancelled)?;
        if total_tests > limits.tests as usize
            || self.image_groups.len() > limits.groups as usize
            || self.scenarios.len() > limits.scenarios as usize
            || scenario_steps > limits.scenario_steps as usize
            || payload_bytes > limits.payload_bytes
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
            cancelled(is_cancelled)?;
            scenario.validate_shape_with_cancellation(is_cancelled)?;
            let mut invalid_test_reference = false;
            for step in &scenario.steps {
                cancelled(is_cancelled)?;
                invalid_test_reference |= matches!(
                    step,
                    ImageScenarioStep::ExpectTestEvent {
                        test: Some(test),
                        ..
                    } if test.0 as usize >= total_tests
                );
            }
            if scenario.id.0 as usize != expected || invalid_test_reference {
                return Err(TestModelError::InvalidScenario(scenario.id));
            }
        }
        let descriptors = self.unit_tests.iter().map(|test| &test.descriptor).chain(
            self.image_groups
                .iter()
                .flat_map(|group| group.tests.iter().map(|test| &test.descriptor)),
        );
        for (expected, descriptor) in descriptors.enumerate() {
            cancelled(is_cancelled)?;
            if descriptor.id.0 as usize != expected {
                return Err(TestModelError::NonDenseTestId {
                    expected,
                    actual: descriptor.id,
                });
            }
            if !text_has_content(&descriptor.name, is_cancelled)? || descriptor.timeout_ns == 0 {
                return Err(TestModelError::InvalidDescriptor(descriptor.id));
            }
        }
        let mut function_keys = Vec::new();
        function_keys.try_reserve_exact(total_tests).map_err(|_| {
            TestModelError::ResourceLimit {
                resource: "test plan function-key scratch",
                limit: u64::from(limits.tests),
            }
        })?;
        for test in &self.unit_tests {
            cancelled(is_cancelled)?;
            if test.descriptor.kind != TestKind::ComptimeUnit || !test.function_key.is_valid() {
                return Err(TestModelError::InvalidDescriptor(test.descriptor.id));
            }
            function_keys.push((test.function_key, test.descriptor.id, true));
        }
        for (expected, group) in self.image_groups.iter().enumerate() {
            cancelled(is_cancelled)?;
            if group.id.0 as usize != expected || !text_has_content(&group.name, is_cancelled)? {
                return invalid_image_group(&group.name, limits.payload_bytes);
            }
            group.validate_compiled_binding_with_limits(limits, is_cancelled)?;
            let root_valid = match &group.root {
                ImageRoot::GeneratedHarness { harness_name } => {
                    text_has_content(harness_name, is_cancelled)
                }
                ImageRoot::Declared {
                    image_name,
                    scenario,
                } => {
                    let Some(scenario) = self.scenarios.get(scenario.0 as usize) else {
                        return invalid_image_group(&group.name, limits.payload_bytes);
                    };
                    let mut valid =
                        text_has_content(image_name, is_cancelled)? && group.tests.len() == 1;
                    for step in &scenario.steps {
                        cancelled(is_cancelled)?;
                        valid &= !matches!(
                            step,
                            ImageScenarioStep::ExpectTestEvent { test: Some(id), .. }
                                if group.tests[0].descriptor.id != *id
                        );
                    }
                    Ok(valid)
                }
            }?;
            let scenario = match &group.root {
                ImageRoot::GeneratedHarness { .. } => None,
                ImageRoot::Declared { scenario, .. } => self.scenarios.get(scenario.0 as usize),
            };
            if !root_valid
                || group
                    .execution_timeout_ns_with_cancellation(scenario, is_cancelled)?
                    .is_none_or(|timeout| timeout > limits.execution_timeout_ns_per_group)
            {
                return invalid_image_group(&group.name, limits.payload_bytes);
            }
            for test in &group.tests {
                cancelled(is_cancelled)?;
                let valid = match (&group.root, &test.invocation, test.descriptor.kind) {
                    (
                        ImageRoot::GeneratedHarness { .. },
                        ImageTestInvocation::GeneratedFunction { function_key },
                        TestKind::IntegrationImage,
                    ) if function_key.is_valid() => {
                        function_keys.push((*function_key, test.descriptor.id, false));
                        true
                    }
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
        cancellable_sort(
            &mut function_keys,
            u64::from(limits.tests),
            "test plan function-key scratch",
            is_cancelled,
        )?;
        for pair in function_keys.windows(2) {
            cancelled(is_cancelled)?;
            if pair[0].0 == pair[1].0 {
                return if pair[1].2 {
                    Err(TestModelError::InvalidDescriptor(pair[1].1))
                } else {
                    Err(TestModelError::WrongGroup(pair[1].1))
                };
            }
        }
        Ok(TestPlanMetrics {
            payload_bytes,
            scenario_steps,
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct TestPlanMetrics {
    payload_bytes: u64,
    scenario_steps: usize,
}

fn test_plan_payload_bytes_with_cancellation(
    plan: &TestPlan,
    maximum_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<u64, TestModelError> {
    let mut bytes = 0u64;
    let mut add = |length: usize| -> Result<(), TestModelError> {
        let length = u64::try_from(length).map_err(|_| TestModelError::ResourceLimit {
            resource: "test plan",
            limit: maximum_bytes,
        })?;
        bytes = bytes
            .checked_add(length)
            .filter(|total| *total <= maximum_bytes)
            .ok_or(TestModelError::ResourceLimit {
                resource: "test plan",
                limit: maximum_bytes,
            })?;
        Ok(())
    };
    for scenario in &plan.scenarios {
        cancelled(is_cancelled)?;
        add(scenario.name.len())?;
        add(scenario.source_path.len())?;
        for step in &scenario.steps {
            cancelled(is_cancelled)?;
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
        cancelled(is_cancelled)?;
        add(test.descriptor.name.len())?;
    }
    for group in &plan.image_groups {
        cancelled(is_cancelled)?;
        add(group.name.len())?;
        match &group.root {
            ImageRoot::GeneratedHarness { harness_name } => add(harness_name.len())?,
            ImageRoot::Declared { image_name, .. } => add(image_name.len())?,
        }
        for test in &group.tests {
            cancelled(is_cancelled)?;
            add(test.descriptor.name.len())?;
            for assertion in &test.assertions {
                add(assertion.expression.len())?;
                add(assertion.message.as_ref().map_or(0, String::len))?;
            }
        }
    }
    Ok(bytes)
}

/// Structurally valid, identity-bound test discovery output. Consumers borrow
/// groups from this wrapper so a group cannot be compiled independently of the
/// plan and build identity that assigned its test/function IDs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedTestPlan {
    plan: TestPlan,
    limits: TestPlanLimits,
    payload_bytes: u64,
    scenario_steps: usize,
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
        self.payload_bytes
    }

    #[must_use]
    pub fn scenario_step_count(&self) -> usize {
        self.scenario_steps
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

fn valid_scenario_sequence_with_cancellation(
    scenario: &ImageScenario,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, TestModelError> {
    let mut shutdown_requested = false;
    let mut saw_exit = false;
    let mut saw_run_finished = false;
    for (index, step) in scenario.steps.iter().enumerate() {
        cancelled(is_cancelled)?;
        match step {
            ImageScenarioStep::RequestShutdown { .. } => {
                if shutdown_requested || saw_exit {
                    return Ok(false);
                }
                shutdown_requested = true;
            }
            ImageScenarioStep::ExpectExit { .. } => {
                if saw_exit || index + 1 != scenario.steps.len() {
                    return Ok(false);
                }
                saw_exit = true;
            }
            ImageScenarioStep::ExpectTestEvent {
                kind: ExpectedScenarioEvent::RunFinished,
                ..
            } => {
                if saw_run_finished || saw_exit || shutdown_requested {
                    return Ok(false);
                }
                saw_run_finished = true;
            }
            _ if saw_exit || shutdown_requested => return Ok(false),
            _ => {}
        }
    }
    Ok(saw_exit || saw_run_finished)
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

/// Closed language-level fatal causes that a checked operation may emit while
/// a test is active. These are test outcomes, never host infrastructure
/// failures; extending this enum requires a protocol and report schema bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LanguageFatalCause {
    CheckedShiftResultLoss,
    InvalidShiftCount,
}

/// Outcomes a running guest can legitimately emit. Host discovery, compile,
/// link, boot, shutdown, and process-crash failures are report infrastructure
/// outcomes and cannot be forged as guest test-finished events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuestTestOutcome {
    Passed,
    Failed { message: String },
    TimedOut { timeout_ns: u64 },
    LanguageFatal { cause: LanguageFatalCause },
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
    LanguageFatal {
        cause: LanguageFatalCause,
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
        self.seal_against_with_cancellation(plan, &|| false)
    }

    pub fn seal_against_with_cancellation(
        self,
        plan: &ValidatedTestPlan,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ValidatedTestReport, TestModelError> {
        self.validate_against_with_cancellation(plan, is_cancelled)?;
        cancelled(is_cancelled)?;
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
        self.validate_against_with_cancellation(validated, &|| false)
    }

    pub fn validate_against_with_cancellation(
        &self,
        validated: &ValidatedTestPlan,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), TestModelError> {
        cancelled(is_cancelled)?;
        let plan = validated.as_plan();
        let limits = validated.limits();
        plan.validate_with_limits_and_cancellation(limits, is_cancelled)?;
        if self.schema != TEST_REPORT_SCHEMA {
            return Err(TestModelError::UnsupportedReportSchema(self.schema));
        }
        if self.build != plan.build {
            return Err(TestModelError::BuildMismatch);
        }
        if self.unit.len() != plan.unit_tests.len() {
            return Err(TestModelError::ResultSetMismatch("comptime".to_owned()));
        }
        if self.images.len() != plan.image_groups.len() {
            return Err(TestModelError::ResultSetMismatch("image groups".to_owned()));
        }
        for (result, group) in self.images.iter().zip(&plan.image_groups) {
            cancelled(is_cancelled)?;
            if result.cases.len() > group.tests.len()
                || result.events.len() > group.maximum_events as usize
                || u64::try_from(result.evidence.stderr.len())
                    .map_or(true, |bytes| bytes > group.maximum_output_bytes)
            {
                return result_set_mismatch(&group.name, limits.payload_bytes);
            }
        }
        test_report_payload_bytes_with_cancellation(self, limits.report_bytes, is_cancelled)?;
        for (result, planned) in self.unit.iter().zip(&plan.unit_tests) {
            cancelled(is_cancelled)?;
            if result.descriptor != planned.descriptor
                || !matches!(
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
                )
                || invalid_host_outcome(&result.outcome, is_cancelled)?
            {
                return Err(TestModelError::ResultSetMismatch("comptime".to_owned()));
            }
        }
        for (result, group) in self.images.iter().zip(&plan.image_groups) {
            cancelled(is_cancelled)?;
            if result.group != group.id || result.cases.len() > group.tests.len() {
                return result_set_mismatch(&group.name, limits.payload_bytes);
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
                return result_set_mismatch(&group.name, limits.payload_bytes);
            }
            if result.infrastructure_failure.is_none() && result.cases.len() != group.tests.len() {
                return result_set_mismatch(&group.name, limits.payload_bytes);
            }
            let invalid_infrastructure_failure = match &result.infrastructure_failure {
                Some(outcome) => {
                    matches!(
                        outcome,
                        TestOutcome::Passed | TestOutcome::LanguageFatal { .. }
                    ) || invalid_host_outcome(outcome, is_cancelled)?
                }
                None => false,
            };
            if invalid_infrastructure_failure
                || result.events.len() > group.maximum_events as usize
                || u64::try_from(result.evidence.stderr.len())
                    .map_or(true, |bytes| bytes > group.maximum_output_bytes)
                || image_transport_payload_bytes_with_cancellation(
                    result,
                    group.maximum_output_bytes,
                    is_cancelled,
                )?
                .is_none()
            {
                return result_set_mismatch(&group.name, limits.payload_bytes);
            }
            validate_evidence_phase(result, group, limits.payload_bytes)?;
            for (case, planned) in result.cases.iter().zip(&group.tests) {
                cancelled(is_cancelled)?;
                if case.descriptor != planned.descriptor {
                    return result_set_mismatch(&group.name, limits.payload_bytes);
                }
            }
            validate_image_events(
                result,
                group,
                limits.tests,
                limits.payload_bytes,
                is_cancelled,
            )?;
        }
        cancelled(is_cancelled)?;
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
    maximum_context_bytes: u64,
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
        Some(TestOutcome::Passed | TestOutcome::LanguageFatal { .. }) => false,
    };
    if valid {
        Ok(())
    } else {
        invalid_evidence(&group.name, maximum_context_bytes)
    }
}

#[derive(Debug, Clone, Copy)]
enum EventTestState<'a> {
    Pending,
    Active,
    AssertionFailed { terminal_message: &'a str },
    Finished(&'a GuestTestOutcome),
}

fn validate_image_events(
    result: &ImageGroupResult,
    group: &FullImageTestGroup,
    maximum_tests: u32,
    maximum_context_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), TestModelError> {
    cancelled(is_cancelled)?;
    if result.events.is_empty() {
        return if result.infrastructure_failure.is_some() && result.cases.is_empty() {
            Ok(())
        } else {
            invalid_event_stream(&group.name, maximum_context_bytes)
        };
    }
    if group.tests.len() > maximum_tests as usize {
        return Err(TestModelError::ResourceLimit {
            resource: "test event state entries",
            limit: u64::from(maximum_tests),
        });
    }
    let mut states = Vec::new();
    states
        .try_reserve_exact(group.tests.len())
        .map_err(|_| TestModelError::ResourceLimit {
            resource: "test event state entries",
            limit: u64::from(maximum_tests),
        })?;
    states.resize(group.tests.len(), EventTestState::Pending);
    let first_test = group.tests.first().map(|test| test.descriptor.id.0);
    let state_index = |test: TestId| -> Option<usize> {
        let offset = test.0.checked_sub(first_test?)?;
        let index = usize::try_from(offset).ok()?;
        group
            .tests
            .get(index)
            .filter(|planned| planned.descriptor.id == test)
            .map(|_| index)
    };
    let mut active_count = 0_usize;
    let mut finished_count = 0_usize;
    let mut terminal = None;
    let mut language_fatal = false;
    let mut last_heartbeat = None;
    for (index, event) in result.events.iter().enumerate() {
        cancelled(is_cancelled)?;
        if event.protocol != TEST_PROTOCOL_VERSION
            || u64::try_from(index).ok() != Some(event.sequence)
            || event_payload_bytes(event).is_none_or(|bytes| bytes > MAX_TEST_EVENT_BYTES as u64)
        {
            return invalid_event_stream(&group.name, maximum_context_bytes);
        }
        if language_fatal && !matches!(&event.kind, TestEventKind::RunFinished { .. }) {
            return invalid_event_stream(&group.name, maximum_context_bytes);
        }
        let pending_assertion = states.iter().enumerate().find_map(|(state_index, state)| {
            let EventTestState::AssertionFailed { terminal_message } = state else {
                return None;
            };
            group
                .tests
                .get(state_index)
                .map(|test| (test.descriptor.id, *terminal_message))
        });
        if let Some((asserted_test, terminal_message)) = pending_assertion {
            if !matches!(
                &event.kind,
                TestEventKind::TestFinished {
                    test,
                    outcome: GuestTestOutcome::Failed { message },
                } if *test == asserted_test && message == terminal_message
            ) {
                return invalid_event_stream(&group.name, maximum_context_bytes);
            }
        }
        match &event.kind {
            TestEventKind::RunStarted { test_count } => {
                if index != 0 || usize::try_from(*test_count).ok() != Some(group.tests.len()) {
                    return invalid_event_stream(&group.name, maximum_context_bytes);
                }
            }
            TestEventKind::TestStarted { test } => {
                let state = state_index(*test).and_then(|index| states.get_mut(index));
                if index == 0
                    || terminal.is_some()
                    || !matches!(state.as_deref(), Some(EventTestState::Pending))
                {
                    return invalid_event_stream(&group.name, maximum_context_bytes);
                }
                let Some(state) = state else {
                    return invalid_event_stream(&group.name, maximum_context_bytes);
                };
                *state = EventTestState::Active;
                active_count =
                    active_count
                        .checked_add(1)
                        .ok_or(TestModelError::ResourceLimit {
                            resource: "test event state entries",
                            limit: u64::from(maximum_tests),
                        })?;
            }
            TestEventKind::Log {
                test: Some(test),
                message,
                ..
            } => {
                if terminal.is_some()
                    || !state_index(*test)
                        .and_then(|index| states.get(index))
                        .is_some_and(|state| matches!(state, EventTestState::Active))
                    || message.is_empty()
                {
                    return invalid_event_stream(&group.name, maximum_context_bytes);
                }
            }
            TestEventKind::Log {
                test: None,
                message,
                ..
            } => {
                if index == 0 || terminal.is_some() || message.is_empty() {
                    return invalid_event_stream(&group.name, maximum_context_bytes);
                }
            }
            TestEventKind::AssertionFailed { test, failure } => {
                let planned_assertion_matches =
                    if matches!(&group.root, ImageRoot::GeneratedHarness { .. }) {
                        state_index(*test)
                            .and_then(|index| group.tests.get(index))
                            .is_some_and(|planned| {
                                failure.expected.is_none()
                                    && failure.actual.is_none()
                                    && failure.source.is_some_and(|source| {
                                        planned.assertions.iter().any(|assertion| {
                                            assertion.source == source
                                                && assertion.expression == failure.expression
                                                && assertion.message == failure.message
                                        })
                                    })
                            })
                    } else {
                        true
                    };
                let state = state_index(*test).and_then(|index| states.get_mut(index));
                let message_is_valid = match failure.message.as_deref() {
                    Some(message) => text_has_content(message, is_cancelled)?,
                    None => true,
                };
                let generated_source_is_valid =
                    !matches!(&group.root, ImageRoot::GeneratedHarness { .. })
                        || failure
                            .source
                            .is_some_and(|source| source.range.start <= source.range.end);
                if terminal.is_some()
                    || !matches!(state.as_deref(), Some(EventTestState::Active))
                    || !text_has_content(&failure.expression, is_cancelled)?
                    || !message_is_valid
                    || !generated_source_is_valid
                    || !planned_assertion_matches
                {
                    return invalid_event_stream(&group.name, maximum_context_bytes);
                }
                let Some(state) = state else {
                    return invalid_event_stream(&group.name, maximum_context_bytes);
                };
                *state = EventTestState::AssertionFailed {
                    terminal_message: failure.message.as_deref().unwrap_or("assertion failed"),
                };
            }
            TestEventKind::TestFinished { test, outcome } => {
                let state = state_index(*test).and_then(|index| states.get_mut(index));
                let valid_state = match (state.as_deref(), outcome) {
                    (Some(EventTestState::Active), _) => true,
                    (
                        Some(EventTestState::AssertionFailed { terminal_message }),
                        GuestTestOutcome::Failed { message },
                    ) => message == terminal_message,
                    _ => false,
                };
                if terminal.is_some()
                    || !valid_state
                    || invalid_guest_outcome(outcome, is_cancelled)?
                {
                    return invalid_event_stream(&group.name, maximum_context_bytes);
                }
                let Some(state) = state else {
                    return invalid_event_stream(&group.name, maximum_context_bytes);
                };
                *state = EventTestState::Finished(outcome);
                language_fatal = matches!(outcome, GuestTestOutcome::LanguageFatal { .. });
                active_count =
                    active_count
                        .checked_sub(1)
                        .ok_or(TestModelError::ResourceLimit {
                            resource: "test event state entries",
                            limit: u64::from(maximum_tests),
                        })?;
                finished_count =
                    finished_count
                        .checked_add(1)
                        .ok_or(TestModelError::ResourceLimit {
                            resource: "test event state entries",
                            limit: u64::from(maximum_tests),
                        })?;
            }
            TestEventKind::Heartbeat { monotonic_ticks } => {
                if index == 0
                    || terminal.is_some()
                    || last_heartbeat.is_some_and(|previous| previous >= *monotonic_ticks)
                {
                    return invalid_event_stream(&group.name, maximum_context_bytes);
                }
                last_heartbeat = Some(*monotonic_ticks);
            }
            TestEventKind::RunFinished { passed, failed } => {
                if terminal.is_some()
                    || index.checked_add(1) != Some(result.events.len())
                    || result.infrastructure_failure.is_some()
                    || active_count != 0
                {
                    return invalid_event_stream(&group.name, maximum_context_bytes);
                }
                terminal = Some((*passed, *failed));
            }
        }
    }
    for case in &result.cases {
        cancelled(is_cancelled)?;
        let outcome = state_index(case.descriptor.id)
            .and_then(|index| states.get(index))
            .and_then(|state| match state {
                EventTestState::Finished(outcome) => Some(*outcome),
                EventTestState::Pending
                | EventTestState::Active
                | EventTestState::AssertionFailed { .. } => None,
            });
        let matches = match outcome {
            Some(outcome) => guest_outcome_matches_case(outcome, &case.outcome, is_cancelled)?,
            None => false,
        };
        if !matches {
            return invalid_event_stream(&group.name, maximum_context_bytes);
        }
    }
    if result.infrastructure_failure.is_some() {
        if terminal.is_some() || finished_count != result.cases.len() {
            return invalid_event_stream(&group.name, maximum_context_bytes);
        }
    } else {
        let mut passed = 0_u32;
        for case in &result.cases {
            cancelled(is_cancelled)?;
            if matches!(case.outcome, TestOutcome::Passed) {
                passed = passed.checked_add(1).ok_or(TestModelError::ResourceLimit {
                    resource: "test event state entries",
                    limit: u64::from(maximum_tests),
                })?;
            }
        }
        let cases =
            u32::try_from(result.cases.len()).map_err(|_| TestModelError::ResourceLimit {
                resource: "test event state entries",
                limit: u64::from(maximum_tests),
            })?;
        let failed = cases
            .checked_sub(passed)
            .ok_or(TestModelError::ResourceLimit {
                resource: "test event state entries",
                limit: u64::from(maximum_tests),
            })?;
        if terminal != Some((passed, failed)) || finished_count != group.tests.len() {
            return invalid_event_stream(&group.name, maximum_context_bytes);
        }
    }
    cancelled(is_cancelled)?;
    Ok(())
}

fn test_report_payload_bytes_with_cancellation(
    report: &TestReport,
    maximum_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<u64, TestModelError> {
    let mut bytes = 0_u64;
    for result in &report.unit {
        cancelled(is_cancelled)?;
        charge_report_payload(&mut bytes, result.descriptor.name.len(), maximum_bytes)?;
        charge_outcome_payload(&mut bytes, &result.outcome, maximum_bytes)?;
    }
    for result in &report.images {
        cancelled(is_cancelled)?;
        charge_report_payload(&mut bytes, result.evidence.stderr.len(), maximum_bytes)?;
        for case in &result.cases {
            cancelled(is_cancelled)?;
            charge_report_payload(&mut bytes, case.descriptor.name.len(), maximum_bytes)?;
            charge_outcome_payload(&mut bytes, &case.outcome, maximum_bytes)?;
        }
        if let Some(outcome) = &result.infrastructure_failure {
            charge_outcome_payload(&mut bytes, outcome, maximum_bytes)?;
        }
        for event in &result.events {
            cancelled(is_cancelled)?;
            let event_bytes = event_payload_bytes(event).ok_or(TestModelError::ResourceLimit {
                resource: "test report payload",
                limit: maximum_bytes,
            })?;
            charge_report_payload_u64(&mut bytes, event_bytes, maximum_bytes)?;
        }
    }
    cancelled(is_cancelled)?;
    Ok(bytes)
}

fn charge_report_payload(
    total: &mut u64,
    length: usize,
    maximum_bytes: u64,
) -> Result<(), TestModelError> {
    let length = u64::try_from(length).map_err(|_| TestModelError::ResourceLimit {
        resource: "test report payload",
        limit: maximum_bytes,
    })?;
    charge_report_payload_u64(total, length, maximum_bytes)
}

fn charge_report_payload_u64(
    total: &mut u64,
    length: u64,
    maximum_bytes: u64,
) -> Result<(), TestModelError> {
    *total = total
        .checked_add(length)
        .filter(|value| *value <= maximum_bytes)
        .ok_or(TestModelError::ResourceLimit {
            resource: "test report payload",
            limit: maximum_bytes,
        })?;
    Ok(())
}

fn charge_outcome_payload(
    total: &mut u64,
    outcome: &TestOutcome,
    maximum_bytes: u64,
) -> Result<(), TestModelError> {
    match outcome {
        TestOutcome::Failed { message, .. } | TestOutcome::Crashed { message, .. } => {
            charge_report_payload(total, message.len(), maximum_bytes)
        }
        TestOutcome::Passed | TestOutcome::TimedOut { .. } | TestOutcome::LanguageFatal { .. } => {
            Ok(())
        }
    }
}

fn image_transport_payload_bytes_with_cancellation(
    result: &ImageGroupResult,
    maximum_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Option<u64>, TestModelError> {
    let Ok(mut bytes) = u64::try_from(result.evidence.stderr.len()) else {
        return Ok(None);
    };
    if bytes > maximum_bytes {
        return Ok(None);
    }
    for event in &result.events {
        cancelled(is_cancelled)?;
        let Some(event_bytes) = event_payload_bytes(event) else {
            return Ok(None);
        };
        let Some(total) = bytes.checked_add(event_bytes) else {
            return Ok(None);
        };
        if total > maximum_bytes {
            return Ok(None);
        }
        bytes = total;
    }
    Ok(Some(bytes))
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

fn invalid_guest_outcome(
    outcome: &GuestTestOutcome,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, TestModelError> {
    Ok(match outcome {
        GuestTestOutcome::Passed => false,
        GuestTestOutcome::Failed { message } => !text_has_content(message, is_cancelled)?,
        GuestTestOutcome::TimedOut { timeout_ns } => *timeout_ns == 0,
        GuestTestOutcome::LanguageFatal { .. } => false,
    })
}

fn guest_outcome_matches_case(
    guest: &GuestTestOutcome,
    case: &TestOutcome,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, TestModelError> {
    Ok(match (guest, case) {
        (GuestTestOutcome::Passed, TestOutcome::Passed) => true,
        (
            GuestTestOutcome::Failed { message: guest },
            TestOutcome::Failed {
                phase: FailurePhase::Runtime,
                message: case,
            },
        ) => text_is_equal(guest, case, is_cancelled)?,
        (
            GuestTestOutcome::TimedOut { timeout_ns: guest },
            TestOutcome::TimedOut {
                phase: FailurePhase::Runtime,
                timeout_ns: case,
            },
        ) => guest == case,
        (
            GuestTestOutcome::LanguageFatal { cause: guest },
            TestOutcome::LanguageFatal { cause: case },
        ) => guest == case,
        (
            GuestTestOutcome::Passed
            | GuestTestOutcome::Failed { .. }
            | GuestTestOutcome::TimedOut { .. }
            | GuestTestOutcome::LanguageFatal { .. },
            TestOutcome::Failed { .. }
            | TestOutcome::TimedOut { .. }
            | TestOutcome::Crashed { .. }
            | TestOutcome::Passed
            | TestOutcome::LanguageFatal { .. },
        ) => false,
    })
}

fn invalid_host_outcome(
    outcome: &TestOutcome,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, TestModelError> {
    Ok(match outcome {
        TestOutcome::Passed => false,
        TestOutcome::Failed { message, .. } | TestOutcome::Crashed { message, .. } => {
            !text_has_content(message, is_cancelled)?
        }
        TestOutcome::TimedOut { timeout_ns, .. } => *timeout_ns == 0,
        TestOutcome::LanguageFatal { .. } => false,
    })
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
    use std::cell::Cell;

    use super::*;
    use wrela_build_model::{LanguageRevision, TargetIdentity};
    use wrela_source::{FileId, TextRange};

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
                    assertions: Vec::new(),
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

    fn language_fatal_report(
        plan: &TestPlan,
        digest: Sha256Digest,
        cause: LanguageFatalCause,
    ) -> TestReport {
        let descriptor = plan.image_groups[0].tests[0].descriptor.clone();
        TestReport {
            schema: TEST_REPORT_SCHEMA,
            build: plan.build.clone(),
            started_unix_ns: None,
            duration_ns: Some(3),
            unit: Vec::new(),
            images: vec![ImageGroupResult {
                group: ImageGroupId(0),
                cases: vec![TestCaseResult {
                    descriptor,
                    outcome: TestOutcome::LanguageFatal { cause },
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
                            outcome: GuestTestOutcome::LanguageFatal { cause },
                        },
                    },
                    TestEvent {
                        protocol: TEST_PROTOCOL_VERSION,
                        sequence: 3,
                        kind: TestEventKind::RunFinished {
                            passed: 0,
                            failed: 1,
                        },
                    },
                ],
                evidence: evidence(digest),
                infrastructure_failure: None,
            }],
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
    fn language_fatal_requires_active_test_exact_cause_and_terminal_counts() {
        let (plan, digest) = fixture();
        let validated = plan.clone().seal().expect("valid plan");
        let report =
            language_fatal_report(&plan, digest, LanguageFatalCause::CheckedShiftResultLoss);
        report
            .validate_against(&validated)
            .expect("active test may terminate with an exact typed language fatal");
        assert!(!report.passed());

        let mut wrong_test = report.clone();
        let TestEventKind::TestFinished { test, .. } = &mut wrong_test.images[0].events[2].kind
        else {
            panic!("fatal fixture has TestFinished at sequence two");
        };
        *test = TestId(1);
        assert!(matches!(
            wrong_test.validate_against(&validated),
            Err(TestModelError::InvalidEventStream(_))
        ));

        let mut wrong_cause = report.clone();
        wrong_cause.images[0].cases[0].outcome = TestOutcome::LanguageFatal {
            cause: LanguageFatalCause::InvalidShiftCount,
        };
        assert!(matches!(
            wrong_cause.validate_against(&validated),
            Err(TestModelError::InvalidEventStream(_))
        ));

        let mut wrong_counts = report;
        wrong_counts.images[0].events[3].kind = TestEventKind::RunFinished {
            passed: 1,
            failed: 0,
        };
        assert!(matches!(
            wrong_counts.validate_against(&validated),
            Err(TestModelError::InvalidEventStream(_))
        ));
    }

    #[test]
    fn language_fatal_is_run_terminal_and_never_infrastructure() {
        let (plan, digest) = fixture();
        let validated = plan.clone().seal().expect("valid plan");
        let report = language_fatal_report(&plan, digest, LanguageFatalCause::InvalidShiftCount);

        let mut pass_after_fatal = report.clone();
        pass_after_fatal.images[0].events.insert(
            3,
            TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 3,
                kind: TestEventKind::TestFinished {
                    test: TestId(0),
                    outcome: GuestTestOutcome::Passed,
                },
            },
        );
        pass_after_fatal.images[0].events[4].sequence = 4;
        assert!(matches!(
            pass_after_fatal.validate_against(&validated),
            Err(TestModelError::InvalidEventStream(_))
        ));

        let mut infrastructure = report;
        infrastructure.images[0].infrastructure_failure = Some(TestOutcome::LanguageFatal {
            cause: LanguageFatalCause::InvalidShiftCount,
        });
        assert!(matches!(
            infrastructure.validate_against(&validated),
            Err(TestModelError::ResultSetMismatch(_))
        ));
    }

    #[test]
    fn language_fatal_schema_and_validation_honor_exact_versions_and_late_cancellation() {
        let (plan, digest) = fixture();
        let validated = plan.clone().seal().expect("valid plan");
        let report =
            language_fatal_report(&plan, digest, LanguageFatalCause::CheckedShiftResultLoss);

        for schema in [TEST_REPORT_SCHEMA - 1, TEST_REPORT_SCHEMA + 1] {
            let mut wrong_schema = report.clone();
            wrong_schema.schema = schema;
            assert_eq!(
                wrong_schema.validate_against(&validated),
                Err(TestModelError::UnsupportedReportSchema(schema))
            );
        }

        let calls = Cell::new(0_u64);
        report
            .validate_against_with_cancellation(&validated, &|| {
                calls.set(calls.get().saturating_add(1));
                false
            })
            .expect("typed fatal validation baseline");
        let baseline = calls.get();
        assert!(baseline > 0);
        calls.set(0);
        assert_eq!(
            report.validate_against_with_cancellation(&validated, &|| {
                let next = calls.get().saturating_add(1);
                calls.set(next);
                next >= baseline
            }),
            Err(TestModelError::Cancelled)
        );
        assert_eq!(calls.get(), baseline);
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
    fn compiled_group_rejects_maximum_plus_one_before_scratch_allocation() {
        let (mut plan, _) = fixture();
        let mut group = plan.image_groups.remove(0);
        group.root = ImageRoot::GeneratedHarness {
            harness_name: "generated-tests".to_owned(),
        };
        group.tests[0].descriptor.kind = TestKind::IntegrationImage;
        group.tests[0].descriptor.source = Some(Span {
            file: FileId(0),
            range: TextRange { start: 0, end: 1 },
        });
        group.tests[0].invocation = ImageTestInvocation::GeneratedFunction {
            function_key: FunctionKey(Sha256Digest::from_bytes([1; 32])),
        };
        let mut second = group.tests[0].clone();
        second.descriptor.id = TestId(1);
        second.descriptor.name = "boots-again".to_owned();
        second.invocation = ImageTestInvocation::GeneratedFunction {
            function_key: FunctionKey(Sha256Digest::from_bytes([2; 32])),
        };
        group.tests.push(second);
        group.maximum_events = 6;
        let limits = TestPlanLimits {
            tests: 1,
            ..TestPlanLimits::standard()
        };
        assert_eq!(
            group.validate_compiled_binding_with_limits(limits, &|| false),
            Err(TestModelError::ResourceLimit {
                resource: "compiled test-group tests",
                limit: 1,
            })
        );
    }

    #[test]
    fn compiled_group_seals_exact_bounded_canonical_assertion_descriptors() {
        let (mut plan, _) = fixture();
        let mut group = plan.image_groups.remove(0);
        group.root = ImageRoot::GeneratedHarness {
            harness_name: "generated-tests".to_owned(),
        };
        group.tests[0].descriptor.kind = TestKind::IntegrationImage;
        group.tests[0].descriptor.source = Some(Span {
            file: FileId(0),
            range: TextRange { start: 0, end: 1 },
        });
        group.tests[0].invocation = ImageTestInvocation::GeneratedFunction {
            function_key: FunctionKey(Sha256Digest::from_bytes([1; 32])),
        };
        group.maximum_events = 5;
        group.tests[0].assertions = vec![PlannedAssertionDescriptor {
            source: Span {
                file: FileId(0),
                range: TextRange { start: 0, end: 1 },
            },
            expression: "x".repeat(MAX_PLANNED_ASSERTION_TEXT_BYTES),
            message: Some("bounded".to_owned()),
        }];
        group
            .validate_compiled_binding_with_limits(TestPlanLimits::standard(), &|| false)
            .expect("exact maximum assertion descriptor");
        let exact_payload = group.name.len()
            + "generated-tests".len()
            + group.tests[0].descriptor.name.len()
            + MAX_PLANNED_ASSERTION_TEXT_BYTES
            + "bounded".len();
        let exact_limits = TestPlanLimits {
            payload_bytes: u64::try_from(exact_payload).expect("fixture payload bytes"),
            ..TestPlanLimits::standard()
        };
        group
            .validate_compiled_binding_with_limits(exact_limits, &|| false)
            .expect("exact compiled-group assertion payload bound");
        let one_under = TestPlanLimits {
            payload_bytes: exact_limits.payload_bytes - 1,
            ..exact_limits
        };
        assert_eq!(
            group.validate_compiled_binding_with_limits(one_under, &|| false),
            Err(TestModelError::ResourceLimit {
                resource: "compiled test-group payload bytes",
                limit: one_under.payload_bytes,
            })
        );

        let mut oversized = group.clone();
        oversized.tests[0].assertions[0].expression.push('x');
        assert!(matches!(
            oversized.validate_compiled_binding_with_limits(TestPlanLimits::standard(), &|| false),
            Err(TestModelError::InvalidImageGroup(_))
        ));

        let mut blank_message = group.clone();
        blank_message.tests[0].assertions[0].message = Some(" \t".to_owned());
        assert!(matches!(
            blank_message
                .validate_compiled_binding_with_limits(TestPlanLimits::standard(), &|| false),
            Err(TestModelError::InvalidImageGroup(_))
        ));

        let mut noncanonical = group.clone();
        let mut earlier = noncanonical.tests[0].assertions[0].clone();
        earlier.source.range = TextRange { start: 0, end: 0 };
        noncanonical.tests[0].assertions.push(earlier);
        assert!(matches!(
            noncanonical
                .validate_compiled_binding_with_limits(TestPlanLimits::standard(), &|| false),
            Err(TestModelError::InvalidImageGroup(_))
        ));

        let mut duplicate = group;
        let repeated = duplicate.tests[0].assertions[0].clone();
        duplicate.tests[0].assertions.push(repeated);
        assert!(matches!(
            duplicate.validate_compiled_binding_with_limits(TestPlanLimits::standard(), &|| false),
            Err(TestModelError::InvalidImageGroup(_))
        ));
    }

    #[test]
    fn cancellation_prevents_late_plan_seal_publication() {
        let (plan, _) = fixture();
        let calls = Cell::new(0_u64);
        plan.validate_with_limits_and_cancellation(TestPlanLimits::standard(), &|| {
            calls.set(calls.get() + 1);
            false
        })
        .expect("validation baseline");
        let baseline = calls.get();
        calls.set(0);
        let result = plan.seal_with_limits_and_cancellation(TestPlanLimits::standard(), &|| {
            let next = calls.get() + 1;
            calls.set(next);
            next > baseline
        });
        assert_eq!(result, Err(TestModelError::Cancelled));
        assert!(calls.get() > baseline);
    }

    #[test]
    fn compiled_group_validation_is_cancellable_during_test_scan() {
        let (plan, _) = fixture();
        assert_eq!(
            plan.image_groups[0]
                .validate_compiled_binding_with_limits(TestPlanLimits::standard(), &|| true,),
            Err(TestModelError::Cancelled)
        );
    }

    #[test]
    fn report_event_state_rejects_maximum_plus_one_before_allocation() {
        let (plan, digest) = fixture();
        let mut group = plan.image_groups[0].clone();
        let mut second = group.tests[0].clone();
        second.descriptor.id = TestId(1);
        second.descriptor.name = "second".to_owned();
        group.tests.push(second);
        let result = ImageGroupResult {
            group: group.id,
            cases: Vec::new(),
            events: vec![TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 0,
                kind: TestEventKind::RunStarted { test_count: 2 },
            }],
            evidence: evidence(digest),
            infrastructure_failure: None,
        };
        assert_eq!(
            validate_image_events(&result, &group, 1, 1024, &|| false),
            Err(TestModelError::ResourceLimit {
                resource: "test event state entries",
                limit: 1,
            })
        );
    }

    #[test]
    fn cancellation_prevents_late_report_seal_publication() {
        let (plan, digest) = fixture();
        let validated = plan.clone().seal().expect("valid plan");
        let report = TestReport {
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
        };
        let calls = Cell::new(0_u64);
        report
            .validate_against_with_cancellation(&validated, &|| {
                calls.set(calls.get() + 1);
                false
            })
            .expect("report validation baseline");
        let baseline = calls.get();
        calls.set(0);
        let result = report.seal_against_with_cancellation(&validated, &|| {
            let next = calls.get() + 1;
            calls.set(next);
            next > baseline
        });
        assert_eq!(result, Err(TestModelError::Cancelled));
        assert!(calls.get() > baseline);
    }

    #[test]
    fn cancellable_sort_stops_during_long_merge_scan() {
        let mut values: Vec<_> = (0_u32..4096).rev().collect();
        let calls = Cell::new(0_u64);
        let result = cancellable_sort(&mut values, 4096, "sort test", &|| {
            let next = calls.get() + 1;
            calls.set(next);
            next > 64
        });
        assert_eq!(result, Err(TestModelError::Cancelled));
        assert!(calls.get() > 64);
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
