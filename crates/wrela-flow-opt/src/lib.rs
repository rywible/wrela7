//! Whole-image, semantics-preserving optimization over validated `FlowWir`.

#![forbid(unsafe_code)]

use std::fmt;

use wrela_build_model::{OptimizationLevel, OptimizationPolicy, Sha256Digest};
use wrela_flow_wir::{
    self as flow, FlowWir, ProofId, TestPlanLimits, ValidatedFlowWir, ValidationErrors,
    ValidationFailure, ValidationLimits,
};

mod development;

/// Stable optimization pipeline identity included in cache keys and reports.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PipelineIdentity {
    pub name: String,
    pub revision: u32,
    pub implementation: Sha256Digest,
}

/// Explicit policy for a deterministic optimization invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptimizationProfile {
    pub level: OptimizationLevel,
    pub pipeline: PipelineIdentity,
    pub verify_after_each_pass: bool,
    pub maximum_iterations: u32,
    pub maximum_ir_growth_percent: u32,
}

pub const CANONICAL_PIPELINE_NAME: &str = "canonical-flow-opt-0.1";
pub const CANONICAL_PIPELINE_REVISION: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptimizationLimits {
    pub functions: u32,
    pub tests: u32,
    pub blocks: u64,
    pub instructions: u64,
    pub values: u64,
    pub proofs: u32,
    /// Total elements across all variable-length `FlowWir` collections.
    pub model_edges: u64,
    /// Total retained `FlowWir` UTF-8 and immediate byte payload.
    pub payload_bytes: u64,
    pub passes: u32,
    pub decisions: u64,
    pub report_bytes: u64,
    /// Conservative bound for model/report scanning and comparison work.
    pub work: u64,
    /// Independent bound for structural validation and dominance work.
    pub validation_work: u64,
    /// Maximum output validation errors retained before failing closed.
    pub validation_errors: u32,
    /// Exact policy for a compiled test-group binding retained by optimization.
    pub test_plan: TestPlanLimits,
}

impl OptimizationLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            functions: 1_000_000,
            tests: 1_000_000,
            blocks: 16_000_000,
            instructions: 256_000_000,
            values: 256_000_000,
            proofs: 64_000_000,
            model_edges: 1_000_000_000,
            payload_bytes: 4 * 1024 * 1024 * 1024,
            passes: 1024,
            decisions: 64_000_000,
            report_bytes: 1024 * 1024 * 1024,
            work: 1_100_000_000_000,
            validation_work: 1_100_000_000_000,
            validation_errors: 100_000,
            test_plan: TestPlanLimits::standard(),
        }
    }

    ///
    /// # Errors
    ///
    /// Returns [`OptimizeError::InvalidLimits`] when any limit is zero,
    /// internally inconsistent, or above its hard ceiling.
    pub const fn validate(self) -> Result<(), OptimizeError> {
        let hard = Self::standard();
        if self.functions == 0
            || self.tests == 0
            || self.blocks == 0
            || self.instructions == 0
            || self.values == 0
            || self.proofs == 0
            || self.model_edges == 0
            || self.payload_bytes == 0
            || self.passes == 0
            || self.decisions == 0
            || self.report_bytes == 0
            || self.work == 0
            || self.validation_work == 0
            || self.validation_errors == 0
            || !self.test_plan.is_valid()
            || self.functions > hard.functions
            || self.tests > hard.tests
            || self.blocks > hard.blocks
            || self.instructions > hard.instructions
            || self.values > hard.values
            || self.proofs > hard.proofs
            || self.model_edges > hard.model_edges
            || self.payload_bytes > hard.payload_bytes
            || self.passes > hard.passes
            || self.decisions > hard.decisions
            || self.report_bytes > hard.report_bytes
            || self.work > hard.work
            || self.validation_work > hard.validation_work
            || self.validation_errors > hard.validation_errors
            || !test_plan_limits_within(self.test_plan, hard.test_plan)
        {
            Err(OptimizeError::InvalidLimits)
        } else {
            Ok(())
        }
    }
}

const fn test_plan_limits_within(limits: TestPlanLimits, hard: TestPlanLimits) -> bool {
    limits.tests <= hard.tests
        && limits.groups <= hard.groups
        && limits.scenarios <= hard.scenarios
        && limits.scenario_steps <= hard.scenario_steps
        && limits.payload_bytes <= hard.payload_bytes
        && limits.report_bytes <= hard.report_bytes
        && limits.events_per_group <= hard.events_per_group
        && limits.output_bytes_per_group <= hard.output_bytes_per_group
        && limits.execution_timeout_ns_per_group <= hard.execution_timeout_ns_per_group
}

impl OptimizationProfile {
    /// Construct the exact production pipeline request from the sealed build
    /// policy. The compiler executable digest identifies the implementation
    /// bytes; it is therefore part of reports and cache identity rather than a
    /// fixture constant chosen by an orchestration layer.
    ///
    /// # Errors
    ///
    /// Returns [`OptimizeError::InvalidProfile`] for unsupported profile-guided
    /// input or when the resulting canonical profile is invalid.
    pub fn from_build_policy(
        policy: &OptimizationPolicy,
        compiler_implementation: Sha256Digest,
    ) -> Result<Self, OptimizeError> {
        if policy.profile_data.is_some() {
            return Err(OptimizeError::InvalidProfile(
                "profile-guided optimization input is not implemented",
            ));
        }
        let (maximum_iterations, maximum_ir_growth_percent) = match policy.level {
            OptimizationLevel::None => (1, 0),
            OptimizationLevel::Development => (8, 25),
            OptimizationLevel::Performance => (32, 100),
            OptimizationLevel::Size => (32, 0),
        };
        let profile = Self {
            level: policy.level,
            pipeline: PipelineIdentity {
                name: canonical_pipeline_name()?,
                revision: CANONICAL_PIPELINE_REVISION,
                implementation: compiler_implementation,
            },
            verify_after_each_pass: true,
            maximum_iterations,
            maximum_ir_growth_percent,
        };
        validate_canonical_profile(&profile)?;
        Ok(profile)
    }

    /// Validate the bounded shape of this profile.
    ///
    /// # Errors
    ///
    /// Returns [`OptimizeError::InvalidProfile`] when a field is empty, zero,
    /// or above its hard ceiling.
    pub fn validate(&self) -> Result<(), OptimizeError> {
        if self.pipeline.name.len() > 4096 {
            return Err(OptimizeError::InvalidProfile(
                "pipeline name exceeds the hard ceiling",
            ));
        }
        if self.pipeline.name.trim().is_empty() {
            return Err(OptimizeError::InvalidProfile("pipeline name is empty"));
        }
        if self.pipeline.revision == 0 {
            return Err(OptimizeError::InvalidProfile(
                "pipeline revision must be nonzero",
            ));
        }
        if self
            .pipeline
            .implementation
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        {
            return Err(OptimizeError::InvalidProfile(
                "pipeline implementation digest is zero",
            ));
        }
        if self.maximum_iterations == 0 || self.maximum_iterations > 1_000_000 {
            return Err(OptimizeError::InvalidProfile(
                "maximum iterations must be nonzero",
            ));
        }
        if self.maximum_ir_growth_percent > 10_000 {
            return Err(OptimizeError::InvalidProfile(
                "maximum IR growth percent exceeds the hard ceiling",
            ));
        }
        Ok(())
    }
}

fn canonical_pipeline_name() -> Result<String, OptimizeError> {
    let mut name = String::new();
    name.try_reserve_exact(CANONICAL_PIPELINE_NAME.len())
        .map_err(|_| OptimizeError::ResourceLimit {
            resource: "optimization pipeline name bytes",
            limit: 4096,
        })?;
    name.push_str(CANONICAL_PIPELINE_NAME);
    Ok(name)
}

pub(crate) fn validate_canonical_profile(
    profile: &OptimizationProfile,
) -> Result<(), OptimizeError> {
    profile.validate()?;
    if profile.pipeline.name != CANONICAL_PIPELINE_NAME
        || profile.pipeline.revision != CANONICAL_PIPELINE_REVISION
    {
        return Err(OptimizeError::InvalidProfile(
            "optimization requires the canonical pipeline identity",
        ));
    }
    let (maximum_iterations, maximum_ir_growth_percent) = match profile.level {
        OptimizationLevel::None => (1, 0),
        OptimizationLevel::Development => (8, 25),
        OptimizationLevel::Performance => (32, 100),
        OptimizationLevel::Size => (32, 0),
    };
    if !profile.verify_after_each_pass
        || profile.maximum_iterations != maximum_iterations
        || profile.maximum_ir_growth_percent != maximum_ir_growth_percent
    {
        return Err(OptimizeError::InvalidProfile(
            "optimization policy parameters are noncanonical",
        ));
    }
    Ok(())
}

/// Immutable optimizer input.
#[derive(Debug)]
pub struct OptimizationRequest {
    pub input: ValidatedFlowWir,
    pub profile: OptimizationProfile,
    pub limits: OptimizationLimits,
}

/// Why an observable operation was changed or deliberately retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DecisionKind {
    Removed,
    Folded,
    Inlined,
    Coalesced,
    Reordered,
    Retained,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptimizationDecision {
    pub pass: String,
    pub subject: String,
    pub kind: DecisionKind,
    pub justification: String,
    pub relied_on: Vec<ProofId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassStatistics {
    pub pass: String,
    pub iterations: u32,
    pub changed: bool,
    pub instructions_before: u64,
    pub instructions_after: u64,
    /// Dense local test entries observed before and after this pass.
    pub test_entries_before: u32,
    pub test_entries_after: u32,
    /// True only when the original table object was retained exactly while
    /// function bodies were transformed and its function-role links rechecked.
    pub test_table_preserved: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptimizationReport {
    /// Exact requested policy, including verification and resource ceilings.
    /// Keeping it in the sealed output prevents report assembly from guessing
    /// which invocation produced the optimized IR.
    pub profile: OptimizationProfile,
    pub passes: Vec<PassStatistics>,
    pub decisions: Vec<OptimizationDecision>,
}

/// Sealed optimizer output. Machine lowering cannot accidentally consume an
/// unoptimized or unverified `FlowWir` value.
#[derive(Debug, Clone, PartialEq)]
pub struct OptimizedFlowWir {
    wir: ValidatedFlowWir,
    report: OptimizationReport,
}

impl OptimizedFlowWir {
    #[must_use]
    pub const fn wir(&self) -> &ValidatedFlowWir {
        &self.wir
    }

    #[must_use]
    pub const fn report(&self) -> &OptimizationReport {
        &self.report
    }

    #[must_use]
    pub fn into_parts(self) -> (ValidatedFlowWir, OptimizationReport) {
        (self.wir, self.report)
    }
}

pub trait FlowOptimizer {
    /// Optimize and seal one validated whole-image model.
    ///
    /// # Errors
    ///
    /// Returns [`OptimizeError`] when the request is invalid, exceeds a
    /// resource bound, is cancelled, or cannot preserve its proof contract.
    fn optimize(
        &self,
        request: OptimizationRequest,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<OptimizedFlowWir, OptimizeError>;
}

/// Production revision-0.1 optimizer.
///
/// `None` transfers the validated input exactly. Every transforming profile
/// runs a canonical deterministic scalar/control-flow pipeline; Performance
/// and Size additionally remove checks whose condition is canonically true.
/// Size forbids all IR growth while Performance retains its declared growth
/// budget for future proof-preserving transforms.
#[derive(Debug, Clone, Copy, Default)]
pub struct CanonicalFlowOptimizer;

impl CanonicalFlowOptimizer {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl FlowOptimizer for CanonicalFlowOptimizer {
    fn optimize(
        &self,
        request: OptimizationRequest,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<OptimizedFlowWir, OptimizeError> {
        match request.profile.level {
            OptimizationLevel::None => seal_preserved_input(request, is_cancelled),
            OptimizationLevel::Development
            | OptimizationLevel::Performance
            | OptimizationLevel::Size => development::optimize(request, is_cancelled),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptimizeError {
    Cancelled,
    UnsupportedOptimizationLevel(OptimizationLevel),
    InvalidProfile(&'static str),
    InvalidLimits,
    ResourceLimit { resource: &'static str, limit: u64 },
    InvalidReport(&'static str),
    InvalidOutput(ValidationErrors),
    ProofViolation { pass: String, detail: String },
}

impl fmt::Display for OptimizeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("FlowWir optimization was cancelled"),
            Self::UnsupportedOptimizationLevel(level) => {
                write!(
                    formatter,
                    "unsupported FlowWir optimization level: {level:?}"
                )
            }
            Self::InvalidProfile(reason) => {
                write!(formatter, "invalid optimization profile: {reason}")
            }
            Self::InvalidLimits => {
                formatter.write_str("optimization limits must be nonzero and within hard ceilings")
            }
            Self::ResourceLimit { resource, limit } => {
                write!(
                    formatter,
                    "FlowWir optimization exceeded {resource} limit {limit}"
                )
            }
            Self::InvalidReport(reason) => {
                write!(formatter, "invalid optimization report: {reason}")
            }
            Self::InvalidOutput(error) => error.fmt(formatter),
            Self::ProofViolation { pass, detail } => {
                write!(
                    formatter,
                    "optimization pass {pass} violated a proof obligation: {detail}"
                )
            }
        }
    }
}

impl std::error::Error for OptimizeError {}

pub(crate) fn flow_validation_limits(limits: OptimizationLimits) -> ValidationLimits {
    ValidationLimits {
        arena_records: limits.model_edges.min(u64::from(u32::MAX)),
        model_edges: limits.model_edges,
        payload_bytes: limits.payload_bytes,
        validation_work: limits.validation_work,
        errors: limits.validation_errors,
        test_plan: limits.test_plan,
    }
}

pub(crate) fn map_validation_failure(error: ValidationFailure) -> OptimizeError {
    match error {
        ValidationFailure::InvalidLimits => OptimizeError::InvalidLimits,
        ValidationFailure::Cancelled => OptimizeError::Cancelled,
        ValidationFailure::ResourceLimit { resource, limit } => {
            OptimizeError::ResourceLimit { resource, limit }
        }
        ValidationFailure::Invalid(errors) => OptimizeError::InvalidOutput(errors),
    }
}

/// Seal project-controlled output for a supported canonical pipeline.
///
/// The request is consumed so the result can retain the original validated
/// input after independently proving that the supplied output is identical.
/// This avoids revalidating malformed output through `FlowWir`'s allocation-heavy
/// diagnostic path and prevents input substitution.
///
/// # Errors
///
/// Returns [`OptimizeError`] when the request or candidate violates the exact
/// canonical pipeline, a resource limit, cancellation, or validation contract.
pub fn seal(
    request: OptimizationRequest,
    wir: FlowWir,
    report: OptimizationReport,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<OptimizedFlowWir, OptimizeError> {
    if request.profile.level != OptimizationLevel::None {
        return development::seal(request, &wir, &report, is_cancelled);
    }
    check_cancelled(is_cancelled)?;
    validate_canonical_profile(&request.profile)?;
    request.limits.validate()?;

    let mut work = WorkMeter::new(request.limits.work, is_cancelled);
    work.checkpoint()?;
    let input_resources = scan_model(request.input.as_wir(), request.limits, &mut work)?;
    work.checkpoint()?;
    scan_model(&wir, request.limits, &mut work)?;
    work.checkpoint()?;
    let report_scan_work = scan_report(&report, request.limits, &mut work)?;
    // The report scan charges every retained byte and edge, which is a
    // conservative upper bound for the streaming exact comparison below.
    work.charge(report_scan_work)?;
    validate_none_report(&report, &request.profile, &mut work)?;

    // Equality is bounded before it runs by charging the same conservative
    // work measured while scanning the validated input.
    work.charge(input_resources.scan_work)?;
    work.checkpoint()?;
    if !flow_wir_equal(request.input.as_wir(), &wir, &mut work)? {
        return Err(OptimizeError::InvalidReport(
            "optimization level `none` did not preserve FlowWir exactly",
        ));
    }
    work.checkpoint()?;
    drop(wir);

    let OptimizationRequest { input, .. } = request;
    Ok(OptimizedFlowWir { report, wir: input })
}

fn seal_preserved_input(
    request: OptimizationRequest,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<OptimizedFlowWir, OptimizeError> {
    check_cancelled(is_cancelled)?;
    validate_canonical_profile(&request.profile)?;
    request.limits.validate()?;

    let OptimizationRequest {
        input,
        profile,
        limits,
    } = request;
    let mut work = WorkMeter::new(limits.work, is_cancelled);
    work.checkpoint()?;
    scan_model(input.as_wir(), limits, &mut work)?;
    work.checkpoint()?;
    let report = OptimizationReport {
        profile,
        passes: Vec::new(),
        decisions: Vec::new(),
    };
    scan_report(&report, limits, &mut work)?;
    work.checkpoint()?;
    Ok(OptimizedFlowWir { wir: input, report })
}

fn validate_none_report(
    report: &OptimizationReport,
    profile: &OptimizationProfile,
    work: &mut WorkMeter<'_>,
) -> Result<(), OptimizeError> {
    if !optimization_profile_equal(&report.profile, profile, work)? {
        return Err(OptimizeError::InvalidReport(
            "optimization profile does not match request",
        ));
    }
    if !report.passes.is_empty() || !report.decisions.is_empty() {
        return Err(OptimizeError::InvalidReport(
            "optimization level `none` requires an empty canonical pass report",
        ));
    }
    Ok(())
}

fn check_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), OptimizeError> {
    if is_cancelled() {
        Err(OptimizeError::Cancelled)
    } else {
        Ok(())
    }
}

struct WorkMeter<'a> {
    used: u64,
    limit: u64,
    is_cancelled: &'a dyn Fn() -> bool,
}

impl<'a> WorkMeter<'a> {
    fn new(limit: u64, is_cancelled: &'a dyn Fn() -> bool) -> Self {
        Self {
            used: 0,
            limit,
            is_cancelled,
        }
    }

    fn checkpoint(&mut self) -> Result<(), OptimizeError> {
        check_cancelled(self.is_cancelled)?;
        self.charge(1)
    }

    fn poll(&self) -> Result<(), OptimizeError> {
        check_cancelled(self.is_cancelled)
    }

    fn charge(&mut self, amount: u64) -> Result<(), OptimizeError> {
        add_bounded(&mut self.used, amount, "optimizer work", self.limit)
    }
}

const CANCELLABLE_COMPARISON_CHUNK_BYTES: usize = 64 * 1024;

fn sequence_equal<T>(
    left: &[T],
    right: &[T],
    work: &mut WorkMeter<'_>,
    mut element_equal: impl FnMut(&T, &T, &mut WorkMeter<'_>) -> Result<bool, OptimizeError>,
) -> Result<bool, OptimizeError> {
    work.poll()?;
    if left.len() != right.len() {
        return Ok(false);
    }
    for (left, right) in left.iter().zip(right) {
        work.poll()?;
        if !element_equal(left, right, work)? {
            return Ok(false);
        }
    }
    work.poll()?;
    Ok(true)
}

fn fixed_sequence_equal<T: PartialEq>(
    left: &[T],
    right: &[T],
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    sequence_equal(left, right, work, |left, right, _| Ok(left == right))
}

fn bytes_equal(left: &[u8], right: &[u8], work: &mut WorkMeter<'_>) -> Result<bool, OptimizeError> {
    work.poll()?;
    if left.len() != right.len() {
        return Ok(false);
    }
    for (left, right) in left
        .chunks(CANCELLABLE_COMPARISON_CHUNK_BYTES)
        .zip(right.chunks(CANCELLABLE_COMPARISON_CHUNK_BYTES))
    {
        work.poll()?;
        if left != right {
            return Ok(false);
        }
    }
    work.poll()?;
    Ok(true)
}

fn text_equal(left: &str, right: &str, work: &mut WorkMeter<'_>) -> Result<bool, OptimizeError> {
    bytes_equal(left.as_bytes(), right.as_bytes(), work)
}

fn optional_text_equal(
    left: Option<&str>,
    right: Option<&str>,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    work.poll()?;
    match (left, right) {
        (Some(left), Some(right)) => text_equal(left, right, work),
        (None, None) => Ok(true),
        (Some(_), None) | (None, Some(_)) => Ok(false),
    }
}

fn build_identity_equal(
    left: &wrela_build_model::BuildIdentity,
    right: &wrela_build_model::BuildIdentity,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    work.poll()?;
    Ok(left.compiler == right.compiler
        && left.language == right.language
        && text_equal(left.target.as_str(), right.target.as_str(), work)?
        && left.target_package == right.target_package
        && left.standard_library == right.standard_library
        && left.source_graph == right.source_graph
        && left.request == right.request
        && left.profile == right.profile)
}

fn type_kind_equal(
    left: &flow::FlowTypeKind,
    right: &flow::FlowTypeKind,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    work.poll()?;
    match (left, right) {
        (flow::FlowTypeKind::Tuple(left), flow::FlowTypeKind::Tuple(right))
        | (
            flow::FlowTypeKind::Struct { fields: left },
            flow::FlowTypeKind::Struct { fields: right },
        ) => fixed_sequence_equal(left, right, work),
        (
            flow::FlowTypeKind::Enum { variants: left },
            flow::FlowTypeKind::Enum { variants: right },
        ) => sequence_equal(left, right, work, |left, right, work| {
            fixed_sequence_equal(left, right, work)
        }),
        (
            flow::FlowTypeKind::Function {
                parameters: left_parameters,
                result: left_result,
            },
            flow::FlowTypeKind::Function {
                parameters: right_parameters,
                result: right_result,
            },
        ) => Ok(left_result == right_result
            && fixed_sequence_equal(left_parameters, right_parameters, work)?),
        (
            flow::FlowTypeKind::OpaqueTarget { name: left },
            flow::FlowTypeKind::OpaqueTarget { name: right },
        ) => text_equal(left, right, work),
        _ => Ok(left == right),
    }
}

fn flow_type_equal(
    left: &flow::FlowType,
    right: &flow::FlowType,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    work.poll()?;
    Ok(left.id == right.id
        && type_kind_equal(&left.kind, &right.kind, work)?
        && optional_text_equal(left.name.as_deref(), right.name.as_deref(), work)?
        && left.copyable == right.copyable
        && left.strict_linear == right.strict_linear)
}

fn immediate_equal(
    left: &flow::Immediate,
    right: &flow::Immediate,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    work.poll()?;
    match (left, right) {
        (
            flow::Immediate::Integer {
                bits: left_bits,
                bytes_le: left,
            },
            flow::Immediate::Integer {
                bits: right_bits,
                bytes_le: right,
            },
        ) => Ok(left_bits == right_bits && bytes_equal(left, right, work)?),
        (flow::Immediate::Bytes(left), flow::Immediate::Bytes(right)) => {
            bytes_equal(left, right, work)
        }
        _ => Ok(left == right),
    }
}

fn operation_equal(
    left: &flow::FlowOperation,
    right: &flow::FlowOperation,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    work.poll()?;
    match (left, right) {
        (flow::FlowOperation::Immediate(left), flow::FlowOperation::Immediate(right)) => {
            immediate_equal(left, right, work)
        }
        (
            flow::FlowOperation::MakeAggregate {
                ty: left_ty,
                fields: left,
            },
            flow::FlowOperation::MakeAggregate {
                ty: right_ty,
                fields: right,
            },
        ) => Ok(left_ty == right_ty && fixed_sequence_equal(left, right, work)?),
        (
            flow::FlowOperation::Call {
                function: left_function,
                arguments: left,
            },
            flow::FlowOperation::Call {
                function: right_function,
                arguments: right,
            },
        ) => Ok(left_function == right_function && fixed_sequence_equal(left, right, work)?),
        (
            flow::FlowOperation::AsyncCall {
                function: left_function,
                arguments: left,
                plan: left_plan,
            },
            flow::FlowOperation::AsyncCall {
                function: right_function,
                arguments: right,
                plan: right_plan,
            },
        ) => Ok(left_function == right_function
            && left_plan == right_plan
            && fixed_sequence_equal(left, right, work)?),
        (
            flow::FlowOperation::TaskStart {
                slot: left_slot,
                entry: left_entry,
                arguments: left,
            },
            flow::FlowOperation::TaskStart {
                slot: right_slot,
                entry: right_entry,
                arguments: right,
            },
        ) => Ok(left_slot == right_slot
            && left_entry == right_entry
            && fixed_sequence_equal(left, right, work)?),
        _ => Ok(left == right),
    }
}

fn instruction_equal(
    left: &flow::Instruction,
    right: &flow::Instruction,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    work.poll()?;
    Ok(left.id == right.id
        && fixed_sequence_equal(&left.results, &right.results, work)?
        && operation_equal(&left.operation, &right.operation, work)?
        && left.source == right.source)
}

fn switch_case_equal(
    left: &flow::SwitchCase,
    right: &flow::SwitchCase,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    work.poll()?;
    Ok(left.value == right.value
        && left.target == right.target
        && fixed_sequence_equal(&left.arguments, &right.arguments, work)?)
}

fn terminator_equal(
    left: &flow::Terminator,
    right: &flow::Terminator,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    work.poll()?;
    match (left, right) {
        (
            flow::Terminator::Jump {
                target: left_target,
                arguments: left,
            },
            flow::Terminator::Jump {
                target: right_target,
                arguments: right,
            },
        ) => Ok(left_target == right_target && fixed_sequence_equal(left, right, work)?),
        (
            flow::Terminator::Branch {
                condition: left_condition,
                then_block: left_then,
                then_arguments: left_then_arguments,
                else_block: left_else,
                else_arguments: left_else_arguments,
            },
            flow::Terminator::Branch {
                condition: right_condition,
                then_block: right_then,
                then_arguments: right_then_arguments,
                else_block: right_else,
                else_arguments: right_else_arguments,
            },
        ) => Ok(left_condition == right_condition
            && left_then == right_then
            && left_else == right_else
            && fixed_sequence_equal(left_then_arguments, right_then_arguments, work)?
            && fixed_sequence_equal(left_else_arguments, right_else_arguments, work)?),
        (
            flow::Terminator::Switch {
                value: left_value,
                cases: left_cases,
                default: left_default,
                default_arguments: left_arguments,
            },
            flow::Terminator::Switch {
                value: right_value,
                cases: right_cases,
                default: right_default,
                default_arguments: right_arguments,
            },
        ) => Ok(left_value == right_value
            && left_default == right_default
            && sequence_equal(left_cases, right_cases, work, switch_case_equal)?
            && fixed_sequence_equal(left_arguments, right_arguments, work)?),
        (flow::Terminator::Return(left), flow::Terminator::Return(right)) => {
            fixed_sequence_equal(left, right, work)
        }
        (
            flow::Terminator::TailCall {
                function: left_function,
                arguments: left,
            },
            flow::Terminator::TailCall {
                function: right_function,
                arguments: right,
            },
        ) => Ok(left_function == right_function && fixed_sequence_equal(left, right, work)?),
        _ => Ok(left == right),
    }
}

fn block_equal(
    left: &flow::Block,
    right: &flow::Block,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    work.poll()?;
    Ok(left.id == right.id
        && fixed_sequence_equal(&left.parameters, &right.parameters, work)?
        && sequence_equal(
            &left.instructions,
            &right.instructions,
            work,
            instruction_equal,
        )?
        && terminator_equal(&left.terminator, &right.terminator, work)?
        && left.source == right.source)
}

fn value_equal(
    left: &flow::Value,
    right: &flow::Value,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    work.poll()?;
    Ok(left.id == right.id
        && left.ty == right.ty
        && optional_text_equal(
            left.source_name.as_deref(),
            right.source_name.as_deref(),
            work,
        )?
        && left.source == right.source)
}

fn function_equal(
    left: &flow::FlowFunction,
    right: &flow::FlowFunction,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    work.poll()?;
    Ok(left.id == right.id
        && text_equal(&left.name, &right.name, work)?
        && left.origin == right.origin
        && left.role == right.role
        && left.color == right.color
        && fixed_sequence_equal(&left.parameters, &right.parameters, work)?
        && fixed_sequence_equal(&left.result_types, &right.result_types, work)?
        && sequence_equal(&left.values, &right.values, work, value_equal)?
        && sequence_equal(&left.blocks, &right.blocks, work, block_equal)?
        && left.entry == right.entry
        && left.stack_bound == right.stack_bound
        && left.frame_bound == right.frame_bound
        && fixed_sequence_equal(&left.proofs, &right.proofs, work)?
        && left.source == right.source)
}

fn global_equal(
    left: &flow::FlowGlobal,
    right: &flow::FlowGlobal,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    work.poll()?;
    Ok(left.id == right.id
        && text_equal(&left.name, &right.name, work)?
        && left.ty == right.ty
        && immediate_equal(&left.initializer, &right.initializer, work)?
        && left.mutable == right.mutable
        && left.owner == right.owner)
}

fn actor_equal(
    left: &flow::ActorPlan,
    right: &flow::ActorPlan,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    work.poll()?;
    Ok(left.id == right.id
        && text_equal(&left.name, &right.name, work)?
        && left.state_type == right.state_type
        && left.mailbox_capacity == right.mailbox_capacity
        && fixed_sequence_equal(&left.message_types, &right.message_types, work)?
        && fixed_sequence_equal(&left.turn_functions, &right.turn_functions, work)?
        && left.priority == right.priority
        && left.supervisor == right.supervisor)
}

fn task_equal(
    left: &flow::TaskPlan,
    right: &flow::TaskPlan,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    work.poll()?;
    Ok(left.id == right.id
        && text_equal(&left.name, &right.name, work)?
        && left.entry == right.entry
        && left.slots == right.slots
        && left.priority == right.priority
        && left.frame_bytes_bound == right.frame_bytes_bound
        && left.supervisor == right.supervisor)
}

fn string_sequence_equal(
    left: &[String],
    right: &[String],
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    sequence_equal(left, right, work, |left, right, work| {
        text_equal(left, right, work)
    })
}

fn device_equal(
    left: &flow::DevicePlan,
    right: &flow::DevicePlan,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    work.poll()?;
    Ok(left.id == right.id
        && text_equal(&left.name, &right.name, work)?
        && text_equal(&left.target_binding, &right.target_binding, work)?
        && left.owner == right.owner
        && left.queue_capacity == right.queue_capacity
        && left.maximum_in_flight == right.maximum_in_flight
        && string_sequence_equal(&left.required_features, &right.required_features, work)?
        && string_sequence_equal(&left.optional_features, &right.optional_features, work)?
        && fixed_sequence_equal(&left.interrupt_functions, &right.interrupt_functions, work)?
        && left.reset_timeout_ns == right.reset_timeout_ns)
}

fn pool_equal(
    left: &flow::PoolPlan,
    right: &flow::PoolPlan,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    work.poll()?;
    Ok(left.id == right.id
        && text_equal(&left.name, &right.name, work)?
        && left.element_type == right.element_type
        && left.capacity == right.capacity
        && left.alignment == right.alignment
        && fixed_sequence_equal(&left.devices, &right.devices, work)?)
}

fn region_equal(
    left: &flow::RegionPlan,
    right: &flow::RegionPlan,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    work.poll()?;
    Ok(left.id == right.id
        && text_equal(&left.name, &right.name, work)?
        && left.class == right.class
        && left.capacity_bytes == right.capacity_bytes
        && left.alignment == right.alignment
        && left.reset_function == right.reset_function
        && left.owner == right.owner
        && left.capacity_proof == right.capacity_proof
        && left.source == right.source)
}

fn proof_equal(
    left: &flow::Proof,
    right: &flow::Proof,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    work.poll()?;
    Ok(left.id == right.id
        && left.kind == right.kind
        && text_equal(&left.subject, &right.subject, work)?
        && fixed_sequence_equal(&left.sources, &right.sources, work)?
        && fixed_sequence_equal(&left.depends_on, &right.depends_on, work)?
        && left.bound == right.bound
        && string_sequence_equal(&left.explanation, &right.explanation, work)?)
}

fn test_entry_equal(
    left: &flow::TestEntry,
    right: &flow::TestEntry,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    work.poll()?;
    Ok(left.id == right.id
        && left.plan_id == right.plan_id
        && left.function_key == right.function_key
        && text_equal(&left.name, &right.name, work)?
        && left.function == right.function
        && left.kind == right.kind
        && left.source == right.source
        && left.timeout_ns == right.timeout_ns)
}

fn test_descriptor_equal(
    left: &wrela_test_model::TestDescriptor,
    right: &wrela_test_model::TestDescriptor,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    work.poll()?;
    Ok(left.id == right.id
        && text_equal(&left.name, &right.name, work)?
        && left.kind == right.kind
        && left.source == right.source
        && left.timeout_ns == right.timeout_ns)
}

fn image_test_equal(
    left: &wrela_test_model::ImageTest,
    right: &wrela_test_model::ImageTest,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    work.poll()?;
    Ok(
        test_descriptor_equal(&left.descriptor, &right.descriptor, work)?
            && left.invocation == right.invocation,
    )
}

fn image_root_equal(
    left: &wrela_test_model::ImageRoot,
    right: &wrela_test_model::ImageRoot,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    work.poll()?;
    match (left, right) {
        (
            wrela_test_model::ImageRoot::GeneratedHarness { harness_name: left },
            wrela_test_model::ImageRoot::GeneratedHarness {
                harness_name: right,
            },
        ) => text_equal(left, right, work),
        (
            wrela_test_model::ImageRoot::Declared {
                image_name: left,
                scenario: left_scenario,
            },
            wrela_test_model::ImageRoot::Declared {
                image_name: right,
                scenario: right_scenario,
            },
        ) => Ok(left_scenario == right_scenario && text_equal(left, right, work)?),
        _ => Ok(false),
    }
}

fn compiled_test_group_equal(
    left: &wrela_test_model::FullImageTestGroup,
    right: &wrela_test_model::FullImageTestGroup,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    work.poll()?;
    Ok(left.id == right.id
        && text_equal(&left.name, &right.name, work)?
        && image_root_equal(&left.root, &right.root, work)?
        && sequence_equal(&left.tests, &right.tests, work, image_test_equal)?
        && left.deterministic_seed == right.deterministic_seed
        && left.boot_timeout_ns == right.boot_timeout_ns
        && left.shutdown_timeout_ns == right.shutdown_timeout_ns
        && left.maximum_events == right.maximum_events
        && left.maximum_output_bytes == right.maximum_output_bytes)
}

fn optional_compiled_test_group_equal(
    left: Option<&wrela_test_model::FullImageTestGroup>,
    right: Option<&wrela_test_model::FullImageTestGroup>,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    work.poll()?;
    match (left, right) {
        (Some(left), Some(right)) => compiled_test_group_equal(left, right, work),
        (None, None) => Ok(true),
        (Some(_), None) | (None, Some(_)) => Ok(false),
    }
}

pub(crate) fn flow_wir_equal(
    left: &FlowWir,
    right: &FlowWir,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    work.poll()?;
    Ok(left.version == right.version
        && text_equal(&left.name, &right.name, work)?
        && build_identity_equal(&left.build, &right.build, work)?
        && left.source_summary == right.source_summary
        && sequence_equal(&left.types, &right.types, work, flow_type_equal)?
        && sequence_equal(&left.globals, &right.globals, work, global_equal)?
        && sequence_equal(&left.functions, &right.functions, work, function_equal)?
        && sequence_equal(&left.actors, &right.actors, work, actor_equal)?
        && sequence_equal(&left.tasks, &right.tasks, work, task_equal)?
        && sequence_equal(&left.devices, &right.devices, work, device_equal)?
        && sequence_equal(&left.pools, &right.pools, work, pool_equal)?
        && sequence_equal(&left.regions, &right.regions, work, region_equal)?
        && fixed_sequence_equal(&left.activations, &right.activations, work)?
        && sequence_equal(&left.proofs, &right.proofs, work, proof_equal)?
        && fixed_sequence_equal(&left.checkpoints, &right.checkpoints, work)?
        && sequence_equal(&left.tests, &right.tests, work, test_entry_equal)?
        && optional_compiled_test_group_equal(
            left.compiled_test_group.as_ref(),
            right.compiled_test_group.as_ref(),
            work,
        )?
        && fixed_sequence_equal(&left.startup_order, &right.startup_order, work)?
        && fixed_sequence_equal(&left.shutdown_order, &right.shutdown_order, work)?
        && left.image_entry == right.image_entry
        && left.static_bytes == right.static_bytes
        && left.peak_bytes == right.peak_bytes)
}

fn optimization_profile_equal(
    left: &OptimizationProfile,
    right: &OptimizationProfile,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    work.poll()?;
    Ok(left.level == right.level
        && text_equal(&left.pipeline.name, &right.pipeline.name, work)?
        && left.pipeline.revision == right.pipeline.revision
        && left.pipeline.implementation == right.pipeline.implementation
        && left.verify_after_each_pass == right.verify_after_each_pass
        && left.maximum_iterations == right.maximum_iterations
        && left.maximum_ir_growth_percent == right.maximum_ir_growth_percent)
}

fn pass_statistics_equal(
    left: &PassStatistics,
    right: &PassStatistics,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    work.poll()?;
    Ok(text_equal(&left.pass, &right.pass, work)?
        && left.iterations == right.iterations
        && left.changed == right.changed
        && left.instructions_before == right.instructions_before
        && left.instructions_after == right.instructions_after
        && left.test_entries_before == right.test_entries_before
        && left.test_entries_after == right.test_entries_after
        && left.test_table_preserved == right.test_table_preserved)
}

fn optimization_decision_equal(
    left: &OptimizationDecision,
    right: &OptimizationDecision,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    work.poll()?;
    Ok(text_equal(&left.pass, &right.pass, work)?
        && text_equal(&left.subject, &right.subject, work)?
        && left.kind == right.kind
        && text_equal(&left.justification, &right.justification, work)?
        && fixed_sequence_equal(&left.relied_on, &right.relied_on, work)?)
}

pub(crate) fn optimization_report_equal(
    left: &OptimizationReport,
    right: &OptimizationReport,
    work: &mut WorkMeter<'_>,
) -> Result<bool, OptimizeError> {
    work.poll()?;
    Ok(
        optimization_profile_equal(&left.profile, &right.profile, work)?
            && sequence_equal(&left.passes, &right.passes, work, pass_statistics_equal)?
            && sequence_equal(
                &left.decisions,
                &right.decisions,
                work,
                optimization_decision_equal,
            )?,
    )
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ModelResources {
    functions: u64,
    tests: u64,
    blocks: u64,
    instructions: u64,
    values: u64,
    proofs: u64,
    model_edges: u64,
    payload_bytes: u64,
    scan_work: u64,
}

struct ModelMeter<'a, 'cancel> {
    resources: ModelResources,
    limits: OptimizationLimits,
    work: &'a mut WorkMeter<'cancel>,
}

impl ModelMeter<'_, '_> {
    fn visit(&mut self) -> Result<(), OptimizeError> {
        self.resources.scan_work =
            self.resources
                .scan_work
                .checked_add(1)
                .ok_or(OptimizeError::ResourceLimit {
                    resource: "optimizer work",
                    limit: self.limits.work,
                })?;
        self.work.checkpoint()
    }

    fn collection(&mut self, length: usize) -> Result<(), OptimizeError> {
        let length = length_as_u64(length, "FlowWir model edges", self.limits.model_edges)?;
        add_bounded(
            &mut self.resources.model_edges,
            length,
            "FlowWir model edges",
            self.limits.model_edges,
        )?;
        self.resources.scan_work =
            self.resources
                .scan_work
                .checked_add(length)
                .ok_or(OptimizeError::ResourceLimit {
                    resource: "optimizer work",
                    limit: self.limits.work,
                })?;
        self.work.charge(length)?;
        self.work.checkpoint()
    }

    fn payload(&mut self, length: usize) -> Result<(), OptimizeError> {
        let length = length_as_u64(length, "FlowWir payload bytes", self.limits.payload_bytes)?;
        add_bounded(
            &mut self.resources.payload_bytes,
            length,
            "FlowWir payload bytes",
            self.limits.payload_bytes,
        )?;
        self.resources.scan_work =
            self.resources
                .scan_work
                .checked_add(length)
                .ok_or(OptimizeError::ResourceLimit {
                    resource: "optimizer work",
                    limit: self.limits.work,
                })?;
        self.work.charge(length)?;
        self.work.checkpoint()
    }

    fn functions(&mut self, length: usize) -> Result<(), OptimizeError> {
        self.resources.functions = length_as_u64(
            length,
            "FlowWir functions",
            u64::from(self.limits.functions),
        )?;
        ensure_limit(
            self.resources.functions,
            "FlowWir functions",
            u64::from(self.limits.functions),
        )
    }

    fn proofs(&mut self, length: usize) -> Result<(), OptimizeError> {
        self.resources.proofs =
            length_as_u64(length, "FlowWir proofs", u64::from(self.limits.proofs))?;
        ensure_limit(
            self.resources.proofs,
            "FlowWir proofs",
            u64::from(self.limits.proofs),
        )
    }

    fn tests(&mut self, length: usize) -> Result<(), OptimizeError> {
        self.resources.tests =
            length_as_u64(length, "FlowWir tests", u64::from(self.limits.tests))?;
        ensure_limit(
            self.resources.tests,
            "FlowWir tests",
            u64::from(self.limits.tests),
        )
    }

    fn add_blocks(&mut self, length: usize) -> Result<(), OptimizeError> {
        let length = length_as_u64(length, "FlowWir blocks", self.limits.blocks)?;
        add_bounded(
            &mut self.resources.blocks,
            length,
            "FlowWir blocks",
            self.limits.blocks,
        )
    }

    fn add_instructions(&mut self, length: usize) -> Result<(), OptimizeError> {
        let length = length_as_u64(length, "FlowWir instructions", self.limits.instructions)?;
        add_bounded(
            &mut self.resources.instructions,
            length,
            "FlowWir instructions",
            self.limits.instructions,
        )
    }

    fn add_values(&mut self, length: usize) -> Result<(), OptimizeError> {
        let length = length_as_u64(length, "FlowWir values", self.limits.values)?;
        add_bounded(
            &mut self.resources.values,
            length,
            "FlowWir values",
            self.limits.values,
        )
    }
}

#[allow(clippy::too_many_lines)]
fn scan_model(
    wir: &FlowWir,
    limits: OptimizationLimits,
    work: &mut WorkMeter<'_>,
) -> Result<ModelResources, OptimizeError> {
    use wrela_flow_wir::FlowTypeKind;

    let mut meter = ModelMeter {
        resources: ModelResources::default(),
        limits,
        work,
    };
    meter.visit()?;
    meter.payload(wir.name.len())?;
    meter.payload(wir.build.target.as_str().len())?;

    meter.collection(wir.types.len())?;
    for ty in &wir.types {
        meter.visit()?;
        if let Some(name) = &ty.name {
            meter.payload(name.len())?;
        }
        match &ty.kind {
            FlowTypeKind::Tuple(fields) | FlowTypeKind::Struct { fields } => {
                meter.collection(fields.len())?;
            }
            FlowTypeKind::Enum { variants } => {
                meter.collection(variants.len())?;
                for variant in variants {
                    meter.visit()?;
                    meter.collection(variant.len())?;
                }
            }
            FlowTypeKind::Function { parameters, .. } => {
                meter.collection(parameters.len())?;
            }
            FlowTypeKind::OpaqueTarget { name } => meter.payload(name.len())?,
            FlowTypeKind::Unit
            | FlowTypeKind::Scalar(_)
            | FlowTypeKind::Array { .. }
            | FlowTypeKind::Activation { .. }
            | FlowTypeKind::RegionHandle(_)
            | FlowTypeKind::PoolHandle(_)
            | FlowTypeKind::ActorHandle(_)
            | FlowTypeKind::TaskHandle(_)
            | FlowTypeKind::Reservation
            | FlowTypeKind::Receipt { .. }
            | FlowTypeKind::DmaToken { .. } => {}
        }
    }

    meter.collection(wir.globals.len())?;
    for global in &wir.globals {
        meter.visit()?;
        meter.payload(global.name.len())?;
        scan_immediate(&global.initializer, &mut meter)?;
    }

    meter.functions(wir.functions.len())?;
    meter.collection(wir.functions.len())?;
    for function in &wir.functions {
        meter.visit()?;
        meter.payload(function.name.len())?;
        meter.collection(function.parameters.len())?;
        meter.collection(function.result_types.len())?;
        meter.collection(function.proofs.len())?;
        meter.add_values(function.values.len())?;
        meter.collection(function.values.len())?;
        for value in &function.values {
            meter.visit()?;
            if let Some(name) = &value.source_name {
                meter.payload(name.len())?;
            }
        }
        meter.add_blocks(function.blocks.len())?;
        meter.collection(function.blocks.len())?;
        for block in &function.blocks {
            meter.visit()?;
            meter.collection(block.parameters.len())?;
            meter.add_instructions(block.instructions.len())?;
            meter.collection(block.instructions.len())?;
            for instruction in &block.instructions {
                meter.visit()?;
                meter.collection(instruction.results.len())?;
                scan_operation(&instruction.operation, &mut meter)?;
            }
            scan_terminator(&block.terminator, &mut meter)?;
        }
    }

    meter.collection(wir.actors.len())?;
    for actor in &wir.actors {
        meter.visit()?;
        meter.payload(actor.name.len())?;
        meter.collection(actor.message_types.len())?;
        meter.collection(actor.turn_functions.len())?;
    }
    meter.collection(wir.tasks.len())?;
    for task in &wir.tasks {
        meter.visit()?;
        meter.payload(task.name.len())?;
    }
    meter.collection(wir.devices.len())?;
    for device in &wir.devices {
        meter.visit()?;
        meter.payload(device.name.len())?;
        meter.payload(device.target_binding.len())?;
        meter.collection(device.required_features.len())?;
        for feature in &device.required_features {
            meter.visit()?;
            meter.payload(feature.len())?;
        }
        meter.collection(device.optional_features.len())?;
        for feature in &device.optional_features {
            meter.visit()?;
            meter.payload(feature.len())?;
        }
        meter.collection(device.interrupt_functions.len())?;
    }
    meter.collection(wir.pools.len())?;
    for pool in &wir.pools {
        meter.visit()?;
        meter.payload(pool.name.len())?;
        meter.collection(pool.devices.len())?;
    }
    meter.collection(wir.regions.len())?;
    for region in &wir.regions {
        meter.visit()?;
        meter.payload(region.name.len())?;
    }
    meter.collection(wir.activations.len())?;
    for _activation in &wir.activations {
        meter.visit()?;
    }

    meter.proofs(wir.proofs.len())?;
    meter.collection(wir.proofs.len())?;
    for proof in &wir.proofs {
        meter.visit()?;
        meter.payload(proof.subject.len())?;
        meter.collection(proof.sources.len())?;
        meter.collection(proof.depends_on.len())?;
        meter.collection(proof.explanation.len())?;
        for line in &proof.explanation {
            meter.visit()?;
            meter.payload(line.len())?;
        }
    }
    meter.collection(wir.checkpoints.len())?;
    for _ in &wir.checkpoints {
        meter.visit()?;
    }
    meter.tests(wir.tests.len())?;
    meter.collection(wir.tests.len())?;
    for test in &wir.tests {
        meter.visit()?;
        meter.payload(test.name.len())?;
    }
    if let Some(group) = &wir.compiled_test_group {
        scan_compiled_test_group(group, &mut meter)?;
    }
    meter.collection(wir.startup_order.len())?;
    meter.collection(wir.shutdown_order.len())?;
    meter.visit()?;
    Ok(meter.resources)
}

fn scan_compiled_test_group(
    group: &wrela_test_model::FullImageTestGroup,
    meter: &mut ModelMeter<'_, '_>,
) -> Result<(), OptimizeError> {
    let test_plan = meter.limits.test_plan;
    let tests = length_as_u64(
        group.tests.len(),
        "compiled test-group tests",
        u64::from(test_plan.tests),
    )?;
    ensure_limit(
        tests,
        "compiled test-group tests",
        u64::from(test_plan.tests),
    )?;

    let mut group_payload_bytes = 0_u64;
    meter.visit()?;
    scan_compiled_test_group_text(
        &group.name,
        &mut group_payload_bytes,
        test_plan.payload_bytes,
        meter,
    )?;
    match &group.root {
        wrela_test_model::ImageRoot::GeneratedHarness { harness_name } => {
            scan_compiled_test_group_text(
                harness_name,
                &mut group_payload_bytes,
                test_plan.payload_bytes,
                meter,
            )?;
        }
        wrela_test_model::ImageRoot::Declared { image_name, .. } => {
            scan_compiled_test_group_text(
                image_name,
                &mut group_payload_bytes,
                test_plan.payload_bytes,
                meter,
            )?;
        }
    }
    meter.collection(group.tests.len())?;
    for test in &group.tests {
        meter.visit()?;
        scan_compiled_test_group_text(
            &test.descriptor.name,
            &mut group_payload_bytes,
            test_plan.payload_bytes,
            meter,
        )?;
    }
    Ok(())
}

fn scan_compiled_test_group_text(
    text: &str,
    group_payload_bytes: &mut u64,
    group_payload_limit: u64,
    meter: &mut ModelMeter<'_, '_>,
) -> Result<(), OptimizeError> {
    let length = length_as_u64(
        text.len(),
        "compiled test-group payload bytes",
        group_payload_limit,
    )?;
    add_bounded(
        group_payload_bytes,
        length,
        "compiled test-group payload bytes",
        group_payload_limit,
    )?;
    meter.payload(text.len())
}

fn scan_immediate(
    immediate: &wrela_flow_wir::Immediate,
    meter: &mut ModelMeter<'_, '_>,
) -> Result<(), OptimizeError> {
    use wrela_flow_wir::Immediate;

    meter.visit()?;
    match immediate {
        Immediate::Integer { bytes_le, .. } | Immediate::Bytes(bytes_le) => {
            meter.payload(bytes_le.len())
        }
        Immediate::Unit
        | Immediate::Bool(_)
        | Immediate::Float32(_)
        | Immediate::Float64(_)
        | Immediate::Zero(_)
        | Immediate::GlobalAddress(_)
        | Immediate::FunctionAddress(_) => Ok(()),
    }
}

fn scan_operation(
    operation: &wrela_flow_wir::FlowOperation,
    meter: &mut ModelMeter<'_, '_>,
) -> Result<(), OptimizeError> {
    use wrela_flow_wir::FlowOperation;

    meter.visit()?;
    match operation {
        FlowOperation::Immediate(value) => scan_immediate(value, meter),
        FlowOperation::MakeAggregate { fields, .. }
        | FlowOperation::Call {
            arguments: fields, ..
        }
        | FlowOperation::AsyncCall {
            arguments: fields, ..
        }
        | FlowOperation::TaskStart {
            arguments: fields, ..
        } => meter.collection(fields.len()),
        FlowOperation::Unary { .. }
        | FlowOperation::ActorStateAddress { .. }
        | FlowOperation::Binary { .. }
        | FlowOperation::Cast { .. }
        | FlowOperation::MakeEnum { .. }
        | FlowOperation::EnumTag { .. }
        | FlowOperation::EnumPayload { .. }
        | FlowOperation::ExtractField { .. }
        | FlowOperation::InsertField { .. }
        | FlowOperation::Select { .. }
        | FlowOperation::BeginAccess { .. }
        | FlowOperation::EndAccess { .. }
        | FlowOperation::Load { .. }
        | FlowOperation::Store { .. }
        | FlowOperation::Move { .. }
        | FlowOperation::Copy { .. }
        | FlowOperation::Drop { .. }
        | FlowOperation::Allocate { .. }
        | FlowOperation::RegionReset { .. }
        | FlowOperation::Promote { .. }
        | FlowOperation::ActorCapability { .. }
        | FlowOperation::ActorReserve { .. }
        | FlowOperation::ActorCommit { .. }
        | FlowOperation::ActorReplyRequest { .. }
        | FlowOperation::ActorReplyResolve { .. }
        | FlowOperation::ActorReject { .. }
        | FlowOperation::MailboxReceive { .. }
        | FlowOperation::ReplyResolve { .. }
        | FlowOperation::ReceiptCommit { .. }
        | FlowOperation::ReceiptResolve { .. }
        | FlowOperation::TaskAcquireSlot { .. }
        | FlowOperation::TaskCancel { .. }
        | FlowOperation::Park { .. }
        | FlowOperation::Wake { .. }
        | FlowOperation::Checkpoint { .. }
        | FlowOperation::DeadlineRead
        | FlowOperation::InterruptMask
        | FlowOperation::InterruptRestore { .. }
        | FlowOperation::InterruptPublish { .. }
        | FlowOperation::MmioRead { .. }
        | FlowOperation::MmioWrite { .. }
        | FlowOperation::Fence { .. }
        | FlowOperation::DmaTransition { .. }
        | FlowOperation::QueueReserve { .. }
        | FlowOperation::QueuePublish { .. }
        | FlowOperation::ValidateDeviceValue { .. }
        | FlowOperation::Check { .. }
        | FlowOperation::RecordEvent { .. }
        | FlowOperation::ReplayEvent { .. }
        | FlowOperation::Assert { .. }
        | FlowOperation::TestEmit { .. }
        | FlowOperation::TestFinish { .. } => Ok(()),
    }
}

fn scan_terminator(
    terminator: &wrela_flow_wir::Terminator,
    meter: &mut ModelMeter<'_, '_>,
) -> Result<(), OptimizeError> {
    use wrela_flow_wir::Terminator;

    meter.visit()?;
    match terminator {
        Terminator::Jump { arguments, .. }
        | Terminator::Return(arguments)
        | Terminator::TailCall { arguments, .. } => meter.collection(arguments.len()),
        Terminator::Branch {
            then_arguments,
            else_arguments,
            ..
        } => {
            meter.collection(then_arguments.len())?;
            meter.collection(else_arguments.len())
        }
        Terminator::Switch {
            cases,
            default_arguments,
            ..
        } => {
            meter.collection(cases.len())?;
            for case in cases {
                meter.visit()?;
                meter.collection(case.arguments.len())?;
            }
            meter.collection(default_arguments.len())
        }
        Terminator::Suspend { .. } | Terminator::Trap { .. } | Terminator::Unreachable => Ok(()),
    }
}

fn scan_report(
    report: &OptimizationReport,
    limits: OptimizationLimits,
    work: &mut WorkMeter<'_>,
) -> Result<u64, OptimizeError> {
    let work_before = work.used;
    let passes = length_as_u64(
        report.passes.len(),
        "optimization passes",
        u64::from(limits.passes),
    )?;
    ensure_limit(passes, "optimization passes", u64::from(limits.passes))?;
    let decisions = length_as_u64(
        report.decisions.len(),
        "optimization decisions",
        limits.decisions,
    )?;
    ensure_limit(decisions, "optimization decisions", limits.decisions)?;

    let mut bytes = 0u64;
    add_report_payload(&mut bytes, report.profile.pipeline.name.len(), limits, work)?;
    work.charge(passes)?;
    for pass in &report.passes {
        work.checkpoint()?;
        add_report_payload(&mut bytes, pass.pass.len(), limits, work)?;
    }
    work.charge(decisions)?;
    for decision in &report.decisions {
        work.checkpoint()?;
        add_report_payload(&mut bytes, decision.pass.len(), limits, work)?;
        add_report_payload(&mut bytes, decision.subject.len(), limits, work)?;
        add_report_payload(&mut bytes, decision.justification.len(), limits, work)?;
        let proof_bytes =
            decision
                .relied_on
                .len()
                .checked_mul(4)
                .ok_or(OptimizeError::ResourceLimit {
                    resource: "optimization report bytes",
                    limit: limits.report_bytes,
                })?;
        add_report_payload(&mut bytes, proof_bytes, limits, work)?;
        for _ in &decision.relied_on {
            work.checkpoint()?;
        }
    }
    work.checkpoint()?;
    work.used
        .checked_sub(work_before)
        .ok_or(OptimizeError::ResourceLimit {
            resource: "optimizer work",
            limit: limits.work,
        })
}

fn add_report_payload(
    total: &mut u64,
    length: usize,
    limits: OptimizationLimits,
    work: &mut WorkMeter<'_>,
) -> Result<(), OptimizeError> {
    let length = length_as_u64(length, "optimization report bytes", limits.report_bytes)?;
    add_bounded(
        total,
        length,
        "optimization report bytes",
        limits.report_bytes,
    )?;
    work.charge(length)?;
    work.checkpoint()
}

fn length_as_u64(length: usize, resource: &'static str, limit: u64) -> Result<u64, OptimizeError> {
    u64::try_from(length).map_err(|_| OptimizeError::ResourceLimit { resource, limit })
}

const fn ensure_limit(value: u64, resource: &'static str, limit: u64) -> Result<(), OptimizeError> {
    if value > limit {
        Err(OptimizeError::ResourceLimit { resource, limit })
    } else {
        Ok(())
    }
}

fn add_bounded(
    total: &mut u64,
    amount: u64,
    resource: &'static str,
    limit: u64,
) -> Result<(), OptimizeError> {
    let next = total
        .checked_add(amount)
        .ok_or(OptimizeError::ResourceLimit { resource, limit })?;
    ensure_limit(next, resource, limit)?;
    *total = next;
    Ok(())
}

#[cfg(test)]
mod contract_tests {
    use std::cell::Cell;

    use super::{
        CANCELLABLE_COMPARISON_CHUNK_BYTES, CanonicalFlowOptimizer, FlowOptimizer,
        OptimizationDecision, OptimizationLimits, OptimizationProfile, OptimizationReport,
        OptimizationRequest, OptimizeError, PassStatistics, PipelineIdentity, WorkMeter,
        flow_wir_equal, optimization_report_equal, scan_model, scan_report, seal,
    };
    use wrela_build_model::{
        BuildIdentity, LanguageRevision, OptimizationLevel, OptimizationPolicy, Sha256Digest,
        TargetIdentity,
    };
    use wrela_flow_lower::{CanonicalFlowLowerer, FlowLowerer, LowerRequest, LoweringLimits};
    use wrela_flow_wir::{self as flow, ValidatedFlowWir};
    use wrela_semantic_wir as semantic;
    use wrela_source::{FileId, Span, TextRange};
    use wrela_test_model::TestPlanLimits;

    fn span(file: u32, start: u32, end: u32) -> Span {
        Span {
            file: FileId(file),
            range: TextRange { start, end },
        }
    }

    fn build() -> BuildIdentity {
        let digest = Sha256Digest::from_bytes([0x41; 32]);
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

    fn proof(
        id: u32,
        kind: semantic::ProofKind,
        depends_on: &[u32],
        bound: Option<u64>,
    ) -> semantic::ProofRecord {
        semantic::ProofRecord {
            id: semantic::ProofId(id),
            kind,
            subject: format!("semantic proof {id}"),
            bound,
            sources: vec![span(id % 2, id * 10, id * 10 + 4)],
            depends_on: depends_on.iter().copied().map(semantic::ProofId).collect(),
            explanation: vec![format!("proof explanation {id}")],
        }
    }

    fn semantic_fixture() -> semantic::ValidatedSemanticWir {
        semantic::SemanticWir {
            version: semantic::SEMANTIC_WIR_VERSION,
            name: "exact-runtime-image".to_owned(),
            build: build(),
            source_summary: semantic::SourceSummary {
                hir_files: 2,
                hir_declarations: 4,
                reachable_declarations: 1,
                monomorphized_instantiations: 1,
                resolved_interface_calls: 0,
            },
            types: vec![semantic::TypeRecord {
                id: semantic::TypeId(0),
                source_name: "unit".to_owned(),
                kind: semantic::TypeKind::Primitive(semantic::PrimitiveType::Unit),
                linearity: semantic::Linearity::CopyScalar,
                source: None,
            }],
            globals: Vec::new(),
            functions: vec![semantic::SemanticFunction {
                id: semantic::FunctionId(0),
                instance_key: Sha256Digest::from_bytes([0x52; 32]),
                name: "__wrela_image_entry".to_owned(),
                origin: semantic::FunctionOrigin::GeneratedImageEntry { constructor: 3 },
                role: semantic::FunctionRole::ImageEntry,
                color: semantic::FunctionColor::Sync,
                parameters: Vec::new(),
                result: semantic::TypeId(0),
                values: Vec::new(),
                body: semantic::SemanticRegion {
                    parameters: Vec::new(),
                    statements: vec![semantic::SemanticStatement::Return(Vec::new())],
                },
                effects: semantic::EffectSet(semantic::EffectSet::FIRMWARE),
                proofs: vec![
                    semantic::ProofId(0),
                    semantic::ProofId(1),
                    semantic::ProofId(2),
                ],
                source: None,
                stack_bound: 0,
                frame_bound: 0,
                uninterrupted_bound: Some(1),
                recursive_depth_bound: Some(1),
            }],
            actors: Vec::new(),
            tasks: Vec::new(),
            devices: Vec::new(),
            pools: Vec::new(),
            regions: Vec::new(),
            activations: Vec::new(),
            scopes: Vec::new(),
            proofs: vec![
                proof(0, semantic::ProofKind::TypeChecked, &[], None),
                proof(1, semantic::ProofKind::EffectsAllowed, &[0], Some(1)),
                proof(2, semantic::ProofKind::ImageClosed, &[0, 1], Some(0)),
            ],
            tests: Vec::new(),
            compiled_test_group: None,
            startup_order: vec![semantic::ImageOwner::Runtime],
            shutdown_order: vec![semantic::ImageOwner::Runtime],
            image_entry: semantic::FunctionId(0),
            static_bytes: 0,
            peak_bytes: 0,
        }
        .validate()
        .expect("valid minimum SemanticWir")
    }

    fn lowered_fixture() -> ValidatedFlowWir {
        CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: semantic_fixture(),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("canonical FlowWir lowering")
            .into_parts()
            .0
    }

    fn async_flow_fixture() -> ValidatedFlowWir {
        let mut wir = lowered_fixture().into_wir();
        let source = span(0, 10, 20);
        wir.source_summary.semantic_functions = 3;
        wir.source_summary.hir_declarations = 4;
        wir.source_summary.reachable_declarations = 3;
        wir.source_summary.monomorphized_instantiations = 3;
        wir.types.push(flow::FlowType {
            id: flow::TypeId(1),
            kind: flow::FlowTypeKind::Activation {
                result: flow::TypeId(0),
            },
            name: Some("__wrela_activation_0".to_owned()),
            copyable: false,
            strict_linear: true,
        });
        wir.functions.push(flow::FlowFunction {
            id: flow::FunctionId(1),
            name: "actor-turn".to_owned(),
            origin: flow::FunctionOrigin::SourceSemantic {
                semantic_function: 1,
            },
            role: flow::FunctionRole::ActorTurn(flow::ActorId(0)),
            color: flow::FunctionColor::Async,
            parameters: Vec::new(),
            result_types: Vec::new(),
            values: vec![
                flow::Value {
                    id: flow::ValueId(0),
                    ty: flow::TypeId(1),
                    source_name: None,
                    source: Some(source),
                },
                flow::Value {
                    id: flow::ValueId(1),
                    ty: flow::TypeId(0),
                    source_name: None,
                    source: Some(source),
                },
            ],
            blocks: vec![
                flow::Block {
                    id: flow::BlockId(0),
                    parameters: Vec::new(),
                    instructions: vec![flow::Instruction {
                        id: flow::InstructionId(0),
                        results: vec![flow::ValueId(0)],
                        operation: flow::FlowOperation::AsyncCall {
                            function: flow::FunctionId(2),
                            arguments: Vec::new(),
                            plan: flow::ActivationId(0),
                        },
                        source: Some(source),
                    }],
                    terminator: flow::Terminator::Suspend {
                        state: 0,
                        activation: flow::ValueId(0),
                        resume: flow::BlockId(1),
                    },
                    source: Some(source),
                },
                flow::Block {
                    id: flow::BlockId(1),
                    parameters: vec![flow::ValueId(1)],
                    instructions: Vec::new(),
                    terminator: flow::Terminator::Return(Vec::new()),
                    source: Some(source),
                },
            ],
            entry: flow::BlockId(0),
            stack_bound: 8,
            frame_bound: 8,
            proofs: vec![flow::ProofId(7)],
            source: Some(source),
        });
        wir.functions.push(flow::FlowFunction {
            id: flow::FunctionId(2),
            name: "async-helper".to_owned(),
            origin: flow::FunctionOrigin::SourceSemantic {
                semantic_function: 2,
            },
            role: flow::FunctionRole::Ordinary,
            color: flow::FunctionColor::Async,
            parameters: Vec::new(),
            result_types: Vec::new(),
            values: Vec::new(),
            blocks: vec![flow::Block {
                id: flow::BlockId(0),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: flow::Terminator::Return(Vec::new()),
                source: Some(source),
            }],
            entry: flow::BlockId(0),
            stack_bound: 8,
            frame_bound: 8,
            proofs: vec![flow::ProofId(2)],
            source: Some(source),
        });
        wir.functions[0].proofs = vec![
            flow::ProofId(3),
            flow::ProofId(4),
            flow::ProofId(5),
            flow::ProofId(6),
            flow::ProofId(8),
        ];
        wir.actors = vec![flow::ActorPlan {
            id: flow::ActorId(0),
            name: "actor".to_owned(),
            state_type: flow::TypeId(0),
            mailbox_capacity: 1,
            message_types: Vec::new(),
            turn_functions: vec![flow::FunctionId(1)],
            priority: 1,
            supervisor: None,
        }];
        wir.proofs = vec![
            flow::Proof {
                id: flow::ProofId(0),
                kind: flow::ProofKind::TypeChecked,
                subject: "actor image types".to_owned(),
                sources: vec![source],
                depends_on: Vec::new(),
                bound: None,
                explanation: vec!["actor image is typed".to_owned()],
            },
            flow::Proof {
                id: flow::ProofId(1),
                kind: flow::ProofKind::EffectsAllowed,
                subject: "actor image effects".to_owned(),
                sources: vec![source],
                depends_on: vec![flow::ProofId(0)],
                bound: None,
                explanation: vec!["actor image effects are closed".to_owned()],
            },
            flow::Proof {
                id: flow::ProofId(2),
                kind: flow::ProofKind::CleanupAcyclic,
                subject: "helper cleanup".to_owned(),
                sources: vec![source],
                depends_on: Vec::new(),
                bound: Some(0),
                explanation: vec!["drop helper frame".to_owned()],
            },
            flow::Proof {
                id: flow::ProofId(3),
                kind: flow::ProofKind::CapacityBound,
                subject: "mailbox capacity".to_owned(),
                sources: vec![source],
                depends_on: Vec::new(),
                bound: Some(1),
                explanation: vec!["one mailbox slot".to_owned()],
            },
            flow::Proof {
                id: flow::ProofId(4),
                kind: flow::ProofKind::CapacityBound,
                subject: "turn capacity".to_owned(),
                sources: vec![source],
                depends_on: Vec::new(),
                bound: Some(1),
                explanation: vec!["one turn frame".to_owned()],
            },
            flow::Proof {
                id: flow::ProofId(5),
                kind: flow::ProofKind::WaitGraphAcyclic,
                subject: "closed actor wait graph".to_owned(),
                sources: vec![source],
                depends_on: vec![flow::ProofId(1)],
                bound: Some(1),
                explanation: vec!["one acyclic await edge".to_owned()],
            },
            flow::Proof {
                id: flow::ProofId(6),
                kind: flow::ProofKind::CapacityBound,
                subject: "base actor allocation".to_owned(),
                sources: vec![source, source],
                depends_on: vec![
                    flow::ProofId(0),
                    flow::ProofId(1),
                    flow::ProofId(3),
                    flow::ProofId(4),
                    flow::ProofId(5),
                ],
                bound: Some(24),
                explanation: vec!["mailbox plus root turn frame".to_owned()],
            },
            flow::Proof {
                id: flow::ProofId(7),
                kind: flow::ProofKind::CapacityBound,
                subject: "call activation".to_owned(),
                sources: vec![source],
                depends_on: vec![flow::ProofId(2)],
                bound: Some(1),
                explanation: vec!["one helper frame".to_owned()],
            },
            flow::Proof {
                id: flow::ProofId(8),
                kind: flow::ProofKind::ImageClosed,
                subject: "closed actor image".to_owned(),
                sources: vec![source],
                depends_on: vec![flow::ProofId(6), flow::ProofId(7)],
                bound: Some(32),
                explanation: vec!["base plus helper activation".to_owned()],
            },
        ];
        wir.regions = vec![
            flow::RegionPlan {
                id: flow::RegionId(0),
                name: "actor.mailbox".to_owned(),
                class: flow::RegionClass::Image,
                capacity_bytes: 16,
                alignment: 8,
                reset_function: None,
                owner: flow::PlanOwner::Actor(flow::ActorId(0)),
                capacity_proof: flow::ProofId(3),
                source,
            },
            flow::RegionPlan {
                id: flow::RegionId(1),
                name: "actor.turn-frame".to_owned(),
                class: flow::RegionClass::TaskFrame,
                capacity_bytes: 8,
                alignment: 8,
                reset_function: None,
                owner: flow::PlanOwner::Actor(flow::ActorId(0)),
                capacity_proof: flow::ProofId(4),
                source,
            },
            flow::RegionPlan {
                id: flow::RegionId(2),
                name: "actor-turn.async-activation-frame".to_owned(),
                class: flow::RegionClass::TaskFrame,
                capacity_bytes: 8,
                alignment: 8,
                reset_function: None,
                owner: flow::PlanOwner::Actor(flow::ActorId(0)),
                capacity_proof: flow::ProofId(7),
                source,
            },
        ];
        wir.activations = vec![flow::ActivationPlan {
            id: flow::ActivationId(0),
            caller: flow::FunctionId(1),
            callee: flow::FunctionId(2),
            region: flow::RegionId(2),
            frame_bytes: 8,
            maximum_live: 1,
            cancellation: flow::ActivationCancellation::DropCalleeThenPropagate,
            capacity_proof: flow::ProofId(7),
            source,
        }];
        wir.startup_order = vec![
            flow::PlanOwner::Runtime,
            flow::PlanOwner::Actor(flow::ActorId(0)),
        ];
        wir.shutdown_order = vec![
            flow::PlanOwner::Actor(flow::ActorId(0)),
            flow::PlanOwner::Runtime,
        ];
        wir.static_bytes = 32;
        wir.peak_bytes = 32;
        wir.validate().expect("valid async optimizer fixture")
    }

    #[allow(clippy::too_many_lines)]
    fn scalar_control_fixture() -> ValidatedFlowWir {
        let mut wir = lowered_fixture().into_wir();
        wir.types.push(flow::FlowType {
            id: flow::TypeId(1),
            kind: flow::FlowTypeKind::Scalar(flow::ScalarType::Bool),
            name: Some("bool".to_owned()),
            copyable: true,
            strict_linear: false,
        });
        wir.types.push(flow::FlowType {
            id: flow::TypeId(2),
            kind: flow::FlowTypeKind::Scalar(flow::ScalarType::Integer {
                signed: false,
                bits: 8,
            }),
            name: Some("u8".to_owned()),
            copyable: true,
            strict_linear: false,
        });
        let function = &mut wir.functions[0];
        function.values = vec![
            flow::Value {
                id: flow::ValueId(0),
                ty: flow::TypeId(1),
                source_name: Some("constant_condition".to_owned()),
                source: None,
            },
            flow::Value {
                id: flow::ValueId(1),
                ty: flow::TypeId(2),
                source_name: Some("left".to_owned()),
                source: None,
            },
            flow::Value {
                id: flow::ValueId(2),
                ty: flow::TypeId(2),
                source_name: Some("right".to_owned()),
                source: None,
            },
            flow::Value {
                id: flow::ValueId(3),
                ty: flow::TypeId(2),
                source_name: Some("wrapped".to_owned()),
                source: None,
            },
            flow::Value {
                id: flow::ValueId(4),
                ty: flow::TypeId(2),
                source_name: Some("unused_pure".to_owned()),
                source: None,
            },
            flow::Value {
                id: flow::ValueId(5),
                ty: flow::TypeId(2),
                source_name: Some("checked_overflow".to_owned()),
                source: None,
            },
        ];
        function.blocks = vec![
            flow::Block {
                id: flow::BlockId(0),
                parameters: Vec::new(),
                instructions: vec![
                    flow::Instruction {
                        id: flow::InstructionId(0),
                        results: vec![flow::ValueId(0)],
                        operation: flow::FlowOperation::Immediate(flow::Immediate::Bool(true)),
                        source: None,
                    },
                    flow::Instruction {
                        id: flow::InstructionId(1),
                        results: Vec::new(),
                        operation: flow::FlowOperation::Check {
                            condition: flow::ValueId(0),
                            failure: flow::FailureKind::Arithmetic,
                            proof: Some(flow::ProofId(0)),
                        },
                        source: None,
                    },
                ],
                terminator: flow::Terminator::Branch {
                    condition: flow::ValueId(0),
                    then_block: flow::BlockId(1),
                    then_arguments: Vec::new(),
                    else_block: flow::BlockId(4),
                    else_arguments: Vec::new(),
                },
                source: None,
            },
            flow::Block {
                id: flow::BlockId(1),
                parameters: Vec::new(),
                instructions: vec![
                    flow::Instruction {
                        id: flow::InstructionId(2),
                        results: vec![flow::ValueId(1)],
                        operation: flow::FlowOperation::Immediate(flow::Immediate::Integer {
                            bits: 8,
                            bytes_le: vec![250],
                        }),
                        source: None,
                    },
                    flow::Instruction {
                        id: flow::InstructionId(3),
                        results: vec![flow::ValueId(2)],
                        operation: flow::FlowOperation::Immediate(flow::Immediate::Integer {
                            bits: 8,
                            bytes_le: vec![36],
                        }),
                        source: None,
                    },
                    flow::Instruction {
                        id: flow::InstructionId(4),
                        results: vec![flow::ValueId(3)],
                        operation: flow::FlowOperation::Binary {
                            op: flow::BinaryOp::AddWrapping,
                            left: flow::ValueId(1),
                            right: flow::ValueId(2),
                        },
                        source: None,
                    },
                    flow::Instruction {
                        id: flow::InstructionId(5),
                        results: vec![flow::ValueId(4)],
                        operation: flow::FlowOperation::Binary {
                            op: flow::BinaryOp::BitXor,
                            left: flow::ValueId(1),
                            right: flow::ValueId(2),
                        },
                        source: None,
                    },
                    flow::Instruction {
                        id: flow::InstructionId(6),
                        results: vec![flow::ValueId(5)],
                        operation: flow::FlowOperation::Binary {
                            op: flow::BinaryOp::AddChecked,
                            left: flow::ValueId(1),
                            right: flow::ValueId(2),
                        },
                        source: None,
                    },
                ],
                terminator: flow::Terminator::Switch {
                    value: flow::ValueId(3),
                    cases: vec![flow::SwitchCase {
                        value: 30,
                        target: flow::BlockId(2),
                        arguments: Vec::new(),
                    }],
                    default: flow::BlockId(3),
                    default_arguments: Vec::new(),
                },
                source: None,
            },
            flow::Block {
                id: flow::BlockId(2),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: flow::Terminator::Jump {
                    target: flow::BlockId(5),
                    arguments: Vec::new(),
                },
                source: None,
            },
            flow::Block {
                id: flow::BlockId(3),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: flow::Terminator::Jump {
                    target: flow::BlockId(5),
                    arguments: Vec::new(),
                },
                source: None,
            },
            flow::Block {
                id: flow::BlockId(4),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: flow::Terminator::Jump {
                    target: flow::BlockId(5),
                    arguments: Vec::new(),
                },
                source: None,
            },
            flow::Block {
                id: flow::BlockId(5),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: flow::Terminator::Return(Vec::new()),
                source: None,
            },
        ];
        function.entry = flow::BlockId(0);
        wir.validate().expect("valid scalar/control-flow fixture")
    }

    fn nontrapping_scalar_control_fixture() -> ValidatedFlowWir {
        let mut wir = scalar_control_fixture().into_wir();
        wir.functions[0].blocks[1].instructions.pop();
        wir.functions[0].values.pop();
        wir.validate()
            .expect("valid nontrapping scalar/control-flow fixture")
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ObservableOutcome {
        Returned,
        Trapped,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum TestScalar {
        Bool(bool),
        U8(u8),
    }

    fn execute_scalar_fixture(wir: &flow::FlowWir) -> ObservableOutcome {
        let function = &wir.functions[0];
        let mut values = vec![None; function.values.len()];
        let mut block = function.entry;
        for _ in 0..64 {
            let record = &function.blocks[usize::try_from(block.0).expect("block index")];
            for instruction in &record.instructions {
                let result = instruction.results.first().copied();
                match &instruction.operation {
                    flow::FlowOperation::Immediate(flow::Immediate::Bool(value)) => {
                        values[usize::try_from(result.expect("Boolean result").0)
                            .expect("value index")] = Some(TestScalar::Bool(*value));
                    }
                    flow::FlowOperation::Immediate(flow::Immediate::Integer {
                        bits: 8,
                        bytes_le,
                    }) => {
                        values[usize::try_from(result.expect("integer result").0)
                            .expect("value index")] = Some(TestScalar::U8(bytes_le[0]));
                    }
                    flow::FlowOperation::Binary { op, left, right } => {
                        let TestScalar::U8(left) = values
                            [usize::try_from(left.0).expect("left value index")]
                        .expect("left value") else {
                            panic!("fixture binary left operand is not u8");
                        };
                        let TestScalar::U8(right) = values
                            [usize::try_from(right.0).expect("right value index")]
                        .expect("right value") else {
                            panic!("fixture binary right operand is not u8");
                        };
                        let value = match op {
                            flow::BinaryOp::AddWrapping => left.wrapping_add(right),
                            flow::BinaryOp::BitXor => left ^ right,
                            flow::BinaryOp::AddChecked => {
                                let Some(value) = left.checked_add(right) else {
                                    return ObservableOutcome::Trapped;
                                };
                                value
                            }
                            _ => panic!("operation is outside the differential fixture"),
                        };
                        values[usize::try_from(result.expect("binary result").0)
                            .expect("value index")] = Some(TestScalar::U8(value));
                    }
                    flow::FlowOperation::Check { condition, .. } => {
                        if values[usize::try_from(condition.0).expect("condition index")]
                            != Some(TestScalar::Bool(true))
                        {
                            return ObservableOutcome::Trapped;
                        }
                    }
                    _ => panic!("operation is outside the differential fixture"),
                }
            }
            block = match &record.terminator {
                flow::Terminator::Jump { target, .. } => *target,
                flow::Terminator::Branch {
                    condition,
                    then_block,
                    else_block,
                    ..
                } => match values[usize::try_from(condition.0).expect("condition index")]
                    .expect("branch condition")
                {
                    TestScalar::Bool(true) => *then_block,
                    TestScalar::Bool(false) => *else_block,
                    TestScalar::U8(_) => panic!("branch condition is not Boolean"),
                },
                flow::Terminator::Switch {
                    value,
                    cases,
                    default,
                    ..
                } => {
                    let selected = match values
                        [usize::try_from(value.0).expect("switch value index")]
                    .expect("switch value")
                    {
                        TestScalar::Bool(value) => u128::from(value),
                        TestScalar::U8(value) => u128::from(value),
                    };
                    cases
                        .iter()
                        .find(|case| case.value == selected)
                        .map_or(*default, |case| case.target)
                }
                flow::Terminator::Return(_) => return ObservableOutcome::Returned,
                _ => panic!("terminator is outside the differential fixture"),
            };
        }
        panic!("differential fixture exceeded its finite step bound");
    }

    fn assert_identity_and_capacity_facts_preserved(before: &flow::FlowWir, after: &flow::FlowWir) {
        assert_eq!(after.version, before.version);
        assert_eq!(after.name, before.name);
        assert_eq!(after.build, before.build);
        assert_eq!(after.source_summary, before.source_summary);
        assert_eq!(after.types, before.types);
        assert_eq!(after.globals, before.globals);
        assert_eq!(after.actors, before.actors);
        assert_eq!(after.tasks, before.tasks);
        assert_eq!(after.devices, before.devices);
        assert_eq!(after.pools, before.pools);
        assert_eq!(after.regions, before.regions);
        assert_eq!(after.activations, before.activations);
        assert_eq!(after.proofs, before.proofs);
        assert_eq!(after.checkpoints, before.checkpoints);
        assert_eq!(after.tests, before.tests);
        assert_eq!(after.compiled_test_group, before.compiled_test_group);
        assert_eq!(after.startup_order, before.startup_order);
        assert_eq!(after.shutdown_order, before.shutdown_order);
        assert_eq!(after.image_entry, before.image_entry);
        assert_eq!(after.static_bytes, before.static_bytes);
        assert_eq!(after.peak_bytes, before.peak_bytes);
        assert_eq!(after.functions.len(), before.functions.len());
        for (before, after) in before.functions.iter().zip(&after.functions) {
            assert_eq!(after.id, before.id);
            assert_eq!(after.name, before.name);
            assert_eq!(after.origin, before.origin);
            assert_eq!(after.role, before.role);
            assert_eq!(after.color, before.color);
            assert_eq!(after.result_types, before.result_types);
            assert_eq!(after.stack_bound, before.stack_bound);
            assert_eq!(after.frame_bound, before.frame_bound);
            assert_eq!(after.proofs, before.proofs);
            assert_eq!(after.source, before.source);
        }
    }

    fn test_metadata_fixture(test_count: u32) -> ValidatedFlowWir {
        let mut wir = scalar_control_fixture().into_wir();
        wir.source_summary.semantic_functions = test_count + 1;
        wir.source_summary.monomorphized_instantiations = u64::from(test_count + 1);
        wir.functions[0].origin = flow::FunctionOrigin::GeneratedTestHarness {
            semantic_function: 0,
            group: 0,
        };
        let mut planned_tests = Vec::new();
        for local_id in 0..test_count {
            let function_id = local_id + 1;
            let key_byte = 0x70 + u8::try_from(local_id).expect("fixture test ID fits in u8");
            let source = span(1, 100 + local_id * 10, 105 + local_id * 10);
            wir.functions.push(flow::FlowFunction {
                id: flow::FunctionId(function_id),
                name: format!("integration-test-{local_id}"),
                origin: flow::FunctionOrigin::SourceSemantic {
                    semantic_function: function_id,
                },
                role: flow::FunctionRole::Test,
                color: flow::FunctionColor::Sync,
                parameters: Vec::new(),
                result_types: Vec::new(),
                values: Vec::new(),
                blocks: vec![flow::Block {
                    id: flow::BlockId(0),
                    parameters: Vec::new(),
                    instructions: Vec::new(),
                    terminator: flow::Terminator::Return(Vec::new()),
                    source: Some(source),
                }],
                entry: flow::BlockId(0),
                stack_bound: 64,
                frame_bound: 0,
                proofs: Vec::new(),
                source: Some(source),
            });
            wir.tests.push(flow::TestEntry {
                id: flow::TestId(local_id),
                plan_id: local_id,
                function_key: Sha256Digest::from_bytes([key_byte; 32]),
                name: format!("integration-test-{local_id}"),
                function: flow::FunctionId(function_id),
                kind: flow::TestKind::Integration,
                source,
                timeout_ns: 1_000_000_000 + u64::from(local_id),
            });
            planned_tests.push(wrela_test_model::ImageTest {
                descriptor: wrela_test_model::TestDescriptor {
                    id: wrela_test_model::TestId(local_id),
                    name: format!("integration-test-{local_id}"),
                    kind: wrela_test_model::TestKind::IntegrationImage,
                    source: Some(source),
                    timeout_ns: 1_000_000_000 + u64::from(local_id),
                },
                invocation: wrela_test_model::ImageTestInvocation::GeneratedFunction {
                    function_key: wrela_test_model::FunctionKey(Sha256Digest::from_bytes(
                        [key_byte; 32],
                    )),
                },
                assertions: Vec::new(),
            });
        }
        wir.compiled_test_group = Some(wrela_test_model::FullImageTestGroup {
            id: wrela_test_model::ImageGroupId(0),
            name: "integration".to_owned(),
            root: wrela_test_model::ImageRoot::GeneratedHarness {
                harness_name: wir.name.clone(),
            },
            tests: planned_tests,
            deterministic_seed: None,
            boot_timeout_ns: 1,
            shutdown_timeout_ns: 1,
            maximum_events: test_count * 2 + 3,
            maximum_output_bytes: 1,
        });
        wir.validate().expect("valid FlowWir test metadata fixture")
    }

    fn profile(level: OptimizationLevel) -> OptimizationProfile {
        let (maximum_iterations, maximum_ir_growth_percent) = match level {
            OptimizationLevel::None => (1, 0),
            OptimizationLevel::Development => (8, 25),
            OptimizationLevel::Performance => (32, 100),
            OptimizationLevel::Size => (32, 0),
        };
        OptimizationProfile {
            level,
            pipeline: PipelineIdentity {
                name: super::CANONICAL_PIPELINE_NAME.to_owned(),
                revision: super::CANONICAL_PIPELINE_REVISION,
                implementation: Sha256Digest::from_bytes([0x91; 32]),
            },
            verify_after_each_pass: true,
            maximum_iterations,
            maximum_ir_growth_percent,
        }
    }

    #[test]
    fn production_profile_is_bound_to_build_policy_and_compiler_bytes() {
        let compiler = Sha256Digest::from_bytes([0xa5; 32]);
        let policy = OptimizationPolicy {
            level: OptimizationLevel::Development,
            profile_data: None,
        };
        let profile = OptimizationProfile::from_build_policy(&policy, compiler)
            .expect("valid production optimization profile");
        assert_eq!(profile.level, OptimizationLevel::Development);
        assert_eq!(profile.pipeline.implementation, compiler);
        assert_eq!(
            profile.pipeline.revision,
            super::CANONICAL_PIPELINE_REVISION
        );
        assert_eq!(super::CANONICAL_PIPELINE_REVISION, 3);
        assert!(profile.verify_after_each_pass);

        let mut stale = profile.clone();
        stale.pipeline.revision = 2;
        assert_eq!(
            super::validate_canonical_profile(&stale),
            Err(OptimizeError::InvalidProfile(
                "optimization requires the canonical pipeline identity"
            ))
        );

        for level in [
            OptimizationLevel::None,
            OptimizationLevel::Development,
            OptimizationLevel::Performance,
            OptimizationLevel::Size,
        ] {
            let guided = OptimizationPolicy {
                level,
                profile_data: Some(Sha256Digest::from_bytes([0x5a; 32])),
            };
            assert_eq!(
                OptimizationProfile::from_build_policy(&guided, compiler),
                Err(OptimizeError::InvalidProfile(
                    "profile-guided optimization input is not implemented"
                ))
            );
        }
        let size = OptimizationProfile::from_build_policy(
            &OptimizationPolicy {
                level: OptimizationLevel::Size,
                profile_data: None,
            },
            compiler,
        )
        .expect("canonical size profile");
        assert_eq!(size.maximum_ir_growth_percent, 0);
    }

    fn request(
        input: ValidatedFlowWir,
        profile: OptimizationProfile,
        limits: OptimizationLimits,
    ) -> OptimizationRequest {
        OptimizationRequest {
            input,
            profile,
            limits,
        }
    }

    fn exact_limits(input: &ValidatedFlowWir, profile: &OptimizationProfile) -> OptimizationLimits {
        let generous = OptimizationLimits::standard();
        let mut work = WorkMeter::new(generous.work, &|| false);
        work.checkpoint().expect("initial boundary");
        let resources = scan_model(input.as_wir(), generous, &mut work).expect("model resources");
        work.checkpoint().expect("report boundary");
        let report = OptimizationReport {
            profile: profile.clone(),
            passes: Vec::new(),
            decisions: Vec::new(),
        };
        scan_report(&report, generous, &mut work).expect("report resources");
        work.checkpoint().expect("final boundary");

        OptimizationLimits {
            functions: u32::try_from(resources.functions.max(1)).expect("function count"),
            tests: u32::try_from(resources.tests.max(1)).expect("test count"),
            blocks: resources.blocks.max(1),
            instructions: resources.instructions.max(1),
            values: resources.values.max(1),
            proofs: u32::try_from(resources.proofs.max(1)).expect("proof count"),
            model_edges: resources.model_edges,
            payload_bytes: resources.payload_bytes,
            passes: 1,
            decisions: 1,
            report_bytes: u64::try_from(profile.pipeline.name.len()).expect("report bytes"),
            work: work.used,
            validation_work: 1,
            validation_errors: 1,
            test_plan: TestPlanLimits {
                tests: 1,
                groups: 1,
                scenarios: 1,
                scenario_steps: 1,
                payload_bytes: 1,
                report_bytes: 1,
                events_per_group: 1,
                output_bytes_per_group: 1,
                execution_timeout_ns_per_group: 1,
            },
        }
    }

    #[test]
    fn optimizer_policy_rejects_zero_capacity() {
        OptimizationLimits::standard()
            .validate()
            .expect("standard limits");
        let mut limits = OptimizationLimits::standard();
        limits.functions = 0;
        assert!(matches!(
            limits.validate(),
            Err(OptimizeError::InvalidLimits)
        ));

        let mut limits = OptimizationLimits::standard();
        limits.tests = 0;
        assert_eq!(limits.validate(), Err(OptimizeError::InvalidLimits));

        let mut limits = OptimizationLimits::standard();
        limits.work += 1;
        assert_eq!(limits.validate(), Err(OptimizeError::InvalidLimits));

        let mut limits = OptimizationLimits::standard();
        limits.validation_work = 0;
        assert_eq!(limits.validate(), Err(OptimizeError::InvalidLimits));

        let mut limits = OptimizationLimits::standard();
        limits.validation_errors = 0;
        assert_eq!(limits.validate(), Err(OptimizeError::InvalidLimits));

        let mut limits = OptimizationLimits::standard();
        limits.test_plan.events_per_group = 0;
        assert_eq!(limits.validate(), Err(OptimizeError::InvalidLimits));
    }

    #[test]
    fn canonical_optimizer_accepts_real_lowering_without_changing_it() {
        let input = lowered_fixture();
        let expected = input.clone();
        let requested_profile = profile(OptimizationLevel::None);

        let output = CanonicalFlowOptimizer::new()
            .optimize(
                request(
                    input,
                    requested_profile.clone(),
                    OptimizationLimits::standard(),
                ),
                &|| false,
            )
            .expect("no-op optimization");

        assert_eq!(output.wir(), &expected);
        assert_eq!(output.report().profile, requested_profile);
        assert!(output.report().passes.is_empty());
        assert!(output.report().decisions.is_empty());

        let repeated = CanonicalFlowOptimizer::new()
            .optimize(
                request(
                    expected,
                    profile(OptimizationLevel::None),
                    OptimizationLimits::standard(),
                ),
                &|| false,
            )
            .expect("repeat no-op optimization");
        assert_eq!(output, repeated);
    }

    #[test]
    fn every_profile_preserves_async_activation_and_result_delivery() {
        let input = async_flow_fixture();
        for level in [
            OptimizationLevel::None,
            OptimizationLevel::Performance,
            OptimizationLevel::Size,
        ] {
            let output = CanonicalFlowOptimizer::new()
                .optimize(
                    request(
                        input.clone(),
                        profile(level),
                        OptimizationLimits::standard(),
                    ),
                    &|| false,
                )
                .expect("async FlowWir optimizes");
            let function = &output.wir().as_wir().functions[1];
            assert_eq!(function.color, flow::FunctionColor::Async);
            assert_eq!(function.proofs, [flow::ProofId(7)]);
            assert_eq!(
                output.wir().as_wir().functions[2].proofs,
                [flow::ProofId(2)]
            );
            assert_eq!(
                output.wir().as_wir().functions[0].proofs,
                [
                    flow::ProofId(3),
                    flow::ProofId(4),
                    flow::ProofId(5),
                    flow::ProofId(6),
                    flow::ProofId(8),
                ]
            );
            assert!(matches!(
                function.blocks.as_slice(),
                [entry, resume]
                    if matches!(
                        entry.instructions.as_slice(),
                        [flow::Instruction {
                            results,
                            operation: flow::FlowOperation::AsyncCall {
                                function: flow::FunctionId(2),
                                arguments,
                                plan: flow::ActivationId(0),
                            },
                            ..
                        }] if results.as_slice() == [flow::ValueId(0)] && arguments.is_empty()
                    )
                    && matches!(
                        entry.terminator,
                        flow::Terminator::Suspend {
                            state: 0,
                            activation: flow::ValueId(0),
                            resume: flow::BlockId(1),
                        }
                    )
                    && resume.parameters.as_slice() == [flow::ValueId(1)]
            ));
        }
    }

    #[test]
    fn aggressive_levels_run_real_canonical_pipelines() {
        let input = lowered_fixture();
        for level in [OptimizationLevel::Performance, OptimizationLevel::Size] {
            let output = CanonicalFlowOptimizer::new()
                .optimize(
                    request(
                        input.clone(),
                        profile(level),
                        OptimizationLimits::standard(),
                    ),
                    &|| false,
                )
                .expect("aggressive canonical optimization");
            assert_eq!(output.report().profile.level, level);
            assert_eq!(output.report().passes.len(), 5);
            assert!(output.report().passes.iter().all(|pass| !pass.changed));
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn aggressive_profiles_remove_proven_checks_preserve_identity_and_are_idempotent() {
        for level in [OptimizationLevel::Performance, OptimizationLevel::Size] {
            let input = scalar_control_fixture();
            let requested_profile = profile(level);
            let output = CanonicalFlowOptimizer::new()
                .optimize(
                    request(
                        input.clone(),
                        requested_profile.clone(),
                        OptimizationLimits::standard(),
                    ),
                    &|| false,
                )
                .expect("aggressive scalar optimization");
            assert_identity_and_capacity_facts_preserved(input.as_wir(), output.wir().as_wir());
            let instructions: Vec<_> = output.wir().as_wir().functions[0]
                .blocks
                .iter()
                .flat_map(|block| &block.instructions)
                .collect();
            assert_eq!(instructions.len(), 3);
            assert!(instructions.iter().all(|instruction| {
                !matches!(instruction.operation, flow::FlowOperation::Check { .. })
            }));
            assert_eq!(output.report().passes.len(), 5);
            assert_eq!(
                output.report().passes[3].pass,
                "proven-true-check-elimination-v1"
            );
            assert!(output.report().passes[3].changed);
            assert!(output.report().decisions.iter().any(|decision| {
                decision.pass == "proven-true-check-elimination-v1"
                    && decision.kind == super::DecisionKind::Removed
                    && decision.relied_on == [flow::ProofId(0)]
            }));

            let repeated = CanonicalFlowOptimizer::new()
                .optimize(
                    request(
                        input.clone(),
                        requested_profile.clone(),
                        OptimizationLimits::standard(),
                    ),
                    &|| false,
                )
                .expect("repeat aggressive optimization");
            assert_eq!(repeated, output);

            let idempotent = CanonicalFlowOptimizer::new()
                .optimize(
                    request(
                        output.wir().clone(),
                        requested_profile.clone(),
                        OptimizationLimits::standard(),
                    ),
                    &|| false,
                )
                .expect("idempotent aggressive optimization");
            assert_eq!(idempotent.wir(), output.wir());
            assert!(idempotent.report().passes.iter().all(|pass| !pass.changed));

            let resealed = seal(
                request(input, requested_profile, OptimizationLimits::standard()),
                output.wir().clone().into_wir(),
                output.report().clone(),
                &|| false,
            )
            .expect("exact aggressive output reseals");
            assert_eq!(resealed, output);
        }
    }

    #[test]
    fn aggressive_profiles_are_differentially_equivalent_on_scalar_cfgs() {
        for input in [
            scalar_control_fixture(),
            nontrapping_scalar_control_fixture(),
        ] {
            let expected = execute_scalar_fixture(input.as_wir());
            for level in [OptimizationLevel::Performance, OptimizationLevel::Size] {
                let output = CanonicalFlowOptimizer::new()
                    .optimize(
                        request(
                            input.clone(),
                            profile(level),
                            OptimizationLimits::standard(),
                        ),
                        &|| false,
                    )
                    .expect("differential aggressive optimization");
                assert_eq!(execute_scalar_fixture(output.wir().as_wir()), expected);
            }
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn aggressive_limits_malformed_candidates_and_late_cancellation_fail_closed() {
        for level in [OptimizationLevel::Performance, OptimizationLevel::Size] {
            let input = scalar_control_fixture();
            let requested_profile = profile(level);
            let mut pass_limited = OptimizationLimits::standard();
            pass_limited.passes = 4;
            assert!(matches!(
                CanonicalFlowOptimizer::new().optimize(
                    request(input.clone(), requested_profile.clone(), pass_limited,),
                    &|| false,
                ),
                Err(OptimizeError::ResourceLimit {
                    resource: "optimization passes",
                    limit: 4,
                })
            ));

            let canonical = CanonicalFlowOptimizer::new()
                .optimize(
                    request(
                        input.clone(),
                        requested_profile.clone(),
                        OptimizationLimits::standard(),
                    ),
                    &|| false,
                )
                .expect("canonical aggressive output");
            let mut malformed = canonical.wir().clone().into_wir();
            malformed.functions[0].blocks[0].terminator = flow::Terminator::Jump {
                target: flow::BlockId(u32::MAX),
                arguments: Vec::new(),
            };
            assert!(matches!(
                seal(
                    request(
                        input.clone(),
                        requested_profile.clone(),
                        OptimizationLimits::standard(),
                    ),
                    malformed,
                    canonical.report().clone(),
                    &|| false,
                ),
                Err(OptimizeError::InvalidReport(
                    "optimizer output does not match the canonical transforming pipeline"
                ))
            ));

            let total_polls = Cell::new(0u32);
            CanonicalFlowOptimizer::new()
                .optimize(
                    request(
                        input.clone(),
                        requested_profile.clone(),
                        OptimizationLimits::standard(),
                    ),
                    &|| {
                        total_polls.set(total_polls.get() + 1);
                        false
                    },
                )
                .expect("count aggressive cancellation checkpoints");
            let cancel_at = total_polls.get().saturating_sub(2);
            assert!(cancel_at > 40);
            let polls = Cell::new(0u32);
            let late_cancel = || {
                let next = polls.get() + 1;
                polls.set(next);
                next >= cancel_at
            };
            assert_eq!(
                CanonicalFlowOptimizer::new().optimize(
                    request(input, requested_profile, OptimizationLimits::standard(),),
                    &late_cancel,
                ),
                Err(OptimizeError::Cancelled)
            );
            assert_eq!(polls.get(), cancel_at);
        }
    }

    #[test]
    fn development_pipeline_folds_cfg_compacts_ssa_and_retains_traps() {
        let input = scalar_control_fixture();
        let original_proofs = input.as_wir().proofs.clone();
        let requested_profile = profile(OptimizationLevel::Development);
        let output = CanonicalFlowOptimizer::new()
            .optimize(
                request(
                    input.clone(),
                    requested_profile.clone(),
                    OptimizationLimits::standard(),
                ),
                &|| false,
            )
            .expect("development optimization");

        assert_eq!(output.wir().as_wir().proofs, original_proofs);
        let function = &output.wir().as_wir().functions[0];
        assert_eq!(function.blocks.len(), 4);
        assert!(
            function
                .blocks
                .iter()
                .enumerate()
                .all(|(index, block)| block.id.0 as usize == index)
        );
        assert!(
            function
                .values
                .iter()
                .enumerate()
                .all(|(index, value)| value.id.0 as usize == index)
        );
        let instructions: Vec<_> = function
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect();
        assert_eq!(instructions.len(), 5);
        assert!(matches!(
            instructions[4].operation,
            flow::FlowOperation::Binary {
                op: flow::BinaryOp::AddChecked,
                ..
            }
        ));
        assert!(matches!(
            function.blocks[0].terminator,
            flow::Terminator::Jump {
                target: flow::BlockId(1),
                ..
            }
        ));
        assert!(matches!(
            function.blocks[1].terminator,
            flow::Terminator::Jump {
                target: flow::BlockId(2),
                ..
            }
        ));

        let report = output.report();
        assert_eq!(report.profile, requested_profile);
        assert_eq!(report.passes.len(), 4);
        assert!(report.passes.iter().all(|pass| pass.changed));
        assert!(
            report
                .decisions
                .iter()
                .any(|decision| decision.kind == super::DecisionKind::Folded)
        );
        assert!(
            report
                .decisions
                .iter()
                .any(|decision| decision.kind == super::DecisionKind::Removed)
        );
        assert!(
            report
                .decisions
                .iter()
                .any(|decision| decision.kind == super::DecisionKind::Retained)
        );
        assert!(report.decisions.iter().any(|decision| {
            decision.kind == super::DecisionKind::Retained
                && decision.relied_on == [flow::ProofId(0)]
        }));

        let repeated = CanonicalFlowOptimizer::new()
            .optimize(
                request(
                    input,
                    profile(OptimizationLevel::Development),
                    OptimizationLimits::standard(),
                ),
                &|| false,
            )
            .expect("repeat deterministic development optimization");
        assert_eq!(output, repeated);
    }

    #[test]
    fn development_pipeline_preserves_and_reports_exact_test_metadata() {
        let input = test_metadata_fixture(2);
        let expected_tests = input.as_wir().tests.clone();
        let requested_profile = profile(OptimizationLevel::Development);
        let output = CanonicalFlowOptimizer::new()
            .optimize(
                request(
                    input.clone(),
                    requested_profile.clone(),
                    OptimizationLimits::standard(),
                ),
                &|| false,
            )
            .expect("development optimization with test metadata");
        assert_eq!(output.wir().as_wir().tests, expected_tests);
        assert!(output.report().passes.iter().all(|pass| {
            pass.test_entries_before == 2
                && pass.test_entries_after == 2
                && pass.test_table_preserved
        }));

        let mut limited = OptimizationLimits::standard();
        limited.tests = 1;
        assert!(matches!(
            CanonicalFlowOptimizer::new().optimize(
                request(input.clone(), requested_profile.clone(), limited),
                &|| false,
            ),
            Err(OptimizeError::ResourceLimit {
                resource: "FlowWir tests",
                limit: 1,
            })
        ));

        let canonical = CanonicalFlowOptimizer::new()
            .optimize(
                request(
                    input.clone(),
                    requested_profile.clone(),
                    OptimizationLimits::standard(),
                ),
                &|| false,
            )
            .expect("canonical metadata output");
        let (wir, report) = canonical.into_parts();
        let mut substituted = wir.into_wir();
        substituted.tests[0].timeout_ns += 1;
        assert!(matches!(
            seal(
                request(input, requested_profile, OptimizationLimits::standard()),
                substituted,
                report,
                &|| false,
            ),
            Err(OptimizeError::InvalidReport(
                "optimizer output does not match the canonical transforming pipeline"
            ))
        ));
    }

    #[test]
    fn development_limits_cancellation_and_exact_resealing_fail_closed() {
        let input = scalar_control_fixture();
        let requested_profile = profile(OptimizationLevel::Development);

        let mut limits = OptimizationLimits::standard();
        limits.passes = 3;
        assert!(matches!(
            CanonicalFlowOptimizer::new().optimize(
                request(input.clone(), requested_profile.clone(), limits),
                &|| false,
            ),
            Err(OptimizeError::ResourceLimit {
                resource: "optimization passes",
                limit: 3,
            })
        ));

        let mut limits = OptimizationLimits::standard();
        limits.validation_work = 1;
        assert!(matches!(
            CanonicalFlowOptimizer::new().optimize(
                request(input.clone(), requested_profile.clone(), limits),
                &|| false,
            ),
            Err(OptimizeError::ResourceLimit {
                resource: "validation work",
                limit: 1,
            })
        ));

        let polls = Cell::new(0u32);
        let cancel_during_pipeline = || {
            let next = polls.get() + 1;
            polls.set(next);
            next == 40
        };
        assert_eq!(
            CanonicalFlowOptimizer::new().optimize(
                request(
                    input.clone(),
                    requested_profile.clone(),
                    OptimizationLimits::standard(),
                ),
                &cancel_during_pipeline,
            ),
            Err(OptimizeError::Cancelled)
        );
        assert_eq!(polls.get(), 40);

        let canonical = CanonicalFlowOptimizer::new()
            .optimize(
                request(
                    input.clone(),
                    requested_profile.clone(),
                    OptimizationLimits::standard(),
                ),
                &|| false,
            )
            .expect("canonical development output");
        let (wir, report) = canonical.into_parts();
        let resealed = seal(
            request(
                input.clone(),
                requested_profile.clone(),
                OptimizationLimits::standard(),
            ),
            wir.clone().into_wir(),
            report.clone(),
            &|| false,
        )
        .expect("exact development output reseals");
        assert_eq!(resealed.wir(), &wir);

        let mut substituted_report = report;
        substituted_report.decisions[0]
            .justification
            .push_str(" substituted");
        assert!(matches!(
            seal(
                request(input, requested_profile, OptimizationLimits::standard(),),
                wir.into_wir(),
                substituted_report,
                &|| false,
            ),
            Err(OptimizeError::InvalidReport(
                "optimizer report does not match the canonical transforming pipeline"
            ))
        ));
    }

    #[test]
    fn exact_model_report_and_work_limits_are_accepted_and_enforced() {
        let input = lowered_fixture();
        let requested_profile = profile(OptimizationLevel::None);
        let limits = exact_limits(&input, &requested_profile);

        CanonicalFlowOptimizer::new()
            .optimize(
                request(input.clone(), requested_profile.clone(), limits),
                &|| false,
            )
            .expect("exact limits");

        for (resource, reduced) in [
            (
                "FlowWir model edges",
                OptimizationLimits {
                    model_edges: limits.model_edges - 1,
                    ..limits
                },
            ),
            (
                "FlowWir payload bytes",
                OptimizationLimits {
                    payload_bytes: limits.payload_bytes - 1,
                    ..limits
                },
            ),
            (
                "optimization report bytes",
                OptimizationLimits {
                    report_bytes: limits.report_bytes - 1,
                    ..limits
                },
            ),
            (
                "optimizer work",
                OptimizationLimits {
                    work: limits.work - 1,
                    ..limits
                },
            ),
        ] {
            assert!(matches!(
                CanonicalFlowOptimizer::new().optimize(
                    request(input.clone(), requested_profile.clone(), reduced),
                    &|| false,
                ),
                Err(OptimizeError::ResourceLimit {
                    resource: actual,
                    ..
                }) if actual == resource
            ));
        }
    }

    #[test]
    fn cancellation_is_observed_at_entry_and_during_model_scan() {
        assert_eq!(
            CanonicalFlowOptimizer::new().optimize(
                request(
                    lowered_fixture(),
                    profile(OptimizationLevel::None),
                    OptimizationLimits::standard(),
                ),
                &|| true,
            ),
            Err(OptimizeError::Cancelled)
        );

        let polls = Cell::new(0u32);
        let cancel_during_function_scan = || {
            let next = polls.get() + 1;
            polls.set(next);
            next == 12
        };
        assert_eq!(
            CanonicalFlowOptimizer::new().optimize(
                request(
                    lowered_fixture(),
                    profile(OptimizationLevel::None),
                    OptimizationLimits::standard(),
                ),
                &cancel_during_function_scan,
            ),
            Err(OptimizeError::Cancelled)
        );
        assert_eq!(polls.get(), 12);

        let report = OptimizationReport {
            profile: profile(OptimizationLevel::None),
            passes: (0..3)
                .map(|index| PassStatistics {
                    pass: format!("untrusted-pass-{index}"),
                    iterations: 1,
                    changed: false,
                    instructions_before: 0,
                    instructions_after: 0,
                    test_entries_before: 0,
                    test_entries_after: 0,
                    test_table_preserved: true,
                })
                .collect(),
            decisions: Vec::new(),
        };
        let report_polls = Cell::new(0u32);
        let cancel_during_report_scan = || {
            let next = report_polls.get() + 1;
            report_polls.set(next);
            next == 4
        };
        let limits = OptimizationLimits::standard();
        let mut work = WorkMeter::new(limits.work, &cancel_during_report_scan);
        assert_eq!(
            scan_report(&report, limits, &mut work),
            Err(OptimizeError::Cancelled)
        );
        assert_eq!(report_polls.get(), 4);
    }

    #[test]
    fn exact_model_comparison_polls_a_long_valid_prefix_at_the_exact_stop() {
        let mut model = lowered_fixture().into_wir();
        model.name = "m".repeat(CANCELLABLE_COMPARISON_CHUNK_BYTES * 3 + 1);
        let model = model
            .validate()
            .expect("valid long-prefix FlowWir v14 model");
        let equal = model.clone();

        let all_polls = Cell::new(0_u32);
        let count_polls = || {
            all_polls.set(all_polls.get() + 1);
            false
        };
        let mut work = WorkMeter::new(OptimizationLimits::standard().work, &count_polls);
        assert!(
            flow_wir_equal(model.as_wir(), equal.as_wir(), &mut work)
                .expect("equal validated models compare")
        );
        assert!(all_polls.get() > 7);

        // Polls 3, 4, and 5 precede the first three 64-KiB host comparisons
        // of the image name. Cancellation therefore stops before a third
        // project-sized chunk can be inspected.
        let cancelled_polls = Cell::new(0_u32);
        let cancel_on_third_name_chunk = || {
            let next = cancelled_polls.get() + 1;
            cancelled_polls.set(next);
            next == 5
        };
        let mut work = WorkMeter::new(
            OptimizationLimits::standard().work,
            &cancel_on_third_name_chunk,
        );
        assert_eq!(
            flow_wir_equal(model.as_wir(), equal.as_wir(), &mut work),
            Err(OptimizeError::Cancelled)
        );
        assert_eq!(cancelled_polls.get(), 5);

        let mut substituted = equal.into_wir();
        assert_eq!(substituted.name.pop(), Some('m'));
        substituted.name.push('n');
        let substituted = substituted
            .validate()
            .expect("valid same-length substituted FlowWir v14 model");
        let mut work = WorkMeter::new(OptimizationLimits::standard().work, &|| false);
        assert!(
            !flow_wir_equal(model.as_wir(), substituted.as_wir(), &mut work)
                .expect("substituted validated models compare")
        );
    }

    #[test]
    fn compiled_test_group_scan_has_exact_bounds_and_nested_equality() {
        let mut model = test_metadata_fixture(1).into_wir();
        let group = model
            .compiled_test_group
            .as_mut()
            .expect("fixture has a compiled group");
        group.name = "g".repeat(CANCELLABLE_COMPARISON_CHUNK_BYTES * 2 + 1);
        let model = model
            .validate()
            .expect("valid FlowWir v14 compiled-group fixture");
        let group = model
            .as_wir()
            .compiled_test_group
            .as_ref()
            .expect("validated fixture retains compiled group");
        let group_payload = group
            .name
            .len()
            .checked_add(match &group.root {
                wrela_test_model::ImageRoot::GeneratedHarness { harness_name } => {
                    harness_name.len()
                }
                wrela_test_model::ImageRoot::Declared { image_name, .. } => image_name.len(),
            })
            .and_then(|total| {
                group.tests.iter().try_fold(total, |total, test| {
                    total.checked_add(test.descriptor.name.len())
                })
            })
            .and_then(|total| u64::try_from(total).ok())
            .expect("fixture payload fits u64");

        let mut exact = OptimizationLimits::standard();
        exact.test_plan.payload_bytes = group_payload;
        let mut work = WorkMeter::new(exact.work, &|| false);
        scan_model(model.as_wir(), exact, &mut work).expect("exact group payload limit");

        let mut over = exact;
        over.test_plan.payload_bytes -= 1;
        let mut work = WorkMeter::new(over.work, &|| false);
        assert!(matches!(
            scan_model(model.as_wir(), over, &mut work),
            Err(OptimizeError::ResourceLimit {
                resource: "compiled test-group payload bytes",
                limit,
            }) if limit == over.test_plan.payload_bytes
        ));

        let mut substituted = model.clone().into_wir();
        let substituted_name = &mut substituted
            .compiled_test_group
            .as_mut()
            .expect("candidate has a compiled group")
            .name;
        assert_eq!(substituted_name.pop(), Some('g'));
        substituted_name.push('h');
        let substituted = substituted
            .validate()
            .expect("valid nested group-name substitution");
        let mut work = WorkMeter::new(OptimizationLimits::standard().work, &|| false);
        assert!(
            !flow_wir_equal(model.as_wir(), substituted.as_wir(), &mut work)
                .expect("nested compiled groups compare")
        );
    }

    #[test]
    fn exact_report_comparison_polls_and_rejects_long_prefix_substitution() {
        let long_justification = "j".repeat(CANCELLABLE_COMPARISON_CHUNK_BYTES * 3 + 1);
        let report = OptimizationReport {
            profile: profile(OptimizationLevel::Development),
            passes: Vec::new(),
            decisions: vec![OptimizationDecision {
                pass: "scalar-fold".to_owned(),
                subject: "function 0 block 0 instruction 0".to_owned(),
                kind: super::DecisionKind::Retained,
                justification: long_justification,
                relied_on: vec![flow::ProofId(0)],
            }],
        };
        let equal = report.clone();
        let mut work = WorkMeter::new(OptimizationLimits::standard().work, &|| false);
        assert!(
            optimization_report_equal(&report, &equal, &mut work)
                .expect("equal bounded reports compare")
        );

        // The twentieth poll is immediately before the third 64-KiB
        // justification chunk for this fixed report shape.
        let polls = Cell::new(0_u32);
        let cancel_on_third_justification_chunk = || {
            let next = polls.get() + 1;
            polls.set(next);
            next == 20
        };
        let mut work = WorkMeter::new(
            OptimizationLimits::standard().work,
            &cancel_on_third_justification_chunk,
        );
        assert_eq!(
            optimization_report_equal(&report, &equal, &mut work),
            Err(OptimizeError::Cancelled)
        );
        assert_eq!(polls.get(), 20);

        let mut substituted = equal;
        let justification = &mut substituted.decisions[0].justification;
        assert_eq!(justification.pop(), Some('j'));
        justification.push('k');
        let mut work = WorkMeter::new(OptimizationLimits::standard().work, &|| false);
        assert!(
            !optimization_report_equal(&report, &substituted, &mut work)
                .expect("same-length report substitution compares")
        );
    }

    #[test]
    fn none_sealer_rejects_a_valid_long_prefix_model_substitution() {
        let mut input = lowered_fixture().into_wir();
        input.name = "s".repeat(CANCELLABLE_COMPARISON_CHUNK_BYTES * 3 + 1);
        let input = input.validate().expect("valid long-prefix input");
        let mut candidate = input.clone().into_wir();
        assert_eq!(candidate.name.pop(), Some('s'));
        candidate.name.push('t');
        let candidate = candidate
            .validate()
            .expect("candidate substitution remains valid")
            .into_wir();
        let requested_profile = profile(OptimizationLevel::None);
        let report = OptimizationReport {
            profile: requested_profile.clone(),
            passes: Vec::new(),
            decisions: Vec::new(),
        };
        assert!(matches!(
            seal(
                request(input, requested_profile, OptimizationLimits::standard(),),
                candidate,
                report,
                &|| false,
            ),
            Err(OptimizeError::InvalidReport(
                "optimization level `none` did not preserve FlowWir exactly"
            ))
        ));
    }

    #[test]
    fn sealer_rejects_model_and_report_substitution() {
        let input = lowered_fixture();
        let requested_profile = profile(OptimizationLevel::None);
        let mut substituted = input.clone().into_wir();
        substituted.proofs[0].explanation[0].push_str(" substituted");
        let report = OptimizationReport {
            profile: requested_profile.clone(),
            passes: Vec::new(),
            decisions: Vec::new(),
        };
        assert!(matches!(
            seal(
                request(
                    input.clone(),
                    requested_profile.clone(),
                    OptimizationLimits::standard(),
                ),
                substituted,
                report,
                &|| false,
            ),
            Err(OptimizeError::InvalidReport(
                "optimization level `none` did not preserve FlowWir exactly"
            ))
        ));

        let exact = input.clone().into_wir();
        let report = OptimizationReport {
            profile: profile(OptimizationLevel::None),
            passes: Vec::new(),
            decisions: Vec::new(),
        };
        let mut substituted_request_profile = requested_profile;
        substituted_request_profile.verify_after_each_pass = false;
        assert!(matches!(
            seal(
                request(
                    input,
                    substituted_request_profile,
                    OptimizationLimits::standard(),
                ),
                exact,
                report,
                &|| false,
            ),
            Err(OptimizeError::InvalidProfile(
                "optimization policy parameters are noncanonical"
            ))
        ));
    }
}
