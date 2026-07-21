//! Total lowering contract from validated [`SemanticWir`](wrela_semantic_wir::SemanticWir)
//! into target-independent typed SSA [`FlowWir`].
//!
//! This crate owns control-flow construction, async state-machine expansion,
//! cleanup paths, and the translation of semantic proof obligations. It does
//! not optimize, select a target ABI, or call the runtime.

#![forbid(unsafe_code)]

use std::fmt;

use wrela_diagnostics::{Diagnostic, Severity, WithDiagnostics};
use wrela_flow_wir::{
    self as flow, FlowWir, FunctionOrigin, FunctionRole, TestPlanLimits, ValidatedFlowWir,
    ValidationErrors, ValidationFailure, ValidationLimits,
};
pub use wrela_flow_wir::{
    BinaryOp as FlowBinaryOp, FlowOperation, FlowTypeKind, Terminator, TypeId as FlowTypeId,
};
use wrela_semantic_wir::{
    self as semantic, FunctionOrigin as SemanticFunctionOrigin,
    FunctionRole as SemanticFunctionRole, ValidatedSemanticWir,
};

/// Finite resources for one lowering invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoweringLimits {
    /// Maximum number of FlowWir blocks constructed across the whole image.
    pub blocks: u64,
    /// Maximum number of FlowWir instructions constructed across the image.
    pub instructions: u64,
    /// Maximum number of generated async states in any one function.
    pub states_per_function: u32,
    /// Maximum nesting depth accepted while lowering structured regions.
    pub region_depth: u32,
    /// Total elements across all variable-length FlowWir collections.
    pub model_edges: u64,
    /// Total UTF-8 and byte-string payload retained in FlowWir.
    pub payload_bytes: u64,
    /// Conservative upper bound for FlowWir validation and dominance work.
    pub validation_work: u64,
    /// Maximum structural validation errors retained before failing closed.
    pub validation_errors: u32,
    /// Exact finite policy for any compiled test-group binding in the output.
    pub test_plan: TestPlanLimits,
    pub diagnostics: u32,
    pub diagnostic_bytes: u64,
}

impl LoweringLimits {
    /// Conservative default suitable for normal compiler operation.
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            blocks: 16_000_000,
            instructions: 256_000_000,
            states_per_function: 1_000_000,
            region_depth: 1024,
            model_edges: 1_000_000_000,
            payload_bytes: 4 * 1024 * 1024 * 1024,
            validation_work: 1_100_000_000_000,
            validation_errors: 100_000,
            test_plan: TestPlanLimits::standard(),
            diagnostics: 100_000,
            diagnostic_bytes: 64 * 1024 * 1024,
        }
    }

    /// Reject zero limits before work begins.
    pub fn validate(self) -> Result<(), LowerError> {
        if self.blocks == 0
            || self.instructions == 0
            || self.states_per_function == 0
            || self.region_depth == 0
            || self.region_depth > 1024
            || self.model_edges == 0
            || self.payload_bytes == 0
            || self.validation_work == 0
            || self.validation_errors == 0
            || !self.test_plan.is_valid()
            || self.diagnostics == 0
            || self.diagnostic_bytes == 0
        {
            return Err(LowerError::InvalidLimits);
        }
        Ok(())
    }
}

/// Immutable input to SemanticWir-to-FlowWir lowering.
#[derive(Debug)]
pub struct LowerRequest {
    /// Semantically complete and structurally validated whole image.
    pub input: ValidatedSemanticWir,
    /// Explicit denial-of-service bounds for compiler-created data.
    pub limits: LoweringLimits,
}

/// Non-fatal observations retained for diagnostics and optimization reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoweringReport {
    pub source_functions: u32,
    pub generated_functions: u32,
    pub blocks: u64,
    pub instructions: u64,
    /// Number of emitted `Suspend` terminators.
    pub async_states: u64,
    /// Direct or tail-call edges whose target has `FunctionRole::Cleanup`.
    pub cleanup_edges: u64,
    /// Total proof records in the output FlowWir.
    pub output_proofs: u64,
}

/// Complete successful output. Its report and canonical warning list are
/// sealed together with the validated IR and cannot be replaced independently.
#[derive(Debug, Clone, PartialEq)]
pub struct LowerOutput {
    validated: ValidatedFlowWir,
    report: LoweringReport,
    diagnostics: Vec<Diagnostic>,
}

impl LowerOutput {
    #[must_use]
    pub fn wir(&self) -> &ValidatedFlowWir {
        &self.validated
    }

    #[must_use]
    pub fn report(&self) -> &LoweringReport {
        &self.report
    }

    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    #[must_use]
    pub fn into_parts(self) -> (ValidatedFlowWir, LoweringReport, Vec<Diagnostic>) {
        (self.validated, self.report, self.diagnostics)
    }
}

/// Implementation boundary used by the driver and by isolated crate tests.
/// Implementations must be deterministic and poll `is_cancelled` at bounded
/// intervals; cancellation is never represented as a partially valid FlowWir.
pub trait FlowLowerer {
    fn lower(
        &self,
        request: LowerRequest,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<LowerOutput, LowerError>;
}

/// Production lowering for the executable SemanticWir surface currently
/// representable by FlowWir: the minimum declared image, synchronous generated
/// integration-test images and their ordinary scalar helper closure, plus the
/// exact plans and scalar/call/await bodies of stateless actor/task images.
/// Async calls produce strict-linear FlowWir activations and suspension resumes
/// through an explicit result block parameter, including for unit results.
/// Test protocol effects remain explicit. Every operation without an exact
/// FlowWir representation fails closed instead of being approximated with
/// fabricated runtime state.
#[derive(Debug, Clone, Copy, Default)]
pub struct CanonicalFlowLowerer;

impl CanonicalFlowLowerer {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl FlowLowerer for CanonicalFlowLowerer {
    fn lower(
        &self,
        request: LowerRequest,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<LowerOutput, LowerError> {
        check_cancelled(is_cancelled)?;
        request.limits.validate()?;
        preflight_input(request.input.as_wir(), request.limits, is_cancelled)?;
        let supported = supported_input(request.input.as_wir(), request.limits, is_cancelled)?;
        let wir = match supported {
            SupportedSemantic::Minimum(minimum) => {
                lower_minimum(minimum, request.limits, is_cancelled)?
            }
            SupportedSemantic::ActorImage(actor) => {
                lower_actor_image(actor, request.limits, is_cancelled)?
            }
            SupportedSemantic::GeneratedTests(generated) => {
                lower_generated_tests(generated, request.limits, is_cancelled)?
            }
        };
        let report = report_for(&wir, request.input.as_wir(), request.limits, is_cancelled)?;
        check_cancelled(is_cancelled)?;
        seal(&request, wir, report, Vec::new(), is_cancelled)
    }
}

/// Failure to produce a sealed FlowWir value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LowerError {
    Cancelled,
    InvalidLimits,
    /// The input is valid SemanticWir, but this lowering implementation does
    /// not yet have an exact operation-level translation for the feature.
    UnsupportedInput {
        feature: &'static str,
    },
    ResourceLimit {
        resource: &'static str,
        limit: u64,
    },
    InvalidReport(&'static str),
    ErrorDiagnosticOnSuccess,
    InternalInvariant {
        operation: String,
        detail: String,
    },
    InvalidOutput(ValidationErrors),
}

impl From<ValidationErrors> for LowerError {
    fn from(value: ValidationErrors) -> Self {
        Self::InvalidOutput(value)
    }
}

impl fmt::Display for LowerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("FlowWir lowering was cancelled"),
            Self::InvalidLimits => formatter.write_str("FlowWir lowering limits must be nonzero"),
            Self::UnsupportedInput { feature } => {
                write!(formatter, "unsupported SemanticWir input: {feature}")
            }
            Self::ResourceLimit { resource, limit } => {
                write!(
                    formatter,
                    "FlowWir lowering exceeded {resource} limit {limit}"
                )
            }
            Self::InvalidReport(reason) => {
                write!(formatter, "invalid FlowWir lowering report: {reason}")
            }
            Self::ErrorDiagnosticOnSuccess => {
                formatter.write_str("successful FlowWir lowering cannot contain error diagnostics")
            }
            Self::InternalInvariant { operation, detail } => {
                write!(
                    formatter,
                    "FlowWir lowering invariant failed in {operation}: {detail}"
                )
            }
            Self::InvalidOutput(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for LowerError {}

#[derive(Debug, Clone, Copy)]
struct MinimumSemantic<'a> {
    input: &'a semantic::SemanticWir,
    ty: &'a semantic::TypeRecord,
    function: &'a semantic::SemanticFunction,
    constructor: u32,
}

#[derive(Debug, Clone, Copy)]
struct GeneratedTestSemantic<'a> {
    input: &'a semantic::SemanticWir,
    harness: &'a semantic::SemanticFunction,
}

#[derive(Debug, Clone, Copy)]
struct ActorImageSemantic<'a> {
    input: &'a semantic::SemanticWir,
}

#[derive(Debug, Clone, Copy)]
enum SupportedSemantic<'a> {
    Minimum(MinimumSemantic<'a>),
    ActorImage(ActorImageSemantic<'a>),
    GeneratedTests(GeneratedTestSemantic<'a>),
}

fn unsupported(feature: &'static str) -> LowerError {
    LowerError::UnsupportedInput { feature }
}

fn supported_input<'a>(
    input: &'a semantic::SemanticWir,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<SupportedSemantic<'a>, LowerError> {
    if input.tests.is_empty() {
        if input.actors.is_empty()
            && input.tasks.is_empty()
            && input.regions.is_empty()
            && input.activations.is_empty()
        {
            supported_minimum(input).map(SupportedSemantic::Minimum)
        } else {
            supported_actor_image(input, limits, is_cancelled).map(SupportedSemantic::ActorImage)
        }
    } else {
        supported_generated_tests(input, limits, is_cancelled)
            .map(SupportedSemantic::GeneratedTests)
    }
}

fn supported_minimum(input: &semantic::SemanticWir) -> Result<MinimumSemantic<'_>, LowerError> {
    if !input.globals.is_empty()
        || !input.actors.is_empty()
        || !input.tasks.is_empty()
        || !input.devices.is_empty()
        || !input.pools.is_empty()
        || !input.regions.is_empty()
        || !input.activations.is_empty()
        || !input.scopes.is_empty()
        || !input.tests.is_empty()
    {
        return Err(unsupported(
            "nonempty runtime plans, scopes, globals, or tests",
        ));
    }
    if input.startup_order.as_slice() != [semantic::ImageOwner::Runtime]
        || input.shutdown_order.as_slice() != [semantic::ImageOwner::Runtime]
        || input.static_bytes != 0
        || input.peak_bytes != 0
    {
        return Err(unsupported("nonempty runtime ownership or memory plans"));
    }
    if input.source_summary.reachable_declarations != 1
        || input.source_summary.monomorphized_instantiations != 1
        || input.source_summary.resolved_interface_calls != 0
    {
        return Err(unsupported(
            "non-minimum source and specialization summaries",
        ));
    }
    let [ty] = input.types.as_slice() else {
        return Err(unsupported(
            "semantic type sets other than the minimum unit type",
        ));
    };
    if ty.id != semantic::TypeId(0)
        || ty.source_name != "unit"
        || ty.kind != semantic::TypeKind::Primitive(semantic::PrimitiveType::Unit)
        || ty.linearity != semantic::Linearity::CopyScalar
        || ty.source.is_some()
    {
        return Err(unsupported(
            "semantic types other than the canonical unit type",
        ));
    }
    let [function] = input.functions.as_slice() else {
        return Err(unsupported("multiple semantic function instances"));
    };
    let constructor = match function.origin {
        semantic::FunctionOrigin::GeneratedImageEntry { constructor } => constructor,
        semantic::FunctionOrigin::Source
        | semantic::FunctionOrigin::GeneratedTestHarness { .. } => {
            return Err(unsupported("source functions or generated test harnesses"));
        }
    };
    if function.id != semantic::FunctionId(0)
        || input.image_entry != function.id
        || function.role != semantic::FunctionRole::ImageEntry
        || function.color != semantic::FunctionColor::Sync
        || !function.parameters.is_empty()
        || function.result != semantic::TypeId(0)
        || !function.values.is_empty()
        || function.effects != semantic::EffectSet(semantic::EffectSet::FIRMWARE)
        || function.source.is_some()
        || function.stack_bound != 0
        || function.frame_bound != 0
        || function.uninterrupted_bound != Some(1)
        || function.recursive_depth_bound != Some(1)
    {
        return Err(unsupported("noncanonical generated image entries"));
    }
    if !function.body.parameters.is_empty()
        || !matches!(
            function.body.statements.as_slice(),
            [semantic::SemanticStatement::Return(values)] if values.is_empty()
        )
    {
        return Err(unsupported("semantic operations or structured bodies"));
    }
    if input.proofs.len() != 3
        || !matches!(input.proofs[0].kind, semantic::ProofKind::TypeChecked)
        || !matches!(input.proofs[1].kind, semantic::ProofKind::EffectsAllowed)
        || !matches!(input.proofs[2].kind, semantic::ProofKind::ImageClosed)
        || function.proofs.as_slice()
            != [
                semantic::ProofId(0),
                semantic::ProofId(1),
                semantic::ProofId(2),
            ]
    {
        return Err(unsupported("noncanonical minimum-image proof sets"));
    }
    Ok(MinimumSemantic {
        input,
        ty,
        function,
        constructor,
    })
}

fn supported_actor_image<'a>(
    input: &'a semantic::SemanticWir,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ActorImageSemantic<'a>, LowerError> {
    if !input.scopes.is_empty() {
        return Err(unsupported(
            "flow-scope-cleanup-lowering-pending (normal-exit cleanup calls)",
        ));
    }
    if !input.globals.is_empty()
        || !input.devices.is_empty()
        || !input.pools.is_empty()
        || !input.tests.is_empty()
        || input.compiled_test_group.is_some()
        || input.actors.is_empty()
        || input.regions.is_empty()
    {
        return Err(unsupported(
            "actor images outside the stateless actor/task/region plan slice",
        ));
    }

    for ty in &input.types {
        check_cancelled(is_cancelled)?;
        match &ty.kind {
            semantic::TypeKind::Primitive(primitive)
                if supported_scalar_primitive(*primitive)
                    && ty.linearity == semantic::Linearity::CopyScalar => {}
            semantic::TypeKind::Array { .. }
                if ty.linearity == semantic::Linearity::ExplicitCopy => {}
            semantic::TypeKind::Struct { fields }
                if fields.is_empty()
                    && matches!(
                        ty.linearity,
                        semantic::Linearity::Reclaimable | semantic::Linearity::Strict
                    ) => {}
            semantic::TypeKind::ActorHandle { actor_type }
                if ty.linearity == semantic::Linearity::ExplicitCopy
                    && ty.source.is_none()
                    && input.types.get(actor_type.0 as usize).is_some()
                    && input
                        .actors
                        .iter()
                        .filter(|actor| actor.ty == *actor_type)
                        .count()
                        == 1 => {}
            semantic::TypeKind::Reservation
                if ty.linearity == semantic::Linearity::Strict && ty.source.is_none() => {}
            semantic::TypeKind::Function(function) => {
                if (function.result.0 as usize) >= input.types.len() {
                    return Err(unsupported(
                        "actor types outside the stateless scalar slice",
                    ));
                }
                for parameter in &function.parameters {
                    check_cancelled(is_cancelled)?;
                    if (parameter.ty.0 as usize) >= input.types.len() {
                        return Err(unsupported(
                            "actor types outside the stateless scalar slice",
                        ));
                    }
                }
            }
            _ => {
                return Err(unsupported(
                    "actor types outside the stateless scalar slice",
                ));
            }
        }
    }
    validate_actor_plan_contract(input, limits, is_cancelled)?;

    let entry = input
        .functions
        .get(input.image_entry.0 as usize)
        .ok_or(unsupported("actor image entry identity"))?;
    let constructor = match entry.origin {
        semantic::FunctionOrigin::GeneratedImageEntry { constructor } => constructor,
        semantic::FunctionOrigin::Source
        | semantic::FunctionOrigin::GeneratedTestHarness { .. } => {
            return Err(unsupported("actor image entry origin"));
        }
    };
    let expected_entry_effects = semantic::EffectSet::FIRMWARE
        | semantic::EffectSet::ACTOR_CALL
        | semantic::EffectSet::TASK_SPAWN;
    if entry.role != semantic::FunctionRole::ImageEntry
        || entry.color != semantic::FunctionColor::Sync
        || !entry.parameters.is_empty()
        || !semantic_type_is(input, entry.result, semantic::PrimitiveType::Unit)
        || !entry.values.is_empty()
        || entry.effects != semantic::EffectSet(expected_entry_effects)
        || entry.source.is_some()
        || entry.stack_bound != 0
        || entry.frame_bound != 0
        || entry.uninterrupted_bound.is_none_or(|bound| bound == 0)
        || entry.recursive_depth_bound.is_none_or(|bound| bound == 0)
        || !entry.body.parameters.is_empty()
        || !matches!(
            entry.body.statements.as_slice(),
            [semantic::SemanticStatement::Return(values)] if values.is_empty()
        )
        || constructor >= input.source_summary.hir_declarations
    {
        return Err(unsupported("noncanonical stateless actor image entry"));
    }

    for function in &input.functions {
        check_cancelled(is_cancelled)?;
        if function.id == entry.id {
            continue;
        }
        validate_actor_source_function(input, function, limits, is_cancelled)?;
    }
    Ok(ActorImageSemantic { input })
}

fn validate_actor_plan_contract(
    input: &semantic::SemanticWir,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LowerError> {
    let mut state_region_count = 0usize;
    for actor in &input.actors {
        check_cancelled(is_cancelled)?;
        for region in &input.regions {
            check_cancelled(is_cancelled)?;
            if region.owner == semantic::ImageOwner::Actor(actor.id)
                && polled_joined_name_matches(&region.name, &actor.name, ".state", is_cancelled)?
            {
                state_region_count =
                    state_region_count
                        .checked_add(1)
                        .ok_or(LowerError::ResourceLimit {
                            resource: "actor region plan",
                            limit: limits.model_edges,
                        })?;
            }
        }
    }
    let expected_regions = input
        .actors
        .len()
        .checked_add(state_region_count)
        .and_then(|count| {
            count.checked_add(
                input
                    .actors
                    .iter()
                    .filter(|actor| !actor.turn_functions.is_empty())
                    .count(),
            )
        })
        .and_then(|count| count.checked_add(input.tasks.len()))
        .and_then(|count| count.checked_add(input.activations.len()))
        .ok_or(LowerError::ResourceLimit {
            resource: "actor region plan",
            limit: limits.model_edges,
        })?;
    if input.regions.len() != expected_regions {
        return Err(unsupported("noncanonical actor mailbox/frame region plan"));
    }
    let capacity_proof_matches =
        |region: &semantic::RegionRecord, bound: u64, region_is_proof_source: bool| {
            input
                .proofs
                .get(region.proof.0 as usize)
                .is_some_and(|proof| {
                    proof.id == region.proof
                        && proof.kind == semantic::ProofKind::CapacityBound
                        && proof.bound == Some(bound)
                        && proof.sources.len() == 1
                        && (!region_is_proof_source || proof.sources[0] == region.source)
                })
        };
    let mut static_bytes = 0_u64;
    let mut region_cursor = 0usize;
    for actor in &input.actors {
        check_cancelled(is_cancelled)?;
        let mailbox = input
            .regions
            .get(region_cursor)
            .ok_or(unsupported("actor mailbox region identity"))?;
        region_cursor = region_cursor
            .checked_add(1)
            .ok_or(LowerError::ResourceLimit {
                resource: "actor region identity",
                limit: limits.model_edges,
            })?;
        let mailbox_bytes =
            u64::from(actor.mailbox_capacity)
                .checked_mul(16)
                .ok_or(LowerError::ResourceLimit {
                    resource: "actor mailbox bytes",
                    limit: limits.model_edges,
                })?;
        let mailbox_name_matches =
            polled_joined_name_matches(&mailbox.name, &actor.name, ".mailbox", is_cancelled)?;
        if !mailbox_name_matches
            || mailbox.class != semantic::RegionClass::Image
            || mailbox.capacity_bytes != mailbox_bytes
            || mailbox.alignment != 8
            || mailbox.owner != semantic::ImageOwner::Actor(actor.id)
            || !capacity_proof_matches(mailbox, u64::from(actor.mailbox_capacity), false)
        {
            return Err(unsupported("noncanonical actor mailbox capacity plan"));
        }
        static_bytes =
            static_bytes
                .checked_add(mailbox_bytes)
                .ok_or(LowerError::ResourceLimit {
                    resource: "actor static bytes",
                    limit: limits.model_edges,
                })?;
        let has_state = if let Some(region) = input.regions.get(region_cursor) {
            region.owner == semantic::ImageOwner::Actor(actor.id)
                && polled_joined_name_matches(&region.name, &actor.name, ".state", is_cancelled)?
        } else {
            false
        };
        if has_state {
            let state = input
                .regions
                .get(region_cursor)
                .ok_or(unsupported("actor state region identity"))?;
            region_cursor = region_cursor
                .checked_add(1)
                .ok_or(LowerError::ResourceLimit {
                    resource: "actor region identity",
                    limit: limits.model_edges,
                })?;
            if state.class != semantic::RegionClass::Image
                || state.capacity_bytes != 8
                || state.alignment != 8
                || state.owner != semantic::ImageOwner::Actor(actor.id)
                || !capacity_proof_matches(state, 1, true)
                || input
                    .proofs
                    .get(state.proof.0 as usize)
                    .is_none_or(|proof| !proof.depends_on.is_empty())
            {
                return Err(unsupported("noncanonical actor state capacity plan"));
            }
            static_bytes = static_bytes
                .checked_add(8)
                .ok_or(LowerError::ResourceLimit {
                    resource: "actor static bytes",
                    limit: limits.model_edges,
                })?;
        }
        if !actor.turn_functions.is_empty() {
            let turn = input
                .regions
                .get(region_cursor)
                .ok_or(unsupported("actor turn-frame region identity"))?;
            region_cursor = region_cursor
                .checked_add(1)
                .ok_or(LowerError::ResourceLimit {
                    resource: "actor region identity",
                    limit: limits.model_edges,
                })?;
            let mut turn_frame_bytes = 1_u64;
            for function in &actor.turn_functions {
                check_cancelled(is_cancelled)?;
                let function = input
                    .functions
                    .get(function.0 as usize)
                    .ok_or(unsupported("actor turn-frame function identity"))?;
                turn_frame_bytes = turn_frame_bytes.max(function.frame_bound.max(1));
            }
            let turn_name_matches =
                polled_joined_name_matches(&turn.name, &actor.name, ".turn-frame", is_cancelled)?;
            if !turn_name_matches
                || turn.class != semantic::RegionClass::TaskFrame
                || turn.capacity_bytes != turn_frame_bytes
                || turn.alignment != 8
                || turn.owner != semantic::ImageOwner::Actor(actor.id)
                || !capacity_proof_matches(turn, 1, true)
            {
                return Err(unsupported("noncanonical actor turn-frame capacity plan"));
            }
            static_bytes =
                static_bytes
                    .checked_add(turn_frame_bytes)
                    .ok_or(LowerError::ResourceLimit {
                        resource: "actor static bytes",
                        limit: limits.model_edges,
                    })?;
        }
    }
    let task_region_start = region_cursor;
    for (index, task) in input.tasks.iter().enumerate() {
        check_cancelled(is_cancelled)?;
        let function = input
            .functions
            .get(task.entry.0 as usize)
            .ok_or(unsupported("actor task entry identity"))?;
        let frame_bytes = function.frame_bound.max(1);
        let capacity_bytes =
            frame_bytes
                .checked_mul(u64::from(task.slots))
                .ok_or(LowerError::ResourceLimit {
                    resource: "actor task-frame bytes",
                    limit: limits.model_edges,
                })?;
        let region = input
            .regions
            .get(task_region_start + index)
            .ok_or(unsupported("actor task-frame region identity"))?;
        let region_name_matches =
            polled_joined_name_matches(&region.name, &task.name, ".frame", is_cancelled)?;
        if !region_name_matches
            || region.class != semantic::RegionClass::TaskFrame
            || region.capacity_bytes != capacity_bytes
            || region.alignment != 8
            || region.owner != semantic::ImageOwner::Task(task.id)
            || !capacity_proof_matches(region, u64::from(task.slots), true)
        {
            return Err(unsupported("noncanonical actor task-frame capacity plan"));
        }
        static_bytes =
            static_bytes
                .checked_add(capacity_bytes)
                .ok_or(LowerError::ResourceLimit {
                    resource: "actor static bytes",
                    limit: limits.model_edges,
                })?;
    }
    for activation in &input.activations {
        check_cancelled(is_cancelled)?;
        let caller = input
            .functions
            .get(activation.caller.0 as usize)
            .ok_or(unsupported("actor activation caller identity"))?;
        if let semantic::FunctionRole::TaskEntry(task) = caller.role {
            if input
                .tasks
                .get(task.0 as usize)
                .is_none_or(|task| task.slots != 1)
            {
                return Err(unsupported("multi-slot task activation capacity"));
            }
        }
        let capacity_bytes = activation
            .frame_bytes
            .checked_mul(u64::from(activation.maximum_live))
            .ok_or(LowerError::ResourceLimit {
                resource: "actor activation bytes",
                limit: limits.model_edges,
            })?;
        let region = input
            .regions
            .get(activation.region.0 as usize)
            .ok_or(unsupported("actor activation region identity"))?;
        let region_name_matches = polled_joined_name_matches(
            &region.name,
            &caller.name,
            ".async-activation-frame",
            is_cancelled,
        )?;
        if region.class != semantic::RegionClass::TaskFrame
            || !region_name_matches
            || region.capacity_bytes != capacity_bytes
            || region.proof != activation.capacity_proof
            || region.source != activation.source
            || !capacity_proof_matches(region, u64::from(activation.maximum_live), true)
        {
            return Err(unsupported("noncanonical actor activation capacity plan"));
        }
        static_bytes =
            static_bytes
                .checked_add(capacity_bytes)
                .ok_or(LowerError::ResourceLimit {
                    resource: "actor static bytes",
                    limit: limits.model_edges,
                })?;
    }
    let mut image_closed = None;
    for proof in &input.proofs {
        check_cancelled(is_cancelled)?;
        if proof.kind == semantic::ProofKind::ImageClosed {
            if image_closed.is_some() {
                return Err(unsupported("noncanonical actor image closure proof"));
            }
            image_closed = Some(proof);
        }
    }
    let image_closed = image_closed.ok_or(unsupported("actor image closure proof"))?;
    let mut closure_matches = image_closed.bound == Some(static_bytes);
    for activation in &input.activations {
        check_cancelled(is_cancelled)?;
        closure_matches &= image_closed
            .depends_on
            .binary_search(&activation.capacity_proof)
            .is_ok();
    }
    if !closure_matches {
        return Err(unsupported("noncanonical actor image closure proof"));
    }
    let expected_owners = 1_usize
        .checked_add(input.actors.len())
        .and_then(|count| count.checked_add(input.tasks.len()))
        .ok_or(LowerError::ResourceLimit {
            resource: "actor ownership order",
            limit: limits.model_edges,
        })?;
    let mut canonical_startup = input.startup_order.len() == expected_owners
        && input.startup_order.first() == Some(&semantic::ImageOwner::Runtime);
    for (index, actor) in input.actors.iter().enumerate() {
        check_cancelled(is_cancelled)?;
        canonical_startup &= input.startup_order.get(index.saturating_add(1))
            == Some(&semantic::ImageOwner::Actor(actor.id));
    }
    for (index, task) in input.tasks.iter().enumerate() {
        check_cancelled(is_cancelled)?;
        let owner = input
            .actors
            .len()
            .checked_add(index)
            .and_then(|index| index.checked_add(1));
        canonical_startup &= owner.and_then(|index| input.startup_order.get(index))
            == Some(&semantic::ImageOwner::Task(task.id));
    }
    let mut canonical_shutdown = input.shutdown_order.len() == expected_owners
        && input.shutdown_order.last() == Some(&semantic::ImageOwner::Runtime);
    for (index, task) in input.tasks.iter().rev().enumerate() {
        check_cancelled(is_cancelled)?;
        canonical_shutdown &=
            input.shutdown_order.get(index) == Some(&semantic::ImageOwner::Task(task.id));
    }
    for (index, actor) in input.actors.iter().rev().enumerate() {
        check_cancelled(is_cancelled)?;
        let owner = input.tasks.len().checked_add(index);
        canonical_shutdown &= owner.and_then(|index| input.shutdown_order.get(index))
            == Some(&semantic::ImageOwner::Actor(actor.id));
    }
    if input.static_bytes != static_bytes
        || input.peak_bytes != static_bytes
        || !canonical_startup
        || !canonical_shutdown
    {
        return Err(unsupported("noncanonical actor memory or ownership order"));
    }
    Ok(())
}

fn validate_actor_source_function(
    input: &semantic::SemanticWir,
    function: &semantic::SemanticFunction,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LowerError> {
    let body_parameters_match = polled_slices_equal(
        &function.body.parameters,
        &function.parameters,
        is_cancelled,
    )?;
    let role_effects = match function.role {
        semantic::FunctionRole::Ordinary => 0,
        semantic::FunctionRole::ActorTurn(_) => semantic::EffectSet::ACTOR_CALL,
        semantic::FunctionRole::TaskEntry(_) => semantic::EffectSet::TASK_SPAWN,
        semantic::FunctionRole::Test
        | semantic::FunctionRole::Isr(_)
        | semantic::FunctionRole::Cleanup
        | semantic::FunctionRole::ImageEntry => u64::MAX,
    };
    let one_way_effect = if matches!(function.role, semantic::FunctionRole::TaskEntry(_))
        && function.effects.0 & semantic::EffectSet::ACTOR_CALL != 0
    {
        semantic::EffectSet::ACTOR_CALL
    } else {
        0
    };
    let expected_effects = role_effects
        | one_way_effect
        | if function.color == semantic::FunctionColor::Async {
            semantic::EffectSet::SUSPEND
        } else {
            0
        };
    if function.origin != semantic::FunctionOrigin::Source
        || !matches!(
            function.role,
            semantic::FunctionRole::Ordinary
                | semantic::FunctionRole::ActorTurn(_)
                | semantic::FunctionRole::TaskEntry(_)
        )
        || !matches!(
            function.color,
            semantic::FunctionColor::Sync | semantic::FunctionColor::Async
        )
        || function.effects != semantic::EffectSet(expected_effects)
        || function.source.is_none()
        || function.uninterrupted_bound.is_none_or(|bound| bound == 0)
        || function
            .recursive_depth_bound
            .is_none_or(|bound| bound == 0)
        || !supported_source_value_type(input, function.result)
        || !body_parameters_match
    {
        return Err(unsupported(
            "actor functions outside the scalar/call/await slice",
        ));
    }
    let mut parameters = try_vec(
        function.values.len(),
        "actor source parameter membership",
        limits.model_edges,
    )?;
    parameters.resize(function.values.len(), false);
    for parameter in &function.parameters {
        check_cancelled(is_cancelled)?;
        let Some(is_parameter) = parameters.get_mut(parameter.0 as usize) else {
            return Err(unsupported("actor source parameter identity"));
        };
        *is_parameter = true;
    }
    for value in &function.values {
        check_cancelled(is_cancelled)?;
        let is_parameter = parameters
            .get(value.id.0 as usize)
            .copied()
            .ok_or(unsupported("actor source value identity"))?;
        let is_reservation = input.types.get(value.ty.0 as usize).is_some_and(|ty| {
            ty.kind == semantic::TypeKind::Reservation
                && ty.linearity == semantic::Linearity::Strict
                && ty.source.is_none()
        });
        let is_capability = input.types.get(value.ty.0 as usize).is_some_and(|ty| {
            matches!(ty.kind, semantic::TypeKind::ActorHandle { .. })
                && ty.linearity == semantic::Linearity::ExplicitCopy
                && ty.source.is_none()
        });
        if scalar_primitive(input, value.ty).is_none()
            && !is_parameter
            && !is_reservation
            && !is_capability
        {
            return Err(unsupported("non-scalar actor temporaries"));
        }
    }

    let mut actor_capabilities = 0_u32;
    let mut actor_reserves = 0_u32;
    let mut mailbox_receives = 0_u32;
    let mut regions = try_vec(1, "actor source region validation", limits.model_edges)?;
    regions.push((&function.body, true, 1_u32));
    while let Some((region, is_root, depth)) = regions.pop() {
        check_cancelled(is_cancelled)?;
        if depth > limits.region_depth || (!is_root && !region.parameters.is_empty()) {
            return Err(unsupported("actor source region parameters or depth"));
        }
        let mut terminated = false;
        for (index, statement) in region.statements.iter().enumerate() {
            check_cancelled(is_cancelled)?;
            if terminated {
                return Err(unsupported("actor statements after terminator"));
            }
            match statement {
                semantic::SemanticStatement::Let(statement) => match &statement.operation {
                    semantic::SemanticOperation::Constant(constant) => {
                        let [result] = statement.results.as_slice() else {
                            return Err(unsupported("actor scalar constant result arity"));
                        };
                        let ty = scalar_value_type(function, *result)
                            .ok_or(unsupported("actor scalar constant result type"))?;
                        if !scalar_constant_matches(input, ty, constant) {
                            return Err(unsupported("actor scalar constant type"));
                        }
                    }
                    semantic::SemanticOperation::Copy { value } => {
                        let [result] = statement.results.as_slice() else {
                            return Err(unsupported("actor copy result arity"));
                        };
                        if scalar_value_type(function, *result)
                            != scalar_value_type(function, *value)
                        {
                            return Err(unsupported("actor copy type"));
                        }
                    }
                    semantic::SemanticOperation::Binary {
                        operator,
                        left,
                        right,
                        arithmetic,
                    } => validate_scalar_binary(
                        input,
                        function,
                        statement,
                        *operator,
                        *left,
                        *right,
                        *arithmetic,
                    )?,
                    semantic::SemanticOperation::Unary {
                        operator,
                        operand,
                        arithmetic,
                    } => validate_scalar_unary(
                        input,
                        function,
                        statement,
                        *operator,
                        *operand,
                        *arithmetic,
                    )?,
                    semantic::SemanticOperation::Convert {
                        value,
                        destination,
                        checked,
                    } => validate_exact_scalar_conversion(
                        input,
                        function,
                        statement,
                        *value,
                        *destination,
                        *checked,
                    )?,
                    semantic::SemanticOperation::Assert { condition, failure } => {
                        if !statement.results.is_empty()
                            || scalar_value_type(function, *condition).is_none_or(|ty| {
                                !semantic_type_is(input, ty, semantic::PrimitiveType::Bool)
                            })
                            || statement.source != Some(failure.source)
                        {
                            return Err(unsupported("generated test assertion"));
                        }
                    }
                    semantic::SemanticOperation::Call {
                        function: callee,
                        arguments,
                        activation,
                    } => {
                        let callee = input
                            .functions
                            .get(callee.0 as usize)
                            .filter(|callee| {
                                callee.origin == semantic::FunctionOrigin::Source
                                    && callee.role == semantic::FunctionRole::Ordinary
                            })
                            .ok_or(unsupported("actor scalar call target"))?;
                        if arguments.len() != callee.parameters.len() {
                            return Err(unsupported("actor scalar call arguments"));
                        }
                        for (argument, parameter) in arguments.iter().zip(&callee.parameters) {
                            check_cancelled(is_cancelled)?;
                            if argument.access != semantic::AccessMode::Read
                                || scalar_value_type(function, argument.value)
                                    != scalar_value_type(callee, *parameter)
                            {
                                return Err(unsupported("actor scalar call arguments"));
                            }
                        }
                        let result_matches = if callee.color == semantic::FunctionColor::Async {
                            if activation.is_none() {
                                return Err(unsupported("async call without activation plan"));
                            }
                            function.color == semantic::FunctionColor::Async
                                && matches!(
                                    statement.results.as_slice(),
                                    [activation]
                                        if scalar_value_type(function, *activation)
                                            == Some(callee.result)
                                            && matches!(
                                                region.statements.get(index + 1),
                                                Some(semantic::SemanticStatement::Let(
                                                    semantic::LetStatement {
                                                        results,
                                                        operation: semantic::SemanticOperation::Await {
                                                            awaitable,
                                                        },
                                                        ..
                                                    }
                                                )) if *awaitable == *activation
                                                    && matches!(results.as_slice(), [delivered]
                                                        if *delivered != *activation
                                                            && scalar_value_type(function, *delivered)
                                                                == Some(callee.result))
                                            )
                                )
                        } else {
                            activation.is_none()
                                && scalar_call_results_match(
                                    input,
                                    function,
                                    callee,
                                    &statement.results,
                                    is_cancelled,
                                )?
                        };
                        if !result_matches {
                            return Err(unsupported("actor scalar call results"));
                        }
                    }
                    semantic::SemanticOperation::ActorCapability {
                        actor,
                        wiring_proof,
                    } => {
                        actor_capabilities =
                            actor_capabilities
                                .checked_add(1)
                                .ok_or(LowerError::ResourceLimit {
                                    resource: "image-wired actor capabilities",
                                    limit: limits.model_edges,
                                })?;
                        let [capability] = statement.results.as_slice() else {
                            return Err(unsupported("actor capability result arity"));
                        };
                        let target = input
                            .actors
                            .get(actor.0 as usize)
                            .filter(|target| target.id == *actor)
                            .ok_or(unsupported("actor capability target"))?;
                        let capability_type = scalar_value_type(function, *capability)
                            .and_then(|ty| input.types.get(ty.0 as usize));
                        let source_actor = match function.role {
                            semantic::FunctionRole::TaskEntry(task) => input
                                .tasks
                                .get(task.0 as usize)
                                .filter(|record| record.id == task)
                                .and_then(|record| record.supervisor),
                            _ => None,
                        };
                        let proof_matches =
                            input
                                .proofs
                                .get(wiring_proof.0 as usize)
                                .is_some_and(|proof| {
                                    proof.id == *wiring_proof
                                        && proof.kind == semantic::ProofKind::ActorAsIf
                                        && proof.bound == Some(1)
                                        && proof.sources.len() == 1
                                        && proof.depends_on.is_empty()
                                });
                        let reserve_matches = matches!(
                            region.statements.get(index + 1),
                            Some(semantic::SemanticStatement::Let(
                                semantic::LetStatement {
                                    operation: semantic::SemanticOperation::ActorReserve {
                                        actor: reserve_actor,
                                        ..
                                    },
                                    ..
                                }
                            )) if reserve_actor == actor
                        );
                        if input.actors.len() != 2
                            || source_actor != Some(semantic::ActorId(1))
                            || *actor != semantic::ActorId(0)
                            || !capability_type.is_some_and(|ty| {
                                ty.kind
                                    == semantic::TypeKind::ActorHandle {
                                        actor_type: target.ty,
                                    }
                                    && ty.linearity == semantic::Linearity::ExplicitCopy
                                    && ty.source.is_none()
                            })
                            || !proof_matches
                            || !reserve_matches
                            || !is_root
                        {
                            return Err(unsupported("noncanonical image-wired actor capability"));
                        }
                    }
                    semantic::SemanticOperation::ActorReserve {
                        actor,
                        method,
                        permit_proof,
                    } => {
                        actor_reserves =
                            actor_reserves
                                .checked_add(1)
                                .ok_or(LowerError::ResourceLimit {
                                    resource: "one-way actor reservations",
                                    limit: limits.model_edges,
                                })?;
                        let [reservation] = statement.results.as_slice() else {
                            return Err(unsupported("one-way reservation result arity"));
                        };
                        let reservation_type = scalar_value_type(function, *reservation)
                            .and_then(|ty| input.types.get(ty.0 as usize))
                            .filter(|ty| {
                                ty.kind == semantic::TypeKind::Reservation
                                    && ty.linearity == semantic::Linearity::Strict
                            })
                            .ok_or(unsupported("one-way reservation type"))?;
                        let caller_actor = match function.role {
                            semantic::FunctionRole::TaskEntry(task) => input
                                .tasks
                                .get(task.0 as usize)
                                .filter(|record| record.id == task)
                                .and_then(|record| record.supervisor),
                            _ => None,
                        };
                        let target_matches =
                            input
                                .functions
                                .get(method.0 as usize)
                                .is_some_and(|target| {
                                    target.id == *method
                                        && target.role == semantic::FunctionRole::ActorTurn(*actor)
                                        && target.color == semantic::FunctionColor::Async
                                        && target.parameters.len() == 1
                                        && semantic_type_is(
                                            input,
                                            target.result,
                                            semantic::PrimitiveType::Unit,
                                        )
                                });
                        let mailbox_proof = input
                            .regions
                            .iter()
                            .filter(|region| {
                                region.owner == semantic::ImageOwner::Actor(*actor)
                                    && region.class == semantic::RegionClass::Image
                            })
                            .map(|region| region.proof)
                            .next();
                        let permit_matches =
                            input
                                .proofs
                                .get(permit_proof.0 as usize)
                                .is_some_and(|proof| {
                                    proof.id == *permit_proof
                                        && proof.kind == semantic::ProofKind::CapacityBound
                                        && proof.bound == Some(1)
                                        && statement.source.is_some_and(|source| {
                                            proof.sources.as_slice() == [source]
                                        })
                                        && mailbox_proof.is_some_and(|mailbox| {
                                            proof.depends_on.as_slice() == [mailbox]
                                        })
                                });
                        let commit_matches = matches!(
                            region.statements.get(index + 1),
                            Some(semantic::SemanticStatement::Let(
                                semantic::LetStatement {
                                    results,
                                    operation: semantic::SemanticOperation::ActorCommit {
                                        reservation: committed,
                                        arguments,
                                    },
                                    source,
                                }
                            )) if results.is_empty()
                                && committed == reservation
                                && arguments.is_empty()
                                && *source == statement.source
                        );
                        let cross_actor = input.actors.len() == 2
                            && caller_actor == Some(semantic::ActorId(1))
                            && *actor == semantic::ActorId(0)
                            && matches!(
                                index.checked_sub(1).and_then(|prior| region.statements.get(prior)),
                                Some(semantic::SemanticStatement::Let(
                                    semantic::LetStatement {
                                        operation: semantic::SemanticOperation::ActorCapability {
                                            actor: capability_actor,
                                            ..
                                        },
                                        ..
                                    }
                                )) if capability_actor == actor
                            );
                        if reservation_type.source.is_some()
                            || (caller_actor != Some(*actor) && !cross_actor)
                            || !target_matches
                            || !permit_matches
                            || !function.proofs.contains(permit_proof)
                            || !commit_matches
                            || !is_root
                        {
                            return Err(unsupported("noncanonical one-way actor reservation"));
                        }
                    }
                    semantic::SemanticOperation::ActorCommit {
                        reservation,
                        arguments,
                    } => {
                        if !arguments.is_empty()
                            || !statement.results.is_empty()
                            || !matches!(
                                index.checked_sub(1).and_then(|prior| region.statements.get(prior)),
                                Some(semantic::SemanticStatement::Let(
                                    semantic::LetStatement {
                                        results,
                                        operation: semantic::SemanticOperation::ActorReserve { .. },
                                        source,
                                    }
                                )) if results.as_slice() == [*reservation]
                                    && *source == statement.source
                            )
                        {
                            return Err(unsupported("noncanonical one-way actor commit"));
                        }
                    }
                    semantic::SemanticOperation::MailboxReceive { actor, method } => {
                        mailbox_receives =
                            mailbox_receives
                                .checked_add(1)
                                .ok_or(LowerError::ResourceLimit {
                                    resource: "one-way mailbox receives",
                                    limit: limits.model_edges,
                                })?;
                        if function.role != semantic::FunctionRole::ActorTurn(*actor)
                            || *method != function.id
                            || !statement.results.is_empty()
                            || !is_root
                            || index != 0
                        {
                            return Err(unsupported("noncanonical one-way mailbox receive"));
                        }
                    }
                    semantic::SemanticOperation::ActorStateLoad {
                        actor,
                        region: state_region,
                        proof,
                    } => {
                        let [result] = statement.results.as_slice() else {
                            return Err(unsupported("actor state load result"));
                        };
                        if !supported_actor_state_access(
                            input,
                            function,
                            *actor,
                            *state_region,
                            *proof,
                        ) || scalar_value_type(function, *result).is_none_or(|ty| {
                            !semantic_type_is(input, ty, semantic::PrimitiveType::U64)
                        }) {
                            return Err(unsupported("actor state load authentication"));
                        }
                    }
                    semantic::SemanticOperation::ActorStateStore {
                        actor,
                        region: state_region,
                        value,
                        proof,
                    } => {
                        if !statement.results.is_empty()
                            || !supported_actor_state_access(
                                input,
                                function,
                                *actor,
                                *state_region,
                                *proof,
                            )
                            || scalar_value_type(function, *value).is_none_or(|ty| {
                                !semantic_type_is(input, ty, semantic::PrimitiveType::U64)
                            })
                        {
                            return Err(unsupported("actor state store authentication"));
                        }
                    }
                    semantic::SemanticOperation::Await { awaitable } => {
                        let [delivered] = statement.results.as_slice() else {
                            return Err(unsupported("async await result delivery"));
                        };
                        let prior_async_call = index.checked_sub(1).and_then(|prior| match region
                            .statements
                            .get(prior)
                        {
                            Some(semantic::SemanticStatement::Let(semantic::LetStatement {
                                results,
                                operation:
                                    semantic::SemanticOperation::Call {
                                        function: callee, ..
                                    },
                                ..
                            })) if results.as_slice() == [*awaitable] => input
                                .functions
                                .get(callee.0 as usize)
                                .filter(|callee| callee.color == semantic::FunctionColor::Async),
                            _ => None,
                        });
                        if function.color != semantic::FunctionColor::Async
                            || prior_async_call.is_none_or(|callee| {
                                scalar_value_type(function, *awaitable) != Some(callee.result)
                                    || scalar_value_type(function, *delivered)
                                        != Some(callee.result)
                            })
                        {
                            return Err(unsupported("async await result delivery"));
                        }
                    }
                    _ => {
                        return Err(unsupported(
                            "actor runtime operation without exact FlowWir lowering",
                        ));
                    }
                },
                semantic::SemanticStatement::If {
                    condition,
                    then_region,
                    else_region,
                    results,
                    ..
                } => {
                    if !results.is_empty()
                        || scalar_value_type(function, *condition).is_none_or(|ty| {
                            !semantic_type_is(input, ty, semantic::PrimitiveType::Bool)
                        })
                    {
                        return Err(unsupported("actor no-phi branch contract"));
                    }
                    let next = depth.checked_add(1).ok_or(LowerError::ResourceLimit {
                        resource: "actor source region depth",
                        limit: u64::from(limits.region_depth),
                    })?;
                    push_bounded(
                        &mut regions,
                        (else_region, false, next),
                        "actor source region validation",
                        limits.model_edges,
                    )?;
                    push_bounded(
                        &mut regions,
                        (then_region, false, next),
                        "actor source region validation",
                        limits.model_edges,
                    )?;
                }
                semantic::SemanticStatement::Return(values) if is_root => {
                    let result_matches = if semantic_type_is(
                        input,
                        function.result,
                        semantic::PrimitiveType::Unit,
                    ) {
                        values.is_empty()
                    } else {
                        matches!(
                            values.as_slice(),
                            [value]
                                if scalar_value_type(function, *value) == Some(function.result)
                        )
                    };
                    if !result_matches || index + 1 != region.statements.len() {
                        return Err(unsupported("actor source return"));
                    }
                    terminated = true;
                }
                semantic::SemanticStatement::Return(_)
                | semantic::SemanticStatement::Unreachable
                | semantic::SemanticStatement::Match { .. }
                | semantic::SemanticStatement::Loop { .. }
                | semantic::SemanticStatement::Yield(_)
                | semantic::SemanticStatement::Break(_)
                | semantic::SemanticStatement::Continue(_) => {
                    return Err(unsupported("actor non-fallthrough source region"));
                }
            }
        }
        if is_root && !terminated {
            return Err(unsupported("actor source root terminator"));
        }
    }
    let expects_send = one_way_effect != 0;
    let expects_receive = matches!(function.role, semantic::FunctionRole::ActorTurn(_))
        && input.functions.iter().any(|candidate| {
            candidate.body.statements.iter().any(|statement| {
                matches!(
                    statement,
                    semantic::SemanticStatement::Let(semantic::LetStatement {
                        operation: semantic::SemanticOperation::ActorReserve { method, .. },
                        ..
                    }) if *method == function.id
                )
            })
        });
    let expects_capability = expects_send
        && input.actors.len() == 2
        && matches!(function.role, semantic::FunctionRole::TaskEntry(task)
            if input.tasks.get(task.0 as usize).and_then(|task| task.supervisor)
                == Some(semantic::ActorId(1)));
    if actor_capabilities != u32::from(expects_capability)
        || actor_reserves != u32::from(expects_send)
        || mailbox_receives != u32::from(expects_receive)
    {
        return Err(unsupported("one-way actor operation census"));
    }
    Ok(())
}

fn supported_actor_state_access(
    input: &semantic::SemanticWir,
    function: &semantic::SemanticFunction,
    actor: semantic::ActorId,
    region: semantic::RegionId,
    proof: semantic::ProofId,
) -> bool {
    function.role == semantic::FunctionRole::ActorTurn(actor)
        && input
            .actors
            .get(actor.0 as usize)
            .is_some_and(|actor_plan| {
                input
                    .regions
                    .get(region.0 as usize)
                    .is_some_and(|region_plan| {
                        region_plan.owner == semantic::ImageOwner::Actor(actor)
                            && region_plan.class == semantic::RegionClass::Image
                            && region_plan.capacity_bytes == 8
                            && region_plan.alignment == 8
                            && region_plan.proof == proof
                            && region_plan.name.strip_suffix(".state")
                                == Some(actor_plan.name.as_str())
                            && input.proofs.get(proof.0 as usize).is_some_and(|proof| {
                                proof.kind == semantic::ProofKind::CapacityBound
                                    && proof.bound == Some(1)
                                    && proof.sources.as_slice() == [region_plan.source]
                                    && proof.depends_on.is_empty()
                            })
                    })
            })
}

fn supported_generated_tests<'a>(
    input: &'a semantic::SemanticWir,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<GeneratedTestSemantic<'a>, LowerError> {
    if !input.globals.is_empty()
        || !input.actors.is_empty()
        || !input.tasks.is_empty()
        || !input.devices.is_empty()
        || !input.pools.is_empty()
        || !input.regions.is_empty()
        || !input.activations.is_empty()
        || !input.scopes.is_empty()
    {
        return Err(unsupported(
            "nonempty runtime plans, scopes, or globals in generated tests",
        ));
    }
    if input.startup_order.as_slice() != [semantic::ImageOwner::Runtime]
        || input.shutdown_order.as_slice() != [semantic::ImageOwner::Runtime]
        || input.static_bytes != 0
        || input.peak_bytes != 0
    {
        return Err(unsupported(
            "nonempty runtime ownership or memory plans in generated tests",
        ));
    }
    let Some(unit) = input.types.first() else {
        return Err(unsupported("generated test type table"));
    };
    if unit.id != semantic::TypeId(0)
        || unit.source_name != "unit"
        || unit.kind != semantic::TypeKind::Primitive(semantic::PrimitiveType::Unit)
        || unit.linearity != semantic::Linearity::CopyScalar
    {
        return Err(unsupported("generated test unit type"));
    }
    let mut previous_frame_length = None;
    let mut saw_frame = false;
    let mut source_type_edges = 0_u64;
    for ty in &input.types {
        check_cancelled(is_cancelled)?;
        match &ty.kind {
            semantic::TypeKind::Primitive(primitive) => {
                if saw_frame
                    || !supported_scalar_primitive(*primitive)
                    || ty.linearity != semantic::Linearity::CopyScalar
                {
                    return Err(unsupported("generated test scalar types"));
                }
            }
            semantic::TypeKind::Function(function) => {
                if saw_frame
                    || function.color != semantic::FunctionColor::Sync
                    || ty.linearity != semantic::Linearity::CopyScalar
                    || !supported_source_value_type(input, function.result)
                {
                    return Err(unsupported("generated test scalar function types"));
                }
                for parameter in &function.parameters {
                    check_cancelled(is_cancelled)?;
                    if parameter.access != semantic::AccessMode::Read
                        || !supported_source_value_type(input, parameter.ty)
                    {
                        return Err(unsupported("generated test scalar function types"));
                    }
                }
            }
            semantic::TypeKind::Struct { fields } => {
                add_bounded(
                    &mut source_type_edges,
                    fields.len(),
                    "generated test source type edges",
                    limits.model_edges,
                )?;
                if saw_frame
                    || ty.linearity != semantic::Linearity::ExplicitCopy
                    || ty.source.is_none()
                    || fields.is_empty()
                {
                    return Err(unsupported("generated test flat structure types"));
                }
                for field in fields {
                    check_cancelled(is_cancelled)?;
                    if field.name.is_empty() || scalar_primitive(input, field.ty).is_none() {
                        return Err(unsupported("generated test flat structure fields"));
                    }
                }
            }
            semantic::TypeKind::Enum { variants } => {
                add_bounded(
                    &mut source_type_edges,
                    variants.len(),
                    "generated test source type edges",
                    limits.model_edges,
                )?;
                if saw_frame
                    || ty.linearity != semantic::Linearity::ExplicitCopy
                    || ty.source.is_none()
                    || variants.is_empty()
                    || variants.len() > 256
                {
                    return Err(unsupported("generated test closed enum types"));
                }
                let mut payload = None;
                for variant in variants {
                    check_cancelled(is_cancelled)?;
                    add_bounded(
                        &mut source_type_edges,
                        variant.fields.len(),
                        "generated test source type edges",
                        limits.model_edges,
                    )?;
                    let [field] = variant.fields.as_slice() else {
                        return Err(unsupported("generated test enum payload shape"));
                    };
                    if field.name.is_empty()
                        && scalar_primitive(input, field.ty).is_some()
                        && payload.is_none_or(|expected| expected == field.ty)
                    {
                        payload = Some(field.ty);
                    } else {
                        return Err(unsupported("generated test enum payload type"));
                    }
                }
            }
            semantic::TypeKind::Array { element, length } => {
                saw_frame = true;
                let name_length = ty
                    .source_name
                    .strip_prefix("__wrela_test_frame_")
                    .and_then(|value| value.parse::<u64>().ok());
                if *length == 0
                    || name_length != Some(*length)
                    || previous_frame_length.is_some_and(|previous| previous >= *length)
                    || !input.types.get(element.0 as usize).is_some_and(|element| {
                        element.kind == semantic::TypeKind::Primitive(semantic::PrimitiveType::U8)
                            && element.linearity == semantic::Linearity::CopyScalar
                    })
                    || ty.linearity != semantic::Linearity::ExplicitCopy
                    || ty.source.is_some()
                {
                    return Err(unsupported("generated test frame types"));
                }
                previous_frame_length = Some(*length);
            }
            semantic::TypeKind::Tuple(_)
            | semantic::TypeKind::Iso { .. }
            | semantic::TypeKind::ActorHandle { .. }
            | semantic::TypeKind::Reservation
            | semantic::TypeKind::Receipt { .. }
            | semantic::TypeKind::DmaPayload { .. }
            | semantic::TypeKind::DmaShared { .. }
            | semantic::TypeKind::Mmio { .. }
            | semantic::TypeKind::Validated { .. }
            | semantic::TypeKind::OpaqueTarget { .. } => {
                return Err(unsupported(
                    "generated test types outside the scalar subset",
                ));
            }
        }
    }
    if !saw_frame {
        return Err(unsupported("generated test frame types"));
    }

    let harness = input
        .functions
        .last()
        .ok_or(unsupported("generated test harness"))?;
    for function in &input.functions[..input.functions.len() - 1] {
        check_cancelled(is_cancelled)?;
        validate_scalar_source_function(input, function, limits, is_cancelled)?;
    }
    let mut selected = try_vec(
        input.functions.len(),
        "generated test function selection",
        limits.model_edges,
    )?;
    selected.resize(input.functions.len(), 0_u32);
    let mut expected_uninterrupted = 2u64;
    for (index, test) in input.tests.iter().enumerate() {
        check_cancelled(is_cancelled)?;
        let Some(index) = u32::try_from(index).ok() else {
            return Err(unsupported("generated test identity"));
        };
        let function = input
            .functions
            .get(test.function.0 as usize)
            .ok_or(unsupported("generated test function identity"))?;
        if test.id != semantic::TestId(index)
            || test.kind != semantic::TestKind::Integration
            || test.name != function.name
            || test.timeout_ns == 0
            || function.origin != semantic::FunctionOrigin::Source
            || function.role != semantic::FunctionRole::Test
            || function.color != semantic::FunctionColor::Sync
            || !function.parameters.is_empty()
            || !semantic_type_is(input, function.result, semantic::PrimitiveType::Unit)
            || function.effects.0 & !semantic::EffectSet::MAY_FAIL != 0
            || function.source != Some(test.source)
            || function.uninterrupted_bound.is_none_or(|bound| bound == 0)
            || function
                .recursive_depth_bound
                .is_none_or(|bound| bound == 0)
            || !function.body.parameters.is_empty()
        {
            return Err(unsupported(
                "generated test functions outside the synchronous scalar subset",
            ));
        }
        let selection = selected
            .get_mut(test.function.0 as usize)
            .ok_or(unsupported("generated test function identity"))?;
        *selection = selection
            .checked_add(1)
            .ok_or(unsupported("generated test function selection"))?;
        expected_uninterrupted = expected_uninterrupted
            .checked_add(3)
            .and_then(|total| total.checked_add(function.uninterrupted_bound?))
            .ok_or(unsupported("generated test uninterrupted-work bound"))?;
    }
    for (function, selected) in input.functions[..input.functions.len() - 1]
        .iter()
        .zip(&selected)
    {
        check_cancelled(is_cancelled)?;
        if (function.role == semantic::FunctionRole::Test && *selected != 1)
            || (function.role == semantic::FunctionRole::Ordinary && *selected != 0)
        {
            return Err(unsupported("generated test source-function closure"));
        }
    }
    match harness.origin {
        semantic::FunctionOrigin::GeneratedTestHarness { .. } => {}
        semantic::FunctionOrigin::Source | semantic::FunctionOrigin::GeneratedImageEntry { .. } => {
            return Err(unsupported("generated test harness origin"));
        }
    }
    if harness.id.0 as usize != input.functions.len() - 1
        || input.image_entry != harness.id
        || harness.role != semantic::FunctionRole::ImageEntry
        || harness.color != semantic::FunctionColor::Sync
        || !harness.parameters.is_empty()
        || harness.result != semantic::TypeId(0)
        || harness.effects != semantic::EffectSet(semantic::EffectSet::FIRMWARE)
        || harness.source.is_some()
        || harness.stack_bound != 0
        || harness.frame_bound != 0
        || harness.uninterrupted_bound != Some(expected_uninterrupted)
        || harness.recursive_depth_bound != Some(1)
        || !harness.body.parameters.is_empty()
    {
        return Err(unsupported("noncanonical generated test harness"));
    }
    validate_generated_harness(input, harness, is_cancelled)?;
    Ok(GeneratedTestSemantic { input, harness })
}

fn supported_scalar_primitive(primitive: semantic::PrimitiveType) -> bool {
    matches!(
        primitive,
        semantic::PrimitiveType::Unit
            | semantic::PrimitiveType::Bool
            | semantic::PrimitiveType::U8
            | semantic::PrimitiveType::U16
            | semantic::PrimitiveType::U32
            | semantic::PrimitiveType::U64
            | semantic::PrimitiveType::U128
            | semantic::PrimitiveType::Usize
            | semantic::PrimitiveType::I8
            | semantic::PrimitiveType::I16
            | semantic::PrimitiveType::I32
            | semantic::PrimitiveType::I64
            | semantic::PrimitiveType::I128
            | semantic::PrimitiveType::Isize
            | semantic::PrimitiveType::F32
            | semantic::PrimitiveType::F64
    )
}

fn semantic_type_is(
    input: &semantic::SemanticWir,
    ty: semantic::TypeId,
    primitive: semantic::PrimitiveType,
) -> bool {
    input.types.get(ty.0 as usize).is_some_and(|ty| {
        ty.kind == semantic::TypeKind::Primitive(primitive)
            && ty.linearity == semantic::Linearity::CopyScalar
    })
}

fn scalar_primitive(
    input: &semantic::SemanticWir,
    ty: semantic::TypeId,
) -> Option<semantic::PrimitiveType> {
    input.types.get(ty.0 as usize).and_then(|record| {
        if record.linearity != semantic::Linearity::CopyScalar {
            return None;
        }
        match record.kind {
            semantic::TypeKind::Primitive(primitive) if supported_scalar_primitive(primitive) => {
                Some(primitive)
            }
            _ => None,
        }
    })
}

fn scalar_value_type(
    function: &semantic::SemanticFunction,
    value: semantic::ValueId,
) -> Option<semantic::TypeId> {
    function
        .values
        .get(value.0 as usize)
        .filter(|record| record.id == value)
        .map(|record| record.ty)
}

fn scalar_call_results_match(
    input: &semantic::SemanticWir,
    caller: &semantic::SemanticFunction,
    callee: &semantic::SemanticFunction,
    results: &[semantic::ValueId],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LowerError> {
    check_cancelled(is_cancelled)?;
    let unit_result = semantic_type_is(input, callee.result, semantic::PrimitiveType::Unit);
    Ok(match results {
        [] => unit_result,
        [result] => scalar_value_type(caller, *result) == Some(callee.result),
        _ => false,
    })
}

fn supported_source_value_type(input: &semantic::SemanticWir, ty: semantic::TypeId) -> bool {
    let Some(record) = input.types.get(ty.0 as usize) else {
        return false;
    };
    if scalar_primitive(input, ty).is_some() {
        return true;
    }
    match &record.kind {
        semantic::TypeKind::Struct { fields } => {
            record.linearity == semantic::Linearity::ExplicitCopy
                && record.source.is_some()
                && !fields.is_empty()
                && fields
                    .iter()
                    .all(|field| scalar_primitive(input, field.ty).is_some())
        }
        semantic::TypeKind::Enum { variants } => {
            let payload = variants
                .first()
                .and_then(|variant| variant.fields.first())
                .map(|field| field.ty);
            record.linearity == semantic::Linearity::ExplicitCopy
                && record.source.is_some()
                && !variants.is_empty()
                && variants.len() <= 256
                && payload.is_some_and(|payload| {
                    scalar_primitive(input, payload).is_some()
                        && variants.iter().all(|variant| {
                            matches!(variant.fields.as_slice(), [field]
                                if field.name.is_empty() && field.ty == payload)
                        })
                })
        }
        _ => false,
    }
}

fn integer_primitive(primitive: semantic::PrimitiveType) -> Option<(bool, u8)> {
    match primitive {
        semantic::PrimitiveType::U8 => Some((false, 8)),
        semantic::PrimitiveType::U16 => Some((false, 16)),
        semantic::PrimitiveType::U32 => Some((false, 32)),
        semantic::PrimitiveType::U64 | semantic::PrimitiveType::Usize => Some((false, 64)),
        semantic::PrimitiveType::U128 => Some((false, 128)),
        semantic::PrimitiveType::I8 => Some((true, 8)),
        semantic::PrimitiveType::I16 => Some((true, 16)),
        semantic::PrimitiveType::I32 => Some((true, 32)),
        semantic::PrimitiveType::I64 | semantic::PrimitiveType::Isize => Some((true, 64)),
        semantic::PrimitiveType::I128 => Some((true, 128)),
        semantic::PrimitiveType::Unit
        | semantic::PrimitiveType::Bool
        | semantic::PrimitiveType::F32
        | semantic::PrimitiveType::F64
        | semantic::PrimitiveType::Char => None,
    }
}

fn scalar_constant_matches(
    input: &semantic::SemanticWir,
    ty: semantic::TypeId,
    constant: &semantic::Constant,
) -> bool {
    let Some(primitive) = scalar_primitive(input, ty) else {
        return false;
    };
    match (primitive, constant) {
        (semantic::PrimitiveType::Unit, semantic::Constant::Unit)
        | (semantic::PrimitiveType::Bool, semantic::Constant::Bool(_))
        | (semantic::PrimitiveType::F32, semantic::Constant::Float32(_))
        | (semantic::PrimitiveType::F64, semantic::Constant::Float64(_)) => true,
        (primitive, semantic::Constant::Unsigned { bits, value }) => integer_primitive(primitive)
            .is_some_and(|(signed, expected)| {
                !signed
                    && *bits == expected
                    && (expected == 128 || *value < (1_u128 << u32::from(expected)))
            }),
        (primitive, semantic::Constant::Signed { bits, value }) => integer_primitive(primitive)
            .is_some_and(|(signed, expected)| {
                if !signed || *bits != expected {
                    return false;
                }
                if expected == 128 {
                    true
                } else {
                    let shift = u32::from(expected - 1);
                    let minimum = -(1_i128 << shift);
                    let maximum = (1_i128 << shift) - 1;
                    (minimum..=maximum).contains(value)
                }
            }),
        _ => false,
    }
}

fn lower_scalar_binary_operator(
    operator: semantic::BinaryOperator,
    arithmetic: semantic::ArithmeticMode,
) -> Result<flow::BinaryOp, LowerError> {
    match (operator, arithmetic) {
        (semantic::BinaryOperator::Add, semantic::ArithmeticMode::Checked) => {
            Ok(flow::BinaryOp::AddChecked)
        }
        (semantic::BinaryOperator::Add, semantic::ArithmeticMode::Wrapping) => {
            Ok(flow::BinaryOp::AddWrapping)
        }
        (semantic::BinaryOperator::Subtract, semantic::ArithmeticMode::Checked) => {
            Ok(flow::BinaryOp::SubChecked)
        }
        (semantic::BinaryOperator::Subtract, semantic::ArithmeticMode::Wrapping) => {
            Ok(flow::BinaryOp::SubWrapping)
        }
        (semantic::BinaryOperator::Multiply, semantic::ArithmeticMode::Checked) => {
            Ok(flow::BinaryOp::MulChecked)
        }
        (semantic::BinaryOperator::Multiply, semantic::ArithmeticMode::Wrapping) => {
            Ok(flow::BinaryOp::MulWrapping)
        }
        (semantic::BinaryOperator::Divide, semantic::ArithmeticMode::Checked) => {
            Ok(flow::BinaryOp::DivChecked)
        }
        (semantic::BinaryOperator::Remainder, semantic::ArithmeticMode::Checked) => {
            Ok(flow::BinaryOp::RemChecked)
        }
        (semantic::BinaryOperator::ShiftLeft, semantic::ArithmeticMode::Checked) => {
            Ok(flow::BinaryOp::ShiftLeftChecked)
        }
        (semantic::BinaryOperator::ShiftLeft, semantic::ArithmeticMode::Wrapping) => {
            Ok(flow::BinaryOp::ShiftLeftWrapping)
        }
        (semantic::BinaryOperator::ShiftRight, semantic::ArithmeticMode::Checked) => {
            Ok(flow::BinaryOp::ShiftRightChecked)
        }
        // Arithmetic mode has no semantic effect for bitwise operations or
        // comparisons. Retaining the operator is therefore exact for either
        // mode; no overflow claim is introduced or discarded.
        (semantic::BinaryOperator::BitAnd, _) => Ok(flow::BinaryOp::BitAnd),
        (semantic::BinaryOperator::BitOr, _) => Ok(flow::BinaryOp::BitOr),
        (semantic::BinaryOperator::BitXor, _) => Ok(flow::BinaryOp::BitXor),
        (semantic::BinaryOperator::Equal, _) => Ok(flow::BinaryOp::Equal),
        (semantic::BinaryOperator::NotEqual, _) => Ok(flow::BinaryOp::NotEqual),
        (semantic::BinaryOperator::Less, _) => Ok(flow::BinaryOp::Less),
        (semantic::BinaryOperator::LessEqual, _) => Ok(flow::BinaryOp::LessEqual),
        (semantic::BinaryOperator::Greater, _) => Ok(flow::BinaryOp::Greater),
        (semantic::BinaryOperator::GreaterEqual, _) => Ok(flow::BinaryOp::GreaterEqual),
        (
            semantic::BinaryOperator::Divide
            | semantic::BinaryOperator::Remainder
            | semantic::BinaryOperator::ShiftRight,
            semantic::ArithmeticMode::Wrapping,
        ) => Err(unsupported("noncanonical wrapping scalar binary operation")),
    }
}

fn validate_scalar_binary(
    input: &semantic::SemanticWir,
    function: &semantic::SemanticFunction,
    statement: &semantic::LetStatement,
    operator: semantic::BinaryOperator,
    left: semantic::ValueId,
    right: semantic::ValueId,
    arithmetic: semantic::ArithmeticMode,
) -> Result<(), LowerError> {
    let [result] = statement.results.as_slice() else {
        return Err(unsupported("scalar binary result arity"));
    };
    let Some(operand_ty) = scalar_value_type(function, left) else {
        return Err(unsupported("scalar binary operand type"));
    };
    if scalar_value_type(function, right) != Some(operand_ty) {
        return Err(unsupported("scalar binary operand type"));
    }
    let Some(primitive) = scalar_primitive(input, operand_ty) else {
        return Err(unsupported("scalar binary operand type"));
    };
    let result_ty =
        scalar_value_type(function, *result).ok_or(unsupported("scalar binary result type"))?;
    match lower_scalar_binary_operator(operator, arithmetic)? {
        flow::BinaryOp::AddWrapping
        | flow::BinaryOp::AddChecked
        | flow::BinaryOp::SubWrapping
        | flow::BinaryOp::SubChecked
        | flow::BinaryOp::MulWrapping
        | flow::BinaryOp::MulChecked
        | flow::BinaryOp::DivChecked
        | flow::BinaryOp::RemChecked
        | flow::BinaryOp::BitAnd
        | flow::BinaryOp::BitOr
        | flow::BinaryOp::BitXor
        | flow::BinaryOp::ShiftLeftChecked
        | flow::BinaryOp::ShiftLeftWrapping
        | flow::BinaryOp::ShiftRightChecked => {
            if integer_primitive(primitive).is_none() || result_ty != operand_ty {
                return Err(unsupported("integer scalar binary type contract"));
            }
        }
        flow::BinaryOp::Equal
        | flow::BinaryOp::NotEqual
        | flow::BinaryOp::Less
        | flow::BinaryOp::LessEqual
        | flow::BinaryOp::Greater
        | flow::BinaryOp::GreaterEqual => {
            if primitive == semantic::PrimitiveType::Unit
                || !semantic_type_is(input, result_ty, semantic::PrimitiveType::Bool)
            {
                return Err(unsupported("scalar comparison type contract"));
            }
            if primitive == semantic::PrimitiveType::Bool
                && !matches!(
                    operator,
                    semantic::BinaryOperator::Equal | semantic::BinaryOperator::NotEqual
                )
            {
                return Err(unsupported("scalar comparison operand contract"));
            }
        }
    }
    Ok(())
}

fn validate_scalar_unary(
    input: &semantic::SemanticWir,
    function: &semantic::SemanticFunction,
    statement: &semantic::LetStatement,
    operator: semantic::UnaryOperator,
    operand: semantic::ValueId,
    arithmetic: semantic::ArithmeticMode,
) -> Result<(), LowerError> {
    let [result] = statement.results.as_slice() else {
        return Err(unsupported("scalar unary result arity"));
    };
    let operand_ty =
        scalar_value_type(function, operand).ok_or(unsupported("scalar unary operand type"))?;
    if scalar_value_type(function, *result) != Some(operand_ty) {
        return Err(unsupported("scalar unary result type"));
    }
    let primitive =
        scalar_primitive(input, operand_ty).ok_or(unsupported("scalar unary operand type"))?;
    let supported = arithmetic == semantic::ArithmeticMode::Checked
        && match operator {
            semantic::UnaryOperator::BoolNot => primitive == semantic::PrimitiveType::Bool,
            semantic::UnaryOperator::BitNot => integer_primitive(primitive).is_some(),
            semantic::UnaryOperator::Negate => {
                matches!(
                    primitive,
                    semantic::PrimitiveType::F32 | semantic::PrimitiveType::F64
                ) || integer_primitive(primitive).is_some_and(|(signed, _)| signed)
            }
        };
    if !supported {
        return Err(unsupported("noncanonical scalar unary operation"));
    }
    Ok(())
}

fn exact_scalar_conversion(
    source: semantic::PrimitiveType,
    destination: semantic::PrimitiveType,
) -> bool {
    if source == destination {
        return source != semantic::PrimitiveType::Unit;
    }
    if let (Some((source_signed, source_bits)), Some((destination_signed, destination_bits))) =
        (integer_primitive(source), integer_primitive(destination))
    {
        return destination_bits > source_bits && (!source_signed || destination_signed);
    }
    match (source, destination) {
        (semantic::PrimitiveType::F32, semantic::PrimitiveType::F64) => true,
        (source, semantic::PrimitiveType::F32) => integer_primitive(source)
            .is_some_and(|(signed, bits)| bits <= if signed { 25 } else { 24 }),
        (source, semantic::PrimitiveType::F64) => integer_primitive(source)
            .is_some_and(|(signed, bits)| bits <= if signed { 54 } else { 53 }),
        _ => false,
    }
}

fn validate_exact_scalar_conversion(
    input: &semantic::SemanticWir,
    function: &semantic::SemanticFunction,
    statement: &semantic::LetStatement,
    value: semantic::ValueId,
    destination: semantic::TypeId,
    checked: bool,
) -> Result<(), LowerError> {
    let [result] = statement.results.as_slice() else {
        return Err(unsupported("scalar conversion result arity"));
    };
    let source_ty =
        scalar_value_type(function, value).ok_or(unsupported("scalar conversion source type"))?;
    if scalar_value_type(function, *result) != Some(destination) {
        return Err(unsupported("mismatched scalar conversion result type"));
    }
    let source =
        scalar_primitive(input, source_ty).ok_or(unsupported("scalar conversion source type"))?;
    let destination = scalar_primitive(input, destination)
        .ok_or(unsupported("scalar conversion destination type"))?;
    if checked {
        let numeric = |primitive| {
            integer_primitive(primitive).is_some()
                || matches!(
                    primitive,
                    semantic::PrimitiveType::F32 | semantic::PrimitiveType::F64
                )
        };
        if numeric(source) && numeric(destination) {
            return Ok(());
        }
        return Err(unsupported(
            "checked conversion requires numeric scalar types",
        ));
    }
    if !exact_scalar_conversion(source, destination) {
        return Err(unsupported(
            "lossy scalar conversion without universally exact lowering",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum ScalarRegionContract<'a> {
    Root,
    MatchArm(&'a [semantic::ValueId]),
    ResultMatchArm {
        bindings: &'a [semantic::ValueId],
        results: &'a [semantic::ValueId],
    },
    Fallthrough,
    Yield(&'a [semantic::ValueId]),
    LoopBody(usize),
    LoopBranch(usize),
}

fn validate_scalar_source_function(
    input: &semantic::SemanticWir,
    function: &semantic::SemanticFunction,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LowerError> {
    if function.origin != semantic::FunctionOrigin::Source
        || !matches!(
            function.role,
            semantic::FunctionRole::Test | semantic::FunctionRole::Ordinary
        )
        || function.color != semantic::FunctionColor::Sync
        || function.effects.0 & !semantic::EffectSet::MAY_FAIL != 0
        || function.source.is_none()
        || function.uninterrupted_bound.is_none_or(|bound| bound == 0)
        || function
            .recursive_depth_bound
            .is_none_or(|bound| bound == 0)
        || !supported_source_value_type(input, function.result)
    {
        return Err(unsupported(
            "source functions outside the synchronous scalar or flat-structure subset",
        ));
    }
    for parameter in &function.parameters {
        check_cancelled(is_cancelled)?;
        if scalar_value_type(function, *parameter)
            .is_none_or(|ty| !supported_source_value_type(input, ty))
        {
            return Err(unsupported(
                "source function parameters outside scalar or flat structures",
            ));
        }
    }
    for value in &function.values {
        check_cancelled(is_cancelled)?;
        if !supported_source_value_type(input, value.ty) {
            return Err(unsupported(
                "source function values outside scalar or flat structures",
            ));
        }
    }

    let mut regions = try_vec(1, "source region validation", limits.model_edges)?;
    regions.push((&function.body, ScalarRegionContract::Root, 1_u32));
    while let Some((region, contract, depth)) = regions.pop() {
        check_cancelled(is_cancelled)?;
        let parameters_match = match contract {
            ScalarRegionContract::Root => region.parameters == function.parameters,
            ScalarRegionContract::MatchArm(bindings) => region.parameters == bindings,
            ScalarRegionContract::ResultMatchArm { bindings, .. } => region.parameters == bindings,
            ScalarRegionContract::Fallthrough
            | ScalarRegionContract::Yield(_)
            | ScalarRegionContract::LoopBranch(_) => region.parameters.is_empty(),
            ScalarRegionContract::LoopBody(arity) => region.parameters.len() == arity,
        };
        if depth > limits.region_depth || !parameters_match {
            return Err(unsupported("scalar source region parameters or depth"));
        }
        let mut terminated = false;
        for (index, statement) in region.statements.iter().enumerate() {
            check_cancelled(is_cancelled)?;
            if terminated {
                return Err(unsupported("statements after a scalar source terminator"));
            }
            match statement {
                semantic::SemanticStatement::Let(statement) => match &statement.operation {
                    semantic::SemanticOperation::Constant(constant) => {
                        let [result] = statement.results.as_slice() else {
                            return Err(unsupported("scalar constant result arity"));
                        };
                        if !scalar_value_type(function, *result)
                            .is_some_and(|ty| scalar_constant_matches(input, ty, constant))
                        {
                            return Err(unsupported("scalar constant result type"));
                        }
                    }
                    semantic::SemanticOperation::Copy { value } => {
                        let [result] = statement.results.as_slice() else {
                            return Err(unsupported("scalar copy result arity"));
                        };
                        if scalar_value_type(function, *result)
                            .zip(scalar_value_type(function, *value))
                            .is_none_or(|(result, source)| {
                                result != source || !supported_source_value_type(input, result)
                            })
                        {
                            return Err(unsupported("source copy type"));
                        }
                    }
                    semantic::SemanticOperation::Aggregate { ty, fields } => {
                        let [result] = statement.results.as_slice() else {
                            return Err(unsupported("flat aggregate result arity"));
                        };
                        let expected_fields = input
                            .types
                            .get(ty.0 as usize)
                            .and_then(|record| match &record.kind {
                                semantic::TypeKind::Struct { fields }
                                    if supported_source_value_type(input, *ty) =>
                                {
                                    Some(fields)
                                }
                                _ => None,
                            })
                            .ok_or(unsupported("flat aggregate type"))?;
                        if scalar_value_type(function, *result) != Some(*ty)
                            || fields.len() != expected_fields.len()
                        {
                            return Err(unsupported("flat aggregate result type"));
                        }
                        for (value, expected) in fields.iter().zip(expected_fields) {
                            check_cancelled(is_cancelled)?;
                            if scalar_value_type(function, *value) != Some(expected.ty)
                                || scalar_primitive(input, expected.ty).is_none()
                            {
                                return Err(unsupported("flat aggregate field type"));
                            }
                        }
                    }
                    semantic::SemanticOperation::InsertField {
                        aggregate,
                        field,
                        value,
                    } => {
                        let [result] = statement.results.as_slice() else {
                            return Err(unsupported("field insertion result arity"));
                        };
                        let aggregate_ty = scalar_value_type(function, *aggregate)
                            .ok_or(unsupported("field insertion aggregate"))?;
                        let expected = input
                            .types
                            .get(aggregate_ty.0 as usize)
                            .and_then(|record| match &record.kind {
                                semantic::TypeKind::Struct { fields }
                                    if supported_source_value_type(input, aggregate_ty) =>
                                {
                                    fields.get(*field as usize).map(|field| field.ty)
                                }
                                _ => None,
                            })
                            .ok_or(unsupported("field insertion field"))?;
                        if scalar_value_type(function, *result) != Some(aggregate_ty)
                            || scalar_value_type(function, *value) != Some(expected)
                            || scalar_primitive(input, expected).is_none()
                        {
                            return Err(unsupported("field insertion type"));
                        }
                    }
                    semantic::SemanticOperation::ConstructEnum {
                        ty,
                        variant,
                        payload,
                    } => {
                        let [result] = statement.results.as_slice() else {
                            return Err(unsupported("closed enum result arity"));
                        };
                        let expected_payload = input
                            .types
                            .get(ty.0 as usize)
                            .and_then(|record| match &record.kind {
                                semantic::TypeKind::Enum { variants }
                                    if supported_source_value_type(input, *ty) =>
                                {
                                    variants
                                        .get(*variant as usize)
                                        .and_then(|variant| variant.fields.first())
                                        .map(|field| field.ty)
                                }
                                _ => None,
                            })
                            .ok_or(unsupported("closed enum constructor type"))?;
                        if scalar_value_type(function, *result) != Some(*ty)
                            || scalar_value_type(function, *payload) != Some(expected_payload)
                            || scalar_primitive(input, expected_payload).is_none()
                        {
                            return Err(unsupported("closed enum constructor payload"));
                        }
                    }
                    semantic::SemanticOperation::Project {
                        base,
                        field,
                        access,
                    } => {
                        let [result] = statement.results.as_slice() else {
                            return Err(unsupported("flat projection result arity"));
                        };
                        let base_ty = scalar_value_type(function, *base)
                            .ok_or(unsupported("flat projection base"))?;
                        let expected = input
                            .types
                            .get(base_ty.0 as usize)
                            .and_then(|record| match &record.kind {
                                semantic::TypeKind::Struct { fields }
                                    if supported_source_value_type(input, base_ty) =>
                                {
                                    fields.get(*field as usize).map(|field| field.ty)
                                }
                                _ => None,
                            })
                            .ok_or(unsupported("flat projection field"))?;
                        if *access != semantic::AccessMode::Read
                            || scalar_value_type(function, *result) != Some(expected)
                            || scalar_primitive(input, expected).is_none()
                        {
                            return Err(unsupported("flat projection type or access"));
                        }
                    }
                    semantic::SemanticOperation::Binary {
                        operator,
                        left,
                        right,
                        arithmetic,
                    } => validate_scalar_binary(
                        input,
                        function,
                        statement,
                        *operator,
                        *left,
                        *right,
                        *arithmetic,
                    )?,
                    semantic::SemanticOperation::Unary {
                        operator,
                        operand,
                        arithmetic,
                    } => validate_scalar_unary(
                        input,
                        function,
                        statement,
                        *operator,
                        *operand,
                        *arithmetic,
                    )?,
                    semantic::SemanticOperation::Convert {
                        value,
                        destination,
                        checked,
                    } => validate_exact_scalar_conversion(
                        input,
                        function,
                        statement,
                        *value,
                        *destination,
                        *checked,
                    )?,
                    semantic::SemanticOperation::Assert { condition, failure } => {
                        if !statement.results.is_empty()
                            || scalar_value_type(function, *condition).is_none_or(|ty| {
                                !semantic_type_is(input, ty, semantic::PrimitiveType::Bool)
                            })
                            || statement.source != Some(failure.source)
                        {
                            return Err(unsupported("generated test assertion"));
                        }
                    }
                    semantic::SemanticOperation::Call {
                        function: callee,
                        arguments,
                        activation,
                    } => {
                        let callee = input
                            .functions
                            .get(callee.0 as usize)
                            .filter(|callee| {
                                callee.id.0 as usize != input.functions.len() - 1
                                    && callee.origin == semantic::FunctionOrigin::Source
                                    && callee.role == semantic::FunctionRole::Ordinary
                                    && callee.color == semantic::FunctionColor::Sync
                            })
                            .ok_or(unsupported("scalar call target"))?;
                        if activation.is_some() || arguments.len() != callee.parameters.len() {
                            return Err(unsupported("scalar call arguments"));
                        }
                        for (argument, parameter) in arguments.iter().zip(&callee.parameters) {
                            check_cancelled(is_cancelled)?;
                            if argument.access != semantic::AccessMode::Read
                                || scalar_value_type(function, argument.value)
                                    != scalar_value_type(callee, *parameter)
                                || scalar_value_type(function, argument.value)
                                    .is_none_or(|ty| !supported_source_value_type(input, ty))
                            {
                                return Err(unsupported("scalar call arguments"));
                            }
                        }
                        let result_matches = scalar_call_results_match(
                            input,
                            function,
                            callee,
                            &statement.results,
                            is_cancelled,
                        )?;
                        if !result_matches {
                            return Err(unsupported("scalar call results"));
                        }
                    }
                    _ => return Err(unsupported("non-scalar source operation")),
                },
                semantic::SemanticStatement::If {
                    condition,
                    then_region,
                    else_region,
                    results,
                    ..
                } => {
                    if scalar_value_type(function, *condition).is_none_or(|ty| {
                        !semantic_type_is(input, ty, semantic::PrimitiveType::Bool)
                    }) {
                        return Err(unsupported("scalar branch condition type"));
                    }
                    for result in results {
                        check_cancelled(is_cancelled)?;
                        if scalar_value_type(function, *result)
                            .is_none_or(|ty| !supported_source_value_type(input, ty))
                        {
                            return Err(unsupported("scalar branch result type"));
                        }
                    }
                    let next = depth.checked_add(1).ok_or(LowerError::ResourceLimit {
                        resource: "source region depth",
                        limit: u64::from(limits.region_depth),
                    })?;
                    let branch_contract = if results.is_empty() {
                        match contract {
                            ScalarRegionContract::LoopBody(arity)
                            | ScalarRegionContract::LoopBranch(arity) => {
                                ScalarRegionContract::LoopBranch(arity)
                            }
                            _ => ScalarRegionContract::Fallthrough,
                        }
                    } else {
                        ScalarRegionContract::Yield(results)
                    };
                    push_bounded(
                        &mut regions,
                        (else_region, branch_contract, next),
                        "source region validation",
                        limits.model_edges,
                    )?;
                    push_bounded(
                        &mut regions,
                        (then_region, branch_contract, next),
                        "source region validation",
                        limits.model_edges,
                    )?;
                }
                semantic::SemanticStatement::Match {
                    scrutinee,
                    arms,
                    results,
                    ..
                } => {
                    let enum_ty = scalar_value_type(function, *scrutinee)
                        .and_then(|ty| input.types.get(ty.0 as usize));
                    let variant_count = enum_ty.and_then(|ty| match &ty.kind {
                        semantic::TypeKind::Enum { variants } => Some(variants.len()),
                        _ => None,
                    });
                    let terminal = results.is_empty();
                    if variant_count != Some(arms.len())
                        || (terminal
                            && (!matches!(contract, ScalarRegionContract::Root)
                                || index + 1 != region.statements.len()))
                        || (!terminal
                            && !exact_result_try_match_protocol(
                                input,
                                function,
                                enum_ty.ok_or_else(|| unsupported("result match enum type"))?,
                                arms,
                                results,
                            ))
                    {
                        return Err(unsupported("terminal closed enum match contract"));
                    }
                    let next = depth.checked_add(1).ok_or(LowerError::ResourceLimit {
                        resource: "source region depth",
                        limit: u64::from(limits.region_depth),
                    })?;
                    let mut seen = vec![false; arms.len()];
                    for arm in arms.iter().rev() {
                        check_cancelled(is_cancelled)?;
                        let Some(variant) = arm.variant else {
                            return Err(unsupported("explicit enum match variant"));
                        };
                        let Some(slot) = seen.get_mut(variant as usize) else {
                            return Err(unsupported("enum match variant range"));
                        };
                        if std::mem::replace(slot, true)
                            || arm.guard.is_some()
                            || arm.bindings.len() != 1
                        {
                            return Err(unsupported("canonical enum match arm"));
                        }
                        push_bounded(
                            &mut regions,
                            (
                                &arm.body,
                                if terminal {
                                    ScalarRegionContract::MatchArm(&arm.bindings)
                                } else {
                                    ScalarRegionContract::ResultMatchArm {
                                        bindings: &arm.bindings,
                                        results,
                                    }
                                },
                                next,
                            ),
                            "source region validation",
                            limits.model_edges,
                        )?;
                    }
                    terminated = terminal;
                }
                semantic::SemanticStatement::Loop {
                    body,
                    carried,
                    uninterrupted_bound,
                    ..
                } => {
                    let Some(bound) = uninterrupted_bound.filter(|bound| *bound > 0) else {
                        return Err(unsupported("synchronous loop uninterrupted-work proof"));
                    };
                    let arity = body.parameters.len();
                    if carried.len() != arity.saturating_mul(3)
                        || bound > function.uninterrupted_bound.unwrap_or(0)
                    {
                        return Err(unsupported("scalar loop carried-value contract"));
                    }
                    for index in 0..arity {
                        let ty = scalar_value_type(function, carried[index]);
                        if ty != scalar_value_type(function, carried[arity + index])
                            || ty != scalar_value_type(function, carried[2 * arity + index])
                        {
                            return Err(unsupported("scalar loop carried-value type"));
                        }
                    }
                    let next = depth.checked_add(1).ok_or(LowerError::ResourceLimit {
                        resource: "source region depth",
                        limit: u64::from(limits.region_depth),
                    })?;
                    push_bounded(
                        &mut regions,
                        (body, ScalarRegionContract::LoopBody(arity), next),
                        "source region validation",
                        limits.model_edges,
                    )?;
                }
                semantic::SemanticStatement::Break(values)
                | semantic::SemanticStatement::Continue(values)
                    if matches!(contract, ScalarRegionContract::LoopBody(arity) | ScalarRegionContract::LoopBranch(arity) if values.len() == arity) =>
                {
                    if index + 1 != region.statements.len() {
                        return Err(unsupported("scalar loop control position"));
                    }
                    terminated = true;
                }
                semantic::SemanticStatement::Return(values)
                    if matches!(
                        contract,
                        ScalarRegionContract::Root
                            | ScalarRegionContract::MatchArm(_)
                            | ScalarRegionContract::ResultMatchArm { .. }
                    ) =>
                {
                    let result_matches = if semantic_type_is(
                        input,
                        function.result,
                        semantic::PrimitiveType::Unit,
                    ) {
                        values.is_empty()
                    } else {
                        matches!(
                            values.as_slice(),
                            [value]
                                if scalar_value_type(function, *value) == Some(function.result)
                        )
                    };
                    if !result_matches || index + 1 != region.statements.len() {
                        return Err(unsupported("scalar source return"));
                    }
                    terminated = true;
                }
                semantic::SemanticStatement::Yield(values)
                    if matches!(
                        contract,
                        ScalarRegionContract::Yield(_)
                            | ScalarRegionContract::ResultMatchArm { .. }
                    ) =>
                {
                    let expected = match contract {
                        ScalarRegionContract::Yield(expected)
                        | ScalarRegionContract::ResultMatchArm {
                            results: expected, ..
                        } => expected,
                        _ => unreachable!(),
                    };
                    if values.len() != expected.len() || index + 1 != region.statements.len() {
                        return Err(unsupported("scalar branch yield arity or position"));
                    }
                    for (value, result) in values.iter().zip(expected) {
                        check_cancelled(is_cancelled)?;
                        if scalar_value_type(function, *value)
                            != scalar_value_type(function, *result)
                        {
                            return Err(unsupported("scalar branch yield type"));
                        }
                    }
                    terminated = true;
                }
                semantic::SemanticStatement::Return(_)
                | semantic::SemanticStatement::Unreachable
                | semantic::SemanticStatement::Yield(_)
                | semantic::SemanticStatement::Break(_)
                | semantic::SemanticStatement::Continue(_) => {
                    return Err(unsupported("non-fallthrough scalar source region"));
                }
            }
        }
        match contract {
            ScalarRegionContract::Root | ScalarRegionContract::MatchArm(_) if !terminated => {
                return Err(unsupported("scalar source root terminator"));
            }
            ScalarRegionContract::ResultMatchArm { .. } if !terminated => {
                return Err(unsupported("result match arm terminator"));
            }
            ScalarRegionContract::Yield(_) if !terminated => {
                return Err(unsupported("scalar branch yield terminator"));
            }
            ScalarRegionContract::Fallthrough if terminated => {
                return Err(unsupported("scalar fallthrough region terminator"));
            }
            ScalarRegionContract::Root
            | ScalarRegionContract::MatchArm(_)
            | ScalarRegionContract::ResultMatchArm { .. }
            | ScalarRegionContract::Fallthrough
            | ScalarRegionContract::Yield(_)
            | ScalarRegionContract::LoopBody(_)
            | ScalarRegionContract::LoopBranch(_) => {}
        }
    }
    Ok(())
}

fn exact_result_try_match_protocol(
    input: &semantic::SemanticWir,
    function: &semantic::SemanticFunction,
    enum_type: &semantic::TypeRecord,
    arms: &[semantic::SemanticMatchArm],
    results: &[semantic::ValueId],
) -> bool {
    let semantic::TypeKind::Enum { variants } = &enum_type.kind else {
        return false;
    };
    let ([ok_variant, err_variant], [ok_arm, err_arm], [result]) =
        (variants.as_slice(), arms, results)
    else {
        return false;
    };
    let ([ok_field], [err_field], [ok_binding], [err_binding]) = (
        ok_variant.fields.as_slice(),
        err_variant.fields.as_slice(),
        ok_arm.bindings.as_slice(),
        err_arm.bindings.as_slice(),
    ) else {
        return false;
    };
    if ok_variant.name != "Ok"
        || err_variant.name != "Err"
        || !ok_field.name.is_empty()
        || !err_field.name.is_empty()
        || !ok_field.public
        || !err_field.public
        || ok_field.ty != err_field.ty
        || scalar_primitive(input, ok_field.ty).is_none()
        || function.result != enum_type.id
        || scalar_value_type(function, *result) != Some(ok_field.ty)
        || ok_arm.variant != Some(0)
        || err_arm.variant != Some(1)
        || ok_arm.guard.is_some()
        || err_arm.guard.is_some()
        || ok_arm.body.parameters.as_slice() != [*ok_binding]
        || err_arm.body.parameters.as_slice() != [*err_binding]
        || scalar_value_type(function, *ok_binding) != Some(ok_field.ty)
        || scalar_value_type(function, *err_binding) != Some(err_field.ty)
        || !matches!(ok_arm.body.statements.as_slice(),
            [semantic::SemanticStatement::Yield(values)] if values.as_slice() == [*ok_binding])
    {
        return false;
    }
    let [
        semantic::SemanticStatement::Let(propagated),
        semantic::SemanticStatement::Return(returned),
    ] = err_arm.body.statements.as_slice()
    else {
        return false;
    };
    let [propagated_value] = propagated.results.as_slice() else {
        return false;
    };
    matches!(
        propagated.operation,
        semantic::SemanticOperation::ConstructEnum {
            ty,
            variant: 1,
            payload,
        } if ty == enum_type.id && payload == *err_binding
    ) && returned.as_slice() == [*propagated_value]
        && scalar_value_type(function, *propagated_value) == Some(enum_type.id)
}

fn validate_generated_harness(
    input: &semantic::SemanticWir,
    harness: &semantic::SemanticFunction,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LowerError> {
    let event_count = input
        .tests
        .len()
        .checked_mul(2)
        .and_then(|count| count.checked_add(2))
        .ok_or(unsupported("generated test event count"))?;
    let expected_values = event_count
        .checked_add(1)
        .ok_or(unsupported("generated test value count"))?;
    if harness.values.len() != expected_values {
        return Err(unsupported("generated test harness values"));
    }
    let expected_statements = event_count
        .checked_mul(2)
        .and_then(|count| count.checked_add(input.tests.len()))
        .and_then(|count| count.checked_add(3))
        .ok_or(unsupported("generated test statement count"))?;
    if harness.body.statements.len() != expected_statements {
        return Err(unsupported("generated test harness statement sequence"));
    }
    let mut statement = 0usize;
    let mut value = 0usize;
    validate_frame_pair(input, harness, &mut statement, &mut value)?;
    for test in &input.tests {
        check_cancelled(is_cancelled)?;
        validate_frame_pair(input, harness, &mut statement, &mut value)?;
        match harness.body.statements.get(statement) {
            Some(semantic::SemanticStatement::Let(semantic::LetStatement {
                results,
                operation:
                    semantic::SemanticOperation::Call {
                        function,
                        arguments,
                        activation: None,
                    },
                source,
            })) if results.is_empty()
                && *function == test.function
                && arguments.is_empty()
                && *source == Some(test.source) => {}
            _ => return Err(unsupported("generated test harness calls")),
        }
        statement += 1;
        validate_frame_pair(input, harness, &mut statement, &mut value)?;
    }
    validate_frame_pair(input, harness, &mut statement, &mut value)?;
    let outcome = semantic::ValueId(
        u32::try_from(value).map_err(|_| unsupported("generated test outcome identity"))?,
    );
    let outcome_value = harness.values.get(value);
    if !outcome_value.is_some_and(|record| {
        record.id == outcome
            && semantic_type_is(input, record.ty, semantic::PrimitiveType::U32)
            && record.origin.is_none()
            && record.name.is_none()
    }) || !matches!(
        harness.body.statements.get(statement),
        Some(semantic::SemanticStatement::Let(semantic::LetStatement {
            results,
            operation: semantic::SemanticOperation::Constant(
                semantic::Constant::Unsigned { bits: 32, value: 0 }
            ),
            source: None,
        })) if results.as_slice() == [outcome]
    ) || !matches!(
        harness.body.statements.get(statement + 1),
        Some(semantic::SemanticStatement::Let(semantic::LetStatement {
            results,
            operation: semantic::SemanticOperation::TestFinish { outcome: finished },
            source: None,
        })) if results.is_empty() && *finished == outcome
    ) || !matches!(
        harness.body.statements.get(statement + 2),
        Some(semantic::SemanticStatement::Unreachable)
    ) {
        return Err(unsupported("generated test terminal outcome"));
    }
    Ok(())
}

fn validate_frame_pair(
    input: &semantic::SemanticWir,
    harness: &semantic::SemanticFunction,
    statement: &mut usize,
    value: &mut usize,
) -> Result<(), LowerError> {
    let value_id = semantic::ValueId(
        u32::try_from(*value).map_err(|_| unsupported("generated test frame identity"))?,
    );
    let Some(record) = harness.values.get(*value) else {
        return Err(unsupported("generated test frame value"));
    };
    let Some(semantic::SemanticStatement::Let(constant)) = harness.body.statements.get(*statement)
    else {
        return Err(unsupported("generated test frame constant"));
    };
    let semantic::SemanticOperation::Constant(semantic::Constant::Bytes(bytes)) =
        &constant.operation
    else {
        return Err(unsupported("generated test frame constant"));
    };
    let frame_type_matches = input
        .types
        .get(record.ty.0 as usize)
        .and_then(|ty| match ty.kind {
            semantic::TypeKind::Array { element, length } => Some((element, length)),
            _ => None,
        })
        .is_some_and(|(element, length)| {
            usize::try_from(length) == Ok(bytes.len())
                && semantic_type_is(input, element, semantic::PrimitiveType::U8)
        });
    if record.id != value_id
        || record.origin.is_some()
        || record.name.is_some()
        || !frame_type_matches
        || constant.results.as_slice() != [value_id]
        || constant.source.is_some()
        || !matches!(
            harness.body.statements.get(*statement + 1),
            Some(semantic::SemanticStatement::Let(semantic::LetStatement {
                results,
                operation: semantic::SemanticOperation::TestEmit { payload },
                source: None,
            })) if results.is_empty() && *payload == value_id
        )
    {
        return Err(unsupported("generated test frame emission"));
    }
    *statement += 2;
    *value += 1;
    Ok(())
}

fn check_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), LowerError> {
    if is_cancelled() {
        Err(LowerError::Cancelled)
    } else {
        Ok(())
    }
}

fn polled_joined_name_matches(
    joined: &str,
    base: &str,
    suffix: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LowerError> {
    let Some(prefix_bytes) = joined.len().checked_sub(suffix.len()) else {
        return Ok(false);
    };
    if prefix_bytes != base.len() {
        return Ok(false);
    }
    let (prefix, actual_suffix) = joined.as_bytes().split_at(prefix_bytes);
    if actual_suffix != suffix.as_bytes() {
        return Ok(false);
    }
    for (actual, expected) in prefix.chunks(4096).zip(base.as_bytes().chunks(4096)) {
        check_cancelled(is_cancelled)?;
        if actual != expected {
            return Ok(false);
        }
    }
    Ok(true)
}

fn semantic_proof_attachments_match(
    source: &[wrela_semantic_wir::ProofId],
    output: &[wrela_flow_wir::ProofId],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LowerError> {
    if source.len() != output.len() {
        return Ok(false);
    }
    for (source, output) in source.iter().zip(output) {
        check_cancelled(is_cancelled)?;
        if source.0 != output.0 {
            return Ok(false);
        }
    }
    Ok(true)
}

fn check_count(resource: &'static str, count: usize, limit: u64) -> Result<u64, LowerError> {
    let count = u64::try_from(count).map_err(|_| LowerError::ResourceLimit { resource, limit })?;
    if count > limit {
        Err(LowerError::ResourceLimit { resource, limit })
    } else {
        Ok(count)
    }
}

fn add_bounded(
    total: &mut u64,
    count: usize,
    resource: &'static str,
    limit: u64,
) -> Result<(), LowerError> {
    let count = check_count(resource, count, limit)?;
    *total = total
        .checked_add(count)
        .filter(|total| *total <= limit)
        .ok_or(LowerError::ResourceLimit { resource, limit })?;
    Ok(())
}

fn preflight_input(
    input: &semantic::SemanticWir,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(u64, u64), LowerError> {
    let mut blocks = check_count("FlowWir blocks", input.functions.len(), limits.blocks)?;
    let mut edges = 0u64;
    let mut payload = 0u64;
    let mut instructions = 0u64;
    for count in [
        input.types.len(),
        input.globals.len(),
        input.functions.len(),
        input.actors.len(),
        input.tasks.len(),
        input.devices.len(),
        input.pools.len(),
        input.regions.len(),
        input.activations.len(),
        input.scopes.len(),
        input.proofs.len(),
        input.tests.len(),
        input.startup_order.len(),
        input.shutdown_order.len(),
    ] {
        add_bounded(
            &mut edges,
            count,
            "semantic model edges",
            limits.model_edges,
        )?;
    }
    for text in [input.name.as_str(), input.build.target.as_str()] {
        add_bounded(
            &mut payload,
            text.len(),
            "semantic payload bytes",
            limits.payload_bytes,
        )?;
    }
    for ty in &input.types {
        check_cancelled(is_cancelled)?;
        add_bounded(
            &mut payload,
            ty.source_name.len(),
            "semantic payload bytes",
            limits.payload_bytes,
        )?;
        match &ty.kind {
            semantic::TypeKind::Tuple(items) => add_bounded(
                &mut edges,
                items.len(),
                "semantic model edges",
                limits.model_edges,
            )?,
            semantic::TypeKind::Struct { fields } => {
                add_bounded(
                    &mut edges,
                    fields.len(),
                    "semantic model edges",
                    limits.model_edges,
                )?;
                for field in fields {
                    add_bounded(
                        &mut payload,
                        field.name.len(),
                        "semantic payload bytes",
                        limits.payload_bytes,
                    )?;
                }
            }
            semantic::TypeKind::Enum { variants } => {
                add_bounded(
                    &mut edges,
                    variants.len(),
                    "semantic model edges",
                    limits.model_edges,
                )?;
                for variant in variants {
                    add_bounded(
                        &mut payload,
                        variant.name.len(),
                        "semantic payload bytes",
                        limits.payload_bytes,
                    )?;
                    add_bounded(
                        &mut edges,
                        variant.fields.len(),
                        "semantic model edges",
                        limits.model_edges,
                    )?;
                    for field in &variant.fields {
                        add_bounded(
                            &mut payload,
                            field.name.len(),
                            "semantic payload bytes",
                            limits.payload_bytes,
                        )?;
                    }
                }
            }
            semantic::TypeKind::Function(function) => add_bounded(
                &mut edges,
                function.parameters.len(),
                "semantic model edges",
                limits.model_edges,
            )?,
            semantic::TypeKind::OpaqueTarget { name } => add_bounded(
                &mut payload,
                name.len(),
                "semantic payload bytes",
                limits.payload_bytes,
            )?,
            semantic::TypeKind::Primitive(_)
            | semantic::TypeKind::Array { .. }
            | semantic::TypeKind::Iso { .. }
            | semantic::TypeKind::ActorHandle { .. }
            | semantic::TypeKind::Reservation
            | semantic::TypeKind::Receipt { .. }
            | semantic::TypeKind::DmaPayload { .. }
            | semantic::TypeKind::DmaShared { .. }
            | semantic::TypeKind::Mmio { .. }
            | semantic::TypeKind::Validated { .. } => {}
        }
    }
    for function in &input.functions {
        check_cancelled(is_cancelled)?;
        let mut async_states = 0_u32;
        for count in [
            function.parameters.len(),
            function.values.len(),
            function.proofs.len(),
        ] {
            add_bounded(
                &mut edges,
                count,
                "semantic model edges",
                limits.model_edges,
            )?;
        }
        add_bounded(
            &mut payload,
            function.name.len(),
            "semantic payload bytes",
            limits.payload_bytes,
        )?;
        for value in &function.values {
            check_cancelled(is_cancelled)?;
            if let Some(name) = &value.name {
                add_bounded(
                    &mut payload,
                    name.len(),
                    "semantic payload bytes",
                    limits.payload_bytes,
                )?;
            }
        }
        let mut regions = try_vec(1, "semantic region preflight", limits.model_edges)?;
        regions.push((&function.body, 1_u32));
        while let Some((region, depth)) = regions.pop() {
            check_cancelled(is_cancelled)?;
            if depth > limits.region_depth {
                return Err(LowerError::ResourceLimit {
                    resource: "semantic region depth",
                    limit: u64::from(limits.region_depth),
                });
            }
            for count in [region.parameters.len(), region.statements.len()] {
                add_bounded(
                    &mut edges,
                    count,
                    "semantic model edges",
                    limits.model_edges,
                )?;
            }
            for statement in &region.statements {
                check_cancelled(is_cancelled)?;
                match statement {
                    semantic::SemanticStatement::Let(statement) => {
                        if matches!(
                            statement.operation,
                            semantic::SemanticOperation::Await { .. }
                        ) {
                            async_states = async_states
                                .checked_add(1)
                                .filter(|count| *count <= limits.states_per_function)
                                .ok_or(LowerError::ResourceLimit {
                                    resource: "FlowWir async states",
                                    limit: u64::from(limits.states_per_function),
                                })?;
                            blocks = blocks
                                .checked_add(1)
                                .filter(|blocks| *blocks <= limits.blocks)
                                .ok_or(LowerError::ResourceLimit {
                                    resource: "FlowWir blocks",
                                    limit: limits.blocks,
                                })?;
                        } else {
                            instructions = instructions
                                .checked_add(1)
                                .filter(|count| *count <= limits.instructions)
                                .ok_or(LowerError::ResourceLimit {
                                    resource: "FlowWir instructions",
                                    limit: limits.instructions,
                                })?;
                        }
                        add_bounded(
                            &mut edges,
                            statement.results.len(),
                            "semantic model edges",
                            limits.model_edges,
                        )?;
                        match &statement.operation {
                            semantic::SemanticOperation::Constant(semantic::Constant::Bytes(
                                bytes,
                            )) => add_bounded(
                                &mut payload,
                                bytes.len(),
                                "semantic payload bytes",
                                limits.payload_bytes,
                            )?,
                            semantic::SemanticOperation::Constant(semantic::Constant::String(
                                text,
                            )) => add_bounded(
                                &mut payload,
                                text.len(),
                                "semantic payload bytes",
                                limits.payload_bytes,
                            )?,
                            semantic::SemanticOperation::Call { arguments, .. } => add_bounded(
                                &mut edges,
                                arguments.len(),
                                "semantic model edges",
                                limits.model_edges,
                            )?,
                            semantic::SemanticOperation::Aggregate { fields, .. }
                            | semantic::SemanticOperation::Select { awaitables: fields }
                            | semantic::SemanticOperation::Race { awaitables: fields }
                            | semantic::SemanticOperation::QueuePublish {
                                payloads: fields, ..
                            } => add_bounded(
                                &mut edges,
                                fields.len(),
                                "semantic model edges",
                                limits.model_edges,
                            )?,
                            semantic::SemanticOperation::ActorCommit { arguments, .. }
                            | semantic::SemanticOperation::SpawnTask { arguments, .. } => {
                                add_bounded(
                                    &mut edges,
                                    arguments.len(),
                                    "semantic model edges",
                                    limits.model_edges,
                                )?;
                            }
                            semantic::SemanticOperation::Constant(_)
                            | semantic::SemanticOperation::ActorStateLoad { .. }
                            | semantic::SemanticOperation::ActorStateStore { .. }
                            | semantic::SemanticOperation::Unary { .. }
                            | semantic::SemanticOperation::Binary { .. }
                            | semantic::SemanticOperation::Convert { .. }
                            | semantic::SemanticOperation::ConstructEnum { .. }
                            | semantic::SemanticOperation::InsertField { .. }
                            | semantic::SemanticOperation::Project { .. }
                            | semantic::SemanticOperation::Index { .. }
                            | semantic::SemanticOperation::BeginAccess { .. }
                            | semantic::SemanticOperation::EndAccess { .. }
                            | semantic::SemanticOperation::Move { .. }
                            | semantic::SemanticOperation::Copy { .. }
                            | semantic::SemanticOperation::Drop { .. }
                            | semantic::SemanticOperation::ActorCapability { .. }
                            | semantic::SemanticOperation::ActorReserve { .. }
                            | semantic::SemanticOperation::MailboxReceive { .. }
                            | semantic::SemanticOperation::ActorSend { .. }
                            | semantic::SemanticOperation::ActorTrySend { .. }
                            | semantic::SemanticOperation::Await { .. }
                            | semantic::SemanticOperation::Cancel { .. }
                            | semantic::SemanticOperation::Checkpoint { .. }
                            | semantic::SemanticOperation::Allocate { .. }
                            | semantic::SemanticOperation::ResetRegion { .. }
                            | semantic::SemanticOperation::Promote { .. }
                            | semantic::SemanticOperation::EnterScope { .. }
                            | semantic::SemanticOperation::CommitScope { .. }
                            | semantic::SemanticOperation::AbortScope { .. }
                            | semantic::SemanticOperation::ExitScope { .. }
                            | semantic::SemanticOperation::DmaTransition { .. }
                            | semantic::SemanticOperation::MmioRead { .. }
                            | semantic::SemanticOperation::MmioWrite { .. }
                            | semantic::SemanticOperation::InterruptPublish { .. }
                            | semantic::SemanticOperation::QueueReserve { .. }
                            | semantic::SemanticOperation::Check { .. }
                            | semantic::SemanticOperation::Assert { .. }
                            | semantic::SemanticOperation::RecordEvent { .. }
                            | semantic::SemanticOperation::TestEmit { .. }
                            | semantic::SemanticOperation::TestFinish { .. } => {}
                        }
                    }
                    semantic::SemanticStatement::If {
                        then_region,
                        else_region,
                        results,
                        ..
                    } => {
                        blocks = blocks
                            .checked_add(3)
                            .filter(|blocks| *blocks <= limits.blocks)
                            .ok_or(LowerError::ResourceLimit {
                                resource: "FlowWir blocks",
                                limit: limits.blocks,
                            })?;
                        add_bounded(
                            &mut edges,
                            results.len(),
                            "semantic model edges",
                            limits.model_edges,
                        )?;
                        let next = depth.checked_add(1).ok_or(LowerError::ResourceLimit {
                            resource: "semantic region depth",
                            limit: u64::from(limits.region_depth),
                        })?;
                        push_bounded(
                            &mut regions,
                            (else_region, next),
                            "semantic region preflight",
                            limits.model_edges,
                        )?;
                        push_bounded(
                            &mut regions,
                            (then_region, next),
                            "semantic region preflight",
                            limits.model_edges,
                        )?;
                    }
                    semantic::SemanticStatement::Match { arms, results, .. } => {
                        let match_blocks = u64::try_from(arms.len())
                            .ok()
                            .and_then(|count| count.checked_add(1))
                            .and_then(|count| count.checked_add(u64::from(!results.is_empty())))
                            .ok_or(LowerError::ResourceLimit {
                                resource: "FlowWir blocks",
                                limit: limits.blocks,
                            })?;
                        blocks = blocks
                            .checked_add(match_blocks)
                            .filter(|blocks| *blocks <= limits.blocks)
                            .ok_or(LowerError::ResourceLimit {
                                resource: "FlowWir blocks",
                                limit: limits.blocks,
                            })?;
                        instructions = instructions
                            .checked_add(2)
                            .filter(|instructions| *instructions <= limits.instructions)
                            .ok_or(LowerError::ResourceLimit {
                                resource: "FlowWir instructions",
                                limit: limits.instructions,
                            })?;
                        add_bounded(
                            &mut edges,
                            arms.len(),
                            "semantic model edges",
                            limits.model_edges,
                        )?;
                        add_bounded(
                            &mut edges,
                            results.len(),
                            "semantic model edges",
                            limits.model_edges,
                        )?;
                        let next = depth.checked_add(1).ok_or(LowerError::ResourceLimit {
                            resource: "semantic region depth",
                            limit: u64::from(limits.region_depth),
                        })?;
                        for arm in arms.iter().rev() {
                            check_cancelled(is_cancelled)?;
                            add_bounded(
                                &mut edges,
                                arm.bindings.len(),
                                "semantic model edges",
                                limits.model_edges,
                            )?;
                            push_bounded(
                                &mut regions,
                                (&arm.body, next),
                                "semantic region preflight",
                                limits.model_edges,
                            )?;
                        }
                    }
                    semantic::SemanticStatement::Loop { body, carried, .. } => {
                        blocks = blocks
                            .checked_add(2)
                            .filter(|blocks| *blocks <= limits.blocks)
                            .ok_or(LowerError::ResourceLimit {
                                resource: "FlowWir blocks",
                                limit: limits.blocks,
                            })?;
                        add_bounded(
                            &mut edges,
                            carried.len(),
                            "semantic model edges",
                            limits.model_edges,
                        )?;
                        let next = depth.checked_add(1).ok_or(LowerError::ResourceLimit {
                            resource: "semantic region depth",
                            limit: u64::from(limits.region_depth),
                        })?;
                        push_bounded(
                            &mut regions,
                            (body, next),
                            "semantic region preflight",
                            limits.model_edges,
                        )?;
                    }
                    semantic::SemanticStatement::Return(values)
                    | semantic::SemanticStatement::Yield(values)
                    | semantic::SemanticStatement::Break(values)
                    | semantic::SemanticStatement::Continue(values) => add_bounded(
                        &mut edges,
                        values.len(),
                        "semantic model edges",
                        limits.model_edges,
                    )?,
                    semantic::SemanticStatement::Unreachable => {}
                }
            }
        }
    }
    for proof in &input.proofs {
        check_cancelled(is_cancelled)?;
        for count in [
            proof.sources.len(),
            proof.depends_on.len(),
            proof.explanation.len(),
        ] {
            add_bounded(
                &mut edges,
                count,
                "semantic model edges",
                limits.model_edges,
            )?;
        }
        add_bounded(
            &mut payload,
            proof.subject.len(),
            "semantic payload bytes",
            limits.payload_bytes,
        )?;
        for line in &proof.explanation {
            check_cancelled(is_cancelled)?;
            add_bounded(
                &mut payload,
                line.len(),
                "semantic payload bytes",
                limits.payload_bytes,
            )?;
        }
    }
    for actor in &input.actors {
        check_cancelled(is_cancelled)?;
        add_bounded(
            &mut payload,
            actor.name.len(),
            "semantic payload bytes",
            limits.payload_bytes,
        )?;
        for count in [actor.message_types.len(), actor.turn_functions.len()] {
            add_bounded(
                &mut edges,
                count,
                "semantic model edges",
                limits.model_edges,
            )?;
        }
    }
    for task in &input.tasks {
        check_cancelled(is_cancelled)?;
        add_bounded(
            &mut payload,
            task.name.len(),
            "semantic payload bytes",
            limits.payload_bytes,
        )?;
    }
    for region in &input.regions {
        check_cancelled(is_cancelled)?;
        add_bounded(
            &mut payload,
            region.name.len(),
            "semantic payload bytes",
            limits.payload_bytes,
        )?;
    }
    for test in &input.tests {
        check_cancelled(is_cancelled)?;
        add_bounded(
            &mut payload,
            test.name.len(),
            "semantic payload bytes",
            limits.payload_bytes,
        )?;
    }
    Ok((edges, payload))
}

fn lower_minimum(
    minimum: MinimumSemantic<'_>,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<FlowWir, LowerError> {
    check_cancelled(is_cancelled)?;
    let input = minimum.input;
    let mut types = try_vec(input.types.len(), "FlowWir types", limits.model_edges)?;
    types.push(flow::FlowType {
        id: flow::TypeId(minimum.ty.id.0),
        kind: flow::FlowTypeKind::Unit,
        name: Some(copy_text(&minimum.ty.source_name, limits.payload_bytes)?),
        copyable: true,
        strict_linear: false,
    });

    let mut proofs = try_vec(input.proofs.len(), "FlowWir proofs", limits.model_edges)?;
    for proof in &input.proofs {
        check_cancelled(is_cancelled)?;
        let mut sources = try_vec(
            proof.sources.len(),
            "FlowWir proof sources",
            limits.model_edges,
        )?;
        sources.extend_from_slice(&proof.sources);
        let mut depends_on = try_vec(
            proof.depends_on.len(),
            "FlowWir proof dependencies",
            limits.model_edges,
        )?;
        depends_on.extend(proof.depends_on.iter().map(|id| flow::ProofId(id.0)));
        let mut explanation = try_vec(
            proof.explanation.len(),
            "FlowWir proof explanations",
            limits.model_edges,
        )?;
        for line in &proof.explanation {
            check_cancelled(is_cancelled)?;
            explanation.push(copy_text(line, limits.payload_bytes)?);
        }
        proofs.push(flow::Proof {
            id: flow::ProofId(proof.id.0),
            kind: lower_proof_kind(&proof.kind),
            subject: copy_text(&proof.subject, limits.payload_bytes)?,
            sources,
            depends_on,
            bound: proof.bound,
            explanation,
        });
    }

    let mut blocks = try_vec(1, "FlowWir blocks", limits.blocks)?;
    blocks.push(flow::Block {
        id: flow::BlockId(0),
        parameters: Vec::new(),
        instructions: Vec::new(),
        terminator: flow::Terminator::Return(Vec::new()),
        source: None,
    });
    let mut functions = try_vec(1, "FlowWir functions", limits.model_edges)?;
    let mut function_proofs = try_vec(
        minimum.function.proofs.len(),
        "FlowWir function proofs",
        limits.model_edges,
    )?;
    function_proofs.extend(
        minimum
            .function
            .proofs
            .iter()
            .map(|proof| flow::ProofId(proof.0)),
    );
    functions.push(flow::FlowFunction {
        id: flow::FunctionId(minimum.function.id.0),
        name: copy_text(&minimum.function.name, limits.payload_bytes)?,
        origin: flow::FunctionOrigin::GeneratedImageEntry {
            semantic_function: minimum.function.id.0,
            constructor: minimum.constructor,
        },
        role: flow::FunctionRole::ImageEntry,
        color: flow::FunctionColor::Sync,
        parameters: Vec::new(),
        result_types: Vec::new(),
        values: Vec::new(),
        blocks,
        entry: flow::BlockId(0),
        stack_bound: minimum.function.stack_bound,
        frame_bound: minimum.function.frame_bound,
        proofs: function_proofs,
        source: minimum.function.source,
    });

    let startup_order = lower_owners(&input.startup_order, limits.model_edges, is_cancelled)?;
    let shutdown_order = lower_owners(&input.shutdown_order, limits.model_edges, is_cancelled)?;
    check_cancelled(is_cancelled)?;
    Ok(FlowWir {
        version: flow::FLOW_WIR_VERSION,
        name: copy_text(&input.name, limits.payload_bytes)?,
        build: input.build.clone(),
        source_summary: flow::SourceSummary {
            semantic_wir_version: semantic::SEMANTIC_WIR_VERSION,
            semantic_functions: u32::try_from(input.functions.len()).map_err(|_| {
                LowerError::ResourceLimit {
                    resource: "semantic functions",
                    limit: limits.model_edges,
                }
            })?,
            hir_files: input.source_summary.hir_files,
            hir_declarations: input.source_summary.hir_declarations,
            reachable_declarations: input.source_summary.reachable_declarations,
            monomorphized_instantiations: input.source_summary.monomorphized_instantiations,
            resolved_interface_calls: input.source_summary.resolved_interface_calls,
        },
        types,
        globals: Vec::new(),
        functions,
        actors: Vec::new(),
        tasks: Vec::new(),
        devices: Vec::new(),
        pools: Vec::new(),
        regions: Vec::new(),
        activations: Vec::new(),
        proofs,
        checkpoints: Vec::new(),
        tests: Vec::new(),
        compiled_test_group: input.compiled_test_group.clone(),
        startup_order,
        shutdown_order,
        image_entry: flow::FunctionId(input.image_entry.0),
        static_bytes: input.static_bytes,
        peak_bytes: input.peak_bytes,
    })
}

fn lower_generated_type(
    ty: &semantic::TypeRecord,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<flow::FlowType, LowerError> {
    check_cancelled(is_cancelled)?;
    let kind = match &ty.kind {
        semantic::TypeKind::Primitive(semantic::PrimitiveType::Unit) => flow::FlowTypeKind::Unit,
        semantic::TypeKind::Primitive(semantic::PrimitiveType::Bool) => {
            flow::FlowTypeKind::Scalar(flow::ScalarType::Bool)
        }
        semantic::TypeKind::Primitive(semantic::PrimitiveType::F32) => {
            flow::FlowTypeKind::Scalar(flow::ScalarType::Float32)
        }
        semantic::TypeKind::Primitive(semantic::PrimitiveType::F64) => {
            flow::FlowTypeKind::Scalar(flow::ScalarType::Float64)
        }
        semantic::TypeKind::Primitive(primitive) => {
            let Some((signed, bits)) = integer_primitive(*primitive) else {
                return Err(unsupported("generated test primitive type"));
            };
            flow::FlowTypeKind::Scalar(flow::ScalarType::Integer {
                signed,
                bits: u16::from(bits),
            })
        }
        semantic::TypeKind::Array { element, length } => flow::FlowTypeKind::Array {
            element: flow::TypeId(element.0),
            length: *length,
        },
        semantic::TypeKind::Struct { fields } => {
            let mut lowered =
                try_vec(fields.len(), "FlowWir structure fields", limits.model_edges)?;
            for field in fields {
                check_cancelled(is_cancelled)?;
                lowered.push(flow::TypeId(field.ty.0));
            }
            flow::FlowTypeKind::Struct { fields: lowered }
        }
        semantic::TypeKind::Enum { variants } => {
            let mut lowered = try_vec(variants.len(), "FlowWir enum variants", limits.model_edges)?;
            for variant in variants {
                check_cancelled(is_cancelled)?;
                let mut fields = try_vec(
                    variant.fields.len(),
                    "FlowWir enum payload fields",
                    limits.model_edges,
                )?;
                for field in &variant.fields {
                    check_cancelled(is_cancelled)?;
                    fields.push(flow::TypeId(field.ty.0));
                }
                lowered.push(fields);
            }
            flow::FlowTypeKind::Enum { variants: lowered }
        }
        semantic::TypeKind::Function(function) => {
            let mut parameters = try_vec(
                function.parameters.len(),
                "FlowWir function type parameters",
                limits.model_edges,
            )?;
            for parameter in &function.parameters {
                check_cancelled(is_cancelled)?;
                if parameter.access != semantic::AccessMode::Read {
                    return Err(unsupported("non-read scalar function type parameter"));
                }
                parameters.push(flow::TypeId(parameter.ty.0));
            }
            flow::FlowTypeKind::Function {
                parameters,
                result: flow::TypeId(function.result.0),
            }
        }
        semantic::TypeKind::Tuple(_)
        | semantic::TypeKind::Iso { .. }
        | semantic::TypeKind::ActorHandle { .. }
        | semantic::TypeKind::Reservation
        | semantic::TypeKind::Receipt { .. }
        | semantic::TypeKind::DmaPayload { .. }
        | semantic::TypeKind::DmaShared { .. }
        | semantic::TypeKind::Mmio { .. }
        | semantic::TypeKind::Validated { .. }
        | semantic::TypeKind::OpaqueTarget { .. } => {
            return Err(unsupported("generated test types changed after validation"));
        }
    };
    Ok(flow::FlowType {
        id: flow::TypeId(ty.id.0),
        kind,
        name: Some(copy_text(&ty.source_name, limits.payload_bytes)?),
        copyable: matches!(
            ty.linearity,
            semantic::Linearity::CopyScalar | semantic::Linearity::ExplicitCopy
        ),
        strict_linear: ty.linearity == semantic::Linearity::Strict,
    })
}

fn lower_actor_type(
    ty: &semantic::TypeRecord,
    actors: &[semantic::ActorInstance],
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<flow::FlowType, LowerError> {
    check_cancelled(is_cancelled)?;
    let kind = match &ty.kind {
        semantic::TypeKind::Primitive(semantic::PrimitiveType::Unit) => flow::FlowTypeKind::Unit,
        semantic::TypeKind::Primitive(semantic::PrimitiveType::Bool) => {
            flow::FlowTypeKind::Scalar(flow::ScalarType::Bool)
        }
        semantic::TypeKind::Primitive(semantic::PrimitiveType::F32) => {
            flow::FlowTypeKind::Scalar(flow::ScalarType::Float32)
        }
        semantic::TypeKind::Primitive(semantic::PrimitiveType::F64) => {
            flow::FlowTypeKind::Scalar(flow::ScalarType::Float64)
        }
        semantic::TypeKind::Primitive(primitive) => {
            let Some((signed, bits)) = integer_primitive(*primitive) else {
                return Err(unsupported("actor primitive type changed after validation"));
            };
            flow::FlowTypeKind::Scalar(flow::ScalarType::Integer {
                signed,
                bits: u16::from(bits),
            })
        }
        semantic::TypeKind::Array { element, length } => flow::FlowTypeKind::Array {
            element: flow::TypeId(element.0),
            length: *length,
        },
        semantic::TypeKind::Struct { fields } if fields.is_empty() => {
            flow::FlowTypeKind::Struct { fields: Vec::new() }
        }
        semantic::TypeKind::Function(function) => {
            let mut parameters = try_vec(
                function.parameters.len(),
                "FlowWir actor function type parameters",
                limits.model_edges,
            )?;
            for parameter in &function.parameters {
                check_cancelled(is_cancelled)?;
                parameters.push(flow::TypeId(parameter.ty.0));
            }
            flow::FlowTypeKind::Function {
                parameters,
                result: flow::TypeId(function.result.0),
            }
        }
        semantic::TypeKind::ActorHandle { actor_type } => {
            let mut targets = actors.iter().filter(|actor| actor.ty == *actor_type);
            let target = targets
                .next()
                .filter(|_| targets.next().is_none())
                .ok_or_else(|| unsupported("ambiguous image-wired actor capability target"))?;
            flow::FlowTypeKind::ActorHandle(flow::ActorId(target.id.0))
        }
        semantic::TypeKind::Reservation => flow::FlowTypeKind::Reservation,
        _ => return Err(unsupported("actor type changed after shape validation")),
    };
    Ok(flow::FlowType {
        id: flow::TypeId(ty.id.0),
        kind,
        name: Some(copy_text(&ty.source_name, limits.payload_bytes)?),
        copyable: matches!(
            ty.linearity,
            semantic::Linearity::CopyScalar | semantic::Linearity::ExplicitCopy
        ),
        strict_linear: ty.linearity == semantic::Linearity::Strict,
    })
}

fn append_activation_types(
    input: &semantic::SemanticWir,
    types: &mut Vec<flow::FlowType>,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<Option<flow::TypeId>>, LowerError> {
    let mut required = try_vec(
        input.types.len(),
        "FlowWir activation type map",
        limits.model_edges,
    )?;
    required.resize(input.types.len(), false);
    for function in &input.functions {
        let mut regions = try_vec(1, "activation type scan", limits.model_edges)?;
        regions.push(&function.body);
        while let Some(region) = regions.pop() {
            check_cancelled(is_cancelled)?;
            for statement in &region.statements {
                check_cancelled(is_cancelled)?;
                match statement {
                    semantic::SemanticStatement::Let(semantic::LetStatement {
                        operation: semantic::SemanticOperation::Call { function, .. },
                        ..
                    }) => {
                        if let Some(callee) = input
                            .functions
                            .get(function.0 as usize)
                            .filter(|callee| callee.color == semantic::FunctionColor::Async)
                        {
                            let slot = required
                                .get_mut(callee.result.0 as usize)
                                .ok_or(unsupported("async call result type identity"))?;
                            *slot = true;
                        }
                    }
                    semantic::SemanticStatement::If {
                        then_region,
                        else_region,
                        ..
                    } => {
                        push_bounded(
                            &mut regions,
                            else_region,
                            "activation type scan",
                            limits.model_edges,
                        )?;
                        push_bounded(
                            &mut regions,
                            then_region,
                            "activation type scan",
                            limits.model_edges,
                        )?;
                    }
                    semantic::SemanticStatement::Match { arms, .. } => {
                        for arm in arms.iter().rev() {
                            push_bounded(
                                &mut regions,
                                &arm.body,
                                "activation type scan",
                                limits.model_edges,
                            )?;
                        }
                    }
                    semantic::SemanticStatement::Loop { body, .. } => push_bounded(
                        &mut regions,
                        body,
                        "activation type scan",
                        limits.model_edges,
                    )?,
                    semantic::SemanticStatement::Let(_)
                    | semantic::SemanticStatement::Return(_)
                    | semantic::SemanticStatement::Yield(_)
                    | semantic::SemanticStatement::Break(_)
                    | semantic::SemanticStatement::Continue(_)
                    | semantic::SemanticStatement::Unreachable => {}
                }
            }
        }
    }

    let mut mapping = try_vec(
        input.types.len(),
        "FlowWir activation type map",
        limits.model_edges,
    )?;
    mapping.resize(input.types.len(), None);
    for (result, required) in required.into_iter().enumerate() {
        check_cancelled(is_cancelled)?;
        if !required {
            continue;
        }
        let result =
            semantic::TypeId(
                u32::try_from(result).map_err(|_| LowerError::ResourceLimit {
                    resource: "FlowWir activation types",
                    limit: limits.model_edges,
                })?,
            );
        let id =
            flow::TypeId(
                u32::try_from(types.len()).map_err(|_| LowerError::ResourceLimit {
                    resource: "FlowWir activation types",
                    limit: limits.model_edges,
                })?,
            );
        let name = format!("__wrela_activation_{}", result.0);
        push_bounded(
            types,
            flow::FlowType {
                id,
                kind: flow::FlowTypeKind::Activation {
                    result: flow::TypeId(result.0),
                },
                name: Some(copy_text(&name, limits.payload_bytes)?),
                copyable: false,
                strict_linear: true,
            },
            "FlowWir activation types",
            limits.model_edges,
        )?;
        mapping[result.0 as usize] = Some(id);
    }
    Ok(mapping)
}

fn activation_values_for_function(
    input: &semantic::SemanticWir,
    function: &semantic::SemanticFunction,
    activation_types: &[Option<flow::TypeId>],
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<Option<flow::TypeId>>, LowerError> {
    let mut values = try_vec(
        function.values.len(),
        "FlowWir activation values",
        limits.model_edges,
    )?;
    values.resize(function.values.len(), None);
    let mut regions = try_vec(1, "activation value scan", limits.model_edges)?;
    regions.push(&function.body);
    while let Some(region) = regions.pop() {
        check_cancelled(is_cancelled)?;
        for statement in &region.statements {
            match statement {
                semantic::SemanticStatement::Let(semantic::LetStatement {
                    results,
                    operation: semantic::SemanticOperation::Call { function, .. },
                    ..
                }) => {
                    if let Some(callee) = input
                        .functions
                        .get(function.0 as usize)
                        .filter(|callee| callee.color == semantic::FunctionColor::Async)
                    {
                        let [result] = results.as_slice() else {
                            return Err(unsupported("async call activation result"));
                        };
                        let activation_type = activation_types
                            .get(callee.result.0 as usize)
                            .copied()
                            .flatten()
                            .ok_or(unsupported("async call activation type"))?;
                        *values
                            .get_mut(result.0 as usize)
                            .ok_or(unsupported("async call activation identity"))? =
                            Some(activation_type);
                    }
                }
                semantic::SemanticStatement::If {
                    then_region,
                    else_region,
                    ..
                } => {
                    push_bounded(
                        &mut regions,
                        else_region,
                        "activation value scan",
                        limits.model_edges,
                    )?;
                    push_bounded(
                        &mut regions,
                        then_region,
                        "activation value scan",
                        limits.model_edges,
                    )?;
                }
                semantic::SemanticStatement::Match { arms, .. } => {
                    for arm in arms.iter().rev() {
                        push_bounded(
                            &mut regions,
                            &arm.body,
                            "activation value scan",
                            limits.model_edges,
                        )?;
                    }
                }
                semantic::SemanticStatement::Loop { body, .. } => push_bounded(
                    &mut regions,
                    body,
                    "activation value scan",
                    limits.model_edges,
                )?,
                semantic::SemanticStatement::Let(_)
                | semantic::SemanticStatement::Return(_)
                | semantic::SemanticStatement::Yield(_)
                | semantic::SemanticStatement::Break(_)
                | semantic::SemanticStatement::Continue(_)
                | semantic::SemanticStatement::Unreachable => {}
            }
        }
    }
    Ok(values)
}

fn validate_actor_flow_output_resources(
    input: &semantic::SemanticWir,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LowerError> {
    let meter = measure_actor_flow_output_resources(input, limits, is_cancelled)?;
    if meter.edge_overflowed || meter.edges > limits.model_edges {
        return Err(LowerError::ResourceLimit {
            resource: "FlowWir actor output model edges",
            limit: limits.model_edges,
        });
    }
    if meter.payload_overflowed || meter.payload_bytes > limits.payload_bytes {
        return Err(LowerError::ResourceLimit {
            resource: "FlowWir actor output payload bytes",
            limit: limits.payload_bytes,
        });
    }
    check_cancelled(is_cancelled)
}

fn measure_actor_flow_output_resources(
    input: &semantic::SemanticWir,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ResourceMeter, LowerError> {
    let mut activation_results = try_vec(
        input.types.len(),
        "FlowWir actor activation resource map",
        limits.model_edges,
    )?;
    activation_results.resize(input.types.len(), false);
    for plan in &input.activations {
        check_cancelled(is_cancelled)?;
        let result = input
            .functions
            .get(plan.callee.0 as usize)
            .filter(|callee| callee.id == plan.callee)
            .ok_or(unsupported("actor activation callee identity"))?
            .result;
        *activation_results
            .get_mut(result.0 as usize)
            .ok_or(unsupported("actor activation result type identity"))? = true;
    }
    let mut activation_type_count = 0_usize;
    for required in &activation_results {
        check_cancelled(is_cancelled)?;
        if *required {
            activation_type_count =
                activation_type_count
                    .checked_add(1)
                    .ok_or(LowerError::ResourceLimit {
                        resource: "FlowWir actor activation types",
                        limit: limits.model_edges,
                    })?;
        }
    }

    let mut meter = ResourceMeter::default();
    meter.text(&input.name);
    meter.text(input.build.target.as_str());
    for count in
        [
            input.types.len().checked_add(activation_type_count).ok_or(
                LowerError::ResourceLimit {
                    resource: "FlowWir actor output model edges",
                    limit: limits.model_edges,
                },
            )?,
            input.functions.len(),
            input.actors.len(),
            input.tasks.len(),
            input.regions.len(),
            input.activations.len(),
            input.proofs.len(),
            input.startup_order.len(),
            input.shutdown_order.len(),
        ]
    {
        meter.add_edges(count);
    }

    for ty in &input.types {
        check_cancelled(is_cancelled)?;
        meter.text(&ty.source_name);
        match &ty.kind {
            semantic::TypeKind::Function(function) => meter.edges(&function.parameters),
            semantic::TypeKind::Struct { fields } => meter.edges(fields),
            semantic::TypeKind::Primitive(_)
            | semantic::TypeKind::Array { .. }
            | semantic::TypeKind::ActorHandle { .. }
            | semantic::TypeKind::Reservation => {}
            _ => return Err(unsupported("actor type changed after shape validation")),
        }
    }
    const ACTIVATION_TYPE_PREFIX: &str = "__wrela_activation_";
    for (result, required) in activation_results.into_iter().enumerate() {
        check_cancelled(is_cancelled)?;
        if required {
            let result = u32::try_from(result).map_err(|_| LowerError::ResourceLimit {
                resource: "FlowWir actor activation types",
                limit: limits.model_edges,
            })?;
            meter.add_payload(ACTIVATION_TYPE_PREFIX.len());
            meter.add_payload(decimal_digits(result));
        }
    }

    for function in &input.functions {
        check_cancelled(is_cancelled)?;
        meter.text(&function.name);
        meter.edges(&function.parameters);
        meter.add_edges(usize::from(!semantic_type_is(
            input,
            function.result,
            semantic::PrimitiveType::Unit,
        )));
        meter.edges(&function.values);
        meter.edges(&function.proofs);
        for value in &function.values {
            check_cancelled(is_cancelled)?;
            if let Some(name) = &value.name {
                meter.text(name);
            }
        }

        let mut block_count = 1_usize;
        let mut instruction_count = 0_usize;
        let mut block_parameter_count = 0_usize;
        let mut regions = try_vec(1, "FlowWir actor output resource scan", limits.model_edges)?;
        regions.push(&function.body);
        while let Some(region) = regions.pop() {
            check_cancelled(is_cancelled)?;
            for statement in &region.statements {
                check_cancelled(is_cancelled)?;
                match statement {
                    semantic::SemanticStatement::Let(statement) => {
                        if matches!(
                            statement.operation,
                            semantic::SemanticOperation::Await { .. }
                        ) {
                            block_count =
                                block_count
                                    .checked_add(1)
                                    .ok_or(LowerError::ResourceLimit {
                                        resource: "FlowWir actor output model edges",
                                        limit: limits.model_edges,
                                    })?;
                            block_parameter_count = block_parameter_count.checked_add(1).ok_or(
                                LowerError::ResourceLimit {
                                    resource: "FlowWir actor output model edges",
                                    limit: limits.model_edges,
                                },
                            )?;
                            continue;
                        }
                        instruction_count =
                            instruction_count
                                .checked_add(1)
                                .ok_or(LowerError::ResourceLimit {
                                    resource: "FlowWir actor output model edges",
                                    limit: limits.model_edges,
                                })?;
                        if matches!(
                            statement.operation,
                            semantic::SemanticOperation::ActorStateLoad { .. }
                                | semantic::SemanticOperation::ActorStateStore { .. }
                        ) {
                            instruction_count = instruction_count.checked_add(1).ok_or(
                                LowerError::ResourceLimit {
                                    resource: "FlowWir actor output model edges",
                                    limit: limits.model_edges,
                                },
                            )?;
                            meter.add_edges(1);
                        }
                        meter.edges(&statement.results);
                        match &statement.operation {
                            semantic::SemanticOperation::Call { arguments, .. }
                            | semantic::SemanticOperation::ActorCommit { arguments, .. } => {
                                meter.edges(arguments)
                            }
                            semantic::SemanticOperation::Constant(semantic::Constant::Bytes(
                                bytes,
                            )) => meter.bytes(bytes),
                            semantic::SemanticOperation::Constant(
                                semantic::Constant::Unsigned { bits, .. }
                                | semantic::Constant::Signed { bits, .. },
                            ) => meter.add_payload(usize::from(*bits).div_ceil(8)),
                            semantic::SemanticOperation::Constant(_)
                            | semantic::SemanticOperation::Copy { .. }
                            | semantic::SemanticOperation::Binary { .. }
                            | semantic::SemanticOperation::Unary { .. }
                            | semantic::SemanticOperation::Convert { .. }
                            | semantic::SemanticOperation::ActorCapability { .. }
                            | semantic::SemanticOperation::ActorReserve { .. }
                            | semantic::SemanticOperation::MailboxReceive { .. }
                            | semantic::SemanticOperation::ActorStateLoad { .. }
                            | semantic::SemanticOperation::ActorStateStore { .. } => {}
                            _ => {
                                return Err(unsupported(
                                    "actor operation changed after shape validation",
                                ));
                            }
                        }
                    }
                    semantic::SemanticStatement::If {
                        then_region,
                        else_region,
                        results,
                        ..
                    } => {
                        block_count =
                            block_count
                                .checked_add(3)
                                .ok_or(LowerError::ResourceLimit {
                                    resource: "FlowWir actor output model edges",
                                    limit: limits.model_edges,
                                })?;
                        block_parameter_count = block_parameter_count
                            .checked_add(results.len())
                            .ok_or(LowerError::ResourceLimit {
                                resource: "FlowWir actor output model edges",
                                limit: limits.model_edges,
                            })?;
                        push_bounded(
                            &mut regions,
                            else_region,
                            "FlowWir actor output resource scan",
                            limits.model_edges,
                        )?;
                        push_bounded(
                            &mut regions,
                            then_region,
                            "FlowWir actor output resource scan",
                            limits.model_edges,
                        )?;
                    }
                    semantic::SemanticStatement::Return(values)
                    | semantic::SemanticStatement::Yield(values) => meter.edges(values),
                    semantic::SemanticStatement::Unreachable => {}
                    semantic::SemanticStatement::Match { .. }
                    | semantic::SemanticStatement::Loop { .. }
                    | semantic::SemanticStatement::Break(_)
                    | semantic::SemanticStatement::Continue(_) => {
                        return Err(unsupported(
                            "actor control flow changed after shape validation",
                        ));
                    }
                }
            }
        }
        meter.add_edges(block_count);
        meter.add_edges(instruction_count);
        meter.add_edges(block_parameter_count);
    }

    for actor in &input.actors {
        check_cancelled(is_cancelled)?;
        meter.text(&actor.name);
        meter.edges(&actor.message_types);
        meter.edges(&actor.turn_functions);
    }
    for task in &input.tasks {
        check_cancelled(is_cancelled)?;
        meter.text(&task.name);
    }
    for region in &input.regions {
        check_cancelled(is_cancelled)?;
        meter.text(&region.name);
    }
    for proof in &input.proofs {
        check_cancelled(is_cancelled)?;
        meter.text(&proof.subject);
        meter.edges(&proof.sources);
        meter.edges(&proof.depends_on);
        meter.edges(&proof.explanation);
        for line in &proof.explanation {
            check_cancelled(is_cancelled)?;
            meter.text(line);
        }
    }
    check_cancelled(is_cancelled)?;
    Ok(meter)
}

const fn decimal_digits(mut value: u32) -> usize {
    let mut digits = 1_usize;
    while value >= 10 {
        value /= 10;
        digits += 1;
    }
    digits
}

fn lower_actor_image(
    actor: ActorImageSemantic<'_>,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<FlowWir, LowerError> {
    let input = actor.input;
    validate_actor_flow_output_resources(input, limits, is_cancelled)?;
    let mut types = try_vec(input.types.len(), "FlowWir actor types", limits.model_edges)?;
    for ty in &input.types {
        types.push(lower_actor_type(ty, &input.actors, limits, is_cancelled)?);
    }
    let actor_state_address_type = if input
        .regions
        .iter()
        .any(|region| region.name.ends_with(".state"))
    {
        let id =
            flow::TypeId(
                u32::try_from(types.len()).map_err(|_| LowerError::ResourceLimit {
                    resource: "FlowWir actor state address type",
                    limit: limits.model_edges,
                })?,
            );
        push_bounded(
            &mut types,
            flow::FlowType {
                id,
                kind: flow::FlowTypeKind::Scalar(flow::ScalarType::Address),
                name: Some("__wrela_actor_state_address".to_owned()),
                copyable: true,
                strict_linear: false,
            },
            "FlowWir actor types",
            limits.model_edges,
        )?;
        Some(id)
    } else {
        None
    };
    let activation_types = append_activation_types(input, &mut types, limits, is_cancelled)?;
    let proofs = lower_proofs(input, limits, is_cancelled)?;
    let mut functions = try_vec(
        input.functions.len(),
        "FlowWir actor functions",
        limits.model_edges,
    )?;
    for function in &input.functions {
        check_cancelled(is_cancelled)?;
        functions.push(lower_generated_function(
            input,
            function,
            &activation_types,
            actor_state_address_type,
            limits,
            is_cancelled,
        )?);
    }

    let mut actors = try_vec(
        input.actors.len(),
        "FlowWir actor plans",
        limits.model_edges,
    )?;
    for source in &input.actors {
        check_cancelled(is_cancelled)?;
        let mut message_types = try_vec(
            source.message_types.len(),
            "FlowWir actor message types",
            limits.model_edges,
        )?;
        message_types.extend(source.message_types.iter().map(|ty| flow::TypeId(ty.0)));
        let mut turn_functions = try_vec(
            source.turn_functions.len(),
            "FlowWir actor turn functions",
            limits.model_edges,
        )?;
        turn_functions.extend(
            source
                .turn_functions
                .iter()
                .map(|function| flow::FunctionId(function.0)),
        );
        actors.push(flow::ActorPlan {
            id: flow::ActorId(source.id.0),
            name: copy_text(&source.name, limits.payload_bytes)?,
            state_type: flow::TypeId(source.ty.0),
            mailbox_capacity: source.mailbox_capacity,
            message_types,
            turn_functions,
            priority: source.priority,
            supervisor: source.supervisor.map(|id| flow::ActorId(id.0)),
        });
    }

    let mut tasks = try_vec(input.tasks.len(), "FlowWir task plans", limits.model_edges)?;
    for source in &input.tasks {
        check_cancelled(is_cancelled)?;
        let frame_bytes_bound = input
            .functions
            .get(source.entry.0 as usize)
            .filter(|function| function.id == source.entry)
            .ok_or(unsupported("actor task entry identity"))?
            .frame_bound;
        tasks.push(flow::TaskPlan {
            id: flow::TaskId(source.id.0),
            name: copy_text(&source.name, limits.payload_bytes)?,
            entry: flow::FunctionId(source.entry.0),
            slots: source.slots,
            priority: source.priority,
            frame_bytes_bound,
            supervisor: source.supervisor.map(|id| flow::ActorId(id.0)),
        });
    }

    let mut regions = try_vec(
        input.regions.len(),
        "FlowWir actor region plans",
        limits.model_edges,
    )?;
    for source in &input.regions {
        check_cancelled(is_cancelled)?;
        regions.push(flow::RegionPlan {
            id: flow::RegionId(source.id.0),
            name: copy_text(&source.name, limits.payload_bytes)?,
            class: lower_region_class(source.class),
            capacity_bytes: source.capacity_bytes,
            alignment: source.alignment,
            // Semantic actor regions are static image-plan records; there is
            // no source reset function to preserve and inventing one would add
            // runtime behavior.
            reset_function: None,
            owner: lower_owner(source.owner),
            capacity_proof: flow::ProofId(source.proof.0),
            source: source.source,
        });
    }

    let mut activations = try_vec(
        input.activations.len(),
        "FlowWir actor activation plans",
        limits.model_edges,
    )?;
    for source in &input.activations {
        check_cancelled(is_cancelled)?;
        activations.push(flow::ActivationPlan {
            id: flow::ActivationId(source.id.0),
            caller: flow::FunctionId(source.caller.0),
            callee: flow::FunctionId(source.callee.0),
            region: flow::RegionId(source.region.0),
            frame_bytes: source.frame_bytes,
            maximum_live: source.maximum_live,
            cancellation: match source.cancellation {
                semantic::ActivationCancellation::DropCalleeThenPropagate => {
                    flow::ActivationCancellation::DropCalleeThenPropagate
                }
            },
            capacity_proof: flow::ProofId(source.capacity_proof.0),
            source: source.source,
        });
    }

    let startup_order = lower_owners(&input.startup_order, limits.model_edges, is_cancelled)?;
    let shutdown_order = lower_owners(&input.shutdown_order, limits.model_edges, is_cancelled)?;
    check_cancelled(is_cancelled)?;
    Ok(FlowWir {
        version: flow::FLOW_WIR_VERSION,
        name: copy_text(&input.name, limits.payload_bytes)?,
        build: input.build.clone(),
        source_summary: flow::SourceSummary {
            semantic_wir_version: semantic::SEMANTIC_WIR_VERSION,
            semantic_functions: u32::try_from(input.functions.len()).map_err(|_| {
                LowerError::ResourceLimit {
                    resource: "semantic functions",
                    limit: limits.model_edges,
                }
            })?,
            hir_files: input.source_summary.hir_files,
            hir_declarations: input.source_summary.hir_declarations,
            reachable_declarations: input.source_summary.reachable_declarations,
            monomorphized_instantiations: input.source_summary.monomorphized_instantiations,
            resolved_interface_calls: input.source_summary.resolved_interface_calls,
        },
        types,
        globals: Vec::new(),
        functions,
        actors,
        tasks,
        devices: Vec::new(),
        pools: Vec::new(),
        regions,
        activations,
        proofs,
        checkpoints: Vec::new(),
        tests: Vec::new(),
        compiled_test_group: None,
        startup_order,
        shutdown_order,
        image_entry: flow::FunctionId(input.image_entry.0),
        static_bytes: input.static_bytes,
        peak_bytes: input.peak_bytes,
    })
}

fn lower_owner(owner: semantic::ImageOwner) -> flow::PlanOwner {
    match owner {
        semantic::ImageOwner::Runtime => flow::PlanOwner::Runtime,
        semantic::ImageOwner::Actor(id) => flow::PlanOwner::Actor(flow::ActorId(id.0)),
        semantic::ImageOwner::Task(id) => flow::PlanOwner::Task(flow::TaskId(id.0)),
        semantic::ImageOwner::Device(id) => flow::PlanOwner::Device(flow::DeviceId(id.0)),
        semantic::ImageOwner::Pool(id) => flow::PlanOwner::Pool(flow::PoolId(id.0)),
        semantic::ImageOwner::BakedArtifact(id) => flow::PlanOwner::BakedArtifact(id),
    }
}

fn lower_function_color(color: semantic::FunctionColor) -> flow::FunctionColor {
    match color {
        semantic::FunctionColor::Sync => flow::FunctionColor::Sync,
        semantic::FunctionColor::Async => flow::FunctionColor::Async,
        semantic::FunctionColor::Isr => flow::FunctionColor::Isr,
    }
}

fn lower_region_class(class: semantic::RegionClass) -> flow::RegionClass {
    match class {
        semantic::RegionClass::Image => flow::RegionClass::Image,
        semantic::RegionClass::TaskFrame => flow::RegionClass::TaskFrame,
        semantic::RegionClass::Call => flow::RegionClass::Call,
        semantic::RegionClass::Request => flow::RegionClass::Request,
        semantic::RegionClass::Pool(pool) => flow::RegionClass::Pool(flow::PoolId(pool.0)),
        semantic::RegionClass::Static => flow::RegionClass::Static,
    }
}

fn lower_generated_tests(
    generated: GeneratedTestSemantic<'_>,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<FlowWir, LowerError> {
    let input = generated.input;
    let mut types = try_vec(input.types.len(), "FlowWir types", limits.model_edges)?;
    for ty in &input.types {
        types.push(lower_generated_type(ty, limits, is_cancelled)?);
    }
    let activation_types = append_activation_types(input, &mut types, limits, is_cancelled)?;

    let proofs = lower_proofs(input, limits, is_cancelled)?;
    let mut functions = try_vec(
        input.functions.len(),
        "FlowWir functions",
        limits.model_edges,
    )?;
    for function in &input.functions {
        check_cancelled(is_cancelled)?;
        functions.push(lower_generated_function(
            input,
            function,
            &activation_types,
            None,
            limits,
            is_cancelled,
        )?);
    }
    let mut tests = try_vec(input.tests.len(), "FlowWir tests", limits.model_edges)?;
    for test in &input.tests {
        check_cancelled(is_cancelled)?;
        tests.push(flow::TestEntry {
            id: flow::TestId(test.id.0),
            plan_id: test.plan_id,
            function_key: input
                .functions
                .get(test.function.0 as usize)
                .ok_or(unsupported("generated test function identity"))?
                .instance_key,
            name: copy_text(&test.name, limits.payload_bytes)?,
            function: flow::FunctionId(test.function.0),
            kind: match test.kind {
                semantic::TestKind::Comptime => flow::TestKind::Comptime,
                semantic::TestKind::Integration => flow::TestKind::Integration,
                semantic::TestKind::Image => flow::TestKind::Image,
            },
            source: test.source,
            timeout_ns: test.timeout_ns,
        });
    }
    let startup_order = lower_owners(&input.startup_order, limits.model_edges, is_cancelled)?;
    let shutdown_order = lower_owners(&input.shutdown_order, limits.model_edges, is_cancelled)?;
    check_cancelled(is_cancelled)?;
    Ok(FlowWir {
        version: flow::FLOW_WIR_VERSION,
        name: copy_text(&input.name, limits.payload_bytes)?,
        build: input.build.clone(),
        source_summary: flow::SourceSummary {
            semantic_wir_version: semantic::SEMANTIC_WIR_VERSION,
            semantic_functions: u32::try_from(input.functions.len()).map_err(|_| {
                LowerError::ResourceLimit {
                    resource: "semantic functions",
                    limit: limits.model_edges,
                }
            })?,
            hir_files: input.source_summary.hir_files,
            hir_declarations: input.source_summary.hir_declarations,
            reachable_declarations: input.source_summary.reachable_declarations,
            monomorphized_instantiations: input.source_summary.monomorphized_instantiations,
            resolved_interface_calls: input.source_summary.resolved_interface_calls,
        },
        types,
        globals: Vec::new(),
        functions,
        actors: Vec::new(),
        tasks: Vec::new(),
        devices: Vec::new(),
        pools: Vec::new(),
        regions: Vec::new(),
        activations: Vec::new(),
        proofs,
        checkpoints: Vec::new(),
        tests,
        compiled_test_group: input.compiled_test_group.clone(),
        startup_order,
        shutdown_order,
        image_entry: flow::FunctionId(generated.harness.id.0),
        static_bytes: input.static_bytes,
        peak_bytes: input.peak_bytes,
    })
}

fn lower_proofs(
    input: &semantic::SemanticWir,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<flow::Proof>, LowerError> {
    let mut proofs = try_vec(input.proofs.len(), "FlowWir proofs", limits.model_edges)?;
    for proof in &input.proofs {
        check_cancelled(is_cancelled)?;
        let mut sources = try_vec(
            proof.sources.len(),
            "FlowWir proof sources",
            limits.model_edges,
        )?;
        sources.extend_from_slice(&proof.sources);
        let mut depends_on = try_vec(
            proof.depends_on.len(),
            "FlowWir proof dependencies",
            limits.model_edges,
        )?;
        depends_on.extend(proof.depends_on.iter().map(|id| flow::ProofId(id.0)));
        let mut explanation = try_vec(
            proof.explanation.len(),
            "FlowWir proof explanations",
            limits.model_edges,
        )?;
        for line in &proof.explanation {
            check_cancelled(is_cancelled)?;
            explanation.push(copy_text(line, limits.payload_bytes)?);
        }
        proofs.push(flow::Proof {
            id: flow::ProofId(proof.id.0),
            kind: lower_proof_kind(&proof.kind),
            subject: copy_text(&proof.subject, limits.payload_bytes)?,
            sources,
            depends_on,
            bound: proof.bound,
            explanation,
        });
    }
    Ok(proofs)
}

struct PendingInstruction<S> {
    results: Vec<flow::ValueId>,
    operation: flow::FlowOperation,
    source: Option<S>,
}

struct PendingBlock<S> {
    id: flow::BlockId,
    parameters: Vec<flow::ValueId>,
    instructions: Vec<PendingInstruction<S>>,
    terminator: Option<flow::Terminator>,
    source: Option<S>,
}

#[derive(Clone, Copy)]
enum RegionExit {
    Root,
    Jump(flow::BlockId),
    Yield(flow::BlockId),
    Loop {
        header: flow::BlockId,
        exit: flow::BlockId,
    },
    LoopBranch {
        merge: flow::BlockId,
        header: flow::BlockId,
        exit: flow::BlockId,
    },
}

struct RegionWork<'a> {
    region: &'a semantic::SemanticRegion,
    next_statement: usize,
    block: flow::BlockId,
    exit: RegionExit,
    depth: u32,
}

fn allocate_pending_block<S: Copy>(
    blocks: &mut Vec<PendingBlock<S>>,
    source: Option<S>,
    limits: LoweringLimits,
) -> Result<flow::BlockId, LowerError> {
    let id = flow::BlockId(
        u32::try_from(blocks.len()).map_err(|_| LowerError::ResourceLimit {
            resource: "FlowWir blocks",
            limit: limits.blocks,
        })?,
    );
    push_bounded(
        blocks,
        PendingBlock {
            id,
            parameters: Vec::new(),
            instructions: Vec::new(),
            terminator: None,
            source,
        },
        "FlowWir blocks",
        limits.blocks,
    )?;
    Ok(id)
}

fn pending_block_mut<S>(
    blocks: &mut [PendingBlock<S>],
    id: flow::BlockId,
) -> Result<&mut PendingBlock<S>, LowerError> {
    blocks
        .get_mut(id.0 as usize)
        .filter(|block| block.id == id)
        .ok_or_else(|| LowerError::InternalInvariant {
            operation: "scalar control-flow construction".to_owned(),
            detail: "pending block identity is missing".to_owned(),
        })
}

fn lower_generated_function(
    input: &semantic::SemanticWir,
    function: &semantic::SemanticFunction,
    activation_types: &[Option<flow::TypeId>],
    actor_state_address_type: Option<flow::TypeId>,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<flow::FlowFunction, LowerError> {
    let activation_values =
        activation_values_for_function(input, function, activation_types, limits, is_cancelled)?;
    let mut values = try_vec(function.values.len(), "FlowWir values", limits.model_edges)?;
    for value in &function.values {
        check_cancelled(is_cancelled)?;
        values.push(flow::Value {
            id: flow::ValueId(value.id.0),
            ty: activation_values
                .get(value.id.0 as usize)
                .copied()
                .flatten()
                .unwrap_or(flow::TypeId(value.ty.0)),
            source_name: value
                .name
                .as_deref()
                .map(|name| copy_text(name, limits.payload_bytes))
                .transpose()?,
            source: value.origin,
        });
    }
    let mut pending_blocks = try_vec(1, "FlowWir blocks", limits.blocks)?;
    let entry = allocate_pending_block(&mut pending_blocks, function.source, limits)?;
    let mut work = try_vec(1, "scalar region work", limits.model_edges)?;
    work.push(RegionWork {
        region: &function.body,
        next_statement: 0,
        block: entry,
        exit: RegionExit::Root,
        depth: 1,
    });
    let mut next_async_state = 0_u32;
    while let Some(mut item) = work.pop() {
        check_cancelled(is_cancelled)?;
        if item.depth > limits.region_depth {
            return Err(LowerError::ResourceLimit {
                resource: "source region depth",
                limit: u64::from(limits.region_depth),
            });
        }
        let mut deferred = false;
        while let Some(statement) = item.region.statements.get(item.next_statement) {
            check_cancelled(is_cancelled)?;
            match statement {
                semantic::SemanticStatement::Let(statement) => {
                    if let semantic::SemanticOperation::ActorStateLoad {
                        actor,
                        region,
                        proof,
                    } = &statement.operation
                    {
                        let [result] = statement.results.as_slice() else {
                            return Err(unsupported("actor state load result"));
                        };
                        let address_ty = actor_state_address_type
                            .ok_or_else(|| unsupported("actor state address type"))?;
                        let address = flow::ValueId(u32::try_from(values.len()).map_err(|_| {
                            LowerError::ResourceLimit {
                                resource: "FlowWir values",
                                limit: limits.model_edges,
                            }
                        })?);
                        push_bounded(
                            &mut values,
                            flow::Value {
                                id: address,
                                ty: address_ty,
                                source_name: None,
                                source: statement.source,
                            },
                            "FlowWir values",
                            limits.model_edges,
                        )?;
                        let block = pending_block_mut(&mut pending_blocks, item.block)?;
                        push_bounded(
                            &mut block.instructions,
                            PendingInstruction {
                                results: vec![address],
                                operation: flow::FlowOperation::ActorStateAddress {
                                    actor: flow::ActorId(actor.0),
                                    region: flow::RegionId(region.0),
                                    proof: flow::ProofId(proof.0),
                                },
                                source: statement.source,
                            },
                            "FlowWir instructions",
                            limits.instructions,
                        )?;
                        push_bounded(
                            &mut block.instructions,
                            PendingInstruction {
                                results: vec![flow::ValueId(result.0)],
                                operation: flow::FlowOperation::Load {
                                    address,
                                    proof: flow::ProofId(proof.0),
                                },
                                source: statement.source,
                            },
                            "FlowWir instructions",
                            limits.instructions,
                        )?;
                        item.next_statement += 1;
                        continue;
                    }
                    if let semantic::SemanticOperation::ActorStateStore {
                        actor,
                        region,
                        value,
                        proof,
                    } = &statement.operation
                    {
                        if !statement.results.is_empty() {
                            return Err(unsupported("actor state store result"));
                        }
                        let address_ty = actor_state_address_type
                            .ok_or_else(|| unsupported("actor state address type"))?;
                        let address = flow::ValueId(u32::try_from(values.len()).map_err(|_| {
                            LowerError::ResourceLimit {
                                resource: "FlowWir values",
                                limit: limits.model_edges,
                            }
                        })?);
                        push_bounded(
                            &mut values,
                            flow::Value {
                                id: address,
                                ty: address_ty,
                                source_name: None,
                                source: statement.source,
                            },
                            "FlowWir values",
                            limits.model_edges,
                        )?;
                        let block = pending_block_mut(&mut pending_blocks, item.block)?;
                        push_bounded(
                            &mut block.instructions,
                            PendingInstruction {
                                results: vec![address],
                                operation: flow::FlowOperation::ActorStateAddress {
                                    actor: flow::ActorId(actor.0),
                                    region: flow::RegionId(region.0),
                                    proof: flow::ProofId(proof.0),
                                },
                                source: statement.source,
                            },
                            "FlowWir instructions",
                            limits.instructions,
                        )?;
                        push_bounded(
                            &mut block.instructions,
                            PendingInstruction {
                                results: Vec::new(),
                                operation: flow::FlowOperation::Store {
                                    address,
                                    value: flow::ValueId(value.0),
                                    proof: flow::ProofId(proof.0),
                                },
                                source: statement.source,
                            },
                            "FlowWir instructions",
                            limits.instructions,
                        )?;
                        item.next_statement += 1;
                        continue;
                    }
                    if let semantic::SemanticOperation::Await { awaitable } = &statement.operation {
                        if u64::from(next_async_state) >= u64::from(limits.states_per_function) {
                            return Err(LowerError::ResourceLimit {
                                resource: "FlowWir async states",
                                limit: u64::from(limits.states_per_function),
                            });
                        }
                        let [delivered] = statement.results.as_slice() else {
                            return Err(unsupported("async await result delivery"));
                        };
                        let resume =
                            allocate_pending_block(&mut pending_blocks, statement.source, limits)?;
                        push_bounded(
                            &mut pending_block_mut(&mut pending_blocks, resume)?.parameters,
                            flow::ValueId(delivered.0),
                            "FlowWir block parameters",
                            limits.model_edges,
                        )?;
                        pending_block_mut(&mut pending_blocks, item.block)?.terminator =
                            Some(flow::Terminator::Suspend {
                                state: next_async_state,
                                activation: flow::ValueId(awaitable.0),
                                resume,
                            });
                        next_async_state =
                            next_async_state
                                .checked_add(1)
                                .ok_or(LowerError::ResourceLimit {
                                    resource: "FlowWir async states",
                                    limit: u64::from(limits.states_per_function),
                                })?;
                        item.block = resume;
                        item.next_statement += 1;
                        continue;
                    }
                    let mut results = try_vec(
                        statement.results.len(),
                        "FlowWir instruction results",
                        limits.model_edges,
                    )?;
                    results.extend(statement.results.iter().map(|value| flow::ValueId(value.0)));
                    let operation = lower_generated_operation(
                        input,
                        &statement.operation,
                        limits,
                        is_cancelled,
                    )?;
                    let block = pending_block_mut(&mut pending_blocks, item.block)?;
                    push_bounded(
                        &mut block.instructions,
                        PendingInstruction {
                            results,
                            operation,
                            source: statement.source,
                        },
                        "FlowWir instructions",
                        limits.instructions,
                    )?;
                    item.next_statement += 1;
                }
                semantic::SemanticStatement::If {
                    condition,
                    then_region,
                    else_region,
                    results,
                    source,
                } => {
                    let then_block = allocate_pending_block(&mut pending_blocks, *source, limits)?;
                    let else_block = allocate_pending_block(&mut pending_blocks, *source, limits)?;
                    let region_terminates = |region: &semantic::SemanticRegion| {
                        matches!(
                            region.statements.last(),
                            Some(
                                semantic::SemanticStatement::Return(_)
                                    | semantic::SemanticStatement::Break(_)
                                    | semantic::SemanticStatement::Continue(_)
                                    | semantic::SemanticStatement::Unreachable
                            )
                        )
                    };
                    let terminal_branches =
                        region_terminates(then_region) && region_terminates(else_region);
                    let merge_block = if terminal_branches {
                        then_block
                    } else {
                        allocate_pending_block(&mut pending_blocks, *source, limits)?
                    };
                    let mut merge_parameters = try_vec(
                        results.len(),
                        "FlowWir block parameters",
                        limits.model_edges,
                    )?;
                    merge_parameters.extend(results.iter().map(|result| flow::ValueId(result.0)));
                    pending_block_mut(&mut pending_blocks, merge_block)?.parameters =
                        merge_parameters;
                    pending_block_mut(&mut pending_blocks, item.block)?.terminator =
                        Some(flow::Terminator::Branch {
                            condition: flow::ValueId(condition.0),
                            then_block,
                            then_arguments: Vec::new(),
                            else_block,
                            else_arguments: Vec::new(),
                        });
                    let next_depth =
                        item.depth.checked_add(1).ok_or(LowerError::ResourceLimit {
                            resource: "source region depth",
                            limit: u64::from(limits.region_depth),
                        })?;
                    if !terminal_branches {
                        push_bounded(
                            &mut work,
                            RegionWork {
                                region: item.region,
                                next_statement: item.next_statement + 1,
                                block: merge_block,
                                exit: item.exit,
                                depth: item.depth,
                            },
                            "scalar region work",
                            limits.model_edges,
                        )?;
                    }
                    let branch_exit = if results.is_empty() {
                        match item.exit {
                            RegionExit::Loop { header, exit }
                            | RegionExit::LoopBranch { header, exit, .. } => {
                                RegionExit::LoopBranch {
                                    merge: merge_block,
                                    header,
                                    exit,
                                }
                            }
                            _ => RegionExit::Jump(merge_block),
                        }
                    } else {
                        RegionExit::Yield(merge_block)
                    };
                    push_bounded(
                        &mut work,
                        RegionWork {
                            region: else_region,
                            next_statement: 0,
                            block: else_block,
                            exit: branch_exit,
                            depth: next_depth,
                        },
                        "scalar region work",
                        limits.model_edges,
                    )?;
                    push_bounded(
                        &mut work,
                        RegionWork {
                            region: then_region,
                            next_statement: 0,
                            block: then_block,
                            exit: branch_exit,
                            depth: next_depth,
                        },
                        "scalar region work",
                        limits.model_edges,
                    )?;
                    deferred = true;
                    break;
                }
                semantic::SemanticStatement::Match {
                    scrutinee,
                    arms,
                    results,
                    source,
                } => {
                    if results.is_empty() && !matches!(item.exit, RegionExit::Root) {
                        return Err(unsupported("terminal closed enum match lowering"));
                    }
                    let enum_ty = function
                        .values
                        .get(scrutinee.0 as usize)
                        .map(|value| value.ty)
                        .ok_or_else(|| unsupported("enum match scrutinee value"))?;
                    let (variant_count, payload_ty) = input
                        .types
                        .get(enum_ty.0 as usize)
                        .and_then(|record| match &record.kind {
                            semantic::TypeKind::Enum { variants } => variants
                                .first()
                                .and_then(|variant| variant.fields.first())
                                .map(|field| (variants.len(), field.ty)),
                            _ => None,
                        })
                        .ok_or_else(|| unsupported("enum match scrutinee type"))?;
                    if variant_count != arms.len() {
                        return Err(unsupported("enum match exhaustiveness"));
                    }
                    let tag_ty = input
                        .types
                        .iter()
                        .find(|ty| {
                            ty.kind == semantic::TypeKind::Primitive(semantic::PrimitiveType::U8)
                        })
                        .map(|ty| flow::TypeId(ty.id.0))
                        .ok_or_else(|| unsupported("enum match canonical u8 tag type"))?;
                    let tag = flow::ValueId(u32::try_from(values.len()).map_err(|_| {
                        LowerError::ResourceLimit {
                            resource: "FlowWir values",
                            limit: limits.model_edges,
                        }
                    })?);
                    push_bounded(
                        &mut values,
                        flow::Value {
                            id: tag,
                            ty: tag_ty,
                            source_name: None,
                            source: *source,
                        },
                        "FlowWir values",
                        limits.model_edges,
                    )?;
                    let payload = flow::ValueId(u32::try_from(values.len()).map_err(|_| {
                        LowerError::ResourceLimit {
                            resource: "FlowWir values",
                            limit: limits.model_edges,
                        }
                    })?);
                    push_bounded(
                        &mut values,
                        flow::Value {
                            id: payload,
                            ty: flow::TypeId(payload_ty.0),
                            source_name: None,
                            source: *source,
                        },
                        "FlowWir values",
                        limits.model_edges,
                    )?;
                    {
                        let block = pending_block_mut(&mut pending_blocks, item.block)?;
                        push_bounded(
                            &mut block.instructions,
                            PendingInstruction {
                                results: vec![tag],
                                operation: flow::FlowOperation::EnumTag {
                                    value: flow::ValueId(scrutinee.0),
                                },
                                source: *source,
                            },
                            "FlowWir instructions",
                            limits.instructions,
                        )?;
                        push_bounded(
                            &mut block.instructions,
                            PendingInstruction {
                                results: vec![payload],
                                operation: flow::FlowOperation::EnumPayload {
                                    value: flow::ValueId(scrutinee.0),
                                },
                                source: *source,
                            },
                            "FlowWir instructions",
                            limits.instructions,
                        )?;
                    }
                    let default = allocate_pending_block(&mut pending_blocks, *source, limits)?;
                    pending_block_mut(&mut pending_blocks, default)?.terminator =
                        Some(flow::Terminator::Unreachable);
                    let merge_block = if results.is_empty() {
                        None
                    } else {
                        let merge = allocate_pending_block(&mut pending_blocks, *source, limits)?;
                        let mut parameters = try_vec(
                            results.len(),
                            "FlowWir enum merge parameters",
                            limits.model_edges,
                        )?;
                        parameters.extend(results.iter().map(|result| flow::ValueId(result.0)));
                        pending_block_mut(&mut pending_blocks, merge)?.parameters = parameters;
                        push_bounded(
                            &mut work,
                            RegionWork {
                                region: item.region,
                                next_statement: item.next_statement + 1,
                                block: merge,
                                exit: item.exit,
                                depth: item.depth,
                            },
                            "scalar region work",
                            limits.model_edges,
                        )?;
                        Some(merge)
                    };
                    let mut cases =
                        try_vec(arms.len(), "FlowWir enum switch cases", limits.model_edges)?;
                    let mut arm_work =
                        try_vec(arms.len(), "FlowWir enum arm work", limits.model_edges)?;
                    let next_depth =
                        item.depth.checked_add(1).ok_or(LowerError::ResourceLimit {
                            resource: "source region depth",
                            limit: u64::from(limits.region_depth),
                        })?;
                    for arm in arms {
                        let [binding] = arm.bindings.as_slice() else {
                            return Err(unsupported("enum match payload binding"));
                        };
                        let variant = arm
                            .variant
                            .ok_or_else(|| unsupported("enum match explicit variant"))?;
                        let block = allocate_pending_block(&mut pending_blocks, *source, limits)?;
                        push_bounded(
                            &mut pending_block_mut(&mut pending_blocks, block)?.parameters,
                            flow::ValueId(binding.0),
                            "FlowWir block parameters",
                            limits.model_edges,
                        )?;
                        cases.push(flow::SwitchCase {
                            value: u128::from(variant),
                            target: block,
                            arguments: vec![payload],
                        });
                        arm_work.push(RegionWork {
                            region: &arm.body,
                            next_statement: 0,
                            block,
                            exit: merge_block.map_or(RegionExit::Root, RegionExit::Yield),
                            depth: next_depth,
                        });
                    }
                    pending_block_mut(&mut pending_blocks, item.block)?.terminator =
                        Some(flow::Terminator::Switch {
                            value: tag,
                            cases,
                            default,
                            default_arguments: Vec::new(),
                        });
                    for arm in arm_work.into_iter().rev() {
                        push_bounded(&mut work, arm, "scalar region work", limits.model_edges)?;
                    }
                    deferred = true;
                    break;
                }
                semantic::SemanticStatement::Loop {
                    body,
                    carried,
                    uninterrupted_bound,
                    source,
                } => {
                    if uninterrupted_bound.is_none_or(|bound| bound == 0) {
                        return Err(unsupported("synchronous loop uninterrupted-work proof"));
                    }
                    let arity = body.parameters.len();
                    if carried.len() != arity.saturating_mul(3) {
                        return Err(unsupported("scalar loop carried-value contract"));
                    }
                    let header = allocate_pending_block(&mut pending_blocks, *source, limits)?;
                    let exit = allocate_pending_block(&mut pending_blocks, *source, limits)?;
                    pending_block_mut(&mut pending_blocks, header)?.parameters = body
                        .parameters
                        .iter()
                        .map(|value| flow::ValueId(value.0))
                        .collect();
                    pending_block_mut(&mut pending_blocks, exit)?.parameters = carried[2 * arity..]
                        .iter()
                        .map(|value| flow::ValueId(value.0))
                        .collect();
                    pending_block_mut(&mut pending_blocks, item.block)?.terminator =
                        Some(flow::Terminator::Jump {
                            target: header,
                            arguments: carried[..arity]
                                .iter()
                                .map(|value| flow::ValueId(value.0))
                                .collect(),
                        });
                    let next_depth =
                        item.depth.checked_add(1).ok_or(LowerError::ResourceLimit {
                            resource: "source region depth",
                            limit: u64::from(limits.region_depth),
                        })?;
                    push_bounded(
                        &mut work,
                        RegionWork {
                            region: item.region,
                            next_statement: item.next_statement + 1,
                            block: exit,
                            exit: item.exit,
                            depth: item.depth,
                        },
                        "scalar region work",
                        limits.model_edges,
                    )?;
                    push_bounded(
                        &mut work,
                        RegionWork {
                            region: body,
                            next_statement: 0,
                            block: header,
                            exit: RegionExit::Loop { header, exit },
                            depth: next_depth,
                        },
                        "scalar region work",
                        limits.model_edges,
                    )?;
                    deferred = true;
                    break;
                }
                semantic::SemanticStatement::Break(values)
                | semantic::SemanticStatement::Continue(values) => {
                    let (header, exit) = match item.exit {
                        RegionExit::Loop { header, exit }
                        | RegionExit::LoopBranch { header, exit, .. } => (header, exit),
                        _ => return Err(unsupported("scalar loop control destination")),
                    };
                    let target = if matches!(statement, semantic::SemanticStatement::Break(_)) {
                        exit
                    } else {
                        header
                    };
                    pending_block_mut(&mut pending_blocks, item.block)?.terminator =
                        Some(flow::Terminator::Jump {
                            target,
                            arguments: values.iter().map(|value| flow::ValueId(value.0)).collect(),
                        });
                    item.next_statement += 1;
                    break;
                }
                semantic::SemanticStatement::Yield(values) => {
                    let RegionExit::Yield(target) = item.exit else {
                        return Err(unsupported("scalar branch yield destination"));
                    };
                    if item.next_statement + 1 != item.region.statements.len() {
                        return Err(unsupported("scalar branch yield position"));
                    }
                    let mut arguments =
                        try_vec(values.len(), "FlowWir edge arguments", limits.model_edges)?;
                    arguments.extend(values.iter().map(|value| flow::ValueId(value.0)));
                    pending_block_mut(&mut pending_blocks, item.block)?.terminator =
                        Some(flow::Terminator::Jump { target, arguments });
                    item.next_statement += 1;
                    break;
                }
                semantic::SemanticStatement::Return(values) => {
                    let mut lowered =
                        try_vec(values.len(), "FlowWir return values", limits.model_edges)?;
                    lowered.extend(values.iter().map(|value| flow::ValueId(value.0)));
                    pending_block_mut(&mut pending_blocks, item.block)?.terminator =
                        Some(flow::Terminator::Return(lowered));
                    item.next_statement += 1;
                    break;
                }
                semantic::SemanticStatement::Unreachable => {
                    pending_block_mut(&mut pending_blocks, item.block)?.terminator =
                        Some(flow::Terminator::Unreachable);
                    item.next_statement += 1;
                    break;
                }
            }
        }
        if deferred {
            continue;
        }
        let block = pending_block_mut(&mut pending_blocks, item.block)?;
        if block.terminator.is_some() {
            if item.next_statement != item.region.statements.len() {
                return Err(unsupported("statements after generated test terminator"));
            }
        } else {
            block.terminator = match item.exit {
                RegionExit::Root => return Err(unsupported("generated test terminator")),
                RegionExit::Jump(target) => Some(flow::Terminator::Jump {
                    target,
                    arguments: Vec::new(),
                }),
                RegionExit::Yield(_) => {
                    return Err(unsupported("scalar branch yield terminator"));
                }
                RegionExit::Loop { header, .. } => Some(flow::Terminator::Jump {
                    target: header,
                    arguments: item
                        .region
                        .parameters
                        .iter()
                        .map(|value| flow::ValueId(value.0))
                        .collect(),
                }),
                RegionExit::LoopBranch { merge, .. } => Some(flow::Terminator::Jump {
                    target: merge,
                    arguments: Vec::new(),
                }),
            };
        }
    }

    let mut blocks = try_vec(pending_blocks.len(), "FlowWir blocks", limits.blocks)?;
    let mut next_instruction = 0u32;
    for pending in pending_blocks {
        check_cancelled(is_cancelled)?;
        let mut instructions = try_vec(
            pending.instructions.len(),
            "FlowWir instructions",
            limits.instructions,
        )?;
        for instruction in pending.instructions {
            check_cancelled(is_cancelled)?;
            instructions.push(flow::Instruction {
                id: flow::InstructionId(next_instruction),
                results: instruction.results,
                operation: instruction.operation,
                source: instruction.source,
            });
            next_instruction =
                next_instruction
                    .checked_add(1)
                    .ok_or(LowerError::ResourceLimit {
                        resource: "FlowWir instructions",
                        limit: limits.instructions,
                    })?;
            if u64::from(next_instruction) > limits.instructions {
                return Err(LowerError::ResourceLimit {
                    resource: "FlowWir instructions",
                    limit: limits.instructions,
                });
            }
        }
        blocks.push(flow::Block {
            id: pending.id,
            parameters: pending.parameters,
            instructions,
            terminator: pending
                .terminator
                .ok_or(unsupported("generated test terminator"))?,
            source: pending.source,
        });
    }
    let origin = match function.origin {
        semantic::FunctionOrigin::Source => flow::FunctionOrigin::SourceSemantic {
            semantic_function: function.id.0,
        },
        semantic::FunctionOrigin::GeneratedTestHarness { group } => {
            flow::FunctionOrigin::GeneratedTestHarness {
                semantic_function: function.id.0,
                group,
            }
        }
        semantic::FunctionOrigin::GeneratedImageEntry { constructor } => {
            flow::FunctionOrigin::GeneratedImageEntry {
                semantic_function: function.id.0,
                constructor,
            }
        }
    };
    let role = match function.role {
        semantic::FunctionRole::Ordinary => flow::FunctionRole::Ordinary,
        semantic::FunctionRole::ActorTurn(actor) => {
            flow::FunctionRole::ActorTurn(flow::ActorId(actor.0))
        }
        semantic::FunctionRole::TaskEntry(task) => {
            flow::FunctionRole::TaskEntry(flow::TaskId(task.0))
        }
        semantic::FunctionRole::Test => flow::FunctionRole::Test,
        semantic::FunctionRole::ImageEntry => flow::FunctionRole::ImageEntry,
        semantic::FunctionRole::Isr(_) | semantic::FunctionRole::Cleanup => {
            return Err(unsupported(
                "generated test function role changed after validation",
            ));
        }
    };
    let mut parameters = try_vec(
        function.parameters.len(),
        "FlowWir function parameters",
        limits.model_edges,
    )?;
    parameters.extend(
        function
            .parameters
            .iter()
            .map(|value| flow::ValueId(value.0)),
    );
    let mut result_types = try_vec(1, "FlowWir function results", limits.model_edges)?;
    if !semantic_type_is(input, function.result, semantic::PrimitiveType::Unit) {
        result_types.push(flow::TypeId(function.result.0));
    }
    let mut function_proofs = try_vec(
        function.proofs.len(),
        "FlowWir function proofs",
        limits.model_edges,
    )?;
    function_proofs.extend(function.proofs.iter().map(|proof| flow::ProofId(proof.0)));
    Ok(flow::FlowFunction {
        id: flow::FunctionId(function.id.0),
        name: copy_text(&function.name, limits.payload_bytes)?,
        origin,
        role,
        color: lower_function_color(function.color),
        parameters,
        result_types,
        values,
        blocks,
        entry: flow::BlockId(0),
        stack_bound: function.stack_bound,
        frame_bound: function.frame_bound,
        proofs: function_proofs,
        source: function.source,
    })
}

fn lower_generated_operation(
    input: &semantic::SemanticWir,
    operation: &semantic::SemanticOperation,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<flow::FlowOperation, LowerError> {
    match operation {
        semantic::SemanticOperation::Constant(semantic::Constant::Unit) => {
            Ok(flow::FlowOperation::Immediate(flow::Immediate::Unit))
        }
        semantic::SemanticOperation::Constant(semantic::Constant::Bool(value)) => Ok(
            flow::FlowOperation::Immediate(flow::Immediate::Bool(*value)),
        ),
        semantic::SemanticOperation::Constant(semantic::Constant::Float32(bits)) => Ok(
            flow::FlowOperation::Immediate(flow::Immediate::Float32(*bits)),
        ),
        semantic::SemanticOperation::Constant(semantic::Constant::Float64(bits)) => Ok(
            flow::FlowOperation::Immediate(flow::Immediate::Float64(*bits)),
        ),
        semantic::SemanticOperation::Constant(semantic::Constant::Bytes(bytes)) => {
            Ok(flow::FlowOperation::Immediate(flow::Immediate::Bytes(
                copy_bytes(bytes, limits.payload_bytes)?,
            )))
        }
        semantic::SemanticOperation::Constant(semantic::Constant::Unsigned { bits, value }) => {
            let width = usize::from(*bits).div_ceil(8);
            Ok(flow::FlowOperation::Immediate(flow::Immediate::Integer {
                bits: u16::from(*bits),
                bytes_le: copy_bytes(&value.to_le_bytes()[..width], limits.payload_bytes)?,
            }))
        }
        semantic::SemanticOperation::Constant(semantic::Constant::Signed { bits, value }) => {
            let width = usize::from(*bits).div_ceil(8);
            Ok(flow::FlowOperation::Immediate(flow::Immediate::Integer {
                bits: u16::from(*bits),
                bytes_le: copy_bytes(&value.to_le_bytes()[..width], limits.payload_bytes)?,
            }))
        }
        semantic::SemanticOperation::Copy { value } => Ok(flow::FlowOperation::Copy {
            value: flow::ValueId(value.0),
        }),
        semantic::SemanticOperation::Binary {
            operator,
            left,
            right,
            arithmetic,
        } => Ok(flow::FlowOperation::Binary {
            op: lower_scalar_binary_operator(*operator, *arithmetic)?,
            left: flow::ValueId(left.0),
            right: flow::ValueId(right.0),
        }),
        semantic::SemanticOperation::Unary {
            operator, operand, ..
        } => Ok(flow::FlowOperation::Unary {
            op: match operator {
                semantic::UnaryOperator::Negate => flow::UnaryOp::Negate,
                semantic::UnaryOperator::BoolNot => flow::UnaryOp::BoolNot,
                semantic::UnaryOperator::BitNot => flow::UnaryOp::BitNot,
            },
            value: flow::ValueId(operand.0),
        }),
        semantic::SemanticOperation::Convert {
            value,
            destination,
            checked,
        } => Ok(flow::FlowOperation::Cast {
            value: flow::ValueId(value.0),
            to: flow::TypeId(destination.0),
            mode: if *checked {
                flow::CastMode::Checked
            } else {
                flow::CastMode::Exact
            },
        }),
        semantic::SemanticOperation::Aggregate { ty, fields } => {
            let mut lowered =
                try_vec(fields.len(), "FlowWir aggregate fields", limits.model_edges)?;
            for field in fields {
                check_cancelled(is_cancelled)?;
                lowered.push(flow::ValueId(field.0));
            }
            Ok(flow::FlowOperation::MakeAggregate {
                ty: flow::TypeId(ty.0),
                fields: lowered,
            })
        }
        semantic::SemanticOperation::InsertField {
            aggregate,
            field,
            value,
        } => Ok(flow::FlowOperation::InsertField {
            aggregate: flow::ValueId(aggregate.0),
            field: *field,
            value: flow::ValueId(value.0),
        }),
        semantic::SemanticOperation::ConstructEnum {
            ty,
            variant,
            payload,
        } => Ok(flow::FlowOperation::MakeEnum {
            ty: flow::TypeId(ty.0),
            variant: u8::try_from(*variant)
                .map_err(|_| unsupported("enum variant exceeds canonical u8 tag"))?,
            payload: flow::ValueId(payload.0),
        }),
        semantic::SemanticOperation::Project {
            base,
            field,
            access: semantic::AccessMode::Read,
        } => Ok(flow::FlowOperation::ExtractField {
            aggregate: flow::ValueId(base.0),
            field: *field,
        }),
        semantic::SemanticOperation::Call {
            function,
            arguments,
            activation,
        } => {
            let mut lowered = try_vec(
                arguments.len(),
                "FlowWir call arguments",
                limits.model_edges,
            )?;
            for argument in arguments {
                check_cancelled(is_cancelled)?;
                lowered.push(flow::ValueId(argument.value.0));
            }
            if input
                .functions
                .get(function.0 as usize)
                .is_some_and(|callee| callee.color == semantic::FunctionColor::Async)
            {
                let activation =
                    activation.ok_or(unsupported("async call without activation plan"))?;
                Ok(flow::FlowOperation::AsyncCall {
                    function: flow::FunctionId(function.0),
                    arguments: lowered,
                    plan: flow::ActivationId(activation.0),
                })
            } else {
                if activation.is_some() {
                    return Err(unsupported("synchronous call with activation plan"));
                }
                Ok(flow::FlowOperation::Call {
                    function: flow::FunctionId(function.0),
                    arguments: lowered,
                })
            }
        }
        semantic::SemanticOperation::ActorCapability {
            actor,
            wiring_proof,
        } => Ok(flow::FlowOperation::ActorCapability {
            actor: flow::ActorId(actor.0),
            proof: flow::ProofId(wiring_proof.0),
        }),
        semantic::SemanticOperation::ActorReserve {
            actor,
            method,
            permit_proof,
        } => Ok(flow::FlowOperation::ActorReserve {
            actor: flow::ActorId(actor.0),
            method: flow::FunctionId(method.0),
            proof: flow::ProofId(permit_proof.0),
        }),
        semantic::SemanticOperation::ActorCommit {
            reservation,
            arguments,
        } => {
            let mut lowered = try_vec(
                arguments.len(),
                "FlowWir actor message arguments",
                limits.model_edges,
            )?;
            for argument in arguments {
                check_cancelled(is_cancelled)?;
                if argument.access != semantic::AccessMode::Read {
                    return Err(unsupported("one-way actor message argument access"));
                }
                lowered.push(flow::ValueId(argument.value.0));
            }
            Ok(flow::FlowOperation::ActorCommit {
                reservation: flow::ValueId(reservation.0),
                arguments: lowered,
            })
        }
        semantic::SemanticOperation::MailboxReceive { actor, method } => {
            Ok(flow::FlowOperation::MailboxReceive {
                actor: flow::ActorId(actor.0),
                method: flow::FunctionId(method.0),
            })
        }
        semantic::SemanticOperation::TestEmit { payload } => Ok(flow::FlowOperation::TestEmit {
            payload: flow::ValueId(payload.0),
        }),
        semantic::SemanticOperation::TestFinish { outcome } => {
            Ok(flow::FlowOperation::TestFinish {
                outcome: flow::ValueId(outcome.0),
            })
        }
        semantic::SemanticOperation::Assert { condition, failure } => {
            Ok(flow::FlowOperation::Assert {
                condition: flow::ValueId(condition.0),
                failure: flow::AssertionFailureDescriptor {
                    expression: copy_text(&failure.expression, limits.payload_bytes)?,
                    message: failure
                        .message
                        .as_deref()
                        .map(|message| copy_text(message, limits.payload_bytes))
                        .transpose()?,
                    source: failure.source,
                },
            })
        }
        semantic::SemanticOperation::Constant(
            semantic::Constant::Char(_)
            | semantic::Constant::String(_)
            | semantic::Constant::Enum { .. }
            | semantic::Constant::Aggregate(_)
            | semantic::Constant::Zeroed(_),
        )
        | semantic::SemanticOperation::ActorStateLoad { .. }
        | semantic::SemanticOperation::ActorStateStore { .. }
        | semantic::SemanticOperation::Project { .. }
        | semantic::SemanticOperation::Index { .. }
        | semantic::SemanticOperation::BeginAccess { .. }
        | semantic::SemanticOperation::EndAccess { .. }
        | semantic::SemanticOperation::Move { .. }
        | semantic::SemanticOperation::Drop { .. }
        | semantic::SemanticOperation::ActorSend { .. }
        | semantic::SemanticOperation::ActorTrySend { .. }
        | semantic::SemanticOperation::Await { .. }
        | semantic::SemanticOperation::SpawnTask { .. }
        | semantic::SemanticOperation::Cancel { .. }
        | semantic::SemanticOperation::Checkpoint { .. }
        | semantic::SemanticOperation::Select { .. }
        | semantic::SemanticOperation::Race { .. }
        | semantic::SemanticOperation::Allocate { .. }
        | semantic::SemanticOperation::ResetRegion { .. }
        | semantic::SemanticOperation::Promote { .. }
        | semantic::SemanticOperation::EnterScope { .. }
        | semantic::SemanticOperation::CommitScope { .. }
        | semantic::SemanticOperation::AbortScope { .. }
        | semantic::SemanticOperation::ExitScope { .. }
        | semantic::SemanticOperation::DmaTransition { .. }
        | semantic::SemanticOperation::MmioRead { .. }
        | semantic::SemanticOperation::MmioWrite { .. }
        | semantic::SemanticOperation::InterruptPublish { .. }
        | semantic::SemanticOperation::QueueReserve { .. }
        | semantic::SemanticOperation::QueuePublish { .. }
        | semantic::SemanticOperation::Check { .. }
        | semantic::SemanticOperation::RecordEvent { .. } => Err(unsupported(
            "generated test operation changed after shape validation",
        )),
    }
}

fn report_for(
    wir: &FlowWir,
    input: &semantic::SemanticWir,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<LoweringReport, LowerError> {
    check_cancelled(is_cancelled)?;
    let source_functions =
        u32::try_from(input.functions.len()).map_err(|_| LowerError::ResourceLimit {
            resource: "FlowWir functions",
            limit: limits.model_edges,
        })?;
    let output_functions =
        u32::try_from(wir.functions.len()).map_err(|_| LowerError::ResourceLimit {
            resource: "FlowWir functions",
            limit: limits.model_edges,
        })?;
    let generated_functions =
        output_functions
            .checked_sub(source_functions)
            .ok_or(LowerError::InternalInvariant {
                operation: "lowering report".to_owned(),
                detail: "output lost a semantic function".to_owned(),
            })?;
    let mut blocks = 0u64;
    let mut instructions = 0u64;
    let mut async_states = 0u64;
    for function in &wir.functions {
        check_cancelled(is_cancelled)?;
        blocks = blocks
            .checked_add(u64::try_from(function.blocks.len()).map_err(|_| {
                LowerError::ResourceLimit {
                    resource: "FlowWir blocks",
                    limit: limits.blocks,
                }
            })?)
            .ok_or(LowerError::ResourceLimit {
                resource: "FlowWir blocks",
                limit: limits.blocks,
            })?;
        for block in &function.blocks {
            check_cancelled(is_cancelled)?;
            if matches!(block.terminator, flow::Terminator::Suspend { .. }) {
                async_states = async_states
                    .checked_add(1)
                    .ok_or(LowerError::ResourceLimit {
                        resource: "FlowWir async states",
                        limit: limits.blocks,
                    })?;
            }
            instructions = instructions
                .checked_add(u64::try_from(block.instructions.len()).map_err(|_| {
                    LowerError::ResourceLimit {
                        resource: "FlowWir instructions",
                        limit: limits.instructions,
                    }
                })?)
                .ok_or(LowerError::ResourceLimit {
                    resource: "FlowWir instructions",
                    limit: limits.instructions,
                })?;
        }
    }
    Ok(LoweringReport {
        source_functions,
        generated_functions,
        blocks,
        instructions,
        async_states,
        cleanup_edges: 0,
        output_proofs: u64::try_from(wir.proofs.len()).map_err(|_| LowerError::ResourceLimit {
            resource: "FlowWir proofs",
            limit: limits.model_edges,
        })?,
    })
}

fn lower_owners(
    owners: &[semantic::ImageOwner],
    limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<flow::PlanOwner>, LowerError> {
    let mut output = try_vec(owners.len(), "FlowWir image order", limit)?;
    for owner in owners {
        check_cancelled(is_cancelled)?;
        output.push(match owner {
            semantic::ImageOwner::Runtime => flow::PlanOwner::Runtime,
            semantic::ImageOwner::Actor(id) => flow::PlanOwner::Actor(flow::ActorId(id.0)),
            semantic::ImageOwner::Task(id) => flow::PlanOwner::Task(flow::TaskId(id.0)),
            semantic::ImageOwner::Device(id) => flow::PlanOwner::Device(flow::DeviceId(id.0)),
            semantic::ImageOwner::Pool(id) => flow::PlanOwner::Pool(flow::PoolId(id.0)),
            semantic::ImageOwner::BakedArtifact(id) => flow::PlanOwner::BakedArtifact(*id),
        });
    }
    Ok(output)
}

fn lower_proof_kind(kind: &semantic::ProofKind) -> flow::ProofKind {
    match kind {
        semantic::ProofKind::TypeChecked => flow::ProofKind::TypeChecked,
        semantic::ProofKind::EffectsAllowed => flow::ProofKind::EffectsAllowed,
        semantic::ProofKind::DefiniteInitialization => flow::ProofKind::DefiniteInitialization,
        semantic::ProofKind::Ownership => flow::ProofKind::Ownership,
        semantic::ProofKind::AccessExclusive => flow::ProofKind::AccessExclusive,
        semantic::ProofKind::ViewDoesNotEscape => flow::ProofKind::ViewDoesNotEscape,
        semantic::ProofKind::RegionBound => flow::ProofKind::RegionBound,
        semantic::ProofKind::CapacityBound => flow::ProofKind::CapacityBound,
        semantic::ProofKind::WaitGraphAcyclic => flow::ProofKind::WaitGraphAcyclic,
        semantic::ProofKind::CleanupAcyclic => flow::ProofKind::CleanupAcyclic,
        semantic::ProofKind::WorkBound => flow::ProofKind::WorkBound,
        semantic::ProofKind::StackBound => flow::ProofKind::StackBound,
        semantic::ProofKind::IsrSafe => flow::ProofKind::IsrSafe,
        semantic::ProofKind::DmaTransition => flow::ProofKind::DmaTransition,
        semantic::ProofKind::MmioPartition => flow::ProofKind::MmioPartition,
        semantic::ProofKind::DeviceValueValidated => flow::ProofKind::DeviceValueValidated,
        semantic::ProofKind::WireLayout => flow::ProofKind::WireLayout,
        semantic::ProofKind::ReceiptLineage => flow::ProofKind::ReceiptLineage,
        semantic::ProofKind::ActorAsIf => flow::ProofKind::ActorAsIf,
        semantic::ProofKind::SupervisionComplete => flow::ProofKind::SupervisionComplete,
        semantic::ProofKind::ImageClosed => flow::ProofKind::ImageClosed,
    }
}

fn try_vec<T>(capacity: usize, resource: &'static str, limit: u64) -> Result<Vec<T>, LowerError> {
    check_count(resource, capacity, limit)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| LowerError::ResourceLimit { resource, limit })?;
    Ok(output)
}

fn push_bounded<T>(
    output: &mut Vec<T>,
    value: T,
    resource: &'static str,
    limit: u64,
) -> Result<(), LowerError> {
    if u64::try_from(output.len()).map_or(true, |length| length >= limit) {
        return Err(LowerError::ResourceLimit { resource, limit });
    }
    output
        .try_reserve(1)
        .map_err(|_| LowerError::ResourceLimit { resource, limit })?;
    output.push(value);
    Ok(())
}

fn copy_text(value: &str, limit: u64) -> Result<String, LowerError> {
    check_count("FlowWir payload bytes", value.len(), limit)?;
    let mut output = String::new();
    output
        .try_reserve_exact(value.len())
        .map_err(|_| LowerError::ResourceLimit {
            resource: "FlowWir payload bytes",
            limit,
        })?;
    output.push_str(value);
    Ok(output)
}

fn copy_bytes(value: &[u8], limit: u64) -> Result<Vec<u8>, LowerError> {
    check_count("FlowWir payload bytes", value.len(), limit)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(value.len())
        .map_err(|_| LowerError::ResourceLimit {
            resource: "FlowWir payload bytes",
            limit,
        })?;
    output.extend_from_slice(value);
    Ok(output)
}

/// Helper used by implementations to seal an output only after structural
/// verification. It cannot manufacture successful output from invalid IR.
pub fn seal(
    request: &LowerRequest,
    wir: FlowWir,
    report: LoweringReport,
    diagnostics: Vec<Diagnostic>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<LowerOutput, LowerError> {
    if is_cancelled() {
        return Err(LowerError::Cancelled);
    }
    request.limits.validate()?;
    if diagnostics.len() > request.limits.diagnostics as usize {
        return Err(LowerError::ResourceLimit {
            resource: "diagnostics",
            limit: u64::from(request.limits.diagnostics),
        });
    }
    let mut diagnostics = WithDiagnostics {
        value: (),
        diagnostics,
    };
    if diagnostics
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == Severity::Error)
    {
        return Err(LowerError::ErrorDiagnosticOnSuccess);
    }
    diagnostics.sort_diagnostics();
    validate_diagnostics(&diagnostics.diagnostics, request.limits, is_cancelled)?;
    validate_model_resources(&wir, request.limits, is_cancelled)?;
    let validated = wir
        .validate_with_limits(flow_validation_limits(request.limits), is_cancelled)
        .map_err(map_validation_failure)?;
    validate_report(
        &request.input,
        &validated,
        &report,
        request.limits,
        is_cancelled,
    )?;
    if is_cancelled() {
        return Err(LowerError::Cancelled);
    }
    Ok(LowerOutput {
        validated,
        report,
        diagnostics: diagnostics.diagnostics,
    })
}

fn flow_validation_limits(limits: LoweringLimits) -> ValidationLimits {
    ValidationLimits {
        arena_records: limits.model_edges.min(u64::from(u32::MAX)),
        model_edges: limits.model_edges,
        payload_bytes: limits.payload_bytes,
        validation_work: limits.validation_work,
        errors: limits.validation_errors,
        test_plan: limits.test_plan,
    }
}

fn map_validation_failure(error: ValidationFailure) -> LowerError {
    match error {
        ValidationFailure::InvalidLimits => LowerError::InvalidLimits,
        ValidationFailure::Cancelled => LowerError::Cancelled,
        ValidationFailure::ResourceLimit { resource, limit } => {
            LowerError::ResourceLimit { resource, limit }
        }
        ValidationFailure::Invalid(errors) => LowerError::InvalidOutput(errors),
    }
}

#[derive(Default)]
struct ResourceMeter {
    edges: u64,
    payload_bytes: u64,
    edge_overflowed: bool,
    payload_overflowed: bool,
}

impl ResourceMeter {
    fn edges<T>(&mut self, values: &[T]) {
        self.add_edges(values.len());
    }

    fn add_edges(&mut self, count: usize) {
        let Ok(count) = u64::try_from(count) else {
            self.edge_overflowed = true;
            return;
        };
        if let Some(total) = self.edges.checked_add(count) {
            self.edges = total;
        } else {
            self.edge_overflowed = true;
        }
    }

    fn text(&mut self, value: &str) {
        self.add_payload(value.len());
    }

    fn bytes(&mut self, value: &[u8]) {
        self.add_payload(value.len());
    }

    fn add_payload(&mut self, count: usize) {
        let Ok(count) = u64::try_from(count) else {
            self.payload_overflowed = true;
            return;
        };
        if let Some(total) = self.payload_bytes.checked_add(count) {
            self.payload_bytes = total;
        } else {
            self.payload_overflowed = true;
        }
    }
}

fn validate_model_resources(
    wir: &wrela_flow_wir::FlowWir,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LowerError> {
    use wrela_flow_wir::{FlowOperation, FlowTypeKind, Immediate, Terminator};

    let mut meter = ResourceMeter::default();
    meter.text(&wir.name);
    meter.text(wir.build.target.as_str());
    for count in [
        wir.types.len(),
        wir.globals.len(),
        wir.functions.len(),
        wir.actors.len(),
        wir.tasks.len(),
        wir.devices.len(),
        wir.pools.len(),
        wir.regions.len(),
        wir.activations.len(),
        wir.proofs.len(),
        wir.checkpoints.len(),
        wir.tests.len(),
        wir.startup_order.len(),
        wir.shutdown_order.len(),
    ] {
        meter.add_edges(count);
    }
    let immediate = |value: &Immediate, meter: &mut ResourceMeter| match value {
        Immediate::Integer { bytes_le, .. } | Immediate::Bytes(bytes_le) => {
            meter.bytes(bytes_le);
        }
        Immediate::Unit
        | Immediate::Bool(_)
        | Immediate::Float32(_)
        | Immediate::Float64(_)
        | Immediate::Zero(_)
        | Immediate::GlobalAddress(_)
        | Immediate::FunctionAddress(_) => {}
    };
    for ty in &wir.types {
        check_cancelled(is_cancelled)?;
        if let Some(name) = &ty.name {
            meter.text(name);
        }
        match &ty.kind {
            FlowTypeKind::Tuple(items) | FlowTypeKind::Struct { fields: items } => {
                meter.edges(items);
            }
            FlowTypeKind::Enum { variants } => {
                meter.edges(variants);
                for variant in variants {
                    check_cancelled(is_cancelled)?;
                    meter.edges(variant);
                }
            }
            FlowTypeKind::Function { parameters, .. } => meter.edges(parameters),
            FlowTypeKind::OpaqueTarget { name } => meter.text(name),
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
    for global in &wir.globals {
        check_cancelled(is_cancelled)?;
        meter.text(&global.name);
        immediate(&global.initializer, &mut meter);
    }
    for function in &wir.functions {
        check_cancelled(is_cancelled)?;
        meter.text(&function.name);
        meter.edges(&function.parameters);
        meter.edges(&function.result_types);
        meter.edges(&function.values);
        meter.edges(&function.blocks);
        for value in &function.values {
            check_cancelled(is_cancelled)?;
            if let Some(name) = &value.source_name {
                meter.text(name);
            }
        }
        for block in &function.blocks {
            check_cancelled(is_cancelled)?;
            meter.edges(&block.parameters);
            meter.edges(&block.instructions);
            for instruction in &block.instructions {
                check_cancelled(is_cancelled)?;
                meter.edges(&instruction.results);
                match &instruction.operation {
                    FlowOperation::Immediate(value) => immediate(value, &mut meter),
                    FlowOperation::ActorStateAddress { .. } => {}
                    FlowOperation::MakeAggregate { fields, .. }
                    | FlowOperation::Call {
                        arguments: fields, ..
                    }
                    | FlowOperation::AsyncCall {
                        arguments: fields, ..
                    }
                    | FlowOperation::TaskStart {
                        arguments: fields, ..
                    } => meter.edges(fields),
                    FlowOperation::Unary { .. }
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
                    | FlowOperation::ActorCapability { .. }
                    | FlowOperation::ActorReserve { .. }
                    | FlowOperation::ActorCommit { .. }
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
                    | FlowOperation::Assert { .. }
                    | FlowOperation::RecordEvent { .. }
                    | FlowOperation::ReplayEvent { .. }
                    | FlowOperation::TestEmit { .. }
                    | FlowOperation::TestFinish { .. } => {}
                }
            }
            match &block.terminator {
                Terminator::Jump { arguments, .. }
                | Terminator::Return(arguments)
                | Terminator::TailCall { arguments, .. } => meter.edges(arguments),
                Terminator::Branch {
                    then_arguments,
                    else_arguments,
                    ..
                } => {
                    meter.edges(then_arguments);
                    meter.edges(else_arguments);
                }
                Terminator::Switch {
                    cases,
                    default_arguments,
                    ..
                } => {
                    meter.edges(cases);
                    meter.edges(default_arguments);
                    for case in cases {
                        check_cancelled(is_cancelled)?;
                        meter.edges(&case.arguments);
                    }
                }
                Terminator::Suspend { .. } | Terminator::Trap { .. } | Terminator::Unreachable => {}
            }
        }
    }
    for actor in &wir.actors {
        check_cancelled(is_cancelled)?;
        meter.text(&actor.name);
        meter.edges(&actor.message_types);
        meter.edges(&actor.turn_functions);
    }
    for task in &wir.tasks {
        check_cancelled(is_cancelled)?;
        meter.text(&task.name);
    }
    for device in &wir.devices {
        check_cancelled(is_cancelled)?;
        meter.text(&device.name);
        meter.text(&device.target_binding);
        meter.edges(&device.required_features);
        meter.edges(&device.optional_features);
        meter.edges(&device.interrupt_functions);
        for feature in device
            .required_features
            .iter()
            .chain(&device.optional_features)
        {
            check_cancelled(is_cancelled)?;
            meter.text(feature);
        }
    }
    for pool in &wir.pools {
        check_cancelled(is_cancelled)?;
        meter.text(&pool.name);
        meter.edges(&pool.devices);
    }
    for region in &wir.regions {
        check_cancelled(is_cancelled)?;
        meter.text(&region.name);
    }
    for proof in &wir.proofs {
        check_cancelled(is_cancelled)?;
        meter.text(&proof.subject);
        meter.edges(&proof.sources);
        meter.edges(&proof.depends_on);
        meter.edges(&proof.explanation);
        for line in &proof.explanation {
            check_cancelled(is_cancelled)?;
            meter.text(line);
        }
    }
    for test in &wir.tests {
        check_cancelled(is_cancelled)?;
        meter.text(&test.name);
    }
    if meter.edge_overflowed || meter.edges > limits.model_edges {
        return Err(LowerError::ResourceLimit {
            resource: "FlowWir model edges",
            limit: limits.model_edges,
        });
    }
    if meter.payload_overflowed || meter.payload_bytes > limits.payload_bytes {
        return Err(LowerError::ResourceLimit {
            resource: "FlowWir payload bytes",
            limit: limits.payload_bytes,
        });
    }
    Ok(())
}

fn validate_report(
    input: &ValidatedSemanticWir,
    output: &ValidatedFlowWir,
    report: &LoweringReport,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LowerError> {
    check_cancelled(is_cancelled)?;
    let input = input.as_wir();
    let output = output.as_wir();
    if input.build != output.build || !polled_text_matches(&input.name, &output.name, is_cancelled)?
    {
        return Err(LowerError::InvalidReport(
            "input/output image or build identity mismatch",
        ));
    }
    let source_functions = u32::try_from(input.functions.len()).ok();
    let output_functions = u32::try_from(output.functions.len()).ok();
    let generated_functions = output_functions
        .zip(source_functions)
        .and_then(|(output, source)| output.checked_sub(source));
    let source_summary_matches = output.source_summary.semantic_wir_version
        == wrela_semantic_wir::SEMANTIC_WIR_VERSION
        && Some(output.source_summary.semantic_functions) == source_functions
        && output.source_summary.hir_files == input.source_summary.hir_files
        && output.source_summary.hir_declarations == input.source_summary.hir_declarations
        && output.source_summary.reachable_declarations
            == input.source_summary.reachable_declarations
        && output.source_summary.monomorphized_instantiations
            == input.source_summary.monomorphized_instantiations
        && output.source_summary.resolved_interface_calls
            == input.source_summary.resolved_interface_calls;
    let mut lowered_by_semantic_function = try_vec(
        input.functions.len(),
        "semantic function report map",
        limits.model_edges,
    )?;
    lowered_by_semantic_function.resize(input.functions.len(), None);
    for function in &output.functions {
        check_cancelled(is_cancelled)?;
        let semantic_function = match function.origin {
            FunctionOrigin::SourceSemantic { semantic_function }
            | FunctionOrigin::GeneratedImageEntry {
                semantic_function, ..
            }
            | FunctionOrigin::GeneratedTestHarness {
                semantic_function, ..
            } => Some(semantic_function),
            FunctionOrigin::GeneratedAsyncState { .. }
            | FunctionOrigin::GeneratedCleanup { .. } => None,
        };
        if let Some(semantic_function) = semantic_function {
            if let Some(slot) = lowered_by_semantic_function.get_mut(semantic_function as usize) {
                if slot.is_none() {
                    *slot = Some(function);
                }
            }
        }
    }
    let mut base_functions_match = true;
    for (index, (source, lowered)) in input
        .functions
        .iter()
        .zip(&lowered_by_semantic_function)
        .enumerate()
    {
        check_cancelled(is_cancelled)?;
        let semantic_function = u32::try_from(index).ok();
        if let Some((semantic_function, function)) = semantic_function.zip(*lowered) {
            base_functions_match &= semantic_function_contract_matches(
                source,
                function,
                semantic_function,
                is_cancelled,
            )?;
        } else {
            base_functions_match = false;
        }
    }
    let image_plan_matches = flow_plan_matches(input, output, is_cancelled)?;
    let proofs_match = semantic_proofs_match(input, output, is_cancelled)?;
    let minimum_shape_matches = supported_minimum(input)
        .map(|minimum| minimum_flow_shape_matches(minimum, output))
        .unwrap_or(true);
    let generated_test_shape_matches = if input.tests.is_empty() {
        true
    } else {
        match supported_generated_tests(input, limits, is_cancelled) {
            Ok(generated) => generated_flow_shape_matches(generated, output, limits, is_cancelled)?,
            Err(LowerError::Cancelled) => return Err(LowerError::Cancelled),
            Err(_) => false,
        }
    };
    let actor_shape_matches = if input.actors.is_empty()
        && input.tasks.is_empty()
        && input.regions.is_empty()
        && input.activations.is_empty()
    {
        true
    } else {
        match supported_actor_image(input, limits, is_cancelled) {
            Ok(actor) => actor_flow_shape_matches(actor, output, limits, is_cancelled)?,
            Err(LowerError::Cancelled) => return Err(LowerError::Cancelled),
            Err(_) => false,
        }
    };
    let test_metadata_matches = semantic_tests_match(input, output);
    let blocks = output.functions.iter().try_fold(0u64, |total, function| {
        total.checked_add(function.blocks.len() as u64)
    });
    let instructions = output.functions.iter().try_fold(0u64, |total, function| {
        function.blocks.iter().try_fold(total, |total, block| {
            total.checked_add(block.instructions.len() as u64)
        })
    });
    let async_states = output
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .filter(|block| matches!(block.terminator, Terminator::Suspend { .. }))
        .count() as u64;
    let states_within_limit = output.functions.iter().all(|function| {
        function
            .blocks
            .iter()
            .filter(|block| matches!(block.terminator, Terminator::Suspend { .. }))
            .count()
            <= limits.states_per_function as usize
    });
    let is_cleanup = |callee: wrela_flow_wir::FunctionId| {
        output
            .functions
            .get(callee.0 as usize)
            .is_some_and(|function| function.role == FunctionRole::Cleanup)
    };
    let cleanup_edges = output
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .map(|block| {
            let calls = block
                .instructions
                .iter()
                .filter(|instruction| {
                    matches!(
                        instruction.operation,
                        FlowOperation::Call { function, .. } if is_cleanup(function)
                    )
                })
                .count() as u64;
            calls
                + u64::from(matches!(
                    block.terminator,
                    Terminator::TailCall { function, .. } if is_cleanup(function)
                ))
        })
        .try_fold(0u64, u64::checked_add);
    validate_semantic_region_depth(input, limits, is_cancelled)?;
    if source_functions != Some(report.source_functions)
        || generated_functions != Some(report.generated_functions)
        || blocks != Some(report.blocks)
        || instructions != Some(report.instructions)
        || async_states != report.async_states
        || cleanup_edges != Some(report.cleanup_edges)
        || output.proofs.len() as u64 != report.output_proofs
        || !source_summary_matches
        || !base_functions_match
        || !image_plan_matches
        || !proofs_match
        || !minimum_shape_matches
        || !generated_test_shape_matches
        || !actor_shape_matches
        || !test_metadata_matches
        || blocks.is_none_or(|count| count > limits.blocks)
        || instructions.is_none_or(|count| count > limits.instructions)
        || !states_within_limit
    {
        Err(LowerError::InvalidReport(
            "reported counts do not match input and validated FlowWir",
        ))
    } else {
        Ok(())
    }
}

fn semantic_tests_match(input: &semantic::SemanticWir, output: &flow::FlowWir) -> bool {
    input.tests.len() == output.tests.len()
        && input.tests.iter().zip(&output.tests).all(|(source, out)| {
            out.id.0 == source.id.0
                && out.name == source.name
                && out.function.0 == source.function.0
                && out.kind
                    == match source.kind {
                        semantic::TestKind::Comptime => flow::TestKind::Comptime,
                        semantic::TestKind::Integration => flow::TestKind::Integration,
                        semantic::TestKind::Image => flow::TestKind::Image,
                    }
                && out.source == source.source
                && out.timeout_ns == source.timeout_ns
        })
}

fn semantic_proofs_match(
    input: &semantic::SemanticWir,
    output: &flow::FlowWir,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LowerError> {
    if output.proofs.len() < input.proofs.len() {
        return Ok(false);
    }
    for (source, lowered) in input.proofs.iter().zip(&output.proofs) {
        check_cancelled(is_cancelled)?;
        if lowered.id.0 != source.id.0
            || lowered.kind != lower_proof_kind(&source.kind)
            || !polled_text_matches(&lowered.subject, &source.subject, is_cancelled)?
            || !polled_slices_equal(&lowered.sources, &source.sources, is_cancelled)?
            || lowered.depends_on.len() != source.depends_on.len()
            || lowered.bound != source.bound
            || lowered.explanation.len() != source.explanation.len()
        {
            return Ok(false);
        }
        for (lowered, source) in lowered.depends_on.iter().zip(&source.depends_on) {
            check_cancelled(is_cancelled)?;
            if lowered.0 != source.0 {
                return Ok(false);
            }
        }
        for (lowered, source) in lowered.explanation.iter().zip(&source.explanation) {
            if !polled_text_matches(lowered, source, is_cancelled)? {
                return Ok(false);
            }
        }
    }
    for proof in &output.proofs[input.proofs.len()..] {
        check_cancelled(is_cancelled)?;
        if !matches!(
            proof.kind,
            flow::ProofKind::FlowControl
                | flow::ProofKind::ValueRange
                | flow::ProofKind::Alignment
                | flow::ProofKind::NoAlias
        ) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn minimum_flow_shape_matches(minimum: MinimumSemantic<'_>, output: &flow::FlowWir) -> bool {
    let [ty] = output.types.as_slice() else {
        return false;
    };
    let [function] = output.functions.as_slice() else {
        return false;
    };
    ty.id.0 == minimum.ty.id.0
        && ty.kind == flow::FlowTypeKind::Unit
        && ty.name.as_deref() == Some(minimum.ty.source_name.as_str())
        && ty.copyable
        && !ty.strict_linear
        && output.globals.is_empty()
        && function.parameters.is_empty()
        && function.result_types.is_empty()
        && function.values.is_empty()
        && matches!(
            function.blocks.as_slice(),
            [flow::Block {
                id: flow::BlockId(0),
                parameters,
                instructions,
                terminator: flow::Terminator::Return(values),
                source: None,
            }] if parameters.is_empty() && instructions.is_empty() && values.is_empty()
        )
        && function.entry == flow::BlockId(0)
        && output.actors.is_empty()
        && output.tasks.is_empty()
        && output.devices.is_empty()
        && output.pools.is_empty()
        && output.regions.is_empty()
        && output.activations.is_empty()
        && output.checkpoints.is_empty()
        && output.tests.is_empty()
        && output.proofs.len() == minimum.input.proofs.len()
}

fn generated_flow_shape_matches(
    generated: GeneratedTestSemantic<'_>,
    output: &flow::FlowWir,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LowerError> {
    let expected = lower_generated_tests(generated, limits, is_cancelled)?;
    Ok(&expected == output)
}

fn actor_flow_shape_matches(
    actor: ActorImageSemantic<'_>,
    output: &flow::FlowWir,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LowerError> {
    let expected = lower_actor_image(actor, limits, is_cancelled)?;
    actor_flow_program_matches(&expected, output, is_cancelled)
}

fn actor_flow_program_matches(
    expected: &flow::FlowWir,
    output: &flow::FlowWir,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LowerError> {
    if expected.types.len() != output.types.len()
        || expected.functions.len() != output.functions.len()
    {
        return Ok(false);
    }
    for (expected, output) in expected.types.iter().zip(&output.types) {
        check_cancelled(is_cancelled)?;
        if expected.id != output.id
            || expected.copyable != output.copyable
            || expected.strict_linear != output.strict_linear
            || match (&expected.name, &output.name) {
                (Some(expected), Some(output)) => {
                    !polled_text_matches(expected, output, is_cancelled)?
                }
                (None, None) => false,
                _ => true,
            }
            || !actor_flow_type_kind_matches(&expected.kind, &output.kind, is_cancelled)?
        {
            return Ok(false);
        }
    }
    for (expected, output) in expected.functions.iter().zip(&output.functions) {
        check_cancelled(is_cancelled)?;
        if expected.id != output.id
            || !polled_text_matches(&expected.name, &output.name, is_cancelled)?
            || expected.origin != output.origin
            || expected.role != output.role
            || expected.color != output.color
            || !polled_slices_equal(&expected.parameters, &output.parameters, is_cancelled)?
            || !polled_slices_equal(&expected.result_types, &output.result_types, is_cancelled)?
            || expected.values.len() != output.values.len()
            || expected.blocks.len() != output.blocks.len()
            || expected.entry != output.entry
            || expected.stack_bound != output.stack_bound
            || expected.frame_bound != output.frame_bound
            || !polled_slices_equal(&expected.proofs, &output.proofs, is_cancelled)?
            || expected.source != output.source
        {
            return Ok(false);
        }
        for (expected, output) in expected.values.iter().zip(&output.values) {
            check_cancelled(is_cancelled)?;
            if expected.id != output.id
                || expected.ty != output.ty
                || expected.source != output.source
                || match (&expected.source_name, &output.source_name) {
                    (Some(expected), Some(output)) => {
                        !polled_text_matches(expected, output, is_cancelled)?
                    }
                    (None, None) => false,
                    _ => true,
                }
            {
                return Ok(false);
            }
        }
        for (expected, output) in expected.blocks.iter().zip(&output.blocks) {
            check_cancelled(is_cancelled)?;
            if expected.id != output.id
                || !polled_slices_equal(&expected.parameters, &output.parameters, is_cancelled)?
                || expected.instructions.len() != output.instructions.len()
                || expected.source != output.source
                || !actor_flow_terminator_matches(
                    &expected.terminator,
                    &output.terminator,
                    is_cancelled,
                )?
            {
                return Ok(false);
            }
            for (expected, output) in expected.instructions.iter().zip(&output.instructions) {
                check_cancelled(is_cancelled)?;
                if expected.id != output.id
                    || !polled_slices_equal(&expected.results, &output.results, is_cancelled)?
                    || expected.source != output.source
                    || !actor_flow_operation_matches(
                        &expected.operation,
                        &output.operation,
                        is_cancelled,
                    )?
                {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

fn actor_flow_type_kind_matches(
    expected: &flow::FlowTypeKind,
    output: &flow::FlowTypeKind,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LowerError> {
    Ok(match (expected, output) {
        (flow::FlowTypeKind::Unit, flow::FlowTypeKind::Unit) => true,
        (flow::FlowTypeKind::Scalar(expected), flow::FlowTypeKind::Scalar(output)) => {
            expected == output
        }
        (
            flow::FlowTypeKind::Array {
                element: expected_element,
                length: expected_length,
            },
            flow::FlowTypeKind::Array {
                element: output_element,
                length: output_length,
            },
        ) => expected_element == output_element && expected_length == output_length,
        (
            flow::FlowTypeKind::Struct { fields: expected },
            flow::FlowTypeKind::Struct { fields: output },
        ) => polled_slices_equal(expected, output, is_cancelled)?,
        (
            flow::FlowTypeKind::Function {
                parameters: expected_parameters,
                result: expected_result,
            },
            flow::FlowTypeKind::Function {
                parameters: output_parameters,
                result: output_result,
            },
        ) => {
            expected_result == output_result
                && polled_slices_equal(expected_parameters, output_parameters, is_cancelled)?
        }
        (
            flow::FlowTypeKind::Activation { result: expected },
            flow::FlowTypeKind::Activation { result: output },
        ) => expected == output,
        (flow::FlowTypeKind::ActorHandle(expected), flow::FlowTypeKind::ActorHandle(output)) => {
            expected == output
        }
        (flow::FlowTypeKind::Reservation, flow::FlowTypeKind::Reservation) => true,
        _ => false,
    })
}

fn actor_flow_operation_matches(
    expected: &flow::FlowOperation,
    output: &flow::FlowOperation,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LowerError> {
    Ok(match (expected, output) {
        (flow::FlowOperation::Immediate(expected), flow::FlowOperation::Immediate(output)) => {
            actor_flow_immediate_matches(expected, output, is_cancelled)?
        }
        (
            flow::FlowOperation::ActorStateAddress {
                actor: ea,
                region: er,
                proof: ep,
            },
            flow::FlowOperation::ActorStateAddress {
                actor: oa,
                region: or,
                proof: op,
            },
        ) => ea == oa && er == or && ep == op,
        (
            flow::FlowOperation::Load {
                address: ea,
                proof: ep,
            },
            flow::FlowOperation::Load {
                address: oa,
                proof: op,
            },
        ) => ea == oa && ep == op,
        (
            flow::FlowOperation::Store {
                address: ea,
                value: ev,
                proof: ep,
            },
            flow::FlowOperation::Store {
                address: oa,
                value: ov,
                proof: op,
            },
        ) => ea == oa && ev == ov && ep == op,
        (
            flow::FlowOperation::Unary {
                op: expected_op,
                value: expected_value,
            },
            flow::FlowOperation::Unary {
                op: output_op,
                value: output_value,
            },
        ) => expected_op == output_op && expected_value == output_value,
        (
            flow::FlowOperation::Binary {
                op: expected_op,
                left: expected_left,
                right: expected_right,
            },
            flow::FlowOperation::Binary {
                op: output_op,
                left: output_left,
                right: output_right,
            },
        ) => {
            expected_op == output_op
                && expected_left == output_left
                && expected_right == output_right
        }
        (
            flow::FlowOperation::Cast {
                value: expected_value,
                to: expected_to,
                mode: expected_mode,
            },
            flow::FlowOperation::Cast {
                value: output_value,
                to: output_to,
                mode: output_mode,
            },
        ) => {
            expected_value == output_value
                && expected_to == output_to
                && expected_mode == output_mode
        }
        (
            flow::FlowOperation::Copy { value: expected },
            flow::FlowOperation::Copy { value: output },
        ) => expected == output,
        (
            flow::FlowOperation::Call {
                function: expected_function,
                arguments: expected_arguments,
            },
            flow::FlowOperation::Call {
                function: output_function,
                arguments: output_arguments,
            },
        ) => {
            expected_function == output_function
                && polled_slices_equal(expected_arguments, output_arguments, is_cancelled)?
        }
        (
            flow::FlowOperation::AsyncCall {
                function: expected_function,
                arguments: expected_arguments,
                plan: expected_plan,
            },
            flow::FlowOperation::AsyncCall {
                function: output_function,
                arguments: output_arguments,
                plan: output_plan,
            },
        ) => {
            expected_function == output_function
                && expected_plan == output_plan
                && polled_slices_equal(expected_arguments, output_arguments, is_cancelled)?
        }
        (
            flow::FlowOperation::ActorCapability {
                actor: expected_actor,
                proof: expected_proof,
            },
            flow::FlowOperation::ActorCapability {
                actor: output_actor,
                proof: output_proof,
            },
        ) => expected_actor == output_actor && expected_proof == output_proof,
        (
            flow::FlowOperation::ActorReserve {
                actor: expected_actor,
                method: expected_method,
                proof: expected_proof,
            },
            flow::FlowOperation::ActorReserve {
                actor: output_actor,
                method: output_method,
                proof: output_proof,
            },
        ) => {
            expected_actor == output_actor
                && expected_method == output_method
                && expected_proof == output_proof
        }
        (
            flow::FlowOperation::ActorCommit {
                reservation: expected_reservation,
                arguments: expected_arguments,
            },
            flow::FlowOperation::ActorCommit {
                reservation: output_reservation,
                arguments: output_arguments,
            },
        ) => {
            expected_reservation == output_reservation
                && polled_slices_equal(expected_arguments, output_arguments, is_cancelled)?
        }
        (
            flow::FlowOperation::MailboxReceive {
                actor: expected_actor,
                method: expected_method,
            },
            flow::FlowOperation::MailboxReceive {
                actor: output_actor,
                method: output_method,
            },
        ) => expected_actor == output_actor && expected_method == output_method,
        _ => false,
    })
}

fn actor_flow_immediate_matches(
    expected: &flow::Immediate,
    output: &flow::Immediate,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LowerError> {
    Ok(match (expected, output) {
        (flow::Immediate::Unit, flow::Immediate::Unit) => true,
        (flow::Immediate::Bool(expected), flow::Immediate::Bool(output)) => expected == output,
        (
            flow::Immediate::Integer {
                bits: expected_bits,
                bytes_le: expected_bytes,
            },
            flow::Immediate::Integer {
                bits: output_bits,
                bytes_le: output_bytes,
            },
        ) => {
            expected_bits == output_bits
                && polled_slices_equal(expected_bytes, output_bytes, is_cancelled)?
        }
        (flow::Immediate::Bytes(expected), flow::Immediate::Bytes(output)) => {
            polled_slices_equal(expected, output, is_cancelled)?
        }
        (flow::Immediate::Float32(expected), flow::Immediate::Float32(output)) => {
            expected == output
        }
        (flow::Immediate::Float64(expected), flow::Immediate::Float64(output)) => {
            expected == output
        }
        (flow::Immediate::Zero(expected), flow::Immediate::Zero(output)) => expected == output,
        _ => false,
    })
}

fn actor_flow_terminator_matches(
    expected: &flow::Terminator,
    output: &flow::Terminator,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LowerError> {
    Ok(match (expected, output) {
        (
            flow::Terminator::Jump {
                target: expected_target,
                arguments: expected_arguments,
            },
            flow::Terminator::Jump {
                target: output_target,
                arguments: output_arguments,
            },
        ) => {
            expected_target == output_target
                && polled_slices_equal(expected_arguments, output_arguments, is_cancelled)?
        }
        (
            flow::Terminator::Branch {
                condition: expected_condition,
                then_block: expected_then,
                then_arguments: expected_then_arguments,
                else_block: expected_else,
                else_arguments: expected_else_arguments,
            },
            flow::Terminator::Branch {
                condition: output_condition,
                then_block: output_then,
                then_arguments: output_then_arguments,
                else_block: output_else,
                else_arguments: output_else_arguments,
            },
        ) => {
            expected_condition == output_condition
                && expected_then == output_then
                && expected_else == output_else
                && polled_slices_equal(
                    expected_then_arguments,
                    output_then_arguments,
                    is_cancelled,
                )?
                && polled_slices_equal(
                    expected_else_arguments,
                    output_else_arguments,
                    is_cancelled,
                )?
        }
        (flow::Terminator::Return(expected), flow::Terminator::Return(output)) => {
            polled_slices_equal(expected, output, is_cancelled)?
        }
        (
            flow::Terminator::Suspend {
                state: expected_state,
                activation: expected_activation,
                resume: expected_resume,
            },
            flow::Terminator::Suspend {
                state: output_state,
                activation: output_activation,
                resume: output_resume,
            },
        ) => {
            expected_state == output_state
                && expected_activation == output_activation
                && expected_resume == output_resume
        }
        (flow::Terminator::Unreachable, flow::Terminator::Unreachable) => true,
        _ => false,
    })
}

fn flow_plan_matches(
    input: &wrela_semantic_wir::SemanticWir,
    output: &wrela_flow_wir::FlowWir,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LowerError> {
    if output.static_bytes != input.static_bytes
        || output.peak_bytes != input.peak_bytes
        || output.image_entry.0 != input.image_entry.0
        || input.actors.len() != output.actors.len()
        || input.tasks.len() != output.tasks.len()
        || input.devices.len() != output.devices.len()
        || input.pools.len() != output.pools.len()
        || input.regions.len() != output.regions.len()
        || input.activations.len() != output.activations.len()
        || output.startup_order.len() != input.startup_order.len()
        || output.shutdown_order.len() != input.shutdown_order.len()
    {
        return Ok(false);
    }
    for (source, out) in input.actors.iter().zip(&output.actors) {
        check_cancelled(is_cancelled)?;
        if out.id.0 != source.id.0
            || !polled_text_matches(&out.name, &source.name, is_cancelled)?
            || out.state_type.0 != source.ty.0
            || out.priority != source.priority
            || out.mailbox_capacity != source.mailbox_capacity
            || out.message_types.len() != source.message_types.len()
            || out.turn_functions.len() != source.turn_functions.len()
            || out.supervisor.map(|id| id.0) != source.supervisor.map(|id| id.0)
        {
            return Ok(false);
        }
        for (out, source) in out.message_types.iter().zip(&source.message_types) {
            check_cancelled(is_cancelled)?;
            if out.0 != source.0 {
                return Ok(false);
            }
        }
        for (out, source) in out.turn_functions.iter().zip(&source.turn_functions) {
            check_cancelled(is_cancelled)?;
            if out.0 != source.0 {
                return Ok(false);
            }
        }
    }
    for (source, out) in input.tasks.iter().zip(&output.tasks) {
        check_cancelled(is_cancelled)?;
        if out.id.0 != source.id.0
            || !polled_text_matches(&out.name, &source.name, is_cancelled)?
            || out.entry.0 != source.entry.0
            || out.slots != source.slots
            || out.priority != source.priority
            || out.supervisor.map(|id| id.0) != source.supervisor.map(|id| id.0)
            || output
                .functions
                .get(out.entry.0 as usize)
                .is_none_or(|function| function.frame_bound != out.frame_bytes_bound)
        {
            return Ok(false);
        }
    }
    for (source, out) in input.regions.iter().zip(&output.regions) {
        check_cancelled(is_cancelled)?;
        if out.id.0 != source.id.0
            || !polled_text_matches(&out.name, &source.name, is_cancelled)?
            || out.class != lower_region_class(source.class)
            || out.capacity_bytes != source.capacity_bytes
            || out.alignment != source.alignment
            || out.capacity_proof.0 != source.proof.0
            || out.source != source.source
            || !flow_owner_matches(out.owner, source.owner)
        {
            return Ok(false);
        }
    }
    for (source, out) in input.activations.iter().zip(&output.activations) {
        check_cancelled(is_cancelled)?;
        if out.id.0 != source.id.0
            || out.caller.0 != source.caller.0
            || out.callee.0 != source.callee.0
            || out.region.0 != source.region.0
            || out.frame_bytes != source.frame_bytes
            || out.maximum_live != source.maximum_live
            || !matches!(
                (out.cancellation, source.cancellation),
                (
                    flow::ActivationCancellation::DropCalleeThenPropagate,
                    semantic::ActivationCancellation::DropCalleeThenPropagate
                )
            )
            || out.capacity_proof.0 != source.capacity_proof.0
            || out.source != source.source
        {
            return Ok(false);
        }
    }
    for (out, source) in output.startup_order.iter().zip(&input.startup_order) {
        check_cancelled(is_cancelled)?;
        if !flow_owner_matches(*out, *source) {
            return Ok(false);
        }
    }
    for (out, source) in output.shutdown_order.iter().zip(&input.shutdown_order) {
        check_cancelled(is_cancelled)?;
        if !flow_owner_matches(*out, *source) {
            return Ok(false);
        }
    }
    Ok(input.devices.is_empty()
        && output.devices.is_empty()
        && input.pools.is_empty()
        && output.pools.is_empty())
}

fn flow_owner_matches(
    output: wrela_flow_wir::PlanOwner,
    input: wrela_semantic_wir::ImageOwner,
) -> bool {
    match (output, input) {
        (wrela_flow_wir::PlanOwner::Runtime, wrela_semantic_wir::ImageOwner::Runtime) => true,
        (wrela_flow_wir::PlanOwner::Actor(out), wrela_semantic_wir::ImageOwner::Actor(source)) => {
            out.0 == source.0
        }
        (wrela_flow_wir::PlanOwner::Task(out), wrela_semantic_wir::ImageOwner::Task(source)) => {
            out.0 == source.0
        }
        (
            wrela_flow_wir::PlanOwner::Device(out),
            wrela_semantic_wir::ImageOwner::Device(source),
        ) => out.0 == source.0,
        (wrela_flow_wir::PlanOwner::Pool(out), wrela_semantic_wir::ImageOwner::Pool(source)) => {
            out.0 == source.0
        }
        (
            wrela_flow_wir::PlanOwner::BakedArtifact(out),
            wrela_semantic_wir::ImageOwner::BakedArtifact(source),
        ) => out == source,
        _ => false,
    }
}

fn semantic_function_contract_matches(
    source: &wrela_semantic_wir::SemanticFunction,
    output: &wrela_flow_wir::FlowFunction,
    semantic_function: u32,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LowerError> {
    let origin = match source.origin {
        SemanticFunctionOrigin::Source => FunctionOrigin::SourceSemantic { semantic_function },
        SemanticFunctionOrigin::GeneratedImageEntry { constructor } => {
            FunctionOrigin::GeneratedImageEntry {
                semantic_function,
                constructor,
            }
        }
        SemanticFunctionOrigin::GeneratedTestHarness { group } => {
            FunctionOrigin::GeneratedTestHarness {
                semantic_function,
                group,
            }
        }
    };
    let role = match source.role {
        SemanticFunctionRole::Ordinary => FunctionRole::Ordinary,
        SemanticFunctionRole::ActorTurn(id) => {
            FunctionRole::ActorTurn(wrela_flow_wir::ActorId(id.0))
        }
        SemanticFunctionRole::TaskEntry(id) => {
            FunctionRole::TaskEntry(wrela_flow_wir::TaskId(id.0))
        }
        SemanticFunctionRole::Isr(id) => FunctionRole::Isr(wrela_flow_wir::DeviceId(id.0)),
        SemanticFunctionRole::Cleanup => FunctionRole::Cleanup,
        SemanticFunctionRole::ImageEntry => FunctionRole::ImageEntry,
        SemanticFunctionRole::Test => FunctionRole::Test,
    };
    let proofs_match =
        semantic_proof_attachments_match(&source.proofs, &output.proofs, is_cancelled)?;
    Ok(
        polled_text_matches(&output.name, &source.name, is_cancelled)?
            && output.origin == origin
            && output.role == role
            && output.color == lower_function_color(source.color)
            && output.stack_bound == source.stack_bound
            && output.frame_bound == source.frame_bound
            && output.source == source.source
            && proofs_match,
    )
}

fn polled_text_matches(
    left: &str,
    right: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LowerError> {
    if left.len() != right.len() {
        return Ok(false);
    }
    for (left, right) in left
        .as_bytes()
        .chunks(4096)
        .zip(right.as_bytes().chunks(4096))
    {
        check_cancelled(is_cancelled)?;
        if left != right {
            return Ok(false);
        }
    }
    Ok(true)
}

fn polled_slices_equal<T: Eq>(
    left: &[T],
    right: &[T],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LowerError> {
    if left.len() != right.len() {
        return Ok(false);
    }
    for (left, right) in left.iter().zip(right) {
        check_cancelled(is_cancelled)?;
        if left != right {
            return Ok(false);
        }
    }
    Ok(true)
}

fn validate_diagnostics(
    diagnostics: &[Diagnostic],
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LowerError> {
    let mut bytes = 0u64;
    for diagnostic in diagnostics {
        check_cancelled(is_cancelled)?;
        if diagnostic.message.trim().is_empty()
            || diagnostic.primary.range.start > diagnostic.primary.range.end
        {
            return Err(LowerError::InternalInvariant {
                operation: "diagnostics".to_owned(),
                detail: "diagnostic message or span is invalid".to_owned(),
            });
        }
        for value in std::iter::once(diagnostic.message.as_str())
            .chain(diagnostic.code.iter().map(String::as_str))
            .chain(diagnostic.labels.iter().map(|value| value.message.as_str()))
            .chain(diagnostic.notes.iter().map(String::as_str))
            .chain(diagnostic.help.iter().map(String::as_str))
            .chain(
                diagnostic
                    .related
                    .iter()
                    .map(|value| value.message.as_str()),
            )
            .chain(
                diagnostic
                    .repairs
                    .iter()
                    .map(|value| value.message.as_str()),
            )
            .chain(
                diagnostic
                    .repairs
                    .iter()
                    .flat_map(|repair| repair.edits.iter())
                    .map(|edit| edit.replacement.as_str()),
            )
        {
            check_cancelled(is_cancelled)?;
            bytes = bytes
                .checked_add(
                    u64::try_from(value.len()).map_err(|_| LowerError::ResourceLimit {
                        resource: "diagnostic bytes",
                        limit: limits.diagnostic_bytes,
                    })?,
                )
                .ok_or(LowerError::ResourceLimit {
                    resource: "diagnostic bytes",
                    limit: limits.diagnostic_bytes,
                })?;
        }
    }
    if bytes > limits.diagnostic_bytes {
        return Err(LowerError::ResourceLimit {
            resource: "diagnostic bytes",
            limit: limits.diagnostic_bytes,
        });
    }
    Ok(())
}

fn validate_semantic_region_depth(
    input: &wrela_semantic_wir::SemanticWir,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LowerError> {
    let mut regions = try_vec(1, "semantic region report work", limits.model_edges)?;
    for function in &input.functions {
        check_cancelled(is_cancelled)?;
        push_bounded(
            &mut regions,
            (&function.body, 1_u32),
            "semantic region report work",
            limits.model_edges,
        )?;
        while let Some((region, depth)) = regions.pop() {
            check_cancelled(is_cancelled)?;
            if depth > limits.region_depth {
                return Err(LowerError::ResourceLimit {
                    resource: "semantic region depth",
                    limit: u64::from(limits.region_depth),
                });
            }
            let next = depth.checked_add(1).ok_or(LowerError::ResourceLimit {
                resource: "semantic region depth",
                limit: u64::from(limits.region_depth),
            })?;
            for statement in region.statements.iter().rev() {
                check_cancelled(is_cancelled)?;
                match statement {
                    wrela_semantic_wir::SemanticStatement::If {
                        then_region,
                        else_region,
                        ..
                    } => {
                        push_bounded(
                            &mut regions,
                            (else_region, next),
                            "semantic region report work",
                            limits.model_edges,
                        )?;
                        push_bounded(
                            &mut regions,
                            (then_region, next),
                            "semantic region report work",
                            limits.model_edges,
                        )?;
                    }
                    wrela_semantic_wir::SemanticStatement::Match { arms, .. } => {
                        for arm in arms.iter().rev() {
                            check_cancelled(is_cancelled)?;
                            push_bounded(
                                &mut regions,
                                (&arm.body, next),
                                "semantic region report work",
                                limits.model_edges,
                            )?;
                        }
                    }
                    wrela_semantic_wir::SemanticStatement::Loop { body, .. } => push_bounded(
                        &mut regions,
                        (body, next),
                        "semantic region report work",
                        limits.model_edges,
                    )?,
                    wrela_semantic_wir::SemanticStatement::Let(_)
                    | wrela_semantic_wir::SemanticStatement::Return(_)
                    | wrela_semantic_wir::SemanticStatement::Yield(_)
                    | wrela_semantic_wir::SemanticStatement::Break(_)
                    | wrela_semantic_wir::SemanticStatement::Continue(_)
                    | wrela_semantic_wir::SemanticStatement::Unreachable => {}
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod contract_tests {
    use std::cell::Cell;

    use super::{
        CanonicalFlowLowerer, FlowLowerer, LowerError, LowerRequest, LoweringLimits,
        LoweringReport, actor_flow_program_matches, lower_proof_kind,
        measure_actor_flow_output_resources, preflight_input, seal, supported_actor_image,
        supported_source_value_type,
    };
    use wrela_build_model::{BuildIdentity, LanguageRevision, Sha256Digest, TargetIdentity};
    use wrela_flow_wir as flow;
    use wrela_semantic_wir as semantic;
    use wrela_source::{FileId, Span, TextRange};
    use wrela_test_model::{
        GuestTestOutcome, TEST_PROTOCOL_VERSION, TestEvent, TestEventKind, TestId,
    };
    use wrela_test_protocol::{CanonicalTestEventCodec, ProtocolLimits, seal_encoded_event};

    fn canonical_passing_frames(tests: &[u32]) -> Vec<Vec<u8>> {
        let mut events = vec![TestEvent {
            protocol: TEST_PROTOCOL_VERSION,
            sequence: 0,
            kind: TestEventKind::RunStarted {
                test_count: u32::try_from(tests.len()).expect("fixture test count"),
            },
        }];
        for (index, test) in tests.iter().copied().enumerate() {
            let sequence = u64::try_from(index * 2 + 1).expect("fixture sequence");
            events.push(TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence,
                kind: TestEventKind::TestStarted { test: TestId(test) },
            });
            events.push(TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: sequence + 1,
                kind: TestEventKind::TestFinished {
                    test: TestId(test),
                    outcome: GuestTestOutcome::Passed,
                },
            });
        }
        events.push(TestEvent {
            protocol: TEST_PROTOCOL_VERSION,
            sequence: u64::try_from(tests.len() * 2 + 1).expect("fixture sequence"),
            kind: TestEventKind::RunFinished {
                passed: u32::try_from(tests.len()).expect("fixture test count"),
                failed: 0,
            },
        });
        events
            .iter()
            .map(|event| {
                seal_encoded_event(
                    &CanonicalTestEventCodec,
                    event,
                    ProtocolLimits::standard(),
                    &|| false,
                )
                .expect("canonical generated passing frame")
                .bytes()
                .to_vec()
            })
            .collect()
    }

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

    fn fixture() -> semantic::ValidatedSemanticWir {
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

    #[test]
    fn supported_flat_structure_types_require_scalar_fields() {
        let mut module = fixture().into_wir();
        module.types.extend([
            semantic::TypeRecord {
                id: semantic::TypeId(1),
                source_name: "u64".to_owned(),
                kind: semantic::TypeKind::Primitive(semantic::PrimitiveType::U64),
                linearity: semantic::Linearity::CopyScalar,
                source: Some(span(0, 1, 2)),
            },
            semantic::TypeRecord {
                id: semantic::TypeId(2),
                source_name: "ScalarField".to_owned(),
                kind: semantic::TypeKind::Struct {
                    fields: vec![semantic::FieldType {
                        name: "value".to_owned(),
                        ty: semantic::TypeId(1),
                        public: true,
                    }],
                },
                linearity: semantic::Linearity::ExplicitCopy,
                source: Some(span(0, 3, 4)),
            },
            semantic::TypeRecord {
                id: semantic::TypeId(3),
                source_name: "NestedField".to_owned(),
                kind: semantic::TypeKind::Struct {
                    fields: vec![semantic::FieldType {
                        name: "nested".to_owned(),
                        ty: semantic::TypeId(2),
                        public: true,
                    }],
                },
                linearity: semantic::Linearity::ExplicitCopy,
                source: Some(span(0, 5, 6)),
            },
        ]);

        assert!(supported_source_value_type(&module, semantic::TypeId(2)));
        assert!(
            !supported_source_value_type(&module, semantic::TypeId(3)),
            "crafted nested aggregate fields must not enter the flat scalar lowering subset"
        );
    }

    fn actor_fixture() -> semantic::ValidatedSemanticWir {
        let helper_source = span(0, 10, 40);
        let turn_source = span(0, 50, 120);
        let task_source = span(0, 130, 180);
        let mut module = fixture().into_wir();
        module.name = "actor-image".to_owned();
        module.source_summary = semantic::SourceSummary {
            hir_files: 2,
            hir_declarations: 8,
            reachable_declarations: 4,
            monomorphized_instantiations: 4,
            resolved_interface_calls: 0,
        };
        module.types = vec![
            semantic::TypeRecord {
                id: semantic::TypeId(0),
                source_name: "unit".to_owned(),
                kind: semantic::TypeKind::Primitive(semantic::PrimitiveType::Unit),
                linearity: semantic::Linearity::CopyScalar,
                source: None,
            },
            semantic::TypeRecord {
                id: semantic::TypeId(1),
                source_name: "u32".to_owned(),
                kind: semantic::TypeKind::Primitive(semantic::PrimitiveType::U32),
                linearity: semantic::Linearity::CopyScalar,
                source: Some(helper_source),
            },
            semantic::TypeRecord {
                id: semantic::TypeId(2),
                source_name: "Worker".to_owned(),
                kind: semantic::TypeKind::Struct { fields: Vec::new() },
                linearity: semantic::Linearity::Reclaimable,
                source: Some(turn_source),
            },
            semantic::TypeRecord {
                id: semantic::TypeId(3),
                source_name: "fn".to_owned(),
                kind: semantic::TypeKind::Function(semantic::FunctionType {
                    color: semantic::FunctionColor::Sync,
                    parameters: vec![semantic::ParameterType {
                        access: semantic::AccessMode::Read,
                        ty: semantic::TypeId(1),
                    }],
                    result: semantic::TypeId(1),
                }),
                linearity: semantic::Linearity::CopyScalar,
                source: Some(helper_source),
            },
            semantic::TypeRecord {
                id: semantic::TypeId(4),
                source_name: "fn".to_owned(),
                kind: semantic::TypeKind::Function(semantic::FunctionType {
                    color: semantic::FunctionColor::Async,
                    parameters: Vec::new(),
                    result: semantic::TypeId(0),
                }),
                linearity: semantic::Linearity::CopyScalar,
                source: Some(turn_source),
            },
        ];
        module.proofs = vec![
            proof(0, semantic::ProofKind::TypeChecked, &[], None),
            proof(1, semantic::ProofKind::EffectsAllowed, &[0], Some(4)),
            proof(2, semantic::ProofKind::CapacityBound, &[], Some(2)),
            proof(3, semantic::ProofKind::CapacityBound, &[], Some(1)),
            proof(4, semantic::ProofKind::CapacityBound, &[], Some(1)),
            proof(5, semantic::ProofKind::Ownership, &[0], None),
            proof(6, semantic::ProofKind::ViewDoesNotEscape, &[5], None),
            proof(7, semantic::ProofKind::WaitGraphAcyclic, &[6], Some(0)),
            proof(8, semantic::ProofKind::CleanupAcyclic, &[7], Some(0)),
            proof(
                9,
                semantic::ProofKind::ImageClosed,
                &[0, 1, 2, 3, 4, 7],
                Some(64),
            ),
        ];
        module.proofs[2].sources = vec![span(0, 110, 111)];
        module.proofs[3].sources = vec![turn_source];
        module.proofs[4].sources = vec![task_source];
        module.proofs[9].sources = vec![module.proofs[0].sources[0], turn_source];
        module.functions = vec![
            semantic::SemanticFunction {
                id: semantic::FunctionId(0),
                instance_key: Sha256Digest::from_bytes([0x70; 32]),
                name: "helper".to_owned(),
                origin: semantic::FunctionOrigin::Source,
                role: semantic::FunctionRole::Ordinary,
                color: semantic::FunctionColor::Sync,
                parameters: vec![semantic::ValueId(0)],
                result: semantic::TypeId(1),
                values: vec![
                    semantic::SemanticValue {
                        id: semantic::ValueId(0),
                        ty: semantic::TypeId(1),
                        origin: Some(helper_source),
                        name: Some("value".to_owned()),
                    },
                    semantic::SemanticValue {
                        id: semantic::ValueId(1),
                        ty: semantic::TypeId(1),
                        origin: Some(span(0, 30, 35)),
                        name: None,
                    },
                ],
                body: semantic::SemanticRegion {
                    parameters: vec![semantic::ValueId(0)],
                    statements: vec![
                        semantic::SemanticStatement::Let(semantic::LetStatement {
                            results: vec![semantic::ValueId(1)],
                            operation: semantic::SemanticOperation::Copy {
                                value: semantic::ValueId(0),
                            },
                            source: Some(span(0, 30, 35)),
                        }),
                        semantic::SemanticStatement::Return(vec![semantic::ValueId(1)]),
                    ],
                },
                effects: semantic::EffectSet::default(),
                proofs: vec![semantic::ProofId(0), semantic::ProofId(1)],
                source: Some(helper_source),
                stack_bound: 4,
                frame_bound: 0,
                uninterrupted_bound: Some(2),
                recursive_depth_bound: Some(1),
            },
            semantic::SemanticFunction {
                id: semantic::FunctionId(1),
                instance_key: Sha256Digest::from_bytes([0x71; 32]),
                name: "Worker.ping".to_owned(),
                origin: semantic::FunctionOrigin::Source,
                role: semantic::FunctionRole::ActorTurn(semantic::ActorId(0)),
                color: semantic::FunctionColor::Async,
                parameters: vec![semantic::ValueId(0)],
                result: semantic::TypeId(0),
                values: vec![
                    semantic::SemanticValue {
                        id: semantic::ValueId(0),
                        ty: semantic::TypeId(2),
                        origin: Some(turn_source),
                        name: Some("self".to_owned()),
                    },
                    semantic::SemanticValue {
                        id: semantic::ValueId(1),
                        ty: semantic::TypeId(1),
                        origin: Some(span(0, 80, 81)),
                        name: None,
                    },
                    semantic::SemanticValue {
                        id: semantic::ValueId(2),
                        ty: semantic::TypeId(1),
                        origin: Some(span(0, 82, 91)),
                        name: None,
                    },
                ],
                body: semantic::SemanticRegion {
                    parameters: vec![semantic::ValueId(0)],
                    statements: vec![
                        semantic::SemanticStatement::Let(semantic::LetStatement {
                            results: vec![semantic::ValueId(1)],
                            operation: semantic::SemanticOperation::Constant(
                                semantic::Constant::Unsigned { bits: 32, value: 7 },
                            ),
                            source: Some(span(0, 80, 81)),
                        }),
                        semantic::SemanticStatement::Let(semantic::LetStatement {
                            results: vec![semantic::ValueId(2)],
                            operation: semantic::SemanticOperation::Call {
                                function: semantic::FunctionId(0),
                                arguments: vec![semantic::Argument {
                                    access: semantic::AccessMode::Read,
                                    value: semantic::ValueId(1),
                                }],
                                activation: None,
                            },
                            source: Some(span(0, 82, 91)),
                        }),
                        semantic::SemanticStatement::Return(Vec::new()),
                    ],
                },
                effects: semantic::EffectSet(
                    semantic::EffectSet::ACTOR_CALL | semantic::EffectSet::SUSPEND,
                ),
                proofs: vec![
                    semantic::ProofId(0),
                    semantic::ProofId(1),
                    semantic::ProofId(5),
                    semantic::ProofId(6),
                    semantic::ProofId(7),
                ],
                source: Some(turn_source),
                stack_bound: 8,
                frame_bound: 16,
                uninterrupted_bound: Some(3),
                recursive_depth_bound: Some(1),
            },
            semantic::SemanticFunction {
                id: semantic::FunctionId(2),
                instance_key: Sha256Digest::from_bytes([0x72; 32]),
                name: "Worker.pulse".to_owned(),
                origin: semantic::FunctionOrigin::Source,
                role: semantic::FunctionRole::TaskEntry(semantic::TaskId(0)),
                color: semantic::FunctionColor::Async,
                parameters: vec![semantic::ValueId(0)],
                result: semantic::TypeId(0),
                values: vec![semantic::SemanticValue {
                    id: semantic::ValueId(0),
                    ty: semantic::TypeId(2),
                    origin: Some(task_source),
                    name: Some("self".to_owned()),
                }],
                body: semantic::SemanticRegion {
                    parameters: vec![semantic::ValueId(0)],
                    statements: vec![semantic::SemanticStatement::Return(Vec::new())],
                },
                effects: semantic::EffectSet(
                    semantic::EffectSet::TASK_SPAWN | semantic::EffectSet::SUSPEND,
                ),
                proofs: vec![
                    semantic::ProofId(0),
                    semantic::ProofId(1),
                    semantic::ProofId(5),
                    semantic::ProofId(7),
                ],
                source: Some(task_source),
                stack_bound: 8,
                frame_bound: 16,
                uninterrupted_bound: Some(1),
                recursive_depth_bound: Some(1),
            },
            semantic::SemanticFunction {
                id: semantic::FunctionId(3),
                instance_key: Sha256Digest::from_bytes([0x73; 32]),
                name: "__wrela_image_entry".to_owned(),
                origin: semantic::FunctionOrigin::GeneratedImageEntry { constructor: 7 },
                role: semantic::FunctionRole::ImageEntry,
                color: semantic::FunctionColor::Sync,
                parameters: Vec::new(),
                result: semantic::TypeId(0),
                values: Vec::new(),
                body: semantic::SemanticRegion {
                    parameters: Vec::new(),
                    statements: vec![semantic::SemanticStatement::Return(Vec::new())],
                },
                effects: semantic::EffectSet(
                    semantic::EffectSet::FIRMWARE
                        | semantic::EffectSet::ACTOR_CALL
                        | semantic::EffectSet::TASK_SPAWN,
                ),
                proofs: vec![
                    semantic::ProofId(2),
                    semantic::ProofId(3),
                    semantic::ProofId(4),
                    semantic::ProofId(7),
                    semantic::ProofId(9),
                ],
                source: None,
                stack_bound: 0,
                frame_bound: 0,
                uninterrupted_bound: Some(1),
                recursive_depth_bound: Some(1),
            },
        ];
        module.actors = vec![semantic::ActorInstance {
            id: semantic::ActorId(0),
            name: "Worker".to_owned(),
            ty: semantic::TypeId(2),
            priority: 1,
            mailbox_capacity: 2,
            message_types: vec![semantic::TypeId(4)],
            turn_functions: vec![semantic::FunctionId(1)],
            supervisor: None,
        }];
        module.tasks = vec![semantic::TaskInstance {
            id: semantic::TaskId(0),
            name: "Worker.pulse".to_owned(),
            entry: semantic::FunctionId(2),
            slots: 1,
            priority: 1,
            supervisor: Some(semantic::ActorId(0)),
        }];
        module.regions = vec![
            semantic::RegionRecord {
                id: semantic::RegionId(0),
                name: "Worker.mailbox".to_owned(),
                class: semantic::RegionClass::Image,
                capacity_bytes: 32,
                alignment: 8,
                owner: semantic::ImageOwner::Actor(semantic::ActorId(0)),
                proof: semantic::ProofId(2),
                source: turn_source,
            },
            semantic::RegionRecord {
                id: semantic::RegionId(1),
                name: "Worker.turn-frame".to_owned(),
                class: semantic::RegionClass::TaskFrame,
                capacity_bytes: 16,
                alignment: 8,
                owner: semantic::ImageOwner::Actor(semantic::ActorId(0)),
                proof: semantic::ProofId(3),
                source: turn_source,
            },
            semantic::RegionRecord {
                id: semantic::RegionId(2),
                name: "Worker.pulse.frame".to_owned(),
                class: semantic::RegionClass::TaskFrame,
                capacity_bytes: 16,
                alignment: 8,
                owner: semantic::ImageOwner::Task(semantic::TaskId(0)),
                proof: semantic::ProofId(4),
                source: task_source,
            },
        ];
        module.startup_order = vec![
            semantic::ImageOwner::Runtime,
            semantic::ImageOwner::Actor(semantic::ActorId(0)),
            semantic::ImageOwner::Task(semantic::TaskId(0)),
        ];
        module.shutdown_order = vec![
            semantic::ImageOwner::Task(semantic::TaskId(0)),
            semantic::ImageOwner::Actor(semantic::ActorId(0)),
            semantic::ImageOwner::Runtime,
        ];
        module.image_entry = semantic::FunctionId(3);
        module.static_bytes = 64;
        module.peak_bytes = 64;
        module
            .validate()
            .expect("valid producer-shaped stateless actor SemanticWir")
    }

    fn actor_state_fixture() -> semantic::ValidatedSemanticWir {
        let mut module = actor_fixture().into_wir();
        let state_source = span(0, 45, 49);
        let mut closed = module.proofs.pop().expect("closed actor proof");
        assert_eq!(closed.id, semantic::ProofId(9));
        module.proofs.push(semantic::ProofRecord {
            id: semantic::ProofId(9),
            kind: semantic::ProofKind::CapacityBound,
            subject: "actor state: Worker".to_owned(),
            bound: Some(1),
            sources: vec![state_source],
            depends_on: Vec::new(),
            explanation: vec!["one canonical zero u64 actor state cell".to_owned()],
        });
        closed.id = semantic::ProofId(10);
        closed.bound = Some(72);
        closed.depends_on.push(semantic::ProofId(9));
        closed.depends_on.sort_unstable();
        module.proofs.push(closed);
        let entry = &mut module.functions[3];
        entry.proofs.retain(|proof| *proof != semantic::ProofId(9));
        entry
            .proofs
            .extend([semantic::ProofId(9), semantic::ProofId(10)]);
        entry.proofs.sort_unstable();
        module.regions.insert(
            1,
            semantic::RegionRecord {
                id: semantic::RegionId(1),
                name: "Worker.state".to_owned(),
                class: semantic::RegionClass::Image,
                capacity_bytes: 8,
                alignment: 8,
                owner: semantic::ImageOwner::Actor(semantic::ActorId(0)),
                proof: semantic::ProofId(9),
                source: state_source,
            },
        );
        for (index, region) in module.regions.iter_mut().enumerate() {
            region.id = semantic::RegionId(u32::try_from(index).expect("region id"));
        }
        module.static_bytes = 72;
        module.peak_bytes = 72;
        module
            .validate()
            .expect("valid producer-shaped actor state SemanticWir")
    }

    fn actor_async_fixture() -> semantic::ValidatedSemanticWir {
        let mut module = actor_fixture().into_wir();
        let helper = &mut module.functions[0];
        helper.color = semantic::FunctionColor::Async;
        helper.effects = semantic::EffectSet(semantic::EffectSet::SUSPEND);
        helper.parameters.clear();
        helper.result = semantic::TypeId(0);
        helper.values.clear();
        helper.body.parameters.clear();
        helper.body.statements = vec![semantic::SemanticStatement::Return(Vec::new())];
        helper.frame_bound = 16;
        helper.proofs.push(semantic::ProofId(8));
        let turn = &mut module.functions[1];
        turn.values.truncate(1);
        turn.values.push(semantic::SemanticValue {
            id: semantic::ValueId(1),
            ty: semantic::TypeId(0),
            origin: Some(span(0, 82, 91)),
            name: None,
        });
        turn.values.push(semantic::SemanticValue {
            id: semantic::ValueId(2),
            ty: semantic::TypeId(0),
            origin: Some(span(0, 82, 97)),
            name: None,
        });
        turn.body.statements = vec![
            semantic::SemanticStatement::Let(semantic::LetStatement {
                results: vec![semantic::ValueId(1)],
                operation: semantic::SemanticOperation::Call {
                    function: semantic::FunctionId(0),
                    arguments: Vec::new(),
                    activation: Some(semantic::ActivationId(0)),
                },
                source: Some(span(0, 82, 91)),
            }),
            semantic::SemanticStatement::Let(semantic::LetStatement {
                results: vec![semantic::ValueId(2)],
                operation: semantic::SemanticOperation::Await {
                    awaitable: semantic::ValueId(1),
                },
                source: Some(span(0, 82, 97)),
            }),
            semantic::SemanticStatement::Return(Vec::new()),
        ];
        turn.effects =
            semantic::EffectSet(semantic::EffectSet::ACTOR_CALL | semantic::EffectSet::SUSPEND);
        turn.proofs.push(semantic::ProofId(10));
        let activation_source = span(0, 82, 91);
        module.proofs[9].kind = semantic::ProofKind::CapacityBound;
        module.proofs.push(semantic::ProofRecord {
            id: semantic::ProofId(10),
            kind: semantic::ProofKind::CapacityBound,
            subject: "async helper activation".to_owned(),
            bound: Some(1),
            sources: vec![activation_source],
            depends_on: vec![semantic::ProofId(8)],
            explanation: vec!["one immediate helper activation".to_owned()],
        });
        module.proofs.push(semantic::ProofRecord {
            id: semantic::ProofId(11),
            kind: semantic::ProofKind::ImageClosed,
            subject: "closed actor image with activation".to_owned(),
            bound: Some(80),
            sources: vec![activation_source],
            depends_on: vec![semantic::ProofId(9), semantic::ProofId(10)],
            explanation: vec!["base image plus helper activation".to_owned()],
        });
        module.functions[3].proofs.push(semantic::ProofId(11));
        module.regions.push(semantic::RegionRecord {
            id: semantic::RegionId(3),
            name: "Worker.ping.async-activation-frame".to_owned(),
            class: semantic::RegionClass::TaskFrame,
            capacity_bytes: 16,
            alignment: 8,
            owner: semantic::ImageOwner::Actor(semantic::ActorId(0)),
            proof: semantic::ProofId(10),
            source: activation_source,
        });
        module.activations.push(semantic::ActivationPlan {
            id: semantic::ActivationId(0),
            caller: semantic::FunctionId(1),
            callee: semantic::FunctionId(0),
            region: semantic::RegionId(3),
            frame_bytes: 16,
            maximum_live: 1,
            cancellation: semantic::ActivationCancellation::DropCalleeThenPropagate,
            capacity_proof: semantic::ProofId(10),
            source: activation_source,
        });
        module.static_bytes = 80;
        module.peak_bytes = 80;
        module
            .validate()
            .expect("valid real-producer-shaped unit async activation")
    }

    fn actor_async_value_fixture() -> semantic::ValidatedSemanticWir {
        let mut module = actor_async_fixture().into_wir();
        let helper = &mut module.functions[0];
        helper.result = semantic::TypeId(1);
        helper.values = vec![semantic::SemanticValue {
            id: semantic::ValueId(0),
            ty: semantic::TypeId(1),
            origin: Some(span(0, 30, 35)),
            name: None,
        }];
        helper.body.statements = vec![
            semantic::SemanticStatement::Let(semantic::LetStatement {
                results: vec![semantic::ValueId(0)],
                operation: semantic::SemanticOperation::Constant(semantic::Constant::Unsigned {
                    bits: 32,
                    value: 7,
                }),
                source: Some(span(0, 30, 35)),
            }),
            semantic::SemanticStatement::Return(vec![semantic::ValueId(0)]),
        ];
        let turn = &mut module.functions[1];
        turn.values[1].ty = semantic::TypeId(1);
        turn.values[2].ty = semantic::TypeId(1);
        module
            .validate()
            .expect("valid real-producer-shaped value async activation")
    }

    fn actor_two_await_fixture() -> semantic::ValidatedSemanticWir {
        let mut module = actor_async_fixture().into_wir();
        let turn = &mut module.functions[1];
        for (id, source) in [(3, span(0, 98, 103)), (4, span(0, 104, 109))] {
            turn.values.push(semantic::SemanticValue {
                id: semantic::ValueId(id),
                ty: semantic::TypeId(0),
                origin: Some(source),
                name: None,
            });
        }
        turn.body.statements.insert(
            2,
            semantic::SemanticStatement::Let(semantic::LetStatement {
                results: vec![semantic::ValueId(3)],
                operation: semantic::SemanticOperation::Call {
                    function: semantic::FunctionId(0),
                    arguments: Vec::new(),
                    activation: Some(semantic::ActivationId(1)),
                },
                source: Some(span(0, 98, 103)),
            }),
        );
        turn.body.statements.insert(
            3,
            semantic::SemanticStatement::Let(semantic::LetStatement {
                results: vec![semantic::ValueId(4)],
                operation: semantic::SemanticOperation::Await {
                    awaitable: semantic::ValueId(3),
                },
                source: Some(span(0, 104, 109)),
            }),
        );
        let removed = module.proofs.pop().expect("first activation closure proof");
        assert_eq!(removed.id, semantic::ProofId(11));
        module.functions[3].proofs.pop();
        module.functions[1].proofs.push(semantic::ProofId(11));
        let second_source = span(0, 98, 103);
        module.proofs.push(semantic::ProofRecord {
            id: semantic::ProofId(11),
            kind: semantic::ProofKind::CapacityBound,
            subject: "second async helper activation".to_owned(),
            bound: Some(1),
            sources: vec![second_source],
            depends_on: vec![semantic::ProofId(8)],
            explanation: vec!["one second immediate helper activation".to_owned()],
        });
        module.proofs.push(semantic::ProofRecord {
            id: semantic::ProofId(12),
            kind: semantic::ProofKind::ImageClosed,
            subject: "closed actor image with two activations".to_owned(),
            bound: Some(96),
            sources: vec![span(0, 82, 91), second_source],
            depends_on: vec![
                semantic::ProofId(9),
                semantic::ProofId(10),
                semantic::ProofId(11),
            ],
            explanation: vec!["base image plus two helper activations".to_owned()],
        });
        module.functions[3].proofs.push(semantic::ProofId(12));
        module.regions.push(semantic::RegionRecord {
            id: semantic::RegionId(4),
            name: "Worker.ping.async-activation-frame".to_owned(),
            class: semantic::RegionClass::TaskFrame,
            capacity_bytes: 16,
            alignment: 8,
            owner: semantic::ImageOwner::Actor(semantic::ActorId(0)),
            proof: semantic::ProofId(11),
            source: second_source,
        });
        module.activations.push(semantic::ActivationPlan {
            id: semantic::ActivationId(1),
            caller: semantic::FunctionId(1),
            callee: semantic::FunctionId(0),
            region: semantic::RegionId(4),
            frame_bytes: 16,
            maximum_live: 1,
            cancellation: semantic::ActivationCancellation::DropCalleeThenPropagate,
            capacity_proof: semantic::ProofId(11),
            source: second_source,
        });
        module.static_bytes = 96;
        module.peak_bytes = 96;
        module
            .validate()
            .expect("valid producer-shaped two-await SemanticWir")
    }

    fn generated_fixture() -> semantic::ValidatedSemanticWir {
        let first_source = span(0, 10, 20);
        let second_source = span(1, 30, 40);
        let tests = [
            ("passes_one", first_source, [0u32, 1u32]),
            ("passes_two", second_source, [2u32, 3u32]),
        ];
        let mut functions = Vec::new();
        for (id, (name, source, proofs)) in tests.iter().enumerate() {
            functions.push(semantic::SemanticFunction {
                id: semantic::FunctionId(id as u32),
                instance_key: Sha256Digest::from_bytes([0x60 + id as u8; 32]),
                name: (*name).to_owned(),
                origin: semantic::FunctionOrigin::Source,
                role: semantic::FunctionRole::Test,
                color: semantic::FunctionColor::Sync,
                parameters: Vec::new(),
                result: semantic::TypeId(0),
                values: Vec::new(),
                body: semantic::SemanticRegion {
                    parameters: Vec::new(),
                    statements: vec![semantic::SemanticStatement::Return(Vec::new())],
                },
                effects: semantic::EffectSet::default(),
                proofs: proofs.iter().copied().map(semantic::ProofId).collect(),
                source: Some(*source),
                stack_bound: 0,
                frame_bound: 0,
                uninterrupted_bound: Some(1 + id as u64),
                recursive_depth_bound: Some(1),
            });
        }
        let mut values = Vec::new();
        let mut statements = Vec::new();
        let frames = canonical_passing_frames(&[12, 13]);
        let mut frame_index = 0u32;
        let mut append_frame =
            |bytes: Vec<u8>,
             values: &mut Vec<semantic::SemanticValue>,
             statements: &mut Vec<semantic::SemanticStatement>| {
                let value = semantic::ValueId(frame_index);
                frame_index += 1;
                let ty = match bytes.len() {
                    49 => semantic::TypeId(3),
                    50 => semantic::TypeId(4),
                    53 => semantic::TypeId(5),
                    _ => panic!("unexpected generated passing frame extent"),
                };
                values.push(semantic::SemanticValue {
                    id: value,
                    ty,
                    origin: None,
                    name: None,
                });
                statements.push(semantic::SemanticStatement::Let(semantic::LetStatement {
                    results: vec![value],
                    operation: semantic::SemanticOperation::Constant(semantic::Constant::Bytes(
                        bytes,
                    )),
                    source: None,
                }));
                statements.push(semantic::SemanticStatement::Let(semantic::LetStatement {
                    results: Vec::new(),
                    operation: semantic::SemanticOperation::TestEmit { payload: value },
                    source: None,
                }));
            };
        append_frame(frames[0].clone(), &mut values, &mut statements);
        for (id, (_, source, _)) in tests.iter().enumerate() {
            append_frame(frames[id * 2 + 1].clone(), &mut values, &mut statements);
            statements.push(semantic::SemanticStatement::Let(semantic::LetStatement {
                results: Vec::new(),
                operation: semantic::SemanticOperation::Call {
                    function: semantic::FunctionId(id as u32),
                    arguments: Vec::new(),
                    activation: None,
                },
                source: Some(*source),
            }));
            append_frame(frames[id * 2 + 2].clone(), &mut values, &mut statements);
        }
        append_frame(frames[5].clone(), &mut values, &mut statements);
        let outcome = semantic::ValueId(frame_index);
        values.push(semantic::SemanticValue {
            id: outcome,
            ty: semantic::TypeId(2),
            origin: None,
            name: None,
        });
        statements.push(semantic::SemanticStatement::Let(semantic::LetStatement {
            results: vec![outcome],
            operation: semantic::SemanticOperation::Constant(semantic::Constant::Unsigned {
                bits: 32,
                value: 0,
            }),
            source: None,
        }));
        statements.push(semantic::SemanticStatement::Let(semantic::LetStatement {
            results: Vec::new(),
            operation: semantic::SemanticOperation::TestFinish { outcome },
            source: None,
        }));
        statements.push(semantic::SemanticStatement::Unreachable);
        functions.push(semantic::SemanticFunction {
            id: semantic::FunctionId(2),
            instance_key: Sha256Digest::from_bytes([0x62; 32]),
            name: "__wrela_test_entry".to_owned(),
            origin: semantic::FunctionOrigin::GeneratedTestHarness { group: 9 },
            role: semantic::FunctionRole::ImageEntry,
            color: semantic::FunctionColor::Sync,
            parameters: Vec::new(),
            result: semantic::TypeId(0),
            values,
            body: semantic::SemanticRegion {
                parameters: Vec::new(),
                statements,
            },
            effects: semantic::EffectSet(semantic::EffectSet::FIRMWARE),
            proofs: vec![
                semantic::ProofId(4),
                semantic::ProofId(5),
                semantic::ProofId(6),
            ],
            source: None,
            stack_bound: 0,
            frame_bound: 0,
            uninterrupted_bound: Some(11),
            recursive_depth_bound: Some(1),
        });
        semantic::SemanticWir {
            version: semantic::SEMANTIC_WIR_VERSION,
            name: "__wrela_test_harness".to_owned(),
            build: build(),
            source_summary: semantic::SourceSummary {
                hir_files: 2,
                hir_declarations: 8,
                reachable_declarations: 2,
                monomorphized_instantiations: 3,
                resolved_interface_calls: 0,
            },
            types: vec![
                semantic::TypeRecord {
                    id: semantic::TypeId(0),
                    source_name: "unit".to_owned(),
                    kind: semantic::TypeKind::Primitive(semantic::PrimitiveType::Unit),
                    linearity: semantic::Linearity::CopyScalar,
                    source: None,
                },
                semantic::TypeRecord {
                    id: semantic::TypeId(1),
                    source_name: "__wrela_test_byte".to_owned(),
                    kind: semantic::TypeKind::Primitive(semantic::PrimitiveType::U8),
                    linearity: semantic::Linearity::CopyScalar,
                    source: None,
                },
                semantic::TypeRecord {
                    id: semantic::TypeId(2),
                    source_name: "__wrela_test_outcome".to_owned(),
                    kind: semantic::TypeKind::Primitive(semantic::PrimitiveType::U32),
                    linearity: semantic::Linearity::CopyScalar,
                    source: None,
                },
                semantic::TypeRecord {
                    id: semantic::TypeId(3),
                    source_name: "__wrela_test_frame_49".to_owned(),
                    kind: semantic::TypeKind::Array {
                        element: semantic::TypeId(1),
                        length: 49,
                    },
                    linearity: semantic::Linearity::ExplicitCopy,
                    source: None,
                },
                semantic::TypeRecord {
                    id: semantic::TypeId(4),
                    source_name: "__wrela_test_frame_50".to_owned(),
                    kind: semantic::TypeKind::Array {
                        element: semantic::TypeId(1),
                        length: 50,
                    },
                    linearity: semantic::Linearity::ExplicitCopy,
                    source: None,
                },
                semantic::TypeRecord {
                    id: semantic::TypeId(5),
                    source_name: "__wrela_test_frame_53".to_owned(),
                    kind: semantic::TypeKind::Array {
                        element: semantic::TypeId(1),
                        length: 53,
                    },
                    linearity: semantic::Linearity::ExplicitCopy,
                    source: None,
                },
            ],
            globals: Vec::new(),
            functions,
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
                proof(2, semantic::ProofKind::TypeChecked, &[], None),
                proof(3, semantic::ProofKind::EffectsAllowed, &[2], Some(1)),
                proof(4, semantic::ProofKind::TypeChecked, &[], Some(2)),
                proof(5, semantic::ProofKind::EffectsAllowed, &[4], Some(6)),
                proof(6, semantic::ProofKind::ImageClosed, &[4, 5], Some(2)),
            ],
            tests: vec![
                semantic::TestEntry {
                    id: semantic::TestId(0),
                    plan_id: 12,
                    name: "passes_one".to_owned(),
                    function: semantic::FunctionId(0),
                    kind: semantic::TestKind::Integration,
                    source: first_source,
                    timeout_ns: 1_000_000,
                },
                semantic::TestEntry {
                    id: semantic::TestId(1),
                    plan_id: 13,
                    name: "passes_two".to_owned(),
                    function: semantic::FunctionId(1),
                    kind: semantic::TestKind::Integration,
                    source: second_source,
                    timeout_ns: 2_000_000,
                },
            ],
            compiled_test_group: Some(wrela_test_model::FullImageTestGroup {
                id: wrela_test_model::ImageGroupId(9),
                name: "integration".to_owned(),
                root: wrela_test_model::ImageRoot::GeneratedHarness {
                    harness_name: "__wrela_test_harness".to_owned(),
                },
                tests: vec![
                    wrela_test_model::ImageTest {
                        descriptor: wrela_test_model::TestDescriptor {
                            id: wrela_test_model::TestId(12),
                            name: "passes_one".to_owned(),
                            kind: wrela_test_model::TestKind::IntegrationImage,
                            source: Some(first_source),
                            timeout_ns: 1_000_000,
                        },
                        invocation: wrela_test_model::ImageTestInvocation::GeneratedFunction {
                            function_key: wrela_test_model::FunctionKey(Sha256Digest::from_bytes(
                                [0x60; 32],
                            )),
                        },
                        assertions: Vec::new(),
                    },
                    wrela_test_model::ImageTest {
                        descriptor: wrela_test_model::TestDescriptor {
                            id: wrela_test_model::TestId(13),
                            name: "passes_two".to_owned(),
                            kind: wrela_test_model::TestKind::IntegrationImage,
                            source: Some(second_source),
                            timeout_ns: 2_000_000,
                        },
                        invocation: wrela_test_model::ImageTestInvocation::GeneratedFunction {
                            function_key: wrela_test_model::FunctionKey(Sha256Digest::from_bytes(
                                [0x61; 32],
                            )),
                        },
                        assertions: Vec::new(),
                    },
                ],
                deterministic_seed: None,
                boot_timeout_ns: 1,
                shutdown_timeout_ns: 1,
                maximum_events: 7,
                maximum_output_bytes: 1,
            }),
            startup_order: vec![semantic::ImageOwner::Runtime],
            shutdown_order: vec![semantic::ImageOwner::Runtime],
            image_entry: semantic::FunctionId(2),
            static_bytes: 0,
            peak_bytes: 0,
        }
        .validate()
        .expect("valid generated-test SemanticWir")
    }

    fn scalar_generated_fixture() -> semantic::ValidatedSemanticWir {
        let mut module = generated_fixture().into_wir();
        let test_source = module.tests[0].source;
        let helper_source = span(0, 170, 209);
        module.types = vec![
            semantic::TypeRecord {
                id: semantic::TypeId(0),
                source_name: "unit".to_owned(),
                kind: semantic::TypeKind::Primitive(semantic::PrimitiveType::Unit),
                linearity: semantic::Linearity::CopyScalar,
                source: None,
            },
            semantic::TypeRecord {
                id: semantic::TypeId(1),
                source_name: "bool".to_owned(),
                kind: semantic::TypeKind::Primitive(semantic::PrimitiveType::Bool),
                linearity: semantic::Linearity::CopyScalar,
                source: Some(span(0, 230, 234)),
            },
            semantic::TypeRecord {
                id: semantic::TypeId(2),
                source_name: "u32".to_owned(),
                kind: semantic::TypeKind::Primitive(semantic::PrimitiveType::U32),
                linearity: semantic::Linearity::CopyScalar,
                source: Some(span(0, 176, 179)),
            },
            semantic::TypeRecord {
                id: semantic::TypeId(3),
                source_name: "fn".to_owned(),
                kind: semantic::TypeKind::Function(semantic::FunctionType {
                    color: semantic::FunctionColor::Sync,
                    parameters: vec![
                        semantic::ParameterType {
                            access: semantic::AccessMode::Read,
                            ty: semantic::TypeId(2),
                        },
                        semantic::ParameterType {
                            access: semantic::AccessMode::Read,
                            ty: semantic::TypeId(2),
                        },
                    ],
                    result: semantic::TypeId(2),
                }),
                linearity: semantic::Linearity::CopyScalar,
                source: Some(helper_source),
            },
            semantic::TypeRecord {
                id: semantic::TypeId(4),
                source_name: "__wrela_test_byte".to_owned(),
                kind: semantic::TypeKind::Primitive(semantic::PrimitiveType::U8),
                linearity: semantic::Linearity::CopyScalar,
                source: None,
            },
            semantic::TypeRecord {
                id: semantic::TypeId(5),
                source_name: "__wrela_test_frame_49".to_owned(),
                kind: semantic::TypeKind::Array {
                    element: semantic::TypeId(4),
                    length: 49,
                },
                linearity: semantic::Linearity::ExplicitCopy,
                source: None,
            },
            semantic::TypeRecord {
                id: semantic::TypeId(6),
                source_name: "__wrela_test_frame_50".to_owned(),
                kind: semantic::TypeKind::Array {
                    element: semantic::TypeId(4),
                    length: 50,
                },
                linearity: semantic::Linearity::ExplicitCopy,
                source: None,
            },
            semantic::TypeRecord {
                id: semantic::TypeId(7),
                source_name: "__wrela_test_frame_53".to_owned(),
                kind: semantic::TypeKind::Array {
                    element: semantic::TypeId(4),
                    length: 53,
                },
                linearity: semantic::Linearity::ExplicitCopy,
                source: None,
            },
        ];

        module.functions[0] = semantic::SemanticFunction {
            id: semantic::FunctionId(0),
            instance_key: Sha256Digest::from_bytes([0x60; 32]),
            name: module.tests[0].name.clone(),
            origin: semantic::FunctionOrigin::Source,
            role: semantic::FunctionRole::Test,
            color: semantic::FunctionColor::Sync,
            parameters: Vec::new(),
            result: semantic::TypeId(0),
            values: vec![
                semantic::SemanticValue {
                    id: semantic::ValueId(0),
                    ty: semantic::TypeId(1),
                    origin: Some(span(0, 238, 242)),
                    name: Some("flag".to_owned()),
                },
                semantic::SemanticValue {
                    id: semantic::ValueId(1),
                    ty: semantic::TypeId(2),
                    origin: Some(span(0, 254, 255)),
                    name: Some("number".to_owned()),
                },
                semantic::SemanticValue {
                    id: semantic::ValueId(2),
                    ty: semantic::TypeId(2),
                    origin: Some(span(0, 268, 269)),
                    name: Some("other".to_owned()),
                },
                semantic::SemanticValue {
                    id: semantic::ValueId(3),
                    ty: semantic::TypeId(2),
                    origin: Some(span(0, 315, 345)),
                    name: None,
                },
            ],
            body: semantic::SemanticRegion {
                parameters: Vec::new(),
                statements: vec![
                    semantic::SemanticStatement::Let(semantic::LetStatement {
                        results: vec![semantic::ValueId(0)],
                        operation: semantic::SemanticOperation::Constant(semantic::Constant::Bool(
                            true,
                        )),
                        source: Some(span(0, 238, 242)),
                    }),
                    semantic::SemanticStatement::Let(semantic::LetStatement {
                        results: vec![semantic::ValueId(1)],
                        operation: semantic::SemanticOperation::Constant(
                            semantic::Constant::Unsigned { bits: 32, value: 7 },
                        ),
                        source: Some(span(0, 254, 255)),
                    }),
                    semantic::SemanticStatement::Let(semantic::LetStatement {
                        results: vec![semantic::ValueId(2)],
                        operation: semantic::SemanticOperation::Constant(
                            semantic::Constant::Unsigned { bits: 32, value: 9 },
                        ),
                        source: Some(span(0, 268, 269)),
                    }),
                    semantic::SemanticStatement::If {
                        condition: semantic::ValueId(0),
                        then_region: semantic::SemanticRegion {
                            parameters: Vec::new(),
                            statements: vec![semantic::SemanticStatement::Let(
                                semantic::LetStatement {
                                    results: vec![semantic::ValueId(3)],
                                    operation: semantic::SemanticOperation::Call {
                                        function: semantic::FunctionId(1),
                                        arguments: vec![
                                            semantic::Argument {
                                                access: semantic::AccessMode::Read,
                                                value: semantic::ValueId(1),
                                            },
                                            semantic::Argument {
                                                access: semantic::AccessMode::Read,
                                                value: semantic::ValueId(2),
                                            },
                                        ],
                                        activation: None,
                                    },
                                    source: Some(span(0, 315, 345)),
                                },
                            )],
                        },
                        else_region: semantic::SemanticRegion::default(),
                        results: Vec::new(),
                        source: Some(span(0, 270, 350)),
                    },
                    semantic::SemanticStatement::Return(Vec::new()),
                ],
            },
            effects: semantic::EffectSet::default(),
            proofs: vec![semantic::ProofId(0), semantic::ProofId(1)],
            source: Some(test_source),
            stack_bound: 4,
            frame_bound: 2,
            uninterrupted_bound: Some(5),
            recursive_depth_bound: Some(1),
        };
        module.functions[1] = semantic::SemanticFunction {
            id: semantic::FunctionId(1),
            instance_key: Sha256Digest::from_bytes([0x61; 32]),
            name: "helper".to_owned(),
            origin: semantic::FunctionOrigin::Source,
            role: semantic::FunctionRole::Ordinary,
            color: semantic::FunctionColor::Sync,
            parameters: vec![semantic::ValueId(0), semantic::ValueId(1)],
            result: semantic::TypeId(2),
            values: vec![
                semantic::SemanticValue {
                    id: semantic::ValueId(0),
                    ty: semantic::TypeId(2),
                    origin: Some(span(0, 174, 179)),
                    name: Some("x".to_owned()),
                },
                semantic::SemanticValue {
                    id: semantic::ValueId(1),
                    ty: semantic::TypeId(2),
                    origin: Some(span(0, 180, 185)),
                    name: Some("y".to_owned()),
                },
                semantic::SemanticValue {
                    id: semantic::ValueId(2),
                    ty: semantic::TypeId(2),
                    origin: Some(span(0, 194, 201)),
                    name: Some("copied".to_owned()),
                },
            ],
            body: semantic::SemanticRegion {
                parameters: vec![semantic::ValueId(0), semantic::ValueId(1)],
                statements: vec![
                    semantic::SemanticStatement::Let(semantic::LetStatement {
                        results: vec![semantic::ValueId(2)],
                        operation: semantic::SemanticOperation::Copy {
                            value: semantic::ValueId(0),
                        },
                        source: Some(span(0, 194, 201)),
                    }),
                    semantic::SemanticStatement::Return(vec![semantic::ValueId(2)]),
                ],
            },
            effects: semantic::EffectSet::default(),
            proofs: vec![semantic::ProofId(2), semantic::ProofId(3)],
            source: Some(helper_source),
            stack_bound: 8,
            frame_bound: 4,
            uninterrupted_bound: Some(2),
            recursive_depth_bound: Some(1),
        };

        let harness = &mut module.functions[2];
        harness.values.clear();
        harness.body.statements.clear();
        for (marker, bytes) in canonical_passing_frames(&[12]).into_iter().enumerate() {
            let marker = u8::try_from(marker).expect("four generated passing frames");
            let value = semantic::ValueId(u32::from(marker));
            let frame_type = match bytes.len() {
                49 => semantic::TypeId(5),
                50 => semantic::TypeId(6),
                53 => semantic::TypeId(7),
                _ => panic!("unexpected generated passing frame extent"),
            };
            harness.values.push(semantic::SemanticValue {
                id: value,
                ty: frame_type,
                origin: None,
                name: None,
            });
            harness
                .body
                .statements
                .push(semantic::SemanticStatement::Let(semantic::LetStatement {
                    results: vec![value],
                    operation: semantic::SemanticOperation::Constant(semantic::Constant::Bytes(
                        bytes,
                    )),
                    source: None,
                }));
            harness
                .body
                .statements
                .push(semantic::SemanticStatement::Let(semantic::LetStatement {
                    results: Vec::new(),
                    operation: semantic::SemanticOperation::TestEmit { payload: value },
                    source: None,
                }));
            if marker == 1 {
                harness
                    .body
                    .statements
                    .push(semantic::SemanticStatement::Let(semantic::LetStatement {
                        results: Vec::new(),
                        operation: semantic::SemanticOperation::Call {
                            function: semantic::FunctionId(0),
                            arguments: Vec::new(),
                            activation: None,
                        },
                        source: Some(test_source),
                    }));
            }
        }
        let outcome = semantic::ValueId(4);
        harness.values.push(semantic::SemanticValue {
            id: outcome,
            ty: semantic::TypeId(2),
            origin: None,
            name: None,
        });
        harness.body.statements.extend([
            semantic::SemanticStatement::Let(semantic::LetStatement {
                results: vec![outcome],
                operation: semantic::SemanticOperation::Constant(semantic::Constant::Unsigned {
                    bits: 32,
                    value: 0,
                }),
                source: None,
            }),
            semantic::SemanticStatement::Let(semantic::LetStatement {
                results: Vec::new(),
                operation: semantic::SemanticOperation::TestFinish { outcome },
                source: None,
            }),
            semantic::SemanticStatement::Unreachable,
        ]);
        harness.uninterrupted_bound = Some(10);

        module.tests.truncate(1);
        let group = module
            .compiled_test_group
            .as_mut()
            .expect("generated group binding");
        group.tests.truncate(1);
        group.maximum_events = 5;
        module
            .validate()
            .expect("valid exact scalar generated-test SemanticWir")
    }

    fn scalar_unit_call_fixture() -> semantic::ValidatedSemanticWir {
        let mut module = scalar_generated_fixture().into_wir();
        let semantic::TypeKind::Function(signature) = &mut module.types[3].kind else {
            panic!("scalar helper function type");
        };
        signature.result = semantic::TypeId(0);
        module.functions[0].values[3].ty = semantic::TypeId(0);
        module.functions[1].result = semantic::TypeId(0);
        module.functions[1].body.statements[1] = semantic::SemanticStatement::Return(Vec::new());
        module
            .validate()
            .expect("valid producer-shaped explicit unit-result call")
    }

    fn scalar_chained_call_fixture() -> semantic::ValidatedSemanticWir {
        let mut module = scalar_generated_fixture().into_wir();
        let source = span(0, 346, 376);
        let caller = &mut module.functions[0];
        caller.values.push(semantic::SemanticValue {
            id: semantic::ValueId(4),
            ty: semantic::TypeId(2),
            origin: Some(source),
            name: Some("chained".to_owned()),
        });
        let semantic::SemanticStatement::If { then_region, .. } = &mut caller.body.statements[3]
        else {
            panic!("scalar branch");
        };
        then_region
            .statements
            .push(semantic::SemanticStatement::Let(semantic::LetStatement {
                results: vec![semantic::ValueId(4)],
                operation: semantic::SemanticOperation::Call {
                    function: semantic::FunctionId(1),
                    arguments: vec![
                        semantic::Argument {
                            access: semantic::AccessMode::Read,
                            value: semantic::ValueId(3),
                        },
                        semantic::Argument {
                            access: semantic::AccessMode::Read,
                            value: semantic::ValueId(2),
                        },
                    ],
                    activation: None,
                },
                source: Some(source),
            }));
        module
            .validate()
            .expect("valid producer-shaped chained scalar calls")
    }

    fn scalar_branch_call_mut(module: &mut semantic::SemanticWir) -> &mut semantic::LetStatement {
        let semantic::SemanticStatement::If { then_region, .. } =
            &mut module.functions[0].body.statements[3]
        else {
            panic!("scalar branch");
        };
        let semantic::SemanticStatement::Let(call) = &mut then_region.statements[0] else {
            panic!("scalar call");
        };
        call
    }

    fn scalar_source_value(id: u32, ty: u32, name: &str, source: Span) -> semantic::SemanticValue {
        semantic::SemanticValue {
            id: semantic::ValueId(id),
            ty: semantic::TypeId(ty),
            origin: Some(source),
            name: Some(name.to_owned()),
        }
    }

    fn scalar_source_let(
        result: u32,
        operation: semantic::SemanticOperation,
        source: Span,
    ) -> semantic::SemanticStatement {
        semantic::SemanticStatement::Let(semantic::LetStatement {
            results: vec![semantic::ValueId(result)],
            operation,
            source: Some(source),
        })
    }

    fn scalar_nested_join_fixture() -> semantic::ValidatedSemanticWir {
        let mut module = scalar_generated_fixture().into_wir();
        let function = &mut module.functions[0];
        function.values.extend([
            scalar_source_value(4, 2, "inner_else", span(0, 300, 305)),
            scalar_source_value(5, 2, "inner_join", span(0, 300, 345)),
            scalar_source_value(6, 2, "outer_else", span(0, 346, 349)),
            scalar_source_value(7, 2, "outer_join", span(0, 270, 350)),
        ]);
        let semantic::SemanticStatement::If {
            then_region,
            else_region,
            results,
            ..
        } = &mut function.body.statements[3]
        else {
            panic!("scalar outer branch");
        };
        let call = then_region
            .statements
            .pop()
            .expect("existing scalar branch call");
        assert!(then_region.statements.is_empty());
        then_region.statements = vec![
            semantic::SemanticStatement::If {
                condition: semantic::ValueId(0),
                then_region: semantic::SemanticRegion {
                    parameters: Vec::new(),
                    statements: vec![
                        call,
                        semantic::SemanticStatement::Yield(vec![semantic::ValueId(3)]),
                    ],
                },
                else_region: semantic::SemanticRegion {
                    parameters: Vec::new(),
                    statements: vec![
                        scalar_source_let(
                            4,
                            semantic::SemanticOperation::Copy {
                                value: semantic::ValueId(2),
                            },
                            span(0, 300, 305),
                        ),
                        semantic::SemanticStatement::Yield(vec![semantic::ValueId(4)]),
                    ],
                },
                results: vec![semantic::ValueId(5)],
                source: Some(span(0, 295, 345)),
            },
            semantic::SemanticStatement::Yield(vec![semantic::ValueId(5)]),
        ];
        *else_region = semantic::SemanticRegion {
            parameters: Vec::new(),
            statements: vec![
                scalar_source_let(
                    6,
                    semantic::SemanticOperation::Copy {
                        value: semantic::ValueId(1),
                    },
                    span(0, 346, 349),
                ),
                semantic::SemanticStatement::Yield(vec![semantic::ValueId(6)]),
            ],
        };
        *results = vec![semantic::ValueId(7)];
        function.uninterrupted_bound = Some(9);
        module.functions[2].uninterrupted_bound = Some(14);
        module
            .validate()
            .expect("valid producer-shaped nested scalar join SemanticWir")
    }

    fn scalar_constant_for_primitive(
        primitive: semantic::PrimitiveType,
        value: u128,
    ) -> semantic::Constant {
        match primitive {
            semantic::PrimitiveType::Unit => semantic::Constant::Unit,
            semantic::PrimitiveType::Bool => semantic::Constant::Bool(value != 0),
            semantic::PrimitiveType::U8 => semantic::Constant::Unsigned { bits: 8, value },
            semantic::PrimitiveType::U16 => semantic::Constant::Unsigned { bits: 16, value },
            semantic::PrimitiveType::U32 => semantic::Constant::Unsigned { bits: 32, value },
            semantic::PrimitiveType::U64 | semantic::PrimitiveType::Usize => {
                semantic::Constant::Unsigned { bits: 64, value }
            }
            semantic::PrimitiveType::U128 => semantic::Constant::Unsigned { bits: 128, value },
            semantic::PrimitiveType::I8 => semantic::Constant::Signed {
                bits: 8,
                value: value as i128,
            },
            semantic::PrimitiveType::I16 => semantic::Constant::Signed {
                bits: 16,
                value: value as i128,
            },
            semantic::PrimitiveType::I32 => semantic::Constant::Signed {
                bits: 32,
                value: value as i128,
            },
            semantic::PrimitiveType::I64 | semantic::PrimitiveType::Isize => {
                semantic::Constant::Signed {
                    bits: 64,
                    value: value as i128,
                }
            }
            semantic::PrimitiveType::I128 => semantic::Constant::Signed {
                bits: 128,
                value: value as i128,
            },
            semantic::PrimitiveType::F32 => semantic::Constant::Float32((value as f32).to_bits()),
            semantic::PrimitiveType::F64 => semantic::Constant::Float64((value as f64).to_bits()),
            semantic::PrimitiveType::Char => panic!("char is not in the scalar join subset"),
        }
    }

    fn scalar_nested_join_primitive_fixture(
        primitive: semantic::PrimitiveType,
    ) -> semantic::ValidatedSemanticWir {
        let mut module = scalar_nested_join_fixture().into_wir();
        let scalar = semantic::TypeId(3);
        module.types[3] = semantic::TypeRecord {
            id: scalar,
            source_name: format!("join_{primitive:?}"),
            kind: semantic::TypeKind::Primitive(primitive),
            linearity: semantic::Linearity::CopyScalar,
            source: Some(span(0, 250, 253)),
        };
        let test = &mut module.functions[0];
        for value in &mut test.values[1..] {
            value.ty = scalar;
        }
        for (statement, value) in test.body.statements[1..3].iter_mut().zip(1_u128..=2) {
            let semantic::SemanticStatement::Let(statement) = statement else {
                panic!("primitive fixture initializer");
            };
            statement.operation = semantic::SemanticOperation::Constant(
                scalar_constant_for_primitive(primitive, value),
            );
        }
        let semantic::SemanticStatement::If { then_region, .. } = &mut test.body.statements[3]
        else {
            panic!("primitive fixture outer branch");
        };
        let semantic::SemanticStatement::If {
            then_region: inner_then,
            ..
        } = &mut then_region.statements[0]
        else {
            panic!("primitive fixture inner branch");
        };
        let semantic::SemanticStatement::Let(inner_value) = &mut inner_then.statements[0] else {
            panic!("primitive fixture inner value");
        };
        inner_value.operation = semantic::SemanticOperation::Copy {
            value: semantic::ValueId(1),
        };
        module
            .validate()
            .expect("valid producer-shaped primitive scalar join SemanticWir")
    }

    fn scalar_binary_generated_fixture() -> semantic::ValidatedSemanticWir {
        let mut module = scalar_generated_fixture().into_wir();
        let mut harness = module.functions.pop().expect("generated test harness");

        let mut generated_test_types = module.types.split_off(4);
        module.types.extend([
            semantic::TypeRecord {
                id: semantic::TypeId(4),
                source_name: "i32".to_owned(),
                kind: semantic::TypeKind::Primitive(semantic::PrimitiveType::I32),
                linearity: semantic::Linearity::CopyScalar,
                source: Some(span(0, 400, 403)),
            },
            semantic::TypeRecord {
                id: semantic::TypeId(5),
                source_name: "f32".to_owned(),
                kind: semantic::TypeKind::Primitive(semantic::PrimitiveType::F32),
                linearity: semantic::Linearity::CopyScalar,
                source: Some(span(0, 404, 407)),
            },
            semantic::TypeRecord {
                id: semantic::TypeId(6),
                source_name: "f64".to_owned(),
                kind: semantic::TypeKind::Primitive(semantic::PrimitiveType::F64),
                linearity: semantic::Linearity::CopyScalar,
                source: Some(span(0, 408, 411)),
            },
        ]);
        for record in &mut generated_test_types {
            record.id.0 = record.id.0.checked_add(3).expect("small test type id");
            if let semantic::TypeKind::Array { element, .. } = &mut record.kind {
                element.0 = element.0.checked_add(3).expect("small test element id");
            }
        }
        module.types.extend(generated_test_types);
        for value in &mut harness.values {
            if value.ty.0 >= 4 {
                value.ty.0 = value.ty.0.checked_add(3).expect("small harness type id");
            }
        }

        let binary_specs = [
            (
                semantic::BinaryOperator::Add,
                semantic::ArithmeticMode::Wrapping,
                2,
                "added",
            ),
            (
                semantic::BinaryOperator::Subtract,
                semantic::ArithmeticMode::Wrapping,
                2,
                "subtracted",
            ),
            (
                semantic::BinaryOperator::Multiply,
                semantic::ArithmeticMode::Wrapping,
                2,
                "multiplied",
            ),
            (
                semantic::BinaryOperator::BitAnd,
                semantic::ArithmeticMode::Checked,
                2,
                "and",
            ),
            (
                semantic::BinaryOperator::BitOr,
                semantic::ArithmeticMode::Checked,
                2,
                "or",
            ),
            (
                semantic::BinaryOperator::BitXor,
                semantic::ArithmeticMode::Checked,
                2,
                "xor",
            ),
            (
                semantic::BinaryOperator::Equal,
                semantic::ArithmeticMode::Checked,
                1,
                "equal",
            ),
            (
                semantic::BinaryOperator::NotEqual,
                semantic::ArithmeticMode::Checked,
                1,
                "not_equal",
            ),
            (
                semantic::BinaryOperator::Less,
                semantic::ArithmeticMode::Checked,
                1,
                "less",
            ),
            (
                semantic::BinaryOperator::LessEqual,
                semantic::ArithmeticMode::Checked,
                1,
                "less_equal",
            ),
            (
                semantic::BinaryOperator::Greater,
                semantic::ArithmeticMode::Checked,
                1,
                "greater",
            ),
            (
                semantic::BinaryOperator::GreaterEqual,
                semantic::ArithmeticMode::Checked,
                1,
                "greater_equal",
            ),
        ];
        let mut helper_values = vec![
            scalar_source_value(0, 2, "x", span(0, 420, 421)),
            scalar_source_value(1, 2, "y", span(0, 422, 423)),
        ];
        let mut helper_statements = Vec::with_capacity(binary_specs.len() + 1);
        for (index, (operator, arithmetic, result_ty, name)) in binary_specs.into_iter().enumerate()
        {
            let result = u32::try_from(index)
                .expect("small scalar operation index")
                .checked_add(2)
                .expect("small scalar value id");
            let start = 430_u32
                .checked_add(u32::try_from(index).expect("small scalar source index") * 4)
                .expect("small scalar source offset");
            let source = span(0, start, start + 3);
            helper_values.push(scalar_source_value(result, result_ty, name, source));
            helper_statements.push(scalar_source_let(
                result,
                semantic::SemanticOperation::Binary {
                    operator,
                    left: semantic::ValueId(0),
                    right: semantic::ValueId(1),
                    arithmetic,
                },
                source,
            ));
        }
        helper_statements.push(semantic::SemanticStatement::Return(vec![
            semantic::ValueId(7),
        ]));
        module.functions[1] = semantic::SemanticFunction {
            id: semantic::FunctionId(1),
            instance_key: Sha256Digest::from_bytes([0x61; 32]),
            name: "scalar_binary_unsigned".to_owned(),
            origin: semantic::FunctionOrigin::Source,
            role: semantic::FunctionRole::Ordinary,
            color: semantic::FunctionColor::Sync,
            parameters: vec![semantic::ValueId(0), semantic::ValueId(1)],
            result: semantic::TypeId(2),
            values: helper_values,
            body: semantic::SemanticRegion {
                parameters: vec![semantic::ValueId(0), semantic::ValueId(1)],
                statements: helper_statements,
            },
            effects: semantic::EffectSet::default(),
            proofs: vec![semantic::ProofId(2), semantic::ProofId(3)],
            source: Some(span(0, 420, 481)),
            stack_bound: 8,
            frame_bound: 4,
            uninterrupted_bound: Some(12),
            recursive_depth_bound: Some(1),
        };

        let signed = semantic::SemanticFunction {
            id: semantic::FunctionId(2),
            instance_key: Sha256Digest::from_bytes([0x62; 32]),
            name: "scalar_binary_signed".to_owned(),
            origin: semantic::FunctionOrigin::Source,
            role: semantic::FunctionRole::Ordinary,
            color: semantic::FunctionColor::Sync,
            parameters: vec![semantic::ValueId(0), semantic::ValueId(1)],
            result: semantic::TypeId(4),
            values: vec![
                scalar_source_value(0, 4, "left", span(0, 490, 491)),
                scalar_source_value(1, 4, "right", span(0, 492, 493)),
                scalar_source_value(2, 4, "sum", span(0, 494, 497)),
                scalar_source_value(3, 1, "ordered", span(0, 498, 501)),
            ],
            body: semantic::SemanticRegion {
                parameters: vec![semantic::ValueId(0), semantic::ValueId(1)],
                statements: vec![
                    scalar_source_let(
                        2,
                        semantic::SemanticOperation::Binary {
                            operator: semantic::BinaryOperator::Add,
                            left: semantic::ValueId(0),
                            right: semantic::ValueId(1),
                            arithmetic: semantic::ArithmeticMode::Wrapping,
                        },
                        span(0, 494, 497),
                    ),
                    scalar_source_let(
                        3,
                        semantic::SemanticOperation::Binary {
                            operator: semantic::BinaryOperator::Less,
                            left: semantic::ValueId(0),
                            right: semantic::ValueId(1),
                            arithmetic: semantic::ArithmeticMode::Checked,
                        },
                        span(0, 498, 501),
                    ),
                    semantic::SemanticStatement::Return(vec![semantic::ValueId(2)]),
                ],
            },
            effects: semantic::EffectSet::default(),
            proofs: vec![semantic::ProofId(2), semantic::ProofId(3)],
            source: Some(span(0, 488, 503)),
            stack_bound: 4,
            frame_bound: 2,
            uninterrupted_bound: Some(2),
            recursive_depth_bound: Some(1),
        };
        let float32 = semantic::SemanticFunction {
            id: semantic::FunctionId(3),
            instance_key: Sha256Digest::from_bytes([0x63; 32]),
            name: "scalar_binary_f32".to_owned(),
            origin: semantic::FunctionOrigin::Source,
            role: semantic::FunctionRole::Ordinary,
            color: semantic::FunctionColor::Sync,
            parameters: Vec::new(),
            result: semantic::TypeId(1),
            values: vec![
                scalar_source_value(0, 5, "one", span(0, 510, 513)),
                scalar_source_value(1, 5, "two", span(0, 514, 517)),
                scalar_source_value(2, 1, "ordered", span(0, 518, 521)),
            ],
            body: semantic::SemanticRegion {
                parameters: Vec::new(),
                statements: vec![
                    scalar_source_let(
                        0,
                        semantic::SemanticOperation::Constant(semantic::Constant::Float32(
                            1.0_f32.to_bits(),
                        )),
                        span(0, 510, 513),
                    ),
                    scalar_source_let(
                        1,
                        semantic::SemanticOperation::Constant(semantic::Constant::Float32(
                            2.0_f32.to_bits(),
                        )),
                        span(0, 514, 517),
                    ),
                    scalar_source_let(
                        2,
                        semantic::SemanticOperation::Binary {
                            operator: semantic::BinaryOperator::Less,
                            left: semantic::ValueId(0),
                            right: semantic::ValueId(1),
                            arithmetic: semantic::ArithmeticMode::Checked,
                        },
                        span(0, 518, 521),
                    ),
                    semantic::SemanticStatement::Return(vec![semantic::ValueId(2)]),
                ],
            },
            effects: semantic::EffectSet::default(),
            proofs: vec![semantic::ProofId(2)],
            source: Some(span(0, 508, 523)),
            stack_bound: 4,
            frame_bound: 2,
            uninterrupted_bound: Some(3),
            recursive_depth_bound: Some(1),
        };
        let float64 = semantic::SemanticFunction {
            id: semantic::FunctionId(4),
            instance_key: Sha256Digest::from_bytes([0x64; 32]),
            name: "scalar_binary_f64".to_owned(),
            origin: semantic::FunctionOrigin::Source,
            role: semantic::FunctionRole::Ordinary,
            color: semantic::FunctionColor::Sync,
            parameters: Vec::new(),
            result: semantic::TypeId(1),
            values: vec![
                scalar_source_value(0, 6, "one", span(0, 530, 533)),
                scalar_source_value(1, 6, "two", span(0, 534, 537)),
                scalar_source_value(2, 1, "ordered", span(0, 538, 541)),
            ],
            body: semantic::SemanticRegion {
                parameters: Vec::new(),
                statements: vec![
                    scalar_source_let(
                        0,
                        semantic::SemanticOperation::Constant(semantic::Constant::Float64(
                            1.0_f64.to_bits(),
                        )),
                        span(0, 530, 533),
                    ),
                    scalar_source_let(
                        1,
                        semantic::SemanticOperation::Constant(semantic::Constant::Float64(
                            2.0_f64.to_bits(),
                        )),
                        span(0, 534, 537),
                    ),
                    scalar_source_let(
                        2,
                        semantic::SemanticOperation::Binary {
                            operator: semantic::BinaryOperator::GreaterEqual,
                            left: semantic::ValueId(0),
                            right: semantic::ValueId(1),
                            arithmetic: semantic::ArithmeticMode::Checked,
                        },
                        span(0, 538, 541),
                    ),
                    semantic::SemanticStatement::Return(vec![semantic::ValueId(2)]),
                ],
            },
            effects: semantic::EffectSet::default(),
            proofs: vec![semantic::ProofId(3)],
            source: Some(span(0, 528, 543)),
            stack_bound: 4,
            frame_bound: 2,
            uninterrupted_bound: Some(3),
            recursive_depth_bound: Some(1),
        };

        harness.id = semantic::FunctionId(5);
        harness.instance_key = Sha256Digest::from_bytes([0x65; 32]);
        module.functions.extend([signed, float32, float64, harness]);
        module.image_entry = semantic::FunctionId(5);
        module.source_summary.reachable_declarations = 5;
        module.source_summary.monomorphized_instantiations = 6;
        module
            .validate()
            .expect("valid producer-shaped scalar binary SemanticWir")
    }

    fn scalar_unary_generated_fixture() -> semantic::ValidatedSemanticWir {
        let mut module = scalar_binary_generated_fixture().into_wir();

        let signed = &mut module.functions[2];
        let semantic::SemanticStatement::Let(bit_not) = &mut signed.body.statements[0] else {
            panic!("signed unary statement")
        };
        bit_not.operation = semantic::SemanticOperation::Unary {
            operator: semantic::UnaryOperator::BitNot,
            operand: semantic::ValueId(0),
            arithmetic: semantic::ArithmeticMode::Checked,
        };

        let bool_not = &mut module.functions[3];
        bool_not.values[0].ty = semantic::TypeId(1);
        let semantic::SemanticStatement::Let(constant) = &mut bool_not.body.statements[0] else {
            panic!("bool constant")
        };
        constant.operation = semantic::SemanticOperation::Constant(semantic::Constant::Bool(true));
        let semantic::SemanticStatement::Let(operation) = &mut bool_not.body.statements[2] else {
            panic!("bool unary statement")
        };
        operation.operation = semantic::SemanticOperation::Unary {
            operator: semantic::UnaryOperator::BoolNot,
            operand: semantic::ValueId(0),
            arithmetic: semantic::ArithmeticMode::Checked,
        };

        let float_negate = &mut module.functions[4];
        float_negate.result = semantic::TypeId(6);
        float_negate.values[2].ty = semantic::TypeId(6);
        let semantic::SemanticStatement::Let(operation) = &mut float_negate.body.statements[2]
        else {
            panic!("float unary statement")
        };
        operation.operation = semantic::SemanticOperation::Unary {
            operator: semantic::UnaryOperator::Negate,
            operand: semantic::ValueId(0),
            arithmetic: semantic::ArithmeticMode::Checked,
        };

        module
            .validate()
            .expect("valid producer-shaped scalar unary SemanticWir")
    }

    fn scalar_conversion_generated_fixture() -> semantic::ValidatedSemanticWir {
        let mut module = scalar_binary_generated_fixture().into_wir();

        let integer = &mut module.functions[2];
        integer.result = semantic::TypeId(6);
        integer.values[2].ty = semantic::TypeId(6);
        let semantic::SemanticStatement::Let(operation) = &mut integer.body.statements[0] else {
            panic!("integer conversion statement")
        };
        operation.operation = semantic::SemanticOperation::Convert {
            value: semantic::ValueId(0),
            destination: semantic::TypeId(6),
            checked: false,
        };

        let float = &mut module.functions[3];
        float.result = semantic::TypeId(6);
        float.values[2].ty = semantic::TypeId(6);
        let semantic::SemanticStatement::Let(operation) = &mut float.body.statements[2] else {
            panic!("float conversion statement")
        };
        operation.operation = semantic::SemanticOperation::Convert {
            value: semantic::ValueId(0),
            destination: semantic::TypeId(6),
            checked: false,
        };

        module
            .validate()
            .expect("valid producer-shaped exact scalar conversion SemanticWir")
    }

    #[test]
    fn flow_lowering_policy_rejects_zero_capacity() {
        LoweringLimits::standard()
            .validate()
            .expect("standard limits");
        let mut limits = LoweringLimits::standard();
        limits.blocks = 0;
        assert!(matches!(limits.validate(), Err(LowerError::InvalidLimits)));
        let mut limits = LoweringLimits::standard();
        limits.validation_work = 0;
        assert!(matches!(limits.validate(), Err(LowerError::InvalidLimits)));
        let mut limits = LoweringLimits::standard();
        limits.validation_errors = 0;
        assert!(matches!(limits.validate(), Err(LowerError::InvalidLimits)));
        let mut limits = LoweringLimits::standard();
        limits.test_plan.events_per_group = 0;
        assert!(matches!(limits.validate(), Err(LowerError::InvalidLimits)));
    }

    #[test]
    fn canonical_minimum_preserves_identity_proofs_and_runtime_plan() {
        let input = fixture();
        let expected = input.as_wir().clone();
        let output = CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input,
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("minimum FlowWir lowering");
        let wir = output.wir().as_wir();
        assert_eq!(wir.version, flow::FLOW_WIR_VERSION);
        assert_eq!(wir.name, expected.name);
        assert_eq!(wir.build, expected.build);
        assert_eq!(
            wir.source_summary.semantic_wir_version,
            semantic::SEMANTIC_WIR_VERSION
        );
        assert_eq!(wir.source_summary.semantic_functions, 1);
        assert_eq!(
            wir.source_summary.hir_files,
            expected.source_summary.hir_files
        );
        assert_eq!(
            wir.source_summary.hir_declarations,
            expected.source_summary.hir_declarations
        );
        assert_eq!(wir.source_summary.reachable_declarations, 1);
        assert!(matches!(
            wir.types.as_slice(),
            [flow::FlowType {
                id: flow::TypeId(0),
                kind: flow::FlowTypeKind::Unit,
                name: Some(name),
                copyable: true,
                strict_linear: false,
            }] if name == "unit"
        ));
        assert!(matches!(
            wir.functions.as_slice(),
            [flow::FlowFunction {
                id: flow::FunctionId(0),
                origin: flow::FunctionOrigin::GeneratedImageEntry {
                    semantic_function: 0,
                    constructor: 3,
                },
                role: flow::FunctionRole::ImageEntry,
                stack_bound: 0,
                frame_bound: 0,
                source: None,
                ..
            }]
        ));
        let entry = &wir.functions[0];
        assert_eq!(entry.name, expected.functions[0].name);
        assert!(entry.parameters.is_empty());
        assert!(entry.result_types.is_empty());
        assert!(entry.values.is_empty());
        assert!(matches!(
            entry.blocks.as_slice(),
            [flow::Block {
                id: flow::BlockId(0),
                parameters,
                instructions,
                terminator: flow::Terminator::Return(values),
                source: None,
            }] if parameters.is_empty() && instructions.is_empty() && values.is_empty()
        ));
        assert_eq!(wir.proofs.len(), expected.proofs.len());
        for (source, lowered) in expected.proofs.iter().zip(&wir.proofs) {
            assert_eq!(lowered.id.0, source.id.0);
            assert_eq!(lowered.kind, lower_proof_kind(&source.kind));
            assert_eq!(lowered.subject, source.subject);
            assert_eq!(lowered.sources, source.sources);
            assert_eq!(
                lowered
                    .depends_on
                    .iter()
                    .map(|proof| proof.0)
                    .collect::<Vec<_>>(),
                source
                    .depends_on
                    .iter()
                    .map(|proof| proof.0)
                    .collect::<Vec<_>>()
            );
            assert_eq!(lowered.bound, source.bound);
            assert_eq!(lowered.explanation, source.explanation);
        }
        assert_eq!(wir.startup_order, [flow::PlanOwner::Runtime]);
        assert_eq!(wir.shutdown_order, [flow::PlanOwner::Runtime]);
        assert_eq!(wir.image_entry, flow::FunctionId(0));
        assert_eq!((wir.static_bytes, wir.peak_bytes), (0, 0));
        assert_eq!(
            output.report(),
            &LoweringReport {
                source_functions: 1,
                generated_functions: 0,
                blocks: 1,
                instructions: 0,
                async_states: 0,
                cleanup_edges: 0,
                output_proofs: 3,
            }
        );
    }

    #[test]
    fn actor_zero_state_region_reaches_flow_and_is_exactly_sealed() {
        let input = actor_state_fixture();
        let output = CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: input.clone(),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("actor state reaches FlowWir");
        let (validated, report, diagnostics) = output.into_parts();
        let baseline = validated.into_wir();
        let state = baseline
            .regions
            .iter()
            .find(|region| region.name.ends_with(".state"))
            .expect("FlowWir state region");
        assert_eq!(state.class, flow::RegionClass::Image);
        assert_eq!(state.owner, flow::PlanOwner::Actor(flow::ActorId(0)));
        assert_eq!(state.capacity_bytes, 8);
        assert_eq!(state.alignment, 8);
        assert_eq!(baseline.static_bytes, 72);
        assert_eq!(baseline.peak_bytes, 72);

        let request = LowerRequest {
            input,
            limits: LoweringLimits::standard(),
        };
        let mut wrong_size = baseline.clone();
        wrong_size
            .regions
            .iter_mut()
            .find(|region| region.name.ends_with(".state"))
            .expect("state region")
            .capacity_bytes = 16;
        wrong_size.static_bytes = 80;
        wrong_size.peak_bytes = 80;
        assert!(matches!(
            seal(
                &request,
                wrong_size,
                report.clone(),
                diagnostics.clone(),
                &|| false,
            ),
            Err(LowerError::InvalidOutput(_))
        ));

        let mut wrong_owner = baseline;
        wrong_owner
            .regions
            .iter_mut()
            .find(|region| region.name.ends_with(".state"))
            .expect("state region")
            .owner = flow::PlanOwner::Runtime;
        assert!(matches!(
            seal(&request, wrong_owner, report, diagnostics, &|| false),
            Err(LowerError::InvalidOutput(_))
        ));
    }

    #[test]
    fn semantic_scope_plans_stop_at_named_flow_cleanup_boundary() {
        let mut input = actor_fixture().into_wir();
        input.scopes.push(semantic::ScopePlan {
            id: semantic::ScopeId(0),
            name: "irqs_masked".to_owned(),
            state_type: semantic::TypeId(1),
            abort: None,
            exit: semantic::FunctionId(3),
            suspend_safe: false,
            dependencies: Vec::new(),
            reverse_source_order: 0,
            cleanup_proof: semantic::ProofId(2),
            source: span(0, 50, 60),
        });
        assert!(matches!(
            supported_actor_image(&input, LoweringLimits::standard(), &|| false),
            Err(LowerError::UnsupportedInput {
                feature: "flow-scope-cleanup-lowering-pending (normal-exit cleanup calls)",
            })
        ));
    }

    #[test]
    fn stateless_actor_projection_preserves_plans_roles_calls_and_proofs() {
        let input = actor_fixture();
        let expected = input.as_wir().clone();
        let output = CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input,
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("stateless actor FlowWir lowering");
        let wir = output.wir().as_wir();
        assert_eq!(wir.name, "actor-image");
        assert_eq!(wir.actors.len(), 1);
        assert_eq!(wir.tasks.len(), 1);
        assert_eq!(wir.regions.len(), 3);
        assert_eq!(wir.actors[0].id, flow::ActorId(0));
        assert_eq!(wir.actors[0].state_type, flow::TypeId(2));
        assert_eq!(wir.actors[0].mailbox_capacity, 2);
        assert_eq!(wir.actors[0].message_types, [flow::TypeId(4)]);
        assert_eq!(wir.actors[0].turn_functions, [flow::FunctionId(1)]);
        assert_eq!(wir.actors[0].priority, 1);
        assert_eq!(wir.tasks[0].entry, flow::FunctionId(2));
        assert_eq!(wir.tasks[0].slots, 1);
        assert_eq!(wir.tasks[0].priority, 1);
        assert_eq!(wir.tasks[0].frame_bytes_bound, 16);
        assert_eq!(wir.tasks[0].supervisor, Some(flow::ActorId(0)));
        for (source, lowered) in expected.regions.iter().zip(&wir.regions) {
            assert_eq!(lowered.id.0, source.id.0);
            assert_eq!(lowered.name, source.name);
            assert_eq!(lowered.class, super::lower_region_class(source.class));
            assert_eq!(lowered.capacity_bytes, source.capacity_bytes);
            assert_eq!(lowered.alignment, source.alignment);
            assert!(lowered.reset_function.is_none());
            assert_eq!(lowered.capacity_proof, flow::ProofId(source.proof.0));
            assert_eq!(lowered.source, source.source);
        }
        assert_eq!(
            wir.regions
                .iter()
                .map(|region| region.owner)
                .collect::<Vec<_>>(),
            [
                flow::PlanOwner::Actor(flow::ActorId(0)),
                flow::PlanOwner::Actor(flow::ActorId(0)),
                flow::PlanOwner::Task(flow::TaskId(0)),
            ]
        );
        assert_eq!(
            wir.startup_order,
            [
                flow::PlanOwner::Runtime,
                flow::PlanOwner::Actor(flow::ActorId(0)),
                flow::PlanOwner::Task(flow::TaskId(0)),
            ]
        );
        assert_eq!(
            wir.shutdown_order,
            [
                flow::PlanOwner::Task(flow::TaskId(0)),
                flow::PlanOwner::Actor(flow::ActorId(0)),
                flow::PlanOwner::Runtime,
            ]
        );
        assert_eq!((wir.static_bytes, wir.peak_bytes), (64, 64));
        assert_eq!(wir.image_entry, flow::FunctionId(3));
        assert!(matches!(
            wir.functions[1],
            flow::FlowFunction {
                origin: flow::FunctionOrigin::SourceSemantic {
                    semantic_function: 1
                },
                role: flow::FunctionRole::ActorTurn(flow::ActorId(0)),
                color: flow::FunctionColor::Async,
                frame_bound: 16,
                ..
            }
        ));
        assert!(matches!(
            wir.functions[2],
            flow::FlowFunction {
                origin: flow::FunctionOrigin::SourceSemantic {
                    semantic_function: 2
                },
                role: flow::FunctionRole::TaskEntry(flow::TaskId(0)),
                color: flow::FunctionColor::Async,
                frame_bound: 16,
                ..
            }
        ));
        assert!(matches!(
            wir.functions[3].origin,
            flow::FunctionOrigin::GeneratedImageEntry {
                semantic_function: 3,
                constructor: 7,
            }
        ));
        assert!(matches!(
            wir.functions[1].blocks[0].instructions.as_slice(),
            [
                flow::Instruction {
                    operation: flow::FlowOperation::Immediate(flow::Immediate::Integer {
                        bits: 32,
                        ..
                    }),
                    ..
                },
                flow::Instruction {
                    results,
                    operation: flow::FlowOperation::Call {
                        function: flow::FunctionId(0),
                        arguments,
                    },
                    ..
                }
            ] if results.as_slice() == [flow::ValueId(2)]
                && arguments.as_slice() == [flow::ValueId(1)]
        ));
        assert_eq!(wir.proofs.len(), expected.proofs.len());
        for (source, lowered) in expected.proofs.iter().zip(&wir.proofs) {
            assert_eq!(lowered.id.0, source.id.0);
            assert_eq!(lowered.kind, lower_proof_kind(&source.kind));
            assert_eq!(lowered.sources, source.sources);
            assert_eq!(lowered.bound, source.bound);
        }
        assert_eq!(
            output.report(),
            &LoweringReport {
                source_functions: 4,
                generated_functions: 0,
                blocks: 4,
                instructions: 3,
                async_states: 0,
                cleanup_edges: 0,
                output_proofs: 10,
            }
        );
    }

    #[test]
    fn actor_flow_output_accepts_exact_aggregate_resources_and_rejects_one_under() {
        let measured_input = actor_async_fixture();
        let (input_edges, input_payload) =
            preflight_input(measured_input.as_wir(), LoweringLimits::standard(), &|| {
                false
            })
            .expect("measure complete actor SemanticWir input");
        let output_meter = measure_actor_flow_output_resources(
            measured_input.as_wir(),
            LoweringLimits::standard(),
            &|| false,
        )
        .expect("measure prospective actor FlowWir output");
        assert!(!output_meter.edge_overflowed && !output_meter.payload_overflowed);

        let mut exact = LoweringLimits::standard();
        exact.model_edges = input_edges.max(output_meter.edges);
        exact.payload_bytes = input_payload.max(output_meter.payload_bytes);
        let exact_output = CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: measured_input,
                    limits: exact,
                },
                &|| false,
            )
            .expect("exact aggregate actor FlowWir budget");
        let mut long_comparison = exact_output.wir().as_wir().clone();
        long_comparison.types[0].name = Some("unit".repeat(32 * 1024));
        let comparison_polls = Cell::new(0_u32);
        assert!(matches!(
            actor_flow_program_matches(&long_comparison, &long_comparison, &|| {
                let next = comparison_polls.get().saturating_add(1);
                comparison_polls.set(next);
                next > 8
            }),
            Err(LowerError::Cancelled)
        ));
        assert_eq!(comparison_polls.get(), 9);

        let mut one_edge_under = exact;
        one_edge_under.model_edges = one_edge_under
            .model_edges
            .checked_sub(1)
            .expect("nonzero actor edge count");
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: actor_async_fixture(),
                    limits: one_edge_under,
                },
                &|| false,
            ),
            Err(LowerError::ResourceLimit { limit, .. }) if limit == one_edge_under.model_edges
        ));

        let mut one_byte_under = exact;
        one_byte_under.payload_bytes = one_byte_under
            .payload_bytes
            .checked_sub(1)
            .expect("nonzero actor payload count");
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: actor_async_fixture(),
                    limits: one_byte_under,
                },
                &|| false,
            ),
            Err(LowerError::ResourceLimit { limit, .. }) if limit == one_byte_under.payload_bytes
        ));
    }

    #[test]
    fn real_producer_unit_async_activation_lowers_to_explicit_delivery() {
        let output = CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: actor_async_fixture(),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("unit async activation has an exact FlowWir representation");
        let wir = output.wir().as_wir();
        let activation = wir
            .types
            .iter()
            .find(|ty| {
                matches!(
                    ty.kind,
                    flow::FlowTypeKind::Activation {
                        result: flow::TypeId(0)
                    }
                )
            })
            .expect("unit activation type");
        assert!(!activation.copyable && activation.strict_linear);
        let turn = &wir.functions[1];
        assert_eq!(turn.color, flow::FunctionColor::Async);
        assert_eq!(turn.values[1].ty, activation.id);
        assert!(matches!(
            turn.blocks.as_slice(),
            [entry, resume]
                if matches!(
                    entry.instructions.as_slice(),
                    [flow::Instruction {
                        results,
                        operation: flow::FlowOperation::AsyncCall {
                            function: flow::FunctionId(0),
                            arguments,
                            plan: flow::ActivationId(0),
                        },
                        ..
                    }] if results.as_slice() == [flow::ValueId(1)] && arguments.is_empty()
                )
                && matches!(
                    entry.terminator,
                    flow::Terminator::Suspend {
                        state: 0,
                        activation: flow::ValueId(1),
                        resume: flow::BlockId(1),
                    }
                )
                && resume.parameters.as_slice() == [flow::ValueId(2)]
                && matches!(resume.terminator, flow::Terminator::Return(ref values) if values.is_empty())
        ));
        assert_eq!(output.report().async_states, 1);
    }

    #[test]
    fn real_producer_value_async_activation_delivers_exact_result_type() {
        let output = CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: actor_async_value_fixture(),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("value async activation has an exact FlowWir representation");
        let wir = output.wir().as_wir();
        let activation = wir
            .types
            .iter()
            .find(|ty| {
                matches!(
                    ty.kind,
                    flow::FlowTypeKind::Activation {
                        result: flow::TypeId(1)
                    }
                )
            })
            .expect("u32 activation type");
        assert!(!activation.copyable && activation.strict_linear);
        let turn = &wir.functions[1];
        assert_eq!(turn.values[1].ty, activation.id);
        assert_eq!(turn.values[2].ty, flow::TypeId(1));
        assert!(matches!(
            turn.blocks.as_slice(),
            [entry, resume]
                if matches!(
                    entry.instructions.as_slice(),
                    [flow::Instruction {
                        results,
                        operation: flow::FlowOperation::AsyncCall {
                            function: flow::FunctionId(0),
                            arguments,
                            plan: flow::ActivationId(0),
                        },
                        ..
                    }] if results.as_slice() == [flow::ValueId(1)] && arguments.is_empty()
                )
                && matches!(
                    entry.terminator,
                    flow::Terminator::Suspend {
                        state: 0,
                        activation: flow::ValueId(1),
                        resume: flow::BlockId(1),
                    }
                )
                && resume.parameters.as_slice() == [flow::ValueId(2)]
                && matches!(resume.terminator, flow::Terminator::Return(ref values) if values.is_empty())
        ));
    }

    #[test]
    fn async_lowering_enforces_adjacency_state_block_limits_and_cancellation() {
        let input = actor_two_await_fixture();
        let mut exact = LoweringLimits::standard();
        exact.states_per_function = 2;
        exact.blocks = 6;
        let output = CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: input.clone(),
                    limits: exact,
                },
                &|| false,
            )
            .expect("exact async state and block maxima are accepted");
        assert_eq!(output.report().async_states, 2);
        assert_eq!(output.report().blocks, 6);

        let mut too_few_states = LoweringLimits::standard();
        too_few_states.states_per_function = 1;
        assert_eq!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: input.clone(),
                    limits: too_few_states,
                },
                &|| false,
            ),
            Err(LowerError::ResourceLimit {
                resource: "FlowWir async states",
                limit: 1,
            })
        );

        let mut too_few_blocks = LoweringLimits::standard();
        too_few_blocks.blocks = 5;
        assert_eq!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: input.clone(),
                    limits: too_few_blocks,
                },
                &|| false,
            ),
            Err(LowerError::ResourceLimit {
                resource: "FlowWir blocks",
                limit: 5,
            })
        );

        let mut non_adjacent = input.clone().into_wir();
        let turn = &mut non_adjacent.functions[1];
        turn.body.statements.swap(1, 2);
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: non_adjacent
                        .validate()
                        .expect("structurally valid non-adjacent awaits"),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            ),
            Err(LowerError::UnsupportedInput {
                feature: "actor scalar call results",
            }) | Err(LowerError::UnsupportedInput {
                feature: "async await result delivery",
            })
        ));

        let polls = Cell::new(0_u32);
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input,
                    limits: LoweringLimits::standard(),
                },
                &|| {
                    let current = polls.get();
                    polls.set(current + 1);
                    current >= 20
                },
            ),
            Err(LowerError::Cancelled)
        ));
        assert!(polls.get() > 20);
    }

    #[test]
    fn actor_projection_rejects_substitution_max_plus_one_and_late_cancellation() {
        let input = actor_fixture();
        let mut missing_actor_authority = input.clone().into_wir();
        missing_actor_authority.functions[1].effects =
            semantic::EffectSet(semantic::EffectSet::SUSPEND);
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: missing_actor_authority
                        .validate()
                        .expect("structurally valid actor-effect substitution"),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            ),
            Err(LowerError::UnsupportedInput {
                feature: "actor functions outside the scalar/call/await slice",
            })
        ));

        let output = CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: input.clone(),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("baseline actor lowering");
        let (validated, report, diagnostics) = output.into_parts();
        let baseline = validated.into_wir();
        let mut substituted = baseline.clone();
        substituted.actors[0].mailbox_capacity = 3;
        assert!(matches!(
            seal(
                &LowerRequest {
                    input: input.clone(),
                    limits: LoweringLimits::standard(),
                },
                substituted,
                report.clone(),
                diagnostics.clone(),
                &|| false,
            ),
            Err(LowerError::InvalidOutput(_))
        ));

        let mut valid_but_substituted = baseline;
        valid_but_substituted.build.request = Sha256Digest::from_bytes([0xA5; 32]);
        assert!(matches!(
            seal(
                &LowerRequest {
                    input: input.clone(),
                    limits: LoweringLimits::standard(),
                },
                valid_but_substituted,
                report,
                diagnostics,
                &|| false,
            ),
            Err(LowerError::InvalidReport(_))
        ));

        let mut limits = LoweringLimits::standard();
        limits.blocks = 3;
        assert_eq!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: input.clone(),
                    limits,
                },
                &|| false,
            ),
            Err(LowerError::ResourceLimit {
                resource: "FlowWir blocks",
                limit: 3,
            })
        );

        let polls = Cell::new(0_u32);
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input,
                    limits: LoweringLimits::standard(),
                },
                &|| {
                    let current = polls.get();
                    polls.set(current + 1);
                    current >= 12
                },
            ),
            Err(LowerError::Cancelled)
        ));
        assert!(polls.get() > 12);
    }

    #[test]
    fn generated_group_preserves_test_table_frames_calls_and_terminal_effect() {
        let input = generated_fixture();
        let expected = input.as_wir().clone();
        let output = CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input,
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("generated test FlowWir lowering");
        let wir = output.wir().as_wir();
        assert_eq!(wir.tests.len(), 2);
        assert_eq!(wir.compiled_test_group, expected.compiled_test_group);
        for (source, lowered) in expected.tests.iter().zip(&wir.tests) {
            assert_eq!(lowered.id.0, source.id.0);
            assert_eq!(lowered.plan_id, source.plan_id);
            assert_eq!(
                lowered.function_key,
                expected.functions[source.function.0 as usize].instance_key
            );
            assert_eq!(lowered.name, source.name);
            assert_eq!(lowered.function.0, source.function.0);
            assert_eq!(lowered.kind, flow::TestKind::Integration);
            assert_eq!(lowered.source, source.source);
            assert_eq!(lowered.timeout_ns, source.timeout_ns);
        }
        assert!(matches!(
            wir.types.as_slice(),
            [
                flow::FlowType {
                    kind: flow::FlowTypeKind::Unit,
                    ..
                },
                flow::FlowType {
                    kind: flow::FlowTypeKind::Scalar(flow::ScalarType::Integer {
                        signed: false,
                        bits: 8,
                    }),
                    ..
                },
                flow::FlowType {
                    kind: flow::FlowTypeKind::Scalar(flow::ScalarType::Integer {
                        signed: false,
                        bits: 32,
                    }),
                    ..
                },
                flow::FlowType {
                    kind: flow::FlowTypeKind::Array {
                        element: flow::TypeId(1),
                        length: 49,
                    },
                    ..
                },
                flow::FlowType {
                    kind: flow::FlowTypeKind::Array {
                        element: flow::TypeId(1),
                        length: 50,
                    },
                    ..
                },
                flow::FlowType {
                    kind: flow::FlowTypeKind::Array {
                        element: flow::TypeId(1),
                        length: 53,
                    },
                    ..
                }
            ]
        ));
        assert_eq!(wir.functions.len(), 3);
        assert!(wir.functions[..2].iter().enumerate().all(|(id, function)| {
            function.id.0 as usize == id
                && function.role == flow::FunctionRole::Test
                && matches!(
                    function.origin,
                    flow::FunctionOrigin::SourceSemantic { semantic_function }
                        if semantic_function as usize == id
                )
                && matches!(
                    function.blocks.as_slice(),
                    [flow::Block {
                        instructions,
                        terminator: flow::Terminator::Return(values),
                        ..
                    }] if instructions.is_empty() && values.is_empty()
                )
        }));
        let harness = &wir.functions[2];
        assert_eq!(
            harness.origin,
            flow::FunctionOrigin::GeneratedTestHarness {
                semantic_function: 2,
                group: 9,
            }
        );
        let [block] = harness.blocks.as_slice() else {
            panic!("one harness block");
        };
        assert_eq!(block.instructions.len(), 16);
        assert!(matches!(block.terminator, flow::Terminator::Unreachable));
        let emitted_frames: Vec<_> = block
            .instructions
            .windows(2)
            .filter_map(|pair| match (&pair[0].operation, &pair[1].operation) {
                (
                    flow::FlowOperation::Immediate(flow::Immediate::Bytes(bytes)),
                    flow::FlowOperation::TestEmit { payload },
                ) if pair[0].results.as_slice() == [*payload] => Some(bytes.as_slice()),
                _ => None,
            })
            .collect();
        assert_eq!(emitted_frames.len(), 6);
        let expected_frames = canonical_passing_frames(&[12, 13]);
        assert!(
            emitted_frames
                .iter()
                .zip(&expected_frames)
                .all(|(actual, expected)| *actual == expected)
        );
        assert!(matches!(
            &block.instructions[14].operation,
            flow::FlowOperation::Immediate(flow::Immediate::Integer {
                bits: 32,
                bytes_le,
            }) if bytes_le.as_slice() == [0, 0, 0, 0]
        ));
        assert!(matches!(
            block.instructions[15].operation,
            flow::FlowOperation::TestFinish {
                outcome: flow::ValueId(6),
            }
        ));
        assert_eq!(
            output.report(),
            &LoweringReport {
                source_functions: 3,
                generated_functions: 0,
                blocks: 3,
                instructions: 16,
                async_states: 0,
                cleanup_edges: 0,
                output_proofs: 7,
            }
        );
    }

    #[test]
    fn scalar_source_closure_lowers_parameters_locals_calls_returns_and_no_phi_if() {
        let input = scalar_generated_fixture();
        let semantic = input.as_wir().clone();
        let output = CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input,
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("scalar source closure FlowWir lowering");
        let wir = output.wir().as_wir();
        assert_eq!(wir.build, semantic.build);
        assert_eq!(wir.source_summary.semantic_functions, 3);
        assert!(matches!(
            wir.types[1].kind,
            flow::FlowTypeKind::Scalar(flow::ScalarType::Bool)
        ));
        assert!(matches!(
            &wir.types[3].kind,
            flow::FlowTypeKind::Function { parameters, result }
                if parameters.as_slice() == [flow::TypeId(2), flow::TypeId(2)]
                    && *result == flow::TypeId(2)
        ));

        let test = &wir.functions[0];
        assert_eq!(test.role, flow::FunctionRole::Test);
        assert_eq!(test.stack_bound, 4);
        assert_eq!(test.frame_bound, 2);
        assert_eq!(test.values.len(), 4);
        assert_eq!(test.values[0].source_name.as_deref(), Some("flag"));
        assert_eq!(test.values[3].source, Some(span(0, 315, 345)));
        let [entry, then_block, else_block, merge] = test.blocks.as_slice() else {
            panic!("exact no-phi branch CFG");
        };
        assert!(matches!(
            entry.terminator,
            flow::Terminator::Branch {
                condition: flow::ValueId(0),
                then_block: flow::BlockId(1),
                else_block: flow::BlockId(2),
                ref then_arguments,
                ref else_arguments,
            } if then_arguments.is_empty() && else_arguments.is_empty()
        ));
        assert_eq!(
            entry
                .instructions
                .iter()
                .map(|instruction| instruction.id.0)
                .collect::<Vec<_>>(),
            [0, 1, 2]
        );
        assert!(matches!(
            &entry.instructions[0].operation,
            flow::FlowOperation::Immediate(flow::Immediate::Bool(true))
        ));
        assert!(matches!(
            &entry.instructions[1].operation,
            flow::FlowOperation::Immediate(flow::Immediate::Integer {
                bits: 32,
                bytes_le,
            }) if bytes_le.as_slice() == [7, 0, 0, 0]
        ));
        assert!(matches!(
            &then_block.instructions[0],
            flow::Instruction {
                id: flow::InstructionId(3),
                results,
                operation: flow::FlowOperation::Call { function, arguments },
                source: Some(source),
            } if results.as_slice() == [flow::ValueId(3)]
                && *function == flow::FunctionId(1)
                && arguments.as_slice() == [flow::ValueId(1), flow::ValueId(2)]
                && *source == span(0, 315, 345)
        ));
        assert!(matches!(
            then_block.terminator,
            flow::Terminator::Jump {
                target: flow::BlockId(3),
                ref arguments,
            } if arguments.is_empty()
        ));
        assert!(matches!(
            else_block.terminator,
            flow::Terminator::Jump {
                target: flow::BlockId(3),
                ref arguments,
            } if arguments.is_empty()
        ));
        assert!(matches!(
            merge.terminator,
            flow::Terminator::Return(ref values) if values.is_empty()
        ));

        let helper = &wir.functions[1];
        assert_eq!(helper.role, flow::FunctionRole::Ordinary);
        assert_eq!(helper.parameters, [flow::ValueId(0), flow::ValueId(1)]);
        assert_eq!(helper.result_types, [flow::TypeId(2)]);
        assert_eq!(helper.values[2].source_name.as_deref(), Some("copied"));
        assert!(matches!(
            helper.blocks[0].instructions.as_slice(),
            [flow::Instruction {
                id: flow::InstructionId(0),
                results,
                operation: flow::FlowOperation::Copy {
                    value: flow::ValueId(0),
                },
                ..
            }] if results.as_slice() == [flow::ValueId(2)]
        ));
        assert!(matches!(
            helper.blocks[0].terminator,
            flow::Terminator::Return(ref values) if values.as_slice() == [flow::ValueId(2)]
        ));
        assert_eq!(
            output.report(),
            &LoweringReport {
                source_functions: 3,
                generated_functions: 0,
                blocks: 6,
                instructions: 16,
                async_states: 0,
                cleanup_edges: 0,
                output_proofs: 7,
            }
        );
    }

    #[test]
    fn scalar_call_result_contract_preserves_real_producer_ssa_type_source_and_ignored_unit_form() {
        let input = scalar_unit_call_fixture();
        let output = CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input,
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("explicit unit-result call lowers");
        let wir = output.wir().as_wir();
        let caller = &wir.functions[0];
        assert_eq!(caller.values[3].ty, flow::TypeId(0));
        assert_eq!(caller.values[3].source, Some(span(0, 315, 345)));
        assert!(matches!(
            caller.blocks[1].instructions.as_slice(),
            [flow::Instruction {
                results,
                operation: flow::FlowOperation::Call {
                    function: flow::FunctionId(1),
                    ..
                },
                source: Some(source),
                ..
            }] if results.as_slice() == [flow::ValueId(3)]
                && *source == span(0, 315, 345)
        ));
        assert!(wir.functions[1].result_types.is_empty());
        assert!(
            wir.functions[2]
                .blocks
                .iter()
                .flat_map(|block| &block.instructions)
                .any(|instruction| matches!(
                    instruction,
                    flow::Instruction {
                        results,
                        operation: flow::FlowOperation::Call {
                            function: flow::FunctionId(0),
                            ..
                        },
                        ..
                    } if results.is_empty()
                ))
        );
    }

    #[test]
    fn scalar_call_result_contract_chains_ssa_identity_deterministically() {
        let input = scalar_chained_call_fixture();
        let lower = |input| {
            CanonicalFlowLowerer::new()
                .lower(
                    LowerRequest {
                        input,
                        limits: LoweringLimits::standard(),
                    },
                    &|| false,
                )
                .expect("chained scalar calls lower")
        };
        let first = lower(input.clone());
        let second = lower(input);
        assert_eq!(first, second);
        let calls = &first.wir().as_wir().functions[0].blocks[1].instructions;
        assert!(matches!(
            calls.as_slice(),
            [
                flow::Instruction {
                    id: flow::InstructionId(3),
                    results: first_results,
                    operation: flow::FlowOperation::Call {
                        arguments: first_arguments,
                        ..
                    },
                    ..
                },
                flow::Instruction {
                    id: flow::InstructionId(4),
                    results: second_results,
                    operation: flow::FlowOperation::Call {
                        arguments: second_arguments,
                        ..
                    },
                    source: Some(source),
                }
            ] if first_results.as_slice() == [flow::ValueId(3)]
                && first_arguments.as_slice() == [flow::ValueId(1), flow::ValueId(2)]
                && second_results.as_slice() == [flow::ValueId(4)]
                && second_arguments.as_slice() == [flow::ValueId(3), flow::ValueId(2)]
                && *source == span(0, 346, 376)
        ));
    }

    #[test]
    fn scalar_call_result_contract_fails_closed_on_zero_two_and_wrong_type() {
        let mut zero = scalar_generated_fixture().into_wir();
        scalar_branch_call_mut(&mut zero).results.clear();
        zero.functions[0].values.pop();
        assert_eq!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: zero.validate().expect("structural zero-result call"),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            ),
            Err(LowerError::UnsupportedInput {
                feature: "scalar call results",
            })
        );

        let mut two = scalar_generated_fixture().into_wir();
        two.functions[0].values.push(semantic::SemanticValue {
            id: semantic::ValueId(4),
            ty: semantic::TypeId(2),
            origin: Some(span(0, 315, 345)),
            name: None,
        });
        scalar_branch_call_mut(&mut two)
            .results
            .push(semantic::ValueId(4));
        assert_eq!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: two.validate().expect("structural two-result call"),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            ),
            Err(LowerError::UnsupportedInput {
                feature: "scalar call results",
            })
        );

        let mut wrong_type = scalar_generated_fixture().into_wir();
        wrong_type.functions[0].values[3].ty = semantic::TypeId(1);
        assert_eq!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: wrong_type
                        .validate()
                        .expect("structural wrong-result-type call"),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            ),
            Err(LowerError::UnsupportedInput {
                feature: "scalar call results",
            })
        );
    }

    #[test]
    fn scalar_call_result_contract_is_exactly_bounded_and_late_cancellable() {
        let input = scalar_chained_call_fixture();
        let (edges, payload) =
            preflight_input(input.as_wir(), LoweringLimits::standard(), &|| false)
                .expect("measure chained-call input");
        let mut exact_input = LoweringLimits::standard();
        exact_input.model_edges = edges;
        exact_input.payload_bytes = payload;
        assert_eq!(
            preflight_input(input.as_wir(), exact_input, &|| false),
            Ok((edges, payload))
        );
        let mut one_under = exact_input;
        one_under.model_edges = edges - 1;
        assert_eq!(
            preflight_input(input.as_wir(), one_under, &|| false),
            Err(LowerError::ResourceLimit {
                resource: "semantic model edges",
                limit: edges - 1,
            })
        );

        let polls = Cell::new(0_u32);
        CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: input.clone(),
                    limits: LoweringLimits::standard(),
                },
                &|| {
                    polls.set(polls.get() + 1);
                    false
                },
            )
            .expect("count chained-call cancellation polls");
        let cancel_at = polls.get();
        polls.set(0);
        assert_eq!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input,
                    limits: LoweringLimits::standard(),
                },
                &|| {
                    let next = polls.get() + 1;
                    polls.set(next);
                    next == cancel_at
                },
            ),
            Err(LowerError::Cancelled)
        );
        assert_eq!(polls.get(), cancel_at);
    }

    #[test]
    fn nested_scalar_branch_results_lower_to_exact_ssa_block_parameters_and_edges() {
        let input = scalar_nested_join_fixture();
        let output = CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: input.clone(),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("nested scalar joins lower to FlowWir");
        let function = &output.wir().as_wir().functions[0];
        let [
            entry,
            outer_then,
            outer_else,
            outer_merge,
            inner_then,
            inner_else,
            inner_merge,
        ] = function.blocks.as_slice()
        else {
            panic!("exact nested scalar join CFG");
        };
        assert!(matches!(
            entry.terminator,
            flow::Terminator::Branch {
                condition: flow::ValueId(0),
                then_block: flow::BlockId(1),
                else_block: flow::BlockId(2),
                ref then_arguments,
                ref else_arguments,
            } if then_arguments.is_empty() && else_arguments.is_empty()
        ));
        assert!(matches!(
            outer_then.terminator,
            flow::Terminator::Branch {
                condition: flow::ValueId(0),
                then_block: flow::BlockId(4),
                else_block: flow::BlockId(5),
                ref then_arguments,
                ref else_arguments,
            } if then_arguments.is_empty() && else_arguments.is_empty()
        ));
        assert!(matches!(
            inner_then.terminator,
            flow::Terminator::Jump {
                target: flow::BlockId(6),
                ref arguments,
            } if arguments.as_slice() == [flow::ValueId(3)]
        ));
        assert!(matches!(
            inner_else.terminator,
            flow::Terminator::Jump {
                target: flow::BlockId(6),
                ref arguments,
            } if arguments.as_slice() == [flow::ValueId(4)]
        ));
        assert_eq!(inner_merge.parameters, [flow::ValueId(5)]);
        assert!(matches!(
            inner_merge.terminator,
            flow::Terminator::Jump {
                target: flow::BlockId(3),
                ref arguments,
            } if arguments.as_slice() == [flow::ValueId(5)]
        ));
        assert!(matches!(
            outer_else.terminator,
            flow::Terminator::Jump {
                target: flow::BlockId(3),
                ref arguments,
            } if arguments.as_slice() == [flow::ValueId(6)]
        ));
        assert_eq!(outer_merge.parameters, [flow::ValueId(7)]);
        assert!(matches!(
            outer_merge.terminator,
            flow::Terminator::Return(ref values) if values.is_empty()
        ));

        let mut forged = output.wir().as_wir().clone();
        let flow::Terminator::Jump { arguments, .. } =
            &mut forged.functions[0].blocks[2].terminator
        else {
            panic!("outer else edge");
        };
        arguments[0] = flow::ValueId(1);
        assert!(matches!(
            seal(
                &LowerRequest {
                    input,
                    limits: LoweringLimits::standard(),
                },
                forged,
                output.report().clone(),
                Vec::new(),
                &|| false,
            ),
            Err(LowerError::InvalidReport(_))
        ));
    }

    #[test]
    fn scalar_ssa_joins_lower_for_every_supported_primitive_type() {
        for primitive in [
            semantic::PrimitiveType::Unit,
            semantic::PrimitiveType::Bool,
            semantic::PrimitiveType::U8,
            semantic::PrimitiveType::U16,
            semantic::PrimitiveType::U32,
            semantic::PrimitiveType::U64,
            semantic::PrimitiveType::U128,
            semantic::PrimitiveType::Usize,
            semantic::PrimitiveType::I8,
            semantic::PrimitiveType::I16,
            semantic::PrimitiveType::I32,
            semantic::PrimitiveType::I64,
            semantic::PrimitiveType::I128,
            semantic::PrimitiveType::Isize,
            semantic::PrimitiveType::F32,
            semantic::PrimitiveType::F64,
        ] {
            let output = CanonicalFlowLowerer::new()
                .lower(
                    LowerRequest {
                        input: scalar_nested_join_primitive_fixture(primitive),
                        limits: LoweringLimits::standard(),
                    },
                    &|| false,
                )
                .unwrap_or_else(|error| panic!("{primitive:?} scalar join: {error:?}"));
            let function = &output.wir().as_wir().functions[0];
            let joins = function
                .blocks
                .iter()
                .filter(|block| !block.parameters.is_empty())
                .collect::<Vec<_>>();
            assert_eq!(joins.len(), 2, "{primitive:?} nested join count");
            for join in joins {
                let [parameter] = join.parameters.as_slice() else {
                    panic!("{primitive:?} scalar join parameter");
                };
                let expected_type = function.values[parameter.0 as usize].ty;
                let incoming = function
                    .blocks
                    .iter()
                    .filter_map(|block| match &block.terminator {
                        flow::Terminator::Jump { target, arguments } if *target == join.id => {
                            Some(arguments)
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                assert_eq!(incoming.len(), 2, "{primitive:?} incoming join edges");
                for arguments in incoming {
                    let [argument] = arguments.as_slice() else {
                        panic!("{primitive:?} scalar join argument");
                    };
                    assert_eq!(function.values[argument.0 as usize].ty, expected_type);
                }
            }
        }
    }

    #[test]
    fn scalar_branch_join_rejects_missing_mistyped_and_misarity_yields() {
        let mut missing = scalar_nested_join_fixture().into_wir();
        let semantic::SemanticStatement::If { else_region, .. } =
            &mut missing.functions[0].body.statements[3]
        else {
            panic!("outer scalar branch");
        };
        else_region.statements.pop();
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: missing.validate().expect("structural missing yield"),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            ),
            Err(LowerError::UnsupportedInput {
                feature: "scalar branch yield terminator",
            })
        ));

        let mut mistyped = scalar_nested_join_fixture().into_wir();
        let semantic::SemanticStatement::If { else_region, .. } =
            &mut mistyped.functions[0].body.statements[3]
        else {
            panic!("outer scalar branch");
        };
        let semantic::SemanticStatement::Yield(values) =
            else_region.statements.last_mut().expect("outer yield")
        else {
            panic!("outer yield statement");
        };
        values[0] = semantic::ValueId(0);
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: mistyped.validate().expect("structural mistyped yield"),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            ),
            Err(LowerError::UnsupportedInput {
                feature: "scalar branch yield type",
            })
        ));

        let mut misarity = scalar_nested_join_fixture().into_wir();
        let semantic::SemanticStatement::If { else_region, .. } =
            &mut misarity.functions[0].body.statements[3]
        else {
            panic!("outer scalar branch");
        };
        let semantic::SemanticStatement::Yield(values) =
            else_region.statements.last_mut().expect("outer yield")
        else {
            panic!("outer yield statement");
        };
        values.clear();
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: misarity.validate().expect("structural misarity yield"),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            ),
            Err(LowerError::UnsupportedInput {
                feature: "scalar branch yield arity or position",
            })
        ));
    }

    #[test]
    fn scalar_branch_join_enforces_exact_limits_max_plus_one_and_late_cancellation() {
        let mut exact = LoweringLimits::standard();
        exact.blocks = 9;
        exact.instructions = 18;
        CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: scalar_nested_join_fixture(),
                    limits: exact,
                },
                &|| false,
            )
            .expect("exact nested scalar join limits");

        let mut blocks = exact;
        blocks.blocks = 8;
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: scalar_nested_join_fixture(),
                    limits: blocks,
                },
                &|| false,
            ),
            Err(LowerError::ResourceLimit {
                resource: "FlowWir blocks",
                limit: 8,
            })
        ));
        let mut instructions = exact;
        instructions.instructions = 17;
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: scalar_nested_join_fixture(),
                    limits: instructions,
                },
                &|| false,
            ),
            Err(LowerError::ResourceLimit {
                resource: "FlowWir instructions",
                limit: 17,
            })
        ));

        let polls = Cell::new(0_u32);
        CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: scalar_nested_join_fixture(),
                    limits: exact,
                },
                &|| {
                    polls.set(polls.get() + 1);
                    false
                },
            )
            .expect("count nested scalar join cancellation polls");
        let cancel_at = polls.get();
        let polls = Cell::new(0_u32);
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: scalar_nested_join_fixture(),
                    limits: exact,
                },
                &|| {
                    let next = polls.get() + 1;
                    polls.set(next);
                    next == cancel_at
                },
            ),
            Err(LowerError::Cancelled)
        ));
        assert_eq!(polls.get(), cancel_at);
    }

    #[test]
    fn scalar_binary_surface_preserves_types_operations_sources_proofs_and_test_binding() {
        let input = scalar_binary_generated_fixture();
        let semantic = input.as_wir().clone();
        let output = CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input,
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("scalar binary FlowWir lowering");
        let wir = output.wir().as_wir();

        assert_eq!(wir.build, semantic.build);
        assert_eq!(wir.source_summary.semantic_functions, 6);
        assert_eq!(
            wir.source_summary.reachable_declarations,
            semantic.source_summary.reachable_declarations
        );
        assert_eq!(
            wir.source_summary.monomorphized_instantiations,
            semantic.source_summary.monomorphized_instantiations
        );
        assert!(matches!(
            wir.types[2].kind,
            flow::FlowTypeKind::Scalar(flow::ScalarType::Integer {
                signed: false,
                bits: 32,
            })
        ));
        assert!(matches!(
            wir.types[4].kind,
            flow::FlowTypeKind::Scalar(flow::ScalarType::Integer {
                signed: true,
                bits: 32,
            })
        ));
        assert!(matches!(
            wir.types[5].kind,
            flow::FlowTypeKind::Scalar(flow::ScalarType::Float32)
        ));
        assert!(matches!(
            wir.types[6].kind,
            flow::FlowTypeKind::Scalar(flow::ScalarType::Float64)
        ));

        let expected_unsigned = [
            flow::BinaryOp::AddWrapping,
            flow::BinaryOp::SubWrapping,
            flow::BinaryOp::MulWrapping,
            flow::BinaryOp::BitAnd,
            flow::BinaryOp::BitOr,
            flow::BinaryOp::BitXor,
            flow::BinaryOp::Equal,
            flow::BinaryOp::NotEqual,
            flow::BinaryOp::Less,
            flow::BinaryOp::LessEqual,
            flow::BinaryOp::Greater,
            flow::BinaryOp::GreaterEqual,
        ];
        let unsigned = &wir.functions[1];
        assert_eq!(unsigned.parameters, [flow::ValueId(0), flow::ValueId(1)]);
        assert_eq!(unsigned.result_types, [flow::TypeId(2)]);
        assert_eq!(unsigned.blocks.len(), 1);
        assert_eq!(
            unsigned.blocks[0].instructions.len(),
            expected_unsigned.len()
        );
        for (index, (instruction, expected_op)) in unsigned.blocks[0]
            .instructions
            .iter()
            .zip(expected_unsigned)
            .enumerate()
        {
            let expected_result = u32::try_from(index)
                .expect("small instruction index")
                .checked_add(2)
                .expect("small result id");
            assert_eq!(instruction.id, flow::InstructionId(index as u32));
            assert_eq!(instruction.results, [flow::ValueId(expected_result)]);
            assert!(matches!(
                instruction.operation,
                flow::FlowOperation::Binary {
                    op,
                    left: flow::ValueId(0),
                    right: flow::ValueId(1),
                } if op == expected_op
            ));
            let semantic::SemanticStatement::Let(source_statement) =
                &semantic.functions[1].body.statements[index]
            else {
                panic!("source scalar binary statement");
            };
            assert_eq!(instruction.source, source_statement.source);
            assert_eq!(
                unsigned.values[expected_result as usize].source,
                semantic.functions[1].values[expected_result as usize].origin
            );
            assert_eq!(
                unsigned.values[expected_result as usize].source_name,
                semantic.functions[1].values[expected_result as usize].name
            );
        }
        assert!(matches!(
            unsigned.blocks[0].terminator,
            flow::Terminator::Return(ref values) if values.as_slice() == [flow::ValueId(7)]
        ));

        let signed = &wir.functions[2];
        assert!(matches!(
            signed.blocks[0].instructions.as_slice(),
            [
                flow::Instruction {
                    operation: flow::FlowOperation::Binary {
                        op: flow::BinaryOp::AddWrapping,
                        left: flow::ValueId(0),
                        right: flow::ValueId(1),
                    },
                    source: Some(first_source),
                    ..
                },
                flow::Instruction {
                    operation: flow::FlowOperation::Binary {
                        op: flow::BinaryOp::Less,
                        left: flow::ValueId(0),
                        right: flow::ValueId(1),
                    },
                    source: Some(second_source),
                    ..
                }
            ] if *first_source == span(0, 494, 497)
                && *second_source == span(0, 498, 501)
        ));

        let float32 = &wir.functions[3].blocks[0].instructions;
        assert!(matches!(
            float32.as_slice(),
            [
                flow::Instruction {
                    operation: flow::FlowOperation::Immediate(flow::Immediate::Float32(one)),
                    ..
                },
                flow::Instruction {
                    operation: flow::FlowOperation::Immediate(flow::Immediate::Float32(two)),
                    ..
                },
                flow::Instruction {
                    operation: flow::FlowOperation::Binary {
                        op: flow::BinaryOp::Less,
                        ..
                    },
                    ..
                }
            ] if *one == 1.0_f32.to_bits() && *two == 2.0_f32.to_bits()
        ));
        let float64 = &wir.functions[4].blocks[0].instructions;
        assert!(matches!(
            float64.as_slice(),
            [
                flow::Instruction {
                    operation: flow::FlowOperation::Immediate(flow::Immediate::Float64(one)),
                    ..
                },
                flow::Instruction {
                    operation: flow::FlowOperation::Immediate(flow::Immediate::Float64(two)),
                    ..
                },
                flow::Instruction {
                    operation: flow::FlowOperation::Binary {
                        op: flow::BinaryOp::GreaterEqual,
                        ..
                    },
                    ..
                }
            ] if *one == 1.0_f64.to_bits() && *two == 2.0_f64.to_bits()
        ));

        assert_eq!(wir.proofs.len(), semantic.proofs.len());
        assert_eq!(
            wir.proofs
                .iter()
                .map(|proof| proof.id.0)
                .collect::<Vec<_>>(),
            semantic
                .proofs
                .iter()
                .map(|proof| proof.id.0)
                .collect::<Vec<_>>()
        );
        let source_test = &semantic.tests[0];
        let lowered_test = &wir.tests[0];
        assert_eq!(lowered_test.id.0, source_test.id.0);
        assert_eq!(lowered_test.plan_id, source_test.plan_id);
        assert_eq!(lowered_test.name, source_test.name);
        assert_eq!(lowered_test.function.0, source_test.function.0);
        assert_eq!(lowered_test.source, source_test.source);
        assert_eq!(lowered_test.timeout_ns, source_test.timeout_ns);
        assert_eq!(
            lowered_test.function_key,
            semantic.functions[source_test.function.0 as usize].instance_key
        );
        assert_eq!(wir.compiled_test_group, semantic.compiled_test_group);
        assert_eq!(wir.image_entry, flow::FunctionId(5));
        assert_eq!(
            output.report(),
            &LoweringReport {
                source_functions: 6,
                generated_functions: 0,
                blocks: 9,
                instructions: 35,
                async_states: 0,
                cleanup_edges: 0,
                output_proofs: 7,
            }
        );
    }

    #[test]
    fn producer_scalar_unary_subset_lowers_with_integer_negation() {
        let mut input = scalar_unary_generated_fixture().into_wir();
        let semantic::SemanticStatement::Let(operation) =
            &mut input.functions[2].body.statements[0]
        else {
            panic!("signed unary statement")
        };
        operation.operation = semantic::SemanticOperation::Unary {
            operator: semantic::UnaryOperator::Negate,
            operand: semantic::ValueId(0),
            arithmetic: semantic::ArithmeticMode::Checked,
        };
        let output = CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: input.validate().expect("structural signed integer negate"),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("exact scalar unary subset lowers");
        let wir = output.wir().as_wir();
        assert!(matches!(
            wir.functions[2].blocks[0].instructions[0].operation,
            flow::FlowOperation::Unary {
                op: flow::UnaryOp::Negate,
                value: flow::ValueId(0),
            }
        ));
        assert!(matches!(
            wir.functions[3].blocks[0].instructions[2].operation,
            flow::FlowOperation::Unary {
                op: flow::UnaryOp::BoolNot,
                value: flow::ValueId(0),
            }
        ));
        assert!(matches!(
            wir.functions[4].blocks[0].instructions[2].operation,
            flow::FlowOperation::Unary {
                op: flow::UnaryOp::Negate,
                value: flow::ValueId(0),
            }
        ));
    }

    #[test]
    fn scalar_conversions_preserve_exact_and_checked_modes() {
        let output = CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: scalar_conversion_generated_fixture(),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("universally exact conversions lower");
        let wir = output.wir().as_wir();
        assert!(matches!(
            wir.functions[2].blocks[0].instructions[0].operation,
            flow::FlowOperation::Cast {
                value: flow::ValueId(0),
                to: flow::TypeId(6),
                mode: flow::CastMode::Exact,
            }
        ));
        assert!(matches!(
            wir.functions[3].blocks[0].instructions[2].operation,
            flow::FlowOperation::Cast {
                value: flow::ValueId(0),
                to: flow::TypeId(6),
                mode: flow::CastMode::Exact,
            }
        ));
        assert!(wir.functions.iter().all(|function| {
            function
                .blocks
                .iter()
                .flat_map(|block| &block.instructions)
                .all(|instruction| {
                    !matches!(
                        instruction.operation,
                        flow::FlowOperation::Cast {
                            mode: flow::CastMode::Bitcast,
                            ..
                        }
                    )
                })
        }));

        let mut checked = scalar_conversion_generated_fixture().into_wir();
        let semantic::SemanticStatement::Let(operation) =
            &mut checked.functions[3].body.statements[2]
        else {
            panic!("checked conversion")
        };
        let semantic::SemanticOperation::Convert {
            checked: checked_flag,
            ..
        } = &mut operation.operation
        else {
            panic!("checked conversion operation")
        };
        *checked_flag = true;
        let checked_output = CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: checked.validate().expect("structural checked conversion"),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("checked numeric conversion lowers");
        assert!(matches!(
            checked_output.wir().as_wir().functions[3].blocks[0].instructions[2].operation,
            flow::FlowOperation::Cast {
                value: flow::ValueId(0),
                to: flow::TypeId(6),
                mode: flow::CastMode::Checked,
            }
        ));

        let mut lossy = scalar_binary_generated_fixture().into_wir();
        let function = &mut lossy.functions[4];
        function.result = semantic::TypeId(5);
        function.values[2].ty = semantic::TypeId(5);
        let semantic::SemanticStatement::Let(operation) = &mut function.body.statements[2] else {
            panic!("lossy conversion")
        };
        operation.operation = semantic::SemanticOperation::Convert {
            value: semantic::ValueId(0),
            destination: semantic::TypeId(5),
            checked: false,
        };
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: lossy.validate().expect("structural lossy conversion"),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            ),
            Err(LowerError::UnsupportedInput {
                feature: "lossy scalar conversion without universally exact lowering",
            })
        ));
    }

    #[test]
    fn checked_integer_binary_operations_lower_exact_flow_operators() {
        let cases = [
            (semantic::BinaryOperator::Add, flow::BinaryOp::AddChecked),
            (
                semantic::BinaryOperator::Subtract,
                flow::BinaryOp::SubChecked,
            ),
            (
                semantic::BinaryOperator::Multiply,
                flow::BinaryOp::MulChecked,
            ),
            (semantic::BinaryOperator::Divide, flow::BinaryOp::DivChecked),
            (
                semantic::BinaryOperator::Remainder,
                flow::BinaryOp::RemChecked,
            ),
            (
                semantic::BinaryOperator::ShiftLeft,
                flow::BinaryOp::ShiftLeftChecked,
            ),
            (
                semantic::BinaryOperator::ShiftRight,
                flow::BinaryOp::ShiftRightChecked,
            ),
        ];
        for (operator, expected) in cases {
            let mut input = scalar_binary_generated_fixture().into_wir();
            let semantic::SemanticStatement::Let(statement) =
                &mut input.functions[1].body.statements[0]
            else {
                panic!("scalar binary statement");
            };
            statement.operation = semantic::SemanticOperation::Binary {
                operator,
                left: semantic::ValueId(0),
                right: semantic::ValueId(1),
                arithmetic: semantic::ArithmeticMode::Checked,
            };
            let output = CanonicalFlowLowerer::new()
                .lower(
                    LowerRequest {
                        input: input
                            .validate()
                            .expect("structural checked scalar operation"),
                        limits: LoweringLimits::standard(),
                    },
                    &|| false,
                )
                .expect("checked scalar operation lowers");
            assert!(matches!(
                output.wir().as_wir().functions[1].blocks[0].instructions[0].operation,
                flow::FlowOperation::Binary { op, .. } if op == expected
            ));
        }
    }

    #[test]
    fn wrapping_left_shift_lowers_to_the_distinct_flow_operation() {
        let mut input = scalar_binary_generated_fixture().into_wir();
        let semantic::SemanticStatement::Let(statement) =
            &mut input.functions[1].body.statements[0]
        else {
            panic!("scalar binary statement");
        };
        statement.operation = semantic::SemanticOperation::Binary {
            operator: semantic::BinaryOperator::ShiftLeft,
            left: semantic::ValueId(0),
            right: semantic::ValueId(1),
            arithmetic: semantic::ArithmeticMode::Wrapping,
        };
        let output = CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: input.validate().expect("structural wrapping left shift"),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("wrapping left shift lowers");
        assert!(matches!(
            output.wir().as_wir().functions[1].blocks[0].instructions[0].operation,
            flow::FlowOperation::Binary {
                op: flow::BinaryOp::ShiftLeftWrapping,
                ..
            }
        ));
    }

    #[test]
    fn scalar_binary_malformed_and_unsupported_substitutions_fail_closed() {
        let mut wrapping_division = scalar_binary_generated_fixture().into_wir();
        let semantic::SemanticStatement::Let(statement) =
            &mut wrapping_division.functions[1].body.statements[0]
        else {
            panic!("scalar binary statement");
        };
        let semantic::SemanticOperation::Binary { operator, .. } = &mut statement.operation else {
            panic!("scalar binary operation");
        };
        *operator = semantic::BinaryOperator::Divide;
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: wrapping_division
                        .validate()
                        .expect("structural wrapping scalar division"),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            ),
            Err(LowerError::UnsupportedInput {
                feature: "noncanonical wrapping scalar binary operation",
            })
        ));

        let mut wrong_result = scalar_binary_generated_fixture().into_wir();
        wrong_result.functions[1].values[2].ty = semantic::TypeId(1);
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: wrong_result
                        .validate()
                        .expect("structural scalar result-type substitution"),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            ),
            Err(LowerError::UnsupportedInput {
                feature: "integer scalar binary type contract",
            })
        ));

        let mut unary = scalar_binary_generated_fixture().into_wir();
        let semantic::SemanticStatement::Let(statement) =
            &mut unary.functions[1].body.statements[0]
        else {
            panic!("scalar add");
        };
        statement.operation = semantic::SemanticOperation::Unary {
            operator: semantic::UnaryOperator::Negate,
            operand: semantic::ValueId(0),
            arithmetic: semantic::ArithmeticMode::Wrapping,
        };
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: unary.validate().expect("structural scalar unary"),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            ),
            Err(LowerError::UnsupportedInput {
                feature: "noncanonical scalar unary operation",
            })
        ));

        let mut conversion = scalar_binary_generated_fixture().into_wir();
        let semantic::SemanticStatement::Let(statement) =
            &mut conversion.functions[1].body.statements[0]
        else {
            panic!("scalar add");
        };
        statement.operation = semantic::SemanticOperation::Convert {
            value: semantic::ValueId(0),
            destination: semantic::TypeId(2),
            checked: false,
        };
        let conversion_output = CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: conversion
                        .validate()
                        .expect("structural exact scalar conversion"),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("unchecked identity conversion is universally exact");
        assert!(matches!(
            conversion_output.wir().as_wir().functions[1].blocks[0].instructions[0].operation,
            flow::FlowOperation::Cast {
                value: flow::ValueId(0),
                to: flow::TypeId(2),
                mode: flow::CastMode::Exact,
            }
        ));

        let mut async_select = scalar_binary_generated_fixture().into_wir();
        let semantic::SemanticStatement::Let(statement) =
            &mut async_select.functions[1].body.statements[0]
        else {
            panic!("scalar add");
        };
        statement.operation = semantic::SemanticOperation::Select {
            awaitables: vec![semantic::ValueId(0), semantic::ValueId(1)],
        };
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: async_select
                        .validate()
                        .expect("structural asynchronous semantic select"),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            ),
            Err(LowerError::UnsupportedInput {
                feature: "non-scalar source operation",
            })
        ));

        let mut float_not_equal = scalar_binary_generated_fixture().into_wir();
        let semantic::SemanticStatement::Let(statement) =
            &mut float_not_equal.functions[4].body.statements[2]
        else {
            panic!("f64 comparison");
        };
        let semantic::SemanticOperation::Binary { operator, .. } = &mut statement.operation else {
            panic!("f64 binary comparison");
        };
        *operator = semantic::BinaryOperator::NotEqual;
        let float_not_equal = CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: float_not_equal
                        .validate()
                        .expect("structural f64 not-equal"),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("NaN-correct f64 not-equal lowers after the downstream predicate seal");
        assert!(matches!(
            float_not_equal.wir().as_wir().functions[4].blocks[0].instructions[2].operation,
            flow::FlowOperation::Binary {
                op: flow::BinaryOp::NotEqual,
                left: flow::ValueId(0),
                right: flow::ValueId(1),
            }
        ));

        let mut bool_ordering = scalar_binary_generated_fixture().into_wir();
        let semantic::SemanticStatement::Let(statement) =
            &mut bool_ordering.functions[0].body.statements[0]
        else {
            panic!("bool constant");
        };
        statement.operation = semantic::SemanticOperation::Binary {
            operator: semantic::BinaryOperator::Less,
            left: semantic::ValueId(0),
            right: semantic::ValueId(0),
            arithmetic: semantic::ArithmeticMode::Checked,
        };
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: bool_ordering.validate().expect("structural bool ordering"),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            ),
            Err(LowerError::UnsupportedInput {
                feature: "scalar comparison operand contract",
            })
        ));
    }

    #[test]
    fn scalar_binary_enforces_exact_limits_max_plus_one_and_late_cancellation() {
        let mut exact = LoweringLimits::standard();
        exact.blocks = 9;
        exact.instructions = 35;
        CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: scalar_binary_generated_fixture(),
                    limits: exact,
                },
                &|| false,
            )
            .expect("exact scalar binary limits");

        let mut blocks = exact;
        blocks.blocks = 8;
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: scalar_binary_generated_fixture(),
                    limits: blocks,
                },
                &|| false,
            ),
            Err(LowerError::ResourceLimit {
                resource: "FlowWir blocks",
                limit: 8,
            })
        ));
        let mut instructions = exact;
        instructions.instructions = 34;
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: scalar_binary_generated_fixture(),
                    limits: instructions,
                },
                &|| false,
            ),
            Err(LowerError::ResourceLimit {
                resource: "FlowWir instructions",
                limit: 34,
            })
        ));

        let polls = Cell::new(0_u32);
        CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: scalar_binary_generated_fixture(),
                    limits: exact,
                },
                &|| {
                    polls.set(polls.get() + 1);
                    false
                },
            )
            .expect("count scalar binary cancellation polls");
        let cancel_at = polls.get();
        let polls = Cell::new(0_u32);
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: scalar_binary_generated_fixture(),
                    limits: exact,
                },
                &|| {
                    let next = polls.get() + 1;
                    polls.set(next);
                    next == cancel_at
                },
            ),
            Err(LowerError::Cancelled)
        ));
        assert_eq!(polls.get(), cancel_at);
    }

    #[test]
    fn scalar_source_closure_rejects_argument_type_id_and_branch_corruption() {
        let mut wrong_type = scalar_generated_fixture().into_wir();
        let semantic::SemanticStatement::If { then_region, .. } =
            &mut wrong_type.functions[0].body.statements[3]
        else {
            panic!("scalar branch");
        };
        let semantic::SemanticStatement::Let(semantic::LetStatement {
            operation: semantic::SemanticOperation::Call { arguments, .. },
            ..
        }) = &mut then_region.statements[0]
        else {
            panic!("scalar call");
        };
        arguments[0].value = semantic::ValueId(0);
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: wrong_type.validate().expect("structural wrong-type call"),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            ),
            Err(LowerError::UnsupportedInput {
                feature: "scalar call arguments",
            })
        ));

        let mut wrong_target = scalar_generated_fixture().into_wir();
        let semantic::SemanticStatement::If { then_region, .. } =
            &mut wrong_target.functions[0].body.statements[3]
        else {
            panic!("scalar branch");
        };
        let semantic::SemanticStatement::Let(semantic::LetStatement {
            operation: semantic::SemanticOperation::Call { function, .. },
            ..
        }) = &mut then_region.statements[0]
        else {
            panic!("scalar call");
        };
        *function = semantic::FunctionId(0);
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: wrong_target
                        .validate()
                        .expect("structural wrong-target call"),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            ),
            Err(LowerError::UnsupportedInput {
                feature: "scalar call target",
            })
        ));

        let mut wrong_branch = scalar_generated_fixture().into_wir();
        let semantic::SemanticStatement::If { condition, .. } =
            &mut wrong_branch.functions[0].body.statements[3]
        else {
            panic!("scalar branch");
        };
        *condition = semantic::ValueId(1);
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: wrong_branch
                        .validate()
                        .expect("structural wrong branch type"),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            ),
            Err(LowerError::UnsupportedInput {
                feature: "scalar branch condition type",
            })
        ));
    }

    #[test]
    fn scalar_flow_seal_rejects_same_typed_argument_permutation() {
        let input = scalar_generated_fixture();
        let output = CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: input.clone(),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("baseline scalar lowering");
        let mut permuted = output.wir().as_wir().clone();
        let flow::FlowOperation::Call { arguments, .. } =
            &mut permuted.functions[0].blocks[1].instructions[0].operation
        else {
            panic!("scalar call");
        };
        arguments.swap(0, 1);
        assert!(matches!(
            seal(
                &LowerRequest {
                    input,
                    limits: LoweringLimits::standard(),
                },
                permuted,
                output.report().clone(),
                Vec::new(),
                &|| false,
            ),
            Err(LowerError::InvalidReport(_))
        ));
    }

    #[test]
    fn scalar_cfg_enforces_exact_block_instruction_depth_limits_and_late_cancellation() {
        let mut exact = LoweringLimits::standard();
        exact.blocks = 6;
        exact.instructions = 16;
        exact.region_depth = 2;
        CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: scalar_generated_fixture(),
                    limits: exact,
                },
                &|| false,
            )
            .expect("exact scalar CFG limits");

        let mut blocks = exact;
        blocks.blocks = 5;
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: scalar_generated_fixture(),
                    limits: blocks,
                },
                &|| false,
            ),
            Err(LowerError::ResourceLimit {
                resource: "FlowWir blocks",
                limit: 5,
            })
        ));
        let mut instructions = exact;
        instructions.instructions = 15;
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: scalar_generated_fixture(),
                    limits: instructions,
                },
                &|| false,
            ),
            Err(LowerError::ResourceLimit {
                resource: "FlowWir instructions",
                limit: 15,
            })
        ));
        let mut depth = exact;
        depth.region_depth = 1;
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: scalar_generated_fixture(),
                    limits: depth,
                },
                &|| false,
            ),
            Err(LowerError::ResourceLimit {
                resource: "semantic region depth",
                limit: 1,
            })
        ));

        let polls = Cell::new(0_u32);
        CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: scalar_generated_fixture(),
                    limits: exact,
                },
                &|| {
                    polls.set(polls.get() + 1);
                    false
                },
            )
            .expect("count scalar lowering cancellation polls");
        let cancel_at = polls.get();
        let polls = Cell::new(0_u32);
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: scalar_generated_fixture(),
                    limits: exact,
                },
                &|| {
                    let next = polls.get() + 1;
                    polls.set(next);
                    next == cancel_at
                },
            ),
            Err(LowerError::Cancelled)
        ));
        assert_eq!(polls.get(), cancel_at);
    }

    #[test]
    fn declared_test_group_image_uses_the_exact_declared_image_lowering() {
        let mut declared = fixture().into_wir();
        declared.name = "declared-scenario-image".to_owned();
        let group = wrela_test_model::FullImageTestGroup {
            id: wrela_test_model::ImageGroupId(4),
            name: "declared-scenario".to_owned(),
            root: wrela_test_model::ImageRoot::Declared {
                image_name: declared.name.clone(),
                scenario: wrela_test_model::ScenarioId(3),
            },
            tests: vec![wrela_test_model::ImageTest {
                descriptor: wrela_test_model::TestDescriptor {
                    id: wrela_test_model::TestId(19),
                    name: "declared-scenario".to_owned(),
                    kind: wrela_test_model::TestKind::DeclaredImage,
                    source: None,
                    timeout_ns: 30,
                },
                invocation: wrela_test_model::ImageTestInvocation::DeclaredScenario,
                assertions: Vec::new(),
            }],
            deterministic_seed: Some(7),
            boot_timeout_ns: 10,
            shutdown_timeout_ns: 10,
            maximum_events: 8,
            maximum_output_bytes: 4096,
        };
        declared.compiled_test_group = Some(group.clone());
        let output = CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: declared.validate().expect("declared test image"),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("declared test group FlowWir lowering");
        let wir = output.wir().as_wir();
        assert_eq!(wir.name, "declared-scenario-image");
        assert_eq!(wir.compiled_test_group.as_ref(), Some(&group));
        assert!(wir.tests.is_empty());
        assert!(wir.functions[0].blocks[0].instructions.is_empty());
        assert!(matches!(
            wir.functions[0].blocks[0].terminator,
            flow::Terminator::Return(ref values) if values.is_empty()
        ));
    }

    #[test]
    fn generated_group_rejects_identity_order_and_terminal_corruption() {
        let mut wrong_name = generated_fixture().into_wir();
        wrong_name.tests[0].name = "different".to_owned();
        assert!(wrong_name.validate().is_err());

        let mut wrong_call = generated_fixture().into_wir();
        let semantic::SemanticStatement::Let(call) =
            &mut wrong_call.functions[2].body.statements[4]
        else {
            panic!("first generated test call");
        };
        call.operation = semantic::SemanticOperation::Call {
            function: semantic::FunctionId(1),
            arguments: Vec::new(),
            activation: None,
        };
        let wrong_call = wrong_call
            .validate()
            .expect("structurally valid call mismatch");
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: wrong_call,
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            ),
            Err(LowerError::UnsupportedInput {
                feature: "generated test harness calls",
            })
        ));

        let mut wrong_finish = generated_fixture().into_wir();
        wrong_finish.functions[2].body.statements[16] =
            semantic::SemanticStatement::Return(Vec::new());
        let wrong_finish = wrong_finish
            .validate()
            .expect("structurally valid terminal mismatch");
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: wrong_finish,
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            ),
            Err(LowerError::UnsupportedInput { .. })
        ));
    }

    #[test]
    fn generated_group_sealer_rejects_frame_operation_and_metadata_substitution() {
        let input = generated_fixture();
        let output = CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: input.clone(),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("baseline generated test lowering");
        let baseline = output.wir().as_wir().clone();
        let request = LowerRequest {
            input,
            limits: LoweringLimits::standard(),
        };

        let mut wrong_frame = baseline.clone();
        let flow::FlowOperation::Immediate(flow::Immediate::Bytes(bytes)) =
            &mut wrong_frame.functions[2].blocks[0].instructions[0].operation
        else {
            panic!("run-start frame");
        };
        bytes[8] ^= 0xff;
        assert!(matches!(
            seal(
                &request,
                wrong_frame,
                output.report().clone(),
                Vec::new(),
                &|| false,
            ),
            Err(LowerError::InvalidReport(_))
        ));

        let mut wrong_operation = baseline.clone();
        wrong_operation.functions[2].blocks[0].instructions[1].operation =
            flow::FlowOperation::RecordEvent {
                kind: 0,
                payload: flow::ValueId(0),
            };
        assert!(matches!(
            seal(
                &request,
                wrong_operation,
                output.report().clone(),
                Vec::new(),
                &|| false,
            ),
            Err(LowerError::InvalidReport(_))
        ));

        let mut wrong_metadata = baseline;
        wrong_metadata.tests[0].timeout_ns += 1;
        assert!(matches!(
            seal(
                &request,
                wrong_metadata,
                output.report().clone(),
                Vec::new(),
                &|| false,
            ),
            Err(LowerError::InvalidOutput(_))
        ));
    }

    #[test]
    fn generated_group_obeys_instruction_payload_and_cancellation_limits() {
        let mut instruction_limits = LoweringLimits::standard();
        instruction_limits.instructions = 15;
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: generated_fixture(),
                    limits: instruction_limits,
                },
                &|| false,
            ),
            Err(LowerError::ResourceLimit {
                resource: "FlowWir instructions",
                limit: 15,
            })
        ));

        let mut payload_limits = LoweringLimits::standard();
        payload_limits.payload_bytes = 250;
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: generated_fixture(),
                    limits: payload_limits,
                },
                &|| false,
            ),
            Err(LowerError::ResourceLimit {
                resource: "semantic payload bytes",
                limit: 250,
            })
        ));

        let polls = Cell::new(0u32);
        let cancel_during_harness = || {
            let poll = polls.get();
            polls.set(poll + 1);
            poll >= 35
        };
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: generated_fixture(),
                    limits: LoweringLimits::standard(),
                },
                &cancel_during_harness,
            ),
            Err(LowerError::Cancelled)
        ));
        assert!(polls.get() >= 36);
    }

    #[test]
    fn sealer_rejects_origin_proof_kind_and_source_substitution() {
        let input = fixture();
        let output = CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: input.clone(),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("baseline lowering");
        let baseline = output.wir().as_wir().clone();
        let request = LowerRequest {
            input,
            limits: LoweringLimits::standard(),
        };

        let mut wrong_origin = baseline.clone();
        wrong_origin.functions[0].origin = flow::FunctionOrigin::GeneratedImageEntry {
            semantic_function: 0,
            constructor: 2,
        };
        assert!(matches!(
            seal(
                &request,
                wrong_origin,
                output.report().clone(),
                Vec::new(),
                &|| false,
            ),
            Err(LowerError::InvalidReport(_))
        ));

        let mut missing_function_proof = baseline.clone();
        missing_function_proof.functions[0].proofs.pop();
        assert!(matches!(
            seal(
                &request,
                missing_function_proof,
                output.report().clone(),
                Vec::new(),
                &|| false,
            ),
            Err(LowerError::InvalidReport(_))
        ));

        let mut reordered_function_proofs = baseline.clone();
        reordered_function_proofs.functions[0].proofs.swap(0, 1);
        assert!(matches!(
            seal(
                &request,
                reordered_function_proofs,
                output.report().clone(),
                Vec::new(),
                &|| false,
            ),
            Err(LowerError::InvalidOutput(_))
        ));

        let mut wrong_kind = baseline.clone();
        wrong_kind.proofs[1].kind = flow::ProofKind::Ownership;
        assert!(matches!(
            seal(
                &request,
                wrong_kind,
                output.report().clone(),
                Vec::new(),
                &|| false,
            ),
            Err(LowerError::InvalidReport(_))
        ));

        let mut wrong_sources = baseline;
        wrong_sources.proofs[0].sources = vec![span(1, 90, 91)];
        assert!(matches!(
            seal(
                &request,
                wrong_sources,
                output.report().clone(),
                Vec::new(),
                &|| false,
            ),
            Err(LowerError::InvalidReport(_))
        ));
    }

    #[test]
    fn proof_kinds_map_one_to_one_without_relabeling() {
        let cases = [
            semantic::ProofKind::TypeChecked,
            semantic::ProofKind::EffectsAllowed,
            semantic::ProofKind::DefiniteInitialization,
            semantic::ProofKind::Ownership,
            semantic::ProofKind::AccessExclusive,
            semantic::ProofKind::ViewDoesNotEscape,
            semantic::ProofKind::RegionBound,
            semantic::ProofKind::CapacityBound,
            semantic::ProofKind::WaitGraphAcyclic,
            semantic::ProofKind::CleanupAcyclic,
            semantic::ProofKind::WorkBound,
            semantic::ProofKind::StackBound,
            semantic::ProofKind::IsrSafe,
            semantic::ProofKind::DmaTransition,
            semantic::ProofKind::MmioPartition,
            semantic::ProofKind::DeviceValueValidated,
            semantic::ProofKind::WireLayout,
            semantic::ProofKind::ReceiptLineage,
            semantic::ProofKind::ActorAsIf,
            semantic::ProofKind::SupervisionComplete,
            semantic::ProofKind::ImageClosed,
        ];
        let expected = [
            flow::ProofKind::TypeChecked,
            flow::ProofKind::EffectsAllowed,
            flow::ProofKind::DefiniteInitialization,
            flow::ProofKind::Ownership,
            flow::ProofKind::AccessExclusive,
            flow::ProofKind::ViewDoesNotEscape,
            flow::ProofKind::RegionBound,
            flow::ProofKind::CapacityBound,
            flow::ProofKind::WaitGraphAcyclic,
            flow::ProofKind::CleanupAcyclic,
            flow::ProofKind::WorkBound,
            flow::ProofKind::StackBound,
            flow::ProofKind::IsrSafe,
            flow::ProofKind::DmaTransition,
            flow::ProofKind::MmioPartition,
            flow::ProofKind::DeviceValueValidated,
            flow::ProofKind::WireLayout,
            flow::ProofKind::ReceiptLineage,
            flow::ProofKind::ActorAsIf,
            flow::ProofKind::SupervisionComplete,
            flow::ProofKind::ImageClosed,
        ];
        for (source, expected) in cases.iter().zip(expected) {
            assert_eq!(lower_proof_kind(source), expected);
        }
    }

    #[test]
    fn resource_limits_and_cancellation_are_hard_failures() {
        let mut limits = LoweringLimits::standard();
        limits.model_edges = 1;
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: generated_fixture(),
                    limits,
                },
                &|| false,
            ),
            Err(LowerError::ResourceLimit {
                resource: "semantic model edges",
                limit: 1,
            })
        ));
        let mut limits = LoweringLimits::standard();
        limits.payload_bytes = 1;
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: fixture(),
                    limits,
                },
                &|| false,
            ),
            Err(LowerError::ResourceLimit {
                resource: "semantic payload bytes",
                limit: 1,
            })
        ));
        let mut limits = LoweringLimits::standard();
        limits.validation_work = 1;
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: generated_fixture(),
                    limits,
                },
                &|| false,
            ),
            Err(LowerError::ResourceLimit {
                resource: "validation work",
                limit: 1,
            })
        ));
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: fixture(),
                    limits: LoweringLimits::standard(),
                },
                &|| true,
            ),
            Err(LowerError::Cancelled)
        ));

        let polls = Cell::new(0u32);
        let cancel_during_proofs = || {
            let poll = polls.get();
            polls.set(poll + 1);
            poll >= 5
        };
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: fixture(),
                    limits: LoweringLimits::standard(),
                },
                &cancel_during_proofs,
            ),
            Err(LowerError::Cancelled)
        ));
        assert!(polls.get() >= 6);

        let polls = Cell::new(0_u32);
        CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: fixture(),
                    limits: LoweringLimits::standard(),
                },
                &|| {
                    polls.set(polls.get() + 1);
                    false
                },
            )
            .expect("uncancelled lowering establishes deterministic poll count");
        let cancel_at = polls.get();
        let polls = Cell::new(0_u32);
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: fixture(),
                    limits: LoweringLimits::standard(),
                },
                &|| {
                    let next = polls.get() + 1;
                    polls.set(next);
                    next == cancel_at
                },
            ),
            Err(LowerError::Cancelled)
        ));
        assert_eq!(polls.get(), cancel_at);
    }

    #[test]
    fn scalar_loop_requires_a_bound_covered_by_the_function_proof() {
        let mut module = scalar_generated_fixture().into_wir();
        let function = &mut module.functions[0];
        function.values.truncate(3);
        function.values.extend([
            scalar_source_value(3, 2, "loop_header", span(0, 350, 351)),
            scalar_source_value(4, 2, "loop_exit", span(0, 350, 351)),
        ]);
        function.body.statements.truncate(3);
        function.body.statements.extend([
            semantic::SemanticStatement::Loop {
                body: semantic::SemanticRegion {
                    parameters: vec![semantic::ValueId(3)],
                    statements: vec![semantic::SemanticStatement::Break(vec![semantic::ValueId(
                        3,
                    )])],
                },
                carried: vec![
                    semantic::ValueId(1),
                    semantic::ValueId(3),
                    semantic::ValueId(4),
                ],
                uninterrupted_bound: Some(5),
                source: Some(span(0, 350, 351)),
            },
            semantic::SemanticStatement::Return(Vec::new()),
        ]);
        let valid = module
            .clone()
            .validate()
            .expect("canonical scalar loop fixture");
        CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: valid,
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("bounded scalar loop lowers");

        let semantic::SemanticStatement::Loop {
            uninterrupted_bound,
            ..
        } = &mut module.functions[0].body.statements[3]
        else {
            unreachable!();
        };
        *uninterrupted_bound = None;
        let mut insufficient_proof = module.clone();
        let semantic::SemanticStatement::Loop {
            uninterrupted_bound,
            ..
        } = &mut insufficient_proof.functions[0].body.statements[3]
        else {
            unreachable!();
        };
        *uninterrupted_bound = Some(5);
        insufficient_proof.functions[0].uninterrupted_bound = Some(4);
        let insufficient_proof = insufficient_proof
            .validate()
            .expect("proof mutation preserves structural SemanticWir validity");
        assert!(
            CanonicalFlowLowerer::new()
                .lower(
                    LowerRequest {
                        input: insufficient_proof,
                        limits: LoweringLimits::standard(),
                    },
                    &|| false,
                )
                .is_err()
        );

        let missing = module.validate().expect("bound is a proof-layer contract");
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: missing,
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            ),
            Err(LowerError::UnsupportedInput {
                feature: "synchronous loop uninterrupted-work proof"
            })
        ));
    }

    #[test]
    fn unsupported_operations_and_structured_bodies_fail_explicitly() {
        let mut operation = fixture().into_wir();
        operation.functions[0].body.statements = vec![semantic::SemanticStatement::Unreachable];
        let operation = operation
            .validate()
            .expect("valid unsupported operation fixture");
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: operation,
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            ),
            Err(LowerError::UnsupportedInput {
                feature: "semantic operations or structured bodies",
            })
        ));

        let mut structured = fixture().into_wir();
        structured.functions[0].body.statements = vec![
            semantic::SemanticStatement::Loop {
                body: semantic::SemanticRegion {
                    parameters: Vec::new(),
                    statements: vec![semantic::SemanticStatement::Break(Vec::new())],
                },
                carried: Vec::new(),
                uninterrupted_bound: Some(1),
                source: None,
            },
            semantic::SemanticStatement::Return(Vec::new()),
        ];
        let structured = structured
            .validate()
            .expect("valid unsupported structured fixture");
        assert!(matches!(
            CanonicalFlowLowerer::new().lower(
                LowerRequest {
                    input: structured,
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            ),
            Err(LowerError::UnsupportedInput {
                feature: "semantic operations or structured bodies",
            })
        ));
    }
}
