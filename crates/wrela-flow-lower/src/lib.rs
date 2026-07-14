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
    FlowOperation, FlowWir, FunctionOrigin, FunctionRole, Terminator, ValidatedFlowWir,
    ValidationErrors,
};
use wrela_semantic_wir::{
    FunctionOrigin as SemanticFunctionOrigin, FunctionRole as SemanticFunctionRole,
    ValidatedSemanticWir,
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

/// Failure to produce a sealed FlowWir value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LowerError {
    Cancelled,
    InvalidLimits,
    ResourceLimit { resource: &'static str, limit: u64 },
    InvalidReport(&'static str),
    ErrorDiagnosticOnSuccess,
    InternalInvariant { operation: String, detail: String },
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
    validate_diagnostics(&diagnostics.diagnostics, request.limits)?;
    validate_model_resources(&wir, request.limits)?;
    let validated = wir.validate()?;
    validate_report(&request.input, &validated, &report, request.limits)?;
    if is_cancelled() {
        return Err(LowerError::Cancelled);
    }
    Ok(LowerOutput {
        validated,
        report,
        diagnostics: diagnostics.diagnostics,
    })
}

#[derive(Default)]
struct ResourceMeter {
    edges: u64,
    payload_bytes: u64,
    overflowed: bool,
}

impl ResourceMeter {
    fn edges<T>(&mut self, values: &[T]) {
        self.add_edges(values.len());
    }

    fn add_edges(&mut self, count: usize) {
        let Ok(count) = u64::try_from(count) else {
            self.overflowed = true;
            return;
        };
        if let Some(total) = self.edges.checked_add(count) {
            self.edges = total;
        } else {
            self.overflowed = true;
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
            self.overflowed = true;
            return;
        };
        if let Some(total) = self.payload_bytes.checked_add(count) {
            self.payload_bytes = total;
        } else {
            self.overflowed = true;
        }
    }
}

fn validate_model_resources(
    wir: &wrela_flow_wir::FlowWir,
    limits: LoweringLimits,
) -> Result<(), LowerError> {
    use wrela_flow_wir::{FlowOperation, FlowTypeKind, Immediate, Terminator};

    let mut meter = ResourceMeter::default();
    meter.text(&wir.name);
    for count in [
        wir.types.len(),
        wir.globals.len(),
        wir.functions.len(),
        wir.actors.len(),
        wir.tasks.len(),
        wir.devices.len(),
        wir.pools.len(),
        wir.regions.len(),
        wir.proofs.len(),
        wir.checkpoints.len(),
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
                    meter.edges(variant);
                }
            }
            FlowTypeKind::Function { parameters, .. } => meter.edges(parameters),
            FlowTypeKind::OpaqueTarget { name } => meter.text(name),
            FlowTypeKind::Unit
            | FlowTypeKind::Scalar(_)
            | FlowTypeKind::Array { .. }
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
        meter.text(&global.name);
        immediate(&global.initializer, &mut meter);
    }
    for function in &wir.functions {
        meter.text(&function.name);
        meter.edges(&function.parameters);
        meter.edges(&function.result_types);
        meter.edges(&function.values);
        meter.edges(&function.blocks);
        for value in &function.values {
            if let Some(name) = &value.source_name {
                meter.text(name);
            }
        }
        for block in &function.blocks {
            meter.edges(&block.parameters);
            meter.edges(&block.instructions);
            for instruction in &block.instructions {
                meter.edges(&instruction.results);
                match &instruction.operation {
                    FlowOperation::Immediate(value) => immediate(value, &mut meter),
                    FlowOperation::MakeAggregate { fields, .. }
                    | FlowOperation::Call {
                        arguments: fields, ..
                    }
                    | FlowOperation::TaskStart {
                        arguments: fields, ..
                    } => meter.edges(fields),
                    FlowOperation::Unary { .. }
                    | FlowOperation::Binary { .. }
                    | FlowOperation::Cast { .. }
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
                        meter.edges(&case.arguments);
                    }
                }
                Terminator::Suspend { .. } | Terminator::Trap { .. } | Terminator::Unreachable => {}
            }
        }
    }
    for actor in &wir.actors {
        meter.text(&actor.name);
        meter.edges(&actor.message_types);
        meter.edges(&actor.turn_functions);
    }
    for task in &wir.tasks {
        meter.text(&task.name);
    }
    for device in &wir.devices {
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
            meter.text(feature);
        }
    }
    for pool in &wir.pools {
        meter.text(&pool.name);
        meter.edges(&pool.devices);
    }
    for region in &wir.regions {
        meter.text(&region.name);
    }
    for proof in &wir.proofs {
        meter.text(&proof.subject);
        meter.edges(&proof.sources);
        meter.edges(&proof.depends_on);
        meter.edges(&proof.explanation);
        for line in &proof.explanation {
            meter.text(line);
        }
    }
    if meter.overflowed
        || meter.edges > limits.model_edges
        || meter.payload_bytes > limits.payload_bytes
    {
        return Err(LowerError::ResourceLimit {
            resource: "FlowWir model edges or payload bytes",
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
) -> Result<(), LowerError> {
    let input = input.as_wir();
    let output = output.as_wir();
    if input.build != output.build || input.name != output.name {
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
        && output.source_summary.reachable_declarations
            == input.source_summary.reachable_declarations
        && output.source_summary.monomorphized_instantiations
            == input.source_summary.monomorphized_instantiations
        && output.source_summary.resolved_interface_calls
            == input.source_summary.resolved_interface_calls;
    let mut lowered_by_semantic_function = std::collections::BTreeMap::new();
    for function in &output.functions {
        let semantic_function = match function.origin {
            FunctionOrigin::SourceSemantic { semantic_function }
            | FunctionOrigin::GeneratedTestHarness {
                semantic_function, ..
            } => Some(semantic_function),
            FunctionOrigin::GeneratedAsyncState { .. }
            | FunctionOrigin::GeneratedCleanup { .. } => None,
        };
        if let Some(semantic_function) = semantic_function {
            lowered_by_semantic_function
                .entry(semantic_function)
                .or_insert(function);
        }
    }
    let base_functions_match = input.functions.iter().enumerate().all(|(index, source)| {
        u32::try_from(index)
            .ok()
            .and_then(|index| lowered_by_semantic_function.get(&index).copied())
            .is_some_and(|function| {
                semantic_function_contract_matches(source, function, index as u32)
            })
    });
    let image_plan_matches = flow_plan_matches(input, output);
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
        || blocks.is_none_or(|count| count > limits.blocks)
        || instructions.is_none_or(|count| count > limits.instructions)
        || !states_within_limit
        || semantic_region_depth(input, limits.region_depth).is_none()
    {
        Err(LowerError::InvalidReport(
            "reported counts do not match input and validated FlowWir",
        ))
    } else {
        Ok(())
    }
}

fn flow_plan_matches(
    input: &wrela_semantic_wir::SemanticWir,
    output: &wrela_flow_wir::FlowWir,
) -> bool {
    output.static_bytes == input.static_bytes
        && output.peak_bytes == input.peak_bytes
        && output.image_entry.0 == input.image_entry.0
        && input
            .actors
            .iter()
            .zip(&output.actors)
            .all(|(source, out)| {
                out.id.0 == source.id.0
                    && out.name == source.name
                    && out.state_type.0 == source.ty.0
                    && out.priority == source.priority
                    && out.mailbox_capacity == source.mailbox_capacity
                    && out
                        .message_types
                        .iter()
                        .map(|id| id.0)
                        .eq(source.message_types.iter().map(|id| id.0))
                    && out
                        .turn_functions
                        .iter()
                        .map(|id| id.0)
                        .eq(source.turn_functions.iter().map(|id| id.0))
                    && out.supervisor.map(|id| id.0) == source.supervisor.map(|id| id.0)
            })
        && input.actors.len() == output.actors.len()
        && input.tasks.iter().zip(&output.tasks).all(|(source, out)| {
            out.id.0 == source.id.0
                && out.name == source.name
                && out.entry.0 == source.entry.0
                && out.slots == source.slots
                && out.priority == source.priority
                && out.supervisor.map(|id| id.0) == source.supervisor.map(|id| id.0)
                && output
                    .functions
                    .get(out.entry.0 as usize)
                    .is_some_and(|function| function.frame_bound == out.frame_bytes_bound)
        })
        && input.tasks.len() == output.tasks.len()
        && input
            .devices
            .iter()
            .zip(&output.devices)
            .all(|(source, out)| {
                out.id.0 == source.id.0
                    && out.name == source.name
                    && out.target_binding == source.target_binding
                    && out.owner.0 == source.owner.0
                    && out.required_features == source.required_features
                    && out.optional_features == source.optional_features
                    && out
                        .interrupt_functions
                        .iter()
                        .map(|id| id.0)
                        .eq(source.interrupt_functions.iter().map(|id| id.0))
                    && out.queue_capacity == source.queue_capacity
                    && out.maximum_in_flight == source.maximum_in_flight
                    && out.reset_timeout_ns == source.reset_timeout_ns
            })
        && input.devices.len() == output.devices.len()
        && input.pools.iter().zip(&output.pools).all(|(source, out)| {
            out.id.0 == source.id.0
                && out.name == source.name
                && out.element_type.0 == source.payload.0
                && out.capacity == source.capacity
                && out.alignment == source.alignment
                && out
                    .devices
                    .iter()
                    .map(|id| id.0)
                    .eq(source.reachable_devices.iter().map(|id| id.0))
        })
        && input.pools.len() == output.pools.len()
        && input
            .regions
            .iter()
            .zip(&output.regions)
            .all(|(source, out)| {
                out.id.0 == source.id.0
                    && out.name == source.name
                    && out.capacity_bytes == source.capacity_bytes
                    && out.alignment == source.alignment
                    && flow_owner_matches(out.owner, source.owner)
            })
        && input.regions.len() == output.regions.len()
        && output
            .startup_order
            .iter()
            .zip(&input.startup_order)
            .all(|(out, source)| flow_owner_matches(*out, *source))
        && output.startup_order.len() == input.startup_order.len()
        && output
            .shutdown_order
            .iter()
            .zip(&input.shutdown_order)
            .all(|(out, source)| flow_owner_matches(*out, *source))
        && output.shutdown_order.len() == input.shutdown_order.len()
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
) -> bool {
    let origin = match source.origin {
        SemanticFunctionOrigin::Source => FunctionOrigin::SourceSemantic { semantic_function },
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
    output.name == source.name
        && output.origin == origin
        && output.role == role
        && output.stack_bound == source.stack_bound
        && output.frame_bound == source.frame_bound
        && output.source == source.source
}

fn validate_diagnostics(
    diagnostics: &[Diagnostic],
    limits: LoweringLimits,
) -> Result<(), LowerError> {
    let mut bytes = 0u64;
    for diagnostic in diagnostics {
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

fn semantic_region_depth(input: &wrela_semantic_wir::SemanticWir, maximum: u32) -> Option<u32> {
    input.functions.iter().try_fold(0u32, |seen, function| {
        region_depth(&function.body, 1, maximum).map(|depth| seen.max(depth))
    })
}

fn region_depth(
    region: &wrela_semantic_wir::SemanticRegion,
    depth: u32,
    maximum: u32,
) -> Option<u32> {
    if depth > maximum {
        return None;
    }
    region.statements.iter().try_fold(depth, |seen, statement| {
        let nested = match statement {
            wrela_semantic_wir::SemanticStatement::If {
                then_region,
                else_region,
                ..
            } => region_depth(then_region, depth + 1, maximum)?.max(region_depth(
                else_region,
                depth + 1,
                maximum,
            )?),
            wrela_semantic_wir::SemanticStatement::Match { arms, .. } => {
                arms.iter().try_fold(depth, |seen, arm| {
                    region_depth(&arm.body, depth + 1, maximum).map(|depth| seen.max(depth))
                })?
            }
            wrela_semantic_wir::SemanticStatement::Loop { body, .. } => {
                region_depth(body, depth + 1, maximum)?
            }
            _ => depth,
        };
        Some(seen.max(nested))
    })
}

#[cfg(test)]
mod contract_tests {
    use super::{LowerError, LoweringLimits};

    #[test]
    fn flow_lowering_policy_rejects_zero_capacity() {
        LoweringLimits::standard()
            .validate()
            .expect("standard limits");
        let mut limits = LoweringLimits::standard();
        limits.blocks = 0;
        assert!(matches!(limits.validate(), Err(LowerError::InvalidLimits)));
    }
}
