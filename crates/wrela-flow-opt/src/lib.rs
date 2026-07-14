//! Whole-image, semantics-preserving optimization over validated FlowWir.

#![forbid(unsafe_code)]

use std::fmt;

use wrela_build_model::{OptimizationLevel, Sha256Digest};
use wrela_flow_wir::{FlowWir, ProofId, ValidatedFlowWir, ValidationErrors};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OptimizationLimits {
    pub functions: u32,
    pub blocks: u64,
    pub instructions: u64,
    pub values: u64,
    pub proofs: u32,
    /// Total elements in mutable global/function-body collections.
    pub model_edges: u64,
    /// UTF-8 and immediate byte payload in mutable global/function bodies.
    pub payload_bytes: u64,
    pub passes: u32,
    pub decisions: u64,
    pub report_bytes: u64,
}

impl OptimizationLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            functions: 1_000_000,
            blocks: 16_000_000,
            instructions: 256_000_000,
            values: 256_000_000,
            proofs: 64_000_000,
            model_edges: 1_000_000_000,
            payload_bytes: 4 * 1024 * 1024 * 1024,
            passes: 1024,
            decisions: 64_000_000,
            report_bytes: 1024 * 1024 * 1024,
        }
    }

    pub fn validate(self) -> Result<(), OptimizeError> {
        if self.functions == 0
            || self.blocks == 0
            || self.instructions == 0
            || self.values == 0
            || self.proofs == 0
            || self.model_edges == 0
            || self.payload_bytes == 0
            || self.passes == 0
            || self.decisions == 0
            || self.report_bytes == 0
        {
            Err(OptimizeError::InvalidLimits)
        } else {
            Ok(())
        }
    }
}

impl OptimizationProfile {
    pub fn validate(&self) -> Result<(), OptimizeError> {
        if self.pipeline.name.trim().is_empty() || self.pipeline.name.len() > 4096 {
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
/// unoptimized or unverified FlowWir value.
#[derive(Debug, Clone, PartialEq)]
pub struct OptimizedFlowWir {
    wir: ValidatedFlowWir,
    report: OptimizationReport,
}

impl OptimizedFlowWir {
    #[must_use]
    pub fn wir(&self) -> &ValidatedFlowWir {
        &self.wir
    }

    #[must_use]
    pub fn report(&self) -> &OptimizationReport {
        &self.report
    }

    #[must_use]
    pub fn into_parts(self) -> (ValidatedFlowWir, OptimizationReport) {
        (self.wir, self.report)
    }
}

pub trait FlowOptimizer {
    fn optimize(
        &self,
        request: OptimizationRequest,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<OptimizedFlowWir, OptimizeError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OptimizeError {
    Cancelled,
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
            Self::InvalidProfile(reason) => {
                write!(formatter, "invalid optimization profile: {reason}")
            }
            Self::InvalidLimits => formatter.write_str("optimization limits must be nonzero"),
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

pub fn seal(
    request: &OptimizationRequest,
    wir: FlowWir,
    report: OptimizationReport,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<OptimizedFlowWir, OptimizeError> {
    if is_cancelled() {
        return Err(OptimizeError::Cancelled);
    }
    request.profile.validate()?;
    request.limits.validate()?;
    let (model_edges, payload_bytes) = mutable_model_resources(&wir);
    if model_edges.is_none_or(|count| count > request.limits.model_edges)
        || payload_bytes.is_none_or(|count| count > request.limits.payload_bytes)
    {
        return Err(OptimizeError::ResourceLimit {
            resource: "optimized IR model edges or payload bytes",
            limit: request.limits.payload_bytes,
        });
    }
    let wir = wir.validate().map_err(OptimizeError::InvalidOutput)?;
    validate_report(
        &request.input,
        &wir,
        &report,
        &request.profile,
        request.limits,
    )?;
    if is_cancelled() {
        return Err(OptimizeError::Cancelled);
    }
    Ok(OptimizedFlowWir { wir, report })
}

fn validate_report(
    input: &ValidatedFlowWir,
    output: &ValidatedFlowWir,
    report: &OptimizationReport,
    profile: &OptimizationProfile,
    limits: OptimizationLimits,
) -> Result<(), OptimizeError> {
    let input_wir = input.as_wir();
    let output_wir = output.as_wir();
    if input_wir.build != output_wir.build || input_wir.name != output_wir.name {
        return Err(OptimizeError::InvalidReport(
            "optimizer changed image or build identity",
        ));
    }
    if !immutable_contract_matches(input_wir, output_wir) {
        return Err(OptimizeError::ProofViolation {
            pass: "pipeline".to_owned(),
            detail: "optimizer changed immutable type, function identity, proof, image-plan, or provenance data".to_owned(),
        });
    }
    if report.profile != *profile {
        return Err(OptimizeError::InvalidReport(
            "optimization profile does not match request",
        ));
    }
    if profile.level == OptimizationLevel::None && input_wir != output_wir {
        return Err(OptimizeError::ProofViolation {
            pass: "pipeline".to_owned(),
            detail: "optimization level `none` changed FlowWir".to_owned(),
        });
    }
    let input_instructions = instruction_count(input_wir).ok_or(OptimizeError::InvalidReport(
        "input instruction count overflow",
    ))?;
    let output_instructions = instruction_count(output_wir).ok_or(OptimizeError::InvalidReport(
        "output instruction count overflow",
    ))?;
    let output_blocks = output_wir
        .functions
        .iter()
        .try_fold(0u64, |total, function| {
            total.checked_add(u64::try_from(function.blocks.len()).ok()?)
        });
    let output_values = output_wir
        .functions
        .iter()
        .try_fold(0u64, |total, function| {
            total.checked_add(u64::try_from(function.values.len()).ok()?)
        });
    let (model_edges, payload_bytes) = mutable_model_resources(output_wir);
    if output_wir.functions.len() > limits.functions as usize
        || output_blocks.is_none_or(|count| count > limits.blocks)
        || output_instructions > limits.instructions
        || output_values.is_none_or(|count| count > limits.values)
        || output_wir.proofs.len() > limits.proofs as usize
        || model_edges.is_none_or(|count| count > limits.model_edges)
        || payload_bytes.is_none_or(|count| count > limits.payload_bytes)
        || report.passes.len() > limits.passes as usize
        || report.decisions.len() as u64 > limits.decisions
    {
        return Err(OptimizeError::ResourceLimit {
            resource: "optimized IR or report items",
            limit: limits.instructions,
        });
    }
    let mut previous = input_instructions;
    let mut pass_names = std::collections::BTreeSet::new();
    for pass in &report.passes {
        if pass.pass.trim().is_empty()
            || !pass_names.insert(pass.pass.as_str())
            || pass.iterations == 0
            || pass.iterations > profile.maximum_iterations
            || pass.instructions_before != previous
            || (!pass.changed && pass.instructions_before != pass.instructions_after)
        {
            return Err(OptimizeError::InvalidReport(
                "pass statistics are noncanonical or internally inconsistent",
            ));
        }
        previous = pass.instructions_after;
    }
    if previous != output_instructions {
        return Err(OptimizeError::InvalidReport(
            "pass instruction chain does not end at output",
        ));
    }
    let allowed_growth = input_instructions
        .checked_mul(u64::from(profile.maximum_ir_growth_percent))
        .and_then(|growth| growth.checked_div(100))
        .and_then(|growth| input_instructions.checked_add(growth))
        .ok_or(OptimizeError::InvalidReport(
            "optimization growth calculation overflow",
        ))?;
    if output_instructions > allowed_growth {
        return Err(OptimizeError::ResourceLimit {
            resource: "IR growth percent",
            limit: u64::from(profile.maximum_ir_growth_percent),
        });
    }
    let pass_order: std::collections::BTreeMap<_, _> = report
        .passes
        .iter()
        .enumerate()
        .map(|(index, pass)| (pass.pass.as_str(), index))
        .collect();
    let mut previous_decision = None;
    for decision in &report.decisions {
        let decision_key = pass_order
            .get(decision.pass.as_str())
            .copied()
            .map(|pass| (pass, decision.subject.as_str()));
        if decision.pass.trim().is_empty()
            || decision.subject.trim().is_empty()
            || decision.justification.trim().is_empty()
            || !pass_names.contains(decision.pass.as_str())
            || decision_key.is_none()
            || previous_decision.is_some_and(|previous| Some(previous) >= decision_key)
            || !decision.relied_on.windows(2).all(|pair| pair[0] < pair[1])
            || decision
                .relied_on
                .iter()
                .any(|proof| proof.0 as usize >= output_wir.proofs.len())
        {
            return Err(OptimizeError::InvalidReport(
                "optimization decision does not name a valid pass, subject, reason, and proof set",
            ));
        }
        previous_decision = decision_key;
    }
    let ir_changed = input_wir != output_wir;
    let report_changed = report.passes.iter().any(|pass| pass.changed);
    let changed_passes: std::collections::BTreeSet<_> = report
        .passes
        .iter()
        .filter(|pass| pass.changed)
        .map(|pass| pass.pass.as_str())
        .collect();
    let decision_passes: std::collections::BTreeSet<_> = report
        .decisions
        .iter()
        .map(|decision| decision.pass.as_str())
        .collect();
    if ir_changed != report_changed
        || !changed_passes.is_subset(&decision_passes)
        || !decision_passes.is_subset(&changed_passes)
    {
        return Err(OptimizeError::InvalidReport(
            "changed passes, decisions, and the optimized IR disagree",
        ));
    }
    let report_bytes = report
        .passes
        .iter()
        .try_fold(0u64, |total, pass| {
            total.checked_add(u64::try_from(pass.pass.len()).ok()?)
        })
        .and_then(|total| {
            report.decisions.iter().try_fold(total, |total, decision| {
                let strings = decision
                    .pass
                    .len()
                    .checked_add(decision.subject.len())?
                    .checked_add(decision.justification.len())?;
                let proof_bytes = decision.relied_on.len().checked_mul(4)?;
                total
                    .checked_add(u64::try_from(strings).ok()?)?
                    .checked_add(u64::try_from(proof_bytes).ok()?)
            })
        });
    if report_bytes.is_none_or(|bytes| bytes > limits.report_bytes) {
        return Err(OptimizeError::ResourceLimit {
            resource: "optimization report bytes",
            limit: limits.report_bytes,
        });
    }
    Ok(())
}

fn mutable_model_resources(wir: &FlowWir) -> (Option<u64>, Option<u64>) {
    fn measure(wir: &FlowWir) -> Option<(u64, u64)> {
        use wrela_flow_wir::{FlowOperation, Immediate, Terminator};

        let mut edges = 0u64;
        let mut bytes = 0u64;
        let add_edges = |total: &mut u64, count: usize| -> Option<()> {
            *total = total.checked_add(u64::try_from(count).ok()?)?;
            Some(())
        };
        let add_bytes = |total: &mut u64, count: usize| -> Option<()> {
            *total = total.checked_add(u64::try_from(count).ok()?)?;
            Some(())
        };
        let immediate_bytes = |value: &Immediate| match value {
            Immediate::Integer { bytes_le, .. } | Immediate::Bytes(bytes_le) => bytes_le.len(),
            Immediate::Unit
            | Immediate::Bool(_)
            | Immediate::Float32(_)
            | Immediate::Float64(_)
            | Immediate::Zero(_)
            | Immediate::GlobalAddress(_)
            | Immediate::FunctionAddress(_) => 0,
        };
        for global in &wir.globals {
            add_bytes(&mut bytes, immediate_bytes(&global.initializer))?;
        }
        for function in &wir.functions {
            add_edges(&mut edges, function.parameters.len())?;
            add_edges(&mut edges, function.result_types.len())?;
            add_edges(&mut edges, function.values.len())?;
            add_edges(&mut edges, function.blocks.len())?;
            for value in &function.values {
                if let Some(name) = &value.source_name {
                    add_bytes(&mut bytes, name.len())?;
                }
            }
            for block in &function.blocks {
                add_edges(&mut edges, block.parameters.len())?;
                add_edges(&mut edges, block.instructions.len())?;
                for instruction in &block.instructions {
                    add_edges(&mut edges, instruction.results.len())?;
                    match &instruction.operation {
                        FlowOperation::Immediate(value) => {
                            add_bytes(&mut bytes, immediate_bytes(value))?;
                        }
                        FlowOperation::MakeAggregate { fields, .. }
                        | FlowOperation::Call {
                            arguments: fields, ..
                        }
                        | FlowOperation::TaskStart {
                            arguments: fields, ..
                        } => add_edges(&mut edges, fields.len())?,
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
                    | Terminator::TailCall { arguments, .. } => {
                        add_edges(&mut edges, arguments.len())?;
                    }
                    Terminator::Branch {
                        then_arguments,
                        else_arguments,
                        ..
                    } => {
                        add_edges(&mut edges, then_arguments.len())?;
                        add_edges(&mut edges, else_arguments.len())?;
                    }
                    Terminator::Switch {
                        cases,
                        default_arguments,
                        ..
                    } => {
                        add_edges(&mut edges, cases.len())?;
                        add_edges(&mut edges, default_arguments.len())?;
                        for case in cases {
                            add_edges(&mut edges, case.arguments.len())?;
                        }
                    }
                    Terminator::Suspend { .. }
                    | Terminator::Trap { .. }
                    | Terminator::Unreachable => {}
                }
            }
        }
        Some((edges, bytes))
    }

    match measure(wir) {
        Some((edges, bytes)) => (Some(edges), Some(bytes)),
        None => (None, None),
    }
}

fn immutable_contract_matches(input: &FlowWir, output: &FlowWir) -> bool {
    input.version == output.version
        && input.source_summary == output.source_summary
        && input.types == output.types
        && input.proofs == output.proofs
        && input.checkpoints == output.checkpoints
        && input.actors == output.actors
        && input.tasks == output.tasks
        && input.devices == output.devices
        && input.pools == output.pools
        && input.regions == output.regions
        && input.startup_order == output.startup_order
        && input.shutdown_order == output.shutdown_order
        && input.image_entry == output.image_entry
        && input.static_bytes == output.static_bytes
        && input.peak_bytes == output.peak_bytes
        && input.globals.len() == output.globals.len()
        && input
            .globals
            .iter()
            .zip(&output.globals)
            .all(|(left, right)| {
                left.id == right.id
                    && left.name == right.name
                    && left.ty == right.ty
                    && left.mutable == right.mutable
                    && left.owner == right.owner
            })
        && input.functions.len() == output.functions.len()
        && input
            .functions
            .iter()
            .zip(&output.functions)
            .all(|(left, right)| {
                left.id == right.id
                    && left.name == right.name
                    && left.origin == right.origin
                    && left.role == right.role
                    && left.parameters.len() == right.parameters.len()
                    && left
                        .parameters
                        .iter()
                        .zip(&right.parameters)
                        .all(|(left_id, right_id)| {
                            left.values.get(left_id.0 as usize).map(|value| value.ty)
                                == right.values.get(right_id.0 as usize).map(|value| value.ty)
                        })
                    && left.result_types == right.result_types
                    && left.stack_bound == right.stack_bound
                    && left.frame_bound == right.frame_bound
                    && left.source == right.source
            })
}

fn instruction_count(wir: &wrela_flow_wir::FlowWir) -> Option<u64> {
    wir.functions.iter().try_fold(0u64, |total, function| {
        function.blocks.iter().try_fold(total, |total, block| {
            total.checked_add(block.instructions.len() as u64)
        })
    })
}

#[cfg(test)]
mod contract_tests {
    use super::{OptimizationLimits, OptimizeError};

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
    }
}
