//! AArch64 target layout, ABI selection, and runtime expansion from optimized
//! FlowWir into validated MachineWir.

#![forbid(unsafe_code)]

/// Exact MachineWir inspection surface for composition roots that consume a
/// sealed lowering result without taking a second direct dependency.
pub use wrela_machine_wir as machine_wir;

mod equality;
mod scalar;

use std::{cmp::Ordering, fmt};

use wrela_build_model::{OptimizationLevel, RecordingMode, ValidatedBuildConfiguration};
use wrela_flow_opt::{OptimizationProfile, OptimizationReport, OptimizedFlowWir};
use wrela_flow_wir as flow;
use wrela_machine_wir::{
    BackendProof, BackendProofKind, BlockId, CallingConvention, DataLayout, Endianness, FunctionId,
    InstructionId, Linkage, MACHINE_WIR_VERSION, MachineBlock, MachineFunction,
    MachineFunctionOrigin, MachineFunctionRole, MachineImmediate, MachineInstruction,
    MachineOperation, MachineTarget, MachineTerminator, MachineType, MachineTypeId,
    MachineTypeKind, MachineValue, MachineWir, ProofId, Section, SectionId, SectionKind, Symbol,
    SymbolDefinition, SymbolId, SymbolVisibility, ValidatedMachineWir, ValidationErrors,
    ValidationFailure, ValidationLimits as MachineValidationLimits, ValueId,
};
use wrela_runtime_abi::{
    EVENT_LOG_STORAGE_BYTES, INTERRUPT_ROUTE_LAYOUT, INTERRUPT_ROUTE_SECTION,
    INTERRUPT_ROUTE_TABLE_SYMBOL, RuntimeIntrinsic, RuntimeRequirements,
};
use wrela_target::TargetPackage;

// Scalar code reservation for the canonical empty body plus the mandatory
// runtime-entry call, zero-status switch, and status-propagating failure edge.
const MINIMUM_ENTRY_CODE_BYTES: u64 = 640;
const SUPPORTED_SEMANTIC_WIR_VERSION: u32 = 12;
const MINIMUM_BACKEND_PROOF: &str = "the canonical empty Flow image body returns EFI_SUCCESS after successful runtime initialization without backend memory facts";
const IMAGE_ENTER_RUNTIME_REASON: &str =
    "generated UEFI image entry initializes the target runtime";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachineLoweringLimits {
    pub types: u64,
    pub functions: u64,
    pub sections: u32,
    pub symbols: u32,
    pub globals: u32,
    pub instructions: u64,
    pub stack_slots: u64,
    pub proofs: u32,
    /// Total elements across all variable-length MachineWir collections.
    pub model_edges: u64,
    /// Total UTF-8 and immediate byte payload retained in MachineWir.
    pub payload_bytes: u64,
    /// Exact independently enforced policy used when sealing the produced
    /// MachineWir. Arena, edge, and payload ceilings must agree with the
    /// corresponding lowering limits so no boundary silently widens policy.
    pub validation: MachineValidationLimits,
    pub static_bytes: u64,
    pub stack_bytes_per_function: u64,
    pub report_bytes: u64,
}

impl MachineLoweringLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            types: 16_000_000,
            functions: 1_000_000,
            sections: 65_536,
            symbols: 16_000_000,
            globals: 16_000_000,
            instructions: 256_000_000,
            stack_slots: 256_000_000,
            proofs: 64_000_000,
            model_edges: 1_000_000_000,
            payload_bytes: 4 * 1024 * 1024 * 1024,
            validation: MachineValidationLimits::standard(),
            static_bytes: 4 * 1024 * 1024 * 1024,
            stack_bytes_per_function: 16 * 1024 * 1024,
            report_bytes: 1024 * 1024 * 1024,
        }
    }

    /// Align the nested MachineWir validator's structural ceilings with this
    /// lowering policy while preserving its caller-selected work/error caps.
    #[must_use]
    pub const fn with_aligned_validation(mut self) -> Self {
        let mut arena_records = self.types;
        if self.functions > arena_records {
            arena_records = self.functions;
        }
        if self.sections as u64 > arena_records {
            arena_records = self.sections as u64;
        }
        if self.symbols as u64 > arena_records {
            arena_records = self.symbols as u64;
        }
        if self.globals as u64 > arena_records {
            arena_records = self.globals as u64;
        }
        if self.instructions > arena_records {
            arena_records = self.instructions;
        }
        if self.stack_slots > arena_records {
            arena_records = self.stack_slots;
        }
        if self.proofs as u64 > arena_records {
            arena_records = self.proofs as u64;
        }
        self.validation.arena_records = arena_records;
        self.validation.model_edges = self.model_edges;
        self.validation.payload_bytes = self.payload_bytes;
        self
    }

    pub fn validate(self) -> Result<(), MachineLowerError> {
        let hard = Self::standard();
        let validation_hard = MachineValidationLimits::standard();
        let expected_validation_arena = self.with_aligned_validation().validation.arena_records;
        if self.types == 0
            || self.functions == 0
            || self.sections == 0
            || self.symbols == 0
            || self.globals == 0
            || self.instructions == 0
            || self.stack_slots == 0
            || self.proofs == 0
            || self.model_edges == 0
            || self.payload_bytes == 0
            || self.static_bytes == 0
            || self.stack_bytes_per_function == 0
            || self.report_bytes == 0
            || !self.validation.is_valid()
            || self.validation.arena_records != expected_validation_arena
            || self.validation.model_edges != self.model_edges
            || self.validation.payload_bytes != self.payload_bytes
            || self.validation.validation_work > validation_hard.validation_work
            || self.validation.errors > validation_hard.errors
            || self.types > hard.types
            || self.functions > hard.functions
            || self.sections > hard.sections
            || self.symbols > hard.symbols
            || self.globals > hard.globals
            || self.instructions > hard.instructions
            || self.stack_slots > hard.stack_slots
            || self.proofs > hard.proofs
            || self.model_edges > hard.model_edges
            || self.payload_bytes > hard.payload_bytes
            || self.static_bytes > hard.static_bytes
            || self.stack_bytes_per_function > hard.stack_bytes_per_function
            || self.report_bytes > hard.report_bytes
        {
            Err(MachineLowerError::InvalidLimits)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
pub struct MachineLoweringRequest<'a> {
    /// Borrowed because the backend also retains the optimized IR for report
    /// assembly. Machine lowering must not require an image-sized clone.
    pub input: &'a OptimizedFlowWir,
    /// The complete validated target package is required here: lowering must
    /// resolve FlowWir's semantic device-binding names to concrete interrupt
    /// identities while also fixing the backend ABI. Later codegen receives
    /// only `target.backend()`.
    pub target: &'a TargetPackage,
    pub build: &'a ValidatedBuildConfiguration,
    pub limits: MachineLoweringLimits,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeUse {
    pub intrinsic: RuntimeIntrinsic,
    pub call_sites: u64,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutSummary {
    /// Sum of reservations in `Code` sections.
    pub code_bytes_upper_bound: u64,
    /// Sum of `ReadOnlyData` and `RuntimeMetadata` section reservations.
    pub read_only_bytes: u64,
    /// Sum of `WritableData` section reservations.
    pub writable_bytes: u64,
    /// Sum of `ZeroFill` section reservations.
    pub zero_fill_bytes: u64,
    /// Maximum `MachineFunction::stack_bytes`, or zero for no functions.
    pub maximum_stack_bytes: u64,
    /// Maximum type, section, global, or stack-slot alignment.
    pub maximum_alignment: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineLoweringReport {
    pub target_identity: String,
    pub types_laid_out: u64,
    pub functions_lowered: u64,
    pub layout: LayoutSummary,
    pub runtime: RuntimeRequirements,
    pub runtime_uses: Vec<RuntimeUse>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachineLoweringOutput {
    wir: ValidatedMachineWir,
    report: MachineLoweringReport,
}

impl MachineLoweringOutput {
    #[must_use]
    pub fn wir(&self) -> &ValidatedMachineWir {
        &self.wir
    }

    #[must_use]
    pub fn report(&self) -> &MachineLoweringReport {
        &self.report
    }

    #[must_use]
    pub fn into_parts(self) -> (ValidatedMachineWir, MachineLoweringReport) {
        (self.wir, self.report)
    }
}

pub trait MachineLowerer {
    fn lower(
        &self,
        request: MachineLoweringRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<MachineLoweringOutput, MachineLowerError>;
}

/// Production revision-0.1 lowering for the executable FlowWir surface that
/// the canonical frontend currently emits.
///
/// This implementation deliberately accepts only the canonical synchronous,
/// empty image entry produced by `CanonicalFlowLowerer`, plus the supported
/// scalar/control-flow surface after any sealed canonical optimization profile.
/// It does not silently approximate richer FlowWir operations, layouts,
/// devices, or proof surfaces.
#[derive(Debug, Clone, Copy, Default)]
pub struct CanonicalMachineLowerer;

impl CanonicalMachineLowerer {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl MachineLowerer for CanonicalMachineLowerer {
    fn lower(
        &self,
        request: MachineLoweringRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<MachineLoweringOutput, MachineLowerError> {
        check_cancelled(is_cancelled)?;
        request.limits.validate()?;
        validate_request_identity(&request, is_cancelled)?;
        request
            .target
            .validate()
            .map_err(|error| MachineLowerError::UnsupportedTarget(error.to_string()))?;
        check_cancelled(is_cancelled)?;
        let (wir, report) = lower_supported(&request, is_cancelled)?;
        check_cancelled(is_cancelled)?;
        seal(&request, wir, report, is_cancelled)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineLowerError {
    Cancelled,
    InvalidLimits,
    BuildIdentityMismatch,
    BuildTargetMismatch,
    EventLogCapacityExceeded {
        requested_bytes: u64,
        capacity_bytes: u64,
    },
    InvalidOptimizerReport(&'static str),
    OutputDoesNotImplementInput,
    UnsupportedInput {
        feature: &'static str,
    },
    UnsupportedTarget(String),
    LayoutOverflow {
        subject: String,
    },
    ResourceLimit {
        resource: &'static str,
        limit: u64,
    },
    MissingRuntimeLowering(RuntimeIntrinsic),
    InvalidReport(&'static str),
    InvalidOutput(ValidationErrors),
}

impl fmt::Display for MachineLowerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("MachineWir lowering was cancelled"),
            Self::InvalidLimits => formatter
                .write_str("MachineWir lowering limits must be nonzero and within hard ceilings"),
            Self::BuildIdentityMismatch => formatter
                .write_str("optimized FlowWir, optimization policy, and build identity differ"),
            Self::BuildTargetMismatch => {
                formatter.write_str("build and backend target identities differ")
            }
            Self::EventLogCapacityExceeded {
                requested_bytes,
                capacity_bytes,
            } => write!(
                formatter,
                "build profile requests {requested_bytes} record/replay bytes, but the target runtime owns exactly {capacity_bytes} bytes",
            ),
            Self::InvalidOptimizerReport(reason) => {
                write!(formatter, "invalid sealed optimizer report: {reason}")
            }
            Self::OutputDoesNotImplementInput => formatter.write_str(
                "MachineWir output is not the canonical implementation of the optimized FlowWir input",
            ),
            Self::UnsupportedInput { feature } => {
                write!(formatter, "unsupported optimized FlowWir input: {feature}")
            }
            Self::UnsupportedTarget(target) => {
                write!(formatter, "unsupported machine target {target}")
            }
            Self::LayoutOverflow { subject } => {
                write!(formatter, "machine layout overflow for {subject}")
            }
            Self::ResourceLimit { resource, limit } => {
                write!(
                    formatter,
                    "MachineWir lowering exceeded {resource} limit {limit}"
                )
            }
            Self::MissingRuntimeLowering(intrinsic) => {
                write!(
                    formatter,
                    "no target lowering exists for runtime intrinsic {intrinsic:?}"
                )
            }
            Self::InvalidReport(reason) => {
                write!(formatter, "invalid machine-lowering report: {reason}")
            }
            Self::InvalidOutput(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for MachineLowerError {}

#[derive(Debug, Clone, Copy)]
struct MinimumFlow<'a> {
    input: &'a flow::FlowWir,
    unit_name: &'a str,
    entry: &'a flow::FlowFunction,
    type_proof: &'a flow::Proof,
    effects_proof: &'a flow::Proof,
    image_closed_proof: &'a flow::Proof,
}

fn unsupported(feature: &'static str) -> MachineLowerError {
    MachineLowerError::UnsupportedInput { feature }
}

fn check_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), MachineLowerError> {
    if is_cancelled() {
        Err(MachineLowerError::Cancelled)
    } else {
        Ok(())
    }
}

fn validate_request_identity(
    request: &MachineLoweringRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), MachineLowerError> {
    let input_build = &request.input.wir().as_wir().build;
    if input_build != &request.build.identity {
        return Err(MachineLowerError::BuildIdentityMismatch);
    }
    if request.build.profile.recording != RecordingMode::Disabled
        && request.build.profile.memory.event_log_bytes > EVENT_LOG_STORAGE_BYTES
    {
        return Err(MachineLowerError::EventLogCapacityExceeded {
            requested_bytes: request.build.profile.memory.event_log_bytes,
            capacity_bytes: EVENT_LOG_STORAGE_BYTES,
        });
    }
    let expected_profile = OptimizationProfile::from_build_policy(
        &request.build.profile.optimization,
        request.build.identity.compiler,
    )
    .map_err(|_| unsupported("the selected optimization policy is not implemented"))?;
    if request.input.report().profile != expected_profile {
        return Err(MachineLowerError::BuildIdentityMismatch);
    }
    validate_optimizer_report(request.input, is_cancelled)?;
    if request.target.identity() != &request.build.identity.target
        || request.target.semantic().content_digest() != request.build.identity.target_package
    {
        return Err(MachineLowerError::BuildTargetMismatch);
    }
    Ok(())
}

fn validate_optimizer_report(
    input: &OptimizedFlowWir,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), MachineLowerError> {
    validate_optimizer_report_contract(input.wir().as_wir(), input.report(), is_cancelled)
}

fn validate_optimizer_report_contract(
    wir: &flow::FlowWir,
    report: &OptimizationReport,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), MachineLowerError> {
    match report.profile.level {
        OptimizationLevel::None => {
            if !report.passes.is_empty() || !report.decisions.is_empty() {
                return Err(MachineLowerError::InvalidOptimizerReport(
                    "None must preserve FlowWir with an empty report",
                ));
            }
            Ok(())
        }
        OptimizationLevel::Development => {
            validate_transforming_optimizer_report(wir, report, 4, is_cancelled)
        }
        OptimizationLevel::Performance | OptimizationLevel::Size => {
            validate_transforming_optimizer_report(wir, report, 5, is_cancelled)
        }
    }
}

fn validate_transforming_optimizer_report(
    wir: &flow::FlowWir,
    report: &OptimizationReport,
    expected_passes: usize,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), MachineLowerError> {
    // `OptimizedFlowWir` is sealed by wrela-flow-opt, which owns the canonical
    // pass names, ordering, transformations, and exact resealing algorithm.
    // This consumer validates the exposed cross-boundary facts without
    // reimplementing those optimizer semantics or trusting free-form report
    // content as authority.
    if report.passes.len() != expected_passes {
        return Err(MachineLowerError::InvalidOptimizerReport(
            "transforming profile has the wrong canonical pass count",
        ));
    }
    let test_entries = u32::try_from(wir.tests.len()).map_err(|_| {
        MachineLowerError::InvalidOptimizerReport("optimized test count cannot be reported")
    })?;
    let mut prior_after = None;
    for (index, pass) in report.passes.iter().enumerate() {
        check_cancelled(is_cancelled)?;
        let mut duplicate = false;
        for prior in &report.passes[..index] {
            check_cancelled(is_cancelled)?;
            if cancellable_text_equal(&prior.pass, &pass.pass, is_cancelled)? {
                duplicate = true;
                break;
            }
        }
        if !cancellable_has_non_whitespace(&pass.pass, is_cancelled)?
            || pass.iterations == 0
            || pass.iterations > report.profile.maximum_iterations
            || prior_after.is_some_and(|prior| prior != pass.instructions_before)
            || (!pass.changed && pass.instructions_before != pass.instructions_after)
            || pass.test_entries_before != test_entries
            || pass.test_entries_after != test_entries
            || !pass.test_table_preserved
            || duplicate
        {
            return Err(MachineLowerError::InvalidOptimizerReport(
                "transforming pass statistics are malformed",
            ));
        }
        prior_after = Some(pass.instructions_after);
    }
    let mut output_instructions = 0u64;
    for function in &wir.functions {
        check_cancelled(is_cancelled)?;
        for block in &function.blocks {
            check_cancelled(is_cancelled)?;
            let instructions = u64::try_from(block.instructions.len()).map_err(|_| {
                MachineLowerError::InvalidOptimizerReport("optimized instruction count overflowed")
            })?;
            output_instructions = output_instructions.checked_add(instructions).ok_or(
                MachineLowerError::InvalidOptimizerReport("optimized instruction count overflowed"),
            )?;
        }
    }
    if prior_after != Some(output_instructions) {
        return Err(MachineLowerError::InvalidOptimizerReport(
            "transforming pass statistics do not end at optimized FlowWir",
        ));
    }
    for decision in &report.decisions {
        check_cancelled(is_cancelled)?;
        let mut pass_exists = false;
        for pass in &report.passes {
            check_cancelled(is_cancelled)?;
            if cancellable_text_equal(&pass.pass, &decision.pass, is_cancelled)? {
                pass_exists = true;
                break;
            }
        }
        if !cancellable_has_non_whitespace(&decision.subject, is_cancelled)?
            || !cancellable_has_non_whitespace(&decision.justification, is_cancelled)?
            || !pass_exists
        {
            return Err(MachineLowerError::InvalidOptimizerReport(
                "transforming decision facts are malformed",
            ));
        }
        let mut previous_proof = None;
        for proof in &decision.relied_on {
            check_cancelled(is_cancelled)?;
            if previous_proof.is_some_and(|previous| previous >= *proof)
                || proof.0 as usize >= wir.proofs.len()
            {
                return Err(MachineLowerError::InvalidOptimizerReport(
                    "transforming decision proof facts are malformed",
                ));
            }
            previous_proof = Some(*proof);
        }
    }
    check_cancelled(is_cancelled)
}

fn supported_minimum(input: &OptimizedFlowWir) -> Result<MinimumFlow<'_>, MachineLowerError> {
    let input = input.wir().as_wir();
    if input.source_summary.semantic_wir_version != SUPPORTED_SEMANTIC_WIR_VERSION
        || input.source_summary.semantic_functions != 1
        || input.source_summary.reachable_declarations != 1
        || input.source_summary.monomorphized_instantiations != 1
        || input.source_summary.resolved_interface_calls != 0
    {
        return Err(unsupported("non-minimum semantic source summaries"));
    }
    if !input.globals.is_empty()
        || !input.actors.is_empty()
        || !input.tasks.is_empty()
        || !input.devices.is_empty()
        || !input.pools.is_empty()
        || !input.regions.is_empty()
        || !input.schedulers.is_empty()
        || !input.checkpoints.is_empty()
        || !input.tests.is_empty()
        || input.startup_order.as_slice() != [flow::PlanOwner::Runtime]
        || input.shutdown_order.as_slice() != [flow::PlanOwner::Runtime]
        || input.static_bytes != 0
        || input.peak_bytes != 0
    {
        return Err(unsupported(
            "globals, runtime plans, devices, checkpoints, or image memory",
        ));
    }

    let [ty] = input.types.as_slice() else {
        return Err(unsupported("types other than the canonical unit type"));
    };
    let Some(unit_name) = ty.name.as_deref() else {
        return Err(unsupported("an unnamed canonical unit type"));
    };
    if ty.id != flow::TypeId(0)
        || ty.kind != flow::FlowTypeKind::Unit
        || unit_name != "unit"
        || !ty.copyable
        || ty.strict_linear
    {
        return Err(unsupported("types other than the canonical unit type"));
    }

    let [entry] = input.functions.as_slice() else {
        return Err(unsupported("multiple or missing Flow functions"));
    };
    if entry.id != flow::FunctionId(0)
        || input.image_entry != entry.id
        || entry.name != "__wrela_image_entry"
        || !matches!(
            entry.origin,
            flow::FunctionOrigin::GeneratedImageEntry {
                semantic_function: 0,
                ..
            }
        )
        || entry.role != flow::FunctionRole::ImageEntry
        || entry.color != flow::FunctionColor::Sync
        || !entry.parameters.is_empty()
        || !entry.result_types.is_empty()
        || !entry.values.is_empty()
        || entry.entry != flow::BlockId(0)
        || entry.stack_bound != 0
        || entry.frame_bound != 0
        || entry.source.is_some()
    {
        return Err(unsupported(
            "noncanonical generated synchronous image entries",
        ));
    }
    let [block] = entry.blocks.as_slice() else {
        return Err(unsupported(
            "control-flow graphs other than one empty block",
        ));
    };
    if block.id != flow::BlockId(0)
        || !block.parameters.is_empty()
        || !block.instructions.is_empty()
        || !matches!(&block.terminator, flow::Terminator::Return(values) if values.is_empty())
        || block.source.is_some()
    {
        return Err(unsupported("Flow operations or nonempty control flow"));
    }

    let [type_proof, effects_proof, image_closed_proof] = input.proofs.as_slice() else {
        return Err(unsupported(
            "proof sets other than the minimum image proof set",
        ));
    };
    if type_proof.id != flow::ProofId(0)
        || type_proof.kind != flow::ProofKind::TypeChecked
        || !type_proof.depends_on.is_empty()
        || type_proof.bound.is_some()
        || effects_proof.id != flow::ProofId(1)
        || effects_proof.kind != flow::ProofKind::EffectsAllowed
        || effects_proof.depends_on.as_slice() != [flow::ProofId(0)]
        || effects_proof.bound != Some(1)
        || image_closed_proof.id != flow::ProofId(2)
        || image_closed_proof.kind != flow::ProofKind::ImageClosed
        || image_closed_proof.depends_on.as_slice() != [flow::ProofId(0), flow::ProofId(1)]
        || image_closed_proof.bound != Some(0)
        || type_proof.sources.len() != 1
        || effects_proof.sources != type_proof.sources
        || image_closed_proof.sources != type_proof.sources
        || type_proof.explanation.len() != 1
        || effects_proof.explanation.len() != 1
        || image_closed_proof.explanation.len() != 1
    {
        return Err(unsupported(
            "optimizer-derived or noncanonical minimum Flow proofs",
        ));
    }

    Ok(MinimumFlow {
        input,
        unit_name,
        entry,
        type_proof,
        effects_proof,
        image_closed_proof,
    })
}

fn check_resource(
    resource: &'static str,
    actual: u64,
    limit: u64,
) -> Result<(), MachineLowerError> {
    if actual > limit {
        Err(MachineLowerError::ResourceLimit { resource, limit })
    } else {
        Ok(())
    }
}

fn add_payload(total: &mut u64, bytes: usize, limit: u64) -> Result<(), MachineLowerError> {
    let bytes = u64::try_from(bytes).map_err(|_| MachineLowerError::ResourceLimit {
        resource: "MachineWir payload bytes",
        limit,
    })?;
    *total = total
        .checked_add(bytes)
        .filter(|total| *total <= limit)
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir payload bytes",
            limit,
        })?;
    Ok(())
}

fn preflight_minimum_output(
    minimum: &MinimumFlow<'_>,
    target: &TargetPackage,
    build: &ValidatedBuildConfiguration,
    limits: MachineLoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), MachineLowerError> {
    check_cancelled(is_cancelled)?;
    for (resource, actual, limit) in [
        ("MachineWir types", 3, limits.types),
        ("MachineWir functions", 1, limits.functions),
        ("MachineWir sections", 2, u64::from(limits.sections)),
        ("MachineWir symbols", 3, u64::from(limits.symbols)),
        ("MachineWir globals", 0, u64::from(limits.globals)),
        ("MachineWir instructions", 2, limits.instructions),
        ("MachineWir stack slots", 0, limits.stack_slots),
        ("MachineWir proofs", 1, u64::from(limits.proofs)),
    ] {
        check_resource(resource, actual, limit)?;
    }

    let feature_edges = u64::try_from(target.backend().llvm_features().len()).map_err(|_| {
        MachineLowerError::ResourceLimit {
            resource: "MachineWir model edges",
            limit: limits.model_edges,
        }
    })?;
    let model_edges = 32u64
        .checked_add(feature_edges)
        .ok_or(MachineLowerError::ResourceLimit {
            resource: "MachineWir model edges",
            limit: limits.model_edges,
        })?;
    check_resource("MachineWir model edges", model_edges, limits.model_edges)?;

    let backend = target.backend();
    let mut payload = 0u64;
    for text in [
        minimum.input.name.as_str(),
        minimum.input.build.target.as_str(),
        target.identity().as_str(),
        backend.llvm_triple(),
        backend.llvm_data_layout(),
        backend.llvm_cpu(),
        backend.coff_machine(),
        minimum.unit_name,
        ".text",
        "image",
        INTERRUPT_ROUTE_SECTION,
        "runtime",
        backend.entry_symbol(),
        RuntimeIntrinsic::ImageEnter.symbol_name(),
        INTERRUPT_ROUTE_TABLE_SYMBOL,
        MINIMUM_BACKEND_PROOF,
    ] {
        add_payload(&mut payload, text.len(), limits.payload_bytes)?;
    }
    for feature in backend.llvm_features() {
        check_cancelled(is_cancelled)?;
        add_payload(&mut payload, feature.len(), limits.payload_bytes)?;
    }
    add_payload(&mut payload, 8, limits.payload_bytes)?;

    let static_bytes = MINIMUM_ENTRY_CODE_BYTES
        .checked_add(u64::from(INTERRUPT_ROUTE_LAYOUT.header_bytes))
        .ok_or_else(|| MachineLowerError::LayoutOverflow {
            subject: "minimum image sections".to_owned(),
        })?;
    check_resource("MachineWir static bytes", static_bytes, limits.static_bytes)?;
    check_resource(
        "build profile static bytes",
        static_bytes,
        build.profile.memory.static_bytes,
    )?;
    check_resource(
        "MachineWir stack bytes per function",
        0,
        limits.stack_bytes_per_function,
    )?;
    check_resource(
        "machine lowering report bytes",
        u64::try_from(
            target
                .identity()
                .as_str()
                .len()
                .checked_add(IMAGE_ENTER_RUNTIME_REASON.len())
                .ok_or(MachineLowerError::ResourceLimit {
                    resource: "machine lowering report bytes",
                    limit: limits.report_bytes,
                })?,
        )
        .map_err(|_| MachineLowerError::ResourceLimit {
            resource: "machine lowering report bytes",
            limit: limits.report_bytes,
        })?,
        limits.report_bytes,
    )?;
    check_cancelled(is_cancelled)
}

fn try_vec<T>(
    capacity: usize,
    resource: &'static str,
    limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<T>, MachineLowerError> {
    check_cancelled(is_cancelled)?;
    check_resource(
        resource,
        u64::try_from(capacity)
            .map_err(|_| MachineLowerError::ResourceLimit { resource, limit })?,
        limit,
    )?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| MachineLowerError::ResourceLimit { resource, limit })?;
    check_cancelled(is_cancelled)?;
    Ok(output)
}

const CANCELLABLE_COPY_CHUNK_BYTES: usize = 64 * 1024;

fn push_text_chunks(
    output: &mut String,
    value: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), MachineLowerError> {
    let mut start = 0usize;
    while start < value.len() {
        check_cancelled(is_cancelled)?;
        let mut end = start
            .saturating_add(CANCELLABLE_COPY_CHUNK_BYTES)
            .min(value.len());
        while end > start && !value.is_char_boundary(end) {
            end -= 1;
        }
        if end == start {
            return Err(unsupported("an invalid UTF-8 chunk boundary"));
        }
        output.push_str(&value[start..end]);
        start = end;
    }
    check_cancelled(is_cancelled)
}

fn cancellable_text_compare(
    left: &str,
    right: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Ordering, MachineLowerError> {
    let common = left.len().min(right.len());
    let mut start = 0usize;
    while start < common {
        check_cancelled(is_cancelled)?;
        let end = start
            .saturating_add(CANCELLABLE_COPY_CHUNK_BYTES)
            .min(common);
        let ordering = left.as_bytes()[start..end].cmp(&right.as_bytes()[start..end]);
        if ordering != Ordering::Equal {
            return Ok(ordering);
        }
        start = end;
    }
    check_cancelled(is_cancelled)?;
    Ok(left.len().cmp(&right.len()))
}

fn cancellable_text_equal(
    left: &str,
    right: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, MachineLowerError> {
    Ok(cancellable_text_compare(left, right, is_cancelled)? == Ordering::Equal)
}

fn cancellable_has_non_whitespace(
    value: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, MachineLowerError> {
    for character in value.chars() {
        check_cancelled(is_cancelled)?;
        if !character.is_whitespace() {
            return Ok(true);
        }
    }
    check_cancelled(is_cancelled)?;
    Ok(false)
}

fn copy_text(
    value: &str,
    resource: &'static str,
    limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<String, MachineLowerError> {
    check_cancelled(is_cancelled)?;
    check_resource(
        resource,
        u64::try_from(value.len())
            .map_err(|_| MachineLowerError::ResourceLimit { resource, limit })?,
        limit,
    )?;
    let mut output = String::new();
    output
        .try_reserve_exact(value.len())
        .map_err(|_| MachineLowerError::ResourceLimit { resource, limit })?;
    check_cancelled(is_cancelled)?;
    push_text_chunks(&mut output, value, is_cancelled)?;
    Ok(output)
}

fn lower_minimum(
    minimum: &MinimumFlow<'_>,
    target: &TargetPackage,
    build: &ValidatedBuildConfiguration,
    limits: MachineLoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(MachineWir, MachineLoweringReport), MachineLowerError> {
    let backend = target.backend();
    let mut features = try_vec(
        backend.llvm_features().len(),
        "MachineWir model edges",
        limits.model_edges,
        is_cancelled,
    )?;
    for feature in backend.llvm_features() {
        features.push(copy_text(
            feature,
            "MachineWir payload bytes",
            limits.payload_bytes,
            is_cancelled,
        )?);
    }

    let mut types = try_vec(3, "MachineWir types", limits.types, is_cancelled)?;
    types.push(MachineType {
        id: MachineTypeId(0),
        kind: MachineTypeKind::Void,
        size: 0,
        alignment: 1,
        source_name: Some(copy_text(
            minimum.unit_name,
            "MachineWir payload bytes",
            limits.payload_bytes,
            is_cancelled,
        )?),
    });
    types.push(MachineType {
        id: MachineTypeId(1),
        kind: MachineTypeKind::Pointer {
            address_space: 0,
            pointee: None,
        },
        size: 8,
        alignment: 8,
        source_name: None,
    });
    types.push(MachineType {
        id: MachineTypeId(2),
        kind: MachineTypeKind::Integer { bits: 64 },
        size: 8,
        alignment: 8,
        source_name: None,
    });

    let mut sections = try_vec(
        2,
        "MachineWir sections",
        u64::from(limits.sections),
        is_cancelled,
    )?;
    sections.push(Section {
        id: SectionId(0),
        name: copy_text(
            ".text",
            "MachineWir payload bytes",
            limits.payload_bytes,
            is_cancelled,
        )?,
        kind: SectionKind::Code,
        alignment: 16,
        reserved_bytes: MINIMUM_ENTRY_CODE_BYTES,
        owner: copy_text(
            "image",
            "MachineWir payload bytes",
            limits.payload_bytes,
            is_cancelled,
        )?,
    });
    sections.push(Section {
        id: SectionId(1),
        name: copy_text(
            INTERRUPT_ROUTE_SECTION,
            "MachineWir payload bytes",
            limits.payload_bytes,
            is_cancelled,
        )?,
        kind: SectionKind::RuntimeMetadata,
        alignment: INTERRUPT_ROUTE_LAYOUT.table_alignment,
        reserved_bytes: u64::from(INTERRUPT_ROUTE_LAYOUT.header_bytes),
        owner: copy_text(
            "runtime",
            "MachineWir payload bytes",
            limits.payload_bytes,
            is_cancelled,
        )?,
    });

    let mut symbols = try_vec(
        3,
        "MachineWir symbols",
        u64::from(limits.symbols),
        is_cancelled,
    )?;
    symbols.push(Symbol {
        id: SymbolId(0),
        name: copy_text(
            backend.entry_symbol(),
            "MachineWir payload bytes",
            limits.payload_bytes,
            is_cancelled,
        )?,
        visibility: SymbolVisibility::ImageEntry,
        definition: SymbolDefinition::Function(FunctionId(0)),
    });
    symbols.push(Symbol {
        id: SymbolId(1),
        name: copy_text(
            RuntimeIntrinsic::ImageEnter.symbol_name(),
            "MachineWir payload bytes",
            limits.payload_bytes,
            is_cancelled,
        )?,
        visibility: SymbolVisibility::Runtime,
        definition: SymbolDefinition::ExternalRuntime(RuntimeIntrinsic::ImageEnter),
    });
    symbols.push(Symbol {
        id: SymbolId(2),
        name: copy_text(
            INTERRUPT_ROUTE_TABLE_SYMBOL,
            "MachineWir payload bytes",
            limits.payload_bytes,
            is_cancelled,
        )?,
        visibility: SymbolVisibility::RuntimeMetadata,
        definition: SymbolDefinition::SectionOffset {
            section: SectionId(1),
            offset: 0,
            bytes: u64::from(INTERRUPT_ROUTE_LAYOUT.header_bytes),
        },
    });

    let mut parameters = try_vec(
        2,
        "MachineWir model edges",
        limits.model_edges,
        is_cancelled,
    )?;
    parameters.extend([ValueId(0), ValueId(1)]);
    let mut values = try_vec(
        4,
        "MachineWir model edges",
        limits.model_edges,
        is_cancelled,
    )?;
    values.extend([
        MachineValue {
            id: ValueId(0),
            ty: MachineTypeId(1),
            source_name: None,
        },
        MachineValue {
            id: ValueId(1),
            ty: MachineTypeId(1),
            source_name: None,
        },
        MachineValue {
            id: ValueId(2),
            ty: MachineTypeId(2),
            source_name: None,
        },
        MachineValue {
            id: ValueId(3),
            ty: MachineTypeId(2),
            source_name: None,
        },
    ]);
    let mut status_bytes = try_vec(
        8,
        "MachineWir payload bytes",
        limits.payload_bytes,
        is_cancelled,
    )?;
    status_bytes.resize(8, 0);
    let mut results = try_vec(
        1,
        "MachineWir model edges",
        limits.model_edges,
        is_cancelled,
    )?;
    results.push(ValueId(2));
    let mut instructions = try_vec(
        1,
        "MachineWir instructions",
        limits.instructions,
        is_cancelled,
    )?;
    instructions.push(MachineInstruction {
        id: InstructionId(0),
        results,
        operation: MachineOperation::Immediate(MachineImmediate::Integer {
            ty: MachineTypeId(2),
            bytes_le: status_bytes,
        }),
        source: None,
    });
    let mut returned = try_vec(
        1,
        "MachineWir model edges",
        limits.model_edges,
        is_cancelled,
    )?;
    returned.push(ValueId(2));
    let mut blocks = try_vec(
        3,
        "MachineWir model edges",
        limits.model_edges,
        is_cancelled,
    )?;
    blocks.push(MachineBlock {
        id: BlockId(0),
        parameters: Vec::new(),
        instructions,
        terminator: MachineTerminator::Return(returned),
    });
    let mut enter_results = try_vec(
        1,
        "MachineWir model edges",
        limits.model_edges,
        is_cancelled,
    )?;
    enter_results.push(ValueId(3));
    let mut enter_arguments = try_vec(
        2,
        "MachineWir model edges",
        limits.model_edges,
        is_cancelled,
    )?;
    enter_arguments.extend([ValueId(0), ValueId(1)]);
    let mut enter_instructions = try_vec(
        1,
        "MachineWir instructions",
        limits.instructions,
        is_cancelled,
    )?;
    enter_instructions.push(MachineInstruction {
        id: InstructionId(1),
        results: enter_results,
        operation: MachineOperation::RuntimeCall {
            intrinsic: RuntimeIntrinsic::ImageEnter,
            arguments: enter_arguments,
        },
        source: None,
    });
    let mut success_cases = try_vec(
        1,
        "MachineWir model edges",
        limits.model_edges,
        is_cancelled,
    )?;
    success_cases.push((0, BlockId(0), Vec::new()));
    blocks.push(MachineBlock {
        id: BlockId(1),
        parameters: Vec::new(),
        instructions: enter_instructions,
        terminator: MachineTerminator::Switch {
            value: ValueId(3),
            cases: success_cases,
            default: BlockId(2),
            default_arguments: Vec::new(),
        },
    });
    let mut failure_return = try_vec(
        1,
        "MachineWir model edges",
        limits.model_edges,
        is_cancelled,
    )?;
    failure_return.push(ValueId(3));
    blocks.push(MachineBlock {
        id: BlockId(2),
        parameters: Vec::new(),
        instructions: Vec::new(),
        terminator: MachineTerminator::Return(failure_return),
    });
    let mut functions = try_vec(1, "MachineWir functions", limits.functions, is_cancelled)?;
    functions.push(MachineFunction {
        id: FunctionId(0),
        flow_function: minimum.entry.id.0,
        origin: match minimum.entry.origin {
            flow::FunctionOrigin::GeneratedImageEntry {
                semantic_function,
                constructor,
            } => MachineFunctionOrigin::GeneratedImageEntry {
                semantic_function,
                constructor,
            },
            _ => return Err(unsupported("noncanonical minimum image-entry provenance")),
        },
        role: MachineFunctionRole::ImageEntry,
        symbol: SymbolId(0),
        section: SectionId(0),
        linkage: Linkage::ExportedEntry,
        convention: CallingConvention::UefiAarch64,
        parameters,
        result: MachineTypeId(2),
        proofs: Vec::new(),
        values,
        stack_slots: Vec::new(),
        blocks,
        entry: BlockId(1),
        stack_bytes: 0,
        source: minimum.entry.source,
    });

    let mut source_proofs = try_vec(
        3,
        "MachineWir model edges",
        limits.model_edges,
        is_cancelled,
    )?;
    source_proofs.extend([
        minimum.type_proof.id.0,
        minimum.effects_proof.id.0,
        minimum.image_closed_proof.id.0,
    ]);
    let mut proof_sources = try_vec(
        minimum.image_closed_proof.sources.len(),
        "MachineWir model edges",
        limits.model_edges,
        is_cancelled,
    )?;
    for source in &minimum.image_closed_proof.sources {
        check_cancelled(is_cancelled)?;
        proof_sources.push(*source);
    }
    let mut proofs = try_vec(
        1,
        "MachineWir proofs",
        u64::from(limits.proofs),
        is_cancelled,
    )?;
    proofs.push(BackendProof {
        id: ProofId(0),
        source_proofs,
        kind: BackendProofKind::ImageClosed,
        depends_on: Vec::new(),
        bound: minimum.image_closed_proof.bound,
        sources: proof_sources,
        statement: copy_text(
            MINIMUM_BACKEND_PROOF,
            "MachineWir payload bytes",
            limits.payload_bytes,
            is_cancelled,
        )?,
        source: minimum.image_closed_proof.sources.first().copied(),
    });

    check_cancelled(is_cancelled)?;
    let target_identity = copy_text(
        target.identity().as_str(),
        "MachineWir payload bytes",
        limits.payload_bytes,
        is_cancelled,
    )?;
    let wir = MachineWir {
        version: MACHINE_WIR_VERSION,
        name: copy_text(
            &minimum.input.name,
            "MachineWir payload bytes",
            limits.payload_bytes,
            is_cancelled,
        )?,
        build: build.identity.clone(),
        target: MachineTarget {
            identity: target_identity.clone(),
            llvm_triple: copy_text(
                backend.llvm_triple(),
                "MachineWir payload bytes",
                limits.payload_bytes,
                is_cancelled,
            )?,
            data_layout: copy_text(
                backend.llvm_data_layout(),
                "MachineWir payload bytes",
                limits.payload_bytes,
                is_cancelled,
            )?,
            cpu: copy_text(
                backend.llvm_cpu(),
                "MachineWir payload bytes",
                limits.payload_bytes,
                is_cancelled,
            )?,
            features,
            coff_machine: copy_text(
                backend.coff_machine(),
                "MachineWir payload bytes",
                limits.payload_bytes,
                is_cancelled,
            )?,
        },
        layout: DataLayout {
            pointer_bits: 64,
            pointer_alignment: 8,
            stack_alignment: 16,
            aggregate_alignment: 8,
            maximum_object_alignment: 16,
            endianness: Endianness::Little,
        },
        runtime: RuntimeRequirements::new(vec![RuntimeIntrinsic::ImageEnter]),
        types,
        sections,
        symbols,
        globals: Vec::new(),
        functions,
        activations: Vec::new(),
        schedulers: Vec::new(),
        region_storage: Vec::new(),
        interrupts: Vec::new(),
        tests: Vec::new(),
        proofs,
        image_entry: FunctionId(0),
    };
    let mut runtime_uses = try_vec(
        1,
        "MachineWir model edges",
        limits.model_edges,
        is_cancelled,
    )?;
    runtime_uses.push(RuntimeUse {
        intrinsic: RuntimeIntrinsic::ImageEnter,
        call_sites: 1,
        reason: copy_text(
            IMAGE_ENTER_RUNTIME_REASON,
            "machine lowering report bytes",
            limits.report_bytes,
            is_cancelled,
        )?,
    });
    let report = MachineLoweringReport {
        target_identity,
        types_laid_out: 3,
        functions_lowered: 1,
        layout: LayoutSummary {
            code_bytes_upper_bound: MINIMUM_ENTRY_CODE_BYTES,
            read_only_bytes: u64::from(INTERRUPT_ROUTE_LAYOUT.header_bytes),
            writable_bytes: 0,
            zero_fill_bytes: 0,
            maximum_stack_bytes: 0,
            maximum_alignment: 16,
        },
        runtime: RuntimeRequirements::new(vec![RuntimeIntrinsic::ImageEnter]),
        runtime_uses,
    };
    check_cancelled(is_cancelled)?;
    Ok((wir, report))
}

fn lower_supported(
    request: &MachineLoweringRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(MachineWir, MachineLoweringReport), MachineLowerError> {
    require_exact_core_zero_scheduler_ownership(request.input.wir().as_wir(), is_cancelled)?;
    if let Ok(minimum) = supported_minimum(request.input) {
        preflight_minimum_output(
            &minimum,
            request.target,
            request.build,
            request.limits,
            is_cancelled,
        )?;
        check_cancelled(is_cancelled)?;
        lower_minimum(
            &minimum,
            request.target,
            request.build,
            request.limits,
            is_cancelled,
        )
    } else {
        scalar::lower_scalar_image(request, is_cancelled)
    }
}

fn require_exact_core_zero_scheduler_ownership(
    input: &flow::FlowWir,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), MachineLowerError> {
    check_cancelled(is_cancelled)?;
    let has_scheduled_work = !input.actors.is_empty() || !input.tasks.is_empty();
    let exact = if has_scheduled_work {
        input.schedulers.len() == 1
            && input.schedulers[0].core == 0
            && input.schedulers[0].actors.len() == input.actors.len()
            && input.schedulers[0]
                .actors
                .iter()
                .copied()
                .eq(input.actors.iter().map(|actor| actor.id))
            && input.schedulers[0].tasks.len() == input.tasks.len()
            && input.schedulers[0]
                .tasks
                .iter()
                .copied()
                .eq(input.tasks.iter().map(|task| task.id))
    } else {
        input.schedulers.is_empty()
    };
    if exact {
        Ok(())
    } else {
        Err(unsupported(
            "scheduler ownership beyond the exact core-zero partition",
        ))
    }
}

pub fn seal(
    request: &MachineLoweringRequest<'_>,
    wir: MachineWir,
    report: MachineLoweringReport,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<MachineLoweringOutput, MachineLowerError> {
    check_cancelled(is_cancelled)?;
    request.limits.validate()?;
    validate_request_identity(request, is_cancelled)?;
    request
        .target
        .validate()
        .map_err(|error| MachineLowerError::UnsupportedTarget(error.to_string()))?;
    let (expected_wir, expected_report) = lower_supported(request, is_cancelled)?;
    if !equality::machine_wir_equal(&wir, &expected_wir, is_cancelled)?
        || !equality::report_equal(&report, &expected_report, is_cancelled)?
    {
        return Err(MachineLowerError::OutputDoesNotImplementInput);
    }
    if wir.build != request.build.identity {
        return Err(MachineLowerError::BuildIdentityMismatch);
    }
    validate_limits(&wir, request.limits, is_cancelled)?;
    validate_build_profile_limits(&wir, request.build, is_cancelled)?;
    check_cancelled(is_cancelled)?;
    check_cancelled(is_cancelled)?;
    let wir = wir
        .validate_with_limits(request.target, request.limits.validation, is_cancelled)
        .map_err(|failure| match failure {
            ValidationFailure::InvalidLimits => MachineLowerError::InvalidLimits,
            ValidationFailure::Cancelled => MachineLowerError::Cancelled,
            ValidationFailure::ResourceLimit { resource, limit } => {
                MachineLowerError::ResourceLimit { resource, limit }
            }
            ValidationFailure::Invalid(errors) => MachineLowerError::InvalidOutput(errors),
        })?;
    check_cancelled(is_cancelled)?;
    if !flow_mapping_matches(request.input, &wir, is_cancelled)? {
        return Err(MachineLowerError::InvalidReport(
            "MachineWir does not preserve the exact FlowWir function and interrupt mapping",
        ));
    }
    check_cancelled(is_cancelled)?;
    validate_report(&wir, &report, request.limits, is_cancelled)?;
    check_cancelled(is_cancelled)?;
    Ok(MachineLoweringOutput { wir, report })
}

fn validate_build_profile_limits(
    wir: &MachineWir,
    build: &ValidatedBuildConfiguration,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), MachineLowerError> {
    let limit = build.profile.memory.static_bytes;
    let mut static_bytes = 0u64;
    for section in &wir.sections {
        check_cancelled(is_cancelled)?;
        static_bytes = static_bytes.checked_add(section.reserved_bytes).ok_or(
            MachineLowerError::ResourceLimit {
                resource: "build profile static bytes",
                limit,
            },
        )?;
        check_resource("build profile static bytes", static_bytes, limit)?;
    }
    Ok(())
}

fn flow_mapping_matches(
    input: &OptimizedFlowWir,
    output: &ValidatedMachineWir,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, MachineLowerError> {
    let flow = input.wir().as_wir();
    let machine = output.as_wir();
    if flow.functions.len() != machine.functions.len()
        || flow.tests.len() != machine.tests.len()
        || flow.schedulers.len() != machine.schedulers.len()
        || machine.image_entry.0 != flow.image_entry.0
    {
        return Ok(false);
    }
    for (source, lowered) in flow.schedulers.iter().zip(&machine.schedulers) {
        check_cancelled(is_cancelled)?;
        if lowered.core != source.core
            || !lowered
                .actors
                .iter()
                .copied()
                .eq(source.actors.iter().map(|actor| actor.0))
            || !lowered
                .tasks
                .iter()
                .copied()
                .eq(source.tasks.iter().map(|task| task.0))
        {
            return Ok(false);
        }
    }
    for (index, (source, lowered)) in flow.functions.iter().zip(&machine.functions).enumerate() {
        check_cancelled(is_cancelled)?;
        let role = match source.role {
            flow::FunctionRole::Ordinary => MachineFunctionRole::Ordinary,
            flow::FunctionRole::ActorTurn(id) => MachineFunctionRole::ActorTurn(id.0),
            flow::FunctionRole::TaskEntry(id) => MachineFunctionRole::TaskEntry(id.0),
            flow::FunctionRole::Isr(id) => MachineFunctionRole::Isr(id.0),
            flow::FunctionRole::Cleanup => MachineFunctionRole::Cleanup,
            flow::FunctionRole::ImageEntry => MachineFunctionRole::ImageEntry,
            flow::FunctionRole::Test => MachineFunctionRole::Test,
        };
        let origin = match source.origin {
            flow::FunctionOrigin::SourceSemantic { semantic_function } => {
                MachineFunctionOrigin::SourceSemantic { semantic_function }
            }
            flow::FunctionOrigin::GeneratedImageEntry {
                semantic_function,
                constructor,
            } => MachineFunctionOrigin::GeneratedImageEntry {
                semantic_function,
                constructor,
            },
            flow::FunctionOrigin::GeneratedTestHarness {
                semantic_function,
                group,
            } => MachineFunctionOrigin::GeneratedTestHarness {
                semantic_function,
                group,
            },
            flow::FunctionOrigin::GeneratedAsyncState {
                semantic_function,
                state,
            } => MachineFunctionOrigin::GeneratedAsyncState {
                semantic_function,
                state,
            },
            flow::FunctionOrigin::GeneratedCleanup {
                semantic_function,
                scope,
            } => MachineFunctionOrigin::GeneratedCleanup {
                semantic_function,
                scope,
            },
        };
        let Some(fixed_array_stack) = fixed_array_stack_allowance(source, lowered, is_cancelled)?
        else {
            return Ok(false);
        };
        let Some(stack_bound) = source.stack_bound.checked_add(fixed_array_stack) else {
            return Ok(false);
        };
        if lowered.flow_function as usize != index
            || lowered.origin != origin
            || lowered.role != role
            || lowered.source != source.source
            || lowered.stack_bytes > stack_bound
        {
            return Ok(false);
        }
    }
    if flow.activations.len() != machine.activations.len() {
        return Ok(false);
    }
    for (source, lowered) in flow.activations.iter().zip(&machine.activations) {
        check_cancelled(is_cancelled)?;
        let Some(caller) = flow.functions.get(source.caller.0 as usize) else {
            return Ok(false);
        };
        let Some(region) = flow.regions.get(source.region.0 as usize) else {
            return Ok(false);
        };
        let Some(capacity) = flow.proofs.get(source.capacity_proof.0 as usize) else {
            return Ok(false);
        };
        let [cleanup] = capacity.depends_on.as_slice() else {
            return Ok(false);
        };
        let owner = match caller.role {
            flow::FunctionRole::ActorTurn(actor) => {
                let Some(actor_plan) = flow.actors.get(actor.0 as usize) else {
                    return Ok(false);
                };
                wrela_machine_wir::MachineActivationOwner::Actor {
                    actor: actor.0,
                    mailbox_capacity: actor_plan.mailbox_capacity,
                }
            }
            flow::FunctionRole::TaskEntry(task) => {
                let Some(task_plan) = flow.tasks.get(task.0 as usize) else {
                    return Ok(false);
                };
                wrela_machine_wir::MachineActivationOwner::Task {
                    task: task.0,
                    slots: task_plan.slots,
                    supervisor: task_plan.supervisor.map(|actor| actor.0),
                }
            }
            _ => return Ok(false),
        };
        let schedule = match owner {
            wrela_machine_wir::MachineActivationOwner::Actor { .. } => {
                let mut has_message = false;
                for function in &flow.functions {
                    check_cancelled(is_cancelled)?;
                    for block in &function.blocks {
                        check_cancelled(is_cancelled)?;
                        for instruction in &block.instructions {
                            check_cancelled(is_cancelled)?;
                            has_message |= matches!(
                                instruction.operation,
                                flow::FlowOperation::ActorReserve { method, .. }
                                    if method == source.caller
                            );
                        }
                    }
                }
                let recurring = match caller.role {
                    flow::FunctionRole::ActorTurn(actor) => flow
                        .actors
                        .get(actor.0 as usize)
                        .is_some_and(|record| record.turn_functions.len() == 2),
                    _ => false,
                };
                if recurring && has_message {
                    wrela_machine_wir::MachineActivationSchedule::SchedulerFifo
                } else if has_message {
                    wrela_machine_wir::MachineActivationSchedule::MailboxOnce
                } else {
                    wrela_machine_wir::MachineActivationSchedule::DormantMailbox
                }
            }
            wrela_machine_wir::MachineActivationOwner::Task { .. } => {
                wrela_machine_wir::MachineActivationSchedule::StartupOnce
            }
        };
        if lowered.id.0 != source.id.0
            || lowered.owner != owner
            || lowered.schedule != schedule
            || lowered.caller.0 != source.caller.0
            || lowered.callee.0 != source.callee.0
            || lowered.region != source.region.0
            || lowered.region_capacity_bytes != region.capacity_bytes
            || u64::from(lowered.region_alignment) != region.alignment
            || lowered.frame_bytes != source.frame_bytes
            || lowered.maximum_live != source.maximum_live
            || lowered.capacity_proof.0 != source.capacity_proof.0
            || lowered.capacity_bound != capacity.bound.unwrap_or(0)
            || lowered.cleanup_proof.0 != cleanup.0
            || lowered.source != source.source
        {
            return Ok(false);
        }
    }
    for (source, lowered) in flow.tests.iter().zip(&machine.tests) {
        check_cancelled(is_cancelled)?;
        let kind = match source.kind {
            flow::TestKind::Comptime => wrela_machine_wir::MachineTestKind::Comptime,
            flow::TestKind::Integration => wrela_machine_wir::MachineTestKind::Integration,
            flow::TestKind::Image => wrela_machine_wir::MachineTestKind::Image,
        };
        if lowered.id.0 != source.id.0
            || !cancellable_text_equal(&lowered.name, &source.name, is_cancelled)?
            || lowered.function.0 != source.function.0
            || lowered.kind != kind
            || lowered.source != source.source
            || lowered.timeout_ns != source.timeout_ns
        {
            return Ok(false);
        }
    }

    let mut expected_interrupts = 0usize;
    for device in &flow.devices {
        check_cancelled(is_cancelled)?;
        expected_interrupts = expected_interrupts
            .checked_add(device.interrupt_functions.len())
            .ok_or(MachineLowerError::ResourceLimit {
                resource: "FlowWir interrupt mappings",
                limit: u64::try_from(machine.interrupts.len()).unwrap_or(u64::MAX),
            })?;
    }
    if expected_interrupts != machine.interrupts.len() {
        return Ok(false);
    }
    for device in &flow.devices {
        check_cancelled(is_cancelled)?;
        for function in &device.interrupt_functions {
            check_cancelled(is_cancelled)?;
            let mut left = 0usize;
            let mut right = machine.interrupts.len();
            let mut found = None;
            while left < right {
                check_cancelled(is_cancelled)?;
                let middle = left + (right - left) / 2;
                let Some(interrupt) = machine.interrupts.get(middle) else {
                    return Ok(false);
                };
                match cancellable_text_compare(
                    interrupt.target_binding.as_str(),
                    device.target_binding.as_str(),
                    is_cancelled,
                )? {
                    Ordering::Less => left = middle + 1,
                    Ordering::Greater => right = middle,
                    Ordering::Equal => {
                        found = Some(middle);
                        break;
                    }
                }
            }
            let Some(index) = found else {
                return Ok(false);
            };
            let Some(interrupt) = machine.interrupts.get(index) else {
                return Ok(false);
            };
            let handler_matches = machine
                .functions
                .get(interrupt.handler.0 as usize)
                .is_some_and(|handler| handler.flow_function == function.0);
            if interrupt.device != device.id.0 || !handler_matches {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn fixed_array_stack_allowance(
    source: &flow::FlowFunction,
    lowered: &MachineFunction,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Option<u64>, MachineLowerError> {
    let source_indexes = source
        .blocks
        .iter()
        .flat_map(|block| &block.instructions)
        .filter(|instruction| {
            matches!(
                instruction.operation,
                flow::FlowOperation::ExtractIndex { .. }
            )
        })
        .count();
    let fixed_slots = lowered
        .stack_slots
        .iter()
        .filter(|slot| slot.source_name.as_deref() == Some("fixed-array.index.storage"))
        .collect::<Vec<_>>();
    if source_indexes != fixed_slots.len() {
        return Ok(None);
    }
    let mut bytes = 0_u64;
    for slot in fixed_slots {
        check_cancelled(is_cancelled)?;
        let alignment = u64::from(slot.alignment);
        bytes = bytes
            .checked_add(alignment - 1)
            .map(|bytes| bytes & !(alignment - 1))
            .and_then(|bytes| bytes.checked_add(slot.size))
            .ok_or(MachineLowerError::InvalidReport(
                "fixed-array implementation stack overflows",
            ))?;
    }
    bytes
        .checked_add(15)
        .map(|bytes| bytes & !15)
        .map(Some)
        .ok_or(MachineLowerError::InvalidReport(
            "fixed-array implementation stack overflows",
        ))
}

fn validate_report(
    validated: &ValidatedMachineWir,
    report: &MachineLoweringReport,
    limits: MachineLoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), MachineLowerError> {
    check_cancelled(is_cancelled)?;
    let wir = validated.as_wir();
    if !cancellable_text_equal(&report.target_identity, &wir.target.identity, is_cancelled)? {
        return Err(MachineLowerError::InvalidReport("target identity mismatch"));
    }
    if report.types_laid_out != wir.types.len() as u64
        || report.functions_lowered != wir.functions.len() as u64
        || report.runtime != wir.runtime
    {
        return Err(MachineLowerError::InvalidReport(
            "type/function/runtime counts do not match MachineWir",
        ));
    }
    let mut code_bytes = 0u64;
    let mut read_only_bytes = 0u64;
    let mut writable_bytes = 0u64;
    let mut zero_fill_bytes = 0u64;
    let mut maximum_alignment = 1u32;
    for ty in &wir.types {
        check_cancelled(is_cancelled)?;
        maximum_alignment = maximum_alignment.max(ty.alignment);
    }
    for section in &wir.sections {
        check_cancelled(is_cancelled)?;
        maximum_alignment = maximum_alignment.max(section.alignment);
        let total = match section.kind {
            SectionKind::Code => &mut code_bytes,
            SectionKind::ReadOnlyData | SectionKind::RuntimeMetadata => &mut read_only_bytes,
            SectionKind::WritableData => &mut writable_bytes,
            SectionKind::ZeroFill => &mut zero_fill_bytes,
            SectionKind::Relocations | SectionKind::Debug => continue,
        };
        *total =
            total
                .checked_add(section.reserved_bytes)
                .ok_or(MachineLowerError::InvalidReport(
                    "section layout byte count overflows",
                ))?;
    }
    for global in &wir.globals {
        check_cancelled(is_cancelled)?;
        maximum_alignment = maximum_alignment.max(global.alignment);
    }
    let mut maximum_stack_bytes = 0u64;
    for function in &wir.functions {
        check_cancelled(is_cancelled)?;
        maximum_stack_bytes = maximum_stack_bytes.max(function.stack_bytes);
        for slot in &function.stack_slots {
            check_cancelled(is_cancelled)?;
            maximum_alignment = maximum_alignment.max(slot.alignment);
        }
    }
    let layout_matches = code_bytes == report.layout.code_bytes_upper_bound
        && read_only_bytes == report.layout.read_only_bytes
        && writable_bytes == report.layout.writable_bytes
        && zero_fill_bytes == report.layout.zero_fill_bytes
        && maximum_stack_bytes == report.layout.maximum_stack_bytes
        && maximum_alignment == report.layout.maximum_alignment;
    if !layout_matches {
        return Err(MachineLowerError::InvalidReport(
            "layout summary does not match section/function layout",
        ));
    }
    for pair in report.runtime_uses.windows(2) {
        check_cancelled(is_cancelled)?;
        if pair[0].intrinsic >= pair[1].intrinsic {
            return Err(MachineLowerError::InvalidReport(
                "runtime uses are not canonical",
            ));
        }
    }
    for usage in &report.runtime_uses {
        check_cancelled(is_cancelled)?;
        let mut has_non_whitespace = false;
        for character in usage.reason.chars() {
            check_cancelled(is_cancelled)?;
            if !character.is_whitespace() {
                has_non_whitespace = true;
                break;
            }
        }
        if usage.call_sites == 0 || !has_non_whitespace {
            return Err(MachineLowerError::InvalidReport(
                "runtime uses are not canonical",
            ));
        }
    }
    let mut runtime_call_counts = std::collections::BTreeMap::new();
    for function in &wir.functions {
        check_cancelled(is_cancelled)?;
        for block in &function.blocks {
            check_cancelled(is_cancelled)?;
            for instruction in &block.instructions {
                check_cancelled(is_cancelled)?;
                let intrinsic = match &instruction.operation {
                    MachineOperation::RuntimeCall { intrinsic, .. } => Some(*intrinsic),
                    MachineOperation::CheckedInteger { .. }
                    | MachineOperation::CheckedConvert { .. }
                    | MachineOperation::ActorReserve { .. }
                    | MachineOperation::ActorReplyRequest { .. }
                    | MachineOperation::MailboxReceive { .. } => Some(RuntimeIntrinsic::Fatal),
                    MachineOperation::TestAssert { .. } => {
                        Some(RuntimeIntrinsic::TestAssertionFail)
                    }
                    _ => None,
                };
                if let Some(intrinsic) = intrinsic {
                    let count = runtime_call_counts.entry(intrinsic).or_insert(0u64);
                    *count = count
                        .checked_add(1)
                        .ok_or(MachineLowerError::InvalidReport(
                            "runtime call-site count overflows",
                        ))?;
                }
            }
        }
    }
    let mut actual_uses = try_vec(
        wir.runtime.intrinsics.len(),
        "MachineWir model edges",
        limits.model_edges,
        is_cancelled,
    )?;
    for intrinsic in &wir.runtime.intrinsics {
        check_cancelled(is_cancelled)?;
        let count = runtime_call_counts.get(intrinsic).copied().unwrap_or(0);
        if count != 0 {
            actual_uses.push((*intrinsic, count));
        }
    }
    if report.runtime_uses.len() != actual_uses.len() {
        return Err(MachineLowerError::InvalidReport(
            "runtime call-site counts do not match MachineWir",
        ));
    }
    for (reported, actual) in report.runtime_uses.iter().zip(actual_uses) {
        check_cancelled(is_cancelled)?;
        if (reported.intrinsic, reported.call_sites) != actual {
            return Err(MachineLowerError::InvalidReport(
                "runtime call-site counts do not match MachineWir",
            ));
        }
    }
    let mut report_bytes = u64::try_from(report.target_identity.len()).map_err(|_| {
        MachineLowerError::ResourceLimit {
            resource: "machine lowering report bytes",
            limit: limits.report_bytes,
        }
    })?;
    for usage in &report.runtime_uses {
        check_cancelled(is_cancelled)?;
        report_bytes = report_bytes
            .checked_add(u64::try_from(usage.reason.len()).map_err(|_| {
                MachineLowerError::ResourceLimit {
                    resource: "machine lowering report bytes",
                    limit: limits.report_bytes,
                }
            })?)
            .ok_or(MachineLowerError::ResourceLimit {
                resource: "machine lowering report bytes",
                limit: limits.report_bytes,
            })?;
    }
    if report_bytes > limits.report_bytes {
        return Err(MachineLowerError::ResourceLimit {
            resource: "machine lowering report bytes",
            limit: limits.report_bytes,
        });
    }
    check_cancelled(is_cancelled)
}

fn validate_limits(
    wir: &MachineWir,
    limits: MachineLoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), MachineLowerError> {
    check_cancelled(is_cancelled)?;
    for (resource, actual, limit) in [
        (
            "MachineWir types",
            u64::try_from(wir.types.len()).unwrap_or(u64::MAX),
            limits.types,
        ),
        (
            "MachineWir functions",
            u64::try_from(wir.functions.len()).unwrap_or(u64::MAX),
            limits.functions,
        ),
        (
            "MachineWir sections",
            u64::try_from(wir.sections.len()).unwrap_or(u64::MAX),
            u64::from(limits.sections),
        ),
        (
            "MachineWir symbols",
            u64::try_from(wir.symbols.len()).unwrap_or(u64::MAX),
            u64::from(limits.symbols),
        ),
        (
            "MachineWir globals",
            u64::try_from(wir.globals.len()).unwrap_or(u64::MAX),
            u64::from(limits.globals),
        ),
        (
            "MachineWir proofs",
            u64::try_from(wir.proofs.len()).unwrap_or(u64::MAX),
            u64::from(limits.proofs),
        ),
    ] {
        check_resource(resource, actual, limit)?;
    }

    let mut instructions = 0u64;
    let mut stack_slots = 0u64;
    for function in &wir.functions {
        check_cancelled(is_cancelled)?;
        check_resource(
            "MachineWir stack bytes per function",
            function.stack_bytes,
            limits.stack_bytes_per_function,
        )?;
        stack_slots = stack_slots
            .checked_add(u64::try_from(function.stack_slots.len()).unwrap_or(u64::MAX))
            .ok_or(MachineLowerError::ResourceLimit {
                resource: "MachineWir stack slots",
                limit: limits.stack_slots,
            })?;
        check_resource("MachineWir stack slots", stack_slots, limits.stack_slots)?;
        for block in &function.blocks {
            check_cancelled(is_cancelled)?;
            instructions = instructions
                .checked_add(u64::try_from(block.instructions.len()).unwrap_or(u64::MAX))
                .ok_or(MachineLowerError::ResourceLimit {
                    resource: "MachineWir instructions",
                    limit: limits.instructions,
                })?;
            check_resource("MachineWir instructions", instructions, limits.instructions)?;
        }
    }

    let mut static_bytes = 0u64;
    for section in &wir.sections {
        check_cancelled(is_cancelled)?;
        static_bytes = static_bytes.checked_add(section.reserved_bytes).ok_or(
            MachineLowerError::ResourceLimit {
                resource: "MachineWir static bytes",
                limit: limits.static_bytes,
            },
        )?;
        check_resource("MachineWir static bytes", static_bytes, limits.static_bytes)?;
    }
    model_resources(wir, limits, is_cancelled)?;
    check_cancelled(is_cancelled)
}

struct ResourceMeter {
    edges: u64,
    payload_bytes: u64,
    edge_limit: u64,
    payload_limit: u64,
}

impl ResourceMeter {
    fn new(limits: MachineLoweringLimits) -> Self {
        Self {
            edges: 0,
            payload_bytes: 0,
            edge_limit: limits.model_edges,
            payload_limit: limits.payload_bytes,
        }
    }

    fn edges<T>(&mut self, values: &[T]) -> Result<(), MachineLowerError> {
        self.add_edges(values.len())
    }

    fn add_edges(&mut self, count: usize) -> Result<(), MachineLowerError> {
        let count = u64::try_from(count).map_err(|_| MachineLowerError::ResourceLimit {
            resource: "MachineWir model edges",
            limit: self.edge_limit,
        })?;
        self.edges = self
            .edges
            .checked_add(count)
            .filter(|total| *total <= self.edge_limit)
            .ok_or(MachineLowerError::ResourceLimit {
                resource: "MachineWir model edges",
                limit: self.edge_limit,
            })?;
        Ok(())
    }

    fn text(&mut self, value: &str) -> Result<(), MachineLowerError> {
        self.add_payload(value.len())
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), MachineLowerError> {
        self.add_payload(value.len())
    }

    fn add_payload(&mut self, count: usize) -> Result<(), MachineLowerError> {
        let count = u64::try_from(count).map_err(|_| MachineLowerError::ResourceLimit {
            resource: "MachineWir payload bytes",
            limit: self.payload_limit,
        })?;
        self.payload_bytes = self
            .payload_bytes
            .checked_add(count)
            .filter(|total| *total <= self.payload_limit)
            .ok_or(MachineLowerError::ResourceLimit {
                resource: "MachineWir payload bytes",
                limit: self.payload_limit,
            })?;
        Ok(())
    }
}

fn model_resources(
    wir: &MachineWir,
    limits: MachineLoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(u64, u64), MachineLowerError> {
    use wrela_machine_wir::{
        MachineImmediate, MachineOperation, MachineTerminator, MachineTypeKind,
    };

    check_cancelled(is_cancelled)?;
    let mut meter = ResourceMeter::new(limits);
    meter.text(&wir.name)?;
    meter.text(wir.build.target.as_str())?;
    meter.text(&wir.target.identity)?;
    meter.text(&wir.target.llvm_triple)?;
    meter.text(&wir.target.data_layout)?;
    meter.text(&wir.target.cpu)?;
    meter.text(&wir.target.coff_machine)?;
    meter.edges(&wir.target.features)?;
    for feature in &wir.target.features {
        check_cancelled(is_cancelled)?;
        meter.text(feature)?;
    }
    meter.edges(&wir.runtime.intrinsics)?;
    for count in [
        wir.types.len(),
        wir.sections.len(),
        wir.symbols.len(),
        wir.globals.len(),
        wir.functions.len(),
        wir.activations.len(),
        wir.schedulers.len(),
        wir.interrupts.len(),
        wir.tests.len(),
        wir.proofs.len(),
    ] {
        meter.add_edges(count)?;
    }
    for scheduler in &wir.schedulers {
        check_cancelled(is_cancelled)?;
        meter.edges(&scheduler.actors)?;
        meter.edges(&scheduler.tasks)?;
    }
    let immediate =
        |value: &MachineImmediate, meter: &mut ResourceMeter| -> Result<(), MachineLowerError> {
            match value {
                MachineImmediate::Integer { bytes_le, .. } | MachineImmediate::Bytes(bytes_le) => {
                    meter.bytes(bytes_le)
                }
                MachineImmediate::Float32(_)
                | MachineImmediate::Float64(_)
                | MachineImmediate::Null(_)
                | MachineImmediate::Zero(_)
                | MachineImmediate::SymbolAddress(_) => Ok(()),
            }
        };
    for ty in &wir.types {
        check_cancelled(is_cancelled)?;
        if let Some(name) = &ty.source_name {
            meter.text(name)?;
        }
        match &ty.kind {
            MachineTypeKind::Struct { fields, .. } => meter.edges(fields)?,
            MachineTypeKind::TaggedEnum {
                payload,
                storage,
                variant_payloads,
                ..
            } => {
                meter.add_edges(
                    1 + usize::from(payload.is_some()) + usize::from(storage.is_some()),
                )?;
                meter.edges(variant_payloads)?;
            }
            MachineTypeKind::Function { parameters, .. } => meter.edges(parameters)?,
            MachineTypeKind::Void
            | MachineTypeKind::Integer { .. }
            | MachineTypeKind::Float32
            | MachineTypeKind::Float64
            | MachineTypeKind::Pointer { .. }
            | MachineTypeKind::Vector { .. }
            | MachineTypeKind::Array { .. } => {}
        }
    }
    for section in &wir.sections {
        check_cancelled(is_cancelled)?;
        meter.text(&section.name)?;
        meter.text(&section.owner)?;
    }
    for symbol in &wir.symbols {
        check_cancelled(is_cancelled)?;
        meter.text(&symbol.name)?;
    }
    for global in &wir.globals {
        check_cancelled(is_cancelled)?;
        immediate(&global.initializer, &mut meter)?;
    }
    for test in &wir.tests {
        check_cancelled(is_cancelled)?;
        meter.text(&test.name)?;
    }
    for function in &wir.functions {
        check_cancelled(is_cancelled)?;
        meter.edges(&function.parameters)?;
        meter.edges(&function.proofs)?;
        meter.edges(&function.values)?;
        meter.edges(&function.stack_slots)?;
        meter.edges(&function.blocks)?;
        for value in &function.values {
            check_cancelled(is_cancelled)?;
            if let Some(name) = &value.source_name {
                meter.text(name)?;
            }
        }
        for slot in &function.stack_slots {
            check_cancelled(is_cancelled)?;
            if let Some(name) = &slot.source_name {
                meter.text(name)?;
            }
            meter.edges(&slot.live_states)?;
        }
        for block in &function.blocks {
            check_cancelled(is_cancelled)?;
            meter.edges(&block.parameters)?;
            meter.edges(&block.instructions)?;
            for instruction in &block.instructions {
                check_cancelled(is_cancelled)?;
                meter.edges(&instruction.results)?;
                match &instruction.operation {
                    MachineOperation::Immediate(value) => immediate(value, &mut meter)?,
                    MachineOperation::Call { arguments, .. }
                    | MachineOperation::RuntimeCall { arguments, .. }
                    | MachineOperation::MakeStruct {
                        fields: arguments, ..
                    }
                    | MachineOperation::MakeArray {
                        elements: arguments,
                        ..
                    } => meter.edges(arguments)?,
                    MachineOperation::TestAssert { failure, .. } => {
                        meter.text(&failure.expression)?;
                        if let Some(message) = &failure.message {
                            meter.text(message)?;
                        }
                    }
                    MachineOperation::Unary { .. }
                    | MachineOperation::Arithmetic { .. }
                    | MachineOperation::CheckedInteger { .. }
                    | MachineOperation::IntegerCompare { .. }
                    | MachineOperation::FloatCompare { .. }
                    | MachineOperation::Convert { .. }
                    | MachineOperation::CheckedConvert { .. }
                    | MachineOperation::Copy { .. }
                    | MachineOperation::Select { .. }
                    | MachineOperation::InsertField { .. }
                    | MachineOperation::ExtractField { .. }
                    | MachineOperation::ExtractIndex { .. }
                    | MachineOperation::MakeEnum { .. }
                    | MachineOperation::EnumTag { .. }
                    | MachineOperation::EnumPayload { .. }
                    | MachineOperation::AddressOffset { .. }
                    | MachineOperation::Load { .. }
                    | MachineOperation::Store { .. }
                    | MachineOperation::ActorReserve { .. }
                    | MachineOperation::ActorCommit { .. }
                    | MachineOperation::ActorReplyRequest { .. }
                    | MachineOperation::ActorReplyResolve { .. }
                    | MachineOperation::MailboxReceive { .. }
                    | MachineOperation::MailboxDispatch { .. }
                    | MachineOperation::MemoryCopy { .. }
                    | MachineOperation::MemorySet { .. }
                    | MachineOperation::StackAddress(_)
                    | MachineOperation::GlobalAddress(_)
                    | MachineOperation::Fence(_) => {}
                }
            }
            match &block.terminator {
                MachineTerminator::Jump { arguments, .. }
                | MachineTerminator::Return(arguments)
                | MachineTerminator::TailCall { arguments, .. } => meter.edges(arguments)?,
                MachineTerminator::Branch {
                    then_arguments,
                    else_arguments,
                    ..
                } => {
                    meter.edges(then_arguments)?;
                    meter.edges(else_arguments)?;
                }
                MachineTerminator::Switch {
                    cases,
                    default_arguments,
                    ..
                } => {
                    meter.edges(cases)?;
                    meter.edges(default_arguments)?;
                    for (_, _, arguments) in cases {
                        check_cancelled(is_cancelled)?;
                        meter.edges(arguments)?;
                    }
                }
                MachineTerminator::Unreachable => {}
            }
        }
    }
    for interrupt in &wir.interrupts {
        check_cancelled(is_cancelled)?;
        meter.text(&interrupt.target_binding)?;
    }
    for proof in &wir.proofs {
        check_cancelled(is_cancelled)?;
        meter.edges(&proof.source_proofs)?;
        meter.edges(&proof.depends_on)?;
        meter.edges(&proof.sources)?;
        meter.text(&proof.statement)?;
    }
    for _activation in &wir.activations {
        check_cancelled(is_cancelled)?;
        meter.add_edges(1)?;
    }
    check_cancelled(is_cancelled)?;
    Ok((meter.edges, meter.payload_bytes))
}

#[cfg(test)]
mod contract_tests {
    use std::cell::Cell;

    use super::{
        CANCELLABLE_COPY_CHUNK_BYTES, CanonicalMachineLowerer, IMAGE_ENTER_RUNTIME_REASON,
        MachineLowerError, MachineLowerer, MachineLoweringLimits, MachineLoweringOutput,
        MachineLoweringRequest, check_cancelled, lower_supported, model_resources,
        require_exact_core_zero_scheduler_ownership, seal, validate_optimizer_report_contract,
        validate_request_identity,
    };
    use wrela_build_model::{
        BuildConfiguration, BuildIdentity, BuildProfile, LanguageRevision, OptimizationLevel,
        RecordingMode, Sha256Digest, TargetIdentity, ValidatedBuildConfiguration,
        seal_build_configuration,
    };
    use wrela_flow_lower::{CanonicalFlowLowerer, FlowLowerer, LowerRequest, LoweringLimits};
    use wrela_flow_opt::{
        CanonicalFlowOptimizer, FlowOptimizer, OptimizationLimits, OptimizationProfile,
        OptimizationRequest, OptimizeError, OptimizedFlowWir,
    };
    use wrela_flow_wir::{
        ActivationCancellation, ActivationId, ActivationPlan, ActorId, ActorPlan, BinaryOp,
        Block as FlowBlock, BlockId as FlowBlockId, FlowFunction, FlowOperation, FlowType,
        FlowTypeKind, FunctionId as FlowFunctionId, FunctionOrigin, FunctionRole,
        Immediate as FlowImmediate, Instruction as FlowInstruction,
        InstructionId as FlowInstructionId, PlanOwner, Proof as FlowProof, ProofId as FlowProofId,
        ProofKind, RegionClass, RegionId, RegionPlan, ScalarType, SchedulerPlan,
        Terminator as FlowTerminator, TestEntry as FlowTestEntry, TestId as FlowTestId,
        TestKind as FlowTestKind, TypeId, ValidatedFlowWir, Value as FlowValue,
        ValueId as FlowValueId,
    };
    use wrela_machine_wir::{
        BlockId, CallingConvention, ConversionOp, FloatPredicate, MachineFunctionOrigin,
        MachineImmediate, MachineInstruction, MachineOperation, MachineTerminator, MachineTestKind,
        MachineTypeKind, MachineUnaryOp, SectionKind, SymbolDefinition, ValidationError, ValueId,
    };
    use wrela_runtime_abi::{EVENT_LOG_STORAGE_BYTES, RuntimeIntrinsic};
    use wrela_semantic_wir as semantic;
    use wrela_source::{FileId, Span, TextRange};
    use wrela_target::TargetPackage;
    use wrela_test_model::{
        GuestTestOutcome, TEST_PROTOCOL_VERSION, TestEvent, TestEventKind, TestId,
    };
    use wrela_test_protocol::{CanonicalTestEventCodec, ProtocolLimits, seal_encoded_event};

    fn span(file: u32, start: u32, end: u32) -> Span {
        Span {
            file: FileId(file),
            range: TextRange { start, end },
        }
    }

    fn identity() -> BuildIdentity {
        let digest = Sha256Digest::from_bytes([0x41; 32]);
        BuildIdentity {
            compiler: digest,
            language: LanguageRevision::Design0_1,
            target: TargetIdentity::aarch64_qemu_virt_uefi(),
            target_package: digest,
            standard_library: Sha256Digest::from_bytes([0x42; 32]),
            source_graph: Sha256Digest::from_bytes([0x43; 32]),
            request: Sha256Digest::from_bytes([0x44; 32]),
            profile: Sha256Digest::from_bytes([0x45; 32]),
        }
    }

    fn build_configuration(identity: BuildIdentity) -> ValidatedBuildConfiguration {
        build_configuration_for_level(identity, OptimizationLevel::None)
    }

    fn build_configuration_for_level(
        identity: BuildIdentity,
        level: OptimizationLevel,
    ) -> ValidatedBuildConfiguration {
        let observed_profile = identity.profile;
        let mut profile = BuildProfile::development();
        profile.optimization.level = level;
        seal_build_configuration(BuildConfiguration { identity, profile }, observed_profile)
            .expect("valid test build configuration")
    }

    fn build_configuration_with_profile_data(
        identity: BuildIdentity,
        level: OptimizationLevel,
    ) -> ValidatedBuildConfiguration {
        let observed_profile = identity.profile;
        let mut profile = BuildProfile::development();
        profile.optimization.level = level;
        profile.optimization.profile_data = Some(Sha256Digest::from_bytes([0xa5; 32]));
        seal_build_configuration(BuildConfiguration { identity, profile }, observed_profile)
            .expect("valid profile-guided test build configuration")
    }

    fn build_configuration_for_recording(
        identity: BuildIdentity,
        recording: RecordingMode,
        event_log_bytes: u64,
    ) -> ValidatedBuildConfiguration {
        let observed_profile = identity.profile;
        let mut profile = BuildProfile::development();
        profile.optimization.level = OptimizationLevel::None;
        profile.recording = recording;
        profile.memory.event_log_bytes = event_log_bytes;
        seal_build_configuration(BuildConfiguration { identity, profile }, observed_profile)
            .expect("valid recording test build configuration")
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
            sources: vec![span(0, 10, 14)],
            depends_on: depends_on.iter().copied().map(semantic::ProofId).collect(),
            explanation: vec![format!("proof explanation {id}")],
        }
    }

    fn semantic_fixture(build: BuildIdentity) -> semantic::ValidatedSemanticWir {
        semantic::SemanticWir {
            version: semantic::SEMANTIC_WIR_VERSION,
            name: "exact-runtime-image".to_owned(),
            build,
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

    fn generated_test_semantic_fixture(build: BuildIdentity) -> semantic::ValidatedSemanticWir {
        let test_source = span(0, 10, 20);
        let events = [
            TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 0,
                kind: TestEventKind::RunStarted { test_count: 1 },
            },
            TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 1,
                kind: TestEventKind::TestStarted { test: TestId(7) },
            },
            TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 2,
                kind: TestEventKind::TestFinished {
                    test: TestId(7),
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
        let frames: Vec<Vec<u8>> = events
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
            .collect();
        let mut types = vec![
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
        ];
        let mut values = Vec::new();
        let mut statements = Vec::new();
        for (marker, bytes) in frames.into_iter().enumerate() {
            let length = bytes.len() as u64;
            let ty = types
                .iter()
                .find_map(|ty| {
                    matches!(
                        ty.kind,
                        semantic::TypeKind::Array {
                            element: semantic::TypeId(1),
                            length: existing,
                        } if existing == length
                    )
                    .then_some(ty.id)
                })
                .unwrap_or_else(|| {
                    let ty = semantic::TypeId(types.len() as u32);
                    types.push(semantic::TypeRecord {
                        id: ty,
                        source_name: format!("__wrela_test_frame_{length}"),
                        kind: semantic::TypeKind::Array {
                            element: semantic::TypeId(1),
                            length,
                        },
                        linearity: semantic::Linearity::ExplicitCopy,
                        source: None,
                    });
                    ty
                });
            let value = semantic::ValueId(values.len() as u32);
            values.push(semantic::SemanticValue {
                id: value,
                ty,
                origin: None,
                name: None,
            });
            statements.push(semantic::SemanticStatement::Let(semantic::LetStatement {
                results: vec![value],
                operation: semantic::SemanticOperation::Constant(semantic::Constant::Bytes(bytes)),
                source: None,
            }));
            statements.push(semantic::SemanticStatement::Let(semantic::LetStatement {
                results: Vec::new(),
                operation: semantic::SemanticOperation::TestEmit { payload: value },
                source: None,
            }));
            if marker == 1 {
                statements.push(semantic::SemanticStatement::Let(semantic::LetStatement {
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
        let outcome = semantic::ValueId(values.len() as u32);
        values.push(semantic::SemanticValue {
            id: outcome,
            ty: semantic::TypeId(2),
            origin: None,
            name: None,
        });
        statements.extend([
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
        semantic::SemanticWir {
            version: semantic::SEMANTIC_WIR_VERSION,
            name: "__wrela_test_harness".to_owned(),
            build,
            source_summary: semantic::SourceSummary {
                hir_files: 2,
                hir_declarations: 4,
                reachable_declarations: 1,
                monomorphized_instantiations: 2,
                resolved_interface_calls: 0,
            },
            types,
            globals: Vec::new(),
            functions: vec![
                semantic::SemanticFunction {
                    id: semantic::FunctionId(0),
                    instance_key: Sha256Digest::from_bytes([0x60; 32]),
                    name: "passes_one".to_owned(),
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
                    proofs: vec![semantic::ProofId(0), semantic::ProofId(1)],
                    source: Some(test_source),
                    stack_bound: 0,
                    frame_bound: 0,
                    uninterrupted_bound: Some(1),
                    recursive_depth_bound: Some(1),
                },
                semantic::SemanticFunction {
                    id: semantic::FunctionId(1),
                    instance_key: Sha256Digest::from_bytes([0x61; 32]),
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
                        semantic::ProofId(2),
                        semantic::ProofId(3),
                        semantic::ProofId(4),
                    ],
                    source: None,
                    stack_bound: 0,
                    frame_bound: 0,
                    uninterrupted_bound: Some(6),
                    recursive_depth_bound: Some(1),
                },
            ],
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
                proof(2, semantic::ProofKind::TypeChecked, &[], Some(1)),
                proof(3, semantic::ProofKind::EffectsAllowed, &[2], Some(4)),
                proof(4, semantic::ProofKind::ImageClosed, &[2, 3], Some(1)),
            ],
            tests: vec![semantic::TestEntry {
                id: semantic::TestId(0),
                plan_id: 7,
                name: "passes_one".to_owned(),
                function: semantic::FunctionId(0),
                kind: semantic::TestKind::Integration,
                source: test_source,
                timeout_ns: 1_000_000,
            }],
            compiled_test_group: Some(wrela_test_model::FullImageTestGroup {
                id: wrela_test_model::ImageGroupId(9),
                name: "integration".to_owned(),
                root: wrela_test_model::ImageRoot::GeneratedHarness {
                    harness_name: "__wrela_test_harness".to_owned(),
                },
                tests: vec![wrela_test_model::ImageTest {
                    descriptor: wrela_test_model::TestDescriptor {
                        id: wrela_test_model::TestId(7),
                        name: "passes_one".to_owned(),
                        kind: wrela_test_model::TestKind::IntegrationImage,
                        source: Some(test_source),
                        timeout_ns: 1_000_000,
                    },
                    invocation: wrela_test_model::ImageTestInvocation::GeneratedFunction {
                        function_key: wrela_test_model::FunctionKey(Sha256Digest::from_bytes(
                            [0x60; 32],
                        )),
                    },
                    assertions: Vec::new(),
                }],
                deterministic_seed: None,
                boot_timeout_ns: 1,
                shutdown_timeout_ns: 1,
                maximum_events: 5,
                maximum_output_bytes: 1,
            }),
            startup_order: vec![semantic::ImageOwner::Runtime],
            shutdown_order: vec![semantic::ImageOwner::Runtime],
            image_entry: semantic::FunctionId(1),
            static_bytes: 0,
            peak_bytes: 0,
        }
        .validate()
        .expect("valid generated-test SemanticWir")
    }

    fn primitive_join_constant(
        primitive: semantic::PrimitiveType,
        value: u128,
    ) -> semantic::Constant {
        match primitive {
            semantic::PrimitiveType::Unit => semantic::Constant::Unit,
            semantic::PrimitiveType::Bool => semantic::Constant::Bool(value & 1 != 0),
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
            semantic::PrimitiveType::Char => {
                panic!("char is outside the revision-0.1 scalar join matrix")
            }
        }
    }

    fn primitive_join_let(
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

    /// Canonical producer fixture for the complete primitive join matrix. The
    /// generated test owns two nested joins and copies the outer result before
    /// passing it to a real helper call. The helper and its argument remain in
    /// MachineWir even when the argument is zero-sized `unit`.
    fn primitive_join_semantic_fixture(
        build: BuildIdentity,
        primitive: semantic::PrimitiveType,
    ) -> semantic::ValidatedSemanticWir {
        let mut module = generated_test_semantic_fixture(build).into_wir();
        let mut harness = module.functions.pop().expect("generated harness function");
        let bool_ty = semantic::TypeId(3);
        let scalar_ty = semantic::TypeId(4);
        for ty in &mut module.types[3..] {
            ty.id.0 += 2;
        }
        for value in &mut harness.values {
            if value.ty.0 >= 3 {
                value.ty.0 += 2;
            }
        }
        module.types.splice(
            3..3,
            [
                semantic::TypeRecord {
                    id: bool_ty,
                    source_name: "join_bool".to_owned(),
                    kind: semantic::TypeKind::Primitive(semantic::PrimitiveType::Bool),
                    linearity: semantic::Linearity::CopyScalar,
                    source: Some(span(0, 200, 204)),
                },
                semantic::TypeRecord {
                    id: scalar_ty,
                    source_name: format!("join_{primitive:?}"),
                    kind: semantic::TypeKind::Primitive(primitive),
                    linearity: semantic::Linearity::CopyScalar,
                    source: Some(span(0, 205, 212)),
                },
            ],
        );

        let value =
            |id: u32, ty: semantic::TypeId, name: &str, source: Span| semantic::SemanticValue {
                id: semantic::ValueId(id),
                ty,
                origin: Some(source),
                name: Some(name.to_owned()),
            };
        let condition_source = span(0, 214, 218);
        let inner_source = span(0, 220, 260);
        let outer_source = span(0, 219, 280);
        let copied_source = span(0, 281, 287);
        module.functions[0].values = vec![
            value(0, bool_ty, "condition", condition_source),
            value(1, scalar_ty, "inner_then", span(0, 228, 232)),
            value(2, scalar_ty, "inner_else", span(0, 240, 244)),
            value(3, scalar_ty, "inner_join", inner_source),
            value(4, scalar_ty, "outer_else", span(0, 268, 272)),
            value(5, scalar_ty, "outer_join", outer_source),
            value(6, scalar_ty, "post_join_copy", copied_source),
        ];
        module.functions[0].body = semantic::SemanticRegion {
            parameters: Vec::new(),
            statements: vec![
                primitive_join_let(
                    0,
                    semantic::SemanticOperation::Constant(semantic::Constant::Bool(true)),
                    condition_source,
                ),
                semantic::SemanticStatement::If {
                    condition: semantic::ValueId(0),
                    then_region: semantic::SemanticRegion {
                        parameters: Vec::new(),
                        statements: vec![
                            semantic::SemanticStatement::If {
                                condition: semantic::ValueId(0),
                                then_region: semantic::SemanticRegion {
                                    parameters: Vec::new(),
                                    statements: vec![
                                        primitive_join_let(
                                            1,
                                            semantic::SemanticOperation::Constant(
                                                primitive_join_constant(primitive, 1),
                                            ),
                                            span(0, 228, 232),
                                        ),
                                        semantic::SemanticStatement::Yield(vec![
                                            semantic::ValueId(1),
                                        ]),
                                    ],
                                },
                                else_region: semantic::SemanticRegion {
                                    parameters: Vec::new(),
                                    statements: vec![
                                        primitive_join_let(
                                            2,
                                            semantic::SemanticOperation::Constant(
                                                primitive_join_constant(primitive, 2),
                                            ),
                                            span(0, 240, 244),
                                        ),
                                        semantic::SemanticStatement::Yield(vec![
                                            semantic::ValueId(2),
                                        ]),
                                    ],
                                },
                                results: vec![semantic::ValueId(3)],
                                source: Some(inner_source),
                            },
                            semantic::SemanticStatement::Yield(vec![semantic::ValueId(3)]),
                        ],
                    },
                    else_region: semantic::SemanticRegion {
                        parameters: Vec::new(),
                        statements: vec![
                            primitive_join_let(
                                4,
                                semantic::SemanticOperation::Constant(primitive_join_constant(
                                    primitive, 3,
                                )),
                                span(0, 268, 272),
                            ),
                            semantic::SemanticStatement::Yield(vec![semantic::ValueId(4)]),
                        ],
                    },
                    results: vec![semantic::ValueId(5)],
                    source: Some(outer_source),
                },
                primitive_join_let(
                    6,
                    semantic::SemanticOperation::Copy {
                        value: semantic::ValueId(5),
                    },
                    copied_source,
                ),
                semantic::SemanticStatement::Let(semantic::LetStatement {
                    results: Vec::new(),
                    operation: semantic::SemanticOperation::Call {
                        function: semantic::FunctionId(1),
                        arguments: vec![semantic::Argument {
                            access: semantic::AccessMode::Read,
                            value: semantic::ValueId(6),
                        }],
                        activation: None,
                    },
                    source: Some(span(0, 288, 305)),
                }),
                semantic::SemanticStatement::Return(Vec::new()),
            ],
        };
        module.functions[0].uninterrupted_bound = Some(12);

        module.functions.push(semantic::SemanticFunction {
            id: semantic::FunctionId(1),
            instance_key: Sha256Digest::from_bytes([0x62; 32]),
            name: format!("consume_{primitive:?}"),
            origin: semantic::FunctionOrigin::Source,
            role: semantic::FunctionRole::Ordinary,
            color: semantic::FunctionColor::Sync,
            parameters: vec![semantic::ValueId(0)],
            result: semantic::TypeId(0),
            values: vec![value(0, scalar_ty, "value", span(0, 310, 315))],
            body: semantic::SemanticRegion {
                parameters: vec![semantic::ValueId(0)],
                statements: vec![semantic::SemanticStatement::Return(Vec::new())],
            },
            effects: semantic::EffectSet::default(),
            proofs: vec![semantic::ProofId(0), semantic::ProofId(1)],
            source: Some(span(0, 306, 330)),
            stack_bound: 0,
            frame_bound: 0,
            uninterrupted_bound: Some(1),
            recursive_depth_bound: Some(1),
        });

        harness.id = semantic::FunctionId(2);
        harness.uninterrupted_bound = Some(17);
        module.functions.push(harness);
        module.image_entry = semantic::FunctionId(2);
        module.source_summary.reachable_declarations = 3;
        module.source_summary.monomorphized_instantiations = 3;
        module
            .validate()
            .expect("valid producer-shaped primitive join SemanticWir")
    }

    fn primitive_join_flow_fixture(
        primitive: semantic::PrimitiveType,
    ) -> (OptimizedFlowWir, TargetPackage, ValidatedBuildConfiguration) {
        let identity = identity();
        let target = TargetPackage::aarch64_qemu_virt_uefi(identity.target_package);
        let build = build_configuration(identity.clone());
        let flow = CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: primitive_join_semantic_fixture(identity, primitive),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .unwrap_or_else(|error| panic!("{primitive:?} canonical Flow lowering: {error:?}"))
            .into_parts()
            .0;
        (optimize(flow), target, build)
    }

    fn extend_flow_edge_arguments(
        terminator: &mut FlowTerminator,
        target: FlowBlockId,
        retained_input_count: usize,
    ) {
        let extend = |arguments: &mut Vec<FlowValueId>| {
            if arguments.is_empty() {
                panic!("unit join edge must carry its original unit argument");
            }
            arguments.resize(retained_input_count, arguments[0]);
        };
        match terminator {
            FlowTerminator::Jump {
                target: edge_target,
                arguments,
            } if *edge_target == target => extend(arguments),
            FlowTerminator::Branch {
                then_block,
                then_arguments,
                else_block,
                else_arguments,
                ..
            } => {
                if *then_block == target {
                    extend(then_arguments);
                }
                if *else_block == target {
                    extend(else_arguments);
                }
            }
            FlowTerminator::Switch {
                cases,
                default,
                default_arguments,
                ..
            } => {
                for case in cases {
                    if case.target == target {
                        extend(&mut case.arguments);
                    }
                }
                if *default == target {
                    extend(default_arguments);
                }
            }
            _ => {}
        }
    }

    fn many_unit_erasure_flow_fixture(
        erased_per_surface: usize,
    ) -> (OptimizedFlowWir, TargetPackage, ValidatedBuildConfiguration) {
        assert!(erased_per_surface > 1);
        let (optimized, target, build) = primitive_join_flow_fixture(semantic::PrimitiveType::Unit);
        let (validated, _) = optimized.into_parts();
        let mut flow = validated.into_wir();
        let unit_ty = flow.functions[1].values[0].ty;

        let passive_type =
            TypeId(u32::try_from(flow.types.len()).expect("bounded many-unit passive type id"));
        flow.types.push(FlowType {
            id: passive_type,
            kind: FlowTypeKind::Function {
                parameters: vec![unit_ty; erased_per_surface],
                result: unit_ty,
            },
            name: Some("many_unit_signature".to_owned()),
            copyable: true,
            strict_linear: false,
        });

        {
            let consumer = &mut flow.functions[1];
            while consumer.parameters.len() < erased_per_surface {
                let id = FlowValueId(
                    u32::try_from(consumer.values.len())
                        .expect("bounded many-unit consumer value id"),
                );
                consumer.values.push(FlowValue {
                    id,
                    ty: unit_ty,
                    source_name: None,
                    source: None,
                });
                consumer.parameters.push(id);
            }
        }

        {
            let test = &mut flow.functions[0];
            let joins = test
                .blocks
                .iter()
                .filter(|block| !block.parameters.is_empty())
                .map(|block| block.id)
                .collect::<Vec<_>>();
            assert_eq!(joins.len(), 2);
            for join in joins {
                let mut added = Vec::with_capacity(erased_per_surface - 1);
                for _ in 1..erased_per_surface {
                    let id = FlowValueId(
                        u32::try_from(test.values.len()).expect("bounded many-unit join value id"),
                    );
                    test.values.push(FlowValue {
                        id,
                        ty: unit_ty,
                        source_name: None,
                        source: None,
                    });
                    added.push(id);
                }
                test.blocks[join.0 as usize].parameters.extend(added);
                for predecessor in &mut test.blocks {
                    extend_flow_edge_arguments(
                        &mut predecessor.terminator,
                        join,
                        erased_per_surface,
                    );
                }
            }

            let mut call_count = 0usize;
            for block in &mut test.blocks {
                for instruction in &mut block.instructions {
                    if let FlowOperation::Call {
                        function,
                        arguments,
                    } = &mut instruction.operation
                    {
                        if *function == FlowFunctionId(1) {
                            assert!(!arguments.is_empty());
                            arguments.resize(erased_per_surface, arguments[0]);
                            call_count += 1;
                        }
                    }
                }
            }
            assert_eq!(call_count, 1);

            let mut next_instruction = test
                .blocks
                .iter()
                .flat_map(|block| &block.instructions)
                .map(|instruction| instruction.id.0)
                .max()
                .unwrap_or(0)
                .checked_add(1)
                .expect("bounded many-unit instruction id");
            let mut erased_instructions = Vec::with_capacity(erased_per_surface);
            for _ in 0..erased_per_surface {
                let value = FlowValueId(
                    u32::try_from(test.values.len()).expect("bounded many-unit immediate value id"),
                );
                test.values.push(FlowValue {
                    id: value,
                    ty: unit_ty,
                    source_name: None,
                    source: None,
                });
                erased_instructions.push(FlowInstruction {
                    id: FlowInstructionId(next_instruction),
                    results: vec![value],
                    operation: FlowOperation::Immediate(FlowImmediate::Unit),
                    source: None,
                });
                next_instruction = next_instruction
                    .checked_add(1)
                    .expect("bounded many-unit instruction id");
            }
            test.blocks
                .last_mut()
                .expect("unit test final block")
                .instructions
                .extend(erased_instructions);
        }

        let validated = flow
            .validate()
            .expect("valid many-unit exact-erasure FlowWir");
        (optimize(validated), target, build)
    }

    fn optimization_profile(compiler: Sha256Digest) -> OptimizationProfile {
        let mut policy = BuildProfile::development().optimization;
        policy.level = OptimizationLevel::None;
        OptimizationProfile::from_build_policy(&policy, compiler)
            .expect("canonical None optimization profile")
    }

    fn optimize(input: ValidatedFlowWir) -> OptimizedFlowWir {
        let compiler = input.as_wir().build.compiler;
        CanonicalFlowOptimizer::new()
            .optimize(
                OptimizationRequest {
                    input,
                    profile: optimization_profile(compiler),
                    limits: OptimizationLimits::standard(),
                },
                &|| false,
            )
            .expect("canonical no-op optimization")
    }

    fn optimize_for_build(
        input: ValidatedFlowWir,
        build: &ValidatedBuildConfiguration,
    ) -> OptimizedFlowWir {
        let profile = OptimizationProfile::from_build_policy(
            &build.profile.optimization,
            build.identity.compiler,
        )
        .expect("implemented optimization profile");
        CanonicalFlowOptimizer::new()
            .optimize(
                OptimizationRequest {
                    input,
                    profile,
                    limits: OptimizationLimits::standard(),
                },
                &|| false,
            )
            .expect("canonical optimization")
    }

    fn lowered_fixture(build: BuildIdentity) -> ValidatedFlowWir {
        CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: semantic_fixture(build),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("canonical FlowWir lowering")
            .into_parts()
            .0
    }

    fn optimized_fixture(build: BuildIdentity) -> OptimizedFlowWir {
        optimize(lowered_fixture(build))
    }

    fn fixture() -> (OptimizedFlowWir, TargetPackage, ValidatedBuildConfiguration) {
        let identity = identity();
        let target = TargetPackage::aarch64_qemu_virt_uefi(identity.target_package);
        let build = build_configuration(identity.clone());
        (optimized_fixture(identity), target, build)
    }

    fn normal_scope_cleanup_flow_fixture()
    -> (OptimizedFlowWir, TargetPackage, ValidatedBuildConfiguration) {
        let (optimized, target, build) = fixture();
        let (validated, _) = optimized.into_parts();
        let mut flow = validated.into_wir();
        let source = span(0, 40, 80);
        flow.source_summary.semantic_functions = 3;
        flow.source_summary.reachable_declarations = 3;
        flow.source_summary.monomorphized_instantiations = 3;
        flow.types.extend([
            FlowType {
                id: TypeId(1),
                kind: FlowTypeKind::Scalar(ScalarType::Integer {
                    signed: false,
                    bits: 32,
                }),
                name: Some("u32".to_owned()),
                copyable: true,
                strict_linear: false,
            },
            FlowType {
                id: TypeId(2),
                kind: FlowTypeKind::Struct {
                    fields: vec![TypeId(1)],
                },
                name: Some("Masked".to_owned()),
                copyable: true,
                strict_linear: false,
            },
        ]);
        flow.proofs[2].id = FlowProofId(4);
        for proof in &mut flow.functions[0].proofs {
            if *proof == FlowProofId(2) {
                *proof = FlowProofId(4);
            }
        }
        flow.proofs.extend([
            FlowProof {
                id: FlowProofId(2),
                kind: ProofKind::CleanupAcyclic,
                subject: "scope protocol cleanup: irqs_masked".to_owned(),
                sources: vec![source],
                depends_on: Vec::new(),
                bound: Some(0),
                explanation: vec!["one pass-only exit helper".to_owned()],
            },
            FlowProof {
                id: FlowProofId(3),
                kind: ProofKind::CleanupAcyclic,
                subject: "scope activation cleanup: irqs_masked".to_owned(),
                sources: vec![source],
                depends_on: vec![FlowProofId(2)],
                bound: Some(0),
                explanation: vec!["one normal-exit activation".to_owned()],
            },
        ]);
        flow.proofs.sort_unstable_by_key(|proof| proof.id);
        let entry = &mut flow.functions[0];
        entry.values.extend([
            FlowValue {
                id: FlowValueId(0),
                ty: TypeId(1),
                source_name: None,
                source: Some(source),
            },
            FlowValue {
                id: FlowValueId(1),
                ty: TypeId(2),
                source_name: Some("mask".to_owned()),
                source: Some(source),
            },
        ]);
        entry.blocks[0].instructions = vec![
            FlowInstruction {
                id: FlowInstructionId(0),
                results: vec![FlowValueId(0)],
                operation: FlowOperation::Immediate(FlowImmediate::Integer {
                    bits: 32,
                    bytes_le: 1_u32.to_le_bytes().to_vec(),
                }),
                source: Some(source),
            },
            FlowInstruction {
                id: FlowInstructionId(1),
                results: vec![FlowValueId(1)],
                operation: FlowOperation::MakeAggregate {
                    ty: TypeId(2),
                    fields: vec![FlowValueId(0)],
                },
                source: Some(source),
            },
            FlowInstruction {
                id: FlowInstructionId(2),
                results: Vec::new(),
                operation: FlowOperation::Call {
                    function: FlowFunctionId(3),
                    arguments: vec![FlowValueId(1)],
                },
                source: Some(source),
            },
        ];
        let helper = FlowFunction {
            id: FlowFunctionId(2),
            name: "irqs_masked.__scope_exit".to_owned(),
            origin: FunctionOrigin::SourceSemantic {
                semantic_function: 2,
            },
            role: FunctionRole::Cleanup,
            color: wrela_flow_wir::FunctionColor::Sync,
            parameters: vec![FlowValueId(0)],
            result_types: Vec::new(),
            values: vec![FlowValue {
                id: FlowValueId(0),
                ty: TypeId(2),
                source_name: Some("state".to_owned()),
                source: Some(source),
            }],
            blocks: vec![FlowBlock {
                id: FlowBlockId(0),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: FlowTerminator::Return(Vec::new()),
                source: Some(source),
            }],
            entry: FlowBlockId(0),
            stack_bound: 0,
            frame_bound: 0,
            proofs: vec![FlowProofId(2)],
            source: Some(source),
        };
        let mut generated = helper.clone();
        generated.id = FlowFunctionId(3);
        generated.origin = FunctionOrigin::GeneratedCleanup {
            semantic_function: 2,
            scope: 0,
        };
        generated.proofs.push(FlowProofId(3));
        flow.functions.push(FlowFunction {
            id: FlowFunctionId(1),
            name: "scope_caller".to_owned(),
            origin: FunctionOrigin::SourceSemantic {
                semantic_function: 1,
            },
            role: FunctionRole::Ordinary,
            color: wrela_flow_wir::FunctionColor::Sync,
            parameters: Vec::new(),
            result_types: Vec::new(),
            values: Vec::new(),
            blocks: vec![FlowBlock {
                id: FlowBlockId(0),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: FlowTerminator::Return(Vec::new()),
                source: Some(source),
            }],
            entry: FlowBlockId(0),
            stack_bound: 0,
            frame_bound: 0,
            proofs: vec![FlowProofId(0), FlowProofId(1)],
            source: Some(source),
        });
        flow.functions.push(helper);
        flow.functions.push(generated);
        let validated = flow
            .validate()
            .expect("valid authenticated normal cleanup FlowWir");
        (optimize(validated), target, build)
    }

    fn async_activation_fixture() -> (OptimizedFlowWir, TargetPackage, ValidatedBuildConfiguration)
    {
        let (optimized, target, build) = fixture();
        let (validated, _) = optimized.into_parts();
        let mut flow = validated.into_wir();
        let source = span(0, 10, 20);
        flow.source_summary.semantic_functions = 3;
        flow.source_summary.hir_declarations = 4;
        flow.source_summary.reachable_declarations = 3;
        flow.source_summary.monomorphized_instantiations = 3;
        flow.types.push(FlowType {
            id: TypeId(1),
            kind: FlowTypeKind::Activation { result: TypeId(0) },
            name: Some("__wrela_activation_0".to_owned()),
            copyable: false,
            strict_linear: true,
        });
        flow.functions.push(FlowFunction {
            id: FlowFunctionId(1),
            name: "async-unit".to_owned(),
            origin: FunctionOrigin::SourceSemantic {
                semantic_function: 1,
            },
            role: FunctionRole::ActorTurn(ActorId(0)),
            color: wrela_flow_wir::FunctionColor::Async,
            parameters: Vec::new(),
            result_types: Vec::new(),
            values: vec![
                FlowValue {
                    id: FlowValueId(0),
                    ty: TypeId(1),
                    source_name: None,
                    source: Some(source),
                },
                FlowValue {
                    id: FlowValueId(1),
                    ty: TypeId(0),
                    source_name: None,
                    source: Some(source),
                },
            ],
            blocks: vec![
                FlowBlock {
                    id: FlowBlockId(0),
                    parameters: Vec::new(),
                    instructions: vec![FlowInstruction {
                        id: FlowInstructionId(0),
                        results: vec![FlowValueId(0)],
                        operation: FlowOperation::AsyncCall {
                            function: FlowFunctionId(2),
                            arguments: Vec::new(),
                            plan: ActivationId(0),
                        },
                        source: Some(source),
                    }],
                    terminator: FlowTerminator::Suspend {
                        state: 0,
                        activation: FlowValueId(0),
                        resume: FlowBlockId(1),
                    },
                    source: Some(source),
                },
                FlowBlock {
                    id: FlowBlockId(1),
                    parameters: vec![FlowValueId(1)],
                    instructions: Vec::new(),
                    terminator: FlowTerminator::Return(Vec::new()),
                    source: Some(source),
                },
            ],
            entry: FlowBlockId(0),
            stack_bound: 8,
            frame_bound: 8,
            proofs: vec![FlowProofId(8)],
            source: Some(source),
        });
        flow.functions.push(FlowFunction {
            id: FlowFunctionId(2),
            name: "async-helper".to_owned(),
            origin: FunctionOrigin::SourceSemantic {
                semantic_function: 2,
            },
            role: FunctionRole::Ordinary,
            color: wrela_flow_wir::FunctionColor::Async,
            parameters: Vec::new(),
            result_types: Vec::new(),
            values: Vec::new(),
            blocks: vec![FlowBlock {
                id: FlowBlockId(0),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: FlowTerminator::Return(Vec::new()),
                source: Some(source),
            }],
            entry: FlowBlockId(0),
            stack_bound: 8,
            frame_bound: 8,
            proofs: vec![FlowProofId(2)],
            source: Some(source),
        });
        flow.functions[0].proofs = vec![
            FlowProofId(3),
            FlowProofId(4),
            FlowProofId(5),
            FlowProofId(6),
            FlowProofId(7),
            FlowProofId(9),
        ];
        flow.actors.push(ActorPlan {
            id: ActorId(0),
            name: "actor".to_owned(),
            state_type: TypeId(0),
            mailbox_capacity: 1,
            message_types: Vec::new(),
            turn_functions: vec![FlowFunctionId(1)],
            priority: 1,
            supervisor: None,
        });
        flow.proofs = vec![
            FlowProof {
                id: FlowProofId(0),
                kind: ProofKind::TypeChecked,
                subject: "actor image types".to_owned(),
                sources: vec![source],
                depends_on: Vec::new(),
                bound: None,
                explanation: vec!["actor image is typed".to_owned()],
            },
            FlowProof {
                id: FlowProofId(1),
                kind: ProofKind::EffectsAllowed,
                subject: "actor image effects".to_owned(),
                sources: vec![source],
                depends_on: vec![FlowProofId(0)],
                bound: None,
                explanation: vec!["actor image effects are closed".to_owned()],
            },
            FlowProof {
                id: FlowProofId(2),
                kind: ProofKind::CleanupAcyclic,
                subject: "helper cleanup".to_owned(),
                sources: vec![source],
                depends_on: Vec::new(),
                bound: Some(0),
                explanation: vec!["drop helper frame".to_owned()],
            },
            FlowProof {
                id: FlowProofId(3),
                kind: ProofKind::CapacityBound,
                subject: "mailbox capacity".to_owned(),
                sources: vec![source],
                depends_on: Vec::new(),
                bound: Some(1),
                explanation: vec!["one mailbox slot".to_owned()],
            },
            FlowProof {
                id: FlowProofId(4),
                kind: ProofKind::CapacityBound,
                subject: "turn capacity".to_owned(),
                sources: vec![source],
                depends_on: Vec::new(),
                bound: Some(1),
                explanation: vec!["one turn frame".to_owned()],
            },
            FlowProof {
                id: FlowProofId(5),
                kind: ProofKind::WaitGraphAcyclic,
                subject: "closed actor wait graph".to_owned(),
                sources: vec![source],
                depends_on: vec![FlowProofId(1)],
                bound: Some(1),
                explanation: vec!["one acyclic await edge".to_owned()],
            },
            FlowProof {
                id: FlowProofId(6),
                kind: ProofKind::SupervisionComplete,
                subject: "complete static actor/task parent topology".to_owned(),
                sources: vec![source],
                depends_on: vec![FlowProofId(0)],
                bound: Some(1),
                explanation: vec!["the static actor parent graph is acyclic and every static @task is owned by exactly its declaring actor; restart policy and failure delivery are not claimed".to_owned()],
            },
            FlowProof {
                id: FlowProofId(7),
                kind: ProofKind::CapacityBound,
                subject: "base actor allocation".to_owned(),
                sources: vec![source, source],
                depends_on: vec![
                    FlowProofId(0),
                    FlowProofId(1),
                    FlowProofId(3),
                    FlowProofId(4),
                    FlowProofId(5),
                    FlowProofId(6),
                ],
                bound: Some(24),
                explanation: vec!["mailbox plus root turn frame".to_owned()],
            },
            FlowProof {
                id: FlowProofId(8),
                kind: ProofKind::CapacityBound,
                subject: "call activation".to_owned(),
                sources: vec![source],
                depends_on: vec![FlowProofId(2)],
                bound: Some(1),
                explanation: vec!["one helper frame".to_owned()],
            },
            FlowProof {
                id: FlowProofId(9),
                kind: ProofKind::ImageClosed,
                subject: "closed actor image".to_owned(),
                sources: vec![source],
                depends_on: vec![FlowProofId(7), FlowProofId(8)],
                bound: Some(32),
                explanation: vec!["base plus helper activation".to_owned()],
            },
        ];
        flow.regions = vec![
            RegionPlan {
                id: RegionId(0),
                name: "actor.mailbox".to_owned(),
                class: RegionClass::Image,
                capacity_bytes: 16,
                alignment: 8,
                reset_function: None,
                owner: PlanOwner::Actor(ActorId(0)),
                capacity_proof: FlowProofId(3),
                source,
            },
            RegionPlan {
                id: RegionId(1),
                name: "actor.turn-frame".to_owned(),
                class: RegionClass::TaskFrame,
                capacity_bytes: 8,
                alignment: 8,
                reset_function: None,
                owner: PlanOwner::Actor(ActorId(0)),
                capacity_proof: FlowProofId(4),
                source,
            },
            RegionPlan {
                id: RegionId(2),
                name: "async-unit.async-activation-frame".to_owned(),
                class: RegionClass::TaskFrame,
                capacity_bytes: 8,
                alignment: 8,
                reset_function: None,
                owner: PlanOwner::Actor(ActorId(0)),
                capacity_proof: FlowProofId(8),
                source,
            },
        ];
        flow.activations.push(ActivationPlan {
            id: ActivationId(0),
            caller: FlowFunctionId(1),
            callee: FlowFunctionId(2),
            region: RegionId(2),
            frame_bytes: 8,
            maximum_live: 1,
            cancellation: ActivationCancellation::DropCalleeThenPropagate,
            capacity_proof: FlowProofId(8),
            source,
        });
        flow.schedulers = vec![SchedulerPlan {
            core: 0,
            actors: vec![ActorId(0)],
            tasks: Vec::new(),
        }];
        flow.startup_order = vec![PlanOwner::Runtime, PlanOwner::Actor(ActorId(0))];
        flow.shutdown_order = vec![PlanOwner::Actor(ActorId(0)), PlanOwner::Runtime];
        flow.static_bytes = 32;
        flow.peak_bytes = 32;
        let validated = flow
            .validate()
            .expect("valid Flow v9 activation/call/suspend fixture");
        (optimize(validated), target, build)
    }

    fn actor_state_activation_fixture()
    -> (OptimizedFlowWir, TargetPackage, ValidatedBuildConfiguration) {
        let (optimized, target, build) = async_activation_fixture();
        let (validated, _) = optimized.into_parts();
        let mut flow = validated.into_wir();
        let state_proof = FlowProofId(6);
        for proof in &mut flow.proofs {
            if proof.id.0 >= state_proof.0 {
                proof.id.0 += 1;
            }
            for dependency in &mut proof.depends_on {
                if dependency.0 >= state_proof.0 {
                    dependency.0 += 1;
                }
            }
        }
        for function in &mut flow.functions {
            for proof in &mut function.proofs {
                if proof.0 >= state_proof.0 {
                    proof.0 += 1;
                }
            }
        }
        for region in &mut flow.regions {
            if region.capacity_proof.0 >= state_proof.0 {
                region.capacity_proof.0 += 1;
            }
        }
        for activation in &mut flow.activations {
            if activation.capacity_proof.0 >= state_proof.0 {
                activation.capacity_proof.0 += 1;
            }
        }
        let source = span(0, 21, 22);
        flow.proofs.push(FlowProof {
            id: state_proof,
            kind: ProofKind::CapacityBound,
            subject: "actor state: actor".to_owned(),
            sources: vec![source],
            depends_on: Vec::new(),
            bound: Some(1),
            explanation: vec!["one canonical zero u64 actor state cell".to_owned()],
        });
        flow.proofs.sort_unstable_by_key(|proof| proof.id);
        let base = &mut flow.proofs[8];
        assert_eq!(base.id, FlowProofId(8));
        base.depends_on.push(state_proof);
        base.depends_on.sort_unstable();
        base.bound = Some(32);
        let closed = &mut flow.proofs[10];
        assert_eq!(closed.id, FlowProofId(10));
        closed.bound = Some(40);
        flow.functions[0].proofs.push(state_proof);
        flow.functions[0].proofs.sort_unstable();
        flow.regions.insert(
            1,
            RegionPlan {
                id: RegionId(1),
                name: "actor.state".to_owned(),
                class: RegionClass::Image,
                capacity_bytes: 8,
                alignment: 8,
                reset_function: None,
                owner: PlanOwner::Actor(ActorId(0)),
                capacity_proof: state_proof,
                source,
            },
        );
        for (index, region) in flow.regions.iter_mut().enumerate() {
            region.id = RegionId(u32::try_from(index).expect("region id"));
        }
        flow.activations[0].region = RegionId(3);
        flow.static_bytes = 40;
        flow.peak_bytes = 40;
        let validated = flow
            .validate()
            .expect("valid Flow v13 actor-state boundary fixture");
        (optimize(validated), target, build)
    }

    fn generated_test_fixture() -> (OptimizedFlowWir, TargetPackage, ValidatedBuildConfiguration) {
        production_generated_test_fixture()
    }

    #[allow(dead_code)]
    fn legacy_generated_test_fixture()
    -> (OptimizedFlowWir, TargetPackage, ValidatedBuildConfiguration) {
        let identity = identity();
        let target = TargetPackage::aarch64_qemu_virt_uefi(identity.target_package);
        let build = build_configuration(identity.clone());
        let mut flow = lowered_fixture(identity).into_wir();
        flow.source_summary.semantic_functions = 2;
        flow.source_summary.reachable_declarations = 2;
        flow.source_summary.monomorphized_instantiations = 2;
        flow.types = vec![
            FlowType {
                id: TypeId(0),
                kind: FlowTypeKind::Unit,
                name: Some("unit".to_owned()),
                copyable: true,
                strict_linear: false,
            },
            FlowType {
                id: TypeId(1),
                kind: FlowTypeKind::Scalar(ScalarType::Integer {
                    signed: false,
                    bits: 8,
                }),
                name: Some("u8".to_owned()),
                copyable: true,
                strict_linear: false,
            },
            FlowType {
                id: TypeId(2),
                kind: FlowTypeKind::Scalar(ScalarType::Integer {
                    signed: false,
                    bits: 32,
                }),
                name: Some("u32".to_owned()),
                copyable: true,
                strict_linear: false,
            },
            FlowType {
                id: TypeId(3),
                kind: FlowTypeKind::Array {
                    element: TypeId(1),
                    length: 32,
                },
                name: Some("test-frame-32".to_owned()),
                copyable: true,
                strict_linear: false,
            },
        ];
        flow.functions = vec![
            FlowFunction {
                id: FlowFunctionId(0),
                name: "integration_smoke".to_owned(),
                origin: FunctionOrigin::SourceSemantic {
                    semantic_function: 0,
                },
                role: FunctionRole::Test,
                color: wrela_flow_wir::FunctionColor::Sync,
                parameters: Vec::new(),
                result_types: Vec::new(),
                values: Vec::new(),
                blocks: vec![FlowBlock {
                    id: FlowBlockId(0),
                    parameters: Vec::new(),
                    instructions: Vec::new(),
                    terminator: FlowTerminator::Return(Vec::new()),
                    source: Some(span(0, 10, 20)),
                }],
                entry: FlowBlockId(0),
                stack_bound: 0,
                frame_bound: 0,
                proofs: Vec::new(),
                source: Some(span(0, 10, 20)),
            },
            FlowFunction {
                id: FlowFunctionId(1),
                name: "__wrela_test_harness_0".to_owned(),
                origin: FunctionOrigin::GeneratedTestHarness {
                    semantic_function: 1,
                    group: 0,
                },
                role: FunctionRole::ImageEntry,
                color: wrela_flow_wir::FunctionColor::Sync,
                parameters: Vec::new(),
                result_types: Vec::new(),
                values: vec![
                    FlowValue {
                        id: FlowValueId(0),
                        ty: TypeId(3),
                        source_name: Some("frame".to_owned()),
                        source: None,
                    },
                    FlowValue {
                        id: FlowValueId(1),
                        ty: TypeId(2),
                        source_name: Some("outcome".to_owned()),
                        source: None,
                    },
                ],
                blocks: vec![FlowBlock {
                    id: FlowBlockId(0),
                    parameters: Vec::new(),
                    instructions: vec![
                        FlowInstruction {
                            id: FlowInstructionId(0),
                            results: vec![FlowValueId(0)],
                            operation: FlowOperation::Immediate(FlowImmediate::Bytes(vec![
                                0x5a;
                                32
                            ])),
                            source: None,
                        },
                        FlowInstruction {
                            id: FlowInstructionId(1),
                            results: Vec::new(),
                            operation: FlowOperation::TestEmit {
                                payload: FlowValueId(0),
                            },
                            source: None,
                        },
                        FlowInstruction {
                            id: FlowInstructionId(2),
                            results: Vec::new(),
                            operation: FlowOperation::Call {
                                function: FlowFunctionId(0),
                                arguments: Vec::new(),
                            },
                            source: None,
                        },
                        FlowInstruction {
                            id: FlowInstructionId(3),
                            results: vec![FlowValueId(1)],
                            operation: FlowOperation::Immediate(FlowImmediate::Integer {
                                bits: 32,
                                bytes_le: vec![0; 4],
                            }),
                            source: None,
                        },
                        FlowInstruction {
                            id: FlowInstructionId(4),
                            results: Vec::new(),
                            operation: FlowOperation::TestFinish {
                                outcome: FlowValueId(1),
                            },
                            source: None,
                        },
                    ],
                    terminator: FlowTerminator::Unreachable,
                    source: None,
                }],
                entry: FlowBlockId(0),
                stack_bound: 0,
                frame_bound: 0,
                proofs: Vec::new(),
                source: None,
            },
        ];
        flow.tests = vec![FlowTestEntry {
            id: FlowTestId(0),
            plan_id: 0,
            function_key: Sha256Digest::from_bytes([0x71; 32]),
            name: "integration_smoke".to_owned(),
            function: FlowFunctionId(0),
            kind: FlowTestKind::Integration,
            source: span(0, 10, 20),
            timeout_ns: 1_000_000,
        }];
        flow.compiled_test_group = Some(wrela_test_model::FullImageTestGroup {
            id: wrela_test_model::ImageGroupId(0),
            name: "integration".to_owned(),
            root: wrela_test_model::ImageRoot::GeneratedHarness {
                harness_name: flow.name.clone(),
            },
            tests: vec![wrela_test_model::ImageTest {
                descriptor: wrela_test_model::TestDescriptor {
                    id: wrela_test_model::TestId(0),
                    name: "integration_smoke".to_owned(),
                    kind: wrela_test_model::TestKind::IntegrationImage,
                    source: Some(span(0, 10, 20)),
                    timeout_ns: 1_000_000,
                },
                invocation: wrela_test_model::ImageTestInvocation::GeneratedFunction {
                    function_key: wrela_test_model::FunctionKey(Sha256Digest::from_bytes(
                        [0x71; 32],
                    )),
                },
                assertions: Vec::new(),
            }],
            deterministic_seed: None,
            boot_timeout_ns: 1,
            shutdown_timeout_ns: 1,
            maximum_events: 5,
            maximum_output_bytes: 1,
        });
        flow.image_entry = FlowFunctionId(1);
        (
            optimize(flow.validate().expect("valid generated-test FlowWir")),
            target,
            build,
        )
    }

    /// Checked producer-boundary fixture for the ordinary revision-0.1 scalar
    /// surface. This mirrors the exact FlowWir shape emitted for a source test
    /// containing named bool/u32 locals, a no-result `if`, and a direct call to
    /// a two-parameter u32 helper. It remains local to this consumer crate so
    /// machine work does not require an operational source frontend.
    fn ordinary_scalar_flow_fixture()
    -> (OptimizedFlowWir, TargetPackage, ValidatedBuildConfiguration) {
        let (optimized, target, build) = generated_test_fixture();
        let (validated, _) = optimized.into_parts();
        let mut flow = validated.into_wir();
        flow.source_summary.semantic_functions = 3;
        flow.source_summary.reachable_declarations = 2;
        flow.source_summary.monomorphized_instantiations = 3;
        flow.types = vec![
            FlowType {
                id: TypeId(0),
                kind: FlowTypeKind::Unit,
                name: Some("unit".to_owned()),
                copyable: true,
                strict_linear: false,
            },
            FlowType {
                id: TypeId(1),
                kind: FlowTypeKind::Scalar(ScalarType::Bool),
                name: Some("bool".to_owned()),
                copyable: true,
                strict_linear: false,
            },
            FlowType {
                id: TypeId(2),
                kind: FlowTypeKind::Scalar(ScalarType::Integer {
                    signed: false,
                    bits: 32,
                }),
                name: Some("u32".to_owned()),
                copyable: true,
                strict_linear: false,
            },
            FlowType {
                id: TypeId(3),
                kind: FlowTypeKind::Function {
                    parameters: vec![TypeId(2), TypeId(2)],
                    result: TypeId(2),
                },
                name: Some("fn".to_owned()),
                copyable: true,
                strict_linear: false,
            },
            FlowType {
                id: TypeId(4),
                kind: FlowTypeKind::Scalar(ScalarType::Integer {
                    signed: false,
                    bits: 8,
                }),
                name: Some("__wrela_test_byte".to_owned()),
                copyable: true,
                strict_linear: false,
            },
            FlowType {
                id: TypeId(5),
                kind: FlowTypeKind::Array {
                    element: TypeId(4),
                    length: 49,
                },
                name: Some("__wrela_test_frame_49".to_owned()),
                copyable: true,
                strict_linear: false,
            },
            FlowType {
                id: TypeId(6),
                kind: FlowTypeKind::Array {
                    element: TypeId(4),
                    length: 50,
                },
                name: Some("__wrela_test_frame_50".to_owned()),
                copyable: true,
                strict_linear: false,
            },
            FlowType {
                id: TypeId(7),
                kind: FlowTypeKind::Array {
                    element: TypeId(4),
                    length: 53,
                },
                name: Some("__wrela_test_frame_53".to_owned()),
                copyable: true,
                strict_linear: false,
            },
        ];

        let frame_types = flow.functions[1].blocks[0]
            .instructions
            .iter()
            .filter_map(|instruction| {
                let FlowOperation::Immediate(FlowImmediate::Bytes(bytes)) = &instruction.operation
                else {
                    return None;
                };
                let [result] = instruction.results.as_slice() else {
                    panic!("generated frame definition result");
                };
                let ty = match bytes.len() {
                    49 => TypeId(5),
                    50 => TypeId(6),
                    53 => TypeId(7),
                    _ => panic!("unexpected generated passing frame extent"),
                };
                Some((*result, ty))
            })
            .collect::<Vec<_>>();
        for (result, ty) in frame_types {
            flow.functions[1].values[result.0 as usize].ty = ty;
        }

        flow.functions[0].values = vec![
            FlowValue {
                id: FlowValueId(0),
                ty: TypeId(1),
                source_name: Some("flag".to_owned()),
                source: Some(span(0, 30, 34)),
            },
            FlowValue {
                id: FlowValueId(1),
                ty: TypeId(2),
                source_name: Some("number".to_owned()),
                source: Some(span(0, 35, 41)),
            },
            FlowValue {
                id: FlowValueId(2),
                ty: TypeId(2),
                source_name: Some("other".to_owned()),
                source: Some(span(0, 42, 47)),
            },
            FlowValue {
                id: FlowValueId(3),
                ty: TypeId(2),
                source_name: None,
                source: Some(span(0, 55, 72)),
            },
        ];
        flow.functions[0].blocks = vec![
            FlowBlock {
                id: FlowBlockId(0),
                parameters: Vec::new(),
                instructions: vec![
                    FlowInstruction {
                        id: FlowInstructionId(0),
                        results: vec![FlowValueId(0)],
                        operation: FlowOperation::Immediate(FlowImmediate::Bool(true)),
                        source: Some(span(0, 30, 34)),
                    },
                    FlowInstruction {
                        id: FlowInstructionId(1),
                        results: vec![FlowValueId(1)],
                        operation: FlowOperation::Immediate(FlowImmediate::Integer {
                            bits: 32,
                            bytes_le: 7u32.to_le_bytes().to_vec(),
                        }),
                        source: Some(span(0, 35, 41)),
                    },
                    FlowInstruction {
                        id: FlowInstructionId(2),
                        results: vec![FlowValueId(2)],
                        operation: FlowOperation::Immediate(FlowImmediate::Integer {
                            bits: 32,
                            bytes_le: 9u32.to_le_bytes().to_vec(),
                        }),
                        source: Some(span(0, 42, 47)),
                    },
                ],
                terminator: FlowTerminator::Branch {
                    condition: FlowValueId(0),
                    then_block: FlowBlockId(1),
                    then_arguments: Vec::new(),
                    else_block: FlowBlockId(2),
                    else_arguments: Vec::new(),
                },
                source: Some(span(0, 48, 75)),
            },
            FlowBlock {
                id: FlowBlockId(1),
                parameters: Vec::new(),
                instructions: vec![FlowInstruction {
                    id: FlowInstructionId(3),
                    results: vec![FlowValueId(3)],
                    operation: FlowOperation::Call {
                        function: FlowFunctionId(2),
                        arguments: vec![FlowValueId(1), FlowValueId(2)],
                    },
                    source: Some(span(0, 55, 72)),
                }],
                terminator: FlowTerminator::Jump {
                    target: FlowBlockId(3),
                    arguments: Vec::new(),
                },
                source: Some(span(0, 55, 72)),
            },
            FlowBlock {
                id: FlowBlockId(2),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: FlowTerminator::Jump {
                    target: FlowBlockId(3),
                    arguments: Vec::new(),
                },
                source: Some(span(0, 73, 75)),
            },
            FlowBlock {
                id: FlowBlockId(3),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: FlowTerminator::Return(Vec::new()),
                source: Some(span(0, 76, 82)),
            },
        ];

        flow.functions.push(FlowFunction {
            id: FlowFunctionId(2),
            name: "helper".to_owned(),
            origin: FunctionOrigin::SourceSemantic {
                semantic_function: 2,
            },
            role: FunctionRole::Ordinary,
            color: wrela_flow_wir::FunctionColor::Sync,
            parameters: vec![FlowValueId(0), FlowValueId(1)],
            result_types: vec![TypeId(2)],
            values: vec![
                FlowValue {
                    id: FlowValueId(0),
                    ty: TypeId(2),
                    source_name: Some("x".to_owned()),
                    source: Some(span(0, 90, 91)),
                },
                FlowValue {
                    id: FlowValueId(1),
                    ty: TypeId(2),
                    source_name: Some("y".to_owned()),
                    source: Some(span(0, 93, 94)),
                },
                FlowValue {
                    id: FlowValueId(2),
                    ty: TypeId(2),
                    source_name: Some("copied".to_owned()),
                    source: Some(span(0, 100, 106)),
                },
            ],
            blocks: vec![FlowBlock {
                id: FlowBlockId(0),
                parameters: Vec::new(),
                instructions: vec![FlowInstruction {
                    id: FlowInstructionId(0),
                    results: vec![FlowValueId(2)],
                    operation: FlowOperation::Copy {
                        value: FlowValueId(0),
                    },
                    source: Some(span(0, 100, 106)),
                }],
                terminator: FlowTerminator::Return(vec![FlowValueId(2)]),
                source: Some(span(0, 100, 115)),
            }],
            entry: FlowBlockId(0),
            stack_bound: 0,
            frame_bound: 0,
            proofs: Vec::new(),
            source: Some(span(0, 84, 115)),
        });

        let validated = flow
            .validate()
            .expect("checked ordinary scalar FlowWir producer fixture");
        (optimize(validated), target, build)
    }

    fn float_not_equal_flow_fixture()
    -> (OptimizedFlowWir, TargetPackage, ValidatedBuildConfiguration) {
        let (optimized, target, build) = ordinary_scalar_flow_fixture();
        let (validated, _) = optimized.into_parts();
        let mut flow = validated.into_wir();
        let float_ty = TypeId(u32::try_from(flow.types.len()).expect("bounded FlowWir type id"));
        flow.types.push(FlowType {
            id: float_ty,
            kind: FlowTypeKind::Scalar(ScalarType::Float32),
            name: Some("f32".to_owned()),
            copyable: true,
            strict_linear: false,
        });
        let double_ty = TypeId(u32::try_from(flow.types.len()).expect("bounded FlowWir type id"));
        flow.types.push(FlowType {
            id: double_ty,
            kind: FlowTypeKind::Scalar(ScalarType::Float64),
            name: Some("f64".to_owned()),
            copyable: true,
            strict_linear: false,
        });
        let function_id = FlowFunctionId(
            u32::try_from(flow.functions.len()).expect("bounded FlowWir function id"),
        );
        flow.functions.push(FlowFunction {
            id: function_id,
            name: "float_not_equal_nan".to_owned(),
            origin: FunctionOrigin::SourceSemantic {
                semantic_function: function_id.0,
            },
            role: FunctionRole::Ordinary,
            color: wrela_flow_wir::FunctionColor::Sync,
            parameters: Vec::new(),
            result_types: vec![TypeId(1)],
            values: vec![
                FlowValue {
                    id: FlowValueId(0),
                    ty: float_ty,
                    source_name: Some("nan".to_owned()),
                    source: Some(span(0, 120, 123)),
                },
                FlowValue {
                    id: FlowValueId(1),
                    ty: float_ty,
                    source_name: Some("zero".to_owned()),
                    source: Some(span(0, 124, 128)),
                },
                FlowValue {
                    id: FlowValueId(2),
                    ty: TypeId(1),
                    source_name: Some("f32_not_equal".to_owned()),
                    source: Some(span(0, 129, 135)),
                },
                FlowValue {
                    id: FlowValueId(3),
                    ty: double_ty,
                    source_name: Some("wide_nan".to_owned()),
                    source: Some(span(0, 136, 139)),
                },
                FlowValue {
                    id: FlowValueId(4),
                    ty: double_ty,
                    source_name: Some("wide_zero".to_owned()),
                    source: Some(span(0, 140, 144)),
                },
                FlowValue {
                    id: FlowValueId(5),
                    ty: TypeId(1),
                    source_name: Some("f64_not_equal".to_owned()),
                    source: Some(span(0, 145, 151)),
                },
            ],
            blocks: vec![FlowBlock {
                id: FlowBlockId(0),
                parameters: Vec::new(),
                instructions: vec![
                    FlowInstruction {
                        id: FlowInstructionId(0),
                        results: vec![FlowValueId(0)],
                        operation: FlowOperation::Immediate(FlowImmediate::Float32(0x7fc0_0000)),
                        source: Some(span(0, 120, 123)),
                    },
                    FlowInstruction {
                        id: FlowInstructionId(1),
                        results: vec![FlowValueId(1)],
                        operation: FlowOperation::Immediate(FlowImmediate::Float32(
                            0.0_f32.to_bits(),
                        )),
                        source: Some(span(0, 124, 128)),
                    },
                    FlowInstruction {
                        id: FlowInstructionId(2),
                        results: vec![FlowValueId(2)],
                        operation: FlowOperation::Binary {
                            op: BinaryOp::NotEqual,
                            left: FlowValueId(0),
                            right: FlowValueId(1),
                        },
                        source: Some(span(0, 129, 135)),
                    },
                    FlowInstruction {
                        id: FlowInstructionId(3),
                        results: vec![FlowValueId(3)],
                        operation: FlowOperation::Immediate(FlowImmediate::Float64(
                            0x7ff8_0000_0000_0000,
                        )),
                        source: Some(span(0, 136, 139)),
                    },
                    FlowInstruction {
                        id: FlowInstructionId(4),
                        results: vec![FlowValueId(4)],
                        operation: FlowOperation::Immediate(FlowImmediate::Float64(
                            0.0_f64.to_bits(),
                        )),
                        source: Some(span(0, 140, 144)),
                    },
                    FlowInstruction {
                        id: FlowInstructionId(5),
                        results: vec![FlowValueId(5)],
                        operation: FlowOperation::Binary {
                            op: BinaryOp::NotEqual,
                            left: FlowValueId(3),
                            right: FlowValueId(4),
                        },
                        source: Some(span(0, 145, 151)),
                    },
                ],
                terminator: FlowTerminator::Return(vec![FlowValueId(5)]),
                source: Some(span(0, 120, 155)),
            }],
            entry: FlowBlockId(0),
            stack_bound: 0,
            frame_bound: 0,
            proofs: Vec::new(),
            source: Some(span(0, 118, 155)),
        });
        flow.source_summary.semantic_functions =
            u32::try_from(flow.functions.len()).expect("bounded semantic function count");
        flow.source_summary.reachable_declarations = flow
            .source_summary
            .reachable_declarations
            .checked_add(1)
            .expect("bounded reachable declaration count");
        flow.source_summary.monomorphized_instantiations = flow
            .source_summary
            .monomorphized_instantiations
            .checked_add(1)
            .expect("bounded monomorphized count");
        let validated = flow
            .validate()
            .expect("valid producer-shaped float-not-equal FlowWir");
        (optimize(validated), target, build)
    }

    fn unary_cast_flow_fixture() -> (OptimizedFlowWir, TargetPackage, ValidatedBuildConfiguration) {
        let (optimized, target, build) = float_not_equal_flow_fixture();
        let (validated, _) = optimized.into_parts();
        let mut flow = validated.into_wir();
        let u16_ty = TypeId(u32::try_from(flow.types.len()).expect("bounded u16 type id"));
        flow.types.push(FlowType {
            id: u16_ty,
            kind: FlowTypeKind::Scalar(ScalarType::Integer {
                signed: false,
                bits: 16,
            }),
            name: Some("u16".to_owned()),
            copyable: true,
            strict_linear: false,
        });
        let i8_ty = TypeId(u32::try_from(flow.types.len()).expect("bounded i8 type id"));
        flow.types.push(FlowType {
            id: i8_ty,
            kind: FlowTypeKind::Scalar(ScalarType::Integer {
                signed: true,
                bits: 8,
            }),
            name: Some("i8".to_owned()),
            copyable: true,
            strict_linear: false,
        });
        let i16_ty = TypeId(u32::try_from(flow.types.len()).expect("bounded i16 type id"));
        flow.types.push(FlowType {
            id: i16_ty,
            kind: FlowTypeKind::Scalar(ScalarType::Integer {
                signed: true,
                bits: 16,
            }),
            name: Some("i16".to_owned()),
            copyable: true,
            strict_linear: false,
        });
        let function_id = FlowFunctionId(
            u32::try_from(flow.functions.len()).expect("bounded unary/cast function id"),
        );
        let value_types = [
            TypeId(1),
            TypeId(1),
            TypeId(4),
            TypeId(4),
            TypeId(8),
            TypeId(8),
            TypeId(9),
            TypeId(9),
            u16_ty,
            i8_ty,
            i16_ty,
            i16_ty,
            TypeId(9),
            TypeId(8),
            TypeId(8),
            TypeId(2),
            TypeId(8),
        ];
        let names = [
            "truth",
            "falsehood",
            "bits",
            "inverted_bits",
            "nan",
            "negated_nan",
            "wide",
            "negated_wide",
            "widened_unsigned",
            "signed_byte",
            "widened_signed",
            "unsigned_to_signed",
            "extended_float",
            "unsigned_float",
            "signed_float",
            "float_bits",
            "round_trip_float",
        ];
        let mut values = Vec::with_capacity(value_types.len());
        for (index, (ty, name)) in value_types.into_iter().zip(names).enumerate() {
            let id = u32::try_from(index).expect("bounded unary/cast value id");
            let start = 160_u32
                .checked_add(id.checked_mul(3).expect("bounded source offset"))
                .expect("bounded source offset");
            values.push(FlowValue {
                id: FlowValueId(id),
                ty,
                source_name: Some(name.to_owned()),
                source: Some(span(
                    0,
                    start,
                    start.checked_add(2).expect("bounded source end"),
                )),
            });
        }
        let unary_source = |id: u32| {
            let start = 160_u32
                .checked_add(id.checked_mul(3).expect("bounded source offset"))
                .expect("bounded source offset");
            Some(span(
                0,
                start,
                start.checked_add(2).expect("bounded source end"),
            ))
        };
        flow.functions.push(FlowFunction {
            id: function_id,
            name: "unary_and_lossless_casts".to_owned(),
            origin: FunctionOrigin::SourceSemantic {
                semantic_function: function_id.0,
            },
            role: FunctionRole::Ordinary,
            color: wrela_flow_wir::FunctionColor::Sync,
            parameters: Vec::new(),
            result_types: vec![TypeId(1)],
            values,
            blocks: vec![FlowBlock {
                id: FlowBlockId(0),
                parameters: Vec::new(),
                instructions: vec![
                    FlowInstruction {
                        id: FlowInstructionId(0),
                        results: vec![FlowValueId(0)],
                        operation: FlowOperation::Immediate(FlowImmediate::Bool(true)),
                        source: unary_source(0),
                    },
                    FlowInstruction {
                        id: FlowInstructionId(1),
                        results: vec![FlowValueId(1)],
                        operation: FlowOperation::Unary {
                            op: wrela_flow_wir::UnaryOp::BoolNot,
                            value: FlowValueId(0),
                        },
                        source: unary_source(1),
                    },
                    FlowInstruction {
                        id: FlowInstructionId(2),
                        results: vec![FlowValueId(2)],
                        operation: FlowOperation::Immediate(FlowImmediate::Integer {
                            bits: 8,
                            bytes_le: vec![0x0f],
                        }),
                        source: unary_source(2),
                    },
                    FlowInstruction {
                        id: FlowInstructionId(3),
                        results: vec![FlowValueId(3)],
                        operation: FlowOperation::Unary {
                            op: wrela_flow_wir::UnaryOp::BitNot,
                            value: FlowValueId(2),
                        },
                        source: unary_source(3),
                    },
                    FlowInstruction {
                        id: FlowInstructionId(4),
                        results: vec![FlowValueId(4)],
                        operation: FlowOperation::Immediate(FlowImmediate::Float32(0x7fc0_0000)),
                        source: unary_source(4),
                    },
                    FlowInstruction {
                        id: FlowInstructionId(5),
                        results: vec![FlowValueId(5)],
                        operation: FlowOperation::Unary {
                            op: wrela_flow_wir::UnaryOp::Negate,
                            value: FlowValueId(4),
                        },
                        source: unary_source(5),
                    },
                    FlowInstruction {
                        id: FlowInstructionId(6),
                        results: vec![FlowValueId(6)],
                        operation: FlowOperation::Immediate(FlowImmediate::Float64(
                            1.5_f64.to_bits(),
                        )),
                        source: unary_source(6),
                    },
                    FlowInstruction {
                        id: FlowInstructionId(7),
                        results: vec![FlowValueId(7)],
                        operation: FlowOperation::Unary {
                            op: wrela_flow_wir::UnaryOp::Negate,
                            value: FlowValueId(6),
                        },
                        source: unary_source(7),
                    },
                    FlowInstruction {
                        id: FlowInstructionId(8),
                        results: vec![FlowValueId(8)],
                        operation: FlowOperation::Cast {
                            value: FlowValueId(2),
                            to: u16_ty,
                            mode: wrela_flow_wir::CastMode::Exact,
                        },
                        source: unary_source(8),
                    },
                    FlowInstruction {
                        id: FlowInstructionId(9),
                        results: vec![FlowValueId(9)],
                        operation: FlowOperation::Immediate(FlowImmediate::Integer {
                            bits: 8,
                            bytes_le: vec![0xfe],
                        }),
                        source: unary_source(9),
                    },
                    FlowInstruction {
                        id: FlowInstructionId(10),
                        results: vec![FlowValueId(10)],
                        operation: FlowOperation::Cast {
                            value: FlowValueId(9),
                            to: i16_ty,
                            mode: wrela_flow_wir::CastMode::Exact,
                        },
                        source: unary_source(10),
                    },
                    FlowInstruction {
                        id: FlowInstructionId(11),
                        results: vec![FlowValueId(11)],
                        operation: FlowOperation::Cast {
                            value: FlowValueId(2),
                            to: i16_ty,
                            mode: wrela_flow_wir::CastMode::Exact,
                        },
                        source: unary_source(11),
                    },
                    FlowInstruction {
                        id: FlowInstructionId(12),
                        results: vec![FlowValueId(12)],
                        operation: FlowOperation::Cast {
                            value: FlowValueId(4),
                            to: TypeId(9),
                            mode: wrela_flow_wir::CastMode::Exact,
                        },
                        source: unary_source(12),
                    },
                    FlowInstruction {
                        id: FlowInstructionId(13),
                        results: vec![FlowValueId(13)],
                        operation: FlowOperation::Cast {
                            value: FlowValueId(2),
                            to: TypeId(8),
                            mode: wrela_flow_wir::CastMode::Exact,
                        },
                        source: unary_source(13),
                    },
                    FlowInstruction {
                        id: FlowInstructionId(14),
                        results: vec![FlowValueId(14)],
                        operation: FlowOperation::Cast {
                            value: FlowValueId(9),
                            to: TypeId(8),
                            mode: wrela_flow_wir::CastMode::Exact,
                        },
                        source: unary_source(14),
                    },
                    FlowInstruction {
                        id: FlowInstructionId(15),
                        results: vec![FlowValueId(15)],
                        operation: FlowOperation::Cast {
                            value: FlowValueId(4),
                            to: TypeId(2),
                            mode: wrela_flow_wir::CastMode::Bitcast,
                        },
                        source: unary_source(15),
                    },
                    FlowInstruction {
                        id: FlowInstructionId(16),
                        results: vec![FlowValueId(16)],
                        operation: FlowOperation::Cast {
                            value: FlowValueId(15),
                            to: TypeId(8),
                            mode: wrela_flow_wir::CastMode::Bitcast,
                        },
                        source: unary_source(16),
                    },
                ],
                terminator: FlowTerminator::Return(vec![FlowValueId(1)]),
                source: Some(span(0, 158, 215)),
            }],
            entry: FlowBlockId(0),
            stack_bound: 0,
            frame_bound: 0,
            proofs: Vec::new(),
            source: Some(span(0, 156, 215)),
        });
        flow.source_summary.semantic_functions =
            u32::try_from(flow.functions.len()).expect("bounded semantic function count");
        flow.source_summary.reachable_declarations = flow
            .source_summary
            .reachable_declarations
            .checked_add(1)
            .expect("bounded reachable declaration count");
        flow.source_summary.monomorphized_instantiations = flow
            .source_summary
            .monomorphized_instantiations
            .checked_add(1)
            .expect("bounded monomorphized count");
        let validated = flow
            .validate()
            .expect("valid producer-shaped unary/cast FlowWir");
        (optimize(validated), target, build)
    }

    fn production_generated_test_fixture()
    -> (OptimizedFlowWir, TargetPackage, ValidatedBuildConfiguration) {
        let identity = identity();
        let target = TargetPackage::aarch64_qemu_virt_uefi(identity.target_package);
        let build = build_configuration(identity.clone());
        let flow = CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: generated_test_semantic_fixture(identity),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("production Flow lowerer accepts generated test SemanticWir")
            .into_parts()
            .0;
        (optimize(flow), target, build)
    }

    fn lower(
        optimized: &OptimizedFlowWir,
        target: &TargetPackage,
        build: &ValidatedBuildConfiguration,
        limits: MachineLoweringLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<MachineLoweringOutput, MachineLowerError> {
        CanonicalMachineLowerer::new().lower(
            MachineLoweringRequest {
                input: optimized,
                target,
                build,
                limits,
            },
            is_cancelled,
        )
    }

    #[test]
    fn machine_policy_rejects_zero_capacity() {
        MachineLoweringLimits::standard()
            .validate()
            .expect("standard limits");
        let mut limits = MachineLoweringLimits::standard();
        limits.types = 0;
        assert!(matches!(
            limits.validate(),
            Err(MachineLowerError::InvalidLimits)
        ));

        let mut limits = MachineLoweringLimits::standard();
        limits.model_edges += 1;
        assert_eq!(limits.validate(), Err(MachineLowerError::InvalidLimits));

        let mut mismatched = MachineLoweringLimits::standard();
        mismatched.validation.model_edges -= 1;
        assert_eq!(mismatched.validate(), Err(MachineLowerError::InvalidLimits));

        let mut aligned = MachineLoweringLimits::standard();
        aligned.model_edges -= 1;
        aligned.payload_bytes -= 1;
        aligned.instructions -= 1;
        aligned = aligned.with_aligned_validation();
        aligned.validate().expect("exactly aligned nested policy");
        assert_eq!(aligned.validation.model_edges, aligned.model_edges);
        assert_eq!(aligned.validation.payload_bytes, aligned.payload_bytes);
        assert_eq!(
            aligned.validation.arena_records,
            aligned.stack_slots.max(aligned.instructions)
        );

        let mut invalid_nested = MachineLoweringLimits::standard();
        invalid_nested.validation.errors = 0;
        assert_eq!(
            invalid_nested.validate(),
            Err(MachineLowerError::InvalidLimits)
        );
    }

    #[test]
    fn machine_validation_boundary_maps_resource_and_late_cancellation() {
        let (optimized, target, build) = fixture();
        let mut limits = MachineLoweringLimits::standard();
        limits.validation.validation_work = 1;
        let polls = Cell::new(0u64);
        assert_eq!(
            lower(&optimized, &target, &build, limits, &|| {
                polls.set(polls.get() + 1);
                false
            }),
            Err(MachineLowerError::ResourceLimit {
                resource: "validation work",
                limit: 1,
            })
        );
        let cancel_at = polls.get().saturating_sub(1);
        assert!(cancel_at > 10);
        let cancellation_polls = Cell::new(0u64);
        assert_eq!(
            lower(&optimized, &target, &build, limits, &|| {
                let next = cancellation_polls.get() + 1;
                cancellation_polls.set(next);
                next >= cancel_at
            }),
            Err(MachineLowerError::Cancelled)
        );
    }

    #[test]
    fn recording_profiles_obey_the_fixed_target_event_log_reservation() {
        let build_identity = identity();
        let target = TargetPackage::aarch64_qemu_virt_uefi(build_identity.target_package);
        let optimized = optimized_fixture(build_identity.clone());
        let exact = build_configuration_for_recording(
            build_identity.clone(),
            RecordingMode::Record,
            EVENT_LOG_STORAGE_BYTES,
        );
        lower(
            &optimized,
            &target,
            &exact,
            MachineLoweringLimits::standard(),
            &|| false,
        )
        .expect("exact target-owned event-log reservation is supported");

        let oversized = build_configuration_for_recording(
            build_identity,
            RecordingMode::Replay,
            EVENT_LOG_STORAGE_BYTES + 1,
        );
        assert_eq!(
            lower(
                &optimized,
                &target,
                &oversized,
                MachineLoweringLimits::standard(),
                &|| false,
            ),
            Err(MachineLowerError::EventLogCapacityExceeded {
                requested_bytes: EVENT_LOG_STORAGE_BYTES + 1,
                capacity_bytes: EVENT_LOG_STORAGE_BYTES,
            })
        );
    }

    #[test]
    fn canonical_minimum_reaches_valid_machine_contract() {
        let (optimized, target, build) = fixture();
        let output = lower(
            &optimized,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| false,
        )
        .expect("canonical machine lowering");
        let wir = output.wir().as_wir();

        assert_eq!(wir.name, optimized.wir().as_wir().name);
        assert_eq!(wir.build, build.identity);
        assert_eq!(wir.target.identity, target.identity().as_str());
        assert!(matches!(
            wir.types.as_slice(),
            [
                wrela_machine_wir::MachineType {
                    kind: MachineTypeKind::Void,
                    ..
                },
                wrela_machine_wir::MachineType {
                    kind: MachineTypeKind::Pointer { .. },
                    ..
                },
                wrela_machine_wir::MachineType {
                    kind: MachineTypeKind::Integer { bits: 64 },
                    ..
                }
            ]
        ));
        assert_eq!(wir.sections.len(), 2);
        assert_eq!(wir.sections[0].kind, SectionKind::Code);
        assert_eq!(wir.sections[1].kind, SectionKind::RuntimeMetadata);
        assert!(matches!(
            wir.symbols[0].definition,
            SymbolDefinition::Function(wrela_machine_wir::FunctionId(0))
        ));
        assert!(matches!(
            wir.symbols[1].definition,
            SymbolDefinition::ExternalRuntime(RuntimeIntrinsic::ImageEnter)
        ));
        let [entry] = wir.functions.as_slice() else {
            panic!("one machine entry expected");
        };
        assert_eq!(entry.convention, CallingConvention::UefiAarch64);
        assert_eq!(entry.parameters.len(), 2);
        assert_eq!(entry.stack_bytes, 0);
        assert_eq!(entry.entry, BlockId(1));
        let [body, prologue, failure] = entry.blocks.as_slice() else {
            panic!("body, runtime prologue, and failure block expected");
        };
        assert!(matches!(
            body.instructions.as_slice(),
            [wrela_machine_wir::MachineInstruction {
                operation: MachineOperation::Immediate(MachineImmediate::Integer {
                    bytes_le,
                    ..
                }),
                ..
            }] if bytes_le.as_slice() == [0; 8]
        ));
        assert!(matches!(
            body.terminator,
            MachineTerminator::Return(ref values) if values.as_slice() == [wrela_machine_wir::ValueId(2)]
        ));
        assert!(matches!(
            prologue.instructions.as_slice(),
            [MachineInstruction {
                results,
                operation: MachineOperation::RuntimeCall {
                    intrinsic: RuntimeIntrinsic::ImageEnter,
                    arguments,
                },
                ..
            }] if results.as_slice() == [ValueId(3)]
                && arguments.as_slice() == [ValueId(0), ValueId(1)]
        ));
        assert!(matches!(
            &prologue.terminator,
            MachineTerminator::Switch {
                value: ValueId(3),
                cases,
                default: BlockId(2),
                default_arguments,
            } if cases.as_slice() == [(0, BlockId(0), Vec::new())]
                && default_arguments.is_empty()
        ));
        assert!(matches!(
            &failure.terminator,
            MachineTerminator::Return(values) if values.as_slice() == [ValueId(3)]
        ));
        assert_eq!(wir.proofs[0].source_proofs, [0, 1, 2]);
        assert_eq!(wir.runtime.intrinsics, [RuntimeIntrinsic::ImageEnter]);
        assert_eq!(output.report().runtime_uses.len(), 1);
        assert_eq!(
            output.report().runtime_uses[0].intrinsic,
            RuntimeIntrinsic::ImageEnter
        );
        assert_eq!(output.report().runtime_uses[0].call_sites, 1);
        assert_eq!(
            output.report().runtime_uses[0].reason,
            IMAGE_ENTER_RUNTIME_REASON
        );

        wir.clone()
            .validate_for_target(&target)
            .expect("immediate MachineWir consumer accepts canonical output");
    }

    #[test]
    fn generated_test_harness_lowers_to_static_runtime_abi_calls() {
        let (optimized, target, build) = generated_test_fixture();
        let output = lower(
            &optimized,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| false,
        )
        .expect("generated test harness reaches MachineWir");
        let machine = output.wir().as_wir();

        assert_eq!(
            machine.runtime.intrinsics,
            [
                RuntimeIntrinsic::ImageEnter,
                RuntimeIntrinsic::TestEmit,
                RuntimeIntrinsic::TestFinish
            ]
        );
        assert_eq!(machine.sections.len(), 4);
        assert_eq!(machine.sections[2].kind, SectionKind::ReadOnlyData);
        assert_eq!(machine.sections[2].reserved_bytes, 201);
        assert_eq!(machine.globals.len(), 4);
        assert_eq!(
            machine
                .globals
                .iter()
                .map(|global| match &global.initializer {
                    MachineImmediate::Bytes(bytes) => bytes.len(),
                    other => panic!("unexpected test payload initializer: {other:?}"),
                })
                .collect::<Vec<_>>(),
            [49, 49, 50, 53],
        );
        assert!(matches!(
            machine.functions[1].origin,
            MachineFunctionOrigin::GeneratedTestHarness {
                semantic_function: 1,
                group: 9,
            }
        ));
        assert_eq!(machine.tests.len(), 1);
        assert_eq!(machine.tests[0].name, "passes_one");
        assert_eq!(machine.tests[0].plan_id, 7);
        assert_eq!(machine.tests[0].kind, MachineTestKind::Integration);

        let runtime_calls = machine.functions[1]
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .filter_map(|instruction| match instruction.operation {
                MachineOperation::RuntimeCall { intrinsic, .. } => Some(intrinsic),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            runtime_calls
                .iter()
                .filter(|intrinsic| **intrinsic == RuntimeIntrinsic::TestEmit)
                .count(),
            4,
        );
        assert_eq!(
            runtime_calls
                .iter()
                .filter(|intrinsic| **intrinsic == RuntimeIntrinsic::TestFinish)
                .count(),
            1,
        );
        assert_eq!(
            runtime_calls
                .iter()
                .filter(|intrinsic| **intrinsic == RuntimeIntrinsic::ImageEnter)
                .count(),
            1,
        );
        assert_eq!(output.report().runtime_uses.len(), 3);
        assert!(
            output
                .report()
                .runtime_uses
                .iter()
                .all(|usage| usage.call_sites
                    == if usage.intrinsic == RuntimeIntrinsic::TestEmit {
                        4
                    } else {
                        1
                    })
        );
        machine
            .clone()
            .validate_for_target(&target)
            .expect("machine consumer accepts generated test ABI lowering");
    }

    #[test]
    fn machine_consumer_rejects_a_substituted_static_protocol_plan_id() {
        let (optimized, target, build) = generated_test_fixture();
        let output = lower(
            &optimized,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| false,
        )
        .expect("canonical generated lifecycle reaches MachineWir");
        let (validated, _) = output.into_parts();
        let mut substituted = validated.into_wir();
        substituted.tests[0].plan_id = substituted.tests[0].plan_id.saturating_add(1);
        let errors = substituted
            .validate_for_target(&target)
            .expect_err("Machine consumer rejects a static frame/test binding substitution");
        assert!(errors.0.iter().any(|error| matches!(
            error,
            ValidationError::InvalidRecord {
                kind: "generated static passing test lifecycle",
                ..
            }
        )));
    }

    #[test]
    fn production_flow_generated_test_output_is_an_immediate_machine_consumer_fixture() {
        let (optimized, target, build) = production_generated_test_fixture();
        let flow = optimized.wir().as_wir();
        assert_eq!(flow.tests.len(), 1);
        assert_eq!(
            flow.functions
                .iter()
                .flat_map(|function| &function.blocks)
                .flat_map(|block| &block.instructions)
                .filter(|instruction| matches!(
                    instruction.operation,
                    FlowOperation::TestEmit { .. }
                ))
                .count(),
            4
        );

        let output = lower(
            &optimized,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| false,
        )
        .expect("real Flow producer output reaches MachineWir");
        let machine = output.wir().as_wir();
        assert_eq!(machine.globals.len(), 4);
        assert_eq!(machine.tests.len(), 1);
        assert_eq!(machine.tests[0].name, flow.tests[0].name);
        let emit = output
            .report()
            .runtime_uses
            .iter()
            .find(|usage| usage.intrinsic == RuntimeIntrinsic::TestEmit)
            .expect("test emission runtime use");
        assert_eq!(emit.call_sites, 4);
        machine
            .clone()
            .validate_for_target(&target)
            .expect("MachineWir validator consumes real Flow output");
    }

    #[test]
    fn development_optimization_preserves_generated_test_machine_contract() {
        let identity = identity();
        let target = TargetPackage::aarch64_qemu_virt_uefi(identity.target_package);
        let build = build_configuration_for_level(identity.clone(), OptimizationLevel::Development);
        let flow = CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: generated_test_semantic_fixture(identity),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("production generated-test Flow lowering")
            .into_parts()
            .0;
        let optimized = optimize_for_build(flow, &build);
        let output = lower(
            &optimized,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| false,
        )
        .expect("Development-optimized generated tests reach MachineWir");
        assert_eq!(output.wir().as_wir().globals.len(), 4);
        let emit = output
            .report()
            .runtime_uses
            .iter()
            .find(|usage| usage.intrinsic == RuntimeIntrinsic::TestEmit)
            .expect("test emission runtime use");
        assert_eq!(emit.call_sites, 4);
        let harness = &output.wir().as_wir().functions[1];
        assert_eq!(
            harness
                .blocks
                .iter()
                .filter(|block| matches!(block.terminator, MachineTerminator::Switch { .. }))
                .count(),
            5,
            "four TestEmit guards plus the ImageEnter guard"
        );
        assert!(harness.blocks.iter().any(|block| {
            block.instructions.iter().any(|instruction| {
                matches!(
                    instruction.operation,
                    MachineOperation::RuntimeCall {
                        intrinsic: RuntimeIntrinsic::TestFinish,
                        ..
                    }
                )
            }) && matches!(block.terminator, MachineTerminator::Unreachable)
        }));
    }

    #[test]
    fn machine_sealer_rejects_test_context_payload_and_nonreturning_corruption() {
        let (optimized, target, build) = generated_test_fixture();
        let output = lower(
            &optimized,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| false,
        )
        .expect("generated test baseline");
        let machine = output.wir().as_wir();

        let mut wrong_size = machine.clone();
        let MachineOperation::Immediate(MachineImmediate::Integer { bytes_le, .. }) =
            &mut wrong_size.functions[1].blocks[0].instructions[1].operation
        else {
            panic!("generated frame-size immediate")
        };
        bytes_le[0] = 31;
        let error = wrong_size
            .validate_for_target(&target)
            .expect_err("mismatched static payload size must fail");
        assert!(
            error
                .0
                .iter()
                .any(|error| matches!(error, ValidationError::InvalidStaticTestPayload { .. }))
        );

        let mut wrong_origin = machine.clone();
        wrong_origin.functions[1].origin = MachineFunctionOrigin::GeneratedImageEntry {
            semantic_function: 1,
            constructor: 0,
        };
        let error = wrong_origin
            .validate_for_target(&target)
            .expect_err("test runtime call outside generated harness must fail");
        assert!(
            error
                .0
                .iter()
                .any(|error| matches!(error, ValidationError::InvalidTestRuntimeContext { .. }))
        );

        let mut returning = machine.clone();
        let finish_block = returning.functions[1]
            .blocks
            .iter()
            .position(|block| {
                block.instructions.iter().any(|instruction| {
                    matches!(
                        instruction.operation,
                        MachineOperation::RuntimeCall {
                            intrinsic: RuntimeIntrinsic::TestFinish,
                            ..
                        }
                    )
                })
            })
            .expect("generated TestFinish block");
        returning.functions[1].blocks[finish_block].terminator =
            MachineTerminator::Return(Vec::new());
        let error = returning
            .validate_for_target(&target)
            .expect_err("nonreturning test finish must not fall through");
        assert!(error.0.iter().any(|error| matches!(
            error,
            ValidationError::NonReturningRuntimeFallthrough { .. }
        )));

        let mut lost_metadata = machine.clone();
        lost_metadata.tests.clear();
        assert!(lost_metadata.validate_for_target(&target).is_err());
    }

    #[test]
    fn machine_lowering_rejects_forged_or_returning_flow_test_intrinsics() {
        let (optimized, target, build) = generated_test_fixture();
        let mut forged = optimized.wir().as_wir().clone();
        forged.functions[1].origin = FunctionOrigin::GeneratedImageEntry {
            semantic_function: 1,
            constructor: 0,
        };
        assert!(forged.validate().is_err());

        let mut returning = optimized.wir().as_wir().clone();
        returning.functions[1].blocks[0].terminator = FlowTerminator::Return(Vec::new());
        let returning = optimize(
            returning
                .validate()
                .expect("Flow model alone permits corruption for consumer rejection"),
        );
        assert!(matches!(
            lower(
                &returning,
                &target,
                &build,
                MachineLoweringLimits::standard(),
                &|| false,
            ),
            Err(MachineLowerError::UnsupportedInput { .. })
        ));
    }

    #[test]
    fn generated_test_lowering_honors_static_limits_and_midframe_cancellation() {
        let (optimized, target, build) = generated_test_fixture();
        let baseline = lower(
            &optimized,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| false,
        )
        .expect("generated test baseline");
        let static_bytes = baseline
            .wir()
            .as_wir()
            .sections
            .iter()
            .try_fold(0u64, |sum, section| sum.checked_add(section.reserved_bytes))
            .expect("bounded static reservation");
        let machine = baseline.wir().as_wir();
        let instruction_count = machine
            .functions
            .iter()
            .flat_map(|function| &function.blocks)
            .map(|block| block.instructions.len() as u64)
            .sum::<u64>();
        let (model_edges, payload_bytes) =
            model_resources(machine, MachineLoweringLimits::standard(), &|| false)
                .expect("measure generated-test MachineWir resources");
        let report_bytes = u64::try_from(
            baseline.report().target_identity.len()
                + baseline
                    .report()
                    .runtime_uses
                    .iter()
                    .map(|usage| usage.reason.len())
                    .sum::<usize>(),
        )
        .expect("generated-test report byte count");
        let mut exact = MachineLoweringLimits::standard();
        exact.static_bytes = static_bytes;
        exact.symbols = u32::try_from(machine.symbols.len()).expect("small fixture symbols");
        exact.instructions = instruction_count;
        exact.model_edges = model_edges;
        exact.payload_bytes = payload_bytes;
        exact.report_bytes = report_bytes;
        exact = exact.with_aligned_validation();
        lower(&optimized, &target, &build, exact, &|| false)
            .expect("exact generated-test resource limits succeed");
        for limited in [
            MachineLoweringLimits {
                symbols: exact.symbols - 1,
                ..exact
            }
            .with_aligned_validation(),
            MachineLoweringLimits {
                instructions: exact.instructions - 1,
                ..exact
            }
            .with_aligned_validation(),
            MachineLoweringLimits {
                model_edges: exact.model_edges - 1,
                ..exact
            }
            .with_aligned_validation(),
            MachineLoweringLimits {
                payload_bytes: exact.payload_bytes - 1,
                ..exact
            }
            .with_aligned_validation(),
            MachineLoweringLimits {
                report_bytes: exact.report_bytes - 1,
                ..exact
            }
            .with_aligned_validation(),
        ] {
            assert!(matches!(
                lower(&optimized, &target, &build, limited, &|| false),
                Err(MachineLowerError::ResourceLimit { .. })
            ));
        }
        let mut below_static = exact;
        below_static.static_bytes -= 1;
        assert_eq!(
            lower(&optimized, &target, &build, below_static, &|| false),
            Err(MachineLowerError::ResourceLimit {
                resource: "MachineWir static bytes",
                limit: static_bytes - 1,
            })
        );

        let polls = Cell::new(0u64);
        lower(
            &optimized,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| {
                polls.set(polls.get() + 1);
                false
            },
        )
        .expect("count generated-test cancellation polls");
        let cancel_after = polls.get() / 2;
        assert!(cancel_after > 10);
        let observed = Cell::new(0u64);
        assert_eq!(
            lower(
                &optimized,
                &target,
                &build,
                MachineLoweringLimits::standard(),
                &|| {
                    observed.set(observed.get() + 1);
                    observed.get() > cancel_after
                },
            ),
            Err(MachineLowerError::Cancelled)
        );
        assert_eq!(observed.get(), cancel_after + 1);
    }

    #[test]
    fn canonical_development_minimum_reaches_valid_machine_contract() {
        let identity = identity();
        let target = TargetPackage::aarch64_qemu_virt_uefi(identity.target_package);
        let build = build_configuration_for_level(identity.clone(), OptimizationLevel::Development);
        let optimized = optimize_for_build(lowered_fixture(identity), &build);
        assert_eq!(optimized.report().passes.len(), 4);
        assert!(optimized.report().passes.iter().all(|pass| !pass.changed));

        let output = lower(
            &optimized,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| false,
        )
        .expect("Development minimum reaches MachineWir");
        output
            .wir()
            .as_wir()
            .clone()
            .validate_for_target(&target)
            .expect("MachineWir consumer accepts Development minimum");

        let mut limited = MachineLoweringLimits::standard();
        limited.types = 2;
        assert!(matches!(
            lower(&optimized, &target, &build, limited, &|| false),
            Err(MachineLowerError::ResourceLimit {
                resource: "MachineWir types",
                limit: 2,
            })
        ));
        assert_eq!(
            lower(
                &optimized,
                &target,
                &build,
                MachineLoweringLimits::standard(),
                &|| true,
            ),
            Err(MachineLowerError::Cancelled)
        );
    }

    #[test]
    fn canonical_development_scalar_transform_reaches_valid_machine_wir() {
        let identity = identity();
        let target = TargetPackage::aarch64_qemu_virt_uefi(identity.target_package);
        let build = build_configuration_for_level(identity.clone(), OptimizationLevel::Development);
        let mut flow = lowered_fixture(identity).into_wir();
        flow.types.push(FlowType {
            id: TypeId(1),
            kind: FlowTypeKind::Scalar(ScalarType::Integer {
                signed: false,
                bits: 32,
            }),
            name: Some("u32".to_owned()),
            copyable: true,
            strict_linear: false,
        });
        flow.functions[0].values.push(FlowValue {
            id: FlowValueId(0),
            ty: TypeId(1),
            source_name: Some("dead_constant".to_owned()),
            source: None,
        });
        flow.functions[0].blocks[0]
            .instructions
            .push(FlowInstruction {
                id: FlowInstructionId(0),
                results: vec![FlowValueId(0)],
                operation: FlowOperation::Immediate(FlowImmediate::Integer {
                    bits: 32,
                    bytes_le: vec![42, 0, 0, 0],
                }),
                source: None,
            });
        let optimized = optimize_for_build(
            flow.validate().expect("valid scalar Development input"),
            &build,
        );
        assert!(optimized.report().passes[3].changed);
        assert!(optimized.wir().as_wir().functions[0].values.is_empty());

        let output = lower(
            &optimized,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| false,
        )
        .expect("transformed Development scalar FlowWir reaches MachineWir");
        assert_eq!(output.wir().as_wir().types.len(), 4);
        output
            .wir()
            .as_wir()
            .clone()
            .validate_for_target(&target)
            .expect("MachineWir consumer accepts transformed Development scalar output");
    }

    #[test]
    fn canonical_aggressive_profiles_reach_the_machine_consumer_with_limits_and_cancellation() {
        for level in [OptimizationLevel::Performance, OptimizationLevel::Size] {
            let identity = identity();
            let target = TargetPackage::aarch64_qemu_virt_uefi(identity.target_package);
            let build = build_configuration_for_level(identity.clone(), level);
            let optimized = optimize_for_build(lowered_fixture(identity), &build);

            assert_eq!(optimized.report().profile.level, level);
            assert_eq!(optimized.report().passes.len(), 5);
            assert!(optimized.report().passes.iter().all(|pass| !pass.changed));

            let output = lower(
                &optimized,
                &target,
                &build,
                MachineLoweringLimits::standard(),
                &|| false,
            )
            .expect("aggressive producer output reaches the machine consumer");
            output
                .wir()
                .as_wir()
                .clone()
                .validate_for_target(&target)
                .expect("aggressive producer output yields valid MachineWir");

            let mut limited = MachineLoweringLimits::standard();
            limited.types = 2;
            assert!(matches!(
                lower(&optimized, &target, &build, limited, &|| false),
                Err(MachineLowerError::ResourceLimit {
                    resource: "MachineWir types",
                    limit: 2,
                })
            ));

            let total_polls = Cell::new(0u32);
            validate_optimizer_report_contract(
                optimized.wir().as_wir(),
                optimized.report(),
                &|| {
                    total_polls.set(total_polls.get() + 1);
                    false
                },
            )
            .expect("count aggressive report-consumer cancellation checkpoints");
            let cancel_at = total_polls.get().saturating_sub(1);
            assert!(cancel_at >= 6);
            let polls = Cell::new(0u32);
            assert_eq!(
                validate_optimizer_report_contract(
                    optimized.wir().as_wir(),
                    optimized.report(),
                    &|| {
                        let next = polls.get() + 1;
                        polls.set(next);
                        next >= cancel_at
                    },
                ),
                Err(MachineLowerError::Cancelled)
            );
            assert_eq!(polls.get(), cancel_at);
        }
    }

    #[test]
    fn aggressive_true_check_elimination_reaches_valid_machine_wir() {
        for level in [OptimizationLevel::Performance, OptimizationLevel::Size] {
            let identity = identity();
            let target = TargetPackage::aarch64_qemu_virt_uefi(identity.target_package);
            let build = build_configuration_for_level(identity.clone(), level);
            let mut flow = lowered_fixture(identity).into_wir();
            flow.types.push(FlowType {
                id: TypeId(1),
                kind: FlowTypeKind::Scalar(ScalarType::Bool),
                name: Some("bool".to_owned()),
                copyable: true,
                strict_linear: false,
            });
            flow.functions[0].values.push(FlowValue {
                id: FlowValueId(0),
                ty: TypeId(1),
                source_name: Some("proven_condition".to_owned()),
                source: None,
            });
            flow.functions[0].blocks[0].instructions.extend([
                FlowInstruction {
                    id: FlowInstructionId(0),
                    results: vec![FlowValueId(0)],
                    operation: FlowOperation::Immediate(FlowImmediate::Bool(true)),
                    source: None,
                },
                FlowInstruction {
                    id: FlowInstructionId(1),
                    results: Vec::new(),
                    operation: FlowOperation::Check {
                        condition: FlowValueId(0),
                        failure: wrela_flow_wir::FailureKind::Arithmetic,
                        proof: Some(FlowProofId(0)),
                    },
                    source: None,
                },
            ]);
            let optimized =
                optimize_for_build(flow.validate().expect("valid proven-check FlowWir"), &build);
            assert!(optimized.report().passes[3].changed);
            assert!(optimized.report().passes[4].changed);
            assert!(optimized.wir().as_wir().functions[0].values.is_empty());
            assert!(
                optimized.wir().as_wir().functions[0].blocks[0]
                    .instructions
                    .is_empty()
            );

            let output = lower(
                &optimized,
                &target,
                &build,
                MachineLoweringLimits::standard(),
                &|| false,
            )
            .expect("aggressively simplified FlowWir reaches MachineWir");
            output
                .wir()
                .as_wir()
                .clone()
                .validate_for_target(&target)
                .expect("aggressively simplified output is valid for the target");
        }
    }

    #[test]
    fn aggressive_report_count_profile_and_build_substitution_fail_closed() {
        let identity = identity();
        let target = TargetPackage::aarch64_qemu_virt_uefi(identity.target_package);
        let performance_build =
            build_configuration_for_level(identity.clone(), OptimizationLevel::Performance);
        let size_build = build_configuration_for_level(identity.clone(), OptimizationLevel::Size);
        let optimized = optimize_for_build(lowered_fixture(identity), &performance_build);

        assert_eq!(
            lower(
                &optimized,
                &target,
                &size_build,
                MachineLoweringLimits::standard(),
                &|| false,
            ),
            Err(MachineLowerError::BuildIdentityMismatch)
        );

        let mut max_plus_one = optimized.report().clone();
        let extra = max_plus_one
            .passes
            .first()
            .expect("aggressive report has a pass")
            .clone();
        max_plus_one.passes.push(extra);
        assert_eq!(
            validate_optimizer_report_contract(optimized.wir().as_wir(), &max_plus_one, &|| false,),
            Err(MachineLowerError::InvalidOptimizerReport(
                "transforming profile has the wrong canonical pass count"
            ))
        );

        let mut wrong_profile = optimized.report().clone();
        wrong_profile.profile.level = OptimizationLevel::Development;
        assert_eq!(
            validate_optimizer_report_contract(optimized.wir().as_wir(), &wrong_profile, &|| false,),
            Err(MachineLowerError::InvalidOptimizerReport(
                "transforming profile has the wrong canonical pass count"
            ))
        );

        let mut malformed_statistics = optimized.report().clone();
        malformed_statistics.passes[0].test_table_preserved = false;
        assert_eq!(
            validate_optimizer_report_contract(
                optimized.wir().as_wir(),
                &malformed_statistics,
                &|| false,
            ),
            Err(MachineLowerError::InvalidOptimizerReport(
                "transforming pass statistics are malformed"
            ))
        );
    }

    #[test]
    fn profile_guidance_remains_an_honestly_unsupported_machine_policy() {
        let identity = identity();
        let target = TargetPackage::aarch64_qemu_virt_uefi(identity.target_package);
        let performance_build =
            build_configuration_for_level(identity.clone(), OptimizationLevel::Performance);
        let optimized = optimize_for_build(lowered_fixture(identity.clone()), &performance_build);
        let guided_build =
            build_configuration_with_profile_data(identity, OptimizationLevel::Performance);

        assert_eq!(
            lower(
                &optimized,
                &target,
                &guided_build,
                MachineLoweringLimits::standard(),
                &|| false,
            ),
            Err(MachineLowerError::UnsupportedInput {
                feature: "the selected optimization policy is not implemented",
            })
        );
    }

    #[test]
    fn stale_development_optimizer_profiles_are_rejected_by_the_producer() {
        let identity = identity();
        let build = build_configuration_for_level(identity.clone(), OptimizationLevel::Development);
        let flow = lowered_fixture(identity);
        let mut stale_profile = OptimizationProfile::from_build_policy(
            &build.profile.optimization,
            build.identity.compiler,
        )
        .expect("canonical Development profile");
        stale_profile.maximum_iterations -= 1;
        assert_eq!(
            CanonicalFlowOptimizer::new().optimize(
                OptimizationRequest {
                    input: flow,
                    profile: stale_profile,
                    limits: OptimizationLimits::standard(),
                },
                &|| false,
            ),
            Err(OptimizeError::InvalidProfile(
                "optimization policy parameters are noncanonical"
            ))
        );
    }

    #[test]
    fn output_is_deterministic() {
        let (optimized, target, build) = fixture();
        let first = lower(
            &optimized,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| false,
        )
        .expect("first lowering");
        let repeated = lower(
            &optimized,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| false,
        )
        .expect("repeated lowering");
        assert_eq!(first, repeated);
    }

    #[test]
    fn actor_state_storage_no_longer_masks_later_plan_validation() {
        let (optimized, target, build) = actor_state_activation_fixture();
        assert!(
            optimized
                .wir()
                .as_wir()
                .regions
                .iter()
                .any(|region| region.name == "actor.state")
        );
        assert_eq!(
            lower(
                &optimized,
                &target,
                &build,
                MachineLoweringLimits::standard(),
                &|| false,
            ),
            Err(MachineLowerError::UnsupportedInput {
                feature: "actor activation images with exactly one static task",
            })
        );
        let mut invalid_limits = MachineLoweringLimits::standard();
        invalid_limits.types = 0;
        assert_eq!(
            lower(&optimized, &target, &build, invalid_limits, &|| false,),
            Err(MachineLowerError::InvalidLimits),
            "public machine policy validation must retain precedence over actor-state plan inspection"
        );
    }

    #[test]
    fn machine_consumer_requires_exact_core_zero_scheduler_ownership() {
        let (optimized, _, _) = async_activation_fixture();
        let exact = optimized.wir().as_wir();
        require_exact_core_zero_scheduler_ownership(exact, &|| false)
            .expect("exact core-zero scheduler partition");

        let mut wrong_core = exact.clone();
        wrong_core.schedulers[0].core = 1;
        assert!(matches!(
            require_exact_core_zero_scheduler_ownership(&wrong_core, &|| false),
            Err(MachineLowerError::UnsupportedInput {
                feature: "scheduler ownership beyond the exact core-zero partition"
            })
        ));

        let mut omitted_actor = exact.clone();
        omitted_actor.schedulers[0].actors.clear();
        assert!(matches!(
            require_exact_core_zero_scheduler_ownership(&omitted_actor, &|| false),
            Err(MachineLowerError::UnsupportedInput {
                feature: "scheduler ownership beyond the exact core-zero partition"
            })
        ));
    }

    #[test]
    fn incomplete_flow_v9_actor_without_static_task_fails_closed() {
        let (optimized, target, build) = async_activation_fixture();
        let flow = optimized.wir().as_wir();
        assert!(matches!(
            flow.types[1].kind,
            FlowTypeKind::Activation { result: TypeId(0) }
        ));
        assert!(matches!(
            flow.functions[1].blocks[0].instructions[0].operation,
            FlowOperation::AsyncCall {
                function: FlowFunctionId(2),
                plan: ActivationId(0),
                ref arguments,
            } if arguments.is_empty()
        ));
        assert!(matches!(
            flow.activations.as_slice(),
            [ActivationPlan {
                id: ActivationId(0),
                caller: FlowFunctionId(1),
                callee: FlowFunctionId(2),
                region: RegionId(2),
                frame_bytes: 8,
                maximum_live: 1,
                cancellation: ActivationCancellation::DropCalleeThenPropagate,
                capacity_proof: FlowProofId(8),
                ..
            }]
        ));
        assert!(matches!(
            flow.regions.get(2),
            Some(RegionPlan {
                id: RegionId(2),
                name,
                class: RegionClass::TaskFrame,
                capacity_bytes: 8,
                owner: PlanOwner::Actor(ActorId(0)),
                capacity_proof: FlowProofId(8),
                ..
            }) if name == "async-unit.async-activation-frame"
        ));
        assert_eq!(flow.functions[1].proofs, [FlowProofId(8)]);
        assert!(matches!(
            flow.proofs.get(8),
            Some(FlowProof {
                kind: ProofKind::CapacityBound,
                bound: Some(1),
                depends_on,
                ..
            }) if depends_on.as_slice() == [FlowProofId(2)]
        ));
        assert!(matches!(
            flow.functions[1].blocks[0].terminator,
            FlowTerminator::Suspend {
                state: 0,
                activation: FlowValueId(0),
                resume: FlowBlockId(1),
            }
        ));
        assert_eq!(
            lower(
                &optimized,
                &target,
                &build,
                MachineLoweringLimits::standard(),
                &|| false,
            ),
            Err(MachineLowerError::UnsupportedInput {
                feature: "actor activation images with exactly one static task",
            })
        );
    }

    #[test]
    fn nested_actor_supervision_fails_closed_before_machine_topology_erasure() {
        let (optimized, _, _) = async_activation_fixture();
        let (validated, _) = optimized.into_parts();
        let mut flow = validated.into_wir();
        let mut runtime_parent = flow.actors[0].clone();
        runtime_parent.id = ActorId(1);
        runtime_parent.name = "runtime-parent".to_owned();
        runtime_parent.turn_functions.clear();
        flow.actors[0].supervisor = Some(ActorId(1));
        flow.actors.push(runtime_parent);

        assert_eq!(
            crate::scalar::test_lower_activation_subset(&flow),
            Err(MachineLowerError::UnsupportedInput {
                feature: "machine-supervision-policy-lowering-pending (nested actor parents)",
            })
        );
    }

    #[test]
    fn scalar_types_lower_while_missing_closure_proofs_fail_closed() {
        let (optimized, target, build) = fixture();
        let (flow, _) = optimized.into_parts();
        let mut richer = flow.into_wir();
        richer.types.push(FlowType {
            id: TypeId(1),
            kind: FlowTypeKind::Scalar(ScalarType::Integer {
                signed: false,
                bits: 8,
            }),
            name: Some("u8".to_owned()),
            copyable: true,
            strict_linear: false,
        });
        let richer = optimize(richer.validate().expect("valid richer FlowWir"));
        let lowered = lower(
            &richer,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| false,
        )
        .expect("scalar type table lowers through the general path");
        assert!(matches!(
            lowered.wir().as_wir().types[1].kind,
            MachineTypeKind::Integer { bits: 8 }
        ));

        let mut richer_proof = richer.wir().as_wir().clone();
        richer_proof.types.truncate(1);
        richer_proof.proofs[2].kind = ProofKind::ValueRange;
        let richer_proof = optimize(
            richer_proof
                .validate()
                .expect("valid optimizer-derived proof surface"),
        );
        assert_eq!(
            lower(
                &richer_proof,
                &target,
                &build,
                MachineLoweringLimits::standard(),
                &|| false,
            ),
            Err(MachineLowerError::UnsupportedInput {
                feature: "an exact final FlowWir image-closure root",
            })
        );

        let mut invalid_proof_dag = optimized_fixture(build.identity.clone())
            .into_parts()
            .0
            .into_wir();
        invalid_proof_dag.proofs[2].depends_on.clear();
        let invalid_proof_dag = optimize(
            invalid_proof_dag
                .validate()
                .expect("structurally valid but noncanonical proof DAG"),
        );
        assert_eq!(
            lower(
                &invalid_proof_dag,
                &target,
                &build,
                MachineLoweringLimits::standard(),
                &|| false,
            ),
            Err(MachineLowerError::UnsupportedInput {
                feature: "a FlowWir image closure without reachable typed effect authority",
            })
        );
    }

    #[test]
    fn nonempty_scalar_ssa_and_branches_reach_valid_machine_wir() {
        let (optimized, target, build) = fixture();
        let (validated, _) = optimized.into_parts();
        let mut flow = validated.into_wir();
        flow.types.extend([
            FlowType {
                id: TypeId(1),
                kind: FlowTypeKind::Scalar(ScalarType::Integer {
                    signed: false,
                    bits: 32,
                }),
                name: Some("u32".to_owned()),
                copyable: true,
                strict_linear: false,
            },
            FlowType {
                id: TypeId(2),
                kind: FlowTypeKind::Scalar(ScalarType::Bool),
                name: Some("bool".to_owned()),
                copyable: true,
                strict_linear: false,
            },
        ]);
        let entry = &mut flow.functions[0];
        entry.values = vec![
            FlowValue {
                id: FlowValueId(0),
                ty: TypeId(1),
                source_name: Some("left".to_owned()),
                source: None,
            },
            FlowValue {
                id: FlowValueId(1),
                ty: TypeId(1),
                source_name: Some("right".to_owned()),
                source: None,
            },
            FlowValue {
                id: FlowValueId(2),
                ty: TypeId(1),
                source_name: Some("sum".to_owned()),
                source: None,
            },
            FlowValue {
                id: FlowValueId(3),
                ty: TypeId(2),
                source_name: Some("ordered".to_owned()),
                source: None,
            },
        ];
        entry.blocks = vec![
            FlowBlock {
                id: FlowBlockId(0),
                parameters: Vec::new(),
                instructions: vec![
                    FlowInstruction {
                        id: FlowInstructionId(0),
                        results: vec![FlowValueId(0)],
                        operation: FlowOperation::Immediate(FlowImmediate::Integer {
                            bits: 32,
                            bytes_le: vec![5, 0, 0, 0],
                        }),
                        source: None,
                    },
                    FlowInstruction {
                        id: FlowInstructionId(1),
                        results: vec![FlowValueId(1)],
                        operation: FlowOperation::Immediate(FlowImmediate::Integer {
                            bits: 32,
                            bytes_le: vec![7, 0, 0, 0],
                        }),
                        source: None,
                    },
                    FlowInstruction {
                        id: FlowInstructionId(2),
                        results: vec![FlowValueId(2)],
                        operation: FlowOperation::Binary {
                            op: BinaryOp::AddWrapping,
                            left: FlowValueId(0),
                            right: FlowValueId(1),
                        },
                        source: None,
                    },
                    FlowInstruction {
                        id: FlowInstructionId(3),
                        results: vec![FlowValueId(3)],
                        operation: FlowOperation::Binary {
                            op: BinaryOp::Less,
                            left: FlowValueId(0),
                            right: FlowValueId(1),
                        },
                        source: None,
                    },
                ],
                terminator: FlowTerminator::Branch {
                    condition: FlowValueId(3),
                    then_block: FlowBlockId(1),
                    then_arguments: Vec::new(),
                    else_block: FlowBlockId(2),
                    else_arguments: Vec::new(),
                },
                source: None,
            },
            FlowBlock {
                id: FlowBlockId(1),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: FlowTerminator::Return(Vec::new()),
                source: None,
            },
            FlowBlock {
                id: FlowBlockId(2),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: FlowTerminator::Return(Vec::new()),
                source: None,
            },
        ];
        let optimized = optimize(flow.validate().expect("valid scalar FlowWir fixture"));
        let output = lower(
            &optimized,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| false,
        )
        .expect("scalar SSA lowering");
        let machine = output.wir().as_wir();
        let entry = &machine.functions[0];
        assert_eq!(entry.blocks.len(), 5);
        assert_eq!(entry.values.len(), 9);
        assert!(matches!(
            entry.blocks[0].instructions[2].operation,
            MachineOperation::Arithmetic {
                op: wrela_machine_wir::ArithmeticOp::IntegerAdd,
                ..
            }
        ));
        assert!(matches!(
            entry.blocks[0].terminator,
            MachineTerminator::Branch { .. }
        ));
        assert!(entry.blocks[1..3].iter().all(|block| matches!(
            block.terminator,
            MachineTerminator::Return(ref values) if values.len() == 1
        )));
        assert_eq!(entry.entry, BlockId(3));
        assert!(matches!(
            entry.blocks[3].instructions.as_slice(),
            [MachineInstruction {
                operation: MachineOperation::RuntimeCall {
                    intrinsic: RuntimeIntrinsic::ImageEnter,
                    arguments,
                },
                ..
            }] if arguments.as_slice() == [ValueId(0), ValueId(1)]
        ));
        assert!(matches!(
            &entry.blocks[4].terminator,
            MachineTerminator::Return(values) if values.as_slice() == [ValueId(8)]
        ));
        machine
            .clone()
            .validate_for_target(&target)
            .expect("MachineWir consumer accepts nonempty scalar CFG");
    }

    #[test]
    fn authenticated_normal_scope_cleanup_carries_flat_state_to_machine_wir() {
        let (optimized, target, build) = normal_scope_cleanup_flow_fixture();
        let output = lower(
            &optimized,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| false,
        )
        .expect("authenticated aggregate cleanup boundary reaches MachineWir");
        let machine = output.wir().as_wir();
        assert!(matches!(
            machine.types[2].kind,
            MachineTypeKind::Struct { ref fields, packed: false }
                if fields.len() == 1 && fields[0].ty == wrela_machine_wir::MachineTypeId(1)
        ));
        assert!(matches!(
            machine.functions[3].origin,
            MachineFunctionOrigin::GeneratedCleanup {
                semantic_function: 2,
                scope: 0,
            }
        ));
        assert_eq!(machine.functions[3].parameters, [ValueId(0)]);
        let entry_instructions = machine.functions[0]
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .collect::<Vec<_>>();
        let state = entry_instructions
            .iter()
            .find_map(|instruction| match &instruction.operation {
                MachineOperation::MakeStruct { ty, fields }
                    if *ty == wrela_machine_wir::MachineTypeId(2) && fields.len() == 1 =>
                {
                    instruction.results.first().copied()
                }
                _ => None,
            })
            .expect("one-field scope state construction");
        assert!(entry_instructions.iter().any(|instruction| matches!(
            &instruction.operation,
            MachineOperation::Call {
                function,
                arguments,
                convention: CallingConvention::Internal,
            } if *function == wrela_machine_wir::FunctionId(3)
                && arguments.as_slice() == [state]
        )));

        let (validated, _) = optimized.clone().into_parts();
        let mut forged = validated.into_wir();
        forged.functions[3].origin = FunctionOrigin::GeneratedCleanup {
            semantic_function: 2,
            scope: 1,
        };
        let forged = optimize(
            forged
                .validate()
                .expect("structurally valid forged scope origin"),
        );
        assert_eq!(
            lower(
                &forged,
                &target,
                &build,
                MachineLoweringLimits::standard(),
                &|| false,
            ),
            Err(MachineLowerError::UnsupportedInput {
                feature: "machine-generated-cleanup-boundary-authentication",
            })
        );

        let mut exact = MachineLoweringLimits::standard();
        exact.functions = 4;
        lower(&optimized, &target, &build, exact, &|| false).expect("exact cleanup function bound");
        exact.functions = 3;
        assert_eq!(
            lower(&optimized, &target, &build, exact, &|| false),
            Err(MachineLowerError::ResourceLimit {
                resource: "MachineWir functions",
                limit: 3,
            })
        );

        let polls = Cell::new(0_u64);
        lower(
            &optimized,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| {
                polls.set(polls.get() + 1);
                false
            },
        )
        .expect("count cleanup lowering cancellation boundaries");
        let cancel_at = polls.get() / 2;
        let observed = Cell::new(0_u64);
        assert_eq!(
            lower(
                &optimized,
                &target,
                &build,
                MachineLoweringLimits::standard(),
                &|| {
                    observed.set(observed.get() + 1);
                    observed.get() == cancel_at
                },
            ),
            Err(MachineLowerError::Cancelled)
        );
        assert_eq!(observed.get(), cancel_at);
    }

    #[test]
    fn internal_scalar_calls_preserve_function_and_result_contracts() {
        let (optimized, target, build) = fixture();
        let (validated, _) = optimized.into_parts();
        let mut flow = validated.into_wir();
        flow.types.push(FlowType {
            id: TypeId(1),
            kind: FlowTypeKind::Scalar(ScalarType::Integer {
                signed: false,
                bits: 32,
            }),
            name: Some("u32".to_owned()),
            copyable: true,
            strict_linear: false,
        });
        let entry = &mut flow.functions[0];
        entry.values.push(FlowValue {
            id: FlowValueId(0),
            ty: TypeId(1),
            source_name: Some("discarded".to_owned()),
            source: None,
        });
        entry.blocks[0].instructions = vec![
            FlowInstruction {
                id: FlowInstructionId(0),
                results: vec![FlowValueId(0)],
                operation: FlowOperation::Call {
                    function: FlowFunctionId(1),
                    arguments: Vec::new(),
                },
                source: None,
            },
            FlowInstruction {
                id: FlowInstructionId(1),
                results: Vec::new(),
                operation: FlowOperation::Drop {
                    value: FlowValueId(0),
                },
                source: None,
            },
        ];
        flow.functions.push(FlowFunction {
            id: FlowFunctionId(1),
            name: "generated-value".to_owned(),
            origin: FunctionOrigin::GeneratedCleanup {
                semantic_function: 0,
                scope: 0,
            },
            role: FunctionRole::Cleanup,
            color: wrela_flow_wir::FunctionColor::Sync,
            parameters: Vec::new(),
            result_types: vec![TypeId(1)],
            values: vec![FlowValue {
                id: FlowValueId(0),
                ty: TypeId(1),
                source_name: Some("result".to_owned()),
                source: None,
            }],
            blocks: vec![FlowBlock {
                id: FlowBlockId(0),
                parameters: Vec::new(),
                instructions: vec![FlowInstruction {
                    id: FlowInstructionId(0),
                    results: vec![FlowValueId(0)],
                    operation: FlowOperation::Immediate(FlowImmediate::Integer {
                        bits: 32,
                        bytes_le: vec![42, 0, 0, 0],
                    }),
                    source: None,
                }],
                terminator: FlowTerminator::Return(vec![FlowValueId(0)]),
                source: None,
            }],
            entry: FlowBlockId(0),
            stack_bound: 0,
            frame_bound: 0,
            proofs: Vec::new(),
            source: None,
        });
        let optimized = optimize(flow.validate().expect("valid scalar call FlowWir"));
        let output = lower(
            &optimized,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| false,
        )
        .expect("scalar call lowering");
        let machine = output.wir().as_wir();
        assert_eq!(machine.functions.len(), 2);
        assert!(matches!(
            machine.functions[0].blocks[0].instructions[0].operation,
            MachineOperation::Call {
                function: wrela_machine_wir::FunctionId(1),
                convention: CallingConvention::Internal,
                ..
            }
        ));
        assert_eq!(
            machine.functions[1].result,
            wrela_machine_wir::MachineTypeId(1)
        );
        machine
            .clone()
            .validate_for_target(&target)
            .expect("MachineWir consumer accepts internal scalar call");
    }

    #[test]
    fn ordinary_scalar_producer_shape_reaches_valid_machine_wir() {
        let (optimized, target, build) = ordinary_scalar_flow_fixture();
        let output = lower(
            &optimized,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| false,
        )
        .expect("ordinary scalar FlowWir reaches MachineWir");
        let machine = output.wir().as_wir();

        assert_eq!(machine.functions.len(), 3);
        let test = &machine.functions[0];
        assert_eq!(test.role, wrela_machine_wir::MachineFunctionRole::Test);
        assert_eq!(test.convention, CallingConvention::Internal);
        assert_eq!(test.values[0].source_name.as_deref(), Some("flag"));
        assert_eq!(test.values[1].source_name.as_deref(), Some("number"));
        assert_eq!(test.values[2].source_name.as_deref(), Some("other"));
        assert_eq!(test.blocks.len(), 4);
        assert!(matches!(
            test.blocks[0].terminator,
            MachineTerminator::Branch {
                condition: wrela_machine_wir::ValueId(0),
                then_block: wrela_machine_wir::BlockId(1),
                ref then_arguments,
                else_block: wrela_machine_wir::BlockId(2),
                ref else_arguments,
            } if then_arguments.is_empty() && else_arguments.is_empty()
        ));
        assert!(matches!(
            test.blocks[1].instructions.as_slice(),
            [wrela_machine_wir::MachineInstruction {
                results,
                operation: MachineOperation::Call {
                    function: wrela_machine_wir::FunctionId(2),
                    arguments,
                    convention: CallingConvention::Internal,
                },
                ..
            }] if results.as_slice() == [wrela_machine_wir::ValueId(3)]
                && arguments.as_slice()
                    == [wrela_machine_wir::ValueId(1), wrela_machine_wir::ValueId(2)]
        ));
        assert!(matches!(
            test.blocks[1].terminator,
            MachineTerminator::Jump {
                block: wrela_machine_wir::BlockId(3),
                ref arguments,
            } if arguments.is_empty()
        ));
        assert!(matches!(
            test.blocks[2].terminator,
            MachineTerminator::Jump {
                block: wrela_machine_wir::BlockId(3),
                ref arguments,
            } if arguments.is_empty()
        ));
        assert!(matches!(
            test.blocks[3].terminator,
            MachineTerminator::Return(ref values) if values.is_empty()
        ));

        assert_eq!(machine.types[0].source_name.as_deref(), Some("unit"));
        assert!(matches!(machine.types[0].kind, MachineTypeKind::Void));
        assert_eq!(machine.types[1].source_name.as_deref(), Some("bool"));
        assert!(matches!(
            machine.types[1].kind,
            MachineTypeKind::Integer { bits: 8 }
        ));
        assert_eq!(machine.types[2].source_name.as_deref(), Some("u32"));
        assert!(matches!(
            machine.types[2].kind,
            MachineTypeKind::Integer { bits: 32 }
        ));
        assert_eq!(machine.types[3].source_name.as_deref(), Some("fn"));
        assert!(matches!(
            machine.types[3].kind,
            MachineTypeKind::Function {
                ref parameters,
                result: wrela_machine_wir::MachineTypeId(2),
            } if parameters.as_slice()
                == [wrela_machine_wir::MachineTypeId(2), wrela_machine_wir::MachineTypeId(2)]
        ));
        assert_eq!((machine.types[3].size, machine.types[3].alignment), (0, 1));
        assert_eq!(
            machine.types[4].source_name.as_deref(),
            Some("__wrela_test_byte")
        );
        assert!(matches!(
            machine.types[4].kind,
            MachineTypeKind::Integer { bits: 8 }
        ));
        for (index, length, name) in [
            (5usize, 49u64, "__wrela_test_frame_49"),
            (6, 50, "__wrela_test_frame_50"),
            (7, 53, "__wrela_test_frame_53"),
        ] {
            assert_eq!(machine.types[index].source_name.as_deref(), Some(name));
            assert!(matches!(
                machine.types[index].kind,
                MachineTypeKind::Array {
                    element: wrela_machine_wir::MachineTypeId(4),
                    length: actual,
                } if actual == length
            ));
        }

        let image_entry = &machine.functions[1];
        assert_eq!(image_entry.convention, CallingConvention::UefiAarch64);
        assert_eq!(image_entry.parameters.len(), 2);
        assert!(image_entry.parameters.iter().all(|parameter| matches!(
            machine.types[image_entry.values[parameter.0 as usize].ty.0 as usize].kind,
            MachineTypeKind::Pointer {
                address_space: 0,
                ..
            }
        )));
        assert!(matches!(
            machine.types[image_entry.result.0 as usize].kind,
            MachineTypeKind::Integer { bits: 64 }
        ));

        let helper = &machine.functions[2];
        assert_eq!(
            helper.role,
            wrela_machine_wir::MachineFunctionRole::Ordinary
        );
        assert_eq!(helper.convention, CallingConvention::Internal);
        assert_eq!(
            helper.parameters,
            [wrela_machine_wir::ValueId(0), wrela_machine_wir::ValueId(1)]
        );
        assert_eq!(helper.values[0].source_name.as_deref(), Some("x"));
        assert_eq!(helper.values[1].source_name.as_deref(), Some("y"));
        assert_eq!(helper.values[2].source_name.as_deref(), Some("copied"));
        assert!(helper.parameters.iter().all(|parameter| {
            helper.values[parameter.0 as usize].ty == wrela_machine_wir::MachineTypeId(2)
        }));
        assert_eq!(helper.result, wrela_machine_wir::MachineTypeId(2));
        assert!(matches!(
            helper.blocks[0].instructions.as_slice(),
            [wrela_machine_wir::MachineInstruction {
                results,
                operation: MachineOperation::Convert {
                    op: wrela_machine_wir::ConversionOp::Bitcast,
                    value: wrela_machine_wir::ValueId(0),
                    destination: wrela_machine_wir::MachineTypeId(2),
                },
                ..
            }] if results.as_slice() == [wrela_machine_wir::ValueId(2)]
        ));
        assert!(matches!(
            helper.blocks[0].terminator,
            MachineTerminator::Return(ref values)
                if values.as_slice() == [wrela_machine_wir::ValueId(2)]
        ));

        machine
            .clone()
            .validate_for_target(&target)
            .expect("MachineWir validator accepts the ordinary scalar producer shape");
    }

    #[test]
    fn float_not_equal_maps_nan_semantics_and_rejects_predicate_substitution() {
        let (optimized, target, build) = float_not_equal_flow_fixture();
        let output = lower(
            &optimized,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| false,
        )
        .expect("float not-equal FlowWir reaches MachineWir");
        let (validated, report) = output.into_parts();
        let machine = validated.as_wir();
        assert_eq!(machine.version, 18);
        assert!(matches!(machine.types[8].kind, MachineTypeKind::Float32));
        assert!(matches!(machine.types[9].kind, MachineTypeKind::Float64));
        let float_function = &machine.functions[3];
        assert_eq!(float_function.values[0].source_name.as_deref(), Some("nan"));
        assert!(matches!(
            &float_function.blocks[0].instructions[..3],
            [
                wrela_machine_wir::MachineInstruction {
                    operation: MachineOperation::Immediate(MachineImmediate::Float32(
                        0x7fc0_0000
                    )),
                    ..
                },
                wrela_machine_wir::MachineInstruction {
                    operation: MachineOperation::Immediate(MachineImmediate::Float32(0)),
                    ..
                },
                wrela_machine_wir::MachineInstruction {
                    results,
                    operation: MachineOperation::FloatCompare {
                        predicate: FloatPredicate::UnorderedNotEqual,
                        left: wrela_machine_wir::ValueId(0),
                        right: wrela_machine_wir::ValueId(1),
                    },
                    source: Some(source),
                    ..
                }
            ] if results.as_slice() == [wrela_machine_wir::ValueId(2)]
                && *source == span(0, 129, 135)
        ));
        assert!(matches!(
            &float_function.blocks[0].instructions[3..],
            [
                wrela_machine_wir::MachineInstruction {
                    operation: MachineOperation::Immediate(MachineImmediate::Float64(
                        0x7ff8_0000_0000_0000
                    )),
                    ..
                },
                wrela_machine_wir::MachineInstruction {
                    operation: MachineOperation::Immediate(MachineImmediate::Float64(0)),
                    ..
                },
                wrela_machine_wir::MachineInstruction {
                    results,
                    operation: MachineOperation::FloatCompare {
                        predicate: FloatPredicate::UnorderedNotEqual,
                        left: wrela_machine_wir::ValueId(3),
                        right: wrela_machine_wir::ValueId(4),
                    },
                    source: Some(source),
                    ..
                }
            ] if results.as_slice() == [wrela_machine_wir::ValueId(5)]
                && *source == span(0, 145, 151)
        ));
        let nan = f32::from_bits(0x7fc0_0000);
        let same_nan = f32::from_bits(0x7fc0_0000);
        assert!(nan.is_nan() && same_nan.is_nan() && nan != same_nan);
        let wide_nan = f64::from_bits(0x7ff8_0000_0000_0000);
        let same_wide_nan = f64::from_bits(0x7ff8_0000_0000_0000);
        assert!(wide_nan.is_nan() && same_wide_nan.is_nan() && wide_nan != same_wide_nan);
        machine
            .clone()
            .validate_for_target(&target)
            .expect("MachineWir consumer accepts unordered float not-equal");

        let mut substituted = validated.into_wir();
        let MachineOperation::FloatCompare { predicate, .. } =
            &mut substituted.functions[3].blocks[0].instructions[2].operation
        else {
            panic!("float comparison");
        };
        *predicate = FloatPredicate::OrderedEqual;
        substituted
            .clone()
            .validate_for_target(&target)
            .expect("the stale predicate is structurally valid but semantically different");
        assert_eq!(
            seal(
                &MachineLoweringRequest {
                    input: &optimized,
                    target: &target,
                    build: &build,
                    limits: MachineLoweringLimits::standard(),
                },
                substituted,
                report,
                &|| false,
            ),
            Err(MachineLowerError::OutputDoesNotImplementInput)
        );
    }

    #[test]
    fn unary_and_lossless_casts_reach_sealed_machine_operations() {
        let (optimized, target, build) = unary_cast_flow_fixture();
        let output = lower(
            &optimized,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| false,
        )
        .expect("unary and lossless casts reach MachineWir");
        let (validated, report) = output.into_parts();
        let machine = validated.as_wir();
        assert_eq!(machine.version, 18);
        assert!(matches!(
            machine.types[10].kind,
            MachineTypeKind::Integer { bits: 16 }
        ));
        assert!(matches!(
            machine.types[11].kind,
            MachineTypeKind::Integer { bits: 8 }
        ));
        let function = &machine.functions[4];
        assert_eq!(
            function.values[5].source_name.as_deref(),
            Some("negated_nan")
        );
        for (index, expected) in [
            (1, MachineUnaryOp::BoolNot),
            (3, MachineUnaryOp::BitNot),
            (5, MachineUnaryOp::FloatNegate),
            (7, MachineUnaryOp::FloatNegate),
        ] {
            assert!(matches!(
                function.blocks[0].instructions[index].operation,
                MachineOperation::Unary { op, .. } if op == expected
            ));
        }
        for (index, expected) in [
            (8, ConversionOp::ZeroExtend),
            (10, ConversionOp::SignExtend),
            (11, ConversionOp::ZeroExtend),
            (12, ConversionOp::FloatExtend),
            (13, ConversionOp::UnsignedIntegerToFloat),
            (14, ConversionOp::SignedIntegerToFloat),
            (15, ConversionOp::Bitcast),
            (16, ConversionOp::Bitcast),
        ] {
            assert!(matches!(
                function.blocks[0].instructions[index].operation,
                MachineOperation::Convert { op, .. } if op == expected
            ));
        }
        assert_eq!(
            function.blocks[0].instructions[12].source,
            Some(span(0, 196, 198))
        );
        machine
            .clone()
            .validate_for_target(&target)
            .expect("MachineWir validates sealed unary and cast operations");

        let mut conversion_substituted = machine.clone();
        let MachineOperation::Convert { op, .. } =
            &mut conversion_substituted.functions[4].blocks[0].instructions[8].operation
        else {
            panic!("unsigned widening operation");
        };
        *op = ConversionOp::SignExtend;
        conversion_substituted
            .clone()
            .validate_for_target(&target)
            .expect("signless integers permit the structurally valid signedness substitution");
        assert_eq!(
            seal(
                &MachineLoweringRequest {
                    input: &optimized,
                    target: &target,
                    build: &build,
                    limits: MachineLoweringLimits::standard(),
                },
                conversion_substituted,
                report.clone(),
                &|| false,
            ),
            Err(MachineLowerError::OutputDoesNotImplementInput)
        );

        let mut substituted = validated.into_wir();
        let MachineOperation::Unary { op, .. } =
            &mut substituted.functions[4].blocks[0].instructions[1].operation
        else {
            panic!("bool-not operation");
        };
        *op = MachineUnaryOp::BitNot;
        substituted
            .clone()
            .validate_for_target(&target)
            .expect("signless i8 permits the structurally valid stale unary tag");
        assert_eq!(
            seal(
                &MachineLoweringRequest {
                    input: &optimized,
                    target: &target,
                    build: &build,
                    limits: MachineLoweringLimits::standard(),
                },
                substituted,
                report,
                &|| false,
            ),
            Err(MachineLowerError::OutputDoesNotImplementInput)
        );
    }

    #[test]
    fn checked_integer_surface_preserves_signedness_provenance_fatal_and_seal() {
        let cases = [
            (
                wrela_flow_wir::BinaryOp::AddChecked,
                wrela_machine_wir::CheckedIntegerOp::Add,
            ),
            (
                wrela_flow_wir::BinaryOp::SubChecked,
                wrela_machine_wir::CheckedIntegerOp::Subtract,
            ),
            (
                wrela_flow_wir::BinaryOp::MulChecked,
                wrela_machine_wir::CheckedIntegerOp::Multiply,
            ),
            (
                wrela_flow_wir::BinaryOp::DivChecked,
                wrela_machine_wir::CheckedIntegerOp::Divide,
            ),
            (
                wrela_flow_wir::BinaryOp::RemChecked,
                wrela_machine_wir::CheckedIntegerOp::Remainder,
            ),
            (
                wrela_flow_wir::BinaryOp::ShiftLeftChecked,
                wrela_machine_wir::CheckedIntegerOp::ShiftLeft,
            ),
            (
                wrela_flow_wir::BinaryOp::ShiftLeftWrapping,
                wrela_machine_wir::CheckedIntegerOp::ShiftLeftWrapping,
            ),
            (
                wrela_flow_wir::BinaryOp::ShiftRightChecked,
                wrela_machine_wir::CheckedIntegerOp::ShiftRight,
            ),
        ];
        for (flow_op, expected) in cases {
            let (optimized, target, build) = ordinary_scalar_flow_fixture();
            let (validated, _) = optimized.into_parts();
            let mut flow = validated.into_wir();
            flow.functions[2].blocks[0].instructions[0].operation = FlowOperation::Binary {
                op: flow_op,
                left: FlowValueId(0),
                right: FlowValueId(1),
            };
            let checked = optimize(
                flow.validate()
                    .expect("structural checked integer FlowWir fixture"),
            );
            let output = lower(
                &checked,
                &target,
                &build,
                MachineLoweringLimits::standard(),
                &|| false,
            )
            .expect("checked integer reaches MachineWir");
            assert!(matches!(
                output.wir().as_wir().functions[2].blocks[0].instructions[0],
                wrela_machine_wir::MachineInstruction {
                    operation: MachineOperation::CheckedInteger {
                        op,
                        signedness: wrela_machine_wir::IntegerSignedness::Unsigned,
                        failure: wrela_machine_wir::ScalarFailureProvenance {
                            kind: wrela_machine_wir::ScalarFailureKind::Arithmetic,
                            flow_function: 2,
                            flow_instruction: 0,
                        },
                        ..
                    },
                    source: Some(source),
                    ..
                } if op == expected && source == span(0, 100, 106)
            ));
            assert_eq!(
                output
                    .report()
                    .runtime_uses
                    .iter()
                    .find(|usage| usage.intrinsic == RuntimeIntrinsic::Fatal)
                    .map(|usage| usage.call_sites),
                Some(1)
            );

            let mut substituted = output.wir().as_wir().clone();
            let MachineOperation::CheckedInteger { signedness, .. } =
                &mut substituted.functions[2].blocks[0].instructions[0].operation
            else {
                panic!("checked integer MachineWir operation");
            };
            *signedness = wrela_machine_wir::IntegerSignedness::Signed;
            substituted
                .clone()
                .validate_for_target(&target)
                .expect("signedness substitution is structurally valid");
            assert_eq!(
                seal(
                    &MachineLoweringRequest {
                        input: &checked,
                        target: &target,
                        build: &build,
                        limits: MachineLoweringLimits::standard(),
                    },
                    substituted,
                    output.report().clone(),
                    &|| false,
                ),
                Err(MachineLowerError::OutputDoesNotImplementInput)
            );
        }

        let (optimized, target, build) = ordinary_scalar_flow_fixture();
        let (validated, _) = optimized.into_parts();
        let mut flow = validated.into_wir();
        flow.functions[2].blocks[0].instructions[0].operation = FlowOperation::Binary {
            op: wrela_flow_wir::BinaryOp::AddChecked,
            left: FlowValueId(0),
            right: FlowValueId(1),
        };
        let checked = optimize(flow.validate().expect("checked limit FlowWir fixture"));
        let baseline = lower(
            &checked,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| false,
        )
        .expect("checked limit baseline");
        let exact_static = baseline
            .wir()
            .as_wir()
            .sections
            .iter()
            .try_fold(0_u64, |sum, section| {
                sum.checked_add(section.reserved_bytes)
            })
            .expect("bounded checked scalar static reservation");
        let mut exact = MachineLoweringLimits::standard();
        exact.static_bytes = exact_static;
        lower(&checked, &target, &build, exact, &|| false)
            .expect("exact checked scalar static limit");
        exact.static_bytes -= 1;
        assert!(matches!(
            lower(&checked, &target, &build, exact, &|| false),
            Err(MachineLowerError::ResourceLimit {
                resource: "MachineWir static bytes",
                ..
            })
        ));
        assert_eq!(
            lower(
                &checked,
                &target,
                &build,
                MachineLoweringLimits::standard(),
                &|| true,
            ),
            Err(MachineLowerError::Cancelled)
        );
    }

    #[test]
    fn parameterized_diamond_join_reaches_machine_block_parameter_and_post_join_use() {
        let (optimized, target, build) = ordinary_scalar_flow_fixture();
        let (validated, _) = optimized.into_parts();
        let mut flow = validated.into_wir();
        let helper = &mut flow.functions[2];
        helper.values.extend([
            FlowValue {
                id: FlowValueId(3),
                ty: TypeId(1),
                source_name: Some("choose_left".to_owned()),
                source: Some(span(0, 116, 120)),
            },
            FlowValue {
                id: FlowValueId(4),
                ty: TypeId(2),
                source_name: Some("joined_copy".to_owned()),
                source: Some(span(0, 121, 132)),
            },
        ]);
        helper.blocks = vec![
            FlowBlock {
                id: FlowBlockId(0),
                parameters: Vec::new(),
                instructions: vec![FlowInstruction {
                    id: FlowInstructionId(0),
                    results: vec![FlowValueId(3)],
                    operation: FlowOperation::Binary {
                        op: wrela_flow_wir::BinaryOp::Less,
                        left: FlowValueId(0),
                        right: FlowValueId(1),
                    },
                    source: Some(span(0, 116, 120)),
                }],
                terminator: FlowTerminator::Branch {
                    condition: FlowValueId(3),
                    then_block: FlowBlockId(1),
                    then_arguments: Vec::new(),
                    else_block: FlowBlockId(2),
                    else_arguments: Vec::new(),
                },
                source: Some(span(0, 116, 120)),
            },
            FlowBlock {
                id: FlowBlockId(1),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: FlowTerminator::Jump {
                    target: FlowBlockId(3),
                    arguments: vec![FlowValueId(0)],
                },
                source: Some(span(0, 121, 124)),
            },
            FlowBlock {
                id: FlowBlockId(2),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: FlowTerminator::Jump {
                    target: FlowBlockId(3),
                    arguments: vec![FlowValueId(1)],
                },
                source: Some(span(0, 125, 128)),
            },
            FlowBlock {
                id: FlowBlockId(3),
                parameters: vec![FlowValueId(2)],
                instructions: vec![FlowInstruction {
                    id: FlowInstructionId(1),
                    results: vec![FlowValueId(4)],
                    operation: FlowOperation::Copy {
                        value: FlowValueId(2),
                    },
                    source: Some(span(0, 121, 132)),
                }],
                terminator: FlowTerminator::Return(vec![FlowValueId(4)]),
                source: Some(span(0, 121, 138)),
            },
        ];
        let joined = optimize(
            flow.validate()
                .expect("valid parameterized FlowWir diamond join"),
        );
        let output = lower(
            &joined,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| false,
        )
        .expect("parameterized diamond join reaches MachineWir");
        let helper = &output.wir().as_wir().functions[2];
        assert!(matches!(
            helper.blocks[1].terminator,
            MachineTerminator::Jump {
                block: wrela_machine_wir::BlockId(3),
                ref arguments,
            } if arguments == &[wrela_machine_wir::ValueId(0)]
        ));
        assert!(matches!(
            helper.blocks[2].terminator,
            MachineTerminator::Jump {
                block: wrela_machine_wir::BlockId(3),
                ref arguments,
            } if arguments == &[wrela_machine_wir::ValueId(1)]
        ));
        assert_eq!(helper.blocks[3].parameters, [wrela_machine_wir::ValueId(2)]);
        assert!(matches!(
            helper.blocks[3].instructions[0],
            wrela_machine_wir::MachineInstruction {
                ref results,
                operation: MachineOperation::Convert {
                    op: ConversionOp::Bitcast,
                    value: wrela_machine_wir::ValueId(2),
                    destination: wrela_machine_wir::MachineTypeId(2),
                },
                ..
            } if results == &[wrela_machine_wir::ValueId(4)]
        ));
        assert!(matches!(
            helper.blocks[3].terminator,
            MachineTerminator::Return(ref values)
                if values == &[wrela_machine_wir::ValueId(4)]
        ));
    }

    #[test]
    fn canonical_every_primitive_nested_join_reaches_machine_wir() {
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
            let (optimized, target, build) = primitive_join_flow_fixture(primitive);
            let flow_test = &optimized.wir().as_wir().functions[0];
            let flow_joins = flow_test
                .blocks
                .iter()
                .filter(|block| !block.parameters.is_empty())
                .map(|block| block.id)
                .collect::<Vec<_>>();
            assert_eq!(flow_joins.len(), 2, "{primitive:?} Flow join count");

            let output = lower(
                &optimized,
                &target,
                &build,
                MachineLoweringLimits::standard(),
                &|| false,
            )
            .unwrap_or_else(|error| panic!("{primitive:?} MachineWir lowering: {error:?}"));
            let machine = output.wir().as_wir();
            machine
                .clone()
                .validate_for_target(&target)
                .unwrap_or_else(|error| panic!("{primitive:?} MachineWir seal: {error:?}"));
            assert!(machine.functions.iter().all(|function| {
                function.values.iter().all(|value| {
                    !matches!(
                        machine.types[value.ty.0 as usize].kind,
                        MachineTypeKind::Void
                    )
                })
            }));

            let test = &machine.functions[0];
            let consumer = &machine.functions[1];
            let unit = primitive == semantic::PrimitiveType::Unit;
            assert_eq!(consumer.parameters.len(), usize::from(!unit));
            for join in flow_joins {
                let block = &test.blocks[join.0 as usize];
                assert_eq!(
                    block.parameters.len(),
                    usize::from(!unit),
                    "{primitive:?} MachineWir join parameter"
                );
                let incoming = test
                    .blocks
                    .iter()
                    .filter_map(|predecessor| match &predecessor.terminator {
                        MachineTerminator::Jump { block, arguments } if block.0 == join.0 => {
                            Some(arguments)
                        }
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                assert_eq!(incoming.len(), 2, "{primitive:?} incoming join edges");
                assert!(
                    incoming
                        .iter()
                        .all(|arguments| arguments.len() == usize::from(!unit))
                );
                if let [parameter] = block.parameters.as_slice() {
                    let expected = match primitive {
                        semantic::PrimitiveType::Bool
                        | semantic::PrimitiveType::U8
                        | semantic::PrimitiveType::I8 => MachineTypeKind::Integer { bits: 8 },
                        semantic::PrimitiveType::U16 | semantic::PrimitiveType::I16 => {
                            MachineTypeKind::Integer { bits: 16 }
                        }
                        semantic::PrimitiveType::U32 | semantic::PrimitiveType::I32 => {
                            MachineTypeKind::Integer { bits: 32 }
                        }
                        semantic::PrimitiveType::U64
                        | semantic::PrimitiveType::Usize
                        | semantic::PrimitiveType::I64
                        | semantic::PrimitiveType::Isize => MachineTypeKind::Integer { bits: 64 },
                        semantic::PrimitiveType::U128 | semantic::PrimitiveType::I128 => {
                            MachineTypeKind::Integer { bits: 128 }
                        }
                        semantic::PrimitiveType::F32 => MachineTypeKind::Float32,
                        semantic::PrimitiveType::F64 => MachineTypeKind::Float64,
                        semantic::PrimitiveType::Unit | semantic::PrimitiveType::Char => {
                            panic!("unexpected retained {primitive:?} join")
                        }
                    };
                    assert_eq!(
                        machine.types[test.values[parameter.0 as usize].ty.0 as usize].kind,
                        expected
                    );
                }
            }
            let post_join_calls = test
                .blocks
                .iter()
                .flat_map(|block| &block.instructions)
                .filter_map(|instruction| match &instruction.operation {
                    MachineOperation::Call {
                        function,
                        arguments,
                        ..
                    } if function.0 == 1 => Some(arguments),
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(post_join_calls.len(), 1, "{primitive:?} post-join call");
            assert_eq!(post_join_calls[0].len(), usize::from(!unit));
            let copies = test
                .blocks
                .iter()
                .flat_map(|block| &block.instructions)
                .filter(|instruction| {
                    matches!(
                        instruction.operation,
                        MachineOperation::Convert {
                            op: ConversionOp::Bitcast,
                            ..
                        }
                    )
                })
                .count();
            assert_eq!(copies, usize::from(!unit), "{primitive:?} post-join copy");
        }
    }

    #[test]
    fn unit_join_erasure_honors_exact_instruction_limit_and_late_cancellation() {
        let (optimized, target, build) = primitive_join_flow_fixture(semantic::PrimitiveType::Unit);
        let baseline = lower(
            &optimized,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| false,
        )
        .expect("unit join baseline");
        let instructions = baseline
            .wir()
            .as_wir()
            .functions
            .iter()
            .flat_map(|function| &function.blocks)
            .map(|block| block.instructions.len() as u64)
            .sum::<u64>();
        assert!(instructions > 0);
        let mut exact = MachineLoweringLimits::standard();
        exact.instructions = instructions;
        exact = exact.with_aligned_validation();
        lower(&optimized, &target, &build, exact, &|| false)
            .expect("exact post-erasure instruction limit");
        exact.instructions -= 1;
        exact = exact.with_aligned_validation();
        assert!(matches!(
            lower(&optimized, &target, &build, exact, &|| false),
            Err(MachineLowerError::ResourceLimit {
                resource: "MachineWir instructions",
                ..
            })
        ));

        let (model_edges, payload_bytes) = model_resources(
            baseline.wir().as_wir(),
            MachineLoweringLimits::standard(),
            &|| false,
        )
        .expect("finite erased-unit MachineWir resources");
        let exact_model = MachineLoweringLimits {
            model_edges,
            payload_bytes,
            ..MachineLoweringLimits::standard()
        }
        .with_aligned_validation();
        lower(&optimized, &target, &build, exact_model, &|| false)
            .expect("exact post-erasure model-edge limit");
        let one_below_model = MachineLoweringLimits {
            model_edges: model_edges - 1,
            ..exact_model
        }
        .with_aligned_validation();
        assert!(matches!(
            lower(
                &optimized,
                &target,
                &build,
                one_below_model,
                &|| false
            ),
            Err(MachineLowerError::ResourceLimit {
                resource: "MachineWir model edges",
                limit,
            }) if limit == model_edges - 1
        ));
        let one_below_payload = MachineLoweringLimits {
            payload_bytes: payload_bytes - 1,
            ..exact_model
        }
        .with_aligned_validation();
        assert!(matches!(
            lower(
                &optimized,
                &target,
                &build,
                one_below_payload,
                &|| false
            ),
            Err(MachineLowerError::ResourceLimit {
                resource: "MachineWir payload bytes",
                limit,
            }) if limit == payload_bytes - 1
        ));

        let polls = Cell::new(0u64);
        lower(
            &optimized,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| {
                polls.set(polls.get() + 1);
                false
            },
        )
        .expect("count unit erasure cancellation polls");
        let cancel_at = polls.get().saturating_sub(1);
        let observed = Cell::new(0u64);
        assert_eq!(
            lower(
                &optimized,
                &target,
                &build,
                MachineLoweringLimits::standard(),
                &|| {
                    let next = observed.get() + 1;
                    observed.set(next);
                    next >= cancel_at
                },
            ),
            Err(MachineLowerError::Cancelled)
        );
        assert_eq!(observed.get(), cancel_at);
    }

    #[test]
    fn many_unit_inputs_construct_only_retained_machine_resources() {
        const ERASED: usize = 4_096;
        let (optimized, target, build) = many_unit_erasure_flow_fixture(ERASED);
        let flow = optimized.wir().as_wir();
        assert_eq!(flow.functions[1].parameters.len(), ERASED);
        assert!(flow.types.iter().any(|ty| {
            matches!(
                &ty.kind,
                FlowTypeKind::Function { parameters, .. } if parameters.len() == ERASED
            )
        }));
        assert!(
            flow.functions[0]
                .blocks
                .iter()
                .filter(|block| !block.parameters.is_empty())
                .all(|block| block.parameters.len() == ERASED)
        );
        assert!(
            flow.functions[0]
                .blocks
                .iter()
                .flat_map(|block| &block.instructions)
                .any(|instruction| matches!(
                    &instruction.operation,
                    FlowOperation::Call { function, arguments }
                        if *function == FlowFunctionId(1) && arguments.len() == ERASED
                ))
        );

        let baseline = lower(
            &optimized,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| false,
        )
        .expect("many-unit retained-size construction");
        let machine = baseline.wir().as_wir();
        let passive = machine
            .types
            .iter()
            .find(|ty| ty.source_name.as_deref() == Some("many_unit_signature"))
            .expect("retained passive function type");
        assert!(matches!(
            &passive.kind,
            MachineTypeKind::Function { parameters, .. } if parameters.is_empty()
        ));
        assert!(machine.functions[1].parameters.is_empty());
        assert!(
            machine.functions[0]
                .blocks
                .iter()
                .all(|block| block.parameters.is_empty())
        );
        assert!(
            machine.functions[0]
                .blocks
                .iter()
                .flat_map(|block| &block.instructions)
                .any(|instruction| matches!(
                    &instruction.operation,
                    MachineOperation::Call { function, arguments, .. }
                        if *function == wrela_machine_wir::FunctionId(1) && arguments.is_empty()
                ))
        );

        let instructions = machine
            .functions
            .iter()
            .flat_map(|function| &function.blocks)
            .map(|block| block.instructions.len() as u64)
            .sum::<u64>();
        let (model_edges, payload_bytes) =
            model_resources(machine, MachineLoweringLimits::standard(), &|| false)
                .expect("measure retained many-unit output");
        assert!(instructions < ERASED as u64);
        assert!(model_edges < ERASED as u64);
        let exact = MachineLoweringLimits {
            instructions,
            model_edges,
            payload_bytes,
            ..MachineLoweringLimits::standard()
        }
        .with_aligned_validation();
        lower(&optimized, &target, &build, exact, &|| false)
            .expect("exact retained instruction/model limits");
        assert!(matches!(
            lower(
                &optimized,
                &target,
                &build,
                MachineLoweringLimits {
                    instructions: instructions - 1,
                    ..exact
                }
                .with_aligned_validation(),
                &|| false,
            ),
            Err(MachineLowerError::ResourceLimit {
                resource: "MachineWir instructions",
                limit,
            }) if limit == instructions - 1
        ));
        assert!(matches!(
            lower(
                &optimized,
                &target,
                &build,
                MachineLoweringLimits {
                    model_edges: model_edges - 1,
                    ..exact
                }
                .with_aligned_validation(),
                &|| false,
            ),
            Err(MachineLowerError::ResourceLimit {
                resource: "MachineWir model edges",
                limit,
            }) if limit == model_edges - 1
        ));

        let all_polls = Cell::new(0u64);
        lower(
            &optimized,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| {
                all_polls.set(all_polls.get() + 1);
                false
            },
        )
        .expect("count many-unit construction polls");
        let cancel_at = all_polls.get() / 2;
        assert!(cancel_at > 1 && cancel_at + 1 < all_polls.get());
        let observed = Cell::new(0u64);
        assert_eq!(
            lower(
                &optimized,
                &target,
                &build,
                MachineLoweringLimits::standard(),
                &|| {
                    let next = observed.get() + 1;
                    observed.set(next);
                    next >= cancel_at
                },
            ),
            Err(MachineLowerError::Cancelled)
        );
        assert_eq!(observed.get(), cancel_at);
    }

    #[test]
    fn unary_cast_traps_lossy_substitutions_limits_and_late_cancellation() {
        let (checked, target, build) = unary_cast_flow_fixture();
        let (validated, _) = checked.into_parts();
        let mut flow = validated.into_wir();
        let FlowOperation::Cast { mode, .. } =
            &mut flow.functions[4].blocks[0].instructions[8].operation
        else {
            panic!("lossless widening cast");
        };
        *mode = wrela_flow_wir::CastMode::Checked;
        let checked = optimize(flow.validate().expect("structural checked cast"));
        let checked_output = lower(
            &checked,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| false,
        )
        .expect("checked scalar conversion reaches MachineWir fatal semantics");
        assert!(matches!(
            checked_output.wir().as_wir().functions[4].blocks[0].instructions[8].operation,
            MachineOperation::CheckedConvert {
                source: wrela_machine_wir::CheckedNumericKind::UnsignedInteger,
                destination_kind: wrela_machine_wir::CheckedNumericKind::UnsignedInteger,
                failure: wrela_machine_wir::ScalarFailureProvenance {
                    kind: wrela_machine_wir::ScalarFailureKind::Conversion,
                    flow_function: 4,
                    flow_instruction: 8,
                },
                ..
            }
        ));
        assert!(
            checked_output
                .report()
                .runtime
                .intrinsics
                .contains(&RuntimeIntrinsic::Fatal)
        );

        let (integer_negate, target, build) = unary_cast_flow_fixture();
        let (validated, _) = integer_negate.into_parts();
        let mut flow = validated.into_wir();
        let FlowOperation::Unary { op, .. } =
            &mut flow.functions[4].blocks[0].instructions[3].operation
        else {
            panic!("integer bit-not");
        };
        *op = wrela_flow_wir::UnaryOp::Negate;
        let integer_negate = optimize(flow.validate().expect("structural integer negate"));
        assert!(matches!(
            lower(
                &integer_negate,
                &target,
                &build,
                MachineLoweringLimits::standard(),
                &|| false,
            ),
            Err(MachineLowerError::UnsupportedInput {
                feature: "checked integer negation without an explicit trap edge",
            })
        ));

        let (lossy, target, build) = unary_cast_flow_fixture();
        let (validated, _) = lossy.into_parts();
        let mut flow = validated.into_wir();
        let FlowOperation::Cast { mode, .. } =
            &mut flow.functions[4].blocks[0].instructions[16].operation
        else {
            panic!("u32-to-f32 bitcast");
        };
        *mode = wrela_flow_wir::CastMode::Exact;
        let lossy = optimize(flow.validate().expect("structural lossy exact cast"));
        assert!(matches!(
            lower(
                &lossy,
                &target,
                &build,
                MachineLoweringLimits::standard(),
                &|| false,
            ),
            Err(MachineLowerError::UnsupportedInput {
                feature: "a scalar conversion that is not universally lossless",
            })
        ));

        let (optimized, target, build) = unary_cast_flow_fixture();
        let baseline = lower(
            &optimized,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| false,
        )
        .expect("measure unary/cast MachineWir");
        let exact_instructions = baseline
            .wir()
            .as_wir()
            .functions
            .iter()
            .flat_map(|function| &function.blocks)
            .try_fold(0_u64, |total, block| {
                total.checked_add(
                    u64::try_from(block.instructions.len()).expect("bounded instruction count"),
                )
            })
            .expect("bounded total instruction count");
        let mut exact = MachineLoweringLimits::standard();
        exact.instructions = exact_instructions;
        lower(&optimized, &target, &build, exact, &|| false)
            .expect("exact unary/cast instruction limit");
        let mut max_plus_one = exact;
        max_plus_one.instructions = max_plus_one
            .instructions
            .checked_sub(1)
            .expect("nonzero instruction count");
        let one_below_exact = exact_instructions
            .checked_sub(1)
            .expect("nonzero instruction count");
        assert_eq!(
            lower(&optimized, &target, &build, max_plus_one, &|| false),
            Err(MachineLowerError::ResourceLimit {
                resource: "MachineWir instructions",
                limit: one_below_exact,
            })
        );

        let polls = Cell::new(0_u64);
        lower(&optimized, &target, &build, exact, &|| {
            polls.set(
                polls
                    .get()
                    .checked_add(1)
                    .expect("bounded cancellation polls"),
            );
            false
        })
        .expect("count unary/cast cancellation polls");
        let cancel_at = polls.get();
        let polls = Cell::new(0_u64);
        assert_eq!(
            lower(&optimized, &target, &build, exact, &|| {
                let next = polls
                    .get()
                    .checked_add(1)
                    .expect("bounded cancellation polls");
                polls.set(next);
                next == cancel_at
            }),
            Err(MachineLowerError::Cancelled)
        );
        assert_eq!(polls.get(), cancel_at);
    }

    #[test]
    fn ordinary_scalar_boundary_rejects_substitution_limits_and_cancellation() {
        let (optimized, target, build) = ordinary_scalar_flow_fixture();
        let baseline = lower(
            &optimized,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| false,
        )
        .expect("ordinary scalar baseline");
        let (validated, report) = baseline.into_parts();
        let mut substituted = validated.into_wir();
        let MachineOperation::Call { arguments, .. } =
            &mut substituted.functions[0].blocks[1].instructions[0].operation
        else {
            panic!("ordinary scalar helper call")
        };
        arguments.swap(0, 1);
        substituted
            .clone()
            .validate_for_target(&target)
            .expect("same-typed argument substitution is structurally valid");
        assert_eq!(
            seal(
                &MachineLoweringRequest {
                    input: &optimized,
                    target: &target,
                    build: &build,
                    limits: MachineLoweringLimits::standard(),
                },
                substituted,
                report,
                &|| false,
            ),
            Err(MachineLowerError::OutputDoesNotImplementInput),
            "the producer/consumer seal must reject semantic argument permutation"
        );

        let exact_function_count = u64::try_from(optimized.wir().as_wir().functions.len())
            .expect("bounded function count");
        let mut exact = MachineLoweringLimits::standard();
        exact.functions = exact_function_count;
        lower(&optimized, &target, &build, exact, &|| false)
            .expect("exact ordinary scalar function limit succeeds");
        exact.functions -= 1;
        assert_eq!(
            lower(&optimized, &target, &build, exact, &|| false),
            Err(MachineLowerError::ResourceLimit {
                resource: "MachineWir functions",
                limit: exact_function_count - 1,
            }),
            "one input past the declared maximum fails before output allocation"
        );

        let polls = Cell::new(0u64);
        lower(
            &optimized,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| {
                polls.set(polls.get() + 1);
                false
            },
        )
        .expect("count ordinary scalar cancellation boundaries");
        let cancel_at = polls.get() / 2;
        assert!(cancel_at > 10);
        let observed = Cell::new(0u64);
        assert_eq!(
            lower(
                &optimized,
                &target,
                &build,
                MachineLoweringLimits::standard(),
                &|| {
                    observed.set(observed.get() + 1);
                    observed.get() == cancel_at
                },
            ),
            Err(MachineLowerError::Cancelled)
        );
        assert_eq!(observed.get(), cancel_at);
    }

    #[test]
    fn public_sealer_rejects_machine_code_that_changes_flow_semantics() {
        let (optimized, target, build) = fixture();
        let output = lower(
            &optimized,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| false,
        )
        .expect("canonical machine lowering");
        let (validated, report) = output.into_parts();
        let mut altered = validated.into_wir();
        let MachineOperation::Immediate(MachineImmediate::Integer { bytes_le, .. }) =
            &mut altered.functions[0].blocks[0].instructions[0].operation
        else {
            panic!("minimum entry immediate")
        };
        bytes_le[0] = 1;

        assert_eq!(
            seal(
                &MachineLoweringRequest {
                    input: &optimized,
                    target: &target,
                    build: &build,
                    limits: MachineLoweringLimits::standard(),
                },
                altered,
                report,
                &|| false,
            ),
            Err(MachineLowerError::OutputDoesNotImplementInput)
        );
    }

    #[test]
    fn public_sealer_cancels_inside_long_structural_equality() {
        let (optimized, target, build) = fixture();
        let (validated, _) = optimized.into_parts();
        let mut flow = validated.into_wir();
        flow.name = "x".repeat(CANCELLABLE_COPY_CHUNK_BYTES * 3);
        let optimized = optimize(flow.validate().expect("valid long-name FlowWir"));
        let limits = MachineLoweringLimits::standard();
        let output = lower(&optimized, &target, &build, limits, &|| false)
            .expect("canonical long-name lowering");
        let (validated, report) = output.into_parts();
        let candidate = validated.into_wir();
        let request = MachineLoweringRequest {
            input: &optimized,
            target: &target,
            build: &build,
            limits,
        };

        let prefix_polls = Cell::new(0u64);
        let count_prefix = || {
            prefix_polls.set(prefix_polls.get() + 1);
            false
        };
        check_cancelled(&count_prefix).expect("initial sealer poll");
        request.limits.validate().expect("valid lowering limits");
        validate_request_identity(&request, &count_prefix).expect("matching request identity");
        request.target.validate().expect("valid target");
        let (expected, _) = lower_supported(&request, &count_prefix)
            .expect("count polls before structural equality");
        assert_eq!(expected.name.len(), CANCELLABLE_COPY_CHUNK_BYTES * 3);

        // Equality first polls at entry, then before each 64-KiB name chunk.
        // Cancelling three polls after the prefix therefore stops before the
        // second equal chunk is compared, not in recomputation or validation.
        let cancel_at = prefix_polls.get() + 3;
        let observed = Cell::new(0u64);
        assert_eq!(
            seal(&request, candidate, report, &|| {
                let next = observed.get() + 1;
                observed.set(next);
                next == cancel_at
            }),
            Err(MachineLowerError::Cancelled)
        );
        assert_eq!(observed.get(), cancel_at);
    }

    #[test]
    fn emitted_static_reservations_obey_the_build_profile() {
        let (optimized, target, build) = fixture();
        let mut profile = build.profile.clone();
        profile.memory.static_bytes = 23;
        let constrained = seal_build_configuration(
            BuildConfiguration {
                identity: build.identity.clone(),
                profile,
            },
            build.identity.profile,
        )
        .expect("valid constrained profile");

        assert_eq!(
            lower(
                &optimized,
                &target,
                &constrained,
                MachineLoweringLimits::standard(),
                &|| false,
            ),
            Err(MachineLowerError::ResourceLimit {
                resource: "build profile static bytes",
                limit: 23,
            })
        );
    }

    #[test]
    fn exact_limits_succeed_and_one_below_fails() {
        let (optimized, target, build) = fixture();
        let baseline = lower(
            &optimized,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| false,
        )
        .expect("baseline lowering");
        let wir = baseline.wir().as_wir();
        let (edges, payload) = model_resources(wir, MachineLoweringLimits::standard(), &|| false)
            .expect("finite model resources");
        let static_bytes = wir
            .sections
            .iter()
            .map(|section| section.reserved_bytes)
            .sum();
        let exact = MachineLoweringLimits {
            types: 3,
            functions: 1,
            sections: 2,
            symbols: 3,
            globals: 1,
            instructions: 2,
            stack_slots: 4,
            proofs: 1,
            model_edges: edges,
            payload_bytes: payload,
            validation: wrela_machine_wir::ValidationLimits::standard(),
            static_bytes,
            stack_bytes_per_function: 1,
            report_bytes: u64::try_from(
                baseline.report().target_identity.len()
                    + baseline
                        .report()
                        .runtime_uses
                        .iter()
                        .map(|usage| usage.reason.len())
                        .sum::<usize>(),
            )
            .expect("report byte count"),
        }
        .with_aligned_validation();
        lower(&optimized, &target, &build, exact, &|| false).expect("exact machine limits");

        for limited in [
            MachineLoweringLimits {
                types: exact.types - 1,
                ..exact
            }
            .with_aligned_validation(),
            MachineLoweringLimits {
                sections: exact.sections - 1,
                ..exact
            }
            .with_aligned_validation(),
            MachineLoweringLimits {
                symbols: exact.symbols - 1,
                ..exact
            }
            .with_aligned_validation(),
            MachineLoweringLimits {
                instructions: exact.instructions - 1,
                ..exact
            }
            .with_aligned_validation(),
            MachineLoweringLimits {
                model_edges: exact.model_edges - 1,
                ..exact
            }
            .with_aligned_validation(),
            MachineLoweringLimits {
                payload_bytes: exact.payload_bytes - 1,
                ..exact
            }
            .with_aligned_validation(),
            MachineLoweringLimits {
                static_bytes: exact.static_bytes - 1,
                ..exact
            },
            MachineLoweringLimits {
                report_bytes: exact.report_bytes - 1,
                ..exact
            },
        ] {
            assert!(matches!(
                lower(&optimized, &target, &build, limited, &|| false),
                Err(MachineLowerError::ResourceLimit { .. })
            ));
        }
    }

    #[test]
    fn cancellation_is_observed_at_every_lowering_boundary() {
        let (optimized, target, build) = fixture();
        let polls = Cell::new(0u32);
        lower(
            &optimized,
            &target,
            &build,
            MachineLoweringLimits::standard(),
            &|| {
                polls.set(polls.get() + 1);
                false
            },
        )
        .expect("count cancellation polls");
        assert!(polls.get() > 10);

        for cancel_at in 1..=polls.get() {
            let calls = Cell::new(0u32);
            assert_eq!(
                lower(
                    &optimized,
                    &target,
                    &build,
                    MachineLoweringLimits::standard(),
                    &|| {
                        calls.set(calls.get() + 1);
                        calls.get() == cancel_at
                    },
                ),
                Err(MachineLowerError::Cancelled),
                "cancellation poll {cancel_at} was not observed"
            );
        }
    }

    #[test]
    fn input_build_and_target_identity_mismatches_are_rejected() {
        let (optimized, target, build) = fixture();
        let mut different = build.identity.clone();
        different.compiler = Sha256Digest::from_bytes([0x99; 32]);
        let different = build_configuration(different);
        assert_eq!(
            lower(
                &optimized,
                &target,
                &different,
                MachineLoweringLimits::standard(),
                &|| false,
            ),
            Err(MachineLowerError::BuildIdentityMismatch)
        );

        let observed_profile = build.identity.profile;
        let wrong_policy = seal_build_configuration(
            BuildConfiguration {
                identity: build.identity.clone(),
                profile: BuildProfile::development(),
            },
            observed_profile,
        )
        .expect("valid mismatched optimization policy fixture");
        assert_eq!(
            lower(
                &optimized,
                &target,
                &wrong_policy,
                MachineLoweringLimits::standard(),
                &|| false,
            ),
            Err(MachineLowerError::BuildIdentityMismatch)
        );

        let wrong_target =
            TargetPackage::aarch64_qemu_virt_uefi(Sha256Digest::from_bytes([0x98; 32]));
        assert_eq!(
            lower(
                &optimized,
                &wrong_target,
                &build,
                MachineLoweringLimits::standard(),
                &|| false,
            ),
            Err(MachineLowerError::BuildTargetMismatch)
        );
    }
}
