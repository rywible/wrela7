//! AArch64 target layout, ABI selection, and runtime expansion from optimized
//! FlowWir into validated MachineWir.

#![forbid(unsafe_code)]

use std::fmt;

use wrela_build_model::ValidatedBuildConfiguration;
use wrela_flow_opt::OptimizedFlowWir;
use wrela_machine_wir::{
    MachineFunctionRole, MachineOperation, MachineWir, SectionKind, ValidatedMachineWir,
    ValidationErrors,
};
use wrela_runtime_abi::{RuntimeIntrinsic, RuntimeRequirements};
use wrela_target::TargetPackage;

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
            static_bytes: 4 * 1024 * 1024 * 1024,
            stack_bytes_per_function: 16 * 1024 * 1024,
            report_bytes: 1024 * 1024 * 1024,
        }
    }

    pub fn validate(self) -> Result<(), MachineLowerError> {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MachineLowerError {
    Cancelled,
    InvalidLimits,
    BuildTargetMismatch,
    UnsupportedTarget(String),
    LayoutOverflow { subject: String },
    ResourceLimit { resource: &'static str, limit: u64 },
    MissingRuntimeLowering(RuntimeIntrinsic),
    InvalidReport(&'static str),
    InvalidOutput(ValidationErrors),
}

impl fmt::Display for MachineLowerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("MachineWir lowering was cancelled"),
            Self::InvalidLimits => {
                formatter.write_str("MachineWir lowering limits must be nonzero")
            }
            Self::BuildTargetMismatch => {
                formatter.write_str("build and backend target identities differ")
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

pub fn seal(
    request: &MachineLoweringRequest<'_>,
    wir: MachineWir,
    report: MachineLoweringReport,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<MachineLoweringOutput, MachineLowerError> {
    if is_cancelled() {
        return Err(MachineLowerError::Cancelled);
    }
    request.limits.validate()?;
    request
        .target
        .validate()
        .map_err(|error| MachineLowerError::UnsupportedTarget(error.to_string()))?;
    validate_limits(&wir, request.limits)?;
    let wir = wir
        .validate_for_target(request.target)
        .map_err(MachineLowerError::InvalidOutput)?;
    let input_build = &request.input.wir().as_wir().build;
    if input_build != &request.build.identity
        || wir.as_wir().build != request.build.identity
        || request.target.identity() != &request.build.identity.target
        || request.target.semantic().content_digest() != request.build.identity.target_package
    {
        return Err(MachineLowerError::BuildTargetMismatch);
    }
    if !flow_mapping_matches(request.input, &wir) {
        return Err(MachineLowerError::InvalidReport(
            "MachineWir does not preserve the exact FlowWir function and interrupt mapping",
        ));
    }
    validate_report(&wir, &report, request.limits)?;
    if is_cancelled() {
        return Err(MachineLowerError::Cancelled);
    }
    Ok(MachineLoweringOutput { wir, report })
}

fn flow_mapping_matches(input: &OptimizedFlowWir, output: &ValidatedMachineWir) -> bool {
    let flow = input.wir().as_wir();
    let machine = output.as_wir();
    if flow.functions.len() != machine.functions.len()
        || machine.image_entry.0 != flow.image_entry.0
    {
        return false;
    }
    let functions_match = flow
        .functions
        .iter()
        .zip(&machine.functions)
        .enumerate()
        .all(|(index, (source, lowered))| {
            let role = match source.role {
                wrela_flow_wir::FunctionRole::Ordinary => MachineFunctionRole::Ordinary,
                wrela_flow_wir::FunctionRole::ActorTurn(id) => MachineFunctionRole::ActorTurn(id.0),
                wrela_flow_wir::FunctionRole::TaskEntry(id) => MachineFunctionRole::TaskEntry(id.0),
                wrela_flow_wir::FunctionRole::Isr(id) => MachineFunctionRole::Isr(id.0),
                wrela_flow_wir::FunctionRole::Cleanup => MachineFunctionRole::Cleanup,
                wrela_flow_wir::FunctionRole::ImageEntry => MachineFunctionRole::ImageEntry,
                wrela_flow_wir::FunctionRole::Test => MachineFunctionRole::Test,
            };
            lowered.flow_function as usize == index
                && lowered.role == role
                && lowered.source == source.source
                && lowered.stack_bytes <= source.stack_bound
        });
    if !functions_match {
        return false;
    }
    let mut expected_interrupts: Vec<_> = flow
        .devices
        .iter()
        .flat_map(|device| {
            device
                .interrupt_functions
                .iter()
                .map(move |function| (device.id.0, device.target_binding.as_str(), function.0))
        })
        .collect();
    expected_interrupts.sort_by(|left, right| left.1.cmp(right.1));
    expected_interrupts.len() == machine.interrupts.len()
        && expected_interrupts
            .into_iter()
            .zip(&machine.interrupts)
            .all(|((device, binding, flow_function), interrupt)| {
                interrupt.device == device
                    && interrupt.target_binding == binding
                    && machine
                        .functions
                        .get(interrupt.handler.0 as usize)
                        .is_some_and(|handler| handler.flow_function == flow_function)
            })
}

fn validate_report(
    validated: &ValidatedMachineWir,
    report: &MachineLoweringReport,
    limits: MachineLoweringLimits,
) -> Result<(), MachineLowerError> {
    let wir = validated.as_wir();
    if report.target_identity != wir.target.identity {
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
    let section_sum = |kinds: &[SectionKind]| {
        wir.sections
            .iter()
            .filter(|section| kinds.contains(&section.kind))
            .try_fold(0u64, |sum, section| sum.checked_add(section.reserved_bytes))
    };
    let maximum_alignment = wir
        .types
        .iter()
        .map(|item| item.alignment)
        .chain(wir.sections.iter().map(|item| item.alignment))
        .chain(wir.globals.iter().map(|item| item.alignment))
        .chain(
            wir.functions
                .iter()
                .flat_map(|function| function.stack_slots.iter().map(|slot| slot.alignment)),
        )
        .max()
        .unwrap_or(1);
    let layout_matches = section_sum(&[SectionKind::Code])
        == Some(report.layout.code_bytes_upper_bound)
        && section_sum(&[SectionKind::ReadOnlyData, SectionKind::RuntimeMetadata])
            == Some(report.layout.read_only_bytes)
        && section_sum(&[SectionKind::WritableData]) == Some(report.layout.writable_bytes)
        && section_sum(&[SectionKind::ZeroFill]) == Some(report.layout.zero_fill_bytes)
        && wir
            .functions
            .iter()
            .map(|function| function.stack_bytes)
            .max()
            .unwrap_or(0)
            == report.layout.maximum_stack_bytes
        && maximum_alignment == report.layout.maximum_alignment;
    if !layout_matches {
        return Err(MachineLowerError::InvalidReport(
            "layout summary does not match section/function layout",
        ));
    }
    if !report
        .runtime_uses
        .windows(2)
        .all(|pair| pair[0].intrinsic < pair[1].intrinsic)
        || report
            .runtime_uses
            .iter()
            .any(|usage| usage.call_sites == 0 || usage.reason.trim().is_empty())
    {
        return Err(MachineLowerError::InvalidReport(
            "runtime uses are not canonical",
        ));
    }
    let mut runtime_call_counts = std::collections::BTreeMap::new();
    for instruction in wir
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .flat_map(|block| &block.instructions)
    {
        if let MachineOperation::RuntimeCall { intrinsic, .. } = &instruction.operation {
            *runtime_call_counts.entry(*intrinsic).or_insert(0u64) += 1;
        }
    }
    let actual_uses: Vec<_> = wir
        .runtime
        .intrinsics
        .iter()
        .map(|intrinsic| {
            (
                *intrinsic,
                runtime_call_counts.get(intrinsic).copied().unwrap_or(0),
            )
        })
        .filter(|(_, count)| *count != 0)
        .collect();
    if report.runtime_uses.len() != actual_uses.len()
        || !report
            .runtime_uses
            .iter()
            .zip(actual_uses)
            .all(|(reported, actual)| (reported.intrinsic, reported.call_sites) == actual)
    {
        return Err(MachineLowerError::InvalidReport(
            "runtime call-site counts do not match MachineWir",
        ));
    }
    let report_bytes = u64::try_from(report.target_identity.len())
        .ok()
        .and_then(|initial| {
            report
                .runtime_uses
                .iter()
                .try_fold(initial, |total, usage| {
                    total.checked_add(u64::try_from(usage.reason.len()).ok()?)
                })
        });
    if report_bytes.is_none_or(|bytes| bytes > limits.report_bytes) {
        return Err(MachineLowerError::ResourceLimit {
            resource: "machine lowering report bytes",
            limit: limits.report_bytes,
        });
    }
    Ok(())
}

fn validate_limits(
    wir: &MachineWir,
    limits: MachineLoweringLimits,
) -> Result<(), MachineLowerError> {
    let instructions = wir.functions.iter().try_fold(0u64, |total, function| {
        function.blocks.iter().try_fold(total, |total, block| {
            total.checked_add(u64::try_from(block.instructions.len()).ok()?)
        })
    });
    let stack_slots = wir.functions.iter().try_fold(0u64, |total, function| {
        total.checked_add(u64::try_from(function.stack_slots.len()).ok()?)
    });
    let static_bytes = wir.sections.iter().try_fold(0u64, |total, section| {
        total.checked_add(section.reserved_bytes)
    });
    let (model_edges, payload_bytes) = model_resources(wir);
    if wir.types.len() as u64 > limits.types
        || wir.functions.len() as u64 > limits.functions
        || wir.sections.len() > limits.sections as usize
        || wir.symbols.len() > limits.symbols as usize
        || wir.globals.len() > limits.globals as usize
        || instructions.is_none_or(|count| count > limits.instructions)
        || stack_slots.is_none_or(|count| count > limits.stack_slots)
        || wir.proofs.len() > limits.proofs as usize
        || model_edges.is_none_or(|count| count > limits.model_edges)
        || payload_bytes.is_none_or(|count| count > limits.payload_bytes)
        || static_bytes.is_none_or(|count| count > limits.static_bytes)
        || wir
            .functions
            .iter()
            .any(|function| function.stack_bytes > limits.stack_bytes_per_function)
    {
        return Err(MachineLowerError::ResourceLimit {
            resource: "MachineWir items, model payload, static bytes, or stack bytes",
            limit: limits.instructions,
        });
    }
    Ok(())
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

fn model_resources(wir: &wrela_machine_wir::MachineWir) -> (Option<u64>, Option<u64>) {
    use wrela_machine_wir::{
        MachineImmediate, MachineOperation, MachineTerminator, MachineTypeKind,
    };

    let mut meter = ResourceMeter::default();
    meter.text(&wir.name);
    meter.text(&wir.target.identity);
    meter.text(&wir.target.llvm_triple);
    meter.text(&wir.target.data_layout);
    meter.text(&wir.target.cpu);
    meter.text(&wir.target.coff_machine);
    meter.edges(&wir.target.features);
    for feature in &wir.target.features {
        meter.text(feature);
    }
    meter.edges(&wir.runtime.intrinsics);
    for count in [
        wir.types.len(),
        wir.sections.len(),
        wir.symbols.len(),
        wir.globals.len(),
        wir.functions.len(),
        wir.interrupts.len(),
        wir.proofs.len(),
    ] {
        meter.add_edges(count);
    }
    let immediate = |value: &MachineImmediate, meter: &mut ResourceMeter| match value {
        MachineImmediate::Integer { bytes_le, .. } | MachineImmediate::Bytes(bytes_le) => {
            meter.bytes(bytes_le);
        }
        MachineImmediate::Float32(_)
        | MachineImmediate::Float64(_)
        | MachineImmediate::Null(_)
        | MachineImmediate::Zero(_)
        | MachineImmediate::SymbolAddress(_) => {}
    };
    for ty in &wir.types {
        if let Some(name) = &ty.source_name {
            meter.text(name);
        }
        match &ty.kind {
            MachineTypeKind::Struct { fields, .. } => meter.edges(fields),
            MachineTypeKind::Function { parameters, .. } => meter.edges(parameters),
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
        meter.text(&section.name);
        meter.text(&section.owner);
    }
    for symbol in &wir.symbols {
        meter.text(&symbol.name);
    }
    for global in &wir.globals {
        immediate(&global.initializer, &mut meter);
    }
    for function in &wir.functions {
        meter.edges(&function.parameters);
        meter.edges(&function.values);
        meter.edges(&function.stack_slots);
        meter.edges(&function.blocks);
        for value in &function.values {
            if let Some(name) = &value.source_name {
                meter.text(name);
            }
        }
        for slot in &function.stack_slots {
            if let Some(name) = &slot.source_name {
                meter.text(name);
            }
            meter.edges(&slot.live_states);
        }
        for block in &function.blocks {
            meter.edges(&block.parameters);
            meter.edges(&block.instructions);
            for instruction in &block.instructions {
                meter.edges(&instruction.results);
                match &instruction.operation {
                    MachineOperation::Immediate(value) => immediate(value, &mut meter),
                    MachineOperation::Call { arguments, .. }
                    | MachineOperation::RuntimeCall { arguments, .. } => meter.edges(arguments),
                    MachineOperation::Arithmetic { .. }
                    | MachineOperation::IntegerCompare { .. }
                    | MachineOperation::FloatCompare { .. }
                    | MachineOperation::Convert { .. }
                    | MachineOperation::Select { .. }
                    | MachineOperation::AddressOffset { .. }
                    | MachineOperation::Load { .. }
                    | MachineOperation::Store { .. }
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
                | MachineTerminator::TailCall { arguments, .. } => meter.edges(arguments),
                MachineTerminator::Branch {
                    then_arguments,
                    else_arguments,
                    ..
                } => {
                    meter.edges(then_arguments);
                    meter.edges(else_arguments);
                }
                MachineTerminator::Switch {
                    cases,
                    default_arguments,
                    ..
                } => {
                    meter.edges(cases);
                    meter.edges(default_arguments);
                    for (_, _, arguments) in cases {
                        meter.edges(arguments);
                    }
                }
                MachineTerminator::Unreachable => {}
            }
        }
    }
    for interrupt in &wir.interrupts {
        meter.text(&interrupt.target_binding);
    }
    for proof in &wir.proofs {
        meter.edges(&proof.source_proofs);
        meter.text(&proof.statement);
    }
    if meter.overflowed {
        (None, None)
    } else {
        (Some(meter.edges), Some(meter.payload_bytes))
    }
}

#[cfg(test)]
mod contract_tests {
    use super::{MachineLowerError, MachineLoweringLimits};

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
    }
}
