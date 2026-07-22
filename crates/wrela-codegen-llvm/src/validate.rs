use wrela_machine_wir::{
    AtomicOrdering, BackendFacts, BackendProofKind, BlockId, CallingConvention, CheckedIntegerOp,
    ConversionOp, Endianness, IntegerSignedness, Linkage, MACHINE_WIR_VERSION,
    MachineActivationOwner, MachineActivationSchedule, MachineFunction, MachineFunctionOrigin,
    MachineFunctionRole, MachineImmediate, MachineInstruction, MachineOperation,
    MachineRegionStorageKind, MachineTerminator, MachineTypeId, MachineTypeKind, MachineUnaryOp,
    MemorySemantics, REGION_STORAGE_SECTION_PREFIX, ScalarFailureKind, Section, SectionKind,
    SymbolDefinition, SymbolVisibility, ValueId,
};
use wrela_runtime_abi::{
    INTERRUPT_ROUTE_LAYOUT, INTERRUPT_ROUTE_SECTION, INTERRUPT_ROUTE_TABLE_SYMBOL,
};
use wrela_target::ObjectFormat;

use crate::{CodegenError, CodegenRequest};

#[derive(Debug, Clone, Copy)]
struct IncomingEdge<'a> {
    target: u32,
    predecessor: u32,
    arguments: &'a [ValueId],
}

pub(super) fn preflight(
    request: &CodegenRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    check_cancelled(is_cancelled)?;
    request.options.validate()?;
    validate_target(request, is_cancelled)?;
    validate_resources(request, is_cancelled)?;
    validate_scalar_surface(request, is_cancelled)?;
    check_cancelled(is_cancelled)
}

fn validate_target(
    request: &CodegenRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let machine = request.module.as_wir();
    let target = request.target;
    if !crate::cancellable_text_equal(
        machine.build.target.as_str(),
        target.identity().as_str(),
        is_cancelled,
    )? || !crate::cancellable_text_equal(
        &machine.target.identity,
        target.identity().as_str(),
        is_cancelled,
    )? {
        return Err(CodegenError::TargetMismatch);
    }
    if machine.build.target_package != target.content_digest() {
        return Err(CodegenError::TargetPackageMismatch);
    }
    if !crate::cancellable_text_equal(
        &machine.target.llvm_triple,
        target.llvm_triple(),
        is_cancelled,
    )? || !crate::cancellable_text_equal(
        &machine.target.data_layout,
        target.llvm_data_layout(),
        is_cancelled,
    )? || !crate::cancellable_text_equal(&machine.target.cpu, target.llvm_cpu(), is_cancelled)?
        || !text_slices_equal(
            &machine.target.features,
            target.llvm_features(),
            is_cancelled,
        )?
        || !crate::cancellable_text_equal(
            &machine.target.coff_machine,
            target.coff_machine(),
            is_cancelled,
        )?
        || target.object_format() != ObjectFormat::Coff
        || target.llvm_triple() != "aarch64-unknown-uefi"
        || target.coff_machine() != "arm64"
    {
        return Err(CodegenError::TargetMachineMismatch(
            "MachineWir and target-owned LLVM fields differ".to_owned(),
        ));
    }
    let name_bytes = u64::try_from(machine.name.len()).unwrap_or(u64::MAX);
    if machine.version != MACHINE_WIR_VERSION
        || machine.name.is_empty()
        || name_bytes > request.options.maximum_measurement_bytes
        || contains_byte(machine.name.as_bytes(), 0, is_cancelled)?
    {
        return Err(CodegenError::UnsupportedMachineContract(
            "module version or bounded LLVM module name",
        ));
    }
    if machine.layout.pointer_bits != 64
        || machine.layout.pointer_alignment != 8
        || machine.layout.stack_alignment != 16
        || machine.layout.aggregate_alignment != 8
        || machine.layout.maximum_object_alignment != 16
        || machine.layout.endianness != Endianness::Little
    {
        return Err(CodegenError::UnsupportedMachineContract(
            "noncanonical AArch64 data layout",
        ));
    }
    Ok(())
}

fn validate_resources(
    request: &CodegenRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let machine = request.module.as_wir();
    let limits = request.options;
    require_limit(
        "types",
        machine.types.len(),
        u64::from(limits.maximum_types),
    )?;
    require_limit(
        "sections",
        machine.sections.len(),
        u64::from(limits.maximum_sections),
    )?;
    require_limit(
        "symbols",
        machine.symbols.len(),
        u64::from(limits.maximum_symbols),
    )?;
    require_limit(
        "functions",
        machine.functions.len(),
        u64::from(limits.maximum_functions),
    )?;
    require_limit(
        "globals",
        machine.globals.len(),
        u64::from(limits.maximum_symbols),
    )?;
    require_limit(
        "tests",
        machine.tests.len(),
        u64::from(limits.maximum_functions),
    )?;
    require_limit("proofs", machine.proofs.len(), limits.maximum_model_edges)?;
    require_limit(
        "activations",
        machine.activations.len(),
        limits.maximum_model_edges,
    )?;
    require_limit(
        "runtime intrinsics",
        machine.runtime.intrinsics.len(),
        u64::from(limits.maximum_symbols),
    )?;

    let mut blocks = 0u64;
    let mut instructions = 0u64;
    let mut values = 0u64;
    let mut edges = 0u64;
    let mut measurement_bytes = u64::try_from(machine.name.len()).unwrap_or(u64::MAX);
    for (index, ty) in machine.types.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        add_text(&mut measurement_bytes, ty.source_name.as_deref())?;
        match &ty.kind {
            MachineTypeKind::Function { parameters, .. } => {
                for (parameter_index, _) in parameters.iter().enumerate() {
                    check_periodically(parameter_index, is_cancelled)?;
                }
                edges = checked_add(edges, parameters.len(), "model edges")?;
            }
            MachineTypeKind::Struct { fields, .. } => {
                for (field_index, _) in fields.iter().enumerate() {
                    check_periodically(field_index, is_cancelled)?;
                }
                edges = checked_add(edges, fields.len(), "model edges")?;
            }
            _ => {}
        }
    }
    for (index, section) in machine.sections.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        add_text(&mut measurement_bytes, Some(&section.name))?;
        add_text(&mut measurement_bytes, Some(&section.owner))?;
    }
    for (index, symbol) in machine.symbols.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        add_text(&mut measurement_bytes, Some(&symbol.name))?;
    }
    for (index, global) in machine.globals.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        if let MachineImmediate::Bytes(bytes) = &global.initializer {
            measurement_bytes = measurement_bytes
                .checked_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
                .ok_or(CodegenError::ResourceLimit {
                    resource: "measurement bytes",
                    limit: u64::MAX,
                    actual: u64::MAX,
                })?;
        }
    }
    for (index, test) in machine.tests.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        add_text(&mut measurement_bytes, Some(&test.name))?;
        edges = checked_add(edges, 1, "model edges")?;
    }
    for (index, proof) in machine.proofs.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        add_text(&mut measurement_bytes, Some(&proof.statement))?;
        edges = checked_add(edges, proof.source_proofs.len(), "model edges")?;
        edges = checked_add(edges, proof.depends_on.len(), "model edges")?;
        edges = checked_add(edges, proof.sources.len(), "model edges")?;
    }
    edges = checked_add(edges, machine.activations.len(), "model edges")?;
    for (function_index, function) in machine.functions.iter().enumerate() {
        check_periodically(function_index, is_cancelled)?;
        blocks = checked_add(blocks, function.blocks.len(), "blocks")?;
        values = checked_add(values, function.values.len(), "values")?;
        edges = checked_add(edges, function.parameters.len(), "model edges")?;
        edges = checked_add(edges, function.proofs.len(), "model edges")?;
        for (value_index, value) in function.values.iter().enumerate() {
            check_periodically(value_index, is_cancelled)?;
            add_text(&mut measurement_bytes, value.source_name.as_deref())?;
        }
        for (block_index, block) in function.blocks.iter().enumerate() {
            check_periodically(block_index, is_cancelled)?;
            instructions = checked_add(instructions, block.instructions.len(), "instructions")?;
            edges = checked_add(edges, block.parameters.len(), "model edges")?;
            for (instruction_index, instruction) in block.instructions.iter().enumerate() {
                check_periodically(instruction_index, is_cancelled)?;
                edges = checked_add(edges, instruction.results.len(), "model edges")?;
                edges = checked_add(
                    edges,
                    operation_edges(&instruction.operation),
                    "model edges",
                )?;
            }
            edges = checked_add(
                edges,
                terminator_edges(&block.terminator, is_cancelled)?,
                "model edges",
            )?;
        }
    }
    require_limit("blocks", blocks, limits.maximum_blocks)?;
    require_limit("instructions", instructions, limits.maximum_instructions)?;
    require_limit("values", values, limits.maximum_values)?;
    require_limit("model edges", edges, limits.maximum_model_edges)?;
    if measurement_bytes > limits.maximum_measurement_bytes {
        return Err(CodegenError::ResourceLimit {
            resource: "measurement bytes",
            limit: limits.maximum_measurement_bytes,
            actual: measurement_bytes,
        });
    }
    Ok(())
}

fn validate_scalar_surface(
    request: &CodegenRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let machine = request.module.as_wir();
    if machine.runtime.version != wrela_runtime_abi::RUNTIME_ABI_VERSION
        || !machine.interrupts.is_empty()
    {
        return Err(CodegenError::UnsupportedMachineContract(
            "runtime ABI version or interrupt routes in scalar codegen",
        ));
    }
    if machine.functions.is_empty() {
        return Err(CodegenError::UnsupportedMachineContract(
            "an empty scalar function table",
        ));
    }
    for ty in &machine.types {
        check_cancelled(is_cancelled)?;
        if !supported_scalar_type(&ty.kind, ty.size, ty.alignment)
            && !supported_enum_type(machine, ty.id)
            && !supported_struct_type(machine, ty.id)
            && !supported_static_byte_array(machine, ty.id)
            && !supported_passive_function_type(machine, ty.id, is_cancelled)?
        {
            return Err(CodegenError::UnsupportedMachineContract(
                "non-scalar type other than a canonical static byte array or passive function signature",
            ));
        }
    }
    let valid_proofs = validate_proofs(request, is_cancelled)?;
    validate_static_globals(request, is_cancelled)?;
    validate_sections_and_symbols(request, is_cancelled)?;
    validate_test_table(request, is_cancelled)?;
    validate_activation_table(request, is_cancelled)?;
    validate_actor_message_table(request, is_cancelled)?;
    for function in &machine.functions {
        check_cancelled(is_cancelled)?;
        for (value_index, value) in function.values.iter().enumerate() {
            check_periodically(value_index, is_cancelled)?;
            if is_function_type(machine, value.ty) {
                return Err(CodegenError::UnsupportedMachineContract(
                    "a first-class function-typed value",
                ));
            }
        }
        validate_function(request, function, &valid_proofs, is_cancelled)?;
    }
    validate_image_entry(request, is_cancelled)
}

fn validate_sections_and_symbols(
    request: &CodegenRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let machine = request.module.as_wir();
    let mut owned_sections = fallible_filled(
        machine.sections.len(),
        u64::from(request.options.maximum_sections),
        "section ownership entries",
        0u8,
        is_cancelled,
    )?;
    for (index, function) in machine.functions.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        let section = machine.sections.get(function.section.0 as usize).ok_or(
            CodegenError::UnsupportedMachineContract("missing function code section"),
        )?;
        let symbol = machine.symbols.get(function.symbol.0 as usize).ok_or(
            CodegenError::UnsupportedMachineContract("missing function symbol"),
        )?;
        let section_name_valid = valid_section_name(&section.name, is_cancelled)?;
        let symbol_name_valid = valid_symbol_name(&symbol.name, is_cancelled)?;
        if section.id.0 != function.id.0
            || section.kind != SectionKind::Code
            || section.alignment != 16
            || section.reserved_bytes == 0
            || !section_name_valid
            || symbol.id.0 != function.id.0
            || !symbol_name_valid
            || symbol.definition != SymbolDefinition::Function(function.id)
        {
            return Err(CodegenError::UnsupportedMachineContract(
                "noncanonical per-function section or symbol",
            ));
        }
        let owned = owned_sections.get_mut(function.section.0 as usize).ok_or(
            CodegenError::UnsupportedMachineContract("missing function code section"),
        )?;
        if std::mem::replace(owned, 1) != 0 {
            return Err(CodegenError::UnsupportedMachineContract(
                "a code section owned by multiple functions",
            ));
        }
    }
    for (index, global) in machine.globals.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        let owned = owned_sections.get_mut(global.section.0 as usize).ok_or(
            CodegenError::UnsupportedMachineContract("a static global with an unknown section"),
        )?;
        *owned = 1;
    }
    let mut metadata_index = None;
    for (index, section) in machine.sections.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        if section.name == INTERRUPT_ROUTE_SECTION
            && section.kind == SectionKind::RuntimeMetadata
            && metadata_index.replace(index).is_some()
        {
            return Err(CodegenError::UnsupportedMachineContract(
                "canonical empty interrupt metadata",
            ));
        }
    }
    let Some(metadata_index) = metadata_index else {
        return Err(CodegenError::UnsupportedMachineContract(
            "canonical empty interrupt metadata",
        ));
    };
    let metadata =
        machine
            .sections
            .get(metadata_index)
            .ok_or(CodegenError::UnsupportedMachineContract(
                "canonical empty interrupt metadata",
            ))?;
    if metadata.alignment != INTERRUPT_ROUTE_LAYOUT.table_alignment
        || metadata.reserved_bytes != u64::from(INTERRUPT_ROUTE_LAYOUT.header_bytes)
    {
        return Err(CodegenError::UnsupportedMachineContract(
            "canonical empty interrupt metadata",
        ));
    }
    let metadata_owned =
        owned_sections
            .get_mut(metadata_index)
            .ok_or(CodegenError::UnsupportedMachineContract(
                "canonical empty interrupt metadata",
            ))?;
    if std::mem::replace(metadata_owned, 1) != 0 {
        return Err(CodegenError::UnsupportedMachineContract(
            "canonical empty interrupt metadata",
        ));
    }
    let expected_metadata_definition = SymbolDefinition::SectionOffset {
        section: metadata.id,
        offset: 0,
        bytes: u64::from(INTERRUPT_ROUTE_LAYOUT.header_bytes),
    };
    let mut metadata_symbol = None;
    for (index, symbol) in machine.symbols.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        if symbol.name == INTERRUPT_ROUTE_TABLE_SYMBOL && metadata_symbol.replace(symbol).is_some()
        {
            return Err(CodegenError::UnsupportedMachineContract(
                "canonical empty interrupt metadata",
            ));
        }
    }
    let Some(metadata_symbol) = metadata_symbol else {
        return Err(CodegenError::UnsupportedMachineContract(
            "canonical empty interrupt metadata",
        ));
    };
    if metadata_symbol.visibility != SymbolVisibility::RuntimeMetadata
        || metadata_symbol.definition != expected_metadata_definition
    {
        return Err(CodegenError::UnsupportedMachineContract(
            "canonical empty interrupt metadata",
        ));
    }
    for (index, section) in machine.sections.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        if owned_sections.get(index) != Some(&1)
            || !valid_data_or_code_section_name(section, is_cancelled)?
        {
            return Err(CodegenError::UnsupportedMachineContract(
                "an unowned or unsupported scalar section",
            ));
        }
    }
    for (index, symbol) in machine.symbols.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        let unsupported_definition = match symbol.definition {
            SymbolDefinition::Function(function) => machine
                .functions
                .get(function.0 as usize)
                .is_none_or(|function| function.symbol != symbol.id),
            SymbolDefinition::Global(global) => machine
                .globals
                .get(global.0 as usize)
                .is_none_or(|global| global.symbol != symbol.id),
            SymbolDefinition::ExternalRuntime(intrinsic) => {
                symbol.name != intrinsic.symbol_name()
                    || !machine.runtime.intrinsics.contains(&intrinsic)
            }
            SymbolDefinition::SectionOffset { .. } => symbol.name != INTERRUPT_ROUTE_TABLE_SYMBOL,
        };
        if !valid_symbol_name(&symbol.name, is_cancelled)? || unsupported_definition {
            return Err(CodegenError::UnsupportedMachineContract(
                "an unsupported scalar symbol",
            ));
        }
    }
    Ok(())
}

fn validate_static_globals(
    request: &CodegenRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let machine = request.module.as_wir();
    let mut section_layouts = fallible_filled(
        machine.sections.len(),
        u64::from(request.options.maximum_sections),
        "static section layout entries",
        (0u64, 0u64),
        is_cancelled,
    )?;
    for (index, global) in machine.globals.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        let Some(ty) = machine.types.get(global.ty.0 as usize) else {
            return Err(CodegenError::UnsupportedMachineContract(
                "a static global with an unknown type",
            ));
        };
        let Some(section) = machine.sections.get(global.section.0 as usize) else {
            return Err(CodegenError::UnsupportedMachineContract(
                "a static global with an unknown section",
            ));
        };
        let Some(symbol) = machine.symbols.get(global.symbol.0 as usize) else {
            return Err(CodegenError::UnsupportedMachineContract(
                "a static global with an unknown symbol",
            ));
        };
        let initializer_matches = match (section.kind, &global.initializer) {
            (SectionKind::ReadOnlyData, MachineImmediate::Bytes(bytes)) => {
                u64::try_from(bytes.len()).ok() == Some(ty.size)
            }
            (
                SectionKind::WritableData | SectionKind::ZeroFill,
                MachineImmediate::Zero(initializer_ty),
            ) => *initializer_ty == global.ty,
            _ => false,
        };
        if global.alignment != ty.alignment
            || section.alignment < global.alignment
            || section.alignment % global.alignment != 0
            || symbol.visibility != SymbolVisibility::Private
            || symbol.definition != SymbolDefinition::Global(global.id)
            || !supported_static_byte_array(machine, global.ty)
            || !initializer_matches
        {
            return Err(CodegenError::UnsupportedMachineContract(
                "a noncanonical static byte global",
            ));
        }
        let layout = section_layouts.get_mut(global.section.0 as usize).ok_or(
            CodegenError::UnsupportedMachineContract("a static global with an unknown section"),
        )?;
        if global.offset != layout.0 {
            return Err(CodegenError::UnsupportedMachineContract(
                "a sparse or noncanonical static global layout",
            ));
        }
        layout.0 =
            layout
                .0
                .checked_add(ty.size)
                .ok_or(CodegenError::UnsupportedMachineContract(
                    "an overflowing static global layout",
                ))?;
        layout.1 = layout
            .1
            .checked_add(1)
            .ok_or(CodegenError::UnsupportedMachineContract(
                "too many static globals",
            ))?;
    }
    for (index, section) in machine.sections.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        if !matches!(
            section.kind,
            SectionKind::ReadOnlyData | SectionKind::WritableData | SectionKind::ZeroFill
        ) {
            continue;
        }
        let (cursor, count) =
            section_layouts
                .get(index)
                .copied()
                .ok_or(CodegenError::UnsupportedMachineContract(
                    "an unknown static section",
                ))?;
        if count == 0 || cursor != section.reserved_bytes {
            return Err(CodegenError::UnsupportedMachineContract(
                "a static section not exactly covered by globals",
            ));
        }
    }
    Ok(())
}

fn validate_proofs(
    request: &CodegenRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>, CodegenError> {
    let mut valid = fallible_filled(
        request.module.as_wir().proofs.len(),
        request.options.maximum_model_edges,
        "backend proof validity entries",
        0u8,
        is_cancelled,
    )?;
    for (index, proof) in request.module.as_wir().proofs.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        if !proof.source_proofs.is_empty()
            && contains_non_whitespace(&proof.statement, is_cancelled)?
        {
            let slot = valid.get_mut(index).ok_or(CodegenError::ResourceLimit {
                resource: "backend proof validity entries",
                limit: request.options.maximum_model_edges,
                actual: u64::MAX,
            })?;
            *slot = 1;
        }
    }
    Ok(valid)
}

fn validate_test_table(
    request: &CodegenRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let machine = request.module.as_wir();
    let mut listed = fallible_filled(
        machine.functions.len(),
        u64::from(request.options.maximum_functions),
        "test function entries",
        0u8,
        is_cancelled,
    )?;
    for (index, test) in machine.tests.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        let Some(function) = machine.functions.get(test.function.0 as usize) else {
            return Err(CodegenError::UnsupportedMachineContract(
                "a test table that differs from executable test functions",
            ));
        };
        let Some(slot) = listed.get_mut(test.function.0 as usize) else {
            return Err(CodegenError::UnsupportedMachineContract(
                "a test table that differs from executable test functions",
            ));
        };
        if function.role != MachineFunctionRole::Test || std::mem::replace(slot, 1) != 0 {
            return Err(CodegenError::UnsupportedMachineContract(
                "a test table that differs from executable test functions",
            ));
        }
    }
    for (index, function) in machine.functions.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        if (function.role == MachineFunctionRole::Test) != (listed.get(index) == Some(&1)) {
            return Err(CodegenError::UnsupportedMachineContract(
                "a test table that differs from executable test functions",
            ));
        }
    }
    Ok(())
}

fn validate_actor_message_table(
    request: &CodegenRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let machine = request.module.as_wir();
    let startup_success = machine
        .functions
        .get(machine.image_entry.0 as usize)
        .and_then(|entry| entry.blocks.get(entry.entry.0 as usize))
        .and_then(|prologue| match &prologue.terminator {
            MachineTerminator::Switch { cases, .. } => match cases.as_slice() {
                [(0, success, arguments)] if arguments.is_empty() => Some(*success),
                _ => None,
            },
            _ => None,
        });
    let invalid = || {
        CodegenError::UnsupportedMachineContract(
            "the sealed unit-message mailbox admission and dispatch contract",
        )
    };
    let mut reserves = Vec::new();
    reserves
        .try_reserve_exact(2)
        .map_err(|_| CodegenError::ResourceLimit {
            resource: "actor mailbox reserve records",
            limit: 2,
            actual: 2,
        })?;
    let mut commit_count = 0_u8;
    let mut receives = Vec::new();
    receives
        .try_reserve_exact(2)
        .map_err(|_| CodegenError::ResourceLimit {
            resource: "actor mailbox receive records",
            limit: 2,
            actual: 2,
        })?;
    check_cancelled(is_cancelled)?;
    let mut dispatch = None;
    let mut reply_request = None;
    let mut reply_resolve = None;

    for (function_index, function) in machine.functions.iter().enumerate() {
        check_periodically(function_index, is_cancelled)?;
        for (block_index, block) in function.blocks.iter().enumerate() {
            check_periodically(block_index, is_cancelled)?;
            for (instruction_index, instruction) in block.instructions.iter().enumerate() {
                check_periodically(instruction_index, is_cancelled)?;
                match &instruction.operation {
                    MachineOperation::ActorReserve {
                        mailbox,
                        actor,
                        method,
                        proof,
                        failure,
                    } => {
                        let [reservation] = instruction.results.as_slice() else {
                            return Err(invalid());
                        };
                        let adjacent = block.instructions.get(instruction_index.saturating_add(1));
                        if reserves.len() >= 2
                            || !match function.role {
                                MachineFunctionRole::TaskEntry(_) => true,
                                MachineFunctionRole::ActorTurn(owner) => owner == *actor,
                                _ => false,
                            }
                            || instruction.source.is_none()
                            || failure.kind != ScalarFailureKind::ActorMailboxFull
                            || failure.flow_function != function.flow_function
                            || failure.flow_instruction != instruction.id.0
                            || !matches!(adjacent,
                                Some(next) if next.results.is_empty()
                                    && next.source == instruction.source
                                    && matches!(&next.operation,
                                        MachineOperation::ActorCommit {
                                            reservation: committed,
                                            mailbox: commit_mailbox,
                                            actor: commit_actor,
                                            method: commit_method,
                                        } if committed == reservation
                                            && commit_mailbox == mailbox
                                            && commit_actor == actor
                                            && commit_method == method))
                        {
                            return Err(invalid());
                        }
                        reserves.push((
                            function.id,
                            *reservation,
                            *mailbox,
                            *actor,
                            *method,
                            *proof,
                            instruction.source,
                        ));
                    }
                    MachineOperation::ActorCommit {
                        reservation,
                        mailbox,
                        actor,
                        method,
                    } => {
                        commit_count = commit_count.saturating_add(1);
                        let prior = instruction_index
                            .checked_sub(1)
                            .and_then(|prior| block.instructions.get(prior));
                        if !instruction.results.is_empty()
                            || !matches!(prior,
                                Some(previous) if previous.results.as_slice() == [*reservation]
                                    && previous.source == instruction.source
                                    && matches!(&previous.operation,
                                        MachineOperation::ActorReserve {
                                            mailbox: reserve_mailbox,
                                            actor: reserve_actor,
                                            method: reserve_method,
                                            ..
                                        } if reserve_mailbox == mailbox
                                            && reserve_actor == actor
                                            && reserve_method == method))
                        {
                            return Err(invalid());
                        }
                    }
                    MachineOperation::MailboxReceive {
                        mailbox,
                        actor,
                        method,
                        failure,
                    } => {
                        if receives.len() >= 2
                            || !instruction.results.is_empty()
                            || block.id != function.entry
                            || instruction_index != 0
                            || function.id != *method
                            || function.role != MachineFunctionRole::ActorTurn(*actor)
                            || instruction.source.is_none()
                            || failure.kind != ScalarFailureKind::ActorMailboxMismatch
                            || failure.flow_function != function.flow_function
                            || failure.flow_instruction != instruction.id.0
                        {
                            return Err(invalid());
                        }
                        receives.push((*mailbox, *actor, *method));
                    }
                    MachineOperation::MailboxDispatch {
                        mailbox,
                        actor,
                        method,
                    } => {
                        let prior = instruction_index
                            .checked_sub(1)
                            .and_then(|prior| block.instructions.get(prior));
                        if dispatch.is_some()
                            || function.id != machine.image_entry
                            || Some(block.id) != startup_success
                            || instruction_index != 1
                            || !instruction.results.is_empty()
                            || instruction.source.is_some()
                            || !matches!(prior,
                                Some(previous) if previous.results.is_empty()
                                    && previous.source.is_none()
                                    && matches!(&previous.operation,
                                        MachineOperation::Call {
                                            arguments,
                                            convention: CallingConvention::Internal,
                                            ..
                                        } if arguments.is_empty()))
                        {
                            return Err(invalid());
                        }
                        dispatch = Some((*mailbox, *actor, *method));
                    }
                    MachineOperation::ActorReplyRequest {
                        slot,
                        mailbox,
                        actor,
                        method,
                        permit,
                        reply,
                        failure,
                        duplicate_failure,
                    } => {
                        let fixed = instruction.results.len() == 1
                            && matches!(function.role, MachineFunctionRole::TaskEntry(_))
                            && instruction.source.is_some()
                            && failure.kind == ScalarFailureKind::ActorReplyStateMismatch
                            && duplicate_failure.kind
                                == ScalarFailureKind::ActorReplyDuplicateResolve
                            && failure.flow_function == function.flow_function
                            && duplicate_failure.flow_function == function.flow_function
                            && failure.flow_instruction == instruction.id.0
                            && duplicate_failure.flow_instruction == instruction.id.0
                            && function
                                .stack_slots
                                .get(slot.0 as usize)
                                .is_some_and(|slot| slot.size == 16 && slot.alignment == 8);
                        if !fixed
                            || reply_request
                                .replace((
                                    function.id,
                                    *mailbox,
                                    *actor,
                                    *method,
                                    *permit,
                                    *reply,
                                    instruction.source,
                                ))
                                .is_some()
                        {
                            return Err(invalid());
                        }
                    }
                    MachineOperation::ActorReplyResolve { outcome, reply } => {
                        let fixed = instruction.results.is_empty()
                            && matches!(function.role, MachineFunctionRole::ActorTurn(_))
                            && function
                                .values
                                .get(outcome.0 as usize)
                                .is_some_and(|value| {
                                    machine.types.get(value.ty.0 as usize).is_some_and(|ty| {
                                        ty.kind == MachineTypeKind::Integer { bits: 64 }
                                    })
                                });
                        if !fixed || reply_resolve.replace((function.id, *reply)).is_some() {
                            return Err(invalid());
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    if let Some((producer, mailbox, actor, method, permit, reply, source)) = reply_request {
        let startup_calls_producer = startup_success
            .and_then(|success| {
                machine
                    .functions
                    .get(machine.image_entry.0 as usize)
                    .and_then(|entry| entry.blocks.get(success.0 as usize))
            })
            .is_some_and(|block| {
                matches!(block.instructions.first(), Some(MachineInstruction {
                    results,
                    operation: MachineOperation::Call {
                        function,
                        arguments,
                        convention: CallingConvention::Internal,
                    },
                    source: None,
                    ..
                }) if results.is_empty() && arguments.is_empty() && *function == producer)
            });
        let storage_matches = machine.region_storage.iter().any(|storage| {
            storage.global == mailbox
                && storage.kind
                    == MachineRegionStorageKind::ActorMailbox {
                        actor,
                        mailbox_capacity: 1,
                    }
                && storage.capacity_bytes == 16
                && storage.alignment == 8
        });
        let permit_matches = machine.proofs.get(permit.0 as usize).is_some_and(|proof| {
            proof.kind == BackendProofKind::CapacityBound
                && proof.bound == Some(1)
                && proof.source == source
        });
        let reply_matches = machine.proofs.get(reply.0 as usize).is_some_and(|proof| {
            proof.kind == BackendProofKind::ActorReplyExactlyOnce
                && proof.bound == Some(1)
                && proof.depends_on.contains(&permit)
                && proof.source == source
        });
        let target_matches = machine
            .functions
            .get(method.0 as usize)
            .is_some_and(|target| {
                target.role == MachineFunctionRole::ActorTurn(actor)
                    && target.parameters.is_empty()
                    && machine
                        .types
                        .get(target.result.0 as usize)
                        .is_some_and(|ty| ty.kind == MachineTypeKind::Integer { bits: 64 })
            });
        if !reserves.is_empty()
            || commit_count != 0
            || receives.as_slice() != [(mailbox, actor, method)]
            || dispatch.is_some()
            || reply_resolve != Some((method, reply))
            || !startup_calls_producer
            || !storage_matches
            || !permit_matches
            || !reply_matches
            || !target_matches
        {
            return Err(invalid());
        }
        return Ok(());
    }

    let any_message =
        !reserves.is_empty() || commit_count != 0 || !receives.is_empty() || dispatch.is_some();
    if !any_message {
        for (index, activation) in machine.activations.iter().enumerate() {
            check_periodically(index, is_cancelled)?;
            if matches!(
                activation.schedule,
                MachineActivationSchedule::MailboxOnce | MachineActivationSchedule::SchedulerFifo
            ) {
                return Err(invalid());
            }
        }
        return Ok(());
    }
    let recurring = reserves.len() == 2 && receives.len() == 2 && commit_count == 2;
    let Some(&(producer, _reservation, mailbox, actor, method, _permit, _source)) =
        reserves.iter().find(|record| {
            machine
                .functions
                .get(record.0.0 as usize)
                .is_some_and(|function| matches!(function.role, MachineFunctionRole::TaskEntry(_)))
        })
    else {
        return Err(invalid());
    };
    let chain_matches = if recurring {
        reserves
            .iter()
            .find(|record| record.0 != producer)
            .is_some_and(|turn| {
                turn.2 == mailbox
                    && turn.3 == actor
                    && turn.0 == method
                    && turn.4 != method
                    && receives.contains(&(mailbox, actor, method))
                    && receives.contains(&(mailbox, actor, turn.4))
                    && dispatch == Some((mailbox, actor, method))
            })
    } else {
        reserves.len() == 1
            && receives.as_slice() == [(mailbox, actor, method)]
            && commit_count == 1
            && dispatch == Some((mailbox, actor, method))
    };
    if !chain_matches {
        return Err(invalid());
    }
    let mut storage = None;
    for (index, candidate) in machine.region_storage.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        if candidate.global == mailbox && storage.replace(candidate).is_some() {
            return Err(invalid());
        }
    }
    let Some(storage) = storage else {
        return Err(invalid());
    };
    if storage.kind
        != (MachineRegionStorageKind::ActorMailbox {
            actor,
            mailbox_capacity: 1,
        })
        || storage.capacity_units != 1
        || storage.bytes_per_unit != 16
        || storage.capacity_bytes != 16
        || storage.alignment != 8
    {
        return Err(invalid());
    }
    for (_, _, reserve_mailbox, reserve_actor, target_method, reserve_permit, reserve_source) in
        &reserves
    {
        let proof = machine
            .proofs
            .get(reserve_permit.0 as usize)
            .ok_or_else(invalid)?;
        let target = machine
            .functions
            .get(target_method.0 as usize)
            .ok_or_else(invalid)?;
        if *reserve_mailbox != mailbox
            || *reserve_actor != actor
            || proof.kind != BackendProofKind::CapacityBound
            || proof.source_proofs.as_slice() != [reserve_permit.0]
            || proof.depends_on.as_slice() != [storage.capacity_proof]
            || proof.bound != Some(1)
            || reserve_source.is_none_or(|source| {
                proof.sources.as_slice() != [source] || proof.source != Some(source)
            })
            || target.id != *target_method
            || target.role != MachineFunctionRole::ActorTurn(actor)
            || !target.parameters.is_empty()
            || machine
                .types
                .get(target.result.0 as usize)
                .is_none_or(|ty| ty.kind != MachineTypeKind::Void)
        {
            return Err(invalid());
        }
    }
    let mut actor_activation = 0_u8;
    let mut task_activation = 0_u8;
    let recurring_methods = recurring.then(|| {
        let continuation = reserves
            .iter()
            .find(|record| record.0 != producer)
            .map(|record| record.4)
            .unwrap_or(method);
        (method, continuation)
    });
    let mut first_fifo = 0_u8;
    let mut second_fifo = 0_u8;
    let mut fifo_callers_match = true;
    for (index, activation) in machine.activations.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        if activation.owner
            == (MachineActivationOwner::Actor {
                actor,
                mailbox_capacity: 1,
            })
            && ((recurring && activation.schedule == MachineActivationSchedule::SchedulerFifo)
                || (!recurring
                    && activation.caller == method
                    && activation.schedule == MachineActivationSchedule::MailboxOnce))
        {
            actor_activation = actor_activation.saturating_add(1);
            if let Some((first, second)) = recurring_methods {
                if activation.caller == first {
                    first_fifo = first_fifo.saturating_add(1);
                } else if activation.caller == second {
                    second_fifo = second_fifo.saturating_add(1);
                } else {
                    fifo_callers_match = false;
                }
            }
        }
        if activation.caller == producer
            && activation.schedule == MachineActivationSchedule::StartupOnce
            && matches!(activation.owner,
            MachineActivationOwner::Task { supervisor: Some(supervisor), .. }
                if supervisor == actor
                    || (actor == 0
                        && supervisor == 1
                        && machine.region_storage.iter().any(|storage| {
                            storage.kind == (MachineRegionStorageKind::ActorMailbox {
                                actor: 1,
                                mailbox_capacity: 1,
                            })
                        })))
        {
            task_activation = task_activation.saturating_add(1);
        }
    }
    if actor_activation != if recurring { 2 } else { 1 }
        || task_activation != 1
        || (recurring && (!fifo_callers_match || first_fifo != 1 || second_fifo != 1))
    {
        return Err(invalid());
    }
    Ok(())
}

fn validate_activation_table(
    request: &CodegenRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let machine = request.module.as_wir();
    let mut caller_counts = fallible_filled(
        machine.functions.len(),
        u64::from(request.options.maximum_functions),
        "activation caller entries",
        0u8,
        is_cancelled,
    )?;
    let startup_success = machine
        .functions
        .get(machine.image_entry.0 as usize)
        .and_then(|entry| entry.blocks.get(entry.entry.0 as usize))
        .and_then(|prologue| match &prologue.terminator {
            MachineTerminator::Switch { cases, .. } => match cases.as_slice() {
                [(0, success, arguments)] if arguments.is_empty() => Some(*success),
                _ => None,
            },
            _ => None,
        });

    for (index, activation) in machine.activations.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        if activation.id.0 as usize != index {
            return Err(CodegenError::UnsupportedMachineContract(
                "a noncanonical activation table",
            ));
        }
        let caller = machine.functions.get(activation.caller.0 as usize).ok_or(
            CodegenError::UnsupportedMachineContract("an activation with an unknown caller"),
        )?;
        let callee = machine.functions.get(activation.callee.0 as usize).ok_or(
            CodegenError::UnsupportedMachineContract("an activation with an unknown callee"),
        )?;
        let count = caller_counts.get_mut(activation.caller.0 as usize).ok_or(
            CodegenError::UnsupportedMachineContract("an activation with an unknown caller"),
        )?;
        *count = count.saturating_add(1);
        let owner_matches = match (activation.owner, caller.role, activation.schedule) {
            (
                MachineActivationOwner::Actor {
                    actor,
                    mailbox_capacity,
                },
                MachineFunctionRole::ActorTurn(role),
                MachineActivationSchedule::DormantMailbox
                | MachineActivationSchedule::MailboxOnce
                | MachineActivationSchedule::SchedulerFifo,
            ) => actor == role && mailbox_capacity != 0,
            (
                MachineActivationOwner::Task {
                    task,
                    slots: 1,
                    supervisor,
                },
                MachineFunctionRole::TaskEntry(role),
                MachineActivationSchedule::StartupOnce,
            ) => {
                task == role
                    && supervisor.is_none_or(|actor| {
                        actor == 0
                            || (actor == 1
                                && machine.region_storage.iter().any(|storage| {
                                    storage.kind
                                        == (MachineRegionStorageKind::ActorMailbox {
                                            actor: 1,
                                            mailbox_capacity: 1,
                                        })
                                }))
                    })
            }
            _ => false,
        };
        let capacity = machine.proofs.get(activation.capacity_proof.0 as usize);
        let cleanup = machine.proofs.get(activation.cleanup_proof.0 as usize);
        let proof_matches = caller.proofs.contains(&activation.capacity_proof)
            && callee.proofs.contains(&activation.cleanup_proof)
            && capacity.is_some_and(|proof| {
                proof.source_proofs.as_slice() == [activation.capacity_proof.0]
                    && proof.kind == BackendProofKind::CapacityBound
                    && proof.depends_on.as_slice() == [activation.cleanup_proof]
                    && proof.bound == Some(activation.capacity_bound)
                    && proof.sources.as_slice() == [activation.source]
            })
            && cleanup.is_some_and(|proof| {
                proof.source_proofs.as_slice() == [activation.cleanup_proof.0]
                    && proof.kind == BackendProofKind::CleanupAcyclic
                    && callee
                        .source
                        .is_some_and(|source| proof.sources.as_slice() == [source])
            });
        let entry = caller.blocks.get(caller.entry.0 as usize);
        let call_matches = entry.is_some_and(|entry| {
            let Some(instruction) = entry.instructions.last() else {
                return false;
            };
            let prefix_matches = match activation.schedule {
                MachineActivationSchedule::DormantMailbox => exact_actor_state_machine_prefix(
                    machine,
                    caller,
                    match activation.owner {
                        MachineActivationOwner::Actor { actor, .. } => actor,
                        MachineActivationOwner::Task { .. } => return false,
                    },
                    &entry.instructions[..entry.instructions.len().saturating_sub(1)],
                ),
                MachineActivationSchedule::MailboxOnce => {
                    matches!(entry.instructions.as_slice(), [receive, _]
                        if receive.results.is_empty()
                            && matches!(receive.operation,
                                MachineOperation::MailboxReceive { method, .. }
                                    if method == activation.caller))
                }
                MachineActivationSchedule::SchedulerFifo => {
                    matches!(entry.instructions.first(), Some(receive)
                        if receive.results.is_empty()
                            && matches!(receive.operation,
                                MachineOperation::MailboxReceive { method, .. }
                                    if method == activation.caller))
                        && (entry.instructions.len() == 2
                            || matches!(entry.instructions.as_slice(), [_, reserve, commit, _]
                                if matches!(
                                    (&reserve.operation, reserve.results.as_slice()),
                                    (
                                        MachineOperation::ActorReserve { method, .. },
                                        [reservation],
                                    ) if *method != activation.caller
                                        && commit.results.is_empty()
                                        && matches!(
                                            &commit.operation,
                                            MachineOperation::ActorCommit {
                                                reservation: committed,
                                                method: commit_method,
                                                ..
                                            } if committed == reservation
                                                && commit_method == method
                                        )
                                )))
                }
                MachineActivationSchedule::StartupOnce => {
                    entry.instructions.len() == 1
                        || matches!(entry.instructions.as_slice(), [capability, reserve, commit, _]
                        if matches!(
                            (&capability.operation, capability.results.as_slice()),
                            (
                                MachineOperation::Immediate(MachineImmediate::Integer {
                                    ty,
                                    bytes_le,
                                }),
                                [handle],
                            ) if bytes_le.as_slice() == 0_u64.to_le_bytes()
                                && caller.values.get(handle.0 as usize).is_some_and(|value| value.ty == *ty)
                                && machine.types.get(ty.0 as usize).is_some_and(|ty| {
                                    ty.source_name.as_deref() == Some("__wrela_actor_capability")
                                        && ty.kind == MachineTypeKind::Integer { bits: 64 }
                                        && ty.size == 8
                                        && ty.alignment == 8
                                })
                        ) && matches!(
                            (&reserve.operation, reserve.results.as_slice()),
                            (
                                MachineOperation::ActorReserve {
                                    mailbox,
                                    actor: 0,
                                    method,
                                    ..
                                },
                                [reservation],
                            ) if commit.results.is_empty()
                                && matches!(&commit.operation,
                                    MachineOperation::ActorCommit {
                                        reservation: committed,
                                        mailbox: commit_mailbox,
                                        actor: 0,
                                        method: commit_method,
                                    } if committed == reservation
                                        && commit_mailbox == mailbox
                                        && commit_method == method)
                        ))
                        || matches!(entry.instructions.as_slice(), [reserve, commit, _]
                        if matches!(
                            (&reserve.operation, reserve.results.as_slice()),
                            (
                                MachineOperation::ActorReserve {
                                    mailbox,
                                    actor,
                                    method,
                                    ..
                                },
                                [reservation],
                            ) if commit.results.is_empty()
                                && matches!(&commit.operation,
                                    MachineOperation::ActorCommit {
                                        reservation: committed,
                                        mailbox: commit_mailbox,
                                        actor: commit_actor,
                                        method: commit_method,
                                    } if committed == reservation
                                        && commit_mailbox == mailbox
                                        && commit_actor == actor
                                        && commit_method == method)
                        ))
                }
            };
            prefix_matches
                && instruction.id == activation.call_instruction
                && instruction.results.is_empty()
                && instruction.source == Some(activation.source)
                && matches!(&instruction.operation,
                    MachineOperation::Call {
                        function,
                        arguments,
                        convention: CallingConvention::Internal,
                    } if *function == activation.callee && arguments.is_empty())
                && matches!(&entry.terminator,
                    MachineTerminator::Jump { block, arguments }
                        if *block == activation.resume_block && arguments.is_empty())
        }) || structured_scope_activation_codegen_matches(machine, caller, activation);
        let resume_matches = caller
            .blocks
            .get(activation.resume_block.0 as usize)
            .is_some_and(|resume| {
                resume.parameters.is_empty()
                    && resume.instructions.is_empty()
                    && matches!(&resume.terminator,
                        MachineTerminator::Return(values) if values.is_empty())
            });
        let callee_matches = callee.role == MachineFunctionRole::Ordinary
            && callee.convention == CallingConvention::Internal
            && callee.parameters.is_empty()
            && machine
                .types
                .get(callee.result.0 as usize)
                .is_some_and(|ty| matches!(ty.kind, MachineTypeKind::Void))
            && matches!(callee.blocks.as_slice(), [block]
                if block.id == callee.entry
                    && block.parameters.is_empty()
                    && block.instructions.is_empty()
                    && matches!(&block.terminator,
                        MachineTerminator::Return(values) if values.is_empty()));
        let schedule_matches = activation_codegen_schedule_matches(
            machine,
            activation.caller,
            activation.schedule,
            startup_success,
            is_cancelled,
        )?;
        if !owner_matches
            || !proof_matches
            || activation.state != 0
            || activation.frame_bytes == 0
            || activation.frame_bytes != activation.region_capacity_bytes
            || activation.maximum_live != 1
            || activation.capacity_bound != u64::from(activation.maximum_live)
            || !call_matches
            || !resume_matches
            || !callee_matches
            || !schedule_matches
        {
            return Err(CodegenError::UnsupportedMachineContract(
                "an unsupported immediate activation contract",
            ));
        }
    }

    for (index, function) in machine.functions.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        let activation_role = matches!(
            function.role,
            MachineFunctionRole::ActorTurn(_) | MachineFunctionRole::TaskEntry(_)
        );
        let reply_role = function.blocks.iter().any(|block| {
            block.instructions.iter().any(|instruction| {
                matches!(
                    instruction.operation,
                    MachineOperation::ActorReplyRequest { .. }
                        | MachineOperation::ActorReplyResolve { .. }
                )
            })
        });
        if activation_role != (caller_counts.get(index) == Some(&1) || reply_role) {
            return Err(CodegenError::UnsupportedMachineContract(
                "an activation function without exactly one plan",
            ));
        }
    }
    Ok(())
}

fn structured_scope_activation_codegen_matches(
    machine: &wrela_machine_wir::MachineWir,
    caller: &MachineFunction,
    activation: &wrela_machine_wir::MachineActivationPlan,
) -> bool {
    let [entry, taken, untaken, fallthrough, resume] = caller.blocks.as_slice() else {
        return false;
    };
    let [state_field, state_constructor, predicate] = entry.instructions.as_slice() else {
        return false;
    };
    let [taken_cleanup] = taken.instructions.as_slice() else {
        return false;
    };
    let [fallthrough_cleanup, activation_call] = fallthrough.instructions.as_slice() else {
        return false;
    };
    let [state_field_value] = state_field.results.as_slice() else {
        return false;
    };
    let [state] = state_constructor.results.as_slice() else {
        return false;
    };
    let [condition] = predicate.results.as_slice() else {
        return false;
    };
    let cleanup_matches = |instruction: &wrela_machine_wir::MachineInstruction| {
        matches!(&instruction.operation,
        MachineOperation::Call {
            function,
            arguments,
            convention: CallingConvention::Internal,
        } if authenticated_generated_cleanup_call(
            machine,
            caller,
            instruction,
            *function,
            arguments,
        ))
    };
    caller.entry == entry.id
        && entry.id == BlockId(0)
        && taken.id == BlockId(1)
        && untaken.id == BlockId(2)
        && fallthrough.id == BlockId(3)
        && resume.id == BlockId(4)
        && activation.resume_block == resume.id
        && entry.parameters.is_empty()
        && taken.parameters.is_empty()
        && untaken.parameters.is_empty()
        && fallthrough.parameters.is_empty()
        && resume.parameters.is_empty()
        && matches!(
            &entry.terminator,
            MachineTerminator::Branch {
                condition: branch_condition,
                then_block,
                then_arguments,
                else_block,
                else_arguments,
            } if branch_condition == condition
                && *then_block == taken.id
                && then_arguments.is_empty()
                && *else_block == untaken.id
                && else_arguments.is_empty()
        )
        && matches!(
            state_field.operation,
            MachineOperation::Immediate(MachineImmediate::Integer { .. })
        )
        && matches!(&state_constructor.operation,
            MachineOperation::MakeStruct { fields, .. }
                if fields.as_slice() == [*state_field_value])
        && matches!(&predicate.operation,
            MachineOperation::Call {
                arguments,
                convention: CallingConvention::Internal,
                ..
            } if arguments.is_empty())
        && cleanup_matches(taken_cleanup)
        && cleanup_matches(fallthrough_cleanup)
        && taken_cleanup.operation == fallthrough_cleanup.operation
        && taken_cleanup.source == fallthrough_cleanup.source
        && matches!(&taken.terminator,
            MachineTerminator::Return(values) if values.is_empty())
        && untaken.instructions.is_empty()
        && matches!(&untaken.terminator,
            MachineTerminator::Jump { block, arguments }
                if *block == fallthrough.id && arguments.is_empty())
        && activation_call.id == activation.call_instruction
        && activation_call.results.is_empty()
        && activation_call.source == Some(activation.source)
        && matches!(&activation_call.operation,
            MachineOperation::Call {
                function,
                arguments,
                convention: CallingConvention::Internal,
            } if *function == activation.callee && arguments.is_empty())
        && matches!(&fallthrough.terminator,
            MachineTerminator::Jump { block, arguments }
                if *block == resume.id && arguments.is_empty())
        && resume.instructions.is_empty()
        && matches!(&resume.terminator,
            MachineTerminator::Return(values) if values.is_empty())
        && machine
            .functions
            .get(activation.callee.0 as usize)
            .is_some()
        && caller
            .values
            .get(state.0 as usize)
            .and_then(|value| machine.types.get(value.ty.0 as usize))
            .is_some_and(|ty| matches!(ty.kind, MachineTypeKind::Struct { .. }))
}

fn exact_actor_state_machine_prefix(
    machine: &wrela_machine_wir::MachineWir,
    function: &MachineFunction,
    actor: u32,
    instructions: &[MachineInstruction],
) -> bool {
    let u64_type = |ty: MachineTypeId| {
        machine.types.get(ty.0 as usize).is_some_and(|ty| {
            ty.kind == MachineTypeKind::Integer { bits: 64 } && ty.size == 8 && ty.alignment == 8
        })
    };
    let mut index = 0;
    while index < instructions.len() {
        if let (MachineOperation::Immediate(MachineImmediate::Integer { ty, bytes_le }), [result]) = (
            &instructions[index].operation,
            instructions[index].results.as_slice(),
        ) {
            if bytes_le.len() != 8
                || !u64_type(*ty)
                || function
                    .values
                    .get(result.0 as usize)
                    .is_none_or(|value| value.ty != *ty)
            {
                return false;
            }
            index += 1;
            continue;
        }
        let address_instruction = &instructions[index];
        let (MachineOperation::GlobalAddress(global), [address]) = (
            &address_instruction.operation,
            address_instruction.results.as_slice(),
        ) else {
            return false;
        };
        if function
            .values
            .get(address.0 as usize)
            .and_then(|value| machine.types.get(value.ty.0 as usize))
            .is_none_or(|ty| !matches!(ty.kind, MachineTypeKind::Pointer { .. }))
        {
            return false;
        }
        let Some(storage) = machine.region_storage.iter().find(|storage| {
            storage.global == *global
                && storage.kind == MachineRegionStorageKind::ActorState { actor }
                && storage.capacity_units == 1
                && storage.bytes_per_unit == 8
                && storage.capacity_bytes == 8
                && storage.alignment == 8
        }) else {
            return false;
        };
        let conservative_facts = |facts: &BackendFacts| {
            facts.proof == storage.capacity_proof
                && facts.alignment.is_none()
                && !facts.non_null
                && !facts.no_alias
                && !facts.in_bounds
                && !facts.no_unsigned_wrap
                && !facts.no_signed_wrap
        };
        let Some(access) = instructions.get(index + 1) else {
            return false;
        };
        let access_matches = match (&access.operation, access.results.as_slice()) {
            (
                MachineOperation::Load {
                    address: loaded,
                    ty,
                    semantics: MemorySemantics::Ordinary,
                    facts,
                },
                [result],
            ) => {
                loaded == address
                    && u64_type(*ty)
                    && conservative_facts(facts)
                    && function
                        .values
                        .get(result.0 as usize)
                        .is_some_and(|value| value.ty == *ty)
            }
            (
                MachineOperation::Store {
                    address: stored,
                    value,
                    semantics: MemorySemantics::Ordinary,
                    facts,
                },
                [],
            ) => {
                stored == address
                    && conservative_facts(facts)
                    && function
                        .values
                        .get(value.0 as usize)
                        .is_some_and(|value| u64_type(value.ty))
            }
            _ => false,
        };
        if !access_matches || access.source != address_instruction.source {
            return false;
        }
        if let (
            MachineOperation::Load { .. },
            [loaded],
            Some(immediate),
            Some(binary),
            Some(store_address),
            Some(store),
        ) = (
            &access.operation,
            access.results.as_slice(),
            instructions.get(index + 2),
            instructions.get(index + 3),
            instructions.get(index + 4),
            instructions.get(index + 5),
        ) {
            let compound_matches = matches!(
                (&immediate.operation, immediate.results.as_slice()),
                (
                    MachineOperation::Immediate(MachineImmediate::Integer { ty, bytes_le }),
                    [right],
                ) if bytes_le.len() == 8
                    && u64_type(*ty)
                    && function.values.get(right.0 as usize)
                        .is_some_and(|value| value.ty == *ty)
                    && matches!(
                        (&binary.operation, binary.results.as_slice()),
                        (
                            MachineOperation::CheckedInteger {
                                op: CheckedIntegerOp::Add,
                                signedness: IntegerSignedness::Unsigned,
                                left,
                                right: binary_right,
                                failure,
                            },
                            [result],
                        ) if left == loaded
                            && binary_right == right
                            && failure.kind == ScalarFailureKind::Arithmetic
                            && function.values.get(result.0 as usize)
                                .is_some_and(|value| u64_type(value.ty))
                            && matches!(
                                (&store_address.operation, store_address.results.as_slice()),
                                (MachineOperation::GlobalAddress(store_global), [stored_address])
                                    if store_global == global
                                        && function.values.get(stored_address.0 as usize)
                                            .and_then(|value| machine.types.get(value.ty.0 as usize))
                                            .is_some_and(|ty| matches!(ty.kind, MachineTypeKind::Pointer { .. }))
                                        && matches!(
                                            (&store.operation, store.results.as_slice()),
                                            (
                                                MachineOperation::Store {
                                                    address,
                                                    value,
                                                    semantics: MemorySemantics::Ordinary,
                                                    facts,
                                                },
                                                [],
                                            ) if address == stored_address
                                                && value == result
                                                && conservative_facts(facts)
                                        )
                            )
                    )
                    && binary.source == address_instruction.source
                    && store_address.source == address_instruction.source
                    && store.source == address_instruction.source
            );
            if compound_matches {
                index += 6;
                continue;
            }
        }
        index += 2;
    }
    true
}

fn activation_codegen_schedule_matches(
    machine: &wrela_machine_wir::MachineWir,
    caller: wrela_machine_wir::FunctionId,
    schedule: MachineActivationSchedule,
    startup_success: Option<wrela_machine_wir::BlockId>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, CodegenError> {
    let mut calls = 0usize;
    let mut startup = false;
    let mut mailbox = false;
    let mut fifo = false;
    let caller_actor = machine
        .functions
        .get(caller.0 as usize)
        .and_then(|function| match function.role {
            MachineFunctionRole::ActorTurn(actor) => Some(actor),
            _ => None,
        });
    for (function_index, function) in machine.functions.iter().enumerate() {
        check_periodically(function_index, is_cancelled)?;
        for (block_index, block) in function.blocks.iter().enumerate() {
            check_periodically(block_index, is_cancelled)?;
            for (instruction_index, instruction) in block.instructions.iter().enumerate() {
                check_periodically(instruction_index, is_cancelled)?;
                let direct_call = matches!(&instruction.operation,
                    MachineOperation::Call { function, .. } if *function == caller);
                let mailbox_dispatch = matches!(&instruction.operation,
                    MachineOperation::MailboxDispatch { method, .. } if *method == caller);
                fifo |= matches!(
                    &instruction.operation,
                    MachineOperation::MailboxDispatch { actor, .. }
                        if Some(*actor) == caller_actor
                            && function.id == machine.image_entry
                            && Some(block.id) == startup_success
                            && instruction_index == 1
                            && instruction.results.is_empty()
                            && instruction.source.is_none()
                );
                if direct_call || mailbox_dispatch {
                    calls = calls.saturating_add(1);
                    startup |= direct_call
                        && function.id == machine.image_entry
                        && Some(block.id) == startup_success
                        && instruction_index == 0
                        && instruction.results.is_empty()
                        && instruction.source.is_none()
                        && matches!(&instruction.operation,
                            MachineOperation::Call {
                                arguments,
                                convention: CallingConvention::Internal,
                                ..
                            } if arguments.is_empty());
                    mailbox |= mailbox_dispatch
                        && function.id == machine.image_entry
                        && Some(block.id) == startup_success
                        && instruction_index == 1
                        && instruction.results.is_empty()
                        && instruction.source.is_none()
                        && matches!(&instruction.operation,
                            MachineOperation::MailboxDispatch { method, .. }
                                if *method == caller);
                }
            }
        }
    }
    Ok(match schedule {
        MachineActivationSchedule::DormantMailbox => calls == 0,
        MachineActivationSchedule::MailboxOnce => calls == 1 && mailbox,
        MachineActivationSchedule::SchedulerFifo => calls == usize::from(mailbox) && fifo,
        MachineActivationSchedule::StartupOnce => calls == 1 && startup,
    })
}

fn validate_function(
    request: &CodegenRequest<'_>,
    function: &MachineFunction,
    valid_proofs: &[u8],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let machine = request.module.as_wir();
    let reply_requests = function
        .blocks
        .iter()
        .flat_map(|block| &block.instructions)
        .filter(|instruction| {
            matches!(
                instruction.operation,
                MachineOperation::ActorReplyRequest { .. }
            )
        })
        .count();
    let exact_reply_slot = matches!(function.stack_slots.as_slice(), [slot]
        if slot.id.0 == 0
            && slot.size == 16
            && slot.alignment == 8
            && slot.live_states.is_empty()
            && slot.overlay_group.is_none())
        && function.stack_bytes == 16
        && matches!(function.role, MachineFunctionRole::TaskEntry(_))
        && reply_requests == 1;
    if ((!function.stack_slots.is_empty() || function.stack_bytes != 0) && !exact_reply_slot)
        || matches!(function.role, MachineFunctionRole::Isr(_))
        || function.convention == CallingConvention::InterruptHandler
    {
        return Err(CodegenError::UnsupportedMachineContract(
            "stack objects, actor/task entries, or interrupt handlers",
        ));
    }
    let valid_abi = if function.id == machine.image_entry {
        function.role == MachineFunctionRole::ImageEntry
            && function.linkage == Linkage::ExportedEntry
            && function.convention == CallingConvention::UefiAarch64
    } else {
        function.role != MachineFunctionRole::ImageEntry
            && function.linkage == Linkage::Private
            && matches!(
                function.convention,
                CallingConvention::Internal | CallingConvention::Aapcs64
            )
    };
    if !valid_abi {
        return Err(CodegenError::UnsupportedMachineContract(
            "scalar function linkage or calling convention",
        ));
    }
    validate_scalar_value_types(&machine.types, &function.values, is_cancelled)?;
    let cleanup_state = authenticated_cleanup_boundary_state(machine, function, is_cancelled)?;
    poll_values(&function.parameters, is_cancelled)?;
    for (parameter_index, parameter) in function.parameters.iter().enumerate() {
        check_periodically(parameter_index, is_cancelled)?;
        if value_type(machine, function, *parameter)
            .is_none_or(|ty| !is_basic_scalar(machine, ty) && cleanup_state != Some(ty))
        {
            return Err(CodegenError::UnsupportedMachineContract(
                "void or non-scalar function parameter",
            ));
        }
    }
    if !is_return_type(machine, function.result) {
        return Err(CodegenError::UnsupportedMachineContract(
            "non-scalar function result",
        ));
    }
    for (block_index, block) in function.blocks.iter().enumerate() {
        check_periodically(block_index, is_cancelled)?;
        for (instruction_index, instruction) in block.instructions.iter().enumerate() {
            check_periodically(instruction_index, is_cancelled)?;
            validate_operation(request, function, instruction, valid_proofs)?;
        }
        validate_terminator(request, function, block.id, &block.terminator, is_cancelled)?;
    }
    validate_control_flow(request, function, is_cancelled)
}

fn validate_scalar_value_types(
    types: &[wrela_machine_wir::MachineType],
    values: &[wrela_machine_wir::MachineValue],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    for (index, value) in values.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        if types
            .get(value.ty.0 as usize)
            .is_some_and(|ty| matches!(ty.kind, MachineTypeKind::Void))
        {
            return Err(CodegenError::UnsupportedMachineContract(
                "void-typed MachineWir SSA values or block parameters",
            ));
        }
    }
    Ok(())
}

fn validate_operation(
    request: &CodegenRequest<'_>,
    function: &MachineFunction,
    instruction: &wrela_machine_wir::MachineInstruction,
    valid_proofs: &[u8],
) -> Result<(), CodegenError> {
    let machine = request.module.as_wir();
    let unsupported = || CodegenError::UnsupportedMachineOperation {
        function: function.id.0,
        instruction: instruction.id.0,
    };
    match &instruction.operation {
        MachineOperation::Immediate(
            MachineImmediate::Integer { .. }
            | MachineImmediate::Float32(_)
            | MachineImmediate::Float64(_)
            | MachineImmediate::Null(_)
            | MachineImmediate::Zero(_)
            | MachineImmediate::SymbolAddress(_),
        )
        | MachineOperation::Unary {
            op: MachineUnaryOp::BoolNot | MachineUnaryOp::BitNot | MachineUnaryOp::FloatNegate,
            ..
        }
        | MachineOperation::Arithmetic { .. }
        | MachineOperation::CheckedInteger { .. }
        | MachineOperation::IntegerCompare { .. }
        | MachineOperation::FloatCompare { .. }
        | MachineOperation::Select { .. }
        | MachineOperation::Copy { .. }
        | MachineOperation::MakeStruct { .. }
        | MachineOperation::InsertField { .. }
        | MachineOperation::ExtractField { .. }
        | MachineOperation::MakeEnum { .. }
        | MachineOperation::EnumTag { .. }
        | MachineOperation::EnumPayload { .. }
        | MachineOperation::GlobalAddress(_)
        | MachineOperation::ActorReserve { .. }
        | MachineOperation::ActorCommit { .. }
        | MachineOperation::ActorReplyRequest { .. }
        | MachineOperation::ActorReplyResolve { .. }
        | MachineOperation::MailboxReceive { .. }
        | MachineOperation::MailboxDispatch { .. }
        | MachineOperation::TestAssert { .. }
        | MachineOperation::Fence(_) => {}
        MachineOperation::Call {
            function: callee,
            arguments,
            ..
        } => {
            let has_aggregate = arguments.iter().any(|argument| {
                value_type(machine, function, *argument)
                    .is_some_and(|ty| !is_basic_scalar(machine, ty))
            });
            if has_aggregate
                && !authenticated_generated_cleanup_call(
                    machine,
                    function,
                    instruction,
                    *callee,
                    arguments,
                )
            {
                return Err(CodegenError::UnsupportedMachineContract(
                    "unauthenticated aggregate cleanup call",
                ));
            }
        }
        MachineOperation::RuntimeCall { intrinsic, .. }
            if *intrinsic != wrela_runtime_abi::RuntimeIntrinsic::TestAssertionFail => {}
        MachineOperation::RuntimeCall { .. } => return Err(unsupported()),
        MachineOperation::CheckedConvert { .. } => {}
        MachineOperation::Convert {
            op,
            value,
            destination,
        } => {
            let source = value_type(machine, function, *value).ok_or_else(unsupported)?;
            if !legal_conversion(machine, *op, source, *destination) {
                return Err(unsupported());
            }
        }
        MachineOperation::AddressOffset { facts, .. } => {
            validate_facts(valid_proofs, function.id.0, instruction.id.0, facts)?;
            if facts.alignment.is_some()
                || facts.non_null
                || facts.no_alias
                || facts.no_unsigned_wrap
                || facts.no_signed_wrap
            {
                return Err(CodegenError::InvalidBackendFact {
                    function: function.id.0,
                    instruction: instruction.id.0,
                    fact: "unsupported address-offset backend flag",
                });
            }
        }
        MachineOperation::Load {
            semantics, facts, ..
        } => {
            validate_facts(valid_proofs, function.id.0, instruction.id.0, facts)?;
            validate_memory_facts(function.id.0, instruction.id.0, facts)?;
            if matches!(
                semantics,
                MemorySemantics::Atomic(AtomicOrdering::Release | AtomicOrdering::AcquireRelease)
            ) {
                return Err(unsupported());
            }
        }
        MachineOperation::Store {
            semantics, facts, ..
        } => {
            validate_facts(valid_proofs, function.id.0, instruction.id.0, facts)?;
            validate_memory_facts(function.id.0, instruction.id.0, facts)?;
            if matches!(
                semantics,
                MemorySemantics::Atomic(AtomicOrdering::Acquire | AtomicOrdering::AcquireRelease)
            ) {
                return Err(unsupported());
            }
        }
        MachineOperation::Immediate(MachineImmediate::Bytes(_))
        | MachineOperation::MemoryCopy { .. }
        | MachineOperation::MemorySet { .. }
        | MachineOperation::StackAddress(_) => return Err(unsupported()),
    }
    Ok(())
}

fn validate_memory_facts(
    function: u32,
    instruction: u32,
    facts: &BackendFacts,
) -> Result<(), CodegenError> {
    if facts.non_null
        || facts.no_alias
        || facts.in_bounds
        || facts.no_unsigned_wrap
        || facts.no_signed_wrap
    {
        Err(CodegenError::InvalidBackendFact {
            function,
            instruction,
            fact: "unsupported load/store backend flag",
        })
    } else {
        Ok(())
    }
}

fn validate_facts(
    valid_proofs: &[u8],
    function: u32,
    instruction: u32,
    facts: &BackendFacts,
) -> Result<(), CodegenError> {
    if valid_proofs.get(facts.proof.0 as usize) != Some(&1) {
        Err(CodegenError::InvalidBackendFact {
            function,
            instruction,
            fact: "nonempty source-backed MachineWir proof",
        })
    } else {
        Ok(())
    }
}

fn validate_terminator(
    request: &CodegenRequest<'_>,
    function: &MachineFunction,
    block: wrela_machine_wir::BlockId,
    terminator: &MachineTerminator,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let machine = request.module.as_wir();
    match terminator {
        MachineTerminator::Jump { arguments, .. }
        | MachineTerminator::Return(arguments)
        | MachineTerminator::TailCall { arguments, .. } => {
            poll_values(arguments, is_cancelled)?;
        }
        MachineTerminator::Branch {
            then_arguments,
            else_arguments,
            ..
        } => {
            poll_values(then_arguments, is_cancelled)?;
            poll_values(else_arguments, is_cancelled)?;
        }
        MachineTerminator::Switch {
            cases,
            default_arguments,
            ..
        } => {
            for (case_index, (_, _, arguments)) in cases.iter().enumerate() {
                check_periodically(case_index, is_cancelled)?;
                poll_values(arguments, is_cancelled)?;
            }
            poll_values(default_arguments, is_cancelled)?;
        }
        MachineTerminator::Unreachable => {}
    }
    if let MachineTerminator::Switch { value, cases, .. } = terminator {
        let bits = value_type(machine, function, *value)
            .and_then(|ty| machine.types.get(ty.0 as usize))
            .and_then(|ty| match ty.kind {
                MachineTypeKind::Integer { bits } => Some(bits),
                _ => None,
            })
            .ok_or(CodegenError::UnsupportedMachineTerminator {
                function: function.id.0,
                block: block.0,
            })?;
        if bits < 128 {
            for (case_index, (value, _, _)) in cases.iter().enumerate() {
                check_periodically(case_index, is_cancelled)?;
                if *value >= (1u128 << bits) {
                    return Err(CodegenError::UnsupportedMachineTerminator {
                        function: function.id.0,
                        block: block.0,
                    });
                }
            }
        }
    }
    if let MachineTerminator::TailCall {
        function: callee,
        arguments,
    } = terminator
    {
        let callee_function = machine.functions.get(callee.0 as usize).ok_or(
            CodegenError::UnsupportedMachineTerminator {
                function: function.id.0,
                block: block.0,
            },
        )?;
        if function.convention == CallingConvention::UefiAarch64
            || function.convention != callee_function.convention
            || function.result != callee_function.result
            || function.parameters.len() != callee_function.parameters.len()
            || arguments.len() != callee_function.parameters.len()
        {
            return Err(CodegenError::UnsupportedMachineTerminator {
                function: function.id.0,
                block: block.0,
            });
        }
        for (parameter_index, (caller_parameter, callee_parameter)) in function
            .parameters
            .iter()
            .zip(&callee_function.parameters)
            .enumerate()
        {
            check_periodically(parameter_index, is_cancelled)?;
            if value_type(machine, function, *caller_parameter)
                != value_type(machine, callee_function, *callee_parameter)
            {
                return Err(CodegenError::UnsupportedMachineTerminator {
                    function: function.id.0,
                    block: block.0,
                });
            }
        }
        for (argument_index, (argument, parameter)) in arguments
            .iter()
            .zip(&callee_function.parameters)
            .enumerate()
        {
            check_periodically(argument_index, is_cancelled)?;
            if value_type(machine, function, *argument)
                != value_type(machine, callee_function, *parameter)
            {
                return Err(CodegenError::UnsupportedMachineTerminator {
                    function: function.id.0,
                    block: block.0,
                });
            }
        }
    }
    Ok(())
}

fn poll_values(values: &[ValueId], is_cancelled: &dyn Fn() -> bool) -> Result<(), CodegenError> {
    for (index, _) in values.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
    }
    Ok(())
}

fn validate_control_flow(
    request: &CodegenRequest<'_>,
    function: &MachineFunction,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let mut edge_count = 0usize;
    for (index, block) in function.blocks.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        edge_count = edge_count
            .checked_add(successor_count(&block.terminator))
            .ok_or(CodegenError::ResourceLimit {
                resource: "CFG edges",
                limit: request.options.maximum_model_edges,
                actual: u64::MAX,
            })?;
    }
    let actual = u64::try_from(edge_count).unwrap_or(u64::MAX);
    if actual > request.options.maximum_model_edges {
        return Err(CodegenError::ResourceLimit {
            resource: "CFG edges",
            limit: request.options.maximum_model_edges,
            actual,
        });
    }
    let mut edges = Vec::new();
    check_cancelled(is_cancelled)?;
    edges
        .try_reserve_exact(edge_count)
        .map_err(|_| CodegenError::ResourceLimit {
            resource: "CFG edges",
            limit: request.options.maximum_model_edges,
            actual,
        })?;
    check_cancelled(is_cancelled)?;
    for (index, block) in function.blocks.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        push_edges(&mut edges, block.id.0, &block.terminator, is_cancelled)?;
    }
    sort_edges(&mut edges, is_cancelled)?;
    for (index, pair) in edges.windows(2).enumerate() {
        check_periodically(index, is_cancelled)?;
        if let [left, right] = pair {
            if left.target == right.target
                && left.predecessor == right.predecessor
                && !value_slices_equal(left.arguments, right.arguments, is_cancelled)?
            {
                return Err(CodegenError::UnsupportedMachineContract(
                    "conflicting parallel CFG edges require edge splitting",
                ));
            }
        }
    }
    let mut incoming = fallible_filled(
        function.blocks.len(),
        request.options.maximum_blocks,
        "CFG incoming-block entries",
        0u8,
        is_cancelled,
    )?;
    for (index, edge) in edges.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        let slot = incoming.get_mut(edge.target as usize).ok_or(
            CodegenError::UnsupportedMachineContract("a CFG edge to an unknown block"),
        )?;
        *slot = 1;
    }
    if incoming.get(function.entry.0 as usize) == Some(&1) {
        return Err(CodegenError::UnsupportedMachineContract(
            "a predecessor edge into the LLVM entry block",
        ));
    }
    for (index, block) in function.blocks.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        if !block.parameters.is_empty() && incoming.get(block.id.0 as usize) != Some(&1) {
            return Err(CodegenError::UnsupportedMachineContract(
                "a parameterized block without predecessors",
            ));
        }
    }
    Ok(())
}

fn value_slices_equal(
    left: &[ValueId],
    right: &[ValueId],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, CodegenError> {
    if left.len() != right.len() {
        return Ok(false);
    }
    for (index, (left, right)) in left.iter().zip(right).enumerate() {
        check_periodically(index, is_cancelled)?;
        if left != right {
            return Ok(false);
        }
    }
    check_cancelled(is_cancelled)?;
    Ok(true)
}

fn push_edges<'a>(
    edges: &mut Vec<IncomingEdge<'a>>,
    predecessor: u32,
    terminator: &'a MachineTerminator,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    match terminator {
        MachineTerminator::Jump { block, arguments } => edges.push(IncomingEdge {
            target: block.0,
            predecessor,
            arguments,
        }),
        MachineTerminator::Branch {
            then_block,
            then_arguments,
            else_block,
            else_arguments,
            ..
        } => {
            edges.push(IncomingEdge {
                target: then_block.0,
                predecessor,
                arguments: then_arguments,
            });
            edges.push(IncomingEdge {
                target: else_block.0,
                predecessor,
                arguments: else_arguments,
            });
        }
        MachineTerminator::Switch {
            cases,
            default,
            default_arguments,
            ..
        } => {
            for (index, (_, target, arguments)) in cases.iter().enumerate() {
                check_periodically(index, is_cancelled)?;
                edges.push(IncomingEdge {
                    target: target.0,
                    predecessor,
                    arguments,
                });
            }
            edges.push(IncomingEdge {
                target: default.0,
                predecessor,
                arguments: default_arguments,
            });
        }
        MachineTerminator::Return(_)
        | MachineTerminator::TailCall { .. }
        | MachineTerminator::Unreachable => {}
    }
    Ok(())
}

fn sort_edges(
    edges: &mut [IncomingEdge<'_>],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    crate::cancellable_sort_by(
        edges,
        |left, right| Ok((left.target, left.predecessor).cmp(&(right.target, right.predecessor))),
        is_cancelled,
    )
}

fn validate_image_entry(
    request: &CodegenRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let machine = request.module.as_wir();
    let entry = machine
        .functions
        .get(machine.image_entry.0 as usize)
        .ok_or(CodegenError::UnsupportedMachineContract(
            "missing image entry",
        ))?;
    let symbol = machine.symbols.get(entry.symbol.0 as usize);
    let parameters_are_pointers = entry.parameters.len() == 2
        && entry.parameters.iter().all(|value| {
            value_type(machine, entry, *value).is_some_and(|ty| {
                machine.types.get(ty.0 as usize).is_some_and(|ty| {
                    matches!(
                        ty.kind,
                        MachineTypeKind::Pointer {
                            address_space: 0,
                            ..
                        }
                    )
                })
            })
        });
    let result_is_status = machine
        .types
        .get(entry.result.0 as usize)
        .is_some_and(|ty| matches!(ty.kind, MachineTypeKind::Integer { bits: 64 }));
    let Some(symbol) = symbol else {
        return Err(CodegenError::UnsupportedMachineContract(
            "noncanonical UEFI AArch64 entry signature",
        ));
    };
    if !parameters_are_pointers
        || !result_is_status
        || !crate::cancellable_text_equal(
            &symbol.name,
            request.target.entry_symbol(),
            is_cancelled,
        )?
        || symbol.visibility != SymbolVisibility::ImageEntry
    {
        return Err(CodegenError::UnsupportedMachineContract(
            "noncanonical UEFI AArch64 entry signature",
        ));
    }
    Ok(())
}

fn text_slices_equal(
    left: &[String],
    right: &[String],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, CodegenError> {
    if left.len() != right.len() {
        return Ok(false);
    }
    for (left, right) in left.iter().zip(right) {
        check_cancelled(is_cancelled)?;
        if !crate::cancellable_text_equal(left, right, is_cancelled)? {
            return Ok(false);
        }
    }
    check_cancelled(is_cancelled)?;
    Ok(true)
}

fn supported_scalar_type(kind: &MachineTypeKind, size: u64, alignment: u32) -> bool {
    match kind {
        MachineTypeKind::Void => size == 0 && alignment == 1,
        MachineTypeKind::Integer {
            bits: 8 | 16 | 32 | 64 | 128,
        } => {
            size == u64::from(match kind {
                MachineTypeKind::Integer { bits } => bits / 8,
                _ => 0,
            }) && alignment == u32::try_from(size.min(16)).unwrap_or(0)
        }
        MachineTypeKind::Float32 => size == 4 && alignment == 4,
        MachineTypeKind::Float64 => size == 8 && alignment == 8,
        MachineTypeKind::Pointer {
            address_space: 0, ..
        } => size == 8 && alignment == 8,
        MachineTypeKind::Integer { .. }
        | MachineTypeKind::Pointer { .. }
        | MachineTypeKind::Vector { .. }
        | MachineTypeKind::Array { .. }
        | MachineTypeKind::Struct { .. }
        | MachineTypeKind::TaggedEnum { .. }
        | MachineTypeKind::Function { .. } => false,
    }
}

fn supported_static_byte_array(machine: &wrela_machine_wir::MachineWir, ty: MachineTypeId) -> bool {
    let Some(ty) = machine.types.get(ty.0 as usize) else {
        return false;
    };
    let MachineTypeKind::Array { element, length } = ty.kind else {
        return false;
    };
    machine
        .types
        .get(element.0 as usize)
        .is_some_and(|element| {
            matches!(element.kind, MachineTypeKind::Integer { bits: 8 })
                && element.size == 1
                && element.alignment == 1
        })
        && ty.size == length
        && ty.alignment.is_power_of_two()
        && ty.alignment <= machine.layout.maximum_object_alignment
        && ty.size % u64::from(ty.alignment) == 0
}

fn supported_enum_type(machine: &wrela_machine_wir::MachineWir, id: MachineTypeId) -> bool {
    let Some(ty) = machine.types.get(id.0 as usize) else {
        return false;
    };
    let MachineTypeKind::TaggedEnum {
        tag,
        payload,
        variants,
        payload_variants,
    } = &ty.kind
    else {
        return false;
    };
    let Some(tag_ty) = machine.types.get(tag.0 as usize) else {
        return false;
    };
    let common = *variants != 0
        && *variants <= 256
        && usize::from(*variants) == payload_variants.len()
        && tag_ty.kind == MachineTypeKind::Integer { bits: 8 }
        && tag_ty.size == 1
        && tag_ty.alignment == 1;
    if !common {
        return false;
    }
    if payload_variants.iter().any(|present| *present) {
        let Some(payload_ty) = payload.and_then(|payload| machine.types.get(payload.0 as usize))
        else {
            return false;
        };
        let alignment = payload_ty.alignment.max(1);
        let payload_offset = (1_u64 + u64::from(alignment) - 1) & !(u64::from(alignment) - 1);
        let size = payload_offset
            .checked_add(payload_ty.size)
            .map(|size| (size + u64::from(alignment) - 1) & !(u64::from(alignment) - 1));
        !matches!(payload_ty.kind, MachineTypeKind::Void)
            && supported_scalar_type(&payload_ty.kind, payload_ty.size, payload_ty.alignment)
            && ty.alignment == alignment
            && size == Some(ty.size)
    } else {
        payload.is_none() && ty.size == 1 && ty.alignment == 1
    }
}

fn supported_struct_type(machine: &wrela_machine_wir::MachineWir, id: MachineTypeId) -> bool {
    supported_struct_layout(&machine.types, id)
}

fn supported_struct_layout(types: &[wrela_machine_wir::MachineType], id: MachineTypeId) -> bool {
    let Some(ty) = types.get(id.0 as usize) else {
        return false;
    };
    let MachineTypeKind::Struct {
        fields,
        packed: false,
    } = &ty.kind
    else {
        return false;
    };
    if fields.is_empty() {
        return false;
    }
    let mut end = 0_u64;
    let mut alignment = 1_u32;
    for field in fields {
        let Some(field_ty) = types.get(field.ty.0 as usize) else {
            return false;
        };
        let field_alignment = u64::from(field_ty.alignment);
        let Some(expected_offset) = end
            .checked_add(field_alignment - 1)
            .map(|offset| offset & !(field_alignment - 1))
        else {
            return false;
        };
        if !supported_scalar_type(&field_ty.kind, field_ty.size, field_ty.alignment)
            || matches!(field_ty.kind, MachineTypeKind::Void)
            || field.offset != expected_offset
        {
            return false;
        }
        let Some(next) = field.offset.checked_add(field_ty.size) else {
            return false;
        };
        end = next;
        alignment = alignment.max(field_ty.alignment);
    }
    let aggregate_alignment = u64::from(alignment);
    let expected_size = end
        .checked_add(aggregate_alignment - 1)
        .map(|size| size & !(aggregate_alignment - 1));
    ty.alignment == alignment && expected_size == Some(ty.size)
}

fn authenticated_cleanup_boundary_state(
    machine: &wrela_machine_wir::MachineWir,
    function: &MachineFunction,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Option<MachineTypeId>, CodegenError> {
    if let Some(state) = authenticated_generated_cleanup_state(machine, function)? {
        return Ok(Some(state));
    }
    let MachineFunctionOrigin::SourceSemantic { semantic_function } = function.origin else {
        return Ok(None);
    };
    if semantic_function != function.flow_function || function.role != MachineFunctionRole::Cleanup
    {
        return Ok(None);
    }
    let mut state = None;
    for (index, candidate) in machine.functions.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        if !matches!(candidate.origin,
            MachineFunctionOrigin::GeneratedCleanup {
                semantic_function: helper,
                ..
            } if helper == semantic_function)
        {
            continue;
        }
        let candidate_state = authenticated_generated_cleanup_state(machine, candidate)?.ok_or(
            CodegenError::UnsupportedMachineContract("unauthenticated generated cleanup function"),
        )?;
        if state.is_some_and(|previous| previous != candidate_state) {
            return Err(CodegenError::UnsupportedMachineContract(
                "unauthenticated generated cleanup function",
            ));
        }
        state = Some(candidate_state);
    }
    Ok(state)
}

fn authenticated_generated_cleanup_state(
    machine: &wrela_machine_wir::MachineWir,
    function: &MachineFunction,
) -> Result<Option<MachineTypeId>, CodegenError> {
    let MachineFunctionOrigin::GeneratedCleanup {
        semantic_function,
        scope,
    } = function.origin
    else {
        return Ok(None);
    };
    let generated_count = machine
        .functions
        .iter()
        .filter(|candidate| {
            matches!(
                candidate.origin,
                MachineFunctionOrigin::GeneratedCleanup { .. }
            )
        })
        .count();
    let first_generated = machine.functions.len().checked_sub(generated_count);
    let expected_id = first_generated
        .and_then(|first| first.checked_add(scope as usize))
        .and_then(|id| u32::try_from(id).ok());
    let helper = machine.functions.get(semantic_function as usize);
    let parameter_type = |candidate: &MachineFunction| {
        let [parameter] = candidate.parameters.as_slice() else {
            return None;
        };
        candidate
            .values
            .get(parameter.0 as usize)
            .map(|value| value.ty)
    };
    let Some(helper) = helper else {
        return Err(CodegenError::UnsupportedMachineContract(
            "unauthenticated generated cleanup function",
        ));
    };
    let state = parameter_type(function);
    let helper_state = parameter_type(helper);
    let proof_matches = matches!(helper.proofs.as_slice(), [helper_proof]
    if matches!(function.proofs.as_slice(), [generated_helper, cleanup]
        if generated_helper == helper_proof
            && machine.proofs.get(helper_proof.0 as usize).is_some_and(|proof| {
                proof.id == *helper_proof
                    && proof.kind == wrela_machine_wir::BackendProofKind::CleanupAcyclic
                    && proof.bound == Some(0)
            })
            && machine.proofs.get(cleanup.0 as usize).is_some_and(|proof| {
                proof.id == *cleanup
                    && proof.kind == wrela_machine_wir::BackendProofKind::CleanupAcyclic
                    && proof.depends_on.as_slice() == [*helper_proof]
            })));
    let helper_identity = matches!(helper.origin,
        MachineFunctionOrigin::SourceSemantic { semantic_function: helper_semantic }
            if helper_semantic == semantic_function && helper.flow_function == semantic_function);
    let state_is_supported = state.is_some_and(|ty| supported_struct_type(machine, ty));
    let void_result = |candidate: &MachineFunction| {
        machine
            .types
            .get(candidate.result.0 as usize)
            .is_some_and(|ty| matches!(ty.kind, MachineTypeKind::Void))
    };
    if first_generated.is_none_or(|first| semantic_function as usize >= first)
        || expected_id != Some(function.id.0)
        || function.flow_function != function.id.0
        || function.role != MachineFunctionRole::Cleanup
        || helper.role != MachineFunctionRole::Cleanup
        || function.linkage != Linkage::Private
        || helper.linkage != Linkage::Private
        || function.convention != CallingConvention::Internal
        || helper.convention != CallingConvention::Internal
        || !void_result(function)
        || !void_result(helper)
        || function.stack_bytes != 0
        || helper.stack_bytes != 0
        || !function.stack_slots.is_empty()
        || !helper.stack_slots.is_empty()
        || function.source != helper.source
        || function.values != helper.values
        || function.blocks != helper.blocks
        || state.is_none()
        || state != helper_state
        || !state_is_supported
        || !helper_identity
        || !proof_matches
    {
        return Err(CodegenError::UnsupportedMachineContract(
            "unauthenticated generated cleanup function",
        ));
    }
    Ok(state)
}

fn authenticated_generated_cleanup_call(
    machine: &wrela_machine_wir::MachineWir,
    caller: &MachineFunction,
    instruction: &wrela_machine_wir::MachineInstruction,
    callee: wrela_machine_wir::FunctionId,
    arguments: &[ValueId],
) -> bool {
    let Some(callee) = machine.functions.get(callee.0 as usize) else {
        return false;
    };
    let Ok(Some(state)) = authenticated_generated_cleanup_state(machine, callee) else {
        return false;
    };
    let activation_proof = callee
        .proofs
        .get(1)
        .and_then(|proof| machine.proofs.get(proof.0 as usize));
    instruction.results.is_empty()
        && matches!(arguments, [argument]
            if value_type(machine, caller, *argument) == Some(state))
        && instruction.source.is_some_and(|source| {
            activation_proof.is_some_and(|proof| proof.sources.contains(&source))
        })
}

fn supported_passive_function_type(
    machine: &wrela_machine_wir::MachineWir,
    ty: MachineTypeId,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, CodegenError> {
    let Some(ty) = machine.types.get(ty.0 as usize) else {
        return Ok(false);
    };
    let MachineTypeKind::Function { parameters, result } = &ty.kind else {
        return Ok(false);
    };
    if ty.size != 0
        || ty.alignment != 1
        || (!is_return_type(machine, *result) && !supported_struct_type(machine, *result))
    {
        return Ok(false);
    }
    for (index, parameter) in parameters.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        if !is_basic_scalar(machine, *parameter) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn is_function_type(machine: &wrela_machine_wir::MachineWir, ty: MachineTypeId) -> bool {
    machine
        .types
        .get(ty.0 as usize)
        .is_some_and(|ty| matches!(ty.kind, MachineTypeKind::Function { .. }))
}

fn legal_conversion(
    machine: &wrela_machine_wir::MachineWir,
    operation: ConversionOp,
    source: MachineTypeId,
    destination: MachineTypeId,
) -> bool {
    let Some(source_ty) = machine.types.get(source.0 as usize) else {
        return false;
    };
    let Some(destination_ty) = machine.types.get(destination.0 as usize) else {
        return false;
    };
    let integer_bits = |ty: &wrela_machine_wir::MachineType| match ty.kind {
        MachineTypeKind::Integer { bits } => Some(bits),
        _ => None,
    };
    match operation {
        ConversionOp::ZeroExtend | ConversionOp::SignExtend => integer_bits(source_ty)
            .zip(integer_bits(destination_ty))
            .is_some_and(|(source, destination)| destination > source),
        ConversionOp::FloatExtend => {
            matches!(source_ty.kind, MachineTypeKind::Float32)
                && matches!(destination_ty.kind, MachineTypeKind::Float64)
        }
        ConversionOp::UnsignedIntegerToFloat => integer_bits(source_ty).is_some_and(|bits| {
            matches!(destination_ty.kind, MachineTypeKind::Float32) && bits <= 24
                || matches!(destination_ty.kind, MachineTypeKind::Float64) && bits <= 53
        }),
        ConversionOp::SignedIntegerToFloat => integer_bits(source_ty).is_some_and(|bits| {
            matches!(destination_ty.kind, MachineTypeKind::Float32) && bits <= 25
                || matches!(destination_ty.kind, MachineTypeKind::Float64) && bits <= 54
        }),
        ConversionOp::Bitcast => legal_bitcast(machine, source, destination),
        ConversionOp::IntegerTruncate
        | ConversionOp::FloatTruncate
        | ConversionOp::FloatToUnsignedInteger
        | ConversionOp::FloatToSignedInteger
        | ConversionOp::PointerToInteger
        | ConversionOp::IntegerToPointer => false,
    }
}

fn legal_bitcast(
    machine: &wrela_machine_wir::MachineWir,
    source: MachineTypeId,
    destination: MachineTypeId,
) -> bool {
    let Some(source) = machine.types.get(source.0 as usize) else {
        return false;
    };
    let Some(destination) = machine.types.get(destination.0 as usize) else {
        return false;
    };
    if source.size != destination.size || source.size == 0 {
        return false;
    }
    match (&source.kind, &destination.kind) {
        (
            MachineTypeKind::Integer { bits: source },
            MachineTypeKind::Integer { bits: destination },
        ) => source == destination,
        (MachineTypeKind::Integer { bits: 32 }, MachineTypeKind::Float32)
        | (MachineTypeKind::Float32, MachineTypeKind::Integer { bits: 32 })
        | (MachineTypeKind::Float32, MachineTypeKind::Float32)
        | (MachineTypeKind::Integer { bits: 64 }, MachineTypeKind::Float64)
        | (MachineTypeKind::Float64, MachineTypeKind::Integer { bits: 64 })
        | (MachineTypeKind::Float64, MachineTypeKind::Float64)
        | (MachineTypeKind::Pointer { .. }, MachineTypeKind::Pointer { .. }) => true,
        _ => false,
    }
}

fn is_basic_scalar(machine: &wrela_machine_wir::MachineWir, ty: MachineTypeId) -> bool {
    machine.types.get(ty.0 as usize).is_some_and(|ty| {
        !matches!(ty.kind, MachineTypeKind::Void)
            && supported_scalar_type(&ty.kind, ty.size, ty.alignment)
    }) || supported_enum_type(machine, ty)
}

fn is_return_type(machine: &wrela_machine_wir::MachineWir, ty: MachineTypeId) -> bool {
    machine
        .types
        .get(ty.0 as usize)
        .is_some_and(|ty| supported_scalar_type(&ty.kind, ty.size, ty.alignment))
        || supported_enum_type(machine, ty)
}

fn value_type(
    _machine: &wrela_machine_wir::MachineWir,
    function: &MachineFunction,
    value: ValueId,
) -> Option<MachineTypeId> {
    function.values.get(value.0 as usize).map(|value| value.ty)
}

fn valid_symbol_name(name: &str, is_cancelled: &dyn Fn() -> bool) -> Result<bool, CodegenError> {
    valid_name(name, false, is_cancelled)
}

fn valid_section_name(name: &str, is_cancelled: &dyn Fn() -> bool) -> Result<bool, CodegenError> {
    Ok(name.starts_with(".text") && valid_name(name, true, is_cancelled)?)
}

fn valid_data_or_code_section_name(
    section: &Section,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, CodegenError> {
    let valid = match section.kind {
        SectionKind::Code => valid_section_name(&section.name, is_cancelled)?,
        SectionKind::ReadOnlyData => {
            section.name.starts_with(".rdata") && valid_name(&section.name, true, is_cancelled)?
        }
        SectionKind::RuntimeMetadata => {
            section.name == INTERRUPT_ROUTE_SECTION
                && valid_name(&section.name, true, is_cancelled)?
        }
        SectionKind::WritableData => {
            (section.name == ".data" || section.name.starts_with(REGION_STORAGE_SECTION_PREFIX))
                && valid_name(&section.name, true, is_cancelled)?
        }
        SectionKind::ZeroFill => {
            section.name == ".bss" && valid_name(&section.name, true, is_cancelled)?
        }
        SectionKind::Relocations | SectionKind::Debug => false,
    };
    Ok(valid)
}

fn valid_name(
    name: &str,
    allow_leading_dot: bool,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, CodegenError> {
    let mut bytes = name.bytes();
    let Some(first) = bytes.next() else {
        return Ok(false);
    };
    let valid_first = first.is_ascii_alphabetic()
        || first == b'_'
        || first == b'$'
        || (allow_leading_dot && first == b'.');
    if !valid_first {
        return Ok(false);
    }
    for (index, byte) in bytes.enumerate() {
        check_periodically(index, is_cancelled)?;
        if !byte.is_ascii_alphanumeric() && !matches!(byte, b'_' | b'$' | b'.' | b'@' | b'?' | b'-')
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn operation_edges(operation: &MachineOperation) -> usize {
    match operation {
        MachineOperation::Immediate(_)
        | MachineOperation::StackAddress(_)
        | MachineOperation::GlobalAddress(_)
        | MachineOperation::ActorReserve { .. }
        | MachineOperation::ActorReplyRequest { .. }
        | MachineOperation::MailboxReceive { .. }
        | MachineOperation::MailboxDispatch { .. }
        | MachineOperation::Fence(_) => 0,
        MachineOperation::Unary { .. }
        | MachineOperation::Convert { .. }
        | MachineOperation::CheckedConvert { .. }
        | MachineOperation::Copy { .. }
        | MachineOperation::MakeEnum { .. }
        | MachineOperation::EnumTag { .. }
        | MachineOperation::EnumPayload { .. }
        | MachineOperation::ExtractField { .. }
        | MachineOperation::TestAssert { .. } => 1,
        MachineOperation::ActorReplyResolve { .. } => 1,
        MachineOperation::MakeStruct { fields, .. } => fields.len(),
        MachineOperation::InsertField { .. } => 2,
        MachineOperation::ActorCommit { .. } => 1,
        MachineOperation::Arithmetic { .. }
        | MachineOperation::CheckedInteger { .. }
        | MachineOperation::IntegerCompare { .. }
        | MachineOperation::FloatCompare { .. }
        | MachineOperation::AddressOffset { .. }
        | MachineOperation::Load { .. } => 2,
        MachineOperation::Select { .. } => 3,
        MachineOperation::Store { .. } => 3,
        MachineOperation::MemoryCopy { .. } => 4,
        MachineOperation::MemorySet { .. } => 3,
        MachineOperation::Call { arguments, .. }
        | MachineOperation::RuntimeCall { arguments, .. } => arguments.len().saturating_add(1),
    }
}

fn terminator_edges(
    terminator: &MachineTerminator,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<usize, CodegenError> {
    let edges = match terminator {
        MachineTerminator::Jump { arguments, .. } => arguments.len().saturating_add(1),
        MachineTerminator::Branch {
            then_arguments,
            else_arguments,
            ..
        } => then_arguments
            .len()
            .saturating_add(else_arguments.len())
            .saturating_add(3),
        MachineTerminator::Switch {
            cases,
            default_arguments,
            ..
        } => {
            let mut total = default_arguments.len().saturating_add(2);
            for (index, (_, _, arguments)) in cases.iter().enumerate() {
                check_periodically(index, is_cancelled)?;
                total = total.saturating_add(arguments.len()).saturating_add(1);
            }
            total
        }
        MachineTerminator::Return(values) => values.len(),
        MachineTerminator::TailCall { arguments, .. } => arguments.len().saturating_add(1),
        MachineTerminator::Unreachable => 0,
    };
    Ok(edges)
}

fn successor_count(terminator: &MachineTerminator) -> usize {
    match terminator {
        MachineTerminator::Jump { .. } => 1,
        MachineTerminator::Branch { .. } => 2,
        MachineTerminator::Switch { cases, .. } => cases.len().saturating_add(1),
        MachineTerminator::Return(_)
        | MachineTerminator::TailCall { .. }
        | MachineTerminator::Unreachable => 0,
    }
}

fn checked_add(total: u64, amount: usize, resource: &'static str) -> Result<u64, CodegenError> {
    total
        .checked_add(u64::try_from(amount).unwrap_or(u64::MAX))
        .ok_or(CodegenError::ResourceLimit {
            resource,
            limit: u64::MAX,
            actual: u64::MAX,
        })
}

fn add_text(total: &mut u64, value: Option<&str>) -> Result<(), CodegenError> {
    if let Some(value) = value {
        *total = total
            .checked_add(u64::try_from(value.len()).unwrap_or(u64::MAX))
            .ok_or(CodegenError::ResourceLimit {
                resource: "measurement bytes",
                limit: u64::MAX,
                actual: u64::MAX,
            })?;
    }
    Ok(())
}

fn require_limit(
    resource: &'static str,
    actual: impl TryInto<u64>,
    limit: u64,
) -> Result<(), CodegenError> {
    let actual = actual.try_into().unwrap_or(u64::MAX);
    if actual > limit {
        Err(CodegenError::ResourceLimit {
            resource,
            limit,
            actual,
        })
    } else {
        Ok(())
    }
}

fn fallible_filled<T: Clone>(
    length: usize,
    limit: u64,
    resource: &'static str,
    value: T,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<T>, CodegenError> {
    let actual = u64::try_from(length).unwrap_or(u64::MAX);
    if actual > limit {
        return Err(CodegenError::ResourceLimit {
            resource,
            limit,
            actual,
        });
    }
    check_cancelled(is_cancelled)?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| CodegenError::ResourceLimit {
            resource,
            limit,
            actual,
        })?;
    check_cancelled(is_cancelled)?;
    for _ in 0..length {
        check_cancelled(is_cancelled)?;
        output.push(value.clone());
    }
    check_cancelled(is_cancelled)?;
    Ok(output)
}

fn contains_byte(
    bytes: &[u8],
    needle: u8,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, CodegenError> {
    for (index, byte) in bytes.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        if *byte == needle {
            return Ok(true);
        }
    }
    Ok(false)
}

fn contains_non_whitespace(
    text: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, CodegenError> {
    for (index, character) in text.chars().enumerate() {
        check_periodically(index, is_cancelled)?;
        if !character.is_whitespace() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn check_periodically(index: usize, is_cancelled: &dyn Fn() -> bool) -> Result<(), CodegenError> {
    if index % 1_024 == 0 {
        check_cancelled(is_cancelled)?;
    }
    Ok(())
}

fn check_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), CodegenError> {
    if is_cancelled() {
        Err(CodegenError::Cancelled)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod adversarial_tests {
    use std::cell::Cell;

    use super::{
        CodegenError, IncomingEdge, contains_non_whitespace, fallible_filled, poll_values,
        sort_edges, supported_struct_layout, terminator_edges, text_slices_equal, valid_name,
        validate_scalar_value_types, value_slices_equal,
    };
    use wrela_machine_wir::{
        BlockId, MachineField, MachineTerminator, MachineType, MachineTypeId, MachineTypeKind,
        MachineValue, ValueId,
    };

    #[test]
    fn unpacked_struct_layout_rejects_a_crafted_aligned_gap() {
        let scalar = MachineType {
            id: MachineTypeId(0),
            kind: MachineTypeKind::Integer { bits: 8 },
            size: 1,
            alignment: 1,
            source_name: None,
        };
        let natural = MachineType {
            id: MachineTypeId(1),
            kind: MachineTypeKind::Struct {
                fields: vec![
                    MachineField {
                        ty: MachineTypeId(0),
                        offset: 0,
                    },
                    MachineField {
                        ty: MachineTypeId(0),
                        offset: 1,
                    },
                ],
                packed: false,
            },
            size: 2,
            alignment: 1,
            source_name: None,
        };
        assert!(supported_struct_layout(
            &[scalar.clone(), natural.clone()],
            MachineTypeId(1)
        ));

        let mut gapped = natural;
        let MachineTypeKind::Struct { fields, .. } = &mut gapped.kind else {
            panic!("fixture struct type")
        };
        fields[1].offset = 7;
        gapped.size = 8;
        assert!(!supported_struct_layout(
            &[scalar, gapped],
            MachineTypeId(1)
        ));
    }

    #[test]
    fn scratch_tables_reject_limits_before_allocation() {
        assert_eq!(
            fallible_filled(2, 1, "adversarial entries", 0u8, &|| false),
            Err(CodegenError::ResourceLimit {
                resource: "adversarial entries",
                limit: 1,
                actual: 2,
            })
        );

        assert_eq!(
            fallible_filled(4_096, 4_096, "adversarial entries", 0u8, &|| true),
            Err(CodegenError::Cancelled),
            "cancellation must win before scratch allocation"
        );

        let polls = Cell::new(0usize);
        assert_eq!(
            fallible_filled(4_096, 4_096, "adversarial entries", 0u8, &|| {
                let next = polls.get() + 1;
                polls.set(next);
                next == 100
            }),
            Err(CodegenError::Cancelled)
        );
        assert_eq!(polls.get(), 100);
    }

    #[test]
    fn long_model_name_scans_are_cancellable() {
        let name = format!("a{}", "b".repeat(2_048));
        assert_eq!(
            valid_name(&name, false, &|| true),
            Err(CodegenError::Cancelled)
        );
    }

    #[test]
    fn long_target_fields_and_features_cancel_inside_equal_prefixes() {
        let field = "x".repeat(3_072);
        let field_polls = Cell::new(0usize);
        assert_eq!(
            crate::cancellable_text_equal(&field, &field, &|| {
                let next = field_polls.get() + 1;
                field_polls.set(next);
                next == 2
            }),
            Err(CodegenError::Cancelled)
        );
        assert_eq!(field_polls.get(), 2);

        let features = vec![field];
        let feature_polls = Cell::new(0usize);
        assert_eq!(
            text_slices_equal(&features, &features, &|| {
                let next = feature_polls.get() + 1;
                feature_polls.set(next);
                next == 3
            }),
            Err(CodegenError::Cancelled)
        );
        assert_eq!(feature_polls.get(), 3);
    }

    #[test]
    fn proof_whitespace_check_preserves_unicode_semantics() {
        assert_eq!(contains_non_whitespace("\u{2003}\n", &|| false), Ok(false));
        assert_eq!(
            contains_non_whitespace("\u{2003}proof", &|| false),
            Ok(true)
        );
    }

    #[test]
    fn cfg_sort_observes_cancellation() {
        let mut edges = [
            IncomingEdge {
                target: 1,
                predecessor: 1,
                arguments: &[],
            },
            IncomingEdge {
                target: 0,
                predecessor: 0,
                arguments: &[],
            },
        ];
        assert_eq!(
            sort_edges(&mut edges, &|| true),
            Err(CodegenError::Cancelled)
        );
    }

    #[test]
    fn parameter_and_switch_scans_cancel_before_their_final_boundary() {
        let values = vec![ValueId(0); 2_049];
        let parameter_polls = Cell::new(0usize);
        assert_eq!(
            poll_values(&values, &|| {
                let next = parameter_polls.get() + 1;
                parameter_polls.set(next);
                next == 2
            }),
            Err(CodegenError::Cancelled)
        );
        assert_eq!(parameter_polls.get(), 2);

        let cases = (0..2_049)
            .map(|value| (value, BlockId(0), Vec::new()))
            .collect();
        let terminator = MachineTerminator::Switch {
            value: ValueId(0),
            cases,
            default: BlockId(0),
            default_arguments: Vec::new(),
        };
        let switch_polls = Cell::new(0usize);
        assert_eq!(
            terminator_edges(&terminator, &|| {
                let next = switch_polls.get() + 1;
                switch_polls.set(next);
                next == 2
            }),
            Err(CodegenError::Cancelled)
        );
        assert_eq!(switch_polls.get(), 2);

        let parallel_arguments = vec![ValueId(7); 2_049];
        let equality_polls = Cell::new(0usize);
        assert_eq!(
            value_slices_equal(&parallel_arguments, &parallel_arguments, &|| {
                let next = equality_polls.get() + 1;
                equality_polls.set(next);
                next == 2
            }),
            Err(CodegenError::Cancelled)
        );
        assert_eq!(equality_polls.get(), 2);
    }

    #[test]
    fn raw_consumer_validation_rejects_void_typed_ssa_values() {
        let types = [MachineType {
            id: MachineTypeId(0),
            kind: MachineTypeKind::Void,
            size: 0,
            alignment: 1,
            source_name: None,
        }];
        let values = [MachineValue {
            id: ValueId(0),
            ty: MachineTypeId(0),
            source_name: None,
        }];
        assert_eq!(
            validate_scalar_value_types(&types, &values, &|| false),
            Err(CodegenError::UnsupportedMachineContract(
                "void-typed MachineWir SSA values or block parameters",
            ))
        );
    }
}
