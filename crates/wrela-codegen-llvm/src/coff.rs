use wrela_machine_wir::{
    MachineOperation, MachineTerminator, MachineWir, SectionKind, SymbolDefinition,
    SymbolVisibility, ValidatedMachineWir,
};
use wrela_runtime_abi::{ALL_RUNTIME_INTRINSICS, RUNTIME_INTRINSIC_COUNT, RuntimeIntrinsic};

use crate::{CodegenError, CodegenOptions, EmittedSection, EmittedSymbol};

const COFF_HEADER_BYTES: usize = 20;
const COFF_SECTION_BYTES: usize = 40;
const COFF_SYMBOL_BYTES: usize = 18;
const COFF_RELOCATION_BYTES: usize = 10;
const IMAGE_FILE_MACHINE_ARM64: u16 = 0xaa64;
const IMAGE_SCN_ALIGN_MASK: u32 = 0x00f0_0000;
const IMAGE_SCN_LNK_NRELOC_OVFL: u32 = 0x0100_0000;
const CODE_CHARACTERISTICS: u32 = 0x6000_0020;
const INITIALIZED_DATA_CHARACTERISTICS: u32 = 0x4000_0040;
const WRITABLE_DATA_CHARACTERISTICS: u32 = 0xc000_0040;
const ZERO_FILL_CHARACTERISTICS: u32 = 0xc000_0080;
const UNWIND_CHARACTERISTICS: u32 = 0x4000_0040;
const IMAGE_REL_ARM64_ADDR32NB: u16 = 0x0002;
const IMAGE_REL_ARM64_BRANCH26: u16 = 0x0003;

#[derive(Debug)]
struct PhysicalSection {
    name: String,
    file_offset: u64,
    /// Addressable extent encoded in the COFF section header. For ordinary
    /// initialized sections this also equals the raw extent; for `.bss` it is
    /// represented only by the section-definition auxiliary record.
    file_bytes: u64,
    /// Bytes physically present in the object. Canonical zero-fill sections
    /// retain `file_bytes` but have no raw payload.
    raw_file_bytes: u64,
    alignment: u32,
    characteristics: u32,
    relocation_offset: usize,
    relocation_count: usize,
    declared: Option<usize>,
}

#[derive(Debug, Clone, Copy)]
enum CoffSymbol {
    Defined {
        section: usize,
        offset: u64,
        function_bytes: Option<u64>,
    },
    ExternalRuntime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum InternalBranchKind {
    Call,
    TailCall,
}

#[derive(Debug, Clone, Copy)]
struct InternalRelocationCell {
    section: usize,
    callee: u32,
    kind: InternalBranchKind,
    required: u32,
    observed: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuntimeRelocationEmission {
    intrinsic: RuntimeIntrinsic,
    directly_required: bool,
}

impl InternalRelocationCell {
    fn key(self) -> (usize, u32, InternalBranchKind) {
        (self.section, self.callee, self.kind)
    }
}

pub(super) fn measure_object(
    bytes: &[u8],
    module: &ValidatedMachineWir,
    options: CodegenOptions,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(Vec<EmittedSection>, Vec<EmittedSymbol>), CodegenError> {
    check_cancelled(is_cancelled)?;
    let object_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if object_bytes > options.maximum_object_bytes {
        return Err(CodegenError::ObjectTooLarge {
            limit: options.maximum_object_bytes,
            actual: object_bytes,
        });
    }
    let machine = module.as_wir();
    if bytes.len() < COFF_HEADER_BYTES || read_u16(bytes, 0)? != IMAGE_FILE_MACHINE_ARM64 {
        return invalid("object is not ordinary ARM64 COFF");
    }
    if read_u32(bytes, 4)? != 0 || read_u16(bytes, 16)? != 0 || read_u16(bytes, 18)? != 0 {
        return invalid("COFF header is timestamped, optional, or noncanonical");
    }
    let section_count = usize::from(read_u16(bytes, 2)?);
    let raw_symbol_count = usize::try_from(read_u32(bytes, 12)?)
        .map_err(|_| invalid_error("COFF symbol count does not fit the host"))?;
    if section_count < machine.sections.len() {
        return invalid("COFF has fewer physical sections than MachineWir declares");
    }
    if section_count > options.maximum_sections as usize {
        return invalid("COFF physical section count exceeds the codegen limit");
    }
    if raw_symbol_count == 0 {
        return invalid("COFF symbol table is empty");
    }
    if raw_symbol_count > options.maximum_symbols as usize {
        return invalid("COFF raw symbol count exceeds the codegen limit");
    }
    let section_table_bytes = section_count
        .checked_mul(COFF_SECTION_BYTES)
        .ok_or_else(|| invalid_error("COFF section table overflows"))?;
    let section_table_end = COFF_HEADER_BYTES
        .checked_add(section_table_bytes)
        .ok_or_else(|| invalid_error("COFF section table overflows"))?;
    require_range(bytes, COFF_HEADER_BYTES, section_table_bytes)?;

    let symbol_table_offset = usize::try_from(read_u32(bytes, 8)?)
        .map_err(|_| invalid_error("COFF symbol table offset does not fit the host"))?;
    let symbol_table_bytes = raw_symbol_count
        .checked_mul(COFF_SYMBOL_BYTES)
        .ok_or_else(|| invalid_error("COFF symbol table overflows"))?;
    let symbol_table_end = symbol_table_offset
        .checked_add(symbol_table_bytes)
        .ok_or_else(|| invalid_error("COFF symbol table overflows"))?;
    if symbol_table_offset < section_table_end {
        return invalid("COFF symbol table overlaps its header");
    }
    require_range(bytes, symbol_table_offset, symbol_table_bytes)?;
    let string_table_bytes = usize::try_from(read_u32(bytes, symbol_table_end)?)
        .map_err(|_| invalid_error("COFF string table size does not fit the host"))?;
    if string_table_bytes < 4 {
        return invalid("COFF string table is truncated");
    }
    require_range(bytes, symbol_table_end, string_table_bytes)?;
    let object_end = symbol_table_end
        .checked_add(string_table_bytes)
        .ok_or_else(|| invalid_error("COFF string table overflows"))?;
    let trailing = bytes
        .get(object_end..)
        .ok_or_else(|| invalid_error("COFF string table escapes the object"))?;
    // LLVM's COFF object writer retains up to three zero sentinel/padding bytes
    // after the string table without promising whole-file four-byte alignment.
    // They are not part of the string table and must remain bounded and zero.
    if trailing.len() > 3 || trailing.iter().any(|byte| *byte != 0) {
        return invalid("COFF has noncanonical trailing bytes after its string table");
    }
    let string_table = checked_slice(bytes, symbol_table_end, string_table_bytes)?;
    let maximum_name_bytes = maximum_accepted_name_bytes(machine, is_cancelled)?;

    let expected_sections = sorted_section_names(module, options, is_cancelled)?;
    let static_globals = sorted_static_global_indices(module, options, is_cancelled)?;
    let mut matched_sections = fallible_zeroes(
        machine.sections.len(),
        "required COFF section matches",
        options.maximum_sections as u64,
        is_cancelled,
    )?;
    let mut occupied = Vec::new();
    check_cancelled(is_cancelled)?;
    occupied
        .try_reserve_exact(section_count.saturating_mul(2).saturating_add(2))
        .map_err(|_| invalid_error("could not reserve bounded COFF ranges"))?;
    check_cancelled(is_cancelled)?;
    occupied.push((0usize, section_table_end));
    occupied.push((symbol_table_offset, object_end));
    let mut physical = Vec::new();
    check_cancelled(is_cancelled)?;
    physical
        .try_reserve_exact(section_count)
        .map_err(|_| invalid_error("could not reserve bounded COFF sections"))?;
    check_cancelled(is_cancelled)?;

    for index in 0..section_count {
        check_cancelled(is_cancelled)?;
        let (_, record) = table_record(
            bytes,
            COFF_HEADER_BYTES,
            index,
            COFF_SECTION_BYTES,
            "COFF section record overflows",
        )?;
        let name_bytes = section_name(record, string_table, maximum_name_bytes, is_cancelled)?;
        let name = copy_utf8(name_bytes, options.maximum_measurement_bytes, is_cancelled)?;
        let virtual_size = read_u32(record, 8)?;
        let virtual_address = read_u32(record, 12)?;
        let file_bytes = u64::from(read_u32(record, 16)?);
        let file_offset = u64::from(read_u32(record, 20)?);
        let relocation_offset = usize::try_from(read_u32(record, 24)?)
            .map_err(|_| invalid_error("COFF relocation offset does not fit the host"))?;
        let line_offset = read_u32(record, 28)?;
        let relocation_count = usize::from(read_u16(record, 32)?);
        let line_count = read_u16(record, 34)?;
        let characteristics = read_u32(record, 36)?;
        let alignment = section_alignment(characteristics)?;
        if virtual_size != 0
            || virtual_address != 0
            || line_offset != 0
            || line_count != 0
            || characteristics & IMAGE_SCN_LNK_NRELOC_OVFL != 0
        {
            return invalid("ordinary COFF section metadata is noncanonical");
        }
        let base_characteristics = characteristics & !IMAGE_SCN_ALIGN_MASK;
        let zero_fill = base_characteristics == ZERO_FILL_CHARACTERISTICS;
        let raw_file_bytes = if zero_fill { 0 } else { file_bytes };
        let raw_offset = usize::try_from(file_offset)
            .map_err(|_| invalid_error("COFF section offset does not fit the host"))?;
        let raw_bytes = usize::try_from(raw_file_bytes)
            .map_err(|_| invalid_error("COFF section size does not fit the host"))?;
        if zero_fill && file_offset != 0 {
            return invalid("zero-fill COFF section has a raw file offset");
        }
        if raw_bytes == 0 {
            if file_offset != 0 && raw_offset > bytes.len() {
                return invalid("empty COFF section has an invalid file offset");
            }
        } else {
            let raw_end = checked_range_end(bytes, raw_offset, raw_bytes)?;
            occupied.push((raw_offset, raw_end));
        }
        let relocation_bytes = relocation_count
            .checked_mul(COFF_RELOCATION_BYTES)
            .ok_or_else(|| invalid_error("COFF relocation table overflows"))?;
        if relocation_count == 0 {
            if relocation_offset != 0 {
                return invalid("COFF section has an offset for an empty relocation table");
            }
        } else {
            let relocation_end = checked_range_end(bytes, relocation_offset, relocation_bytes)?;
            occupied.push((relocation_offset, relocation_end));
        }

        let declared = crate::cancellable_binary_search_by(
            &expected_sections,
            |(expected, _)| {
                cancellable_bytes_compare(expected.as_bytes(), name_bytes, is_cancelled)
            },
            is_cancelled,
        )?
        .and_then(|position| expected_sections.get(position).map(|entry| entry.1));
        if let Some(declared_index) = declared {
            let matched = matched_sections
                .get_mut(declared_index)
                .ok_or_else(|| invalid_error("required COFF section identity is out of range"))?;
            if std::mem::replace(matched, 1) != 0 {
                return invalid("COFF duplicates a required MachineWir section");
            }
            let expected = machine
                .sections
                .get(declared_index)
                .ok_or_else(|| invalid_error("required COFF section identity is out of range"))?;
            let payload_valid = match expected.kind {
                SectionKind::Code => base_characteristics == CODE_CHARACTERISTICS,
                SectionKind::ReadOnlyData => {
                    base_characteristics == INITIALIZED_DATA_CHARACTERISTICS
                        && relocation_count == 0
                        && file_bytes == expected.reserved_bytes
                        && raw_file_bytes == file_bytes
                        && static_section_storage_matches(
                            machine,
                            expected.id,
                            Some(checked_slice(bytes, raw_offset, raw_bytes)?),
                            file_bytes,
                            &static_globals,
                            is_cancelled,
                        )?
                }
                SectionKind::RuntimeMetadata => {
                    base_characteristics == INITIALIZED_DATA_CHARACTERISTICS
                        && relocation_count == 0
                        && checked_slice(bytes, raw_offset, raw_bytes)? == [0; 8]
                }
                SectionKind::WritableData => {
                    base_characteristics == WRITABLE_DATA_CHARACTERISTICS
                        && relocation_count == 0
                        && file_bytes == expected.reserved_bytes
                        && raw_file_bytes == file_bytes
                        && static_section_storage_matches(
                            machine,
                            expected.id,
                            Some(checked_slice(bytes, raw_offset, raw_bytes)?),
                            file_bytes,
                            &static_globals,
                            is_cancelled,
                        )?
                }
                SectionKind::ZeroFill => {
                    base_characteristics == ZERO_FILL_CHARACTERISTICS
                        && relocation_count == 0
                        && file_offset == 0
                        && raw_file_bytes == 0
                        && file_bytes == expected.reserved_bytes
                        && static_section_storage_matches(
                            machine,
                            expected.id,
                            None,
                            file_bytes,
                            &static_globals,
                            is_cancelled,
                        )?
                }
                SectionKind::Relocations | SectionKind::Debug => false,
            };
            let valid = alignment == expected.alignment
                && file_bytes != 0
                && file_bytes <= expected.reserved_bytes
                && payload_valid;
            if !valid {
                if expected.kind == SectionKind::ZeroFill {
                    if base_characteristics != ZERO_FILL_CHARACTERISTICS {
                        return invalid(
                            "required zero-fill COFF section has initialized-data characteristics",
                        );
                    }
                    if alignment != expected.alignment {
                        return invalid("required zero-fill COFF section alignment is invalid");
                    }
                    if file_bytes != expected.reserved_bytes {
                        return invalid("required zero-fill COFF section extent is invalid");
                    }
                    return invalid("required zero-fill COFF section payload is invalid");
                }
                return invalid("required COFF section flags, extent, or payload are invalid");
            }
        } else if !valid_empty_bookkeeping(&name, file_bytes, relocation_count, characteristics)
            && !valid_generated_unwind(
                &name,
                file_bytes,
                relocation_count,
                alignment,
                characteristics,
            )
        {
            return invalid("COFF contains an undeclared physical section");
        }
        physical.push(PhysicalSection {
            name,
            file_offset,
            file_bytes,
            raw_file_bytes,
            alignment,
            characteristics,
            relocation_offset,
            relocation_count,
            declared,
        });
    }
    validate_physical_name_uniqueness(&physical, options, is_cancelled)?;
    for matched in &matched_sections {
        check_cancelled(is_cancelled)?;
        if *matched == 0 {
            return invalid("COFF omits a required MachineWir section");
        }
    }
    let (mut xdata_count, mut pdata_count) = (0usize, 0usize);
    for section in &physical {
        check_cancelled(is_cancelled)?;
        match section.name.as_str() {
            ".xdata" => xdata_count = xdata_count.saturating_add(1),
            ".pdata" => pdata_count = pdata_count.saturating_add(1),
            _ => {}
        }
    }
    if xdata_count > machine.functions.len() || pdata_count > machine.functions.len() {
        return invalid("COFF contains too many generated ARM64 unwind sections");
    }
    validate_nonoverlapping_zero_gaps(bytes, &mut occupied, object_end, is_cancelled)?;

    let expected_symbols = sorted_symbol_names(module, options, is_cancelled)?;
    let mut matched_symbols: Vec<Option<CoffSymbol>> = fallible_filled(
        machine.symbols.len(),
        None,
        "required COFF symbol matches",
        u64::from(options.maximum_symbols),
        is_cancelled,
    )?;
    let mut relocation_targets = fallible_u32_zeroes(
        raw_symbol_count,
        "COFF symbol identities",
        u64::from(options.maximum_symbols),
        is_cancelled,
    )?;
    // Preserve the exact required MachineWir symbol behind every raw COFF
    // symbol. `relocation_targets` is intentionally a smaller section-or-symbol
    // admission map used by unwind validation; it cannot prove that a runtime
    // call was relocated to the intrinsic the MachineWir names.
    let mut required_symbol_targets = fallible_u32_zeroes(
        raw_symbol_count,
        "COFF required symbol identities",
        u64::from(options.maximum_symbols),
        is_cancelled,
    )?;
    let mut saw_feature_symbol = false;
    let mut saw_file_symbol = false;
    let mut saw_section_symbol = fallible_zeroes(
        section_count,
        "COFF section symbols",
        u64::from(options.maximum_sections),
        is_cancelled,
    )?;
    let mut raw_index = 0usize;
    while raw_index < raw_symbol_count {
        check_cancelled(is_cancelled)?;
        let (base, record) = table_record(
            bytes,
            symbol_table_offset,
            raw_index,
            COFF_SYMBOL_BYTES,
            "COFF symbol record overflows",
        )?;
        let name = symbol_name(record, string_table, maximum_name_bytes, is_cancelled)?;
        let value = u64::from(read_u32(record, 8)?);
        let section_number = read_i16(record, 12)?;
        let symbol_type = read_u16(record, 14)?;
        let storage_class = record
            .get(16)
            .copied()
            .ok_or_else(|| invalid_error("COFF symbol storage class is truncated"))?;
        let auxiliary_count = usize::from(
            record
                .get(17)
                .copied()
                .ok_or_else(|| invalid_error("COFF auxiliary count is truncated"))?,
        );
        let next = raw_index
            .checked_add(1)
            .and_then(|next| next.checked_add(auxiliary_count))
            .ok_or_else(|| invalid_error("COFF auxiliary symbol count overflows"))?;
        if next > raw_symbol_count {
            return invalid("COFF auxiliary symbol records are truncated");
        }
        let expected_index = crate::cancellable_binary_search_by(
            &expected_symbols,
            |(expected, _)| cancellable_bytes_compare(expected.as_bytes(), name, is_cancelled),
            is_cancelled,
        )?
        .and_then(|position| expected_symbols.get(position).map(|entry| entry.1));
        let mut accepted = false;
        if let Some(expected_index) = expected_index {
            let matched = matched_symbols
                .get_mut(expected_index)
                .ok_or_else(|| invalid_error("required COFF symbol identity is out of range"))?;
            if matched.is_some() {
                return invalid("COFF duplicates a required symbol");
            }
            let expected = machine
                .symbols
                .get(expected_index)
                .ok_or_else(|| invalid_error("required COFF symbol identity is out of range"))?;
            if matches!(expected.definition, SymbolDefinition::ExternalRuntime(_)) {
                if section_number != 0
                    || value != 0
                    || symbol_type != 0
                    || storage_class != 2
                    || auxiliary_count != 0
                {
                    return invalid("runtime symbol is not a canonical undefined function");
                }
                *matched = Some(CoffSymbol::ExternalRuntime);
            } else {
                if section_number <= 0 {
                    return invalid("COFF undefines a required definition symbol");
                }
                let expected_storage = match expected.visibility {
                    SymbolVisibility::Private => 3,
                    SymbolVisibility::ImageEntry | SymbolVisibility::RuntimeMetadata => 2,
                    SymbolVisibility::Runtime => {
                        return invalid("defined symbol unexpectedly has runtime visibility");
                    }
                };
                let attributes_valid = match expected.definition {
                    SymbolDefinition::Function(_) => symbol_type == 0x20 && auxiliary_count <= 1,
                    SymbolDefinition::Global(_) | SymbolDefinition::SectionOffset { .. } => {
                        symbol_type == 0 && auxiliary_count == 0
                    }
                    SymbolDefinition::ExternalRuntime(_) => false,
                };
                if storage_class != expected_storage || !attributes_valid {
                    return invalid("required COFF symbol has noncanonical type or storage");
                }
                let function_bytes = if auxiliary_count == 1 {
                    let auxiliary = base
                        .checked_add(COFF_SYMBOL_BYTES)
                        .ok_or_else(|| invalid_error("COFF auxiliary record overflows"))?;
                    let bytes = u64::from(read_u32(bytes, checked_add(auxiliary, 4)?)?);
                    (bytes != 0).then_some(bytes)
                } else {
                    None
                };
                *matched = Some(CoffSymbol::Defined {
                    section: usize::try_from(section_number - 1)
                        .map_err(|_| invalid_error("COFF section number does not fit the host"))?,
                    offset: value,
                    function_bytes,
                });
            }
            *relocation_targets
                .get_mut(raw_index)
                .ok_or_else(|| invalid_error("COFF symbol identity is out of range"))? = u32::MAX;
            *required_symbol_targets
                .get_mut(raw_index)
                .ok_or_else(|| invalid_error("COFF symbol identity is out of range"))? =
                u32::try_from(expected_index)
                    .ok()
                    .and_then(|index| index.checked_add(1))
                    .ok_or_else(|| invalid_error("required COFF symbol identity overflows"))?;
            accepted = true;
        } else if section_number > 0 {
            let section = usize::try_from(section_number - 1)
                .map_err(|_| invalid_error("COFF section number does not fit the host"))?;
            let physical_section = physical.get(section);
            let section_symbol = saw_section_symbol.get_mut(section);
            let physical_name_matches = if let Some(physical) = physical_section {
                cancellable_bytes_equal(name, physical.name.as_bytes(), is_cancelled)?
            } else {
                false
            };
            if physical_name_matches
                && storage_class == 3
                && symbol_type == 0
                && value == 0
                && auxiliary_count == 1
                && section_symbol.is_some_and(|seen| std::mem::replace(seen, 1) == 0)
            {
                let auxiliary = base
                    .checked_add(COFF_SYMBOL_BYTES)
                    .ok_or_else(|| invalid_error("COFF auxiliary record overflows"))?;
                validate_section_auxiliary(
                    bytes,
                    auxiliary,
                    section_number,
                    physical_section.ok_or_else(|| {
                        invalid_error("COFF section symbol identity is out of range")
                    })?,
                )?;
                *relocation_targets
                    .get_mut(raw_index)
                    .ok_or_else(|| invalid_error("COFF symbol identity is out of range"))? =
                    u32::try_from(section)
                        .ok()
                        .and_then(|section| section.checked_add(1))
                        .ok_or_else(|| invalid_error("COFF section identity overflows"))?;
                accepted = true;
            }
        } else if name == b"@feat.00" {
            accepted = !std::mem::replace(&mut saw_feature_symbol, true)
                && section_number == -1
                && value == 0
                && symbol_type == 0
                && storage_class == 3
                && auxiliary_count == 0;
        } else if name == b".file" {
            let auxiliary_bytes = auxiliary_count
                .checked_mul(COFF_SYMBOL_BYTES)
                .ok_or_else(|| invalid_error("COFF file symbol overflows"))?;
            let auxiliary = base
                .checked_add(COFF_SYMBOL_BYTES)
                .ok_or_else(|| invalid_error("COFF file symbol overflows"))?;
            let file_name = checked_slice(bytes, auxiliary, auxiliary_bytes)?;
            accepted = !std::mem::replace(&mut saw_file_symbol, true)
                && section_number == -2
                && value == 0
                && symbol_type == 0
                && storage_class == 103
                && auxiliary_count != 0
                && file_name.first().is_some_and(|byte| *byte != 0);
        }
        if !accepted {
            return invalid("COFF contains an undeclared or malformed primary symbol");
        }
        raw_index = next;
    }
    for matched in &matched_symbols {
        check_cancelled(is_cancelled)?;
        if matched.is_none() {
            return invalid("COFF omits a required MachineWir symbol");
        }
    }
    validate_relocations(
        bytes,
        machine,
        &physical,
        &relocation_targets,
        &required_symbol_targets,
        options,
        is_cancelled,
    )?;

    let mut emitted_sections = Vec::new();
    check_cancelled(is_cancelled)?;
    emitted_sections
        .try_reserve_exact(machine.sections.len())
        .map_err(|_| invalid_error("could not reserve final COFF sections"))?;
    check_cancelled(is_cancelled)?;
    for section in &physical {
        check_cancelled(is_cancelled)?;
        if section.declared.is_some() {
            emitted_sections.push(EmittedSection {
                name: copy_utf8(
                    section.name.as_bytes(),
                    options.maximum_measurement_bytes,
                    is_cancelled,
                )?,
                alignment: section.alignment,
                file_offset: section.file_offset,
                file_bytes: section.raw_file_bytes,
                virtual_bytes: section.file_bytes,
            });
        }
    }
    cancellable_sort_owned_by(
        &mut emitted_sections,
        |left, right| crate::cancellable_text_compare(&left.name, &right.name, is_cancelled),
        is_cancelled,
    )?;

    let mut emitted_symbols = Vec::new();
    check_cancelled(is_cancelled)?;
    emitted_symbols
        .try_reserve_exact(machine.symbols.len())
        .map_err(|_| invalid_error("could not reserve final COFF symbols"))?;
    check_cancelled(is_cancelled)?;
    for (expected, observed) in machine.symbols.iter().zip(matched_symbols) {
        check_cancelled(is_cancelled)?;
        let observed = observed.ok_or_else(|| invalid_error("COFF omits a required symbol"))?;
        if matches!(expected.definition, SymbolDefinition::ExternalRuntime(_)) {
            if !matches!(observed, CoffSymbol::ExternalRuntime) {
                return invalid("runtime symbol is unexpectedly defined");
            }
            continue;
        }
        let CoffSymbol::Defined {
            section: observed_section,
            offset: observed_offset,
            function_bytes,
        } = observed
        else {
            return invalid("required definition symbol is unexpectedly external");
        };
        let section = physical
            .get(observed_section)
            .ok_or_else(|| invalid_error("required COFF symbol names a nonexistent section"))?;
        let expected_section = match expected.definition {
            SymbolDefinition::Function(function) => machine
                .functions
                .get(function.0 as usize)
                .map(|function| function.section),
            SymbolDefinition::Global(global) => machine
                .globals
                .get(global.0 as usize)
                .map(|global| global.section),
            SymbolDefinition::SectionOffset { section, .. } => Some(section),
            SymbolDefinition::ExternalRuntime(_) => None,
        }
        .and_then(|section| machine.sections.get(section.0 as usize));
        let expected_section_matches = if let Some(expected) = expected_section {
            crate::cancellable_text_equal(&expected.name, &section.name, is_cancelled)?
        } else {
            false
        };
        if !expected_section_matches {
            return invalid("required COFF symbol is in the wrong section");
        }
        let symbol_bytes = match expected.definition {
            SymbolDefinition::Function(_) => {
                function_bytes.unwrap_or_else(|| section.file_bytes.saturating_sub(observed_offset))
            }
            SymbolDefinition::Global(global) => machine
                .globals
                .get(global.0 as usize)
                .and_then(|global| machine.types.get(global.ty.0 as usize))
                .map(|ty| ty.size)
                .ok_or_else(|| invalid_error("global symbol has no declared extent"))?,
            SymbolDefinition::SectionOffset { bytes, .. } => bytes,
            SymbolDefinition::ExternalRuntime(_) => 0,
        };
        let expected_offset = match expected.definition {
            SymbolDefinition::Function(_) => 0,
            SymbolDefinition::Global(global) => machine
                .globals
                .get(global.0 as usize)
                .map(|global| global.offset)
                .ok_or_else(|| invalid_error("global symbol has no declared offset"))?,
            SymbolDefinition::SectionOffset { offset, .. } => offset,
            SymbolDefinition::ExternalRuntime(_) => 0,
        };
        if observed_offset != expected_offset
            || symbol_bytes == 0
            || observed_offset
                .checked_add(symbol_bytes)
                .is_none_or(|end| end > section.file_bytes)
            || (matches!(expected.definition, SymbolDefinition::Function(_))
                && symbol_bytes != section.file_bytes)
        {
            return invalid("required COFF symbol has an invalid emitted extent");
        }
        emitted_symbols.push(EmittedSymbol {
            name: copy_utf8(
                expected.name.as_bytes(),
                options.maximum_measurement_bytes,
                is_cancelled,
            )?,
            section: copy_utf8(
                section.name.as_bytes(),
                options.maximum_measurement_bytes,
                is_cancelled,
            )?,
            section_offset: observed_offset,
            bytes: symbol_bytes,
        });
    }
    cancellable_sort_owned_by(
        &mut emitted_symbols,
        |left, right| crate::cancellable_text_compare(&left.name, &right.name, is_cancelled),
        is_cancelled,
    )?;
    check_cancelled(is_cancelled)?;
    Ok((emitted_sections, emitted_symbols))
}

pub(super) fn static_section_storage_matches(
    machine: &wrela_machine_wir::MachineWir,
    section: wrela_machine_wir::SectionId,
    raw: Option<&[u8]>,
    logical_bytes: u64,
    sorted_globals: &[usize],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, CodegenError> {
    let mut cursor = 0u64;
    let mut count = 0usize;
    let mut left = 0usize;
    let mut right = sorted_globals.len();
    while left < right {
        check_cancelled(is_cancelled)?;
        let middle = left
            .checked_add((right - left) / 2)
            .ok_or_else(|| invalid_error("COFF static global search overflows"))?;
        let global_index = *sorted_globals
            .get(middle)
            .ok_or_else(|| invalid_error("COFF static global search is out of bounds"))?;
        let global = machine
            .globals
            .get(global_index)
            .ok_or_else(|| invalid_error("COFF static global identity is out of range"))?;
        if global.section.0 < section.0 {
            left = middle
                .checked_add(1)
                .ok_or_else(|| invalid_error("COFF static global search overflows"))?;
        } else {
            right = middle;
        }
    }
    check_cancelled(is_cancelled)?;

    for (index, global_index) in sorted_globals
        .get(left..)
        .ok_or_else(|| invalid_error("COFF static global range is out of bounds"))?
        .iter()
        .enumerate()
    {
        check_periodically(index, is_cancelled)?;
        let global = machine
            .globals
            .get(*global_index)
            .ok_or_else(|| invalid_error("COFF static global identity is out of range"))?;
        if global.section.0 != section.0 {
            break;
        }
        let Some(ty) = machine.types.get(global.ty.0 as usize) else {
            return Ok(false);
        };
        let Some(end) = global.offset.checked_add(ty.size) else {
            return Ok(false);
        };
        if global.offset != cursor || end > logical_bytes {
            return Ok(false);
        }
        match (&global.initializer, raw) {
            (wrela_machine_wir::MachineImmediate::Bytes(expected), Some(raw)) => {
                let Ok(offset) = usize::try_from(global.offset) else {
                    return Ok(false);
                };
                let Ok(end) = usize::try_from(end) else {
                    return Ok(false);
                };
                let Some(observed) = raw.get(offset..end) else {
                    return Ok(false);
                };
                if !slices_equal(observed, expected, is_cancelled)? {
                    return Ok(false);
                }
            }
            (wrela_machine_wir::MachineImmediate::Zero(initializer_ty), Some(raw)) => {
                if *initializer_ty != global.ty {
                    return Ok(false);
                }
                let Ok(offset) = usize::try_from(global.offset) else {
                    return Ok(false);
                };
                let Ok(end) = usize::try_from(end) else {
                    return Ok(false);
                };
                let Some(observed) = raw.get(offset..end) else {
                    return Ok(false);
                };
                if contains_nonzero(observed, is_cancelled)? {
                    return Ok(false);
                }
            }
            (wrela_machine_wir::MachineImmediate::Zero(initializer_ty), None)
                if *initializer_ty == global.ty => {}
            _ => return Ok(false),
        }
        cursor = end;
        count = count
            .checked_add(1)
            .ok_or_else(|| invalid_error("COFF static global count overflows"))?;
    }
    let raw_extent_matches =
        raw.is_none_or(|raw| u64::try_from(raw.len()).ok() == Some(logical_bytes));
    Ok(count != 0 && cursor == logical_bytes && raw_extent_matches)
}

fn sorted_static_global_indices(
    module: &ValidatedMachineWir,
    options: CodegenOptions,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<usize>, CodegenError> {
    let machine = module.as_wir();
    let actual = u64::try_from(machine.globals.len()).unwrap_or(u64::MAX);
    if actual > u64::from(options.maximum_symbols) {
        return Err(CodegenError::ResourceLimit {
            resource: "COFF static global identities",
            limit: u64::from(options.maximum_symbols),
            actual,
        });
    }
    let mut indices = Vec::new();
    check_cancelled(is_cancelled)?;
    indices
        .try_reserve_exact(machine.globals.len())
        .map_err(|_| CodegenError::ResourceLimit {
            resource: "COFF static global identities",
            limit: u64::from(options.maximum_symbols),
            actual,
        })?;
    check_cancelled(is_cancelled)?;
    for index in 0..machine.globals.len() {
        check_periodically(index, is_cancelled)?;
        indices.push(index);
    }
    crate::cancellable_sort_by(
        &mut indices,
        |left, right| {
            let left_section = machine.globals.get(*left).map(|global| global.section.0);
            let right_section = machine.globals.get(*right).map(|global| global.section.0);
            Ok((left_section, left).cmp(&(right_section, right)))
        },
        is_cancelled,
    )?;
    Ok(indices)
}

fn maximum_accepted_name_bytes(
    machine: &wrela_machine_wir::MachineWir,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<usize, CodegenError> {
    let mut maximum = [
        ".xdata".len(),
        ".pdata".len(),
        ".text".len(),
        ".data".len(),
        ".bss".len(),
        "@feat.00".len(),
        ".file".len(),
    ]
    .into_iter()
    .max()
    .unwrap_or(0);
    for section in &machine.sections {
        check_cancelled(is_cancelled)?;
        maximum = maximum.max(section.name.len());
    }
    for symbol in &machine.symbols {
        check_cancelled(is_cancelled)?;
        maximum = maximum.max(symbol.name.len());
    }
    check_cancelled(is_cancelled)?;
    Ok(maximum)
}

fn validate_physical_name_uniqueness(
    physical: &[PhysicalSection],
    options: CodegenOptions,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let actual = u64::try_from(physical.len()).unwrap_or(u64::MAX);
    if actual > u64::from(options.maximum_sections) {
        return Err(CodegenError::ResourceLimit {
            resource: "COFF physical section names",
            limit: u64::from(options.maximum_sections),
            actual,
        });
    }
    let mut names = Vec::new();
    check_cancelled(is_cancelled)?;
    names
        .try_reserve_exact(physical.len())
        .map_err(|_| CodegenError::ResourceLimit {
            resource: "COFF physical section names",
            limit: u64::from(options.maximum_sections),
            actual,
        })?;
    check_cancelled(is_cancelled)?;
    for section in physical {
        check_cancelled(is_cancelled)?;
        names.push(section.name.as_str());
    }
    crate::cancellable_sort_by(
        &mut names,
        |left, right| crate::cancellable_text_compare(left, right, is_cancelled),
        is_cancelled,
    )?;
    for pair in names.windows(2) {
        check_cancelled(is_cancelled)?;
        let [left, right] = pair else {
            continue;
        };
        if !matches!(*left, ".xdata" | ".pdata")
            && crate::cancellable_text_equal(left, right, is_cancelled)?
        {
            return invalid("COFF contains duplicate physical section names");
        }
    }
    Ok(())
}

fn sorted_section_names<'a>(
    module: &'a ValidatedMachineWir,
    options: CodegenOptions,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<(&'a str, usize)>, CodegenError> {
    let machine = module.as_wir();
    let mut names = Vec::new();
    check_cancelled(is_cancelled)?;
    names
        .try_reserve_exact(machine.sections.len())
        .map_err(|_| invalid_error("could not reserve required COFF section names"))?;
    check_cancelled(is_cancelled)?;
    for (index, section) in machine.sections.iter().enumerate() {
        check_cancelled(is_cancelled)?;
        if u64::try_from(section.name.len()).unwrap_or(u64::MAX) > options.maximum_measurement_bytes
        {
            return invalid("MachineWir section name exceeds COFF measurement limits");
        }
        names.push((section.name.as_str(), index));
    }
    crate::cancellable_sort_by(
        &mut names,
        |left, right| crate::cancellable_text_compare(left.0, right.0, is_cancelled),
        is_cancelled,
    )?;
    Ok(names)
}

fn sorted_symbol_names<'a>(
    module: &'a ValidatedMachineWir,
    options: CodegenOptions,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<(&'a str, usize)>, CodegenError> {
    let machine = module.as_wir();
    let mut names = Vec::new();
    check_cancelled(is_cancelled)?;
    names
        .try_reserve_exact(machine.symbols.len())
        .map_err(|_| invalid_error("could not reserve required COFF symbol names"))?;
    check_cancelled(is_cancelled)?;
    for (index, symbol) in machine.symbols.iter().enumerate() {
        check_cancelled(is_cancelled)?;
        if u64::try_from(symbol.name.len()).unwrap_or(u64::MAX) > options.maximum_measurement_bytes
        {
            return invalid("MachineWir symbol name exceeds COFF measurement limits");
        }
        names.push((symbol.name.as_str(), index));
    }
    crate::cancellable_sort_by(
        &mut names,
        |left, right| crate::cancellable_text_compare(left.0, right.0, is_cancelled),
        is_cancelled,
    )?;
    Ok(names)
}

fn validate_section_auxiliary(
    bytes: &[u8],
    auxiliary: usize,
    section_number: i16,
    section: &PhysicalSection,
) -> Result<(), CodegenError> {
    let record = checked_slice(bytes, auxiliary, COFF_SYMBOL_BYTES)?;
    if u64::from(read_u32(record, 0)?) != section.file_bytes
        || usize::from(read_u16(record, 4)?) != section.relocation_count
        || read_u16(record, 6)? != 0
        || read_i16(record, 12)? != section_number
        || record.get(14) != Some(&0)
        || record.get(15) != Some(&0)
        || read_i16(record, 16)? != 0
    {
        invalid("COFF section-definition auxiliary record is invalid")
    } else {
        Ok(())
    }
}

fn runtime_relocation_cell(
    section: usize,
    intrinsic: RuntimeIntrinsic,
) -> Result<usize, CodegenError> {
    let intrinsic = ALL_RUNTIME_INTRINSICS
        .iter()
        .position(|candidate| *candidate == intrinsic)
        .ok_or_else(|| invalid_error("runtime relocation names an unknown intrinsic"))?;
    section
        .checked_mul(RUNTIME_INTRINSIC_COUNT)
        .and_then(|base| base.checked_add(intrinsic))
        .ok_or_else(|| invalid_error("runtime relocation identity overflows"))
}

fn operation_runtime_relocation(operation: &MachineOperation) -> Option<RuntimeRelocationEmission> {
    match operation {
        MachineOperation::RuntimeCall { intrinsic, .. } => Some(RuntimeRelocationEmission {
            intrinsic: *intrinsic,
            directly_required: true,
        }),
        MachineOperation::CheckedInteger { .. } | MachineOperation::CheckedConvert { .. } => {
            Some(RuntimeRelocationEmission {
                intrinsic: RuntimeIntrinsic::Fatal,
                directly_required: false,
            })
        }
        MachineOperation::ActorReserve { .. } | MachineOperation::MailboxReceive { .. } => {
            Some(RuntimeRelocationEmission {
                intrinsic: RuntimeIntrinsic::Fatal,
                directly_required: false,
            })
        }
        MachineOperation::TestAssert { .. } => Some(RuntimeRelocationEmission {
            intrinsic: RuntimeIntrinsic::TestAssertionFail,
            directly_required: false,
        }),
        _ => None,
    }
}

fn required_internal_relocations(
    machine: &MachineWir,
    options: CodegenOptions,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<InternalRelocationCell>, CodegenError> {
    let mut count = 0u64;
    for (function_index, function) in machine.functions.iter().enumerate() {
        check_periodically(function_index, is_cancelled)?;
        for (block_index, block) in function.blocks.iter().enumerate() {
            check_periodically(block_index, is_cancelled)?;
            for (instruction_index, instruction) in block.instructions.iter().enumerate() {
                check_periodically(instruction_index, is_cancelled)?;
                if operation_internal_branch(&instruction.operation).is_some() {
                    count = count.checked_add(1).ok_or(CodegenError::ResourceLimit {
                        resource: "internal call relocations",
                        limit: options.maximum_instructions,
                        actual: u64::MAX,
                    })?;
                }
            }
            if matches!(block.terminator, MachineTerminator::TailCall { .. }) {
                count = count.checked_add(1).ok_or(CodegenError::ResourceLimit {
                    resource: "internal call relocations",
                    limit: options.maximum_instructions,
                    actual: u64::MAX,
                })?;
            }
        }
    }
    if count > options.maximum_instructions {
        return Err(CodegenError::ResourceLimit {
            resource: "internal call relocations",
            limit: options.maximum_instructions,
            actual: count,
        });
    }
    let capacity = usize::try_from(count).map_err(|_| CodegenError::ResourceLimit {
        resource: "internal call relocations",
        limit: options.maximum_instructions,
        actual: count,
    })?;
    let mut raw = Vec::new();
    raw.try_reserve_exact(capacity)
        .map_err(|_| CodegenError::ResourceLimit {
            resource: "internal call relocations",
            limit: options.maximum_instructions,
            actual: count,
        })?;
    check_cancelled(is_cancelled)?;
    for function in &machine.functions {
        check_cancelled(is_cancelled)?;
        let section = usize::try_from(function.section.0)
            .map_err(|_| invalid_error("internal call section does not fit the host"))?;
        for block in &function.blocks {
            check_cancelled(is_cancelled)?;
            for instruction in &block.instructions {
                check_cancelled(is_cancelled)?;
                if let Some((callee, kind)) = operation_internal_branch(&instruction.operation) {
                    raw.push(InternalRelocationCell {
                        section,
                        callee,
                        kind,
                        required: 1,
                        observed: 0,
                    });
                }
            }
            if let MachineTerminator::TailCall {
                function: callee, ..
            } = block.terminator
            {
                raw.push(InternalRelocationCell {
                    section,
                    callee: callee.0,
                    kind: InternalBranchKind::TailCall,
                    required: 1,
                    observed: 0,
                });
            }
        }
    }
    crate::cancellable_sort_by(
        &mut raw,
        |left, right| {
            check_cancelled(is_cancelled)?;
            Ok(left.key().cmp(&right.key()))
        },
        is_cancelled,
    )?;
    let mut compact: Vec<InternalRelocationCell> = Vec::new();
    compact
        .try_reserve_exact(raw.len())
        .map_err(|_| CodegenError::ResourceLimit {
            resource: "internal call relocation identities",
            limit: options.maximum_instructions,
            actual: count,
        })?;
    for edge in raw {
        check_cancelled(is_cancelled)?;
        if let Some(previous) = compact.last_mut()
            && previous.key() == edge.key()
        {
            previous.required = previous
                .required
                .checked_add(1)
                .ok_or_else(|| invalid_error("internal call relocation count overflows"))?;
        } else {
            compact.push(edge);
        }
    }
    check_cancelled(is_cancelled)?;
    Ok(compact)
}

fn operation_internal_branch(operation: &MachineOperation) -> Option<(u32, InternalBranchKind)> {
    match operation {
        MachineOperation::Call { function, .. } => Some((function.0, InternalBranchKind::Call)),
        MachineOperation::MailboxDispatch { method, .. } => {
            Some((method.0, InternalBranchKind::Call))
        }
        _ => None,
    }
}

fn observe_internal_relocation(
    cells: &mut [InternalRelocationCell],
    section: usize,
    callee: u32,
    relocation_kind: u16,
    instruction: u32,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    check_cancelled(is_cancelled)?;
    if relocation_kind != IMAGE_REL_ARM64_BRANCH26 {
        return invalid("internal call relocation is not an exact ARM64 branch");
    }
    let branch = match instruction & 0xfc00_0000 {
        0x9400_0000 => InternalBranchKind::Call,
        0x1400_0000 => InternalBranchKind::TailCall,
        _ => return invalid("internal branch relocation does not select ARM64 BL or B"),
    };
    let key = (section, callee, branch);
    let cell =
        crate::cancellable_binary_search_by(cells, |cell| Ok(cell.key().cmp(&key)), is_cancelled)?
            .and_then(|index| cells.get_mut(index))
            .ok_or_else(|| invalid_error("internal relocation has no exact MachineWir branch"))?;
    cell.observed = cell
        .observed
        .checked_add(1)
        .ok_or_else(|| invalid_error("observed internal relocation count overflows"))?;
    Ok(())
}

fn validate_internal_relocation_counts(
    cells: &[InternalRelocationCell],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    for (index, cell) in cells.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        if cell.observed != cell.required {
            return invalid("internal call relocations do not match MachineWir");
        }
    }
    check_cancelled(is_cancelled)
}

fn observe_canonical_relocation_offset(
    previous: &mut Option<u64>,
    offset: u64,
) -> Result<(), CodegenError> {
    if previous.is_some_and(|previous| offset <= previous) {
        return invalid("COFF code relocations are not strictly ordered and unique");
    }
    *previous = Some(offset);
    Ok(())
}

fn validate_relocations(
    bytes: &[u8],
    machine: &MachineWir,
    sections: &[PhysicalSection],
    relocation_targets: &[u32],
    required_symbol_targets: &[u32],
    options: CodegenOptions,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let mut internal_relocations = required_internal_relocations(machine, options, is_cancelled)?;
    let mut code_unwind_records = fallible_zeroes(
        sections.len(),
        "ARM64 code unwind records",
        u64::from(options.maximum_sections),
        is_cancelled,
    )?;
    let mut xdata_references = fallible_zeroes(
        sections.len(),
        "ARM64 xdata references",
        u64::from(options.maximum_sections),
        is_cancelled,
    )?;
    let runtime_cells = machine
        .sections
        .len()
        .checked_mul(RUNTIME_INTRINSIC_COUNT)
        .ok_or_else(|| invalid_error("runtime relocation matrix overflows"))?;
    let runtime_cell_limit = u64::from(options.maximum_sections)
        .checked_mul(u64::try_from(RUNTIME_INTRINSIC_COUNT).unwrap_or(u64::MAX))
        .ok_or_else(|| invalid_error("runtime relocation matrix limit overflows"))?;
    let mut required_runtime_relocations = fallible_u32_zeroes(
        runtime_cells,
        "required runtime relocations",
        runtime_cell_limit,
        is_cancelled,
    )?;
    let mut allowed_runtime_relocations = fallible_u32_zeroes(
        runtime_cells,
        "allowed runtime relocations",
        runtime_cell_limit,
        is_cancelled,
    )?;
    let mut observed_runtime_relocations = fallible_u32_zeroes(
        runtime_cells,
        "observed runtime relocations",
        runtime_cell_limit,
        is_cancelled,
    )?;
    for (function_index, function) in machine.functions.iter().enumerate() {
        check_periodically(function_index, is_cancelled)?;
        let section = usize::try_from(function.section.0)
            .map_err(|_| invalid_error("runtime call section does not fit the host"))?;
        for (block_index, block) in function.blocks.iter().enumerate() {
            check_periodically(block_index, is_cancelled)?;
            for (instruction_index, instruction) in block.instructions.iter().enumerate() {
                check_periodically(instruction_index, is_cancelled)?;
                let Some(emission) = operation_runtime_relocation(&instruction.operation) else {
                    continue;
                };
                let cell = runtime_relocation_cell(section, emission.intrinsic)?;
                let count = allowed_runtime_relocations
                    .get_mut(cell)
                    .ok_or_else(|| invalid_error("runtime call section is out of range"))?;
                *count = count
                    .checked_add(1)
                    .ok_or_else(|| invalid_error("runtime call relocation count overflows"))?;
                if emission.directly_required {
                    let count = required_runtime_relocations
                        .get_mut(cell)
                        .ok_or_else(|| invalid_error("runtime call section is out of range"))?;
                    *count = count.checked_add(1).ok_or_else(|| {
                        invalid_error("required runtime relocation count overflows")
                    })?;
                }
            }
        }
    }
    for section in sections {
        check_cancelled(is_cancelled)?;
        if section.name == ".pdata" {
            validate_pdata_relocations(
                bytes,
                section,
                sections,
                relocation_targets,
                &mut code_unwind_records,
                &mut xdata_references,
            )?;
            continue;
        }
        if section.name == ".xdata" && section.relocation_count != 0 {
            return invalid("generated ARM64 xdata unexpectedly contains relocations");
        }
        if section.relocation_count != 0
            && (section.declared.is_none()
                || section.characteristics & !IMAGE_SCN_ALIGN_MASK != CODE_CHARACTERISTICS)
        {
            return invalid("non-code COFF section contains a relocation");
        }
        let mut previous_relocation_offset = None;
        for index in 0..section.relocation_count {
            if index % 1024 == 0 {
                check_cancelled(is_cancelled)?;
            }
            let (_, record) = table_record(
                bytes,
                section.relocation_offset,
                index,
                COFF_RELOCATION_BYTES,
                "COFF relocation record overflows",
            )?;
            let offset = u64::from(read_u32(record, 0)?);
            observe_canonical_relocation_offset(&mut previous_relocation_offset, offset)?;
            let symbol = usize::try_from(read_u32(record, 4)?)
                .map_err(|_| invalid_error("COFF relocation symbol does not fit the host"))?;
            let kind = read_u16(record, 8)?;
            if offset >= section.file_bytes
                || relocation_targets.get(symbol).copied().unwrap_or(0) == 0
                || kind > 0x10
            {
                return invalid("COFF relocation is out of range or names an undeclared symbol");
            }
            let required_symbol = required_symbol_targets.get(symbol).copied().unwrap_or(0);
            if required_symbol != 0 {
                let required_symbol = usize::try_from(required_symbol - 1).map_err(|_| {
                    invalid_error("runtime relocation symbol does not fit the host")
                })?;
                let definition = machine
                    .symbols
                    .get(required_symbol)
                    .map(|symbol| &symbol.definition)
                    .ok_or_else(|| invalid_error("runtime relocation symbol is out of range"))?;
                if let SymbolDefinition::ExternalRuntime(intrinsic) = definition {
                    if kind != IMAGE_REL_ARM64_BRANCH26 {
                        return invalid("runtime call relocation is not an exact ARM64 branch");
                    }
                    if offset % 4 != 0
                        || offset
                            .checked_add(4)
                            .is_none_or(|end| end > section.file_bytes)
                    {
                        return invalid("runtime call relocation is not instruction-aligned");
                    }
                    let declared = section.declared.ok_or_else(|| {
                        invalid_error("runtime call relocation is outside declared code")
                    })?;
                    let instruction_offset = usize::try_from(section.file_offset)
                        .ok()
                        .and_then(|base| {
                            usize::try_from(offset)
                                .ok()
                                .and_then(|offset| base.checked_add(offset))
                        })
                        .ok_or_else(|| {
                            invalid_error("runtime call instruction offset overflows")
                        })?;
                    let instruction = read_u32(bytes, instruction_offset)?;
                    if instruction & 0xfc00_0000 != 0x9400_0000 {
                        return invalid("runtime call relocation does not select an ARM64 BL");
                    }
                    let cell = runtime_relocation_cell(declared, *intrinsic)?;
                    let count = observed_runtime_relocations.get_mut(cell).ok_or_else(|| {
                        invalid_error("runtime relocation section is out of range")
                    })?;
                    *count = count.checked_add(1).ok_or_else(|| {
                        invalid_error("observed runtime relocation count overflows")
                    })?;
                } else if let SymbolDefinition::Function(callee) = definition {
                    if offset % 4 != 0
                        || offset
                            .checked_add(4)
                            .is_none_or(|end| end > section.file_bytes)
                    {
                        return invalid("internal call relocation is not instruction-aligned");
                    }
                    let declared = section.declared.ok_or_else(|| {
                        invalid_error("internal call relocation is outside declared code")
                    })?;
                    let instruction_offset = usize::try_from(section.file_offset)
                        .ok()
                        .and_then(|base| {
                            usize::try_from(offset)
                                .ok()
                                .and_then(|offset| base.checked_add(offset))
                        })
                        .ok_or_else(|| {
                            invalid_error("internal call instruction offset overflows")
                        })?;
                    let instruction = read_u32(bytes, instruction_offset)?;
                    observe_internal_relocation(
                        &mut internal_relocations,
                        declared,
                        callee.0,
                        kind,
                        instruction,
                        is_cancelled,
                    )?;
                }
            }
        }
    }
    for (cell, ((required, allowed), observed)) in required_runtime_relocations
        .iter()
        .zip(&allowed_runtime_relocations)
        .zip(&observed_runtime_relocations)
        .enumerate()
    {
        check_periodically(cell, is_cancelled)?;
        let intrinsic = ALL_RUNTIME_INTRINSICS
            .get(cell % RUNTIME_INTRINSIC_COUNT)
            .copied()
            .ok_or_else(|| invalid_error("runtime relocation intrinsic is out of range"))?;
        validate_runtime_relocation_count(intrinsic, *required, *allowed, *observed)?;
    }
    validate_internal_relocation_counts(&internal_relocations, is_cancelled)?;
    for (index, section) in sections.iter().enumerate() {
        check_cancelled(is_cancelled)?;
        let xdata_references = xdata_references
            .get(index)
            .copied()
            .ok_or_else(|| invalid_error("ARM64 xdata identity is out of range"))?;
        let code_unwind_records = code_unwind_records
            .get(index)
            .copied()
            .ok_or_else(|| invalid_error("ARM64 code identity is out of range"))?;
        if section.name == ".xdata" && section.file_bytes != 0 && xdata_references != 1 {
            return invalid("generated ARM64 xdata is not selected by exactly one pdata record");
        }
        if section.declared.is_some()
            && section.characteristics & !IMAGE_SCN_ALIGN_MASK == CODE_CHARACTERISTICS
            && code_unwind_records > 1
        {
            return invalid("a code section has duplicate ARM64 pdata records");
        }
    }
    Ok(())
}

fn validate_runtime_relocation_count(
    intrinsic: RuntimeIntrinsic,
    required: u32,
    allowed: u32,
    observed: u32,
) -> Result<(), CodegenError> {
    if observed != 0 && allowed == 0 {
        return invalid("runtime relocation has no MachineWir call");
    }
    if observed < required {
        return invalid("required runtime call relocation is missing");
    }
    if observed > allowed {
        return invalid("runtime call relocation count exceeds MachineWir producers");
    }
    if intrinsic == RuntimeIntrinsic::ImageEnter
        && allowed != 0
        && (required != 1 || allowed != 1 || observed != 1)
    {
        return invalid("runtime call relocations do not match MachineWir");
    }
    Ok(())
}

fn validate_pdata_relocations(
    bytes: &[u8],
    pdata: &PhysicalSection,
    sections: &[PhysicalSection],
    relocation_targets: &[u32],
    code_unwind_records: &mut [u8],
    xdata_references: &mut [u8],
) -> Result<(), CodegenError> {
    if pdata.file_bytes != 8 || !matches!(pdata.relocation_count, 1 | 2) {
        return invalid("generated ARM64 pdata does not contain one unwind record");
    }
    let payload_offset = usize::try_from(pdata.file_offset)
        .map_err(|_| invalid_error("ARM64 pdata payload offset does not fit the host"))?;
    let payload = checked_slice(bytes, payload_offset, 8)?;
    let first = pdata.relocation_offset;
    let first_record = checked_slice(bytes, first, COFF_RELOCATION_BYTES)?;
    let first_offset = read_u32(first_record, 0)?;
    let first_kind = read_u16(first_record, 8)?;
    let first_symbol = usize::try_from(read_u32(first_record, 4)?)
        .map_err(|_| invalid_error("ARM64 pdata code symbol does not fit the host"))?;
    let code = decode_section_target(relocation_targets, first_symbol)?;
    let valid_code = sections.get(code).is_some_and(|section| {
        section.declared.is_some()
            && section.characteristics & !IMAGE_SCN_ALIGN_MASK == CODE_CHARACTERISTICS
    });
    if pdata.relocation_count == 1 {
        // ARM64's packed unwind form keeps the function RVA relocatable in
        // word zero and stores the complete unwind descriptor in word one.
        // Flags 01 and 10 are defined; 11 is reserved. The 11-bit function
        // length is measured in four-byte instructions and must describe the
        // complete one-function MachineWir code section exactly.
        let packed = read_u32(payload, 4)?;
        let flag = packed & 0b11;
        let function_bytes = u64::from((packed >> 2) & 0x7ff) * 4;
        let integer_registers = (packed >> 16) & 0xf;
        let exact_function_extent = sections
            .get(code)
            .is_some_and(|section| section.file_bytes == function_bytes);
        if read_u32(payload, 0)? != 0
            || first_offset != 0
            || first_kind != IMAGE_REL_ARM64_ADDR32NB
            || !matches!(flag, 1 | 2)
            || function_bytes == 0
            || integer_registers > 10
            || !valid_code
            || !exact_function_extent
        {
            return invalid("generated ARM64 packed pdata record is noncanonical");
        }
        let code_record = code_unwind_records
            .get_mut(code)
            .ok_or_else(|| invalid_error("ARM64 pdata code identity is out of range"))?;
        if *code_record != 0 {
            return invalid("generated ARM64 pdata relocation pair is noncanonical");
        }
        *code_record = 1;
        return Ok(());
    }

    let second = first
        .checked_add(COFF_RELOCATION_BYTES)
        .ok_or_else(|| invalid_error("ARM64 pdata relocation offset overflows"))?;
    let second_record = checked_slice(bytes, second, COFF_RELOCATION_BYTES)?;
    let second_offset = read_u32(second_record, 0)?;
    let second_kind = read_u16(second_record, 8)?;
    let second_symbol = usize::try_from(read_u32(second_record, 4)?)
        .map_err(|_| invalid_error("ARM64 pdata xdata symbol does not fit the host"))?;
    let xdata = decode_section_target(relocation_targets, second_symbol)?;
    let valid_xdata = sections
        .get(xdata)
        .is_some_and(|section| section.name == ".xdata");
    if read_u32(payload, 0)? != 0
        || read_u32(payload, 4)? != 0
        || first_offset != 0
        || second_offset != 4
        || first_kind != IMAGE_REL_ARM64_ADDR32NB
        || second_kind != IMAGE_REL_ARM64_ADDR32NB
        || !valid_code
        || !valid_xdata
    {
        return invalid("generated ARM64 pdata relocation pair is noncanonical");
    }
    let code_record = code_unwind_records
        .get_mut(code)
        .ok_or_else(|| invalid_error("ARM64 pdata code identity is out of range"))?;
    let xdata_reference = xdata_references
        .get_mut(xdata)
        .ok_or_else(|| invalid_error("ARM64 pdata xdata identity is out of range"))?;
    if *code_record != 0 || *xdata_reference != 0 {
        return invalid("generated ARM64 pdata relocation pair is noncanonical");
    }
    *code_record = 1;
    *xdata_reference = 1;
    Ok(())
}

fn decode_section_target(targets: &[u32], symbol: usize) -> Result<usize, CodegenError> {
    let target = targets.get(symbol).copied().unwrap_or(0);
    if target == 0 || target == u32::MAX {
        return invalid("ARM64 unwind relocation does not target a section definition");
    }
    usize::try_from(target - 1)
        .map_err(|_| invalid_error("ARM64 unwind section identity does not fit the host"))
}

fn valid_empty_bookkeeping(
    name: &str,
    bytes: u64,
    relocations: usize,
    characteristics: u32,
) -> bool {
    if bytes != 0 || relocations != 0 {
        return false;
    }
    let base = characteristics & !IMAGE_SCN_ALIGN_MASK;
    matches!(
        (name, base),
        (".text", CODE_CHARACTERISTICS)
            | (".data", WRITABLE_DATA_CHARACTERISTICS)
            | (".bss", ZERO_FILL_CHARACTERISTICS)
    )
}

fn valid_generated_unwind(
    name: &str,
    bytes: u64,
    relocations: usize,
    alignment: u32,
    characteristics: u32,
) -> bool {
    let base = characteristics & !IMAGE_SCN_ALIGN_MASK;
    match name {
        ".xdata" => {
            alignment == 4
                && base == UNWIND_CHARACTERISTICS
                && relocations == 0
                && (bytes == 0 || ((4..=64 * 1024).contains(&bytes) && bytes % 4 == 0))
        }
        ".pdata" => {
            alignment == 4
                && base == UNWIND_CHARACTERISTICS
                && bytes == 8
                && matches!(relocations, 1 | 2)
        }
        _ => false,
    }
}

fn validate_nonoverlapping_zero_gaps(
    bytes: &[u8],
    occupied: &mut [(usize, usize)],
    object_end: usize,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    crate::cancellable_sort_by(occupied, |left, right| Ok(left.cmp(right)), is_cancelled)?;
    let mut end = 0usize;
    for (index, &(start, next_end)) in occupied.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        if start < end || next_end < start || next_end > object_end {
            return invalid("COFF headers, sections, relocations, or tables overlap");
        }
        let gap = bytes
            .get(end..start)
            .ok_or_else(|| invalid_error("COFF layout gap escapes the object"))?;
        if contains_nonzero(gap, is_cancelled)? {
            return invalid("COFF layout padding is not deterministically zero");
        }
        end = next_end;
    }
    if end != object_end {
        return invalid("COFF contains unaccounted bytes before its string table end");
    }
    Ok(())
}

fn section_alignment(characteristics: u32) -> Result<u32, CodegenError> {
    let encoded = (characteristics & IMAGE_SCN_ALIGN_MASK) >> 20;
    if !(1..=14).contains(&encoded) {
        return invalid("COFF section has no supported explicit alignment");
    }
    Ok(1u32 << (encoded - 1))
}

fn section_name<'a>(
    record: &'a [u8],
    string_table: &'a [u8],
    maximum_name_bytes: usize,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<&'a [u8], CodegenError> {
    let inline = record
        .get(..8)
        .ok_or_else(|| invalid_error("COFF section name is truncated"))?;
    if inline.first() == Some(&b'/') {
        let end = inline.iter().position(|byte| *byte == 0).unwrap_or(8);
        let decimal = std::str::from_utf8(&inline[1..end])
            .map_err(|_| invalid_error("COFF long section-name offset is not ASCII"))?;
        let offset = decimal
            .parse::<usize>()
            .map_err(|_| invalid_error("COFF long section-name offset is invalid"))?;
        string_name(string_table, offset, maximum_name_bytes, is_cancelled)
    } else {
        let end = inline.iter().position(|byte| *byte == 0).unwrap_or(8);
        if end == 0 {
            invalid("COFF section name is empty")
        } else {
            Ok(&inline[..end])
        }
    }
}

fn symbol_name<'a>(
    record: &'a [u8],
    string_table: &'a [u8],
    maximum_name_bytes: usize,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<&'a [u8], CodegenError> {
    let inline = record
        .get(..8)
        .ok_or_else(|| invalid_error("COFF symbol name is truncated"))?;
    if inline.starts_with(&[0, 0, 0, 0]) {
        let offset = usize::try_from(read_u32(inline, 4)?)
            .map_err(|_| invalid_error("COFF long symbol-name offset does not fit the host"))?;
        string_name(string_table, offset, maximum_name_bytes, is_cancelled)
    } else {
        let end = inline.iter().position(|byte| *byte == 0).unwrap_or(8);
        if end == 0 {
            invalid("COFF symbol name is empty")
        } else {
            Ok(&inline[..end])
        }
    }
}

fn string_name<'a>(
    table: &'a [u8],
    offset: usize,
    maximum_name_bytes: usize,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<&'a [u8], CodegenError> {
    if offset < 4 || offset >= table.len() {
        return invalid("COFF string-table offset is outside the table");
    }
    let maximum_end = offset
        .checked_add(maximum_name_bytes)
        .and_then(|end| end.checked_add(1))
        .unwrap_or(usize::MAX)
        .min(table.len());
    let remainder = table
        .get(offset..maximum_end)
        .ok_or_else(|| invalid_error("COFF string-table name range overflows"))?;
    let mut consumed = 0usize;
    let mut end = None;
    for chunk in remainder.chunks(64 * 1024) {
        check_cancelled(is_cancelled)?;
        if let Some(position) = chunk.iter().position(|byte| *byte == 0) {
            end = consumed.checked_add(position);
            break;
        }
        consumed = consumed
            .checked_add(chunk.len())
            .ok_or_else(|| invalid_error("COFF string-table name length overflows"))?;
    }
    let end = end.ok_or_else(|| {
        if maximum_end < table.len() {
            invalid_error("COFF string-table name exceeds the accepted name bound")
        } else {
            invalid_error("COFF string-table name is unterminated")
        }
    })?;
    if end == 0 {
        invalid("COFF string-table name is empty")
    } else {
        Ok(&remainder[..end])
    }
}

fn copy_utf8(
    bytes: &[u8],
    limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<String, CodegenError> {
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return invalid("COFF name exceeds the measurement-byte limit");
    }
    let mut output = String::new();
    check_cancelled(is_cancelled)?;
    output
        .try_reserve_exact(bytes.len())
        .map_err(|_| invalid_error("could not reserve COFF name measurement"))?;
    check_cancelled(is_cancelled)?;
    for chunk in bytes.chunks(64 * 1024) {
        check_cancelled(is_cancelled)?;
        if !chunk.is_ascii() {
            return invalid("COFF required name is not canonical ASCII");
        }
        output.extend(chunk.iter().map(|byte| char::from(*byte)));
    }
    Ok(output)
}

fn fallible_zeroes(
    length: usize,
    resource: &'static str,
    limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>, CodegenError> {
    fallible_filled(length, 0, resource, limit, is_cancelled)
}

fn fallible_u32_zeroes(
    length: usize,
    resource: &'static str,
    limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u32>, CodegenError> {
    fallible_filled(length, 0, resource, limit, is_cancelled)
}

fn fallible_filled<T: Copy>(
    length: usize,
    value: T,
    resource: &'static str,
    limit: u64,
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
    let mut output = Vec::new();
    check_cancelled(is_cancelled)?;
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
        output.push(value);
    }
    check_cancelled(is_cancelled)?;
    Ok(output)
}

fn require_range(bytes: &[u8], offset: usize, length: usize) -> Result<(), CodegenError> {
    checked_range_end(bytes, offset, length).map(|_| ())
}

fn checked_range_end(bytes: &[u8], offset: usize, length: usize) -> Result<usize, CodegenError> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| invalid_error("COFF record range overflows"))?;
    if end > bytes.len() {
        invalid("COFF record range is outside the object")
    } else {
        Ok(end)
    }
}

fn checked_slice(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8], CodegenError> {
    let end = checked_range_end(bytes, offset, length)?;
    bytes
        .get(offset..end)
        .ok_or_else(|| invalid_error("COFF record range is outside the object"))
}

fn table_record<'a>(
    bytes: &'a [u8],
    table_offset: usize,
    index: usize,
    record_bytes: usize,
    overflow_reason: &'static str,
) -> Result<(usize, &'a [u8]), CodegenError> {
    let displacement = index
        .checked_mul(record_bytes)
        .ok_or_else(|| invalid_error(overflow_reason))?;
    let offset = table_offset
        .checked_add(displacement)
        .ok_or_else(|| invalid_error(overflow_reason))?;
    Ok((offset, checked_slice(bytes, offset, record_bytes)?))
}

fn checked_add(base: usize, displacement: usize) -> Result<usize, CodegenError> {
    base.checked_add(displacement)
        .ok_or_else(|| invalid_error("COFF field offset overflows"))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, CodegenError> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| invalid_error("COFF u16 field overflows"))?;
    let raw: [u8; 2] = bytes
        .get(offset..end)
        .ok_or_else(|| invalid_error("COFF u16 field is truncated"))?
        .try_into()
        .map_err(|_| invalid_error("COFF u16 field is truncated"))?;
    Ok(u16::from_le_bytes(raw))
}

fn read_i16(bytes: &[u8], offset: usize) -> Result<i16, CodegenError> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| invalid_error("COFF i16 field overflows"))?;
    let raw: [u8; 2] = bytes
        .get(offset..end)
        .ok_or_else(|| invalid_error("COFF i16 field is truncated"))?
        .try_into()
        .map_err(|_| invalid_error("COFF i16 field is truncated"))?;
    Ok(i16::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, CodegenError> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| invalid_error("COFF u32 field overflows"))?;
    let raw: [u8; 4] = bytes
        .get(offset..end)
        .ok_or_else(|| invalid_error("COFF u32 field is truncated"))?
        .try_into()
        .map_err(|_| invalid_error("COFF u32 field is truncated"))?;
    Ok(u32::from_le_bytes(raw))
}

fn slices_equal(
    left: &[u8],
    right: &[u8],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, CodegenError> {
    if left.len() != right.len() {
        return Ok(false);
    }
    for (left, right) in left.chunks(64 * 1024).zip(right.chunks(64 * 1024)) {
        check_cancelled(is_cancelled)?;
        if left != right {
            return Ok(false);
        }
    }
    Ok(true)
}

fn contains_nonzero(bytes: &[u8], is_cancelled: &dyn Fn() -> bool) -> Result<bool, CodegenError> {
    for chunk in bytes.chunks(64 * 1024) {
        check_cancelled(is_cancelled)?;
        if chunk.iter().any(|byte| *byte != 0) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn cancellable_bytes_compare(
    left: &[u8],
    right: &[u8],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<std::cmp::Ordering, CodegenError> {
    for (index, (left, right)) in left.iter().zip(right).enumerate() {
        check_periodically(index, is_cancelled)?;
        match left.cmp(right) {
            std::cmp::Ordering::Equal => {}
            ordering => return Ok(ordering),
        }
    }
    check_cancelled(is_cancelled)?;
    Ok(left.len().cmp(&right.len()))
}

fn cancellable_bytes_equal(
    left: &[u8],
    right: &[u8],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, CodegenError> {
    Ok(cancellable_bytes_compare(left, right, is_cancelled)? == std::cmp::Ordering::Equal)
}

fn cancellable_sort_owned_by<T>(
    values: &mut Vec<T>,
    mut compare: impl FnMut(&T, &T) -> Result<std::cmp::Ordering, CodegenError>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    let actual = u64::try_from(values.len()).unwrap_or(u64::MAX);
    let mut order = Vec::new();
    check_cancelled(is_cancelled)?;
    order
        .try_reserve_exact(values.len())
        .map_err(|_| CodegenError::ResourceLimit {
            resource: "cancellable owned sort order entries",
            limit: actual,
            actual,
        })?;
    check_cancelled(is_cancelled)?;
    for index in 0..values.len() {
        check_cancelled(is_cancelled)?;
        order.push(index);
    }
    crate::cancellable_sort_by(
        &mut order,
        |left, right| {
            let left = values
                .get(*left)
                .ok_or(CodegenError::UnsupportedMachineContract(
                    "cancellable owned sort left identity escaped its input",
                ))?;
            let right = values
                .get(*right)
                .ok_or(CodegenError::UnsupportedMachineContract(
                    "cancellable owned sort right identity escaped its input",
                ))?;
            compare(left, right)
        },
        is_cancelled,
    )?;

    let original = std::mem::take(values);
    let mut slots = Vec::new();
    check_cancelled(is_cancelled)?;
    slots
        .try_reserve_exact(original.len())
        .map_err(|_| CodegenError::ResourceLimit {
            resource: "cancellable owned sort value entries",
            limit: actual,
            actual,
        })?;
    check_cancelled(is_cancelled)?;
    for value in original {
        check_cancelled(is_cancelled)?;
        slots.push(Some(value));
    }
    check_cancelled(is_cancelled)?;
    values
        .try_reserve_exact(slots.len())
        .map_err(|_| CodegenError::ResourceLimit {
            resource: "cancellable owned sort output entries",
            limit: actual,
            actual,
        })?;
    check_cancelled(is_cancelled)?;
    for index in order {
        check_cancelled(is_cancelled)?;
        let value = slots.get_mut(index).and_then(Option::take).ok_or(
            CodegenError::UnsupportedMachineContract(
                "cancellable owned sort identity was duplicated or out of range",
            ),
        )?;
        values.push(value);
    }
    check_cancelled(is_cancelled)
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

fn invalid<T>(reason: &'static str) -> Result<T, CodegenError> {
    Err(invalid_error(reason))
}

fn invalid_error(reason: &'static str) -> CodegenError {
    CodegenError::InvalidObjectMeasurements(reason)
}

#[cfg(test)]
mod adversarial_tests {
    use super::{
        CODE_CHARACTERISTICS, CodegenError, IMAGE_REL_ARM64_ADDR32NB, IMAGE_REL_ARM64_BRANCH26,
        InternalBranchKind, InternalRelocationCell, PhysicalSection, UNWIND_CHARACTERISTICS,
        cancellable_bytes_compare, cancellable_sort_owned_by, checked_slice, contains_nonzero,
        fallible_filled, fallible_zeroes, observe_canonical_relocation_offset,
        observe_internal_relocation, operation_internal_branch, operation_runtime_relocation,
        string_name, valid_generated_unwind, validate_internal_relocation_counts,
        validate_pdata_relocations, validate_runtime_relocation_count,
    };
    use std::cell::Cell;
    use wrela_machine_wir::{
        FunctionId, GlobalId, MachineAssertionFailure, MachineOperation, ValueId,
    };
    use wrela_runtime_abi::RuntimeIntrinsic;

    #[test]
    fn string_table_names_are_bounded_before_a_long_scan() {
        let oversized = b"\0\0\0\0abcde\0";
        assert_eq!(
            string_name(oversized, 4, 4, &|| false),
            Err(CodegenError::InvalidObjectMeasurements(
                "COFF string-table name exceeds the accepted name bound"
            ))
        );
        assert_eq!(
            string_name(b"\0\0\0\0abcd", 4, 8, &|| false),
            Err(CodegenError::InvalidObjectMeasurements(
                "COFF string-table name is unterminated"
            ))
        );
        assert_eq!(
            string_name(oversized, usize::MAX, 4, &|| false),
            Err(CodegenError::InvalidObjectMeasurements(
                "COFF string-table offset is outside the table"
            ))
        );
    }

    #[test]
    fn record_ranges_reject_host_arithmetic_overflow() {
        assert_eq!(
            checked_slice(&[], usize::MAX, 2),
            Err(CodegenError::InvalidObjectMeasurements(
                "COFF record range overflows"
            ))
        );
    }

    #[test]
    fn fallible_tables_enforce_the_declared_limit_before_allocation() {
        assert_eq!(
            fallible_zeroes(2, "adversarial identities", 1, &|| false),
            Err(CodegenError::ResourceLimit {
                resource: "adversarial identities",
                limit: 1,
                actual: 2,
            })
        );

        let polls = Cell::new(0usize);
        assert_eq!(
            fallible_filled(4, 0u32, "adversarial identities", 4, &|| {
                polls.set(polls.get().saturating_add(1));
                true
            }),
            Err(CodegenError::Cancelled)
        );
        assert_eq!(polls.get(), 1, "pre-cancelled fill reached allocation");

        let polls = Cell::new(0usize);
        assert_eq!(
            fallible_filled(4, 0u32, "adversarial identities", 4, &|| {
                let next = polls.get().saturating_add(1);
                polls.set(next);
                next >= 6
            }),
            Err(CodegenError::Cancelled)
        );
        assert_eq!(polls.get(), 6, "fill continued past its exact stop poll");
    }

    #[test]
    fn out_of_range_pdata_targets_are_errors_instead_of_indexes() {
        let mut bytes = [0u8; 20];
        bytes
            .get_mut(10..14)
            .expect("fixed test range")
            .copy_from_slice(&4u32.to_le_bytes());
        bytes
            .get_mut(8..10)
            .expect("fixed test range")
            .copy_from_slice(&IMAGE_REL_ARM64_ADDR32NB.to_le_bytes());
        bytes
            .get_mut(18..20)
            .expect("fixed test range")
            .copy_from_slice(&IMAGE_REL_ARM64_ADDR32NB.to_le_bytes());
        let pdata = PhysicalSection {
            name: ".pdata".to_owned(),
            file_offset: 0,
            file_bytes: 8,
            raw_file_bytes: 8,
            alignment: 4,
            characteristics: UNWIND_CHARACTERISTICS,
            relocation_offset: 0,
            relocation_count: 2,
            declared: None,
        };
        let sections = [PhysicalSection {
            name: ".text".to_owned(),
            file_offset: 0,
            file_bytes: 8,
            raw_file_bytes: 8,
            alignment: 16,
            characteristics: 0,
            relocation_offset: 0,
            relocation_count: 0,
            declared: Some(0),
        }];
        let targets = [2u32, 2u32];
        assert_eq!(
            validate_pdata_relocations(&bytes, &pdata, &sections, &targets, &mut [0], &mut [0],),
            Err(CodegenError::InvalidObjectMeasurements(
                "generated ARM64 pdata relocation pair is noncanonical"
            ))
        );
    }

    #[test]
    fn internal_call_relocation_multiset_rejects_omit_kind_opcode_and_redirect() {
        let fixture = || {
            vec![InternalRelocationCell {
                section: 2,
                callee: 7,
                kind: InternalBranchKind::Call,
                required: 1,
                observed: 0,
            }]
        };

        assert_eq!(
            validate_internal_relocation_counts(&fixture(), &|| false),
            Err(CodegenError::InvalidObjectMeasurements(
                "internal call relocations do not match MachineWir"
            ))
        );

        let mut wrong_kind = fixture();
        assert_eq!(
            observe_internal_relocation(
                &mut wrong_kind,
                2,
                7,
                IMAGE_REL_ARM64_ADDR32NB,
                0x9400_0000,
                &|| false,
            ),
            Err(CodegenError::InvalidObjectMeasurements(
                "internal call relocation is not an exact ARM64 branch"
            ))
        );

        let mut wrong_opcode = fixture();
        assert_eq!(
            observe_internal_relocation(
                &mut wrong_opcode,
                2,
                7,
                IMAGE_REL_ARM64_BRANCH26,
                0xd503_201f,
                &|| false,
            ),
            Err(CodegenError::InvalidObjectMeasurements(
                "internal branch relocation does not select ARM64 BL or B"
            ))
        );

        let mut redirected = fixture();
        assert_eq!(
            observe_internal_relocation(
                &mut redirected,
                2,
                8,
                IMAGE_REL_ARM64_BRANCH26,
                0x9400_0000,
                &|| false,
            ),
            Err(CodegenError::InvalidObjectMeasurements(
                "internal relocation has no exact MachineWir branch"
            ))
        );

        let mut valid = fixture();
        assert_eq!(
            observe_internal_relocation(
                &mut valid,
                2,
                7,
                IMAGE_REL_ARM64_BRANCH26,
                0x9400_0000,
                &|| true,
            ),
            Err(CodegenError::Cancelled)
        );
        observe_internal_relocation(
            &mut valid,
            2,
            7,
            IMAGE_REL_ARM64_BRANCH26,
            0x9400_0000,
            &|| false,
        )
        .expect("exact ARM64 BL relocation");
        validate_internal_relocation_counts(&valid, &|| false)
            .expect("exact internal relocation multiset");

        let mut duplicate = fixture();
        duplicate[0].required = 2;
        observe_internal_relocation(
            &mut duplicate,
            2,
            7,
            IMAGE_REL_ARM64_BRANCH26,
            0x9400_0000,
            &|| false,
        )
        .expect("first duplicate relocation");
        assert_eq!(
            validate_internal_relocation_counts(&duplicate, &|| false),
            Err(CodegenError::InvalidObjectMeasurements(
                "internal call relocations do not match MachineWir"
            ))
        );
        observe_internal_relocation(
            &mut duplicate,
            2,
            7,
            IMAGE_REL_ARM64_BRANCH26,
            0x9400_0000,
            &|| false,
        )
        .expect("second duplicate relocation");
        validate_internal_relocation_counts(&duplicate, &|| false)
            .expect("duplicate call count remains exact");

        let mut previous = None;
        observe_canonical_relocation_offset(&mut previous, 24)
            .expect("first code relocation offset");
        assert_eq!(
            observe_canonical_relocation_offset(&mut previous, 24),
            Err(CodegenError::InvalidObjectMeasurements(
                "COFF code relocations are not strictly ordered and unique"
            ))
        );
    }

    #[test]
    fn mailbox_dispatch_requires_one_exact_internal_call_relocation() {
        let (callee, kind) = operation_internal_branch(&MachineOperation::MailboxDispatch {
            mailbox: GlobalId(3),
            actor: 5,
            method: FunctionId(7),
        })
        .expect("mailbox dispatch emits one internal branch");
        assert_eq!((callee, kind), (7, InternalBranchKind::Call));

        let fixture = || {
            vec![InternalRelocationCell {
                section: 2,
                callee,
                kind,
                required: 1,
                observed: 0,
            }]
        };
        assert_eq!(
            validate_internal_relocation_counts(&fixture(), &|| false),
            Err(CodegenError::InvalidObjectMeasurements(
                "internal call relocations do not match MachineWir"
            ))
        );

        let mut redirected = fixture();
        assert_eq!(
            observe_internal_relocation(
                &mut redirected,
                2,
                callee + 1,
                IMAGE_REL_ARM64_BRANCH26,
                0x9400_0000,
                &|| false,
            ),
            Err(CodegenError::InvalidObjectMeasurements(
                "internal relocation has no exact MachineWir branch"
            ))
        );

        let mut exact = fixture();
        observe_internal_relocation(
            &mut exact,
            2,
            callee,
            IMAGE_REL_ARM64_BRANCH26,
            0x9400_0000,
            &|| false,
        )
        .expect("exact dispatch BL relocation");
        validate_internal_relocation_counts(&exact, &|| false)
            .expect("dispatch relocation count matches MachineWir");

        let mut duplicate = exact;
        observe_internal_relocation(
            &mut duplicate,
            2,
            callee,
            IMAGE_REL_ARM64_BRANCH26,
            0x9400_0000,
            &|| false,
        )
        .expect("second observed dispatch relocation");
        assert_eq!(
            validate_internal_relocation_counts(&duplicate, &|| false),
            Err(CodegenError::InvalidObjectMeasurements(
                "internal call relocations do not match MachineWir"
            ))
        );
    }

    #[test]
    fn actor_failure_paths_allow_only_their_bounded_fatal_relocations() {
        let reserve = operation_runtime_relocation(&MachineOperation::ActorReserve {
            mailbox: GlobalId(3),
            actor: 5,
            method: FunctionId(7),
            proof: wrela_machine_wir::ProofId(11),
            failure: wrela_machine_wir::ScalarFailureProvenance {
                kind: wrela_machine_wir::ScalarFailureKind::ActorMailboxFull,
                flow_function: 13,
                flow_instruction: 17,
            },
        })
        .expect("actor reserve emits Fatal");
        let receive = operation_runtime_relocation(&MachineOperation::MailboxReceive {
            mailbox: GlobalId(3),
            actor: 5,
            method: FunctionId(7),
            failure: wrela_machine_wir::ScalarFailureProvenance {
                kind: wrela_machine_wir::ScalarFailureKind::ActorMailboxMismatch,
                flow_function: 19,
                flow_instruction: 23,
            },
        })
        .expect("mailbox receive emits Fatal");
        for emission in [reserve, receive] {
            assert_eq!(emission.intrinsic, RuntimeIntrinsic::Fatal);
            assert!(!emission.directly_required);
        }

        let direct = operation_runtime_relocation(&MachineOperation::RuntimeCall {
            intrinsic: RuntimeIntrinsic::CpuIdle,
            arguments: Vec::new(),
        })
        .expect("direct runtime call emits one required relocation");
        assert_eq!(direct.intrinsic, RuntimeIntrinsic::CpuIdle);
        assert!(direct.directly_required);

        validate_runtime_relocation_count(RuntimeIntrinsic::Fatal, 0, 1, 0)
            .expect("LLVM may prove an actor failure branch safe");
        validate_runtime_relocation_count(RuntimeIntrinsic::Fatal, 0, 1, 1)
            .expect("an unproved actor failure branch retains one Fatal relocation");
        assert_eq!(
            validate_runtime_relocation_count(RuntimeIntrinsic::Fatal, 0, 1, 2),
            Err(CodegenError::InvalidObjectMeasurements(
                "runtime call relocation count exceeds MachineWir producers"
            ))
        );
        assert_eq!(
            validate_runtime_relocation_count(RuntimeIntrinsic::CpuIdle, 1, 1, 0),
            Err(CodegenError::InvalidObjectMeasurements(
                "required runtime call relocation is missing"
            ))
        );
        assert_eq!(
            validate_runtime_relocation_count(RuntimeIntrinsic::ImageExit, 0, 0, 1),
            Err(CodegenError::InvalidObjectMeasurements(
                "runtime relocation has no MachineWir call"
            ))
        );
        validate_runtime_relocation_count(RuntimeIntrinsic::Fatal, 1, 2, 1)
            .expect("an optional checked failure may be proved away");
        validate_runtime_relocation_count(RuntimeIntrinsic::Fatal, 1, 2, 2)
            .expect("an optional checked failure may remain emitted");
    }

    #[test]
    fn generated_test_assertion_allows_exactly_one_noreturn_runtime_relocation() {
        let emission = operation_runtime_relocation(&MachineOperation::TestAssert {
            condition: ValueId(0),
            failure: MachineAssertionFailure {
                expression: "false".to_owned(),
                expression_global: GlobalId(0),
                message: None,
                message_global: None,
                source: wrela_source::Span {
                    file: wrela_source::FileId(0),
                    range: wrela_source::TextRange { start: 0, end: 5 },
                },
            },
        })
        .expect("TestAssert emits one bounded assertion-failure relocation");
        assert_eq!(emission.intrinsic, RuntimeIntrinsic::TestAssertionFail);
        assert!(!emission.directly_required);
        validate_runtime_relocation_count(RuntimeIntrinsic::TestAssertionFail, 0, 1, 0)
            .expect("LLVM may prove the assertion true");
        validate_runtime_relocation_count(RuntimeIntrinsic::TestAssertionFail, 0, 1, 1)
            .expect("one false edge retains one assertion-failure relocation");
        assert_eq!(
            validate_runtime_relocation_count(RuntimeIntrinsic::TestAssertionFail, 0, 1, 2),
            Err(CodegenError::InvalidObjectMeasurements(
                "runtime call relocation count exceeds MachineWir producers"
            ))
        );
    }

    #[test]
    fn image_enter_runtime_cells_distinguish_empty_from_declared_singletons() {
        validate_runtime_relocation_count(RuntimeIntrinsic::ImageEnter, 0, 0, 0)
            .expect("an unrelated section has no ImageEnter relocation cell");
        validate_runtime_relocation_count(RuntimeIntrinsic::ImageEnter, 1, 1, 1)
            .expect("the declared image entry has exactly one ImageEnter relocation");
        assert_eq!(
            validate_runtime_relocation_count(RuntimeIntrinsic::ImageEnter, 1, 1, 0),
            Err(CodegenError::InvalidObjectMeasurements(
                "required runtime call relocation is missing"
            ))
        );
        assert_eq!(
            validate_runtime_relocation_count(RuntimeIntrinsic::ImageEnter, 1, 1, 2),
            Err(CodegenError::InvalidObjectMeasurements(
                "runtime call relocation count exceeds MachineWir producers"
            ))
        );
        assert_eq!(
            validate_runtime_relocation_count(RuntimeIntrinsic::ImageEnter, 0, 0, 1),
            Err(CodegenError::InvalidObjectMeasurements(
                "runtime relocation has no MachineWir call"
            ))
        );
    }

    #[test]
    fn packed_pdata_requires_an_exact_code_extent_and_nonreserved_flag() {
        let mut bytes = [0u8; 18];
        bytes
            .get_mut(4..8)
            .expect("fixed packed unwind word")
            .copy_from_slice(&((2u32 << 2) | 1).to_le_bytes());
        bytes
            .get_mut(16..18)
            .expect("fixed relocation kind")
            .copy_from_slice(&IMAGE_REL_ARM64_ADDR32NB.to_le_bytes());
        let pdata = PhysicalSection {
            name: ".pdata".to_owned(),
            file_offset: 0,
            file_bytes: 8,
            raw_file_bytes: 8,
            alignment: 4,
            characteristics: UNWIND_CHARACTERISTICS,
            relocation_offset: 8,
            relocation_count: 1,
            declared: None,
        };
        let sections = [PhysicalSection {
            name: ".text.wrela.0".to_owned(),
            file_offset: 0,
            file_bytes: 8,
            raw_file_bytes: 8,
            alignment: 16,
            characteristics: CODE_CHARACTERISTICS,
            relocation_offset: 0,
            relocation_count: 0,
            declared: Some(0),
        }];
        let mut code_records = [0];
        validate_pdata_relocations(&bytes, &pdata, &sections, &[1], &mut code_records, &mut [0])
            .expect("canonical packed ARM64 unwind record");
        assert_eq!(code_records, [1]);

        bytes
            .get_mut(4..8)
            .expect("fixed packed unwind word")
            .copy_from_slice(&((2u32 << 2) | 3).to_le_bytes());
        assert_eq!(
            validate_pdata_relocations(&bytes, &pdata, &sections, &[1], &mut [0], &mut [0],),
            Err(CodegenError::InvalidObjectMeasurements(
                "generated ARM64 packed pdata record is noncanonical"
            ))
        );

        bytes
            .get_mut(4..8)
            .expect("fixed packed unwind word")
            .copy_from_slice(&((1u32 << 2) | 1).to_le_bytes());
        assert_eq!(
            validate_pdata_relocations(&bytes, &pdata, &sections, &[1], &mut [0], &mut [0],),
            Err(CodegenError::InvalidObjectMeasurements(
                "generated ARM64 packed pdata record is noncanonical"
            ))
        );

        bytes
            .get_mut(4..8)
            .expect("fixed packed unwind word")
            .copy_from_slice(&((2u32 << 2) | (11 << 16) | 1).to_le_bytes());
        assert_eq!(
            validate_pdata_relocations(&bytes, &pdata, &sections, &[1], &mut [0], &mut [0],),
            Err(CodegenError::InvalidObjectMeasurements(
                "generated ARM64 packed pdata record is noncanonical"
            ))
        );
    }

    #[test]
    fn empty_llvm_xdata_bookkeeping_is_exact_and_nonrelocatable() {
        assert!(valid_generated_unwind(
            ".xdata",
            0,
            0,
            4,
            UNWIND_CHARACTERISTICS,
        ));
        assert!(!valid_generated_unwind(
            ".xdata",
            0,
            1,
            4,
            UNWIND_CHARACTERISTICS,
        ));
        assert!(!valid_generated_unwind(
            ".xdata",
            0,
            0,
            8,
            UNWIND_CHARACTERISTICS,
        ));
    }

    #[test]
    fn large_padding_scans_observe_cancellation() {
        let padding = vec![0u8; 128 * 1024];
        assert_eq!(
            contains_nonzero(&padding, &|| true),
            Err(CodegenError::Cancelled)
        );
    }

    #[test]
    fn owned_sort_and_long_name_comparison_cancel_inside_work() {
        let mut pre_cancelled = vec!["right".to_owned(), "left".to_owned()];
        let comparisons = Cell::new(0usize);
        assert_eq!(
            cancellable_sort_owned_by(
                &mut pre_cancelled,
                |left, right| {
                    comparisons.set(comparisons.get().saturating_add(1));
                    Ok(left.cmp(right))
                },
                &|| true,
            ),
            Err(CodegenError::Cancelled)
        );
        assert_eq!(comparisons.get(), 0);
        assert_eq!(pre_cancelled, ["right", "left"]);

        let mut names = (0..64)
            .rev()
            .map(|index| format!("section-{index:04}"))
            .collect::<Vec<_>>();
        let polls = Cell::new(0usize);
        let comparisons = Cell::new(0usize);
        let cancelled = || {
            let next = polls.get().saturating_add(1);
            polls.set(next);
            next >= 140
        };
        assert_eq!(
            cancellable_sort_owned_by(
                &mut names,
                |left, right| {
                    comparisons.set(comparisons.get().saturating_add(1));
                    Ok(left.cmp(right))
                },
                &cancelled,
            ),
            Err(CodegenError::Cancelled)
        );
        assert_eq!(polls.get(), 140);
        assert!(comparisons.get() < 16, "sort continued after cancellation");

        let left = vec![b'a'; 4 * 1024];
        let mut right = left.clone();
        *right.last_mut().expect("nonempty long test name") = b'b';
        let polls = Cell::new(0usize);
        assert_eq!(
            cancellable_bytes_compare(&left, &right, &|| {
                let next = polls.get().saturating_add(1);
                polls.set(next);
                next >= 2
            }),
            Err(CodegenError::Cancelled)
        );
        assert_eq!(polls.get(), 2);
    }
}
