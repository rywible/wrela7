//! Mechanical LLVM translation from validated MachineWir to AArch64 COFF.
//! LLVM/Inkwell values and contexts never cross this crate boundary.

#![forbid(unsafe_code)]

use std::fmt;

use wrela_build_model::BuildIdentity;
#[cfg(any(feature = "llvm", test))]
use wrela_machine_wir::SymbolDefinition;
use wrela_machine_wir::ValidatedMachineWir;
use wrela_target::{ObjectFormat, TargetBackendContract};

#[cfg(any(feature = "llvm", test))]
mod coff;
#[cfg(any(feature = "llvm", test))]
mod ir;
#[cfg(feature = "llvm")]
mod native;
mod validate;

#[cfg(test)]
const MINIMUM_BACKEND_PROOF: &str = "the canonical empty Flow image body returns EFI_SUCCESS after successful runtime initialization without backend memory facts";
#[cfg(feature = "llvm")]
const PINNED_LLVM_VERSION: (u32, u32, u32) = (22, 1, 3);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodegenOptions {
    pub maximum_object_bytes: u64,
    pub maximum_sections: u32,
    pub maximum_symbols: u32,
    pub maximum_measurement_bytes: u64,
    pub maximum_types: u32,
    pub maximum_functions: u32,
    pub maximum_blocks: u64,
    pub maximum_instructions: u64,
    pub maximum_values: u64,
    pub maximum_model_edges: u64,
    pub maximum_ir_bytes: u64,
}

impl CodegenOptions {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            maximum_object_bytes: 4 * 1024 * 1024 * 1024,
            maximum_sections: 65_536,
            maximum_symbols: 16_000_000,
            maximum_measurement_bytes: 4 * 1024 * 1024 * 1024,
            maximum_types: 1_000_000,
            maximum_functions: 1_000_000,
            maximum_blocks: 16_000_000,
            maximum_instructions: 64_000_000,
            maximum_values: 64_000_000,
            maximum_model_edges: 256_000_000,
            maximum_ir_bytes: 4 * 1024 * 1024 * 1024,
        }
    }

    pub fn validate(self) -> Result<(), CodegenError> {
        if self.maximum_object_bytes == 0
            || self.maximum_sections == 0
            || self.maximum_symbols == 0
            || self.maximum_measurement_bytes == 0
            || self.maximum_types == 0
            || self.maximum_functions == 0
            || self.maximum_blocks == 0
            || self.maximum_instructions == 0
            || self.maximum_values == 0
            || self.maximum_model_edges == 0
            || self.maximum_ir_bytes == 0
        {
            Err(CodegenError::InvalidOptions)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
pub struct CodegenRequest<'a> {
    pub module: &'a ValidatedMachineWir,
    pub target: &'a TargetBackendContract,
    pub options: CodegenOptions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmittedSection {
    pub name: String,
    pub alignment: u32,
    /// Offset of the section's initialized bytes in the COFF object.
    pub file_offset: u64,
    pub file_bytes: u64,
    /// Addressable bytes, including zero-fill data not present in the file.
    pub virtual_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmittedSymbol {
    pub name: String,
    pub section: String,
    pub section_offset: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectArtifact {
    bytes: Vec<u8>,
    build: BuildIdentity,
    target_triple: String,
    format: ObjectFormat,
    sections: Vec<EmittedSection>,
    symbols: Vec<EmittedSymbol>,
}

impl ObjectArtifact {
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn build(&self) -> &BuildIdentity {
        &self.build
    }

    #[must_use]
    pub fn target_triple(&self) -> &str {
        &self.target_triple
    }

    #[must_use]
    pub fn format(&self) -> ObjectFormat {
        self.format
    }

    #[must_use]
    pub fn sections(&self) -> &[EmittedSection] {
        &self.sections
    }

    #[must_use]
    pub fn symbols(&self) -> &[EmittedSymbol] {
        &self.symbols
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

pub trait CodeGenerator {
    fn emit_object(
        &self,
        request: CodegenRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ObjectArtifact, CodegenError>;
}

/// Production revision-0.1 translator. The native LLVM implementation is
/// deliberately present only when the crate is built with the `llvm` feature.
#[derive(Debug, Clone, Copy, Default)]
pub struct CanonicalLlvmCodeGenerator;

impl CanonicalLlvmCodeGenerator {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl CodeGenerator for CanonicalLlvmCodeGenerator {
    fn emit_object(
        &self,
        request: CodegenRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ObjectArtifact, CodegenError> {
        preflight(&request, is_cancelled)?;
        #[cfg(feature = "llvm")]
        {
            native::emit_object(request, is_cancelled)
        }
        #[cfg(not(feature = "llvm"))]
        {
            let _ = request;
            Err(CodegenError::BackendNotBuilt)
        }
    }
}

/// Whether this crate instance contains the statically linked LLVM backend.
#[must_use]
pub const fn llvm_backend_available() -> bool {
    cfg!(feature = "llvm")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodegenError {
    BackendNotBuilt,
    Cancelled,
    InvalidOptions,
    TargetMismatch,
    TargetPackageMismatch,
    LlvmVersionMismatch {
        expected: (u32, u32, u32),
        observed: (u32, u32, u32),
    },
    TargetMachineMismatch(String),
    TargetInitialization(String),
    UnsupportedMachineContract(&'static str),
    UnsupportedMachineOperation {
        function: u32,
        instruction: u32,
    },
    UnsupportedMachineTerminator {
        function: u32,
        block: u32,
    },
    InvalidBackendFact {
        function: u32,
        instruction: u32,
        fact: &'static str,
    },
    ResourceLimit {
        resource: &'static str,
        limit: u64,
        actual: u64,
    },
    LlvmVerification(String),
    ObjectEmission(String),
    ObjectTooLarge {
        limit: u64,
        actual: u64,
    },
    InvalidObjectMeasurements(&'static str),
}

impl fmt::Display for CodegenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BackendNotBuilt => {
                formatter.write_str("LLVM codegen is absent from this developer build")
            }
            Self::Cancelled => formatter.write_str("LLVM code generation was cancelled"),
            Self::InvalidOptions => formatter.write_str("invalid LLVM code-generation options"),
            Self::TargetMismatch => {
                formatter.write_str("MachineWir target does not match codegen target")
            }
            Self::TargetPackageMismatch => formatter
                .write_str("MachineWir target-package digest does not match codegen target"),
            Self::LlvmVersionMismatch { expected, observed } => write!(
                formatter,
                "LLVM version mismatch: expected {}.{}.{}, observed {}.{}.{}",
                expected.0, expected.1, expected.2, observed.0, observed.1, observed.2
            ),
            Self::TargetMachineMismatch(reason) => {
                write!(formatter, "LLVM target-machine contract mismatch: {reason}")
            }
            Self::TargetInitialization(message) => {
                write!(
                    formatter,
                    "LLVM AArch64 target initialization failed: {message}"
                )
            }
            Self::UnsupportedMachineContract(feature) => {
                write!(formatter, "unsupported MachineWir contract: {feature}")
            }
            Self::UnsupportedMachineOperation {
                function,
                instruction,
            } => write!(
                formatter,
                "unsupported MachineWir operation at function {function}, instruction {instruction}"
            ),
            Self::UnsupportedMachineTerminator { function, block } => write!(
                formatter,
                "unsupported MachineWir terminator at function {function}, block {block}"
            ),
            Self::InvalidBackendFact {
                function,
                instruction,
                fact,
            } => write!(
                formatter,
                "unproved backend fact {fact} at function {function}, instruction {instruction}"
            ),
            Self::ResourceLimit {
                resource,
                limit,
                actual,
            } => write!(
                formatter,
                "LLVM code generation requires {actual} {resource}, exceeding {limit}"
            ),
            Self::LlvmVerification(message) => {
                write!(formatter, "LLVM verification failed: {message}")
            }
            Self::ObjectEmission(message) => {
                write!(formatter, "COFF object emission failed: {message}")
            }
            Self::ObjectTooLarge { limit, actual } => write!(
                formatter,
                "COFF object contains {actual} bytes, exceeding {limit}"
            ),
            Self::InvalidObjectMeasurements(reason) => {
                write!(formatter, "invalid COFF object measurements: {reason}")
            }
        }
    }
}

impl std::error::Error for CodegenError {}

fn preflight(
    request: &CodegenRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    validate::preflight(request, is_cancelled)
}

/// Seal bytes and measurements produced by the private LLVM implementation.
/// Test doubles use the same constructor, so orchestration cannot receive a
/// structurally impossible success artifact.
#[cfg(any(feature = "llvm", test))]
pub(crate) fn seal_object(
    request: &CodegenRequest<'_>,
    bytes: Vec<u8>,
    sections: Vec<EmittedSection>,
    symbols: Vec<EmittedSymbol>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ObjectArtifact, CodegenError> {
    preflight(request, is_cancelled)?;
    let machine = request.module.as_wir();
    let actual = u64::try_from(bytes.len()).map_err(|_| CodegenError::ObjectTooLarge {
        limit: request.options.maximum_object_bytes,
        actual: u64::MAX,
    })?;
    if actual == 0 || actual > request.options.maximum_object_bytes {
        return Err(CodegenError::ObjectTooLarge {
            limit: request.options.maximum_object_bytes,
            actual,
        });
    }
    let (derived_sections, derived_symbols) =
        coff::measure_object(&bytes, request.module, request.options, is_cancelled)?;
    if !emitted_measurements_equal(
        &derived_sections,
        &derived_symbols,
        &sections,
        &symbols,
        is_cancelled,
    )? {
        return Err(CodegenError::InvalidObjectMeasurements(
            "caller-supplied measurements differ from the emitted COFF",
        ));
    }
    let section_count = u64::try_from(sections.len()).unwrap_or(u64::MAX);
    let symbol_count = u64::try_from(symbols.len()).unwrap_or(u64::MAX);
    let mut measurement_bytes = 0u64;
    for (index, section) in sections.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        measurement_bytes = measurement_bytes
            .checked_add(u64::try_from(section.name.len()).unwrap_or(u64::MAX))
            .ok_or(CodegenError::InvalidObjectMeasurements(
                "section/symbol measurement bytes overflow",
            ))?;
    }
    for (index, symbol) in symbols.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        measurement_bytes = measurement_bytes
            .checked_add(u64::try_from(symbol.name.len()).unwrap_or(u64::MAX))
            .and_then(|bytes| {
                bytes.checked_add(u64::try_from(symbol.section.len()).unwrap_or(u64::MAX))
            })
            .ok_or(CodegenError::InvalidObjectMeasurements(
                "section/symbol measurement bytes overflow",
            ))?;
    }
    if section_count > u64::from(request.options.maximum_sections)
        || symbol_count > u64::from(request.options.maximum_symbols)
        || measurement_bytes > request.options.maximum_measurement_bytes
    {
        return Err(CodegenError::InvalidObjectMeasurements(
            "section/symbol measurements exceed codegen limits",
        ));
    }
    // IMAGE_FILE_MACHINE_ARM64 (0xAA64), little-endian. The pinned backend
    // emits ordinary COFF objects rather than anonymous BigObj records.
    if !bytes.starts_with(&[0x64, 0xaa]) || request.target.object_format() != ObjectFormat::Coff {
        return Err(CodegenError::InvalidObjectMeasurements(
            "object is not ordinary ARM64 COFF",
        ));
    }
    if !cancellable_text_equal(
        machine.build.target.as_str(),
        request.target.identity().as_str(),
        is_cancelled,
    )? || machine.build.target_package != request.target.content_digest()
        || !cancellable_text_equal(
            &machine.target.llvm_triple,
            request.target.llvm_triple(),
            is_cancelled,
        )?
    {
        return Err(CodegenError::TargetPackageMismatch);
    }
    let mut file_ranges = Vec::new();
    check_cancelled(is_cancelled)?;
    file_ranges.try_reserve_exact(sections.len()).map_err(|_| {
        CodegenError::InvalidObjectMeasurements(
            "could not reserve bounded section validation ranges",
        )
    })?;
    check_cancelled(is_cancelled)?;
    let mut previous_section_name = None;
    for (index, section) in sections.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        let end = section.file_offset.checked_add(section.file_bytes).ok_or(
            CodegenError::InvalidObjectMeasurements("section file range overflows"),
        )?;
        let name_is_noncanonical = if let Some(previous) = previous_section_name {
            cancellable_text_compare(previous, &section.name, is_cancelled)?
                != std::cmp::Ordering::Less
        } else {
            false
        };
        if section.name.is_empty()
            || name_is_noncanonical
            || !section.alignment.is_power_of_two()
            || section.file_bytes > section.virtual_bytes
            || end > actual
        {
            return Err(CodegenError::InvalidObjectMeasurements(
                "sections are empty, duplicate, overlapping, or outside object bytes",
            ));
        }
        previous_section_name = Some(section.name.as_str());
        file_ranges.push((section.file_offset, end));
    }
    if sections.is_empty() {
        return Err(CodegenError::InvalidObjectMeasurements(
            "sections are empty, duplicate, overlapping, or outside object bytes",
        ));
    }
    cancellable_sort_by(
        &mut file_ranges,
        |left, right| Ok(left.cmp(right)),
        is_cancelled,
    )?;
    for (index, pair) in file_ranges.windows(2).enumerate() {
        check_periodically(index, is_cancelled)?;
        let [left, right] = pair else {
            return Err(CodegenError::InvalidObjectMeasurements(
                "section range window is malformed",
            ));
        };
        if left.1 > right.0 {
            return Err(CodegenError::InvalidObjectMeasurements(
                "sections are empty, duplicate, overlapping, or outside object bytes",
            ));
        }
    }

    let mut previous_symbol_name = None;
    for (index, symbol) in symbols.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        let section = cancellable_binary_search_by(
            &sections,
            |section| cancellable_text_compare(&section.name, &symbol.section, is_cancelled),
            is_cancelled,
        )?
        .and_then(|position| sections.get(position));
        let name_is_noncanonical = if let Some(previous) = previous_symbol_name {
            cancellable_text_compare(previous, &symbol.name, is_cancelled)?
                != std::cmp::Ordering::Less
        } else {
            false
        };
        if symbol.name.is_empty()
            || name_is_noncanonical
            || section.is_none_or(|section| {
                symbol
                    .section_offset
                    .checked_add(symbol.bytes)
                    .is_none_or(|end| end > section.virtual_bytes)
            })
        {
            return Err(CodegenError::InvalidObjectMeasurements(
                "symbols are noncanonical or outside their named section",
            ));
        }
        previous_symbol_name = Some(symbol.name.as_str());
    }
    let mut expected_sections = Vec::new();
    check_cancelled(is_cancelled)?;
    expected_sections
        .try_reserve_exact(machine.sections.len())
        .map_err(|_| {
            CodegenError::InvalidObjectMeasurements(
                "could not reserve bounded expected section records",
            )
        })?;
    check_cancelled(is_cancelled)?;
    for (index, section) in machine.sections.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        expected_sections.push((section.name.as_str(), section));
    }
    cancellable_sort_by(
        &mut expected_sections,
        |left, right| cancellable_text_compare(left.0, right.0, is_cancelled),
        is_cancelled,
    )?;

    let mut expected_symbols = Vec::new();
    check_cancelled(is_cancelled)?;
    expected_symbols
        .try_reserve_exact(machine.symbols.len())
        .map_err(|_| {
            CodegenError::InvalidObjectMeasurements(
                "could not reserve bounded expected symbol records",
            )
        })?;
    check_cancelled(is_cancelled)?;
    for (index, symbol) in machine.symbols.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        if !matches!(symbol.definition, SymbolDefinition::ExternalRuntime(_)) {
            expected_symbols.push((symbol.name.as_str(), symbol));
        }
    }
    cancellable_sort_by(
        &mut expected_symbols,
        |left, right| cancellable_text_compare(left.0, right.0, is_cancelled),
        is_cancelled,
    )?;

    let mut section_names_match = expected_sections.len() == sections.len();
    if section_names_match {
        for (index, ((expected, _), actual)) in expected_sections.iter().zip(&sections).enumerate()
        {
            check_periodically(index, is_cancelled)?;
            if !cancellable_text_equal(expected, &actual.name, is_cancelled)? {
                section_names_match = false;
                break;
            }
        }
    }
    let mut symbol_names_match = expected_symbols.len() == symbols.len();
    if symbol_names_match {
        for (index, ((expected, _), actual)) in expected_symbols.iter().zip(&symbols).enumerate() {
            check_periodically(index, is_cancelled)?;
            if !cancellable_text_equal(expected, &actual.name, is_cancelled)? {
                symbol_names_match = false;
                break;
            }
        }
    }
    if !section_names_match || !symbol_names_match {
        return Err(CodegenError::InvalidObjectMeasurements(
            "emitted section or defined-symbol set differs from MachineWir",
        ));
    }

    for (index, emitted) in sections.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        let invalid = cancellable_binary_search_by(
            &expected_sections,
            |(name, _)| cancellable_text_compare(name, &emitted.name, is_cancelled),
            is_cancelled,
        )?
        .and_then(|position| expected_sections.get(position))
        .is_none_or(|(_, expected)| {
            emitted.alignment != expected.alignment
                || emitted.virtual_bytes > expected.reserved_bytes
        });
        if invalid {
            return Err(CodegenError::InvalidObjectMeasurements(
                "section layout or symbol placement differs from MachineWir",
            ));
        }
    }
    for (index, emitted) in symbols.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        let Some(expected) = cancellable_binary_search_by(
            &expected_symbols,
            |(name, _)| cancellable_text_compare(name, &emitted.name, is_cancelled),
            is_cancelled,
        )?
        .and_then(|position| expected_symbols.get(position).map(|(_, symbol)| *symbol)) else {
            return Err(CodegenError::InvalidObjectMeasurements(
                "section layout or symbol placement differs from MachineWir",
            ));
        };
        let expected_section = |section: wrela_machine_wir::SectionId| {
            machine
                .sections
                .get(section.0 as usize)
                .map(|section| section.name.as_str())
        };
        let invalid = match expected.definition {
            SymbolDefinition::Function(function) => match machine
                .functions
                .get(function.0 as usize)
                .and_then(|function| expected_section(function.section))
            {
                Some(section) => {
                    !cancellable_text_equal(&emitted.section, section, is_cancelled)?
                        || emitted.bytes == 0
                }
                None => true,
            },
            SymbolDefinition::Global(global) => {
                match machine.globals.get(global.0 as usize).and_then(|global| {
                    machine
                        .types
                        .get(global.ty.0 as usize)
                        .zip(expected_section(global.section))
                        .map(|(ty, section)| (global.offset, ty.size, section))
                }) {
                    Some((offset, bytes, section)) => {
                        !cancellable_text_equal(&emitted.section, section, is_cancelled)?
                            || emitted.section_offset != offset
                            || emitted.bytes != bytes
                    }
                    None => true,
                }
            }
            SymbolDefinition::SectionOffset {
                section,
                offset,
                bytes,
            } => match expected_section(section) {
                Some(section) => {
                    !cancellable_text_equal(&emitted.section, section, is_cancelled)?
                        || emitted.section_offset != offset
                        || emitted.bytes != bytes
                }
                None => true,
            },
            SymbolDefinition::ExternalRuntime(_) => true,
        };
        if invalid {
            return Err(CodegenError::InvalidObjectMeasurements(
                "section layout or symbol placement differs from MachineWir",
            ));
        }
    }
    let mut symbol_ranges = Vec::new();
    check_cancelled(is_cancelled)?;
    symbol_ranges
        .try_reserve_exact(symbols.len())
        .map_err(|_| {
            CodegenError::InvalidObjectMeasurements(
                "could not reserve bounded symbol validation ranges",
            )
        })?;
    check_cancelled(is_cancelled)?;
    for (index, symbol) in symbols.iter().enumerate() {
        check_periodically(index, is_cancelled)?;
        let end = symbol.section_offset.checked_add(symbol.bytes).ok_or(
            CodegenError::InvalidObjectMeasurements("emitted symbol range overflows"),
        )?;
        symbol_ranges.push((symbol.section.as_str(), symbol.section_offset, end));
    }
    cancellable_sort_by(
        &mut symbol_ranges,
        |left, right| {
            let section = cancellable_text_compare(left.0, right.0, is_cancelled)?;
            Ok(section.then_with(|| (left.1, left.2).cmp(&(right.1, right.2))))
        },
        is_cancelled,
    )?;
    for (index, pair) in symbol_ranges.windows(2).enumerate() {
        check_periodically(index, is_cancelled)?;
        let [left, right] = pair else {
            return Err(CodegenError::InvalidObjectMeasurements(
                "symbol range window is malformed",
            ));
        };
        if cancellable_text_equal(left.0, right.0, is_cancelled)? && left.2 > right.1 {
            return Err(CodegenError::InvalidObjectMeasurements(
                "emitted symbol ranges overlap",
            ));
        }
    }
    let target_triple = cancellable_copy_text(
        request.target.llvm_triple(),
        request.options.maximum_measurement_bytes,
        is_cancelled,
    )?;
    // BuildIdentity's only heap payload is a validated target identity, whose
    // schema caps the atom at 4 KiB. Keep that bounded clone bracketed by a
    // cancellation poll; the potentially MiB-scale target triple above is
    // copied in independently cancellable chunks.
    let build = machine.build.clone();
    check_cancelled(is_cancelled)?;
    Ok(ObjectArtifact {
        bytes,
        build,
        target_triple,
        format: request.target.object_format(),
        sections,
        symbols,
    })
}

fn cancellable_sort_by<T: Copy>(
    values: &mut [T],
    mut compare: impl FnMut(&T, &T) -> Result<std::cmp::Ordering, CodegenError>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodegenError> {
    if values.len() < 2 {
        return check_cancelled(is_cancelled);
    }
    check_cancelled(is_cancelled)?;
    let actual = u64::try_from(values.len()).unwrap_or(u64::MAX);
    let mut scratch = Vec::new();
    scratch
        .try_reserve_exact(values.len())
        .map_err(|_| CodegenError::ResourceLimit {
            resource: "cancellable sort scratch entries",
            limit: actual,
            actual,
        })?;
    check_cancelled(is_cancelled)?;
    for value in values.iter().copied() {
        check_cancelled(is_cancelled)?;
        scratch.push(value);
    }
    let mut width = 1usize;
    while width < values.len() {
        let mut start = 0usize;
        while start < values.len() {
            check_cancelled(is_cancelled)?;
            let middle = start.saturating_add(width).min(values.len());
            let end = middle.saturating_add(width).min(values.len());
            let (mut left, mut right, mut output) = (start, middle, start);
            while left < middle || right < end {
                check_cancelled(is_cancelled)?;
                let take_left = right == end
                    || (left < middle
                        && compare(&values[left], &values[right])? != std::cmp::Ordering::Greater);
                scratch[output] = if take_left {
                    let value = values[left];
                    left += 1;
                    value
                } else {
                    let value = values[right];
                    right += 1;
                    value
                };
                output += 1;
            }
            start = end;
        }
        for (index, value) in scratch.iter().copied().enumerate() {
            check_cancelled(is_cancelled)?;
            values[index] = value;
        }
        width = width.checked_mul(2).unwrap_or(values.len());
    }
    check_cancelled(is_cancelled)
}

#[cfg(any(feature = "llvm", test))]
fn emitted_measurements_equal(
    left_sections: &[EmittedSection],
    left_symbols: &[EmittedSymbol],
    right_sections: &[EmittedSection],
    right_symbols: &[EmittedSymbol],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, CodegenError> {
    if left_sections.len() != right_sections.len() || left_symbols.len() != right_symbols.len() {
        return Ok(false);
    }
    for (index, (left, right)) in left_sections.iter().zip(right_sections).enumerate() {
        check_periodically(index, is_cancelled)?;
        if !cancellable_text_equal(&left.name, &right.name, is_cancelled)?
            || left.alignment != right.alignment
            || left.file_offset != right.file_offset
            || left.file_bytes != right.file_bytes
            || left.virtual_bytes != right.virtual_bytes
        {
            return Ok(false);
        }
    }
    for (index, (left, right)) in left_symbols.iter().zip(right_symbols).enumerate() {
        check_periodically(index, is_cancelled)?;
        if !cancellable_text_equal(&left.name, &right.name, is_cancelled)?
            || !cancellable_text_equal(&left.section, &right.section, is_cancelled)?
            || left.section_offset != right.section_offset
            || left.bytes != right.bytes
        {
            return Ok(false);
        }
    }
    check_cancelled(is_cancelled)?;
    Ok(true)
}

fn cancellable_text_compare(
    left: &str,
    right: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<std::cmp::Ordering, CodegenError> {
    for (index, (left, right)) in left.bytes().zip(right.bytes()).enumerate() {
        check_periodically(index, is_cancelled)?;
        match left.cmp(&right) {
            std::cmp::Ordering::Equal => {}
            ordering => return Ok(ordering),
        }
    }
    check_cancelled(is_cancelled)?;
    Ok(left.len().cmp(&right.len()))
}

fn cancellable_text_equal(
    left: &str,
    right: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, CodegenError> {
    Ok(cancellable_text_compare(left, right, is_cancelled)? == std::cmp::Ordering::Equal)
}

#[cfg(any(feature = "llvm", test))]
fn cancellable_copy_text(
    value: &str,
    limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<String, CodegenError> {
    const CHUNK_BYTES: usize = 64 * 1024;

    let actual = u64::try_from(value.len()).unwrap_or(u64::MAX);
    if actual > limit {
        return Err(CodegenError::ResourceLimit {
            resource: "object artifact target triple bytes",
            limit,
            actual,
        });
    }
    check_cancelled(is_cancelled)?;
    let mut copied = String::new();
    copied
        .try_reserve_exact(value.len())
        .map_err(|_| CodegenError::ResourceLimit {
            resource: "object artifact target triple bytes",
            limit,
            actual,
        })?;
    check_cancelled(is_cancelled)?;
    let mut start = 0usize;
    while start < value.len() {
        check_cancelled(is_cancelled)?;
        let mut end = start.saturating_add(CHUNK_BYTES).min(value.len());
        while end > start && !value.is_char_boundary(end) {
            end -= 1;
        }
        if end == start {
            return Err(CodegenError::InvalidObjectMeasurements(
                "target triple has an invalid UTF-8 chunk boundary",
            ));
        }
        copied.push_str(&value[start..end]);
        start = end;
    }
    check_cancelled(is_cancelled)?;
    Ok(copied)
}

#[cfg(any(feature = "llvm", test))]
fn cancellable_binary_search_by<T>(
    values: &[T],
    mut compare: impl FnMut(&T) -> Result<std::cmp::Ordering, CodegenError>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Option<usize>, CodegenError> {
    let (mut left, mut right) = (0usize, values.len());
    while left < right {
        check_cancelled(is_cancelled)?;
        let middle = left + (right - left) / 2;
        match compare(&values[middle])? {
            std::cmp::Ordering::Less => left = middle + 1,
            std::cmp::Ordering::Greater => right = middle,
            std::cmp::Ordering::Equal => return Ok(Some(middle)),
        }
    }
    Ok(None)
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
mod contract_tests {
    use std::cell::Cell;

    use super::{
        CanonicalLlvmCodeGenerator, CodeGenerator, CodegenError, CodegenOptions, CodegenRequest,
        llvm_backend_available, seal_object,
    };
    use wrela_build_model::{
        BuildConfiguration, BuildProfile, OptimizationLevel, ValidatedBuildConfiguration,
        seal_build_configuration,
    };
    use wrela_build_model::{BuildIdentity, LanguageRevision, Sha256Digest, TargetIdentity};
    use wrela_flow_lower::{CanonicalFlowLowerer, FlowLowerer, LowerRequest, LoweringLimits};
    use wrela_flow_opt::{
        CanonicalFlowOptimizer, FlowOptimizer, OptimizationLimits, OptimizationProfile,
        OptimizationRequest,
    };
    use wrela_machine_lower::{
        CanonicalMachineLowerer, MachineLowerer, MachineLoweringLimits, MachineLoweringRequest,
    };
    use wrela_machine_wir::{
        ArithmeticOp, BackendFacts, BackendProof, BackendProofKind, BlockId, CallingConvention,
        CheckedIntegerOp, CheckedNumericKind, ConversionOp, DataLayout, Endianness, FloatPredicate,
        FunctionId, GlobalId, InstructionId, IntegerPredicate, IntegerSignedness, Linkage,
        MACHINE_WIR_VERSION, MachineAssertionFailure, MachineBlock, MachineFence, MachineFunction,
        MachineFunctionOrigin, MachineFunctionRole, MachineGlobal, MachineImmediate,
        MachineInstruction, MachineOperation, MachineTarget, MachineTerminator, MachineTestEntry,
        MachineTestId, MachineTestKind, MachineType, MachineTypeId, MachineTypeKind,
        MachineUnaryOp, MachineValue, MachineWir, MemorySemantics, ProofId, ScalarFailureKind,
        ScalarFailureProvenance, Section, SectionId, SectionKind, Symbol, SymbolDefinition,
        SymbolId, SymbolVisibility, ValidatedMachineWir, ValidationError, ValueId,
    };
    use wrela_runtime_abi::{
        INTERRUPT_ROUTE_LAYOUT, INTERRUPT_ROUTE_SECTION, INTERRUPT_ROUTE_TABLE_SYMBOL,
        RuntimeIntrinsic, RuntimeRequirements,
    };
    use wrela_semantic_wir as semantic;
    use wrela_source::{FileId, Span, TextRange};
    use wrela_target::TargetPackage;
    use wrela_test_model::{
        GuestTestOutcome, TEST_PROTOCOL_VERSION, TestEvent, TestEventKind, TestId,
    };
    use wrela_test_protocol::{CanonicalTestEventCodec, ProtocolLimits, seal_encoded_event};

    fn identity() -> BuildIdentity {
        BuildIdentity {
            compiler: Sha256Digest::from_bytes([0x31; 32]),
            language: LanguageRevision::Design0_1,
            target: TargetIdentity::aarch64_qemu_virt_uefi(),
            target_package: Sha256Digest::from_bytes([0x32; 32]),
            standard_library: Sha256Digest::from_bytes([0x33; 32]),
            source_graph: Sha256Digest::from_bytes([0x34; 32]),
            request: Sha256Digest::from_bytes([0x35; 32]),
            profile: Sha256Digest::from_bytes([0x36; 32]),
        }
    }

    fn machine_candidate() -> (MachineWir, TargetPackage) {
        let build = identity();
        let target = TargetPackage::aarch64_qemu_virt_uefi(build.target_package);
        let backend = target.backend();
        let mut machine = MachineWir {
            version: MACHINE_WIR_VERSION,
            name: "minimum-image".to_owned(),
            build,
            target: MachineTarget {
                identity: target.identity().as_str().to_owned(),
                llvm_triple: backend.llvm_triple().to_owned(),
                data_layout: backend.llvm_data_layout().to_owned(),
                cpu: backend.llvm_cpu().to_owned(),
                features: backend.llvm_features().to_vec(),
                coff_machine: backend.coff_machine().to_owned(),
            },
            layout: DataLayout {
                pointer_bits: 64,
                pointer_alignment: 8,
                stack_alignment: 16,
                aggregate_alignment: 8,
                maximum_object_alignment: 16,
                endianness: Endianness::Little,
            },
            runtime: RuntimeRequirements::new(Vec::new()),
            types: vec![
                MachineType {
                    id: MachineTypeId(0),
                    kind: MachineTypeKind::Void,
                    size: 0,
                    alignment: 1,
                    source_name: Some("unit".to_owned()),
                },
                MachineType {
                    id: MachineTypeId(1),
                    kind: MachineTypeKind::Pointer {
                        address_space: 0,
                        pointee: None,
                    },
                    size: 8,
                    alignment: 8,
                    source_name: None,
                },
                MachineType {
                    id: MachineTypeId(2),
                    kind: MachineTypeKind::Integer { bits: 64 },
                    size: 8,
                    alignment: 8,
                    source_name: None,
                },
            ],
            sections: vec![
                Section {
                    id: SectionId(0),
                    name: ".text".to_owned(),
                    kind: SectionKind::Code,
                    alignment: 16,
                    reserved_bytes: 640,
                    owner: "image".to_owned(),
                },
                Section {
                    id: SectionId(1),
                    name: INTERRUPT_ROUTE_SECTION.to_owned(),
                    kind: SectionKind::RuntimeMetadata,
                    alignment: INTERRUPT_ROUTE_LAYOUT.table_alignment,
                    reserved_bytes: u64::from(INTERRUPT_ROUTE_LAYOUT.header_bytes),
                    owner: "runtime".to_owned(),
                },
            ],
            symbols: vec![
                Symbol {
                    id: SymbolId(0),
                    name: backend.entry_symbol().to_owned(),
                    visibility: SymbolVisibility::ImageEntry,
                    definition: SymbolDefinition::Function(FunctionId(0)),
                },
                Symbol {
                    id: SymbolId(1),
                    name: INTERRUPT_ROUTE_TABLE_SYMBOL.to_owned(),
                    visibility: SymbolVisibility::RuntimeMetadata,
                    definition: SymbolDefinition::SectionOffset {
                        section: SectionId(1),
                        offset: 0,
                        bytes: u64::from(INTERRUPT_ROUTE_LAYOUT.header_bytes),
                    },
                },
            ],
            globals: Vec::new(),
            functions: vec![MachineFunction {
                id: FunctionId(0),
                flow_function: 0,
                origin: MachineFunctionOrigin::GeneratedImageEntry {
                    semantic_function: 0,
                    constructor: 0,
                },
                role: MachineFunctionRole::ImageEntry,
                symbol: SymbolId(0),
                section: SectionId(0),
                linkage: Linkage::ExportedEntry,
                convention: CallingConvention::UefiAarch64,
                parameters: vec![ValueId(0), ValueId(1)],
                result: MachineTypeId(2),
                proofs: Vec::new(),
                values: vec![
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
                ],
                stack_slots: Vec::new(),
                blocks: vec![MachineBlock {
                    id: BlockId(0),
                    parameters: Vec::new(),
                    instructions: vec![MachineInstruction {
                        id: InstructionId(0),
                        results: vec![ValueId(2)],
                        operation: MachineOperation::Immediate(MachineImmediate::Integer {
                            ty: MachineTypeId(2),
                            bytes_le: vec![0; 8],
                        }),
                        source: None,
                    }],
                    terminator: MachineTerminator::Return(vec![ValueId(2)]),
                }],
                entry: BlockId(0),
                stack_bytes: 0,
                source: None,
            }],
            activations: Vec::new(),
            region_storage: Vec::new(),
            interrupts: Vec::new(),
            tests: Vec::new(),
            proofs: vec![BackendProof {
                id: ProofId(0),
                source_proofs: vec![0, 1, 2],
                kind: BackendProofKind::ImageClosed,
                depends_on: Vec::new(),
                bound: None,
                sources: Vec::new(),
                statement: super::MINIMUM_BACKEND_PROOF.to_owned(),
                source: None,
            }],
            image_entry: FunctionId(0),
        };
        install_image_enter_contract(&mut machine);
        (machine, target)
    }

    fn fixture() -> (ValidatedMachineWir, TargetPackage) {
        let (machine, target) = machine_candidate();
        let validated = machine
            .validate_for_target(&target)
            .expect("valid minimum MachineWir fixture");
        (validated, target)
    }

    fn normal_cleanup_machine_fixture() -> (ValidatedMachineWir, TargetPackage) {
        let (mut machine, target) = machine_candidate();
        let cleanup_source = Span {
            file: FileId(0),
            range: TextRange { start: 40, end: 49 },
        };
        let scope_source = Span {
            file: FileId(0),
            range: TextRange { start: 70, end: 79 },
        };
        machine.name = "normal-scope-cleanup".to_owned();
        machine.types.extend([
            MachineType {
                id: MachineTypeId(3),
                kind: MachineTypeKind::Integer { bits: 32 },
                size: 4,
                alignment: 4,
                source_name: Some("u32".to_owned()),
            },
            MachineType {
                id: MachineTypeId(4),
                kind: MachineTypeKind::Struct {
                    fields: vec![wrela_machine_wir::MachineField {
                        ty: MachineTypeId(3),
                        offset: 0,
                    }],
                    packed: false,
                },
                size: 4,
                alignment: 4,
                source_name: Some("Masked".to_owned()),
            },
        ]);

        let mut metadata = machine.sections.remove(1);
        metadata.id = SectionId(3);
        machine.sections.extend([
            Section {
                id: SectionId(1),
                name: ".text.wrela.1".to_owned(),
                kind: SectionKind::Code,
                alignment: 16,
                reserved_bytes: 64,
                owner: "function".to_owned(),
            },
            Section {
                id: SectionId(2),
                name: ".text.wrela.2".to_owned(),
                kind: SectionKind::Code,
                alignment: 16,
                reserved_bytes: 64,
                owner: "function".to_owned(),
            },
            metadata,
        ]);

        let entry_symbol = machine.symbols.remove(0);
        let mut metadata_symbol = machine
            .symbols
            .iter()
            .find(|symbol| symbol.name == INTERRUPT_ROUTE_TABLE_SYMBOL)
            .cloned()
            .expect("interrupt metadata symbol");
        metadata_symbol.id = SymbolId(3);
        metadata_symbol.definition = SymbolDefinition::SectionOffset {
            section: SectionId(3),
            offset: 0,
            bytes: u64::from(INTERRUPT_ROUTE_LAYOUT.header_bytes),
        };
        let mut runtime_symbol = machine
            .symbols
            .iter()
            .find(|symbol| {
                symbol.definition == SymbolDefinition::ExternalRuntime(RuntimeIntrinsic::ImageEnter)
            })
            .cloned()
            .expect("image-enter symbol");
        runtime_symbol.id = SymbolId(4);
        machine.symbols = vec![
            entry_symbol,
            Symbol {
                id: SymbolId(1),
                name: "__wrela_fn_1".to_owned(),
                visibility: SymbolVisibility::Private,
                definition: SymbolDefinition::Function(FunctionId(1)),
            },
            Symbol {
                id: SymbolId(2),
                name: "__wrela_fn_2".to_owned(),
                visibility: SymbolVisibility::Private,
                definition: SymbolDefinition::Function(FunctionId(2)),
            },
            metadata_symbol,
            runtime_symbol,
        ];

        machine.proofs.extend([
            BackendProof {
                id: ProofId(1),
                source_proofs: vec![1],
                kind: BackendProofKind::CleanupAcyclic,
                depends_on: Vec::new(),
                bound: Some(0),
                sources: vec![cleanup_source],
                statement: "one pass-only scope exit helper".to_owned(),
                source: Some(cleanup_source),
            },
            BackendProof {
                id: ProofId(2),
                source_proofs: vec![2],
                kind: BackendProofKind::CleanupAcyclic,
                depends_on: vec![ProofId(1)],
                bound: Some(0),
                sources: vec![scope_source],
                statement: "one normal scope cleanup activation".to_owned(),
                source: Some(scope_source),
            },
        ]);
        let helper = MachineFunction {
            id: FunctionId(1),
            flow_function: 1,
            origin: MachineFunctionOrigin::SourceSemantic {
                semantic_function: 1,
            },
            role: MachineFunctionRole::Cleanup,
            symbol: SymbolId(1),
            section: SectionId(1),
            linkage: Linkage::Private,
            convention: CallingConvention::Internal,
            parameters: vec![ValueId(0)],
            result: MachineTypeId(0),
            proofs: vec![ProofId(1)],
            values: vec![MachineValue {
                id: ValueId(0),
                ty: MachineTypeId(4),
                source_name: Some("state".to_owned()),
            }],
            stack_slots: Vec::new(),
            blocks: vec![MachineBlock {
                id: BlockId(0),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: MachineTerminator::Return(Vec::new()),
            }],
            entry: BlockId(0),
            stack_bytes: 0,
            source: Some(cleanup_source),
        };
        let mut generated = helper.clone();
        generated.id = FunctionId(2);
        generated.flow_function = 2;
        generated.origin = MachineFunctionOrigin::GeneratedCleanup {
            semantic_function: 1,
            scope: 0,
        };
        generated.symbol = SymbolId(2);
        generated.section = SectionId(2);
        generated.proofs.push(ProofId(2));
        machine.functions.extend([helper, generated]);

        let entry = &mut machine.functions[0];
        entry.values.extend([
            MachineValue {
                id: ValueId(4),
                ty: MachineTypeId(3),
                source_name: None,
            },
            MachineValue {
                id: ValueId(5),
                ty: MachineTypeId(4),
                source_name: Some("mask".to_owned()),
            },
        ]);
        entry.blocks[0].instructions.extend([
            MachineInstruction {
                id: InstructionId(1),
                results: vec![ValueId(4)],
                operation: MachineOperation::Immediate(MachineImmediate::Integer {
                    ty: MachineTypeId(3),
                    bytes_le: 1_u32.to_le_bytes().to_vec(),
                }),
                source: Some(scope_source),
            },
            MachineInstruction {
                id: InstructionId(2),
                results: vec![ValueId(5)],
                operation: MachineOperation::MakeStruct {
                    ty: MachineTypeId(4),
                    fields: vec![ValueId(4)],
                },
                source: Some(scope_source),
            },
            MachineInstruction {
                id: InstructionId(3),
                results: Vec::new(),
                operation: MachineOperation::Call {
                    function: FunctionId(2),
                    arguments: vec![ValueId(5)],
                    convention: CallingConvention::Internal,
                },
                source: Some(scope_source),
            },
        ]);
        let mut next_instruction = 0_u32;
        for block in &mut entry.blocks {
            for instruction in &mut block.instructions {
                instruction.id = InstructionId(next_instruction);
                next_instruction += 1;
            }
        }
        machine.sections[0].reserved_bytes = 896;
        let validated = machine
            .validate_for_target(&target)
            .expect("valid authenticated cleanup MachineWir fixture");
        (validated, target)
    }

    fn storage_candidate() -> (MachineWir, TargetPackage) {
        let (mut machine, target) = machine_candidate();
        machine.name = "zero-initialized-storage-image".to_owned();
        machine.types.extend([
            MachineType {
                id: MachineTypeId(3),
                kind: MachineTypeKind::Integer { bits: 8 },
                size: 1,
                alignment: 1,
                source_name: Some("u8".to_owned()),
            },
            MachineType {
                id: MachineTypeId(4),
                kind: MachineTypeKind::Array {
                    element: MachineTypeId(3),
                    length: 8,
                },
                size: 8,
                alignment: 8,
                source_name: Some("storage-8".to_owned()),
            },
            MachineType {
                id: MachineTypeId(5),
                kind: MachineTypeKind::Array {
                    element: MachineTypeId(3),
                    length: 16,
                },
                size: 16,
                alignment: 8,
                source_name: Some("storage-16".to_owned()),
            },
        ]);
        machine.sections.extend([
            Section {
                id: SectionId(2),
                name: ".data".to_owned(),
                kind: SectionKind::WritableData,
                alignment: 8,
                reserved_bytes: 24,
                owner: "compiler-storage".to_owned(),
            },
            Section {
                id: SectionId(3),
                name: ".bss".to_owned(),
                kind: SectionKind::ZeroFill,
                alignment: 8,
                reserved_bytes: 24,
                owner: "compiler-storage".to_owned(),
            },
        ]);
        machine.symbols.extend([
            Symbol {
                id: SymbolId(3),
                name: "__wrela_data_0".to_owned(),
                visibility: SymbolVisibility::Private,
                definition: SymbolDefinition::Global(GlobalId(0)),
            },
            Symbol {
                id: SymbolId(4),
                name: "__wrela_data_1".to_owned(),
                visibility: SymbolVisibility::Private,
                definition: SymbolDefinition::Global(GlobalId(1)),
            },
            Symbol {
                id: SymbolId(5),
                name: "__wrela_bss_0".to_owned(),
                visibility: SymbolVisibility::Private,
                definition: SymbolDefinition::Global(GlobalId(2)),
            },
            Symbol {
                id: SymbolId(6),
                name: "__wrela_bss_1".to_owned(),
                visibility: SymbolVisibility::Private,
                definition: SymbolDefinition::Global(GlobalId(3)),
            },
        ]);
        machine.globals.extend([
            MachineGlobal {
                id: GlobalId(0),
                symbol: SymbolId(3),
                ty: MachineTypeId(4),
                section: SectionId(2),
                offset: 0,
                alignment: 8,
                initializer: MachineImmediate::Zero(MachineTypeId(4)),
            },
            MachineGlobal {
                id: GlobalId(1),
                symbol: SymbolId(4),
                ty: MachineTypeId(5),
                section: SectionId(2),
                offset: 8,
                alignment: 8,
                initializer: MachineImmediate::Zero(MachineTypeId(5)),
            },
            MachineGlobal {
                id: GlobalId(2),
                symbol: SymbolId(5),
                ty: MachineTypeId(4),
                section: SectionId(3),
                offset: 0,
                alignment: 8,
                initializer: MachineImmediate::Zero(MachineTypeId(4)),
            },
            MachineGlobal {
                id: GlobalId(3),
                symbol: SymbolId(6),
                ty: MachineTypeId(5),
                section: SectionId(3),
                offset: 8,
                alignment: 8,
                initializer: MachineImmediate::Zero(MachineTypeId(5)),
            },
        ]);

        let entry = machine
            .functions
            .get_mut(machine.image_entry.0 as usize)
            .expect("storage fixture image entry");
        entry.values.extend((4..=7).map(|id| MachineValue {
            id: ValueId(id),
            ty: MachineTypeId(1),
            source_name: None,
        }));
        let facts = BackendFacts {
            proof: ProofId(0),
            alignment: None,
            non_null: false,
            no_alias: false,
            in_bounds: false,
            no_unsigned_wrap: false,
            no_signed_wrap: false,
        };
        entry
            .blocks
            .get_mut(1)
            .and_then(|block| block.instructions.first_mut())
            .expect("storage fixture image-enter prologue")
            .id = InstructionId(9);
        let entry_body = entry
            .blocks
            .get_mut(0)
            .expect("storage fixture original entry body");
        for (index, global) in [GlobalId(0), GlobalId(1), GlobalId(2), GlobalId(3)]
            .into_iter()
            .enumerate()
        {
            let address = ValueId(u32::try_from(index + 4).expect("small storage value"));
            let instruction = u32::try_from(index * 2 + 1).expect("small storage instruction");
            entry_body.instructions.extend([
                MachineInstruction {
                    id: InstructionId(instruction),
                    results: vec![address],
                    operation: MachineOperation::GlobalAddress(global),
                    source: None,
                },
                MachineInstruction {
                    id: InstructionId(instruction + 1),
                    results: Vec::new(),
                    operation: MachineOperation::Store {
                        address,
                        value: ValueId(2),
                        semantics: MemorySemantics::Ordinary,
                        facts,
                    },
                    source: None,
                },
            ]);
        }
        (machine, target)
    }

    fn storage_fixture() -> (ValidatedMachineWir, TargetPackage) {
        let (machine, target) = storage_candidate();
        let validated = machine
            .validate_for_target(&target)
            .expect("valid zero-initialized storage MachineWir fixture");
        (validated, target)
    }

    fn scalar_fixture() -> (ValidatedMachineWir, TargetPackage) {
        let (mut machine, target) = machine_candidate();
        machine.name = "scalar-cfg-image".to_owned();
        machine.types.extend([
            MachineType {
                id: MachineTypeId(3),
                kind: MachineTypeKind::Integer { bits: 8 },
                size: 1,
                alignment: 1,
                source_name: Some("bool".to_owned()),
            },
            MachineType {
                id: MachineTypeId(4),
                kind: MachineTypeKind::Integer { bits: 32 },
                size: 4,
                alignment: 4,
                source_name: Some("u32".to_owned()),
            },
            MachineType {
                id: MachineTypeId(5),
                kind: MachineTypeKind::Float32,
                size: 4,
                alignment: 4,
                source_name: Some("f32".to_owned()),
            },
            MachineType {
                id: MachineTypeId(6),
                kind: MachineTypeKind::Float64,
                size: 8,
                alignment: 8,
                source_name: Some("f64".to_owned()),
            },
        ]);
        machine.sections = vec![
            Section {
                id: SectionId(0),
                name: ".text.wrela.entry".to_owned(),
                kind: SectionKind::Code,
                alignment: 16,
                reserved_bytes: 16 * 1024,
                owner: "image".to_owned(),
            },
            Section {
                id: SectionId(1),
                name: ".text.wrela.1".to_owned(),
                kind: SectionKind::Code,
                alignment: 16,
                reserved_bytes: 16 * 1024,
                owner: "function".to_owned(),
            },
            Section {
                id: SectionId(2),
                name: INTERRUPT_ROUTE_SECTION.to_owned(),
                kind: SectionKind::RuntimeMetadata,
                alignment: INTERRUPT_ROUTE_LAYOUT.table_alignment,
                reserved_bytes: u64::from(INTERRUPT_ROUTE_LAYOUT.header_bytes),
                owner: "runtime".to_owned(),
            },
        ];
        machine.symbols = vec![
            Symbol {
                id: SymbolId(0),
                name: target.backend().entry_symbol().to_owned(),
                visibility: SymbolVisibility::ImageEntry,
                definition: SymbolDefinition::Function(FunctionId(0)),
            },
            Symbol {
                id: SymbolId(1),
                name: "__wrela_fn_1".to_owned(),
                visibility: SymbolVisibility::Private,
                definition: SymbolDefinition::Function(FunctionId(1)),
            },
            Symbol {
                id: SymbolId(2),
                name: INTERRUPT_ROUTE_TABLE_SYMBOL.to_owned(),
                visibility: SymbolVisibility::RuntimeMetadata,
                definition: SymbolDefinition::SectionOffset {
                    section: SectionId(2),
                    offset: 0,
                    bytes: u64::from(INTERRUPT_ROUTE_LAYOUT.header_bytes),
                },
            },
        ];
        let facts = BackendFacts {
            proof: ProofId(0),
            alignment: None,
            non_null: false,
            no_alias: false,
            in_bounds: false,
            no_unsigned_wrap: false,
            no_signed_wrap: false,
        };
        machine.functions = vec![
            MachineFunction {
                id: FunctionId(0),
                flow_function: 0,
                origin: MachineFunctionOrigin::GeneratedImageEntry {
                    semantic_function: 0,
                    constructor: 0,
                },
                role: MachineFunctionRole::ImageEntry,
                symbol: SymbolId(0),
                section: SectionId(0),
                linkage: Linkage::ExportedEntry,
                convention: CallingConvention::UefiAarch64,
                parameters: vec![ValueId(0), ValueId(1)],
                result: MachineTypeId(2),
                proofs: Vec::new(),
                values: vec![
                    machine_value(0, 1),
                    machine_value(1, 1),
                    machine_value(2, 2),
                    machine_value(3, 1),
                    machine_value(4, 2),
                    machine_value(5, 2),
                    machine_value(6, 2),
                    machine_value(7, 3),
                    machine_value(8, 2),
                    machine_value(9, 2),
                    machine_value(10, 2),
                    machine_value(11, 2),
                ],
                stack_slots: Vec::new(),
                blocks: vec![
                    MachineBlock {
                        id: BlockId(0),
                        parameters: Vec::new(),
                        instructions: vec![
                            machine_instruction(
                                0,
                                &[2],
                                MachineOperation::Immediate(MachineImmediate::Integer {
                                    ty: MachineTypeId(2),
                                    bytes_le: 3u64.to_le_bytes().to_vec(),
                                }),
                            ),
                            machine_instruction(
                                1,
                                &[3],
                                MachineOperation::AddressOffset {
                                    base: ValueId(0),
                                    byte_offset: ValueId(2),
                                    facts,
                                },
                            ),
                            machine_instruction(
                                2,
                                &[4],
                                MachineOperation::Load {
                                    address: ValueId(3),
                                    ty: MachineTypeId(2),
                                    semantics: MemorySemantics::Ordinary,
                                    facts,
                                },
                            ),
                            machine_instruction(
                                3,
                                &[],
                                MachineOperation::Store {
                                    address: ValueId(3),
                                    value: ValueId(4),
                                    semantics: MemorySemantics::Ordinary,
                                    facts,
                                },
                            ),
                            machine_instruction(
                                4,
                                &[5],
                                MachineOperation::Call {
                                    function: FunctionId(1),
                                    arguments: vec![ValueId(4)],
                                    convention: CallingConvention::Internal,
                                },
                            ),
                            machine_instruction(
                                5,
                                &[6],
                                MachineOperation::Immediate(MachineImmediate::Integer {
                                    ty: MachineTypeId(2),
                                    bytes_le: vec![0; 8],
                                }),
                            ),
                            machine_instruction(
                                6,
                                &[7],
                                MachineOperation::IntegerCompare {
                                    predicate: IntegerPredicate::NotEqual,
                                    left: ValueId(5),
                                    right: ValueId(6),
                                },
                            ),
                        ],
                        terminator: MachineTerminator::Branch {
                            condition: ValueId(7),
                            then_block: BlockId(1),
                            then_arguments: vec![ValueId(5)],
                            else_block: BlockId(2),
                            else_arguments: vec![ValueId(6)],
                        },
                    },
                    MachineBlock {
                        id: BlockId(1),
                        parameters: vec![ValueId(8)],
                        instructions: Vec::new(),
                        terminator: MachineTerminator::Jump {
                            block: BlockId(3),
                            arguments: vec![ValueId(8)],
                        },
                    },
                    MachineBlock {
                        id: BlockId(2),
                        parameters: vec![ValueId(9)],
                        instructions: vec![machine_instruction(
                            7,
                            &[10],
                            MachineOperation::Select {
                                condition: ValueId(7),
                                then_value: ValueId(9),
                                else_value: ValueId(6),
                            },
                        )],
                        terminator: MachineTerminator::Jump {
                            block: BlockId(3),
                            arguments: vec![ValueId(10)],
                        },
                    },
                    MachineBlock {
                        id: BlockId(3),
                        parameters: vec![ValueId(11)],
                        instructions: vec![
                            machine_instruction(
                                8,
                                &[],
                                MachineOperation::Fence(MachineFence::AcquireRelease),
                            ),
                            machine_instruction(
                                9,
                                &[],
                                MachineOperation::Fence(MachineFence::DeviceFull),
                            ),
                        ],
                        terminator: MachineTerminator::Return(vec![ValueId(11)]),
                    },
                ],
                entry: BlockId(0),
                stack_bytes: 0,
                source: None,
            },
            MachineFunction {
                id: FunctionId(1),
                flow_function: 1,
                origin: MachineFunctionOrigin::SourceSemantic {
                    semantic_function: 1,
                },
                role: MachineFunctionRole::Ordinary,
                symbol: SymbolId(1),
                section: SectionId(1),
                linkage: Linkage::Private,
                convention: CallingConvention::Internal,
                parameters: vec![ValueId(0)],
                result: MachineTypeId(2),
                proofs: Vec::new(),
                values: vec![
                    machine_value(0, 2),
                    machine_value(1, 2),
                    machine_value(2, 2),
                    machine_value(3, 5),
                    machine_value(4, 5),
                    machine_value(5, 5),
                    machine_value(6, 3),
                    machine_value(7, 5),
                    machine_value(8, 4),
                    machine_value(9, 2),
                    machine_value(10, 2),
                    machine_value(11, 2),
                    machine_value(12, 2),
                    machine_value(13, 2),
                    machine_value(14, 2),
                    machine_value(15, 2),
                    machine_value(16, 3),
                    machine_value(17, 3),
                    machine_value(18, 3),
                    machine_value(19, 3),
                    machine_value(20, 3),
                    machine_value(21, 3),
                    machine_value(22, 3),
                    machine_value(23, 3),
                    machine_value(24, 3),
                    machine_value(25, 3),
                    machine_value(26, 2),
                    machine_value(27, 3),
                    machine_value(28, 6),
                    machine_value(29, 6),
                    machine_value(30, 3),
                ],
                stack_slots: Vec::new(),
                blocks: vec![
                    MachineBlock {
                        id: BlockId(0),
                        parameters: Vec::new(),
                        instructions: vec![
                            machine_instruction(
                                0,
                                &[1],
                                MachineOperation::Immediate(MachineImmediate::Integer {
                                    ty: MachineTypeId(2),
                                    bytes_le: 1u64.to_le_bytes().to_vec(),
                                }),
                            ),
                            machine_instruction(
                                1,
                                &[2],
                                MachineOperation::Arithmetic {
                                    op: ArithmeticOp::IntegerAdd,
                                    left: ValueId(0),
                                    right: ValueId(1),
                                },
                            ),
                            machine_instruction(
                                2,
                                &[3],
                                MachineOperation::Immediate(MachineImmediate::Float32(0x7fc0_0000)),
                            ),
                            machine_instruction(
                                3,
                                &[4],
                                MachineOperation::Immediate(MachineImmediate::Float32(
                                    2.0f32.to_bits(),
                                )),
                            ),
                            machine_instruction(
                                4,
                                &[5],
                                MachineOperation::Arithmetic {
                                    op: ArithmeticOp::FloatAdd,
                                    left: ValueId(3),
                                    right: ValueId(4),
                                },
                            ),
                            machine_instruction(
                                5,
                                &[6],
                                MachineOperation::FloatCompare {
                                    predicate: FloatPredicate::OrderedLess,
                                    left: ValueId(3),
                                    right: ValueId(5),
                                },
                            ),
                            machine_instruction(
                                6,
                                &[7],
                                MachineOperation::Select {
                                    condition: ValueId(6),
                                    then_value: ValueId(3),
                                    else_value: ValueId(5),
                                },
                            ),
                            machine_instruction(
                                7,
                                &[8],
                                MachineOperation::Convert {
                                    op: ConversionOp::Bitcast,
                                    value: ValueId(7),
                                    destination: MachineTypeId(4),
                                },
                            ),
                            machine_instruction(
                                8,
                                &[11],
                                MachineOperation::Arithmetic {
                                    op: ArithmeticOp::IntegerSubtract,
                                    left: ValueId(2),
                                    right: ValueId(1),
                                },
                            ),
                            machine_instruction(
                                9,
                                &[12],
                                MachineOperation::Arithmetic {
                                    op: ArithmeticOp::IntegerMultiply,
                                    left: ValueId(11),
                                    right: ValueId(1),
                                },
                            ),
                            machine_instruction(
                                10,
                                &[13],
                                MachineOperation::Arithmetic {
                                    op: ArithmeticOp::BitAnd,
                                    left: ValueId(12),
                                    right: ValueId(2),
                                },
                            ),
                            machine_instruction(
                                11,
                                &[14],
                                MachineOperation::Arithmetic {
                                    op: ArithmeticOp::BitOr,
                                    left: ValueId(13),
                                    right: ValueId(1),
                                },
                            ),
                            machine_instruction(
                                12,
                                &[15],
                                MachineOperation::Arithmetic {
                                    op: ArithmeticOp::BitXor,
                                    left: ValueId(14),
                                    right: ValueId(2),
                                },
                            ),
                            machine_instruction(
                                13,
                                &[16],
                                MachineOperation::IntegerCompare {
                                    predicate: IntegerPredicate::Equal,
                                    left: ValueId(15),
                                    right: ValueId(2),
                                },
                            ),
                            machine_instruction(
                                14,
                                &[17],
                                MachineOperation::IntegerCompare {
                                    predicate: IntegerPredicate::NotEqual,
                                    left: ValueId(15),
                                    right: ValueId(2),
                                },
                            ),
                            machine_instruction(
                                15,
                                &[18],
                                MachineOperation::IntegerCompare {
                                    predicate: IntegerPredicate::UnsignedLess,
                                    left: ValueId(15),
                                    right: ValueId(2),
                                },
                            ),
                            machine_instruction(
                                16,
                                &[19],
                                MachineOperation::IntegerCompare {
                                    predicate: IntegerPredicate::UnsignedLessEqual,
                                    left: ValueId(15),
                                    right: ValueId(2),
                                },
                            ),
                            machine_instruction(
                                17,
                                &[20],
                                MachineOperation::IntegerCompare {
                                    predicate: IntegerPredicate::UnsignedGreater,
                                    left: ValueId(15),
                                    right: ValueId(2),
                                },
                            ),
                            machine_instruction(
                                18,
                                &[21],
                                MachineOperation::IntegerCompare {
                                    predicate: IntegerPredicate::UnsignedGreaterEqual,
                                    left: ValueId(15),
                                    right: ValueId(2),
                                },
                            ),
                            machine_instruction(
                                19,
                                &[22],
                                MachineOperation::IntegerCompare {
                                    predicate: IntegerPredicate::SignedLess,
                                    left: ValueId(15),
                                    right: ValueId(2),
                                },
                            ),
                            machine_instruction(
                                20,
                                &[23],
                                MachineOperation::IntegerCompare {
                                    predicate: IntegerPredicate::SignedLessEqual,
                                    left: ValueId(15),
                                    right: ValueId(2),
                                },
                            ),
                            machine_instruction(
                                21,
                                &[24],
                                MachineOperation::IntegerCompare {
                                    predicate: IntegerPredicate::SignedGreater,
                                    left: ValueId(15),
                                    right: ValueId(2),
                                },
                            ),
                            machine_instruction(
                                22,
                                &[25],
                                MachineOperation::IntegerCompare {
                                    predicate: IntegerPredicate::SignedGreaterEqual,
                                    left: ValueId(15),
                                    right: ValueId(2),
                                },
                            ),
                            machine_instruction(
                                23,
                                &[26],
                                MachineOperation::Select {
                                    condition: ValueId(16),
                                    then_value: ValueId(15),
                                    else_value: ValueId(2),
                                },
                            ),
                            machine_instruction(
                                24,
                                &[27],
                                MachineOperation::FloatCompare {
                                    predicate: FloatPredicate::UnorderedNotEqual,
                                    left: ValueId(3),
                                    right: ValueId(4),
                                },
                            ),
                            machine_instruction(
                                25,
                                &[28],
                                MachineOperation::Immediate(MachineImmediate::Float64(
                                    0x7ff8_0000_0000_0000,
                                )),
                            ),
                            machine_instruction(
                                26,
                                &[29],
                                MachineOperation::Immediate(MachineImmediate::Float64(0)),
                            ),
                            machine_instruction(
                                27,
                                &[30],
                                MachineOperation::FloatCompare {
                                    predicate: FloatPredicate::UnorderedNotEqual,
                                    left: ValueId(28),
                                    right: ValueId(29),
                                },
                            ),
                        ],
                        terminator: MachineTerminator::Switch {
                            value: ValueId(26),
                            cases: vec![
                                (0, BlockId(1), vec![ValueId(1)]),
                                (1, BlockId(2), vec![ValueId(2)]),
                            ],
                            default: BlockId(3),
                            default_arguments: Vec::new(),
                        },
                    },
                    MachineBlock {
                        id: BlockId(1),
                        parameters: vec![ValueId(9)],
                        instructions: Vec::new(),
                        terminator: MachineTerminator::Return(vec![ValueId(9)]),
                    },
                    MachineBlock {
                        id: BlockId(2),
                        parameters: vec![ValueId(10)],
                        instructions: Vec::new(),
                        terminator: MachineTerminator::TailCall {
                            function: FunctionId(1),
                            arguments: vec![ValueId(10)],
                        },
                    },
                    MachineBlock {
                        id: BlockId(3),
                        parameters: Vec::new(),
                        instructions: Vec::new(),
                        terminator: MachineTerminator::Unreachable,
                    },
                ],
                entry: BlockId(0),
                stack_bytes: 0,
                source: Some(Span {
                    file: FileId(0),
                    range: TextRange { start: 1, end: 2 },
                }),
            },
        ];
        install_image_enter_contract(&mut machine);
        let machine = machine
            .validate_for_target(&target)
            .expect("valid checked multi-function scalar MachineWir fixture");
        (machine, target)
    }

    fn unary_cast_scalar_fixture() -> (ValidatedMachineWir, TargetPackage) {
        let (machine, target) = scalar_fixture();
        let mut machine = machine.as_wir().clone();
        machine.name = "unary-cast-scalar-image".to_owned();
        machine.types.push(MachineType {
            id: MachineTypeId(7),
            kind: MachineTypeKind::Integer { bits: 16 },
            size: 2,
            alignment: 2,
            source_name: Some("u16-or-i16".to_owned()),
        });
        let function = machine
            .functions
            .get_mut(1)
            .expect("scalar fixture ordinary function");
        function.values.extend([
            machine_value(31, 3),
            machine_value(32, 3),
            machine_value(33, 3),
            machine_value(34, 3),
            machine_value(35, 5),
            machine_value(36, 5),
            machine_value(37, 6),
            machine_value(38, 6),
            machine_value(39, 7),
            machine_value(40, 7),
            machine_value(41, 6),
            machine_value(42, 5),
            machine_value(43, 5),
            machine_value(44, 4),
            machine_value(45, 5),
        ]);
        let block = function
            .blocks
            .get_mut(0)
            .expect("scalar fixture entry block");
        block.instructions.extend([
            machine_instruction(
                28,
                &[31],
                MachineOperation::Immediate(MachineImmediate::Integer {
                    ty: MachineTypeId(3),
                    bytes_le: vec![1],
                }),
            ),
            machine_instruction(
                29,
                &[32],
                MachineOperation::Unary {
                    op: MachineUnaryOp::BoolNot,
                    value: ValueId(31),
                },
            ),
            machine_instruction(
                30,
                &[33],
                MachineOperation::Immediate(MachineImmediate::Integer {
                    ty: MachineTypeId(3),
                    bytes_le: vec![0x0f],
                }),
            ),
            machine_instruction(
                31,
                &[34],
                MachineOperation::Unary {
                    op: MachineUnaryOp::BitNot,
                    value: ValueId(33),
                },
            ),
            machine_instruction(
                32,
                &[35],
                MachineOperation::Immediate(MachineImmediate::Float32(0x7fc0_0000)),
            ),
            machine_instruction(
                33,
                &[36],
                MachineOperation::Unary {
                    op: MachineUnaryOp::FloatNegate,
                    value: ValueId(35),
                },
            ),
            machine_instruction(
                34,
                &[37],
                MachineOperation::Immediate(MachineImmediate::Float64(1.5_f64.to_bits())),
            ),
            machine_instruction(
                35,
                &[38],
                MachineOperation::Unary {
                    op: MachineUnaryOp::FloatNegate,
                    value: ValueId(37),
                },
            ),
            machine_instruction(
                36,
                &[39],
                MachineOperation::Convert {
                    op: ConversionOp::ZeroExtend,
                    value: ValueId(33),
                    destination: MachineTypeId(7),
                },
            ),
            machine_instruction(
                37,
                &[40],
                MachineOperation::Convert {
                    op: ConversionOp::SignExtend,
                    value: ValueId(33),
                    destination: MachineTypeId(7),
                },
            ),
            machine_instruction(
                38,
                &[41],
                MachineOperation::Convert {
                    op: ConversionOp::FloatExtend,
                    value: ValueId(35),
                    destination: MachineTypeId(6),
                },
            ),
            machine_instruction(
                39,
                &[42],
                MachineOperation::Convert {
                    op: ConversionOp::UnsignedIntegerToFloat,
                    value: ValueId(33),
                    destination: MachineTypeId(5),
                },
            ),
            machine_instruction(
                40,
                &[43],
                MachineOperation::Convert {
                    op: ConversionOp::SignedIntegerToFloat,
                    value: ValueId(33),
                    destination: MachineTypeId(5),
                },
            ),
            machine_instruction(
                41,
                &[44],
                MachineOperation::Convert {
                    op: ConversionOp::Bitcast,
                    value: ValueId(35),
                    destination: MachineTypeId(4),
                },
            ),
            machine_instruction(
                42,
                &[45],
                MachineOperation::Convert {
                    op: ConversionOp::Bitcast,
                    value: ValueId(44),
                    destination: MachineTypeId(5),
                },
            ),
        ]);
        let machine = machine
            .validate_for_target(&target)
            .expect("valid unary and exact-cast scalar MachineWir fixture");
        (machine, target)
    }

    fn machine_value(id: u32, ty: u32) -> MachineValue {
        MachineValue {
            id: ValueId(id),
            ty: MachineTypeId(ty),
            source_name: None,
        }
    }

    fn machine_instruction(
        id: u32,
        results: &[u32],
        operation: MachineOperation,
    ) -> MachineInstruction {
        MachineInstruction {
            id: InstructionId(id),
            results: results.iter().copied().map(ValueId).collect(),
            operation,
            source: None,
        }
    }

    fn install_image_enter_contract(machine: &mut MachineWir) {
        if !machine
            .runtime
            .intrinsics
            .contains(&RuntimeIntrinsic::ImageEnter)
        {
            machine
                .runtime
                .intrinsics
                .push(RuntimeIntrinsic::ImageEnter);
            machine.runtime.intrinsics.sort_unstable();
        }
        if !machine.symbols.iter().any(|symbol| {
            symbol.definition == SymbolDefinition::ExternalRuntime(RuntimeIntrinsic::ImageEnter)
        }) {
            machine.symbols.push(Symbol {
                id: SymbolId(u32::try_from(machine.symbols.len()).expect("small fixture symbols")),
                name: RuntimeIntrinsic::ImageEnter.symbol_name().to_owned(),
                visibility: SymbolVisibility::Runtime,
                definition: SymbolDefinition::ExternalRuntime(RuntimeIntrinsic::ImageEnter),
            });
        }

        let entry = machine
            .functions
            .get_mut(machine.image_entry.0 as usize)
            .expect("fixture image entry");
        if entry
            .blocks
            .get(entry.entry.0 as usize)
            .is_some_and(|block| {
                matches!(
                    block.instructions.as_slice(),
                    [MachineInstruction {
                        operation: MachineOperation::RuntimeCall {
                            intrinsic: RuntimeIntrinsic::ImageEnter,
                            ..
                        },
                        ..
                    }]
                )
            })
        {
            return;
        }

        let status = ValueId(u32::try_from(entry.values.len()).expect("small fixture values"));
        entry.values.push(MachineValue {
            id: status,
            ty: entry.result,
            source_name: None,
        });
        let prior_entry = entry.entry;
        let prologue = BlockId(u32::try_from(entry.blocks.len()).expect("small fixture blocks"));
        let failure = BlockId(prologue.0.checked_add(1).expect("small fixture blocks"));
        let instruction = InstructionId(
            u32::try_from(
                entry
                    .blocks
                    .iter()
                    .map(|block| block.instructions.len())
                    .sum::<usize>(),
            )
            .expect("small fixture instructions"),
        );
        entry.blocks.push(MachineBlock {
            id: prologue,
            parameters: Vec::new(),
            instructions: vec![MachineInstruction {
                id: instruction,
                results: vec![status],
                operation: MachineOperation::RuntimeCall {
                    intrinsic: RuntimeIntrinsic::ImageEnter,
                    arguments: vec![ValueId(0), ValueId(1)],
                },
                source: None,
            }],
            terminator: MachineTerminator::Switch {
                value: status,
                cases: vec![(0, prior_entry, Vec::new())],
                default: failure,
                default_arguments: Vec::new(),
            },
        });
        entry.blocks.push(MachineBlock {
            id: failure,
            parameters: Vec::new(),
            instructions: Vec::new(),
            terminator: MachineTerminator::Return(vec![status]),
        });
        entry.entry = prologue;
    }

    fn canonical_passing_frames(test: TestId) -> Vec<Vec<u8>> {
        let events = [
            TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 0,
                kind: TestEventKind::RunStarted { test_count: 1 },
            },
            TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 1,
                kind: TestEventKind::TestStarted { test },
            },
            TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence: 2,
                kind: TestEventKind::TestFinished {
                    test,
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

    fn runtime_test_fixture() -> (ValidatedMachineWir, TargetPackage, Vec<Vec<u8>>) {
        runtime_test_fixture_with_frames(canonical_passing_frames(TestId(1)))
    }

    fn runtime_test_fixture_with_frames(
        frames: Vec<Vec<u8>>,
    ) -> (ValidatedMachineWir, TargetPackage, Vec<Vec<u8>>) {
        let (mut machine, target) = machine_candidate();
        assert_eq!(frames.len(), 4, "runtime fixture requires four frames");
        let frame_lengths = frames
            .iter()
            .map(|frame| u64::try_from(frame.len()).expect("small test frame"))
            .collect::<Vec<_>>();
        let payload_bytes = frame_lengths.iter().sum();
        let test_source = Span {
            file: FileId(0),
            range: TextRange { start: 4, end: 12 },
        };
        machine.name = "runtime-test-image".to_owned();
        machine.runtime = RuntimeRequirements::new(vec![
            RuntimeIntrinsic::TestEmit,
            RuntimeIntrinsic::TestFinish,
        ]);
        machine.types.extend([
            MachineType {
                id: MachineTypeId(3),
                kind: MachineTypeKind::Integer { bits: 8 },
                size: 1,
                alignment: 1,
                source_name: Some("u8".to_owned()),
            },
            MachineType {
                id: MachineTypeId(4),
                kind: MachineTypeKind::Array {
                    element: MachineTypeId(3),
                    length: frame_lengths[0],
                },
                size: frame_lengths[0],
                alignment: 1,
                source_name: Some("test-frame-start".to_owned()),
            },
            MachineType {
                id: MachineTypeId(5),
                kind: MachineTypeKind::Array {
                    element: MachineTypeId(3),
                    length: frame_lengths[1],
                },
                size: frame_lengths[1],
                alignment: 1,
                source_name: Some("test-frame-finish".to_owned()),
            },
            MachineType {
                id: MachineTypeId(6),
                kind: MachineTypeKind::Array {
                    element: MachineTypeId(3),
                    length: frame_lengths[2],
                },
                size: frame_lengths[2],
                alignment: 1,
                source_name: Some("test-frame-passed".to_owned()),
            },
            MachineType {
                id: MachineTypeId(7),
                kind: MachineTypeKind::Array {
                    element: MachineTypeId(3),
                    length: frame_lengths[3],
                },
                size: frame_lengths[3],
                alignment: 1,
                source_name: Some("test-frame-summary".to_owned()),
            },
            MachineType {
                id: MachineTypeId(8),
                kind: MachineTypeKind::Integer { bits: 32 },
                size: 4,
                alignment: 4,
                source_name: Some("u32".to_owned()),
            },
        ]);
        machine.sections = vec![
            Section {
                id: SectionId(0),
                name: ".text.wrela.entry".to_owned(),
                kind: SectionKind::Code,
                alignment: 16,
                reserved_bytes: 16 * 1024,
                owner: "generated-test-harness".to_owned(),
            },
            Section {
                id: SectionId(1),
                name: ".text.wrela.1".to_owned(),
                kind: SectionKind::Code,
                alignment: 16,
                reserved_bytes: 16 * 1024,
                owner: "test".to_owned(),
            },
            Section {
                id: SectionId(2),
                name: ".rdata.wrela.test".to_owned(),
                kind: SectionKind::ReadOnlyData,
                alignment: 8,
                reserved_bytes: payload_bytes,
                owner: "generated-test-harness".to_owned(),
            },
            Section {
                id: SectionId(3),
                name: INTERRUPT_ROUTE_SECTION.to_owned(),
                kind: SectionKind::RuntimeMetadata,
                alignment: INTERRUPT_ROUTE_LAYOUT.table_alignment,
                reserved_bytes: u64::from(INTERRUPT_ROUTE_LAYOUT.header_bytes),
                owner: "runtime".to_owned(),
            },
        ];
        machine.symbols = vec![
            Symbol {
                id: SymbolId(0),
                name: target.backend().entry_symbol().to_owned(),
                visibility: SymbolVisibility::ImageEntry,
                definition: SymbolDefinition::Function(FunctionId(0)),
            },
            Symbol {
                id: SymbolId(1),
                name: "__wrela_fn_1".to_owned(),
                visibility: SymbolVisibility::Private,
                definition: SymbolDefinition::Function(FunctionId(1)),
            },
            Symbol {
                id: SymbolId(2),
                name: "__wrela_test_frame_0".to_owned(),
                visibility: SymbolVisibility::Private,
                definition: SymbolDefinition::Global(GlobalId(0)),
            },
            Symbol {
                id: SymbolId(3),
                name: "__wrela_test_frame_1".to_owned(),
                visibility: SymbolVisibility::Private,
                definition: SymbolDefinition::Global(GlobalId(1)),
            },
            Symbol {
                id: SymbolId(4),
                name: "__wrela_test_frame_2".to_owned(),
                visibility: SymbolVisibility::Private,
                definition: SymbolDefinition::Global(GlobalId(2)),
            },
            Symbol {
                id: SymbolId(5),
                name: "__wrela_test_frame_3".to_owned(),
                visibility: SymbolVisibility::Private,
                definition: SymbolDefinition::Global(GlobalId(3)),
            },
            Symbol {
                id: SymbolId(6),
                name: RuntimeIntrinsic::TestEmit.symbol_name().to_owned(),
                visibility: SymbolVisibility::Runtime,
                definition: SymbolDefinition::ExternalRuntime(RuntimeIntrinsic::TestEmit),
            },
            Symbol {
                id: SymbolId(7),
                name: RuntimeIntrinsic::TestFinish.symbol_name().to_owned(),
                visibility: SymbolVisibility::Runtime,
                definition: SymbolDefinition::ExternalRuntime(RuntimeIntrinsic::TestFinish),
            },
            Symbol {
                id: SymbolId(8),
                name: INTERRUPT_ROUTE_TABLE_SYMBOL.to_owned(),
                visibility: SymbolVisibility::RuntimeMetadata,
                definition: SymbolDefinition::SectionOffset {
                    section: SectionId(3),
                    offset: 0,
                    bytes: u64::from(INTERRUPT_ROUTE_LAYOUT.header_bytes),
                },
            },
        ];
        machine.globals = vec![
            MachineGlobal {
                id: GlobalId(0),
                symbol: SymbolId(2),
                ty: MachineTypeId(4),
                section: SectionId(2),
                offset: 0,
                alignment: 1,
                initializer: MachineImmediate::Bytes(frames[0].clone()),
            },
            MachineGlobal {
                id: GlobalId(1),
                symbol: SymbolId(3),
                ty: MachineTypeId(5),
                section: SectionId(2),
                offset: frame_lengths[0],
                alignment: 1,
                initializer: MachineImmediate::Bytes(frames[1].clone()),
            },
            MachineGlobal {
                id: GlobalId(2),
                symbol: SymbolId(4),
                ty: MachineTypeId(6),
                section: SectionId(2),
                offset: frame_lengths[0] + frame_lengths[1],
                alignment: 1,
                initializer: MachineImmediate::Bytes(frames[2].clone()),
            },
            MachineGlobal {
                id: GlobalId(3),
                symbol: SymbolId(5),
                ty: MachineTypeId(7),
                section: SectionId(2),
                offset: frame_lengths[0] + frame_lengths[1] + frame_lengths[2],
                alignment: 1,
                initializer: MachineImmediate::Bytes(frames[3].clone()),
            },
        ];
        machine.functions = vec![
            MachineFunction {
                id: FunctionId(0),
                flow_function: 0,
                origin: MachineFunctionOrigin::GeneratedTestHarness {
                    semantic_function: 1,
                    group: 9,
                },
                role: MachineFunctionRole::ImageEntry,
                symbol: SymbolId(0),
                section: SectionId(0),
                linkage: Linkage::ExportedEntry,
                convention: CallingConvention::UefiAarch64,
                parameters: vec![ValueId(0), ValueId(1)],
                result: MachineTypeId(2),
                proofs: Vec::new(),
                values: vec![
                    machine_value(0, 1),
                    machine_value(1, 1),
                    machine_value(2, 1),
                    machine_value(3, 2),
                    machine_value(4, 2),
                    machine_value(5, 1),
                    machine_value(6, 2),
                    machine_value(7, 2),
                    machine_value(8, 1),
                    machine_value(9, 2),
                    machine_value(10, 2),
                    machine_value(11, 1),
                    machine_value(12, 2),
                    machine_value(13, 2),
                    machine_value(14, 8),
                ],
                stack_slots: Vec::new(),
                blocks: vec![
                    MachineBlock {
                        id: BlockId(0),
                        parameters: Vec::new(),
                        instructions: vec![
                            machine_instruction(
                                0,
                                &[2],
                                MachineOperation::GlobalAddress(GlobalId(0)),
                            ),
                            machine_instruction(
                                1,
                                &[3],
                                MachineOperation::Immediate(MachineImmediate::Integer {
                                    ty: MachineTypeId(2),
                                    bytes_le: frame_lengths[0].to_le_bytes().to_vec(),
                                }),
                            ),
                            machine_instruction(
                                2,
                                &[4],
                                MachineOperation::RuntimeCall {
                                    intrinsic: RuntimeIntrinsic::TestEmit,
                                    arguments: vec![ValueId(2), ValueId(3)],
                                },
                            ),
                        ],
                        terminator: MachineTerminator::Switch {
                            value: ValueId(4),
                            cases: vec![(0, BlockId(2), Vec::new())],
                            default: BlockId(1),
                            default_arguments: Vec::new(),
                        },
                    },
                    MachineBlock {
                        id: BlockId(1),
                        parameters: Vec::new(),
                        instructions: Vec::new(),
                        terminator: MachineTerminator::Return(vec![ValueId(4)]),
                    },
                    MachineBlock {
                        id: BlockId(2),
                        parameters: Vec::new(),
                        instructions: vec![
                            machine_instruction(
                                3,
                                &[5],
                                MachineOperation::GlobalAddress(GlobalId(1)),
                            ),
                            machine_instruction(
                                4,
                                &[6],
                                MachineOperation::Immediate(MachineImmediate::Integer {
                                    ty: MachineTypeId(2),
                                    bytes_le: frame_lengths[1].to_le_bytes().to_vec(),
                                }),
                            ),
                            machine_instruction(
                                5,
                                &[7],
                                MachineOperation::RuntimeCall {
                                    intrinsic: RuntimeIntrinsic::TestEmit,
                                    arguments: vec![ValueId(5), ValueId(6)],
                                },
                            ),
                        ],
                        terminator: MachineTerminator::Switch {
                            value: ValueId(7),
                            cases: vec![(0, BlockId(4), Vec::new())],
                            default: BlockId(3),
                            default_arguments: Vec::new(),
                        },
                    },
                    MachineBlock {
                        id: BlockId(3),
                        parameters: Vec::new(),
                        instructions: Vec::new(),
                        terminator: MachineTerminator::Return(vec![ValueId(7)]),
                    },
                    MachineBlock {
                        id: BlockId(4),
                        parameters: Vec::new(),
                        instructions: vec![
                            machine_instruction(
                                6,
                                &[],
                                MachineOperation::Call {
                                    function: FunctionId(1),
                                    arguments: Vec::new(),
                                    convention: CallingConvention::Internal,
                                },
                            ),
                            machine_instruction(
                                7,
                                &[8],
                                MachineOperation::GlobalAddress(GlobalId(2)),
                            ),
                            machine_instruction(
                                8,
                                &[9],
                                MachineOperation::Immediate(MachineImmediate::Integer {
                                    ty: MachineTypeId(2),
                                    bytes_le: frame_lengths[2].to_le_bytes().to_vec(),
                                }),
                            ),
                            machine_instruction(
                                9,
                                &[10],
                                MachineOperation::RuntimeCall {
                                    intrinsic: RuntimeIntrinsic::TestEmit,
                                    arguments: vec![ValueId(8), ValueId(9)],
                                },
                            ),
                        ],
                        terminator: MachineTerminator::Switch {
                            value: ValueId(10),
                            cases: vec![(0, BlockId(6), Vec::new())],
                            default: BlockId(5),
                            default_arguments: Vec::new(),
                        },
                    },
                    MachineBlock {
                        id: BlockId(5),
                        parameters: Vec::new(),
                        instructions: Vec::new(),
                        terminator: MachineTerminator::Return(vec![ValueId(10)]),
                    },
                    MachineBlock {
                        id: BlockId(6),
                        parameters: Vec::new(),
                        instructions: vec![
                            machine_instruction(
                                10,
                                &[11],
                                MachineOperation::GlobalAddress(GlobalId(3)),
                            ),
                            machine_instruction(
                                11,
                                &[12],
                                MachineOperation::Immediate(MachineImmediate::Integer {
                                    ty: MachineTypeId(2),
                                    bytes_le: frame_lengths[3].to_le_bytes().to_vec(),
                                }),
                            ),
                            machine_instruction(
                                12,
                                &[13],
                                MachineOperation::RuntimeCall {
                                    intrinsic: RuntimeIntrinsic::TestEmit,
                                    arguments: vec![ValueId(11), ValueId(12)],
                                },
                            ),
                        ],
                        terminator: MachineTerminator::Switch {
                            value: ValueId(13),
                            cases: vec![(0, BlockId(8), Vec::new())],
                            default: BlockId(7),
                            default_arguments: Vec::new(),
                        },
                    },
                    MachineBlock {
                        id: BlockId(7),
                        parameters: Vec::new(),
                        instructions: Vec::new(),
                        terminator: MachineTerminator::Return(vec![ValueId(13)]),
                    },
                    MachineBlock {
                        id: BlockId(8),
                        parameters: Vec::new(),
                        instructions: vec![
                            machine_instruction(
                                13,
                                &[14],
                                MachineOperation::Immediate(MachineImmediate::Integer {
                                    ty: MachineTypeId(8),
                                    bytes_le: 0u32.to_le_bytes().to_vec(),
                                }),
                            ),
                            machine_instruction(
                                14,
                                &[],
                                MachineOperation::RuntimeCall {
                                    intrinsic: RuntimeIntrinsic::TestFinish,
                                    arguments: vec![ValueId(14)],
                                },
                            ),
                        ],
                        terminator: MachineTerminator::Unreachable,
                    },
                ],
                entry: BlockId(0),
                stack_bytes: 0,
                source: None,
            },
            MachineFunction {
                id: FunctionId(1),
                flow_function: 1,
                origin: MachineFunctionOrigin::SourceSemantic {
                    semantic_function: 0,
                },
                role: MachineFunctionRole::Test,
                symbol: SymbolId(1),
                section: SectionId(1),
                linkage: Linkage::Private,
                convention: CallingConvention::Internal,
                parameters: Vec::new(),
                result: MachineTypeId(0),
                proofs: Vec::new(),
                values: Vec::new(),
                stack_slots: Vec::new(),
                blocks: vec![MachineBlock {
                    id: BlockId(0),
                    parameters: Vec::new(),
                    instructions: Vec::new(),
                    terminator: MachineTerminator::Return(Vec::new()),
                }],
                entry: BlockId(0),
                stack_bytes: 0,
                source: Some(test_source),
            },
        ];
        machine.tests = vec![MachineTestEntry {
            id: MachineTestId(0),
            plan_id: 1,
            name: "passes_one".to_owned(),
            function: FunctionId(1),
            kind: MachineTestKind::Integration,
            source: test_source,
            timeout_ns: 1_000_000,
        }];
        machine.image_entry = FunctionId(0);
        install_image_enter_contract(&mut machine);
        let machine = machine
            .validate_for_target(&target)
            .expect("valid runtime-test MachineWir fixture");
        (machine, target, frames)
    }

    fn runtime_assertion_fixture(
        condition: bool,
    ) -> (ValidatedMachineWir, TargetPackage, Vec<Vec<u8>>) {
        let (machine, target, frames) = runtime_test_fixture();
        let mut machine = machine.as_wir().clone();
        let source = Span {
            file: FileId(0),
            range: TextRange { start: 5, end: 10 },
        };
        let expression = "false";
        let message = "intentional runtime assertion failure";
        let bool_ty = MachineTypeId(u32::try_from(machine.types.len()).expect("fixture types"));
        machine.types.push(MachineType {
            id: bool_ty,
            kind: MachineTypeKind::Integer { bits: 8 },
            size: 1,
            alignment: 1,
            source_name: Some("bool".to_owned()),
        });
        let storage_ty = MachineTypeId(u32::try_from(machine.types.len()).expect("fixture types"));
        machine.types.push(MachineType {
            id: storage_ty,
            kind: MachineTypeKind::Array {
                element: MachineTypeId(3),
                length: 4096,
            },
            size: 4096,
            alignment: 1,
            source_name: Some("assertion-storage".to_owned()),
        });
        let expression_global = GlobalId(u32::try_from(machine.globals.len()).expect("globals"));
        let message_global = GlobalId(expression_global.0 + 1);
        let expression_symbol = SymbolId(u32::try_from(machine.symbols.len()).expect("symbols"));
        let message_symbol = SymbolId(expression_symbol.0 + 1);
        let runtime_symbol = SymbolId(expression_symbol.0 + 2);
        machine.symbols.extend([
            Symbol {
                id: expression_symbol,
                name: "__wrela_assertion_0".to_owned(),
                visibility: SymbolVisibility::Private,
                definition: SymbolDefinition::Global(expression_global),
            },
            Symbol {
                id: message_symbol,
                name: "__wrela_assertion_1".to_owned(),
                visibility: SymbolVisibility::Private,
                definition: SymbolDefinition::Global(message_global),
            },
            Symbol {
                id: runtime_symbol,
                name: RuntimeIntrinsic::TestAssertionFail.symbol_name().to_owned(),
                visibility: SymbolVisibility::Runtime,
                definition: SymbolDefinition::ExternalRuntime(RuntimeIntrinsic::TestAssertionFail),
            },
        ]);
        let first_offset = machine.sections[2].reserved_bytes;
        let padded = |text: &str| {
            let mut bytes = text.as_bytes().to_vec();
            bytes.resize(4096, 0);
            bytes
        };
        machine.globals.extend([
            MachineGlobal {
                id: expression_global,
                symbol: expression_symbol,
                ty: storage_ty,
                section: SectionId(2),
                offset: first_offset,
                alignment: 1,
                initializer: MachineImmediate::Bytes(padded(expression)),
            },
            MachineGlobal {
                id: message_global,
                symbol: message_symbol,
                ty: storage_ty,
                section: SectionId(2),
                offset: first_offset + 4096,
                alignment: 1,
                initializer: MachineImmediate::Bytes(padded(message)),
            },
        ]);
        machine.sections[2].reserved_bytes += 8192;
        let mut intrinsics = machine.runtime.intrinsics.clone();
        intrinsics.push(RuntimeIntrinsic::TestAssertionFail);
        machine.runtime = RuntimeRequirements::new(intrinsics);
        let test = &mut machine.functions[1];
        test.values = vec![MachineValue {
            id: ValueId(0),
            ty: bool_ty,
            source_name: Some("condition".to_owned()),
        }];
        test.blocks[0].instructions = vec![
            machine_instruction(
                0,
                &[0],
                MachineOperation::Immediate(MachineImmediate::Integer {
                    ty: bool_ty,
                    bytes_le: vec![u8::from(condition)],
                }),
            ),
            MachineInstruction {
                id: InstructionId(1),
                results: Vec::new(),
                operation: MachineOperation::TestAssert {
                    condition: ValueId(0),
                    failure: MachineAssertionFailure {
                        expression: expression.to_owned(),
                        expression_global,
                        message: Some(message.to_owned()),
                        message_global: Some(message_global),
                        source,
                    },
                },
                source: Some(source),
            },
        ];
        let machine = machine
            .validate_for_target(&target)
            .expect("valid runtime assertion MachineWir fixture");
        (machine, target, frames)
    }

    #[cfg(feature = "llvm")]
    fn real_producer_fixture() -> (ValidatedMachineWir, TargetPackage) {
        let identity = identity();
        let target = TargetPackage::aarch64_qemu_virt_uefi(identity.target_package);
        let build = build_configuration(identity.clone());
        let optimization_profile = OptimizationProfile::from_build_policy(
            &build.profile.optimization,
            build.identity.compiler,
        )
        .expect("implemented producer optimization profile");
        let semantic = semantic_fixture(identity);
        let flow = CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: semantic,
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("real canonical FlowWir lowering")
            .into_parts()
            .0;
        let optimized = CanonicalFlowOptimizer::new()
            .optimize(
                OptimizationRequest {
                    input: flow,
                    profile: optimization_profile,
                    limits: OptimizationLimits::standard(),
                },
                &|| false,
            )
            .expect("real canonical none optimization");
        let machine = CanonicalMachineLowerer::new()
            .lower(
                MachineLoweringRequest {
                    input: &optimized,
                    target: &target,
                    build: &build,
                    limits: MachineLoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("real canonical MachineWir lowering")
            .into_parts()
            .0;
        (machine, target)
    }

    fn build_configuration(identity: BuildIdentity) -> ValidatedBuildConfiguration {
        let observed_profile = identity.profile;
        let mut profile = BuildProfile::development();
        profile.optimization.level = OptimizationLevel::None;
        seal_build_configuration(BuildConfiguration { identity, profile }, observed_profile)
            .expect("valid producer test build configuration")
    }

    #[cfg(feature = "llvm")]
    fn semantic_fixture(build: BuildIdentity) -> semantic::ValidatedSemanticWir {
        semantic::SemanticWir {
            version: semantic::SEMANTIC_WIR_VERSION,
            name: "minimum-image".to_owned(),
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
                semantic_proof(0, semantic::ProofKind::TypeChecked, &[], None),
                semantic_proof(1, semantic::ProofKind::EffectsAllowed, &[0], Some(1)),
                semantic_proof(2, semantic::ProofKind::ImageClosed, &[0, 1], Some(0)),
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
        .expect("valid real-producer SemanticWir")
    }

    fn semantic_proof(
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
            sources: vec![Span {
                file: FileId(0),
                range: TextRange { start: 10, end: 14 },
            }],
            depends_on: depends_on.iter().copied().map(semantic::ProofId).collect(),
            explanation: vec![format!("proof explanation {id}")],
        }
    }

    fn ordinary_scalar_producer_fixture() -> (ValidatedMachineWir, TargetPackage) {
        let identity = identity();
        let target = TargetPackage::aarch64_qemu_virt_uefi(identity.target_package);
        let build = build_configuration(identity.clone());
        let optimization_profile = OptimizationProfile::from_build_policy(
            &build.profile.optimization,
            build.identity.compiler,
        )
        .expect("implemented scalar producer optimization profile");
        let flow = CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: ordinary_scalar_semantic_fixture(identity),
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("production scalar FlowWir lowering")
            .into_parts()
            .0;
        let optimized = CanonicalFlowOptimizer::new()
            .optimize(
                OptimizationRequest {
                    input: flow,
                    profile: optimization_profile,
                    limits: OptimizationLimits::standard(),
                },
                &|| false,
            )
            .expect("production scalar FlowWir optimization");
        let machine = CanonicalMachineLowerer::new()
            .lower(
                MachineLoweringRequest {
                    input: &optimized,
                    target: &target,
                    build: &build,
                    limits: MachineLoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("production scalar MachineWir lowering")
            .into_parts()
            .0;
        (machine, target)
    }

    fn checked_scalar_producer_fixture(
        operation: semantic::SemanticOperation,
    ) -> (ValidatedMachineWir, TargetPackage) {
        let identity = identity();
        let target = TargetPackage::aarch64_qemu_virt_uefi(identity.target_package);
        let build = build_configuration(identity.clone());
        let optimization_profile = OptimizationProfile::from_build_policy(
            &build.profile.optimization,
            build.identity.compiler,
        )
        .expect("implemented checked-scalar producer optimization profile");
        let mut semantic = ordinary_scalar_semantic_fixture(identity).into_wir();
        let semantic::SemanticStatement::Let(statement) =
            &mut semantic.functions[1].body.statements[0]
        else {
            panic!("checked scalar helper statement");
        };
        statement.operation = operation;
        let semantic = semantic
            .validate()
            .expect("valid checked scalar producer SemanticWir");
        let flow = CanonicalFlowLowerer::new()
            .lower(
                LowerRequest {
                    input: semantic,
                    limits: LoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("checked scalar reaches production FlowWir")
            .into_parts()
            .0;
        let optimized = CanonicalFlowOptimizer::new()
            .optimize(
                OptimizationRequest {
                    input: flow,
                    profile: optimization_profile,
                    limits: OptimizationLimits::standard(),
                },
                &|| false,
            )
            .expect("checked scalar reaches production optimized FlowWir");
        let machine = CanonicalMachineLowerer::new()
            .lower(
                MachineLoweringRequest {
                    input: &optimized,
                    target: &target,
                    build: &build,
                    limits: MachineLoweringLimits::standard(),
                },
                &|| false,
            )
            .expect("checked scalar reaches production MachineWir")
            .into_parts()
            .0;
        (machine, target)
    }

    fn append_machine_scalar_type(
        machine: &mut MachineWir,
        kind: MachineTypeKind,
    ) -> MachineTypeId {
        let id = MachineTypeId(
            u32::try_from(machine.types.len()).expect("bounded checked scalar type table"),
        );
        let (size, alignment) = match kind {
            MachineTypeKind::Integer { bits } => {
                let bytes = u64::from(bits.div_ceil(8));
                (
                    bytes,
                    u32::try_from(bytes).expect("supported scalar alignment"),
                )
            }
            MachineTypeKind::Float32 => (4, 4),
            MachineTypeKind::Float64 => (8, 8),
            _ => panic!("non-scalar checked conversion test type"),
        };
        machine.types.push(MachineType {
            id,
            kind,
            size,
            alignment,
            source_name: Some(format!("checked_scalar_{}", id.0)),
        });
        id
    }

    fn checked_conversion_machine_fixture(
        source_kind: CheckedNumericKind,
        source_type: MachineTypeKind,
        destination_kind: CheckedNumericKind,
        destination_type: MachineTypeKind,
    ) -> (ValidatedMachineWir, TargetPackage) {
        let (machine, target) =
            checked_scalar_producer_fixture(semantic::SemanticOperation::Convert {
                value: semantic::ValueId(0),
                destination: semantic::TypeId(2),
                checked: true,
            });
        let mut machine = machine.into_wir();
        let source = append_machine_scalar_type(&mut machine, source_type);
        let destination = append_machine_scalar_type(&mut machine, destination_type);

        for id in [ValueId(1), ValueId(2)] {
            machine.functions[0].values[id.0 as usize].ty = source;
        }
        machine.functions[0].values[3].ty = destination;
        for instruction in &mut machine.functions[0].blocks[0].instructions {
            let Some(result) = instruction.results.first() else {
                continue;
            };
            if !matches!(result, ValueId(1) | ValueId(2)) {
                continue;
            }
            instruction.operation = MachineOperation::Immediate(match source_kind {
                CheckedNumericKind::UnsignedInteger | CheckedNumericKind::SignedInteger => {
                    let bits = match machine.types[source.0 as usize].kind {
                        MachineTypeKind::Integer { bits } => bits,
                        _ => unreachable!(),
                    };
                    let mut bytes = vec![0_u8; usize::from(bits.div_ceil(8))];
                    bytes[0] = 7;
                    MachineImmediate::Integer {
                        ty: source,
                        bytes_le: bytes,
                    }
                }
                CheckedNumericKind::Float32 => MachineImmediate::Float32(7.5_f32.to_bits()),
                CheckedNumericKind::Float64 => MachineImmediate::Float64(7.5_f64.to_bits()),
            });
        }

        let helper = &mut machine.functions[1];
        helper.values[0].ty = source;
        helper.values[1].ty = source;
        helper.values[2].ty = destination;
        helper.result = destination;
        let MachineOperation::CheckedConvert {
            source: operation_source,
            destination_kind: operation_destination,
            destination: operation_type,
            ..
        } = &mut helper.blocks[0].instructions[0].operation
        else {
            panic!("checked conversion helper operation");
        };
        *operation_source = source_kind;
        *operation_destination = destination_kind;
        *operation_type = destination;

        let machine = machine
            .validate_for_target(&target)
            .expect("valid checked conversion MachineWir mutation fixture");
        (machine, target)
    }

    fn checked_integer_machine_fixture(
        operation: CheckedIntegerOp,
        signedness: IntegerSignedness,
        bits: u16,
    ) -> (ValidatedMachineWir, TargetPackage) {
        let (machine, target) =
            checked_scalar_producer_fixture(semantic::SemanticOperation::Binary {
                operator: match operation {
                    CheckedIntegerOp::Add => semantic::BinaryOperator::Add,
                    CheckedIntegerOp::Subtract => semantic::BinaryOperator::Subtract,
                    CheckedIntegerOp::Multiply => semantic::BinaryOperator::Multiply,
                    CheckedIntegerOp::Divide => semantic::BinaryOperator::Divide,
                    CheckedIntegerOp::Remainder => semantic::BinaryOperator::Remainder,
                    CheckedIntegerOp::ShiftLeft => semantic::BinaryOperator::ShiftLeft,
                    CheckedIntegerOp::ShiftLeftWrapping => semantic::BinaryOperator::ShiftLeft,
                    CheckedIntegerOp::ShiftRight => semantic::BinaryOperator::ShiftRight,
                },
                left: semantic::ValueId(0),
                right: semantic::ValueId(1),
                arithmetic: if operation == CheckedIntegerOp::ShiftLeftWrapping {
                    semantic::ArithmeticMode::Wrapping
                } else {
                    semantic::ArithmeticMode::Checked
                },
            });
        let mut machine = machine.into_wir();
        let ty = append_machine_scalar_type(&mut machine, MachineTypeKind::Integer { bits });
        for id in [ValueId(1), ValueId(2), ValueId(3)] {
            machine.functions[0].values[id.0 as usize].ty = ty;
        }
        for instruction in &mut machine.functions[0].blocks[0].instructions {
            let Some(result) = instruction.results.first() else {
                continue;
            };
            if !matches!(result, ValueId(1) | ValueId(2)) {
                continue;
            }
            let mut bytes = vec![0_u8; usize::from(bits.div_ceil(8))];
            bytes[0] = 7;
            instruction.operation = MachineOperation::Immediate(MachineImmediate::Integer {
                ty,
                bytes_le: bytes,
            });
        }
        let helper = &mut machine.functions[1];
        for value in &mut helper.values {
            value.ty = ty;
        }
        helper.result = ty;
        let MachineOperation::CheckedInteger {
            op,
            signedness: operation_signedness,
            ..
        } = &mut helper.blocks[0].instructions[0].operation
        else {
            panic!("checked integer helper operation");
        };
        *op = operation;
        *operation_signedness = signedness;
        let machine = machine
            .validate_for_target(&target)
            .expect("valid checked integer MachineWir mutation fixture");
        (machine, target)
    }

    fn ordinary_scalar_semantic_fixture(build: BuildIdentity) -> semantic::ValidatedSemanticWir {
        let test_source = source_span(0, 10, 20);
        let helper_source = source_span(0, 170, 209);
        let mut harness_values = Vec::new();
        let mut harness_statements = Vec::new();
        for (marker, bytes) in canonical_passing_frames(TestId(12)).into_iter().enumerate() {
            let marker = u8::try_from(marker).expect("four generated passing frames");
            let frame_type = match bytes.len() {
                49 => semantic::TypeId(5),
                50 => semantic::TypeId(6),
                53 => semantic::TypeId(7),
                _ => panic!("unexpected generated passing frame extent"),
            };
            let value = semantic::ValueId(u32::from(marker));
            harness_values.push(semantic::SemanticValue {
                id: value,
                ty: frame_type,
                origin: None,
                name: None,
            });
            harness_statements.extend([
                semantic::SemanticStatement::Let(semantic::LetStatement {
                    results: vec![value],
                    operation: semantic::SemanticOperation::Constant(semantic::Constant::Bytes(
                        bytes,
                    )),
                    source: None,
                }),
                semantic::SemanticStatement::Let(semantic::LetStatement {
                    results: Vec::new(),
                    operation: semantic::SemanticOperation::TestEmit { payload: value },
                    source: None,
                }),
            ]);
            if marker == 1 {
                harness_statements.push(semantic::SemanticStatement::Let(semantic::LetStatement {
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
        harness_values.push(semantic::SemanticValue {
            id: outcome,
            ty: semantic::TypeId(2),
            origin: None,
            name: None,
        });
        harness_statements.extend([
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
                hir_files: 1,
                hir_declarations: 3,
                reachable_declarations: 2,
                monomorphized_instantiations: 3,
                resolved_interface_calls: 0,
            },
            types: vec![
                semantic_type(
                    0,
                    "unit",
                    semantic::TypeKind::Primitive(semantic::PrimitiveType::Unit),
                    semantic::Linearity::CopyScalar,
                    None,
                ),
                semantic_type(
                    1,
                    "bool",
                    semantic::TypeKind::Primitive(semantic::PrimitiveType::Bool),
                    semantic::Linearity::CopyScalar,
                    Some(source_span(0, 230, 234)),
                ),
                semantic_type(
                    2,
                    "u32",
                    semantic::TypeKind::Primitive(semantic::PrimitiveType::U32),
                    semantic::Linearity::CopyScalar,
                    Some(source_span(0, 176, 179)),
                ),
                semantic_type(
                    3,
                    "fn",
                    semantic::TypeKind::Function(semantic::FunctionType {
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
                    semantic::Linearity::CopyScalar,
                    Some(helper_source),
                ),
                semantic_type(
                    4,
                    "__wrela_test_byte",
                    semantic::TypeKind::Primitive(semantic::PrimitiveType::U8),
                    semantic::Linearity::CopyScalar,
                    None,
                ),
                semantic_type(
                    5,
                    "__wrela_test_frame_49",
                    semantic::TypeKind::Array {
                        element: semantic::TypeId(4),
                        length: 49,
                    },
                    semantic::Linearity::ExplicitCopy,
                    None,
                ),
                semantic_type(
                    6,
                    "__wrela_test_frame_50",
                    semantic::TypeKind::Array {
                        element: semantic::TypeId(4),
                        length: 50,
                    },
                    semantic::Linearity::ExplicitCopy,
                    None,
                ),
                semantic_type(
                    7,
                    "__wrela_test_frame_53",
                    semantic::TypeKind::Array {
                        element: semantic::TypeId(4),
                        length: 53,
                    },
                    semantic::Linearity::ExplicitCopy,
                    None,
                ),
            ],
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
                    values: vec![
                        semantic_value(0, 1, Some("flag"), Some(source_span(0, 238, 242))),
                        semantic_value(1, 2, Some("number"), Some(source_span(0, 254, 255))),
                        semantic_value(2, 2, Some("other"), Some(source_span(0, 268, 269))),
                        semantic_value(3, 2, None, Some(source_span(0, 315, 345))),
                    ],
                    body: semantic::SemanticRegion {
                        parameters: Vec::new(),
                        statements: vec![
                            semantic_let(
                                0,
                                semantic::SemanticOperation::Constant(semantic::Constant::Bool(
                                    true,
                                )),
                                source_span(0, 238, 242),
                            ),
                            semantic_let(
                                1,
                                semantic::SemanticOperation::Constant(
                                    semantic::Constant::Unsigned { bits: 32, value: 7 },
                                ),
                                source_span(0, 254, 255),
                            ),
                            semantic_let(
                                2,
                                semantic::SemanticOperation::Constant(
                                    semantic::Constant::Unsigned { bits: 32, value: 9 },
                                ),
                                source_span(0, 268, 269),
                            ),
                            semantic::SemanticStatement::If {
                                condition: semantic::ValueId(0),
                                then_region: semantic::SemanticRegion {
                                    parameters: Vec::new(),
                                    statements: vec![semantic_let(
                                        3,
                                        semantic::SemanticOperation::Call {
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
                                        source_span(0, 315, 345),
                                    )],
                                },
                                else_region: semantic::SemanticRegion::default(),
                                results: Vec::new(),
                                source: Some(source_span(0, 270, 350)),
                            },
                            semantic::SemanticStatement::Return(Vec::new()),
                        ],
                    },
                    effects: semantic::EffectSet::default(),
                    proofs: vec![semantic::ProofId(0), semantic::ProofId(1)],
                    source: Some(test_source),
                    stack_bound: 0,
                    frame_bound: 0,
                    uninterrupted_bound: Some(5),
                    recursive_depth_bound: Some(1),
                },
                semantic::SemanticFunction {
                    id: semantic::FunctionId(1),
                    instance_key: Sha256Digest::from_bytes([0x61; 32]),
                    name: "helper".to_owned(),
                    origin: semantic::FunctionOrigin::Source,
                    role: semantic::FunctionRole::Ordinary,
                    color: semantic::FunctionColor::Sync,
                    parameters: vec![semantic::ValueId(0), semantic::ValueId(1)],
                    result: semantic::TypeId(2),
                    values: vec![
                        semantic_value(0, 2, Some("x"), Some(source_span(0, 174, 179))),
                        semantic_value(1, 2, Some("y"), Some(source_span(0, 180, 185))),
                        semantic_value(2, 2, Some("copied"), Some(source_span(0, 194, 201))),
                    ],
                    body: semantic::SemanticRegion {
                        parameters: vec![semantic::ValueId(0), semantic::ValueId(1)],
                        statements: vec![
                            semantic_let(
                                2,
                                semantic::SemanticOperation::Copy {
                                    value: semantic::ValueId(0),
                                },
                                source_span(0, 194, 201),
                            ),
                            semantic::SemanticStatement::Return(vec![semantic::ValueId(2)]),
                        ],
                    },
                    effects: semantic::EffectSet::default(),
                    proofs: vec![semantic::ProofId(2), semantic::ProofId(3)],
                    source: Some(helper_source),
                    stack_bound: 0,
                    frame_bound: 0,
                    uninterrupted_bound: Some(2),
                    recursive_depth_bound: Some(1),
                },
                semantic::SemanticFunction {
                    id: semantic::FunctionId(2),
                    instance_key: Sha256Digest::from_bytes([0x62; 32]),
                    name: "__wrela_test_entry".to_owned(),
                    origin: semantic::FunctionOrigin::GeneratedTestHarness { group: 9 },
                    role: semantic::FunctionRole::ImageEntry,
                    color: semantic::FunctionColor::Sync,
                    parameters: Vec::new(),
                    result: semantic::TypeId(0),
                    values: harness_values,
                    body: semantic::SemanticRegion {
                        parameters: Vec::new(),
                        statements: harness_statements,
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
                    uninterrupted_bound: Some(10),
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
                semantic_proof(0, semantic::ProofKind::TypeChecked, &[], None),
                semantic_proof(1, semantic::ProofKind::EffectsAllowed, &[0], Some(1)),
                semantic_proof(2, semantic::ProofKind::TypeChecked, &[], None),
                semantic_proof(3, semantic::ProofKind::EffectsAllowed, &[2], Some(1)),
                semantic_proof(4, semantic::ProofKind::TypeChecked, &[], Some(2)),
                semantic_proof(5, semantic::ProofKind::EffectsAllowed, &[4], Some(4)),
                semantic_proof(6, semantic::ProofKind::ImageClosed, &[4, 5], Some(1)),
            ],
            tests: vec![semantic::TestEntry {
                id: semantic::TestId(0),
                plan_id: 12,
                name: "passes_one".to_owned(),
                function: semantic::FunctionId(0),
                kind: semantic::TestKind::Integration,
                source: test_source,
                timeout_ns: 1_000_000,
            }],
            compiled_test_group: Some(semantic::FullImageTestGroup {
                id: semantic::ImageGroupId(9),
                name: "integration".to_owned(),
                root: semantic::ImageRoot::GeneratedHarness {
                    harness_name: "__wrela_test_harness".to_owned(),
                },
                tests: vec![semantic::ImageTest {
                    descriptor: semantic::TestDescriptor {
                        id: semantic::ModelTestId(12),
                        name: "passes_one".to_owned(),
                        kind: semantic::ModelTestKind::IntegrationImage,
                        source: Some(test_source),
                        timeout_ns: 1_000_000,
                    },
                    invocation: semantic::ImageTestInvocation::GeneratedFunction {
                        function_key: semantic::FunctionKey(Sha256Digest::from_bytes([0x60; 32])),
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
            image_entry: semantic::FunctionId(2),
            static_bytes: 0,
            peak_bytes: 0,
        }
        .validate()
        .expect("valid ordinary scalar producer SemanticWir")
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

    fn primitive_join_semantic_fixture(
        build: BuildIdentity,
        primitive: semantic::PrimitiveType,
    ) -> semantic::ValidatedSemanticWir {
        let mut module = ordinary_scalar_semantic_fixture(build).into_wir();
        let mut frames = module.types.split_off(5);
        for frame in &mut frames {
            frame.id = semantic::TypeId(frame.id.0 + 1);
        }
        for value in &mut module.functions[2].values {
            if value.ty.0 >= 5 {
                value.ty = semantic::TypeId(value.ty.0 + 1);
            }
        }
        module.types.push(semantic_type(
            5,
            &format!("join_{primitive:?}"),
            semantic::TypeKind::Primitive(primitive),
            semantic::Linearity::CopyScalar,
            Some(source_span(0, 205, 212)),
        ));
        module.types.extend(frames);
        module.types[3].kind = semantic::TypeKind::Function(semantic::FunctionType {
            color: semantic::FunctionColor::Sync,
            parameters: vec![semantic::ParameterType {
                access: semantic::AccessMode::Read,
                ty: semantic::TypeId(5),
            }],
            result: semantic::TypeId(0),
        });

        let condition_source = source_span(0, 214, 218);
        let inner_source = source_span(0, 220, 260);
        let outer_source = source_span(0, 219, 280);
        let copied_source = source_span(0, 281, 287);
        module.functions[0].values = vec![
            semantic_value(0, 1, Some("condition"), Some(condition_source)),
            semantic_value(1, 5, Some("inner_then"), Some(source_span(0, 228, 232))),
            semantic_value(2, 5, Some("inner_else"), Some(source_span(0, 240, 244))),
            semantic_value(3, 5, Some("inner_join"), Some(inner_source)),
            semantic_value(4, 5, Some("outer_else"), Some(source_span(0, 268, 272))),
            semantic_value(5, 5, Some("outer_join"), Some(outer_source)),
            semantic_value(6, 5, Some("post_join_copy"), Some(copied_source)),
        ];
        module.functions[0].body = semantic::SemanticRegion {
            parameters: Vec::new(),
            statements: vec![
                semantic_let(
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
                                        semantic_let(
                                            1,
                                            semantic::SemanticOperation::Constant(
                                                primitive_join_constant(primitive, 1),
                                            ),
                                            source_span(0, 228, 232),
                                        ),
                                        semantic::SemanticStatement::Yield(vec![
                                            semantic::ValueId(1),
                                        ]),
                                    ],
                                },
                                else_region: semantic::SemanticRegion {
                                    parameters: Vec::new(),
                                    statements: vec![
                                        semantic_let(
                                            2,
                                            semantic::SemanticOperation::Constant(
                                                primitive_join_constant(primitive, 2),
                                            ),
                                            source_span(0, 240, 244),
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
                            semantic_let(
                                4,
                                semantic::SemanticOperation::Constant(primitive_join_constant(
                                    primitive, 3,
                                )),
                                source_span(0, 268, 272),
                            ),
                            semantic::SemanticStatement::Yield(vec![semantic::ValueId(4)]),
                        ],
                    },
                    results: vec![semantic::ValueId(5)],
                    source: Some(outer_source),
                },
                semantic_let(
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
                    source: Some(source_span(0, 288, 305)),
                }),
                semantic::SemanticStatement::Return(Vec::new()),
            ],
        };
        module.functions[0].uninterrupted_bound = Some(12);

        module.functions[1].name = format!("consume_{primitive:?}");
        module.functions[1].parameters = vec![semantic::ValueId(0)];
        module.functions[1].result = semantic::TypeId(0);
        module.functions[1].values = vec![semantic_value(
            0,
            5,
            Some("value"),
            Some(source_span(0, 310, 315)),
        )];
        module.functions[1].body = semantic::SemanticRegion {
            parameters: vec![semantic::ValueId(0)],
            statements: vec![semantic::SemanticStatement::Return(Vec::new())],
        };
        module.functions[1].uninterrupted_bound = Some(1);
        module.functions[2].uninterrupted_bound = Some(17);
        module
            .validate()
            .expect("valid primitive join backend producer SemanticWir")
    }

    fn primitive_join_machine_fixture(
        primitive: semantic::PrimitiveType,
    ) -> (ValidatedMachineWir, TargetPackage) {
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
            .unwrap_or_else(|error| panic!("{primitive:?} Flow lowering: {error:?}"))
            .into_parts()
            .0;
        let optimized = CanonicalFlowOptimizer::new()
            .optimize(
                OptimizationRequest {
                    input: flow,
                    profile: OptimizationProfile::from_build_policy(
                        &build.profile.optimization,
                        build.identity.compiler,
                    )
                    .expect("implemented primitive join optimization profile"),
                    limits: OptimizationLimits::standard(),
                },
                &|| false,
            )
            .expect("primitive join FlowWir optimization");
        let machine = CanonicalMachineLowerer::new()
            .lower(
                MachineLoweringRequest {
                    input: &optimized,
                    target: &target,
                    build: &build,
                    limits: MachineLoweringLimits::standard(),
                },
                &|| false,
            )
            .unwrap_or_else(|error| panic!("{primitive:?} MachineWir lowering: {error:?}"))
            .into_parts()
            .0;
        (machine, target)
    }

    fn primitive_join_matrix() -> [semantic::PrimitiveType; 16] {
        [
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
        ]
    }

    fn primitive_llvm_type(primitive: semantic::PrimitiveType) -> Option<&'static str> {
        match primitive {
            semantic::PrimitiveType::Unit => None,
            semantic::PrimitiveType::Bool
            | semantic::PrimitiveType::U8
            | semantic::PrimitiveType::I8 => Some("i8"),
            semantic::PrimitiveType::U16 | semantic::PrimitiveType::I16 => Some("i16"),
            semantic::PrimitiveType::U32 | semantic::PrimitiveType::I32 => Some("i32"),
            semantic::PrimitiveType::U64
            | semantic::PrimitiveType::Usize
            | semantic::PrimitiveType::I64
            | semantic::PrimitiveType::Isize => Some("i64"),
            semantic::PrimitiveType::U128 | semantic::PrimitiveType::I128 => Some("i128"),
            semantic::PrimitiveType::F32 => Some("float"),
            semantic::PrimitiveType::F64 => Some("double"),
            semantic::PrimitiveType::Char => None,
        }
    }

    fn source_span(file: u32, start: u32, end: u32) -> Span {
        Span {
            file: FileId(file),
            range: TextRange { start, end },
        }
    }

    fn semantic_type(
        id: u32,
        name: &str,
        kind: semantic::TypeKind,
        linearity: semantic::Linearity,
        source: Option<Span>,
    ) -> semantic::TypeRecord {
        semantic::TypeRecord {
            id: semantic::TypeId(id),
            source_name: name.to_owned(),
            kind,
            linearity,
            source,
        }
    }

    fn semantic_value(
        id: u32,
        ty: u32,
        name: Option<&str>,
        origin: Option<Span>,
    ) -> semantic::SemanticValue {
        semantic::SemanticValue {
            id: semantic::ValueId(id),
            ty: semantic::TypeId(ty),
            origin,
            name: name.map(str::to_owned),
        }
    }

    fn semantic_let(
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

    #[test]
    fn codegen_policy_rejects_zero_capacity() {
        CodegenOptions::standard()
            .validate()
            .expect("standard options");
        let mut options = CodegenOptions::standard();
        options.maximum_object_bytes = 0;
        assert!(matches!(
            options.validate(),
            Err(CodegenError::InvalidOptions)
        ));
    }

    #[test]
    fn default_build_reports_the_absent_backend_honestly() {
        let (machine, target) = fixture();
        let request = CodegenRequest {
            module: &machine,
            target: target.backend(),
            options: CodegenOptions::standard(),
        };
        if llvm_backend_available() {
            return;
        }
        assert_eq!(
            CanonicalLlvmCodeGenerator::new().emit_object(request, &|| false),
            Err(CodegenError::BackendNotBuilt)
        );
    }

    #[test]
    fn preflight_accepts_a_nonzero_scalar_status_immediate() {
        let (mut machine, target) = machine_candidate();
        let MachineOperation::Immediate(MachineImmediate::Integer { bytes_le, .. }) =
            &mut machine.functions[0].blocks[0].instructions[0].operation
        else {
            panic!("integer status fixture");
        };
        bytes_le[0] = 1;
        let machine = machine
            .validate_for_target(&target)
            .expect("nonzero status remains structurally valid MachineWir");
        super::preflight(
            &CodegenRequest {
                module: &machine,
                target: target.backend(),
                options: CodegenOptions::standard(),
            },
            &|| false,
        )
        .expect("bounded scalar immediate is supported");
    }

    #[test]
    fn unused_proof_text_is_not_misrepresented_as_a_backend_fact() {
        let (mut machine, target) = machine_candidate();
        machine.proofs[0].statement = "a different backend claim".to_owned();
        let machine = machine
            .validate_for_target(&target)
            .expect("different nonempty proof text remains structurally valid");
        super::preflight(
            &CodegenRequest {
                module: &machine,
                target: target.backend(),
                options: CodegenOptions::standard(),
            },
            &|| false,
        )
        .expect("an unused proof is not translated into an LLVM fact");
    }

    #[test]
    fn cancellation_precedes_native_backend_availability() {
        let (machine, target) = fixture();
        assert_eq!(
            CanonicalLlvmCodeGenerator::new().emit_object(
                CodegenRequest {
                    module: &machine,
                    target: target.backend(),
                    options: CodegenOptions::standard(),
                },
                &|| true,
            ),
            Err(CodegenError::Cancelled)
        );
    }

    #[test]
    fn bounded_ir_renderer_preserves_entry_abi_and_exact_sections() {
        let (machine, target) = fixture();
        let request = CodegenRequest {
            module: &machine,
            target: target.backend(),
            options: CodegenOptions::standard(),
        };
        let bytes = super::ir::render_module(&request, &|| false).expect("bounded scalar LLVM IR");
        let text = std::str::from_utf8(&bytes).expect("renderer emits UTF-8 LLVM IR");
        assert!(text.contains(
            "define dso_local i64 @wrela_image_entry(ptr %v0, ptr %v1) section \".text\" align 16"
        ));
        assert!(text.contains("declare i64 @wrela_rt_v2_image_enter(ptr, ptr)"));
        assert!(text.contains("%v3 = call i64 @wrela_rt_v2_image_enter(ptr %v0, ptr %v1)"));
        assert!(text.contains("switch i64 %v3"));
        assert!(text.contains("i64 0, label %b0"));
        assert!(text.contains("ret i64 %v3"));
        assert!(text.contains("%v2 = add i64 0, 0"));
        assert!(text.contains("module asm \".section .rdata$wrela_irq"));

        let mut options = CodegenOptions::standard();
        options.maximum_ir_bytes = 32;
        assert!(matches!(
            super::ir::render_module(
                &CodegenRequest {
                    module: &machine,
                    target: target.backend(),
                    options,
                },
                &|| false,
            ),
            Err(CodegenError::ResourceLimit {
                resource: "LLVM IR bytes",
                ..
            })
        ));
        assert_eq!(
            super::ir::render_module(&request, &|| true),
            Err(CodegenError::Cancelled)
        );
    }

    #[test]
    fn authenticated_normal_cleanup_call_renders_exact_aggregate_llvm_boundary() {
        let (machine, target) = normal_cleanup_machine_fixture();
        let request = CodegenRequest {
            module: &machine,
            target: target.backend(),
            options: CodegenOptions::standard(),
        };
        super::preflight(&request, &|| false)
            .expect("authenticated cleanup aggregate passes codegen preflight");
        let first = super::ir::render_module(&request, &|| false)
            .expect("cleanup aggregate renders to bounded LLVM IR");
        let second = super::ir::render_module(&request, &|| false)
            .expect("cleanup aggregate rerenders deterministically");
        assert_eq!(first, second);
        let text = std::str::from_utf8(&first).expect("LLVM IR is UTF-8");
        assert!(
            text.contains("define internal fastcc void @__wrela_fn_2({ i32 } %v0)"),
            "{text}"
        );
        assert!(
            text.contains("call fastcc void @__wrela_fn_2({ i32 } %v5)"),
            "{text}"
        );

        let mut ordinary_boundary = machine.clone().into_wir();
        ordinary_boundary.functions[1].role = MachineFunctionRole::Ordinary;
        let ordinary_boundary = ordinary_boundary
            .validate_for_target(&target)
            .expect("ordinary aggregate parameter remains structurally valid");
        assert_eq!(
            super::preflight(
                &CodegenRequest {
                    module: &ordinary_boundary,
                    target: target.backend(),
                    options: CodegenOptions::standard(),
                },
                &|| false,
            ),
            Err(CodegenError::UnsupportedMachineContract(
                "unauthenticated aggregate cleanup call",
            ))
        );

        let mut forged = machine.into_wir();
        forged.functions[2].origin = MachineFunctionOrigin::GeneratedCleanup {
            semantic_function: 1,
            scope: 1,
        };
        let forged = forged
            .validate_for_target(&target)
            .expect("forged cleanup origin remains structurally valid");
        assert_eq!(
            super::preflight(
                &CodegenRequest {
                    module: &forged,
                    target: target.backend(),
                    options: CodegenOptions::standard(),
                },
                &|| false,
            ),
            Err(CodegenError::UnsupportedMachineContract(
                "unauthenticated aggregate cleanup call",
            ))
        );
    }

    #[cfg(feature = "llvm")]
    #[test]
    fn authenticated_normal_cleanup_emits_deterministic_native_coff() {
        let (machine, target) = normal_cleanup_machine_fixture();
        let emit = || {
            CanonicalLlvmCodeGenerator::new()
                .emit_object(
                    CodegenRequest {
                        module: &machine,
                        target: target.backend(),
                        options: CodegenOptions::standard(),
                    },
                    &|| false,
                )
                .expect("authenticated cleanup aggregate emits through pinned LLVM")
        };
        let first = emit();
        let second = emit();
        assert_eq!(
            first, second,
            "identical cleanup input must seal identically"
        );
        assert_eq!(first.bytes().get(..2), Some(&[0x64, 0xaa][..]));
        super::coff::measure_object(first.bytes(), &machine, CodegenOptions::standard(), &|| {
            false
        })
        .expect("cleanup COFF passes the independent object consumer");
    }

    #[test]
    fn zero_initialized_writable_storage_preflights_and_renders_exact_ir() {
        let (machine, target) = storage_fixture();
        let request = CodegenRequest {
            module: &machine,
            target: target.backend(),
            options: CodegenOptions::standard(),
        };
        super::preflight(&request, &|| false).expect("canonical writable storage preflight");
        let first = super::ir::render_module(&request, &|| false)
            .expect("render canonical writable storage");
        let second = super::ir::render_module(&request, &|| false)
            .expect("rerender canonical writable storage");
        assert_eq!(first, second, "writable-storage IR must be deterministic");
        let text = std::str::from_utf8(&first).expect("storage LLVM IR is UTF-8");
        for expected in [
            "@__wrela_data_0 = internal global [8 x i8] zeroinitializer, section \".data\", align 8",
            "@__wrela_data_1 = internal global [16 x i8] zeroinitializer, section \".data\", align 8",
            "@__wrela_bss_0 = internal global [8 x i8] zeroinitializer, section \".bss\", align 8",
            "@__wrela_bss_1 = internal global [16 x i8] zeroinitializer, section \".bss\", align 8",
            "%v4 = getelementptr i8, ptr @__wrela_data_0, i64 0",
            "store i64 %v2, ptr %v4",
            "%v6 = getelementptr i8, ptr @__wrela_bss_0, i64 0",
            "store i64 %v2, ptr %v6",
        ] {
            assert!(text.contains(expected), "missing storage IR: {expected}");
        }

        let exact_ir_bytes = u64::try_from(first.len()).expect("bounded fixture IR");
        let mut exact_options = CodegenOptions::standard();
        exact_options.maximum_ir_bytes = exact_ir_bytes;
        assert_eq!(
            super::ir::render_module(
                &CodegenRequest {
                    module: &machine,
                    target: target.backend(),
                    options: exact_options,
                },
                &|| false,
            )
            .expect("exact LLVM IR limit accepts storage fixture"),
            first
        );
        exact_options.maximum_ir_bytes = exact_ir_bytes - 1;
        assert!(matches!(
            super::ir::render_module(
                &CodegenRequest {
                    module: &machine,
                    target: target.backend(),
                    options: exact_options,
                },
                &|| false,
            ),
            Err(CodegenError::ResourceLimit {
                resource: "LLVM IR bytes",
                ..
            })
        ));

        let exact_symbols = u32::try_from(machine.as_wir().symbols.len()).expect("small fixture");
        let mut exact_options = CodegenOptions::standard();
        exact_options.maximum_symbols = exact_symbols;
        super::preflight(
            &CodegenRequest {
                module: &machine,
                target: target.backend(),
                options: exact_options,
            },
            &|| false,
        )
        .expect("exact construction bound accepts storage fixture");
        exact_options.maximum_symbols -= 1;
        assert_eq!(
            super::preflight(
                &CodegenRequest {
                    module: &machine,
                    target: target.backend(),
                    options: exact_options,
                },
                &|| false,
            ),
            Err(CodegenError::ResourceLimit {
                resource: "symbols",
                limit: u64::from(exact_options.maximum_symbols),
                actual: u64::from(exact_symbols),
            })
        );
    }

    #[test]
    fn writable_storage_rejects_noncanonical_initializer_layout_extent_and_name() {
        let (candidate, target) = storage_candidate();
        let reject = |machine: MachineWir, expected| {
            let machine = machine
                .validate_for_target(&target)
                .expect("mutation remains structurally valid MachineWir");
            assert_eq!(
                super::preflight(
                    &CodegenRequest {
                        module: &machine,
                        target: target.backend(),
                        options: CodegenOptions::standard(),
                    },
                    &|| false,
                ),
                Err(CodegenError::UnsupportedMachineContract(expected))
            );
        };

        let mut bytes_initializer = candidate.clone();
        bytes_initializer.globals[0].initializer = MachineImmediate::Bytes(vec![0; 8]);
        reject(bytes_initializer, "a noncanonical static byte global");

        let mut sparse = candidate.clone();
        sparse.globals[1].offset = 16;
        sparse.sections[2].reserved_bytes = 32;
        reject(sparse, "a sparse or noncanonical static global layout");

        let mut over_reserved = candidate.clone();
        over_reserved.sections[2].reserved_bytes = 25;
        reject(
            over_reserved,
            "a static section not exactly covered by globals",
        );

        let mut wrong_kind = candidate.clone();
        wrong_kind.sections[2].kind = SectionKind::ReadOnlyData;
        reject(wrong_kind, "a noncanonical static byte global");

        let mut under_aligned = candidate.clone();
        under_aligned.globals[1].alignment = 4;
        reject(under_aligned, "a noncanonical static byte global");

        let mut under_aligned_section = candidate.clone();
        under_aligned_section.sections[2].alignment = 4;
        reject(under_aligned_section, "a noncanonical static byte global");

        let mut wrong_name = candidate;
        wrong_name.sections[3].name = ".zerofill".to_owned();
        reject(wrong_name, "an unowned or unsupported scalar section");
    }

    #[test]
    fn project_sized_static_global_walk_honors_late_cancellation() {
        let (mut candidate, target) = storage_candidate();
        candidate.types.push(MachineType {
            id: MachineTypeId(6),
            kind: MachineTypeKind::Array {
                element: MachineTypeId(3),
                length: 1,
            },
            size: 1,
            alignment: 1,
            source_name: Some("storage-byte".to_owned()),
        });
        for section_index in [2usize, 3usize] {
            for index in 0..2_048u32 {
                let global_id = GlobalId(
                    u32::try_from(candidate.globals.len()).expect("bounded global identities"),
                );
                let symbol_id = SymbolId(
                    u32::try_from(candidate.symbols.len()).expect("bounded symbol identities"),
                );
                let section = candidate
                    .sections
                    .get_mut(section_index)
                    .expect("storage section");
                let offset = section.reserved_bytes;
                section.reserved_bytes += 1;
                candidate.symbols.push(Symbol {
                    id: symbol_id,
                    name: format!("__wrela_storage_{section_index}_{index:04}"),
                    visibility: SymbolVisibility::Private,
                    definition: SymbolDefinition::Global(global_id),
                });
                candidate.globals.push(MachineGlobal {
                    id: global_id,
                    symbol: symbol_id,
                    ty: MachineTypeId(6),
                    section: SectionId(u32::try_from(section_index).expect("small section id")),
                    offset,
                    alignment: 1,
                    initializer: MachineImmediate::Zero(MachineTypeId(6)),
                });
            }
        }
        let machine = candidate
            .validate_for_target(&target)
            .expect("project-sized static-global fixture");
        let request = CodegenRequest {
            module: &machine,
            target: target.backend(),
            options: CodegenOptions::standard(),
        };
        let polls = Cell::new(0usize);
        let rendered = super::ir::render_module(&request, &|| {
            polls.set(polls.get() + 1);
            false
        })
        .expect("calibrate deterministic project-sized render");
        assert!(!rendered.is_empty());
        let stop_poll = polls.get().checked_sub(1).expect("renderer polls");
        assert!(stop_poll > 4_096, "fixture must reach a late render poll");

        let cancelled_polls = Cell::new(0usize);
        assert_eq!(
            super::ir::render_module(&request, &|| {
                let next = cancelled_polls.get() + 1;
                cancelled_polls.set(next);
                next >= stop_poll
            }),
            Err(CodegenError::Cancelled)
        );
        assert_eq!(cancelled_polls.get(), stop_poll);

        let mut sorted_globals = (0..machine.as_wir().globals.len()).collect::<Vec<_>>();
        sorted_globals
            .sort_unstable_by_key(|index| (machine.as_wir().globals[*index].section.0, *index));
        let coff_polls = Cell::new(0usize);
        assert!(
            super::coff::static_section_storage_matches(
                machine.as_wir(),
                SectionId(3),
                None,
                machine.as_wir().sections[3].reserved_bytes,
                &sorted_globals,
                &|| {
                    coff_polls.set(coff_polls.get() + 1);
                    false
                },
            )
            .expect("calibrate project-sized COFF static storage walk")
        );
        let coff_stop_poll = coff_polls.get();
        assert!(coff_stop_poll > 12, "COFF walk must poll past its search");
        let cancelled_coff_polls = Cell::new(0usize);
        assert_eq!(
            super::coff::static_section_storage_matches(
                machine.as_wir(),
                SectionId(3),
                None,
                machine.as_wir().sections[3].reserved_bytes,
                &sorted_globals,
                &|| {
                    let next = cancelled_coff_polls.get() + 1;
                    cancelled_coff_polls.set(next);
                    next >= coff_stop_poll
                },
            ),
            Err(CodegenError::Cancelled)
        );
        assert_eq!(cancelled_coff_polls.get(), coff_stop_poll);
    }

    #[test]
    fn production_ordinary_scalar_pipeline_preflights_and_renders_exact_ir() {
        let (machine, target) = ordinary_scalar_producer_fixture();
        let wir = machine.as_wir();
        let [test, helper, entry] = wir.functions.as_slice() else {
            panic!("scalar producer closure must retain test, helper, and image entry");
        };

        assert_eq!(wir.image_entry, FunctionId(2));
        assert!(matches!(
            &wir.types[3].kind,
            MachineTypeKind::Function { parameters, result }
                if parameters.as_slice() == [MachineTypeId(2), MachineTypeId(2)]
                    && *result == MachineTypeId(2)
        ));
        assert_eq!(helper.convention, CallingConvention::Internal);
        assert_eq!(helper.parameters, [ValueId(0), ValueId(1)]);
        assert_eq!(helper.result, MachineTypeId(2));
        assert!(matches!(
            helper.blocks[0].instructions.as_slice(),
            [MachineInstruction {
                results,
                operation: MachineOperation::Convert {
                    op: ConversionOp::Bitcast,
                    value: ValueId(0),
                    destination: MachineTypeId(2),
                },
                ..
            }] if results.as_slice() == [ValueId(2)]
        ));
        assert_eq!(
            helper.blocks[0].terminator,
            MachineTerminator::Return(vec![ValueId(2)])
        );

        assert!(test.blocks.iter().all(|block| block.parameters.is_empty()));
        assert!(matches!(
            test.blocks[0].terminator,
            MachineTerminator::Branch {
                condition: ValueId(0),
                then_block: BlockId(1),
                ref then_arguments,
                else_block: BlockId(2),
                ref else_arguments,
            } if then_arguments.is_empty() && else_arguments.is_empty()
        ));
        assert!(matches!(
            test.blocks[1].instructions.as_slice(),
            [MachineInstruction {
                results,
                operation: MachineOperation::Call {
                    function: FunctionId(1),
                    arguments,
                    convention: CallingConvention::Internal,
                },
                ..
            }] if results.as_slice() == [ValueId(3)]
                && arguments.as_slice() == [ValueId(1), ValueId(2)]
        ));
        assert_eq!(test.blocks.len(), 4);
        for block in [&test.blocks[1], &test.blocks[2]] {
            assert!(matches!(
                &block.terminator,
                MachineTerminator::Jump { block, arguments }
                    if *block == BlockId(3) && arguments.is_empty()
            ));
        }
        assert_eq!(
            test.blocks[3].terminator,
            MachineTerminator::Return(Vec::new())
        );

        assert_eq!(entry.id, FunctionId(2));
        assert_eq!(entry.convention, CallingConvention::UefiAarch64);
        assert_eq!(entry.linkage, Linkage::ExportedEntry);
        assert_eq!(entry.parameters.len(), 2);
        assert_eq!(
            wir.symbols[entry.symbol.0 as usize].name,
            target.backend().entry_symbol()
        );
        assert!(matches!(
            wir.types[entry.result.0 as usize].kind,
            MachineTypeKind::Integer { bits: 64 }
        ));

        let request = CodegenRequest {
            module: &machine,
            target: target.backend(),
            options: CodegenOptions::standard(),
        };
        super::preflight(&request, &|| false)
            .expect("production scalar MachineWir passes codegen preflight");
        let first = super::ir::render_module(&request, &|| false)
            .expect("production scalar MachineWir renders to LLVM IR");
        let second = super::ir::render_module(&request, &|| false)
            .expect("production scalar MachineWir rerenders deterministically");
        assert_eq!(first, second);
        let text = std::str::from_utf8(&first).expect("renderer emits UTF-8 LLVM IR");

        let bool_constant = text
            .find("  %v0 = add i8 0, 1\n")
            .expect("source bool local");
        let first_argument = text
            .find("  %v1 = add i32 0, 7\n")
            .expect("first source u32 local");
        let second_argument = text
            .find("  %v2 = add i32 0, 9\n")
            .expect("second source u32 local");
        let ordered_call = text
            .find("  %v3 = call fastcc i32 @__wrela_fn_1(i32 %v1, i32 %v2)\n")
            .expect("ordered Internal helper call and u32 result");
        assert!(
            bool_constant < first_argument
                && first_argument < second_argument
                && second_argument < ordered_call
        );
        assert!(text.contains(
            "  %t0_branch = icmp ne i8 %v0, 0\n  br i1 %t0_branch, label %b1, label %b2\n"
        ));
        assert!(!text.contains(" = phi "));
        assert!(text.contains(
            "define internal fastcc i32 @__wrela_fn_1(i32 %v0, i32 %v1) section \".text.wrela.1\" align 16 {\n"
        ));
        assert!(text.contains("  %v2 = select i1 true, i32 %v0, i32 %v0\n  ret i32 %v2\n"));
        assert!(text.contains(
            "define dso_local i64 @wrela_image_entry(ptr %v0, ptr %v1) section \".text.wrela.entry\" align 16 {\n"
        ));
    }

    #[test]
    fn canonical_every_primitive_join_renders_exact_textual_llvm() {
        for primitive in primitive_join_matrix() {
            let (machine, target) = primitive_join_machine_fixture(primitive);
            let request = CodegenRequest {
                module: &machine,
                target: target.backend(),
                options: CodegenOptions::standard(),
            };
            super::preflight(&request, &|| false)
                .unwrap_or_else(|error| panic!("{primitive:?} backend preflight: {error:?}"));
            let first = super::ir::render_module(&request, &|| false)
                .unwrap_or_else(|error| panic!("{primitive:?} LLVM render: {error:?}"));
            let second = super::ir::render_module(&request, &|| false)
                .expect("primitive join LLVM rerender");
            assert_eq!(first, second, "{primitive:?} deterministic textual LLVM");
            let text = std::str::from_utf8(&first).expect("LLVM renderer emits UTF-8");
            assert!(!text.contains("phi void"), "{primitive:?} emitted phi void");
            assert!(machine.as_wir().functions.iter().all(|function| {
                function.values.iter().all(|value| {
                    !matches!(
                        machine.as_wir().types[value.ty.0 as usize].kind,
                        MachineTypeKind::Void
                    )
                })
            }));

            if let Some(llvm_ty) = primitive_llvm_type(primitive) {
                assert_eq!(
                    text.matches(&format!(" = phi {llvm_ty} ")).count(),
                    2,
                    "{primitive:?} exact nested phi count"
                );
                assert!(
                    text.contains(&format!(
                        "define internal fastcc void @__wrela_fn_1({llvm_ty} %v0)"
                    )),
                    "{primitive:?} retained helper parameter"
                );
                assert!(
                    text.contains(&format!("call fastcc void @__wrela_fn_1({llvm_ty} %v")),
                    "{primitive:?} retained post-join call"
                );
            } else {
                assert!(!text.contains(" = phi "), "unit retains an LLVM phi");
                assert!(text.contains("define internal fastcc void @__wrela_fn_1()"));
                assert!(text.contains("call fastcc void @__wrela_fn_1()"));
            }
        }
    }

    #[test]
    fn real_checked_scalar_surface_reaches_machine_v15_and_textual_llvm() {
        let cases = [
            (
                semantic::BinaryOperator::Add,
                semantic::ArithmeticMode::Checked,
                CheckedIntegerOp::Add,
                "_wide_result = add i64",
            ),
            (
                semantic::BinaryOperator::Subtract,
                semantic::ArithmeticMode::Checked,
                CheckedIntegerOp::Subtract,
                "_wide_result = sub i64",
            ),
            (
                semantic::BinaryOperator::Multiply,
                semantic::ArithmeticMode::Checked,
                CheckedIntegerOp::Multiply,
                "_wide_result = mul i64",
            ),
            (
                semantic::BinaryOperator::Divide,
                semantic::ArithmeticMode::Checked,
                CheckedIntegerOp::Divide,
                " = udiv i32",
            ),
            (
                semantic::BinaryOperator::Remainder,
                semantic::ArithmeticMode::Checked,
                CheckedIntegerOp::Remainder,
                " = urem i32",
            ),
            (
                semantic::BinaryOperator::ShiftLeft,
                semantic::ArithmeticMode::Checked,
                CheckedIntegerOp::ShiftLeft,
                " = shl i32",
            ),
            (
                semantic::BinaryOperator::ShiftLeft,
                semantic::ArithmeticMode::Wrapping,
                CheckedIntegerOp::ShiftLeftWrapping,
                " = shl i32",
            ),
            (
                semantic::BinaryOperator::ShiftRight,
                semantic::ArithmeticMode::Checked,
                CheckedIntegerOp::ShiftRight,
                " = lshr i32",
            ),
        ];
        for (operator, arithmetic, expected, ir_fragment) in cases {
            let (machine, target) =
                checked_scalar_producer_fixture(semantic::SemanticOperation::Binary {
                    operator,
                    left: semantic::ValueId(0),
                    right: semantic::ValueId(1),
                    arithmetic,
                });
            assert_eq!(machine.as_wir().version, 15);
            assert!(
                machine
                    .as_wir()
                    .runtime
                    .intrinsics
                    .contains(&RuntimeIntrinsic::Fatal)
            );
            assert!(matches!(
                machine.as_wir().functions[1].blocks[0].instructions[0],
                MachineInstruction {
                    operation: MachineOperation::CheckedInteger {
                        op,
                        signedness: IntegerSignedness::Unsigned,
                        failure: ScalarFailureProvenance {
                            kind: ScalarFailureKind::Arithmetic,
                            flow_function: 1,
                            flow_instruction: 0,
                        },
                        ..
                    },
                    source: Some(source),
                    ..
                } if op == expected && source == source_span(0, 194, 201)
            ));
            let request = CodegenRequest {
                module: &machine,
                target: target.backend(),
                options: CodegenOptions::standard(),
            };
            super::preflight(&request, &|| false).expect("checked scalar codegen preflight");
            let ir =
                super::ir::render_module(&request, &|| false).expect("checked scalar textual LLVM");
            let text = std::str::from_utf8(&ir).expect("UTF-8 checked scalar LLVM");
            assert!(
                text.contains(ir_fragment),
                "missing {ir_fragment:?}: {text}"
            );
            match expected {
                CheckedIntegerOp::ShiftLeft => {
                    assert!(
                        text.contains("_fatal_code = select i1 %t0_count_invalid, i32 6, i32 5")
                    );
                    assert!(text.contains(
                        "call void @wrela_rt_v2_fatal(i32 %t0_fatal_code, i64 4294967296)"
                    ));
                }
                CheckedIntegerOp::ShiftLeftWrapping | CheckedIntegerOp::ShiftRight => {
                    assert!(text.contains("call void @wrela_rt_v2_fatal(i32 6, i64 4294967296)"));
                }
                CheckedIntegerOp::Add
                | CheckedIntegerOp::Subtract
                | CheckedIntegerOp::Multiply
                | CheckedIntegerOp::Divide
                | CheckedIntegerOp::Remainder => {
                    assert!(text.contains("call void @wrela_rt_v2_fatal(i32 1, i64 4294967296)"));
                }
            }
            assert!(text.contains("unreachable\ni0_ok:"));
        }

        let (machine, target) =
            checked_scalar_producer_fixture(semantic::SemanticOperation::Convert {
                value: semantic::ValueId(0),
                destination: semantic::TypeId(2),
                checked: true,
            });
        assert!(matches!(
            machine.as_wir().functions[1].blocks[0].instructions[0].operation,
            MachineOperation::CheckedConvert {
                source: CheckedNumericKind::UnsignedInteger,
                destination_kind: CheckedNumericKind::UnsignedInteger,
                failure: ScalarFailureProvenance {
                    kind: ScalarFailureKind::Conversion,
                    flow_function: 1,
                    flow_instruction: 0,
                },
                ..
            }
        ));
        let request = CodegenRequest {
            module: &machine,
            target: target.backend(),
            options: CodegenOptions::standard(),
        };
        let ir =
            super::ir::render_module(&request, &|| false).expect("checked conversion textual LLVM");
        let text = std::str::from_utf8(&ir).expect("UTF-8 checked conversion LLVM");
        assert!(text.contains("call void @wrela_rt_v2_fatal(i32 2, i64 4294967296)"));
    }

    #[test]
    fn checked_conversion_matrix_renders_exact_range_and_infinity_guards() {
        let cases = [
            (
                CheckedNumericKind::UnsignedInteger,
                MachineTypeKind::Integer { bits: 64 },
                CheckedNumericKind::SignedInteger,
                MachineTypeKind::Integer { bits: 32 },
                "_sign_ok = icmp ult i64",
            ),
            (
                CheckedNumericKind::SignedInteger,
                MachineTypeKind::Integer { bits: 64 },
                CheckedNumericKind::UnsignedInteger,
                MachineTypeKind::Integer { bits: 32 },
                "_sign_ok = icmp sge i64",
            ),
            (
                CheckedNumericKind::UnsignedInteger,
                MachineTypeKind::Integer { bits: 128 },
                CheckedNumericKind::Float32,
                MachineTypeKind::Float32,
                "_positive_infinity = fcmp oeq float",
            ),
            (
                CheckedNumericKind::SignedInteger,
                MachineTypeKind::Integer { bits: 64 },
                CheckedNumericKind::Float64,
                MachineTypeKind::Float64,
                " = sitofp i64",
            ),
            (
                CheckedNumericKind::Float64,
                MachineTypeKind::Float64,
                CheckedNumericKind::Float32,
                MachineTypeKind::Float32,
                "_failed = and i1",
            ),
            (
                CheckedNumericKind::Float32,
                MachineTypeKind::Float32,
                CheckedNumericKind::Float64,
                MachineTypeKind::Float64,
                "_failed = or i1 false, false",
            ),
            (
                CheckedNumericKind::Float32,
                MachineTypeKind::Float32,
                CheckedNumericKind::SignedInteger,
                MachineTypeKind::Integer { bits: 32 },
                "_lower_ok = fcmp oge float",
            ),
            (
                CheckedNumericKind::Float64,
                MachineTypeKind::Float64,
                CheckedNumericKind::UnsignedInteger,
                MachineTypeKind::Integer { bits: 64 },
                "_lower_ok = fcmp ogt double",
            ),
            (
                CheckedNumericKind::Float32,
                MachineTypeKind::Float32,
                CheckedNumericKind::SignedInteger,
                MachineTypeKind::Integer { bits: 128 },
                "_storage = bitcast float",
            ),
            (
                CheckedNumericKind::Float64,
                MachineTypeKind::Float64,
                CheckedNumericKind::UnsignedInteger,
                MachineTypeKind::Integer { bits: 128 },
                "_converted = select i1 false",
            ),
        ];
        for (source_kind, source_type, destination_kind, destination_type, expected) in cases {
            let (machine, target) = checked_conversion_machine_fixture(
                source_kind,
                source_type,
                destination_kind,
                destination_type,
            );
            let request = CodegenRequest {
                module: &machine,
                target: target.backend(),
                options: CodegenOptions::standard(),
            };
            super::preflight(&request, &|| false).expect("checked conversion matrix preflight");
            let ir = super::ir::render_module(&request, &|| false)
                .expect("checked conversion matrix textual LLVM");
            let text = std::str::from_utf8(&ir).expect("UTF-8 checked conversion matrix");
            assert!(text.contains(expected), "missing {expected:?}: {text}");
            assert!(text.contains("call void @wrela_rt_v2_fatal(i32 2, i64 4294967296)"));
        }
    }

    #[test]
    fn checked_i128_division_and_remainder_render_closed_software_semantics() {
        for (operation, signedness) in [
            (CheckedIntegerOp::Divide, IntegerSignedness::Signed),
            (CheckedIntegerOp::Remainder, IntegerSignedness::Signed),
            (CheckedIntegerOp::Divide, IntegerSignedness::Unsigned),
            (CheckedIntegerOp::Remainder, IntegerSignedness::Unsigned),
        ] {
            let (machine, target) = checked_integer_machine_fixture(operation, signedness, 128);
            let request = CodegenRequest {
                module: &machine,
                target: target.backend(),
                options: CodegenOptions::standard(),
            };
            let ir = super::ir::render_module(&request, &|| false)
                .expect("checked i128 software division textual LLVM");
            let text = std::str::from_utf8(&ir).expect("UTF-8 checked i128 LLVM");
            assert!(text.contains("_division_remainder_128 = select i1"));
            assert!(text.contains("_division_quotient_128 = select i1"));
            assert!(!text.contains("sdiv i128"));
            assert!(!text.contains("udiv i128"));
            assert!(!text.contains("srem i128"));
            assert!(!text.contains("urem i128"));
            if operation == CheckedIntegerOp::Divide && signedness == IntegerSignedness::Signed {
                assert!(text.contains("_overflow = and i1"));
            }
        }
    }

    #[test]
    fn checked_integer_guards_preserve_signedness_width_and_failure_edges() {
        let render = |operation, signedness, bits| {
            let (machine, target) = checked_integer_machine_fixture(operation, signedness, bits);
            let request = CodegenRequest {
                module: &machine,
                target: target.backend(),
                options: CodegenOptions::standard(),
            };
            String::from_utf8(
                super::ir::render_module(&request, &|| false)
                    .expect("checked integer edge textual LLVM"),
            )
            .expect("UTF-8 checked integer edge LLVM")
        };

        let signed_divide = render(CheckedIntegerOp::Divide, IntegerSignedness::Signed, 8);
        assert!(signed_divide.contains("_zero = icmp eq i8"));
        assert!(signed_divide.contains("_minimum = icmp eq i8 %v0, 128"));
        assert!(signed_divide.contains("_minus_one = icmp eq i8 %v1, 255"));
        assert!(signed_divide.contains("_failed = or i1"));
        assert!(signed_divide.contains(" = sdiv i8"));

        let signed_remainder = render(CheckedIntegerOp::Remainder, IntegerSignedness::Signed, 8);
        assert!(signed_remainder.contains(" = srem i8"));
        assert!(!signed_remainder.contains("_overflow ="));

        let signed_shift = render(CheckedIntegerOp::ShiftRight, IntegerSignedness::Signed, 8);
        assert!(signed_shift.contains("_negative = icmp slt i8"));
        assert!(signed_shift.contains("_wide_shift = icmp sge i8"));
        assert!(signed_shift.contains(" = ashr i8"));
        assert!(signed_shift.contains("call void @wrela_rt_v2_fatal(i32 6,"));

        let unsigned_shift = render(CheckedIntegerOp::ShiftRight, IntegerSignedness::Unsigned, 8);
        assert!(unsigned_shift.contains("_failed = icmp uge i8"));
        assert!(unsigned_shift.contains(" = lshr i8"));
        assert!(unsigned_shift.contains("call void @wrela_rt_v2_fatal(i32 6,"));

        let signed_left = render(CheckedIntegerOp::ShiftLeft, IntegerSignedness::Signed, 8);
        assert!(signed_left.contains("_count_invalid = or i1"));
        assert!(signed_left.contains("_safe_count = select i1"));
        assert!(signed_left.contains(" = shl i8"));
        assert!(signed_left.contains("_roundtrip = ashr i8"));
        assert!(signed_left.contains("_lost = icmp ne i8"));
        assert!(signed_left.contains("_fatal_code = select i1 %t0_count_invalid, i32 6, i32 5"));
        assert!(signed_left.contains("call void @wrela_rt_v2_fatal(i32 %t0_fatal_code,"));
        assert!(!signed_left.contains("shl nsw"));
        assert!(!signed_left.contains("shl nuw"));

        let unsigned_left = render(CheckedIntegerOp::ShiftLeft, IntegerSignedness::Unsigned, 8);
        assert!(unsigned_left.contains("_count_invalid = icmp uge i8"));
        assert!(unsigned_left.contains("_safe_count = select i1"));
        assert!(unsigned_left.contains("_roundtrip = lshr i8"));

        let wrapping_left = render(
            CheckedIntegerOp::ShiftLeftWrapping,
            IntegerSignedness::Signed,
            8,
        );
        assert!(wrapping_left.contains("_safe_count = select i1"));
        assert!(wrapping_left.contains(" = shl i8"));
        assert!(!wrapping_left.contains("_roundtrip ="));
        assert!(!wrapping_left.contains("_lost ="));
        assert!(wrapping_left.contains("call void @wrela_rt_v2_fatal(i32 6,"));

        let signed_i128_left = render(CheckedIntegerOp::ShiftLeft, IntegerSignedness::Signed, 128);
        assert!(signed_i128_left.contains("_safe_count = select i1"));
        assert!(signed_i128_left.contains(" = shl i128"));
        assert!(signed_i128_left.contains("_roundtrip = ashr i128"));

        let unsigned_i128_wrapping = render(
            CheckedIntegerOp::ShiftLeftWrapping,
            IntegerSignedness::Unsigned,
            128,
        );
        assert!(unsigned_i128_wrapping.contains("_count_invalid = icmp uge i128"));
        assert!(unsigned_i128_wrapping.contains("_safe_count = select i1"));
        assert!(unsigned_i128_wrapping.contains(" = shl i128"));
        assert!(!unsigned_i128_wrapping.contains("_roundtrip ="));

        let signed_add = render(CheckedIntegerOp::Add, IntegerSignedness::Signed, 128);
        assert!(signed_add.contains("sext i128 %v0 to i256"));
        assert!(signed_add.contains("_failed = icmp ne i256"));

        let unsigned_multiply =
            render(CheckedIntegerOp::Multiply, IntegerSignedness::Unsigned, 128);
        assert!(unsigned_multiply.contains("zext i128 %v0 to i256"));
        assert!(unsigned_multiply.contains("_wide_result = mul i256"));
    }

    #[test]
    fn checked_i128_rendering_obeys_exact_ir_limit_and_mid_operation_cancellation() {
        let (machine, target) = checked_integer_machine_fixture(
            CheckedIntegerOp::Divide,
            IntegerSignedness::Unsigned,
            128,
        );
        let baseline_request = CodegenRequest {
            module: &machine,
            target: target.backend(),
            options: CodegenOptions::standard(),
        };
        let baseline = super::ir::render_module(&baseline_request, &|| false)
            .expect("checked i128 baseline IR");
        let exact_bytes = u64::try_from(baseline.len()).expect("bounded checked i128 IR");
        let mut exact = CodegenOptions::standard();
        exact.maximum_ir_bytes = exact_bytes;
        super::ir::render_module(
            &CodegenRequest {
                module: &machine,
                target: target.backend(),
                options: exact,
            },
            &|| false,
        )
        .expect("exact checked i128 IR byte limit");
        exact.maximum_ir_bytes -= 1;
        assert!(matches!(
            super::ir::render_module(
                &CodegenRequest {
                    module: &machine,
                    target: target.backend(),
                    options: exact,
                },
                &|| false,
            ),
            Err(CodegenError::ResourceLimit {
                resource: "LLVM IR bytes",
                ..
            })
        ));

        let polls = Cell::new(0_u32);
        assert_eq!(
            super::ir::render_module(&baseline_request, &|| {
                let next = polls.get().saturating_add(1);
                polls.set(next);
                next > 100
            }),
            Err(CodegenError::Cancelled)
        );
        assert!(polls.get() > 100);
    }

    #[test]
    fn producer_scalar_preflight_enforces_max_plus_one_and_late_cancellation() {
        let (machine, target) = ordinary_scalar_producer_fixture();
        let actual_instructions = machine
            .as_wir()
            .functions
            .iter()
            .flat_map(|function| &function.blocks)
            .map(|block| block.instructions.len() as u64)
            .sum::<u64>();
        assert!(
            actual_instructions > 1,
            "producer fixture must exercise a real body"
        );

        let mut exact_options = CodegenOptions::standard();
        exact_options.maximum_instructions = actual_instructions;
        super::preflight(
            &CodegenRequest {
                module: &machine,
                target: target.backend(),
                options: exact_options,
            },
            &|| false,
        )
        .expect("the exact producer instruction boundary is accepted");

        let mut max_plus_one_options = exact_options;
        max_plus_one_options.maximum_instructions = actual_instructions - 1;
        assert_eq!(
            super::preflight(
                &CodegenRequest {
                    module: &machine,
                    target: target.backend(),
                    options: max_plus_one_options,
                },
                &|| false,
            ),
            Err(CodegenError::ResourceLimit {
                resource: "instructions",
                limit: actual_instructions - 1,
                actual: actual_instructions,
            })
        );

        let request = CodegenRequest {
            module: &machine,
            target: target.backend(),
            options: CodegenOptions::standard(),
        };
        let calibration_polls = Cell::new(0usize);
        super::preflight(&request, &|| {
            calibration_polls.set(calibration_polls.get().saturating_add(1));
            false
        })
        .expect("producer preflight calibration succeeds");
        let final_poll = calibration_polls.get();
        assert!(
            final_poll > 1,
            "preflight must expose a late cancellation boundary"
        );

        let observed_polls = Cell::new(0usize);
        assert_eq!(
            super::preflight(&request, &|| {
                let next = observed_polls.get().saturating_add(1);
                observed_polls.set(next);
                next == final_poll
            }),
            Err(CodegenError::Cancelled)
        );
        assert_eq!(observed_polls.get(), final_poll);
    }

    #[test]
    fn producer_shaped_malformed_operation_fails_closed_before_rendering() {
        let (machine, target) = ordinary_scalar_producer_fixture();
        let mut malformed = machine.as_wir().clone();
        let (function_index, block_index, instruction_index) = malformed
            .functions
            .iter()
            .enumerate()
            .find_map(|(function_index, function)| {
                function
                    .blocks
                    .iter()
                    .enumerate()
                    .find_map(|(block_index, block)| {
                        block
                            .instructions
                            .iter()
                            .position(|instruction| {
                                matches!(instruction.operation, MachineOperation::Immediate(_))
                            })
                            .map(|instruction_index| {
                                (function_index, block_index, instruction_index)
                            })
                    })
            })
            .expect("producer fixture contains a scalar immediate");
        let function = malformed.functions[function_index].id.0;
        let instruction = &mut malformed.functions[function_index].blocks[block_index].instructions
            [instruction_index];
        let instruction_id = instruction.id.0;
        instruction.operation = MachineOperation::Immediate(MachineImmediate::Bytes(vec![0]));
        let malformed = malformed
            .validate_for_target(&target)
            .expect("byte immediate remains structurally valid MachineWir");
        assert_eq!(
            super::preflight(
                &CodegenRequest {
                    module: &malformed,
                    target: target.backend(),
                    options: CodegenOptions::standard(),
                },
                &|| false,
            ),
            Err(CodegenError::UnsupportedMachineOperation {
                function,
                instruction: instruction_id,
            })
        );
    }

    #[test]
    fn generated_test_surface_renders_exact_globals_and_runtime_calls() {
        let (machine, target, frames) = runtime_test_fixture();
        let request = CodegenRequest {
            module: &machine,
            target: target.backend(),
            options: CodegenOptions::standard(),
        };
        super::preflight(&request, &|| false)
            .expect("validated test metadata and runtime surface pass preflight");
        let bytes = super::ir::render_module(&request, &|| false)
            .expect("generated test surface renders to bounded LLVM IR");
        let text = std::str::from_utf8(&bytes).expect("LLVM IR is UTF-8");
        let escaped_frames = frames
            .iter()
            .map(|frame| {
                frame
                    .iter()
                    .map(|byte| format!("\\{byte:02X}"))
                    .collect::<String>()
            })
            .collect::<Vec<_>>();
        for required in [
            "declare i64 @wrela_rt_v2_image_enter(ptr, ptr)",
            "declare i64 @wrela_rt_v2_test_emit(ptr, i64)",
            "declare void @wrela_rt_v2_test_finish(i32) noreturn",
            "@__wrela_test_frame_0 = internal constant",
            "section \".rdata.wrela.test\", align 8",
            "getelementptr i8, ptr @__wrela_test_frame_0, i64 0",
            "@__wrela_test_frame_1 = internal constant",
            "section \".rdata.wrela.test\", align 1",
            "getelementptr i8, ptr @__wrela_test_frame_1, i64 0",
            "%v4 = call i64 @wrela_rt_v2_test_emit(ptr %v2, i64 %v3)",
            "switch i64 %v4",
            "i64 0, label %b2",
            "ret i64 %v4",
            "%v7 = call i64 @wrela_rt_v2_test_emit(ptr %v5, i64 %v6)",
            "switch i64 %v7",
            "i64 0, label %b4",
            "ret i64 %v7",
            "@__wrela_test_frame_2 = internal constant",
            "%v10 = call i64 @wrela_rt_v2_test_emit(ptr %v8, i64 %v9)",
            "i64 0, label %b6",
            "ret i64 %v10",
            "@__wrela_test_frame_3 = internal constant",
            "%v13 = call i64 @wrela_rt_v2_test_emit(ptr %v11, i64 %v12)",
            "i64 0, label %b8",
            "ret i64 %v13",
            "call void @wrela_rt_v2_test_finish(i32 %v14)",
            "%v15 = call i64 @wrela_rt_v2_image_enter(ptr %v0, ptr %v1)",
            "switch i64 %v15",
            "i64 0, label %b0",
            "ret i64 %v15",
        ] {
            assert!(
                text.contains(required),
                "missing LLVM IR fragment {required:?}"
            );
        }
        for escaped_frame in escaped_frames {
            assert!(text.contains(&format!("c\"{escaped_frame}\"")));
        }
        assert_eq!(machine.as_wir().tests[0].function, FunctionId(1));
        assert!(matches!(
            machine.as_wir().functions[0].origin,
            MachineFunctionOrigin::GeneratedTestHarness { group: 9, .. }
        ));
    }

    #[test]
    fn generated_test_assertion_seal_rejects_substitution_and_direct_runtime_calls() {
        let (machine, target, _) = runtime_assertion_fixture(false);

        let mut corrupt_padding = machine.as_wir().clone();
        let MachineImmediate::Bytes(bytes) = &mut corrupt_padding.globals[4].initializer else {
            panic!("assertion expression storage")
        };
        *bytes.last_mut().expect("fixed assertion storage") = 1;
        let errors = corrupt_padding
            .validate_for_target(&target)
            .expect_err("nonzero assertion padding");
        assert!(errors.0.contains(&ValidationError::InvalidRecord {
            kind: "generated test assertion",
            id: 1,
        }));

        let mut substituted_source = machine.as_wir().clone();
        substituted_source.functions[1].blocks[0].instructions[1].source = Some(Span {
            file: FileId(0),
            range: TextRange { start: 6, end: 10 },
        });
        let errors = substituted_source
            .validate_for_target(&target)
            .expect_err("substituted assertion source");
        assert!(errors.0.contains(&ValidationError::InvalidRecord {
            kind: "generated test assertion",
            id: 1,
        }));

        let mut direct = machine.as_wir().clone();
        direct.functions[1].blocks[0].instructions[1].operation = MachineOperation::RuntimeCall {
            intrinsic: RuntimeIntrinsic::TestAssertionFail,
            arguments: Vec::new(),
        };
        let errors = direct
            .validate_for_target(&target)
            .expect_err("source MachineWir cannot directly call assertion runtime");
        assert!(
            errors
                .0
                .contains(&ValidationError::InvalidTestRuntimeContext {
                    intrinsic: RuntimeIntrinsic::TestAssertionFail,
                    function: FunctionId(1),
                    instruction: InstructionId(1),
                })
        );
    }

    #[test]
    fn generated_test_assertion_renders_exact_false_edge_and_noreturn_call() {
        for condition in [true, false] {
            let (machine, target, _) = runtime_assertion_fixture(condition);
            let request = CodegenRequest {
                module: &machine,
                target: target.backend(),
                options: CodegenOptions::standard(),
            };
            super::preflight(&request, &|| false).expect("assertion preflight");
            let bytes = super::ir::render_module(&request, &|| false)
                .expect("assertion MachineWir renders to LLVM IR");
            let text = std::str::from_utf8(&bytes).expect("LLVM IR is UTF-8");
            for required in [
                "declare void @wrela_rt_v2_test_assertion_fail(ptr, i64, ptr, i64, i32, i32, i32) noreturn",
                "%t1_assertion = icmp ne i8 %v0, 0\n  br i1 %t1_assertion, label %i1_ok, label %i1_assert_fail",
                "i1_assert_fail:\n  call void @wrela_rt_v2_test_assertion_fail(ptr @__wrela_assertion_0, i64 5, ptr @__wrela_assertion_1, i64 37, i32 0, i32 5, i32 10)",
                "unreachable\ni1_ok:",
            ] {
                assert!(text.contains(required), "missing {required:?}: {text}");
            }
        }
    }

    #[test]
    fn generated_test_seal_rejects_cross_emit_status_remapping_before_codegen() {
        let (machine, target, _) = runtime_test_fixture();
        let mut remapped = machine.as_wir().clone();
        let MachineTerminator::Switch { value, .. } =
            &mut remapped.functions[0].blocks[2].terminator
        else {
            panic!("second canonical TestEmit guard")
        };
        // The first status dominates this block and has the same EFI_STATUS
        // type, so ordinary SSA/type validation cannot detect this swap. The
        // generated-harness contract must bind each guard to its own call.
        *value = ValueId(4);
        let errors = remapped
            .validate_for_target(&target)
            .expect_err("a later TestEmit may not reuse an earlier status");
        assert!(
            errors
                .0
                .contains(&ValidationError::InvalidTestEmitStatusContract {
                    function: FunctionId(0),
                    instruction: InstructionId(5),
                })
        );
    }

    #[test]
    fn renderer_observes_cancellation_inside_input_sized_global_data() {
        let (machine, target, _) = runtime_assertion_fixture(false);
        let request = CodegenRequest {
            module: &machine,
            target: target.backend(),
            options: CodegenOptions::standard(),
        };
        let polls = Cell::new(0usize);
        let result = super::ir::render_module(&request, &|| {
            let next = polls.get().saturating_add(1);
            polls.set(next);
            next > 32
        });
        assert_eq!(result, Err(CodegenError::Cancelled));
        assert!(
            polls.get() > 32,
            "renderer never reached the cancellation poll"
        );
    }

    #[test]
    fn measurement_sort_reports_cancellation_without_panicking() {
        let mut values: Vec<_> = (0..16_384u32).rev().collect();
        let polls = Cell::new(0usize);
        let comparisons = Cell::new(0usize);
        let cancel_at = values.len() + 10;
        let result = super::cancellable_sort_by(
            &mut values,
            |left, right| {
                comparisons.set(comparisons.get() + 1);
                Ok(left.cmp(right))
            },
            &|| {
                let next = polls.get().saturating_add(1);
                polls.set(next);
                next >= cancel_at
            },
        );
        assert_eq!(result, Err(CodegenError::Cancelled));
        assert_eq!(polls.get(), cancel_at);
        assert!(
            comparisons.get() <= 4,
            "sort kept working after cancellation"
        );

        let long_prefix = "x".repeat(2_049);
        let text_polls = Cell::new(0usize);
        assert_eq!(
            super::cancellable_text_compare(&long_prefix, &long_prefix, &|| {
                let next = text_polls.get() + 1;
                text_polls.set(next);
                next == 2
            }),
            Err(CodegenError::Cancelled)
        );
        assert_eq!(text_polls.get(), 2);

        let long_triple = "x".repeat(64 * 1024 * 3);
        let copy_polls = Cell::new(0usize);
        assert_eq!(
            super::cancellable_copy_text(&long_triple, long_triple.len() as u64, &|| {
                let next = copy_polls.get() + 1;
                copy_polls.set(next);
                next == 4
            },),
            Err(CodegenError::Cancelled)
        );
        assert_eq!(copy_polls.get(), 4);
    }

    #[test]
    fn checked_scalar_cfg_renders_the_complete_scalar_and_control_flow_surface() {
        let (machine, target) = scalar_fixture();
        let request = CodegenRequest {
            module: &machine,
            target: target.backend(),
            options: CodegenOptions::standard(),
        };
        super::preflight(&request, &|| false).expect("checked scalar CFG passes codegen preflight");
        let bytes = super::ir::render_module(&request, &|| false).expect("render scalar CFG");
        let text = std::str::from_utf8(&bytes).expect("UTF-8 LLVM IR");
        for required in [
            "define internal fastcc i64 @__wrela_fn_1",
            "getelementptr i8, ptr %v0",
            "load i64, ptr %v3, align 1",
            "store i64 %v4, ptr %v3, align 1",
            "call fastcc i64 @__wrela_fn_1",
            "phi i64",
            "switch i64",
            "musttail call fastcc i64 @__wrela_fn_1",
            "fence acq_rel",
            "dmb osh",
            "unreachable",
            "fcmp olt float",
            "fcmp une float",
            "fcmp une double",
            "bitcast float",
            "sub i64",
            "mul i64",
            "and i64",
            "or i64",
            "xor i64",
            "icmp eq i64",
            "icmp ne i64",
            "icmp ult i64",
            "icmp ule i64",
            "icmp ugt i64",
            "icmp uge i64",
            "icmp slt i64",
            "icmp sle i64",
            "icmp sgt i64",
            "icmp sge i64",
        ] {
            assert!(
                text.contains(required),
                "missing LLVM IR fragment {required:?}"
            );
        }
    }

    #[test]
    fn float_not_equal_renders_llvm_unordered_or_not_equal_for_nan() {
        let (machine, target) = scalar_fixture();
        let request = CodegenRequest {
            module: &machine,
            target: target.backend(),
            options: CodegenOptions::standard(),
        };
        let bytes = super::ir::render_module(&request, &|| false)
            .expect("render unordered float not-equal");
        let text = std::str::from_utf8(&bytes).expect("UTF-8 LLVM IR");
        assert!(text.contains("%v3 = bitcast i32 2143289344 to float"));
        assert!(text.contains("%t24_compare = fcmp une float %v3, %v4"));
        assert!(text.contains("%v27 = zext i1 %t24_compare to i8"));
        assert!(text.contains("%v28 = bitcast i64 9221120237041090560 to double"));
        assert!(text.contains("%t27_compare = fcmp une double %v28, %v29"));
        assert!(text.contains("%v30 = zext i1 %t27_compare to i8"));
        assert!(!text.contains("fcmp one"));
        let nan = f32::from_bits(0x7fc0_0000);
        let same_nan = f32::from_bits(0x7fc0_0000);
        assert!(nan.is_nan() && same_nan.is_nan() && nan != same_nan);
        let wide_nan = f64::from_bits(0x7ff8_0000_0000_0000);
        let same_wide_nan = f64::from_bits(0x7ff8_0000_0000_0000);
        assert!(wide_nan.is_nan() && same_wide_nan.is_nan() && wide_nan != same_wide_nan);
    }

    #[test]
    fn unary_and_exact_casts_render_without_trap_or_nan_approximations() {
        let (machine, target) = unary_cast_scalar_fixture();
        let request = CodegenRequest {
            module: &machine,
            target: target.backend(),
            options: CodegenOptions::standard(),
        };
        super::preflight(&request, &|| false).expect("unary/cast scalar preflight");
        let bytes =
            super::ir::render_module(&request, &|| false).expect("render unary and exact casts");
        let text = std::str::from_utf8(&bytes).expect("UTF-8 LLVM IR");
        for required in [
            "%t29_bool_not = icmp eq i8 %v31, 0",
            "%v32 = zext i1 %t29_bool_not to i8",
            "%v34 = xor i8 %v33, -1",
            "%t33_negated = fneg float %v35",
            "%t33_nan = fcmp uno float %v35, %v35",
            "%t33_canonical_nan = bitcast i32 2143289344 to float",
            "%v36 = select i1 %t33_nan, float %t33_canonical_nan, float %t33_negated",
            "%t35_negated = fneg double %v37",
            "%t35_nan = fcmp uno double %v37, %v37",
            "%t35_canonical_nan = bitcast i64 9221120237041090560 to double",
            "%v38 = select i1 %t35_nan, double %t35_canonical_nan, double %t35_negated",
            "%v39 = zext i8 %v33 to i16",
            "%v40 = sext i8 %v33 to i16",
            "%v41 = fpext float %v35 to double",
            "%v42 = uitofp i8 %v33 to float",
            "%v43 = sitofp i8 %v33 to float",
            "%v44 = bitcast float %v35 to i32",
            "%v45 = bitcast i32 %v44 to float",
        ] {
            assert!(
                text.contains(required),
                "missing unary/cast LLVM IR fragment {required:?}"
            );
        }

        let mut lossy = machine.as_wir().clone();
        let MachineOperation::Convert { op, .. } =
            &mut lossy.functions[1].blocks[0].instructions[41].operation
        else {
            panic!("f32-to-u32 bitcast");
        };
        *op = ConversionOp::FloatToUnsignedInteger;
        let lossy = lossy
            .validate_for_target(&target)
            .expect("float-to-integer substitution is structurally valid MachineWir");
        assert_eq!(
            super::preflight(
                &CodegenRequest {
                    module: &lossy,
                    target: target.backend(),
                    options: CodegenOptions::standard(),
                },
                &|| false,
            ),
            Err(CodegenError::UnsupportedMachineOperation {
                function: 1,
                instruction: 41,
            })
        );
    }

    #[test]
    fn scalar_preflight_rejects_unsupported_operations_facts_and_limits() {
        let (machine, target) = scalar_fixture();
        let mut unsupported = machine.as_wir().clone();
        unsupported.functions[1].blocks[0].instructions[0].operation =
            MachineOperation::Immediate(MachineImmediate::Bytes(vec![0; 8]));
        let unsupported = unsupported
            .validate_for_target(&target)
            .expect("byte immediate remains structurally valid MachineWir");
        assert!(matches!(
            super::preflight(
                &CodegenRequest {
                    module: &unsupported,
                    target: target.backend(),
                    options: CodegenOptions::standard(),
                },
                &|| false,
            ),
            Err(CodegenError::UnsupportedMachineOperation {
                function: 1,
                instruction: 0
            })
        ));

        let mut unproved = machine.as_wir().clone();
        let MachineOperation::Load { facts, .. } =
            &mut unproved.functions[0].blocks[0].instructions[2].operation
        else {
            panic!("checked load fixture");
        };
        facts.no_alias = true;
        let unproved = unproved
            .validate_for_target(&target)
            .expect("MachineWir accepts the proof-bearing backend flag structurally");
        assert!(matches!(
            super::preflight(
                &CodegenRequest {
                    module: &unproved,
                    target: target.backend(),
                    options: CodegenOptions::standard(),
                },
                &|| false,
            ),
            Err(CodegenError::InvalidBackendFact {
                function: 0,
                instruction: 2,
                ..
            })
        ));

        let mut options = CodegenOptions::standard();
        options.maximum_functions = 1;
        assert!(matches!(
            super::preflight(
                &CodegenRequest {
                    module: &machine,
                    target: target.backend(),
                    options,
                },
                &|| false,
            ),
            Err(CodegenError::ResourceLimit {
                resource: "functions",
                limit: 1,
                actual: 2
            })
        ));
        assert_eq!(
            super::ir::render_module(
                &CodegenRequest {
                    module: &machine,
                    target: target.backend(),
                    options: CodegenOptions::standard(),
                },
                &|| true,
            ),
            Err(CodegenError::Cancelled)
        );
    }

    #[test]
    fn bounded_coff_inspection_derives_real_ranges() {
        let (machine, target) = fixture();
        let bytes = ordinary_coff_fixture();
        let options = CodegenOptions::standard();
        let (sections, symbols) = super::coff::measure_object(&bytes, &machine, options, &|| false)
            .expect("bounded COFF inspection");
        assert_eq!(sections.len(), 2);
        assert_eq!(symbols.len(), 2);
        assert_eq!(
            symbols
                .iter()
                .find(|symbol| symbol.name == "wrela_image_entry")
                .map(|symbol| symbol.bytes),
            Some(8)
        );
        let artifact = seal_object(
            &CodegenRequest {
                module: &machine,
                target: target.backend(),
                options,
            },
            bytes,
            sections,
            symbols,
            &|| false,
        )
        .expect("inspected object seals");
        assert_eq!(artifact.sections().len(), 2);
    }

    #[test]
    fn public_seal_rejects_arm64_magic_with_forged_measurements() {
        let (machine, target) = fixture();
        let options = CodegenOptions::standard();
        let valid_bytes = ordinary_coff_fixture();
        let (sections, symbols) =
            super::coff::measure_object(&valid_bytes, &machine, options, &|| false)
                .expect("valid source measurements");
        let mut fake_bytes = vec![0u8; valid_bytes.len()];
        fake_bytes[..2].copy_from_slice(&[0x64, 0xaa]);
        let error = seal_object(
            &CodegenRequest {
                module: &machine,
                target: target.backend(),
                options,
            },
            fake_bytes,
            sections,
            symbols,
            &|| false,
        )
        .expect_err("ARM64 magic alone cannot seal an object");
        assert!(matches!(error, CodegenError::InvalidObjectMeasurements(_)));
    }

    #[test]
    fn coff_inspection_rejects_trailing_and_noncanonical_ranges() {
        let (machine, _) = fixture();
        let options = CodegenOptions::standard();
        let mut trailing = ordinary_coff_fixture();
        trailing.push(1);
        assert_eq!(
            super::coff::measure_object(&trailing, &machine, options, &|| false),
            Err(CodegenError::InvalidObjectMeasurements(
                "COFF has noncanonical trailing bytes after its string table"
            ))
        );

        let mut overlapping = ordinary_coff_fixture();
        write_u32(&mut overlapping, 20 + 20, 20);
        assert!(matches!(
            super::coff::measure_object(&overlapping, &machine, options, &|| false),
            Err(CodegenError::InvalidObjectMeasurements(_))
        ));
    }

    #[test]
    fn coff_inspection_proves_declared_sections_relocations_and_symbols() {
        const TEXT_HEADER: usize = 20;
        const TEXT_OFFSET: usize = 20 + 2 * 40;
        const METADATA_OFFSET: usize = TEXT_OFFSET + 8;
        const RELOCATION_OFFSET: usize = METADATA_OFFSET + 8;
        const SYMBOL_OFFSET: usize = METADATA_OFFSET + 8 + 10;

        let (machine, _) = fixture();
        let options = CodegenOptions::standard();
        let rejected = |bytes: &[u8]| {
            assert!(matches!(
                super::coff::measure_object(bytes, &machine, options, &|| false),
                Err(CodegenError::InvalidObjectMeasurements(_))
            ));
        };

        let mut nonzero_metadata = ordinary_coff_fixture();
        nonzero_metadata[METADATA_OFFSET] = 1;
        rejected(&nonzero_metadata);

        let mut writable_text = ordinary_coff_fixture();
        write_u32(&mut writable_text, TEXT_HEADER + 36, 0xe050_0020);
        rejected(&writable_text);

        let mut zero_fill_text = ordinary_coff_fixture();
        write_u32(&mut zero_fill_text, TEXT_HEADER + 8, 8);
        write_u32(&mut zero_fill_text, TEXT_HEADER + 16, 0);
        rejected(&zero_fill_text);

        let mut addressed_text = ordinary_coff_fixture();
        write_u32(&mut addressed_text, TEXT_HEADER + 12, 8);
        rejected(&addressed_text);

        let mut relocation = ordinary_coff_fixture();
        write_u32(&mut relocation, TEXT_HEADER + 24, TEXT_OFFSET as u32);
        write_u16(&mut relocation, TEXT_HEADER + 32, 1);
        rejected(&relocation);

        let mut omitted_runtime_relocation = ordinary_coff_fixture();
        write_u32(&mut omitted_runtime_relocation, TEXT_HEADER + 24, 0);
        write_u16(&mut omitted_runtime_relocation, TEXT_HEADER + 32, 0);
        omitted_runtime_relocation[RELOCATION_OFFSET..RELOCATION_OFFSET + 10].fill(0);
        assert_eq!(
            super::coff::measure_object(&omitted_runtime_relocation, &machine, options, &|| false,),
            Err(CodegenError::InvalidObjectMeasurements(
                "required runtime call relocation is missing"
            ))
        );

        let mut wrong_runtime_relocation_kind = ordinary_coff_fixture();
        write_u16(&mut wrong_runtime_relocation_kind, RELOCATION_OFFSET + 8, 2);
        assert_eq!(
            super::coff::measure_object(&wrong_runtime_relocation_kind, &machine, options, &|| {
                false
            },),
            Err(CodegenError::InvalidObjectMeasurements(
                "runtime call relocation is not an exact ARM64 branch"
            ))
        );

        let mut wrong_runtime_relocation_opcode = ordinary_coff_fixture();
        wrong_runtime_relocation_opcode[TEXT_OFFSET..TEXT_OFFSET + 4]
            .copy_from_slice(&[0x1f, 0x20, 0x03, 0xd5]);
        assert_eq!(
            super::coff::measure_object(
                &wrong_runtime_relocation_opcode,
                &machine,
                options,
                &|| false,
            ),
            Err(CodegenError::InvalidObjectMeasurements(
                "runtime call relocation does not select an ARM64 BL"
            ))
        );

        let mut misdirected_runtime_relocation = ordinary_coff_fixture();
        write_u32(
            &mut misdirected_runtime_relocation,
            RELOCATION_OFFSET + 4,
            0,
        );
        assert_eq!(
            super::coff::measure_object(
                &misdirected_runtime_relocation,
                &machine,
                options,
                &|| false,
            ),
            Err(CodegenError::InvalidObjectMeasurements(
                "internal relocation has no exact MachineWir branch"
            ))
        );

        let mut wrong_entry_type = ordinary_coff_fixture();
        write_u16(&mut wrong_entry_type, SYMBOL_OFFSET + 14, 0);
        rejected(&wrong_entry_type);

        let mut nonexternal_entry = ordinary_coff_fixture();
        nonexternal_entry[SYMBOL_OFFSET + 16] = 3;
        rejected(&nonexternal_entry);

        let mut defined_runtime = ordinary_coff_fixture();
        defined_runtime[SYMBOL_OFFSET + 2 * 18 + 16] = 3;
        rejected(&defined_runtime);

        let mut nonruntime_relocation = ordinary_coff_fixture();
        write_u32(&mut nonruntime_relocation, RELOCATION_OFFSET + 4, 3);
        rejected(&nonruntime_relocation);

        let mut nonzero_features = ordinary_coff_fixture();
        write_u32(&mut nonzero_features, SYMBOL_OFFSET + 3 * 18 + 8, 1);
        rejected(&nonzero_features);
    }

    #[cfg(feature = "llvm")]
    #[test]
    fn canonical_producer_reaches_real_llvm_coff_consumer() {
        let (machine, target) = real_producer_fixture();
        let artifact = CanonicalLlvmCodeGenerator::new()
            .emit_object(
                CodegenRequest {
                    module: &machine,
                    target: target.backend(),
                    options: CodegenOptions::standard(),
                },
                &|| false,
            )
            .expect("validated minimum MachineWir emits through LLVM");
        assert_eq!(&artifact.bytes()[..2], &[0x64, 0xaa]);
        let metadata = artifact
            .sections()
            .iter()
            .find(|section| section.name == INTERRUPT_ROUTE_SECTION)
            .expect("interrupt metadata section");
        let start = usize::try_from(metadata.file_offset).expect("host offset");
        let end = start + usize::try_from(metadata.file_bytes).expect("host size");
        assert_eq!(&artifact.bytes()[start..end], &[0; 8]);
        assert!(
            artifact
                .symbols()
                .iter()
                .any(|symbol| symbol.name == INTERRUPT_ROUTE_TABLE_SYMBOL && symbol.bytes == 8)
        );
    }

    #[cfg(feature = "llvm")]
    #[test]
    fn ordinary_scalar_producer_emits_deterministic_native_coff() {
        let (machine, target) = ordinary_scalar_producer_fixture();
        let emit = || {
            CanonicalLlvmCodeGenerator::new()
                .emit_object(
                    CodegenRequest {
                        module: &machine,
                        target: target.backend(),
                        options: CodegenOptions::standard(),
                    },
                    &|| false,
                )
                .expect("production scalar MachineWir emits through pinned LLVM")
        };
        let first = emit();
        let second = emit();
        assert_eq!(
            first, second,
            "identical producer input must seal identically"
        );
        assert_eq!(
            first.bytes().get(..2).expect("COFF header bytes"),
            &[0x64, 0xaa]
        );

        let (measured_sections, measured_symbols) = super::coff::measure_object(
            first.bytes(),
            &machine,
            CodegenOptions::standard(),
            &|| false,
        )
        .expect("emitted producer object passes the independent COFF consumer");
        assert_eq!(measured_sections.as_slice(), first.sections());
        assert_eq!(measured_symbols.as_slice(), first.symbols());

        let wir = machine.as_wir();
        for function in &wir.functions {
            let section = wir
                .sections
                .get(function.section.0 as usize)
                .expect("validated producer function section");
            assert!(
                first
                    .sections()
                    .iter()
                    .any(|emitted| { emitted.name == section.name && emitted.file_bytes != 0 })
            );
            let symbol = wir
                .symbols
                .get(function.symbol.0 as usize)
                .expect("validated producer function symbol");
            assert!(
                first
                    .symbols()
                    .iter()
                    .any(|emitted| emitted.name == symbol.name)
            );
        }
    }

    #[cfg(feature = "llvm")]
    #[test]
    fn every_primitive_join_emits_deterministic_native_coff() {
        for primitive in primitive_join_matrix() {
            let (machine, target) = primitive_join_machine_fixture(primitive);
            let emit = || {
                CanonicalLlvmCodeGenerator::new()
                    .emit_object(
                        CodegenRequest {
                            module: &machine,
                            target: target.backend(),
                            options: CodegenOptions::standard(),
                        },
                        &|| false,
                    )
                    .unwrap_or_else(|error| {
                        panic!("{primitive:?} emits through pinned LLVM: {error:?}")
                    })
            };
            let first = emit();
            let second = emit();
            assert_eq!(first, second, "{primitive:?} must seal deterministically");
            assert_eq!(
                first.bytes().get(..2).expect("COFF header bytes"),
                &[0x64, 0xaa],
                "{primitive:?} AArch64 COFF header"
            );

            let (measured_sections, measured_symbols) = super::coff::measure_object(
                first.bytes(),
                &machine,
                CodegenOptions::standard(),
                &|| false,
            )
            .unwrap_or_else(|error| {
                panic!("{primitive:?} independent COFF consumption: {error:?}")
            });
            assert_eq!(measured_sections.as_slice(), first.sections());
            assert_eq!(measured_symbols.as_slice(), first.symbols());
        }
    }

    #[cfg(feature = "llvm")]
    #[test]
    fn real_checked_scalar_reaches_pinned_llvm_and_fatal_coff_relocation() {
        let (machine, target) =
            checked_scalar_producer_fixture(semantic::SemanticOperation::Binary {
                operator: semantic::BinaryOperator::Multiply,
                left: semantic::ValueId(0),
                right: semantic::ValueId(1),
                arithmetic: semantic::ArithmeticMode::Checked,
            });
        let artifact = CanonicalLlvmCodeGenerator::new()
            .emit_object(
                CodegenRequest {
                    module: &machine,
                    target: target.backend(),
                    options: CodegenOptions::standard(),
                },
                &|| false,
            )
            .expect("checked scalar emits through pinned LLVM and COFF inspection");
        assert_eq!(&artifact.bytes()[..2], &[0x64, 0xaa]);
        assert!(
            artifact
                .sections()
                .iter()
                .any(|section| section.name == ".text.wrela.1" && section.file_bytes != 0)
        );
        assert!(
            !artifact
                .symbols()
                .iter()
                .any(|symbol| symbol.name == RuntimeIntrinsic::Fatal.symbol_name())
        );
    }

    #[cfg(feature = "llvm")]
    #[test]
    fn checked_i128_matrix_reaches_pinned_llvm_without_implicit_runtime_symbols() {
        for (operation, signedness) in [
            (CheckedIntegerOp::Add, IntegerSignedness::Signed),
            (CheckedIntegerOp::Subtract, IntegerSignedness::Signed),
            (CheckedIntegerOp::Multiply, IntegerSignedness::Signed),
            (CheckedIntegerOp::Divide, IntegerSignedness::Signed),
            (CheckedIntegerOp::Remainder, IntegerSignedness::Signed),
            (CheckedIntegerOp::ShiftLeft, IntegerSignedness::Signed),
            (
                CheckedIntegerOp::ShiftLeftWrapping,
                IntegerSignedness::Signed,
            ),
            (CheckedIntegerOp::ShiftRight, IntegerSignedness::Signed),
            (CheckedIntegerOp::Divide, IntegerSignedness::Unsigned),
            (CheckedIntegerOp::Remainder, IntegerSignedness::Unsigned),
            (CheckedIntegerOp::ShiftLeft, IntegerSignedness::Unsigned),
            (
                CheckedIntegerOp::ShiftLeftWrapping,
                IntegerSignedness::Unsigned,
            ),
        ] {
            let (machine, target) = checked_integer_machine_fixture(operation, signedness, 128);
            CanonicalLlvmCodeGenerator::new()
                .emit_object(
                    CodegenRequest {
                        module: &machine,
                        target: target.backend(),
                        options: CodegenOptions::standard(),
                    },
                    &|| false,
                )
                .unwrap_or_else(|error| {
                    panic!("checked i128 {signedness:?} {operation:?} failed: {error:?}")
                });
        }
    }

    #[cfg(feature = "llvm")]
    #[test]
    fn checked_conversion_matrix_reaches_pinned_llvm_coff() {
        let cases = [
            (
                CheckedNumericKind::UnsignedInteger,
                MachineTypeKind::Integer { bits: 64 },
                CheckedNumericKind::SignedInteger,
                MachineTypeKind::Integer { bits: 32 },
            ),
            (
                CheckedNumericKind::SignedInteger,
                MachineTypeKind::Integer { bits: 64 },
                CheckedNumericKind::UnsignedInteger,
                MachineTypeKind::Integer { bits: 32 },
            ),
            (
                CheckedNumericKind::UnsignedInteger,
                MachineTypeKind::Integer { bits: 128 },
                CheckedNumericKind::Float32,
                MachineTypeKind::Float32,
            ),
            (
                CheckedNumericKind::SignedInteger,
                MachineTypeKind::Integer { bits: 64 },
                CheckedNumericKind::Float64,
                MachineTypeKind::Float64,
            ),
            (
                CheckedNumericKind::Float64,
                MachineTypeKind::Float64,
                CheckedNumericKind::Float32,
                MachineTypeKind::Float32,
            ),
            (
                CheckedNumericKind::Float32,
                MachineTypeKind::Float32,
                CheckedNumericKind::Float64,
                MachineTypeKind::Float64,
            ),
            (
                CheckedNumericKind::Float32,
                MachineTypeKind::Float32,
                CheckedNumericKind::SignedInteger,
                MachineTypeKind::Integer { bits: 32 },
            ),
            (
                CheckedNumericKind::Float64,
                MachineTypeKind::Float64,
                CheckedNumericKind::UnsignedInteger,
                MachineTypeKind::Integer { bits: 64 },
            ),
            (
                CheckedNumericKind::Float32,
                MachineTypeKind::Float32,
                CheckedNumericKind::SignedInteger,
                MachineTypeKind::Integer { bits: 128 },
            ),
            (
                CheckedNumericKind::Float64,
                MachineTypeKind::Float64,
                CheckedNumericKind::UnsignedInteger,
                MachineTypeKind::Integer { bits: 128 },
            ),
        ];
        for (source_kind, source_type, destination_kind, destination_type) in cases {
            let (machine, target) = checked_conversion_machine_fixture(
                source_kind,
                source_type,
                destination_kind,
                destination_type,
            );
            CanonicalLlvmCodeGenerator::new()
                .emit_object(
                    CodegenRequest {
                        module: &machine,
                        target: target.backend(),
                        options: CodegenOptions::standard(),
                    },
                    &|| false,
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "checked conversion {source_kind:?} -> {destination_kind:?} failed: {error:?}"
                    )
                });
        }
    }

    #[cfg(feature = "llvm")]
    #[test]
    fn generated_test_runtime_reaches_real_llvm_and_exact_coff_consumer() {
        let (machine, target, frames) = runtime_test_fixture();
        let artifact = CanonicalLlvmCodeGenerator::new()
            .emit_object(
                CodegenRequest {
                    module: &machine,
                    target: target.backend(),
                    options: CodegenOptions::standard(),
                },
                &|| false,
            )
            .expect("test globals and runtime calls emit through pinned LLVM");
        let data = artifact
            .sections()
            .iter()
            .find(|section| section.name == ".rdata.wrela.test")
            .expect("test payload section");
        let start = usize::try_from(data.file_offset).expect("host section offset");
        let bytes = usize::try_from(data.file_bytes).expect("host section extent");
        let expected_payload = frames.concat();
        assert_eq!(&artifact.bytes()[start..start + bytes], expected_payload);
        let code = artifact
            .sections()
            .iter()
            .find(|section| section.name == ".text.wrela.entry")
            .expect("generated test harness code section");
        let code_start = usize::try_from(code.file_offset).expect("host code offset");
        let code_bytes = usize::try_from(code.file_bytes).expect("host code extent");
        let conditional_branches = artifact.bytes()[code_start..code_start + code_bytes]
            .chunks_exact(4)
            .filter(|bytes| {
                let instruction = u32::from_le_bytes(
                    <[u8; 4]>::try_from(*bytes).expect("one AArch64 instruction"),
                );
                instruction & 0x7e00_0000 == 0x3400_0000 || instruction & 0xff00_0010 == 0x5400_0000
            })
            .count();
        assert!(
            conditional_branches >= 3,
            "both TestEmit statuses and ImageEnter must remain native conditional guards"
        );
        let mut offset = 0u64;
        for (index, frame) in frames.iter().enumerate() {
            assert!(artifact.symbols().iter().any(|symbol| {
                symbol.name == format!("__wrela_test_frame_{index}")
                    && symbol.section == ".rdata.wrela.test"
                    && symbol.section_offset == offset
                    && symbol.bytes == frame.len() as u64
            }));
            offset += frame.len() as u64;
        }
        assert!(!artifact.symbols().iter().any(|symbol| {
            matches!(
                symbol.name.as_str(),
                "wrela_rt_v2_test_emit" | "wrela_rt_v2_test_finish"
            )
        }));
    }

    #[cfg(feature = "llvm")]
    #[test]
    fn aligned_writable_storage_reaches_exact_native_coff_contract() {
        let (machine, target) = storage_fixture();
        let emit = || {
            CanonicalLlvmCodeGenerator::new()
                .emit_object(
                    CodegenRequest {
                        module: &machine,
                        target: target.backend(),
                        options: CodegenOptions::standard(),
                    },
                    &|| false,
                )
                .expect("aligned writable storage emits through pinned LLVM")
        };
        let first = emit();
        let second = emit();
        assert_eq!(first, second, "storage COFF emission must be deterministic");

        let data = first
            .sections()
            .iter()
            .find(|section| section.name == ".data")
            .expect("initialized writable section");
        assert_eq!(data.alignment, 8);
        assert_eq!(data.file_bytes, 24);
        assert_eq!(data.virtual_bytes, 24);
        let data_start = usize::try_from(data.file_offset).expect("host data offset");
        let data_bytes = usize::try_from(data.file_bytes).expect("host data extent");
        assert_eq!(
            first
                .bytes()
                .get(data_start..data_start + data_bytes)
                .expect("initialized data payload"),
            &[0; 24]
        );

        let bss = first
            .sections()
            .iter()
            .find(|section| section.name == ".bss")
            .expect("zero-fill writable section");
        assert_eq!(bss.alignment, 8);
        assert_eq!(bss.file_offset, 0);
        assert_eq!(bss.file_bytes, 0);
        assert_eq!(bss.virtual_bytes, 24);

        for (name, section, offset, bytes) in [
            ("__wrela_data_0", ".data", 0, 8),
            ("__wrela_data_1", ".data", 8, 16),
            ("__wrela_bss_0", ".bss", 0, 8),
            ("__wrela_bss_1", ".bss", 8, 16),
        ] {
            assert!(first.symbols().iter().any(|symbol| {
                symbol.name == name
                    && symbol.section == section
                    && symbol.section_offset == offset
                    && symbol.bytes == bytes
            }));
        }

        let (measured_sections, measured_symbols) = super::coff::measure_object(
            first.bytes(),
            &machine,
            CodegenOptions::standard(),
            &|| false,
        )
        .expect("native storage object passes independent COFF inspection");
        assert_eq!(measured_sections.as_slice(), first.sections());
        assert_eq!(measured_symbols.as_slice(), first.symbols());

        let exact_object_bytes = u64::try_from(first.bytes().len()).expect("bounded object");
        let mut exact_options = CodegenOptions::standard();
        exact_options.maximum_object_bytes = exact_object_bytes;
        super::coff::measure_object(first.bytes(), &machine, exact_options, &|| false)
            .expect("exact object-byte bound accepts storage COFF");
        exact_options.maximum_object_bytes -= 1;
        assert_eq!(
            super::coff::measure_object(first.bytes(), &machine, exact_options, &|| false),
            Err(CodegenError::ObjectTooLarge {
                limit: exact_object_bytes - 1,
                actual: exact_object_bytes,
            })
        );

        let reject = |bytes: &[u8]| {
            assert!(matches!(
                super::coff::measure_object(bytes, &machine, CodegenOptions::standard(), &|| false,),
                Err(CodegenError::InvalidObjectMeasurements(_))
            ));
        };

        let mut nonzero_data = first.bytes().to_vec();
        nonzero_data[data_start] = 1;
        reject(&nonzero_data);

        let bss_header = physical_section_header(first.bytes(), b".bss", 0)
            .expect("native zero-fill section header");
        let mut short_bss = first.bytes().to_vec();
        write_u32(&mut short_bss, bss_header + 16, 23);
        reject(&short_bss);

        let mut addressed_bss = first.bytes().to_vec();
        write_u32(&mut addressed_bss, bss_header + 20, 1);
        assert_eq!(
            super::coff::measure_object(
                &addressed_bss,
                &machine,
                CodegenOptions::standard(),
                &|| false,
            ),
            Err(CodegenError::InvalidObjectMeasurements(
                "zero-fill COFF section has a raw file offset"
            ))
        );

        let mut initialized_bss = first.bytes().to_vec();
        let bss_characteristics = read_test_u32(&initialized_bss, bss_header + 36);
        write_u32(
            &mut initialized_bss,
            bss_header + 36,
            (bss_characteristics & 0x00f0_0000) | 0xc000_0040,
        );
        reject(&initialized_bss);

        let mut shifted_symbol = first.bytes().to_vec();
        let bss_symbol = physical_symbol_record(&shifted_symbol, b"__wrela_bss_1")
            .expect("native zero-fill global symbol");
        write_u32(&mut shifted_symbol, bss_symbol + 8, 16);
        reject(&shifted_symbol);
    }

    #[cfg(feature = "llvm")]
    #[test]
    fn scalar_cfg_reaches_real_llvm_and_relocation_aware_coff_consumer() {
        let (machine, target) = unary_cast_scalar_fixture();
        let artifact = CanonicalLlvmCodeGenerator::new()
            .emit_object(
                CodegenRequest {
                    module: &machine,
                    target: target.backend(),
                    options: CodegenOptions::standard(),
                },
                &|| false,
            )
            .expect("checked scalar CFG emits and passes the COFF consumer");
        assert_eq!(&artifact.bytes()[..2], &[0x64, 0xaa]);
        assert!(
            artifact
                .sections()
                .iter()
                .any(|section| { section.name == ".text.wrela.entry" && section.file_bytes != 0 })
        );
        assert!(
            artifact.symbols().iter().any(|symbol| {
                symbol.name == "__wrela_fn_1" && symbol.section == ".text.wrela.1"
            })
        );

        let mut corrupt_unwind = artifact.bytes().to_vec();
        let pdata = physical_section_header(&corrupt_unwind, b".pdata", 0)
            .expect("LLVM emitted ARM64 pdata");
        let relocations = usize::try_from(read_test_u32(&corrupt_unwind, pdata + 24))
            .expect("host relocation offset");
        write_u16(
            &mut corrupt_unwind,
            relocations + 10 + 8,
            3, // IMAGE_REL_ARM64_BRANCH26 is invalid in the xdata slot.
        );
        assert_eq!(
            super::coff::measure_object(
                &corrupt_unwind,
                &machine,
                CodegenOptions::standard(),
                &|| false,
            ),
            Err(CodegenError::InvalidObjectMeasurements(
                "generated ARM64 pdata relocation pair is noncanonical"
            ))
        );
    }

    #[cfg(feature = "llvm")]
    fn physical_section_header(bytes: &[u8], name: &[u8], occurrence: usize) -> Option<usize> {
        let count = usize::from(u16::from_le_bytes(bytes.get(2..4)?.try_into().ok()?));
        let mut observed = 0usize;
        for index in 0..count {
            let base = 20usize.checked_add(index.checked_mul(40)?)?;
            let inline = bytes.get(base..base + 8)?;
            let end = inline.iter().position(|byte| *byte == 0).unwrap_or(8);
            if &inline[..end] == name {
                if observed == occurrence {
                    return Some(base);
                }
                observed += 1;
            }
        }
        None
    }

    #[cfg(feature = "llvm")]
    fn physical_symbol_record(bytes: &[u8], name: &[u8]) -> Option<usize> {
        let table = usize::try_from(read_test_u32(bytes, 8)).ok()?;
        let count = usize::try_from(read_test_u32(bytes, 12)).ok()?;
        let strings = table.checked_add(count.checked_mul(18)?)?;
        let string_bytes = usize::try_from(read_test_u32(bytes, strings)).ok()?;
        let string_table = bytes.get(strings..strings.checked_add(string_bytes)?)?;
        let mut index = 0usize;
        while index < count {
            let record = table.checked_add(index.checked_mul(18)?)?;
            let inline = bytes.get(record..record + 8)?;
            let observed = if inline.get(..4)? == [0; 4] {
                let offset = usize::try_from(read_test_u32(bytes, record + 4)).ok()?;
                let suffix = string_table.get(offset..)?;
                let end = suffix.iter().position(|byte| *byte == 0)?;
                suffix.get(..end)?
            } else {
                let end = inline.iter().position(|byte| *byte == 0).unwrap_or(8);
                inline.get(..end)?
            };
            if observed == name {
                return Some(record);
            }
            let auxiliaries = usize::from(*bytes.get(record + 17)?);
            index = index.checked_add(auxiliaries.checked_add(1)?)?;
        }
        None
    }

    #[cfg(feature = "llvm")]
    fn read_test_u32(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("checked COFF fixture field"),
        )
    }

    fn ordinary_coff_fixture() -> Vec<u8> {
        const HEADER_END: usize = 20 + 2 * 40;
        const TEXT_OFFSET: usize = HEADER_END;
        const METADATA_OFFSET: usize = TEXT_OFFSET + 8;
        const RELOCATION_OFFSET: usize = METADATA_OFFSET + 8;
        const SYMBOL_OFFSET: usize = RELOCATION_OFFSET + 10;
        let long_section = INTERRUPT_ROUTE_SECTION.as_bytes();
        let entry = b"wrela_image_entry";
        let interrupt = INTERRUPT_ROUTE_TABLE_SYMBOL.as_bytes();
        let image_enter = RuntimeIntrinsic::ImageEnter.symbol_name().as_bytes();
        let section_name_offset = 4u32;
        let entry_name_offset =
            section_name_offset + u32::try_from(long_section.len() + 1).unwrap();
        let interrupt_name_offset = entry_name_offset + u32::try_from(entry.len() + 1).unwrap();
        let image_enter_name_offset =
            interrupt_name_offset + u32::try_from(interrupt.len() + 1).unwrap();
        let string_bytes = 4
            + long_section.len()
            + 1
            + entry.len()
            + 1
            + interrupt.len()
            + 1
            + image_enter.len()
            + 1;
        let symbol_table_bytes = 4 * 18;
        let mut bytes = vec![0u8; SYMBOL_OFFSET + symbol_table_bytes + string_bytes];
        write_u16(&mut bytes, 0, 0xaa64);
        write_u16(&mut bytes, 2, 2);
        write_u32(&mut bytes, 8, u32::try_from(SYMBOL_OFFSET).unwrap());
        write_u32(&mut bytes, 12, 4);

        bytes[20..25].copy_from_slice(b".text");
        write_u32(&mut bytes, 20 + 16, 8);
        write_u32(&mut bytes, 20 + 20, u32::try_from(TEXT_OFFSET).unwrap());
        write_u32(
            &mut bytes,
            20 + 24,
            u32::try_from(RELOCATION_OFFSET).unwrap(),
        );
        write_u16(&mut bytes, 20 + 32, 1);
        write_u32(
            &mut bytes,
            20 + 36,
            (5 << 20) | 0x20 | 0x2000_0000 | 0x4000_0000,
        );
        bytes[TEXT_OFFSET..TEXT_OFFSET + 8]
            .copy_from_slice(&[0x00, 0x00, 0x00, 0x94, 0xc0, 0x03, 0x5f, 0xd6]);
        write_u32(&mut bytes, RELOCATION_OFFSET, 0);
        write_u32(&mut bytes, RELOCATION_OFFSET + 4, 2);
        write_u16(&mut bytes, RELOCATION_OFFSET + 8, 3);

        let metadata_header = 20 + 40;
        let encoded = format!("/{section_name_offset}");
        bytes[metadata_header..metadata_header + encoded.len()].copy_from_slice(encoded.as_bytes());
        write_u32(&mut bytes, metadata_header + 16, 8);
        write_u32(
            &mut bytes,
            metadata_header + 20,
            u32::try_from(METADATA_OFFSET).unwrap(),
        );
        write_u32(
            &mut bytes,
            metadata_header + 36,
            (4 << 20) | 0x40 | 0x4000_0000,
        );

        write_u32(&mut bytes, SYMBOL_OFFSET + 4, entry_name_offset);
        write_i16(&mut bytes, SYMBOL_OFFSET + 12, 1);
        write_u16(&mut bytes, SYMBOL_OFFSET + 14, 0x20);
        bytes[SYMBOL_OFFSET + 16] = 2;
        let second_symbol = SYMBOL_OFFSET + 18;
        write_u32(&mut bytes, second_symbol + 4, interrupt_name_offset);
        write_i16(&mut bytes, second_symbol + 12, 2);
        bytes[second_symbol + 16] = 2;
        let runtime_symbol = SYMBOL_OFFSET + 2 * 18;
        write_u32(&mut bytes, runtime_symbol + 4, image_enter_name_offset);
        bytes[runtime_symbol + 16] = 2;
        let feature_symbol = SYMBOL_OFFSET + 3 * 18;
        bytes[feature_symbol..feature_symbol + 8].copy_from_slice(b"@feat.00");
        write_i16(&mut bytes, feature_symbol + 12, -1);
        bytes[feature_symbol + 16] = 3;

        let strings = SYMBOL_OFFSET + symbol_table_bytes;
        write_u32(&mut bytes, strings, u32::try_from(string_bytes).unwrap());
        let mut cursor = strings + 4;
        for name in [long_section, entry.as_slice(), interrupt, image_enter] {
            bytes[cursor..cursor + name.len()].copy_from_slice(name);
            cursor += name.len() + 1;
        }
        bytes
    }

    fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_i16(bytes: &mut [u8], offset: usize, value: i16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
}
