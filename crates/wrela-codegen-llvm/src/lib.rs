//! Mechanical LLVM translation from validated MachineWir to AArch64 COFF.
//! LLVM/Inkwell values and contexts never cross this crate boundary.

#![forbid(unsafe_code)]

use std::fmt;

use wrela_build_model::BuildIdentity;
use wrela_machine_wir::{SymbolDefinition, ValidatedMachineWir};
use wrela_target::{ObjectFormat, TargetBackendContract};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodegenOptions {
    pub maximum_object_bytes: u64,
    pub maximum_sections: u32,
    pub maximum_symbols: u32,
    pub maximum_measurement_bytes: u64,
}

impl CodegenOptions {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            maximum_object_bytes: 4 * 1024 * 1024 * 1024,
            maximum_sections: 65_536,
            maximum_symbols: 16_000_000,
            maximum_measurement_bytes: 4 * 1024 * 1024 * 1024,
        }
    }

    pub fn validate(self) -> Result<(), CodegenError> {
        if self.maximum_object_bytes == 0
            || self.maximum_sections == 0
            || self.maximum_symbols == 0
            || self.maximum_measurement_bytes == 0
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodegenError {
    BackendNotBuilt,
    Cancelled,
    InvalidOptions,
    TargetMismatch,
    TargetPackageMismatch,
    UnsupportedMachineOperation {
        function: u32,
        instruction: u32,
    },
    InvalidBackendFact {
        function: u32,
        instruction: u32,
        fact: &'static str,
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
            Self::UnsupportedMachineOperation {
                function,
                instruction,
            } => write!(
                formatter,
                "unsupported MachineWir operation at function {function}, instruction {instruction}"
            ),
            Self::InvalidBackendFact {
                function,
                instruction,
                fact,
            } => write!(
                formatter,
                "unproved backend fact {fact} at function {function}, instruction {instruction}"
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

/// Seal bytes and measurements produced by the private LLVM implementation.
/// Test doubles use the same constructor, so orchestration cannot receive a
/// structurally impossible success artifact.
pub fn seal_object(
    request: &CodegenRequest<'_>,
    bytes: Vec<u8>,
    sections: Vec<EmittedSection>,
    symbols: Vec<EmittedSymbol>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ObjectArtifact, CodegenError> {
    if is_cancelled() {
        return Err(CodegenError::Cancelled);
    }
    let machine = request.module.as_wir();
    request.options.validate()?;
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
    let measurement_bytes = sections
        .iter()
        .try_fold(0u64, |total, section| {
            total.checked_add(u64::try_from(section.name.len()).ok()?)
        })
        .and_then(|initial| {
            symbols.iter().try_fold(initial, |total, symbol| {
                total
                    .checked_add(u64::try_from(symbol.name.len()).ok()?)?
                    .checked_add(u64::try_from(symbol.section.len()).ok()?)
            })
        });
    if sections.len() > request.options.maximum_sections as usize
        || symbols.len() > request.options.maximum_symbols as usize
        || measurement_bytes.is_none_or(|bytes| bytes > request.options.maximum_measurement_bytes)
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
    if machine.build.target != *request.target.identity()
        || machine.build.target_package != request.target.content_digest()
        || machine.target.llvm_triple != request.target.llvm_triple()
    {
        return Err(CodegenError::TargetPackageMismatch);
    }
    let sections_valid = !sections.is_empty()
        && sections.windows(2).all(|pair| pair[0].name < pair[1].name)
        && sections.iter().all(|section| {
            !section.name.trim().is_empty()
                && section.alignment.is_power_of_two()
                && section.file_bytes <= section.virtual_bytes
                && section
                    .file_offset
                    .checked_add(section.file_bytes)
                    .is_some_and(|end| end <= actual)
        })
        && {
            let mut file_ranges: Vec<_> = sections
                .iter()
                .map(|section| {
                    (
                        section.file_offset,
                        section.file_offset + section.file_bytes,
                    )
                })
                .collect();
            file_ranges.sort_unstable();
            file_ranges.windows(2).all(|pair| pair[0].1 <= pair[1].0)
        };
    if !sections_valid {
        return Err(CodegenError::InvalidObjectMeasurements(
            "sections are empty, duplicate, overlapping, or outside object bytes",
        ));
    }
    let section_extents: std::collections::BTreeMap<_, _> = sections
        .iter()
        .map(|section| (section.name.as_str(), section.virtual_bytes))
        .collect();
    let symbols_valid = symbols.windows(2).all(|pair| pair[0].name < pair[1].name)
        && symbols.iter().all(|symbol| {
            !symbol.name.trim().is_empty()
                && section_extents
                    .get(symbol.section.as_str())
                    .is_some_and(|section_bytes| {
                        symbol
                            .section_offset
                            .checked_add(symbol.bytes)
                            .is_some_and(|end| end <= *section_bytes)
                    })
        });
    if !symbols_valid {
        return Err(CodegenError::InvalidObjectMeasurements(
            "symbols are noncanonical or outside their named section",
        ));
    }
    let expected_sections: std::collections::BTreeSet<_> = machine
        .sections
        .iter()
        .map(|section| section.name.as_str())
        .collect();
    let expected_section_records: std::collections::BTreeMap<_, _> = machine
        .sections
        .iter()
        .map(|section| (section.name.as_str(), section))
        .collect();
    let actual_sections: std::collections::BTreeSet<_> = sections
        .iter()
        .map(|section| section.name.as_str())
        .collect();
    let expected_symbols: std::collections::BTreeSet<_> = machine
        .symbols
        .iter()
        .filter(|symbol| !matches!(symbol.definition, SymbolDefinition::ExternalRuntime(_)))
        .map(|symbol| symbol.name.as_str())
        .collect();
    let expected_symbol_records: std::collections::BTreeMap<_, _> = machine
        .symbols
        .iter()
        .filter(|symbol| !matches!(symbol.definition, SymbolDefinition::ExternalRuntime(_)))
        .map(|symbol| (symbol.name.as_str(), symbol))
        .collect();
    let actual_symbols: std::collections::BTreeSet<_> =
        symbols.iter().map(|symbol| symbol.name.as_str()).collect();
    if actual_sections != expected_sections || actual_symbols != expected_symbols {
        return Err(CodegenError::InvalidObjectMeasurements(
            "emitted section or defined-symbol set differs from MachineWir",
        ));
    }
    if sections.iter().any(|emitted| {
        expected_section_records
            .get(emitted.name.as_str())
            .is_none_or(|expected| {
                emitted.alignment != expected.alignment
                    || emitted.virtual_bytes > expected.reserved_bytes
            })
    }) || symbols.iter().any(|emitted| {
        let Some(expected) = expected_symbol_records.get(emitted.name.as_str()) else {
            return true;
        };
        let expected_section = |section: wrela_machine_wir::SectionId| {
            machine
                .sections
                .get(section.0 as usize)
                .map(|section| section.name.as_str())
        };
        match expected.definition {
            SymbolDefinition::Function(function) => machine
                .functions
                .get(function.0 as usize)
                .and_then(|function| expected_section(function.section))
                .is_none_or(|section| emitted.section != section || emitted.bytes == 0),
            SymbolDefinition::Global(global) => machine
                .globals
                .get(global.0 as usize)
                .and_then(|global| {
                    machine
                        .types
                        .get(global.ty.0 as usize)
                        .zip(expected_section(global.section))
                        .map(|(ty, section)| (global.offset, ty.size, section))
                })
                .is_none_or(|(offset, bytes, section)| {
                    emitted.section != section
                        || emitted.section_offset != offset
                        || emitted.bytes != bytes
                }),
            SymbolDefinition::SectionOffset {
                section,
                offset,
                bytes,
            } => expected_section(section).is_none_or(|section| {
                emitted.section != section
                    || emitted.section_offset != offset
                    || emitted.bytes != bytes
            }),
            SymbolDefinition::ExternalRuntime(_) => true,
        }
    }) {
        return Err(CodegenError::InvalidObjectMeasurements(
            "section layout or symbol placement differs from MachineWir",
        ));
    }
    let mut symbol_ranges: Vec<_> = symbols
        .iter()
        .map(|symbol| {
            (
                symbol.section.as_str(),
                symbol.section_offset,
                symbol.section_offset + symbol.bytes,
            )
        })
        .collect();
    symbol_ranges.sort_unstable();
    if symbol_ranges
        .windows(2)
        .any(|pair| pair[0].0 == pair[1].0 && pair[0].2 > pair[1].1)
    {
        return Err(CodegenError::InvalidObjectMeasurements(
            "emitted symbol ranges overlap",
        ));
    }
    if is_cancelled() {
        return Err(CodegenError::Cancelled);
    }
    Ok(ObjectArtifact {
        bytes,
        build: machine.build.clone(),
        target_triple: request.target.llvm_triple().to_owned(),
        format: request.target.object_format(),
        sections,
        symbols,
    })
}

#[cfg(test)]
mod contract_tests {
    use super::{CodegenError, CodegenOptions};

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
}
