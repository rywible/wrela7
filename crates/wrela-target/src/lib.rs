//! Host-independent target and final-image policy.

#![forbid(unsafe_code)]

use std::fmt;

/// Stable identity recorded in WIR and build artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TargetIdentity(pub String);

/// CPU architecture selected by a target package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    /// AMD64 / Intel 64.
    X86_64,
    /// 64-bit Arm.
    Aarch64,
}

/// Object format accepted by the target linker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectFormat {
    /// Microsoft Common Object File Format.
    Coff,
}

/// Validated target contract consumed by analysis, codegen, and linking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Stable target-package identity.
    pub identity: TargetIdentity,
    /// LLVM target triple used only by the codegen layer.
    pub llvm_triple: String,
    /// CPU architecture.
    pub architecture: Architecture,
    /// Backend object format.
    pub object_format: ObjectFormat,
    /// PE/COFF entry symbol.
    pub entry_symbol: String,
    /// PE subsystem name understood by the EFI linker layer.
    pub subsystem: String,
}

impl Target {
    /// Reference revision 0.1 target used by contract tests.
    #[must_use]
    pub fn x86_64_uefi() -> Self {
        Self {
            identity: TargetIdentity("x86_64-uefi".to_owned()),
            llvm_triple: "x86_64-unknown-windows".to_owned(),
            architecture: Architecture::X86_64,
            object_format: ObjectFormat::Coff,
            entry_symbol: "wrela_image_entry".to_owned(),
            subsystem: "efi_application".to_owned(),
        }
    }

    /// Reject incomplete packages before any semantic or backend phase uses them.
    pub fn validate(&self) -> Result<(), TargetError> {
        if self.identity.0.trim().is_empty() {
            return Err(TargetError::MissingIdentity);
        }
        if self.entry_symbol.trim().is_empty() {
            return Err(TargetError::MissingEntrySymbol);
        }
        Ok(())
    }
}

/// Invalid target package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetError {
    /// The stable package name is empty.
    MissingIdentity,
    /// The final image has no entry point.
    MissingEntrySymbol,
}

impl fmt::Display for TargetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingIdentity => formatter.write_str("target package has no identity"),
            Self::MissingEntrySymbol => formatter.write_str("target package has no entry symbol"),
        }
    }
}

impl std::error::Error for TargetError {}
