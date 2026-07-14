//! LLVM object generation. Inkwell is private to this crate.
//!
//! The default build exposes and tests the layer contract without requiring an
//! LLVM installation. Distribution builds enable `llvm` against the prefix
//! constructed from `toolchain/llvm.lock.toml`.

#![forbid(unsafe_code)]

use std::fmt;

use wrela_target::Target;
use wrela_wir_passes::VerifiedModule;

/// LLVM backend profile selected by the driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodegenProfile {
    /// Faster compiler execution and richer generated diagnostics.
    Development,
    /// Whole-image runtime performance and footprint optimization.
    Release,
}

/// Complete input contract for object generation.
#[derive(Debug)]
pub struct CodegenRequest<'a> {
    /// WIR whose semantic invariants have been checked.
    pub module: &'a VerifiedModule,
    /// Validated target package matching the WIR target identity.
    pub target: &'a Target,
    /// Optimization profile.
    pub profile: CodegenProfile,
}

/// Ordinary object bytes ready for the EFI linker layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectArtifact {
    /// COFF object contents.
    pub bytes: Vec<u8>,
    /// LLVM target triple used during emission.
    pub target_triple: String,
}

/// LLVM translation or emission failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodegenError {
    /// This developer build omitted the pinned LLVM feature.
    BackendNotBuilt,
    /// WIR and selected target package do not match.
    TargetMismatch,
}

impl fmt::Display for CodegenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BackendNotBuilt => formatter.write_str(
                "LLVM codegen is not present in this developer build; build the bundled backend",
            ),
            Self::TargetMismatch => formatter.write_str("WIR target does not match codegen target"),
        }
    }
}

impl std::error::Error for CodegenError {}

/// Emit one COFF object without exposing any Inkwell or LLVM type to callers.
pub fn emit_object(request: &CodegenRequest<'_>) -> Result<ObjectArtifact, CodegenError> {
    if request.module.as_module().target != request.target.identity {
        return Err(CodegenError::TargetMismatch);
    }

    // The implementation behind the `llvm` feature lands with xtask's pinned
    // LLVM build. Keeping this result explicit prevents a developer scaffold
    // from being mistaken for a functioning backend.
    Err(CodegenError::BackendNotBuilt)
}
