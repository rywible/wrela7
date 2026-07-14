//! Backend-independent whole-image IR data model.
//!
//! WIR is deliberately independent of LLVM. Verification and transformation
//! live in `wrela-wir-passes` so this contract can be constructed directly.

#![forbid(unsafe_code)]

/// On-disk WIR format emitted by this compiler revision.
pub const FORMAT_VERSION: u32 = 1;

/// A fully specialized whole-image module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Module {
    /// Human-readable image name.
    pub name: String,
    /// Exact target under which semantic proofs were established.
    pub target: wrela_target::TargetIdentity,
    /// Reachable, monomorphized functions.
    pub functions: Vec<Function>,
}

/// A concrete function in the sealed image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Function {
    /// Stable compiler-assigned identifier.
    pub id: FunctionId,
    /// Source-facing diagnostic name.
    pub name: String,
}

/// Stable identifier within one WIR module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FunctionId(pub u32);
