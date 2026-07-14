//! Mutually dependent whole-image semantic analyses over HIR.
//!
//! Types, effects, access, regions, actors, async state, capacity, and hardware
//! rules remain modules in one crate until their fixed-point boundaries are
//! understood well enough to justify further crates.

#![forbid(unsafe_code)]

use wrela_diagnostics::WithDiagnostics;
use wrela_hir::Package;
use wrela_target::{Target, TargetIdentity};

/// Semantically closed image ready for whole-image lowering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzedImage {
    /// Normalized program retained for source-oriented diagnostics.
    pub hir: Package,
    /// Exact target under which all proofs were established.
    pub target: TargetIdentity,
}

/// Establish language and target invariants without depending on WIR or LLVM.
pub fn analyze(hir: Package, target: &Target) -> WithDiagnostics<AnalyzedImage> {
    WithDiagnostics::clean(AnalyzedImage {
        hir,
        target: target.identity.clone(),
    })
}

#[cfg(test)]
mod tests {
    use wrela_hir::Package;
    use wrela_source::FileId;
    use wrela_target::Target;

    use super::analyze;

    #[test]
    fn semantic_layer_accepts_hir_fixtures_directly() {
        let hir = Package {
            root: FileId(0),
            image_name: "fixture".to_owned(),
            declarations: Vec::new(),
        };

        let analyzed = analyze(hir, &Target::x86_64_uefi());
        assert_eq!(analyzed.value.target.0, "x86_64-uefi");
    }
}
