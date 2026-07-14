//! Desugaring and name resolution from recoverable syntax into normalized HIR.

#![forbid(unsafe_code)]

use wrela_diagnostics::WithDiagnostics;
use wrela_hir::Package;
use wrela_source::SourceDatabase;
use wrela_syntax::ParsedPackage;

/// Lower parsed syntax into HIR without invoking semantic analysis.
///
/// Declaration lowering lands behind this contract. The scaffold establishes
/// deterministic package identity so downstream layers can be exercised now.
pub fn lower(parsed: &ParsedPackage, sources: &SourceDatabase) -> WithDiagnostics<Package> {
    let image_name = sources
        .get(parsed.root)
        .and_then(|file| file.path().file_stem())
        .and_then(|stem| stem.to_str())
        .unwrap_or("image")
        .to_owned();

    WithDiagnostics::clean(Package {
        root: parsed.root,
        image_name,
        declarations: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use wrela_source::SourceDatabase;
    use wrela_syntax::parse;

    use super::lower;

    #[test]
    fn hir_lowering_is_runnable_from_a_syntax_fixture() {
        let mut sources = SourceDatabase::default();
        let root = sources.add("appliance.wr", "");
        let parsed = parse(&sources, root).expect("parse root");

        let hir = lower(&parsed.value, &sources);
        assert_eq!(hir.value.image_name, "appliance");
    }
}
