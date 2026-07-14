use wrela_hir_lower::lower as lower_hir;
use wrela_sema::analyze;
use wrela_source::SourceDatabase;
use wrela_syntax::parse;
use wrela_target::Target;
use wrela_wir_codec::{decode, encode};
use wrela_wir_lower::lower as lower_wir;
use wrela_wir_passes::verify;

#[test]
fn frontend_layer_contracts_compose_without_the_backend() {
    let mut sources = SourceDatabase::default();
    let root = sources.add("contract.wr", "@image fn image() {}\n");
    let target = Target::x86_64_uefi();

    let syntax = parse(&sources, root).expect("parse fixture");
    let hir = lower_hir(&syntax.value, &sources);
    let analyzed = analyze(hir.value, &target);
    let wir = lower_wir(&analyzed.value);
    let verified = verify(wir).expect("verify lowered fixture");
    let encoded = encode(verified.as_module()).expect("encode fixture");
    let decoded = decode(&encoded).expect("decode fixture");

    assert_eq!(decoded.name, "contract");
    assert_eq!(decoded.target, target.identity);
}
