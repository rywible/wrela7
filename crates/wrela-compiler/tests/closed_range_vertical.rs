#![forbid(unsafe_code)]

use std::sync::Arc;

use wrela_backend::{
    CodegenError, emit_prepared_object, llvm_backend_available,
    machine_wir::{MachineFunctionOrigin, MachineTerminator},
    prepare_canonical_frame_for_codegen,
};
use wrela_build_model::{
    BuildConfiguration, BuildIdentity, BuildProfile, LanguageRevision, Sha256Digest,
    TargetIdentity, seal_build_configuration,
};
use wrela_flow_lower::{
    CanonicalFlowLowerer, FlowLowerer, LowerRequest as FlowLowerRequest,
    LoweringLimits as FlowLoweringLimits,
};
use wrela_flow_wir_codec::{CanonicalFlowWirCodec, CodecLimits, EncodeRequest, encode_and_verify};
use wrela_hir::StatementKind;
use wrela_hir_lower::{
    CanonicalHirLowerer, ChangeSet as HirChangeSet, HirLowerer, LowerRequest as HirLowerRequest,
    LoweringLimits as HirLoweringLimits,
};
use wrela_package::{
    DependencyAlias, ModulePath, PackageGraphBuilder, PackageIdentity, PackageName, PackageVersion,
};
use wrela_sema::{
    AnalysisChangeSet, AnalysisLimits, AnalysisMode, AnalysisRequest, CanonicalSemanticAnalyzer,
    SemanticAnalyzer, TestDiscoverySelection,
};
use wrela_semantic_lower::{
    CanonicalSemanticLowerer, LowerRequest as SemanticLowerRequest,
    LoweringLimits as SemanticLoweringLimits, SemanticLowerer,
};
use wrela_source::{SourceDatabase, SourceInput};
use wrela_syntax::{ParseLimits, ParseRequest, SyntaxParser, WrelaSyntaxParser};
use wrela_target::TargetPackage;

const CORE_IMAGE_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/image.wr");
const APPLICATION_SOURCE: &str = r#"module app

from core.image import Image, Target

@image
pub fn boot() -> Image:
    return Image(name="closed-range-image", target=Target.aarch64_qemu_virt_uefi)

@test(runtime)
fn closed_range_runtime():
    for index in 2 .. 6:
        consume(index)
    return

fn consume(value: u64) -> u64:
    return value
"#;

fn identity(name: &str, digest: Sha256Digest) -> PackageIdentity {
    PackageIdentity {
        name: PackageName::new(name).expect("package name"),
        version: PackageVersion::new("1.0.0").expect("package version"),
        source_digest: digest,
    }
}

fn never_cancelled() -> bool {
    false
}

#[test]
fn closed_literal_range_reaches_flow_machine_and_deterministic_native_emission() {
    let source_graph_digest = Sha256Digest::from_bytes([0x81; 32]);
    let core_package_digest = Sha256Digest::from_bytes([0x82; 32]);
    let target_digest = Sha256Digest::from_bytes([0x83; 32]);
    let mut sources = SourceDatabase::default();
    let application_file = sources
        .add(SourceInput {
            path: "app.wr".to_owned(),
            text: APPLICATION_SOURCE.to_owned(),
            digest: Sha256Digest::from_bytes([0x84; 32]),
        })
        .expect("application source");
    let core_file = sources
        .add(SourceInput {
            path: "core/image.wr".to_owned(),
            text: CORE_IMAGE_SOURCE.to_owned(),
            digest: Sha256Digest::from_bytes([0x85; 32]),
        })
        .expect("core source");
    let parsed_files = [application_file, core_file]
        .into_iter()
        .map(|file| {
            let (parsed, diagnostics) = WrelaSyntaxParser::new()
                .parse(
                    ParseRequest {
                        sources: &sources,
                        file,
                        limits: ParseLimits::standard(),
                    },
                    &never_cancelled,
                )
                .expect("source parses")
                .into_parts();
            assert!(diagnostics.is_empty(), "parse diagnostics: {diagnostics:?}");
            parsed
        })
        .collect::<Vec<_>>();

    let mut graph = PackageGraphBuilder::new(identity(
        "closed-range-application",
        Sha256Digest::from_bytes([0x86; 32]),
    ));
    let core = graph
        .add_package(identity("wrela-core", core_package_digest))
        .expect("core package");
    graph
        .add_dependency(
            graph.root(),
            DependencyAlias::new("core").expect("core alias"),
            core,
        )
        .expect("core dependency");
    graph
        .add_module(
            graph.root(),
            ModulePath::new(["app".to_owned()]).expect("application module"),
            application_file,
        )
        .expect("application module record");
    graph
        .add_module(
            core,
            ModulePath::new(["image".to_owned()]).expect("core image module"),
            core_file,
        )
        .expect("core module record");
    let hir_output = CanonicalHirLowerer::new()
        .lower(
            HirLowerRequest {
                packages: Arc::new(graph.finish().expect("package graph")),
                source_graph_digest,
                parsed_files: &parsed_files,
                sources: &sources,
                changes: &HirChangeSet {
                    previous_source_graph: None,
                    changed_files: Vec::new(),
                },
                limits: HirLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("source lowers to sealed HIR");
    assert!(
        hir_output.diagnostics().is_empty(),
        "HIR diagnostics: {:?}",
        hir_output.diagnostics()
    );
    let program = hir_output.lowered().program().as_program();
    assert_eq!(
        program
            .statements
            .iter()
            .filter(|statement| matches!(statement.kind, StatementKind::For { .. }))
            .count(),
        1
    );
    let image_entry = *program.image_candidates.first().expect("image entry");
    let hir = Arc::new(hir_output.into_parts().0.into_program());

    let profile = BuildProfile::development();
    let profile_digest = Sha256Digest::from_bytes([0x87; 32]);
    let build = seal_build_configuration(
        BuildConfiguration {
            identity: BuildIdentity {
                compiler: Sha256Digest::from_bytes([0x88; 32]),
                language: LanguageRevision::Design0_1,
                target: TargetIdentity::aarch64_qemu_virt_uefi(),
                target_package: target_digest,
                standard_library: Sha256Digest::from_bytes([0x89; 32]),
                source_graph: source_graph_digest,
                request: Sha256Digest::from_bytes([0x8a; 32]),
                profile: profile_digest,
            },
            profile,
        },
        profile_digest,
    )
    .expect("validated build configuration");
    let target = TargetPackage::aarch64_qemu_virt_uefi(target_digest);
    let changes = AnalysisChangeSet {
        previous_source_graph: None,
        changed_declarations: Vec::new(),
    };
    let analyzer = CanonicalSemanticAnalyzer::new();
    let discovery = analyzer
        .analyze(
            AnalysisRequest {
                hir: Arc::clone(&hir),
                standard_library_package: wrela_package::PackageId(1),
                target: target.semantic(),
                build: &build,
                mode: AnalysisMode::DiscoverTests {
                    image_name: "closed-range-image",
                    image_entry,
                    declared_image_tests: &[],
                    source_selection: TestDiscoverySelection::All,
                },
                changes: &changes,
                limits: AnalysisLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("test discovery accepts closed range");
    assert!(discovery.diagnostics().is_empty());
    let plan = discovery
        .successful()
        .and_then(|image| image.facts().test_plan.as_ref())
        .expect("source test plan")
        .clone();
    let group = plan.image_groups()[0].id;
    let compilation = analyzer
        .analyze(
            AnalysisRequest {
                hir,
                standard_library_package: wrela_package::PackageId(1),
                target: target.semantic(),
                build: &build,
                mode: AnalysisMode::CompileTestGroup {
                    plan: &plan,
                    group,
                    declared_entry: None,
                },
                changes: &changes,
                limits: AnalysisLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("closed range reaches semantic facts");
    assert!(compilation.diagnostics().is_empty());
    let analyzed = compilation
        .into_parts()
        .0
        .expect("sealed runtime test image");
    let semantic_output = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed,
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("closed range lowers to SemanticWir");
    let semantic_debug = format!("{:?}", semantic_output.wir().as_wir());
    assert_eq!(semantic_debug.matches("Loop {").count(), 1);
    assert!(semantic_debug.contains("uninterrupted_bound: Some(4)"));

    let (semantic_wir, _) = semantic_output.into_parts();
    let first_flow = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic_wir.clone(),
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("first cold range lowering");
    let flow_output = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic_wir,
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("closed range lowers to FlowWir");
    assert_eq!(first_flow.wir().as_wir(), flow_output.wir().as_wir());
    assert!(flow_output.diagnostics().is_empty());
    let (flow_wir, _, _) = flow_output.into_parts();
    let encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: &flow_wir,
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("closed range FlowWir canonical frame");
    let prepared =
        prepare_canonical_frame_for_codegen(encoded.bytes(), &target, &build, &never_cancelled)
            .expect("closed range MachineWir preparation");
    let source_blocks = prepared
        .machine()
        .wir()
        .as_wir()
        .functions
        .iter()
        .filter(|function| {
            matches!(
                function.origin,
                MachineFunctionOrigin::SourceSemantic { .. }
            )
        })
        .flat_map(|function| &function.blocks)
        .collect::<Vec<_>>();
    assert_eq!(
        source_blocks
            .iter()
            .filter(|block| matches!(block.terminator, MachineTerminator::Branch { .. }))
            .count(),
        1,
        "the generated range comparison remains an executable machine branch"
    );
    assert_eq!(
        source_blocks
            .iter()
            .filter(|block| !block.parameters.is_empty())
            .count(),
        2,
        "range header and exit carry the exact induction value"
    );

    match emit_prepared_object(&prepared, &target, &never_cancelled) {
        Err(CodegenError::BackendNotBuilt) if !llvm_backend_available() => {}
        Err(error) => panic!("closed range native object emission failed: {error}"),
        Ok(_) if !llvm_backend_available() => {
            panic!("native object emitted while LLVM reports unavailable")
        }
        Ok(first) => {
            let second = emit_prepared_object(&prepared, &target, &never_cancelled)
                .expect("repeat closed range native object emission");
            assert_eq!(
                first.bytes(),
                second.bytes(),
                "identical range MachineWir must emit byte-identical ARM64 COFF"
            );
        }
    }
}
