#![forbid(unsafe_code)]

use std::sync::Arc;

use wrela_build_model::{
    BuildConfiguration, BuildIdentity, BuildProfile, LanguageRevision, Sha256Digest,
    TargetIdentity, seal_build_configuration,
};
use wrela_flow_lower::{
    CanonicalFlowLowerer, FlowLowerer, LowerRequest as FlowLowerRequest,
    LoweringLimits as FlowLoweringLimits,
};
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
pub comptime fn boot() -> Image:
    return Image(name="elif-image", target=Target.aarch64_qemu_virt_uefi)

@test
fn elif_runtime():
    first: bool = false
    second: bool = false
    third: bool = true
    joined: u32 = 7
    if first:
        joined = 11
    elif second:
        joined = 13
    elif third:
        joined = 17
    else:
        joined = 19
    consume(value=joined)
    return

fn consume(value: u32) -> u32:
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
fn source_elif_reaches_nested_semantic_and_flow_ssa_joins() {
    let source_graph_digest = Sha256Digest::from_bytes([0x71; 32]);
    let core_package_digest = Sha256Digest::from_bytes([0x72; 32]);
    let target_digest = Sha256Digest::from_bytes([0x73; 32]);
    let mut sources = SourceDatabase::default();
    let application_file = sources
        .add(SourceInput {
            path: "app.wr".to_owned(),
            text: APPLICATION_SOURCE.to_owned(),
            digest: Sha256Digest::from_bytes([0x74; 32]),
        })
        .expect("application source");
    let core_file = sources
        .add(SourceInput {
            path: "core/image.wr".to_owned(),
            text: CORE_IMAGE_SOURCE.to_owned(),
            digest: Sha256Digest::from_bytes([0x75; 32]),
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
        "elif-application",
        Sha256Digest::from_bytes([0x76; 32]),
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
    let packages = Arc::new(graph.finish().expect("package graph"));
    let hir_changes = HirChangeSet {
        previous_source_graph: None,
        changed_files: Vec::new(),
    };
    let hir_output = CanonicalHirLowerer::new()
        .lower(
            HirLowerRequest {
                packages,
                source_graph_digest,
                parsed_files: &parsed_files,
                sources: &sources,
                changes: &hir_changes,
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
    let hir_program = hir_output.lowered().program().as_program();
    let hir_ifs = hir_program
        .statements
        .iter()
        .filter_map(|statement| match &statement.kind {
            StatementKind::If { branches, .. } => Some(branches.len()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(hir_ifs, [1, 1, 1]);
    let image_entry = *hir_program
        .image_candidates
        .first()
        .expect("image entry candidate");
    let hir = Arc::new(hir_output.into_parts().0.into_program());

    let profile = BuildProfile::development();
    let profile_digest = Sha256Digest::from_bytes([0x77; 32]);
    let build = seal_build_configuration(
        BuildConfiguration {
            identity: BuildIdentity {
                compiler: Sha256Digest::from_bytes([0x78; 32]),
                language: LanguageRevision::Design0_1,
                target: TargetIdentity::aarch64_qemu_virt_uefi(),
                target_package: target_digest,
                standard_library: Sha256Digest::from_bytes([0x79; 32]),
                source_graph: source_graph_digest,
                request: Sha256Digest::from_bytes([0x7a; 32]),
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
                    image_name: "elif-image",
                    image_entry,
                    declared_image_tests: &[],
                    source_selection: TestDiscoverySelection::All,
                },
                changes: &changes,
                limits: AnalysisLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("test discovery accepts normalized elif HIR");
    assert!(
        discovery.diagnostics().is_empty(),
        "discovery diagnostics: {:?}",
        discovery.diagnostics()
    );
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
        .expect("runtime elif test reaches semantic facts");
    assert!(
        compilation.diagnostics().is_empty(),
        "compilation diagnostics: {:?}",
        compilation.diagnostics()
    );
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
        .expect("normalized elif lowers to SemanticWir");
    let semantic_debug = format!("{:?}", semantic_output.wir().as_wir());
    assert_eq!(semantic_debug.matches("If {").count(), 3);

    let (semantic_wir, _) = semantic_output.into_parts();
    let flow_output = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic_wir,
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("nested SemanticWir elif chain lowers to FlowWir");
    assert!(
        flow_output.diagnostics().is_empty(),
        "Flow diagnostics: {:?}",
        flow_output.diagnostics()
    );
    let join_blocks = flow_output
        .wir()
        .as_wir()
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .filter(|block| !block.parameters.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(
        join_blocks.len(),
        3,
        "one scalar SSA join per source clause"
    );
    assert!(join_blocks.iter().all(|block| block.parameters.len() == 1));
}
