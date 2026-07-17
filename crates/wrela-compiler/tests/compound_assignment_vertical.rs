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
use wrela_hir::{AssignmentOperator, Definition, StatementKind};
use wrela_hir_lower::{
    CanonicalHirLowerer, ChangeSet as HirChangeSet, HirLowerer, LowerRequest as HirLowerRequest,
    LoweringLimits as HirLoweringLimits,
};
use wrela_package::{
    DependencyAlias, ModulePath, PackageGraphBuilder, PackageIdentity, PackageName, PackageVersion,
};
use wrela_sema::{
    AnalysisChangeSet, AnalysisLimits, AnalysisMode, AnalysisRequest, CanonicalSemanticAnalyzer,
    SemanticAnalyzer, SemanticValueOrigin, TestDiscoverySelection,
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
    return Image(name="compound-image", target=Target.aarch64_qemu_virt_uefi)

@test
fn compound_runtime():
    value: u32 = 40
    value += 5
    value -= 2
    value *= 3
    value /= 2
    value %= 17
    value &= 15
    value |= 16
    value ^= 3
    value <<= 1
    value >>= 2
    branch: bool = true
    if branch:
        value += 1
    else:
        value -= 1
    consume(value=value)
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
fn source_compound_assignments_reach_checked_semantic_and_flow_operations() {
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
        "compound-application",
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
    let packages = Arc::new(graph.finish().expect("package graph"));
    let changes = HirChangeSet {
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
                changes: &changes,
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
    let assignments = program
        .statements
        .iter()
        .filter_map(|statement| match &statement.kind {
            StatementKind::Assign {
                targets,
                operator,
                value,
            } => Some((statement.id, targets.clone(), *operator, *value)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(assignments.len(), 12);
    assert_eq!(
        assignments
            .iter()
            .take(10)
            .map(|(_, _, operator, _)| *operator)
            .collect::<Vec<_>>(),
        [
            AssignmentOperator::Add,
            AssignmentOperator::Subtract,
            AssignmentOperator::Multiply,
            AssignmentOperator::Divide,
            AssignmentOperator::Remainder,
            AssignmentOperator::BitAnd,
            AssignmentOperator::BitOr,
            AssignmentOperator::BitXor,
            AssignmentOperator::ShiftLeft,
            AssignmentOperator::ShiftRight,
        ]
    );
    assert!(assignments.iter().all(|(_, targets, operator, _)| {
        matches!(
            targets.as_slice(),
            [target]
                if matches!(target.root, Definition::Local(_))
                    && target.projections.is_empty()
                    && *operator != AssignmentOperator::Assign
        )
    }));
    let image_entry = *program
        .image_candidates
        .first()
        .expect("image entry candidate");
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
                    image_name: "compound-image",
                    image_entry,
                    declared_image_tests: &[],
                    source_selection: TestDiscoverySelection::All,
                },
                changes: &changes,
                limits: AnalysisLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("compound test discovery");
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
    let compilation = analyzer
        .analyze(
            AnalysisRequest {
                hir,
                standard_library_package: wrela_package::PackageId(1),
                target: target.semantic(),
                build: &build,
                mode: AnalysisMode::CompileTestGroup {
                    plan: &plan,
                    group: plan.image_groups()[0].id,
                    declared_entry: None,
                },
                changes: &changes,
                limits: AnalysisLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("compound test semantic analysis");
    assert!(
        compilation.diagnostics().is_empty(),
        "compilation diagnostics: {:?}",
        compilation.diagnostics()
    );
    let analyzed = compilation
        .into_parts()
        .0
        .expect("sealed compound test image");
    for (statement, _, _, rhs) in &assignments {
        let fact = analyzed
            .facts()
            .statements
            .iter()
            .find(|fact| fact.statement == *statement)
            .expect("compound statement fact");
        let [definition] = fact.definitions.as_slice() else {
            panic!("one fresh compound definition");
        };
        let function = fact.function;
        let rhs = analyzed
            .facts()
            .expressions
            .iter()
            .find(|fact| fact.function == function && fact.expression == *rhs)
            .expect("compound RHS fact");
        assert_ne!(rhs.result, Some(definition.value));
        assert!(matches!(
            analyzed.facts().values[definition.value.0 as usize].origin,
            SemanticValueOrigin::Local(_)
        ));
        assert!(!analyzed.facts().expressions.iter().any(|expression| {
            expression.function == fact.function && expression.result == Some(definition.value)
        }));
    }

    let semantic_output = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed,
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("compound assignments lower to SemanticWir");
    let semantic_debug = format!("{:?}", semantic_output.wir().as_wir());
    assert_eq!(semantic_debug.matches("operation: Binary {").count(), 12);
    assert_eq!(semantic_debug.matches("arithmetic: Checked").count(), 12);

    let (semantic_wir, _) = semantic_output.into_parts();
    let flow_output = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic_wir,
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("compound SemanticWir lowers to FlowWir");
    assert!(
        flow_output.diagnostics().is_empty(),
        "Flow diagnostics: {:?}",
        flow_output.diagnostics()
    );
    let flow_debug = format!("{:?}", flow_output.wir().as_wir());
    for operator in [
        "AddChecked",
        "SubChecked",
        "MulChecked",
        "DivChecked",
        "RemChecked",
        "BitAnd",
        "BitOr",
        "BitXor",
        "ShiftLeftChecked",
        "ShiftRightChecked",
    ] {
        assert!(
            flow_debug.contains(operator),
            "missing Flow operation {operator}"
        );
    }
}
