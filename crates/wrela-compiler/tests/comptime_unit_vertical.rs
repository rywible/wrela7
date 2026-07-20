#![forbid(unsafe_code)]

use std::cell::Cell;
use std::sync::Arc;

use wrela_build_model::{
    BuildConfiguration, BuildIdentity, BuildProfile, LanguageRevision, Sha256Digest,
    TargetIdentity, seal_build_configuration,
};
use wrela_hir_lower::{
    CanonicalHirLowerer, ChangeSet as HirChangeSet, HirLowerer, LowerRequest as HirLowerRequest,
    LoweringLimits as HirLoweringLimits,
};
use wrela_package::{
    DependencyAlias, ModulePath, PackageGraphBuilder, PackageIdentity, PackageName, PackageVersion,
};
use wrela_sema::{
    AnalysisChangeSet, AnalysisFailure, AnalysisLimits, AnalysisMode, AnalysisRequest,
    CanonicalSemanticAnalyzer, SemanticAnalyzer, TestDiscoverySelection,
};
use wrela_source::{SourceDatabase, SourceInput};
use wrela_syntax::{ParseLimits, ParseRequest, SyntaxParser, WrelaSyntaxParser};
use wrela_target::TargetPackage;

const CORE_IMAGE_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/image.wr");
const IMAGE_SOURCE: &str = r#"module app.image

from core.image import Image, Target

@image
pub fn boot() -> Image:
    return Image(name="comptime-unit-image", target=Target.aarch64_qemu_virt_uefi)
"#;
const PRODUCTION_SOURCE: &str = r#"module app.math

pub fn countdown(value: u32) -> u32:
    if value == 0:
        return 42
    return countdown(value - 1)
"#;
const TEST_SOURCE: &str = r#"module app.math_test

from app.math import countdown

@test
fn shallow_imported_call():
    result: u32 = countdown(0)
    comptime assert result == 42, "shallow imported call returned the wrong value"

@test
fn deep_imported_call():
    result: u32 = countdown(24)
    comptime assert result == 42, "deep imported call returned the wrong value"
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
fn real_imported_nested_call_evaluation_polls_and_preserves_cancellation() {
    let source_graph_digest = Sha256Digest::from_bytes([0x91; 32]);
    let target_digest = Sha256Digest::from_bytes([0x92; 32]);
    let mut sources = SourceDatabase::default();
    let application_image = sources
        .add(SourceInput {
            path: "app/image.wr".to_owned(),
            text: IMAGE_SOURCE.to_owned(),
            digest: Sha256Digest::from_bytes([0x93; 32]),
        })
        .expect("application image source");
    let production_math = sources
        .add(SourceInput {
            path: "app/math.wr".to_owned(),
            text: PRODUCTION_SOURCE.to_owned(),
            digest: Sha256Digest::from_bytes([0x94; 32]),
        })
        .expect("production math source");
    let unit_tests = sources
        .add(SourceInput {
            path: "app/math_test.wr".to_owned(),
            text: TEST_SOURCE.to_owned(),
            digest: Sha256Digest::from_bytes([0x95; 32]),
        })
        .expect("unit test source");
    let core_image = sources
        .add(SourceInput {
            path: "core/image.wr".to_owned(),
            text: CORE_IMAGE_SOURCE.to_owned(),
            digest: Sha256Digest::from_bytes([0x96; 32]),
        })
        .expect("core image source");
    let parsed_files = [application_image, production_math, unit_tests, core_image]
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
                .expect("real source parses")
                .into_parts();
            assert!(diagnostics.is_empty(), "parse diagnostics: {diagnostics:?}");
            parsed
        })
        .collect::<Vec<_>>();

    let mut graph = PackageGraphBuilder::new(identity(
        "comptime-unit-application",
        Sha256Digest::from_bytes([0x97; 32]),
    ));
    let core = graph
        .add_package(identity("wrela-core", Sha256Digest::from_bytes([0x98; 32])))
        .expect("core package");
    graph
        .add_dependency(
            graph.root(),
            DependencyAlias::new("core").expect("core alias"),
            core,
        )
        .expect("core dependency");
    for (module, file) in [
        (["app", "image"], application_image),
        (["app", "math"], production_math),
        (["app", "math_test"], unit_tests),
    ] {
        graph
            .add_module(
                graph.root(),
                ModulePath::new(module.map(str::to_owned)).expect("application module path"),
                file,
            )
            .expect("application module record");
    }
    graph
        .add_module(
            core,
            ModulePath::new(["image".to_owned()]).expect("core image module"),
            core_image,
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
        .expect("real source lowers to sealed HIR");
    assert!(
        hir_output.diagnostics().is_empty(),
        "HIR diagnostics: {:?}",
        hir_output.diagnostics()
    );
    let image_entry = *hir_output
        .lowered()
        .program()
        .as_program()
        .image_candidates
        .first()
        .expect("image entry candidate");
    let hir = Arc::new(hir_output.into_parts().0.into_program());

    let profile = BuildProfile::development();
    let profile_digest = Sha256Digest::from_bytes([0x99; 32]);
    let build = seal_build_configuration(
        BuildConfiguration {
            identity: BuildIdentity {
                compiler: Sha256Digest::from_bytes([0x9a; 32]),
                language: LanguageRevision::Design0_1,
                target: TargetIdentity::aarch64_qemu_virt_uefi(),
                target_package: target_digest,
                standard_library: Sha256Digest::from_bytes([0x9b; 32]),
                source_graph: source_graph_digest,
                request: Sha256Digest::from_bytes([0x9c; 32]),
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
    let analyze = |filter: &str, is_cancelled: &dyn Fn() -> bool| {
        analyzer.analyze(
            AnalysisRequest {
                hir: Arc::clone(&hir),
                standard_library_package: wrela_package::PackageId(1),
                target: target.semantic(),
                build: &build,
                mode: AnalysisMode::DiscoverTests {
                    image_name: "comptime-unit-image",
                    image_entry,
                    declared_image_tests: &[],
                    source_selection: TestDiscoverySelection::NameContains(filter),
                },
                changes: &changes,
                limits: AnalysisLimits::standard(),
            },
            is_cancelled,
        )
    };

    let shallow_polls = Cell::new(0_u64);
    let shallow = analyze("shallow_imported_call", &|| {
        shallow_polls.set(shallow_polls.get().saturating_add(1));
        false
    })
    .expect("shallow imported call analysis");
    assert!(shallow.diagnostics().is_empty());
    let shallow_plan = shallow
        .successful()
        .and_then(|image| image.facts().test_plan.as_ref())
        .expect("shallow source test plan");
    assert_eq!(shallow_plan.unit_tests().len(), 1);

    let deep_polls = Cell::new(0_u64);
    let deep = analyze("deep_imported_call", &|| {
        deep_polls.set(deep_polls.get().saturating_add(1));
        false
    })
    .expect("deep imported call analysis");
    assert!(deep.diagnostics().is_empty());
    let deep_plan = deep
        .successful()
        .and_then(|image| image.facts().test_plan.as_ref())
        .expect("deep source test plan");
    assert_eq!(deep_plan.unit_tests().len(), 1);
    assert!(
        deep_polls.get() > shallow_polls.get().saturating_add(24),
        "deep imported recursion must add enough evaluator polls to calibrate cancellation"
    );

    let cancel_at = shallow_polls
        .get()
        .checked_add((deep_polls.get() - shallow_polls.get()) / 2)
        .expect("bounded cancellation calibration");
    assert!(cancel_at > shallow_polls.get() && cancel_at < deep_polls.get());
    let cancelled_polls = Cell::new(0_u64);
    let cancelled = analyze("deep_imported_call", &|| {
        let next = cancelled_polls.get().saturating_add(1);
        cancelled_polls.set(next);
        next == cancel_at
    });
    assert!(matches!(cancelled, Err(AnalysisFailure::Cancelled)));
    assert_eq!(cancelled_polls.get(), cancel_at);
}
