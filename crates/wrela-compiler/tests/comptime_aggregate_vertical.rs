#![forbid(unsafe_code)]

use std::cell::Cell;
use std::sync::Arc;

use wrela_build_model::{
    BuildConfiguration, BuildIdentity, BuildProfile, LanguageRevision, Sha256Digest,
    TargetIdentity, ValidatedBuildConfiguration, seal_build_configuration,
};
use wrela_hir::DeclarationId;
use wrela_hir_lower::{
    CanonicalHirLowerer, ChangeSet as HirChangeSet, HirLowerer, LowerRequest as HirLowerRequest,
    LoweringLimits as HirLoweringLimits,
};
use wrela_package::{
    DependencyAlias, ModulePath, PackageGraphBuilder, PackageIdentity, PackageName, PackageVersion,
};
use wrela_sema::{
    AnalysisChangeSet, AnalysisFailure, AnalysisLimits, AnalysisMode, AnalysisOutput,
    AnalysisRequest, CanonicalSemanticAnalyzer, SemanticAnalyzer, TestDiscoverySelection,
};
use wrela_source::{SourceDatabase, SourceInput};
use wrela_syntax::{ParseLimits, ParseRequest, SyntaxParser, WrelaSyntaxParser};
use wrela_target::TargetPackage;
use wrela_test_model::{FailurePhase, TestOutcome};

const CORE_IMAGE_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/image.wr");
const IMAGE_SOURCE: &str = r#"module app.image

from core.image import Image, Target

@image
pub fn boot() -> Image:
    return Image(name="comptime-aggregate-image", target=Target.aarch64_qemu_virt_uefi)
"#;

const PASSING_PRODUCTION: &str = r#"module app.values

pub struct Measurement:
    pub magnitude: u32
    pub accepted: bool

pub fn make_measurement(magnitude: u32, accepted: bool) -> Measurement:
    return Measurement(accepted=accepted, magnitude=magnitude)

pub fn forward(value: Measurement) -> Measurement:
    return copy value

pub fn nested(left: u32, right: u32, accepted: bool) -> Measurement:
    combined: u32 = left + right
    candidate = make_measurement(combined, accepted)
    if candidate.accepted:
        return forward(candidate)
    return make_measurement(0, false)

pub fn failing_leaf() -> Measurement:
    value = nested(20, 22, true)
    comptime assert value.magnitude == 0, "production aggregate failure"
    return value

pub fn failing_outer() -> Measurement:
    return failing_leaf()
"#;

const PASSING_TESTS: &str = r#"module app.values_test

from app.values import failing_outer, nested

@test
fn imported_aggregate_branch_and_nested_calls():
    result = nested(20, 22, true)
    comptime assert result.magnitude == 42 and result.accepted, "aggregate branch result"

@test
fn aggregate_name_filter_uses_production_code():
    result = nested(99, 1, false)
    comptime assert result.magnitude == 0 and not result.accepted, "aggregate false branch"

@test
fn nested_aggregate_failure_has_source_stack():
    failing_outer()
"#;

const EXACT_PRODUCTION: &str = r#"module app.values

pub struct Pair:
    pub left: u32
    pub right: u32

pub fn forward(value: Pair) -> Pair:
    return copy value

pub fn make_and_forward(left: u32, right: u32) -> Pair:
    pair: Pair = Pair(left=left, right=right)
    return forward(pair)
"#;

const EXACT_TEST: &str = r#"module app.values_test

from app.values import make_and_forward

@test
fn aggregate_bound():
    result = make_and_forward(20, 22)
    comptime assert result.left + result.right == 42, "aggregate result"
"#;

struct Fixture {
    hir: Arc<wrela_hir::ValidatedProgram>,
    image_entry: DeclarationId,
    target: TargetPackage,
    build: ValidatedBuildConfiguration,
}

#[test]
fn parsed_cross_module_aggregate_functions_pass_and_name_selection_is_real() {
    let fixture = fixture(
        PASSING_PRODUCTION,
        PASSING_TESTS,
        BuildProfile::development(),
    );
    let selected = analyze(
        &fixture,
        TestDiscoverySelection::NameContains("imported_aggregate_branch"),
        AnalysisLimits::standard(),
        &never_cancelled,
    )
    .expect("selected aggregate analysis");
    assert!(
        selected.diagnostics().is_empty(),
        "{:?}",
        selected.diagnostics()
    );
    let selected = selected.successful().expect("selected aggregate image");
    let plan = selected.facts().test_plan.as_ref().expect("selected plan");
    assert_eq!(plan.unit_tests().len(), 1);
    assert_eq!(selected.facts().comptime_test_results.len(), 1);
    assert_eq!(
        selected.facts().comptime_test_results[0].outcome,
        TestOutcome::Passed
    );

    let filtered = analyze(
        &fixture,
        TestDiscoverySelection::NameContains("aggregate_name_filter"),
        AnalysisLimits::standard(),
        &never_cancelled,
    )
    .expect("name-filtered aggregate analysis");
    assert!(filtered.diagnostics().is_empty());
    let filtered = filtered.successful().expect("filtered aggregate image");
    assert_eq!(
        filtered
            .facts()
            .test_plan
            .as_ref()
            .expect("filtered plan")
            .unit_tests()
            .len(),
        1
    );
    assert_eq!(
        filtered.facts().comptime_test_results[0].outcome,
        TestOutcome::Passed
    );

    let repeated = analyze(
        &fixture,
        TestDiscoverySelection::NameContains("imported_aggregate_branch"),
        AnalysisLimits::standard(),
        &never_cancelled,
    )
    .expect("repeated aggregate analysis");
    assert_eq!(
        repeated
            .successful()
            .expect("repeated aggregate image")
            .facts()
            .comptime_test_results,
        selected.facts().comptime_test_results
    );
}

#[test]
fn failed_production_assertion_is_classified_and_retains_nested_source_stack() {
    let fixture = fixture(
        PASSING_PRODUCTION,
        PASSING_TESTS,
        BuildProfile::development(),
    );
    let output = analyze(
        &fixture,
        TestDiscoverySelection::NameContains("nested_aggregate_failure"),
        AnalysisLimits::standard(),
        &never_cancelled,
    )
    .expect("failing aggregate analysis");
    assert!(
        output.diagnostics().is_empty(),
        "{:?}",
        output.diagnostics()
    );
    let image = output
        .successful()
        .expect("sealed failing aggregate analysis");
    let [result] = image.facts().comptime_test_results.as_slice() else {
        panic!("one selected aggregate failure result");
    };
    let assertion = source_span(
        1,
        PASSING_PRODUCTION,
        "comptime assert value.magnitude == 0, \"production aggregate failure\"",
    );
    let inner_call = source_span_last(1, PASSING_PRODUCTION, "failing_leaf()");
    let outer_call = source_span(2, PASSING_TESTS, "failing_outer()");
    assert_eq!(
        result.outcome,
        TestOutcome::Failed {
            phase: FailurePhase::Comptime,
            message: format!(
                "production aggregate failure [source {assertion}; comptime calls <- {inner_call} <- {outer_call}]"
            ),
        }
    );
}

#[test]
fn flat_structure_evaluator_admits_exact_bounds_and_classifies_plus_one() {
    let standard_fixture = fixture(EXACT_PRODUCTION, EXACT_TEST, BuildProfile::development());
    for (steps, passes) in [(163, true), (162, false)] {
        let mut limits = AnalysisLimits::standard();
        limits.evaluator_steps = steps;
        let output = analyze(
            &standard_fixture,
            TestDiscoverySelection::Comptime,
            limits,
            &never_cancelled,
        )
        .expect("step-bounded aggregate analysis");
        assert!(
            output.diagnostics().is_empty(),
            "{:?}",
            output.diagnostics()
        );
        let image = output.successful().expect("step-bounded aggregate image");
        let outcome = &image.facts().comptime_test_results[0].outcome;
        if passes {
            assert_eq!(outcome, &TestOutcome::Passed);
        } else {
            assert_eq!(
                outcome,
                &TestOutcome::Failed {
                    phase: FailurePhase::Comptime,
                    message: format!(
                        "comptime test exceeded comptime evaluator steps limit 162 [source {}]",
                        source_span(2, EXACT_TEST, "42")
                    ),
                }
            );
        }
    }
    for (bytes, passes) in [(608, true), (607, false)] {
        let mut limits = AnalysisLimits::standard();
        limits.evaluator_bytes = bytes;
        let output = analyze(
            &standard_fixture,
            TestDiscoverySelection::Comptime,
            limits,
            &never_cancelled,
        )
        .expect("memory-bounded aggregate analysis");
        assert!(
            output.diagnostics().is_empty(),
            "{:?}",
            output.diagnostics()
        );
        let image = output.successful().expect("memory-bounded aggregate image");
        let outcome = &image.facts().comptime_test_results[0].outcome;
        if passes {
            assert_eq!(outcome, &TestOutcome::Passed);
        } else {
            assert_eq!(
                outcome,
                &TestOutcome::Failed {
                    phase: FailurePhase::Comptime,
                    message: format!(
                        "comptime test exceeded comptime evaluator bytes limit 607 [source {}; comptime calls <- {} <- {}]",
                        source_span_nth(1, EXACT_PRODUCTION, "value", 2),
                        source_span(1, EXACT_PRODUCTION, "forward(pair)"),
                        source_span(2, EXACT_TEST, "make_and_forward(20, 22)"),
                    ),
                }
            );
        }
    }

    let exact_depth = fixture(EXACT_PRODUCTION, EXACT_TEST, profile_with_depth(3));
    let exact = analyze(
        &exact_depth,
        TestDiscoverySelection::Comptime,
        AnalysisLimits::standard(),
        &never_cancelled,
    )
    .expect("exact aggregate depth analysis");
    assert_eq!(
        exact
            .successful()
            .expect("exact aggregate depth image")
            .facts()
            .comptime_test_results[0]
            .outcome,
        TestOutcome::Passed
    );
    let over_depth = fixture(EXACT_PRODUCTION, EXACT_TEST, profile_with_depth(2));
    let over = analyze(
        &over_depth,
        TestDiscoverySelection::Comptime,
        AnalysisLimits::standard(),
        &never_cancelled,
    )
    .expect("over aggregate depth analysis");
    assert!(over.diagnostics().is_empty());
    assert!(matches!(
        &over
            .successful()
            .expect("over aggregate depth image")
            .facts()
            .comptime_test_results[0]
            .outcome,
        TestOutcome::Failed {
            phase: FailurePhase::Comptime,
            message,
        } if message.contains("comptime evaluator depth limit 2")
            && message.contains("comptime calls")
    ));
}

#[test]
fn aggregate_source_evaluation_polls_and_preserves_cancellation() {
    let fixture = fixture(EXACT_PRODUCTION, EXACT_TEST, BuildProfile::development());
    let polls = Cell::new(0u64);
    let complete = analyze(
        &fixture,
        TestDiscoverySelection::Comptime,
        AnalysisLimits::standard(),
        &|| {
            polls.set(polls.get() + 1);
            false
        },
    )
    .expect("polled aggregate analysis");
    assert!(complete.diagnostics().is_empty());
    let complete_polls = polls.get();
    assert!(complete_polls > 163);

    let cancel_at = complete_polls / 2;
    let cancelled_polls = Cell::new(0u64);
    let cancelled = analyze(
        &fixture,
        TestDiscoverySelection::Comptime,
        AnalysisLimits::standard(),
        &|| {
            let next = cancelled_polls.get() + 1;
            cancelled_polls.set(next);
            next == cancel_at
        },
    );
    assert!(matches!(cancelled, Err(AnalysisFailure::Cancelled)));
    assert_eq!(cancelled_polls.get(), cancel_at);
}

#[test]
fn aggregate_move_copy_parameter_and_branch_join_semantics_are_source_checked() {
    const OWNERSHIP_PRODUCTION: &str = r#"module app.values

pub struct Pair:
    pub left: u32
    pub right: u32

pub struct ScalarBox:
    pub value: u32

pub fn make(left: u32, right: u32) -> Pair:
    return Pair(right=right, left=left)

pub fn read_left(value: Pair) -> u32:
    return value.left

pub fn copied(value: Pair) -> Pair:
    return copy value

pub fn boxed() -> ScalarBox:
    return ScalarBox(42)
"#;
    let passing_tests = r#"module app.values_test

from app.values import boxed, copied, make, read_left

@test
fn aggregate_moves_copy_and_reinitialize():
    first = make(20, 22)
    second = first
    first = make(1, 2)
    duplicate = copy second
    comptime assert read_left(first) == 1 and read_left(second) == 20 and copied(duplicate).right == 22 and boxed().value == 42, "ownership result"
"#;
    let passing = analyze(
        &fixture(
            OWNERSHIP_PRODUCTION,
            passing_tests,
            BuildProfile::development(),
        ),
        TestDiscoverySelection::Comptime,
        AnalysisLimits::standard(),
        &never_cancelled,
    )
    .expect("ownership passing analysis");
    assert!(
        passing.diagnostics().is_empty(),
        "{:?}",
        passing.diagnostics()
    );
    assert_eq!(
        passing
            .successful()
            .expect("ownership passing image")
            .facts()
            .comptime_test_results[0]
            .outcome,
        TestOutcome::Passed
    );

    let valid_branch_tests = r#"module app.values_test

from app.values import make

@test
fn every_continuing_branch_reinitializes():
    value = make(20, 22)
    if true:
        moved = value
        value = make(moved.left, 1)
    else:
        moved = value
        value = make(moved.right, 2)
    comptime assert value.left == 20, "branch ownership"
"#;
    let valid_branch = analyze(
        &fixture(
            OWNERSHIP_PRODUCTION,
            valid_branch_tests,
            BuildProfile::development(),
        ),
        TestDiscoverySelection::Comptime,
        AnalysisLimits::standard(),
        &never_cancelled,
    )
    .expect("valid branch ownership analysis");
    assert!(
        valid_branch.diagnostics().is_empty(),
        "{:?}",
        valid_branch.diagnostics()
    );
    assert_eq!(
        valid_branch
            .successful()
            .expect("valid branch image")
            .facts()
            .comptime_test_results[0]
            .outcome,
        TestOutcome::Passed
    );

    let rejected = [
        (
            OWNERSHIP_PRODUCTION,
            r#"module app.values_test

from app.values import make

@test
fn moved_local_cannot_be_read():
    first = make(20, 22)
    second = first
    comptime assert first.left == second.left, "moved local"
"#,
            "semantic-comptime-use-after-move",
        ),
        (
            r#"module app.values

pub struct Pair:
    pub left: u32
    pub right: u32

pub fn make(left: u32, right: u32) -> Pair:
    return Pair(right=right, left=left)

pub fn invalid_forward(value: Pair) -> Pair:
    return value
"#,
            r#"module app.values_test

from app.values import invalid_forward, make

@test
fn read_parameter_cannot_become_owned():
    invalid_forward(make(20, 22))
"#,
            "semantic-comptime-borrowed-value-move",
        ),
        (
            OWNERSHIP_PRODUCTION,
            r#"module app.values_test

from app.values import make

@test
fn one_branch_move_poison_joins():
    value = make(20, 22)
    if true:
        moved = value
        comptime assert moved.left == 20, "moved branch"
    else:
        pass
    comptime assert value.right == 22, "invalid join"
"#,
            "semantic-comptime-use-after-move",
        ),
    ];
    for (index, (production, tests, code)) in rejected.into_iter().enumerate() {
        let output = analyze(
            &fixture(production, tests, BuildProfile::development()),
            TestDiscoverySelection::Comptime,
            AnalysisLimits::standard(),
            &never_cancelled,
        )
        .unwrap_or_else(|error| panic!("ownership rejection {index}: {error:?}"));
        assert!(
            output.successful().is_none(),
            "ownership case {index} sealed"
        );
        let [diagnostic] = output.diagnostics() else {
            panic!("ownership case {index} must have one diagnostic");
        };
        assert_eq!(diagnostic.code.as_deref(), Some(code), "case {index}");
    }
}

#[test]
fn nominal_privacy_malformed_and_unsupported_aggregate_shapes_fail_closed() {
    let cases = [
        (
            r#"module app.values

pub struct First:
    pub value: u32

pub struct Second:
    pub value: u32

pub fn wrong_nominal() -> First:
    return Second(value=1)
"#,
            r#"module app.values_test

from app.values import wrong_nominal

@test
fn nominal_identity_is_preserved():
    wrong_nominal()
"#,
            "semantic-comptime-type-mismatch",
        ),
        (
            r#"module app.values

pub struct Inner:
    pub value: u32

pub struct Outer:
    pub inner: Inner

pub fn nested_shape() -> Outer:
    return Outer(inner=Inner(value=1))
"#,
            r#"module app.values_test

from app.values import nested_shape

@test
fn nested_aggregate_is_future_work():
    nested_shape()
"#,
            "semantic-comptime-aggregate-not-supported",
        ),
        (
            r#"module app.values

pub struct Secret:
    value: u32

pub fn make_secret() -> Secret:
    return Secret(value=7)
"#,
            r#"module app.values_test

from app.values import make_secret

@test
fn private_field_stays_private():
    value = make_secret()
    comptime assert value.value == 7, "private field"
"#,
            "semantic-comptime-field-private",
        ),
        (
            r#"module app.values

pub struct Pair:
    pub left: u32
    pub right: u32

pub fn malformed() -> Pair:
    return Pair(left=1)
"#,
            r#"module app.values_test

from app.values import malformed

@test
fn missing_constructor_field_is_rejected():
    malformed()
"#,
            "semantic-comptime-constructor-argument",
        ),
        (
            r#"module app.values

pub struct Flat:
    pub value: u32

pub fn unsupported_loop() -> Flat:
    loop:
        pass
    return Flat(value=1)
"#,
            r#"module app.values_test

from app.values import unsupported_loop

@test
fn unsupported_operation_is_classified():
    unsupported_loop()
"#,
            "semantic-comptime-operation-not-implemented",
        ),
        (
            r#"module app.values

pub struct Pair:
    pub left: u32
    pub right: u32

pub fn positional_pair() -> Pair:
    return Pair(1, right=2)
"#,
            r#"module app.values_test

from app.values import positional_pair

@test
fn multi_field_positional_is_rejected():
    positional_pair()
"#,
            "semantic-comptime-constructor-argument",
        ),
        (
            r#"module app.values

pub struct Flat:
    pub value: u32

pub fn generic_make[T](value: u32) -> Flat:
    return Flat(value=value)
"#,
            r#"module app.values_test

from app.values import generic_make

@test
fn generic_aggregate_function_is_future_work():
    generic_make(1)
"#,
            "semantic-comptime-signature-not-supported",
        ),
        (
            r#"module app.values

pub struct GenericBox[T]:
    pub value: T

pub fn generic_box() -> GenericBox[u32]:
    return GenericBox[u32](value=1)
"#,
            r#"module app.values_test

from app.values import generic_box

@test
fn generic_aggregate_shape_is_future_work():
    generic_box()
"#,
            "semantic-comptime-signature-not-supported",
        ),
        (
            r#"module app.values

pub struct Pair:
    pub left: u32
    pub right: u32

    pub fn sum(read self) -> u32:
        return self.left + self.right

pub fn make_pair() -> Pair:
    return Pair(right=22, left=20)
"#,
            r#"module app.values_test

from app.values import make_pair

@test
fn aggregate_methods_are_future_work():
    value = make_pair()
    comptime assert value.sum() == 42, "method result"
"#,
            "semantic-comptime-operation-not-implemented",
        ),
    ];

    for (index, (production, test, expected_code)) in cases.into_iter().enumerate() {
        let fixture = fixture(production, test, BuildProfile::development());
        let output = analyze(
            &fixture,
            TestDiscoverySelection::Comptime,
            AnalysisLimits::standard(),
            &never_cancelled,
        )
        .unwrap_or_else(|error| panic!("case {index} analysis failure: {error:?}"));
        assert!(
            output.successful().is_none(),
            "case {index} unexpectedly sealed"
        );
        let [diagnostic] = output.diagnostics() else {
            panic!("case {index} must produce exactly one diagnostic");
        };
        assert_eq!(
            diagnostic.code.as_deref(),
            Some(expected_code),
            "case {index}: {diagnostic:?}"
        );
    }
}

fn fixture(production: &str, tests: &str, profile: BuildProfile) -> Fixture {
    let source_graph_digest = Sha256Digest::from_bytes([0xa1; 32]);
    let target_digest = Sha256Digest::from_bytes([0xa2; 32]);
    let mut sources = SourceDatabase::default();
    let image = add_source(&mut sources, "app/image.wr", IMAGE_SOURCE, 0xa3);
    let production_file = add_source(&mut sources, "app/values.wr", production, 0xa4);
    let test_file = add_source(&mut sources, "app/values_test.wr", tests, 0xa5);
    let core = add_source(&mut sources, "core/image.wr", CORE_IMAGE_SOURCE, 0xa6);
    let parsed_files = [image, production_file, test_file, core]
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
                .expect("aggregate source parses")
                .into_parts();
            assert!(diagnostics.is_empty(), "parse diagnostics: {diagnostics:?}");
            parsed
        })
        .collect::<Vec<_>>();

    let mut graph = PackageGraphBuilder::new(identity(
        "comptime-aggregate-application",
        Sha256Digest::from_bytes([0xa7; 32]),
    ));
    let core_package = graph
        .add_package(identity("wrela-core", Sha256Digest::from_bytes([0xa8; 32])))
        .expect("core package");
    graph
        .add_dependency(
            graph.root(),
            DependencyAlias::new("core").expect("core alias"),
            core_package,
        )
        .expect("core dependency");
    for (path, file) in [
        (["app", "image"], image),
        (["app", "values"], production_file),
        (["app", "values_test"], test_file),
    ] {
        graph
            .add_module(
                graph.root(),
                ModulePath::new(path.map(str::to_owned)).expect("application module path"),
                file,
            )
            .expect("application module");
    }
    graph
        .add_module(
            core_package,
            ModulePath::new(["image".to_owned()]).expect("core module path"),
            core,
        )
        .expect("core module");
    let changes = HirChangeSet {
        previous_source_graph: None,
        changed_files: Vec::new(),
    };
    let lowered = CanonicalHirLowerer::new()
        .lower(
            HirLowerRequest {
                packages: Arc::new(graph.finish().expect("aggregate package graph")),
                source_graph_digest,
                parsed_files: &parsed_files,
                sources: &sources,
                changes: &changes,
                limits: HirLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("aggregate source lowers");
    assert!(
        lowered.diagnostics().is_empty(),
        "HIR diagnostics: {:?}",
        lowered.diagnostics()
    );
    let image_entry = lowered.lowered().program().as_program().image_candidates[0];
    let hir = Arc::new(lowered.into_parts().0.into_program());
    let profile_digest = Sha256Digest::from_bytes([0xa9; 32]);
    let build = seal_build_configuration(
        BuildConfiguration {
            identity: BuildIdentity {
                compiler: Sha256Digest::from_bytes([0xaa; 32]),
                language: LanguageRevision::Design0_1,
                target: TargetIdentity::aarch64_qemu_virt_uefi(),
                target_package: target_digest,
                standard_library: Sha256Digest::from_bytes([0xab; 32]),
                source_graph: source_graph_digest,
                request: Sha256Digest::from_bytes([0xac; 32]),
                profile: profile_digest,
            },
            profile,
        },
        profile_digest,
    )
    .expect("aggregate build configuration");
    Fixture {
        hir,
        image_entry,
        target: TargetPackage::aarch64_qemu_virt_uefi(target_digest),
        build,
    }
}

fn analyze(
    fixture: &Fixture,
    source_selection: TestDiscoverySelection<'_>,
    limits: AnalysisLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<AnalysisOutput, AnalysisFailure> {
    CanonicalSemanticAnalyzer::new().analyze(
        AnalysisRequest {
            hir: Arc::clone(&fixture.hir),
            standard_library_package: wrela_package::PackageId(1),
            target: fixture.target.semantic(),
            build: &fixture.build,
            mode: AnalysisMode::DiscoverTests {
                image_name: "comptime-aggregate-image",
                image_entry: fixture.image_entry,
                declared_image_tests: &[],
                source_selection,
            },
            changes: &AnalysisChangeSet {
                previous_source_graph: None,
                changed_declarations: Vec::new(),
            },
            limits,
        },
        is_cancelled,
    )
}

fn add_source(
    sources: &mut SourceDatabase,
    path: &str,
    text: &str,
    digest: u8,
) -> wrela_source::FileId {
    sources
        .add(SourceInput {
            path: path.to_owned(),
            text: text.to_owned(),
            digest: Sha256Digest::from_bytes([digest; 32]),
        })
        .expect("bounded aggregate source")
}

fn identity(name: &str, digest: Sha256Digest) -> PackageIdentity {
    PackageIdentity {
        name: PackageName::new(name).expect("package name"),
        version: PackageVersion::new("1.0.0").expect("package version"),
        source_digest: digest,
    }
}

fn profile_with_depth(depth: u32) -> BuildProfile {
    let mut profile = BuildProfile::development();
    profile.comptime.call_depth = depth;
    profile
}

fn source_span(file: u32, source: &str, needle: &str) -> String {
    let mut matches = source.match_indices(needle);
    let (start, _) = matches.next().expect("source span needle");
    assert!(matches.next().is_none(), "source span needle is unique");
    format!("{file}:{start}-{}", start + needle.len())
}

fn source_span_last(file: u32, source: &str, needle: &str) -> String {
    let (start, _) = source
        .match_indices(needle)
        .last()
        .expect("source span needle");
    format!("{file}:{start}-{}", start + needle.len())
}

fn source_span_nth(file: u32, source: &str, needle: &str, index: usize) -> String {
    let (start, _) = source
        .match_indices(needle)
        .nth(index)
        .expect("source span occurrence");
    format!("{file}:{start}-{}", start + needle.len())
}

fn never_cancelled() -> bool {
    false
}
