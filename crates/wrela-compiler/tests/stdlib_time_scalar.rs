#![forbid(unsafe_code)]

use std::{cell::Cell, sync::Arc};

use wrela_backend::{
    CodegenError, emit_prepared_object, llvm_backend_available,
    machine_wir::{
        CheckedIntegerOp, ConversionOp, IntegerPredicate, MachineOperation, MachineTerminator,
        MachineTypeKind, SymbolDefinition,
    },
    prepare_canonical_frame_for_codegen,
};
use wrela_build_model::{
    BuildConfiguration, BuildIdentity, Sha256Digest, TargetIdentity, seal_build_configuration,
};
use wrela_flow_lower::{
    CanonicalFlowLowerer, FlowBinaryOp, FlowLowerer, FlowOperation,
    LowerRequest as FlowLowerRequest, LoweringLimits as FlowLoweringLimits,
    Terminator as FlowTerminator,
};
use wrela_flow_wir_codec::{CanonicalFlowWirCodec, CodecLimits, EncodeRequest, encode_and_verify};
use wrela_hir::DeclarationId;
use wrela_hir_lower::{
    CanonicalHirLowerer, ChangeSet as HirChangeSet, HirLowerer, LowerRequest as HirLowerRequest,
    LoweringLimits as HirLoweringLimits,
};
use wrela_package::{
    DependencyAlias, LOCKFILE_SCHEMA_VERSION, LockedDependency, LockedPackage, Lockfile,
    ModulePath, PackageGraphBuilder, PackageIdentity, PackageLocator,
};
use wrela_package_loader::{
    CanonicalPackageCodec, CanonicalWorkspaceLoader, ContentHasher, LoadLimits, LoadRequest,
    LoadedWorkspace, LockfileCodecLimits, ManifestCodecLimits, PackageBundle, PackageCodec,
    PackageContentKind, PackageContentRecord, PackageSourceProvider, ProviderError, SoftwareSha256,
    WorkspaceLoader, package_content_digest,
};
use wrela_sema::{
    AnalysisChangeSet, AnalysisFailure, AnalysisLimits, AnalysisMode, AnalysisRequest,
    CanonicalSemanticAnalyzer, SemanticAnalyzer, TestDiscoverySelection,
};
use wrela_semantic_lower::{
    CanonicalSemanticLowerer, LowerRequest as SemanticLowerRequest, LoweredSemanticStatement,
    LoweringLimits as SemanticLoweringLimits, SemanticArithmeticMode, SemanticLowerer,
    SemanticOperation, semantic_wir::BinaryOperator as SemanticBinaryOperator,
};
use wrela_source::{SourceDatabase, SourceInput};
use wrela_syntax::{ParseLimits, ParseRequest, SyntaxParser, WrelaSyntaxParser};
use wrela_target::TargetPackage;
use wrela_test_model::{FailurePhase, TestOutcome};

const WORKSPACE_MANIFEST: &[u8] =
    include_bytes!("../../../std/examples/stdlib-time-scalar/wrela.toml");
const WORKSPACE_LOCKFILE: &[u8] =
    include_bytes!("../../../std/examples/stdlib-time-scalar/wrela.lock");
const IMAGE_SOURCE: &str =
    include_str!("../../../std/examples/stdlib-time-scalar/src/conformance/image.wr");
const PASSING_TEST_SOURCE: &str = include_str!(
    "../../../std/examples/stdlib-time-scalar/src/conformance/duration_scalar_test.wr"
);
const CORE_MANIFEST: &[u8] = include_bytes!("../../../std/wrela-core-0.1/wrela.toml");
const CORE_IMAGE_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/image.wr");
const CORE_OPS_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/ops.wr");
const CORE_RESULT_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/result.wr");
const CORE_TIME_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/time.wr");
const OVER_BOUND_TEST_SOURCE: &str = r#"module conformance.duration_scalar_test

from core.time import as_nanoseconds, seconds

@test
fn scalar_second_conversion_rejects_one_over_bound():
    result = seconds(18446744074)
    comptime assert as_nanoseconds(result) == 0, "unreachable after duration overflow"
"#;
const MINUTE_OVER_BOUND_TEST_SOURCE: &str = r#"module conformance.duration_scalar_test

from core.time import as_nanoseconds, minutes

@test
fn scalar_minute_conversion_rejects_one_over_bound():
    result = minutes(307445735)
    comptime assert as_nanoseconds(result) == 0, "unreachable after duration overflow"
"#;
const HOUR_OVER_BOUND_TEST_SOURCE: &str = r#"module conformance.duration_scalar_test

from core.time import as_nanoseconds, hours

@test
fn scalar_hour_conversion_rejects_one_over_bound():
    result = hours(5124096)
    comptime assert as_nanoseconds(result) == 0, "unreachable after duration overflow"
"#;
const DAY_OVER_BOUND_TEST_SOURCE: &str = r#"module conformance.duration_scalar_test

from core.time import as_nanoseconds, days

@test
fn scalar_day_conversion_rejects_one_over_bound():
    result = days(213504)
    comptime assert as_nanoseconds(result) == 0, "unreachable after duration overflow"
"#;
const WEEK_OVER_BOUND_TEST_SOURCE: &str = r#"module conformance.duration_scalar_test

from core.time import as_nanoseconds, weeks

@test
fn scalar_week_conversion_rejects_one_over_bound():
    result = weeks(30501)
    comptime assert as_nanoseconds(result) == 0, "unreachable after duration overflow"
"#;
const ADD_OVER_BOUND_TEST_SOURCE: &str = r#"module conformance.duration_scalar_test

from core.time import as_nanoseconds, ns

@test
fn duration_addition_rejects_one_over_bound():
    result = ns(18446744073709551615) + ns(1)
    comptime assert as_nanoseconds(result) == 0, "unreachable after duration addition overflow"
"#;
const SCALE_OVER_BOUND_TEST_SOURCE: &str = r#"module conformance.duration_scalar_test

from core.time import as_nanoseconds, ns, scale

@test
fn duration_scaling_rejects_one_over_bound():
    result = scale(value=ns(9223372036854775808), factor=2)
    comptime assert as_nanoseconds(result) == 0, "unreachable after duration scaling overflow"
"#;
const SUBTRACT_UNDERFLOW_TEST_SOURCE: &str = r#"module conformance.duration_scalar_test

from core.time import as_nanoseconds, ns

@test
fn duration_subtraction_rejects_underflow():
    result = ns(0) - ns(1)
    comptime assert as_nanoseconds(result) == 0, "unreachable after duration subtraction underflow"
"#;
const CLAMP_INVERTED_BOUNDS_TEST_SOURCE: &str = r#"module conformance.duration_scalar_test

from core.time import as_nanoseconds, clamp, ns

@test
fn duration_clamp_rejects_inverted_bounds():
    result = clamp(value=ns(42), lower=ns(42), upper=ns(20))
    comptime assert as_nanoseconds(result) == 0, "unreachable after inverted duration clamp bounds"
"#;
const UNSUPPORTED_ARITHMETIC_TEST_SOURCE: &str = r#"module conformance.duration_scalar_test

from core.time import ns

@test
fn duration_arithmetic_rejects_unsupported_loop():
    result = ns(20) + ns(22)
    loop:
        pass
"#;

static HASHER: SoftwareSha256 = SoftwareSha256;

struct SourceFixture {
    hir: Arc<wrela_hir::ValidatedProgram>,
    entry: DeclarationId,
    root_identity: PackageIdentity,
    profile: wrela_build_model::BuildProfile,
}

#[test]
fn checked_in_time_scalar_workspace_is_canonical_and_exact_bounds_pass() {
    let (manifest, root_identity, canonical_lockfile) = canonical_workspace();
    assert_eq!(
        canonical_lockfile,
        WORKSPACE_LOCKFILE,
        "checked-in workspace lockfile is stale; canonical bytes were:\n{}",
        String::from_utf8_lossy(&canonical_lockfile)
    );

    let workspace = load_checked_in_workspace();
    assert_eq!(workspace.canonical_lockfile(), WORKSPACE_LOCKFILE);
    assert_eq!(workspace.graph().packages().len(), 2);
    assert_eq!(workspace.graph().modules().len(), 6);
    assert_eq!(workspace.sources().len(), 6);
    // The manifest declares no `[[module]]` block: modules are derived from
    // a source-root walk. Confirm the loader derived exactly the two root
    // package modules the checked-in sources provide.
    let mut root_module_paths: Vec<String> = workspace
        .graph()
        .modules()
        .iter()
        .filter(|module| module.package == workspace.graph().root())
        .map(|module| module.path.dotted())
        .collect();
    root_module_paths.sort();
    assert_eq!(
        root_module_paths,
        ["conformance.duration_scalar_test", "conformance.image"]
    );
    assert_eq!(workspace.lockfile().root, root_identity);
    let fixture = loaded_source_fixture(workspace, root_identity, manifest.profiles[0].clone());
    let first = analyze(&fixture, TestDiscoverySelection::Comptime);
    assert!(
        first.diagnostics().is_empty(),
        "time-scalar source diagnostics: {:?}",
        first.diagnostics()
    );
    let first_image = first.successful().expect("sealed time-scalar analysis");
    let first_plan = first_image
        .facts()
        .test_plan
        .as_ref()
        .expect("time-scalar test plan");
    assert_eq!(first_plan.unit_tests().len(), 5);
    assert!(first_plan.image_groups().is_empty());
    assert_eq!(
        first_image
            .facts()
            .comptime_test_results
            .iter()
            .map(|result| &result.outcome)
            .collect::<Vec<_>>(),
        [
            &TestOutcome::Passed,
            &TestOutcome::Passed,
            &TestOutcome::Passed,
            &TestOutcome::Passed,
            &TestOutcome::Passed,
        ]
    );

    let filtered = analyze(
        &fixture,
        TestDiscoverySelection::NameContains("conversion_edges"),
    );
    assert!(filtered.diagnostics().is_empty());
    let filtered_image = filtered.successful().expect("sealed filtered analysis");
    assert_eq!(
        filtered_image
            .facts()
            .test_plan
            .as_ref()
            .expect("filtered time-scalar plan")
            .unit_tests()
            .len(),
        1
    );
    assert_eq!(
        filtered_image.facts().comptime_test_results[0].outcome,
        TestOutcome::Passed
    );

    let arithmetic = analyze(
        &fixture,
        TestDiscoverySelection::NameContains("duration_arithmetic_edges"),
    );
    assert!(arithmetic.diagnostics().is_empty());
    let arithmetic_image = arithmetic.successful().expect("sealed arithmetic analysis");
    assert_eq!(
        arithmetic_image
            .facts()
            .test_plan
            .as_ref()
            .expect("arithmetic time-scalar plan")
            .unit_tests()
            .len(),
        1
    );
    assert_eq!(
        arithmetic_image.facts().comptime_test_results[0].outcome,
        TestOutcome::Passed
    );

    let ordering = analyze(
        &fixture,
        TestDiscoverySelection::NameContains("total_order_edges"),
    );
    assert!(ordering.diagnostics().is_empty());
    let ordering_image = ordering.successful().expect("sealed ordering analysis");
    assert_eq!(
        ordering_image
            .facts()
            .test_plan
            .as_ref()
            .expect("ordering time-scalar plan")
            .unit_tests()
            .len(),
        1
    );
    assert_eq!(
        ordering_image.facts().comptime_test_results[0].outcome,
        TestOutcome::Passed
    );

    let subtraction = analyze(
        &fixture,
        TestDiscoverySelection::NameContains("subtraction_clamp_edges"),
    );
    assert!(subtraction.diagnostics().is_empty());
    let subtraction_image = subtraction
        .successful()
        .expect("sealed subtraction analysis");
    assert_eq!(
        subtraction_image
            .facts()
            .test_plan
            .as_ref()
            .expect("subtraction time-scalar plan")
            .unit_tests()
            .len(),
        1
    );
    assert_eq!(
        subtraction_image.facts().comptime_test_results[0].outcome,
        TestOutcome::Passed
    );

    let repeated = analyze(&fixture, TestDiscoverySelection::Comptime);
    let repeated_image = repeated.successful().expect("repeated sealed analysis");
    assert_eq!(
        repeated_image.facts().comptime_test_results,
        first_image.facts().comptime_test_results
    );
    assert_eq!(
        repeated_image.facts().test_plan,
        first_image.facts().test_plan
    );
}

#[test]
fn installed_duration_arithmetic_rejects_exactly_one_over_bounds() {
    // `add` and `scale` no longer have manual `comptime assert` bound checks
    // -- they rely purely on checked u64 arithmetic trapping on overflow, so
    // exactly one nanosecond (respectively one doubling) over the
    // representable bound now fails with a code-prefixed
    // `semantic-comptime-arithmetic` overflow, not an assertion-style
    // message.
    let (manifest, root_identity, _) = canonical_workspace();
    for (test_source, arithmetic, call) in [
        (
            ADD_OVER_BOUND_TEST_SOURCE,
            b"self.nanoseconds + right.nanoseconds".as_slice(),
            b"ns(18446744073709551615) + ns(1)".as_slice(),
        ),
        (
            SCALE_OVER_BOUND_TEST_SOURCE,
            b"value.nanoseconds * factor".as_slice(),
            b"scale(value=ns(9223372036854775808), factor=2)".as_slice(),
        ),
    ] {
        let fixture = source_fixture(
            test_source,
            root_identity.clone(),
            manifest.profiles[0].clone(),
        );
        let output = analyze(&fixture, TestDiscoverySelection::Comptime);
        assert!(
            output.diagnostics().is_empty(),
            "arithmetic one-over source diagnostics: {:?}",
            output.diagnostics()
        );
        let image = output
            .successful()
            .expect("sealed arithmetic one-over analysis");
        let [result] = image.facts().comptime_test_results.as_slice() else {
            panic!("arithmetic one-over workspace must produce exactly one result");
        };
        let expected_source = source_span(0, CORE_TIME_SOURCE, arithmetic);
        let expected_call = source_span(1, test_source, call);
        assert_eq!(
            result.outcome,
            TestOutcome::Failed {
                phase: FailurePhase::Comptime,
                message: format!(
                    "semantic-comptime-arithmetic: comptime integer arithmetic overflow [source {expected_source}; comptime calls <- {expected_call}]"
                ),
            }
        );
    }
}

#[test]
fn installed_duration_subtraction_rejects_underflow_without_wrapping() {
    let (manifest, root_identity, _) = canonical_workspace();
    let fixture = source_fixture(
        SUBTRACT_UNDERFLOW_TEST_SOURCE,
        root_identity,
        manifest.profiles[0].clone(),
    );
    let output = analyze(&fixture, TestDiscoverySelection::Comptime);
    assert!(
        output.diagnostics().is_empty(),
        "subtraction underflow source diagnostics: {:?}",
        output.diagnostics()
    );
    let image = output
        .successful()
        .expect("sealed subtraction underflow analysis");
    let [result] = image.facts().comptime_test_results.as_slice() else {
        panic!("subtraction underflow workspace must produce exactly one result");
    };
    // `subtract` no longer has a manual `comptime assert` underflow guard --
    // it relies purely on checked u64 subtraction trapping on underflow, so
    // this now fails with a code-prefixed `semantic-comptime-arithmetic`
    // overflow (the evaluator reports underflow the same way as overflow),
    // not an assertion-style message.
    let arithmetic = b"self.nanoseconds - right.nanoseconds";
    let call = b"ns(0) - ns(1)";
    let expected_source = source_span(0, CORE_TIME_SOURCE, arithmetic);
    let expected_call = source_span(1, SUBTRACT_UNDERFLOW_TEST_SOURCE, call);
    assert_eq!(
        result.outcome,
        TestOutcome::Failed {
            phase: FailurePhase::Comptime,
            message: format!(
                "semantic-comptime-arithmetic: comptime integer arithmetic overflow [source {expected_source}; comptime calls <- {expected_call}]"
            ),
        }
    );
}

#[test]
fn installed_duration_clamp_rejects_inverted_bounds() {
    let (manifest, root_identity, _) = canonical_workspace();
    let fixture = source_fixture(
        CLAMP_INVERTED_BOUNDS_TEST_SOURCE,
        root_identity,
        manifest.profiles[0].clone(),
    );
    let output = analyze(&fixture, TestDiscoverySelection::Comptime);
    assert!(
        output.diagnostics().is_empty(),
        "inverted clamp source diagnostics: {:?}",
        output.diagnostics()
    );
    let image = output.successful().expect("sealed inverted clamp analysis");
    let [result] = image.facts().comptime_test_results.as_slice() else {
        panic!("inverted clamp workspace must produce exactly one result");
    };
    // `clamp` keeps its plain semantic-contract `assert lower.nanoseconds <=
    // upper.nanoseconds` (a real invariant, not an overflow guard), so this
    // still fails assertion-style (no diagnostic-code prefix), just against
    // the plain (not `_comptime`-suffixed) call spelling.
    let assertion =
        b"assert lower <= upper, \"duration clamp lower bound exceeds its upper bound\"";
    let call = b"clamp(value=ns(42), lower=ns(42), upper=ns(20))";
    let expected_source = source_span(0, CORE_TIME_SOURCE, assertion);
    let expected_call = source_span(1, CLAMP_INVERTED_BOUNDS_TEST_SOURCE, call);
    assert_eq!(
        result.outcome,
        TestOutcome::Failed {
            phase: FailurePhase::Comptime,
            message: format!(
                "duration clamp lower bound exceeds its upper bound [source {expected_source}; comptime calls <- {expected_call}]"
            ),
        }
    );
}

#[test]
fn installed_duration_arithmetic_unsupported_operation_fails_closed() {
    let (manifest, root_identity, _) = canonical_workspace();
    let fixture = source_fixture(
        UNSUPPORTED_ARITHMETIC_TEST_SOURCE,
        root_identity,
        manifest.profiles[0].clone(),
    );
    // An unconditional `loop:` is unsupported both by the static
    // comptime-legality checker (so this plain `fn` never qualifies for the
    // comptime tier) and by the runtime-shape checker (it is not a bounded
    // `while`), so this is not a supported test at either tier. An explicit
    // `--comptime` selection prefers the comptime checker's own diagnostic
    // in that case (it is the more specific, correct explanation), and
    // since this fixture's only test candidate is the rejected one, there
    // is nothing else for discovery to fall back to -- it fails closed with
    // that diagnostic rather than silently sealing an empty test group.
    let output = analyze(&fixture, TestDiscoverySelection::Comptime);
    assert!(output.successful().is_none());
    let [diagnostic] = output.diagnostics() else {
        panic!("unsupported duration arithmetic must produce exactly one diagnostic");
    };
    assert_eq!(
        diagnostic.code.as_deref(),
        Some("semantic-comptime-operation-not-implemented")
    );
    assert_eq!(diagnostic.primary.file, wrela_source::FileId(1));
    let loop_start = UNSUPPORTED_ARITHMETIC_TEST_SOURCE
        .find("loop:")
        .expect("unsupported loop source") as u32;
    assert_eq!(diagnostic.primary.range.start, loop_start);
}

#[test]
fn real_imported_unit_conversions_reject_exactly_one_over_bound() {
    // Each per-unit conversion (`seconds`, `minutes`, ...) no longer has a
    // manual `comptime assert` bound check -- it relies purely on the
    // language's checked u64 multiplication trapping on overflow, so
    // exactly one nanosecond over the representable bound now fails with a
    // code-prefixed `semantic-comptime-arithmetic` overflow, not an
    // assertion-style message.
    let (manifest, root_identity, _) = canonical_workspace();
    for (test_source, arithmetic, call) in [
        (
            OVER_BOUND_TEST_SOURCE,
            b"value * 1000000000)".as_slice(),
            b"seconds(18446744074)".as_slice(),
        ),
        (
            MINUTE_OVER_BOUND_TEST_SOURCE,
            b"value * 60000000000)".as_slice(),
            b"minutes(307445735)".as_slice(),
        ),
        (
            HOUR_OVER_BOUND_TEST_SOURCE,
            b"value * 3600000000000)".as_slice(),
            b"hours(5124096)".as_slice(),
        ),
        (
            DAY_OVER_BOUND_TEST_SOURCE,
            b"value * 86400000000000)".as_slice(),
            b"days(213504)".as_slice(),
        ),
        (
            WEEK_OVER_BOUND_TEST_SOURCE,
            b"value * 604800000000000)".as_slice(),
            b"weeks(30501)".as_slice(),
        ),
    ] {
        let fixture = source_fixture(
            test_source,
            root_identity.clone(),
            manifest.profiles[0].clone(),
        );
        let output = analyze(&fixture, TestDiscoverySelection::Comptime);
        assert!(
            output.diagnostics().is_empty(),
            "one-over source diagnostics: {:?}",
            output.diagnostics()
        );
        let image = output.successful().expect("sealed one-over analysis");
        let [result] = image.facts().comptime_test_results.as_slice() else {
            panic!("one-over workspace must produce exactly one result");
        };
        // `arithmetic` above includes the trailing `)` so the needle search
        // cannot ambiguously match a shorter numeric-literal prefix shared
        // by another unit conversion (e.g. `value * 1000` inside `value *
        // 1000000`).
        let arithmetic_start = arithmetic.len() - 1;
        let expected_source = source_span(0, CORE_TIME_SOURCE, &arithmetic[..arithmetic_start]);
        let expected_call = source_span(1, test_source, call);
        let expected = format!(
            "semantic-comptime-arithmetic: comptime integer arithmetic overflow [source {expected_source}; comptime calls <- {expected_call}]"
        );
        assert_eq!(
            result.outcome,
            TestOutcome::Failed {
                phase: FailurePhase::Comptime,
                message: expected,
            }
        );
    }
}

#[test]
fn installed_duration_arithmetic_has_exact_resources_and_cancellation() {
    let (manifest, root_identity, _) = canonical_workspace();
    let workspace = load_checked_in_workspace();
    let fixture = loaded_source_fixture(workspace, root_identity, manifest.profiles[0].clone());

    // The manual `comptime assert` bound checks in the deleted `_comptime`
    // twins no longer execute, so the exact evaluator-step boundary for this
    // selection dropped from the old dual-twin core (was 1350/1349); the new
    // boundary below was measured empirically against the de-twinned
    // `std/wrela-core-0.1/src/time.wr`. The evaluator-bytes boundary is
    // unaffected (structure/argument byte accounting does not change).
    for (steps, expected) in [
        (1109, TestOutcome::Passed),
        (
            1108,
            TestOutcome::Failed {
                phase: FailurePhase::Comptime,
                message: format!(
                    "comptime test exceeded comptime evaluator steps limit 1108 [source {}]",
                    source_span_nth(0, PASSING_TEST_SOURCE, b"42", 1),
                ),
            },
        ),
    ] {
        let mut limits = AnalysisLimits::standard();
        limits.evaluator_steps = steps;
        let outcome = arithmetic_outcome(&fixture, limits, &never_cancelled)
            .expect("step-bounded installed duration arithmetic");
        assert_eq!(outcome, expected);
    }
    for (bytes, expected) in [
        (832, TestOutcome::Passed),
        (
            831,
            TestOutcome::Failed {
                phase: FailurePhase::Comptime,
                message: format!(
                    "comptime test exceeded comptime evaluator bytes limit 831 [source {}; comptime calls <- {} <- {}]",
                    source_span_nth(5, CORE_TIME_SOURCE, b"Duration(nanoseconds=value)", 0,),
                    source_span(
                        5,
                        CORE_TIME_SOURCE,
                        b"ns(value=self.nanoseconds + right.nanoseconds)"
                    ),
                    source_span(
                        0,
                        PASSING_TEST_SOURCE,
                        b"scale(value=ns(value=20), factor=2) + ns(value=2)",
                    ),
                ),
            },
        ),
    ] {
        let mut limits = AnalysisLimits::standard();
        limits.evaluator_bytes = bytes;
        let outcome = arithmetic_outcome(&fixture, limits, &never_cancelled)
            .expect("memory-bounded installed duration arithmetic");
        assert_eq!(outcome, expected);
    }

    let polls = Cell::new(0u64);
    assert_eq!(
        arithmetic_outcome(&fixture, AnalysisLimits::standard(), &|| {
            polls.set(polls.get() + 1);
            false
        })
        .expect("polled installed duration arithmetic"),
        TestOutcome::Passed
    );
    let complete_polls = polls.get();
    assert!(complete_polls > 1109);
    let cancel_at = complete_polls / 2;
    let cancelled_polls = Cell::new(0u64);
    let cancelled = arithmetic_outcome(&fixture, AnalysisLimits::standard(), &|| {
        let next = cancelled_polls.get() + 1;
        cancelled_polls.set(next);
        next == cancel_at
    });
    assert!(matches!(cancelled, Err(AnalysisFailure::Cancelled)));
    assert_eq!(cancelled_polls.get(), cancel_at);

    let repeated_polls = Cell::new(0u64);
    let repeated = arithmetic_outcome(&fixture, AnalysisLimits::standard(), &|| {
        let next = repeated_polls.get() + 1;
        repeated_polls.set(next);
        next == cancel_at
    });
    assert!(matches!(repeated, Err(AnalysisFailure::Cancelled)));
    assert_eq!(repeated_polls.get(), cancel_at);
}

fn arithmetic_outcome(
    fixture: &SourceFixture,
    limits: AnalysisLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<TestOutcome, AnalysisFailure> {
    let output = analyze_with(
        fixture,
        TestDiscoverySelection::NameContains("duration_arithmetic_edges"),
        limits,
        is_cancelled,
    )?;
    assert!(
        output.diagnostics().is_empty(),
        "duration arithmetic resource diagnostics: {:?}",
        output.diagnostics()
    );
    let image = output
        .successful()
        .expect("sealed duration arithmetic resource analysis");
    let [result] = image.facts().comptime_test_results.as_slice() else {
        panic!("duration arithmetic selection must produce exactly one result");
    };
    Ok(result.outcome.clone())
}

fn ordering_outcome(
    fixture: &SourceFixture,
    limits: AnalysisLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<TestOutcome, AnalysisFailure> {
    let output = analyze_with(
        fixture,
        TestDiscoverySelection::NameContains("duration_total_order_edges"),
        limits,
        is_cancelled,
    )?;
    assert!(
        output.diagnostics().is_empty(),
        "duration ordering resource diagnostics: {:?}",
        output.diagnostics()
    );
    let image = output
        .successful()
        .expect("sealed duration ordering resource analysis");
    let [result] = image.facts().comptime_test_results.as_slice() else {
        panic!("duration ordering selection must produce exactly one result");
    };
    Ok(result.outcome.clone())
}

fn subtraction_outcome(
    fixture: &SourceFixture,
    limits: AnalysisLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<TestOutcome, AnalysisFailure> {
    let output = analyze_with(
        fixture,
        TestDiscoverySelection::NameContains("duration_subtraction_clamp_edges"),
        limits,
        is_cancelled,
    )?;
    assert!(
        output.diagnostics().is_empty(),
        "duration subtraction resource diagnostics: {:?}",
        output.diagnostics()
    );
    let image = output
        .successful()
        .expect("sealed duration subtraction resource analysis");
    let [result] = image.facts().comptime_test_results.as_slice() else {
        panic!("duration subtraction selection must produce exactly one result");
    };
    Ok(result.outcome.clone())
}

#[test]
fn installed_duration_subtraction_and_clamp_have_exact_resources_and_cancellation() {
    let (manifest, root_identity, _) = canonical_workspace();
    let fixture = loaded_source_fixture(
        load_checked_in_workspace(),
        root_identity.clone(),
        manifest.profiles[0].clone(),
    );
    // Empirically re-measured against the de-twinned time.wr: the manual
    // `comptime assert` bound checks in the deleted `_comptime` twins no
    // longer execute, so the exact evaluator-step boundary dropped from the
    // old dual-twin core (was 2793/2792). The evaluator-bytes boundary is
    // unaffected.
    for (steps, expected) in [
        (2804, TestOutcome::Passed),
        (
            2803,
            TestOutcome::Failed {
                phase: FailurePhase::Comptime,
                message: format!(
                    "comptime test exceeded comptime evaluator steps limit 2803 [source {}]",
                    source_span_nth(0, PASSING_TEST_SOURCE, b"22", 0),
                ),
            },
        ),
    ] {
        let mut limits = AnalysisLimits::standard();
        limits.evaluator_steps = steps;
        assert_eq!(
            subtraction_outcome(&fixture, limits, &never_cancelled)
                .expect("step-bounded installed duration subtraction"),
            expected
        );
    }
    for (bytes, expected) in [
        (1312, TestOutcome::Passed),
        (
            1311,
            TestOutcome::Failed {
                phase: FailurePhase::Comptime,
                message: format!(
                    "comptime test exceeded comptime evaluator bytes limit 1311 [source {}; comptime calls <- {} <- {}]",
                    source_span_nth(5, CORE_TIME_SOURCE, b"self", 5),
                    source_span(5, CORE_TIME_SOURCE, b"selected < lower"),
                    source_span_nth(
                        0,
                        PASSING_TEST_SOURCE,
                        b"clamp(value=ns(value=84), lower=ns(value=20), upper=ns(value=42))",
                        1,
                    ),
                ),
            },
        ),
    ] {
        let mut limits = AnalysisLimits::standard();
        limits.evaluator_bytes = bytes;
        assert_eq!(
            subtraction_outcome(&fixture, limits, &never_cancelled)
                .expect("memory-bounded installed duration subtraction"),
            expected
        );
    }

    let mut exact_profile = manifest.profiles[0].clone();
    exact_profile.comptime.call_depth = 3;
    let exact_depth = loaded_source_fixture(
        load_checked_in_workspace(),
        root_identity.clone(),
        exact_profile,
    );
    assert_eq!(
        subtraction_outcome(&exact_depth, AnalysisLimits::standard(), &never_cancelled)
            .expect("exact-depth installed duration subtraction"),
        TestOutcome::Passed
    );
    let mut over_profile = manifest.profiles[0].clone();
    over_profile.comptime.call_depth = 2;
    let over_depth =
        loaded_source_fixture(load_checked_in_workspace(), root_identity, over_profile);
    let helper_call = source_span(
        5,
        CORE_TIME_SOURCE,
        b"ns(value=self.nanoseconds - right.nanoseconds)",
    );
    let outer_call = source_span(0, PASSING_TEST_SOURCE, b"ns(value=42) - ns(value=42)");
    assert_eq!(
        subtraction_outcome(&over_depth, AnalysisLimits::standard(), &never_cancelled)
            .expect("over-depth installed duration subtraction"),
        TestOutcome::Failed {
            phase: FailurePhase::Comptime,
            message: format!(
                "comptime test exceeded comptime evaluator depth limit 2 [source {helper_call}; comptime calls <- {helper_call} <- {outer_call}]"
            ),
        }
    );

    let polls = Cell::new(0u64);
    assert_eq!(
        subtraction_outcome(&fixture, AnalysisLimits::standard(), &|| {
            polls.set(polls.get() + 1);
            false
        })
        .expect("polled installed duration subtraction"),
        TestOutcome::Passed
    );
    let complete_polls = polls.get();
    assert!(complete_polls > 2804);
    let cancel_at = complete_polls / 2;
    for _ in 0..2 {
        let cancelled_polls = Cell::new(0u64);
        let cancelled = subtraction_outcome(&fixture, AnalysisLimits::standard(), &|| {
            let next = cancelled_polls.get() + 1;
            cancelled_polls.set(next);
            next == cancel_at
        });
        assert!(matches!(cancelled, Err(AnalysisFailure::Cancelled)));
        assert_eq!(cancelled_polls.get(), cancel_at);
    }
}

#[test]
fn installed_duration_ordering_has_exact_resources_depth_and_cancellation() {
    let (manifest, root_identity, _) = canonical_workspace();
    let fixture = loaded_source_fixture(
        load_checked_in_workspace(),
        root_identity.clone(),
        manifest.profiles[0].clone(),
    );
    // Empirically re-measured against the copy-fixed time.wr, whose
    // comparisons now route through `impl Ord for Duration: fn less_than`
    // (called via the raw `<`/`<=`/`>`/`>=` operators rather than the
    // deleted free-function comparison helpers).
    for (steps, expected) in [
        (2153, TestOutcome::Passed),
        (
            2152,
            TestOutcome::Failed {
                phase: FailurePhase::Comptime,
                message: format!(
                    "comptime test exceeded comptime evaluator steps limit 2152 [source {}]",
                    source_span_nth(0, PASSING_TEST_SOURCE, b"42", 6),
                ),
            },
        ),
    ] {
        let mut limits = AnalysisLimits::standard();
        limits.evaluator_steps = steps;
        let outcome = ordering_outcome(&fixture, limits, &never_cancelled)
            .expect("step-bounded installed duration ordering");
        assert_eq!(outcome, expected);
    }
    // The evaluator-bytes boundary's cross-function-call chain now bottoms
    // out earlier, inside `max`'s own `if left < right:` comparison (which
    // calls into `impl Ord for Duration: fn less_than`'s `self` reference),
    // rather than in the subsequent `ns` constructor call.
    for (bytes, expected) in [
        (1632, TestOutcome::Passed),
        (
            1631,
            TestOutcome::Failed {
                phase: FailurePhase::Comptime,
                message: format!(
                    "comptime test exceeded comptime evaluator bytes limit 1631 [source {}; comptime calls <- {} <- {}]",
                    source_span_nth(5, CORE_TIME_SOURCE, b"self", 5),
                    source_span(5, CORE_TIME_SOURCE, b"left < right"),
                    source_span(0, PASSING_TEST_SOURCE, b"max(left=zero, right=forty_two)"),
                ),
            },
        ),
    ] {
        let mut limits = AnalysisLimits::standard();
        limits.evaluator_bytes = bytes;
        let outcome = ordering_outcome(&fixture, limits, &never_cancelled)
            .expect("memory-bounded installed duration ordering");
        assert_eq!(outcome, expected);
    }

    let mut exact_profile = manifest.profiles[0].clone();
    exact_profile.comptime.call_depth = 3;
    let exact_depth = loaded_source_fixture(
        load_checked_in_workspace(),
        root_identity.clone(),
        exact_profile,
    );
    assert_eq!(
        ordering_outcome(&exact_depth, AnalysisLimits::standard(), &never_cancelled)
            .expect("exact-depth installed duration ordering"),
        TestOutcome::Passed
    );
    let mut over_profile = manifest.profiles[0].clone();
    over_profile.comptime.call_depth = 2;
    let over_depth =
        loaded_source_fixture(load_checked_in_workspace(), root_identity, over_profile);
    // The over-depth chain used to bottom out in the deleted `less_than`
    // helper (called from `min`); `min` now performs that comparison inline,
    // so the depth-3 call it still makes runs straight through to its own
    // `ns` constructor call.
    // `min`'s own `if left <= right:` comparison (routed through the `<=`
    // operator) is now the depth-exceeding frame directly, rather than a
    // deleted `less_than` helper or a subsequent `ns` constructor call.
    let helper_call = source_span(5, CORE_TIME_SOURCE, b"left <= right");
    let outer_call = source_span(
        0,
        PASSING_TEST_SOURCE,
        b"min(left=copy forty_two, right=copy forty_one)",
    );
    assert_eq!(
        ordering_outcome(&over_depth, AnalysisLimits::standard(), &never_cancelled)
            .expect("over-depth installed duration ordering"),
        TestOutcome::Failed {
            phase: FailurePhase::Comptime,
            message: format!(
                "comptime test exceeded comptime evaluator depth limit 2 [source {helper_call}; comptime calls <- {helper_call} <- {outer_call}]"
            ),
        }
    );

    let polls = Cell::new(0u64);
    assert_eq!(
        ordering_outcome(&fixture, AnalysisLimits::standard(), &|| {
            polls.set(polls.get() + 1);
            false
        })
        .expect("polled installed duration ordering"),
        TestOutcome::Passed
    );
    let complete_polls = polls.get();
    assert!(complete_polls > 2153);
    let cancel_at = complete_polls / 2;
    let cancelled_polls = Cell::new(0u64);
    let cancelled = ordering_outcome(&fixture, AnalysisLimits::standard(), &|| {
        let next = cancelled_polls.get() + 1;
        cancelled_polls.set(next);
        next == cancel_at
    });
    assert!(matches!(cancelled, Err(AnalysisFailure::Cancelled)));
    assert_eq!(cancelled_polls.get(), cancel_at);

    let repeated_polls = Cell::new(0u64);
    let repeated = ordering_outcome(&fixture, AnalysisLimits::standard(), &|| {
        let next = repeated_polls.get() + 1;
        repeated_polls.set(next);
        next == cancel_at
    });
    assert!(matches!(repeated, Err(AnalysisFailure::Cancelled)));
    assert_eq!(repeated_polls.get(), cancel_at);
}

#[test]
fn installed_runtime_duration_functions_reach_canonical_machine_and_native_object() {
    let (manifest, root_identity, _) = canonical_workspace();
    let workspace = load_checked_in_workspace();
    let fixture = loaded_source_fixture(workspace, root_identity, manifest.profiles[0].clone());
    let discovery = analyze(
        &fixture,
        TestDiscoverySelection::NameContains("installed_runtime_duration_functions_reach_machine"),
    );
    assert!(
        discovery.diagnostics().is_empty(),
        "runtime discovery diagnostics: {:?}",
        discovery.diagnostics()
    );
    let discovery_image = discovery.successful().expect("sealed runtime discovery");
    let plan = discovery_image
        .facts()
        .test_plan
        .as_ref()
        .expect("runtime test plan");
    assert!(plan.unit_tests().is_empty());
    let [group] = plan.image_groups() else {
        panic!("installed runtime test must produce exactly one image group");
    };
    assert_eq!(group.tests.len(), 1);

    let (build, target) = analysis_build(&fixture);
    let compilation = CanonicalSemanticAnalyzer::new()
        .analyze(
            AnalysisRequest {
                hir: Arc::clone(&fixture.hir),
                standard_library_package: wrela_package::PackageId(1),
                target: target.semantic(),
                build: &build,
                mode: AnalysisMode::CompileTestGroup {
                    plan,
                    group: group.id,
                    declared_entry: None,
                },
                changes: &AnalysisChangeSet {
                    previous_source_graph: None,
                    changed_declarations: Vec::new(),
                },
                limits: AnalysisLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("installed runtime test semantic analysis");
    assert!(
        compilation.diagnostics().is_empty(),
        "runtime compilation diagnostics: {:?}",
        compilation.diagnostics()
    );
    let analyzed = compilation
        .into_parts()
        .0
        .expect("sealed installed runtime test image");
    let semantic = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed,
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("installed core.time lowers to SemanticWir");
    let semantic_model = semantic.wir().as_wir();
    let duration_semantic_type = semantic_model
        .types
        .iter()
        .find(|ty| ty.source_name == "Duration")
        .expect("installed core.time.Duration SemanticWir type");
    let mut semantic_aggregates = 0;
    let mut semantic_projects = 0;
    let mut semantic_checked_multiplies = 0;
    let mut semantic_checked_adds = 0;
    let mut semantic_checked_subtracts = 0;
    let mut semantic_comparisons = Vec::new();
    let mut semantic_copies = 0;
    let mut semantic_branches = 0;
    for function in &semantic_model.functions {
        if !function.name.starts_with("wrela-core@0.1.0::time::") {
            continue;
        }
        let mut regions = vec![&function.body];
        while let Some(region) = regions.pop() {
            for statement in &region.statements {
                match statement {
                    LoweredSemanticStatement::Let(statement) => match &statement.operation {
                        SemanticOperation::Aggregate { ty, fields }
                            if *ty == duration_semantic_type.id =>
                        {
                            assert_eq!(fields.len(), 1);
                            semantic_aggregates += 1;
                        }
                        SemanticOperation::Project { field, .. } => {
                            assert_eq!(*field, 0);
                            semantic_projects += 1;
                        }
                        SemanticOperation::Binary {
                            operator: SemanticBinaryOperator::Multiply,
                            arithmetic: SemanticArithmeticMode::Checked,
                            ..
                        } => semantic_checked_multiplies += 1,
                        SemanticOperation::Binary {
                            operator: SemanticBinaryOperator::Add,
                            arithmetic: SemanticArithmeticMode::Checked,
                            ..
                        } => semantic_checked_adds += 1,
                        SemanticOperation::Binary {
                            operator: SemanticBinaryOperator::Subtract,
                            arithmetic: SemanticArithmeticMode::Checked,
                            ..
                        } => semantic_checked_subtracts += 1,
                        SemanticOperation::Binary { operator, .. }
                            if matches!(
                                operator,
                                SemanticBinaryOperator::Less | SemanticBinaryOperator::LessEqual
                            ) =>
                        {
                            semantic_comparisons.push(*operator);
                        }
                        SemanticOperation::Copy { .. } => semantic_copies += 1,
                        _ => {}
                    },
                    LoweredSemanticStatement::If {
                        then_region,
                        else_region,
                        ..
                    } => {
                        semantic_branches += 1;
                        regions.push(else_region);
                        regions.push(then_region);
                    }
                    LoweredSemanticStatement::Match { arms, .. } => {
                        regions.extend(arms.iter().map(|arm| &arm.body));
                    }
                    LoweredSemanticStatement::Loop { body, .. } => regions.push(body),
                    _ => {}
                }
            }
        }
    }
    // Empirically re-measured against the operator-desugared model: `<`,
    // `<=`, `>`, and `>=` now compile as calls into `impl Ord for Duration:
    // fn less_than` (rather than an inlined comparison per call site), so
    // exactly one `Less` binary op appears -- the single literal
    // `self.nanoseconds < right.nanoseconds` inside `less_than`'s own body
    // -- and no `LessEqual` op appears at all (`<=`/`>`/`>=` are expressed
    // as calls plus argument order/negation, not a distinct binary op).
    // `add`/`subtract` are likewise now separate `impl Add`/`impl Sub`
    // functions with exactly one checked binary op each in their own
    // bodies (was 2/2 when arithmetic was still partly inlined).
    // `min`/`max`/`clamp` no longer end with a `ns(value=selected)` call,
    // so `projects` drops to the sum of the leaf field-accessing bodies
    // (`as_nanoseconds`:1, `add`:2, `subtract`:2, `less_than`:2, `scale`:1 =
    // 8), while `copies` rises to the sum of `min`'s 2, `max`'s 2, and
    // `clamp`'s 3 `copy`-annotated reassignments (was 1, from a different
    // pre-copy-fix shape). `branches` (4: one `if` each in `min`/`max`,
    // two in `clamp`) is unaffected.
    assert_eq!(semantic_aggregates, 1);
    assert_eq!(semantic_projects, 8);
    assert_eq!(semantic_checked_multiplies, 8);
    assert_eq!(semantic_checked_adds, 1);
    assert_eq!(semantic_checked_subtracts, 1);
    semantic_comparisons.sort_by_key(|operator| match operator {
        SemanticBinaryOperator::Less => 0,
        SemanticBinaryOperator::LessEqual => 1,
        _ => 2,
    });
    assert_eq!(semantic_comparisons, [SemanticBinaryOperator::Less]);
    assert_eq!(semantic_copies, 7);
    assert_eq!(semantic_branches, 4);

    let (semantic_wir, _) = semantic.into_parts();
    let flow = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic_wir,
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("installed core.time lowers to FlowWir");
    assert!(flow.diagnostics().is_empty());
    let flow_model = flow.wir().as_wir();
    let duration_flow_type = flow_model
        .types
        .iter()
        .find(|ty| ty.name.as_deref() == Some("Duration"))
        .expect("installed core.time.Duration FlowWir type");
    let mut flow_aggregates = 0;
    let mut flow_projects = 0;
    let mut flow_checked_multiplies = 0;
    let mut flow_checked_adds = 0;
    let mut flow_checked_subtracts = 0;
    let mut flow_comparisons = Vec::new();
    let mut flow_copies = 0;
    let mut flow_branches = 0;
    let mut flow_call_edges = Vec::new();
    for function in &flow_model.functions {
        let is_core_time = function.name.starts_with("wrela-core@0.1.0::time::");
        for block in &function.blocks {
            for instruction in &block.instructions {
                if is_core_time {
                    match &instruction.operation {
                        FlowOperation::MakeAggregate { ty, fields }
                            if *ty == duration_flow_type.id =>
                        {
                            assert_eq!(fields.len(), 1);
                            flow_aggregates += 1;
                        }
                        FlowOperation::ExtractField { field, .. } => {
                            assert_eq!(*field, 0);
                            flow_projects += 1;
                        }
                        FlowOperation::Binary {
                            op: FlowBinaryOp::MulChecked,
                            ..
                        } => flow_checked_multiplies += 1,
                        FlowOperation::Binary {
                            op: FlowBinaryOp::AddChecked,
                            ..
                        } => flow_checked_adds += 1,
                        FlowOperation::Binary {
                            op: FlowBinaryOp::SubChecked,
                            ..
                        } => flow_checked_subtracts += 1,
                        FlowOperation::Binary { op, .. }
                            if matches!(op, FlowBinaryOp::Less | FlowBinaryOp::LessEqual) =>
                        {
                            flow_comparisons.push(*op);
                        }
                        FlowOperation::Copy { .. } => flow_copies += 1,
                        _ => {}
                    }
                }
                if let FlowOperation::Call {
                    function: callee, ..
                } = &instruction.operation
                {
                    flow_call_edges.push((
                        function.name.clone(),
                        flow_model.functions[callee.0 as usize].name.clone(),
                    ));
                }
            }
            if is_core_time && matches!(block.terminator, FlowTerminator::Branch { .. }) {
                flow_branches += 1;
            }
        }
    }
    // Same operator-desugared shape as the SemanticWir counts above (FlowWir
    // preserves the same operation counts 1:1 from SemanticWir here).
    assert_eq!(flow_aggregates, 1);
    assert_eq!(flow_projects, 8);
    assert_eq!(flow_checked_multiplies, 8);
    assert_eq!(flow_checked_adds, 1);
    assert_eq!(flow_checked_subtracts, 1);
    flow_comparisons.sort_by_key(|operator| match operator {
        FlowBinaryOp::Less => 0,
        FlowBinaryOp::LessEqual => 1,
        _ => 2,
    });
    assert_eq!(flow_comparisons, [FlowBinaryOp::Less]);
    assert_eq!(flow_copies, 7);
    assert_eq!(flow_branches, 4);
    flow_call_edges.sort();
    assert_eq!(flow_call_edges, expected_runtime_call_edges());
    let flow_function_names = flow_model
        .functions
        .iter()
        .map(|function| function.name.clone())
        .collect::<Vec<_>>();

    let (flow_wir, _, _) = flow.into_parts();
    let encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: &flow_wir,
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("installed core.time canonical FlowWir v7 roundtrip");
    let prepared =
        prepare_canonical_frame_for_codegen(encoded.bytes(), &target, &build, &never_cancelled)
            .expect("canonical backend accepts installed core.time FlowWir");
    let machine = prepared.machine().wir().as_wir();
    let duration_machine_type = machine
        .types
        .iter()
        .find(|ty| ty.source_name.as_deref() == Some("Duration"))
        .expect("installed core.time.Duration MachineWir type");
    assert_eq!(
        duration_machine_type.kind,
        MachineTypeKind::Integer { bits: 64 }
    );
    assert_eq!(
        (duration_machine_type.size, duration_machine_type.alignment),
        (8, 8)
    );
    let mut machine_bitcasts = 0;
    let mut machine_checked_multiplies = 0;
    let mut machine_checked_adds = 0;
    let mut machine_checked_subtracts = 0;
    let mut machine_comparisons = Vec::new();
    let mut machine_branches = 0;
    let mut called_functions = Vec::new();
    let mut machine_call_edges = Vec::new();
    for function in &machine.functions {
        let flow_name = &flow_function_names[function.flow_function as usize];
        let is_core_time = flow_name.starts_with("wrela-core@0.1.0::time::");
        for block in &function.blocks {
            for instruction in &block.instructions {
                if is_core_time {
                    match &instruction.operation {
                        MachineOperation::Convert {
                            op: ConversionOp::Bitcast,
                            ..
                        } => machine_bitcasts += 1,
                        MachineOperation::CheckedInteger {
                            op: CheckedIntegerOp::Multiply,
                            ..
                        } => machine_checked_multiplies += 1,
                        MachineOperation::CheckedInteger {
                            op: CheckedIntegerOp::Add,
                            ..
                        } => machine_checked_adds += 1,
                        MachineOperation::CheckedInteger {
                            op: CheckedIntegerOp::Subtract,
                            ..
                        } => machine_checked_subtracts += 1,
                        MachineOperation::IntegerCompare { predicate, .. } => {
                            machine_comparisons.push(*predicate);
                        }
                        _ => {}
                    }
                }
                if let MachineOperation::Call {
                    function: callee, ..
                } = &instruction.operation
                {
                    called_functions.push(*callee);
                    let callee_function = &machine.functions[callee.0 as usize];
                    machine_call_edges.push((
                        flow_name.clone(),
                        flow_function_names[callee_function.flow_function as usize].clone(),
                    ));
                }
            }
            if is_core_time && matches!(block.terminator, MachineTerminator::Branch { .. }) {
                machine_branches += 1;
            }
        }
    }
    // Bitcasts track the fewer Duration<->u64 field accesses/aggregates in
    // the operator-desugared shape above (was 24; the projects/aggregates
    // count driving them dropped from 22/1 to 8/1).
    assert_eq!(machine_bitcasts, 16);
    assert_eq!(machine_checked_multiplies, 8);
    assert_eq!(machine_checked_adds, 1);
    assert_eq!(machine_checked_subtracts, 1);
    machine_comparisons.sort_by_key(|predicate| match predicate {
        IntegerPredicate::UnsignedLess => 0,
        IntegerPredicate::UnsignedLessEqual => 1,
        _ => 2,
    });
    assert_eq!(machine_comparisons, [IntegerPredicate::UnsignedLess]);
    assert_eq!(machine_branches, 4);
    machine_call_edges.sort();
    assert_eq!(machine_call_edges, expected_runtime_call_edges());

    match emit_prepared_object(&prepared, &target, &never_cancelled) {
        Err(CodegenError::BackendNotBuilt) if !llvm_backend_available() => {}
        Err(CodegenError::BackendNotBuilt) => {
            panic!("LLVM reports available but rejected installed core.time object emission")
        }
        Err(error) => {
            panic!("installed core.time MachineWir must reach the frozen native backend: {error}")
        }
        Ok(_) if !llvm_backend_available() => {
            panic!("installed core.time object emitted while LLVM reports unavailable")
        }
        Ok(first) => {
            let second = emit_prepared_object(&prepared, &target, &never_cancelled)
                .expect("repeated installed core.time native object emission");
            assert_eq!(first, second);
            assert_eq!(first.bytes().get(..2), Some([0x64, 0xaa].as_slice()));
            for called in &called_functions {
                let symbol = machine
                    .symbols
                    .iter()
                    .find(|symbol| symbol.definition == SymbolDefinition::Function(*called))
                    .expect("called installed core.time function has an exact native symbol");
                assert!(
                    first
                        .symbols()
                        .iter()
                        .any(|emitted| emitted.name == symbol.name)
                );
            }
        }
    }
}

fn expected_runtime_call_edges() -> Vec<(String, String)> {
    const TEST: &str = "stdlib-time-scalar-conformance@0.1.0::conformance.duration_scalar_test::installed_runtime_duration_functions_reach_machine";
    const ADD: &str = "wrela-core@0.1.0::time::add";
    const AS_NANOSECONDS: &str = "wrela-core@0.1.0::time::as_nanoseconds";
    const CLAMP: &str = "wrela-core@0.1.0::time::clamp";
    const DAYS: &str = "wrela-core@0.1.0::time::days";
    const HOURS: &str = "wrela-core@0.1.0::time::hours";
    const LESS_THAN: &str = "wrela-core@0.1.0::time::less_than";
    const MAX: &str = "wrela-core@0.1.0::time::max";
    const MILLISECONDS: &str = "wrela-core@0.1.0::time::ms";
    const MIN: &str = "wrela-core@0.1.0::time::min";
    const MINUTES: &str = "wrela-core@0.1.0::time::minutes";
    const NANOSECONDS: &str = "wrela-core@0.1.0::time::ns";
    const SECONDS: &str = "wrela-core@0.1.0::time::seconds";
    const SCALE: &str = "wrela-core@0.1.0::time::scale";
    const MICROSECONDS: &str = "wrela-core@0.1.0::time::us";
    const SUBTRACT: &str = "wrela-core@0.1.0::time::subtract";
    const WEEKS: &str = "wrela-core@0.1.0::time::weeks";

    let mut edges = Vec::new();
    let mut push = |caller: &str, callee: &str, count: usize| {
        for _ in 0..count {
            edges.push((caller.to_owned(), callee.to_owned()));
        }
    };
    push("__wrela_test_entry", TEST, 1);
    // The `<`/`<=`/`>`/`>=` comparisons on `before`, `before_or_equal`,
    // `after`, and `after_or_equal` now desugar to four direct calls into
    // `impl Ord for Duration: fn less_than` -- the native operator proof for
    // this suite -- rather than an inlined comparison. `as_nanoseconds` is
    // called from exactly the 14 call sites that wrap a `Duration` result
    // (the four raw comparisons above return `bool` directly and no longer
    // route through `as_nanoseconds`).
    push(TEST, AS_NANOSECONDS, 14);
    push(TEST, NANOSECONDS, 21);
    push(TEST, LESS_THAN, 4);
    for callee in [
        ADD,
        CLAMP,
        DAYS,
        HOURS,
        MAX,
        MILLISECONDS,
        MIN,
        MINUTES,
        SCALE,
        SECONDS,
        SUBTRACT,
        MICROSECONDS,
        WEEKS,
    ] {
        push(TEST, callee, 1);
    }
    // `min`/`max`/`clamp` no longer end with `return ns(value=selected)` --
    // they return the branch-joined `selected: Duration` local directly, so
    // they no longer call `ns` at all. Their `<`/`<=` comparisons instead
    // call `less_than` directly: once each for `min`'s `left <= right` and
    // `max`'s `left < right`, and three times for `clamp`'s
    // `assert lower <= upper`, `if selected < lower`, and
    // `if upper < selected`.
    push(MIN, LESS_THAN, 1);
    push(MAX, LESS_THAN, 1);
    push(CLAMP, LESS_THAN, 3);
    for caller in [
        ADD,
        DAYS,
        HOURS,
        MILLISECONDS,
        MINUTES,
        SCALE,
        SECONDS,
        SUBTRACT,
        MICROSECONDS,
        WEEKS,
    ] {
        push(caller, NANOSECONDS, 1);
    }
    edges.sort();
    edges
}

fn canonical_workspace() -> (wrela_package::PackageManifest, PackageIdentity, Vec<u8>) {
    let codec = CanonicalPackageCodec::new();
    let manifest = codec
        .decode_manifest(WORKSPACE_MANIFEST, manifest_limits(), &never_cancelled)
        .expect("checked-in time-scalar manifest");
    // The checked-in manifest declares only `[[profile]]` overrides and no
    // `[[module]]` block (modules are derived by the loader, not decoded
    // here), so it need not be byte-identical to its own canonical
    // re-encoding; every digest below binds the canonical bytes, exactly as
    // the production loader does.
    let canonical_manifest = codec
        .canonical_manifest(&manifest, manifest_limits(), &never_cancelled)
        .expect("canonical time-scalar manifest");
    assert_eq!(
        codec
            .decode_manifest(&canonical_manifest, manifest_limits(), &never_cancelled)
            .expect("redecode canonical time-scalar manifest"),
        manifest
    );
    let core_manifest = codec
        .decode_manifest(CORE_MANIFEST, manifest_limits(), &never_cancelled)
        .expect("checked-in core manifest");
    let canonical_core_manifest = codec
        .canonical_manifest(&core_manifest, manifest_limits(), &never_cancelled)
        .expect("canonical core manifest");
    let root_identity = PackageIdentity {
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        source_digest: package_content_digest(
            &canonical_manifest,
            &[
                content_record("conformance/duration_scalar_test.wr", PASSING_TEST_SOURCE),
                content_record("conformance/image.wr", IMAGE_SOURCE),
            ],
            &HASHER,
            &never_cancelled,
        )
        .expect("time-scalar package identity"),
    };
    let core_identity = PackageIdentity {
        name: core_manifest.name.clone(),
        version: core_manifest.version.clone(),
        source_digest: package_content_digest(
            &canonical_core_manifest,
            &[
                content_record("image.wr", CORE_IMAGE_SOURCE),
                content_record("ops.wr", CORE_OPS_SOURCE),
                content_record("result.wr", CORE_RESULT_SOURCE),
                content_record("time.wr", CORE_TIME_SOURCE),
            ],
            &HASHER,
            &never_cancelled,
        )
        .expect("core package identity"),
    };
    let mut packages = vec![
        LockedPackage {
            identity: root_identity.clone(),
            locator: PackageLocator::Workspace {
                path: ".".to_owned(),
            },
            dependencies: vec![LockedDependency {
                alias: DependencyAlias::new("core").expect("core alias"),
                identity: core_identity.clone(),
            }],
            manifest_digest: HASHER.sha256(&canonical_manifest),
        },
        LockedPackage {
            identity: core_identity,
            locator: PackageLocator::Toolchain {
                component: "wrela-core-0.1".to_owned(),
            },
            dependencies: Vec::new(),
            manifest_digest: HASHER.sha256(&canonical_core_manifest),
        },
    ];
    packages.sort_by(|left, right| left.identity.cmp(&right.identity));
    let lockfile = Lockfile {
        schema: LOCKFILE_SCHEMA_VERSION,
        root: root_identity.clone(),
        packages,
    };
    let canonical_lockfile = codec
        .canonical_lockfile(&lockfile, lockfile_limits(), &never_cancelled)
        .expect("canonical time-scalar lockfile");
    let decoded_lockfile = codec
        .decode_lockfile(&canonical_lockfile, lockfile_limits(), &never_cancelled)
        .expect("round-trip time-scalar lockfile");
    assert_eq!(decoded_lockfile, lockfile);
    (manifest, root_identity, canonical_lockfile)
}

fn source_fixture(
    test_source: &str,
    _root_identity: PackageIdentity,
    profile: wrela_build_model::BuildProfile,
) -> SourceFixture {
    let root_identity = override_root_identity(test_source);
    let mut sources = SourceDatabase::default();
    let core_time = add_source(&mut sources, "a-core/time.wr", CORE_TIME_SOURCE, 0x81);
    let tests = add_source(
        &mut sources,
        "conformance/duration_scalar_test.wr",
        test_source,
        0x82,
    );
    let image = add_source(&mut sources, "conformance/image.wr", IMAGE_SOURCE, 0x83);
    let core_image = add_source(&mut sources, "core/image.wr", CORE_IMAGE_SOURCE, 0x84);
    let core_ops = add_source(&mut sources, "core/ops.wr", CORE_OPS_SOURCE, 0x8b);
    let mut graph = PackageGraphBuilder::new(root_identity.clone());
    let core_package = graph
        .add_package(PackageIdentity {
            name: wrela_package::PackageName::new("wrela-core").expect("core package name"),
            version: wrela_package::PackageVersion::new("0.1.0").expect("core package version"),
            source_digest: Sha256Digest::from_bytes([0x85; 32]),
        })
        .expect("core package");
    graph
        .add_dependency(
            graph.root(),
            DependencyAlias::new("core").expect("core alias"),
            core_package,
        )
        .expect("core dependency");
    for (module, file) in [
        (["conformance", "duration_scalar_test"], tests),
        (["conformance", "image"], image),
    ] {
        graph
            .add_module(
                graph.root(),
                ModulePath::new(module.map(str::to_owned)).expect("conformance module path"),
                file,
            )
            .expect("conformance module");
    }
    for (module, file) in [
        (["image"], core_image),
        (["ops"], core_ops),
        (["time"], core_time),
    ] {
        graph
            .add_module(
                core_package,
                ModulePath::new(module.map(str::to_owned)).expect("core module path"),
                file,
            )
            .expect("core module");
    }
    lower_source_fixture(
        Arc::new(graph.finish().expect("sealed package graph")),
        sources,
        root_identity.source_digest,
        root_identity,
        profile,
    )
}

fn override_root_identity(test_source: &str) -> PackageIdentity {
    let codec = CanonicalPackageCodec::new();
    let manifest = codec
        .decode_manifest(WORKSPACE_MANIFEST, manifest_limits(), &never_cancelled)
        .expect("checked-in time-scalar manifest");
    let canonical_manifest = codec
        .canonical_manifest(&manifest, manifest_limits(), &never_cancelled)
        .expect("canonical time-scalar manifest");
    PackageIdentity {
        name: manifest.name,
        version: manifest.version,
        source_digest: package_content_digest(
            &canonical_manifest,
            &[
                content_record("conformance/duration_scalar_test.wr", test_source),
                content_record("conformance/image.wr", IMAGE_SOURCE),
            ],
            &HASHER,
            &never_cancelled,
        )
        .expect("overridden time-scalar package identity"),
    }
}

fn loaded_source_fixture(
    workspace: LoadedWorkspace,
    root_identity: PackageIdentity,
    profile: wrela_build_model::BuildProfile,
) -> SourceFixture {
    let source_graph_digest = workspace.source_graph_digest();
    let parts = workspace.into_parts();
    lower_source_fixture(
        Arc::new(parts.graph),
        parts.sources,
        source_graph_digest,
        root_identity,
        profile,
    )
}

fn lower_source_fixture(
    graph: Arc<wrela_package::PackageGraph>,
    sources: SourceDatabase,
    source_graph_digest: Sha256Digest,
    root_identity: PackageIdentity,
    profile: wrela_build_model::BuildProfile,
) -> SourceFixture {
    let parsed_files = sources
        .files()
        .iter()
        .map(|source| {
            let (parsed, diagnostics) = WrelaSyntaxParser::new()
                .parse(
                    ParseRequest {
                        sources: &sources,
                        file: source.id(),
                        limits: ParseLimits::standard(),
                    },
                    &never_cancelled,
                )
                .expect("time-scalar source parses")
                .into_parts();
            assert!(diagnostics.is_empty(), "parse diagnostics: {diagnostics:?}");
            parsed
        })
        .collect::<Vec<_>>();
    let output = CanonicalHirLowerer::new()
        .lower(
            HirLowerRequest {
                packages: graph,
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
        .expect("time-scalar source lowers");
    assert!(
        output.diagnostics().is_empty(),
        "HIR diagnostics: {:?}",
        output.diagnostics()
    );
    let entry = *output
        .lowered()
        .program()
        .as_program()
        .image_candidates
        .first()
        .expect("time-scalar image entry");
    SourceFixture {
        hir: Arc::new(output.into_parts().0.into_program()),
        entry,
        root_identity,
        profile,
    }
}

#[derive(Clone)]
struct CheckedInProvider {
    bundles: Vec<PackageBundle>,
}

impl PackageSourceProvider for CheckedInProvider {
    fn acquire(
        &self,
        locator: &PackageLocator,
        expected: &PackageIdentity,
        maximum_bytes: u64,
        maximum_manifest_bytes: u64,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<PackageBundle, ProviderError> {
        if is_cancelled() {
            return Err(ProviderError::Unavailable("cancelled".to_owned()));
        }
        let bundle = self
            .bundles
            .iter()
            .find(|bundle| &bundle.locator == locator)
            .ok_or_else(|| ProviderError::Unavailable("unknown fixture locator".to_owned()))?;
        if &bundle.identity != expected {
            return Err(ProviderError::IdentityMismatch);
        }
        let manifest_bytes = u64::try_from(bundle.manifest_bytes.len()).unwrap_or(u64::MAX);
        if manifest_bytes > maximum_manifest_bytes {
            return Err(ProviderError::TooLarge {
                limit: maximum_manifest_bytes,
            });
        }
        let total = bundle
            .sources
            .iter()
            .try_fold(manifest_bytes, |total, source| {
                total.checked_add(u64::try_from(source.text.len()).unwrap_or(u64::MAX))
            });
        if total.is_none_or(|total| total > maximum_bytes) {
            return Err(ProviderError::TooLarge {
                limit: maximum_bytes,
            });
        }
        Ok(bundle.clone())
    }
}

fn load_checked_in_workspace() -> LoadedWorkspace {
    let codec = CanonicalPackageCodec::new();
    let lockfile = codec
        .decode_lockfile(WORKSPACE_LOCKFILE, lockfile_limits(), &never_cancelled)
        .expect("checked-in time-scalar lockfile");
    let root = lockfile
        .packages
        .iter()
        .find(|package| package.identity == lockfile.root)
        .expect("locked time-scalar root");
    let core = lockfile
        .packages
        .iter()
        .find(|package| package.identity.name.as_str() == "wrela-core")
        .expect("locked core package");
    let provider = CheckedInProvider {
        bundles: vec![
            PackageBundle {
                identity: root.identity.clone(),
                locator: root.locator.clone(),
                manifest_bytes: WORKSPACE_MANIFEST.to_vec(),
                sources: vec![
                    source_input("conformance/duration_scalar_test.wr", PASSING_TEST_SOURCE),
                    source_input("conformance/image.wr", IMAGE_SOURCE),
                ],
                scenarios: Vec::new(),
            },
            PackageBundle {
                identity: core.identity.clone(),
                locator: core.locator.clone(),
                manifest_bytes: CORE_MANIFEST.to_vec(),
                sources: vec![
                    source_input("image.wr", CORE_IMAGE_SOURCE),
                    source_input("ops.wr", CORE_OPS_SOURCE),
                    source_input("result.wr", CORE_RESULT_SOURCE),
                    source_input("time.wr", CORE_TIME_SOURCE),
                ],
                scenarios: Vec::new(),
            },
        ],
    };
    CanonicalWorkspaceLoader::new()
        .load(
            LoadRequest {
                root_locator: PackageLocator::Workspace {
                    path: ".".to_owned(),
                },
                root_manifest_bytes: WORKSPACE_MANIFEST,
                lockfile_bytes: WORKSPACE_LOCKFILE,
                provider: &provider,
                hasher: &HASHER,
                codec: &codec,
                limits: LoadLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("production loader seals checked-in time-scalar workspace")
}

fn analyze(
    fixture: &SourceFixture,
    selection: TestDiscoverySelection<'_>,
) -> wrela_sema::AnalysisOutput {
    analyze_with(
        fixture,
        selection,
        AnalysisLimits::standard(),
        &never_cancelled,
    )
    .expect("time-scalar semantic analysis")
}

fn analyze_with(
    fixture: &SourceFixture,
    selection: TestDiscoverySelection<'_>,
    limits: AnalysisLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<wrela_sema::AnalysisOutput, AnalysisFailure> {
    let (build, target) = analysis_build(fixture);
    CanonicalSemanticAnalyzer::new().analyze(
        AnalysisRequest {
            hir: Arc::clone(&fixture.hir),
            standard_library_package: wrela_package::PackageId(1),
            target: target.semantic(),
            build: &build,
            mode: AnalysisMode::DiscoverTests {
                image_name: "stdlib-time-scalar-conformance",
                image_entry: fixture.entry,
                declared_image_tests: &[],
                source_selection: selection,
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

fn analysis_build(
    fixture: &SourceFixture,
) -> (
    wrela_build_model::ValidatedBuildConfiguration,
    TargetPackage,
) {
    let profile_digest = Sha256Digest::from_bytes([0x86; 32]);
    let target_digest = Sha256Digest::from_bytes([0x87; 32]);
    let build = seal_build_configuration(
        BuildConfiguration {
            identity: BuildIdentity {
                compiler: Sha256Digest::from_bytes([0x88; 32]),
                language: wrela_build_model::LanguageRevision::Design0_1,
                target: TargetIdentity::aarch64_qemu_virt_uefi(),
                target_package: target_digest,
                standard_library: Sha256Digest::from_bytes([0x89; 32]),
                source_graph: fixture.root_identity.source_digest,
                request: Sha256Digest::from_bytes([0x8a; 32]),
                profile: profile_digest,
            },
            profile: fixture.profile.clone(),
        },
        profile_digest,
    )
    .expect("time-scalar build configuration");
    (build, TargetPackage::aarch64_qemu_virt_uefi(target_digest))
}

fn add_source(
    sources: &mut SourceDatabase,
    path: &str,
    text: &str,
    digest_byte: u8,
) -> wrela_source::FileId {
    sources
        .add(SourceInput {
            path: path.to_owned(),
            text: text.to_owned(),
            digest: Sha256Digest::from_bytes([digest_byte; 32]),
        })
        .expect("bounded time-scalar source")
}

fn source_input(path: &str, text: &str) -> SourceInput {
    SourceInput {
        path: path.to_owned(),
        text: text.to_owned(),
        digest: HASHER.sha256(text.as_bytes()),
    }
}

fn content_record<'a>(path: &'a str, source: &str) -> PackageContentRecord<'a> {
    PackageContentRecord {
        kind: PackageContentKind::Source,
        path,
        digest: HASHER.sha256(source.as_bytes()),
    }
}

fn source_span(file: u32, source: &str, needle: &[u8]) -> String {
    let source = source.as_bytes();
    let mut matches = source
        .windows(needle.len())
        .enumerate()
        .filter_map(|(offset, candidate)| (candidate == needle).then_some(offset));
    let start = matches.next().expect("source span is present");
    assert!(matches.next().is_none(), "source span is unique");
    format!("{file}:{start}-{}", start + needle.len())
}

fn source_span_nth(file: u32, source: &str, needle: &[u8], nth: usize) -> String {
    let source = source.as_bytes();
    let start = source
        .windows(needle.len())
        .enumerate()
        .filter_map(|(offset, candidate)| (candidate == needle).then_some(offset))
        .nth(nth)
        .expect("requested source span is present");
    format!("{file}:{start}-{}", start + needle.len())
}

fn manifest_limits() -> ManifestCodecLimits {
    ManifestCodecLimits {
        bytes: 1024 * 1024,
        string_bytes: 1024 * 1024,
        modules: 16,
        dependencies: 16,
        profiles: 16,
        images: 16,
        image_tests: 16,
    }
}

fn lockfile_limits() -> LockfileCodecLimits {
    LockfileCodecLimits {
        bytes: 1024 * 1024,
        string_bytes: 1024 * 1024,
        packages: 16,
        dependencies: 16,
    }
}

fn never_cancelled() -> bool {
    false
}
