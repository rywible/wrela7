#![forbid(unsafe_code)]

use std::cell::Cell;
use std::sync::Arc;

use wrela_backend::{
    CodegenError, emit_prepared_object, llvm_backend_available,
    machine_wir::{CheckedIntegerOp, MachineImmediate, MachineOperation},
    prepare_canonical_frame_for_codegen,
};
use wrela_build_model::{
    BuildConfiguration, BuildIdentity, BuildProfile, LanguageRevision, Sha256Digest,
    TargetIdentity, seal_build_configuration,
};
use wrela_flow_lower::{
    CanonicalFlowLowerer, FlowBinaryOp, FlowLowerer, FlowOperation, LowerError as FlowLowerError,
    LowerRequest as FlowLowerRequest, LoweringLimits as FlowLoweringLimits,
};
use wrela_flow_wir_codec::{CanonicalFlowWirCodec, CodecLimits, EncodeRequest, encode_and_verify};
use wrela_hir_lower::{
    CanonicalHirLowerer, ChangeSet as HirChangeSet, HirLowerer, LowerRequest as HirLowerRequest,
    LoweringLimits as HirLoweringLimits,
};
use wrela_package::{
    DependencyAlias, ModulePath, PackageGraphBuilder, PackageIdentity, PackageName, PackageVersion,
};
use wrela_package_loader::{
    CanonicalPackageCodec, ContentHasher, ManifestCodecLimits, PackageCodec, PackageContentKind,
    PackageContentRecord, SoftwareSha256, package_content_digest,
};
use wrela_sema::{
    AnalysisChangeSet, AnalysisLimits, AnalysisMode, AnalysisRequest, CanonicalSemanticAnalyzer,
    SemanticAnalyzer, TestDiscoverySelection,
};
use wrela_semantic_lower::{
    CanonicalSemanticLowerer, LowerRequest as SemanticLowerRequest, LoweredSemanticStatement,
    LoweringLimits as SemanticLoweringLimits, SemanticArithmeticMode, SemanticLowerer,
    SemanticOperation,
    semantic_wir::{BinaryOperator as SemanticBinaryOperator, SemanticRegion},
};
use wrela_source::{FileId, SourceDatabase, SourceInput};
use wrela_syntax::{ParseLimits, ParseRequest, SyntaxParser, WrelaSyntaxParser};
use wrela_target::TargetPackage;
use wrela_test_model::{LanguageFatalCause, TestId, TestKind};

const WORKSPACE_MANIFEST: &[u8] =
    include_bytes!("../../../std/examples/checked-shift-runtime/wrela.toml");
const APPLICATION_SOURCE: &str =
    include_str!("../../../std/examples/checked-shift-runtime/src/checked_shift/image.wr");
const CORE_MANIFEST: &[u8] = include_bytes!("../../../std/wrela-core-0.1/wrela.toml");
const CORE_IMAGE_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/image.wr");
const CORE_OPS_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/ops.wr");
const CORE_RESULT_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/result.wr");
const CORE_OPTION_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/option.wr");
const CORE_PANIC_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/panic.wr");
const CORE_TIME_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/time.wr");

static HASHER: SoftwareSha256 = SoftwareSha256;

fn identity(name: &str, digest: Sha256Digest) -> PackageIdentity {
    PackageIdentity {
        name: PackageName::new(name).expect("package name"),
        version: PackageVersion::new("0.1.0").expect("package version"),
        source_digest: digest,
    }
}

fn never_cancelled() -> bool {
    false
}

fn expected_runtime_assertions(selector: &str) -> Vec<(&'static str, Option<&'static str>)> {
    match selector {
        "checked_shift_passes" => vec![
            (
                "value == 8",
                Some("checked shift must produce the exact target-width result"),
            ),
            (
                "value == 8",
                Some("helper must observe the checked shift result"),
            ),
        ],
        "runtime_assertion_fails" => vec![("false", Some("intentional runtime assertion failure"))],
        "checked_shift_result_loss" | "invalid_shift_count" => Vec::new(),
        _ => panic!("unknown checked-shift selector {selector}"),
    }
}

fn collect_semantic_shifts(
    region: &SemanticRegion,
    sources: &SourceDatabase,
    application_file: FileId,
    shifts: &mut Vec<(SemanticArithmeticMode, String)>,
) {
    for statement in &region.statements {
        match statement {
            LoweredSemanticStatement::Let(statement) => {
                let SemanticOperation::Binary {
                    operator: SemanticBinaryOperator::ShiftLeft,
                    arithmetic,
                    ..
                } = &statement.operation
                else {
                    continue;
                };
                let Some(source) = statement
                    .source
                    .filter(|source| source.file == application_file)
                else {
                    continue;
                };
                shifts.push((
                    *arithmetic,
                    sources
                        .span_text(source)
                        .expect("source shift spelling")
                        .to_owned(),
                ));
            }
            LoweredSemanticStatement::If {
                then_region,
                else_region,
                ..
            } => {
                collect_semantic_shifts(then_region, sources, application_file, shifts);
                collect_semantic_shifts(else_region, sources, application_file, shifts);
            }
            LoweredSemanticStatement::Match { arms, .. } => {
                for arm in arms {
                    collect_semantic_shifts(&arm.body, sources, application_file, shifts);
                }
            }
            LoweredSemanticStatement::Loop { body, .. } => {
                collect_semantic_shifts(body, sources, application_file, shifts);
            }
            LoweredSemanticStatement::Return(_)
            | LoweredSemanticStatement::Yield(_)
            | LoweredSemanticStatement::Break(_)
            | LoweredSemanticStatement::Continue(_)
            | LoweredSemanticStatement::Unreachable => {}
        }
    }
}

fn canonical_workspace() -> (wrela_package::PackageManifest, PackageIdentity) {
    let codec = CanonicalPackageCodec::new();
    let manifest = codec
        .decode_manifest(WORKSPACE_MANIFEST, manifest_limits(), &never_cancelled)
        .expect("checked-in checked-shift manifest");
    // The checked-in manifest declares only `[[profile]]` overrides and no
    // `[[module]]` block (modules are derived by the loader, not decoded
    // here), so it need not be byte-identical to its own canonical
    // re-encoding; every digest below binds the canonical bytes, exactly as
    // the production loader does.
    let canonical_manifest = codec
        .canonical_manifest(&manifest, manifest_limits(), &never_cancelled)
        .expect("canonical checked-shift manifest");
    assert_eq!(
        codec
            .decode_manifest(&canonical_manifest, manifest_limits(), &never_cancelled)
            .expect("redecode canonical checked-shift manifest"),
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
            &[content_record("checked_shift/image.wr", APPLICATION_SOURCE)],
            &HASHER,
            &never_cancelled,
        )
        .expect("checked-shift package identity"),
    };
    // There is no lockfile to cross-check against; computing the core
    // package's identity here still exercises that its checked-in manifest
    // and sources hash without error, exactly as the loader itself would
    // independently do when it resolves the reserved `core` alias via the
    // toolchain rather than a recorded locator.
    let _core_identity = PackageIdentity {
        name: core_manifest.name.clone(),
        version: core_manifest.version.clone(),
        source_digest: package_content_digest(
            &canonical_core_manifest,
            &[
                content_record("image.wr", CORE_IMAGE_SOURCE),
                content_record("ops.wr", CORE_OPS_SOURCE),
                content_record("option.wr", CORE_OPTION_SOURCE),
                content_record("panic.wr", CORE_PANIC_SOURCE),
                content_record("result.wr", CORE_RESULT_SOURCE),
                content_record("time.wr", CORE_TIME_SOURCE),
            ],
            &HASHER,
            &never_cancelled,
        )
        .expect("core package identity"),
    };
    (manifest, root_identity)
}

fn content_record<'a>(path: &'a str, source: &str) -> PackageContentRecord<'a> {
    PackageContentRecord {
        kind: PackageContentKind::Source,
        path,
        digest: HASHER.sha256(source.as_bytes()),
    }
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

#[test]
fn checked_in_runtime_fixture_is_canonical_and_has_four_exact_selectors() {
    let (manifest, _root_identity) = canonical_workspace();
    assert_eq!(manifest.name.as_str(), "checked-shift-runtime");
    assert_eq!(manifest.version.as_str(), "0.1.0");
    assert_eq!(manifest.images.len(), 1);
    assert_eq!(manifest.images[0].name, "checked-shift-runtime");
    assert_eq!(manifest.images[0].module.dotted(), "checked_shift.image");
    assert_eq!(manifest.images[0].entry, "boot");

    for name in [
        "checked_shift_passes",
        "runtime_assertion_fails",
        "checked_shift_result_loss",
        "invalid_shift_count",
    ] {
        assert_eq!(
            APPLICATION_SOURCE.matches(&format!("fn {name}():")).count(),
            1,
            "selector {name:?} must name exactly one source test",
        );
    }
    assert!(APPLICATION_SOURCE.contains("return left << count"));
}

#[test]
fn source_checked_left_shifts_reach_distinct_semantic_and_flow_operations() {
    let source_graph_digest = Sha256Digest::from_bytes([0x91; 32]);
    let core_package_digest = Sha256Digest::from_bytes([0x92; 32]);
    let target_digest = Sha256Digest::from_bytes([0x93; 32]);
    let mut sources = SourceDatabase::default();
    let application_file = sources
        .add(SourceInput {
            path: "checked_shift/image.wr".to_owned(),
            text: APPLICATION_SOURCE.to_owned(),
            digest: Sha256Digest::from_bytes([0x94; 32]),
        })
        .expect("application source");
    let core_file = sources
        .add(SourceInput {
            path: "core/image.wr".to_owned(),
            text: CORE_IMAGE_SOURCE.to_owned(),
            digest: Sha256Digest::from_bytes([0x95; 32]),
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
        "checked-shift-runtime",
        Sha256Digest::from_bytes([0x96; 32]),
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
            ModulePath::new(["checked_shift".to_owned(), "image".to_owned()])
                .expect("application module"),
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
    let image_entry = *hir_output
        .lowered()
        .program()
        .as_program()
        .image_candidates
        .first()
        .expect("image entry candidate");
    let hir = Arc::new(hir_output.into_parts().0.into_program());

    let profile = BuildProfile::development();
    let profile_digest = Sha256Digest::from_bytes([0x97; 32]);
    let build = seal_build_configuration(
        BuildConfiguration {
            identity: BuildIdentity {
                compiler: Sha256Digest::from_bytes([0x98; 32]),
                language: LanguageRevision::Design0_1,
                target: TargetIdentity::aarch64_qemu_virt_uefi(),
                target_package: target_digest,
                standard_library: Sha256Digest::from_bytes([0x99; 32]),
                source_graph: source_graph_digest,
                request: Sha256Digest::from_bytes([0x9a; 32]),
                profile: profile_digest,
            },
            profile,
        },
        profile_digest,
    )
    .expect("validated build configuration");
    let target = TargetPackage::aarch64_qemu_virt_uefi(target_digest);
    let analysis_changes = AnalysisChangeSet {
        previous_source_graph: None,
        changed_declarations: Vec::new(),
    };
    let analyzer = CanonicalSemanticAnalyzer::new();
    let cases = [
        (
            "checked_shift_passes",
            Some((
                SemanticArithmeticMode::Checked,
                FlowBinaryOp::ShiftLeftChecked,
                CheckedIntegerOp::ShiftLeft,
            )),
            None,
        ),
        ("runtime_assertion_fails", None, None),
        (
            "checked_shift_result_loss",
            Some((
                SemanticArithmeticMode::Checked,
                FlowBinaryOp::ShiftLeftChecked,
                CheckedIntegerOp::ShiftLeft,
            )),
            Some(LanguageFatalCause::CheckedShiftResultLoss),
        ),
        (
            "invalid_shift_count",
            Some((
                SemanticArithmeticMode::Checked,
                FlowBinaryOp::ShiftLeftChecked,
                CheckedIntegerOp::ShiftLeft,
            )),
            Some(LanguageFatalCause::InvalidShiftCount),
        ),
    ];

    for (case_index, (selector, shift, expected_fatal)) in cases.into_iter().enumerate() {
        let discovery = analyzer
            .analyze(
                AnalysisRequest {
                    hir: Arc::clone(&hir),
                    standard_library_package: wrela_package::PackageId(1),
                    target: target.semantic(),
                    build: &build,
                    mode: AnalysisMode::DiscoverTests {
                        image_name: "checked-shift-runtime",
                        image_entry,
                        declared_image_tests: &[],
                        source_selection: TestDiscoverySelection::NameContains(selector),
                    },
                    changes: &analysis_changes,
                    limits: AnalysisLimits::standard(),
                },
                &never_cancelled,
            )
            .unwrap_or_else(|error| panic!("{selector} test discovery failed: {error}"));
        assert!(
            discovery.diagnostics().is_empty(),
            "{selector} discovery diagnostics: {:?}",
            discovery.diagnostics()
        );
        let plan = discovery
            .successful()
            .and_then(|image| image.facts().test_plan.as_ref())
            .unwrap_or_else(|| panic!("{selector} source test plan"))
            .clone();
        assert!(plan.unit_tests().is_empty());
        let [group] = plan.image_groups() else {
            panic!("{selector} must produce exactly one image group");
        };
        let [selected] = group.tests.as_slice() else {
            panic!("{selector} must select exactly one runtime test");
        };
        assert_eq!(selected.descriptor.id, TestId(0));
        assert_eq!(selected.descriptor.kind, TestKind::IntegrationImage);
        assert_eq!(selected.descriptor.timeout_ns, 30_000_000_000);
        assert_eq!(
            selected.descriptor.name,
            format!("checked-shift-runtime@0.1.0::checked_shift.image::{selector}")
        );
        let planned_assertions = selected
            .assertions
            .iter()
            .map(|assertion| {
                assert_eq!(
                    sources
                        .span_text(assertion.source)
                        .expect("planned assertion source"),
                    assertion.expression
                );
                (assertion.expression.as_str(), assertion.message.as_deref())
            })
            .collect::<Vec<_>>();
        assert_eq!(planned_assertions, expected_runtime_assertions(selector));
        assert_eq!(group.maximum_events, 5);

        let compilation = analyzer
            .analyze(
                AnalysisRequest {
                    hir: Arc::clone(&hir),
                    standard_library_package: wrela_package::PackageId(1),
                    target: target.semantic(),
                    build: &build,
                    mode: AnalysisMode::CompileTestGroup {
                        plan: &plan,
                        group: group.id,
                        declared_entry: None,
                    },
                    changes: &analysis_changes,
                    limits: AnalysisLimits::standard(),
                },
                &never_cancelled,
            )
            .unwrap_or_else(|error| panic!("{selector} semantic analysis failed: {error}"));
        assert!(
            compilation.diagnostics().is_empty(),
            "{selector} semantic diagnostics: {:?}",
            compilation.diagnostics()
        );
        let analyzed = compilation
            .into_parts()
            .0
            .expect("sealed selected checked-shift test image");

        let semantic = CanonicalSemanticLowerer::new()
            .lower(
                SemanticLowerRequest {
                    input: analyzed,
                    limits: SemanticLoweringLimits::standard(),
                },
                &never_cancelled,
            )
            .unwrap_or_else(|error| panic!("{selector} SemanticWir lowering failed: {error}"));
        let mut semantic_shifts = Vec::new();
        for function in &semantic.wir().as_wir().functions {
            collect_semantic_shifts(
                &function.body,
                &sources,
                application_file,
                &mut semantic_shifts,
            );
        }
        let expected_semantic_shifts = shift
            .map(|(mode, _, _)| {
                vec![(
                    mode,
                    match mode {
                        SemanticArithmeticMode::Checked => "left << count",
                        SemanticArithmeticMode::Wrapping => "left <<% count",
                    }
                    .to_owned(),
                )]
            })
            .unwrap_or_default();
        assert_eq!(semantic_shifts, expected_semantic_shifts);
        let semantic_assertions = semantic
            .wir()
            .as_wir()
            .functions
            .iter()
            .flat_map(|function| &function.body.statements)
            .filter_map(|statement| {
                let LoweredSemanticStatement::Let(statement) = statement else {
                    return None;
                };
                let SemanticOperation::Assert { failure, .. } = &statement.operation else {
                    return None;
                };
                assert_eq!(statement.source, Some(failure.source));
                assert_eq!(
                    sources
                        .span_text(failure.source)
                        .expect("SemanticWir assertion source"),
                    failure.expression
                );
                Some((failure.expression.as_str(), failure.message.as_deref()))
            })
            .collect::<Vec<_>>();
        assert_eq!(semantic_assertions, expected_runtime_assertions(selector));

        let (semantic_wir, _) = semantic.into_parts();
        let flow = CanonicalFlowLowerer::new()
            .lower(
                FlowLowerRequest {
                    input: semantic_wir.clone(),
                    limits: FlowLoweringLimits::standard(),
                },
                &never_cancelled,
            )
            .unwrap_or_else(|error| panic!("{selector} FlowWir lowering failed: {error}"));
        assert!(
            flow.diagnostics().is_empty(),
            "{selector} FlowWir diagnostics: {:?}",
            flow.diagnostics()
        );
        let mut flow_shifts = Vec::new();
        for function in &flow.wir().as_wir().functions {
            for block in &function.blocks {
                for instruction in &block.instructions {
                    let FlowOperation::Binary {
                        op: op @ (FlowBinaryOp::ShiftLeftChecked | FlowBinaryOp::ShiftLeftWrapping),
                        ..
                    } = &instruction.operation
                    else {
                        continue;
                    };
                    let Some(source) = instruction
                        .source
                        .filter(|source| source.file == application_file)
                    else {
                        continue;
                    };
                    flow_shifts.push((
                        *op,
                        sources
                            .span_text(source)
                            .expect("Flow shift spelling")
                            .to_owned(),
                    ));
                }
            }
        }
        let expected_flow_shifts = shift
            .map(|(_, op, _)| {
                vec![(
                    op,
                    match op {
                        FlowBinaryOp::ShiftLeftChecked => "left << count",
                        FlowBinaryOp::ShiftLeftWrapping => "left <<% count",
                        _ => unreachable!("case table admits only left shifts"),
                    }
                    .to_owned(),
                )]
            })
            .unwrap_or_default();
        assert_eq!(flow_shifts, expected_flow_shifts);
        let flow_assertions = flow
            .wir()
            .as_wir()
            .functions
            .iter()
            .flat_map(|function| &function.blocks)
            .flat_map(|block| &block.instructions)
            .filter_map(|instruction| {
                let FlowOperation::Assert { failure, .. } = &instruction.operation else {
                    return None;
                };
                assert_eq!(instruction.source, Some(failure.source));
                assert_eq!(
                    sources
                        .span_text(failure.source)
                        .expect("FlowWir assertion source"),
                    failure.expression
                );
                Some((failure.expression.as_str(), failure.message.as_deref()))
            })
            .collect::<Vec<_>>();
        assert_eq!(flow_assertions, expected_runtime_assertions(selector));

        let report = flow.report().clone();
        let mut exact_limits = FlowLoweringLimits::standard();
        // Every selector's body ends in a bounded `guard: u32 = 0; while guard
        // < 1: guard += 1` marker (see the long comment on
        // checked_shift/image.wr's boot() function... actually see
        // std/examples/checked-shift-runtime/src/checked_shift/image.wr):
        // that marker is what forces the test out of the comptime tier (a
        // bounded while is unsupported by the static comptime checker but
        // fully supported by the runtime-shape checker). Its FlowWir lowering
        // reserves one more block than the report's final trimmed count, so
        // the tight resource bound below needs a `+ 1` fudge that a
        // marker-free body would not.
        exact_limits.blocks = report.blocks + 1;
        exact_limits.instructions = report.instructions;
        CanonicalFlowLowerer::new()
            .lower(
                FlowLowerRequest {
                    input: semantic_wir.clone(),
                    limits: exact_limits,
                },
                &never_cancelled,
            )
            .unwrap_or_else(|error| panic!("{selector} exact FlowWir bounds failed: {error}"));
        assert!(report.instructions > 1);
        let mut one_instruction_under = exact_limits;
        one_instruction_under.instructions -= 1;
        assert_eq!(
            CanonicalFlowLowerer::new().lower(
                FlowLowerRequest {
                    input: semantic_wir.clone(),
                    limits: one_instruction_under,
                },
                &never_cancelled,
            ),
            Err(FlowLowerError::ResourceLimit {
                resource: "FlowWir instructions",
                limit: one_instruction_under.instructions,
            }),
            "{selector} must fail closed one instruction below its real producer bound"
        );

        if case_index == 0 {
            let successful_polls = Cell::new(0_u32);
            CanonicalFlowLowerer::new()
                .lower(
                    FlowLowerRequest {
                        input: semantic_wir.clone(),
                        limits: exact_limits,
                    },
                    &|| {
                        successful_polls.set(successful_polls.get().saturating_add(1));
                        false
                    },
                )
                .expect("counted checked-shift FlowWir lowering");
            let cancel_at = successful_polls.get().saturating_sub(1);
            assert!(cancel_at > 1);
            let cancelled_polls = Cell::new(0_u32);
            let cancelled = CanonicalFlowLowerer::new().lower(
                FlowLowerRequest {
                    input: semantic_wir.clone(),
                    limits: exact_limits,
                },
                &|| {
                    let next = cancelled_polls.get().saturating_add(1);
                    cancelled_polls.set(next);
                    next == cancel_at
                },
            );
            assert_eq!(cancelled, Err(FlowLowerError::Cancelled));
            assert_eq!(cancelled_polls.get(), cancel_at);
        }

        let (flow_wir, _, _) = flow.into_parts();
        let encoded = encode_and_verify(
            &CanonicalFlowWirCodec,
            EncodeRequest {
                wir: &flow_wir,
                limits: CodecLimits::standard(),
            },
            &never_cancelled,
        )
        .unwrap_or_else(|error| panic!("{selector} canonical FlowWir frame failed: {error}"));
        assert!(!encoded.bytes().is_empty());
        let prepared =
            prepare_canonical_frame_for_codegen(encoded.bytes(), &target, &build, &never_cancelled)
                .unwrap_or_else(|error| panic!("{selector} backend preparation failed: {error}"));

        let mut optimized_shifts = Vec::new();
        for function in &prepared.optimized().wir().as_wir().functions {
            for block in &function.blocks {
                for instruction in &block.instructions {
                    let FlowOperation::Binary {
                        op: op @ (FlowBinaryOp::ShiftLeftChecked | FlowBinaryOp::ShiftLeftWrapping),
                        ..
                    } = &instruction.operation
                    else {
                        continue;
                    };
                    if matches!(instruction.source, Some(source) if source.file == application_file)
                    {
                        optimized_shifts.push(*op);
                    }
                }
            }
        }
        assert_eq!(
            optimized_shifts,
            shift.map(|(_, op, _)| vec![op]).unwrap_or_default()
        );

        let machine = prepared.machine().wir().as_wir();
        let machine_assertions = machine
            .functions
            .iter()
            .flat_map(|function| &function.blocks)
            .flat_map(|block| &block.instructions)
            .filter_map(|instruction| {
                let MachineOperation::TestAssert { failure, .. } = &instruction.operation else {
                    return None;
                };
                assert_eq!(instruction.source, Some(failure.source));
                assert_eq!(
                    sources
                        .span_text(failure.source)
                        .expect("MachineWir assertion source"),
                    failure.expression
                );
                for (global_id, text) in
                    std::iter::once((failure.expression_global, failure.expression.as_str()))
                        .chain(failure.message_global.zip(failure.message.as_deref()))
                {
                    let global = machine
                        .globals
                        .get(global_id.0 as usize)
                        .expect("assertion global");
                    let MachineImmediate::Bytes(bytes) = &global.initializer else {
                        panic!("assertion storage must be first-class bytes");
                    };
                    assert_eq!(bytes.len(), 4096);
                    assert_eq!(&bytes[..text.len()], text.as_bytes());
                    assert!(bytes[text.len()..].iter().all(|byte| *byte == 0));
                }
                Some((failure.expression.as_str(), failure.message.as_deref()))
            })
            .collect::<Vec<_>>();
        assert_eq!(machine_assertions, expected_runtime_assertions(selector));
        assert_eq!(
            machine
                .runtime
                .intrinsics
                .iter()
                .any(|intrinsic| intrinsic.symbol_name() == "wrela_rt_v2_test_assertion_fail"),
            !machine_assertions.is_empty()
        );
        let machine_shifts = machine
            .functions
            .iter()
            .flat_map(|function| &function.blocks)
            .flat_map(|block| &block.instructions)
            .filter_map(|instruction| {
                let MachineOperation::CheckedInteger {
                    op: op @ (CheckedIntegerOp::ShiftLeft | CheckedIntegerOp::ShiftLeftWrapping),
                    ..
                } = &instruction.operation
                else {
                    // Every selector's body ends in a bounded `while guard <
                    // 1: guard += 1` marker (the mechanism that forces it out
                    // of the comptime tier); its `+= 1` also lowers to a
                    // `CheckedInteger::Add` in this same function, which this
                    // exercise is not about, so only the shift variants are
                    // collected here.
                    return None;
                };
                matches!(instruction.source, Some(source) if source.file == application_file)
                    .then_some(*op)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            machine_shifts,
            shift.map(|(_, _, op)| vec![op]).unwrap_or_default()
        );
        if let Some((_, _, machine_op)) = shift {
            assert_eq!(
                machine_op
                    .invalid_shift_count_fatal_code()
                    .expect("left shifts check their count")
                    .as_u32(),
                6
            );
            match machine_op {
                CheckedIntegerOp::ShiftLeft => assert_eq!(
                    machine_op
                        .result_loss_fatal_code()
                        .expect("checked left shift checks result loss")
                        .as_u32(),
                    5
                ),
                CheckedIntegerOp::ShiftLeftWrapping => {
                    assert_eq!(machine_op.result_loss_fatal_code(), None)
                }
                _ => unreachable!("case table admits only left shifts"),
            }
            match expected_fatal {
                Some(LanguageFatalCause::CheckedShiftResultLoss) => assert_eq!(
                    machine_op
                        .result_loss_fatal_code()
                        .map(|code| code.as_u32()),
                    Some(5)
                ),
                Some(LanguageFatalCause::InvalidShiftCount) => assert_eq!(
                    machine_op
                        .invalid_shift_count_fatal_code()
                        .map(|code| code.as_u32()),
                    Some(6)
                ),
                None => {}
            }
        } else {
            assert_eq!(expected_fatal, None);
        }

        if case_index == 0 {
            let successful_polls = Cell::new(0_u32);
            prepare_canonical_frame_for_codegen(encoded.bytes(), &target, &build, &|| {
                successful_polls.set(successful_polls.get().saturating_add(1));
                false
            })
            .expect("counted checked-shift backend preparation");
            let cancel_at = successful_polls.get().saturating_sub(1);
            assert!(cancel_at > 1);
            let cancelled_polls = Cell::new(0_u32);
            let error =
                prepare_canonical_frame_for_codegen(encoded.bytes(), &target, &build, &|| {
                    let next = cancelled_polls.get().saturating_add(1);
                    cancelled_polls.set(next);
                    next == cancel_at
                })
                .expect_err("late cancellation must not publish checked-shift MachineWir");
            assert!(error.is_cancelled());
            assert_eq!(cancelled_polls.get(), cancel_at);
        }

        match emit_prepared_object(&prepared, &target, &never_cancelled) {
            Err(CodegenError::BackendNotBuilt) if !llvm_backend_available() => {}
            Err(CodegenError::BackendNotBuilt) => {
                panic!("LLVM reports available but rejected {selector} native emission")
            }
            Err(error) => panic!("{selector} MachineWir failed native codegen: {error}"),
            Ok(_) if !llvm_backend_available() => {
                panic!("{selector} emitted a native object while LLVM reports unavailable")
            }
            Ok(first) => {
                let second = emit_prepared_object(&prepared, &target, &never_cancelled)
                    .unwrap_or_else(|error| panic!("repeated {selector} emission failed: {error}"));
                assert_eq!(first, second);
                assert_eq!(first.bytes().get(..2), Some([0x64, 0xaa].as_slice()));
            }
        }
    }
}
