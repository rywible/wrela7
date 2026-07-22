#![forbid(unsafe_code)]

use std::cell::Cell;
use std::sync::Arc;

use wrela_backend::{
    CodegenError, emit_prepared_object, llvm_backend_available,
    machine_wir::{
        CheckedIntegerOp, ConversionOp, MachineOperation, MachineTerminator, MachineTypeKind,
    },
    prepare_canonical_frame_for_codegen,
};
use wrela_build_model::{
    BuildConfiguration, BuildIdentity, BuildProfile, LanguageRevision, Sha256Digest,
    TargetIdentity, seal_build_configuration,
};
use wrela_flow_lower::{
    CanonicalFlowLowerer, FlowBinaryOp, FlowLowerer, FlowOperation, FlowTypeId, FlowTypeKind,
    LowerError as FlowLowerError, LowerRequest as FlowLowerRequest,
    LoweringLimits as FlowLoweringLimits, Terminator,
};
use wrela_flow_wir_codec::{
    CanonicalFlowWirCodec, CodecLimits, DecodeRequest, EncodeRequest, FlowWirCodec,
    encode_and_verify,
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
    AnalyzedImage, CanonicalSemanticAnalyzer, SemanticAnalyzer, SemanticTypeKind,
    TestDiscoverySelection,
};
use wrela_semantic_lower::{
    CanonicalSemanticLowerer, LowerError as SemanticLowerError,
    LowerRequest as SemanticLowerRequest, LoweredSemanticStatement,
    LoweringLimits as SemanticLoweringLimits, SemanticArithmeticMode, SemanticLowerer,
    SemanticOperation, SemanticTypeId, SemanticTypeKind as LoweredSemanticTypeKind,
};
use wrela_source::{SourceDatabase, SourceInput};
use wrela_syntax::{ParseLimits, ParseRequest, SyntaxParser, WrelaSyntaxParser};
use wrela_target::TargetPackage;
use wrela_test_model::ValidatedTestPlan;

const CORE_IMAGE_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/image.wr");
const IMAGE_SOURCE: &str = r#"module app.image

from core.image import Image, Target

@image
pub fn boot() -> Image:
    return Image(name="flat-duration-image", target=Target.aarch64_qemu_virt_uefi)
"#;

const DURATION_SOURCE: &str = r#"module app.duration

pub struct RuntimeDurationRepresentation:
    pub nanoseconds: u64

pub fn nanoseconds(value: u64) -> RuntimeDurationRepresentation:
    return RuntimeDurationRepresentation(nanoseconds=value)

pub fn microseconds(value: u64) -> RuntimeDurationRepresentation:
    return nanoseconds(value * 1000)

pub fn milliseconds(value: u64) -> RuntimeDurationRepresentation:
    return nanoseconds(value * 1000000)

pub fn seconds(value: u64) -> RuntimeDurationRepresentation:
    return nanoseconds(value * 1000000000)

pub fn copied(value: RuntimeDurationRepresentation) -> RuntimeDurationRepresentation:
    return copy value

pub fn as_nanoseconds(value: RuntimeDurationRepresentation) -> u64:
    return value.nanoseconds
"#;

const TEST_SOURCE: &str = r#"module app.duration_test

from app.duration import as_nanoseconds, copied, microseconds, milliseconds, nanoseconds, seconds

@test(runtime)
fn imported_duration_constructors_reach_flow():
    nanos: u64 = as_nanoseconds(nanoseconds(42))
    copied_nanos: u64 = as_nanoseconds(copied(nanoseconds(42)))
    micros: u64 = as_nanoseconds(microseconds(42))
    millis: u64 = as_nanoseconds(milliseconds(42))
    secs: u64 = as_nanoseconds(seconds(42))
    # `@test(runtime)` keeps this in the runtime/image tier.
    return
"#;

const MUTATION_SOURCE: &str = r#"module app.duration

pub struct RuntimeDurationRepresentation:
    pub nanoseconds: u64

pub fn replace_nanoseconds(value: u64) -> u64:
    duration: RuntimeDurationRepresentation = RuntimeDurationRepresentation(nanoseconds=1)
    duration.nanoseconds = value
    return duration.nanoseconds
"#;

const MUTATION_TEST_SOURCE: &str = r#"module app.duration_test

from app.duration import replace_nanoseconds

@test(runtime)
fn local_field_update_reaches_native():
    updated: u64 = replace_nanoseconds(42)
    return
"#;

const INITIALIZER_SOURCE: &str = r#"module app.duration

pub struct Box:
    pub value: u64

    init(mut self, value: u64):
        self.value = value

pub fn make_box(value: u64) -> Box:
    return Box(value)

pub fn read_box(value: Box) -> u64:
    return value.value
"#;

const INITIALIZER_TEST_SOURCE: &str = r#"module app.duration_test

from app.duration import Box, make_box, read_box

@test(runtime)
fn initializer_reaches_native():
    built: Box = make_box(42)
    observed: u64 = read_box(built)
    return
"#;

const LOCAL_RESULT_SOURCE: &str = r#"module app.duration

pub enum LocalResult:
    Ok(u8,)
    Err(u8,)

pub fn ok(value: u8) -> LocalResult:
    return LocalResult.Ok(value)

pub fn err(value: u8) -> LocalResult:
    return LocalResult.Err(value)

pub fn unwrap_or_zero(value: LocalResult) -> u8:
    match value:
        case LocalResult.Ok(payload):
            return payload
        case LocalResult.Err(code):
            return 0
"#;

const LOCAL_RESULT_TEST_SOURCE: &str = r#"module app.duration_test

from app.duration import err, ok, unwrap_or_zero

@test(runtime)
fn result_ok_match_returns_payload():
    value: u8 = unwrap_or_zero(ok(42))
    return

@test(runtime)
fn result_err_match_returns_payload():
    value: u8 = unwrap_or_zero(err(7))
    return
"#;

const WIDE_STRUCTURE_SOURCE: &str = r#"module app.duration

pub struct Wide:
    pub a: u64
    pub b: u64
    pub c: u64
    pub d: u64
    pub e: u64
    pub f: u64
    pub g: u64
    pub h: u64

pub fn make(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64) -> Wide:
    return Wide(a=a, b=b, c=c, d=d, e=e, f=f, g=g, h=h)

pub fn last(value: Wide) -> u64:
    return value.h
"#;

const WIDE_STRUCTURE_TEST_SOURCE: &str = r#"module app.duration_test

from app.duration import last, make

@test(runtime)
fn imported_late_field_is_bounded():
    value: u64 = last(make(a=1, b=2, c=3, d=4, e=5, f=6, g=7, h=8))
    # `@test(runtime)` keeps this in the runtime/image tier.
    return
"#;

const NATIVE_PAIR_SOURCE: &str = r#"module app.duration

pub struct Pair:
    pub count: u32
    pub total: u64

pub fn update_and_read() -> u64:
    value: Pair = Pair(count=1, total=2)
    value.total = 9
    return value.total
"#;

const NATIVE_PAIR_TEST_SOURCE: &str = r#"module app.duration_test

from app.duration import update_and_read

@test(runtime)
fn native_pair_field_update_runs():
    value: u64 = update_and_read()
    return
"#;

const NATIVE_PAIR_JOIN_SOURCE: &str = r#"module app.duration

pub struct Pair:
    pub count: u32
    pub total: u64

pub fn update_across_branch(choose: bool) -> u64:
    value: Pair = Pair(count=1, total=2)
    if choose:
        value.total = 9
    else:
        value.total = 7
    return value.total
"#;

const NATIVE_PAIR_JOIN_TEST_SOURCE: &str = r#"module app.duration_test

from app.duration import update_across_branch

@test(runtime)
fn native_pair_survives_branch_join():
    value: u64 = update_across_branch(true)
    return
"#;

struct Fixture {
    hir: Arc<wrela_hir::ValidatedProgram>,
    target: TargetPackage,
    build: wrela_build_model::ValidatedBuildConfiguration,
    plan: Option<ValidatedTestPlan>,
    discovery_diagnostics: Vec<wrela_diagnostics::Diagnostic>,
}

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

fn fixture(duration: &str, tests: &str) -> Fixture {
    fixture_selected(duration, tests, TestDiscoverySelection::All)
}

fn fixture_selected(
    duration: &str,
    tests: &str,
    source_selection: TestDiscoverySelection<'_>,
) -> Fixture {
    let source_graph_digest = Sha256Digest::from_bytes([0xb1; 32]);
    let target_digest = Sha256Digest::from_bytes([0xb2; 32]);
    let mut sources = SourceDatabase::default();
    let source_rows = [
        ("app/duration.wr", duration, [0xb3; 32]),
        ("app/duration_test.wr", tests, [0xb4; 32]),
        ("app/image.wr", IMAGE_SOURCE, [0xb5; 32]),
        ("core/image.wr", CORE_IMAGE_SOURCE, [0xb6; 32]),
    ];
    let files = source_rows
        .iter()
        .map(|(path, text, digest)| {
            sources
                .add(SourceInput {
                    path: (*path).to_owned(),
                    text: (*text).to_owned(),
                    digest: Sha256Digest::from_bytes(*digest),
                })
                .expect("source input")
        })
        .collect::<Vec<_>>();
    let parsed_files = files
        .iter()
        .copied()
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
        "flat-duration-application",
        Sha256Digest::from_bytes([0xb7; 32]),
    ));
    let core = graph
        .add_package(identity("wrela-core", Sha256Digest::from_bytes([0xb8; 32])))
        .expect("core package");
    graph
        .add_dependency(
            graph.root(),
            DependencyAlias::new("core").expect("core alias"),
            core,
        )
        .expect("core dependency");
    for (path, file) in [
        (["app", "duration"].as_slice(), files[0]),
        (["app", "duration_test"].as_slice(), files[1]),
        (["app", "image"].as_slice(), files[2]),
    ] {
        graph
            .add_module(
                graph.root(),
                ModulePath::new(path.iter().map(|part| (*part).to_owned()))
                    .expect("application module"),
                file,
            )
            .expect("application module record");
    }
    graph
        .add_module(
            core,
            ModulePath::new(["image".to_owned()]).expect("core module"),
            files[3],
        )
        .expect("core module record");
    let changes = HirChangeSet {
        previous_source_graph: None,
        changed_files: Vec::new(),
    };
    let hir_output = CanonicalHirLowerer::new()
        .lower(
            HirLowerRequest {
                packages: Arc::new(graph.finish().expect("package graph")),
                source_graph_digest,
                parsed_files: &parsed_files,
                sources: &sources,
                changes: &changes,
                limits: HirLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("source lowers to HIR");
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
        .expect("image candidate");
    let hir = Arc::new(hir_output.into_parts().0.into_program());
    let profile = BuildProfile::development();
    let profile_digest = Sha256Digest::from_bytes([0xb9; 32]);
    let build = seal_build_configuration(
        BuildConfiguration {
            identity: BuildIdentity {
                compiler: Sha256Digest::from_bytes([0xba; 32]),
                language: LanguageRevision::Design0_1,
                target: TargetIdentity::aarch64_qemu_virt_uefi(),
                target_package: target_digest,
                standard_library: Sha256Digest::from_bytes([0xbb; 32]),
                source_graph: source_graph_digest,
                request: Sha256Digest::from_bytes([0xbc; 32]),
                profile: profile_digest,
            },
            profile,
        },
        profile_digest,
    )
    .expect("build configuration");
    let target = TargetPackage::aarch64_qemu_virt_uefi(target_digest);
    let analysis_changes = AnalysisChangeSet {
        previous_source_graph: None,
        changed_declarations: Vec::new(),
    };
    let discovery = CanonicalSemanticAnalyzer::new()
        .analyze(
            AnalysisRequest {
                hir: Arc::clone(&hir),
                standard_library_package: wrela_package::PackageId(1),
                target: target.semantic(),
                build: &build,
                mode: AnalysisMode::DiscoverTests {
                    image_name: "flat-duration-image",
                    image_entry,
                    declared_image_tests: &[],
                    source_selection,
                },
                changes: &analysis_changes,
                limits: AnalysisLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("test discovery");
    let discovery_diagnostics = discovery.diagnostics().to_vec();
    let plan = discovery
        .successful()
        .and_then(|image| image.facts().test_plan.as_ref())
        .cloned();
    Fixture {
        hir,
        target,
        build,
        plan,
        discovery_diagnostics,
    }
}

fn compile(
    fixture: &Fixture,
    limits: AnalysisLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<wrela_sema::AnalysisOutput, AnalysisFailure> {
    let changes = AnalysisChangeSet {
        previous_source_graph: None,
        changed_declarations: Vec::new(),
    };
    let plan = fixture
        .plan
        .as_ref()
        .ok_or(AnalysisFailure::RequestMismatch)?;
    CanonicalSemanticAnalyzer::new().analyze(
        AnalysisRequest {
            hir: Arc::clone(&fixture.hir),
            standard_library_package: wrela_package::PackageId(1),
            target: fixture.target.semantic(),
            build: &fixture.build,
            mode: AnalysisMode::CompileTestGroup {
                plan,
                group: plan.image_groups()[0].id,
                declared_entry: None,
            },
            changes: &changes,
            limits,
        },
        is_cancelled,
    )
}

fn analyzed(fixture: &Fixture) -> AnalyzedImage {
    assert!(
        fixture.discovery_diagnostics.is_empty(),
        "discovery diagnostics: {:?}",
        fixture.discovery_diagnostics
    );
    let output =
        compile(fixture, AnalysisLimits::standard(), &never_cancelled).expect("semantic analysis");
    assert!(
        output.diagnostics().is_empty(),
        "semantic diagnostics: {:?}",
        output.diagnostics()
    );
    output.into_parts().0.expect("sealed semantic image")
}

#[test]
fn real_imported_duration_shape_reaches_flow_and_v12_roundtrips_exactly() {
    let fixture = fixture(DURATION_SOURCE, TEST_SOURCE);
    let analyzed = analyzed(&fixture);
    let duration_ty = analyzed
        .facts()
        .types
        .iter()
        .find(|ty| {
            matches!(
                &ty.kind,
                SemanticTypeKind::Structure { fields, .. }
                    if fields.len() == 1 && fields[0].name == "nanoseconds"
            )
        })
        .expect("nominal runtime duration type")
        .id;

    let semantic = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed,
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("flat structure lowers to SemanticWir");
    let semantic_model = semantic.wir().as_wir();
    let duration_semantic_type = &semantic_model.types[duration_ty.0 as usize];
    assert_eq!(
        duration_semantic_type.source_name,
        "RuntimeDurationRepresentation"
    );
    let LoweredSemanticTypeKind::Struct { fields } = &duration_semantic_type.kind else {
        panic!("duration semantic type must be a struct");
    };
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].name, "nanoseconds");
    assert!(fields[0].public);
    let mut semantic_aggregates = 0;
    let mut semantic_copies = 0;
    let mut semantic_projects = 0;
    let mut semantic_checked_multiplies = 0;
    let mut semantic_calls = 0;
    for function in &semantic_model.functions {
        for statement in &function.body.statements {
            let LoweredSemanticStatement::Let(statement) = statement else {
                continue;
            };
            match &statement.operation {
                SemanticOperation::Aggregate { ty, fields } => {
                    assert_eq!(*ty, SemanticTypeId(duration_ty.0));
                    assert_eq!(fields.len(), 1);
                    assert_eq!(statement.results.len(), 1);
                    semantic_aggregates += 1;
                }
                SemanticOperation::Copy { .. } => {
                    assert_eq!(statement.results.len(), 1);
                    semantic_copies += 1;
                }
                SemanticOperation::Project { field, access, .. } => {
                    assert_eq!(*field, 0);
                    assert_eq!(*access, wrela_semantic_lower::SemanticAccessMode::Read);
                    assert_eq!(statement.results.len(), 1);
                    semantic_projects += 1;
                }
                SemanticOperation::Binary { arithmetic, .. }
                    if *arithmetic == SemanticArithmeticMode::Checked =>
                {
                    semantic_checked_multiplies += 1;
                }
                SemanticOperation::Call { activation, .. } => {
                    assert!(activation.is_none());
                    semantic_calls += 1;
                }
                _ => {}
            }
        }
    }
    assert_eq!(semantic_aggregates, 1);
    assert_eq!(semantic_copies, 1);
    assert_eq!(semantic_projects, 1);
    assert_eq!(semantic_checked_multiplies, 3);
    assert!(semantic_calls >= 8);

    let (semantic_wir, _) = semantic.into_parts();
    let flow = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic_wir,
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("flat structure lowers to FlowWir");
    assert!(flow.diagnostics().is_empty());
    let flow_model = flow.wir().as_wir();
    let duration_flow_type = &flow_model.types[duration_ty.0 as usize];
    assert_eq!(
        duration_flow_type.name.as_deref(),
        Some("RuntimeDurationRepresentation")
    );
    let FlowTypeKind::Struct { fields } = &duration_flow_type.kind else {
        panic!("duration Flow type must be a struct");
    };
    assert_eq!(fields.len(), 1);
    let mut flow_aggregates = 0;
    let mut flow_copies = 0;
    let mut flow_projects = 0;
    let mut flow_checked_multiplies = 0;
    let mut flow_calls = 0;
    for function in &flow_model.functions {
        for block in &function.blocks {
            for instruction in &block.instructions {
                match &instruction.operation {
                    FlowOperation::MakeAggregate { ty, fields } => {
                        assert_eq!(*ty, FlowTypeId(duration_ty.0));
                        assert_eq!(fields.len(), 1);
                        assert_eq!(instruction.results.len(), 1);
                        flow_aggregates += 1;
                    }
                    FlowOperation::Copy { .. } => {
                        assert_eq!(instruction.results.len(), 1);
                        flow_copies += 1;
                    }
                    FlowOperation::ExtractField { field, .. } => {
                        assert_eq!(*field, 0);
                        assert_eq!(instruction.results.len(), 1);
                        flow_projects += 1;
                    }
                    FlowOperation::Binary {
                        op: FlowBinaryOp::MulChecked,
                        ..
                    } => flow_checked_multiplies += 1,
                    FlowOperation::Call { .. } => flow_calls += 1,
                    _ => {}
                }
            }
        }
    }
    assert_eq!(flow_aggregates, 1);
    assert_eq!(flow_copies, 1);
    assert_eq!(flow_projects, 1);
    assert_eq!(flow_checked_multiplies, 3);
    assert!(flow_calls >= 8);
    assert!(flow_model.functions.iter().any(|function| {
        function.result_types == [FlowTypeId(duration_ty.0)]
            && function.blocks.iter().any(|block| {
                matches!(&block.terminator, Terminator::Return(values) if values.len() == 1)
            })
    }));

    let (flow_wir, _, _) = flow.into_parts();
    let codec_limits = CodecLimits::standard();
    let encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: &flow_wir,
            limits: codec_limits,
        },
        &never_cancelled,
    )
    .expect("FlowWir v12 canonical roundtrip");
    let decoded = CanonicalFlowWirCodec
        .decode(
            DecodeRequest {
                bytes: encoded.bytes(),
                limits: codec_limits,
                expected_build: Some(fixture.build.identity()),
            },
            &never_cancelled,
        )
        .expect("FlowWir v12 decode");
    assert_eq!(decoded, flow_wir);

    let prepared = prepare_canonical_frame_for_codegen(
        encoded.bytes(),
        &fixture.target,
        &fixture.build,
        &never_cancelled,
    )
    .expect("canonical backend accepts one-field u64 aggregate FlowWir");
    let machine = prepared.machine().wir().as_wir();
    let duration_machine_type = machine
        .types
        .iter()
        .find(|ty| ty.source_name.as_deref() == Some("RuntimeDurationRepresentation"))
        .expect("nominal duration representation reaches MachineWir");
    assert_eq!(duration_machine_type.id.0, duration_ty.0);
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
    let mut machine_calls = 0;
    for function in &machine.functions {
        for block in &function.blocks {
            for instruction in &block.instructions {
                match &instruction.operation {
                    MachineOperation::Convert {
                        op: ConversionOp::Bitcast,
                        ..
                    } => machine_bitcasts += 1,
                    MachineOperation::CheckedInteger {
                        op: CheckedIntegerOp::Multiply,
                        ..
                    } => machine_checked_multiplies += 1,
                    MachineOperation::Call { .. } => machine_calls += 1,
                    _ => {}
                }
            }
        }
    }
    assert_eq!(machine_bitcasts, 3);
    assert_eq!(machine_checked_multiplies, 3);
    assert!(machine_calls >= 8);
}

#[test]
fn local_flat_field_update_reaches_deterministic_native_coff() {
    let fixture = fixture(MUTATION_SOURCE, MUTATION_TEST_SOURCE);
    let semantic = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed(&fixture),
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("owned local field update lowers to SemanticWir");
    let repeated_semantic = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed(&fixture),
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("repeat owned local field update lowering");
    assert_eq!(
        semantic.wir().as_wir(),
        repeated_semantic.wir().as_wir(),
        "identical source must produce identical SemanticWir v9"
    );
    let semantic_insertions = semantic
        .wir()
        .as_wir()
        .functions
        .iter()
        .flat_map(|function| &function.body.statements)
        .filter(|statement| {
            matches!(
                statement,
                LoweredSemanticStatement::Let(statement)
                    if matches!(statement.operation, SemanticOperation::InsertField { field: 0, .. })
                        && statement.results.len() == 1
            )
        })
        .count();
    assert_eq!(semantic_insertions, 1);

    let (semantic_wir, _) = semantic.into_parts();
    let (repeated_semantic_wir, _) = repeated_semantic.into_parts();
    let flow = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic_wir,
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("owned local field update lowers to FlowWir");
    let repeated_flow = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: repeated_semantic_wir,
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("repeat owned local field update FlowWir lowering");
    assert_eq!(
        flow.wir().as_wir(),
        repeated_flow.wir().as_wir(),
        "identical SemanticWir must produce identical FlowWir v12"
    );
    let flow_insertions = flow
        .wir()
        .as_wir()
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .flat_map(|block| &block.instructions)
        .filter(|instruction| {
            matches!(
                instruction.operation,
                FlowOperation::InsertField { field: 0, .. }
            ) && instruction.results.len() == 1
        })
        .count();
    assert_eq!(flow_insertions, 1);

    let (flow_wir, _, _) = flow.into_parts();
    let encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: &flow_wir,
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("field-update FlowWir canonical frame");
    let decoded = CanonicalFlowWirCodec
        .decode(
            DecodeRequest {
                bytes: encoded.bytes(),
                limits: CodecLimits::standard(),
                expected_build: Some(fixture.build.identity()),
            },
            &never_cancelled,
        )
        .expect("field-update FlowWir v12 decode");
    assert_eq!(decoded, flow_wir);

    let prepared = prepare_canonical_frame_for_codegen(
        encoded.bytes(),
        &fixture.target,
        &fixture.build,
        &never_cancelled,
    )
    .expect("one-field u64 update reaches MachineWir");
    let update_bitcasts = prepared
        .machine()
        .wir()
        .as_wir()
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .flat_map(|block| &block.instructions)
        .filter(|instruction| {
            matches!(
                instruction.operation,
                MachineOperation::Convert {
                    op: ConversionOp::Bitcast,
                    ..
                }
            )
        })
        .count();
    assert_eq!(
        update_bitcasts, 3,
        "construct, full-field replacement, and projection each lower to one exact bitcast"
    );

    match emit_prepared_object(&prepared, &fixture.target, &never_cancelled) {
        Err(CodegenError::BackendNotBuilt) if !llvm_backend_available() => {}
        Err(error) => panic!("field-update native object emission failed: {error}"),
        Ok(_) if !llvm_backend_available() => {
            panic!("native object emitted while LLVM reports unavailable")
        }
        Ok(first) => {
            let second = emit_prepared_object(&prepared, &fixture.target, &never_cancelled)
                .expect("repeat field-update native object emission");
            assert_eq!(
                first.bytes(),
                second.bytes(),
                "identical field-update MachineWir must emit byte-identical ARM64 COFF"
            );
        }
    }
}

#[test]
fn infallible_initializer_reaches_deterministic_native_coff() {
    let fixture = fixture(INITIALIZER_SOURCE, INITIALIZER_TEST_SOURCE);
    let semantic = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed(&fixture),
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("infallible initializer lowers to SemanticWir");
    let repeated_semantic = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed(&fixture),
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("repeat infallible initializer lowering");
    assert_eq!(semantic.wir().as_wir(), repeated_semantic.wir().as_wir());
    assert_eq!(
        semantic
            .wir()
            .as_wir()
            .functions
            .iter()
            .flat_map(|function| &function.body.statements)
            .filter(|statement| matches!(
                statement,
                LoweredSemanticStatement::Let(statement)
                    if matches!(&statement.operation, SemanticOperation::Aggregate { fields, .. } if fields.len() == 1)
            ))
            .count(),
        1,
        "the authenticated init body desugars to one aggregate construction"
    );

    let (semantic_wir, _) = semantic.into_parts();
    let (repeated_semantic_wir, _) = repeated_semantic.into_parts();
    let flow = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic_wir,
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("initializer lowers to FlowWir");
    let repeated_flow = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: repeated_semantic_wir,
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("repeat initializer FlowWir lowering");
    assert_eq!(flow.wir().as_wir(), repeated_flow.wir().as_wir());
    let (flow_wir, _, _) = flow.into_parts();
    let encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: &flow_wir,
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("initializer FlowWir canonical frame");
    let prepared = prepare_canonical_frame_for_codegen(
        encoded.bytes(),
        &fixture.target,
        &fixture.build,
        &never_cancelled,
    )
    .expect("initializer reaches MachineWir");
    assert!(
        prepared
            .machine()
            .wir()
            .as_wir()
            .types
            .iter()
            .any(|ty| ty.source_name.as_deref() == Some("Box")
                && ty.kind == MachineTypeKind::Integer { bits: 64 })
    );
    match emit_prepared_object(&prepared, &fixture.target, &never_cancelled) {
        Err(CodegenError::BackendNotBuilt) if !llvm_backend_available() => {}
        Err(error) => panic!("initializer native object emission failed: {error}"),
        Ok(_) if !llvm_backend_available() => {
            panic!("native object emitted while LLVM reports unavailable")
        }
        Ok(first) => {
            let second = emit_prepared_object(&prepared, &fixture.target, &never_cancelled)
                .expect("repeat initializer native object emission");
            assert_eq!(
                first.bytes(),
                second.bytes(),
                "identical initializer MachineWir must emit byte-identical ARM64 COFF"
            );
        }
    }
}

#[test]
fn two_field_flat_local_reaches_unpacked_machine_wir_and_deterministic_coff() {
    let fixture = fixture(NATIVE_PAIR_SOURCE, NATIVE_PAIR_TEST_SOURCE);
    let semantic = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed(&fixture),
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("two-field local lowers to SemanticWir");
    let flow = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic.into_parts().0,
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("two-field local lowers to FlowWir");
    let encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: &flow.into_parts().0,
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("two-field FlowWir canonical frame");
    let prepared = prepare_canonical_frame_for_codegen(
        encoded.bytes(),
        &fixture.target,
        &fixture.build,
        &never_cancelled,
    )
    .expect("two-field local reaches MachineWir v13");
    let machine = prepared.machine().wir().as_wir();
    let pair = machine
        .types
        .iter()
        .find(|ty| ty.source_name.as_deref() == Some("Pair"))
        .expect("nominal Pair machine type");
    let MachineTypeKind::Struct {
        fields,
        packed: false,
    } = &pair.kind
    else {
        panic!("Pair must retain an unpacked machine representation")
    };
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[0].offset, 0);
    assert_eq!(fields[1].offset, 8);
    assert_eq!((pair.size, pair.alignment), (16, 8));

    let mut constructs = 0;
    let mut inserts = 0;
    let mut extracts = 0;
    for instruction in machine
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .flat_map(|block| &block.instructions)
    {
        match instruction.operation {
            MachineOperation::MakeStruct { .. } => constructs += 1,
            MachineOperation::InsertField { field: 1, .. } => inserts += 1,
            MachineOperation::ExtractField { field: 1, .. } => extracts += 1,
            _ => {}
        }
    }
    assert_eq!((constructs, inserts, extracts), (1, 1, 1));

    match emit_prepared_object(&prepared, &fixture.target, &never_cancelled) {
        Err(CodegenError::BackendNotBuilt) if !llvm_backend_available() => {}
        Err(error) => panic!("two-field native object emission failed: {error}"),
        Ok(_) if !llvm_backend_available() => {
            panic!("native object emitted while LLVM reports unavailable")
        }
        Ok(first) => {
            let second = emit_prepared_object(&prepared, &fixture.target, &never_cancelled)
                .expect("repeat two-field native object emission");
            assert_eq!(
                first.bytes(),
                second.bytes(),
                "identical two-field MachineWir emits byte-identical ARM64 COFF"
            );
        }
    }
}

#[test]
fn two_field_flat_local_crosses_cfg_join_and_emits_deterministically() {
    let fixture = fixture(NATIVE_PAIR_JOIN_SOURCE, NATIVE_PAIR_JOIN_TEST_SOURCE);
    let semantic = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed(&fixture),
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("branched two-field local lowers to SemanticWir");
    let flow = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic.into_parts().0,
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("branched two-field local lowers to FlowWir");
    let encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: &flow.into_parts().0,
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("branched two-field FlowWir canonical frame");
    let prepared = prepare_canonical_frame_for_codegen(
        encoded.bytes(),
        &fixture.target,
        &fixture.build,
        &never_cancelled,
    )
    .expect("two-field local crosses a MachineWir CFG join");
    let machine = prepared.machine().wir().as_wir();
    let pair = machine
        .types
        .iter()
        .find(|ty| ty.source_name.as_deref() == Some("Pair"))
        .expect("nominal Pair machine type");
    assert!(matches!(pair.kind, MachineTypeKind::Struct { .. }));
    assert!(machine.functions.iter().any(|function| {
        function.blocks.iter().any(|block| {
            block
                .parameters
                .iter()
                .any(|parameter| function.values[parameter.0 as usize].ty == pair.id)
        })
    }));

    match emit_prepared_object(&prepared, &fixture.target, &never_cancelled) {
        Err(CodegenError::BackendNotBuilt) if !llvm_backend_available() => {}
        Err(error) => panic!("joined two-field native object emission failed: {error}"),
        Ok(_) if !llvm_backend_available() => {
            panic!("native object emitted while LLVM reports unavailable")
        }
        Ok(first) => {
            let second = emit_prepared_object(&prepared, &fixture.target, &never_cancelled)
                .expect("repeat joined two-field native object emission");
            assert_eq!(
                first.bytes(),
                second.bytes(),
                "identical joined aggregate MachineWir emits byte-identical ARM64 COFF"
            );
        }
    }
}

#[test]
fn local_result_constructor_and_exhaustive_match_reach_machine_switch() {
    let fixture = fixture(LOCAL_RESULT_SOURCE, LOCAL_RESULT_TEST_SOURCE);
    let analyzed = analyzed(&fixture);
    let result_ty = analyzed
        .facts()
        .types
        .iter()
        .find(|ty| {
            matches!(
                &ty.kind,
                SemanticTypeKind::Enumeration { variants, .. }
                    if variants.len() == 2
                        && variants[0].name == "Ok"
                        && variants[1].name == "Err"
            )
        })
        .expect("local closed result enum")
        .id;

    let semantic = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed,
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("local result lowers to SemanticWir");
    let semantic_model = semantic.wir().as_wir();
    let LoweredSemanticTypeKind::Enum { variants } =
        &semantic_model.types[result_ty.0 as usize].kind
    else {
        panic!("local result SemanticWir type must remain an enum");
    };
    assert_eq!(variants.len(), 2);
    assert_eq!(variants[0].name, "Ok");
    assert_eq!(variants[1].name, "Err");
    let semantic_constructors = semantic_model
        .functions
        .iter()
        .flat_map(|function| &function.body.statements)
        .filter(|statement| {
            matches!(
                statement,
                LoweredSemanticStatement::Let(statement)
                    if matches!(statement.operation, SemanticOperation::ConstructEnum { .. })
            )
        })
        .count();
    let constructor_semantic_functions = semantic_model
        .functions
        .iter()
        .filter(|function| {
            function.body.statements.iter().any(|statement| {
                matches!(
                    statement,
                    LoweredSemanticStatement::Let(statement)
                        if matches!(statement.operation, SemanticOperation::ConstructEnum { .. })
                )
            })
        })
        .map(|function| function.id.0)
        .collect::<Vec<_>>();
    let semantic_matches = semantic_model
        .functions
        .iter()
        .flat_map(|function| &function.body.statements)
        .filter(|statement| matches!(statement, LoweredSemanticStatement::Match { arms, .. } if arms.len() == 2))
        .count();
    let match_semantic_function = semantic_model
        .functions
        .iter()
        .find(|function| {
            function.body.statements.iter().any(
                |statement| matches!(statement, LoweredSemanticStatement::Match { arms, .. } if arms.len() == 2),
            )
        })
        .expect("one exhaustive local result match")
        .id
        .0;
    assert_eq!(semantic_constructors, 2);
    assert_eq!(semantic_matches, 1);

    let (semantic_wir, _) = semantic.into_parts();
    let flow = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic_wir,
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("local result lowers to FlowWir");
    assert!(flow.diagnostics().is_empty());
    let flow_model = flow.wir().as_wir();
    assert!(matches!(
        &flow_model.types[result_ty.0 as usize].kind,
        FlowTypeKind::Enum { variants } if variants.len() == 2
    ));
    let mut flow_make = 0;
    let mut flow_tag = 0;
    let mut flow_payload = 0;
    let mut flow_switch = 0;
    for function in &flow_model.functions {
        let source_semantic_function = match function.origin {
            wrela_backend::flow_wir::FunctionOrigin::SourceSemantic { semantic_function } => {
                Some(semantic_function)
            }
            _ => None,
        };
        let is_unwrap_or_zero = source_semantic_function == Some(match_semantic_function);
        let is_result_source = is_unwrap_or_zero
            || source_semantic_function
                .is_some_and(|id| constructor_semantic_functions.contains(&id));
        for block in &function.blocks {
            for instruction in &block.instructions {
                if is_result_source {
                    match instruction.operation {
                        FlowOperation::MakeEnum { .. } => flow_make += 1,
                        FlowOperation::EnumTag { .. } => flow_tag += 1,
                        FlowOperation::EnumPayload { .. } => flow_payload += 1,
                        _ => {}
                    }
                }
            }
            if is_unwrap_or_zero && matches!(block.terminator, Terminator::Switch { .. }) {
                flow_switch += 1;
            }
        }
    }
    assert_eq!(flow_make, 2);
    assert_eq!(flow_tag, 1);
    assert_eq!(flow_payload, 1);
    assert_eq!(flow_switch, 1);

    let (flow_wir, _, _) = flow.into_parts();
    let encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: &flow_wir,
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("FlowWir v12 enum roundtrip");
    let prepared = prepare_canonical_frame_for_codegen(
        encoded.bytes(),
        &fixture.target,
        &fixture.build,
        &never_cancelled,
    )
    .expect("canonical backend accepts local result FlowWir");
    let machine = prepared.machine().wir().as_wir();
    assert!(machine.types.iter().any(|ty| {
        ty.source_name.as_deref() == Some("LocalResult")
            && matches!(ty.kind, MachineTypeKind::TaggedEnum { variants: 2, .. })
    }));
    let mut machine_make = 0;
    let mut machine_tag = 0;
    let mut machine_payload = 0;
    let mut machine_switch = 0;
    for function in &machine.functions {
        let source_semantic_function = match function.origin {
            wrela_backend::machine_wir::MachineFunctionOrigin::SourceSemantic {
                semantic_function,
            } => Some(semantic_function),
            _ => None,
        };
        let is_unwrap_or_zero = source_semantic_function == Some(match_semantic_function);
        let is_result_source = is_unwrap_or_zero
            || source_semantic_function
                .is_some_and(|id| constructor_semantic_functions.contains(&id));
        for block in &function.blocks {
            for instruction in &block.instructions {
                if is_result_source {
                    match instruction.operation {
                        MachineOperation::MakeEnum { .. } => machine_make += 1,
                        MachineOperation::EnumTag { .. } => machine_tag += 1,
                        MachineOperation::EnumPayload { .. } => machine_payload += 1,
                        _ => {}
                    }
                }
            }
            if is_unwrap_or_zero && matches!(block.terminator, MachineTerminator::Switch { .. }) {
                machine_switch += 1;
            }
        }
    }
    assert_eq!(machine_make, 2);
    assert_eq!(machine_tag, 1);
    assert_eq!(machine_payload, 1);
    assert_eq!(machine_switch, 1);
}

#[test]
fn structure_lowering_honors_exact_operation_bounds_and_late_cancellation() {
    let fixture = fixture(DURATION_SOURCE, TEST_SOURCE);
    let mut exact_lookup_limits = AnalysisLimits::standard();
    exact_lookup_limits.runtime_aggregate_lookup_work = 126;
    let exact_lookup = compile(&fixture, exact_lookup_limits, &never_cancelled)
        .expect("exact runtime aggregate lookup-work bound");
    assert!(exact_lookup.diagnostics().is_empty());
    exact_lookup_limits.runtime_aggregate_lookup_work = 125;
    assert!(matches!(
        compile(&fixture, exact_lookup_limits, &never_cancelled),
        Err(AnalysisFailure::ResourceLimit {
            resource: "runtime type and aggregate lookup work",
            limit: 125,
        })
    ));

    let analyzed = analyzed(&fixture);
    let semantic_polls = Cell::new(0_u64);
    let count_semantic_polls = || {
        semantic_polls.set(semantic_polls.get() + 1);
        false
    };
    let baseline = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed.clone(),
                limits: SemanticLoweringLimits::standard(),
            },
            &count_semantic_polls,
        )
        .expect("baseline semantic lowering");
    let semantic_poll_count = semantic_polls.get();
    assert!(semantic_poll_count > 8);
    let exact = baseline.report().operations;
    let mut exact_limits = SemanticLoweringLimits::standard();
    exact_limits.operations = exact;
    CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed.clone(),
                limits: exact_limits,
            },
            &never_cancelled,
        )
        .expect("exact SemanticWir operation bound");
    exact_limits.operations = exact - 1;
    assert!(matches!(
        CanonicalSemanticLowerer::new().lower(
            SemanticLowerRequest {
                input: analyzed.clone(),
                limits: exact_limits,
            },
            &never_cancelled,
        ),
        Err(SemanticLowerError::ResourceLimit {
            resource: "SemanticWir operations",
            limit,
        }) if limit == exact - 1
    ));

    let semantic_cancel_at = semantic_poll_count - 4;
    let semantic_cancel_polls = Cell::new(0_u64);
    let cancel_semantic_late = || {
        let next = semantic_cancel_polls.get() + 1;
        semantic_cancel_polls.set(next);
        next == semantic_cancel_at
    };
    assert!(matches!(
        CanonicalSemanticLowerer::new().lower(
            SemanticLowerRequest {
                input: analyzed,
                limits: SemanticLoweringLimits::standard(),
            },
            &cancel_semantic_late,
        ),
        Err(SemanticLowerError::Cancelled)
    ));
    assert_eq!(semantic_cancel_polls.get(), semantic_cancel_at);

    let (semantic_wir, _) = baseline.into_parts();
    let flow_polls = Cell::new(0_u64);
    let count_flow_polls = || {
        flow_polls.set(flow_polls.get() + 1);
        false
    };
    let baseline_flow = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic_wir.clone(),
                limits: FlowLoweringLimits::standard(),
            },
            &count_flow_polls,
        )
        .expect("baseline FlowWir lowering");
    let flow_poll_count = flow_polls.get();
    assert!(flow_poll_count > 8);
    let exact_instructions = baseline_flow.report().instructions;
    let mut flow_limits = FlowLoweringLimits::standard();
    flow_limits.instructions = exact_instructions;
    CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic_wir.clone(),
                limits: flow_limits,
            },
            &never_cancelled,
        )
        .expect("exact FlowWir instruction bound");
    flow_limits.instructions = exact_instructions - 1;
    assert!(matches!(
        CanonicalFlowLowerer::new().lower(
            FlowLowerRequest {
                input: semantic_wir.clone(),
                limits: flow_limits,
            },
            &never_cancelled,
        ),
        Err(FlowLowerError::ResourceLimit {
            resource: "FlowWir instructions",
            limit,
        }) if limit == exact_instructions - 1
    ));

    let flow_cancel_at = flow_poll_count - 4;
    let flow_cancel_polls = Cell::new(0_u64);
    let cancel_flow_late = || {
        let next = flow_cancel_polls.get() + 1;
        flow_cancel_polls.set(next);
        next == flow_cancel_at
    };
    assert!(matches!(
        CanonicalFlowLowerer::new().lower(
            FlowLowerRequest {
                input: semantic_wir,
                limits: FlowLoweringLimits::standard(),
            },
            &cancel_flow_late,
        ),
        Err(FlowLowerError::Cancelled)
    ));
    assert_eq!(flow_cancel_polls.get(), flow_cancel_at);
}

#[test]
fn late_named_field_lookup_has_an_exact_global_work_bound() {
    let fixture = fixture(WIDE_STRUCTURE_SOURCE, WIDE_STRUCTURE_TEST_SOURCE);
    let mut limits = AnalysisLimits::standard();
    // The field-name component is 8 * 8 + 8 = 72 comparisons. Including all
    // type interning and nominal lookup scans
    // guard's own scalar local, makes the exact global work bound below.
    limits.runtime_aggregate_lookup_work = 173;
    let exact = compile(&fixture, limits, &never_cancelled)
        .expect("exact late-field aggregate lookup-work bound");
    assert!(exact.diagnostics().is_empty());

    limits.runtime_aggregate_lookup_work = 154;
    let over_bound_polls = Cell::new(0_u64);
    let count_over_bound_polls = || {
        over_bound_polls.set(over_bound_polls.get() + 1);
        false
    };
    assert!(matches!(
        compile(&fixture, limits, &count_over_bound_polls),
        Err(AnalysisFailure::ResourceLimit {
            resource: "runtime type and aggregate lookup work",
            limit: 154,
        })
    ));
    let cancel_at = over_bound_polls.get();
    assert!(cancel_at > 154);
    let cancellation_polls = Cell::new(0_u64);
    let cancel_on_last_lookup = || {
        let next = cancellation_polls.get() + 1;
        cancellation_polls.set(next);
        next == cancel_at
    };
    assert!(matches!(
        compile(&fixture, AnalysisLimits::standard(), &cancel_on_last_lookup,),
        Err(AnalysisFailure::Cancelled)
    ));
    assert_eq!(cancellation_polls.get(), cancel_at);
}

#[test]
fn malformed_nested_private_and_implicit_copy_forms_fail_with_stable_codes() {
    let cases = [
        (
            r#"module app.duration
pub struct Pair:
    pub left: u64
    pub right: u64
pub fn malformed(value: u64) -> Pair:
    return Pair(left=value)
"#,
            r#"module app.duration_test
from app.duration import malformed
@test(runtime)
fn malformed_constructor():
    malformed(1)
    return
"#,
            "semantic-runtime-constructor-argument",
        ),
        (
            r#"module app.duration
pub struct Inner:
    pub value: u64
pub struct Outer:
    pub inner: Inner
pub fn unsupported(value: u64) -> Outer:
    return Outer(inner=Inner(value=value))
"#,
            r#"module app.duration_test
from app.duration import unsupported
@test(runtime)
fn nested_structure():
    unsupported(1)
    return
"#,
            "semantic-runtime-aggregate-not-supported",
        ),
        (
            r#"module app.duration
pub struct Secret:
    value: u64
pub fn make(value: u64) -> Secret:
    return Secret(value=value)
"#,
            r#"module app.duration_test
from app.duration import Secret, make
@test(runtime)
fn private_projection():
    secret: Secret = make(1)
    consume(secret.value)
    return
fn consume(value: u64):
    return
"#,
            "semantic-runtime-field-private",
        ),
        (
            r#"module app.duration
pub struct Flat:
    pub value: u64
pub fn make(value: u64) -> Flat:
    return Flat(value=value)
"#,
            r#"module app.duration_test
from app.duration import Flat, make
@test(runtime)
fn implicit_copy():
    first: Flat = make(1)
    second: Flat = first
    return
"#,
            "semantic-explicit-copy-required",
        ),
        (
            r#"module app.duration
pub struct First:
    pub value: u64
pub struct Second:
    pub value: u64
pub fn wrong_nominal(value: u64) -> First:
    return Second(value=value)
"#,
            r#"module app.duration_test
from app.duration import wrong_nominal
@test(runtime)
fn nominal_substitution():
    wrong_nominal(1)
    return
"#,
            "semantic-constructor-result-type",
        ),
    ];
    for (production, tests, expected_code) in cases {
        let fixture = fixture(production, tests);
        if fixture
            .discovery_diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code.as_deref() == Some(expected_code))
        {
            continue;
        }
        let output = compile(&fixture, AnalysisLimits::standard(), &never_cancelled)
            .expect("bounded semantic rejection");
        assert!(output.successful().is_none());
        assert!(
            output
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code.as_deref() == Some(expected_code)),
            "missing {expected_code}: {:?}",
            output.diagnostics()
        );
    }
}

#[test]
fn copy_struct_permits_implicit_duplication() {
    let fixture = fixture(
        r#"module app.duration
pub copy struct Point:
    pub value: u64
pub fn make(value: u64) -> Point:
    return Point(value=value)
"#,
        r#"module app.duration_test
from app.duration import Point, make
@test(runtime)
fn copy_struct_implicit_copy():
    first: Point = make(1)
    second: Point = first
    return
"#,
    );
    let output = compile(&fixture, AnalysisLimits::standard(), &never_cancelled)
        .expect("copy struct implicit duplication analyzes");
    assert!(
        output.diagnostics().is_empty(),
        "{:?}",
        output.diagnostics()
    );
    assert!(output.successful().is_some());
}

#[test]
fn inline_if_expression_analyzes() {
    let fixture = fixture(
        r#"module app.duration
pub fn pick(flag: bool) -> u64:
    return if flag: 1 else: 0
"#,
        r#"module app.duration_test
from app.duration import pick
@test(runtime)
fn inline_if_value():
    chosen: u64 = pick(true)
    return
"#,
    );
    assert!(
        fixture.discovery_diagnostics.is_empty(),
        "{:?}",
        fixture.discovery_diagnostics
    );
    let output = compile(&fixture, AnalysisLimits::standard(), &never_cancelled)
        .expect("inline if expression analyzes");
    assert!(
        output.diagnostics().is_empty(),
        "{:?}",
        output.diagnostics()
    );
    assert!(output.successful().is_some());
}

#[test]
fn deriving_unknown_name_is_rejected() {
    let fixture = fixture(
        r#"module app.duration
pub struct Point deriving(Clone):
    pub value: u64
pub fn make(value: u64) -> Point:
    return Point(value=value)
"#,
        r#"module app.duration_test
from app.duration import Point, make
@test(runtime)
fn unused():
    point: Point = make(1)
    return
"#,
    );
    assert!(
        fixture
            .discovery_diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code.as_deref() == Some("semantic-deriving-unknown")),
        "{:?}",
        fixture.discovery_diagnostics
    );
}

#[test]
fn deriving_eq_is_accepted() {
    let fixture = fixture(
        r#"module app.duration
pub struct Point deriving(Eq):
    pub value: u64
pub fn make(value: u64) -> Point:
    return Point(value=value)
"#,
        r#"module app.duration_test
from app.duration import Point, make
@test(runtime)
fn deriving_eq_parses():
    first: Point = make(1)
    return
"#,
    );
    let output = compile(&fixture, AnalysisLimits::standard(), &never_cancelled)
        .expect("deriving Eq analyzes");
    assert!(
        output.diagnostics().is_empty(),
        "{:?}",
        output.diagnostics()
    );
    assert!(output.successful().is_some());
}
