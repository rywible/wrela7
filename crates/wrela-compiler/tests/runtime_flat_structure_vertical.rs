#![forbid(unsafe_code)]

use std::cell::Cell;
use std::sync::Arc;

use wrela_backend::{
    BackendContentHasher, BackendPreparationOptions, BackendPreparationServices,
    CanonicalBackendContentHasher, CanonicalFlowOptimizer, CanonicalMachineLowerer, CodegenError,
    MachineLowerError, MachineLoweringLimits, OptimizationLimits, OptimizationProfile,
    emit_prepared_object, flow_wir as flow, llvm_backend_available,
    machine_wir::{
        CheckedIntegerOp, ConversionOp, MachineOperation, MachineTerminator, MachineTypeKind,
    },
    prepare_canonical_frame_for_codegen, prepare_for_codegen,
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
    seal as seal_semantic,
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

const DERIVED_EQ_SOURCE: &str = r#"module app.duration

pub struct Point deriving(Eq):
    pub value: u64

pub fn make(value: u64) -> Point:
    return Point(value=value)

pub fn same(read left: Point, read right: Point) -> bool:
    result: bool = left == right
    left_after: u64 = left.value
    right_after: u64 = right.value
    return result

pub fn different(read left: Point, read right: Point) -> bool:
    return left != right
"#;

const DERIVED_EQ_TEST_SOURCE: &str = r#"module app.duration_test

from app.duration import Point, different, make, same

@test(runtime)
fn derived_equality_reaches_native():
    first: Point = make(1)
    second: Point = make(1)
    equal: bool = same(left=first, right=second)
    unequal: bool = different(left=first, right=second)
    return
"#;

const MULTIFIELD_DERIVED_EQ_SOURCE: &str = r#"module app.duration

pub struct Pair deriving(Eq):
    pub first: u64
    pub second: bool

pub fn compare() -> bool:
    left: Pair = Pair(first=1, second=true)
    right: Pair = Pair(first=1, second=true)
    result: bool = left == right
    left_after: u64 = left.first
    right_after: bool = right.second
    different: bool = left != right
    return result
"#;

const MULTIFIELD_DERIVED_EQ_TEST_SOURCE: &str = r#"module app.duration_test

from app.duration import compare

@test(runtime)
fn multifield_derived_equality_reaches_native():
    equal: bool = compare()
    return
"#;

const DERIVED_FROM_SOURCE: &str = r#"module app.duration
pub enum Milliseconds deriving(From):
    value(u64,)

pub fn convert(value: u64) -> Milliseconds:
    return Milliseconds.from(value)
"#;

const DERIVED_FROM_TEST_SOURCE: &str = r#"module app.duration_test
from app.duration import Milliseconds, convert

@test(runtime)
fn derived_from_is_available():
    converted: Milliseconds = convert(42)
    return
"#;

const DERIVED_FROM_NATIVE_SOURCE: &str = r#"module app.duration
pub enum Milliseconds deriving(From):
    value(u64,)

pub fn convert(value: u64) -> Milliseconds:
    return Milliseconds.from(value)

pub fn construct(value: u64) -> Milliseconds:
    return Milliseconds.value(value)
"#;

const DERIVED_FROM_NATIVE_TEST_SOURCE: &str = r#"module app.duration_test
from app.duration import Milliseconds, construct, convert

@test(runtime)
fn generated_and_direct_construction_reach_native():
    converted: Milliseconds = convert(42)
    constructed: Milliseconds = construct(43)
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

const GENERIC_NATIVE_PAIR_SOURCE: &str = r#"module app.duration

pub struct Cell[T]:
    pub left: T
    pub right: T

pub fn update_and_read() -> u64:
    value: Cell[u64] = Cell(left=1, right=2)
    value.right = 9
    return value.right
"#;

const GENERIC_NATIVE_PAIR_TEST_SOURCE: &str = r#"module app.duration_test

from app.duration import update_and_read

@test(runtime)
fn generic_native_pair_field_update_runs():
    value: u64 = update_and_read()
    return
"#;

const NATIVE_PAIR_ARGUMENT_SOURCE: &str = r#"module app.duration

pub struct Pair:
    pub count: u32
    pub total: u64

pub fn read_total(value: Pair) -> u64:
    return value.total

pub fn call_reader() -> u64:
    value: Pair = Pair(count=1, total=42)
    return read_total(value)
"#;

const NATIVE_PAIR_ARGUMENT_TEST_SOURCE: &str = r#"module app.duration_test

from app.duration import call_reader

@test(runtime)
fn native_pair_argument_reaches_reader():
    observed: u64 = call_reader()
    return
"#;

const NATIVE_PAIR_RESULT_SOURCE: &str = r#"module app.duration

pub struct Pair:
    pub count: u32
    pub total: u64

pub fn make_pair(count: u32, total: u64) -> Pair:
    return Pair(count=count, total=total)

pub fn call_builder() -> u64:
    value: Pair = make_pair(count=1, total=42)
    return value.total
"#;

const NATIVE_PAIR_RESULT_TEST_SOURCE: &str = r#"module app.duration_test

from app.duration import call_builder

@test(runtime)
fn native_pair_result_reaches_caller():
    observed: u64 = call_builder()
    return
"#;

const GENERIC_INTERFACE_READER_SOURCE: &str = r#"module app.duration

pub interface Read[T]:
    fn convert(read self) -> T

pub struct Pair:
    pub count: u32
    pub total: u64

impl Read[u64] for Pair:
    fn convert(read self) -> u64:
        return self.total

pub fn call_interface() -> u64:
    value: Pair = Pair(count=1, total=42)
    return value.convert()
"#;

const GENERIC_INTERFACE_READER_TEST_SOURCE: &str = r#"module app.duration_test

from app.duration import call_interface

@test(runtime)
fn generic_interface_reader_reaches_native():
    observed: u64 = call_interface()
    return
"#;

const GENERIC_INTERFACE_ARGUMENT_SOURCE: &str = r#"module app.duration

pub interface Convert[T]:
    fn convert(read self, value: T) -> T

pub struct Cell:
    pub tag: u32
    pub value: u64

impl Convert[u64] for Cell:
    fn convert(read self, value: u64) -> u64:
        return value

pub fn call_interface_argument() -> u64:
    cell: Cell = Cell(tag=1, value=2)
    return cell.convert(42)
"#;

const GENERIC_INTERFACE_ARGUMENT_TEST_SOURCE: &str = r#"module app.duration_test

from app.duration import call_interface_argument

@test(runtime)
fn generic_interface_argument_reaches_native():
    observed: u64 = call_interface_argument()
    return
"#;

const GENERIC_INTERFACE_COMBINE_SOURCE: &str = r#"module app.duration

pub interface Combine[T]:
    fn combine(read self, value: T) -> T

pub struct Cell:
    pub tag: u32
    pub value: u64

impl Combine[u64] for Cell:
    fn combine(read self, value: u64) -> u64:
        return self.value + value

pub fn call_interface_combine() -> u64:
    cell: Cell = Cell(tag=1, value=2)
    return cell.combine(40)
"#;

const GENERIC_INTERFACE_COMBINE_TEST_SOURCE: &str = r#"module app.duration_test

from app.duration import call_interface_combine

@test(runtime)
fn generic_interface_combine_reaches_native():
    observed: u64 = call_interface_combine()
    return
"#;

const SCALAR_VIEW_SOURCE: &str = r#"module app.duration

pub struct Packet:
    pub header: u64
    pub stamp: u8

pub projection header(read packet: Packet) -> view u64:
    yield packet.header

pub fn consume(value: u64):
    pass
"#;

const SCALAR_VIEW_TEST_SOURCE: &str = r#"module app.duration_test

from app.duration import Packet, consume, header

@test(runtime)
fn scalar_view_projection_reaches_native():
    packet: Packet = Packet(header=42, stamp=1)
    observed: view u64 = header(packet)
    consume(observed)
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
fn read_only_scalar_view_projection_reaches_semantic_wir() {
    let fixture = fixture(SCALAR_VIEW_SOURCE, SCALAR_VIEW_TEST_SOURCE);
    let analyzed = analyzed(&fixture);
    assert_eq!(analyzed.facts().projection_protocols.len(), 1);
    assert_eq!(analyzed.facts().lexical_views.len(), 1);
    let projection_proof = analyzed.facts().projection_protocols[0].proof;
    let semantic = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed.clone(),
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("authenticated read-only scalar view lowers to SemanticWir");
    let semantic_model = semantic.wir().as_wir();
    assert_eq!(
        semantic_model.version,
        wrela_semantic_lower::semantic_wir::SEMANTIC_WIR_VERSION
    );
    assert_eq!(
        semantic_model.source_summary.reachable_declarations, 4,
        "test, unary consumer, Packet, and the projection declaration are reachable"
    );
    let proof = &semantic_model.proofs[projection_proof.0 as usize];
    assert_eq!(
        proof.kind,
        wrela_semantic_lower::semantic_wir::ProofKind::ViewDoesNotEscape
    );
    assert_eq!(proof.bound, Some(1));
    let project_functions = semantic_model
        .functions
        .iter()
        .filter(|function| {
            function.body.statements.iter().any(|statement| {
                matches!(
                    statement,
                    LoweredSemanticStatement::Let(statement)
                        if matches!(statement.operation, SemanticOperation::Project {
                            field: 0,
                            access: wrela_semantic_lower::SemanticAccessMode::Read,
                            ..
                        }) && statement.results.len() == 1
                )
            })
        })
        .collect::<Vec<_>>();
    let [project_function] = project_functions.as_slice() else {
        panic!("exactly one source function must contain the scalar projection")
    };
    assert!(
        project_function
            .proofs
            .contains(&wrela_semantic_lower::semantic_wir::ProofId(
                projection_proof.0
            ))
    );

    let (semantic_wir, _) = semantic.into_parts();
    let flow = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic_wir,
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("scalar view projection lowers to FlowWir");
    assert!(flow.diagnostics().is_empty());
    let flow_model = flow.wir().as_wir();
    assert_eq!(flow_model.version, 19);
    let flow_projects = flow_model
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .flat_map(|block| &block.instructions)
        .filter(|instruction| {
            matches!(
                instruction.operation,
                FlowOperation::ExtractField { field: 0, .. }
            ) && instruction.results.len() == 1
        })
        .count();
    assert_eq!(flow_projects, 1);

    let (flow_wir, _, _) = flow.into_parts();
    let encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: &flow_wir,
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("scalar view FlowWir v19 canonical frame");
    let decoded = CanonicalFlowWirCodec
        .decode(
            DecodeRequest {
                bytes: encoded.bytes(),
                limits: CodecLimits::standard(),
                expected_build: Some(fixture.build.identity()),
            },
            &never_cancelled,
        )
        .expect("scalar view FlowWir v19 decode");
    assert_eq!(decoded, flow_wir);

    let prepared = prepare_canonical_frame_for_codegen(
        encoded.bytes(),
        &fixture.target,
        &fixture.build,
        &never_cancelled,
    )
    .expect("scalar view projection reaches MachineWir");
    let machine = prepared.machine().wir().as_wir();
    assert_eq!(machine.version, 19);
    let machine_projects = machine
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .flat_map(|block| &block.instructions)
        .filter(|instruction| {
            matches!(
                instruction.operation,
                MachineOperation::ExtractField { field: 0, .. }
            ) && instruction.results.len() == 1
        })
        .count();
    assert_eq!(machine_projects, 1);

    match emit_prepared_object(&prepared, &fixture.target, &never_cancelled) {
        Err(CodegenError::BackendNotBuilt) if !llvm_backend_available() => {}
        Err(error) => panic!("scalar view native object emission failed: {error}"),
        Ok(_) if !llvm_backend_available() => {
            panic!("native object emitted while LLVM reports unavailable")
        }
        Ok(first) => {
            let second = emit_prepared_object(&prepared, &fixture.target, &never_cancelled)
                .expect("repeat scalar view native object emission");
            assert_eq!(
                first.bytes(),
                second.bytes(),
                "identical scalar-view MachineWir must emit byte-identical ARM64 COFF"
            );
        }
    }
}

#[test]
fn scalar_view_project_sealer_rejects_field_access_and_deletion_forgeries() {
    let fixture = fixture(SCALAR_VIEW_SOURCE, SCALAR_VIEW_TEST_SOURCE);
    let analyzed = analyzed(&fixture);
    let lowered = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed.clone(),
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("baseline scalar view lowering");
    let baseline = lowered.wir().as_wir().clone();
    let request = SemanticLowerRequest {
        input: analyzed,
        limits: SemanticLoweringLimits::standard(),
    };

    fn project(
        model: &mut wrela_semantic_lower::semantic_wir::SemanticWir,
    ) -> &mut wrela_semantic_lower::semantic_wir::LetStatement {
        model
            .functions
            .iter_mut()
            .flat_map(|function| &mut function.body.statements)
            .find_map(|statement| match statement {
                LoweredSemanticStatement::Let(statement)
                    if matches!(statement.operation, SemanticOperation::Project { .. }) =>
                {
                    Some(statement)
                }
                _ => None,
            })
            .expect("scalar projection operation")
    }

    let mut wrong_field = baseline.clone();
    let SemanticOperation::Project { field, .. } = &mut project(&mut wrong_field).operation else {
        unreachable!()
    };
    *field = 1;
    assert!(
        seal_semantic(
            &request,
            wrong_field,
            lowered.report().clone(),
            &never_cancelled,
        )
        .is_err()
    );

    let mut wrong_access = baseline.clone();
    let SemanticOperation::Project { access, .. } = &mut project(&mut wrong_access).operation
    else {
        unreachable!()
    };
    *access = wrela_semantic_lower::SemanticAccessMode::Mutate;
    assert!(
        seal_semantic(
            &request,
            wrong_access,
            lowered.report().clone(),
            &never_cancelled,
        )
        .is_err()
    );

    let mut deleted = baseline;
    let owner = deleted
        .functions
        .iter_mut()
        .find(|function| {
            function.body.statements.iter().any(|statement| {
                matches!(statement,
                    LoweredSemanticStatement::Let(statement)
                        if matches!(statement.operation, SemanticOperation::Project { .. }))
            })
        })
        .expect("projection owner");
    owner.body.statements.retain(|statement| {
        !matches!(statement,
            LoweredSemanticStatement::Let(statement)
                if matches!(statement.operation, SemanticOperation::Project { .. }))
    });
    assert!(
        seal_semantic(
            &request,
            deleted,
            lowered.report().clone(),
            &never_cancelled,
        )
        .is_err()
    );
}

#[test]
fn scalar_view_projection_has_exact_operation_bound_and_late_cancellation() {
    let fixture = fixture(SCALAR_VIEW_SOURCE, SCALAR_VIEW_TEST_SOURCE);
    let analyzed = analyzed(&fixture);
    let baseline = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed.clone(),
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("baseline scalar view lowering");
    let exact = baseline.report().operations;
    assert!(exact > 1);
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
        .expect("the exact scalar-view operation bound is admitted");
    let mut one_under = exact_limits;
    one_under.operations = exact - 1;
    assert!(matches!(
        CanonicalSemanticLowerer::new().lower(
            SemanticLowerRequest {
                input: analyzed.clone(),
                limits: one_under,
            },
            &never_cancelled,
        ),
        Err(SemanticLowerError::ResourceLimit {
            resource: "SemanticWir operations",
            limit,
        }) if limit == exact - 1
    ));

    let polls = Cell::new(0_u32);
    CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed.clone(),
                limits: SemanticLoweringLimits::standard(),
            },
            &|| {
                polls.set(polls.get().saturating_add(1));
                false
            },
        )
        .expect("count scalar-view lowering cancellation polls");
    let cancel_at = polls.get().saturating_sub(2);
    let cancelled = Cell::new(0_u32);
    assert!(matches!(
        CanonicalSemanticLowerer::new().lower(
            SemanticLowerRequest {
                input: analyzed.clone(),
                limits: SemanticLoweringLimits::standard(),
            },
            &|| {
                let next = cancelled.get().saturating_add(1);
                cancelled.set(next);
                next >= cancel_at
            },
        ),
        Err(SemanticLowerError::Cancelled)
    ));
    assert!(cancelled.get() >= cancel_at);

    let mut exact_edges = SemanticLoweringLimits::standard();
    exact_edges.model_edges = 123;
    CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed.clone(),
                limits: exact_edges,
            },
            &never_cancelled,
        )
        .expect("the exact projection-aware model-edge bound is admitted");
    let mut one_edge_under = exact_edges;
    one_edge_under.model_edges = 122;
    assert!(matches!(
        CanonicalSemanticLowerer::new().lower(
            SemanticLowerRequest {
                input: analyzed,
                limits: one_edge_under,
            },
            &never_cancelled,
        ),
        Err(SemanticLowerError::ResourceLimit {
            resource: "semantic model edges",
            limit: 122,
        })
    ));
}

#[test]
fn multi_source_projection_lowering_tail_stays_named_and_fail_closed() {
    let source = SCALAR_VIEW_SOURCE.replace(
        "read packet: Packet",
        "read packet: Packet, read fallback: Packet",
    );
    let tests =
        SCALAR_VIEW_TEST_SOURCE.replace("header(packet)", "header(packet=packet, fallback=packet)");
    let fixture = fixture(&source, &tests);
    let error = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed(&fixture),
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect_err("multi-source projection lowering remains deferred");
    assert!(matches!(
        error,
        SemanticLowerError::UnsupportedInput {
            feature: "semantic-projection-lowering-pending (outside generated read-only scalar projection subset)"
        }
    ));
}

#[test]
fn real_imported_duration_shape_reaches_flow_and_v16_roundtrips_exactly() {
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
    .expect("FlowWir v19 canonical roundtrip");
    let decoded = CanonicalFlowWirCodec
        .decode(
            DecodeRequest {
                bytes: encoded.bytes(),
                limits: codec_limits,
                expected_build: Some(fixture.build.identity()),
            },
            &never_cancelled,
        )
        .expect("FlowWir v19 decode");
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
        "identical SemanticWir must produce identical FlowWir v19"
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
        .expect("field-update FlowWir v19 decode");
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
    .expect("two-field local reaches MachineWir v19");
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
fn generic_flat_field_update_reaches_flow_machine_and_deterministic_coff() {
    let fixture = fixture(GENERIC_NATIVE_PAIR_SOURCE, GENERIC_NATIVE_PAIR_TEST_SOURCE);
    let semantic = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed(&fixture),
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("generic field update lowers to SemanticWir");
    let semantic_wir = semantic.into_parts().0;
    let flow = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic_wir.clone(),
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("generic field update reaches FlowWir");
    let flow_model = flow.wir().as_wir();
    let cell = flow_model
        .types
        .iter()
        .find(|ty| ty.name.as_deref() == Some("Cell"))
        .expect("concrete Cell[u64] FlowWir type");
    let FlowTypeKind::Struct { fields } = &cell.kind else {
        panic!("Cell[u64] must remain a FlowWir structure")
    };
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[0], fields[1]);
    let update = flow_model
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .flat_map(|block| &block.instructions)
        .find(|instruction| {
            matches!(
                instruction.operation,
                FlowOperation::InsertField { field: 1, .. }
            )
        })
        .expect("exact generic FlowWir field update");
    assert_eq!(flow_model.functions.iter().flat_map(|function| &function.blocks).flat_map(|block| &block.instructions).filter(|instruction| matches!(instruction.operation, FlowOperation::MakeAggregate { ty, .. } if ty == cell.id)).count(), 1);
    assert_eq!(
        flow_model
            .functions
            .iter()
            .flat_map(|function| &function.blocks)
            .flat_map(|block| &block.instructions)
            .filter(|instruction| matches!(
                instruction.operation,
                FlowOperation::ExtractField { field: 1, .. }
            ))
            .count(),
        1
    );
    assert_eq!(update.results.len(), 1);

    let flow_instruction_count = flow.report().instructions;
    let mut exact_flow_limits = FlowLoweringLimits::standard();
    exact_flow_limits.instructions = flow_instruction_count;
    CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic_wir.clone(),
                limits: exact_flow_limits,
            },
            &never_cancelled,
        )
        .expect("generic field update accepts its exact FlowWir instruction ceiling");
    let mut one_under_flow = exact_flow_limits;
    one_under_flow.instructions = flow_instruction_count - 1;
    assert!(matches!(
        CanonicalFlowLowerer::new().lower(
            FlowLowerRequest {
                input: semantic_wir.clone(),
                limits: one_under_flow,
            },
            &never_cancelled,
        ),
        Err(FlowLowerError::ResourceLimit {
            resource: "FlowWir instructions",
            limit,
        }) if limit == flow_instruction_count - 1
    ));
    let flow_polls = Cell::new(0_u64);
    CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic_wir.clone(),
                limits: exact_flow_limits,
            },
            &|| {
                flow_polls.set(flow_polls.get().saturating_add(1));
                false
            },
        )
        .expect("count generic field-update FlowWir cancellation polls");
    let flow_cancel_at = flow_polls.get().saturating_sub(2);
    assert!(flow_cancel_at > 2);
    let cancelled_flow_polls = Cell::new(0_u64);
    let cancelled_flow = CanonicalFlowLowerer::new().lower(
        FlowLowerRequest {
            input: semantic_wir,
            limits: exact_flow_limits,
        },
        &|| {
            let next = cancelled_flow_polls.get().saturating_add(1);
            cancelled_flow_polls.set(next);
            next >= flow_cancel_at
        },
    );
    assert!(matches!(cancelled_flow, Err(FlowLowerError::Cancelled)));

    let flow_wir = flow.into_parts().0;
    let mut forged_flow = flow_wir.as_wir().clone();
    let forged_field = forged_flow
        .functions
        .iter_mut()
        .flat_map(|function| &mut function.blocks)
        .flat_map(|block| &mut block.instructions)
        .find_map(|instruction| match &mut instruction.operation {
            FlowOperation::InsertField { field, .. } if *field == 1 => Some(field),
            _ => None,
        })
        .expect("mutable generic FlowWir field update");
    *forged_field = 2;
    assert!(
        forged_flow.validate().is_err(),
        "FlowWir validation must reject a forged generic field identity before encoding"
    );

    let encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: &flow_wir,
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("generic field-update FlowWir canonical frame");
    let decoded = CanonicalFlowWirCodec
        .decode(
            DecodeRequest {
                bytes: encoded.bytes(),
                limits: CodecLimits::standard(),
                expected_build: Some(fixture.build.identity()),
            },
            &never_cancelled,
        )
        .expect("generic field-update FlowWir v19 decode");
    assert_eq!(decoded, flow_wir);

    let prepared = prepare_canonical_frame_for_codegen(
        encoded.bytes(),
        &fixture.target,
        &fixture.build,
        &never_cancelled,
    )
    .expect("generic field update reaches MachineWir");
    let machine = prepared.machine().wir().as_wir();
    let cell = machine
        .types
        .iter()
        .find(|ty| ty.source_name.as_deref() == Some("Cell"))
        .expect("concrete Cell[u64] MachineWir type");
    assert!(matches!(
        &cell.kind,
        MachineTypeKind::Struct {
            fields,
            packed: false,
        } if fields.len() == 2
    ));
    assert_eq!((cell.size, cell.alignment), (16, 8));
    let operations = machine
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .flat_map(|block| &block.instructions)
        .filter_map(|instruction| match instruction.operation {
            MachineOperation::MakeStruct { ty, .. } if ty == cell.id => Some(0_u8),
            MachineOperation::InsertField { field: 1, .. } => Some(1_u8),
            MachineOperation::ExtractField { field: 1, .. } => Some(2_u8),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(operations, [0, 1, 2]);

    let codec = CanonicalFlowWirCodec;
    let hasher = CanonicalBackendContentHasher::new();
    let optimizer = CanonicalFlowOptimizer::new();
    let machine_lowerer = CanonicalMachineLowerer::new();
    let expected_digest = hasher
        .sha256(encoded.bytes(), &never_cancelled)
        .expect("generic field-update frame digest");
    let optimization = OptimizationProfile::from_build_policy(
        &fixture.build.profile.optimization,
        fixture.build.identity.compiler,
    )
    .expect("generic field-update optimization profile");
    let prepare_with = |machine_limits: MachineLoweringLimits, is_cancelled: &dyn Fn() -> bool| {
        prepare_for_codegen(
            BackendPreparationServices {
                codec: &codec,
                hasher: &hasher,
                optimizer: &optimizer,
                machine_lowerer: &machine_lowerer,
            },
            encoded.bytes(),
            expected_digest,
            &fixture.target,
            &fixture.build,
            BackendPreparationOptions {
                codec_limits: CodecLimits::standard(),
                optimization: optimization.clone(),
                optimization_limits: OptimizationLimits::standard(),
                machine_limits,
            },
            is_cancelled,
        )
    };
    let instruction_count = machine
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .map(|block| block.instructions.len() as u64)
        .sum::<u64>();
    let mut exact_machine_limits = MachineLoweringLimits::standard();
    exact_machine_limits.types = machine.types.len() as u64;
    exact_machine_limits.functions = machine.functions.len() as u64;
    exact_machine_limits.sections = machine.sections.len() as u32;
    exact_machine_limits.symbols = machine.symbols.len() as u32;
    exact_machine_limits.globals = machine.globals.len() as u32;
    exact_machine_limits.instructions = instruction_count;
    exact_machine_limits.stack_slots = machine
        .functions
        .iter()
        .map(|function| function.stack_slots.len() as u64)
        .sum::<u64>()
        .max(1);
    exact_machine_limits.proofs = machine.proofs.len() as u32;
    exact_machine_limits.static_bytes = machine
        .sections
        .iter()
        .map(|section| section.reserved_bytes)
        .sum();
    exact_machine_limits.stack_bytes_per_function = machine
        .functions
        .iter()
        .map(|function| function.stack_bytes)
        .max()
        .unwrap_or(0)
        .max(1);
    exact_machine_limits = exact_machine_limits.with_aligned_validation();
    let exact = prepare_with(exact_machine_limits, &never_cancelled)
        .expect("generic field update accepts exact MachineWir instruction ceiling");
    assert_eq!(exact.machine().wir().as_wir(), machine);
    let mut one_under_machine = exact_machine_limits;
    one_under_machine.instructions -= 1;
    one_under_machine = one_under_machine.with_aligned_validation();
    let one_under_error = prepare_with(one_under_machine, &never_cancelled)
        .expect_err("one fewer generic field-update MachineWir instruction must fail");
    assert_eq!(
        one_under_error.machine_lower_error(),
        Some(&MachineLowerError::ResourceLimit {
            resource: "MachineWir instructions",
            limit: instruction_count - 1,
        })
    );
    let machine_polls = Cell::new(0_u64);
    prepare_with(MachineLoweringLimits::standard(), &|| {
        machine_polls.set(machine_polls.get().saturating_add(1));
        false
    })
    .expect("count generic field-update MachineWir cancellation polls");
    let machine_cancel_at = machine_polls.get().saturating_sub(2);
    assert!(machine_cancel_at > 2);
    let cancelled_machine_polls = Cell::new(0_u64);
    let cancellation = prepare_with(MachineLoweringLimits::standard(), &|| {
        let next = cancelled_machine_polls.get().saturating_add(1);
        cancelled_machine_polls.set(next);
        next >= machine_cancel_at
    })
    .expect_err("late generic field-update MachineWir cancellation must propagate");
    assert!(cancellation.is_cancelled());

    match emit_prepared_object(&prepared, &fixture.target, &never_cancelled) {
        Err(CodegenError::BackendNotBuilt) if !llvm_backend_available() => {}
        Err(error) => panic!("generic field-update native object emission failed: {error}"),
        Ok(_) if !llvm_backend_available() => {
            panic!("native object emitted while LLVM reports unavailable")
        }
        Ok(first) => {
            let second = emit_prepared_object(&prepared, &fixture.target, &never_cancelled)
                .expect("repeat generic field-update native emission");
            assert_eq!(
                first.bytes(),
                second.bytes(),
                "identical generic field-update MachineWir emits byte-identical ARM64 COFF"
            );
        }
    }
}

#[test]
fn two_field_owned_argument_reaches_scalar_reader_and_deterministic_coff() {
    let fixture = fixture(
        NATIVE_PAIR_ARGUMENT_SOURCE,
        NATIVE_PAIR_ARGUMENT_TEST_SOURCE,
    );
    let semantic = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed(&fixture),
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("owned two-field argument lowers to SemanticWir");
    let flow = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic.into_parts().0,
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("owned two-field argument lowers to FlowWir");
    let flow_model = flow.wir().as_wir();
    let pair = flow_model
        .types
        .iter()
        .find(|ty| ty.name.as_deref() == Some("Pair"))
        .expect("nominal Pair FlowWir type");
    let FlowTypeKind::Struct { fields } = &pair.kind else {
        panic!("Pair must be a FlowWir struct")
    };
    assert_eq!(fields.len(), 2);
    let total_ty = fields[1];
    let reader = flow_model
        .functions
        .iter()
        .find(|callee| {
            callee.parameters.len() == 1
                && callee
                    .parameters
                    .first()
                    .is_some_and(|parameter| callee.values[parameter.0 as usize].ty == pair.id)
                && callee.result_types == [total_ty]
                && callee.blocks.iter().any(|block| {
                    matches!(
                        block.instructions.as_slice(),
                        [instruction]
                            if matches!(instruction.operation,
                                FlowOperation::ExtractField { field: 1, .. })
                    )
                })
        })
        .expect("exact FlowWir scalar-field reader");
    let reader_id = reader.id;

    let flow_wir = flow.into_parts().0;
    let mut forged_flow = flow_wir.as_wir().clone();
    let forged_reader = &mut forged_flow.functions[reader_id.0 as usize];
    let projected = forged_reader.blocks[0].instructions[0].results[0];
    let forged_value = flow::ValueId(forged_reader.values.len() as u32);
    forged_reader.values.push(flow::Value {
        id: forged_value,
        ty: total_ty,
        source_name: Some("forged_copy".to_owned()),
        source: forged_reader.source,
    });
    forged_reader.blocks[0]
        .instructions
        .push(flow::Instruction {
            id: flow::InstructionId(1),
            results: vec![forged_value],
            operation: flow::FlowOperation::Copy { value: projected },
            source: forged_reader.source,
        });
    forged_reader.blocks[0].terminator = flow::Terminator::Return(vec![forged_value]);
    let forged_flow = forged_flow
        .validate()
        .expect("extra reader computation remains structurally valid FlowWir");
    let forged_encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: &forged_flow,
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("forged reader FlowWir canonical frame");
    let forged_error = prepare_canonical_frame_for_codegen(
        forged_encoded.bytes(),
        &fixture.target,
        &fixture.build,
        &never_cancelled,
    )
    .expect_err("Machine lowering must reauthenticate the exact reader body");
    assert_eq!(
        forged_error.machine_lower_error(),
        Some(&MachineLowerError::UnsupportedInput {
            feature: "machine-flat-structure-operation-lowering-pending",
        })
    );

    let encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: &flow_wir,
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("owned two-field argument FlowWir canonical frame");
    let prepared = prepare_canonical_frame_for_codegen(
        encoded.bytes(),
        &fixture.target,
        &fixture.build,
        &never_cancelled,
    )
    .expect("owned two-field argument reaches MachineWir");
    let machine = prepared.machine().wir().as_wir();
    let pair = machine
        .types
        .iter()
        .find(|ty| ty.source_name.as_deref() == Some("Pair"))
        .expect("nominal Pair MachineWir type");
    assert!(
        matches!(&pair.kind, MachineTypeKind::Struct { fields, packed: false } if fields.len() == 2)
    );
    assert!(machine.functions.iter().any(|callee| {
        callee.parameters.len() == 1
            && callee
                .parameters
                .first()
                .is_some_and(|parameter| callee.values[parameter.0 as usize].ty == pair.id)
            && callee.blocks.iter().any(|block| {
                matches!(
                    block.instructions.as_slice(),
                    [instruction]
                        if matches!(instruction.operation,
                            MachineOperation::ExtractField { field: 1, .. })
                )
            })
    }));

    let codec = CanonicalFlowWirCodec;
    let hasher = CanonicalBackendContentHasher::new();
    let optimizer = CanonicalFlowOptimizer::new();
    let machine_lowerer = CanonicalMachineLowerer::new();
    let expected_digest = hasher
        .sha256(encoded.bytes(), &never_cancelled)
        .expect("owned aggregate frame digest");
    let optimization = OptimizationProfile::from_build_policy(
        &fixture.build.profile.optimization,
        fixture.build.identity.compiler,
    )
    .expect("owned aggregate optimization profile");
    let prepare_with = |machine_limits: MachineLoweringLimits, is_cancelled: &dyn Fn() -> bool| {
        prepare_for_codegen(
            BackendPreparationServices {
                codec: &codec,
                hasher: &hasher,
                optimizer: &optimizer,
                machine_lowerer: &machine_lowerer,
            },
            encoded.bytes(),
            expected_digest,
            &fixture.target,
            &fixture.build,
            BackendPreparationOptions {
                codec_limits: CodecLimits::standard(),
                optimization: optimization.clone(),
                optimization_limits: OptimizationLimits::standard(),
                machine_limits,
            },
            is_cancelled,
        )
    };
    let instruction_count = machine
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .map(|block| block.instructions.len() as u64)
        .sum::<u64>();
    let static_bytes = machine
        .sections
        .iter()
        .map(|section| section.reserved_bytes)
        .sum::<u64>();
    let stack_slots = machine
        .functions
        .iter()
        .map(|function| function.stack_slots.len() as u64)
        .sum::<u64>();
    let stack_bytes = machine
        .functions
        .iter()
        .map(|function| function.stack_bytes)
        .max()
        .unwrap_or(0);
    let mut exact_limits = MachineLoweringLimits::standard();
    exact_limits.types = machine.types.len() as u64;
    exact_limits.functions = machine.functions.len() as u64;
    exact_limits.sections = machine.sections.len() as u32;
    exact_limits.symbols = machine.symbols.len() as u32;
    exact_limits.globals = machine.globals.len() as u32;
    exact_limits.instructions = instruction_count;
    exact_limits.stack_slots = stack_slots.max(1);
    exact_limits.proofs = machine.proofs.len() as u32;
    exact_limits.static_bytes = static_bytes;
    exact_limits.stack_bytes_per_function = stack_bytes.max(1);
    exact_limits = exact_limits.with_aligned_validation();
    let exact = prepare_with(exact_limits, &never_cancelled)
        .expect("owned aggregate argument accepts its exact instruction ceiling");
    assert_eq!(exact.machine().wir().as_wir(), machine);

    let mut one_under = exact_limits;
    one_under.instructions = one_under.instructions.saturating_sub(1);
    one_under = one_under.with_aligned_validation();
    let one_under_error = prepare_with(one_under, &never_cancelled)
        .expect_err("one fewer MachineWir instruction must fail closed");
    assert_eq!(
        one_under_error.machine_lower_error(),
        Some(&MachineLowerError::ResourceLimit {
            resource: "MachineWir instructions",
            limit: instruction_count - 1,
        })
    );

    let polls = Cell::new(0_u64);
    prepare_with(MachineLoweringLimits::standard(), &|| {
        polls.set(polls.get().saturating_add(1));
        false
    })
    .expect("count owned aggregate preparation cancellation polls");
    let cancel_at = polls.get().saturating_sub(2);
    assert!(cancel_at > 2);
    let cancelled = Cell::new(0_u64);
    let cancellation = prepare_with(MachineLoweringLimits::standard(), &|| {
        let next = cancelled.get().saturating_add(1);
        cancelled.set(next);
        next >= cancel_at
    })
    .expect_err("late aggregate preparation cancellation must propagate");
    assert!(cancellation.is_cancelled());
    assert!(cancelled.get() >= cancel_at);

    match emit_prepared_object(&prepared, &fixture.target, &never_cancelled) {
        Err(CodegenError::BackendNotBuilt) if !llvm_backend_available() => {}
        Err(error) => panic!("owned aggregate argument native object emission failed: {error}"),
        Ok(_) if !llvm_backend_available() => {
            panic!("native object emitted while LLVM reports unavailable")
        }
        Ok(first) => {
            let second = emit_prepared_object(&prepared, &fixture.target, &never_cancelled)
                .expect("repeat owned aggregate argument native object emission");
            assert_eq!(first.bytes(), second.bytes());
        }
    }
}

#[test]
fn two_field_owned_result_reaches_caller_and_deterministic_coff() {
    let fixture = fixture(NATIVE_PAIR_RESULT_SOURCE, NATIVE_PAIR_RESULT_TEST_SOURCE);
    let semantic = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed(&fixture),
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("owned two-field result lowers to SemanticWir");
    let flow = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic.into_parts().0,
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("owned two-field result lowers to FlowWir");
    let flow_wir = flow.into_parts().0;
    let mut forged_flow = flow_wir.as_wir().clone();
    let builder = forged_flow
        .functions
        .iter_mut()
        .find(|function| {
            function.result_types.len() == 1
                && function.blocks.iter().any(|block| {
                    matches!(
                        block.instructions.as_slice(),
                        [instruction]
                            if matches!(instruction.operation, FlowOperation::MakeAggregate { .. })
                    )
                })
        })
        .expect("exact FlowWir aggregate builder");
    let built = builder.blocks[0].instructions[0].results[0];
    let forged_value = flow::ValueId(builder.values.len() as u32);
    builder.values.push(flow::Value {
        id: forged_value,
        ty: builder.result_types[0],
        source_name: Some("forged_copy".to_owned()),
        source: builder.source,
    });
    builder.blocks[0].instructions.push(flow::Instruction {
        id: flow::InstructionId(1),
        results: vec![forged_value],
        operation: flow::FlowOperation::Copy { value: built },
        source: builder.source,
    });
    builder.blocks[0].terminator = flow::Terminator::Return(vec![forged_value]);
    let forged_flow = forged_flow
        .validate()
        .expect("extra builder computation remains structurally valid FlowWir");
    let forged_encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: &forged_flow,
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("forged builder FlowWir canonical frame");
    let forged_error = prepare_canonical_frame_for_codegen(
        forged_encoded.bytes(),
        &fixture.target,
        &fixture.build,
        &never_cancelled,
    )
    .expect_err("Machine lowering must reauthenticate the exact builder body");
    assert_eq!(
        forged_error.machine_lower_error(),
        Some(&MachineLowerError::UnsupportedInput {
            feature: "machine-flat-structure-operation-lowering-pending",
        })
    );

    let encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: &flow_wir,
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("owned two-field result FlowWir canonical frame");
    let prepared = prepare_canonical_frame_for_codegen(
        encoded.bytes(),
        &fixture.target,
        &fixture.build,
        &never_cancelled,
    )
    .expect("owned two-field result reaches MachineWir");
    let machine = prepared.machine().wir().as_wir();
    assert!(machine.functions.iter().any(|function| {
        function.parameters.len() == 2
            && matches!(
                machine.types[function.result.0 as usize].kind,
                MachineTypeKind::Struct { ref fields, packed: false } if fields.len() == 2
            )
            && matches!(
                function.blocks.as_slice(),
                [block]
                    if matches!(block.instructions.as_slice(), [instruction]
                        if matches!(instruction.operation, MachineOperation::MakeStruct { .. }))
            )
    }));

    let codec = CanonicalFlowWirCodec;
    let hasher = CanonicalBackendContentHasher::new();
    let optimizer = CanonicalFlowOptimizer::new();
    let machine_lowerer = CanonicalMachineLowerer::new();
    let expected_digest = hasher
        .sha256(encoded.bytes(), &never_cancelled)
        .expect("owned aggregate-result frame digest");
    let optimization = OptimizationProfile::from_build_policy(
        &fixture.build.profile.optimization,
        fixture.build.identity.compiler,
    )
    .expect("owned aggregate-result optimization profile");
    let prepare_with = |machine_limits: MachineLoweringLimits, is_cancelled: &dyn Fn() -> bool| {
        prepare_for_codegen(
            BackendPreparationServices {
                codec: &codec,
                hasher: &hasher,
                optimizer: &optimizer,
                machine_lowerer: &machine_lowerer,
            },
            encoded.bytes(),
            expected_digest,
            &fixture.target,
            &fixture.build,
            BackendPreparationOptions {
                codec_limits: CodecLimits::standard(),
                optimization: optimization.clone(),
                optimization_limits: OptimizationLimits::standard(),
                machine_limits,
            },
            is_cancelled,
        )
    };
    let instruction_count = machine
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .map(|block| block.instructions.len() as u64)
        .sum::<u64>();
    let mut exact_limits = MachineLoweringLimits::standard();
    exact_limits.types = machine.types.len() as u64;
    exact_limits.functions = machine.functions.len() as u64;
    exact_limits.sections = machine.sections.len() as u32;
    exact_limits.symbols = machine.symbols.len() as u32;
    exact_limits.globals = machine.globals.len() as u32;
    exact_limits.instructions = instruction_count;
    exact_limits.stack_slots = machine
        .functions
        .iter()
        .map(|function| function.stack_slots.len() as u64)
        .sum::<u64>()
        .max(1);
    exact_limits.proofs = machine.proofs.len() as u32;
    exact_limits.static_bytes = machine
        .sections
        .iter()
        .map(|section| section.reserved_bytes)
        .sum();
    exact_limits.stack_bytes_per_function = machine
        .functions
        .iter()
        .map(|function| function.stack_bytes)
        .max()
        .unwrap_or(0)
        .max(1);
    exact_limits = exact_limits.with_aligned_validation();
    let exact = prepare_with(exact_limits, &never_cancelled)
        .expect("owned aggregate result accepts its exact instruction ceiling");
    assert_eq!(exact.machine().wir().as_wir(), machine);

    let mut one_under = exact_limits;
    one_under.instructions = one_under.instructions.saturating_sub(1);
    one_under = one_under.with_aligned_validation();
    let one_under_error = prepare_with(one_under, &never_cancelled)
        .expect_err("one fewer MachineWir result instruction must fail closed");
    assert_eq!(
        one_under_error.machine_lower_error(),
        Some(&MachineLowerError::ResourceLimit {
            resource: "MachineWir instructions",
            limit: instruction_count - 1,
        })
    );

    let polls = Cell::new(0_u64);
    prepare_with(MachineLoweringLimits::standard(), &|| {
        polls.set(polls.get().saturating_add(1));
        false
    })
    .expect("count owned aggregate-result preparation polls");
    let cancel_at = polls.get().saturating_sub(2);
    assert!(cancel_at > 2);
    let cancelled = Cell::new(0_u64);
    let cancellation = prepare_with(MachineLoweringLimits::standard(), &|| {
        let next = cancelled.get().saturating_add(1);
        cancelled.set(next);
        next >= cancel_at
    })
    .expect_err("late aggregate-result preparation cancellation must propagate");
    assert!(cancellation.is_cancelled());
    assert!(cancelled.get() >= cancel_at);

    match emit_prepared_object(&prepared, &fixture.target, &never_cancelled) {
        Err(CodegenError::BackendNotBuilt) if !llvm_backend_available() => {}
        Err(error) => panic!("two-field result native object emission failed: {error}"),
        Ok(_) if !llvm_backend_available() => {
            panic!("native object emitted while LLVM reports unavailable")
        }
        Ok(first) => {
            let second = emit_prepared_object(&prepared, &fixture.target, &never_cancelled)
                .expect("repeat two-field result native object emission");
            assert_eq!(first.bytes(), second.bytes());
        }
    }
}

#[test]
fn generic_interface_reader_reaches_flow_machine_and_deterministic_coff() {
    let fixture = fixture(
        GENERIC_INTERFACE_READER_SOURCE,
        GENERIC_INTERFACE_READER_TEST_SOURCE,
    );
    let semantic = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed(&fixture),
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("generic-interface reader lowers to SemanticWir");
    let flow = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic.into_parts().0,
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("generic-interface reader lowers to FlowWir");
    let encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: &flow.into_parts().0,
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("generic-interface reader FlowWir canonical frame");
    let prepared = prepare_canonical_frame_for_codegen(
        encoded.bytes(),
        &fixture.target,
        &fixture.build,
        &never_cancelled,
    )
    .expect("generic-interface reader reaches MachineWir");

    match emit_prepared_object(&prepared, &fixture.target, &never_cancelled) {
        Err(CodegenError::BackendNotBuilt) if !llvm_backend_available() => {}
        Err(error) => panic!("generic-interface reader native emission failed: {error}"),
        Ok(_) if !llvm_backend_available() => {
            panic!("native object emitted while LLVM reports unavailable")
        }
        Ok(first) => {
            let second = emit_prepared_object(&prepared, &fixture.target, &never_cancelled)
                .expect("repeat generic-interface reader native emission");
            assert_eq!(first.bytes(), second.bytes());
        }
    }
}

#[test]
fn generic_interface_argument_reaches_flow_machine_and_deterministic_coff() {
    let fixture = fixture(
        GENERIC_INTERFACE_ARGUMENT_SOURCE,
        GENERIC_INTERFACE_ARGUMENT_TEST_SOURCE,
    );
    let semantic = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed(&fixture),
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("generic-interface argument lowers to SemanticWir");
    let flow = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic.into_parts().0,
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("generic-interface argument lowers to FlowWir");
    let encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: &flow.into_parts().0,
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("generic-interface argument FlowWir canonical frame");
    let prepared = prepare_canonical_frame_for_codegen(
        encoded.bytes(),
        &fixture.target,
        &fixture.build,
        &never_cancelled,
    )
    .expect("generic-interface argument reaches MachineWir");

    match emit_prepared_object(&prepared, &fixture.target, &never_cancelled) {
        Err(CodegenError::BackendNotBuilt) if !llvm_backend_available() => {}
        Err(error) => panic!("generic-interface argument native emission failed: {error}"),
        Ok(_) if !llvm_backend_available() => {
            panic!("native object emitted while LLVM reports unavailable")
        }
        Ok(first) => {
            let second = emit_prepared_object(&prepared, &fixture.target, &never_cancelled)
                .expect("repeat generic-interface argument native emission");
            assert_eq!(first.bytes(), second.bytes());
        }
    }
}

#[test]
fn generic_interface_checked_combine_reaches_flow_machine_and_deterministic_coff() {
    let fixture = fixture(
        GENERIC_INTERFACE_COMBINE_SOURCE,
        GENERIC_INTERFACE_COMBINE_TEST_SOURCE,
    );
    let semantic = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed(&fixture),
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("generic-interface checked combine lowers to SemanticWir");
    let flow = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic.into_parts().0,
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("generic-interface checked combine lowers to FlowWir");
    let flow_wir = flow.into_parts().0;
    let mut forged_flow = flow_wir.as_wir().clone();
    let combine = forged_flow
        .functions
        .iter_mut()
        .find(|function| {
            function.parameters.len() == 2
                && matches!(
                    function.blocks.as_slice(),
                    [block] if matches!(
                        block.instructions.as_slice(),
                        [projection, addition]
                            if matches!(projection.operation, FlowOperation::ExtractField { .. })
                                && matches!(addition.operation,
                                    FlowOperation::Binary {
                                        op: FlowBinaryOp::AddChecked,
                                        ..
                                    })
                    )
                )
        })
        .expect("exact FlowWir aggregate checked-combine function");
    let projected = combine.blocks[0].instructions[0].results[0];
    let FlowOperation::Binary { right, .. } = &mut combine.blocks[0].instructions[1].operation
    else {
        panic!("checked-combine FlowWir operation")
    };
    *right = projected;
    let forged_flow = forged_flow
        .validate()
        .expect("checked-combine operand substitution remains structurally valid FlowWir");
    let forged_encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: &forged_flow,
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("forged checked-combine FlowWir canonical frame");
    let forged_error = prepare_canonical_frame_for_codegen(
        forged_encoded.bytes(),
        &fixture.target,
        &fixture.build,
        &never_cancelled,
    )
    .expect_err("Machine lowering must reauthenticate checked-combine operands");
    assert_eq!(
        forged_error.machine_lower_error(),
        Some(&MachineLowerError::UnsupportedInput {
            feature: "machine-flat-structure-operation-lowering-pending",
        })
    );
    let encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: &flow_wir,
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("generic-interface checked combine FlowWir canonical frame");
    let prepared = prepare_canonical_frame_for_codegen(
        encoded.bytes(),
        &fixture.target,
        &fixture.build,
        &never_cancelled,
    )
    .expect("generic-interface checked combine reaches MachineWir");

    match emit_prepared_object(&prepared, &fixture.target, &never_cancelled) {
        Err(CodegenError::BackendNotBuilt) if !llvm_backend_available() => {}
        Err(error) => panic!("generic-interface checked combine native emission failed: {error}"),
        Ok(_) if !llvm_backend_available() => {
            panic!("native object emitted while LLVM reports unavailable")
        }
        Ok(first) => {
            let second = emit_prepared_object(&prepared, &fixture.target, &never_cancelled)
                .expect("repeat generic-interface checked combine native emission");
            assert_eq!(first.bytes(), second.bytes());
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
    .expect("FlowWir v19 enum roundtrip");
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
    let fixture = fixture(DERIVED_EQ_SOURCE, DERIVED_EQ_TEST_SOURCE);
    let output = compile(&fixture, AnalysisLimits::standard(), &never_cancelled)
        .expect("deriving Eq analyzes");
    assert!(
        output.diagnostics().is_empty(),
        "{:?}",
        output.diagnostics()
    );
    assert!(output.successful().is_some());
}

#[test]
fn multifield_derived_eq_is_accepted() {
    let fixture = fixture(
        MULTIFIELD_DERIVED_EQ_SOURCE,
        MULTIFIELD_DERIVED_EQ_TEST_SOURCE,
    );
    let output = compile(&fixture, AnalysisLimits::standard(), &never_cancelled)
        .expect("multi-field deriving Eq analysis remains bounded");
    assert!(
        output.diagnostics().is_empty(),
        "{:?}",
        output.diagnostics()
    );
    assert!(output.successful().is_some());
}

#[test]
fn multifield_derived_eq_reaches_deterministic_native_coff() {
    let fixture = fixture(
        MULTIFIELD_DERIVED_EQ_SOURCE,
        MULTIFIELD_DERIVED_EQ_TEST_SOURCE,
    );
    let analyzed = analyzed(&fixture);
    let semantic = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed.clone(),
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("derived equality lowers to SemanticWir");
    let repeated_semantic = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed,
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("repeat derived equality lowering");
    assert_eq!(semantic.wir().as_wir(), repeated_semantic.wir().as_wir());

    let mut semantic_projects = 0;
    let mut semantic_equal = 0;
    let mut semantic_conjunctions = 0;
    let mut semantic_negations = 0;
    for statement in semantic
        .wir()
        .as_wir()
        .functions
        .iter()
        .flat_map(|function| &function.body.statements)
    {
        let LoweredSemanticStatement::Let(statement) = statement else {
            continue;
        };
        match statement.operation {
            SemanticOperation::Project {
                access: wrela_semantic_lower::SemanticAccessMode::Read,
                ..
            } => semantic_projects += 1,
            SemanticOperation::Binary {
                operator: wrela_semantic_lower::semantic_wir::BinaryOperator::Equal,
                arithmetic: SemanticArithmeticMode::Checked,
                ..
            } => semantic_equal += 1,
            SemanticOperation::Binary {
                operator: wrela_semantic_lower::semantic_wir::BinaryOperator::BitAnd,
                arithmetic: SemanticArithmeticMode::Checked,
                ..
            } => semantic_conjunctions += 1,
            SemanticOperation::Unary {
                operator: wrela_semantic_lower::semantic_wir::UnaryOperator::BoolNot,
                arithmetic: SemanticArithmeticMode::Checked,
                ..
            } => semantic_negations += 1,
            _ => {}
        }
    }
    assert_eq!(
        semantic_projects, 10,
        "two derived comparisons project both fields of both operands and equality preserves both operands for post-comparison reads"
    );
    assert_eq!(
        (semantic_equal, semantic_conjunctions, semantic_negations),
        (4, 2, 1)
    );

    let (semantic_wir, _) = semantic.into_parts();
    let flow = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic_wir,
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("derived equality lowers to FlowWir");
    assert!(flow.diagnostics().is_empty());
    let flow_model = flow.wir().as_wir();
    let flow_projects = flow_model
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .flat_map(|block| &block.instructions)
        .filter(|instruction| matches!(instruction.operation, FlowOperation::ExtractField { .. }))
        .count();
    let flow_equal = flow_model
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .flat_map(|block| &block.instructions)
        .filter(|instruction| {
            matches!(
                instruction.operation,
                FlowOperation::Binary {
                    op: FlowBinaryOp::Equal,
                    ..
                }
            )
        })
        .count();
    let flow_conjunctions = flow_model
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .flat_map(|block| &block.instructions)
        .filter(|instruction| {
            matches!(
                instruction.operation,
                FlowOperation::Binary {
                    op: FlowBinaryOp::BitAnd,
                    ..
                }
            )
        })
        .count();
    assert_eq!(flow_projects, 10);
    assert_eq!((flow_equal, flow_conjunctions), (4, 2));

    let (flow_wir, _, _) = flow.into_parts();
    let encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: &flow_wir,
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("derived equality FlowWir canonical frame");
    let decoded = CanonicalFlowWirCodec
        .decode(
            DecodeRequest {
                bytes: encoded.bytes(),
                limits: CodecLimits::standard(),
                expected_build: Some(fixture.build.identity()),
            },
            &never_cancelled,
        )
        .expect("derived equality FlowWir decode");
    assert_eq!(decoded, flow_wir);

    let prepared = prepare_canonical_frame_for_codegen(
        encoded.bytes(),
        &fixture.target,
        &fixture.build,
        &never_cancelled,
    )
    .expect("derived equality reaches MachineWir");
    let machine = prepared.machine().wir().as_wir();
    let comparisons = machine
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .flat_map(|block| &block.instructions)
        .filter(|instruction| {
            matches!(
                instruction.operation,
                MachineOperation::IntegerCompare { .. }
            )
        })
        .count();
    assert_eq!(comparisons, 4, "every field pair reaches machine equality");

    match emit_prepared_object(&prepared, &fixture.target, &never_cancelled) {
        Err(CodegenError::BackendNotBuilt) if !llvm_backend_available() => {}
        Err(error) => panic!("derived equality native object emission failed: {error}"),
        Ok(_) if !llvm_backend_available() => {
            panic!("native object emitted while LLVM reports unavailable")
        }
        Ok(first) => {
            let second = emit_prepared_object(&prepared, &fixture.target, &never_cancelled)
                .expect("repeat derived equality native object emission");
            assert_eq!(
                first.bytes(),
                second.bytes(),
                "identical derived equality MachineWir must emit byte-identical ARM64 COFF"
            );
        }
    }
}

#[test]
fn derived_eq_rejects_unmarked_and_unsupported_shapes_by_name() {
    let cases = [(
        r#"module app.duration
pub struct Point:
    pub value: u64
pub fn make(value: u64) -> Point:
    return Point(value=value)
pub fn same(read left: Point, read right: Point) -> bool:
    return left == right
"#,
        r#"module app.duration_test
from app.duration import Point, make, same
@test(runtime)
fn unmarked_equality():
    first: Point = make(1)
    second: Point = make(1)
    equal: bool = same(left=first, right=second)
    return
"#,
        "semantic-derived-eq-required",
    )];
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
            .expect("derived equality rejection remains bounded");
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
fn deriving_from_rejects_a_single_multifield_payload_variant() {
    let fixture = fixture(
        r#"module app.duration
pub enum PairResult deriving(From):
    Pair(u64, u64,)
"#,
        r#"module app.duration_test
@test(runtime)
fn unused():
    return
"#,
    );
    assert!(
        fixture.discovery_diagnostics.iter().any(|diagnostic| {
            diagnostic.code.as_deref() == Some("semantic-deriving-from-shape")
        }),
        "{:?}",
        fixture.discovery_diagnostics
    );
}

#[test]
fn single_variant_scalar_derived_from_analyzes_and_lowers_exactly() {
    let fixture = fixture(DERIVED_FROM_SOURCE, DERIVED_FROM_TEST_SOURCE);
    let analyzed = analyzed(&fixture);
    let conversion = analyzed
        .facts()
        .expressions
        .iter()
        .find(|fact| {
            matches!(
                fact.resolution,
                wrela_sema::ExpressionResolution::DerivedFrom { .. }
            )
        })
        .expect("derived From conversion fact");
    assert!(matches!(
        analyzed
            .facts()
            .types
            .get(conversion.ty.0 as usize)
            .map(|ty| &ty.kind),
        Some(SemanticTypeKind::Enumeration { variants, .. })
            if matches!(variants.as_slice(), [variant] if variant.fields.len() == 1)
    ));
    let lowered = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed,
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("derived From lowers to SemanticWir");
    assert!(lowered.wir().as_wir().functions.iter().any(|function| {
        function.body.statements.iter().any(|statement| {
            matches!(
                statement,
                LoweredSemanticStatement::Let(statement)
                    if matches!(statement.operation, SemanticOperation::ConstructEnum {
                        variant: 0,
                        payload: Some(_),
                        ..
                    })
            )
        })
    }));
}

#[test]
fn generated_scalar_from_reaches_flow_machine_and_deterministic_native_coff() {
    let fixture = fixture(DERIVED_FROM_NATIVE_SOURCE, DERIVED_FROM_NATIVE_TEST_SOURCE);
    let analyzed = analyzed(&fixture);
    assert_eq!(
        analyzed
            .facts()
            .expressions
            .iter()
            .filter(|fact| matches!(
                fact.resolution,
                wrela_sema::ExpressionResolution::DerivedFrom { .. }
            ))
            .count(),
        1,
        "only the generated conversion carries derived-From source authority"
    );
    assert_eq!(
        analyzed
            .facts()
            .expressions
            .iter()
            .filter(|fact| matches!(
                fact.resolution,
                wrela_sema::ExpressionResolution::Constructor {
                    variant: Some(0),
                    ..
                }
            ))
            .count(),
        2,
        "the adjacent direct constructor retains its callee and value witnesses"
    );
    let semantic = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed,
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("generated From lowers to SemanticWir");
    let semantic_model = semantic.wir().as_wir();
    let semantic_constructors = semantic_model
        .functions
        .iter()
        .filter(|function| {
            function.name.ends_with("convert") || function.name.ends_with("construct")
        })
        .map(|function| {
            function
                .body
                .statements
                .iter()
                .find_map(|statement| match statement {
                    LoweredSemanticStatement::Let(statement) => match statement.operation {
                        SemanticOperation::ConstructEnum {
                            ty,
                            variant: 0,
                            payload: Some(_),
                        } => Some(ty),
                        _ => None,
                    },
                    _ => None,
                })
                .expect("conversion helper has one canonical enum construction")
        })
        .collect::<Vec<_>>();
    assert_eq!(semantic_constructors.len(), 2);
    assert_eq!(semantic_constructors[0], semantic_constructors[1]);

    // From this boundary onward both expressions intentionally share the same
    // canonical constructor representation. The source/sema authority above,
    // not an invented downstream provenance bit, distinguishes their origin.
    let semantic_wir = semantic.into_parts().0;
    let flow = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic_wir.clone(),
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("generated From reaches FlowWir");
    assert_eq!(
        flow.wir()
            .as_wir()
            .functions
            .iter()
            .flat_map(|function| &function.blocks)
            .flat_map(|block| &block.instructions)
            .filter(|instruction| matches!(instruction.operation, FlowOperation::MakeEnum { .. }))
            .count(),
        2,
        "generated conversion and direct construction must each reach FlowWir"
    );
    let milliseconds = flow
        .wir()
        .as_wir()
        .types
        .iter()
        .find(|ty| ty.name.as_deref() == Some("Milliseconds"))
        .expect("Milliseconds FlowWir type");
    assert!(matches!(
        &milliseconds.kind,
        FlowTypeKind::Enum { variants }
            if matches!(variants.as_slice(), [variant] if variant.len() == 1)
    ));
    assert!(
        flow.wir()
            .as_wir()
            .functions
            .iter()
            .flat_map(|function| &function.blocks)
            .flat_map(|block| &block.instructions)
            .filter_map(|instruction| match instruction.operation {
                FlowOperation::MakeEnum {
                    ty,
                    variant: 0,
                    payload: Some(_),
                } => Some(ty),
                _ => None,
            })
            .all(|ty| ty == milliseconds.id)
    );

    let flow_instruction_count = flow.report().instructions;
    let mut exact_flow_limits = FlowLoweringLimits::standard();
    exact_flow_limits.instructions = flow_instruction_count;
    CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic_wir.clone(),
                limits: exact_flow_limits,
            },
            &never_cancelled,
        )
        .expect("generated From accepts its exact FlowWir instruction ceiling");
    let mut one_under_flow = exact_flow_limits;
    one_under_flow.instructions = flow_instruction_count - 1;
    assert!(matches!(
        CanonicalFlowLowerer::new().lower(
            FlowLowerRequest {
                input: semantic_wir.clone(),
                limits: one_under_flow,
            },
            &never_cancelled,
        ),
        Err(FlowLowerError::ResourceLimit {
            resource: "FlowWir instructions",
            limit,
        }) if limit == flow_instruction_count - 1
    ));
    let flow_polls = Cell::new(0_u64);
    CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic_wir.clone(),
                limits: exact_flow_limits,
            },
            &|| {
                flow_polls.set(flow_polls.get().saturating_add(1));
                false
            },
        )
        .expect("count generated From FlowWir cancellation polls");
    let flow_cancel_at = flow_polls.get().saturating_sub(2);
    assert!(flow_cancel_at > 2);
    let cancelled_flow_polls = Cell::new(0_u64);
    assert!(matches!(
        CanonicalFlowLowerer::new().lower(
            FlowLowerRequest {
                input: semantic_wir,
                limits: exact_flow_limits,
            },
            &|| {
                let next = cancelled_flow_polls.get().saturating_add(1);
                cancelled_flow_polls.set(next);
                next >= flow_cancel_at
            },
        ),
        Err(FlowLowerError::Cancelled)
    ));

    let flow_wir = flow.into_parts().0;
    let mut forged_flow = flow_wir.as_wir().clone();
    let forged_variant = forged_flow
        .functions
        .iter_mut()
        .flat_map(|function| &mut function.blocks)
        .flat_map(|block| &mut block.instructions)
        .find_map(|instruction| match &mut instruction.operation {
            FlowOperation::MakeEnum { variant, .. } => Some(variant),
            _ => None,
        })
        .expect("mutable generated From FlowWir constructor");
    *forged_variant = 1;
    assert!(
        forged_flow.validate().is_err(),
        "FlowWir must reject a forged generated-conversion variant"
    );
    let encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: &flow_wir,
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("generated From canonical FlowWir frame");
    let decoded = CanonicalFlowWirCodec
        .decode(
            DecodeRequest {
                bytes: encoded.bytes(),
                limits: CodecLimits::standard(),
                expected_build: Some(fixture.build.identity()),
            },
            &never_cancelled,
        )
        .expect("generated From canonical FlowWir decode");
    assert_eq!(decoded, flow_wir);

    let prepared = prepare_canonical_frame_for_codegen(
        encoded.bytes(),
        &fixture.target,
        &fixture.build,
        &never_cancelled,
    )
    .expect("generated From reaches MachineWir");
    let machine = prepared.machine().wir().as_wir();
    let milliseconds = machine
        .types
        .iter()
        .find(|ty| ty.source_name.as_deref() == Some("Milliseconds"))
        .expect("Milliseconds MachineWir type");
    assert!(matches!(
        &milliseconds.kind,
        MachineTypeKind::TaggedEnum {
            variants: 1,
            payload: Some(_),
            storage: None,
            variant_payloads,
            ..
        } if variant_payloads.len() == 1
    ));
    let machine_constructors = machine
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .flat_map(|block| &block.instructions)
        .filter(|instruction| {
            matches!(
                instruction.operation,
                MachineOperation::MakeEnum {
                    ty,
                    variant: 0,
                    payload: Some(_),
                } if ty == milliseconds.id
            )
        })
        .count();
    assert_eq!(machine_constructors, 2);
    let mut forged_machine = machine.clone();
    let forged_variant = forged_machine
        .functions
        .iter_mut()
        .flat_map(|function| &mut function.blocks)
        .flat_map(|block| &mut block.instructions)
        .find_map(|instruction| match &mut instruction.operation {
            MachineOperation::MakeEnum { variant, .. } => Some(variant),
            _ => None,
        })
        .expect("mutable generated From MachineWir constructor");
    *forged_variant = 1;
    assert!(
        forged_machine.validate_for_target(&fixture.target).is_err(),
        "MachineWir must reject a forged generated-conversion variant"
    );

    let codec = CanonicalFlowWirCodec;
    let hasher = CanonicalBackendContentHasher::new();
    let optimizer = CanonicalFlowOptimizer::new();
    let machine_lowerer = CanonicalMachineLowerer::new();
    let expected_digest = hasher
        .sha256(encoded.bytes(), &never_cancelled)
        .expect("generated From frame digest");
    let optimization = OptimizationProfile::from_build_policy(
        &fixture.build.profile.optimization,
        fixture.build.identity.compiler,
    )
    .expect("generated From optimization profile");
    let prepare_with = |machine_limits: MachineLoweringLimits, is_cancelled: &dyn Fn() -> bool| {
        prepare_for_codegen(
            BackendPreparationServices {
                codec: &codec,
                hasher: &hasher,
                optimizer: &optimizer,
                machine_lowerer: &machine_lowerer,
            },
            encoded.bytes(),
            expected_digest,
            &fixture.target,
            &fixture.build,
            BackendPreparationOptions {
                codec_limits: CodecLimits::standard(),
                optimization: optimization.clone(),
                optimization_limits: OptimizationLimits::standard(),
                machine_limits,
            },
            is_cancelled,
        )
    };
    let instruction_count = machine
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .map(|block| block.instructions.len() as u64)
        .sum::<u64>();
    let mut exact_machine_limits = MachineLoweringLimits::standard();
    exact_machine_limits.types = machine.types.len() as u64;
    exact_machine_limits.functions = machine.functions.len() as u64;
    exact_machine_limits.sections = machine.sections.len() as u32;
    exact_machine_limits.symbols = machine.symbols.len() as u32;
    exact_machine_limits.globals = machine.globals.len() as u32;
    exact_machine_limits.instructions = instruction_count;
    exact_machine_limits.stack_slots = machine
        .functions
        .iter()
        .map(|function| function.stack_slots.len() as u64)
        .sum::<u64>()
        .max(1);
    exact_machine_limits.proofs = machine.proofs.len() as u32;
    exact_machine_limits.static_bytes = machine
        .sections
        .iter()
        .map(|section| section.reserved_bytes)
        .sum();
    exact_machine_limits.stack_bytes_per_function = machine
        .functions
        .iter()
        .map(|function| function.stack_bytes)
        .max()
        .unwrap_or(0)
        .max(1);
    exact_machine_limits = exact_machine_limits.with_aligned_validation();
    let exact = prepare_with(exact_machine_limits, &never_cancelled)
        .expect("generated From accepts its exact MachineWir ceiling");
    assert_eq!(exact.machine().wir().as_wir(), machine);
    let mut one_under_machine = exact_machine_limits;
    one_under_machine.instructions -= 1;
    one_under_machine = one_under_machine.with_aligned_validation();
    let one_under_error = prepare_with(one_under_machine, &never_cancelled)
        .expect_err("one fewer generated From MachineWir instruction must fail");
    assert_eq!(
        one_under_error.machine_lower_error(),
        Some(&MachineLowerError::ResourceLimit {
            resource: "MachineWir instructions",
            limit: instruction_count - 1,
        })
    );
    let machine_polls = Cell::new(0_u64);
    prepare_with(MachineLoweringLimits::standard(), &|| {
        machine_polls.set(machine_polls.get().saturating_add(1));
        false
    })
    .expect("count generated From MachineWir cancellation polls");
    let machine_cancel_at = machine_polls.get().saturating_sub(2);
    assert!(machine_cancel_at > 2);
    let cancelled_machine_polls = Cell::new(0_u64);
    let cancellation = prepare_with(MachineLoweringLimits::standard(), &|| {
        let next = cancelled_machine_polls.get().saturating_add(1);
        cancelled_machine_polls.set(next);
        next >= machine_cancel_at
    })
    .expect_err("late generated From MachineWir cancellation must propagate");
    assert!(cancellation.is_cancelled());

    match emit_prepared_object(&prepared, &fixture.target, &never_cancelled) {
        Err(CodegenError::BackendNotBuilt) if !llvm_backend_available() => {}
        Err(error) => panic!("generated From native object emission failed: {error}"),
        Ok(_) if !llvm_backend_available() => {
            panic!("native object emitted while LLVM reports unavailable")
        }
        Ok(first) => {
            let second = emit_prepared_object(&prepared, &fixture.target, &never_cancelled)
                .expect("repeat generated From native object emission");
            assert_eq!(
                first.bytes(),
                second.bytes(),
                "identical generated From MachineWir emits byte-identical ARM64 COFF"
            );
        }
    }
}

#[test]
fn derived_from_full_seal_rejects_nominal_variant_payload_and_witness_forgeries() {
    let analyzed = analyzed(&fixture(DERIVED_FROM_SOURCE, DERIVED_FROM_TEST_SOURCE));

    let mut wrong_variant = analyzed.facts().clone();
    let variant = wrong_variant
        .expressions
        .iter_mut()
        .find_map(|fact| match &mut fact.resolution {
            wrela_sema::ExpressionResolution::DerivedFrom { variant, .. } => Some(variant),
            _ => None,
        })
        .expect("derived From fact");
    *variant = 1;
    assert!(
        wrong_variant
            .validate_for_seal(analyzed.hir(), &never_cancelled)
            .is_err()
    );

    let mut wrong_payload = analyzed.facts().clone();
    let result = wrong_payload
        .expressions
        .iter()
        .find_map(|fact| match fact.resolution {
            wrela_sema::ExpressionResolution::DerivedFrom { .. } => fact.result,
            _ => None,
        })
        .expect("derived From result");
    let payload = wrong_payload
        .expressions
        .iter_mut()
        .find_map(|fact| match &mut fact.resolution {
            wrela_sema::ExpressionResolution::DerivedFrom { payload, .. } => Some(payload),
            _ => None,
        })
        .expect("derived From payload");
    *payload = result;
    assert!(
        wrong_payload
            .validate_for_seal(analyzed.hir(), &never_cancelled)
            .is_err()
    );

    let mut wrong_witness = analyzed.facts().clone();
    let witness_variant = wrong_witness
        .expressions
        .iter_mut()
        .find_map(|fact| match &mut fact.resolution {
            wrela_sema::ExpressionResolution::DerivedFromFunction { variant, .. } => Some(variant),
            _ => None,
        })
        .expect("derived From associated witness");
    *witness_variant = 1;
    assert!(
        wrong_witness
            .validate_for_seal(analyzed.hir(), &never_cancelled)
            .is_err()
    );
}

#[test]
fn derived_from_lowering_has_exact_operation_bound_and_late_cancellation() {
    let analyzed = analyzed(&fixture(DERIVED_FROM_SOURCE, DERIVED_FROM_TEST_SOURCE));
    let baseline = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed.clone(),
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("baseline derived From lowering");
    let exact = baseline.report().operations;
    assert!(exact > 0);
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
        .expect("exact derived From operation bound is admitted");
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

    let polls = Cell::new(0_u32);
    CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed.clone(),
                limits: SemanticLoweringLimits::standard(),
            },
            &|| {
                polls.set(polls.get().saturating_add(1));
                false
            },
        )
        .expect("count derived From cancellation polls");
    let cancel_at = polls.get().saturating_sub(2);
    let cancelled = Cell::new(0_u32);
    assert!(matches!(
        CanonicalSemanticLowerer::new().lower(
            SemanticLowerRequest {
                input: analyzed,
                limits: SemanticLoweringLimits::standard(),
            },
            &|| {
                let next = cancelled.get().saturating_add(1);
                cancelled.set(next);
                next >= cancel_at
            },
        ),
        Err(SemanticLowerError::Cancelled)
    ));
    assert!(cancelled.get() >= cancel_at);
}

#[test]
fn derived_from_adjacent_shapes_and_labels_fail_closed_by_name() {
    let cases = [
        (
            r#"module app.duration
pub enum Ambiguous deriving(From):
    first(u64,)
    second(u64,)
"#,
            r#"module app.duration_test
@test(runtime)
fn unused():
    return
"#,
            "semantic-deriving-from-shape",
        ),
        (
            r#"module app.duration
pub enum Plain:
    value(u64,)
pub fn convert(value: u64) -> Plain:
    return Plain.from(value)
"#,
            r#"module app.duration_test
from app.duration import Plain, convert
@test(runtime)
fn rejected():
    converted: Plain = convert(1)
    return
"#,
            "semantic-derived-from-required",
        ),
        (
            r#"module app.duration
pub enum Wrapped deriving(From):
    value(u64,)
pub fn convert(value: u64) -> Wrapped:
    return Wrapped.from(value=value)
"#,
            r#"module app.duration_test
from app.duration import Wrapped, convert
@test(runtime)
fn rejected():
    converted: Wrapped = convert(1)
    return
"#,
            "semantic-argument-label-forbidden",
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
            .expect("derived From rejection remains bounded");
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
fn derived_eq_full_seal_rejects_field_and_intermediate_forgeries() {
    let analyzed = analyzed(&fixture(DERIVED_EQ_SOURCE, DERIVED_EQ_TEST_SOURCE));
    let mut wrong_field = analyzed.facts().clone();
    let resolution = wrong_field
        .expressions
        .iter_mut()
        .find_map(|fact| match &mut fact.resolution {
            wrela_sema::ExpressionResolution::DerivedEquality { fields, .. } => {
                fields.first_mut().map(|field| &mut field.field)
            }
            _ => None,
        })
        .expect("derived equality fact");
    *resolution = 1;
    assert!(
        wrong_field
            .validate_for_seal(analyzed.hir(), &never_cancelled)
            .is_err()
    );

    let mut aliased_intermediate = analyzed.facts().clone();
    let (left_field, right_field) = aliased_intermediate
        .expressions
        .iter_mut()
        .find_map(|fact| match &mut fact.resolution {
            wrela_sema::ExpressionResolution::DerivedEquality { fields, .. } => fields
                .first_mut()
                .map(|field| (field.left, &mut field.right)),
            _ => None,
        })
        .expect("derived equality intermediates");
    *right_field = left_field;
    assert!(
        aliased_intermediate
            .validate_for_seal(analyzed.hir(), &never_cancelled)
            .is_err()
    );
}

#[test]
fn multifield_derived_eq_full_seal_rejects_order_and_fold_forgeries() {
    let analyzed = analyzed(&fixture(
        MULTIFIELD_DERIVED_EQ_SOURCE,
        MULTIFIELD_DERIVED_EQ_TEST_SOURCE,
    ));

    let mut reordered = analyzed.facts().clone();
    reordered
        .expressions
        .iter_mut()
        .find_map(|fact| match &mut fact.resolution {
            wrela_sema::ExpressionResolution::DerivedEquality { fields, .. }
                if fields.len() == 2 =>
            {
                fields.swap(0, 1);
                Some(())
            }
            _ => None,
        })
        .expect("multi-field derived equality fact");
    assert!(
        reordered
            .validate_for_seal(analyzed.hir(), &never_cancelled)
            .is_err()
    );

    let mut aliased_comparison = analyzed.facts().clone();
    aliased_comparison
        .expressions
        .iter_mut()
        .find_map(|fact| match &mut fact.resolution {
            wrela_sema::ExpressionResolution::DerivedEquality { fields, .. }
                if fields.len() == 2 =>
            {
                fields[1].comparison = fields[0].comparison;
                Some(())
            }
            _ => None,
        })
        .expect("multi-field comparison chain");
    assert!(
        aliased_comparison
            .validate_for_seal(analyzed.hir(), &never_cancelled)
            .is_err()
    );

    let mut aliased_conjunction = analyzed.facts().clone();
    aliased_conjunction
        .expressions
        .iter_mut()
        .find_map(|fact| match &mut fact.resolution {
            wrela_sema::ExpressionResolution::DerivedEquality {
                fields,
                conjunctions,
                ..
            } if fields.len() == 2 && conjunctions.len() == 1 => {
                conjunctions[0] = fields[0].comparison;
                Some(())
            }
            _ => None,
        })
        .expect("multi-field conjunction chain");
    assert!(
        aliased_conjunction
            .validate_for_seal(analyzed.hir(), &never_cancelled)
            .is_err()
    );
}

#[test]
fn derived_eq_lowering_has_exact_operation_bound_and_late_cancellation() {
    let analyzed = analyzed(&fixture(DERIVED_EQ_SOURCE, DERIVED_EQ_TEST_SOURCE));
    let baseline = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed.clone(),
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("baseline derived equality lowering");
    let exact = baseline.report().operations;
    assert!(exact > 1);
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
        .expect("exact derived equality operation bound is admitted");
    let mut one_under = exact_limits;
    one_under.operations = exact - 1;
    assert!(matches!(
        CanonicalSemanticLowerer::new().lower(
            SemanticLowerRequest {
                input: analyzed.clone(),
                limits: one_under,
            },
            &never_cancelled,
        ),
        Err(SemanticLowerError::ResourceLimit {
            resource: "SemanticWir operations",
            limit,
        }) if limit == exact - 1
    ));

    let polls = Cell::new(0_u32);
    CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed.clone(),
                limits: SemanticLoweringLimits::standard(),
            },
            &|| {
                polls.set(polls.get().saturating_add(1));
                false
            },
        )
        .expect("count derived equality cancellation polls");
    let cancel_at = polls.get().saturating_sub(2);
    let cancelled = Cell::new(0_u32);
    assert!(matches!(
        CanonicalSemanticLowerer::new().lower(
            SemanticLowerRequest {
                input: analyzed,
                limits: SemanticLoweringLimits::standard(),
            },
            &|| {
                let next = cancelled.get().saturating_add(1);
                cancelled.set(next);
                next >= cancel_at
            },
        ),
        Err(SemanticLowerError::Cancelled)
    ));
    assert!(cancelled.get() >= cancel_at);
}
