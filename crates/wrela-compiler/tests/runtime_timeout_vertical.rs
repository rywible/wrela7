#![forbid(unsafe_code)]

use std::sync::Arc;

use wrela_backend::{
    flow_wir::{FlowFunction, FlowWir, ScalarType},
    machine_wir::{
        CheckedIntegerOp, IntegerSignedness, MachineOperation, MachineTypeKind, ScalarFailureKind,
    },
    prepare_canonical_frame_for_codegen,
};
use wrela_build_model::{
    BuildConfiguration, BuildIdentity, BuildProfile, LanguageRevision, Sha256Digest,
    TargetIdentity, seal_build_configuration,
};
use wrela_flow_lower::{
    CanonicalFlowLowerer, FlowBinaryOp, FlowLowerer, FlowOperation, FlowTypeKind,
    LowerRequest as FlowLowerRequest, LoweringLimits as FlowLoweringLimits,
};
use wrela_flow_wir_codec::{CanonicalFlowWirCodec, CodecLimits, EncodeRequest, encode_and_verify};
use wrela_hir_lower::{
    CanonicalHirLowerer, ChangeSet as HirChangeSet, HirLowerer, LowerRequest as HirLowerRequest,
    LoweringLimits as HirLoweringLimits,
};
use wrela_package::{DependencyAlias, ModulePath, PackageGraphBuilder, PackageIdentity};
use wrela_package_loader::{
    CanonicalPackageCodec, ContentHasher, ManifestCodecLimits, PackageCodec, PackageContentKind,
    PackageContentRecord, SoftwareSha256, package_content_digest,
};
use wrela_sema::{
    AnalysisChangeSet, AnalysisLimits, AnalysisMode, AnalysisRequest, CanonicalSemanticAnalyzer,
    SemanticAnalyzer, TestDiscoverySelection,
};
use wrela_semantic_lower::{
    CanonicalSemanticLowerer, LowerRequest as SemanticLowerRequest,
    LoweringLimits as SemanticLoweringLimits, SemanticLowerer,
};
use wrela_source::{FileId, SourceDatabase, SourceInput};
use wrela_syntax::{ParseLimits, ParseRequest, SyntaxParser, WrelaSyntaxParser};
use wrela_target::TargetPackage;
use wrela_test_model::{TestId, TestKind};

const WORKSPACE_MANIFEST: &[u8] =
    include_bytes!("../../../std/examples/runtime-timeout/wrela.toml");
const APPLICATION_SOURCE: &str =
    include_str!("../../../std/examples/runtime-timeout/src/runtime_timeout/image.wr");
const CORE_MANIFEST: &[u8] = include_bytes!("../../../std/wrela-core-0.1/wrela.toml");
const CORE_IMAGE_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/image.wr");
const CORE_OPS_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/ops.wr");
const CORE_RESULT_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/result.wr");
const CORE_TIME_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/time.wr");
const IMAGE_NAME: &str = "runtime-timeout";
const SELECTOR: &str = "checked_arithmetic_fatal_times_out";
const TEST_FUNCTION: &str =
    "runtime-timeout@0.1.0::runtime_timeout.image::checked_arithmetic_fatal_times_out";
const CHECKED_ADD_FUNCTION: &str = "runtime-timeout@0.1.0::runtime_timeout.image::checked_add";
const SOURCE_PATHS: [&str; 4] = [
    "core/image.wr",
    "core/ops.wr",
    "core/time.wr",
    "runtime_timeout/image.wr",
];

static HASHER: SoftwareSha256 = SoftwareSha256;

fn never_cancelled() -> bool {
    false
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

fn content_record<'a>(path: &'a str, source: &str) -> PackageContentRecord<'a> {
    PackageContentRecord {
        kind: PackageContentKind::Source,
        path,
        digest: HASHER.sha256(source.as_bytes()),
    }
}

fn add_source(sources: &mut SourceDatabase, path: &str, text: &str) -> FileId {
    sources
        .add(SourceInput {
            path: path.to_owned(),
            text: text.to_owned(),
            digest: HASHER.sha256(text.as_bytes()),
        })
        .expect("fixture source")
}

fn assert_unsigned_u8_flow_type(
    model: &FlowWir,
    function: &FlowFunction,
    value: wrela_backend::flow_wir::ValueId,
) {
    let ty = function.values[value.0 as usize].ty;
    assert_eq!(
        model.types[ty.0 as usize].kind,
        FlowTypeKind::Scalar(ScalarType::Integer {
            signed: false,
            bits: 8,
        })
    );
}

#[test]
fn checked_in_runtime_timeout_retains_reachable_checked_u8_add_and_fatal_edge() {
    let codec = CanonicalPackageCodec::new();
    let manifest = codec
        .decode_manifest(WORKSPACE_MANIFEST, manifest_limits(), &never_cancelled)
        .expect("checked-in runtime-timeout manifest");
    // The checked-in manifest declares only `[[profile]]` overrides and no
    // `[[module]]` block (modules are derived by the loader from a
    // source-root walk, not decoded here), so it need not be byte-identical
    // to its own canonical re-encoding; decode -> canonical -> decode must
    // still be a fixed point, and every digest below binds the canonical
    // bytes exactly as the production loader does.
    let canonical_manifest = codec
        .canonical_manifest(&manifest, manifest_limits(), &never_cancelled)
        .expect("canonical runtime-timeout manifest");
    assert_eq!(
        codec
            .decode_manifest(&canonical_manifest, manifest_limits(), &never_cancelled)
            .expect("redecode canonical runtime-timeout manifest"),
        manifest
    );
    assert_eq!(manifest.name.as_str(), IMAGE_NAME);
    assert_eq!(manifest.images.len(), 1);
    assert_eq!(manifest.images[0].name, IMAGE_NAME);
    assert_eq!(manifest.images[0].module.dotted(), "runtime_timeout.image");

    let root_identity = PackageIdentity {
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        source_digest: package_content_digest(
            &canonical_manifest,
            &[content_record(
                "runtime_timeout/image.wr",
                APPLICATION_SOURCE,
            )],
            &HASHER,
            &never_cancelled,
        )
        .expect("runtime-timeout package identity"),
    };
    let core_manifest = codec
        .decode_manifest(CORE_MANIFEST, manifest_limits(), &never_cancelled)
        .expect("checked-in core manifest");
    let canonical_core_manifest = codec
        .canonical_manifest(&core_manifest, manifest_limits(), &never_cancelled)
        .expect("canonical core manifest");
    assert_eq!(
        codec
            .decode_manifest(
                &canonical_core_manifest,
                manifest_limits(),
                &never_cancelled
            )
            .expect("redecode canonical core manifest"),
        core_manifest
    );
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
    // There is no lockfile to also cross-check these identities against:
    // they are exactly what the loader computes at load time, independently
    // recomputed here from the same checked-in manifests and sources.
    assert_eq!(
        APPLICATION_SOURCE
            .matches(&format!("fn {SELECTOR}():"))
            .count(),
        1
    );
    assert_eq!(APPLICATION_SOURCE.matches("fn checked_add(").count(), 1);
    assert_eq!(APPLICATION_SOURCE.matches("return left + right").count(), 1);

    let mut sources = SourceDatabase::default();
    let core_image_file = add_source(&mut sources, SOURCE_PATHS[0], CORE_IMAGE_SOURCE);
    let core_ops_file = add_source(&mut sources, SOURCE_PATHS[1], CORE_OPS_SOURCE);
    let core_time_file = add_source(&mut sources, SOURCE_PATHS[2], CORE_TIME_SOURCE);
    let application_file = add_source(&mut sources, SOURCE_PATHS[3], APPLICATION_SOURCE);
    let mut graph = PackageGraphBuilder::new(root_identity.clone());
    let core = graph
        .add_package(core_identity.clone())
        .expect("core package graph node");
    graph
        .add_dependency(
            graph.root(),
            DependencyAlias::new("core").expect("core alias"),
            core,
        )
        .expect("root core dependency");
    graph
        .add_module(
            graph.root(),
            ModulePath::new(["runtime_timeout".to_owned(), "image".to_owned()])
                .expect("application module path"),
            application_file,
        )
        .expect("application module");
    graph
        .add_module(
            core,
            ModulePath::new(["image".to_owned()]).expect("core image module path"),
            core_image_file,
        )
        .expect("core image module");
    graph
        .add_module(
            core,
            ModulePath::new(["ops".to_owned()]).expect("core ops module path"),
            core_ops_file,
        )
        .expect("core ops module");
    graph
        .add_module(
            core,
            ModulePath::new(["time".to_owned()]).expect("core time module path"),
            core_time_file,
        )
        .expect("core time module");

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
                .expect("runtime-timeout source parses")
                .into_parts();
            assert!(diagnostics.is_empty(), "parse diagnostics: {diagnostics:?}");
            parsed
        })
        .collect::<Vec<_>>();
    let hir_output = CanonicalHirLowerer::new()
        .lower(
            HirLowerRequest {
                packages: Arc::new(graph.finish().expect("package graph")),
                source_graph_digest: root_identity.source_digest,
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
        .expect("runtime-timeout source lowers to HIR");
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
        .expect("runtime-timeout image entry");
    let hir = Arc::new(hir_output.into_parts().0.into_program());

    let profile_digest = Sha256Digest::from_bytes([0xb1; 32]);
    let target_digest = Sha256Digest::from_bytes([0xb2; 32]);
    let build = seal_build_configuration(
        BuildConfiguration {
            identity: BuildIdentity {
                compiler: Sha256Digest::from_bytes([0xb3; 32]),
                language: LanguageRevision::Design0_1,
                target: TargetIdentity::aarch64_qemu_virt_uefi(),
                target_package: target_digest,
                standard_library: core_identity.source_digest,
                source_graph: root_identity.source_digest,
                request: Sha256Digest::from_bytes([0xb4; 32]),
                profile: profile_digest,
            },
            profile: BuildProfile::development(),
        },
        profile_digest,
    )
    .expect("runtime-timeout build configuration");
    let target = TargetPackage::aarch64_qemu_virt_uefi(target_digest);
    let analyzer = CanonicalSemanticAnalyzer::new();
    let changes = AnalysisChangeSet {
        previous_source_graph: None,
        changed_declarations: Vec::new(),
    };
    let discovery = analyzer
        .analyze(
            AnalysisRequest {
                hir: Arc::clone(&hir),
                standard_library_package: wrela_package::PackageId(1),
                target: target.semantic(),
                build: &build,
                mode: AnalysisMode::DiscoverTests {
                    image_name: IMAGE_NAME,
                    image_entry,
                    declared_image_tests: &[],
                    source_selection: TestDiscoverySelection::NameContains(SELECTOR),
                },
                changes: &changes,
                limits: AnalysisLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("runtime-timeout test discovery");
    assert!(
        discovery.diagnostics().is_empty(),
        "discovery diagnostics: {:?}",
        discovery.diagnostics()
    );
    let plan = discovery
        .successful()
        .and_then(|image| image.facts().test_plan.as_ref())
        .expect("runtime-timeout test plan")
        .clone();
    assert!(plan.unit_tests().is_empty());
    let [group] = plan.image_groups() else {
        panic!("selector must produce exactly one generated image group");
    };
    let [selected] = group.tests.as_slice() else {
        panic!("selector must choose exactly one runtime test");
    };
    assert_eq!(selected.descriptor.id, TestId(0));
    assert_eq!(selected.descriptor.kind, TestKind::IntegrationImage);
    assert_eq!(selected.descriptor.timeout_ns, 30_000_000_000);
    assert_eq!(selected.descriptor.name, TEST_FUNCTION);

    let compiled = analyzer
        .analyze(
            AnalysisRequest {
                hir,
                standard_library_package: wrela_package::PackageId(1),
                target: target.semantic(),
                build: &build,
                mode: AnalysisMode::CompileTestGroup {
                    plan: &plan,
                    group: group.id,
                    declared_entry: None,
                },
                changes: &changes,
                limits: AnalysisLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("runtime-timeout selected image analysis");
    assert!(
        compiled.diagnostics().is_empty(),
        "compile diagnostics: {:?}",
        compiled.diagnostics()
    );
    let analyzed = compiled
        .into_parts()
        .0
        .expect("sealed selected runtime-timeout image");
    let semantic = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed,
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("runtime-timeout SemanticWir lowering")
        .into_parts()
        .0;
    let flow = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic,
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("runtime-timeout FlowWir lowering");
    assert!(flow.diagnostics().is_empty());
    let flow_model = flow.wir().as_wir();
    let test_function = flow_model
        .functions
        .iter()
        .find(|function| function.name == TEST_FUNCTION)
        .expect("selected test Flow function");
    let checked_add_calls = test_function
        .blocks
        .iter()
        .flat_map(|block| &block.instructions)
        .filter_map(|instruction| match &instruction.operation {
            FlowOperation::Call {
                function,
                arguments,
            } if flow_model.functions[function.0 as usize].name == CHECKED_ADD_FUNCTION => {
                Some((instruction, arguments.as_slice()))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    let [(checked_add_call, checked_add_arguments)] = checked_add_calls.as_slice() else {
        panic!("selected test must directly call the checked-add helper exactly once");
    };
    let [maximum_argument, one_argument] = *checked_add_arguments else {
        panic!("checked-add call must have exactly two arguments");
    };
    assert_eq!(
        checked_add_call
            .source
            .and_then(|source| sources.span_text(source))
            .expect("checked-add call source spelling"),
        "checked_add(left=maximum, right=one)"
    );
    for (argument, expected) in [(*maximum_argument, [255_u8]), (*one_argument, [1_u8])] {
        assert_unsigned_u8_flow_type(flow_model, test_function, argument);
        let definitions = test_function
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .filter(|instruction| instruction.results.as_slice() == [argument])
            .collect::<Vec<_>>();
        let [definition] = definitions.as_slice() else {
            panic!("checked-add argument must have exactly one defining instruction");
        };
        assert!(matches!(
            &definition.operation,
            FlowOperation::Immediate(wrela_backend::flow_wir::Immediate::Integer {
                bits: 8,
                bytes_le,
            }) if bytes_le.as_slice() == expected
        ));
    }
    let checked_add = flow_model
        .functions
        .iter()
        .find(|function| function.name == CHECKED_ADD_FUNCTION)
        .expect("reachable checked-add Flow function");
    assert_eq!(checked_add.parameters.len(), 2);
    assert!(
        checked_add
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .all(|instruction| !matches!(instruction.operation, FlowOperation::Immediate(_)))
    );
    let checked_adds = checked_add
        .blocks
        .iter()
        .flat_map(|block| &block.instructions)
        .filter_map(|instruction| match instruction.operation {
            FlowOperation::Binary {
                op: FlowBinaryOp::AddChecked,
                left,
                right,
            } => Some((instruction, left, right)),
            _ => None,
        })
        .collect::<Vec<_>>();
    let [(flow_add, left, right)] = checked_adds.as_slice() else {
        panic!("reachable helper must retain exactly one checked add");
    };
    assert_eq!([*left, *right], checked_add.parameters.as_slice());
    assert_eq!(
        flow_add
            .source
            .and_then(|source| sources.span_text(source))
            .expect("checked-add source spelling"),
        "left + right"
    );
    let [result] = flow_add.results.as_slice() else {
        panic!("checked add must produce exactly one result");
    };
    for value in [*left, *right, *result] {
        assert_unsigned_u8_flow_type(flow_model, checked_add, value);
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
    .expect("canonical runtime-timeout FlowWir frame");
    let prepared =
        prepare_canonical_frame_for_codegen(encoded.bytes(), &target, &build, &never_cancelled)
            .expect("runtime-timeout MachineWir preparation");
    let optimized_flow = prepared.optimized().wir().as_wir();
    let optimized_helper = optimized_flow
        .functions
        .iter()
        .find(|function| function.name == CHECKED_ADD_FUNCTION)
        .expect("optimized checked-add Flow function");
    let optimized_adds = optimized_helper
        .blocks
        .iter()
        .flat_map(|block| &block.instructions)
        .filter(|instruction| {
            matches!(
                instruction.operation,
                FlowOperation::Binary {
                    op: FlowBinaryOp::AddChecked,
                    ..
                }
            )
        })
        .count();
    assert_eq!(optimized_adds, 1, "optimizer must not fold the checked add");

    let machine = prepared.machine().wir().as_wir();
    let machine_helper = machine
        .functions
        .iter()
        .find(|function| function.flow_function == optimized_helper.id.0)
        .expect("checked-add Machine function");
    let machine_adds = machine_helper
        .blocks
        .iter()
        .flat_map(|block| &block.instructions)
        .filter_map(|instruction| match &instruction.operation {
            MachineOperation::CheckedInteger {
                op: CheckedIntegerOp::Add,
                signedness,
                left,
                right,
                failure,
            } => Some((instruction, *signedness, *left, *right, *failure)),
            _ => None,
        })
        .collect::<Vec<_>>();
    let [(machine_add, signedness, left, right, failure)] = machine_adds.as_slice() else {
        panic!("checked-add helper must retain exactly one machine checked add");
    };
    assert_eq!(*signedness, IntegerSignedness::Unsigned);
    assert_eq!([*left, *right], machine_helper.parameters.as_slice());
    assert_eq!(failure.kind, ScalarFailureKind::Arithmetic);
    assert_eq!(failure.kind.runtime_code().as_u32(), 1);
    assert_eq!(failure.flow_function, optimized_helper.id.0);
    assert_eq!(
        machine_add
            .source
            .and_then(|source| sources.span_text(source))
            .expect("machine checked-add source spelling"),
        "left + right"
    );
    let [machine_result] = machine_add.results.as_slice() else {
        panic!("machine checked add must produce exactly one result");
    };
    for value in [*left, *right, *machine_result] {
        let ty = machine_helper.values[value.0 as usize].ty;
        assert_eq!(
            machine.types[ty.0 as usize].kind,
            MachineTypeKind::Integer { bits: 8 }
        );
    }
    assert!(
        machine_helper
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .all(|instruction| !matches!(instruction.operation, MachineOperation::Immediate(_)))
    );
}
