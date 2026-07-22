#![forbid(unsafe_code)]

use std::cell::Cell;
use std::sync::Arc;

use wrela_backend::{
    BackendContentHasher, BackendPreparationOptions, BackendPreparationServices,
    CanonicalBackendContentHasher, CanonicalFlowOptimizer, CanonicalMachineLowerer, CodegenError,
    MachineLowerError, MachineLoweringLimits, OptimizationLimits, OptimizationProfile,
    emit_prepared_object, llvm_backend_available,
    machine_wir::{MachineImmediate, MachineOperation, MachineTypeKind},
    prepare_canonical_frame_for_codegen, prepare_for_codegen,
};
use wrela_build_model::{
    BuildConfiguration, BuildIdentity, BuildProfile, LanguageRevision, Sha256Digest,
    TargetIdentity, seal_build_configuration,
};
use wrela_flow_lower::{CanonicalFlowLowerer, FlowLowerer, LowerRequest as FlowLowerRequest};
use wrela_flow_wir_codec::{CanonicalFlowWirCodec, CodecLimits, EncodeRequest, encode_and_verify};
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
    return Image(name="static-bytes-image", target=Target.aarch64_qemu_virt_uefi)

@test(runtime)
fn static_bytes_runtime():
    packet = b"\0\x7f\xff"
    return
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
fn arbitrary_static_bytes_reach_machine_and_deterministic_native_coff() {
    let source_graph_digest = Sha256Digest::from_bytes([0xc1; 32]);
    let core_package_digest = Sha256Digest::from_bytes([0xc2; 32]);
    let target_digest = Sha256Digest::from_bytes([0xc3; 32]);
    let mut sources = SourceDatabase::default();
    let application_file = sources
        .add(SourceInput {
            path: "app.wr".to_owned(),
            text: APPLICATION_SOURCE.to_owned(),
            digest: Sha256Digest::from_bytes([0xc4; 32]),
        })
        .expect("application source");
    let core_file = sources
        .add(SourceInput {
            path: "core/image.wr".to_owned(),
            text: CORE_IMAGE_SOURCE.to_owned(),
            digest: Sha256Digest::from_bytes([0xc5; 32]),
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
        "static-bytes-application",
        Sha256Digest::from_bytes([0xc6; 32]),
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
    let image_entry = *program.image_candidates.first().expect("image entry");
    let hir = Arc::new(hir_output.into_parts().0.into_program());

    let profile = BuildProfile::development();
    let profile_digest = Sha256Digest::from_bytes([0xc7; 32]);
    let build = seal_build_configuration(
        BuildConfiguration {
            identity: BuildIdentity {
                compiler: Sha256Digest::from_bytes([0xc8; 32]),
                language: LanguageRevision::Design0_1,
                target: TargetIdentity::aarch64_qemu_virt_uefi(),
                target_package: target_digest,
                standard_library: Sha256Digest::from_bytes([0xc9; 32]),
                source_graph: source_graph_digest,
                request: Sha256Digest::from_bytes([0xca; 32]),
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
                    image_name: "static-bytes-image",
                    image_entry,
                    declared_image_tests: &[],
                    source_selection: TestDiscoverySelection::All,
                },
                changes: &changes,
                limits: AnalysisLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("test discovery accepts exact static bytes");
    assert!(discovery.diagnostics().is_empty());
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
        .expect("static-bytes test group analysis");
    assert!(compilation.diagnostics().is_empty());
    let semantic = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: compilation
                    .successful()
                    .expect("analyzed static-bytes group")
                    .clone(),
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("static bytes reach SemanticWir");
    let flow_first = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic.wir().clone(),
                limits: wrela_flow_lower::LoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("static bytes reach FlowWir");
    let flow_second = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic.wir().clone(),
                limits: wrela_flow_lower::LoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("repeat static bytes Flow lowering");
    assert_eq!(flow_first.wir().as_wir(), flow_second.wir().as_wir());
    assert_eq!(flow_first.wir().as_wir().version, 19);
    let encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: flow_first.wir(),
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("canonical static-bytes FlowWir frame");
    assert_eq!(encoded.header().wire_version, 19);
    let prepared =
        prepare_canonical_frame_for_codegen(encoded.bytes(), &target, &build, &never_cancelled)
            .expect("static bytes reach MachineWir preparation");
    let machine = prepared.machine().wir().as_wir();
    assert_eq!(machine.version, 21);
    assert!(machine.types.iter().any(|ty| {
        ty.kind == MachineTypeKind::StaticBytes { bytes: 3 }
            && ty.size == 3
            && ty.alignment == 1
            && ty.source_name.as_deref() == Some("Static[Bytes[3]]")
    }));
    let literal = machine
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .flat_map(|block| &block.instructions)
        .find_map(|instruction| match &instruction.operation {
            MachineOperation::Immediate(MachineImmediate::Bytes(bytes))
                if bytes.as_slice() == [0, 0x7f, 0xff] =>
            {
                Some(bytes.as_slice())
            }
            _ => None,
        })
        .expect("exact non-UTF-8 bytes survive Machine lowering");
    assert_eq!(literal, [0, 0x7f, 0xff]);

    let mut forged_extent = machine.clone();
    let static_ty = forged_extent
        .types
        .iter_mut()
        .find(|ty| matches!(ty.kind, MachineTypeKind::StaticBytes { .. }))
        .expect("exact StaticBytes Machine type");
    static_ty.kind = MachineTypeKind::StaticBytes { bytes: 4 };
    assert!(forged_extent.validate_for_target(&target).is_err());
    let mut forged_name = machine.clone();
    forged_name
        .types
        .iter_mut()
        .find(|ty| matches!(ty.kind, MachineTypeKind::StaticBytes { .. }))
        .expect("exact StaticBytes Machine type")
        .source_name = Some("Static[Str]".to_owned());
    assert!(forged_name.validate_for_target(&target).is_err());

    let codec = CanonicalFlowWirCodec;
    let hasher = CanonicalBackendContentHasher::new();
    let optimizer = CanonicalFlowOptimizer::new();
    let machine_lowerer = CanonicalMachineLowerer::new();
    let expected_digest = hasher
        .sha256(encoded.bytes(), &never_cancelled)
        .expect("static-bytes frame digest");
    let optimization = OptimizationProfile::from_build_policy(
        &build.profile.optimization,
        build.identity.compiler,
    )
    .expect("static-bytes optimization profile");
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
            &target,
            &build,
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
    let mut exact = MachineLoweringLimits::standard();
    exact.types = machine.types.len() as u64;
    exact.functions = machine.functions.len() as u64;
    exact.sections = machine.sections.len() as u32;
    exact.symbols = machine.symbols.len() as u32;
    exact.globals = machine.globals.len() as u32;
    exact.instructions = instruction_count;
    exact.stack_slots = machine
        .functions
        .iter()
        .map(|function| function.stack_slots.len() as u64)
        .sum::<u64>()
        .max(1);
    exact.proofs = machine.proofs.len() as u32;
    exact.static_bytes = machine
        .sections
        .iter()
        .map(|section| section.reserved_bytes)
        .sum();
    exact.stack_bytes_per_function = machine
        .functions
        .iter()
        .map(|function| function.stack_bytes)
        .max()
        .unwrap_or(0)
        .max(1);
    exact = exact.with_aligned_validation();
    let mut payload_low = 1_u64;
    let mut payload_high = exact.payload_bytes;
    while payload_low < payload_high {
        let midpoint = payload_low + (payload_high - payload_low) / 2;
        let mut candidate = exact;
        candidate.payload_bytes = midpoint;
        candidate = candidate.with_aligned_validation();
        match prepare_with(candidate, &never_cancelled) {
            Ok(_) => payload_high = midpoint,
            Err(error)
                if matches!(
                    error.machine_lower_error(),
                    Some(MachineLowerError::ResourceLimit {
                        resource: "MachineWir payload bytes",
                        ..
                    })
                ) =>
            {
                payload_low = midpoint + 1;
            }
            Err(error) => panic!("unexpected payload-bound failure: {error}"),
        }
    }
    assert!(payload_low >= 3, "the exact arbitrary bytes are metered");
    exact.payload_bytes = payload_low;
    exact = exact.with_aligned_validation();
    let exact_output =
        prepare_with(exact, &never_cancelled).expect("exact static-bytes Machine limits pass");
    assert_eq!(exact_output.machine().wir().as_wir(), machine);

    let mut instruction_one_under = exact;
    instruction_one_under.instructions -= 1;
    instruction_one_under = instruction_one_under.with_aligned_validation();
    let instruction_error = prepare_with(instruction_one_under, &never_cancelled)
        .expect_err("one fewer Machine instruction must fail");
    assert_eq!(
        instruction_error.machine_lower_error(),
        Some(&MachineLowerError::ResourceLimit {
            resource: "MachineWir instructions",
            limit: instruction_count - 1,
        })
    );
    let mut payload_one_under = exact;
    payload_one_under.payload_bytes -= 1;
    payload_one_under = payload_one_under.with_aligned_validation();
    let payload_error = prepare_with(payload_one_under, &never_cancelled)
        .expect_err("one fewer Machine payload byte must fail");
    assert_eq!(
        payload_error.machine_lower_error(),
        Some(&MachineLowerError::ResourceLimit {
            resource: "MachineWir payload bytes",
            limit: payload_low - 1,
        })
    );

    let polls = Cell::new(0_u64);
    prepare_with(MachineLoweringLimits::standard(), &|| {
        polls.set(polls.get().saturating_add(1));
        false
    })
    .expect("count static-bytes Machine lowering polls");
    let cancel_at = polls.get().saturating_sub(2);
    assert!(cancel_at > 2);
    let cancelled_polls = Cell::new(0_u64);
    let cancellation = prepare_with(MachineLoweringLimits::standard(), &|| {
        let next = cancelled_polls.get().saturating_add(1);
        cancelled_polls.set(next);
        next >= cancel_at
    })
    .expect_err("late static-bytes Machine cancellation must propagate");
    assert!(cancellation.is_cancelled());

    match emit_prepared_object(&prepared, &target, &never_cancelled) {
        Err(CodegenError::BackendNotBuilt) if !llvm_backend_available() => {}
        Err(error) => panic!("static-bytes native object emission failed: {error}"),
        Ok(_) if !llvm_backend_available() => {
            panic!("native object emitted while LLVM reports unavailable")
        }
        Ok(first) => {
            let second = emit_prepared_object(&prepared, &target, &never_cancelled)
                .expect("repeat static-bytes native object emission");
            assert_eq!(
                first.bytes(),
                second.bytes(),
                "identical StaticBytes MachineWir must emit byte-identical ARM64 COFF"
            );
        }
    }
}
