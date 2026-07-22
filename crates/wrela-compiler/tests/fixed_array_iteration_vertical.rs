#![forbid(unsafe_code)]

use std::cell::Cell;
use std::sync::Arc;

use wrela_backend::{
    BackendContentHasher, BackendPreparationOptions, BackendPreparationServices,
    CanonicalBackendContentHasher, CanonicalFlowOptimizer, CanonicalMachineLowerer, CodegenError,
    MachineLowerError, MachineLoweringLimits, OptimizationLimits, OptimizationProfile,
    emit_prepared_object, llvm_backend_available, machine_wir::MachineOperation,
    prepare_canonical_frame_for_codegen, prepare_for_codegen,
};
use wrela_build_model::{
    BuildConfiguration, BuildIdentity, BuildProfile, LanguageRevision, Sha256Digest,
    TargetIdentity, seal_build_configuration,
};
use wrela_flow_lower::{
    CanonicalFlowLowerer, FlowLowerer, FlowOperation, LowerError as FlowLowerError,
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
    return Image(name="fixed-array-image", target=Target.aarch64_qemu_virt_uefi)

@test(runtime)
fn fixed_array_runtime():
    for item in [1, 2, 3]:
        consume(item)
    for flag in [true, false, true]:
        consume_bool(flag)
    return

fn consume(value: i64) -> i64:
    return value

fn consume_bool(value: bool) -> bool:
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
fn fixed_array_iteration_reaches_flow_machine_and_deterministic_native_coff() {
    let source_graph_digest = Sha256Digest::from_bytes([0xb1; 32]);
    let core_package_digest = Sha256Digest::from_bytes([0xb2; 32]);
    let target_digest = Sha256Digest::from_bytes([0xb3; 32]);
    let mut sources = SourceDatabase::default();
    let application_file = sources
        .add(SourceInput {
            path: "app.wr".to_owned(),
            text: APPLICATION_SOURCE.to_owned(),
            digest: Sha256Digest::from_bytes([0xb4; 32]),
        })
        .expect("application source");
    let core_file = sources
        .add(SourceInput {
            path: "core/image.wr".to_owned(),
            text: CORE_IMAGE_SOURCE.to_owned(),
            digest: Sha256Digest::from_bytes([0xb5; 32]),
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
        "fixed-array-application",
        Sha256Digest::from_bytes([0xb6; 32]),
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
    let profile_digest = Sha256Digest::from_bytes([0xb7; 32]);
    let build = seal_build_configuration(
        BuildConfiguration {
            identity: BuildIdentity {
                compiler: Sha256Digest::from_bytes([0xb8; 32]),
                language: LanguageRevision::Design0_1,
                target: TargetIdentity::aarch64_qemu_virt_uefi(),
                target_package: target_digest,
                standard_library: Sha256Digest::from_bytes([0xb9; 32]),
                source_graph: source_graph_digest,
                request: Sha256Digest::from_bytes([0xba; 32]),
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
                    image_name: "fixed-array-image",
                    image_entry,
                    declared_image_tests: &[],
                    source_selection: TestDiscoverySelection::All,
                },
                changes: &changes,
                limits: AnalysisLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("test discovery accepts fixed-array iteration");
    assert!(discovery.diagnostics().is_empty());
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
        .expect("fixed-array test group analysis");
    assert!(compilation.diagnostics().is_empty());
    let analyzed = compilation
        .successful()
        .expect("analyzed fixed-array group");
    let semantic = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed.clone(),
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("fixed-array test group reaches SemanticWir");
    let wir = semantic.wir().as_wir();
    let debug = format!("{wir:?}");
    assert!(debug.contains("Array"));
    assert!(debug.contains("length: 3"));
    assert!(debug.contains("Aggregate"));
    assert!(debug.contains("Index"));
    assert_eq!(debug.matches("uninterrupted_bound: Some(3)").count(), 2);
    let first_flow = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic.wir().clone(),
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("first cold fixed-array Flow lowering");
    let flow_instruction_count = first_flow.report().instructions;
    let mut exact_flow_limits = FlowLoweringLimits::standard();
    exact_flow_limits.instructions = flow_instruction_count;
    CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic.wir().clone(),
                limits: exact_flow_limits,
            },
            &never_cancelled,
        )
        .expect("fixed array accepts its exact FlowWir instruction ceiling");
    exact_flow_limits.instructions -= 1;
    assert!(matches!(
        CanonicalFlowLowerer::new().lower(
            FlowLowerRequest {
                input: semantic.wir().clone(),
                limits: exact_flow_limits,
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
                input: semantic.wir().clone(),
                limits: FlowLoweringLimits::standard(),
            },
            &|| {
                flow_polls.set(flow_polls.get().saturating_add(1));
                false
            },
        )
        .expect("count fixed-array Flow lowering polls");
    let flow_cancel_at = flow_polls.get().saturating_sub(2);
    assert!(flow_cancel_at > 2);
    let cancelled_flow_polls = Cell::new(0_u64);
    let cancelled_flow = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic.wir().clone(),
                limits: FlowLoweringLimits::standard(),
            },
            &|| {
                let next = cancelled_flow_polls.get().saturating_add(1);
                cancelled_flow_polls.set(next);
                next >= flow_cancel_at
            },
        )
        .expect_err("late fixed-array Flow cancellation must propagate");
    assert!(matches!(cancelled_flow, FlowLowerError::Cancelled));
    let flow = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic.wir().clone(),
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("fixed array reaches FlowWir");
    assert_eq!(first_flow.wir().as_wir(), flow.wir().as_wir());
    assert_eq!(flow.wir().as_wir().version, 17);
    assert_eq!(
        flow.wir()
            .as_wir()
            .functions
            .iter()
            .flat_map(|function| &function.blocks)
            .flat_map(|block| &block.instructions)
            .filter(|instruction| {
                matches!(instruction.operation, FlowOperation::ExtractIndex { .. })
            })
            .count(),
        2
    );
    let encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: flow.wir(),
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("fixed-array canonical FlowWir frame");
    assert_eq!(encoded.header().wire_version, 17);
    let prepared =
        prepare_canonical_frame_for_codegen(encoded.bytes(), &target, &build, &never_cancelled)
            .expect("fixed-array MachineWir preparation");
    let machine = prepared.machine().wir().as_wir();
    assert_eq!(machine.version, 18);
    assert_eq!(
        machine
            .functions
            .iter()
            .flat_map(|function| &function.blocks)
            .flat_map(|block| &block.instructions)
            .filter(|instruction| {
                matches!(instruction.operation, MachineOperation::ExtractIndex { .. })
            })
            .count(),
        2
    );
    assert_eq!(
        machine
            .functions
            .iter()
            .flat_map(|function| &function.blocks)
            .flat_map(|block| &block.instructions)
            .filter(|instruction| {
                matches!(instruction.operation, MachineOperation::MakeArray { .. })
            })
            .count(),
        2
    );
    let mut fixed_array_slot_sizes = machine
        .functions
        .iter()
        .flat_map(|function| &function.stack_slots)
        .filter(|slot| slot.source_name.as_deref() == Some("fixed-array.index.storage"))
        .map(|slot| slot.size)
        .collect::<Vec<_>>();
    fixed_array_slot_sizes.sort_unstable();
    assert_eq!(fixed_array_slot_sizes, [3, 24]);
    assert_eq!(
        machine
            .functions
            .iter()
            .filter(|function| {
                function
                    .stack_slots
                    .iter()
                    .any(|slot| slot.source_name.as_deref() == Some("fixed-array.index.storage"))
            })
            .map(|function| function.stack_bytes)
            .collect::<Vec<_>>(),
        [32]
    );
    let mut forged_machine = machine.clone();
    let proof = forged_machine
        .proofs
        .iter_mut()
        .find(|proof| proof.statement.contains("inline fixed-array iteration"))
        .expect("lowered fixed-array capacity proof");
    proof.bound = proof.bound.and_then(|bound| bound.checked_sub(1));
    assert!(
        forged_machine.validate_for_target(&target).is_err(),
        "MachineWir must independently reject a forged fixed-array extent proof"
    );

    let codec = CanonicalFlowWirCodec;
    let hasher = CanonicalBackendContentHasher::new();
    let optimizer = CanonicalFlowOptimizer::new();
    let machine_lowerer = CanonicalMachineLowerer::new();
    let expected_digest = hasher
        .sha256(encoded.bytes(), &never_cancelled)
        .expect("fixed-array frame digest");
    let optimization = OptimizationProfile::from_build_policy(
        &build.profile.optimization,
        build.identity.compiler,
    )
    .expect("fixed-array optimization profile");
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
        .expect("fixed array accepts its exact MachineWir instruction ceiling");
    assert_eq!(exact.machine().wir().as_wir(), machine);
    let mut one_under = exact_machine_limits;
    one_under.instructions -= 1;
    one_under = one_under.with_aligned_validation();
    let one_under_error = prepare_with(one_under, &never_cancelled)
        .expect_err("one fewer fixed-array MachineWir instruction must fail");
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
    .expect("count fixed-array MachineWir cancellation polls");
    let machine_cancel_at = machine_polls.get().saturating_sub(2);
    assert!(machine_cancel_at > 2);
    let cancelled_machine_polls = Cell::new(0_u64);
    let cancellation = prepare_with(MachineLoweringLimits::standard(), &|| {
        let next = cancelled_machine_polls.get().saturating_add(1);
        cancelled_machine_polls.set(next);
        next >= machine_cancel_at
    })
    .expect_err("late fixed-array MachineWir cancellation must propagate");
    assert!(cancellation.is_cancelled());

    match emit_prepared_object(&prepared, &target, &never_cancelled) {
        Err(CodegenError::BackendNotBuilt) if !llvm_backend_available() => {}
        Err(error) => panic!("fixed-array native object emission failed: {error}"),
        Ok(_) if !llvm_backend_available() => {
            panic!("native object emitted while LLVM reports unavailable")
        }
        Ok(first) => {
            let second = emit_prepared_object(&prepared, &target, &never_cancelled)
                .expect("repeat fixed-array native object emission");
            assert_eq!(
                first.bytes(),
                second.bytes(),
                "identical fixed-array MachineWir must emit byte-identical ARM64 COFF"
            );
        }
    }

    let mut forged = flow.wir().as_wir().clone();
    let proof = forged
        .proofs
        .iter_mut()
        .find(|proof| proof.subject == "inline fixed-array iteration")
        .expect("fixed-array capacity proof");
    proof.bound = proof.bound.and_then(|bound| bound.checked_sub(1));
    assert!(
        forged.validate().is_err(),
        "FlowWir must independently reject a forged fixed-array extent proof"
    );
}
