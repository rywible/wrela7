#![forbid(unsafe_code)]

use std::{cell::Cell, sync::Arc};

use wrela_backend::{
    BackendContentHasher, BackendPreparationOptions, BackendPreparationServices,
    CanonicalBackendContentHasher, CanonicalFlowOptimizer, CanonicalMachineLowerer, CodegenError,
    MachineLowerError, MachineLoweringLimits, OptimizationLimits, OptimizationProfile,
    emit_prepared_object, flow_wir as flow, llvm_backend_available,
    machine_wir::{MachineFunctionRole, MachineOperation, ValidationError},
    prepare_canonical_frame_for_codegen, prepare_for_codegen,
};
use wrela_build_model::{
    BuildConfiguration, BuildIdentity, BuildProfile, LanguageRevision, Sha256Digest,
    TargetIdentity, seal_build_configuration,
};
use wrela_flow_lower::{
    CanonicalFlowLowerer, FlowLowerer, LowerRequest as FlowLowerRequest,
    LoweringLimits as FlowLoweringLimits,
};
use wrela_flow_wir_codec::{CanonicalFlowWirCodec, CodecLimits, EncodeRequest, encode_and_verify};
use wrela_hir_lower::{
    CanonicalHirLowerer, ChangeSet as HirChangeSet, HirLowerer, LowerRequest as HirLowerRequest,
    LoweringLimits as HirLoweringLimits,
};
use wrela_package::{
    DependencyAlias, ModulePath, PackageGraphBuilder, PackageId, PackageIdentity, PackageName,
    PackageVersion,
};
use wrela_sema::{
    AnalysisChangeSet, AnalysisLimits, AnalysisMode, AnalysisRequest, CanonicalSemanticAnalyzer,
    SemanticAnalyzer,
};
use wrela_semantic_lower::{
    CanonicalSemanticLowerer, LowerRequest as SemanticLowerRequest,
    LoweringLimits as SemanticLoweringLimits, SemanticLowerer,
};
use wrela_source::{SourceDatabase, SourceInput};
use wrela_syntax::{ParseLimits, ParseRequest, SyntaxParser, WrelaSyntaxParser};
use wrela_target::TargetPackage;

const CORE_IMAGE_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/image.wr");
const STRUCTURED_SCOPE_SOURCE: &str = r#"module app

from core.image import Image, Target

pub struct Masked:
    token: u32

scope irqs_masked() -> Masked:
    enter Masked(token=1)
    exit state:
        pass

async fn checkpoint():
    pass

fn should_stop() -> bool:
    return true

@service
pub struct Worker:
    pub async fn ping(mut self):
        with irqs_masked() as mask:
            if should_stop():
                pass
            else:
                return
        await checkpoint()

    @task
    async fn pulse(mut self):
        await checkpoint()

@image
pub fn boot() -> Image:
    img = Image(name="scope-image", target=Target.aarch64_qemu_virt_uefi)
    installed = img.service(Worker, mailbox=2)
    return img
"#;

fn package(name: &str, digest: Sha256Digest) -> PackageIdentity {
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
fn structured_scope_return_reaches_machine_and_deterministic_native_coff() {
    let source_graph_digest = Sha256Digest::from_bytes([0xc1; 32]);
    let target_digest = Sha256Digest::from_bytes([0xc2; 32]);
    let mut sources = SourceDatabase::default();
    let application_file = sources
        .add(SourceInput {
            path: "app.wr".to_owned(),
            text: STRUCTURED_SCOPE_SOURCE.to_owned(),
            digest: Sha256Digest::from_bytes([0xc3; 32]),
        })
        .expect("structured scope source");
    let core_file = sources
        .add(SourceInput {
            path: "core/image.wr".to_owned(),
            text: CORE_IMAGE_SOURCE.to_owned(),
            digest: Sha256Digest::from_bytes([0xc4; 32]),
        })
        .expect("core image source");
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
                .expect("scope source parses")
                .into_parts();
            assert!(diagnostics.is_empty(), "parse diagnostics: {diagnostics:?}");
            parsed
        })
        .collect::<Vec<_>>();

    let mut packages = PackageGraphBuilder::new(package(
        "scope-application",
        Sha256Digest::from_bytes([0xc5; 32]),
    ));
    let core = packages
        .add_package(package("wrela-core", Sha256Digest::from_bytes([0xc6; 32])))
        .expect("core package");
    packages
        .add_dependency(
            packages.root(),
            DependencyAlias::new("core").expect("core alias"),
            core,
        )
        .expect("core dependency");
    packages
        .add_module(
            packages.root(),
            ModulePath::new(["app".to_owned()]).expect("app module"),
            application_file,
        )
        .expect("app module record");
    packages
        .add_module(
            core,
            ModulePath::new(["image".to_owned()]).expect("core module"),
            core_file,
        )
        .expect("core module record");
    let hir_output = CanonicalHirLowerer::new()
        .lower(
            HirLowerRequest {
                packages: Arc::new(packages.finish().expect("package graph")),
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
        .expect("scope source lowers to HIR");
    assert!(hir_output.diagnostics().is_empty());
    let image_entry = *hir_output
        .lowered()
        .program()
        .as_program()
        .image_candidates
        .first()
        .expect("image entry");
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
    .expect("build configuration");
    let target = TargetPackage::aarch64_qemu_virt_uefi(target_digest);
    let analysis = CanonicalSemanticAnalyzer::new()
        .analyze(
            AnalysisRequest {
                hir,
                standard_library_package: PackageId(1),
                target: target.semantic(),
                build: &build,
                mode: AnalysisMode::Image {
                    name: "scope-image",
                    entry: image_entry,
                },
                changes: &AnalysisChangeSet {
                    previous_source_graph: None,
                    changed_declarations: Vec::new(),
                },
                limits: AnalysisLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("scope semantic analysis");
    assert!(
        analysis.diagnostics().is_empty(),
        "semantic diagnostics: {:?}",
        analysis.diagnostics()
    );
    let analyzed = analysis.into_parts().0.expect("sealed scope image");
    let semantic = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed,
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("structured scope reaches SemanticWir")
        .into_parts()
        .0;
    let flow_output = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic,
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("structured scope reaches FlowWir");
    let flow_turn = flow_output
        .wir()
        .as_wir()
        .functions
        .iter()
        .find(|function| matches!(function.role, flow::FunctionRole::ActorTurn(_)))
        .expect("FlowWir actor turn");
    let cleanup = flow_output
        .wir()
        .as_wir()
        .functions
        .iter()
        .find(|function| {
            matches!(
                function.origin,
                flow::FunctionOrigin::GeneratedCleanup { .. }
            )
        })
        .expect("generated cleanup");
    assert_eq!(
        flow_turn
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .filter(|instruction| matches!(instruction.operation, flow::FlowOperation::Call { function, .. } if function == cleanup.id))
            .count(),
        2
    );
    assert_eq!(flow_turn.blocks.iter().filter(|block| matches!(block.terminator, flow::Terminator::Return(ref values) if values.is_empty())).count(), 2);

    let encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: flow_output.wir(),
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("structured scope FlowWir encodes canonically");

    let mut forged_flow = flow_output.wir().as_wir().clone();
    let forged_turn = forged_flow
        .functions
        .iter_mut()
        .find(|function| matches!(function.role, flow::FunctionRole::ActorTurn(_)))
        .expect("forged actor turn");
    let forged_cleanup = forged_turn
        .blocks
        .iter_mut()
        .flat_map(|block| &mut block.instructions)
        .find(|instruction| {
            matches!(
                instruction.operation,
                flow::FlowOperation::Call { function, .. } if function == cleanup.id
            )
        })
        .expect("forged taken-path cleanup call");
    let copied_state = match &forged_cleanup.operation {
        flow::FlowOperation::Call { arguments, .. } => arguments[0],
        _ => unreachable!("selected only a cleanup call"),
    };
    forged_cleanup.operation = flow::FlowOperation::Copy {
        value: copied_state,
    };
    let forged_flow = forged_flow
        .validate()
        .expect("structurally valid missing taken cleanup");
    let forged_encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: &forged_flow,
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("forged structured scope FlowWir encodes structurally");
    let error = prepare_canonical_frame_for_codegen(
        forged_encoded.bytes(),
        &target,
        &build,
        &never_cancelled,
    )
    .expect_err("Machine lowering must reauthenticate both cleanup paths");
    assert_eq!(
        error.machine_lower_error(),
        Some(&MachineLowerError::UnsupportedInput {
            feature: "machine-structured-scope-activation-boundary-authentication",
        })
    );
    let prepared =
        prepare_canonical_frame_for_codegen(encoded.bytes(), &target, &build, &never_cancelled)
            .expect("structured scope reaches MachineWir");
    let machine = prepared.machine().wir().as_wir();
    let machine_turn = machine
        .functions
        .iter()
        .find(|function| function.role == MachineFunctionRole::ActorTurn(0))
        .expect("MachineWir actor turn");
    assert_eq!(
        machine_turn
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .filter(|instruction| matches!(instruction.operation, MachineOperation::Call { function, .. } if function.0 == cleanup.id.0))
            .count(),
        2
    );
    let repeated =
        prepare_canonical_frame_for_codegen(encoded.bytes(), &target, &build, &never_cancelled)
            .expect("repeated structured scope preparation");
    assert_eq!(machine, repeated.machine().wir().as_wir());

    let mut missing_taken_cleanup = machine.clone();
    missing_taken_cleanup.functions[machine_turn.id.0 as usize]
        .blocks
        .iter_mut()
        .find(|block| {
            matches!(
                block.terminator,
                wrela_backend::machine_wir::MachineTerminator::Return(ref values)
                    if values.is_empty() && !block.instructions.is_empty()
            )
        })
        .expect("returning scope branch")
        .instructions
        .clear();
    let errors = missing_taken_cleanup
        .validate_for_target(&target)
        .expect_err("the taken structured path cannot omit cleanup");
    assert!(errors.0.contains(&ValidationError::InvalidActivationPlan(
        machine.activations[0].id
    )));

    let prepare_with_machine_limits =
        |machine_limits: MachineLoweringLimits, is_cancelled: &dyn Fn() -> bool| {
            let codec = CanonicalFlowWirCodec;
            let hasher = CanonicalBackendContentHasher::new();
            let optimizer = CanonicalFlowOptimizer::new();
            let machine_lowerer = CanonicalMachineLowerer::new();
            let expected_digest = hasher
                .sha256(encoded.bytes(), &never_cancelled)
                .expect("canonical structured-scope frame digest");
            let optimization = OptimizationProfile::from_build_policy(
                &build.profile.optimization,
                build.identity.compiler,
            )
            .expect("structured-scope optimization profile");
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
                    optimization,
                    optimization_limits: OptimizationLimits::standard(),
                    machine_limits,
                },
                is_cancelled,
            )
        };
    let exact_instructions = machine
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
    exact.instructions = exact_instructions;
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
    let exact_prepared = prepare_with_machine_limits(exact, &never_cancelled)
        .expect("structured cleanup accepts exact MachineWir bounds");
    assert_eq!(machine, exact_prepared.machine().wir().as_wir());
    let mut one_under = exact;
    one_under.instructions -= 1;
    one_under = one_under.with_aligned_validation();
    let error = prepare_with_machine_limits(one_under, &never_cancelled)
        .expect_err("one-under structured cleanup instruction limit");
    assert_eq!(
        error.machine_lower_error(),
        Some(&MachineLowerError::ResourceLimit {
            resource: "MachineWir instructions",
            limit: one_under.instructions,
        })
    );

    let successful_polls = Cell::new(0_u32);
    prepare_with_machine_limits(exact, &|| {
        successful_polls.set(successful_polls.get().saturating_add(1));
        false
    })
    .expect("count structured cleanup preparation polls");
    let cancel_at = successful_polls.get().saturating_sub(1);
    assert!(cancel_at > 1);
    let cancelled_polls = Cell::new(0_u32);
    let error = prepare_with_machine_limits(exact, &|| {
        let next = cancelled_polls.get().saturating_add(1);
        cancelled_polls.set(next);
        next == cancel_at
    })
    .expect_err("late cancellation cannot publish structured cleanup MachineWir");
    assert!(error.is_cancelled());
    assert_eq!(cancelled_polls.get(), cancel_at);

    match emit_prepared_object(&prepared, &target, &never_cancelled) {
        Err(CodegenError::BackendNotBuilt) if !llvm_backend_available() => {}
        Err(error) => panic!("structured scope must pass native codegen: {error}"),
        Ok(first) => {
            assert!(llvm_backend_available());
            let second = emit_prepared_object(&prepared, &target, &never_cancelled)
                .expect("repeated structured scope native emission");
            assert_eq!(
                first, second,
                "structured scope COFF must be byte-identical"
            );
            assert_eq!(first.bytes().get(..2), Some([0x64, 0xaa].as_slice()));
        }
    }
}
