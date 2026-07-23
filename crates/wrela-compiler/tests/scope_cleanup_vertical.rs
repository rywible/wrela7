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
    LoweringLimits as SemanticLoweringLimits, SemanticLowerer, semantic_wir as semantic,
};
use wrela_source::{SourceDatabase, SourceInput};
use wrela_syntax::{ParseLimits, ParseRequest, SyntaxParser, WrelaSyntaxParser};
use wrela_target::TargetPackage;

const CORE_IMAGE_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/image.wr");
const CORE_OPTION_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/option.wr");
const CORE_RESULT_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/result.wr");
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

/// Same admitted scope shape as `STRUCTURED_SCOPE_SOURCE`, but the `with`
/// activations are owned by an ordinary module-level synchronous free function
/// that the turn calls, rather than by the turn itself. Normal-path exit only:
/// nothing here can suspend, fail, or unwind.
const ORDINARY_OWNER_SCOPE_SOURCE: &str = r#"module app

from core.image import Image, Target

pub struct Masked:
    token: u32

scope irqs_masked() -> Masked:
    enter Masked(token=1)
    exit state:
        pass

async fn checkpoint():
    pass

fn guarded():
    with irqs_masked() as outer:
        with irqs_masked() as inner:
            pass

@service
pub struct Worker:
    pub async fn ping(mut self):
        guarded()
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

/// The first genuine abnormal exit out of a `with` body: an ordinary
/// module-level synchronous free function returning `Option[u64]` owns two
/// nested activations, and the inner body propagates with `?`. The success
/// fallthrough and the propagating failure arm must each tear both scopes down
/// inner-before-outer.
const QUESTION_EXIT_SCOPE_SOURCE: &str = r#"module app

from core.image import Image, Target

pub struct Masked:
    token: u32

scope irqs_masked() -> Masked:
    enter Masked(token=1)
    exit state:
        pass

async fn checkpoint():
    pass

fn make_option() -> Option[u64]:
    return Some(9)

fn guarded() -> Option[u64]:
    with irqs_masked() as outer:
        with irqs_masked() as inner:
            payload: u64 = make_option()?
    return Some(4)

@service
pub struct Worker:
    pub async fn ping(mut self):
        outcome: Option[u64] = guarded()
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

/// Runs the front half of the toolchain for a scope fixture. The existing
/// structured-return vertical inlines the same sequence; this helper exists so
/// the ordinary-owner case can reuse it without perturbing that test's pinned
/// bounds.
fn lower_scope_source_to_flow(
    source: &str,
    include_outcomes: bool,
) -> (
    wrela_flow_lower::LowerOutput,
    TargetPackage,
    wrela_build_model::ValidatedBuildConfiguration,
) {
    let (semantic, target, build) = lower_scope_source_to_semantic(source, include_outcomes);
    let flow_output = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic,
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("scope owner reaches FlowWir");
    (flow_output, target, build)
}

/// The same front half, stopping at SemanticWir. The `?`-exit fixture needs it
/// because its FlowWir tail is pinned fail-closed for a reason unrelated to
/// scopes (see `question_exit_out_of_a_with_body_...`).
fn lower_scope_source_to_semantic(
    source: &str,
    include_outcomes: bool,
) -> (
    semantic::ValidatedSemanticWir,
    TargetPackage,
    wrela_build_model::ValidatedBuildConfiguration,
) {
    let source_graph_digest = Sha256Digest::from_bytes([0xd1; 32]);
    let target_digest = Sha256Digest::from_bytes([0xd2; 32]);
    let mut sources = SourceDatabase::default();
    let application_file = sources
        .add(SourceInput {
            path: "app.wr".to_owned(),
            text: source.to_owned(),
            digest: Sha256Digest::from_bytes([0xd3; 32]),
        })
        .expect("scope owner source");
    let core_file = sources
        .add(SourceInput {
            path: "core/image.wr".to_owned(),
            text: CORE_IMAGE_SOURCE.to_owned(),
            digest: Sha256Digest::from_bytes([0xd4; 32]),
        })
        .expect("core image source");
    let outcome_files = include_outcomes.then(|| {
        let option_file = sources
            .add(SourceInput {
                path: "core/option.wr".to_owned(),
                text: CORE_OPTION_SOURCE.to_owned(),
                digest: Sha256Digest::from_bytes([0xdb; 32]),
            })
            .expect("core option source");
        let result_file = sources
            .add(SourceInput {
                path: "core/result.wr".to_owned(),
                text: CORE_RESULT_SOURCE.to_owned(),
                digest: Sha256Digest::from_bytes([0xdc; 32]),
            })
            .expect("core result source");
        [option_file, result_file]
    });
    let parsed_files = [application_file, core_file]
        .into_iter()
        .chain(outcome_files.into_iter().flatten())
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
        Sha256Digest::from_bytes([0xd5; 32]),
    ));
    let core = packages
        .add_package(package("wrela-core", Sha256Digest::from_bytes([0xd6; 32])))
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
    if let Some([option_file, result_file]) = outcome_files {
        packages
            .add_module(
                core,
                ModulePath::new(["option".to_owned()]).expect("core option module"),
                option_file,
            )
            .expect("core option module record");
        packages
            .add_module(
                core,
                ModulePath::new(["result".to_owned()]).expect("core result module"),
                result_file,
            )
            .expect("core result module record");
    }
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
    let profile_digest = Sha256Digest::from_bytes([0xd7; 32]);
    let build = seal_build_configuration(
        BuildConfiguration {
            identity: BuildIdentity {
                compiler: Sha256Digest::from_bytes([0xd8; 32]),
                language: LanguageRevision::Design0_1,
                target: TargetIdentity::aarch64_qemu_virt_uefi(),
                target_package: target_digest,
                standard_library: Sha256Digest::from_bytes([0xd9; 32]),
                source_graph: source_graph_digest,
                request: Sha256Digest::from_bytes([0xda; 32]),
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
        .expect("scope owner reaches SemanticWir")
        .into_parts()
        .0;
    (semantic, target, build)
}

/// Widening the scope owner is a semantic-tier admission change; FlowWir is
/// owner-agnostic and composes with it unchanged. Both generated cleanups land
/// in the ordinary owner, inner before outer, and none is left in the calling
/// turn.
///
/// The MachineWir tail stays closed, but for a reason that has nothing to do
/// with scopes: the mailbox-once activation contract in `wrela-machine-lower`
/// pins an actor turn's entry block to exactly `[MailboxReceive, AsyncCall]`,
/// so a turn that also performs a plain synchronous call is refused under the
/// pre-existing, named `machine-async-result-delivery-pending`. The control
/// program below reproduces that refusal with the same turn shape and no `with`
/// anywhere, so a later widening of the activation contract has to revisit this
/// pin deliberately.
#[test]
fn ordinary_function_scope_owner_reaches_flow_and_pins_the_machine_tail() {
    let (flow_output, target, build) =
        lower_scope_source_to_flow(ORDINARY_OWNER_SCOPE_SOURCE, false);
    let wir = flow_output.wir().as_wir();
    // FlowWir specializes one generated cleanup per activation, so the reverse
    // teardown order is observable as the call order of scope 0 then scope 1.
    let cleanup_for = |scope: u32| {
        wir.functions
            .iter()
            .find(|function| {
                matches!(
                    function.origin,
                    flow::FunctionOrigin::GeneratedCleanup { scope: id, .. } if id == scope
                )
            })
            .expect("generated cleanup for activation")
            .id
    };
    let (inner, outer) = (cleanup_for(0), cleanup_for(1));
    let cleanup_calls = |function: &flow::FlowFunction| {
        function
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .filter_map(|instruction| match instruction.operation {
                flow::FlowOperation::Call { function, .. } if function == inner => Some("inner"),
                flow::FlowOperation::Call { function, .. } if function == outer => Some("outer"),
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    let owner = wir
        .functions
        .iter()
        .find(|function| function.name.ends_with("::guarded"))
        .expect("FlowWir ordinary scope owner");
    assert_eq!(owner.role, flow::FunctionRole::Ordinary);
    assert_eq!(owner.color, flow::FunctionColor::Sync);
    assert_eq!(
        cleanup_calls(owner),
        ["inner", "outer"],
        "an ordinary owner runs both cleanups inner-before-outer"
    );
    for turn in wir
        .functions
        .iter()
        .filter(|function| matches!(function.role, flow::FunctionRole::ActorTurn(_)))
    {
        assert!(
            cleanup_calls(turn).is_empty(),
            "no cleanup is left behind in a calling turn"
        );
    }

    let encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: flow_output.wir(),
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("ordinary-owner scope FlowWir encodes canonically");
    let error =
        prepare_canonical_frame_for_codegen(encoded.bytes(), &target, &build, &never_cancelled)
            .expect_err("the turn-entry activation contract still refuses this turn shape");
    assert_eq!(
        error.machine_lower_error(),
        Some(&MachineLowerError::UnsupportedInput {
            feature: "machine-async-result-delivery-pending",
        })
    );

    // The same refusal with no scope anywhere: the wall is the turn's extra
    // synchronous call, not the ordinary scope owner.
    let scopeless_source = ORDINARY_OWNER_SCOPE_SOURCE.replace(
        "    with irqs_masked() as outer:\n        with irqs_masked() as inner:\n            pass",
        "    pass",
    );
    let (scopeless, target, build) = lower_scope_source_to_flow(&scopeless_source, false);
    assert!(
        !scopeless.wir().as_wir().functions.iter().any(|function| {
            matches!(
                function.origin,
                flow::FunctionOrigin::GeneratedCleanup { .. }
            )
        }),
        "the control program contains no scope at all"
    );
    let scopeless = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: scopeless.wir(),
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("scopeless control FlowWir encodes canonically");
    let error =
        prepare_canonical_frame_for_codegen(scopeless.bytes(), &target, &build, &never_cancelled)
            .expect_err("the control program is refused identically");
    assert_eq!(
        error.machine_lower_error(),
        Some(&MachineLowerError::UnsupportedInput {
            feature: "machine-async-result-delivery-pending",
        })
    );
}

/// The `?` early exit out of a `with` body reaches SemanticWir with cleanup on
/// both paths: the success fallthrough and the propagating failure arm each
/// commit and exit both activations, inner before outer.
///
/// The FlowWir tail stays closed here, and for a reason that has nothing to do
/// with scopes: the actor-image type slice in `wrela-flow-lower` admits a
/// nominal `Enum` only when it is the declared result of the async-outcome
/// profile, so an `Option[u64]` flowing anywhere in the image is refused under
/// the pre-existing, named `actor types outside the stateless scalar slice`.
/// The control program below reproduces that refusal with the same `?`
/// propagation and no `with` anywhere, so widening the type slice later has to
/// revisit this pin deliberately.
#[test]
fn question_exit_out_of_a_with_body_reaches_semantic_wir_and_pins_the_flow_tail() {
    let (semantic, _target, _build) =
        lower_scope_source_to_semantic(QUESTION_EXIT_SCOPE_SOURCE, true);
    let wir = semantic.as_wir();
    assert_eq!(wir.scopes.len(), 2, "two exact scope activation plans");
    let owner = wir
        .functions
        .iter()
        .find(|function| function.name.ends_with("::guarded"))
        .expect("SemanticWir fallible scope owner");
    let markers = |region: &semantic::SemanticRegion| {
        region
            .statements
            .iter()
            .filter_map(|statement| match statement {
                semantic::SemanticStatement::Let(semantic::LetStatement { operation, .. }) => {
                    match operation {
                        semantic::SemanticOperation::EnterScope { scope, .. } => {
                            Some(("enter", scope.0))
                        }
                        semantic::SemanticOperation::CommitScope { scope, .. } => {
                            Some(("commit", scope.0))
                        }
                        semantic::SemanticOperation::ExitScope { scope } => Some(("exit", scope.0)),
                        _ => None,
                    }
                }
                _ => None,
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        markers(&owner.body),
        [
            ("enter", 1),
            ("enter", 0),
            ("commit", 0),
            ("exit", 0),
            ("commit", 1),
            ("exit", 1),
        ],
        "the success fallthrough keeps the established reverse teardown"
    );
    let propagating_arm = owner
        .body
        .statements
        .iter()
        .find_map(|statement| match statement {
            semantic::SemanticStatement::Match { arms, results, .. } if results.len() == 1 => {
                arms.last()
            }
            _ => None,
        })
        .expect("postfix question propagating arm");
    assert_eq!(
        markers(&propagating_arm.body),
        [("commit", 0), ("exit", 0), ("commit", 1), ("exit", 1)],
        "the `?` failure path tears both activations down in the same reverse order"
    );

    let flow = CanonicalFlowLowerer::new().lower(
        FlowLowerRequest {
            input: semantic,
            limits: FlowLoweringLimits::standard(),
        },
        &never_cancelled,
    );
    assert!(
        matches!(
            flow,
            Err(wrela_flow_lower::LowerError::UnsupportedInput { feature })
                if feature == "actor types outside the stateless scalar slice"
        ),
        "the actor-image type slice still refuses an Option-typed image"
    );

    // The same refusal with no scope anywhere: the wall is the outcome type in
    // an actor image, not the `?` exit out of a `with` body.
    let scopeless_source = QUESTION_EXIT_SCOPE_SOURCE.replace(
        "    with irqs_masked() as outer:\n        with irqs_masked() as inner:\n            payload: u64 = make_option()?\n",
        "    payload: u64 = make_option()?\n",
    );
    let (scopeless, _target, _build) = lower_scope_source_to_semantic(&scopeless_source, true);
    assert!(
        scopeless.as_wir().scopes.is_empty(),
        "the control program contains no scope at all"
    );
    let control = CanonicalFlowLowerer::new().lower(
        FlowLowerRequest {
            input: scopeless,
            limits: FlowLoweringLimits::standard(),
        },
        &never_cancelled,
    );
    assert!(
        matches!(
            control,
            Err(wrela_flow_lower::LowerError::UnsupportedInput { feature })
                if feature == "actor types outside the stateless scalar slice"
        ),
        "the control program is refused identically"
    );
}

/// A `break` whose target loop *encloses* the `with` — the first loop-carried
/// abnormal exit out of a scope. The activation is entered and torn down once
/// per iteration, and the breaking edge tears it down before jumping out.
const LOOP_BREAK_SCOPE_SOURCE: &str = r#"module app

from core.image import Image, Target

pub struct Masked:
    token: u32

scope irqs_masked() -> Masked:
    enter Masked(token=1)
    exit state:
        pass

async fn checkpoint():
    pass

fn guarded():
    index: u32 = 0
    while index < 8:
        index += 1
        with irqs_masked() as mask:
            break

@service
pub struct Worker:
    pub async fn ping(mut self):
        guarded()
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

/// The same owner with no `with` anywhere: a bare `break` out of a `while` in an
/// ordinary free function called by the turn. It reproduces the FlowWir refusal
/// below, which is what proves that wall is the loop-exiting edge itself and not
/// the scope.
const LOOP_BREAK_CONTROL_SOURCE: &str = r#"module app

from core.image import Image, Target

async fn checkpoint():
    pass

fn guarded():
    index: u32 = 0
    while index < 8:
        index += 1
        break

@service
pub struct Worker:
    pub async fn ping(mut self):
        guarded()
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

/// A `break` whose target loop encloses the `with` tears the activation down on
/// the breaking edge, and only on it.
///
/// Before this slice the semantic tier refused the program outright under
/// `semantic-with-abnormal-cleanup-lowering-pending (early control-flow exit)`.
/// The general rule computes the edge instead: `break` at loop nesting depth 0
/// *within the body* targets a loop outside the `with`, so it exits the scope
/// and cleans; the body cannot fall through past it, so no second teardown is
/// appended.
///
/// **The vertical stops at SemanticWir, for a reason unrelated to scopes.**
/// `wrela-flow-lower`'s actor-image source-region validation admits only
/// fallthrough regions and refuses every `Break`/`Continue` under the
/// pre-existing `actor non-fallthrough source region`, wherever it appears and
/// whether or not a scope is involved. `LOOP_BREAK_CONTROL_SOURCE` carries the
/// identical loop and `break` with no `with` at all and is refused identically,
/// so the wall is the loop-exiting edge in an actor image, not the scope
/// teardown. Widening that actor slice is a separate increment; until it lands,
/// no `with` + `break` program reaches FlowWir, and the loop-control scope
/// invariant added to `wrela-flow-lower` alongside this change
/// (`FlowWir loop control with an active scope`) is a fail-closed guard that
/// source cannot yet reach.
#[test]
fn break_out_of_a_loop_enclosing_a_with_cleans_on_the_breaking_edge_and_pins_the_flow_tail() {
    let (semantic, _target, _build) =
        lower_scope_source_to_semantic(LOOP_BREAK_SCOPE_SOURCE, false);
    let wir = semantic.as_wir();
    let [plan] = wir.scopes.as_slice() else {
        panic!("one exact scope activation plan")
    };
    assert_eq!(plan.name, "irqs_masked");
    assert_eq!(plan.abort, None);
    assert!(!plan.suspend_safe);
    assert_eq!(
        wir.functions[plan.exit.0 as usize].role,
        semantic::FunctionRole::Cleanup
    );

    let owner = wir
        .functions
        .iter()
        .find(|function| function.name.ends_with("::guarded"))
        .expect("the scope owner is lowered as a source function");
    assert_eq!(owner.role, semantic::FunctionRole::Ordinary);

    // Every scope marker sits inside the loop, and the teardown pair sits
    // immediately before the `Break` — the whole observable content of the
    // general rule for this program.
    assert_eq!(
        scope_marker_names(&owner.body),
        ["enter", "commit", "exit"],
        "the activation is entered and torn down exactly once, inside the loop"
    );
    assert!(
        breaking_region(&owner.body).is_some_and(|statements| matches!(
            statements,
            [
                ..,
                semantic::SemanticStatement::Let(semantic::LetStatement {
                    operation: semantic::SemanticOperation::CommitScope { .. },
                    ..
                }),
                semantic::SemanticStatement::Let(semantic::LetStatement {
                    operation: semantic::SemanticOperation::ExitScope { .. },
                    ..
                }),
                semantic::SemanticStatement::Break(_),
            ]
        )),
        "cleanup is emitted immediately before the break, not after it"
    );

    // The FlowWir wall, and the scope-free control program that proves what it
    // is really refusing.
    let flow_error = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic,
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect_err("FlowWir still refuses a loop-exiting edge in an actor image");
    let (control, _target, _build) =
        lower_scope_source_to_semantic(LOOP_BREAK_CONTROL_SOURCE, false);
    let control_error = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: control,
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect_err("the scope-free control program is refused the same way");
    assert!(
        matches!(
            (&flow_error, &control_error),
            (
                wrela_flow_lower::LowerError::UnsupportedInput { feature },
                wrela_flow_lower::LowerError::UnsupportedInput { feature: control },
            ) if feature == control && *feature == "actor non-fallthrough source region"
        ),
        "the wall is the loop-exiting edge, not the scope: {flow_error:?} vs {control_error:?}"
    );
}

/// The scope markers of a region tree in order, walking loops and branches.
fn scope_marker_names(region: &semantic::SemanticRegion) -> Vec<&'static str> {
    fn walk(region: &semantic::SemanticRegion, out: &mut Vec<&'static str>) {
        for statement in &region.statements {
            match statement {
                semantic::SemanticStatement::Let(semantic::LetStatement { operation, .. }) => {
                    match operation {
                        semantic::SemanticOperation::EnterScope { .. } => out.push("enter"),
                        semantic::SemanticOperation::CommitScope { .. } => out.push("commit"),
                        semantic::SemanticOperation::ExitScope { .. } => out.push("exit"),
                        _ => {}
                    }
                }
                semantic::SemanticStatement::If {
                    then_region,
                    else_region,
                    ..
                } => {
                    walk(then_region, out);
                    walk(else_region, out);
                }
                semantic::SemanticStatement::Loop { body, .. } => walk(body, out),
                semantic::SemanticStatement::Match { arms, .. } => {
                    for arm in arms {
                        walk(&arm.body, out);
                    }
                }
                _ => {}
            }
        }
    }
    let mut out = Vec::new();
    walk(region, &mut out);
    out
}

/// The statements of the region that ends in a `Break`, wherever it is nested.
fn breaking_region(region: &semantic::SemanticRegion) -> Option<&[semantic::SemanticStatement]> {
    if matches!(
        region.statements.last(),
        Some(semantic::SemanticStatement::Break(_))
    ) {
        return Some(region.statements.as_slice());
    }
    region
        .statements
        .iter()
        .find_map(|statement| match statement {
            semantic::SemanticStatement::If {
                then_region,
                else_region,
                ..
            } => breaking_region(then_region).or_else(|| breaking_region(else_region)),
            semantic::SemanticStatement::Loop { body, .. } => breaking_region(body),
            semantic::SemanticStatement::Match { arms, .. } => {
                arms.iter().find_map(|arm| breaking_region(&arm.body))
            }
            _ => None,
        })
}
