#![forbid(unsafe_code)]

use std::{cell::Cell, sync::Arc};

use wrela_backend::{
    BackendContentHasher, BackendPreparationOptions, BackendPreparationServices,
    CanonicalBackendContentHasher, CanonicalFlowOptimizer, CanonicalMachineLowerer, CodegenError,
    MachineLowerError, MachineLoweringLimits, OptimizationLimits, OptimizationProfile,
    emit_prepared_object, flow_wir as flow, llvm_backend_available,
    machine_wir::{
        BackendProofKind, CallingConvention, MachineActivationCancellation, MachineActivationOwner,
        MachineActivationSchedule, MachineFunctionRole, MachineImmediate, MachineOperation,
        MachineRegionStorageKind, MachineTerminator, MachineTypeKind, SectionKind,
        SymbolDefinition, ValidationError,
    },
    prepare_canonical_frame_for_codegen, prepare_for_codegen,
};
use wrela_build_model::{
    BuildConfiguration, BuildIdentity, BuildProfile, LanguageRevision, Sha256Digest,
    TargetIdentity, seal_build_configuration,
};
use wrela_flow_lower::{
    CanonicalFlowLowerer, FlowLowerer, LowerError as FlowLowerError,
    LowerRequest as FlowLowerRequest, LoweringLimits as FlowLoweringLimits,
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
const ACTOR_SOURCE: &str = r#"module app

from core.image import Image, Target

async fn checkpoint():
    pass

@service
pub struct Worker:
    pub async fn ping(mut self):
        await checkpoint()

    @task
    async fn pulse(mut self):
        await checkpoint()

@image
pub fn boot() -> Image:
    img = Image(name="actor-image", target=Target.aarch64_qemu_virt_uefi)
    installed = img.service(Worker, mailbox=2)
    return img
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
fn parsed_actor_source_reaches_flow_with_exact_authority_activations_and_bounds() {
    let source_graph_digest = Sha256Digest::from_bytes([0xa1; 32]);
    let core_package_digest = Sha256Digest::from_bytes([0xa2; 32]);
    let target_digest = Sha256Digest::from_bytes([0xa3; 32]);
    let mut sources = SourceDatabase::default();
    let application_file = sources
        .add(SourceInput {
            path: "app.wr".to_owned(),
            text: ACTOR_SOURCE.to_owned(),
            digest: Sha256Digest::from_bytes([0xa4; 32]),
        })
        .expect("actor application source");
    let core_file = sources
        .add(SourceInput {
            path: "core/image.wr".to_owned(),
            text: CORE_IMAGE_SOURCE.to_owned(),
            digest: Sha256Digest::from_bytes([0xa5; 32]),
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
                .expect("actor source parses")
                .into_parts();
            assert!(diagnostics.is_empty(), "parse diagnostics: {diagnostics:?}");
            parsed
        })
        .collect::<Vec<_>>();

    let mut packages = PackageGraphBuilder::new(identity(
        "actor-application",
        Sha256Digest::from_bytes([0xa6; 32]),
    ));
    let core = packages
        .add_package(identity("wrela-core", core_package_digest))
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
            ModulePath::new(["app".to_owned()]).expect("application module"),
            application_file,
        )
        .expect("application module record");
    packages
        .add_module(
            core,
            ModulePath::new(["image".to_owned()]).expect("core image module"),
            core_file,
        )
        .expect("core module record");
    let hir_changes = HirChangeSet {
        previous_source_graph: None,
        changed_files: Vec::new(),
    };
    let hir_output = CanonicalHirLowerer::new()
        .lower(
            HirLowerRequest {
                packages: Arc::new(packages.finish().expect("actor package graph")),
                source_graph_digest,
                parsed_files: &parsed_files,
                sources: &sources,
                changes: &hir_changes,
                limits: HirLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("actor source lowers to sealed HIR");
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
        .expect("actor image entry");
    let hir = Arc::new(hir_output.into_parts().0.into_program());

    let profile = BuildProfile::development();
    let profile_digest = Sha256Digest::from_bytes([0xa7; 32]);
    let build = seal_build_configuration(
        BuildConfiguration {
            identity: BuildIdentity {
                compiler: Sha256Digest::from_bytes([0xa8; 32]),
                language: LanguageRevision::Design0_1,
                target: TargetIdentity::aarch64_qemu_virt_uefi(),
                target_package: target_digest,
                standard_library: Sha256Digest::from_bytes([0xa9; 32]),
                source_graph: source_graph_digest,
                request: Sha256Digest::from_bytes([0xaa; 32]),
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
    let analysis = CanonicalSemanticAnalyzer::new()
        .analyze(
            AnalysisRequest {
                hir,
                standard_library_package: PackageId(1),
                target: target.semantic(),
                build: &build,
                mode: AnalysisMode::Image {
                    name: "actor-image",
                    entry: image_entry,
                },
                changes: &changes,
                limits: AnalysisLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("actor semantic analysis");
    assert!(
        analysis.diagnostics().is_empty(),
        "semantic diagnostics: {:?}",
        analysis.diagnostics()
    );
    let analyzed = analysis.into_parts().0.expect("sealed parsed actor image");
    let semantic_output = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed,
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("parsed actor lowers to SemanticWir");

    let semantic = semantic_output.wir().as_wir();
    let actor_turn = semantic
        .functions
        .iter()
        .find(|function| function.role == semantic::FunctionRole::ActorTurn(semantic::ActorId(0)))
        .expect("one actor turn function");
    let task_entry = semantic
        .functions
        .iter()
        .find(|function| function.role == semantic::FunctionRole::TaskEntry(semantic::TaskId(0)))
        .expect("one static task entry");
    assert_eq!(actor_turn.effects.0, (1 << 1) | (1 << 2));
    assert_eq!(task_entry.effects.0, (1 << 1) | (1 << 3));
    assert_eq!(semantic.regions.len(), 5);
    assert_eq!(semantic.activations.len(), 2);
    assert_eq!(semantic.static_bytes, 96);
    assert_eq!(semantic.peak_bytes, 96);
    for (index, plan) in semantic.activations.iter().enumerate() {
        assert_eq!(plan.id.0, index as u32);
        assert_eq!(plan.region.0, 3 + index as u32);
        assert_eq!(plan.frame_bytes, 16);
        assert_eq!(plan.maximum_live, 1);
        assert_eq!(
            plan.cancellation,
            semantic::ActivationCancellation::DropCalleeThenPropagate
        );

        let caller = &semantic.functions[plan.caller.0 as usize];
        let caller_owner = match caller.role {
            semantic::FunctionRole::ActorTurn(actor) => semantic::ImageOwner::Actor(actor),
            semantic::FunctionRole::TaskEntry(task) => semantic::ImageOwner::Task(task),
            role => panic!("activation caller has unsupported role {role:?}"),
        };
        assert!(caller.proofs.contains(&plan.capacity_proof));
        assert!(caller.body.statements.iter().any(|statement| {
            matches!(
                statement,
                semantic::SemanticStatement::Let(statement)
                    if matches!(
                        &statement.operation,
                        semantic::SemanticOperation::Call {
                            function,
                            arguments,
                            activation: Some(activation),
                        } if *function == plan.callee
                            && arguments.is_empty()
                            && *activation == plan.id
                    ) && statement.source == Some(plan.source)
            )
        }));

        let callee = &semantic.functions[plan.callee.0 as usize];
        assert_eq!(callee.role, semantic::FunctionRole::Ordinary);
        assert_eq!(callee.color, semantic::FunctionColor::Async);
        assert_eq!(callee.frame_bound, plan.frame_bytes);
        let cleanup = callee
            .proofs
            .iter()
            .copied()
            .find(|proof| {
                semantic.proofs[proof.0 as usize].kind == semantic::ProofKind::CleanupAcyclic
            })
            .expect("activation callee cleanup proof");
        let capacity = &semantic.proofs[plan.capacity_proof.0 as usize];
        assert_eq!(capacity.kind, semantic::ProofKind::CapacityBound);
        assert_eq!(capacity.bound, Some(1));
        assert_eq!(capacity.sources.as_slice(), [plan.source]);
        assert_eq!(capacity.depends_on.as_slice(), [cleanup]);

        let region = &semantic.regions[plan.region.0 as usize];
        assert_eq!(region.class, semantic::RegionClass::TaskFrame);
        assert_eq!(region.owner, caller_owner);
        assert_eq!(region.capacity_bytes, plan.frame_bytes);
        assert_eq!(region.proof, plan.capacity_proof);
        assert_eq!(region.source, plan.source);
    }
    let semantic_closed = semantic
        .proofs
        .iter()
        .find(|proof| proof.kind == semantic::ProofKind::ImageClosed)
        .expect("activation-aware semantic image closure");
    assert_eq!(semantic_closed.bound, Some(96));
    assert_eq!(semantic_closed.depends_on.len(), 3);
    assert_eq!(
        &semantic_closed.depends_on[1..],
        semantic
            .activations
            .iter()
            .map(|plan| plan.capacity_proof)
            .collect::<Vec<_>>()
    );

    let (semantic_wir, _) = semantic_output.into_parts();
    let baseline = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic_wir.clone(),
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("production SemanticWir actor reaches sealed FlowWir");
    assert!(
        baseline.diagnostics().is_empty(),
        "Flow diagnostics: {:?}",
        baseline.diagnostics()
    );
    let flow = baseline.wir().as_wir();
    assert_eq!(flow.actors.len(), 1);
    assert_eq!(flow.tasks.len(), 1);
    assert_eq!(flow.regions.len(), 5);
    assert_eq!(flow.activations.len(), 2);
    assert_eq!(flow.actors[0].id.0, 0);
    assert_eq!(flow.actors[0].mailbox_capacity, 2);
    assert_eq!(flow.tasks[0].id.0, 0);
    assert_eq!(flow.tasks[0].slots, 1);
    assert_eq!(flow.static_bytes, 96);
    assert_eq!(flow.peak_bytes, 96);
    assert_eq!(
        flow.startup_order,
        [
            flow::PlanOwner::Runtime,
            flow::PlanOwner::Actor(flow::ActorId(0)),
            flow::PlanOwner::Task(flow::TaskId(0)),
        ]
    );
    assert_eq!(
        flow.shutdown_order,
        [
            flow::PlanOwner::Task(flow::TaskId(0)),
            flow::PlanOwner::Actor(flow::ActorId(0)),
            flow::PlanOwner::Runtime,
        ]
    );

    let activation = flow
        .types
        .iter()
        .find(|ty| ty.name.as_deref() == Some("__wrela_activation_0"))
        .expect("unit activation type retained from real async source");
    assert_eq!(
        activation.kind,
        flow::FlowTypeKind::Activation {
            result: flow::TypeId(0),
        }
    );
    assert!(!activation.copyable && activation.strict_linear);

    let actor_functions = flow
        .functions
        .iter()
        .filter(|function| {
            matches!(
                function.role,
                flow::FunctionRole::ActorTurn(flow::ActorId(0))
                    | flow::FunctionRole::TaskEntry(flow::TaskId(0))
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(actor_functions.len(), 2);
    let helper = flow
        .functions
        .iter()
        .find(|function| {
            function.role == flow::FunctionRole::Ordinary
                && function.color == flow::FunctionColor::Async
        })
        .expect("closed ordinary async helper");
    for function in actor_functions {
        let plan = flow
            .activations
            .iter()
            .find(|plan| plan.caller == function.id)
            .expect("one activation plan per actor entry function");
        assert_eq!(plan.callee, helper.id);
        assert_eq!(plan.region.0, 3 + plan.id.0);
        assert_eq!(plan.frame_bytes, 16);
        assert_eq!(plan.maximum_live, 1);
        assert_eq!(
            plan.cancellation,
            flow::ActivationCancellation::DropCalleeThenPropagate
        );
        assert!(function.proofs.contains(&plan.capacity_proof));
        let region = &flow.regions[plan.region.0 as usize];
        assert_eq!(region.class, flow::RegionClass::TaskFrame);
        assert_eq!(region.capacity_bytes, plan.frame_bytes);
        assert_eq!(region.capacity_proof, plan.capacity_proof);
        assert_eq!(region.source, plan.source);
        let expected_owner = match function.role {
            flow::FunctionRole::ActorTurn(actor) => flow::PlanOwner::Actor(actor),
            flow::FunctionRole::TaskEntry(task) => flow::PlanOwner::Task(task),
            role => panic!("activation caller has unsupported Flow role {role:?}"),
        };
        assert_eq!(region.owner, expected_owner);

        let capacity = &flow.proofs[plan.capacity_proof.0 as usize];
        assert_eq!(capacity.kind, flow::ProofKind::CapacityBound);
        assert_eq!(capacity.bound, Some(1));
        assert_eq!(capacity.sources.as_slice(), [plan.source]);
        let cleanup = helper
            .proofs
            .iter()
            .copied()
            .find(|proof| flow.proofs[proof.0 as usize].kind == flow::ProofKind::CleanupAcyclic)
            .expect("Flow activation callee cleanup proof");
        assert_eq!(capacity.depends_on.as_slice(), [cleanup]);

        assert_eq!(function.values[1].ty, activation.id);
        let [entry, resume] = function.blocks.as_slice() else {
            panic!("one entry and one resume block per async actor function");
        };
        let [call] = entry.instructions.as_slice() else {
            panic!("one async call before suspension");
        };
        assert_eq!(call.results[0].0, 1);
        assert!(matches!(
            &call.operation,
            flow::FlowOperation::AsyncCall {
                function: callee,
                arguments,
                plan: activation_plan,
            } if *callee == helper.id && arguments.is_empty() && *activation_plan == plan.id
        ));
        assert_eq!(
            entry.terminator,
            flow::Terminator::Suspend {
                state: 0,
                activation: flow::ValueId(1),
                resume: flow::BlockId(1),
            }
        );
        assert_eq!(resume.parameters.len(), 1);
        assert_eq!(resume.parameters[0].0, 2);
        assert_eq!(resume.terminator, flow::Terminator::Return(Vec::new()));
    }
    let flow_closed = flow
        .proofs
        .iter()
        .find(|proof| proof.kind == flow::ProofKind::ImageClosed)
        .expect("activation-aware Flow image closure");
    assert_eq!(flow_closed.bound, Some(96));
    assert_eq!(flow_closed.depends_on.len(), 3);
    assert_eq!(
        &flow_closed.depends_on[1..],
        flow.activations
            .iter()
            .map(|plan| plan.capacity_proof)
            .collect::<Vec<_>>()
    );
    assert_eq!(baseline.report().async_states, 2);
    let ownership = flow
        .proofs
        .iter()
        .find(|proof| proof.kind == flow::ProofKind::Ownership)
        .expect("actor ownership proof");
    assert!(
        ownership
            .explanation
            .iter()
            .any(|line| line.contains("non-reentrant"))
    );
    let wait = flow
        .proofs
        .iter()
        .find(|proof| proof.kind == flow::ProofKind::WaitGraphAcyclic)
        .expect("wait-graph proof");
    assert_eq!(wait.bound, Some(2));
    let encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: baseline.wir(),
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("real actor FlowWir has a canonical private-backend frame");
    let prepared =
        prepare_canonical_frame_for_codegen(encoded.bytes(), &target, &build, &never_cancelled)
            .expect("real parsed actor source reaches sealed MachineWir v13");
    let optimized_wait = prepared
        .optimized()
        .wir()
        .as_wir()
        .proofs
        .iter()
        .find(|proof| proof.id == wait.id)
        .expect("optimized wait-graph proof");
    assert_eq!(optimized_wait.kind, flow::ProofKind::WaitGraphAcyclic);
    let machine = prepared.machine().wir().as_wir();
    assert_eq!(machine.version, 13);
    assert_eq!(machine.activations.len(), 2);
    assert_eq!(machine.region_storage.len(), flow.regions.len());
    assert_eq!(machine.region_storage.len(), 5);
    assert_eq!(machine.globals.len(), 5);
    let machine_closed = machine
        .proofs
        .iter()
        .find(|proof| proof.kind == BackendProofKind::ImageClosed)
        .expect("MachineWir activation-aware image closure");
    assert_eq!(machine_closed.source_proofs.as_slice(), [flow_closed.id.0]);
    assert_eq!(machine_closed.bound, flow_closed.bound);
    assert_eq!(
        machine_closed.depends_on.len(),
        flow_closed.depends_on.len()
    );
    assert_eq!(machine_closed.sources, flow_closed.sources);
    assert!(
        machine.functions[machine.image_entry.0 as usize]
            .proofs
            .contains(&machine_closed.id)
    );
    let mut detached_image_closure = machine.clone();
    detached_image_closure.functions[machine.image_entry.0 as usize]
        .proofs
        .retain(|proof| *proof != machine_closed.id);
    let errors = detached_image_closure
        .validate_for_target(&target)
        .expect_err("image entry cannot detach the closed static allocation proof");
    assert!(errors.0.iter().any(|error| matches!(
        error,
        ValidationError::InvalidRecord {
            kind: "region storage image bound",
            ..
        }
    )));
    let machine_wait = machine
        .proofs
        .iter()
        .find(|proof| proof.kind == BackendProofKind::WaitGraphAcyclic)
        .expect("MachineWir wait-graph proof");
    assert_eq!(machine_wait.source_proofs.as_slice(), [wait.id.0]);
    assert_eq!(machine_wait.bound, wait.bound);
    assert_eq!(machine_wait.depends_on.len(), wait.depends_on.len());
    assert_eq!(machine_wait.sources, wait.sources);
    let mut substituted_wait_proof = machine.clone();
    substituted_wait_proof.proofs[machine_wait.id.0 as usize].kind = BackendProofKind::Ownership;
    let errors = substituted_wait_proof
        .validate_for_target(&target)
        .expect_err("actor wait proof kind cannot be substituted after machine lowering");
    assert!(errors.0.iter().any(|error| matches!(
        error,
        ValidationError::InvalidRecord {
            kind: "actor wait proof",
            ..
        }
    )));
    let mut reserved_region_bytes = 0u64;
    for (storage, flow_region) in machine.region_storage.iter().zip(&flow.regions) {
        assert_eq!(storage.id.0, flow_region.id.0);
        assert_eq!(storage.flow_region, flow_region.id.0);
        assert_eq!(storage.name, flow_region.name);
        assert_eq!(storage.capacity_bytes, flow_region.capacity_bytes);
        assert_eq!(u64::from(storage.alignment), flow_region.alignment);
        assert_eq!(storage.capacity_proof.0, flow_region.capacity_proof.0);
        assert_eq!(storage.source, flow_region.source);
        let flow_capacity = &flow.proofs[flow_region.capacity_proof.0 as usize];
        assert_eq!(flow_capacity.sources.as_slice(), [storage.capacity_source]);
        assert_eq!(flow_capacity.bound, Some(storage.capacity_units));
        assert_eq!(
            storage.capacity_units * storage.bytes_per_unit,
            storage.capacity_bytes
        );
        let global = &machine.globals[storage.global.0 as usize];
        let symbol = &machine.symbols[storage.symbol.0 as usize];
        let section = &machine.sections[storage.section.0 as usize];
        let ty = &machine.types[storage.ty.0 as usize];
        assert_eq!(global.symbol, storage.symbol);
        assert_eq!(global.ty, storage.ty);
        assert_eq!(global.section, storage.section);
        assert_eq!(global.offset, 0);
        assert_eq!(global.alignment, storage.alignment);
        assert_eq!(global.initializer, MachineImmediate::Zero(storage.ty));
        assert_eq!(symbol.definition, SymbolDefinition::Global(storage.global));
        assert_eq!(section.kind, SectionKind::WritableData);
        assert_eq!(section.reserved_bytes, storage.capacity_bytes);
        assert_eq!(section.alignment, storage.alignment);
        assert_eq!(section.owner, storage.name);
        assert_eq!(ty.size, storage.capacity_bytes);
        assert_eq!(ty.alignment, storage.alignment);
        assert_eq!(ty.source_name.as_deref(), Some(storage.name.as_str()));
        assert!(matches!(
            ty.kind,
            MachineTypeKind::Array { length, .. } if length == storage.capacity_bytes
        ));
        reserved_region_bytes += storage.capacity_bytes;
    }
    assert_eq!(reserved_region_bytes, flow.static_bytes);
    assert_eq!(reserved_region_bytes, 96);
    assert!(matches!(
        machine.region_storage[0].kind,
        MachineRegionStorageKind::ActorMailbox {
            actor: 0,
            mailbox_capacity: 2
        }
    ));
    assert!(matches!(
        machine.region_storage[1].kind,
        MachineRegionStorageKind::ActorTurnFrame { actor: 0, .. }
    ));
    assert!(matches!(
        machine.region_storage[2].kind,
        MachineRegionStorageKind::TaskEntryFrame {
            task: 0,
            slots: 1,
            ..
        }
    ));
    let actor_activation = machine
        .activations
        .iter()
        .find(|activation| activation.schedule == MachineActivationSchedule::DormantMailbox)
        .expect("compiled dormant actor-turn activation");
    let task_activation = machine
        .activations
        .iter()
        .find(|activation| activation.schedule == MachineActivationSchedule::StartupOnce)
        .expect("one startup task activation");
    for (activation, flow_plan) in machine.activations.iter().zip(&flow.activations) {
        let flow_caller = &flow.functions[flow_plan.caller.0 as usize];
        let flow_entry = &flow_caller.blocks[flow_caller.entry.0 as usize];
        let flow_resume = &flow_caller.blocks[1];
        let flow_region = &flow.regions[flow_plan.region.0 as usize];
        let flow_capacity = &flow.proofs[flow_plan.capacity_proof.0 as usize];
        let [flow_cleanup] = flow_capacity.depends_on.as_slice() else {
            panic!("activation capacity proof has one cleanup dependency");
        };
        assert_eq!(activation.id.0, flow_plan.id.0);
        assert_eq!(activation.caller.0, flow_plan.caller.0);
        assert_eq!(activation.callee.0, flow_plan.callee.0);
        assert_eq!(
            activation.call_instruction.0,
            flow_entry.instructions[0].id.0
        );
        assert_eq!(activation.resume_block.0, flow_resume.id.0);
        assert_eq!(activation.region, flow_plan.region.0);
        assert_eq!(activation.frame_bytes, flow_plan.frame_bytes);
        assert_eq!(activation.region_capacity_bytes, flow_region.capacity_bytes);
        assert_eq!(
            u64::from(activation.region_alignment),
            flow_region.alignment
        );
        assert_eq!(activation.maximum_live, flow_plan.maximum_live);
        assert_eq!(activation.capacity_proof.0, flow_plan.capacity_proof.0);
        assert_eq!(activation.cleanup_proof.0, flow_cleanup.0);
        assert_eq!(activation.capacity_bound, flow_capacity.bound.unwrap());
        assert_eq!(
            activation.cancellation,
            MachineActivationCancellation::DropCalleeThenPropagate
        );
        assert_eq!(activation.source, flow_plan.source);
        assert_eq!(activation.state, 0);
        let capacity = &machine.proofs[activation.capacity_proof.0 as usize];
        let cleanup = &machine.proofs[activation.cleanup_proof.0 as usize];
        assert_eq!(capacity.kind, BackendProofKind::CapacityBound);
        assert_eq!(capacity.depends_on.as_slice(), [activation.cleanup_proof]);
        assert_eq!(capacity.bound, Some(activation.capacity_bound));
        assert_eq!(capacity.sources.as_slice(), [activation.source]);
        assert_eq!(cleanup.kind, BackendProofKind::CleanupAcyclic);
    }
    assert_eq!(
        actor_activation.owner,
        MachineActivationOwner::Actor {
            actor: 0,
            mailbox_capacity: 2,
        }
    );
    assert_eq!(
        task_activation.owner,
        MachineActivationOwner::Task {
            task: 0,
            slots: 1,
            supervisor: Some(0),
        }
    );
    assert_eq!(
        machine.functions[actor_activation.caller.0 as usize].role,
        MachineFunctionRole::ActorTurn(0)
    );
    assert_eq!(
        machine.functions[task_activation.caller.0 as usize].role,
        MachineFunctionRole::TaskEntry(0)
    );
    let image = &machine.functions[machine.image_entry.0 as usize];
    let image_entry = &image.blocks[image.entry.0 as usize];
    let (success_id, failure_id) = match &image_entry.terminator {
        MachineTerminator::Switch {
            cases,
            default,
            default_arguments,
            ..
        } if matches!(cases.as_slice(), [(0, _, arguments)] if arguments.is_empty())
            && default_arguments.is_empty() =>
        {
            (cases[0].1, *default)
        }
        other => panic!("validated ImageEnter prologue has exact zero-success switch: {other:?}"),
    };
    let success = &image.blocks[success_id.0 as usize];
    assert!(matches!(
        success.instructions.first().map(|instruction| &instruction.operation),
        Some(MachineOperation::Call {
            function,
            arguments,
            convention: CallingConvention::Internal,
        }) if *function == task_activation.caller && arguments.is_empty()
    ));
    let task_calls = image
        .blocks
        .iter()
        .flat_map(|block| &block.instructions)
        .filter(|instruction| {
            matches!(
                instruction.operation,
                MachineOperation::Call { function, .. } if function == task_activation.caller
            )
        })
        .count();
    let actor_calls = image
        .blocks
        .iter()
        .flat_map(|block| &block.instructions)
        .filter(|instruction| {
            matches!(
                instruction.operation,
                MachineOperation::Call { function, .. } if function == actor_activation.caller
            )
        })
        .count();
    assert_eq!(task_calls, 1, "ImageEnter success executes TaskEntry once");
    assert_eq!(actor_calls, 0, "an empty mailbox invents no actor turn");
    let repeated =
        prepare_canonical_frame_for_codegen(encoded.bytes(), &target, &build, &never_cancelled)
            .expect("repeated actor backend preparation");
    assert_eq!(machine, repeated.machine().wir().as_wir());
    match emit_prepared_object(&prepared, &target, &never_cancelled) {
        Err(CodegenError::BackendNotBuilt) if !llvm_backend_available() => {}
        Err(CodegenError::BackendNotBuilt) => {
            panic!("LLVM reports available but rejected native actor object emission")
        }
        Err(error) => panic!("actor MachineWir must reach the frozen native backend: {error}"),
        Ok(_) if !llvm_backend_available() => {
            panic!("native actor object emitted while LLVM reports unavailable")
        }
        Ok(first) => {
            let second = emit_prepared_object(&prepared, &target, &never_cancelled)
                .expect("repeated actor native object emission");
            assert_eq!(first, second);
            assert_eq!(first.bytes().get(..2), Some([0x64, 0xaa].as_slice()));
            for caller in [actor_activation.caller, task_activation.caller] {
                let symbol = machine
                    .symbols
                    .iter()
                    .find(|symbol| symbol.definition == SymbolDefinition::Function(caller))
                    .expect("activation caller has an exact native symbol");
                assert!(
                    first
                        .symbols()
                        .iter()
                        .any(|emitted| emitted.name == symbol.name)
                );
            }
            for storage in &machine.region_storage {
                let section = &machine.sections[storage.section.0 as usize];
                let symbol = &machine.symbols[storage.symbol.0 as usize];
                let emitted_section = first
                    .sections()
                    .iter()
                    .find(|emitted| emitted.name == section.name)
                    .expect("actor region has an exact native writable section");
                assert_eq!(emitted_section.alignment, storage.alignment);
                assert_eq!(emitted_section.file_bytes, storage.capacity_bytes);
                assert_eq!(emitted_section.virtual_bytes, storage.capacity_bytes);
                let emitted_symbol = first
                    .symbols()
                    .iter()
                    .find(|emitted| emitted.name == symbol.name)
                    .expect("actor region has an exact native storage symbol");
                assert_eq!(emitted_symbol.section, section.name);
                assert_eq!(emitted_symbol.section_offset, 0);
                assert_eq!(emitted_symbol.bytes, storage.capacity_bytes);
            }
        }
    }

    let mut omitted_storage = machine.clone();
    omitted_storage.region_storage.pop();
    let omission_errors = omitted_storage
        .validate_for_target(&target)
        .expect_err("omitted actor region storage must be rejected");
    assert!(omission_errors.0.contains(&ValidationError::InvalidRecord {
        kind: "region storage set",
        id: 4,
    }));

    let mut substituted_storage = machine.clone();
    let substituted_id = substituted_storage.region_storage[4].id;
    substituted_storage.region_storage[4].capacity_proof =
        substituted_storage.region_storage[3].capacity_proof;
    let substitution_errors = substituted_storage
        .validate_for_target(&target)
        .expect_err("substituted actor region capacity proof must be rejected");
    assert!(
        substitution_errors
            .0
            .contains(&ValidationError::InvalidRegionStorage(substituted_id))
    );

    let mut substituted_source = machine.clone();
    let source_id = substituted_source.region_storage[3].id;
    substituted_source.region_storage[3].capacity_source =
        substituted_source.region_storage[0].capacity_source;
    let source_errors = substituted_source
        .validate_for_target(&target)
        .expect_err("substituted actor region proof source must be rejected");
    assert!(
        source_errors
            .0
            .contains(&ValidationError::InvalidRegionStorage(source_id))
    );

    let mut overlapping_storage = machine.clone();
    let first_storage = overlapping_storage.region_storage[0].clone();
    let second_storage = overlapping_storage.region_storage[1].clone();
    overlapping_storage.globals[second_storage.global.0 as usize].section = first_storage.section;
    let overlap_errors = overlapping_storage
        .validate_for_target(&target)
        .expect_err("overlapping actor region globals must be rejected");
    assert!(overlap_errors.0.iter().any(|error| matches!(
        error,
        ValidationError::InvalidRecord {
            kind: "overlapping global placement",
            ..
        }
    )));

    let mut misaligned_storage = machine.clone();
    let misaligned = misaligned_storage.region_storage[2].clone();
    misaligned_storage.globals[misaligned.global.0 as usize].alignment = 4;
    let misalignment_errors = misaligned_storage
        .validate_for_target(&target)
        .expect_err("misaligned actor region global must be rejected");
    assert!(
        misalignment_errors
            .0
            .contains(&ValidationError::InvalidRegionStorage(misaligned.id))
    );

    let mut moved_startup = machine.clone();
    let moved_image = &mut moved_startup.functions[machine.image_entry.0 as usize];
    let call_index = moved_image.blocks[success_id.0 as usize]
        .instructions
        .iter()
        .position(|instruction| {
            matches!(
                instruction.operation,
                MachineOperation::Call { function, .. } if function == task_activation.caller
            )
        })
        .expect("one startup task call in the success block");
    let startup_call = moved_image.blocks[success_id.0 as usize]
        .instructions
        .remove(call_index);
    moved_image.blocks[failure_id.0 as usize]
        .instructions
        .push(startup_call);
    let moved_errors = moved_startup
        .validate_for_target(&target)
        .expect_err("startup call moved to ImageEnter failure must be rejected");
    assert!(
        moved_errors
            .0
            .contains(&ValidationError::InvalidActivationPlan(task_activation.id))
    );

    let mut bad_capacity = machine.clone();
    bad_capacity.activations[task_activation.id.0 as usize].capacity_proof =
        task_activation.cleanup_proof;
    let capacity_errors = bad_capacity
        .validate_for_target(&target)
        .expect_err("capacity/cleanup proof substitution must be rejected");
    assert!(
        capacity_errors
            .0
            .contains(&ValidationError::InvalidActivationPlan(task_activation.id))
    );

    let mut bad_cleanup = machine.clone();
    bad_cleanup.activations[task_activation.id.0 as usize].cleanup_proof =
        task_activation.capacity_proof;
    let cleanup_errors = bad_cleanup
        .validate_for_target(&target)
        .expect_err("cleanup/capacity proof substitution must be rejected");
    assert!(
        cleanup_errors
            .0
            .contains(&ValidationError::InvalidActivationPlan(task_activation.id))
    );

    let mut self_dependent = machine.clone();
    self_dependent.proofs[task_activation.capacity_proof.0 as usize].depends_on =
        vec![task_activation.capacity_proof];
    let self_errors = self_dependent
        .validate_for_target(&target)
        .expect_err("self-dependent backend proof must be rejected");
    assert!(self_errors.0.contains(&ValidationError::InvalidRecord {
        kind: "backend proof",
        id: task_activation.capacity_proof.0,
    }));

    let mut forward_dependent = machine.clone();
    let final_proof = forward_dependent.proofs.last().unwrap().id;
    let first_proof = forward_dependent.proofs[0].id;
    forward_dependent.proofs[0].depends_on = vec![final_proof];
    let forward_errors = forward_dependent
        .validate_for_target(&target)
        .expect_err("forward backend proof dependency must be rejected");
    assert!(forward_errors.0.contains(&ValidationError::InvalidRecord {
        kind: "backend proof",
        id: first_proof.0,
    }));

    let mut cyclic = machine.clone();
    cyclic.proofs[0].depends_on = vec![final_proof];
    cyclic.proofs[final_proof.0 as usize].depends_on = vec![first_proof];
    let cycle_errors = cyclic
        .validate_for_target(&target)
        .expect_err("cyclic backend proof dependencies must be rejected");
    assert!(cycle_errors.0.contains(&ValidationError::InvalidRecord {
        kind: "backend proof",
        id: first_proof.0,
    }));

    let prepare_with_machine_limits = |machine_limits: MachineLoweringLimits| {
        let codec = CanonicalFlowWirCodec;
        let hasher = CanonicalBackendContentHasher::new();
        let optimizer = CanonicalFlowOptimizer::new();
        let machine_lowerer = CanonicalMachineLowerer::new();
        let expected_digest = hasher
            .sha256(encoded.bytes(), &never_cancelled)
            .expect("canonical actor frame digest");
        let optimization = OptimizationProfile::from_build_policy(
            &build.profile.optimization,
            build.identity.compiler,
        )
        .expect("actor optimization profile");
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
            &never_cancelled,
        )
    };
    let exact_static_bytes = machine
        .sections
        .iter()
        .map(|section| section.reserved_bytes)
        .sum::<u64>();
    let exact_instructions = machine
        .functions
        .iter()
        .flat_map(|function| &function.blocks)
        .map(|block| block.instructions.len() as u64)
        .sum::<u64>();
    let exact_stack_slots = machine
        .functions
        .iter()
        .map(|function| function.stack_slots.len() as u64)
        .sum::<u64>();
    let exact_stack_bytes = machine
        .functions
        .iter()
        .map(|function| function.stack_bytes)
        .max()
        .unwrap_or(0)
        .max(1);
    let mut exact_machine_limits = MachineLoweringLimits::standard();
    exact_machine_limits.types = machine.types.len() as u64;
    exact_machine_limits.functions = machine.functions.len() as u64;
    exact_machine_limits.sections = machine.sections.len() as u32;
    exact_machine_limits.symbols = machine.symbols.len() as u32;
    exact_machine_limits.globals = machine.globals.len() as u32;
    exact_machine_limits.instructions = exact_instructions;
    exact_machine_limits.stack_slots = exact_stack_slots.max(1);
    exact_machine_limits.proofs = machine.proofs.len() as u32;
    exact_machine_limits.static_bytes = exact_static_bytes;
    exact_machine_limits.stack_bytes_per_function = exact_stack_bytes;
    exact_machine_limits = exact_machine_limits.with_aligned_validation();
    let exact_prepared = prepare_with_machine_limits(exact_machine_limits)
        .expect("real actor source accepts exact MachineWir collection and byte ceilings");
    assert_eq!(machine, exact_prepared.machine().wir().as_wir());

    let mut below_static = exact_machine_limits;
    below_static.static_bytes = exact_static_bytes - 1;
    let below_static_error = prepare_with_machine_limits(below_static)
        .expect_err("one byte below the actor storage layout must fail closed");
    assert_eq!(
        below_static_error.machine_lower_error(),
        Some(&MachineLowerError::ResourceLimit {
            resource: "MachineWir static bytes",
            limit: exact_static_bytes - 1,
        })
    );

    let mut below_globals = exact_machine_limits;
    below_globals.globals -= 1;
    below_globals = below_globals.with_aligned_validation();
    let below_globals_error = prepare_with_machine_limits(below_globals)
        .expect_err("one global below the sealed actor region set must fail closed");
    assert_eq!(
        below_globals_error.machine_lower_error(),
        Some(&MachineLowerError::ResourceLimit {
            resource: "MachineWir globals",
            limit: u64::from(below_globals.globals),
        })
    );

    let successful_polls = Cell::new(0_u32);
    let counted = prepare_canonical_frame_for_codegen(encoded.bytes(), &target, &build, &|| {
        successful_polls.set(successful_polls.get().saturating_add(1));
        false
    })
    .expect("counted actor backend preparation");
    assert_eq!(machine, counted.machine().wir().as_wir());
    let total_polls = successful_polls.get();
    assert!(total_polls > 2);
    let cancel_at = total_polls - 1;
    let cancelled_polls = Cell::new(0_u32);
    let cancelled = prepare_canonical_frame_for_codegen(encoded.bytes(), &target, &build, &|| {
        let next = cancelled_polls.get().saturating_add(1);
        cancelled_polls.set(next);
        next == cancel_at
    })
    .expect_err("late cancellation must not publish prepared MachineWir");
    assert!(cancelled.is_cancelled());
    assert_eq!(cancelled_polls.get(), cancel_at);

    let mut exact = FlowLoweringLimits::standard();
    exact.blocks = baseline.report().blocks;
    exact.instructions = baseline.report().instructions;
    exact.states_per_function = 1;
    CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic_wir.clone(),
                limits: exact,
            },
            &never_cancelled,
        )
        .expect("real actor source accepts exact Flow resource bounds");

    let mut over = exact;
    over.blocks -= 1;
    assert_eq!(
        CanonicalFlowLowerer::new().lower(
            FlowLowerRequest {
                input: semantic_wir.clone(),
                limits: over,
            },
            &never_cancelled,
        ),
        Err(FlowLowerError::ResourceLimit {
            resource: "FlowWir blocks",
            limit: over.blocks,
        })
    );

    let polls = Cell::new(0_u32);
    assert_eq!(
        CanonicalFlowLowerer::new().lower(
            FlowLowerRequest {
                input: semantic_wir,
                limits: FlowLoweringLimits::standard(),
            },
            &|| {
                let current = polls.get();
                polls.set(current.saturating_add(1));
                current >= 12
            },
        ),
        Err(FlowLowerError::Cancelled)
    );
    assert!(polls.get() >= 13);
}
