#![forbid(unsafe_code)]

use std::{cell::Cell, sync::Arc};

use wrela_backend::{
    BackendContentHasher, BackendPreparationOptions, BackendPreparationServices,
    CanonicalBackendContentHasher, CanonicalFlowOptimizer, CanonicalMachineLowerer, CodegenError,
    MachineLowerError, MachineLoweringLimits, OptimizationLimits, OptimizationProfile,
    emit_prepared_object, flow_wir as flow, llvm_backend_available,
    machine_wir::{
        BackendProofKind, MachineActivationSchedule, MachineOperation, ScalarFailureKind,
        ValidationError,
    },
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
    ExpressionResolution, SemanticAnalyzer, SemanticTypeKind,
};
use wrela_semantic_lower::{
    CanonicalSemanticLowerer, LowerRequest as SemanticLowerRequest,
    LoweringLimits as SemanticLoweringLimits, SemanticLowerer, semantic_wir as semantic,
};
use wrela_source::{SourceDatabase, SourceInput};
use wrela_syntax::{ParseLimits, ParseRequest, SyntaxParser, WrelaSyntaxParser};
use wrela_target::TargetPackage;

const CORE_IMAGE_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/image.wr");
const ACTOR_SEND_SOURCE: &str = r#"module app

from core.image import Image, Target

async fn checkpoint():
    pass

@service
pub struct Worker:
    pub async fn ping(mut self):
        await checkpoint()

@app
pub struct Client:
    worker: Actor[Worker]

    @task
    async fn publish(mut self):
        send self.worker.ping()
        await checkpoint()

@image
pub fn boot() -> Image:
    img = Image(name="actor-cross-send-image", target=Target.aarch64_qemu_virt_uefi)
    worker = img.service(Worker, mailbox=1)
    client = img.app(Client, worker=worker.handle(), mailbox=1)
    return img
"#;

const ACTOR_REPLY_SOURCE: &str = r#"module app

from core.image import Image, Target

@service
pub struct Worker:
    pub async fn ping(mut self) -> u64:
        return 7

@app
pub struct Client:
    worker: Actor[Worker]

    @task
    async fn request(mut self):
        answer: u64 = await self.worker.ping()

@image
pub fn boot() -> Image:
    img = Image(name="actor-reply-image", target=Target.aarch64_qemu_virt_uefi)
    worker = img.service(Worker, mailbox=1)
    client = img.app(Client, worker=worker.handle(), mailbox=1)
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

fn renumber_instructions(function: &mut flow::FlowFunction) {
    let mut next = 0_u32;
    for block in &mut function.blocks {
        for instruction in &mut block.instructions {
            instruction.id = flow::InstructionId(next);
            next = next.checked_add(1).expect("bounded test instruction ids");
        }
    }
}

fn has_invalid_record(errors: &flow::ValidationErrors, kind: &'static str) -> bool {
    errors.0.iter().any(|error| {
        matches!(
            error,
            flow::ValidationError::InvalidRecord {
                kind: actual,
                ..
            } if *actual == kind
        )
    })
}

#[test]
fn exact_u64_actor_reply_reaches_one_native_caller_owned_slot() {
    let source_graph_digest = Sha256Digest::from_bytes([0xc1; 32]);
    let core_package_digest = Sha256Digest::from_bytes([0xc2; 32]);
    let target_digest = Sha256Digest::from_bytes([0xc3; 32]);
    let mut sources = SourceDatabase::default();
    let application_file = sources
        .add(SourceInput {
            path: "app.wr".to_owned(),
            text: ACTOR_REPLY_SOURCE.to_owned(),
            digest: Sha256Digest::from_bytes([0xc4; 32]),
        })
        .expect("actor reply application source");
    let core_file = sources
        .add(SourceInput {
            path: "core/image.wr".to_owned(),
            text: CORE_IMAGE_SOURCE.to_owned(),
            digest: Sha256Digest::from_bytes([0xc5; 32]),
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
                .expect("actor reply source parses")
                .into_parts();
            assert!(diagnostics.is_empty(), "parse diagnostics: {diagnostics:?}");
            parsed
        })
        .collect::<Vec<_>>();
    let mut packages = PackageGraphBuilder::new(identity(
        "actor-reply-application",
        Sha256Digest::from_bytes([0xc6; 32]),
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
    let changes = HirChangeSet {
        previous_source_graph: None,
        changed_files: Vec::new(),
    };
    let hir_output = CanonicalHirLowerer::new()
        .lower(
            HirLowerRequest {
                packages: Arc::new(packages.finish().expect("actor reply package graph")),
                source_graph_digest,
                parsed_files: &parsed_files,
                sources: &sources,
                changes: &changes,
                limits: HirLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("actor reply lowers to HIR");
    assert!(hir_output.diagnostics().is_empty());
    let image_entry = hir_output.lowered().program().as_program().image_candidates[0];
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
    .expect("validated actor reply build");
    let target = TargetPackage::aarch64_qemu_virt_uefi(target_digest);
    let analysis_changes = AnalysisChangeSet {
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
                    name: "actor-reply-image",
                    entry: image_entry,
                },
                changes: &analysis_changes,
                limits: AnalysisLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("actor reply semantic analysis");
    assert!(
        analysis.diagnostics().is_empty(),
        "semantic diagnostics: {:?}",
        analysis.diagnostics()
    );
    let analyzed = analysis.into_parts().0.expect("sealed actor reply image");
    let semantic_output = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed,
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("actor reply SemanticWir");
    let (semantic_wir, _) = semantic_output.into_parts();
    let flow_output = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic_wir,
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("actor reply FlowWir");
    let flow = flow_output.wir().as_wir();
    assert!(
        flow.functions
            .iter()
            .any(|function| function.blocks.iter().any(|block| {
                block.instructions.iter().any(|instruction| {
                    matches!(
                        instruction.operation,
                        flow::FlowOperation::ActorReplyRequest { .. }
                    )
                })
            }))
    );
    let encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: flow_output.wir(),
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("actor reply canonical frame");
    let prepared =
        prepare_canonical_frame_for_codegen(encoded.bytes(), &target, &build, &never_cancelled)
            .expect("actor reply reaches MachineWir");
    let machine = prepared.machine().wir().as_wir();
    let producer = machine
        .functions
        .iter()
        .find(|function| {
            function.blocks.iter().any(|block| {
                block.instructions.iter().any(|instruction| {
                    matches!(
                        instruction.operation,
                        MachineOperation::ActorReplyRequest { .. }
                    )
                })
            })
        })
        .expect("machine actor reply producer");
    assert_eq!(producer.stack_slots.len(), 1);
    assert_eq!(producer.stack_slots[0].size, 16);
    assert_eq!(producer.stack_slots[0].alignment, 8);
    assert_eq!(producer.stack_bytes, 16);
    let producer_index = producer.id.0 as usize;
    let (request_block_index, request_index, method, permit, reply) =
        producer
            .blocks
            .iter()
            .enumerate()
            .find_map(|(block_index, block)| {
                block.instructions.iter().enumerate().find_map(
                    |(instruction_index, instruction)| {
                        let MachineOperation::ActorReplyRequest {
                            method,
                            permit,
                            reply,
                            failure,
                            duplicate_failure,
                            ..
                        } = instruction.operation
                        else {
                            return None;
                        };
                        assert_eq!(failure.kind, ScalarFailureKind::ActorReplyStateMismatch);
                        assert_eq!(
                            duplicate_failure.kind,
                            ScalarFailureKind::ActorReplyDuplicateResolve
                        );
                        Some((block_index, instruction_index, method, permit, reply))
                    },
                )
            })
            .expect("machine actor reply request");
    assert_eq!(
        machine.proofs[reply.0 as usize].kind,
        BackendProofKind::ActorReplyExactlyOnce
    );
    assert!(
        machine.proofs[reply.0 as usize]
            .depends_on
            .contains(&permit)
    );
    let target_index = method.0 as usize;
    let (resolve_block_index, resolve_index) = machine.functions[target_index]
        .blocks
        .iter()
        .enumerate()
        .find_map(|(block_index, block)| {
            block
                .instructions
                .iter()
                .position(|instruction| {
                    matches!(
                        instruction.operation,
                        MachineOperation::ActorReplyResolve {
                            reply: actual,
                            ..
                        } if actual == reply
                    )
                })
                .map(|instruction_index| (block_index, instruction_index))
        })
        .expect("machine actor reply resolve");

    let mut undersized_slot = machine.clone();
    undersized_slot.functions[producer_index].stack_slots[0].size = 8;
    assert!(undersized_slot.validate_for_target(&target).is_err());

    let mut substituted_reply_proof = machine.clone();
    let MachineOperation::ActorReplyRequest {
        reply: forged_reply,
        ..
    } = &mut substituted_reply_proof.functions[producer_index].blocks[request_block_index]
        .instructions[request_index]
        .operation
    else {
        panic!("machine actor reply request operation");
    };
    *forged_reply = permit;
    let errors = substituted_reply_proof
        .validate_for_target(&target)
        .expect_err("capacity proof cannot substitute for reply proof");
    assert!(errors.0.iter().any(|error| matches!(
        error,
        ValidationError::InvalidRecord {
            kind: "actor reply message contract",
            ..
        }
    )));

    let mut duplicate_resolve = machine.clone();
    let duplicate = duplicate_resolve.functions[target_index].blocks[resolve_block_index]
        .instructions[resolve_index]
        .clone();
    duplicate_resolve.functions[target_index].blocks[resolve_block_index]
        .instructions
        .insert(resolve_index + 1, duplicate);
    let errors = duplicate_resolve
        .validate_for_target(&target)
        .expect_err("actor reply cannot resolve twice");
    assert!(errors.0.iter().any(|error| matches!(
        error,
        ValidationError::InvalidRecord {
            kind: "actor reply resolve contract" | "actor reply message contract",
            ..
        }
    )));

    let prepare_with_machine_limits = |machine_limits: MachineLoweringLimits| {
        let codec = CanonicalFlowWirCodec;
        let hasher = CanonicalBackendContentHasher::new();
        let optimizer = CanonicalFlowOptimizer::new();
        let machine_lowerer = CanonicalMachineLowerer::new();
        let expected_digest = hasher
            .sha256(encoded.bytes(), &never_cancelled)
            .expect("canonical actor-reply frame digest");
        let optimization = OptimizationProfile::from_build_policy(
            &build.profile.optimization,
            build.identity.compiler,
        )
        .expect("actor-reply optimization profile");
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
        .unwrap_or(0);
    assert_eq!(exact_stack_slots, 1);
    assert_eq!(exact_stack_bytes, 16);
    let mut exact_machine_limits = MachineLoweringLimits::standard();
    exact_machine_limits.types = machine.types.len() as u64;
    exact_machine_limits.functions = machine.functions.len() as u64;
    exact_machine_limits.sections = machine.sections.len() as u32;
    exact_machine_limits.symbols = machine.symbols.len() as u32;
    exact_machine_limits.globals = machine.globals.len() as u32;
    exact_machine_limits.instructions = exact_instructions;
    exact_machine_limits.stack_slots = exact_stack_slots;
    exact_machine_limits.proofs = machine.proofs.len() as u32;
    exact_machine_limits.static_bytes = exact_static_bytes;
    exact_machine_limits.stack_bytes_per_function = exact_stack_bytes;
    exact_machine_limits = exact_machine_limits.with_aligned_validation();
    let exact_prepared = prepare_with_machine_limits(exact_machine_limits)
        .expect("actor reply accepts exact stack-slot and stack-byte ceilings");
    assert_eq!(machine, exact_prepared.machine().wir().as_wir());

    // A zero stack-slot ceiling is not a valid backend limits object, so the
    // representable exact boundary is proved by the one-slot model assertion
    // above and the exact prepared-model equality here.
    let mut below_stack_bytes = exact_machine_limits;
    below_stack_bytes.stack_bytes_per_function -= 1;
    let error = prepare_with_machine_limits(below_stack_bytes)
        .expect_err("fifteen reply stack bytes must fail closed");
    assert_eq!(
        error.machine_lower_error(),
        Some(&MachineLowerError::ResourceLimit {
            resource: "MachineWir stack bytes per function",
            limit: 15,
        })
    );

    match emit_prepared_object(&prepared, &target, &never_cancelled) {
        Err(CodegenError::BackendNotBuilt) if !llvm_backend_available() => {}
        Err(error) => panic!("actor reply native codegen: {error}"),
        Ok(first) => {
            let second = emit_prepared_object(&prepared, &target, &never_cancelled)
                .expect("repeat actor reply native codegen");
            assert_eq!(first, second);
        }
    }
}

#[test]
fn real_image_wired_cross_actor_send_reaches_source_derived_backend_evidence() {
    let source_graph_digest = Sha256Digest::from_bytes([0xb1; 32]);
    let core_package_digest = Sha256Digest::from_bytes([0xb2; 32]);
    let target_digest = Sha256Digest::from_bytes([0xb3; 32]);
    let mut sources = SourceDatabase::default();
    let application_file = sources
        .add(SourceInput {
            path: "app.wr".to_owned(),
            text: ACTOR_SEND_SOURCE.to_owned(),
            digest: Sha256Digest::from_bytes([0xb4; 32]),
        })
        .expect("actor send application source");
    let core_file = sources
        .add(SourceInput {
            path: "core/image.wr".to_owned(),
            text: CORE_IMAGE_SOURCE.to_owned(),
            digest: Sha256Digest::from_bytes([0xb5; 32]),
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
                .expect("actor send source parses")
                .into_parts();
            assert!(diagnostics.is_empty(), "parse diagnostics: {diagnostics:?}");
            parsed
        })
        .collect::<Vec<_>>();

    let mut packages = PackageGraphBuilder::new(identity(
        "actor-send-application",
        Sha256Digest::from_bytes([0xb6; 32]),
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
                packages: Arc::new(packages.finish().expect("actor send package graph")),
                source_graph_digest,
                parsed_files: &parsed_files,
                sources: &sources,
                changes: &hir_changes,
                limits: HirLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("actor send source lowers to sealed HIR");
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
        .expect("actor send image entry");
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
    let analysis = CanonicalSemanticAnalyzer::new()
        .analyze(
            AnalysisRequest {
                hir,
                standard_library_package: PackageId(1),
                target: target.semantic(),
                build: &build,
                mode: AnalysisMode::Image {
                    name: "actor-cross-send-image",
                    entry: image_entry,
                },
                changes: &changes,
                limits: AnalysisLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("actor send semantic analysis");
    assert!(
        analysis.diagnostics().is_empty(),
        "semantic diagnostics: {:?}",
        analysis.diagnostics()
    );
    let analyzed = analysis
        .into_parts()
        .0
        .expect("sealed parsed actor send image");
    let facts = analyzed.facts();
    let request = facts
        .expressions
        .iter()
        .find(|fact| matches!(fact.resolution, ExpressionResolution::ActorRequest { .. }))
        .expect("real send has an actor-request fact");
    assert!(facts.types.iter().any(|ty| {
        ty.id == request.ty
            && ty.kind == SemanticTypeKind::Reservation
            && ty.linearity == wrela_sema::Linearity::StrictLinear
    }));

    let semantic_output = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed,
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("parsed actor send lowers to SemanticWir");
    let semantic = semantic_output.wir().as_wir();
    assert!(semantic.types.iter().any(|ty| {
        ty.kind == semantic::TypeKind::Reservation && ty.linearity == semantic::Linearity::Strict
    }));
    let task = semantic
        .functions
        .iter()
        .find(|function| matches!(function.role, semantic::FunctionRole::TaskEntry(_)))
        .expect("startup task");
    let actor = semantic
        .functions
        .iter()
        .find(|function| matches!(function.role, semantic::FunctionRole::ActorTurn(_)))
        .expect("actor turn");
    assert!(task.body.statements.iter().any(|statement| matches!(
        statement,
        semantic::SemanticStatement::Let(statement)
            if matches!(statement.operation, semantic::SemanticOperation::ActorReserve { .. })
    )));
    assert!(task.body.statements.iter().any(|statement| matches!(
        statement,
        semantic::SemanticStatement::Let(statement)
            if matches!(statement.operation, semantic::SemanticOperation::ActorCommit { .. })
    )));
    assert!(matches!(
        actor.body.statements.first(),
        Some(semantic::SemanticStatement::Let(statement))
            if matches!(statement.operation, semantic::SemanticOperation::MailboxReceive { .. })
    ));

    let (semantic_wir, _) = semantic_output.into_parts();
    let flow_output = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic_wir,
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("real actor send lowers to sealed FlowWir");
    let flow = flow_output.wir().as_wir();
    let reservation = flow
        .types
        .iter()
        .find(|ty| ty.kind == flow::FlowTypeKind::Reservation)
        .expect("strict FlowWir reservation type");
    assert!(!reservation.copyable && reservation.strict_linear);
    let task = flow
        .functions
        .iter()
        .find(|function| matches!(function.role, flow::FunctionRole::TaskEntry(_)))
        .expect("FlowWir startup task");
    let actor = flow
        .functions
        .iter()
        .find(|function| matches!(function.role, flow::FunctionRole::ActorTurn(_)))
        .expect("FlowWir actor turn");
    assert!(
        task.blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .any(|instruction| matches!(
                instruction.operation,
                flow::FlowOperation::ActorReserve { .. }
            ))
    );
    assert!(
        task.blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .any(|instruction| matches!(
                instruction.operation,
                flow::FlowOperation::ActorCommit { .. }
            ))
    );
    assert!(matches!(
        actor.blocks[actor.entry.0 as usize]
            .instructions
            .first()
            .map(|instruction| &instruction.operation),
        Some(flow::FlowOperation::MailboxReceive { .. })
    ));

    let standard_flow_validation = flow::ValidationLimits::standard();
    let mut lower_work = 1_u64;
    let mut upper_work = standard_flow_validation.validation_work;
    while lower_work < upper_work {
        let midpoint = lower_work + (upper_work - lower_work) / 2;
        let mut limits = standard_flow_validation;
        limits.validation_work = midpoint;
        match flow.clone().validate_with_limits(limits, &never_cancelled) {
            Ok(_) => upper_work = midpoint,
            Err(flow::ValidationFailure::ResourceLimit {
                resource: "validation work",
                ..
            }) => lower_work = midpoint + 1,
            other => panic!("actor-send Flow validation work search changed class: {other:?}"),
        }
    }
    let mut exact_flow_validation = standard_flow_validation;
    exact_flow_validation.validation_work = lower_work;
    flow.clone()
        .validate_with_limits(exact_flow_validation, &never_cancelled)
        .expect("real actor send accepts its exact Flow validation-work bound");
    let mut below_flow_validation = exact_flow_validation;
    below_flow_validation.validation_work -= 1;
    assert_eq!(
        flow.clone()
            .validate_with_limits(below_flow_validation, &never_cancelled),
        Err(flow::ValidationFailure::ResourceLimit {
            resource: "validation work",
            limit: below_flow_validation.validation_work,
        })
    );
    let successful_flow_polls = Cell::new(0_u32);
    flow.clone()
        .validate_with_limits(standard_flow_validation, &|| {
            successful_flow_polls.set(successful_flow_polls.get().saturating_add(1));
            false
        })
        .expect("counted actor-send Flow validation");
    let flow_cancel_at = successful_flow_polls.get().saturating_sub(1);
    assert!(flow_cancel_at > 1);
    for _ in 0..2 {
        let polls = Cell::new(0_u32);
        assert_eq!(
            flow.clone()
                .validate_with_limits(standard_flow_validation, &|| {
                    let next = polls.get().saturating_add(1);
                    polls.set(next);
                    next == flow_cancel_at
                }),
            Err(flow::ValidationFailure::Cancelled)
        );
        assert_eq!(polls.get(), flow_cancel_at);
    }

    let capability_type = flow
        .types
        .iter()
        .find(|ty| matches!(ty.kind, flow::FlowTypeKind::ActorHandle(_)))
        .expect("exact image-wired Flow capability type");
    assert_eq!(
        capability_type.kind,
        flow::FlowTypeKind::ActorHandle(flow::ActorId(0))
    );
    assert!(capability_type.copyable && !capability_type.strict_linear);
    let (capability_function, capability_block, capability_instruction) = flow
        .functions
        .iter()
        .enumerate()
        .find_map(|(function_index, function)| {
            function
                .blocks
                .iter()
                .enumerate()
                .find_map(|(block_index, block)| {
                    block
                        .instructions
                        .iter()
                        .position(|instruction| {
                            matches!(
                                instruction.operation,
                                flow::FlowOperation::ActorCapability { .. }
                            )
                        })
                        .map(|instruction_index| (function_index, block_index, instruction_index))
                })
        })
        .expect("one exact image-wired Flow capability");
    let mut wrong_capability_target = flow.clone();
    let flow::FlowOperation::ActorCapability {
        actor: capability_actor,
        ..
    } = &mut wrong_capability_target.functions[capability_function].blocks[capability_block]
        .instructions[capability_instruction]
        .operation
    else {
        unreachable!()
    };
    *capability_actor = flow::ActorId(1);
    let errors = wrong_capability_target
        .validate()
        .expect_err("capability target cannot be substituted with the client actor");
    assert!(has_invalid_record(&errors, "actor capability"));

    let mut wrong_capability_type = flow.clone();
    wrong_capability_type.types[capability_type.id.0 as usize].kind =
        flow::FlowTypeKind::ActorHandle(flow::ActorId(1));
    let errors = wrong_capability_type
        .validate()
        .expect_err("capability type cannot point at the client actor");
    assert!(has_invalid_record(&errors, "actor capability"));

    let encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: flow_output.wir(),
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("real actor send FlowWir has one canonical bounded frame");
    assert!(!encoded.bytes().is_empty());
    let prepared =
        prepare_canonical_frame_for_codegen(encoded.bytes(), &target, &build, &never_cancelled)
            .expect("real actor send reaches sealed MachineWir");
    let machine = prepared.machine().wir().as_wir();
    assert!(
        machine
            .activations
            .iter()
            .any(|activation| { activation.schedule == MachineActivationSchedule::MailboxOnce })
    );
    assert!(machine.functions.iter().any(|function| {
        function
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .any(|instruction| {
                matches!(instruction.operation, MachineOperation::ActorReserve { .. })
            })
    }));
    assert!(machine.functions.iter().any(|function| {
        function
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .any(|instruction| {
                matches!(instruction.operation, MachineOperation::ActorCommit { .. })
            })
    }));
    assert!(machine.functions.iter().any(|function| {
        function
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .any(|instruction| {
                matches!(
                    instruction.operation,
                    MachineOperation::MailboxReceive { .. }
                )
            })
    }));
    assert!(machine.functions.iter().any(|function| {
        function
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .any(|instruction| {
                matches!(
                    instruction.operation,
                    MachineOperation::MailboxDispatch { .. }
                )
            })
    }));
    match emit_prepared_object(&prepared, &target, &never_cancelled) {
        Err(CodegenError::BackendNotBuilt) if !llvm_backend_available() => {}
        Err(error) => panic!("actor send must pass native codegen preflight: {error}"),
        Ok(_) if !llvm_backend_available() => {
            panic!("native actor object emitted while LLVM reports unavailable")
        }
        Ok(first) => {
            let second = emit_prepared_object(&prepared, &target, &never_cancelled)
                .expect("repeated actor-send object emission");
            assert_eq!(first, second);
            assert_eq!(first.bytes().get(..2), Some([0x64, 0xaa].as_slice()));
            let mailbox = machine
                .region_storage
                .iter()
                .find(|storage| {
                    matches!(
                        storage.kind,
                        wrela_backend::machine_wir::MachineRegionStorageKind::ActorMailbox { .. }
                    )
                })
                .expect("machine mailbox storage");
            let symbol = &machine.symbols[mailbox.symbol.0 as usize];
            assert!(first.symbols().iter().any(|item| item.name == symbol.name));
        }
    }

    let prepare_with_machine_limits = |machine_limits: MachineLoweringLimits| {
        let codec = CanonicalFlowWirCodec;
        let hasher = CanonicalBackendContentHasher::new();
        let optimizer = CanonicalFlowOptimizer::new();
        let machine_lowerer = CanonicalMachineLowerer::new();
        let expected_digest = hasher
            .sha256(encoded.bytes(), &never_cancelled)
            .expect("canonical actor-send frame digest");
        let optimization = OptimizationProfile::from_build_policy(
            &build.profile.optimization,
            build.identity.compiler,
        )
        .expect("actor-send optimization profile");
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
        .expect("real actor send accepts exact MachineWir collection and byte ceilings");
    assert_eq!(machine, exact_prepared.machine().wir().as_wir());

    let mut below_static = exact_machine_limits;
    below_static.static_bytes -= 1;
    let below_static_error = prepare_with_machine_limits(below_static)
        .expect_err("one byte below actor-send storage must fail closed");
    assert_eq!(
        below_static_error.machine_lower_error(),
        Some(&MachineLowerError::ResourceLimit {
            resource: "MachineWir static bytes",
            limit: below_static.static_bytes,
        })
    );
    let mut below_instructions = exact_machine_limits;
    below_instructions.instructions -= 1;
    below_instructions = below_instructions.with_aligned_validation();
    let below_instruction_error = prepare_with_machine_limits(below_instructions)
        .expect_err("one instruction below actor-send lowering must fail closed");
    assert_eq!(
        below_instruction_error.machine_lower_error(),
        Some(&MachineLowerError::ResourceLimit {
            resource: "MachineWir instructions",
            limit: below_instructions.instructions,
        })
    );

    let successful_polls = Cell::new(0_u32);
    prepare_canonical_frame_for_codegen(encoded.bytes(), &target, &build, &|| {
        successful_polls.set(successful_polls.get().saturating_add(1));
        false
    })
    .expect("counted actor-send backend preparation");
    let cancel_at = successful_polls.get().saturating_sub(1);
    assert!(cancel_at > 1);
    for _ in 0..2 {
        let cancelled_polls = Cell::new(0_u32);
        let cancelled =
            prepare_canonical_frame_for_codegen(encoded.bytes(), &target, &build, &|| {
                let next = cancelled_polls.get().saturating_add(1);
                cancelled_polls.set(next);
                next == cancel_at
            })
            .expect_err("late actor-send cancellation cannot publish MachineWir");
        assert!(cancelled.is_cancelled());
        assert_eq!(cancelled_polls.get(), cancel_at);
    }

    let machine_task = machine
        .functions
        .iter()
        .find(|function| {
            matches!(
                function.role,
                wrela_backend::machine_wir::MachineFunctionRole::TaskEntry(_)
            )
        })
        .expect("machine startup task");
    let machine_actor = machine
        .functions
        .iter()
        .find(|function| {
            matches!(
                function.role,
                wrela_backend::machine_wir::MachineFunctionRole::ActorTurn(_)
            )
        })
        .expect("machine actor turn");
    let machine_task_index = machine_task.id.0 as usize;
    let machine_actor_index = machine_actor.id.0 as usize;
    let machine_task_entry = machine_task.entry.0 as usize;
    let machine_actor_entry = machine_actor.entry.0 as usize;
    let machine_reserve_index = machine_task.blocks[machine_task_entry]
        .instructions
        .iter()
        .position(|instruction| {
            matches!(instruction.operation, MachineOperation::ActorReserve { .. })
        })
        .expect("machine actor reserve");
    let machine_commit_index = machine_reserve_index + 1;
    let image = &machine.functions[machine.image_entry.0 as usize];
    let success = match &image.blocks[image.entry.0 as usize].terminator {
        wrela_backend::machine_wir::MachineTerminator::Switch { cases, .. } => cases[0].1,
        other => panic!("image entry must route successful runtime entry: {other:?}"),
    };
    let machine_dispatch_index = image.blocks[success.0 as usize]
        .instructions
        .iter()
        .position(|instruction| {
            matches!(
                instruction.operation,
                MachineOperation::MailboxDispatch { .. }
            )
        })
        .expect("machine mailbox dispatch");

    let mut wrong_machine_method = machine.clone();
    let MachineOperation::ActorReserve { method, .. } =
        &mut wrong_machine_method.functions[machine_task_index].blocks[machine_task_entry]
            .instructions[machine_reserve_index]
            .operation
    else {
        panic!("machine actor reserve operation");
    };
    *method = machine_task.id;
    let errors = wrong_machine_method
        .validate_for_target(&target)
        .expect_err("machine reserve method cannot be substituted");
    assert!(errors.0.iter().any(|error| matches!(
        error,
        ValidationError::InvalidRecord {
            kind: "actor mailbox message contract",
            ..
        } | ValidationError::InvalidRecord {
            kind: "actor mailbox reserve contract",
            ..
        }
    )));

    let mut omitted_machine_commit = machine.clone();
    omitted_machine_commit.functions[machine_task_index].blocks[machine_task_entry]
        .instructions
        .remove(machine_commit_index);
    let errors = omitted_machine_commit
        .validate_for_target(&target)
        .expect_err("machine reservation cannot omit commit");
    assert!(errors.0.iter().any(|error| matches!(
        error,
        ValidationError::InvalidRecord {
            kind: "actor mailbox message contract",
            ..
        } | ValidationError::InvalidRecord {
            kind: "actor mailbox reserve contract",
            ..
        }
    )));

    let mut duplicate_machine_commit = machine.clone();
    let duplicate = duplicate_machine_commit.functions[machine_task_index].blocks
        [machine_task_entry]
        .instructions[machine_commit_index]
        .clone();
    duplicate_machine_commit.functions[machine_task_index].blocks[machine_task_entry]
        .instructions
        .insert(machine_commit_index + 1, duplicate);
    let errors = duplicate_machine_commit
        .validate_for_target(&target)
        .expect_err("machine reservation cannot commit twice");
    assert!(errors.0.iter().any(|error| matches!(
        error,
        ValidationError::InvalidRecord {
            kind: "actor mailbox message contract",
            ..
        }
    )));

    let mut omitted_machine_receive = machine.clone();
    omitted_machine_receive.functions[machine_actor_index].blocks[machine_actor_entry]
        .instructions
        .remove(0);
    let errors = omitted_machine_receive
        .validate_for_target(&target)
        .expect_err("machine actor turn cannot omit receive and clear");
    assert!(errors.0.iter().any(|error| matches!(
        error,
        ValidationError::InvalidRecord {
            kind: "actor mailbox message contract",
            ..
        }
    )));

    let mut omitted_machine_dispatch = machine.clone();
    omitted_machine_dispatch.functions[machine.image_entry.0 as usize].blocks[success.0 as usize]
        .instructions
        .remove(machine_dispatch_index);
    let errors = omitted_machine_dispatch
        .validate_for_target(&target)
        .expect_err("machine image cannot omit conditional dispatch");
    assert!(errors.0.iter().any(|error| matches!(
        error,
        ValidationError::InvalidRecord {
            kind: "actor mailbox message contract",
            ..
        }
    )));

    let mut substituted_machine_dispatch = machine.clone();
    let replacement_mailbox = substituted_machine_dispatch
        .region_storage
        .iter()
        .find(|storage| {
            !matches!(
                storage.kind,
                wrela_backend::machine_wir::MachineRegionStorageKind::ActorMailbox { .. }
            )
        })
        .expect("non-mailbox actor storage")
        .global;
    let MachineOperation::MailboxDispatch { mailbox, .. } = &mut substituted_machine_dispatch
        .functions[machine.image_entry.0 as usize]
        .blocks[success.0 as usize]
        .instructions[machine_dispatch_index]
        .operation
    else {
        panic!("machine mailbox dispatch operation");
    };
    *mailbox = replacement_mailbox;
    let errors = substituted_machine_dispatch
        .validate_for_target(&target)
        .expect_err("machine dispatch mailbox cannot be substituted");
    assert!(errors.0.iter().any(|error| matches!(
        error,
        ValidationError::InvalidRecord {
            kind: "actor mailbox message contract",
            ..
        }
    )));

    let task_index = task.id.0 as usize;
    let actor_index = actor.id.0 as usize;
    let task_block = task
        .blocks
        .iter()
        .position(|block| {
            block.instructions.iter().any(|instruction| {
                matches!(
                    instruction.operation,
                    flow::FlowOperation::ActorReserve { .. }
                )
            })
        })
        .expect("task reserve block");
    let reserve_index = task.blocks[task_block]
        .instructions
        .iter()
        .position(|instruction| {
            matches!(
                instruction.operation,
                flow::FlowOperation::ActorReserve { .. }
            )
        })
        .expect("task reserve instruction");
    let commit_index = reserve_index + 1;

    let mut wrong_method = flow.clone();
    let flow::FlowOperation::ActorReserve { method, .. } =
        &mut wrong_method.functions[task_index].blocks[task_block].instructions[reserve_index]
            .operation
    else {
        panic!("reserve operation");
    };
    *method = task.id;
    let errors = wrong_method
        .validate()
        .expect_err("a task function cannot substitute for the actor method");
    assert!(has_invalid_record(&errors, "actor reserve contract"));

    let mut wrong_proof = flow.clone();
    let replacement = wrong_proof
        .proofs
        .iter()
        .find(|proof| proof.kind != flow::ProofKind::CapacityBound)
        .expect("non-capacity proof")
        .id;
    let flow::FlowOperation::ActorReserve { proof, .. } =
        &mut wrong_proof.functions[task_index].blocks[task_block].instructions[reserve_index]
            .operation
    else {
        panic!("reserve operation");
    };
    *proof = replacement;
    let errors = wrong_proof
        .validate()
        .expect_err("an unrelated proof cannot authorize mailbox admission");
    assert!(has_invalid_record(&errors, "actor reserve contract"));

    let mut omitted_commit = flow.clone();
    omitted_commit.functions[task_index].blocks[task_block]
        .instructions
        .remove(commit_index);
    renumber_instructions(&mut omitted_commit.functions[task_index]);
    let errors = omitted_commit
        .validate()
        .expect_err("a reservation cannot be left uncommitted");
    assert!(has_invalid_record(&errors, "actor reservation delivery"));

    let mut duplicate_commit = flow.clone();
    let duplicate = duplicate_commit.functions[task_index].blocks[task_block].instructions
        [commit_index]
        .clone();
    duplicate_commit.functions[task_index].blocks[task_block]
        .instructions
        .insert(commit_index + 1, duplicate);
    renumber_instructions(&mut duplicate_commit.functions[task_index]);
    let errors = duplicate_commit
        .validate()
        .expect_err("one reservation cannot be committed twice");
    assert!(has_invalid_record(&errors, "actor reservation delivery"));

    let mut omitted_receive = flow.clone();
    omitted_receive.functions[actor_index].blocks[actor.entry.0 as usize]
        .instructions
        .remove(0);
    renumber_instructions(&mut omitted_receive.functions[actor_index]);
    let errors = omitted_receive
        .validate()
        .expect_err("an admitted message requires one matching receive");
    assert!(has_invalid_record(
        &errors,
        "actor mailbox dispatch contract"
    ));

    let mut substituted_receive = flow.clone();
    let flow::FlowOperation::MailboxReceive { method, .. } =
        &mut substituted_receive.functions[actor_index].blocks[actor.entry.0 as usize].instructions
            [0]
        .operation
    else {
        panic!("mailbox receive operation");
    };
    *method = task.id;
    let errors = substituted_receive
        .validate()
        .expect_err("mailbox receive method identity cannot be substituted");
    assert!(has_invalid_record(&errors, "mailbox receive contract"));
}
