#![forbid(unsafe_code)]

use std::sync::Arc;

use wrela_backend::{
    CodegenError, MachineLowerError, emit_prepared_object, flow_wir as flow,
    llvm_backend_available,
    machine_wir::{CheckedIntegerOp, MachineOperation, MachineRegionStorageKind, ValidationError},
    prepare_canonical_frame_for_codegen,
};
use wrela_build_model::{
    BuildConfiguration, BuildIdentity, BuildProfile, LanguageRevision, Sha256Digest,
    TargetIdentity, seal_build_configuration,
};
use wrela_compiler::{AnalysisFactAssembler, AnalysisFactRequest, CanonicalAnalysisFactAssembler};
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
const ACTOR_STATE_SOURCE: &str = r#"module app

from core.image import Image, Target

async fn checkpoint():
    pass

@service
pub struct Worker:
    value: u64 = 0

    pub async fn ping(mut self):
        self.value = 5
        self.value += 7
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
fn canonical_checked_add_actor_state_reaches_native_machine_storage() {
    let source_graph_digest = Sha256Digest::from_bytes([0xb1; 32]);
    let core_package_digest = Sha256Digest::from_bytes([0xb2; 32]);
    let target_digest = Sha256Digest::from_bytes([0xb3; 32]);
    let mut sources = SourceDatabase::default();
    let application_file = sources
        .add(SourceInput {
            path: "app.wr".to_owned(),
            text: ACTOR_STATE_SOURCE.to_owned(),
            digest: Sha256Digest::from_bytes([0xb4; 32]),
        })
        .expect("actor state source");
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
                .expect("actor state parses")
                .into_parts();
            assert!(diagnostics.is_empty(), "parse diagnostics: {diagnostics:?}");
            parsed
        })
        .collect::<Vec<_>>();

    let mut packages = PackageGraphBuilder::new(identity(
        "actor-state-application",
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
            ModulePath::new(["app".to_owned()]).expect("app module"),
            application_file,
        )
        .expect("app module record");
    packages
        .add_module(
            core,
            ModulePath::new(["image".to_owned()]).expect("core image module"),
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
        .expect("actor state lowers to HIR");
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
                    name: "actor-image",
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
        .expect("actor state semantic analysis");
    assert!(
        analysis.diagnostics().is_empty(),
        "semantic diagnostics: {:?}",
        analysis.diagnostics()
    );
    let analyzed = analysis.into_parts().0.expect("sealed actor state image");
    let graph = analyzed.facts().graph.as_ref().expect("actor graph");
    let state = graph
        .regions
        .iter()
        .find(|region| region.name.ends_with(".state"))
        .expect("semantic actor state region");
    assert_eq!(state.capacity_bytes, 8);
    assert_eq!(state.alignment, 8);
    assert_eq!(
        state.owner,
        wrela_sema::ImageOwner::Actor(wrela_sema::ActorId(0))
    );
    let report = CanonicalAnalysisFactAssembler::new()
        .assemble(
            AnalysisFactRequest {
                analysis: &analyzed,
                limits: wrela_image_report::AnalysisFactLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("compound actor-state promotions reach the image report");
    let report = report.as_facts();
    assert_eq!(
        report
            .region_assignments
            .iter()
            .map(|fact| fact.allocation.as_str())
            .collect::<Vec<_>>(),
        [
            "alloc:0:actor-state-store",
            "alloc:1:actor-state-compound-store",
        ]
    );
    assert_eq!(
        report
            .promotions
            .iter()
            .map(|fact| fact.allocation.as_str())
            .collect::<Vec<_>>(),
        [
            "alloc:0:actor-state-store",
            "alloc:1:actor-state-compound-store",
        ]
    );
    assert!(report.promotions.iter().all(|fact| {
        fact.source_region == wrela_image_report::RegionClass::TaskFrame
            && fact.destination_region == wrela_image_report::RegionClass::Image
            && fact.reason == "actor state store outlives its non-reentrant turn frame"
            && report.proofs[fact.proof as usize].category == "region-bound"
    }));

    let semantic_output = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analyzed,
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("actor state reaches SemanticWir");
    let semantic_state = semantic_output
        .wir()
        .as_wir()
        .regions
        .iter()
        .find(|region| region.name.ends_with(".state"))
        .expect("SemanticWir state region");
    assert_eq!(semantic_state.class, semantic::RegionClass::Image);
    assert_eq!(semantic_state.capacity_bytes, 8);
    assert_eq!(semantic_state.alignment, 8);
    assert_eq!(
        semantic_state.owner,
        semantic::ImageOwner::Actor(semantic::ActorId(0))
    );
    let semantic_actor_turn = semantic_output
        .wir()
        .as_wir()
        .functions
        .iter()
        .find(|function| function.role == semantic::FunctionRole::ActorTurn(semantic::ActorId(0)))
        .expect("SemanticWir actor turn");
    let semantic_state_operations = semantic_actor_turn
        .body
        .statements
        .iter()
        .filter_map(|statement| match statement {
            semantic::SemanticStatement::Let(statement)
                if matches!(
                    statement.operation,
                    semantic::SemanticOperation::Promote { .. }
                        | semantic::SemanticOperation::ActorStateLoad { .. }
                        | semantic::SemanticOperation::Binary { .. }
                        | semantic::SemanticOperation::ActorStateStore { .. }
                ) =>
            {
                Some(statement)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert!(matches!(
        semantic_state_operations.as_slice(),
        [
            semantic::LetStatement {
                results: promotion_results,
                operation: semantic::SemanticOperation::Promote {
                    value: promoted,
                    destination: promotion_region,
                    proof: promotion_proof,
                },
                source: promotion_source,
            },
            semantic::LetStatement {
                results: direct_store_results,
                operation: semantic::SemanticOperation::ActorStateStore {
                    actor: semantic::ActorId(0),
                    region: direct_store_region,
                    value: directly_stored,
                    proof: direct_store_proof,
                },
                source: direct_store_source,
            },
            semantic::LetStatement {
                results: loaded,
                operation: semantic::SemanticOperation::ActorStateLoad {
                    actor: semantic::ActorId(0),
                    region,
                    proof,
                },
                ..
            },
            semantic::LetStatement {
                results: summed,
                operation: semantic::SemanticOperation::Binary {
                    operator: semantic::BinaryOperator::Add,
                    left,
                    arithmetic: semantic::ArithmeticMode::Checked,
                    ..
                },
                ..
            },
            semantic::LetStatement {
                results: compound_promotion_results,
                operation: semantic::SemanticOperation::Promote {
                    value: compound_promoted,
                    destination: compound_promotion_region,
                    proof: compound_promotion_proof,
                },
                source: compound_promotion_source,
            },
            semantic::LetStatement {
                results: stored_results,
                operation: semantic::SemanticOperation::ActorStateStore {
                    actor: semantic::ActorId(0),
                    region: store_region,
                    value: stored,
                    proof: store_proof,
                },
                source: compound_store_source,
            },
        ] if promotion_results.is_empty()
            && direct_store_results.is_empty()
            && *promoted == *directly_stored
            && *promotion_region == semantic_state.id
            && *direct_store_region == semantic_state.id
            && *direct_store_proof == semantic_state.proof
            && *promotion_source == *direct_store_source
            && semantic_actor_turn.proofs.contains(promotion_proof)
            && *region == semantic_state.id
            && store_region == region
            && *proof == semantic_state.proof
            && store_proof == proof
            && matches!(loaded.as_slice(), [loaded] if loaded == left)
            && matches!(summed.as_slice(), [sum] if sum == stored)
            && compound_promotion_results.is_empty()
            && compound_promoted == stored
            && *compound_promotion_region == semantic_state.id
            && semantic_actor_turn.proofs.contains(compound_promotion_proof)
            && *compound_promotion_source == *compound_store_source
            && stored_results.is_empty()
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
        .expect("actor state reaches FlowWir");
    let flow_state = flow_output
        .wir()
        .as_wir()
        .regions
        .iter()
        .find(|region| region.name.ends_with(".state"))
        .expect("FlowWir state region");
    assert_eq!(flow_state.class, flow::RegionClass::Image);
    assert_eq!(flow_state.capacity_bytes, 8);
    assert_eq!(flow_state.alignment, 8);
    assert_eq!(flow_state.owner, flow::PlanOwner::Actor(flow::ActorId(0)));
    let flow_actor_turn = flow_output
        .wir()
        .as_wir()
        .functions
        .iter()
        .find(|function| function.role == flow::FunctionRole::ActorTurn(flow::ActorId(0)))
        .expect("FlowWir actor turn");
    let flow_promotions = flow_actor_turn
        .blocks
        .iter()
        .flat_map(|block| &block.instructions)
        .filter(|instruction| {
            matches!(
                instruction.operation,
                flow::FlowOperation::Promote {
                    destination,
                    proof,
                    ..
                } if destination == flow_state.id
                    && flow_actor_turn.proofs.contains(&proof)
            )
        })
        .count();
    assert_eq!(flow_promotions, 2);
    let flow_state_addresses = flow_actor_turn
        .blocks
        .iter()
        .flat_map(|block| &block.instructions)
        .filter(|instruction| {
            matches!(
                instruction.operation,
                flow::FlowOperation::ActorStateAddress {
                    actor: flow::ActorId(0),
                    region,
                    proof,
                } if region == flow_state.id && proof == flow_state.capacity_proof
            )
        })
        .count();
    assert_eq!(flow_state_addresses, 3);
    assert_eq!(
        flow_actor_turn
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .filter(|instruction| matches!(instruction.operation, flow::FlowOperation::Load { .. }))
            .count(),
        1
    );
    assert_eq!(
        flow_actor_turn
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .filter(|instruction| matches!(
                instruction.operation,
                flow::FlowOperation::Binary {
                    op: flow::BinaryOp::AddChecked,
                    ..
                }
            ))
            .count(),
        1
    );
    assert_eq!(
        flow_actor_turn
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .filter(|instruction| matches!(
                instruction.operation,
                flow::FlowOperation::Store { .. }
            ))
            .count(),
        2
    );
    let mut forged_flow = flow_output.wir().as_wir().clone();
    let forged_turn = forged_flow
        .functions
        .iter_mut()
        .find(|function| function.role == flow::FunctionRole::ActorTurn(flow::ActorId(0)))
        .expect("forged FlowWir actor turn");
    let compound_right = forged_turn
        .blocks
        .iter()
        .flat_map(|block| &block.instructions)
        .find_map(|instruction| match instruction.operation {
            flow::FlowOperation::Binary {
                op: flow::BinaryOp::AddChecked,
                right,
                ..
            } => Some(right),
            _ => None,
        })
        .expect("compound RHS value");
    let compound_promotion = forged_turn
        .blocks
        .iter_mut()
        .flat_map(|block| &mut block.instructions)
        .filter(|instruction| matches!(instruction.operation, flow::FlowOperation::Promote { .. }))
        .nth(1)
        .expect("compound promotion marker");
    let flow::FlowOperation::Promote { value, .. } = &mut compound_promotion.operation else {
        unreachable!("filtered compound promotion")
    };
    *value = compound_right;
    let forged_flow = forged_flow
        .validate()
        .expect("RHS substitution remains structurally valid FlowWir");
    let forged_encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: &forged_flow,
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("RHS substitution remains structurally valid FlowWir");
    let error = prepare_canonical_frame_for_codegen(
        forged_encoded.bytes(),
        &target,
        &build,
        &never_cancelled,
    )
    .expect_err("Machine lowering must reject compound promotion of the RHS");
    assert_eq!(
        error.machine_lower_error(),
        Some(&MachineLowerError::UnsupportedInput {
            feature: "machine-async-result-delivery-pending",
        })
    );
    let encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: flow_output.wir(),
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("actor state FlowWir encodes canonically");
    let prepared =
        prepare_canonical_frame_for_codegen(encoded.bytes(), &target, &build, &never_cancelled)
            .expect("canonical actor state reaches MachineWir");
    let machine = prepared.machine().wir().as_wir();
    assert_eq!(
        machine
            .functions
            .iter()
            .flat_map(|function| &function.blocks)
            .map(|block| block.instructions.len())
            .sum::<usize>(),
        14,
        "both lifetime markers are erased before exact MachineWir instruction accounting"
    );
    assert_eq!(machine.version, 16);
    let machine_state = machine
        .region_storage
        .iter()
        .find(|storage| {
            matches!(
                storage.kind,
                MachineRegionStorageKind::ActorState { actor: 0 }
            )
        })
        .expect("MachineWir actor state storage");
    assert_eq!(machine_state.name, flow_state.name);
    assert_eq!(machine_state.capacity_units, 1);
    assert_eq!(machine_state.bytes_per_unit, 8);
    assert_eq!(machine_state.capacity_bytes, 8);
    assert_eq!(machine_state.alignment, 8);
    let machine_actor_turn = machine
        .functions
        .iter()
        .find(|function| {
            function.role == wrela_backend::machine_wir::MachineFunctionRole::ActorTurn(0)
        })
        .expect("MachineWir actor turn");
    assert_eq!(
        machine_actor_turn
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .filter(|instruction| {
                instruction.operation == MachineOperation::GlobalAddress(machine_state.global)
            })
            .count(),
        3
    );
    assert_eq!(
        machine_actor_turn
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .filter(|instruction| matches!(instruction.operation, MachineOperation::Load { .. }))
            .count(),
        1
    );
    assert_eq!(
        machine_actor_turn
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .filter(|instruction| matches!(
                instruction.operation,
                MachineOperation::CheckedInteger {
                    op: CheckedIntegerOp::Add,
                    ..
                }
            ))
            .count(),
        1
    );
    assert_eq!(
        machine_actor_turn
            .blocks
            .iter()
            .flat_map(|block| &block.instructions)
            .filter(|instruction| matches!(instruction.operation, MachineOperation::Store { .. }))
            .count(),
        2
    );

    let repeated =
        prepare_canonical_frame_for_codegen(encoded.bytes(), &target, &build, &never_cancelled)
            .expect("repeated canonical actor-state preparation");
    assert_eq!(machine, repeated.machine().wir().as_wir());

    let state_id = machine_state.id;
    let state_section = machine.sections[machine_state.section.0 as usize].clone();
    let state_symbol = machine.symbols[machine_state.symbol.0 as usize].clone();
    match emit_prepared_object(&prepared, &target, &never_cancelled) {
        Err(CodegenError::BackendNotBuilt) if !llvm_backend_available() => {}
        Err(CodegenError::BackendNotBuilt) => {
            panic!("LLVM reports available but rejected actor-state emission")
        }
        Err(error) => panic!("actor state must pass native codegen: {error}"),
        Ok(_) if !llvm_backend_available() => {
            panic!("native actor-state object emitted while LLVM reports unavailable")
        }
        Ok(first) => {
            let second = emit_prepared_object(&prepared, &target, &never_cancelled)
                .expect("repeated actor-state native object emission");
            assert_eq!(first, second, "actor-state COFF must be byte-identical");
            assert_eq!(first.bytes().get(..2), Some([0x64, 0xaa].as_slice()));
            let emitted_section = first
                .sections()
                .iter()
                .find(|section| section.name == state_section.name)
                .expect("actor state has a native writable section");
            assert_eq!(emitted_section.alignment, 8);
            assert_eq!(emitted_section.file_bytes, 8);
            assert_eq!(emitted_section.virtual_bytes, 8);
            let emitted_symbol = first
                .symbols()
                .iter()
                .find(|symbol| symbol.name == state_symbol.name)
                .expect("actor state has a native storage symbol");
            assert_eq!(emitted_symbol.section, state_section.name);
            assert_eq!(emitted_symbol.section_offset, 0);
            assert_eq!(emitted_symbol.bytes, 8);
        }
    }

    let mut wrong_owner = machine.clone();
    wrong_owner.region_storage[state_id.0 as usize].kind =
        MachineRegionStorageKind::ActorState { actor: 1 };
    let errors = wrong_owner
        .validate_for_target(&target)
        .expect_err("actor state cannot be reassigned to another actor");
    assert!(
        errors
            .0
            .contains(&ValidationError::InvalidRegionStorage(state_id))
    );

    let mut wrong_proof = machine.clone();
    wrong_proof.region_storage[state_id.0 as usize].capacity_proof =
        wrong_proof.region_storage[0].capacity_proof;
    let errors = wrong_proof
        .validate_for_target(&target)
        .expect_err("actor state cannot borrow the mailbox capacity proof");
    assert!(
        errors
            .0
            .contains(&ValidationError::InvalidRegionStorage(state_id))
    );

    let mut wrong_order = machine.clone();
    wrong_order
        .region_storage
        .swap(state_id.0 as usize, state_id.0 as usize + 1);
    let errors = wrong_order
        .validate_for_target(&target)
        .expect_err("actor state must remain between mailbox and turn-frame storage");
    assert!(errors.0.iter().any(|error| matches!(
        error,
        ValidationError::NonDenseId {
            kind: "region storage",
            ..
        }
    )));

    let mut wrong_layout = machine.clone();
    wrong_layout.region_storage[state_id.0 as usize].bytes_per_unit = 16;
    let errors = wrong_layout
        .validate_for_target(&target)
        .expect_err("actor state cannot widen beyond one u64 cell");
    assert!(
        errors
            .0
            .contains(&ValidationError::InvalidRegionStorage(state_id))
    );

    let mut wrong_name = machine.clone();
    let renamed_state = wrong_name.region_storage[state_id.0 as usize].clone();
    wrong_name.region_storage[state_id.0 as usize].name = "Renamed.state".to_owned();
    wrong_name.sections[renamed_state.section.0 as usize].owner = "Renamed.state".to_owned();
    wrong_name.types[renamed_state.ty.0 as usize].source_name = Some("Renamed.state".to_owned());
    let errors = wrong_name
        .validate_for_target(&target)
        .expect_err("actor state must retain the matching mailbox actor-name stem");
    assert!(
        errors
            .0
            .contains(&ValidationError::InvalidRegionStorage(state_id))
    );
}
