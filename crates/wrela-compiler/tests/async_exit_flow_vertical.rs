#![forbid(unsafe_code)]

use std::sync::Arc;

use wrela_backend::{MachineLowerError, flow_wir as flow, prepare_canonical_frame_for_codegen};
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

const CORE_ACTOR_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/actor.wr");
const CORE_IMAGE_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/image.wr");
const CORE_RESULT_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/result.wr");

const APPLICATION_SOURCE: &str = r#"module app

from core.actor import AsyncExit
from core.image import Image, Target
from core.result import Result

async fn checkpoint() -> Result[u64, u64]:
    return Result.Ok(7)

@service
pub struct Worker:
    @task
    async fn consume(mut self):
        match await checkpoint():
            case Result.Ok(value):
                pass
            case Result.Err(outcome):
                match outcome:
                    case AsyncExit.Operation(error):
                        pass
                    case AsyncExit.Cancelled(_):
                        pass
                    case AsyncExit.DeadlineRejected(_):
                        pass
                    case AsyncExit.DeadlineExceeded(_):
                        pass

@image
pub fn boot() -> Image:
    img = Image(name="actor-image", target=Target.aarch64_qemu_virt_uefi)
    installed = img.service(Worker, mailbox=1)
    return img
"#;

const DIRECT_IS_SOURCE: &str = r#"module app

from core.actor import AsyncExit
from core.image import Image, Target
from core.result import Result

async fn checkpoint() -> Result[u64, u64]:
    return Result.Ok(7)

@service
pub struct Worker:
    @task
    async fn consume(mut self):
        selected: bool = await checkpoint() is Result.Err(_)

@image
pub fn boot() -> Image:
    img = Image(name="actor-image", target=Target.aarch64_qemu_virt_uefi)
    installed = img.service(Worker, mailbox=1)
    return img
"#;

fn never_cancelled() -> bool {
    false
}

fn identity(name: &str, digest: Sha256Digest) -> PackageIdentity {
    PackageIdentity {
        name: PackageName::new(name).expect("package name"),
        version: PackageVersion::new("1.0.0").expect("package version"),
        source_digest: digest,
    }
}

struct CompiledFixture {
    semantic: semantic::ValidatedSemanticWir,
    target: TargetPackage,
    build: wrela_build_model::ValidatedBuildConfiguration,
}

fn compile_semantic(application_source: &str) -> CompiledFixture {
    let source_graph_digest = Sha256Digest::from_bytes([0xb1; 32]);
    let target_digest = Sha256Digest::from_bytes([0xb2; 32]);
    let mut sources = SourceDatabase::default();
    let inputs = [
        ("app.wr", application_source, [0xb3; 32]),
        ("core/actor.wr", CORE_ACTOR_SOURCE, [0xb4; 32]),
        ("core/image.wr", CORE_IMAGE_SOURCE, [0xb5; 32]),
        ("core/result.wr", CORE_RESULT_SOURCE, [0xb6; 32]),
    ];
    let files = inputs
        .into_iter()
        .map(|(path, text, digest)| {
            sources
                .add(SourceInput {
                    path: path.to_owned(),
                    text: text.to_owned(),
                    digest: Sha256Digest::from_bytes(digest),
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

    let mut packages = PackageGraphBuilder::new(identity(
        "async-exit-application",
        Sha256Digest::from_bytes([0xb7; 32]),
    ));
    let core = packages
        .add_package(identity("wrela-core", Sha256Digest::from_bytes([0xb8; 32])))
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
            files[0],
        )
        .expect("application module record");
    for (name, file) in [
        ("actor", files[1]),
        ("image", files[2]),
        ("result", files[3]),
    ] {
        packages
            .add_module(
                core,
                ModulePath::new([name.to_owned()]).expect("core module"),
                file,
            )
            .expect("core module record");
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
        .expect("source lowers to HIR");
    assert!(hir_output.diagnostics().is_empty());
    let image_entry = hir_output.lowered().program().as_program().image_candidates[0];
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
        .expect("semantic analysis");
    assert!(analysis.diagnostics().is_empty());
    let semantic = CanonicalSemanticLowerer::new()
        .lower(
            SemanticLowerRequest {
                input: analysis.into_parts().0.expect("sealed image"),
                limits: SemanticLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("SemanticWir lowering")
        .into_parts()
        .0;
    CompiledFixture {
        semantic,
        target,
        build,
    }
}

#[test]
fn authenticated_async_exit_reaches_exact_flow_suspend_and_match_protocol() {
    let fixture = compile_semantic(APPLICATION_SOURCE);
    let semantic = fixture.semantic.clone();
    let lowered = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic.clone(),
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("authenticated AsyncExit reaches FlowWir");
    assert_eq!(lowered.report().async_states, 1);
    let wir = lowered.wir().as_wir();
    let exit = wir
        .types
        .iter()
        .find(|ty| ty.name.as_deref() == Some("AsyncExit"))
        .expect("authenticated AsyncExit Flow type");
    let flow::FlowTypeKind::Enum { variants: exits } = &exit.kind else {
        panic!("AsyncExit lowers to one exact closed Flow enum")
    };
    assert_eq!(exits.len(), 4);
    let outcome = wir
        .types
        .iter()
        .find(|ty| {
            matches!(&ty.kind, flow::FlowTypeKind::Enum { variants }
                if variants.as_slice() == [vec![flow::TypeId(2)], vec![exit.id]])
        })
        .expect("authenticated Result[u64,AsyncExit[u64]] Flow type");
    let authority = wir
        .proofs
        .iter()
        .find(|proof| proof.subject == "direct fallible await widens to AsyncExit[u64]")
        .expect("Flow retains exact async-outcome authority");
    assert_eq!(authority.kind, flow::ProofKind::TypeChecked);
    assert_eq!(authority.bound, Some(1));
    assert_eq!(authority.depends_on, [flow::ProofId(0), flow::ProofId(1)]);

    let caller = wir
        .functions
        .iter()
        .find(|function| matches!(function.role, flow::FunctionRole::TaskEntry(_)))
        .expect("one exact outcome consumer");
    let suspend = caller
        .blocks
        .iter()
        .find_map(|block| match block.terminator {
            flow::Terminator::Suspend {
                state,
                activation,
                resume,
            } => Some((state, activation, resume)),
            _ => None,
        })
        .expect("authenticated await becomes one suspension");
    assert_eq!(suspend.0, 0);
    let activation_ty = wir
        .types
        .get(caller.values[suspend.1.0 as usize].ty.0 as usize)
        .expect("activation type");
    assert_eq!(
        activation_ty.kind,
        flow::FlowTypeKind::Activation { result: outcome.id }
    );
    let [delivered] = caller.blocks[suspend.2.0 as usize].parameters.as_slice() else {
        panic!("resume delivers exactly one authenticated outcome")
    };
    assert_eq!(caller.values[delivered.0 as usize].ty, outcome.id);
    assert_eq!(
        caller
            .blocks
            .iter()
            .filter(|block| matches!(block.terminator, flow::Terminator::Switch { .. }))
            .count(),
        2,
        "outer Result and nested AsyncExit are both explicit Flow switches"
    );

    let encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: lowered.wir(),
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("authenticated AsyncExit FlowWir round-trips canonically");
    let machine_error = prepare_canonical_frame_for_codegen(
        encoded.bytes(),
        &fixture.target,
        &fixture.build,
        &never_cancelled,
    )
    .expect_err("runtime cause delivery remains an explicit Machine boundary");
    assert_eq!(
        machine_error.machine_lower_error(),
        Some(&MachineLowerError::UnsupportedInput {
            feature: "machine-async-outcome-lowering-pending (scheduler cancellation and deadline delivery)",
        })
    );
    let mut proof_subject_forgery = lowered.wir().as_wir().clone();
    proof_subject_forgery.proofs[authority.id.0 as usize].subject =
        "forged but structurally valid proof subject".to_owned();
    let proof_subject_forgery = proof_subject_forgery
        .validate()
        .expect("proof-subject mutation remains structurally valid FlowWir");
    let forged_encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: &proof_subject_forgery,
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("proof-subject mutation encodes canonically");
    let forged_machine_error = prepare_canonical_frame_for_codegen(
        forged_encoded.bytes(),
        &fixture.target,
        &fixture.build,
        &never_cancelled,
    )
    .expect_err("the structural async-outcome profile retains the Machine boundary");
    assert_eq!(
        forged_machine_error.machine_lower_error(),
        Some(&MachineLowerError::UnsupportedInput {
            feature: "machine-async-outcome-lowering-pending (scheduler cancellation and deadline delivery)",
        })
    );

    let exact_instructions = lowered.report().instructions;
    let mut exact = FlowLoweringLimits::standard();
    exact.instructions = exact_instructions;
    CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic.clone(),
                limits: exact,
            },
            &never_cancelled,
        )
        .expect("exact AsyncExit Flow instruction limit");
    let mut one_under = exact;
    one_under.instructions = exact_instructions - 1;
    assert!(matches!(
        CanonicalFlowLowerer::new().lower(
            FlowLowerRequest {
                input: semantic.clone(),
                limits: one_under,
            },
            &never_cancelled,
        ),
        Err(FlowLowerError::ResourceLimit {
            resource: "FlowWir instructions",
            limit,
        }) if limit == exact_instructions - 1
    ));

    let mut forged = wir.clone();
    forged.proofs[authority.id.0 as usize].subject = "ordinary await".to_owned();
    assert!(
        forged.clone().validate().is_ok(),
        "forgery remains structurally valid"
    );
    assert!(matches!(
        wrela_flow_lower::seal(
            &FlowLowerRequest {
                input: semantic.clone(),
                limits: FlowLoweringLimits::standard(),
            },
            forged,
            lowered.report().clone(),
            Vec::new(),
            &never_cancelled,
        ),
        Err(FlowLowerError::InvalidReport(_))
    ));
    let mut forged_operation = wir.clone();
    let cases = forged_operation
        .functions
        .iter_mut()
        .flat_map(|function| &mut function.blocks)
        .find_map(|block| match &mut block.terminator {
            flow::Terminator::Switch { cases, .. } if cases.len() == 2 => Some(cases),
            _ => None,
        })
        .expect("outer async-outcome switch");
    cases.swap(0, 1);
    assert!(
        forged_operation.clone().validate().is_ok(),
        "case-order substitution remains structurally valid"
    );
    assert!(matches!(
        wrela_flow_lower::seal(
            &FlowLowerRequest {
                input: semantic.clone(),
                limits: FlowLoweringLimits::standard(),
            },
            forged_operation,
            lowered.report().clone(),
            Vec::new(),
            &never_cancelled,
        ),
        Err(FlowLowerError::InvalidReport(_))
    ));
    let mut forged_type = wir.clone();
    forged_type.types[exit.id.0 as usize].name = Some("LookalikeExit".to_owned());
    assert!(forged_type.validate().is_err());

    let polls = std::cell::Cell::new(0_u64);
    CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: semantic.clone(),
                limits: FlowLoweringLimits::standard(),
            },
            &|| {
                polls.set(polls.get() + 1);
                false
            },
        )
        .expect("count exact AsyncExit Flow cancellation polls");
    let final_poll = polls.get();
    polls.set(0);
    assert!(matches!(
        CanonicalFlowLowerer::new().lower(
            FlowLowerRequest {
                input: semantic,
                limits: FlowLoweringLimits::standard(),
            },
            &|| {
                let next = polls.get() + 1;
                polls.set(next);
                next >= final_poll
            },
        ),
        Err(FlowLowerError::Cancelled)
    ));
    assert_eq!(polls.get(), final_poll);
}

#[test]
fn authenticated_async_exit_direct_is_uses_the_same_flow_delivery_profile() {
    let fixture = compile_semantic(DIRECT_IS_SOURCE);
    let lowered = CanonicalFlowLowerer::new()
        .lower(
            FlowLowerRequest {
                input: fixture.semantic,
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("direct is consumes the authenticated outcome in FlowWir");
    assert_eq!(lowered.report().async_states, 1);
    let caller = lowered
        .wir()
        .as_wir()
        .functions
        .iter()
        .find(|function| matches!(function.role, flow::FunctionRole::TaskEntry(_)))
        .expect("direct-is consumer");
    assert!(
        caller
            .blocks
            .iter()
            .any(|block| { matches!(block.terminator, flow::Terminator::Switch { .. }) })
    );
}

#[test]
fn async_exit_flow_tails_fail_closed_by_name() {
    let err_source = APPLICATION_SOURCE.replace("Result.Ok(7)", "Result.Err(7)");
    let fixture = compile_semantic(&err_source);
    assert!(matches!(
        CanonicalFlowLowerer::new().lower(
            FlowLowerRequest {
                input: fixture.semantic,
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        ),
        Err(FlowLowerError::UnsupportedInput {
            feature: "flow-async-outcome-producer-pending (only direct Ok[u64])",
        })
    ));
}

#[test]
fn async_exit_flow_rejects_metadata_and_nondiscriminating_is_forgeries() {
    let fixture = compile_semantic(DIRECT_IS_SOURCE);
    let mut metadata_forgery = fixture.semantic.clone().into_wir();
    let caller = metadata_forgery
        .functions
        .iter_mut()
        .find(|function| matches!(function.role, semantic::FunctionRole::TaskEntry(_)))
        .expect("outcome caller");
    caller.effects = semantic::EffectSet(semantic::EffectSet::SUSPEND);
    let metadata_forgery = metadata_forgery
        .validate()
        .expect("metadata forgery remains structurally valid");
    assert!(matches!(
        CanonicalFlowLowerer::new().lower(
            FlowLowerRequest {
                input: metadata_forgery,
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        ),
        Err(FlowLowerError::UnsupportedInput {
            feature: "flow-async-outcome-authentication (function metadata)",
        })
    ));

    let mut consumer_forgery = fixture.semantic.into_wir();
    let caller = consumer_forgery
        .functions
        .iter_mut()
        .find(|function| matches!(function.role, semantic::FunctionRole::TaskEntry(_)))
        .expect("outcome caller");
    let constant = caller
        .body
        .statements
        .iter_mut()
        .find_map(|statement| match statement {
            semantic::SemanticStatement::Match { arms, results, .. } if results.len() == 1 => arms
                .first_mut()
                .and_then(|arm| match &mut arm.body.statements[0] {
                    semantic::SemanticStatement::Let(statement) => Some(&mut statement.operation),
                    _ => None,
                }),
            _ => None,
        })
        .expect("direct-is false arm");
    *constant = semantic::SemanticOperation::Constant(semantic::Constant::Bool(true));
    let consumer_forgery = consumer_forgery
        .validate()
        .expect("nondiscriminating direct-is forgery remains structurally valid");
    assert!(matches!(
        CanonicalFlowLowerer::new().lower(
            FlowLowerRequest {
                input: consumer_forgery,
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        ),
        Err(FlowLowerError::UnsupportedInput {
            feature: "flow-async-outcome-consumer-pending (non-immediate match or is)",
        })
    ));

    let mut swapped_consumer = compile_semantic(DIRECT_IS_SOURCE).semantic.into_wir();
    let caller = swapped_consumer
        .functions
        .iter_mut()
        .find(|function| matches!(function.role, semantic::FunctionRole::TaskEntry(_)))
        .expect("outcome caller");
    let arms = caller
        .body
        .statements
        .iter_mut()
        .find_map(|statement| match statement {
            semantic::SemanticStatement::Match { arms, results, .. } if results.len() == 1 => {
                Some(arms)
            }
            _ => None,
        })
        .expect("direct-is result arms");
    for arm in arms {
        let semantic::SemanticStatement::Let(statement) = &mut arm.body.statements[0] else {
            panic!("direct-is arm starts with its boolean constant")
        };
        let semantic::SemanticOperation::Constant(semantic::Constant::Bool(value)) =
            &mut statement.operation
        else {
            panic!("direct-is arm defines a boolean constant")
        };
        *value = !*value;
    }
    let swapped_consumer = swapped_consumer
        .validate()
        .expect("swapped direct-is arms remain structurally valid");
    assert!(matches!(
        CanonicalFlowLowerer::new().lower(
            FlowLowerRequest {
                input: swapped_consumer,
                limits: FlowLoweringLimits::standard(),
            },
            &never_cancelled,
        ),
        Err(FlowLowerError::UnsupportedInput {
            feature: "flow-async-outcome-consumer-pending (non-immediate match or is)",
        })
    ));
}
