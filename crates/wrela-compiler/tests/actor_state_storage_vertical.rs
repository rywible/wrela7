#![forbid(unsafe_code)]

use std::sync::Arc;

use wrela_backend::{MachineLowerError, flow_wir as flow, prepare_canonical_frame_for_codegen};
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
const ACTOR_STATE_SOURCE: &str = r#"module app

from core.image import Image, Target

async fn checkpoint():
    pass

@service
pub struct Worker:
    value: u64 = 0

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
fn canonical_zero_actor_state_reaches_flow_and_named_machine_boundary() {
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
    let encoded = encode_and_verify(
        &CanonicalFlowWirCodec,
        EncodeRequest {
            wir: flow_output.wir(),
            limits: CodecLimits::standard(),
        },
        &never_cancelled,
    )
    .expect("actor state FlowWir encodes canonically");
    let error =
        prepare_canonical_frame_for_codegen(encoded.bytes(), &target, &build, &never_cancelled)
            .expect_err("MachineWir v11 has no actor-state storage identity");
    assert_eq!(
        error.machine_lower_error(),
        Some(&MachineLowerError::UnsupportedInput {
            feature: "machine-actor-state-storage-lowering-pending",
        })
    );
}
