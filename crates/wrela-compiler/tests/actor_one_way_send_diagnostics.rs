#![forbid(unsafe_code)]

use std::cell::Cell;
use std::sync::Arc;

use wrela_build_model::{
    BuildConfiguration, BuildIdentity, BuildProfile, LanguageRevision, Sha256Digest,
    TargetIdentity, seal_build_configuration,
};
use wrela_hir_lower::{
    CanonicalHirLowerer, ChangeSet as HirChangeSet, HirLowerer, LowerRequest as HirLowerRequest,
    LoweringLimits as HirLoweringLimits,
};
use wrela_package::{
    DependencyAlias, ModulePath, PackageGraphBuilder, PackageId, PackageIdentity, PackageName,
    PackageVersion,
};
use wrela_sema::{
    AnalysisChangeSet, AnalysisFailure, AnalysisLimits, AnalysisMode, AnalysisOutput,
    AnalysisRequest, CanonicalSemanticAnalyzer, SemanticAnalyzer,
};
use wrela_source::{FileId, SourceDatabase, SourceInput};
use wrela_syntax::{ParseLimits, ParseRequest, SyntaxParser, WrelaSyntaxParser};
use wrela_target::TargetPackage;

const CORE_IMAGE_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/image.wr");

const VALID_SEND_SOURCE: &str = r#"module app

from core.image import Image, Target

async fn checkpoint():
    pass

@service
pub struct Worker:
    pub async fn ping(mut self):
        await checkpoint()

    @task
    async fn publish(mut self):
        send self.ping()
        await checkpoint()

@image
pub fn boot() -> Image:
    img = Image(name="actor-send-diagnostic-image", target=Target.aarch64_qemu_virt_uefi)
    installed = img.service(Worker, mailbox=1)
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

fn analyze(
    application_source: &str,
    limits: AnalysisLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<AnalysisOutput, AnalysisFailure> {
    let source_graph_digest = Sha256Digest::from_bytes([0xc1; 32]);
    let core_package_digest = Sha256Digest::from_bytes([0xc2; 32]);
    let target_digest = Sha256Digest::from_bytes([0xc3; 32]);
    let mut sources = SourceDatabase::default();
    let application_file = sources
        .add(SourceInput {
            path: "app.wr".to_owned(),
            text: application_source.to_owned(),
            digest: Sha256Digest::from_bytes([0xc4; 32]),
        })
        .expect("actor-send diagnostic application source");
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
                .expect("actor-send diagnostic source parses")
                .into_parts();
            assert!(diagnostics.is_empty(), "parse diagnostics: {diagnostics:?}");
            parsed
        })
        .collect::<Vec<_>>();

    let mut packages = PackageGraphBuilder::new(identity(
        "actor-send-diagnostic-application",
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
                packages: Arc::new(packages.finish().expect("actor-send package graph")),
                source_graph_digest,
                parsed_files: &parsed_files,
                sources: &sources,
                changes: &changes,
                limits: HirLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("actor-send diagnostic source lowers to HIR");
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
        .expect("actor-send image entry");
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
    CanonicalSemanticAnalyzer::new().analyze(
        AnalysisRequest {
            hir,
            standard_library_package: PackageId(1),
            target: target.semantic(),
            build: &build,
            mode: AnalysisMode::Image {
                name: "actor-send-diagnostic-image",
                entry: image_entry,
            },
            changes: &changes,
            limits,
        },
        is_cancelled,
    )
}

fn assert_source_diagnostic(source: &str, expected_code: &str, marker: &str) {
    let output = analyze(source, AnalysisLimits::standard(), &never_cancelled)
        .expect("invalid actor send produces a source diagnostic");
    assert!(output.successful().is_none());
    let [diagnostic] = output.diagnostics() else {
        panic!(
            "expected one {expected_code} diagnostic, got {:?}",
            output.diagnostics()
        );
    };
    assert_eq!(diagnostic.code.as_deref(), Some(expected_code));
    assert_eq!(diagnostic.primary.file, FileId(0));
    assert!(!diagnostic.message.is_empty());
    assert!(!diagnostic.help.is_empty());
    let start = diagnostic.primary.range.start as usize;
    let end = diagnostic.primary.range.end as usize;
    let primary_source = source
        .get(start..end)
        .expect("diagnostic primary is a UTF-8 application-source range");
    assert!(
        primary_source.contains(marker) && end < source.len(),
        "primary {:?} = {primary_source:?} does not retain marker {marker:?}",
        diagnostic.primary,
    );
}

#[test]
fn source_actor_send_admission_bounds_have_stable_codes_and_statement_spans() {
    let mailbox_over_bound = VALID_SEND_SOURCE.replacen(
        "        send self.ping()\n        await checkpoint()",
        "        send self.ping()\n        send self.ping()\n        await checkpoint()",
        1,
    );
    assert_source_diagnostic(
        &mailbox_over_bound,
        "semantic-actor-send-mailbox-over-bound",
        "send self.ping()",
    );

    let single_message_bound = mailbox_over_bound.replacen("mailbox=1", "mailbox=2", 1);
    assert_source_diagnostic(
        &single_message_bound,
        "semantic-actor-send-single-message-bound",
        "send self.ping()",
    );
}

#[test]
fn source_actor_send_shape_rejections_have_stable_codes_and_precise_owners() {
    let payload = VALID_SEND_SOURCE
        .replacen(
            "pub async fn ping(mut self):",
            "pub async fn ping(mut self, value: u64):",
            1,
        )
        .replacen("send self.ping()", "send self.ping(42)", 1);
    assert_source_diagnostic(
        &payload,
        "semantic-actor-send-payload-not-supported",
        "self.ping(42)",
    );

    let non_self = VALID_SEND_SOURCE.replacen("send self.ping()", "send Worker.ping()", 1);
    assert_source_diagnostic(&non_self, "semantic-actor-send-receiver", "Worker");

    let non_task_producer = VALID_SEND_SOURCE
        .replacen("        send self.ping()\n", "", 1)
        .replacen(
            "        await checkpoint()\n\n    @task",
            "        send self.ping()\n        await checkpoint()\n\n    @task",
            1,
        );
    assert_source_diagnostic(
        &non_task_producer,
        "semantic-actor-send-producer",
        "self.ping()",
    );

    let non_actor_producer = VALID_SEND_SOURCE
        .replacen(
            "async fn checkpoint():\n    pass",
            "async fn checkpoint():\n    pass\n\nasync fn emit(worker: u64):\n    send worker.ping()",
            1,
        )
        .replacen("send self.ping()", "await emit(0)", 1);
    assert_source_diagnostic(
        &non_actor_producer,
        "semantic-actor-send-producer",
        "worker.ping()",
    );

    let synchronous_target = VALID_SEND_SOURCE.replacen(
        "pub async fn ping(mut self):\n        await checkpoint()",
        "pub fn ping(mut self):\n        pass",
        1,
    );
    assert_source_diagnostic(
        &synchronous_target,
        "semantic-actor-send-target",
        "self.ping",
    );

    let private_target = VALID_SEND_SOURCE.replacen("pub async fn ping", "async fn ping", 1);
    assert_source_diagnostic(
        &private_target,
        "semantic-actor-private-helper-not-supported",
        "async fn ping",
    );
}

#[test]
fn source_actor_send_analysis_preserves_deterministic_limits_and_cancellation() {
    let baseline_polls = Cell::new(0_u64);
    let count_polls = || {
        baseline_polls.set(baseline_polls.get() + 1);
        false
    };
    let baseline = analyze(VALID_SEND_SOURCE, AnalysisLimits::standard(), &count_polls)
        .expect("valid source actor send analysis");
    assert!(baseline.diagnostics().is_empty());
    let graph = baseline
        .successful()
        .expect("sealed actor image")
        .facts()
        .graph
        .as_ref()
        .expect("sealed actor graph");
    let exact_image_nodes = graph
        .actors
        .len()
        .checked_add(graph.tasks.len())
        .and_then(|count| count.checked_add(graph.devices.len()))
        .and_then(|count| count.checked_add(graph.pools.len()))
        .and_then(|count| count.checked_add(graph.regions.len()))
        .and_then(|count| count.checked_add(graph.brands.len()))
        .and_then(|count| u32::try_from(count).ok())
        .expect("bounded actor image-node count");
    assert_eq!(exact_image_nodes, 5);

    let mut exact = AnalysisLimits::standard();
    exact.image_nodes = exact_image_nodes;
    let exact_output = analyze(VALID_SEND_SOURCE, exact, &never_cancelled)
        .expect("exact actor-send image-node bound");
    assert!(exact_output.diagnostics().is_empty());

    let mut over = exact;
    over.image_nodes -= 1;
    let over_result = analyze(VALID_SEND_SOURCE, over, &never_cancelled);
    assert!(
        matches!(
            over_result,
            Err(AnalysisFailure::ResourceLimit {
                resource: "image nodes",
                limit,
            }) if limit == u64::from(over.image_nodes)
        ),
        "one-under actor-send image-node result: {over_result:?}"
    );

    let cancel_at = baseline_polls
        .get()
        .checked_sub(4)
        .expect("late cancellation poll");
    assert!(cancel_at > 0);
    for _ in 0..2 {
        let polls = Cell::new(0_u64);
        let cancel_late = || {
            let next = polls.get() + 1;
            polls.set(next);
            next == cancel_at
        };
        assert!(matches!(
            analyze(VALID_SEND_SOURCE, AnalysisLimits::standard(), &cancel_late,),
            Err(AnalysisFailure::Cancelled)
        ));
        assert_eq!(polls.get(), cancel_at);
    }
}
