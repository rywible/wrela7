#![forbid(unsafe_code)]

//! Task B5b vertical — the unified wait-for graph over the closed image actor
//! graph, proven at semantic-analysis time.
//!
//! This is a negative-only / fail-closed analysis: it *adds rejections*, it
//! does not lower a reply/runtime path (that is B5c). The three fixtures below
//! pin exactly what the wait-for-graph analysis rejects and accepts:
//!
//!   * a hold-and-wait cycle among async activations in the closed image is a
//!     named `semantic-wait-cycle` rejection that names every participant;
//!   * a public `@driver` handler that self-waits (suspends at `await`) is a
//!     named `semantic-driver-handler-waits` rejection that names the handler,
//!     enforced before image evaluation so it fires whether or not the driver
//!     is ever installed (design ch04 §3.1: driver handlers are synchronous in
//!     revision 0.1 and never self-wait);
//!   * an acyclic wait graph does **not** trip either diagnostic and produces a
//!     `WaitGraphAcyclic` proof over the closed image.

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
    AnalysisChangeSet, AnalysisLimits, AnalysisMode, AnalysisOutput, AnalysisRequest,
    CanonicalSemanticAnalyzer, ProofKind, SemanticAnalyzer,
};
use wrela_source::{SourceDatabase, SourceInput};
use wrela_syntax::{ParseLimits, ParseRequest, SyntaxParser, WrelaSyntaxParser};
use wrela_target::TargetPackage;

const CORE_IMAGE_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/image.wr");

/// An acyclic wait graph: one installed service whose handler and task await a
/// shared async helper. No hold-and-wait cycle, no driver handler.
const ACYCLIC_SOURCE: &str = r#"module app

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
    img = Image(name="wait-graph-acyclic-image", target=Target.aarch64_qemu_virt_uefi)
    installed = img.service(Worker, mailbox=2)
    return img
"#;

/// A hold-and-wait cycle: two mutually awaiting async activations reachable from
/// the installed actor's turn. The turn retains its activation while the cycle
/// can never resolve.
const WAIT_CYCLE_SOURCE: &str = r#"module app

from core.image import Image, Target

async fn ping():
    await pong()

async fn pong():
    await ping()

@service
pub struct Worker:
    pub async fn run(mut self):
        await ping()

@image
pub fn boot() -> Image:
    img = Image(name="wait-graph-cycle-image", target=Target.aarch64_qemu_virt_uefi)
    installed = img.service(Worker, mailbox=2)
    return img
"#;

/// A public `@driver` handler that self-waits by suspending at `await`. The
/// driver is never installed; the rejection is a declaration-level property of
/// the handler and must fire regardless.
const DRIVER_SELF_WAIT_SOURCE: &str = r#"module app

from core.image import Image, Target

async fn checkpoint():
    pass

@driver
pub struct Gpio:
    pub async fn toggle(mut self):
        await checkpoint()

@service
pub struct Worker:
    pub async fn ping(mut self):
        await checkpoint()

@image
pub fn boot() -> Image:
    img = Image(name="wait-graph-driver-image", target=Target.aarch64_qemu_virt_uefi)
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

/// Parse, lower to sealed HIR, and run whole-image semantic analysis over one
/// application module wired against the core image contracts. Returns the raw
/// analysis output so each test can pin diagnostics and proofs directly.
fn analyze_image(application_source: &str, image_name: &str) -> AnalysisOutput {
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
        .expect("wait-graph application source");
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
                .expect("wait-graph source parses")
                .into_parts();
            assert!(diagnostics.is_empty(), "parse diagnostics: {diagnostics:?}");
            parsed
        })
        .collect::<Vec<_>>();

    let mut packages = PackageGraphBuilder::new(identity(
        "wait-graph-application",
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
    let hir_changes = HirChangeSet {
        previous_source_graph: None,
        changed_files: Vec::new(),
    };
    let hir_output = CanonicalHirLowerer::new()
        .lower(
            HirLowerRequest {
                packages: Arc::new(packages.finish().expect("wait-graph package graph")),
                source_graph_digest,
                parsed_files: &parsed_files,
                sources: &sources,
                changes: &hir_changes,
                limits: HirLoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("wait-graph source lowers to sealed HIR");
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
        .expect("wait-graph image entry");
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
    CanonicalSemanticAnalyzer::new()
        .analyze(
            AnalysisRequest {
                hir,
                standard_library_package: PackageId(1),
                target: target.semantic(),
                build: &build,
                mode: AnalysisMode::Image {
                    name: image_name,
                    entry: image_entry,
                },
                changes: &changes,
                limits: AnalysisLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("wait-graph semantic analysis is recoverable")
}

#[test]
fn acyclic_wait_graph_is_accepted_with_a_wait_graph_acyclic_proof() {
    let output = analyze_image(ACYCLIC_SOURCE, "wait-graph-acyclic-image");
    assert!(
        output.diagnostics().is_empty(),
        "acyclic wait graph must not be rejected: {:?}",
        output.diagnostics()
    );
    let analyzed = output
        .successful()
        .expect("acyclic wait graph seals an analyzed image");
    let proofs = &analyzed.facts().proofs;
    assert!(
        proofs
            .iter()
            .any(|proof| proof.kind == ProofKind::WaitGraphAcyclic),
        "the closed image proves its wait-for graph acyclic"
    );
    // Determinism: repeated analysis yields byte-identical diagnostics/product.
    let repeat = analyze_image(ACYCLIC_SOURCE, "wait-graph-acyclic-image");
    assert_eq!(output, repeat);
}

#[test]
fn hold_and_wait_cycle_is_a_named_wait_cycle_rejection() {
    let output = analyze_image(WAIT_CYCLE_SOURCE, "wait-graph-cycle-image");
    assert!(
        output.successful().is_none(),
        "a wait cycle rejects the image"
    );
    let cycle = output
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code.as_deref() == Some("semantic-wait-cycle"))
        .expect("wait cycle produces the named wait-cycle diagnostic");
    assert_eq!(cycle.category, wrela_diagnostics::Category::ASYNC);
    // Every participant of the retained hold-and-wait cycle is named.
    assert!(
        cycle
            .labels
            .iter()
            .any(|label| label.message.contains("ping") && label.message.contains("pong")),
        "the diagnostic names the cycle participants: {:?}",
        cycle.labels
    );
    assert!(cycle.primary.range.end > cycle.primary.range.start);
    let repeat = analyze_image(WAIT_CYCLE_SOURCE, "wait-graph-cycle-image");
    assert_eq!(output, repeat);
}

#[test]
fn driver_handler_self_wait_is_a_named_rejection_before_image_evaluation() {
    let output = analyze_image(DRIVER_SELF_WAIT_SOURCE, "wait-graph-driver-image");
    assert!(
        output.successful().is_none(),
        "a self-waiting driver handler rejects the program"
    );
    let self_wait = output
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code.as_deref() == Some("semantic-driver-handler-waits"))
        .expect("self-waiting driver handler produces the named rejection");
    assert_eq!(self_wait.category, wrela_diagnostics::Category::ASYNC);
    // The self-waiting handler is named, not a generic message.
    assert!(
        self_wait
            .labels
            .iter()
            .chain(std::iter::once(&wrela_diagnostics::Label {
                span: self_wait.primary,
                message: self_wait.message.clone(),
            }))
            .any(|label| label.message.contains("Gpio") && label.message.contains("toggle")),
        "the diagnostic names the self-waiting handler Gpio.toggle: {:?} / {:?}",
        self_wait.message,
        self_wait.labels
    );
    assert!(self_wait.primary.range.end > self_wait.primary.range.start);
    // The image-install fail-closed for drivers must not be what rejects here:
    // the handler property is decided first, at declaration granularity.
    assert!(
        output
            .diagnostics()
            .iter()
            .all(|diagnostic| diagnostic.code.as_deref()
                != Some("semantic-hardware-actor-not-supported")),
        "declaration-level self-wait rejection pre-empts driver install: {:?}",
        output.diagnostics()
    );
    let repeat = analyze_image(DRIVER_SELF_WAIT_SOURCE, "wait-graph-driver-image");
    assert_eq!(output, repeat);
}
