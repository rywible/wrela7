#![forbid(unsafe_code)]

use std::cell::Cell;
use std::sync::Arc;

use wrela_build_model::{
    BuildConfiguration, BuildIdentity, BuildProfile, LanguageRevision, Sha256Digest,
    TargetIdentity, ValidatedBuildConfiguration, seal_build_configuration,
};
use wrela_compiler::{
    INCREMENTAL_ANALYSIS_SESSION_VERSION, IncrementalAnalysisFailure, IncrementalAnalysisLimits,
    IncrementalAnalysisRequest, IncrementalAnalysisSession,
};
use wrela_flow_lower::{CanonicalFlowLowerer, FlowLowerer};
use wrela_package::{
    DependencyAlias, ModulePath, PackageGraph, PackageGraphBuilder, PackageId, PackageIdentity,
    PackageName, PackageVersion,
};
use wrela_package_loader::{ContentHasher, SoftwareSha256};
use wrela_semantic_lower::{CanonicalSemanticLowerer, SemanticLowerer};
use wrela_source::{FileId, SourceDatabase, SourceInput};
use wrela_syntax::{ParseLimits, ParseRequest, ParsedFile, SyntaxParser, WrelaSyntaxParser};
use wrela_target::TargetPackage;

const IMAGE: &str = r#"module app.image

from core.image import Image, Target

@image
pub fn boot() -> Image:
    return Image(name="session-image", target=Target.aarch64_qemu_virt_uefi)
"#;

const DEPENDENT_IMAGE: &str = r#"module app.image

from app.leaf import leaf
from core.image import Image, Target

@image
pub fn boot() -> Image:
    return Image(name="session-image", target=Target.aarch64_qemu_virt_uefi)

fn dependent() -> u8:
    return leaf()
"#;

const PRIVATE_ONE: &str = "module app.leaf\n\nfn leaf() -> u8:\n    return 1\n";
const PRIVATE_TWO: &str = "module app.leaf\n\nfn leaf() -> u8:\n    return 2\n";
const PUBLIC_ONE: &str = "module app.leaf\n\npub fn leaf() -> u8:\n    return 1\n";
const PUBLIC_TWO: &str = "module app.leaf\n\npub fn leaf() -> u8:\n    return 2\n";
const PUBLIC_U16: &str = "module app.leaf\n\npub fn leaf() -> u16:\n    return 1\n";
const CONSTANT_ONE: &str = "module app.leaf\n\nconst leaf: u8 = 1\n";
const CONSTANT_TWO: &str = "module app.leaf\n\nconst leaf: u8 = 2\n";
const CORE_IMAGE: &str = include_str!("../../../std/wrela-core-0.1/src/image.wr");

static HASHER: SoftwareSha256 = SoftwareSha256;

fn digest(byte: u8) -> Sha256Digest {
    Sha256Digest::from_bytes([byte; 32])
}

fn identity(name: &str, source_digest: Sha256Digest) -> PackageIdentity {
    PackageIdentity {
        name: PackageName::new(name).expect("package name"),
        version: PackageVersion::new("0.1.0").expect("package version"),
        source_digest,
    }
}

fn never_cancelled() -> bool {
    false
}

struct Revision {
    sources: SourceDatabase,
    parsed: Vec<ParsedFile>,
    packages: Arc<PackageGraph>,
    source_graph: Sha256Digest,
    leaf_file: FileId,
    core_package: PackageId,
}

impl Revision {
    fn request<'a>(
        &'a self,
        target: &'a TargetPackage,
        build: &'a ValidatedBuildConfiguration,
    ) -> IncrementalAnalysisRequest<'a> {
        self.request_with(target, build, "session-image", self.core_package)
    }

    fn request_with<'a>(
        &'a self,
        target: &'a TargetPackage,
        build: &'a ValidatedBuildConfiguration,
        image_name: &'a str,
        standard_library_package: PackageId,
    ) -> IncrementalAnalysisRequest<'a> {
        IncrementalAnalysisRequest {
            packages: Arc::clone(&self.packages),
            source_graph_digest: self.source_graph,
            parsed_files: &self.parsed,
            sources: &self.sources,
            lowering_limits: wrela_hir_lower::LoweringLimits::standard(),
            standard_library_package,
            target: target.semantic(),
            build,
            mode: wrela_sema::AnalysisMode::Image {
                name: image_name,
                entry: wrela_hir::DeclarationId(0),
            },
            analysis_limits: wrela_sema::AnalysisLimits::standard(),
        }
    }
}

fn revision(image: &str, leaf: &str, revision: u8, leaf_path: &str, swap: bool) -> Revision {
    revision_full(image, leaf, revision, leaf_path, swap, false, None)
}

fn revision_with_extra(
    image: &str,
    leaf: &str,
    revision: u8,
    leaf_path: &str,
    swap: bool,
    extra_module: bool,
) -> Revision {
    revision_full(image, leaf, revision, leaf_path, swap, extra_module, None)
}

fn revision_with_package_digest(
    image: &str,
    leaf: &str,
    revision: u8,
    package_source_digest: Sha256Digest,
) -> Revision {
    revision_full(
        image,
        leaf,
        revision,
        "app/leaf.wr",
        false,
        false,
        Some(package_source_digest),
    )
}

fn revision_full(
    image: &str,
    leaf: &str,
    revision: u8,
    leaf_path: &str,
    swap: bool,
    extra_module: bool,
    package_source_digest: Option<Sha256Digest>,
) -> Revision {
    let mut sources = SourceDatabase::default();
    let image_file = sources
        .add(SourceInput {
            path: "app/image.wr".to_owned(),
            text: image.to_owned(),
            digest: HASHER.sha256(image.as_bytes()),
        })
        .expect("image source");
    let leaf_file = sources
        .add(SourceInput {
            path: leaf_path.to_owned(),
            text: leaf.to_owned(),
            digest: HASHER.sha256(leaf.as_bytes()),
        })
        .expect("leaf source");
    let extra_file = if extra_module {
        let text = "module app.zz_extra\n\nfn extra() -> u8:\n    return 7\n";
        Some(
            sources
                .add(SourceInput {
                    path: "app/zz_extra.wr".to_owned(),
                    text: text.to_owned(),
                    digest: HASHER.sha256(text.as_bytes()),
                })
                .expect("extra source"),
        )
    } else {
        None
    };
    let core_file = sources
        .add(SourceInput {
            path: "core/image.wr".to_owned(),
            text: CORE_IMAGE.to_owned(),
            digest: HASHER.sha256(CORE_IMAGE.as_bytes()),
        })
        .expect("core source");
    let source_graph = digest(revision);
    let mut graph = PackageGraphBuilder::new(identity(
        "session-app",
        package_source_digest.unwrap_or(source_graph),
    ));
    let core_handle = graph
        .add_package(identity("wrela-core", digest(0xc1)))
        .expect("core package");
    graph
        .add_dependency(
            graph.root(),
            DependencyAlias::new("core").expect("core alias"),
            core_handle,
        )
        .expect("core dependency");
    graph
        .add_module(
            graph.root(),
            ModulePath::new(["app".to_owned(), "image".to_owned()]).expect("image module"),
            if swap { leaf_file } else { image_file },
        )
        .expect("image module record");
    graph
        .add_module(
            graph.root(),
            ModulePath::new(["app".to_owned(), "leaf".to_owned()]).expect("leaf module"),
            if swap { image_file } else { leaf_file },
        )
        .expect("leaf module record");
    if let Some(extra_file) = extra_file {
        graph
            .add_module(
                graph.root(),
                ModulePath::new(["app".to_owned(), "zz_extra".to_owned()]).expect("extra module"),
                extra_file,
            )
            .expect("extra module record");
    }
    graph
        .add_module(
            core_handle,
            ModulePath::new(["image".to_owned()]).expect("core image module"),
            core_file,
        )
        .expect("core module record");
    let parsed = (0..sources.len())
        .map(|index| {
            let (parsed, diagnostics) = WrelaSyntaxParser::new()
                .parse(
                    ParseRequest {
                        sources: &sources,
                        file: FileId(index as u32),
                        limits: ParseLimits::standard(),
                    },
                    &never_cancelled,
                )
                .expect("source parse")
                .into_parts();
            assert!(diagnostics.is_empty(), "parse diagnostics: {diagnostics:?}");
            parsed
        })
        .collect();
    let packages = graph.finish().expect("package graph");
    let core_package = packages
        .packages()
        .iter()
        .find(|package| package.identity.name.as_str() == "wrela-core")
        .expect("sealed core package")
        .id;
    Revision {
        sources,
        parsed,
        packages: Arc::new(packages),
        source_graph,
        leaf_file,
        core_package,
    }
}

fn build(
    source_graph: Sha256Digest,
    request: u8,
    compiler: u8,
    target_package: Sha256Digest,
    profile_digest: Sha256Digest,
) -> ValidatedBuildConfiguration {
    seal_build_configuration(
        BuildConfiguration {
            identity: BuildIdentity {
                compiler: digest(compiler),
                language: LanguageRevision::Design0_1,
                target: TargetIdentity::aarch64_qemu_virt_uefi(),
                target_package,
                standard_library: digest(0xd1),
                source_graph,
                request: digest(request),
                profile: profile_digest,
            },
            profile: BuildProfile::development(),
        },
        profile_digest,
    )
    .expect("build configuration")
}

fn downstream(
    analysis: &wrela_sema::AnalysisOutput,
) -> (
    wrela_semantic_lower::LowerOutput,
    wrela_flow_lower::LowerOutput,
) {
    let semantic = CanonicalSemanticLowerer::new()
        .lower(
            wrela_semantic_lower::LowerRequest {
                input: analysis
                    .successful()
                    .expect("complete semantic image")
                    .clone(),
                limits: wrela_semantic_lower::LoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("SemanticWir lowering");
    let flow = CanonicalFlowLowerer::new()
        .lower(
            wrela_flow_lower::LowerRequest {
                input: semantic.wir().clone(),
                limits: wrela_flow_lower::LoweringLimits::standard(),
            },
            &never_cancelled,
        )
        .expect("FlowWir lowering");
    (semantic, flow)
}

fn cold_session(
    input: &Revision,
    target: &TargetPackage,
    build: &ValidatedBuildConfiguration,
) -> IncrementalAnalysisSession {
    let mut session = IncrementalAnalysisSession::new();
    let output = session
        .analyze(
            input.request(target, build),
            IncrementalAnalysisLimits::standard(),
            &never_cancelled,
        )
        .expect("cold session analysis");
    assert!(!output.evidence().exact_revision_reused);
    assert!(output.evidence().hir.reused_declarations.is_empty());
    assert!(output.evidence().analysis.reused_functions.is_empty());
    assert_eq!(output.evidence().change_comparisons, 0);
    assert_eq!(output.evidence().semantic_change_comparisons, 0);
    session
}

#[test]
fn production_session_reuses_real_producers_and_matches_clean_semantic_and_flow_consumers() {
    let target_digest = digest(0xe0);
    let target = TargetPackage::aarch64_qemu_virt_uefi(target_digest);
    let profile = digest(0xd0);
    let base = revision(IMAGE, PRIVATE_ONE, 0x10, "app/leaf.wr", false);
    let base_build = build(base.source_graph, 0xa0, 0xa1, target_digest, profile);
    let mut session = cold_session(&base, &target, &base_build);
    let base_snapshot = session.snapshot().expect("base snapshot");

    let exact = session
        .analyze(
            base.request(&target, &base_build),
            IncrementalAnalysisLimits::standard(),
            &never_cancelled,
        )
        .expect("exact identity hit");
    assert!(exact.evidence().exact_revision_reused);
    assert_eq!(exact.evidence().hir.producer_declarations_executed, 0);
    assert_eq!(exact.evidence().analysis.producer_functions_executed, 0);
    drop(exact);

    let current = revision(IMAGE, PRIVATE_TWO, 0x20, "app/leaf.wr", false);
    let current_build = build(current.source_graph, 0xa0, 0xa1, target_digest, profile);
    let clean = cold_session(&current, &target, &current_build)
        .snapshot()
        .expect("clean snapshot");
    let incremental = session
        .analyze(
            current.request(&target, &current_build),
            IncrementalAnalysisLimits::standard(),
            &never_cancelled,
        )
        .expect("incremental session analysis");
    assert_eq!(incremental.hir(), clean.hir.as_ref());
    assert_eq!(incremental.analysis(), clean.analysis.as_ref());
    assert_eq!(incremental.evidence().changed_files, [current.leaf_file]);
    assert!(!incremental.evidence().hir.reused_declarations.is_empty());
    assert!(incremental.evidence().hir.producer_declarations_executed > 0);
    assert_eq!(
        incremental.evidence().analysis.producer_functions_executed,
        0
    );
    assert!(!incremental.evidence().analysis.reused_functions.is_empty());
    assert!(incremental.evidence().change_comparisons > 0);
    assert!(incremental.evidence().semantic_change_comparisons > 0);
    let exact_limits = IncrementalAnalysisLimits {
        change_comparisons: incremental.evidence().change_comparisons,
        hir_reuse: wrela_hir_lower::HirReuseLimits {
            comparisons: incremental.evidence().hir.comparisons,
        },
        semantic_change: wrela_sema::AnalysisReuseLimits {
            comparisons: incremental.evidence().semantic_change_comparisons,
        },
        semantic_reuse: wrela_sema::AnalysisReuseLimits {
            comparisons: incremental.evidence().analysis.comparisons,
        },
    };
    let incremental_consumers = downstream(incremental.analysis());
    let clean_consumers = downstream(clean.analysis.as_ref());
    assert_eq!(incremental_consumers, clean_consumers);
    drop(incremental);

    IncrementalAnalysisSession::restore(base_snapshot.clone())
        .expect("restore exact base")
        .analyze(
            current.request(&target, &current_build),
            exact_limits,
            &never_cancelled,
        )
        .expect("all exact reuse limits");
    let mut one_under = exact_limits;
    one_under.change_comparisons -= 1;
    let error = IncrementalAnalysisSession::restore(base_snapshot.clone())
        .expect("restore one-under base")
        .analyze(
            current.request(&target, &current_build),
            one_under,
            &never_cancelled,
        )
        .expect_err("one-under change bound");
    assert_eq!(
        error,
        IncrementalAnalysisFailure::ResourceLimit {
            resource: "incremental change comparisons",
            limit: one_under.change_comparisons,
        }
    );
    let mut semantic_one_under = exact_limits;
    semantic_one_under.semantic_change.comparisons -= 1;
    assert!(matches!(
        IncrementalAnalysisSession::restore(base_snapshot)
            .expect("restore semantic one-under base")
            .analyze(
                current.request(&target, &current_build),
                semantic_one_under,
                &never_cancelled,
            ),
        Err(IncrementalAnalysisFailure::Analysis(
            wrela_sema::AnalysisFailure::ResourceLimit {
                resource: "semantic reuse comparisons",
                ..
            }
        ))
    ));
}

fn assert_semantic_cold_fallback(image: &str, old_leaf: &str, new_leaf: &str, seed: u8) {
    let target_digest = digest(seed.wrapping_add(1));
    let target = TargetPackage::aarch64_qemu_virt_uefi(target_digest);
    let profile = digest(0xd0);
    let base = revision(image, old_leaf, seed, "app/leaf.wr", false);
    let base_build = build(base.source_graph, 0xb0, 0xb1, target_digest, profile);
    let mut session = cold_session(&base, &target, &base_build);
    let current = revision(image, new_leaf, seed.wrapping_add(2), "app/leaf.wr", false);
    let current_build = build(current.source_graph, 0xb0, 0xb1, target_digest, profile);
    let output = session
        .analyze(
            current.request(&target, &current_build),
            IncrementalAnalysisLimits::standard(),
            &never_cancelled,
        )
        .expect("conservative semantic fallback");
    assert!(output.evidence().analysis.reused_functions.is_empty());
    assert!(output.evidence().analysis.producer_functions_executed > 0);
}

#[test]
fn dependent_header_type_constant_comptime_and_shape_drift_fall_back_cold() {
    assert_semantic_cold_fallback(DEPENDENT_IMAGE, PUBLIC_ONE, PUBLIC_TWO, 0x31);
    assert_semantic_cold_fallback(DEPENDENT_IMAGE, PUBLIC_ONE, PUBLIC_U16, 0x41);
    assert_semantic_cold_fallback(IMAGE, CONSTANT_ONE, CONSTANT_TWO, 0x51);
    // Revision 0.1 has no comptime function color, so there is no longer a
    // distinct "comptime fn changed" case to force conservative invalidation
    // for: an ordinary `fn leaf()` edited under an `IMAGE` fixture that never
    // imports `app.leaf` at all is now correctly recognized as unreachable
    // from `boot()`, and its unrelated function instance is safely reused
    // rather than forced cold -- the old `COMPTIME_ONE`/`COMPTIME_TWO` case
    // here exercised exactly the distinction this migration removed.

    let target_digest = digest(0xe2);
    let target = TargetPackage::aarch64_qemu_virt_uefi(target_digest);
    let profile = digest(0xd0);
    let base = revision(IMAGE, PRIVATE_ONE, 0x70, "app/leaf.wr", false);
    let base_build = build(base.source_graph, 0xc0, 0xc1, target_digest, profile);
    let mut session = cold_session(&base, &target, &base_build);
    let base_snapshot = session.snapshot().expect("shape base snapshot");
    let renamed = revision(IMAGE, PRIVATE_TWO, 0x71, "app/renamed_leaf.wr", false);
    assert_ne!(
        base.sources.get(base.leaf_file).expect("base leaf").path(),
        renamed
            .sources
            .get(renamed.leaf_file)
            .expect("renamed leaf")
            .path()
    );
    let renamed_build = build(renamed.source_graph, 0xc0, 0xc1, target_digest, profile);
    let output = session
        .analyze(
            renamed.request(&target, &renamed_build),
            IncrementalAnalysisLimits::standard(),
            &never_cancelled,
        )
        .expect("renamed source cold rebuild");
    assert!(output.evidence().hir.reused_declarations.is_empty());
    assert!(output.evidence().analysis.reused_functions.is_empty());
    assert!(output.evidence().hir.producer_declarations_executed > 0);
    assert!(output.evidence().analysis.producer_functions_executed > 0);

    let added = revision_with_extra(IMAGE, PRIVATE_TWO, 0x73, "app/leaf.wr", false, true);
    let added_build = build(added.source_graph, 0xc0, 0xc1, target_digest, profile);
    let added_output = IncrementalAnalysisSession::restore(base_snapshot.clone())
        .expect("add-module base restore")
        .analyze(
            added.request(&target, &added_build),
            IncrementalAnalysisLimits::standard(),
            &never_cancelled,
        )
        .expect("added source/module cold rebuild");
    assert!(added_output.evidence().hir.reused_declarations.is_empty());
    assert!(added_output.evidence().analysis.reused_functions.is_empty());

    let added_session = cold_session(&added, &target, &added_build);
    let removed = revision(IMAGE, PRIVATE_TWO, 0x74, "app/leaf.wr", false);
    let removed_build = build(removed.source_graph, 0xc0, 0xc1, target_digest, profile);
    let removed_output = IncrementalAnalysisSession::restore(
        added_session.snapshot().expect("added-module snapshot"),
    )
    .expect("remove-module restore")
    .analyze(
        removed.request(&target, &removed_build),
        IncrementalAnalysisLimits::standard(),
        &never_cancelled,
    )
    .expect("removed source/module cold rebuild");
    assert!(removed_output.evidence().hir.reused_declarations.is_empty());
    assert!(
        removed_output
            .evidence()
            .analysis
            .reused_functions
            .is_empty()
    );

    let manifest_only = revision(IMAGE, PRIVATE_ONE, 0x72, "app/leaf.wr", false);
    let manifest_build = build(
        manifest_only.source_graph,
        0xc0,
        0xc1,
        target_digest,
        profile,
    );
    let manifest_output = IncrementalAnalysisSession::restore(base_snapshot)
        .expect("manifest base restore")
        .analyze(
            manifest_only.request(&target, &manifest_build),
            IncrementalAnalysisLimits::standard(),
            &never_cancelled,
        )
        .expect("manifest-only source graph drift");
    assert!(
        manifest_output
            .evidence()
            .hir
            .reused_declarations
            .is_empty()
    );
    assert!(
        manifest_output
            .evidence()
            .analysis
            .reused_functions
            .is_empty()
    );
    assert!(
        manifest_output
            .evidence()
            .hir
            .producer_declarations_executed
            > 0
    );
    assert!(
        manifest_output
            .evidence()
            .analysis
            .producer_functions_executed
            > 0
    );
}

#[test]
fn snapshots_identity_cold_paths_and_cancellation_preserve_atomic_prior_state() {
    let target_digest = digest(0xe4);
    let target = TargetPackage::aarch64_qemu_virt_uefi(target_digest);
    let profile = digest(0xd0);
    let base = revision(IMAGE, PRIVATE_ONE, 0x80, "app/leaf.wr", false);
    let base_build = build(base.source_graph, 0xd2, 0xd3, target_digest, profile);
    let base_session = cold_session(&base, &target, &base_build);
    let snapshot = base_session.snapshot().expect("base snapshot");

    let mut stale_parsed = revision(IMAGE, PRIVATE_ONE, 0x80, "app/leaf.wr", false);
    let other_parse = revision(IMAGE, PRIVATE_TWO, 0x81, "app/leaf.wr", false);
    stale_parsed.parsed[stale_parsed.leaf_file.0 as usize] =
        other_parse.parsed[other_parse.leaf_file.0 as usize].clone();
    assert_eq!(
        IncrementalAnalysisSession::restore(snapshot.clone())
            .expect("stale parsed restore")
            .analyze(
                stale_parsed.request(&target, &base_build),
                IncrementalAnalysisLimits::standard(),
                &never_cancelled,
            )
            .expect_err("stale parsed product"),
        IncrementalAnalysisFailure::StaleParsedInput
    );

    let forged_package = revision_with_package_digest(IMAGE, PRIVATE_ONE, 0x80, digest(0xfe));
    let mut package_session =
        IncrementalAnalysisSession::restore(snapshot.clone()).expect("package restore");
    assert_eq!(
        package_session
            .analyze(
                forged_package.request(&target, &base_build),
                IncrementalAnalysisLimits::standard(),
                &never_cancelled,
            )
            .expect_err("same-graph package identity forgery"),
        IncrementalAnalysisFailure::RequestMismatch(
            "package identity changed without a new source graph identity"
        )
    );
    assert_eq!(
        package_session.source_graph_digest(),
        Some(base.source_graph)
    );

    for version in [0, INCREMENTAL_ANALYSIS_SESSION_VERSION + 1] {
        let mut corrupt = snapshot.clone();
        corrupt.contract_version = version;
        assert_eq!(
            IncrementalAnalysisSession::restore(corrupt).expect_err("session version"),
            IncrementalAnalysisFailure::UnsupportedSessionVersion { observed: version }
        );
    }
    for version in [0, 1, wrela_hir_lower::HIR_CHANGE_SET_REUSE_VERSION + 1] {
        let mut corrupt = snapshot.clone();
        corrupt.hir_reuse_version = version;
        assert_eq!(
            IncrementalAnalysisSession::restore(corrupt).expect_err("HIR reuse version"),
            IncrementalAnalysisFailure::UnsupportedHirReuseVersion { observed: version }
        );
    }
    for version in [0, wrela_sema::ANALYSIS_CHANGE_SET_REUSE_VERSION + 1] {
        let mut corrupt = snapshot.clone();
        corrupt.analysis_reuse_version = version;
        assert_eq!(
            IncrementalAnalysisSession::restore(corrupt).expect_err("analysis reuse version"),
            IncrementalAnalysisFailure::UnsupportedAnalysisReuseVersion { observed: version }
        );
    }
    let mut corrupt_source = snapshot.clone();
    corrupt_source.source_revisions[0].digest = digest(0xff);
    assert_eq!(
        IncrementalAnalysisSession::restore(corrupt_source).expect_err("corrupt revision"),
        IncrementalAnalysisFailure::CorruptSnapshot("source revisions do not match sealed HIR")
    );
    let mut corrupt_std = snapshot.clone();
    corrupt_std.standard_library_package = PackageId(0);
    assert_eq!(
        IncrementalAnalysisSession::restore(corrupt_std).expect_err("corrupt std package"),
        IncrementalAnalysisFailure::CorruptSnapshot(
            "selected standard-library package is not the root core dependency"
        )
    );

    let request_drift_build = build(base.source_graph, 0xd4, 0xd3, target_digest, profile);
    let request_drift = IncrementalAnalysisSession::restore(snapshot.clone())
        .expect("request drift restore")
        .analyze(
            base.request(&target, &request_drift_build),
            IncrementalAnalysisLimits::standard(),
            &never_cancelled,
        )
        .expect("request drift cold semantic");
    assert_eq!(
        request_drift.evidence().hir.producer_declarations_executed,
        0
    );
    assert!(
        request_drift
            .evidence()
            .analysis
            .producer_functions_executed
            > 0
    );

    let profile_drift = digest(0xd5);
    let profile_build = build(base.source_graph, 0xd2, 0xd3, target_digest, profile_drift);
    let profile_output = IncrementalAnalysisSession::restore(snapshot.clone())
        .expect("profile restore")
        .analyze(
            base.request(&target, &profile_build),
            IncrementalAnalysisLimits::standard(),
            &never_cancelled,
        )
        .expect("profile drift cold semantic");
    assert_eq!(
        profile_output.evidence().hir.producer_declarations_executed,
        0
    );
    assert!(
        profile_output
            .evidence()
            .analysis
            .producer_functions_executed
            > 0
    );

    let other_target_digest = digest(0xe5);
    let other_target = TargetPackage::aarch64_qemu_virt_uefi(other_target_digest);
    let target_build = build(base.source_graph, 0xd2, 0xd3, other_target_digest, profile);
    let target_output = IncrementalAnalysisSession::restore(snapshot.clone())
        .expect("target restore")
        .analyze(
            base.request(&other_target, &target_build),
            IncrementalAnalysisLimits::standard(),
            &never_cancelled,
        )
        .expect("target drift cold semantic");
    assert_eq!(
        target_output.evidence().hir.producer_declarations_executed,
        0
    );
    assert!(
        target_output
            .evidence()
            .analysis
            .producer_functions_executed
            > 0
    );

    let mut mode_drift =
        IncrementalAnalysisSession::restore(snapshot.clone()).expect("mode restore");
    assert_eq!(
        mode_drift
            .analyze(
                base.request_with(&target, &base_build, "other-image", base.core_package),
                IncrementalAnalysisLimits::standard(),
                &never_cancelled,
            )
            .expect_err("mode drift must not reuse semantics"),
        IncrementalAnalysisFailure::IncompleteAnalysis
    );
    assert_eq!(mode_drift.source_graph_digest(), Some(base.source_graph));

    let mut std_drift = IncrementalAnalysisSession::restore(snapshot.clone()).expect("std restore");
    assert_eq!(
        std_drift
            .analyze(
                base.request_with(&target, &base_build, "session-image", PackageId(0)),
                IncrementalAnalysisLimits::standard(),
                &never_cancelled,
            )
            .expect_err("std package drift must not reuse semantics"),
        IncrementalAnalysisFailure::Analysis(wrela_sema::AnalysisFailure::RequestMismatch)
    );
    assert_eq!(std_drift.source_graph_digest(), Some(base.source_graph));

    let current = revision(IMAGE, PRIVATE_TWO, 0x81, "app/leaf.wr", false);
    let current_build = build(current.source_graph, 0xd2, 0xd3, target_digest, profile);
    let mut early = IncrementalAnalysisSession::restore(snapshot.clone()).expect("early restore");
    assert!(
        early
            .analyze(
                current.request(&target, &current_build),
                IncrementalAnalysisLimits::standard(),
                &|| true,
            )
            .expect_err("early cancellation")
            .is_cancelled()
    );
    assert_eq!(early.source_graph_digest(), Some(base.source_graph));

    let polls = Cell::new(0_u32);
    IncrementalAnalysisSession::restore(snapshot.clone())
        .expect("poll probe restore")
        .analyze(
            current.request(&target, &current_build),
            IncrementalAnalysisLimits::standard(),
            &|| {
                polls.set(polls.get().saturating_add(1));
                false
            },
        )
        .expect("poll probe");
    let late_at = polls.get();
    assert!(late_at > 1);
    let late_polls = Cell::new(0_u32);
    let mut late = IncrementalAnalysisSession::restore(snapshot).expect("late restore");
    assert!(
        late.analyze(
            current.request(&target, &current_build),
            IncrementalAnalysisLimits::standard(),
            &|| {
                let next = late_polls.get().saturating_add(1);
                late_polls.set(next);
                next == late_at
            },
        )
        .expect_err("late cancellation")
        .is_cancelled()
    );
    assert_eq!(late.source_graph_digest(), Some(base.source_graph));
    let retry = late
        .analyze(
            current.request(&target, &current_build),
            IncrementalAnalysisLimits::standard(),
            &never_cancelled,
        )
        .expect("successful retry after cancellation");
    assert_eq!(
        retry.hir().lowered().source_graph_digest(),
        current.source_graph
    );
}
