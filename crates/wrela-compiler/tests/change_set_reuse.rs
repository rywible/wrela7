#![forbid(unsafe_code)]

use std::cell::Cell;
use std::sync::Arc;

use wrela_build_model::{
    BuildConfiguration, BuildIdentity, BuildProfile, LanguageRevision, Sha256Digest,
    TargetIdentity, ValidatedBuildConfiguration, seal_build_configuration,
};
use wrela_hir::{DeclarationId, ValidatedProgram};
use wrela_hir_lower::{
    CanonicalHirLowerer, ChangeSet, HIR_CHANGE_SET_REUSE_VERSION, HirReuseLimits, LowerFailure,
    LowerOutput, LowerRequest, LoweringLimits, PreviousHirProduct,
};
use wrela_package::{
    DependencyAlias, ModuleId, ModulePath, PackageGraph, PackageGraphBuilder, PackageIdentity,
    PackageName, PackageVersion,
};
use wrela_package_loader::{ContentHasher, SoftwareSha256};
use wrela_sema::{
    ANALYSIS_CHANGE_SET_REUSE_VERSION, AnalysisChangeSet, AnalysisFailure, AnalysisLimits,
    AnalysisMode, AnalysisRequest, AnalysisReuseLimits, CanonicalSemanticAnalyzer,
    PreviousAnalysisProduct, SemanticAnalyzer,
};
use wrela_source::{FileId, SourceDatabase, SourceInput};
use wrela_syntax::{ParseLimits, ParseRequest, ParsedFile, SyntaxParser, WrelaSyntaxParser};
use wrela_target::TargetPackage;

const IMAGE_SOURCE: &str = r#"module app.image

from core.image import Image, Target

@image
pub fn boot() -> Image:
    return Image(name="reuse-image", target=Target.aarch64_qemu_virt_uefi)
"#;

const DEPENDENT_IMAGE_SOURCE: &str = r#"module app.image

from app.leaf import leaf
from core.image import Image, Target

@image
pub fn boot() -> Image:
    return Image(name="reuse-image", target=Target.aarch64_qemu_virt_uefi)

fn dependent() -> u8:
    return leaf()
"#;

const LEAF_ONE: &str = r#"module app.leaf

fn leaf() -> u8:
    return 1
"#;

const LEAF_TWO: &str = r#"module app.leaf

fn leaf() -> u8:
    return 2
"#;

const PUBLIC_LEAF_ONE: &str = r#"module app.leaf

pub fn leaf() -> u8:
    return 1
"#;

const PUBLIC_LEAF_TWO: &str = r#"module app.leaf

pub fn leaf() -> u8:
    return 2
"#;

const LEAF_U16: &str = r#"module app.leaf

pub fn leaf() -> u16:
    return 1
"#;

const LEAF_CONSTANT_ONE: &str = r#"module app.leaf

const leaf: u8 = 1
"#;

const LEAF_CONSTANT_TWO: &str = r#"module app.leaf

const leaf: u8 = 2
"#;

const LEAF_ERROR_ONE: &str = r#"module app.leaf

fn leaf() -> u8:
    return missing_old
"#;

const LEAF_ERROR_TWO: &str = r#"module app.leaf

fn leaf() -> u8:
    return missing_new
"#;

const CORE_IMAGE_SOURCE: &str = include_str!("../../../std/wrela-core-0.1/src/image.wr");

static HASHER: SoftwareSha256 = SoftwareSha256;

fn never_cancelled() -> bool {
    false
}

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

struct RevisionInput {
    sources: SourceDatabase,
    parsed: Vec<ParsedFile>,
    packages: Arc<PackageGraph>,
    source_graph: Sha256Digest,
    image_file: FileId,
    leaf_file: FileId,
}

impl RevisionInput {
    fn hir_request<'a>(&'a self, changes: &'a ChangeSet) -> LowerRequest<'a> {
        LowerRequest {
            packages: Arc::clone(&self.packages),
            source_graph_digest: self.source_graph,
            parsed_files: &self.parsed,
            sources: &self.sources,
            changes,
            limits: LoweringLimits::standard(),
        }
    }
}

fn revision_input(
    image: &str,
    leaf: &str,
    revision: u8,
    swap_module_sources: bool,
) -> RevisionInput {
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
            path: "app/leaf.wr".to_owned(),
            text: leaf.to_owned(),
            digest: HASHER.sha256(leaf.as_bytes()),
        })
        .expect("leaf source");
    let core_file = sources
        .add(SourceInput {
            path: "core/image.wr".to_owned(),
            text: CORE_IMAGE_SOURCE.to_owned(),
            digest: HASHER.sha256(CORE_IMAGE_SOURCE.as_bytes()),
        })
        .expect("core source");

    let source_graph = digest(revision);
    let mut graph = PackageGraphBuilder::new(identity("reuse-app", source_graph));
    let core = graph
        .add_package(identity("wrela-core", digest(0xc1)))
        .expect("core package");
    graph
        .add_dependency(
            graph.root(),
            DependencyAlias::new("core").expect("core alias"),
            core,
        )
        .expect("core dependency");
    graph
        .add_module(
            graph.root(),
            ModulePath::new(["app".to_owned(), "image".to_owned()]).expect("image module"),
            if swap_module_sources {
                leaf_file
            } else {
                image_file
            },
        )
        .expect("image module record");
    graph
        .add_module(
            graph.root(),
            ModulePath::new(["app".to_owned(), "leaf".to_owned()]).expect("leaf module"),
            if swap_module_sources {
                image_file
            } else {
                leaf_file
            },
        )
        .expect("leaf module record");
    graph
        .add_module(
            core,
            ModulePath::new(["image".to_owned()]).expect("core image module"),
            core_file,
        )
        .expect("core module record");

    let parsed = (0..sources.len())
        .map(|index| {
            let file = FileId(index as u32);
            let (parsed, diagnostics) = WrelaSyntaxParser::new()
                .parse(
                    ParseRequest {
                        sources: &sources,
                        file,
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

    RevisionInput {
        sources,
        parsed,
        packages: Arc::new(graph.finish().expect("package graph")),
        source_graph,
        image_file,
        leaf_file,
    }
}

fn cold_hir(input: &RevisionInput) -> (LowerOutput, wrela_hir_lower::HirReuseReport) {
    let changes = ChangeSet {
        previous_source_graph: None,
        changed_files: Vec::new(),
    };
    CanonicalHirLowerer::new()
        .lower_tracked(
            input.hir_request(&changes),
            None,
            HirReuseLimits::standard(),
            &never_cancelled,
        )
        .expect("cold HIR lowering")
        .into_parts()
}

fn shared_hir(output: &LowerOutput) -> Arc<ValidatedProgram> {
    Arc::new(output.lowered().program().clone())
}

fn package_id(hir: &ValidatedProgram, name: &str) -> wrela_package::PackageId {
    hir.as_program()
        .packages
        .packages()
        .iter()
        .find(|package| package.identity.name.as_str() == name)
        .expect("package identity")
        .id
}

fn module_id(hir: &ValidatedProgram, dotted: &str) -> ModuleId {
    hir.as_program()
        .modules
        .iter()
        .find(|module| module.path.dotted() == dotted)
        .expect("module identity")
        .id
}

fn module_declarations(hir: &ValidatedProgram, module: ModuleId) -> Vec<DeclarationId> {
    hir.as_program()
        .declarations
        .iter()
        .filter(|declaration| declaration.module == module)
        .map(|declaration| declaration.id)
        .collect()
}

fn build(
    source_graph: Sha256Digest,
    request: u8,
    compiler: u8,
    target_package: Sha256Digest,
) -> ValidatedBuildConfiguration {
    let profile = BuildProfile::development();
    let profile_digest = digest(0xd0);
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
            profile,
        },
        profile_digest,
    )
    .expect("build configuration")
}

fn analysis_request<'a>(
    hir: Arc<ValidatedProgram>,
    target: &'a TargetPackage,
    build: &'a ValidatedBuildConfiguration,
    changes: &'a AnalysisChangeSet,
) -> AnalysisRequest<'a> {
    let entry = *hir
        .as_program()
        .image_candidates
        .first()
        .expect("image entry");
    let standard_library_package = package_id(hir.as_ref(), "wrela-core");
    AnalysisRequest {
        hir,
        standard_library_package,
        target: target.semantic(),
        build,
        mode: AnalysisMode::Image {
            name: "reuse-image",
            entry,
        },
        changes,
        limits: AnalysisLimits::standard(),
    }
}

#[test]
fn real_change_sets_reuse_unaffected_producers_and_equal_clean_recomputation() {
    let base_input = revision_input(IMAGE_SOURCE, LEAF_ONE, 0x10, false);
    let (base_hir_output, base_hir_reuse) = cold_hir(&base_input);
    assert!(base_hir_reuse.reused_modules.is_empty());
    assert!(base_hir_reuse.reused_declarations.is_empty());
    assert_eq!(base_hir_reuse.comparisons, 0);
    assert_eq!(
        base_hir_reuse.producer_declarations_executed,
        base_hir_output
            .lowered()
            .program()
            .as_program()
            .declarations
            .len() as u64
    );
    let base_hir = shared_hir(&base_hir_output);

    let target_digest = digest(0xe0);
    let target = TargetPackage::aarch64_qemu_virt_uefi(target_digest);
    let base_build = build(base_input.source_graph, 0xe1, 0xe2, target_digest);
    let cold_analysis_changes = AnalysisChangeSet {
        previous_source_graph: None,
        changed_declarations: Vec::new(),
    };
    let base_analysis = CanonicalSemanticAnalyzer::new()
        .analyze_tracked(
            analysis_request(
                Arc::clone(&base_hir),
                &target,
                &base_build,
                &cold_analysis_changes,
            ),
            None,
            AnalysisReuseLimits::standard(),
            &never_cancelled,
        )
        .expect("cold semantic analysis");
    assert!(base_analysis.reuse().reused_functions.is_empty());
    assert_eq!(base_analysis.reuse().comparisons, 0);
    assert_eq!(
        base_analysis.reuse().producer_functions_executed,
        base_analysis.output().partial().functions.len() as u64
    );

    let current_input = revision_input(IMAGE_SOURCE, LEAF_TWO, 0x20, false);
    let (clean_hir, clean_hir_reuse) = cold_hir(&current_input);
    let current_changes = ChangeSet {
        previous_source_graph: Some(base_input.source_graph),
        changed_files: vec![current_input.leaf_file],
    };
    let incremental_hir = CanonicalHirLowerer::new()
        .lower_tracked(
            current_input.hir_request(&current_changes),
            Some(PreviousHirProduct {
                contract_version: HIR_CHANGE_SET_REUSE_VERSION,
                output: &base_hir_output,
            }),
            HirReuseLimits::standard(),
            &never_cancelled,
        )
        .expect("incremental HIR lowering");
    assert_eq!(incremental_hir.output(), &clean_hir);
    assert_eq!(
        incremental_hir.output().diagnostics(),
        clean_hir.diagnostics()
    );
    assert_eq!(
        incremental_hir.reuse().recomputed_files,
        [current_input.leaf_file]
    );
    assert!(!incremental_hir.reuse().reused_modules.is_empty());
    assert!(!incremental_hir.reuse().reused_declarations.is_empty());
    assert!(incremental_hir.reuse().comparisons > 0);
    assert!(
        incremental_hir.reuse().producer_declarations_executed
            < clean_hir_reuse.producer_declarations_executed
    );
    assert_eq!(
        incremental_hir.reuse().producer_declarations_executed
            + incremental_hir.reuse().reused_declarations.len() as u64,
        clean_hir_reuse.producer_declarations_executed
    );
    let reused_image = module_id(incremental_hir.output().lowered().program(), "app.image");
    assert!(
        incremental_hir
            .reuse()
            .reused_modules
            .contains(&reused_image)
    );

    let exact_hir_limits = HirReuseLimits {
        comparisons: incremental_hir.reuse().comparisons,
    };
    CanonicalHirLowerer::new()
        .lower_tracked(
            current_input.hir_request(&current_changes),
            Some(PreviousHirProduct {
                contract_version: HIR_CHANGE_SET_REUSE_VERSION,
                output: &base_hir_output,
            }),
            exact_hir_limits,
            &never_cancelled,
        )
        .expect("exact HIR reuse comparison bound");
    let one_under_hir = HirReuseLimits {
        comparisons: exact_hir_limits.comparisons - 1,
    };
    assert_eq!(
        CanonicalHirLowerer::new().lower_tracked(
            current_input.hir_request(&current_changes),
            Some(PreviousHirProduct {
                contract_version: HIR_CHANGE_SET_REUSE_VERSION,
                output: &base_hir_output,
            }),
            one_under_hir,
            &never_cancelled,
        ),
        Err(LowerFailure::ResourceLimit {
            resource: "HIR reuse comparisons",
            limit: one_under_hir.comparisons,
        })
    );
    let hir_cancel_polls = Cell::new(0_u32);
    let cancel_at = u32::try_from(base_input.sources.len()).expect("source count") + 2;
    let cancelled_hir = CanonicalHirLowerer::new().lower_tracked(
        current_input.hir_request(&current_changes),
        Some(PreviousHirProduct {
            contract_version: HIR_CHANGE_SET_REUSE_VERSION,
            output: &base_hir_output,
        }),
        HirReuseLimits::standard(),
        &|| {
            let next = hir_cancel_polls.get().saturating_add(1);
            hir_cancel_polls.set(next);
            next == cancel_at
        },
    );
    assert_eq!(cancelled_hir, Err(LowerFailure::Cancelled));
    assert_eq!(hir_cancel_polls.get(), cancel_at);

    let current_hir = shared_hir(incremental_hir.output());
    let leaf_module = module_id(current_hir.as_ref(), "app.leaf");
    let changed_declarations = module_declarations(current_hir.as_ref(), leaf_module);
    assert_eq!(changed_declarations.len(), 1);
    let current_build = build(current_input.source_graph, 0xe3, 0xe2, target_digest);
    let clean_current_analysis = CanonicalSemanticAnalyzer::new()
        .analyze_tracked(
            analysis_request(
                Arc::clone(&current_hir),
                &target,
                &current_build,
                &cold_analysis_changes,
            ),
            None,
            AnalysisReuseLimits::standard(),
            &never_cancelled,
        )
        .expect("clean current semantic analysis");
    let semantic_changes = AnalysisChangeSet {
        previous_source_graph: Some(base_input.source_graph),
        changed_declarations: changed_declarations.clone(),
    };
    let incremental_analysis = CanonicalSemanticAnalyzer::new()
        .analyze_tracked(
            analysis_request(
                Arc::clone(&current_hir),
                &target,
                &current_build,
                &semantic_changes,
            ),
            Some(PreviousAnalysisProduct {
                contract_version: ANALYSIS_CHANGE_SET_REUSE_VERSION,
                output: base_analysis.output(),
            }),
            AnalysisReuseLimits::standard(),
            &never_cancelled,
        )
        .expect("incremental semantic analysis");
    assert_eq!(
        incremental_analysis.output(),
        clean_current_analysis.output()
    );
    assert_eq!(
        incremental_analysis.output().diagnostics(),
        clean_current_analysis.output().diagnostics()
    );
    assert_eq!(
        incremental_analysis.reuse().recomputed_declarations,
        changed_declarations
    );
    assert!(!incremental_analysis.reuse().reused_declarations.is_empty());
    assert!(!incremental_analysis.reuse().reused_functions.is_empty());
    assert_eq!(incremental_analysis.reuse().producer_functions_executed, 0);
    assert!(incremental_analysis.reuse().comparisons > 0);

    let exact_analysis_limits = AnalysisReuseLimits {
        comparisons: incremental_analysis.reuse().comparisons,
    };
    CanonicalSemanticAnalyzer::new()
        .analyze_tracked(
            analysis_request(
                Arc::clone(&current_hir),
                &target,
                &current_build,
                &semantic_changes,
            ),
            Some(PreviousAnalysisProduct {
                contract_version: ANALYSIS_CHANGE_SET_REUSE_VERSION,
                output: base_analysis.output(),
            }),
            exact_analysis_limits,
            &never_cancelled,
        )
        .expect("exact semantic reuse comparison bound");
    let one_under_analysis = AnalysisReuseLimits {
        comparisons: exact_analysis_limits.comparisons - 1,
    };
    assert_eq!(
        CanonicalSemanticAnalyzer::new().analyze_tracked(
            analysis_request(
                Arc::clone(&current_hir),
                &target,
                &current_build,
                &semantic_changes,
            ),
            Some(PreviousAnalysisProduct {
                contract_version: ANALYSIS_CHANGE_SET_REUSE_VERSION,
                output: base_analysis.output(),
            }),
            one_under_analysis,
            &never_cancelled,
        ),
        Err(AnalysisFailure::ResourceLimit {
            resource: "semantic reuse comparisons",
            limit: one_under_analysis.comparisons,
        })
    );
    let analysis_cancel_polls = Cell::new(0_u32);
    let cancelled_analysis = CanonicalSemanticAnalyzer::new().analyze_tracked(
        analysis_request(
            Arc::clone(&current_hir),
            &target,
            &current_build,
            &semantic_changes,
        ),
        Some(PreviousAnalysisProduct {
            contract_version: ANALYSIS_CHANGE_SET_REUSE_VERSION,
            output: base_analysis.output(),
        }),
        AnalysisReuseLimits::standard(),
        &|| {
            let next = analysis_cancel_polls.get().saturating_add(1);
            analysis_cancel_polls.set(next);
            next == 2
        },
    );
    assert_eq!(cancelled_analysis, Err(AnalysisFailure::Cancelled));
    assert_eq!(analysis_cancel_polls.get(), 2);
}

#[test]
fn reuse_contract_rejects_forgery_underreporting_versions_targets_and_aliases() {
    let base_input = revision_input(IMAGE_SOURCE, LEAF_ONE, 0x31, false);
    let (base_hir_output, _) = cold_hir(&base_input);
    let current_input = revision_input(IMAGE_SOURCE, LEAF_TWO, 0x32, false);
    let valid_changes = ChangeSet {
        previous_source_graph: Some(base_input.source_graph),
        changed_files: vec![current_input.leaf_file],
    };
    let prior = PreviousHirProduct {
        contract_version: HIR_CHANGE_SET_REUSE_VERSION,
        output: &base_hir_output,
    };

    let forged = ChangeSet {
        previous_source_graph: Some(digest(0xff)),
        changed_files: valid_changes.changed_files.clone(),
    };
    assert_eq!(
        CanonicalHirLowerer::new().lower_tracked(
            current_input.hir_request(&forged),
            Some(prior),
            HirReuseLimits::standard(),
            &never_cancelled,
        ),
        Err(LowerFailure::InvalidChangeSet)
    );
    let omitted = ChangeSet {
        previous_source_graph: Some(base_input.source_graph),
        changed_files: Vec::new(),
    };
    assert_eq!(
        CanonicalHirLowerer::new().lower_tracked(
            current_input.hir_request(&omitted),
            Some(prior),
            HirReuseLimits::standard(),
            &never_cancelled,
        ),
        Err(LowerFailure::InvalidChangeSet)
    );
    for version in [0, 1, HIR_CHANGE_SET_REUSE_VERSION + 1] {
        assert_eq!(
            CanonicalHirLowerer::new().lower_tracked(
                current_input.hir_request(&valid_changes),
                Some(PreviousHirProduct {
                    contract_version: version,
                    output: &base_hir_output,
                }),
                HirReuseLimits::standard(),
                &never_cancelled,
            ),
            Err(LowerFailure::UnsupportedReuseVersion { observed: version })
        );
    }
    let aliased = revision_input(IMAGE_SOURCE, LEAF_TWO, 0x32, true);
    assert_eq!(
        CanonicalHirLowerer::new().lower_tracked(
            aliased.hir_request(&valid_changes),
            Some(prior),
            HirReuseLimits::standard(),
            &never_cancelled,
        ),
        Err(LowerFailure::InvalidChangeSet)
    );

    let dependent_base = revision_input(DEPENDENT_IMAGE_SOURCE, PUBLIC_LEAF_ONE, 0x41, false);
    let (dependent_base_output, _) = cold_hir(&dependent_base);
    assert!(dependent_base_output.diagnostics().is_empty());
    let dependent_current = revision_input(DEPENDENT_IMAGE_SOURCE, PUBLIC_LEAF_TWO, 0x42, false);
    let underreported_files = ChangeSet {
        previous_source_graph: Some(dependent_base.source_graph),
        changed_files: vec![dependent_current.leaf_file],
    };
    assert_eq!(
        CanonicalHirLowerer::new().lower_tracked(
            dependent_current.hir_request(&underreported_files),
            Some(PreviousHirProduct {
                contract_version: HIR_CHANGE_SET_REUSE_VERSION,
                output: &dependent_base_output,
            }),
            HirReuseLimits::standard(),
            &never_cancelled,
        ),
        Err(LowerFailure::InvalidChangeSet)
    );

    let target_digest = digest(0x50);
    let target = TargetPackage::aarch64_qemu_virt_uefi(target_digest);
    let base_hir = shared_hir(&base_hir_output);
    let base_build = build(base_input.source_graph, 0x51, 0x52, target_digest);
    let cold_changes = AnalysisChangeSet {
        previous_source_graph: None,
        changed_declarations: Vec::new(),
    };
    let base_analysis = CanonicalSemanticAnalyzer::new()
        .analyze(
            analysis_request(base_hir, &target, &base_build, &cold_changes),
            &never_cancelled,
        )
        .expect("base semantic analysis");
    let current_hir = shared_hir(
        CanonicalHirLowerer::new()
            .lower_tracked(
                current_input.hir_request(&valid_changes),
                Some(prior),
                HirReuseLimits::standard(),
                &never_cancelled,
            )
            .expect("current HIR")
            .output(),
    );
    let leaf = module_id(current_hir.as_ref(), "app.leaf");
    let leaf_declarations = module_declarations(current_hir.as_ref(), leaf);
    let current_build = build(current_input.source_graph, 0x53, 0x52, target_digest);
    let semantic_changes = AnalysisChangeSet {
        previous_source_graph: Some(base_input.source_graph),
        changed_declarations: leaf_declarations.clone(),
    };
    let semantic_prior = PreviousAnalysisProduct {
        contract_version: ANALYSIS_CHANGE_SET_REUSE_VERSION,
        output: &base_analysis,
    };
    let forged_semantic = AnalysisChangeSet {
        previous_source_graph: Some(digest(0xfe)),
        changed_declarations: leaf_declarations.clone(),
    };
    assert_eq!(
        CanonicalSemanticAnalyzer::new().analyze_tracked(
            analysis_request(
                Arc::clone(&current_hir),
                &target,
                &current_build,
                &forged_semantic,
            ),
            Some(semantic_prior),
            AnalysisReuseLimits::standard(),
            &never_cancelled,
        ),
        Err(AnalysisFailure::RequestMismatch)
    );
    let omitted_semantic = AnalysisChangeSet {
        previous_source_graph: Some(base_input.source_graph),
        changed_declarations: Vec::new(),
    };
    assert_eq!(
        CanonicalSemanticAnalyzer::new().analyze_tracked(
            analysis_request(
                Arc::clone(&current_hir),
                &target,
                &current_build,
                &omitted_semantic,
            ),
            Some(semantic_prior),
            AnalysisReuseLimits::standard(),
            &never_cancelled,
        ),
        Err(AnalysisFailure::RequestMismatch)
    );
    for version in [0, ANALYSIS_CHANGE_SET_REUSE_VERSION + 1] {
        assert_eq!(
            CanonicalSemanticAnalyzer::new().analyze_tracked(
                analysis_request(
                    Arc::clone(&current_hir),
                    &target,
                    &current_build,
                    &semantic_changes,
                ),
                Some(PreviousAnalysisProduct {
                    contract_version: version,
                    output: &base_analysis,
                }),
                AnalysisReuseLimits::standard(),
                &never_cancelled,
            ),
            Err(AnalysisFailure::UnsupportedReuseVersion { observed: version })
        );
    }
    let wrong_build = build(current_input.source_graph, 0x53, 0x99, target_digest);
    assert_eq!(
        CanonicalSemanticAnalyzer::new().analyze_tracked(
            analysis_request(
                Arc::clone(&current_hir),
                &target,
                &wrong_build,
                &semantic_changes,
            ),
            Some(semantic_prior),
            AnalysisReuseLimits::standard(),
            &never_cancelled,
        ),
        Err(AnalysisFailure::RequestMismatch)
    );
    let wrong_target = TargetPackage::aarch64_qemu_virt_uefi(digest(0x98));
    assert_eq!(
        CanonicalSemanticAnalyzer::new().analyze_tracked(
            analysis_request(
                Arc::clone(&current_hir),
                &wrong_target,
                &current_build,
                &semantic_changes,
            ),
            Some(semantic_prior),
            AnalysisReuseLimits::standard(),
            &never_cancelled,
        ),
        Err(AnalysisFailure::RequestMismatch)
    );

    let dependent_current_changes = ChangeSet {
        previous_source_graph: Some(dependent_base.source_graph),
        changed_files: vec![dependent_current.image_file, dependent_current.leaf_file],
    };
    let dependent_incremental = CanonicalHirLowerer::new()
        .lower_tracked(
            dependent_current.hir_request(&dependent_current_changes),
            Some(PreviousHirProduct {
                contract_version: HIR_CHANGE_SET_REUSE_VERSION,
                output: &dependent_base_output,
            }),
            HirReuseLimits::standard(),
            &never_cancelled,
        )
        .expect("dependent current HIR");
    assert!(dependent_incremental.output().diagnostics().is_empty());
    let dependent_hir = shared_hir(dependent_incremental.output());
    let dependent_leaf = module_id(dependent_hir.as_ref(), "app.leaf");
    let dependent_leaf_change = module_declarations(dependent_hir.as_ref(), dependent_leaf);
    let dependent_base_hir = shared_hir(&dependent_base_output);
    let dependent_base_build = build(dependent_base.source_graph, 0x61, 0x62, target_digest);
    let dependent_base_analysis = CanonicalSemanticAnalyzer::new()
        .analyze(
            analysis_request(
                dependent_base_hir,
                &target,
                &dependent_base_build,
                &cold_changes,
            ),
            &never_cancelled,
        )
        .expect("dependent base analysis");
    let dependent_current_build = build(dependent_current.source_graph, 0x63, 0x62, target_digest);
    let underreported_declarations = AnalysisChangeSet {
        previous_source_graph: Some(dependent_base.source_graph),
        changed_declarations: dependent_leaf_change,
    };
    assert_eq!(
        CanonicalSemanticAnalyzer::new().analyze_tracked(
            analysis_request(
                dependent_hir,
                &target,
                &dependent_current_build,
                &underreported_declarations,
            ),
            Some(PreviousAnalysisProduct {
                contract_version: ANALYSIS_CHANGE_SET_REUSE_VERSION,
                output: &dependent_base_analysis,
            }),
            AnalysisReuseLimits::standard(),
            &never_cancelled,
        ),
        Err(AnalysisFailure::RequestMismatch)
    );
}

#[test]
fn changed_module_diagnostics_and_source_spans_equal_clean_recomputation() {
    let base = revision_input(IMAGE_SOURCE, LEAF_ERROR_ONE, 0x71, false);
    let (base_output, _) = cold_hir(&base);
    assert!(!base_output.diagnostics().is_empty());
    let current = revision_input(IMAGE_SOURCE, LEAF_ERROR_TWO, 0x72, false);
    let (clean, _) = cold_hir(&current);
    let changes = ChangeSet {
        previous_source_graph: Some(base.source_graph),
        changed_files: vec![current.leaf_file],
    };
    let incremental = CanonicalHirLowerer::new()
        .lower_tracked(
            current.hir_request(&changes),
            Some(PreviousHirProduct {
                contract_version: HIR_CHANGE_SET_REUSE_VERSION,
                output: &base_output,
            }),
            HirReuseLimits::standard(),
            &never_cancelled,
        )
        .expect("diagnostic incremental HIR");
    assert_eq!(incremental.output(), &clean);
    assert_eq!(incremental.output().diagnostics(), clean.diagnostics());
    assert!(!incremental.output().diagnostics().is_empty());
    for diagnostic in incremental.output().diagnostics() {
        assert_eq!(
            current.sources.span_text(diagnostic.primary),
            clean
                .diagnostics()
                .iter()
                .find(|candidate| candidate.code == diagnostic.code)
                .and_then(|candidate| current.sources.span_text(candidate.primary))
        );
    }
}

#[test]
fn non_literal_header_changes_force_real_semantic_producer_execution() {
    let base = revision_input(DEPENDENT_IMAGE_SOURCE, PUBLIC_LEAF_ONE, 0x81, false);
    let (base_hir_output, _) = cold_hir(&base);
    assert!(base_hir_output.diagnostics().is_empty());
    let base_hir = shared_hir(&base_hir_output);
    let target_digest = digest(0x82);
    let target = TargetPackage::aarch64_qemu_virt_uefi(target_digest);
    let base_build = build(base.source_graph, 0x83, 0x84, target_digest);
    let cold_changes = AnalysisChangeSet {
        previous_source_graph: None,
        changed_declarations: Vec::new(),
    };
    let base_analysis = CanonicalSemanticAnalyzer::new()
        .analyze(
            analysis_request(base_hir, &target, &base_build, &cold_changes),
            &never_cancelled,
        )
        .expect("base semantic analysis");

    let current = revision_input(DEPENDENT_IMAGE_SOURCE, LEAF_U16, 0x85, false);
    let (current_hir_output, _) = cold_hir(&current);
    assert!(current_hir_output.diagnostics().is_empty());
    let current_hir = shared_hir(&current_hir_output);
    let changed_declarations = current_hir
        .as_program()
        .declarations
        .iter()
        .map(|declaration| declaration.id)
        .collect::<Vec<_>>();
    let current_build = build(current.source_graph, 0x86, 0x84, target_digest);
    let clean = CanonicalSemanticAnalyzer::new()
        .analyze_tracked(
            analysis_request(
                Arc::clone(&current_hir),
                &target,
                &current_build,
                &cold_changes,
            ),
            None,
            AnalysisReuseLimits::standard(),
            &never_cancelled,
        )
        .expect("clean semantic analysis");
    let changes = AnalysisChangeSet {
        previous_source_graph: Some(base.source_graph),
        changed_declarations: changed_declarations.clone(),
    };
    let incremental = CanonicalSemanticAnalyzer::new()
        .analyze_tracked(
            analysis_request(Arc::clone(&current_hir), &target, &current_build, &changes),
            Some(PreviousAnalysisProduct {
                contract_version: ANALYSIS_CHANGE_SET_REUSE_VERSION,
                output: &base_analysis,
            }),
            AnalysisReuseLimits::standard(),
            &never_cancelled,
        )
        .expect("header-changing semantic analysis");
    assert_eq!(incremental.output(), clean.output());
    assert_eq!(
        incremental.output().diagnostics(),
        clean.output().diagnostics()
    );
    assert_eq!(
        incremental.reuse().recomputed_declarations,
        changed_declarations
    );
    assert!(incremental.reuse().reused_declarations.is_empty());
    assert!(incremental.reuse().reused_functions.is_empty());
    assert_eq!(
        incremental.reuse().producer_functions_executed,
        clean.output().partial().functions.len() as u64
    );
    assert!(incremental.reuse().producer_functions_executed > 0);
}

#[test]
fn constant_literal_changes_cannot_claim_narrow_semantic_reuse() {
    let base = revision_input(IMAGE_SOURCE, LEAF_CONSTANT_ONE, 0x91, false);
    let (base_hir_output, _) = cold_hir(&base);
    let base_hir = shared_hir(&base_hir_output);
    let target_digest = digest(0x92);
    let target = TargetPackage::aarch64_qemu_virt_uefi(target_digest);
    let base_build = build(base.source_graph, 0x93, 0x94, target_digest);
    let cold_changes = AnalysisChangeSet {
        previous_source_graph: None,
        changed_declarations: Vec::new(),
    };
    let base_analysis = CanonicalSemanticAnalyzer::new()
        .analyze(
            analysis_request(base_hir, &target, &base_build, &cold_changes),
            &never_cancelled,
        )
        .expect("base constant semantic analysis");

    let current = revision_input(IMAGE_SOURCE, LEAF_CONSTANT_TWO, 0x95, false);
    let (current_hir_output, _) = cold_hir(&current);
    let current_hir = shared_hir(&current_hir_output);
    let changed_declarations = current_hir
        .as_program()
        .declarations
        .iter()
        .map(|declaration| declaration.id)
        .collect::<Vec<_>>();
    let current_build = build(current.source_graph, 0x96, 0x94, target_digest);
    let clean = CanonicalSemanticAnalyzer::new()
        .analyze_tracked(
            analysis_request(
                Arc::clone(&current_hir),
                &target,
                &current_build,
                &cold_changes,
            ),
            None,
            AnalysisReuseLimits::standard(),
            &never_cancelled,
        )
        .expect("clean constant semantic analysis");
    let changes = AnalysisChangeSet {
        previous_source_graph: Some(base.source_graph),
        changed_declarations: changed_declarations.clone(),
    };
    let incremental = CanonicalSemanticAnalyzer::new()
        .analyze_tracked(
            analysis_request(Arc::clone(&current_hir), &target, &current_build, &changes),
            Some(PreviousAnalysisProduct {
                contract_version: ANALYSIS_CHANGE_SET_REUSE_VERSION,
                output: &base_analysis,
            }),
            AnalysisReuseLimits::standard(),
            &never_cancelled,
        )
        .expect("constant change semantic analysis");
    assert_eq!(incremental.output(), clean.output());
    assert_eq!(
        incremental.reuse().recomputed_declarations,
        changed_declarations
    );
    assert!(incremental.reuse().reused_declarations.is_empty());
    assert!(incremental.reuse().reused_functions.is_empty());
    assert_eq!(
        incremental.reuse().producer_functions_executed,
        clean.output().partial().functions.len() as u64
    );
    assert!(incremental.reuse().producer_functions_executed > 0);
}
