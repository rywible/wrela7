//! Atomic, stateful HIR and semantic reuse for a persistent compiler engine.
//!
//! The session never accepts caller-authored file or declaration invalidation
//! lists. It derives both from sealed prior products, runs the real tracked
//! producers, and replaces its prior state only after the new HIR and complete
//! semantic image have both sealed.

use std::fmt;
use std::sync::Arc;

use wrela_build_model::{Sha256Digest, ValidatedBuildConfiguration};
use wrela_hir_lower::{
    CanonicalHirLowerer, ChangeSet as HirChangeSet, HIR_CHANGE_SET_REUSE_VERSION, HirReuseLimits,
    HirReuseReport, LowerFailure, LowerOutput, LowerRequest, LoweringLimits, PreviousHirProduct,
    SourceRevision,
};
use wrela_package::{ModuleId, PackageGraph, PackageId};
use wrela_sema::{
    ANALYSIS_CHANGE_SET_REUSE_VERSION, AnalysisChangeSet, AnalysisFailure, AnalysisLimits,
    AnalysisMode, AnalysisOutput, AnalysisRequest, AnalysisReuseLimits, AnalysisReuseReport,
    AnalysisRoot, CanonicalSemanticAnalyzer, PreviousAnalysisProduct,
};
use wrela_source::{FileId, SourceDatabase};
use wrela_syntax::ParsedFile;
use wrela_target::TargetSemanticContract;

/// Version of the in-memory session snapshot contract. It is separate from
/// the HIR and semantic reuse versions so any change in atomic publication or
/// source-identity validation invalidates old snapshots explicitly.
pub const INCREMENTAL_ANALYSIS_SESSION_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IncrementalAnalysisLimits {
    /// Comparisons used to derive the complete file dependency closure.
    pub change_comparisons: u64,
    /// Independent bounds for HIR reuse validation and installation.
    pub hir_reuse: HirReuseLimits,
    /// Independent bound for deriving the exact semantic declaration set.
    pub semantic_change: AnalysisReuseLimits,
    /// Independent bound for semantic product validation and reuse.
    pub semantic_reuse: AnalysisReuseLimits,
}

impl IncrementalAnalysisLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            change_comparisons: 256_000_000,
            hir_reuse: HirReuseLimits::standard(),
            semantic_change: AnalysisReuseLimits::standard(),
            semantic_reuse: AnalysisReuseLimits::standard(),
        }
    }

    fn validate(self) -> Result<(), IncrementalAnalysisFailure> {
        if self.change_comparisons == 0 {
            Err(IncrementalAnalysisFailure::InvalidLimits)
        } else {
            Ok(())
        }
    }
}

/// One complete compiler request without any caller-provided ChangeSet.
#[derive(Debug, Clone)]
pub struct IncrementalAnalysisRequest<'a> {
    pub packages: Arc<PackageGraph>,
    pub source_graph_digest: Sha256Digest,
    pub parsed_files: &'a [ParsedFile],
    pub sources: &'a SourceDatabase,
    pub lowering_limits: LoweringLimits,
    pub standard_library_package: PackageId,
    pub target: &'a TargetSemanticContract,
    pub build: &'a ValidatedBuildConfiguration,
    pub mode: AnalysisMode<'a>,
    pub analysis_limits: AnalysisLimits,
}

/// Non-semantic execution evidence from one atomically published revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncrementalReuseEvidence {
    pub exact_revision_reused: bool,
    pub changed_files: Vec<FileId>,
    pub changed_declarations: Vec<wrela_hir::DeclarationId>,
    pub change_comparisons: u64,
    pub semantic_change_comparisons: u64,
    pub hir: HirReuseReport,
    pub analysis: AnalysisReuseReport,
}

/// Borrowed view of the newly committed products. The evidence is owned by
/// the result and never enters either sealed producer product.
#[derive(Debug)]
pub struct IncrementalAnalysisResult {
    hir: Arc<LowerOutput>,
    analysis: Arc<AnalysisOutput>,
    evidence: IncrementalReuseEvidence,
}

impl IncrementalAnalysisResult {
    #[must_use]
    pub fn hir(&self) -> &LowerOutput {
        self.hir.as_ref()
    }

    #[must_use]
    pub fn analysis(&self) -> &AnalysisOutput {
        self.analysis.as_ref()
    }

    #[must_use]
    pub const fn evidence(&self) -> &IncrementalReuseEvidence {
        &self.evidence
    }
}

/// Transfer object for a persistent engine restart. All fields are public so
/// untrusted or stale persisted metadata can be reconstructed and rejected by
/// [`IncrementalAnalysisSession::restore`]; the HIR and semantic products
/// themselves remain sealed by their producer crates.
#[derive(Debug, Clone, PartialEq)]
pub struct IncrementalAnalysisSnapshot {
    pub contract_version: u32,
    pub hir_reuse_version: u32,
    pub analysis_reuse_version: u32,
    pub source_revisions: Vec<SourceRevision>,
    pub standard_library_package: PackageId,
    pub hir: Arc<LowerOutput>,
    pub analysis: Arc<AnalysisOutput>,
}

#[derive(Debug)]
struct IncrementalState {
    source_revisions: Vec<SourceRevision>,
    standard_library_package: PackageId,
    hir: Arc<LowerOutput>,
    analysis: Arc<AnalysisOutput>,
}

/// Stateful compiler consumer intended to live inside the hermetic Linux
/// engine. No parser, filesystem, target, or build request is retained between
/// calls; only sealed products and exact source identities survive.
#[derive(Debug, Default)]
pub struct IncrementalAnalysisSession {
    state: Option<IncrementalState>,
}

impl IncrementalAnalysisSession {
    #[must_use]
    pub const fn new() -> Self {
        Self { state: None }
    }

    pub fn restore(
        snapshot: IncrementalAnalysisSnapshot,
    ) -> Result<Self, IncrementalAnalysisFailure> {
        validate_snapshot(&snapshot)?;
        Ok(Self {
            state: Some(IncrementalState {
                source_revisions: snapshot.source_revisions,
                standard_library_package: snapshot.standard_library_package,
                hir: snapshot.hir,
                analysis: snapshot.analysis,
            }),
        })
    }

    #[must_use]
    pub const fn has_prior(&self) -> bool {
        self.state.is_some()
    }

    #[must_use]
    pub fn source_graph_digest(&self) -> Option<Sha256Digest> {
        self.state
            .as_ref()
            .map(|state| state.hir.lowered().source_graph_digest())
    }

    #[must_use]
    pub fn snapshot(&self) -> Option<IncrementalAnalysisSnapshot> {
        self.state
            .as_ref()
            .map(|state| IncrementalAnalysisSnapshot {
                contract_version: INCREMENTAL_ANALYSIS_SESSION_VERSION,
                hir_reuse_version: HIR_CHANGE_SET_REUSE_VERSION,
                analysis_reuse_version: ANALYSIS_CHANGE_SET_REUSE_VERSION,
                source_revisions: state.source_revisions.clone(),
                standard_library_package: state.standard_library_package,
                hir: state.hir.clone(),
                analysis: state.analysis.clone(),
            })
    }

    /// Run and atomically publish one revision. Any error, cancellation, or
    /// incomplete semantic result drops all current locals and leaves the
    /// previous state byte-for-byte reusable for a retry.
    pub fn analyze(
        &mut self,
        request: IncrementalAnalysisRequest<'_>,
        limits: IncrementalAnalysisLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<IncrementalAnalysisResult, IncrementalAnalysisFailure> {
        limits.validate()?;
        request.lowering_limits.validate()?;
        if request.build.identity().source_graph != request.source_graph_digest {
            return Err(IncrementalAnalysisFailure::RequestMismatch(
                "build and source graph identities differ",
            ));
        }
        let current_revisions =
            collect_source_revisions(request.sources, request.lowering_limits, is_cancelled)?;
        validate_parsed_revisions(
            request.parsed_files,
            &current_revisions,
            request.lowering_limits,
            is_cancelled,
        )?;

        let mut exact_revision_reused = false;
        let mut hir_incremental = false;
        let mut semantic_incremental = false;
        let (hir_output, hir_reuse, changed_files, change_comparisons) = if let Some(previous) =
            self.state.as_ref()
        {
            let prior_packages = previous
                .hir
                .lowered()
                .program()
                .as_program()
                .packages
                .as_ref();
            let reusable_shape =
                compatible_package_graphs(prior_packages, request.packages.as_ref())
                    && source_revision_shapes_match(&previous.source_revisions, &current_revisions);
            if !reusable_shape {
                let (output, reuse) = cold_hir(&request, limits.hir_reuse, is_cancelled)?;
                let changed_files = current_revisions
                    .iter()
                    .map(|revision| revision.file)
                    .collect();
                (output, reuse, changed_files, 0)
            } else {
                let mut meter = ChangeMeter::new(limits.change_comparisons, is_cancelled);
                let delta = derive_hir_changes(previous, &current_revisions, &mut meter)?;
                let same_graph =
                    previous.hir.lowered().source_graph_digest() == request.source_graph_digest;
                let exact_package_identity = prior_packages == request.packages.as_ref();
                let semantic_identity_matches = semantic_identity_matches(previous, &request);
                if delta.direct_changes.is_empty() && same_graph && !exact_package_identity {
                    return Err(IncrementalAnalysisFailure::RequestMismatch(
                        "package identity changed without a new source graph identity",
                    ));
                }
                if delta.direct_changes.is_empty()
                    && same_graph
                    && exact_package_identity
                    && semantic_identity_matches
                {
                    check_cancelled(is_cancelled)?;
                    exact_revision_reused = true;
                    let evidence = IncrementalReuseEvidence {
                        exact_revision_reused,
                        changed_files: Vec::new(),
                        changed_declarations: Vec::new(),
                        change_comparisons: meter.used,
                        semantic_change_comparisons: 0,
                        hir: identity_hir_reuse(previous, meter.used),
                        analysis: identity_analysis_reuse(previous),
                    };
                    return Ok(IncrementalAnalysisResult {
                        hir: Arc::clone(&previous.hir),
                        analysis: Arc::clone(&previous.analysis),
                        evidence,
                    });
                }
                if !delta.direct_changes.is_empty() && same_graph {
                    return Err(IncrementalAnalysisFailure::RequestMismatch(
                        "source content changed without a new source graph identity",
                    ));
                }
                semantic_incremental =
                    !delta.direct_changes.is_empty() && semantic_identity_matches;
                if delta.direct_changes.is_empty() {
                    if same_graph {
                        // The HIR request is byte-identical. A changed target,
                        // profile, command request, mode, or selected std package
                        // invalidates semantics only; retain the exact sealed HIR.
                        (
                            Arc::clone(&previous.hir),
                            identity_hir_reuse(previous, meter.used),
                            Vec::new(),
                            meter.used,
                        )
                    } else {
                        // A manifest/package source identity changed without a
                        // file payload delta. Reuse no HIR producer state across
                        // that boundary even when topology remains compatible.
                        let (output, reuse) = cold_hir(&request, limits.hir_reuse, is_cancelled)?;
                        (output, reuse, Vec::new(), meter.used)
                    }
                } else {
                    hir_incremental = true;
                    let changes = HirChangeSet {
                        previous_source_graph: Some(previous.hir.lowered().source_graph_digest()),
                        changed_files: delta.affected_files.clone(),
                    };
                    let tracked = CanonicalHirLowerer::new().lower_tracked(
                        hir_request(&request, &changes),
                        Some(PreviousHirProduct {
                            contract_version: HIR_CHANGE_SET_REUSE_VERSION,
                            output: previous.hir.as_ref(),
                        }),
                        limits.hir_reuse,
                        is_cancelled,
                    )?;
                    let (output, reuse) = tracked.into_parts();
                    (Arc::new(output), reuse, delta.affected_files, meter.used)
                }
            }
        } else {
            let (output, reuse) = cold_hir(&request, limits.hir_reuse, is_cancelled)?;
            (output, reuse, Vec::new(), 0)
        };

        let shared_hir = Arc::clone(hir_output.lowered().shared_program());
        let (analysis_output, analysis_reuse, changed_declarations, semantic_change_comparisons) =
            if hir_incremental && semantic_incremental {
                let previous = self
                    .state
                    .as_ref()
                    .expect("incremental HIR requires prior state");
                let derived = CanonicalSemanticAnalyzer::new().derive_change_set(
                    shared_hir.as_ref(),
                    request.source_graph_digest,
                    PreviousAnalysisProduct {
                        contract_version: ANALYSIS_CHANGE_SET_REUSE_VERSION,
                        output: previous.analysis.as_ref(),
                    },
                    limits.semantic_change,
                    is_cancelled,
                )?;
                let (changes, comparisons) = derived.into_parts();
                let changed_declarations = changes.changed_declarations.clone();
                let tracked = CanonicalSemanticAnalyzer::new().analyze_tracked(
                    AnalysisRequest {
                        hir: Arc::clone(&shared_hir),
                        standard_library_package: request.standard_library_package,
                        target: request.target,
                        build: request.build,
                        mode: request.mode,
                        changes: &changes,
                        limits: request.analysis_limits,
                    },
                    Some(PreviousAnalysisProduct {
                        contract_version: ANALYSIS_CHANGE_SET_REUSE_VERSION,
                        output: previous.analysis.as_ref(),
                    }),
                    limits.semantic_reuse,
                    is_cancelled,
                )?;
                let (output, reuse) = tracked.into_parts();
                (output, reuse, changed_declarations, comparisons)
            } else {
                let changes = AnalysisChangeSet {
                    previous_source_graph: None,
                    changed_declarations: Vec::new(),
                };
                let tracked = CanonicalSemanticAnalyzer::new().analyze_tracked(
                    AnalysisRequest {
                        hir: Arc::clone(&shared_hir),
                        standard_library_package: request.standard_library_package,
                        target: request.target,
                        build: request.build,
                        mode: request.mode,
                        changes: &changes,
                        limits: request.analysis_limits,
                    },
                    None,
                    limits.semantic_reuse,
                    is_cancelled,
                )?;
                let (output, reuse) = tracked.into_parts();
                (output, reuse, Vec::new(), 0)
            };
        if analysis_output.successful().is_none() {
            return Err(IncrementalAnalysisFailure::IncompleteAnalysis);
        }
        if is_cancelled() {
            return Err(IncrementalAnalysisFailure::Cancelled);
        }

        let evidence = IncrementalReuseEvidence {
            exact_revision_reused,
            changed_files,
            changed_declarations,
            change_comparisons,
            semantic_change_comparisons,
            hir: hir_reuse,
            analysis: analysis_reuse,
        };
        self.state = Some(IncrementalState {
            source_revisions: current_revisions,
            standard_library_package: request.standard_library_package,
            hir: hir_output,
            analysis: Arc::new(analysis_output),
        });
        let state = self
            .state
            .as_ref()
            .expect("incremental state was assigned immediately above");
        Ok(IncrementalAnalysisResult {
            hir: Arc::clone(&state.hir),
            analysis: Arc::clone(&state.analysis),
            evidence,
        })
    }
}

fn hir_request<'a>(
    request: &'a IncrementalAnalysisRequest<'_>,
    changes: &'a HirChangeSet,
) -> LowerRequest<'a> {
    LowerRequest {
        packages: Arc::clone(&request.packages),
        source_graph_digest: request.source_graph_digest,
        parsed_files: request.parsed_files,
        sources: request.sources,
        changes,
        limits: request.lowering_limits,
    }
}

fn cold_hir(
    request: &IncrementalAnalysisRequest<'_>,
    limits: HirReuseLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(Arc<LowerOutput>, HirReuseReport), IncrementalAnalysisFailure> {
    let changes = HirChangeSet {
        previous_source_graph: None,
        changed_files: Vec::new(),
    };
    let (output, reuse) = CanonicalHirLowerer::new()
        .lower_tracked(hir_request(request, &changes), None, limits, is_cancelled)?
        .into_parts();
    Ok((Arc::new(output), reuse))
}

fn semantic_identity_matches(
    previous: &IncrementalState,
    request: &IncrementalAnalysisRequest<'_>,
) -> bool {
    let Some(analyzed) = previous.analysis.successful() else {
        return false;
    };
    let old = &analyzed.facts().build;
    let new = request.build.identity();
    old.compiler == new.compiler
        && old.language == new.language
        && old.target == new.target
        && old.target_package == new.target_package
        && old.standard_library == new.standard_library
        && old.profile == new.profile
        && old.request == new.request
        && analyzed.facts().target_digest == request.target.content_digest()
        && request.target.identity() == &new.target
        && previous.standard_library_package == request.standard_library_package
        && mode_matches_root(&request.mode, &analyzed.facts().root)
}

fn mode_matches_root(mode: &AnalysisMode<'_>, root: &AnalysisRoot) -> bool {
    matches!(
        (mode, root),
        (
            AnalysisMode::Image { name, entry },
            AnalysisRoot::DeclaredImage {
                image_name,
                declaration,
                test_group: None,
            }
        ) if *name == image_name && entry == declaration
    )
}

fn identity_hir_reuse(previous: &IncrementalState, comparisons: u64) -> HirReuseReport {
    let program = previous.hir.lowered().program().as_program();
    HirReuseReport {
        reused_modules: program.modules.iter().map(|module| module.id).collect(),
        reused_declarations: program
            .declarations
            .iter()
            .map(|declaration| declaration.id)
            .collect(),
        recomputed_files: Vec::new(),
        producer_declarations_executed: 0,
        comparisons,
    }
}

fn identity_analysis_reuse(previous: &IncrementalState) -> AnalysisReuseReport {
    let analyzed = previous
        .analysis
        .successful()
        .expect("session state admits only complete semantic products");
    let reused_declarations = match &analyzed.facts().root {
        AnalysisRoot::DeclaredImage { declaration, .. } => vec![*declaration],
        AnalysisRoot::GeneratedTestHarness { .. } => Vec::new(),
    };
    AnalysisReuseReport {
        reused_declarations,
        reused_functions: analyzed
            .facts()
            .functions
            .iter()
            .map(|function| function.id)
            .collect(),
        recomputed_declarations: Vec::new(),
        producer_functions_executed: 0,
        comparisons: 0,
    }
}

fn compatible_package_graphs(previous: &PackageGraph, current: &PackageGraph) -> bool {
    previous.root() == current.root()
        && previous.packages().len() == current.packages().len()
        && previous.modules() == current.modules()
        && previous
            .packages()
            .iter()
            .zip(current.packages())
            .all(|(left, right)| {
                left.id == right.id
                    && left.identity.name == right.identity.name
                    && left.identity.version == right.identity.version
                    && left.dependencies == right.dependencies
            })
}

fn source_revision_shapes_match(previous: &[SourceRevision], current: &[SourceRevision]) -> bool {
    previous.len() == current.len()
        && previous
            .iter()
            .zip(current)
            .all(|(left, right)| left.file == right.file && left.path == right.path)
}

fn validate_snapshot(
    snapshot: &IncrementalAnalysisSnapshot,
) -> Result<(), IncrementalAnalysisFailure> {
    if snapshot.contract_version != INCREMENTAL_ANALYSIS_SESSION_VERSION {
        return Err(IncrementalAnalysisFailure::UnsupportedSessionVersion {
            observed: snapshot.contract_version,
        });
    }
    if snapshot.hir_reuse_version != HIR_CHANGE_SET_REUSE_VERSION {
        return Err(IncrementalAnalysisFailure::UnsupportedHirReuseVersion {
            observed: snapshot.hir_reuse_version,
        });
    }
    if snapshot.analysis_reuse_version != ANALYSIS_CHANGE_SET_REUSE_VERSION {
        return Err(
            IncrementalAnalysisFailure::UnsupportedAnalysisReuseVersion {
                observed: snapshot.analysis_reuse_version,
            },
        );
    }
    if snapshot.source_revisions.as_slice() != snapshot.hir.lowered().source_revisions() {
        return Err(IncrementalAnalysisFailure::CorruptSnapshot(
            "source revisions do not match sealed HIR",
        ));
    }
    let packages = snapshot
        .hir
        .lowered()
        .program()
        .as_program()
        .packages
        .as_ref();
    if selected_standard_library_package(packages) != Some(snapshot.standard_library_package) {
        return Err(IncrementalAnalysisFailure::CorruptSnapshot(
            "selected standard-library package is not the root core dependency",
        ));
    }
    let Some(analyzed) = snapshot.analysis.successful() else {
        return Err(IncrementalAnalysisFailure::CorruptSnapshot(
            "prior semantic product is incomplete",
        ));
    };
    if analyzed.hir() != snapshot.hir.lowered().program()
        || analyzed.facts().build.source_graph != snapshot.hir.lowered().source_graph_digest()
    {
        return Err(IncrementalAnalysisFailure::CorruptSnapshot(
            "semantic and HIR products describe different revisions",
        ));
    }
    Ok(())
}

fn selected_standard_library_package(packages: &PackageGraph) -> Option<PackageId> {
    packages
        .packages()
        .get(packages.root().0 as usize)?
        .dependencies
        .iter()
        .find(|dependency| dependency.alias.as_str() == "core")
        .map(|dependency| dependency.package)
}

fn collect_source_revisions(
    sources: &SourceDatabase,
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<SourceRevision>, IncrementalAnalysisFailure> {
    if sources.len() > limits.modules as usize {
        return Err(IncrementalAnalysisFailure::ResourceLimit {
            resource: "incremental source revisions",
            limit: u64::from(limits.modules),
        });
    }
    let mut revisions = Vec::new();
    revisions.try_reserve_exact(sources.len()).map_err(|_| {
        IncrementalAnalysisFailure::ResourceLimit {
            resource: "incremental source revisions",
            limit: u64::from(limits.modules),
        }
    })?;
    let mut path_bytes = 0_u64;
    for index in 0..sources.len() {
        check_cancelled(is_cancelled)?;
        let file = FileId(u32::try_from(index).map_err(|_| {
            IncrementalAnalysisFailure::ResourceLimit {
                resource: "incremental source revisions",
                limit: u64::from(limits.modules),
            }
        })?);
        let source = sources
            .get(file)
            .ok_or(IncrementalAnalysisFailure::RequestMismatch(
                "source database is not dense",
            ))?;
        path_bytes = path_bytes
            .checked_add(u64::try_from(source.path().len()).map_err(|_| {
                IncrementalAnalysisFailure::ResourceLimit {
                    resource: "incremental source revision path bytes",
                    limit: limits.payload_bytes,
                }
            })?)
            .ok_or(IncrementalAnalysisFailure::ResourceLimit {
                resource: "incremental source revision path bytes",
                limit: limits.payload_bytes,
            })?;
        if path_bytes > limits.payload_bytes {
            return Err(IncrementalAnalysisFailure::ResourceLimit {
                resource: "incremental source revision path bytes",
                limit: limits.payload_bytes,
            });
        }
        let mut path = String::new();
        path.try_reserve_exact(source.path().len()).map_err(|_| {
            IncrementalAnalysisFailure::ResourceLimit {
                resource: "incremental source revision path bytes",
                limit: limits.payload_bytes,
            }
        })?;
        path.push_str(source.path());
        revisions.push(SourceRevision {
            file,
            path,
            digest: source.digest(),
        });
    }
    Ok(revisions)
}

fn validate_parsed_revisions(
    parsed_files: &[ParsedFile],
    revisions: &[SourceRevision],
    limits: LoweringLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), IncrementalAnalysisFailure> {
    if parsed_files.len() != revisions.len() || parsed_files.len() > limits.modules as usize {
        return Err(IncrementalAnalysisFailure::StaleParsedInput);
    }
    for (index, (parsed, revision)) in parsed_files.iter().zip(revisions).enumerate() {
        check_cancelled(is_cancelled)?;
        let file = FileId(u32::try_from(index).map_err(|_| {
            IncrementalAnalysisFailure::ResourceLimit {
                resource: "incremental parsed revisions",
                limit: u64::from(limits.modules),
            }
        })?);
        if parsed.file() != file
            || revision.file != file
            || parsed.source_digest() != revision.digest
        {
            return Err(IncrementalAnalysisFailure::StaleParsedInput);
        }
    }
    Ok(())
}

fn derive_hir_changes(
    previous: &IncrementalState,
    current_revisions: &[SourceRevision],
    meter: &mut ChangeMeter<'_>,
) -> Result<HirRevisionDelta, IncrementalAnalysisFailure> {
    if previous.source_revisions.len() != current_revisions.len() {
        return Err(IncrementalAnalysisFailure::SourceShapeMismatch);
    }
    let mut direct_changes = Vec::new();
    for (prior, current) in previous.source_revisions.iter().zip(current_revisions) {
        meter.poll()?;
        if prior.file != current.file || prior.path != current.path {
            return Err(IncrementalAnalysisFailure::SourceShapeMismatch);
        }
        if prior.digest != current.digest {
            direct_changes.push(current.file);
        }
    }
    if direct_changes.is_empty() {
        return Ok(HirRevisionDelta {
            direct_changes,
            affected_files: Vec::new(),
        });
    }
    let mut affected = direct_changes
        .iter()
        .copied()
        .collect::<std::collections::BTreeSet<_>>();
    let packages = previous
        .hir
        .lowered()
        .program()
        .as_program()
        .packages
        .as_ref();
    loop {
        let before = affected.len();
        for record in previous.hir.lowered().uses() {
            meter.poll()?;
            let Some(module) = binding_module(record.target.as_ref()) else {
                continue;
            };
            let target_file = packages
                .modules()
                .get(module.0 as usize)
                .ok_or(IncrementalAnalysisFailure::SourceShapeMismatch)?
                .source;
            if affected.contains(&target_file) {
                affected.insert(record.source.file);
            }
        }
        if before == affected.len() {
            break;
        }
    }
    Ok(HirRevisionDelta {
        direct_changes,
        affected_files: affected.into_iter().collect(),
    })
}

struct HirRevisionDelta {
    direct_changes: Vec<FileId>,
    affected_files: Vec<FileId>,
}

fn binding_module(binding: Option<&wrela_hir_lower::ResolvedBinding>) -> Option<ModuleId> {
    match binding? {
        wrela_hir_lower::ResolvedBinding::Declaration(declaration) => Some(declaration.module),
        wrela_hir_lower::ResolvedBinding::Variant(variant) => Some(variant.enumeration.module),
        wrela_hir_lower::ResolvedBinding::Module { module, .. } => Some(*module),
        wrela_hir_lower::ResolvedBinding::Local(_)
        | wrela_hir_lower::ResolvedBinding::Parameter(_)
        | wrela_hir_lower::ResolvedBinding::Generic(_)
        | wrela_hir_lower::ResolvedBinding::LocalRegion(_)
        | wrela_hir_lower::ResolvedBinding::Builtin(_) => None,
    }
}

struct ChangeMeter<'a> {
    used: u64,
    limit: u64,
    is_cancelled: &'a dyn Fn() -> bool,
}

impl<'a> ChangeMeter<'a> {
    fn new(limit: u64, is_cancelled: &'a dyn Fn() -> bool) -> Self {
        Self {
            used: 0,
            limit,
            is_cancelled,
        }
    }

    fn poll(&mut self) -> Result<(), IncrementalAnalysisFailure> {
        check_cancelled(self.is_cancelled)?;
        self.used = self
            .used
            .checked_add(1)
            .ok_or(IncrementalAnalysisFailure::ResourceLimit {
                resource: "incremental change comparisons",
                limit: self.limit,
            })?;
        if self.used > self.limit {
            return Err(IncrementalAnalysisFailure::ResourceLimit {
                resource: "incremental change comparisons",
                limit: self.limit,
            });
        }
        Ok(())
    }
}

fn check_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), IncrementalAnalysisFailure> {
    if is_cancelled() {
        Err(IncrementalAnalysisFailure::Cancelled)
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum IncrementalAnalysisFailure {
    Cancelled,
    InvalidLimits,
    StaleParsedInput,
    SourceShapeMismatch,
    RequestMismatch(&'static str),
    UnsupportedSessionVersion { observed: u32 },
    UnsupportedHirReuseVersion { observed: u32 },
    UnsupportedAnalysisReuseVersion { observed: u32 },
    CorruptSnapshot(&'static str),
    IncompleteAnalysis,
    ResourceLimit { resource: &'static str, limit: u64 },
    Hir(LowerFailure),
    Analysis(AnalysisFailure),
}

impl IncrementalAnalysisFailure {
    #[must_use]
    pub const fn is_cancelled(&self) -> bool {
        matches!(
            self,
            Self::Cancelled
                | Self::Hir(LowerFailure::Cancelled)
                | Self::Analysis(AnalysisFailure::Cancelled)
        )
    }
}

impl From<LowerFailure> for IncrementalAnalysisFailure {
    fn from(value: LowerFailure) -> Self {
        Self::Hir(value)
    }
}

impl From<AnalysisFailure> for IncrementalAnalysisFailure {
    fn from(value: AnalysisFailure) -> Self {
        Self::Analysis(value)
    }
}

impl fmt::Display for IncrementalAnalysisFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("incremental analysis was cancelled"),
            Self::InvalidLimits => formatter.write_str("invalid incremental analysis limits"),
            Self::StaleParsedInput => {
                formatter.write_str("parsed files do not match current source revisions")
            }
            Self::SourceShapeMismatch => {
                formatter.write_str("incremental source identity shape changed")
            }
            Self::RequestMismatch(detail) | Self::CorruptSnapshot(detail) => {
                formatter.write_str(detail)
            }
            Self::UnsupportedSessionVersion { observed } => {
                write!(
                    formatter,
                    "unsupported incremental session version {observed}"
                )
            }
            Self::UnsupportedHirReuseVersion { observed } => {
                write!(formatter, "unsupported HIR reuse version {observed}")
            }
            Self::UnsupportedAnalysisReuseVersion { observed } => {
                write!(formatter, "unsupported analysis reuse version {observed}")
            }
            Self::IncompleteAnalysis => {
                formatter.write_str("semantic analysis did not seal a complete image")
            }
            Self::ResourceLimit { resource, limit } => {
                write!(
                    formatter,
                    "incremental analysis exceeded {resource} limit {limit}"
                )
            }
            Self::Hir(error) => error.fmt(formatter),
            Self::Analysis(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for IncrementalAnalysisFailure {}
