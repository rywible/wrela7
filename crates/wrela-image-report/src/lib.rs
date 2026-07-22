//! Backend-neutral, versioned image-report schema and deterministic rendering.

#![forbid(unsafe_code)]

use std::{cmp::Ordering, fmt};

use wrela_build_model::{BuildIdentity, Sha256Digest, TargetIdentity};

mod decode;

pub use decode::decode_image_report_json;

/// Current machine-readable report schema.
///
/// Version 12 added whole-image region inference facts (`RegionAssignmentFact`
/// and `PromotionFact`) to the sealed analysis section. Version 13 makes their
/// allocation identities, final-region join, and bounded proof join exact.
/// Version 14 introduced the machine-representation version binding. Version 15
/// retains the authenticated FlowWir scheduler ownership partition. Version 16
/// adds the exact all-or-empty actor placement input set and binds reports to
/// the current MachineWir v21 contract. Version 17 adds exact
/// source-authenticated iso-pool/brand/region contracts. Version 18 adds the
/// exact all-or-empty completed-activation task-frame reset contract
/// (`ActivationFrameResetFact`). The decoder gates on this exact value, so
/// every older representation is rejected as
/// [`ReportError::UnsupportedSchema`].
pub const REPORT_SCHEMA_VERSION: u32 = 18;

const CURRENT_SEMANTIC_WIR_VERSION: u32 = 15;
const CURRENT_FLOW_WIR_VERSION: u32 = 19;
const CURRENT_FLOW_WIR_WIRE_VERSION: u32 = 19;
const CURRENT_MACHINE_WIR_VERSION: u32 = 21;
const CURRENT_RUNTIME_ABI_VERSION: u32 = 2;

/// One finite capacity or memory fact established by the build.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BoundFact {
    pub category: String,
    pub owner: String,
    pub source: String,
    pub amount: u64,
    pub unit: String,
}

/// One proof result or required recovery path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProofFact {
    /// Dense `FlowWir` proof ID retained so optimization decisions can refer to
    /// the exact proof they consumed.
    pub id: u32,
    pub category: String,
    pub subject: String,
    pub result: String,
    /// Exact finite bound retained from the producer proof, when that proof
    /// establishes a scalar capacity or work ceiling.
    pub bound: Option<u64>,
    /// Canonical source identities retained from the producer proof.
    pub sources: Vec<String>,
    /// Canonical, backward-only proof dependencies retained by dense ID.
    pub depends_on: Vec<u32>,
    pub why_chain: Vec<String>,
}

/// Physical lowering selected for one logical actor edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ActorLoweringKind {
    Queued,
    DirectDispatch,
    TailForwarded,
    Fused,
}

impl ActorLoweringKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::DirectDispatch => "direct-dispatch",
            Self::TailForwarded => "tail-forwarded",
            Self::Fused => "fused",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ActorLoweringFact {
    pub source: String,
    pub destination: String,
    pub message: String,
    pub kind: ActorLoweringKind,
    pub logical_slots: u64,
    pub physical_bytes: u64,
}

/// One logical node produced by compile-time image construction.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ImageNodeFact {
    pub kind: String,
    pub name: String,
    pub owner: String,
    pub source: String,
    pub static_bytes: u64,
}

/// Exact FlowWir capacity proof consumed by one reportable region node.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RegionCapacityEvidenceFact {
    pub region: String,
    pub capacity_proof: u32,
}

/// Exact source-authenticated contract for one generative iso pool.
///
/// This is static image evidence only. It does not claim that pool allocation,
/// transfer, or reclamation has been lowered into the runtime.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct IsoPoolFact {
    pub pool: String,
    pub brand: String,
    pub region: String,
    pub payload_type: String,
    pub owner: String,
    pub source: String,
    pub brand_source: String,
    pub slots_source: String,
    pub maximum_payload_source: String,
    pub payload_source: String,
    pub slots: u64,
    pub maximum_payload_bytes: u64,
    pub payload_bytes: u64,
    pub alignment: u32,
    pub capacity_proof: u32,
}

/// Closed cancellation behavior retained for one statically admitted async
/// helper activation frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ActivationCancellationFact {
    DropCalleeThenPropagate,
}

impl ActivationCancellationFact {
    const fn as_str(self) -> &'static str {
        match self {
            Self::DropCalleeThenPropagate => "drop-callee-then-propagate",
        }
    }
}

/// Exact `ActivationPlan` evidence for one reportable suspended helper frame.
/// `plan` is dense in canonical order and `region` joins this record to both
/// an activation image node and its exact capacity-proof evidence.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ActivationFrameEvidenceFact {
    pub plan: u32,
    pub region: String,
    pub caller: String,
    pub callee: String,
    pub owner: String,
    pub source: String,
    pub frame_bytes: u64,
    pub maximum_live: u32,
    pub cancellation: ActivationCancellationFact,
    pub capacity_proof: u32,
}

/// Exact evidence that one completed immediate activation's task-frame region
/// is reset at the await that completed it (ch03 §6.2).
///
/// `plan` joins this record to exactly the [`ActivationFrameEvidenceFact`] with
/// the same dense `ActivationPlan` ID, so the caller/callee/cancellation of the
/// await that this reset follows is read from that record rather than repeated
/// here. Everything retained here is the region contract the reset re-establishes:
/// the inferred [`RegionClass`], the owning task, the exact capacity and
/// alignment, and the dense capacity proof plus the finite bound that proof
/// establishes.
///
/// This is static image evidence that the reset is emitted and bounded. It does
/// not claim that any wider region-reset, arena, or promotion runtime exists.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ActivationFrameResetFact {
    pub plan: u32,
    pub region: String,
    pub owner: String,
    pub source: String,
    pub region_class: RegionClass,
    pub capacity_bytes: u64,
    pub alignment: u64,
    pub capacity_proof: u32,
    pub capacity_bound: u64,
}

/// Region class one allocation is assigned by whole-image region inference.
///
/// These are the classes of `docs/language/03-values-views-regions.md` §6: the
/// image region (§6.1), the task-frame region (§6.2), the call region (§6.3),
/// the request region (§6.4), an `iso`/pool region (§6.5), and immutable baked
/// static data (§6.1). Every allocation is assigned exactly one class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RegionClass {
    Image,
    TaskFrame,
    Call,
    Request,
    Pool,
    Static,
}

impl RegionClass {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Image => "image",
            Self::TaskFrame => "task-frame",
            Self::Call => "call",
            Self::Request => "request",
            Self::Pool => "pool",
            Self::Static => "static",
        }
    }
}

/// One allocation's inferred region assignment (ch03 §7 region inference).
///
/// Records the allocation identity and the exact region class inference placed
/// it in. Allocation identities use the canonical producer form
/// `alloc:<dense-u32-id>:<nonempty-name>`. IDs are dense and unique across the
/// assignment vector. Stateful actor direct stores now fill this from sealed
/// whole-image escape analysis; images without a supported allocation producer
/// leave the vector empty.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RegionAssignmentFact {
    pub allocation: String,
    pub region_class: RegionClass,
}

/// One allocation promoted to a longer-lived region (ch03 §8 promotion and
/// budgets).
///
/// A promotion moves an allocation whose required lifetime cannot be kept local
/// into a wider region, and only when doing so stays statically bounded. This
/// retains what §8 requires a promotion to record: the promoted allocation, the
/// region it was promoted from, the region it was promoted into, the
/// human-readable reason (the why-chain summary), and an authenticated dense
/// `FlowWir` proof ID establishing the promotion is bounded. Like
/// [`RegionAssignmentFact`], the supported actor-state producer authenticates
/// these rows against the exact semantic value, source/destination regions,
/// and `RegionBound` proof.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PromotionFact {
    pub allocation: String,
    pub source_region: RegionClass,
    pub destination_region: RegionClass,
    pub reason: String,
    pub proof: u32,
}

/// One logical scheduling, request, supervision, or hardware edge.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ImageEdgeFact {
    pub kind: String,
    pub source: String,
    pub destination: String,
    pub capacity: Option<u64>,
    pub priority: Option<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct WorkFact {
    pub function: String,
    pub stack_bytes: u64,
    pub frame_bytes: u64,
    pub uninterrupted_work: Option<u64>,
    pub checkpoint_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct HardwareFact {
    pub device: String,
    pub binding: String,
    pub owner: String,
    pub dma_policy: String,
    pub queue_capacity: Option<u64>,
    pub maximum_in_flight: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RecoveryFact {
    pub subject: String,
    pub supervisor: String,
    pub reset_timeout_ns: u64,
    pub quarantine_bytes: u64,
    pub cleanup_path: Vec<String>,
}

/// Exact actor/task ownership assigned to one cooperative scheduler core.
///
/// This is evidence copied from validated FlowWir. It does not imply that a
/// runtime scheduler or inferred multi-core placement has been emitted.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SchedulerOwnershipFact {
    pub core: u32,
    pub actors: Vec<String>,
    pub tasks: Vec<String>,
}

/// Exact actor-local inputs available before placement can be proposed.
///
/// `reserved_region_bytes` is deliberately narrower than the normative total
/// reserved-byte input: it is the checked sum of sealed actor-owned FlowWir
/// regions. Pool bytes and other actor-owned image bytes need separately
/// authenticated producers before this record may become a placement proposal.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ActorPlacementInputFact {
    pub actor: String,
    pub maximum_uninterrupted_work: u64,
    pub reserved_region_bytes: u64,
}

/// Frontend and WIR facts independent of final object bytes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AnalysisFacts {
    pub reachable_declarations: u64,
    pub monomorphized_instantiations: u64,
    pub resolved_interface_calls: u64,
    pub bounds: Vec<BoundFact>,
    pub proofs: Vec<ProofFact>,
    pub actor_lowerings: Vec<ActorLoweringFact>,
    pub image_nodes: Vec<ImageNodeFact>,
    pub region_capacity_evidence: Vec<RegionCapacityEvidenceFact>,
    /// Exact pool/brand/region joins for pool-only images. Empty until a
    /// source-authenticated iso-pool producer is present.
    pub iso_pools: Vec<IsoPoolFact>,
    pub activation_frame_evidence: Vec<ActivationFrameEvidenceFact>,
    /// Exact task-frame region resets emitted at a completed await. Empty
    /// unless the image matches the exact admitted completed-activation
    /// profile; never a partial or approximate region account.
    pub activation_frame_resets: Vec<ActivationFrameResetFact>,
    /// Inferred region class per reportable allocation (ch03 §7). Empty for
    /// images without a supported whole-image allocation producer.
    pub region_assignments: Vec<RegionAssignmentFact>,
    /// Reported region promotions (ch03 §8). Empty when no value escapes its
    /// inferred source lifetime.
    pub promotions: Vec<PromotionFact>,
    pub image_edges: Vec<ImageEdgeFact>,
    pub work: Vec<WorkFact>,
    pub hardware: Vec<HardwareFact>,
    pub recovery: Vec<RecoveryFact>,
    pub actor_placement_inputs: Vec<ActorPlacementInputFact>,
    pub scheduler_ownership: Vec<SchedulerOwnershipFact>,
    /// Exact test-plan group compiled into this image. This remains absent for
    /// ordinary builds and is copied, never inferred, by both report producers.
    pub compiled_test_group: Option<wrela_test_model::FullImageTestGroup>,
    pub startup_order: Vec<String>,
    pub shutdown_order: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalysisFactLimits {
    pub items: u64,
    pub proof_edges: u64,
    pub payload_bytes: u64,
}

#[derive(Clone, Copy)]
pub struct AnalysisFactRequest<'a> {
    pub build: &'a BuildIdentity,
    pub image_name: &'a str,
    pub limits: AnalysisFactLimits,
}

impl AnalysisFactLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            items: 64_000_000,
            proof_edges: 256_000_000,
            payload_bytes: 1024 * 1024 * 1024,
        }
    }

    /// Validates that every analysis-report resource ceiling is nonzero.
    ///
    /// # Errors
    ///
    /// Returns [`ReportError::InvalidLimits`] when any ceiling is zero.
    pub const fn validate(self) -> Result<(), ReportError> {
        if self.items == 0 || self.proof_edges == 0 || self.payload_bytes == 0 {
            Err(ReportError::InvalidLimits)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedAnalysisFacts {
    build: BuildIdentity,
    image_name: String,
    facts: AnalysisFacts,
    limits: AnalysisFactLimits,
}

impl ValidatedAnalysisFacts {
    #[must_use]
    pub const fn build(&self) -> &BuildIdentity {
        &self.build
    }

    #[must_use]
    pub fn image_name(&self) -> &str {
        &self.image_name
    }

    #[must_use]
    pub const fn as_facts(&self) -> &AnalysisFacts {
        &self.facts
    }

    #[must_use]
    pub const fn limits(&self) -> AnalysisFactLimits {
        self.limits
    }

    #[must_use]
    pub fn into_facts(self) -> AnalysisFacts {
        self.facts
    }
}

/// Measures, canonicalizes, validates, and binds frontend facts to one build.
///
/// # Errors
///
/// Returns a [`ReportError`] when cancellation is requested, a declared
/// resource ceiling is exceeded, identity binding fails, or any fact is
/// invalid or noncanonical after deterministic ordering.
pub fn seal_analysis_facts(
    request: AnalysisFactRequest<'_>,
    mut facts: AnalysisFacts,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ValidatedAnalysisFacts, ReportError> {
    if is_cancelled() {
        return Err(ReportError::Cancelled);
    }
    request.limits.validate()?;
    let (items, proof_edges, payload_bytes, _) =
        measure_analysis(&facts, request.image_name, request.limits, is_cancelled)?;
    enforce_analysis_limits(request.limits, items, proof_edges, payload_bytes)?;
    if !valid_build_identity(request.build) {
        return Err(ReportError::IdentityMismatch);
    }
    if !nonempty(request.image_name, is_cancelled)? {
        return Err(ReportError::InvalidScalar);
    }
    if let Some(group) = &facts.compiled_test_group {
        let root_name = match &group.root {
            wrela_test_model::ImageRoot::GeneratedHarness { harness_name } => harness_name,
            wrela_test_model::ImageRoot::Declared { image_name, .. } => image_name,
        };
        if !text_equal(root_name, request.image_name, is_cancelled)? {
            return Err(ReportError::IdentityMismatch);
        }
    }
    canonicalize_analysis(&mut facts, is_cancelled)?;
    validate_analysis(&facts, is_cancelled)?;
    if is_cancelled() {
        return Err(ReportError::Cancelled);
    }
    Ok(ValidatedAnalysisFacts {
        build: copy_build_identity(request.build)?,
        image_name: copy_string(
            request.image_name,
            "analysis fact payload",
            request.limits.payload_bytes,
        )?,
        facts,
        limits: request.limits,
    })
}

/// One final emitted section measurement.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SectionFact {
    pub name: String,
    pub owner: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SymbolFact {
    pub name: String,
    pub section: String,
    pub offset: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepresentationFacts {
    pub semantic_wir_version: u32,
    pub flow_wir_version: u32,
    pub flow_wir_wire_version: u32,
    pub machine_wir_version: u32,
    pub runtime_abi_version: u32,
    pub optimization_pipeline_name: String,
    pub optimization_pipeline_revision: u32,
    pub optimization_pipeline_implementation: Sha256Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OptimizationAction {
    Removed,
    Folded,
    Inlined,
    Coalesced,
    Reordered,
    Retained,
}

impl OptimizationAction {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Removed => "removed",
            Self::Folded => "folded",
            Self::Inlined => "inlined",
            Self::Coalesced => "coalesced",
            Self::Reordered => "reordered",
            Self::Retained => "retained",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct OptimizationDecisionFact {
    pub pass: String,
    pub subject: String,
    pub action: OptimizationAction,
    pub justification: String,
    /// Sorted, unique `FlowWir` proof IDs.
    pub relied_on: Vec<u32>,
}

/// Backend facts available only after layout and linking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendFacts {
    /// Digest of the exact canonical `FlowWir` frame independently validated by
    /// the backend. Together with `image_name`, this distinguishes artifacts
    /// emitted from the same source/build request.
    pub flow_wir_digest: Sha256Digest,
    pub artifact_bytes: u64,
    pub artifact_digest: Sha256Digest,
    /// Exact PE base-relocation directory extent retained from the sealed
    /// linked-image inspection.
    pub relocation_directory_bytes: u64,
    /// Number of canonical PE base-relocation blocks in that directory.
    pub base_relocation_blocks: u32,
    /// Number of decoded AArch64 `DIR64` relocation entries. Individual rows
    /// are not retained by this report schema.
    pub base_relocation_dir64_count: u32,
    /// Domain-separated digest binding the image, validated path-independent
    /// LLD contribution layout, and sealed COFF relocation provenance used by
    /// linked-image inspection.
    pub base_relocation_provenance_digest: Sha256Digest,
    pub sections: Vec<SectionFact>,
    pub symbols: Vec<SymbolFact>,
    pub representations: RepresentationFacts,
    pub required_runtime_intrinsics: Vec<String>,
    pub target_variable_reservations: Vec<BoundFact>,
    pub excluded_target_variables: Vec<String>,
    pub optimization_decisions: Vec<OptimizationDecisionFact>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendFactLimits {
    pub items: u64,
    pub optimization_proof_edges: u64,
    pub payload_bytes: u64,
}

impl BackendFactLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            items: 64_000_000,
            optimization_proof_edges: 256_000_000,
            payload_bytes: 1024 * 1024 * 1024,
        }
    }

    /// Validates that every backend-report resource ceiling is nonzero.
    ///
    /// # Errors
    ///
    /// Returns [`ReportError::InvalidLimits`] when any ceiling is zero.
    pub const fn validate(self) -> Result<(), ReportError> {
        if self.items == 0 || self.optimization_proof_edges == 0 || self.payload_bytes == 0 {
            Err(ReportError::InvalidLimits)
        } else {
            Ok(())
        }
    }
}

/// Complete report bound to exactly the same inputs as WIR.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageReport {
    schema: u32,
    build: BuildIdentity,
    image_name: String,
    analysis: AnalysisFacts,
    analysis_limits: AnalysisFactLimits,
    backend: BackendFacts,
    backend_limits: BackendFactLimits,
}

impl ImageReport {
    /// Joins validated analysis facts to exact backend measurements.
    ///
    /// # Errors
    ///
    /// Returns a [`ReportError`] when cancellation is requested, identities do
    /// not match, a backend resource ceiling is exceeded, or backend facts and
    /// measurements are invalid or noncanonical.
    pub fn new(
        build: BuildIdentity,
        image_name: String,
        analysis: ValidatedAnalysisFacts,
        mut backend: BackendFacts,
        backend_limits: BackendFactLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, ReportError> {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        backend_limits.validate()?;
        if analysis.build() != &build
            || !text_equal(analysis.image_name(), &image_name, is_cancelled)?
        {
            return Err(ReportError::IdentityMismatch);
        }
        let analysis_limits = analysis.limits();
        let analysis = analysis.into_facts();
        let (items, optimization_proof_edges, payload_bytes, _) =
            measure_backend(&backend, backend_limits, is_cancelled)?;
        enforce_backend_limits(
            backend_limits,
            items,
            optimization_proof_edges,
            payload_bytes,
        )?;
        canonicalize_backend(&mut backend, is_cancelled)?;
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        validate_backend(&analysis, &backend, is_cancelled)?;
        let report = Self {
            schema: REPORT_SCHEMA_VERSION,
            build,
            image_name,
            analysis,
            analysis_limits,
            backend,
            backend_limits,
        };
        report.validate_with_cancellation(is_cancelled)?;
        Ok(report)
    }

    #[must_use]
    pub const fn schema(&self) -> u32 {
        self.schema
    }

    #[must_use]
    pub const fn build(&self) -> &BuildIdentity {
        &self.build
    }

    #[must_use]
    pub fn image_name(&self) -> &str {
        &self.image_name
    }

    #[must_use]
    pub const fn analysis(&self) -> &AnalysisFacts {
        &self.analysis
    }

    #[must_use]
    pub const fn analysis_limits(&self) -> AnalysisFactLimits {
        self.analysis_limits
    }

    #[must_use]
    pub const fn backend(&self) -> &BackendFacts {
        &self.backend
    }

    #[must_use]
    pub const fn backend_limits(&self) -> BackendFactLimits {
        self.backend_limits
    }

    /// Revalidates the complete report without cancellation.
    ///
    /// # Errors
    ///
    /// Returns a [`ReportError`] for schema, identity, resource, ordering,
    /// representation, fact, digest, or extent violations.
    pub fn validate(&self) -> Result<(), ReportError> {
        self.validate_with_cancellation(&|| false)
    }

    /// Revalidates the complete report while observing cancellation.
    ///
    /// # Errors
    ///
    /// Returns [`ReportError::Cancelled`] when requested, or another
    /// [`ReportError`] for schema, resource, ordering, fact, digest, or extent
    /// violations.
    pub fn validate_with_cancellation(
        &self,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), ReportError> {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        if self.schema != REPORT_SCHEMA_VERSION {
            return Err(ReportError::UnsupportedSchema(self.schema));
        }
        self.analysis_limits.validate()?;
        self.backend_limits.validate()?;
        let (analysis_items, analysis_edges, analysis_payload, _) = measure_analysis(
            &self.analysis,
            &self.image_name,
            self.analysis_limits,
            is_cancelled,
        )?;
        enforce_analysis_limits(
            self.analysis_limits,
            analysis_items,
            analysis_edges,
            analysis_payload,
        )?;
        let (backend_items, backend_edges, backend_payload, _) =
            measure_backend(&self.backend, self.backend_limits, is_cancelled)?;
        enforce_backend_limits(
            self.backend_limits,
            backend_items,
            backend_edges,
            backend_payload,
        )?;
        if !valid_build_identity(&self.build) {
            return Err(ReportError::IdentityMismatch);
        }
        if !nonempty(&self.image_name, is_cancelled)? || self.backend.artifact_bytes == 0 {
            return Err(ReportError::InvalidScalar);
        }
        if digest_is_zero(self.backend.flow_wir_digest)
            || digest_is_zero(self.backend.artifact_digest)
        {
            return Err(ReportError::InvalidMeasurement);
        }
        let versions = &self.backend.representations;
        if versions.semantic_wir_version != CURRENT_SEMANTIC_WIR_VERSION
            || versions.flow_wir_version != CURRENT_FLOW_WIR_VERSION
            || versions.flow_wir_wire_version != CURRENT_FLOW_WIR_WIRE_VERSION
            || versions.machine_wir_version != CURRENT_MACHINE_WIR_VERSION
            || versions.runtime_abi_version != CURRENT_RUNTIME_ABI_VERSION
            || !nonempty(&versions.optimization_pipeline_name, is_cancelled)?
            || versions.optimization_pipeline_revision == 0
            || versions
                .optimization_pipeline_implementation
                .as_bytes()
                .iter()
                .all(|byte| *byte == 0)
        {
            return Err(ReportError::InvalidRepresentations);
        }
        require_sorted_unique(
            "runtime intrinsics",
            &self.backend.required_runtime_intrinsics,
            is_cancelled,
        )?;
        require_sorted_unique(
            "excluded target variables",
            &self.backend.excluded_target_variables,
            is_cancelled,
        )?;
        validate_analysis(&self.analysis, is_cancelled)?;
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        validate_backend(&self.analysis, &self.backend, is_cancelled)?;
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        Ok(())
    }

    /// Stable readable summary for the CLI.
    ///
    /// # Panics
    ///
    /// Panics only if the summary cannot fit its fallibly measured allocation.
    /// Call [`Self::render_summary_with_cancellation`] to handle that resource
    /// error explicitly.
    #[must_use]
    pub fn render_summary(&self) -> String {
        self.render_summary_with_cancellation(&|| false)
            .expect("a validated report summary must fit its measured allocation")
    }

    /// Renders the CLI summary using a measured, fallible allocation.
    ///
    /// # Errors
    ///
    /// Returns [`ReportError::Cancelled`] when requested,
    /// [`ReportError::MeasurementOverflow`] when size arithmetic overflows, or
    /// [`ReportError::ResourceLimit`] when allocation fails.
    pub fn render_summary_with_cancellation(
        &self,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<String, ReportError> {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        let capacity = 512usize
            .checked_add(self.image_name.len())
            .and_then(|value| value.checked_add(self.build.target.as_str().len()))
            .and_then(|value| value.checked_add(self.build.language.as_str().len()))
            .ok_or(ReportError::MeasurementOverflow)?;
        let mut output = String::new();
        output
            .try_reserve_exact(capacity)
            .map_err(|_| ReportError::ResourceLimit {
                resource: "image report summary allocation",
                limit: u64::try_from(capacity).unwrap_or(u64::MAX),
            })?;
        output.push_str("image ............................... ");
        push_text_cancellable(&mut output, &self.image_name, is_cancelled)?;
        output.push_str("\ntarget .............................. ");
        push_text_cancellable(&mut output, self.build.target.as_str(), is_cancelled)?;
        output.push_str("\nlanguage revision ................... ");
        push_text_cancellable(&mut output, self.build.language.as_str(), is_cancelled)?;
        output.push_str("\nreachable declarations .............. ");
        push_u64(&mut output, self.analysis.reachable_declarations);
        output.push_str("\nartifact bytes ...................... ");
        push_u64(&mut output, self.backend.artifact_bytes);
        output.push_str("\nartifact sha256 ..................... ");
        push_digest_hex(&mut output, self.backend.artifact_digest);
        output.push('\n');
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        Ok(output)
    }

    /// Canonical JSON with fixed field order and preserved fact order.
    ///
    /// # Panics
    ///
    /// Panics only if the already validated report cannot fit the fallibly
    /// measured encoding allocation. Call [`Self::to_json_with_cancellation`]
    /// to handle that resource error explicitly.
    #[must_use]
    pub fn to_json(&self) -> String {
        self.to_json_with_cancellation(&|| false)
            .expect("a validated canonical report must fit its measured encoding allocation")
    }

    /// Encodes canonical JSON using a measured, fallible allocation.
    ///
    /// # Errors
    ///
    /// Returns [`ReportError::Cancelled`] when requested,
    /// [`ReportError::MeasurementOverflow`] when encoded-size arithmetic
    /// overflows, or [`ReportError::ResourceLimit`] when allocation fails.
    #[allow(clippy::too_many_lines)]
    pub fn to_json_with_cancellation(
        &self,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<String, ReportError> {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        let capacity = encoded_capacity(self, is_cancelled)?;
        let mut output = String::new();
        output
            .try_reserve_exact(capacity)
            .map_err(|_| ReportError::ResourceLimit {
                resource: "encoded image report allocation",
                limit: u64::try_from(capacity).unwrap_or(u64::MAX),
            })?;
        output.push('{');
        json_number(&mut output, "schema", u64::from(self.schema), false);
        json_string(
            &mut output,
            "image_name",
            &self.image_name,
            true,
            is_cancelled,
        )?;
        json_string(
            &mut output,
            "language",
            self.build.language.as_str(),
            true,
            is_cancelled,
        )?;
        json_string(
            &mut output,
            "target",
            self.build.target.as_str(),
            true,
            is_cancelled,
        )?;
        json_digest(&mut output, "compiler_sha256", self.build.compiler, true);
        json_digest(
            &mut output,
            "target_package_sha256",
            self.build.target_package,
            true,
        );
        json_digest(
            &mut output,
            "standard_library_sha256",
            self.build.standard_library,
            true,
        );
        json_digest(
            &mut output,
            "source_graph_sha256",
            self.build.source_graph,
            true,
        );
        json_digest(&mut output, "request_sha256", self.build.request, true);
        json_digest(&mut output, "profile_sha256", self.build.profile, true);
        json_digest(
            &mut output,
            "flow_wir_sha256",
            self.backend.flow_wir_digest,
            true,
        );
        json_number(
            &mut output,
            "reachable_declarations",
            self.analysis.reachable_declarations,
            true,
        );
        json_number(
            &mut output,
            "monomorphized_instantiations",
            self.analysis.monomorphized_instantiations,
            true,
        );
        json_number(
            &mut output,
            "resolved_interface_calls",
            self.analysis.resolved_interface_calls,
            true,
        );
        json_number(
            &mut output,
            "artifact_bytes",
            self.backend.artifact_bytes,
            true,
        );
        json_digest(
            &mut output,
            "artifact_sha256",
            self.backend.artifact_digest,
            true,
        );
        json_number(
            &mut output,
            "relocation_directory_bytes",
            self.backend.relocation_directory_bytes,
            true,
        );
        json_number(
            &mut output,
            "base_relocation_blocks",
            u64::from(self.backend.base_relocation_blocks),
            true,
        );
        json_number(
            &mut output,
            "base_relocation_dir64_count",
            u64::from(self.backend.base_relocation_dir64_count),
            true,
        );
        json_digest(
            &mut output,
            "base_relocation_provenance_sha256",
            self.backend.base_relocation_provenance_digest,
            true,
        );
        output.push_str(",\"bounds\":[");
        for (index, fact) in self.analysis.bounds.iter().enumerate() {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            json_string(&mut output, "category", &fact.category, false, is_cancelled)?;
            json_string(&mut output, "owner", &fact.owner, true, is_cancelled)?;
            json_string(&mut output, "source", &fact.source, true, is_cancelled)?;
            json_number(&mut output, "amount", fact.amount, true);
            json_string(&mut output, "unit", &fact.unit, true, is_cancelled)?;
            output.push('}');
        }
        output.push_str("],\"actor_lowerings\":[");
        for (index, fact) in self.analysis.actor_lowerings.iter().enumerate() {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            json_string(&mut output, "source", &fact.source, false, is_cancelled)?;
            json_string(
                &mut output,
                "destination",
                &fact.destination,
                true,
                is_cancelled,
            )?;
            json_string(&mut output, "message", &fact.message, true, is_cancelled)?;
            json_string(&mut output, "kind", fact.kind.as_str(), true, is_cancelled)?;
            json_number(&mut output, "logical_slots", fact.logical_slots, true);
            json_number(&mut output, "physical_bytes", fact.physical_bytes, true);
            output.push('}');
        }
        output.push_str("],\"image_nodes\":[");
        for (index, fact) in self.analysis.image_nodes.iter().enumerate() {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            json_string(&mut output, "kind", &fact.kind, false, is_cancelled)?;
            json_string(&mut output, "name", &fact.name, true, is_cancelled)?;
            json_string(&mut output, "owner", &fact.owner, true, is_cancelled)?;
            json_string(&mut output, "source", &fact.source, true, is_cancelled)?;
            json_number(&mut output, "static_bytes", fact.static_bytes, true);
            output.push('}');
        }
        output.push_str("],\"iso_pools\":[");
        for (index, fact) in self.analysis.iso_pools.iter().enumerate() {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            json_string(&mut output, "pool", &fact.pool, false, is_cancelled)?;
            json_string(&mut output, "brand", &fact.brand, true, is_cancelled)?;
            json_string(&mut output, "region", &fact.region, true, is_cancelled)?;
            json_string(
                &mut output,
                "payload_type",
                &fact.payload_type,
                true,
                is_cancelled,
            )?;
            json_string(&mut output, "owner", &fact.owner, true, is_cancelled)?;
            json_string(&mut output, "source", &fact.source, true, is_cancelled)?;
            json_string(
                &mut output,
                "brand_source",
                &fact.brand_source,
                true,
                is_cancelled,
            )?;
            json_string(
                &mut output,
                "slots_source",
                &fact.slots_source,
                true,
                is_cancelled,
            )?;
            json_string(
                &mut output,
                "maximum_payload_source",
                &fact.maximum_payload_source,
                true,
                is_cancelled,
            )?;
            json_string(
                &mut output,
                "payload_source",
                &fact.payload_source,
                true,
                is_cancelled,
            )?;
            json_number(&mut output, "slots", fact.slots, true);
            json_number(
                &mut output,
                "maximum_payload_bytes",
                fact.maximum_payload_bytes,
                true,
            );
            json_number(&mut output, "payload_bytes", fact.payload_bytes, true);
            json_number(&mut output, "alignment", u64::from(fact.alignment), true);
            json_number(
                &mut output,
                "capacity_proof",
                u64::from(fact.capacity_proof),
                true,
            );
            output.push('}');
        }
        output.push_str("],\"region_capacity_evidence\":[");
        for (index, fact) in self.analysis.region_capacity_evidence.iter().enumerate() {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            json_string(&mut output, "region", &fact.region, false, is_cancelled)?;
            json_number(
                &mut output,
                "capacity_proof",
                u64::from(fact.capacity_proof),
                true,
            );
            output.push('}');
        }
        output.push_str("],\"activation_frame_evidence\":[");
        for (index, fact) in self.analysis.activation_frame_evidence.iter().enumerate() {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            json_number(&mut output, "plan", u64::from(fact.plan), false);
            json_string(&mut output, "region", &fact.region, true, is_cancelled)?;
            json_string(&mut output, "caller", &fact.caller, true, is_cancelled)?;
            json_string(&mut output, "callee", &fact.callee, true, is_cancelled)?;
            json_string(&mut output, "owner", &fact.owner, true, is_cancelled)?;
            json_string(&mut output, "source", &fact.source, true, is_cancelled)?;
            json_number(&mut output, "frame_bytes", fact.frame_bytes, true);
            json_number(
                &mut output,
                "maximum_live",
                u64::from(fact.maximum_live),
                true,
            );
            json_string(
                &mut output,
                "cancellation",
                fact.cancellation.as_str(),
                true,
                is_cancelled,
            )?;
            json_number(
                &mut output,
                "capacity_proof",
                u64::from(fact.capacity_proof),
                true,
            );
            output.push('}');
        }
        output.push_str("],\"activation_frame_resets\":[");
        for (index, fact) in self.analysis.activation_frame_resets.iter().enumerate() {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            json_number(&mut output, "plan", u64::from(fact.plan), false);
            json_string(&mut output, "region", &fact.region, true, is_cancelled)?;
            json_string(&mut output, "owner", &fact.owner, true, is_cancelled)?;
            json_string(&mut output, "source", &fact.source, true, is_cancelled)?;
            json_string(
                &mut output,
                "region_class",
                fact.region_class.as_str(),
                true,
                is_cancelled,
            )?;
            json_number(&mut output, "capacity_bytes", fact.capacity_bytes, true);
            json_number(&mut output, "alignment", fact.alignment, true);
            json_number(
                &mut output,
                "capacity_proof",
                u64::from(fact.capacity_proof),
                true,
            );
            json_number(&mut output, "capacity_bound", fact.capacity_bound, true);
            output.push('}');
        }
        output.push_str("],\"image_edges\":[");
        for (index, fact) in self.analysis.image_edges.iter().enumerate() {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            json_string(&mut output, "kind", &fact.kind, false, is_cancelled)?;
            json_string(&mut output, "source", &fact.source, true, is_cancelled)?;
            json_string(
                &mut output,
                "destination",
                &fact.destination,
                true,
                is_cancelled,
            )?;
            json_optional_number(&mut output, "capacity", fact.capacity, true);
            json_optional_number(&mut output, "priority", fact.priority.map(u64::from), true);
            output.push('}');
        }
        output.push_str("],\"work\":[");
        for (index, fact) in self.analysis.work.iter().enumerate() {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            json_string(&mut output, "function", &fact.function, false, is_cancelled)?;
            json_number(&mut output, "stack_bytes", fact.stack_bytes, true);
            json_number(&mut output, "frame_bytes", fact.frame_bytes, true);
            json_optional_number(
                &mut output,
                "uninterrupted_work",
                fact.uninterrupted_work,
                true,
            );
            json_number(&mut output, "checkpoint_count", fact.checkpoint_count, true);
            output.push('}');
        }
        output.push_str("],\"hardware\":[");
        for (index, fact) in self.analysis.hardware.iter().enumerate() {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            json_string(&mut output, "device", &fact.device, false, is_cancelled)?;
            json_string(&mut output, "binding", &fact.binding, true, is_cancelled)?;
            json_string(&mut output, "owner", &fact.owner, true, is_cancelled)?;
            json_string(
                &mut output,
                "dma_policy",
                &fact.dma_policy,
                true,
                is_cancelled,
            )?;
            json_optional_number(&mut output, "queue_capacity", fact.queue_capacity, true);
            json_optional_number(
                &mut output,
                "maximum_in_flight",
                fact.maximum_in_flight,
                true,
            );
            output.push('}');
        }
        output.push_str("],\"recovery\":[");
        for (index, fact) in self.analysis.recovery.iter().enumerate() {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            json_string(&mut output, "subject", &fact.subject, false, is_cancelled)?;
            json_string(
                &mut output,
                "supervisor",
                &fact.supervisor,
                true,
                is_cancelled,
            )?;
            json_number(&mut output, "reset_timeout_ns", fact.reset_timeout_ns, true);
            json_number(&mut output, "quarantine_bytes", fact.quarantine_bytes, true);
            output.push_str(",\"cleanup_path\":");
            json_string_array(&mut output, &fact.cleanup_path, is_cancelled)?;
            output.push('}');
        }
        output.push_str("],\"scheduler_ownership\":[");
        for (index, fact) in self.analysis.scheduler_ownership.iter().enumerate() {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            json_number(&mut output, "core", u64::from(fact.core), false);
            output.push_str(",\"actors\":");
            json_string_array(&mut output, &fact.actors, is_cancelled)?;
            output.push_str(",\"tasks\":");
            json_string_array(&mut output, &fact.tasks, is_cancelled)?;
            output.push('}');
        }
        output.push_str("],\"actor_placement_inputs\":[");
        for (index, fact) in self.analysis.actor_placement_inputs.iter().enumerate() {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            json_string(&mut output, "actor", &fact.actor, false, is_cancelled)?;
            json_number(
                &mut output,
                "maximum_uninterrupted_work",
                fact.maximum_uninterrupted_work,
                true,
            );
            json_number(
                &mut output,
                "reserved_region_bytes",
                fact.reserved_region_bytes,
                true,
            );
            output.push('}');
        }
        output.push_str("],\"compiled_test_group\":");
        json_compiled_test_group(
            &mut output,
            self.analysis.compiled_test_group.as_ref(),
            is_cancelled,
        )?;
        output.push_str(",\"startup_order\":");
        json_string_array(&mut output, &self.analysis.startup_order, is_cancelled)?;
        output.push_str(",\"shutdown_order\":");
        json_string_array(&mut output, &self.analysis.shutdown_order, is_cancelled)?;
        output.push_str(",\"proofs\":[");
        for (index, fact) in self.analysis.proofs.iter().enumerate() {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            json_number(&mut output, "id", u64::from(fact.id), false);
            json_string(&mut output, "category", &fact.category, true, is_cancelled)?;
            json_string(&mut output, "subject", &fact.subject, true, is_cancelled)?;
            json_string(&mut output, "result", &fact.result, true, is_cancelled)?;
            json_optional_number(&mut output, "bound", fact.bound, true);
            output.push_str(",\"sources\":");
            json_string_array(&mut output, &fact.sources, is_cancelled)?;
            output.push_str(",\"depends_on\":");
            json_u32_array(&mut output, &fact.depends_on, is_cancelled)?;
            output.push_str(",\"why_chain\":");
            json_string_array(&mut output, &fact.why_chain, is_cancelled)?;
            output.push('}');
        }
        output.push_str("],\"region_assignments\":[");
        for (index, fact) in self.analysis.region_assignments.iter().enumerate() {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            json_string(
                &mut output,
                "allocation",
                &fact.allocation,
                false,
                is_cancelled,
            )?;
            json_string(
                &mut output,
                "region_class",
                fact.region_class.as_str(),
                true,
                is_cancelled,
            )?;
            output.push('}');
        }
        output.push_str("],\"promotions\":[");
        for (index, fact) in self.analysis.promotions.iter().enumerate() {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            json_string(
                &mut output,
                "allocation",
                &fact.allocation,
                false,
                is_cancelled,
            )?;
            json_string(
                &mut output,
                "source_region",
                fact.source_region.as_str(),
                true,
                is_cancelled,
            )?;
            json_string(
                &mut output,
                "destination_region",
                fact.destination_region.as_str(),
                true,
                is_cancelled,
            )?;
            json_string(&mut output, "reason", &fact.reason, true, is_cancelled)?;
            json_number(&mut output, "proof", u64::from(fact.proof), true);
            output.push('}');
        }
        output.push_str("],\"sections\":[");
        for (index, fact) in self.backend.sections.iter().enumerate() {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            json_string(&mut output, "name", &fact.name, false, is_cancelled)?;
            json_string(&mut output, "owner", &fact.owner, true, is_cancelled)?;
            json_number(&mut output, "bytes", fact.bytes, true);
            output.push('}');
        }
        output.push_str("],\"symbols\":[");
        for (index, fact) in self.backend.symbols.iter().enumerate() {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            json_string(&mut output, "name", &fact.name, false, is_cancelled)?;
            json_string(&mut output, "section", &fact.section, true, is_cancelled)?;
            json_number(&mut output, "offset", fact.offset, true);
            json_number(&mut output, "bytes", fact.bytes, true);
            output.push('}');
        }
        output.push_str("],\"representations\":{");
        json_number(
            &mut output,
            "semantic_wir_version",
            u64::from(self.backend.representations.semantic_wir_version),
            false,
        );
        json_number(
            &mut output,
            "flow_wir_version",
            u64::from(self.backend.representations.flow_wir_version),
            true,
        );
        json_number(
            &mut output,
            "flow_wir_wire_version",
            u64::from(self.backend.representations.flow_wir_wire_version),
            true,
        );
        json_number(
            &mut output,
            "machine_wir_version",
            u64::from(self.backend.representations.machine_wir_version),
            true,
        );
        json_number(
            &mut output,
            "runtime_abi_version",
            u64::from(self.backend.representations.runtime_abi_version),
            true,
        );
        json_string(
            &mut output,
            "optimization_pipeline_name",
            &self.backend.representations.optimization_pipeline_name,
            true,
            is_cancelled,
        )?;
        json_number(
            &mut output,
            "optimization_pipeline_revision",
            u64::from(self.backend.representations.optimization_pipeline_revision),
            true,
        );
        json_digest(
            &mut output,
            "optimization_pipeline_implementation_sha256",
            self.backend
                .representations
                .optimization_pipeline_implementation,
            true,
        );
        output.push('}');
        output.push_str(",\"required_runtime_intrinsics\":");
        json_string_array(
            &mut output,
            &self.backend.required_runtime_intrinsics,
            is_cancelled,
        )?;
        output.push_str(",\"target_variable_reservations\":[");
        for (index, fact) in self.backend.target_variable_reservations.iter().enumerate() {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            json_string(&mut output, "category", &fact.category, false, is_cancelled)?;
            json_string(&mut output, "owner", &fact.owner, true, is_cancelled)?;
            json_string(&mut output, "source", &fact.source, true, is_cancelled)?;
            json_number(&mut output, "amount", fact.amount, true);
            json_string(&mut output, "unit", &fact.unit, true, is_cancelled)?;
            output.push('}');
        }
        output.push_str("],\"excluded_target_variables\":");
        json_string_array(
            &mut output,
            &self.backend.excluded_target_variables,
            is_cancelled,
        )?;
        output.push_str(",\"optimization_decisions\":[");
        for (index, decision) in self.backend.optimization_decisions.iter().enumerate() {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if index != 0 {
                output.push(',');
            }
            output.push('{');
            json_string(&mut output, "pass", &decision.pass, false, is_cancelled)?;
            json_string(
                &mut output,
                "subject",
                &decision.subject,
                true,
                is_cancelled,
            )?;
            json_string(
                &mut output,
                "action",
                decision.action.as_str(),
                true,
                is_cancelled,
            )?;
            json_string(
                &mut output,
                "justification",
                &decision.justification,
                true,
                is_cancelled,
            )?;
            output.push_str(",\"relied_on\":");
            json_u32_array(&mut output, &decision.relied_on, is_cancelled)?;
            output.push('}');
        }
        output.push(']');
        output.push('}');
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        Ok(output)
    }
}

fn encoded_capacity(
    report: &ImageReport,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<usize, ReportError> {
    let (analysis_items, analysis_edges, analysis_payload, analysis_expansion) = measure_analysis(
        &report.analysis,
        &report.image_name,
        report.analysis_limits,
        is_cancelled,
    )?;
    let (backend_items, backend_edges, backend_payload, backend_expansion) =
        measure_backend(&report.backend, report.backend_limits, is_cancelled)?;
    let identity_payload = u64::try_from(report.build.language.as_str().len())
        .map_err(|_| ReportError::MeasurementOverflow)?
        .checked_add(
            u64::try_from(report.build.target.as_str().len())
                .map_err(|_| ReportError::MeasurementOverflow)?,
        )
        .ok_or(ReportError::MeasurementOverflow)?;
    let identity_expansion = json_string_expansion(report.build.language.as_str(), is_cancelled)?
        .checked_add(json_string_expansion(
            report.build.target.as_str(),
            is_cancelled,
        )?)
        .ok_or(ReportError::MeasurementOverflow)?;
    let payload = analysis_payload
        .checked_add(backend_payload)
        .and_then(|value| value.checked_add(identity_payload))
        .ok_or(ReportError::MeasurementOverflow)?;
    let items = analysis_items
        .checked_add(backend_items)
        .ok_or(ReportError::MeasurementOverflow)?;
    let edges = analysis_edges
        .checked_add(backend_edges)
        .ok_or(ReportError::MeasurementOverflow)?;

    let expansion = analysis_expansion
        .checked_add(backend_expansion)
        .and_then(|value| value.checked_add(identity_expansion))
        .ok_or(ReportError::MeasurementOverflow)?;
    // The remaining terms conservatively cover field names, punctuation,
    // numeric scalars, fixed-size identities, and per-edge separators. String
    // payload and its exact JSON-escape expansion are measured separately.
    let capacity = 8_192u64
        .checked_add(payload)
        .and_then(|value| value.checked_add(expansion))
        .and_then(|value| value.checked_add(items.checked_mul(1_024)?))
        .and_then(|value| value.checked_add(edges.checked_mul(32)?))
        .ok_or(ReportError::MeasurementOverflow)?;
    usize::try_from(capacity).map_err(|_| ReportError::MeasurementOverflow)
}

fn json_string_expansion(value: &str, is_cancelled: &dyn Fn() -> bool) -> Result<u64, ReportError> {
    let mut expansion = 0u64;
    for (index, character) in value.chars().enumerate() {
        if index % 1_024 == 0 && is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        let encoded_bytes = match character {
            '"' | '\\' | '\n' | '\r' | '\t' => 2usize,
            character if character.is_control() => 6,
            character => character.len_utf8(),
        };
        let extra = encoded_bytes
            .checked_sub(character.len_utf8())
            .ok_or(ReportError::MeasurementOverflow)?;
        expansion = expansion
            .checked_add(u64::try_from(extra).map_err(|_| ReportError::MeasurementOverflow)?)
            .ok_or(ReportError::MeasurementOverflow)?;
    }
    if is_cancelled() {
        return Err(ReportError::Cancelled);
    }
    Ok(expansion)
}

const fn enforce_analysis_limits(
    limits: AnalysisFactLimits,
    items: u64,
    proof_edges: u64,
    payload_bytes: u64,
) -> Result<(), ReportError> {
    if items > limits.items {
        return Err(ReportError::ResourceLimit {
            resource: "analysis fact items",
            limit: limits.items,
        });
    }
    if proof_edges > limits.proof_edges {
        return Err(ReportError::ResourceLimit {
            resource: "analysis proof edges",
            limit: limits.proof_edges,
        });
    }
    if payload_bytes > limits.payload_bytes {
        return Err(ReportError::ResourceLimit {
            resource: "analysis fact payload",
            limit: limits.payload_bytes,
        });
    }
    Ok(())
}

const fn enforce_backend_limits(
    limits: BackendFactLimits,
    items: u64,
    optimization_proof_edges: u64,
    payload_bytes: u64,
) -> Result<(), ReportError> {
    if items > limits.items {
        return Err(ReportError::ResourceLimit {
            resource: "backend fact items",
            limit: limits.items,
        });
    }
    if optimization_proof_edges > limits.optimization_proof_edges {
        return Err(ReportError::ResourceLimit {
            resource: "optimization proof edges",
            limit: limits.optimization_proof_edges,
        });
    }
    if payload_bytes > limits.payload_bytes {
        return Err(ReportError::ResourceLimit {
            resource: "backend fact payload",
            limit: limits.payload_bytes,
        });
    }
    Ok(())
}

fn copy_string(value: &str, resource: &'static str, limit: u64) -> Result<String, ReportError> {
    let actual = u64::try_from(value.len()).map_err(|_| ReportError::MeasurementOverflow)?;
    if actual > limit {
        return Err(ReportError::ResourceLimit { resource, limit });
    }
    let mut output = String::new();
    output
        .try_reserve_exact(value.len())
        .map_err(|_| ReportError::ResourceLimit { resource, limit })?;
    output.push_str(value);
    Ok(output)
}

fn copy_build_identity(value: &BuildIdentity) -> Result<BuildIdentity, ReportError> {
    let target_limit = u64::try_from(wrela_build_model::MAX_PROFILE_ATOM_BYTES)
        .map_err(|_| ReportError::MeasurementOverflow)?;
    let target = copy_string(value.target.as_str(), "build identity target", target_limit)?;
    Ok(BuildIdentity {
        compiler: value.compiler,
        language: value.language,
        target: TargetIdentity::new(target).map_err(|_| ReportError::IdentityMismatch)?,
        target_package: value.target_package,
        standard_library: value.standard_library,
        source_graph: value.source_graph,
        request: value.request,
        profile: value.profile,
    })
}

fn cancellable_sort<T: Ord>(
    values: &mut [T],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ReportError> {
    if is_cancelled() {
        return Err(ReportError::Cancelled);
    }
    if values.len() < 2 {
        return Ok(());
    }
    let length = values.len();
    for root in (0..length / 2).rev() {
        sift_down(values, root, length, is_cancelled)?;
    }
    for end in (1..length).rev() {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        values.swap(0, end);
        sift_down(values, 0, end, is_cancelled)?;
    }
    Ok(())
}

fn sift_down<T: Ord>(
    values: &mut [T],
    mut root: usize,
    end: usize,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ReportError> {
    loop {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        let Some(left) = root.checked_mul(2).and_then(|value| value.checked_add(1)) else {
            return Err(ReportError::MeasurementOverflow);
        };
        if left >= end {
            return Ok(());
        }
        let right = left + 1;
        let child = if right < end && values[left] < values[right] {
            right
        } else {
            left
        };
        if values[root] >= values[child] {
            return Ok(());
        }
        values.swap(root, child);
        root = child;
    }
}

fn canonicalize_analysis(
    analysis: &mut AnalysisFacts,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ReportError> {
    cancellable_sort(&mut analysis.bounds, is_cancelled)?;
    cancellable_sort(&mut analysis.proofs, is_cancelled)?;
    cancellable_sort(&mut analysis.actor_lowerings, is_cancelled)?;
    cancellable_sort(&mut analysis.image_nodes, is_cancelled)?;
    cancellable_sort(&mut analysis.iso_pools, is_cancelled)?;
    cancellable_sort(&mut analysis.region_capacity_evidence, is_cancelled)?;
    cancellable_sort(&mut analysis.activation_frame_evidence, is_cancelled)?;
    cancellable_sort(&mut analysis.activation_frame_resets, is_cancelled)?;
    cancellable_sort(&mut analysis.region_assignments, is_cancelled)?;
    cancellable_sort(&mut analysis.promotions, is_cancelled)?;
    cancellable_sort(&mut analysis.image_edges, is_cancelled)?;
    cancellable_sort(&mut analysis.work, is_cancelled)?;
    cancellable_sort(&mut analysis.hardware, is_cancelled)?;
    cancellable_sort(&mut analysis.recovery, is_cancelled)?;
    cancellable_sort(&mut analysis.actor_placement_inputs, is_cancelled)?;
    for ownership in &mut analysis.scheduler_ownership {
        cancellable_sort(&mut ownership.actors, is_cancelled)?;
        cancellable_sort(&mut ownership.tasks, is_cancelled)?;
    }
    cancellable_sort(&mut analysis.scheduler_ownership, is_cancelled)
}

fn canonicalize_backend(
    backend: &mut BackendFacts,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ReportError> {
    cancellable_sort(&mut backend.sections, is_cancelled)?;
    cancellable_sort(&mut backend.symbols, is_cancelled)?;
    cancellable_sort(&mut backend.required_runtime_intrinsics, is_cancelled)?;
    cancellable_sort(&mut backend.target_variable_reservations, is_cancelled)?;
    cancellable_sort(&mut backend.excluded_target_variables, is_cancelled)?;
    for decision in &mut backend.optimization_decisions {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        cancellable_sort(&mut decision.relied_on, is_cancelled)?;
    }
    cancellable_sort(&mut backend.optimization_decisions, is_cancelled)
}

#[allow(clippy::too_many_lines)]
fn measure_analysis(
    analysis: &AnalysisFacts,
    image_name: &str,
    limits: AnalysisFactLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(u64, u64, u64, u64), ReportError> {
    let mut items = 0u64;
    let mut proof_edges = 0u64;
    let mut payload = 0u64;
    let mut json_expansion = 0u64;
    let mut add_items = |count: usize| -> Result<(), ReportError> {
        items = items
            .checked_add(u64::try_from(count).map_err(|_| ReportError::MeasurementOverflow)?)
            .ok_or(ReportError::MeasurementOverflow)?;
        if items > limits.items {
            return Err(ReportError::ResourceLimit {
                resource: "analysis fact items",
                limit: limits.items,
            });
        }
        Ok(())
    };
    for count in [
        analysis.bounds.len(),
        analysis.proofs.len(),
        analysis.actor_lowerings.len(),
        analysis.image_nodes.len(),
        analysis.iso_pools.len(),
        analysis.region_capacity_evidence.len(),
        analysis.activation_frame_evidence.len(),
        analysis.activation_frame_resets.len(),
        analysis.region_assignments.len(),
        analysis.promotions.len(),
        analysis.image_edges.len(),
        analysis.work.len(),
        analysis.hardware.len(),
        analysis.recovery.len(),
        analysis.actor_placement_inputs.len(),
        analysis.scheduler_ownership.len(),
        analysis.startup_order.len(),
        analysis.shutdown_order.len(),
    ] {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        add_items(count)?;
    }
    if let Some(group) = &analysis.compiled_test_group {
        add_items(1)?;
        add_items(group.tests.len())?;
        let assertion_count = group.tests.iter().try_fold(0usize, |count, test| {
            count
                .checked_add(test.assertions.len())
                .ok_or(ReportError::MeasurementOverflow)
        })?;
        add_items(assertion_count)?;
    }
    let mut add = |value: &str| -> Result<(), ReportError> {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        json_expansion = json_expansion
            .checked_add(json_string_expansion(value, is_cancelled)?)
            .ok_or(ReportError::MeasurementOverflow)?;
        payload = payload
            .checked_add(u64::try_from(value.len()).map_err(|_| ReportError::MeasurementOverflow)?)
            .ok_or(ReportError::MeasurementOverflow)?;
        if payload > limits.payload_bytes {
            return Err(ReportError::ResourceLimit {
                resource: "analysis fact payload",
                limit: limits.payload_bytes,
            });
        }
        Ok(())
    };
    add(image_name)?;
    for fact in &analysis.bounds {
        for value in [&fact.category, &fact.owner, &fact.source, &fact.unit] {
            add(value)?;
        }
    }
    for fact in &analysis.proofs {
        for value in [&fact.category, &fact.subject, &fact.result] {
            add(value)?;
        }
        proof_edges = proof_edges
            .checked_add(
                u64::try_from(fact.sources.len()).map_err(|_| ReportError::MeasurementOverflow)?,
            )
            .and_then(|edges| edges.checked_add(u64::try_from(fact.depends_on.len()).ok()?))
            .and_then(|edges| edges.checked_add(u64::try_from(fact.why_chain.len()).ok()?))
            .ok_or(ReportError::MeasurementOverflow)?;
        if proof_edges > limits.proof_edges {
            return Err(ReportError::ResourceLimit {
                resource: "analysis proof edges",
                limit: limits.proof_edges,
            });
        }
        for value in &fact.sources {
            add(value)?;
        }
        for value in &fact.why_chain {
            add(value)?;
        }
    }
    for fact in &analysis.actor_lowerings {
        for value in [&fact.source, &fact.destination, &fact.message] {
            add(value)?;
        }
    }
    for fact in &analysis.image_nodes {
        for value in [&fact.kind, &fact.name, &fact.owner, &fact.source] {
            add(value)?;
        }
    }
    for fact in &analysis.iso_pools {
        for value in [
            &fact.pool,
            &fact.brand,
            &fact.region,
            &fact.payload_type,
            &fact.owner,
            &fact.source,
            &fact.brand_source,
            &fact.slots_source,
            &fact.maximum_payload_source,
            &fact.payload_source,
        ] {
            add(value)?;
        }
    }
    for fact in &analysis.region_capacity_evidence {
        add(&fact.region)?;
    }
    for fact in &analysis.region_assignments {
        add(&fact.allocation)?;
    }
    for fact in &analysis.promotions {
        add(&fact.allocation)?;
        add(&fact.reason)?;
    }
    for fact in &analysis.activation_frame_evidence {
        for value in [
            &fact.region,
            &fact.caller,
            &fact.callee,
            &fact.owner,
            &fact.source,
        ] {
            add(value)?;
        }
    }
    for fact in &analysis.activation_frame_resets {
        for value in [&fact.region, &fact.owner, &fact.source] {
            add(value)?;
        }
    }
    for fact in &analysis.image_edges {
        for value in [&fact.kind, &fact.source, &fact.destination] {
            add(value)?;
        }
    }
    for fact in &analysis.work {
        add(&fact.function)?;
    }
    for fact in &analysis.hardware {
        for value in [&fact.device, &fact.binding, &fact.owner, &fact.dma_policy] {
            add(value)?;
        }
    }
    for fact in &analysis.recovery {
        add(&fact.subject)?;
        add(&fact.supervisor)?;
        proof_edges = proof_edges
            .checked_add(
                u64::try_from(fact.cleanup_path.len())
                    .map_err(|_| ReportError::MeasurementOverflow)?,
            )
            .ok_or(ReportError::MeasurementOverflow)?;
        if proof_edges > limits.proof_edges {
            return Err(ReportError::ResourceLimit {
                resource: "analysis proof edges",
                limit: limits.proof_edges,
            });
        }
        for value in &fact.cleanup_path {
            add(value)?;
        }
    }
    for fact in &analysis.actor_placement_inputs {
        add(&fact.actor)?;
    }
    for fact in &analysis.scheduler_ownership {
        add_items(fact.actors.len())?;
        add_items(fact.tasks.len())?;
        for value in fact.actors.iter().chain(&fact.tasks) {
            add(value)?;
        }
    }
    if let Some(group) = &analysis.compiled_test_group {
        add(&group.name)?;
        match &group.root {
            wrela_test_model::ImageRoot::GeneratedHarness { harness_name } => add(harness_name)?,
            wrela_test_model::ImageRoot::Declared { image_name, .. } => add(image_name)?,
        }
        for test in &group.tests {
            add(&test.descriptor.name)?;
            for assertion in &test.assertions {
                add(&assertion.expression)?;
                if let Some(message) = &assertion.message {
                    add(message)?;
                }
            }
        }
    }
    for value in analysis
        .startup_order
        .iter()
        .chain(&analysis.shutdown_order)
    {
        add(value)?;
    }
    Ok((items, proof_edges, payload, json_expansion))
}

fn measure_backend(
    backend: &BackendFacts,
    limits: BackendFactLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(u64, u64, u64, u64), ReportError> {
    let mut items = 0u64;
    for count in [
        backend.sections.len(),
        backend.symbols.len(),
        backend.required_runtime_intrinsics.len(),
        backend.target_variable_reservations.len(),
        backend.excluded_target_variables.len(),
        backend.optimization_decisions.len(),
    ] {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        items = items
            .checked_add(u64::try_from(count).map_err(|_| ReportError::MeasurementOverflow)?)
            .ok_or(ReportError::MeasurementOverflow)?;
        if items > limits.items {
            return Err(ReportError::ResourceLimit {
                resource: "backend fact items",
                limit: limits.items,
            });
        }
    }
    let mut optimization_proof_edges = 0u64;
    let mut payload = 0u64;
    let mut json_expansion = 0u64;
    let mut add = |value: &str| -> Result<(), ReportError> {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        json_expansion = json_expansion
            .checked_add(json_string_expansion(value, is_cancelled)?)
            .ok_or(ReportError::MeasurementOverflow)?;
        payload = payload
            .checked_add(u64::try_from(value.len()).map_err(|_| ReportError::MeasurementOverflow)?)
            .ok_or(ReportError::MeasurementOverflow)?;
        if payload > limits.payload_bytes {
            return Err(ReportError::ResourceLimit {
                resource: "backend fact payload",
                limit: limits.payload_bytes,
            });
        }
        Ok(())
    };
    add(&backend.representations.optimization_pipeline_name)?;
    for fact in &backend.sections {
        add(&fact.name)?;
        add(&fact.owner)?;
    }
    for fact in &backend.symbols {
        add(&fact.name)?;
        add(&fact.section)?;
    }
    for value in &backend.required_runtime_intrinsics {
        add(value)?;
    }
    for fact in &backend.target_variable_reservations {
        for value in [&fact.category, &fact.owner, &fact.source, &fact.unit] {
            add(value)?;
        }
    }
    for value in &backend.excluded_target_variables {
        add(value)?;
    }
    for decision in &backend.optimization_decisions {
        add(&decision.pass)?;
        add(&decision.subject)?;
        add(&decision.justification)?;
        optimization_proof_edges = optimization_proof_edges
            .checked_add(
                u64::try_from(decision.relied_on.len())
                    .map_err(|_| ReportError::MeasurementOverflow)?,
            )
            .ok_or(ReportError::MeasurementOverflow)?;
        if optimization_proof_edges > limits.optimization_proof_edges {
            return Err(ReportError::ResourceLimit {
                resource: "optimization proof edges",
                limit: limits.optimization_proof_edges,
            });
        }
    }
    Ok((items, optimization_proof_edges, payload, json_expansion))
}

#[allow(clippy::too_many_lines)]
fn validate_analysis(
    analysis: &AnalysisFacts,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ReportError> {
    require_canonical("bounds", &analysis.bounds, is_cancelled)?;
    require_canonical("proofs", &analysis.proofs, is_cancelled)?;
    require_canonical("actor lowerings", &analysis.actor_lowerings, is_cancelled)?;
    require_canonical("image nodes", &analysis.image_nodes, is_cancelled)?;
    require_canonical("iso pools", &analysis.iso_pools, is_cancelled)?;
    require_canonical(
        "region capacity evidence",
        &analysis.region_capacity_evidence,
        is_cancelled,
    )?;
    require_canonical(
        "activation frame evidence",
        &analysis.activation_frame_evidence,
        is_cancelled,
    )?;
    require_canonical(
        "activation frame resets",
        &analysis.activation_frame_resets,
        is_cancelled,
    )?;
    require_canonical(
        "region assignments",
        &analysis.region_assignments,
        is_cancelled,
    )?;
    require_canonical("promotions", &analysis.promotions, is_cancelled)?;
    require_canonical("image edges", &analysis.image_edges, is_cancelled)?;
    require_canonical("work facts", &analysis.work, is_cancelled)?;
    require_canonical("hardware facts", &analysis.hardware, is_cancelled)?;
    require_canonical("recovery facts", &analysis.recovery, is_cancelled)?;
    require_canonical(
        "actor placement input facts",
        &analysis.actor_placement_inputs,
        is_cancelled,
    )?;
    require_canonical(
        "scheduler ownership facts",
        &analysis.scheduler_ownership,
        is_cancelled,
    )?;
    require_nonempty_unique("startup order", &analysis.startup_order, is_cancelled)?;
    require_nonempty_unique("shutdown order", &analysis.shutdown_order, is_cancelled)?;
    if is_cancelled() {
        return Err(ReportError::Cancelled);
    }
    if let Some(group) = &analysis.compiled_test_group {
        group
            .validate_compiled_binding_with_limits(
                wrela_test_model::TestPlanLimits::standard(),
                is_cancelled,
            )
            .map_err(|error| map_test_model_error(&error))?;
    }
    if !strictly_increasing_by(
        &analysis.work,
        |left, right| left.function < right.function,
        is_cancelled,
    )? || !strictly_increasing_by(
        &analysis.hardware,
        |left, right| left.device < right.device,
        is_cancelled,
    )? || !strictly_increasing_by(
        &analysis.recovery,
        |left, right| left.subject < right.subject,
        is_cancelled,
    )? || !strictly_increasing_by(
        &analysis.actor_placement_inputs,
        |left, right| left.actor < right.actor,
        is_cancelled,
    )? {
        return Err(ReportError::NonCanonical("named analysis facts"));
    }
    for fact in &analysis.bounds {
        if invalid_bound(fact, is_cancelled)? {
            return Err(ReportError::InvalidFact);
        }
    }
    for (index, proof) in analysis.proofs.iter().enumerate() {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        if usize::try_from(proof.id).map_err(|_| ReportError::MeasurementOverflow)? != index
            || !nonempty(&proof.category, is_cancelled)?
            || !nonempty(&proof.subject, is_cancelled)?
            || !nonempty(&proof.result, is_cancelled)?
            || proof.why_chain.is_empty()
        {
            return Err(ReportError::InvalidFact);
        }
        for source in &proof.sources {
            if !canonical_source_identity(source, is_cancelled)? {
                return Err(ReportError::InvalidFact);
            }
        }
        let mut prior_dependency = None;
        for dependency in &proof.depends_on {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if *dependency >= proof.id || prior_dependency.is_some_and(|prior| prior >= *dependency)
            {
                return Err(ReportError::InvalidFact);
            }
            prior_dependency = Some(*dependency);
        }
        require_nonempty_values(&proof.why_chain, is_cancelled)?;
    }
    for fact in &analysis.actor_lowerings {
        if !nonempty(&fact.source, is_cancelled)?
            || !nonempty(&fact.destination, is_cancelled)?
            || !nonempty(&fact.message, is_cancelled)?
        {
            return Err(ReportError::InvalidFact);
        }
    }
    for fact in &analysis.image_nodes {
        if !nonempty(&fact.kind, is_cancelled)?
            || !nonempty(&fact.name, is_cancelled)?
            || !nonempty(&fact.owner, is_cancelled)?
            || !nonempty(&fact.source, is_cancelled)?
        {
            return Err(ReportError::InvalidFact);
        }
    }
    let scheduler_identity_count =
        analysis
            .scheduler_ownership
            .iter()
            .try_fold(0usize, |count, fact| {
                count
                    .checked_add(fact.actors.len())
                    .and_then(|count| count.checked_add(fact.tasks.len()))
                    .ok_or(ReportError::MeasurementOverflow)
            })?;
    let scheduler_identity_limit =
        u64::try_from(scheduler_identity_count).map_err(|_| ReportError::MeasurementOverflow)?;
    let mut scheduler_identities = Vec::new();
    let mut scheduler_actors = Vec::new();
    scheduler_identities
        .try_reserve_exact(scheduler_identity_count)
        .map_err(|_| ReportError::ResourceLimit {
            resource: "scheduler ownership validation index",
            limit: scheduler_identity_limit,
        })?;
    scheduler_actors
        .try_reserve_exact(scheduler_identity_count)
        .map_err(|_| ReportError::ResourceLimit {
            resource: "actor placement validation index",
            limit: scheduler_identity_limit,
        })?;
    for (index, fact) in analysis.scheduler_ownership.iter().enumerate() {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        if usize::try_from(fact.core).map_err(|_| ReportError::MeasurementOverflow)? != index
            || (fact.actors.is_empty() && fact.tasks.is_empty())
            || !strictly_increasing_by(&fact.actors, |left, right| left < right, is_cancelled)?
            || !strictly_increasing_by(&fact.tasks, |left, right| left < right, is_cancelled)?
        {
            return Err(ReportError::InvalidFact);
        }
        for actor in &fact.actors {
            if !canonical_named_identity(actor, "actor", is_cancelled)? {
                return Err(ReportError::InvalidFact);
            }
            scheduler_identities.push(("actor", actor));
            scheduler_actors.push(actor.as_str());
        }
        for task in &fact.tasks {
            if !canonical_named_identity(task, "task", is_cancelled)? {
                return Err(ReportError::InvalidFact);
            }
            scheduler_identities.push(("task", task));
        }
    }
    cancellable_sort(&mut scheduler_identities, is_cancelled)?;
    for pair in scheduler_identities.windows(2) {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        if pair[0] == pair[1] {
            return Err(ReportError::InvalidFact);
        }
    }
    if !analysis.actor_placement_inputs.is_empty() {
        cancellable_sort(&mut scheduler_actors, is_cancelled)?;
        if scheduler_actors.len() != analysis.actor_placement_inputs.len()
            || scheduler_actors
                .iter()
                .zip(&analysis.actor_placement_inputs)
                .any(|(owned, input)| *owned != input.actor)
        {
            return Err(ReportError::InvalidFact);
        }
    }
    for fact in &analysis.region_capacity_evidence {
        if !nonempty(&fact.region, is_cancelled)? {
            return Err(ReportError::InvalidFact);
        }
    }
    let assignment_count = u32::try_from(analysis.region_assignments.len())
        .map_err(|_| ReportError::MeasurementOverflow)?;
    let mut allocation_ids = Vec::new();
    allocation_ids
        .try_reserve_exact(analysis.region_assignments.len())
        .map_err(|_| ReportError::ResourceLimit {
            resource: "region assignment validation index",
            limit: u64::from(assignment_count),
        })?;
    allocation_ids.resize(analysis.region_assignments.len(), false);
    let mut prior_allocation: Option<&str> = None;
    for fact in &analysis.region_assignments {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        let Some(allocation_id) =
            canonical_named_identity_id(&fact.allocation, "alloc", is_cancelled)?
        else {
            return Err(ReportError::InvalidFact);
        };
        let allocation_index =
            usize::try_from(allocation_id).map_err(|_| ReportError::MeasurementOverflow)?;
        if allocation_id >= assignment_count
            || allocation_ids
                .get(allocation_index)
                .copied()
                .unwrap_or(true)
            || prior_allocation == Some(fact.allocation.as_str())
        {
            return Err(ReportError::InvalidFact);
        }
        allocation_ids[allocation_index] = true;
        prior_allocation = Some(&fact.allocation);
    }
    for fact in &analysis.promotions {
        // A promotion moves an allocation between two distinct regions with a
        // stated reason. A same-region "promotion" or an empty identity/reason
        // is not a promotion the report can carry.
        let proof = usize::try_from(fact.proof)
            .ok()
            .and_then(|proof| analysis.proofs.get(proof));
        let assignment = analysis
            .region_assignments
            .binary_search_by(|assignment| assignment.allocation.cmp(&fact.allocation))
            .ok()
            .and_then(|index| analysis.region_assignments.get(index));
        if !canonical_named_identity(&fact.allocation, "alloc", is_cancelled)?
            || !nonempty(&fact.reason, is_cancelled)?
            || fact.source_region == fact.destination_region
            || assignment.is_none_or(|assignment| {
                assignment.allocation != fact.allocation
                    || assignment.region_class != fact.destination_region
            })
            || proof.is_none_or(|proof| {
                proof.id != fact.proof
                    || proof.category != "region-bound"
                    || proof.subject != fact.allocation
                    || proof.result != "proved"
                    || proof.bound.is_none_or(|bound| bound == 0)
            })
        {
            return Err(ReportError::InvalidFact);
        }
    }
    for (index, fact) in analysis.activation_frame_evidence.iter().enumerate() {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        if usize::try_from(fact.plan).map_err(|_| ReportError::MeasurementOverflow)? != index
            || !nonempty(&fact.region, is_cancelled)?
            || !nonempty(&fact.caller, is_cancelled)?
            || !nonempty(&fact.callee, is_cancelled)?
            || !nonempty(&fact.owner, is_cancelled)?
            || !canonical_source_identity(&fact.source, is_cancelled)?
            || fact.frame_bytes == 0
            || fact.maximum_live == 0
        {
            return Err(ReportError::InvalidFact);
        }
    }
    let mut prior_reset_plan: Option<u32> = None;
    for fact in &analysis.activation_frame_resets {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        // A reset record is only meaningful when it names an activation plan
        // this same report already publishes. A reset without its plan, or a
        // second reset for one plan, is not evidence the report can carry.
        let plan_index =
            usize::try_from(fact.plan).map_err(|_| ReportError::MeasurementOverflow)?;
        if prior_reset_plan.is_some_and(|prior| prior >= fact.plan)
            || analysis
                .activation_frame_evidence
                .get(plan_index)
                .is_none_or(|activation| activation.plan != fact.plan)
            || !nonempty(&fact.region, is_cancelled)?
            || !nonempty(&fact.owner, is_cancelled)?
            || !canonical_source_identity(&fact.source, is_cancelled)?
            || fact.region_class != RegionClass::TaskFrame
            || fact.capacity_bytes == 0
            || fact.alignment == 0
            || !fact.alignment.is_power_of_two()
            || fact.capacity_bound == 0
        {
            return Err(ReportError::InvalidFact);
        }
        prior_reset_plan = Some(fact.plan);
    }
    for fact in &analysis.image_edges {
        if !nonempty(&fact.kind, is_cancelled)?
            || !nonempty(&fact.source, is_cancelled)?
            || !nonempty(&fact.destination, is_cancelled)?
        {
            return Err(ReportError::InvalidFact);
        }
    }
    for fact in &analysis.work {
        if !nonempty(&fact.function, is_cancelled)? {
            return Err(ReportError::InvalidFact);
        }
    }
    for fact in &analysis.hardware {
        if !nonempty(&fact.device, is_cancelled)?
            || !nonempty(&fact.binding, is_cancelled)?
            || !nonempty(&fact.owner, is_cancelled)?
            || !nonempty(&fact.dma_policy, is_cancelled)?
        {
            return Err(ReportError::InvalidFact);
        }
    }
    for fact in &analysis.recovery {
        if !nonempty(&fact.subject, is_cancelled)?
            || !nonempty(&fact.supervisor, is_cancelled)?
            || fact.cleanup_path.is_empty()
        {
            return Err(ReportError::InvalidFact);
        }
        require_nonempty_values(&fact.cleanup_path, is_cancelled)?;
    }
    for fact in &analysis.actor_placement_inputs {
        if !canonical_named_identity(&fact.actor, "actor", is_cancelled)?
            || fact.reserved_region_bytes == 0
        {
            return Err(ReportError::InvalidFact);
        }
    }
    validate_image_graph(analysis, is_cancelled)?;
    Ok(())
}

fn validate_image_graph(
    analysis: &AnalysisFacts,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ReportError> {
    let index_limit =
        u64::try_from(analysis.image_nodes.len()).map_err(|_| ReportError::MeasurementOverflow)?;
    let mut nodes = Vec::new();
    let mut region_nodes = Vec::new();
    nodes
        .try_reserve_exact(analysis.image_nodes.len())
        .map_err(|_| ReportError::ResourceLimit {
            resource: "image node validation index",
            limit: index_limit,
        })?;
    region_nodes
        .try_reserve_exact(analysis.image_nodes.len())
        .map_err(|_| ReportError::ResourceLimit {
            resource: "region node validation index",
            limit: index_limit,
        })?;
    for (position, node) in analysis.image_nodes.iter().enumerate() {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        if !valid_image_node(node, is_cancelled)? {
            return Err(ReportError::InvalidFact);
        }
        if is_reportable_region_kind(&node.kind) {
            let region = canonical_named_identity_id(&node.name, "region", is_cancelled)?
                .ok_or(ReportError::InvalidFact)?;
            region_nodes.push((region, position));
        }
        nodes.push((node.name.as_str(), position));
    }
    cancellable_sort(&mut region_nodes, is_cancelled)?;
    for pair in region_nodes.windows(2) {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        if pair[0].0 == pair[1].0 {
            return Err(ReportError::NonCanonical("region node identifiers"));
        }
    }
    cancellable_sort(&mut nodes, is_cancelled)?;
    for pair in nodes.windows(2) {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        if pair[0].0 == pair[1].0 {
            return Err(ReportError::NonCanonical("image node identities"));
        }
    }

    let evidence_limit = u64::try_from(analysis.region_capacity_evidence.len())
        .map_err(|_| ReportError::MeasurementOverflow)?;
    let mut region_evidence = Vec::new();
    region_evidence
        .try_reserve_exact(analysis.region_capacity_evidence.len())
        .map_err(|_| ReportError::ResourceLimit {
            resource: "region capacity evidence validation index",
            limit: evidence_limit,
        })?;
    for (position, evidence) in analysis.region_capacity_evidence.iter().enumerate() {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        let region = canonical_named_identity_id(&evidence.region, "region", is_cancelled)?
            .ok_or(ReportError::InvalidFact)?;
        let node = region_nodes
            .binary_search_by_key(&region, |(id, _)| *id)
            .ok()
            .and_then(|index| region_nodes.get(index))
            .and_then(|(_, position)| analysis.image_nodes.get(*position))
            .ok_or(ReportError::InvalidFact)?;
        if !text_equal_cancellable(&node.name, &evidence.region, is_cancelled)? {
            return Err(ReportError::InvalidFact);
        }
        let proof_index = usize::try_from(evidence.capacity_proof)
            .map_err(|_| ReportError::MeasurementOverflow)?;
        analysis
            .proofs
            .get(proof_index)
            .filter(|proof| {
                proof.id == evidence.capacity_proof && proof.category == "capacity-bound"
            })
            .ok_or(ReportError::InvalidFact)?;
        let capacity = unique_bound(analysis, "region-capacity", &evidence.region, is_cancelled)?;
        if capacity.owner != evidence.region
            || capacity.unit != "bytes"
            || capacity.amount != node.static_bytes
        {
            return Err(ReportError::InvalidFact);
        }
        region_evidence.push((region, position));
    }
    cancellable_sort(&mut region_evidence, is_cancelled)?;
    for pair in region_evidence.windows(2) {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        if pair[0].0 == pair[1].0 {
            return Err(ReportError::NonCanonical(
                "region capacity evidence identities",
            ));
        }
    }

    for fact in &analysis.activation_frame_resets {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        // The reset must agree exactly with the activation record it names, the
        // published region node, that node's capacity evidence, and the bounds
        // and capacity proof that region already carries. Any disagreement is a
        // forged or approximate region account rather than a reset.
        let plan_index =
            usize::try_from(fact.plan).map_err(|_| ReportError::MeasurementOverflow)?;
        let activation = analysis
            .activation_frame_evidence
            .get(plan_index)
            .filter(|activation| activation.plan == fact.plan)
            .ok_or(ReportError::InvalidFact)?;
        let region_id = canonical_named_identity_id(&fact.region, "region", is_cancelled)?
            .ok_or(ReportError::InvalidFact)?;
        let node = indexed_image_node(analysis, &nodes, &fact.region, is_cancelled)?
            .filter(|node| is_reportable_region_kind(&node.kind))
            .ok_or(ReportError::InvalidFact)?;
        let evidence = region_evidence
            .binary_search_by_key(&region_id, |(id, _)| *id)
            .ok()
            .and_then(|position| region_evidence.get(position))
            .and_then(|(_, position)| analysis.region_capacity_evidence.get(*position))
            .ok_or(ReportError::InvalidFact)?;
        let proof = analysis
            .proofs
            .get(
                usize::try_from(fact.capacity_proof)
                    .map_err(|_| ReportError::MeasurementOverflow)?,
            )
            .filter(|proof| {
                proof.id == fact.capacity_proof
                    && proof.category == "capacity-bound"
                    && proof.bound == Some(fact.capacity_bound)
            })
            .ok_or(ReportError::InvalidFact)?;
        let capacity = unique_bound(analysis, "region-capacity", &fact.region, is_cancelled)?;
        let alignment = unique_bound(analysis, "region-alignment", &fact.region, is_cancelled)?;
        if !text_equal_cancellable(&activation.region, &fact.region, is_cancelled)?
            || !text_equal_cancellable(&activation.owner, &fact.owner, is_cancelled)?
            || !text_equal_cancellable(&activation.source, &fact.source, is_cancelled)?
            || activation.frame_bytes != fact.capacity_bytes
            || activation.capacity_proof != fact.capacity_proof
            || !text_equal_cancellable(&node.owner, &fact.owner, is_cancelled)?
            || !text_equal_cancellable(&node.source, &fact.source, is_cancelled)?
            || node.static_bytes != fact.capacity_bytes
            || evidence.capacity_proof != fact.capacity_proof
            || proof.id != fact.capacity_proof
            || capacity.unit != "bytes"
            || capacity.amount != fact.capacity_bytes
            || alignment.unit != "bytes"
            || alignment.amount != fact.alignment
        {
            return Err(ReportError::InvalidFact);
        }
    }

    let mut iso_pool_node_count = 0usize;
    let mut iso_pool_region_count = 0usize;
    for node in &analysis.image_nodes {
        match node.kind.as_str() {
            "iso-pool" => iso_pool_node_count = iso_pool_node_count.saturating_add(1),
            "iso-pool-region" => iso_pool_region_count = iso_pool_region_count.saturating_add(1),
            _ => {}
        }
    }
    if iso_pool_node_count != analysis.iso_pools.len()
        || iso_pool_region_count != analysis.iso_pools.len()
    {
        return Err(ReportError::InvalidFact);
    }
    for (index, fact) in analysis.iso_pools.iter().enumerate() {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        let pool_id = canonical_named_identity_id(&fact.pool, "pool", is_cancelled)?
            .ok_or(ReportError::InvalidFact)?;
        let brand_id = canonical_named_identity_id(&fact.brand, "brand", is_cancelled)?
            .ok_or(ReportError::InvalidFact)?;
        let region_id = canonical_named_identity_id(&fact.region, "region", is_cancelled)?
            .ok_or(ReportError::InvalidFact)?;
        if usize::try_from(pool_id).map_err(|_| ReportError::MeasurementOverflow)? != index
            || pool_id != brand_id
            || pool_id != region_id
            || !canonical_named_identity(&fact.payload_type, "type", is_cancelled)?
            || !text_equal_cancellable(&fact.owner, &fact.pool, is_cancelled)?
            || !canonical_source_identity(&fact.source, is_cancelled)?
            || !canonical_source_identity(&fact.brand_source, is_cancelled)?
            || !canonical_source_identity(&fact.slots_source, is_cancelled)?
            || !canonical_source_identity(&fact.maximum_payload_source, is_cancelled)?
            || !canonical_source_identity(&fact.payload_source, is_cancelled)?
            || fact.slots == 0
            || fact.maximum_payload_bytes == 0
            || fact.payload_bytes == 0
            || fact.payload_bytes > fact.maximum_payload_bytes
            || !fact.alignment.is_power_of_two()
        {
            return Err(ReportError::InvalidFact);
        }
        let pool = indexed_image_node(analysis, &nodes, &fact.pool, is_cancelled)?
            .filter(|node| node.kind == "iso-pool")
            .ok_or(ReportError::InvalidFact)?;
        let region = indexed_image_node(analysis, &nodes, &fact.region, is_cancelled)?
            .filter(|node| node.kind == "iso-pool-region")
            .ok_or(ReportError::InvalidFact)?;
        let evidence = region_evidence
            .binary_search_by_key(&region_id, |(id, _)| *id)
            .ok()
            .and_then(|position| region_evidence.get(position))
            .and_then(|(_, position)| analysis.region_capacity_evidence.get(*position))
            .ok_or(ReportError::InvalidFact)?;
        let proof = analysis
            .proofs
            .get(
                usize::try_from(fact.capacity_proof)
                    .map_err(|_| ReportError::MeasurementOverflow)?,
            )
            .filter(|proof| {
                proof.id == fact.capacity_proof
                    && proof.category == "capacity-bound"
                    && proof.bound == Some(fact.slots)
            })
            .ok_or(ReportError::InvalidFact)?;
        let slots = unique_bound(analysis, "pool-slots", &fact.pool, is_cancelled)?;
        let maximum = unique_bound(analysis, "pool-maximum-payload", &fact.pool, is_cancelled)?;
        let payload = unique_bound(analysis, "pool-payload", &fact.payload_type, is_cancelled)?;
        let capacity = unique_bound(analysis, "region-capacity", &fact.region, is_cancelled)?;
        let alignment = unique_bound(analysis, "region-alignment", &fact.region, is_cancelled)?;
        let backing_bytes = fact
            .slots
            .checked_mul(fact.maximum_payload_bytes)
            .ok_or(ReportError::MeasurementOverflow)?;
        if pool.owner != "runtime"
            || pool.static_bytes != 0
            || !text_equal_cancellable(&pool.source, &fact.source, is_cancelled)?
            || !text_equal_cancellable(&region.owner, &fact.pool, is_cancelled)?
            || !text_equal_cancellable(&region.source, &fact.source, is_cancelled)?
            || region.static_bytes != backing_bytes
            || evidence.capacity_proof != fact.capacity_proof
            || !text_equal_cancellable(&evidence.region, &fact.region, is_cancelled)?
            || proof.sources.as_slice()
                != [
                    fact.source.as_str(),
                    fact.brand_source.as_str(),
                    fact.slots_source.as_str(),
                    fact.maximum_payload_source.as_str(),
                ]
            || slots.amount != fact.slots
            || slots.unit != "slots"
            || maximum.amount != fact.maximum_payload_bytes
            || maximum.unit != "bytes"
            || payload.amount != fact.payload_bytes
            || payload.unit != "bytes"
            || capacity.amount != backing_bytes
            || capacity.unit != "bytes"
            || alignment.amount != u64::from(fact.alignment)
            || alignment.unit != "bytes"
        {
            return Err(ReportError::InvalidFact);
        }
    }

    let activation_limit = u64::try_from(analysis.activation_frame_evidence.len())
        .map_err(|_| ReportError::MeasurementOverflow)?;
    let mut activation_regions = Vec::new();
    let mut activation_callers = Vec::new();
    let mut activation_proofs = Vec::new();
    activation_regions
        .try_reserve_exact(analysis.activation_frame_evidence.len())
        .map_err(|_| ReportError::ResourceLimit {
            resource: "activation frame validation index",
            limit: activation_limit,
        })?;
    activation_callers
        .try_reserve_exact(analysis.activation_frame_evidence.len())
        .map_err(|_| ReportError::ResourceLimit {
            resource: "activation caller validation index",
            limit: activation_limit,
        })?;
    activation_proofs
        .try_reserve_exact(analysis.activation_frame_evidence.len())
        .map_err(|_| ReportError::ResourceLimit {
            resource: "activation proof validation index",
            limit: activation_limit,
        })?;
    let work_limit =
        u64::try_from(analysis.work.len()).map_err(|_| ReportError::MeasurementOverflow)?;
    let mut work_by_id = Vec::new();
    work_by_id
        .try_reserve_exact(analysis.work.len())
        .map_err(|_| ReportError::ResourceLimit {
            resource: "activation work validation index",
            limit: work_limit,
        })?;
    for (position, work) in analysis.work.iter().enumerate() {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        if let Some(function) =
            canonical_named_identity_id(&work.function, "function", is_cancelled)?
        {
            work_by_id.push((function, position));
        }
    }
    cancellable_sort(&mut work_by_id, is_cancelled)?;
    for pair in work_by_id.windows(2) {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        if pair[0].0 == pair[1].0 {
            return Err(ReportError::NonCanonical("function work identifiers"));
        }
    }
    for evidence in &analysis.activation_frame_evidence {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        let region = canonical_named_identity_id(&evidence.region, "region", is_cancelled)?
            .ok_or(ReportError::InvalidFact)?;
        let caller = canonical_named_identity_id(&evidence.caller, "function", is_cancelled)?
            .ok_or(ReportError::InvalidFact)?;
        let callee = canonical_named_identity_id(&evidence.callee, "function", is_cancelled)?
            .ok_or(ReportError::InvalidFact)?;
        let node = region_nodes
            .binary_search_by_key(&region, |(id, _)| *id)
            .ok()
            .and_then(|index| region_nodes.get(index))
            .and_then(|(_, position)| analysis.image_nodes.get(*position))
            .ok_or(ReportError::InvalidFact)?;
        let capacity_evidence = region_evidence
            .binary_search_by_key(&region, |(id, _)| *id)
            .ok()
            .and_then(|index| region_evidence.get(index))
            .and_then(|(_, position)| analysis.region_capacity_evidence.get(*position))
            .ok_or(ReportError::InvalidFact)?;
        let caller_work = work_by_id
            .binary_search_by_key(&caller, |(id, _)| *id)
            .ok()
            .and_then(|index| work_by_id.get(index))
            .and_then(|(_, position)| analysis.work.get(*position))
            .ok_or(ReportError::InvalidFact)?;
        let callee_work = work_by_id
            .binary_search_by_key(&callee, |(id, _)| *id)
            .ok()
            .and_then(|index| work_by_id.get(index))
            .and_then(|(_, position)| analysis.work.get(*position))
            .ok_or(ReportError::InvalidFact)?;
        let proof_index = usize::try_from(evidence.capacity_proof)
            .map_err(|_| ReportError::MeasurementOverflow)?;
        let proof = analysis
            .proofs
            .get(proof_index)
            .filter(|proof| {
                proof.id == evidence.capacity_proof && proof.category == "capacity-bound"
            })
            .ok_or(ReportError::InvalidFact)?;
        let cleanup_index = proof
            .depends_on
            .first()
            .copied()
            .map(usize::try_from)
            .transpose()
            .map_err(|_| ReportError::MeasurementOverflow)?;
        let cleanup = cleanup_index.and_then(|dependency| analysis.proofs.get(dependency));
        let frame_capacity = evidence
            .frame_bytes
            .checked_mul(u64::from(evidence.maximum_live));
        if !matches!(
            node.kind.as_str(),
            "actor-activation-frame-region" | "task-activation-frame-region"
        ) || !text_equal_cancellable(&node.name, &evidence.region, is_cancelled)?
            || !text_equal_cancellable(&capacity_evidence.region, &evidence.region, is_cancelled)?
            || capacity_evidence.capacity_proof != evidence.capacity_proof
            || !text_equal_cancellable(&node.owner, &evidence.owner, is_cancelled)?
            || !text_equal_cancellable(&node.source, &evidence.source, is_cancelled)?
            || !text_equal_cancellable(&caller_work.function, &evidence.caller, is_cancelled)?
            || !text_equal_cancellable(&callee_work.function, &evidence.callee, is_cancelled)?
            || text_equal_cancellable(&evidence.caller, &evidence.callee, is_cancelled)?
            || !activation_region_name_matches_caller(
                &evidence.region,
                &evidence.caller,
                is_cancelled,
            )?
            || evidence.maximum_live != 1
            || frame_capacity != Some(node.static_bytes)
            || callee_work.frame_bytes.max(1) != evidence.frame_bytes
            || proof.bound != Some(u64::from(evidence.maximum_live))
            || proof.sources.len() != 1
            || !text_equal_cancellable(&proof.sources[0], &evidence.source, is_cancelled)?
            || proof.depends_on.len() != 1
            || cleanup.is_none_or(|cleanup| cleanup.category != "cleanup-acyclic")
        {
            return Err(ReportError::InvalidFact);
        }
        activation_regions.push((region, evidence.plan));
        activation_callers.push((caller, evidence.plan));
        activation_proofs.push((evidence.capacity_proof, evidence.plan));
    }
    cancellable_sort(&mut activation_regions, is_cancelled)?;
    cancellable_sort(&mut activation_callers, is_cancelled)?;
    cancellable_sort(&mut activation_proofs, is_cancelled)?;
    for pair in activation_regions.windows(2) {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        if pair[0].0 == pair[1].0 {
            return Err(ReportError::NonCanonical(
                "activation frame region identities",
            ));
        }
    }
    for (facts, kind) in [
        (&activation_callers, "activation caller identities"),
        (&activation_proofs, "activation capacity proof identities"),
    ] {
        for pair in facts.windows(2) {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            if pair[0].0 == pair[1].0 {
                return Err(ReportError::NonCanonical(kind));
            }
        }
    }
    let mut activation_node_count = 0_u64;
    for node in &analysis.image_nodes {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        if matches!(
            node.kind.as_str(),
            "actor-activation-frame-region" | "task-activation-frame-region"
        ) {
            activation_node_count = activation_node_count
                .checked_add(1)
                .ok_or(ReportError::MeasurementOverflow)?;
        }
    }
    if activation_node_count != activation_limit {
        return Err(ReportError::InvalidFact);
    }

    let edge_limit =
        u64::try_from(analysis.image_edges.len()).map_err(|_| ReportError::MeasurementOverflow)?;
    let mut supervision_sources = Vec::new();
    supervision_sources
        .try_reserve_exact(analysis.image_edges.len())
        .map_err(|_| ReportError::ResourceLimit {
            resource: "image edge validation index",
            limit: edge_limit,
        })?;
    for (edge_index, edge) in analysis.image_edges.iter().enumerate() {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        let source = indexed_image_node(analysis, &nodes, &edge.source, is_cancelled)?;
        match edge.kind.as_str() {
            "actor-supervision" => {
                let source = source.filter(|node| node.kind == "actor");
                let destination =
                    indexed_image_node(analysis, &nodes, &edge.destination, is_cancelled)?
                        .filter(|node| node.kind == "actor");
                if source.is_none()
                    || destination.is_none()
                    || edge.source == edge.destination
                    || edge.capacity.is_some()
                    || edge.priority.is_none()
                {
                    return Err(ReportError::InvalidFact);
                }
            }
            "task-supervision" => {
                let Some(source) = source.filter(|node| node.kind == "task") else {
                    return Err(ReportError::InvalidFact);
                };
                let destination_is_valid = edge.destination == "runtime"
                    || indexed_image_node(analysis, &nodes, &edge.destination, is_cancelled)?
                        .is_some_and(|node| node.kind == "actor");
                if !destination_is_valid
                    || source.owner != edge.destination
                    || edge.capacity.is_none()
                    || edge.priority.is_none()
                {
                    return Err(ReportError::InvalidFact);
                }
            }
            _ => return Err(ReportError::InvalidFact),
        }
        supervision_sources.push((edge.source.as_str(), edge_index));
    }
    cancellable_sort(&mut supervision_sources, is_cancelled)?;
    for pair in supervision_sources.windows(2) {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        if pair[0].0 == pair[1].0 {
            return Err(ReportError::NonCanonical("supervision edge sources"));
        }
    }

    for node in &analysis.image_nodes {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        match node.kind.as_str() {
            "actor" => {
                let mailbox = unique_bound(analysis, "actor-mailbox", &node.name, is_cancelled)?;
                if mailbox.unit != "messages" || mailbox.amount == 0 || node.static_bytes != 0 {
                    return Err(ReportError::InvalidFact);
                }
            }
            "task" => {
                let slots = unique_bound(analysis, "task-slots", &node.name, is_cancelled)?;
                let frame = unique_bound(analysis, "task-frame", &node.name, is_cancelled)?;
                let edge = supervision_sources
                    .binary_search_by(|(source, _)| source.cmp(&node.name.as_str()))
                    .ok()
                    .and_then(|position| supervision_sources.get(position))
                    .and_then(|(_, edge)| analysis.image_edges.get(*edge))
                    .ok_or(ReportError::InvalidFact)?;
                if slots.unit != "slots"
                    || slots.amount == 0
                    || frame.unit != "bytes"
                    || edge.kind != "task-supervision"
                    || edge.capacity != Some(slots.amount)
                    || node.static_bytes != 0
                {
                    return Err(ReportError::InvalidFact);
                }
            }
            "actor-mailbox-region"
            | "actor-turn-frame-region"
            | "task-frame-region"
            | "actor-activation-frame-region"
            | "task-activation-frame-region" => {
                let region = canonical_named_identity_id(&node.name, "region", is_cancelled)?
                    .ok_or(ReportError::InvalidFact)?;
                let evidence = region_evidence
                    .binary_search_by_key(&region, |(id, _)| *id)
                    .ok()
                    .and_then(|position| region_evidence.get(position))
                    .and_then(|(_, position)| analysis.region_capacity_evidence.get(*position))
                    .ok_or(ReportError::InvalidFact)?;
                let capacity = unique_bound(analysis, "region-capacity", &node.name, is_cancelled)?;
                let alignment =
                    unique_bound(analysis, "region-alignment", &node.name, is_cancelled)?;
                let owner_kind = match node.kind.as_str() {
                    "task-frame-region" | "task-activation-frame-region" => "task",
                    _ => "actor",
                };
                if indexed_image_node(analysis, &nodes, &node.owner, is_cancelled)?
                    .is_none_or(|owner| owner.kind != owner_kind)
                    || capacity.unit != "bytes"
                    || capacity.amount == 0
                    || alignment.unit != "bytes"
                    || !alignment.amount.is_power_of_two()
                    || node.static_bytes != capacity.amount
                    || !text_equal_cancellable(&evidence.region, &node.name, is_cancelled)?
                {
                    return Err(ReportError::InvalidFact);
                }
            }
            "iso-pool" => {
                let slots = unique_bound(analysis, "pool-slots", &node.name, is_cancelled)?;
                let maximum =
                    unique_bound(analysis, "pool-maximum-payload", &node.name, is_cancelled)?;
                if node.owner != "runtime"
                    || node.static_bytes != 0
                    || slots.unit != "slots"
                    || slots.amount == 0
                    || maximum.unit != "bytes"
                    || maximum.amount == 0
                {
                    return Err(ReportError::InvalidFact);
                }
            }
            "iso-pool-region" => {
                let capacity = unique_bound(analysis, "region-capacity", &node.name, is_cancelled)?;
                let alignment =
                    unique_bound(analysis, "region-alignment", &node.name, is_cancelled)?;
                if indexed_image_node(analysis, &nodes, &node.owner, is_cancelled)?
                    .is_none_or(|owner| owner.kind != "iso-pool")
                    || capacity.unit != "bytes"
                    || capacity.amount != node.static_bytes
                    || alignment.unit != "bytes"
                    || !alignment.amount.is_power_of_two()
                {
                    return Err(ReportError::InvalidFact);
                }
            }
            _ => return Err(ReportError::InvalidFact),
        }
    }
    Ok(())
}

fn is_reportable_region_kind(kind: &str) -> bool {
    matches!(
        kind,
        "actor-mailbox-region"
            | "actor-turn-frame-region"
            | "task-frame-region"
            | "actor-activation-frame-region"
            | "task-activation-frame-region"
            | "iso-pool-region"
    )
}

fn valid_image_node(
    node: &ImageNodeFact,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, ReportError> {
    let (identity_kind, owner_kind, structural_source) = match node.kind.as_str() {
        "actor" => ("actor", None, Some("FlowWir.ActorPlan")),
        "task" => ("task", Some("actor"), Some("FlowWir.TaskPlan")),
        "iso-pool" => ("pool", None, None),
        "iso-pool-region" => ("region", Some("pool"), None),
        "actor-mailbox-region" | "actor-turn-frame-region" | "actor-activation-frame-region" => {
            ("region", Some("actor"), None)
        }
        "task-frame-region" | "task-activation-frame-region" => ("region", Some("task"), None),
        _ => return Ok(false),
    };
    if !canonical_named_identity(&node.name, identity_kind, is_cancelled)? {
        return Ok(false);
    }
    let owner_is_valid = match owner_kind {
        None => node.owner == "runtime",
        Some(kind) if node.kind == "task" => {
            node.owner == "runtime" || canonical_named_identity(&node.owner, kind, is_cancelled)?
        }
        Some(kind) => canonical_named_identity(&node.owner, kind, is_cancelled)?,
    };
    if !owner_is_valid {
        return Ok(false);
    }
    canonical_source_identity(&node.source, is_cancelled)
        .map(|source| source || structural_source.is_some_and(|expected| node.source == expected))
}

fn indexed_image_node<'a>(
    analysis: &'a AnalysisFacts,
    index: &[(&str, usize)],
    name: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Option<&'a ImageNodeFact>, ReportError> {
    let mut start = 0;
    let mut end = index.len();
    while start < end {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        let midpoint = start + (end - start) / 2;
        let (candidate, _) = index.get(midpoint).ok_or(ReportError::InvalidFact)?;
        match text_cmp_cancellable(candidate, name, is_cancelled)? {
            Ordering::Less => start = midpoint + 1,
            Ordering::Greater => end = midpoint,
            Ordering::Equal => {
                return Ok(index
                    .get(midpoint)
                    .and_then(|(_, position)| analysis.image_nodes.get(*position)));
            }
        }
    }
    Ok(None)
}

fn unique_bound<'a>(
    analysis: &'a AnalysisFacts,
    category: &str,
    owner: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<&'a BoundFact, ReportError> {
    let mut start = 0;
    let mut end = analysis.bounds.len();
    while start < end {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        let midpoint = start + (end - start) / 2;
        let fact = analysis
            .bounds
            .get(midpoint)
            .ok_or(ReportError::InvalidFact)?;
        if bound_key_cmp(fact, category, owner, is_cancelled)? == Ordering::Less {
            start = midpoint + 1;
        } else {
            end = midpoint;
        }
    }
    let fact = analysis.bounds.get(start).ok_or(ReportError::InvalidFact)?;
    if bound_key_cmp(fact, category, owner, is_cancelled)? != Ordering::Equal {
        return Err(ReportError::InvalidFact);
    }
    if let Some(next) = analysis.bounds.get(start + 1)
        && bound_key_cmp(next, category, owner, is_cancelled)? == Ordering::Equal
    {
        return Err(ReportError::InvalidFact);
    }
    Ok(fact)
}

fn bound_key_cmp(
    fact: &BoundFact,
    category: &str,
    owner: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Ordering, ReportError> {
    match text_cmp_cancellable(&fact.category, category, is_cancelled)? {
        Ordering::Equal => text_cmp_cancellable(&fact.owner, owner, is_cancelled),
        ordering => Ok(ordering),
    }
}

fn canonical_named_identity(
    value: &str,
    kind: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, ReportError> {
    canonical_named_identity_id(value, kind, is_cancelled).map(|identity| identity.is_some())
}

fn canonical_named_identity_id(
    value: &str,
    kind: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Option<u32>, ReportError> {
    let Some(rest) = value
        .strip_prefix(kind)
        .and_then(|rest| rest.strip_prefix(':'))
    else {
        return Ok(None);
    };
    let Some((id, name)) = rest.split_once(':') else {
        return Ok(None);
    };
    let id = canonical_u32(id, is_cancelled)?;
    if !nonempty(name, is_cancelled)? {
        return Ok(None);
    }
    Ok(id)
}

fn text_equal_cancellable(
    left: &str,
    right: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, ReportError> {
    if left.len() != right.len() {
        return Ok(false);
    }
    for (left, right) in left
        .as_bytes()
        .chunks(4_096)
        .zip(right.as_bytes().chunks(4_096))
    {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        if left != right {
            return Ok(false);
        }
    }
    if is_cancelled() {
        return Err(ReportError::Cancelled);
    }
    Ok(true)
}

fn text_cmp_cancellable(
    left: &str,
    right: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Ordering, ReportError> {
    for (left, right) in left
        .as_bytes()
        .chunks(4_096)
        .zip(right.as_bytes().chunks(4_096))
    {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        match left.cmp(right) {
            Ordering::Equal => {}
            ordering => return Ok(ordering),
        }
    }
    if is_cancelled() {
        return Err(ReportError::Cancelled);
    }
    Ok(left.len().cmp(&right.len()))
}

fn activation_region_name_matches_caller(
    region: &str,
    caller: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, ReportError> {
    const SUFFIX: &str = ".async-activation-frame";
    let Some((_, region_tail)) = region.split_once(':') else {
        return Ok(false);
    };
    let Some((_, region_name)) = region_tail.split_once(':') else {
        return Ok(false);
    };
    let Some((_, caller_tail)) = caller.split_once(':') else {
        return Ok(false);
    };
    let Some((_, caller_name)) = caller_tail.split_once(':') else {
        return Ok(false);
    };
    let Some(prefix_length) = region_name.len().checked_sub(SUFFIX.len()) else {
        return Ok(false);
    };
    let Some((prefix, suffix)) = region_name.as_bytes().split_at_checked(prefix_length) else {
        return Ok(false);
    };
    if suffix != SUFFIX.as_bytes() {
        return Ok(false);
    }
    let prefix = std::str::from_utf8(prefix).map_err(|_| ReportError::InvalidFact)?;
    text_equal_cancellable(prefix, caller_name, is_cancelled)
}

fn canonical_source_identity(
    value: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, ReportError> {
    let Some(rest) = value.strip_prefix("file:") else {
        return Ok(false);
    };
    let Some((file, range)) = rest.split_once(":bytes:") else {
        return Ok(false);
    };
    let Some((start, end)) = range.split_once("..") else {
        return Ok(false);
    };
    let Some(file) = canonical_u32(file, is_cancelled)? else {
        return Ok(false);
    };
    let Some(start) = canonical_u32(start, is_cancelled)? else {
        return Ok(false);
    };
    let Some(end) = canonical_u32(end, is_cancelled)? else {
        return Ok(false);
    };
    let _ = file;
    Ok(start <= end)
}

fn canonical_u32(value: &str, is_cancelled: &dyn Fn() -> bool) -> Result<Option<u32>, ReportError> {
    if value.is_empty() || value.len() > 10 || value.len() > 1 && value.starts_with('0') {
        return Ok(None);
    }
    let mut number = 0_u32;
    for byte in value.bytes() {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        if !byte.is_ascii_digit() {
            return Ok(None);
        }
        number = match number
            .checked_mul(10)
            .and_then(|number| number.checked_add(u32::from(byte - b'0')))
        {
            Some(number) => number,
            None => return Ok(None),
        };
    }
    Ok(Some(number))
}

fn validate_base_relocation_evidence(
    backend: &BackendFacts,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ReportError> {
    let mut nonzero_digest = false;
    for (index, byte) in backend
        .base_relocation_provenance_digest
        .as_bytes()
        .iter()
        .copied()
        .enumerate()
    {
        if index % 8 == 0 && is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        nonzero_digest |= byte != 0;
    }
    let blocks = u64::from(backend.base_relocation_blocks);
    let relocations = u64::from(backend.base_relocation_dir64_count);
    let counts_are_plausible = blocks != 0
        && relocations != 0
        && blocks <= relocations
        && blocks
            .checked_mul(512)
            .is_some_and(|maximum| relocations <= maximum);
    let minimum_bytes = blocks
        .checked_mul(8)
        .and_then(|bytes| relocations.checked_mul(2)?.checked_add(bytes));
    let maximum_bytes = minimum_bytes.and_then(|minimum| {
        blocks
            .checked_mul(2)
            .and_then(|padding| minimum.checked_add(padding))
    });
    let extent_is_plausible = minimum_bytes
        .zip(maximum_bytes)
        .is_some_and(|(minimum, maximum)| {
            backend.relocation_directory_bytes % 4 == 0
                && backend.relocation_directory_bytes >= minimum
                && backend.relocation_directory_bytes <= maximum
                && (backend.relocation_directory_bytes - minimum) % 2 == 0
                && backend.relocation_directory_bytes <= backend.artifact_bytes
        });
    if is_cancelled() {
        return Err(ReportError::Cancelled);
    }
    if !nonzero_digest || !counts_are_plausible || !extent_is_plausible {
        return Err(ReportError::InvalidMeasurement);
    }
    Ok(())
}

fn validate_backend(
    analysis: &AnalysisFacts,
    backend: &BackendFacts,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ReportError> {
    validate_base_relocation_evidence(backend, is_cancelled)?;
    require_canonical("sections", &backend.sections, is_cancelled)?;
    require_canonical("symbols", &backend.symbols, is_cancelled)?;
    require_canonical(
        "target variable reservations",
        &backend.target_variable_reservations,
        is_cancelled,
    )?;
    require_canonical(
        "optimization decisions",
        &backend.optimization_decisions,
        is_cancelled,
    )?;
    if !strictly_increasing_by(
        &backend.sections,
        |left, right| left.name < right.name,
        is_cancelled,
    )? || !strictly_increasing_by(
        &backend.symbols,
        |left, right| left.name < right.name,
        is_cancelled,
    )? || !strictly_increasing_by(
        &backend.optimization_decisions,
        |left, right| (&left.pass, &left.subject) < (&right.pass, &right.subject),
        is_cancelled,
    )? {
        return Err(ReportError::NonCanonical("named backend facts"));
    }
    for fact in &backend.target_variable_reservations {
        if invalid_bound(fact, is_cancelled)? {
            return Err(ReportError::InvalidFact);
        }
    }
    for section in &backend.sections {
        if !nonempty(&section.name, is_cancelled)?
            || !nonempty(&section.owner, is_cancelled)?
            || section.bytes == 0
        {
            return Err(ReportError::InvalidMeasurement);
        }
    }
    for symbol in &backend.symbols {
        if !nonempty(&symbol.name, is_cancelled)?
            || !nonempty(&symbol.section, is_cancelled)?
            || symbol.bytes == 0
        {
            return Err(ReportError::InvalidMeasurement);
        }
        let section = backend
            .sections
            .binary_search_by(|candidate| candidate.name.as_str().cmp(symbol.section.as_str()))
            .ok()
            .and_then(|index| backend.sections.get(index))
            .ok_or(ReportError::InvalidMeasurement)?;
        let end = symbol
            .offset
            .checked_add(symbol.bytes)
            .ok_or(ReportError::InvalidMeasurement)?;
        if end > section.bytes {
            return Err(ReportError::InvalidMeasurement);
        }
    }
    for decision in &backend.optimization_decisions {
        if !nonempty(&decision.pass, is_cancelled)?
            || !nonempty(&decision.subject, is_cancelled)?
            || !nonempty(&decision.justification, is_cancelled)?
        {
            return Err(ReportError::InvalidOptimizationDecision);
        }
        require_strictly_increasing_u32(&decision.relied_on, is_cancelled)?;
        for proof in &decision.relied_on {
            if is_cancelled() {
                return Err(ReportError::Cancelled);
            }
            let proof = usize::try_from(*proof).map_err(|_| ReportError::MeasurementOverflow)?;
            if proof >= analysis.proofs.len() {
                return Err(ReportError::InvalidOptimizationDecision);
            }
        }
    }
    Ok(())
}

fn digest_is_zero(digest: Sha256Digest) -> bool {
    digest.as_bytes().iter().all(|byte| *byte == 0)
}

fn valid_build_identity(build: &BuildIdentity) -> bool {
    [
        build.compiler,
        build.target_package,
        build.standard_library,
        build.source_graph,
        build.request,
        build.profile,
    ]
    .into_iter()
    .all(|digest| !digest_is_zero(digest))
}

const fn map_test_model_error(error: &wrela_test_model::TestModelError) -> ReportError {
    match error {
        wrela_test_model::TestModelError::Cancelled => ReportError::Cancelled,
        wrela_test_model::TestModelError::InvalidLimits => ReportError::InvalidLimits,
        wrela_test_model::TestModelError::ResourceLimit { resource, limit } => {
            ReportError::ResourceLimit {
                resource,
                limit: *limit,
            }
        }
        _ => ReportError::InvalidFact,
    }
}

fn text_equal(
    left: &str,
    right: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, ReportError> {
    if left.len() != right.len() {
        return Ok(false);
    }
    for (index, (left, right)) in left.bytes().zip(right.bytes()).enumerate() {
        if index % 4_096 == 0 && is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        if left != right {
            return Ok(false);
        }
    }
    if is_cancelled() {
        return Err(ReportError::Cancelled);
    }
    Ok(true)
}

fn invalid_bound(fact: &BoundFact, is_cancelled: &dyn Fn() -> bool) -> Result<bool, ReportError> {
    Ok(!nonempty(&fact.category, is_cancelled)?
        || !nonempty(&fact.owner, is_cancelled)?
        || !nonempty(&fact.source, is_cancelled)?
        || !nonempty(&fact.unit, is_cancelled)?)
}

fn nonempty(value: &str, is_cancelled: &dyn Fn() -> bool) -> Result<bool, ReportError> {
    for character in value.chars() {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        if !character.is_whitespace() {
            return Ok(true);
        }
    }
    Ok(false)
}

fn require_canonical<T: Ord>(
    kind: &'static str,
    values: &[T],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ReportError> {
    for pair in values.windows(2) {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        if pair[0] >= pair[1] {
            return Err(ReportError::NonCanonical(kind));
        }
    }
    Ok(())
}

fn require_nonempty_unique(
    kind: &'static str,
    values: &[String],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ReportError> {
    require_nonempty_values(values, is_cancelled)?;
    let limit = u64::try_from(values.len()).map_err(|_| ReportError::MeasurementOverflow)?;
    let mut workspace = Vec::new();
    workspace
        .try_reserve_exact(values.len())
        .map_err(|_| ReportError::ResourceLimit {
            resource: "canonical uniqueness workspace",
            limit,
        })?;
    for value in values {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        workspace.push(value.as_str());
    }
    cancellable_sort(&mut workspace, is_cancelled)?;
    require_canonical(kind, &workspace, is_cancelled)
}

fn require_nonempty_values(
    values: &[String],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ReportError> {
    for value in values {
        if !nonempty(value, is_cancelled)? {
            return Err(ReportError::InvalidFact);
        }
    }
    Ok(())
}

fn require_sorted_unique(
    kind: &'static str,
    values: &[String],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ReportError> {
    for value in values {
        if !nonempty(value, is_cancelled)? {
            return Err(ReportError::NonCanonical(kind));
        }
    }
    require_canonical(kind, values, is_cancelled)
}

fn strictly_increasing_by<T>(
    values: &[T],
    less: impl Fn(&T, &T) -> bool,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, ReportError> {
    for pair in values.windows(2) {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        if !less(&pair[0], &pair[1]) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn require_strictly_increasing_u32(
    values: &[u32],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ReportError> {
    for pair in values.windows(2) {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        if pair[0] >= pair[1] {
            return Err(ReportError::InvalidOptimizationDecision);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportError {
    Cancelled,
    InvalidLimits,
    ResourceLimit { resource: &'static str, limit: u64 },
    MeasurementOverflow,
    IdentityMismatch,
    UnsupportedSchema(u32),
    InvalidScalar,
    InvalidRepresentations,
    InvalidMeasurement,
    InvalidFact,
    InvalidOptimizationDecision,
    InvalidEncoding(&'static str),
    NonCanonical(&'static str),
}

impl fmt::Display for ReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("image report construction was cancelled"),
            Self::InvalidLimits => formatter.write_str("image report limits must be nonzero"),
            Self::ResourceLimit { resource, limit } => {
                write!(formatter, "{resource} exceeded limit {limit}")
            }
            Self::MeasurementOverflow => {
                formatter.write_str("image report measurement arithmetic overflowed")
            }
            Self::IdentityMismatch => {
                formatter.write_str("image report facts describe a different build or image")
            }
            Self::UnsupportedSchema(schema) => {
                write!(formatter, "unsupported image report schema {schema}")
            }
            Self::InvalidScalar => {
                formatter.write_str("image report has an invalid name or artifact size")
            }
            Self::InvalidRepresentations => {
                formatter.write_str("image report representation versions are incomplete")
            }
            Self::InvalidMeasurement => formatter
                .write_str("image report contains an invalid section or symbol measurement"),
            Self::InvalidFact => {
                formatter.write_str("image report contains an incomplete or invalid fact")
            }
            Self::InvalidOptimizationDecision => {
                formatter.write_str("image report contains an invalid optimization decision")
            }
            Self::InvalidEncoding(kind) => {
                write!(
                    formatter,
                    "image report contains an invalid {kind} encoding"
                )
            }
            Self::NonCanonical(kind) => {
                write!(formatter, "image report {kind} are not canonical")
            }
        }
    }
}

impl std::error::Error for ReportError {}

fn json_string_array(
    output: &mut String,
    values: &[String],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ReportError> {
    output.push('[');
    for (index, value) in values.iter().enumerate() {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        if index != 0 {
            output.push(',');
        }
        push_json_string_cancellable(output, value, is_cancelled)?;
    }
    output.push(']');
    Ok(())
}

fn json_compiled_test_group(
    output: &mut String,
    group: Option<&wrela_test_model::FullImageTestGroup>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ReportError> {
    let Some(group) = group else {
        output.push_str("null");
        return Ok(());
    };
    if is_cancelled() {
        return Err(ReportError::Cancelled);
    }
    output.push('{');
    json_number(output, "id", u64::from(group.id.0), false);
    json_string(output, "name", &group.name, true, is_cancelled)?;
    output.push_str(",\"root\":{");
    match &group.root {
        wrela_test_model::ImageRoot::GeneratedHarness { harness_name } => {
            json_string(output, "kind", "generated-harness", false, is_cancelled)?;
            json_string(output, "harness_name", harness_name, true, is_cancelled)?;
        }
        wrela_test_model::ImageRoot::Declared {
            image_name,
            scenario,
        } => {
            json_string(output, "kind", "declared-image", false, is_cancelled)?;
            json_string(output, "image_name", image_name, true, is_cancelled)?;
            json_number(output, "scenario", u64::from(scenario.0), true);
        }
    }
    output.push_str("},\"tests\":[");
    for (index, test) in group.tests.iter().enumerate() {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        if index != 0 {
            output.push(',');
        }
        output.push('{');
        json_number(output, "id", u64::from(test.descriptor.id.0), false);
        json_string(output, "name", &test.descriptor.name, true, is_cancelled)?;
        json_string(
            output,
            "kind",
            match test.descriptor.kind {
                wrela_test_model::TestKind::ComptimeUnit => "comptime-unit",
                wrela_test_model::TestKind::IntegrationImage => "integration-image",
                wrela_test_model::TestKind::DeclaredImage => "declared-image",
            },
            true,
            is_cancelled,
        )?;
        output.push_str(",\"source\":");
        if let Some(source) = test.descriptor.source {
            output.push('{');
            json_number(output, "file", u64::from(source.file.0), false);
            json_number(output, "start", u64::from(source.range.start), true);
            json_number(output, "end", u64::from(source.range.end), true);
            output.push('}');
        } else {
            output.push_str("null");
        }
        json_number(output, "timeout_ns", test.descriptor.timeout_ns, true);
        output.push_str(",\"invocation\":{");
        match test.invocation {
            wrela_test_model::ImageTestInvocation::GeneratedFunction { function_key } => {
                json_string(output, "kind", "generated-function", false, is_cancelled)?;
                json_digest(output, "function_key_sha256", function_key.0, true);
            }
            wrela_test_model::ImageTestInvocation::DeclaredScenario => {
                json_string(output, "kind", "declared-scenario", false, is_cancelled)?;
            }
        }
        output.push_str("},\"assertions\":[");
        for (assertion_index, assertion) in test.assertions.iter().enumerate() {
            if assertion_index != 0 {
                output.push(',');
            }
            output.push_str("{\"source\":{");
            json_number(output, "file", u64::from(assertion.source.file.0), false);
            json_number(
                output,
                "start",
                u64::from(assertion.source.range.start),
                true,
            );
            json_number(output, "end", u64::from(assertion.source.range.end), true);
            output.push('}');
            json_string(
                output,
                "expression",
                &assertion.expression,
                true,
                is_cancelled,
            )?;
            output.push_str(",\"message\":");
            if let Some(message) = &assertion.message {
                push_json_string(output, message);
            } else {
                output.push_str("null");
            }
            output.push('}');
        }
        output.push_str("]}");
    }
    output.push(']');
    json_optional_number(output, "deterministic_seed", group.deterministic_seed, true);
    json_number(output, "boot_timeout_ns", group.boot_timeout_ns, true);
    json_number(
        output,
        "shutdown_timeout_ns",
        group.shutdown_timeout_ns,
        true,
    );
    json_number(
        output,
        "maximum_events",
        u64::from(group.maximum_events),
        true,
    );
    json_number(
        output,
        "maximum_output_bytes",
        group.maximum_output_bytes,
        true,
    );
    output.push('}');
    Ok(())
}

fn json_u32_array(
    output: &mut String,
    values: &[u32],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ReportError> {
    output.push('[');
    for (index, value) in values.iter().enumerate() {
        if is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        if index != 0 {
            output.push(',');
        }
        push_u64(output, u64::from(*value));
    }
    output.push(']');
    Ok(())
}

fn json_string(
    output: &mut String,
    name: &str,
    value: &str,
    comma: bool,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ReportError> {
    if comma {
        output.push(',');
    }
    push_json_string(output, name);
    output.push(':');
    push_json_string_cancellable(output, value, is_cancelled)
}

fn json_digest(output: &mut String, name: &str, value: Sha256Digest, comma: bool) {
    if comma {
        output.push(',');
    }
    push_json_string(output, name);
    output.push_str(":\"");
    push_digest_hex(output, value);
    output.push('"');
}

fn push_digest_hex(output: &mut String, value: Sha256Digest) {
    for byte in value.as_bytes() {
        output.push(hex_digit(*byte >> 4));
        output.push(hex_digit(*byte & 0x0f));
    }
}

fn json_number(output: &mut String, name: &str, value: u64, comma: bool) {
    if comma {
        output.push(',');
    }
    push_json_string(output, name);
    output.push(':');
    push_u64(output, value);
}

fn json_optional_number(output: &mut String, name: &str, value: Option<u64>, comma: bool) {
    if comma {
        output.push(',');
    }
    push_json_string(output, name);
    output.push(':');
    match value {
        Some(value) => push_u64(output, value),
        None => output.push_str("null"),
    }
}

fn push_json_string(output: &mut String, value: &str) {
    output.push('"');
    for character in value.chars() {
        push_json_character(output, character);
    }
    output.push('"');
}

fn push_json_string_cancellable(
    output: &mut String,
    value: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ReportError> {
    output.push('"');
    for (index, character) in value.chars().enumerate() {
        if index % 1_024 == 0 && is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        push_json_character(output, character);
    }
    output.push('"');
    if is_cancelled() {
        return Err(ReportError::Cancelled);
    }
    Ok(())
}

fn push_json_character(output: &mut String, character: char) {
    match character {
        '"' => output.push_str("\\\""),
        '\\' => output.push_str("\\\\"),
        '\n' => output.push_str("\\n"),
        '\r' => output.push_str("\\r"),
        '\t' => output.push_str("\\t"),
        character if character.is_control() => {
            let scalar = character as u32;
            output.push_str("\\u");
            output.push(hex_digit(((scalar >> 12) & 0x0f) as u8));
            output.push(hex_digit(((scalar >> 8) & 0x0f) as u8));
            output.push(hex_digit(((scalar >> 4) & 0x0f) as u8));
            output.push(hex_digit((scalar & 0x0f) as u8));
        }
        character => output.push(character),
    }
}

fn push_text_cancellable(
    output: &mut String,
    value: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ReportError> {
    for (index, character) in value.chars().enumerate() {
        if index % 1_024 == 0 && is_cancelled() {
            return Err(ReportError::Cancelled);
        }
        output.push(character);
    }
    if is_cancelled() {
        return Err(ReportError::Cancelled);
    }
    Ok(())
}

fn push_u64(output: &mut String, mut value: u64) {
    let mut digits = [0u8; 20];
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = b'0' + u8::try_from(value % 10).expect("one decimal digit fits in u8");
        value /= 10;
        if value == 0 {
            break;
        }
    }
    for digit in &digits[start..] {
        output.push(char::from(*digit));
    }
}

const fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + value - 10) as char,
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use wrela_build_model::{BuildIdentity, LanguageRevision, Sha256Digest, TargetIdentity};

    use super::{
        ActivationCancellationFact, ActivationFrameEvidenceFact, ActivationFrameResetFact,
        ActorPlacementInputFact, AnalysisFactLimits, AnalysisFactRequest, AnalysisFacts,
        BackendFactLimits, BackendFacts, BoundFact, ImageEdgeFact, ImageNodeFact, ImageReport,
        IsoPoolFact, OptimizationAction, OptimizationDecisionFact, PromotionFact, ProofFact,
        RegionAssignmentFact, RegionCapacityEvidenceFact, RegionClass, ReportError,
        SchedulerOwnershipFact, SectionFact, SymbolFact, ValidatedAnalysisFacts, WorkFact,
        cancellable_sort, decode_image_report_json, push_json_string_cancellable,
        seal_analysis_facts,
    };

    fn build(digest: Sha256Digest) -> BuildIdentity {
        BuildIdentity {
            compiler: digest,
            language: LanguageRevision::Design0_1,
            target: TargetIdentity::aarch64_qemu_virt_uefi(),
            target_package: digest,
            standard_library: digest,
            source_graph: digest,
            request: digest,
            profile: digest,
        }
    }

    fn backend(digest: Sha256Digest) -> BackendFacts {
        BackendFacts {
            flow_wir_digest: digest,
            artifact_bytes: 42,
            artifact_digest: digest,
            relocation_directory_bytes: 12,
            base_relocation_blocks: 1,
            base_relocation_dir64_count: 1,
            base_relocation_provenance_digest: digest,
            sections: Vec::new(),
            symbols: Vec::new(),
            representations: super::RepresentationFacts {
                semantic_wir_version: 15,
                flow_wir_version: 19,
                flow_wir_wire_version: 19,
                machine_wir_version: 21,
                runtime_abi_version: 2,
                optimization_pipeline_name: "fixture".to_owned(),
                optimization_pipeline_revision: 1,
                optimization_pipeline_implementation: digest,
            },
            required_runtime_intrinsics: Vec::new(),
            target_variable_reservations: Vec::new(),
            excluded_target_variables: Vec::new(),
            optimization_decisions: Vec::new(),
        }
    }

    fn sealed_analysis(
        digest: Sha256Digest,
        image_name: &str,
        facts: AnalysisFacts,
    ) -> ValidatedAnalysisFacts {
        let build = build(digest);
        seal_analysis_facts(
            AnalysisFactRequest {
                build: &build,
                image_name,
                limits: AnalysisFactLimits::standard(),
            },
            facts,
            &|| false,
        )
        .expect("valid analysis facts")
    }

    fn assemble(
        digest: Sha256Digest,
        facts: AnalysisFacts,
        backend: BackendFacts,
    ) -> Result<ImageReport, ReportError> {
        ImageReport::new(
            build(digest),
            "image".to_owned(),
            sealed_analysis(digest, "image", facts),
            backend,
            BackendFactLimits::standard(),
            &|| false,
        )
    }

    fn actor_region_facts() -> AnalysisFacts {
        AnalysisFacts {
            bounds: vec![
                BoundFact {
                    category: "actor-mailbox".to_owned(),
                    owner: "actor:0:root".to_owned(),
                    source: "ActorPlan.mailbox_capacity".to_owned(),
                    amount: 8,
                    unit: "messages".to_owned(),
                },
                BoundFact {
                    category: "actor-mailbox".to_owned(),
                    owner: "actor:1:worker".to_owned(),
                    source: "ActorPlan.mailbox_capacity".to_owned(),
                    amount: 4,
                    unit: "messages".to_owned(),
                },
                BoundFact {
                    category: "task-slots".to_owned(),
                    owner: "task:0:flush".to_owned(),
                    source: "TaskPlan.slots".to_owned(),
                    amount: 2,
                    unit: "slots".to_owned(),
                },
                BoundFact {
                    category: "task-frame".to_owned(),
                    owner: "task:0:flush".to_owned(),
                    source: "TaskPlan.frame_bytes_bound".to_owned(),
                    amount: 16,
                    unit: "bytes".to_owned(),
                },
                BoundFact {
                    category: "region-capacity".to_owned(),
                    owner: "region:0:mailbox".to_owned(),
                    source: "RegionPlan.capacity_bytes".to_owned(),
                    amount: 64,
                    unit: "bytes".to_owned(),
                },
                BoundFact {
                    category: "region-alignment".to_owned(),
                    owner: "region:0:mailbox".to_owned(),
                    source: "RegionPlan.alignment".to_owned(),
                    amount: 8,
                    unit: "bytes".to_owned(),
                },
                BoundFact {
                    category: "region-capacity".to_owned(),
                    owner: "region:1:turn".to_owned(),
                    source: "RegionPlan.capacity_bytes".to_owned(),
                    amount: 16,
                    unit: "bytes".to_owned(),
                },
                BoundFact {
                    category: "region-alignment".to_owned(),
                    owner: "region:1:turn".to_owned(),
                    source: "RegionPlan.alignment".to_owned(),
                    amount: 8,
                    unit: "bytes".to_owned(),
                },
                BoundFact {
                    category: "region-capacity".to_owned(),
                    owner: "region:2:task-frame".to_owned(),
                    source: "RegionPlan.capacity_bytes".to_owned(),
                    amount: 16,
                    unit: "bytes".to_owned(),
                },
                BoundFact {
                    category: "region-alignment".to_owned(),
                    owner: "region:2:task-frame".to_owned(),
                    source: "RegionPlan.alignment".to_owned(),
                    amount: 8,
                    unit: "bytes".to_owned(),
                },
                BoundFact {
                    category: "region-capacity".to_owned(),
                    owner: "region:3:worker_turn.async-activation-frame".to_owned(),
                    source: "RegionPlan.capacity_bytes".to_owned(),
                    amount: 8,
                    unit: "bytes".to_owned(),
                },
                BoundFact {
                    category: "region-alignment".to_owned(),
                    owner: "region:3:worker_turn.async-activation-frame".to_owned(),
                    source: "RegionPlan.alignment".to_owned(),
                    amount: 8,
                    unit: "bytes".to_owned(),
                },
                BoundFact {
                    category: "region-capacity".to_owned(),
                    owner: "region:4:flush_task.async-activation-frame".to_owned(),
                    source: "RegionPlan.capacity_bytes".to_owned(),
                    amount: 16,
                    unit: "bytes".to_owned(),
                },
                BoundFact {
                    category: "region-alignment".to_owned(),
                    owner: "region:4:flush_task.async-activation-frame".to_owned(),
                    source: "RegionPlan.alignment".to_owned(),
                    amount: 8,
                    unit: "bytes".to_owned(),
                },
            ],
            proofs: vec![
                ProofFact {
                    id: 0,
                    category: "capacity-bound".to_owned(),
                    subject: "actor/task region capacities".to_owned(),
                    result: "proved".to_owned(),
                    bound: Some(1),
                    sources: vec!["file:0:bytes:21..30".to_owned()],
                    depends_on: Vec::new(),
                    why_chain: vec!["sealed FlowWir capacity proof".to_owned()],
                },
                ProofFact {
                    id: 1,
                    category: "cleanup-acyclic".to_owned(),
                    subject: "actor helper cleanup".to_owned(),
                    result: "proved".to_owned(),
                    bound: Some(0),
                    sources: vec!["file:0:bytes:51..60".to_owned()],
                    depends_on: Vec::new(),
                    why_chain: vec!["drop actor helper frame".to_owned()],
                },
                ProofFact {
                    id: 2,
                    category: "capacity-bound".to_owned(),
                    subject: "actor helper activation".to_owned(),
                    result: "proved".to_owned(),
                    bound: Some(1),
                    sources: vec!["file:0:bytes:51..60".to_owned()],
                    depends_on: vec![1],
                    why_chain: vec!["one actor helper frame".to_owned()],
                },
                ProofFact {
                    id: 3,
                    category: "cleanup-acyclic".to_owned(),
                    subject: "task helper cleanup".to_owned(),
                    result: "proved".to_owned(),
                    bound: Some(0),
                    sources: vec!["file:0:bytes:61..70".to_owned()],
                    depends_on: Vec::new(),
                    why_chain: vec!["drop task helper frame".to_owned()],
                },
                ProofFact {
                    id: 4,
                    category: "capacity-bound".to_owned(),
                    subject: "task helper activation".to_owned(),
                    result: "proved".to_owned(),
                    bound: Some(1),
                    sources: vec!["file:0:bytes:61..70".to_owned()],
                    depends_on: vec![3],
                    why_chain: vec!["one task helper frame".to_owned()],
                },
            ],
            image_nodes: vec![
                ImageNodeFact {
                    kind: "actor".to_owned(),
                    name: "actor:0:root".to_owned(),
                    owner: "runtime".to_owned(),
                    source: "file:0:bytes:10..20".to_owned(),
                    static_bytes: 0,
                },
                ImageNodeFact {
                    kind: "actor".to_owned(),
                    name: "actor:1:worker".to_owned(),
                    owner: "runtime".to_owned(),
                    source: "FlowWir.ActorPlan".to_owned(),
                    static_bytes: 0,
                },
                ImageNodeFact {
                    kind: "task".to_owned(),
                    name: "task:0:flush".to_owned(),
                    owner: "actor:1:worker".to_owned(),
                    source: "FlowWir.TaskPlan".to_owned(),
                    static_bytes: 0,
                },
                ImageNodeFact {
                    kind: "actor-mailbox-region".to_owned(),
                    name: "region:0:mailbox".to_owned(),
                    owner: "actor:1:worker".to_owned(),
                    source: "file:0:bytes:21..30".to_owned(),
                    static_bytes: 64,
                },
                ImageNodeFact {
                    kind: "actor-turn-frame-region".to_owned(),
                    name: "region:1:turn".to_owned(),
                    owner: "actor:1:worker".to_owned(),
                    source: "file:0:bytes:31..40".to_owned(),
                    static_bytes: 16,
                },
                ImageNodeFact {
                    kind: "task-frame-region".to_owned(),
                    name: "region:2:task-frame".to_owned(),
                    owner: "task:0:flush".to_owned(),
                    source: "file:0:bytes:41..50".to_owned(),
                    static_bytes: 16,
                },
                ImageNodeFact {
                    kind: "actor-activation-frame-region".to_owned(),
                    name: "region:3:worker_turn.async-activation-frame".to_owned(),
                    owner: "actor:1:worker".to_owned(),
                    source: "file:0:bytes:51..60".to_owned(),
                    static_bytes: 8,
                },
                ImageNodeFact {
                    kind: "task-activation-frame-region".to_owned(),
                    name: "region:4:flush_task.async-activation-frame".to_owned(),
                    owner: "task:0:flush".to_owned(),
                    source: "file:0:bytes:61..70".to_owned(),
                    static_bytes: 16,
                },
            ],
            region_capacity_evidence: vec![
                RegionCapacityEvidenceFact {
                    region: "region:0:mailbox".to_owned(),
                    capacity_proof: 0,
                },
                RegionCapacityEvidenceFact {
                    region: "region:1:turn".to_owned(),
                    capacity_proof: 0,
                },
                RegionCapacityEvidenceFact {
                    region: "region:2:task-frame".to_owned(),
                    capacity_proof: 0,
                },
                RegionCapacityEvidenceFact {
                    region: "region:3:worker_turn.async-activation-frame".to_owned(),
                    capacity_proof: 2,
                },
                RegionCapacityEvidenceFact {
                    region: "region:4:flush_task.async-activation-frame".to_owned(),
                    capacity_proof: 4,
                },
            ],
            activation_frame_evidence: vec![
                ActivationFrameEvidenceFact {
                    plan: 0,
                    region: "region:3:worker_turn.async-activation-frame".to_owned(),
                    caller: "function:0:worker_turn".to_owned(),
                    callee: "function:1:actor_helper".to_owned(),
                    owner: "actor:1:worker".to_owned(),
                    source: "file:0:bytes:51..60".to_owned(),
                    frame_bytes: 8,
                    maximum_live: 1,
                    cancellation: ActivationCancellationFact::DropCalleeThenPropagate,
                    capacity_proof: 2,
                },
                ActivationFrameEvidenceFact {
                    plan: 1,
                    region: "region:4:flush_task.async-activation-frame".to_owned(),
                    caller: "function:2:flush_task".to_owned(),
                    callee: "function:3:task_helper".to_owned(),
                    owner: "task:0:flush".to_owned(),
                    source: "file:0:bytes:61..70".to_owned(),
                    frame_bytes: 16,
                    maximum_live: 1,
                    cancellation: ActivationCancellationFact::DropCalleeThenPropagate,
                    capacity_proof: 4,
                },
            ],
            image_edges: vec![
                ImageEdgeFact {
                    kind: "actor-supervision".to_owned(),
                    source: "actor:1:worker".to_owned(),
                    destination: "actor:0:root".to_owned(),
                    capacity: None,
                    priority: Some(2),
                },
                ImageEdgeFact {
                    kind: "task-supervision".to_owned(),
                    source: "task:0:flush".to_owned(),
                    destination: "actor:1:worker".to_owned(),
                    capacity: Some(2),
                    priority: Some(3),
                },
            ],
            work: vec![
                WorkFact {
                    function: "function:0:worker_turn".to_owned(),
                    stack_bytes: 8,
                    frame_bytes: 8,
                    uninterrupted_work: None,
                    checkpoint_count: 0,
                },
                WorkFact {
                    function: "function:1:actor_helper".to_owned(),
                    stack_bytes: 8,
                    frame_bytes: 8,
                    uninterrupted_work: None,
                    checkpoint_count: 0,
                },
                WorkFact {
                    function: "function:2:flush_task".to_owned(),
                    stack_bytes: 16,
                    frame_bytes: 16,
                    uninterrupted_work: None,
                    checkpoint_count: 0,
                },
                WorkFact {
                    function: "function:3:task_helper".to_owned(),
                    stack_bytes: 16,
                    frame_bytes: 16,
                    uninterrupted_work: None,
                    checkpoint_count: 0,
                },
            ],
            ..AnalysisFacts::default()
        }
    }

    fn iso_pool_facts() -> AnalysisFacts {
        AnalysisFacts {
            bounds: vec![
                BoundFact {
                    category: "pool-slots".to_owned(),
                    owner: "pool:0:Payloads".to_owned(),
                    source: "Semantic.PoolNode.capacity".to_owned(),
                    amount: 2,
                    unit: "slots".to_owned(),
                },
                BoundFact {
                    category: "pool-maximum-payload".to_owned(),
                    owner: "pool:0:Payloads".to_owned(),
                    source: "Semantic.Region.capacity_bytes/Semantic.PoolNode.capacity".to_owned(),
                    amount: 64,
                    unit: "bytes".to_owned(),
                },
                BoundFact {
                    category: "pool-payload".to_owned(),
                    owner: "type:2:pool-payload".to_owned(),
                    source: "Semantic.SemanticType.size_upper_bound".to_owned(),
                    amount: 8,
                    unit: "bytes".to_owned(),
                },
                BoundFact {
                    category: "region-capacity".to_owned(),
                    owner: "region:0:Payloads".to_owned(),
                    source: "Semantic.Region.capacity_bytes".to_owned(),
                    amount: 128,
                    unit: "bytes".to_owned(),
                },
                BoundFact {
                    category: "region-alignment".to_owned(),
                    owner: "region:0:Payloads".to_owned(),
                    source: "Semantic.Region.alignment".to_owned(),
                    amount: 8,
                    unit: "bytes".to_owned(),
                },
            ],
            proofs: vec![ProofFact {
                id: 0,
                category: "capacity-bound".to_owned(),
                subject: "iso pool slots: Payloads".to_owned(),
                result: "proved".to_owned(),
                bound: Some(2),
                sources: vec![
                    "file:0:bytes:100..170".to_owned(),
                    "file:0:bytes:125..133".to_owned(),
                    "file:0:bytes:141..142".to_owned(),
                    "file:0:bytes:156..158".to_owned(),
                ],
                depends_on: Vec::new(),
                why_chain: vec!["exact generative pool capacity".to_owned()],
            }],
            image_nodes: vec![
                ImageNodeFact {
                    kind: "iso-pool".to_owned(),
                    name: "pool:0:Payloads".to_owned(),
                    owner: "runtime".to_owned(),
                    source: "file:0:bytes:100..170".to_owned(),
                    static_bytes: 0,
                },
                ImageNodeFact {
                    kind: "iso-pool-region".to_owned(),
                    name: "region:0:Payloads".to_owned(),
                    owner: "pool:0:Payloads".to_owned(),
                    source: "file:0:bytes:100..170".to_owned(),
                    static_bytes: 128,
                },
            ],
            region_capacity_evidence: vec![RegionCapacityEvidenceFact {
                region: "region:0:Payloads".to_owned(),
                capacity_proof: 0,
            }],
            iso_pools: vec![IsoPoolFact {
                pool: "pool:0:Payloads".to_owned(),
                brand: "brand:0:Payloads".to_owned(),
                region: "region:0:Payloads".to_owned(),
                payload_type: "type:2:pool-payload".to_owned(),
                owner: "pool:0:Payloads".to_owned(),
                source: "file:0:bytes:100..170".to_owned(),
                brand_source: "file:0:bytes:125..133".to_owned(),
                slots_source: "file:0:bytes:141..142".to_owned(),
                maximum_payload_source: "file:0:bytes:156..158".to_owned(),
                payload_source: "file:0:bytes:20..60".to_owned(),
                slots: 2,
                maximum_payload_bytes: 64,
                payload_bytes: 8,
                alignment: 8,
                capacity_proof: 0,
            }],
            startup_order: vec!["runtime".to_owned(), "pool:0:Payloads".to_owned()],
            shutdown_order: vec!["pool:0:Payloads".to_owned(), "runtime".to_owned()],
            ..AnalysisFacts::default()
        }
    }

    #[test]
    fn actor_task_region_graph_is_canonical_bounded_and_cancellable() {
        let digest = Sha256Digest::from_bytes([0x44; 32]);
        let facts = actor_region_facts();
        let items = [
            facts.bounds.len(),
            facts.proofs.len(),
            facts.image_nodes.len(),
            facts.region_capacity_evidence.len(),
            facts.activation_frame_evidence.len(),
            facts.image_edges.len(),
            facts.work.len(),
        ]
        .into_iter()
        .try_fold(0_u64, |total, count| {
            total.checked_add(u64::try_from(count).expect("bounded graph fact count"))
        })
        .expect("bounded graph fact total");
        let proof_edges = facts
            .proofs
            .iter()
            .map(|proof| proof.sources.len() + proof.depends_on.len() + proof.why_chain.len())
            .try_fold(0_u64, |total, count| {
                total.checked_add(u64::try_from(count).expect("bounded proof edge count"))
            })
            .expect("bounded proof edge total");
        let limits = AnalysisFactLimits {
            items,
            proof_edges,
            payload_bytes: 64 * 1024,
        };
        let build = build(digest);
        let request = AnalysisFactRequest {
            build: &build,
            image_name: "image",
            limits,
        };
        let sealed = seal_analysis_facts(request, facts.clone(), &|| false)
            .expect("exact actor/task/region graph limit");
        assert_eq!(super::REPORT_SCHEMA_VERSION, 18);
        assert_eq!(sealed.as_facts().image_nodes.len(), 8);
        assert_eq!(sealed.as_facts().region_capacity_evidence.len(), 5);
        assert_eq!(sealed.as_facts().activation_frame_evidence.len(), 2);
        assert_eq!(sealed.as_facts().image_edges.len(), 2);
        assert_eq!(
            sealed
                .as_facts()
                .activation_frame_evidence
                .iter()
                .map(|fact| fact.plan)
                .collect::<Vec<_>>(),
            [0, 1]
        );
        let report = ImageReport::new(
            build.clone(),
            "image".to_owned(),
            sealed.clone(),
            backend(digest),
            BackendFactLimits::standard(),
            &|| false,
        )
        .expect("schema-v16 activation report");
        let json = report.to_json();
        assert!(json.contains("\"activation_frame_evidence\":[{"));
        assert!(json.contains("\"kind\":\"actor-activation-frame-region\""));
        assert!(json.contains("\"kind\":\"task-activation-frame-region\""));
        assert_eq!(
            decode_image_report_json(
                json.as_bytes(),
                &build,
                limits,
                BackendFactLimits::standard(),
                u64::try_from(json.len()).expect("bounded activation report bytes"),
                &|| false,
            )
            .expect("decode exact schema-v16 activation evidence"),
            report
        );
        let corrupt_cancellation = json.replacen(
            "drop-callee-then-propagate",
            "retain-callee-and-propagate",
            1,
        );
        assert!(matches!(
            decode_image_report_json(
                corrupt_cancellation.as_bytes(),
                &build,
                limits,
                BackendFactLimits::standard(),
                u64::try_from(corrupt_cancellation.len())
                    .expect("bounded corrupt activation report bytes"),
                &|| false,
            ),
            Err(ReportError::InvalidEncoding("activation cancellation"))
        ));
        let corrupt_bound = json.replacen(
            "\"id\":2,\"category\":\"capacity-bound\",\"subject\":\"actor helper activation\",\"result\":\"proved\",\"bound\":1",
            "\"id\":2,\"category\":\"capacity-bound\",\"subject\":\"actor helper activation\",\"result\":\"proved\",\"bound\":2",
            1,
        );
        assert!(matches!(
            decode_image_report_json(
                corrupt_bound.as_bytes(),
                &build,
                limits,
                BackendFactLimits::standard(),
                u64::try_from(corrupt_bound.len()).expect("bounded corrupt proof bound bytes"),
                &|| false,
            ),
            Err(ReportError::InvalidFact)
        ));
        let corrupt_source = json.replacen(
            "\"bound\":1,\"sources\":[\"file:0:bytes:51..60\"],\"depends_on\":[1]",
            "\"bound\":1,\"sources\":[\"file:0:bytes:52..60\"],\"depends_on\":[1]",
            1,
        );
        assert!(matches!(
            decode_image_report_json(
                corrupt_source.as_bytes(),
                &build,
                limits,
                BackendFactLimits::standard(),
                u64::try_from(corrupt_source.len()).expect("bounded corrupt proof source bytes"),
                &|| false,
            ),
            Err(ReportError::InvalidFact)
        ));
        let corrupt_dependency = json.replacen(
            "\"depends_on\":[1],\"why_chain\":[\"one actor helper frame\"]",
            "\"depends_on\":[0],\"why_chain\":[\"one actor helper frame\"]",
            1,
        );
        assert!(matches!(
            decode_image_report_json(
                corrupt_dependency.as_bytes(),
                &build,
                limits,
                BackendFactLimits::standard(),
                u64::try_from(corrupt_dependency.len())
                    .expect("bounded corrupt proof dependency bytes"),
                &|| false,
            ),
            Err(ReportError::InvalidFact)
        ));
        let mut omitted_activation = json.clone();
        let activation_start = omitted_activation
            .find("\"activation_frame_evidence\":[")
            .expect("activation evidence field");
        let activation_end = omitted_activation[activation_start..]
            .find("],\"activation_frame_resets\":[")
            .and_then(|offset| activation_start.checked_add(offset + 1))
            .expect("activation evidence extent");
        omitted_activation.replace_range(
            activation_start..activation_end,
            "\"activation_frame_evidence\":[]",
        );
        assert!(matches!(
            decode_image_report_json(
                omitted_activation.as_bytes(),
                &build,
                limits,
                BackendFactLimits::standard(),
                u64::try_from(omitted_activation.len()).expect("bounded omitted activation bytes"),
                &|| false,
            ),
            Err(ReportError::InvalidFact)
        ));
        let mut reversed = facts.clone();
        reversed.activation_frame_evidence.reverse();
        reversed.region_capacity_evidence.reverse();
        reversed.image_nodes.reverse();
        reversed.proofs.reverse();
        assert_eq!(
            seal_analysis_facts(request, reversed, &|| false)
                .expect("deterministically canonicalized activation facts"),
            sealed
        );
        let one_below = items.checked_sub(1).expect("nonempty graph fact set");
        assert!(matches!(
            seal_analysis_facts(
                AnalysisFactRequest {
                    limits: AnalysisFactLimits {
                        items: one_below,
                        ..limits
                    },
                    ..request
                },
                facts.clone(),
                &|| false,
            ),
            Err(ReportError::ResourceLimit {
                resource: "analysis fact items",
                limit,
            }) if limit == one_below
        ));

        let polls = Cell::new(0_u64);
        seal_analysis_facts(request, facts.clone(), &|| {
            polls.set(
                polls
                    .get()
                    .checked_add(1)
                    .expect("bounded graph cancellation polls"),
            );
            false
        })
        .expect("measure graph cancellation polls");
        let cancel_at = polls.get();
        let polls = Cell::new(0_u64);
        assert_eq!(
            seal_analysis_facts(request, facts, &|| {
                let next = polls
                    .get()
                    .checked_add(1)
                    .expect("bounded graph cancellation polls");
                polls.set(next);
                next == cancel_at
            }),
            Err(ReportError::Cancelled)
        );
    }

    fn completed_activation_reset_facts() -> AnalysisFacts {
        let mut facts = actor_region_facts();
        facts.activation_frame_resets = vec![ActivationFrameResetFact {
            plan: 1,
            region: "region:4:flush_task.async-activation-frame".to_owned(),
            owner: "task:0:flush".to_owned(),
            source: "file:0:bytes:61..70".to_owned(),
            region_class: RegionClass::TaskFrame,
            capacity_bytes: 16,
            alignment: 8,
            capacity_proof: 4,
            capacity_bound: 1,
        }];
        facts
    }

    #[test]
    fn completed_activation_frame_reset_is_exact_sealed_bounded_and_round_trips() {
        let digest = Sha256Digest::from_bytes([0x4b; 32]);
        let build = build(digest);
        let facts = completed_activation_reset_facts();
        let measured = super::measure_analysis(
            &facts,
            "reset-image",
            AnalysisFactLimits::standard(),
            &|| false,
        )
        .expect("measure exact completed-activation reset facts");
        let exact = AnalysisFactLimits {
            items: measured.0,
            proof_edges: measured.1,
            payload_bytes: measured.2,
        };
        let request = AnalysisFactRequest {
            build: &build,
            image_name: "reset-image",
            limits: exact,
        };
        let sealed = seal_analysis_facts(request, facts.clone(), &|| false)
            .expect("exact completed-activation reset limit");
        assert_eq!(
            sealed.as_facts().activation_frame_resets,
            [ActivationFrameResetFact {
                plan: 1,
                region: "region:4:flush_task.async-activation-frame".to_owned(),
                owner: "task:0:flush".to_owned(),
                source: "file:0:bytes:61..70".to_owned(),
                region_class: RegionClass::TaskFrame,
                capacity_bytes: 16,
                alignment: 8,
                capacity_proof: 4,
                capacity_bound: 1,
            }]
        );
        let report = ImageReport::new(
            build.clone(),
            "reset-image".to_owned(),
            sealed,
            backend(digest),
            BackendFactLimits::standard(),
            &|| false,
        )
        .expect("completed-activation reset report");
        let json = report.to_json();
        assert!(json.contains(
            "\"activation_frame_resets\":[{\"plan\":1,\"region\":\"region:4:flush_task.async-activation-frame\",\"owner\":\"task:0:flush\",\"source\":\"file:0:bytes:61..70\",\"region_class\":\"task-frame\",\"capacity_bytes\":16,\"alignment\":8,\"capacity_proof\":4,\"capacity_bound\":1}]"
        ));
        assert_eq!(
            decode_image_report_json(
                json.as_bytes(),
                &build,
                exact,
                BackendFactLimits::standard(),
                u64::try_from(json.len()).expect("bounded reset report bytes"),
                &|| false,
            )
            .expect("canonical completed-activation reset round trip"),
            report
        );

        // Every substitution that would let the reset describe a different
        // region contract than the one FlowWir authenticated must fail closed.
        for (mutate_index, mutate) in [
            |facts: &mut AnalysisFacts| facts.activation_frame_resets[0].plan = 0,
            |facts: &mut AnalysisFacts| facts.activation_frame_resets[0].plan = 2,
            |facts: &mut AnalysisFacts| {
                facts.activation_frame_resets[0].region =
                    "region:3:worker_turn.async-activation-frame".to_owned();
            },
            |facts: &mut AnalysisFacts| {
                facts.activation_frame_resets[0].owner = "actor:1:worker".to_owned();
            },
            |facts: &mut AnalysisFacts| {
                facts.activation_frame_resets[0].source = "file:0:bytes:61..71".to_owned();
            },
            |facts: &mut AnalysisFacts| {
                facts.activation_frame_resets[0].region_class = RegionClass::Call;
            },
            |facts: &mut AnalysisFacts| facts.activation_frame_resets[0].capacity_bytes = 8,
            |facts: &mut AnalysisFacts| facts.activation_frame_resets[0].alignment = 16,
            |facts: &mut AnalysisFacts| facts.activation_frame_resets[0].capacity_proof = 2,
            |facts: &mut AnalysisFacts| facts.activation_frame_resets[0].capacity_bound = 2,
        ]
        .into_iter()
        .enumerate()
        {
            let mut forged = facts.clone();
            mutate(&mut forged);
            assert!(
                matches!(
                    seal_analysis_facts(
                        AnalysisFactRequest {
                            limits: AnalysisFactLimits::standard(),
                            ..request
                        },
                        forged,
                        &|| false,
                    ),
                    Err(ReportError::InvalidFact)
                ),
                "reset forgery {mutate_index} must fail closed"
            );
        }

        // Two reset records for one activation plan are rejected as
        // noncanonical before any join runs, so a duplicated reset can never be
        // read as two bounded resets.
        let mut duplicated = facts.clone();
        let duplicate = duplicated.activation_frame_resets[0].clone();
        duplicated.activation_frame_resets.push(duplicate);
        assert_eq!(
            seal_analysis_facts(
                AnalysisFactRequest {
                    limits: AnalysisFactLimits::standard(),
                    ..request
                },
                duplicated,
                &|| false,
            ),
            Err(ReportError::NonCanonical("activation frame resets"))
        );

        for (resource, limits) in [
            (
                "analysis fact items",
                AnalysisFactLimits {
                    items: exact.items - 1,
                    ..exact
                },
            ),
            (
                "analysis fact payload",
                AnalysisFactLimits {
                    payload_bytes: exact.payload_bytes - 1,
                    ..exact
                },
            ),
        ] {
            assert!(matches!(
                seal_analysis_facts(
                    AnalysisFactRequest { limits, ..request },
                    facts.clone(),
                    &|| false,
                ),
                Err(ReportError::ResourceLimit { resource: actual, .. }) if actual == resource
            ));
        }

        let polls = Cell::new(0_u64);
        seal_analysis_facts(request, facts.clone(), &|| {
            polls.set(
                polls
                    .get()
                    .checked_add(1)
                    .expect("bounded reset cancellation polls"),
            );
            false
        })
        .expect("measure reset cancellation polls");
        let cancel_at = polls.get();
        let polls = Cell::new(0_u64);
        assert_eq!(
            seal_analysis_facts(request, facts, &|| {
                let next = polls
                    .get()
                    .checked_add(1)
                    .expect("bounded reset cancellation polls");
                polls.set(next);
                next == cancel_at
            }),
            Err(ReportError::Cancelled)
        );
    }

    #[test]
    fn iso_pool_contract_is_exact_independently_sealed_bounded_and_cancellable() {
        let digest = Sha256Digest::from_bytes([0x47; 32]);
        let build = build(digest);
        let facts = iso_pool_facts();
        let measured = super::measure_analysis(
            &facts,
            "pool-image",
            AnalysisFactLimits::standard(),
            &|| false,
        )
        .expect("measure exact pool facts");
        let exact = AnalysisFactLimits {
            items: measured.0,
            proof_edges: measured.1,
            payload_bytes: measured.2,
        };
        let sealed = seal_analysis_facts(
            AnalysisFactRequest {
                build: &build,
                image_name: "pool-image",
                limits: exact,
            },
            facts.clone(),
            &|| false,
        )
        .expect("exact pool report limit");
        assert_eq!(sealed.as_facts().iso_pools, facts.iso_pools);
        let encoded = ImageReport::new(
            build.clone(),
            "pool-image".to_owned(),
            sealed,
            backend(digest),
            BackendFactLimits::standard(),
            &|| false,
        )
        .expect("pool image report")
        .to_json();
        let decoded = decode_image_report_json(
            encoded.as_bytes(),
            &build,
            exact,
            BackendFactLimits::standard(),
            u64::MAX,
            &|| false,
        )
        .expect("canonical pool report round trip");
        assert_eq!(decoded.analysis().iso_pools, facts.iso_pools);

        for (resource, limits) in [
            (
                "analysis fact items",
                AnalysisFactLimits {
                    items: exact.items - 1,
                    ..exact
                },
            ),
            (
                "analysis proof edges",
                AnalysisFactLimits {
                    proof_edges: exact.proof_edges - 1,
                    ..exact
                },
            ),
            (
                "analysis fact payload",
                AnalysisFactLimits {
                    payload_bytes: exact.payload_bytes - 1,
                    ..exact
                },
            ),
        ] {
            assert!(matches!(
                seal_analysis_facts(
                    AnalysisFactRequest {
                        build: &build,
                        image_name: "pool-image",
                        limits,
                    },
                    facts.clone(),
                    &|| false,
                ),
                Err(ReportError::ResourceLimit { resource: actual, .. }) if actual == resource
            ));
        }

        let mut forged = facts.clone();
        forged.iso_pools[0].maximum_payload_bytes = 63;
        assert!(matches!(
            seal_analysis_facts(
                AnalysisFactRequest {
                    build: &build,
                    image_name: "pool-image",
                    limits: AnalysisFactLimits::standard(),
                },
                forged,
                &|| false,
            ),
            Err(ReportError::InvalidFact)
        ));

        let polls = Cell::new(0u32);
        seal_analysis_facts(
            AnalysisFactRequest {
                build: &build,
                image_name: "pool-image",
                limits: AnalysisFactLimits::standard(),
            },
            facts.clone(),
            &|| {
                polls.set(polls.get().saturating_add(1));
                false
            },
        )
        .expect("baseline pool report polls");
        let final_poll = polls.get();
        polls.set(0);
        assert!(matches!(
            seal_analysis_facts(
                AnalysisFactRequest {
                    build: &build,
                    image_name: "pool-image",
                    limits: AnalysisFactLimits::standard(),
                },
                facts,
                &|| {
                    let next = polls.get().saturating_add(1);
                    polls.set(next);
                    next >= final_poll
                },
            ),
            Err(ReportError::Cancelled)
        ));
        assert_eq!(polls.get(), final_poll);
    }

    #[test]
    fn scheduler_ownership_is_canonical_exact_bounded_and_fail_closed() {
        let digest = Sha256Digest::from_bytes([0x46; 32]);
        let build = build(digest);
        let request = |items| AnalysisFactRequest {
            build: &build,
            image_name: "scheduler-image",
            limits: AnalysisFactLimits {
                items,
                proof_edges: 1,
                payload_bytes: 64,
            },
        };
        let mut facts = AnalysisFacts {
            scheduler_ownership: vec![SchedulerOwnershipFact {
                core: 0,
                actors: vec!["actor:1:worker".to_owned(), "actor:0:root".to_owned()],
                tasks: vec!["task:0:flush".to_owned()],
            }],
            ..AnalysisFacts::default()
        };
        let sealed = seal_analysis_facts(request(4), facts.clone(), &|| false)
            .expect("one scheduler row and its three exact owners fit four items");
        assert_eq!(
            sealed.as_facts().scheduler_ownership[0].actors,
            ["actor:0:root", "actor:1:worker"]
        );
        assert_eq!(
            seal_analysis_facts(request(3), facts.clone(), &|| false),
            Err(ReportError::ResourceLimit {
                resource: "analysis fact items",
                limit: 3,
            })
        );

        facts.scheduler_ownership[0].actors[0] = "actor:0:root".to_owned();
        assert_eq!(
            seal_analysis_facts(request(4), facts, &|| false),
            Err(ReportError::InvalidFact)
        );
        let gapped = AnalysisFacts {
            scheduler_ownership: vec![SchedulerOwnershipFact {
                core: 1,
                actors: Vec::new(),
                tasks: Vec::new(),
            }],
            ..AnalysisFacts::default()
        };
        assert_eq!(
            seal_analysis_facts(request(1), gapped, &|| false),
            Err(ReportError::InvalidFact)
        );
    }

    #[test]
    fn actor_placement_inputs_are_canonical_exact_bounded_and_fail_closed() {
        let digest = Sha256Digest::from_bytes([0x47; 32]);
        let build = build(digest);
        let request = |items| AnalysisFactRequest {
            build: &build,
            image_name: "placement-input-image",
            limits: AnalysisFactLimits {
                items,
                proof_edges: 1,
                payload_bytes: 128,
            },
        };
        let facts = AnalysisFacts {
            actor_placement_inputs: vec![
                ActorPlacementInputFact {
                    actor: "actor:1:worker".to_owned(),
                    maximum_uninterrupted_work: 7,
                    reserved_region_bytes: 65,
                },
                ActorPlacementInputFact {
                    actor: "actor:0:root".to_owned(),
                    maximum_uninterrupted_work: 11,
                    reserved_region_bytes: 129,
                },
            ],
            scheduler_ownership: vec![SchedulerOwnershipFact {
                core: 0,
                actors: vec!["actor:1:worker".to_owned(), "actor:0:root".to_owned()],
                tasks: Vec::new(),
            }],
            ..AnalysisFacts::default()
        };
        let sealed = seal_analysis_facts(request(5), facts.clone(), &|| false)
            .expect("two placement inputs, ownership row, and two owner links fit exactly");
        assert_eq!(
            sealed.as_facts().actor_placement_inputs[0].actor,
            "actor:0:root"
        );
        assert_eq!(
            seal_analysis_facts(request(4), facts.clone(), &|| false),
            Err(ReportError::ResourceLimit {
                resource: "analysis fact items",
                limit: 4,
            })
        );

        let mut zero_reserved = facts.clone();
        zero_reserved.actor_placement_inputs[0].reserved_region_bytes = 0;
        assert_eq!(
            seal_analysis_facts(request(5), zero_reserved, &|| false),
            Err(ReportError::InvalidFact)
        );
        let mut partial = facts.clone();
        partial.actor_placement_inputs.pop();
        assert_eq!(
            seal_analysis_facts(request(4), partial, &|| false),
            Err(ReportError::InvalidFact)
        );
        let mut duplicate = facts;
        duplicate.actor_placement_inputs[1].actor = "actor:1:worker".to_owned();
        assert!(matches!(
            seal_analysis_facts(request(5), duplicate, &|| false),
            Err(ReportError::InvalidFact | ReportError::NonCanonical(_))
        ));
    }

    #[test]
    fn actor_task_region_graph_rejects_identity_role_capacity_and_proof_substitution() {
        let digest = Sha256Digest::from_bytes([0x45; 32]);
        let build = build(digest);
        let request = AnalysisFactRequest {
            build: &build,
            image_name: "image",
            limits: AnalysisFactLimits::standard(),
        };
        let reject = |facts| {
            assert!(matches!(
                seal_analysis_facts(request, facts, &|| false),
                Err(ReportError::InvalidFact | ReportError::NonCanonical(_))
            ));
        };

        let mut stale_destination = actor_region_facts();
        stale_destination.image_edges[0].destination = "actor:0".to_owned();
        reject(stale_destination);

        let mut wrong_capacity = actor_region_facts();
        wrong_capacity.image_nodes[3].static_bytes = 63;
        reject(wrong_capacity);

        let mut wrong_role = actor_region_facts();
        wrong_role.image_nodes[5].owner = "actor:1:worker".to_owned();
        reject(wrong_role);

        let mut stale_identity = actor_region_facts();
        stale_identity.image_nodes[0].name = "actor:00:root".to_owned();
        reject(stale_identity);

        let mut wrong_proof = actor_region_facts();
        wrong_proof.proofs[0].category = "ownership".to_owned();
        reject(wrong_proof);

        let mut missing_link = actor_region_facts();
        missing_link.region_capacity_evidence.pop();
        reject(missing_link);

        let mut duplicate_link = actor_region_facts();
        duplicate_link
            .region_capacity_evidence
            .push(duplicate_link.region_capacity_evidence[0].clone());
        reject(duplicate_link);

        let mut dangling_proof = actor_region_facts();
        dangling_proof.region_capacity_evidence[0].capacity_proof = 1;
        reject(dangling_proof);

        let mut actor_link = actor_region_facts();
        actor_link.region_capacity_evidence[0].region = "actor:0:root".to_owned();
        reject(actor_link);

        let mut dangling_region = actor_region_facts();
        dangling_region.region_capacity_evidence[0].region = "region:9:absent".to_owned();
        reject(dangling_region);

        let mut noncanonical_region = actor_region_facts();
        noncanonical_region.region_capacity_evidence[0].region = "region:00:mailbox".to_owned();
        reject(noncanonical_region);

        let mut wrong_bound_owner = actor_region_facts();
        wrong_bound_owner.bounds[4].owner = "region:9:substituted".to_owned();
        reject(wrong_bound_owner);

        let mut wrong_slots = actor_region_facts();
        wrong_slots.image_edges[1].capacity = Some(3);
        reject(wrong_slots);

        let mut reversed_source = actor_region_facts();
        reversed_source.image_nodes[3].source = "file:0:bytes:30..21".to_owned();
        reject(reversed_source);

        let mut invented_source = actor_region_facts();
        invented_source.image_nodes[3].source = "FlowWir.RegionPlan".to_owned();
        reject(invented_source);

        let mut missing_activation = actor_region_facts();
        missing_activation.activation_frame_evidence.pop();
        reject(missing_activation);

        let mut duplicate_activation = actor_region_facts();
        duplicate_activation
            .activation_frame_evidence
            .push(duplicate_activation.activation_frame_evidence[0].clone());
        reject(duplicate_activation);

        let mut substituted_activation_owner = actor_region_facts();
        substituted_activation_owner.activation_frame_evidence[0].owner = "task:0:flush".to_owned();
        reject(substituted_activation_owner);

        let mut substituted_activation_kind = actor_region_facts();
        substituted_activation_kind
            .image_nodes
            .iter_mut()
            .find(|node| node.kind == "actor-activation-frame-region")
            .expect("actor activation node")
            .kind = "task-activation-frame-region".to_owned();
        reject(substituted_activation_kind);

        let mut substituted_activation_proof = actor_region_facts();
        substituted_activation_proof.activation_frame_evidence[0].capacity_proof = 4;
        reject(substituted_activation_proof);

        let mut substituted_activation_source = actor_region_facts();
        substituted_activation_source.activation_frame_evidence[0].source =
            "file:0:bytes:52..60".to_owned();
        reject(substituted_activation_source);

        let mut substituted_activation_bound = actor_region_facts();
        substituted_activation_bound.proofs[2].bound = Some(2);
        reject(substituted_activation_bound);

        let mut substituted_activation_proof_source = actor_region_facts();
        substituted_activation_proof_source.proofs[2].sources[0] = "file:0:bytes:52..60".to_owned();
        reject(substituted_activation_proof_source);

        let mut substituted_activation_cleanup = actor_region_facts();
        substituted_activation_cleanup.proofs[2].depends_on[0] = 0;
        reject(substituted_activation_cleanup);

        let mut substituted_activation_callee = actor_region_facts();
        substituted_activation_callee.activation_frame_evidence[0].callee =
            "function:3:task_helper".to_owned();
        reject(substituted_activation_callee);

        let mut substituted_activation_region = actor_region_facts();
        substituted_activation_region.activation_frame_evidence[0].region =
            "region:4:flush_task.async-activation-frame".to_owned();
        reject(substituted_activation_region);

        let mut over_live_activation = actor_region_facts();
        over_live_activation.activation_frame_evidence[0].maximum_live = 2;
        reject(over_live_activation);

        let mut orphan_activation_node = actor_region_facts();
        orphan_activation_node
            .image_nodes
            .iter_mut()
            .find(|node| node.kind == "actor-turn-frame-region")
            .expect("actor turn region")
            .kind = "actor-activation-frame-region".to_owned();
        reject(orphan_activation_node);
    }

    #[test]
    fn activation_text_joins_poll_interior_chunks_at_the_exact_stop() {
        let caller_name = "helper".repeat(2_048);
        let caller = format!("function:0:{caller_name}");
        let region_name = format!("region:0:{caller_name}.async-activation-frame");
        let calls = Cell::new(0_u64);
        assert!(
            super::activation_region_name_matches_caller(&region_name, &caller, &|| {
                calls.set(
                    calls
                        .get()
                        .checked_add(1)
                        .expect("bounded comparison polls"),
                );
                false
            })
            .expect("bounded activation-name comparison")
        );
        let exact_stop = calls.get();
        assert!(exact_stop > 2, "long comparison polls interior chunks");
        let calls = Cell::new(0_u64);
        assert_eq!(
            super::activation_region_name_matches_caller(&region_name, &caller, &|| {
                let next = calls
                    .get()
                    .checked_add(1)
                    .expect("bounded comparison polls");
                calls.set(next);
                next == exact_stop
            }),
            Err(ReportError::Cancelled)
        );

        let left = "雪".repeat(4_097);
        let calls = Cell::new(0_u64);
        assert!(
            super::text_equal_cancellable(&left, &left, &|| {
                calls.set(calls.get().checked_add(1).expect("bounded text polls"));
                false
            })
            .expect("bounded exact text comparison")
        );
        let exact_stop = calls.get();
        let calls = Cell::new(0_u64);
        assert_eq!(
            super::text_equal_cancellable(&left, &left, &|| {
                let next = calls.get().checked_add(1).expect("bounded text polls");
                calls.set(next);
                next == exact_stop
            }),
            Err(ReportError::Cancelled)
        );
    }

    #[test]
    fn report_json_is_deterministic_and_escaped() {
        let digest = Sha256Digest::from_bytes([1; 32]);
        let report = ImageReport::new(
            build(digest),
            "a\"b".to_owned(),
            sealed_analysis(digest, "a\"b", AnalysisFacts::default()),
            backend(digest),
            BackendFactLimits::standard(),
            &|| false,
        )
        .expect("valid report");
        let json = report.to_json();
        assert!(json.contains("\"image_name\":\"a\\\"b\""));
        assert_eq!(json, report.to_json());
        serde_json::from_str::<serde_json::Value>(&json).expect("valid JSON");
    }

    #[test]
    fn constructor_canonicalizes_fact_sets_and_proof_links() {
        let digest = Sha256Digest::from_bytes([2; 32]);
        let mut analysis = AnalysisFacts {
            proofs: vec![
                ProofFact {
                    id: 1,
                    category: "ownership".to_owned(),
                    subject: "z".to_owned(),
                    result: "proved".to_owned(),
                    bound: None,
                    sources: Vec::new(),
                    depends_on: vec![0],
                    why_chain: vec!["z".to_owned()],
                },
                ProofFact {
                    id: 0,
                    category: "capacity".to_owned(),
                    subject: "a".to_owned(),
                    result: "proved".to_owned(),
                    bound: Some(1),
                    sources: Vec::new(),
                    depends_on: Vec::new(),
                    why_chain: vec!["a".to_owned()],
                },
            ],
            ..AnalysisFacts::default()
        };
        analysis.startup_order = vec!["device".to_owned(), "actor".to_owned()];
        let mut backend = backend(digest);
        backend.sections = vec![
            SectionFact {
                name: ".text.z".to_owned(),
                owner: "image".to_owned(),
                bytes: 16,
            },
            SectionFact {
                name: ".text.a".to_owned(),
                owner: "image".to_owned(),
                bytes: 8,
            },
        ];
        backend.symbols = vec![SymbolFact {
            name: "entry".to_owned(),
            section: ".text.a".to_owned(),
            offset: 0,
            bytes: 8,
        }];
        backend.optimization_decisions = vec![OptimizationDecisionFact {
            pass: "cleanup".to_owned(),
            subject: "call".to_owned(),
            action: OptimizationAction::Retained,
            justification: "observable".to_owned(),
            relied_on: vec![1, 0],
        }];

        let report = ImageReport::new(
            build(digest),
            "image".to_owned(),
            sealed_analysis(digest, "image", analysis),
            backend,
            BackendFactLimits::standard(),
            &|| false,
        )
        .expect("canonical report");
        assert_eq!(
            report
                .analysis()
                .proofs
                .iter()
                .map(|proof| proof.id)
                .collect::<Vec<_>>(),
            [0, 1]
        );
        assert_eq!(report.backend().sections[0].name, ".text.a");
        assert_eq!(report.backend().optimization_decisions[0].relied_on, [0, 1]);
    }

    #[test]
    fn symbol_measurements_cannot_escape_their_section() {
        let digest = Sha256Digest::from_bytes([3; 32]);
        let mut backend = backend(digest);
        backend.sections.push(SectionFact {
            name: ".text".to_owned(),
            owner: "image".to_owned(),
            bytes: 4,
        });
        backend.symbols.push(SymbolFact {
            name: "entry".to_owned(),
            section: ".text".to_owned(),
            offset: 4,
            bytes: 1,
        });
        assert!(matches!(
            ImageReport::new(
                build(digest),
                "image".to_owned(),
                sealed_analysis(digest, "image", AnalysisFacts::default()),
                backend,
                BackendFactLimits::standard(),
                &|| false,
            ),
            Err(ReportError::InvalidMeasurement)
        ));
    }

    #[test]
    fn analysis_and_backend_candidates_are_bounded_before_publication() {
        let digest = Sha256Digest::from_bytes([4; 32]);
        let analysis_build = build(digest);
        let analysis_error = seal_analysis_facts(
            AnalysisFactRequest {
                build: &analysis_build,
                image_name: "image",
                limits: AnalysisFactLimits {
                    items: 1,
                    proof_edges: 1,
                    payload_bytes: 4,
                },
            },
            AnalysisFacts {
                startup_order: vec!["actor".to_owned()],
                ..AnalysisFacts::default()
            },
            &|| false,
        );
        assert!(matches!(
            analysis_error,
            Err(ReportError::ResourceLimit {
                resource: "analysis fact payload",
                limit: 4
            })
        ));

        let mut backend = backend(digest);
        backend.required_runtime_intrinsics = vec!["runtime.poll".to_owned()];
        assert!(matches!(
            ImageReport::new(
                build(digest),
                "image".to_owned(),
                sealed_analysis(digest, "image", AnalysisFacts::default()),
                backend,
                BackendFactLimits {
                    items: 1,
                    optimization_proof_edges: 1,
                    payload_bytes: 4,
                },
                &|| false,
            ),
            Err(ReportError::ResourceLimit {
                resource: "backend fact payload",
                limit: 4
            })
        ));
    }

    #[test]
    fn analysis_facts_cannot_cross_build_or_image_boundaries() {
        let digest = Sha256Digest::from_bytes([5; 32]);
        assert!(matches!(
            ImageReport::new(
                build(digest),
                "other-image".to_owned(),
                sealed_analysis(digest, "image", AnalysisFacts::default()),
                backend(digest),
                BackendFactLimits::standard(),
                &|| false,
            ),
            Err(ReportError::IdentityMismatch)
        ));
    }

    #[test]
    fn ordinary_scalar_backend_fixture_round_trips_with_exact_extents() {
        let build_digest = Sha256Digest::from_bytes([0x31; 32]);
        let flow_digest = Sha256Digest::from_bytes([0x32; 32]);
        let artifact_digest = Sha256Digest::from_bytes([0x33; 32]);
        let facts = AnalysisFacts {
            reachable_declarations: 1,
            monomorphized_instantiations: 1,
            work: vec![WorkFact {
                function: "wrela_image_entry".to_owned(),
                stack_bytes: 16,
                frame_bytes: 16,
                uninterrupted_work: Some(1),
                checkpoint_count: 0,
            }],
            ..AnalysisFacts::default()
        };
        let mut backend = backend(build_digest);
        backend.flow_wir_digest = flow_digest;
        backend.artifact_bytes = 1_024;
        backend.artifact_digest = artifact_digest;
        backend.sections = vec![
            SectionFact {
                name: ".rdata".to_owned(),
                owner: "linked-image-layout".to_owned(),
                bytes: 8,
            },
            SectionFact {
                name: ".text".to_owned(),
                owner: "image".to_owned(),
                bytes: 16,
            },
        ];
        backend.symbols = vec![SymbolFact {
            name: "wrela_image_entry".to_owned(),
            section: ".text".to_owned(),
            offset: 0,
            bytes: 16,
        }];
        backend.required_runtime_intrinsics = vec!["wrela.runtime.enter".to_owned()];

        let report = assemble(build_digest, facts, backend).expect("ordinary scalar report");
        let json = report
            .to_json_with_cancellation(&|| false)
            .expect("bounded canonical encoding");
        let decoded = decode_image_report_json(
            json.as_bytes(),
            &build(build_digest),
            AnalysisFactLimits::standard(),
            BackendFactLimits::standard(),
            u64::try_from(json.len()).expect("fixture JSON length"),
            &|| false,
        )
        .expect("authenticate ordinary scalar report");

        assert_eq!(decoded, report);
        assert_eq!(decoded.backend().flow_wir_digest, flow_digest);
        assert_eq!(decoded.backend().artifact_digest, artifact_digest);
        assert_eq!(decoded.backend().symbols[0].offset, 0);
        assert_eq!(decoded.backend().symbols[0].bytes, 16);
    }

    #[test]
    fn base_relocation_evidence_accepts_minimum_and_representative_extents() {
        let digest = Sha256Digest::from_bytes([0x67; 32]);
        let minimum = assemble(digest, AnalysisFacts::default(), backend(digest))
            .expect("minimum one-block DIR64 relocation evidence");
        assert_eq!(minimum.schema(), 18);
        assert_eq!(minimum.backend().relocation_directory_bytes, 12);
        assert_eq!(minimum.backend().base_relocation_blocks, 1);
        assert_eq!(minimum.backend().base_relocation_dir64_count, 1);

        let mut representative = backend(digest);
        representative.artifact_bytes = 4_096;
        representative.relocation_directory_bytes = 24;
        representative.base_relocation_blocks = 2;
        representative.base_relocation_dir64_count = 3;
        representative.base_relocation_provenance_digest = Sha256Digest::from_bytes([0x68; 32]);
        let representative = assemble(digest, AnalysisFacts::default(), representative)
            .expect("representative padded two-block relocation evidence");
        let json = representative.to_json();
        assert!(json.contains("\"base_relocation_dir64_count\":3"));
        assert!(json.contains(&format!(
            "\"base_relocation_provenance_sha256\":\"{}\"",
            "68".repeat(32)
        )));

        let polls = Cell::new(0_u64);
        representative
            .validate_with_cancellation(&|| {
                polls.set(
                    polls
                        .get()
                        .checked_add(1)
                        .expect("bounded relocation validation polls"),
                );
                false
            })
            .expect("measure relocation validation cancellation polls");
        let cancel_at = polls.get();
        let polls = Cell::new(0_u64);
        assert_eq!(
            representative.validate_with_cancellation(&|| {
                let next = polls
                    .get()
                    .checked_add(1)
                    .expect("bounded relocation validation polls");
                polls.set(next);
                next == cancel_at
            }),
            Err(ReportError::Cancelled)
        );
    }

    #[test]
    fn base_relocation_zero_digest_counts_and_impossible_extents_fail_closed() {
        let digest = Sha256Digest::from_bytes([0x69; 32]);
        let reject = |candidate| {
            assert_eq!(
                assemble(digest, AnalysisFacts::default(), candidate),
                Err(ReportError::InvalidMeasurement)
            );
        };

        let mut zero_digest = backend(digest);
        zero_digest.base_relocation_provenance_digest = Sha256Digest::from_bytes([0; 32]);
        reject(zero_digest);

        let mut zero_blocks = backend(digest);
        zero_blocks.base_relocation_blocks = 0;
        reject(zero_blocks);

        let mut zero_relocations = backend(digest);
        zero_relocations.base_relocation_dir64_count = 0;
        reject(zero_relocations);

        let mut too_many_blocks = backend(digest);
        too_many_blocks.base_relocation_blocks = 2;
        reject(too_many_blocks);

        let mut unaligned_directory = backend(digest);
        unaligned_directory.relocation_directory_bytes = 10;
        reject(unaligned_directory);

        let mut directory_outside_artifact = backend(digest);
        directory_outside_artifact.artifact_bytes = 8;
        reject(directory_outside_artifact);
    }

    #[test]
    fn zero_digests_and_zero_extents_fail_closed() {
        let digest = Sha256Digest::from_bytes([6; 32]);
        let zero = Sha256Digest::from_bytes([0; 32]);

        let mut candidate = backend(digest);
        candidate.flow_wir_digest = zero;
        assert_eq!(
            assemble(digest, AnalysisFacts::default(), candidate),
            Err(ReportError::InvalidMeasurement)
        );

        let mut candidate = backend(digest);
        candidate.artifact_digest = zero;
        assert_eq!(
            assemble(digest, AnalysisFacts::default(), candidate),
            Err(ReportError::InvalidMeasurement)
        );

        let mut candidate = backend(digest);
        candidate
            .representations
            .optimization_pipeline_implementation = zero;
        assert_eq!(
            assemble(digest, AnalysisFacts::default(), candidate),
            Err(ReportError::InvalidRepresentations)
        );

        let mut candidate = backend(digest);
        candidate.sections.push(SectionFact {
            name: ".text".to_owned(),
            owner: "image".to_owned(),
            bytes: 0,
        });
        assert_eq!(
            assemble(digest, AnalysisFacts::default(), candidate),
            Err(ReportError::InvalidMeasurement)
        );

        let mut candidate = backend(digest);
        candidate.sections.push(SectionFact {
            name: ".text".to_owned(),
            owner: "image".to_owned(),
            bytes: 1,
        });
        candidate.symbols.push(SymbolFact {
            name: "entry".to_owned(),
            section: ".text".to_owned(),
            offset: 0,
            bytes: 0,
        });
        assert_eq!(
            assemble(digest, AnalysisFacts::default(), candidate),
            Err(ReportError::InvalidMeasurement)
        );

        assert_eq!(
            seal_analysis_facts(
                AnalysisFactRequest {
                    build: &build(zero),
                    image_name: "image",
                    limits: AnalysisFactLimits::standard(),
                },
                AnalysisFacts::default(),
                &|| false,
            ),
            Err(ReportError::IdentityMismatch)
        );
    }

    #[test]
    fn every_non_current_representation_version_fails_closed() {
        let digest = Sha256Digest::from_bytes([0x6a; 32]);
        let mutations: [fn(&mut super::RepresentationFacts); 10] = [
            |versions| versions.semantic_wir_version = 14,
            |versions| versions.semantic_wir_version = 16,
            |versions| versions.flow_wir_version = 18,
            |versions| versions.flow_wir_version = 20,
            |versions| versions.flow_wir_wire_version = 18,
            |versions| versions.flow_wir_wire_version = 20,
            |versions| versions.machine_wir_version = 20,
            |versions| versions.machine_wir_version = 22,
            |versions| versions.runtime_abi_version = 1,
            |versions| versions.runtime_abi_version = 3,
        ];

        for mutate in mutations {
            let mut candidate = backend(digest);
            mutate(&mut candidate.representations);
            assert_eq!(
                assemble(digest, AnalysisFacts::default(), candidate),
                Err(ReportError::InvalidRepresentations)
            );
        }
    }

    #[test]
    fn duplicate_backend_identities_are_rejected_after_sorting() {
        let digest = Sha256Digest::from_bytes([7; 32]);
        let mut duplicate_sections = backend(digest);
        duplicate_sections.sections = vec![
            SectionFact {
                name: ".text".to_owned(),
                owner: "first".to_owned(),
                bytes: 8,
            },
            SectionFact {
                name: ".text".to_owned(),
                owner: "second".to_owned(),
                bytes: 8,
            },
        ];
        assert_eq!(
            assemble(digest, AnalysisFacts::default(), duplicate_sections),
            Err(ReportError::NonCanonical("named backend facts"))
        );

        let mut duplicate_symbols = backend(digest);
        duplicate_symbols.sections.push(SectionFact {
            name: ".text".to_owned(),
            owner: "image".to_owned(),
            bytes: 8,
        });
        duplicate_symbols.symbols = vec![
            SymbolFact {
                name: "entry".to_owned(),
                section: ".text".to_owned(),
                offset: 0,
                bytes: 4,
            },
            SymbolFact {
                name: "entry".to_owned(),
                section: ".text".to_owned(),
                offset: 4,
                bytes: 4,
            },
        ];
        assert_eq!(
            assemble(digest, AnalysisFacts::default(), duplicate_symbols),
            Err(ReportError::NonCanonical("named backend facts"))
        );
    }

    #[test]
    fn exact_resource_boundaries_are_accepted_before_canonical_sorting() {
        let digest = Sha256Digest::from_bytes([8; 32]);
        let facts = AnalysisFacts {
            startup_order: vec!["b".to_owned(), "a".to_owned()],
            ..AnalysisFacts::default()
        };
        let exact_analysis_limits = AnalysisFactLimits {
            items: 2,
            proof_edges: 1,
            payload_bytes: 7,
        };
        let analysis_build = build(digest);
        let exact_analysis = seal_analysis_facts(
            AnalysisFactRequest {
                build: &analysis_build,
                image_name: "image",
                limits: exact_analysis_limits,
            },
            facts.clone(),
            &|| false,
        )
        .expect("exact analysis boundary");
        assert_eq!(exact_analysis.as_facts().startup_order, ["b", "a"]);
        assert!(matches!(
            seal_analysis_facts(
                AnalysisFactRequest {
                    build: &analysis_build,
                    image_name: "image",
                    limits: AnalysisFactLimits {
                        items: 1,
                        ..exact_analysis_limits
                    },
                },
                facts,
                &|| false,
            ),
            Err(ReportError::ResourceLimit {
                resource: "analysis fact items",
                limit: 1
            })
        ));

        let mut backend = backend(digest);
        backend.required_runtime_intrinsics = vec!["z".to_owned(), "a".to_owned()];
        let exact_backend_limits = BackendFactLimits {
            items: 2,
            optimization_proof_edges: 1,
            payload_bytes: 9,
        };
        let report = ImageReport::new(
            build(digest),
            "image".to_owned(),
            exact_analysis,
            backend,
            exact_backend_limits,
            &|| false,
        )
        .expect("exact backend boundary");
        assert_eq!(report.backend().required_runtime_intrinsics, ["a", "z"]);
    }

    #[test]
    fn item_limit_preempts_sort_and_heapsort_observes_cancellation() {
        let digest = Sha256Digest::from_bytes([9; 32]);
        let analysis_build = build(digest);
        let checks = Cell::new(0usize);
        let never_cancelled = || {
            checks.set(checks.get() + 1);
            false
        };
        let result = seal_analysis_facts(
            AnalysisFactRequest {
                build: &analysis_build,
                image_name: "image",
                limits: AnalysisFactLimits {
                    items: 1,
                    proof_edges: 1,
                    payload_bytes: 5,
                },
            },
            AnalysisFacts {
                bounds: vec![
                    super::BoundFact {
                        category: "z".to_owned(),
                        owner: "z".to_owned(),
                        source: "z".to_owned(),
                        amount: 1,
                        unit: "z".to_owned(),
                    },
                    super::BoundFact {
                        category: "a".to_owned(),
                        owner: "a".to_owned(),
                        source: "a".to_owned(),
                        amount: 1,
                        unit: "a".to_owned(),
                    },
                ],
                ..AnalysisFacts::default()
            },
            &never_cancelled,
        );
        assert!(matches!(
            result,
            Err(ReportError::ResourceLimit {
                resource: "analysis fact items",
                limit: 1
            })
        ));
        assert_eq!(checks.get(), 2, "limit must trip during item measurement");

        let sort_checks = Cell::new(0usize);
        let cancel_sort = || {
            let next = sort_checks.get() + 1;
            sort_checks.set(next);
            next > 16
        };
        let mut values = (0u32..256).rev().collect::<Vec<_>>();
        assert_eq!(
            cancellable_sort(&mut values, &cancel_sort),
            Err(ReportError::Cancelled)
        );
    }

    #[test]
    fn long_json_string_encoding_observes_cancellation() {
        let value = "x".repeat(8 * 1_024);
        let mut output = String::new();
        output
            .try_reserve_exact(value.len() + 2)
            .expect("fixture JSON allocation");
        let checks = Cell::new(0usize);
        let cancelled = || {
            let next = checks.get() + 1;
            checks.set(next);
            next > 2
        };
        assert_eq!(
            push_json_string_cancellable(&mut output, &value, &cancelled),
            Err(ReportError::Cancelled)
        );
        assert!(output.len() < value.len() + 2);
    }

    fn region_fact_base() -> AnalysisFacts {
        AnalysisFacts {
            proofs: vec![region_proof(0, "alloc:0:buffer")],
            startup_order: vec!["only".to_owned()],
            shutdown_order: vec!["only".to_owned()],
            ..AnalysisFacts::default()
        }
    }

    fn region_proof(id: u32, allocation: &str) -> ProofFact {
        ProofFact {
            id,
            category: "region-bound".to_owned(),
            subject: allocation.to_owned(),
            result: "proved".to_owned(),
            bound: Some(1),
            sources: Vec::new(),
            depends_on: Vec::new(),
            why_chain: vec!["bounded whole-image region inference".to_owned()],
        }
    }

    #[test]
    fn region_assignment_and_promotion_facts_round_trip_canonically_and_encode_identically() {
        let digest = Sha256Digest::from_bytes([0x71; 32]);
        let mut facts = region_fact_base();
        facts.proofs = [
            "alloc:0:actor-state",
            "alloc:1:frame-live",
            "alloc:2:scratch",
            "alloc:3:req-buffer",
            "alloc:4:pool-slot",
            "alloc:5:baked-table",
        ]
        .into_iter()
        .enumerate()
        .map(|(id, allocation)| {
            region_proof(
                u32::try_from(id).expect("bounded proof fixture"),
                allocation,
            )
        })
        .collect();
        // Deliberately out of canonical order so sealing must sort both vectors.
        facts.region_assignments = vec![
            RegionAssignmentFact {
                allocation: "alloc:2:scratch".to_owned(),
                region_class: RegionClass::Call,
            },
            RegionAssignmentFact {
                allocation: "alloc:0:actor-state".to_owned(),
                region_class: RegionClass::Image,
            },
            RegionAssignmentFact {
                allocation: "alloc:1:frame-live".to_owned(),
                region_class: RegionClass::TaskFrame,
            },
            RegionAssignmentFact {
                allocation: "alloc:3:req-buffer".to_owned(),
                region_class: RegionClass::Request,
            },
            RegionAssignmentFact {
                allocation: "alloc:4:pool-slot".to_owned(),
                region_class: RegionClass::Pool,
            },
            RegionAssignmentFact {
                allocation: "alloc:5:baked-table".to_owned(),
                region_class: RegionClass::Static,
            },
        ];
        facts.promotions = vec![
            PromotionFact {
                allocation: "alloc:2:scratch".to_owned(),
                source_region: RegionClass::TaskFrame,
                destination_region: RegionClass::Call,
                reason: "escapes through `self.pending`".to_owned(),
                proof: 2,
            },
            PromotionFact {
                allocation: "alloc:4:pool-slot".to_owned(),
                source_region: RegionClass::Call,
                destination_region: RegionClass::Pool,
                reason: "moved into durable pool".to_owned(),
                proof: 4,
            },
        ];
        let digest_build = build(digest);
        let report = assemble(digest, facts, backend(digest)).expect("assemble region report");
        assert_eq!(report.schema(), 18);
        // Canonicalization sorted both vectors by their derived total order.
        assert_eq!(
            report
                .analysis()
                .region_assignments
                .iter()
                .map(|fact| fact.allocation.as_str())
                .collect::<Vec<_>>(),
            [
                "alloc:0:actor-state",
                "alloc:1:frame-live",
                "alloc:2:scratch",
                "alloc:3:req-buffer",
                "alloc:4:pool-slot",
                "alloc:5:baked-table",
            ]
        );
        assert_eq!(
            report
                .analysis()
                .promotions
                .iter()
                .map(|fact| fact.allocation.as_str())
                .collect::<Vec<_>>(),
            ["alloc:2:scratch", "alloc:4:pool-slot"]
        );
        let json = report.to_json();
        // Both arrays are present with all six region-class spellings and the promotion shape.
        assert!(json.contains(
            "\"region_assignments\":[{\"allocation\":\"alloc:0:actor-state\",\"region_class\":\"image\"}"
        ));
        for spelling in [
            "\"region_class\":\"image\"",
            "\"region_class\":\"task-frame\"",
            "\"region_class\":\"call\"",
            "\"region_class\":\"request\"",
            "\"region_class\":\"pool\"",
            "\"region_class\":\"static\"",
        ] {
            assert!(
                json.contains(spelling),
                "missing region-class spelling {spelling}"
            );
        }
        assert!(json.contains(
            "\"promotions\":[{\"allocation\":\"alloc:2:scratch\",\"source_region\":\"task-frame\",\"destination_region\":\"call\",\"reason\":\"escapes through `self.pending`\",\"proof\":2}"
        ));
        // Repeat encode of the same validated report is byte-identical.
        assert_eq!(report.to_json(), json);
        // Decode round-trips to an equal report, and re-encoding stays byte-identical.
        let decoded = decode_image_report_json(
            json.as_bytes(),
            &digest_build,
            AnalysisFactLimits::standard(),
            BackendFactLimits::standard(),
            u64::try_from(json.len()).expect("bounded region report bytes"),
            &|| false,
        )
        .expect("decode region facts");
        assert_eq!(decoded, report);
        assert_eq!(decoded.to_json(), json);
    }

    #[test]
    fn region_and_promotion_facts_fail_closed_on_invalid_and_noncanonical_shapes() {
        let digest = Sha256Digest::from_bytes([0x72; 32]);
        let digest_build = build(digest);
        let reject = |facts: AnalysisFacts| {
            let request = AnalysisFactRequest {
                build: &digest_build,
                image_name: "image",
                limits: AnalysisFactLimits::standard(),
            };
            assert!(matches!(
                seal_analysis_facts(request, facts, &|| false),
                Err(ReportError::InvalidFact | ReportError::NonCanonical(_))
            ));
        };

        let mut empty_assignment_allocation = region_fact_base();
        empty_assignment_allocation.region_assignments = vec![RegionAssignmentFact {
            allocation: String::new(),
            region_class: RegionClass::Image,
        }];
        reject(empty_assignment_allocation);

        let mut noncanonical_assignment_allocation = region_fact_base();
        noncanonical_assignment_allocation.region_assignments = vec![RegionAssignmentFact {
            allocation: "allocation:0:buffer".to_owned(),
            region_class: RegionClass::Image,
        }];
        reject(noncanonical_assignment_allocation);

        let mut unnamed_assignment_allocation = region_fact_base();
        unnamed_assignment_allocation.region_assignments = vec![RegionAssignmentFact {
            allocation: "alloc:0".to_owned(),
            region_class: RegionClass::Image,
        }];
        reject(unnamed_assignment_allocation);

        let mut duplicate_assignment = region_fact_base();
        duplicate_assignment.region_assignments = vec![
            RegionAssignmentFact {
                allocation: "alloc:0:buffer".to_owned(),
                region_class: RegionClass::Image,
            },
            RegionAssignmentFact {
                allocation: "alloc:0:buffer".to_owned(),
                region_class: RegionClass::Image,
            },
        ];
        reject(duplicate_assignment);

        let mut gapped_assignment = region_fact_base();
        gapped_assignment.region_assignments = vec![RegionAssignmentFact {
            allocation: "alloc:1:buffer".to_owned(),
            region_class: RegionClass::Image,
        }];
        reject(gapped_assignment);

        let mut reused_assignment_id = region_fact_base();
        reused_assignment_id.region_assignments = vec![
            RegionAssignmentFact {
                allocation: "alloc:0:first".to_owned(),
                region_class: RegionClass::Image,
            },
            RegionAssignmentFact {
                allocation: "alloc:0:second".to_owned(),
                region_class: RegionClass::Call,
            },
        ];
        reject(reused_assignment_id);

        let mut empty_promotion_allocation = region_fact_base();
        empty_promotion_allocation.promotions = vec![PromotionFact {
            allocation: String::new(),
            source_region: RegionClass::Call,
            destination_region: RegionClass::Image,
            reason: "escapes".to_owned(),
            proof: 0,
        }];
        reject(empty_promotion_allocation);

        let mut empty_promotion_reason = region_fact_base();
        empty_promotion_reason.promotions = vec![PromotionFact {
            allocation: "alloc:0:buffer".to_owned(),
            source_region: RegionClass::Call,
            destination_region: RegionClass::Image,
            reason: String::new(),
            proof: 0,
        }];
        reject(empty_promotion_reason);

        let mut same_region_promotion = region_fact_base();
        same_region_promotion.promotions = vec![PromotionFact {
            allocation: "alloc:0:buffer".to_owned(),
            source_region: RegionClass::Image,
            destination_region: RegionClass::Image,
            reason: "no-op".to_owned(),
            proof: 0,
        }];
        reject(same_region_promotion);

        let mut noncanonical_promotion_allocation = region_fact_base();
        noncanonical_promotion_allocation.promotions = vec![PromotionFact {
            allocation: "alloc:00:buffer".to_owned(),
            source_region: RegionClass::Call,
            destination_region: RegionClass::Image,
            reason: "escapes".to_owned(),
            proof: 0,
        }];
        reject(noncanonical_promotion_allocation);

        let mut foreign_promotion_proof = region_fact_base();
        foreign_promotion_proof.promotions = vec![PromotionFact {
            allocation: "alloc:0:buffer".to_owned(),
            source_region: RegionClass::Call,
            destination_region: RegionClass::Image,
            reason: "escapes".to_owned(),
            proof: 1,
        }];
        reject(foreign_promotion_proof);

        let valid_promotion_facts = || {
            let mut facts = region_fact_base();
            facts.region_assignments = vec![RegionAssignmentFact {
                allocation: "alloc:0:buffer".to_owned(),
                region_class: RegionClass::Image,
            }];
            facts.promotions = vec![PromotionFact {
                allocation: "alloc:0:buffer".to_owned(),
                source_region: RegionClass::Call,
                destination_region: RegionClass::Image,
                reason: "escapes".to_owned(),
                proof: 0,
            }];
            facts
        };

        let mut wrong_promotion_destination = valid_promotion_facts();
        wrong_promotion_destination.promotions[0].destination_region = RegionClass::Pool;
        reject(wrong_promotion_destination);

        let mut wrong_promotion_category = valid_promotion_facts();
        wrong_promotion_category.proofs[0].category = "unrelated".to_owned();
        reject(wrong_promotion_category);

        let mut wrong_promotion_subject = valid_promotion_facts();
        wrong_promotion_subject.proofs[0].subject = "alloc:0:other".to_owned();
        reject(wrong_promotion_subject);

        let mut unbounded_promotion = valid_promotion_facts();
        unbounded_promotion.proofs[0].bound = None;
        reject(unbounded_promotion);
    }

    #[test]
    fn region_and_promotion_fact_assembly_observes_cancellation() {
        let digest = Sha256Digest::from_bytes([0x73; 32]);
        let mut facts = region_fact_base();
        facts.region_assignments = vec![RegionAssignmentFact {
            allocation: "alloc:0:buffer".to_owned(),
            region_class: RegionClass::Image,
        }];
        facts.promotions = vec![PromotionFact {
            allocation: "alloc:0:buffer".to_owned(),
            source_region: RegionClass::TaskFrame,
            destination_region: RegionClass::Image,
            reason: "escapes through `self.pending`".to_owned(),
            proof: 0,
        }];
        let digest_build = build(digest);
        let request = AnalysisFactRequest {
            build: &digest_build,
            image_name: "image",
            limits: AnalysisFactLimits::standard(),
        };
        // Cancellation observed before any work fails closed.
        assert_eq!(
            seal_analysis_facts(request, facts.clone(), &|| true),
            Err(ReportError::Cancelled)
        );
        // Count the cancellation polls a full seal performs.
        let polls = Cell::new(0_u64);
        seal_analysis_facts(request, facts.clone(), &|| {
            polls.set(
                polls
                    .get()
                    .checked_add(1)
                    .expect("bounded region cancellation polls"),
            );
            false
        })
        .expect("measure region cancellation polls");
        let total = polls.get();
        assert!(total > 0);
        // Cancelling at each poll index in turn always fails closed, never a partial seal.
        for stop in 1..=total {
            let seen = Cell::new(0_u64);
            assert_eq!(
                seal_analysis_facts(request, facts.clone(), &|| {
                    let next = seen
                        .get()
                        .checked_add(1)
                        .expect("bounded region cancellation polls");
                    seen.set(next);
                    next == stop
                }),
                Err(ReportError::Cancelled)
            );
        }
    }
}
