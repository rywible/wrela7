//! Production composition root for the independently implemented compiler
//! phases. This crate owns no language or IR model; it wires sealed phase
//! contracts to the public driver and injects all host capabilities.

#![forbid(unsafe_code)]

mod analysis_facts;
mod cache;
mod engine;
mod incremental;
mod input;
mod local_build;
mod local_check;
mod local_doctor;
mod local_format;
mod local_lint;
mod local_test;

pub use analysis_facts::CanonicalAnalysisFactAssembler;
pub use cache::{
    LocalArtifactCache, ResolvedFlowWirFrame, flow_wir_cache_key, resolve_flow_wir_frame,
};
pub use engine::{
    HeadlessCheckError, HeadlessCheckExecution, HeadlessCheckExecutor,
    HeadlessCheckFrameStreamError, HeadlessCheckResponse, LateCancelDisposition,
    LateRequestControl,
};
pub use incremental::{
    INCREMENTAL_ANALYSIS_SESSION_VERSION, IncrementalAnalysisFailure, IncrementalAnalysisLimits,
    IncrementalAnalysisRequest, IncrementalAnalysisResult, IncrementalAnalysisSession,
    IncrementalAnalysisSnapshot, IncrementalReuseEvidence,
};
pub use input::{
    FrontendInputError, FrontendWorkspace, FrontendWorkspaceRequest, LocalFrontendService,
    LocalPackageProvider, LocalToolchainPackageProvider, LocalWorkspaceProvider,
};
pub use local_build::{LocalBuildDriver, execute_local_build};
pub use local_check::{LocalCheckDriver, execute_local_check};
pub use local_doctor::{LocalDoctorDriver, execute_local_doctor};
pub use local_format::{CanonicalSourceFormatter, LocalFormatDriver, execute_local_format};
pub use local_lint::{LocalLintDriver, execute_local_lint};
pub use local_test::{LocalTestDriver, execute_local_test};
pub use wrela_toolchain::{
    LocalToolchainVerification, LocalToolchainVerificationError, LocalToolchainVerificationLimits,
    LocalToolchainVerifier,
};

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use wrela_build_model::{
    BuildConfiguration, BuildIdentity, BuildProfile, Sha256Digest, TargetIdentity,
    ValidatedBuildConfiguration, seal_build_configuration,
};
use wrela_driver::{Command, CommandOutput, CompilerDriver, DriverError, TestSelection};
use wrela_package::{ImageDeclaration, PackageId, PackageLocator};
use wrela_package_loader::{
    ContentHasher, LoadLimits, LoadedWorkspace, PackageCodec, PackageSourceProvider,
    WorkspaceLoader, sha256_cancellable,
};
use wrela_target::{TargetDecodeLimits, TargetPackage, TargetPackageCodec};
use wrela_toolchain::{
    ComponentKind, ToolchainDecodeLimits, ToolchainManifestCodec, VerifiedToolchain,
};

/// Static application entry used by the public binary while concrete phase
/// implementations are brought up behind [`CompilerFactory`]. Keeping this
/// entry in the composition root makes the final executable dependency chain
/// correct from the outset; no compiler implementation can be installed in the
/// public API/model crate by accident.
pub fn run(command: &Command) -> Result<CommandOutput, DriverError> {
    match command {
        Command::Doctor => execute_local_doctor(command),
        Command::Check { .. } => execute_local_check(command),
        Command::Build { .. } => execute_local_build(command),
        Command::Format { .. } => execute_local_format(command),
        Command::Lint { .. } => execute_local_lint(command),
        Command::Test { .. } => execute_local_test(command),
    }
}

/// Every replaceable compiler implementation dependency. A vertical can use a
/// real producer with fixture consumers, or a fixture producer with a real
/// consumer, without filesystem, process, LLVM, or QEMU globals.
pub struct CompilerServices<'a> {
    pub workspace_loader: &'a dyn WorkspaceLoader,
    pub package_codec: &'a dyn PackageCodec,
    pub parser: &'a dyn wrela_syntax::SyntaxParser,
    pub hir_lowerer: &'a dyn wrela_hir_lower::HirLowerer,
    pub semantic_analyzer: &'a dyn wrela_sema::SemanticAnalyzer,
    pub analysis_fact_assembler: &'a dyn AnalysisFactAssembler,
    pub formatter: &'a dyn wrela_format::Formatter,
    pub linter: &'a dyn wrela_lint::Linter,
    pub semantic_lowerer: &'a dyn wrela_semantic_lower::SemanticLowerer,
    pub flow_lowerer: &'a dyn wrela_flow_lower::FlowLowerer,
    pub flow_codec: &'a dyn wrela_flow_wir_codec::FlowWirCodec,
    pub backend: &'a dyn wrela_backend::BackendExecutor,
    pub target_codec: &'a dyn TargetPackageCodec,
    pub toolchain_codec: &'a dyn ToolchainManifestCodec,
    pub test_executor: &'a dyn wrela_test_runner::ProcessExecutor,
    pub test_harness: &'a dyn wrela_test_runner::ImageHarness,
    pub image_scenario_codec: &'a dyn wrela_test_model::ImageScenarioCodec,
    pub test_report_codec: &'a dyn wrela_test_model::TestReportCodec,
    pub artifact_cache: &'a dyn ArtifactCache,
    pub build_planner: &'a dyn BuildPlanner,
}

/// The sole semantic-database to public analysis-report projection. Keeping
/// this distinct from semantic analysis lets either side be implemented and
/// fixture-tested without importing the other's concrete implementation.
pub struct AnalysisFactRequest<'a> {
    pub analysis: &'a wrela_sema::AnalyzedImage,
    pub limits: wrela_image_report::AnalysisFactLimits,
}

pub trait AnalysisFactAssembler {
    fn assemble(
        &self,
        request: AnalysisFactRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<wrela_image_report::ValidatedAnalysisFacts, AnalysisFactAssemblyError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnalysisFactAssemblyError {
    Cancelled,
    UnsupportedInput { feature: &'static str },
    ResourceLimit { resource: &'static str, limit: u64 },
    InvalidSemanticFacts(&'static str),
    Report(wrela_image_report::ReportError),
}

impl From<wrela_image_report::ReportError> for AnalysisFactAssemblyError {
    fn from(value: wrela_image_report::ReportError) -> Self {
        match value {
            wrela_image_report::ReportError::Cancelled => Self::Cancelled,
            wrela_image_report::ReportError::ResourceLimit { resource, limit } => {
                Self::ResourceLimit { resource, limit }
            }
            value => Self::Report(value),
        }
    }
}

impl fmt::Display for AnalysisFactAssemblyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("analysis-fact assembly was cancelled"),
            Self::UnsupportedInput { feature } => {
                write!(
                    formatter,
                    "analysis-fact assembly does not yet support {feature}"
                )
            }
            Self::ResourceLimit { resource, limit } => {
                write!(
                    formatter,
                    "analysis-fact assembly exceeded {resource} limit {limit}"
                )
            }
            Self::InvalidSemanticFacts(detail) => {
                write!(formatter, "invalid sealed semantic facts: {detail}")
            }
            Self::Report(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for AnalysisFactAssemblyError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheLimits {
    pub entry_bytes: u64,
}

impl CacheLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            entry_bytes: 4 * 1024 * 1024 * 1024,
        }
    }

    #[must_use]
    pub const fn is_valid(self) -> bool {
        self.entry_bytes > 0
    }
}

pub const CACHE_KEY_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CachedArtifactKind {
    FlowWirFrame,
    BackendImage,
    ImageReport,
    TestReport,
}

/// Content-addressed cache identity. `build` already includes compiler,
/// source, target, profile, and command request digests; `subject` distinguishes
/// group/root-specific products within one test build.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    version: u32,
    kind: CachedArtifactKind,
    build: BuildIdentity,
    subject: Sha256Digest,
}

impl CacheKey {
    pub fn new(
        kind: CachedArtifactKind,
        build: BuildIdentity,
        subject: Sha256Digest,
    ) -> Result<Self, CacheError> {
        if subject.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(CacheError::InvalidKey);
        }
        Ok(Self {
            version: CACHE_KEY_VERSION,
            kind,
            build,
            subject,
        })
    }

    /// Schema version for persistent namespace separation. Cache backends must
    /// include this value in any path, database key, or remote-cache key they
    /// derive; entries from another version are not interchangeable.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    #[must_use]
    pub const fn kind(&self) -> CachedArtifactKind {
        self.kind
    }

    #[must_use]
    pub fn build(&self) -> &BuildIdentity {
        &self.build
    }

    #[must_use]
    pub const fn subject(&self) -> Sha256Digest {
        self.subject
    }
}

pub struct CacheReadRequest<'a> {
    pub key: &'a CacheKey,
    pub maximum_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CacheEntryCandidate {
    pub key: CacheKey,
    pub bytes: Vec<u8>,
    pub digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedArtifact {
    key: CacheKey,
    bytes: Vec<u8>,
    digest: Sha256Digest,
}

impl CachedArtifact {
    #[must_use]
    pub fn key(&self) -> &CacheKey {
        &self.key
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    #[must_use]
    pub fn into_bytes_and_digest(self) -> (Vec<u8>, Sha256Digest) {
        (self.bytes, self.digest)
    }
}

pub fn seal_cached_artifact(
    request: &CacheReadRequest<'_>,
    candidate: CacheEntryCandidate,
    hasher: &dyn ContentHasher,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<CachedArtifact, CacheError> {
    if is_cancelled() {
        return Err(CacheError::Cancelled);
    }
    if request.maximum_bytes == 0 {
        return Err(CacheError::InvalidLimit);
    }
    let bytes = u64::try_from(candidate.bytes.len()).map_err(|_| CacheError::ResourceLimit {
        limit: request.maximum_bytes,
    })?;
    if bytes > request.maximum_bytes {
        return Err(CacheError::ResourceLimit {
            limit: request.maximum_bytes,
        });
    }
    if &candidate.key != request.key {
        return Err(CacheError::KeyMismatch);
    }
    if sha256_cancellable(hasher, &candidate.bytes, is_cancelled)
        .map_err(|_| CacheError::Cancelled)?
        != candidate.digest
    {
        return Err(CacheError::DigestMismatch);
    }
    if is_cancelled() {
        return Err(CacheError::Cancelled);
    }
    Ok(CachedArtifact {
        key: candidate.key,
        bytes: candidate.bytes,
        digest: candidate.digest,
    })
}

/// Opaque persistent cache capability. Cache misses and corruption never
/// change semantics: callers validate candidates before decoding and may
/// always recompute. Implementations publish entries atomically and may evict
/// them at any time.
pub trait ArtifactCache {
    fn load(
        &self,
        request: &CacheReadRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Option<CacheEntryCandidate>, CacheError>;

    fn store(
        &self,
        artifact: &CachedArtifact,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), CacheError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheError {
    Cancelled,
    InvalidKey,
    InvalidLimit,
    ResourceLimit { limit: u64 },
    KeyMismatch,
    DigestMismatch,
    Io(String),
}

impl fmt::Display for CacheError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "compiler cache error: {self:?}")
    }
}

impl std::error::Error for CacheError {}

/// One place for all compiler-created resource ceilings. Individual phases
/// remain authoritative for validation; this aggregate only prevents the
/// composition layer from silently choosing unrelated defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipelineLimits {
    pub cache: CacheLimits,
    pub package_load: LoadLimits,
    pub parse: wrela_syntax::ParseLimits,
    pub hir: wrela_hir_lower::LoweringLimits,
    pub semantic: wrela_sema::AnalysisLimits,
    pub analysis_facts: wrela_image_report::AnalysisFactLimits,
    pub format: FormatBatchLimits,
    pub lint: wrela_lint::LintLimits,
    pub test_plan: wrela_test_model::TestPlanLimits,
    pub test_runner: wrela_test_runner::RunnerLimits,
    pub semantic_lower: wrela_semantic_lower::LoweringLimits,
    pub flow_lower: wrela_flow_lower::LoweringLimits,
    pub flow_codec: wrela_flow_wir_codec::CodecLimits,
    pub backend: wrela_backend::BackendLimits,
    pub target_decode: TargetDecodeLimits,
    pub toolchain_decode: ToolchainDecodeLimits,
    pub toolchain_verify: LocalToolchainVerificationLimits,
}

impl PipelineLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            cache: CacheLimits::standard(),
            package_load: LoadLimits::standard(),
            parse: wrela_syntax::ParseLimits::standard(),
            hir: wrela_hir_lower::LoweringLimits::standard(),
            semantic: wrela_sema::AnalysisLimits::standard(),
            analysis_facts: wrela_image_report::AnalysisFactLimits::standard(),
            format: FormatBatchLimits::standard(),
            lint: wrela_lint::LintLimits::standard(),
            test_plan: wrela_test_model::TestPlanLimits::standard(),
            test_runner: wrela_test_runner::RunnerLimits::standard(),
            semantic_lower: wrela_semantic_lower::LoweringLimits::standard(),
            flow_lower: wrela_flow_lower::LoweringLimits::standard(),
            flow_codec: wrela_flow_wir_codec::CodecLimits::standard(),
            backend: wrela_backend::BackendLimits::standard(),
            target_decode: TargetDecodeLimits::standard(),
            toolchain_decode: ToolchainDecodeLimits::standard(),
            toolchain_verify: LocalToolchainVerificationLimits::standard(),
        }
    }

    pub fn validate(self) -> Result<(), CompositionError> {
        if !self.cache.is_valid()
            || self.package_load.validate().is_err()
            || self.parse.validate().is_err()
            || self.hir.validate().is_err()
            || self.semantic.validate().is_err()
            || self.analysis_facts.validate().is_err()
            || self.format.validate().is_err()
            || self.lint.validate().is_err()
            || !self.test_plan.is_valid()
            || !self.test_runner.is_valid()
            || self.semantic_lower.validate().is_err()
            || self.flow_lower.validate().is_err()
            || self.flow_codec.validate().is_err()
            || self.backend.validate().is_err()
            // The revision-0.1 private protocol does not encode limits. The
            // child therefore enforces exactly its compiled-in standard
            // policy, and the composition root must reject any caller policy
            // that could not be communicated across that boundary.
            || self.backend != wrela_backend::BackendLimits::standard()
            || self.target_decode.validate().is_err()
            || self.toolchain_decode.validate().is_err()
            || self.toolchain_verify.validate().is_err()
            || self.target_decode != self.toolchain_verify.target_package
            || self.toolchain_decode != self.toolchain_verify.toolchain_manifest
            || self.flow_codec != self.backend.codec
            || self.flow_lower.test_plan != self.test_plan
            || self.flow_codec.test_plan != self.test_plan
            || self.backend.codec.test_plan != self.test_plan
            || self.backend.optimization.test_plan != self.test_plan
            || self.cache.entry_bytes < self.flow_codec.frame_bytes
            || self.cache.entry_bytes < self.backend.link.image_bytes
            || self.analysis_facts != self.backend.analysis_report_facts
            || self.format.files > self.package_load.sources
            || self.format.input_bytes > self.package_load.source_bytes
            || self.semantic.tests != self.test_plan.tests
            || self.semantic.test_groups != self.test_plan.groups
            || self.semantic.test_scenarios != self.test_plan.scenarios
            || self.semantic.test_scenario_steps != self.test_plan.scenario_steps
            || self.semantic.test_bytes != self.test_plan.payload_bytes
            || self.semantic.test_report_bytes != self.test_plan.report_bytes
            || self.semantic.test_events_per_group != self.test_plan.events_per_group
            || self.semantic.test_output_bytes_per_group != self.test_plan.output_bytes_per_group
            || self.semantic.test_timeout_ns_per_group
                != self.test_plan.execution_timeout_ns_per_group
        {
            Err(CompositionError::InvalidLimits)
        } else {
            Ok(())
        }
    }
}

/// Batch-level bounds for the driver-facing format command. Per-file syntax
/// and formatter bounds still apply independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormatBatchLimits {
    pub files: u32,
    pub input_bytes: u64,
    pub edits_per_file: u32,
    pub output_bytes_per_file: u64,
    pub output_bytes: u64,
}

impl FormatBatchLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            files: 1_000_000,
            input_bytes: 4 * 1024 * 1024 * 1024,
            edits_per_file: 1_000_000,
            output_bytes_per_file: 256 * 1024 * 1024,
            output_bytes: 4 * 1024 * 1024 * 1024,
        }
    }

    pub const fn validate(self) -> Result<(), CompositionError> {
        if self.files == 0
            || self.input_bytes == 0
            || self.edits_per_file == 0
            || self.output_bytes_per_file == 0
            || self.output_bytes == 0
            || self.output_bytes_per_file > self.output_bytes
        {
            Err(CompositionError::InvalidLimits)
        } else {
            Ok(())
        }
    }
}

/// Bounded bytes returned by the only ambient-file read capability available
/// to the composition root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedInput {
    path: PathBuf,
    bytes: Vec<u8>,
    digest: Sha256Digest,
}

impl VerifiedInput {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        self.digest
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

#[derive(Debug, Clone, Copy)]
pub struct InputReadRequest<'a> {
    pub path: &'a Path,
    pub maximum_bytes: u64,
}

pub fn seal_verified_input(
    request: &InputReadRequest<'_>,
    hasher: &dyn ContentHasher,
    bytes: Vec<u8>,
    observed_digest: Sha256Digest,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<VerifiedInput, HostError> {
    if is_cancelled() {
        return Err(HostError::Cancelled);
    }
    let size = u64::try_from(bytes.len()).map_err(|_| HostError::ResourceLimit {
        resource: "input bytes",
        limit: request.maximum_bytes,
    })?;
    let normalized: PathBuf = request.path.components().collect();
    if !request.path.is_absolute()
        || request.path.components().count() <= 1
        || normalized != request.path
        || request.path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(HostError::InvalidPath(request.path.to_owned()));
    }
    if request.maximum_bytes == 0 || size > request.maximum_bytes {
        return Err(HostError::ResourceLimit {
            resource: "input bytes",
            limit: request.maximum_bytes,
        });
    }
    if sha256_cancellable(hasher, &bytes, is_cancelled).map_err(|_| HostError::Cancelled)?
        != observed_digest
    {
        return Err(HostError::DigestMismatch(request.path.to_owned()));
    }
    if is_cancelled() {
        return Err(HostError::Cancelled);
    }
    Ok(VerifiedInput {
        path: request.path.to_owned(),
        bytes,
        digest: observed_digest,
    })
}

/// Host authority required by orchestration. Package acquisition remains a
/// separately typed supertrait so its declared-locator restrictions cannot be
/// bypassed by a generic path read.
pub trait CompilerHost:
    PackageSourceProvider + ContentHasher + wrela_driver::OutcomeContentHasher
{
    fn read_bounded(
        &self,
        request: &InputReadRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<VerifiedInput, HostError>;

    fn create_private_directory(
        &self,
        purpose: &str,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<PathBuf, HostError>;

    fn remove_private_directory(
        &self,
        path: &Path,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), HostError>;

    /// Materialize a sealed byte sequence through a same-filesystem temporary
    /// file, durability barrier, and atomic rename. `ReplaceIfDigest` must hash
    /// the current destination while holding the replacement lock and reject a
    /// concurrent edit. Cancellation is honored before the visible rename.
    fn publish_atomic(
        &self,
        request: &FilePublicationRequest,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<FilePublicationReceipt, HostError>;

    fn load_target(
        &self,
        identity: &TargetIdentity,
        codec: &dyn TargetPackageCodec,
        limits: TargetDecodeLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<TargetPackage, HostError>;

    fn verify_toolchain(
        &self,
        codec: &dyn ToolchainManifestCodec,
        limits: ToolchainDecodeLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<VerifiedToolchain, HostError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilePublicationMode {
    CreateNew,
    ReplaceIfDigest(Sha256Digest),
}

/// Bytes and identity sealed before any externally visible file mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilePublicationRequest {
    destination: PathBuf,
    payload: FilePublicationPayload,
    digest: Sha256Digest,
    mode: FilePublicationMode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FilePublicationPayload {
    Bytes(Vec<u8>),
    TestReport(Arc<wrela_test_model::EncodedTestReport>),
}

impl FilePublicationPayload {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Bytes(bytes) => bytes,
            Self::TestReport(encoded) => encoded.bytes(),
        }
    }
}

impl FilePublicationRequest {
    #[must_use]
    pub fn destination(&self) -> &Path {
        &self.destination
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        self.payload.bytes()
    }

    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        self.digest
    }

    #[must_use]
    pub const fn mode(&self) -> FilePublicationMode {
        self.mode
    }
}

pub fn seal_file_publication_request(
    hasher: &dyn ContentHasher,
    destination: PathBuf,
    bytes: Vec<u8>,
    mode: FilePublicationMode,
    maximum_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<FilePublicationRequest, HostError> {
    seal_file_publication_payload(
        hasher,
        destination,
        FilePublicationPayload::Bytes(bytes),
        mode,
        maximum_bytes,
        is_cancelled,
    )
}

fn seal_file_publication_payload(
    hasher: &dyn ContentHasher,
    destination: PathBuf,
    payload: FilePublicationPayload,
    mode: FilePublicationMode,
    maximum_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<FilePublicationRequest, HostError> {
    if is_cancelled() {
        return Err(HostError::Cancelled);
    }
    let normalized: PathBuf = destination.components().collect();
    let length = u64::try_from(payload.bytes().len()).map_err(|_| HostError::ResourceLimit {
        resource: "publication bytes",
        limit: maximum_bytes,
    })?;
    if maximum_bytes == 0 || length > maximum_bytes {
        return Err(HostError::ResourceLimit {
            resource: "publication bytes",
            limit: maximum_bytes,
        });
    }
    if !destination.is_absolute()
        || destination.components().count() <= 1
        || normalized != destination
        || destination.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(HostError::InvalidPath(destination));
    }
    let digest = sha256_cancellable(hasher, payload.bytes(), is_cancelled)
        .map_err(|_| HostError::Cancelled)?;
    if is_cancelled() {
        return Err(HostError::Cancelled);
    }
    Ok(FilePublicationRequest {
        destination,
        payload,
        digest,
        mode,
    })
}

/// Raw host receipt. Callers must pass it through
/// [`seal_file_publication`] before constructing a driver outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilePublicationReceipt {
    pub path: PathBuf,
    pub digest: Sha256Digest,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedFile(FilePublicationReceipt);

impl PublishedFile {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0.path
    }

    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        self.0.digest
    }

    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.0.bytes
    }
}

pub fn seal_file_publication(
    request: &FilePublicationRequest,
    receipt: FilePublicationReceipt,
) -> Result<PublishedFile, HostError> {
    let expected_bytes =
        u64::try_from(request.bytes().len()).map_err(|_| HostError::ResourceLimit {
            resource: "publication bytes",
            limit: u64::MAX,
        })?;
    if receipt.path != request.destination
        || receipt.digest != request.digest
        || receipt.bytes != expected_bytes
    {
        return Err(HostError::PublicationMismatch(receipt.path));
    }
    Ok(PublishedFile(receipt))
}

/// Binds canonical report bytes to the exact validated report until atomic
/// publication has been acknowledged and cross-checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestReportPublicationRequest {
    file: FilePublicationRequest,
    encoded: Arc<wrela_test_model::EncodedTestReport>,
}

impl TestReportPublicationRequest {
    #[must_use]
    pub fn file(&self) -> &FilePublicationRequest {
        &self.file
    }

    #[must_use]
    pub fn report(&self) -> &wrela_test_model::ValidatedTestReport {
        self.encoded.report()
    }
}

pub fn seal_test_report_publication_request(
    hasher: &dyn ContentHasher,
    destination: PathBuf,
    encoded: wrela_test_model::EncodedTestReport,
    maximum_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<TestReportPublicationRequest, HostError> {
    let encoded = Arc::new(encoded);
    let file = seal_file_publication_payload(
        hasher,
        destination,
        FilePublicationPayload::TestReport(Arc::clone(&encoded)),
        FilePublicationMode::CreateNew,
        maximum_bytes,
        is_cancelled,
    )?;
    Ok(TestReportPublicationRequest { file, encoded })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedTestReport {
    file: PublishedFile,
    encoded: wrela_test_model::EncodedTestReport,
}

impl PublishedTestReport {
    #[must_use]
    pub fn file(&self) -> &PublishedFile {
        &self.file
    }

    #[must_use]
    pub fn report(&self) -> &wrela_test_model::ValidatedTestReport {
        self.encoded.report()
    }

    #[must_use]
    pub fn encoded(&self) -> &wrela_test_model::EncodedTestReport {
        &self.encoded
    }

    #[must_use]
    pub fn into_parts(self) -> (PublishedFile, wrela_test_model::EncodedTestReport) {
        (self.file, self.encoded)
    }
}

pub fn seal_test_report_publication(
    request: TestReportPublicationRequest,
    receipt: FilePublicationReceipt,
) -> Result<PublishedTestReport, HostError> {
    let TestReportPublicationRequest {
        file: request,
        encoded,
    } = request;
    let file = seal_file_publication(&request, receipt)?;
    drop(request);
    let encoded = Arc::try_unwrap(encoded)
        .map_err(|_| HostError::PublicationMismatch(file.path().to_owned()))?;
    Ok(PublishedTestReport { file, encoded })
}

/// Inputs that establish the sole build identity before semantic analysis or
/// cache lookup begins.
#[derive(Debug, Clone, Copy)]
pub enum BuildIntent<'a> {
    Check,
    Build,
    Test { selection: &'a TestSelection },
    Lint,
}

pub struct BuildPlanningRequest<'a> {
    /// Exact sealed package/source product; supplies language revision and
    /// source-graph identity without re-reading the manifest.
    pub workspace: &'a LoadedWorkspace,
    /// Exact root-manifest image selected by the public command.
    pub image: &'a ImageDeclaration,
    /// Exact root-manifest profile selected for this invocation.
    pub profile: &'a BuildProfile,
    pub intent: BuildIntent<'a>,
    pub target: &'a TargetPackage,
    pub toolchain: &'a VerifiedToolchain,
    pub hasher: &'a dyn ContentHasher,
    pub compiler_digest: Sha256Digest,
}

pub trait BuildPlanner {
    fn plan(
        &self,
        request: BuildPlanningRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<PlannedBuild, BuildPlanningError>;
}

/// Deterministic production planner for one sealed workspace/image/profile
/// selection. The candidate is still passed through [`seal_build_plan`], so
/// construction and verification remain separate steps.
#[derive(Debug, Clone, Copy, Default)]
pub struct CanonicalBuildPlanner;

impl CanonicalBuildPlanner {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl BuildPlanner for CanonicalBuildPlanner {
    fn plan(
        &self,
        request: BuildPlanningRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<PlannedBuild, BuildPlanningError> {
        if is_cancelled() {
            return Err(BuildPlanningError::Cancelled);
        }
        let profile_bytes = request
            .profile
            .canonical_bytes()
            .map_err(|error| BuildPlanningError::InvalidProfile(error.to_string()))?;
        let profile = sha256_cancellable(request.hasher, &profile_bytes, is_cancelled)
            .map_err(|_| BuildPlanningError::Cancelled)?;
        let request_bytes = canonical_build_request(&request, is_cancelled)?;
        let request_digest = sha256_cancellable(request.hasher, &request_bytes, is_cancelled)
            .map_err(|_| BuildPlanningError::Cancelled)?;
        let standard_library_package =
            selected_standard_library_package(request.workspace, request.toolchain, is_cancelled)?;
        let standard_library = request
            .toolchain
            .standard_library()
            .map_err(|_| BuildPlanningError::ToolchainMismatch)?
            .digest();
        let configuration = BuildConfiguration {
            identity: BuildIdentity {
                compiler: request.compiler_digest,
                language: request.workspace.root_manifest().language,
                target: request.target.identity().clone(),
                target_package: request.target.semantic().content_digest(),
                standard_library,
                source_graph: request.workspace.source_graph_digest(),
                request: request_digest,
                profile,
            },
            profile: request.profile.clone(),
        };
        if is_cancelled() {
            return Err(BuildPlanningError::Cancelled);
        }
        seal_build_plan_with_selection(
            &request,
            configuration,
            standard_library_package,
            is_cancelled,
        )
    }
}

/// Build configuration sealed against the exact workspace selection and
/// verified installation, not merely against a self-consistent profile hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedBuild {
    configuration: ValidatedBuildConfiguration,
    standard_library_package: PackageId,
}

impl PlannedBuild {
    #[must_use]
    pub fn configuration(&self) -> &ValidatedBuildConfiguration {
        &self.configuration
    }

    /// Exact package selected by the root package's reserved `core`
    /// dependency. This is intentionally distinct from the installed
    /// standard-library component digest in the build identity.
    #[must_use]
    pub const fn standard_library_package(&self) -> PackageId {
        self.standard_library_package
    }

    #[must_use]
    pub fn into_configuration(self) -> ValidatedBuildConfiguration {
        self.configuration
    }

    #[must_use]
    pub fn into_parts(self) -> (ValidatedBuildConfiguration, PackageId) {
        (self.configuration, self.standard_library_package)
    }
}

pub fn seal_build_plan(
    request: &BuildPlanningRequest<'_>,
    configuration: BuildConfiguration,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<PlannedBuild, BuildPlanningError> {
    let standard_library_package =
        selected_standard_library_package(request.workspace, request.toolchain, is_cancelled)?;
    seal_build_plan_with_selection(
        request,
        configuration,
        standard_library_package,
        is_cancelled,
    )
}

fn seal_build_plan_with_selection(
    request: &BuildPlanningRequest<'_>,
    configuration: BuildConfiguration,
    standard_library_package: PackageId,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<PlannedBuild, BuildPlanningError> {
    if is_cancelled() {
        return Err(BuildPlanningError::Cancelled);
    }
    request
        .target
        .validate()
        .map_err(|error| BuildPlanningError::InvalidBuild(error.to_string()))?;
    let selected_image = request.workspace.image(&request.image.name);
    let selected_profile = request.workspace.profile(&request.profile.name);
    let installed_frontend = request
        .toolchain
        .component(ComponentKind::Frontend)
        .map_err(|_| BuildPlanningError::ToolchainMismatch)?;
    let installed_standard_library = request
        .toolchain
        .standard_library()
        .map_err(|_| BuildPlanningError::ToolchainMismatch)?;
    let installed_target = request
        .toolchain
        .target(request.target.identity())
        .map_err(|_| BuildPlanningError::ToolchainMismatch)?;
    let profile_bytes = request
        .profile
        .canonical_bytes()
        .map_err(|error| BuildPlanningError::InvalidProfile(error.to_string()))?;
    let profile_digest = sha256_cancellable(request.hasher, &profile_bytes, is_cancelled)
        .map_err(|_| BuildPlanningError::Cancelled)?;
    let canonical_request = canonical_build_request(request, is_cancelled)?;
    let request_digest = sha256_cancellable(request.hasher, &canonical_request, is_cancelled)
        .map_err(|_| BuildPlanningError::Cancelled)?;
    if is_cancelled() {
        return Err(BuildPlanningError::Cancelled);
    }
    let identity = &configuration.identity;
    if selected_image != Some(request.image)
        || selected_profile != Some(request.profile)
        || request.image.target != *request.target.identity()
        || request.image.profile != request.profile.name
        || configuration.profile != *request.profile
        || identity.compiler != request.compiler_digest
        || identity.compiler != installed_frontend.digest()
        || identity.language != request.workspace.root_manifest().language
        || identity.target != *request.target.identity()
        || identity.target_package != request.target.semantic().content_digest()
        || identity.target_package != installed_target.digest()
        || identity.standard_library != installed_standard_library.digest()
        || identity.source_graph != request.workspace.source_graph_digest()
        || identity.request != request_digest
        || identity.profile != profile_digest
    {
        return Err(BuildPlanningError::Selection(
            "build configuration differs from the sealed workspace, image, profile, target, toolchain, or command identity".to_owned(),
        ));
    }
    seal_build_configuration(configuration, profile_digest)
        .map(|configuration| PlannedBuild {
            configuration,
            standard_library_package,
        })
        .map_err(|error| BuildPlanningError::InvalidBuild(error.to_string()))
}

fn selected_standard_library_package(
    workspace: &LoadedWorkspace,
    toolchain: &VerifiedToolchain,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<PackageId, BuildPlanningError> {
    if is_cancelled() {
        return Err(BuildPlanningError::Cancelled);
    }
    let graph = workspace.graph();
    let root = graph
        .package(graph.root())
        .ok_or(BuildPlanningError::StandardLibrarySelection)?;
    let dependency_index = root
        .dependencies
        .binary_search_by(|dependency| dependency.alias.as_str().cmp("core"))
        .map_err(|_| BuildPlanningError::StandardLibrarySelection)?;
    let package = root
        .dependencies
        .get(dependency_index)
        .map(|dependency| dependency.package)
        .ok_or(BuildPlanningError::StandardLibrarySelection)?;
    let index =
        usize::try_from(package.0).map_err(|_| BuildPlanningError::StandardLibrarySelection)?;
    let graph_package = graph
        .package(package)
        .ok_or(BuildPlanningError::StandardLibrarySelection)?;
    let manifest = workspace
        .manifests()
        .get(index)
        .ok_or(BuildPlanningError::StandardLibrarySelection)?;
    if manifest.identity() != &graph_package.identity
        || !matches!(manifest.locator(), PackageLocator::Toolchain { .. })
    {
        return Err(BuildPlanningError::StandardLibrarySelection);
    }
    let indexed = toolchain
        .standard_library_package(manifest.identity())
        .ok_or(BuildPlanningError::StandardLibrarySelection)?;
    if &indexed.locator != manifest.locator()
        || indexed.manifest_digest != manifest.manifest_digest()
    {
        return Err(BuildPlanningError::StandardLibrarySelection);
    }
    if is_cancelled() {
        return Err(BuildPlanningError::Cancelled);
    }
    Ok(package)
}

fn canonical_build_request(
    request: &BuildPlanningRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>, BuildPlanningError> {
    encode_canonical_build_request(
        request.image,
        request.target.identity(),
        &request.profile.name,
        request.intent,
        is_cancelled,
    )
}

const CANONICAL_BUILD_REQUEST_BYTES: u64 = 64 * 1024;

fn encode_canonical_build_request(
    image: &ImageDeclaration,
    target: &TargetIdentity,
    profile_name: &str,
    intent: BuildIntent<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>, BuildPlanningError> {
    const MAGIC: &[u8; 8] = b"WRELREQ\0";
    const VERSION: u32 = 1;
    if is_cancelled() {
        return Err(BuildPlanningError::Cancelled);
    }
    let mut builder = CanonicalRequestBuilder::new()?;
    builder.push_bytes(MAGIC)?;
    builder.push_bytes(&VERSION.to_le_bytes())?;
    builder.push_string(&image.name)?;
    builder.push_module(&image.module, is_cancelled)?;
    builder.push_string(&image.entry)?;
    builder.push_string(target.as_str())?;
    builder.push_string(profile_name)?;
    match intent {
        BuildIntent::Check => builder.push_byte(0)?,
        BuildIntent::Build => builder.push_byte(1)?,
        BuildIntent::Test { selection } => {
            builder.push_byte(2)?;
            match selection {
                TestSelection::All => builder.push_byte(0)?,
                TestSelection::Comptime => builder.push_byte(1)?,
                TestSelection::Integration => builder.push_byte(2)?,
                TestSelection::Images => builder.push_byte(3)?,
                TestSelection::NameContains(value) => {
                    if value.trim().is_empty() || value.len() > 4096 {
                        return Err(BuildPlanningError::Selection(
                            "test name filter is empty or exceeds 4096 bytes".to_owned(),
                        ));
                    }
                    builder.push_byte(4)?;
                    builder.push_string(value)?;
                }
            }
        }
        BuildIntent::Lint => builder.push_byte(3)?,
    }
    if is_cancelled() {
        return Err(BuildPlanningError::Cancelled);
    }
    Ok(builder.finish())
}

struct CanonicalRequestBuilder {
    bytes: Vec<u8>,
}

impl CanonicalRequestBuilder {
    fn new() -> Result<Self, BuildPlanningError> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(CANONICAL_BUILD_REQUEST_BYTES as usize)
            .map_err(|_| BuildPlanningError::ResourceLimit {
                resource: "canonical build request bytes",
                limit: CANONICAL_BUILD_REQUEST_BYTES,
            })?;
        Ok(Self { bytes })
    }

    fn push_byte(&mut self, value: u8) -> Result<(), BuildPlanningError> {
        self.push_bytes(&[value])
    }

    fn push_string(&mut self, value: &str) -> Result<(), BuildPlanningError> {
        let length = u32::try_from(value.len()).map_err(|_| BuildPlanningError::ResourceLimit {
            resource: "canonical build request bytes",
            limit: CANONICAL_BUILD_REQUEST_BYTES,
        })?;
        self.push_bytes(&length.to_le_bytes())?;
        self.push_bytes(value.as_bytes())
    }

    fn push_module(
        &mut self,
        module: &wrela_package::ModulePath,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), BuildPlanningError> {
        let length = module
            .segments()
            .iter()
            .enumerate()
            .try_fold(0usize, |total, (index, segment)| {
                total
                    .checked_add(usize::from(index != 0))
                    .and_then(|total| total.checked_add(segment.len()))
            })
            .ok_or(BuildPlanningError::ResourceLimit {
                resource: "canonical build request bytes",
                limit: CANONICAL_BUILD_REQUEST_BYTES,
            })?;
        let length = u32::try_from(length).map_err(|_| BuildPlanningError::ResourceLimit {
            resource: "canonical build request bytes",
            limit: CANONICAL_BUILD_REQUEST_BYTES,
        })?;
        self.push_bytes(&length.to_le_bytes())?;
        for (index, segment) in module.segments().iter().enumerate() {
            if is_cancelled() {
                return Err(BuildPlanningError::Cancelled);
            }
            if index != 0 {
                self.push_byte(b'.')?;
            }
            self.push_bytes(segment.as_bytes())?;
        }
        Ok(())
    }

    fn push_bytes(&mut self, value: &[u8]) -> Result<(), BuildPlanningError> {
        let next = self
            .bytes
            .len()
            .checked_add(value.len())
            .and_then(|length| u64::try_from(length).ok())
            .filter(|length| *length <= CANONICAL_BUILD_REQUEST_BYTES)
            .ok_or(BuildPlanningError::ResourceLimit {
                resource: "canonical build request bytes",
                limit: CANONICAL_BUILD_REQUEST_BYTES,
            })?;
        self.bytes.extend_from_slice(value);
        debug_assert_eq!(u64::try_from(self.bytes.len()).ok(), Some(next));
        Ok(())
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

/// Factory boundary for the concrete driver. Construction receives the full
/// service/capability graph once; commands and cancellation remain the stable
/// `wrela-driver` API used by the CLI.
pub trait CompilerFactory {
    fn create<'a>(
        &'a self,
        services: CompilerServices<'a>,
        host: &'a dyn CompilerHost,
        limits: PipelineLimits,
    ) -> Result<Box<dyn CompilerDriver + 'a>, CompositionError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostError {
    Cancelled,
    InvalidPath(PathBuf),
    ResourceLimit {
        resource: &'static str,
        limit: u64,
    },
    Io {
        operation: &'static str,
        message: String,
    },
    DigestMismatch(PathBuf),
    StaleInput(PathBuf),
    DestinationExists(PathBuf),
    PublicationMismatch(PathBuf),
    Target(String),
    Toolchain(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildPlanningError {
    Cancelled,
    ResourceLimit { resource: &'static str, limit: u64 },
    Selection(String),
    TargetMismatch,
    ToolchainMismatch,
    StandardLibrarySelection,
    InvalidProfile(String),
    InvalidBuild(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompositionError {
    InvalidLimits,
    InvalidServices(String),
}

impl fmt::Display for HostError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "compiler host error: {self:?}")
    }
}

impl fmt::Display for BuildPlanningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "build planning failed: {self:?}")
    }
}

impl fmt::Display for CompositionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "compiler composition failed: {self:?}")
    }
}

impl std::error::Error for HostError {}
impl std::error::Error for BuildPlanningError {}
impl std::error::Error for CompositionError {}

#[cfg(test)]
mod tests {
    use super::*;

    struct FixtureHasher;

    struct FixtureDigest(Vec<u8>);

    impl wrela_package_loader::ContentDigest for FixtureDigest {
        fn update(&mut self, bytes: &[u8]) {
            self.0.extend_from_slice(bytes);
        }

        fn finish(self: Box<Self>) -> Sha256Digest {
            FixtureHasher.sha256(&self.0)
        }
    }

    impl ContentHasher for FixtureHasher {
        fn sha256(&self, bytes: &[u8]) -> Sha256Digest {
            let byte = u8::try_from(bytes.len()).unwrap_or(u8::MAX);
            Sha256Digest::from_bytes([byte; 32])
        }

        fn begin_sha256(&self) -> Box<dyn wrela_package_loader::ContentDigest + '_> {
            Box::new(FixtureDigest(Vec::new()))
        }
    }

    fn fixture_build(digest: Sha256Digest) -> BuildIdentity {
        BuildIdentity {
            compiler: digest,
            language: wrela_build_model::LanguageRevision::Design0_1,
            target: TargetIdentity::aarch64_qemu_virt_uefi(),
            target_package: digest,
            standard_library: digest,
            source_graph: digest,
            request: digest,
            profile: digest,
        }
    }

    fn fixture_image() -> ImageDeclaration {
        ImageDeclaration {
            name: "appliance".to_owned(),
            module: wrela_package::ModulePath::new(["firmware".to_owned(), "image".to_owned()])
                .expect("fixture module"),
            entry: "build_image".to_owned(),
            target: TargetIdentity::aarch64_qemu_virt_uefi(),
            profile: "development".to_owned(),
        }
    }

    #[test]
    fn standard_pipeline_policy_is_internally_consistent() {
        PipelineLimits::standard()
            .validate()
            .expect("standard pipeline limits");
    }

    #[test]
    fn canonical_build_request_is_deterministic_and_identity_sensitive() {
        let image = fixture_image();
        let target = TargetIdentity::aarch64_qemu_virt_uefi();
        let baseline = encode_canonical_build_request(
            &image,
            &target,
            "development",
            BuildIntent::Build,
            &|| false,
        )
        .expect("canonical request");
        assert_eq!(
            baseline,
            encode_canonical_build_request(
                &image,
                &target,
                "development",
                BuildIntent::Build,
                &|| false,
            )
            .expect("repeat canonical request")
        );
        assert!(baseline.starts_with(b"WRELREQ\0\x01\0\0\0"));
        assert!(
            baseline
                .windows("firmware.image".len())
                .any(|window| { window == "firmware.image".as_bytes() })
        );

        let mut changed = image.clone();
        changed.name = "other".to_owned();
        assert_ne!(
            baseline,
            encode_canonical_build_request(
                &changed,
                &target,
                "development",
                BuildIntent::Build,
                &|| false,
            )
            .expect("changed image name")
        );
        let mut changed = image.clone();
        changed.module =
            wrela_package::ModulePath::new(["other".to_owned()]).expect("changed module");
        assert_ne!(
            baseline,
            encode_canonical_build_request(
                &changed,
                &target,
                "development",
                BuildIntent::Build,
                &|| false,
            )
            .expect("changed module")
        );
        let mut changed = image.clone();
        changed.entry = "other_entry".to_owned();
        assert_ne!(
            baseline,
            encode_canonical_build_request(
                &changed,
                &target,
                "development",
                BuildIntent::Build,
                &|| false,
            )
            .expect("changed entry")
        );
        let other_target = TargetIdentity::new("test-target").expect("other target");
        assert_ne!(
            baseline,
            encode_canonical_build_request(
                &image,
                &other_target,
                "development",
                BuildIntent::Build,
                &|| false,
            )
            .expect("changed target")
        );
        assert_ne!(
            baseline,
            encode_canonical_build_request(&image, &target, "release", BuildIntent::Build, &|| {
                false
            },)
            .expect("changed profile")
        );
        assert_ne!(
            baseline,
            encode_canonical_build_request(
                &image,
                &target,
                "development",
                BuildIntent::Check,
                &|| false,
            )
            .expect("changed intent")
        );
        let filter = TestSelection::NameContains("driver".to_owned());
        let test = encode_canonical_build_request(
            &image,
            &target,
            "development",
            BuildIntent::Test { selection: &filter },
            &|| false,
        )
        .expect("test selection request");
        assert_ne!(baseline, test);
        let lint = encode_canonical_build_request(
            &image,
            &target,
            "development",
            BuildIntent::Lint,
            &|| false,
        )
        .expect("lint request");
        assert_ne!(baseline, lint);
        assert_ne!(test, lint);
    }

    #[test]
    fn canonical_build_request_is_bounded_and_cancellable() {
        let image = fixture_image();
        let target = TargetIdentity::aarch64_qemu_virt_uefi();
        assert!(matches!(
            encode_canonical_build_request(
                &image,
                &target,
                "development",
                BuildIntent::Build,
                &|| true,
            ),
            Err(BuildPlanningError::Cancelled)
        ));
        let mut builder = CanonicalRequestBuilder {
            bytes: vec![0; CANONICAL_BUILD_REQUEST_BYTES as usize],
        };
        assert!(matches!(
            builder.push_byte(0),
            Err(BuildPlanningError::ResourceLimit {
                resource: "canonical build request bytes",
                limit: CANONICAL_BUILD_REQUEST_BYTES,
            })
        ));
        let empty = TestSelection::NameContains("  ".to_owned());
        assert!(matches!(
            encode_canonical_build_request(
                &image,
                &target,
                "development",
                BuildIntent::Test { selection: &empty },
                &|| false,
            ),
            Err(BuildPlanningError::Selection(_))
        ));
    }

    #[test]
    fn rejects_frontend_backend_wire_limit_drift() {
        let mut limits = PipelineLimits::standard();
        limits.flow_codec.frame_bytes -= 1;
        assert_eq!(limits.validate(), Err(CompositionError::InvalidLimits));
    }

    #[test]
    fn rejects_backend_policy_the_private_protocol_cannot_carry() {
        let mut limits = PipelineLimits::standard();
        limits.backend.optimization.decisions -= 1;
        assert_eq!(limits.validate(), Err(CompositionError::InvalidLimits));

        let mut limits = PipelineLimits::standard();
        limits.backend.machine.stack_bytes_per_function -= 1;
        assert_eq!(limits.validate(), Err(CompositionError::InvalidLimits));

        let mut limits = PipelineLimits::standard();
        limits.backend.codegen.maximum_ir_bytes -= 1;
        assert_eq!(limits.validate(), Err(CompositionError::InvalidLimits));

        let mut limits = PipelineLimits::standard();
        limits.backend.maximum_report_bytes -= 1;
        assert_eq!(limits.validate(), Err(CompositionError::InvalidLimits));
    }

    #[test]
    fn rejects_toolchain_observation_decode_limit_drift() {
        let mut limits = PipelineLimits::standard();
        limits.toolchain_verify.target_package.bytes -= 1;
        assert_eq!(limits.validate(), Err(CompositionError::InvalidLimits));

        let mut limits = PipelineLimits::standard();
        limits.toolchain_verify.toolchain_manifest.bytes -= 1;
        assert_eq!(limits.validate(), Err(CompositionError::InvalidLimits));
    }

    #[test]
    fn rejects_cache_policy_too_small_for_canonical_artifacts() {
        let mut limits = PipelineLimits::standard();
        limits.cache.entry_bytes = limits.flow_codec.frame_bytes - 1;
        assert_eq!(limits.validate(), Err(CompositionError::InvalidLimits));
    }

    #[test]
    fn rejects_semantic_test_policy_drift() {
        let mut limits = PipelineLimits::standard();
        limits.test_plan.events_per_group -= 1;
        assert_eq!(limits.validate(), Err(CompositionError::InvalidLimits));
    }

    #[test]
    fn rejects_flow_and_backend_test_policy_drift() {
        let mut limits = PipelineLimits::standard();
        limits.flow_lower.test_plan.events_per_group -= 1;
        assert_eq!(limits.validate(), Err(CompositionError::InvalidLimits));

        let mut limits = PipelineLimits::standard();
        limits.flow_codec.test_plan.events_per_group -= 1;
        assert_eq!(limits.validate(), Err(CompositionError::InvalidLimits));

        let mut limits = PipelineLimits::standard();
        limits.backend.codec.test_plan.events_per_group -= 1;
        assert_eq!(limits.validate(), Err(CompositionError::InvalidLimits));

        let mut limits = PipelineLimits::standard();
        limits.backend.optimization.test_plan.events_per_group -= 1;
        assert_eq!(limits.validate(), Err(CompositionError::InvalidLimits));
    }

    #[test]
    fn rejects_codegen_link_measurement_drift() {
        let mut limits = PipelineLimits::standard();
        limits.backend.link.sections -= 1;
        assert_eq!(limits.validate(), Err(CompositionError::InvalidLimits));
    }

    #[test]
    fn rejects_frontend_backend_report_policy_drift() {
        let mut limits = PipelineLimits::standard();
        limits.backend.analysis_report_facts.items -= 1;
        assert_eq!(limits.validate(), Err(CompositionError::InvalidLimits));
    }

    #[test]
    fn rejects_format_batch_without_aggregate_budget() {
        let mut limits = PipelineLimits::standard();
        limits.format.output_bytes = limits.format.output_bytes_per_file - 1;
        assert_eq!(limits.validate(), Err(CompositionError::InvalidLimits));

        let mut limits = PipelineLimits::standard();
        limits.format.edits_per_file = 0;
        assert_eq!(limits.validate(), Err(CompositionError::InvalidLimits));
    }

    #[test]
    fn seals_atomic_publication_identity_before_driver_use() {
        let request = seal_file_publication_request(
            &FixtureHasher,
            PathBuf::from("/tmp/wrela/report.json"),
            b"report".to_vec(),
            FilePublicationMode::CreateNew,
            64,
            &|| false,
        )
        .expect("valid publication request");
        let receipt = FilePublicationReceipt {
            path: request.destination().to_owned(),
            digest: request.digest(),
            bytes: request.bytes().len() as u64,
        };
        let published = seal_file_publication(&request, receipt).expect("matching receipt");
        assert_eq!(published.path(), Path::new("/tmp/wrela/report.json"));
        assert!(matches!(
            seal_file_publication_request(
                &FixtureHasher,
                PathBuf::from("relative/report.json"),
                Vec::new(),
                FilePublicationMode::CreateNew,
                64,
                &|| false,
            ),
            Err(HostError::InvalidPath(_))
        ));
    }

    #[test]
    fn cache_candidates_are_bound_to_exact_build_key_and_bytes() {
        let bytes = b"flow-frame".to_vec();
        let digest = FixtureHasher.sha256(&bytes);
        let key = CacheKey::new(
            CachedArtifactKind::FlowWirFrame,
            fixture_build(Sha256Digest::from_bytes([1; 32])),
            Sha256Digest::from_bytes([2; 32]),
        )
        .expect("valid cache key");
        let request = CacheReadRequest {
            key: &key,
            maximum_bytes: 64,
        };
        let artifact = seal_cached_artifact(
            &request,
            CacheEntryCandidate {
                key: key.clone(),
                bytes: bytes.clone(),
                digest,
            },
            &FixtureHasher,
            &|| false,
        )
        .expect("valid cache candidate");
        assert_eq!(artifact.bytes(), bytes);
        assert_eq!(artifact.key(), &key);

        let wrong_key = CacheKey::new(
            CachedArtifactKind::ImageReport,
            fixture_build(Sha256Digest::from_bytes([1; 32])),
            Sha256Digest::from_bytes([2; 32]),
        )
        .expect("valid other cache key");
        assert_eq!(
            seal_cached_artifact(
                &request,
                CacheEntryCandidate {
                    key: wrong_key,
                    bytes,
                    digest,
                },
                &FixtureHasher,
                &|| false,
            ),
            Err(CacheError::KeyMismatch)
        );
    }
}
