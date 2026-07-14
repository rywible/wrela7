//! Private backend composition: decode and independently validate FlowWir,
//! optimize it, fix AArch64 layout/runtime ABI, generate COFF, link EFI, and
//! report the exact artifact.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Component, Path, PathBuf};

use wrela_backend_protocol::{
    BackendFailure, BackendOutcome, BackendRequest, BackendResponse, BackendSuccess,
};
use wrela_build_model::{Sha256Digest, ValidatedBuildConfiguration};
use wrela_codegen_llvm::{CodegenOptions, ObjectArtifact};
use wrela_flow_opt::{
    FlowOptimizer, OptimizationLimits, OptimizationProfile, OptimizationRequest, OptimizedFlowWir,
};
use wrela_flow_wir::ValidatedFlowWir;
use wrela_flow_wir_codec::{
    CodecLimits, DecodeRequest, FlowWirCodec, decode_and_verify as decode_flow_wir,
};
use wrela_image_report::{AnalysisFactLimits, BackendFactLimits, ImageReport, ReportError};
use wrela_link_efi::{EfiArtifact, LinkLimits, TargetRuntimeObject};
use wrela_machine_lower::{
    MachineLowerError, MachineLowerer, MachineLoweringLimits, MachineLoweringOutput,
    MachineLoweringRequest,
};
use wrela_target::TargetPackage;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendPreparationOptions {
    pub codec_limits: CodecLimits,
    pub optimization: OptimizationProfile,
    pub optimization_limits: OptimizationLimits,
    pub machine_limits: MachineLoweringLimits,
}

/// Complete resource policy for one private backend job. Keeping this as one
/// value lets the composition root validate every backend ceiling without
/// depending directly on the backend's implementation crates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendLimits {
    pub codec: CodecLimits,
    pub optimization: OptimizationLimits,
    pub machine: MachineLoweringLimits,
    pub codegen: CodegenOptions,
    pub link: LinkLimits,
    pub analysis_report_facts: AnalysisFactLimits,
    pub report_facts: BackendFactLimits,
    pub maximum_report_bytes: u64,
}

impl BackendLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            codec: CodecLimits::standard(),
            optimization: OptimizationLimits::standard(),
            machine: MachineLoweringLimits::standard(),
            codegen: CodegenOptions::standard(),
            link: LinkLimits::standard(),
            analysis_report_facts: AnalysisFactLimits::standard(),
            report_facts: BackendFactLimits::standard(),
            maximum_report_bytes: 1024 * 1024 * 1024,
        }
    }

    pub fn validate(self) -> Result<(), BackendExecutionError> {
        self.codec
            .validate()
            .map_err(|error| BackendExecutionError::InvalidRequest(error.to_string()))?;
        self.optimization
            .validate()
            .map_err(|error| BackendExecutionError::InvalidRequest(error.to_string()))?;
        self.machine
            .validate()
            .map_err(|error| BackendExecutionError::InvalidRequest(error.to_string()))?;
        self.codegen
            .validate()
            .map_err(|error| BackendExecutionError::InvalidRequest(error.to_string()))?;
        if !self.link.is_valid()
            || self.analysis_report_facts.validate().is_err()
            || self.report_facts.validate().is_err()
            || self.maximum_report_bytes == 0
            || self.codegen.maximum_object_bytes != self.link.object_bytes
            || self.codegen.maximum_sections != self.link.sections
            || self.codegen.maximum_symbols != self.link.symbols
            || self.codegen.maximum_measurement_bytes != self.link.measurement_bytes
        {
            return Err(BackendExecutionError::InvalidRequest(
                "backend codegen/link/report ceilings are invalid or inconsistent".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PreparedBackendInput {
    optimized: OptimizedFlowWir,
    machine: MachineLoweringOutput,
}

impl PreparedBackendInput {
    #[must_use]
    pub fn optimized(&self) -> &OptimizedFlowWir {
        &self.optimized
    }

    #[must_use]
    pub fn machine(&self) -> &MachineLoweringOutput {
        &self.machine
    }

    #[must_use]
    pub fn into_parts(self) -> (OptimizedFlowWir, MachineLoweringOutput) {
        (self.optimized, self.machine)
    }
}

#[derive(Clone, Copy)]
pub struct BackendPreparationServices<'a> {
    pub codec: &'a dyn FlowWirCodec,
    pub hasher: &'a dyn BackendContentHasher,
    pub optimizer: &'a dyn FlowOptimizer,
    pub machine_lowerer: &'a dyn MachineLowerer,
}

/// SHA-256 capability used before the backend decodes a frontend-produced IR
/// frame. It is injected so tests can verify the ordering without filesystem
/// or global crypto state.
pub trait BackendContentHasher {
    /// Return `None` only when cancellation was observed while hashing.
    fn sha256(&self, bytes: &[u8], is_cancelled: &dyn Fn() -> bool) -> Option<Sha256Digest>;
}

/// All paths are inside one driver-created private directory. Final paths are
/// distinct from temporary paths so a failed job cannot expose partial output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendJobPathCandidate {
    pub private_root: PathBuf,
    pub generated_object: PathBuf,
    pub temporary_image: PathBuf,
    pub temporary_map: PathBuf,
    pub final_image: PathBuf,
    pub final_report: PathBuf,
}

/// Validated private namespace for one backend job. Fields are immutable after
/// construction so path validation cannot be invalidated before execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendJobPaths(BackendJobPathCandidate);

impl BackendJobPaths {
    pub fn new(candidate: BackendJobPathCandidate) -> Result<Self, BackendExecutionError> {
        let paths = [
            &candidate.generated_object,
            &candidate.temporary_image,
            &candidate.temporary_map,
            &candidate.final_image,
            &candidate.final_report,
        ];
        let valid = normal_absolute_path(&candidate.private_root)
            && candidate.private_root.components().count() > 1
            && paths.iter().all(|path| {
                normal_absolute_path(path)
                    && path.starts_with(&candidate.private_root)
                    && *path != &candidate.private_root
            })
            && paths
                .iter()
                .enumerate()
                .all(|(index, path)| paths[..index].iter().all(|other| other != path));
        if !valid {
            return Err(BackendExecutionError::InvalidPaths);
        }
        Ok(Self(candidate))
    }

    #[must_use]
    pub fn private_root(&self) -> &Path {
        &self.0.private_root
    }

    #[must_use]
    pub fn generated_object(&self) -> &Path {
        &self.0.generated_object
    }

    #[must_use]
    pub fn temporary_image(&self) -> &Path {
        &self.0.temporary_image
    }

    #[must_use]
    pub fn temporary_map(&self) -> &Path {
        &self.0.temporary_map
    }

    #[must_use]
    pub fn final_image(&self) -> &Path {
        &self.0.final_image
    }

    #[must_use]
    pub fn final_report(&self) -> &Path {
        &self.0.final_report
    }
}

fn normal_absolute_path(path: &Path) -> bool {
    let normalized: PathBuf = path.components().collect();
    path.is_absolute()
        && !path.as_os_str().is_empty()
        && normalized.as_os_str() == path.as_os_str()
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendExecutionOptions {
    pub optimization: OptimizationProfile,
    pub limits: BackendLimits,
}

impl BackendExecutionOptions {
    pub fn validate(&self) -> Result<(), BackendExecutionError> {
        self.optimization
            .validate()
            .map_err(|error| BackendExecutionError::InvalidRequest(error.to_string()))?;
        self.limits.validate()
    }

    #[must_use]
    pub fn preparation(&self) -> BackendPreparationOptions {
        BackendPreparationOptions {
            codec_limits: self.limits.codec,
            optimization: self.optimization.clone(),
            optimization_limits: self.limits.optimization,
            machine_limits: self.limits.machine,
        }
    }
}

#[derive(Debug)]
pub struct BackendExecutionRequest<'a> {
    pub protocol: &'a BackendRequest,
    /// Independently profile-digest-verified form of `protocol.build`.
    pub build: &'a ValidatedBuildConfiguration,
    pub wir_bytes: &'a [u8],
    pub target: &'a TargetPackage,
    pub target_runtime: TargetRuntimeObject<'a>,
    pub paths: &'a BackendJobPaths,
    pub options: BackendExecutionOptions,
}

impl BackendExecutionRequest<'_> {
    /// Validate all orchestration-only joins before decoding or LLVM work.
    pub fn validate(&self) -> Result<(), BackendExecutionError> {
        self.target
            .validate()
            .map_err(|error| BackendExecutionError::InvalidRequest(error.to_string()))?;
        if self.paths.final_image()
            != self
                .paths
                .private_root()
                .join(self.protocol.output.as_str())
            || self.paths.final_report()
                != self
                    .paths
                    .private_root()
                    .join(self.protocol.report.as_str())
        {
            return Err(BackendExecutionError::InvalidPaths);
        }
        if self.protocol.build != *self.build.as_configuration()
            || self.build.identity.target != *self.target.identity()
            || self.build.identity.target_package != self.target.semantic().content_digest()
            || self.target_runtime.target_package != self.target.semantic().content_digest()
            || self.target_runtime.runtime_abi_version
                != self.target.backend().runtime_abi_version()
            || self.target_runtime.bytes == 0
            || !normal_absolute_path(self.target_runtime.path)
        {
            return Err(BackendExecutionError::InvalidRequest(
                "request build, target package, or verified runtime object disagree".to_owned(),
            ));
        }
        self.options.validate()?;
        Ok(())
    }
}

/// Complete inputs for deterministic report construction. Every measurement
/// comes from a sealed producer rather than another filesystem inspection.
pub struct BackendReportRequest<'a> {
    pub flow_wir_digest: Sha256Digest,
    pub optimized: &'a OptimizedFlowWir,
    pub machine: &'a MachineLoweringOutput,
    pub object: &'a ObjectArtifact,
    pub artifact: &'a EfiArtifact,
    pub target: &'a TargetPackage,
    pub analysis_fact_limits: AnalysisFactLimits,
    pub fact_limits: BackendFactLimits,
    pub maximum_report_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBackendReport(ImageReport);

impl VerifiedBackendReport {
    #[must_use]
    pub fn as_report(&self) -> &ImageReport {
        &self.0
    }

    #[must_use]
    pub fn into_report(self) -> ImageReport {
        self.0
    }
}

pub trait BackendReportAssembler {
    fn assemble(
        &self,
        request: BackendReportRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<VerifiedBackendReport, BackendReportError>;
}

/// Bind an assembled report to every independently sealed backend input. This
/// catches a report implementation that is internally valid but describes a
/// different IR, pipeline, target, object, or linked image.
pub fn seal_backend_report(
    request: &BackendReportRequest<'_>,
    report: ImageReport,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<VerifiedBackendReport, BackendReportError> {
    if is_cancelled() {
        return Err(BackendReportError::Cancelled);
    }
    report
        .validate_with_cancellation(is_cancelled)
        .map_err(BackendReportError::Report)?;
    request
        .analysis_fact_limits
        .validate()
        .map_err(BackendReportError::Report)?;
    request
        .fact_limits
        .validate()
        .map_err(BackendReportError::Report)?;
    if request.maximum_report_bytes == 0 {
        return Err(BackendReportError::Mismatch("report byte limit is zero"));
    }
    let flow = request.optimized.wir().as_wir();
    let machine = request.machine.wir().as_wir();
    let backend = report.backend();
    let representations = &backend.representations;
    let pipeline = &request.optimized.report().profile.pipeline;
    let analysis = report.analysis();
    if report.build() != &flow.build
        || report.build() != &machine.build
        || report.build() != request.object.build()
        || report.build() != request.artifact.build()
        || report.image_name() != flow.name
        || report.image_name() != machine.name
        || report.analysis_limits() != request.analysis_fact_limits
        || report.backend_limits() != request.fact_limits
        || backend.flow_wir_digest != request.flow_wir_digest
        || analysis.reachable_declarations != flow.source_summary.reachable_declarations
        || analysis.monomorphized_instantiations != flow.source_summary.monomorphized_instantiations
        || analysis.resolved_interface_calls != flow.source_summary.resolved_interface_calls
        || representations.semantic_wir_version != flow.source_summary.semantic_wir_version
        || representations.flow_wir_version != flow.version
        || representations.flow_wir_wire_version != wrela_flow_wir_codec::FLOW_WIR_WIRE_VERSION
        || representations.machine_wir_version != machine.version
        || representations.runtime_abi_version != machine.runtime.version
        || representations.optimization_pipeline_name != pipeline.name
        || representations.optimization_pipeline_revision != pipeline.revision
        || representations.optimization_pipeline_implementation != pipeline.implementation
        || request.target.identity() != &flow.build.target
        || request.target.semantic().content_digest() != flow.build.target_package
        || backend.artifact_bytes != request.artifact.measurements().artifact_bytes
        || backend.artifact_digest != request.artifact.measurements().artifact_digest
    {
        return Err(BackendReportError::Mismatch(
            "report identity, version, pipeline, target, or artifact facts differ from inputs",
        ));
    }
    let expected_intrinsics: Vec<_> = machine
        .runtime
        .intrinsics
        .iter()
        .map(|intrinsic| intrinsic.symbol_name().to_owned())
        .collect();
    if backend.required_runtime_intrinsics != expected_intrinsics
        || !report_sections_match(backend, request.artifact.measurements(), is_cancelled)?
        || !report_symbols_match(backend, request.artifact.measurements(), is_cancelled)?
    {
        return Err(BackendReportError::Mismatch(
            "report runtime, section, or symbol facts differ from linked image",
        ));
    }
    let json = report
        .to_json_with_cancellation(is_cancelled)
        .map_err(BackendReportError::Report)?;
    let bytes = u64::try_from(json.len())
        .map_err(|_| BackendReportError::Mismatch("report byte count overflowed"))?;
    if bytes > request.maximum_report_bytes {
        return Err(BackendReportError::Mismatch(
            "canonical report exceeds the request byte limit",
        ));
    }
    if is_cancelled() {
        return Err(BackendReportError::Cancelled);
    }
    Ok(VerifiedBackendReport(report))
}

fn report_sections_match(
    report: &wrela_image_report::BackendFacts,
    artifact: &wrela_link_efi::ImageMeasurements,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, BackendReportError> {
    let measured: BTreeMap<_, _> = artifact
        .sections
        .iter()
        .map(|section| (section.name.as_str(), section.virtual_bytes))
        .collect();
    if measured.len() != artifact.sections.len() || report.sections.len() != measured.len() {
        return Ok(false);
    }
    for reported in &report.sections {
        if is_cancelled() {
            return Err(BackendReportError::Cancelled);
        }
        if measured.get(reported.name.as_str()).copied() != Some(reported.bytes) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn report_symbols_match(
    report: &wrela_image_report::BackendFacts,
    artifact: &wrela_link_efi::ImageMeasurements,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, BackendReportError> {
    let sections: BTreeMap<_, _> = artifact
        .sections
        .iter()
        .map(|section| (section.name.as_str(), section.virtual_address))
        .collect();
    let symbols: BTreeMap<_, _> = artifact
        .symbols
        .iter()
        .map(|symbol| (symbol.name.as_str(), symbol))
        .collect();
    if sections.len() != artifact.sections.len()
        || symbols.len() != artifact.symbols.len()
        || report.symbols.len() != symbols.len()
    {
        return Ok(false);
    }
    for reported in &report.symbols {
        if is_cancelled() {
            return Err(BackendReportError::Cancelled);
        }
        let Some(measured) = symbols.get(reported.name.as_str()) else {
            return Ok(false);
        };
        let Some(section_address) = sections.get(measured.section.as_str()) else {
            return Ok(false);
        };
        if measured.section != reported.section
            || measured.bytes != reported.bytes
            || measured.virtual_address.checked_sub(*section_address) != Some(reported.offset)
        {
            return Ok(false);
        }
    }
    Ok(true)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendReportError {
    Cancelled,
    Report(ReportError),
    Mismatch(&'static str),
}

impl fmt::Display for BackendReportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("backend report assembly was cancelled"),
            Self::Report(error) => error.fmt(formatter),
            Self::Mismatch(reason) => write!(formatter, "backend report mismatch: {reason}"),
        }
    }
}

impl std::error::Error for BackendReportError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedBackendArtifacts {
    success: BackendSuccess,
    build: wrela_build_model::BuildIdentity,
}

impl PublishedBackendArtifacts {
    #[must_use]
    pub fn success(&self) -> &BackendSuccess {
        &self.success
    }
}

/// Bind an atomic publication result to the exact request, post-link artifact,
/// and canonical report. This is the only constructor for a successful
/// publication capability.
pub fn seal_publication(
    request: &BackendRequest,
    artifact: &EfiArtifact,
    report: &VerifiedBackendReport,
    success: BackendSuccess,
    hasher: &dyn BackendContentHasher,
    maximum_report_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<PublishedBackendArtifacts, BackendExecutionError> {
    if is_cancelled() {
        return Err(BackendExecutionError::Cancelled);
    }
    let report = report.as_report();
    if artifact.build() != &request.build.identity || report.build() != &request.build.identity {
        return Err(BackendExecutionError::InternalInvariant(
            "published artifact or report build identity differs from the request".to_owned(),
        ));
    }
    if success.artifact != request.output || success.report != request.report {
        return Err(BackendExecutionError::InternalInvariant(
            "publisher returned paths other than the requested artifact/report paths".to_owned(),
        ));
    }
    if success.artifact_digest != artifact.measurements().artifact_digest {
        return Err(BackendExecutionError::DigestMismatch { artifact: "image" });
    }
    if report.backend().flow_wir_digest != request.wir_digest
        || report.backend().artifact_digest != artifact.measurements().artifact_digest
        || report.backend().artifact_bytes != artifact.measurements().artifact_bytes
    {
        return Err(BackendExecutionError::InternalInvariant(
            "published report describes different FlowWir or artifact measurements".to_owned(),
        ));
    }
    let report_json = bounded_report_json(report, maximum_report_bytes, is_cancelled)?;
    let report_digest = hasher
        .sha256(report_json.as_bytes(), is_cancelled)
        .ok_or(BackendExecutionError::Cancelled)?;
    if success.report_digest != report_digest {
        return Err(BackendExecutionError::DigestMismatch { artifact: "report" });
    }
    Ok(PublishedBackendArtifacts {
        success,
        build: request.build.identity.clone(),
    })
}

/// Only capability allowed to materialize the generated object and atomically
/// publish the final image/report pair. Implementations must verify the report
/// digest over `ImageReport::to_json()` and the artifact digest supplied by the
/// post-link inspector before a rename/publish becomes visible.
pub trait BackendPublisher {
    fn materialize_object(
        &self,
        path: &Path,
        object: &ObjectArtifact,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), BackendExecutionError>;

    fn publish(
        &self,
        request: &BackendRequest,
        paths: &BackendJobPaths,
        artifact: &EfiArtifact,
        report: &VerifiedBackendReport,
        maximum_report_bytes: u64,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<PublishedBackendArtifacts, BackendExecutionError>;
}

#[derive(Debug)]
pub struct BackendExecutionOutput {
    response: BackendResponse,
    product: BackendExecutionProduct,
}

#[derive(Debug)]
enum BackendExecutionProduct {
    Success {
        artifact: Box<EfiArtifact>,
        report: Box<ImageReport>,
    },
    Failure(BackendFailure),
}

pub type BackendSuccessProduct = (Box<EfiArtifact>, Box<ImageReport>);
pub type BackendExecutionParts = (
    BackendResponse,
    Result<BackendSuccessProduct, BackendFailure>,
);

impl BackendExecutionOutput {
    #[must_use]
    pub fn response(&self) -> &BackendResponse {
        &self.response
    }

    #[must_use]
    pub fn artifact(&self) -> Option<&EfiArtifact> {
        match &self.product {
            BackendExecutionProduct::Success { artifact, .. } => Some(artifact),
            BackendExecutionProduct::Failure(_) => None,
        }
    }

    #[must_use]
    pub fn report(&self) -> Option<&ImageReport> {
        match &self.product {
            BackendExecutionProduct::Success { report, .. } => Some(report),
            BackendExecutionProduct::Failure(_) => None,
        }
    }

    #[must_use]
    pub fn failure(&self) -> Option<&BackendFailure> {
        match &self.product {
            BackendExecutionProduct::Success { .. } => None,
            BackendExecutionProduct::Failure(failure) => Some(failure),
        }
    }

    pub fn into_parts(self) -> BackendExecutionParts {
        let product = match self.product {
            BackendExecutionProduct::Success { artifact, report } => Ok((artifact, report)),
            BackendExecutionProduct::Failure(failure) => Err(failure),
        };
        (self.response, product)
    }
}

/// Finish a backend success only when publication is still bound to the exact
/// artifact and report passed to the consumer.
pub fn finish_success(
    request: &BackendRequest,
    publication: PublishedBackendArtifacts,
    artifact: EfiArtifact,
    report: VerifiedBackendReport,
    hasher: &dyn BackendContentHasher,
    maximum_report_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<BackendExecutionOutput, BackendExecutionError> {
    if is_cancelled() {
        return Err(BackendExecutionError::Cancelled);
    }
    let report_json = bounded_report_json(report.as_report(), maximum_report_bytes, is_cancelled)?;
    let report_digest = hasher
        .sha256(report_json.as_bytes(), is_cancelled)
        .ok_or(BackendExecutionError::Cancelled)?;
    if publication.build != request.build.identity
        || artifact.build() != &publication.build
        || report.as_report().build() != &publication.build
        || report.as_report().backend().flow_wir_digest != request.wir_digest
        || report.as_report().backend().artifact_digest != artifact.measurements().artifact_digest
        || report.as_report().backend().artifact_bytes != artifact.measurements().artifact_bytes
        || publication.success.artifact_digest != artifact.measurements().artifact_digest
        || publication.success.report_digest != report_digest
    {
        return Err(BackendExecutionError::InternalInvariant(
            "published success was paired with a different request, artifact, or report".to_owned(),
        ));
    }
    let response = BackendResponse {
        request_id: request.request_id,
        outcome: BackendOutcome::Success(publication.success),
    };
    let report = report.into_report();
    Ok(BackendExecutionOutput {
        response,
        product: BackendExecutionProduct::Success {
            artifact: Box::new(artifact),
            report: Box::new(report),
        },
    })
}

fn bounded_report_json(
    report: &ImageReport,
    maximum_report_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<String, BackendExecutionError> {
    if is_cancelled() {
        return Err(BackendExecutionError::Cancelled);
    }
    if maximum_report_bytes == 0 {
        return Err(BackendExecutionError::InvalidRequest(
            "maximum report bytes must be nonzero".to_owned(),
        ));
    }
    let json = report
        .to_json_with_cancellation(is_cancelled)
        .map_err(|error| BackendExecutionError::InternalInvariant(error.to_string()))?;
    if is_cancelled() {
        return Err(BackendExecutionError::Cancelled);
    }
    let bytes = u64::try_from(json.len()).map_err(|_| {
        BackendExecutionError::InvalidRequest("image report byte count overflow".to_owned())
    })?;
    if bytes > maximum_report_bytes {
        return Err(BackendExecutionError::InvalidRequest(format!(
            "image report exceeds {maximum_report_bytes} bytes"
        )));
    }
    Ok(json)
}

/// Construct a failure response from one source of truth; the typed protocol
/// outcome and local failure value cannot disagree.
#[must_use]
pub fn finish_failure(request: &BackendRequest, failure: BackendFailure) -> BackendExecutionOutput {
    BackendExecutionOutput {
        response: BackendResponse {
            request_id: request.request_id,
            outcome: BackendOutcome::Failure(failure.clone()),
        },
        product: BackendExecutionProduct::Failure(failure),
    }
}

/// Production backend service boundary. A job failure is returned as a typed
/// protocol response; only cancellation, private-workspace I/O, or a violated
/// internal invariant escapes as `BackendExecutionError`.
pub trait BackendExecutor {
    fn execute(
        &self,
        request: BackendExecutionRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<BackendExecutionOutput, BackendExecutionError>;
}

#[derive(Debug)]
pub enum BackendExecutionError {
    Cancelled,
    InvalidPaths,
    InvalidRequest(String),
    PrivateIo {
        operation: &'static str,
        message: String,
    },
    DigestMismatch {
        artifact: &'static str,
    },
    InternalInvariant(String),
}

impl fmt::Display for BackendExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("backend execution was cancelled"),
            Self::InvalidPaths => {
                formatter.write_str("backend private or publication paths are invalid")
            }
            Self::InvalidRequest(message) => {
                write!(formatter, "invalid backend execution request: {message}")
            }
            Self::PrivateIo { operation, message } => {
                write!(formatter, "backend {operation} failed: {message}")
            }
            Self::DigestMismatch { artifact } => write!(
                formatter,
                "published {artifact} digest differs from its sealed measurement"
            ),
            Self::InternalInvariant(message) => {
                write!(formatter, "backend invariant failed: {message}")
            }
        }
    }
}

impl std::error::Error for BackendExecutionError {}

/// Exact frontend artifact and provenance expected by backend verification.
/// Keeping these fields together prevents callers from accidentally mixing an
/// artifact from one build with the target or limits from another invocation.
pub struct BackendDecodeRequest<'a> {
    pub bytes: &'a [u8],
    pub expected_digest: Sha256Digest,
    pub target: &'a TargetPackage,
    pub build: &'a ValidatedBuildConfiguration,
    pub limits: CodecLimits,
}

/// Decode and structurally validate the exact frontend/backend exchange type.
pub fn decode_and_verify(
    codec: &dyn FlowWirCodec,
    hasher: &dyn BackendContentHasher,
    request: BackendDecodeRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ValidatedFlowWir, BackendInputError> {
    if hasher
        .sha256(request.bytes, is_cancelled)
        .ok_or(BackendInputError::Cancelled)?
        != request.expected_digest
    {
        return Err(BackendInputError::FlowWirDigestMismatch);
    }
    request
        .target
        .validate()
        .map_err(BackendInputError::Target)?;
    if request.target.identity() != &request.build.identity.target
        || request.target.semantic().content_digest() != request.build.identity.target_package
    {
        return Err(BackendInputError::BuildTargetMismatch);
    }
    decode_flow_wir(
        codec,
        DecodeRequest {
            bytes: request.bytes,
            limits: request.limits,
            expected_build: Some(&request.build.identity),
        },
        is_cancelled,
    )
    .map_err(BackendInputError::Decode)
}

/// Complete all representation transitions required before LLVM. The backend
/// owns these implementations and re-establishes their invariants even when
/// the frontend has already done equivalent checking.
pub fn prepare_for_codegen(
    services: BackendPreparationServices<'_>,
    bytes: &[u8],
    expected_digest: Sha256Digest,
    target: &TargetPackage,
    build: &ValidatedBuildConfiguration,
    options: BackendPreparationOptions,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<PreparedBackendInput, BackendInputError> {
    let decoded = decode_and_verify(
        services.codec,
        services.hasher,
        BackendDecodeRequest {
            bytes,
            expected_digest,
            target,
            build,
            limits: options.codec_limits,
        },
        is_cancelled,
    )?;
    let optimized = services
        .optimizer
        .optimize(
            OptimizationRequest {
                input: decoded,
                profile: options.optimization,
                limits: options.optimization_limits,
            },
            is_cancelled,
        )
        .map_err(BackendInputError::Optimize)?;
    let machine = services
        .machine_lowerer
        .lower(
            MachineLoweringRequest {
                input: &optimized,
                target,
                build,
                limits: options.machine_limits,
            },
            is_cancelled,
        )
        .map_err(BackendInputError::MachineLower)?;
    Ok(PreparedBackendInput { optimized, machine })
}

#[derive(Debug)]
pub enum BackendInputError {
    Cancelled,
    FlowWirDigestMismatch,
    Target(wrela_target::TargetError),
    BuildTargetMismatch,
    Decode(wrela_flow_wir_codec::CodecError),
    Optimize(wrela_flow_opt::OptimizeError),
    MachineLower(MachineLowerError),
}

impl fmt::Display for BackendInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("backend input verification was cancelled"),
            Self::FlowWirDigestMismatch => {
                formatter.write_str("FlowWir bytes do not match the backend request digest")
            }
            Self::Target(error) => error.fmt(formatter),
            Self::BuildTargetMismatch => {
                formatter.write_str("backend build and selected target differ")
            }
            Self::Decode(error) => error.fmt(formatter),
            Self::Optimize(error) => error.fmt(formatter),
            Self::MachineLower(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for BackendInputError {}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{BackendExecutionError, BackendJobPathCandidate, BackendJobPaths};

    fn paths(root: &str) -> BackendJobPathCandidate {
        let root = PathBuf::from(root);
        BackendJobPathCandidate {
            generated_object: root.join("image.obj"),
            temporary_image: root.join("image.tmp.efi"),
            temporary_map: root.join("image.tmp.map"),
            final_image: root.join("image.efi"),
            final_report: root.join("image.json"),
            private_root: root,
        }
    }

    #[test]
    fn backend_paths_require_one_normal_private_namespace() {
        BackendJobPaths::new(paths("/private/wrela/job")).expect("valid private namespace");
        assert!(matches!(
            BackendJobPaths::new(paths("/")),
            Err(BackendExecutionError::InvalidPaths)
        ));
        assert!(matches!(
            BackendJobPaths::new(paths("/private/./wrela/job")),
            Err(BackendExecutionError::InvalidPaths)
        ));
        assert!(matches!(
            BackendJobPaths::new(paths("/private/wrela/../job")),
            Err(BackendExecutionError::InvalidPaths)
        ));

        let mut duplicate = paths("/private/wrela/job");
        duplicate.final_report = duplicate.final_image.clone();
        assert!(matches!(
            BackendJobPaths::new(duplicate),
            Err(BackendExecutionError::InvalidPaths)
        ));

        let mut root_as_file = paths("/private/wrela/job");
        root_as_file.final_report = root_as_file.private_root.clone();
        assert!(matches!(
            BackendJobPaths::new(root_as_file),
            Err(BackendExecutionError::InvalidPaths)
        ));
    }
}
