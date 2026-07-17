//! Concrete local revision-0.1 build composition.
//!
//! The frontend keeps source acquisition and semantic analysis in-process, but
//! crosses the installed, digest-verified private backend executable for every
//! native operation. Inputs are copied into one private directory, the framed
//! response is decoded canonically, and both returned files are independently
//! reopened and remeasured before publication.

use std::cell::RefCell;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command as ProcessCommand, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use wrela_backend::{
    BackendFailureKind, BackendLimits, BackendOutcome, BackendPath, BackendRequest,
    MAX_PROTOCOL_FRAME_BYTES, RequestId, decode_response, encode_request, encode_response,
};
use wrela_build_model::Sha256Digest;
use wrela_diagnostics::Severity;
use wrela_driver::{
    BackendFailurePhase, BuildOutcome, BuildOutcomeCandidate, Command, CommandOutput,
    CompilerDriver, DiagnosticReport, DriverError, DriverEvent, EventSink, OutcomeContentHasher,
    WorkspaceSelection,
};
use wrela_flow_lower::{CanonicalFlowLowerer, FlowLowerer};
use wrela_package_loader::{ContentHasher, SoftwareSha256, sha256_cancellable};
use wrela_semantic_lower::{CanonicalSemanticLowerer, SemanticLowerer};
use wrela_toolchain::VerifiedPath;

use crate::local_check::{LocalAnalysis, LocalCheckDriver};
use crate::{
    ArtifactCache, BuildIntent, CacheEntryCandidate, CacheError, CacheReadRequest, CachedArtifact,
    CompositionError, LocalArtifactCache, PipelineLimits, flow_wir_cache_key,
    resolve_flow_wir_frame,
};

const BACKEND_STDERR_BYTES: usize = 1024 * 1024;
const BACKEND_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(10);
const TEMPORARY_DIRECTORY_ATTEMPTS: u64 = 1024;
const MAX_OUTPUT_PATH_BYTES: usize = 1024 * 1024;

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct DeferredArtifactCache<'a> {
    cache: &'a LocalArtifactCache,
    pending: RefCell<Option<CachedArtifact>>,
}

impl<'a> DeferredArtifactCache<'a> {
    fn new(cache: &'a LocalArtifactCache) -> Self {
        Self {
            cache,
            pending: RefCell::new(None),
        }
    }

    fn flush_after_publication(&self, is_cancelled: &dyn Fn() -> bool) {
        if let Some(artifact) = self.pending.borrow_mut().take() {
            let _ = self.cache.store(&artifact, is_cancelled);
        }
    }
}

impl ArtifactCache for DeferredArtifactCache<'_> {
    fn load(
        &self,
        request: &CacheReadRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Option<CacheEntryCandidate>, CacheError> {
        self.cache.load(request, is_cancelled)
    }

    fn store(
        &self,
        artifact: &CachedArtifact,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), CacheError> {
        if is_cancelled() {
            return Err(CacheError::Cancelled);
        }
        let pending = artifact.clone();
        if is_cancelled() {
            return Err(CacheError::Cancelled);
        }
        self.pending.replace(Some(pending));
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct LocalBuildDriver {
    frontend: LocalCheckDriver,
}

impl LocalBuildDriver {
    pub fn new(
        toolchain: wrela_toolchain::Toolchain,
        limits: PipelineLimits,
    ) -> Result<Self, CompositionError> {
        Ok(Self {
            frontend: LocalCheckDriver::new(toolchain, limits)?,
        })
    }

    pub fn discover(limits: PipelineLimits) -> Result<Self, DriverError> {
        Ok(Self {
            frontend: LocalCheckDriver::discover(limits)?,
        })
    }

    #[must_use]
    pub const fn limits(&self) -> PipelineLimits {
        self.frontend.limits()
    }

    fn build(
        &self,
        workspace: &WorkspaceSelection,
        output_directory: &Path,
        options: &wrela_driver::DiagnosticOptions,
        events: &dyn EventSink,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<CommandOutput, DriverError> {
        check_cancelled(is_cancelled)?;
        validate_output_selection(output_directory)?;
        let limits = self.limits();
        let LocalAnalysis {
            build,
            image_name,
            diagnostics,
            analysis,
            analyzed,
            verification,
            warnings_as_errors,
            standard_library_package: _,
            declared_image_entries: _,
        } = self
            .frontend
            .analyze(workspace, options, BuildIntent::Build, events, is_cancelled)?;
        let analysis = analysis.ok_or_else(|| {
            backend_error("ordinary build analysis omitted its sealed frontend facts")
        })?;

        phase_started(events, "semantic-wir-lowering");
        let semantic = CanonicalSemanticLowerer::new()
            .lower(
                wrela_semantic_lower::LowerRequest {
                    input: analyzed,
                    limits: limits.semantic_lower,
                },
                is_cancelled,
            )
            .map_err(map_semantic_lower_error)?;
        check_cancelled(is_cancelled)?;
        phase_finished(events, "semantic-wir-lowering");

        phase_started(events, "flow-wir-lowering");
        let flow = CanonicalFlowLowerer::new()
            .lower(
                wrela_flow_lower::LowerRequest {
                    input: semantic.into_parts().0,
                    limits: limits.flow_lower,
                },
                is_cancelled,
            )
            .map_err(map_flow_lower_error)?;
        let (flow, _flow_report, flow_diagnostics) = flow.into_parts();
        let diagnostics = merge_flow_diagnostics(
            diagnostics,
            flow_diagnostics,
            warnings_as_errors,
            options.maximum_diagnostics,
            events,
            is_cancelled,
        )?;
        check_cancelled(is_cancelled)?;
        phase_finished(events, "flow-wir-lowering");

        phase_started(events, "flow-wir-encoding");
        let cache = LocalArtifactCache::for_output(output_directory).ok();
        let deferred_cache = cache.as_ref().map(DeferredArtifactCache::new);
        let cache_key = flow_wir_cache_key(build.identity()).map_err(|error| {
            backend_error(format!(
                "cannot derive the canonical FlowWir cache key: {error}"
            ))
        })?;
        let encoded = resolve_flow_wir_frame(
            deferred_cache
                .as_ref()
                .map(|cache| cache as &dyn crate::ArtifactCache),
            &cache_key,
            &flow,
            limits.flow_codec,
            limits.cache.entry_bytes,
            is_cancelled,
        )
        .map_err(map_flow_codec_error)?;
        let wir_digest = encoded.digest();
        check_cancelled(is_cancelled)?;
        phase_finished_with_reuse(events, "flow-wir-encoding", encoded.reused());

        phase_started(events, "private-backend");
        let backend = execute_backend(
            BackendProcessRequest {
                build: &build,
                flow_wir: encoded.bytes(),
                flow_wir_digest: wir_digest,
                verification: &verification,
                limits: limits.backend,
            },
            is_cancelled,
        )?;
        check_cancelled(is_cancelled)?;
        phase_finished(events, "private-backend");

        phase_started(events, "backend-report-verification");
        let report = wrela_image_report::decode_image_report_json(
            &backend.report,
            build.identity(),
            limits.backend.analysis_report_facts,
            limits.backend.report_facts,
            limits.backend.maximum_report_bytes,
            is_cancelled,
        )
        .map_err(map_backend_report_error)?;
        if report.image_name() != image_name
            || report.analysis() != analysis.as_facts()
            || report.backend().flow_wir_digest != wir_digest
            || report.backend().artifact_digest != backend.artifact_digest
            || report.backend().artifact_bytes != backend.artifact_bytes
        {
            return Err(backend_error(
                "backend report disagrees with the sealed frontend analysis or artifact",
            ));
        }
        phase_finished(events, "backend-report-verification");

        phase_started(events, "publication");
        let publication = publish_build(
            output_directory,
            &image_name,
            &backend.artifact,
            backend.artifact_digest,
            &backend.report,
            backend.report_digest,
            limits,
            is_cancelled,
        )?;
        let outcome = BuildOutcome::new(
            BuildOutcomeCandidate {
                diagnostics,
                artifact: publication.artifact_path,
                artifact_digest: backend.artifact_digest,
                artifact_bytes: backend.artifact_bytes,
                report_path: publication.report_path,
                report_digest: backend.report_digest,
                report_bytes: backend.report_bytes,
                report,
            },
            &LocalOutcomeHasher,
            is_cancelled,
        )
        .map_err(|error| match error {
            wrela_driver::OutcomeError::Cancelled => DriverError::Cancelled,
            error => publication_error(output_directory, error.to_string()),
        })?;
        events.emit(DriverEvent::ArtifactPublished {
            path: outcome.artifact().to_owned(),
            digest: outcome.artifact_digest(),
        });
        check_cancelled(is_cancelled)?;
        phase_finished(events, "publication");
        if let Some(cache) = &deferred_cache {
            cache.flush_after_publication(is_cancelled);
        }
        Ok(CommandOutput::Build(Box::new(outcome)))
    }
}

impl CompilerDriver for LocalBuildDriver {
    fn execute(
        &self,
        command: &Command,
        events: &dyn EventSink,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<CommandOutput, DriverError> {
        check_cancelled(is_cancelled)?;
        match command {
            Command::Build {
                workspace,
                output_directory,
                diagnostics,
            } => self.build(
                workspace,
                output_directory,
                diagnostics,
                events,
                is_cancelled,
            ),
            _ => Err(DriverError::InvalidCommand(
                "local build driver accepts only a normalized `build` command".to_owned(),
            )),
        }
    }
}

pub fn execute_local_build(command: &Command) -> Result<CommandOutput, DriverError> {
    LocalBuildDriver::discover(PipelineLimits::standard())?.execute(
        command,
        &SilentEvents,
        &never_cancelled,
    )
}

struct SilentEvents;

impl EventSink for SilentEvents {
    fn emit(&self, _event: DriverEvent<'_>) {}
}

const fn never_cancelled() -> bool {
    false
}

pub(super) fn merge_flow_diagnostics(
    diagnostics: DiagnosticReport,
    mut flow: Vec<wrela_diagnostics::Diagnostic>,
    warnings_as_errors: bool,
    maximum_diagnostics: u32,
    events: &dyn EventSink,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<DiagnosticReport, DriverError> {
    if flow
        .iter()
        .any(|diagnostic| diagnostic.severity == Severity::Error)
    {
        return Err(backend_error(
            "FlowWir lowering reported an error diagnostic on success",
        ));
    }
    if warnings_as_errors {
        for diagnostic in &mut flow {
            check_cancelled(is_cancelled)?;
            diagnostic.severity = Severity::Error;
        }
    }
    let (mut all, sources) = diagnostics.into_parts();
    all.try_reserve_exact(flow.len())
        .map_err(|_| DriverError::Input {
            phase: "FlowWir diagnostics",
            message: "cannot allocate diagnostic aggregation".to_owned(),
        })?;
    all.extend(flow);
    let report = if warnings_as_errors && all.iter().any(|item| item.severity == Severity::Error) {
        DiagnosticReport::rejected(all, sources, maximum_diagnostics, is_cancelled)
    } else {
        DiagnosticReport::successful(all, sources, maximum_diagnostics, is_cancelled)
    }
    .map_err(|error| match error {
        wrela_driver::OutcomeError::Cancelled => DriverError::Cancelled,
        error => DriverError::Input {
            phase: "FlowWir diagnostics",
            message: error.to_string(),
        },
    })?;
    if report.error_count() != 0 {
        for diagnostic in report.diagnostics() {
            check_cancelled(is_cancelled)?;
            events.emit(DriverEvent::Diagnostic {
                diagnostic,
                sources: report.sources(),
            });
        }
        return Err(DriverError::Rejected { report });
    }
    Ok(report)
}

pub(super) struct BackendProcessRequest<'a> {
    pub(super) build: &'a wrela_build_model::ValidatedBuildConfiguration,
    pub(super) flow_wir: &'a [u8],
    pub(super) flow_wir_digest: Sha256Digest,
    pub(super) verification: &'a crate::LocalToolchainVerification,
    pub(super) limits: BackendLimits,
}

pub(super) struct BackendProcessOutput {
    pub(super) artifact: Vec<u8>,
    pub(super) artifact_digest: Sha256Digest,
    pub(super) artifact_bytes: u64,
    pub(super) report: Vec<u8>,
    pub(super) report_digest: Sha256Digest,
    pub(super) report_bytes: u64,
}

pub(super) fn execute_backend(
    request: BackendProcessRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<BackendProcessOutput, DriverError> {
    check_cancelled(is_cancelled)?;
    validate_private_backend_limits(request.limits)?;
    if request.build.identity().target != *request.verification.target().identity()
        || request.build.identity().target_package
            != request.verification.target().semantic().content_digest()
        || SoftwareSha256.sha256(request.flow_wir) != request.flow_wir_digest
    {
        return Err(backend_error(
            "backend request does not match the verified build, target, or FlowWir bytes",
        ));
    }

    let installed = request.verification.toolchain();
    let backend = installed
        .backend()
        .map_err(|error| backend_error(format!("verified backend is unavailable: {error}")))?;
    let target_root = installed
        .target(request.verification.target().identity())
        .map_err(|error| backend_error(format!("verified target is unavailable: {error}")))?;
    let runtime_relative = request.verification.target().backend().runtime_object();
    let runtime = installed
        .target_file(request.verification.target().identity(), runtime_relative)
        .map_err(|error| {
            backend_error(format!("verified target runtime is unavailable: {error}"))
        })?;

    let _backend_bytes =
        read_verified_installation_file(&backend, backend.bytes(), true, is_cancelled)?;
    let retained_target_manifest = request.verification.target_manifest_bytes();
    let target_manifest_limit = u64::try_from(retained_target_manifest.len())
        .map_err(|_| backend_error("verified target manifest length does not fit u64"))?;
    let target_toml_bytes = read_stable_file(
        &target_root.path().join("target.toml"),
        target_manifest_limit,
        false,
        is_cancelled,
    )?;
    if target_toml_bytes != retained_target_manifest {
        return Err(backend_error(
            "installed target.toml changed after toolchain verification",
        ));
    }
    let runtime_bytes = read_verified_installation_file(
        &runtime,
        request.limits.link.object_bytes,
        false,
        is_cancelled,
    )?;

    let private = PrivateDirectory::create(is_cancelled)?;
    let target_directory = private.path().join("target");
    create_private_directory(&target_directory).map_err(|error| {
        backend_error(format!("cannot create private target directory: {error}"))
    })?;
    let wir_path = private.path().join("input.flowwir");
    let target_toml_path = target_directory.join("target.toml");
    let runtime_path = target_directory.join(runtime_relative);
    let runtime_parent = runtime_path
        .parent()
        .ok_or_else(|| backend_error("verified runtime path has no target-package parent"))?;
    if runtime_parent != target_directory {
        create_private_directory(runtime_parent).map_err(|error| {
            backend_error(format!("cannot create private runtime directory: {error}"))
        })?;
    }
    write_new_synced_file(&wir_path, request.flow_wir)?;
    write_new_synced_file(&target_toml_path, &target_toml_bytes)?;
    write_new_synced_file(&runtime_path, &runtime_bytes)?;

    let request_id = request_id(request.flow_wir_digest);
    let protocol_request = BackendRequest {
        request_id,
        build: request.build.as_configuration().clone(),
        wir: backend_path("input.flowwir")?,
        wir_digest: request.flow_wir_digest,
        target_runtime_digest: runtime.digest(),
        target_runtime_bytes: runtime.bytes(),
        target_package: backend_path("target")?,
        output: backend_path("output.efi")?,
        report: backend_path("report.json")?,
    };
    let frame = encode_request(&protocol_request, request.build)
        .map_err(|error| backend_error(format!("cannot encode backend request: {error}")))?;
    let process = run_backend_process(backend.path(), private.path(), frame, is_cancelled)?;
    if !process.status.success() {
        let stderr = String::from_utf8_lossy(&process.stderr);
        return Err(backend_error(format!(
            "private backend exited with {}: {}",
            process.status,
            stderr.trim()
        )));
    }
    if !process.stderr.is_empty() {
        return Err(backend_error(
            "private backend wrote unexpected diagnostics on a successful protocol response",
        ));
    }
    let response = decode_response(&process.stdout)
        .map_err(|error| backend_error(format!("cannot decode backend response: {error}")))?;
    let canonical = encode_response(&response)
        .map_err(|error| backend_error(format!("cannot canonicalize backend response: {error}")))?;
    if canonical != process.stdout || response.request_id != request_id {
        return Err(backend_error(
            "private backend returned a noncanonical or mismatched response",
        ));
    }
    let success = match response.outcome {
        BackendOutcome::Success(success) => success,
        BackendOutcome::Failure(failure) => {
            let phase = if failure.kind == BackendFailureKind::Link {
                BackendFailurePhase::Link
            } else {
                BackendFailurePhase::Compile
            };
            return Err(backend_failure(
                phase,
                format!(
                    "private backend {:?} failure: {}",
                    failure.kind, failure.message
                ),
            ));
        }
    };
    if success.artifact.as_str() != "output.efi" || success.report.as_str() != "report.json" {
        return Err(backend_error(
            "private backend returned unexpected publication paths",
        ));
    }

    let artifact = read_private_output(
        &private.path().join(success.artifact.as_str()),
        request.limits.link.image_bytes,
        success.artifact_digest,
        is_cancelled,
    )?;
    let report = read_private_output(
        &private.path().join(success.report.as_str()),
        request.limits.maximum_report_bytes,
        success.report_digest,
        is_cancelled,
    )?;
    let artifact_bytes = u64::try_from(artifact.len())
        .map_err(|_| backend_error("backend artifact length does not fit u64"))?;
    let report_bytes = u64::try_from(report.len())
        .map_err(|_| backend_error("backend report length does not fit u64"))?;
    check_cancelled(is_cancelled)?;
    Ok(BackendProcessOutput {
        artifact,
        artifact_digest: success.artifact_digest,
        artifact_bytes,
        report,
        report_digest: success.report_digest,
        report_bytes,
    })
}

fn validate_private_backend_limits(limits: BackendLimits) -> Result<(), DriverError> {
    limits
        .validate()
        .map_err(|error| backend_error(format!("invalid backend limits: {error}")))?;
    if limits != BackendLimits::standard() {
        return Err(backend_error(
            "private backend protocol cannot carry nonstandard backend limits",
        ));
    }
    Ok(())
}

fn backend_path(value: &str) -> Result<BackendPath, DriverError> {
    BackendPath::new(value).map_err(|error| backend_error(format!("invalid backend path: {error}")))
}

fn request_id(digest: Sha256Digest) -> RequestId {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&digest.as_bytes()[..8]);
    RequestId(u64::from_le_bytes(bytes))
}

struct ProcessOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run_backend_process(
    executable: &Path,
    private_root: &Path,
    frame: Vec<u8>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ProcessOutput, DriverError> {
    check_cancelled(is_cancelled)?;
    let mut child = ProcessCommand::new(executable)
        .arg("--private-root")
        .arg(private_root)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| backend_error(format!("cannot spawn verified backend: {error}")))?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| terminate_child(&mut child, "backend stdin is unavailable"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| terminate_child(&mut child, "backend stdout is unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| terminate_child(&mut child, "backend stderr is unavailable"))?;

    let write_failed = Arc::new(AtomicBool::new(false));
    let writer_failed = Arc::clone(&write_failed);
    let writer = thread::spawn(move || {
        let mut stdin = stdin;
        if stdin
            .write_all(&frame)
            .and_then(|()| stdin.flush())
            .is_err()
        {
            writer_failed.store(true, Ordering::Release);
        }
    });
    let output_overflow = Arc::new(AtomicBool::new(false));
    let stdout_overflow = Arc::clone(&output_overflow);
    let stdout_reader = thread::spawn(move || {
        read_bounded_pipe(
            stdout,
            MAX_PROTOCOL_FRAME_BYTES.saturating_add(17),
            &stdout_overflow,
        )
    });
    let stderr_overflow = Arc::clone(&output_overflow);
    let stderr_reader =
        thread::spawn(move || read_bounded_pipe(stderr, BACKEND_STDERR_BYTES, &stderr_overflow));

    let started = Instant::now();
    let status = loop {
        if is_cancelled() {
            kill_and_wait(&mut child);
            join_process_threads(writer, stdout_reader, stderr_reader);
            return Err(DriverError::Cancelled);
        }
        if output_overflow.load(Ordering::Acquire) {
            kill_and_wait(&mut child);
            join_process_threads(writer, stdout_reader, stderr_reader);
            return Err(backend_error(
                "private backend output exceeded its byte limit",
            ));
        }
        if started.elapsed() > BACKEND_TIMEOUT {
            kill_and_wait(&mut child);
            join_process_threads(writer, stdout_reader, stderr_reader);
            return Err(backend_error(
                "private backend exceeded its execution timeout",
            ));
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => thread::sleep(PROCESS_POLL_INTERVAL),
            Err(error) => {
                kill_and_wait(&mut child);
                join_process_threads(writer, stdout_reader, stderr_reader);
                return Err(backend_error(format!(
                    "cannot observe private backend status: {error}"
                )));
            }
        }
    };
    writer
        .join()
        .map_err(|_| backend_error("backend request writer panicked"))?;
    let stdout = stdout_reader
        .join()
        .map_err(|_| backend_error("backend response reader panicked"))?
        .map_err(|error| backend_error(format!("cannot read backend response: {error}")))?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| backend_error("backend diagnostic reader panicked"))?
        .map_err(|error| backend_error(format!("cannot read backend diagnostics: {error}")))?;
    if write_failed.load(Ordering::Acquire) {
        return Err(backend_error("cannot write the complete backend request"));
    }
    if output_overflow.load(Ordering::Acquire) {
        return Err(backend_error(
            "private backend output exceeded its byte limit",
        ));
    }
    Ok(ProcessOutput {
        status,
        stdout,
        stderr,
    })
}

fn read_bounded_pipe(
    mut pipe: impl Read,
    maximum_bytes: usize,
    overflow: &AtomicBool,
) -> io::Result<Vec<u8>> {
    let mut retained = Vec::new();
    retained
        .try_reserve_exact(maximum_bytes.min(64 * 1024))
        .map_err(|_| io::Error::new(io::ErrorKind::OutOfMemory, "cannot reserve process output"))?;
    let mut total = 0usize;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = match pipe.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        total = total.checked_add(read).ok_or_else(|| {
            overflow.store(true, Ordering::Release);
            io::Error::new(io::ErrorKind::InvalidData, "process output length overflow")
        })?;
        let retain = maximum_bytes.saturating_sub(retained.len()).min(read);
        if retain != 0 {
            retained.try_reserve_exact(retain).map_err(|_| {
                io::Error::new(io::ErrorKind::OutOfMemory, "cannot reserve process output")
            })?;
            retained.extend_from_slice(&buffer[..retain]);
        }
        if total > maximum_bytes {
            overflow.store(true, Ordering::Release);
        }
    }
    Ok(retained)
}

fn terminate_child(child: &mut Child, message: &'static str) -> DriverError {
    kill_and_wait(child);
    backend_error(message)
}

fn kill_and_wait(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn join_process_threads(
    writer: thread::JoinHandle<()>,
    stdout: thread::JoinHandle<io::Result<Vec<u8>>>,
    stderr: thread::JoinHandle<io::Result<Vec<u8>>>,
) {
    let _ = writer.join();
    let _ = stdout.join();
    let _ = stderr.join();
}

struct PrivateDirectory {
    path: PathBuf,
}

impl PrivateDirectory {
    fn create(is_cancelled: &dyn Fn() -> bool) -> Result<Self, DriverError> {
        check_cancelled(is_cancelled)?;
        let base = fs::canonicalize(std::env::temp_dir()).map_err(|error| {
            backend_error(format!("cannot resolve the temporary directory: {error}"))
        })?;
        validate_directory(&base, false)
            .map_err(|message| backend_error(format!("invalid temporary directory: {message}")))?;
        for _ in 0..TEMPORARY_DIRECTORY_ATTEMPTS {
            check_cancelled(is_cancelled)?;
            let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = base.join(format!(
                "wrela-build-{}-{sequence:016x}",
                std::process::id()
            ));
            match create_private_directory(&path) {
                Ok(()) => {
                    let canonical = fs::canonicalize(&path).map_err(|error| {
                        backend_error(format!("cannot seal private build directory: {error}"))
                    })?;
                    if canonical != path {
                        let _ = fs::remove_dir_all(&path);
                        return Err(backend_error(
                            "private build directory canonicalized to a different path",
                        ));
                    }
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(backend_error(format!(
                        "cannot create private build directory: {error}"
                    )));
                }
            }
        }
        Err(backend_error(
            "cannot allocate a unique private build directory",
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn create_private_directory(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)
}

fn write_new_synced_file(path: &Path, bytes: &[u8]) -> Result<(), DriverError> {
    let parent = path
        .parent()
        .ok_or_else(|| backend_error("private file has no parent directory"))?;
    validate_directory(parent, true)
        .map_err(|message| backend_error(format!("invalid private file parent: {message}")))?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| backend_error(format!("cannot create private input: {error}")))?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(path);
        return Err(backend_error(format!(
            "cannot materialize private input: {error}"
        )));
    }
    Ok(())
}

fn read_verified_installation_file(
    evidence: &VerifiedPath,
    maximum_bytes: u64,
    require_executable: bool,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>, DriverError> {
    if evidence.bytes() == 0 || evidence.bytes() > maximum_bytes {
        return Err(backend_error(
            "verified installation file has an invalid byte measurement",
        ));
    }
    let bytes = read_stable_file(
        evidence.path(),
        maximum_bytes,
        require_executable,
        is_cancelled,
    )?;
    if u64::try_from(bytes.len()).ok() != Some(evidence.bytes())
        || SoftwareSha256.sha256(&bytes) != evidence.digest()
    {
        return Err(backend_error(format!(
            "verified installation file changed: {}",
            evidence.path().display()
        )));
    }
    Ok(bytes)
}

pub(super) fn read_private_output(
    path: &Path,
    maximum_bytes: u64,
    expected_digest: Sha256Digest,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>, DriverError> {
    let bytes = read_stable_file(path, maximum_bytes, false, is_cancelled)?;
    if bytes.is_empty() || SoftwareSha256.sha256(&bytes) != expected_digest {
        return Err(backend_error(format!(
            "private backend output changed or has the wrong digest: {}",
            path.display()
        )));
    }
    Ok(bytes)
}

fn read_stable_file(
    path: &Path,
    maximum_bytes: u64,
    require_executable: bool,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>, DriverError> {
    check_cancelled(is_cancelled)?;
    if maximum_bytes == 0 || !normal_absolute_path(path) {
        return Err(backend_error(format!(
            "invalid bounded file path: {}",
            path.display()
        )));
    }
    let canonical = fs::canonicalize(path)
        .map_err(|error| backend_error(format!("cannot resolve {}: {error}", path.display())))?;
    if canonical != path {
        return Err(backend_error(format!(
            "file path is not canonical: {}",
            path.display()
        )));
    }
    let before = fs::symlink_metadata(path)
        .map_err(|error| backend_error(format!("cannot inspect {}: {error}", path.display())))?;
    validate_regular_file(&before, require_executable)
        .map_err(|message| backend_error(format!("invalid file {}: {message}", path.display())))?;
    let identity = file_identity(&before);
    if identity.bytes == 0 || identity.bytes > maximum_bytes {
        return Err(backend_error(format!(
            "file exceeds its byte limit: {}",
            path.display()
        )));
    }
    let mut file = File::open(path)
        .map_err(|error| backend_error(format!("cannot open {}: {error}", path.display())))?;
    let opened = file
        .metadata()
        .map_err(|error| backend_error(format!("cannot inspect {}: {error}", path.display())))?;
    validate_regular_file(&opened, require_executable)
        .map_err(|message| backend_error(format!("invalid file {}: {message}", path.display())))?;
    if file_identity(&opened) != identity {
        return Err(backend_error(format!(
            "file changed while it was opened: {}",
            path.display()
        )));
    }
    let length = usize::try_from(identity.bytes)
        .map_err(|_| backend_error("bounded file length does not fit the host"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| backend_error("cannot allocate bounded file input"))?;
    let mut buffer = [0u8; 64 * 1024];
    while bytes.len() < length {
        check_cancelled(is_cancelled)?;
        let wanted = (length - bytes.len()).min(buffer.len());
        let read = file
            .read(&mut buffer[..wanted])
            .map_err(|error| backend_error(format!("cannot read {}: {error}", path.display())))?;
        if read == 0 {
            return Err(backend_error(format!(
                "file was truncated while reading: {}",
                path.display()
            )));
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    let mut trailing = [0u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|error| backend_error(format!("cannot finish {}: {error}", path.display())))?
        != 0
    {
        return Err(backend_error(format!(
            "file grew while reading: {}",
            path.display()
        )));
    }
    let opened_after = file
        .metadata()
        .map_err(|error| backend_error(format!("cannot recheck {}: {error}", path.display())))?;
    let current = fs::symlink_metadata(path)
        .map_err(|error| backend_error(format!("cannot recheck {}: {error}", path.display())))?;
    validate_regular_file(&opened_after, require_executable)
        .and_then(|()| validate_regular_file(&current, require_executable))
        .map_err(|message| backend_error(format!("invalid file {}: {message}", path.display())))?;
    if file_identity(&opened_after) != identity || file_identity(&current) != identity {
        return Err(backend_error(format!(
            "file changed during measurement: {}",
            path.display()
        )));
    }
    check_cancelled(is_cancelled)?;
    Ok(bytes)
}

fn validate_regular_file(
    metadata: &Metadata,
    require_executable: bool,
) -> Result<(), &'static str> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("not a regular non-symlink file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 || metadata.mode() & 0o022 != 0 {
            return Err("file is linked or group/other writable");
        }
        if require_executable && metadata.mode() & 0o111 == 0 {
            return Err("file is not executable");
        }
    }
    let _ = require_executable;
    Ok(())
}

fn validate_directory(path: &Path, require_private: bool) -> Result<(), &'static str> {
    let canonical = fs::canonicalize(path).map_err(|_| "directory cannot be canonicalized")?;
    let metadata = fs::symlink_metadata(path).map_err(|_| "directory cannot be inspected")?;
    if canonical != path || metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err("directory is not canonical, real, and a directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let forbidden = if require_private { 0o077 } else { 0o022 };
        if metadata.mode() & forbidden != 0 {
            return Err("directory permissions violate the requested policy");
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    bytes: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    links: u64,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(windows)]
    attributes: u32,
    #[cfg(windows)]
    creation_time: u64,
    #[cfg(windows)]
    modified_time: u64,
}

#[cfg(unix)]
fn file_identity(metadata: &Metadata) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;
    FileIdentity {
        bytes: metadata.len(),
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode(),
        links: metadata.nlink(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
    }
}

#[cfg(windows)]
fn file_identity(metadata: &Metadata) -> FileIdentity {
    use std::os::windows::fs::MetadataExt;
    FileIdentity {
        bytes: metadata.len(),
        attributes: metadata.file_attributes(),
        creation_time: metadata.creation_time(),
        modified_time: metadata.last_write_time(),
    }
}

#[cfg(not(any(unix, windows)))]
fn file_identity(metadata: &Metadata) -> FileIdentity {
    FileIdentity {
        bytes: metadata.len(),
    }
}

pub(super) struct BuildPublication {
    pub(super) artifact_path: PathBuf,
    pub(super) report_path: PathBuf,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn publish_build(
    output_directory: &Path,
    image_name: &str,
    artifact: &[u8],
    artifact_digest: Sha256Digest,
    report: &[u8],
    report_digest: Sha256Digest,
    limits: PipelineLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<BuildPublication, DriverError> {
    check_cancelled(is_cancelled)?;
    let mut image_components = Path::new(image_name).components();
    if !matches!(image_components.next(), Some(Component::Normal(_)))
        || image_components.next().is_some()
        || image_name.len() > 4096
        || image_name.trim() != image_name
        || artifact.is_empty()
        || u64::try_from(artifact.len())
            .ok()
            .is_none_or(|bytes| bytes > limits.backend.link.image_bytes)
        || report.is_empty()
        || u64::try_from(report.len())
            .ok()
            .is_none_or(|bytes| bytes > limits.backend.maximum_report_bytes)
        || SoftwareSha256.sha256(artifact) != artifact_digest
        || SoftwareSha256.sha256(report) != report_digest
    {
        return Err(publication_error(
            output_directory,
            "backend publication bytes violate their sealed limits or digests",
        ));
    }
    prepare_output_directory(output_directory)?;
    let artifact_path = output_directory.join(format!("{image_name}.efi"));
    let report_path = output_directory.join(format!("{image_name}.image-report.json"));
    for path in [&artifact_path, &report_path] {
        if path.as_os_str().as_encoded_bytes().len() > MAX_OUTPUT_PATH_BYTES
            || !normal_absolute_path(path)
        {
            return Err(publication_error(
                path,
                "publication path is not bounded and normalized",
            ));
        }
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(publication_error(
                    path,
                    "destination already exists; builds use create-new publication",
                ));
            }
            Err(error) => return Err(publication_error(path, error.to_string())),
        }
    }

    let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let stem = format!(".wrela-publish-{}-{sequence:016x}", std::process::id());
    let staged_artifact = output_directory.join(format!("{stem}.efi"));
    let staged_report = output_directory.join(format!("{stem}.json"));
    write_new_publication_file(&staged_artifact, artifact)?;
    if let Err(error) = write_new_publication_file(&staged_report, report) {
        let _ = fs::remove_file(&staged_artifact);
        return Err(error);
    }
    let published = (|| {
        check_cancelled(is_cancelled)?;
        fs::hard_link(&staged_artifact, &artifact_path)
            .map_err(|error| publication_error(&artifact_path, error.to_string()))?;
        if let Err(error) = fs::hard_link(&staged_report, &report_path) {
            let _ = fs::remove_file(&artifact_path);
            return Err(publication_error(&report_path, error.to_string()));
        }
        fs::remove_file(&staged_artifact)
            .map_err(|error| publication_error(&staged_artifact, error.to_string()))?;
        fs::remove_file(&staged_report)
            .map_err(|error| publication_error(&staged_report, error.to_string()))?;
        sync_directory(output_directory)?;
        let observed_artifact = read_private_output(
            &artifact_path,
            limits.backend.link.image_bytes,
            artifact_digest,
            is_cancelled,
        )?;
        let observed_report = read_private_output(
            &report_path,
            limits.backend.maximum_report_bytes,
            report_digest,
            is_cancelled,
        )?;
        if observed_artifact != artifact || observed_report != report {
            return Err(publication_error(
                output_directory,
                "published bytes differ from their sealed private inputs",
            ));
        }
        check_cancelled(is_cancelled)?;
        Ok(BuildPublication {
            artifact_path: artifact_path.clone(),
            report_path: report_path.clone(),
        })
    })();
    if published.is_err() {
        let _ = fs::remove_file(&staged_artifact);
        let _ = fs::remove_file(&staged_report);
        let _ = fs::remove_file(&artifact_path);
        let _ = fs::remove_file(&report_path);
        let _ = sync_directory(output_directory);
    }
    published
}

pub(super) fn validate_output_selection(output_directory: &Path) -> Result<(), DriverError> {
    if !normal_absolute_path(output_directory)
        || output_directory.as_os_str().as_encoded_bytes().len() > MAX_OUTPUT_PATH_BYTES
    {
        return Err(DriverError::InvalidCommand(
            "build output directory must be a bounded normalized absolute path".to_owned(),
        ));
    }
    Ok(())
}

pub(super) fn prepare_output_directory(output_directory: &Path) -> Result<(), DriverError> {
    fs::create_dir_all(output_directory)
        .map_err(|error| publication_error(output_directory, error.to_string()))?;
    validate_directory(output_directory, false)
        .map_err(|message| publication_error(output_directory, message))
}

pub(super) fn write_new_publication_file(path: &Path, bytes: &[u8]) -> Result<(), DriverError> {
    let parent = path
        .parent()
        .ok_or_else(|| publication_error(path, "publication file has no parent"))?;
    validate_directory(parent, false).map_err(|message| publication_error(parent, message))?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| publication_error(path, error.to_string()))?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(path);
        return Err(publication_error(path, error.to_string()));
    }
    Ok(())
}

pub(super) fn sync_directory(path: &Path) -> Result<(), DriverError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| publication_error(path, error.to_string()))
}

pub(super) fn normal_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path.components().count() > 1
        && PathBuf::from_iter(path.components()) == path
        && !path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
}

pub(super) struct LocalOutcomeHasher;

impl OutcomeContentHasher for LocalOutcomeHasher {
    fn sha256(&self, bytes: &[u8], is_cancelled: &dyn Fn() -> bool) -> Option<Sha256Digest> {
        sha256_cancellable(&SoftwareSha256, bytes, is_cancelled).ok()
    }
}

fn map_semantic_lower_error(error: wrela_semantic_lower::LowerError) -> DriverError {
    match error {
        wrela_semantic_lower::LowerError::Cancelled => DriverError::Cancelled,
        error => DriverError::Input {
            phase: "SemanticWir lowering",
            message: error.to_string(),
        },
    }
}

fn map_flow_lower_error(error: wrela_flow_lower::LowerError) -> DriverError {
    match error {
        wrela_flow_lower::LowerError::Cancelled => DriverError::Cancelled,
        error => DriverError::Input {
            phase: "FlowWir lowering",
            message: error.to_string(),
        },
    }
}

pub(super) fn map_flow_codec_error(error: wrela_flow_wir_codec::CodecError) -> DriverError {
    match error {
        wrela_flow_wir_codec::CodecError::Cancelled => DriverError::Cancelled,
        error => DriverError::Input {
            phase: "FlowWir encoding",
            message: error.to_string(),
        },
    }
}

fn map_backend_report_error(error: wrela_image_report::ReportError) -> DriverError {
    match error {
        wrela_image_report::ReportError::Cancelled => DriverError::Cancelled,
        error => backend_error(format!("backend report verification failed: {error}")),
    }
}

fn check_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), DriverError> {
    if is_cancelled() {
        Err(DriverError::Cancelled)
    } else {
        Ok(())
    }
}

fn phase_started(events: &dyn EventSink, phase: &'static str) {
    events.emit(DriverEvent::PhaseStarted { phase });
}

fn phase_finished(events: &dyn EventSink, phase: &'static str) {
    phase_finished_with_reuse(events, phase, false);
}

fn phase_finished_with_reuse(events: &dyn EventSink, phase: &'static str, reused: bool) {
    events.emit(DriverEvent::PhaseFinished { phase, reused });
}

fn backend_error(message: impl Into<String>) -> DriverError {
    backend_failure(BackendFailurePhase::Compile, message)
}

fn backend_failure(phase: BackendFailurePhase, message: impl Into<String>) -> DriverError {
    DriverError::Backend {
        phase,
        message: message.into(),
    }
}

fn publication_error(path: &Path, message: impl Into<String>) -> DriverError {
    DriverError::Publication {
        path: path.to_owned(),
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use wrela_backend::{BackendResponse, BackendSuccess};

    use super::*;

    fn digest(bytes: &[u8]) -> Sha256Digest {
        SoftwareSha256.sha256(bytes)
    }

    #[test]
    fn private_backend_rejects_limits_its_protocol_cannot_carry() {
        validate_private_backend_limits(BackendLimits::standard()).expect("standard policy");

        let mut limits = BackendLimits::standard();
        limits.maximum_report_bytes -= 1;
        assert!(matches!(
            validate_private_backend_limits(limits),
            Err(DriverError::Backend {
                phase: BackendFailurePhase::Compile,
                message,
            }) if message == "private backend protocol cannot carry nonstandard backend limits"
        ));
    }

    #[test]
    fn flow_codec_errors_preserve_driver_error_categories() {
        assert!(matches!(
            map_flow_codec_error(wrela_flow_wir_codec::CodecError::Cancelled),
            DriverError::Cancelled
        ));
        assert!(matches!(
            map_flow_codec_error(wrela_flow_wir_codec::CodecError::InvalidLimits),
            DriverError::Input {
                phase: "FlowWir encoding",
                ..
            }
        ));
        assert!(matches!(
            map_backend_report_error(wrela_image_report::ReportError::Cancelled),
            DriverError::Cancelled
        ));
    }

    #[test]
    fn deferred_cache_stays_invisible_until_publication_flush() {
        let private = PrivateDirectory::create(&never_cancelled).expect("private fixture");
        let identity = digest(b"build identity");
        let key = crate::CacheKey::new(
            crate::CachedArtifactKind::FlowWirFrame,
            wrela_build_model::BuildIdentity {
                compiler: identity,
                language: wrela_build_model::LanguageRevision::Design0_1,
                target: wrela_build_model::TargetIdentity::aarch64_qemu_virt_uefi(),
                target_package: identity,
                standard_library: identity,
                source_graph: identity,
                request: identity,
                profile: identity,
            },
            digest(b"cache subject"),
        )
        .expect("cache key");
        let request = CacheReadRequest {
            key: &key,
            maximum_bytes: 64,
        };
        let bytes = b"deferred producer bytes".to_vec();
        let artifact = crate::seal_cached_artifact(
            &request,
            CacheEntryCandidate {
                key: key.clone(),
                digest: digest(&bytes),
                bytes,
            },
            &SoftwareSha256,
            &never_cancelled,
        )
        .expect("sealed cache artifact");

        let cache = LocalArtifactCache::at(private.path().join("cache")).expect("cache");
        let deferred = DeferredArtifactCache::new(&cache);
        deferred
            .store(&artifact, &never_cancelled)
            .expect("defer cache store");
        assert!(!cache.root().exists());
        assert!(
            deferred
                .load(&request, &never_cancelled)
                .expect("pre-publication cache load")
                .is_none()
        );
        deferred.flush_after_publication(&never_cancelled);
        let loaded = cache
            .load(&request, &never_cancelled)
            .expect("post-publication cache load")
            .expect("published cache entry");
        assert_eq!(loaded.bytes, artifact.bytes());

        let cancelled_cache =
            LocalArtifactCache::at(private.path().join("cancelled-cache")).expect("cache");
        let cancelled = DeferredArtifactCache::new(&cancelled_cache);
        cancelled
            .store(&artifact, &never_cancelled)
            .expect("defer cancelled cache store");
        cancelled.flush_after_publication(&|| true);
        assert!(!cancelled_cache.root().exists());
    }

    #[test]
    fn publication_is_create_new_atomic_and_digest_bound() {
        let private = PrivateDirectory::create(&never_cancelled).expect("private fixture");
        let output = private.path().join("out");
        let artifact = b"MZ\0\0sealed artifact";
        let report = b"{\"sealed\":true}";
        let publication = publish_build(
            &output,
            "demo",
            artifact,
            digest(artifact),
            report,
            digest(report),
            PipelineLimits::standard(),
            &never_cancelled,
        )
        .expect("publish build pair");
        assert_eq!(
            fs::read(&publication.artifact_path).expect("artifact bytes"),
            artifact
        );
        assert_eq!(
            fs::read(&publication.report_path).expect("report bytes"),
            report
        );
        assert!(
            publish_build(
                &output,
                "demo",
                artifact,
                digest(artifact),
                report,
                digest(report),
                PipelineLimits::standard(),
                &never_cancelled,
            )
            .is_err()
        );
        assert!(
            publish_build(
                &output,
                "../escape",
                artifact,
                digest(artifact),
                report,
                digest(report),
                PipelineLimits::standard(),
                &never_cancelled,
            )
            .is_err()
        );
        assert!(!private.path().join("escape.efi").exists());
    }

    #[cfg(unix)]
    #[test]
    fn stable_reads_reject_symlinks_hardlinks_and_writable_inputs() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let private = PrivateDirectory::create(&never_cancelled).expect("private fixture");
        let original = private.path().join("input");
        write_new_synced_file(&original, b"sealed").expect("input");
        let alias = private.path().join("alias");
        symlink(&original, &alias).expect("symlink");
        assert!(read_stable_file(&alias, 64, false, &never_cancelled).is_err());
        fs::remove_file(&alias).expect("remove symlink");

        fs::hard_link(&original, &alias).expect("hard link");
        assert!(read_stable_file(&original, 64, false, &never_cancelled).is_err());
        fs::remove_file(&alias).expect("remove hard link");

        fs::set_permissions(&original, fs::Permissions::from_mode(0o620))
            .expect("make group writable");
        assert!(read_stable_file(&original, 64, false, &never_cancelled).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn process_runner_transfers_binary_protocol_without_shell_environment() {
        use std::os::unix::fs::PermissionsExt;

        let private = PrivateDirectory::create(&never_cancelled).expect("private fixture");
        let artifact = b"MZ fake image";
        let report = b"{}";
        let response = encode_response(&BackendResponse {
            request_id: RequestId(7),
            outcome: BackendOutcome::Success(BackendSuccess {
                artifact: backend_path("output.efi").expect("artifact path"),
                artifact_digest: digest(artifact),
                report: backend_path("report.json").expect("report path"),
                report_digest: digest(report),
            }),
        })
        .expect("response frame");
        let script = private.path().join("fake-backend");
        let source = format!(
            "#!/bin/sh\nIFS= read -r ignored\nroot=$2\nprintf '{}' > \"$root/output.efi\"\nprintf '{}' > \"$root/report.json\"\nprintf '{}'\n",
            shell_octal(artifact),
            shell_octal(report),
            shell_octal(&response),
        );
        write_new_synced_file(&script, source.as_bytes()).expect("script");
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).expect("executable");
        let output = run_backend_process(
            &script,
            private.path(),
            b"request\n".to_vec(),
            &never_cancelled,
        )
        .expect("run fake backend");
        assert!(output.status.success());
        assert_eq!(output.stdout, response);
        assert!(output.stderr.is_empty());
        assert_eq!(
            fs::read(private.path().join("output.efi")).expect("artifact"),
            artifact
        );
        assert_eq!(
            fs::read(private.path().join("report.json")).expect("report"),
            report
        );
    }

    fn shell_octal(bytes: &[u8]) -> String {
        let mut escaped = String::new();
        for byte in bytes {
            write!(escaped, "\\{byte:03o}").expect("writing to String");
        }
        escaped
    }
}
