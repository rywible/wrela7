//! Exact-current headless `check` execution over the private engine protocol.
//!
//! The launcher-provided tree is never used in place. Validated stream actions
//! are materialized below one caller-supplied, engine-owned private directory,
//! re-opened and remeasured, and made read-only before the local frontend is
//! given any path. The staging directory is a capability: callers must keep it
//! private to the engine for the executor's lifetime. This is the explicit
//! trust boundary that makes the pathname-based local frontend safe from
//! hostile ancestor replacement without ambient current-directory or temp-dir
//! discovery.

use std::cell::{Cell, RefCell};
use std::cmp::Ordering;
use std::convert::Infallible;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering as AtomicOrdering};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

use wrela_build_model::{Sha256Digest, TargetIdentity};
use wrela_diagnostics::{Diagnostic, Severity};
use wrela_driver::engine::{
    AcceptedRequestFrame, CheckReportIdentityBuilder, CheckRequest, CheckRequestStream,
    ClientHello, DiagnosticSeverity, EngineEvent, EngineProtocolError, EngineProtocolLimits,
    EngineResourceUsage, EngineResponseMessageRef, EngineTerminal, LateCancelStream,
    RequestStreamProgress, ServerHello, TerminalStatus, TreeMeasurement, TreeMode, TreeRecord,
    ValidatedRequestAction, empty_tree_measurement, encode_response_frame, measure_tree,
    nonce_proof,
};
use wrela_driver::{
    Command, CommandOutput, CompilerDriver, DiagnosticOptions, DiagnosticReport, DriverError,
    DriverEvent, EventSink, WorkspaceSelection,
};
use wrela_package_loader::{
    CanonicalPackageCodec, ContentHasher, ManifestCodecLimits, PackageCodec, SoftwareSha256,
};
use wrela_source::SourceDatabase;
use wrela_toolchain::{LinuxPayloadAuthority, Toolchain};

use crate::{LocalCheckDriver, PipelineLimits};

const IO_CHUNK_BYTES: usize = 64 * 1024;
const CANCELLATION_CHUNK_BYTES: usize = 1024;

/// Failure before a canonical engine response can be produced.
#[derive(Debug)]
pub enum HeadlessCheckError {
    Protocol(EngineProtocolError),
    InvalidStagingRoot(&'static str),
    Materialization(&'static str),
    Io(std::io::Error),
    NotReady,
    AlreadyExecuted,
}

impl fmt::Display for HeadlessCheckError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => error.fmt(formatter),
            Self::InvalidStagingRoot(detail) => {
                write!(formatter, "invalid private engine staging root: {detail}")
            }
            Self::Materialization(detail) => {
                write!(formatter, "engine input materialization failed: {detail}")
            }
            Self::Io(error) => write!(formatter, "engine staging I/O failed: {error}"),
            Self::NotReady => {
                formatter.write_str("headless check input is not complete and sealed")
            }
            Self::AlreadyExecuted => {
                formatter.write_str("headless check request was already executed")
            }
        }
    }
}

impl std::error::Error for HeadlessCheckError {}

impl From<EngineProtocolError> for HeadlessCheckError {
    fn from(value: EngineProtocolError) -> Self {
        Self::Protocol(value)
    }
}

impl From<std::io::Error> for HeadlessCheckError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

/// Failure while encoding or delivering a bounded response frame stream.
#[derive(Debug)]
pub enum HeadlessCheckFrameStreamError<E> {
    Protocol(EngineProtocolError),
    Sink(E),
}

impl<E: fmt::Display> fmt::Display for HeadlessCheckFrameStreamError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => write!(formatter, "cannot encode headless response: {error}"),
            Self::Sink(error) => {
                write!(formatter, "cannot deliver headless response frame: {error}")
            }
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for HeadlessCheckFrameStreamError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Sink(error) => Some(error),
        }
    }
}

/// Canonical response components for one completed headless check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadlessCheckResponse {
    request_identity: Sha256Digest,
    hello: ServerHello,
    events: Vec<EngineEvent>,
    output: TreeMeasurement,
    terminal: EngineTerminal,
}

impl HeadlessCheckResponse {
    #[must_use]
    pub fn events(&self) -> &[EngineEvent] {
        &self.events
    }

    #[must_use]
    pub const fn terminal(&self) -> &EngineTerminal {
        &self.terminal
    }

    fn frame_count(&self) -> Result<usize, EngineProtocolError> {
        self.events
            .len()
            .checked_add(4)
            .ok_or(EngineProtocolError::ResourceLimit {
                resource: "response frames",
                limit: u64::MAX,
            })
    }

    /// Encode and deliver one bounded frame at a time in canonical stream
    /// order. The frame allocation is dropped before the next frame is
    /// encoded unless the sink explicitly retains it.
    pub fn stream_encoded_frames<E>(
        &self,
        limits: EngineProtocolLimits,
        is_cancelled: &dyn Fn() -> bool,
        mut sink: impl FnMut(Vec<u8>) -> Result<(), E>,
    ) -> Result<(), HeadlessCheckFrameStreamError<E>> {
        limits
            .validate()
            .map_err(HeadlessCheckFrameStreamError::Protocol)?;
        let count = self
            .frame_count()
            .map_err(HeadlessCheckFrameStreamError::Protocol)?;
        let count = u64::try_from(count).map_err(|_| {
            HeadlessCheckFrameStreamError::Protocol(EngineProtocolError::ResourceLimit {
                resource: "response frames",
                limit: limits.frames,
            })
        })?;
        if count > limits.frames {
            return Err(HeadlessCheckFrameStreamError::Protocol(
                EngineProtocolError::ResourceLimit {
                    resource: "response frames",
                    limit: limits.frames,
                },
            ));
        }
        let mut sequence = 0u64;
        stream_response_frame(
            &mut sequence,
            self.request_identity,
            EngineResponseMessageRef::ServerHello(&self.hello),
            limits,
            is_cancelled,
            &mut sink,
        )?;
        for event in &self.events {
            stream_response_frame(
                &mut sequence,
                self.request_identity,
                EngineResponseMessageRef::Event(event),
                limits,
                is_cancelled,
                &mut sink,
            )?;
        }
        for message in [
            EngineResponseMessageRef::OutputHeader(self.output),
            EngineResponseMessageRef::OutputFinish(self.output),
            EngineResponseMessageRef::Terminal(&self.terminal),
        ] {
            stream_response_frame(
                &mut sequence,
                self.request_identity,
                message,
                limits,
                is_cancelled,
                &mut sink,
            )?;
        }
        debug_assert_eq!(sequence, count);
        Ok(())
    }

    /// Convenience aggregation layered over [`Self::stream_encoded_frames`].
    pub fn encode_frames(
        &self,
        limits: EngineProtocolLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<Vec<u8>>, EngineProtocolError> {
        let count = self.frame_count()?;
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(count)
            .map_err(|_| EngineProtocolError::ResourceLimit {
                resource: "response frames",
                limit: limits.frames,
            })?;
        match self.stream_encoded_frames(limits, is_cancelled, |frame| {
            frames.push(frame);
            Ok::<(), Infallible>(())
        }) {
            Ok(()) => Ok(frames),
            Err(HeadlessCheckFrameStreamError::Protocol(error)) => Err(error),
            Err(HeadlessCheckFrameStreamError::Sink(error)) => match error {},
        }
    }
}

fn stream_response_frame<E>(
    sequence: &mut u64,
    request_identity: Sha256Digest,
    message: EngineResponseMessageRef<'_>,
    limits: EngineProtocolLimits,
    is_cancelled: &dyn Fn() -> bool,
    sink: &mut impl FnMut(Vec<u8>) -> Result<(), E>,
) -> Result<(), HeadlessCheckFrameStreamError<E>> {
    let frame = encode_response_frame(*sequence, request_identity, message, limits, is_cancelled)
        .map_err(HeadlessCheckFrameStreamError::Protocol)?;
    sink(frame).map_err(HeadlessCheckFrameStreamError::Sink)?;
    *sequence = sequence.checked_add(1).ok_or_else(|| {
        HeadlessCheckFrameStreamError::Protocol(EngineProtocolError::ResourceLimit {
            resource: "response frames",
            limit: limits.frames,
        })
    })?;
    Ok(())
}

/// Stateful, single-request exact-v1 headless check executor.
pub struct HeadlessCheckExecutor {
    stream: CheckRequestStream,
    staging_parent: PathBuf,
    toolchain: Toolchain,
    pipeline_limits: PipelineLimits,
    protocol_limits: EngineProtocolLimits,
    linux_payload_authority: Option<LinuxPayloadAuthority>,
    stage: Option<Stage>,
    sealed: Option<SealedInput>,
    executed: bool,
    poisoned: bool,
}

/// Single-use execution half of a sealed request. It shares no mutable
/// protocol parser with the late-control half.
pub struct HeadlessCheckExecution {
    executor: HeadlessCheckExecutor,
    completion: Arc<ExecutionCompletion>,
}

impl HeadlessCheckExecution {
    pub fn execute(
        mut self,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<HeadlessCheckResponse, HeadlessCheckError> {
        let completion = &self.completion;
        let combined = || completion.is_cancel_requested() || is_cancelled();
        self.executor
            .execute_with_completion(&combined, &|status| completion.complete(status))
    }
}

const EXECUTION_RUNNING: u8 = 0;
const EXECUTION_CANCEL_REQUESTED: u8 = 1;
const EXECUTION_COMPLETED: u8 = 2;
const EXECUTION_COMPLETED_CANCELLED: u8 = 3;

struct ExecutionCompletion {
    state: AtomicU8,
}

impl ExecutionCompletion {
    const fn new() -> Self {
        Self {
            state: AtomicU8::new(EXECUTION_RUNNING),
        }
    }

    fn is_cancel_requested(&self) -> bool {
        matches!(
            self.state.load(AtomicOrdering::Acquire),
            EXECUTION_CANCEL_REQUESTED | EXECUTION_COMPLETED_CANCELLED
        )
    }

    fn request_cancel(&self) -> LateCancelDisposition {
        self.request_cancel_after(&|| {})
    }

    fn request_cancel_after(&self, before_linearization: &dyn Fn()) -> LateCancelDisposition {
        before_linearization();
        match self.state.compare_exchange(
            EXECUTION_RUNNING,
            EXECUTION_CANCEL_REQUESTED,
            AtomicOrdering::AcqRel,
            AtomicOrdering::Acquire,
        ) {
            Ok(_) | Err(EXECUTION_CANCEL_REQUESTED) => LateCancelDisposition::Requested,
            Err(EXECUTION_COMPLETED | EXECUTION_COMPLETED_CANCELLED) => {
                LateCancelDisposition::ExecutionCompleted
            }
            Err(_) => unreachable!("execution completion state is closed"),
        }
    }

    fn complete(&self, status: TerminalStatus) -> TerminalStatus {
        self.complete_after(status, &|| {})
    }

    fn complete_after(
        &self,
        status: TerminalStatus,
        before_linearization: &dyn Fn(),
    ) -> TerminalStatus {
        before_linearization();
        match self.state.compare_exchange(
            EXECUTION_RUNNING,
            EXECUTION_COMPLETED,
            AtomicOrdering::AcqRel,
            AtomicOrdering::Acquire,
        ) {
            Ok(_) => status,
            Err(EXECUTION_CANCEL_REQUESTED) => {
                self.state
                    .store(EXECUTION_COMPLETED_CANCELLED, AtomicOrdering::Release);
                TerminalStatus::Cancelled
            }
            Err(EXECUTION_COMPLETED) => status,
            Err(EXECUTION_COMPLETED_CANCELLED) => TerminalStatus::Cancelled,
            Err(_) => unreachable!("execution completion state is closed"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LateCancelDisposition {
    Requested,
    ExecutionCompleted,
}

/// Scalar-only late request control. A valid exact-next `Cancel` sets the
/// execution half's shared cancellation flag; every other frame fails closed.
pub struct LateRequestControl {
    stream: LateCancelStream,
    completion: Arc<ExecutionCompletion>,
}

impl LateRequestControl {
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.completion.is_cancel_requested()
    }

    pub fn accept_cancel_frame(
        &mut self,
        encoded: &[u8],
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<LateCancelDisposition, EngineProtocolError> {
        self.stream.accept(encoded, is_cancelled)?;
        Ok(self.completion.request_cancel())
    }
}

impl HeadlessCheckExecutor {
    pub fn new(
        staging_parent: impl Into<PathBuf>,
        toolchain: Toolchain,
        expected_launcher_identity: Sha256Digest,
        expected_engine_identity: Sha256Digest,
        expected_payload_identity: Sha256Digest,
        pipeline_limits: PipelineLimits,
        protocol_limits: EngineProtocolLimits,
    ) -> Result<Self, HeadlessCheckError> {
        pipeline_limits
            .validate()
            .map_err(|_| HeadlessCheckError::InvalidStagingRoot("invalid pipeline limits"))?;
        let staging_parent = staging_parent.into();
        validate_private_staging_root(&staging_parent)?;
        let stream = CheckRequestStream::new(
            expected_launcher_identity,
            expected_engine_identity,
            expected_payload_identity,
            protocol_limits,
        )?;
        Ok(Self {
            stream,
            staging_parent,
            toolchain,
            pipeline_limits,
            protocol_limits,
            linux_payload_authority: None,
            stage: None,
            sealed: None,
            executed: false,
            poisoned: false,
        })
    }

    /// Construct the exact Linux direct-child execution path. The authority
    /// is bound during the driver's existing single toolchain verification.
    pub fn new_with_linux_payload_authority(
        staging_parent: impl Into<PathBuf>,
        toolchain: Toolchain,
        expected_launcher_identity: Sha256Digest,
        expected_engine_identity: Sha256Digest,
        authority: LinuxPayloadAuthority,
        pipeline_limits: PipelineLimits,
        protocol_limits: EngineProtocolLimits,
    ) -> Result<Self, HeadlessCheckError> {
        let payload_identity = authority.payload_identity();
        let mut executor = Self::new(
            staging_parent,
            toolchain,
            expected_launcher_identity,
            expected_engine_identity,
            payload_identity,
            pipeline_limits,
            protocol_limits,
        )?;
        executor.linux_payload_authority = Some(authority);
        Ok(executor)
    }

    /// Decode and validate exactly once, then consume only the owned validated
    /// action. A failed protocol or materialization step permanently poisons
    /// this executor; callers must start a fresh request in a fresh directory.
    pub fn accept_request_frame(
        &mut self,
        encoded: &[u8],
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<RequestStreamProgress, HeadlessCheckError> {
        if self.poisoned || self.executed {
            return Err(HeadlessCheckError::AlreadyExecuted);
        }
        let accepted = match self.stream.accept_validated(encoded, is_cancelled) {
            Ok(accepted) => accepted,
            Err(error) => {
                self.poisoned = true;
                return Err(error.into());
            }
        };
        let progress = accepted.progress();
        if let Err(error) = self.consume_action(accepted, is_cancelled) {
            self.poisoned = true;
            return Err(error);
        }
        Ok(progress)
    }

    /// Consume a fully sealed request into independently movable execution
    /// and late-cancellation halves. The control half retains only exact
    /// scalar protocol continuation state and an atomic cancellation flag.
    pub fn into_execution(
        self,
    ) -> Result<(HeadlessCheckExecution, LateRequestControl), HeadlessCheckError> {
        if self.poisoned || self.executed || self.sealed.is_none() || !self.stream.is_complete() {
            return Err(HeadlessCheckError::NotReady);
        }
        let stream = self.stream.late_cancel_stream()?;
        let completion = Arc::new(ExecutionCompletion::new());
        Ok((
            HeadlessCheckExecution {
                executor: self,
                completion: Arc::clone(&completion),
            },
            LateRequestControl { stream, completion },
        ))
    }

    fn consume_action(
        &mut self,
        accepted: AcceptedRequestFrame,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), HeadlessCheckError> {
        match accepted.into_action() {
            ValidatedRequestAction::ClientHello(_) => Ok(()),
            ValidatedRequestAction::RequestHeader => {
                let request = self
                    .stream
                    .request()
                    .ok_or(HeadlessCheckError::Materialization(
                        "missing sealed request header",
                    ))?;
                let hello = self
                    .stream
                    .hello()
                    .ok_or(HeadlessCheckError::Materialization("missing client hello"))?;
                self.stage = Some(Stage::create(
                    &self.staging_parent,
                    request,
                    hello,
                    self.protocol_limits,
                    is_cancelled,
                )?);
                Ok(())
            }
            ValidatedRequestAction::InputRecord { index, record } => {
                self.stage_mut()?.start_record(index, record, is_cancelled)
            }
            ValidatedRequestAction::InputChunk {
                record,
                offset,
                bytes,
            } => self
                .stage_mut()?
                .write_chunk(record, offset, &bytes, is_cancelled),
            ValidatedRequestAction::InputFinished(measurement) => {
                let stage = self
                    .stage
                    .take()
                    .ok_or(HeadlessCheckError::Materialization(
                        "input completed before staging began",
                    ))?;
                match stage.finish(measurement, self.protocol_limits, is_cancelled) {
                    Ok(sealed) => {
                        self.sealed = Some(sealed);
                        Ok(())
                    }
                    Err(error) => Err(error),
                }
            }
            ValidatedRequestAction::Cancelled => {
                self.stage = None;
                Ok(())
            }
        }
    }

    fn stage_mut(&mut self) -> Result<&mut Stage, HeadlessCheckError> {
        self.stage
            .as_mut()
            .ok_or(HeadlessCheckError::Materialization(
                "input record arrived before header",
            ))
    }

    /// Execute the sealed source tree exactly once and construct a canonical
    /// response. No backend, process execution, image publication, or QEMU is
    /// reachable through this check-only path.
    pub fn execute(
        &mut self,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<HeadlessCheckResponse, HeadlessCheckError> {
        self.execute_with_completion(is_cancelled, &|status| {
            if is_cancelled() {
                TerminalStatus::Cancelled
            } else {
                status
            }
        })
    }

    fn execute_with_completion(
        &mut self,
        is_cancelled: &dyn Fn() -> bool,
        complete_status: &dyn Fn(TerminalStatus) -> TerminalStatus,
    ) -> Result<HeadlessCheckResponse, HeadlessCheckError> {
        if self.poisoned {
            return Err(HeadlessCheckError::NotReady);
        }
        if self.executed {
            return Err(HeadlessCheckError::AlreadyExecuted);
        }
        let hello = self.stream.hello().ok_or(HeadlessCheckError::NotReady)?;
        let cancelled = self.stream.is_cancelled() || is_cancelled();
        if !cancelled && self.sealed.is_none() {
            return Err(HeadlessCheckError::NotReady);
        }
        self.executed = true;

        let request = self.stream.request().ok_or(HeadlessCheckError::NotReady)?;
        let mut response =
            ResponseAssembler::new(request, hello, self.protocol_limits, is_cancelled)?;
        if cancelled {
            return response.finish(TerminalStatus::Cancelled, is_cancelled, complete_status);
        }
        let sealed = self.sealed.as_ref().ok_or(HeadlessCheckError::NotReady)?;

        let mut limits = self.pipeline_limits;
        limits.semantic.evaluator_steps = limits
            .semantic
            .evaluator_steps
            .min(request.resources.comptime_steps);
        limits.semantic.evaluator_bytes = limits
            .semantic
            .evaluator_bytes
            .min(request.resources.comptime_memory_bytes);
        limits.semantic.constant_depth = limits
            .semantic
            .constant_depth
            .min(request.resources.comptime_call_depth);
        limits.parse.diagnostics = limits
            .parse
            .diagnostics
            .min(request.diagnostics.maximum_diagnostics);
        limits.semantic.diagnostic_count = limits
            .semantic
            .diagnostic_count
            .min(request.diagnostics.maximum_diagnostics);

        match validate_profile_policy(sealed, request, limits, is_cancelled) {
            Ok(()) => {}
            Err(PreflightError::Cancelled) => {
                return response.finish(TerminalStatus::Cancelled, is_cancelled, complete_status);
            }
            Err(PreflightError::Resource(message)) => {
                response.push_synthetic(
                    DiagnosticSeverity::Error,
                    "engine-resource-policy",
                    message,
                    is_cancelled,
                );
                return response.finish(
                    TerminalStatus::ResourceLimit,
                    is_cancelled,
                    complete_status,
                );
            }
            Err(PreflightError::Rejected(message)) => {
                response.push_synthetic(
                    DiagnosticSeverity::Error,
                    "engine-invalid-workspace",
                    message,
                    is_cancelled,
                );
                return response.finish(TerminalStatus::Rejected, is_cancelled, complete_status);
            }
            Err(PreflightError::Internal(message)) => {
                response.push_synthetic(
                    DiagnosticSeverity::Error,
                    "engine-staging-integrity",
                    message,
                    is_cancelled,
                );
                return response.finish(
                    TerminalStatus::InternalFailure,
                    is_cancelled,
                    complete_status,
                );
            }
        }

        let driver = if let Some(authority) = &self.linux_payload_authority {
            LocalCheckDriver::new_with_linux_payload_authority(
                self.toolchain.clone(),
                limits,
                authority.clone(),
            )
        } else {
            LocalCheckDriver::new(self.toolchain.clone(), limits)
        }
        .map_err(|_| {
            HeadlessCheckError::Materialization("bounded local check composition failed")
        })?;
        let events = PhaseEvents::new(request.resources.events);
        let command = Command::Check {
            workspace: WorkspaceSelection {
                manifest: sealed.root.join_path(&request.manifest)?,
                lockfile: sealed.root.join_path(&request.lockfile)?,
                image: try_copy_string(&request.image).map_err(|()| {
                    HeadlessCheckError::Materialization("image selection allocation failed")
                })?,
                target: TargetIdentity::new(try_copy_string(request.target.as_str()).map_err(
                    |()| HeadlessCheckError::Materialization("target selection allocation failed"),
                )?)
                .map_err(|_| {
                    HeadlessCheckError::Materialization("sealed target identity became invalid")
                })?,
                profile: try_copy_string(&request.profile).map_err(|()| {
                    HeadlessCheckError::Materialization("profile selection allocation failed")
                })?,
            },
            diagnostics: DiagnosticOptions {
                warnings_as_errors: request.diagnostics.warnings_as_errors,
                maximum_diagnostics: request.diagnostics.maximum_diagnostics,
            },
        };
        let result = driver.execute(&command, &events, is_cancelled);
        for event in events.take() {
            response.push(event, is_cancelled);
        }
        if events.overflowed() {
            return response.finish(TerminalStatus::ResourceLimit, is_cancelled, complete_status);
        }

        match result {
            Ok(CommandOutput::Check(outcome)) => {
                response.push_report(outcome.diagnostic_report(), is_cancelled);
                response.finish(TerminalStatus::Success, is_cancelled, complete_status)
            }
            Ok(_) => {
                response.push_synthetic(
                    DiagnosticSeverity::Error,
                    "engine-command-output",
                    "local check returned a non-check output".to_owned(),
                    is_cancelled,
                );
                response.finish(
                    TerminalStatus::InternalFailure,
                    is_cancelled,
                    complete_status,
                )
            }
            Err(DriverError::Cancelled) => {
                response.finish(TerminalStatus::Cancelled, is_cancelled, complete_status)
            }
            Err(DriverError::Rejected { report }) => {
                let status = if report.diagnostics().iter().any(|diagnostic| {
                    diagnostic.code.as_deref() == Some("semantic-comptime-resource-limit")
                }) {
                    TerminalStatus::ResourceLimit
                } else {
                    TerminalStatus::Rejected
                };
                response.push_report(&report, is_cancelled);
                response.finish(status, is_cancelled, complete_status)
            }
            Err(DriverError::Input { phase, message }) => {
                response.push_synthetic(
                    DiagnosticSeverity::Error,
                    "engine-workspace-input",
                    format!("{phase} input failed: {message}"),
                    is_cancelled,
                );
                response.finish(TerminalStatus::Rejected, is_cancelled, complete_status)
            }
            Err(DriverError::InvalidCommand(message)) => {
                response.push_synthetic(
                    DiagnosticSeverity::Error,
                    "engine-invalid-command",
                    message,
                    is_cancelled,
                );
                response.finish(
                    TerminalStatus::InternalFailure,
                    is_cancelled,
                    complete_status,
                )
            }
            Err(error) => {
                response.push_synthetic(
                    DiagnosticSeverity::Error,
                    "engine-internal-failure",
                    error.to_string(),
                    is_cancelled,
                );
                response.finish(
                    TerminalStatus::InternalFailure,
                    is_cancelled,
                    complete_status,
                )
            }
        }
    }
}

struct Stage {
    records: Vec<TreeRecord>,
    active: Option<ActiveFile>,
    directory_path_bytes: u64,
    maximum_directory_path_bytes: u64,
    root: OwnedTreeRoot,
}

struct ActiveFile {
    index: u32,
    declared_bytes: u64,
    offset: u64,
    file: File,
}

impl Stage {
    fn create(
        parent: &Path,
        request: &CheckRequest,
        hello: ClientHello,
        limits: EngineProtocolLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, HeadlessCheckError> {
        check_cancelled(is_cancelled)?;
        let name = request_directory_name(request.identity(), &hello.nonce)?;
        let path = try_join_relative(parent, &name)?;
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        builder.mode(0o700);
        builder.create(&path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                HeadlessCheckError::Materialization("request staging directory already exists")
            } else {
                HeadlessCheckError::Io(error)
            }
        })?;
        Ok(Self {
            records: Vec::new(),
            active: None,
            directory_path_bytes: 0,
            maximum_directory_path_bytes: limits.tree_path_bytes,
            root: OwnedTreeRoot {
                path,
                entries: Vec::new(),
            },
        })
    }

    fn start_record(
        &mut self,
        index: u32,
        record: TreeRecord,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), HeadlessCheckError> {
        check_cancelled(is_cancelled)?;
        self.finish_active()?;
        if index as usize != self.records.len() || record.mode != TreeMode::Data {
            return Err(HeadlessCheckError::Materialization(
                "validated record order or mode changed",
            ));
        }
        let path = self.root.join_path(&record.path)?;
        self.create_private_parents(&path, is_cancelled)?;
        self.records
            .try_reserve(1)
            .map_err(|_| HeadlessCheckError::Materialization("record table allocation failed"))?;
        self.root.entries.try_reserve(1).map_err(|_| {
            HeadlessCheckError::Materialization("staging entry table allocation failed")
        })?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let file = options.open(&path)?;
        self.root.entries.push(StagedEntry {
            path,
            kind: StagedEntryKind::File,
        });
        let declared_bytes = record.bytes;
        self.records.push(record);
        self.active = Some(ActiveFile {
            index,
            declared_bytes,
            offset: 0,
            file,
        });
        Ok(())
    }

    fn create_private_parents(
        &mut self,
        file: &Path,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), HeadlessCheckError> {
        let relative = file
            .strip_prefix(&self.root.path)
            .map_err(|_| HeadlessCheckError::Materialization("path escaped staging root"))?;
        let mut current = try_copy_path(&self.root.path)?;
        let Some(parent) = relative.parent() else {
            return Ok(());
        };
        for component in parent.components() {
            check_cancelled(is_cancelled)?;
            let Component::Normal(component) = component else {
                return Err(HeadlessCheckError::Materialization(
                    "non-normal path component reached staging",
                ));
            };
            current
                .try_reserve(component.len().saturating_add(1))
                .map_err(|_| {
                    HeadlessCheckError::Materialization("staging directory path allocation failed")
                })?;
            current.push(component);
            match fs::symlink_metadata(&current) {
                Ok(metadata) => {
                    if !metadata.is_dir() || metadata.file_type().is_symlink() {
                        return Err(HeadlessCheckError::Materialization(
                            "staging parent is not a real directory",
                        ));
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    let relative = current.strip_prefix(&self.root.path).map_err(|_| {
                        HeadlessCheckError::Materialization("staging directory escaped root")
                    })?;
                    let path_bytes = path_to_portable(relative, is_cancelled)?.len() as u64;
                    let next = self.directory_path_bytes.checked_add(path_bytes).ok_or(
                        HeadlessCheckError::Materialization(
                            "staging directory path-byte count overflow",
                        ),
                    )?;
                    if next > self.maximum_directory_path_bytes {
                        return Err(HeadlessCheckError::Protocol(
                            EngineProtocolError::ResourceLimit {
                                resource: "staging directory path bytes",
                                limit: self.maximum_directory_path_bytes,
                            },
                        ));
                    }
                    self.root.entries.try_reserve(1).map_err(|_| {
                        HeadlessCheckError::Materialization("staging entry table allocation failed")
                    })?;
                    let tracked_path = try_copy_path(&current)?;
                    let mut builder = fs::DirBuilder::new();
                    #[cfg(unix)]
                    builder.mode(0o700);
                    builder.create(&current)?;
                    self.root.entries.push(StagedEntry {
                        path: tracked_path,
                        kind: StagedEntryKind::Directory,
                    });
                    self.directory_path_bytes = next;
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn write_chunk(
        &mut self,
        record: u32,
        offset: u64,
        bytes: &[u8],
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), HeadlessCheckError> {
        check_cancelled(is_cancelled)?;
        let active = self
            .active
            .as_mut()
            .ok_or(HeadlessCheckError::Materialization(
                "validated chunk has no active file",
            ))?;
        if active.index != record || active.offset != offset {
            return Err(HeadlessCheckError::Materialization(
                "validated chunk position changed",
            ));
        }
        active.file.write_all(bytes)?;
        active.offset = active
            .offset
            .checked_add(bytes.len() as u64)
            .ok_or(HeadlessCheckError::Materialization("file size overflow"))?;
        if active.offset > active.declared_bytes {
            return Err(HeadlessCheckError::Materialization(
                "materialized file exceeded its declaration",
            ));
        }
        check_cancelled(is_cancelled)
    }

    fn finish_active(&mut self) -> Result<(), HeadlessCheckError> {
        if let Some(active) = self.active.take() {
            if active.offset != active.declared_bytes {
                return Err(HeadlessCheckError::Materialization(
                    "materialized file ended before its declaration",
                ));
            }
            active.file.sync_all()?;
        }
        Ok(())
    }

    fn finish(
        mut self,
        declared: TreeMeasurement,
        limits: EngineProtocolLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<SealedInput, HeadlessCheckError> {
        self.finish_active()?;
        verify_inventory(
            &self.root,
            &self.records,
            self.directory_path_bytes,
            is_cancelled,
        )?;
        for record in &self.records {
            check_cancelled(is_cancelled)?;
            let path = self.root.join_path(&record.path)?;
            let (bytes, digest) = remeasure_file(&path, record.bytes, is_cancelled)?;
            if bytes != record.bytes || digest != record.digest {
                return Err(HeadlessCheckError::Materialization(
                    "staged file changed during independent remeasurement",
                ));
            }
        }
        if measure_tree(&self.records, limits, is_cancelled)? != declared {
            return Err(HeadlessCheckError::Materialization(
                "independently remeasured tree differs from request",
            ));
        }
        seal_tree_read_only(&self.root, is_cancelled)?;
        sync_directories(&self.root, is_cancelled)?;
        Ok(SealedInput { root: self.root })
    }
}

struct SealedInput {
    root: OwnedTreeRoot,
}

struct OwnedTreeRoot {
    path: PathBuf,
    entries: Vec<StagedEntry>,
}

#[derive(Clone, Copy)]
enum StagedEntryKind {
    File,
    Directory,
}

struct StagedEntry {
    path: PathBuf,
    kind: StagedEntryKind,
}

impl OwnedTreeRoot {
    fn join_path(
        &self,
        path: &wrela_driver::engine::EnginePath,
    ) -> Result<PathBuf, HeadlessCheckError> {
        try_join_relative(&self.path, path.as_str())
    }
}

impl Drop for OwnedTreeRoot {
    fn drop(&mut self) {
        make_owned_entry_writable(&self.path, StagedEntryKind::Directory);
        for entry in &self.entries {
            if matches!(entry.kind, StagedEntryKind::Directory) {
                make_owned_entry_writable(&entry.path, entry.kind);
            }
        }
        for entry in &self.entries {
            if matches!(entry.kind, StagedEntryKind::File) {
                make_owned_entry_writable(&entry.path, entry.kind);
            }
        }
        for entry in self.entries.iter().rev() {
            let Ok(metadata) = fs::symlink_metadata(&entry.path) else {
                continue;
            };
            if metadata.file_type().is_symlink() {
                continue;
            }
            match entry.kind {
                StagedEntryKind::File => {
                    let _ = fs::remove_file(&entry.path);
                }
                StagedEntryKind::Directory => {
                    let _ = fs::remove_dir(&entry.path);
                }
            }
        }
        let _ = fs::remove_dir(&self.path);
    }
}

fn make_owned_entry_writable(path: &Path, kind: StagedEntryKind) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.file_type().is_symlink() {
        return;
    }
    let mut permissions = metadata.permissions();
    #[cfg(unix)]
    permissions.set_mode(match kind {
        StagedEntryKind::File => 0o600,
        StagedEntryKind::Directory => 0o700,
    });
    #[cfg(not(unix))]
    permissions.set_readonly(false);
    let _ = fs::set_permissions(path, permissions);
}

#[derive(Debug)]
enum PreflightError {
    Cancelled,
    Resource(String),
    Rejected(String),
    Internal(String),
}

fn validate_profile_policy(
    sealed: &SealedInput,
    request: &CheckRequest,
    limits: PipelineLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), PreflightError> {
    if is_cancelled() {
        return Err(PreflightError::Cancelled);
    }
    let path = sealed.root.join_path(&request.manifest).map_err(|_| {
        PreflightError::Resource("cannot allocate the bounded sealed manifest path".to_owned())
    })?;
    let bytes = read_bounded(
        &path,
        limits.package_load.manifest_bytes_per_package,
        is_cancelled,
    )
    .map_err(|error| match error {
        BoundedReadError::Cancelled => PreflightError::Cancelled,
        BoundedReadError::Limit => PreflightError::Resource(
            "workspace manifest exceeds the configured manifest-byte limit".to_owned(),
        ),
        BoundedReadError::Io(message) => PreflightError::Internal(message),
    })?;
    let entry_limit =
        u32::try_from(limits.package_load.manifest_bytes_per_package).unwrap_or(u32::MAX);
    let manifest = CanonicalPackageCodec::new()
        .decode_manifest(
            &bytes,
            ManifestCodecLimits {
                bytes: limits.package_load.manifest_bytes_per_package,
                string_bytes: limits.package_load.manifest_bytes_per_package,
                modules: limits.package_load.sources.min(entry_limit),
                dependencies: entry_limit,
                profiles: entry_limit,
                images: entry_limit,
                image_tests: limits.package_load.scenarios.min(entry_limit),
            },
            is_cancelled,
        )
        .map_err(|error| {
            if is_cancelled() {
                PreflightError::Cancelled
            } else {
                PreflightError::Rejected(format!(
                    "cannot decode sealed workspace manifest: {error}"
                ))
            }
        })?;
    let profile = manifest
        .profiles
        .iter()
        .find(|profile| profile.name == request.profile)
        .ok_or_else(|| {
            PreflightError::Rejected(format!(
                "workspace does not declare requested profile `{}`",
                request.profile
            ))
        })?;
    if profile.comptime.steps > request.resources.comptime_steps
        || profile.comptime.memory_bytes > request.resources.comptime_memory_bytes
        || profile.comptime.call_depth > request.resources.comptime_call_depth
    {
        return Err(PreflightError::Resource(format!(
            "profile `{}` compile-time policy exceeds the sealed engine request quota",
            request.profile
        )));
    }
    Ok(())
}

struct PhaseEvents {
    events: RefCell<Vec<EngineEvent>>,
    maximum: u32,
    overflowed: Cell<bool>,
}

impl PhaseEvents {
    fn new(maximum: u32) -> Self {
        Self {
            events: RefCell::new(Vec::new()),
            maximum,
            overflowed: Cell::new(false),
        }
    }

    fn take(&self) -> Vec<EngineEvent> {
        std::mem::take(&mut *self.events.borrow_mut())
    }

    fn overflowed(&self) -> bool {
        self.overflowed.get()
    }
}

impl EventSink for PhaseEvents {
    fn emit(&self, event: DriverEvent<'_>) {
        let projected = match event {
            DriverEvent::PhaseStarted { phase } => match try_copy_string(phase) {
                Ok(phase) => Some(EngineEvent::PhaseStarted { phase }),
                Err(()) => {
                    self.overflowed.set(true);
                    None
                }
            },
            DriverEvent::PhaseFinished { phase, reused } => match try_copy_string(phase) {
                Ok(phase) => Some(EngineEvent::PhaseFinished { phase, reused }),
                Err(()) => {
                    self.overflowed.set(true);
                    None
                }
            },
            // The final sealed DiagnosticReport is projected exactly once by
            // the executor. Retaining this borrowed callback would duplicate
            // diagnostics and detach them from their source database.
            DriverEvent::Diagnostic { .. }
            | DriverEvent::ArtifactPublished { .. }
            | DriverEvent::TestProgress { .. } => None,
        };
        if let Some(projected) = projected {
            let mut events = self.events.borrow_mut();
            if events.len() >= self.maximum as usize || events.try_reserve(1).is_err() {
                self.overflowed.set(true);
            } else {
                events.push(projected);
            }
        }
    }
}

struct ResponseAssembler {
    request_identity: Sha256Digest,
    input: TreeMeasurement,
    maximum_diagnostics: u32,
    hello: ServerHello,
    output: TreeMeasurement,
    events: Vec<EngineEvent>,
    report: Option<CheckReportIdentityBuilder>,
    diagnostic_count: u32,
    quota_exhausted: bool,
    projection_failed: bool,
    cancelled: bool,
}

impl ResponseAssembler {
    fn new(
        request: &CheckRequest,
        client: ClientHello,
        mut limits: EngineProtocolLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, HeadlessCheckError> {
        limits.events = limits.events.min(request.resources.events);
        limits.event_bytes = limits.event_bytes.min(request.resources.event_bytes);
        let mut cancelled = false;
        let nonce = match nonce_proof(
            request.identity(),
            client.launcher_identity,
            request.engine_identity,
            request.payload_identity,
            client.nonce,
            is_cancelled,
        ) {
            Ok(nonce) => nonce,
            Err(EngineProtocolError::Cancelled) => {
                cancelled = true;
                nonce_proof(
                    request.identity(),
                    client.launcher_identity,
                    request.engine_identity,
                    request.payload_identity,
                    client.nonce,
                    &|| false,
                )?
            }
            Err(error) => return Err(error.into()),
        };
        let hello = ServerHello {
            engine_identity: request.engine_identity,
            payload_identity: request.payload_identity,
            nonce_proof: nonce,
        };
        let output = match empty_tree_measurement(is_cancelled) {
            Ok(output) => output,
            Err(EngineProtocolError::Cancelled) => {
                cancelled = true;
                empty_tree_measurement(&|| false)?
            }
            Err(error) => return Err(error.into()),
        };
        Ok(Self {
            request_identity: request.identity(),
            input: request.input,
            maximum_diagnostics: request.diagnostics.maximum_diagnostics,
            hello,
            output,
            events: Vec::new(),
            report: Some(CheckReportIdentityBuilder::new(request.identity(), limits)?),
            diagnostic_count: 0,
            quota_exhausted: false,
            projection_failed: false,
            cancelled,
        })
    }

    fn push(&mut self, event: EngineEvent, is_cancelled: &dyn Fn() -> bool) {
        if self.cancelled || is_cancelled() {
            self.cancelled = true;
            return;
        }
        if self.quota_exhausted || self.projection_failed {
            return;
        }
        if matches!(event, EngineEvent::Diagnostic { .. })
            && self.diagnostic_count >= self.maximum_diagnostics
        {
            self.quota_exhausted = true;
            return;
        }
        let Some(report) = self.report.as_mut() else {
            self.quota_exhausted = true;
            return;
        };
        if self.events.try_reserve(1).is_err() {
            self.quota_exhausted = true;
            return;
        }
        match report.observe(&event, is_cancelled) {
            Ok(()) => {
                if matches!(event, EngineEvent::Diagnostic { .. }) {
                    self.diagnostic_count += 1;
                }
                self.events.push(event);
            }
            Err(EngineProtocolError::ResourceLimit { .. }) => self.quota_exhausted = true,
            Err(EngineProtocolError::Cancelled) => self.cancelled = true,
            Err(_) => self.projection_failed = true,
        }
    }

    fn push_report(&mut self, report: &DiagnosticReport, is_cancelled: &dyn Fn() -> bool) {
        for diagnostic in report.diagnostics() {
            if is_cancelled() {
                self.cancelled = true;
                return;
            }
            match project_diagnostic(diagnostic, report.sources(), is_cancelled) {
                Ok(event) => self.push(event, is_cancelled),
                Err(ProjectionError::Resource) => {
                    self.quota_exhausted = true;
                    return;
                }
                Err(ProjectionError::InvalidSource) => {
                    self.projection_failed = true;
                    return;
                }
                Err(ProjectionError::Cancelled) => {
                    self.cancelled = true;
                    return;
                }
            }
        }
    }

    fn push_synthetic(
        &mut self,
        severity: DiagnosticSeverity,
        code: &'static str,
        message: String,
        is_cancelled: &dyn Fn() -> bool,
    ) {
        let stable_id = match stable_event_id(severity, code, &message, None, 0, 0, is_cancelled) {
            Ok(stable_id) => stable_id,
            Err(ProjectionError::Cancelled) => {
                self.cancelled = true;
                return;
            }
            Err(_) => {
                self.quota_exhausted = true;
                return;
            }
        };
        let code = match try_copy_string_cancellable(code, is_cancelled) {
            Ok(code) => code,
            Err(ProjectionError::Cancelled) => {
                self.cancelled = true;
                return;
            }
            Err(_) => {
                self.quota_exhausted = true;
                return;
            }
        };
        self.push(
            EngineEvent::Diagnostic {
                stable_id,
                severity,
                code,
                message,
                path: None,
                line: 0,
                column: 0,
            },
            is_cancelled,
        );
    }

    fn finish(
        mut self,
        requested_status: TerminalStatus,
        is_cancelled: &dyn Fn() -> bool,
        complete_status: &dyn Fn(TerminalStatus) -> TerminalStatus,
    ) -> Result<HeadlessCheckResponse, HeadlessCheckError> {
        let mut status = if self.cancelled || is_cancelled() {
            TerminalStatus::Cancelled
        } else if self.quota_exhausted {
            TerminalStatus::ResourceLimit
        } else if self.projection_failed {
            TerminalStatus::InternalFailure
        } else {
            requested_status
        };
        let report = self
            .report
            .take()
            .ok_or(HeadlessCheckError::Materialization(
                "response report already finished",
            ))?;
        let events = report.events();
        let event_bytes = report.event_bytes();
        let report_identity = match report.finish(is_cancelled) {
            Ok(identity) => identity,
            Err(EngineProtocolError::Cancelled) => {
                status = TerminalStatus::Cancelled;
                report.finish(&|| false)?
            }
            Err(error) => return Err(error.into()),
        };
        status = complete_status(status);
        Ok(HeadlessCheckResponse {
            request_identity: self.request_identity,
            hello: self.hello,
            events: self.events,
            output: self.output,
            terminal: EngineTerminal {
                status,
                diagnostic_count: self.diagnostic_count,
                report_identity,
                usage: EngineResourceUsage {
                    input_bytes: self.input.content_bytes,
                    output_bytes: 0,
                    events,
                    event_bytes,
                    // The semantic evaluator enforces the sealed limits, but
                    // CheckOutcome does not yet export exact counters. Keep
                    // the explicitly optional measurement absent.
                    comptime: None,
                },
            },
        })
    }
}

enum ProjectionError {
    Resource,
    InvalidSource,
    Cancelled,
}

fn project_diagnostic(
    diagnostic: &Diagnostic,
    sources: &SourceDatabase,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<EngineEvent, ProjectionError> {
    check_projection_cancelled(is_cancelled)?;
    let severity = match diagnostic.severity {
        Severity::Warning => DiagnosticSeverity::Warning,
        Severity::Error => DiagnosticSeverity::Error,
    };
    let code = try_copy_string_cancellable(
        diagnostic
            .code
            .as_deref()
            .unwrap_or_else(|| diagnostic.category.as_str()),
        is_cancelled,
    )?;
    let mut extra_bytes = 0usize;
    for note in &diagnostic.notes {
        check_projection_cancelled(is_cancelled)?;
        extra_bytes = extra_bytes
            .checked_add(7)
            .and_then(|total| total.checked_add(note.len()))
            .ok_or(ProjectionError::Resource)?;
    }
    for help in &diagnostic.help {
        check_projection_cancelled(is_cancelled)?;
        extra_bytes = extra_bytes
            .checked_add(7)
            .and_then(|total| total.checked_add(help.len()))
            .ok_or(ProjectionError::Resource)?;
    }
    let capacity = diagnostic
        .message
        .len()
        .checked_add(extra_bytes)
        .ok_or(ProjectionError::Resource)?;
    let mut message = String::new();
    message
        .try_reserve_exact(capacity)
        .map_err(|_| ProjectionError::Resource)?;
    push_str_cancellable(&mut message, &diagnostic.message, is_cancelled)?;
    for note in &diagnostic.notes {
        message.push_str("\nnote: ");
        push_str_cancellable(&mut message, note, is_cancelled)?;
    }
    for help in &diagnostic.help {
        message.push_str("\nhelp: ");
        push_str_cancellable(&mut message, help, is_cancelled)?;
    }
    let source = sources
        .get(diagnostic.primary.file)
        .ok_or(ProjectionError::InvalidSource)?;
    let path = wrela_driver::engine::EnginePath::new(try_copy_string_cancellable(
        source.path(),
        is_cancelled,
    )?)
    .map_err(|_| ProjectionError::InvalidSource)?;
    let position = source
        .position(diagnostic.primary.range.start)
        .ok_or(ProjectionError::InvalidSource)?;
    let line = position.line;
    let column = position.byte_column;
    let stable_id = stable_event_id(
        severity,
        &code,
        &message,
        Some(&path),
        line,
        column,
        is_cancelled,
    )?;
    Ok(EngineEvent::Diagnostic {
        stable_id,
        severity,
        code,
        message,
        path: Some(path),
        line,
        column,
    })
}

fn stable_event_id(
    severity: DiagnosticSeverity,
    code: &str,
    message: &str,
    path: Option<&wrela_driver::engine::EnginePath>,
    line: u32,
    column: u32,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Sha256Digest, ProjectionError> {
    let path_bytes = path.map_or(&[][..], |path| path.as_str().as_bytes());
    check_projection_cancelled(is_cancelled)?;
    let mut digest = SoftwareSha256.begin_sha256();
    digest.update(b"WRELDEI\0");
    digest.update(&1u32.to_le_bytes());
    digest.update(&[match severity {
        DiagnosticSeverity::Warning => 1,
        DiagnosticSeverity::Error => 2,
    }]);
    update_stable_hashed(&mut digest, code.as_bytes(), is_cancelled)?;
    update_stable_hashed(&mut digest, message.as_bytes(), is_cancelled)?;
    update_stable_hashed(&mut digest, path_bytes, is_cancelled)?;
    digest.update(&line.to_le_bytes());
    digest.update(&column.to_le_bytes());
    check_projection_cancelled(is_cancelled)?;
    Ok(digest.finish())
}

fn update_stable_hashed(
    digest: &mut Box<dyn wrela_package_loader::ContentDigest + '_>,
    value: &[u8],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ProjectionError> {
    let length = u64::try_from(value.len()).map_err(|_| ProjectionError::Resource)?;
    digest.update(&length.to_le_bytes());
    for chunk in value.chunks(CANCELLATION_CHUNK_BYTES) {
        check_projection_cancelled(is_cancelled)?;
        digest.update(chunk);
    }
    check_projection_cancelled(is_cancelled)
}

fn check_projection_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), ProjectionError> {
    if is_cancelled() {
        Err(ProjectionError::Cancelled)
    } else {
        Ok(())
    }
}

fn push_str_cancellable(
    output: &mut String,
    value: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ProjectionError> {
    let mut offset = 0usize;
    while offset < value.len() {
        check_projection_cancelled(is_cancelled)?;
        let mut end = offset
            .checked_add(CANCELLATION_CHUNK_BYTES)
            .map_or(value.len(), |end| end.min(value.len()));
        while end > offset && !value.is_char_boundary(end) {
            end -= 1;
        }
        if end == offset {
            end = value[offset..]
                .char_indices()
                .nth(1)
                .map_or(value.len(), |(index, _)| offset + index);
        }
        output.push_str(&value[offset..end]);
        offset = end;
    }
    check_projection_cancelled(is_cancelled)
}

fn try_copy_string_cancellable(
    value: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<String, ProjectionError> {
    let mut copy = String::new();
    copy.try_reserve_exact(value.len())
        .map_err(|_| ProjectionError::Resource)?;
    push_str_cancellable(&mut copy, value, is_cancelled)?;
    Ok(copy)
}

fn try_copy_string(value: &str) -> Result<String, ()> {
    let mut copy = String::new();
    copy.try_reserve_exact(value.len()).map_err(|_| ())?;
    copy.push_str(value);
    Ok(copy)
}

fn validate_private_staging_root(path: &Path) -> Result<(), HeadlessCheckError> {
    if !normal_absolute_path(path) {
        return Err(HeadlessCheckError::InvalidStagingRoot(
            "path must be absolute and lexically normalized",
        ));
    }
    let canonical = fs::canonicalize(path)?;
    if canonical != path {
        return Err(HeadlessCheckError::InvalidStagingRoot(
            "path must already be canonical and contain no symlink spelling",
        ));
    }
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(HeadlessCheckError::InvalidStagingRoot(
            "path must name a real directory",
        ));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o7777 != 0o700 {
        return Err(HeadlessCheckError::InvalidStagingRoot(
            "directory mode must be exactly owner-only readable, writable, and searchable (0700)",
        ));
    }
    Ok(())
}

fn normal_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        })
}

fn verify_inventory(
    root: &OwnedTreeRoot,
    records: &[TreeRecord],
    directory_path_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), HeadlessCheckError> {
    let mut expected_dirs = Vec::new();
    for entry in &root.entries {
        check_cancelled(is_cancelled)?;
        if matches!(entry.kind, StagedEntryKind::Directory) {
            expected_dirs.try_reserve(1).map_err(|_| {
                HeadlessCheckError::Materialization(
                    "expected directory inventory allocation failed",
                )
            })?;
            expected_dirs.push(path_to_portable(
                entry.path.strip_prefix(&root.path).map_err(|_| {
                    HeadlessCheckError::Materialization("tracked directory escaped staging root")
                })?,
                is_cancelled,
            )?);
        }
    }
    cancellable_sort_strings(&mut expected_dirs, is_cancelled)?;
    let maximum_entries = records.len().checked_add(expected_dirs.len()).ok_or(
        HeadlessCheckError::Materialization("staging inventory entry count overflow"),
    )?;
    let maximum_path_bytes = records
        .iter()
        .try_fold(directory_path_bytes, |total, record| {
            total.checked_add(record.path.as_str().len() as u64)
        })
        .ok_or(HeadlessCheckError::Materialization(
            "staging inventory path-byte count overflow",
        ))?;
    let (mut actual_files, mut actual_dirs) = inventory_directory(
        &root.path,
        maximum_entries,
        maximum_path_bytes,
        is_cancelled,
    )?;
    cancellable_sort_strings(&mut actual_files, is_cancelled)?;
    cancellable_sort_strings(&mut actual_dirs, is_cancelled)?;
    if actual_files.len() != records.len()
        || actual_files
            .iter()
            .zip(records)
            .any(|(actual, expected)| actual != expected.path.as_str())
        || actual_dirs != expected_dirs
    {
        return Err(HeadlessCheckError::Materialization(
            "staging tree contains missing or undeclared entries",
        ));
    }
    Ok(())
}

fn inventory_directory(
    root: &Path,
    maximum_entries: usize,
    maximum_path_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(Vec<String>, Vec<String>), HeadlessCheckError> {
    let mut work = Vec::new();
    work.try_reserve(1).map_err(|_| {
        HeadlessCheckError::Materialization("staging inventory worklist allocation failed")
    })?;
    work.push(try_copy_path(root)?);
    let mut files = Vec::new();
    let mut directories = Vec::new();
    let mut path_bytes = 0u64;
    while let Some(directory) = work.pop() {
        check_cancelled(is_cancelled)?;
        for entry in fs::read_dir(&directory)? {
            check_cancelled(is_cancelled)?;
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                return Err(HeadlessCheckError::Materialization(
                    "symlink appeared in private staging tree",
                ));
            }
            let relative = path.strip_prefix(root).map_err(|_| {
                HeadlessCheckError::Materialization("inventory escaped staging root")
            })?;
            let portable = path_to_portable(relative, is_cancelled)?;
            path_bytes = path_bytes.checked_add(portable.len() as u64).ok_or(
                HeadlessCheckError::Materialization("staging inventory path-byte count overflow"),
            )?;
            if path_bytes > maximum_path_bytes {
                return Err(HeadlessCheckError::Materialization(
                    "staging inventory exceeds its sealed path-byte bound",
                ));
            }
            let observed = files
                .len()
                .checked_add(directories.len())
                .and_then(|count| count.checked_add(1))
                .ok_or(HeadlessCheckError::Materialization(
                    "staging inventory entry count overflow",
                ))?;
            if observed > maximum_entries {
                return Err(HeadlessCheckError::Materialization(
                    "staging tree contains undeclared entries",
                ));
            }
            if metadata.is_dir() {
                directories.try_reserve(1).map_err(|_| {
                    HeadlessCheckError::Materialization(
                        "staging directory inventory allocation failed",
                    )
                })?;
                work.try_reserve(1).map_err(|_| {
                    HeadlessCheckError::Materialization(
                        "staging inventory worklist allocation failed",
                    )
                })?;
                directories.push(portable);
                work.push(path);
            } else if metadata.is_file() {
                files.try_reserve(1).map_err(|_| {
                    HeadlessCheckError::Materialization("staging file inventory allocation failed")
                })?;
                files.push(portable);
            } else {
                return Err(HeadlessCheckError::Materialization(
                    "non-data filesystem entry appeared in staging tree",
                ));
            }
        }
    }
    Ok((files, directories))
}

fn cancellable_sort_strings(
    values: &mut [String],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), HeadlessCheckError> {
    let length = values.len();
    for start in (0..length / 2).rev() {
        sift_down(values, start, length, is_cancelled)?;
    }
    for end in (1..length).rev() {
        check_cancelled(is_cancelled)?;
        values.swap(0, end);
        sift_down(values, 0, end, is_cancelled)?;
    }
    Ok(())
}

fn sift_down(
    values: &mut [String],
    mut root: usize,
    end: usize,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), HeadlessCheckError> {
    loop {
        check_cancelled(is_cancelled)?;
        let Some(left) = root.checked_mul(2).and_then(|value| value.checked_add(1)) else {
            return Err(HeadlessCheckError::Materialization(
                "staging inventory sort index overflow",
            ));
        };
        if left >= end {
            return Ok(());
        }
        let right = left + 1;
        let child = if right < end
            && compare_strings(&values[right], &values[left], is_cancelled)? == Ordering::Greater
        {
            right
        } else {
            left
        };
        if compare_strings(&values[root], &values[child], is_cancelled)? != Ordering::Less {
            return Ok(());
        }
        values.swap(root, child);
        root = child;
    }
}

fn compare_strings(
    left: &str,
    right: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Ordering, HeadlessCheckError> {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let common = left.len().min(right.len());
    let mut offset = 0usize;
    while offset < common {
        check_cancelled(is_cancelled)?;
        let end = offset
            .checked_add(CANCELLATION_CHUNK_BYTES)
            .map_or(common, |end| end.min(common));
        let ordering = left[offset..end].cmp(&right[offset..end]);
        if ordering != Ordering::Equal {
            return Ok(ordering);
        }
        offset = end;
    }
    check_cancelled(is_cancelled)?;
    Ok(left.len().cmp(&right.len()))
}

fn path_to_portable(
    path: &Path,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<String, HeadlessCheckError> {
    let mut result = String::new();
    for component in path.components() {
        check_cancelled(is_cancelled)?;
        let Component::Normal(component) = component else {
            return Err(HeadlessCheckError::Materialization(
                "staging path is not portable",
            ));
        };
        let component = component
            .to_str()
            .ok_or(HeadlessCheckError::Materialization(
                "staging path is not UTF-8",
            ))?;
        let additional = component
            .len()
            .checked_add(usize::from(!result.is_empty()))
            .ok_or(HeadlessCheckError::Materialization(
                "staging portable path length overflow",
            ))?;
        result.try_reserve(additional).map_err(|_| {
            HeadlessCheckError::Materialization("staging portable path allocation failed")
        })?;
        for _ in component.as_bytes().chunks(CANCELLATION_CHUNK_BYTES) {
            check_cancelled(is_cancelled)?;
        }
        if !result.is_empty() {
            result.push('/');
        }
        result.push_str(component);
    }
    Ok(result)
}

fn try_copy_path(path: &Path) -> Result<PathBuf, HeadlessCheckError> {
    let mut result = PathBuf::new();
    result
        .try_reserve_exact(path.as_os_str().len())
        .map_err(|_| HeadlessCheckError::Materialization("staging path allocation failed"))?;
    result.push(path);
    Ok(result)
}

fn try_join_relative(base: &Path, relative: &str) -> Result<PathBuf, HeadlessCheckError> {
    let capacity = base
        .as_os_str()
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_add(relative.len()))
        .ok_or(HeadlessCheckError::Materialization(
            "staging path length overflow",
        ))?;
    let mut result = PathBuf::new();
    result
        .try_reserve_exact(capacity)
        .map_err(|_| HeadlessCheckError::Materialization("staging path allocation failed"))?;
    result.push(base);
    result.push(relative);
    Ok(result)
}

fn remeasure_file(
    path: &Path,
    maximum: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(u64, Sha256Digest), HeadlessCheckError> {
    let before = fs::symlink_metadata(path)?;
    if !before.is_file() || before.file_type().is_symlink() || before.len() > maximum {
        return Err(HeadlessCheckError::Materialization(
            "staged record is not the declared data file",
        ));
    }
    let mut file = File::open(path)?;
    let mut digest = SoftwareSha256.begin_sha256();
    let mut buffer = [0u8; IO_CHUNK_BYTES];
    let mut total = 0u64;
    loop {
        check_cancelled(is_cancelled)?;
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or(HeadlessCheckError::Materialization(
                "staged file size overflow",
            ))?;
        if total > maximum {
            return Err(HeadlessCheckError::Materialization(
                "staged record exceeded its declared size",
            ));
        }
        digest.update(&buffer[..read]);
    }
    let after = file.metadata()?;
    if !same_file_snapshot(&before, &after) || total != after.len() {
        return Err(HeadlessCheckError::Materialization(
            "staged file changed while it was remeasured",
        ));
    }
    Ok((total, digest.finish()))
}

#[cfg(unix)]
fn same_file_snapshot(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(not(unix))]
fn same_file_snapshot(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}

fn seal_tree_read_only(
    root: &OwnedTreeRoot,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), HeadlessCheckError> {
    for entry in &root.entries {
        check_cancelled(is_cancelled)?;
        if matches!(entry.kind, StagedEntryKind::File) {
            let mut permissions = fs::metadata(&entry.path)?.permissions();
            #[cfg(unix)]
            permissions.set_mode(0o400);
            #[cfg(not(unix))]
            permissions.set_readonly(true);
            fs::set_permissions(&entry.path, permissions)?;
        }
    }
    for entry in root.entries.iter().rev() {
        check_cancelled(is_cancelled)?;
        if matches!(entry.kind, StagedEntryKind::Directory) {
            let mut permissions = fs::metadata(&entry.path)?.permissions();
            #[cfg(unix)]
            permissions.set_mode(0o500);
            #[cfg(not(unix))]
            permissions.set_readonly(true);
            fs::set_permissions(&entry.path, permissions)?;
        }
    }
    let mut permissions = fs::metadata(&root.path)?.permissions();
    #[cfg(unix)]
    permissions.set_mode(0o500);
    #[cfg(not(unix))]
    permissions.set_readonly(true);
    fs::set_permissions(&root.path, permissions)?;
    check_cancelled(is_cancelled)
}

fn sync_directories(
    root: &OwnedTreeRoot,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), HeadlessCheckError> {
    for entry in root.entries.iter().rev() {
        check_cancelled(is_cancelled)?;
        if matches!(entry.kind, StagedEntryKind::Directory) {
            File::open(&entry.path)?.sync_all()?;
        }
    }
    check_cancelled(is_cancelled)?;
    File::open(&root.path)?.sync_all()?;
    check_cancelled(is_cancelled)
}

enum BoundedReadError {
    Cancelled,
    Limit,
    Io(String),
}

fn read_bounded(
    path: &Path,
    maximum: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>, BoundedReadError> {
    if is_cancelled() {
        return Err(BoundedReadError::Cancelled);
    }
    let before =
        fs::symlink_metadata(path).map_err(|error| BoundedReadError::Io(error.to_string()))?;
    if !before.is_file() || before.file_type().is_symlink() {
        return Err(BoundedReadError::Io(
            "sealed manifest is not a regular file".to_owned(),
        ));
    }
    let length = before.len();
    if length > maximum {
        return Err(BoundedReadError::Limit);
    }
    let mut file = File::open(path).map_err(|error| BoundedReadError::Io(error.to_string()))?;
    let opened = file
        .metadata()
        .map_err(|error| BoundedReadError::Io(error.to_string()))?;
    if !same_file_snapshot(&before, &opened) {
        return Err(BoundedReadError::Io(
            "sealed manifest changed while opening".to_owned(),
        ));
    }
    let capacity = usize::try_from(length).map_err(|_| BoundedReadError::Limit)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| BoundedReadError::Limit)?;
    let mut buffer = [0u8; IO_CHUNK_BYTES];
    loop {
        if is_cancelled() {
            return Err(BoundedReadError::Cancelled);
        }
        let read = file
            .read(&mut buffer)
            .map_err(|error| BoundedReadError::Io(error.to_string()))?;
        if read == 0 {
            break;
        }
        let next = bytes
            .len()
            .checked_add(read)
            .ok_or(BoundedReadError::Limit)?;
        if next as u64 > maximum {
            return Err(BoundedReadError::Limit);
        }
        bytes
            .try_reserve(read)
            .map_err(|_| BoundedReadError::Limit)?;
        bytes.extend_from_slice(&buffer[..read]);
    }
    let after = file
        .metadata()
        .map_err(|error| BoundedReadError::Io(error.to_string()))?;
    if !same_file_snapshot(&before, &after) || bytes.len() as u64 != after.len() {
        return Err(BoundedReadError::Io(
            "sealed manifest changed while reading".to_owned(),
        ));
    }
    if is_cancelled() {
        return Err(BoundedReadError::Cancelled);
    }
    Ok(bytes)
}

fn check_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), HeadlessCheckError> {
    if is_cancelled() {
        Err(HeadlessCheckError::Protocol(EngineProtocolError::Cancelled))
    } else {
        Ok(())
    }
}

fn request_directory_name(
    identity: Sha256Digest,
    nonce: &[u8; 32],
) -> Result<String, HeadlessCheckError> {
    let capacity = b"request-".len() + identity.as_bytes().len() * 2 + 1 + nonce.len() * 2;
    let mut result = String::new();
    result.try_reserve_exact(capacity).map_err(|_| {
        HeadlessCheckError::Materialization("request directory name allocation failed")
    })?;
    result.push_str("request-");
    append_hex(&mut result, identity.as_bytes());
    result.push('-');
    append_hex(&mut result, nonce);
    Ok(result)
}

fn append_hex(result: &mut String, bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
    use std::thread;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use wrela_driver::engine::{
        CheckDiagnosticPolicy, CheckRequestFields, CheckResponseStream, EnginePath,
        EngineResourcePolicy, ResponseStreamProgress, sha256,
    };

    use super::*;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn staged_directory_metadata_accepts_exact_bound_and_rejects_one_over() {
        let directory = TestDirectory::new();
        let mut limits = EngineProtocolLimits::standard();
        limits.tree_path_bytes = 100;

        let (request, hello, records, contents) = request_fixture(10, limits);
        let mut exact = Stage::create(&directory.root, &request, hello, limits, &|| false)
            .expect("exact-bound stage");
        feed_records(&mut exact, &records, &contents).expect("exact-bound records");
        assert_eq!(exact.directory_path_bytes, 100);
        let sealed = exact
            .finish(request.input, limits, &|| false)
            .expect("exact-bound sealed tree");
        drop(sealed);
        assert!(directory.is_empty());

        let (request, hello, records, _) = request_fixture(11, limits);
        let mut over = Stage::create(&directory.root, &request, hello, limits, &|| false)
            .expect("over-bound stage");
        assert!(matches!(
            over.start_record(0, records[0].clone(), &|| false),
            Err(HeadlessCheckError::Protocol(
                EngineProtocolError::ResourceLimit {
                    resource: "staging directory path bytes",
                    limit: 100,
                }
            ))
        ));
        drop(over);
        assert!(directory.is_empty());
    }

    #[test]
    fn deep_staging_and_inventory_sort_poll_cancellation_and_cleanup() {
        let directory = TestDirectory::new();
        let limits = EngineProtocolLimits::standard();
        let (request, hello, records, _) = request_fixture(64, limits);
        let mut stage = Stage::create(&directory.root, &request, hello, limits, &|| false)
            .expect("cancellable stage");
        let polls = Cell::new(0u32);
        let cancelled = || {
            let next = polls.get().saturating_add(1);
            polls.set(next);
            next >= 12
        };
        assert!(matches!(
            stage.start_record(0, records[0].clone(), &cancelled),
            Err(HeadlessCheckError::Protocol(EngineProtocolError::Cancelled))
        ));
        drop(stage);
        assert!(directory.is_empty());

        let mut values = (0..256)
            .rev()
            .map(|value| format!("path-{value:04}"))
            .collect::<Vec<_>>();
        let polls = Cell::new(0u32);
        let cancelled = || {
            let next = polls.get().saturating_add(1);
            polls.set(next);
            next >= 20
        };
        assert!(matches!(
            cancellable_sort_strings(&mut values, &cancelled),
            Err(HeadlessCheckError::Protocol(EngineProtocolError::Cancelled))
        ));
    }

    #[test]
    fn long_equal_prefix_comparison_stops_at_the_exact_cancelled_chunk() {
        let mut left = "x".repeat(CANCELLATION_CHUNK_BYTES * 4);
        let mut right = left.clone();
        left.push('a');
        right.push('b');
        assert_eq!(
            compare_strings(&left, &right, &|| false).expect("long-prefix comparison"),
            Ordering::Less
        );

        let polls = Cell::new(0u32);
        let cancelled = || {
            let next = polls.get().saturating_add(1);
            polls.set(next);
            next == 5
        };
        assert!(matches!(
            compare_strings(&left, &right, &cancelled),
            Err(HeadlessCheckError::Protocol(EngineProtocolError::Cancelled))
        ));
        assert_eq!(polls.get(), 5);
    }

    #[test]
    fn deep_portable_path_conversion_polls_through_the_tail() {
        let depth = 64u32;
        let mut path = PathBuf::new();
        for _ in 0..depth {
            path.push("component");
        }
        assert_eq!(
            path_to_portable(&path, &|| false)
                .expect("deep portable path")
                .split('/')
                .count(),
            depth as usize
        );

        let polls = Cell::new(0u32);
        let cancelled = || {
            let next = polls.get().saturating_add(1);
            polls.set(next);
            next == depth * 2
        };
        assert!(matches!(
            path_to_portable(&path, &cancelled),
            Err(HeadlessCheckError::Protocol(EngineProtocolError::Cancelled))
        ));
        assert_eq!(polls.get(), depth * 2);
    }

    #[test]
    fn bounded_manifest_read_polls_between_fixed_chunks() {
        let directory = TestDirectory::new();
        let path = directory.root.join("manifest.bin");
        fs::write(&path, vec![0x5a; IO_CHUNK_BYTES * 4]).expect("bounded manifest fixture");
        let polls = Cell::new(0u32);
        let cancelled = || {
            let next = polls.get().saturating_add(1);
            polls.set(next);
            next >= 3
        };
        assert!(matches!(
            read_bounded(&path, (IO_CHUNK_BYTES * 4) as u64, &cancelled),
            Err(BoundedReadError::Cancelled)
        ));
    }

    #[test]
    fn cancellation_winning_the_terminal_race_constructs_a_cancelled_response() {
        let limits = EngineProtocolLimits::standard();
        let (request, hello, _, _) = request_fixture(1, limits);
        let response =
            ResponseAssembler::new(&request, hello, limits, &|| false).expect("response assembler");
        let completion = Arc::new(ExecutionCompletion::new());
        let at_linearization = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let worker_completion = Arc::clone(&completion);
        let worker_at = Arc::clone(&at_linearization);
        let worker_release = Arc::clone(&release);
        let worker = thread::spawn(move || {
            response.finish(
                TerminalStatus::Success,
                &|| worker_completion.is_cancel_requested(),
                &|status| {
                    worker_completion.complete_after(status, &|| {
                        worker_at.wait();
                        worker_release.wait();
                    })
                },
            )
        });
        at_linearization.wait();
        assert_eq!(
            completion.request_cancel(),
            LateCancelDisposition::Requested
        );
        release.wait();
        let response = worker
            .join()
            .expect("terminal worker")
            .expect("cancelled response");
        assert_eq!(response.terminal().status, TerminalStatus::Cancelled);
        validate_unit_response(&request, hello, &response);
    }

    #[test]
    fn completion_winning_the_terminal_race_rejects_late_relabeling() {
        let limits = EngineProtocolLimits::standard();
        let (request, hello, _, _) = request_fixture(1, limits);
        let response =
            ResponseAssembler::new(&request, hello, limits, &|| false).expect("response assembler");
        let completion = Arc::new(ExecutionCompletion::new());
        let at_linearization = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let cancel_completion = Arc::clone(&completion);
        let cancel_at = Arc::clone(&at_linearization);
        let cancel_release = Arc::clone(&release);
        let cancel = thread::spawn(move || {
            cancel_completion.request_cancel_after(&|| {
                cancel_at.wait();
                cancel_release.wait();
            })
        });
        at_linearization.wait();
        let response = response
            .finish(
                TerminalStatus::Success,
                &|| completion.is_cancel_requested(),
                &|status| completion.complete(status),
            )
            .expect("completed response");
        release.wait();
        assert_eq!(
            cancel.join().expect("late cancel worker"),
            LateCancelDisposition::ExecutionCompleted
        );
        assert_eq!(response.terminal().status, TerminalStatus::Success);
        validate_unit_response(&request, hello, &response);
    }

    #[test]
    fn response_projection_and_report_sealing_poll_cancellation() {
        let limits = EngineProtocolLimits::standard();
        let (request, hello, _, _) = request_fixture(1, limits);

        let mut projection = ResponseAssembler::new(&request, hello, limits, &|| false)
            .expect("projection response");
        let projection_polls = Cell::new(0u32);
        let cancel_projection = || {
            let next = projection_polls.get().saturating_add(1);
            projection_polls.set(next);
            next >= 6
        };
        projection.push_synthetic(
            DiagnosticSeverity::Error,
            "large-projection",
            "x".repeat(CANCELLATION_CHUNK_BYTES * 8),
            &cancel_projection,
        );
        let projected = projection
            .finish(TerminalStatus::Rejected, &cancel_projection, &|status| {
                status
            })
            .expect("projection cancellation response");
        assert_eq!(projected.terminal().status, TerminalStatus::Cancelled);
        assert!(projected.events().is_empty());
        validate_unit_response(&request, hello, &projected);

        let mut sealing =
            ResponseAssembler::new(&request, hello, limits, &|| false).expect("sealing response");
        sealing.push(
            EngineEvent::PhaseStarted {
                phase: "parse".to_owned(),
            },
            &|| false,
        );
        let sealing_polls = Cell::new(0u32);
        let cancel_sealing = || {
            let next = sealing_polls.get().saturating_add(1);
            sealing_polls.set(next);
            next >= 2
        };
        let sealed = sealing
            .finish(TerminalStatus::Success, &cancel_sealing, &|status| status)
            .expect("report sealing cancellation response");
        assert_eq!(sealed.terminal().status, TerminalStatus::Cancelled);
        assert_eq!(sealed.events().len(), 1);
        validate_unit_response(&request, hello, &sealed);

        let handshake = ResponseAssembler::new(&request, hello, limits, &|| true)
            .expect("cancelled handshake response")
            .finish(TerminalStatus::Success, &|| true, &|status| status)
            .expect("cancelled handshake terminal");
        assert_eq!(handshake.terminal().status, TerminalStatus::Cancelled);
        validate_unit_response(&request, hello, &handshake);
    }

    fn validate_unit_response(
        request: &CheckRequest,
        hello: ClientHello,
        response: &HeadlessCheckResponse,
    ) {
        let limits = EngineProtocolLimits::standard();
        let mut stream = CheckResponseStream::new(request, hello, limits, &|| false)
            .expect("unit response stream");
        let mut progress = ResponseStreamProgress::Pending;
        for frame in response
            .encode_frames(limits, &|| false)
            .expect("unit response frames")
        {
            progress = stream
                .accept(&frame, &|| false)
                .expect("validated unit response frame");
        }
        assert_eq!(progress, ResponseStreamProgress::Complete);
    }

    fn request_fixture(
        depth: usize,
        limits: EngineProtocolLimits,
    ) -> (CheckRequest, ClientHello, Vec<TreeRecord>, Vec<Vec<u8>>) {
        let path = format!("{}/data.wr", vec!["a"; depth].join("/"));
        let contents = vec![b"x".to_vec(), b"l".to_vec(), b"m".to_vec()];
        let paths = [path.as_str(), "wrela.lock", "wrela.toml"];
        let records = paths
            .into_iter()
            .zip(&contents)
            .map(|(path, bytes)| TreeRecord {
                path: EnginePath::new(path).expect("deep portable path"),
                mode: TreeMode::Data,
                bytes: bytes.len() as u64,
                digest: sha256(bytes, &|| false).expect("record digest"),
            })
            .collect::<Vec<_>>();
        let input = measure_tree(&records, limits, &|| false).expect("deep tree measurement");
        let mut resources = EngineResourcePolicy::check_standard();
        resources.input_records = input.records;
        resources.input_path_bytes = input.path_bytes;
        resources.input_content_bytes = input.content_bytes;
        let payload_identity = sha256(b"deep payload", &|| false).expect("payload digest");
        let request = CheckRequest::seal(
            CheckRequestFields {
                engine_identity: sha256(b"deep engine", &|| false).expect("engine digest"),
                payload_identity,
                manifest: EnginePath::new("wrela.toml").expect("manifest path"),
                lockfile: EnginePath::new("wrela.lock").expect("lock path"),
                image: "bootstrap".to_owned(),
                target: wrela_build_model::TargetIdentity::aarch64_qemu_virt_uefi(),
                profile: "development".to_owned(),
                diagnostics: CheckDiagnosticPolicy {
                    warnings_as_errors: false,
                    maximum_diagnostics: 16,
                },
                resources,
                input,
            },
            limits,
            &|| false,
        )
        .expect("deep request");
        let hello = ClientHello {
            launcher_identity: sha256(b"deep launcher", &|| false).expect("launcher digest"),
            payload_identity,
            nonce: [0x44; 32],
        };
        (request, hello, records, contents)
    }

    fn feed_records(
        stage: &mut Stage,
        records: &[TreeRecord],
        contents: &[Vec<u8>],
    ) -> Result<(), HeadlessCheckError> {
        for (index, (record, bytes)) in records.iter().zip(contents).enumerate() {
            stage.start_record(index as u32, record.clone(), &|| false)?;
            stage.write_chunk(index as u32, 0, bytes, &|| false)?;
        }
        Ok(())
    }

    struct TestDirectory {
        root: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            let base = fs::canonicalize(std::env::temp_dir()).expect("canonical temp directory");
            for _ in 0..128 {
                let sequence = NEXT_DIRECTORY.fetch_add(1, AtomicOrdering::Relaxed);
                let root = base.join(format!(
                    "wrela-engine-unit-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&root) {
                    Ok(()) => {
                        #[cfg(unix)]
                        {
                            let mut permissions = fs::metadata(&root)
                                .expect("test root metadata")
                                .permissions();
                            permissions.set_mode(0o700);
                            fs::set_permissions(&root, permissions)
                                .expect("private test root permissions");
                        }
                        return Self {
                            root: fs::canonicalize(root).expect("canonical test root"),
                        };
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("cannot create engine unit directory: {error}"),
                }
            }
            panic!("cannot allocate engine unit directory")
        }

        fn is_empty(&self) -> bool {
            fs::read_dir(&self.root)
                .expect("test root inventory")
                .next()
                .is_none()
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
