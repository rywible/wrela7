//! Linux-musl direct-execution candidate for one sealed engine request.
//!
//! The direct mode is intentionally a thin consumer of the existing engine-v1
//! protocol. It authenticates opaque producer artifacts by exact witnesses,
//! validates a complete canonical request, self-spawns the same measured ELF in
//! one-shot mode, validates the complete response, and only then publishes a
//! path-free candidate receipt. Production execution is refused unless the
//! binary targets AArch64 Linux-musl. A separate authenticated runner envelope
//! must prove that execution was native rather than user-mode emulation.

#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

use wrela_build_model::Sha256Digest;
use wrela_driver::engine::{
    CheckRequest, CheckRequestStream, CheckResponseStream, ClientHello, ENGINE_FRAME_HEADER_BYTES,
    ENGINE_PROTOCOL_VERSION, EngineComptimeUsage, EngineEvent, EngineMessage, EngineProtocolError,
    EngineProtocolLimits, EngineResourcePolicy, EngineResourceUsage, EngineTerminal,
    RequestStreamProgress, ResponseStreamProgress, TerminalStatus, TreeMeasurement,
    ValidatedResponseAction, decode_frame, decode_frame_header, empty_tree_measurement, sha256,
};
use wrela_toolchain::{
    LinuxPayloadAuthority, LinuxPayloadFileWitness, MAX_LINUX_PAYLOAD_AUTHORITY_BYTES,
};

const MAX_HOST_PATH_BYTES: usize = 64 * 1024;
const MAX_PRODUCER_OUTPUT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_PRODUCER_RECEIPT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_REQUEST_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ENGINE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_STDERR_BYTES: u64 = 64 * 1024;
const MAX_DIRECT_RECEIPT_BYTES: u64 = 16 * 1024;
const MAX_TIMEOUT_MILLISECONDS: u64 = 60 * 60 * 1000;
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Failure at the native direct-execution boundary. Messages deliberately do
/// not contain host paths or child-controlled text.
#[derive(Debug)]
pub enum DirectError {
    Usage,
    InvalidArgument(&'static str),
    UnsupportedHost,
    IdentityMismatch(&'static str),
    Protocol(EngineProtocolError),
    Io {
        operation: &'static str,
        kind: io::ErrorKind,
    },
    Allocation(&'static str),
    Cancelled,
    TimedOut,
    OutputLimit(&'static str),
    ChildFailure,
    ChildDiagnostic,
    InvalidReceipt,
    PublicationExists,
    PayloadAuthorityNotProven,
}

impl DirectError {
    /// Stable process exit category for the direct subcommand.
    #[must_use]
    pub const fn exit_code(&self) -> u8 {
        match self {
            Self::Usage | Self::InvalidArgument(_) => 2,
            Self::Cancelled => 130,
            _ => 1,
        }
    }
}

impl fmt::Display for DirectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage => formatter.write_str(
                "usage: wrela-engine direct --staging-parent ABSOLUTE --toolchain-root ABSOLUTE --producer-output ABSOLUTE --producer-output-sha256 HEX --producer-output-bytes DECIMAL --producer-receipt ABSOLUTE --producer-receipt-sha256 HEX --producer-receipt-bytes DECIMAL --request ABSOLUTE --request-sha256 HEX --request-bytes DECIMAL --payload-authority ABSOLUTE --payload-authority-sha256 HEX --payload-authority-bytes DECIMAL --engine-sha256 HEX --engine-bytes DECIMAL --timeout-ms DECIMAL --cancel-file ABSOLUTE --receipt ABSOLUTE",
            ),
            Self::InvalidArgument(name) => write!(formatter, "invalid direct argument {name}"),
            Self::UnsupportedHost => {
                formatter.write_str("direct execution requires the aarch64 Linux-musl engine")
            }
            Self::IdentityMismatch(name) => write!(formatter, "direct {name} identity mismatch"),
            Self::Protocol(error) => write!(formatter, "invalid direct engine-v1 stream: {error}"),
            Self::Io { operation, kind } => write!(formatter, "direct {operation} failed: {kind}"),
            Self::Allocation(resource) => {
                write!(formatter, "direct cannot allocate bounded {resource}")
            }
            Self::Cancelled => formatter.write_str("direct execution was cancelled"),
            Self::TimedOut => formatter.write_str("direct execution exceeded its timeout"),
            Self::OutputLimit(stream) => write!(formatter, "direct child {stream} exceeded its limit"),
            Self::ChildFailure => formatter.write_str("direct child failed"),
            Self::ChildDiagnostic => formatter.write_str("direct child emitted a process diagnostic"),
            Self::InvalidReceipt => formatter.write_str("direct candidate receipt is noncanonical or invalid"),
            Self::PublicationExists => formatter.write_str("direct receipt destination already exists"),
            Self::PayloadAuthorityNotProven => formatter
                .write_str("direct child did not prove the sealed Linux payload authority"),
        }
    }
}

impl std::error::Error for DirectError {}

impl From<EngineProtocolError> for DirectError {
    fn from(value: EngineProtocolError) -> Self {
        Self::Protocol(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileWitness {
    digest: Sha256Digest,
    bytes: u64,
}

#[derive(Debug)]
struct DirectConfig {
    staging_parent: PathBuf,
    toolchain_root: PathBuf,
    producer_output: PathBuf,
    producer_output_witness: FileWitness,
    producer_receipt: PathBuf,
    producer_receipt_witness: FileWitness,
    request: PathBuf,
    request_witness: FileWitness,
    payload_authority: PathBuf,
    payload_authority_witness: FileWitness,
    engine_witness: FileWitness,
    timeout: Duration,
    cancel_file: PathBuf,
    receipt: PathBuf,
}

impl DirectConfig {
    fn parse(mut arguments: impl Iterator<Item = OsString>) -> Result<Self, DirectError> {
        let staging_parent = exact_path(&mut arguments, "--staging-parent")?;
        let toolchain_root = exact_path(&mut arguments, "--toolchain-root")?;
        let producer_output = exact_path(&mut arguments, "--producer-output")?;
        let producer_output_witness = FileWitness {
            digest: exact_digest(&mut arguments, "--producer-output-sha256")?,
            bytes: exact_count(
                &mut arguments,
                "--producer-output-bytes",
                MAX_PRODUCER_OUTPUT_BYTES,
            )?,
        };
        let producer_receipt = exact_path(&mut arguments, "--producer-receipt")?;
        let producer_receipt_witness = FileWitness {
            digest: exact_digest(&mut arguments, "--producer-receipt-sha256")?,
            bytes: exact_count(
                &mut arguments,
                "--producer-receipt-bytes",
                MAX_PRODUCER_RECEIPT_BYTES,
            )?,
        };
        let request = exact_path(&mut arguments, "--request")?;
        let request_witness = FileWitness {
            digest: exact_digest(&mut arguments, "--request-sha256")?,
            bytes: exact_count(&mut arguments, "--request-bytes", MAX_REQUEST_BYTES)?,
        };
        let payload_authority = exact_path(&mut arguments, "--payload-authority")?;
        let payload_authority_witness = FileWitness {
            digest: exact_digest(&mut arguments, "--payload-authority-sha256")?,
            bytes: exact_count(
                &mut arguments,
                "--payload-authority-bytes",
                MAX_LINUX_PAYLOAD_AUTHORITY_BYTES,
            )?,
        };
        let engine_witness = FileWitness {
            digest: exact_digest(&mut arguments, "--engine-sha256")?,
            bytes: exact_count(&mut arguments, "--engine-bytes", MAX_ENGINE_BYTES)?,
        };
        let timeout_ms = exact_count(&mut arguments, "--timeout-ms", MAX_TIMEOUT_MILLISECONDS)?;
        let cancel_file = exact_path(&mut arguments, "--cancel-file")?;
        let receipt = exact_path(&mut arguments, "--receipt")?;
        if arguments.next().is_some() {
            return Err(DirectError::Usage);
        }
        Ok(Self {
            staging_parent,
            toolchain_root,
            producer_output,
            producer_output_witness,
            producer_receipt,
            producer_receipt_witness,
            request,
            request_witness,
            payload_authority,
            payload_authority_witness,
            engine_witness,
            timeout: Duration::from_millis(timeout_ms),
            cancel_file,
            receipt,
        })
    }
}

fn exact_path(
    arguments: &mut impl Iterator<Item = OsString>,
    expected: &'static str,
) -> Result<PathBuf, DirectError> {
    if arguments.next().as_deref() != Some(OsStr::new(expected)) {
        return Err(DirectError::Usage);
    }
    arguments
        .next()
        .map(PathBuf::from)
        .ok_or(DirectError::InvalidArgument(expected))
}

fn exact_digest(
    arguments: &mut impl Iterator<Item = OsString>,
    expected: &'static str,
) -> Result<Sha256Digest, DirectError> {
    if arguments.next().as_deref() != Some(OsStr::new(expected)) {
        return Err(DirectError::Usage);
    }
    let value = arguments
        .next()
        .ok_or(DirectError::InvalidArgument(expected))?;
    parse_digest(&value).ok_or(DirectError::InvalidArgument(expected))
}

fn exact_count(
    arguments: &mut impl Iterator<Item = OsString>,
    expected: &'static str,
    maximum: u64,
) -> Result<u64, DirectError> {
    if arguments.next().as_deref() != Some(OsStr::new(expected)) {
        return Err(DirectError::Usage);
    }
    let value = arguments
        .next()
        .and_then(|value| value.to_str().map(str::to_owned))
        .ok_or(DirectError::InvalidArgument(expected))?;
    if value.is_empty() || value.starts_with('0') && value != "0" {
        return Err(DirectError::InvalidArgument(expected));
    }
    let count = value
        .parse::<u64>()
        .ok()
        .filter(|count| *count > 0 && *count <= maximum)
        .ok_or(DirectError::InvalidArgument(expected))?;
    Ok(count)
}

fn parse_digest(value: &OsStr) -> Option<Sha256Digest> {
    let bytes = value.to_str()?.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut digest = [0u8; 32];
    for (index, pair) in bytes.chunks_exact(2).enumerate() {
        digest[index] = (lowercase_hex_nibble(pair[0])? << 4) | lowercase_hex_nibble(pair[1])?;
    }
    (!digest.iter().all(|byte| *byte == 0)).then_some(Sha256Digest::from_bytes(digest))
}

const fn lowercase_hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// Execute the exact `direct` argument tail. This function never bypasses the
/// AArch64 Linux-musl ABI check; the emitted candidate claims only the narrow
/// sealed payload-authority binding, not authenticated execution or runner
/// authority.
pub fn run_direct(arguments: impl Iterator<Item = OsString>) -> Result<(), DirectError> {
    if !cfg!(all(
        target_os = "linux",
        target_arch = "aarch64",
        target_env = "musl"
    )) {
        return Err(DirectError::UnsupportedHost);
    }
    let config = DirectConfig::parse(arguments)?;
    execute_direct(&config)
}

fn execute_direct(config: &DirectConfig) -> Result<(), DirectError> {
    validate_directory(&config.staging_parent, "--staging-parent")?;
    validate_directory(&config.toolchain_root, "--toolchain-root")?;
    if config.staging_parent.starts_with(&config.toolchain_root)
        || config.toolchain_root.starts_with(&config.staging_parent)
    {
        return Err(DirectError::InvalidArgument("disjoint roots"));
    }
    validate_normalized_absolute(&config.payload_authority, "--payload-authority")?;
    if config.payload_authority.starts_with(&config.toolchain_root)
        || config.payload_authority.starts_with(&config.staging_parent)
    {
        return Err(DirectError::InvalidArgument("payload authority placement"));
    }
    validate_leaf_path(&config.cancel_file, "--cancel-file")?;
    validate_leaf_path(&config.receipt, "--receipt")?;
    validate_receipt_name(&config.receipt)?;
    if config.cancel_file.parent() != Some(config.staging_parent.as_path())
        || config.receipt.parent() != Some(config.staging_parent.as_path())
        || config.receipt == config.cancel_file
    {
        return Err(DirectError::InvalidArgument("direct control paths"));
    }
    require_absent(&config.cancel_file, "--cancel-file")?;
    require_absent(&config.receipt, "--receipt")?;
    let is_cancelled = || cancellation_requested(&config.cancel_file);

    let producer_output = read_measured_cancellable(
        &config.producer_output,
        config.producer_output_witness,
        MAX_PRODUCER_OUTPUT_BYTES,
        "producer output",
        &is_cancelled,
    )?;
    drop(producer_output);
    let producer_receipt = read_measured_cancellable(
        &config.producer_receipt,
        config.producer_receipt_witness,
        MAX_PRODUCER_RECEIPT_BYTES,
        "producer receipt",
        &is_cancelled,
    )?;
    drop(producer_receipt);
    let request_bytes = read_measured_cancellable(
        &config.request,
        config.request_witness,
        MAX_REQUEST_BYTES,
        "request",
        &is_cancelled,
    )?;
    let (request, hello) = validate_request(&request_bytes)?;
    let authority_bytes = read_measured_cancellable(
        &config.payload_authority,
        config.payload_authority_witness,
        MAX_LINUX_PAYLOAD_AUTHORITY_BYTES,
        "payload authority",
        &is_cancelled,
    )?;
    let (linux_payload_authority, payload_authority_identity) = validate_payload_authority(
        &authority_bytes,
        request.payload_identity,
        config.engine_witness,
    )?;

    let executable = std::env::current_exe().map_err(|error| DirectError::Io {
        operation: "process-image discovery",
        kind: error.kind(),
    })?;
    let engine_bytes = read_measured_cancellable(
        &executable,
        config.engine_witness,
        MAX_ENGINE_BYTES,
        "engine",
        &is_cancelled,
    )?;
    drop(engine_bytes);
    if request.engine_identity != config.engine_witness.digest {
        return Err(DirectError::IdentityMismatch("request engine"));
    }
    if hello.launcher_identity != config.engine_witness.digest {
        return Err(DirectError::IdentityMismatch("request launcher"));
    }

    let mut child = Command::new(&executable);
    child
        .args(one_shot_arguments(config, hello, &request))
        .current_dir(&config.staging_parent)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = run_bounded_child(child, request_bytes, config.timeout, &config.cancel_file)?;
    if !output.status.success() {
        return Err(DirectError::ChildFailure);
    }
    if !output.stderr.is_empty() {
        return Err(DirectError::ChildDiagnostic);
    }
    let (terminal, output_tree) = validate_response(&request, hello, &output.stdout)?;

    // Re-observe every authority immediately before publication. The child
    // also remeasures its own image, closing the executable substitution gap.
    remeasure_cancellable(
        &config.producer_output,
        config.producer_output_witness,
        MAX_PRODUCER_OUTPUT_BYTES,
        "producer output",
        &is_cancelled,
    )?;
    remeasure_cancellable(
        &config.producer_receipt,
        config.producer_receipt_witness,
        MAX_PRODUCER_RECEIPT_BYTES,
        "producer receipt",
        &is_cancelled,
    )?;
    remeasure_cancellable(
        &config.request,
        config.request_witness,
        MAX_REQUEST_BYTES,
        "request",
        &is_cancelled,
    )?;
    remeasure_cancellable(
        &config.payload_authority,
        config.payload_authority_witness,
        MAX_LINUX_PAYLOAD_AUTHORITY_BYTES,
        "payload authority",
        &is_cancelled,
    )?;
    remeasure_cancellable(
        &executable,
        config.engine_witness,
        MAX_ENGINE_BYTES,
        "engine",
        &is_cancelled,
    )?;
    if cancellation_requested(&config.cancel_file)? {
        return Err(DirectError::Cancelled);
    }

    let response_witness = FileWitness {
        digest: sha256(&output.stdout, &|| false)?,
        bytes: output.stdout.len() as u64,
    };
    let receipt = DirectExecutionReceipt {
        producer_output: config.producer_output_witness,
        producer_receipt: config.producer_receipt_witness,
        request: config.request_witness,
        payload_authority: config.payload_authority_witness,
        linux_payload_authority,
        engine: config.engine_witness,
        response: response_witness,
        request_identity: request.identity(),
        launcher_identity: hello.launcher_identity,
        payload_identity: request.payload_identity,
        payload_authority_identity,
        timeout_ms: u64::try_from(config.timeout.as_millis())
            .map_err(|_| DirectError::InvalidArgument("--timeout-ms"))?,
        output_tree,
        terminal,
    };
    // A receipt must never survive a failure to deliver the validated response
    // to this direct caller. Receipt publication is therefore the final step.
    let stdout = io::stdout();
    let mut published_response = stdout.lock();
    published_response
        .write_all(&output.stdout)
        .and_then(|()| published_response.flush())
        .map_err(|error| DirectError::Io {
            operation: "validated response publication",
            kind: error.kind(),
        })?;
    publish_create_new(&config.receipt, &receipt)
}

fn validate_payload_authority(
    bytes: &[u8],
    request_payload_identity: Sha256Digest,
    engine: FileWitness,
) -> Result<(LinuxPayloadAuthority, Sha256Digest), DirectError> {
    let authority =
        LinuxPayloadAuthority::decode_canonical(bytes, MAX_LINUX_PAYLOAD_AUTHORITY_BYTES, &|| {
            false
        })
        .map_err(|_| DirectError::IdentityMismatch("payload authority"))?;
    let identity = authority.payload_identity();
    if request_payload_identity != identity {
        return Err(DirectError::IdentityMismatch("request payload authority"));
    }
    if authority.frontend_engine()
        != (LinuxPayloadFileWitness {
            digest: engine.digest,
            bytes: engine.bytes,
        })
    {
        return Err(DirectError::IdentityMismatch("payload frontend engine"));
    }
    Ok((authority, identity))
}

fn one_shot_arguments(
    config: &DirectConfig,
    hello: ClientHello,
    request: &CheckRequest,
) -> Vec<OsString> {
    vec![
        OsString::from("direct-child"),
        OsString::from("--payload-authority"),
        config.payload_authority.as_os_str().to_owned(),
        OsString::from("--payload-authority-sha256"),
        OsString::from(config.payload_authority_witness.digest.to_hex()),
        OsString::from("--payload-authority-bytes"),
        OsString::from(config.payload_authority_witness.bytes.to_string()),
        OsString::from("--engine-bytes"),
        OsString::from(config.engine_witness.bytes.to_string()),
        OsString::from("--staging-parent"),
        config.staging_parent.as_os_str().to_owned(),
        OsString::from("--toolchain-root"),
        config.toolchain_root.as_os_str().to_owned(),
        OsString::from("--launcher-sha256"),
        OsString::from(hello.launcher_identity.to_hex()),
        OsString::from("--engine-sha256"),
        OsString::from(request.engine_identity.to_hex()),
        OsString::from("--payload-sha256"),
        OsString::from(request.payload_identity.to_hex()),
    ]
}

fn validate_request(bytes: &[u8]) -> Result<(CheckRequest, ClientHello), DirectError> {
    let limits = EngineProtocolLimits::standard();
    let frames = split_frames(bytes, limits)?;
    if frames.len() < 2 {
        return Err(DirectError::Protocol(EngineProtocolError::Truncated));
    }
    let first = decode_frame(frames[0], limits, &|| false)?;
    let hello = match first.message {
        EngineMessage::ClientHello(hello) => hello,
        _ => {
            return Err(DirectError::Protocol(
                EngineProtocolError::UnexpectedMessage {
                    expected: "ClientHello",
                    actual: "another message",
                },
            ));
        }
    };
    let second = decode_frame(frames[1], limits, &|| false)?;
    let request = match second.message {
        EngineMessage::RequestHeader(request) => *request,
        _ => {
            return Err(DirectError::Protocol(
                EngineProtocolError::UnexpectedMessage {
                    expected: "RequestHeader",
                    actual: "another message",
                },
            ));
        }
    };
    let mut validator = CheckRequestStream::new(
        hello.launcher_identity,
        request.engine_identity,
        request.payload_identity,
        limits,
    )?;
    let mut progress = RequestStreamProgress::Pending;
    for frame in frames {
        progress = validator.accept(frame, &|| false)?;
    }
    if !matches!(
        progress,
        RequestStreamProgress::Complete | RequestStreamProgress::Cancelled
    ) {
        return Err(DirectError::Protocol(EngineProtocolError::Truncated));
    }
    Ok((request, hello))
}

fn validate_response(
    request: &CheckRequest,
    hello: ClientHello,
    bytes: &[u8],
) -> Result<(EngineTerminal, TreeMeasurement), DirectError> {
    let limits = EngineProtocolLimits::standard();
    let frames = split_frames(bytes, limits)?;
    let mut validator = CheckResponseStream::new(request, hello, limits, &|| false)?;
    let mut progress = ResponseStreamProgress::Pending;
    let mut output_tree = None;
    let mut payload_authority = PayloadAuthorityProgress::Pending;
    for frame in frames {
        let accepted = validator.accept_validated(frame, &|| false)?;
        progress = accepted.progress();
        match accepted.into_action() {
            ValidatedResponseAction::Event(event) => payload_authority.observe(&event)?,
            ValidatedResponseAction::OutputFinished(measurement)
                if output_tree.replace(measurement).is_some() =>
            {
                return Err(DirectError::Protocol(
                    EngineProtocolError::UnexpectedMessage {
                        expected: "one OutputFinish",
                        actual: "duplicate OutputFinish",
                    },
                ));
            }
            _ => {}
        }
    }
    if progress != ResponseStreamProgress::Complete || !validator.is_complete() {
        return Err(DirectError::Protocol(EngineProtocolError::Truncated));
    }
    let terminal = validator
        .terminal()
        .cloned()
        .ok_or(DirectError::Protocol(EngineProtocolError::Truncated))?;
    let output_tree = output_tree.ok_or(DirectError::Protocol(EngineProtocolError::Truncated))?;
    if payload_authority != PayloadAuthorityProgress::Finished {
        return Err(DirectError::PayloadAuthorityNotProven);
    }
    Ok((terminal, output_tree))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PayloadAuthorityProgress {
    Pending,
    Started,
    Finished,
}

impl PayloadAuthorityProgress {
    fn observe(&mut self, event: &EngineEvent) -> Result<(), DirectError> {
        match event {
            EngineEvent::PhaseStarted { phase } if phase == "toolchain-verification" => {
                if *self != Self::Pending {
                    return Err(DirectError::PayloadAuthorityNotProven);
                }
                *self = Self::Started;
            }
            EngineEvent::PhaseFinished { phase, reused } if phase == "toolchain-verification" => {
                if *self != Self::Started || *reused {
                    return Err(DirectError::PayloadAuthorityNotProven);
                }
                *self = Self::Finished;
            }
            _ => {}
        }
        Ok(())
    }
}

fn split_frames(bytes: &[u8], limits: EngineProtocolLimits) -> Result<Vec<&[u8]>, DirectError> {
    let mut remaining = bytes;
    let mut frames = Vec::new();
    while !remaining.is_empty() {
        if remaining.len() < ENGINE_FRAME_HEADER_BYTES {
            return Err(DirectError::Protocol(EngineProtocolError::Truncated));
        }
        let header =
            decode_frame_header(&remaining[..ENGINE_FRAME_HEADER_BYTES], limits, &|| false)?;
        let length = usize::try_from(header.encoded_frame_bytes())
            .map_err(|_| DirectError::Allocation("frame length"))?;
        if remaining.len() < length {
            return Err(DirectError::Protocol(EngineProtocolError::Truncated));
        }
        frames
            .try_reserve(1)
            .map_err(|_| DirectError::Allocation("frame index"))?;
        frames.push(&remaining[..length]);
        remaining = &remaining[length..];
        if frames.len() as u64 > limits.frames {
            return Err(DirectError::Protocol(EngineProtocolError::ResourceLimit {
                resource: "frames",
                limit: limits.frames,
            }));
        }
    }
    Ok(frames)
}

#[derive(Debug)]
struct ChildOutput {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run_bounded_child(
    mut command: Command,
    input: Vec<u8>,
    timeout: Duration,
    cancel_file: &Path,
) -> Result<ChildOutput, DirectError> {
    let mut child = command.spawn().map_err(|error| DirectError::Io {
        operation: "child spawn",
        kind: error.kind(),
    })?;
    let mut writer = None;
    let mut stdout_reader = None;
    let mut stderr_reader = None;
    let stdin = match child.stdin.take() {
        Some(stdin) => stdin,
        None => {
            return fail_after_spawn(
                &mut child,
                &mut writer,
                &mut stdout_reader,
                &mut stderr_reader,
                DirectError::ChildFailure,
            );
        }
    };
    let stdout = match child.stdout.take() {
        Some(stdout) => stdout,
        None => {
            return fail_after_spawn(
                &mut child,
                &mut writer,
                &mut stdout_reader,
                &mut stderr_reader,
                DirectError::ChildFailure,
            );
        }
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            return fail_after_spawn(
                &mut child,
                &mut writer,
                &mut stdout_reader,
                &mut stderr_reader,
                DirectError::ChildFailure,
            );
        }
    };
    let write_failed = Arc::new(AtomicBool::new(false));
    let writer_failed = Arc::clone(&write_failed);
    writer = Some(
        match thread::Builder::new()
            .name("wrela-direct-request".to_owned())
            .spawn(move || {
                let mut stdin = stdin;
                if stdin
                    .write_all(&input)
                    .and_then(|()| stdin.flush())
                    .is_err()
                {
                    writer_failed.store(true, Ordering::Release);
                }
            }) {
            Ok(writer) => writer,
            Err(error) => {
                return fail_after_spawn(
                    &mut child,
                    &mut writer,
                    &mut stdout_reader,
                    &mut stderr_reader,
                    DirectError::Io {
                        operation: "request writer spawn",
                        kind: error.kind(),
                    },
                );
            }
        },
    );
    let stdout_overflow = Arc::new(AtomicBool::new(false));
    let stderr_overflow = Arc::new(AtomicBool::new(false));
    stdout_reader = Some(
        match spawn_reader(
            "wrela-direct-stdout",
            stdout,
            MAX_RESPONSE_BYTES,
            Arc::clone(&stdout_overflow),
        ) {
            Ok(reader) => reader,
            Err(error) => {
                return fail_after_spawn(
                    &mut child,
                    &mut writer,
                    &mut stdout_reader,
                    &mut stderr_reader,
                    error,
                );
            }
        },
    );
    stderr_reader = Some(
        match spawn_reader(
            "wrela-direct-stderr",
            stderr,
            MAX_STDERR_BYTES,
            Arc::clone(&stderr_overflow),
        ) {
            Ok(reader) => reader,
            Err(error) => {
                return fail_after_spawn(
                    &mut child,
                    &mut writer,
                    &mut stdout_reader,
                    &mut stderr_reader,
                    error,
                );
            }
        },
    );

    let started = Instant::now();
    let status = loop {
        match cancellation_requested(cancel_file) {
            Ok(true) => {
                return fail_after_spawn(
                    &mut child,
                    &mut writer,
                    &mut stdout_reader,
                    &mut stderr_reader,
                    DirectError::Cancelled,
                );
            }
            Ok(false) => {}
            Err(error) => {
                return fail_after_spawn(
                    &mut child,
                    &mut writer,
                    &mut stdout_reader,
                    &mut stderr_reader,
                    error,
                );
            }
        }
        if stdout_overflow.load(Ordering::Acquire) || stderr_overflow.load(Ordering::Acquire) {
            let stream = if stdout_overflow.load(Ordering::Acquire) {
                "stdout"
            } else {
                "stderr"
            };
            return fail_after_spawn(
                &mut child,
                &mut writer,
                &mut stdout_reader,
                &mut stderr_reader,
                DirectError::OutputLimit(stream),
            );
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                return fail_after_spawn(
                    &mut child,
                    &mut writer,
                    &mut stdout_reader,
                    &mut stderr_reader,
                    DirectError::Io {
                        operation: "child wait",
                        kind: error.kind(),
                    },
                );
            }
        }
        if started.elapsed() >= timeout {
            return fail_after_spawn(
                &mut child,
                &mut writer,
                &mut stdout_reader,
                &mut stderr_reader,
                DirectError::TimedOut,
            );
        }
        thread::sleep(POLL_INTERVAL.min(timeout.saturating_sub(started.elapsed())));
    };
    let writer_result = writer.take().expect("writer is installed").join();
    let stdout_result = stdout_reader
        .take()
        .expect("stdout reader is installed")
        .join();
    let stderr_result = stderr_reader
        .take()
        .expect("stderr reader is installed")
        .join();
    if writer_result.is_err() {
        return Err(DirectError::ChildFailure);
    }
    let stdout = finish_reader(stdout_result)?;
    let stderr = finish_reader(stderr_result)?;
    if write_failed.load(Ordering::Acquire) {
        return Err(DirectError::ChildFailure);
    }
    if stdout_overflow.load(Ordering::Acquire) {
        return Err(DirectError::OutputLimit("stdout"));
    }
    if stderr_overflow.load(Ordering::Acquire) {
        return Err(DirectError::OutputLimit("stderr"));
    }
    Ok(ChildOutput {
        status,
        stdout,
        stderr,
    })
}

fn spawn_reader<R: Read + Send + 'static>(
    name: &str,
    mut reader: R,
    limit: u64,
    overflow: Arc<AtomicBool>,
) -> Result<thread::JoinHandle<io::Result<Vec<u8>>>, DirectError> {
    thread::Builder::new()
        .name(name.to_owned())
        .spawn(move || {
            let mut output = Vec::new();
            let mut buffer = [0u8; 16 * 1024];
            loop {
                let read = reader.read(&mut buffer)?;
                if read == 0 {
                    return Ok(output);
                }
                let next = (output.len() as u64).checked_add(read as u64);
                if next.is_none_or(|next| next > limit) {
                    overflow.store(true, Ordering::Release);
                    return Ok(output);
                }
                output.try_reserve_exact(read).map_err(io::Error::other)?;
                output.extend_from_slice(&buffer[..read]);
            }
        })
        .map_err(|error| DirectError::Io {
            operation: "output reader spawn",
            kind: error.kind(),
        })
}

type ReaderHandle = thread::JoinHandle<io::Result<Vec<u8>>>;

fn finish_reader(result: thread::Result<io::Result<Vec<u8>>>) -> Result<Vec<u8>, DirectError> {
    result
        .map_err(|_| DirectError::ChildFailure)?
        .map_err(|error| DirectError::Io {
            operation: "child output read",
            kind: error.kind(),
        })
}

fn fail_after_spawn<T>(
    child: &mut Child,
    writer: &mut Option<thread::JoinHandle<()>>,
    stdout: &mut Option<ReaderHandle>,
    stderr: &mut Option<ReaderHandle>,
    error: DirectError,
) -> Result<T, DirectError> {
    let termination = kill_and_reap(child);
    if let Some(writer) = writer.take() {
        let _ = writer.join();
    }
    if let Some(stdout) = stdout.take() {
        let _ = stdout.join();
    }
    if let Some(stderr) = stderr.take() {
        let _ = stderr.join();
    }
    termination.map(|_| ())?;
    Err(error)
}

fn kill_and_reap(child: &mut Child) -> Result<ExitStatus, DirectError> {
    // Always attempt both operations. A kill can race with natural exit, but
    // wait is still required to reap the child and unblock every pipe thread.
    let _ = child.kill();
    child.wait().map_err(|error| DirectError::Io {
        operation: "child reap",
        kind: error.kind(),
    })
}

fn cancellation_requested(path: &Path) -> Result<bool, DirectError> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len() == 0 =>
        {
            Ok(true)
        }
        Ok(_) => Err(DirectError::InvalidArgument("--cancel-file")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(DirectError::Io {
            operation: "cancellation observation",
            kind: error.kind(),
        }),
    }
}

fn validate_directory(path: &Path, name: &'static str) -> Result<(), DirectError> {
    validate_normalized_absolute(path, name)?;
    let canonical = fs::canonicalize(path).map_err(|error| DirectError::Io {
        operation: "directory canonicalization",
        kind: error.kind(),
    })?;
    let metadata = fs::symlink_metadata(path).map_err(|error| DirectError::Io {
        operation: "directory metadata observation",
        kind: error.kind(),
    })?;
    if canonical != path || !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(DirectError::InvalidArgument(name));
    }
    Ok(())
}

fn validate_leaf_path(path: &Path, name: &'static str) -> Result<(), DirectError> {
    validate_normalized_absolute(path, name)?;
    let parent = path.parent().ok_or(DirectError::InvalidArgument(name))?;
    validate_directory(parent, name)
}

fn validate_receipt_name(path: &Path) -> Result<(), DirectError> {
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or(DirectError::InvalidArgument("--receipt"))?;
    if name.is_empty()
        || name.len() > 128
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(DirectError::InvalidArgument("--receipt"));
    }
    Ok(())
}

fn validate_normalized_absolute(path: &Path, name: &'static str) -> Result<(), DirectError> {
    if path.as_os_str().as_encoded_bytes().is_empty()
        || path.as_os_str().as_encoded_bytes().len() > MAX_HOST_PATH_BYTES
        || !path.is_absolute()
        || !path.components().all(|component| {
            matches!(
                component,
                Component::Prefix(_) | Component::RootDir | Component::Normal(_)
            )
        })
        || path.components().collect::<PathBuf>() != path
    {
        return Err(DirectError::InvalidArgument(name));
    }
    Ok(())
}

fn require_absent(path: &Path, name: &'static str) -> Result<(), DirectError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(DirectError::InvalidArgument(name)),
        Err(error) => Err(DirectError::Io {
            operation: "destination absence observation",
            kind: error.kind(),
        }),
    }
}

fn read_measured(
    path: &Path,
    expected: FileWitness,
    maximum: u64,
    name: &'static str,
) -> Result<Vec<u8>, DirectError> {
    read_measured_cancellable(path, expected, maximum, name, &|| Ok(false))
}

fn read_measured_cancellable(
    path: &Path,
    expected: FileWitness,
    maximum: u64,
    name: &'static str,
    is_cancelled: &dyn Fn() -> Result<bool, DirectError>,
) -> Result<Vec<u8>, DirectError> {
    check_direct_cancelled(is_cancelled)?;
    validate_normalized_absolute(path, name)?;
    let canonical = fs::canonicalize(path).map_err(|error| DirectError::Io {
        operation: "input canonicalization",
        kind: error.kind(),
    })?;
    let before = fs::symlink_metadata(path).map_err(|error| DirectError::Io {
        operation: "input metadata observation",
        kind: error.kind(),
    })?;
    if canonical != path
        || !before.is_file()
        || before.file_type().is_symlink()
        || before.len() == 0
        || before.len() > maximum
        || before.len() != expected.bytes
    {
        return Err(DirectError::IdentityMismatch(name));
    }
    check_direct_cancelled(is_cancelled)?;
    let mut file = File::open(path).map_err(|error| DirectError::Io {
        operation: "input open",
        kind: error.kind(),
    })?;
    let opened = file.metadata().map_err(|error| DirectError::Io {
        operation: "opened input metadata observation",
        kind: error.kind(),
    })?;
    if !same_file_observation(&before, &opened) {
        return Err(DirectError::IdentityMismatch(name));
    }
    let length = usize::try_from(expected.bytes).map_err(|_| DirectError::Allocation(name))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| DirectError::Allocation(name))?;
    bytes.resize(length, 0);
    let mut offset = 0_usize;
    while offset < length {
        check_direct_cancelled(is_cancelled)?;
        let end = offset.saturating_add(64 * 1024).min(length);
        let read = file
            .read(&mut bytes[offset..end])
            .map_err(|error| DirectError::Io {
                operation: "input read",
                kind: error.kind(),
            })?;
        if read == 0 {
            return Err(DirectError::IdentityMismatch(name));
        }
        offset = offset.saturating_add(read);
    }
    check_direct_cancelled(is_cancelled)?;
    let mut trailing = [0_u8; 1];
    let trailing = file.read(&mut trailing).map_err(|error| DirectError::Io {
        operation: "input read",
        kind: error.kind(),
    })?;
    let after_open = file.metadata().map_err(|error| DirectError::Io {
        operation: "opened input final observation",
        kind: error.kind(),
    })?;
    let after_path = fs::symlink_metadata(path).map_err(|error| DirectError::Io {
        operation: "input final observation",
        kind: error.kind(),
    })?;
    let callback_error = RefCell::new(None);
    let digest = sha256(&bytes, &|| match is_cancelled() {
        Ok(cancelled) => cancelled,
        Err(error) => {
            *callback_error.borrow_mut() = Some(error);
            true
        }
    });
    if let Some(error) = callback_error.into_inner() {
        return Err(error);
    }
    let digest = match digest {
        Ok(digest) => digest,
        Err(EngineProtocolError::Cancelled) => return Err(DirectError::Cancelled),
        Err(error) => return Err(DirectError::Protocol(error)),
    };
    if trailing != 0
        || bytes.len() != length
        || !same_file_observation(&before, &after_open)
        || !same_file_observation(&before, &after_path)
        || digest != expected.digest
    {
        return Err(DirectError::IdentityMismatch(name));
    }
    check_direct_cancelled(is_cancelled)?;
    Ok(bytes)
}

fn remeasure_cancellable(
    path: &Path,
    expected: FileWitness,
    maximum: u64,
    name: &'static str,
    is_cancelled: &dyn Fn() -> Result<bool, DirectError>,
) -> Result<(), DirectError> {
    drop(read_measured_cancellable(
        path,
        expected,
        maximum,
        name,
        is_cancelled,
    )?);
    Ok(())
}

fn check_direct_cancelled(
    is_cancelled: &dyn Fn() -> Result<bool, DirectError>,
) -> Result<(), DirectError> {
    if is_cancelled()? {
        Err(DirectError::Cancelled)
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn same_file_observation(left: &Metadata, right: &Metadata) -> bool {
    left.is_file()
        && right.is_file()
        && left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

#[cfg(not(unix))]
fn same_file_observation(left: &Metadata, right: &Metadata) -> bool {
    left.is_file()
        && right.is_file()
        && left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
}

/// Canonical path-free evidence emitted only after a complete validated direct
/// response and zero child exit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectExecutionReceipt {
    producer_output: FileWitness,
    producer_receipt: FileWitness,
    request: FileWitness,
    payload_authority: FileWitness,
    linux_payload_authority: LinuxPayloadAuthority,
    engine: FileWitness,
    response: FileWitness,
    request_identity: Sha256Digest,
    launcher_identity: Sha256Digest,
    payload_identity: Sha256Digest,
    payload_authority_identity: Sha256Digest,
    timeout_ms: u64,
    output_tree: TreeMeasurement,
    terminal: EngineTerminal,
}

impl DirectExecutionReceipt {
    /// Exact schema-2 encoding. No host path, clock, locale, PID, or unordered
    /// collection contributes to these bytes.
    #[must_use]
    pub fn encode_canonical(&self) -> Vec<u8> {
        format!(
            concat!(
                "schema=2\n",
                "route=linux-arm64-direct\n",
                "host=aarch64-unknown-linux-musl\n",
                "engine_protocol={}\n",
                "receipt_kind=candidate\n",
                "execution_proven=false\n",
                "payload_authority_proven=true\n",
                "runner_authority_proven=false\n",
                "timeout_ms={}\n",
                "producer_output_sha256={}\n",
                "producer_output_bytes={}\n",
                "producer_receipt_sha256={}\n",
                "producer_receipt_bytes={}\n",
                "request_sha256={}\n",
                "request_bytes={}\n",
                "payload_authority_sha256={}\n",
                "payload_authority_bytes={}\n",
                "payload_manifest_sha256={}\n",
                "payload_manifest_bytes={}\n",
                "payload_frontend_sha256={}\n",
                "payload_frontend_bytes={}\n",
                "engine_sha256={}\n",
                "engine_bytes={}\n",
                "response_sha256={}\n",
                "response_bytes={}\n",
                "request_identity={}\n",
                "launcher_identity={}\n",
                "payload_identity={}\n",
                "payload_authority_identity={}\n",
                "output_tree_sha256={}\n",
                "output_records={}\n",
                "output_path_bytes={}\n",
                "output_content_bytes={}\n",
                "report_identity={}\n",
                "terminal_status={}\n",
                "diagnostic_count={}\n",
                "input_bytes={}\n",
                "output_bytes={}\n",
                "events={}\n",
                "event_bytes={}\n",
                "comptime_steps={}\n",
                "comptime_peak_memory_bytes={}\n",
                "comptime_peak_call_depth={}\n",
                "exit_code=0\n"
            ),
            ENGINE_PROTOCOL_VERSION,
            self.timeout_ms,
            self.producer_output.digest.to_hex(),
            self.producer_output.bytes,
            self.producer_receipt.digest.to_hex(),
            self.producer_receipt.bytes,
            self.request.digest.to_hex(),
            self.request.bytes,
            self.payload_authority.digest.to_hex(),
            self.payload_authority.bytes,
            self.linux_payload_authority
                .toolchain_manifest()
                .digest
                .to_hex(),
            self.linux_payload_authority.toolchain_manifest().bytes,
            self.linux_payload_authority
                .frontend_engine()
                .digest
                .to_hex(),
            self.linux_payload_authority.frontend_engine().bytes,
            self.engine.digest.to_hex(),
            self.engine.bytes,
            self.response.digest.to_hex(),
            self.response.bytes,
            self.request_identity.to_hex(),
            self.launcher_identity.to_hex(),
            self.payload_identity.to_hex(),
            self.payload_authority_identity.to_hex(),
            self.output_tree.digest.to_hex(),
            self.output_tree.records,
            self.output_tree.path_bytes,
            self.output_tree.content_bytes,
            self.terminal.report_identity.to_hex(),
            terminal_status_name(self.terminal.status),
            self.terminal.diagnostic_count,
            self.terminal.usage.input_bytes,
            self.terminal.usage.output_bytes,
            self.terminal.usage.events,
            self.terminal.usage.event_bytes,
            optional_usage(self.terminal.usage.comptime, |usage| usage.steps),
            optional_usage(self.terminal.usage.comptime, |usage| usage
                .peak_memory_bytes),
            optional_usage(self.terminal.usage.comptime, |usage| u64::from(
                usage.peak_call_depth
            )),
        )
        .into_bytes()
    }

    /// Decode exactly schema 2 and reject every noncanonical spelling, field
    /// order, unknown field, stale/future schema, and out-of-policy count.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, DirectError> {
        if bytes.is_empty()
            || bytes.len() as u64 > MAX_DIRECT_RECEIPT_BYTES
            || !bytes.ends_with(b"\n")
        {
            return Err(DirectError::InvalidReceipt);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| DirectError::InvalidReceipt)?;
        let mut lines = text.split_terminator('\n');
        expect_receipt_constant(&mut lines, "schema", "2")?;
        expect_receipt_constant(&mut lines, "route", "linux-arm64-direct")?;
        expect_receipt_constant(&mut lines, "host", "aarch64-unknown-linux-musl")?;
        expect_receipt_constant(
            &mut lines,
            "engine_protocol",
            &ENGINE_PROTOCOL_VERSION.to_string(),
        )?;
        expect_receipt_constant(&mut lines, "receipt_kind", "candidate")?;
        expect_receipt_constant(&mut lines, "execution_proven", "false")?;
        expect_receipt_constant(&mut lines, "payload_authority_proven", "true")?;
        expect_receipt_constant(&mut lines, "runner_authority_proven", "false")?;
        let timeout_ms = receipt_count(
            receipt_value(&mut lines, "timeout_ms")?,
            MAX_TIMEOUT_MILLISECONDS,
            false,
        )?;
        let producer_output = receipt_witness(
            &mut lines,
            "producer_output_sha256",
            "producer_output_bytes",
            MAX_PRODUCER_OUTPUT_BYTES,
        )?;
        let producer_receipt = receipt_witness(
            &mut lines,
            "producer_receipt_sha256",
            "producer_receipt_bytes",
            MAX_PRODUCER_RECEIPT_BYTES,
        )?;
        let request = receipt_witness(
            &mut lines,
            "request_sha256",
            "request_bytes",
            MAX_REQUEST_BYTES,
        )?;
        let payload_authority = receipt_witness(
            &mut lines,
            "payload_authority_sha256",
            "payload_authority_bytes",
            MAX_LINUX_PAYLOAD_AUTHORITY_BYTES,
        )?;
        let payload_manifest = receipt_witness(
            &mut lines,
            "payload_manifest_sha256",
            "payload_manifest_bytes",
            wrela_toolchain::ToolchainDecodeLimits::standard().bytes,
        )?;
        let payload_frontend = receipt_witness(
            &mut lines,
            "payload_frontend_sha256",
            "payload_frontend_bytes",
            wrela_toolchain::MAX_LINUX_FRONTEND_ENGINE_BYTES,
        )?;
        let linux_payload_authority = LinuxPayloadAuthority::from_witnesses(
            LinuxPayloadFileWitness {
                digest: payload_manifest.digest,
                bytes: payload_manifest.bytes,
            },
            LinuxPayloadFileWitness {
                digest: payload_frontend.digest,
                bytes: payload_frontend.bytes,
            },
        )
        .map_err(|_| DirectError::InvalidReceipt)?;
        let engine = receipt_witness(
            &mut lines,
            "engine_sha256",
            "engine_bytes",
            MAX_ENGINE_BYTES,
        )?;
        let response = receipt_witness(
            &mut lines,
            "response_sha256",
            "response_bytes",
            MAX_RESPONSE_BYTES,
        )?;
        let request_identity = receipt_digest(&mut lines, "request_identity")?;
        let launcher_identity = receipt_digest(&mut lines, "launcher_identity")?;
        let payload_identity = receipt_digest(&mut lines, "payload_identity")?;
        let payload_authority_identity = receipt_digest(&mut lines, "payload_authority_identity")?;
        let output_tree = TreeMeasurement {
            digest: receipt_digest(&mut lines, "output_tree_sha256")?,
            records: u32::try_from(receipt_count(
                receipt_value(&mut lines, "output_records")?,
                u64::from(EngineProtocolLimits::standard().tree_records),
                true,
            )?)
            .map_err(|_| DirectError::InvalidReceipt)?,
            path_bytes: receipt_count(
                receipt_value(&mut lines, "output_path_bytes")?,
                EngineProtocolLimits::standard().tree_path_bytes,
                true,
            )?,
            content_bytes: receipt_count(
                receipt_value(&mut lines, "output_content_bytes")?,
                EngineProtocolLimits::standard().tree_content_bytes,
                true,
            )?,
        };
        let report_identity = receipt_digest(&mut lines, "report_identity")?;
        let status = receipt_terminal_status(receipt_value(&mut lines, "terminal_status")?)?;
        let diagnostic_count = u32::try_from(receipt_count(
            receipt_value(&mut lines, "diagnostic_count")?,
            u64::from(u32::MAX),
            true,
        )?)
        .map_err(|_| DirectError::InvalidReceipt)?;
        let input_bytes = receipt_count(
            receipt_value(&mut lines, "input_bytes")?,
            EngineProtocolLimits::standard().tree_content_bytes,
            true,
        )?;
        let output_bytes = receipt_count(
            receipt_value(&mut lines, "output_bytes")?,
            EngineProtocolLimits::standard().tree_content_bytes,
            true,
        )?;
        let events = u32::try_from(receipt_count(
            receipt_value(&mut lines, "events")?,
            u64::from(EngineProtocolLimits::standard().events),
            true,
        )?)
        .map_err(|_| DirectError::InvalidReceipt)?;
        let event_bytes = receipt_count(
            receipt_value(&mut lines, "event_bytes")?,
            EngineProtocolLimits::standard().event_bytes,
            true,
        )?;
        let steps = receipt_optional_count(receipt_value(&mut lines, "comptime_steps")?)?;
        let memory =
            receipt_optional_count(receipt_value(&mut lines, "comptime_peak_memory_bytes")?)?;
        let depth = receipt_optional_count(receipt_value(&mut lines, "comptime_peak_call_depth")?)?;
        expect_receipt_constant(&mut lines, "exit_code", "0")?;
        if lines.next().is_some()
            || [steps.is_some(), memory.is_some(), depth.is_some()]
                .iter()
                .any(|present| *present != steps.is_some())
        {
            return Err(DirectError::InvalidReceipt);
        }
        let comptime = match (steps, memory, depth) {
            (Some(steps), Some(peak_memory_bytes), Some(peak_call_depth)) => {
                Some(EngineComptimeUsage {
                    steps,
                    peak_memory_bytes,
                    peak_call_depth: u32::try_from(peak_call_depth)
                        .map_err(|_| DirectError::InvalidReceipt)?,
                })
            }
            (None, None, None) => None,
            _ => return Err(DirectError::InvalidReceipt),
        };
        let receipt = Self {
            producer_output,
            producer_receipt,
            request,
            payload_authority,
            linux_payload_authority,
            engine,
            response,
            request_identity,
            launcher_identity,
            payload_identity,
            payload_authority_identity,
            timeout_ms,
            output_tree,
            terminal: EngineTerminal {
                status,
                diagnostic_count,
                report_identity,
                usage: EngineResourceUsage {
                    input_bytes,
                    output_bytes,
                    events,
                    event_bytes,
                    comptime,
                },
            },
        };
        receipt.validate_semantics()?;
        if receipt.encode_canonical() != bytes {
            return Err(DirectError::InvalidReceipt);
        }
        Ok(receipt)
    }

    fn validate_semantics(&self) -> Result<(), DirectError> {
        let standard = EngineResourcePolicy::check_standard();
        let empty_output = empty_tree_measurement(&|| false).map_err(DirectError::Protocol)?;
        let authority_bytes = self.linux_payload_authority.encode_canonical();
        let authority_witness = FileWitness {
            digest: sha256(&authority_bytes, &|| false).map_err(DirectError::Protocol)?,
            bytes: authority_bytes.len() as u64,
        };
        if self.launcher_identity != self.engine.digest
            || self.payload_identity != self.payload_authority_identity
            || self.payload_authority_identity != self.linux_payload_authority.payload_identity()
            || self.payload_authority != authority_witness
            || self.linux_payload_authority.frontend_engine()
                != (LinuxPayloadFileWitness {
                    digest: self.engine.digest,
                    bytes: self.engine.bytes,
                })
            || self.output_tree != empty_output
            || self.terminal.usage.output_bytes != self.output_tree.content_bytes
            || self.terminal.diagnostic_count > self.terminal.usage.events
            || self.terminal.usage.input_bytes > standard.input_content_bytes
            || self.terminal.usage.events > standard.events
            || self.terminal.usage.event_bytes > standard.event_bytes
            || self.terminal.usage.comptime.is_some_and(|usage| {
                usage.steps > standard.comptime_steps
                    || usage.peak_memory_bytes > standard.comptime_memory_bytes
                    || usage.peak_call_depth > standard.comptime_call_depth
            })
        {
            return Err(DirectError::InvalidReceipt);
        }
        Ok(())
    }
}

fn optional_usage(
    usage: Option<EngineComptimeUsage>,
    select: impl FnOnce(EngineComptimeUsage) -> u64,
) -> String {
    usage
        .map(select)
        .map_or_else(|| "none".to_owned(), |value| value.to_string())
}

fn receipt_value<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    key: &str,
) -> Result<&'a str, DirectError> {
    let line = lines.next().ok_or(DirectError::InvalidReceipt)?;
    line.strip_prefix(key)
        .and_then(|value| value.strip_prefix('='))
        .filter(|_| !key.is_empty())
        .ok_or(DirectError::InvalidReceipt)
}

fn expect_receipt_constant<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    key: &str,
    expected: &str,
) -> Result<(), DirectError> {
    (receipt_value(lines, key)? == expected)
        .then_some(())
        .ok_or(DirectError::InvalidReceipt)
}

fn receipt_digest<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    key: &str,
) -> Result<Sha256Digest, DirectError> {
    parse_digest(OsStr::new(receipt_value(lines, key)?)).ok_or(DirectError::InvalidReceipt)
}

fn receipt_witness<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    digest_key: &str,
    bytes_key: &str,
    maximum: u64,
) -> Result<FileWitness, DirectError> {
    Ok(FileWitness {
        digest: receipt_digest(lines, digest_key)?,
        bytes: receipt_count(receipt_value(lines, bytes_key)?, maximum, false)?,
    })
}

fn receipt_count(value: &str, maximum: u64, allow_zero: bool) -> Result<u64, DirectError> {
    if value.is_empty() || value.starts_with('0') && value != "0" {
        return Err(DirectError::InvalidReceipt);
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|count| *count <= maximum && (allow_zero || *count != 0))
        .ok_or(DirectError::InvalidReceipt)
}

fn receipt_optional_count(value: &str) -> Result<Option<u64>, DirectError> {
    if value == "none" {
        Ok(None)
    } else {
        receipt_count(value, u64::MAX, true).map(Some)
    }
}

fn receipt_terminal_status(value: &str) -> Result<TerminalStatus, DirectError> {
    match value {
        "success" => Ok(TerminalStatus::Success),
        "rejected" => Ok(TerminalStatus::Rejected),
        "cancelled" => Ok(TerminalStatus::Cancelled),
        "resource-limit" => Ok(TerminalStatus::ResourceLimit),
        "internal-failure" => Ok(TerminalStatus::InternalFailure),
        _ => Err(DirectError::InvalidReceipt),
    }
}

const fn terminal_status_name(status: TerminalStatus) -> &'static str {
    match status {
        TerminalStatus::Success => "success",
        TerminalStatus::Rejected => "rejected",
        TerminalStatus::Cancelled => "cancelled",
        TerminalStatus::ResourceLimit => "resource-limit",
        TerminalStatus::InternalFailure => "internal-failure",
    }
}

fn publish_create_new(
    destination: &Path,
    receipt: &DirectExecutionReceipt,
) -> Result<(), DirectError> {
    let bytes = receipt.encode_canonical();
    if bytes.len() as u64 > MAX_DIRECT_RECEIPT_BYTES
        || DirectExecutionReceipt::decode_canonical(&bytes)? != *receipt
    {
        return Err(DirectError::InvalidReceipt);
    }
    let parent = destination
        .parent()
        .ok_or(DirectError::InvalidArgument("--receipt"))?;
    validate_receipt_name(destination)?;
    let mut candidate = None;
    for sequence in 0..64u8 {
        let path = parent.join(receipt_candidate_name(std::process::id(), sequence));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&path) {
            Ok(file) => {
                candidate = Some((path, file));
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(DirectError::Io {
                    operation: "receipt candidate create",
                    kind: error.kind(),
                });
            }
        }
    }
    let (candidate_path, mut file) = candidate.ok_or(DirectError::PublicationExists)?;
    let mut published = false;
    let result = (|| {
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| DirectError::Io {
                operation: "receipt candidate seal",
                kind: error.kind(),
            })?;
        drop(file);
        let candidate_witness = FileWitness {
            digest: sha256(&bytes, &|| false)?,
            bytes: bytes.len() as u64,
        };
        let observed = read_measured(
            &candidate_path,
            candidate_witness,
            MAX_DIRECT_RECEIPT_BYTES,
            "candidate receipt",
        )?;
        if DirectExecutionReceipt::decode_canonical(&observed)? != *receipt {
            return Err(DirectError::InvalidReceipt);
        }
        fs::hard_link(&candidate_path, destination).map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                DirectError::PublicationExists
            } else {
                DirectError::Io {
                    operation: "receipt publication",
                    kind: error.kind(),
                }
            }
        })?;
        published = true;
        fs::remove_file(&candidate_path).map_err(|error| DirectError::Io {
            operation: "receipt candidate cleanup",
            kind: error.kind(),
        })?;
        sync_directory(parent, "receipt publication sync")?;
        let published_bytes = read_measured(
            destination,
            candidate_witness,
            MAX_DIRECT_RECEIPT_BYTES,
            "published receipt",
        )?;
        if DirectExecutionReceipt::decode_canonical(&published_bytes)? != *receipt {
            return Err(DirectError::InvalidReceipt);
        }
        Ok(())
    })();
    match result {
        Ok(()) => Ok(()),
        Err(primary) => {
            cleanup_failed_publication(parent, &candidate_path, destination, published)?;
            Err(primary)
        }
    }
}

fn receipt_candidate_name(process: u32, sequence: u8) -> String {
    format!(".wrela-direct-{process}-{sequence}.tmp")
}

fn cleanup_failed_publication(
    parent: &Path,
    candidate: &Path,
    destination: &Path,
    published: bool,
) -> Result<(), DirectError> {
    let mut failure = None;
    if published {
        remove_cleanup_path(destination, "failed receipt rollback", &mut failure);
    }
    remove_cleanup_path(candidate, "failed receipt candidate cleanup", &mut failure);
    if let Err(error) = sync_directory(parent, "failed receipt cleanup sync") {
        failure.get_or_insert(error);
    }
    failure.map_or(Ok(()), Err)
}

fn remove_cleanup_path(path: &Path, operation: &'static str, failure: &mut Option<DirectError>) {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            failure.get_or_insert(DirectError::Io {
                operation,
                kind: error.kind(),
            });
        }
    }
}

fn sync_directory(parent: &Path, operation: &'static str) -> Result<(), DirectError> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| DirectError::Io {
            operation,
            kind: error.kind(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn digest(label: &[u8]) -> Sha256Digest {
        sha256(label, &|| false).expect("test digest")
    }

    fn receipt() -> DirectExecutionReceipt {
        let engine = FileWitness {
            digest: digest(b"engine"),
            bytes: 14,
        };
        let authority = LinuxPayloadAuthority::from_witnesses(
            LinuxPayloadFileWitness {
                digest: digest(b"manifest"),
                bytes: 4096,
            },
            LinuxPayloadFileWitness {
                digest: engine.digest,
                bytes: engine.bytes,
            },
        )
        .expect("authority");
        let authority_bytes = authority.encode_canonical();
        DirectExecutionReceipt {
            producer_output: FileWitness {
                digest: digest(b"producer-output"),
                bytes: 11,
            },
            producer_receipt: FileWitness {
                digest: digest(b"producer-receipt"),
                bytes: 12,
            },
            request: FileWitness {
                digest: digest(b"request"),
                bytes: 13,
            },
            payload_authority: FileWitness {
                digest: digest(&authority_bytes),
                bytes: authority_bytes.len() as u64,
            },
            linux_payload_authority: authority.clone(),
            engine,
            response: FileWitness {
                digest: digest(b"response"),
                bytes: 15,
            },
            request_identity: digest(b"request-id"),
            launcher_identity: digest(b"engine"),
            payload_identity: authority.payload_identity(),
            payload_authority_identity: authority.payload_identity(),
            timeout_ms: 10_000,
            output_tree: empty_tree_measurement(&|| false).expect("empty tree"),
            terminal: EngineTerminal {
                status: TerminalStatus::Success,
                diagnostic_count: 0,
                report_identity: digest(b"report-id"),
                usage: EngineResourceUsage {
                    input_bytes: 13,
                    output_bytes: 0,
                    events: 0,
                    event_bytes: 0,
                    comptime: None,
                },
            },
        }
    }

    fn authority_bytes(engine: FileWitness) -> Vec<u8> {
        format!(
            concat!(
                "schema=1\n",
                "route=linux-arm64-direct\n",
                "host=aarch64-unknown-linux-musl\n",
                "engine_protocol=1\n",
                "toolchain_manifest_sha256={}\n",
                "toolchain_manifest_bytes=4096\n",
                "frontend_engine_sha256={}\n",
                "frontend_engine_bytes={}\n"
            ),
            digest(b"manifest").to_hex(),
            engine.digest.to_hex(),
            engine.bytes,
        )
        .into_bytes()
    }

    #[test]
    fn direct_authority_binding_rejects_request_and_frontend_substitution() {
        let engine = FileWitness {
            digest: digest(b"engine"),
            bytes: 14,
        };
        let bytes = authority_bytes(engine);
        let authority = LinuxPayloadAuthority::decode_canonical(
            &bytes,
            MAX_LINUX_PAYLOAD_AUTHORITY_BYTES,
            &|| false,
        )
        .expect("authority");
        validate_payload_authority(&bytes, authority.payload_identity(), engine)
            .expect("exact binding");
        assert!(matches!(
            validate_payload_authority(&bytes, digest(b"stale-payload"), engine),
            Err(DirectError::IdentityMismatch("request payload authority"))
        ));
        assert!(matches!(
            validate_payload_authority(
                &bytes,
                authority.payload_identity(),
                FileWitness {
                    digest: digest(b"other-engine"),
                    bytes: engine.bytes,
                },
            ),
            Err(DirectError::IdentityMismatch("payload frontend engine"))
        ));
    }

    #[test]
    fn receipt_authority_requires_exact_toolchain_phase_completion() {
        let started = EngineEvent::PhaseStarted {
            phase: "toolchain-verification".to_owned(),
        };
        let finished = EngineEvent::PhaseFinished {
            phase: "toolchain-verification".to_owned(),
            reused: false,
        };
        let reused = EngineEvent::PhaseFinished {
            phase: "toolchain-verification".to_owned(),
            reused: true,
        };
        let mut progress = PayloadAuthorityProgress::Pending;
        progress.observe(&started).expect("start");
        progress.observe(&finished).expect("finish");
        assert_eq!(progress, PayloadAuthorityProgress::Finished);

        for events in [vec![finished.clone()], vec![started.clone(), reused]] {
            let mut progress = PayloadAuthorityProgress::Pending;
            assert!(
                events
                    .iter()
                    .try_for_each(|event| progress.observe(event))
                    .is_err()
            );
            assert_ne!(progress, PayloadAuthorityProgress::Finished);
        }
        let mut duplicate = PayloadAuthorityProgress::Pending;
        duplicate.observe(&started).expect("first start");
        assert!(duplicate.observe(&started).is_err());
    }

    #[test]
    fn receipt_is_path_free_fixed_order_and_deterministic() {
        let first = receipt().encode_canonical();
        let second = receipt().encode_canonical();
        assert_eq!(first, second);
        let text = String::from_utf8(first).expect("receipt UTF-8");
        assert!(
            text.starts_with(
                "schema=2\nroute=linux-arm64-direct\nhost=aarch64-unknown-linux-musl\n"
            )
        );
        assert!(text.ends_with("exit_code=0\n"));
        assert!(text.contains("execution_proven=false\n"));
        assert!(text.contains("payload_authority_proven=true\n"));
        assert!(text.contains("runner_authority_proven=false\n"));
        assert!(!text.contains('/') && !text.contains("pid") && !text.contains("clock"));
        assert_eq!(
            DirectExecutionReceipt::decode_canonical(text.as_bytes()).expect("canonical receipt"),
            receipt()
        );
    }

    #[test]
    fn receipt_decoder_rejects_stale_reordered_unknown_and_noncanonical_counts() {
        let bytes = receipt().encode_canonical();
        let text = String::from_utf8(bytes).expect("receipt UTF-8");
        let substituted_launcher = digest(b"other-launcher").to_hex();
        for malformed in [
            text.replacen("schema=2", "schema=1", 1),
            text.replacen(
                "route=linux-arm64-direct\nhost=aarch64-unknown-linux-musl",
                "host=aarch64-unknown-linux-musl\nroute=linux-arm64-direct",
                1,
            ),
            text.replacen(
                "receipt_kind=candidate",
                "unknown=value\nreceipt_kind=candidate",
                1,
            ),
            text.replacen("timeout_ms=10000", "timeout_ms=010000", 1),
            text.replacen("execution_proven=false", "execution_proven=true", 1),
            text.replacen(
                "payload_authority_proven=true",
                "payload_authority_proven=false",
                1,
            ),
            text.replacen(
                "payload_manifest_bytes=4096",
                "payload_manifest_bytes=4097",
                1,
            ),
            text.replacen(
                &format!("launcher_identity={}", digest(b"engine").to_hex()),
                &format!("launcher_identity={substituted_launcher}"),
                1,
            ),
            text.replacen("output_records=0", "output_records=1", 1),
            text.replacen("diagnostic_count=0", "diagnostic_count=1", 1),
        ] {
            assert!(matches!(
                DirectExecutionReceipt::decode_canonical(malformed.as_bytes()),
                Err(DirectError::InvalidReceipt)
            ));
        }
    }

    #[test]
    fn exact_argv_rejects_reordering_uppercase_digest_and_noncanonical_counts() {
        let root = PathBuf::from("/tmp/direct");
        let d = digest(b"d").to_hex();
        let valid = vec![
            "--staging-parent".into(),
            root.clone().into_os_string(),
            "--toolchain-root".into(),
            root.clone().into_os_string(),
            "--producer-output".into(),
            root.clone().into_os_string(),
            "--producer-output-sha256".into(),
            d.clone().into(),
            "--producer-output-bytes".into(),
            "1".into(),
            "--producer-receipt".into(),
            root.clone().into_os_string(),
            "--producer-receipt-sha256".into(),
            d.clone().into(),
            "--producer-receipt-bytes".into(),
            "1".into(),
            "--request".into(),
            root.clone().into_os_string(),
            "--request-sha256".into(),
            d.clone().into(),
            "--request-bytes".into(),
            "1".into(),
            "--payload-authority".into(),
            root.clone().into_os_string(),
            "--payload-authority-sha256".into(),
            d.clone().into(),
            "--payload-authority-bytes".into(),
            "1".into(),
            "--engine-sha256".into(),
            d.clone().into(),
            "--engine-bytes".into(),
            "1".into(),
            "--timeout-ms".into(),
            "1".into(),
            "--cancel-file".into(),
            root.clone().into_os_string(),
            "--receipt".into(),
            root.into_os_string(),
        ];
        DirectConfig::parse(valid.clone().into_iter()).expect("exact argv");
        let mut reordered = valid.clone();
        reordered.swap(0, 2);
        assert!(matches!(
            DirectConfig::parse(reordered.into_iter()),
            Err(DirectError::Usage)
        ));
        let mut uppercase = valid.clone();
        uppercase[7] = uppercase[7].to_string_lossy().to_uppercase().into();
        assert!(matches!(
            DirectConfig::parse(uppercase.into_iter()),
            Err(DirectError::InvalidArgument("--producer-output-sha256"))
        ));
        let mut padded = valid;
        padded[9] = "01".into();
        assert!(matches!(
            DirectConfig::parse(padded.into_iter()),
            Err(DirectError::InvalidArgument("--producer-output-bytes"))
        ));
    }

    #[test]
    #[cfg(not(all(target_os = "linux", target_arch = "aarch64", target_env = "musl")))]
    fn unsupported_host_refuses_before_parsing_or_observing_arguments() {
        let error = run_direct(
            [
                OsString::from("--malformed"),
                OsString::from("/does/not/exist"),
            ]
            .into_iter(),
        )
        .expect_err("unsupported host");
        assert!(matches!(error, DirectError::UnsupportedHost));
    }

    #[test]
    fn stable_measurement_rejects_substitution() {
        let root = temporary_root("measure");
        let path = root.join("input");
        fs::write(&path, b"first").expect("write input");
        let path = fs::canonicalize(path).expect("canonical input");
        let witness = FileWitness {
            digest: digest(b"first"),
            bytes: 5,
        };
        assert_eq!(
            read_measured(&path, witness, 16, "fixture").expect("measured"),
            b"first"
        );
        fs::write(&path, b"other").expect("substitute input");
        assert!(matches!(
            read_measured(&path, witness, 16, "fixture"),
            Err(DirectError::IdentityMismatch("fixture"))
        ));
        fs::remove_dir_all(root).expect("cleanup root");
    }

    #[test]
    fn stable_measurement_polls_cancellation_during_read_and_hash() {
        let root = temporary_root("measure-cancel");
        let path = root.join("large-input");
        let bytes = vec![0x5a_u8; 256 * 1024];
        fs::write(&path, &bytes).expect("write large input");
        let path = fs::canonicalize(path).expect("canonical input");
        let witness = FileWitness {
            digest: digest(&bytes),
            bytes: bytes.len() as u64,
        };
        for cancel_at in [4_u8, 8_u8] {
            let polls = Cell::new(0_u8);
            let result =
                read_measured_cancellable(&path, witness, witness.bytes, "fixture", &|| {
                    let current = polls.get();
                    polls.set(current.saturating_add(1));
                    Ok(current >= cancel_at)
                });
            assert!(matches!(result, Err(DirectError::Cancelled)));
            assert!(polls.get() > cancel_at);
        }
        fs::remove_dir_all(root).expect("cleanup root");
    }

    #[test]
    fn receipt_publication_is_confined_to_the_staging_parent() {
        let root = temporary_root("receipt-parent");
        let staging = root.join("staging");
        let toolchain = root.join("toolchain");
        fs::create_dir(&staging).expect("staging");
        fs::create_dir(&toolchain).expect("toolchain");
        let witness = FileWitness {
            digest: digest(b"unused"),
            bytes: 6,
        };
        let config = DirectConfig {
            staging_parent: fs::canonicalize(&staging).expect("staging path"),
            toolchain_root: fs::canonicalize(&toolchain).expect("toolchain path"),
            producer_output: root.join("producer-output"),
            producer_output_witness: witness,
            producer_receipt: root.join("producer-receipt"),
            producer_receipt_witness: witness,
            request: root.join("request"),
            request_witness: witness,
            payload_authority: root.join("payload-authority"),
            payload_authority_witness: witness,
            engine_witness: witness,
            timeout: Duration::from_millis(1),
            cancel_file: staging.join("cancel"),
            receipt: toolchain.join("receipt"),
        };
        assert!(matches!(
            execute_direct(&config),
            Err(DirectError::InvalidArgument("direct control paths"))
        ));
        assert!(!config.receipt.exists());
        fs::remove_dir_all(root).expect("cleanup root");
    }

    #[test]
    fn payload_authority_must_be_outside_toolchain_and_staging_roots() {
        let root = temporary_root("authority-placement");
        let staging = root.join("staging");
        let toolchain = root.join("toolchain");
        fs::create_dir(&staging).expect("staging");
        fs::create_dir(&toolchain).expect("toolchain");
        let witness = FileWitness {
            digest: digest(b"unused"),
            bytes: 6,
        };
        let config = DirectConfig {
            staging_parent: fs::canonicalize(&staging).expect("staging path"),
            toolchain_root: fs::canonicalize(&toolchain).expect("toolchain path"),
            producer_output: root.join("producer-output"),
            producer_output_witness: witness,
            producer_receipt: root.join("producer-receipt"),
            producer_receipt_witness: witness,
            request: root.join("request"),
            request_witness: witness,
            payload_authority: toolchain.join("payload-authority"),
            payload_authority_witness: witness,
            engine_witness: witness,
            timeout: Duration::from_millis(1),
            cancel_file: staging.join("cancel"),
            receipt: staging.join("receipt"),
        };
        assert!(matches!(
            execute_direct(&config),
            Err(DirectError::InvalidArgument("payload authority placement"))
        ));
        fs::remove_dir_all(root).expect("cleanup root");
    }

    #[test]
    #[cfg(unix)]
    fn non_utf8_receipt_name_is_rejected_during_preflight() {
        use std::os::unix::ffi::OsStringExt as _;

        let path = PathBuf::from("/tmp").join(OsString::from_vec(vec![0xff]));
        assert!(matches!(
            validate_receipt_name(&path),
            Err(DirectError::InvalidArgument("--receipt"))
        ));
    }

    #[test]
    fn receipt_candidate_leaf_has_a_fixed_small_bound() {
        let leaf = receipt_candidate_name(u32::MAX, u8::MAX);
        assert!(leaf.len() < 64);
        assert!(leaf.bytes().all(|byte| byte.is_ascii()));
        assert!(!leaf.contains('/'));
        let oversized = PathBuf::from("/tmp").join("r".repeat(129));
        assert!(matches!(
            validate_receipt_name(&oversized),
            Err(DirectError::InvalidArgument("--receipt"))
        ));
    }

    #[test]
    #[cfg(unix)]
    fn timeout_terminates_and_reaps_without_publication() {
        let root = temporary_root("timeout");
        let cancel = root.join("cancel");
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "sleep 5"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env_clear();
        let error = run_bounded_child(command, Vec::new(), Duration::from_millis(20), &cancel)
            .expect_err("timeout");
        assert!(matches!(error, DirectError::TimedOut));
        assert_eq!(fs::read_dir(&root).expect("root inventory").count(), 0);
        fs::remove_dir(root).expect("cleanup root");
    }

    #[test]
    fn create_new_publication_never_overwrites_and_cleans_candidate() {
        let root = temporary_root("publish");
        let destination = root.join("receipt");
        let first = receipt();
        publish_create_new(&destination, &first).expect("first publication");
        let mut second = receipt();
        second.timeout_ms += 1;
        assert!(matches!(
            publish_create_new(&destination, &second),
            Err(DirectError::PublicationExists)
        ));
        assert_eq!(
            DirectExecutionReceipt::decode_canonical(&fs::read(&destination).expect("receipt"))
                .expect("published receipt"),
            first
        );
        assert_eq!(fs::read_dir(&root).expect("inventory").count(), 1);
        fs::remove_dir_all(root).expect("cleanup root");
    }

    fn temporary_root(label: &str) -> PathBuf {
        let base = fs::canonicalize(std::env::temp_dir()).expect("temporary directory");
        for _ in 0..128 {
            let sequence = NEXT.fetch_add(1, AtomicOrdering::Relaxed);
            let root = base.join(format!(
                "wrela-engine-direct-{label}-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => return fs::canonicalize(root).expect("canonical fixture root"),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("create fixture root: {error}"),
            }
        }
        panic!("allocate fixture root")
    }
}
