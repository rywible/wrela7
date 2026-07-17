//! Exact-current, filesystem-free transport model for the headless compiler
//! engine.
//!
//! This module owns only canonical bytes, portable bundle-relative paths,
//! deterministic identities, and ordered request/response validation. Process
//! supervision, VM transport, filesystem capture/materialization, and compiler
//! execution deliberately remain outside `wrela-driver`.

use std::fmt;

use wrela_build_model::{Sha256Digest, TargetIdentity};

pub const ENGINE_PROTOCOL_VERSION: u32 = 1;
pub const ENGINE_FRAME_HEADER_BYTES: usize = 92;
pub const ENGINE_MAX_CHUNK_BYTES: usize = 64 * 1024;

const FRAME_MAGIC: &[u8; 8] = b"WRELENG\0";
const TREE_MAGIC: &[u8; 8] = b"WRELNTR\0";
const REQUEST_MAGIC: &[u8; 8] = b"WRELRQB\0";
const NONCE_PROOF_MAGIC: &[u8; 8] = b"WRELNPR\0";
const CHECK_REPORT_MAGIC: &[u8; 8] = b"WRELCRP\0";
const TREE_ENCODING_VERSION: u32 = 1;
const REQUEST_ENCODING_VERSION: u32 = 1;
const NONCE_PROOF_VERSION: u32 = 1;
const CHECK_REPORT_VERSION: u32 = 1;
const DIGEST_BYTES: usize = 32;
const MAX_PORTABLE_PATH_BYTES: usize = 64 * 1024;
const HASH_POLL_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineProtocolLimits {
    pub frame_payload_bytes: u32,
    pub frames: u64,
    pub tree_records: u32,
    pub path_bytes_per_record: u32,
    pub tree_path_bytes: u64,
    pub tree_content_bytes: u64,
    pub text_bytes: u32,
    pub events: u32,
    pub event_bytes: u64,
}

impl EngineProtocolLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            frame_payload_bytes: 1024 * 1024,
            frames: 2_000_000,
            tree_records: 1_000_000,
            path_bytes_per_record: 64 * 1024,
            tree_path_bytes: 256 * 1024 * 1024,
            tree_content_bytes: 64 * 1024 * 1024 * 1024,
            text_bytes: 1024 * 1024,
            events: 1_000_000,
            event_bytes: 1024 * 1024 * 1024,
        }
    }

    pub fn validate(self) -> Result<(), EngineProtocolError> {
        let hard = Self::standard();
        if self.frame_payload_bytes == 0
            || self.frames == 0
            || self.tree_records == 0
            || self.path_bytes_per_record == 0
            || self.tree_path_bytes == 0
            || self.tree_content_bytes == 0
            || self.text_bytes == 0
            || self.events == 0
            || self.event_bytes == 0
            || self.frame_payload_bytes > hard.frame_payload_bytes
            || self.frames > hard.frames
            || self.tree_records > hard.tree_records
            || self.path_bytes_per_record > hard.path_bytes_per_record
            || self.tree_path_bytes > hard.tree_path_bytes
            || self.tree_content_bytes > hard.tree_content_bytes
            || self.text_bytes > hard.text_bytes
            || self.events > hard.events
            || self.event_bytes > hard.event_bytes
        {
            return Err(EngineProtocolError::InvalidLimits);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EnginePath(String);

impl EnginePath {
    pub fn new(value: impl Into<String>) -> Result<Self, EngineProtocolError> {
        let value = value.into();
        if !portable_path(&value) {
            return Err(EngineProtocolError::InvalidPath);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TreeMode {
    Data,
}

impl TreeMode {
    const fn tag(self) -> u8 {
        match self {
            Self::Data => 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeRecord {
    pub path: EnginePath,
    pub mode: TreeMode,
    pub bytes: u64,
    pub digest: Sha256Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeMeasurement {
    pub digest: Sha256Digest,
    pub records: u32,
    pub content_bytes: u64,
    pub path_bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineResourcePolicy {
    pub input_records: u32,
    pub input_path_bytes: u64,
    pub input_content_bytes: u64,
    pub output_records: u32,
    pub output_path_bytes: u64,
    pub output_content_bytes: u64,
    pub events: u32,
    pub event_bytes: u64,
    pub comptime_steps: u64,
    pub comptime_memory_bytes: u64,
    pub comptime_call_depth: u32,
}

impl EngineResourcePolicy {
    #[must_use]
    pub const fn check_standard() -> Self {
        Self {
            input_records: 1_000_000,
            input_path_bytes: 256 * 1024 * 1024,
            input_content_bytes: 64 * 1024 * 1024 * 1024,
            output_records: 0,
            output_path_bytes: 0,
            output_content_bytes: 0,
            events: 1_000_000,
            event_bytes: 1024 * 1024 * 1024,
            comptime_steps: 10_000_000,
            comptime_memory_bytes: 256 * 1024 * 1024,
            comptime_call_depth: 1024,
        }
    }

    fn validate(self, limits: EngineProtocolLimits) -> Result<(), EngineProtocolError> {
        let hard = Self::check_standard();
        if self.input_records == 0
            || self.input_records > limits.tree_records
            || self.input_path_bytes == 0
            || self.input_path_bytes > limits.tree_path_bytes
            || self.input_content_bytes > limits.tree_content_bytes
            || self.output_records != 0
            || self.output_path_bytes != 0
            || self.output_content_bytes != 0
            || self.events == 0
            || self.events > limits.events
            || self.event_bytes == 0
            || self.event_bytes > limits.event_bytes
            || self.comptime_steps == 0
            || self.comptime_steps > hard.comptime_steps
            || self.comptime_memory_bytes == 0
            || self.comptime_memory_bytes > hard.comptime_memory_bytes
            || self.comptime_call_depth == 0
            || self.comptime_call_depth > hard.comptime_call_depth
        {
            return Err(EngineProtocolError::InvalidResourcePolicy);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckDiagnosticPolicy {
    pub warnings_as_errors: bool,
    pub maximum_diagnostics: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckRequest {
    identity: Sha256Digest,
    pub engine_identity: Sha256Digest,
    pub payload_identity: Sha256Digest,
    pub manifest: EnginePath,
    pub lockfile: EnginePath,
    pub image: String,
    pub target: TargetIdentity,
    pub profile: String,
    pub diagnostics: CheckDiagnosticPolicy,
    pub resources: EngineResourcePolicy,
    pub input: TreeMeasurement,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckRequestFields {
    pub engine_identity: Sha256Digest,
    pub payload_identity: Sha256Digest,
    pub manifest: EnginePath,
    pub lockfile: EnginePath,
    pub image: String,
    pub target: TargetIdentity,
    pub profile: String,
    pub diagnostics: CheckDiagnosticPolicy,
    pub resources: EngineResourcePolicy,
    pub input: TreeMeasurement,
}

impl CheckRequest {
    pub fn seal(
        fields: CheckRequestFields,
        limits: EngineProtocolLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, EngineProtocolError> {
        validate_request_fields(&fields, limits)?;
        let identity = request_identity(&fields, is_cancelled)?;
        Ok(Self {
            identity,
            engine_identity: fields.engine_identity,
            payload_identity: fields.payload_identity,
            manifest: fields.manifest,
            lockfile: fields.lockfile,
            image: fields.image,
            target: fields.target,
            profile: fields.profile,
            diagnostics: fields.diagnostics,
            resources: fields.resources,
            input: fields.input,
        })
    }

    #[must_use]
    pub const fn identity(&self) -> Sha256Digest {
        self.identity
    }

    #[must_use]
    pub fn to_fields(&self) -> CheckRequestFields {
        CheckRequestFields {
            engine_identity: self.engine_identity,
            payload_identity: self.payload_identity,
            manifest: self.manifest.clone(),
            lockfile: self.lockfile.clone(),
            image: self.image.clone(),
            target: self.target.clone(),
            profile: self.profile.clone(),
            diagnostics: self.diagnostics,
            resources: self.resources,
            input: self.input,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientHello {
    pub launcher_identity: Sha256Digest,
    pub payload_identity: Sha256Digest,
    pub nonce: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerHello {
    pub engine_identity: Sha256Digest,
    pub payload_identity: Sha256Digest,
    pub nonce_proof: Sha256Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticSeverity {
    Warning,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineEvent {
    PhaseStarted {
        phase: String,
    },
    PhaseFinished {
        phase: String,
        reused: bool,
    },
    Diagnostic {
        stable_id: Sha256Digest,
        severity: DiagnosticSeverity,
        code: String,
        message: String,
        path: Option<EnginePath>,
        line: u32,
        column: u32,
    },
}

pub struct CheckReportIdentityBuilder {
    limits: EngineProtocolLimits,
    events: u32,
    event_bytes: u64,
    digest: Sha256State,
}

impl CheckReportIdentityBuilder {
    pub fn new(
        request_identity: Sha256Digest,
        limits: EngineProtocolLimits,
    ) -> Result<Self, EngineProtocolError> {
        limits.validate()?;
        check_digest(request_identity)?;
        Ok(Self {
            limits,
            events: 0,
            event_bytes: 0,
            digest: check_report_digest_start(request_identity),
        })
    }

    pub fn observe(
        &mut self,
        event: &EngineEvent,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), EngineProtocolError> {
        check_cancelled(is_cancelled)?;
        if self.events >= self.limits.events {
            return Err(EngineProtocolError::ResourceLimit {
                resource: "check report events",
                limit: u64::from(self.limits.events),
            });
        }
        let mut writer = Writer::new(self.limits);
        encode_event(&mut writer, event, is_cancelled)?;
        let payload = writer.finish();
        let next_event_bytes = self.event_bytes.checked_add(payload.len() as u64).ok_or(
            EngineProtocolError::ResourceLimit {
                resource: "check report event bytes",
                limit: self.limits.event_bytes,
            },
        )?;
        if next_event_bytes > self.limits.event_bytes {
            return Err(EngineProtocolError::ResourceLimit {
                resource: "check report event bytes",
                limit: self.limits.event_bytes,
            });
        }
        let mut digest = self.digest.clone();
        update_check_report_event(&mut digest, self.events, &payload, is_cancelled)?;
        check_cancelled(is_cancelled)?;
        self.digest = digest;
        self.event_bytes = next_event_bytes;
        self.events += 1;
        Ok(())
    }

    #[must_use]
    pub const fn events(&self) -> u32 {
        self.events
    }

    #[must_use]
    pub const fn event_bytes(&self) -> u64 {
        self.event_bytes
    }

    pub fn finish(
        &self,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Sha256Digest, EngineProtocolError> {
        check_cancelled(is_cancelled)?;
        let mut digest = self.digest.clone();
        digest.update(&self.events.to_le_bytes());
        digest.update(&self.event_bytes.to_le_bytes());
        check_cancelled(is_cancelled)?;
        Ok(digest.finish())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalStatus {
    Success,
    Rejected,
    Cancelled,
    ResourceLimit,
    InternalFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineComptimeUsage {
    pub steps: u64,
    pub peak_memory_bytes: u64,
    pub peak_call_depth: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EngineResourceUsage {
    pub input_bytes: u64,
    pub output_bytes: u64,
    pub events: u32,
    pub event_bytes: u64,
    /// Exact evaluator counters when exported by the compiler. `None` means
    /// unavailable, not that evaluation consumed zero resources.
    pub comptime: Option<EngineComptimeUsage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineTerminal {
    pub status: TerminalStatus,
    pub diagnostic_count: u32,
    pub report_identity: Sha256Digest,
    pub usage: EngineResourceUsage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineMessage {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    RequestHeader(Box<CheckRequest>),
    InputRecord {
        index: u32,
        record: TreeRecord,
    },
    InputChunk {
        record: u32,
        offset: u64,
        bytes: Vec<u8>,
    },
    InputFinish(TreeMeasurement),
    Cancel,
    Event(EngineEvent),
    OutputHeader(TreeMeasurement),
    OutputRecord {
        index: u32,
        record: TreeRecord,
    },
    OutputChunk {
        record: u32,
        offset: u64,
        bytes: Vec<u8>,
    },
    OutputFinish(TreeMeasurement),
    Terminal(EngineTerminal),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineFrame {
    pub sequence: u64,
    pub request_identity: Sha256Digest,
    pub message: EngineMessage,
}

/// Fixed-size, fully validated metadata for one exact-v1 frame.
///
/// A process transport reads exactly [`ENGINE_FRAME_HEADER_BYTES`], validates
/// it with [`decode_frame_header`], then reads exactly
/// [`Self::payload_bytes`] more bytes. No transport needs to duplicate wire
/// offsets or trust an unbounded peer-declared length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedEngineFrameHeader {
    kind: u16,
    sequence: u64,
    payload_bytes: u32,
    request_identity: Sha256Digest,
    payload_digest: Sha256Digest,
}

impl ValidatedEngineFrameHeader {
    #[must_use]
    pub const fn kind(self) -> u16 {
        self.kind
    }

    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub const fn payload_bytes(self) -> u32 {
        self.payload_bytes
    }

    #[must_use]
    pub const fn encoded_frame_bytes(self) -> u64 {
        ENGINE_FRAME_HEADER_BYTES as u64 + self.payload_bytes as u64
    }

    #[must_use]
    pub const fn request_identity(self) -> Sha256Digest {
        self.request_identity
    }

    #[must_use]
    pub const fn payload_digest(self) -> Sha256Digest {
        self.payload_digest
    }
}

/// Borrowed response message used by bounded one-frame-at-a-time encoders.
#[derive(Debug, Clone, Copy)]
pub enum EngineResponseMessageRef<'a> {
    ServerHello(&'a ServerHello),
    Event(&'a EngineEvent),
    OutputHeader(TreeMeasurement),
    OutputFinish(TreeMeasurement),
    Terminal(&'a EngineTerminal),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineProtocolError {
    Cancelled,
    InvalidLimits,
    InvalidResourcePolicy,
    InvalidMagic,
    UnsupportedVersion(u32),
    UnknownFrameKind(u16),
    NonZeroReserved,
    FrameTooLarge {
        limit: u64,
        actual: u64,
    },
    FrameLengthMismatch {
        declared: u64,
        actual: u64,
    },
    PayloadDigestMismatch,
    RequestIdentityMismatch,
    InvalidPath,
    InvalidText,
    InvalidDigest,
    InvalidTag {
        field: &'static str,
        tag: u8,
    },
    Truncated,
    TrailingBytes,
    ResourceLimit {
        resource: &'static str,
        limit: u64,
    },
    SequenceMismatch {
        expected: u64,
        actual: u64,
    },
    UnexpectedMessage {
        expected: &'static str,
        actual: &'static str,
    },
    TreeOrder,
    TreeMeasurementMismatch,
    RecordIndexMismatch {
        expected: u32,
        actual: u32,
    },
    ChunkOffsetMismatch {
        expected: u64,
        actual: u64,
    },
    EmptyChunk,
    RecordDigestMismatch,
    NonceProofMismatch,
    TerminalPolicyMismatch,
}

impl fmt::Display for EngineProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("engine protocol operation was cancelled"),
            Self::InvalidLimits => formatter.write_str("engine protocol limits are invalid"),
            Self::InvalidResourcePolicy => {
                formatter.write_str("engine request resource policy is invalid")
            }
            Self::InvalidMagic => formatter.write_str("engine frame magic is invalid"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported engine protocol version {version}")
            }
            Self::UnknownFrameKind(kind) => write!(formatter, "unknown engine frame kind {kind}"),
            Self::NonZeroReserved => formatter.write_str("engine frame reserved bits are nonzero"),
            Self::FrameTooLarge { limit, actual } => write!(
                formatter,
                "engine frame size {actual} exceeds limit {limit}"
            ),
            Self::FrameLengthMismatch { declared, actual } => write!(
                formatter,
                "engine frame declares {declared} payload bytes but carries {actual}"
            ),
            Self::PayloadDigestMismatch => {
                formatter.write_str("engine frame payload digest does not match")
            }
            Self::RequestIdentityMismatch => {
                formatter.write_str("engine request identity does not match")
            }
            Self::InvalidPath => {
                formatter.write_str("engine bundle path is not canonical and relative")
            }
            Self::InvalidText => formatter.write_str("engine protocol text is invalid"),
            Self::InvalidDigest => formatter.write_str("engine protocol digest is unset"),
            Self::InvalidTag { field, tag } => {
                write!(formatter, "engine protocol {field} has unknown tag {tag}")
            }
            Self::Truncated => formatter.write_str("engine frame is truncated"),
            Self::TrailingBytes => formatter.write_str("engine frame has trailing bytes"),
            Self::ResourceLimit { resource, limit } => write!(
                formatter,
                "engine protocol {resource} exceeds limit {limit}"
            ),
            Self::SequenceMismatch { expected, actual } => write!(
                formatter,
                "engine stream expected sequence {expected}, received {actual}"
            ),
            Self::UnexpectedMessage { expected, actual } => write!(
                formatter,
                "engine stream expected {expected}, received {actual}"
            ),
            Self::TreeOrder => {
                formatter.write_str("engine tree records are not in canonical order")
            }
            Self::TreeMeasurementMismatch => {
                formatter.write_str("engine tree measurement does not match its records")
            }
            Self::RecordIndexMismatch { expected, actual } => write!(
                formatter,
                "engine tree expected record {expected}, received {actual}"
            ),
            Self::ChunkOffsetMismatch { expected, actual } => write!(
                formatter,
                "engine tree expected chunk offset {expected}, received {actual}"
            ),
            Self::EmptyChunk => formatter.write_str("engine tree chunk is empty"),
            Self::RecordDigestMismatch => {
                formatter.write_str("engine tree record digest does not match its bytes")
            }
            Self::NonceProofMismatch => {
                formatter.write_str("engine hello nonce proof does not match")
            }
            Self::TerminalPolicyMismatch => {
                formatter.write_str("engine terminal usage or status violates the request policy")
            }
        }
    }
}

impl std::error::Error for EngineProtocolError {}

pub fn sha256(
    bytes: &[u8],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Sha256Digest, EngineProtocolError> {
    check_cancelled(is_cancelled)?;
    let mut state = Sha256State::new();
    for chunk in bytes.chunks(HASH_POLL_BYTES) {
        check_cancelled(is_cancelled)?;
        state.update(chunk);
    }
    check_cancelled(is_cancelled)?;
    Ok(state.finish())
}

pub fn measure_tree(
    records: &[TreeRecord],
    limits: EngineProtocolLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<TreeMeasurement, EngineProtocolError> {
    limits.validate()?;
    check_cancelled(is_cancelled)?;
    let count = u32::try_from(records.len()).map_err(|_| EngineProtocolError::ResourceLimit {
        resource: "tree records",
        limit: u64::from(limits.tree_records),
    })?;
    if count > limits.tree_records {
        return Err(EngineProtocolError::ResourceLimit {
            resource: "tree records",
            limit: u64::from(limits.tree_records),
        });
    }

    let mut digest = tree_digest_start(count);
    let mut previous = None;
    let mut path_bytes = 0u64;
    let mut content_bytes = 0u64;
    for record in records {
        check_cancelled(is_cancelled)?;
        validate_record_metadata(record, limits)?;
        if previous.is_some_and(|path: &str| path >= record.path.as_str()) {
            return Err(EngineProtocolError::TreeOrder);
        }
        previous = Some(record.path.as_str());
        add_limit(
            &mut path_bytes,
            usize_u64(
                record.path.as_str().len(),
                "tree path bytes",
                limits.tree_path_bytes,
            )?,
            "tree path bytes",
            limits.tree_path_bytes,
        )?;
        add_limit(
            &mut content_bytes,
            record.bytes,
            "tree content bytes",
            limits.tree_content_bytes,
        )?;
        update_tree_record(&mut digest, record);
    }
    check_cancelled(is_cancelled)?;
    Ok(TreeMeasurement {
        digest: digest.finish(),
        records: count,
        content_bytes,
        path_bytes,
    })
}

pub fn empty_tree_measurement(
    is_cancelled: &dyn Fn() -> bool,
) -> Result<TreeMeasurement, EngineProtocolError> {
    measure_tree(&[], EngineProtocolLimits::standard(), is_cancelled)
}

pub fn nonce_proof(
    request_identity: Sha256Digest,
    launcher_identity: Sha256Digest,
    engine_identity: Sha256Digest,
    payload_identity: Sha256Digest,
    nonce: [u8; 32],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Sha256Digest, EngineProtocolError> {
    // This is an exact transcript/liveness proof for an already authenticated
    // transport. It is deliberately not a MAC and must not be treated as
    // secret-key authentication by a launcher or engine implementation.
    check_digest(request_identity)?;
    check_digest(launcher_identity)?;
    check_digest(engine_identity)?;
    check_digest(payload_identity)?;
    if nonce.iter().all(|byte| *byte == 0) {
        return Err(EngineProtocolError::InvalidDigest);
    }
    check_cancelled(is_cancelled)?;
    let mut digest = Sha256State::new();
    digest.update(NONCE_PROOF_MAGIC);
    digest.update(&NONCE_PROOF_VERSION.to_le_bytes());
    digest.update(request_identity.as_bytes());
    digest.update(launcher_identity.as_bytes());
    digest.update(engine_identity.as_bytes());
    digest.update(payload_identity.as_bytes());
    digest.update(&nonce);
    check_cancelled(is_cancelled)?;
    Ok(digest.finish())
}

pub fn encode_frame(
    frame: &EngineFrame,
    limits: EngineProtocolLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>, EngineProtocolError> {
    limits.validate()?;
    check_cancelled(is_cancelled)?;
    if frame.sequence >= limits.frames {
        return Err(EngineProtocolError::ResourceLimit {
            resource: "frame sequence",
            limit: limits.frames,
        });
    }
    check_digest(frame.request_identity)?;
    let (kind, payload) =
        encode_message(&frame.message, frame.request_identity, limits, is_cancelled)?;
    encode_frame_payload(
        frame.sequence,
        frame.request_identity,
        kind,
        payload,
        limits,
        is_cancelled,
    )
}

/// Encode one borrowed response message into one bounded frame.
///
/// The returned allocation is bounded by `limits.frame_payload_bytes` and can
/// be written and discarded before the next response message is encoded.
pub fn encode_response_frame(
    sequence: u64,
    request_identity: Sha256Digest,
    message: EngineResponseMessageRef<'_>,
    limits: EngineProtocolLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>, EngineProtocolError> {
    limits.validate()?;
    check_cancelled(is_cancelled)?;
    let (kind, payload) = encode_response_message(message, limits, is_cancelled)?;
    encode_frame_payload(
        sequence,
        request_identity,
        kind,
        payload,
        limits,
        is_cancelled,
    )
}

fn encode_frame_payload(
    sequence: u64,
    request_identity: Sha256Digest,
    kind: u16,
    payload: Vec<u8>,
    limits: EngineProtocolLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>, EngineProtocolError> {
    if sequence >= limits.frames {
        return Err(EngineProtocolError::ResourceLimit {
            resource: "frame sequence",
            limit: limits.frames,
        });
    }
    check_digest(request_identity)?;
    let payload_bytes = usize_u64(
        payload.len(),
        "frame payload bytes",
        u64::from(limits.frame_payload_bytes),
    )?;
    if payload_bytes > u64::from(limits.frame_payload_bytes) {
        return Err(EngineProtocolError::FrameTooLarge {
            limit: u64::from(limits.frame_payload_bytes),
            actual: payload_bytes,
        });
    }
    let payload_length =
        u32::try_from(payload.len()).map_err(|_| EngineProtocolError::FrameTooLarge {
            limit: u64::from(limits.frame_payload_bytes),
            actual: payload_bytes,
        })?;
    let payload_digest = sha256(&payload, is_cancelled)?;
    let total = ENGINE_FRAME_HEADER_BYTES.checked_add(payload.len()).ok_or(
        EngineProtocolError::FrameTooLarge {
            limit: u64::from(limits.frame_payload_bytes),
            actual: u64::MAX,
        },
    )?;
    let mut bytes = Vec::new();
    reserve(&mut bytes, total, "encoded frame bytes", total as u64)?;
    bytes.extend_from_slice(FRAME_MAGIC);
    bytes.extend_from_slice(&ENGINE_PROTOCOL_VERSION.to_le_bytes());
    bytes.extend_from_slice(&kind.to_le_bytes());
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&sequence.to_le_bytes());
    bytes.extend_from_slice(&payload_length.to_le_bytes());
    bytes.extend_from_slice(request_identity.as_bytes());
    bytes.extend_from_slice(payload_digest.as_bytes());
    debug_assert_eq!(bytes.len(), ENGINE_FRAME_HEADER_BYTES);
    bytes.extend_from_slice(&payload);
    check_cancelled(is_cancelled)?;
    Ok(bytes)
}

/// Validate exactly one fixed-size frame header without reading its payload.
pub fn decode_frame_header(
    bytes: &[u8],
    limits: EngineProtocolLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ValidatedEngineFrameHeader, EngineProtocolError> {
    limits.validate()?;
    check_cancelled(is_cancelled)?;
    if bytes.len() < ENGINE_FRAME_HEADER_BYTES {
        return Err(EngineProtocolError::Truncated);
    }
    if bytes.len() > ENGINE_FRAME_HEADER_BYTES {
        return Err(EngineProtocolError::TrailingBytes);
    }
    if bytes.get(..FRAME_MAGIC.len()) != Some(FRAME_MAGIC.as_slice()) {
        return Err(EngineProtocolError::InvalidMagic);
    }
    let version = fixed_u32(bytes, 8)?;
    if version != ENGINE_PROTOCOL_VERSION {
        return Err(EngineProtocolError::UnsupportedVersion(version));
    }
    let kind = fixed_u16(bytes, 12)?;
    if !(1..=13).contains(&kind) {
        return Err(EngineProtocolError::UnknownFrameKind(kind));
    }
    if fixed_u16(bytes, 14)? != 0 {
        return Err(EngineProtocolError::NonZeroReserved);
    }
    let sequence = fixed_u64(bytes, 16)?;
    if sequence >= limits.frames {
        return Err(EngineProtocolError::ResourceLimit {
            resource: "frame sequence",
            limit: limits.frames,
        });
    }
    let payload_bytes = fixed_u32(bytes, 24)?;
    if payload_bytes > limits.frame_payload_bytes {
        return Err(EngineProtocolError::FrameTooLarge {
            limit: u64::from(limits.frame_payload_bytes),
            actual: u64::from(payload_bytes),
        });
    }
    let request_identity = fixed_digest(bytes, 28)?;
    check_digest(request_identity)?;
    let payload_digest = fixed_digest(bytes, 60)?;
    check_digest(payload_digest)?;
    check_cancelled(is_cancelled)?;
    Ok(ValidatedEngineFrameHeader {
        kind,
        sequence,
        payload_bytes,
        request_identity,
        payload_digest,
    })
}

pub fn decode_frame(
    bytes: &[u8],
    limits: EngineProtocolLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<EngineFrame, EngineProtocolError> {
    limits.validate()?;
    check_cancelled(is_cancelled)?;
    if bytes.len() < ENGINE_FRAME_HEADER_BYTES {
        return Err(EngineProtocolError::Truncated);
    }
    let header = decode_frame_header(
        bytes
            .get(..ENGINE_FRAME_HEADER_BYTES)
            .ok_or(EngineProtocolError::Truncated)?,
        limits,
        is_cancelled,
    )?;
    let declared = u64::from(header.payload_bytes);
    let actual = usize_u64(
        bytes.len() - ENGINE_FRAME_HEADER_BYTES,
        "frame payload bytes",
        u64::from(limits.frame_payload_bytes),
    )?;
    if actual != declared {
        return Err(EngineProtocolError::FrameLengthMismatch { declared, actual });
    }
    let payload = bytes
        .get(ENGINE_FRAME_HEADER_BYTES..)
        .ok_or(EngineProtocolError::Truncated)?;
    if sha256(payload, is_cancelled)? != header.payload_digest {
        return Err(EngineProtocolError::PayloadDigestMismatch);
    }
    let message = decode_message(
        header.kind,
        payload,
        header.request_identity,
        limits,
        is_cancelled,
    )?;
    check_cancelled(is_cancelled)?;
    Ok(EngineFrame {
        sequence: header.sequence,
        request_identity: header.request_identity,
        message,
    })
}

fn validate_request_fields(
    fields: &CheckRequestFields,
    limits: EngineProtocolLimits,
) -> Result<(), EngineProtocolError> {
    limits.validate()?;
    check_digest(fields.engine_identity)?;
    check_digest(fields.payload_identity)?;
    fields.resources.validate(limits)?;
    if !valid_atom(&fields.image)
        || !valid_atom(&fields.profile)
        || fields.manifest.as_str().len() > limits.text_bytes as usize
        || fields.lockfile.as_str().len() > limits.text_bytes as usize
        || fields.image.len() > limits.text_bytes as usize
        || fields.target.as_str().len() > limits.text_bytes as usize
        || fields.profile.len() > limits.text_bytes as usize
        || !canonical_check_paths(&fields.manifest, &fields.lockfile)
        || fields.diagnostics.maximum_diagnostics == 0
        || fields.diagnostics.maximum_diagnostics > fields.resources.events
        || fields.input.records == 0
        || fields.input.records > fields.resources.input_records
        || fields.input.path_bytes > fields.resources.input_path_bytes
        || fields.input.content_bytes > fields.resources.input_content_bytes
        || digest_is_zero(fields.input.digest)
    {
        return Err(EngineProtocolError::InvalidResourcePolicy);
    }
    Ok(())
}

fn canonical_check_paths(manifest: &EnginePath, lockfile: &EnginePath) -> bool {
    fn split(path: &str) -> (&str, &str) {
        path.rsplit_once('/').unwrap_or(("", path))
    }

    let (manifest_parent, manifest_name) = split(manifest.as_str());
    let (lock_parent, lock_name) = split(lockfile.as_str());
    manifest_parent == lock_parent && manifest_name == "wrela.toml" && lock_name == "wrela.lock"
}

fn request_identity(
    fields: &CheckRequestFields,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Sha256Digest, EngineProtocolError> {
    check_cancelled(is_cancelled)?;
    let mut digest = Sha256State::new();
    digest.update(REQUEST_MAGIC);
    digest.update(&REQUEST_ENCODING_VERSION.to_le_bytes());
    digest.update(&1u16.to_le_bytes());
    digest.update(fields.engine_identity.as_bytes());
    digest.update(fields.payload_identity.as_bytes());
    update_hashed_bytes(&mut digest, fields.manifest.as_str().as_bytes());
    update_hashed_bytes(&mut digest, fields.lockfile.as_str().as_bytes());
    update_hashed_bytes(&mut digest, fields.image.as_bytes());
    update_hashed_bytes(&mut digest, fields.target.as_str().as_bytes());
    update_hashed_bytes(&mut digest, fields.profile.as_bytes());
    digest.update(&[u8::from(fields.diagnostics.warnings_as_errors)]);
    digest.update(&fields.diagnostics.maximum_diagnostics.to_le_bytes());
    update_resource_policy(&mut digest, fields.resources);
    update_tree_measurement(&mut digest, fields.input);
    check_cancelled(is_cancelled)?;
    Ok(digest.finish())
}

fn encode_message(
    message: &EngineMessage,
    request_identity: Sha256Digest,
    limits: EngineProtocolLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(u16, Vec<u8>), EngineProtocolError> {
    check_cancelled(is_cancelled)?;
    let mut writer = Writer::new(limits);
    let kind = match message {
        EngineMessage::ClientHello(hello) => {
            check_digest(hello.launcher_identity)?;
            check_digest(hello.payload_identity)?;
            if hello.nonce.iter().all(|byte| *byte == 0) {
                return Err(EngineProtocolError::InvalidDigest);
            }
            writer.digest(hello.launcher_identity)?;
            writer.digest(hello.payload_identity)?;
            writer.bytes(&hello.nonce)?;
            1
        }
        EngineMessage::ServerHello(hello) => {
            check_digest(hello.engine_identity)?;
            check_digest(hello.payload_identity)?;
            check_digest(hello.nonce_proof)?;
            writer.digest(hello.engine_identity)?;
            writer.digest(hello.payload_identity)?;
            writer.digest(hello.nonce_proof)?;
            2
        }
        EngineMessage::RequestHeader(request) => {
            verify_request(request, request_identity, limits, is_cancelled)?;
            encode_request(&mut writer, request)?;
            3
        }
        EngineMessage::InputRecord { index, record } => {
            validate_record_metadata(record, limits)?;
            writer.u32(*index)?;
            encode_record(&mut writer, record)?;
            4
        }
        EngineMessage::InputChunk {
            record,
            offset,
            bytes,
        } => {
            validate_chunk(bytes, limits)?;
            writer.u32(*record)?;
            writer.u64(*offset)?;
            writer.byte_string(bytes)?;
            5
        }
        EngineMessage::InputFinish(measurement) => {
            encode_measurement(&mut writer, *measurement)?;
            6
        }
        EngineMessage::Cancel => 7,
        EngineMessage::Event(event) => {
            encode_event(&mut writer, event, is_cancelled)?;
            8
        }
        EngineMessage::OutputHeader(measurement) => {
            encode_measurement(&mut writer, *measurement)?;
            9
        }
        EngineMessage::OutputRecord { index, record } => {
            validate_record_metadata(record, limits)?;
            writer.u32(*index)?;
            encode_record(&mut writer, record)?;
            10
        }
        EngineMessage::OutputChunk {
            record,
            offset,
            bytes,
        } => {
            validate_chunk(bytes, limits)?;
            writer.u32(*record)?;
            writer.u64(*offset)?;
            writer.byte_string(bytes)?;
            11
        }
        EngineMessage::OutputFinish(measurement) => {
            encode_measurement(&mut writer, *measurement)?;
            12
        }
        EngineMessage::Terminal(terminal) => {
            encode_terminal(&mut writer, terminal)?;
            13
        }
    };
    check_cancelled(is_cancelled)?;
    Ok((kind, writer.finish()))
}

fn encode_response_message(
    message: EngineResponseMessageRef<'_>,
    limits: EngineProtocolLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(u16, Vec<u8>), EngineProtocolError> {
    check_cancelled(is_cancelled)?;
    let mut writer = Writer::new(limits);
    let kind = match message {
        EngineResponseMessageRef::ServerHello(hello) => {
            check_digest(hello.engine_identity)?;
            check_digest(hello.payload_identity)?;
            check_digest(hello.nonce_proof)?;
            writer.digest(hello.engine_identity)?;
            writer.digest(hello.payload_identity)?;
            writer.digest(hello.nonce_proof)?;
            2
        }
        EngineResponseMessageRef::Event(event) => {
            encode_event(&mut writer, event, is_cancelled)?;
            8
        }
        EngineResponseMessageRef::OutputHeader(measurement) => {
            encode_measurement(&mut writer, measurement)?;
            9
        }
        EngineResponseMessageRef::OutputFinish(measurement) => {
            encode_measurement(&mut writer, measurement)?;
            12
        }
        EngineResponseMessageRef::Terminal(terminal) => {
            encode_terminal(&mut writer, terminal)?;
            13
        }
    };
    check_cancelled(is_cancelled)?;
    Ok((kind, writer.finish()))
}

fn decode_message(
    kind: u16,
    payload: &[u8],
    request_identity: Sha256Digest,
    limits: EngineProtocolLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<EngineMessage, EngineProtocolError> {
    let mut reader = Reader::new(payload, limits);
    let message = match kind {
        1 => EngineMessage::ClientHello(ClientHello {
            launcher_identity: reader.digest()?,
            payload_identity: reader.digest()?,
            nonce: reader.fixed_32()?,
        }),
        2 => EngineMessage::ServerHello(ServerHello {
            engine_identity: reader.digest()?,
            payload_identity: reader.digest()?,
            nonce_proof: reader.digest()?,
        }),
        3 => {
            let request = decode_request(&mut reader, limits, is_cancelled)?;
            if request.identity() != request_identity {
                return Err(EngineProtocolError::RequestIdentityMismatch);
            }
            EngineMessage::RequestHeader(Box::new(request))
        }
        4 => EngineMessage::InputRecord {
            index: reader.u32()?,
            record: decode_record(&mut reader)?,
        },
        5 => EngineMessage::InputChunk {
            record: reader.u32()?,
            offset: reader.u64()?,
            bytes: reader.byte_string(ENGINE_MAX_CHUNK_BYTES)?,
        },
        6 => EngineMessage::InputFinish(decode_measurement(&mut reader)?),
        7 => EngineMessage::Cancel,
        8 => EngineMessage::Event(decode_event(&mut reader)?),
        9 => EngineMessage::OutputHeader(decode_measurement(&mut reader)?),
        10 => EngineMessage::OutputRecord {
            index: reader.u32()?,
            record: decode_record(&mut reader)?,
        },
        11 => EngineMessage::OutputChunk {
            record: reader.u32()?,
            offset: reader.u64()?,
            bytes: reader.byte_string(ENGINE_MAX_CHUNK_BYTES)?,
        },
        12 => EngineMessage::OutputFinish(decode_measurement(&mut reader)?),
        13 => EngineMessage::Terminal(decode_terminal(&mut reader)?),
        other => return Err(EngineProtocolError::UnknownFrameKind(other)),
    };
    reader.finish()?;
    validate_decoded_message(&message, request_identity, limits, is_cancelled)?;
    Ok(message)
}

fn verify_request(
    request: &CheckRequest,
    expected_identity: Sha256Digest,
    limits: EngineProtocolLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), EngineProtocolError> {
    let fields = request.to_fields();
    validate_request_fields(&fields, limits)?;
    if request.identity != expected_identity
        || request_identity(&fields, is_cancelled)? != expected_identity
    {
        return Err(EngineProtocolError::RequestIdentityMismatch);
    }
    Ok(())
}

fn encode_request(writer: &mut Writer, request: &CheckRequest) -> Result<(), EngineProtocolError> {
    writer.digest(request.engine_identity)?;
    writer.digest(request.payload_identity)?;
    writer.string(request.manifest.as_str())?;
    writer.string(request.lockfile.as_str())?;
    writer.string(&request.image)?;
    writer.string(request.target.as_str())?;
    writer.string(&request.profile)?;
    writer.boolean(request.diagnostics.warnings_as_errors)?;
    writer.u32(request.diagnostics.maximum_diagnostics)?;
    encode_resource_policy(writer, request.resources)?;
    encode_measurement(writer, request.input)
}

fn decode_request(
    reader: &mut Reader<'_>,
    limits: EngineProtocolLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<CheckRequest, EngineProtocolError> {
    let fields = CheckRequestFields {
        engine_identity: reader.digest()?,
        payload_identity: reader.digest()?,
        manifest: EnginePath::new(reader.string()?)?,
        lockfile: EnginePath::new(reader.string()?)?,
        image: reader.string()?,
        target: TargetIdentity::new(reader.string()?)
            .map_err(|_| EngineProtocolError::InvalidText)?,
        profile: reader.string()?,
        diagnostics: CheckDiagnosticPolicy {
            warnings_as_errors: reader.boolean()?,
            maximum_diagnostics: reader.u32()?,
        },
        resources: decode_resource_policy(reader)?,
        input: decode_measurement(reader)?,
    };
    CheckRequest::seal(fields, limits, is_cancelled)
}

fn encode_resource_policy(
    writer: &mut Writer,
    policy: EngineResourcePolicy,
) -> Result<(), EngineProtocolError> {
    writer.u32(policy.input_records)?;
    writer.u64(policy.input_path_bytes)?;
    writer.u64(policy.input_content_bytes)?;
    writer.u32(policy.output_records)?;
    writer.u64(policy.output_path_bytes)?;
    writer.u64(policy.output_content_bytes)?;
    writer.u32(policy.events)?;
    writer.u64(policy.event_bytes)?;
    writer.u64(policy.comptime_steps)?;
    writer.u64(policy.comptime_memory_bytes)?;
    writer.u32(policy.comptime_call_depth)
}

fn decode_resource_policy(
    reader: &mut Reader<'_>,
) -> Result<EngineResourcePolicy, EngineProtocolError> {
    Ok(EngineResourcePolicy {
        input_records: reader.u32()?,
        input_path_bytes: reader.u64()?,
        input_content_bytes: reader.u64()?,
        output_records: reader.u32()?,
        output_path_bytes: reader.u64()?,
        output_content_bytes: reader.u64()?,
        events: reader.u32()?,
        event_bytes: reader.u64()?,
        comptime_steps: reader.u64()?,
        comptime_memory_bytes: reader.u64()?,
        comptime_call_depth: reader.u32()?,
    })
}

fn encode_record(writer: &mut Writer, record: &TreeRecord) -> Result<(), EngineProtocolError> {
    writer.string(record.path.as_str())?;
    writer.u8(record.mode.tag())?;
    writer.u64(record.bytes)?;
    writer.digest(record.digest)
}

fn decode_record(reader: &mut Reader<'_>) -> Result<TreeRecord, EngineProtocolError> {
    let path = EnginePath::new(reader.string()?)?;
    let mode = match reader.u8()? {
        1 => TreeMode::Data,
        tag => {
            return Err(EngineProtocolError::InvalidTag {
                field: "tree mode",
                tag,
            });
        }
    };
    Ok(TreeRecord {
        path,
        mode,
        bytes: reader.u64()?,
        digest: reader.digest()?,
    })
}

fn encode_measurement(
    writer: &mut Writer,
    measurement: TreeMeasurement,
) -> Result<(), EngineProtocolError> {
    check_digest(measurement.digest)?;
    writer.digest(measurement.digest)?;
    writer.u32(measurement.records)?;
    writer.u64(measurement.content_bytes)?;
    writer.u64(measurement.path_bytes)
}

fn decode_measurement(reader: &mut Reader<'_>) -> Result<TreeMeasurement, EngineProtocolError> {
    Ok(TreeMeasurement {
        digest: reader.digest()?,
        records: reader.u32()?,
        content_bytes: reader.u64()?,
        path_bytes: reader.u64()?,
    })
}

fn encode_event(
    writer: &mut Writer,
    event: &EngineEvent,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), EngineProtocolError> {
    check_cancelled(is_cancelled)?;
    match event {
        EngineEvent::PhaseStarted { phase } => {
            validate_short_text(phase)?;
            writer.u8(1)?;
            writer.string_cancellable(phase, is_cancelled)
        }
        EngineEvent::PhaseFinished { phase, reused } => {
            validate_short_text(phase)?;
            writer.u8(2)?;
            writer.string_cancellable(phase, is_cancelled)?;
            writer.boolean(*reused)
        }
        EngineEvent::Diagnostic {
            stable_id,
            severity,
            code,
            message,
            path,
            line,
            column,
        } => {
            check_digest(*stable_id)?;
            validate_short_text(code)?;
            validate_message_text(message)?;
            validate_diagnostic_location(path.as_ref(), *line, *column)?;
            writer.u8(3)?;
            writer.digest(*stable_id)?;
            writer.u8(match severity {
                DiagnosticSeverity::Warning => 1,
                DiagnosticSeverity::Error => 2,
            })?;
            writer.string_cancellable(code, is_cancelled)?;
            writer.string_cancellable(message, is_cancelled)?;
            writer.boolean(path.is_some())?;
            if let Some(path) = path {
                writer.string_cancellable(path.as_str(), is_cancelled)?;
            }
            writer.u32(*line)?;
            writer.u32(*column)?;
            check_cancelled(is_cancelled)
        }
    }
}

fn decode_event(reader: &mut Reader<'_>) -> Result<EngineEvent, EngineProtocolError> {
    match reader.u8()? {
        1 => Ok(EngineEvent::PhaseStarted {
            phase: reader.string()?,
        }),
        2 => Ok(EngineEvent::PhaseFinished {
            phase: reader.string()?,
            reused: reader.boolean()?,
        }),
        3 => {
            let stable_id = reader.digest()?;
            let severity = match reader.u8()? {
                1 => DiagnosticSeverity::Warning,
                2 => DiagnosticSeverity::Error,
                tag => {
                    return Err(EngineProtocolError::InvalidTag {
                        field: "diagnostic severity",
                        tag,
                    });
                }
            };
            let code = reader.string()?;
            let message = reader.string()?;
            let path = if reader.boolean()? {
                Some(EnginePath::new(reader.string()?)?)
            } else {
                None
            };
            Ok(EngineEvent::Diagnostic {
                stable_id,
                severity,
                code,
                message,
                path,
                line: reader.u32()?,
                column: reader.u32()?,
            })
        }
        tag => Err(EngineProtocolError::InvalidTag {
            field: "event",
            tag,
        }),
    }
}

fn encode_terminal(
    writer: &mut Writer,
    terminal: &EngineTerminal,
) -> Result<(), EngineProtocolError> {
    check_digest(terminal.report_identity)?;
    writer.u8(match terminal.status {
        TerminalStatus::Success => 1,
        TerminalStatus::Rejected => 2,
        TerminalStatus::Cancelled => 3,
        TerminalStatus::ResourceLimit => 4,
        TerminalStatus::InternalFailure => 5,
    })?;
    writer.u32(terminal.diagnostic_count)?;
    writer.digest(terminal.report_identity)?;
    writer.u64(terminal.usage.input_bytes)?;
    writer.u64(terminal.usage.output_bytes)?;
    writer.u32(terminal.usage.events)?;
    writer.u64(terminal.usage.event_bytes)?;
    writer.boolean(terminal.usage.comptime.is_some())?;
    if let Some(comptime) = terminal.usage.comptime {
        writer.u64(comptime.steps)?;
        writer.u64(comptime.peak_memory_bytes)?;
        writer.u32(comptime.peak_call_depth)?;
    }
    Ok(())
}

fn decode_terminal(reader: &mut Reader<'_>) -> Result<EngineTerminal, EngineProtocolError> {
    let status = match reader.u8()? {
        1 => TerminalStatus::Success,
        2 => TerminalStatus::Rejected,
        3 => TerminalStatus::Cancelled,
        4 => TerminalStatus::ResourceLimit,
        5 => TerminalStatus::InternalFailure,
        tag => {
            return Err(EngineProtocolError::InvalidTag {
                field: "terminal status",
                tag,
            });
        }
    };
    Ok(EngineTerminal {
        status,
        diagnostic_count: reader.u32()?,
        report_identity: reader.digest()?,
        usage: EngineResourceUsage {
            input_bytes: reader.u64()?,
            output_bytes: reader.u64()?,
            events: reader.u32()?,
            event_bytes: reader.u64()?,
            comptime: if reader.boolean()? {
                Some(EngineComptimeUsage {
                    steps: reader.u64()?,
                    peak_memory_bytes: reader.u64()?,
                    peak_call_depth: reader.u32()?,
                })
            } else {
                None
            },
        },
    })
}

fn validate_decoded_message(
    message: &EngineMessage,
    request_identity: Sha256Digest,
    limits: EngineProtocolLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), EngineProtocolError> {
    match message {
        EngineMessage::ClientHello(hello) => {
            check_digest(hello.launcher_identity)?;
            check_digest(hello.payload_identity)?;
            if hello.nonce.iter().all(|byte| *byte == 0) {
                return Err(EngineProtocolError::InvalidDigest);
            }
        }
        EngineMessage::ServerHello(hello) => {
            check_digest(hello.engine_identity)?;
            check_digest(hello.payload_identity)?;
            check_digest(hello.nonce_proof)?;
        }
        EngineMessage::RequestHeader(request) => {
            verify_request(request, request_identity, limits, is_cancelled)?;
        }
        EngineMessage::InputRecord { record, .. } | EngineMessage::OutputRecord { record, .. } => {
            validate_record_metadata(record, limits)?;
        }
        EngineMessage::InputChunk { bytes, .. } | EngineMessage::OutputChunk { bytes, .. } => {
            validate_chunk(bytes, limits)?
        }
        EngineMessage::InputFinish(measurement)
        | EngineMessage::OutputHeader(measurement)
        | EngineMessage::OutputFinish(measurement) => check_digest(measurement.digest)?,
        EngineMessage::Event(event) => validate_event(event)?,
        EngineMessage::Terminal(terminal) => {
            check_digest(terminal.report_identity)?;
        }
        EngineMessage::Cancel => {}
    }
    Ok(())
}

fn validate_event(event: &EngineEvent) -> Result<(), EngineProtocolError> {
    match event {
        EngineEvent::PhaseStarted { phase } | EngineEvent::PhaseFinished { phase, .. } => {
            validate_short_text(phase)
        }
        EngineEvent::Diagnostic {
            stable_id,
            code,
            message,
            path,
            line,
            column,
            ..
        } => {
            check_digest(*stable_id)?;
            validate_short_text(code)?;
            validate_message_text(message)?;
            validate_diagnostic_location(path.as_ref(), *line, *column)
        }
    }
}

fn validate_diagnostic_location(
    path: Option<&EnginePath>,
    line: u32,
    column: u32,
) -> Result<(), EngineProtocolError> {
    if (path.is_some() && (line == 0 || column == 0))
        || (path.is_none() && (line != 0 || column != 0))
    {
        Err(EngineProtocolError::InvalidText)
    } else {
        Ok(())
    }
}

struct Writer {
    bytes: Vec<u8>,
    limit: usize,
    text_limit: usize,
}

impl Writer {
    fn new(limits: EngineProtocolLimits) -> Self {
        Self {
            bytes: Vec::new(),
            limit: limits.frame_payload_bytes as usize,
            text_limit: limits.text_bytes as usize,
        }
    }

    fn reserve(&mut self, additional: usize) -> Result<(), EngineProtocolError> {
        let total =
            self.bytes
                .len()
                .checked_add(additional)
                .ok_or(EngineProtocolError::FrameTooLarge {
                    limit: self.limit as u64,
                    actual: u64::MAX,
                })?;
        if total > self.limit {
            return Err(EngineProtocolError::FrameTooLarge {
                limit: self.limit as u64,
                actual: total as u64,
            });
        }
        reserve(
            &mut self.bytes,
            additional,
            "frame payload bytes",
            self.limit as u64,
        )
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), EngineProtocolError> {
        self.reserve(value.len())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), EngineProtocolError> {
        self.bytes(&[value])
    }

    fn boolean(&mut self, value: bool) -> Result<(), EngineProtocolError> {
        self.u8(u8::from(value))
    }

    fn u32(&mut self, value: u32) -> Result<(), EngineProtocolError> {
        self.bytes(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), EngineProtocolError> {
        self.bytes(&value.to_le_bytes())
    }

    fn digest(&mut self, value: Sha256Digest) -> Result<(), EngineProtocolError> {
        check_digest(value)?;
        self.bytes(value.as_bytes())
    }

    fn string(&mut self, value: &str) -> Result<(), EngineProtocolError> {
        if value.len() > self.text_limit {
            return Err(EngineProtocolError::ResourceLimit {
                resource: "text bytes",
                limit: self.text_limit as u64,
            });
        }
        let length = u32::try_from(value.len()).map_err(|_| EngineProtocolError::InvalidText)?;
        self.u32(length)?;
        self.bytes(value.as_bytes())
    }

    fn string_cancellable(
        &mut self,
        value: &str,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), EngineProtocolError> {
        if value.len() > self.text_limit {
            return Err(EngineProtocolError::ResourceLimit {
                resource: "text bytes",
                limit: self.text_limit as u64,
            });
        }
        let length = u32::try_from(value.len()).map_err(|_| EngineProtocolError::InvalidText)?;
        self.u32(length)?;
        self.reserve(value.len())?;
        for chunk in value.as_bytes().chunks(HASH_POLL_BYTES) {
            check_cancelled(is_cancelled)?;
            self.bytes.extend_from_slice(chunk);
        }
        check_cancelled(is_cancelled)
    }

    fn byte_string(&mut self, value: &[u8]) -> Result<(), EngineProtocolError> {
        let length =
            u32::try_from(value.len()).map_err(|_| EngineProtocolError::FrameTooLarge {
                limit: self.limit as u64,
                actual: value.len() as u64,
            })?;
        self.u32(length)?;
        self.bytes(value)
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

struct Reader<'a> {
    remaining: &'a [u8],
    limits: EngineProtocolLimits,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8], limits: EngineProtocolLimits) -> Self {
        Self {
            remaining: bytes,
            limits,
        }
    }

    fn take(&mut self, bytes: usize) -> Result<&'a [u8], EngineProtocolError> {
        let (value, remaining) = self
            .remaining
            .split_at_checked(bytes)
            .ok_or(EngineProtocolError::Truncated)?;
        self.remaining = remaining;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, EngineProtocolError> {
        Ok(*self
            .take(1)?
            .first()
            .ok_or(EngineProtocolError::Truncated)?)
    }

    fn boolean(&mut self) -> Result<bool, EngineProtocolError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            tag => Err(EngineProtocolError::InvalidTag {
                field: "boolean",
                tag,
            }),
        }
    }

    fn u32(&mut self) -> Result<u32, EngineProtocolError> {
        let mut fixed = [0u8; 4];
        fixed.copy_from_slice(self.take(4)?);
        Ok(u32::from_le_bytes(fixed))
    }

    fn u64(&mut self) -> Result<u64, EngineProtocolError> {
        let mut fixed = [0u8; 8];
        fixed.copy_from_slice(self.take(8)?);
        Ok(u64::from_le_bytes(fixed))
    }

    fn fixed_32(&mut self) -> Result<[u8; 32], EngineProtocolError> {
        let mut fixed = [0u8; 32];
        fixed.copy_from_slice(self.take(32)?);
        Ok(fixed)
    }

    fn digest(&mut self) -> Result<Sha256Digest, EngineProtocolError> {
        let digest = Sha256Digest::from_bytes(self.fixed_32()?);
        check_digest(digest)?;
        Ok(digest)
    }

    fn string(&mut self) -> Result<String, EngineProtocolError> {
        let length = self.u32()? as usize;
        if length > self.limits.text_bytes as usize {
            return Err(EngineProtocolError::ResourceLimit {
                resource: "text bytes",
                limit: u64::from(self.limits.text_bytes),
            });
        }
        let value = std::str::from_utf8(self.take(length)?)
            .map_err(|_| EngineProtocolError::InvalidText)?;
        copy_string(value, self.limits.text_bytes as usize)
    }

    fn byte_string(&mut self, maximum: usize) -> Result<Vec<u8>, EngineProtocolError> {
        let length = self.u32()? as usize;
        if length > maximum {
            return Err(EngineProtocolError::ResourceLimit {
                resource: "chunk bytes",
                limit: maximum as u64,
            });
        }
        let source = self.take(length)?;
        let mut bytes = Vec::new();
        reserve(&mut bytes, source.len(), "chunk bytes", maximum as u64)?;
        bytes.extend_from_slice(source);
        Ok(bytes)
    }

    fn finish(self) -> Result<(), EngineProtocolError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(EngineProtocolError::TrailingBytes)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestStreamProgress {
    Pending,
    Complete,
    Cancelled,
}

/// One request-side action after the frame has passed canonical decoding,
/// identity/sequence checks, and the current stream-state checks. Input chunks
/// may be written to private untrusted staging immediately; publication or
/// compiler use must wait for [`ValidatedRequestAction::InputFinished`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidatedRequestAction {
    ClientHello(ClientHello),
    RequestHeader,
    InputRecord {
        index: u32,
        record: TreeRecord,
    },
    InputChunk {
        record: u32,
        offset: u64,
        bytes: Vec<u8>,
    },
    InputFinished(TreeMeasurement),
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedRequestFrame {
    progress: RequestStreamProgress,
    action: ValidatedRequestAction,
}

impl AcceptedRequestFrame {
    #[must_use]
    pub const fn progress(&self) -> RequestStreamProgress {
        self.progress
    }

    #[must_use]
    pub const fn action(&self) -> &ValidatedRequestAction {
        &self.action
    }

    #[must_use]
    pub fn into_action(self) -> ValidatedRequestAction {
        self.action
    }
}

pub struct CheckRequestStream {
    limits: EngineProtocolLimits,
    expected_launcher_identity: Sha256Digest,
    expected_engine_identity: Sha256Digest,
    expected_payload_identity: Sha256Digest,
    expected_sequence: u64,
    request_identity: Option<Sha256Digest>,
    hello: Option<ClientHello>,
    request: Option<CheckRequest>,
    manifest_seen: bool,
    lockfile_seen: bool,
    phase: RequestPhase,
}

/// Exact continuation accepted after a request tree has been fully sealed.
/// It owns only the next sequence, request identity, and protocol bounds; no
/// request body or compiler state is shared with an execution thread.
pub struct LateCancelStream {
    limits: EngineProtocolLimits,
    expected_sequence: u64,
    request_identity: Sha256Digest,
    state: LateCancelState,
}

enum LateCancelState {
    Open,
    Accepted,
    Poisoned,
}

impl LateCancelStream {
    #[must_use]
    pub const fn expected_sequence(&self) -> u64 {
        self.expected_sequence
    }

    #[must_use]
    pub const fn request_identity(&self) -> Sha256Digest {
        self.request_identity
    }

    /// Accept exactly one canonical, sequence- and request-bound `Cancel`.
    /// Any invalid frame permanently poisons this continuation.
    pub fn accept(
        &mut self,
        encoded: &[u8],
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), EngineProtocolError> {
        if !matches!(self.state, LateCancelState::Open) {
            return Err(EngineProtocolError::UnexpectedMessage {
                expected: "a new late-cancel stream",
                actual: "a frame after late-cancel completion or failure",
            });
        }
        let frame = match decode_frame(encoded, self.limits, is_cancelled) {
            Ok(frame) => frame,
            Err(error) => {
                self.state = LateCancelState::Poisoned;
                return Err(error);
            }
        };
        let result = if frame.sequence != self.expected_sequence {
            Err(EngineProtocolError::SequenceMismatch {
                expected: self.expected_sequence,
                actual: frame.sequence,
            })
        } else if frame.request_identity != self.request_identity {
            Err(EngineProtocolError::RequestIdentityMismatch)
        } else if !matches!(&frame.message, EngineMessage::Cancel) {
            Err(EngineProtocolError::UnexpectedMessage {
                expected: "Cancel",
                actual: message_name(&frame.message),
            })
        } else {
            check_cancelled(is_cancelled)
        };
        match result {
            Ok(()) => {
                self.state = LateCancelState::Accepted;
                Ok(())
            }
            Err(error) => {
                self.state = LateCancelState::Poisoned;
                Err(error)
            }
        }
    }
}

enum RequestPhase {
    ClientHello,
    Header,
    Input(Box<TreeStream>),
    Complete,
    Cancelled,
    Poisoned,
}

impl CheckRequestStream {
    pub fn new(
        expected_launcher_identity: Sha256Digest,
        expected_engine_identity: Sha256Digest,
        expected_payload_identity: Sha256Digest,
        limits: EngineProtocolLimits,
    ) -> Result<Self, EngineProtocolError> {
        limits.validate()?;
        check_digest(expected_launcher_identity)?;
        check_digest(expected_engine_identity)?;
        check_digest(expected_payload_identity)?;
        Ok(Self {
            limits,
            expected_launcher_identity,
            expected_engine_identity,
            expected_payload_identity,
            expected_sequence: 0,
            request_identity: None,
            hello: None,
            request: None,
            manifest_seen: false,
            lockfile_seen: false,
            phase: RequestPhase::ClientHello,
        })
    }

    pub fn accept(
        &mut self,
        encoded: &[u8],
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<RequestStreamProgress, EngineProtocolError> {
        self.accept_validated(encoded, is_cancelled)
            .map(|accepted| accepted.progress())
    }

    pub fn accept_validated(
        &mut self,
        encoded: &[u8],
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<AcceptedRequestFrame, EngineProtocolError> {
        if matches!(self.phase, RequestPhase::Poisoned) {
            return Err(EngineProtocolError::UnexpectedMessage {
                expected: "a new request stream",
                actual: "a frame after stream failure",
            });
        }
        let frame = match decode_frame(encoded, self.limits, is_cancelled) {
            Ok(frame) => frame,
            Err(error) => {
                self.phase = RequestPhase::Poisoned;
                return Err(error);
            }
        };
        let result = self.accept_frame(frame, is_cancelled);
        if result.is_err() {
            self.phase = RequestPhase::Poisoned;
        }
        result
    }

    #[must_use]
    pub fn hello(&self) -> Option<ClientHello> {
        self.hello
    }

    #[must_use]
    pub fn request(&self) -> Option<&CheckRequest> {
        self.request.as_ref()
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        matches!(self.phase, RequestPhase::Complete)
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        matches!(self.phase, RequestPhase::Cancelled)
    }

    /// Seal the scalar-only continuation for a possible late `Cancel` after
    /// `InputFinish`. Callers that need single ownership should consume their
    /// enclosing request executor when obtaining this value.
    pub fn late_cancel_stream(&self) -> Result<LateCancelStream, EngineProtocolError> {
        if !self.is_complete() {
            return Err(EngineProtocolError::UnexpectedMessage {
                expected: "InputFinish",
                actual: request_phase_name(&self.phase),
            });
        }
        Ok(LateCancelStream {
            limits: self.limits,
            expected_sequence: self.expected_sequence,
            request_identity: self
                .request_identity
                .ok_or(EngineProtocolError::RequestIdentityMismatch)?,
            state: LateCancelState::Open,
        })
    }

    fn accept_frame(
        &mut self,
        frame: EngineFrame,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<AcceptedRequestFrame, EngineProtocolError> {
        check_cancelled(is_cancelled)?;
        if frame.sequence != self.expected_sequence {
            return Err(EngineProtocolError::SequenceMismatch {
                expected: self.expected_sequence,
                actual: frame.sequence,
            });
        }
        if self
            .request_identity
            .is_some_and(|identity| identity != frame.request_identity)
        {
            return Err(EngineProtocolError::RequestIdentityMismatch);
        }
        let phase = std::mem::replace(&mut self.phase, RequestPhase::Poisoned);
        let (next, progress, action) = match (phase, frame.message) {
            (RequestPhase::ClientHello, EngineMessage::ClientHello(hello)) => {
                if hello.launcher_identity != self.expected_launcher_identity
                    || hello.payload_identity != self.expected_payload_identity
                {
                    return Err(EngineProtocolError::RequestIdentityMismatch);
                }
                self.request_identity = Some(frame.request_identity);
                self.hello = Some(hello);
                (
                    RequestPhase::Header,
                    RequestStreamProgress::Pending,
                    ValidatedRequestAction::ClientHello(hello),
                )
            }
            (RequestPhase::Header, EngineMessage::RequestHeader(request)) => {
                let hello = self.hello.ok_or(EngineProtocolError::UnexpectedMessage {
                    expected: "ClientHello",
                    actual: "RequestHeader",
                })?;
                if hello.payload_identity != request.payload_identity
                    || request.engine_identity != self.expected_engine_identity
                    || request.payload_identity != self.expected_payload_identity
                    || request.identity() != frame.request_identity
                {
                    return Err(EngineProtocolError::RequestIdentityMismatch);
                }
                let tree = TreeStream::new(
                    request.input,
                    TreeAllowance {
                        records: request.resources.input_records,
                        path_bytes: request.resources.input_path_bytes,
                        content_bytes: request.resources.input_content_bytes,
                    },
                    self.limits,
                )?;
                self.request = Some(*request);
                (
                    RequestPhase::Input(Box::new(tree)),
                    RequestStreamProgress::Pending,
                    ValidatedRequestAction::RequestHeader,
                )
            }
            (RequestPhase::Input(_), EngineMessage::Cancel)
            | (RequestPhase::Complete, EngineMessage::Cancel) => (
                RequestPhase::Cancelled,
                RequestStreamProgress::Cancelled,
                ValidatedRequestAction::Cancelled,
            ),
            (RequestPhase::Input(mut tree), EngineMessage::InputRecord { index, record }) => {
                let request =
                    self.request
                        .as_ref()
                        .ok_or(EngineProtocolError::UnexpectedMessage {
                            expected: "RequestHeader",
                            actual: "InputRecord",
                        })?;
                self.manifest_seen |= record.path == request.manifest;
                self.lockfile_seen |= record.path == request.lockfile;
                tree.accept_record(index, &record)?;
                (
                    RequestPhase::Input(tree),
                    RequestStreamProgress::Pending,
                    ValidatedRequestAction::InputRecord { index, record },
                )
            }
            (
                RequestPhase::Input(mut tree),
                EngineMessage::InputChunk {
                    record,
                    offset,
                    bytes,
                },
            ) => {
                tree.accept_chunk(record, offset, &bytes, is_cancelled)?;
                (
                    RequestPhase::Input(tree),
                    RequestStreamProgress::Pending,
                    ValidatedRequestAction::InputChunk {
                        record,
                        offset,
                        bytes,
                    },
                )
            }
            (RequestPhase::Input(tree), EngineMessage::InputFinish(measurement)) => {
                (*tree).finish(measurement, is_cancelled)?;
                if !self.manifest_seen || !self.lockfile_seen {
                    return Err(EngineProtocolError::TreeMeasurementMismatch);
                }
                (
                    RequestPhase::Complete,
                    RequestStreamProgress::Complete,
                    ValidatedRequestAction::InputFinished(measurement),
                )
            }
            (actual_phase, message) => {
                return Err(EngineProtocolError::UnexpectedMessage {
                    expected: request_phase_name(&actual_phase),
                    actual: message_name(&message),
                });
            }
        };
        self.expected_sequence =
            self.expected_sequence
                .checked_add(1)
                .ok_or(EngineProtocolError::ResourceLimit {
                    resource: "frame sequence",
                    limit: self.limits.frames,
                })?;
        self.phase = next;
        check_cancelled(is_cancelled)?;
        Ok(AcceptedRequestFrame { progress, action })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseStreamProgress {
    Pending,
    Complete,
}

/// One response-side action after the frame has passed canonical decoding,
/// request/handshake binding, sequencing, tree, event, and quota checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidatedResponseAction {
    ServerHello(ServerHello),
    Event(EngineEvent),
    OutputHeader(TreeMeasurement),
    OutputRecord {
        index: u32,
        record: TreeRecord,
    },
    OutputChunk {
        record: u32,
        offset: u64,
        bytes: Vec<u8>,
    },
    OutputFinished(TreeMeasurement),
    Terminal(EngineTerminal),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedResponseFrame {
    progress: ResponseStreamProgress,
    action: ValidatedResponseAction,
}

impl AcceptedResponseFrame {
    #[must_use]
    pub const fn progress(&self) -> ResponseStreamProgress {
        self.progress
    }

    #[must_use]
    pub const fn action(&self) -> &ValidatedResponseAction {
        &self.action
    }

    #[must_use]
    pub fn into_action(self) -> ValidatedResponseAction {
        self.action
    }
}

pub struct CheckResponseStream {
    limits: EngineProtocolLimits,
    expected_sequence: u64,
    request_identity: Sha256Digest,
    launcher_identity: Sha256Digest,
    engine_identity: Sha256Digest,
    payload_identity: Sha256Digest,
    nonce: [u8; 32],
    diagnostics: CheckDiagnosticPolicy,
    resources: EngineResourcePolicy,
    input: TreeMeasurement,
    observed_events: u32,
    observed_event_bytes: u64,
    observed_diagnostics: u32,
    observed_rejecting_diagnostics: u32,
    report_digest: Sha256State,
    terminal: Option<EngineTerminal>,
    phase: ResponsePhase,
}

enum ResponsePhase {
    ServerHello,
    Events,
    Output(Box<TreeStream>),
    Terminal,
    Complete,
    Poisoned,
}

impl CheckResponseStream {
    pub fn new(
        request: &CheckRequest,
        hello: ClientHello,
        limits: EngineProtocolLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Self, EngineProtocolError> {
        limits.validate()?;
        verify_request(request, request.identity(), limits, is_cancelled)?;
        check_digest(hello.launcher_identity)?;
        if hello.nonce.iter().all(|byte| *byte == 0)
            || hello.payload_identity != request.payload_identity
        {
            return Err(EngineProtocolError::RequestIdentityMismatch);
        }
        Ok(Self {
            limits,
            expected_sequence: 0,
            request_identity: request.identity(),
            launcher_identity: hello.launcher_identity,
            engine_identity: request.engine_identity,
            payload_identity: request.payload_identity,
            nonce: hello.nonce,
            diagnostics: request.diagnostics,
            resources: request.resources,
            input: request.input,
            observed_events: 0,
            observed_event_bytes: 0,
            observed_diagnostics: 0,
            observed_rejecting_diagnostics: 0,
            report_digest: check_report_digest_start(request.identity()),
            terminal: None,
            phase: ResponsePhase::ServerHello,
        })
    }

    pub fn accept(
        &mut self,
        encoded: &[u8],
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ResponseStreamProgress, EngineProtocolError> {
        self.accept_validated(encoded, is_cancelled)
            .map(|accepted| accepted.progress())
    }

    pub fn accept_validated(
        &mut self,
        encoded: &[u8],
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<AcceptedResponseFrame, EngineProtocolError> {
        if matches!(self.phase, ResponsePhase::Poisoned) {
            return Err(EngineProtocolError::UnexpectedMessage {
                expected: "a new response stream",
                actual: "a frame after stream failure",
            });
        }
        let frame = match decode_frame(encoded, self.limits, is_cancelled) {
            Ok(frame) => frame,
            Err(error) => {
                self.phase = ResponsePhase::Poisoned;
                return Err(error);
            }
        };
        let payload = &encoded[ENGINE_FRAME_HEADER_BYTES..];
        let result = self.accept_frame(frame, payload, is_cancelled);
        if result.is_err() {
            self.phase = ResponsePhase::Poisoned;
        }
        result
    }

    #[must_use]
    pub fn terminal(&self) -> Option<&EngineTerminal> {
        self.terminal.as_ref()
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        matches!(self.phase, ResponsePhase::Complete)
    }

    fn accept_frame(
        &mut self,
        frame: EngineFrame,
        payload: &[u8],
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<AcceptedResponseFrame, EngineProtocolError> {
        check_cancelled(is_cancelled)?;
        if frame.sequence != self.expected_sequence {
            return Err(EngineProtocolError::SequenceMismatch {
                expected: self.expected_sequence,
                actual: frame.sequence,
            });
        }
        if frame.request_identity != self.request_identity {
            return Err(EngineProtocolError::RequestIdentityMismatch);
        }
        let phase = std::mem::replace(&mut self.phase, ResponsePhase::Poisoned);
        let (next, progress, action) = match (phase, frame.message) {
            (ResponsePhase::ServerHello, EngineMessage::ServerHello(hello)) => {
                let expected_proof = nonce_proof(
                    self.request_identity,
                    self.launcher_identity,
                    self.engine_identity,
                    self.payload_identity,
                    self.nonce,
                    is_cancelled,
                )?;
                if hello.engine_identity != self.engine_identity
                    || hello.payload_identity != self.payload_identity
                    || hello.nonce_proof != expected_proof
                {
                    return Err(EngineProtocolError::NonceProofMismatch);
                }
                (
                    ResponsePhase::Events,
                    ResponseStreamProgress::Pending,
                    ValidatedResponseAction::ServerHello(hello),
                )
            }
            (ResponsePhase::Events, EngineMessage::Event(event)) => {
                self.observed_events = self.observed_events.checked_add(1).ok_or(
                    EngineProtocolError::ResourceLimit {
                        resource: "response events",
                        limit: u64::from(self.resources.events),
                    },
                )?;
                if self.observed_events > self.resources.events {
                    return Err(EngineProtocolError::ResourceLimit {
                        resource: "response events",
                        limit: u64::from(self.resources.events),
                    });
                }
                add_limit(
                    &mut self.observed_event_bytes,
                    payload.len() as u64,
                    "response event bytes",
                    self.resources.event_bytes,
                )?;
                update_check_report_event(
                    &mut self.report_digest,
                    self.observed_events - 1,
                    payload,
                    is_cancelled,
                )?;
                if let EngineEvent::Diagnostic { severity, .. } = &event {
                    self.observed_diagnostics = self.observed_diagnostics.checked_add(1).ok_or(
                        EngineProtocolError::ResourceLimit {
                            resource: "response diagnostics",
                            limit: u64::from(self.diagnostics.maximum_diagnostics),
                        },
                    )?;
                    if self.observed_diagnostics > self.diagnostics.maximum_diagnostics {
                        return Err(EngineProtocolError::ResourceLimit {
                            resource: "response diagnostics",
                            limit: u64::from(self.diagnostics.maximum_diagnostics),
                        });
                    }
                    if *severity == DiagnosticSeverity::Error
                        || (*severity == DiagnosticSeverity::Warning
                            && self.diagnostics.warnings_as_errors)
                    {
                        self.observed_rejecting_diagnostics = self
                            .observed_rejecting_diagnostics
                            .checked_add(1)
                            .ok_or(EngineProtocolError::TerminalPolicyMismatch)?;
                    }
                }
                (
                    ResponsePhase::Events,
                    ResponseStreamProgress::Pending,
                    ValidatedResponseAction::Event(event),
                )
            }
            (ResponsePhase::Events, EngineMessage::OutputHeader(measurement)) => {
                let empty = empty_tree_measurement(is_cancelled)?;
                if measurement != empty {
                    return Err(EngineProtocolError::TreeMeasurementMismatch);
                }
                let tree = TreeStream::new(
                    measurement,
                    TreeAllowance {
                        records: self.resources.output_records,
                        path_bytes: self.resources.output_path_bytes,
                        content_bytes: self.resources.output_content_bytes,
                    },
                    self.limits,
                )?;
                (
                    ResponsePhase::Output(Box::new(tree)),
                    ResponseStreamProgress::Pending,
                    ValidatedResponseAction::OutputHeader(measurement),
                )
            }
            (ResponsePhase::Output(mut tree), EngineMessage::OutputRecord { index, record }) => {
                tree.accept_record(index, &record)?;
                (
                    ResponsePhase::Output(tree),
                    ResponseStreamProgress::Pending,
                    ValidatedResponseAction::OutputRecord { index, record },
                )
            }
            (
                ResponsePhase::Output(mut tree),
                EngineMessage::OutputChunk {
                    record,
                    offset,
                    bytes,
                },
            ) => {
                tree.accept_chunk(record, offset, &bytes, is_cancelled)?;
                (
                    ResponsePhase::Output(tree),
                    ResponseStreamProgress::Pending,
                    ValidatedResponseAction::OutputChunk {
                        record,
                        offset,
                        bytes,
                    },
                )
            }
            (ResponsePhase::Output(tree), EngineMessage::OutputFinish(measurement)) => {
                (*tree).finish(measurement, is_cancelled)?;
                (
                    ResponsePhase::Terminal,
                    ResponseStreamProgress::Pending,
                    ValidatedResponseAction::OutputFinished(measurement),
                )
            }
            (ResponsePhase::Terminal, EngineMessage::Terminal(terminal)) => {
                self.validate_terminal(&terminal)?;
                self.terminal = Some(terminal.clone());
                (
                    ResponsePhase::Complete,
                    ResponseStreamProgress::Complete,
                    ValidatedResponseAction::Terminal(terminal),
                )
            }
            (actual_phase, message) => {
                return Err(EngineProtocolError::UnexpectedMessage {
                    expected: response_phase_name(&actual_phase),
                    actual: message_name(&message),
                });
            }
        };
        self.expected_sequence =
            self.expected_sequence
                .checked_add(1)
                .ok_or(EngineProtocolError::ResourceLimit {
                    resource: "frame sequence",
                    limit: self.limits.frames,
                })?;
        self.phase = next;
        check_cancelled(is_cancelled)?;
        Ok(AcceptedResponseFrame { progress, action })
    }

    fn validate_terminal(&self, terminal: &EngineTerminal) -> Result<(), EngineProtocolError> {
        let usage = terminal.usage;
        let mut report_digest = self.report_digest.clone();
        report_digest.update(&self.observed_events.to_le_bytes());
        report_digest.update(&self.observed_event_bytes.to_le_bytes());
        if usage.input_bytes != self.input.content_bytes
            || usage.output_bytes != 0
            || usage.events != self.observed_events
            || usage.event_bytes != self.observed_event_bytes
            || usage.comptime.is_some_and(|comptime| {
                comptime.steps > self.resources.comptime_steps
                    || comptime.peak_memory_bytes > self.resources.comptime_memory_bytes
                    || comptime.peak_call_depth > self.resources.comptime_call_depth
            })
            || terminal.diagnostic_count != self.observed_diagnostics
            || terminal.report_identity != report_digest.finish()
            || (terminal.status == TerminalStatus::Success
                && self.observed_rejecting_diagnostics != 0)
            || (terminal.status == TerminalStatus::Rejected
                && self.observed_rejecting_diagnostics == 0)
        {
            return Err(EngineProtocolError::TerminalPolicyMismatch);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct TreeAllowance {
    records: u32,
    path_bytes: u64,
    content_bytes: u64,
}

struct ActiveRecord {
    index: u32,
    bytes: u64,
    digest: Sha256Digest,
    offset: u64,
    content_digest: Sha256State,
}

struct TreeStream {
    declared: TreeMeasurement,
    allowance: TreeAllowance,
    limits: EngineProtocolLimits,
    next_record: u32,
    path_bytes: u64,
    content_bytes: u64,
    previous_path: Option<String>,
    tree_digest: Option<Sha256State>,
    active: Option<ActiveRecord>,
}

impl TreeStream {
    fn new(
        declared: TreeMeasurement,
        allowance: TreeAllowance,
        limits: EngineProtocolLimits,
    ) -> Result<Self, EngineProtocolError> {
        check_digest(declared.digest)?;
        if declared.records > allowance.records
            || declared.records > limits.tree_records
            || declared.path_bytes > allowance.path_bytes
            || declared.path_bytes > limits.tree_path_bytes
            || declared.content_bytes > allowance.content_bytes
            || declared.content_bytes > limits.tree_content_bytes
        {
            return Err(EngineProtocolError::TreeMeasurementMismatch);
        }
        Ok(Self {
            declared,
            allowance,
            limits,
            next_record: 0,
            path_bytes: 0,
            content_bytes: 0,
            previous_path: None,
            tree_digest: Some(tree_digest_start(declared.records)),
            active: None,
        })
    }

    fn accept_record(
        &mut self,
        index: u32,
        record: &TreeRecord,
    ) -> Result<(), EngineProtocolError> {
        if self.active.is_some() {
            return Err(EngineProtocolError::UnexpectedMessage {
                expected: "a chunk completing the active tree record",
                actual: "another tree record",
            });
        }
        if index != self.next_record {
            return Err(EngineProtocolError::RecordIndexMismatch {
                expected: self.next_record,
                actual: index,
            });
        }
        if index >= self.declared.records || index >= self.allowance.records {
            return Err(EngineProtocolError::ResourceLimit {
                resource: "tree records",
                limit: u64::from(self.allowance.records),
            });
        }
        validate_record_metadata(record, self.limits)?;
        if self
            .previous_path
            .as_deref()
            .is_some_and(|previous| previous >= record.path.as_str())
        {
            return Err(EngineProtocolError::TreeOrder);
        }
        add_limit(
            &mut self.path_bytes,
            record.path.as_str().len() as u64,
            "tree path bytes",
            self.allowance.path_bytes,
        )?;
        add_limit(
            &mut self.content_bytes,
            record.bytes,
            "tree content bytes",
            self.allowance.content_bytes,
        )?;
        if self.path_bytes > self.declared.path_bytes
            || self.content_bytes > self.declared.content_bytes
        {
            return Err(EngineProtocolError::TreeMeasurementMismatch);
        }
        let path = copy_string(
            record.path.as_str(),
            self.limits.path_bytes_per_record as usize,
        )?;
        self.previous_path = Some(path);
        update_tree_record(
            self.tree_digest
                .as_mut()
                .ok_or(EngineProtocolError::TreeMeasurementMismatch)?,
            record,
        );
        self.next_record =
            self.next_record
                .checked_add(1)
                .ok_or(EngineProtocolError::ResourceLimit {
                    resource: "tree records",
                    limit: u64::from(self.allowance.records),
                })?;
        let active = ActiveRecord {
            index,
            bytes: record.bytes,
            digest: record.digest,
            offset: 0,
            content_digest: Sha256State::new(),
        };
        if active.bytes == 0 {
            if active.content_digest.finish() != active.digest {
                return Err(EngineProtocolError::RecordDigestMismatch);
            }
        } else {
            self.active = Some(active);
        }
        Ok(())
    }

    fn accept_chunk(
        &mut self,
        record: u32,
        offset: u64,
        bytes: &[u8],
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), EngineProtocolError> {
        check_cancelled(is_cancelled)?;
        validate_chunk(bytes, self.limits)?;
        let active = self
            .active
            .as_mut()
            .ok_or(EngineProtocolError::UnexpectedMessage {
                expected: "a tree record",
                actual: "a tree chunk",
            })?;
        if record != active.index {
            return Err(EngineProtocolError::RecordIndexMismatch {
                expected: active.index,
                actual: record,
            });
        }
        if offset != active.offset {
            return Err(EngineProtocolError::ChunkOffsetMismatch {
                expected: active.offset,
                actual: offset,
            });
        }
        let chunk_bytes = bytes.len() as u64;
        let next =
            active
                .offset
                .checked_add(chunk_bytes)
                .ok_or(EngineProtocolError::ResourceLimit {
                    resource: "tree record bytes",
                    limit: active.bytes,
                })?;
        if next > active.bytes {
            return Err(EngineProtocolError::ResourceLimit {
                resource: "tree record bytes",
                limit: active.bytes,
            });
        }
        active.content_digest.update(bytes);
        active.offset = next;
        if next == active.bytes {
            let completed = self
                .active
                .take()
                .ok_or(EngineProtocolError::TreeMeasurementMismatch)?;
            if completed.content_digest.finish() != completed.digest {
                return Err(EngineProtocolError::RecordDigestMismatch);
            }
        }
        check_cancelled(is_cancelled)
    }

    fn finish(
        mut self,
        provided: TreeMeasurement,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), EngineProtocolError> {
        check_cancelled(is_cancelled)?;
        if self.active.is_some()
            || self.next_record != self.declared.records
            || self.path_bytes != self.declared.path_bytes
            || self.content_bytes != self.declared.content_bytes
            || provided != self.declared
        {
            return Err(EngineProtocolError::TreeMeasurementMismatch);
        }
        let measured = TreeMeasurement {
            digest: self
                .tree_digest
                .take()
                .ok_or(EngineProtocolError::TreeMeasurementMismatch)?
                .finish(),
            records: self.next_record,
            content_bytes: self.content_bytes,
            path_bytes: self.path_bytes,
        };
        if measured != self.declared {
            return Err(EngineProtocolError::TreeMeasurementMismatch);
        }
        check_cancelled(is_cancelled)
    }
}

fn request_phase_name(phase: &RequestPhase) -> &'static str {
    match phase {
        RequestPhase::ClientHello => "ClientHello",
        RequestPhase::Header => "RequestHeader or Cancel",
        RequestPhase::Input(_) => "InputRecord, InputChunk, InputFinish, or Cancel",
        RequestPhase::Complete => "Cancel or end of request stream",
        RequestPhase::Cancelled => "end of cancelled request stream",
        RequestPhase::Poisoned => "a new request stream",
    }
}

fn response_phase_name(phase: &ResponsePhase) -> &'static str {
    match phase {
        ResponsePhase::ServerHello => "ServerHello",
        ResponsePhase::Events => "Event or OutputHeader",
        ResponsePhase::Output(_) => "OutputRecord, OutputChunk, or OutputFinish",
        ResponsePhase::Terminal => "Terminal",
        ResponsePhase::Complete => "end of response stream",
        ResponsePhase::Poisoned => "a new response stream",
    }
}

fn message_name(message: &EngineMessage) -> &'static str {
    match message {
        EngineMessage::ClientHello(_) => "ClientHello",
        EngineMessage::ServerHello(_) => "ServerHello",
        EngineMessage::RequestHeader(_) => "RequestHeader",
        EngineMessage::InputRecord { .. } => "InputRecord",
        EngineMessage::InputChunk { .. } => "InputChunk",
        EngineMessage::InputFinish(_) => "InputFinish",
        EngineMessage::Cancel => "Cancel",
        EngineMessage::Event(_) => "Event",
        EngineMessage::OutputHeader(_) => "OutputHeader",
        EngineMessage::OutputRecord { .. } => "OutputRecord",
        EngineMessage::OutputChunk { .. } => "OutputChunk",
        EngineMessage::OutputFinish(_) => "OutputFinish",
        EngineMessage::Terminal(_) => "Terminal",
    }
}

fn portable_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PORTABLE_PATH_BYTES
        && !value.starts_with('/')
        && !value.starts_with('\\')
        && !value.ends_with('/')
        && !value.contains('\\')
        && !value.contains(':')
        && !value.chars().any(char::is_control)
        && value.split('/').all(|component| {
            !component.is_empty()
                && !matches!(component, "." | "..")
                && !component.ends_with(['.', ' '])
        })
}

fn valid_atom(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn validate_short_text(value: &str) -> Result<(), EngineProtocolError> {
    if value.is_empty()
        || value.len() > 4096
        || value
            .chars()
            .any(|character| character.is_control() || character == '\0')
    {
        Err(EngineProtocolError::InvalidText)
    } else {
        Ok(())
    }
}

fn validate_message_text(value: &str) -> Result<(), EngineProtocolError> {
    if value.is_empty()
        || value.len() > 1024 * 1024
        || value.chars().any(|character| {
            character == '\0'
                || (character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        })
    {
        Err(EngineProtocolError::InvalidText)
    } else {
        Ok(())
    }
}

fn validate_record_metadata(
    record: &TreeRecord,
    limits: EngineProtocolLimits,
) -> Result<(), EngineProtocolError> {
    if record.path.as_str().len() > limits.path_bytes_per_record as usize {
        return Err(EngineProtocolError::ResourceLimit {
            resource: "tree path bytes per record",
            limit: u64::from(limits.path_bytes_per_record),
        });
    }
    if record.bytes > limits.tree_content_bytes {
        return Err(EngineProtocolError::ResourceLimit {
            resource: "tree content bytes",
            limit: limits.tree_content_bytes,
        });
    }
    check_digest(record.digest)
}

fn validate_chunk(bytes: &[u8], limits: EngineProtocolLimits) -> Result<(), EngineProtocolError> {
    if bytes.is_empty() {
        return Err(EngineProtocolError::EmptyChunk);
    }
    let maximum = ENGINE_MAX_CHUNK_BYTES.min(limits.frame_payload_bytes as usize);
    if bytes.len() > maximum {
        return Err(EngineProtocolError::ResourceLimit {
            resource: "chunk bytes",
            limit: maximum as u64,
        });
    }
    Ok(())
}

fn check_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), EngineProtocolError> {
    if is_cancelled() {
        Err(EngineProtocolError::Cancelled)
    } else {
        Ok(())
    }
}

fn digest_is_zero(digest: Sha256Digest) -> bool {
    digest.as_bytes().iter().all(|byte| *byte == 0)
}

fn check_digest(digest: Sha256Digest) -> Result<(), EngineProtocolError> {
    if digest_is_zero(digest) {
        Err(EngineProtocolError::InvalidDigest)
    } else {
        Ok(())
    }
}

fn reserve(
    bytes: &mut Vec<u8>,
    additional: usize,
    resource: &'static str,
    limit: u64,
) -> Result<(), EngineProtocolError> {
    bytes
        .try_reserve(additional)
        .map_err(|_| EngineProtocolError::ResourceLimit { resource, limit })
}

fn copy_string(value: &str, limit: usize) -> Result<String, EngineProtocolError> {
    let mut copied = String::new();
    copied
        .try_reserve(value.len())
        .map_err(|_| EngineProtocolError::ResourceLimit {
            resource: "text bytes",
            limit: limit as u64,
        })?;
    copied.push_str(value);
    Ok(copied)
}

fn usize_u64(value: usize, resource: &'static str, limit: u64) -> Result<u64, EngineProtocolError> {
    u64::try_from(value).map_err(|_| EngineProtocolError::ResourceLimit { resource, limit })
}

fn add_limit(
    total: &mut u64,
    additional: u64,
    resource: &'static str,
    limit: u64,
) -> Result<(), EngineProtocolError> {
    *total = total
        .checked_add(additional)
        .ok_or(EngineProtocolError::ResourceLimit { resource, limit })?;
    if *total > limit {
        return Err(EngineProtocolError::ResourceLimit { resource, limit });
    }
    Ok(())
}

fn fixed_u16(bytes: &[u8], offset: usize) -> Result<u16, EngineProtocolError> {
    let mut fixed = [0u8; 2];
    fixed.copy_from_slice(
        bytes
            .get(offset..offset + 2)
            .ok_or(EngineProtocolError::Truncated)?,
    );
    Ok(u16::from_le_bytes(fixed))
}

fn fixed_u32(bytes: &[u8], offset: usize) -> Result<u32, EngineProtocolError> {
    let mut fixed = [0u8; 4];
    fixed.copy_from_slice(
        bytes
            .get(offset..offset + 4)
            .ok_or(EngineProtocolError::Truncated)?,
    );
    Ok(u32::from_le_bytes(fixed))
}

fn fixed_u64(bytes: &[u8], offset: usize) -> Result<u64, EngineProtocolError> {
    let mut fixed = [0u8; 8];
    fixed.copy_from_slice(
        bytes
            .get(offset..offset + 8)
            .ok_or(EngineProtocolError::Truncated)?,
    );
    Ok(u64::from_le_bytes(fixed))
}

fn fixed_digest(bytes: &[u8], offset: usize) -> Result<Sha256Digest, EngineProtocolError> {
    let mut fixed = [0u8; DIGEST_BYTES];
    fixed.copy_from_slice(
        bytes
            .get(offset..offset + DIGEST_BYTES)
            .ok_or(EngineProtocolError::Truncated)?,
    );
    Ok(Sha256Digest::from_bytes(fixed))
}

fn tree_digest_start(records: u32) -> Sha256State {
    let mut digest = Sha256State::new();
    digest.update(TREE_MAGIC);
    digest.update(&TREE_ENCODING_VERSION.to_le_bytes());
    digest.update(&records.to_le_bytes());
    digest
}

fn update_tree_record(digest: &mut Sha256State, record: &TreeRecord) {
    digest.update(&[record.mode.tag()]);
    update_hashed_bytes(digest, record.path.as_str().as_bytes());
    digest.update(&record.bytes.to_le_bytes());
    digest.update(record.digest.as_bytes());
}

fn update_hashed_bytes(digest: &mut Sha256State, bytes: &[u8]) {
    digest.update(&(bytes.len() as u64).to_le_bytes());
    digest.update(bytes);
}

fn update_resource_policy(digest: &mut Sha256State, policy: EngineResourcePolicy) {
    digest.update(&policy.input_records.to_le_bytes());
    digest.update(&policy.input_path_bytes.to_le_bytes());
    digest.update(&policy.input_content_bytes.to_le_bytes());
    digest.update(&policy.output_records.to_le_bytes());
    digest.update(&policy.output_path_bytes.to_le_bytes());
    digest.update(&policy.output_content_bytes.to_le_bytes());
    digest.update(&policy.events.to_le_bytes());
    digest.update(&policy.event_bytes.to_le_bytes());
    digest.update(&policy.comptime_steps.to_le_bytes());
    digest.update(&policy.comptime_memory_bytes.to_le_bytes());
    digest.update(&policy.comptime_call_depth.to_le_bytes());
}

fn update_tree_measurement(digest: &mut Sha256State, measurement: TreeMeasurement) {
    digest.update(measurement.digest.as_bytes());
    digest.update(&measurement.records.to_le_bytes());
    digest.update(&measurement.content_bytes.to_le_bytes());
    digest.update(&measurement.path_bytes.to_le_bytes());
}

fn check_report_digest_start(request_identity: Sha256Digest) -> Sha256State {
    let mut digest = Sha256State::new();
    digest.update(CHECK_REPORT_MAGIC);
    digest.update(&CHECK_REPORT_VERSION.to_le_bytes());
    digest.update(request_identity.as_bytes());
    digest
}

fn update_check_report_event(
    digest: &mut Sha256State,
    sequence: u32,
    payload: &[u8],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), EngineProtocolError> {
    check_cancelled(is_cancelled)?;
    digest.update(&sequence.to_le_bytes());
    digest.update(&(payload.len() as u64).to_le_bytes());
    for chunk in payload.chunks(HASH_POLL_BYTES) {
        check_cancelled(is_cancelled)?;
        digest.update(chunk);
    }
    check_cancelled(is_cancelled)
}

const SHA256_INITIAL_STATE: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const SHA256_ROUND_CONSTANTS: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

#[derive(Clone)]
struct Sha256State {
    state: [u32; 8],
    buffer: [u8; 64],
    buffer_len: usize,
    total_bytes: u128,
}

impl Sha256State {
    const fn new() -> Self {
        Self {
            state: SHA256_INITIAL_STATE,
            buffer: [0; 64],
            buffer_len: 0,
            total_bytes: 0,
        }
    }

    fn update(&mut self, mut bytes: &[u8]) {
        self.total_bytes = self.total_bytes.saturating_add(bytes.len() as u128);
        if self.buffer_len != 0 {
            let take = (64 - self.buffer_len).min(bytes.len());
            let end = self.buffer_len + take;
            self.buffer[self.buffer_len..end].copy_from_slice(&bytes[..take]);
            self.buffer_len = end;
            bytes = &bytes[take..];
            if self.buffer_len == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffer_len = 0;
            }
        }
        while bytes.len() >= 64 {
            let (block, remaining) = bytes.split_at(64);
            let mut fixed = [0u8; 64];
            fixed.copy_from_slice(block);
            self.compress(&fixed);
            bytes = remaining;
        }
        if !bytes.is_empty() {
            self.buffer[..bytes.len()].copy_from_slice(bytes);
            self.buffer_len = bytes.len();
        }
    }

    fn finish(mut self) -> Sha256Digest {
        let bit_length = self.total_bytes.wrapping_mul(8) as u64;
        self.buffer[self.buffer_len] = 0x80;
        self.buffer_len += 1;
        if self.buffer_len > 56 {
            self.buffer[self.buffer_len..].fill(0);
            let block = self.buffer;
            self.compress(&block);
            self.buffer = [0; 64];
            self.buffer_len = 0;
        }
        self.buffer[self.buffer_len..56].fill(0);
        self.buffer[56..64].copy_from_slice(&bit_length.to_be_bytes());
        let block = self.buffer;
        self.compress(&block);
        let mut bytes = [0u8; 32];
        for (word, destination) in self.state.iter().zip(bytes.chunks_exact_mut(4)) {
            destination.copy_from_slice(&word.to_be_bytes());
        }
        Sha256Digest::from_bytes(bytes)
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut schedule = [0u32; 64];
        for (index, word) in block.chunks_exact(4).enumerate() {
            let mut fixed = [0u8; 4];
            fixed.copy_from_slice(word);
            schedule[index] = u32::from_be_bytes(fixed);
        }
        for index in 16..64 {
            let s0 = schedule[index - 15].rotate_right(7)
                ^ schedule[index - 15].rotate_right(18)
                ^ (schedule[index - 15] >> 3);
            let s1 = schedule[index - 2].rotate_right(17)
                ^ schedule[index - 2].rotate_right(19)
                ^ (schedule[index - 2] >> 10);
            schedule[index] = schedule[index - 16]
                .wrapping_add(s0)
                .wrapping_add(schedule[index - 7])
                .wrapping_add(s1);
        }
        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];
        for (constant, word) in SHA256_ROUND_CONSTANTS.iter().zip(schedule) {
            let sum1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temporary1 = h
                .wrapping_add(sum1)
                .wrapping_add(choice)
                .wrapping_add(*constant)
                .wrapping_add(word);
            let sum0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temporary2 = sum0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temporary1);
            d = c;
            c = b;
            b = a;
            a = temporary1.wrapping_add(temporary2);
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }
}
