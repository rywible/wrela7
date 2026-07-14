//! Canonical framed protocol between the frontend driver and private backend.
//!
//! This is an implementation boundary, not a public language ABI. Every frame
//! carries an exact protocol version and is bounded before allocation.

#![forbid(unsafe_code)]

use std::fmt;

use wrela_build_model::{
    BuildConfiguration, BuildIdentity, BuildMode, BuildProfile, ComptimeLimits, DiagnosticPolicy,
    DmaPolicy, LanguageRevision, MemoryLimits, OptimizationLevel, OptimizationPolicy,
    RecordingMode, RecoveryPolicy, Sha256Digest, TargetIdentity, ValidatedBuildConfiguration,
};

pub const PROTOCOL_VERSION: u32 = 4;
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;
const MAX_TEXT_BYTES: usize = 1024 * 1024;
const MAGIC: &[u8; 8] = b"WRELBEP\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequestId(pub u64);

/// UTF-8 path inside the driver's private controlled build directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendPath(String);

impl BackendPath {
    pub fn new(value: impl Into<String>) -> Result<Self, ProtocolError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ProtocolError::InvalidPath("path is empty".to_owned()));
        }
        if value.contains('\0') {
            return Err(ProtocolError::InvalidPath("path contains NUL".to_owned()));
        }
        if value.starts_with('/') || value.starts_with('\\') || value.contains(':') {
            return Err(ProtocolError::InvalidPath(
                "path must be relative to the private build directory".to_owned(),
            ));
        }
        if value.contains('\\') {
            return Err(ProtocolError::InvalidPath(
                "path must use canonical forward-slash separators".to_owned(),
            ));
        }
        if value
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
        {
            return Err(ProtocolError::InvalidPath(
                "path contains an empty, current-directory, or parent component".to_owned(),
            ));
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One complete backend invocation. The backend independently checks that WIR,
/// target package, and build identity agree before invoking LLVM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendRequest {
    pub request_id: RequestId,
    pub build: BuildConfiguration,
    pub wir: BackendPath,
    /// SHA-256 of the exact canonical FlowWir frame at `wir`.
    pub wir_digest: Sha256Digest,
    pub target_package: BackendPath,
    pub output: BackendPath,
    pub report: BackendPath,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendSuccess {
    pub artifact: BackendPath,
    pub artifact_digest: Sha256Digest,
    pub report: BackendPath,
    pub report_digest: Sha256Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendFailureKind {
    Protocol,
    Input,
    Target,
    Verification,
    Codegen,
    Link,
    Report,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendFailure {
    pub kind: BackendFailureKind,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendOutcome {
    Success(BackendSuccess),
    Failure(BackendFailure),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendResponse {
    pub request_id: RequestId,
    pub outcome: BackendOutcome,
}

pub fn encode_request(
    request: &BackendRequest,
    build: &ValidatedBuildConfiguration,
) -> Result<Vec<u8>, ProtocolError> {
    if request.build != *build.as_configuration() {
        return Err(ProtocolError::BuildConfigurationMismatch);
    }
    request
        .build
        .validate()
        .map_err(|error| ProtocolError::InvalidProfile(error.to_string()))?;
    let mut payload = Vec::new();
    push_u64(&mut payload, request.request_id.0);
    encode_configuration(&mut payload, &request.build)?;
    push_digest(&mut payload, request.wir_digest);
    for path in [
        &request.wir,
        &request.target_package,
        &request.output,
        &request.report,
    ] {
        push_string(&mut payload, path.as_str())?;
    }
    frame(MessageKind::Request, payload)
}

pub fn decode_request(bytes: &[u8]) -> Result<BackendRequest, ProtocolError> {
    let mut reader = unframe(bytes, MessageKind::Request)?;
    let request_id = RequestId(reader.u64()?);
    let build = decode_configuration(&mut reader)?;
    let wir_digest = reader.digest()?;
    let request = BackendRequest {
        request_id,
        build,
        wir: BackendPath::new(reader.string()?)?,
        wir_digest,
        target_package: BackendPath::new(reader.string()?)?,
        output: BackendPath::new(reader.string()?)?,
        report: BackendPath::new(reader.string()?)?,
    };
    reader.finish()?;
    request
        .build
        .validate()
        .map_err(|error| ProtocolError::InvalidProfile(error.to_string()))?;
    Ok(request)
}

pub fn encode_response(response: &BackendResponse) -> Result<Vec<u8>, ProtocolError> {
    let mut payload = Vec::new();
    push_u64(&mut payload, response.request_id.0);
    match &response.outcome {
        BackendOutcome::Success(success) => {
            push_u8(&mut payload, 0);
            push_string(&mut payload, success.artifact.as_str())?;
            push_digest(&mut payload, success.artifact_digest);
            push_string(&mut payload, success.report.as_str())?;
            push_digest(&mut payload, success.report_digest);
        }
        BackendOutcome::Failure(failure) => {
            push_u8(&mut payload, 1);
            push_u8(&mut payload, failure_kind_tag(failure.kind));
            push_string(&mut payload, &failure.message)?;
        }
    }
    frame(MessageKind::Response, payload)
}

pub fn decode_response(bytes: &[u8]) -> Result<BackendResponse, ProtocolError> {
    let mut reader = unframe(bytes, MessageKind::Response)?;
    let request_id = RequestId(reader.u64()?);
    let outcome = match reader.u8()? {
        0 => BackendOutcome::Success(BackendSuccess {
            artifact: BackendPath::new(reader.string()?)?,
            artifact_digest: reader.digest()?,
            report: BackendPath::new(reader.string()?)?,
            report_digest: reader.digest()?,
        }),
        1 => BackendOutcome::Failure(BackendFailure {
            kind: decode_failure_kind(reader.u8()?)?,
            message: reader.string()?,
        }),
        tag => return Err(ProtocolError::InvalidOutcomeTag(tag)),
    };
    reader.finish()?;
    Ok(BackendResponse {
        request_id,
        outcome,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MessageKind {
    Request = 1,
    Response = 2,
}

fn frame(kind: MessageKind, payload: Vec<u8>) -> Result<Vec<u8>, ProtocolError> {
    if payload.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge(payload.len()));
    }
    let length: u32 = payload
        .len()
        .try_into()
        .map_err(|_| ProtocolError::FrameTooLarge(payload.len()))?;
    let mut frame = Vec::with_capacity(MAGIC.len() + 9 + payload.len());
    frame.extend_from_slice(MAGIC);
    push_u32(&mut frame, PROTOCOL_VERSION);
    push_u8(&mut frame, kind as u8);
    push_u32(&mut frame, length);
    frame.extend_from_slice(&payload);
    Ok(frame)
}

fn unframe(bytes: &[u8], expected: MessageKind) -> Result<Reader<'_>, ProtocolError> {
    if bytes.len() > MAX_FRAME_BYTES + MAGIC.len() + 9 {
        return Err(ProtocolError::FrameTooLarge(bytes.len()));
    }
    let mut reader = Reader::new(bytes);
    if reader.take(MAGIC.len())? != MAGIC {
        return Err(ProtocolError::InvalidMagic);
    }
    let version = reader.u32()?;
    if version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(version));
    }
    let kind = reader.u8()?;
    if kind != expected as u8 {
        return Err(ProtocolError::UnexpectedMessageKind(kind));
    }
    let length = reader.u32()? as usize;
    if length > MAX_FRAME_BYTES {
        return Err(ProtocolError::FrameTooLarge(length));
    }
    if reader.remaining.len() != length {
        return Err(ProtocolError::FrameLengthMismatch {
            declared: length,
            actual: reader.remaining.len(),
        });
    }
    Ok(reader)
}

fn encode_configuration(
    bytes: &mut Vec<u8>,
    configuration: &BuildConfiguration,
) -> Result<(), ProtocolError> {
    encode_identity(bytes, &configuration.identity)?;
    encode_profile(bytes, &configuration.profile)
}

fn decode_configuration(reader: &mut Reader<'_>) -> Result<BuildConfiguration, ProtocolError> {
    Ok(BuildConfiguration {
        identity: decode_identity(reader)?,
        profile: decode_profile(reader)?,
    })
}

fn encode_identity(bytes: &mut Vec<u8>, identity: &BuildIdentity) -> Result<(), ProtocolError> {
    push_digest(bytes, identity.compiler);
    push_u8(bytes, language_tag(identity.language));
    push_string(bytes, identity.target.as_str())?;
    push_digest(bytes, identity.target_package);
    push_digest(bytes, identity.standard_library);
    push_digest(bytes, identity.source_graph);
    push_digest(bytes, identity.request);
    push_digest(bytes, identity.profile);
    Ok(())
}

fn decode_identity(reader: &mut Reader<'_>) -> Result<BuildIdentity, ProtocolError> {
    let compiler = reader.digest()?;
    let language = decode_language(reader.u8()?)?;
    let target = TargetIdentity::new(reader.string()?)
        .map_err(|error| ProtocolError::InvalidTarget(error.to_string()))?;
    Ok(BuildIdentity {
        compiler,
        language,
        target,
        target_package: reader.digest()?,
        standard_library: reader.digest()?,
        source_graph: reader.digest()?,
        request: reader.digest()?,
        profile: reader.digest()?,
    })
}

fn encode_profile(bytes: &mut Vec<u8>, profile: &BuildProfile) -> Result<(), ProtocolError> {
    push_string(bytes, &profile.name)?;
    push_u8(bytes, mode_tag(profile.mode));
    push_u64(bytes, profile.comptime.steps);
    push_u64(bytes, profile.comptime.memory_bytes);
    push_u32(bytes, profile.comptime.call_depth);
    push_u64(bytes, profile.memory.static_bytes);
    push_u64(bytes, profile.memory.peak_bytes);
    push_u64(bytes, profile.memory.event_log_bytes);
    push_bool(bytes, profile.dma.coherent);
    push_bool(bytes, profile.dma.require_iommu);
    push_u64(bytes, profile.recovery.reset_timeout_ns);
    push_u64(bytes, profile.recovery.quarantine_bytes);
    push_u8(bytes, recording_tag(profile.recording));
    push_u8(bytes, optimization_tag(profile.optimization.level));
    match profile.optimization.profile_data {
        Some(digest) => {
            push_bool(bytes, true);
            push_digest(bytes, digest);
        }
        None => push_bool(bytes, false),
    }
    push_bool(bytes, profile.diagnostics.sealed_deployment);
    push_bool(bytes, profile.diagnostics.warnings_as_errors);
    push_bool(bytes, profile.diagnostics.watchdogs);
    Ok(())
}

fn decode_profile(reader: &mut Reader<'_>) -> Result<BuildProfile, ProtocolError> {
    let name = reader.string()?;
    let mode = decode_mode(reader.u8()?)?;
    let comptime = ComptimeLimits {
        steps: reader.u64()?,
        memory_bytes: reader.u64()?,
        call_depth: reader.u32()?,
    };
    let memory = MemoryLimits {
        static_bytes: reader.u64()?,
        peak_bytes: reader.u64()?,
        event_log_bytes: reader.u64()?,
    };
    let dma = DmaPolicy {
        coherent: reader.boolean()?,
        require_iommu: reader.boolean()?,
    };
    let recovery = RecoveryPolicy {
        reset_timeout_ns: reader.u64()?,
        quarantine_bytes: reader.u64()?,
    };
    let recording = decode_recording(reader.u8()?)?;
    let level = decode_optimization(reader.u8()?)?;
    let profile_data = if reader.boolean()? {
        Some(reader.digest()?)
    } else {
        None
    };
    let diagnostics = DiagnosticPolicy {
        sealed_deployment: reader.boolean()?,
        warnings_as_errors: reader.boolean()?,
        watchdogs: reader.boolean()?,
    };
    Ok(BuildProfile {
        name,
        mode,
        comptime,
        memory,
        dma,
        recovery,
        recording,
        optimization: OptimizationPolicy {
            level,
            profile_data,
        },
        diagnostics,
    })
}

fn language_tag(value: LanguageRevision) -> u8 {
    match value {
        LanguageRevision::Design0_1 => 1,
    }
}

fn decode_language(tag: u8) -> Result<LanguageRevision, ProtocolError> {
    match tag {
        1 => Ok(LanguageRevision::Design0_1),
        _ => Err(ProtocolError::InvalidEnumTag("language revision", tag)),
    }
}

fn mode_tag(value: BuildMode) -> u8 {
    match value {
        BuildMode::Development => 1,
        BuildMode::Release => 2,
    }
}

fn decode_mode(tag: u8) -> Result<BuildMode, ProtocolError> {
    match tag {
        1 => Ok(BuildMode::Development),
        2 => Ok(BuildMode::Release),
        _ => Err(ProtocolError::InvalidEnumTag("build mode", tag)),
    }
}

fn recording_tag(value: RecordingMode) -> u8 {
    match value {
        RecordingMode::Disabled => 0,
        RecordingMode::Record => 1,
        RecordingMode::Replay => 2,
    }
}

fn decode_recording(tag: u8) -> Result<RecordingMode, ProtocolError> {
    match tag {
        0 => Ok(RecordingMode::Disabled),
        1 => Ok(RecordingMode::Record),
        2 => Ok(RecordingMode::Replay),
        _ => Err(ProtocolError::InvalidEnumTag("recording mode", tag)),
    }
}

fn optimization_tag(value: OptimizationLevel) -> u8 {
    match value {
        OptimizationLevel::None => 0,
        OptimizationLevel::Development => 1,
        OptimizationLevel::Performance => 2,
        OptimizationLevel::Size => 3,
    }
}

fn decode_optimization(tag: u8) -> Result<OptimizationLevel, ProtocolError> {
    match tag {
        0 => Ok(OptimizationLevel::None),
        1 => Ok(OptimizationLevel::Development),
        2 => Ok(OptimizationLevel::Performance),
        3 => Ok(OptimizationLevel::Size),
        _ => Err(ProtocolError::InvalidEnumTag("optimization level", tag)),
    }
}

fn failure_kind_tag(value: BackendFailureKind) -> u8 {
    match value {
        BackendFailureKind::Protocol => 0,
        BackendFailureKind::Input => 1,
        BackendFailureKind::Target => 2,
        BackendFailureKind::Verification => 3,
        BackendFailureKind::Codegen => 4,
        BackendFailureKind::Link => 5,
        BackendFailureKind::Report => 6,
        BackendFailureKind::Internal => 7,
    }
}

fn decode_failure_kind(tag: u8) -> Result<BackendFailureKind, ProtocolError> {
    match tag {
        0 => Ok(BackendFailureKind::Protocol),
        1 => Ok(BackendFailureKind::Input),
        2 => Ok(BackendFailureKind::Target),
        3 => Ok(BackendFailureKind::Verification),
        4 => Ok(BackendFailureKind::Codegen),
        5 => Ok(BackendFailureKind::Link),
        6 => Ok(BackendFailureKind::Report),
        7 => Ok(BackendFailureKind::Internal),
        _ => Err(ProtocolError::InvalidEnumTag("backend failure kind", tag)),
    }
}

fn push_u8(bytes: &mut Vec<u8>, value: u8) {
    bytes.push(value);
}

fn push_bool(bytes: &mut Vec<u8>, value: bool) {
    push_u8(bytes, u8::from(value));
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_digest(bytes: &mut Vec<u8>, value: Sha256Digest) {
    bytes.extend_from_slice(value.as_bytes());
}

fn push_string(bytes: &mut Vec<u8>, value: &str) -> Result<(), ProtocolError> {
    if value.len() > MAX_TEXT_BYTES {
        return Err(ProtocolError::TextTooLong(value.len()));
    }
    let length: u32 = value
        .len()
        .try_into()
        .map_err(|_| ProtocolError::TextTooLong(value.len()))?;
    push_u32(bytes, length);
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

struct Reader<'a> {
    remaining: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], ProtocolError> {
        if self.remaining.len() < length {
            return Err(ProtocolError::UnexpectedEnd);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.take(1)?[0])
    }

    fn boolean(&mut self) -> Result<bool, ProtocolError> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            tag => Err(ProtocolError::InvalidBoolean(tag)),
        }
    }

    fn u32(&mut self) -> Result<u32, ProtocolError> {
        let bytes: [u8; 4] = self
            .take(4)?
            .try_into()
            .map_err(|_| ProtocolError::UnexpectedEnd)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, ProtocolError> {
        let bytes: [u8; 8] = self
            .take(8)?
            .try_into()
            .map_err(|_| ProtocolError::UnexpectedEnd)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn digest(&mut self) -> Result<Sha256Digest, ProtocolError> {
        let bytes: [u8; 32] = self
            .take(32)?
            .try_into()
            .map_err(|_| ProtocolError::UnexpectedEnd)?;
        Ok(Sha256Digest::from_bytes(bytes))
    }

    fn string(&mut self) -> Result<String, ProtocolError> {
        let length = self.u32()? as usize;
        if length > MAX_TEXT_BYTES {
            return Err(ProtocolError::TextTooLong(length));
        }
        let bytes = self.take(length)?;
        let value = std::str::from_utf8(bytes).map_err(|_| ProtocolError::InvalidUtf8)?;
        Ok(value.to_owned())
    }

    fn finish(self) -> Result<(), ProtocolError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(ProtocolError::TrailingBytes)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    InvalidMagic,
    UnsupportedVersion(u32),
    UnexpectedMessageKind(u8),
    FrameTooLarge(usize),
    FrameLengthMismatch { declared: usize, actual: usize },
    UnexpectedEnd,
    TrailingBytes,
    InvalidUtf8,
    TextTooLong(usize),
    InvalidBoolean(u8),
    InvalidEnumTag(&'static str, u8),
    InvalidOutcomeTag(u8),
    InvalidPath(String),
    InvalidTarget(String),
    InvalidProfile(String),
    BuildConfigurationMismatch,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMagic => formatter.write_str("invalid backend protocol magic"),
            Self::UnsupportedVersion(version) => {
                write!(formatter, "unsupported backend protocol version {version}")
            }
            Self::UnexpectedMessageKind(kind) => {
                write!(formatter, "unexpected message kind {kind}")
            }
            Self::FrameTooLarge(length) => {
                write!(formatter, "backend frame is too large: {length} bytes")
            }
            Self::FrameLengthMismatch { declared, actual } => write!(
                formatter,
                "backend frame declares {declared} payload bytes but contains {actual}"
            ),
            Self::UnexpectedEnd => formatter.write_str("unexpected end of backend frame"),
            Self::TrailingBytes => formatter.write_str("trailing bytes in backend payload"),
            Self::InvalidUtf8 => formatter.write_str("backend text is not valid UTF-8"),
            Self::TextTooLong(length) => {
                write!(formatter, "backend text exceeds limit: {length} bytes")
            }
            Self::InvalidBoolean(tag) => write!(formatter, "invalid backend boolean tag {tag}"),
            Self::InvalidEnumTag(name, tag) => write!(formatter, "invalid {name} tag {tag}"),
            Self::InvalidOutcomeTag(tag) => write!(formatter, "invalid backend outcome tag {tag}"),
            Self::InvalidPath(message) => write!(formatter, "invalid backend path: {message}"),
            Self::InvalidTarget(message) => write!(formatter, "invalid backend target: {message}"),
            Self::InvalidProfile(message) => {
                write!(formatter, "invalid backend profile: {message}")
            }
            Self::BuildConfigurationMismatch => formatter.write_str(
                "backend request build differs from its profile-digest-validated configuration",
            ),
        }
    }
}

impl std::error::Error for ProtocolError {}

#[cfg(test)]
mod tests {
    use wrela_build_model::{
        BuildConfiguration, BuildIdentity, BuildProfile, LanguageRevision, Sha256Digest,
        TargetIdentity, ValidatedBuildConfiguration, seal_build_configuration,
    };

    use super::{
        BackendFailure, BackendFailureKind, BackendOutcome, BackendPath, BackendRequest,
        BackendResponse, ProtocolError, RequestId, decode_request, decode_response, encode_request,
        encode_response,
    };

    fn request_fixture() -> BackendRequest {
        let digest = Sha256Digest::from_bytes([1; 32]);
        BackendRequest {
            request_id: RequestId(7),
            build: BuildConfiguration {
                identity: BuildIdentity {
                    compiler: digest,
                    language: LanguageRevision::Design0_1,
                    target: TargetIdentity::aarch64_qemu_virt_uefi(),
                    target_package: digest,
                    standard_library: digest,
                    source_graph: digest,
                    request: digest,
                    profile: digest,
                },
                profile: BuildProfile::development(),
            },
            wir: BackendPath::new("build/input.wir").expect("path"),
            wir_digest: digest,
            target_package: BackendPath::new("targets/aarch64-qemu-virt-uefi").expect("path"),
            output: BackendPath::new("build/image.efi").expect("path"),
            report: BackendPath::new("build/image.json").expect("path"),
        }
    }

    fn validated_build(request: &BackendRequest) -> ValidatedBuildConfiguration {
        seal_build_configuration(request.build.clone(), request.build.identity.profile)
            .expect("validated build fixture")
    }

    #[test]
    fn request_round_trip_is_canonical() {
        let request = request_fixture();
        let encoded = encode_request(&request, &validated_build(&request)).expect("encode");
        assert_eq!(decode_request(&encoded), Ok(request));
    }

    #[test]
    fn controlled_paths_reject_escape_and_noncanonical_spelling() {
        for path in [
            "/tmp/input.wir",
            "../input.wir",
            "build/../input.wir",
            "build//input.wir",
            "C:/input.wir",
            r"build\input.wir",
        ] {
            assert!(BackendPath::new(path).is_err(), "accepted {path:?}");
        }
    }

    #[test]
    fn corrupt_request_frames_are_rejected_before_payload_use() {
        let request = request_fixture();
        let encoded = encode_request(&request, &validated_build(&request)).expect("encode");

        let mut bad_magic = encoded.clone();
        bad_magic[0] ^= 0xff;
        assert_eq!(decode_request(&bad_magic), Err(ProtocolError::InvalidMagic));

        let mut bad_version = encoded.clone();
        bad_version[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            decode_request(&bad_version),
            Err(ProtocolError::UnsupportedVersion(u32::MAX))
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert!(matches!(
            decode_request(&trailing),
            Err(ProtocolError::FrameLengthMismatch { .. })
        ));
    }

    #[test]
    fn typed_failure_response_round_trips() {
        let response = BackendResponse {
            request_id: RequestId(9),
            outcome: BackendOutcome::Failure(BackendFailure {
                kind: BackendFailureKind::Verification,
                message: "proof failed".to_owned(),
            }),
        };
        let encoded = encode_response(&response).expect("response encode");
        assert_eq!(decode_response(&encoded), Ok(response));
    }
}
