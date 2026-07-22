//! Canonical, bounded, exactly versioned FlowWir serialization across the
//! private frontend/backend process boundary.

#![forbid(unsafe_code)]

use std::fmt;

use wrela_build_model::BuildIdentity;
use wrela_flow_wir::{
    FLOW_WIR_VERSION, ValidatedFlowWir, ValidationErrors, ValidationFailure, ValidationLimits,
};
use wrela_test_model::TestPlanLimits;

mod canonical;

pub use canonical::CanonicalFlowWirCodec;

pub const FLOW_WIR_WIRE_VERSION: u32 = 13;
pub const FLOW_WIR_MAGIC: &[u8; 8] = b"WRELFLO\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecLimits {
    pub frame_bytes: u64,
    pub string_bytes: u32,
    pub vector_items: u32,
    pub functions: u32,
    pub tests: u32,
    pub blocks: u64,
    pub instructions: u64,
    pub nesting_depth: u32,
    /// Conservative upper bound for structural validation and dominance work.
    pub validation_work: u64,
    /// Maximum decoded-model validation errors retained before failing closed.
    pub validation_errors: u32,
    /// Exact policy applied to any decoded compiled test-group binding.
    pub test_plan: TestPlanLimits,
}

impl CodecLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            frame_bytes: 4 * 1024 * 1024 * 1024,
            string_bytes: 1024 * 1024,
            vector_items: 16_000_000,
            functions: 1_000_000,
            tests: 1_000_000,
            blocks: 16_000_000,
            instructions: 256_000_000,
            nesting_depth: 1024,
            validation_work: 1_100_000_000_000,
            validation_errors: 100_000,
            test_plan: TestPlanLimits::standard(),
        }
    }

    pub fn validate(self) -> Result<(), CodecError> {
        if self.frame_bytes == 0
            || self.string_bytes == 0
            || self.vector_items == 0
            || self.functions == 0
            || self.tests == 0
            || self.blocks == 0
            || self.instructions == 0
            || self.nesting_depth == 0
            || self.nesting_depth > 1024
            || self.validation_work == 0
            || self.validation_errors == 0
            || !self.test_plan.is_valid()
        {
            Err(CodecError::InvalidLimits)
        } else {
            Ok(())
        }
    }
}

pub(crate) fn flow_validation_limits(limits: CodecLimits) -> ValidationLimits {
    ValidationLimits {
        arena_records: u64::from(limits.vector_items),
        model_edges: u64::from(limits.vector_items),
        // Immediate bytes are charged as vector items by the wire codec, while
        // model validation classifies them as payload. The complete frame is
        // therefore the exact caller-owned upper bound shared by both views.
        payload_bytes: limits.frame_bytes,
        validation_work: limits.validation_work,
        errors: limits.validation_errors,
        test_plan: limits.test_plan,
    }
}

pub(crate) fn map_validation_failure(error: ValidationFailure) -> CodecError {
    match error {
        ValidationFailure::InvalidLimits => CodecError::InvalidLimits,
        ValidationFailure::Cancelled => CodecError::Cancelled,
        ValidationFailure::ResourceLimit { resource, limit } => {
            CodecError::ValidationResourceLimit { resource, limit }
        }
        ValidationFailure::Invalid(errors) => CodecError::InvalidFlowWir(errors),
    }
}

#[derive(Debug)]
pub struct EncodeRequest<'a> {
    pub wir: &'a ValidatedFlowWir,
    pub limits: CodecLimits,
}

#[derive(Debug)]
pub struct DecodeRequest<'a> {
    pub bytes: &'a [u8],
    pub limits: CodecLimits,
    /// When supplied by the backend protocol, mismatch is rejected before use.
    pub expected_build: Option<&'a BuildIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireHeader {
    pub wire_version: u32,
    pub flow_wir_version: u32,
    pub payload_bytes: u64,
    pub build: BuildIdentity,
}

#[derive(Debug)]
pub struct EncodedFlowWir {
    header: WireHeader,
    bytes: Vec<u8>,
}

#[derive(Debug)]
pub struct EncodedFlowWirCandidate {
    pub header: WireHeader,
    pub bytes: Vec<u8>,
}

impl EncodedFlowWir {
    #[must_use]
    pub fn header(&self) -> &WireHeader {
        &self.header
    }

    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Seal the redundant encoded header against the exact validated model and
/// bounded frame bytes. Backend decoding still independently revalidates every
/// model invariant.
pub fn encode_and_verify(
    codec: &dyn FlowWirCodec,
    request: EncodeRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<EncodedFlowWir, CodecError> {
    check_cancelled(is_cancelled)?;
    request.limits.validate()?;
    let wir = request.wir;
    let limits = request.limits;
    let candidate = codec.encode(request, is_cancelled)?;
    validate_candidate(&candidate, wir, limits, is_cancelled)?;
    let inspected = codec.inspect_header(&candidate.bytes, is_cancelled)?;
    if !wire_header_equal(&inspected, &candidate.header, is_cancelled)? {
        return Err(CodecError::NonCanonical(
            "inspected header differs from encoded header",
        ));
    }

    // The production v13 encoder is the exact source-model identity. This
    // avoids an uninterruptible derived equality walk over two project-sized
    // models and prevents an injected codec from silently omitting fields.
    let expected = CanonicalFlowWirCodec.encode(EncodeRequest { wir, limits }, is_cancelled)?;
    if !encoded_candidate_equal(&expected, &candidate, is_cancelled)? {
        return Err(CodecError::NonCanonical(
            "codec output differs from the canonical FlowWir v13 encoding",
        ));
    }
    drop(expected);

    let decoded = codec.decode(
        DecodeRequest {
            bytes: &candidate.bytes,
            limits,
            expected_build: Some(&wir.as_wir().build),
        },
        is_cancelled,
    )?;
    let decoded_canonical = CanonicalFlowWirCodec.encode(
        EncodeRequest {
            wir: &decoded,
            limits,
        },
        is_cancelled,
    )?;
    if !encoded_candidate_equal(&decoded_canonical, &candidate, is_cancelled)? {
        return Err(CodecError::NonCanonical(
            "encoded bytes decode to a different FlowWir model",
        ));
    }
    drop(decoded_canonical);

    let repeated = codec.encode(EncodeRequest { wir, limits }, is_cancelled)?;
    if !encoded_candidate_equal(&repeated, &candidate, is_cancelled)? {
        return Err(CodecError::NonCanonical(
            "FlowWir encoder is nondeterministic",
        ));
    }
    drop(repeated);
    check_cancelled(is_cancelled)?;
    Ok(EncodedFlowWir {
        header: candidate.header,
        bytes: candidate.bytes,
    })
}

pub fn decode_and_verify(
    codec: &dyn FlowWirCodec,
    request: DecodeRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ValidatedFlowWir, CodecError> {
    check_cancelled(is_cancelled)?;
    request.limits.validate()?;
    let frame_bytes = u64::try_from(request.bytes.len()).map_err(|_| CodecError::LengthOverflow)?;
    if frame_bytes > request.limits.frame_bytes {
        return Err(CodecError::ResourceLimit {
            resource: "FlowWir frame bytes",
            limit: request.limits.frame_bytes,
            actual: frame_bytes,
        });
    }
    let bytes = request.bytes;
    let limits = request.limits;
    let expected_build = request.expected_build;
    let inspected = codec.inspect_header(bytes, is_cancelled)?;
    let decoded = codec.decode(request, is_cancelled)?;
    if let Some(expected) = expected_build {
        if !build_identity_equal(expected, &decoded.as_wir().build, is_cancelled)? {
            return Err(CodecError::BuildIdentityMismatch);
        }
    }
    let canonical = codec.encode(
        EncodeRequest {
            wir: &decoded,
            limits,
        },
        is_cancelled,
    )?;
    validate_candidate(&canonical, &decoded, limits, is_cancelled)?;
    if !wire_header_equal(&inspected, &canonical.header, is_cancelled)?
        || !bytes_equal(&canonical.bytes, bytes, is_cancelled)?
    {
        return Err(CodecError::NonCanonical(
            "decoded model does not reproduce its complete frame",
        ));
    }
    Ok(decoded)
}

fn validate_candidate(
    candidate: &EncodedFlowWirCandidate,
    wir: &ValidatedFlowWir,
    limits: CodecLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), CodecError> {
    check_cancelled(is_cancelled)?;
    let frame_bytes =
        u64::try_from(candidate.bytes.len()).map_err(|_| CodecError::LengthOverflow)?;
    if frame_bytes > limits.frame_bytes {
        return Err(CodecError::ResourceLimit {
            resource: "FlowWir frame bytes",
            limit: limits.frame_bytes,
            actual: frame_bytes,
        });
    }
    if !candidate.bytes.starts_with(FLOW_WIR_MAGIC)
        || candidate.header.wire_version != FLOW_WIR_WIRE_VERSION
        || candidate.header.flow_wir_version != FLOW_WIR_VERSION
        || !build_identity_equal(&candidate.header.build, &wir.as_wir().build, is_cancelled)?
        || candidate.header.payload_bytes == 0
        || candidate.header.payload_bytes > frame_bytes
    {
        return Err(CodecError::NonCanonical(
            "encoded header, build, payload length, or magic",
        ));
    }
    Ok(())
}

pub(crate) const CANCELLABLE_CODEC_CHUNK_BYTES: usize = 64 * 1024;

pub(crate) fn check_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), CodecError> {
    if is_cancelled() {
        Err(CodecError::Cancelled)
    } else {
        Ok(())
    }
}

pub(crate) fn bytes_equal(
    left: &[u8],
    right: &[u8],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, CodecError> {
    check_cancelled(is_cancelled)?;
    if left.len() != right.len() {
        return Ok(false);
    }
    for (left, right) in left
        .chunks(CANCELLABLE_CODEC_CHUNK_BYTES)
        .zip(right.chunks(CANCELLABLE_CODEC_CHUNK_BYTES))
    {
        check_cancelled(is_cancelled)?;
        if left != right {
            return Ok(false);
        }
    }
    check_cancelled(is_cancelled)?;
    Ok(true)
}

fn text_equal(
    left: &str,
    right: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, CodecError> {
    bytes_equal(left.as_bytes(), right.as_bytes(), is_cancelled)
}

pub(crate) fn build_identity_equal(
    left: &BuildIdentity,
    right: &BuildIdentity,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, CodecError> {
    check_cancelled(is_cancelled)?;
    Ok(left.compiler == right.compiler
        && left.language == right.language
        && text_equal(left.target.as_str(), right.target.as_str(), is_cancelled)?
        && left.target_package == right.target_package
        && left.standard_library == right.standard_library
        && left.source_graph == right.source_graph
        && left.request == right.request
        && left.profile == right.profile)
}

fn wire_header_equal(
    left: &WireHeader,
    right: &WireHeader,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, CodecError> {
    check_cancelled(is_cancelled)?;
    Ok(left.wire_version == right.wire_version
        && left.flow_wir_version == right.flow_wir_version
        && left.payload_bytes == right.payload_bytes
        && build_identity_equal(&left.build, &right.build, is_cancelled)?)
}

fn encoded_candidate_equal(
    left: &EncodedFlowWirCandidate,
    right: &EncodedFlowWirCandidate,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, CodecError> {
    Ok(
        wire_header_equal(&left.header, &right.header, is_cancelled)?
            && bytes_equal(&left.bytes, &right.bytes, is_cancelled)?,
    )
}

/// Codec implementations must use a single canonical little-endian,
/// length-prefixed encoding, reject duplicate/non-dense IDs, consume input
/// exactly, and call FlowWir structural validation after decoding.
pub trait FlowWirCodec {
    fn encode(
        &self,
        request: EncodeRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<EncodedFlowWirCandidate, CodecError>;
    fn inspect_header(
        &self,
        bytes: &[u8],
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<WireHeader, CodecError>;
    fn decode(
        &self,
        request: DecodeRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ValidatedFlowWir, CodecError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    Cancelled,
    InvalidLimits,
    InvalidMagic,
    UnsupportedWireVersion(u32),
    UnsupportedFlowWirVersion(u32),
    BuildIdentityMismatch,
    UnexpectedEnd,
    InvalidUtf8,
    InvalidEnumTag {
        kind: &'static str,
        tag: u64,
    },
    NonCanonical(&'static str),
    LengthOverflow,
    AllocationFailed,
    ResourceLimit {
        resource: &'static str,
        limit: u64,
        actual: u64,
    },
    ValidationResourceLimit {
        resource: &'static str,
        limit: u64,
    },
    TrailingBytes,
    InvalidFlowWir(ValidationErrors),
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("FlowWir codec operation was cancelled"),
            Self::InvalidLimits => formatter.write_str("FlowWir codec limits must be nonzero"),
            Self::InvalidMagic => formatter.write_str("invalid FlowWir magic"),
            Self::UnsupportedWireVersion(version) => {
                write!(formatter, "unsupported FlowWir wire version {version}")
            }
            Self::UnsupportedFlowWirVersion(version) => write!(
                formatter,
                "unsupported FlowWir model version {version}; expected {FLOW_WIR_VERSION}"
            ),
            Self::BuildIdentityMismatch => {
                formatter.write_str("FlowWir build identity does not match the backend request")
            }
            Self::UnexpectedEnd => formatter.write_str("unexpected end of FlowWir input"),
            Self::InvalidUtf8 => formatter.write_str("invalid UTF-8 in FlowWir input"),
            Self::InvalidEnumTag { kind, tag } => write!(formatter, "invalid {kind} tag {tag}"),
            Self::NonCanonical(reason) => {
                write!(formatter, "noncanonical FlowWir encoding: {reason}")
            }
            Self::LengthOverflow => formatter.write_str("FlowWir encoded length overflow"),
            Self::AllocationFailed => {
                formatter.write_str("memory allocation for FlowWir codec input failed")
            }
            Self::ResourceLimit {
                resource,
                limit,
                actual,
            } => write!(formatter, "FlowWir {resource} {actual} exceeds {limit}"),
            Self::ValidationResourceLimit { resource, limit } => {
                write!(
                    formatter,
                    "FlowWir validation exceeded {resource} limit {limit}"
                )
            }
            Self::TrailingBytes => formatter.write_str("trailing bytes after FlowWir payload"),
            Self::InvalidFlowWir(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for CodecError {}

#[cfg(test)]
mod tests {
    use super::*;
    use wrela_build_model::{BuildIdentity, LanguageRevision, Sha256Digest, TargetIdentity};
    use wrela_flow_wir::{
        Block, BlockId, FlowFunction, FlowType, FlowTypeKind, FlowWir, FunctionColor, FunctionId,
        FunctionOrigin, FunctionRole, PlanOwner, SourceSummary, Terminator, TypeId,
    };

    fn fixture() -> ValidatedFlowWir {
        let digest = Sha256Digest::from_bytes([1; 32]);
        FlowWir {
            version: FLOW_WIR_VERSION,
            name: "image".to_owned(),
            build: BuildIdentity {
                compiler: digest,
                language: LanguageRevision::Design0_1,
                target: TargetIdentity::aarch64_qemu_virt_uefi(),
                target_package: digest,
                standard_library: digest,
                source_graph: digest,
                request: digest,
                profile: digest,
            },
            source_summary: SourceSummary {
                semantic_wir_version: 11,
                semantic_functions: 1,
                hir_files: 1,
                hir_declarations: 1,
                reachable_declarations: 1,
                monomorphized_instantiations: 1,
                resolved_interface_calls: 0,
            },
            types: vec![FlowType {
                id: TypeId(0),
                kind: FlowTypeKind::Unit,
                name: Some("unit".to_owned()),
                copyable: true,
                strict_linear: false,
            }],
            globals: Vec::new(),
            functions: vec![FlowFunction {
                id: FunctionId(0),
                name: "entry".to_owned(),
                origin: FunctionOrigin::GeneratedImageEntry {
                    semantic_function: 0,
                    constructor: 0,
                },
                role: FunctionRole::ImageEntry,
                color: FunctionColor::Sync,
                parameters: Vec::new(),
                result_types: Vec::new(),
                values: Vec::new(),
                blocks: vec![Block {
                    id: BlockId(0),
                    parameters: Vec::new(),
                    instructions: Vec::new(),
                    terminator: Terminator::Return(Vec::new()),
                    source: None,
                }],
                entry: BlockId(0),
                stack_bound: 0,
                frame_bound: 0,
                proofs: Vec::new(),
                source: None,
            }],
            actors: Vec::new(),
            tasks: Vec::new(),
            devices: Vec::new(),
            pools: Vec::new(),
            regions: Vec::new(),
            activations: Vec::new(),
            proofs: Vec::new(),
            checkpoints: Vec::new(),
            tests: Vec::new(),
            compiled_test_group: None,
            startup_order: vec![PlanOwner::Runtime],
            shutdown_order: vec![PlanOwner::Runtime],
            image_entry: FunctionId(0),
            static_bytes: 0,
            peak_bytes: 0,
        }
        .validate()
        .expect("valid FlowWir")
    }

    struct MustNotRunCodec;

    impl FlowWirCodec for MustNotRunCodec {
        fn encode(
            &self,
            _request: EncodeRequest<'_>,
            _is_cancelled: &dyn Fn() -> bool,
        ) -> Result<EncodedFlowWirCandidate, CodecError> {
            panic!("entry cancellation must precede encode")
        }

        fn inspect_header(
            &self,
            _bytes: &[u8],
            _is_cancelled: &dyn Fn() -> bool,
        ) -> Result<WireHeader, CodecError> {
            panic!("entry cancellation must precede header inspection")
        }

        fn decode(
            &self,
            _request: DecodeRequest<'_>,
            _is_cancelled: &dyn Fn() -> bool,
        ) -> Result<ValidatedFlowWir, CodecError> {
            panic!("entry cancellation must precede decode")
        }
    }

    #[test]
    fn seals_canonical_frame_against_exact_model() {
        let model = fixture();
        let codec = CanonicalFlowWirCodec;
        let encoded = encode_and_verify(
            &codec,
            EncodeRequest {
                wir: &model,
                limits: CodecLimits::standard(),
            },
            &|| false,
        )
        .expect("canonical frame");
        assert_eq!(encoded.header().wire_version, FLOW_WIR_WIRE_VERSION);
        assert!(!encoded.bytes().is_empty());
    }

    #[test]
    fn backend_rejects_noncanonical_complete_frame() {
        let model = fixture();
        let codec = CanonicalFlowWirCodec;
        let mut bytes = codec
            .encode(
                EncodeRequest {
                    wir: &model,
                    limits: CodecLimits::standard(),
                },
                &|| false,
            )
            .expect("canonical fixture frame")
            .bytes;
        bytes.push(0);
        assert_eq!(
            decode_and_verify(
                &codec,
                DecodeRequest {
                    bytes: &bytes,
                    limits: CodecLimits::standard(),
                    expected_build: Some(&model.as_wir().build),
                },
                &|| false,
            ),
            Err(CodecError::TrailingBytes)
        );
    }

    #[test]
    fn codec_cancellation_precedes_candidate_work() {
        let model = fixture();
        assert!(matches!(
            encode_and_verify(
                &MustNotRunCodec,
                EncodeRequest {
                    wir: &model,
                    limits: CodecLimits::standard(),
                },
                &|| true,
            ),
            Err(CodecError::Cancelled)
        ));
    }

    #[test]
    fn codec_policy_requires_explicit_flow_validation_limits() {
        CodecLimits::standard()
            .validate()
            .expect("standard codec policy is complete");

        let mut limits = CodecLimits::standard();
        limits.validation_work = 0;
        assert_eq!(limits.validate(), Err(CodecError::InvalidLimits));

        let mut limits = CodecLimits::standard();
        limits.validation_errors = 0;
        assert_eq!(limits.validate(), Err(CodecError::InvalidLimits));

        let mut limits = CodecLimits::standard();
        limits.test_plan.events_per_group = 0;
        assert_eq!(limits.validate(), Err(CodecError::InvalidLimits));
    }
}
