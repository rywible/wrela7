//! Canonical, bounded, exactly versioned FlowWir serialization across the
//! private frontend/backend process boundary.

#![forbid(unsafe_code)]

use std::fmt;

use wrela_build_model::BuildIdentity;
use wrela_flow_wir::{FLOW_WIR_VERSION, ValidatedFlowWir, ValidationErrors};

pub const FLOW_WIR_WIRE_VERSION: u32 = 1;
pub const FLOW_WIR_MAGIC: &[u8; 8] = b"WRELFLO\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodecLimits {
    pub frame_bytes: u64,
    pub string_bytes: u32,
    pub vector_items: u32,
    pub functions: u32,
    pub blocks: u64,
    pub instructions: u64,
    pub nesting_depth: u32,
}

impl CodecLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            frame_bytes: 4 * 1024 * 1024 * 1024,
            string_bytes: 1024 * 1024,
            vector_items: 16_000_000,
            functions: 1_000_000,
            blocks: 16_000_000,
            instructions: 256_000_000,
            nesting_depth: 1024,
        }
    }

    pub fn validate(self) -> Result<(), CodecError> {
        if self.frame_bytes == 0
            || self.string_bytes == 0
            || self.vector_items == 0
            || self.functions == 0
            || self.blocks == 0
            || self.instructions == 0
            || self.nesting_depth == 0
            || self.nesting_depth > 1024
        {
            Err(CodecError::InvalidLimits)
        } else {
            Ok(())
        }
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedFlowWir {
    header: WireHeader,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
    if is_cancelled() {
        return Err(CodecError::Cancelled);
    }
    request.limits.validate()?;
    let wir = request.wir;
    let limits = request.limits;
    let candidate = codec.encode(request, is_cancelled)?;
    validate_candidate(&candidate, wir, limits)?;
    if codec.inspect_header(&candidate.bytes)? != candidate.header {
        return Err(CodecError::NonCanonical(
            "inspected header differs from encoded header",
        ));
    }
    let decoded = codec.decode(
        DecodeRequest {
            bytes: &candidate.bytes,
            limits,
            expected_build: Some(&wir.as_wir().build),
        },
        is_cancelled,
    )?;
    if decoded != *wir {
        return Err(CodecError::NonCanonical(
            "encoded bytes decode to a different FlowWir model",
        ));
    }
    let canonical = codec.encode(
        EncodeRequest {
            wir: &decoded,
            limits,
        },
        is_cancelled,
    )?;
    if canonical != candidate {
        return Err(CodecError::NonCanonical(
            "FlowWir encoder is nondeterministic",
        ));
    }
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
    if is_cancelled() {
        return Err(CodecError::Cancelled);
    }
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
    let inspected = codec.inspect_header(bytes)?;
    let decoded = codec.decode(request, is_cancelled)?;
    if expected_build.is_some_and(|expected| expected != &decoded.as_wir().build) {
        return Err(CodecError::BuildIdentityMismatch);
    }
    let canonical = codec.encode(
        EncodeRequest {
            wir: &decoded,
            limits,
        },
        is_cancelled,
    )?;
    validate_candidate(&canonical, &decoded, limits)?;
    if inspected != canonical.header || canonical.bytes != bytes {
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
) -> Result<(), CodecError> {
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
        || candidate.header.build != wir.as_wir().build
        || candidate.header.payload_bytes == 0
        || candidate.header.payload_bytes > frame_bytes
    {
        return Err(CodecError::NonCanonical(
            "encoded header, build, payload length, or magic",
        ));
    }
    Ok(())
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
    fn inspect_header(&self, bytes: &[u8]) -> Result<WireHeader, CodecError>;
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
    ResourceLimit {
        resource: &'static str,
        limit: u64,
        actual: u64,
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
            Self::ResourceLimit {
                resource,
                limit,
                actual,
            } => write!(
                formatter,
                "FlowWir {resource} count {actual} exceeds {limit}"
            ),
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
        Block, BlockId, FlowFunction, FlowType, FlowTypeKind, FlowWir, FunctionId, FunctionOrigin,
        FunctionRole, SourceSummary, Terminator, TypeId,
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
                semantic_wir_version: 1,
                semantic_functions: 1,
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
                origin: FunctionOrigin::GeneratedTestHarness {
                    semantic_function: 0,
                    group: 0,
                },
                role: FunctionRole::ImageEntry,
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
                source: None,
            }],
            actors: Vec::new(),
            tasks: Vec::new(),
            devices: Vec::new(),
            pools: Vec::new(),
            regions: Vec::new(),
            proofs: Vec::new(),
            checkpoints: Vec::new(),
            startup_order: Vec::new(),
            shutdown_order: Vec::new(),
            image_entry: FunctionId(0),
            static_bytes: 0,
            peak_bytes: 0,
        }
        .validate()
        .expect("valid FlowWir")
    }

    struct FixtureCodec {
        wir: ValidatedFlowWir,
    }

    impl FixtureCodec {
        fn candidate(&self) -> EncodedFlowWirCandidate {
            let mut bytes = FLOW_WIR_MAGIC.to_vec();
            bytes.push(1);
            EncodedFlowWirCandidate {
                header: WireHeader {
                    wire_version: FLOW_WIR_WIRE_VERSION,
                    flow_wir_version: FLOW_WIR_VERSION,
                    payload_bytes: 1,
                    build: self.wir.as_wir().build.clone(),
                },
                bytes,
            }
        }
    }

    impl FlowWirCodec for FixtureCodec {
        fn encode(
            &self,
            request: EncodeRequest<'_>,
            _is_cancelled: &dyn Fn() -> bool,
        ) -> Result<EncodedFlowWirCandidate, CodecError> {
            if request.wir != &self.wir {
                return Err(CodecError::NonCanonical("wrong fixture model"));
            }
            Ok(self.candidate())
        }

        fn inspect_header(&self, _bytes: &[u8]) -> Result<WireHeader, CodecError> {
            Ok(self.candidate().header)
        }

        fn decode(
            &self,
            _request: DecodeRequest<'_>,
            _is_cancelled: &dyn Fn() -> bool,
        ) -> Result<ValidatedFlowWir, CodecError> {
            Ok(self.wir.clone())
        }
    }

    #[test]
    fn seals_canonical_frame_against_exact_model() {
        let codec = FixtureCodec { wir: fixture() };
        let encoded = encode_and_verify(
            &codec,
            EncodeRequest {
                wir: &codec.wir,
                limits: CodecLimits::standard(),
            },
            &|| false,
        )
        .expect("canonical frame");
        assert_eq!(encoded.bytes(), codec.candidate().bytes);
    }

    #[test]
    fn backend_rejects_noncanonical_complete_frame() {
        let codec = FixtureCodec { wir: fixture() };
        let mut bytes = codec.candidate().bytes;
        bytes.push(0);
        assert!(matches!(
            decode_and_verify(
                &codec,
                DecodeRequest {
                    bytes: &bytes,
                    limits: CodecLimits::standard(),
                    expected_build: Some(&codec.wir.as_wir().build),
                },
                &|| false,
            ),
            Err(CodecError::NonCanonical(_))
        ));
    }

    #[test]
    fn codec_cancellation_precedes_candidate_work() {
        let codec = FixtureCodec { wir: fixture() };
        assert_eq!(
            encode_and_verify(
                &codec,
                EncodeRequest {
                    wir: &codec.wir,
                    limits: CodecLimits::standard(),
                },
                &|| true,
            ),
            Err(CodecError::Cancelled)
        );
    }
}
