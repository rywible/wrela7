//! Stable host/guest event framing for full-image tests.

#![forbid(unsafe_code)]

use std::fmt;

use wrela_test_model::{TEST_PROTOCOL_VERSION, TestEvent};

pub const TEST_FRAME_MAGIC: &[u8; 8] = b"WRELTST\0";
pub const TEST_FRAME_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolLimits {
    pub frame_bytes: u32,
    pub string_bytes: u32,
    pub events: u32,
}

impl ProtocolLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            frame_bytes: 1024 * 1024,
            string_bytes: 256 * 1024,
            events: 1_000_000,
        }
    }

    pub fn validate(self) -> Result<(), ProtocolError> {
        if self.frame_bytes == 0 || self.string_bytes == 0 || self.events == 0 {
            Err(ProtocolError::InvalidLimits)
        } else {
            Ok(())
        }
    }
}

/// Header precedes an escaped binary payload on PL011. `checksum` is CRC32C of
/// the unescaped payload, and sequence must advance exactly by one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub frame_version: u32,
    pub event_version: u32,
    pub sequence: u64,
    pub payload_bytes: u32,
    pub checksum: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedEvent {
    header: FrameHeader,
    bytes: Vec<u8>,
}

impl EncodedEvent {
    #[must_use]
    pub const fn header(&self) -> FrameHeader {
        self.header
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedEventCandidate {
    pub header: FrameHeader,
    pub bytes: Vec<u8>,
}

pub trait TestEventCodec {
    fn encode(
        &self,
        event: &TestEvent,
        limits: ProtocolLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<EncodedEventCandidate, ProtocolError>;
    fn inspect_header(
        &self,
        frame: &[u8],
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<FrameHeader, ProtocolError>;
    fn decode(
        &self,
        frame: &[u8],
        limits: ProtocolLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<TestEvent, ProtocolError>;
}

pub fn seal_encoded_event(
    codec: &dyn TestEventCodec,
    event: &TestEvent,
    limits: ProtocolLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<EncodedEvent, ProtocolError> {
    if is_cancelled() {
        return Err(ProtocolError::Cancelled);
    }
    validate_event(event, limits)?;
    let candidate = codec.encode(event, limits, is_cancelled)?;
    validate_frame_shape(&candidate.bytes, candidate.header, limits)?;
    if codec.inspect_header(&candidate.bytes, is_cancelled)? != candidate.header
        || decode_and_verify_event(codec, &candidate.bytes, limits, is_cancelled)? != *event
    {
        return Err(ProtocolError::NonCanonical(
            "encoded header or event differs from its input",
        ));
    }
    Ok(EncodedEvent {
        header: candidate.header,
        bytes: candidate.bytes,
    })
}

pub fn decode_and_verify_event(
    codec: &dyn TestEventCodec,
    frame: &[u8],
    limits: ProtocolLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<TestEvent, ProtocolError> {
    if is_cancelled() {
        return Err(ProtocolError::Cancelled);
    }
    limits.validate()?;
    let header = codec.inspect_header(frame, is_cancelled)?;
    validate_frame_shape(frame, header, limits)?;
    let event = codec.decode(frame, limits, is_cancelled)?;
    validate_event(&event, limits)?;
    if header.sequence != event.sequence {
        return Err(ProtocolError::SequenceMismatch {
            header: header.sequence,
            event: event.sequence,
        });
    }
    let canonical = codec.encode(&event, limits, is_cancelled)?;
    if is_cancelled() {
        return Err(ProtocolError::Cancelled);
    }
    if canonical.header != header || canonical.bytes != frame {
        return Err(ProtocolError::NonCanonical(
            "decoded event does not reproduce its complete frame",
        ));
    }
    Ok(event)
}

fn validate_event(event: &TestEvent, limits: ProtocolLimits) -> Result<(), ProtocolError> {
    limits.validate()?;
    if event.protocol != TEST_PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedEventVersion(event.protocol));
    }
    if event.sequence >= u64::from(limits.events) {
        return Err(ProtocolError::EventLimit {
            limit: limits.events,
            sequence: event.sequence,
        });
    }
    Ok(())
}

fn validate_frame_shape(
    frame: &[u8],
    header: FrameHeader,
    limits: ProtocolLimits,
) -> Result<(), ProtocolError> {
    let frame_bytes = usize::try_from(limits.frame_bytes).unwrap_or(usize::MAX);
    if frame.is_empty() || frame.len() > frame_bytes {
        return Err(ProtocolError::FrameTooLarge {
            limit: limits.frame_bytes,
            actual: frame.len(),
        });
    }
    if header.frame_version != TEST_FRAME_VERSION {
        return Err(ProtocolError::UnsupportedFrameVersion(header.frame_version));
    }
    if header.event_version != TEST_PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedEventVersion(header.event_version));
    }
    if header.sequence >= u64::from(limits.events) {
        return Err(ProtocolError::EventLimit {
            limit: limits.events,
            sequence: header.sequence,
        });
    }
    if header.payload_bytes > limits.frame_bytes {
        return Err(ProtocolError::FrameTooLarge {
            limit: limits.frame_bytes,
            actual: usize::try_from(header.payload_bytes).unwrap_or(usize::MAX),
        });
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    Cancelled,
    InvalidLimits,
    InvalidMagic,
    UnsupportedFrameVersion(u32),
    UnsupportedEventVersion(u32),
    UnexpectedEnd,
    InvalidUtf8,
    InvalidTag { kind: &'static str, tag: u64 },
    InvalidChecksum,
    FrameTooLarge { limit: u32, actual: usize },
    StringTooLarge { limit: u32, actual: usize },
    EventLimit { limit: u32, sequence: u64 },
    SequenceMismatch { header: u64, event: u64 },
    TrailingBytes,
    NonCanonical(&'static str),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("test event codec operation was cancelled"),
            Self::InvalidLimits => formatter.write_str("test protocol limits must be nonzero"),
            Self::InvalidMagic => formatter.write_str("invalid test event frame magic"),
            Self::UnsupportedFrameVersion(version) => {
                write!(formatter, "unsupported test frame version {version}")
            }
            Self::UnsupportedEventVersion(version) => write!(
                formatter,
                "unsupported test event version {version}; expected {TEST_PROTOCOL_VERSION}"
            ),
            Self::UnexpectedEnd => formatter.write_str("unexpected end of test event frame"),
            Self::InvalidUtf8 => formatter.write_str("invalid UTF-8 in test event frame"),
            Self::InvalidTag { kind, tag } => write!(formatter, "invalid test {kind} tag {tag}"),
            Self::InvalidChecksum => formatter.write_str("test event checksum mismatch"),
            Self::FrameTooLarge { limit, actual } => write!(
                formatter,
                "test frame contains {actual} bytes, exceeding {limit}"
            ),
            Self::StringTooLarge { limit, actual } => write!(
                formatter,
                "test string contains {actual} bytes, exceeding {limit}"
            ),
            Self::EventLimit { limit, sequence } => write!(
                formatter,
                "test event sequence {sequence} exceeds event limit {limit}"
            ),
            Self::SequenceMismatch { header, event } => write!(
                formatter,
                "test frame sequence {header} differs from event sequence {event}"
            ),
            Self::TrailingBytes => formatter.write_str("trailing bytes after test event payload"),
            Self::NonCanonical(reason) => {
                write!(formatter, "noncanonical test event encoding: {reason}")
            }
        }
    }
}

impl std::error::Error for ProtocolError {}

#[cfg(test)]
mod tests {
    use super::*;
    use wrela_test_model::TestEventKind;

    struct FixtureCodec;

    impl TestEventCodec for FixtureCodec {
        fn encode(
            &self,
            event: &TestEvent,
            _limits: ProtocolLimits,
            _is_cancelled: &dyn Fn() -> bool,
        ) -> Result<EncodedEventCandidate, ProtocolError> {
            Ok(EncodedEventCandidate {
                header: FrameHeader {
                    frame_version: TEST_FRAME_VERSION,
                    event_version: TEST_PROTOCOL_VERSION,
                    sequence: event.sequence,
                    payload_bytes: 1,
                    checksum: u32::from(event.sequence as u8),
                },
                bytes: vec![event.sequence as u8],
            })
        }

        fn inspect_header(
            &self,
            frame: &[u8],
            _is_cancelled: &dyn Fn() -> bool,
        ) -> Result<FrameHeader, ProtocolError> {
            let sequence = u64::from(*frame.first().ok_or(ProtocolError::UnexpectedEnd)?);
            Ok(FrameHeader {
                frame_version: TEST_FRAME_VERSION,
                event_version: TEST_PROTOCOL_VERSION,
                sequence,
                payload_bytes: 1,
                checksum: u32::try_from(sequence).unwrap_or(u32::MAX),
            })
        }

        fn decode(
            &self,
            frame: &[u8],
            _limits: ProtocolLimits,
            _is_cancelled: &dyn Fn() -> bool,
        ) -> Result<TestEvent, ProtocolError> {
            let sequence = u64::from(*frame.first().ok_or(ProtocolError::UnexpectedEnd)?);
            Ok(TestEvent {
                protocol: TEST_PROTOCOL_VERSION,
                sequence,
                kind: TestEventKind::RunStarted { test_count: 0 },
            })
        }
    }

    #[test]
    fn seals_and_revalidates_complete_canonical_frame() {
        let event = TestEvent {
            protocol: TEST_PROTOCOL_VERSION,
            sequence: 3,
            kind: TestEventKind::RunStarted { test_count: 0 },
        };
        let encoded =
            seal_encoded_event(&FixtureCodec, &event, ProtocolLimits::standard(), &|| false)
                .expect("sealed event");
        assert_eq!(encoded.header().sequence, 3);
        assert_eq!(encoded.bytes(), &[3]);
        assert_eq!(
            decode_and_verify_event(
                &FixtureCodec,
                encoded.bytes(),
                ProtocolLimits::standard(),
                &|| false,
            )
            .expect("verified event"),
            event
        );
    }

    #[test]
    fn rejects_noncanonical_trailing_frame_bytes() {
        assert!(matches!(
            decode_and_verify_event(&FixtureCodec, &[0, 1], ProtocolLimits::standard(), &|| {
                false
            },),
            Err(ProtocolError::NonCanonical(_))
        ));
    }
}
