//! Stable host/guest event framing for full-image tests.

#![forbid(unsafe_code)]

use std::fmt;

use wrela_source::{FileId, Span, TextRange};
use wrela_test_model::{
    AssertionFailure, GuestTestOutcome, LanguageFatalCause, LogLevel, MAX_RUNTIME_TEST_EVENTS,
    MAX_TEST_EVENT_BYTES, TEST_PROTOCOL_VERSION, TestEvent, TestEventKind, TestId,
};

pub const TEST_FRAME_MAGIC: &[u8; 8] = b"WRELTST\0";
pub const TEST_FRAME_VERSION: u32 = 1;
/// Test-model protocol version independently supported by frame schema 1.
/// A model version bump must deliberately update this pin and the canonical
/// checked-in frame fixture.
pub const TEST_EVENT_VERSION: u32 = 3;
pub const TEST_FRAME_HEADER_BYTES: usize = 32;
pub const MAX_PROTOCOL_FRAME_BYTES: u32 = 1024 * 1024;
pub const MAX_PROTOCOL_STRING_BYTES: u32 = 256 * 1024;
pub const MAX_PROTOCOL_EVENTS: u32 = MAX_RUNTIME_TEST_EVENTS;
pub const MAX_PROTOCOL_STREAM_BYTES: u64 = 1024 * 1024 * 1024;

const CANCELLATION_POLL_BYTES: usize = 4096;
const CANCELLATION_POLL_ENTRIES: usize = 1024;

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
            frame_bytes: MAX_PROTOCOL_FRAME_BYTES,
            string_bytes: MAX_PROTOCOL_STRING_BYTES,
            events: MAX_PROTOCOL_EVENTS,
        }
    }

    pub fn validate(self) -> Result<(), ProtocolError> {
        if usize::try_from(self.frame_bytes)
            .ok()
            .is_none_or(|bytes| bytes < TEST_FRAME_HEADER_BYTES)
            || self.string_bytes == 0
            || self.events == 0
            || self.string_bytes > self.frame_bytes
        {
            return Err(ProtocolError::InvalidLimits);
        }
        check_limit(
            "frame bytes",
            u64::from(self.frame_bytes),
            u64::from(MAX_PROTOCOL_FRAME_BYTES),
        )?;
        check_limit(
            "string bytes",
            u64::from(self.string_bytes),
            u64::from(MAX_PROTOCOL_STRING_BYTES),
        )?;
        check_limit(
            "events",
            u64::from(self.events),
            u64::from(MAX_PROTOCOL_EVENTS),
        )?;
        if u64::from(MAX_PROTOCOL_FRAME_BYTES) != MAX_TEST_EVENT_BYTES as u64 {
            return Err(ProtocolError::ProtocolContractMismatch(
                "frame ceiling differs from the test model event ceiling",
            ));
        }
        if TEST_EVENT_VERSION != TEST_PROTOCOL_VERSION {
            return Err(ProtocolError::ProtocolContractMismatch(
                "frame schema event version differs from the test model protocol version",
            ));
        }
        Ok(())
    }

    /// Maximum complete unescaped stream accepted under these per-frame and
    /// event-count limits, capped by the protocol-wide output ceiling.
    pub fn maximum_stream_bytes(self) -> Result<u64, ProtocolError> {
        self.validate()?;
        u64::from(self.frame_bytes)
            .checked_mul(u64::from(self.events))
            .map(|bytes| bytes.min(MAX_PROTOCOL_STREAM_BYTES))
            .ok_or(ProtocolError::InvalidLimits)
    }
}

fn check_limit(resource: &'static str, actual: u64, maximum: u64) -> Result<(), ProtocolError> {
    if actual > maximum {
        Err(ProtocolError::LimitTooLarge {
            resource,
            maximum,
            actual,
        })
    } else {
        Ok(())
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

/// Canonical revision-1 host/guest test-event codec.
///
/// The byte representation is an unescaped binary frame. A target transport
/// may escape these bytes for PL011, but escaping is outside the stable event
/// schema and is removed before this codec is called. All integers are
/// little-endian. The fixed 32-byte header is magic, frame version, event
/// version, sequence, payload length, and CRC32C of the payload.
#[derive(Debug, Default, Clone, Copy)]
pub struct CanonicalTestEventCodec;

impl TestEventCodec for CanonicalTestEventCodec {
    fn encode(
        &self,
        event: &TestEvent,
        limits: ProtocolLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<EncodedEventCandidate, ProtocolError> {
        if is_cancelled() {
            return Err(ProtocolError::Cancelled);
        }
        validate_event(event, limits, is_cancelled)?;
        let frame_limit =
            usize::try_from(limits.frame_bytes).map_err(|_| ProtocolError::InvalidLimits)?;
        let payload_limit = frame_limit
            .checked_sub(TEST_FRAME_HEADER_BYTES)
            .ok_or(ProtocolError::InvalidLimits)?;
        let mut payload = PayloadWriter::new(payload_limit, limits.frame_bytes, is_cancelled);
        payload.u32(event.protocol)?;
        payload.u64(event.sequence)?;
        encode_event_kind(&mut payload, &event.kind, limits, is_cancelled)?;
        if is_cancelled() {
            return Err(ProtocolError::Cancelled);
        }
        let payload = payload.finish();
        let payload_bytes =
            u32::try_from(payload.len()).map_err(|_| ProtocolError::FrameTooLarge {
                limit: limits.frame_bytes,
                actual: payload.len(),
            })?;
        let checksum = crc32c_cancellable(&payload, is_cancelled)?;
        let header = FrameHeader {
            frame_version: TEST_FRAME_VERSION,
            event_version: TEST_EVENT_VERSION,
            sequence: event.sequence,
            payload_bytes,
            checksum,
        };
        let capacity = TEST_FRAME_HEADER_BYTES.checked_add(payload.len()).ok_or(
            ProtocolError::FrameTooLarge {
                limit: limits.frame_bytes,
                actual: usize::MAX,
            },
        )?;
        if capacity > frame_limit {
            return Err(ProtocolError::FrameTooLarge {
                limit: limits.frame_bytes,
                actual: capacity,
            });
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| ProtocolError::ResourceLimit {
                resource: "encoded frame bytes",
                limit: u64::from(limits.frame_bytes),
            })?;
        bytes.extend_from_slice(TEST_FRAME_MAGIC);
        bytes.extend_from_slice(&header.frame_version.to_le_bytes());
        bytes.extend_from_slice(&header.event_version.to_le_bytes());
        bytes.extend_from_slice(&header.sequence.to_le_bytes());
        bytes.extend_from_slice(&header.payload_bytes.to_le_bytes());
        bytes.extend_from_slice(&header.checksum.to_le_bytes());
        bytes.extend_from_slice(&payload);
        Ok(EncodedEventCandidate { header, bytes })
    }

    fn inspect_header(
        &self,
        frame: &[u8],
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<FrameHeader, ProtocolError> {
        if is_cancelled() {
            return Err(ProtocolError::Cancelled);
        }
        parse_header(frame)
    }

    fn decode(
        &self,
        frame: &[u8],
        limits: ProtocolLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<TestEvent, ProtocolError> {
        if is_cancelled() {
            return Err(ProtocolError::Cancelled);
        }
        limits.validate()?;
        let header = parse_header(frame)?;
        validate_frame_shape(frame, header, limits, is_cancelled)?;
        let payload = frame
            .get(TEST_FRAME_HEADER_BYTES..)
            .ok_or(ProtocolError::UnexpectedEnd)?;
        let mut reader = PayloadReader::new(payload, limits, is_cancelled);
        let protocol = reader.u32()?;
        let sequence = reader.u64()?;
        let kind = decode_event_kind(&mut reader)?;
        reader.finish()?;
        let event = TestEvent {
            protocol,
            sequence,
            kind,
        };
        validate_event(&event, limits, is_cancelled)?;
        if event.protocol != header.event_version || event.sequence != header.sequence {
            return Err(ProtocolError::SequenceMismatch {
                header: header.sequence,
                event: event.sequence,
            });
        }
        Ok(event)
    }
}

struct PayloadWriter<'a> {
    bytes: Vec<u8>,
    payload_limit: usize,
    frame_limit: u32,
    is_cancelled: &'a dyn Fn() -> bool,
}

impl<'a> PayloadWriter<'a> {
    fn new(payload_limit: usize, frame_limit: u32, is_cancelled: &'a dyn Fn() -> bool) -> Self {
        Self {
            bytes: Vec::new(),
            payload_limit,
            frame_limit,
            is_cancelled,
        }
    }

    fn extend(&mut self, value: &[u8]) -> Result<(), ProtocolError> {
        let actual =
            self.bytes
                .len()
                .checked_add(value.len())
                .ok_or(ProtocolError::FrameTooLarge {
                    limit: self.frame_limit,
                    actual: usize::MAX,
                })?;
        if actual > self.payload_limit {
            return Err(ProtocolError::FrameTooLarge {
                limit: self.frame_limit,
                actual: TEST_FRAME_HEADER_BYTES.saturating_add(actual),
            });
        }
        self.bytes
            .try_reserve(value.len())
            .map_err(|_| ProtocolError::ResourceLimit {
                resource: "encoded payload bytes",
                limit: u64::from(self.frame_limit),
            })?;
        for chunk in value.chunks(CANCELLATION_POLL_BYTES) {
            if (self.is_cancelled)() {
                return Err(ProtocolError::Cancelled);
            }
            self.bytes.extend_from_slice(chunk);
        }
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), ProtocolError> {
        self.extend(&[value])
    }

    fn u32(&mut self, value: u32) -> Result<(), ProtocolError> {
        self.extend(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), ProtocolError> {
        self.extend(&value.to_le_bytes())
    }

    fn string(&mut self, value: &str, limits: ProtocolLimits) -> Result<(), ProtocolError> {
        let length = u32::try_from(value.len()).map_err(|_| ProtocolError::StringTooLarge {
            limit: limits.string_bytes,
            actual: value.len(),
        })?;
        if length > limits.string_bytes {
            return Err(ProtocolError::StringTooLarge {
                limit: limits.string_bytes,
                actual: value.len(),
            });
        }
        self.u32(length)?;
        self.extend(value.as_bytes())
    }

    fn optional_string(
        &mut self,
        value: Option<&str>,
        limits: ProtocolLimits,
    ) -> Result<(), ProtocolError> {
        match value {
            None => self.u8(0),
            Some(value) => {
                self.u8(1)?;
                self.string(value, limits)
            }
        }
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

struct PayloadReader<'a> {
    bytes: &'a [u8],
    offset: usize,
    limits: ProtocolLimits,
    is_cancelled: &'a dyn Fn() -> bool,
}

impl<'a> PayloadReader<'a> {
    fn new(bytes: &'a [u8], limits: ProtocolLimits, is_cancelled: &'a dyn Fn() -> bool) -> Self {
        Self {
            bytes,
            offset: 0,
            limits,
            is_cancelled,
        }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], ProtocolError> {
        if (self.is_cancelled)() {
            return Err(ProtocolError::Cancelled);
        }
        let end = self
            .offset
            .checked_add(count)
            .ok_or(ProtocolError::UnexpectedEnd)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(ProtocolError::UnexpectedEnd)?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, ProtocolError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(ProtocolError::UnexpectedEnd)
    }

    fn u32(&mut self) -> Result<u32, ProtocolError> {
        let value = self.take(4)?;
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(value);
        Ok(u32::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, ProtocolError> {
        let value = self.take(8)?;
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(value);
        Ok(u64::from_le_bytes(bytes))
    }

    fn string(&mut self) -> Result<String, ProtocolError> {
        let length = usize::try_from(self.u32()?).map_err(|_| ProtocolError::StringTooLarge {
            limit: self.limits.string_bytes,
            actual: usize::MAX,
        })?;
        if length > self.limits.string_bytes as usize {
            return Err(ProtocolError::StringTooLarge {
                limit: self.limits.string_bytes,
                actual: length,
            });
        }
        let bytes = self.take(length)?;
        copy_utf8(bytes, self.is_cancelled)
    }

    fn optional_string(&mut self, kind: &'static str) -> Result<Option<String>, ProtocolError> {
        match self.u8()? {
            0 => Ok(None),
            1 => self.string().map(Some),
            tag => Err(ProtocolError::InvalidTag {
                kind,
                tag: u64::from(tag),
            }),
        }
    }

    fn finish(self) -> Result<(), ProtocolError> {
        if (self.is_cancelled)() {
            return Err(ProtocolError::Cancelled);
        }
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(ProtocolError::TrailingBytes)
        }
    }
}

fn copy_utf8(bytes: &[u8], is_cancelled: &dyn Fn() -> bool) -> Result<String, ProtocolError> {
    let mut output = String::new();
    output
        .try_reserve_exact(bytes.len())
        .map_err(|_| ProtocolError::ResourceLimit {
            resource: "decoded string bytes",
            limit: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        })?;
    let mut offset = 0usize;
    while offset < bytes.len() {
        if is_cancelled() {
            return Err(ProtocolError::Cancelled);
        }
        let mut end = offset
            .checked_add(CANCELLATION_POLL_BYTES)
            .unwrap_or(bytes.len())
            .min(bytes.len());
        if end < bytes.len() {
            while end < bytes.len() && bytes[end] & 0xc0 == 0x80 {
                end += 1;
            }
        }
        let chunk =
            std::str::from_utf8(bytes.get(offset..end).ok_or(ProtocolError::UnexpectedEnd)?)
                .map_err(|_| ProtocolError::InvalidUtf8)?;
        output.push_str(chunk);
        offset = end;
    }
    if is_cancelled() {
        Err(ProtocolError::Cancelled)
    } else {
        Ok(output)
    }
}

fn encode_event_kind(
    output: &mut PayloadWriter<'_>,
    kind: &TestEventKind,
    limits: ProtocolLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ProtocolError> {
    if is_cancelled() {
        return Err(ProtocolError::Cancelled);
    }
    match kind {
        TestEventKind::RunStarted { test_count } => {
            output.u8(0)?;
            output.u32(*test_count)
        }
        TestEventKind::TestStarted { test } => {
            output.u8(1)?;
            output.u32(test.0)
        }
        TestEventKind::Log {
            test,
            level,
            message,
        } => {
            output.u8(2)?;
            match test {
                None => output.u8(0)?,
                Some(test) => {
                    output.u8(1)?;
                    output.u32(test.0)?;
                }
            }
            output.u8(log_level_tag(*level))?;
            output.string(message, limits)
        }
        TestEventKind::AssertionFailed { test, failure } => {
            output.u8(3)?;
            output.u32(test.0)?;
            output.string(&failure.expression, limits)?;
            output.optional_string(failure.message.as_deref(), limits)?;
            match failure.source {
                None => output.u8(0)?,
                Some(source) => {
                    output.u8(1)?;
                    output.u32(source.file.0)?;
                    output.u32(source.range.start)?;
                    output.u32(source.range.end)?;
                }
            }
            output.optional_string(failure.expected.as_deref(), limits)?;
            output.optional_string(failure.actual.as_deref(), limits)
        }
        TestEventKind::TestFinished { test, outcome } => {
            output.u8(4)?;
            output.u32(test.0)?;
            match outcome {
                GuestTestOutcome::Passed => output.u8(0),
                GuestTestOutcome::Failed { message } => {
                    output.u8(1)?;
                    output.string(message, limits)
                }
                GuestTestOutcome::TimedOut { timeout_ns } => {
                    output.u8(2)?;
                    output.u64(*timeout_ns)
                }
                GuestTestOutcome::LanguageFatal { cause } => {
                    output.u8(3)?;
                    output.u8(language_fatal_cause_tag(*cause))
                }
            }
        }
        TestEventKind::Heartbeat { monotonic_ticks } => {
            output.u8(5)?;
            output.u64(*monotonic_ticks)
        }
        TestEventKind::RunFinished { passed, failed } => {
            output.u8(6)?;
            output.u32(*passed)?;
            output.u32(*failed)
        }
    }
}

fn decode_event_kind(reader: &mut PayloadReader<'_>) -> Result<TestEventKind, ProtocolError> {
    match reader.u8()? {
        0 => Ok(TestEventKind::RunStarted {
            test_count: reader.u32()?,
        }),
        1 => Ok(TestEventKind::TestStarted {
            test: TestId(reader.u32()?),
        }),
        2 => {
            let test = match reader.u8()? {
                0 => None,
                1 => Some(TestId(reader.u32()?)),
                tag => {
                    return Err(ProtocolError::InvalidTag {
                        kind: "optional test",
                        tag: u64::from(tag),
                    });
                }
            };
            let level = decode_log_level(reader.u8()?)?;
            let message = reader.string()?;
            Ok(TestEventKind::Log {
                test,
                level,
                message,
            })
        }
        3 => {
            let test = TestId(reader.u32()?);
            let expression = reader.string()?;
            let message = reader.optional_string("optional assertion message")?;
            let source = match reader.u8()? {
                0 => None,
                1 => {
                    let file = FileId(reader.u32()?);
                    let start = reader.u32()?;
                    let end = reader.u32()?;
                    let range = TextRange::new(start, end)
                        .map_err(|_| ProtocolError::InvalidSourceRange { start, end })?;
                    Some(Span { file, range })
                }
                tag => {
                    return Err(ProtocolError::InvalidTag {
                        kind: "optional assertion source",
                        tag: u64::from(tag),
                    });
                }
            };
            let expected = reader.optional_string("optional expected value")?;
            let actual = reader.optional_string("optional actual value")?;
            Ok(TestEventKind::AssertionFailed {
                test,
                failure: AssertionFailure {
                    expression,
                    message,
                    source,
                    expected,
                    actual,
                },
            })
        }
        4 => {
            let test = TestId(reader.u32()?);
            let outcome = match reader.u8()? {
                0 => GuestTestOutcome::Passed,
                1 => GuestTestOutcome::Failed {
                    message: reader.string()?,
                },
                2 => GuestTestOutcome::TimedOut {
                    timeout_ns: reader.u64()?,
                },
                3 => GuestTestOutcome::LanguageFatal {
                    cause: decode_language_fatal_cause(reader.u8()?)?,
                },
                tag => {
                    return Err(ProtocolError::InvalidTag {
                        kind: "guest outcome",
                        tag: u64::from(tag),
                    });
                }
            };
            Ok(TestEventKind::TestFinished { test, outcome })
        }
        5 => Ok(TestEventKind::Heartbeat {
            monotonic_ticks: reader.u64()?,
        }),
        6 => Ok(TestEventKind::RunFinished {
            passed: reader.u32()?,
            failed: reader.u32()?,
        }),
        tag => Err(ProtocolError::InvalidTag {
            kind: "event",
            tag: u64::from(tag),
        }),
    }
}

fn log_level_tag(level: LogLevel) -> u8 {
    match level {
        LogLevel::Trace => 0,
        LogLevel::Debug => 1,
        LogLevel::Info => 2,
        LogLevel::Warning => 3,
        LogLevel::Error => 4,
    }
}

fn decode_log_level(tag: u8) -> Result<LogLevel, ProtocolError> {
    match tag {
        0 => Ok(LogLevel::Trace),
        1 => Ok(LogLevel::Debug),
        2 => Ok(LogLevel::Info),
        3 => Ok(LogLevel::Warning),
        4 => Ok(LogLevel::Error),
        tag => Err(ProtocolError::InvalidTag {
            kind: "log level",
            tag: u64::from(tag),
        }),
    }
}

fn language_fatal_cause_tag(cause: LanguageFatalCause) -> u8 {
    match cause {
        LanguageFatalCause::CheckedShiftResultLoss => 0,
        LanguageFatalCause::InvalidShiftCount => 1,
    }
}

fn decode_language_fatal_cause(tag: u8) -> Result<LanguageFatalCause, ProtocolError> {
    match tag {
        0 => Ok(LanguageFatalCause::CheckedShiftResultLoss),
        1 => Ok(LanguageFatalCause::InvalidShiftCount),
        tag => Err(ProtocolError::InvalidTag {
            kind: "language fatal cause",
            tag: u64::from(tag),
        }),
    }
}

fn parse_header(frame: &[u8]) -> Result<FrameHeader, ProtocolError> {
    if frame.len() < TEST_FRAME_HEADER_BYTES {
        return Err(ProtocolError::UnexpectedEnd);
    }
    if frame.get(..TEST_FRAME_MAGIC.len()) != Some(TEST_FRAME_MAGIC.as_slice()) {
        return Err(ProtocolError::InvalidMagic);
    }
    Ok(FrameHeader {
        frame_version: fixed_u32(frame, 8)?,
        event_version: fixed_u32(frame, 12)?,
        sequence: fixed_u64(frame, 16)?,
        payload_bytes: fixed_u32(frame, 24)?,
        checksum: fixed_u32(frame, 28)?,
    })
}

fn fixed_u32(bytes: &[u8], offset: usize) -> Result<u32, ProtocolError> {
    let end = offset.checked_add(4).ok_or(ProtocolError::UnexpectedEnd)?;
    let value = bytes.get(offset..end).ok_or(ProtocolError::UnexpectedEnd)?;
    let mut fixed = [0u8; 4];
    fixed.copy_from_slice(value);
    Ok(u32::from_le_bytes(fixed))
}

fn fixed_u64(bytes: &[u8], offset: usize) -> Result<u64, ProtocolError> {
    let end = offset.checked_add(8).ok_or(ProtocolError::UnexpectedEnd)?;
    let value = bytes.get(offset..end).ok_or(ProtocolError::UnexpectedEnd)?;
    let mut fixed = [0u8; 8];
    fixed.copy_from_slice(value);
    Ok(u64::from_le_bytes(fixed))
}

fn crc32c_cancellable(bytes: &[u8], is_cancelled: &dyn Fn() -> bool) -> Result<u32, ProtocolError> {
    let mut checksum = !0u32;
    for chunk in bytes.chunks(CANCELLATION_POLL_BYTES) {
        if is_cancelled() {
            return Err(ProtocolError::Cancelled);
        }
        for byte in chunk {
            checksum ^= u32::from(*byte);
            for _ in 0..8 {
                checksum = (checksum >> 1) ^ (0x82f6_3b78 & (0u32.wrapping_sub(checksum & 1)));
            }
        }
    }
    if is_cancelled() {
        return Err(ProtocolError::Cancelled);
    }
    Ok(!checksum)
}

fn bytes_equal(
    left: &[u8],
    right: &[u8],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, ProtocolError> {
    if is_cancelled() {
        return Err(ProtocolError::Cancelled);
    }
    if left.len() != right.len() {
        return Ok(false);
    }
    for (left, right) in left
        .chunks(CANCELLATION_POLL_BYTES)
        .zip(right.chunks(CANCELLATION_POLL_BYTES))
    {
        if is_cancelled() {
            return Err(ProtocolError::Cancelled);
        }
        if left != right {
            return Ok(false);
        }
    }
    if is_cancelled() {
        Err(ProtocolError::Cancelled)
    } else {
        Ok(true)
    }
}

fn optional_strings_equal(
    left: Option<&str>,
    right: Option<&str>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, ProtocolError> {
    match (left, right) {
        (Some(left), Some(right)) => bytes_equal(left.as_bytes(), right.as_bytes(), is_cancelled),
        (None, None) => Ok(true),
        (Some(_), None) | (None, Some(_)) => Ok(false),
    }
}

fn outcomes_equal(
    left: &GuestTestOutcome,
    right: &GuestTestOutcome,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, ProtocolError> {
    match (left, right) {
        (GuestTestOutcome::Passed, GuestTestOutcome::Passed) => Ok(true),
        (
            GuestTestOutcome::Failed { message: left },
            GuestTestOutcome::Failed { message: right },
        ) => bytes_equal(left.as_bytes(), right.as_bytes(), is_cancelled),
        (
            GuestTestOutcome::TimedOut { timeout_ns: left },
            GuestTestOutcome::TimedOut { timeout_ns: right },
        ) => Ok(left == right),
        (
            GuestTestOutcome::LanguageFatal { cause: left },
            GuestTestOutcome::LanguageFatal { cause: right },
        ) => Ok(left == right),
        _ => Ok(false),
    }
}

fn events_equal(
    left: &TestEvent,
    right: &TestEvent,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, ProtocolError> {
    if is_cancelled() {
        return Err(ProtocolError::Cancelled);
    }
    if left.protocol != right.protocol || left.sequence != right.sequence {
        return Ok(false);
    }
    match (&left.kind, &right.kind) {
        (
            TestEventKind::RunStarted { test_count: left },
            TestEventKind::RunStarted { test_count: right },
        ) => Ok(left == right),
        (TestEventKind::TestStarted { test: left }, TestEventKind::TestStarted { test: right }) => {
            Ok(left == right)
        }
        (
            TestEventKind::Log {
                test: left_test,
                level: left_level,
                message: left_message,
            },
            TestEventKind::Log {
                test: right_test,
                level: right_level,
                message: right_message,
            },
        ) => Ok(left_test == right_test
            && left_level == right_level
            && bytes_equal(
                left_message.as_bytes(),
                right_message.as_bytes(),
                is_cancelled,
            )?),
        (
            TestEventKind::AssertionFailed {
                test: left_test,
                failure: left,
            },
            TestEventKind::AssertionFailed {
                test: right_test,
                failure: right,
            },
        ) => Ok(left_test == right_test
            && left.source == right.source
            && bytes_equal(
                left.expression.as_bytes(),
                right.expression.as_bytes(),
                is_cancelled,
            )?
            && optional_strings_equal(
                left.message.as_deref(),
                right.message.as_deref(),
                is_cancelled,
            )?
            && optional_strings_equal(
                left.expected.as_deref(),
                right.expected.as_deref(),
                is_cancelled,
            )?
            && optional_strings_equal(
                left.actual.as_deref(),
                right.actual.as_deref(),
                is_cancelled,
            )?),
        (
            TestEventKind::TestFinished {
                test: left_test,
                outcome: left,
            },
            TestEventKind::TestFinished {
                test: right_test,
                outcome: right,
            },
        ) => Ok(left_test == right_test && outcomes_equal(left, right, is_cancelled)?),
        (
            TestEventKind::Heartbeat {
                monotonic_ticks: left,
            },
            TestEventKind::Heartbeat {
                monotonic_ticks: right,
            },
        ) => Ok(left == right),
        (
            TestEventKind::RunFinished {
                passed: left_passed,
                failed: left_failed,
            },
            TestEventKind::RunFinished {
                passed: right_passed,
                failed: right_failed,
            },
        ) => Ok(left_passed == right_passed && left_failed == right_failed),
        _ => Ok(false),
    }
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
    validate_event(event, limits, is_cancelled)?;
    let candidate = codec.encode(event, limits, is_cancelled)?;
    validate_frame_shape(&candidate.bytes, candidate.header, limits, is_cancelled)?;
    if codec.inspect_header(&candidate.bytes, is_cancelled)? != candidate.header {
        return Err(ProtocolError::NonCanonical(
            "encoded header differs from its bytes",
        ));
    }
    let decoded = decode_and_verify_event(codec, &candidate.bytes, limits, is_cancelled)?;
    if !events_equal(event, &decoded, is_cancelled)? {
        return Err(ProtocolError::NonCanonical(
            "encoded event differs from its input",
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
    let frame_limit =
        usize::try_from(limits.frame_bytes).map_err(|_| ProtocolError::InvalidLimits)?;
    if frame.len() > frame_limit {
        return Err(ProtocolError::FrameTooLarge {
            limit: limits.frame_bytes,
            actual: frame.len(),
        });
    }
    let header = codec.inspect_header(frame, is_cancelled)?;
    validate_frame_shape(frame, header, limits, is_cancelled)?;
    let event = codec.decode(frame, limits, is_cancelled)?;
    validate_event(&event, limits, is_cancelled)?;
    if header.sequence != event.sequence {
        return Err(ProtocolError::SequenceMismatch {
            header: header.sequence,
            event: event.sequence,
        });
    }
    let canonical = codec.encode(&event, limits, is_cancelled)?;
    validate_frame_shape(&canonical.bytes, canonical.header, limits, is_cancelled)?;
    if canonical.header != header || !bytes_equal(&canonical.bytes, frame, is_cancelled)? {
        return Err(ProtocolError::NonCanonical(
            "decoded event does not reproduce its complete frame",
        ));
    }
    Ok(event)
}

/// Decode a complete concatenation of canonical frames and independently
/// enforce the stream's dense zero-based sequence. PL011 unescaping must occur
/// before this function; no incomplete trailing frame is accepted.
pub fn decode_and_verify_stream(
    codec: &dyn TestEventCodec,
    stream: &[u8],
    limits: ProtocolLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<TestEvent>, ProtocolError> {
    if is_cancelled() {
        return Err(ProtocolError::Cancelled);
    }
    let maximum_stream_bytes = limits.maximum_stream_bytes()?;
    let actual_stream_bytes =
        u64::try_from(stream.len()).map_err(|_| ProtocolError::StreamTooLarge {
            limit: maximum_stream_bytes,
            actual: u64::MAX,
        })?;
    if actual_stream_bytes > maximum_stream_bytes {
        return Err(ProtocolError::StreamTooLarge {
            limit: maximum_stream_bytes,
            actual: actual_stream_bytes,
        });
    }
    let mut offset = 0usize;
    let mut events = Vec::new();
    let mut stream_state = StreamState::new(limits.events);
    let frame_limit =
        usize::try_from(limits.frame_bytes).map_err(|_| ProtocolError::InvalidLimits)?;
    while offset < stream.len() {
        if is_cancelled() {
            return Err(ProtocolError::Cancelled);
        }
        let expected_sequence =
            u64::try_from(events.len()).map_err(|_| ProtocolError::EventLimit {
                limit: limits.events,
                sequence: u64::MAX,
            })?;
        if expected_sequence >= u64::from(limits.events) {
            return Err(ProtocolError::EventLimit {
                limit: limits.events,
                sequence: expected_sequence,
            });
        }
        let remaining = stream.get(offset..).ok_or(ProtocolError::UnexpectedEnd)?;
        let header = codec.inspect_header(remaining, is_cancelled)?;
        let payload_bytes =
            usize::try_from(header.payload_bytes).map_err(|_| ProtocolError::FrameTooLarge {
                limit: limits.frame_bytes,
                actual: usize::MAX,
            })?;
        let frame_bytes = TEST_FRAME_HEADER_BYTES.checked_add(payload_bytes).ok_or(
            ProtocolError::FrameTooLarge {
                limit: limits.frame_bytes,
                actual: usize::MAX,
            },
        )?;
        if frame_bytes > frame_limit {
            return Err(ProtocolError::FrameTooLarge {
                limit: limits.frame_bytes,
                actual: frame_bytes,
            });
        }
        let end = offset
            .checked_add(frame_bytes)
            .ok_or(ProtocolError::UnexpectedEnd)?;
        let frame = stream
            .get(offset..end)
            .ok_or(ProtocolError::UnexpectedEnd)?;
        let event = decode_and_verify_event(codec, frame, limits, is_cancelled)?;
        if event.sequence != expected_sequence {
            return Err(ProtocolError::StreamSequenceMismatch {
                expected: expected_sequence,
                actual: event.sequence,
            });
        }
        stream_state.observe(&event, is_cancelled)?;
        events
            .try_reserve(1)
            .map_err(|_| ProtocolError::ResourceLimit {
                resource: "decoded event entries",
                limit: u64::from(limits.events),
            })?;
        events.push(event);
        offset = end;
    }
    if is_cancelled() {
        return Err(ProtocolError::Cancelled);
    }
    Ok(events)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TrackedTestState {
    Active,
    Finished,
}

#[derive(Debug, Clone, Copy)]
struct TestStateSlot {
    test: TestId,
    state: TrackedTestState,
}

struct TestStateTable {
    slots: Vec<Option<TestStateSlot>>,
    entries: usize,
    maximum: u32,
}

impl TestStateTable {
    fn new(maximum: u32) -> Self {
        Self {
            slots: Vec::new(),
            entries: 0,
            maximum,
        }
    }

    fn set_maximum(&mut self, maximum: u32) {
        self.maximum = maximum;
    }

    fn state(
        &self,
        test: TestId,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Option<TrackedTestState>, ProtocolError> {
        Ok(self
            .find(test, is_cancelled)?
            .and_then(|index| self.slots.get(index))
            .and_then(Option::as_ref)
            .map(|slot| slot.state))
    }

    fn insert_active(
        &mut self,
        test: TestId,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<bool, ProtocolError> {
        if self.find(test, is_cancelled)?.is_some() {
            return Ok(false);
        }
        self.ensure_insert_capacity(is_cancelled)?;
        let slot = TestStateSlot {
            test,
            state: TrackedTestState::Active,
        };
        if !place_test_slot(&mut self.slots, slot, is_cancelled)? {
            return Err(ProtocolError::ProtocolContractMismatch(
                "test-state table has no insertion slot",
            ));
        }
        self.entries = self
            .entries
            .checked_add(1)
            .ok_or(ProtocolError::ResourceLimit {
                resource: "test-state entries",
                limit: u64::from(self.maximum),
            })?;
        Ok(true)
    }

    fn mark_finished(
        &mut self,
        test: TestId,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<bool, ProtocolError> {
        let Some(index) = self.find(test, is_cancelled)? else {
            return Ok(false);
        };
        let Some(Some(slot)) = self.slots.get_mut(index) else {
            return Ok(false);
        };
        if slot.state != TrackedTestState::Active {
            return Ok(false);
        }
        slot.state = TrackedTestState::Finished;
        Ok(true)
    }

    fn find(
        &self,
        test: TestId,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Option<usize>, ProtocolError> {
        if self.slots.is_empty() {
            return Ok(None);
        }
        let mask = self.slots.len() - 1;
        let mut index = test_slot_start(test, mask);
        for probe in 0..self.slots.len() {
            poll_entries(probe, is_cancelled)?;
            match self.slots.get(index) {
                Some(Some(slot)) if slot.test == test => return Ok(Some(index)),
                Some(Some(_)) => index = (index + 1) & mask,
                Some(None) | None => return Ok(None),
            }
        }
        Ok(None)
    }

    fn ensure_insert_capacity(
        &mut self,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), ProtocolError> {
        let required = self
            .entries
            .checked_add(1)
            .ok_or(ProtocolError::ResourceLimit {
                resource: "test-state entries",
                limit: u64::from(self.maximum),
            })?;
        let maximum = usize::try_from(self.maximum).map_err(|_| ProtocolError::ResourceLimit {
            resource: "test-state entries",
            limit: u64::from(self.maximum),
        })?;
        if required > maximum {
            return Err(ProtocolError::ResourceLimit {
                resource: "test-state entries",
                limit: u64::from(self.maximum),
            });
        }
        if !self.slots.is_empty() && required <= self.slots.len() / 2 {
            return Ok(());
        }
        let maximum_capacity = maximum
            .checked_mul(2)
            .and_then(usize::checked_next_power_of_two)
            .ok_or(ProtocolError::ResourceLimit {
                resource: "test-state table slots",
                limit: u64::from(self.maximum),
            })?;
        let proposed = if self.slots.is_empty() {
            2
        } else {
            self.slots
                .len()
                .checked_mul(2)
                .ok_or(ProtocolError::ResourceLimit {
                    resource: "test-state table slots",
                    limit: u64::from(self.maximum),
                })?
        };
        let capacity = proposed.min(maximum_capacity);
        if capacity <= self.slots.len() || capacity < required {
            return Err(ProtocolError::ResourceLimit {
                resource: "test-state table slots",
                limit: u64::from(self.maximum),
            });
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity)
            .map_err(|_| ProtocolError::ResourceLimit {
                resource: "test-state table slots",
                limit: u64::from(self.maximum),
            })?;
        slots.resize(capacity, None);
        for (index, slot) in self.slots.iter().flatten().copied().enumerate() {
            poll_entries(index, is_cancelled)?;
            if !place_test_slot(&mut slots, slot, is_cancelled)? {
                return Err(ProtocolError::ProtocolContractMismatch(
                    "test-state table rehash failed",
                ));
            }
        }
        self.slots = slots;
        Ok(())
    }
}

fn test_slot_start(test: TestId, mask: usize) -> usize {
    let mixed = test.0.wrapping_mul(0x9e37_79b9) ^ test.0.rotate_right(16);
    usize::try_from(mixed).unwrap_or(0) & mask
}

fn place_test_slot(
    slots: &mut [Option<TestStateSlot>],
    slot: TestStateSlot,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, ProtocolError> {
    if slots.is_empty() {
        return Ok(false);
    }
    let mask = slots.len() - 1;
    let mut index = test_slot_start(slot.test, mask);
    for probe in 0..slots.len() {
        poll_entries(probe, is_cancelled)?;
        match slots.get(index) {
            Some(None) => {
                if let Some(destination) = slots.get_mut(index) {
                    *destination = Some(slot);
                    return Ok(true);
                }
                return Ok(false);
            }
            Some(Some(_)) => index = (index + 1) & mask,
            None => return Ok(false),
        }
    }
    Ok(false)
}

fn poll_entries(index: usize, is_cancelled: &dyn Fn() -> bool) -> Result<(), ProtocolError> {
    if index & (CANCELLATION_POLL_ENTRIES - 1) == 0 && is_cancelled() {
        Err(ProtocolError::Cancelled)
    } else {
        Ok(())
    }
}

struct StreamState {
    declared_tests: Option<u32>,
    tests: TestStateTable,
    started: u32,
    finished: u32,
    passed: u32,
    failed: u32,
    language_fatal: bool,
    pending_assertion: Option<(TestId, String)>,
    last_heartbeat: Option<u64>,
    terminal: bool,
}

impl StreamState {
    fn new(maximum_tests: u32) -> Self {
        Self {
            declared_tests: None,
            tests: TestStateTable::new(maximum_tests),
            started: 0,
            finished: 0,
            passed: 0,
            failed: 0,
            language_fatal: false,
            pending_assertion: None,
            last_heartbeat: None,
            terminal: false,
        }
    }

    fn observe(
        &mut self,
        event: &TestEvent,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), ProtocolError> {
        if is_cancelled() {
            return Err(ProtocolError::Cancelled);
        }
        if let TestEventKind::RunStarted { test_count } = event.kind {
            if self.declared_tests.is_some() || event.sequence != 0 {
                return Err(ProtocolError::InvalidStreamOrder {
                    sequence: event.sequence,
                    reason: "RunStarted must appear exactly once at sequence zero",
                });
            }
            if test_count > self.tests.maximum {
                return Err(ProtocolError::TestCountExceeded {
                    sequence: event.sequence,
                    limit: self.tests.maximum,
                    actual: test_count,
                });
            }
            self.declared_tests = Some(test_count);
            self.tests.set_maximum(test_count);
            return Ok(());
        }
        let declared = self
            .declared_tests
            .ok_or(ProtocolError::InvalidStreamOrder {
                sequence: event.sequence,
                reason: "RunStarted must precede every other event",
            })?;
        if self.terminal {
            return Err(ProtocolError::InvalidStreamOrder {
                sequence: event.sequence,
                reason: "no event may follow RunFinished",
            });
        }
        if self.language_fatal && !matches!(&event.kind, TestEventKind::RunFinished { .. }) {
            return Err(ProtocolError::InvalidStreamOrder {
                sequence: event.sequence,
                reason: "LanguageFatal must be followed immediately by RunFinished",
            });
        }
        if let Some((asserted_test, terminal_message)) = &self.pending_assertion {
            if !matches!(
                &event.kind,
                TestEventKind::TestFinished {
                    test,
                    outcome: GuestTestOutcome::Failed { message },
                } if test == asserted_test && message == terminal_message
            ) {
                return Err(ProtocolError::InvalidStreamOrder {
                    sequence: event.sequence,
                    reason: "AssertionFailed must be followed immediately by its exact failed TestFinished",
                });
            }
        }
        match &event.kind {
            TestEventKind::TestStarted { test } => {
                let actual = self
                    .started
                    .checked_add(1)
                    .ok_or(ProtocolError::ResourceLimit {
                        resource: "started test count",
                        limit: u64::from(declared),
                    })?;
                if actual > declared {
                    return Err(ProtocolError::TestCountExceeded {
                        sequence: event.sequence,
                        limit: declared,
                        actual,
                    });
                }
                if !self.tests.insert_active(*test, is_cancelled)? {
                    return Err(ProtocolError::DuplicateTestStart {
                        sequence: event.sequence,
                        test: test.0,
                    });
                }
                self.started = actual;
            }
            TestEventKind::Log {
                test: Some(test), ..
            } => self.require_active(event.sequence, *test, "Log", is_cancelled)?,
            TestEventKind::AssertionFailed { test, failure } => {
                self.require_active(event.sequence, *test, "AssertionFailed", is_cancelled)?;
                self.pending_assertion = Some((
                    *test,
                    failure
                        .message
                        .clone()
                        .unwrap_or_else(|| "assertion failed".to_owned()),
                ));
            }
            TestEventKind::TestFinished { test, outcome } => {
                self.require_active(event.sequence, *test, "TestFinished", is_cancelled)?;
                if !self.tests.mark_finished(*test, is_cancelled)? {
                    return Err(ProtocolError::InvalidTestReference {
                        sequence: event.sequence,
                        test: test.0,
                        event: "TestFinished",
                    });
                }
                self.finished = checked_stream_count(self.finished, declared, "finished tests")?;
                match outcome {
                    GuestTestOutcome::Passed => {
                        self.passed = checked_stream_count(self.passed, declared, "passed tests")?;
                    }
                    GuestTestOutcome::Failed { .. } | GuestTestOutcome::TimedOut { .. } => {
                        self.failed = checked_stream_count(self.failed, declared, "failed tests")?;
                    }
                    GuestTestOutcome::LanguageFatal { .. } => {
                        self.failed = checked_stream_count(self.failed, declared, "failed tests")?;
                        self.language_fatal = true;
                    }
                }
                self.pending_assertion = None;
            }
            TestEventKind::Heartbeat { monotonic_ticks } => {
                if let Some(previous) = self.last_heartbeat {
                    if previous >= *monotonic_ticks {
                        return Err(ProtocolError::NonMonotonicHeartbeat {
                            sequence: event.sequence,
                            previous,
                            actual: *monotonic_ticks,
                        });
                    }
                }
                self.last_heartbeat = Some(*monotonic_ticks);
            }
            TestEventKind::RunFinished { passed, failed } => {
                if self.started != declared
                    || self.finished != declared
                    || self.passed != *passed
                    || self.failed != *failed
                    || passed.checked_add(*failed) != Some(declared)
                {
                    return Err(ProtocolError::StreamSummaryMismatch {
                        sequence: event.sequence,
                        declared,
                        started: self.started,
                        finished: self.finished,
                        observed_passed: self.passed,
                        observed_failed: self.failed,
                        reported_passed: *passed,
                        reported_failed: *failed,
                    });
                }
                self.terminal = true;
            }
            TestEventKind::Log { test: None, .. } => {}
            TestEventKind::RunStarted { .. } => {
                return Err(ProtocolError::InvalidStreamOrder {
                    sequence: event.sequence,
                    reason: "RunStarted must appear exactly once",
                });
            }
        }
        Ok(())
    }

    fn require_active(
        &self,
        sequence: u64,
        test: TestId,
        event: &'static str,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<(), ProtocolError> {
        if self.tests.state(test, is_cancelled)? == Some(TrackedTestState::Active) {
            Ok(())
        } else {
            Err(ProtocolError::InvalidTestReference {
                sequence,
                test: test.0,
                event,
            })
        }
    }
}

fn checked_stream_count(
    value: u32,
    limit: u32,
    resource: &'static str,
) -> Result<u32, ProtocolError> {
    value
        .checked_add(1)
        .filter(|value| *value <= limit)
        .ok_or(ProtocolError::ResourceLimit {
            resource,
            limit: u64::from(limit),
        })
}

fn validate_event(
    event: &TestEvent,
    limits: ProtocolLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ProtocolError> {
    if is_cancelled() {
        return Err(ProtocolError::Cancelled);
    }
    limits.validate()?;
    if event.protocol != TEST_EVENT_VERSION {
        return Err(ProtocolError::UnsupportedEventVersion(event.protocol));
    }
    if event.sequence >= u64::from(limits.events) {
        return Err(ProtocolError::EventLimit {
            limit: limits.events,
            sequence: event.sequence,
        });
    }
    let validate_string = |value: &str| -> Result<(), ProtocolError> {
        if value.len() > limits.string_bytes as usize {
            Err(ProtocolError::StringTooLarge {
                limit: limits.string_bytes,
                actual: value.len(),
            })
        } else {
            Ok(())
        }
    };
    match &event.kind {
        TestEventKind::Log { message, .. } => {
            validate_string(message)?;
            if message.is_empty() {
                return Err(ProtocolError::NonCanonical("log message is empty"));
            }
        }
        TestEventKind::AssertionFailed { failure, .. } => {
            validate_string(&failure.expression)?;
            if !contains_non_whitespace(&failure.expression, is_cancelled)? {
                return Err(ProtocolError::NonCanonical("assertion expression is empty"));
            }
            for value in [
                failure.message.as_deref(),
                failure.expected.as_deref(),
                failure.actual.as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                validate_string(value)?;
            }
            if failure
                .message
                .as_ref()
                .is_some_and(|message| !message.chars().any(|character| !character.is_whitespace()))
            {
                return Err(ProtocolError::NonCanonical("assertion message is empty"));
            }
            if let Some(source) = failure.source {
                if source.range.start > source.range.end {
                    return Err(ProtocolError::InvalidSourceRange {
                        start: source.range.start,
                        end: source.range.end,
                    });
                }
            }
        }
        TestEventKind::TestFinished {
            outcome: GuestTestOutcome::Failed { message },
            ..
        } => {
            validate_string(message)?;
            if !contains_non_whitespace(message, is_cancelled)? {
                return Err(ProtocolError::NonCanonical("failed test message is empty"));
            }
        }
        TestEventKind::TestFinished {
            outcome: GuestTestOutcome::TimedOut { timeout_ns: 0 },
            ..
        } => {
            return Err(ProtocolError::NonCanonical("test timeout must be nonzero"));
        }
        TestEventKind::RunFinished { passed, failed } => {
            if passed
                .checked_add(*failed)
                .is_none_or(|total| total > limits.events)
            {
                return Err(ProtocolError::ResourceLimit {
                    resource: "terminal test count",
                    limit: u64::from(limits.events),
                });
            }
        }
        TestEventKind::RunStarted { .. }
        | TestEventKind::TestStarted { .. }
        | TestEventKind::TestFinished { .. }
        | TestEventKind::Heartbeat { .. } => {}
    }
    Ok(())
}

fn contains_non_whitespace(
    value: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, ProtocolError> {
    for (byte_offset, character) in value.char_indices() {
        if byte_offset & (CANCELLATION_POLL_BYTES - 1) == 0 && is_cancelled() {
            return Err(ProtocolError::Cancelled);
        }
        if !character.is_whitespace() {
            return Ok(true);
        }
    }
    if is_cancelled() {
        Err(ProtocolError::Cancelled)
    } else {
        Ok(false)
    }
}

fn validate_frame_shape(
    frame: &[u8],
    header: FrameHeader,
    limits: ProtocolLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ProtocolError> {
    if is_cancelled() {
        return Err(ProtocolError::Cancelled);
    }
    limits.validate()?;
    let frame_bytes =
        usize::try_from(limits.frame_bytes).map_err(|_| ProtocolError::InvalidLimits)?;
    if frame.len() < TEST_FRAME_HEADER_BYTES {
        return Err(ProtocolError::UnexpectedEnd);
    }
    if frame.len() > frame_bytes {
        return Err(ProtocolError::FrameTooLarge {
            limit: limits.frame_bytes,
            actual: frame.len(),
        });
    }
    let observed = parse_header(frame)?;
    if observed != header {
        return Err(ProtocolError::NonCanonical(
            "reported header differs from frame bytes",
        ));
    }
    if header.frame_version != TEST_FRAME_VERSION {
        return Err(ProtocolError::UnsupportedFrameVersion(header.frame_version));
    }
    if header.event_version != TEST_EVENT_VERSION {
        return Err(ProtocolError::UnsupportedEventVersion(header.event_version));
    }
    if header.sequence >= u64::from(limits.events) {
        return Err(ProtocolError::EventLimit {
            limit: limits.events,
            sequence: header.sequence,
        });
    }
    let payload_bytes =
        usize::try_from(header.payload_bytes).map_err(|_| ProtocolError::FrameTooLarge {
            limit: limits.frame_bytes,
            actual: usize::MAX,
        })?;
    let expected_frame_bytes =
        TEST_FRAME_HEADER_BYTES
            .checked_add(payload_bytes)
            .ok_or(ProtocolError::FrameTooLarge {
                limit: limits.frame_bytes,
                actual: usize::MAX,
            })?;
    if expected_frame_bytes > frame.len() {
        return Err(ProtocolError::UnexpectedEnd);
    }
    if expected_frame_bytes < frame.len() {
        return Err(ProtocolError::TrailingBytes);
    }
    if expected_frame_bytes > frame_bytes {
        return Err(ProtocolError::FrameTooLarge {
            limit: limits.frame_bytes,
            actual: expected_frame_bytes,
        });
    }
    let payload = frame
        .get(TEST_FRAME_HEADER_BYTES..expected_frame_bytes)
        .ok_or(ProtocolError::UnexpectedEnd)?;
    if crc32c_cancellable(payload, is_cancelled)? != header.checksum {
        return Err(ProtocolError::InvalidChecksum);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    Cancelled,
    InvalidLimits,
    ProtocolContractMismatch(&'static str),
    LimitTooLarge {
        resource: &'static str,
        maximum: u64,
        actual: u64,
    },
    ResourceLimit {
        resource: &'static str,
        limit: u64,
    },
    InvalidMagic,
    UnsupportedFrameVersion(u32),
    UnsupportedEventVersion(u32),
    UnexpectedEnd,
    InvalidUtf8,
    InvalidSourceRange {
        start: u32,
        end: u32,
    },
    InvalidTag {
        kind: &'static str,
        tag: u64,
    },
    InvalidChecksum,
    FrameTooLarge {
        limit: u32,
        actual: usize,
    },
    StreamTooLarge {
        limit: u64,
        actual: u64,
    },
    StringTooLarge {
        limit: u32,
        actual: usize,
    },
    EventLimit {
        limit: u32,
        sequence: u64,
    },
    SequenceMismatch {
        header: u64,
        event: u64,
    },
    StreamSequenceMismatch {
        expected: u64,
        actual: u64,
    },
    InvalidStreamOrder {
        sequence: u64,
        reason: &'static str,
    },
    DuplicateTestStart {
        sequence: u64,
        test: u32,
    },
    InvalidTestReference {
        sequence: u64,
        test: u32,
        event: &'static str,
    },
    TestCountExceeded {
        sequence: u64,
        limit: u32,
        actual: u32,
    },
    NonMonotonicHeartbeat {
        sequence: u64,
        previous: u64,
        actual: u64,
    },
    StreamSummaryMismatch {
        sequence: u64,
        declared: u32,
        started: u32,
        finished: u32,
        observed_passed: u32,
        observed_failed: u32,
        reported_passed: u32,
        reported_failed: u32,
    },
    TrailingBytes,
    NonCanonical(&'static str),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("test event codec operation was cancelled"),
            Self::InvalidLimits => formatter.write_str(
                "test protocol limits must be nonzero, internally consistent, and fit the frame header",
            ),
            Self::ProtocolContractMismatch(reason) => {
                write!(formatter, "test protocol contract mismatch: {reason}")
            }
            Self::LimitTooLarge {
                resource,
                maximum,
                actual,
            } => write!(
                formatter,
                "test protocol {resource} limit {actual} exceeds hard maximum {maximum}",
            ),
            Self::ResourceLimit { resource, limit } => {
                write!(
                    formatter,
                    "test protocol {resource} exceeds resource limit {limit}"
                )
            }
            Self::InvalidMagic => formatter.write_str("invalid test event frame magic"),
            Self::UnsupportedFrameVersion(version) => {
                write!(formatter, "unsupported test frame version {version}")
            }
            Self::UnsupportedEventVersion(version) => write!(
                formatter,
                "unsupported test event version {version}; expected {TEST_EVENT_VERSION}"
            ),
            Self::UnexpectedEnd => formatter.write_str("unexpected end of test event frame"),
            Self::InvalidUtf8 => formatter.write_str("invalid UTF-8 in test event frame"),
            Self::InvalidSourceRange { start, end } => {
                write!(formatter, "invalid assertion source range {start}..{end}")
            }
            Self::InvalidTag { kind, tag } => write!(formatter, "invalid test {kind} tag {tag}"),
            Self::InvalidChecksum => formatter.write_str("test event checksum mismatch"),
            Self::FrameTooLarge { limit, actual } => write!(
                formatter,
                "test frame contains {actual} bytes, exceeding {limit}"
            ),
            Self::StreamTooLarge { limit, actual } => write!(
                formatter,
                "test event stream contains {actual} bytes, exceeding {limit}"
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
            Self::StreamSequenceMismatch { expected, actual } => write!(
                formatter,
                "test stream expected sequence {expected}, received {actual}"
            ),
            Self::InvalidStreamOrder { sequence, reason } => {
                write!(
                    formatter,
                    "test stream event {sequence} is out of order: {reason}"
                )
            }
            Self::DuplicateTestStart { sequence, test } => write!(
                formatter,
                "test stream event {sequence} starts test {test} more than once",
            ),
            Self::InvalidTestReference {
                sequence,
                test,
                event,
            } => write!(
                formatter,
                "test stream {event} event {sequence} references inactive test {test}",
            ),
            Self::TestCountExceeded {
                sequence,
                limit,
                actual,
            } => write!(
                formatter,
                "test stream event {sequence} test count {actual} exceeds limit {limit}",
            ),
            Self::NonMonotonicHeartbeat {
                sequence,
                previous,
                actual,
            } => write!(
                formatter,
                "test stream heartbeat {sequence} did not advance: {previous} then {actual}",
            ),
            Self::StreamSummaryMismatch {
                sequence,
                declared,
                started,
                finished,
                observed_passed,
                observed_failed,
                reported_passed,
                reported_failed,
            } => write!(
                formatter,
                "test stream terminal event {sequence} disagrees with counts: declared {declared}, started {started}, finished {finished}, observed {observed_passed} passed/{observed_failed} failed, reported {reported_passed} passed/{reported_failed} failed",
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
    use std::cell::Cell;

    fn event(sequence: u64, kind: TestEventKind) -> TestEvent {
        TestEvent {
            protocol: TEST_EVENT_VERSION,
            sequence,
            kind,
        }
    }

    fn encode(event: &TestEvent, limits: ProtocolLimits) -> EncodedEvent {
        seal_encoded_event(&CanonicalTestEventCodec, event, limits, &|| false)
            .expect("canonical event")
    }

    fn encode_stream(events: &[TestEvent], limits: ProtocolLimits) -> Vec<u8> {
        let mut stream = Vec::new();
        for event in events {
            stream.extend_from_slice(encode(event, limits).bytes());
        }
        stream
    }

    fn decode_stream_events(events: &[TestEvent]) -> Result<Vec<TestEvent>, ProtocolError> {
        let limits = ProtocolLimits::standard();
        decode_and_verify_stream(
            &CanonicalTestEventCodec,
            &encode_stream(events, limits),
            limits,
            &|| false,
        )
    }

    fn language_fatal_events(cause: LanguageFatalCause) -> Vec<TestEvent> {
        vec![
            event(0, TestEventKind::RunStarted { test_count: 1 }),
            event(1, TestEventKind::TestStarted { test: TestId(7) }),
            event(
                2,
                TestEventKind::TestFinished {
                    test: TestId(7),
                    outcome: GuestTestOutcome::LanguageFatal { cause },
                },
            ),
            event(
                3,
                TestEventKind::RunFinished {
                    passed: 0,
                    failed: 1,
                },
            ),
        ]
    }

    fn rewrite_checksum(frame: &mut [u8]) {
        let checksum =
            crc32c_cancellable(&frame[TEST_FRAME_HEADER_BYTES..], &|| false).expect("checksum");
        frame[28..32].copy_from_slice(&checksum.to_le_bytes());
    }

    fn hex(bytes: &[u8]) -> String {
        let mut output = String::with_capacity(bytes.len() * 2 + 1);
        for byte in bytes {
            use std::fmt::Write as _;
            write!(&mut output, "{byte:02x}").expect("writing to a String cannot fail");
        }
        output.push('\n');
        output
    }

    fn unhex(value: &str) -> Vec<u8> {
        let value = value.trim_end();
        assert_eq!(value.len() % 2, 0, "hex fixture has complete bytes");
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let pair = std::str::from_utf8(pair).expect("ASCII hex fixture");
                u8::from_str_radix(pair, 16).expect("valid hex fixture")
            })
            .collect()
    }

    #[test]
    fn every_event_variant_round_trips_canonically() {
        let variants = vec![
            TestEventKind::RunStarted { test_count: 2 },
            TestEventKind::TestStarted { test: TestId(1) },
            TestEventKind::Log {
                test: None,
                level: LogLevel::Info,
                message: "booted".to_owned(),
            },
            TestEventKind::Log {
                test: Some(TestId(1)),
                level: LogLevel::Warning,
                message: "slow path".to_owned(),
            },
            TestEventKind::AssertionFailed {
                test: TestId(1),
                failure: AssertionFailure {
                    expression: "actual == expected".to_owned(),
                    message: Some("values differ".to_owned()),
                    source: Some(Span {
                        file: FileId(7),
                        range: TextRange::new(11, 29).expect("range"),
                    }),
                    expected: Some("42".to_owned()),
                    actual: Some("41".to_owned()),
                },
            },
            TestEventKind::TestFinished {
                test: TestId(0),
                outcome: GuestTestOutcome::Passed,
            },
            TestEventKind::TestFinished {
                test: TestId(1),
                outcome: GuestTestOutcome::Failed {
                    message: "assertion failed".to_owned(),
                },
            },
            TestEventKind::TestFinished {
                test: TestId(1),
                outcome: GuestTestOutcome::TimedOut { timeout_ns: 50 },
            },
            TestEventKind::TestFinished {
                test: TestId(1),
                outcome: GuestTestOutcome::LanguageFatal {
                    cause: LanguageFatalCause::CheckedShiftResultLoss,
                },
            },
            TestEventKind::TestFinished {
                test: TestId(1),
                outcome: GuestTestOutcome::LanguageFatal {
                    cause: LanguageFatalCause::InvalidShiftCount,
                },
            },
            TestEventKind::Heartbeat {
                monotonic_ticks: 99,
            },
            TestEventKind::RunFinished {
                passed: 1,
                failed: 1,
            },
        ];
        for (sequence, kind) in variants.into_iter().enumerate() {
            let event = event(sequence as u64, kind);
            let encoded = encode(&event, ProtocolLimits::standard());
            assert_eq!(encoded.header().sequence, sequence as u64);
            assert_eq!(
                decode_and_verify_event(
                    &CanonicalTestEventCodec,
                    encoded.bytes(),
                    ProtocolLimits::standard(),
                    &|| false,
                )
                .expect("verified event"),
                event
            );
        }
    }

    #[test]
    fn language_fatal_event_tags_are_closed_and_exact() {
        assert_eq!(TEST_EVENT_VERSION, 3);
        assert_eq!(TEST_EVENT_VERSION, TEST_PROTOCOL_VERSION);
        for (cause, cause_tag) in [
            (LanguageFatalCause::CheckedShiftResultLoss, 0_u8),
            (LanguageFatalCause::InvalidShiftCount, 1_u8),
        ] {
            let fatal = event(
                0,
                TestEventKind::TestFinished {
                    test: TestId(7),
                    outcome: GuestTestOutcome::LanguageFatal { cause },
                },
            );
            let encoded = encode(&fatal, ProtocolLimits::standard());
            assert_eq!(encoded.header().frame_version, TEST_FRAME_VERSION);
            assert_eq!(encoded.header().event_version, TEST_EVENT_VERSION);
            assert_eq!(encoded.header().payload_bytes, 19);
            assert_eq!(encoded.bytes()[TEST_FRAME_HEADER_BYTES + 12], 4);
            assert_eq!(encoded.bytes()[TEST_FRAME_HEADER_BYTES + 17], 3);
            assert_eq!(encoded.bytes()[TEST_FRAME_HEADER_BYTES + 18], cause_tag);
            assert_eq!(
                decode_and_verify_event(
                    &CanonicalTestEventCodec,
                    encoded.bytes(),
                    ProtocolLimits::standard(),
                    &|| false,
                ),
                Ok(fatal)
            );
        }

        let canonical = encode(
            &event(
                0,
                TestEventKind::TestFinished {
                    test: TestId(7),
                    outcome: GuestTestOutcome::LanguageFatal {
                        cause: LanguageFatalCause::CheckedShiftResultLoss,
                    },
                },
            ),
            ProtocolLimits::standard(),
        )
        .into_bytes();
        for tag in [2_u8, 0xff] {
            let mut invalid_cause = canonical.clone();
            invalid_cause[TEST_FRAME_HEADER_BYTES + 18] = tag;
            rewrite_checksum(&mut invalid_cause);
            assert_eq!(
                decode_and_verify_event(
                    &CanonicalTestEventCodec,
                    &invalid_cause,
                    ProtocolLimits::standard(),
                    &|| false,
                ),
                Err(ProtocolError::InvalidTag {
                    kind: "language fatal cause",
                    tag: u64::from(tag),
                })
            );
        }

        let mut future_outcome = canonical;
        future_outcome[TEST_FRAME_HEADER_BYTES + 17] = 4;
        rewrite_checksum(&mut future_outcome);
        assert_eq!(
            decode_and_verify_event(
                &CanonicalTestEventCodec,
                &future_outcome,
                ProtocolLimits::standard(),
                &|| false,
            ),
            Err(ProtocolError::InvalidTag {
                kind: "guest outcome",
                tag: 4,
            })
        );
    }

    #[test]
    fn canonical_run_started_fixture_is_stable() {
        assert_eq!(TEST_EVENT_VERSION, TEST_PROTOCOL_VERSION);
        let event = event(0, TestEventKind::RunStarted { test_count: 2 });
        let encoded = encode(&event, ProtocolLimits::standard());
        let fixture = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/contracts/protocol/v1/run-started.hex"
        ));
        assert_eq!(hex(encoded.bytes()), fixture);
        assert_eq!(
            decode_and_verify_event(
                &CanonicalTestEventCodec,
                &unhex(fixture),
                ProtocolLimits::standard(),
                &|| false,
            )
            .expect("checked-in frame"),
            event
        );
    }

    #[test]
    fn rejects_magic_checksum_length_and_trailing_corruption() {
        let event = event(0, TestEventKind::RunStarted { test_count: 1 });
        let original = encode(&event, ProtocolLimits::standard()).into_bytes();

        let mut bad_magic = original.clone();
        bad_magic[0] ^= 1;
        assert_eq!(
            decode_and_verify_event(
                &CanonicalTestEventCodec,
                &bad_magic,
                ProtocolLimits::standard(),
                &|| false,
            ),
            Err(ProtocolError::InvalidMagic)
        );

        let mut bad_checksum = original.clone();
        let last = bad_checksum.len() - 1;
        bad_checksum[last] ^= 1;
        assert_eq!(
            decode_and_verify_event(
                &CanonicalTestEventCodec,
                &bad_checksum,
                ProtocolLimits::standard(),
                &|| false,
            ),
            Err(ProtocolError::InvalidChecksum)
        );

        let mut short = original.clone();
        short[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            decode_and_verify_event(
                &CanonicalTestEventCodec,
                &short,
                ProtocolLimits::standard(),
                &|| false,
            ),
            Err(ProtocolError::UnexpectedEnd)
        );

        let mut trailing = original;
        trailing.push(0);
        assert!(matches!(
            decode_and_verify_event(
                &CanonicalTestEventCodec,
                &trailing,
                ProtocolLimits::standard(),
                &|| false,
            ),
            Err(ProtocolError::TrailingBytes)
        ));
    }

    #[test]
    fn every_single_byte_mutation_and_truncated_prefix_is_rejected() {
        let canonical = encode(
            &event(0, TestEventKind::RunStarted { test_count: 2 }),
            ProtocolLimits::standard(),
        )
        .into_bytes();
        for index in 0..canonical.len() {
            let mut mutated = canonical.clone();
            mutated[index] ^= 1;
            assert!(
                decode_and_verify_event(
                    &CanonicalTestEventCodec,
                    &mutated,
                    ProtocolLimits::standard(),
                    &|| false,
                )
                .is_err(),
                "single-byte mutation at {index} was accepted",
            );
        }
        for end in 0..canonical.len() {
            assert!(
                decode_and_verify_event(
                    &CanonicalTestEventCodec,
                    &canonical[..end],
                    ProtocolLimits::standard(),
                    &|| false,
                )
                .is_err(),
                "truncated prefix of {end} bytes was accepted",
            );
        }
    }

    #[test]
    fn rejects_invalid_tags_utf8_versions_and_sequence() {
        let log_event = event(
            1,
            TestEventKind::Log {
                test: None,
                level: LogLevel::Info,
                message: "ok".to_owned(),
            },
        );
        let original = encode(&log_event, ProtocolLimits::standard()).into_bytes();

        let mut invalid_tag = original.clone();
        invalid_tag[TEST_FRAME_HEADER_BYTES + 12] = 0xff;
        rewrite_checksum(&mut invalid_tag);
        assert!(matches!(
            decode_and_verify_event(
                &CanonicalTestEventCodec,
                &invalid_tag,
                ProtocolLimits::standard(),
                &|| false,
            ),
            Err(ProtocolError::InvalidTag {
                kind: "event",
                tag: 255
            })
        ));

        let mut invalid_utf8 = original.clone();
        let message = invalid_utf8.len() - 2;
        invalid_utf8[message] = 0xff;
        rewrite_checksum(&mut invalid_utf8);
        assert_eq!(
            decode_and_verify_event(
                &CanonicalTestEventCodec,
                &invalid_utf8,
                ProtocolLimits::standard(),
                &|| false,
            ),
            Err(ProtocolError::InvalidUtf8)
        );

        let mut wrong_version = original.clone();
        wrong_version[8..12].copy_from_slice(&99u32.to_le_bytes());
        assert_eq!(
            decode_and_verify_event(
                &CanonicalTestEventCodec,
                &wrong_version,
                ProtocolLimits::standard(),
                &|| false,
            ),
            Err(ProtocolError::UnsupportedFrameVersion(99))
        );

        for version in [TEST_EVENT_VERSION - 1, TEST_EVENT_VERSION + 1] {
            let mut wrong_event_version = original.clone();
            wrong_event_version[12..16].copy_from_slice(&version.to_le_bytes());
            assert_eq!(
                decode_and_verify_event(
                    &CanonicalTestEventCodec,
                    &wrong_event_version,
                    ProtocolLimits::standard(),
                    &|| false,
                ),
                Err(ProtocolError::UnsupportedEventVersion(version))
            );

            let mut wrong_payload_version = original.clone();
            wrong_payload_version[TEST_FRAME_HEADER_BYTES..TEST_FRAME_HEADER_BYTES + 4]
                .copy_from_slice(&version.to_le_bytes());
            rewrite_checksum(&mut wrong_payload_version);
            assert_eq!(
                decode_and_verify_event(
                    &CanonicalTestEventCodec,
                    &wrong_payload_version,
                    ProtocolLimits::standard(),
                    &|| false,
                ),
                Err(ProtocolError::UnsupportedEventVersion(version))
            );
        }

        let mut wrong_sequence = original;
        wrong_sequence[16..24].copy_from_slice(&2u64.to_le_bytes());
        assert_eq!(
            decode_and_verify_event(
                &CanonicalTestEventCodec,
                &wrong_sequence,
                ProtocolLimits::standard(),
                &|| false,
            ),
            Err(ProtocolError::SequenceMismatch {
                header: 2,
                event: 1
            })
        );

        let assertion = event(
            0,
            TestEventKind::AssertionFailed {
                test: TestId(1),
                failure: AssertionFailure {
                    expression: "x".to_owned(),
                    message: None,
                    source: Some(Span {
                        file: FileId(7),
                        range: TextRange::new(2, 3).expect("valid range"),
                    }),
                    expected: None,
                    actual: None,
                },
            },
        );
        let mut invalid_range = encode(&assertion, ProtocolLimits::standard()).into_bytes();
        let range_start = TEST_FRAME_HEADER_BYTES + 28;
        let range_end = TEST_FRAME_HEADER_BYTES + 32;
        invalid_range[range_start..range_start + 4].copy_from_slice(&4u32.to_le_bytes());
        invalid_range[range_end..range_end + 4].copy_from_slice(&3u32.to_le_bytes());
        rewrite_checksum(&mut invalid_range);
        assert_eq!(
            decode_and_verify_event(
                &CanonicalTestEventCodec,
                &invalid_range,
                ProtocolLimits::standard(),
                &|| false,
            ),
            Err(ProtocolError::InvalidSourceRange { start: 4, end: 3 })
        );
    }

    #[test]
    fn enforces_exact_frame_string_event_and_cancellation_limits() {
        let log_event = event(
            0,
            TestEventKind::Log {
                test: None,
                level: LogLevel::Info,
                message: "four".to_owned(),
            },
        );
        let encoded = encode(&log_event, ProtocolLimits::standard());
        let exact_frame = u32::try_from(encoded.bytes().len()).expect("small fixture");
        let exact = ProtocolLimits {
            frame_bytes: exact_frame,
            string_bytes: 4,
            events: 1,
        };
        seal_encoded_event(&CanonicalTestEventCodec, &log_event, exact, &|| false)
            .expect("exact limits");

        let short_string = ProtocolLimits {
            string_bytes: 3,
            ..exact
        };
        assert_eq!(
            seal_encoded_event(&CanonicalTestEventCodec, &log_event, short_string, &|| {
                false
            },),
            Err(ProtocolError::StringTooLarge {
                limit: 3,
                actual: 4
            })
        );
        let short_frame = ProtocolLimits {
            frame_bytes: exact_frame - 1,
            string_bytes: 4,
            events: 1,
        };
        assert!(matches!(
            seal_encoded_event(&CanonicalTestEventCodec, &log_event, short_frame, &|| false),
            Err(ProtocolError::FrameTooLarge { .. })
        ));
        let no_sequence = ProtocolLimits { events: 0, ..exact };
        assert_eq!(
            seal_encoded_event(&CanonicalTestEventCodec, &log_event, no_sequence, &|| false),
            Err(ProtocolError::InvalidLimits)
        );
        let partial_run = event(0, TestEventKind::RunStarted { test_count: 100 });
        seal_encoded_event(
            &CanonicalTestEventCodec,
            &partial_run,
            ProtocolLimits {
                events: 1,
                ..ProtocolLimits::standard()
            },
            &|| false,
        )
        .expect("an individually sealed prefix may declare unobserved tests");
        let oversized_frame = ProtocolLimits {
            frame_bytes: u32::try_from(MAX_TEST_EVENT_BYTES).expect("event limit fits u32") + 1,
            string_bytes: 4,
            events: 1,
        };
        assert_eq!(
            seal_encoded_event(
                &CanonicalTestEventCodec,
                &log_event,
                oversized_frame,
                &|| false,
            ),
            Err(ProtocolError::LimitTooLarge {
                resource: "frame bytes",
                maximum: u64::from(MAX_PROTOCOL_FRAME_BYTES),
                actual: u64::from(MAX_PROTOCOL_FRAME_BYTES) + 1,
            })
        );
        assert_eq!(
            ProtocolLimits {
                frame_bytes: MAX_PROTOCOL_FRAME_BYTES,
                string_bytes: MAX_PROTOCOL_STRING_BYTES + 1,
                events: 1,
            }
            .validate(),
            Err(ProtocolError::LimitTooLarge {
                resource: "string bytes",
                maximum: u64::from(MAX_PROTOCOL_STRING_BYTES),
                actual: u64::from(MAX_PROTOCOL_STRING_BYTES) + 1,
            })
        );
        assert_eq!(
            ProtocolLimits {
                events: MAX_PROTOCOL_EVENTS + 1,
                ..ProtocolLimits::standard()
            }
            .validate(),
            Err(ProtocolError::LimitTooLarge {
                resource: "events",
                maximum: u64::from(MAX_PROTOCOL_EVENTS),
                actual: u64::from(MAX_PROTOCOL_EVENTS) + 1,
            })
        );
        let sequence_at_limit = event(
            1,
            TestEventKind::Log {
                test: None,
                level: LogLevel::Info,
                message: "four".to_owned(),
            },
        );
        assert_eq!(
            seal_encoded_event(&CanonicalTestEventCodec, &sequence_at_limit, exact, &|| {
                false
            },),
            Err(ProtocolError::EventLimit {
                limit: 1,
                sequence: 1,
            })
        );
        let maximum_sequence = event(
            u64::from(MAX_PROTOCOL_EVENTS - 1),
            TestEventKind::Heartbeat { monotonic_ticks: 1 },
        );
        let maximum_sequence_frame = encode(&maximum_sequence, ProtocolLimits::standard());
        assert_eq!(
            decode_and_verify_event(
                &CanonicalTestEventCodec,
                maximum_sequence_frame.bytes(),
                ProtocolLimits::standard(),
                &|| false,
            ),
            Ok(maximum_sequence)
        );
        let tiny_stream_limits = ProtocolLimits {
            frame_bytes: u32::try_from(TEST_FRAME_HEADER_BYTES).expect("header fits u32"),
            string_bytes: 1,
            events: 2,
        };
        assert_eq!(
            tiny_stream_limits.maximum_stream_bytes(),
            Ok(u64::try_from(TEST_FRAME_HEADER_BYTES * 2).expect("small limit"))
        );
        assert_eq!(
            ProtocolLimits::standard().maximum_stream_bytes(),
            Ok(MAX_PROTOCOL_STREAM_BYTES)
        );
        assert_eq!(
            decode_and_verify_stream(
                &CanonicalTestEventCodec,
                &[0; TEST_FRAME_HEADER_BYTES * 2 + 1],
                tiny_stream_limits,
                &|| false,
            ),
            Err(ProtocolError::StreamTooLarge {
                limit: u64::try_from(TEST_FRAME_HEADER_BYTES * 2).expect("small limit"),
                actual: u64::try_from(TEST_FRAME_HEADER_BYTES * 2 + 1).expect("small input"),
            })
        );

        let polls = Cell::new(0u32);
        let cancel = || {
            let next = polls.get() + 1;
            polls.set(next);
            next >= 2
        };
        assert_eq!(
            seal_encoded_event(&CanonicalTestEventCodec, &log_event, exact, &cancel),
            Err(ProtocolError::Cancelled)
        );

        let whitespace_assertion = event(
            0,
            TestEventKind::AssertionFailed {
                test: TestId(0),
                failure: AssertionFailure {
                    expression: " ".repeat(16 * 1024),
                    message: None,
                    source: None,
                    expected: None,
                    actual: None,
                },
            },
        );
        let polls = Cell::new(0u32);
        let cancel_during_scan = || {
            let next = polls.get() + 1;
            polls.set(next);
            next >= 4
        };
        assert_eq!(
            seal_encoded_event(
                &CanonicalTestEventCodec,
                &whitespace_assertion,
                ProtocolLimits::standard(),
                &cancel_during_scan,
            ),
            Err(ProtocolError::Cancelled)
        );
        assert!(polls.get() >= 4);
    }

    #[test]
    fn language_fatal_frame_honors_exact_one_under_and_late_cancellation() {
        let fatal = event(
            0,
            TestEventKind::TestFinished {
                test: TestId(7),
                outcome: GuestTestOutcome::LanguageFatal {
                    cause: LanguageFatalCause::CheckedShiftResultLoss,
                },
            },
        );
        let encoded = encode(&fatal, ProtocolLimits::standard());
        let exact_frame = u32::try_from(encoded.bytes().len()).expect("fatal frame fits u32");
        let exact = ProtocolLimits {
            frame_bytes: exact_frame,
            string_bytes: 1,
            events: 1,
        };
        assert_eq!(
            seal_encoded_event(&CanonicalTestEventCodec, &fatal, exact, &|| false)
                .expect("fatal frame at exact limit")
                .bytes(),
            encoded.bytes()
        );
        assert!(matches!(
            seal_encoded_event(
                &CanonicalTestEventCodec,
                &fatal,
                ProtocolLimits {
                    frame_bytes: exact_frame - 1,
                    ..exact
                },
                &|| false,
            ),
            Err(ProtocolError::FrameTooLarge { .. })
        ));

        let terminal = language_fatal_events(LanguageFatalCause::CheckedShiftResultLoss)
            .pop()
            .expect("terminal event");
        seal_encoded_event(
            &CanonicalTestEventCodec,
            &terminal,
            ProtocolLimits {
                events: 4,
                ..ProtocolLimits::standard()
            },
            &|| false,
        )
        .expect("sequence three is valid at an event limit of four");
        assert_eq!(
            seal_encoded_event(
                &CanonicalTestEventCodec,
                &terminal,
                ProtocolLimits {
                    events: 3,
                    ..ProtocolLimits::standard()
                },
                &|| false,
            ),
            Err(ProtocolError::EventLimit {
                limit: 3,
                sequence: 3,
            })
        );

        let calls = Cell::new(0_u32);
        seal_encoded_event(&CanonicalTestEventCodec, &fatal, exact, &|| {
            calls.set(calls.get().saturating_add(1));
            false
        })
        .expect("fatal frame cancellation baseline");
        let baseline = calls.get();
        assert!(baseline > 0);
        calls.set(0);
        assert_eq!(
            seal_encoded_event(&CanonicalTestEventCodec, &fatal, exact, &|| {
                let next = calls.get().saturating_add(1);
                calls.set(next);
                next >= baseline
            }),
            Err(ProtocolError::Cancelled)
        );
        assert_eq!(calls.get(), baseline);
    }

    #[test]
    fn maximum_string_is_valid_and_utf8_copy_is_bounded_and_cancellable() {
        let message = "x"
            .repeat(usize::try_from(MAX_PROTOCOL_STRING_BYTES).expect("string ceiling fits usize"));
        let maximum = event(
            0,
            TestEventKind::Log {
                test: None,
                level: LogLevel::Info,
                message,
            },
        );
        let encoded = encode(&maximum, ProtocolLimits::standard());
        assert_eq!(
            decode_and_verify_event(
                &CanonicalTestEventCodec,
                encoded.bytes(),
                ProtocolLimits::standard(),
                &|| false,
            ),
            Ok(maximum)
        );
        let decode_polls = Cell::new(0u32);
        let cancel_decode = || {
            let next = decode_polls.get() + 1;
            decode_polls.set(next);
            next >= 5
        };
        assert_eq!(
            decode_and_verify_event(
                &CanonicalTestEventCodec,
                encoded.bytes(),
                ProtocolLimits::standard(),
                &cancel_decode,
            ),
            Err(ProtocolError::Cancelled)
        );
        assert!(decode_polls.get() >= 5);

        let crossing = format!(
            "{}é{}",
            "a".repeat(CANCELLATION_POLL_BYTES - 1),
            "b".repeat(32)
        );
        assert_eq!(
            copy_utf8(crossing.as_bytes(), &|| false).expect("valid chunk-boundary UTF-8"),
            crossing
        );
        let polls = Cell::new(0u32);
        let cancel = || {
            let next = polls.get() + 1;
            polls.set(next);
            next >= 2
        };
        assert_eq!(
            copy_utf8(&vec![b'x'; CANCELLATION_POLL_BYTES * 3], &cancel),
            Err(ProtocolError::Cancelled)
        );
        assert!(polls.get() >= 2);
    }

    #[test]
    fn complete_stream_requires_dense_sequences_and_exact_frames() {
        let first = encode(
            &event(0, TestEventKind::RunStarted { test_count: 1 }),
            ProtocolLimits::standard(),
        );
        let second = encode(
            &event(1, TestEventKind::TestStarted { test: TestId(0) }),
            ProtocolLimits::standard(),
        );
        let mut stream = first.bytes().to_vec();
        stream.extend_from_slice(second.bytes());
        assert_eq!(
            decode_and_verify_stream(
                &CanonicalTestEventCodec,
                &stream,
                ProtocolLimits::standard(),
                &|| false,
            )
            .expect("stream"),
            vec![
                event(0, TestEventKind::RunStarted { test_count: 1 }),
                event(1, TestEventKind::TestStarted { test: TestId(0) }),
            ]
        );

        let gap = encode(
            &event(2, TestEventKind::TestStarted { test: TestId(0) }),
            ProtocolLimits::standard(),
        );
        let mut gapped = first.bytes().to_vec();
        gapped.extend_from_slice(gap.bytes());
        assert_eq!(
            decode_and_verify_stream(
                &CanonicalTestEventCodec,
                &gapped,
                ProtocolLimits::standard(),
                &|| false,
            ),
            Err(ProtocolError::StreamSequenceMismatch {
                expected: 1,
                actual: 2
            })
        );

        stream.pop();
        assert_eq!(
            decode_and_verify_stream(
                &CanonicalTestEventCodec,
                &stream,
                ProtocolLimits::standard(),
                &|| false,
            ),
            Err(ProtocolError::UnexpectedEnd)
        );
    }

    #[test]
    fn stream_lifecycle_references_and_terminal_summary_are_exact() {
        let events = vec![
            event(0, TestEventKind::RunStarted { test_count: 2 }),
            event(1, TestEventKind::TestStarted { test: TestId(7) }),
            event(
                2,
                TestEventKind::Log {
                    test: Some(TestId(7)),
                    level: LogLevel::Info,
                    message: "running".to_owned(),
                },
            ),
            event(
                3,
                TestEventKind::Heartbeat {
                    monotonic_ticks: 10,
                },
            ),
            event(
                4,
                TestEventKind::TestFinished {
                    test: TestId(7),
                    outcome: GuestTestOutcome::Passed,
                },
            ),
            event(5, TestEventKind::TestStarted { test: TestId(99) }),
            event(
                6,
                TestEventKind::TestFinished {
                    test: TestId(99),
                    outcome: GuestTestOutcome::Failed {
                        message: "failed".to_owned(),
                    },
                },
            ),
            event(
                7,
                TestEventKind::RunFinished {
                    passed: 1,
                    failed: 1,
                },
            ),
        ];
        assert_eq!(decode_stream_events(&events), Ok(events));
    }

    #[test]
    fn language_fatal_stream_is_exactly_terminal() {
        for cause in [
            LanguageFatalCause::CheckedShiftResultLoss,
            LanguageFatalCause::InvalidShiftCount,
        ] {
            let events = language_fatal_events(cause);
            assert_eq!(decode_stream_events(&events), Ok(events));
        }

        let mut wrong_counts = language_fatal_events(LanguageFatalCause::CheckedShiftResultLoss);
        wrong_counts[3].kind = TestEventKind::RunFinished {
            passed: 1,
            failed: 0,
        };
        assert_eq!(
            decode_stream_events(&wrong_counts),
            Err(ProtocolError::StreamSummaryMismatch {
                sequence: 3,
                declared: 1,
                started: 1,
                finished: 1,
                observed_passed: 0,
                observed_failed: 1,
                reported_passed: 1,
                reported_failed: 0,
            })
        );
    }

    #[test]
    fn language_fatal_stream_rejects_wrong_duplicate_late_and_pass_after_fatal() {
        let fatal = GuestTestOutcome::LanguageFatal {
            cause: LanguageFatalCause::InvalidShiftCount,
        };
        let inactive = vec![
            event(0, TestEventKind::RunStarted { test_count: 1 }),
            event(
                1,
                TestEventKind::TestFinished {
                    test: TestId(7),
                    outcome: fatal.clone(),
                },
            ),
        ];
        assert_eq!(
            decode_stream_events(&inactive),
            Err(ProtocolError::InvalidTestReference {
                sequence: 1,
                test: 7,
                event: "TestFinished",
            })
        );

        let mut wrong_id = language_fatal_events(LanguageFatalCause::InvalidShiftCount);
        let TestEventKind::TestFinished { test, .. } = &mut wrong_id[2].kind else {
            panic!("fatal fixture has TestFinished at sequence two");
        };
        *test = TestId(8);
        assert_eq!(
            decode_stream_events(&wrong_id),
            Err(ProtocolError::InvalidTestReference {
                sequence: 2,
                test: 8,
                event: "TestFinished",
            })
        );

        let mut duplicate = language_fatal_events(LanguageFatalCause::InvalidShiftCount);
        duplicate.insert(
            3,
            event(
                3,
                TestEventKind::TestFinished {
                    test: TestId(7),
                    outcome: fatal.clone(),
                },
            ),
        );
        duplicate[4].sequence = 4;
        assert_eq!(
            decode_stream_events(&duplicate),
            Err(ProtocolError::InvalidStreamOrder {
                sequence: 3,
                reason: "LanguageFatal must be followed immediately by RunFinished",
            })
        );

        let mut heartbeat_after_fatal =
            language_fatal_events(LanguageFatalCause::InvalidShiftCount);
        heartbeat_after_fatal.insert(3, event(3, TestEventKind::Heartbeat { monotonic_ticks: 1 }));
        heartbeat_after_fatal[4].sequence = 4;
        assert_eq!(
            decode_stream_events(&heartbeat_after_fatal),
            Err(ProtocolError::InvalidStreamOrder {
                sequence: 3,
                reason: "LanguageFatal must be followed immediately by RunFinished",
            })
        );

        let pass_after_fatal = vec![
            event(0, TestEventKind::RunStarted { test_count: 2 }),
            event(1, TestEventKind::TestStarted { test: TestId(7) }),
            event(
                2,
                TestEventKind::TestFinished {
                    test: TestId(7),
                    outcome: fatal,
                },
            ),
            event(3, TestEventKind::TestStarted { test: TestId(8) }),
            event(
                4,
                TestEventKind::TestFinished {
                    test: TestId(8),
                    outcome: GuestTestOutcome::Passed,
                },
            ),
            event(
                5,
                TestEventKind::RunFinished {
                    passed: 1,
                    failed: 1,
                },
            ),
        ];
        assert_eq!(
            decode_stream_events(&pass_after_fatal),
            Err(ProtocolError::InvalidStreamOrder {
                sequence: 3,
                reason: "LanguageFatal must be followed immediately by RunFinished",
            })
        );

        let mut after_terminal = language_fatal_events(LanguageFatalCause::InvalidShiftCount);
        after_terminal.push(event(4, TestEventKind::Heartbeat { monotonic_ticks: 1 }));
        assert_eq!(
            decode_stream_events(&after_terminal),
            Err(ProtocolError::InvalidStreamOrder {
                sequence: 4,
                reason: "no event may follow RunFinished",
            })
        );
    }

    #[test]
    fn stream_rejects_order_duplicate_reference_count_and_heartbeat_drift() {
        let missing_start = vec![event(
            0,
            TestEventKind::Log {
                test: None,
                level: LogLevel::Info,
                message: "orphan".to_owned(),
            },
        )];
        assert_eq!(
            decode_stream_events(&missing_start),
            Err(ProtocolError::InvalidStreamOrder {
                sequence: 0,
                reason: "RunStarted must precede every other event",
            })
        );

        let duplicate = vec![
            event(0, TestEventKind::RunStarted { test_count: 2 }),
            event(1, TestEventKind::TestStarted { test: TestId(5) }),
            event(2, TestEventKind::TestStarted { test: TestId(5) }),
        ];
        assert_eq!(
            decode_stream_events(&duplicate),
            Err(ProtocolError::DuplicateTestStart {
                sequence: 2,
                test: 5,
            })
        );

        let dangling = vec![
            event(0, TestEventKind::RunStarted { test_count: 1 }),
            event(
                1,
                TestEventKind::AssertionFailed {
                    test: TestId(42),
                    failure: AssertionFailure {
                        expression: "false".to_owned(),
                        message: None,
                        source: None,
                        expected: None,
                        actual: None,
                    },
                },
            ),
        ];
        assert_eq!(
            decode_stream_events(&dangling),
            Err(ProtocolError::InvalidTestReference {
                sequence: 1,
                test: 42,
                event: "AssertionFailed",
            })
        );

        let too_many = vec![
            event(0, TestEventKind::RunStarted { test_count: 1 }),
            event(1, TestEventKind::TestStarted { test: TestId(1) }),
            event(2, TestEventKind::TestStarted { test: TestId(2) }),
        ];
        assert_eq!(
            decode_stream_events(&too_many),
            Err(ProtocolError::TestCountExceeded {
                sequence: 2,
                limit: 1,
                actual: 2,
            })
        );

        let heartbeat_regression = vec![
            event(0, TestEventKind::RunStarted { test_count: 0 }),
            event(1, TestEventKind::Heartbeat { monotonic_ticks: 7 }),
            event(2, TestEventKind::Heartbeat { monotonic_ticks: 7 }),
        ];
        assert_eq!(
            decode_stream_events(&heartbeat_regression),
            Err(ProtocolError::NonMonotonicHeartbeat {
                sequence: 2,
                previous: 7,
                actual: 7,
            })
        );

        let bad_terminal = vec![
            event(0, TestEventKind::RunStarted { test_count: 1 }),
            event(1, TestEventKind::TestStarted { test: TestId(3) }),
            event(
                2,
                TestEventKind::TestFinished {
                    test: TestId(3),
                    outcome: GuestTestOutcome::Passed,
                },
            ),
            event(
                3,
                TestEventKind::RunFinished {
                    passed: 0,
                    failed: 1,
                },
            ),
        ];
        assert_eq!(
            decode_stream_events(&bad_terminal),
            Err(ProtocolError::StreamSummaryMismatch {
                sequence: 3,
                declared: 1,
                started: 1,
                finished: 1,
                observed_passed: 1,
                observed_failed: 0,
                reported_passed: 0,
                reported_failed: 1,
            })
        );

        let after_terminal = vec![
            event(0, TestEventKind::RunStarted { test_count: 0 }),
            event(
                1,
                TestEventKind::RunFinished {
                    passed: 0,
                    failed: 0,
                },
            ),
            event(2, TestEventKind::Heartbeat { monotonic_ticks: 1 }),
        ];
        assert_eq!(
            decode_stream_events(&after_terminal),
            Err(ProtocolError::InvalidStreamOrder {
                sequence: 2,
                reason: "no event may follow RunFinished",
            })
        );
    }

    #[test]
    fn crc32c_matches_castagnoli_check_vector() {
        assert_eq!(
            crc32c_cancellable(b"123456789", &|| false).expect("checksum"),
            0xe306_9283
        );
    }

    #[test]
    fn dishonest_codec_cannot_bypass_independent_frame_validation() {
        struct DishonestCodec;
        impl TestEventCodec for DishonestCodec {
            fn encode(
                &self,
                event: &TestEvent,
                _limits: ProtocolLimits,
                _is_cancelled: &dyn Fn() -> bool,
            ) -> Result<EncodedEventCandidate, ProtocolError> {
                Ok(EncodedEventCandidate {
                    header: FrameHeader {
                        frame_version: TEST_FRAME_VERSION,
                        event_version: TEST_EVENT_VERSION,
                        sequence: event.sequence,
                        payload_bytes: 1,
                        checksum: 0,
                    },
                    bytes: vec![0],
                })
            }

            fn inspect_header(
                &self,
                _frame: &[u8],
                _is_cancelled: &dyn Fn() -> bool,
            ) -> Result<FrameHeader, ProtocolError> {
                Err(ProtocolError::InvalidMagic)
            }

            fn decode(
                &self,
                _frame: &[u8],
                _limits: ProtocolLimits,
                _is_cancelled: &dyn Fn() -> bool,
            ) -> Result<TestEvent, ProtocolError> {
                Err(ProtocolError::InvalidMagic)
            }
        }

        let event = event(0, TestEventKind::RunStarted { test_count: 0 });
        assert_eq!(
            seal_encoded_event(&DishonestCodec, &event, ProtocolLimits::standard(), &|| {
                false
            },),
            Err(ProtocolError::UnexpectedEnd)
        );
    }

    #[test]
    fn equivalent_but_noncanonical_codec_frame_is_rejected() {
        struct AliasCodec;

        impl TestEventCodec for AliasCodec {
            fn encode(
                &self,
                event: &TestEvent,
                limits: ProtocolLimits,
                is_cancelled: &dyn Fn() -> bool,
            ) -> Result<EncodedEventCandidate, ProtocolError> {
                CanonicalTestEventCodec.encode(event, limits, is_cancelled)
            }

            fn inspect_header(
                &self,
                frame: &[u8],
                is_cancelled: &dyn Fn() -> bool,
            ) -> Result<FrameHeader, ProtocolError> {
                CanonicalTestEventCodec.inspect_header(frame, is_cancelled)
            }

            fn decode(
                &self,
                _frame: &[u8],
                _limits: ProtocolLimits,
                is_cancelled: &dyn Fn() -> bool,
            ) -> Result<TestEvent, ProtocolError> {
                if is_cancelled() {
                    Err(ProtocolError::Cancelled)
                } else {
                    Ok(event(0, TestEventKind::RunStarted { test_count: 1 }))
                }
            }
        }

        let canonical = encode(
            &event(0, TestEventKind::RunStarted { test_count: 1 }),
            ProtocolLimits::standard(),
        );
        let mut alias = canonical.into_bytes();
        alias.push(0);
        let payload_bytes =
            u32::try_from(alias.len() - TEST_FRAME_HEADER_BYTES).expect("alias payload fits u32");
        alias[24..28].copy_from_slice(&payload_bytes.to_le_bytes());
        rewrite_checksum(&mut alias);
        assert_eq!(
            decode_and_verify_event(&AliasCodec, &alias, ProtocolLimits::standard(), &|| false,),
            Err(ProtocolError::NonCanonical(
                "decoded event does not reproduce its complete frame",
            ))
        );
    }
}
