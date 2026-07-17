use std::str;

use wrela_build_model::{BuildIdentity, LanguageRevision, Sha256Digest, TargetIdentity};
use wrela_source::{FileId, Span, TextRange};

use crate::{
    AssertionFailure, FailurePhase, GuestTestOutcome, ImageExecutionEvidence, ImageGroupId,
    ImageGroupResult, LanguageFatalCause, LogLevel, TestCaseResult, TestDescriptor, TestEvent,
    TestEventKind, TestId, TestKind, TestOutcome, TestReport, TestReportCodec,
    TestReportCodecError,
};

/// Stable magic prefix for the revision-1 canonical test-report encoding.
pub const CANONICAL_TEST_REPORT_MAGIC: &[u8; 8] = b"WRELTRP\0";
/// Byte-level version of [`CanonicalTestReportCodec`].
pub const CANONICAL_TEST_REPORT_ENCODING_VERSION: u32 = 2;

const COPY_POLL_BYTES: usize = 16 * 1024;
const MIN_CASE_BYTES: usize = 20;
const MIN_EVENT_BYTES: usize = 17;
const MIN_IMAGE_GROUP_BYTES: usize = 55;

/// Canonical, self-identifying binary codec for complete [`TestReport`] values.
///
/// All integers are fixed-width little-endian. Strings and byte arrays have a
/// `u32` byte length, vectors have a `u32` element count, and enum/option tags
/// are exactly one byte. This leaves no alternate representation for a decoded
/// value. The decoder consumes the entire input and validates all tags, UTF-8,
/// lengths, aggregate payload, and collection counts before allocation.
#[derive(Debug, Default, Clone, Copy)]
pub struct CanonicalTestReportCodec;

impl CanonicalTestReportCodec {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl TestReportCodec for CanonicalTestReportCodec {
    fn encode(
        &self,
        report: &TestReport,
        maximum_bytes: u64,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, TestReportCodecError> {
        check_limit_and_cancellation(maximum_bytes, is_cancelled)?;

        let mut counter = Encoder::counter(maximum_bytes, is_cancelled);
        encode_document(&mut counter, report)?;
        let encoded_length = counter.length;
        let capacity =
            usize::try_from(encoded_length).map_err(|_| TestReportCodecError::OutputTooLarge {
                limit: maximum_bytes,
            })?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| encode_error("unable to allocate canonical report output"))?;

        let mut encoder = Encoder::buffer(bytes, maximum_bytes, is_cancelled);
        encode_document(&mut encoder, report)?;
        let bytes = encoder.finish()?;
        if bytes.len() != capacity {
            return Err(encode_error(
                "canonical report length changed while encoding",
            ));
        }
        Ok(bytes)
    }

    fn decode(
        &self,
        bytes: &[u8],
        maximum_bytes: u64,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<TestReport, TestReportCodecError> {
        check_limit_and_cancellation(maximum_bytes, is_cancelled)?;
        let encoded_length =
            u64::try_from(bytes.len()).map_err(|_| TestReportCodecError::OutputTooLarge {
                limit: maximum_bytes,
            })?;
        if encoded_length > maximum_bytes {
            return Err(TestReportCodecError::OutputTooLarge {
                limit: maximum_bytes,
            });
        }

        let mut reader = Reader::new(bytes, maximum_bytes, is_cancelled);
        let magic = reader.raw(CANONICAL_TEST_REPORT_MAGIC.len())?;
        if magic != CANONICAL_TEST_REPORT_MAGIC {
            return Err(decode_error("invalid canonical test-report magic"));
        }
        let encoding_version = reader.u32()?;
        if encoding_version != CANONICAL_TEST_REPORT_ENCODING_VERSION {
            return Err(decode_error(
                "unsupported canonical test-report encoding version",
            ));
        }
        let report = decode_report(&mut reader)?;
        reader.finish()?;
        Ok(report)
    }
}

fn check_limit_and_cancellation(
    maximum_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), TestReportCodecError> {
    if maximum_bytes == 0 {
        return Err(TestReportCodecError::InvalidLimit);
    }
    poll(is_cancelled)
}

fn poll(is_cancelled: &dyn Fn() -> bool) -> Result<(), TestReportCodecError> {
    if is_cancelled() {
        Err(TestReportCodecError::Cancelled)
    } else {
        Ok(())
    }
}

fn encode_error(message: &'static str) -> TestReportCodecError {
    TestReportCodecError::Encode(message.to_owned())
}

fn decode_error(message: &'static str) -> TestReportCodecError {
    TestReportCodecError::Decode(message.to_owned())
}

struct Encoder<'a> {
    bytes: Option<Vec<u8>>,
    length: u64,
    maximum_bytes: u64,
    is_cancelled: &'a dyn Fn() -> bool,
}

impl<'a> Encoder<'a> {
    fn counter(maximum_bytes: u64, is_cancelled: &'a dyn Fn() -> bool) -> Self {
        Self {
            bytes: None,
            length: 0,
            maximum_bytes,
            is_cancelled,
        }
    }

    fn buffer(bytes: Vec<u8>, maximum_bytes: u64, is_cancelled: &'a dyn Fn() -> bool) -> Self {
        Self {
            bytes: Some(bytes),
            length: 0,
            maximum_bytes,
            is_cancelled,
        }
    }

    fn finish(self) -> Result<Vec<u8>, TestReportCodecError> {
        poll(self.is_cancelled)?;
        self.bytes
            .ok_or_else(|| encode_error("canonical report encoder has no output buffer"))
    }

    fn raw(&mut self, value: &[u8]) -> Result<(), TestReportCodecError> {
        poll(self.is_cancelled)?;
        let value_length =
            u64::try_from(value.len()).map_err(|_| TestReportCodecError::OutputTooLarge {
                limit: self.maximum_bytes,
            })?;
        let next =
            self.length
                .checked_add(value_length)
                .ok_or(TestReportCodecError::OutputTooLarge {
                    limit: self.maximum_bytes,
                })?;
        if next > self.maximum_bytes {
            return Err(TestReportCodecError::OutputTooLarge {
                limit: self.maximum_bytes,
            });
        }
        if let Some(bytes) = &mut self.bytes {
            for chunk in value.chunks(COPY_POLL_BYTES) {
                poll(self.is_cancelled)?;
                bytes.extend_from_slice(chunk);
            }
        }
        self.length = next;
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), TestReportCodecError> {
        self.raw(&value.to_le_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<(), TestReportCodecError> {
        self.raw(&value.to_le_bytes())
    }

    fn i32(&mut self, value: i32) -> Result<(), TestReportCodecError> {
        self.raw(&value.to_le_bytes())
    }

    fn u64(&mut self, value: u64) -> Result<(), TestReportCodecError> {
        self.raw(&value.to_le_bytes())
    }

    fn string(&mut self, value: &str) -> Result<(), TestReportCodecError> {
        let length = u32::try_from(value.len())
            .map_err(|_| encode_error("string length exceeds canonical u32 field"))?;
        self.u32(length)?;
        self.raw(value.as_bytes())
    }

    fn bytes(&mut self, value: &[u8]) -> Result<(), TestReportCodecError> {
        let length = u32::try_from(value.len())
            .map_err(|_| encode_error("byte-array length exceeds canonical u32 field"))?;
        self.u32(length)?;
        self.raw(value)
    }

    fn option<T>(
        &mut self,
        value: Option<&T>,
        encode: impl FnOnce(&mut Self, &T) -> Result<(), TestReportCodecError>,
    ) -> Result<(), TestReportCodecError> {
        match value {
            None => self.u8(0),
            Some(value) => {
                self.u8(1)?;
                encode(self, value)
            }
        }
    }

    fn vector<T>(
        &mut self,
        values: &[T],
        mut encode: impl FnMut(&mut Self, &T) -> Result<(), TestReportCodecError>,
    ) -> Result<(), TestReportCodecError> {
        let count = u32::try_from(values.len())
            .map_err(|_| encode_error("vector count exceeds canonical u32 field"))?;
        self.u32(count)?;
        for value in values {
            poll(self.is_cancelled)?;
            encode(self, value)?;
        }
        Ok(())
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
    maximum_bytes: u64,
    payload_bytes: u64,
    aggregate_items: u64,
    is_cancelled: &'a dyn Fn() -> bool,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], maximum_bytes: u64, is_cancelled: &'a dyn Fn() -> bool) -> Self {
        Self {
            bytes,
            position: 0,
            maximum_bytes,
            payload_bytes: 0,
            aggregate_items: 0,
            is_cancelled,
        }
    }

    fn finish(&self) -> Result<(), TestReportCodecError> {
        poll(self.is_cancelled)?;
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(decode_error("trailing bytes after canonical test report"))
        }
    }

    fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    fn raw(&mut self, length: usize) -> Result<&'a [u8], TestReportCodecError> {
        poll(self.is_cancelled)?;
        let end = self
            .position
            .checked_add(length)
            .ok_or_else(|| decode_error("canonical field length overflow"))?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| decode_error("truncated canonical test report"))?;
        self.position = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8, TestReportCodecError> {
        self.raw(1)?
            .first()
            .copied()
            .ok_or_else(|| decode_error("truncated canonical u8"))
    }

    fn u32(&mut self) -> Result<u32, TestReportCodecError> {
        let bytes: [u8; 4] = self
            .raw(4)?
            .try_into()
            .map_err(|_| decode_error("truncated canonical u32"))?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn i32(&mut self) -> Result<i32, TestReportCodecError> {
        let bytes: [u8; 4] = self
            .raw(4)?
            .try_into()
            .map_err(|_| decode_error("truncated canonical i32"))?;
        Ok(i32::from_le_bytes(bytes))
    }

    fn u64(&mut self) -> Result<u64, TestReportCodecError> {
        let bytes: [u8; 8] = self
            .raw(8)?
            .try_into()
            .map_err(|_| decode_error("truncated canonical u64"))?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn charge_payload(&mut self, length: usize) -> Result<(), TestReportCodecError> {
        let length = u64::try_from(length)
            .map_err(|_| decode_error("aggregate report payload length overflow"))?;
        self.payload_bytes = self
            .payload_bytes
            .checked_add(length)
            .ok_or_else(|| decode_error("aggregate report payload length overflow"))?;
        if self.payload_bytes > self.maximum_bytes {
            return Err(decode_error("aggregate report payload exceeds byte limit"));
        }
        Ok(())
    }

    fn string(&mut self) -> Result<String, TestReportCodecError> {
        let length = usize::try_from(self.u32()?)
            .map_err(|_| decode_error("string length does not fit this host"))?;
        self.charge_payload(length)?;
        if length > self.remaining() {
            return Err(decode_error("string length exceeds remaining report bytes"));
        }
        let source = self.raw(length)?;
        let value = str::from_utf8(source)
            .map_err(|_| decode_error("canonical report string is not UTF-8"))?;
        let mut owned = String::new();
        owned
            .try_reserve_exact(length)
            .map_err(|_| decode_error("unable to allocate canonical report string"))?;
        let mut start = 0;
        while start < value.len() {
            let mut end = start.saturating_add(COPY_POLL_BYTES).min(value.len());
            while end > start && !value.is_char_boundary(end) {
                end -= 1;
            }
            if end == start {
                return Err(decode_error("unable to advance through UTF-8 string"));
            }
            poll(self.is_cancelled)?;
            let chunk = value
                .get(start..end)
                .ok_or_else(|| decode_error("invalid UTF-8 string boundary"))?;
            owned.push_str(chunk);
            start = end;
        }
        Ok(owned)
    }

    fn byte_vector(&mut self) -> Result<Vec<u8>, TestReportCodecError> {
        let length = usize::try_from(self.u32()?)
            .map_err(|_| decode_error("byte-array length does not fit this host"))?;
        self.charge_payload(length)?;
        if length > self.remaining() {
            return Err(decode_error(
                "byte-array length exceeds remaining report bytes",
            ));
        }
        let source = self.raw(length)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| decode_error("unable to allocate canonical report byte array"))?;
        for chunk in source.chunks(COPY_POLL_BYTES) {
            poll(self.is_cancelled)?;
            bytes.extend_from_slice(chunk);
        }
        Ok(bytes)
    }

    fn option<T>(
        &mut self,
        decode: impl FnOnce(&mut Self) -> Result<T, TestReportCodecError>,
    ) -> Result<Option<T>, TestReportCodecError> {
        match self.u8()? {
            0 => Ok(None),
            1 => Ok(Some(decode(self)?)),
            _ => Err(decode_error("invalid canonical option-presence tag")),
        }
    }

    fn vector<T>(
        &mut self,
        minimum_item_bytes: usize,
        mut decode: impl FnMut(&mut Self) -> Result<T, TestReportCodecError>,
    ) -> Result<Vec<T>, TestReportCodecError> {
        let count = usize::try_from(self.u32()?)
            .map_err(|_| decode_error("vector count does not fit this host"))?;
        let minimum_bytes = count
            .checked_mul(minimum_item_bytes)
            .ok_or_else(|| decode_error("vector minimum byte count overflow"))?;
        if minimum_bytes > self.remaining() {
            return Err(decode_error("vector count exceeds remaining report bytes"));
        }
        let count_u64 = u64::try_from(count)
            .map_err(|_| decode_error("aggregate report item count overflow"))?;
        self.aggregate_items = self
            .aggregate_items
            .checked_add(count_u64)
            .ok_or_else(|| decode_error("aggregate report item count overflow"))?;
        if self.aggregate_items > self.maximum_bytes {
            return Err(decode_error(
                "aggregate report item count exceeds byte limit",
            ));
        }
        let mut values = Vec::new();
        values
            .try_reserve_exact(count)
            .map_err(|_| decode_error("unable to allocate canonical report vector"))?;
        for _ in 0..count {
            poll(self.is_cancelled)?;
            values.push(decode(self)?);
        }
        Ok(values)
    }
}

fn encode_document(
    encoder: &mut Encoder<'_>,
    report: &TestReport,
) -> Result<(), TestReportCodecError> {
    encoder.raw(CANONICAL_TEST_REPORT_MAGIC)?;
    encoder.u32(CANONICAL_TEST_REPORT_ENCODING_VERSION)?;
    encode_report(encoder, report)
}

fn encode_report(
    encoder: &mut Encoder<'_>,
    report: &TestReport,
) -> Result<(), TestReportCodecError> {
    encoder.u32(report.schema)?;
    encode_build_identity(encoder, &report.build)?;
    encoder.option(report.started_unix_ns.as_ref(), |encoder, value| {
        encoder.u64(*value)
    })?;
    encoder.option(report.duration_ns.as_ref(), |encoder, value| {
        encoder.u64(*value)
    })?;
    encoder.vector(&report.unit, encode_case_result)?;
    encoder.vector(&report.images, encode_image_group_result)
}

fn decode_report(reader: &mut Reader<'_>) -> Result<TestReport, TestReportCodecError> {
    Ok(TestReport {
        schema: reader.u32()?,
        build: decode_build_identity(reader)?,
        started_unix_ns: reader.option(Reader::u64)?,
        duration_ns: reader.option(Reader::u64)?,
        unit: reader.vector(MIN_CASE_BYTES, decode_case_result)?,
        images: reader.vector(MIN_IMAGE_GROUP_BYTES, decode_image_group_result)?,
    })
}

fn encode_build_identity(
    encoder: &mut Encoder<'_>,
    build: &BuildIdentity,
) -> Result<(), TestReportCodecError> {
    encode_digest(encoder, build.compiler)?;
    encoder.u8(match build.language {
        LanguageRevision::Design0_1 => 0,
    })?;
    encoder.string(build.target.as_str())?;
    encode_digest(encoder, build.target_package)?;
    encode_digest(encoder, build.standard_library)?;
    encode_digest(encoder, build.source_graph)?;
    encode_digest(encoder, build.request)?;
    encode_digest(encoder, build.profile)
}

fn decode_build_identity(reader: &mut Reader<'_>) -> Result<BuildIdentity, TestReportCodecError> {
    let compiler = decode_digest(reader)?;
    let language = match reader.u8()? {
        0 => LanguageRevision::Design0_1,
        _ => return Err(decode_error("invalid language-revision tag")),
    };
    let target = TargetIdentity::new(reader.string()?).map_err(|error| {
        TestReportCodecError::Decode(format!("invalid target identity: {error}"))
    })?;
    Ok(BuildIdentity {
        compiler,
        language,
        target,
        target_package: decode_digest(reader)?,
        standard_library: decode_digest(reader)?,
        source_graph: decode_digest(reader)?,
        request: decode_digest(reader)?,
        profile: decode_digest(reader)?,
    })
}

fn encode_digest(
    encoder: &mut Encoder<'_>,
    digest: Sha256Digest,
) -> Result<(), TestReportCodecError> {
    encoder.raw(digest.as_bytes())
}

fn decode_digest(reader: &mut Reader<'_>) -> Result<Sha256Digest, TestReportCodecError> {
    let bytes: [u8; 32] = reader
        .raw(32)?
        .try_into()
        .map_err(|_| decode_error("truncated SHA-256 digest"))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn encode_descriptor(
    encoder: &mut Encoder<'_>,
    descriptor: &TestDescriptor,
) -> Result<(), TestReportCodecError> {
    encoder.u32(descriptor.id.0)?;
    encoder.string(&descriptor.name)?;
    encoder.u8(test_kind_tag(descriptor.kind))?;
    encoder.option(descriptor.source.as_ref(), encode_span)?;
    encoder.u64(descriptor.timeout_ns)
}

fn decode_descriptor(reader: &mut Reader<'_>) -> Result<TestDescriptor, TestReportCodecError> {
    Ok(TestDescriptor {
        id: TestId(reader.u32()?),
        name: reader.string()?,
        kind: decode_test_kind(reader.u8()?)?,
        source: reader.option(decode_span)?,
        timeout_ns: reader.u64()?,
    })
}

fn test_kind_tag(kind: TestKind) -> u8 {
    match kind {
        TestKind::ComptimeUnit => 0,
        TestKind::IntegrationImage => 1,
        TestKind::DeclaredImage => 2,
    }
}

fn decode_test_kind(tag: u8) -> Result<TestKind, TestReportCodecError> {
    match tag {
        0 => Ok(TestKind::ComptimeUnit),
        1 => Ok(TestKind::IntegrationImage),
        2 => Ok(TestKind::DeclaredImage),
        _ => Err(decode_error("invalid test-kind tag")),
    }
}

fn encode_span(encoder: &mut Encoder<'_>, span: &Span) -> Result<(), TestReportCodecError> {
    encoder.u32(span.file.0)?;
    encoder.u32(span.range.start)?;
    encoder.u32(span.range.end)
}

fn decode_span(reader: &mut Reader<'_>) -> Result<Span, TestReportCodecError> {
    Ok(Span {
        file: FileId(reader.u32()?),
        range: TextRange {
            start: reader.u32()?,
            end: reader.u32()?,
        },
    })
}

fn encode_case_result(
    encoder: &mut Encoder<'_>,
    result: &TestCaseResult,
) -> Result<(), TestReportCodecError> {
    encode_descriptor(encoder, &result.descriptor)?;
    encode_outcome(encoder, &result.outcome)?;
    encoder.option(result.duration_ns.as_ref(), |encoder, value| {
        encoder.u64(*value)
    })
}

fn decode_case_result(reader: &mut Reader<'_>) -> Result<TestCaseResult, TestReportCodecError> {
    Ok(TestCaseResult {
        descriptor: decode_descriptor(reader)?,
        outcome: decode_outcome(reader)?,
        duration_ns: reader.option(Reader::u64)?,
    })
}

fn encode_outcome(
    encoder: &mut Encoder<'_>,
    outcome: &TestOutcome,
) -> Result<(), TestReportCodecError> {
    match outcome {
        TestOutcome::Passed => encoder.u8(0),
        TestOutcome::Failed { phase, message } => {
            encoder.u8(1)?;
            encoder.u8(failure_phase_tag(*phase))?;
            encoder.string(message)
        }
        TestOutcome::TimedOut { phase, timeout_ns } => {
            encoder.u8(2)?;
            encoder.u8(failure_phase_tag(*phase))?;
            encoder.u64(*timeout_ns)
        }
        TestOutcome::Crashed { code, message } => {
            encoder.u8(3)?;
            encoder.option(code.as_ref(), |encoder, value| encoder.i32(*value))?;
            encoder.string(message)
        }
        TestOutcome::LanguageFatal { cause } => {
            encoder.u8(4)?;
            encode_language_fatal_cause(encoder, *cause)
        }
    }
}

fn decode_outcome(reader: &mut Reader<'_>) -> Result<TestOutcome, TestReportCodecError> {
    match reader.u8()? {
        0 => Ok(TestOutcome::Passed),
        1 => Ok(TestOutcome::Failed {
            phase: decode_failure_phase(reader.u8()?)?,
            message: reader.string()?,
        }),
        2 => Ok(TestOutcome::TimedOut {
            phase: decode_failure_phase(reader.u8()?)?,
            timeout_ns: reader.u64()?,
        }),
        3 => Ok(TestOutcome::Crashed {
            code: reader.option(Reader::i32)?,
            message: reader.string()?,
        }),
        4 => Ok(TestOutcome::LanguageFatal {
            cause: decode_language_fatal_cause(reader)?,
        }),
        _ => Err(decode_error("invalid test-outcome tag")),
    }
}

fn failure_phase_tag(phase: FailurePhase) -> u8 {
    match phase {
        FailurePhase::Discovery => 0,
        FailurePhase::Comptime => 1,
        FailurePhase::Compile => 2,
        FailurePhase::Link => 3,
        FailurePhase::Boot => 4,
        FailurePhase::Runtime => 5,
        FailurePhase::Shutdown => 6,
        FailurePhase::Protocol => 7,
    }
}

fn decode_failure_phase(tag: u8) -> Result<FailurePhase, TestReportCodecError> {
    match tag {
        0 => Ok(FailurePhase::Discovery),
        1 => Ok(FailurePhase::Comptime),
        2 => Ok(FailurePhase::Compile),
        3 => Ok(FailurePhase::Link),
        4 => Ok(FailurePhase::Boot),
        5 => Ok(FailurePhase::Runtime),
        6 => Ok(FailurePhase::Shutdown),
        7 => Ok(FailurePhase::Protocol),
        _ => Err(decode_error("invalid failure-phase tag")),
    }
}

fn encode_image_group_result(
    encoder: &mut Encoder<'_>,
    result: &ImageGroupResult,
) -> Result<(), TestReportCodecError> {
    encoder.u32(result.group.0)?;
    encoder.vector(&result.cases, encode_case_result)?;
    encoder.vector(&result.events, encode_event)?;
    encode_evidence(encoder, &result.evidence)?;
    encoder.option(result.infrastructure_failure.as_ref(), encode_outcome)
}

fn decode_image_group_result(
    reader: &mut Reader<'_>,
) -> Result<ImageGroupResult, TestReportCodecError> {
    Ok(ImageGroupResult {
        group: ImageGroupId(reader.u32()?),
        cases: reader.vector(MIN_CASE_BYTES, decode_case_result)?,
        events: reader.vector(MIN_EVENT_BYTES, decode_event)?,
        evidence: decode_evidence(reader)?,
        infrastructure_failure: reader.option(decode_outcome)?,
    })
}

fn encode_evidence(
    encoder: &mut Encoder<'_>,
    evidence: &ImageExecutionEvidence,
) -> Result<(), TestReportCodecError> {
    encode_optional_digest(encoder, evidence.image_digest)?;
    encode_digest(encoder, evidence.target_digest)?;
    encode_optional_digest(encoder, evidence.emulator_digest)?;
    encode_optional_digest(encoder, evidence.scenario_digest)?;
    encode_optional_digest(encoder, evidence.command_digest)?;
    encode_optional_digest(encoder, evidence.event_stream_digest)?;
    encoder.option(evidence.exit_code.as_ref(), |encoder, value| {
        encoder.i32(*value)
    })?;
    encoder.bytes(&evidence.stderr)
}

fn decode_evidence(
    reader: &mut Reader<'_>,
) -> Result<ImageExecutionEvidence, TestReportCodecError> {
    Ok(ImageExecutionEvidence {
        image_digest: decode_optional_digest(reader)?,
        target_digest: decode_digest(reader)?,
        emulator_digest: decode_optional_digest(reader)?,
        scenario_digest: decode_optional_digest(reader)?,
        command_digest: decode_optional_digest(reader)?,
        event_stream_digest: decode_optional_digest(reader)?,
        exit_code: reader.option(Reader::i32)?,
        stderr: reader.byte_vector()?,
    })
}

fn encode_optional_digest(
    encoder: &mut Encoder<'_>,
    digest: Option<Sha256Digest>,
) -> Result<(), TestReportCodecError> {
    encoder.option(digest.as_ref(), |encoder, digest| {
        encode_digest(encoder, *digest)
    })
}

fn decode_optional_digest(
    reader: &mut Reader<'_>,
) -> Result<Option<Sha256Digest>, TestReportCodecError> {
    reader.option(decode_digest)
}

fn encode_event(encoder: &mut Encoder<'_>, event: &TestEvent) -> Result<(), TestReportCodecError> {
    encoder.u32(event.protocol)?;
    encoder.u64(event.sequence)?;
    match &event.kind {
        TestEventKind::RunStarted { test_count } => {
            encoder.u8(0)?;
            encoder.u32(*test_count)
        }
        TestEventKind::TestStarted { test } => {
            encoder.u8(1)?;
            encoder.u32(test.0)
        }
        TestEventKind::Log {
            test,
            level,
            message,
        } => {
            encoder.u8(2)?;
            encoder.option(test.as_ref(), |encoder, test| encoder.u32(test.0))?;
            encoder.u8(log_level_tag(*level))?;
            encoder.string(message)
        }
        TestEventKind::AssertionFailed { test, failure } => {
            encoder.u8(3)?;
            encoder.u32(test.0)?;
            encode_assertion_failure(encoder, failure)
        }
        TestEventKind::TestFinished { test, outcome } => {
            encoder.u8(4)?;
            encoder.u32(test.0)?;
            encode_guest_outcome(encoder, outcome)
        }
        TestEventKind::Heartbeat { monotonic_ticks } => {
            encoder.u8(5)?;
            encoder.u64(*monotonic_ticks)
        }
        TestEventKind::RunFinished { passed, failed } => {
            encoder.u8(6)?;
            encoder.u32(*passed)?;
            encoder.u32(*failed)
        }
    }
}

fn decode_event(reader: &mut Reader<'_>) -> Result<TestEvent, TestReportCodecError> {
    let protocol = reader.u32()?;
    let sequence = reader.u64()?;
    let kind = match reader.u8()? {
        0 => TestEventKind::RunStarted {
            test_count: reader.u32()?,
        },
        1 => TestEventKind::TestStarted {
            test: TestId(reader.u32()?),
        },
        2 => TestEventKind::Log {
            test: reader.option(|reader| Ok(TestId(reader.u32()?)))?,
            level: decode_log_level(reader.u8()?)?,
            message: reader.string()?,
        },
        3 => TestEventKind::AssertionFailed {
            test: TestId(reader.u32()?),
            failure: decode_assertion_failure(reader)?,
        },
        4 => TestEventKind::TestFinished {
            test: TestId(reader.u32()?),
            outcome: decode_guest_outcome(reader)?,
        },
        5 => TestEventKind::Heartbeat {
            monotonic_ticks: reader.u64()?,
        },
        6 => TestEventKind::RunFinished {
            passed: reader.u32()?,
            failed: reader.u32()?,
        },
        _ => return Err(decode_error("invalid test-event-kind tag")),
    };
    Ok(TestEvent {
        protocol,
        sequence,
        kind,
    })
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

fn decode_log_level(tag: u8) -> Result<LogLevel, TestReportCodecError> {
    match tag {
        0 => Ok(LogLevel::Trace),
        1 => Ok(LogLevel::Debug),
        2 => Ok(LogLevel::Info),
        3 => Ok(LogLevel::Warning),
        4 => Ok(LogLevel::Error),
        _ => Err(decode_error("invalid log-level tag")),
    }
}

fn encode_assertion_failure(
    encoder: &mut Encoder<'_>,
    failure: &AssertionFailure,
) -> Result<(), TestReportCodecError> {
    encoder.string(&failure.expression)?;
    encoder.option(failure.message.as_ref(), |encoder, value| {
        encoder.string(value)
    })?;
    encoder.option(failure.source.as_ref(), encode_span)?;
    encoder.option(failure.expected.as_ref(), |encoder, value| {
        encoder.string(value)
    })?;
    encoder.option(failure.actual.as_ref(), |encoder, value| {
        encoder.string(value)
    })
}

fn decode_assertion_failure(
    reader: &mut Reader<'_>,
) -> Result<AssertionFailure, TestReportCodecError> {
    Ok(AssertionFailure {
        expression: reader.string()?,
        message: reader.option(Reader::string)?,
        source: reader.option(decode_span)?,
        expected: reader.option(Reader::string)?,
        actual: reader.option(Reader::string)?,
    })
}

fn encode_guest_outcome(
    encoder: &mut Encoder<'_>,
    outcome: &GuestTestOutcome,
) -> Result<(), TestReportCodecError> {
    match outcome {
        GuestTestOutcome::Passed => encoder.u8(0),
        GuestTestOutcome::Failed { message } => {
            encoder.u8(1)?;
            encoder.string(message)
        }
        GuestTestOutcome::TimedOut { timeout_ns } => {
            encoder.u8(2)?;
            encoder.u64(*timeout_ns)
        }
        GuestTestOutcome::LanguageFatal { cause } => {
            encoder.u8(3)?;
            encode_language_fatal_cause(encoder, *cause)
        }
    }
}

fn decode_guest_outcome(reader: &mut Reader<'_>) -> Result<GuestTestOutcome, TestReportCodecError> {
    match reader.u8()? {
        0 => Ok(GuestTestOutcome::Passed),
        1 => Ok(GuestTestOutcome::Failed {
            message: reader.string()?,
        }),
        2 => Ok(GuestTestOutcome::TimedOut {
            timeout_ns: reader.u64()?,
        }),
        3 => Ok(GuestTestOutcome::LanguageFatal {
            cause: decode_language_fatal_cause(reader)?,
        }),
        _ => Err(decode_error("invalid guest-test-outcome tag")),
    }
}

fn encode_language_fatal_cause(
    encoder: &mut Encoder<'_>,
    cause: LanguageFatalCause,
) -> Result<(), TestReportCodecError> {
    encoder.u8(match cause {
        LanguageFatalCause::CheckedShiftResultLoss => 0,
        LanguageFatalCause::InvalidShiftCount => 1,
    })
}

fn decode_language_fatal_cause(
    reader: &mut Reader<'_>,
) -> Result<LanguageFatalCause, TestReportCodecError> {
    match reader.u8()? {
        0 => Ok(LanguageFatalCause::CheckedShiftResultLoss),
        1 => Ok(LanguageFatalCause::InvalidShiftCount),
        _ => Err(decode_error("invalid language-fatal-cause tag")),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::*;
    use crate::{TEST_PROTOCOL_VERSION, TEST_REPORT_SCHEMA};

    const LIMIT: u64 = 1024 * 1024;

    fn digest(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn build_identity() -> BuildIdentity {
        BuildIdentity {
            compiler: digest(1),
            language: LanguageRevision::Design0_1,
            target: TargetIdentity::aarch64_qemu_virt_uefi(),
            target_package: digest(2),
            standard_library: digest(3),
            source_graph: digest(4),
            request: digest(5),
            profile: digest(6),
        }
    }

    fn descriptor(id: u32, name: &str, kind: TestKind, source: bool) -> TestDescriptor {
        TestDescriptor {
            id: TestId(id),
            name: name.to_owned(),
            kind,
            source: source.then_some(Span {
                file: FileId(id.saturating_add(10)),
                range: TextRange {
                    start: id,
                    end: id.saturating_add(7),
                },
            }),
            timeout_ns: 1000_u64.saturating_add(u64::from(id)),
        }
    }

    fn case(
        id: u32,
        name: &str,
        kind: TestKind,
        outcome: TestOutcome,
        duration_ns: Option<u64>,
    ) -> TestCaseResult {
        TestCaseResult {
            descriptor: descriptor(id, name, kind, id.is_multiple_of(2)),
            outcome,
            duration_ns,
        }
    }

    fn event(sequence: u64, kind: TestEventKind) -> TestEvent {
        TestEvent {
            protocol: TEST_PROTOCOL_VERSION,
            sequence,
            kind,
        }
    }

    fn representative_report() -> TestReport {
        let mut events = vec![
            event(0, TestEventKind::RunStarted { test_count: 4 }),
            event(1, TestEventKind::TestStarted { test: TestId(10) }),
        ];
        for (index, level) in [
            LogLevel::Trace,
            LogLevel::Debug,
            LogLevel::Info,
            LogLevel::Warning,
            LogLevel::Error,
        ]
        .into_iter()
        .enumerate()
        {
            events.push(event(
                u64::try_from(index).expect("small index") + 2,
                TestEventKind::Log {
                    test: (index != 0).then_some(TestId(10)),
                    level,
                    message: format!("level-{index}-λ"),
                },
            ));
        }
        events.extend([
            event(
                7,
                TestEventKind::AssertionFailed {
                    test: TestId(10),
                    failure: AssertionFailure {
                        expression: "actual == expected".to_owned(),
                        message: Some("mismatch 🧪".to_owned()),
                        source: Some(Span {
                            file: FileId(91),
                            range: TextRange { start: 12, end: 34 },
                        }),
                        expected: Some("42".to_owned()),
                        actual: Some("41".to_owned()),
                    },
                },
            ),
            event(
                8,
                TestEventKind::TestFinished {
                    test: TestId(10),
                    outcome: GuestTestOutcome::Passed,
                },
            ),
            event(
                9,
                TestEventKind::TestFinished {
                    test: TestId(11),
                    outcome: GuestTestOutcome::Failed {
                        message: "guest failure".to_owned(),
                    },
                },
            ),
            event(
                10,
                TestEventKind::TestFinished {
                    test: TestId(12),
                    outcome: GuestTestOutcome::TimedOut { timeout_ns: 77 },
                },
            ),
            event(
                11,
                TestEventKind::TestFinished {
                    test: TestId(13),
                    outcome: GuestTestOutcome::LanguageFatal {
                        cause: LanguageFatalCause::CheckedShiftResultLoss,
                    },
                },
            ),
            event(
                12,
                TestEventKind::Heartbeat {
                    monotonic_ticks: u64::MAX - 1,
                },
            ),
            event(
                13,
                TestEventKind::RunFinished {
                    passed: 1,
                    failed: 3,
                },
            ),
        ]);

        TestReport {
            schema: TEST_REPORT_SCHEMA,
            build: build_identity(),
            started_unix_ns: Some(1_725_000_000_123_456_789),
            duration_ns: None,
            unit: vec![
                case(
                    0,
                    "unit-pass",
                    TestKind::ComptimeUnit,
                    TestOutcome::Passed,
                    Some(9),
                ),
                case(
                    1,
                    "image-fail",
                    TestKind::IntegrationImage,
                    TestOutcome::Failed {
                        phase: FailurePhase::Comptime,
                        message: "compile-time failure".to_owned(),
                    },
                    None,
                ),
                case(
                    2,
                    "declared-timeout",
                    TestKind::DeclaredImage,
                    TestOutcome::TimedOut {
                        phase: FailurePhase::Boot,
                        timeout_ns: u64::MAX,
                    },
                    Some(0),
                ),
                case(
                    3,
                    "crashed",
                    TestKind::ComptimeUnit,
                    TestOutcome::Crashed {
                        code: Some(i32::MIN),
                        message: "signal-like failure".to_owned(),
                    },
                    None,
                ),
                case(
                    4,
                    "language-fatal",
                    TestKind::IntegrationImage,
                    TestOutcome::LanguageFatal {
                        cause: LanguageFatalCause::InvalidShiftCount,
                    },
                    Some(1),
                ),
            ],
            images: vec![ImageGroupResult {
                group: ImageGroupId(u32::MAX),
                cases: vec![case(
                    10,
                    "guest-case",
                    TestKind::IntegrationImage,
                    TestOutcome::Passed,
                    Some(u64::MAX),
                )],
                events,
                evidence: ImageExecutionEvidence {
                    image_digest: Some(digest(10)),
                    target_digest: digest(11),
                    emulator_digest: Some(digest(12)),
                    scenario_digest: None,
                    command_digest: Some(digest(14)),
                    event_stream_digest: Some(digest(15)),
                    exit_code: Some(i32::MAX),
                    stderr: vec![0, 0xff, b'\n', 0x80],
                },
                infrastructure_failure: Some(TestOutcome::Crashed {
                    code: None,
                    message: "transport closed".to_owned(),
                }),
            }],
        }
    }

    fn encode(report: &TestReport) -> Vec<u8> {
        CanonicalTestReportCodec::new()
            .encode(report, LIMIT, &|| false)
            .expect("encode report")
    }

    fn assert_round_trip(report: &TestReport) {
        let bytes = encode(report);
        let decoded = CanonicalTestReportCodec
            .decode(&bytes, LIMIT, &|| false)
            .expect("decode report");
        assert_eq!(&decoded, report);
        assert_eq!(encode(&decoded), bytes);
    }

    fn encode_outcome_bytes(outcome: &TestOutcome) -> Vec<u8> {
        let mut encoder = Encoder::buffer(Vec::new(), LIMIT, &|| false);
        encode_outcome(&mut encoder, outcome).expect("encode outcome");
        encoder.finish().expect("outcome bytes")
    }

    fn encode_guest_outcome_bytes(outcome: &GuestTestOutcome) -> Vec<u8> {
        let mut encoder = Encoder::buffer(Vec::new(), LIMIT, &|| false);
        encode_guest_outcome(&mut encoder, outcome).expect("encode guest outcome");
        encoder.finish().expect("guest outcome bytes")
    }

    fn reader_after_build<'a>(bytes: &'a [u8]) -> Reader<'a> {
        let mut reader = Reader::new(bytes, LIMIT, &|| false);
        assert_eq!(
            reader
                .raw(CANONICAL_TEST_REPORT_MAGIC.len())
                .expect("magic"),
            CANONICAL_TEST_REPORT_MAGIC
        );
        assert_eq!(
            reader.u32().expect("encoding version"),
            CANONICAL_TEST_REPORT_ENCODING_VERSION
        );
        let _schema = reader.u32().expect("schema");
        let _build = decode_build_identity(&mut reader).expect("build");
        reader
    }

    #[test]
    fn full_report_round_trips_every_nested_shape_and_is_deterministic() {
        let report = representative_report();
        let first = encode(&report);
        let second = encode(&report);
        assert_eq!(first, second);
        assert_eq!(
            first.get(..CANONICAL_TEST_REPORT_MAGIC.len()),
            Some(CANONICAL_TEST_REPORT_MAGIC.as_slice())
        );
        assert_round_trip(&report);
    }

    #[test]
    fn language_fatal_tags_are_closed_append_only_and_round_trip() {
        assert_eq!(TEST_REPORT_SCHEMA, 2);
        assert_eq!(CANONICAL_TEST_REPORT_ENCODING_VERSION, 2);
        for (cause, tag) in [
            (LanguageFatalCause::CheckedShiftResultLoss, 0_u8),
            (LanguageFatalCause::InvalidShiftCount, 1_u8),
        ] {
            let host = TestOutcome::LanguageFatal { cause };
            assert_eq!(encode_outcome_bytes(&host), [4, tag]);
            assert_eq!(
                decode_outcome(&mut Reader::new(&[4, tag], LIMIT, &|| false)),
                Ok(host)
            );

            let guest = GuestTestOutcome::LanguageFatal { cause };
            assert_eq!(encode_guest_outcome_bytes(&guest), [3, tag]);
            assert_eq!(
                decode_guest_outcome(&mut Reader::new(&[3, tag], LIMIT, &|| false)),
                Ok(guest)
            );
        }

        for bytes in [[4, 2], [4, 0xff]] {
            assert!(decode_outcome(&mut Reader::new(&bytes, LIMIT, &|| false)).is_err());
        }
        for bytes in [[3, 2], [3, 0xff]] {
            assert!(decode_guest_outcome(&mut Reader::new(&bytes, LIMIT, &|| false)).is_err());
        }
        assert!(decode_outcome(&mut Reader::new(&[5], LIMIT, &|| false)).is_err());
        assert!(decode_guest_outcome(&mut Reader::new(&[4], LIMIT, &|| false)).is_err());
    }

    #[test]
    fn every_failure_phase_has_a_stable_round_trip() {
        let phases = [
            FailurePhase::Discovery,
            FailurePhase::Comptime,
            FailurePhase::Compile,
            FailurePhase::Link,
            FailurePhase::Boot,
            FailurePhase::Runtime,
            FailurePhase::Shutdown,
            FailurePhase::Protocol,
        ];
        let mut report = representative_report();
        report.unit = phases
            .into_iter()
            .enumerate()
            .flat_map(|(index, phase)| {
                let id = u32::try_from(index).expect("small index");
                [
                    case(
                        id.saturating_mul(2),
                        "phase-failed",
                        TestKind::ComptimeUnit,
                        TestOutcome::Failed {
                            phase,
                            message: "failed".to_owned(),
                        },
                        None,
                    ),
                    case(
                        id.saturating_mul(2).saturating_add(1),
                        "phase-timeout",
                        TestKind::IntegrationImage,
                        TestOutcome::TimedOut {
                            phase,
                            timeout_ns: 1,
                        },
                        Some(2),
                    ),
                ]
            })
            .collect();
        assert_round_trip(&report);
    }

    #[test]
    fn rejects_magic_version_trailing_and_every_truncation() {
        let report = representative_report();
        let bytes = encode(&report);

        let mut bad_magic = bytes.clone();
        if let Some(first) = bad_magic.first_mut() {
            *first ^= 0xff;
        }
        assert!(
            CanonicalTestReportCodec
                .decode(&bad_magic, LIMIT, &|| false)
                .is_err()
        );

        let mut stale_version = bytes.clone();
        let version_offset = CANONICAL_TEST_REPORT_MAGIC.len();
        let version_end = version_offset + 4;
        stale_version[version_offset..version_end].copy_from_slice(&1_u32.to_le_bytes());
        assert!(
            CanonicalTestReportCodec
                .decode(&stale_version, LIMIT, &|| false)
                .is_err()
        );

        let mut future_version = bytes.clone();
        future_version[version_offset..version_end].copy_from_slice(&3_u32.to_le_bytes());
        assert!(
            CanonicalTestReportCodec
                .decode(&future_version, LIMIT, &|| false)
                .is_err()
        );

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(
            CanonicalTestReportCodec
                .decode(&trailing, LIMIT, &|| false)
                .is_err()
        );

        for end in 0..bytes.len() {
            assert!(
                CanonicalTestReportCodec
                    .decode(&bytes[..end], LIMIT, &|| false)
                    .is_err(),
                "accepted truncation at {end}"
            );
        }
    }

    #[test]
    fn rejects_invalid_utf8_enum_and_presence_tags() {
        let bytes = encode(&representative_report());

        let mut invalid_utf8 = bytes.clone();
        let needle = b"unit-pass";
        let offset = invalid_utf8
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("fixture string");
        invalid_utf8[offset] = 0xff;
        assert!(
            CanonicalTestReportCodec
                .decode(&invalid_utf8, LIMIT, &|| false)
                .is_err()
        );

        let mut invalid_enum = bytes.clone();
        let language_offset = CANONICAL_TEST_REPORT_MAGIC.len() + 4 + 4 + 32;
        invalid_enum[language_offset] = 0xff;
        assert!(
            CanonicalTestReportCodec
                .decode(&invalid_enum, LIMIT, &|| false)
                .is_err()
        );

        let mut invalid_presence = bytes.clone();
        let started_offset = reader_after_build(&invalid_presence).position;
        invalid_presence[started_offset] = 2;
        assert!(
            CanonicalTestReportCodec
                .decode(&invalid_presence, LIMIT, &|| false)
                .is_err()
        );
    }

    #[test]
    fn rejects_invalid_tags_in_each_nested_enum_family() {
        assert!(decode_test_kind(3).is_err());
        assert!(decode_failure_phase(8).is_err());
        assert!(decode_log_level(5).is_err());

        let invalid_outcome = [0xff];
        assert!(decode_outcome(&mut Reader::new(&invalid_outcome, LIMIT, &|| false)).is_err());
        let invalid_guest_outcome = [0xff];
        assert!(
            decode_guest_outcome(&mut Reader::new(&invalid_guest_outcome, LIMIT, &|| false))
                .is_err()
        );

        let mut invalid_event = Vec::new();
        invalid_event.extend_from_slice(&TEST_PROTOCOL_VERSION.to_le_bytes());
        invalid_event.extend_from_slice(&0_u64.to_le_bytes());
        invalid_event.push(0xff);
        assert!(decode_event(&mut Reader::new(&invalid_event, LIMIT, &|| false)).is_err());
    }

    #[test]
    fn rejects_count_and_length_bombs_before_allocation() {
        let bytes = encode(&representative_report());

        let mut count_bomb = bytes.clone();
        let mut reader = reader_after_build(&count_bomb);
        let _started = reader.option(Reader::u64).expect("started");
        let _duration = reader.option(Reader::u64).expect("duration");
        let count_offset = reader.position;
        count_bomb[count_offset..count_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(
            CanonicalTestReportCodec
                .decode(&count_bomb, LIMIT, &|| false)
                .is_err()
        );

        let mut length_bomb = bytes.clone();
        let target_length_offset = CANONICAL_TEST_REPORT_MAGIC.len() + 4 + 4 + 32 + 1;
        length_bomb[target_length_offset..target_length_offset + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(
            CanonicalTestReportCodec
                .decode(&length_bomb, LIMIT, &|| false)
                .is_err()
        );
    }

    #[test]
    fn applies_exact_byte_limits_before_output_or_decode_allocation() {
        let report = representative_report();
        let bytes = encode(&report);
        let exact = u64::try_from(bytes.len()).expect("fixture length");
        assert_eq!(
            CanonicalTestReportCodec
                .encode(&report, exact, &|| false)
                .expect("exact encode"),
            bytes
        );
        assert_eq!(
            CanonicalTestReportCodec
                .decode(&bytes, exact, &|| false)
                .expect("exact decode"),
            report
        );
        assert!(matches!(
            CanonicalTestReportCodec.encode(&report, exact - 1, &|| false),
            Err(TestReportCodecError::OutputTooLarge { .. })
        ));
        assert!(matches!(
            CanonicalTestReportCodec.decode(&bytes, exact - 1, &|| false),
            Err(TestReportCodecError::OutputTooLarge { .. })
        ));
        assert_eq!(
            CanonicalTestReportCodec.encode(&report, 0, &|| false),
            Err(TestReportCodecError::InvalidLimit)
        );
        assert_eq!(
            CanonicalTestReportCodec.decode(&bytes, 0, &|| false),
            Err(TestReportCodecError::InvalidLimit)
        );
    }

    #[test]
    fn polls_cancellation_during_both_passes_and_nested_decode() {
        let report = representative_report();
        assert_eq!(
            CanonicalTestReportCodec.encode(&report, LIMIT, &|| true),
            Err(TestReportCodecError::Cancelled)
        );
        let bytes = encode(&report);
        assert_eq!(
            CanonicalTestReportCodec.decode(&bytes, LIMIT, &|| true),
            Err(TestReportCodecError::Cancelled)
        );

        let encode_polls = Cell::new(0_u32);
        let cancel_encode = || {
            let next = encode_polls.get().saturating_add(1);
            encode_polls.set(next);
            next > 30
        };
        assert_eq!(
            CanonicalTestReportCodec.encode(&report, LIMIT, &cancel_encode),
            Err(TestReportCodecError::Cancelled)
        );

        let decode_polls = Cell::new(0_u32);
        let cancel_decode = || {
            let next = decode_polls.get().saturating_add(1);
            decode_polls.set(next);
            next > 30
        };
        assert_eq!(
            CanonicalTestReportCodec.decode(&bytes, LIMIT, &cancel_decode),
            Err(TestReportCodecError::Cancelled)
        );
    }
}
