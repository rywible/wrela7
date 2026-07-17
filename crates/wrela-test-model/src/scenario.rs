//! Canonical revision-1 codec for manifest-declared image scenarios.
//!
//! The external form is the closed TOML subset documented by the language
//! guide. Canonical documents use UTF-8, LF line endings, one space around
//! `=`, fields in schema order, lowercase hexadecimal byte strings, canonical
//! decimal integers, no comments, and exactly one final newline. Optional
//! fields are omitted when absent. String values use TOML basic-string escapes
//! with uppercase Unicode escape digits. The decoder accepts no alternate
//! representation: after structural decoding it independently re-encodes the
//! value and requires byte-for-byte equality with the declared file.

use std::str;

use crate::{
    ExpectedScenarioEvent, IMAGE_SCENARIO_SCHEMA, ImageScenario, ImageScenarioCodec,
    ImageScenarioStep, ScenarioDecodeRequest, ScenarioId, TestId, TestModelError,
};

const COPY_POLL_BYTES: usize = 16 * 1024;
const SCENARIO_BYTES_RESOURCE: &str = "image scenario bytes";
const SCENARIO_STEPS_RESOURCE: &str = "image scenario steps";
const STEP_BYTES_RESOURCE: &str = "image scenario step payload bytes";

/// Canonical codec for schema-one manifest image-scenario TOML files.
#[derive(Debug, Default, Clone, Copy)]
pub struct CanonicalImageScenarioCodec;

impl CanonicalImageScenarioCodec {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl ImageScenarioCodec for CanonicalImageScenarioCodec {
    fn decode(
        &self,
        request: ScenarioDecodeRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ImageScenario, TestModelError> {
        validate_limits(
            request.maximum_bytes,
            request.maximum_steps,
            request.maximum_step_bytes,
            is_cancelled,
        )?;
        enforce_length(
            request.bytes.len(),
            request.maximum_bytes,
            SCENARIO_BYTES_RESOURCE,
        )?;
        for _ in request.bytes.chunks(COPY_POLL_BYTES) {
            poll(is_cancelled)?;
        }
        let text = str::from_utf8(request.bytes).map_err(|_| invalid_scenario(request.id))?;
        let scenario = decode_document(text, &request, is_cancelled)?;
        scenario.validate_shape()?;

        let canonical = encode_scenario(
            &scenario,
            request.maximum_bytes,
            request.maximum_steps,
            request.maximum_step_bytes,
            is_cancelled,
        )?;
        if canonical != request.bytes {
            return Err(TestModelError::NonCanonicalScenario(request.id));
        }
        Ok(scenario)
    }

    fn encode_canonical(
        &self,
        scenario: &ImageScenario,
        maximum_bytes: u64,
        maximum_steps: u32,
        maximum_step_bytes: u64,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, TestModelError> {
        validate_limits(
            maximum_bytes,
            maximum_steps,
            maximum_step_bytes,
            is_cancelled,
        )?;
        encode_scenario(
            scenario,
            maximum_bytes,
            maximum_steps,
            maximum_step_bytes,
            is_cancelled,
        )
    }
}

fn validate_limits(
    maximum_bytes: u64,
    maximum_steps: u32,
    maximum_step_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), TestModelError> {
    poll(is_cancelled)?;
    if maximum_bytes == 0 || maximum_steps == 0 || maximum_step_bytes == 0 {
        return Err(TestModelError::InvalidLimits);
    }
    Ok(())
}

fn poll(is_cancelled: &dyn Fn() -> bool) -> Result<(), TestModelError> {
    if is_cancelled() {
        Err(TestModelError::Cancelled)
    } else {
        Ok(())
    }
}

fn invalid_scenario(id: ScenarioId) -> TestModelError {
    TestModelError::InvalidScenario(id)
}

fn resource_limit(resource: &'static str, limit: u64) -> TestModelError {
    TestModelError::ResourceLimit { resource, limit }
}

fn enforce_length(
    length: usize,
    limit: u64,
    resource: &'static str,
) -> Result<u64, TestModelError> {
    let length = u64::try_from(length).map_err(|_| resource_limit(resource, limit))?;
    if length > limit {
        Err(resource_limit(resource, limit))
    } else {
        Ok(length)
    }
}

fn decode_document(
    text: &str,
    request: &ScenarioDecodeRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ImageScenario, TestModelError> {
    let id = request.id;
    if text.is_empty() || !text.ends_with('\n') || text.as_bytes().contains(&b'\r') {
        return Err(invalid_scenario(id));
    }
    poll(is_cancelled)?;

    let (line_count, step_count) = count_lines_and_steps(text, id, is_cancelled)?;
    enforce_length(
        step_count,
        u64::from(request.maximum_steps),
        SCENARIO_STEPS_RESOURCE,
    )?;
    if step_count == 0 {
        return Err(invalid_scenario(id));
    }
    let maximum_structural_lines = step_count
        .checked_mul(7)
        .and_then(|count| count.checked_add(2))
        .ok_or_else(|| invalid_scenario(id))?;
    if line_count < 6 || line_count > maximum_structural_lines {
        return Err(invalid_scenario(id));
    }
    let mut lines = Vec::new();
    lines
        .try_reserve_exact(line_count)
        .map_err(|_| resource_limit(SCENARIO_STEPS_RESOURCE, u64::from(request.maximum_steps)))?;
    for (index, value) in text.split_terminator('\n').enumerate() {
        if index % 1024 == 0 {
            poll(is_cancelled)?;
        }
        lines.push(value);
    }
    if lines.first().copied() != Some("schema = 1") {
        return Err(invalid_scenario(id));
    }

    let name_line = lines.get(1).copied().ok_or_else(|| invalid_scenario(id))?;
    let name_encoded = exact_value(name_line, "name", id)?;
    let name = decode_basic_string(
        name_encoded,
        request.maximum_bytes,
        SCENARIO_BYTES_RESOURCE,
        id,
        is_cancelled,
    )?;
    if name != request.name {
        return Err(TestModelError::ScenarioIdentityMismatch(id));
    }
    if lines.get(2).copied() != Some("") {
        return Err(invalid_scenario(id));
    }

    let mut steps = Vec::new();
    steps
        .try_reserve_exact(step_count)
        .map_err(|_| resource_limit(SCENARIO_STEPS_RESOURCE, u64::from(request.maximum_steps)))?;
    let mut line = 3usize;
    while line < lines.len() {
        poll(is_cancelled)?;
        if lines.get(line).copied() != Some("[[step]]") {
            return Err(invalid_scenario(id));
        }
        line = line.checked_add(1).ok_or_else(|| invalid_scenario(id))?;
        let kind_line = lines
            .get(line)
            .copied()
            .ok_or_else(|| invalid_scenario(id))?;
        let kind = decode_literal(exact_value(kind_line, "kind", id)?, id, is_cancelled)?;
        line = line.checked_add(1).ok_or_else(|| invalid_scenario(id))?;

        let step = match kind.as_str() {
            "send-serial" => {
                let bytes = decode_hex_field(
                    &lines,
                    &mut line,
                    "bytes_hex",
                    request.maximum_step_bytes,
                    id,
                    is_cancelled,
                )?;
                ImageScenarioStep::SendSerial { bytes }
            }
            "expect-serial" => {
                let bytes = decode_hex_field(
                    &lines,
                    &mut line,
                    "bytes_hex",
                    request.maximum_step_bytes,
                    id,
                    is_cancelled,
                )?;
                let timeout_ns = decode_u64_field(&lines, &mut line, "timeout_ns", id)?;
                ImageScenarioStep::ExpectSerial { bytes, timeout_ns }
            }
            "expect-test-event" => decode_event_step(
                &lines,
                &mut line,
                request.maximum_step_bytes,
                id,
                is_cancelled,
            )?,
            "expect-exit" => {
                let code = if has_key(&lines, line, "code") {
                    Some(decode_i32_field(&lines, &mut line, "code", id)?)
                } else {
                    None
                };
                let timeout_ns = decode_u64_field(&lines, &mut line, "timeout_ns", id)?;
                ImageScenarioStep::ExpectExit { code, timeout_ns }
            }
            "request-shutdown" => {
                let timeout_ns = decode_u64_field(&lines, &mut line, "timeout_ns", id)?;
                ImageScenarioStep::RequestShutdown { timeout_ns }
            }
            _ => return Err(invalid_scenario(id)),
        };
        steps.push(step);

        if line < lines.len() {
            if lines.get(line).copied() != Some("") {
                return Err(invalid_scenario(id));
            }
            line = line.checked_add(1).ok_or_else(|| invalid_scenario(id))?;
            if line == lines.len() {
                return Err(invalid_scenario(id));
            }
        }
    }
    if steps.len() != step_count {
        return Err(invalid_scenario(id));
    }

    let source_path = copy_string(request.source_path, request.maximum_bytes, id, is_cancelled)?;
    Ok(ImageScenario {
        id,
        schema: IMAGE_SCENARIO_SCHEMA,
        name,
        source_path,
        digest: request.verified_digest,
        steps,
    })
}

fn count_lines_and_steps(
    text: &str,
    id: ScenarioId,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(usize, usize), TestModelError> {
    let mut line_count = 0usize;
    let mut step_count = 0usize;
    let mut bytes_since_poll = 0usize;
    for line in text.split_terminator('\n') {
        bytes_since_poll = bytes_since_poll
            .checked_add(line.len())
            .and_then(|length| length.checked_add(1))
            .ok_or_else(|| invalid_scenario(id))?;
        if bytes_since_poll >= COPY_POLL_BYTES {
            poll(is_cancelled)?;
            bytes_since_poll = 0;
        }
        line_count = line_count
            .checked_add(1)
            .ok_or_else(|| invalid_scenario(id))?;
        if line == "[[step]]" {
            step_count = step_count
                .checked_add(1)
                .ok_or_else(|| invalid_scenario(id))?;
        }
    }
    poll(is_cancelled)?;
    Ok((line_count, step_count))
}

fn decode_event_step(
    lines: &[&str],
    line: &mut usize,
    maximum_step_bytes: u64,
    id: ScenarioId,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ImageScenarioStep, TestModelError> {
    let event_line = lines
        .get(*line)
        .copied()
        .ok_or_else(|| invalid_scenario(id))?;
    let event = decode_literal(exact_value(event_line, "event", id)?, id, is_cancelled)?;
    let kind = match event.as_str() {
        "run-started" => ExpectedScenarioEvent::RunStarted,
        "test-started" => ExpectedScenarioEvent::TestStarted,
        "log" => ExpectedScenarioEvent::Log,
        "assertion-failed" => ExpectedScenarioEvent::AssertionFailed,
        "test-finished" => ExpectedScenarioEvent::TestFinished,
        "heartbeat" => ExpectedScenarioEvent::Heartbeat,
        "run-finished" => ExpectedScenarioEvent::RunFinished,
        _ => return Err(invalid_scenario(id)),
    };
    *line = line.checked_add(1).ok_or_else(|| invalid_scenario(id))?;

    let test = if has_key(lines, *line, "test") {
        Some(TestId(decode_u32_field(lines, line, "test", id)?))
    } else {
        None
    };
    let message_contains = if has_key(lines, *line, "message_contains") {
        let encoded = exact_value(
            lines
                .get(*line)
                .copied()
                .ok_or_else(|| invalid_scenario(id))?,
            "message_contains",
            id,
        )?;
        let value = decode_basic_string(
            encoded,
            maximum_step_bytes,
            STEP_BYTES_RESOURCE,
            id,
            is_cancelled,
        )?;
        *line = line.checked_add(1).ok_or_else(|| invalid_scenario(id))?;
        Some(value)
    } else {
        None
    };
    let timeout_ns = decode_u64_field(lines, line, "timeout_ns", id)?;
    Ok(ImageScenarioStep::ExpectTestEvent {
        kind,
        test,
        message_contains,
        timeout_ns,
    })
}

fn exact_value<'a>(line: &'a str, key: &str, id: ScenarioId) -> Result<&'a str, TestModelError> {
    let prefix_length = key
        .len()
        .checked_add(3)
        .ok_or_else(|| invalid_scenario(id))?;
    if line.len() < prefix_length
        || line.get(..key.len()) != Some(key)
        || line.get(key.len()..prefix_length) != Some(" = ")
    {
        return Err(invalid_scenario(id));
    }
    line.get(prefix_length..)
        .ok_or_else(|| invalid_scenario(id))
}

fn has_key(lines: &[&str], line: usize, key: &str) -> bool {
    let Some(value) = lines.get(line) else {
        return false;
    };
    let Some(prefix_length) = key.len().checked_add(3) else {
        return false;
    };
    value.len() >= prefix_length
        && value.get(..key.len()) == Some(key)
        && value.get(key.len()..prefix_length) == Some(" = ")
}

fn decode_u64_field(
    lines: &[&str],
    line: &mut usize,
    key: &str,
    id: ScenarioId,
) -> Result<u64, TestModelError> {
    let source = exact_value(
        lines
            .get(*line)
            .copied()
            .ok_or_else(|| invalid_scenario(id))?,
        key,
        id,
    )?;
    let value = parse_canonical_u64(source, id)?;
    *line = line.checked_add(1).ok_or_else(|| invalid_scenario(id))?;
    Ok(value)
}

fn decode_u32_field(
    lines: &[&str],
    line: &mut usize,
    key: &str,
    id: ScenarioId,
) -> Result<u32, TestModelError> {
    let value = decode_u64_field(lines, line, key, id)?;
    u32::try_from(value).map_err(|_| invalid_scenario(id))
}

fn decode_i32_field(
    lines: &[&str],
    line: &mut usize,
    key: &str,
    id: ScenarioId,
) -> Result<i32, TestModelError> {
    let source = exact_value(
        lines
            .get(*line)
            .copied()
            .ok_or_else(|| invalid_scenario(id))?,
        key,
        id,
    )?;
    if source.len() > 11 {
        return Err(invalid_scenario(id));
    }
    if source.is_empty()
        || source.starts_with('+')
        || source == "-0"
        || source.starts_with("00")
        || (source.starts_with('-') && source.get(1..2) == Some("0"))
        || !source
            .strip_prefix('-')
            .unwrap_or(source)
            .bytes()
            .all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid_scenario(id));
    }
    let value = source.parse::<i32>().map_err(|_| invalid_scenario(id))?;
    *line = line.checked_add(1).ok_or_else(|| invalid_scenario(id))?;
    Ok(value)
}

fn parse_canonical_u64(source: &str, id: ScenarioId) -> Result<u64, TestModelError> {
    if source.len() > 20
        || source.is_empty()
        || source.starts_with('+')
        || (source.len() > 1 && source.starts_with('0'))
        || !source.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(invalid_scenario(id));
    }
    source.parse::<u64>().map_err(|_| invalid_scenario(id))
}

fn decode_hex_field(
    lines: &[&str],
    line: &mut usize,
    key: &str,
    maximum_step_bytes: u64,
    id: ScenarioId,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>, TestModelError> {
    let encoded = exact_value(
        lines
            .get(*line)
            .copied()
            .ok_or_else(|| invalid_scenario(id))?,
        key,
        id,
    )?;
    let maximum_hex_bytes = maximum_step_bytes.saturating_mul(2);
    let hex = decode_basic_string(
        encoded,
        maximum_hex_bytes,
        STEP_BYTES_RESOURCE,
        id,
        is_cancelled,
    )
    .map_err(|error| match error {
        TestModelError::ResourceLimit {
            resource: STEP_BYTES_RESOURCE,
            ..
        } => resource_limit(STEP_BYTES_RESOURCE, maximum_step_bytes),
        other => other,
    })?;
    if hex.is_empty() || hex.len() % 2 != 0 {
        return Err(invalid_scenario(id));
    }
    let decoded_length = hex.len() / 2;
    enforce_length(decoded_length, maximum_step_bytes, STEP_BYTES_RESOURCE)?;
    for chunk in hex.as_bytes().chunks(COPY_POLL_BYTES) {
        poll(is_cancelled)?;
        if !chunk.iter().all(u8::is_ascii_hexdigit) {
            return Err(invalid_scenario(id));
        }
    }

    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(decoded_length)
        .map_err(|_| resource_limit(STEP_BYTES_RESOURCE, maximum_step_bytes))?;
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        if index % COPY_POLL_BYTES == 0 {
            poll(is_cancelled)?;
        }
        let high = hex_digit(pair[0]).ok_or_else(|| invalid_scenario(id))?;
        let low = hex_digit(pair[1]).ok_or_else(|| invalid_scenario(id))?;
        bytes.push((high << 4) | low);
    }
    *line = line.checked_add(1).ok_or_else(|| invalid_scenario(id))?;
    Ok(bytes)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_literal(
    source: &str,
    id: ScenarioId,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<String, TestModelError> {
    decode_basic_string(
        source,
        u64::try_from(source.len()).unwrap_or(u64::MAX),
        SCENARIO_BYTES_RESOURCE,
        id,
        is_cancelled,
    )
}

fn copy_string(
    source: &str,
    maximum_bytes: u64,
    id: ScenarioId,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<String, TestModelError> {
    let mut output = String::new();
    output
        .try_reserve_exact(source.len())
        .map_err(|_| resource_limit(SCENARIO_BYTES_RESOURCE, maximum_bytes))?;
    let mut start = 0usize;
    while start < source.len() {
        poll(is_cancelled)?;
        let mut end = start.saturating_add(COPY_POLL_BYTES).min(source.len());
        while end > start && !source.is_char_boundary(end) {
            end -= 1;
        }
        if end == start {
            return Err(invalid_scenario(id));
        }
        output.push_str(source.get(start..end).ok_or_else(|| invalid_scenario(id))?);
        start = end;
    }
    poll(is_cancelled)?;
    Ok(output)
}

fn decode_basic_string(
    source: &str,
    maximum_decoded_bytes: u64,
    resource: &'static str,
    id: ScenarioId,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<String, TestModelError> {
    let inner = source
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| invalid_scenario(id))?;
    let decoded_length = walk_basic_string(inner, id, is_cancelled, |_| Ok(()))?;
    enforce_length(decoded_length, maximum_decoded_bytes, resource)?;
    let mut decoded = String::new();
    decoded
        .try_reserve_exact(decoded_length)
        .map_err(|_| resource_limit(resource, maximum_decoded_bytes))?;
    let second_length = walk_basic_string(inner, id, is_cancelled, |character| {
        decoded.push(character);
        Ok(())
    })?;
    if second_length != decoded_length {
        return Err(invalid_scenario(id));
    }
    Ok(decoded)
}

fn walk_basic_string(
    inner: &str,
    id: ScenarioId,
    is_cancelled: &dyn Fn() -> bool,
    mut emit: impl FnMut(char) -> Result<(), TestModelError>,
) -> Result<usize, TestModelError> {
    let mut decoded_length = 0usize;
    let mut characters = inner.char_indices().peekable();
    let mut polled_at = 0usize;
    while let Some((offset, character)) = characters.next() {
        if offset.saturating_sub(polled_at) >= COPY_POLL_BYTES {
            poll(is_cancelled)?;
            polled_at = offset;
        }
        let decoded = if character == '\\' {
            let (_, escape) = characters.next().ok_or_else(|| invalid_scenario(id))?;
            match escape {
                '"' => '"',
                '\\' => '\\',
                'b' => '\u{0008}',
                't' => '\t',
                'n' => '\n',
                'f' => '\u{000c}',
                'r' => '\r',
                'u' => decode_unicode_escape(&mut characters, 4, id)?,
                'U' => decode_unicode_escape(&mut characters, 8, id)?,
                _ => return Err(invalid_scenario(id)),
            }
        } else {
            if character == '"' || character <= '\u{001f}' || character == '\u{007f}' {
                return Err(invalid_scenario(id));
            }
            character
        };
        decoded_length = decoded_length
            .checked_add(decoded.len_utf8())
            .ok_or_else(|| invalid_scenario(id))?;
        emit(decoded)?;
    }
    poll(is_cancelled)?;
    Ok(decoded_length)
}

fn decode_unicode_escape(
    characters: &mut std::iter::Peekable<str::CharIndices<'_>>,
    digits: usize,
    id: ScenarioId,
) -> Result<char, TestModelError> {
    let mut scalar = 0u32;
    for _ in 0..digits {
        let (_, digit) = characters.next().ok_or_else(|| invalid_scenario(id))?;
        let value = digit.to_digit(16).ok_or_else(|| invalid_scenario(id))?;
        scalar = scalar
            .checked_mul(16)
            .and_then(|value_so_far| value_so_far.checked_add(value))
            .ok_or_else(|| invalid_scenario(id))?;
    }
    char::from_u32(scalar).ok_or_else(|| invalid_scenario(id))
}

fn encode_scenario(
    scenario: &ImageScenario,
    maximum_bytes: u64,
    maximum_steps: u32,
    maximum_step_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>, TestModelError> {
    scenario.validate_shape()?;
    if scenario.steps.len() > maximum_steps as usize {
        return Err(resource_limit(
            SCENARIO_STEPS_RESOURCE,
            u64::from(maximum_steps),
        ));
    }
    for step in &scenario.steps {
        poll(is_cancelled)?;
        let payload = step_payload_bytes(step)
            .ok_or_else(|| resource_limit(STEP_BYTES_RESOURCE, maximum_step_bytes))?;
        if payload > maximum_step_bytes {
            return Err(resource_limit(STEP_BYTES_RESOURCE, maximum_step_bytes));
        }
    }

    let mut counter = TextEncoder::counter(maximum_bytes, is_cancelled);
    encode_document(&mut counter, scenario)?;
    let capacity = usize::try_from(counter.length)
        .map_err(|_| resource_limit(SCENARIO_BYTES_RESOURCE, maximum_bytes))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| resource_limit(SCENARIO_BYTES_RESOURCE, maximum_bytes))?;
    let mut encoder = TextEncoder::buffer(bytes, maximum_bytes, is_cancelled);
    encode_document(&mut encoder, scenario)?;
    let bytes = encoder.finish()?;
    if bytes.len() != capacity {
        return Err(invalid_scenario(scenario.id));
    }
    Ok(bytes)
}

fn step_payload_bytes(step: &ImageScenarioStep) -> Option<u64> {
    let length = match step {
        ImageScenarioStep::SendSerial { bytes } | ImageScenarioStep::ExpectSerial { bytes, .. } => {
            bytes.len()
        }
        ImageScenarioStep::ExpectTestEvent {
            message_contains, ..
        } => message_contains.as_ref().map_or(0, String::len),
        ImageScenarioStep::ExpectExit { .. } | ImageScenarioStep::RequestShutdown { .. } => 0,
    };
    u64::try_from(length).ok()
}

struct TextEncoder<'a> {
    bytes: Option<Vec<u8>>,
    length: u64,
    maximum_bytes: u64,
    is_cancelled: &'a dyn Fn() -> bool,
}

impl<'a> TextEncoder<'a> {
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

    fn finish(self) -> Result<Vec<u8>, TestModelError> {
        poll(self.is_cancelled)?;
        self.bytes.ok_or_else(|| invalid_scenario(ScenarioId(0)))
    }

    fn raw(&mut self, value: &[u8]) -> Result<(), TestModelError> {
        let value_length = u64::try_from(value.len())
            .map_err(|_| resource_limit(SCENARIO_BYTES_RESOURCE, self.maximum_bytes))?;
        let next = self
            .length
            .checked_add(value_length)
            .ok_or_else(|| resource_limit(SCENARIO_BYTES_RESOURCE, self.maximum_bytes))?;
        if next > self.maximum_bytes {
            return Err(resource_limit(SCENARIO_BYTES_RESOURCE, self.maximum_bytes));
        }
        if let Some(bytes) = &mut self.bytes {
            for chunk in value.chunks(COPY_POLL_BYTES) {
                poll(self.is_cancelled)?;
                bytes.extend_from_slice(chunk);
            }
        } else {
            poll(self.is_cancelled)?;
        }
        self.length = next;
        Ok(())
    }

    fn text(&mut self, value: &str) -> Result<(), TestModelError> {
        self.raw(value.as_bytes())
    }

    fn quoted(&mut self, value: &str) -> Result<(), TestModelError> {
        self.raw(b"\"")?;
        for character in value.chars() {
            match character {
                '"' => self.raw(b"\\\"")?,
                '\\' => self.raw(b"\\\\")?,
                '\u{0008}' => self.raw(b"\\b")?,
                '\t' => self.raw(b"\\t")?,
                '\n' => self.raw(b"\\n")?,
                '\u{000c}' => self.raw(b"\\f")?,
                '\r' => self.raw(b"\\r")?,
                '\u{0000}'..='\u{001f}' | '\u{007f}' => {
                    self.raw(b"\\u")?;
                    self.unicode_hex(character as u32, 4)?;
                }
                _ => {
                    let mut storage = [0u8; 4];
                    self.text(character.encode_utf8(&mut storage))?;
                }
            }
        }
        self.raw(b"\"")
    }

    fn unicode_hex(&mut self, value: u32, digits: usize) -> Result<(), TestModelError> {
        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        let mut encoded = [b'0'; 8];
        for (index, byte) in encoded[..digits].iter_mut().enumerate() {
            let shift = (digits - index - 1) * 4;
            *byte = HEX[((value >> shift) & 0x0f) as usize];
        }
        self.raw(&encoded[..digits])
    }

    fn decimal<T: ToString>(&mut self, value: T) -> Result<(), TestModelError> {
        self.text(&value.to_string())
    }

    fn bytes_hex(&mut self, bytes: &[u8]) -> Result<(), TestModelError> {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        self.raw(b"\"")?;
        for byte in bytes {
            self.raw(&[HEX[(byte >> 4) as usize], HEX[(byte & 0x0f) as usize]])?;
        }
        self.raw(b"\"")
    }
}

fn encode_document(
    encoder: &mut TextEncoder<'_>,
    scenario: &ImageScenario,
) -> Result<(), TestModelError> {
    encoder.text("schema = ")?;
    encoder.decimal(scenario.schema)?;
    encoder.text("\nname = ")?;
    encoder.quoted(&scenario.name)?;
    encoder.raw(b"\n")?;
    for step in &scenario.steps {
        encoder.text("\n[[step]]\n")?;
        encode_step(encoder, step)?;
    }
    Ok(())
}

fn encode_step(
    encoder: &mut TextEncoder<'_>,
    step: &ImageScenarioStep,
) -> Result<(), TestModelError> {
    match step {
        ImageScenarioStep::SendSerial { bytes } => {
            encoder.text("kind = \"send-serial\"\nbytes_hex = ")?;
            encoder.bytes_hex(bytes)?;
            encoder.raw(b"\n")
        }
        ImageScenarioStep::ExpectSerial { bytes, timeout_ns } => {
            encoder.text("kind = \"expect-serial\"\nbytes_hex = ")?;
            encoder.bytes_hex(bytes)?;
            encoder.text("\ntimeout_ns = ")?;
            encoder.decimal(*timeout_ns)?;
            encoder.raw(b"\n")
        }
        ImageScenarioStep::ExpectTestEvent {
            kind,
            test,
            message_contains,
            timeout_ns,
        } => {
            encoder.text("kind = \"expect-test-event\"\nevent = \"")?;
            encoder.text(event_name(*kind))?;
            encoder.raw(b"\"\n")?;
            if let Some(test) = test {
                encoder.text("test = ")?;
                encoder.decimal(test.0)?;
                encoder.raw(b"\n")?;
            }
            if let Some(message) = message_contains {
                encoder.text("message_contains = ")?;
                encoder.quoted(message)?;
                encoder.raw(b"\n")?;
            }
            encoder.text("timeout_ns = ")?;
            encoder.decimal(*timeout_ns)?;
            encoder.raw(b"\n")
        }
        ImageScenarioStep::ExpectExit { code, timeout_ns } => {
            encoder.text("kind = \"expect-exit\"\n")?;
            if let Some(code) = code {
                encoder.text("code = ")?;
                encoder.decimal(*code)?;
                encoder.raw(b"\n")?;
            }
            encoder.text("timeout_ns = ")?;
            encoder.decimal(*timeout_ns)?;
            encoder.raw(b"\n")
        }
        ImageScenarioStep::RequestShutdown { timeout_ns } => {
            encoder.text("kind = \"request-shutdown\"\ntimeout_ns = ")?;
            encoder.decimal(*timeout_ns)?;
            encoder.raw(b"\n")
        }
    }
}

fn event_name(kind: ExpectedScenarioEvent) -> &'static str {
    match kind {
        ExpectedScenarioEvent::RunStarted => "run-started",
        ExpectedScenarioEvent::TestStarted => "test-started",
        ExpectedScenarioEvent::Log => "log",
        ExpectedScenarioEvent::AssertionFailed => "assertion-failed",
        ExpectedScenarioEvent::TestFinished => "test-finished",
        ExpectedScenarioEvent::Heartbeat => "heartbeat",
        ExpectedScenarioEvent::RunFinished => "run-finished",
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use wrela_build_model::Sha256Digest;

    use super::*;
    use crate::decode_and_verify_image_scenario;

    const MAXIMUM_BYTES: u64 = 1024 * 1024;
    const MAXIMUM_STEPS: u32 = 128;
    const MAXIMUM_STEP_BYTES: u64 = 4096;
    const SOURCE_PATH: &str = "fixtures/boots-and-serves.toml";

    fn digest() -> Sha256Digest {
        Sha256Digest::from_bytes([0x5a; 32])
    }

    fn request<'a>(name: &'a str, bytes: &'a [u8]) -> ScenarioDecodeRequest<'a> {
        ScenarioDecodeRequest {
            id: ScenarioId(7),
            name,
            source_path: SOURCE_PATH,
            bytes,
            verified_digest: digest(),
            maximum_bytes: MAXIMUM_BYTES,
            maximum_steps: MAXIMUM_STEPS,
            maximum_step_bytes: MAXIMUM_STEP_BYTES,
        }
    }

    fn representative_scenario() -> ImageScenario {
        ImageScenario {
            id: ScenarioId(7),
            schema: IMAGE_SCENARIO_SCHEMA,
            name: "boots-and-serves".to_owned(),
            source_path: SOURCE_PATH.to_owned(),
            digest: digest(),
            steps: vec![
                ImageScenarioStep::ExpectTestEvent {
                    kind: ExpectedScenarioEvent::RunStarted,
                    test: None,
                    message_contains: None,
                    timeout_ns: 30_000_000_000,
                },
                ImageScenarioStep::SendSerial {
                    bytes: b"ping\n".to_vec(),
                },
                ImageScenarioStep::ExpectSerial {
                    bytes: b"pong\n".to_vec(),
                    timeout_ns: 1_000_000_000,
                },
                ImageScenarioStep::RequestShutdown {
                    timeout_ns: 5_000_000_000,
                },
                ImageScenarioStep::ExpectExit {
                    code: Some(0),
                    timeout_ns: 5_000_000_000,
                },
            ],
        }
    }

    fn representative_text() -> &'static str {
        "schema = 1\n\
name = \"boots-and-serves\"\n\
\n\
[[step]]\n\
kind = \"expect-test-event\"\n\
event = \"run-started\"\n\
timeout_ns = 30000000000\n\
\n\
[[step]]\n\
kind = \"send-serial\"\n\
bytes_hex = \"70696e670a\"\n\
\n\
[[step]]\n\
kind = \"expect-serial\"\n\
bytes_hex = \"706f6e670a\"\n\
timeout_ns = 1000000000\n\
\n\
[[step]]\n\
kind = \"request-shutdown\"\n\
timeout_ns = 5000000000\n\
\n\
[[step]]\n\
kind = \"expect-exit\"\n\
code = 0\n\
timeout_ns = 5000000000\n"
    }

    #[test]
    fn representative_language_scenario_is_exactly_canonical() {
        let codec = CanonicalImageScenarioCodec::new();
        let encoded = codec
            .encode_canonical(
                &representative_scenario(),
                MAXIMUM_BYTES,
                MAXIMUM_STEPS,
                MAXIMUM_STEP_BYTES,
                &|| false,
            )
            .expect("encode representative scenario");
        assert_eq!(encoded, representative_text().as_bytes());

        let decoded = decode_and_verify_image_scenario(
            &codec,
            request("boots-and-serves", &encoded),
            &|| false,
        )
        .expect("decode representative scenario");
        assert_eq!(decoded, representative_scenario());
    }

    #[test]
    fn every_step_and_event_variant_round_trips() {
        let scenario = ImageScenario {
            id: ScenarioId(7),
            schema: IMAGE_SCENARIO_SCHEMA,
            name: "all-events-\"quoted\"-雪\nline".to_owned(),
            source_path: SOURCE_PATH.to_owned(),
            digest: digest(),
            steps: vec![
                ImageScenarioStep::SendSerial {
                    bytes: vec![0, 1, 0x7f, 0x80, 0xff],
                },
                ImageScenarioStep::ExpectSerial {
                    bytes: vec![0xde, 0xad, 0xbe, 0xef],
                    timeout_ns: 1,
                },
                ImageScenarioStep::ExpectTestEvent {
                    kind: ExpectedScenarioEvent::RunStarted,
                    test: None,
                    message_contains: None,
                    timeout_ns: 2,
                },
                ImageScenarioStep::ExpectTestEvent {
                    kind: ExpectedScenarioEvent::TestStarted,
                    test: Some(TestId(0)),
                    message_contains: None,
                    timeout_ns: 3,
                },
                ImageScenarioStep::ExpectTestEvent {
                    kind: ExpectedScenarioEvent::Log,
                    test: Some(TestId(u32::MAX)),
                    message_contains: Some(
                        "quoted \"message\" \\ tab\t controls\u{0001}\u{007f}雪".to_owned(),
                    ),
                    timeout_ns: 4,
                },
                ImageScenarioStep::ExpectTestEvent {
                    kind: ExpectedScenarioEvent::AssertionFailed,
                    test: Some(TestId(19)),
                    message_contains: Some("assertion\nfailed".to_owned()),
                    timeout_ns: 5,
                },
                ImageScenarioStep::ExpectTestEvent {
                    kind: ExpectedScenarioEvent::TestFinished,
                    test: Some(TestId(19)),
                    message_contains: None,
                    timeout_ns: 6,
                },
                ImageScenarioStep::ExpectTestEvent {
                    kind: ExpectedScenarioEvent::Heartbeat,
                    test: None,
                    message_contains: None,
                    timeout_ns: 7,
                },
                ImageScenarioStep::RequestShutdown { timeout_ns: 8 },
                ImageScenarioStep::ExpectExit {
                    code: Some(i32::MIN),
                    timeout_ns: u64::MAX - 36,
                },
            ],
        };
        let codec = CanonicalImageScenarioCodec::new();
        let encoded = codec
            .encode_canonical(
                &scenario,
                MAXIMUM_BYTES,
                MAXIMUM_STEPS,
                MAXIMUM_STEP_BYTES,
                &|| false,
            )
            .expect("encode all variants");
        let decoded =
            decode_and_verify_image_scenario(&codec, request(&scenario.name, &encoded), &|| false)
                .expect("decode all variants");
        assert_eq!(decoded, scenario);
    }

    #[test]
    fn run_finished_and_absent_exit_code_round_trip() {
        let codec = CanonicalImageScenarioCodec::new();
        for (name, steps) in [
            (
                "run-finished",
                vec![ImageScenarioStep::ExpectTestEvent {
                    kind: ExpectedScenarioEvent::RunFinished,
                    test: None,
                    message_contains: None,
                    timeout_ns: 99,
                }],
            ),
            (
                "any-exit",
                vec![ImageScenarioStep::ExpectExit {
                    code: None,
                    timeout_ns: 99,
                }],
            ),
        ] {
            let scenario = ImageScenario {
                id: ScenarioId(7),
                schema: IMAGE_SCENARIO_SCHEMA,
                name: name.to_owned(),
                source_path: SOURCE_PATH.to_owned(),
                digest: digest(),
                steps,
            };
            let encoded = codec
                .encode_canonical(
                    &scenario,
                    MAXIMUM_BYTES,
                    MAXIMUM_STEPS,
                    MAXIMUM_STEP_BYTES,
                    &|| false,
                )
                .expect("encode terminal variant");
            let decoded =
                decode_and_verify_image_scenario(&codec, request(name, &encoded), &|| false)
                    .expect("decode terminal variant");
            assert_eq!(decoded, scenario);
        }
    }

    #[test]
    fn rejects_noncanonical_but_structurally_decodable_forms() {
        let codec = CanonicalImageScenarioCodec::new();
        for changed in [
            representative_text().replacen("70696e", "70696E", 1),
            representative_text().replacen("boots", "\\u0062oots", 1),
            representative_text().replacen("code = 0", "code = +0", 1),
        ] {
            assert!(matches!(
                codec.decode(request("boots-and-serves", changed.as_bytes()), &|| false),
                Err(TestModelError::NonCanonicalScenario(ScenarioId(7)))
                    | Err(TestModelError::InvalidScenario(ScenarioId(7)))
            ));
        }
    }

    #[test]
    fn rejects_corruption_unknowns_duplicates_order_and_trailing_data() {
        let codec = CanonicalImageScenarioCodec::new();
        let canonical = representative_text();
        let corruptions = [
            canonical.replacen("schema = 1", "schema=1", 1),
            canonical.replacen(
                "name = \"boots-and-serves\"\n",
                "name = \"boots-and-serves\"\nname = \"boots-and-serves\"\n",
                1,
            ),
            canonical.replacen(
                "bytes_hex = \"70696e670a\"",
                "unknown = 1\nbytes_hex = \"70696e670a\"",
                1,
            ),
            canonical.replacen("kind = \"send-serial\"", "kind = \"send\"", 1),
            canonical.replacen("70696e670a", "70696g670a", 1),
            canonical.replacen("70696e670a", "70696e670", 1),
            canonical.replacen(
                "kind = \"send-serial\"\nbytes_hex = \"70696e670a\"",
                "bytes_hex = \"70696e670a\"\nkind = \"send-serial\"",
                1,
            ),
            canonical.replacen("timeout_ns = 1000000000", "timeout_ns = 0", 1),
            canonical.replacen("timeout_ns = 1000000000", "timeout_ns = 01000000000", 1),
            format!("{canonical}unknown = 1\n"),
            canonical.trim_end_matches('\n').to_owned(),
            canonical.replace('\n', "\r\n"),
            format!("{canonical}\n"),
        ];
        for corrupt in corruptions {
            assert!(
                decode_and_verify_image_scenario(
                    &codec,
                    request("boots-and-serves", corrupt.as_bytes()),
                    &|| false,
                )
                .is_err(),
                "accepted corruption: {corrupt:?}"
            );
        }

        let mut invalid_utf8 = canonical.as_bytes().to_vec();
        invalid_utf8[0] = 0xff;
        assert!(matches!(
            codec.decode(request("boots-and-serves", &invalid_utf8), &|| false),
            Err(TestModelError::InvalidScenario(ScenarioId(7)))
        ));
    }

    #[test]
    fn rejects_every_truncation_of_a_canonical_document() {
        let codec = CanonicalImageScenarioCodec::new();
        let canonical = representative_text().as_bytes();
        for length in 0..canonical.len() {
            let truncated = canonical.get(..length).expect("in-range prefix");
            assert!(
                codec
                    .decode(request("boots-and-serves", truncated), &|| false)
                    .is_err(),
                "accepted truncation at byte {length}"
            );
        }
    }

    #[test]
    fn rejects_invalid_optional_fields_and_event_shapes() {
        let codec = CanonicalImageScenarioCodec::new();
        let base = "schema = 1\nname = \"event\"\n\n[[step]]\nkind = \"expect-test-event\"\nevent = \"run-finished\"\ntimeout_ns = 1\n";
        for invalid in [
            base.replace("event = \"run-finished\"\n", "event = \"unknown\"\n"),
            base.replace(
                "event = \"run-finished\"\n",
                "event = \"run-finished\"\ntest = 0\n",
            ),
            base.replace(
                "event = \"run-finished\"\n",
                "event = \"run-finished\"\nmessage_contains = \"bad\"\n",
            ),
            base.replace(
                "event = \"run-finished\"\n",
                "event = \"log\"\nmessage_contains = \"\"\n",
            ),
            base.replace(
                "event = \"run-finished\"\n",
                "message_contains = \"wrong-order\"\nevent = \"run-finished\"\n",
            ),
        ] {
            assert!(
                codec
                    .decode(request("event", invalid.as_bytes()), &|| false)
                    .is_err()
            );
        }
    }

    #[test]
    fn enforces_total_step_count_and_step_payload_limits_before_success() {
        let codec = CanonicalImageScenarioCodec::new();
        let scenario = representative_scenario();
        let canonical = representative_text().as_bytes();
        let too_small_total = u64::try_from(canonical.len()).expect("length") - 1;
        let mut limited = request("boots-and-serves", canonical);
        limited.maximum_bytes = too_small_total;
        assert!(matches!(
            codec.decode(limited, &|| false),
            Err(TestModelError::ResourceLimit {
                resource: SCENARIO_BYTES_RESOURCE,
                limit
            }) if limit == too_small_total
        ));

        let mut limited = request("boots-and-serves", canonical);
        limited.maximum_steps = 4;
        assert!(matches!(
            codec.decode(limited, &|| false),
            Err(TestModelError::ResourceLimit {
                resource: SCENARIO_STEPS_RESOURCE,
                limit: 4
            })
        ));

        let mut limited = request("boots-and-serves", canonical);
        limited.maximum_step_bytes = 4;
        let result = codec.decode(limited, &|| false);
        assert_eq!(
            result,
            Err(TestModelError::ResourceLimit {
                resource: STEP_BYTES_RESOURCE,
                limit: 4
            })
        );

        assert!(matches!(
            codec.encode_canonical(
                &scenario,
                too_small_total,
                MAXIMUM_STEPS,
                MAXIMUM_STEP_BYTES,
                &|| false,
            ),
            Err(TestModelError::ResourceLimit {
                resource: SCENARIO_BYTES_RESOURCE,
                limit
            }) if limit == too_small_total
        ));
        assert!(matches!(
            codec.encode_canonical(&scenario, MAXIMUM_BYTES, 4, MAXIMUM_STEP_BYTES, &|| false),
            Err(TestModelError::ResourceLimit {
                resource: SCENARIO_STEPS_RESOURCE,
                limit: 4
            })
        ));
        assert!(matches!(
            codec.encode_canonical(&scenario, MAXIMUM_BYTES, MAXIMUM_STEPS, 4, &|| false),
            Err(TestModelError::ResourceLimit {
                resource: STEP_BYTES_RESOURCE,
                limit: 4
            })
        ));

        let mut permissive = request("boots-and-serves", canonical);
        permissive.maximum_bytes = u64::MAX;
        permissive.maximum_step_bytes = u64::MAX;
        assert_eq!(
            codec.decode(permissive, &|| false).expect("maximum limits"),
            scenario
        );
    }

    #[test]
    fn binds_request_identity_and_rejects_invalid_limits() {
        let codec = CanonicalImageScenarioCodec::new();
        let canonical = representative_text().as_bytes();
        assert!(matches!(
            codec.decode(request("different", canonical), &|| false),
            Err(TestModelError::ScenarioIdentityMismatch(ScenarioId(7)))
        ));

        let mut invalid = request("boots-and-serves", canonical);
        invalid.maximum_step_bytes = 0;
        assert!(matches!(
            codec.decode(invalid, &|| false),
            Err(TestModelError::InvalidLimits)
        ));
        assert!(matches!(
            codec.encode_canonical(
                &representative_scenario(),
                0,
                MAXIMUM_STEPS,
                MAXIMUM_STEP_BYTES,
                &|| false,
            ),
            Err(TestModelError::InvalidLimits)
        ));
    }

    #[test]
    fn cancellation_interrupts_decode_encode_and_canonical_round_trip() {
        let codec = CanonicalImageScenarioCodec::new();
        assert!(matches!(
            codec.decode(
                request("boots-and-serves", representative_text().as_bytes()),
                &|| true
            ),
            Err(TestModelError::Cancelled)
        ));
        assert!(matches!(
            codec.encode_canonical(
                &representative_scenario(),
                MAXIMUM_BYTES,
                MAXIMUM_STEPS,
                MAXIMUM_STEP_BYTES,
                &|| true,
            ),
            Err(TestModelError::Cancelled)
        ));

        let polls = Cell::new(0usize);
        let cancel_after_first_poll = || {
            let next = polls.get() + 1;
            polls.set(next);
            next > 1
        };
        assert!(matches!(
            decode_and_verify_image_scenario(
                &codec,
                request("boots-and-serves", representative_text().as_bytes()),
                &cancel_after_first_poll,
            ),
            Err(TestModelError::Cancelled)
        ));
    }
}
