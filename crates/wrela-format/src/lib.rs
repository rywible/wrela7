//! Canonical source formatting over the lossless typed AST.

#![forbid(unsafe_code)]

use std::fmt;

use wrela_source::{FileId, SourceFile, TextRange};
use wrela_syntax::ParsedFile;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineEnding {
    Lf,
    CrLf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatOptions {
    pub indentation_width: u8,
    pub maximum_line_width: u16,
    pub line_ending: LineEnding,
    pub trailing_newline: bool,
    /// Maximum number of canonical, non-overlapping edits a formatter may
    /// return for one file.
    pub maximum_edits: u32,
    /// Aggregate ceiling for the complete formatted file and replacement text.
    pub maximum_output_bytes: u64,
}

impl Default for FormatOptions {
    fn default() -> Self {
        Self {
            indentation_width: 4,
            maximum_line_width: 100,
            line_ending: LineEnding::Lf,
            trailing_newline: true,
            maximum_edits: 1_000_000,
            maximum_output_bytes: 256 * 1024 * 1024,
        }
    }
}

impl FormatOptions {
    pub fn validate(&self) -> Result<(), FormatError> {
        if !(1..=16).contains(&self.indentation_width) {
            return Err(FormatError::InvalidOptions(
                "indentation width must be between 1 and 16",
            ));
        }
        if !(20..=1000).contains(&self.maximum_line_width) {
            return Err(FormatError::InvalidOptions(
                "maximum line width must be between 20 and 1000",
            ));
        }
        if self.maximum_output_bytes == 0 {
            return Err(FormatError::InvalidOptions(
                "maximum output bytes must be nonzero",
            ));
        }
        if self.maximum_edits == 0 {
            return Err(FormatError::InvalidOptions(
                "maximum edit count must be nonzero",
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub struct FormatRequest<'a> {
    pub parsed: &'a ParsedFile,
    /// Exact source bytes whose digest and file ID must match `parsed`.
    pub source: &'a SourceFile,
    pub options: &'a FormatOptions,
    /// When present, formatting is restricted to the smallest enclosing AST
    /// node and the returned edits do not touch bytes outside that node.
    pub range: Option<TextRange>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextEdit {
    pub file: FileId,
    pub range: TextRange,
    pub replacement: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatOutputCandidate {
    pub edits: Vec<TextEdit>,
    pub formatted: String,
    pub changed: bool,
    /// Exact AST node selected for range formatting, or the whole-file range.
    pub effective_range: TextRange,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatOutput {
    edits: Vec<TextEdit>,
    formatted: String,
    effective_range: TextRange,
}

impl FormatOutput {
    #[must_use]
    pub fn edits(&self) -> &[TextEdit] {
        &self.edits
    }

    #[must_use]
    pub fn formatted(&self) -> &str {
        &self.formatted
    }

    #[must_use]
    pub fn changed(&self) -> bool {
        !self.edits.is_empty()
    }

    #[must_use]
    pub fn effective_range(&self) -> TextRange {
        self.effective_range
    }
}

pub trait Formatter {
    fn format(
        &self,
        request: FormatRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<FormatOutput, FormatError>;
}

/// Cross-check and seal the formatter's redundant text/edit representation.
pub fn seal_format_output(
    request: &FormatRequest<'_>,
    candidate: FormatOutputCandidate,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<FormatOutput, FormatError> {
    const CANCELLATION_INTERVAL: usize = 256;

    if is_cancelled() {
        return Err(FormatError::Cancelled);
    }
    request.options.validate()?;
    if request.parsed.file() != request.source.id()
        || request.parsed.source_digest() != request.source.digest()
    {
        return Err(FormatError::StaleParsedFile);
    }
    if !request.parsed.recovery_complete() {
        return Err(FormatError::IncompleteRecovery);
    }
    let full_range = request.source.full_span().range;
    let effective_range = match request.range {
        None => full_range,
        Some(range) => {
            if request.source.slice(range).is_none() {
                return Err(FormatError::RangeOutsideFile);
            }
            request
                .parsed
                .smallest_enclosing_node(range)
                .ok_or(FormatError::RangeOutsideFile)?
        }
    };
    if candidate.effective_range != effective_range {
        return Err(FormatError::WrongEffectiveRange);
    }
    let formatted_bytes =
        u64::try_from(candidate.formatted.len()).map_err(|_| FormatError::OutputTooLarge {
            limit: request.options.maximum_output_bytes,
        })?;
    if formatted_bytes > request.options.maximum_output_bytes {
        return Err(FormatError::OutputTooLarge {
            limit: request.options.maximum_output_bytes,
        });
    }
    if request.range.is_none() {
        validate_line_policy(&candidate.formatted, request.options, is_cancelled)?;
    }
    if u32::try_from(candidate.edits.len())
        .map_or(true, |edits| edits > request.options.maximum_edits)
    {
        return Err(FormatError::TooManyEdits {
            limit: request.options.maximum_edits,
        });
    }

    let mut replacement_bytes = 0u64;
    let mut previous_end = 0u32;
    for (work, edit) in candidate.edits.iter().enumerate() {
        if work % CANCELLATION_INTERVAL == 0 && is_cancelled() {
            return Err(FormatError::Cancelled);
        }
        let original = request
            .source
            .slice(edit.range)
            .ok_or(FormatError::InvalidEdits)?;
        if edit.file != request.source.id()
            || edit.range.start < effective_range.start
            || edit.range.end > effective_range.end
            || edit.range.start < previous_end
            || equal_text(original, &edit.replacement, is_cancelled)?
        {
            return Err(FormatError::InvalidEdits);
        }
        previous_end = edit.range.end;
        replacement_bytes = replacement_bytes
            .checked_add(u64::try_from(edit.replacement.len()).map_err(|_| {
                FormatError::OutputTooLarge {
                    limit: request.options.maximum_output_bytes,
                }
            })?)
            .ok_or(FormatError::OutputTooLarge {
                limit: request.options.maximum_output_bytes,
            })?;
        if request.range.is_some() {
            validate_line_endings(&edit.replacement, request.options.line_ending, is_cancelled)?;
        }
    }
    if replacement_bytes > request.options.maximum_output_bytes {
        return Err(FormatError::OutputTooLarge {
            limit: request.options.maximum_output_bytes,
        });
    }
    let reconstructed = apply_edits(
        request.source,
        &candidate.edits,
        formatted_bytes,
        is_cancelled,
    )?;
    let reconstructed_matches = equal_text(&reconstructed, &candidate.formatted, is_cancelled)?;
    let changed = !equal_text(&candidate.formatted, request.source.text(), is_cancelled)?;
    if !reconstructed_matches
        || candidate.changed != changed
        || candidate.edits.is_empty() == changed
    {
        return Err(FormatError::InconsistentOutput);
    }
    if is_cancelled() {
        return Err(FormatError::Cancelled);
    }
    Ok(FormatOutput {
        edits: candidate.edits,
        formatted: candidate.formatted,
        effective_range,
    })
}

fn apply_edits(
    source: &SourceFile,
    edits: &[TextEdit],
    output_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<String, FormatError> {
    const CANCELLATION_INTERVAL: usize = 256;

    let capacity = usize::try_from(output_bytes).map_err(|_| FormatError::OutputTooLarge {
        limit: output_bytes,
    })?;
    let mut reconstructed_bytes = source.text().len();
    for (work, edit) in edits.iter().enumerate() {
        if work % CANCELLATION_INTERVAL == 0 && is_cancelled() {
            return Err(FormatError::Cancelled);
        }
        let removed = (edit.range.end - edit.range.start) as usize;
        reconstructed_bytes = reconstructed_bytes
            .checked_sub(removed)
            .and_then(|bytes| bytes.checked_add(edit.replacement.len()))
            .ok_or(FormatError::InconsistentOutput)?;
    }
    if reconstructed_bytes != capacity {
        return Err(FormatError::InconsistentOutput);
    }

    let mut output = String::new();
    output
        .try_reserve_exact(capacity)
        .map_err(|_| FormatError::ResourceExhausted("reconstructed format output"))?;
    let mut cursor = 0usize;
    for (work, edit) in edits.iter().enumerate() {
        if work % CANCELLATION_INTERVAL == 0 && is_cancelled() {
            return Err(FormatError::Cancelled);
        }
        let start = edit.range.start as usize;
        let end = edit.range.end as usize;
        output.push_str(
            source
                .text()
                .get(cursor..start)
                .ok_or(FormatError::InvalidEdits)?,
        );
        output.push_str(&edit.replacement);
        cursor = end;
    }
    output.push_str(
        source
            .text()
            .get(cursor..)
            .ok_or(FormatError::InvalidEdits)?,
    );
    Ok(output)
}

fn validate_line_policy(
    formatted: &str,
    options: &FormatOptions,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), FormatError> {
    validate_line_endings(formatted, options.line_ending, is_cancelled)?;
    let newline = match options.line_ending {
        LineEnding::Lf => "\n",
        LineEnding::CrLf => "\r\n",
    };
    if options.trailing_newline != formatted.ends_with(newline) {
        return Err(FormatError::InconsistentOutput);
    }
    Ok(())
}

fn validate_line_endings(
    formatted: &str,
    line_ending: LineEnding,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), FormatError> {
    match line_ending {
        LineEnding::Lf => {
            for (work, byte) in formatted.bytes().enumerate() {
                poll_text_work(work, is_cancelled)?;
                if byte == b'\r' {
                    return Err(FormatError::InconsistentOutput);
                }
            }
        }
        LineEnding::CrLf => {
            let bytes = formatted.as_bytes();
            for (index, byte) in bytes.iter().enumerate() {
                poll_text_work(index, is_cancelled)?;
                if (*byte == b'\n' && (index == 0 || bytes[index - 1] != b'\r'))
                    || (*byte == b'\r' && (index + 1 == bytes.len() || bytes[index + 1] != b'\n'))
                {
                    return Err(FormatError::InconsistentOutput);
                }
            }
        }
    }
    Ok(())
}

fn equal_text(
    left: &str,
    right: &str,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, FormatError> {
    const COMPARISON_CHUNK: usize = 64 * 1024;
    if left.len() != right.len() {
        return Ok(false);
    }
    for (left, right) in left
        .as_bytes()
        .chunks(COMPARISON_CHUNK)
        .zip(right.as_bytes().chunks(COMPARISON_CHUNK))
    {
        if is_cancelled() {
            return Err(FormatError::Cancelled);
        }
        if left != right {
            return Ok(false);
        }
    }
    Ok(true)
}

fn poll_text_work(work: usize, is_cancelled: &dyn Fn() -> bool) -> Result<(), FormatError> {
    if work % 4096 == 0 && is_cancelled() {
        Err(FormatError::Cancelled)
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatError {
    Cancelled,
    InvalidOptions(&'static str),
    RangeOutsideFile,
    StaleParsedFile,
    IncompleteRecovery,
    WrongEffectiveRange,
    InvalidEdits,
    InconsistentOutput,
    MalformedLosslessAst(&'static str),
    TooManyEdits { limit: u32 },
    OutputTooLarge { limit: u64 },
    ResourceExhausted(&'static str),
}

impl fmt::Display for FormatError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("formatting was cancelled"),
            Self::InvalidOptions(reason) => {
                write!(formatter, "invalid formatter options: {reason}")
            }
            Self::RangeOutsideFile => {
                formatter.write_str("format range is outside the source file")
            }
            Self::StaleParsedFile => {
                formatter.write_str("parsed file does not match the source being formatted")
            }
            Self::IncompleteRecovery => {
                formatter.write_str("cannot format a parse stopped by a resource bound")
            }
            Self::WrongEffectiveRange => {
                formatter.write_str("formatter selected the wrong enclosing AST range")
            }
            Self::InvalidEdits => {
                formatter.write_str("formatter edits are stale, overlapping, unsorted, or no-op")
            }
            Self::InconsistentOutput => {
                formatter.write_str("formatter text, edits, changed flag, or line policy disagree")
            }
            Self::MalformedLosslessAst(reason) => {
                write!(formatter, "cannot format malformed lossless AST: {reason}")
            }
            Self::TooManyEdits { limit } => {
                write!(formatter, "formatter output exceeds {limit} edits")
            }
            Self::OutputTooLarge { limit } => {
                write!(formatter, "formatted output exceeds {limit} bytes")
            }
            Self::ResourceExhausted(resource) => {
                write!(formatter, "cannot allocate bounded {resource}")
            }
        }
    }
}

impl std::error::Error for FormatError {}

#[cfg(test)]
mod contract_tests {
    use std::cell::Cell;

    use wrela_source::{Sha256Digest, SourceDatabase, SourceInput, TextRange};
    use wrela_syntax::{ParseLimits, ParseRequest, SyntaxParser, WrelaSyntaxParser};

    use super::{
        FormatError, FormatOptions, FormatOutputCandidate, FormatRequest, TextEdit,
        seal_format_output,
    };

    fn parsed_source(text: &str) -> (SourceDatabase, wrela_syntax::ParsedFile) {
        let mut sources = SourceDatabase::default();
        let file = sources
            .add(SourceInput {
                path: "app.wr".to_owned(),
                text: text.to_owned(),
                digest: Sha256Digest::from_bytes([0x41; 32]),
            })
            .expect("canonical source");
        let (parsed, diagnostics) = WrelaSyntaxParser::new()
            .parse(
                ParseRequest {
                    sources: &sources,
                    file,
                    limits: ParseLimits::standard(),
                },
                &|| false,
            )
            .expect("bounded parse")
            .into_parts();
        assert!(
            diagnostics.is_empty(),
            "fixture must parse without recovery"
        );
        (sources, parsed)
    }

    #[test]
    fn formatter_policy_rejects_zero_output_capacity() {
        FormatOptions::default()
            .validate()
            .expect("standard options");
        let options = FormatOptions {
            maximum_output_bytes: 0,
            ..FormatOptions::default()
        };
        assert!(matches!(
            options.validate(),
            Err(FormatError::InvalidOptions(_))
        ));

        let options = FormatOptions {
            maximum_edits: 0,
            ..FormatOptions::default()
        };
        assert!(matches!(
            options.validate(),
            Err(FormatError::InvalidOptions(_))
        ));
    }

    #[test]
    fn formatter_seal_bounds_edit_count_and_rejects_length_substitution() {
        let (sources, parsed) = parsed_source("module app\n");
        let source = sources.get(parsed.file()).expect("parsed source");
        let options = FormatOptions {
            maximum_edits: 1,
            ..FormatOptions::default()
        };
        let request = FormatRequest {
            parsed: &parsed,
            source,
            options: &options,
            range: None,
        };
        let edit = TextEdit {
            file: source.id(),
            range: TextRange { start: 7, end: 10 },
            replacement: "core".to_owned(),
        };
        assert!(matches!(
            seal_format_output(
                &request,
                FormatOutputCandidate {
                    edits: vec![edit.clone(), edit.clone()],
                    formatted: source.text().to_owned(),
                    changed: false,
                    effective_range: source.full_span().range,
                },
                &|| false,
            ),
            Err(FormatError::TooManyEdits { limit: 1 })
        ));

        let mut substituted = edit.clone();
        substituted.replacement = "longer".to_owned();
        assert!(matches!(
            seal_format_output(
                &request,
                FormatOutputCandidate {
                    edits: vec![substituted],
                    formatted: "module core\n".to_owned(),
                    changed: true,
                    effective_range: source.full_span().range,
                },
                &|| false,
            ),
            Err(FormatError::InconsistentOutput)
        ));

        let output = seal_format_output(
            &request,
            FormatOutputCandidate {
                edits: vec![edit],
                formatted: "module core\n".to_owned(),
                changed: true,
                effective_range: source.full_span().range,
            },
            &|| false,
        )
        .expect("exact edit reconstruction");
        assert_eq!(output.formatted(), "module core\n");
    }

    #[test]
    fn formatter_seal_polls_inside_project_sized_text() {
        let (sources, parsed) = parsed_source("module app\n");
        let source = sources.get(parsed.file()).expect("parsed source");
        let options = FormatOptions::default();
        let request = FormatRequest {
            parsed: &parsed,
            source,
            options: &options,
            range: None,
        };
        let polls = Cell::new(0u32);
        assert_eq!(
            seal_format_output(
                &request,
                FormatOutputCandidate {
                    edits: Vec::new(),
                    formatted: "a".repeat(8192),
                    changed: true,
                    effective_range: source.full_span().range,
                },
                &|| {
                    let next = polls.get().saturating_add(1);
                    polls.set(next);
                    next >= 3
                },
            ),
            Err(FormatError::Cancelled)
        );
        assert!(polls.get() >= 3);
    }
}
