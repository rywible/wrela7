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
        validate_line_policy(&candidate.formatted, request.options)?;
    }

    let mut replacement_bytes = 0u64;
    let mut previous_end = 0u32;
    for edit in &candidate.edits {
        if edit.file != request.source.id()
            || request.source.slice(edit.range).is_none()
            || edit.range.start < effective_range.start
            || edit.range.end > effective_range.end
            || edit.range.start < previous_end
            || request.source.slice(edit.range) == Some(edit.replacement.as_str())
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
            validate_line_endings(&edit.replacement, request.options.line_ending)?;
        }
    }
    if replacement_bytes > request.options.maximum_output_bytes {
        return Err(FormatError::OutputTooLarge {
            limit: request.options.maximum_output_bytes,
        });
    }
    let reconstructed = apply_edits(request.source, &candidate.edits, formatted_bytes)?;
    let changed = candidate.formatted != request.source.text();
    if reconstructed != candidate.formatted
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
) -> Result<String, FormatError> {
    let capacity = usize::try_from(output_bytes).map_err(|_| FormatError::OutputTooLarge {
        limit: output_bytes,
    })?;
    let mut output = String::with_capacity(capacity);
    let mut cursor = 0usize;
    for edit in edits {
        let start = edit.range.start as usize;
        let end = edit.range.end as usize;
        output.push_str(&source.text()[cursor..start]);
        output.push_str(&edit.replacement);
        cursor = end;
    }
    output.push_str(&source.text()[cursor..]);
    Ok(output)
}

fn validate_line_policy(formatted: &str, options: &FormatOptions) -> Result<(), FormatError> {
    validate_line_endings(formatted, options.line_ending)?;
    let newline = match options.line_ending {
        LineEnding::Lf => "\n",
        LineEnding::CrLf => "\r\n",
    };
    if options.trailing_newline != formatted.ends_with(newline) {
        return Err(FormatError::InconsistentOutput);
    }
    Ok(())
}

fn validate_line_endings(formatted: &str, line_ending: LineEnding) -> Result<(), FormatError> {
    match line_ending {
        LineEnding::Lf => {
            if formatted.as_bytes().contains(&b'\r') {
                return Err(FormatError::InconsistentOutput);
            }
        }
        LineEnding::CrLf => {
            let bytes = formatted.as_bytes();
            if bytes.iter().enumerate().any(|(index, byte)| {
                (*byte == b'\n' && (index == 0 || bytes[index - 1] != b'\r'))
                    || (*byte == b'\r' && (index + 1 == bytes.len() || bytes[index + 1] != b'\n'))
            }) {
                return Err(FormatError::InconsistentOutput);
            }
        }
    }
    Ok(())
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
    MalformedLosslessAst(String),
    OutputTooLarge { limit: u64 },
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
            Self::OutputTooLarge { limit } => {
                write!(formatter, "formatted output exceeds {limit} bytes")
            }
        }
    }
}

impl std::error::Error for FormatError {}

#[cfg(test)]
mod contract_tests {
    use super::{FormatError, FormatOptions};

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
    }
}
