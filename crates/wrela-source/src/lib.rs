//! Stable immutable source identities, text, ranges, and locations.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt;

use unicode_normalization::UnicodeNormalization;
pub use wrela_build_model::Sha256Digest;

/// Maximum UTF-8 size of a canonical compilation-wide source path.
///
/// Package tooling uses the same bound before it constructs a source
/// database, so an otherwise valid manifest cannot fail only at insertion.
pub const MAX_SOURCE_PATH_BYTES: usize = 4096;

/// Dense identity assigned to one source file in a compilation session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FileId(pub u32);

/// Validated half-open byte range within UTF-8 source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TextRange {
    pub start: u32,
    pub end: u32,
}

impl TextRange {
    pub fn new(start: u32, end: u32) -> Result<Self, SourceError> {
        if start > end {
            return Err(SourceError::InvalidRange { start, end });
        }
        Ok(Self { start, end })
    }
}

/// Source range paired with its stable file identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Span {
    pub file: FileId,
    pub range: TextRange,
}

/// One-based human display position. `byte_column` is a UTF-8 byte offset from
/// the line start and is deliberately distinct from editor display columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourcePosition {
    pub line: u32,
    pub byte_column: u32,
}

/// Immutable source retained for diagnostics and frontend queries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFile {
    id: FileId,
    path: String,
    text: String,
    digest: Sha256Digest,
    line_starts: Vec<u32>,
}

impl SourceFile {
    #[must_use]
    pub fn id(&self) -> FileId {
        self.id
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Digest verified against the exact UTF-8 bytes before insertion.
    #[must_use]
    pub fn digest(&self) -> Sha256Digest {
        self.digest
    }

    #[must_use]
    pub fn full_span(&self) -> Span {
        Span {
            file: self.id,
            range: TextRange {
                start: 0,
                end: self.text.len() as u32,
            },
        }
    }

    #[must_use]
    pub fn slice(&self, range: TextRange) -> Option<&str> {
        let start = range.start as usize;
        let end = range.end as usize;
        (end <= self.text.len()
            && self.text.is_char_boundary(start)
            && self.text.is_char_boundary(end))
        .then(|| &self.text[start..end])
    }

    /// Resolve a valid byte offset to a stable one-based line/byte-column pair.
    #[must_use]
    pub fn position(&self, offset: u32) -> Option<SourcePosition> {
        if offset as usize > self.text.len() || !self.text.is_char_boundary(offset as usize) {
            return None;
        }
        let line_index = self.line_starts.partition_point(|start| *start <= offset) - 1;
        Some(SourcePosition {
            line: (line_index + 1) as u32,
            byte_column: offset - self.line_starts[line_index] + 1,
        })
    }
}

/// Session-local source storage. IDs remain stable after insertion.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SourceDatabase {
    files: Vec<SourceFile>,
    portable_paths: BTreeSet<String>,
}

/// One declared, content-addressed source input. The database does not hash;
/// package loading must verify `digest` against `text` before insertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceInput {
    pub path: String,
    pub text: String,
    pub digest: Sha256Digest,
}

impl SourceDatabase {
    /// Add already validated UTF-8 source without truncation or panic.
    pub fn add(&mut self, input: SourceInput) -> Result<FileId, SourceError> {
        let SourceInput { path, text, digest } = input;
        validate_source_path(&path)?;
        let mut portable_path = String::new();
        portable_path
            .try_reserve_exact(path.len())
            .map_err(|_| SourceError::ResourceExhausted("portable source path"))?;
        for character in path.chars() {
            portable_path.push(character.to_ascii_lowercase());
        }
        if self.portable_paths.contains(&portable_path) {
            return Err(SourceError::PortablePathCollision(path));
        }
        if let Some(previous) = self.files.last() {
            if previous.path >= path {
                return Err(SourceError::NonCanonicalPathOrder {
                    previous: previous.path.clone(),
                    next: path,
                });
            }
        }
        let length: u32 = text
            .len()
            .try_into()
            .map_err(|_| SourceError::FileTooLarge(text.len()))?;
        let id = FileId(
            self.files
                .len()
                .try_into()
                .map_err(|_| SourceError::TooManyFiles)?,
        );
        let line_start_count = text
            .bytes()
            .filter(|byte| *byte == b'\n')
            .count()
            .checked_add(1)
            .ok_or(SourceError::TooManyLines)?;
        if line_start_count > u32::MAX as usize {
            return Err(SourceError::TooManyLines);
        }
        let mut line_starts = Vec::new();
        line_starts
            .try_reserve_exact(line_start_count)
            .map_err(|_| SourceError::ResourceExhausted("source line index"))?;
        line_starts.push(0);
        for (index, byte) in text.bytes().enumerate() {
            if byte == b'\n' {
                let next = index + 1;
                if next <= length as usize {
                    line_starts.push(next as u32);
                }
            }
        }
        self.files
            .try_reserve(1)
            .map_err(|_| SourceError::ResourceExhausted("source file table"))?;
        self.portable_paths.insert(portable_path);
        self.files.push(SourceFile {
            id,
            path,
            text,
            digest,
            line_starts,
        });
        Ok(id)
    }

    #[must_use]
    pub fn get(&self, id: FileId) -> Option<&SourceFile> {
        self.files.get(id.0 as usize)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.files.len()
    }

    #[must_use]
    pub fn files(&self) -> &[SourceFile] {
        &self.files
    }

    #[must_use]
    pub fn span_text(&self, span: Span) -> Option<&str> {
        self.get(span.file)?.slice(span.range)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceError {
    InvalidRange { start: u32, end: u32 },
    InvalidPath(String),
    PortablePathCollision(String),
    NonCanonicalPathOrder { previous: String, next: String },
    FileTooLarge(usize),
    TooManyFiles,
    TooManyLines,
    ResourceExhausted(&'static str),
}

impl fmt::Display for SourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRange { start, end } => {
                write!(
                    formatter,
                    "source range starts at {start} after ending at {end}"
                )
            }
            Self::InvalidPath(reason) => write!(formatter, "invalid source path: {reason}"),
            Self::PortablePathCollision(path) => {
                write!(formatter, "source path collides portably: {path:?}")
            }
            Self::NonCanonicalPathOrder { previous, next } => write!(
                formatter,
                "source paths must be strictly ordered: {next:?} follows {previous:?}"
            ),
            Self::FileTooLarge(bytes) => {
                write!(
                    formatter,
                    "source file contains {bytes} bytes; maximum is 4 GiB - 1"
                )
            }
            Self::TooManyFiles => formatter.write_str("source database exceeds 32-bit file IDs"),
            Self::TooManyLines => formatter.write_str("source file exceeds 32-bit line IDs"),
            Self::ResourceExhausted(resource) => {
                write!(formatter, "cannot allocate bounded {resource}")
            }
        }
    }
}

impl std::error::Error for SourceError {}

fn validate_source_path(value: &str) -> Result<(), SourceError> {
    if value.is_empty() {
        return Err(SourceError::InvalidPath("path is empty".to_owned()));
    }
    if value.len() > MAX_SOURCE_PATH_BYTES {
        return Err(SourceError::InvalidPath(format!(
            "path exceeds {MAX_SOURCE_PATH_BYTES} UTF-8 bytes"
        )));
    }
    if !value.nfc().eq(value.chars()) {
        return Err(SourceError::InvalidPath(
            "path is not in Unicode NFC".to_owned(),
        ));
    }
    if value.starts_with('/')
        || value.starts_with('\\')
        || value.chars().any(|character| {
            character == '\0' || character == '\\' || character == ':' || character.is_control()
        })
        || value
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(SourceError::InvalidPath(
            "path must be a portable canonical relative UTF-8 path".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use wrela_build_model::Sha256Digest;

    use super::{FileId, SourceDatabase, SourceInput, SourcePosition};

    fn input(path: &str, text: &str) -> SourceInput {
        SourceInput {
            path: path.to_owned(),
            text: text.to_owned(),
            digest: Sha256Digest::from_bytes([0; 32]),
        }
    }

    #[test]
    fn file_ids_are_dense_and_positions_are_stable() {
        let mut sources = SourceDatabase::default();
        let first = sources
            .add(input("first.wr", "first\nline"))
            .expect("first");
        let second = sources.add(input("second.wr", "second")).expect("second");
        assert_eq!(first, FileId(0));
        assert_eq!(second, FileId(1));
        assert_eq!(
            sources.get(first).expect("first file").position(6),
            Some(SourcePosition {
                line: 2,
                byte_column: 1,
            })
        );
    }

    #[test]
    fn source_paths_cannot_escape_or_reorder_the_declared_graph() {
        let mut sources = SourceDatabase::default();
        sources
            .add(input("b.wr", ""))
            .expect("first canonical source");
        assert!(sources.add(input("a.wr", "")).is_err());

        let mut sources = SourceDatabase::default();
        assert!(sources.add(input("../outside.wr", "")).is_err());
        assert!(sources.add(input("C:/outside.wr", "")).is_err());

        let mut sources = SourceDatabase::default();
        sources.add(input("Main.wr", "")).expect("first spelling");
        assert!(sources.add(input("main.wr", "")).is_err());
    }
}
