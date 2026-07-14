//! Stable source identities and byte ranges shared by compiler layers.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

/// Dense identity assigned to one source file in a compilation session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FileId(pub u32);

/// Half-open byte range within one UTF-8 source file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TextRange {
    /// Inclusive byte offset.
    pub start: u32,
    /// Exclusive byte offset.
    pub end: u32,
}

impl TextRange {
    /// Construct a valid half-open range.
    #[must_use]
    pub fn new(start: u32, end: u32) -> Self {
        assert!(start <= end, "source range start must not exceed its end");
        Self { start, end }
    }
}

/// A source range paired with its stable file identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Span {
    /// File containing the range.
    pub file: FileId,
    /// Byte range within the file.
    pub range: TextRange,
}

/// Source text retained for diagnostics and frontend queries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFile {
    id: FileId,
    path: PathBuf,
    text: String,
}

impl SourceFile {
    /// Stable identity within the containing source database.
    #[must_use]
    pub fn id(&self) -> FileId {
        self.id
    }

    /// Declared path, normalized later by the package loader.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Original UTF-8 source.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Span covering the entire file.
    #[must_use]
    pub fn full_span(&self) -> Span {
        Span {
            file: self.id,
            range: TextRange::new(0, self.text.len().try_into().expect("source exceeds 4 GiB")),
        }
    }
}

/// Session-local source storage. IDs remain stable after files are added.
#[derive(Debug, Default)]
pub struct SourceDatabase {
    files: Vec<SourceFile>,
}

impl SourceDatabase {
    /// Add a source file and return its dense identity.
    pub fn add(&mut self, path: impl Into<PathBuf>, text: impl Into<String>) -> FileId {
        let id = FileId(self.files.len().try_into().expect("too many source files"));
        self.files.push(SourceFile {
            id,
            path: path.into(),
            text: text.into(),
        });
        id
    }

    /// Look up a file without allowing later layers to mutate its identity.
    #[must_use]
    pub fn get(&self, id: FileId) -> Option<&SourceFile> {
        self.files.get(id.0 as usize)
    }

    /// Number of loaded source files.
    #[must_use]
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether no source files have been loaded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{FileId, SourceDatabase};

    #[test]
    fn file_ids_are_dense_and_stable() {
        let mut sources = SourceDatabase::default();
        let first = sources.add("first.wr", "first");
        let second = sources.add("second.wr", "second");

        assert_eq!(first, FileId(0));
        assert_eq!(second, FileId(1));
        assert_eq!(sources.get(first).expect("first file").text(), "first");
    }
}
