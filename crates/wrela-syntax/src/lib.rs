//! Recoverable syntax representation. This layer knows no names or types.

#![forbid(unsafe_code)]

use std::fmt;

use wrela_diagnostics::WithDiagnostics;
use wrela_source::{FileId, SourceDatabase, Span};

/// Syntax node kinds exposed at the layer contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyntaxKind {
    /// Root of one parsed source file.
    SourceFile,
    /// Placeholder retained after syntax recovery.
    Error,
}

/// Immutable, source-preserving syntax node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyntaxNode {
    /// Node classification.
    pub kind: SyntaxKind,
    /// Exact source range represented by this node.
    pub span: Span,
    /// Ordered child nodes.
    pub children: Vec<SyntaxNode>,
}

/// Parsed root package. Import expansion will add further file roots here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPackage {
    /// File selected as the build root.
    pub root: FileId,
    /// Recoverable syntax tree for the root file.
    pub tree: SyntaxNode,
}

/// Failure to begin parsing rather than a recoverable syntax diagnostic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The requested root does not exist in the source database.
    UnknownRoot(FileId),
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownRoot(id) => write!(formatter, "unknown root source file {}", id.0),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parse one package without requiring any later compiler layer.
pub fn parse(
    sources: &SourceDatabase,
    root: FileId,
) -> Result<WithDiagnostics<ParsedPackage>, ParseError> {
    let file = sources.get(root).ok_or(ParseError::UnknownRoot(root))?;
    Ok(WithDiagnostics::clean(ParsedPackage {
        root,
        tree: SyntaxNode {
            kind: SyntaxKind::SourceFile,
            span: file.full_span(),
            children: Vec::new(),
        },
    }))
}

#[cfg(test)]
mod tests {
    use wrela_source::SourceDatabase;

    use super::{SyntaxKind, parse};

    #[test]
    fn syntax_layer_runs_without_semantic_layers() {
        let mut sources = SourceDatabase::default();
        let root = sources.add("image.wr", "@image fn image() {}\n");

        let parsed = parse(&sources, root).expect("known root");
        assert!(!parsed.has_errors());
        assert_eq!(parsed.value.tree.kind, SyntaxKind::SourceFile);
    }
}
