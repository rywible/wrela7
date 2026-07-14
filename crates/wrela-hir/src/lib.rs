//! Normalized high-level IR. This crate contains data, not lowering logic.

#![forbid(unsafe_code)]

use wrela_source::{FileId, Span};

/// Dense declaration identity within one HIR package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DeclarationId(pub u32);

/// Normalized declaration categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeclarationKind {
    /// Sealed image constructor.
    Image,
    /// Ordinary function.
    Function,
    /// Actor root such as an app, service, or driver.
    Actor,
}

/// One normalized declaration before type and effect analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Declaration {
    /// Stable dense identity.
    pub id: DeclarationId,
    /// Source-facing name.
    pub name: String,
    /// Declaration category.
    pub kind: DeclarationKind,
    /// Source range used by later diagnostics.
    pub span: Span,
}

/// Complete normalized source graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    /// Root source selected by the build request.
    pub root: FileId,
    /// Name used for diagnostics and artifact defaults.
    pub image_name: String,
    /// Declarations in deterministic source order.
    pub declarations: Vec<Declaration>,
}
