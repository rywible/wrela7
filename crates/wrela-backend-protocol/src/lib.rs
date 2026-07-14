//! Stable-in-a-release messages exchanged with the private backend process.
//!
//! This protocol is an implementation boundary, not a public language ABI. The
//! version is checked before the driver sends whole-image IR to the backend.

#![forbid(unsafe_code)]

use std::path::PathBuf;

/// Protocol spoken by this build of the frontend and backend.
pub const PROTOCOL_VERSION: u32 = 1;

/// A request to lower verified WIR into the final target artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendRequest {
    /// Path to the serialized, verified WIR module.
    pub wir: PathBuf,
    /// Name of a target shipped in this toolchain.
    pub target: String,
    /// Optimization and diagnostics profile.
    pub profile: BuildProfile,
    /// Path at which the backend must write the final image.
    pub output: PathBuf,
}

/// Backend optimization profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildProfile {
    /// Favor compilation speed and rich diagnostics.
    Development,
    /// Favor runtime performance and image size.
    Release,
}

/// A successful backend response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendResponse {
    /// Final bootable image.
    pub artifact: PathBuf,
    /// Machine-readable build report produced alongside the image.
    pub report: PathBuf,
}
