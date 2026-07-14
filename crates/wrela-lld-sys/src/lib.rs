//! Raw LLD driver boundary.
//!
//! This is the only crate permitted to contain the C ABI declarations and
//! unsafe calls for the pinned C++ shim. It contains no language semantics.

use std::fmt;

/// Raw LLD driver failure before the safe EFI linker adds target policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LldError {
    /// This developer build does not contain the private LLD libraries.
    NotLinked,
    /// LLD completed with a nonzero driver status.
    DriverFailed(i32),
}

impl fmt::Display for LldError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotLinked => formatter.write_str("bundled LLD is not linked into this build"),
            Self::DriverFailed(status) => write!(formatter, "LLD COFF driver failed with {status}"),
        }
    }
}

impl std::error::Error for LldError {}

/// Invoke the raw COFF driver with already validated arguments.
pub fn link_coff(_arguments: &[String]) -> Result<(), LldError> {
    Err(LldError::NotLinked)
}
