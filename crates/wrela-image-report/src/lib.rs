//! Backend-neutral image report model required by the build contract.

#![forbid(unsafe_code)]

use wrela_target::TargetIdentity;

/// Current machine-readable report schema.
pub const REPORT_SCHEMA_VERSION: u32 = 1;

/// Initial cross-layer report fields. Analysis and layout passes will extend it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageReport {
    /// Schema used to encode this report.
    pub schema: u32,
    /// Sealed image name.
    pub image_name: String,
    /// Exact emitted target.
    pub target: TargetIdentity,
    /// Reachable declarations after closed-world elimination.
    pub reachable_declarations: u64,
    /// Final artifact size in bytes.
    pub artifact_bytes: u64,
}

impl ImageReport {
    /// Produce a stable readable summary for the CLI.
    #[must_use]
    pub fn render_summary(&self) -> String {
        format!(
            "image ............................... {}\ntarget .............................. {}\nreachable declarations .............. {}\nartifact bytes ...................... {}\n",
            self.image_name, self.target.0, self.reachable_declarations, self.artifact_bytes
        )
    }
}
