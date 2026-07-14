//! Orchestrates frontend analysis, WIR verification, and private backend work.

#![forbid(unsafe_code)]

use std::fmt;
use std::path::PathBuf;

use wrela_toolchain::Toolchain;

/// Commands exposed by the initial toolchain shell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Print installation health and selected component paths.
    Doctor,
    /// Type-check and analyze an image without loading LLVM.
    Check { root: PathBuf },
    /// Compile and link a bootable image with the bundled backend.
    Build { root: PathBuf },
}

/// Execute one public toolchain command.
pub fn run(command: &Command) -> Result<String, DriverError> {
    match command {
        Command::Doctor => {
            let toolchain = Toolchain::discover().map_err(DriverError::Toolchain)?;
            let report = toolchain.doctor();
            let mut output = format!("toolchain root: {}\n", toolchain.root().display());
            for check in &report.checks {
                let state = if check.present { "ok" } else { "missing" };
                output.push_str(&format!(
                    "{state:>7}  {:<16} {}\n",
                    check.name,
                    check.path.display()
                ));
            }
            if !report.is_healthy() {
                output.push_str(
                    "hint: this is expected when running an unpackaged development build\n",
                );
            }
            Ok(output)
        }
        Command::Check { root } | Command::Build { root } => Err(DriverError::NotImplemented {
            operation: match command {
                Command::Check { .. } => "check",
                Command::Build { .. } => "build",
                Command::Doctor => unreachable!(),
            },
            root: root.clone(),
        }),
    }
}

/// Toolchain command failure.
#[derive(Debug)]
pub enum DriverError {
    /// Bundled installation discovery failed.
    Toolchain(wrela_toolchain::ToolchainError),
    /// A compiler phase has not landed yet.
    NotImplemented {
        /// Requested operation.
        operation: &'static str,
        /// Source root passed by the user.
        root: PathBuf,
    },
}

impl fmt::Display for DriverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Toolchain(error) => error.fmt(formatter),
            Self::NotImplemented { operation, root } => write!(
                formatter,
                "`wrela {operation} {}` is scaffolded but not implemented",
                root.display()
            ),
        }
    }
}

impl std::error::Error for DriverError {}
