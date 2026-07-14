//! Locate and validate components shipped in a wrela distribution.

#![forbid(unsafe_code)]

use std::env;
use std::fmt;
use std::path::{Path, PathBuf};

const ROOT_OVERRIDE: &str = "WRELA_TOOLCHAIN_ROOT";

/// Filesystem layout of one atomic wrela toolchain installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Toolchain {
    root: PathBuf,
}

impl Toolchain {
    /// Resolve from an explicit development override or relative to `wrela`.
    pub fn discover() -> Result<Self, ToolchainError> {
        if let Some(root) = env::var_os(ROOT_OVERRIDE) {
            return Ok(Self::at(root));
        }

        let executable = env::current_exe().map_err(ToolchainError::CurrentExecutable)?;
        Self::from_executable(&executable)
    }

    /// Construct a toolchain rooted at an explicit directory.
    #[must_use]
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Infer the installation root from `<root>/bin/wrela[.exe]`.
    pub fn from_executable(executable: &Path) -> Result<Self, ToolchainError> {
        let bin = executable
            .parent()
            .ok_or_else(|| ToolchainError::UnexpectedLayout {
                executable: executable.to_owned(),
            })?;
        if bin.file_name().and_then(|name| name.to_str()) != Some("bin") {
            return Err(ToolchainError::UnexpectedLayout {
                executable: executable.to_owned(),
            });
        }
        let root = bin
            .parent()
            .ok_or_else(|| ToolchainError::UnexpectedLayout {
                executable: executable.to_owned(),
            })?;
        Ok(Self::at(root))
    }

    /// Installation root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Private LLVM backend executable. It is never searched for on `PATH`.
    #[must_use]
    pub fn backend(&self) -> PathBuf {
        self.root
            .join("libexec")
            .join("wrela")
            .join(executable_name("wrela-backend"))
    }

    /// Manifest describing versions, hashes, targets, and protocol versions.
    #[must_use]
    pub fn manifest(&self) -> PathBuf {
        self.root.join("share/wrela/toolchain.toml")
    }

    /// Installed standard-library source and precompiled target artifacts.
    #[must_use]
    pub fn standard_library(&self) -> PathBuf {
        self.root.join("share/wrela/std")
    }

    /// Check that required bundled components are present.
    #[must_use]
    pub fn doctor(&self) -> DoctorReport {
        let checks = [
            ComponentCheck::new("backend", self.backend()),
            ComponentCheck::new("manifest", self.manifest()),
            ComponentCheck::new("standard library", self.standard_library()),
        ];
        DoctorReport {
            checks: checks.into_iter().collect(),
        }
    }
}

fn executable_name(stem: &str) -> String {
    if cfg!(windows) {
        format!("{stem}.exe")
    } else {
        stem.to_owned()
    }
}

/// Status of a required bundled component.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentCheck {
    /// Human-readable component name.
    pub name: &'static str,
    /// Exact path selected by the toolchain.
    pub path: PathBuf,
    /// Whether the path currently exists.
    pub present: bool,
}

impl ComponentCheck {
    fn new(name: &'static str, path: PathBuf) -> Self {
        let present = path.exists();
        Self {
            name,
            path,
            present,
        }
    }
}

/// Results from validating a toolchain installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorReport {
    /// Required component checks.
    pub checks: Vec<ComponentCheck>,
}

impl DoctorReport {
    /// Whether every required component is present.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.checks.iter().all(|check| check.present)
    }
}

/// Failure to locate the atomic installation containing `wrela`.
#[derive(Debug)]
pub enum ToolchainError {
    /// The operating system did not provide the current executable path.
    CurrentExecutable(std::io::Error),
    /// The executable was not under the expected `<root>/bin` directory.
    UnexpectedLayout {
        /// Executable used for discovery.
        executable: PathBuf,
    },
}

impl fmt::Display for ToolchainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CurrentExecutable(error) => {
                write!(
                    formatter,
                    "cannot locate the running wrela executable: {error}"
                )
            }
            Self::UnexpectedLayout { executable } => write!(
                formatter,
                "{} is not installed under <toolchain>/bin",
                executable.display()
            ),
        }
    }
}

impl std::error::Error for ToolchainError {}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::Toolchain;

    #[test]
    fn derives_private_components_without_path_lookup() {
        let toolchain =
            Toolchain::from_executable(Path::new("/opt/wrela/bin/wrela")).expect("valid layout");

        assert_eq!(toolchain.root(), Path::new("/opt/wrela"));
        assert_eq!(
            toolchain.backend(),
            Path::new("/opt/wrela/libexec/wrela").join(if cfg!(windows) {
                "wrela-backend.exe"
            } else {
                "wrela-backend"
            })
        );
    }

    #[test]
    fn rejects_a_public_binary_outside_bin() {
        let error = Toolchain::from_executable(Path::new("/opt/wrela/wrela"))
            .expect_err("unexpected layout must fail");

        assert!(error.to_string().contains("not installed under"));
    }
}
