//! Raw LLD driver boundary.
//!
//! This is the only crate permitted to shell out to the system `lld-link`
//! executable. It contains no Wrela model or target policy.

use std::fmt;

#[cfg(test)]
mod archive;

const MAX_LLD_ARGUMENTS: usize = 4096;
const MAX_LLD_ARGUMENT_BYTES: usize = 64 * 1024 * 1024;
#[cfg(feature = "bundled-lld")]
const MAX_LLD_DIAGNOSTIC_BYTES: usize = 1024 * 1024;

/// Raw LLD driver failure before the safe EFI linker adds target policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LldError {
    /// This developer build does not contain the private LLD libraries.
    NotLinked,
    InvalidArguments(&'static str),
    ResourceLimit {
        resource: &'static str,
        limit: usize,
        actual: usize,
    },
    NativeStateUnavailable,
    DiagnosticTooLarge {
        limit: usize,
        actual: usize,
    },
    InvalidDiagnosticEncoding,
    UnexpectedOutput(String),
    DriverFailed {
        status: i32,
        diagnostic: String,
    },
    DriverCannotRunAgain {
        status: i32,
        diagnostic: String,
    },
}

impl fmt::Display for LldError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotLinked => formatter.write_str("bundled LLD is not linked into this build"),
            Self::InvalidArguments(reason) => write!(formatter, "invalid LLD arguments: {reason}"),
            Self::ResourceLimit {
                resource,
                limit,
                actual,
            } => write!(
                formatter,
                "LLD {resource} measured {actual}, exceeding {limit}"
            ),
            Self::NativeStateUnavailable => {
                formatter.write_str("the in-process LLD state is unavailable")
            }
            Self::DiagnosticTooLarge { limit, actual } => write!(
                formatter,
                "LLD diagnostics contain {actual} bytes, exceeding {limit}"
            ),
            Self::InvalidDiagnosticEncoding => {
                formatter.write_str("LLD diagnostics are not valid UTF-8")
            }
            Self::UnexpectedOutput(output) => {
                write!(formatter, "LLD succeeded with unexpected output: {output}")
            }
            Self::DriverFailed { status, diagnostic } => {
                write!(
                    formatter,
                    "LLD COFF driver failed with {status}: {diagnostic}"
                )
            }
            Self::DriverCannotRunAgain { status, diagnostic } => write!(
                formatter,
                "LLD COFF driver left native state unusable after {status}: {diagnostic}"
            ),
        }
    }
}

impl std::error::Error for LldError {}

/// Invoke the raw COFF driver with already policy-validated arguments.
///
/// This shells out to the system `lld-link` executable, passing `arguments`
/// as the remaining argv entries (the linker binary itself is argv[0]).
pub fn link_coff(arguments: &[String]) -> Result<(), LldError> {
    validate_arguments(arguments)?;
    #[cfg(feature = "bundled-lld")]
    {
        native::link_coff(arguments)
    }
    #[cfg(not(feature = "bundled-lld"))]
    {
        let _ = arguments;
        Err(LldError::NotLinked)
    }
}

fn validate_arguments(arguments: &[String]) -> Result<(), LldError> {
    if arguments.is_empty() {
        return Err(LldError::InvalidArguments("argument vector is empty"));
    }
    if arguments.len() > MAX_LLD_ARGUMENTS {
        return Err(LldError::ResourceLimit {
            resource: "argument count",
            limit: MAX_LLD_ARGUMENTS,
            actual: arguments.len(),
        });
    }
    let mut bytes = "lld-link".len() + 1;
    for argument in arguments {
        if argument.is_empty() || argument.as_bytes().contains(&0) {
            return Err(LldError::InvalidArguments(
                "arguments must be nonempty NUL-free UTF-8",
            ));
        }
        bytes = bytes
            .checked_add(argument.len())
            .and_then(|value| value.checked_add(1))
            .ok_or(LldError::ResourceLimit {
                resource: "argument bytes",
                limit: MAX_LLD_ARGUMENT_BYTES,
                actual: usize::MAX,
            })?;
        if bytes > MAX_LLD_ARGUMENT_BYTES {
            return Err(LldError::ResourceLimit {
                resource: "argument bytes",
                limit: MAX_LLD_ARGUMENT_BYTES,
                actual: bytes,
            });
        }
    }
    Ok(())
}

#[cfg(feature = "bundled-lld")]
mod native {
    use std::env;
    use std::path::PathBuf;
    use std::process::Command;

    use super::{LldError, MAX_LLD_DIAGNOSTIC_BYTES};

    const FALLBACK_LLD_LINK: &str = "/opt/homebrew/opt/lld/bin/lld-link";

    pub(super) fn link_coff(arguments: &[String]) -> Result<(), LldError> {
        require_exactly_one_direct_output(arguments)?;
        let linker = discover_linker();
        let output = Command::new(&linker)
            .args(arguments)
            .output()
            .map_err(|error| LldError::DriverFailed {
                status: -1,
                diagnostic: format!("cannot execute {}: {error}", linker.display()),
            })?;
        let status = output.status.code().unwrap_or(-1);
        let mut diagnostic = String::with_capacity(output.stdout.len() + output.stderr.len());
        diagnostic.push_str(&String::from_utf8_lossy(&output.stdout));
        diagnostic.push_str(&String::from_utf8_lossy(&output.stderr));
        let diagnostic = trim_in_place(diagnostic);
        if diagnostic.len() > MAX_LLD_DIAGNOSTIC_BYTES {
            return Err(LldError::DiagnosticTooLarge {
                limit: MAX_LLD_DIAGNOSTIC_BYTES,
                actual: diagnostic.len(),
            });
        }
        if !output.status.success() {
            return Err(LldError::DriverFailed { status, diagnostic });
        }
        if !diagnostic.is_empty() {
            return Err(LldError::UnexpectedOutput(diagnostic));
        }
        Ok(())
    }

    /// Port of the old in-process shim's one-`/out:`-path guard, checked
    /// before spawning the linker so behavior matches the prior boundary.
    fn require_exactly_one_direct_output(arguments: &[String]) -> Result<(), LldError> {
        let direct_outputs = arguments
            .iter()
            .filter(|argument| argument.to_ascii_lowercase().starts_with("/out:"))
            .count();
        if direct_outputs != 1 {
            return Err(LldError::DriverFailed {
                status: -2,
                diagnostic: "LLD invocation requires exactly one direct /out: path".to_owned(),
            });
        }
        Ok(())
    }

    fn discover_linker() -> PathBuf {
        if let Some(path) = env::var_os("WRELA_LLD_LINK") {
            return PathBuf::from(path);
        }
        if let Some(path) = find_on_path("lld-link") {
            return path;
        }
        PathBuf::from(FALLBACK_LLD_LINK)
    }

    fn find_on_path(name: &str) -> Option<PathBuf> {
        let path_variable = env::var_os("PATH")?;
        env::split_paths(&path_variable).find_map(|directory| {
            let candidate = directory.join(name);
            candidate.is_file().then_some(candidate)
        })
    }

    fn trim_in_place(mut value: String) -> String {
        let leading_bytes = value.len() - value.trim_start().len();
        let trimmed_bytes = value.trim().len();
        if leading_bytes != 0 {
            value.drain(..leading_bytes);
        }
        value.truncate(trimmed_bytes);
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_boundary_rejects_invalid_or_oversized_arguments_before_native_code() {
        assert_eq!(
            link_coff(&[]),
            Err(LldError::InvalidArguments("argument vector is empty"))
        );
        assert!(matches!(
            link_coff(&vec!["x".to_owned(); MAX_LLD_ARGUMENTS + 1]),
            Err(LldError::ResourceLimit {
                resource: "argument count",
                ..
            })
        ));
        assert_eq!(
            link_coff(&["bad\0argument".to_owned()]),
            Err(LldError::InvalidArguments(
                "arguments must be nonempty NUL-free UTF-8"
            ))
        );
    }

    #[cfg(feature = "bundled-lld")]
    #[test]
    fn native_boundary_requires_one_direct_output_before_running_lld() {
        let expected = Err(LldError::DriverFailed {
            status: -2,
            diagnostic: "LLD invocation requires exactly one direct /out: path".to_owned(),
        });
        assert_eq!(link_coff(&["/machine:arm64".to_owned()]), expected);
        assert_eq!(
            link_coff(&[
                "/out:/tmp/first.efi".to_owned(),
                "/OUT:/tmp/second.efi".to_owned(),
            ]),
            Err(LldError::DriverFailed {
                status: -2,
                diagnostic: "LLD invocation requires exactly one direct /out: path".to_owned(),
            })
        );
    }

    #[cfg(not(feature = "bundled-lld"))]
    #[test]
    fn developer_build_reports_the_absent_native_driver_honestly() {
        assert_eq!(
            link_coff(&["/machine:arm64".to_owned()]),
            Err(LldError::NotLinked)
        );
    }
}
