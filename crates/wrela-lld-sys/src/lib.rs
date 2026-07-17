//! Raw LLD driver boundary.
//!
//! This is the only crate permitted to contain the C ABI declaration and
//! unsafe call for the pinned C++ shim. It contains no Wrela model or target
//! policy.

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
/// The shim prepends the fixed `lld-link` program name, captures diagnostics
/// into a fixed Rust-owned buffer, seals the one direct output as a private
/// non-executable regular file, and serializes in-process LLD calls.
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
    use std::ffi::CString;
    use std::os::raw::c_char;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::{LldError, MAX_LLD_DIAGNOSTIC_BYTES};

    static DRIVER_LOCK: Mutex<()> = Mutex::new(());
    static DRIVER_AVAILABLE: AtomicBool = AtomicBool::new(true);

    #[repr(C)]
    struct NativeResult {
        status: i32,
        can_run_again: u8,
        reserved: [u8; 3],
        captured_bytes: usize,
        total_bytes: usize,
    }

    unsafe extern "C" {
        fn wrela_lld_link_coff(
            arguments: *const *const c_char,
            argument_count: usize,
            diagnostics: *mut c_char,
            diagnostic_capacity: usize,
        ) -> NativeResult;
    }

    pub(super) fn link_coff(arguments: &[String]) -> Result<(), LldError> {
        let _guard = DRIVER_LOCK
            .lock()
            .map_err(|_| LldError::NativeStateUnavailable)?;
        if !DRIVER_AVAILABLE.load(Ordering::Acquire) {
            return Err(LldError::NativeStateUnavailable);
        }
        let mut native_arguments = Vec::new();
        native_arguments
            .try_reserve_exact(arguments.len() + 1)
            .map_err(|_| LldError::ResourceLimit {
                resource: "argument count",
                limit: super::MAX_LLD_ARGUMENTS + 1,
                actual: arguments.len() + 1,
            })?;
        native_arguments.push(c_string("lld-link")?);
        for argument in arguments {
            native_arguments.push(c_string(argument)?);
        }
        let mut pointers = Vec::new();
        pointers
            .try_reserve_exact(native_arguments.len())
            .map_err(|_| LldError::ResourceLimit {
                resource: "argument count",
                limit: super::MAX_LLD_ARGUMENTS + 1,
                actual: native_arguments.len(),
            })?;
        pointers.extend(native_arguments.iter().map(|argument| argument.as_ptr()));
        let mut diagnostics = Vec::new();
        diagnostics
            .try_reserve_exact(MAX_LLD_DIAGNOSTIC_BYTES)
            .map_err(|_| LldError::ResourceLimit {
                resource: "diagnostic bytes",
                limit: MAX_LLD_DIAGNOSTIC_BYTES,
                actual: MAX_LLD_DIAGNOSTIC_BYTES,
            })?;
        diagnostics.resize(MAX_LLD_DIAGNOSTIC_BYTES, 0u8);

        // SAFETY: every pointer comes from a live `CString`, the pointer array
        // and fixed diagnostic buffer remain alive for the complete call, and
        // the C++ shim exposes this exact `repr(C)` signature without throwing.
        let result = unsafe {
            wrela_lld_link_coff(
                pointers.as_ptr(),
                pointers.len(),
                diagnostics.as_mut_ptr().cast(),
                diagnostics.len(),
            )
        };
        if result.can_run_again > 1 || result.captured_bytes > diagnostics.len() {
            DRIVER_AVAILABLE.store(false, Ordering::Release);
            return Err(LldError::NativeStateUnavailable);
        }
        if result.can_run_again == 0 {
            DRIVER_AVAILABLE.store(false, Ordering::Release);
        }
        if result.total_bytes > diagnostics.len() {
            return Err(LldError::DiagnosticTooLarge {
                limit: diagnostics.len(),
                actual: result.total_bytes,
            });
        }
        diagnostics.truncate(result.captured_bytes);
        let diagnostic =
            String::from_utf8(diagnostics).map_err(|_| LldError::InvalidDiagnosticEncoding)?;
        let diagnostic = trim_in_place(diagnostic);
        if result.can_run_again == 0 {
            return Err(LldError::DriverCannotRunAgain {
                status: result.status,
                diagnostic,
            });
        }
        if result.status != 0 {
            return Err(LldError::DriverFailed {
                status: result.status,
                diagnostic,
            });
        }
        if !diagnostic.is_empty() {
            return Err(LldError::UnexpectedOutput(diagnostic));
        }
        Ok(())
    }

    fn c_string(value: &str) -> Result<CString, LldError> {
        let capacity = value.len().checked_add(1).ok_or(LldError::ResourceLimit {
            resource: "argument bytes",
            limit: super::MAX_LLD_ARGUMENT_BYTES,
            actual: usize::MAX,
        })?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| LldError::ResourceLimit {
                resource: "argument bytes",
                limit: super::MAX_LLD_ARGUMENT_BYTES,
                actual: capacity,
            })?;
        bytes.extend_from_slice(value.as_bytes());
        bytes.push(0);
        CString::from_vec_with_nul(bytes)
            .map_err(|_| LldError::InvalidArguments("arguments must be nonempty NUL-free UTF-8"))
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
