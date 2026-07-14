//! Private backend composition boundary shared by the backend executable tests.

#![forbid(unsafe_code)]

use std::fmt;

use wrela_wir_passes::VerifiedModule;

/// Decode serialized frontend output and independently re-establish WIR proofs.
pub fn decode_and_verify(bytes: &[u8]) -> Result<VerifiedModule, BackendInputError> {
    let module = wrela_wir_codec::decode(bytes).map_err(BackendInputError::Decode)?;
    wrela_wir_passes::verify(module).map_err(BackendInputError::Verify)
}

/// Rejected backend input before LLVM is invoked.
#[derive(Debug)]
pub enum BackendInputError {
    /// Malformed or incompatible serialized WIR.
    Decode(wrela_wir_codec::DecodeError),
    /// Decoded WIR violates a semantic invariant.
    Verify(wrela_wir_passes::VerificationError),
}

impl fmt::Display for BackendInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => error.fmt(formatter),
            Self::Verify(error) => formatter.write_str(error.message()),
        }
    }
}

impl std::error::Error for BackendInputError {}

#[cfg(test)]
mod tests {
    use wrela_target::TargetIdentity;
    use wrela_wir::Module;

    use super::{BackendInputError, decode_and_verify};

    #[test]
    fn backend_reverifies_decoded_wir() {
        let invalid = Module {
            name: String::new(),
            target: TargetIdentity("x86_64-uefi".to_owned()),
            functions: Vec::new(),
        };
        let bytes = wrela_wir_codec::encode(&invalid).expect("encode invalid fixture");

        assert!(matches!(
            decode_and_verify(&bytes),
            Err(BackendInputError::Verify(_))
        ));
    }
}
