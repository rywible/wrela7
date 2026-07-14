//! Mandatory WIR verification and whole-image transformation pipeline.

#![forbid(unsafe_code)]

use wrela_wir::Module;

/// A module whose currently defined WIR invariants have been established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedModule(Module);

impl VerifiedModule {
    /// Borrow verified WIR for code generation or reporting.
    #[must_use]
    pub fn as_module(&self) -> &Module {
        &self.0
    }

    /// Recover ownership while retaining the caller's proof obligation.
    #[must_use]
    pub fn into_module(self) -> Module {
        self.0
    }
}

/// A semantic or structural WIR invariant violation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationError {
    message: String,
}

impl VerificationError {
    /// Source-facing explanation to attach to a lowering why-chain.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Re-establish invariants after lowering and every semantics-sensitive pass.
pub fn verify(module: Module) -> Result<VerifiedModule, VerificationError> {
    if module.name.trim().is_empty() {
        return Err(VerificationError {
            message: "the whole-image module has no name".to_owned(),
        });
    }
    if module.target.0.trim().is_empty() {
        return Err(VerificationError {
            message: "the whole-image module has no target".to_owned(),
        });
    }

    for (index, function) in module.functions.iter().enumerate() {
        if function.id.0 as usize != index {
            return Err(VerificationError {
                message: format!("function IDs must be dense; expected {index}"),
            });
        }
    }

    Ok(VerifiedModule(module))
}

#[cfg(test)]
mod tests {
    use wrela_target::TargetIdentity;
    use wrela_wir::{Function, FunctionId, Module};

    use super::verify;

    #[test]
    fn passes_are_testable_with_hand_built_wir() {
        let module = Module {
            name: "demo".to_owned(),
            target: TargetIdentity("x86_64-uefi".to_owned()),
            functions: vec![Function {
                id: FunctionId(0),
                name: "image".to_owned(),
            }],
        };

        assert_eq!(verify(module).expect("valid WIR").as_module().name, "demo");
    }
}
