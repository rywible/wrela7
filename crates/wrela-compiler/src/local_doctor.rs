//! Concrete local composition for the public `doctor` command.
//!
//! The structural component table remains useful for an incomplete
//! installation, but existence alone is not evidence of a healthy toolchain.
//! Once every displayed component exists, this driver applies the same
//! bounded installation verification and running-frontend binding used by the
//! compilation pipeline before it can return a healthy outcome.

use std::path::Path;

use wrela_build_model::TargetIdentity;
use wrela_driver::{
    Command, CommandOutput, CompilerDriver, DoctorCheck, DoctorOutcome, DriverError, DriverEvent,
    EventSink,
};
use wrela_toolchain::{
    LocalToolchainVerificationError, LocalToolchainVerificationLimits, LocalToolchainVerifier,
    Toolchain,
};

use crate::CompositionError;

/// Production driver for validating one explicit local toolchain installation.
#[derive(Debug, Clone)]
pub struct LocalDoctorDriver {
    toolchain: Toolchain,
    limits: LocalToolchainVerificationLimits,
}

impl LocalDoctorDriver {
    /// Construct a doctor driver for one already selected installation root.
    pub fn new(
        toolchain: Toolchain,
        limits: LocalToolchainVerificationLimits,
    ) -> Result<Self, CompositionError> {
        limits
            .validate()
            .map_err(|_| CompositionError::InvalidLimits)?;
        Ok(Self { toolchain, limits })
    }

    /// Resolve the declared override or the installation containing the
    /// running frontend. Discovery never searches ambient `PATH`.
    pub fn discover(limits: LocalToolchainVerificationLimits) -> Result<Self, DriverError> {
        let toolchain =
            Toolchain::discover().map_err(|error| DriverError::Toolchain(error.to_string()))?;
        Self::new(toolchain, limits).map_err(|error| DriverError::Input {
            phase: "composition",
            message: error.to_string(),
        })
    }

    #[must_use]
    pub fn toolchain_root(&self) -> &Path {
        self.toolchain.root()
    }

    #[must_use]
    pub const fn limits(&self) -> LocalToolchainVerificationLimits {
        self.limits
    }

    fn doctor(&self, is_cancelled: &dyn Fn() -> bool) -> Result<CommandOutput, DriverError> {
        check_cancelled(is_cancelled)?;
        let checks = self
            .toolchain
            .doctor()
            .checks
            .into_iter()
            .map(|check| {
                DoctorCheck::new(check.name.to_owned(), check.path, check.present).map_err(|_| {
                    DriverError::Toolchain("toolchain returned an invalid check".to_owned())
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let outcome = DoctorOutcome::new(checks).map_err(|_| {
            DriverError::Toolchain("toolchain returned an invalid doctor report".to_owned())
        })?;

        // Preserve the actionable missing-component table. A complete-looking
        // installation, however, must earn a healthy outcome through content,
        // compatibility, target, and running-frontend verification.
        if !outcome.is_healthy() {
            check_cancelled(is_cancelled)?;
            return Ok(CommandOutput::Doctor(outcome));
        }

        let verification = LocalToolchainVerifier::new(self.toolchain.clone())
            .verify(
                &TargetIdentity::aarch64_qemu_virt_uefi(),
                self.limits,
                is_cancelled,
            )
            .map_err(map_verification_error)?;
        verification
            .bind_running_frontend(self.limits.single_file_bytes, is_cancelled)
            .map_err(map_verification_error)?;
        check_cancelled(is_cancelled)?;
        Ok(CommandOutput::Doctor(outcome))
    }
}

impl CompilerDriver for LocalDoctorDriver {
    fn execute(
        &self,
        command: &Command,
        _events: &dyn EventSink,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<CommandOutput, DriverError> {
        check_cancelled(is_cancelled)?;
        match command {
            Command::Doctor => self.doctor(is_cancelled),
            _ => Err(DriverError::InvalidCommand(
                "local doctor driver accepts only a `doctor` command".to_owned(),
            )),
        }
    }
}

/// CLI-oriented entry point using the standard finite verification policy.
pub fn execute_local_doctor(command: &Command) -> Result<CommandOutput, DriverError> {
    LocalDoctorDriver::discover(LocalToolchainVerificationLimits::standard())?.execute(
        command,
        &SilentEvents,
        &never_cancelled,
    )
}

fn map_verification_error(error: LocalToolchainVerificationError) -> DriverError {
    match error {
        LocalToolchainVerificationError::Cancelled => DriverError::Cancelled,
        error => DriverError::Toolchain(error.to_string()),
    }
}

fn check_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), DriverError> {
    if is_cancelled() {
        Err(DriverError::Cancelled)
    } else {
        Ok(())
    }
}

struct SilentEvents;

impl EventSink for SilentEvents {
    fn emit(&self, _event: DriverEvent<'_>) {}
}

const fn never_cancelled() -> bool {
    false
}
