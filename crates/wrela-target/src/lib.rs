//! Validated target-package contract with separate semantic and backend views.
//!
//! Semantic analysis cannot observe LLVM triples, linker switches, or host
//! details. Code generation and linking cannot mutate facts under which the
//! frontend established proofs.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt;

pub use wrela_build_model::{Sha256Digest, TargetIdentity};

pub const TARGET_PACKAGE_SCHEMA: u32 = 1;

/// CPU architecture selected by a target package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Architecture {
    Aarch64,
}

/// Byte order of ordinary target scalar storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Endianness {
    Little,
    Big,
}

/// Object format accepted by the target's safe linker policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectFormat {
    Coff,
}

/// Final boot artifact container.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ImageFormat {
    PeCoff,
}

/// Architecture-defined interrupt namespace used by a platform binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InterruptDomain {
    /// ARM Generic Interrupt Controller shared peripheral interrupt.
    GicSpi,
}

/// Interrupt controller whose architectural behavior is exposed to whole-image
/// analysis and implemented by the target runtime object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InterruptController {
    ArmGicV3,
}

/// Interrupt facts visible while proving stack and latency bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterruptSemanticContract {
    controller: InterruptController,
    nested_preemption: bool,
}

impl InterruptSemanticContract {
    #[must_use]
    pub fn controller(self) -> InterruptController {
        self.controller
    }

    #[must_use]
    pub fn nested_preemption(self) -> bool {
        self.nested_preemption
    }
}

/// Exact exception-entry behavior implemented by the target runtime object.
/// Revision 0.1 deliberately forbids nesting and SIMD use in interrupt bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterruptBackendContract {
    controller: InterruptController,
    vector_table_alignment: u32,
    stack_alignment: u32,
    nested_preemption: bool,
    saves_simd: bool,
    cpu_irq_masked_during_handler: bool,
    eoi_deactivates: bool,
    spurious_global_id_minimum: u32,
}

impl InterruptBackendContract {
    #[must_use]
    pub fn controller(self) -> InterruptController {
        self.controller
    }

    #[must_use]
    pub fn vector_table_alignment(self) -> u32 {
        self.vector_table_alignment
    }

    #[must_use]
    pub fn stack_alignment(self) -> u32 {
        self.stack_alignment
    }

    #[must_use]
    pub fn nested_preemption(self) -> bool {
        self.nested_preemption
    }

    #[must_use]
    pub fn saves_simd(self) -> bool {
        self.saves_simd
    }

    /// Whether target entry glue keeps `PSTATE.I` set from acknowledgement
    /// through completion of the handler.
    #[must_use]
    pub fn cpu_irq_masked_during_handler(self) -> bool {
        self.cpu_irq_masked_during_handler
    }

    /// Whether `ICC_EOIR1_EL1` both drops priority and deactivates the INTID
    /// (GICv3 EOImode 0), avoiding a separate deactivate write.
    #[must_use]
    pub fn eoi_deactivates(self) -> bool {
        self.eoi_deactivates
    }

    #[must_use]
    pub fn spurious_global_id_minimum(self) -> u32 {
        self.spurious_global_id_minimum
    }
}

/// One target-owned interrupt identity. `line` is the domain-local number;
/// `global_id` is the architectural interrupt ID reported to source semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct InterruptBinding {
    pub domain: InterruptDomain,
    pub line: u32,
    pub global_id: u32,
}

/// One statically described MMIO device window and optional interrupt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MmioBinding {
    pub name: String,
    pub base: u64,
    pub size: u64,
    pub interrupt: Option<InterruptBinding>,
}

/// Facts available to parsing-independent language semantics and proof checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetSemanticContract {
    identity: TargetIdentity,
    content_digest: Sha256Digest,
    architecture: Architecture,
    pointer_width: u8,
    endianness: Endianness,
    uefi_revision: String,
    coherent_dma: bool,
    iommu_available: bool,
    interrupts: InterruptSemanticContract,
    mmio_bindings: Vec<MmioBinding>,
}

impl TargetSemanticContract {
    #[must_use]
    pub fn identity(&self) -> &TargetIdentity {
        &self.identity
    }

    /// Digest of the complete target package whose facts are exposed here.
    #[must_use]
    pub fn content_digest(&self) -> Sha256Digest {
        self.content_digest
    }

    #[must_use]
    pub fn architecture(&self) -> Architecture {
        self.architecture
    }

    #[must_use]
    pub fn pointer_width(&self) -> u8 {
        self.pointer_width
    }

    #[must_use]
    pub fn endianness(&self) -> Endianness {
        self.endianness
    }

    #[must_use]
    pub fn uefi_revision(&self) -> &str {
        &self.uefi_revision
    }

    #[must_use]
    pub fn coherent_dma(&self) -> bool {
        self.coherent_dma
    }

    #[must_use]
    pub fn iommu_available(&self) -> bool {
        self.iommu_available
    }

    #[must_use]
    pub fn interrupts(&self) -> InterruptSemanticContract {
        self.interrupts
    }

    /// Canonically named target-owned MMIO/interrupt facts.
    #[must_use]
    pub fn mmio_bindings(&self) -> &[MmioBinding] {
        &self.mmio_bindings
    }
}

/// Target-owned safe linker policy; callers cannot inject raw LLD switches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkPolicy {
    dynamic_linking: bool,
    default_libraries: bool,
    relocations: bool,
}

impl LinkPolicy {
    #[must_use]
    pub fn dynamic_linking(&self) -> bool {
        self.dynamic_linking
    }

    #[must_use]
    pub fn default_libraries(&self) -> bool {
        self.default_libraries
    }

    #[must_use]
    pub fn relocations(&self) -> bool {
        self.relocations
    }
}

/// Facts visible only after semantic analysis, at backend boundaries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetBackendContract {
    identity: TargetIdentity,
    content_digest: Sha256Digest,
    llvm_triple: String,
    llvm_data_layout: String,
    llvm_cpu: String,
    llvm_features: Vec<String>,
    coff_machine: String,
    object_format: ObjectFormat,
    image_format: ImageFormat,
    entry_symbol: String,
    subsystem: String,
    runtime_object: String,
    runtime_abi_version: u32,
    interrupts: InterruptBackendContract,
    link: LinkPolicy,
}

/// Host runner kind selected by the target package. It is deliberately
/// separate from semantic and code-generation target facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmulatorKind {
    QemuSystemAarch64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestTransport {
    /// Bounded binary frames escaped over the first non-secure PL011 UART.
    Pl011Serial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootMedium {
    /// A generated FAT EFI system partition exposed through virtio-blk-mmio.
    VirtioBlockFat,
}

/// Reproducible full-image execution profile. Paths are target-relative
/// component names; the toolchain resolves and digest-checks them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetRunnerContract {
    emulator: EmulatorKind,
    machine: String,
    cpu: String,
    accelerator: String,
    memory_mib: u32,
    virtual_cpus: u16,
    firmware_code: String,
    firmware_variables_template: String,
    boot: BootMedium,
    test_transport: TestTransport,
}

impl TargetRunnerContract {
    #[must_use]
    pub fn emulator(&self) -> EmulatorKind {
        self.emulator
    }

    #[must_use]
    pub fn machine(&self) -> &str {
        &self.machine
    }

    #[must_use]
    pub fn cpu(&self) -> &str {
        &self.cpu
    }

    #[must_use]
    pub fn accelerator(&self) -> &str {
        &self.accelerator
    }

    #[must_use]
    pub fn memory_mib(&self) -> u32 {
        self.memory_mib
    }

    #[must_use]
    pub fn virtual_cpus(&self) -> u16 {
        self.virtual_cpus
    }

    #[must_use]
    pub fn firmware_code(&self) -> &str {
        &self.firmware_code
    }

    #[must_use]
    pub fn firmware_variables_template(&self) -> &str {
        &self.firmware_variables_template
    }

    #[must_use]
    pub fn boot_medium(&self) -> BootMedium {
        self.boot
    }

    #[must_use]
    pub fn test_transport(&self) -> TestTransport {
        self.test_transport
    }
}

impl TargetBackendContract {
    #[must_use]
    pub fn identity(&self) -> &TargetIdentity {
        &self.identity
    }

    /// Digest of the complete target package whose policy is exposed here.
    #[must_use]
    pub fn content_digest(&self) -> Sha256Digest {
        self.content_digest
    }

    #[must_use]
    pub fn llvm_triple(&self) -> &str {
        &self.llvm_triple
    }

    #[must_use]
    pub fn llvm_data_layout(&self) -> &str {
        &self.llvm_data_layout
    }

    #[must_use]
    pub fn llvm_cpu(&self) -> &str {
        &self.llvm_cpu
    }

    /// Canonical target-machine features fixed by the target package. These
    /// are not user profile switches; notably UEFI requires X18 to be unused.
    #[must_use]
    pub fn llvm_features(&self) -> &[String] {
        &self.llvm_features
    }

    /// LLD COFF `/machine:` value pinned by the target package.
    #[must_use]
    pub fn coff_machine(&self) -> &str {
        &self.coff_machine
    }

    #[must_use]
    pub fn object_format(&self) -> ObjectFormat {
        self.object_format
    }

    #[must_use]
    pub fn image_format(&self) -> ImageFormat {
        self.image_format
    }

    #[must_use]
    pub fn entry_symbol(&self) -> &str {
        &self.entry_symbol
    }

    #[must_use]
    pub fn subsystem(&self) -> &str {
        &self.subsystem
    }

    #[must_use]
    pub fn runtime_object(&self) -> &str {
        &self.runtime_object
    }

    #[must_use]
    pub fn runtime_abi_version(&self) -> u32 {
        self.runtime_abi_version
    }

    #[must_use]
    pub fn interrupts(&self) -> InterruptBackendContract {
        self.interrupts
    }

    #[must_use]
    pub fn link_policy(&self) -> &LinkPolicy {
        &self.link
    }
}

/// One validated target package containing intentionally separated views.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetPackage {
    schema: u32,
    semantic: TargetSemanticContract,
    backend: TargetBackendContract,
    runner: TargetRunnerContract,
}

#[derive(Debug)]
pub struct TargetDecodeRequest<'a> {
    pub toml_bytes: &'a [u8],
    pub expected_identity: &'a TargetIdentity,
    pub verified_digest: Sha256Digest,
    pub limits: TargetDecodeLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetDecodeLimits {
    pub bytes: u64,
    pub string_bytes: u32,
    pub mmio_bindings: u32,
    pub llvm_features: u32,
}

impl TargetDecodeLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            bytes: 16 * 1024 * 1024,
            string_bytes: 1024 * 1024,
            mmio_bindings: 1_000_000,
            llvm_features: 1024,
        }
    }

    pub fn validate(self) -> Result<(), TargetDecodeError> {
        if self.bytes == 0
            || self.string_bytes == 0
            || self.mmio_bindings == 0
            || self.llvm_features == 0
        {
            Err(TargetDecodeError::InvalidLimits)
        } else {
            Ok(())
        }
    }
}

/// Canonical target-package TOML codec. Unknown fields and duplicate keys are
/// rejected so a newer package cannot be silently interpreted with older
/// semantics.
pub trait TargetPackageCodec {
    fn decode(
        &self,
        request: TargetDecodeRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<TargetPackage, TargetDecodeError>;

    fn encode_canonical(
        &self,
        package: &TargetPackage,
        limits: TargetDecodeLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, TargetDecodeError>;
}

pub fn decode_and_verify_target_package(
    codec: &dyn TargetPackageCodec,
    request: TargetDecodeRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<TargetPackage, TargetDecodeError> {
    if is_cancelled() {
        return Err(TargetDecodeError::Cancelled);
    }
    request.limits.validate()?;
    let bytes =
        u64::try_from(request.toml_bytes.len()).map_err(|_| TargetDecodeError::TooLarge {
            limit: request.limits.bytes,
            actual: u64::MAX,
        })?;
    if bytes > request.limits.bytes {
        return Err(TargetDecodeError::TooLarge {
            limit: request.limits.bytes,
            actual: bytes,
        });
    }
    let input = request.toml_bytes;
    let expected_identity = request.expected_identity.clone();
    let expected_digest = request.verified_digest;
    let limits = request.limits;
    let package = codec.decode(request, is_cancelled)?;
    if is_cancelled() {
        return Err(TargetDecodeError::Cancelled);
    }
    package
        .validate()
        .map_err(TargetDecodeError::InvalidPackage)?;
    if package.identity() != &expected_identity
        || package.semantic().content_digest() != expected_digest
        || package.backend().content_digest() != expected_digest
    {
        return Err(TargetDecodeError::IdentityMismatch);
    }
    let canonical = codec.encode_canonical(&package, limits, is_cancelled)?;
    if is_cancelled() {
        return Err(TargetDecodeError::Cancelled);
    }
    if canonical != input {
        return Err(TargetDecodeError::NonCanonical);
    }
    Ok(package)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetDecodeError {
    Cancelled,
    InvalidLimits,
    TooLarge { limit: u64, actual: u64 },
    InvalidUtf8,
    Malformed { byte_offset: usize, message: String },
    DuplicateKey(String),
    UnknownField(String),
    IdentityMismatch,
    NonCanonical,
    ResourceLimit { resource: &'static str, limit: u64 },
    InvalidPackage(TargetError),
}

impl fmt::Display for TargetDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("target package decoding was cancelled"),
            Self::InvalidLimits => formatter.write_str("target decode limits must be nonzero"),
            Self::TooLarge { limit, actual } => write!(
                formatter,
                "target package contains {actual} bytes, exceeding {limit}"
            ),
            Self::InvalidUtf8 => formatter.write_str("target package is not UTF-8"),
            Self::Malformed {
                byte_offset,
                message,
            } => write!(
                formatter,
                "malformed target package at byte {byte_offset}: {message}"
            ),
            Self::DuplicateKey(key) => write!(formatter, "duplicate target package key {key}"),
            Self::UnknownField(field) => write!(formatter, "unknown target package field {field}"),
            Self::IdentityMismatch => {
                formatter.write_str("decoded target identity does not match the selected target")
            }
            Self::NonCanonical => formatter.write_str(
                "target package bytes are not the canonical encoding of the decoded package",
            ),
            Self::ResourceLimit { resource, limit } => {
                write!(
                    formatter,
                    "target package exceeded {resource} limit {limit}"
                )
            }
            Self::InvalidPackage(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for TargetDecodeError {}

impl TargetPackage {
    /// Revision 0.1 QEMU `virt` AArch64 UEFI target.
    #[must_use]
    pub fn aarch64_qemu_virt_uefi(content_digest: Sha256Digest) -> Self {
        let identity = TargetIdentity::aarch64_qemu_virt_uefi();
        Self {
            schema: TARGET_PACKAGE_SCHEMA,
            semantic: TargetSemanticContract {
                identity: identity.clone(),
                content_digest,
                architecture: Architecture::Aarch64,
                pointer_width: 64,
                endianness: Endianness::Little,
                uefi_revision: "2.11".to_owned(),
                // QEMU `virt` does not make a portable coherent-DMA promise
                // that source semantics may assume.
                coherent_dma: false,
                iommu_available: false,
                interrupts: InterruptSemanticContract {
                    controller: InterruptController::ArmGicV3,
                    nested_preemption: false,
                },
                mmio_bindings: vec![MmioBinding {
                    name: "virtio-mmio-0".to_owned(),
                    base: 0x0a00_0000,
                    size: 0x200,
                    interrupt: Some(InterruptBinding {
                        domain: InterruptDomain::GicSpi,
                        line: 16,
                        global_id: 48,
                    }),
                }],
            },
            backend: TargetBackendContract {
                identity,
                content_digest,
                llvm_triple: "aarch64-unknown-uefi".to_owned(),
                llvm_data_layout: "e-m:e-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128-Fn32"
                    .to_owned(),
                llvm_cpu: "cortex-a57".to_owned(),
                llvm_features: vec!["+reserve-x18".to_owned()],
                coff_machine: "arm64".to_owned(),
                object_format: ObjectFormat::Coff,
                image_format: ImageFormat::PeCoff,
                entry_symbol: "wrela_image_entry".to_owned(),
                subsystem: "efi_application".to_owned(),
                runtime_object: "runtime/wrela-runtime-aarch64.obj".to_owned(),
                runtime_abi_version: wrela_runtime_abi::RUNTIME_ABI_VERSION,
                interrupts: InterruptBackendContract {
                    controller: InterruptController::ArmGicV3,
                    vector_table_alignment: 2048,
                    stack_alignment: 16,
                    nested_preemption: false,
                    saves_simd: false,
                    cpu_irq_masked_during_handler: true,
                    eoi_deactivates: true,
                    spurious_global_id_minimum: 1020,
                },
                link: LinkPolicy {
                    dynamic_linking: false,
                    default_libraries: false,
                    relocations: true,
                },
            },
            runner: TargetRunnerContract {
                emulator: EmulatorKind::QemuSystemAarch64,
                // Versioned QEMU machine behavior is part of target identity.
                machine: "virt-10.0,gic-version=3,secure=off".to_owned(),
                cpu: "cortex-a57".to_owned(),
                accelerator: "tcg,thread=single".to_owned(),
                memory_mib: 512,
                virtual_cpus: 1,
                firmware_code: "firmware/QEMU_EFI.fd".to_owned(),
                firmware_variables_template: "firmware/QEMU_VARS.fd".to_owned(),
                boot: BootMedium::VirtioBlockFat,
                test_transport: TestTransport::Pl011Serial,
            },
        }
    }

    #[must_use]
    pub fn schema(&self) -> u32 {
        self.schema
    }

    #[must_use]
    pub fn identity(&self) -> &TargetIdentity {
        self.semantic.identity()
    }

    #[must_use]
    pub fn semantic(&self) -> &TargetSemanticContract {
        &self.semantic
    }

    #[must_use]
    pub fn backend(&self) -> &TargetBackendContract {
        &self.backend
    }

    #[must_use]
    pub fn runner(&self) -> &TargetRunnerContract {
        &self.runner
    }

    /// Reject incomplete or internally inconsistent target packages.
    pub fn validate(&self) -> Result<(), TargetError> {
        if self.schema != TARGET_PACKAGE_SCHEMA {
            return Err(TargetError::UnsupportedSchema(self.schema));
        }
        if self.semantic.identity != self.backend.identity {
            return Err(TargetError::IdentityMismatch);
        }
        if self.semantic.content_digest != self.backend.content_digest {
            return Err(TargetError::ContentDigestMismatch);
        }
        if !matches!(self.semantic.pointer_width, 32 | 64) {
            return Err(TargetError::InvalidPointerWidth(
                self.semantic.pointer_width,
            ));
        }
        if self.semantic.uefi_revision != "2.11" {
            return Err(TargetError::UnsupportedUefiRevision(
                self.semantic.uefi_revision.clone(),
            ));
        }
        validate_mmio_bindings(&self.semantic.mmio_bindings)?;
        if self.backend.llvm_triple.trim().is_empty() {
            return Err(TargetError::MissingLlvmTriple);
        }
        if self.semantic.architecture != Architecture::Aarch64
            || self.backend.llvm_triple != "aarch64-unknown-uefi"
            || self.backend.llvm_data_layout
                != "e-m:e-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128-Fn32"
            || self.backend.llvm_cpu != "cortex-a57"
            || self.backend.llvm_features != ["+reserve-x18"]
            || self.backend.coff_machine != "arm64"
            || self.backend.llvm_cpu != self.runner.cpu
        {
            return Err(TargetError::ArchitectureBackendMismatch);
        }
        if self.semantic.interrupts.controller != InterruptController::ArmGicV3
            || self.semantic.interrupts.nested_preemption
            || self.backend.interrupts.controller != self.semantic.interrupts.controller
            || self.backend.interrupts.nested_preemption
            || self.backend.interrupts.vector_table_alignment != 2048
            || self.backend.interrupts.stack_alignment != 16
            || self.backend.interrupts.saves_simd
            || !self.backend.interrupts.cpu_irq_masked_during_handler
            || !self.backend.interrupts.eoi_deactivates
            || self.backend.interrupts.spurious_global_id_minimum != 1020
        {
            return Err(TargetError::InvalidInterruptContract);
        }
        if self.backend.entry_symbol.trim().is_empty() {
            return Err(TargetError::MissingEntrySymbol);
        }
        if self.backend.subsystem != "efi_application" {
            return Err(TargetError::UnsupportedSubsystem(
                self.backend.subsystem.clone(),
            ));
        }
        if self.backend.runtime_abi_version != wrela_runtime_abi::RUNTIME_ABI_VERSION
            || validate_component_path(&self.backend.runtime_object).is_err()
        {
            return Err(TargetError::RuntimeAbiMismatch);
        }
        if self.backend.link.dynamic_linking || self.backend.link.default_libraries {
            return Err(TargetError::UnsafeLinkPolicy);
        }
        if self.runner.machine.trim().is_empty()
            || self.runner.cpu.trim().is_empty()
            || self.runner.accelerator.trim().is_empty()
            || self.runner.memory_mib == 0
            || self.runner.virtual_cpus == 0
            || validate_component_path(&self.runner.firmware_code).is_err()
            || validate_component_path(&self.runner.firmware_variables_template).is_err()
        {
            return Err(TargetError::InvalidRunnerContract);
        }
        Ok(())
    }
}

/// Invalid target package before semantic or backend use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetError {
    UnsupportedSchema(u32),
    IdentityMismatch,
    ContentDigestMismatch,
    InvalidPointerWidth(u8),
    UnsupportedUefiRevision(String),
    MissingLlvmTriple,
    ArchitectureBackendMismatch,
    MissingEntrySymbol,
    UnsupportedSubsystem(String),
    UnsafeLinkPolicy,
    InvalidMmioBindings,
    InvalidInterruptContract,
    InvalidRunnerContract,
    RuntimeAbiMismatch,
}

impl fmt::Display for TargetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchema(schema) => {
                write!(formatter, "unsupported target schema {schema}")
            }
            Self::IdentityMismatch => {
                formatter.write_str("semantic and backend target identities differ")
            }
            Self::ContentDigestMismatch => {
                formatter.write_str("semantic and backend target content digests differ")
            }
            Self::InvalidPointerWidth(width) => write!(formatter, "invalid pointer width {width}"),
            Self::UnsupportedUefiRevision(revision) => {
                write!(formatter, "unsupported UEFI revision {revision}")
            }
            Self::MissingLlvmTriple => formatter.write_str("target package has no LLVM triple"),
            Self::ArchitectureBackendMismatch => formatter
                .write_str("target architecture does not match its LLVM triple and COFF machine"),
            Self::MissingEntrySymbol => formatter.write_str("target package has no entry symbol"),
            Self::UnsupportedSubsystem(subsystem) => {
                write!(formatter, "unsupported PE subsystem {subsystem}")
            }
            Self::UnsafeLinkPolicy => {
                formatter.write_str("target permits dynamic or default-library linking")
            }
            Self::InvalidMmioBindings => formatter.write_str(
                "target MMIO bindings must be named, sorted, nonempty, nonoverlapping, and use valid interrupt identities",
            ),
            Self::InvalidInterruptContract => formatter.write_str(
                "target interrupt semantics and exception-entry ABI are inconsistent",
            ),
            Self::InvalidRunnerContract => formatter.write_str(
                "target full-image runner contract is incomplete or contains an invalid component path",
            ),
            Self::RuntimeAbiMismatch => formatter.write_str(
                "target runtime object is missing or uses an incompatible compiler runtime ABI",
            ),
        }
    }
}

impl std::error::Error for TargetError {}

fn validate_mmio_bindings(bindings: &[MmioBinding]) -> Result<(), TargetError> {
    if !bindings.windows(2).all(|pair| pair[0].name < pair[1].name) {
        return Err(TargetError::InvalidMmioBindings);
    }
    let mut ranges = Vec::with_capacity(bindings.len());
    let mut interrupt_ids = BTreeSet::new();
    for binding in bindings {
        let Some(end) = binding.base.checked_add(binding.size) else {
            return Err(TargetError::InvalidMmioBindings);
        };
        if binding.name.is_empty() || binding.size == 0 {
            return Err(TargetError::InvalidMmioBindings);
        }
        if let Some(interrupt) = binding.interrupt {
            match interrupt.domain {
                InterruptDomain::GicSpi
                    if interrupt.line.checked_add(32).is_some_and(|global| {
                        global == interrupt.global_id && interrupt.global_id < 1020
                    }) && interrupt_ids.insert(interrupt.global_id) => {}
                InterruptDomain::GicSpi => return Err(TargetError::InvalidMmioBindings),
            }
        }
        ranges.push((binding.base, end));
    }
    ranges.sort_unstable();
    if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(TargetError::InvalidMmioBindings);
    }
    Ok(())
}

fn validate_component_path(value: &str) -> Result<(), ()> {
    if value.is_empty()
        || value.starts_with('/')
        || value.starts_with('\\')
        || value.contains('\\')
        || value.contains(':')
        || value
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        Err(())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        InterruptController, Sha256Digest, TargetDecodeError, TargetDecodeLimits,
        TargetDecodeRequest, TargetPackage, TargetPackageCodec, decode_and_verify_target_package,
    };
    use wrela_build_model::TargetIdentity;

    struct FixtureCodec;

    impl TargetPackageCodec for FixtureCodec {
        fn decode(
            &self,
            request: TargetDecodeRequest<'_>,
            _is_cancelled: &dyn Fn() -> bool,
        ) -> Result<TargetPackage, TargetDecodeError> {
            Ok(TargetPackage::aarch64_qemu_virt_uefi(
                request.verified_digest,
            ))
        }

        fn encode_canonical(
            &self,
            _package: &TargetPackage,
            _limits: TargetDecodeLimits,
            _is_cancelled: &dyn Fn() -> bool,
        ) -> Result<Vec<u8>, TargetDecodeError> {
            Ok(b"target-v1".to_vec())
        }
    }

    #[test]
    fn reference_target_is_internally_consistent() {
        let digest = Sha256Digest::from_bytes([1; 32]);
        let aarch64 = TargetPackage::aarch64_qemu_virt_uefi(digest);
        aarch64.validate().expect("valid AArch64 reference target");
        assert_eq!(aarch64.backend().llvm_triple(), "aarch64-unknown-uefi");
        assert_eq!(aarch64.backend().llvm_cpu(), "cortex-a57");
        assert_eq!(aarch64.backend().llvm_features(), ["+reserve-x18"]);
        assert_eq!(
            aarch64.backend().llvm_data_layout(),
            "e-m:e-i8:8:32-i16:16:32-i64:64-i128:128-n32:64-S128-Fn32"
        );
        assert_eq!(aarch64.backend().coff_machine(), "arm64");
        assert_eq!(
            aarch64.semantic().interrupts().controller(),
            InterruptController::ArmGicV3
        );
        assert!(!aarch64.semantic().interrupts().nested_preemption());
        assert_eq!(
            aarch64.backend().interrupts().vector_table_alignment(),
            2048
        );
        assert!(!aarch64.backend().interrupts().saves_simd());
        assert!(
            aarch64
                .backend()
                .interrupts()
                .cpu_irq_masked_during_handler()
        );
        assert!(aarch64.backend().interrupts().eoi_deactivates());
        assert_eq!(aarch64.semantic().mmio_bindings()[0].base, 0x0a00_0000);
    }

    #[test]
    fn decoded_target_is_bound_to_complete_canonical_input() {
        let digest = Sha256Digest::from_bytes([1; 32]);
        let identity = TargetIdentity::aarch64_qemu_virt_uefi();
        let request = |bytes| TargetDecodeRequest {
            toml_bytes: bytes,
            expected_identity: &identity,
            verified_digest: digest,
            limits: TargetDecodeLimits::standard(),
        };
        decode_and_verify_target_package(&FixtureCodec, request(b"target-v1"), &|| false)
            .expect("canonical target");
        assert_eq!(
            decode_and_verify_target_package(
                &FixtureCodec,
                request(b"target-v1\nignored"),
                &|| false,
            ),
            Err(TargetDecodeError::NonCanonical)
        );
    }
}
