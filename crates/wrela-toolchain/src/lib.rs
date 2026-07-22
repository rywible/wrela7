//! Locate and validate components shipped in a wrela distribution.

#![forbid(unsafe_code)]

use std::env;
use std::fmt;
use std::path::{Path, PathBuf};

use wrela_build_model::{LanguageRevision, Sha256Digest, TargetIdentity};
use wrela_package::{PackageIdentity, PackageLocator};

mod codec;
mod local;

pub use codec::CanonicalToolchainManifestCodec;
pub use local::{
    LocalToolchainVerification, LocalToolchainVerificationError, LocalToolchainVerificationLimits,
    LocalToolchainVerifier,
};

const ROOT_OVERRIDE: &str = "WRELA_TOOLCHAIN_ROOT";
pub const TOOLCHAIN_MANIFEST_SCHEMA: u32 = 1;
pub const REQUIRED_LLVM_PROJECT_REVISION: &str = "llvmorg-22.1.3";
/// Maximum package records committed by one revision-0.1 standard-library
/// component. The byte codec can select a smaller request-local limit.
pub const MAX_STANDARD_LIBRARY_PACKAGES: usize = 4096;

/// Exact Rust host triple admitted by a local revision-0.1 installation.
/// Unsupported build targets return `None` rather than guessing from a
/// manifest-controlled string.
#[must_use]
pub const fn current_host_identity() -> Option<&'static str> {
    if cfg!(all(target_arch = "aarch64", target_os = "macos")) {
        Some("aarch64-apple-darwin")
    } else if cfg!(all(target_arch = "x86_64", target_os = "macos")) {
        Some("x86_64-apple-darwin")
    } else if cfg!(all(
        target_arch = "aarch64",
        target_os = "linux",
        target_env = "gnu"
    )) {
        Some("aarch64-unknown-linux-gnu")
    } else if cfg!(all(
        target_arch = "x86_64",
        target_os = "linux",
        target_env = "gnu"
    )) {
        Some("x86_64-unknown-linux-gnu")
    } else if cfg!(all(
        target_arch = "aarch64",
        target_os = "linux",
        target_env = "musl"
    )) {
        Some("aarch64-unknown-linux-musl")
    } else if cfg!(all(
        target_arch = "x86_64",
        target_os = "linux",
        target_env = "musl"
    )) {
        Some("x86_64-unknown-linux-musl")
    } else if cfg!(all(
        target_arch = "aarch64",
        target_os = "windows",
        target_env = "msvc"
    )) {
        Some("aarch64-pc-windows-msvc")
    } else if cfg!(all(
        target_arch = "x86_64",
        target_os = "windows",
        target_env = "msvc"
    )) {
        Some("x86_64-pc-windows-msvc")
    } else if cfg!(all(
        target_arch = "x86_64",
        target_os = "windows",
        target_env = "gnu"
    )) {
        Some("x86_64-pc-windows-gnu")
    } else {
        None
    }
}

const QEMU_ENV_OVERRIDE: &str = "WRELA_QEMU";
const QEMU_FIRMWARE_CODE_ENV_OVERRIDE: &str = "WRELA_QEMU_FIRMWARE_CODE";
const QEMU_FIRMWARE_VARS_ENV_OVERRIDE: &str = "WRELA_QEMU_FIRMWARE_VARS";
const QEMU_BINARY_NAME: &str = "qemu-system-aarch64";
const QEMU_HOMEBREW_DEFAULT: &str = "/opt/homebrew/bin/qemu-system-aarch64";
const QEMU_FIRMWARE_CODE_HOMEBREW_DEFAULT: &str = "/opt/homebrew/share/qemu/edk2-aarch64-code.fd";
const QEMU_FIRMWARE_VARS_HOMEBREW_DEFAULT: &str = "/opt/homebrew/share/qemu/edk2-arm-vars.fd";

/// System `qemu-system-aarch64` binary, resolved from `WRELA_QEMU` if set,
/// otherwise located on `PATH`, otherwise the Homebrew default install
/// location. Total: always returns a path without verifying it exists.
#[must_use]
pub fn system_qemu() -> PathBuf {
    resolve_qemu_binary(env::var_os(QEMU_ENV_OVERRIDE), env::var_os("PATH"))
}

fn resolve_qemu_binary(
    override_value: Option<std::ffi::OsString>,
    path_value: Option<std::ffi::OsString>,
) -> PathBuf {
    if let Some(path) = override_value {
        return PathBuf::from(path);
    }
    if let Some(path) = path_value {
        for directory in env::split_paths(&path) {
            let candidate = directory.join(QEMU_BINARY_NAME);
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    PathBuf::from(QEMU_HOMEBREW_DEFAULT)
}

/// System EDK2 AArch64 code firmware, resolved from
/// `WRELA_QEMU_FIRMWARE_CODE` if set, otherwise the Homebrew default install
/// location. Total: always returns a path without verifying it exists.
#[must_use]
pub fn system_firmware_code() -> PathBuf {
    resolve_override_or_default(
        env::var_os(QEMU_FIRMWARE_CODE_ENV_OVERRIDE),
        QEMU_FIRMWARE_CODE_HOMEBREW_DEFAULT,
    )
}

/// System EDK2 AArch64 variable store, resolved from
/// `WRELA_QEMU_FIRMWARE_VARS` if set, otherwise the Homebrew default install
/// location. Total: always returns a path without verifying it exists.
#[must_use]
pub fn system_firmware_vars() -> PathBuf {
    resolve_override_or_default(
        env::var_os(QEMU_FIRMWARE_VARS_ENV_OVERRIDE),
        QEMU_FIRMWARE_VARS_HOMEBREW_DEFAULT,
    )
}

fn resolve_override_or_default(
    override_value: Option<std::ffi::OsString>,
    default: &'static str,
) -> PathBuf {
    override_value.map_or_else(|| PathBuf::from(default), PathBuf::from)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolchainDecodeLimits {
    pub bytes: u64,
    pub string_bytes: u32,
    pub components: u32,
    pub targets: u32,
    pub target_files: u32,
    pub standard_library_packages: u32,
}

impl ToolchainDecodeLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            bytes: 16 * 1024 * 1024,
            string_bytes: 1024 * 1024,
            components: 1024,
            targets: 1024,
            target_files: 16_384,
            standard_library_packages: 4096,
        }
    }

    pub fn validate(self) -> Result<(), ToolchainDecodeError> {
        let hard = Self::standard();
        if self.bytes == 0
            || self.string_bytes == 0
            || self.components == 0
            || self.targets == 0
            || self.target_files == 0
            || self.standard_library_packages == 0
            || self.bytes > hard.bytes
            || self.string_bytes > hard.string_bytes
            || self.components > hard.components
            || self.targets > hard.targets
            || self.target_files > hard.target_files
            || self.standard_library_packages > hard.standard_library_packages
        {
            Err(ToolchainDecodeError::InvalidLimits)
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
pub struct ToolchainDecodeRequest<'a> {
    pub bytes: &'a [u8],
    pub limits: ToolchainDecodeLimits,
    pub required: &'a ToolchainCompatibility,
}

/// Canonical toolchain-manifest codec. The decoder rejects duplicate/unknown
/// TOML fields and applies all allocation limits before returning a manifest.
pub trait ToolchainManifestCodec {
    fn decode(
        &self,
        request: ToolchainDecodeRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<ToolchainManifest, ToolchainDecodeError>;

    fn encode_canonical(
        &self,
        manifest: &ToolchainManifest,
        limits: ToolchainDecodeLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, ToolchainDecodeError>;
}

pub fn decode_and_verify_toolchain_manifest(
    codec: &dyn ToolchainManifestCodec,
    request: ToolchainDecodeRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<ToolchainManifest, ToolchainDecodeError> {
    if is_cancelled() {
        return Err(ToolchainDecodeError::Cancelled);
    }
    request.limits.validate()?;
    let bytes = u64::try_from(request.bytes.len()).map_err(|_| ToolchainDecodeError::TooLarge {
        limit: request.limits.bytes,
        actual: u64::MAX,
    })?;
    if bytes > request.limits.bytes {
        return Err(ToolchainDecodeError::TooLarge {
            limit: request.limits.bytes,
            actual: bytes,
        });
    }
    let input = request.bytes;
    let required = request.required.clone();
    let limits = request.limits;
    let manifest = codec.decode(request, is_cancelled)?;
    if is_cancelled() {
        return Err(ToolchainDecodeError::Cancelled);
    }
    manifest
        .validate(&required)
        .map_err(ToolchainDecodeError::InvalidManifest)?;
    if codec.encode_canonical(&manifest, limits, is_cancelled)? != input {
        return Err(ToolchainDecodeError::NonCanonical);
    }
    if is_cancelled() {
        return Err(ToolchainDecodeError::Cancelled);
    }
    Ok(manifest)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToolchainDecodeError {
    Cancelled,
    InvalidLimits,
    TooLarge { limit: u64, actual: u64 },
    InvalidUtf8,
    Malformed { byte_offset: usize, message: String },
    MissingField(String),
    DuplicateKey(String),
    UnknownField(String),
    NonCanonical,
    ResourceLimit { resource: &'static str, limit: u64 },
    InvalidManifest(ManifestError),
}

impl fmt::Display for ToolchainDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("toolchain manifest decoding was cancelled"),
            Self::InvalidLimits => formatter.write_str("toolchain decode limits must be nonzero"),
            Self::TooLarge { limit, actual } => {
                write!(
                    formatter,
                    "toolchain manifest has {actual} bytes, exceeding {limit}"
                )
            }
            Self::InvalidUtf8 => formatter.write_str("toolchain manifest is not UTF-8"),
            Self::Malformed {
                byte_offset,
                message,
            } => write!(
                formatter,
                "malformed toolchain manifest at byte {byte_offset}: {message}"
            ),
            Self::MissingField(field) => {
                write!(formatter, "toolchain manifest is missing field {field}")
            }
            Self::DuplicateKey(key) => write!(formatter, "duplicate toolchain key {key}"),
            Self::UnknownField(field) => write!(formatter, "unknown toolchain field {field}"),
            Self::NonCanonical => formatter.write_str(
                "toolchain manifest bytes are not the canonical encoding of the decoded manifest",
            ),
            Self::ResourceLimit { resource, limit } => write!(
                formatter,
                "toolchain manifest exceeded {resource} limit {limit}"
            ),
            Self::InvalidManifest(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ToolchainDecodeError {}

/// Version tuple that must agree across one atomic distribution. Model
/// versions are listed separately so a mixed frontend/backend/runtime/test
/// installation is rejected before any artifact is decoded or executed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolchainCompatibility {
    pub language: LanguageRevision,
    pub build_profile_encoding: u32,
    pub backend_protocol: u32,
    pub target_package: u32,
    pub semantic_wir: u32,
    pub flow_wir: u32,
    pub flow_wir_wire: u32,
    pub machine_wir: u32,
    pub runtime_abi: u32,
    pub image_report: u32,
    pub test_plan: u32,
    pub test_report: u32,
    pub image_scenario: u32,
    pub test_event: u32,
    pub test_frame: u32,
}

impl ToolchainCompatibility {
    /// Compatibility tuple for this compiler build. This is the sole call site
    /// consumers use when verifying an installation; individual phases do not
    /// reconstruct or partially compare the tuple.
    #[must_use]
    pub const fn current() -> Self {
        Self {
            language: LanguageRevision::Design0_1,
            build_profile_encoding: 2,
            backend_protocol: 5,
            target_package: 1,
            semantic_wir: 15,
            flow_wir: 19,
            flow_wir_wire: 19,
            machine_wir: 20,
            runtime_abi: 2,
            image_report: 17,
            test_plan: 2,
            test_report: 2,
            image_scenario: 1,
            test_event: 3,
            test_frame: 1,
        }
    }
}

/// Required content-addressed installation component.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ComponentKind {
    Frontend,
    Backend,
    StandardLibrary,
}

/// Validated portable path relative to the toolchain root.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ComponentPath(String);

impl ComponentPath {
    pub fn new(value: impl Into<String>) -> Result<Self, ManifestError> {
        let value = value.into();
        validate_relative_path(&value)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One non-target component pinned by exact contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShippedComponent {
    pub kind: ComponentKind,
    pub path: ComponentPath,
    pub digest: Sha256Digest,
    pub bytes: u64,
}

/// One target-relative runtime or firmware file whose exact bytes are part of
/// the installed target capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShippedTargetFile {
    pub path: ComponentPath,
    pub digest: Sha256Digest,
    pub bytes: u64,
}

/// One installed target package pinned by identity and exact contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShippedTarget {
    pub identity: TargetIdentity,
    pub path: ComponentPath,
    pub digest: Sha256Digest,
    pub bytes: u64,
    /// Strict target-relative path order. For revision 0.1 this includes the
    /// runtime COFF object and both firmware images.
    pub files: Vec<ShippedTargetFile>,
}

/// One package declared inside the content-verified standard-library
/// component. Identity and canonical manifest bytes are independently pinned;
/// the locator is retained as [`PackageLocator`] so consumers compare the
/// loaded package without reconstructing a second locator representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShippedStandardLibraryPackage {
    pub identity: PackageIdentity,
    pub locator: PackageLocator,
    pub manifest_digest: Sha256Digest,
}

/// Decoded, immutable `share/wrela/toolchain.toml` contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolchainManifest {
    pub schema: u32,
    pub release: String,
    pub host: String,
    /// LLVM and LLD are built from this one pinned llvm-project revision.
    pub llvm_project_revision: String,
    pub compatibility: ToolchainCompatibility,
    /// Nonempty, strictly identity- and component-ordered package index for
    /// the exact standard-library component committed by this manifest.
    pub standard_library_packages: Vec<ShippedStandardLibraryPackage>,
    /// Strictly sorted by `(kind, path)` and duplicate-free.
    pub components: Vec<ShippedComponent>,
    /// Strictly sorted by target identity and duplicate-free.
    pub targets: Vec<ShippedTarget>,
}

/// Read-only measurements produced by the crate-owned filesystem verifier
/// after hashing every declared installation path. Private fields prevent a
/// caller from turning manifest claims into verification evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedInstallation {
    components: Vec<ShippedComponent>,
    targets: Vec<ShippedTarget>,
}

impl ObservedInstallation {
    #[must_use]
    pub fn components(&self) -> &[ShippedComponent] {
        &self.components
    }

    #[must_use]
    pub fn targets(&self) -> &[ShippedTarget] {
        &self.targets
    }
}

/// One content-verified path from an atomic toolchain installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPath {
    path: PathBuf,
    digest: Sha256Digest,
    bytes: u64,
}

impl VerifiedPath {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub const fn digest(&self) -> Sha256Digest {
        self.digest
    }

    #[must_use]
    pub const fn bytes(&self) -> u64 {
        self.bytes
    }
}

/// Toolchain capability handed to backend and test consumers only after the
/// manifest is compatible and every declared component digest was observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedToolchain {
    root: PathBuf,
    manifest: ToolchainManifest,
}

impl VerifiedToolchain {
    #[must_use]
    pub fn manifest(&self) -> &ToolchainManifest {
        &self.manifest
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn component(&self, kind: ComponentKind) -> Result<VerifiedPath, ManifestError> {
        let component = self
            .manifest
            .components
            .iter()
            .find(|component| component.kind == kind)
            .ok_or(ManifestError::MissingOrDuplicateComponent)?;
        Ok(VerifiedPath {
            path: self.root.join(component.path.as_str()),
            digest: component.digest,
            bytes: component.bytes,
        })
    }

    pub fn target(&self, identity: &TargetIdentity) -> Result<VerifiedPath, ManifestError> {
        let target = self
            .manifest
            .targets
            .binary_search_by(|target| target.identity.cmp(identity))
            .ok()
            .map(|index| &self.manifest.targets[index])
            .ok_or_else(|| ManifestError::MissingTarget(identity.clone()))?;
        Ok(VerifiedPath {
            path: self.root.join(target.path.as_str()),
            digest: target.digest,
            bytes: target.bytes,
        })
    }

    pub fn target_file(
        &self,
        identity: &TargetIdentity,
        relative_path: &str,
    ) -> Result<VerifiedPath, ManifestError> {
        validate_relative_path(relative_path)?;
        let target = self
            .manifest
            .targets
            .binary_search_by(|target| target.identity.cmp(identity))
            .ok()
            .map(|index| &self.manifest.targets[index])
            .ok_or_else(|| ManifestError::MissingTarget(identity.clone()))?;
        let file = target
            .files
            .binary_search_by(|file| file.path.as_str().cmp(relative_path))
            .ok()
            .map(|index| &target.files[index])
            .ok_or_else(|| ManifestError::MissingTargetFile(relative_path.to_owned()))?;
        Ok(VerifiedPath {
            path: self
                .root
                .join(target.path.as_str())
                .join(file.path.as_str()),
            digest: file.digest,
            bytes: file.bytes,
        })
    }

    pub fn backend(&self) -> Result<VerifiedPath, ManifestError> {
        self.component(ComponentKind::Backend)
    }

    pub fn standard_library(&self) -> Result<VerifiedPath, ManifestError> {
        self.component(ComponentKind::StandardLibrary)
    }

    /// Canonical package index committed by the verified standard-library
    /// component.
    #[must_use]
    pub fn standard_library_packages(&self) -> &[ShippedStandardLibraryPackage] {
        &self.manifest.standard_library_packages
    }

    /// Look up one exact shipped package identity without accepting a name-
    /// only or version-only substitution.
    #[must_use]
    pub fn standard_library_package(
        &self,
        identity: &PackageIdentity,
    ) -> Option<&ShippedStandardLibraryPackage> {
        self.manifest
            .standard_library_packages
            .binary_search_by(|package| package.identity.cmp(identity))
            .ok()
            .map(|index| &self.manifest.standard_library_packages[index])
    }
}

impl ToolchainManifest {
    /// Reject an incomplete, mixed-release, or noncanonical manifest before
    /// any component path is trusted.
    pub fn validate(&self, required: &ToolchainCompatibility) -> Result<(), ManifestError> {
        if self.schema != TOOLCHAIN_MANIFEST_SCHEMA {
            return Err(ManifestError::UnsupportedSchema(self.schema));
        }
        for (field, value) in [
            ("release", self.release.as_str()),
            ("host", self.host.as_str()),
            ("llvm-project revision", self.llvm_project_revision.as_str()),
        ] {
            validate_manifest_atom(value)
                .map_err(|reason| ManifestError::InvalidField { field, reason })?;
        }
        if &self.compatibility != required {
            return Err(ManifestError::IncompatibleVersion {
                installed: self.compatibility.clone(),
                required: required.clone(),
            });
        }
        if self.standard_library_packages.is_empty()
            || self.standard_library_packages.len() > MAX_STANDARD_LIBRARY_PACKAGES
            || !self
                .standard_library_packages
                .windows(2)
                .all(|pair| pair[0].identity < pair[1].identity)
            || standard_library_components_are_duplicated(&self.standard_library_packages)
            || self
                .standard_library_packages
                .iter()
                .any(|package| !valid_standard_library_package(package))
        {
            return Err(ManifestError::InvalidStandardLibraryPackages);
        }
        if self.components.len() != 3 {
            return Err(ManifestError::MissingOrDuplicateComponent);
        }
        if !self
            .components
            .windows(2)
            .all(|pair| (&pair[0].kind, &pair[0].path) < (&pair[1].kind, &pair[1].path))
        {
            return Err(ManifestError::NonCanonicalComponents);
        }
        for required_kind in [
            ComponentKind::Frontend,
            ComponentKind::Backend,
            ComponentKind::StandardLibrary,
        ] {
            if self
                .components
                .iter()
                .filter(|component| component.kind == required_kind)
                .count()
                != 1
            {
                return Err(ManifestError::MissingOrDuplicateComponent);
            }
        }
        if self
            .components
            .iter()
            .any(|component| component.bytes == 0 || !digest_is_nonzero(component.digest))
        {
            return Err(ManifestError::InvalidComponentMeasurement);
        }
        let windows_host = self.host.split('-').any(|component| component == "windows");
        if self.components.iter().any(|component| {
            component.path.as_str() != expected_component_path(component.kind, windows_host)
        }) {
            return Err(ManifestError::UnexpectedComponentLayout);
        }
        if self.targets.len() != 1
            || self.targets[0].identity != TargetIdentity::aarch64_qemu_virt_uefi()
        {
            return Err(ManifestError::MissingOrUnexpectedTarget);
        }
        if !self
            .targets
            .windows(2)
            .all(|pair| pair[0].identity < pair[1].identity)
        {
            return Err(ManifestError::NonCanonicalTargets);
        }
        if self.targets.iter().any(|target| {
            target.bytes == 0
                || !digest_is_nonzero(target.digest)
                || target.path.as_str() != "share/wrela/targets/aarch64-qemu-virt-uefi"
                || target.files.len() != REQUIRED_TARGET_FILES.len()
                || !target
                    .files
                    .windows(2)
                    .all(|pair| pair[0].path < pair[1].path)
                || target
                    .files
                    .iter()
                    .any(|file| file.bytes == 0 || !digest_is_nonzero(file.digest))
                || target
                    .files
                    .iter()
                    .zip(REQUIRED_TARGET_FILES)
                    .any(|(file, required)| file.path.as_str() != required)
        }) {
            return Err(ManifestError::InvalidTargetFiles);
        }
        Ok(())
    }
}

/// Invalid decoded toolchain manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    Cancelled,
    UnsupportedSchema(u32),
    InvalidField {
        field: &'static str,
        reason: String,
    },
    InvalidComponentPath(String),
    IncompatibleVersion {
        installed: ToolchainCompatibility,
        required: ToolchainCompatibility,
    },
    MissingOrDuplicateComponent,
    InvalidStandardLibraryPackages,
    NonCanonicalComponents,
    MissingOrUnexpectedTarget,
    NonCanonicalTargets,
    MissingTarget(TargetIdentity),
    MissingTargetFile(String),
    InvalidComponentMeasurement,
    UnexpectedComponentLayout,
    InvalidTargetFiles,
    ObservedInstallationMismatch,
}

impl fmt::Display for ManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("toolchain verification was cancelled"),
            Self::UnsupportedSchema(schema) => {
                write!(formatter, "unsupported toolchain manifest schema {schema}")
            }
            Self::InvalidField { field, reason } => {
                write!(formatter, "invalid toolchain {field}: {reason}")
            }
            Self::InvalidComponentPath(reason) => {
                write!(formatter, "invalid toolchain component path: {reason}")
            }
            Self::IncompatibleVersion { .. } => {
                formatter.write_str("installed toolchain versions do not match this frontend")
            }
            Self::MissingOrDuplicateComponent => formatter.write_str(
                "toolchain must contain exactly one frontend, backend, and standard library",
            ),
            Self::InvalidStandardLibraryPackages => formatter.write_str(
                "toolchain standard-library package index is empty, invalid, duplicated, or noncanonical",
            ),
            Self::NonCanonicalComponents => {
                formatter.write_str("toolchain components are not strictly sorted")
            }
            Self::MissingOrUnexpectedTarget => formatter.write_str(
                "revision 0.1 toolchain must contain exactly the AArch64 QEMU virt UEFI target",
            ),
            Self::NonCanonicalTargets => {
                formatter.write_str("toolchain targets are not strictly sorted and unique")
            }
            Self::MissingTarget(identity) => {
                write!(
                    formatter,
                    "toolchain does not contain target {}",
                    identity.as_str()
                )
            }
            Self::MissingTargetFile(path) => {
                write!(formatter, "toolchain target does not contain component {path}")
            }
            Self::InvalidComponentMeasurement => {
                formatter.write_str("toolchain component has a zero byte measurement")
            }
            Self::UnexpectedComponentLayout => formatter.write_str(
                "toolchain components do not use the fixed revision 0.1 installation layout",
            ),
            Self::InvalidTargetFiles => formatter.write_str(
                "toolchain target files are empty, zero-sized, duplicated, or noncanonical",
            ),
            Self::ObservedInstallationMismatch => formatter.write_str(
                "observed toolchain component digests do not match the manifest",
            ),
        }
    }
}

impl std::error::Error for ManifestError {}

fn validate_manifest_atom(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("value is empty".to_owned());
    }
    if value.len() > 4096 {
        return Err("value exceeds 4096 UTF-8 bytes".to_owned());
    }
    if let Some(character) = value
        .chars()
        .find(|character| character.is_control() || character.is_whitespace())
    {
        return Err(format!("forbidden character {character:?}"));
    }
    Ok(())
}

fn validate_relative_path(value: &str) -> Result<(), ManifestError> {
    if value.is_empty()
        || value.len() > 4096
        || value.starts_with('/')
        || value.starts_with('\\')
        || value
            .chars()
            .any(|character| matches!(character, '\\' | ':'))
        || value
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(ManifestError::InvalidComponentPath(value.to_owned()));
    }
    Ok(())
}

fn toolchain_locator_component(locator: &PackageLocator) -> Option<&str> {
    match locator {
        PackageLocator::Toolchain { component } => Some(component),
        PackageLocator::Workspace { .. } | PackageLocator::Archive { .. } => None,
    }
}

fn valid_standard_library_package(package: &ShippedStandardLibraryPackage) -> bool {
    let Some(component) = toolchain_locator_component(&package.locator) else {
        return false;
    };
    validate_standard_library_component(component).is_ok()
        && digest_is_nonzero(package.identity.source_digest)
        && digest_is_nonzero(package.manifest_digest)
}

fn validate_standard_library_component(value: &str) -> Result<(), ManifestError> {
    const MAX_BYTES: usize = 255;
    if value.is_empty()
        || value.len() > MAX_BYTES
        || matches!(value, "." | "..")
        || value.ends_with('.')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || is_windows_reserved_component(value)
    {
        return Err(ManifestError::InvalidComponentPath(value.to_owned()));
    }
    Ok(())
}

fn is_windows_reserved_component(value: &str) -> bool {
    let basename = value.split('.').next().unwrap_or(value);
    if ["CON", "PRN", "AUX", "NUL"]
        .iter()
        .any(|reserved| basename.eq_ignore_ascii_case(reserved))
    {
        return true;
    }
    let bytes = basename.as_bytes();
    bytes.len() == 4
        && (bytes[..3].eq_ignore_ascii_case(b"COM") || bytes[..3].eq_ignore_ascii_case(b"LPT"))
        && matches!(bytes[3], b'1'..=b'9')
}

fn standard_library_components_are_duplicated(packages: &[ShippedStandardLibraryPackage]) -> bool {
    packages.iter().enumerate().any(|(index, package)| {
        let component = toolchain_locator_component(&package.locator);
        packages[index + 1..]
            .iter()
            .any(|candidate| toolchain_locator_component(&candidate.locator) == component)
    })
}

fn digest_is_nonzero(digest: Sha256Digest) -> bool {
    digest.as_bytes().iter().any(|byte| *byte != 0)
}

const REQUIRED_TARGET_FILES: [&str; 1] = ["runtime/wrela-runtime-aarch64.obj"];

const fn expected_component_path(kind: ComponentKind, windows_host: bool) -> &'static str {
    match (kind, windows_host) {
        (ComponentKind::Frontend, false) => "bin/wrela",
        (ComponentKind::Frontend, true) => "bin/wrela.exe",
        (ComponentKind::Backend, false) => "libexec/wrela/wrela-backend",
        (ComponentKind::Backend, true) => "libexec/wrela/wrela-backend.exe",
        (ComponentKind::StandardLibrary, _) => "share/wrela/std",
    }
}

/// Filesystem layout of one atomic wrela toolchain installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Toolchain {
    root: PathBuf,
}

impl Toolchain {
    /// Private seal used only after this crate's concrete observer has hashed
    /// and revalidated the complete installation.
    pub(crate) fn verify(
        self,
        manifest: ToolchainManifest,
        required: &ToolchainCompatibility,
        observed: ObservedInstallation,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<VerifiedToolchain, ManifestError> {
        if is_cancelled() {
            return Err(ManifestError::Cancelled);
        }
        manifest.validate(required)?;
        if observed.components != manifest.components || observed.targets != manifest.targets {
            return Err(ManifestError::ObservedInstallationMismatch);
        }
        if is_cancelled() {
            return Err(ManifestError::Cancelled);
        }
        Ok(VerifiedToolchain {
            root: self.root,
            manifest,
        })
    }

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

    /// Selected installed target directory. The caller must first match its
    /// identity and digest against a validated [`ToolchainManifest`].
    #[must_use]
    pub fn target(&self, identity: &TargetIdentity) -> PathBuf {
        self.root
            .join("share/wrela/targets")
            .join(identity.as_str())
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

    use wrela_build_model::{Sha256Digest, TargetIdentity};
    use wrela_package::{PackageIdentity, PackageLocator, PackageName, PackageVersion};

    use super::{
        ComponentKind, ComponentPath, ObservedInstallation, ShippedComponent,
        ShippedStandardLibraryPackage, ShippedTarget, ShippedTargetFile, TOOLCHAIN_MANIFEST_SCHEMA,
        Toolchain, ToolchainCompatibility, ToolchainDecodeError, ToolchainDecodeLimits,
        ToolchainDecodeRequest, ToolchainManifest, ToolchainManifestCodec,
        decode_and_verify_toolchain_manifest,
    };

    fn fixture_manifest() -> (ToolchainManifest, ToolchainCompatibility, Sha256Digest) {
        let compatibility = ToolchainCompatibility::current();
        let digest = Sha256Digest::from_bytes([1; 32]);
        let manifest = ToolchainManifest {
            schema: TOOLCHAIN_MANIFEST_SCHEMA,
            release: "0.1.0".to_owned(),
            host: "aarch64-apple-darwin".to_owned(),
            llvm_project_revision: "llvmorg-22.1.0".to_owned(),
            compatibility: compatibility.clone(),
            standard_library_packages: vec![ShippedStandardLibraryPackage {
                identity: PackageIdentity {
                    name: PackageName::new("wrela-core").expect("standard-library name"),
                    version: PackageVersion::new("0.1.0").expect("standard-library version"),
                    source_digest: digest,
                },
                locator: PackageLocator::Toolchain {
                    component: "wrela-core-0.1".to_owned(),
                },
                manifest_digest: digest,
            }],
            components: vec![
                ShippedComponent {
                    kind: ComponentKind::Frontend,
                    path: ComponentPath::new("bin/wrela").expect("frontend path"),
                    digest,
                    bytes: 1,
                },
                ShippedComponent {
                    kind: ComponentKind::Backend,
                    path: ComponentPath::new("libexec/wrela/wrela-backend").expect("backend path"),
                    digest,
                    bytes: 1,
                },
                ShippedComponent {
                    kind: ComponentKind::StandardLibrary,
                    path: ComponentPath::new("share/wrela/std").expect("standard library path"),
                    digest,
                    bytes: 1,
                },
            ],
            targets: vec![ShippedTarget {
                identity: TargetIdentity::aarch64_qemu_virt_uefi(),
                path: ComponentPath::new("share/wrela/targets/aarch64-qemu-virt-uefi")
                    .expect("AArch64 target path"),
                digest,
                bytes: 3,
                files: vec![ShippedTargetFile {
                    path: ComponentPath::new("runtime/wrela-runtime-aarch64.obj")
                        .expect("runtime object path"),
                    digest,
                    bytes: 1,
                }],
            }],
        };
        (manifest, compatibility, digest)
    }

    struct FixtureCodec {
        manifest: ToolchainManifest,
    }

    impl ToolchainManifestCodec for FixtureCodec {
        fn decode(
            &self,
            _request: ToolchainDecodeRequest<'_>,
            _is_cancelled: &dyn Fn() -> bool,
        ) -> Result<ToolchainManifest, ToolchainDecodeError> {
            Ok(self.manifest.clone())
        }

        fn encode_canonical(
            &self,
            _manifest: &ToolchainManifest,
            _limits: ToolchainDecodeLimits,
            _is_cancelled: &dyn Fn() -> bool,
        ) -> Result<Vec<u8>, ToolchainDecodeError> {
            Ok(b"toolchain-v1".to_vec())
        }
    }

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

    #[test]
    fn manifest_contract_rejects_mixed_or_escaping_installations() {
        let (manifest, compatibility, digest) = fixture_manifest();

        manifest
            .validate(&compatibility)
            .expect("compatible manifest");
        let observed = ObservedInstallation {
            components: manifest.components.clone(),
            targets: manifest.targets.clone(),
        };
        let verified = Toolchain::at("/opt/wrela")
            .verify(manifest.clone(), &compatibility, observed, &|| false)
            .expect("verified installation");
        assert_eq!(
            verified
                .component(ComponentKind::Backend)
                .expect("backend component")
                .digest,
            digest
        );
        assert!(ComponentPath::new("../bin/wrela").is_err());

        let incompatible = ToolchainCompatibility {
            backend_protocol: 4,
            ..compatibility.clone()
        };
        assert!(manifest.validate(&incompatible).is_err());
        for machine_wir in [19, 21] {
            let incompatible = ToolchainCompatibility {
                machine_wir,
                ..compatibility.clone()
            };
            assert!(
                manifest.validate(&incompatible).is_err(),
                "MachineWir {machine_wir} must not cross the exact v20 distribution boundary"
            );
        }
    }

    #[test]
    fn decoded_manifest_is_bound_to_complete_canonical_input() {
        let (manifest, compatibility, _) = fixture_manifest();
        let codec = FixtureCodec { manifest };
        let request = |bytes| ToolchainDecodeRequest {
            bytes,
            limits: ToolchainDecodeLimits::standard(),
            required: &compatibility,
        };
        decode_and_verify_toolchain_manifest(&codec, request(b"toolchain-v1"), &|| false)
            .expect("canonical manifest");
        assert_eq!(
            decode_and_verify_toolchain_manifest(
                &codec,
                request(b"toolchain-v1\nignored"),
                &|| false,
            ),
            Err(ToolchainDecodeError::NonCanonical)
        );
    }

    #[test]
    fn system_qemu_env_override_takes_precedence_over_path_search() {
        use std::ffi::OsString;
        use std::path::PathBuf;

        use super::resolve_qemu_binary;

        let overridden = resolve_qemu_binary(
            Some(OsString::from("/custom/qemu-system-aarch64")),
            Some(OsString::from("/usr/bin:/bin")),
        );
        assert_eq!(
            overridden,
            PathBuf::from("/custom/qemu-system-aarch64"),
            "an explicit WRELA_QEMU override must win over any PATH search"
        );
    }

    #[test]
    fn system_firmware_env_overrides_take_precedence_over_defaults() {
        use std::ffi::OsString;
        use std::path::PathBuf;

        use super::resolve_override_or_default;

        assert_eq!(
            resolve_override_or_default(
                Some(OsString::from("/custom/edk2-code.fd")),
                "/opt/homebrew/share/qemu/edk2-aarch64-code.fd",
            ),
            PathBuf::from("/custom/edk2-code.fd")
        );
        assert_eq!(
            resolve_override_or_default(None, "/opt/homebrew/share/qemu/edk2-aarch64-code.fd"),
            PathBuf::from("/opt/homebrew/share/qemu/edk2-aarch64-code.fd")
        );
    }
}
