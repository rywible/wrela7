//! Locate and validate components shipped in a wrela distribution.

#![forbid(unsafe_code)]

use std::env;
use std::fmt;
use std::path::{Path, PathBuf};

use wrela_build_model::{LanguageRevision, Sha256Digest, TargetIdentity};

const ROOT_OVERRIDE: &str = "WRELA_TOOLCHAIN_ROOT";
pub const TOOLCHAIN_MANIFEST_SCHEMA: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ToolchainDecodeLimits {
    pub bytes: u64,
    pub string_bytes: u32,
    pub components: u32,
    pub targets: u32,
    pub target_files: u32,
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
        }
    }

    pub fn validate(self) -> Result<(), ToolchainDecodeError> {
        if self.bytes == 0
            || self.string_bytes == 0
            || self.components == 0
            || self.targets == 0
            || self.target_files == 0
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
            backend_protocol: 4,
            target_package: 1,
            semantic_wir: 1,
            flow_wir: 1,
            flow_wir_wire: 1,
            machine_wir: 1,
            runtime_abi: 1,
            image_report: 5,
            test_plan: 1,
            test_report: 1,
            image_scenario: 1,
            test_event: 2,
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
    Aarch64Emulator,
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

/// Decoded, immutable `share/wrela/toolchain.toml` contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolchainManifest {
    pub schema: u32,
    pub release: String,
    pub host: String,
    /// LLVM and LLD are built from this one pinned llvm-project revision.
    pub llvm_project_revision: String,
    pub compatibility: ToolchainCompatibility,
    /// Strictly sorted by `(kind, path)` and duplicate-free.
    pub components: Vec<ShippedComponent>,
    /// Strictly sorted by target identity and duplicate-free.
    pub targets: Vec<ShippedTarget>,
}

/// Digests observed by the driver after hashing every declared installation
/// path. The vectors use the manifest's exact canonical order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedInstallation {
    pub components: Vec<ShippedComponent>,
    pub targets: Vec<ShippedTarget>,
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

    pub fn aarch64_emulator(&self) -> Result<VerifiedPath, ManifestError> {
        self.component(ComponentKind::Aarch64Emulator)
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
        if self.components.len() != 4 {
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
            ComponentKind::Aarch64Emulator,
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
        if self.components.iter().any(|component| component.bytes == 0) {
            return Err(ManifestError::InvalidComponentMeasurement);
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
                || target.files.is_empty()
                || !target
                    .files
                    .windows(2)
                    .all(|pair| pair[0].path < pair[1].path)
                || target.files.iter().any(|file| file.bytes == 0)
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
    NonCanonicalComponents,
    MissingOrUnexpectedTarget,
    NonCanonicalTargets,
    MissingTarget(TargetIdentity),
    MissingTargetFile(String),
    InvalidComponentMeasurement,
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
                "toolchain must contain exactly one frontend, backend, standard library, and AArch64 emulator",
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

/// Filesystem layout of one atomic wrela toolchain installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Toolchain {
    root: PathBuf,
}

impl Toolchain {
    /// Seal a compatible, content-verified installation for consumers. Hashing
    /// itself remains a driver capability; this method checks its complete,
    /// canonical evidence against the decoded manifest.
    pub fn verify(
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

    /// Bundled, digest-checked emulator for AArch64 full-image tests.
    #[must_use]
    pub fn aarch64_emulator(&self) -> PathBuf {
        self.root
            .join("libexec")
            .join("wrela")
            .join(executable_name("qemu-system-aarch64"))
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
            ComponentCheck::new("AArch64 emulator", self.aarch64_emulator()),
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

    use super::{
        ComponentKind, ComponentPath, ObservedInstallation, ShippedComponent, ShippedTarget,
        ShippedTargetFile, TOOLCHAIN_MANIFEST_SCHEMA, Toolchain, ToolchainCompatibility,
        ToolchainDecodeError, ToolchainDecodeLimits, ToolchainDecodeRequest, ToolchainManifest,
        ToolchainManifestCodec, decode_and_verify_toolchain_manifest,
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
                ShippedComponent {
                    kind: ComponentKind::Aarch64Emulator,
                    path: ComponentPath::new("libexec/wrela/qemu-system-aarch64")
                        .expect("emulator path"),
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
                files: vec![
                    ShippedTargetFile {
                        path: ComponentPath::new("firmware/QEMU_EFI.fd")
                            .expect("firmware code path"),
                        digest,
                        bytes: 1,
                    },
                    ShippedTargetFile {
                        path: ComponentPath::new("firmware/QEMU_VARS.fd")
                            .expect("firmware variables path"),
                        digest,
                        bytes: 1,
                    },
                    ShippedTargetFile {
                        path: ComponentPath::new("runtime/wrela-runtime-aarch64.obj")
                            .expect("runtime object path"),
                        digest,
                        bytes: 1,
                    },
                ],
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
                .aarch64_emulator()
                .expect("emulator component")
                .digest,
            digest
        );
        assert!(ComponentPath::new("../bin/wrela").is_err());

        let incompatible = ToolchainCompatibility {
            backend_protocol: 5,
            ..compatibility
        };
        assert!(manifest.validate(&incompatible).is_err());
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
}
