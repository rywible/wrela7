//! Concrete local-filesystem verification for one explicit toolchain root.
//!
//! This module uses only path-based `std::fs` operations. It rejects symlinks,
//! revalidates file and directory metadata around every observation, and fails
//! closed when a replacement is visible. It cannot make pathname resolution
//! race-free: an adversary can replace and restore a path between separate
//! standard-library calls. Deployments on hostile filesystems must put the
//! immutable toolchain root behind an OS capability/sandbox or replace this
//! host with an `openat`-style implementation.

use std::env;
use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::fs::MetadataExt;

use crate::{
    CanonicalToolchainManifestCodec, ComponentKind, ManifestError, ObservedInstallation,
    REQUIRED_LLVM_PROJECT_REVISION, ShippedComponent, ShippedTarget, ShippedTargetFile, Toolchain,
    ToolchainCompatibility, ToolchainDecodeError, ToolchainDecodeLimits, ToolchainDecodeRequest,
    ToolchainManifest, VerifiedToolchain, current_host_identity,
    decode_and_verify_toolchain_manifest,
};
use wrela_build_model::{Sha256Digest, TargetIdentity};
use wrela_package::PackageLocator;
use wrela_package_loader::{
    CanonicalTreeDigestError, CanonicalTreeLimits, CanonicalTreeRecord, ContentHasher,
    SoftwareSha256, canonical_tree_digest,
};
use wrela_target::{
    CanonicalTargetPackageCodec, TargetDecodeError, TargetDecodeLimits, TargetDecodeRequest,
    TargetPackage, decode_and_verify_target_package,
};

const READ_CHUNK_BYTES: usize = 64 * 1024;
const MAX_HOST_PATH_BYTES: usize = 64 * 1024;
const MAX_TRAVERSAL_DEPTH: u32 = 256;
const TREE_ENTRY_METADATA_BYTES: u64 = 64;
const TARGET_MANIFEST_PATH: &str = "target.toml";
const PACKAGE_MANIFEST_NAME: &str = "wrela.toml";

/// Finite policy for one complete local installation verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalToolchainVerificationLimits {
    pub toolchain_manifest: ToolchainDecodeLimits,
    pub target_package: TargetDecodeLimits,
    /// Applies to the installation-wide metadata preflight and independently
    /// to each standard-library or target directory. During traversal,
    /// `records`, `path_bytes`, and `metadata_bytes` cover directories as well
    /// as regular files; canonical hashing reapplies the same limits to file
    /// records.
    pub tree: CanonicalTreeLimits,
    pub single_file_bytes: u64,
    /// Maximum relative component count, including a leaf file.
    pub traversal_depth: u32,
}

impl LocalToolchainVerificationLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            toolchain_manifest: ToolchainDecodeLimits::standard(),
            target_package: TargetDecodeLimits::standard(),
            tree: CanonicalTreeLimits::standard(),
            single_file_bytes: 1024 * 1024 * 1024,
            traversal_depth: 64,
        }
    }

    pub fn validate(self) -> Result<(), LocalToolchainVerificationError> {
        self.toolchain_manifest
            .validate()
            .map_err(LocalToolchainVerificationError::ToolchainManifest)?;
        self.target_package
            .validate()
            .map_err(LocalToolchainVerificationError::TargetPackage)?;
        self.tree
            .validate()
            .map_err(LocalToolchainVerificationError::TreeDigest)?;
        if self.single_file_bytes == 0
            || self.single_file_bytes > CanonicalTreeLimits::standard().content_bytes
        {
            return Err(LocalToolchainVerificationError::InvalidLimits(
                "single-file bytes",
            ));
        }
        if self.traversal_depth == 0 || self.traversal_depth > MAX_TRAVERSAL_DEPTH {
            return Err(LocalToolchainVerificationError::InvalidLimits(
                "traversal depth",
            ));
        }
        Ok(())
    }
}

impl Default for LocalToolchainVerificationLimits {
    fn default() -> Self {
        Self::standard()
    }
}

/// Complete evidence and validated products from one immutable observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalToolchainVerification {
    manifest: ToolchainManifest,
    observed: ObservedInstallation,
    toolchain: VerifiedToolchain,
    target: TargetPackage,
    target_manifest: Vec<u8>,
}

impl LocalToolchainVerification {
    #[must_use]
    pub const fn manifest(&self) -> &ToolchainManifest {
        &self.manifest
    }

    #[must_use]
    pub const fn observed(&self) -> &ObservedInstallation {
        &self.observed
    }

    #[must_use]
    pub const fn toolchain(&self) -> &VerifiedToolchain {
        &self.toolchain
    }

    #[must_use]
    pub const fn target(&self) -> &TargetPackage {
        &self.target
    }

    /// Exact `target.toml` bytes retained from the same verified target-tree
    /// observation that produced [`Self::target`]. Consumers that must stage
    /// the private backend input can re-read the installed file and require
    /// byte equality with this capability before copying it.
    #[must_use]
    pub fn target_manifest_bytes(&self) -> &[u8] {
        &self.target_manifest
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        ToolchainManifest,
        ObservedInstallation,
        VerifiedToolchain,
        TargetPackage,
    ) {
        (self.manifest, self.observed, self.toolchain, self.target)
    }

    /// Measure the currently running process image and require its exact bytes
    /// to equal the frontend component in this verified installation. This
    /// prevents an override root from attributing an in-process compilation to
    /// a different compiler binary. As with installation verification, this is
    /// a stable pathname observation rather than an OS-held immutable handle;
    /// hostile deployments must enforce immutable executable paths externally.
    pub fn bind_running_frontend(
        &self,
        maximum_bytes: u64,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Sha256Digest, LocalToolchainVerificationError> {
        if maximum_bytes == 0
            || maximum_bytes > LocalToolchainVerificationLimits::standard().single_file_bytes
        {
            return Err(LocalToolchainVerificationError::InvalidLimits(
                "running frontend bytes",
            ));
        }
        check_cancelled(is_cancelled)?;
        let installed = self
            .toolchain
            .component(ComponentKind::Frontend)
            .map_err(LocalToolchainVerificationError::Manifest)?;
        let executable =
            env::current_exe().map_err(|error| LocalToolchainVerificationError::Io {
                operation: "running executable discovery",
                path: PathBuf::from("<current-executable>"),
                kind: error.kind(),
            })?;
        // The running executable's location is host-controlled (build
        // directories routinely live under symlinked roots such as macOS's
        // `/var` -> `private/var`), so resolve it to its canonical,
        // symlink-free form before applying the stable-read policy. The
        // binding guarantee is the byte/digest equality against the installed
        // frontend component, which canonicalization does not weaken.
        let executable =
            fs::canonicalize(&executable).map_err(|error| LocalToolchainVerificationError::Io {
                operation: "running executable canonicalization",
                path: executable.clone(),
                kind: error.kind(),
            })?;
        let observed = read_stable_file(&executable, maximum_bytes, false, true, is_cancelled)?;
        if observed.bytes != installed.bytes() || observed.digest != installed.digest() {
            return Err(LocalToolchainVerificationError::RunningFrontendMismatch(
                executable,
            ));
        }
        check_cancelled(is_cancelled)?;
        Ok(observed.digest)
    }
}

/// Local verification capability bound to one explicit installation root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalToolchainVerifier {
    toolchain: Toolchain,
}

impl LocalToolchainVerifier {
    #[must_use]
    pub const fn new(toolchain: Toolchain) -> Self {
        Self { toolchain }
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        self.toolchain.root()
    }

    /// Verify every schema-1 component and decode the selected target only
    /// after its complete directory tree agrees with the canonical manifest.
    pub fn verify(
        &self,
        selected_target: &TargetIdentity,
        limits: LocalToolchainVerificationLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<LocalToolchainVerification, LocalToolchainVerificationError> {
        limits.validate()?;
        check_cancelled(is_cancelled)?;
        validate_root_path(self.root(), is_cancelled)?;
        let root_before = directory_snapshot(self.root(), is_cancelled)?;

        let manifest_path = self.toolchain.manifest();
        let manifest_maximum = limits
            .single_file_bytes
            .min(limits.toolchain_manifest.bytes);
        let manifest_file =
            read_stable_file(&manifest_path, manifest_maximum, true, false, is_cancelled)?;
        let manifest_bytes = manifest_file
            .retained
            .as_deref()
            .ok_or(LocalToolchainVerificationError::InternalInvariant)?;
        let compatibility = ToolchainCompatibility::current();
        let manifest = decode_and_verify_toolchain_manifest(
            &CanonicalToolchainManifestCodec::new(),
            ToolchainDecodeRequest {
                bytes: manifest_bytes,
                limits: limits.toolchain_manifest,
                required: &compatibility,
            },
            is_cancelled,
        )
        .map_err(LocalToolchainVerificationError::ToolchainManifest)?;

        let required_host = current_host_identity()
            .ok_or(LocalToolchainVerificationError::UnsupportedCompilerHost)?;
        if manifest.host != required_host {
            return Err(LocalToolchainVerificationError::HostMismatch {
                required: required_host,
                installed: manifest.host.clone(),
            });
        }
        if manifest.llvm_project_revision != REQUIRED_LLVM_PROJECT_REVISION {
            return Err(LocalToolchainVerificationError::LlvmRevisionMismatch {
                required: REQUIRED_LLVM_PROJECT_REVISION,
                installed: manifest.llvm_project_revision.clone(),
            });
        }

        // Components are content-measured below. This metadata-only pass also
        // rejects unsafe entry types in unused distribution directories, so a
        // symlink or device cannot hide merely because schema 1 does not name
        // that optional directory as a build input.
        validate_installation_entries(self.root(), limits, is_cancelled)?;

        if !manifest
            .targets
            .iter()
            .any(|target| &target.identity == selected_target)
        {
            return Err(LocalToolchainVerificationError::TargetNotDeclared(
                selected_target.clone(),
            ));
        }

        let mut observed_components = Vec::new();
        observed_components
            .try_reserve_exact(manifest.components.len())
            .map_err(|_| allocation_error("observed components", limits.tree.records))?;
        for component in &manifest.components {
            check_cancelled(is_cancelled)?;
            let path = join_manifest_path(self.root(), component.path.as_str())?;
            let observed = match component.kind {
                ComponentKind::Frontend | ComponentKind::Backend => {
                    let file = read_stable_file(
                        &path,
                        limits.single_file_bytes,
                        false,
                        true,
                        is_cancelled,
                    )?;
                    ShippedComponent {
                        kind: component.kind,
                        path: component.path.clone(),
                        digest: file.digest,
                        bytes: file.bytes,
                    }
                }
                ComponentKind::StandardLibrary => {
                    let tree = measure_tree(&path, limits, &|_| None, is_cancelled)?;
                    verify_standard_library_index(&manifest, &tree, limits)?;
                    ShippedComponent {
                        kind: component.kind,
                        path: component.path.clone(),
                        digest: tree.measurement.digest,
                        bytes: tree.measurement.content_bytes,
                    }
                }
            };
            if &observed != component {
                return Err(LocalToolchainVerificationError::MeasurementMismatch(path));
            }
            observed_components.push(observed);
        }

        let mut observed_targets = Vec::new();
        observed_targets
            .try_reserve_exact(manifest.targets.len())
            .map_err(|_| allocation_error("observed targets", limits.tree.records))?;
        let mut selected_target_manifest = None;
        for declared in &manifest.targets {
            check_cancelled(is_cancelled)?;
            let path = join_manifest_path(self.root(), declared.path.as_str())?;
            let mut tree = measure_tree(
                &path,
                limits,
                &|relative| {
                    (relative == TARGET_MANIFEST_PATH).then_some(limits.target_package.bytes)
                },
                is_cancelled,
            )?;
            let observed = observe_target(declared, &tree, &path, limits)?;
            if observed.digest != declared.digest || observed.bytes != declared.bytes {
                return Err(LocalToolchainVerificationError::MeasurementMismatch(path));
            }
            if &declared.identity == selected_target {
                selected_target_manifest =
                    Some(tree.take_retained(TARGET_MANIFEST_PATH).ok_or_else(|| {
                        LocalToolchainVerificationError::UnexpectedTargetTree {
                            target: declared.identity.clone(),
                        }
                    })?);
            }
            observed_targets.push(observed);
        }

        let observed = ObservedInstallation {
            components: observed_components,
            targets: observed_targets,
        };
        let verified_toolchain = self
            .toolchain
            .clone()
            .verify(
                manifest.clone(),
                &compatibility,
                observed.clone(),
                is_cancelled,
            )
            .map_err(LocalToolchainVerificationError::Manifest)?;
        let selected_target_manifest =
            selected_target_manifest.ok_or(LocalToolchainVerificationError::InternalInvariant)?;
        let declared_target = manifest
            .targets
            .iter()
            .find(|target| &target.identity == selected_target)
            .ok_or(LocalToolchainVerificationError::InternalInvariant)?;
        let target = decode_and_verify_target_package(
            &CanonicalTargetPackageCodec::new(),
            TargetDecodeRequest {
                toml_bytes: &selected_target_manifest,
                expected_identity: selected_target,
                verified_digest: declared_target.digest,
                limits: limits.target_package,
            },
            is_cancelled,
        )
        .map_err(LocalToolchainVerificationError::TargetPackage)?;

        let root_after = directory_snapshot(self.root(), is_cancelled)?;
        if root_before != root_after {
            return Err(LocalToolchainVerificationError::ReplacementDetected(
                self.root().to_path_buf(),
            ));
        }
        check_cancelled(is_cancelled)?;
        Ok(LocalToolchainVerification {
            manifest,
            observed,
            toolchain: verified_toolchain,
            target,
            target_manifest: selected_target_manifest,
        })
    }
}

#[derive(Debug)]
pub enum LocalToolchainVerificationError {
    Cancelled,
    UnsupportedCompilerHost,
    HostMismatch {
        required: &'static str,
        installed: String,
    },
    LlvmRevisionMismatch {
        required: &'static str,
        installed: String,
    },
    InvalidLimits(&'static str),
    InvalidRoot(PathBuf),
    Io {
        operation: &'static str,
        path: PathBuf,
        kind: std::io::ErrorKind,
    },
    Symlink(PathBuf),
    NonRegularEntry(PathBuf),
    UnsupportedMode(PathBuf),
    ReplacementDetected(PathBuf),
    NonPortableName(PathBuf),
    RootEscape(PathBuf),
    EmptyDirectory(PathBuf),
    DuplicatePath(String),
    ResourceLimit {
        resource: &'static str,
        limit: u64,
    },
    UnexpectedStandardLibraryEntry(String),
    InvalidStandardLibraryLocator(String),
    StandardLibraryManifestMismatch(String),
    UnexpectedTargetTree {
        target: TargetIdentity,
    },
    MeasurementMismatch(PathBuf),
    RunningFrontendMismatch(PathBuf),
    TargetNotDeclared(TargetIdentity),
    ToolchainManifest(ToolchainDecodeError),
    TreeDigest(CanonicalTreeDigestError),
    Manifest(ManifestError),
    TargetPackage(TargetDecodeError),
    InternalInvariant,
}

impl fmt::Display for LocalToolchainVerificationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("local toolchain verification was cancelled"),
            Self::UnsupportedCompilerHost => {
                formatter.write_str("this compiler host has no revision-0.1 toolchain layout")
            }
            Self::HostMismatch {
                required,
                installed,
            } => write!(
                formatter,
                "toolchain host mismatch: compiler requires {required}, installation declares {installed}"
            ),
            Self::LlvmRevisionMismatch {
                required,
                installed,
            } => write!(
                formatter,
                "toolchain LLVM revision mismatch: compiler requires {required}, installation declares {installed}"
            ),
            Self::InvalidLimits(resource) => {
                write!(formatter, "invalid local toolchain {resource} limit")
            }
            Self::InvalidRoot(path) => write!(
                formatter,
                "toolchain root is not an absolute canonical directory: {}",
                path.display()
            ),
            Self::Io {
                operation,
                path,
                kind,
            } => write!(
                formatter,
                "toolchain {operation} failed for {}: {kind}",
                path.display()
            ),
            Self::Symlink(path) => {
                write!(
                    formatter,
                    "toolchain path contains a symlink: {}",
                    path.display()
                )
            }
            Self::NonRegularEntry(path) => write!(
                formatter,
                "toolchain entry is neither a regular file nor directory: {}",
                path.display()
            ),
            Self::UnsupportedMode(path) => {
                write!(
                    formatter,
                    "toolchain entry has an unsupported mode: {}",
                    path.display()
                )
            }
            Self::ReplacementDetected(path) => write!(
                formatter,
                "toolchain entry changed while it was observed: {}",
                path.display()
            ),
            Self::NonPortableName(path) => write!(
                formatter,
                "toolchain tree contains a nonportable name: {}",
                path.display()
            ),
            Self::RootEscape(path) => write!(
                formatter,
                "toolchain manifest path escaped the explicit root: {}",
                path.display()
            ),
            Self::EmptyDirectory(path) => write!(
                formatter,
                "toolchain tree contains an uncommitted empty directory: {}",
                path.display()
            ),
            Self::DuplicatePath(path) => {
                write!(formatter, "toolchain tree contains duplicate path {path}")
            }
            Self::ResourceLimit { resource, limit } => {
                write!(formatter, "toolchain exceeded {resource} limit {limit}")
            }
            Self::UnexpectedStandardLibraryEntry(path) => write!(
                formatter,
                "standard-library root or package index has unexpected entry {path}"
            ),
            Self::InvalidStandardLibraryLocator(path) => write!(
                formatter,
                "standard-library package locator is not one direct child: {path}"
            ),
            Self::StandardLibraryManifestMismatch(path) => write!(
                formatter,
                "standard-library package manifest does not match its index: {path}"
            ),
            Self::UnexpectedTargetTree { target } => write!(
                formatter,
                "target {} contains missing, extra, or misplaced files",
                target.as_str()
            ),
            Self::MeasurementMismatch(path) => write!(
                formatter,
                "toolchain measurement differs from the manifest: {}",
                path.display()
            ),
            Self::RunningFrontendMismatch(path) => write!(
                formatter,
                "running compiler {} differs from the verified toolchain frontend",
                path.display()
            ),
            Self::TargetNotDeclared(target) => {
                write!(
                    formatter,
                    "toolchain does not declare target {}",
                    target.as_str()
                )
            }
            Self::ToolchainManifest(error) => error.fmt(formatter),
            Self::TreeDigest(error) => error.fmt(formatter),
            Self::Manifest(error) => error.fmt(formatter),
            Self::TargetPackage(error) => error.fmt(formatter),
            Self::InternalInvariant => {
                formatter.write_str("local toolchain verifier invariant failed")
            }
        }
    }
}

impl std::error::Error for LocalToolchainVerificationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ToolchainManifest(error) => Some(error),
            Self::TreeDigest(error) => Some(error),
            Self::Manifest(error) => Some(error),
            Self::TargetPackage(error) => Some(error),
            _ => None,
        }
    }
}

#[derive(Debug)]
struct FileObservation {
    bytes: u64,
    digest: Sha256Digest,
    retained: Option<Vec<u8>>,
}

#[derive(Debug)]
struct OwnedTreeRecord {
    path: String,
    bytes: u64,
    digest: Sha256Digest,
    retained: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectEntryKind {
    File,
    Directory,
}

#[derive(Debug)]
struct DirectEntry {
    name: String,
    kind: DirectEntryKind,
}

#[derive(Debug)]
struct TreeObservation {
    measurement: wrela_package_loader::CanonicalTreeMeasurement,
    files: Vec<OwnedTreeRecord>,
    direct_entries: Vec<DirectEntry>,
}

impl TreeObservation {
    fn file(&self, path: &str) -> Option<&OwnedTreeRecord> {
        self.files
            .binary_search_by(|record| record.path.as_str().cmp(path))
            .ok()
            .map(|index| &self.files[index])
    }

    fn take_retained(&mut self, path: &str) -> Option<Vec<u8>> {
        self.files
            .binary_search_by(|record| record.path.as_str().cmp(path))
            .ok()
            .and_then(|index| self.files[index].retained.take())
    }
}

#[derive(Debug)]
struct TraversalBudget {
    limits: LocalToolchainVerificationLimits,
    entries: u32,
    path_bytes: u64,
    metadata_bytes: u64,
    content_bytes: u64,
}

impl TraversalBudget {
    const fn new(limits: LocalToolchainVerificationLimits) -> Self {
        Self {
            limits,
            entries: 0,
            path_bytes: 0,
            metadata_bytes: 0,
            content_bytes: 0,
        }
    }

    fn add_entry(
        &mut self,
        relative_bytes: usize,
        depth: u32,
    ) -> Result<(), LocalToolchainVerificationError> {
        if depth > self.limits.traversal_depth {
            return Err(resource_error(
                "toolchain traversal depth",
                u64::from(self.limits.traversal_depth),
            ));
        }
        self.entries = self.entries.checked_add(1).ok_or_else(|| {
            resource_error(
                "toolchain tree entries",
                u64::from(self.limits.tree.records),
            )
        })?;
        if self.entries > self.limits.tree.records {
            return Err(resource_error(
                "toolchain tree entries",
                u64::from(self.limits.tree.records),
            ));
        }
        let path_bytes = u64::try_from(relative_bytes).unwrap_or(u64::MAX);
        add_limited(
            &mut self.path_bytes,
            path_bytes,
            "toolchain tree path bytes",
            self.limits.tree.path_bytes,
        )?;
        let metadata = TREE_ENTRY_METADATA_BYTES
            .checked_add(path_bytes)
            .ok_or_else(|| {
                resource_error(
                    "toolchain tree metadata bytes",
                    self.limits.tree.metadata_bytes,
                )
            })?;
        add_limited(
            &mut self.metadata_bytes,
            metadata,
            "toolchain tree metadata bytes",
            self.limits.tree.metadata_bytes,
        )
    }

    fn file_limit(&self) -> u64 {
        self.limits.single_file_bytes.min(
            self.limits
                .tree
                .content_bytes
                .saturating_sub(self.content_bytes),
        )
    }

    fn add_content(&mut self, bytes: u64) -> Result<(), LocalToolchainVerificationError> {
        add_limited(
            &mut self.content_bytes,
            bytes,
            "toolchain tree content bytes",
            self.limits.tree.content_bytes,
        )
    }
}

fn measure_tree(
    root: &Path,
    limits: LocalToolchainVerificationLimits,
    retain: &dyn Fn(&str) -> Option<u64>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<TreeObservation, LocalToolchainVerificationError> {
    let before = directory_snapshot(root, is_cancelled)?;
    let mut files = Vec::new();
    let mut direct_entries = Vec::new();
    let mut budget = TraversalBudget::new(limits);
    walk_directory(
        root,
        "",
        0,
        &mut budget,
        &mut files,
        &mut direct_entries,
        retain,
        is_cancelled,
    )?;
    let after = directory_snapshot(root, is_cancelled)?;
    if before != after {
        return Err(LocalToolchainVerificationError::ReplacementDetected(
            root.to_path_buf(),
        ));
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    if let Some(pair) = files.windows(2).find(|pair| pair[0].path == pair[1].path) {
        return Err(LocalToolchainVerificationError::DuplicatePath(
            pair[0].path.clone(),
        ));
    }
    let mut records = Vec::new();
    records
        .try_reserve_exact(files.len())
        .map_err(|_| allocation_error("canonical tree records", limits.tree.records))?;
    records.extend(files.iter().map(|record| CanonicalTreeRecord {
        path: &record.path,
        bytes: record.bytes,
        digest: record.digest,
    }));
    let measurement = canonical_tree_digest(&records, &SoftwareSha256, limits.tree, is_cancelled)
        .map_err(LocalToolchainVerificationError::TreeDigest)?;
    if measurement.content_bytes != budget.content_bytes {
        return Err(LocalToolchainVerificationError::InternalInvariant);
    }
    Ok(TreeObservation {
        measurement,
        files,
        direct_entries,
    })
}

fn validate_installation_entries(
    root: &Path,
    limits: LocalToolchainVerificationLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LocalToolchainVerificationError> {
    let mut budget = TraversalBudget::new(limits);
    walk_installation_entries(root, "", 0, &mut budget, is_cancelled)
}

fn walk_installation_entries(
    directory: &Path,
    prefix: &str,
    directory_depth: u32,
    budget: &mut TraversalBudget,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LocalToolchainVerificationError> {
    check_cancelled(is_cancelled)?;
    let before = directory_snapshot(directory, is_cancelled)?;
    let entries = fs::read_dir(directory)
        .map_err(|error| io_error("installation enumeration", directory, &error))?;
    let mut names = Vec::new();
    for entry in entries {
        check_cancelled(is_cancelled)?;
        let entry =
            entry.map_err(|error| io_error("installation enumeration", directory, &error))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(LocalToolchainVerificationError::NonPortableName(
                directory.join(&name),
            ));
        };
        if !portable_component(name) {
            return Err(LocalToolchainVerificationError::NonPortableName(
                directory.join(name),
            ));
        }
        let relative_bytes = relative_path_bytes(prefix, name, budget.limits.tree.path_bytes)?;
        budget.add_entry(relative_bytes, directory_depth.saturating_add(1))?;
        names
            .try_reserve(1)
            .map_err(|_| allocation_error("installation entries", budget.limits.tree.records))?;
        names.push((name.to_owned(), relative_path(prefix, name)?));
    }
    names.sort_by(|left, right| left.0.cmp(&right.0));
    if let Some(pair) = names.windows(2).find(|pair| pair[0].0 == pair[1].0) {
        return Err(LocalToolchainVerificationError::DuplicatePath(
            pair[0].1.clone(),
        ));
    }
    for (name, relative) in names {
        check_cancelled(is_cancelled)?;
        let path = directory.join(name);
        let metadata = checked_metadata(&path, is_cancelled)?;
        if metadata.is_dir() {
            validate_directory_mode(&path, &metadata)?;
            walk_installation_entries(
                &path,
                &relative,
                directory_depth.saturating_add(1),
                budget,
                is_cancelled,
            )?;
        } else if metadata.is_file() {
            validate_file_mode(&path, &metadata, false)?;
        } else {
            return Err(LocalToolchainVerificationError::NonRegularEntry(path));
        }
    }
    let after = directory_snapshot(directory, is_cancelled)?;
    if before != after {
        return Err(LocalToolchainVerificationError::ReplacementDetected(
            directory.to_path_buf(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn walk_directory(
    directory: &Path,
    prefix: &str,
    directory_depth: u32,
    budget: &mut TraversalBudget,
    files: &mut Vec<OwnedTreeRecord>,
    direct_entries: &mut Vec<DirectEntry>,
    retain: &dyn Fn(&str) -> Option<u64>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LocalToolchainVerificationError> {
    check_cancelled(is_cancelled)?;
    let before = directory_snapshot(directory, is_cancelled)?;
    let mut names = Vec::new();
    let entries = fs::read_dir(directory)
        .map_err(|error| io_error("directory enumeration", directory, &error))?;
    for entry in entries {
        check_cancelled(is_cancelled)?;
        let entry = entry.map_err(|error| io_error("directory enumeration", directory, &error))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(LocalToolchainVerificationError::NonPortableName(
                directory.join(&name),
            ));
        };
        if !portable_component(name) {
            return Err(LocalToolchainVerificationError::NonPortableName(
                directory.join(name),
            ));
        }
        let relative_bytes = prefix
            .len()
            .checked_add(usize::from(!prefix.is_empty()))
            .and_then(|length| length.checked_add(name.len()))
            .ok_or_else(|| {
                resource_error("toolchain tree path bytes", budget.limits.tree.path_bytes)
            })?;
        budget.add_entry(relative_bytes, directory_depth.saturating_add(1))?;
        let relative = relative_path(prefix, name)?;
        names
            .try_reserve(1)
            .map_err(|_| allocation_error("directory entries", budget.limits.tree.records))?;
        names.push((name.to_owned(), relative));
    }
    names.sort_by(|left, right| left.0.cmp(&right.0));
    if let Some(pair) = names.windows(2).find(|pair| pair[0].0 == pair[1].0) {
        return Err(LocalToolchainVerificationError::DuplicatePath(
            pair[0].1.clone(),
        ));
    }

    let files_before = files.len();
    for (name, relative) in names {
        check_cancelled(is_cancelled)?;
        let path = directory.join(&name);
        let metadata = checked_metadata(&path, is_cancelled)?;
        let kind = if metadata.is_dir() {
            DirectEntryKind::Directory
        } else if metadata.is_file() {
            DirectEntryKind::File
        } else {
            return Err(LocalToolchainVerificationError::NonRegularEntry(path));
        };
        if directory_depth == 0 {
            direct_entries
                .try_reserve(1)
                .map_err(|_| allocation_error("direct tree entries", budget.limits.tree.records))?;
            direct_entries.push(DirectEntry { name, kind });
        }
        match kind {
            DirectEntryKind::Directory => walk_directory(
                &path,
                &relative,
                directory_depth.saturating_add(1),
                budget,
                files,
                direct_entries,
                retain,
                is_cancelled,
            )?,
            DirectEntryKind::File => {
                let retained_limit = retain(&relative);
                let maximum = budget.file_limit().min(retained_limit.unwrap_or(u64::MAX));
                let observed = read_stable_file(
                    &path,
                    maximum,
                    retained_limit.is_some(),
                    false,
                    is_cancelled,
                )?;
                budget.add_content(observed.bytes)?;
                files
                    .try_reserve(1)
                    .map_err(|_| allocation_error("tree files", budget.limits.tree.records))?;
                files.push(OwnedTreeRecord {
                    path: relative,
                    bytes: observed.bytes,
                    digest: observed.digest,
                    retained: observed.retained,
                });
            }
        }
    }
    if directory_depth != 0 && files.len() == files_before {
        return Err(LocalToolchainVerificationError::EmptyDirectory(
            directory.to_path_buf(),
        ));
    }
    let after = directory_snapshot(directory, is_cancelled)?;
    if before != after {
        return Err(LocalToolchainVerificationError::ReplacementDetected(
            directory.to_path_buf(),
        ));
    }
    Ok(())
}

fn observe_target(
    declared: &ShippedTarget,
    tree: &TreeObservation,
    root: &Path,
    limits: LocalToolchainVerificationLimits,
) -> Result<ShippedTarget, LocalToolchainVerificationError> {
    let expected_count = declared
        .files
        .len()
        .checked_add(1)
        .ok_or_else(|| resource_error("target files", u64::from(limits.tree.records)))?;
    let mut expected = Vec::new();
    expected
        .try_reserve_exact(expected_count)
        .map_err(|_| allocation_error("target files", limits.tree.records))?;
    expected.push(TARGET_MANIFEST_PATH);
    expected.extend(declared.files.iter().map(|file| file.path.as_str()));
    expected.sort_unstable();
    if expected.len() != tree.files.len()
        || expected
            .iter()
            .zip(&tree.files)
            .any(|(expected, actual)| *expected != actual.path)
    {
        return Err(LocalToolchainVerificationError::UnexpectedTargetTree {
            target: declared.identity.clone(),
        });
    }

    let mut files = Vec::new();
    files
        .try_reserve_exact(declared.files.len())
        .map_err(|_| allocation_error("observed target files", limits.tree.records))?;
    for file in &declared.files {
        let actual = tree.file(file.path.as_str()).ok_or_else(|| {
            LocalToolchainVerificationError::UnexpectedTargetTree {
                target: declared.identity.clone(),
            }
        })?;
        if actual.digest != file.digest || actual.bytes != file.bytes {
            return Err(LocalToolchainVerificationError::MeasurementMismatch(
                root.join(file.path.as_str()),
            ));
        }
        files.push(ShippedTargetFile {
            path: file.path.clone(),
            digest: actual.digest,
            bytes: actual.bytes,
        });
    }
    Ok(ShippedTarget {
        identity: declared.identity.clone(),
        path: declared.path.clone(),
        digest: tree.measurement.digest,
        bytes: tree.measurement.content_bytes,
        files,
    })
}

fn verify_standard_library_index(
    manifest: &ToolchainManifest,
    tree: &TreeObservation,
    limits: LocalToolchainVerificationLimits,
) -> Result<(), LocalToolchainVerificationError> {
    let mut expected = Vec::new();
    expected
        .try_reserve_exact(manifest.standard_library_packages.len())
        .map_err(|_| allocation_error("standard-library package index", limits.tree.records))?;
    for package in &manifest.standard_library_packages {
        let PackageLocator::Toolchain { component } = &package.locator else {
            return Err(
                LocalToolchainVerificationError::InvalidStandardLibraryLocator(
                    "non-toolchain locator".to_owned(),
                ),
            );
        };
        if component.contains('/') || !portable_component(component) {
            return Err(
                LocalToolchainVerificationError::InvalidStandardLibraryLocator(component.clone()),
            );
        }
        expected.push((component.as_str(), package.manifest_digest));
    }
    expected.sort_unstable_by(|left, right| left.0.cmp(right.0));
    if expected.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err(
            LocalToolchainVerificationError::InvalidStandardLibraryLocator(
                "duplicate package directory".to_owned(),
            ),
        );
    }
    if expected.len() != tree.direct_entries.len() {
        return Err(
            LocalToolchainVerificationError::UnexpectedStandardLibraryEntry(
                "direct package set".to_owned(),
            ),
        );
    }
    for ((component, manifest_digest), actual) in expected.iter().zip(&tree.direct_entries) {
        if actual.name != *component || actual.kind != DirectEntryKind::Directory {
            return Err(
                LocalToolchainVerificationError::UnexpectedStandardLibraryEntry(
                    actual.name.clone(),
                ),
            );
        }
        let manifest_path = relative_path(component, PACKAGE_MANIFEST_NAME)?;
        let record = tree.file(&manifest_path).ok_or_else(|| {
            LocalToolchainVerificationError::StandardLibraryManifestMismatch(manifest_path.clone())
        })?;
        if record.digest != *manifest_digest {
            return Err(
                LocalToolchainVerificationError::StandardLibraryManifestMismatch(manifest_path),
            );
        }
    }
    Ok(())
}

fn read_stable_file(
    path: &Path,
    maximum_bytes: u64,
    retain: bool,
    require_executable: bool,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<FileObservation, LocalToolchainVerificationError> {
    check_cancelled(is_cancelled)?;
    reject_symlink_components(path, is_cancelled)?;
    let before_metadata = checked_metadata(path, is_cancelled)?;
    if !before_metadata.is_file() {
        return Err(LocalToolchainVerificationError::NonRegularEntry(
            path.to_path_buf(),
        ));
    }
    validate_file_mode(path, &before_metadata, require_executable)?;
    let before = MetadataSnapshot::capture(path, &before_metadata)?;
    if before.len() > maximum_bytes {
        return Err(resource_error("single-file bytes", maximum_bytes));
    }
    let mut file = File::open(path).map_err(|error| io_error("file open", path, &error))?;
    let opened_metadata = file
        .metadata()
        .map_err(|error| io_error("opened-file metadata", path, &error))?;
    validate_file_mode(path, &opened_metadata, require_executable)?;
    let opened = MetadataSnapshot::capture(path, &opened_metadata)?;
    if before != opened {
        return Err(LocalToolchainVerificationError::ReplacementDetected(
            path.to_path_buf(),
        ));
    }

    let mut retained = retain.then(Vec::new);
    if let Some(bytes) = &mut retained {
        let capacity = usize::try_from(before.len())
            .map_err(|_| resource_error("single-file allocation bytes", maximum_bytes))?;
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| resource_error("single-file allocation bytes", maximum_bytes))?;
    }
    let hasher = SoftwareSha256;
    let mut digest = hasher.begin_sha256();
    let mut bytes_read = 0u64;
    let mut buffer = [0u8; READ_CHUNK_BYTES];
    loop {
        check_cancelled(is_cancelled)?;
        let read = file
            .read(&mut buffer)
            .map_err(|error| io_error("file read", path, &error))?;
        if read == 0 {
            break;
        }
        let read = u64::try_from(read).unwrap_or(u64::MAX);
        bytes_read = bytes_read
            .checked_add(read)
            .ok_or_else(|| resource_error("single-file bytes", maximum_bytes))?;
        if bytes_read > maximum_bytes {
            return Err(resource_error("single-file bytes", maximum_bytes));
        }
        let read = usize::try_from(read)
            .map_err(|_| resource_error("single-file bytes", maximum_bytes))?;
        digest.update(&buffer[..read]);
        if let Some(bytes) = &mut retained {
            bytes
                .try_reserve(read)
                .map_err(|_| resource_error("single-file allocation bytes", maximum_bytes))?;
            bytes.extend_from_slice(&buffer[..read]);
        }
    }
    check_cancelled(is_cancelled)?;
    let handle_after = MetadataSnapshot::capture(
        path,
        &file
            .metadata()
            .map_err(|error| io_error("opened-file metadata", path, &error))?,
    )?;
    reject_symlink_components(path, is_cancelled)?;
    let path_after_metadata = checked_metadata(path, is_cancelled)?;
    validate_file_mode(path, &path_after_metadata, require_executable)?;
    let path_after = MetadataSnapshot::capture(path, &path_after_metadata)?;
    if before != handle_after || handle_after != path_after || bytes_read != path_after.len() {
        return Err(LocalToolchainVerificationError::ReplacementDetected(
            path.to_path_buf(),
        ));
    }
    check_cancelled(is_cancelled)?;
    Ok(FileObservation {
        bytes: bytes_read,
        digest: digest.finish(),
        retained,
    })
}

fn directory_snapshot(
    path: &Path,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<MetadataSnapshot, LocalToolchainVerificationError> {
    reject_symlink_components(path, is_cancelled)?;
    let metadata = checked_metadata(path, is_cancelled)?;
    if !metadata.is_dir() {
        return Err(LocalToolchainVerificationError::NonRegularEntry(
            path.to_path_buf(),
        ));
    }
    validate_directory_mode(path, &metadata)?;
    MetadataSnapshot::capture(path, &metadata)
}

fn checked_metadata(
    path: &Path,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Metadata, LocalToolchainVerificationError> {
    check_cancelled(is_cancelled)?;
    let metadata =
        fs::symlink_metadata(path).map_err(|error| io_error("metadata", path, &error))?;
    if metadata.file_type().is_symlink() || metadata_is_reparse_point(&metadata) {
        return Err(LocalToolchainVerificationError::Symlink(path.to_path_buf()));
    }
    Ok(metadata)
}

#[cfg(windows)]
fn metadata_is_reparse_point(metadata: &Metadata) -> bool {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
const fn metadata_is_reparse_point(_metadata: &Metadata) -> bool {
    false
}

#[cfg(unix)]
fn validate_file_mode(
    path: &Path,
    metadata: &Metadata,
    require_executable: bool,
) -> Result<(), LocalToolchainVerificationError> {
    let mode = metadata.mode();
    if mode & 0o7000 != 0
        || mode & 0o022 != 0
        || metadata.nlink() != 1
        || (require_executable && mode & 0o111 != 0o111)
    {
        Err(LocalToolchainVerificationError::UnsupportedMode(
            path.to_path_buf(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn validate_directory_mode(
    path: &Path,
    metadata: &Metadata,
) -> Result<(), LocalToolchainVerificationError> {
    if metadata.mode() & 0o7022 != 0 {
        Err(LocalToolchainVerificationError::UnsupportedMode(
            path.to_path_buf(),
        ))
    } else {
        Ok(())
    }
}

#[cfg(not(unix))]
fn validate_file_mode(
    _path: &Path,
    _metadata: &Metadata,
    _require_executable: bool,
) -> Result<(), LocalToolchainVerificationError> {
    Ok(())
}

#[cfg(not(unix))]
fn validate_directory_mode(
    _path: &Path,
    _metadata: &Metadata,
) -> Result<(), LocalToolchainVerificationError> {
    Ok(())
}

fn validate_root_path(
    root: &Path,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LocalToolchainVerificationError> {
    let normalized: PathBuf = root.components().collect();
    if !root.is_absolute()
        || root.components().count() <= 1
        || normalized != root
        || root.as_os_str().as_encoded_bytes().len() > MAX_HOST_PATH_BYTES
        || root
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(LocalToolchainVerificationError::InvalidRoot(
            root.to_path_buf(),
        ));
    }
    reject_symlink_components(root, is_cancelled)?;
    let canonical =
        fs::canonicalize(root).map_err(|error| io_error("root canonicalization", root, &error))?;
    if canonical != root {
        return Err(LocalToolchainVerificationError::InvalidRoot(
            root.to_path_buf(),
        ));
    }
    let metadata = checked_metadata(root, is_cancelled)?;
    if !metadata.is_dir() {
        return Err(LocalToolchainVerificationError::InvalidRoot(
            root.to_path_buf(),
        ));
    }
    validate_directory_mode(root, &metadata)?;
    Ok(())
}

fn reject_symlink_components(
    path: &Path,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LocalToolchainVerificationError> {
    if !path.is_absolute()
        || path.as_os_str().as_encoded_bytes().len() > MAX_HOST_PATH_BYTES
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(LocalToolchainVerificationError::RootEscape(
            path.to_path_buf(),
        ));
    }
    let mut cursor = PathBuf::new();
    for component in path.components() {
        check_cancelled(is_cancelled)?;
        cursor.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&cursor)
            .map_err(|error| io_error("path-component metadata", &cursor, &error))?;
        if metadata.file_type().is_symlink() || metadata_is_reparse_point(&metadata) {
            return Err(LocalToolchainVerificationError::Symlink(cursor));
        }
    }
    Ok(())
}

fn join_manifest_path(
    root: &Path,
    relative: &str,
) -> Result<PathBuf, LocalToolchainVerificationError> {
    if relative.is_empty()
        || !relative.is_ascii()
        || relative.starts_with('/')
        || relative
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(LocalToolchainVerificationError::RootEscape(
            root.join(relative),
        ));
    }
    let mut path = root.to_path_buf();
    path.try_reserve(relative.len().saturating_add(1))
        .map_err(|_| resource_error("toolchain path bytes", MAX_HOST_PATH_BYTES as u64))?;
    for component in relative.split('/') {
        path.push(component);
    }
    if !path.starts_with(root) || path.as_os_str().as_encoded_bytes().len() > MAX_HOST_PATH_BYTES {
        return Err(LocalToolchainVerificationError::RootEscape(path));
    }
    Ok(path)
}

fn relative_path(prefix: &str, component: &str) -> Result<String, LocalToolchainVerificationError> {
    let separator = usize::from(!prefix.is_empty());
    let capacity = prefix
        .len()
        .checked_add(separator)
        .and_then(|length| length.checked_add(component.len()))
        .ok_or_else(|| resource_error("toolchain tree path bytes", u64::MAX))?;
    let mut path = String::new();
    path.try_reserve_exact(capacity)
        .map_err(|_| resource_error("toolchain tree path bytes", u64::MAX))?;
    path.push_str(prefix);
    if !prefix.is_empty() {
        path.push('/');
    }
    path.push_str(component);
    Ok(path)
}

fn relative_path_bytes(
    prefix: &str,
    component: &str,
    limit: u64,
) -> Result<usize, LocalToolchainVerificationError> {
    prefix
        .len()
        .checked_add(usize::from(!prefix.is_empty()))
        .and_then(|length| length.checked_add(component.len()))
        .ok_or_else(|| resource_error("toolchain tree path bytes", limit))
}

fn portable_component(component: &str) -> bool {
    !component.is_empty()
        && component.is_ascii()
        && !matches!(component, "." | "..")
        && !component.ends_with('.')
        && component
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
        && !windows_reserved_component(component)
}

fn windows_reserved_component(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component);
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    RESERVED
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
}

fn check_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), LocalToolchainVerificationError> {
    if is_cancelled() {
        Err(LocalToolchainVerificationError::Cancelled)
    } else {
        Ok(())
    }
}

fn add_limited(
    total: &mut u64,
    amount: u64,
    resource: &'static str,
    limit: u64,
) -> Result<(), LocalToolchainVerificationError> {
    let next = total
        .checked_add(amount)
        .ok_or_else(|| resource_error(resource, limit))?;
    if next > limit {
        return Err(resource_error(resource, limit));
    }
    *total = next;
    Ok(())
}

const fn resource_error(resource: &'static str, limit: u64) -> LocalToolchainVerificationError {
    LocalToolchainVerificationError::ResourceLimit { resource, limit }
}

fn allocation_error(resource: &'static str, limit: u32) -> LocalToolchainVerificationError {
    resource_error(resource, u64::from(limit))
}

fn io_error(
    operation: &'static str,
    path: &Path,
    error: &std::io::Error,
) -> LocalToolchainVerificationError {
    LocalToolchainVerificationError::Io {
        operation,
        path: path.to_path_buf(),
        kind: error.kind(),
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MetadataSnapshot {
    device: u64,
    inode: u64,
    links: u64,
    length: u64,
    mode: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MetadataSnapshot {
    volume: Option<u32>,
    index: Option<u64>,
    length: u64,
    attributes: u32,
    created: u64,
    modified: u64,
    links: Option<u32>,
}

#[cfg(not(any(unix, windows)))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct MetadataSnapshot {
    length: u64,
    readonly: bool,
    modified: std::time::SystemTime,
}

impl MetadataSnapshot {
    #[cfg(unix)]
    fn capture(_path: &Path, metadata: &Metadata) -> Result<Self, LocalToolchainVerificationError> {
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            links: metadata.nlink(),
            length: metadata.len(),
            mode: metadata.mode(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        })
    }

    #[cfg(windows)]
    fn capture(_path: &Path, metadata: &Metadata) -> Result<Self, LocalToolchainVerificationError> {
        Ok(Self {
            volume: metadata.volume_serial_number(),
            index: metadata.file_index(),
            length: metadata.file_size(),
            attributes: metadata.file_attributes(),
            created: metadata.creation_time(),
            modified: metadata.last_write_time(),
            links: metadata.number_of_links(),
        })
    }

    #[cfg(not(any(unix, windows)))]
    fn capture(path: &Path, metadata: &Metadata) -> Result<Self, LocalToolchainVerificationError> {
        Ok(Self {
            length: metadata.len(),
            readonly: metadata.permissions().readonly(),
            modified: metadata
                .modified()
                .map_err(|error| io_error("entry timestamp", path, &error))?,
        })
    }

    const fn len(&self) -> u64 {
        self.length
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[cfg(unix)]
    use std::os::unix::fs::{PermissionsExt, symlink};

    use crate::{
        ComponentPath, ShippedStandardLibraryPackage, TOOLCHAIN_MANIFEST_SCHEMA,
        ToolchainManifestCodec,
    };
    use wrela_package::{PackageIdentity, PackageName, PackageVersion};
    use wrela_package_loader::{CanonicalTreeRecord, ContentHasher};

    use super::*;

    const FRONTEND_BYTES: &[u8] = b"wrela frontend fixture";
    const BACKEND_BYTES: &[u8] = b"wrela backend fixture";
    const PACKAGE_MANIFEST: &[u8] = b"schema = 1\n";
    const PACKAGE_SOURCE: &[u8] = b"module image\npub fn target():\n    pass\n";
    const RUNTIME_OBJECT: &[u8] = b"AArch64 COFF runtime fixture";
    const TARGET_MANIFEST: &[u8] =
        include_bytes!("../../../toolchain/targets/aarch64-qemu-virt-uefi/target.toml");
    const PACKAGE_COMPONENT: &str = "wrela-core-0.1";

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    #[derive(Debug)]
    struct TestDirectory {
        root: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            let base = fs::canonicalize(std::env::temp_dir()).expect("canonical temporary base");
            for _ in 0..128 {
                let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let root = base.join(format!(
                    "wrela-local-toolchain-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&root) {
                    Ok(()) => {
                        return Self {
                            root: fs::canonicalize(root).expect("canonical fixture root"),
                        };
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("cannot create verifier fixture: {error}"),
                }
            }
            panic!("cannot allocate a unique verifier fixture")
        }

        fn write(&self, relative: &str, bytes: &[u8]) -> PathBuf {
            let path = self.root.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("fixture parent directory");
            }
            fs::write(&path, bytes).expect("bounded fixture write");
            path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[derive(Debug)]
    struct Fixture {
        directory: TestDirectory,
        manifest: ToolchainManifest,
    }

    impl Fixture {
        fn new() -> Self {
            let directory = TestDirectory::new();
            let frontend_path = frontend_path();
            let backend_path = backend_path();
            directory.write(frontend_path, FRONTEND_BYTES);
            directory.write(backend_path, BACKEND_BYTES);
            set_executable(&directory.root.join(frontend_path));
            set_executable(&directory.root.join(backend_path));

            directory.write(
                &format!("share/wrela/std/{PACKAGE_COMPONENT}/wrela.toml"),
                PACKAGE_MANIFEST,
            );
            directory.write(
                &format!("share/wrela/std/{PACKAGE_COMPONENT}/src/image.wr"),
                PACKAGE_SOURCE,
            );
            let target_root = "share/wrela/targets/aarch64-qemu-virt-uefi";
            directory.write(&format!("{target_root}/target.toml"), TARGET_MANIFEST);
            directory.write(
                &format!("{target_root}/runtime/wrela-runtime-aarch64.obj"),
                RUNTIME_OBJECT,
            );

            let standard_library = tree_measurement(&[
                tree_record("wrela-core-0.1/src/image.wr", PACKAGE_SOURCE),
                tree_record("wrela-core-0.1/wrela.toml", PACKAGE_MANIFEST),
            ]);
            let target = tree_measurement(&[
                tree_record("runtime/wrela-runtime-aarch64.obj", RUNTIME_OBJECT),
                tree_record("target.toml", TARGET_MANIFEST),
            ]);
            let hasher = SoftwareSha256;
            let manifest = ToolchainManifest {
                schema: TOOLCHAIN_MANIFEST_SCHEMA,
                release: "0.1.0-test".to_owned(),
                host: host_identity().to_owned(),
                llvm_project_revision: REQUIRED_LLVM_PROJECT_REVISION.to_owned(),
                compatibility: ToolchainCompatibility::current(),
                standard_library_packages: vec![ShippedStandardLibraryPackage {
                    identity: PackageIdentity {
                        name: PackageName::new("wrela-core").expect("package name"),
                        version: PackageVersion::new("0.1.0").expect("package version"),
                        source_digest: hasher.sha256(b"fixture package identity"),
                    },
                    locator: PackageLocator::Toolchain {
                        component: PACKAGE_COMPONENT.to_owned(),
                    },
                    manifest_digest: hasher.sha256(PACKAGE_MANIFEST),
                }],
                components: vec![
                    shipped_component(ComponentKind::Frontend, frontend_path, FRONTEND_BYTES),
                    shipped_component(ComponentKind::Backend, backend_path, BACKEND_BYTES),
                    ShippedComponent {
                        kind: ComponentKind::StandardLibrary,
                        path: ComponentPath::new("share/wrela/std").expect("standard library path"),
                        digest: standard_library.digest,
                        bytes: standard_library.content_bytes,
                    },
                ],
                targets: vec![ShippedTarget {
                    identity: TargetIdentity::aarch64_qemu_virt_uefi(),
                    path: ComponentPath::new(target_root).expect("target path"),
                    digest: target.digest,
                    bytes: target.content_bytes,
                    files: vec![shipped_target_file(
                        "runtime/wrela-runtime-aarch64.obj",
                        RUNTIME_OBJECT,
                    )],
                }],
            };
            let fixture = Self {
                directory,
                manifest,
            };
            fixture.write_manifest();
            fixture
        }

        fn write_manifest(&self) {
            let bytes = CanonicalToolchainManifestCodec::new()
                .encode_canonical(
                    &self.manifest,
                    ToolchainDecodeLimits::standard(),
                    &never_cancelled,
                )
                .expect("canonical fixture manifest");
            self.directory.write("share/wrela/toolchain.toml", &bytes);
        }

        fn verifier(&self) -> LocalToolchainVerifier {
            LocalToolchainVerifier::new(Toolchain::at(self.directory.root.clone()))
        }

        fn verify(&self) -> Result<LocalToolchainVerification, LocalToolchainVerificationError> {
            self.verifier().verify(
                &TargetIdentity::aarch64_qemu_virt_uefi(),
                LocalToolchainVerificationLimits::standard(),
                &never_cancelled,
            )
        }
    }

    #[test]
    fn verifies_complete_installation_and_returns_all_products() {
        let fixture = Fixture::new();
        let verified = fixture.verify().expect("complete verified toolchain");
        assert_eq!(verified.manifest(), &fixture.manifest);
        assert_eq!(verified.observed().components, fixture.manifest.components);
        assert_eq!(verified.observed().targets, fixture.manifest.targets);
        assert_eq!(verified.toolchain().root(), fixture.directory.root);
        assert_eq!(
            verified.target().identity(),
            &TargetIdentity::aarch64_qemu_virt_uefi()
        );
        assert_eq!(
            verified.target().semantic().content_digest(),
            fixture.manifest.targets[0].digest
        );
        assert_eq!(verified.target_manifest_bytes(), TARGET_MANIFEST);
    }

    #[test]
    fn evidence_is_deterministic_across_independent_walks() {
        let fixture = Fixture::new();
        let first = fixture.verify().expect("first verification");
        let second = fixture.verify().expect("second verification");
        assert_eq!(first.manifest(), second.manifest());
        assert_eq!(first.observed(), second.observed());
        assert_eq!(first.toolchain(), second.toolchain());
        assert_eq!(first.target(), second.target());
        assert_eq!(
            first.target_manifest_bytes(),
            second.target_manifest_bytes()
        );
    }

    #[test]
    fn corrupt_and_noncanonical_manifests_are_rejected() {
        let corrupt = Fixture::new();
        corrupt
            .directory
            .write("share/wrela/toolchain.toml", b"this is not TOML\n");
        assert!(matches!(
            corrupt.verify(),
            Err(LocalToolchainVerificationError::ToolchainManifest(
                ToolchainDecodeError::Malformed { .. }
                    | ToolchainDecodeError::MissingField(_)
                    | ToolchainDecodeError::UnknownField(_)
            ))
        ));

        let noncanonical = Fixture::new();
        let path = noncanonical
            .directory
            .root
            .join("share/wrela/toolchain.toml");
        let source = fs::read_to_string(&path).expect("canonical manifest text");
        let mut lines: Vec<_> = source.lines().collect();
        lines.swap(0, 1);
        let mut reordered = lines.join("\n");
        reordered.push('\n');
        fs::write(path, reordered).expect("reordered manifest");
        assert!(matches!(
            noncanonical.verify(),
            Err(LocalToolchainVerificationError::ToolchainManifest(
                ToolchainDecodeError::NonCanonical
            ))
        ));
    }

    #[test]
    fn foreign_host_and_unpinned_llvm_revision_are_rejected_before_measurement() {
        let mut foreign = Fixture::new();
        let current = host_identity();
        foreign.manifest.host = if current.contains("windows") {
            if current.starts_with("aarch64") {
                "x86_64-pc-windows-msvc"
            } else {
                "aarch64-pc-windows-msvc"
            }
        } else if current == "x86_64-unknown-linux-gnu" {
            "aarch64-unknown-linux-gnu"
        } else {
            "x86_64-unknown-linux-gnu"
        }
        .to_owned();
        foreign.write_manifest();
        assert!(matches!(
            foreign.verify(),
            Err(LocalToolchainVerificationError::HostMismatch { .. })
        ));

        let mut revision = Fixture::new();
        revision.manifest.llvm_project_revision = "llvmorg-22.1.8".to_owned();
        revision.write_manifest();
        assert!(matches!(
            revision.verify(),
            Err(LocalToolchainVerificationError::LlvmRevisionMismatch { .. })
        ));
    }

    #[test]
    fn altered_raw_component_and_standard_library_tree_are_rejected() {
        let raw = Fixture::new();
        raw.directory.write(backend_path(), b"substituted backend");
        set_executable(&raw.directory.root.join(backend_path()));
        assert!(matches!(
            raw.verify(),
            Err(LocalToolchainVerificationError::MeasurementMismatch(_))
        ));

        let tree = Fixture::new();
        tree.directory.write(
            &format!("share/wrela/std/{PACKAGE_COMPONENT}/src/image.wr"),
            b"substituted source",
        );
        assert!(matches!(
            tree.verify(),
            Err(LocalToolchainVerificationError::MeasurementMismatch(_))
        ));
    }

    #[test]
    fn standard_library_index_is_an_exact_manifest_bound_directory_set() {
        let loose = Fixture::new();
        loose
            .directory
            .write("share/wrela/std/README.txt", b"undeclared");
        assert!(matches!(
            loose.verify(),
            Err(LocalToolchainVerificationError::UnexpectedStandardLibraryEntry(_))
        ));

        let changed_manifest = Fixture::new();
        changed_manifest.directory.write(
            &format!("share/wrela/std/{PACKAGE_COMPONENT}/wrela.toml"),
            b"schema = 2\n",
        );
        assert!(matches!(
            changed_manifest.verify(),
            Err(LocalToolchainVerificationError::StandardLibraryManifestMismatch(_))
        ));
    }

    #[test]
    fn target_tree_is_exact_and_declared_files_are_individually_checked() {
        let extra = Fixture::new();
        extra.directory.write(
            "share/wrela/targets/aarch64-qemu-virt-uefi/extra.bin",
            b"undeclared",
        );
        assert!(matches!(
            extra.verify(),
            Err(LocalToolchainVerificationError::UnexpectedTargetTree { .. })
        ));

        let changed = Fixture::new();
        changed.directory.write(
            "share/wrela/targets/aarch64-qemu-virt-uefi/runtime/wrela-runtime-aarch64.obj",
            b"substituted runtime object",
        );
        assert!(matches!(
            changed.verify(),
            Err(LocalToolchainVerificationError::MeasurementMismatch(_))
        ));
    }

    #[test]
    fn nonportable_tree_name_is_rejected_before_hashing() {
        let fixture = Fixture::new();
        fixture.directory.write(
            &format!("share/wrela/std/{PACKAGE_COMPONENT}/bad name"),
            b"invalid path",
        );
        assert!(matches!(
            fixture.verify(),
            Err(LocalToolchainVerificationError::NonPortableName(_))
        ));
    }

    #[test]
    fn semver_build_metadata_is_portable_in_installed_notice_paths() {
        let fixture = Fixture::new();
        fixture.directory.write(
            "share/wrela/licenses/rust/crates/toml_writer-1.1.2+spec-1.1.0/LICENSE-MIT",
            b"reviewed dependency notice",
        );
        fixture
            .verify()
            .expect("SemVer build metadata is valid in an installed notice path");
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_entry_is_rejected() {
        let fixture = Fixture::new();
        let source = fixture
            .directory
            .root
            .join(format!("share/wrela/std/{PACKAGE_COMPONENT}/src/image.wr"));
        fs::remove_file(&source).expect("remove package source");
        let outside = fixture.directory.write("outside.wr", b"outside");
        symlink(outside, source).expect("source symlink");
        assert!(matches!(
            fixture.verify(),
            Err(LocalToolchainVerificationError::Symlink(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn hardlinked_or_group_writable_entry_is_rejected() {
        let hardlinked = Fixture::new();
        let source = hardlinked
            .directory
            .root
            .join(format!("share/wrela/std/{PACKAGE_COMPONENT}/src/image.wr"));
        fs::hard_link(&source, hardlinked.directory.root.join("outside-alias.wr"))
            .expect("hard-link alias");
        assert!(matches!(
            hardlinked.verify(),
            Err(LocalToolchainVerificationError::UnsupportedMode(_))
        ));

        let writable = Fixture::new();
        let path = writable.directory.root.join(backend_path());
        let mut permissions = fs::metadata(&path).expect("backend metadata").permissions();
        permissions.set_mode(0o775);
        fs::set_permissions(path, permissions).expect("group-writable backend");
        assert!(matches!(
            writable.verify(),
            Err(LocalToolchainVerificationError::UnsupportedMode(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn missing_executable_mode_is_rejected() {
        let fixture = Fixture::new();
        let path = fixture.directory.root.join(backend_path());
        let mut permissions = fs::metadata(&path).expect("backend metadata").permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(path, permissions).expect("non-executable backend");
        assert!(matches!(
            fixture.verify(),
            Err(LocalToolchainVerificationError::UnsupportedMode(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn privileged_root_directory_mode_is_rejected() {
        let fixture = Fixture::new();
        let root = &fixture.directory.root;
        let mut permissions = fs::metadata(root).expect("root metadata").permissions();
        permissions.set_mode(0o2755);
        fs::set_permissions(root, permissions).expect("setgid root permissions");
        assert!(matches!(
            fixture.verify(),
            Err(LocalToolchainVerificationError::UnsupportedMode(_))
        ));
        let mut permissions = fs::metadata(root).expect("root metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(root, permissions).expect("restored root permissions");
    }

    #[test]
    fn explicit_limits_apply_before_unbounded_traversal_or_reads() {
        let fixture = Fixture::new();
        let mut file_limits = LocalToolchainVerificationLimits::standard();
        file_limits.single_file_bytes = 4;
        assert!(matches!(
            fixture.verifier().verify(
                &TargetIdentity::aarch64_qemu_virt_uefi(),
                file_limits,
                &never_cancelled
            ),
            Err(LocalToolchainVerificationError::ResourceLimit {
                resource: "single-file bytes",
                ..
            })
        ));

        let mut tree_limits = LocalToolchainVerificationLimits::standard();
        tree_limits.tree.records = 1;
        assert!(matches!(
            fixture.verifier().verify(
                &TargetIdentity::aarch64_qemu_virt_uefi(),
                tree_limits,
                &never_cancelled
            ),
            Err(LocalToolchainVerificationError::ResourceLimit {
                resource: "toolchain tree entries",
                ..
            })
        ));
    }

    #[test]
    fn zero_byte_file_fits_an_exhausted_tree_content_budget() {
        let directory = TestDirectory::new();
        let path = directory.write("empty", b"");
        let observed = read_stable_file(&path, 0, false, false, &never_cancelled)
            .expect("an empty file consumes no remaining content bytes");
        assert_eq!(observed.bytes, 0);
        assert_eq!(observed.digest, SoftwareSha256.sha256(b""));
    }

    #[test]
    fn cancellation_is_polled_during_filesystem_work() {
        let fixture = Fixture::new();
        let polls = Cell::new(0u32);
        let cancelled = || {
            let next = polls.get().saturating_add(1);
            polls.set(next);
            next > 12
        };
        assert!(matches!(
            fixture.verifier().verify(
                &TargetIdentity::aarch64_qemu_virt_uefi(),
                LocalToolchainVerificationLimits::standard(),
                &cancelled
            ),
            Err(LocalToolchainVerificationError::Cancelled)
        ));
        assert!(polls.get() > 12);
    }

    fn shipped_component(kind: ComponentKind, path: &str, bytes: &[u8]) -> ShippedComponent {
        ShippedComponent {
            kind,
            path: ComponentPath::new(path).expect("component path"),
            digest: SoftwareSha256.sha256(bytes),
            bytes: u64::try_from(bytes.len()).expect("component byte count"),
        }
    }

    fn shipped_target_file(path: &str, bytes: &[u8]) -> ShippedTargetFile {
        ShippedTargetFile {
            path: ComponentPath::new(path).expect("target file path"),
            digest: SoftwareSha256.sha256(bytes),
            bytes: u64::try_from(bytes.len()).expect("target file byte count"),
        }
    }

    fn tree_record<'a>(path: &'a str, bytes: &'a [u8]) -> CanonicalTreeRecord<'a> {
        CanonicalTreeRecord {
            path,
            bytes: u64::try_from(bytes.len()).expect("tree file byte count"),
            digest: SoftwareSha256.sha256(bytes),
        }
    }

    fn tree_measurement(
        records: &[CanonicalTreeRecord<'_>],
    ) -> wrela_package_loader::CanonicalTreeMeasurement {
        canonical_tree_digest(
            records,
            &SoftwareSha256,
            CanonicalTreeLimits::standard(),
            &never_cancelled,
        )
        .expect("fixture tree measurement")
    }

    #[cfg(windows)]
    const fn frontend_path() -> &'static str {
        "bin/wrela.exe"
    }

    #[cfg(not(windows))]
    const fn frontend_path() -> &'static str {
        "bin/wrela"
    }

    #[cfg(windows)]
    const fn backend_path() -> &'static str {
        "libexec/wrela/wrela-backend.exe"
    }

    #[cfg(not(windows))]
    const fn backend_path() -> &'static str {
        "libexec/wrela/wrela-backend"
    }

    fn host_identity() -> &'static str {
        current_host_identity().expect("tests run on a supported revision-0.1 compiler host")
    }

    #[cfg(unix)]
    fn set_executable(path: &Path) {
        let mut permissions = fs::metadata(path)
            .expect("executable metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("executable permissions");
    }

    #[cfg(not(unix))]
    fn set_executable(_path: &Path) {}

    fn never_cancelled() -> bool {
        false
    }
}
