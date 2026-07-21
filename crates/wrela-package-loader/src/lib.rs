//! Hermetic acquisition and loading boundary for TOML manifests and the
//! complete content-addressed source graph.
//!
//! Revision 0.1 has no lockfile: the dependency graph is fully determined by
//! the root `wrela.toml` together with the toolchain-shipped `core` component
//! (`docs/language/02-source-language.md` §2.1). The root manifest's sole
//! dependency must use the reserved alias `core`; its package bytes come from
//! whichever [`PackageLocator`] the driver resolves for that alias
//! (`LoadRequest::core_locator`), never from a name- or digest-based lookup
//! recorded on disk.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use wrela_build_model::Sha256Digest;
use wrela_package::{
    PackageGraph, PackageIdentity, PackageLocator, PackageManifest, PackageName, PackageVersion,
    exact_requirement_version,
};
use wrela_source::{MAX_SOURCE_PATH_BYTES, SourceDatabase, SourceError, SourceInput};

mod codec;
mod loader;
mod sha256;

pub use codec::CanonicalPackageCodec;
pub use loader::CanonicalWorkspaceLoader;
pub use sha256::SoftwareSha256;

pub const SOURCE_GRAPH_DIGEST_VERSION: u32 = 1;
const SOURCE_GRAPH_MAGIC: &[u8; 8] = b"WRELSRC\0";
/// Canonical package-content digest encoding recorded in `PackageIdentity`.
pub const PACKAGE_CONTENT_DIGEST_VERSION: u32 = 1;
const PACKAGE_CONTENT_MAGIC: &[u8; 8] = b"WRELPKG\0";
/// Canonical digest encoding for a toolchain-owned directory tree.
pub const CANONICAL_TREE_DIGEST_VERSION: u32 = 1;
const CANONICAL_TREE_MAGIC: &[u8; 8] = b"WRELTRE\0";
/// Maximum UTF-8 bytes retained from one project- or provider-controlled value
/// in a package-loader error, including the truncation marker.
pub const MAX_LOAD_ERROR_VALUE_BYTES: usize = 256;

pub(crate) fn bounded_load_error_value(value: &str) -> String {
    if value.len() <= MAX_LOAD_ERROR_VALUE_BYTES {
        return value.to_owned();
    }
    const TRUNCATION_MARKER: &str = "…";
    let mut end = MAX_LOAD_ERROR_VALUE_BYTES - TRUNCATION_MARKER.len();
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    let mut bounded = String::with_capacity(MAX_LOAD_ERROR_VALUE_BYTES);
    bounded.push_str(&value[..end]);
    bounded.push_str(TRUNCATION_MARKER);
    bounded
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadLimits {
    pub packages: u32,
    pub sources: u32,
    pub manifest_bytes_per_package: u64,
    /// Aggregate canonical manifest bytes across the complete package graph.
    pub manifest_bytes: u64,
    pub source_bytes: u64,
    pub scenarios: u32,
    pub scenario_bytes: u64,
    pub bytes_per_package: u64,
}

impl LoadLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            packages: 1_000_000,
            sources: 16_000_000,
            manifest_bytes_per_package: 16 * 1024 * 1024,
            manifest_bytes: 4 * 1024 * 1024 * 1024,
            source_bytes: 4 * 1024 * 1024 * 1024,
            scenarios: 1_000_000,
            scenario_bytes: 4 * 1024 * 1024 * 1024,
            bytes_per_package: 1024 * 1024 * 1024,
        }
    }

    pub fn validate(self) -> Result<(), LoadError> {
        if self.packages == 0
            || self.sources == 0
            || self.manifest_bytes_per_package == 0
            || self.manifest_bytes == 0
            || self.source_bytes == 0
            || self.scenarios == 0
            || self.scenario_bytes == 0
            || self.bytes_per_package == 0
            || self.manifest_bytes_per_package > self.bytes_per_package
        {
            Err(LoadError::InvalidLimits)
        } else {
            Ok(())
        }
    }
}

/// Exact bytes supplied by a driver-selected provider. Paths are package
/// relative, canonical, and declared by the decoded manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageBundle {
    pub identity: PackageIdentity,
    pub locator: PackageLocator,
    pub manifest_bytes: Vec<u8>,
    pub sources: Vec<SourceInput>,
    pub scenarios: Vec<ScenarioInput>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioInput {
    pub package: PackageIdentity,
    pub path: String,
    pub bytes: Vec<u8>,
    pub digest: Sha256Digest,
}

/// Acquisition capability supplied by the driver. An implementation may read
/// a workspace, cache, archive store, or toolchain component, but it must not
/// resolve an undeclared locator or use ambient network configuration. The
/// manifest ceiling is independent from the complete package ceiling and must
/// be enforced before manifest decode or any declared source/scenario I/O.
///
/// `expected_name`/`expected_version` are the only identity known before
/// acquisition (there is no lockfile to pre-record a content digest). The
/// returned [`PackageBundle::identity`] carries the digest the provider
/// itself computed or, for a toolchain component, already had verified; the
/// loader never supplies a digest to check acquisition against.
pub trait PackageSourceProvider {
    fn acquire(
        &self,
        locator: &PackageLocator,
        expected_name: &PackageName,
        expected_version: &PackageVersion,
        maximum_bytes: u64,
        maximum_manifest_bytes: u64,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<PackageBundle, ProviderError>;
}

/// SHA-256 implementation supplied by the host layer. All comparisons remain
/// inside the loader so unchecked bytes never reach the source database.
pub trait ContentHasher {
    fn sha256(&self, bytes: &[u8]) -> Sha256Digest;
    fn begin_sha256(&self) -> Box<dyn ContentDigest + '_>;
}

/// Incremental SHA-256 state used to hash canonical graphs without allocating
/// an image-sized concatenation buffer.
pub trait ContentDigest {
    fn update(&mut self, bytes: &[u8]);
    fn finish(self: Box<Self>) -> Sha256Digest;
}

/// Hash a potentially large byte sequence without making cancellation wait for
/// the complete input. Individual digest updates are capped at one MiB.
pub fn sha256_cancellable(
    hasher: &dyn ContentHasher,
    bytes: &[u8],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Sha256Digest, ContentHashError> {
    let mut digest = hasher.begin_sha256();
    for chunk in bytes.chunks(1024 * 1024) {
        if is_cancelled() {
            return Err(ContentHashError::Cancelled);
        }
        digest.update(chunk);
    }
    if is_cancelled() {
        return Err(ContentHashError::Cancelled);
    }
    Ok(digest.finish())
}

pub(crate) fn try_loader_vec<T>(
    capacity: usize,
    resource: &'static str,
    limit: u64,
) -> Result<Vec<T>, LoadError> {
    if u64::try_from(capacity).map_or(true, |capacity| capacity > limit) {
        return Err(LoadError::ResourceLimit { resource, limit });
    }
    let mut values = Vec::new();
    try_reserve_loader_vec(&mut values, capacity, resource, limit)?;
    Ok(values)
}

pub(crate) fn try_reserve_loader_vec<T>(
    values: &mut Vec<T>,
    additional: usize,
    resource: &'static str,
    limit: u64,
) -> Result<(), LoadError> {
    let required = values
        .len()
        .checked_add(additional)
        .and_then(|required| u64::try_from(required).ok())
        .ok_or(LoadError::ResourceLimit { resource, limit })?;
    if required > limit {
        return Err(LoadError::ResourceLimit { resource, limit });
    }
    values
        .try_reserve_exact(additional)
        .map_err(|_| LoadError::ResourceLimit { resource, limit })
}

pub(crate) fn is_utf8_cancellable(
    bytes: &[u8],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LoadError> {
    const CHUNK_BYTES: usize = 64 * 1024;
    let mut offset = 0usize;
    while offset < bytes.len() {
        if is_cancelled() {
            return Err(LoadError::Cancelled);
        }
        let end = offset.saturating_add(CHUNK_BYTES).min(bytes.len());
        match std::str::from_utf8(&bytes[offset..end]) {
            Ok(_) => offset = end,
            Err(error) if error.error_len().is_none() && end < bytes.len() => {
                let valid = error.valid_up_to();
                if valid == 0 {
                    return Ok(false);
                }
                offset = offset.saturating_add(valid);
            }
            Err(_) => return Ok(false),
        }
    }
    if is_cancelled() {
        return Err(LoadError::Cancelled);
    }
    Ok(true)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentHashError {
    Cancelled,
}

impl fmt::Display for ContentHashError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("content hashing was cancelled")
    }
}

impl std::error::Error for ContentHashError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PackageContentKind {
    Source,
    Scenario,
}

/// One canonical package-relative content record. Records must be strictly
/// ordered by `(kind, path)` and must cover exactly the files declared by the
/// manifest before [`package_content_digest`] is called.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageContentRecord<'a> {
    pub kind: PackageContentKind,
    pub path: &'a str,
    pub digest: Sha256Digest,
}

/// Compute the portable package identity digest without concatenating all
/// package bytes. File contents have already been individually SHA-256 hashed;
/// the canonical manifest binds declarations and this encoding binds each
/// declared kind/path to its exact content digest.
pub fn package_content_digest(
    canonical_manifest: &[u8],
    records: &[PackageContentRecord<'_>],
    hasher: &dyn ContentHasher,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Sha256Digest, PackageContentDigestError> {
    if is_cancelled() {
        return Err(PackageContentDigestError::Cancelled);
    }
    if canonical_manifest.is_empty() {
        return Err(PackageContentDigestError::NonCanonicalInput);
    }
    let mut previous = None;
    for record in records {
        if is_cancelled() {
            return Err(PackageContentDigestError::Cancelled);
        }
        let key = (record.kind, record.path);
        if record.path.is_empty() || previous.is_some_and(|previous| previous >= key) {
            return Err(PackageContentDigestError::NonCanonicalInput);
        }
        previous = Some(key);
    }
    let mut digest = hasher.begin_sha256();
    digest.update(PACKAGE_CONTENT_MAGIC);
    digest.update(&PACKAGE_CONTENT_DIGEST_VERSION.to_le_bytes());
    update_bytes_cancellable(&mut *digest, canonical_manifest, is_cancelled)
        .map_err(|()| PackageContentDigestError::Cancelled)?;
    let record_count =
        u64::try_from(records.len()).map_err(|_| PackageContentDigestError::NonCanonicalInput)?;
    update_u64(&mut *digest, record_count);
    for record in records {
        if is_cancelled() {
            return Err(PackageContentDigestError::Cancelled);
        }
        digest.update(&[match record.kind {
            PackageContentKind::Source => 0,
            PackageContentKind::Scenario => 1,
        }]);
        update_string(&mut *digest, record.path);
        digest.update(record.digest.as_bytes());
    }
    if is_cancelled() {
        return Err(PackageContentDigestError::Cancelled);
    }
    Ok(digest.finish())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageContentDigestError {
    Cancelled,
    NonCanonicalInput,
}

impl fmt::Display for PackageContentDigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("package content digest was cancelled"),
            Self::NonCanonicalInput => formatter
                .write_str("package content records are empty, duplicated, or not canonical"),
        }
    }
}

impl std::error::Error for PackageContentDigestError {}

/// Finite policy for measuring one installed toolchain directory component.
///
/// The standard policy is also the hard revision-0.1 ceiling. Callers may use
/// smaller limits for focused operations, but cannot silently admit a larger
/// distribution surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalTreeLimits {
    pub records: u32,
    pub path_bytes: u64,
    pub content_bytes: u64,
    pub metadata_bytes: u64,
}

impl CanonicalTreeLimits {
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            records: 1_000_000,
            path_bytes: 256 * 1024 * 1024,
            content_bytes: 64 * 1024 * 1024 * 1024,
            metadata_bytes: 1024 * 1024 * 1024,
        }
    }

    pub fn validate(self) -> Result<(), CanonicalTreeDigestError> {
        let hard = Self::standard();
        if self.records == 0
            || self.path_bytes == 0
            || self.content_bytes == 0
            || self.metadata_bytes == 0
            || self.records > hard.records
            || self.path_bytes > hard.path_bytes
            || self.content_bytes > hard.content_bytes
            || self.metadata_bytes > hard.metadata_bytes
        {
            Err(CanonicalTreeDigestError::InvalidLimits)
        } else {
            Ok(())
        }
    }
}

/// One already-hashed regular file in a toolchain-owned directory component.
/// Records must be strictly ordered by their portable component-relative path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalTreeRecord<'a> {
    pub path: &'a str,
    pub bytes: u64,
    pub digest: Sha256Digest,
}

/// Canonical identity and declared content size of one complete directory
/// tree. `content_bytes` is the checked sum of regular-file lengths, not the
/// size of the digest metadata stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalTreeMeasurement {
    pub digest: Sha256Digest,
    pub content_bytes: u64,
    pub records: u32,
}

/// Hash a complete, already-observed directory tree without concatenating its
/// file contents or metadata into an allocation-sized buffer.
///
/// Paths use a deliberately narrow ASCII portable spelling because these are
/// distribution-owned paths, not user package paths. The filesystem observer
/// must reject symlinks, non-regular entries, undeclared replacement, and
/// per-file digest mismatches before supplying these records.
pub fn canonical_tree_digest(
    records: &[CanonicalTreeRecord<'_>],
    hasher: &dyn ContentHasher,
    limits: CanonicalTreeLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<CanonicalTreeMeasurement, CanonicalTreeDigestError> {
    check_tree_cancelled(is_cancelled)?;
    limits.validate()?;
    let record_count =
        u32::try_from(records.len()).map_err(|_| CanonicalTreeDigestError::ResourceLimit {
            resource: "canonical tree records",
            limit: u64::from(limits.records),
        })?;
    if record_count == 0 {
        return Err(CanonicalTreeDigestError::NonCanonicalInput);
    }
    if record_count > limits.records {
        return Err(CanonicalTreeDigestError::ResourceLimit {
            resource: "canonical tree records",
            limit: u64::from(limits.records),
        });
    }

    let mut path_bytes = 0u64;
    let mut content_bytes = 0u64;
    let mut metadata_bytes = 20u64;
    let mut previous_path = None;
    for record in records {
        check_tree_cancelled(is_cancelled)?;
        if !canonical_tree_path(record.path)
            || previous_path.is_some_and(|previous| previous >= record.path)
            || record.digest.as_bytes().iter().all(|byte| *byte == 0)
        {
            return Err(CanonicalTreeDigestError::NonCanonicalInput);
        }
        previous_path = Some(record.path);
        let length = u64::try_from(record.path.len()).map_err(|_| {
            CanonicalTreeDigestError::ResourceLimit {
                resource: "canonical tree path bytes",
                limit: limits.path_bytes,
            }
        })?;
        add_tree_limit(
            &mut path_bytes,
            length,
            "canonical tree path bytes",
            limits.path_bytes,
        )?;
        add_tree_limit(
            &mut content_bytes,
            record.bytes,
            "canonical tree content bytes",
            limits.content_bytes,
        )?;
        let record_metadata = 8u64
            .checked_add(length)
            .and_then(|bytes| bytes.checked_add(8 + 32))
            .ok_or(CanonicalTreeDigestError::ResourceLimit {
                resource: "canonical tree metadata bytes",
                limit: limits.metadata_bytes,
            })?;
        add_tree_limit(
            &mut metadata_bytes,
            record_metadata,
            "canonical tree metadata bytes",
            limits.metadata_bytes,
        )?;
    }
    if content_bytes == 0 {
        return Err(CanonicalTreeDigestError::NonCanonicalInput);
    }

    let mut digest = hasher.begin_sha256();
    digest.update(CANONICAL_TREE_MAGIC);
    digest.update(&CANONICAL_TREE_DIGEST_VERSION.to_le_bytes());
    update_u64(&mut *digest, u64::from(record_count));
    for record in records {
        check_tree_cancelled(is_cancelled)?;
        update_bytes_cancellable(&mut *digest, record.path.as_bytes(), is_cancelled)
            .map_err(|()| CanonicalTreeDigestError::Cancelled)?;
        update_u64(&mut *digest, record.bytes);
        digest.update(record.digest.as_bytes());
    }
    check_tree_cancelled(is_cancelled)?;
    Ok(CanonicalTreeMeasurement {
        digest: digest.finish(),
        content_bytes,
        records: record_count,
    })
}

fn canonical_tree_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_SOURCE_PATH_BYTES
        && path.is_ascii()
        && !path.starts_with('/')
        && !path.ends_with('/')
        && path.split('/').all(|component| {
            !component.is_empty()
                && !matches!(component, "." | "..")
                && !component.ends_with('.')
                && component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
                && !windows_reserved_tree_component(component)
        })
}

fn windows_reserved_tree_component(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component);
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    RESERVED
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
}

fn check_tree_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), CanonicalTreeDigestError> {
    if is_cancelled() {
        Err(CanonicalTreeDigestError::Cancelled)
    } else {
        Ok(())
    }
}

fn add_tree_limit(
    total: &mut u64,
    amount: u64,
    resource: &'static str,
    limit: u64,
) -> Result<(), CanonicalTreeDigestError> {
    let next = total
        .checked_add(amount)
        .ok_or(CanonicalTreeDigestError::ResourceLimit { resource, limit })?;
    if next > limit {
        return Err(CanonicalTreeDigestError::ResourceLimit { resource, limit });
    }
    *total = next;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalTreeDigestError {
    Cancelled,
    InvalidLimits,
    NonCanonicalInput,
    ResourceLimit { resource: &'static str, limit: u64 },
}

impl fmt::Display for CanonicalTreeDigestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("canonical tree hashing was cancelled"),
            Self::InvalidLimits => formatter.write_str(
                "canonical tree limits must be nonzero and within revision-0.1 hard ceilings",
            ),
            Self::NonCanonicalInput => formatter.write_str(
                "canonical tree records are empty, unordered, duplicated, nonportable, or invalid",
            ),
            Self::ResourceLimit { resource, limit } => {
                write!(
                    formatter,
                    "canonical tree exceeded {resource} limit {limit}"
                )
            }
        }
    }
}

impl std::error::Error for CanonicalTreeDigestError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestCodecLimits {
    pub bytes: u64,
    pub string_bytes: u64,
    pub modules: u32,
    pub dependencies: u32,
    pub profiles: u32,
    pub images: u32,
    pub image_tests: u32,
}

impl ManifestCodecLimits {
    pub fn validate(self) -> Result<(), DecodeError> {
        if self.bytes == 0 || self.string_bytes == 0 {
            Err(DecodeError::InvalidLimits)
        } else {
            Ok(())
        }
    }
}

/// Schema codec for `wrela.toml`. The production loader owns a canonical TOML
/// implementation; this trait permits isolated deterministic fixtures without
/// filesystem or parser coupling.
pub trait PackageCodec {
    fn decode_manifest(
        &self,
        bytes: &[u8],
        limits: ManifestCodecLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<PackageManifest, DecodeError>;
    fn canonical_manifest(
        &self,
        manifest: &PackageManifest,
        limits: ManifestCodecLimits,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, DecodeError>;
}

pub struct LoadRequest<'a> {
    pub root_locator: PackageLocator,
    pub root_manifest_bytes: &'a [u8],
    /// Locator for the reserved `core` alias's package bytes. The root
    /// manifest names the package and exact version it requires; only which
    /// concrete bytes back that alias is a driver decision (never inferred
    /// from the package name), matching
    /// `docs/language/02-source-language.md` §2.1.
    pub core_locator: PackageLocator,
    pub provider: &'a dyn PackageSourceProvider,
    pub hasher: &'a dyn ContentHasher,
    pub codec: &'a dyn PackageCodec,
    pub limits: LoadLimits,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedManifestInput {
    pub identity: PackageIdentity,
    pub locator: PackageLocator,
    pub manifest_digest: Sha256Digest,
    pub manifest: PackageManifest,
    pub canonical_manifest: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedManifest {
    identity: PackageIdentity,
    locator: PackageLocator,
    manifest_digest: Sha256Digest,
    manifest: PackageManifest,
}

impl LoadedManifest {
    #[must_use]
    pub fn identity(&self) -> &PackageIdentity {
        &self.identity
    }

    #[must_use]
    pub fn locator(&self) -> &PackageLocator {
        &self.locator
    }

    #[must_use]
    pub fn manifest_digest(&self) -> Sha256Digest {
        self.manifest_digest
    }

    #[must_use]
    pub fn manifest(&self) -> &PackageManifest {
        &self.manifest
    }
}

/// Complete immutable package-loading output. `source_graph_digest` covers
/// every manifest and every source and scenario `(package, path, digest)`
/// tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedWorkspace {
    graph: PackageGraph,
    sources: SourceDatabase,
    manifests: Vec<LoadedManifest>,
    /// Declared scenario files in canonical `(package, path)` order. Their
    /// digests and paths participate in `source_graph_digest`.
    scenarios: Vec<ScenarioInput>,
    source_graph_digest: Sha256Digest,
}

impl LoadedWorkspace {
    #[must_use]
    pub fn graph(&self) -> &PackageGraph {
        &self.graph
    }

    #[must_use]
    pub fn sources(&self) -> &SourceDatabase {
        &self.sources
    }

    #[must_use]
    pub fn manifests(&self) -> &[LoadedManifest] {
        &self.manifests
    }

    #[must_use]
    pub fn root_manifest(&self) -> &PackageManifest {
        // The loader seal requires one manifest per graph package in package-ID
        // order, and the package graph fixes the root at ID zero.
        self.manifests[0].manifest()
    }

    #[must_use]
    pub fn image(&self, name: &str) -> Option<&wrela_package::ImageDeclaration> {
        self.root_manifest()
            .images
            .binary_search_by(|image| image.name.as_str().cmp(name))
            .ok()
            .and_then(|index| self.root_manifest().images.get(index))
    }

    #[must_use]
    pub fn profile(&self, name: &str) -> Option<&wrela_build_model::BuildProfile> {
        self.root_manifest()
            .profiles
            .binary_search_by(|profile| profile.name.as_str().cmp(name))
            .ok()
            .and_then(|index| self.root_manifest().profiles.get(index))
    }

    #[must_use]
    pub fn scenarios(&self) -> &[ScenarioInput] {
        &self.scenarios
    }

    #[must_use]
    pub fn source_graph_digest(&self) -> Sha256Digest {
        self.source_graph_digest
    }

    /// Consume the loader product when the frontend advances from parsing to
    /// HIR. This moves image-sized graph/source storage instead of cloning it.
    #[must_use]
    pub fn into_parts(self) -> LoadedWorkspaceParts {
        LoadedWorkspaceParts {
            graph: self.graph,
            sources: self.sources,
            manifests: self.manifests,
            scenarios: self.scenarios,
            source_graph_digest: self.source_graph_digest,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedWorkspaceParts {
    pub graph: PackageGraph,
    pub sources: SourceDatabase,
    pub manifests: Vec<LoadedManifest>,
    pub scenarios: Vec<ScenarioInput>,
    pub source_graph_digest: Sha256Digest,
}

/// Candidate products assembled by a loader implementation. The sealer binds
/// all members to the original request before producing `LoadedWorkspace`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedWorkspaceCandidate {
    pub graph: PackageGraph,
    pub sources: SourceDatabase,
    pub manifests: Vec<LoadedManifestInput>,
    pub scenarios: Vec<ScenarioInput>,
}

/// Confirm a package's graph edges are exactly its manifest-declared
/// dependencies (same alias, same target package name, and a target version
/// satisfying the declared exact requirement). There is no lockfile to also
/// cross-check against; the manifest is the sole source of truth.
fn candidate_dependencies_match(
    graph: &PackageGraph,
    package: &wrela_package::PackageRecord,
    manifest: &PackageManifest,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<bool, LoadError> {
    if package.dependencies.len() != manifest.dependencies.len() {
        return Ok(false);
    }
    for (graph_edge, manifest_edge) in package.dependencies.iter().zip(&manifest.dependencies) {
        if is_cancelled() {
            return Err(LoadError::Cancelled);
        }
        let Some(dependency) = graph.package(graph_edge.package) else {
            return Ok(false);
        };
        if graph_edge.alias != manifest_edge.alias
            || manifest_edge.package != dependency.identity.name
            || exact_requirement_version(&manifest_edge.requirement)
                .is_none_or(|version| version != dependency.identity.version)
        {
            return Ok(false);
        }
    }
    if is_cancelled() {
        return Err(LoadError::Cancelled);
    }
    Ok(true)
}

fn validate_candidate_manifest_shape(
    manifest: &PackageManifest,
    limits: ManifestCodecLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LoadError> {
    for (resource, count, limit) in [
        (
            "manifest dependencies",
            manifest.dependencies.len(),
            limits.dependencies,
        ),
        (
            "manifest profiles",
            manifest.profiles.len(),
            limits.profiles,
        ),
        ("manifest images", manifest.images.len(), limits.images),
        (
            "manifest image tests",
            manifest.image_tests.len(),
            limits.image_tests,
        ),
    ] {
        let count = u64::try_from(count).map_err(|_| LoadError::ResourceLimit {
            resource,
            limit: u64::from(limit),
        })?;
        if count > u64::from(limit) {
            return Err(LoadError::ResourceLimit {
                resource,
                limit: u64::from(limit),
            });
        }
    }
    if manifest.source_root.len() > 4096 {
        return Err(LoadError::InvalidOutput(
            "candidate source root exceeds the semantic limit".to_owned(),
        ));
    }
    for dependency in &manifest.dependencies {
        if is_cancelled() {
            return Err(LoadError::Cancelled);
        }
        // An exact requirement is `=` plus a `PackageVersion`, whose validated
        // payload is at most 255 bytes. Reject oversized alternate-loader
        // models before model validation would clone the whole value.
        if dependency.requirement.len() > 256 {
            return Err(LoadError::InvalidOutput(
                "candidate dependency requirement exceeds the semantic limit".to_owned(),
            ));
        }
    }
    for name in manifest
        .profiles
        .iter()
        .map(|profile| profile.name.as_str())
    {
        if is_cancelled() {
            return Err(LoadError::Cancelled);
        }
        if name.len() > 4096 {
            return Err(LoadError::InvalidOutput(
                "candidate manifest name exceeds the semantic limit".to_owned(),
            ));
        }
    }
    for image in &manifest.images {
        if is_cancelled() {
            return Err(LoadError::Cancelled);
        }
        if [&image.name, &image.entry, &image.profile]
            .into_iter()
            .any(|value| value.len() > 4096)
        {
            return Err(LoadError::InvalidOutput(
                "candidate image text exceeds the semantic limit".to_owned(),
            ));
        }
    }
    for test in &manifest.image_tests {
        if is_cancelled() {
            return Err(LoadError::Cancelled);
        }
        if [&test.name, &test.image, &test.scenario]
            .into_iter()
            .any(|value| value.len() > 4096)
        {
            return Err(LoadError::InvalidOutput(
                "candidate image-test text exceeds the semantic limit".to_owned(),
            ));
        }
    }
    if is_cancelled() {
        return Err(LoadError::Cancelled);
    }
    Ok(())
}

/// Cross-check and seal the complete loader output. This is the only
/// constructor for `LoadedWorkspace`; no downstream phase can observe a graph,
/// source database, manifest set, scenario set, or digest assembled from
/// different acquisitions.
pub fn seal_loaded_workspace(
    request: &LoadRequest<'_>,
    candidate: LoadedWorkspaceCandidate,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<LoadedWorkspace, LoadError> {
    if is_cancelled() {
        return Err(LoadError::Cancelled);
    }
    let LoadedWorkspaceCandidate {
        graph,
        sources,
        manifests,
        scenarios,
    } = candidate;
    let limits = request.limits;
    let hasher = request.hasher;
    let codec = request.codec;
    limits.validate()?;
    let entry_limit = u32::try_from(limits.manifest_bytes_per_package).unwrap_or(u32::MAX);
    let manifest_codec_limits = ManifestCodecLimits {
        bytes: limits.manifest_bytes_per_package,
        string_bytes: limits.manifest_bytes_per_package,
        modules: limits.sources.min(entry_limit),
        dependencies: entry_limit,
        profiles: entry_limit,
        images: entry_limit,
        image_tests: limits.scenarios.min(entry_limit),
    };
    let root_manifest_bytes =
        u64::try_from(request.root_manifest_bytes.len()).map_err(|_| LoadError::ResourceLimit {
            resource: "root manifest bytes",
            limit: limits.manifest_bytes_per_package,
        })?;
    if root_manifest_bytes > limits.manifest_bytes_per_package {
        return Err(LoadError::ResourceLimit {
            resource: "root manifest bytes",
            limit: limits.manifest_bytes_per_package,
        });
    }
    wrela_package::validate_locator(&request.root_locator).map_err(|error| {
        LoadError::Manifest(bounded_load_error_value(&format!(
            "invalid root locator: {error}"
        )))
    })?;
    wrela_package::validate_locator(&request.core_locator).map_err(|error| {
        LoadError::Manifest(bounded_load_error_value(&format!(
            "invalid core locator: {error}"
        )))
    })?;
    // The seal repeats the raw-byte snapshot immediately before it re-decodes
    // the original root request. Canonical semantic identity is checked
    // independently below, so equivalent TOML spellings remain valid.
    let _raw_requested_manifest_digest =
        sha256_cancellable(hasher, request.root_manifest_bytes, is_cancelled)
            .map_err(|_| LoadError::Cancelled)?;
    let requested_manifest = codec
        .decode_manifest(
            request.root_manifest_bytes,
            manifest_codec_limits,
            is_cancelled,
        )
        .map_err(map_root_decode_error)?;
    if is_cancelled() {
        return Err(LoadError::Cancelled);
    }

    let package_limit = u64::from(limits.packages);
    let source_limit = u64::from(limits.sources);
    let scenario_limit = u64::from(limits.scenarios);
    for (resource, count, limit) in [
        ("graph packages", graph.packages().len(), package_limit),
        ("graph modules", graph.modules().len(), source_limit),
        ("source records", sources.len(), source_limit),
        ("manifest records", manifests.len(), package_limit),
        ("scenario records", scenarios.len(), scenario_limit),
    ] {
        let count =
            u64::try_from(count).map_err(|_| LoadError::ResourceLimit { resource, limit })?;
        if count > limit {
            return Err(LoadError::ResourceLimit { resource, limit });
        }
    }
    let mut candidate_source_bytes = 0u64;
    for source in sources.files() {
        if is_cancelled() {
            return Err(LoadError::Cancelled);
        }
        let bytes = u64::try_from(source.text().len()).map_err(|_| LoadError::ResourceLimit {
            resource: "candidate source bytes",
            limit: limits.source_bytes,
        })?;
        candidate_source_bytes =
            candidate_source_bytes
                .checked_add(bytes)
                .ok_or(LoadError::ResourceLimit {
                    resource: "candidate source bytes",
                    limit: limits.source_bytes,
                })?;
        if candidate_source_bytes > limits.source_bytes {
            return Err(LoadError::ResourceLimit {
                resource: "candidate source bytes",
                limit: limits.source_bytes,
            });
        }
    }
    let mut candidate_scenario_bytes = 0u64;
    for scenario in &scenarios {
        if is_cancelled() {
            return Err(LoadError::Cancelled);
        }
        let bytes = u64::try_from(scenario.bytes.len()).map_err(|_| LoadError::ResourceLimit {
            resource: "candidate scenario bytes",
            limit: limits.scenario_bytes,
        })?;
        candidate_scenario_bytes =
            candidate_scenario_bytes
                .checked_add(bytes)
                .ok_or(LoadError::ResourceLimit {
                    resource: "candidate scenario bytes",
                    limit: limits.scenario_bytes,
                })?;
        if candidate_scenario_bytes > limits.scenario_bytes {
            return Err(LoadError::ResourceLimit {
                resource: "candidate scenario bytes",
                limit: limits.scenario_bytes,
            });
        }
    }
    let mut candidate_manifest_bytes = 0u64;
    for manifest in &manifests {
        if is_cancelled() {
            return Err(LoadError::Cancelled);
        }
        validate_candidate_manifest_shape(&manifest.manifest, manifest_codec_limits, is_cancelled)?;
        let bytes = u64::try_from(manifest.canonical_manifest.len()).map_err(|_| {
            LoadError::ResourceLimit {
                resource: "candidate canonical manifest bytes",
                limit: limits.manifest_bytes_per_package,
            }
        })?;
        if bytes > limits.manifest_bytes_per_package {
            return Err(LoadError::ResourceLimit {
                resource: "candidate canonical manifest bytes",
                limit: limits.manifest_bytes_per_package,
            });
        }
        candidate_manifest_bytes =
            candidate_manifest_bytes
                .checked_add(bytes)
                .ok_or(LoadError::ResourceLimit {
                    resource: "candidate aggregate manifest bytes",
                    limit: limits.manifest_bytes,
                })?;
        if candidate_manifest_bytes > limits.manifest_bytes {
            return Err(LoadError::ResourceLimit {
                resource: "candidate aggregate manifest bytes",
                limit: limits.manifest_bytes,
            });
        }
    }
    let root_index = usize::try_from(graph.root().0)
        .map_err(|_| LoadError::InvalidOutput("root package ID does not fit usize".to_owned()))?;
    let root_input = manifests.get(root_index);
    if graph.packages().is_empty()
        || manifests.len() != graph.packages().len()
        || root_input.is_none_or(|root| {
            root.locator != request.root_locator || root.manifest != requested_manifest
        })
    {
        return Err(LoadError::InvalidOutput(
            "package, source, manifest, or root set differs".to_owned(),
        ));
    }

    let mut loaded_manifests = try_loader_vec(
        manifests.len(),
        "sealed manifest records",
        u64::from(limits.packages),
    )?;
    let mut canonical_manifests = try_loader_vec(
        manifests.len(),
        "canonical manifest records",
        u64::from(limits.packages),
    )?;
    let mut total_manifest_bytes = 0u64;
    for (package, candidate) in graph.packages().iter().zip(manifests) {
        if is_cancelled() {
            return Err(LoadError::Cancelled);
        }
        let canonical = codec
            .canonical_manifest(&candidate.manifest, manifest_codec_limits, is_cancelled)
            .map_err(map_candidate_manifest_error)?;
        let canonical_len =
            u64::try_from(canonical.len()).map_err(|_| LoadError::ResourceLimit {
                resource: "encoded canonical manifest bytes",
                limit: limits.manifest_bytes_per_package,
            })?;
        if canonical_len > limits.manifest_bytes_per_package {
            return Err(LoadError::ResourceLimit {
                resource: "encoded canonical manifest bytes",
                limit: limits.manifest_bytes_per_package,
            });
        }
        candidate.manifest.validate().map_err(|error| {
            LoadError::InvalidOutput(bounded_load_error_value(&format!(
                "invalid manifest: {error}"
            )))
        })?;
        let canonical_digest = sha256_cancellable(hasher, &canonical, is_cancelled)
            .map_err(|_| LoadError::Cancelled)?;
        let dependency_sets_match =
            candidate_dependencies_match(&graph, package, &candidate.manifest, is_cancelled)?;
        // There is no lockfile to also cross-check the locator against; the
        // package is either the root (bound to `root_locator`) or the sole
        // `core` dependency (bound to `core_locator`), both caller-supplied.
        let expected_locator = if package.id == graph.root() {
            &request.root_locator
        } else {
            &request.core_locator
        };
        total_manifest_bytes = total_manifest_bytes
            .checked_add(canonical_len)
            .ok_or_else(|| LoadError::InvalidOutput("manifest byte total overflow".to_owned()))?;
        if package.identity != candidate.identity
            || candidate.identity.name != candidate.manifest.name
            || candidate.identity.version != candidate.manifest.version
            || canonical != candidate.canonical_manifest
            || canonical_len > limits.manifest_bytes_per_package
            || total_manifest_bytes > limits.manifest_bytes
            || canonical_digest != candidate.manifest_digest
            || !dependency_sets_match
            || candidate.locator != *expected_locator
        {
            return Err(LoadError::InvalidOutput(bounded_load_error_value(
                &format!(
                    "manifest for {}@{} differs from graph, canonical bytes, digest, or locator",
                    candidate.identity.name.as_str(),
                    candidate.identity.version.as_str()
                ),
            )));
        }
        loaded_manifests.push(LoadedManifest {
            identity: candidate.identity,
            locator: candidate.locator,
            manifest_digest: candidate.manifest_digest,
            manifest: candidate.manifest,
        });
        canonical_manifests.push(canonical);
    }

    if graph.modules().len() != sources.len() {
        return Err(LoadError::InvalidOutput(
            "module graph does not cover each source exactly once".to_owned(),
        ));
    }
    let mut covered_source_ids = try_loader_vec(
        sources.len(),
        "source coverage bitmap",
        u64::from(limits.sources),
    )?;
    covered_source_ids.resize(sources.len(), false);
    for module in graph.modules() {
        if is_cancelled() {
            return Err(LoadError::Cancelled);
        }
        let source_index = usize::try_from(module.source.0)
            .map_err(|_| LoadError::InvalidOutput("source ID does not fit usize".to_owned()))?;
        let Some(covered) = covered_source_ids.get_mut(source_index) else {
            return Err(LoadError::InvalidOutput(
                "module source ID is outside the source database".to_owned(),
            ));
        };
        if std::mem::replace(covered, true) {
            return Err(LoadError::InvalidOutput(
                "module graph uses one source more than once".to_owned(),
            ));
        }
    }
    // Equal cardinality plus one unique in-range ID per module proves complete
    // dense coverage without another non-cancellable full scan.
    drop(covered_source_ids);
    let mut source_bytes = 0u64;
    let package_count = graph.packages().len();
    let mut package_bytes = try_loader_vec(
        package_count,
        "per-package byte totals",
        u64::from(limits.packages),
    )?;
    package_bytes.resize(package_count, 0u64);
    let mut package_records = try_loader_vec(
        package_count,
        "per-package content record sets",
        u64::from(limits.packages),
    )?;
    let content_record_limit =
        u64::from(limits.sources).saturating_add(u64::from(limits.scenarios));
    // Modules are not declared by the manifest, so per-package module counts
    // come from the graph (already sorted by `(package, path)`) rather than a
    // manifest-side module list.
    let mut package_module_counts = try_loader_vec(
        package_count,
        "per-package module counts",
        u64::from(limits.packages),
    )?;
    package_module_counts.resize(package_count, 0usize);
    for module in graph.modules() {
        if is_cancelled() {
            return Err(LoadError::Cancelled);
        }
        let package_index = usize::try_from(module.package.0)
            .map_err(|_| LoadError::InvalidOutput("package ID does not fit usize".to_owned()))?;
        let count = package_module_counts
            .get_mut(package_index)
            .ok_or_else(|| LoadError::InvalidOutput("module package ID is not dense".to_owned()))?;
        *count = count
            .checked_add(1)
            .ok_or_else(|| LoadError::InvalidOutput("package module count overflow".to_owned()))?;
    }
    for (loaded, module_count) in loaded_manifests.iter().zip(&package_module_counts) {
        if is_cancelled() {
            return Err(LoadError::Cancelled);
        }
        let capacity = module_count
            .checked_add(loaded.manifest.image_tests.len())
            .ok_or(LoadError::ResourceLimit {
                resource: "per-package content records",
                limit: content_record_limit,
            })?;
        package_records.push(try_loader_vec(
            capacity,
            "per-package content records",
            content_record_limit,
        )?);
    }
    for (index, canonical) in canonical_manifests.iter().enumerate() {
        let bytes = u64::try_from(canonical.len()).map_err(|_| {
            LoadError::InvalidOutput("manifest byte count does not fit u64".to_owned())
        })?;
        let package_total = package_bytes.get_mut(index).ok_or_else(|| {
            LoadError::InvalidOutput("canonical manifest package is missing".to_owned())
        })?;
        *package_total = bytes;
    }
    // Modules are not declared by the manifest: the expected relative source
    // path is a pure function of the graph-assigned module path (segments
    // joined by `/`, `.wr` appended). This mirrors the derivation the loader
    // itself performed when it built these modules from a source-root walk.
    let mut module_relative_paths = try_loader_vec(
        graph.modules().len(),
        "module relative source paths",
        u64::from(limits.sources),
    )?;
    for module in graph.modules() {
        if is_cancelled() {
            return Err(LoadError::Cancelled);
        }
        module_relative_paths.push(module.path.expected_source_path());
    }
    for (module_index, module) in graph.modules().iter().enumerate() {
        if is_cancelled() {
            return Err(LoadError::Cancelled);
        }
        graph.package(module.package).ok_or_else(|| {
            LoadError::InvalidOutput("module refers to an unknown package".to_owned())
        })?;
        let package_index = usize::try_from(module.package.0)
            .map_err(|_| LoadError::InvalidOutput("package ID does not fit usize".to_owned()))?;
        let loaded = loaded_manifests
            .get(package_index)
            .ok_or_else(|| LoadError::InvalidOutput("module manifest is missing".to_owned()))?;
        let relative_path = module_relative_paths.get(module_index).ok_or_else(|| {
            LoadError::InvalidOutput("module relative source path is missing".to_owned())
        })?;
        let source = sources
            .get(module.source)
            .ok_or_else(|| LoadError::InvalidOutput("module source ID is missing".to_owned()))?;
        let expected_path = qualified_source_path(
            &loaded.identity,
            &loaded.manifest.source_root,
            relative_path,
        )?;
        let bytes = u64::try_from(source.text().len()).map_err(|_| {
            LoadError::InvalidOutput("source byte count does not fit u64".to_owned())
        })?;
        let source_digest = sha256_cancellable(hasher, source.text().as_bytes(), is_cancelled)
            .map_err(|_| LoadError::Cancelled)?;
        source_bytes = source_bytes
            .checked_add(bytes)
            .ok_or_else(|| LoadError::InvalidOutput("source byte total overflow".to_owned()))?;
        let package_total = package_bytes
            .get_mut(package_index)
            .ok_or_else(|| LoadError::InvalidOutput("module package ID is not dense".to_owned()))?;
        *package_total = package_total.checked_add(bytes).ok_or_else(|| {
            LoadError::InvalidOutput("package source byte total overflow".to_owned())
        })?;
        if source.path() != expected_path || source_digest != source.digest() {
            return Err(LoadError::InvalidOutput(bounded_load_error_value(
                &format!(
                    "source {} differs from its declaration or digest",
                    source.path()
                ),
            )));
        }
        package_records
            .get_mut(package_index)
            .ok_or_else(|| {
                LoadError::InvalidOutput("module package content set is missing".to_owned())
            })?
            .push(PackageContentRecord {
                kind: PackageContentKind::Source,
                path: relative_path,
                digest: source.digest(),
            });
    }
    if source_bytes > limits.source_bytes {
        return Err(LoadError::ResourceLimit {
            resource: "source graph bytes",
            limit: limits.source_bytes,
        });
    }

    if u64::try_from(scenarios.len()).unwrap_or(u64::MAX) > u64::from(limits.scenarios) {
        return Err(LoadError::ResourceLimit {
            resource: "scenario records",
            limit: u64::from(limits.scenarios),
        });
    }
    let mut declared_scenarios = BTreeSet::<(&PackageIdentity, &str)>::new();
    let mut package_indices = BTreeMap::new();
    let mut declared_image_tests = 0u64;
    for (index, loaded) in loaded_manifests.iter().enumerate() {
        if is_cancelled() {
            return Err(LoadError::Cancelled);
        }
        if package_indices.insert(&loaded.identity, index).is_some() {
            return Err(LoadError::InvalidOutput(
                "loaded manifest identities are duplicated".to_owned(),
            ));
        }
        // Multiple image tests may intentionally reuse one declared scenario
        // file; the sealed input set contains that file exactly once.
        for test in &loaded.manifest.image_tests {
            if is_cancelled() {
                return Err(LoadError::Cancelled);
            }
            declared_image_tests =
                declared_image_tests
                    .checked_add(1)
                    .ok_or(LoadError::ResourceLimit {
                        resource: "declared image tests",
                        limit: u64::from(limits.scenarios),
                    })?;
            if declared_image_tests > u64::from(limits.scenarios) {
                return Err(LoadError::ResourceLimit {
                    resource: "declared image tests",
                    limit: u64::from(limits.scenarios),
                });
            }
            declared_scenarios.insert((&loaded.identity, test.scenario.as_str()));
        }
    }
    for pair in scenarios.windows(2) {
        if is_cancelled() {
            return Err(LoadError::Cancelled);
        }
        if (&pair[0].package, &pair[0].path) >= (&pair[1].package, &pair[1].path) {
            return Err(LoadError::InvalidOutput(
                "scenario inputs are duplicated or not canonical".to_owned(),
            ));
        }
    }
    let mut scenario_bytes = 0u64;
    for scenario in &scenarios {
        if is_cancelled() {
            return Err(LoadError::Cancelled);
        }
        let Some(&package_index) = package_indices.get(&scenario.package) else {
            return Err(LoadError::InvalidOutput(
                "scenario belongs to an unknown package".to_owned(),
            ));
        };
        if !declared_scenarios.remove(&(&scenario.package, scenario.path.as_str())) {
            return Err(LoadError::InvalidOutput(
                "scenario is duplicated or was not declared by its package".to_owned(),
            ));
        }
        if scenario.path.trim().is_empty() || !is_utf8_cancellable(&scenario.bytes, is_cancelled)? {
            return Err(LoadError::InvalidOutput(
                "scenario path is empty or its bytes are not UTF-8".to_owned(),
            ));
        }
        let bytes = u64::try_from(scenario.bytes.len()).map_err(|_| {
            LoadError::InvalidOutput("scenario byte count does not fit u64".to_owned())
        })?;
        let scenario_digest = sha256_cancellable(hasher, &scenario.bytes, is_cancelled)
            .map_err(|_| LoadError::Cancelled)?;
        if scenario_digest != scenario.digest {
            return Err(LoadError::InvalidOutput(
                "scenario bytes differ from their digest".to_owned(),
            ));
        }
        scenario_bytes = scenario_bytes
            .checked_add(bytes)
            .ok_or_else(|| LoadError::InvalidOutput("scenario byte total overflow".to_owned()))?;
        let package_total = package_bytes.get_mut(package_index).ok_or_else(|| {
            LoadError::InvalidOutput("scenario package ID is not dense".to_owned())
        })?;
        *package_total = package_total.checked_add(bytes).ok_or_else(|| {
            LoadError::InvalidOutput("package scenario byte total overflow".to_owned())
        })?;
        package_records
            .get_mut(package_index)
            .ok_or_else(|| {
                LoadError::InvalidOutput("scenario package content set is missing".to_owned())
            })?
            .push(PackageContentRecord {
                kind: PackageContentKind::Scenario,
                path: &scenario.path,
                digest: scenario.digest,
            });
    }
    if !declared_scenarios.is_empty() || scenario_bytes > limits.scenario_bytes {
        return Err(LoadError::InvalidOutput(
            "scenario set, order, size, declaration, or digest differs".to_owned(),
        ));
    }
    for bytes in &package_bytes {
        if is_cancelled() {
            return Err(LoadError::Cancelled);
        }
        if *bytes > limits.bytes_per_package {
            return Err(LoadError::ResourceLimit {
                resource: "package bytes",
                limit: limits.bytes_per_package,
            });
        }
    }

    for (index, records) in package_records.iter_mut().enumerate() {
        if is_cancelled() {
            return Err(LoadError::Cancelled);
        }
        let canonical = canonical_manifests.get(index).ok_or_else(|| {
            LoadError::InvalidOutput("canonical package manifest is missing".to_owned())
        })?;
        let actual =
            package_content_digest(canonical, records, hasher, is_cancelled).map_err(|error| {
                match error {
                    PackageContentDigestError::Cancelled => LoadError::Cancelled,
                    PackageContentDigestError::NonCanonicalInput => LoadError::InvalidOutput(
                        "package content records are not canonical".to_owned(),
                    ),
                }
            })?;
        let loaded = loaded_manifests.get(index).ok_or_else(|| {
            LoadError::InvalidOutput("loaded package manifest is missing".to_owned())
        })?;
        let expected = loaded.identity.source_digest;
        if actual != expected {
            return Err(LoadError::DigestMismatch {
                subject: bounded_load_error_value(&format!(
                    "package {}@{} content",
                    loaded.identity.name.as_str(),
                    loaded.identity.version.as_str()
                )),
                expected,
                actual,
            });
        }
    }
    drop(package_records);

    let source_graph_digest = hash_source_graph(
        SourceGraphHashInput {
            graph: &graph,
            sources: &sources,
            manifests: &loaded_manifests,
            scenarios: &scenarios,
        },
        hasher,
        is_cancelled,
    )?;
    Ok(LoadedWorkspace {
        graph,
        sources,
        manifests: loaded_manifests,
        scenarios,
        source_graph_digest,
    })
}

#[must_use = "qualified source path construction can fail its finite allocation bound"]
pub fn qualified_source_path(
    package: &PackageIdentity,
    source_root: &str,
    source_path: &str,
) -> Result<String, LoadError> {
    let name_bytes =
        package
            .name
            .as_str()
            .len()
            .checked_mul(2)
            .ok_or(LoadError::ResourceLimit {
                resource: "qualified source path bytes",
                limit: u64::try_from(MAX_SOURCE_PATH_BYTES).unwrap_or(u64::MAX),
            })?;
    let version_bytes =
        package
            .version
            .as_str()
            .len()
            .checked_mul(2)
            .ok_or(LoadError::ResourceLimit {
                resource: "qualified source path bytes",
                limit: u64::try_from(MAX_SOURCE_PATH_BYTES).unwrap_or(u64::MAX),
            })?;
    let length = 9usize
        .checked_add(name_bytes)
        .and_then(|length| length.checked_add(1))
        .and_then(|length| length.checked_add(version_bytes))
        .and_then(|length| length.checked_add(1 + 64 + 1))
        .and_then(|length| length.checked_add(source_root.len()))
        .and_then(|length| length.checked_add(1))
        .and_then(|length| length.checked_add(source_path.len()))
        .ok_or(LoadError::ResourceLimit {
            resource: "qualified source path bytes",
            limit: u64::try_from(MAX_SOURCE_PATH_BYTES).unwrap_or(u64::MAX),
        })?;
    if length > MAX_SOURCE_PATH_BYTES {
        return Err(LoadError::ResourceLimit {
            resource: "qualified source path bytes",
            limit: u64::try_from(MAX_SOURCE_PATH_BYTES).unwrap_or(u64::MAX),
        });
    }
    let mut output = String::new();
    output
        .try_reserve_exact(length)
        .map_err(|_| LoadError::ResourceLimit {
            resource: "qualified source path bytes",
            limit: u64::try_from(MAX_SOURCE_PATH_BYTES).unwrap_or(u64::MAX),
        })?;
    output.push_str("packages/");
    push_hex_bytes(&mut output, package.name.as_str().as_bytes());
    output.push('/');
    push_hex_bytes(&mut output, package.version.as_str().as_bytes());
    output.push('/');
    push_hex_bytes(&mut output, package.source_digest.as_bytes());
    output.push('/');
    output.push_str(source_root);
    output.push('/');
    output.push_str(source_path);
    Ok(output)
}

fn push_hex_bytes(output: &mut String, bytes: &[u8]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
}

struct SourceGraphHashInput<'a> {
    graph: &'a PackageGraph,
    sources: &'a SourceDatabase,
    manifests: &'a [LoadedManifest],
    scenarios: &'a [ScenarioInput],
}

fn hash_source_graph(
    input: SourceGraphHashInput<'_>,
    hasher: &dyn ContentHasher,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Sha256Digest, LoadError> {
    let SourceGraphHashInput {
        graph,
        sources,
        manifests,
        scenarios,
    } = input;
    if is_cancelled() {
        return Err(LoadError::Cancelled);
    }
    let mut digest = hasher.begin_sha256();
    digest.update(SOURCE_GRAPH_MAGIC);
    digest.update(&SOURCE_GRAPH_DIGEST_VERSION.to_le_bytes());
    let manifest_count = u64::try_from(manifests.len())
        .map_err(|_| LoadError::InvalidOutput("manifest count does not fit u64".to_owned()))?;
    update_u64(&mut *digest, manifest_count);
    for manifest in manifests {
        if is_cancelled() {
            return Err(LoadError::Cancelled);
        }
        update_identity(&mut *digest, &manifest.identity);
        update_locator(&mut *digest, &manifest.locator);
        digest.update(manifest.manifest_digest.as_bytes());
    }
    let package_count = graph.packages().len();
    let module_start_count = package_count
        .checked_add(1)
        .ok_or_else(|| LoadError::InvalidOutput("module range count overflow".to_owned()))?;
    let mut module_starts = try_loader_vec(
        module_start_count,
        "source graph module ranges",
        u64::try_from(module_start_count).unwrap_or(u64::MAX),
    )?;
    let modules = graph.modules();
    let mut module_cursor = 0usize;
    for package_index in 0..package_count {
        if is_cancelled() {
            return Err(LoadError::Cancelled);
        }
        module_starts.push(module_cursor);
        while let Some(module) = modules.get(module_cursor) {
            if is_cancelled() {
                return Err(LoadError::Cancelled);
            }
            let module_package = usize::try_from(module.package.0).map_err(|_| {
                LoadError::InvalidOutput("module package ID does not fit usize".to_owned())
            })?;
            if module_package != package_index {
                break;
            }
            module_cursor = module_cursor.checked_add(1).ok_or_else(|| {
                LoadError::InvalidOutput("module range cursor overflow".to_owned())
            })?;
        }
    }
    module_starts.push(module_cursor);
    if module_cursor != modules.len() {
        return Err(LoadError::InvalidOutput(
            "module records are not grouped by dense package ID".to_owned(),
        ));
    }

    let module_count = u64::try_from(modules.len())
        .map_err(|_| LoadError::InvalidOutput("module count does not fit u64".to_owned()))?;
    update_u64(&mut *digest, module_count);
    // There is no lockfile order to hash against; the graph's own package
    // order (root first, then every other package in canonical identity
    // order -- see `PackageGraphBuilder::finish`) is already deterministic.
    for (package_index, package) in graph.packages().iter().enumerate() {
        if is_cancelled() {
            return Err(LoadError::Cancelled);
        }
        let start = *module_starts.get(package_index).ok_or_else(|| {
            LoadError::InvalidOutput("source graph module range is missing".to_owned())
        })?;
        let range_end_index = package_index.checked_add(1).ok_or_else(|| {
            LoadError::InvalidOutput("source graph module range overflow".to_owned())
        })?;
        let end = *module_starts.get(range_end_index).ok_or_else(|| {
            LoadError::InvalidOutput("source graph module range end is missing".to_owned())
        })?;
        for module in modules.get(start..end).ok_or_else(|| {
            LoadError::InvalidOutput("source graph module range is invalid".to_owned())
        })? {
            if is_cancelled() {
                return Err(LoadError::Cancelled);
            }
            let source = sources.get(module.source).ok_or_else(|| {
                LoadError::InvalidOutput(
                    "source graph hashing encountered a missing source".to_owned(),
                )
            })?;
            update_identity(&mut *digest, &package.identity);
            update_string(&mut *digest, source.path());
            digest.update(source.digest().as_bytes());
        }
    }
    let scenario_count = u64::try_from(scenarios.len())
        .map_err(|_| LoadError::InvalidOutput("scenario count does not fit u64".to_owned()))?;
    update_u64(&mut *digest, scenario_count);
    for scenario in scenarios {
        if is_cancelled() {
            return Err(LoadError::Cancelled);
        }
        update_identity(&mut *digest, &scenario.package);
        update_string(&mut *digest, &scenario.path);
        digest.update(scenario.digest.as_bytes());
    }
    if is_cancelled() {
        return Err(LoadError::Cancelled);
    }
    Ok(digest.finish())
}

fn update_identity(digest: &mut dyn ContentDigest, identity: &PackageIdentity) {
    update_string(digest, identity.name.as_str());
    update_string(digest, identity.version.as_str());
    digest.update(identity.source_digest.as_bytes());
}

fn update_locator(digest: &mut dyn ContentDigest, locator: &PackageLocator) {
    match locator {
        PackageLocator::Workspace { path } => {
            digest.update(&[0]);
            update_string(digest, path);
        }
        PackageLocator::Archive { provider, key } => {
            digest.update(&[1]);
            update_string(digest, provider);
            update_string(digest, key);
        }
        PackageLocator::Toolchain { component } => {
            digest.update(&[2]);
            update_string(digest, component);
        }
    }
}

fn update_string(digest: &mut dyn ContentDigest, value: &str) {
    update_bytes(digest, value.as_bytes());
}

fn update_bytes(digest: &mut dyn ContentDigest, value: &[u8]) {
    update_u64(digest, value.len() as u64);
    digest.update(value);
}

fn update_bytes_cancellable(
    digest: &mut dyn ContentDigest,
    value: &[u8],
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ()> {
    update_u64(digest, value.len() as u64);
    for chunk in value.chunks(1024 * 1024) {
        if is_cancelled() {
            return Err(());
        }
        digest.update(chunk);
    }
    if is_cancelled() {
        return Err(());
    }
    Ok(())
}

fn update_u64(digest: &mut dyn ContentDigest, value: u64) {
    digest.update(&value.to_le_bytes());
}

pub trait WorkspaceLoader {
    fn load(
        &self,
        request: LoadRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<LoadedWorkspace, LoadError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderError {
    Unavailable(String),
    AccessDenied(String),
    TooLarge { limit: u64 },
    IdentityMismatch,
    Corrupt(String),
}

pub(crate) fn bounded_provider_error(error: ProviderError) -> ProviderError {
    match error {
        ProviderError::Unavailable(message) => {
            ProviderError::Unavailable(bounded_load_error_value(&message))
        }
        ProviderError::AccessDenied(message) => {
            ProviderError::AccessDenied(bounded_load_error_value(&message))
        }
        ProviderError::Corrupt(message) => {
            ProviderError::Corrupt(bounded_load_error_value(&message))
        }
        error @ (ProviderError::TooLarge { .. } | ProviderError::IdentityMismatch) => error,
    }
}

impl fmt::Display for ProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(message) => write!(
                formatter,
                "provider is unavailable: {}",
                bounded_load_error_value(message)
            ),
            Self::AccessDenied(message) => write!(
                formatter,
                "provider denied access: {}",
                bounded_load_error_value(message)
            ),
            Self::TooLarge { limit } => {
                write!(formatter, "provider input exceeds byte limit {limit}")
            }
            Self::IdentityMismatch => formatter.write_str("provider substituted package identity"),
            Self::Corrupt(message) => write!(
                formatter,
                "provider returned corrupt input: {}",
                bounded_load_error_value(message)
            ),
        }
    }
}

impl std::error::Error for ProviderError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    Cancelled,
    InvalidLimits,
    InvalidUtf8,
    Malformed {
        byte_offset: usize,
        message: String,
    },
    DuplicateKey(String),
    UnknownField(String),
    MissingField(&'static str),
    UnsupportedValue {
        field: &'static str,
        expected: &'static str,
    },
    ResourceLimit {
        resource: &'static str,
        limit: u64,
    },
    NonCanonical(String),
    UnsupportedSchema(u32),
}

pub(crate) fn bounded_decode_error(error: DecodeError) -> DecodeError {
    match error {
        DecodeError::Malformed {
            byte_offset,
            message,
        } => DecodeError::Malformed {
            byte_offset,
            message: bounded_load_error_value(&message),
        },
        DecodeError::DuplicateKey(value) => {
            DecodeError::DuplicateKey(bounded_load_error_value(&value))
        }
        DecodeError::UnknownField(value) => {
            DecodeError::UnknownField(bounded_load_error_value(&value))
        }
        DecodeError::NonCanonical(value) => {
            DecodeError::NonCanonical(bounded_load_error_value(&value))
        }
        error => error,
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("decoding was cancelled"),
            Self::InvalidLimits => formatter.write_str("codec limits are invalid"),
            Self::InvalidUtf8 => formatter.write_str("input is not UTF-8"),
            Self::Malformed {
                byte_offset,
                message,
            } => write!(
                formatter,
                "malformed input at byte {byte_offset}: {}",
                bounded_load_error_value(message)
            ),
            Self::DuplicateKey(key) => {
                write!(formatter, "duplicate key {}", bounded_load_error_value(key))
            }
            Self::UnknownField(field) => write!(
                formatter,
                "unknown field {}",
                bounded_load_error_value(field)
            ),
            Self::MissingField(field) => write!(formatter, "missing field {field}"),
            Self::UnsupportedValue { field, expected } => {
                write!(formatter, "unsupported {field}; expected {expected}")
            }
            Self::ResourceLimit { resource, limit } => {
                write!(formatter, "{resource} exceeds limit {limit}")
            }
            Self::NonCanonical(message) => write!(
                formatter,
                "noncanonical input: {}",
                bounded_load_error_value(message)
            ),
            Self::UnsupportedSchema(schema) => write!(formatter, "unsupported schema {schema}"),
        }
    }
}

impl std::error::Error for DecodeError {}

fn map_root_decode_error(error: DecodeError) -> LoadError {
    match bounded_decode_error(error) {
        DecodeError::Cancelled => LoadError::Cancelled,
        DecodeError::InvalidLimits => LoadError::InvalidLimits,
        DecodeError::ResourceLimit { resource, limit } => {
            LoadError::ResourceLimit { resource, limit }
        }
        error => LoadError::RootManifest(error),
    }
}

fn map_candidate_manifest_error(error: DecodeError) -> LoadError {
    match error {
        DecodeError::Cancelled => LoadError::Cancelled,
        DecodeError::InvalidLimits => LoadError::InvalidLimits,
        DecodeError::ResourceLimit { resource, limit } => {
            LoadError::ResourceLimit { resource, limit }
        }
        _ => {
            LoadError::InvalidOutput("candidate manifest cannot be canonically encoded".to_owned())
        }
    }
}

pub(crate) fn bounded_source_error(error: SourceError) -> SourceError {
    match error {
        SourceError::InvalidPath(value) => {
            SourceError::InvalidPath(bounded_load_error_value(&value))
        }
        SourceError::PortablePathCollision(value) => {
            SourceError::PortablePathCollision(bounded_load_error_value(&value))
        }
        SourceError::NonCanonicalPathOrder { previous, next } => {
            SourceError::NonCanonicalPathOrder {
                previous: bounded_load_error_value(&previous),
                next: bounded_load_error_value(&next),
            }
        }
        error => error,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    Cancelled,
    InvalidLimits,
    RootManifest(DecodeError),
    PackageManifest {
        package: PackageIdentity,
        error: DecodeError,
    },
    Provider {
        package: PackageIdentity,
        error: ProviderError,
    },
    Manifest(String),
    DigestMismatch {
        subject: String,
        expected: Sha256Digest,
        actual: Sha256Digest,
    },
    UndeclaredSource(String),
    DuplicateSource(String),
    UndeclaredScenario(String),
    MissingScenario(String),
    DuplicateScenario(String),
    Source(SourceError),
    Graph(String),
    /// A producer attempted to seal mutually inconsistent loader products.
    InvalidOutput(String),
    ResourceLimit {
        resource: &'static str,
        limit: u64,
    },
}

impl fmt::Display for LoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("package loading was cancelled"),
            Self::InvalidLimits => formatter.write_str("package loading limits must be nonzero"),
            Self::RootManifest(error) => write!(formatter, "invalid root manifest: {error}"),
            Self::PackageManifest { package, error } => write!(
                formatter,
                "invalid manifest for {}@{}: {error}",
                package.name.as_str(),
                package.version.as_str()
            ),
            Self::Provider { package, error } => write!(
                formatter,
                "cannot acquire {}@{}: {error}",
                package.name.as_str(),
                package.version.as_str()
            ),
            Self::Manifest(message) => write!(
                formatter,
                "invalid package manifest: {}",
                bounded_load_error_value(message)
            ),
            Self::DigestMismatch {
                subject,
                expected,
                actual,
            } => write!(
                formatter,
                "digest mismatch for {}: expected {}, got {}",
                bounded_load_error_value(subject),
                expected.to_hex(),
                actual.to_hex()
            ),
            Self::UndeclaredSource(path) => {
                write!(
                    formatter,
                    "provider returned undeclared source {}",
                    bounded_load_error_value(path)
                )
            }
            Self::DuplicateSource(path) => {
                write!(
                    formatter,
                    "source {} was returned more than once",
                    bounded_load_error_value(path)
                )
            }
            Self::UndeclaredScenario(path) => {
                write!(
                    formatter,
                    "provider returned undeclared image scenario {}",
                    bounded_load_error_value(path)
                )
            }
            Self::MissingScenario(path) => {
                write!(
                    formatter,
                    "manifest image scenario {} is missing",
                    bounded_load_error_value(path)
                )
            }
            Self::DuplicateScenario(path) => {
                write!(
                    formatter,
                    "image scenario {} was returned more than once",
                    bounded_load_error_value(path)
                )
            }
            Self::Source(error) => {
                formatter.write_str(&bounded_load_error_value(&error.to_string()))
            }
            Self::Graph(message) => write!(
                formatter,
                "invalid package graph: {}",
                bounded_load_error_value(message)
            ),
            Self::InvalidOutput(message) => {
                write!(
                    formatter,
                    "package loader produced invalid output: {}",
                    bounded_load_error_value(message)
                )
            }
            Self::ResourceLimit { resource, limit } => {
                write!(
                    formatter,
                    "package loading exceeded {resource} limit {limit}"
                )
            }
        }
    }
}

impl std::error::Error for LoadError {}

#[cfg(test)]
mod contract_tests {
    use std::cell::Cell;

    use super::{
        CanonicalTreeDigestError, CanonicalTreeLimits, CanonicalTreeRecord, ContentHasher,
        LoadError, LoadLimits, SoftwareSha256, canonical_tree_digest,
    };

    #[test]
    fn loader_policy_separates_and_validates_manifest_budgets() {
        let limits = LoadLimits::standard();
        limits.validate().expect("standard limits");
        assert!(limits.manifest_bytes > limits.manifest_bytes_per_package);
        let mut invalid = limits;
        invalid.manifest_bytes_per_package = 0;
        assert!(matches!(invalid.validate(), Err(LoadError::InvalidLimits)));
        let mut inverted = limits;
        inverted.manifest_bytes_per_package = inverted.bytes_per_package + 1;
        assert!(matches!(inverted.validate(), Err(LoadError::InvalidLimits)));
    }

    fn tree_records() -> [CanonicalTreeRecord<'static>; 2] {
        let hasher = SoftwareSha256;
        [
            CanonicalTreeRecord {
                path: "runtime/wrela-runtime-aarch64.obj",
                bytes: 7,
                digest: hasher.sha256(b"runtime"),
            },
            CanonicalTreeRecord {
                path: "target.toml",
                bytes: 6,
                digest: hasher.sha256(b"target"),
            },
        ]
    }

    fn exact_tree_limits(records: &[CanonicalTreeRecord<'_>]) -> CanonicalTreeLimits {
        let path_bytes = records
            .iter()
            .map(|record| u64::try_from(record.path.len()).expect("path bytes"))
            .sum();
        let content_bytes = records.iter().map(|record| record.bytes).sum();
        let metadata_bytes = records.iter().fold(20u64, |total, record| {
            total + 48 + u64::try_from(record.path.len()).expect("path bytes")
        });
        CanonicalTreeLimits {
            records: u32::try_from(records.len()).expect("record count"),
            path_bytes,
            content_bytes,
            metadata_bytes,
        }
    }

    #[test]
    fn canonical_tree_digest_is_streaming_deterministic_and_identity_sensitive() {
        let records = tree_records();
        let limits = exact_tree_limits(&records);
        let measured = canonical_tree_digest(&records, &SoftwareSha256, limits, &|| false)
            .expect("canonical tree");
        assert_eq!(measured.records, 2);
        assert_eq!(measured.content_bytes, 13);
        assert_eq!(
            measured.digest.to_hex(),
            "390d76275dc9d61ed33d532844ddabd1e782c01651bbd2dc998142eef39f4a9d"
        );
        assert_eq!(
            canonical_tree_digest(&records, &SoftwareSha256, limits, &|| false)
                .expect("repeat tree"),
            measured
        );

        let mut changed = records;
        changed[0].bytes += 1;
        assert_ne!(
            canonical_tree_digest(
                &changed,
                &SoftwareSha256,
                CanonicalTreeLimits::standard(),
                &|| false,
            )
            .expect("changed tree")
            .digest,
            measured.digest
        );
        changed[0].bytes -= 1;
        changed[0].digest = SoftwareSha256.sha256(b"substituted");
        assert_ne!(
            canonical_tree_digest(
                &changed,
                &SoftwareSha256,
                CanonicalTreeLimits::standard(),
                &|| false,
            )
            .expect("changed digest tree")
            .digest,
            measured.digest
        );

        let changed_path = [
            CanonicalTreeRecord {
                path: "runtime/wrela-runtime-aarch64-v2.obj",
                ..records[0]
            },
            records[1],
        ];
        assert_ne!(
            canonical_tree_digest(
                &changed_path,
                &SoftwareSha256,
                CanonicalTreeLimits::standard(),
                &|| false,
            )
            .expect("changed path tree")
            .digest,
            measured.digest
        );
    }

    #[test]
    fn canonical_tree_digest_enforces_exact_limits_order_and_portability() {
        let records = tree_records();
        let limits = exact_tree_limits(&records);
        canonical_tree_digest(&records, &SoftwareSha256, limits, &|| false)
            .expect("exact tree limits");

        for reduced in [
            CanonicalTreeLimits {
                records: limits.records - 1,
                ..limits
            },
            CanonicalTreeLimits {
                path_bytes: limits.path_bytes - 1,
                ..limits
            },
            CanonicalTreeLimits {
                content_bytes: limits.content_bytes - 1,
                ..limits
            },
            CanonicalTreeLimits {
                metadata_bytes: limits.metadata_bytes - 1,
                ..limits
            },
        ] {
            assert!(matches!(
                canonical_tree_digest(&records, &SoftwareSha256, reduced, &|| false),
                Err(CanonicalTreeDigestError::ResourceLimit { .. })
            ));
        }

        let reversed = [records[1], records[0]];
        assert_eq!(
            canonical_tree_digest(
                &reversed,
                &SoftwareSha256,
                CanonicalTreeLimits::standard(),
                &|| false,
            ),
            Err(CanonicalTreeDigestError::NonCanonicalInput)
        );
        assert_eq!(
            canonical_tree_digest(
                &[],
                &SoftwareSha256,
                CanonicalTreeLimits::standard(),
                &|| false,
            ),
            Err(CanonicalTreeDigestError::NonCanonicalInput)
        );
        let zero_digest = [CanonicalTreeRecord {
            path: "target.toml",
            bytes: 1,
            digest: wrela_build_model::Sha256Digest::from_bytes([0; 32]),
        }];
        assert_eq!(
            canonical_tree_digest(
                &zero_digest,
                &SoftwareSha256,
                CanonicalTreeLimits::standard(),
                &|| false,
            ),
            Err(CanonicalTreeDigestError::NonCanonicalInput)
        );
        for path in [
            "../target.toml",
            "/target.toml",
            "firmware\\code.fd",
            "firmware/QEMU EFI.fd",
            "firmware/NUL.fd",
            "firmware/code.",
            "unicodé.wr",
        ] {
            let invalid = [CanonicalTreeRecord {
                path,
                bytes: 1,
                digest: SoftwareSha256.sha256(b"x"),
            }];
            assert_eq!(
                canonical_tree_digest(
                    &invalid,
                    &SoftwareSha256,
                    CanonicalTreeLimits::standard(),
                    &|| false,
                ),
                Err(CanonicalTreeDigestError::NonCanonicalInput),
                "path {path:?}"
            );
        }
    }

    #[test]
    fn canonical_tree_digest_observes_entry_and_midstream_cancellation() {
        let records = tree_records();
        assert_eq!(
            canonical_tree_digest(
                &records,
                &SoftwareSha256,
                CanonicalTreeLimits::standard(),
                &|| true,
            ),
            Err(CanonicalTreeDigestError::Cancelled)
        );

        let polls = Cell::new(0u32);
        let cancel = || {
            let next = polls.get() + 1;
            polls.set(next);
            next == 5
        };
        assert_eq!(
            canonical_tree_digest(
                &records,
                &SoftwareSha256,
                CanonicalTreeLimits::standard(),
                &cancel,
            ),
            Err(CanonicalTreeDigestError::Cancelled)
        );
        assert_eq!(polls.get(), 5);
    }
}

#[cfg(test)]
mod loader_tests {
    use std::cell::{Cell, RefCell};

    use wrela_build_model::Sha256Digest;
    use wrela_package::{
        DependencyAlias, PackageIdentity, PackageLocator, PackageName, PackageVersion,
    };
    use wrela_source::{SourceDatabase, SourceInput};

    use super::{
        CanonicalPackageCodec, CanonicalWorkspaceLoader, ContentHasher, DecodeError, LoadError,
        LoadLimits, LoadRequest, LoadedManifestInput, LoadedWorkspace, LoadedWorkspaceCandidate,
        MAX_LOAD_ERROR_VALUE_BYTES, ManifestCodecLimits, PackageBundle, PackageCodec,
        PackageContentDigestError, PackageContentKind, PackageContentRecord, PackageSourceProvider,
        ProviderError, ScenarioInput, SoftwareSha256, WorkspaceLoader, bounded_decode_error,
        bounded_provider_error, candidate_dependencies_match, is_utf8_cancellable,
        package_content_digest, seal_loaded_workspace,
    };

    struct ScenarioFixture {
        path: String,
        bytes: Vec<u8>,
        digest: Sha256Digest,
    }

    struct PackageFixture {
        identity: PackageIdentity,
        manifest_bytes: Vec<u8>,
        sources: Vec<SourceInput>,
        scenarios: Vec<ScenarioFixture>,
    }

    impl PackageFixture {
        fn new(
            manifest_bytes: &[u8],
            sources: &[(&str, &str)],
            scenarios: &[(&str, &str)],
        ) -> Self {
            let codec = CanonicalPackageCodec::new();
            let hasher = SoftwareSha256;
            let manifest = codec
                .decode_manifest(manifest_bytes, test_manifest_limits(), &never_cancelled)
                .expect("test package manifest");
            let manifest_bytes = codec
                .canonical_manifest(&manifest, test_manifest_limits(), &never_cancelled)
                .expect("canonical test package manifest");
            let sources = sources
                .iter()
                .map(|(path, text)| SourceInput {
                    path: (*path).to_owned(),
                    text: (*text).to_owned(),
                    digest: hasher.sha256(text.as_bytes()),
                })
                .collect::<Vec<_>>();
            let scenarios = scenarios
                .iter()
                .map(|(path, text)| ScenarioFixture {
                    path: (*path).to_owned(),
                    bytes: text.as_bytes().to_vec(),
                    digest: hasher.sha256(text.as_bytes()),
                })
                .collect::<Vec<_>>();
            let mut records = sources
                .iter()
                .map(|source| PackageContentRecord {
                    kind: PackageContentKind::Source,
                    path: source.path.as_str(),
                    digest: source.digest,
                })
                .chain(scenarios.iter().map(|scenario| PackageContentRecord {
                    kind: PackageContentKind::Scenario,
                    path: scenario.path.as_str(),
                    digest: scenario.digest,
                }))
                .collect::<Vec<_>>();
            records.sort_by_key(|record| (record.kind, record.path));
            let source_digest =
                package_content_digest(&manifest_bytes, &records, &hasher, &never_cancelled)
                    .expect("test package content digest");
            Self {
                identity: PackageIdentity {
                    name: manifest.name,
                    version: manifest.version,
                    source_digest,
                },
                manifest_bytes,
                sources,
                scenarios,
            }
        }

        fn bundle(&self, locator: PackageLocator) -> PackageBundle {
            PackageBundle {
                identity: self.identity.clone(),
                locator,
                manifest_bytes: self.manifest_bytes.clone(),
                sources: self.sources.clone(),
                scenarios: self
                    .scenarios
                    .iter()
                    .map(|scenario| ScenarioInput {
                        package: self.identity.clone(),
                        path: scenario.path.clone(),
                        bytes: scenario.bytes.clone(),
                        digest: scenario.digest,
                    })
                    .collect(),
            }
        }
    }

    /// Serves exactly two fixed roles -- root and the reserved `core`
    /// dependency -- routed by the *requested* locator, not by whatever a
    /// test has corrupted on the returned bundle. There is no lockfile: the
    /// loader independently recomputes and verifies each bundle's identity
    /// after acquisition (`verify_package_identity`), so this provider need
    /// not pre-validate anything beyond byte ceilings.
    struct InMemoryProvider {
        root_locator: PackageLocator,
        root_bundle: PackageBundle,
        core_locator: PackageLocator,
        core_bundle: PackageBundle,
        acquisitions: RefCell<Vec<(PackageName, PackageVersion, u64, u64)>>,
    }

    impl PackageSourceProvider for InMemoryProvider {
        fn acquire(
            &self,
            locator: &PackageLocator,
            expected_name: &PackageName,
            expected_version: &PackageVersion,
            maximum_bytes: u64,
            maximum_manifest_bytes: u64,
            is_cancelled: &dyn Fn() -> bool,
        ) -> Result<PackageBundle, ProviderError> {
            self.acquisitions.borrow_mut().push((
                expected_name.clone(),
                expected_version.clone(),
                maximum_bytes,
                maximum_manifest_bytes,
            ));
            if is_cancelled() {
                return Err(ProviderError::Unavailable("cancelled".to_owned()));
            }
            let bundle = if *locator == self.root_locator {
                &self.root_bundle
            } else if *locator == self.core_locator {
                &self.core_bundle
            } else {
                return Err(ProviderError::Unavailable(
                    "missing in-memory bundle".to_owned(),
                ));
            };
            if bundle.manifest_bytes.len() as u64 > maximum_manifest_bytes {
                return Err(ProviderError::TooLarge {
                    limit: maximum_manifest_bytes,
                });
            }
            let bytes = bundle
                .sources
                .iter()
                .try_fold(bundle.manifest_bytes.len() as u64, |total, source| {
                    total.checked_add(source.text.len() as u64)
                })
                .and_then(|total| {
                    bundle.scenarios.iter().try_fold(total, |total, scenario| {
                        total.checked_add(scenario.bytes.len() as u64)
                    })
                })
                .ok_or(ProviderError::TooLarge {
                    limit: maximum_bytes,
                })?;
            if bytes > maximum_bytes {
                return Err(ProviderError::TooLarge {
                    limit: maximum_bytes,
                });
            }
            Ok(bundle.clone())
        }
    }

    struct WorkspaceFixture {
        root_identity: PackageIdentity,
        root_locator: PackageLocator,
        root_manifest: Vec<u8>,
        core_locator: PackageLocator,
        provider: InMemoryProvider,
        limits: LoadLimits,
    }

    fn test_manifest_limits() -> ManifestCodecLimits {
        ManifestCodecLimits {
            bytes: 1024 * 1024,
            string_bytes: 1024 * 1024,
            modules: 128,
            dependencies: 128,
            profiles: 128,
            images: 128,
            image_tests: 128,
        }
    }

    fn test_load_limits() -> LoadLimits {
        LoadLimits {
            packages: 128,
            sources: 1024,
            manifest_bytes_per_package: 1024 * 1024,
            manifest_bytes: 16 * 1024 * 1024,
            source_bytes: 16 * 1024 * 1024,
            scenarios: 1024,
            scenario_bytes: 16 * 1024 * 1024,
            bytes_per_package: 8 * 1024 * 1024,
        }
    }

    fn exact_limits_for_fixture(fixture: &WorkspaceFixture) -> LoadLimits {
        let mut manifest_bytes = 0u64;
        let mut manifest_bytes_per_package = 0u64;
        let mut source_bytes = 0u64;
        let mut scenario_bytes = 0u64;
        let mut bytes_per_package = 0u64;
        let mut sources = 0u32;
        let mut scenarios = 0u32;
        for bundle in [&fixture.provider.root_bundle, &fixture.provider.core_bundle] {
            let manifest = u64::try_from(bundle.manifest_bytes.len()).expect("manifest bytes");
            let package_sources = bundle.sources.iter().fold(0u64, |total, source| {
                total + u64::try_from(source.text.len()).expect("source bytes")
            });
            let package_scenarios = bundle.scenarios.iter().fold(0u64, |total, scenario| {
                total + u64::try_from(scenario.bytes.len()).expect("scenario bytes")
            });
            manifest_bytes += manifest;
            manifest_bytes_per_package = manifest_bytes_per_package.max(manifest);
            source_bytes += package_sources;
            scenario_bytes += package_scenarios;
            bytes_per_package =
                bytes_per_package.max(manifest + package_sources + package_scenarios);
            sources += u32::try_from(bundle.sources.len()).expect("source count");
            scenarios += u32::try_from(bundle.scenarios.len()).expect("scenario count");
        }
        LoadLimits {
            packages: 2,
            sources,
            manifest_bytes_per_package,
            manifest_bytes,
            source_bytes,
            scenarios: scenarios.max(1),
            scenario_bytes: scenario_bytes.max(1),
            bytes_per_package,
        }
    }

    fn never_cancelled() -> bool {
        false
    }

    fn manifest_bytes(name: &str, version: &str, dependencies: &[(&str, &str, &str)]) -> Vec<u8> {
        let mut manifest = format!(
            "schema = 1\nlanguage = \"0.1-design\"\n\n[package]\nname = \"{name}\"\nversion = \"{version}\"\nsource_root = \"src\"\n"
        );
        for (alias, package, requirement) in dependencies {
            manifest.push_str(&format!(
                "\n[[dependency]]\nalias = \"{alias}\"\npackage = \"{package}\"\nrequirement = \"={requirement}\"\n"
            ));
        }
        manifest.push_str(
            "\n[[profile]]\nname = \"development\"\nmode = \"development\"\ncomptime_steps = 1\ncomptime_memory_bytes = 1\ncomptime_call_depth = 1\nstatic_bytes = 1\npeak_bytes = 1\nevent_log_bytes = 0\ndma_coherent = false\nrequire_iommu = false\nreset_timeout_ns = 1\nquarantine_bytes = 0\nrecording = \"disabled\"\noptimization = \"none\"\nsealed_deployment = false\nwarnings_as_errors = false\nwatchdogs = false\n",
        );
        manifest.into_bytes()
    }

    /// Assemble the only shape revision 0.1 can load: a root package plus its
    /// sole `core` dependency. There is no lockfile to also record; the
    /// caller supplies each locator directly, exactly as
    /// `LoadRequest::core_locator` expects from a real driver.
    fn assemble_fixture(
        root: PackageFixture,
        root_locator: PackageLocator,
        core: PackageFixture,
        core_locator: PackageLocator,
    ) -> WorkspaceFixture {
        let root_identity = root.identity.clone();
        let root_manifest = root.manifest_bytes.clone();
        let root_bundle = root.bundle(root_locator.clone());
        let core_bundle = core.bundle(core_locator.clone());
        WorkspaceFixture {
            root_identity,
            root_locator: root_locator.clone(),
            root_manifest,
            core_locator: core_locator.clone(),
            provider: InMemoryProvider {
                root_locator,
                root_bundle,
                core_locator,
                core_bundle,
                acquisitions: RefCell::new(Vec::new()),
            },
            limits: test_load_limits(),
        }
    }

    fn minimal_fixture() -> WorkspaceFixture {
        let core = PackageFixture::new(
            &manifest_bytes("wrela-core", "0.1.0", &[]),
            &[("wrela_core.wr", "fn core() -> unit:\n    return ()\n")],
            &[],
        );
        let root = PackageFixture::new(
            &manifest_bytes("mini", "1.0.0", &[("core", "wrela-core", "0.1.0")]),
            &[("mini.wr", "fn mini() -> unit:\n    return ()\n")],
            &[],
        );
        assemble_fixture(
            root,
            PackageLocator::Workspace {
                path: "packages/mini".to_owned(),
            },
            core,
            PackageLocator::Toolchain {
                component: "wrela-core-0.1".to_owned(),
            },
        )
    }

    /// A root manifest that also declares an image and an image test, so
    /// scenario-handling paths (declared, missing, duplicate, undeclared,
    /// non-UTF-8) have something to exercise. Revision 0.1's loader accepts
    /// only the reserved `core` dependency, so unlike the old
    /// lockfile-era fixture this has exactly two packages, not three.
    fn scenario_fixture() -> WorkspaceFixture {
        let core = PackageFixture::new(
            &manifest_bytes("wrela-core", "0.1.0", &[]),
            &[("wrela_core.wr", "fn core() -> unit:\n    return ()\n")],
            &[],
        );
        let root_manifest = "schema = 1\nlanguage = \"0.1-design\"\n\n[package]\nname = \"appliance\"\nversion = \"0.1.0\"\nsource_root = \"src\"\n\n[[dependency]]\nalias = \"core\"\npackage = \"wrela-core\"\nrequirement = \"=0.1.0\"\n\n[[profile]]\nname = \"development\"\nmode = \"development\"\n\n[[image]]\nname = \"appliance\"\nmodule = \"appliance.image\"\nentry = \"image\"\ntarget = \"aarch64-qemu-virt-uefi\"\nprofile = \"development\"\n\n[[image_test]]\nname = \"boots-and-serves\"\nimage = \"appliance\"\nscenario = \"fixtures/boots-and-serves.toml\"\nboot_timeout_ns = 30000000000\nshutdown_timeout_ns = 5000000000\nmaximum_events = 10000\nmaximum_output_bytes = 1048576\ndeterministic_seed = 42\n"
            .to_owned();
        let root = PackageFixture::new(
            root_manifest.as_bytes(),
            &[
                ("appliance/image.wr", "fn image() -> unit:\n    return ()\n"),
                (
                    "appliance/runtime.wr",
                    "fn runtime() -> unit:\n    return ()\n",
                ),
            ],
            &[(
                "fixtures/boots-and-serves.toml",
                "schema = 1\nname = \"boots-and-serves\"\n",
            )],
        );
        assemble_fixture(
            root,
            PackageLocator::Workspace {
                path: "packages/appliance".to_owned(),
            },
            core,
            PackageLocator::Toolchain {
                component: "wrela-core-0.1".to_owned(),
            },
        )
    }

    fn load_fixture(
        fixture: &WorkspaceFixture,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<super::LoadedWorkspace, LoadError> {
        let codec = CanonicalPackageCodec::new();
        let hasher = SoftwareSha256;
        CanonicalWorkspaceLoader::new().load(
            LoadRequest {
                root_locator: fixture.root_locator.clone(),
                root_manifest_bytes: &fixture.root_manifest,
                core_locator: fixture.core_locator.clone(),
                provider: &fixture.provider,
                hasher: &hasher,
                codec: &codec,
                limits: fixture.limits,
            },
            is_cancelled,
        )
    }

    fn candidate_from_workspace(workspace: &LoadedWorkspace) -> LoadedWorkspaceCandidate {
        let codec = CanonicalPackageCodec::new();
        let manifests = workspace
            .manifests()
            .iter()
            .map(|loaded| LoadedManifestInput {
                identity: loaded.identity().clone(),
                locator: loaded.locator().clone(),
                manifest_digest: loaded.manifest_digest(),
                manifest: loaded.manifest().clone(),
                canonical_manifest: codec
                    .canonical_manifest(loaded.manifest(), test_manifest_limits(), &never_cancelled)
                    .expect("candidate canonical manifest"),
            })
            .collect();
        LoadedWorkspaceCandidate {
            graph: workspace.graph().clone(),
            sources: workspace.sources().clone(),
            manifests,
            scenarios: workspace.scenarios().to_vec(),
        }
    }

    fn candidate_from_fixture(fixture: &WorkspaceFixture) -> LoadedWorkspaceCandidate {
        let workspace = load_fixture(fixture, &never_cancelled).expect("fixture workspace");
        candidate_from_workspace(&workspace)
    }

    fn seal_fixture_candidate(
        fixture: &WorkspaceFixture,
        candidate: LoadedWorkspaceCandidate,
    ) -> Result<LoadedWorkspace, LoadError> {
        let codec = CanonicalPackageCodec::new();
        let hasher = SoftwareSha256;
        seal_loaded_workspace(
            &LoadRequest {
                root_locator: fixture.root_locator.clone(),
                root_manifest_bytes: &fixture.root_manifest,
                core_locator: fixture.core_locator.clone(),
                provider: &fixture.provider,
                hasher: &hasher,
                codec: &codec,
                limits: fixture.limits,
            },
            candidate,
            &never_cancelled,
        )
    }

    fn substitute_first_source_digest(candidate: &mut LoadedWorkspaceCandidate) {
        let mut sources = SourceDatabase::default();
        for (index, source) in candidate.sources.files().iter().enumerate() {
            sources
                .add(SourceInput {
                    path: source.path().to_owned(),
                    text: source.text().to_owned(),
                    digest: if index == 0 {
                        Sha256Digest::from_bytes([0x5a; 32])
                    } else {
                        source.digest()
                    },
                })
                .expect("rebuilt source database");
        }
        candidate.sources = sources;
    }

    fn root_bundle_mut(fixture: &mut WorkspaceFixture) -> &mut PackageBundle {
        &mut fixture.provider.root_bundle
    }

    fn core_bundle_mut(fixture: &mut WorkspaceFixture) -> &mut PackageBundle {
        &mut fixture.provider.core_bundle
    }

    #[test]
    fn canonical_loader_seals_root_and_core_workspace() {
        let fixture = minimal_fixture();
        let workspace = load_fixture(&fixture, &never_cancelled).expect("minimum workspace");
        assert_eq!(workspace.graph().packages().len(), 2);
        assert_eq!(workspace.graph().modules().len(), 2);
        assert_eq!(workspace.sources().len(), 2);
        assert_eq!(workspace.manifests().len(), 2);
        assert_eq!(workspace.root_manifest().name, fixture.root_identity.name);
        let root_record = workspace
            .graph()
            .package(workspace.graph().root())
            .expect("loaded root package");
        assert_eq!(root_record.identity, fixture.root_identity);
        assert_eq!(root_record.dependencies.len(), 1);
        assert_eq!(root_record.dependencies[0].alias.as_str(), "core");
        assert_eq!(fixture.provider.acquisitions.borrow().len(), 2);
        assert!(fixture.provider.acquisitions.borrow().iter().all(
            |(_, _, package_bytes, manifest_bytes)| *package_bytes
                == fixture.limits.bytes_per_package
                && *manifest_bytes == fixture.limits.manifest_bytes_per_package
        ));
    }

    #[test]
    fn provider_identity_substitution_is_rejected() {
        let mut fixture = minimal_fixture();
        root_bundle_mut(&mut fixture).identity.name =
            PackageName::new("substituted").expect("substituted name");
        assert!(matches!(
            load_fixture(&fixture, &never_cancelled),
            Err(LoadError::Provider {
                error: ProviderError::IdentityMismatch,
                ..
            })
        ));
    }

    #[test]
    fn provider_locator_substitution_is_rejected() {
        let mut fixture = minimal_fixture();
        root_bundle_mut(&mut fixture).locator = PackageLocator::Toolchain {
            component: "substitute".to_owned(),
        };
        assert!(matches!(
            load_fixture(&fixture, &never_cancelled),
            Err(LoadError::Provider {
                error: ProviderError::Corrupt(_),
                ..
            })
        ));
    }

    #[test]
    fn stale_claimed_package_content_identity_is_rejected() {
        // There is no lockfile-recorded digest to go stale; corrupting the
        // identity the provider itself claims is the equivalent revision
        // 0.1 failure mode -- the loader recomputes content and rejects the
        // mismatch.
        let mut fixture = minimal_fixture();
        root_bundle_mut(&mut fixture).identity.source_digest = Sha256Digest::from_bytes([0x77; 32]);
        assert!(matches!(
            load_fixture(&fixture, &never_cancelled),
            Err(LoadError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn malformed_acquired_root_manifest_is_package_scoped() {
        let mut fixture = minimal_fixture();
        root_bundle_mut(&mut fixture).manifest_bytes = b"schema =\n".to_vec();
        // The root manifest is decoded before acquisition, so a corrupted
        // *acquired* copy first fails the "provider returned the requested
        // root manifest" cross-check.
        assert!(matches!(
            load_fixture(&fixture, &never_cancelled),
            Err(LoadError::PackageManifest {
                error: DecodeError::Malformed { .. },
                ..
            })
        ));
    }

    #[test]
    fn malformed_core_manifest_reports_the_core_package() {
        let mut fixture = minimal_fixture();
        let core_identity = fixture.provider.core_bundle.identity.clone();
        core_bundle_mut(&mut fixture).manifest_bytes = b"schema =\n".to_vec();
        assert!(matches!(
            load_fixture(&fixture, &never_cancelled),
            Err(LoadError::PackageManifest {
                package,
                error: DecodeError::Malformed { .. },
            }) if package == core_identity
        ));
    }

    #[test]
    fn source_set_rejects_missing_duplicate_and_oversized_inputs() {
        // Modules are derived from whatever the provider supplies, so an
        // emptied or extended source set is not a distinct "missing" or
        // "undeclared" declared-source class any more: it silently derives a
        // different module set, and the package content digest computed over
        // that set then mismatches the identity the provider claimed.
        let mut missing = minimal_fixture();
        root_bundle_mut(&mut missing).sources.clear();
        assert!(matches!(
            load_fixture(&missing, &never_cancelled),
            Err(LoadError::DigestMismatch { .. })
        ));

        let mut extra = minimal_fixture();
        let text = "fn extra() -> unit:\n    return ()\n";
        root_bundle_mut(&mut extra).sources.push(SourceInput {
            path: "extra.wr".to_owned(),
            text: text.to_owned(),
            digest: SoftwareSha256.sha256(text.as_bytes()),
        });
        assert!(matches!(
            load_fixture(&extra, &never_cancelled),
            Err(LoadError::DigestMismatch { .. })
        ));

        let mut duplicate = minimal_fixture();
        let repeated = root_bundle_mut(&mut duplicate).sources[0].clone();
        root_bundle_mut(&mut duplicate).sources.push(repeated);
        assert!(matches!(
            load_fixture(&duplicate, &never_cancelled),
            Err(LoadError::DuplicateSource(_))
        ));

        // `UndeclaredSource` still fires for a source path over the portable
        // length ceiling, independent of anything the manifest declares.
        let mut oversized = minimal_fixture();
        let oversized_path = "x".repeat(wrela_source::MAX_SOURCE_PATH_BYTES + 1);
        root_bundle_mut(&mut oversized).sources.push(SourceInput {
            path: oversized_path,
            text: text.to_owned(),
            digest: SoftwareSha256.sha256(text.as_bytes()),
        });
        assert!(matches!(
            load_fixture(&oversized, &never_cancelled),
            Err(LoadError::UndeclaredSource(_))
        ));
    }

    #[test]
    fn scenario_set_rejects_missing_duplicate_and_undeclared_inputs() {
        let mut missing = scenario_fixture();
        root_bundle_mut(&mut missing).scenarios.clear();
        assert!(matches!(
            load_fixture(&missing, &never_cancelled),
            Err(LoadError::MissingScenario(_))
        ));

        let mut duplicate = scenario_fixture();
        let repeated = root_bundle_mut(&mut duplicate).scenarios[0].clone();
        root_bundle_mut(&mut duplicate).scenarios.push(repeated);
        assert!(matches!(
            load_fixture(&duplicate, &never_cancelled),
            Err(LoadError::DuplicateScenario(_))
        ));

        let mut undeclared = scenario_fixture();
        let bytes = b"schema = 1\nname = \"extra\"\n".to_vec();
        let identity = undeclared.root_identity.clone();
        let digest = SoftwareSha256.sha256(&bytes);
        root_bundle_mut(&mut undeclared)
            .scenarios
            .push(ScenarioInput {
                package: identity,
                path: "fixtures/extra.toml".to_owned(),
                bytes,
                digest,
            });
        assert!(matches!(
            load_fixture(&undeclared, &never_cancelled),
            Err(LoadError::UndeclaredScenario(_))
        ));

        let mut invalid_utf8 = scenario_fixture();
        let scenario = &mut root_bundle_mut(&mut invalid_utf8).scenarios[0];
        scenario.bytes = vec![0xff];
        scenario.digest = SoftwareSha256.sha256(&scenario.bytes);
        assert!(matches!(
            load_fixture(&invalid_utf8, &never_cancelled),
            Err(LoadError::Provider {
                error: ProviderError::Corrupt(_),
                ..
            })
        ));
    }

    #[test]
    fn sealer_dependency_binding_rejects_alias_identity_and_requirement_mutations() {
        let fixture = minimal_fixture();
        let candidate = candidate_from_fixture(&fixture);
        // The root is always graph package 0 and `manifests[0]`; there is no
        // lockfile-recorded dependency set to also cross-check, so this only
        // exercises the manifest/graph comparison.
        let package = &candidate.graph.packages()[0];
        let manifest = &candidate.manifests[0].manifest;
        assert!(
            candidate_dependencies_match(&candidate.graph, package, manifest, &never_cancelled)
                .expect("valid dependency binding")
        );

        let mut alias = manifest.clone();
        alias.dependencies[0].alias = DependencyAlias::new("altered").expect("altered alias");
        assert!(
            !candidate_dependencies_match(&candidate.graph, package, &alias, &never_cancelled)
                .expect("alias mismatch")
        );

        let mut identity = manifest.clone();
        identity.dependencies[0].package = PackageName::new("substitute").expect("package name");
        assert!(
            !candidate_dependencies_match(&candidate.graph, package, &identity, &never_cancelled)
                .expect("identity mismatch")
        );

        let mut requirement = manifest.clone();
        requirement.dependencies[0].requirement = "=999.0.0".to_owned();
        assert!(
            !candidate_dependencies_match(
                &candidate.graph,
                package,
                &requirement,
                &never_cancelled
            )
            .expect("requirement mismatch")
        );
        assert!(matches!(
            candidate_dependencies_match(&candidate.graph, package, manifest, &|| true),
            Err(LoadError::Cancelled)
        ));
    }

    #[test]
    fn sealer_rebinds_request_root_and_candidate_order() {
        let mut changed_request = minimal_fixture();
        let candidate = candidate_from_fixture(&changed_request);
        changed_request.root_manifest =
            manifest_bytes("other", "1.0.0", &[("core", "wrela-core", "0.1.0")]);
        assert!(matches!(
            seal_fixture_candidate(&changed_request, candidate),
            Err(LoadError::InvalidOutput(_))
        ));

        let order_fixture = minimal_fixture();
        let mut candidate = candidate_from_fixture(&order_fixture);
        candidate.manifests.swap(0, 1);
        assert!(matches!(
            seal_fixture_candidate(&order_fixture, candidate),
            Err(LoadError::InvalidOutput(_))
        ));

        let graph_fixture = scenario_fixture();
        let mut candidate = candidate_from_fixture(&graph_fixture);
        candidate.graph = candidate_from_fixture(&minimal_fixture()).graph;
        assert!(matches!(
            seal_fixture_candidate(&graph_fixture, candidate),
            Err(LoadError::InvalidOutput(_))
        ));
    }

    #[test]
    fn sealer_rejects_locator_source_and_scenario_substitution() {
        let locator_fixture = minimal_fixture();
        let mut candidate = candidate_from_fixture(&locator_fixture);
        candidate.manifests[0].locator = PackageLocator::Toolchain {
            component: "substitute".to_owned(),
        };
        assert!(matches!(
            seal_fixture_candidate(&locator_fixture, candidate),
            Err(LoadError::InvalidOutput(_))
        ));

        let source_fixture = minimal_fixture();
        let mut candidate = candidate_from_fixture(&source_fixture);
        substitute_first_source_digest(&mut candidate);
        assert!(matches!(
            seal_fixture_candidate(&source_fixture, candidate),
            Err(LoadError::InvalidOutput(_))
        ));

        let digest_fixture = scenario_fixture();
        let mut candidate = candidate_from_fixture(&digest_fixture);
        candidate.scenarios[0].digest = Sha256Digest::from_bytes([0x33; 32]);
        assert!(matches!(
            seal_fixture_candidate(&digest_fixture, candidate),
            Err(LoadError::InvalidOutput(_))
        ));

        let utf8_fixture = scenario_fixture();
        let mut candidate = candidate_from_fixture(&utf8_fixture);
        candidate.scenarios[0].bytes = vec![0xff];
        assert!(matches!(
            seal_fixture_candidate(&utf8_fixture, candidate),
            Err(LoadError::InvalidOutput(message)) if message.contains("not UTF-8")
        ));

        let duplicate_fixture = scenario_fixture();
        let mut candidate = candidate_from_fixture(&duplicate_fixture);
        candidate.scenarios.push(candidate.scenarios[0].clone());
        assert!(matches!(
            seal_fixture_candidate(&duplicate_fixture, candidate),
            Err(LoadError::InvalidOutput(_))
        ));
    }

    #[test]
    fn sealer_preflights_malicious_candidate_limits_and_manifest_shape() {
        let mut manifest_fixture = minimal_fixture();
        manifest_fixture.limits = exact_limits_for_fixture(&manifest_fixture);
        let mut candidate = candidate_from_fixture(&manifest_fixture);
        candidate.manifests[0].canonical_manifest.push(b' ');
        assert!(matches!(
            seal_fixture_candidate(&manifest_fixture, candidate),
            Err(LoadError::ResourceLimit {
                resource: "candidate canonical manifest bytes",
                ..
            })
        ));

        let mut source_fixture = minimal_fixture();
        let candidate = candidate_from_fixture(&source_fixture);
        source_fixture.limits = exact_limits_for_fixture(&source_fixture);
        source_fixture.limits.source_bytes -= 1;
        assert!(matches!(
            seal_fixture_candidate(&source_fixture, candidate),
            Err(LoadError::ResourceLimit {
                resource: "candidate source bytes",
                ..
            })
        ));

        let mut scenario_test_fixture = scenario_fixture();
        scenario_test_fixture.limits = exact_limits_for_fixture(&scenario_test_fixture);
        let mut candidate = candidate_from_fixture(&scenario_test_fixture);
        candidate.scenarios.push(candidate.scenarios[0].clone());
        assert!(matches!(
            seal_fixture_candidate(&scenario_test_fixture, candidate),
            Err(LoadError::ResourceLimit {
                resource: "scenario records",
                ..
            })
        ));

        let requirement_fixture = minimal_fixture();
        let mut candidate = candidate_from_fixture(&requirement_fixture);
        candidate.manifests[0].manifest.dependencies[0].requirement =
            format!("={}", "1".repeat(256));
        assert!(matches!(
            seal_fixture_candidate(&requirement_fixture, candidate),
            Err(LoadError::InvalidOutput(message))
                if message.contains("requirement exceeds")
        ));
    }

    #[test]
    fn cancellable_validators_poll_during_linear_scans() {
        let digest = Sha256Digest::from_bytes([0x44; 32]);
        let records = [
            PackageContentRecord {
                kind: PackageContentKind::Source,
                path: "a.wr",
                digest,
            },
            PackageContentRecord {
                kind: PackageContentKind::Source,
                path: "b.wr",
                digest,
            },
            PackageContentRecord {
                kind: PackageContentKind::Source,
                path: "c.wr",
                digest,
            },
        ];
        let polls = Cell::new(0usize);
        let cancel_during_order_check = || {
            let next = polls.get().saturating_add(1);
            polls.set(next);
            next >= 3
        };
        assert_eq!(
            package_content_digest(
                b"canonical manifest",
                &records,
                &SoftwareSha256,
                &cancel_during_order_check,
            ),
            Err(PackageContentDigestError::Cancelled)
        );

        let mut split_scalar = vec![b'a'; 64 * 1024 - 1];
        split_scalar.extend_from_slice("€".as_bytes());
        assert!(is_utf8_cancellable(&split_scalar, &never_cancelled).expect("split UTF-8"));
        split_scalar[64 * 1024] = b'x';
        assert!(!is_utf8_cancellable(&split_scalar, &never_cancelled).expect("invalid UTF-8"));
    }

    #[test]
    fn loader_error_payloads_are_structurally_bounded() {
        let long = "é".repeat(8_192);
        let ProviderError::Corrupt(provider) =
            bounded_provider_error(ProviderError::Corrupt(long.clone()))
        else {
            panic!("unexpected provider error")
        };
        assert!(provider.len() <= MAX_LOAD_ERROR_VALUE_BYTES);
        assert!(provider.ends_with('…'));

        let DecodeError::Malformed { message, .. } = bounded_decode_error(DecodeError::Malformed {
            byte_offset: 0,
            message: long.clone(),
        }) else {
            panic!("unexpected decode error")
        };
        assert!(message.len() <= MAX_LOAD_ERROR_VALUE_BYTES);
        assert!(message.ends_with('…'));

        let rendered = LoadError::InvalidOutput(long).to_string();
        assert!(rendered.len() <= MAX_LOAD_ERROR_VALUE_BYTES + 48);
        assert!(rendered.ends_with('…'));
    }

    #[test]
    fn root_manifest_with_more_than_one_dependency_is_rejected() {
        let mut fixture = minimal_fixture();
        fixture.root_manifest = manifest_bytes(
            "mini",
            "1.0.0",
            &[
                ("core", "wrela-core", "0.1.0"),
                ("extra", "wrela-extra", "1.0.0"),
            ],
        );
        assert!(matches!(
            load_fixture(&fixture, &never_cancelled),
            Err(LoadError::Manifest(_))
        ));
        assert!(fixture.provider.acquisitions.borrow().is_empty());
    }

    #[test]
    fn root_manifest_dependency_not_aliased_core_is_rejected() {
        let mut fixture = minimal_fixture();
        fixture.root_manifest = manifest_bytes("mini", "1.0.0", &[("std", "wrela-core", "0.1.0")]);
        assert!(matches!(
            load_fixture(&fixture, &never_cancelled),
            Err(LoadError::Manifest(_))
        ));
        assert!(fixture.provider.acquisitions.borrow().is_empty());
    }

    #[test]
    fn exact_limits_succeed_and_one_byte_over_fails() {
        let mut exact = minimal_fixture();
        exact.limits = exact_limits_for_fixture(&exact);
        load_fixture(&exact, &never_cancelled).expect("exact configured limits");

        let mut over = minimal_fixture();
        over.limits.manifest_bytes = over.provider.root_bundle.manifest_bytes.len() as u64
            + over.provider.core_bundle.manifest_bytes.len() as u64
            - 1;
        assert!(matches!(
            load_fixture(&over, &never_cancelled),
            Err(LoadError::ResourceLimit { .. })
        ));
    }

    #[test]
    fn scenario_workspace_count_and_byte_limits_are_exact_boundaries() {
        let mut exact = scenario_fixture();
        exact.limits = exact_limits_for_fixture(&exact);
        load_fixture(&exact, &never_cancelled).expect("exact scenario workspace limits");

        let mut packages = scenario_fixture();
        packages.limits = exact_limits_for_fixture(&packages);
        packages.limits.packages -= 1;
        assert!(matches!(
            load_fixture(&packages, &never_cancelled),
            Err(LoadError::ResourceLimit { .. })
        ));

        let mut sources = scenario_fixture();
        sources.limits = exact_limits_for_fixture(&sources);
        sources.limits.sources -= 1;
        assert!(matches!(
            load_fixture(&sources, &never_cancelled),
            Err(LoadError::ResourceLimit { .. })
        ));

        let mut scenarios = scenario_fixture();
        scenarios.limits = exact_limits_for_fixture(&scenarios);
        scenarios.limits.scenario_bytes -= 1;
        assert!(matches!(
            load_fixture(&scenarios, &never_cancelled),
            Err(LoadError::ResourceLimit { .. })
        ));
    }

    #[test]
    fn cancellation_is_observed_before_and_during_provider_acquisition() {
        let immediate = minimal_fixture();
        assert!(matches!(
            load_fixture(&immediate, &|| true),
            Err(LoadError::Cancelled)
        ));
        assert!(immediate.provider.acquisitions.borrow().is_empty());

        let during = minimal_fixture();
        let cancel_after_provider_entry = || !during.provider.acquisitions.borrow().is_empty();
        assert!(matches!(
            load_fixture(&during, &cancel_after_provider_entry),
            Err(LoadError::Cancelled)
        ));
        assert_eq!(during.provider.acquisitions.borrow().len(), 1);
    }
}
