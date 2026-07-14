//! Hermetic acquisition and loading boundary for TOML manifests, the canonical
//! lockfile, and the complete content-addressed source graph.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use wrela_build_model::Sha256Digest;
use wrela_package::{
    Lockfile, PackageGraph, PackageIdentity, PackageLocator, PackageManifest,
    exact_requirement_version,
};
use wrela_source::{SourceDatabase, SourceError, SourceInput};

pub const SOURCE_GRAPH_DIGEST_VERSION: u32 = 1;
const SOURCE_GRAPH_MAGIC: &[u8; 8] = b"WRELSRC\0";
/// Canonical package-content digest encoding recorded in `PackageIdentity`.
pub const PACKAGE_CONTENT_DIGEST_VERSION: u32 = 1;
const PACKAGE_CONTENT_MAGIC: &[u8; 8] = b"WRELPKG\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadLimits {
    pub packages: u32,
    pub sources: u32,
    pub manifest_bytes_per_package: u64,
    /// Aggregate canonical manifest bytes across the complete package graph.
    pub manifest_bytes: u64,
    pub lockfile_bytes: u64,
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
            lockfile_bytes: 256 * 1024 * 1024,
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
            || self.lockfile_bytes == 0
            || self.source_bytes == 0
            || self.scenarios == 0
            || self.scenario_bytes == 0
            || self.bytes_per_package == 0
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
/// resolve an undeclared locator or use ambient network configuration.
pub trait PackageSourceProvider {
    fn acquire(
        &self,
        locator: &PackageLocator,
        expected: &PackageIdentity,
        maximum_bytes: u64,
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
    if canonical_manifest.is_empty()
        || records.iter().any(|record| record.path.is_empty())
        || !records
            .windows(2)
            .all(|pair| (pair[0].kind, pair[0].path) < (pair[1].kind, pair[1].path))
    {
        return Err(PackageContentDigestError::NonCanonicalInput);
    }
    let mut digest = hasher.begin_sha256();
    digest.update(PACKAGE_CONTENT_MAGIC);
    digest.update(&PACKAGE_CONTENT_DIGEST_VERSION.to_le_bytes());
    update_bytes_cancellable(&mut *digest, canonical_manifest, is_cancelled)
        .map_err(|()| PackageContentDigestError::Cancelled)?;
    update_u64(&mut *digest, records.len() as u64);
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

/// Schema codec for `wrela.toml` and `wrela.lock`. The production loader owns a
/// canonical TOML implementation; this trait permits isolated deterministic
/// fixtures without filesystem or parser coupling.
pub trait PackageCodec {
    fn decode_manifest(
        &self,
        bytes: &[u8],
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<PackageManifest, DecodeError>;
    fn decode_lockfile(
        &self,
        bytes: &[u8],
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Lockfile, DecodeError>;
    fn canonical_manifest(
        &self,
        manifest: &PackageManifest,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, DecodeError>;
    fn canonical_lockfile(
        &self,
        lockfile: &Lockfile,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>, DecodeError>;
}

pub struct LoadRequest<'a> {
    pub root_locator: PackageLocator,
    pub root_manifest_bytes: &'a [u8],
    pub lockfile_bytes: &'a [u8],
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

/// Complete immutable package-loading output. `source_graph_digest` covers the
/// canonical lockfile, every manifest, and every source and scenario
/// `(package, path, digest)` tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedWorkspace {
    graph: PackageGraph,
    sources: SourceDatabase,
    manifests: Vec<LoadedManifest>,
    /// Declared scenario files in canonical `(package, path)` order. Their
    /// digests and paths participate in `source_graph_digest`.
    scenarios: Vec<ScenarioInput>,
    lockfile: Lockfile,
    canonical_lockfile: Vec<u8>,
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
    pub fn lockfile(&self) -> &Lockfile {
        &self.lockfile
    }

    #[must_use]
    pub fn canonical_lockfile(&self) -> &[u8] {
        &self.canonical_lockfile
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
            lockfile: self.lockfile,
            canonical_lockfile: self.canonical_lockfile,
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
    pub lockfile: Lockfile,
    pub canonical_lockfile: Vec<u8>,
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
    pub lockfile: Lockfile,
    pub canonical_lockfile: Vec<u8>,
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
        lockfile,
        canonical_lockfile,
    } = candidate;
    let limits = request.limits;
    let hasher = request.hasher;
    let codec = request.codec;
    limits.validate()?;
    let root_manifest_bytes =
        u64::try_from(request.root_manifest_bytes.len()).map_err(|_| LoadError::ResourceLimit {
            resource: "root manifest bytes",
            limit: limits.manifest_bytes_per_package,
        })?;
    let lockfile_bytes =
        u64::try_from(request.lockfile_bytes.len()).map_err(|_| LoadError::ResourceLimit {
            resource: "lockfile bytes",
            limit: limits.lockfile_bytes,
        })?;
    if root_manifest_bytes > limits.manifest_bytes_per_package
        || lockfile_bytes > limits.lockfile_bytes
    {
        return Err(LoadError::ResourceLimit {
            resource: "manifest or lockfile input bytes",
            limit: limits.manifest_bytes_per_package.max(limits.lockfile_bytes),
        });
    }
    let requested_manifest = codec
        .decode_manifest(request.root_manifest_bytes, is_cancelled)
        .map_err(LoadError::RootManifest)?;
    let requested_lockfile = codec
        .decode_lockfile(request.lockfile_bytes, is_cancelled)
        .map_err(LoadError::Lockfile)?;
    if is_cancelled() {
        return Err(LoadError::Cancelled);
    }
    lockfile
        .validate()
        .map_err(|error| LoadError::InvalidOutput(format!("invalid lockfile: {error}")))?;
    let root_index = graph.root().0 as usize;
    let root_input = manifests.get(root_index);
    if graph.packages().is_empty()
        || graph.packages().len() > limits.packages as usize
        || sources.len() > limits.sources as usize
        || manifests.len() != graph.packages().len()
        || lockfile.packages.len() != graph.packages().len()
        || canonical_lockfile.len() as u64 > limits.lockfile_bytes
        || codec
            .canonical_lockfile(&lockfile, is_cancelled)
            .map_err(LoadError::Lockfile)?
            != canonical_lockfile
        || request.lockfile_bytes != canonical_lockfile
        || requested_lockfile != lockfile
        || root_input.is_none_or(|root| {
            root.locator != request.root_locator || root.manifest != requested_manifest
        })
        || graph
            .package(graph.root())
            .is_none_or(|root| root.identity != lockfile.root)
    {
        return Err(LoadError::InvalidOutput(
            "package, source, manifest, root, or canonical lockfile set differs".to_owned(),
        ));
    }

    let mut loaded_manifests = Vec::with_capacity(manifests.len());
    let mut canonical_manifests = Vec::with_capacity(manifests.len());
    let mut total_manifest_bytes = 0u64;
    for (package, candidate) in graph.packages().iter().zip(manifests) {
        if is_cancelled() {
            return Err(LoadError::Cancelled);
        }
        candidate
            .manifest
            .validate()
            .map_err(|error| LoadError::InvalidOutput(format!("invalid manifest: {error}")))?;
        let canonical = codec
            .canonical_manifest(&candidate.manifest, is_cancelled)
            .map_err(LoadError::RootManifest)?;
        let canonical_digest = sha256_cancellable(hasher, &canonical, is_cancelled)
            .map_err(|_| LoadError::Cancelled)?;
        let locked = lockfile
            .packages
            .binary_search_by(|locked| locked.identity.cmp(&candidate.identity))
            .ok()
            .and_then(|index| lockfile.packages.get(index));
        let dependency_sets_match = locked.is_some_and(|locked| {
            package.dependencies.len() == locked.dependencies.len()
                && locked.dependencies.len() == candidate.manifest.dependencies.len()
                && package
                    .dependencies
                    .iter()
                    .zip(&locked.dependencies)
                    .zip(&candidate.manifest.dependencies)
                    .all(|((graph_edge, locked_edge), manifest_edge)| {
                        graph_edge.alias == locked_edge.alias
                            && manifest_edge.alias == locked_edge.alias
                            && graph.package(graph_edge.package).is_some_and(|dependency| {
                                dependency.identity == locked_edge.identity
                                    && manifest_edge.package == dependency.identity.name
                                    && exact_requirement_version(&manifest_edge.requirement)
                                        .is_some_and(|version| {
                                            version == dependency.identity.version
                                        })
                            })
                    })
        });
        total_manifest_bytes = total_manifest_bytes
            .checked_add(u64::try_from(canonical.len()).map_err(|_| {
                LoadError::InvalidOutput("manifest byte count does not fit u64".to_owned())
            })?)
            .ok_or_else(|| LoadError::InvalidOutput("manifest byte total overflow".to_owned()))?;
        if package.identity != candidate.identity
            || candidate.identity.name != candidate.manifest.name
            || candidate.identity.version != candidate.manifest.version
            || canonical != candidate.canonical_manifest
            || canonical.len() as u64 > limits.manifest_bytes_per_package
            || total_manifest_bytes > limits.manifest_bytes
            || canonical_digest != candidate.manifest_digest
            || !dependency_sets_match
            || locked.is_none_or(|locked| {
                locked.locator != candidate.locator
                    || locked.manifest_digest != candidate.manifest_digest
            })
        {
            return Err(LoadError::InvalidOutput(format!(
                "manifest for {}@{} differs from graph, lockfile, canonical bytes, or digest",
                candidate.identity.name.as_str(),
                candidate.identity.version.as_str()
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

    let source_ids: BTreeSet<_> = graph.modules().iter().map(|module| module.source).collect();
    let expected_source_ids: BTreeSet<_> = (0..sources.len())
        .map(|index| {
            u32::try_from(index)
                .map(wrela_source::FileId)
                .map_err(|_| LoadError::InvalidOutput("too many source IDs".to_owned()))
        })
        .collect::<Result<_, _>>()?;
    if source_ids != expected_source_ids || graph.modules().len() != sources.len() {
        return Err(LoadError::InvalidOutput(
            "module graph does not cover each source exactly once".to_owned(),
        ));
    }
    let mut source_bytes = 0u64;
    let mut package_bytes = vec![0u64; graph.packages().len()];
    let mut package_module_counts = vec![0usize; graph.packages().len()];
    let mut package_records = vec![Vec::<PackageContentRecord<'_>>::new(); graph.packages().len()];
    for (index, canonical) in canonical_manifests.iter().enumerate() {
        package_bytes[index] = u64::try_from(canonical.len()).map_err(|_| {
            LoadError::InvalidOutput("manifest byte count does not fit u64".to_owned())
        })?;
    }
    for module in graph.modules() {
        if is_cancelled() {
            return Err(LoadError::Cancelled);
        }
        graph.package(module.package).ok_or_else(|| {
            LoadError::InvalidOutput("module refers to an unknown package".to_owned())
        })?;
        let package_index = module.package.0 as usize;
        let loaded = loaded_manifests
            .get(package_index)
            .ok_or_else(|| LoadError::InvalidOutput("module manifest is missing".to_owned()))?;
        let declared = loaded
            .manifest
            .modules
            .binary_search_by(|declared| declared.module.cmp(&module.path))
            .ok()
            .and_then(|index| loaded.manifest.modules.get(index))
            .ok_or_else(|| {
                LoadError::InvalidOutput("graph contains an undeclared module".to_owned())
            })?;
        let source = sources
            .get(module.source)
            .ok_or_else(|| LoadError::InvalidOutput("module source ID is missing".to_owned()))?;
        let expected_path = qualified_source_path(
            &loaded.identity,
            &loaded.manifest.source_root,
            &declared.source_path,
        );
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
            return Err(LoadError::InvalidOutput(format!(
                "source {} differs from its declaration or digest",
                source.path()
            )));
        }
        package_module_counts[package_index] += 1;
        package_records[package_index].push(PackageContentRecord {
            kind: PackageContentKind::Source,
            path: &declared.source_path,
            digest: source.digest(),
        });
    }
    if source_bytes > limits.source_bytes
        || loaded_manifests
            .iter()
            .zip(&package_module_counts)
            .any(|(loaded, count)| *count != loaded.manifest.modules.len())
    {
        return Err(LoadError::ResourceLimit {
            resource: "source graph bytes or module coverage",
            limit: limits.source_bytes,
        });
    }

    let declared_scenarios: BTreeSet<_> = loaded_manifests
        .iter()
        .flat_map(|loaded| {
            loaded
                .manifest
                .image_tests
                .iter()
                .map(|test| (loaded.identity.clone(), test.scenario.clone()))
        })
        .collect();
    let actual_scenarios: BTreeSet<_> = scenarios
        .iter()
        .map(|scenario| (scenario.package.clone(), scenario.path.clone()))
        .collect();
    let package_indices: BTreeMap<_, _> = loaded_manifests
        .iter()
        .enumerate()
        .map(|(index, manifest)| (&manifest.identity, index))
        .collect();
    let mut scenario_bytes = Some(0u64);
    for scenario in &scenarios {
        if is_cancelled() {
            return Err(LoadError::Cancelled);
        }
        let Some(&package_index) = package_indices.get(&scenario.package) else {
            return Err(LoadError::InvalidOutput(
                "scenario belongs to an unknown package".to_owned(),
            ));
        };
        let bytes = u64::try_from(scenario.bytes.len()).ok();
        let scenario_digest = sha256_cancellable(hasher, &scenario.bytes, is_cancelled)
            .map_err(|_| LoadError::Cancelled)?;
        if scenario_digest != scenario.digest {
            return Err(LoadError::InvalidOutput(
                "scenario bytes differ from their digest".to_owned(),
            ));
        }
        scenario_bytes = scenario_bytes
            .zip(bytes)
            .and_then(|(total, bytes)| total.checked_add(bytes));
        let package_total = package_bytes.get_mut(package_index).ok_or_else(|| {
            LoadError::InvalidOutput("scenario package ID is not dense".to_owned())
        })?;
        *package_total = package_total
            .checked_add(bytes.ok_or_else(|| {
                LoadError::InvalidOutput("scenario byte count does not fit u64".to_owned())
            })?)
            .ok_or_else(|| {
                LoadError::InvalidOutput("package scenario byte total overflow".to_owned())
            })?;
        package_records[package_index].push(PackageContentRecord {
            kind: PackageContentKind::Scenario,
            path: &scenario.path,
            digest: scenario.digest,
        });
    }
    if scenarios.len() > limits.scenarios as usize
        || !scenarios
            .windows(2)
            .all(|pair| (&pair[0].package, &pair[0].path) < (&pair[1].package, &pair[1].path))
        || declared_scenarios != actual_scenarios
        || scenario_bytes.is_none_or(|bytes| bytes > limits.scenario_bytes)
        || package_bytes
            .iter()
            .any(|bytes| *bytes > limits.bytes_per_package)
        || scenarios
            .iter()
            .any(|scenario| scenario.path.trim().is_empty())
    {
        return Err(LoadError::InvalidOutput(
            "scenario set, order, size, declaration, or digest differs".to_owned(),
        ));
    }

    for (index, records) in package_records.iter_mut().enumerate() {
        if is_cancelled() {
            return Err(LoadError::Cancelled);
        }
        records.sort_by_key(|record| (record.kind, record.path));
        let actual =
            package_content_digest(&canonical_manifests[index], records, hasher, is_cancelled)
                .map_err(|error| match error {
                    PackageContentDigestError::Cancelled => LoadError::Cancelled,
                    PackageContentDigestError::NonCanonicalInput => LoadError::InvalidOutput(
                        "package content records are not canonical".to_owned(),
                    ),
                })?;
        let expected = loaded_manifests[index].identity.source_digest;
        if actual != expected {
            return Err(LoadError::DigestMismatch {
                subject: format!(
                    "package {}@{} content",
                    loaded_manifests[index].identity.name.as_str(),
                    loaded_manifests[index].identity.version.as_str()
                ),
                expected,
                actual,
            });
        }
    }
    drop(package_records);

    let source_graph_digest = hash_source_graph(
        &graph,
        &sources,
        &loaded_manifests,
        &scenarios,
        &canonical_lockfile,
        hasher,
        is_cancelled,
    )?;
    Ok(LoadedWorkspace {
        graph,
        sources,
        manifests: loaded_manifests,
        scenarios,
        lockfile,
        canonical_lockfile,
        source_graph_digest,
    })
}

#[must_use]
pub fn qualified_source_path(
    package: &PackageIdentity,
    source_root: &str,
    source_path: &str,
) -> String {
    format!(
        "packages/{}/{}/{}/{}/{}",
        hex_bytes(package.name.as_str().as_bytes()),
        hex_bytes(package.version.as_str().as_bytes()),
        package.source_digest.to_hex(),
        source_root,
        source_path
    )
}

fn hex_bytes(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(DIGITS[(byte >> 4) as usize] as char);
        output.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    output
}

fn hash_source_graph(
    graph: &PackageGraph,
    sources: &SourceDatabase,
    manifests: &[LoadedManifest],
    scenarios: &[ScenarioInput],
    canonical_lockfile: &[u8],
    hasher: &dyn ContentHasher,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Sha256Digest, LoadError> {
    if is_cancelled() {
        return Err(LoadError::Cancelled);
    }
    let mut digest = hasher.begin_sha256();
    digest.update(SOURCE_GRAPH_MAGIC);
    digest.update(&SOURCE_GRAPH_DIGEST_VERSION.to_le_bytes());
    update_bytes_cancellable(&mut *digest, canonical_lockfile, is_cancelled)
        .map_err(|()| LoadError::Cancelled)?;
    update_u64(&mut *digest, manifests.len() as u64);
    for manifest in manifests {
        if is_cancelled() {
            return Err(LoadError::Cancelled);
        }
        update_identity(&mut *digest, &manifest.identity);
        update_locator(&mut *digest, &manifest.locator);
        digest.update(manifest.manifest_digest.as_bytes());
    }
    let mut source_records: Vec<_> = graph
        .modules()
        .iter()
        .filter_map(|module| {
            graph
                .package(module.package)
                .zip(sources.get(module.source))
        })
        .collect();
    source_records.sort_by(
        |(left_package, left_source), (right_package, right_source)| {
            (&left_package.identity, left_source.path())
                .cmp(&(&right_package.identity, right_source.path()))
        },
    );
    update_u64(&mut *digest, source_records.len() as u64);
    for (package, source) in source_records {
        if is_cancelled() {
            return Err(LoadError::Cancelled);
        }
        update_identity(&mut *digest, &package.identity);
        update_string(&mut *digest, source.path());
        digest.update(source.digest().as_bytes());
    }
    update_u64(&mut *digest, scenarios.len() as u64);
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    InvalidUtf8,
    Malformed { byte_offset: usize, message: String },
    DuplicateKey(String),
    UnknownField(String),
    NonCanonical(String),
    UnsupportedSchema(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    Cancelled,
    InvalidLimits,
    RootManifest(DecodeError),
    Lockfile(DecodeError),
    PackageManifest {
        package: PackageIdentity,
        error: DecodeError,
    },
    Provider {
        package: PackageIdentity,
        error: ProviderError,
    },
    Manifest(String),
    Lock(String),
    DigestMismatch {
        subject: String,
        expected: Sha256Digest,
        actual: Sha256Digest,
    },
    UndeclaredSource(String),
    MissingSource(String),
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
            Self::RootManifest(error) => write!(formatter, "invalid root manifest: {error:?}"),
            Self::Lockfile(error) => write!(formatter, "invalid lockfile: {error:?}"),
            Self::PackageManifest { package, error } => write!(
                formatter,
                "invalid manifest for {}@{}: {error:?}",
                package.name.as_str(),
                package.version.as_str()
            ),
            Self::Provider { package, error } => write!(
                formatter,
                "cannot acquire {}@{}: {error:?}",
                package.name.as_str(),
                package.version.as_str()
            ),
            Self::Manifest(message) => write!(formatter, "invalid package manifest: {message}"),
            Self::Lock(message) => write!(formatter, "invalid package lockfile: {message}"),
            Self::DigestMismatch {
                subject,
                expected,
                actual,
            } => write!(
                formatter,
                "digest mismatch for {subject}: expected {}, got {}",
                expected.to_hex(),
                actual.to_hex()
            ),
            Self::UndeclaredSource(path) => {
                write!(formatter, "provider returned undeclared source {path}")
            }
            Self::MissingSource(path) => write!(formatter, "manifest source {path} is missing"),
            Self::DuplicateSource(path) => {
                write!(formatter, "source {path} was returned more than once")
            }
            Self::UndeclaredScenario(path) => {
                write!(
                    formatter,
                    "provider returned undeclared image scenario {path}"
                )
            }
            Self::MissingScenario(path) => {
                write!(formatter, "manifest image scenario {path} is missing")
            }
            Self::DuplicateScenario(path) => {
                write!(
                    formatter,
                    "image scenario {path} was returned more than once"
                )
            }
            Self::Source(error) => error.fmt(formatter),
            Self::Graph(message) => write!(formatter, "invalid package graph: {message}"),
            Self::InvalidOutput(message) => {
                write!(
                    formatter,
                    "package loader produced invalid output: {message}"
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
    use super::{LoadError, LoadLimits};

    #[test]
    fn loader_policy_separates_and_validates_manifest_budgets() {
        let limits = LoadLimits::standard();
        limits.validate().expect("standard limits");
        assert!(limits.manifest_bytes > limits.manifest_bytes_per_package);
        let mut invalid = limits;
        invalid.manifest_bytes_per_package = 0;
        assert!(matches!(invalid.validate(), Err(LoadError::InvalidLimits)));
    }
}
