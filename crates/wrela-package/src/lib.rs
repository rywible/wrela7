//! Deterministic package and module graph supplied to parsing and name resolution.
//!
//! Filesystem discovery and manifest decoding must produce this validated model
//! before syntax or semantic analysis begins. This crate performs neither task.

#![forbid(unsafe_code)]

use std::collections::{BTreeSet, VecDeque};
use std::fmt;

use unicode_ident::{is_xid_continue, is_xid_start};
use unicode_normalization::UnicodeNormalization;
use wrela_build_model::{BuildProfile, LanguageRevision, Sha256Digest};
use wrela_source::FileId;

pub const MAX_PACKAGES: usize = 1_000_000;
/// Maximum derived modules (one per discovered `*.wr` file) in one package.
pub const MAX_MODULES: usize = 1_000_000;
pub const MAX_DEPENDENCIES_PER_PACKAGE: usize = 65_536;
/// Maximum UTF-8 bytes retained from any project-controlled value in a
/// [`ManifestError`], including the truncation marker.
pub const MAX_MANIFEST_ERROR_VALUE_BYTES: usize = 256;
/// Current TOML manifest schema.
pub const MANIFEST_SCHEMA_VERSION: u32 = 1;
/// Current canonical lockfile schema.
pub const LOCKFILE_SCHEMA_VERSION: u32 = 1;

/// Return whether `value` is exactly a revision 0.1 source identifier.
///
/// This is the shared compiler boundary for source-facing names outside the
/// scanner. It applies the pinned Unicode 16 XID tables, NFC, keyword,
/// wildcard, default-ignorable, bidi-control, and byte-length rules.
#[must_use]
pub fn is_valid_source_identifier(value: &str) -> bool {
    validate_source_identifier(value).is_ok()
}

// Keep this list identical to revision 0.1's lexical keyword table.
const REVISION_0_1_KEYWORDS: &[&str] = &[
    "module",
    "pub",
    "import",
    "from",
    "as",
    "const",
    "brand",
    "fn",
    "async",
    "isr",
    "comptime",
    "struct",
    "class",
    "enum",
    "iface",
    "impl",
    "for",
    "projection",
    "scope",
    "implements",
    "region",
    "view",
    "mut",
    "iso",
    "read",
    "take",
    "self",
    "if",
    "elif",
    "else",
    "match",
    "case",
    "bind",
    "in",
    "not",
    "while",
    "loop",
    "with",
    "enter",
    "abort",
    "exit",
    "shadow",
    "return",
    "break",
    "continue",
    "pass",
    "assert",
    "send",
    "try",
    "yield",
    "await",
    "copy",
    "race",
    "true",
    "false",
    "unit",
    "or",
    "and",
    "is",
];

// Revision 0.1's fixed Unicode 16 default-ignorable and bidi-format-control
// exclusions. These ranges intentionally mirror the source lexer contract.
const FORBIDDEN_IDENTIFIER_CODE_POINT_RANGES: &[(u32, u32)] = &[
    (0x00ad, 0x00ad),
    (0x034f, 0x034f),
    (0x061c, 0x061c),
    (0x115f, 0x1160),
    (0x17b4, 0x17b5),
    (0x180b, 0x180f),
    (0x200b, 0x200f),
    (0x202a, 0x202e),
    (0x2060, 0x206f),
    (0x3164, 0x3164),
    (0xfe00, 0xfe0f),
    (0xfeff, 0xfeff),
    (0xffa0, 0xffa0),
    (0xfff0, 0xfff8),
    (0x1bca0, 0x1bca3),
    (0x1d173, 0x1d17a),
    (0xe0000, 0xe0fff),
];

/// Exact source location understood only by a driver-injected package source
/// provider. Locators are data: this crate never dereferences them.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PackageLocator {
    /// Canonical path relative to the workspace root.
    Workspace { path: String },
    /// Content-addressed archive in an explicitly configured provider.
    Archive { provider: String, key: String },
    /// Compiler-distributed package, such as the standard library.
    Toolchain { component: String },
}

/// Dependency declaration before the canonical lockfile selects an identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestDependency {
    pub alias: DependencyAlias,
    pub package: PackageName,
    /// Exact requirement spelling. Resolution policy is owned by the loader.
    pub requirement: String,
}

/// One full bootable image entry point declared by the root package.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageDeclaration {
    pub name: String,
    /// Entry module path. Must equal a module derived from the package's
    /// source-root walk; the loader checks this once modules are derived.
    pub module: ModulePath,
    pub entry: String,
    pub target: wrela_build_model::TargetIdentity,
    pub profile: String,
}

/// Host-authored scenario for a full-image test. It selects a real image root;
/// it does not introduce a hosted runtime or alternate language semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageTestDeclaration {
    pub name: String,
    pub image: String,
    pub scenario: String,
    pub boot_timeout_ns: u64,
    pub shutdown_timeout_ns: u64,
    pub maximum_events: u32,
    pub maximum_output_bytes: u64,
    pub deterministic_seed: Option<u64>,
}

/// Decoded, validated `wrela.toml` model.
///
/// Modules are not declared here: the loader derives them from a deterministic
/// walk of `source_root`, mapping every `*.wr` file to the module path given by
/// its root-relative path (`/` becomes `.`, the `.wr` suffix is dropped). See
/// `wrela_package_loader`'s workspace loader for the derivation and the
/// image-module cross-reference check, which both require filesystem access
/// this pure model crate deliberately does not have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageManifest {
    pub schema: u32,
    pub language: LanguageRevision,
    pub name: PackageName,
    pub version: PackageVersion,
    pub source_root: String,
    pub dependencies: Vec<ManifestDependency>,
    pub profiles: Vec<BuildProfile>,
    pub images: Vec<ImageDeclaration>,
    pub image_tests: Vec<ImageTestDeclaration>,
}

impl PackageManifest {
    /// Validate canonical order and cross-references after TOML decoding.
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.schema != MANIFEST_SCHEMA_VERSION {
            return Err(ManifestError::UnsupportedManifestSchema(self.schema));
        }
        validate_source_path(&self.source_root)?;
        require_strict_order(
            self.profiles.iter().map(|profile| profile.name.clone()),
            "build profile",
        )?;
        require_strict_order(
            self.dependencies
                .iter()
                .map(|dependency| dependency.alias.as_str().to_owned()),
            "dependency alias",
        )?;
        require_strict_order(self.images.iter().map(|image| image.name.clone()), "image")?;
        require_strict_order(
            self.image_tests.iter().map(|test| test.name.clone()),
            "image test",
        )?;
        if self.dependencies.len() > MAX_DEPENDENCIES_PER_PACKAGE {
            return Err(ManifestError::TooManyDependencies);
        }
        for dependency in &self.dependencies {
            if exact_requirement_version(&dependency.requirement).is_none() {
                return Err(ManifestError::InvalidDependencyRequirement(
                    bounded_manifest_error_value(dependency.alias.as_str()),
                ));
            }
        }
        for profile in &self.profiles {
            validate_declared_atom(&profile.name, "profile name")?;
            profile.validate().map_err(|error| {
                ManifestError::InvalidProfile(bounded_manifest_error_value(&error.to_string()))
            })?;
        }
        let profile_names: BTreeSet<_> = self
            .profiles
            .iter()
            .map(|profile| profile.name.as_str())
            .collect();
        let image_names: BTreeSet<_> = self
            .images
            .iter()
            .map(|image| image.name.as_str())
            .collect();
        for image in &self.images {
            validate_declared_atom(&image.name, "image name")?;
            validate_manifest_source_identifier(&image.entry, "image entry")?;
            validate_declared_atom(&image.profile, "profile name")?;
            if image.target != wrela_build_model::TargetIdentity::aarch64_qemu_virt_uefi() {
                return Err(ManifestError::UnsupportedImageTarget {
                    image: bounded_manifest_error_value(&image.name),
                    target: bounded_manifest_error_value(image.target.as_str()),
                });
            }
            // `image.module` existence is checked by the loader once modules
            // are derived from a filesystem walk; this pure model has no
            // filesystem access.
            if !profile_names.contains(image.profile.as_str()) {
                return Err(ManifestError::UnknownImageProfile {
                    image: bounded_manifest_error_value(&image.name),
                    profile: bounded_manifest_error_value(&image.profile),
                });
            }
        }
        for test in &self.image_tests {
            validate_declared_atom(&test.name, "image test name")?;
            validate_source_path(&test.scenario)?;
            if test.boot_timeout_ns == 0
                || test.shutdown_timeout_ns == 0
                || test.maximum_events == 0
                || test.maximum_output_bytes == 0
            {
                return Err(ManifestError::InvalidTestLimits(
                    bounded_manifest_error_value(&test.name),
                ));
            }
            if !image_names.contains(test.image.as_str()) {
                return Err(ManifestError::UnknownTestImage(
                    bounded_manifest_error_value(&test.image),
                ));
            }
        }
        Ok(())
    }
}

/// One resolved package in canonical lockfile order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedPackage {
    pub identity: PackageIdentity,
    pub locator: PackageLocator,
    /// Aliases and exact identities of direct dependencies.
    pub dependencies: Vec<LockedDependency>,
    /// Digest of canonical manifest bytes within the acquired package.
    pub manifest_digest: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockedDependency {
    pub alias: DependencyAlias,
    pub identity: PackageIdentity,
}

/// Canonical `wrela.lock` model. The root entry is explicit and all transitive
/// package bytes are pinned by digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lockfile {
    pub schema: u32,
    pub root: PackageIdentity,
    pub packages: Vec<LockedPackage>,
}

impl Lockfile {
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.schema != LOCKFILE_SCHEMA_VERSION {
            return Err(ManifestError::UnsupportedLockfileSchema(self.schema));
        }
        if self.packages.len() > MAX_PACKAGES {
            return Err(ManifestError::TooManyLockedPackages {
                count: self.packages.len(),
                limit: MAX_PACKAGES,
            });
        }
        if !self
            .packages
            .windows(2)
            .all(|pair| pair[0].identity < pair[1].identity)
        {
            return Err(ManifestError::NonCanonicalOrder("locked package"));
        }
        let root_index = if let Ok(index) = self
            .packages
            .binary_search_by(|package| package.identity.cmp(&self.root))
        {
            index
        } else {
            return Err(ManifestError::MissingRootPackage);
        };
        for package in &self.packages {
            validate_locator(&package.locator)?;
            if !package
                .dependencies
                .windows(2)
                .all(|pair| pair[0].alias < pair[1].alias)
            {
                return Err(ManifestError::NonCanonicalOrder("locked dependency"));
            }
            for dependency in &package.dependencies {
                if self
                    .packages
                    .binary_search_by(|candidate| candidate.identity.cmp(&dependency.identity))
                    .is_err()
                {
                    return Err(ManifestError::MissingLockedDependency {
                        package: bounded_package_identity(&package.identity),
                        dependency: bounded_package_identity(&dependency.identity),
                    });
                }
            }
        }
        let mut reachable = vec![false; self.packages.len()];
        let mut pending = VecDeque::with_capacity(self.packages.len());
        reachable[root_index] = true;
        pending.push_back(root_index);
        while let Some(package_index) = pending.pop_front() {
            for dependency in &self.packages[package_index].dependencies {
                let dependency_index = self
                    .packages
                    .binary_search_by(|candidate| candidate.identity.cmp(&dependency.identity))
                    .expect("locked dependency existence was validated above");
                if !reachable[dependency_index] {
                    reachable[dependency_index] = true;
                    pending.push_back(dependency_index);
                }
            }
        }
        if let Some(unreachable_index) = reachable.iter().position(|reachable| !reachable) {
            return Err(ManifestError::UnreachableLockedPackage {
                package: bounded_package_identity(&self.packages[unreachable_index].identity),
            });
        }
        Ok(())
    }
}

/// Dense package identity within one build graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PackageId(pub u32);

/// Dense module identity within one build graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ModuleId(pub u32);

/// Opaque package reference valid only while constructing a graph.
///
/// It is deliberately distinct from [`PackageId`]: final IDs are assigned in
/// canonical identity order, independently of discovery order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PackageHandle(u32);

/// Opaque module reference valid only while constructing a graph.
///
/// Final [`ModuleId`] values are assigned in canonical package/path order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ModuleHandle(u32);

/// Human-facing package name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PackageName(String);

impl PackageName {
    pub fn new(value: impl Into<String>) -> Result<Self, GraphError> {
        let value = value.into();
        validate_name_component(&value).map_err(GraphError::InvalidPackageName)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Exact package version spelling from its manifest.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PackageVersion(String);

impl PackageVersion {
    pub fn new(value: impl Into<String>) -> Result<Self, GraphError> {
        let value = value.into();
        validate_version(&value).map_err(GraphError::InvalidPackageVersion)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Local source-facing name for one dependency edge.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct DependencyAlias(String);

impl DependencyAlias {
    pub fn new(value: impl Into<String>) -> Result<Self, GraphError> {
        let value = value.into();
        validate_source_identifier(&value).map_err(GraphError::InvalidDependencyAlias)?;
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Nominal package identity fixed by the language specification.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PackageIdentity {
    pub name: PackageName,
    pub version: PackageVersion,
    pub source_digest: Sha256Digest,
}

/// Canonical dot-separated module path.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ModulePath(Vec<String>);

impl ModulePath {
    pub fn new(segments: impl IntoIterator<Item = String>) -> Result<Self, GraphError> {
        let segments: Vec<_> = segments.into_iter().collect();
        if segments.is_empty() {
            return Err(GraphError::EmptyModulePath);
        }
        for segment in &segments {
            validate_source_identifier(segment).map_err(GraphError::InvalidModuleSegment)?;
        }
        Ok(Self(segments))
    }

    #[must_use]
    pub fn segments(&self) -> &[String] {
        &self.0
    }

    #[must_use]
    pub fn dotted(&self) -> String {
        self.0.join(".")
    }

    /// Canonical source path beneath a package's source root.
    #[must_use]
    pub fn expected_source_path(&self) -> String {
        format!("{}.wr", self.0.join("/"))
    }

    fn portable_key(&self) -> Vec<String> {
        self.0
            .iter()
            .map(|segment| segment.to_ascii_lowercase())
            .collect()
    }
}

/// Revision 0.1 deliberately supports exact dependency requirements only.
/// This keeps lockfile verification deterministic without an implicit package
/// registry, range solver, prerelease policy, or update policy.
#[must_use]
pub fn exact_requirement_version(requirement: &str) -> Option<PackageVersion> {
    let version = requirement.strip_prefix('=')?;
    if version.is_empty() || version.starts_with('=') {
        return None;
    }
    PackageVersion::new(version.to_owned()).ok()
}

/// One package in deterministic graph order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageRecord {
    pub id: PackageId,
    pub identity: PackageIdentity,
    pub dependencies: Vec<DependencyEdge>,
}

/// Canonically ordered dependency visible to package name resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyEdge {
    pub alias: DependencyAlias,
    pub package: PackageId,
}

/// One source module in deterministic graph order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleRecord {
    pub id: ModuleId,
    pub package: PackageId,
    pub path: ModulePath,
    pub source: FileId,
}

/// Complete validated package/module/source closure for one build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageGraph {
    root: PackageId,
    packages: Vec<PackageRecord>,
    modules: Vec<ModuleRecord>,
}

impl PackageGraph {
    #[must_use]
    pub fn root(&self) -> PackageId {
        self.root
    }

    #[must_use]
    pub fn packages(&self) -> &[PackageRecord] {
        &self.packages
    }

    #[must_use]
    pub fn modules(&self) -> &[ModuleRecord] {
        &self.modules
    }

    #[must_use]
    pub fn package(&self, id: PackageId) -> Option<&PackageRecord> {
        self.packages.get(id.0 as usize)
    }
}

/// Deterministic graph construction with duplicate and edge validation.
#[derive(Debug)]
pub struct PackageGraphBuilder {
    root: PackageHandle,
    packages: Vec<PendingPackage>,
    modules: Vec<PendingModule>,
    identities: BTreeSet<PackageIdentity>,
    module_paths: BTreeSet<(PackageHandle, ModulePath)>,
    portable_module_paths: BTreeSet<(PackageHandle, Vec<String>)>,
    module_sources: BTreeSet<FileId>,
}

#[derive(Debug)]
struct PendingPackage {
    identity: PackageIdentity,
    dependencies: Vec<PendingDependency>,
    dependency_aliases: BTreeSet<String>,
    dependency_packages: BTreeSet<PackageHandle>,
}

#[derive(Debug)]
struct PendingDependency {
    alias: DependencyAlias,
    package: PackageHandle,
}

#[derive(Debug)]
struct PendingModule {
    package: PackageHandle,
    path: ModulePath,
    source: FileId,
}

impl PackageGraphBuilder {
    #[must_use]
    pub fn new(root_identity: PackageIdentity) -> Self {
        let root = PackageHandle(0);
        let mut identities = BTreeSet::new();
        identities.insert(root_identity.clone());
        Self {
            root,
            packages: vec![PendingPackage {
                identity: root_identity,
                dependencies: Vec::new(),
                dependency_aliases: BTreeSet::new(),
                dependency_packages: BTreeSet::new(),
            }],
            modules: Vec::new(),
            identities,
            module_paths: BTreeSet::new(),
            portable_module_paths: BTreeSet::new(),
            module_sources: BTreeSet::new(),
        }
    }

    /// Root package identity allocated by construction.
    #[must_use]
    pub fn root(&self) -> PackageHandle {
        self.root
    }

    pub fn add_package(&mut self, identity: PackageIdentity) -> Result<PackageHandle, GraphError> {
        if self.packages.len() >= MAX_PACKAGES {
            return Err(GraphError::GraphTooLarge);
        }
        if !self.identities.insert(identity.clone()) {
            return Err(GraphError::DuplicatePackage(identity));
        }
        let handle = PackageHandle(
            self.packages
                .len()
                .try_into()
                .map_err(|_| GraphError::GraphTooLarge)?,
        );
        self.packages.push(PendingPackage {
            identity,
            dependencies: Vec::new(),
            dependency_aliases: BTreeSet::new(),
            dependency_packages: BTreeSet::new(),
        });
        Ok(handle)
    }

    pub fn add_dependency(
        &mut self,
        package: PackageHandle,
        alias: DependencyAlias,
        dependency: PackageHandle,
    ) -> Result<(), GraphError> {
        if package == dependency {
            return Err(GraphError::SelfDependency(package));
        }
        if self.package_index(package).is_none() {
            return Err(GraphError::UnknownPackage(package));
        }
        if self.package_index(dependency).is_none() {
            return Err(GraphError::UnknownPackage(dependency));
        }
        let pending = &mut self.packages[package.0 as usize];
        let portable_alias = alias.as_str().to_ascii_lowercase();
        if pending.dependency_aliases.contains(&portable_alias) {
            return Err(GraphError::DuplicateDependencyAlias { package, alias });
        }
        if pending.dependency_packages.contains(&dependency) {
            return Err(GraphError::DuplicateDependencyPackage {
                package,
                dependency,
            });
        }
        if pending.dependencies.len() >= MAX_DEPENDENCIES_PER_PACKAGE {
            return Err(GraphError::TooManyDependencies(package));
        }
        pending.dependency_aliases.insert(portable_alias);
        pending.dependency_packages.insert(dependency);
        pending.dependencies.push(PendingDependency {
            alias,
            package: dependency,
        });
        Ok(())
    }

    pub fn add_module(
        &mut self,
        package: PackageHandle,
        path: ModulePath,
        source: FileId,
    ) -> Result<ModuleHandle, GraphError> {
        if self.modules.len() >= MAX_MODULES {
            return Err(GraphError::GraphTooLarge);
        }
        if self.package_index(package).is_none() {
            return Err(GraphError::UnknownPackage(package));
        }
        let exact_key = (package, path.clone());
        if self.module_paths.contains(&exact_key) {
            return Err(GraphError::DuplicateModule { package, path });
        }
        let portable_key = (package, path.portable_key());
        if self.portable_module_paths.contains(&portable_key) {
            return Err(GraphError::PortableModuleCollision { package, path });
        }
        if !self.module_sources.insert(source) {
            return Err(GraphError::DuplicateModuleSource(source));
        }
        let handle = ModuleHandle(
            self.modules
                .len()
                .try_into()
                .map_err(|_| GraphError::GraphTooLarge)?,
        );
        self.modules.push(PendingModule {
            package,
            path,
            source,
        });
        self.module_paths.insert(exact_key);
        self.portable_module_paths.insert(portable_key);
        Ok(handle)
    }

    pub fn finish(self) -> Result<PackageGraph, GraphError> {
        reject_dependency_cycles(&self.packages)?;
        reject_unreachable_packages(&self.packages, self.root)?;

        // Root is always zero. Every other identity is ordered by its complete
        // nominal identity, including the source digest, not discovery order.
        let mut order: Vec<_> = (1..self.packages.len()).collect();
        order.sort_by(|left, right| {
            self.packages[*left]
                .identity
                .cmp(&self.packages[*right].identity)
        });
        order.insert(0, 0);

        let mut final_ids = vec![PackageId(0); self.packages.len()];
        for (final_index, pending_index) in order.iter().copied().enumerate() {
            final_ids[pending_index] = PackageId(
                final_index
                    .try_into()
                    .map_err(|_| GraphError::GraphTooLarge)?,
            );
        }

        let mut packages = Vec::with_capacity(self.packages.len());
        for pending_index in order {
            let pending = &self.packages[pending_index];
            let mut dependencies: Vec<_> = pending
                .dependencies
                .iter()
                .map(|edge| DependencyEdge {
                    alias: edge.alias.clone(),
                    package: final_ids[edge.package.0 as usize],
                })
                .collect();
            dependencies.sort_by(|left, right| left.alias.cmp(&right.alias));
            packages.push(PackageRecord {
                id: final_ids[pending_index],
                identity: pending.identity.clone(),
                dependencies,
            });
        }

        let mut pending_modules = self.modules;
        pending_modules.sort_by(|left, right| {
            (final_ids[left.package.0 as usize], &left.path)
                .cmp(&(final_ids[right.package.0 as usize], &right.path))
        });
        let mut modules = Vec::with_capacity(pending_modules.len());
        for (index, pending) in pending_modules.into_iter().enumerate() {
            modules.push(ModuleRecord {
                id: ModuleId(index.try_into().map_err(|_| GraphError::GraphTooLarge)?),
                package: final_ids[pending.package.0 as usize],
                path: pending.path,
                source: pending.source,
            });
        }

        Ok(PackageGraph {
            root: PackageId(0),
            packages,
            modules,
        })
    }

    fn package_index(&self, id: PackageHandle) -> Option<usize> {
        let index = id.0 as usize;
        (index < self.packages.len()).then_some(index)
    }
}

fn reject_dependency_cycles(packages: &[PendingPackage]) -> Result<(), GraphError> {
    let mut remaining_dependencies: Vec<_> = packages
        .iter()
        .map(|package| package.dependencies.len())
        .collect();
    let mut dependents = vec![Vec::<usize>::new(); packages.len()];
    for (package_index, package) in packages.iter().enumerate() {
        for dependency in &package.dependencies {
            dependents[dependency.package.0 as usize].push(package_index);
        }
    }
    let mut ready: BTreeSet<_> = remaining_dependencies
        .iter()
        .enumerate()
        .filter_map(|(index, count)| (*count == 0).then_some(index))
        .collect();
    let mut completed = 0usize;
    while let Some(index) = ready.pop_first() {
        completed += 1;
        for dependent in &dependents[index] {
            remaining_dependencies[*dependent] -= 1;
            if remaining_dependencies[*dependent] == 0 {
                ready.insert(*dependent);
            }
        }
    }
    if completed != packages.len() {
        let index = remaining_dependencies
            .iter()
            .position(|count| *count != 0)
            .unwrap_or(0);
        return Err(GraphError::DependencyCycle(PackageHandle(index as u32)));
    }
    Ok(())
}

fn reject_unreachable_packages(
    packages: &[PendingPackage],
    root: PackageHandle,
) -> Result<(), GraphError> {
    debug_assert!(packages.len() <= MAX_PACKAGES);
    let mut reachable = vec![false; packages.len()];
    let mut pending = VecDeque::with_capacity(packages.len());
    reachable[root.0 as usize] = true;
    pending.push_back(root.0 as usize);
    while let Some(package_index) = pending.pop_front() {
        for dependency in &packages[package_index].dependencies {
            let dependency_index = dependency.package.0 as usize;
            if !reachable[dependency_index] {
                reachable[dependency_index] = true;
                pending.push_back(dependency_index);
            }
        }
    }
    if let Some(index) = reachable.iter().position(|reachable| !reachable) {
        return Err(GraphError::UnreachablePackage(PackageHandle(index as u32)));
    }
    Ok(())
}

fn require_strict_order(
    values: impl IntoIterator<Item = String>,
    kind: &'static str,
) -> Result<(), ManifestError> {
    let mut previous: Option<String> = None;
    for value in values {
        if previous.as_ref().is_some_and(|previous| previous >= &value) {
            return Err(ManifestError::NonCanonicalOrder(kind));
        }
        previous = Some(value);
    }
    Ok(())
}

/// Validate a portable, NFC-normalized, `/`-separated manifest-relative path.
///
/// Rejects a leading separator, `\`, `:`, control characters, non-NFC
/// spellings, and any empty, `.`, or `..` component. Shared by manifest field
/// validation (`source_root`, image-test `scenario`) and by the loader's
/// derived module-path walk, which applies the same rule to every discovered
/// `*.wr` file since `[[module]]` no longer declares them.
pub fn validate_source_path(path: &str) -> Result<(), ManifestError> {
    if path.is_empty()
        || path.len() > 4096
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.nfc().collect::<String>() != path
        || path.chars().any(|character| {
            character == '\0' || character == '\\' || character == ':' || character.is_control()
        })
        || path
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(ManifestError::InvalidSourcePath(
            bounded_manifest_error_value(path),
        ));
    }
    Ok(())
}

fn validate_manifest_source_identifier(
    value: &str,
    kind: &'static str,
) -> Result<(), ManifestError> {
    validate_source_identifier(value).map_err(|_| ManifestError::InvalidSourceIdentifier {
        kind,
        value: bounded_manifest_error_value(value),
    })
}

fn validate_declared_atom(value: &str, kind: &'static str) -> Result<(), ManifestError> {
    if value.is_empty()
        || value.len() > 4096
        || value.nfc().collect::<String>() != value
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(ManifestError::InvalidAtom {
            kind,
            value: bounded_manifest_error_value(value),
        });
    }
    Ok(())
}

fn bounded_package_identity(identity: &PackageIdentity) -> String {
    bounded_manifest_error_value(&format!(
        "{}@{}",
        identity.name.as_str(),
        identity.version.as_str()
    ))
}

fn bounded_manifest_error_value(value: &str) -> String {
    if value.len() <= MAX_MANIFEST_ERROR_VALUE_BYTES {
        return value.to_owned();
    }
    const TRUNCATION_MARKER: &str = "…";
    let mut end = MAX_MANIFEST_ERROR_VALUE_BYTES - TRUNCATION_MARKER.len();
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    let mut bounded = String::with_capacity(MAX_MANIFEST_ERROR_VALUE_BYTES);
    bounded.push_str(&value[..end]);
    bounded.push_str(TRUNCATION_MARKER);
    bounded
}

fn validate_locator(locator: &PackageLocator) -> Result<(), ManifestError> {
    match locator {
        // `.` is the sole canonical spelling for the package at the workspace
        // capability root (the ordinary public-CLI layout where `wrela.toml`
        // and `wrela.lock` are siblings). It is handled as a marker, never as
        // a path component. All other workspace locators use the portable
        // relative-path contract and continue to reject dot components.
        PackageLocator::Workspace { path } if path == "." => Ok(()),
        PackageLocator::Workspace { path } => validate_source_path(path),
        PackageLocator::Archive { provider, key } => {
            validate_declared_atom(provider, "package provider")?;
            validate_declared_atom(key, "package key")
        }
        PackageLocator::Toolchain { component } => {
            validate_declared_atom(component, "toolchain component")
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    UnsupportedManifestSchema(u32),
    UnsupportedLockfileSchema(u32),
    NonCanonicalOrder(&'static str),
    InvalidSourcePath(String),
    InvalidDependencyRequirement(String),
    TooManyDependencies,
    TooManyLockedPackages { count: usize, limit: usize },
    InvalidProfile(String),
    InvalidSourceIdentifier { kind: &'static str, value: String },
    InvalidAtom { kind: &'static str, value: String },
    UnknownImageProfile { image: String, profile: String },
    UnsupportedImageTarget { image: String, target: String },
    InvalidTestLimits(String),
    UnknownTestImage(String),
    MissingRootPackage,
    MissingLockedDependency { package: String, dependency: String },
    UnreachableLockedPackage { package: String },
}

impl fmt::Display for ManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedManifestSchema(schema) => {
                write!(formatter, "unsupported manifest schema {schema}")
            }
            Self::UnsupportedLockfileSchema(schema) => {
                write!(formatter, "unsupported lockfile schema {schema}")
            }
            Self::NonCanonicalOrder(kind) => {
                write!(formatter, "{kind} entries are not strictly ordered")
            }
            Self::InvalidSourcePath(path) => {
                write!(
                    formatter,
                    "invalid manifest source path {:?}",
                    bounded_manifest_error_value(path)
                )
            }
            Self::InvalidDependencyRequirement(alias) => {
                write!(
                    formatter,
                    "dependency {} must use one exact revision 0.1 requirement (=version)",
                    bounded_manifest_error_value(alias)
                )
            }
            Self::TooManyDependencies => write!(
                formatter,
                "manifest exceeds the dependency-count limit of {MAX_DEPENDENCIES_PER_PACKAGE}"
            ),
            Self::TooManyLockedPackages { count, limit } => write!(
                formatter,
                "lockfile contains {count} packages; limit is {limit}"
            ),
            Self::InvalidProfile(message) => write!(
                formatter,
                "invalid build profile: {}",
                bounded_manifest_error_value(message)
            ),
            Self::InvalidSourceIdentifier { kind, value } => {
                write!(
                    formatter,
                    "invalid source identifier for {kind}: {:?}",
                    bounded_manifest_error_value(value)
                )
            }
            Self::InvalidAtom { kind, value } => write!(
                formatter,
                "invalid {kind} {:?}",
                bounded_manifest_error_value(value)
            ),
            Self::UnknownImageProfile { image, profile } => write!(
                formatter,
                "image {} refers to unknown build profile {}",
                bounded_manifest_error_value(image),
                bounded_manifest_error_value(profile)
            ),
            Self::UnsupportedImageTarget { image, target } => write!(
                formatter,
                "image {} selects unsupported revision 0.1 target {}",
                bounded_manifest_error_value(image),
                bounded_manifest_error_value(target)
            ),
            Self::InvalidTestLimits(test) => {
                write!(
                    formatter,
                    "image test {} has an invalid zero limit",
                    bounded_manifest_error_value(test)
                )
            }
            Self::UnknownTestImage(image) => {
                write!(
                    formatter,
                    "image test refers to unknown image {}",
                    bounded_manifest_error_value(image)
                )
            }
            Self::MissingRootPackage => {
                formatter.write_str("lockfile does not contain its root package")
            }
            Self::MissingLockedDependency {
                package,
                dependency,
            } => write!(
                formatter,
                "locked package {} refers to missing dependency {}",
                bounded_manifest_error_value(package),
                bounded_manifest_error_value(dependency)
            ),
            Self::UnreachableLockedPackage { package } => write!(
                formatter,
                "locked package {} is not reachable from the root package",
                bounded_manifest_error_value(package)
            ),
        }
    }
}

impl std::error::Error for ManifestError {}

/// Invalid package graph or canonical name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphError {
    InvalidPackageName(String),
    InvalidPackageVersion(String),
    InvalidDependencyAlias(String),
    EmptyModulePath,
    InvalidModuleSegment(String),
    DuplicatePackage(PackageIdentity),
    UnknownPackage(PackageHandle),
    SelfDependency(PackageHandle),
    DuplicateDependencyAlias {
        package: PackageHandle,
        alias: DependencyAlias,
    },
    DuplicateDependencyPackage {
        package: PackageHandle,
        dependency: PackageHandle,
    },
    DuplicateModule {
        package: PackageHandle,
        path: ModulePath,
    },
    PortableModuleCollision {
        package: PackageHandle,
        path: ModulePath,
    },
    DuplicateModuleSource(FileId),
    DependencyCycle(PackageHandle),
    UnreachablePackage(PackageHandle),
    TooManyDependencies(PackageHandle),
    GraphTooLarge,
}

impl fmt::Display for GraphError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPackageName(reason) => write!(formatter, "invalid package name: {reason}"),
            Self::InvalidPackageVersion(reason) => {
                write!(formatter, "invalid package version: {reason}")
            }
            Self::InvalidDependencyAlias(reason) => {
                write!(formatter, "invalid dependency alias: {reason}")
            }
            Self::EmptyModulePath => formatter.write_str("module path is empty"),
            Self::InvalidModuleSegment(reason) => {
                write!(formatter, "invalid module path segment: {reason}")
            }
            Self::DuplicatePackage(identity) => write!(
                formatter,
                "duplicate package {}@{}",
                identity.name.as_str(),
                identity.version.as_str()
            ),
            Self::UnknownPackage(id) => write!(formatter, "unknown package {}", id.0),
            Self::SelfDependency(id) => write!(formatter, "package {} depends on itself", id.0),
            Self::DuplicateDependencyAlias { package, alias } => write!(
                formatter,
                "dependency alias {} is duplicated in package {}",
                alias.as_str(),
                package.0
            ),
            Self::DuplicateDependencyPackage {
                package,
                dependency,
            } => write!(
                formatter,
                "package {} declares package {} more than once",
                package.0, dependency.0
            ),
            Self::DuplicateModule { package, path } => write!(
                formatter,
                "duplicate module {} in package {}",
                path.dotted(),
                package.0
            ),
            Self::PortableModuleCollision { package, path } => write!(
                formatter,
                "module {} collides under portable path comparison in package {}",
                path.dotted(),
                package.0
            ),
            Self::DuplicateModuleSource(source) => write!(
                formatter,
                "source {} is assigned to more than one module",
                source.0
            ),
            Self::DependencyCycle(id) => {
                write!(
                    formatter,
                    "package dependency cycle through package {}",
                    id.0
                )
            }
            Self::UnreachablePackage(id) => write!(
                formatter,
                "package {} is not reachable from the root package",
                id.0
            ),
            Self::TooManyDependencies(id) => write!(
                formatter,
                "package {} exceeds the dependency-count limit of {}",
                id.0, MAX_DEPENDENCIES_PER_PACKAGE
            ),
            Self::GraphTooLarge => {
                formatter.write_str("package graph exceeds its configured size limit")
            }
        }
    }
}

impl std::error::Error for GraphError {}

fn validate_name_component(value: &str) -> Result<(), String> {
    validate_atom(value, false)
}

fn validate_source_identifier(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err("value is empty".to_owned());
    }
    if value.len() > 255 {
        return Err("value exceeds 255 UTF-8 bytes".to_owned());
    }
    if value == "_" {
        return Err("the wildcard spelling `_` is not an identifier".to_owned());
    }
    if value.chars().nfc().ne(value.chars()) {
        return Err("value is not in Unicode NFC".to_owned());
    }
    if REVISION_0_1_KEYWORDS.contains(&value) {
        return Err("value is a reserved revision 0.1 keyword".to_owned());
    }
    if let Some(character) = value
        .chars()
        .find(|character| is_forbidden_identifier_character(*character))
    {
        return Err(format!(
            "forbidden default-ignorable or bidi format control U+{:04X}",
            character as u32
        ));
    }
    let mut characters = value.chars();
    let first = characters.next().expect("nonempty identifier");
    if !is_xid_start(first) {
        return Err(format!(
            "first character U+{:04X} is not Unicode 16 XID_Start",
            first as u32
        ));
    }
    if let Some(character) = characters.find(|character| !is_xid_continue(*character)) {
        return Err(format!(
            "character U+{:04X} is not Unicode 16 XID_Continue",
            character as u32
        ));
    }
    Ok(())
}

fn is_forbidden_identifier_character(character: char) -> bool {
    let value = character as u32;
    FORBIDDEN_IDENTIFIER_CODE_POINT_RANGES
        .iter()
        .any(|(start, end)| (*start..=*end).contains(&value))
}

fn validate_version(value: &str) -> Result<(), String> {
    validate_atom(value, true)
}

fn validate_atom(value: &str, allow_dot: bool) -> Result<(), String> {
    if value.is_empty() {
        return Err("value is empty".to_owned());
    }
    if value.len() > 255 {
        return Err("value exceeds 255 UTF-8 bytes".to_owned());
    }
    if value.nfc().collect::<String>() != value {
        return Err("value is not in Unicode NFC".to_owned());
    }
    if let Some(character) = value.chars().find(|character| {
        character.is_control()
            || character.is_whitespace()
            || matches!(character, '/' | '\\' | ':')
            || (!allow_dot && *character == '.')
    }) {
        return Err(format!("forbidden character {character:?}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use wrela_build_model::{BuildProfile, LanguageRevision, Sha256Digest, TargetIdentity};
    use wrela_source::FileId;

    use super::{
        DependencyAlias, FORBIDDEN_IDENTIFIER_CODE_POINT_RANGES, GraphError, ImageDeclaration,
        ImageTestDeclaration, LOCKFILE_SCHEMA_VERSION, LockedDependency, LockedPackage, Lockfile,
        MANIFEST_SCHEMA_VERSION, MAX_MANIFEST_ERROR_VALUE_BYTES, ManifestError, ModulePath,
        PackageGraphBuilder, PackageIdentity, PackageLocator, PackageManifest, PackageName,
        PackageVersion, REVISION_0_1_KEYWORDS, bounded_manifest_error_value,
        validate_declared_atom, validate_source_identifier, validate_source_path,
    };

    fn identity(name: &str) -> PackageIdentity {
        PackageIdentity {
            name: PackageName::new(name).expect("package name"),
            version: PackageVersion::new("1").expect("version"),
            source_digest: Sha256Digest::from_bytes([name.len() as u8; 32]),
        }
    }

    fn manifest_with_image_entry(entry: &str) -> PackageManifest {
        let module = ModulePath::new(["app".to_owned()]).expect("module path");
        PackageManifest {
            schema: MANIFEST_SCHEMA_VERSION,
            language: LanguageRevision::Design0_1,
            name: PackageName::new("root").expect("package name"),
            version: PackageVersion::new("1.0.0").expect("package version"),
            source_root: "src".to_owned(),
            dependencies: Vec::new(),
            profiles: vec![BuildProfile::development()],
            images: vec![ImageDeclaration {
                name: "boot-image".to_owned(),
                module,
                entry: entry.to_owned(),
                target: TargetIdentity::aarch64_qemu_virt_uefi(),
                profile: "development".to_owned(),
            }],
            image_tests: Vec::new(),
        }
    }

    fn locked_package(
        identity: PackageIdentity,
        dependencies: Vec<LockedDependency>,
    ) -> LockedPackage {
        let path = format!("packages/{}", identity.name.as_str());
        LockedPackage {
            identity,
            locator: PackageLocator::Workspace { path },
            dependencies,
            manifest_digest: Sha256Digest::from_bytes([0x42; 32]),
        }
    }

    fn lockfile(root: PackageIdentity, mut packages: Vec<LockedPackage>) -> Lockfile {
        packages.sort_by(|left, right| left.identity.cmp(&right.identity));
        Lockfile {
            schema: LOCKFILE_SCHEMA_VERSION,
            root,
            packages,
        }
    }

    #[test]
    fn graph_ids_and_module_order_are_stable() {
        let mut builder = PackageGraphBuilder::new(identity("root"));
        let dependency = builder.add_package(identity("dep")).expect("dependency");
        builder
            .add_dependency(
                builder.root,
                DependencyAlias::new("dep").expect("alias"),
                dependency,
            )
            .expect("edge");
        builder
            .add_module(
                builder.root,
                ModulePath::new(["main".to_owned()]).expect("module path"),
                FileId(0),
            )
            .expect("module");
        let graph = builder.finish().expect("acyclic graph");
        assert_eq!(graph.packages().len(), 2);
        assert_eq!(graph.modules()[0].source, FileId(0));
    }

    #[test]
    fn final_ids_do_not_depend_on_discovery_order() {
        fn build(reverse: bool) -> super::PackageGraph {
            let mut builder = PackageGraphBuilder::new(identity("root"));
            let (alpha, zulu) = if reverse {
                let zulu = builder.add_package(identity("zulu")).expect("zulu");
                let alpha = builder.add_package(identity("alpha")).expect("alpha");
                (alpha, zulu)
            } else {
                let alpha = builder.add_package(identity("alpha")).expect("alpha");
                let zulu = builder.add_package(identity("zulu")).expect("zulu");
                (alpha, zulu)
            };
            builder
                .add_dependency(
                    builder.root(),
                    DependencyAlias::new("zulu").expect("zulu alias"),
                    zulu,
                )
                .expect("root to zulu");
            builder
                .add_dependency(
                    builder.root(),
                    DependencyAlias::new("alpha").expect("alpha alias"),
                    alpha,
                )
                .expect("root to alpha");
            builder
                .add_module(
                    zulu,
                    ModulePath::new(["zulu".to_owned()]).expect("zulu module"),
                    FileId(2),
                )
                .expect("zulu module");
            builder
                .add_module(
                    alpha,
                    ModulePath::new(["alpha".to_owned()]).expect("alpha module"),
                    FileId(1),
                )
                .expect("alpha module");
            builder.finish().expect("canonical graph")
        }

        assert_eq!(build(false), build(true));
    }

    #[test]
    fn versions_allow_dots_and_modules_reject_portable_collisions() {
        assert!(PackageVersion::new("1.2.3-alpha.1").is_ok());

        let mut builder = PackageGraphBuilder::new(identity("root"));
        builder
            .add_module(
                builder.root(),
                ModulePath::new(["Main".to_owned()]).expect("first path"),
                FileId(0),
            )
            .expect("first module");
        assert!(
            builder
                .add_module(
                    builder.root(),
                    ModulePath::new(["main".to_owned()]).expect("second path"),
                    FileId(1),
                )
                .is_err()
        );
    }

    #[test]
    fn one_source_cannot_back_multiple_modules() {
        let mut builder = PackageGraphBuilder::new(identity("root"));
        let root = builder.root();
        builder
            .add_module(
                root,
                ModulePath::new(["first".to_owned()]).expect("first path"),
                FileId(0),
            )
            .expect("first module");
        assert!(matches!(
            builder.add_module(
                root,
                ModulePath::new(["second".to_owned()]).expect("second path"),
                FileId(0),
            ),
            Err(GraphError::DuplicateModuleSource(FileId(0)))
        ));
    }

    #[test]
    fn disconnected_dependency_cycles_preserve_cycle_errors() {
        let mut builder = PackageGraphBuilder::new(identity("root"));
        let alpha = builder.add_package(identity("alpha")).expect("alpha");
        let beta = builder.add_package(identity("beta")).expect("beta");
        builder
            .add_dependency(
                alpha,
                DependencyAlias::new("beta").expect("beta alias"),
                beta,
            )
            .expect("alpha to beta");
        builder
            .add_dependency(
                beta,
                DependencyAlias::new("alpha").expect("alpha alias"),
                alpha,
            )
            .expect("beta to alpha");
        assert!(matches!(
            builder.finish(),
            Err(GraphError::DependencyCycle(handle)) if handle == alpha
        ));
    }

    #[test]
    fn graph_rejects_an_isolated_package() {
        let mut builder = PackageGraphBuilder::new(identity("root"));
        let isolated = builder
            .add_package(identity("isolated"))
            .expect("isolated package");
        assert!(matches!(
            builder.finish(),
            Err(GraphError::UnreachablePackage(handle)) if handle == isolated
        ));
    }

    #[test]
    fn lockfile_rejects_an_isolated_package() {
        let root = identity("root");
        let isolated = identity("isolated");
        let lockfile = lockfile(
            root.clone(),
            vec![
                locked_package(root, Vec::new()),
                locked_package(isolated, Vec::new()),
            ],
        );
        assert!(matches!(
            lockfile.validate(),
            Err(ManifestError::UnreachableLockedPackage { package })
                if package == "isolated@1"
        ));
    }

    #[test]
    fn lockfile_rejects_a_disconnected_dependency_cycle() {
        let root = identity("root");
        let alpha = identity("alpha");
        let beta = identity("beta");
        let lockfile = lockfile(
            root.clone(),
            vec![
                locked_package(root, Vec::new()),
                locked_package(
                    alpha.clone(),
                    vec![LockedDependency {
                        alias: DependencyAlias::new("beta").expect("beta alias"),
                        identity: beta.clone(),
                    }],
                ),
                locked_package(
                    beta,
                    vec![LockedDependency {
                        alias: DependencyAlias::new("alpha").expect("alpha alias"),
                        identity: alpha,
                    }],
                ),
            ],
        );
        assert!(matches!(
            lockfile.validate(),
            Err(ManifestError::UnreachableLockedPackage { package })
                if package == "alpha@1"
        ));
    }

    #[test]
    fn every_revision_keyword_is_rejected_in_source_facing_manifest_names() {
        assert_eq!(REVISION_0_1_KEYWORDS.len(), 59);
        for keyword in REVISION_0_1_KEYWORDS {
            assert!(
                DependencyAlias::new((*keyword).to_owned()).is_err(),
                "dependency alias accepted keyword {keyword:?}"
            );
            assert!(
                ModulePath::new([(*keyword).to_owned()]).is_err(),
                "module segment accepted keyword {keyword:?}"
            );
            assert!(matches!(
                manifest_with_image_entry(keyword).validate(),
                Err(ManifestError::InvalidSourceIdentifier {
                    kind: "image entry",
                    value,
                }) if value == *keyword
            ));
        }
    }

    #[test]
    fn every_forbidden_identifier_code_point_is_rejected() {
        for &(start, end) in FORBIDDEN_IDENTIFIER_CODE_POINT_RANGES {
            for value in start..=end {
                let character = char::from_u32(value).expect("Unicode scalar range");
                let spelling = format!("a{character}b");
                assert!(
                    validate_source_identifier(&spelling).is_err(),
                    "identifier accepted U+{value:04X}"
                );
            }
        }
    }

    #[test]
    fn source_identifier_rules_apply_at_all_manifest_boundaries() {
        for invalid in [
            "_",
            "_hidden",
            "9start",
            "bad-name",
            "de\u{301}composed",
            "a\u{200b}b",
            "for",
        ] {
            assert!(DependencyAlias::new(invalid.to_owned()).is_err());
            assert!(ModulePath::new([invalid.to_owned()]).is_err());
            assert!(matches!(
                manifest_with_image_entry(invalid).validate(),
                Err(ManifestError::InvalidSourceIdentifier {
                    kind: "image entry",
                    ..
                })
            ));
        }
    }

    #[test]
    fn unicode_16_nfc_source_identifiers_are_accepted() {
        assert_eq!(unicode_normalization::UNICODE_VERSION, (16, 0, 0));
        // U+1C89 entered XID_Start in Unicode 16.0.0, so this case also guards
        // the revision's pinned property-table version rather than only ASCII.
        for identifier in ["Delta", "Δelta", "café", "变量", "a_1", "\u{1c89}name"] {
            DependencyAlias::new(identifier.to_owned()).expect("dependency alias");
            ModulePath::new([identifier.to_owned()]).expect("module path");
            manifest_with_image_entry(identifier)
                .validate()
                .expect("image entry");
        }
    }

    #[test]
    fn nominal_manifest_names_remain_non_source_atoms() {
        PackageName::new("for-package").expect("nominal package name");
        PackageName::new("for").expect("keyword package name");
        validate_declared_atom("for-profile", "profile name").expect("profile atom");
        validate_declared_atom("for-image", "image name").expect("image atom");
        validate_declared_atom("for-test", "image test name").expect("test atom");

        let mut manifest = manifest_with_image_entry("start");
        manifest.profiles[0].name = "for-profile".to_owned();
        manifest.images[0].name = "for-image".to_owned();
        manifest.images[0].profile = "for-profile".to_owned();
        manifest.image_tests.push(ImageTestDeclaration {
            name: "for-test".to_owned(),
            image: "for-image".to_owned(),
            scenario: "tests/for-test.toml".to_owned(),
            boot_timeout_ns: 1,
            shutdown_timeout_ns: 1,
            maximum_events: 1,
            maximum_output_bytes: 1,
            deterministic_seed: None,
        });
        manifest.validate().expect("nominal manifest atoms");
    }

    #[test]
    fn manifest_error_values_are_bounded_on_utf8_boundaries() {
        let long_ascii = "x".repeat(8_192);
        let invalid_path = format!("/{long_ascii}");
        let path_error = validate_source_path(&invalid_path).expect_err("invalid path");
        let ManifestError::InvalidSourcePath(path) = path_error else {
            panic!("unexpected source path error");
        };
        assert!(path.len() <= MAX_MANIFEST_ERROR_VALUE_BYTES);
        assert!(path.ends_with('…'));

        let atom_error =
            validate_declared_atom(&long_ascii, "image name").expect_err("oversized manifest atom");
        let ManifestError::InvalidAtom { value, .. } = atom_error else {
            panic!("unexpected manifest atom error");
        };
        assert!(value.len() <= MAX_MANIFEST_ERROR_VALUE_BYTES);
        assert!(value.ends_with('…'));

        let multibyte = bounded_manifest_error_value(&"é".repeat(8_192));
        assert!(multibyte.len() <= MAX_MANIFEST_ERROR_VALUE_BYTES);
        assert!(multibyte.ends_with('…'));

        let rendered = ManifestError::UnknownTestImage(long_ascii).to_string();
        assert!(rendered.len() <= MAX_MANIFEST_ERROR_VALUE_BYTES + 48);
        assert!(rendered.ends_with('…'));
    }

    #[test]
    fn manifest_profile_names_must_be_unicode_nfc() {
        let mut profile = BuildProfile::development();
        profile.name = "de\u{301}velopment".to_owned();
        let manifest = PackageManifest {
            schema: MANIFEST_SCHEMA_VERSION,
            language: LanguageRevision::Design0_1,
            name: PackageName::new("root").expect("package name"),
            version: PackageVersion::new("1.0.0").expect("package version"),
            source_root: "src".to_owned(),
            dependencies: Vec::new(),
            profiles: vec![profile],
            images: Vec::new(),
            image_tests: Vec::new(),
        };
        assert!(matches!(
            manifest.validate(),
            Err(ManifestError::InvalidAtom {
                kind: "profile name",
                ..
            })
        ));
    }

    #[test]
    fn workspace_root_has_one_exact_locator_spelling() {
        let root = identity("root");
        let mut package = locked_package(root.clone(), Vec::new());
        package.locator = PackageLocator::Workspace {
            path: ".".to_owned(),
        };
        lockfile(root.clone(), vec![package])
            .validate()
            .expect("exact workspace-root locator");

        for path in ["", "..", "./child", "child/.", "child/../other"] {
            let mut package = locked_package(root.clone(), Vec::new());
            package.locator = PackageLocator::Workspace {
                path: path.to_owned(),
            };
            assert!(lockfile(root.clone(), vec![package]).validate().is_err());
        }
    }
}
