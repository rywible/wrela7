//! Concrete local-filesystem input host and load-to-parse composition.
//!
//! These providers deliberately use path-based standard-library I/O so they
//! are portable and dependency-free. They reject symlinks and revalidate
//! canonical containment plus file identity before and after every read.
//! Those checks fail closed for observable replacement, but they are not a
//! race-free directory capability: an adversarial process can still race
//! pathname resolution between individual `std::fs` operations. Callers using
//! a hostile multi-user filesystem must place the workspace and toolchain
//! roots behind an OS-level capability/sandbox or inject an `openat`-style
//! host.

use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use wrela_package::{ModuleId, PackageIdentity, PackageLocator, PackageName, PackageVersion};
use wrela_package_loader::{
    CanonicalPackageCodec, CanonicalWorkspaceLoader, ContentHasher, LoadError, LoadLimits,
    LoadRequest, LoadedWorkspace, ManifestCodecLimits, PackageBundle, PackageCodec,
    PackageContentDigestError, PackageContentKind, PackageContentRecord, PackageSourceProvider,
    ProviderError, ScenarioInput, SoftwareSha256, WorkspaceLoader, package_content_digest,
};
use wrela_source::{FileId, MAX_SOURCE_PATH_BYTES, SourceInput};
use wrela_syntax::{
    ParseFailure, ParseLimits, ParseOutput, ParseRequest, ParseUsage, SyntaxParser,
    WrelaSyntaxParser,
};
use wrela_toolchain::{ShippedStandardLibraryPackage, VerifiedToolchain};

const MANIFEST_FILE_NAME: &str = "wrela.toml";
const LOCKFILE_FILE_NAME: &str = "wrela.lock";
const READ_CHUNK_BYTES: usize = 64 * 1024;
const MAX_HOST_PATH_BYTES: usize = 64 * 1024;
const CANCELLED_MESSAGE: &str = "package acquisition was cancelled";
const MAX_TOOLCHAIN_INDEX_COPY_BYTES: u64 = 16 * 1024 * 1024;

/// Local provider rooted at one predeclared canonical directory.
///
/// Only [`PackageLocator::Workspace`] is supported. Archive and toolchain
/// locators require separately configured capabilities and are never resolved
/// implicitly by this host.
#[derive(Debug, Clone)]
pub struct LocalWorkspaceProvider {
    root: LocalPackageRoot,
}

impl LocalWorkspaceProvider {
    /// Bind the provider to an existing, absolute, canonical, symlink-free
    /// workspace root.
    pub fn new(workspace_root: impl AsRef<Path>) -> Result<Self, ProviderError> {
        Ok(Self {
            root: LocalPackageRoot::new(workspace_root.as_ref())?,
        })
    }

    #[must_use]
    pub fn workspace_root(&self) -> &Path {
        self.root.path()
    }

    fn package_directory(&self, locator: &PackageLocator) -> Result<PathBuf, ProviderError> {
        let PackageLocator::Workspace { path } = locator else {
            return Err(access_denied(
                "local provider does not support archive or toolchain locators",
            ));
        };
        if path == "." {
            return Ok(self.root.path().to_path_buf());
        }
        join_portable_relative(self.root.path(), path)
    }

    fn read_root_manifest(
        &self,
        locator: &PackageLocator,
        maximum_bytes: u64,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<StableFile, ProviderError> {
        let package_directory = self.package_directory(locator)?;
        let path = join_fixed_name(&package_directory, MANIFEST_FILE_NAME)?;
        self.root
            .read_stable_file(&path, maximum_bytes, maximum_bytes, is_cancelled)
    }

    fn read_lockfile(
        &self,
        maximum_bytes: u64,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<StableFile, ProviderError> {
        let path = join_fixed_name(self.root.path(), LOCKFILE_FILE_NAME)?;
        self.root
            .read_stable_file(&path, maximum_bytes, maximum_bytes, is_cancelled)
    }
}

impl PackageSourceProvider for LocalWorkspaceProvider {
    fn acquire(
        &self,
        locator: &PackageLocator,
        expected: &PackageIdentity,
        maximum_bytes: u64,
        maximum_manifest_bytes: u64,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<PackageBundle, ProviderError> {
        check_cancelled(is_cancelled)?;
        let package_directory = self.package_directory(locator)?;
        acquire_local_package(
            &self.root,
            &package_directory,
            locator,
            expected,
            LocalAcquisitionLimits {
                total_bytes: maximum_bytes,
                manifest_bytes: maximum_manifest_bytes,
            },
            None,
            is_cancelled,
        )
    }
}

/// Local provider rooted at the standard-library directory from a verified
/// toolchain installation.
///
/// Only [`PackageLocator::Toolchain`] is supported. Each locator component is
/// a portable relative path naming one package below the sealed standard-
/// library root; workspace and archive locators always fail closed.
#[derive(Debug, Clone)]
pub struct LocalToolchainPackageProvider {
    root: LocalPackageRoot,
    packages: Arc<Vec<ShippedStandardLibraryPackage>>,
}

impl LocalToolchainPackageProvider {
    /// Select and bind the standard-library capability from a fully verified
    /// toolchain installation. The provider retains a fallibly copied exact
    /// package index; a directory capability without this identity/manifest
    /// evidence is intentionally insufficient to construct a provider.
    pub fn from_toolchain(toolchain: &VerifiedToolchain) -> Result<Self, ProviderError> {
        let standard_library = toolchain
            .standard_library()
            .map_err(|_| access_denied("verified toolchain has no standard-library capability"))?;
        Ok(Self {
            root: LocalPackageRoot::new(standard_library.path())?,
            packages: Arc::new(copy_toolchain_package_index(toolchain)?),
        })
    }

    #[must_use]
    pub fn standard_library_root(&self) -> &Path {
        self.root.path()
    }

    fn package_directory(&self, locator: &PackageLocator) -> Result<PathBuf, ProviderError> {
        let PackageLocator::Toolchain { component } = locator else {
            return Err(access_denied(
                "toolchain provider supports only toolchain locators",
            ));
        };
        join_portable_relative(self.root.path(), component)
    }
}

impl PackageSourceProvider for LocalToolchainPackageProvider {
    fn acquire(
        &self,
        locator: &PackageLocator,
        expected: &PackageIdentity,
        maximum_bytes: u64,
        maximum_manifest_bytes: u64,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<PackageBundle, ProviderError> {
        check_cancelled(is_cancelled)?;
        let package_directory = self.package_directory(locator)?;
        let indexed = self
            .packages
            .binary_search_by(|package| package.identity.cmp(expected))
            .ok()
            .and_then(|index| self.packages.get(index))
            .ok_or(ProviderError::IdentityMismatch)?;
        if &indexed.locator != locator {
            return Err(ProviderError::IdentityMismatch);
        }
        acquire_local_package(
            &self.root,
            &package_directory,
            locator,
            expected,
            LocalAcquisitionLimits {
                total_bytes: maximum_bytes,
                manifest_bytes: maximum_manifest_bytes,
            },
            Some(indexed.manifest_digest),
            is_cancelled,
        )
    }
}

fn copy_toolchain_package_index(
    toolchain: &VerifiedToolchain,
) -> Result<Vec<ShippedStandardLibraryPackage>, ProviderError> {
    let declared = toolchain.standard_library_packages();
    let mut packages = Vec::new();
    packages
        .try_reserve_exact(declared.len())
        .map_err(|_| ProviderError::TooLarge {
            limit: MAX_TOOLCHAIN_INDEX_COPY_BYTES,
        })?;
    let mut copied_bytes = 0u64;
    for package in declared {
        let component = match &package.locator {
            PackageLocator::Toolchain { component } => component,
            PackageLocator::Workspace { .. } | PackageLocator::Archive { .. } => {
                return Err(corrupt(
                    "verified standard-library index contains a non-toolchain locator",
                ));
            }
        };
        for value in [
            package.identity.name.as_str(),
            package.identity.version.as_str(),
            component.as_str(),
        ] {
            copied_bytes = copied_bytes
                .checked_add(u64::try_from(value.len()).unwrap_or(u64::MAX))
                .ok_or(ProviderError::TooLarge {
                    limit: MAX_TOOLCHAIN_INDEX_COPY_BYTES,
                })?;
            if copied_bytes > MAX_TOOLCHAIN_INDEX_COPY_BYTES {
                return Err(ProviderError::TooLarge {
                    limit: MAX_TOOLCHAIN_INDEX_COPY_BYTES,
                });
            }
        }
        let identity = PackageIdentity {
            name: PackageName::new(copy_bounded_path(
                package.identity.name.as_str(),
                MAX_TOOLCHAIN_INDEX_COPY_BYTES,
            )?)
            .map_err(|_| corrupt("verified standard-library package name is invalid"))?,
            version: PackageVersion::new(copy_bounded_path(
                package.identity.version.as_str(),
                MAX_TOOLCHAIN_INDEX_COPY_BYTES,
            )?)
            .map_err(|_| corrupt("verified standard-library package version is invalid"))?,
            source_digest: package.identity.source_digest,
        };
        packages.push(ShippedStandardLibraryPackage {
            identity,
            locator: PackageLocator::Toolchain {
                component: copy_bounded_path(component, MAX_TOOLCHAIN_INDEX_COPY_BYTES)?,
            },
            manifest_digest: package.manifest_digest,
        });
    }
    Ok(packages)
}

/// Explicit local provider composition for workspace and verified toolchain
/// packages. Archive locators have no configured capability and fail closed.
#[derive(Debug, Clone)]
pub struct LocalPackageProvider {
    workspace: LocalWorkspaceProvider,
    toolchain: LocalToolchainPackageProvider,
}

impl LocalPackageProvider {
    #[must_use]
    pub const fn new(
        workspace: LocalWorkspaceProvider,
        toolchain: LocalToolchainPackageProvider,
    ) -> Self {
        Self {
            workspace,
            toolchain,
        }
    }

    #[must_use]
    pub const fn workspace_provider(&self) -> &LocalWorkspaceProvider {
        &self.workspace
    }

    #[must_use]
    pub const fn toolchain_provider(&self) -> &LocalToolchainPackageProvider {
        &self.toolchain
    }
}

impl PackageSourceProvider for LocalPackageProvider {
    fn acquire(
        &self,
        locator: &PackageLocator,
        expected: &PackageIdentity,
        maximum_bytes: u64,
        maximum_manifest_bytes: u64,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<PackageBundle, ProviderError> {
        check_cancelled(is_cancelled)?;
        match locator {
            PackageLocator::Workspace { .. } => self.workspace.acquire(
                locator,
                expected,
                maximum_bytes,
                maximum_manifest_bytes,
                is_cancelled,
            ),
            PackageLocator::Toolchain { .. } => self.toolchain.acquire(
                locator,
                expected,
                maximum_bytes,
                maximum_manifest_bytes,
                is_cancelled,
            ),
            PackageLocator::Archive { .. } => Err(access_denied(
                "local provider has no configured archive capability",
            )),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct LocalAcquisitionLimits {
    total_bytes: u64,
    manifest_bytes: u64,
}

fn acquire_local_package(
    root: &LocalPackageRoot,
    package_directory: &Path,
    locator: &PackageLocator,
    expected: &PackageIdentity,
    limits: LocalAcquisitionLimits,
    expected_manifest_digest: Option<wrela_build_model::Sha256Digest>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<PackageBundle, ProviderError> {
    check_cancelled(is_cancelled)?;
    let maximum_bytes = limits.total_bytes;
    let maximum_manifest_bytes = limits.manifest_bytes;
    if maximum_bytes == 0 {
        return Err(ProviderError::TooLarge { limit: 0 });
    }
    if maximum_manifest_bytes == 0 {
        return Err(ProviderError::TooLarge { limit: 0 });
    }
    let effective_manifest_bytes = maximum_manifest_bytes.min(maximum_bytes);
    let manifest_path = join_fixed_name(package_directory, MANIFEST_FILE_NAME)?;
    let manifest_file = root.read_stable_file(
        &manifest_path,
        effective_manifest_bytes,
        effective_manifest_bytes,
        is_cancelled,
    )?;
    let mut remaining = maximum_bytes
        .checked_sub(u64::try_from(manifest_file.bytes.len()).unwrap_or(u64::MAX))
        .ok_or(ProviderError::TooLarge {
            limit: maximum_bytes,
        })?;

    // Toolchain packages must agree with the verified installation index
    // before manifest-controlled source paths are decoded or opened.
    if expected_manifest_digest.is_some_and(|expected| expected != manifest_file.digest) {
        return Err(ProviderError::IdentityMismatch);
    }
    let codec = CanonicalPackageCodec::new();
    let codec_limits = manifest_codec_limits(effective_manifest_bytes);
    let manifest = codec
        .decode_manifest(&manifest_file.bytes, codec_limits, is_cancelled)
        .map_err(|error| map_manifest_error(error, effective_manifest_bytes))?;
    if manifest.name != expected.name || manifest.version != expected.version {
        return Err(ProviderError::IdentityMismatch);
    }
    reject_duplicate_declarations(&manifest)?;

    // There is no `[[module]]` list to consult: every acquired module source
    // is one `*.wr` regular file discovered by a deterministic, portable,
    // symlink-rejecting walk of `source_root`. Each file is still read
    // through `root.read_stable_file`, so the same race-free
    // open/hash/re-validate contract applies as it did for a manifest-
    // declared path.
    let mut sources = Vec::new();
    let source_directory = join_portable_relative(package_directory, &manifest.source_root)?;
    walk_module_source_files(
        root,
        &source_directory,
        "",
        0,
        &mut sources,
        &mut remaining,
        maximum_bytes,
        is_cancelled,
    )?;

    let mut scenarios = Vec::new();
    scenarios
        .try_reserve_exact(manifest.image_tests.len())
        .map_err(|_| ProviderError::TooLarge {
            limit: maximum_bytes,
        })?;
    for test in &manifest.image_tests {
        check_cancelled(is_cancelled)?;
        let scenario_path = join_portable_relative(package_directory, &test.scenario)?;
        let scenario_file =
            root.read_stable_file(&scenario_path, remaining, maximum_bytes, is_cancelled)?;
        remaining = subtract_bytes(remaining, scenario_file.bytes.len(), maximum_bytes)?;
        validate_utf8(&scenario_file.bytes, is_cancelled)
            .map_err(|error| map_utf8_error(error, "declared scenario is not valid UTF-8"))?;
        scenarios.push(ScenarioInput {
            package: expected.clone(),
            path: copy_bounded_path(&test.scenario, maximum_bytes)?,
            bytes: scenario_file.bytes,
            digest: scenario_file.digest,
        });
    }

    let canonical_manifest = codec
        .canonical_manifest(&manifest, codec_limits, is_cancelled)
        .map_err(|error| map_manifest_error(error, effective_manifest_bytes))?;
    verify_package_content(
        expected,
        &canonical_manifest,
        &sources,
        &scenarios,
        maximum_bytes,
        is_cancelled,
    )?;
    check_cancelled(is_cancelled)?;
    Ok(PackageBundle {
        identity: expected.clone(),
        locator: locator.clone(),
        manifest_bytes: manifest_file.bytes,
        sources,
        scenarios,
    })
}

/// Concrete request for the filesystem load-to-parse vertical.
#[derive(Debug, Clone, Copy)]
pub struct FrontendWorkspaceRequest<'a> {
    pub root_locator: &'a PackageLocator,
    pub load_limits: LoadLimits,
    pub parse_limits: ParseLimits,
}

/// One sealed workspace paired with parser outputs in canonical graph-module
/// order. Index `ModuleId(n)` corresponds to `parsed_modules()[n]`.
#[derive(Debug, Clone, PartialEq)]
pub struct FrontendWorkspace {
    workspace: LoadedWorkspace,
    parsed_modules: Vec<ParseOutput>,
    parse_usage: ParseUsage,
    remaining_parse_limits: ParseLimits,
}

impl FrontendWorkspace {
    #[must_use]
    pub fn workspace(&self) -> &LoadedWorkspace {
        &self.workspace
    }

    #[must_use]
    pub fn parsed_modules(&self) -> &[ParseOutput] {
        &self.parsed_modules
    }

    #[must_use]
    pub fn parsed_module(&self, module: ModuleId) -> Option<&ParseOutput> {
        usize::try_from(module.0)
            .ok()
            .and_then(|index| self.parsed_modules.get(index))
    }

    /// Exact aggregate usage remeasured by each retained parser-output seal.
    #[must_use]
    pub const fn parse_usage(&self) -> ParseUsage {
        self.parse_usage
    }

    /// Exact unconsumed additive command budgets after every retained module.
    #[must_use]
    pub const fn remaining_parse_limits(&self) -> ParseLimits {
        self.remaining_parse_limits
    }

    #[must_use]
    pub fn into_parts(self) -> (LoadedWorkspace, Vec<ParseOutput>) {
        (self.workspace, self.parsed_modules)
    }
}

/// Production input composition using the concrete loader, codec, SHA-256,
/// and revision-0.1 syntax parser.
#[derive(Debug, Clone)]
pub struct LocalFrontendService {
    workspace_provider: LocalWorkspaceProvider,
    package_provider: Option<LocalPackageProvider>,
    workspace_loader: CanonicalWorkspaceLoader,
    package_codec: CanonicalPackageCodec,
    hasher: SoftwareSha256,
    parser: WrelaSyntaxParser,
}

impl LocalFrontendService {
    /// Construct a workspace-only frontend. Toolchain and archive locators
    /// remain unsupported and fail closed during package acquisition.
    pub fn new(workspace_root: impl AsRef<Path>) -> Result<Self, FrontendInputError> {
        let workspace_provider =
            LocalWorkspaceProvider::new(workspace_root).map_err(FrontendInputError::Provider)?;
        Ok(Self::from_providers(workspace_provider, None))
    }

    /// Construct a workspace frontend by selecting the standard-library
    /// capability from a complete verified toolchain.
    pub fn new_with_toolchain(
        workspace_root: impl AsRef<Path>,
        toolchain: &VerifiedToolchain,
    ) -> Result<Self, FrontendInputError> {
        let workspace =
            LocalWorkspaceProvider::new(workspace_root).map_err(FrontendInputError::Provider)?;
        let toolchain = LocalToolchainPackageProvider::from_toolchain(toolchain)
            .map_err(FrontendInputError::Provider)?;
        Ok(Self::with_package_provider(LocalPackageProvider::new(
            workspace, toolchain,
        )))
    }

    /// Construct from an already configured local workspace/toolchain
    /// provider. Root manifest and lockfile reads still use only its workspace
    /// capability.
    #[must_use]
    pub fn with_package_provider(provider: LocalPackageProvider) -> Self {
        Self::from_providers(provider.workspace.clone(), Some(provider))
    }

    fn from_providers(
        workspace_provider: LocalWorkspaceProvider,
        package_provider: Option<LocalPackageProvider>,
    ) -> Self {
        Self {
            workspace_provider,
            package_provider,
            workspace_loader: CanonicalWorkspaceLoader::new(),
            package_codec: CanonicalPackageCodec::new(),
            hasher: SoftwareSha256,
            parser: WrelaSyntaxParser::new(),
        }
    }

    #[must_use]
    pub fn provider(&self) -> &LocalWorkspaceProvider {
        &self.workspace_provider
    }

    #[must_use]
    pub fn package_provider(&self) -> Option<&LocalPackageProvider> {
        self.package_provider.as_ref()
    }

    pub fn load_and_parse(
        &self,
        request: FrontendWorkspaceRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<FrontendWorkspace, FrontendInputError> {
        request
            .load_limits
            .validate()
            .map_err(FrontendInputError::Load)?;
        request
            .parse_limits
            .validate()
            .map_err(|error| FrontendInputError::Parse { file: None, error })?;
        if is_cancelled() {
            return Err(FrontendInputError::Cancelled);
        }
        let root_manifest = self
            .workspace_provider
            .read_root_manifest(
                request.root_locator,
                request.load_limits.manifest_bytes_per_package,
                is_cancelled,
            )
            .map_err(|error| map_frontend_provider_error(error, is_cancelled))?;
        let lockfile = self
            .workspace_provider
            .read_lockfile(request.load_limits.lockfile_bytes, is_cancelled)
            .map_err(|error| map_frontend_provider_error(error, is_cancelled))?;
        let package_provider: &dyn PackageSourceProvider = self
            .package_provider
            .as_ref()
            .map_or(&self.workspace_provider, |provider| provider);
        let workspace = self
            .workspace_loader
            .load(
                LoadRequest {
                    root_locator: request.root_locator.clone(),
                    root_manifest_bytes: &root_manifest.bytes,
                    lockfile_bytes: &lockfile.bytes,
                    provider: package_provider,
                    hasher: &self.hasher,
                    codec: &self.package_codec,
                    limits: request.load_limits,
                },
                is_cancelled,
            )
            .map_err(map_frontend_load_error)?;

        let module_count = workspace.graph().modules().len();
        let mut parsed_modules = Vec::new();
        parsed_modules
            .try_reserve_exact(module_count)
            .map_err(|_| FrontendInputError::ResourceLimit {
                resource: "parsed module outputs",
                limit: u64::from(request.parse_limits.ast_nodes),
            })?;
        let mut parse_usage = ParseUsage::ZERO;
        let mut remaining_parse_limits = request.parse_limits;
        for (index, module) in workspace.graph().modules().iter().enumerate() {
            if is_cancelled() {
                return Err(FrontendInputError::Cancelled);
            }
            if usize::try_from(module.id.0).ok() != Some(index) {
                return Err(FrontendInputError::InvalidModuleMapping);
            }
            if remaining_parse_limits.tokens == 0 {
                return Err(map_frontend_parse_error(
                    Some(module.source),
                    ParseFailure::ResourceLimit {
                        resource: "tokens",
                        limit: u64::from(request.parse_limits.tokens),
                    },
                ));
            }
            if remaining_parse_limits.ast_nodes == 0 {
                return Err(map_frontend_parse_error(
                    Some(module.source),
                    ParseFailure::ResourceLimit {
                        resource: "AST nodes",
                        limit: u64::from(request.parse_limits.ast_nodes),
                    },
                ));
            }
            let output = self
                .parser
                .parse(
                    ParseRequest {
                        sources: workspace.sources(),
                        file: module.source,
                        limits: remaining_parse_limits,
                    },
                    is_cancelled,
                )
                .map_err(|error| {
                    map_batch_parse_error(Some(module.source), error, request.parse_limits)
                })?;
            if output.parsed().file() != module.source {
                return Err(FrontendInputError::InvalidModuleMapping);
            }
            let output_usage = output.usage();
            parse_usage = parse_usage
                .checked_add(output_usage, request.parse_limits)
                .map_err(|error| {
                    map_batch_parse_error(Some(module.source), error, request.parse_limits)
                })?;
            remaining_parse_limits = remaining_parse_limits
                .remaining_after(output_usage)
                .map_err(|error| {
                    map_batch_parse_error(Some(module.source), error, request.parse_limits)
                })?;
            parsed_modules.push(output);
        }
        if is_cancelled() {
            return Err(FrontendInputError::Cancelled);
        }
        Ok(FrontendWorkspace {
            workspace,
            parsed_modules,
            parse_usage,
            remaining_parse_limits,
        })
    }
}

#[derive(Debug)]
pub enum FrontendInputError {
    Cancelled,
    Provider(ProviderError),
    Load(LoadError),
    Parse {
        file: Option<FileId>,
        error: ParseFailure,
    },
    ResourceLimit {
        resource: &'static str,
        limit: u64,
    },
    InvalidModuleMapping,
}

impl fmt::Display for FrontendInputError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("frontend input was cancelled"),
            Self::Provider(error) => write!(formatter, "local package provider failed: {error}"),
            Self::Load(error) => write!(formatter, "workspace loading failed: {error}"),
            Self::Parse { file, error } => match file {
                Some(file) => write!(formatter, "source {} parsing failed: {error}", file.0),
                None => write!(formatter, "parser configuration failed: {error}"),
            },
            Self::ResourceLimit { resource, limit } => {
                write!(formatter, "frontend exceeded {resource} limit {limit}")
            }
            Self::InvalidModuleMapping => {
                formatter.write_str("loader graph and parser outputs have inconsistent module IDs")
            }
        }
    }
}

impl std::error::Error for FrontendInputError {}

#[derive(Debug, Clone)]
struct LocalPackageRoot {
    path: PathBuf,
    identity: MetadataSnapshot,
}

impl LocalPackageRoot {
    fn new(path: &Path) -> Result<Self, ProviderError> {
        if !normal_absolute_path(path)
            || path.as_os_str().as_encoded_bytes().len() > MAX_HOST_PATH_BYTES
        {
            return Err(access_denied("local package root is not canonical"));
        }
        reject_absolute_symlink_components(path)?;
        let canonical = fs::canonicalize(path)
            .map_err(|error| map_io_error(&error, "local package root is unavailable"))?;
        if canonical != path {
            return Err(access_denied("local package root contains a symlink"));
        }
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| map_io_error(&error, "local package root is unavailable"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(access_denied("local package root is not a real directory"));
        }
        Ok(Self {
            path: canonical,
            identity: MetadataSnapshot::capture(&metadata)?,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn revalidate(&self) -> Result<(), ProviderError> {
        reject_absolute_symlink_components(&self.path)?;
        let canonical = fs::canonicalize(&self.path)
            .map_err(|error| map_io_error(&error, "local package root became unavailable"))?;
        if canonical != self.path {
            return Err(access_denied("local package root containment changed"));
        }
        let metadata = fs::symlink_metadata(&self.path)
            .map_err(|error| map_io_error(&error, "local package root became unavailable"))?;
        let current = MetadataSnapshot::capture(&metadata)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || !self.identity.same_object(&current)
        {
            return Err(corrupt("local package root was replaced"));
        }
        Ok(())
    }

    fn validate_existing_file(&self, path: &Path) -> Result<MetadataSnapshot, ProviderError> {
        self.revalidate()?;
        if !normal_absolute_path(path)
            || !path.starts_with(&self.path)
            || path == self.path
            || path.as_os_str().as_encoded_bytes().len() > MAX_HOST_PATH_BYTES
        {
            return Err(access_denied(
                "declared package file escaped the configured root",
            ));
        }
        let relative = path
            .strip_prefix(&self.path)
            .map_err(|_| access_denied("declared package file escaped the configured root"))?;
        let mut cursor = self.path.clone();
        let mut components = relative.components().peekable();
        if components.peek().is_none() {
            return Err(access_denied("declared package file path is empty"));
        }
        while let Some(component) = components.next() {
            let Component::Normal(segment) = component else {
                return Err(access_denied("declared package file path is not canonical"));
            };
            cursor.push(segment);
            let metadata = fs::symlink_metadata(&cursor)
                .map_err(|error| map_io_error(&error, "declared package file is unavailable"))?;
            if metadata.file_type().is_symlink() {
                return Err(access_denied(
                    "declared package file path contains a symlink",
                ));
            }
            let is_last = components.peek().is_none();
            if (!is_last && !metadata.is_dir()) || (is_last && !metadata.is_file()) {
                return Err(corrupt("declared package path has the wrong file type"));
            }
        }
        let canonical = fs::canonicalize(path)
            .map_err(|error| map_io_error(&error, "declared package file is unavailable"))?;
        if canonical != path || !canonical.starts_with(&self.path) {
            return Err(access_denied(
                "declared package file canonical containment failed",
            ));
        }
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| map_io_error(&error, "declared package file is unavailable"))?;
        MetadataSnapshot::capture(&metadata)
    }

    fn read_stable_file(
        &self,
        path: &Path,
        maximum_bytes: u64,
        aggregate_limit: u64,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<StableFile, ProviderError> {
        check_cancelled(is_cancelled)?;
        let before = self.validate_existing_file(path)?;
        if before.len > maximum_bytes {
            return Err(ProviderError::TooLarge {
                limit: aggregate_limit,
            });
        }
        let mut file = File::open(path)
            .map_err(|error| map_io_error(&error, "declared package file cannot be opened"))?;
        let opened = MetadataSnapshot::capture(
            &file
                .metadata()
                .map_err(|error| map_io_error(&error, "package file metadata failed"))?,
        )?;
        if before != opened {
            return Err(corrupt("package file changed while it was opened"));
        }

        let expected_capacity = usize::try_from(before.len).unwrap_or(usize::MAX);
        let maximum_capacity = usize::try_from(maximum_bytes).unwrap_or(usize::MAX);
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(expected_capacity.min(maximum_capacity))
            .map_err(|_| ProviderError::TooLarge {
                limit: aggregate_limit,
            })?;
        let hasher = SoftwareSha256;
        let mut digest = hasher.begin_sha256();
        let mut buffer = [0u8; READ_CHUNK_BYTES];
        loop {
            check_cancelled(is_cancelled)?;
            let read = file
                .read(&mut buffer)
                .map_err(|error| map_io_error(&error, "package file read failed"))?;
            if read == 0 {
                break;
            }
            let next = bytes
                .len()
                .checked_add(read)
                .ok_or(ProviderError::TooLarge {
                    limit: aggregate_limit,
                })?;
            if u64::try_from(next).unwrap_or(u64::MAX) > maximum_bytes {
                return Err(ProviderError::TooLarge {
                    limit: aggregate_limit,
                });
            }
            bytes
                .try_reserve_exact(read)
                .map_err(|_| ProviderError::TooLarge {
                    limit: aggregate_limit,
                })?;
            bytes.extend_from_slice(&buffer[..read]);
            digest.update(&buffer[..read]);
        }
        check_cancelled(is_cancelled)?;

        let after_handle = MetadataSnapshot::capture(
            &file
                .metadata()
                .map_err(|error| map_io_error(&error, "package file metadata failed"))?,
        )?;
        let after_path = self.validate_existing_file(path)?;
        if before != after_handle || after_handle != after_path {
            return Err(corrupt("package file changed while it was read"));
        }
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) != after_handle.len {
            return Err(corrupt("package file length changed while it was read"));
        }
        check_cancelled(is_cancelled)?;
        Ok(StableFile {
            bytes,
            digest: digest.finish(),
        })
    }
}

#[derive(Debug)]
struct StableFile {
    bytes: Vec<u8>,
    digest: wrela_build_model::Sha256Digest,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MetadataSnapshot {
    dev: u64,
    ino: u64,
    len: u64,
    mode: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[cfg(not(unix))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct MetadataSnapshot {
    len: u64,
    modified: std::time::SystemTime,
}

impl MetadataSnapshot {
    #[cfg(unix)]
    fn capture(metadata: &Metadata) -> Result<Self, ProviderError> {
        Ok(Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            len: metadata.len(),
            mode: metadata.mode(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        })
    }

    #[cfg(not(unix))]
    fn capture(metadata: &Metadata) -> Result<Self, ProviderError> {
        Ok(Self {
            len: metadata.len(),
            modified: metadata
                .modified()
                .map_err(|error| map_io_error(&error, "package file timestamp failed"))?,
        })
    }

    #[cfg(unix)]
    const fn same_object(&self, other: &Self) -> bool {
        self.dev == other.dev && self.ino == other.ino
    }

    #[cfg(not(unix))]
    fn same_object(&self, other: &Self) -> bool {
        self == other
    }
}

fn normal_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && path.components().count() > 1
        && path
            .components()
            .all(|component| !matches!(component, Component::CurDir | Component::ParentDir))
}

fn reject_absolute_symlink_components(path: &Path) -> Result<(), ProviderError> {
    if !normal_absolute_path(path) {
        return Err(access_denied("local package path is not canonical"));
    }
    let mut cursor = PathBuf::new();
    for component in path.components() {
        cursor.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&cursor)
            .map_err(|error| map_io_error(&error, "package path component is unavailable"))?;
        if metadata.file_type().is_symlink() {
            return Err(access_denied("local package path contains a symlink"));
        }
    }
    Ok(())
}

fn join_fixed_name(base: &Path, name: &'static str) -> Result<PathBuf, ProviderError> {
    let mut path = base.to_path_buf();
    path.try_reserve(name.len().saturating_add(1))
        .map_err(|_| corrupt("local package path allocation failed"))?;
    path.push(name);
    if path.as_os_str().as_encoded_bytes().len() > MAX_HOST_PATH_BYTES {
        return Err(access_denied("local package path exceeds the host limit"));
    }
    Ok(path)
}

fn join_portable_relative(base: &Path, relative: &str) -> Result<PathBuf, ProviderError> {
    if relative.is_empty()
        || relative.len() > MAX_SOURCE_PATH_BYTES
        || relative.starts_with('/')
        || relative
            .chars()
            .any(|character| matches!(character, '\\' | ':' | '\0'))
        || relative
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
        || Path::new(relative)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(access_denied(
            "package locator or declared path is not portable",
        ));
    }
    let mut path = base.to_path_buf();
    path.try_reserve(relative.len().saturating_add(1))
        .map_err(|_| corrupt("local package path allocation failed"))?;
    for segment in relative.split('/') {
        path.push(segment);
    }
    if path.as_os_str().as_encoded_bytes().len() > MAX_HOST_PATH_BYTES {
        return Err(access_denied("local package path exceeds the host limit"));
    }
    Ok(path)
}

/// Bound recursive directory depth for [`walk_module_source_files`]. The
/// portable path-length ceiling (`MAX_SOURCE_PATH_BYTES`) already bounds
/// total path bytes; this additionally bounds directory nesting depth.
const MAX_SOURCE_WALK_DEPTH: u32 = 64;

/// Recursively acquire every `*.wr` regular file under `directory` in
/// sorted, portable order as one module source. `prefix` is this
/// subdirectory's slash-separated path relative to the walk root (the
/// package's `source_root`), used verbatim as each discovered file's
/// [`SourceInput::path`]. Each file is opened, hashed, and re-validated
/// through `root.read_stable_file`, so a race replacing an entry between
/// listing and reading still fails closed exactly as a manifest-declared
/// path would have. Symlinks and non-regular entries are rejected; portable
/// component and identifier rules (NFC, no `.`/`..`, no forbidden
/// characters, XID identifiers) are re-validated downstream by the loader,
/// which is the sole authority for a provider's untrusted input.
#[allow(clippy::too_many_arguments)]
fn walk_module_source_files(
    root: &LocalPackageRoot,
    directory: &Path,
    prefix: &str,
    depth: u32,
    sources: &mut Vec<SourceInput>,
    remaining: &mut u64,
    maximum_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ProviderError> {
    check_cancelled(is_cancelled)?;
    if depth > MAX_SOURCE_WALK_DEPTH {
        return Err(access_denied(
            "package source tree exceeds the maximum walk depth",
        ));
    }
    let entries = fs::read_dir(directory)
        .map_err(|error| map_io_error(&error, "package source directory is unavailable"))?;
    let mut names = Vec::new();
    for entry in entries {
        check_cancelled(is_cancelled)?;
        let entry = entry
            .map_err(|error| map_io_error(&error, "package source directory is unavailable"))?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(access_denied(
                "package source entry name is not portable UTF-8",
            ));
        };
        names
            .try_reserve(1)
            .map_err(|_| corrupt("package source tree allocation failed"))?;
        names.push(name.to_owned());
    }
    names.sort();
    for name in names {
        check_cancelled(is_cancelled)?;
        let path = directory.join(&name);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| map_io_error(&error, "package source entry is unavailable"))?;
        if metadata.file_type().is_symlink() {
            return Err(access_denied("package source tree contains a symlink"));
        }
        let relative = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}/{name}")
        };
        if metadata.is_dir() {
            walk_module_source_files(
                root,
                &path,
                &relative,
                depth.saturating_add(1),
                sources,
                remaining,
                maximum_bytes,
                is_cancelled,
            )?;
        } else if metadata.is_file() {
            if name.ends_with(".wr") {
                let source_file =
                    root.read_stable_file(&path, *remaining, maximum_bytes, is_cancelled)?;
                *remaining = subtract_bytes(*remaining, source_file.bytes.len(), maximum_bytes)?;
                let text = decode_utf8(source_file.bytes, is_cancelled)
                    .map_err(|error| map_utf8_error(error, "declared source is not valid UTF-8"))?;
                sources
                    .try_reserve(1)
                    .map_err(|_| ProviderError::TooLarge {
                        limit: maximum_bytes,
                    })?;
                sources.push(SourceInput {
                    path: copy_bounded_path(&relative, maximum_bytes)?,
                    text,
                    digest: source_file.digest,
                });
            }
        } else {
            return Err(corrupt("package source tree contains a non-regular entry"));
        }
    }
    Ok(())
}

fn manifest_codec_limits(maximum_bytes: u64) -> ManifestCodecLimits {
    let entries = u32::try_from(maximum_bytes).unwrap_or(u32::MAX);
    ManifestCodecLimits {
        bytes: maximum_bytes,
        string_bytes: maximum_bytes,
        modules: entries,
        dependencies: entries,
        profiles: entries,
        images: entries,
        image_tests: entries,
    }
}

fn reject_duplicate_declarations(
    manifest: &wrela_package::PackageManifest,
) -> Result<(), ProviderError> {
    // Modules are not declared; they are discovered by a directory walk, so
    // there is no manifest-side source-path list to check for duplicates
    // here (a real directory cannot list one entry name twice).
    let mut scenario_paths = Vec::new();
    scenario_paths
        .try_reserve_exact(manifest.image_tests.len())
        .map_err(|_| corrupt("scenario declaration allocation failed"))?;
    scenario_paths.extend(
        manifest
            .image_tests
            .iter()
            .map(|test| test.scenario.as_str()),
    );
    scenario_paths.sort_unstable();
    if scenario_paths.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(corrupt(
            "manifest declares one scenario file more than once",
        ));
    }
    Ok(())
}

fn verify_package_content(
    expected: &PackageIdentity,
    canonical_manifest: &[u8],
    sources: &[SourceInput],
    scenarios: &[ScenarioInput],
    maximum_bytes: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), ProviderError> {
    let record_count =
        sources
            .len()
            .checked_add(scenarios.len())
            .ok_or(ProviderError::TooLarge {
                limit: maximum_bytes,
            })?;
    let mut records = Vec::new();
    records
        .try_reserve_exact(record_count)
        .map_err(|_| ProviderError::TooLarge {
            limit: maximum_bytes,
        })?;
    records.extend(sources.iter().map(|source| PackageContentRecord {
        kind: PackageContentKind::Source,
        path: source.path.as_str(),
        digest: source.digest,
    }));
    records.extend(scenarios.iter().map(|scenario| PackageContentRecord {
        kind: PackageContentKind::Scenario,
        path: scenario.path.as_str(),
        digest: scenario.digest,
    }));
    records.sort_by_key(|record| (record.kind, record.path));
    let actual =
        package_content_digest(canonical_manifest, &records, &SoftwareSha256, is_cancelled)
            .map_err(|error| match error {
                PackageContentDigestError::Cancelled => {
                    ProviderError::Unavailable(CANCELLED_MESSAGE.to_owned())
                }
                PackageContentDigestError::NonCanonicalInput => {
                    corrupt("package content declarations are not canonical")
                }
            })?;
    if actual != expected.source_digest {
        return Err(corrupt(
            "package content differs from its expected identity",
        ));
    }
    Ok(())
}

fn subtract_bytes(
    remaining: u64,
    bytes: usize,
    aggregate_limit: u64,
) -> Result<u64, ProviderError> {
    remaining
        .checked_sub(u64::try_from(bytes).unwrap_or(u64::MAX))
        .ok_or(ProviderError::TooLarge {
            limit: aggregate_limit,
        })
}

fn copy_bounded_path(value: &str, maximum_bytes: u64) -> Result<String, ProviderError> {
    let mut output = String::new();
    output
        .try_reserve_exact(value.len())
        .map_err(|_| ProviderError::TooLarge {
            limit: maximum_bytes,
        })?;
    output.push_str(value);
    Ok(output)
}

fn decode_utf8(bytes: Vec<u8>, is_cancelled: &dyn Fn() -> bool) -> Result<String, Utf8ReadError> {
    let mut output = String::new();
    output
        .try_reserve_exact(bytes.len())
        .map_err(|_| Utf8ReadError::Allocation)?;
    visit_utf8_chunks(&bytes, is_cancelled, |text| output.push_str(text))?;
    Ok(output)
}

fn validate_utf8(bytes: &[u8], is_cancelled: &dyn Fn() -> bool) -> Result<(), Utf8ReadError> {
    visit_utf8_chunks(bytes, is_cancelled, |_| {})
}

fn visit_utf8_chunks(
    bytes: &[u8],
    is_cancelled: &dyn Fn() -> bool,
    mut visit: impl FnMut(&str),
) -> Result<(), Utf8ReadError> {
    let mut offset = 0usize;
    while offset < bytes.len() {
        if is_cancelled() {
            return Err(Utf8ReadError::Cancelled);
        }
        let mut end = offset.saturating_add(READ_CHUNK_BYTES).min(bytes.len());
        loop {
            match std::str::from_utf8(&bytes[offset..end]) {
                Ok(text) => {
                    visit(text);
                    offset = end;
                    break;
                }
                Err(error) if error.error_len().is_none() && end < bytes.len() => {
                    let valid = error.valid_up_to();
                    if valid == 0 {
                        end = end.saturating_add(3).min(bytes.len());
                        continue;
                    }
                    let valid_end = offset.saturating_add(valid);
                    let text = std::str::from_utf8(&bytes[offset..valid_end])
                        .map_err(|_| Utf8ReadError::Invalid)?;
                    visit(text);
                    offset = valid_end;
                    break;
                }
                Err(_) => return Err(Utf8ReadError::Invalid),
            }
        }
    }
    if is_cancelled() {
        Err(Utf8ReadError::Cancelled)
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Utf8ReadError {
    Cancelled,
    Invalid,
    Allocation,
}

fn map_utf8_error(error: Utf8ReadError, invalid_message: &'static str) -> ProviderError {
    match error {
        Utf8ReadError::Cancelled => ProviderError::Unavailable(CANCELLED_MESSAGE.to_owned()),
        Utf8ReadError::Invalid => corrupt(invalid_message),
        Utf8ReadError::Allocation => corrupt("UTF-8 input allocation failed"),
    }
}

fn map_frontend_provider_error(
    error: ProviderError,
    is_cancelled: &dyn Fn() -> bool,
) -> FrontendInputError {
    if is_cancelled()
        || matches!(&error, ProviderError::Unavailable(message) if message == CANCELLED_MESSAGE)
    {
        FrontendInputError::Cancelled
    } else {
        FrontendInputError::Provider(error)
    }
}

fn map_frontend_load_error(error: LoadError) -> FrontendInputError {
    let cancelled = matches!(&error, LoadError::Cancelled)
        || matches!(
            &error,
            LoadError::Provider {
                error: ProviderError::Unavailable(message),
                ..
            } if message == CANCELLED_MESSAGE
        );
    if cancelled {
        FrontendInputError::Cancelled
    } else {
        FrontendInputError::Load(error)
    }
}

fn map_frontend_parse_error(file: Option<FileId>, error: ParseFailure) -> FrontendInputError {
    if matches!(error, ParseFailure::Cancelled) {
        FrontendInputError::Cancelled
    } else {
        FrontendInputError::Parse { file, error }
    }
}

fn map_batch_parse_error(
    file: Option<FileId>,
    error: ParseFailure,
    command_limits: ParseLimits,
) -> FrontendInputError {
    let error = match error {
        ParseFailure::ResourceLimit {
            resource,
            limit: observed_limit,
        } => {
            let limit = match resource {
                "tokens" => u64::from(command_limits.tokens),
                "AST nodes" => u64::from(command_limits.ast_nodes),
                "literal bytes" => command_limits.literal_bytes,
                "diagnostics" => u64::from(command_limits.diagnostics),
                "diagnostic bytes" => command_limits.diagnostic_bytes,
                _ => observed_limit,
            };
            ParseFailure::ResourceLimit { resource, limit }
        }
        other => other,
    };
    map_frontend_parse_error(file, error)
}

fn map_manifest_error(error: wrela_package_loader::DecodeError, limit: u64) -> ProviderError {
    match error {
        wrela_package_loader::DecodeError::Cancelled => {
            ProviderError::Unavailable(CANCELLED_MESSAGE.to_owned())
        }
        wrela_package_loader::DecodeError::ResourceLimit { .. } => {
            ProviderError::TooLarge { limit }
        }
        _ => corrupt("package manifest is invalid"),
    }
}

fn check_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), ProviderError> {
    if is_cancelled() {
        Err(ProviderError::Unavailable(CANCELLED_MESSAGE.to_owned()))
    } else {
        Ok(())
    }
}

fn map_io_error(error: &std::io::Error, fallback: &'static str) -> ProviderError {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => access_denied("package file access was denied"),
        _ => ProviderError::Unavailable(fallback.to_owned()),
    }
}

fn access_denied(message: &'static str) -> ProviderError {
    ProviderError::AccessDenied(message.to_owned())
}

fn corrupt(message: &'static str) -> ProviderError {
    ProviderError::Corrupt(message.to_owned())
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    use wrela_build_model::Sha256Digest;
    use wrela_package::{
        DependencyAlias, LOCKFILE_SCHEMA_VERSION, LockedDependency, LockedPackage, Lockfile,
        PackageName, PackageVersion,
    };
    use wrela_package_loader::LockfileCodecLimits;

    use super::*;

    const TEST_BYTES: u64 = 4 * 1024 * 1024;
    const MINIMAL_MANIFEST: &[u8] =
        include_bytes!("../../../tests/contracts/package/v1/minimal.toml");
    const SOURCE_TEXT: &str = "module mini\nfn mini():\n    return \"ok\"\n";

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
                    "wrela-compiler-input-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&root) {
                    Ok(()) => {
                        return Self {
                            root: fs::canonicalize(root).expect("canonical test directory"),
                        };
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("cannot create test directory: {error}"),
                }
            }
            panic!("cannot allocate a unique test directory")
        }

        fn write(&self, relative: &str, bytes: &[u8]) -> PathBuf {
            let path = self.root.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("test file parent");
            }
            fs::write(&path, bytes).expect("test file");
            path
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[derive(Debug)]
    struct WorkspaceFixture {
        directory: TestDirectory,
        locator: PackageLocator,
        identity: PackageIdentity,
        manifest_bytes: Vec<u8>,
        lockfile_bytes: Vec<u8>,
        source_bytes: Vec<u8>,
        scenario_bytes: Vec<Vec<u8>>,
        manifest_path: PathBuf,
        source_path: PathBuf,
    }

    impl WorkspaceFixture {
        fn new(source_bytes: &[u8]) -> Self {
            Self::from_inputs(MINIMAL_MANIFEST, source_bytes, &[])
        }

        fn with_scenario(source_bytes: &[u8], scenario_bytes: &[u8]) -> Self {
            let mut manifest =
                String::from_utf8(MINIMAL_MANIFEST.to_vec()).expect("minimal manifest is UTF-8");
            manifest.push_str(
                "\n[[image]]\nname = \"mini\"\nmodule = \"mini\"\nentry = \"image\"\ntarget = \"aarch64-qemu-virt-uefi\"\nprofile = \"development\"\n\n[[image_test]]\nname = \"boot\"\nimage = \"mini\"\nscenario = \"fixtures/boot.toml\"\nboot_timeout_ns = 1\nshutdown_timeout_ns = 1\nmaximum_events = 1\nmaximum_output_bytes = 1\ndeterministic_seed = 1\n",
            );
            Self::from_inputs(
                manifest.as_bytes(),
                source_bytes,
                &[("fixtures/boot.toml", scenario_bytes)],
            )
        }

        fn from_inputs(
            manifest_input: &[u8],
            source_bytes: &[u8],
            scenarios: &[(&str, &[u8])],
        ) -> Self {
            let directory = TestDirectory::new();
            let locator = PackageLocator::Workspace {
                path: "package".to_owned(),
            };
            let codec = CanonicalPackageCodec::new();
            let hasher = SoftwareSha256;
            let manifest = codec
                .decode_manifest(
                    manifest_input,
                    manifest_codec_limits(TEST_BYTES),
                    &never_cancelled,
                )
                .expect("minimal manifest");
            let manifest_bytes = codec
                .canonical_manifest(
                    &manifest,
                    manifest_codec_limits(TEST_BYTES),
                    &never_cancelled,
                )
                .expect("canonical manifest");
            let source_digest = hasher.sha256(source_bytes);
            let mut content_records = vec![PackageContentRecord {
                kind: PackageContentKind::Source,
                path: "mini.wr",
                digest: source_digest,
            }];
            content_records.extend(scenarios.iter().map(|(path, bytes)| PackageContentRecord {
                kind: PackageContentKind::Scenario,
                path,
                digest: hasher.sha256(bytes),
            }));
            content_records.sort_by_key(|record| (record.kind, record.path));
            let package_digest = package_content_digest(
                &manifest_bytes,
                &content_records,
                &hasher,
                &never_cancelled,
            )
            .expect("package content digest");
            let identity = PackageIdentity {
                name: manifest.name,
                version: manifest.version,
                source_digest: package_digest,
            };
            let manifest_digest = hasher.sha256(&manifest_bytes);
            let lockfile = Lockfile {
                schema: LOCKFILE_SCHEMA_VERSION,
                root: identity.clone(),
                packages: vec![LockedPackage {
                    identity: identity.clone(),
                    locator: locator.clone(),
                    dependencies: Vec::new(),
                    manifest_digest,
                }],
            };
            let lockfile_bytes = codec
                .canonical_lockfile(&lockfile, lockfile_limits(), &never_cancelled)
                .expect("canonical lockfile");
            let manifest_path = directory.write("package/wrela.toml", &manifest_bytes);
            let source_path = directory.write("package/src/mini.wr", source_bytes);
            for (path, bytes) in scenarios {
                directory.write(&format!("package/{path}"), bytes);
            }
            directory.write("wrela.lock", &lockfile_bytes);
            Self {
                directory,
                locator,
                identity,
                manifest_bytes,
                lockfile_bytes,
                source_bytes: source_bytes.to_vec(),
                scenario_bytes: scenarios.iter().map(|(_, bytes)| bytes.to_vec()).collect(),
                manifest_path,
                source_path,
            }
        }

        fn provider(&self) -> LocalWorkspaceProvider {
            LocalWorkspaceProvider::new(&self.directory.root).expect("local provider")
        }

        fn total_package_bytes(&self) -> u64 {
            let scenario_bytes = self.scenario_bytes.iter().map(Vec::len).sum::<usize>();
            u64::try_from(self.manifest_bytes.len() + self.source_bytes.len() + scenario_bytes)
                .expect("test package byte count")
        }
    }

    #[derive(Debug)]
    struct CanonicalTestPackage {
        identity: PackageIdentity,
        manifest_bytes: Vec<u8>,
        manifest_digest: Sha256Digest,
        source_path: String,
        source_bytes: Vec<u8>,
    }

    impl CanonicalTestPackage {
        fn new(manifest_input: &[u8], source_path: &str, source_bytes: &[u8]) -> Self {
            let codec = CanonicalPackageCodec::new();
            let manifest = codec
                .decode_manifest(
                    manifest_input,
                    manifest_codec_limits(TEST_BYTES),
                    &never_cancelled,
                )
                .expect("test package manifest");
            let manifest_bytes = codec
                .canonical_manifest(
                    &manifest,
                    manifest_codec_limits(TEST_BYTES),
                    &never_cancelled,
                )
                .expect("canonical test package manifest");
            let source_digest = SoftwareSha256.sha256(source_bytes);
            let package_digest = package_content_digest(
                &manifest_bytes,
                &[PackageContentRecord {
                    kind: PackageContentKind::Source,
                    path: source_path,
                    digest: source_digest,
                }],
                &SoftwareSha256,
                &never_cancelled,
            )
            .expect("test package content digest");
            Self {
                identity: PackageIdentity {
                    name: manifest.name,
                    version: manifest.version,
                    source_digest: package_digest,
                },
                manifest_digest: SoftwareSha256.sha256(&manifest_bytes),
                manifest_bytes,
                source_path: source_path.to_owned(),
                source_bytes: source_bytes.to_vec(),
            }
        }

        fn total_bytes(&self) -> u64 {
            u64::try_from(self.manifest_bytes.len() + self.source_bytes.len())
                .expect("test package byte count")
        }
    }

    #[derive(Debug)]
    struct ToolchainWorkspaceFixture {
        directory: TestDirectory,
        workspace_root: PathBuf,
        standard_library_root: PathBuf,
        root_locator: PackageLocator,
        core_locator: PackageLocator,
        root_identity: PackageIdentity,
        core: CanonicalTestPackage,
        core_source_path: PathBuf,
    }

    impl ToolchainWorkspaceFixture {
        fn new() -> Self {
            Self::with_sources(
                b"module app\nfn image():\n    return \"app\"\n",
                b"module core\nfn core():\n    return \"core\"\n",
            )
        }

        fn with_sources(root_source: &[u8], core_source: &[u8]) -> Self {
            let directory = TestDirectory::new();
            let core_manifest = test_package_manifest("wrela-core", "0.1.0", &[]);
            let core = CanonicalTestPackage::new(&core_manifest, "core.wr", core_source);
            let root_manifest =
                test_package_manifest("appliance", "0.1.0", &[("core", "wrela-core", "0.1.0")]);
            let root = CanonicalTestPackage::new(&root_manifest, "app.wr", root_source);
            let root_locator = PackageLocator::Workspace {
                path: "package".to_owned(),
            };
            let core_locator = PackageLocator::Toolchain {
                component: "wrela-core-0.1".to_owned(),
            };
            let mut packages = vec![
                LockedPackage {
                    identity: root.identity.clone(),
                    locator: root_locator.clone(),
                    dependencies: vec![LockedDependency {
                        alias: DependencyAlias::new("core").expect("dependency alias"),
                        identity: core.identity.clone(),
                    }],
                    manifest_digest: root.manifest_digest,
                },
                LockedPackage {
                    identity: core.identity.clone(),
                    locator: core_locator.clone(),
                    dependencies: Vec::new(),
                    manifest_digest: core.manifest_digest,
                },
            ];
            packages.sort_by(|left, right| left.identity.cmp(&right.identity));
            let lockfile = Lockfile {
                schema: LOCKFILE_SCHEMA_VERSION,
                root: root.identity.clone(),
                packages,
            };
            let lockfile_bytes = CanonicalPackageCodec::new()
                .canonical_lockfile(&lockfile, lockfile_limits(), &never_cancelled)
                .expect("two-package lockfile");

            directory.write("workspace/package/wrela.toml", &root.manifest_bytes);
            directory.write(
                &format!("workspace/package/src/{}", root.source_path),
                &root.source_bytes,
            );
            directory.write("workspace/wrela.lock", &lockfile_bytes);
            directory.write(
                "toolchain/share/wrela/std/wrela-core-0.1/wrela.toml",
                &core.manifest_bytes,
            );
            let core_source_path = directory.write(
                &format!(
                    "toolchain/share/wrela/std/wrela-core-0.1/src/{}",
                    core.source_path
                ),
                &core.source_bytes,
            );

            let workspace_root = directory.root.join("workspace");
            let standard_library_root = directory.root.join("toolchain/share/wrela/std");
            Self {
                directory,
                workspace_root,
                standard_library_root,
                root_locator,
                core_locator,
                root_identity: root.identity,
                core,
                core_source_path,
            }
        }

        fn toolchain_provider(&self) -> LocalToolchainPackageProvider {
            LocalToolchainPackageProvider {
                root: LocalPackageRoot::new(&self.standard_library_root)
                    .expect("test standard-library root"),
                packages: Arc::new(vec![ShippedStandardLibraryPackage {
                    identity: self.core.identity.clone(),
                    locator: self.core_locator.clone(),
                    manifest_digest: self.core.manifest_digest,
                }]),
            }
        }

        fn composite_provider(&self) -> LocalPackageProvider {
            LocalPackageProvider::new(
                LocalWorkspaceProvider::new(&self.workspace_root).expect("workspace provider"),
                self.toolchain_provider(),
            )
        }
    }

    fn test_package_manifest(
        name: &str,
        version: &str,
        dependencies: &[(&str, &str, &str)],
    ) -> Vec<u8> {
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

    fn lockfile_limits() -> LockfileCodecLimits {
        LockfileCodecLimits {
            bytes: TEST_BYTES,
            string_bytes: TEST_BYTES,
            packages: 16,
            dependencies: 64,
        }
    }

    fn load_limits() -> LoadLimits {
        LoadLimits {
            packages: 16,
            sources: 64,
            manifest_bytes_per_package: TEST_BYTES,
            manifest_bytes: TEST_BYTES,
            lockfile_bytes: TEST_BYTES,
            source_bytes: TEST_BYTES,
            scenarios: 16,
            scenario_bytes: TEST_BYTES,
            bytes_per_package: TEST_BYTES,
        }
    }

    fn never_cancelled() -> bool {
        false
    }

    #[test]
    fn real_workspace_loads_and_parses_only_derived_modules() {
        // Modules are derived from a walk of `source_root`, not declared: a
        // file outside `source_root` is not a module regardless of its
        // extension, but every `*.wr` file inside `source_root` is (there is
        // no separate "ignored" class of `.wr` file under `source_root`).
        let fixture = WorkspaceFixture::new(SOURCE_TEXT.as_bytes());
        fixture
            .directory
            .write("package/undeclared.bin", &[0u8; 32]);
        fixture.directory.write("package/src.wr", &[0u8; 32]);

        let service = LocalFrontendService::new(&fixture.directory.root).expect("frontend service");
        let frontend = service
            .load_and_parse(
                FrontendWorkspaceRequest {
                    root_locator: &fixture.locator,
                    load_limits: load_limits(),
                    parse_limits: ParseLimits::standard(),
                },
                &never_cancelled,
            )
            .expect("real filesystem frontend");

        assert_eq!(frontend.workspace().graph().packages().len(), 1);
        assert_eq!(frontend.workspace().graph().modules().len(), 1);
        assert_eq!(frontend.workspace().sources().len(), 1);
        assert_eq!(frontend.parsed_modules().len(), 1);
        assert!(frontend.parsed_modules()[0].diagnostics().is_empty());
        let module = &frontend.workspace().graph().modules()[0];
        assert_eq!(
            frontend.parsed_module(module.id),
            Some(&frontend.parsed_modules()[0])
        );
        assert_eq!(frontend.parsed_modules()[0].parsed().file(), module.source);
    }

    #[test]
    fn exact_dot_locator_loads_manifest_and_lockfile_from_workspace_root() {
        let fixture = WorkspaceFixture::new(SOURCE_TEXT.as_bytes());
        let root_locator = PackageLocator::Workspace {
            path: ".".to_owned(),
        };
        fixture
            .directory
            .write("wrela.toml", &fixture.manifest_bytes);
        fixture
            .directory
            .write("src/mini.wr", &fixture.source_bytes);
        let lockfile = Lockfile {
            schema: LOCKFILE_SCHEMA_VERSION,
            root: fixture.identity.clone(),
            packages: vec![LockedPackage {
                identity: fixture.identity.clone(),
                locator: root_locator.clone(),
                dependencies: Vec::new(),
                manifest_digest: SoftwareSha256.sha256(&fixture.manifest_bytes),
            }],
        };
        let lockfile_bytes = CanonicalPackageCodec::new()
            .canonical_lockfile(&lockfile, lockfile_limits(), &never_cancelled)
            .expect("root-layout lockfile");
        fixture.directory.write("wrela.lock", &lockfile_bytes);

        let service = LocalFrontendService::new(&fixture.directory.root)
            .expect("root-layout frontend service");
        let frontend = service
            .load_and_parse(
                FrontendWorkspaceRequest {
                    root_locator: &root_locator,
                    load_limits: load_limits(),
                    parse_limits: ParseLimits::standard(),
                },
                &never_cancelled,
            )
            .expect("root-layout workspace");
        assert_eq!(frontend.workspace().graph().packages().len(), 1);
        assert_eq!(frontend.workspace().graph().modules().len(), 1);
        assert_eq!(frontend.workspace().manifests()[0].locator(), &root_locator);

        for path in ["", "./", "./package", "package/.", "package/../package"] {
            assert!(matches!(
                service.provider().acquire(
                    &PackageLocator::Workspace {
                        path: path.to_owned(),
                    },
                    &fixture.identity,
                    TEST_BYTES,
                    TEST_BYTES,
                    &never_cancelled,
                ),
                Err(ProviderError::AccessDenied(_))
            ));
        }
    }

    #[test]
    fn real_workspace_and_verified_toolchain_package_load_and_parse_together() {
        let fixture = ToolchainWorkspaceFixture::new();
        // Non-source files inside and outside the source root are skipped by
        // the derived module walk; every `.wr` file is load-bearing.
        fixture.directory.write(
            "toolchain/share/wrela/std/wrela-core-0.1/src/ignored.txt",
            b"\xff\xfe\xfd",
        );
        fixture.directory.write(
            "toolchain/share/wrela/std/wrela-core-0.1/undeclared.bin",
            &[0u8; 32],
        );
        let service = LocalFrontendService::with_package_provider(fixture.composite_provider());
        let frontend = service
            .load_and_parse(
                FrontendWorkspaceRequest {
                    root_locator: &fixture.root_locator,
                    load_limits: load_limits(),
                    parse_limits: ParseLimits::standard(),
                },
                &never_cancelled,
            )
            .expect("workspace and toolchain frontend");

        assert_eq!(frontend.workspace().graph().packages().len(), 2);
        assert_eq!(frontend.workspace().graph().modules().len(), 2);
        assert_eq!(frontend.workspace().sources().len(), 2);
        assert_eq!(frontend.parsed_modules().len(), 2);
        assert!(
            frontend
                .parsed_modules()
                .iter()
                .all(|output| output.diagnostics().is_empty())
        );
        assert_eq!(
            frontend.workspace().root_manifest().dependencies[0]
                .alias
                .as_str(),
            "core"
        );
        assert!(frontend.workspace().manifests().iter().any(|manifest| {
            manifest.identity() == &fixture.core.identity
                && manifest.locator() == &fixture.core_locator
        }));
        assert_eq!(
            service
                .package_provider()
                .expect("composite package provider")
                .toolchain_provider()
                .standard_library_root(),
            fixture.standard_library_root
        );
    }

    #[test]
    fn stray_invalid_source_file_in_derived_walk_fails_closed() {
        // Under derived modules every `.wr` file below the source root is a
        // module source; a stray undecodable one is a load error, never
        // silently skipped.
        let fixture = ToolchainWorkspaceFixture::new();
        fixture.directory.write(
            "toolchain/share/wrela/std/wrela-core-0.1/src/stray.wr",
            b"\xff\xfe\xfd",
        );
        let service = LocalFrontendService::with_package_provider(fixture.composite_provider());
        let error = service
            .load_and_parse(
                FrontendWorkspaceRequest {
                    root_locator: &fixture.root_locator,
                    load_limits: load_limits(),
                    parse_limits: ParseLimits::standard(),
                },
                &never_cancelled,
            )
            .expect_err("stray invalid source must fail closed");
        assert!(
            format!("{error:?}").contains("not valid UTF-8"),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn multi_file_parse_resources_are_command_wide_exact_and_sealed() {
        let fixture = ToolchainWorkspaceFixture::with_sources(
            b"module app\nfn image():\n    return \"app\"\n$\n",
            b"module core\nfn core():\n    return \"core\"\n$\n",
        );
        let service = LocalFrontendService::with_package_provider(fixture.composite_provider());
        let baseline = service
            .load_and_parse(
                FrontendWorkspaceRequest {
                    root_locator: &fixture.root_locator,
                    load_limits: load_limits(),
                    parse_limits: ParseLimits::standard(),
                },
                &never_cancelled,
            )
            .expect("baseline multi-file parse");
        assert_eq!(baseline.parsed_modules().len(), 2);
        let measured = baseline
            .parsed_modules()
            .iter()
            .try_fold(ParseUsage::ZERO, |usage, output| {
                usage.checked_add(output.usage(), ParseLimits::standard())
            })
            .expect("baseline usage sum");
        assert_eq!(baseline.parse_usage(), measured);
        assert!(measured.tokens() > 0);
        assert!(measured.ast_nodes() > 0);
        assert!(measured.literal_bytes() > 0);
        assert!(measured.diagnostics() >= 2);
        assert!(measured.diagnostic_bytes() > 0);

        let mut exact = ParseLimits::standard();
        exact.tokens = measured.tokens();
        exact.ast_nodes = measured.ast_nodes();
        exact.literal_bytes = measured.literal_bytes();
        exact.diagnostics = measured.diagnostics();
        exact.diagnostic_bytes = measured.diagnostic_bytes();
        let exact_output = service
            .load_and_parse(
                FrontendWorkspaceRequest {
                    root_locator: &fixture.root_locator,
                    load_limits: load_limits(),
                    parse_limits: exact,
                },
                &never_cancelled,
            )
            .expect("exact command-wide parse limits");
        assert_eq!(exact_output.parse_usage(), measured);
        let remaining = exact_output.remaining_parse_limits();
        assert_eq!(remaining.tokens, 0);
        assert_eq!(remaining.ast_nodes, 0);
        assert_eq!(remaining.literal_bytes, 0);
        assert_eq!(remaining.diagnostics, 0);
        assert_eq!(remaining.diagnostic_bytes, 0);
        assert_eq!(remaining.nesting_depth, exact.nesting_depth);

        let mut over_tokens = exact;
        over_tokens.tokens -= 1;
        let mut over_nodes = exact;
        over_nodes.ast_nodes -= 1;
        let mut over_literals = exact;
        over_literals.literal_bytes -= 1;
        let mut over_diagnostics = exact;
        over_diagnostics.diagnostics -= 1;
        let mut over_diagnostic_bytes = exact;
        over_diagnostic_bytes.diagnostic_bytes -= 1;
        for (resource, limit, limits) in [
            ("tokens", u64::from(over_tokens.tokens), over_tokens),
            ("AST nodes", u64::from(over_nodes.ast_nodes), over_nodes),
            ("literal bytes", over_literals.literal_bytes, over_literals),
            (
                "diagnostics",
                u64::from(over_diagnostics.diagnostics),
                over_diagnostics,
            ),
            (
                "diagnostic bytes",
                over_diagnostic_bytes.diagnostic_bytes,
                over_diagnostic_bytes,
            ),
        ] {
            let error = service
                .load_and_parse(
                    FrontendWorkspaceRequest {
                        root_locator: &fixture.root_locator,
                        load_limits: load_limits(),
                        parse_limits: limits,
                    },
                    &never_cancelled,
                )
                .expect_err("one-over aggregate parse resource must fail");
            assert!(matches!(
                error,
                FrontendInputError::Parse {
                    file: Some(_),
                    error: ParseFailure::ResourceLimit {
                        resource: actual_resource,
                        limit: actual_limit,
                    },
                } if actual_resource == resource && actual_limit == limit
            ));
        }
    }

    #[test]
    fn multi_file_clean_parse_accepts_zero_literal_and_diagnostic_budgets() {
        let fixture = ToolchainWorkspaceFixture::with_sources(
            b"module app\nfn image():\n    return unit\n",
            b"module core\nfn core():\n    return unit\n",
        );
        let service = LocalFrontendService::with_package_provider(fixture.composite_provider());
        let mut limits = ParseLimits::standard();
        limits.literal_bytes = 0;
        limits.diagnostics = 0;
        limits.diagnostic_bytes = 0;
        let frontend = service
            .load_and_parse(
                FrontendWorkspaceRequest {
                    root_locator: &fixture.root_locator,
                    load_limits: load_limits(),
                    parse_limits: limits,
                },
                &never_cancelled,
            )
            .expect("zero additive budgets on clean literal-free files");
        assert_eq!(frontend.parse_usage().literal_bytes(), 0);
        assert_eq!(frontend.parse_usage().diagnostics(), 0);
        assert_eq!(frontend.parse_usage().diagnostic_bytes(), 0);
        assert_eq!(frontend.remaining_parse_limits().literal_bytes, 0);
        assert_eq!(frontend.remaining_parse_limits().diagnostics, 0);
        assert_eq!(frontend.remaining_parse_limits().diagnostic_bytes, 0);
    }

    #[test]
    fn composite_dispatches_exact_locator_kinds_without_fallback() {
        let fixture = ToolchainWorkspaceFixture::new();
        let provider = fixture.composite_provider();
        let root = provider
            .acquire(
                &fixture.root_locator,
                &fixture.root_identity,
                TEST_BYTES,
                TEST_BYTES,
                &never_cancelled,
            )
            .expect("workspace package dispatch");
        let core = provider
            .acquire(
                &fixture.core_locator,
                &fixture.core.identity,
                TEST_BYTES,
                TEST_BYTES,
                &never_cancelled,
            )
            .expect("toolchain package dispatch");
        assert_eq!(root.locator, fixture.root_locator);
        assert_eq!(core.locator, fixture.core_locator);
        assert_eq!(core.manifest_bytes, fixture.core.manifest_bytes);
        assert_eq!(core.sources.len(), 1);
        assert_eq!(core.sources[0].path, fixture.core.source_path);
        assert_eq!(
            core.sources[0].text.as_bytes(),
            fixture.core.source_bytes.as_slice()
        );

        assert!(matches!(
            provider.workspace_provider().acquire(
                &fixture.core_locator,
                &fixture.core.identity,
                TEST_BYTES,
                TEST_BYTES,
                &never_cancelled
            ),
            Err(ProviderError::AccessDenied(_))
        ));
        assert!(matches!(
            provider.toolchain_provider().acquire(
                &fixture.root_locator,
                &fixture.root_identity,
                TEST_BYTES,
                TEST_BYTES,
                &never_cancelled
            ),
            Err(ProviderError::AccessDenied(_))
        ));
        assert!(matches!(
            provider.acquire(
                &PackageLocator::Toolchain {
                    component: "package".to_owned(),
                },
                &fixture.root_identity,
                TEST_BYTES,
                TEST_BYTES,
                &never_cancelled
            ),
            Err(ProviderError::IdentityMismatch)
        ));
        assert!(matches!(
            provider.acquire(
                &PackageLocator::Workspace {
                    path: "wrela-core-0.1".to_owned(),
                },
                &fixture.core.identity,
                TEST_BYTES,
                TEST_BYTES,
                &never_cancelled
            ),
            Err(ProviderError::Unavailable(_))
        ));
        assert!(matches!(
            provider.acquire(
                &PackageLocator::Archive {
                    provider: "cache".to_owned(),
                    key: "core".to_owned(),
                },
                &fixture.core.identity,
                TEST_BYTES,
                TEST_BYTES,
                &never_cancelled
            ),
            Err(ProviderError::AccessDenied(_))
        ));

        fs::write(
            &fixture.core_source_path,
            b"module core\nfn substituted() -> unit:\n    return ()\n",
        )
        .expect("mutated toolchain package source");
        assert!(matches!(
            provider.acquire(
                &fixture.core_locator,
                &fixture.core.identity,
                TEST_BYTES,
                TEST_BYTES,
                &never_cancelled,
            ),
            Err(ProviderError::Corrupt(_))
        ));
    }

    #[test]
    fn workspace_only_frontend_rejects_locked_toolchain_dependencies() {
        let fixture = ToolchainWorkspaceFixture::new();
        let service =
            LocalFrontendService::new(&fixture.workspace_root).expect("workspace-only frontend");
        let error = service
            .load_and_parse(
                FrontendWorkspaceRequest {
                    root_locator: &fixture.root_locator,
                    load_limits: load_limits(),
                    parse_limits: ParseLimits::standard(),
                },
                &never_cancelled,
            )
            .expect_err("workspace provider must not resolve a toolchain locator");
        assert!(matches!(
            error,
            FrontendInputError::Load(LoadError::Provider {
                error: ProviderError::AccessDenied(_),
                ..
            })
        ));
        assert!(service.package_provider().is_none());
    }

    #[test]
    fn provider_returns_the_exact_locked_bundle_and_raw_source_digest() {
        let fixture = WorkspaceFixture::new(SOURCE_TEXT.as_bytes());
        let bundle = fixture
            .provider()
            .acquire(
                &fixture.locator,
                &fixture.identity,
                fixture.total_package_bytes(),
                u64::try_from(fixture.manifest_bytes.len()).expect("manifest byte count"),
                &never_cancelled,
            )
            .expect("exact bundle");

        assert_eq!(bundle.identity, fixture.identity);
        assert_eq!(bundle.locator, fixture.locator);
        assert_eq!(bundle.manifest_bytes, fixture.manifest_bytes);
        assert_eq!(bundle.sources.len(), 1);
        assert_eq!(bundle.sources[0].path, "mini.wr");
        assert_eq!(bundle.sources[0].text.as_bytes(), fixture.source_bytes);
        assert_eq!(
            bundle.sources[0].digest,
            SoftwareSha256.sha256(&fixture.source_bytes)
        );
        assert!(bundle.scenarios.is_empty());
    }

    #[test]
    fn declared_scenario_is_read_exactly_and_requires_utf8() {
        let scenario = b"schema = 1\nseed = 7\n";
        let fixture = WorkspaceFixture::with_scenario(SOURCE_TEXT.as_bytes(), scenario);
        let bundle = fixture
            .provider()
            .acquire(
                &fixture.locator,
                &fixture.identity,
                fixture.total_package_bytes(),
                u64::try_from(fixture.manifest_bytes.len()).expect("manifest byte count"),
                &never_cancelled,
            )
            .expect("scenario bundle");
        assert_eq!(bundle.scenarios.len(), 1);
        assert_eq!(bundle.scenarios[0].package, fixture.identity);
        assert_eq!(bundle.scenarios[0].path, "fixtures/boot.toml");
        assert_eq!(bundle.scenarios[0].bytes, scenario);
        assert_eq!(bundle.scenarios[0].digest, SoftwareSha256.sha256(scenario));

        let invalid = WorkspaceFixture::with_scenario(SOURCE_TEXT.as_bytes(), b"\xff\xfe");
        assert!(matches!(
            invalid.provider().acquire(
                &invalid.locator,
                &invalid.identity,
                invalid.total_package_bytes(),
                u64::try_from(invalid.manifest_bytes.len()).expect("manifest byte count"),
                &never_cancelled
            ),
            Err(ProviderError::Corrupt(_))
        ));
    }

    #[test]
    fn package_byte_limit_is_checked_per_read_and_in_aggregate() {
        let fixture = WorkspaceFixture::new(SOURCE_TEXT.as_bytes());
        let provider = fixture.provider();
        let exact = fixture.total_package_bytes();
        let exact_manifest =
            u64::try_from(fixture.manifest_bytes.len()).expect("manifest byte count");
        provider
            .acquire(
                &fixture.locator,
                &fixture.identity,
                exact,
                exact_manifest,
                &never_cancelled,
            )
            .expect("exact package byte limit");

        let aggregate_error = provider
            .acquire(
                &fixture.locator,
                &fixture.identity,
                exact - 1,
                exact_manifest,
                &never_cancelled,
            )
            .expect_err("aggregate limit must fail");
        assert_eq!(
            aggregate_error,
            ProviderError::TooLarge { limit: exact - 1 }
        );

        let manifest_limit =
            u64::try_from(fixture.manifest_bytes.len() - 1).expect("manifest byte limit");
        let file_error = provider
            .acquire(
                &fixture.locator,
                &fixture.identity,
                exact,
                manifest_limit,
                &never_cancelled,
            )
            .expect_err("per-file manifest limit must fail");
        assert_eq!(
            file_error,
            ProviderError::TooLarge {
                limit: manifest_limit
            }
        );
    }

    #[test]
    fn manifest_limit_rejects_before_manifest_decode_or_source_io() {
        let fixture = WorkspaceFixture::new(SOURCE_TEXT.as_bytes());
        fs::remove_file(&fixture.source_path)
            .expect("remove source to detect premature source I/O");
        let invalid_manifest = b"this is not a Wrela package manifest";
        fs::write(&fixture.manifest_path, invalid_manifest).expect("oversized invalid manifest");
        let manifest_limit =
            u64::try_from(invalid_manifest.len() - 1).expect("manifest byte limit");
        let error = fixture
            .provider()
            .acquire(
                &fixture.locator,
                &fixture.identity,
                TEST_BYTES,
                manifest_limit,
                &never_cancelled,
            )
            .expect_err("manifest cap must reject before decode and missing source access");
        assert_eq!(
            error,
            ProviderError::TooLarge {
                limit: manifest_limit
            }
        );
    }

    #[test]
    fn unsupported_and_escaping_locators_fail_closed() {
        let fixture = WorkspaceFixture::new(SOURCE_TEXT.as_bytes());
        let provider = fixture.provider();
        for locator in [
            PackageLocator::Archive {
                provider: "cache".to_owned(),
                key: "object".to_owned(),
            },
            PackageLocator::Toolchain {
                component: "stdlib".to_owned(),
            },
        ] {
            assert!(matches!(
                provider.acquire(
                    &locator,
                    &fixture.identity,
                    TEST_BYTES,
                    TEST_BYTES,
                    &never_cancelled
                ),
                Err(ProviderError::AccessDenied(_))
            ));
        }
        for path in [
            "",
            "/absolute",
            "../package",
            "package/../package",
            "package\\child",
            "C:package",
            "package//child",
        ] {
            let locator = PackageLocator::Workspace {
                path: path.to_owned(),
            };
            assert!(matches!(
                provider.acquire(
                    &locator,
                    &fixture.identity,
                    TEST_BYTES,
                    TEST_BYTES,
                    &never_cancelled
                ),
                Err(ProviderError::AccessDenied(_))
            ));
        }

        let hostile = "x".repeat(MAX_SOURCE_PATH_BYTES + 1);
        let error = provider
            .acquire(
                &PackageLocator::Workspace { path: hostile },
                &fixture.identity,
                TEST_BYTES,
                TEST_BYTES,
                &never_cancelled,
            )
            .expect_err("overlong locator must fail");
        let ProviderError::AccessDenied(message) = error else {
            panic!("overlong locator returned the wrong error class")
        };
        assert!(message.len() < 128);
    }

    #[test]
    fn toolchain_components_reject_nonportable_or_escaping_paths() {
        let fixture = ToolchainWorkspaceFixture::new();
        let provider = fixture.toolchain_provider();
        for component in [
            "",
            "/absolute",
            "../wrela-core-0.1",
            "wrela-core-0.1/..",
            "wrela-core-0.1\\child",
            "C:wrela-core-0.1",
            "wrela-core-0.1//child",
        ] {
            assert!(matches!(
                provider.acquire(
                    &PackageLocator::Toolchain {
                        component: component.to_owned(),
                    },
                    &fixture.core.identity,
                    TEST_BYTES,
                    TEST_BYTES,
                    &never_cancelled,
                ),
                Err(ProviderError::AccessDenied(_))
            ));
        }

        let hostile = "x".repeat(MAX_SOURCE_PATH_BYTES + 1);
        let error = provider
            .acquire(
                &PackageLocator::Toolchain { component: hostile },
                &fixture.core.identity,
                TEST_BYTES,
                TEST_BYTES,
                &never_cancelled,
            )
            .expect_err("overlong toolchain component must fail");
        assert!(matches!(error, ProviderError::AccessDenied(_)));
    }

    #[test]
    fn toolchain_acquisition_enforces_package_limits_and_cancellation() {
        let fixture = ToolchainWorkspaceFixture::new();
        let provider = fixture.toolchain_provider();
        let exact = fixture.core.total_bytes();
        let exact_manifest =
            u64::try_from(fixture.core.manifest_bytes.len()).expect("manifest byte count");
        provider
            .acquire(
                &fixture.core_locator,
                &fixture.core.identity,
                exact,
                exact_manifest,
                &never_cancelled,
            )
            .expect("exact toolchain package byte limit");
        assert_eq!(
            provider
                .acquire(
                    &fixture.core_locator,
                    &fixture.core.identity,
                    exact - 1,
                    exact_manifest,
                    &never_cancelled,
                )
                .expect_err("toolchain package aggregate limit"),
            ProviderError::TooLarge { limit: exact - 1 }
        );
        assert_eq!(
            provider
                .acquire(
                    &fixture.core_locator,
                    &fixture.core.identity,
                    TEST_BYTES,
                    TEST_BYTES,
                    &|| true,
                )
                .expect_err("toolchain package cancellation"),
            ProviderError::Unavailable(CANCELLED_MESSAGE.to_owned())
        );

        let service = LocalFrontendService::with_package_provider(fixture.composite_provider());
        assert!(matches!(
            service.load_and_parse(
                FrontendWorkspaceRequest {
                    root_locator: &fixture.root_locator,
                    load_limits: load_limits(),
                    parse_limits: ParseLimits::standard(),
                },
                &|| true,
            ),
            Err(FrontendInputError::Cancelled)
        ));
    }

    #[test]
    fn toolchain_acquisition_requires_exact_index_identity_locator_and_manifest() {
        let fixture = ToolchainWorkspaceFixture::new();
        let provider = fixture.toolchain_provider();

        let mut unindexed_identity = fixture.core.identity.clone();
        unindexed_identity.source_digest = Sha256Digest::from_bytes([0x44; 32]);
        assert_eq!(
            provider
                .acquire(
                    &fixture.core_locator,
                    &unindexed_identity,
                    TEST_BYTES,
                    TEST_BYTES,
                    &never_cancelled,
                )
                .expect_err("unindexed source identity"),
            ProviderError::IdentityMismatch
        );
        assert_eq!(
            provider
                .acquire(
                    &PackageLocator::Toolchain {
                        component: "secondary".to_owned(),
                    },
                    &fixture.core.identity,
                    TEST_BYTES,
                    TEST_BYTES,
                    &never_cancelled,
                )
                .expect_err("unindexed locator"),
            ProviderError::IdentityMismatch
        );

        let mut substituted_manifest = fixture.core.manifest_bytes.clone();
        substituted_manifest.push(b'\n');
        fs::write(
            fixture
                .standard_library_root
                .join("wrela-core-0.1/wrela.toml"),
            substituted_manifest,
        )
        .expect("substituted raw manifest");
        assert_eq!(
            provider
                .acquire(
                    &fixture.core_locator,
                    &fixture.core.identity,
                    TEST_BYTES,
                    TEST_BYTES,
                    &never_cancelled,
                )
                .expect_err("manifest not committed by index"),
            ProviderError::IdentityMismatch
        );
    }

    #[test]
    fn root_capability_requires_an_absolute_canonical_real_directory() {
        assert!(matches!(
            LocalWorkspaceProvider::new("relative/workspace"),
            Err(ProviderError::AccessDenied(_))
        ));
        let fixture = WorkspaceFixture::new(SOURCE_TEXT.as_bytes());
        let parent_spelling = fixture.directory.root.join("package/..");
        assert!(matches!(
            LocalWorkspaceProvider::new(parent_spelling),
            Err(ProviderError::AccessDenied(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn root_and_declared_file_symlinks_are_rejected() {
        let fixture = WorkspaceFixture::new(SOURCE_TEXT.as_bytes());
        let root_link = fixture.directory.root.with_extension("workspace-link");
        symlink(&fixture.directory.root, &root_link).expect("root symlink");
        assert!(matches!(
            LocalWorkspaceProvider::new(&root_link),
            Err(ProviderError::AccessDenied(_))
        ));
        fs::remove_file(root_link).expect("remove root symlink");

        let outside = fixture
            .directory
            .write("outside.wr", SOURCE_TEXT.as_bytes());
        fs::remove_file(&fixture.source_path).expect("remove declared source");
        symlink(outside, &fixture.source_path).expect("declared source symlink");
        assert!(matches!(
            fixture.provider().acquire(
                &fixture.locator,
                &fixture.identity,
                TEST_BYTES,
                TEST_BYTES,
                &never_cancelled
            ),
            Err(ProviderError::AccessDenied(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn toolchain_root_and_declared_file_symlinks_are_rejected() {
        let fixture = ToolchainWorkspaceFixture::new();
        let standard_library = &fixture.standard_library_root;
        let standard_library_old = standard_library.with_extension("real");
        fs::rename(standard_library, &standard_library_old).expect("move standard-library root");
        symlink(&standard_library_old, standard_library).expect("standard-library root symlink");
        assert!(matches!(
            LocalPackageRoot::new(standard_library),
            Err(ProviderError::AccessDenied(_))
        ));
        fs::remove_file(standard_library).expect("remove standard-library symlink");
        fs::rename(&standard_library_old, standard_library).expect("restore standard-library root");

        let provider = fixture.toolchain_provider();
        let outside = fixture
            .directory
            .write("outside-core.wr", &fixture.core.source_bytes);
        fs::remove_file(&fixture.core_source_path).expect("remove declared core source");
        symlink(outside, &fixture.core_source_path).expect("declared core source symlink");
        assert!(matches!(
            provider.acquire(
                &fixture.core_locator,
                &fixture.core.identity,
                TEST_BYTES,
                TEST_BYTES,
                &never_cancelled,
            ),
            Err(ProviderError::AccessDenied(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn stable_read_detects_same_content_path_replacement() {
        let fixture = WorkspaceFixture::new(SOURCE_TEXT.as_bytes());
        let provider = fixture.provider();
        let old_path = fixture.source_path.with_extension("old");
        let polls = Cell::new(0u32);
        let replace_during_read = || {
            let poll = polls.get();
            polls.set(poll + 1);
            if poll == 1 {
                fs::rename(&fixture.source_path, &old_path).expect("move opened source");
                fs::write(&fixture.source_path, &fixture.source_bytes)
                    .expect("replace opened source");
            }
            false
        };

        let error = provider
            .root
            .read_stable_file(
                &fixture.source_path,
                TEST_BYTES,
                TEST_BYTES,
                &replace_during_read,
            )
            .expect_err("path replacement must fail");
        assert!(matches!(error, ProviderError::Corrupt(_)));
        assert!(polls.get() >= 2);
    }

    #[cfg(unix)]
    #[test]
    fn toolchain_stable_read_detects_same_content_path_replacement() {
        let fixture = ToolchainWorkspaceFixture::new();
        let provider = fixture.toolchain_provider();
        let old_path = fixture.core_source_path.with_extension("old");
        let polls = Cell::new(0u32);
        let replace_during_read = || {
            let poll = polls.get();
            polls.set(poll + 1);
            if poll == 1 {
                fs::rename(&fixture.core_source_path, &old_path).expect("move opened core source");
                fs::write(&fixture.core_source_path, &fixture.core.source_bytes)
                    .expect("replace opened core source");
            }
            false
        };

        let error = provider
            .root
            .read_stable_file(
                &fixture.core_source_path,
                TEST_BYTES,
                TEST_BYTES,
                &replace_during_read,
            )
            .expect_err("toolchain path replacement must fail");
        assert!(matches!(error, ProviderError::Corrupt(_)));
        assert!(polls.get() >= 2);
    }

    #[cfg(unix)]
    #[test]
    fn replaced_toolchain_standard_library_root_is_rejected_by_identity() {
        let fixture = ToolchainWorkspaceFixture::new();
        let provider = fixture.toolchain_provider();
        let standard_library = &fixture.standard_library_root;
        let replaced = standard_library.with_extension("old-root");
        fs::rename(standard_library, &replaced).expect("move standard-library root");
        fs::create_dir(standard_library).expect("replacement standard-library root");

        let error = provider
            .acquire(
                &fixture.core_locator,
                &fixture.core.identity,
                TEST_BYTES,
                TEST_BYTES,
                &never_cancelled,
            )
            .expect_err("replaced standard-library root must fail");
        assert!(matches!(error, ProviderError::Corrupt(_)));

        fs::remove_dir(standard_library).expect("remove replacement standard-library root");
        fs::rename(replaced, standard_library).expect("restore standard-library root");
    }

    #[cfg(unix)]
    #[test]
    fn replaced_workspace_root_is_rejected_by_identity() {
        let fixture = WorkspaceFixture::new(SOURCE_TEXT.as_bytes());
        let provider = fixture.provider();
        let replaced = fixture.directory.root.with_extension("old-root");
        fs::rename(&fixture.directory.root, &replaced).expect("move workspace root");
        fs::create_dir(&fixture.directory.root).expect("replacement workspace root");

        let error = provider
            .root
            .revalidate()
            .expect_err("root replacement must fail");
        assert!(matches!(error, ProviderError::Corrupt(_)));

        fs::remove_dir(&fixture.directory.root).expect("remove replacement root");
        fs::rename(replaced, &fixture.directory.root).expect("restore workspace root");
    }

    #[test]
    fn malformed_declared_paths_are_rejected_before_file_access() {
        let fixture = WorkspaceFixture::new(SOURCE_TEXT.as_bytes());
        let malicious = String::from_utf8(fixture.manifest_bytes.clone())
            .expect("UTF-8 manifest")
            .replace("source_root = \"src\"", "source_root = \"../src\"");
        fs::write(&fixture.manifest_path, malicious).expect("malicious manifest");

        let error = fixture
            .provider()
            .acquire(
                &fixture.locator,
                &fixture.identity,
                TEST_BYTES,
                TEST_BYTES,
                &never_cancelled,
            )
            .expect_err("parent traversal declaration must fail");
        assert!(matches!(error, ProviderError::Corrupt(_)));
    }

    #[test]
    fn content_mutation_and_invalid_utf8_cannot_match_locked_identity() {
        let fixture = WorkspaceFixture::new(SOURCE_TEXT.as_bytes());
        fs::write(
            &fixture.source_path,
            b"fn mini() -> unit:\n    return ( )\n",
        )
        .expect("mutated source");
        assert!(matches!(
            fixture.provider().acquire(
                &fixture.locator,
                &fixture.identity,
                TEST_BYTES,
                TEST_BYTES,
                &never_cancelled
            ),
            Err(ProviderError::Corrupt(_))
        ));

        let invalid = WorkspaceFixture::new(b"fn mini():\n    \xff\n");
        assert!(matches!(
            invalid.provider().acquire(
                &invalid.locator,
                &invalid.identity,
                TEST_BYTES,
                TEST_BYTES,
                &never_cancelled
            ),
            Err(ProviderError::Corrupt(_))
        ));
    }

    #[test]
    fn package_identity_name_version_and_digest_are_all_enforced() {
        let fixture = WorkspaceFixture::new(SOURCE_TEXT.as_bytes());
        let provider = fixture.provider();
        let wrong_name = PackageIdentity {
            name: PackageName::new("other").expect("package name"),
            version: fixture.identity.version.clone(),
            source_digest: fixture.identity.source_digest,
        };
        assert_eq!(
            provider
                .acquire(
                    &fixture.locator,
                    &wrong_name,
                    TEST_BYTES,
                    TEST_BYTES,
                    &never_cancelled,
                )
                .expect_err("name mismatch"),
            ProviderError::IdentityMismatch
        );
        let wrong_version = PackageIdentity {
            name: fixture.identity.name.clone(),
            version: PackageVersion::new("1.0.1").expect("package version"),
            source_digest: fixture.identity.source_digest,
        };
        assert_eq!(
            provider
                .acquire(
                    &fixture.locator,
                    &wrong_version,
                    TEST_BYTES,
                    TEST_BYTES,
                    &never_cancelled
                )
                .expect_err("version mismatch"),
            ProviderError::IdentityMismatch
        );
        let wrong_digest = PackageIdentity {
            name: fixture.identity.name.clone(),
            version: fixture.identity.version.clone(),
            source_digest: Sha256Digest::from_bytes([0x55; 32]),
        };
        assert!(matches!(
            provider.acquire(
                &fixture.locator,
                &wrong_digest,
                TEST_BYTES,
                TEST_BYTES,
                &never_cancelled
            ),
            Err(ProviderError::Corrupt(_))
        ));
    }

    #[test]
    fn cancellation_is_polled_during_streaming_and_normalized_by_frontend() {
        let large_source = vec![b'a'; READ_CHUNK_BYTES * 3];
        let fixture = WorkspaceFixture::new(&large_source);
        let provider = fixture.provider();
        let polls = Cell::new(0u32);
        let cancel_after_one_chunk = || {
            let poll = polls.get();
            polls.set(poll + 1);
            poll >= 2
        };
        let error = provider
            .root
            .read_stable_file(
                &fixture.source_path,
                TEST_BYTES,
                TEST_BYTES,
                &cancel_after_one_chunk,
            )
            .expect_err("stream read cancellation");
        assert_eq!(
            error,
            ProviderError::Unavailable(CANCELLED_MESSAGE.to_owned())
        );
        assert!(polls.get() >= 3);

        let service = LocalFrontendService::new(&fixture.directory.root).expect("frontend service");
        assert!(matches!(
            service.load_and_parse(
                FrontendWorkspaceRequest {
                    root_locator: &fixture.locator,
                    load_limits: load_limits(),
                    parse_limits: ParseLimits::standard(),
                },
                &|| true,
            ),
            Err(FrontendInputError::Cancelled)
        ));
    }

    #[test]
    fn parser_resource_limit_is_preserved_with_exact_file_identity() {
        let fixture = WorkspaceFixture::new(SOURCE_TEXT.as_bytes());
        let service = LocalFrontendService::new(&fixture.directory.root).expect("frontend service");
        let mut parse_limits = ParseLimits::standard();
        parse_limits.tokens = 1;
        let error = service
            .load_and_parse(
                FrontendWorkspaceRequest {
                    root_locator: &fixture.locator,
                    load_limits: load_limits(),
                    parse_limits,
                },
                &never_cancelled,
            )
            .expect_err("parser token limit");
        assert!(matches!(
            error,
            FrontendInputError::Parse {
                file: Some(FileId(0)),
                error: ParseFailure::ResourceLimit {
                    resource: "tokens",
                    limit: 1
                }
            }
        ));
    }

    #[test]
    fn loader_rejects_manifest_mutation_after_request_snapshot() {
        let fixture = WorkspaceFixture::new(SOURCE_TEXT.as_bytes());
        let provider = fixture.provider();
        let snapshot = fixture.manifest_bytes.clone();
        let mutated = String::from_utf8(snapshot.clone())
            .expect("UTF-8 manifest")
            .replace("version = \"1.0.0\"", "version = \"1.0.1\"");
        fs::write(&fixture.manifest_path, mutated).expect("mutated root manifest");

        let error = CanonicalWorkspaceLoader::new()
            .load(
                LoadRequest {
                    root_locator: fixture.locator.clone(),
                    root_manifest_bytes: &snapshot,
                    lockfile_bytes: &fixture.lockfile_bytes,
                    provider: &provider,
                    hasher: &SoftwareSha256,
                    codec: &CanonicalPackageCodec::new(),
                    limits: load_limits(),
                },
                &never_cancelled,
            )
            .expect_err("manifest mutation must fail");
        assert!(matches!(
            error,
            LoadError::Provider {
                error: ProviderError::IdentityMismatch,
                ..
            }
        ));
    }
}
