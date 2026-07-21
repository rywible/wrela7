use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};

use wrela_build_model::Sha256Digest;
use wrela_package::{PackageGraphBuilder, PackageIdentity, PackageManifest};
use wrela_source::{MAX_SOURCE_PATH_BYTES, SourceDatabase, SourceInput};

use crate::{
    DecodeError, LoadError, LoadRequest, LoadedManifestInput, LoadedWorkspace,
    LoadedWorkspaceCandidate, ManifestCodecLimits, PackageBundle, PackageContentDigestError,
    PackageContentKind, PackageContentRecord, ProviderError, ScenarioInput, WorkspaceLoader,
    bounded_load_error_value, bounded_provider_error, bounded_source_error, is_utf8_cancellable,
    package_content_digest, qualified_source_path, seal_loaded_workspace, sha256_cancellable,
    try_loader_vec, try_reserve_loader_vec,
};

/// Reserved alias binding the sole revision-0.1 dependency to the
/// toolchain-shipped `core` component (`docs/language/02-source-language.md`
/// §2.1). No other alias is resolvable: revision 0.1 cannot acquire
/// third-party packages, so a lockfile would pin no choice.
const CORE_ALIAS: &str = "core";

/// Production workspace producer for the hermetic manifest/provider boundary.
///
/// There is no lockfile: the root manifest's sole dependency (the reserved
/// `core` alias) resolves directly against `LoadRequest::core_locator`.
#[derive(Debug, Clone, Copy, Default)]
pub struct CanonicalWorkspaceLoader;

impl CanonicalWorkspaceLoader {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl WorkspaceLoader for CanonicalWorkspaceLoader {
    fn load(
        &self,
        request: LoadRequest<'_>,
        is_cancelled: &dyn Fn() -> bool,
    ) -> Result<LoadedWorkspace, LoadError> {
        check_cancelled(is_cancelled)?;
        request.limits.validate()?;
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
        let manifest_limits = manifest_codec_limits(&request);
        check_input_bytes(
            request.root_manifest_bytes.len(),
            request.limits.manifest_bytes_per_package,
            "root manifest bytes",
        )?;

        // Snapshot the exact caller bytes under SHA-256 before any TOML parser
        // observes them. Semantic identity is checked independently below, so
        // equivalent-but-noncanonical TOML remains accepted.
        let _raw_root_manifest_digest =
            sha256_cancellable(request.hasher, request.root_manifest_bytes, is_cancelled)
                .map_err(|_| LoadError::Cancelled)?;
        let requested_root = request
            .codec
            .decode_manifest(request.root_manifest_bytes, manifest_limits, is_cancelled)
            .map_err(map_root_manifest_error)?;
        requested_root.validate().map_err(|error| {
            LoadError::Manifest(bounded_load_error_value(&format!(
                "invalid root manifest: {error}"
            )))
        })?;
        let core_dependency = one_core_dependency(&requested_root)?;
        let core_version = wrela_package::exact_requirement_version(&core_dependency.requirement)
            .ok_or_else(|| {
            LoadError::Manifest(
                "core dependency requirement must be one exact revision 0.1 requirement".to_owned(),
            )
        })?;

        let root_bundle = acquire_package(
            &request,
            &request.root_locator,
            &requested_root.name,
            &requested_root.version,
            is_cancelled,
        )?;
        let core_bundle = acquire_package(
            &request,
            &request.core_locator,
            &core_dependency.package,
            &core_version,
            is_cancelled,
        )?;

        let (root_manifest, root_canonical_manifest, root_validated_sources, root_scenarios) =
            acquire_manifest_content(&request, &root_bundle, manifest_limits, is_cancelled)?;
        if root_manifest != requested_root {
            return Err(LoadError::Manifest(
                "provider substituted a different root manifest".to_owned(),
            ));
        }
        let (core_manifest, core_canonical_manifest, core_validated_sources, core_scenarios) =
            acquire_manifest_content(&request, &core_bundle, manifest_limits, is_cancelled)?;
        if core_manifest.name != core_dependency.package || core_manifest.version != core_version {
            return Err(LoadError::Manifest(
                "acquired core package does not match the declared core dependency".to_owned(),
            ));
        }

        verify_package_identity(
            &root_bundle,
            &root_canonical_manifest,
            &root_validated_sources,
            &root_scenarios,
            &request,
            is_cancelled,
        )?;
        verify_package_identity(
            &core_bundle,
            &core_canonical_manifest,
            &core_validated_sources,
            &core_scenarios,
            &request,
            is_cancelled,
        )?;

        let mut graph_builder = PackageGraphBuilder::new(root_bundle.identity.clone());
        let root_handle = graph_builder.root();
        let core_handle = graph_builder
            .add_package(core_bundle.identity.clone())
            .map_err(|error| LoadError::Graph(bounded_load_error_value(&error.to_string())))?;
        graph_builder
            .add_dependency(root_handle, core_dependency.alias.clone(), core_handle)
            .map_err(|error| LoadError::Graph(bounded_load_error_value(&error.to_string())))?;

        let mut manifests = try_loader_vec(
            2,
            "loaded manifest records",
            u64::from(request.limits.packages),
        )?;
        let mut sources = SourceDatabase::default();
        let mut scenarios = Vec::new();
        let mut provided_scenario_count = 0u64;

        for (bundle, manifest, canonical_manifest, validated_sources, validated_scenarios) in [
            (
                &root_bundle,
                root_manifest,
                root_canonical_manifest,
                root_validated_sources,
                root_scenarios,
            ),
            (
                &core_bundle,
                core_manifest,
                core_canonical_manifest,
                core_validated_sources,
                core_scenarios,
            ),
        ] {
            check_cancelled(is_cancelled)?;
            let manifest_digest =
                sha256_cancellable(request.hasher, &canonical_manifest, is_cancelled)
                    .map_err(|_| LoadError::Cancelled)?;
            add_count(
                &mut provided_scenario_count,
                validated_scenarios.len(),
                u64::from(request.limits.scenarios),
                "provided scenario files",
            )?;

            let handle = if bundle.identity == root_bundle.identity {
                root_handle
            } else {
                core_handle
            };
            for source in validated_sources {
                check_cancelled(is_cancelled)?;
                let source_id = sources
                    .add(SourceInput {
                        path: qualified_source_path(
                            &bundle.identity,
                            &manifest.source_root,
                            &source.relative_path,
                        )?,
                        text: source.text,
                        digest: source.digest,
                    })
                    .map_err(|error| LoadError::Source(bounded_source_error(error)))?;
                check_cancelled(is_cancelled)?;
                graph_builder
                    .add_module(handle, source.module, source_id)
                    .map_err(|error| {
                        LoadError::Graph(bounded_load_error_value(&error.to_string()))
                    })?;
            }
            for scenario in validated_scenarios {
                check_cancelled(is_cancelled)?;
                scenarios.push(scenario);
            }
            manifests.push(LoadedManifestInput {
                identity: bundle.identity.clone(),
                locator: bundle.locator.clone(),
                manifest_digest,
                manifest,
                canonical_manifest,
            });
        }

        if u64::try_from(scenarios.len()).unwrap_or(u64::MAX) != provided_scenario_count {
            return Err(LoadError::Manifest(
                "validated and provided scenario file counts differ".to_owned(),
            ));
        }
        check_cancelled(is_cancelled)?;
        let graph = graph_builder
            .finish()
            .map_err(|error| LoadError::Graph(bounded_load_error_value(&error.to_string())))?;
        check_cancelled(is_cancelled)?;

        // Root is always graph package ID 0; `manifests` was pushed in that
        // same [root, core] order above.
        let candidate = LoadedWorkspaceCandidate {
            graph,
            sources,
            manifests,
            scenarios,
        };
        seal_loaded_workspace(&request, candidate, is_cancelled)
    }
}

struct ValidatedSource {
    module: wrela_package::ModulePath,
    relative_path: String,
    text: String,
    digest: wrela_build_model::Sha256Digest,
}

fn manifest_codec_limits(request: &LoadRequest<'_>) -> ManifestCodecLimits {
    let entry_limit = u32::try_from(request.limits.manifest_bytes_per_package).unwrap_or(u32::MAX);
    ManifestCodecLimits {
        bytes: request.limits.manifest_bytes_per_package,
        string_bytes: request.limits.manifest_bytes_per_package,
        modules: request.limits.sources.min(entry_limit),
        dependencies: entry_limit,
        profiles: entry_limit,
        images: entry_limit,
        image_tests: request.limits.scenarios.min(entry_limit),
    }
}

/// Revision 0.1's root manifest declares exactly one dependency, aliased
/// `core` (`docs/language/02-source-language.md` §2.1). There is no lockfile
/// to instead resolve an arbitrary declared set, so this is a hard loader
/// precondition rather than a general dependency-graph walk.
fn one_core_dependency(
    manifest: &PackageManifest,
) -> Result<&wrela_package::ManifestDependency, LoadError> {
    match manifest.dependencies.as_slice() {
        [dependency] if dependency.alias.as_str() == CORE_ALIAS => Ok(dependency),
        [dependency] => Err(LoadError::Manifest(bounded_load_error_value(&format!(
            "root manifest's sole dependency must use the reserved alias `core`, not {}",
            dependency.alias.as_str()
        )))),
        _ => Err(LoadError::Manifest(
            "root manifest must declare exactly one dependency, the reserved core alias".to_owned(),
        )),
    }
}

fn check_cancelled(is_cancelled: &dyn Fn() -> bool) -> Result<(), LoadError> {
    if is_cancelled() {
        Err(LoadError::Cancelled)
    } else {
        Ok(())
    }
}

fn check_input_bytes(length: usize, limit: u64, resource: &'static str) -> Result<(), LoadError> {
    if u64::try_from(length).unwrap_or(u64::MAX) > limit {
        Err(resource_limit(resource, limit))
    } else {
        Ok(())
    }
}

fn resource_limit(resource: &'static str, limit: u64) -> LoadError {
    LoadError::ResourceLimit { resource, limit }
}

fn add_count(
    total: &mut u64,
    count: usize,
    limit: u64,
    resource: &'static str,
) -> Result<(), LoadError> {
    let count = u64::try_from(count).map_err(|_| resource_limit(resource, limit))?;
    *total = total
        .checked_add(count)
        .ok_or_else(|| resource_limit(resource, limit))?;
    if *total > limit {
        Err(resource_limit(resource, limit))
    } else {
        Ok(())
    }
}

fn add_bytes(
    total: &mut u64,
    bytes: u64,
    limit: u64,
    resource: &'static str,
) -> Result<(), LoadError> {
    *total = total
        .checked_add(bytes)
        .ok_or_else(|| resource_limit(resource, limit))?;
    if *total > limit {
        Err(resource_limit(resource, limit))
    } else {
        Ok(())
    }
}

fn map_root_manifest_error(error: DecodeError) -> LoadError {
    match crate::bounded_decode_error(error) {
        DecodeError::Cancelled => LoadError::Cancelled,
        DecodeError::InvalidLimits => LoadError::InvalidLimits,
        DecodeError::ResourceLimit { resource, limit } => {
            LoadError::ResourceLimit { resource, limit }
        }
        error => LoadError::RootManifest(error),
    }
}

fn map_package_manifest_error(package: &PackageIdentity, error: DecodeError) -> LoadError {
    match crate::bounded_decode_error(error) {
        DecodeError::Cancelled => LoadError::Cancelled,
        DecodeError::InvalidLimits => LoadError::InvalidLimits,
        DecodeError::ResourceLimit { resource, limit } => {
            LoadError::ResourceLimit { resource, limit }
        }
        error => LoadError::PackageManifest {
            package: package.clone(),
            error,
        },
    }
}

/// Placeholder identity for error display only, used before a package's real
/// identity (whose digest depends on acquired content) is known. Never
/// compared for equality; `LoadError::Provider`'s `Display` prints only the
/// name and version.
fn pending_identity(
    name: &wrela_package::PackageName,
    version: &wrela_package::PackageVersion,
) -> PackageIdentity {
    PackageIdentity {
        name: name.clone(),
        version: version.clone(),
        source_digest: Sha256Digest::from_bytes([0; 32]),
    }
}

fn acquire_package(
    request: &LoadRequest<'_>,
    locator: &wrela_package::PackageLocator,
    expected_name: &wrela_package::PackageName,
    expected_version: &wrela_package::PackageVersion,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<PackageBundle, LoadError> {
    let acquired = request.provider.acquire(
        locator,
        expected_name,
        expected_version,
        request.limits.bytes_per_package,
        request.limits.manifest_bytes_per_package,
        is_cancelled,
    );
    if is_cancelled() {
        return Err(LoadError::Cancelled);
    }
    let bundle = acquired.map_err(|error| LoadError::Provider {
        package: pending_identity(expected_name, expected_version),
        error: bounded_provider_error(error),
    })?;
    if &bundle.identity.name != expected_name || &bundle.identity.version != expected_version {
        return Err(LoadError::Provider {
            package: pending_identity(expected_name, expected_version),
            error: ProviderError::IdentityMismatch,
        });
    }
    if &bundle.locator != locator {
        return Err(LoadError::Provider {
            package: bundle.identity.clone(),
            error: ProviderError::Corrupt("provider substituted the package locator".to_owned()),
        });
    }
    Ok(bundle)
}

type AcquiredManifest = (
    PackageManifest,
    Vec<u8>,
    Vec<ValidatedSource>,
    Vec<ScenarioInput>,
);

/// Decode, canonicalize, derive modules for, and validate scenarios of one
/// acquired package's bundle. Shared by the root and the sole `core`
/// dependency; there is no wider dependency walk in revision 0.1.
fn acquire_manifest_content(
    request: &LoadRequest<'_>,
    bundle: &PackageBundle,
    manifest_limits: ManifestCodecLimits,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<AcquiredManifest, LoadError> {
    check_input_bytes(
        bundle.manifest_bytes.len(),
        request.limits.manifest_bytes_per_package,
        "package manifest bytes",
    )?;
    let (package_source_bytes, package_scenario_bytes, acquired_package_bytes) =
        preflight_package_bytes(
            &bundle.manifest_bytes,
            &bundle.sources,
            &bundle.scenarios,
            request.limits.bytes_per_package,
            is_cancelled,
        )?;
    let _ = (package_source_bytes, package_scenario_bytes);
    if acquired_package_bytes > request.limits.bytes_per_package {
        return Err(resource_limit(
            "package bytes",
            request.limits.bytes_per_package,
        ));
    }

    let _raw_acquired_manifest_digest =
        sha256_cancellable(request.hasher, &bundle.manifest_bytes, is_cancelled)
            .map_err(|_| LoadError::Cancelled)?;
    let manifest = request
        .codec
        .decode_manifest(&bundle.manifest_bytes, manifest_limits, is_cancelled)
        .map_err(|error| map_package_manifest_error(&bundle.identity, error))?;
    manifest.validate().map_err(|error| {
        LoadError::Manifest(bounded_load_error_value(&format!(
            "invalid manifest for {}@{}: {error}",
            bundle.identity.name.as_str(),
            bundle.identity.version.as_str()
        )))
    })?;
    let canonical_manifest = request
        .codec
        .canonical_manifest(&manifest, manifest_limits, is_cancelled)
        .map_err(|error| map_package_manifest_error(&bundle.identity, error))?;
    if manifest.name != bundle.identity.name || manifest.version != bundle.identity.version {
        return Err(LoadError::Manifest(bounded_load_error_value(&format!(
            "manifest identity differs from the acquired package {}@{}",
            bundle.identity.name.as_str(),
            bundle.identity.version.as_str()
        ))));
    }

    let validated_sources = derive_modules(
        &bundle.identity,
        bundle.sources.clone(),
        request.hasher,
        is_cancelled,
    )?;
    reject_unknown_image_modules(&manifest, &validated_sources)?;
    let validated_scenarios = validate_scenarios(
        &bundle.identity,
        &manifest,
        bundle.scenarios.clone(),
        request.hasher,
        is_cancelled,
    )?;

    Ok((
        manifest,
        canonical_manifest,
        validated_sources,
        validated_scenarios,
    ))
}

fn preflight_package_bytes(
    manifest: &[u8],
    sources: &[SourceInput],
    scenarios: &[ScenarioInput],
    limit: u64,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(u64, u64, u64), LoadError> {
    let mut source_bytes = 0u64;
    for source in sources {
        check_cancelled(is_cancelled)?;
        add_bytes(
            &mut source_bytes,
            u64::try_from(source.text.len()).unwrap_or(u64::MAX),
            limit,
            "package bytes",
        )?;
    }
    let mut scenario_bytes = 0u64;
    for scenario in scenarios {
        check_cancelled(is_cancelled)?;
        add_bytes(
            &mut scenario_bytes,
            u64::try_from(scenario.bytes.len()).unwrap_or(u64::MAX),
            limit,
            "package bytes",
        )?;
    }
    let package_bytes = u64::try_from(manifest.len())
        .unwrap_or(u64::MAX)
        .checked_add(source_bytes)
        .and_then(|bytes| bytes.checked_add(scenario_bytes))
        .ok_or_else(|| resource_limit("package bytes", limit))?;
    if package_bytes > limit {
        return Err(resource_limit("package bytes", limit));
    }
    Ok((source_bytes, scenario_bytes, package_bytes))
}

const MODULE_SOURCE_SUFFIX: &str = ".wr";

/// Derive this package's modules from the provider-supplied source set.
///
/// There is no `[[module]]` declaration to consult: every acquired source is
/// treated as one deterministic (sorted, portable) walk result under
/// `source_root`. A `BTreeMap` keyed by path gives the sorted, duplicate-free
/// order for free. Each surviving path must end in `.wr`, pass the same
/// portable/NFC path rules a manifest field would (`validate_source_path`),
/// and not collide with another module's path under ASCII case-folding; its
/// module path is then derived by dropping the `.wr` suffix and splitting on
/// `/`, with every segment validated as a source identifier by
/// `ModulePath::new` (NFC, XID_start/continue, no reserved keyword, no
/// wildcard `_`, no default-ignorable/bidi-control code point).
fn derive_modules(
    package: &PackageIdentity,
    sources: Vec<SourceInput>,
    hasher: &dyn crate::ContentHasher,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<ValidatedSource>, LoadError> {
    let mut provided = BTreeMap::new();
    for source in sources {
        check_cancelled(is_cancelled)?;
        if source.path.len() > MAX_SOURCE_PATH_BYTES {
            return Err(LoadError::UndeclaredSource(bounded_path(&source.path)));
        }
        match provided.entry(source.path) {
            Entry::Vacant(entry) => {
                entry.insert((source.text, source.digest));
            }
            Entry::Occupied(entry) => {
                return Err(LoadError::DuplicateSource(bounded_path(entry.key())));
            }
        }
    }
    if provided.len() > wrela_package::MAX_MODULES {
        return Err(resource_limit(
            "package modules",
            u64::try_from(wrela_package::MAX_MODULES).unwrap_or(u64::MAX),
        ));
    }

    let mut validated = try_loader_vec(
        provided.len(),
        "validated source records",
        u64::try_from(provided.len()).unwrap_or(u64::MAX),
    )?;
    let mut portable_paths = BTreeSet::new();
    for (relative_path, (text, digest)) in provided {
        check_cancelled(is_cancelled)?;
        wrela_package::validate_source_path(&relative_path)
            .map_err(|error| LoadError::Manifest(bounded_load_error_value(&error.to_string())))?;
        let Some(module_text) = relative_path.strip_suffix(MODULE_SOURCE_SUFFIX) else {
            return Err(LoadError::Manifest(bounded_load_error_value(&format!(
                "source {relative_path} under source_root is not a `.wr` module file"
            ))));
        };
        if !portable_paths.insert(relative_path.to_ascii_lowercase()) {
            return Err(LoadError::Manifest(bounded_load_error_value(&format!(
                "module source path collides portably: {relative_path}"
            ))));
        }
        let mut segments = Vec::new();
        try_reserve_loader_vec(
            &mut segments,
            module_text.split('/').count(),
            "module path segments",
            u64::try_from(module_text.len()).unwrap_or(u64::MAX),
        )?;
        segments.extend(module_text.split('/').map(str::to_owned));
        let module = wrela_package::ModulePath::new(segments).map_err(|error| {
            LoadError::Manifest(bounded_load_error_value(&format!(
                "module path derived from {relative_path} is invalid: {error}"
            )))
        })?;

        let actual = sha256_cancellable(hasher, text.as_bytes(), is_cancelled)
            .map_err(|_| LoadError::Cancelled)?;
        if actual != digest {
            return Err(LoadError::DigestMismatch {
                subject: bounded_load_error_value(&format!(
                    "source {} for {}@{}",
                    relative_path,
                    package.name.as_str(),
                    package.version.as_str()
                )),
                expected: digest,
                actual,
            });
        }
        validated.push(ValidatedSource {
            module,
            relative_path,
            text,
            digest,
        });
    }
    for pair in validated.windows(2) {
        check_cancelled(is_cancelled)?;
        if pair[0].relative_path >= pair[1].relative_path {
            return Err(LoadError::Manifest(
                "derived module source paths are not canonical".to_owned(),
            ));
        }
    }
    Ok(validated)
}

/// Cross-check `[[image]]` entry modules against derived modules. The
/// manifest cannot check this itself (`PackageManifest::validate` has no
/// filesystem access), so it is deferred to the loader once modules are
/// known.
fn reject_unknown_image_modules(
    manifest: &wrela_package::PackageManifest,
    modules: &[ValidatedSource],
) -> Result<(), LoadError> {
    let derived: BTreeSet<&wrela_package::ModulePath> =
        modules.iter().map(|module| &module.module).collect();
    for image in &manifest.images {
        if !derived.contains(&image.module) {
            return Err(LoadError::Manifest(bounded_load_error_value(&format!(
                "image {} refers to an undeclared module",
                image.name
            ))));
        }
    }
    Ok(())
}

fn validate_scenarios(
    package: &PackageIdentity,
    manifest: &wrela_package::PackageManifest,
    scenarios: Vec<ScenarioInput>,
    hasher: &dyn crate::ContentHasher,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<Vec<ScenarioInput>, LoadError> {
    let mut expected = BTreeSet::new();
    for test in &manifest.image_tests {
        check_cancelled(is_cancelled)?;
        expected.insert(test.scenario.as_str());
    }
    let mut provided = BTreeMap::new();
    for scenario in scenarios {
        check_cancelled(is_cancelled)?;
        if scenario.package != *package {
            return Err(LoadError::Provider {
                package: package.clone(),
                error: ProviderError::Corrupt(
                    "provider substituted a scenario package identity".to_owned(),
                ),
            });
        }
        if scenario.path.len() > MAX_SOURCE_PATH_BYTES {
            return Err(LoadError::UndeclaredScenario(bounded_path(&scenario.path)));
        }
        match provided.entry(scenario.path) {
            Entry::Vacant(entry) => {
                entry.insert((scenario.bytes, scenario.digest));
            }
            Entry::Occupied(entry) => {
                return Err(LoadError::DuplicateScenario(bounded_path(entry.key())));
            }
        }
    }

    let mut validated = try_loader_vec(
        expected.len(),
        "validated scenario records",
        u64::try_from(expected.len()).unwrap_or(u64::MAX),
    )?;
    for expected_path in expected {
        check_cancelled(is_cancelled)?;
        let Some((path, (bytes, digest))) = provided.remove_entry(expected_path) else {
            return Err(LoadError::MissingScenario(bounded_path(expected_path)));
        };
        if !is_utf8_cancellable(&bytes, is_cancelled)? {
            return Err(LoadError::Provider {
                package: package.clone(),
                error: ProviderError::Corrupt(bounded_load_error_value(&format!(
                    "scenario {path} is not UTF-8"
                ))),
            });
        }
        let actual =
            sha256_cancellable(hasher, &bytes, is_cancelled).map_err(|_| LoadError::Cancelled)?;
        if actual != digest {
            return Err(LoadError::DigestMismatch {
                subject: bounded_load_error_value(&format!(
                    "scenario {} for {}@{}",
                    path,
                    package.name.as_str(),
                    package.version.as_str()
                )),
                expected: digest,
                actual,
            });
        }
        validated.push(ScenarioInput {
            package: package.clone(),
            path,
            bytes,
            digest,
        });
    }
    if let Some((path, _)) = provided.pop_first() {
        return Err(LoadError::UndeclaredScenario(bounded_path(&path)));
    }
    Ok(validated)
}

/// Independently recompute this package's content digest from its
/// (already digest-verified) sources and scenarios plus its canonical
/// manifest, and confirm it equals the identity the provider returned. There
/// is no lockfile-recorded digest to check against instead: a provider is
/// trusted for which bytes it hands back, never for the identity it computes
/// from them.
fn verify_package_identity(
    bundle: &PackageBundle,
    canonical_manifest: &[u8],
    sources: &[ValidatedSource],
    scenarios: &[ScenarioInput],
    request: &LoadRequest<'_>,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LoadError> {
    let record_limit =
        u64::from(request.limits.sources).saturating_add(u64::from(request.limits.scenarios));
    let record_count = sources
        .len()
        .checked_add(scenarios.len())
        .ok_or_else(|| resource_limit("package content records", record_limit))?;
    let mut records = try_loader_vec(record_count, "package content records", record_limit)?;
    for source in sources {
        check_cancelled(is_cancelled)?;
        records.push(PackageContentRecord {
            kind: PackageContentKind::Source,
            path: &source.relative_path,
            digest: source.digest,
        });
    }
    for scenario in scenarios {
        check_cancelled(is_cancelled)?;
        records.push(PackageContentRecord {
            kind: PackageContentKind::Scenario,
            path: &scenario.path,
            digest: scenario.digest,
        });
    }
    let actual = package_content_digest(canonical_manifest, &records, request.hasher, is_cancelled)
        .map_err(|error| match error {
            PackageContentDigestError::Cancelled => LoadError::Cancelled,
            PackageContentDigestError::NonCanonicalInput => {
                LoadError::Manifest("package content records are not canonical".to_owned())
            }
        })?;
    if actual != bundle.identity.source_digest {
        return Err(LoadError::DigestMismatch {
            subject: bounded_load_error_value(&format!(
                "package {}@{} content",
                bundle.identity.name.as_str(),
                bundle.identity.version.as_str()
            )),
            expected: bundle.identity.source_digest,
            actual,
        });
    }
    Ok(())
}

fn bounded_path(path: &str) -> String {
    bounded_load_error_value(path)
}
