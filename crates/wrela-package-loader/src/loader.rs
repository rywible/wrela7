use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};

use wrela_package::{
    LockedPackage, PackageGraphBuilder, PackageHandle, PackageIdentity, exact_requirement_version,
};
use wrela_source::{MAX_SOURCE_PATH_BYTES, SourceDatabase, SourceInput};

use crate::{
    DecodeError, LoadError, LoadRequest, LoadedManifestInput, LoadedWorkspace,
    LoadedWorkspaceCandidate, LockfileCodecLimits, ManifestCodecLimits, PackageBundle,
    PackageContentDigestError, PackageContentKind, PackageContentRecord, ProviderError,
    ScenarioInput, WorkspaceLoader, bounded_decode_error, bounded_load_error_value,
    bounded_provider_error, bounded_source_error, is_utf8_cancellable, package_content_digest,
    qualified_source_path, seal_loaded_workspace, sha256_cancellable, try_loader_vec,
    try_reserve_loader_vec,
};

/// Production workspace producer for the hermetic manifest/lock/provider boundary.
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
        let manifest_limits = manifest_codec_limits(&request);
        let lockfile_limits = lockfile_codec_limits(&request);
        check_input_bytes(
            request.lockfile_bytes.len(),
            request.limits.lockfile_bytes,
            "lockfile bytes",
        )?;
        check_input_bytes(
            request.root_manifest_bytes.len(),
            request.limits.manifest_bytes_per_package,
            "root manifest bytes",
        )?;

        let lockfile = request
            .codec
            .decode_lockfile(request.lockfile_bytes, lockfile_limits, is_cancelled)
            .map_err(map_lockfile_error)?;
        let canonical_lockfile = request
            .codec
            .canonical_lockfile(&lockfile, lockfile_limits, is_cancelled)
            .map_err(map_lockfile_error)?;
        if canonical_lockfile.as_slice() != request.lockfile_bytes {
            return Err(LoadError::Lock(
                "caller-supplied lockfile bytes are not canonical schema-1 TOML".to_owned(),
            ));
        }
        validate_locked_closure(&lockfile, is_cancelled)?;

        let root_index = lockfile
            .packages
            .binary_search_by(|package| package.identity.cmp(&lockfile.root))
            .map_err(|_| {
                LoadError::Lock("lockfile does not contain its root package".to_owned())
            })?;
        let root_locked = lockfile
            .packages
            .get(root_index)
            .ok_or_else(|| LoadError::Lock("lockfile root package index is invalid".to_owned()))?;
        if root_locked.locator != request.root_locator {
            return Err(LoadError::Lock(
                "requested root locator differs from the exact locked root locator".to_owned(),
            ));
        }
        let root_identity = root_locked.identity.clone();
        let root_manifest_digest = root_locked.manifest_digest;

        // Snapshot the exact caller bytes under SHA-256 before any TOML parser
        // observes them. The lock binds the independently encoded canonical
        // digest below, so semantically equivalent noncanonical TOML remains
        // accepted without making parsing precede integrity work.
        let _raw_root_manifest_digest =
            sha256_cancellable(request.hasher, request.root_manifest_bytes, is_cancelled)
                .map_err(|_| LoadError::Cancelled)?;
        let requested_root = request
            .codec
            .decode_manifest(request.root_manifest_bytes, manifest_limits, is_cancelled)
            .map_err(map_root_manifest_error)?;
        let requested_root_canonical = request
            .codec
            .canonical_manifest(&requested_root, manifest_limits, is_cancelled)
            .map_err(map_root_manifest_error)?;
        let requested_root_digest =
            sha256_cancellable(request.hasher, &requested_root_canonical, is_cancelled)
                .map_err(|_| LoadError::Cancelled)?;
        if requested_root.name != root_identity.name
            || requested_root.version != root_identity.version
        {
            return Err(LoadError::Manifest(
                "caller-supplied root manifest name or version differs from the lockfile root"
                    .to_owned(),
            ));
        }
        if requested_root_digest != root_manifest_digest {
            return Err(LoadError::DigestMismatch {
                subject: "caller-supplied root manifest".to_owned(),
                expected: root_manifest_digest,
                actual: requested_root_digest,
            });
        }

        let mut graph_builder = PackageGraphBuilder::new(root_identity.clone());
        let mut package_handles = BTreeMap::<&PackageIdentity, PackageHandle>::new();
        package_handles.insert(&lockfile.root, graph_builder.root());
        for package in &lockfile.packages {
            check_cancelled(is_cancelled)?;
            if package.identity != root_identity {
                let handle = graph_builder
                    .add_package(package.identity.clone())
                    .map_err(|error| {
                        LoadError::Graph(bounded_load_error_value(&error.to_string()))
                    })?;
                package_handles.insert(&package.identity, handle);
            }
        }
        for package in &lockfile.packages {
            check_cancelled(is_cancelled)?;
            let owner_handle = package_handle(&package_handles, &package.identity)?;
            for dependency in &package.dependencies {
                check_cancelled(is_cancelled)?;
                let dependency_handle = package_handle(&package_handles, &dependency.identity)?;
                graph_builder
                    .add_dependency(owner_handle, dependency.alias.clone(), dependency_handle)
                    .map_err(|error| {
                        LoadError::Graph(bounded_load_error_value(&error.to_string()))
                    })?;
            }
        }

        let package_capacity = lockfile.packages.len();
        let mut manifests = try_loader_vec(
            package_capacity,
            "loaded manifest records",
            u64::from(request.limits.packages),
        )?;
        let mut sources = SourceDatabase::default();
        let mut scenarios = Vec::new();
        let mut declared_source_count = 0u64;
        let mut provided_source_count = 0u64;
        let mut declared_image_test_count = 0u64;
        let mut provided_scenario_count = 0u64;
        let mut manifest_bytes = 0u64;
        let mut source_bytes = 0u64;
        let mut scenario_bytes = 0u64;

        for package in &lockfile.packages {
            check_cancelled(is_cancelled)?;
            let bundle = acquire_package(&request, package, is_cancelled)?;
            let PackageBundle {
                identity: _,
                locator: _,
                manifest_bytes: package_manifest_bytes,
                sources: provided_sources,
                scenarios: provided_scenarios,
            } = bundle;

            add_count(
                &mut provided_source_count,
                provided_sources.len(),
                u64::from(request.limits.sources),
                "provided source files",
            )?;
            add_count(
                &mut provided_scenario_count,
                provided_scenarios.len(),
                u64::from(request.limits.scenarios),
                "provided scenario files",
            )?;
            let (package_source_bytes, package_scenario_bytes, acquired_package_bytes) =
                preflight_package_bytes(
                    &package_manifest_bytes,
                    &provided_sources,
                    &provided_scenarios,
                    request.limits.bytes_per_package,
                    is_cancelled,
                )?;
            add_bytes(
                &mut source_bytes,
                package_source_bytes,
                request.limits.source_bytes,
                "source bytes",
            )?;
            add_bytes(
                &mut scenario_bytes,
                package_scenario_bytes,
                request.limits.scenario_bytes,
                "scenario bytes",
            )?;

            // Hash the immutable acquired bytes before semantic TOML decode;
            // the canonical digest is computed and lock-checked separately.
            let _raw_acquired_manifest_digest =
                sha256_cancellable(request.hasher, &package_manifest_bytes, is_cancelled)
                    .map_err(|_| LoadError::Cancelled)?;
            let manifest = request
                .codec
                .decode_manifest(&package_manifest_bytes, manifest_limits, is_cancelled)
                .map_err(|error| map_package_manifest_error(&package.identity, error))?;
            let canonical_manifest = request
                .codec
                .canonical_manifest(&manifest, manifest_limits, is_cancelled)
                .map_err(|error| map_package_manifest_error(&package.identity, error))?;
            add_bytes(
                &mut manifest_bytes,
                u64::try_from(canonical_manifest.len()).unwrap_or(u64::MAX),
                request.limits.manifest_bytes,
                "canonical manifest bytes",
            )?;
            add_count(
                &mut declared_source_count,
                manifest.modules.len(),
                u64::from(request.limits.sources),
                "declared source files",
            )?;
            add_count(
                &mut declared_image_test_count,
                manifest.image_tests.len(),
                u64::from(request.limits.scenarios),
                "declared image tests",
            )?;
            let canonical_package_bytes = u64::try_from(canonical_manifest.len())
                .unwrap_or(u64::MAX)
                .checked_add(package_source_bytes)
                .and_then(|bytes| bytes.checked_add(package_scenario_bytes))
                .ok_or_else(|| resource_limit("package bytes", request.limits.bytes_per_package))?;
            if acquired_package_bytes > request.limits.bytes_per_package
                || canonical_package_bytes > request.limits.bytes_per_package
            {
                return Err(resource_limit(
                    "package bytes",
                    request.limits.bytes_per_package,
                ));
            }

            validate_manifest_identity_and_dependencies(&manifest, package, is_cancelled)?;
            if package.identity == root_identity && manifest != requested_root {
                return Err(LoadError::Manifest(
                    "provider substituted a different root manifest".to_owned(),
                ));
            }
            let manifest_digest =
                sha256_cancellable(request.hasher, &canonical_manifest, is_cancelled)
                    .map_err(|_| LoadError::Cancelled)?;
            if manifest_digest != package.manifest_digest {
                return Err(LoadError::DigestMismatch {
                    subject: bounded_load_error_value(&format!(
                        "manifest for {}@{}",
                        package.identity.name.as_str(),
                        package.identity.version.as_str()
                    )),
                    expected: package.manifest_digest,
                    actual: manifest_digest,
                });
            }

            let validated_sources = validate_sources(
                &package.identity,
                &manifest,
                provided_sources,
                request.hasher,
                is_cancelled,
            )?;
            let validated_scenarios = validate_scenarios(
                &package.identity,
                &manifest,
                provided_scenarios,
                request.hasher,
                is_cancelled,
            )?;
            verify_package_identity(
                package,
                &canonical_manifest,
                &validated_sources,
                &validated_scenarios,
                &request,
                is_cancelled,
            )?;

            try_reserve_loader_vec(
                &mut scenarios,
                validated_scenarios.len(),
                "loaded scenario records",
                u64::from(request.limits.scenarios),
            )?;

            let handle = package_handle(&package_handles, &package.identity)?;
            for source in validated_sources {
                check_cancelled(is_cancelled)?;
                let source_id = sources
                    .add(SourceInput {
                        path: qualified_source_path(
                            &package.identity,
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
                identity: package.identity.clone(),
                locator: package.locator.clone(),
                manifest_digest,
                manifest,
                canonical_manifest,
            });
        }

        if declared_source_count != provided_source_count {
            return Err(LoadError::Manifest(
                "declared and provided source counts differ".to_owned(),
            ));
        }
        if u64::try_from(scenarios.len()).unwrap_or(u64::MAX) != provided_scenario_count {
            return Err(LoadError::Manifest(
                "validated and provided scenario file counts differ".to_owned(),
            ));
        }
        check_cancelled(is_cancelled)?;
        drop(package_handles);
        let graph = graph_builder
            .finish()
            .map_err(|error| LoadError::Graph(bounded_load_error_value(&error.to_string())))?;
        check_cancelled(is_cancelled)?;

        let root_manifest = manifests.get(root_index).ok_or_else(|| {
            LoadError::Manifest("root manifest acquisition is missing".to_owned())
        })?;
        if root_manifest.identity != root_identity {
            return Err(LoadError::Manifest(
                "root manifest acquisition is not at the locked root index".to_owned(),
            ));
        }
        let root_manifest = manifests.remove(root_index);
        let graph_manifest_count = manifests.len().checked_add(1).ok_or_else(|| {
            resource_limit(
                "loaded manifest records",
                u64::from(request.limits.packages),
            )
        })?;
        let mut graph_order_manifests = try_loader_vec(
            graph_manifest_count,
            "loaded manifest records",
            u64::from(request.limits.packages),
        )?;
        graph_order_manifests.push(root_manifest);
        graph_order_manifests.extend(manifests);

        let candidate = LoadedWorkspaceCandidate {
            graph,
            sources,
            manifests: graph_order_manifests,
            scenarios,
            lockfile,
            canonical_lockfile,
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

fn lockfile_codec_limits(request: &LoadRequest<'_>) -> LockfileCodecLimits {
    LockfileCodecLimits {
        bytes: request.limits.lockfile_bytes,
        string_bytes: request.limits.lockfile_bytes,
        packages: request.limits.packages,
        dependencies: u32::try_from(request.limits.lockfile_bytes).unwrap_or(u32::MAX),
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

fn map_lockfile_error(error: DecodeError) -> LoadError {
    match bounded_decode_error(error) {
        DecodeError::Cancelled => LoadError::Cancelled,
        DecodeError::InvalidLimits => LoadError::InvalidLimits,
        DecodeError::ResourceLimit { resource, limit } => {
            LoadError::ResourceLimit { resource, limit }
        }
        error => LoadError::Lockfile(error),
    }
}

fn map_root_manifest_error(error: DecodeError) -> LoadError {
    match bounded_decode_error(error) {
        DecodeError::Cancelled => LoadError::Cancelled,
        DecodeError::InvalidLimits => LoadError::InvalidLimits,
        DecodeError::ResourceLimit { resource, limit } => {
            LoadError::ResourceLimit { resource, limit }
        }
        error => LoadError::RootManifest(error),
    }
}

fn map_package_manifest_error(package: &PackageIdentity, error: DecodeError) -> LoadError {
    match bounded_decode_error(error) {
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

fn package_handle(
    handles: &BTreeMap<&PackageIdentity, PackageHandle>,
    identity: &PackageIdentity,
) -> Result<PackageHandle, LoadError> {
    handles
        .get(identity)
        .copied()
        .ok_or_else(|| LoadError::Graph("locked dependency identity is missing".to_owned()))
}

fn validate_locked_closure(
    lockfile: &wrela_package::Lockfile,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LoadError> {
    let package_count = lockfile.packages.len();
    let package_limit = u64::try_from(package_count).unwrap_or(u64::MAX);
    let root_index = lockfile
        .packages
        .binary_search_by(|package| package.identity.cmp(&lockfile.root))
        .map_err(|_| LoadError::Lock("lockfile does not contain its root package".to_owned()))?;
    let mut reachable = try_loader_vec(package_count, "locked closure bitmap", package_limit)?;
    reachable.resize(package_count, false);
    let mut pending = try_loader_vec(package_count, "locked closure traversal", package_limit)?;
    let root_reachable = reachable
        .get_mut(root_index)
        .ok_or_else(|| LoadError::Lock("lockfile root package index is invalid".to_owned()))?;
    *root_reachable = true;
    pending.push(root_index);
    while let Some(package_index) = pending.pop() {
        check_cancelled(is_cancelled)?;
        let package = lockfile
            .packages
            .get(package_index)
            .ok_or_else(|| LoadError::Lock("locked package index is invalid".to_owned()))?;
        for dependency in &package.dependencies {
            check_cancelled(is_cancelled)?;
            let dependency_index = lockfile
                .packages
                .binary_search_by(|package| package.identity.cmp(&dependency.identity))
                .map_err(|_| LoadError::Lock("locked dependency identity is missing".to_owned()))?;
            let dependency_reachable = reachable
                .get_mut(dependency_index)
                .ok_or_else(|| LoadError::Lock("locked dependency index is invalid".to_owned()))?;
            if !std::mem::replace(dependency_reachable, true) {
                pending.push(dependency_index);
            }
        }
    }
    for is_reachable in reachable {
        check_cancelled(is_cancelled)?;
        if !is_reachable {
            return Err(LoadError::Lock(
                "lockfile contains a package outside the root dependency closure".to_owned(),
            ));
        }
    }
    Ok(())
}

fn acquire_package(
    request: &LoadRequest<'_>,
    package: &LockedPackage,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<PackageBundle, LoadError> {
    let acquired = request.provider.acquire(
        &package.locator,
        &package.identity,
        request.limits.bytes_per_package,
        request.limits.manifest_bytes_per_package,
        is_cancelled,
    );
    if is_cancelled() {
        return Err(LoadError::Cancelled);
    }
    let bundle = acquired.map_err(|error| LoadError::Provider {
        package: package.identity.clone(),
        error: bounded_provider_error(error),
    })?;
    if bundle.identity != package.identity {
        return Err(LoadError::Provider {
            package: package.identity.clone(),
            error: ProviderError::IdentityMismatch,
        });
    }
    if bundle.locator != package.locator {
        return Err(LoadError::Provider {
            package: package.identity.clone(),
            error: ProviderError::Corrupt("provider substituted the package locator".to_owned()),
        });
    }
    Ok(bundle)
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

fn validate_manifest_identity_and_dependencies(
    manifest: &wrela_package::PackageManifest,
    package: &LockedPackage,
    is_cancelled: &dyn Fn() -> bool,
) -> Result<(), LoadError> {
    check_cancelled(is_cancelled)?;
    if manifest.name != package.identity.name || manifest.version != package.identity.version {
        return Err(LoadError::Manifest(bounded_load_error_value(&format!(
            "manifest identity differs from locked package {}@{}",
            package.identity.name.as_str(),
            package.identity.version.as_str()
        ))));
    }
    if manifest.dependencies.len() != package.dependencies.len() {
        return Err(LoadError::Manifest(bounded_load_error_value(&format!(
            "manifest dependency count differs for {}@{}",
            package.identity.name.as_str(),
            package.identity.version.as_str()
        ))));
    }
    for (declared, locked) in manifest.dependencies.iter().zip(&package.dependencies) {
        check_cancelled(is_cancelled)?;
        let exact_version = exact_requirement_version(&declared.requirement);
        if declared.alias != locked.alias
            || declared.package != locked.identity.name
            || exact_version.as_ref() != Some(&locked.identity.version)
        {
            return Err(LoadError::Manifest(bounded_load_error_value(&format!(
                "manifest dependency {} differs from its exact locked identity",
                declared.alias.as_str()
            ))));
        }
    }
    check_cancelled(is_cancelled)?;
    Ok(())
}

fn validate_sources(
    package: &PackageIdentity,
    manifest: &wrela_package::PackageManifest,
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

    let mut validated = try_loader_vec(
        manifest.modules.len(),
        "validated source records",
        u64::try_from(manifest.modules.len()).unwrap_or(u64::MAX),
    )?;
    for declaration in &manifest.modules {
        check_cancelled(is_cancelled)?;
        let Some((relative_path, (text, digest))) = provided.remove_entry(&declaration.source_path)
        else {
            return Err(LoadError::MissingSource(bounded_path(
                &declaration.source_path,
            )));
        };
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
            module: declaration.module.clone(),
            relative_path,
            text,
            digest,
        });
    }
    if let Some((path, _)) = provided.pop_first() {
        return Err(LoadError::UndeclaredSource(bounded_path(&path)));
    }
    for pair in validated.windows(2) {
        check_cancelled(is_cancelled)?;
        if pair[0].relative_path >= pair[1].relative_path {
            return Err(LoadError::Manifest(
                "declared module source paths are not canonical".to_owned(),
            ));
        }
    }
    Ok(validated)
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

fn verify_package_identity(
    package: &LockedPackage,
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
    if actual != package.identity.source_digest {
        return Err(LoadError::DigestMismatch {
            subject: bounded_load_error_value(&format!(
                "package {}@{} content",
                package.identity.name.as_str(),
                package.identity.version.as_str()
            )),
            expected: package.identity.source_digest,
            actual,
        });
    }
    Ok(())
}

fn bounded_path(path: &str) -> String {
    bounded_load_error_value(path)
}
