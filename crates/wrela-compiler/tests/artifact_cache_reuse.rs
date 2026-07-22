#![forbid(unsafe_code)]

use std::cell::Cell;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use wrela_backend::flow_wir::{
    Block, BlockId, FLOW_WIR_VERSION, FlowFunction, FlowType, FlowTypeKind, FlowWir, FunctionColor,
    FunctionId, FunctionOrigin, FunctionRole, PlanOwner, SourceSummary, Terminator, TypeId,
    ValidatedFlowWir,
};
use wrela_build_model::{BuildIdentity, LanguageRevision, Sha256Digest, TargetIdentity};
use wrela_compiler::{
    ArtifactCache, CacheEntryCandidate, CacheReadRequest, LocalArtifactCache, flow_wir_cache_key,
    resolve_flow_wir_frame, seal_cached_artifact,
};
use wrela_flow_wir_codec::CodecLimits;
use wrela_package_loader::SoftwareSha256;

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

#[test]
fn real_flow_frame_cache_reuses_only_validated_bytes_and_misses_every_identity_drift() {
    let fixture = TestDirectory::new();
    let output = fixture.root.join("authorized-output");
    let cache = LocalArtifactCache::for_output(&output).expect("normalized output cache");
    assert_eq!(cache.root(), output.join(".wrela-cache-v1"));
    assert!(!cache.root().exists());

    let flow = flow_fixture(build_identity(7));
    let key = flow_wir_cache_key(&flow.as_wir().build).expect("FlowWir key");
    let first = resolve_flow_wir_frame(
        Some(&cache),
        &key,
        &flow,
        CodecLimits::standard(),
        1024 * 1024,
        &|| false,
    )
    .expect("cold local build cache stage");
    assert!(!first.reused());
    let entry = cache.entry_path(&key).expect("content-addressed path");
    assert!(entry.starts_with(cache.root()));
    assert!(entry.is_file());

    let second = resolve_flow_wir_frame(
        Some(&cache),
        &key,
        &flow,
        CodecLimits::standard(),
        1024 * 1024,
        &|| false,
    )
    .expect("identical local build cache stage");
    assert!(second.reused());
    assert_eq!(second.bytes(), first.bytes());
    assert_eq!(second.digest(), first.digest());

    let mutations = [
        IdentityMutation::Source,
        IdentityMutation::Profile,
        IdentityMutation::Target,
        IdentityMutation::Request,
    ];
    for mutation in mutations {
        let changed = mutated_flow(&flow, mutation);
        let changed_key = flow_wir_cache_key(&changed.as_wir().build).expect("mutated FlowWir key");
        assert_ne!(changed_key, key);
        let selected = resolve_flow_wir_frame(
            Some(&cache),
            &changed_key,
            &changed,
            CodecLimits::standard(),
            1024 * 1024,
            &|| false,
        )
        .expect("identity mutation recomputes");
        assert!(!selected.reused(), "{mutation:?} must miss");
        assert!(
            cache
                .entry_path(&changed_key)
                .expect("mutated path")
                .is_file()
        );
    }
}

#[test]
fn corrupt_stale_future_wrong_key_truncated_and_over_limit_entries_recompute() {
    let fixture = TestDirectory::new();
    let cache = LocalArtifactCache::at(fixture.root.join("cache")).expect("fixture cache");
    let flow = flow_fixture(build_identity(11));
    let key = flow_wir_cache_key(&flow.as_wir().build).expect("key");
    let cold = resolve(&cache, &key, &flow);
    assert!(!cold.reused());
    let path = cache.entry_path(&key).expect("entry path");
    let canonical_entry = fs::read(&path).expect("canonical entry");

    let assert_recomputed = |bytes: &[u8]| {
        fs::write(&path, bytes).expect("mutated entry");
        let selected = resolve(&cache, &key, &flow);
        assert!(!selected.reused());
        assert_eq!(selected.bytes(), cold.bytes());
        assert!(resolve(&cache, &key, &flow).reused());
    };

    let mut corrupt = canonical_entry.clone();
    *corrupt.last_mut().expect("payload byte") ^= 0x80;
    assert_recomputed(&corrupt);

    assert_recomputed(&canonical_entry[..canonical_entry.len() - 1]);

    let mut stale = canonical_entry.clone();
    stale[8..12].copy_from_slice(&0_u32.to_le_bytes());
    assert_recomputed(&stale);

    let mut future = canonical_entry.clone();
    future[8..12].copy_from_slice(&2_u32.to_le_bytes());
    assert_recomputed(&future);

    let other_flow = flow_fixture(build_identity(12));
    let other_key = flow_wir_cache_key(&other_flow.as_wir().build).expect("other key");
    assert!(!resolve(&cache, &other_key, &other_flow).reused());
    let other_entry =
        fs::read(cache.entry_path(&other_key).expect("other path")).expect("other entry bytes");
    assert_recomputed(&other_entry);

    let request = CacheReadRequest {
        key: &key,
        maximum_bytes: u64::try_from(cold.bytes().len() - 1).expect("one-under limit"),
    };
    assert!(
        cache
            .load(&request, &|| false)
            .expect("bounded over-limit load")
            .is_none()
    );

    let mut appended = fs::read(&path).expect("restored canonical entry");
    appended.push(0);
    assert_recomputed(&appended);
}

#[test]
fn cancellation_before_visibility_leaves_no_entry_or_staging_file() {
    let fixture = TestDirectory::new();
    let cache = LocalArtifactCache::at(fixture.root.join("cancel-cache")).expect("fixture cache");
    let flow = flow_fixture(build_identity(19));
    let key = flow_wir_cache_key(&flow.as_wir().build).expect("key");
    let encoded = resolve_flow_wir_frame(
        None,
        &key,
        &flow,
        CodecLimits::standard(),
        1024 * 1024,
        &|| false,
    )
    .expect("uncached producer frame");
    let request = CacheReadRequest {
        key: &key,
        maximum_bytes: 1024 * 1024,
    };
    let artifact = seal_cached_artifact(
        &request,
        CacheEntryCandidate {
            key: key.clone(),
            bytes: encoded.bytes().to_vec(),
            digest: encoded.digest(),
        },
        &SoftwareSha256,
        &|| false,
    )
    .expect("sealed producer artifact");
    let polls = Cell::new(0_u32);
    let cancel_during_store = || {
        let next = polls.get() + 1;
        polls.set(next);
        next >= 4
    };
    assert_eq!(
        cache.store(&artifact, &cancel_during_store),
        Err(wrela_compiler::CacheError::Cancelled)
    );
    assert!(!cache.entry_path(&key).expect("entry path").exists());
    if let Some(namespace) = cache.entry_path(&key).expect("entry path").parent() {
        if namespace.exists() {
            assert!(
                fs::read_dir(namespace)
                    .expect("cache namespace")
                    .next()
                    .is_none(),
                "cancelled store left a staging artifact"
            );
        }
    }

    let cancelled = || true;
    assert!(matches!(
        resolve_flow_wir_frame(
            Some(&cache),
            &key,
            &flow,
            CodecLimits::standard(),
            1024 * 1024,
            &cancelled,
        ),
        Err(wrela_flow_wir_codec::CodecError::Cancelled)
    ));
}

fn resolve(
    cache: &LocalArtifactCache,
    key: &wrela_compiler::CacheKey,
    flow: &ValidatedFlowWir,
) -> wrela_compiler::ResolvedFlowWirFrame {
    resolve_flow_wir_frame(
        Some(cache),
        key,
        flow,
        CodecLimits::standard(),
        1024 * 1024,
        &|| false,
    )
    .expect("cache selection")
}

#[derive(Debug, Clone, Copy)]
enum IdentityMutation {
    Source,
    Profile,
    Target,
    Request,
}

fn mutated_flow(flow: &ValidatedFlowWir, mutation: IdentityMutation) -> ValidatedFlowWir {
    let mut model = flow.as_wir().clone();
    match mutation {
        IdentityMutation::Source => {
            model.build.source_graph = Sha256Digest::from_bytes([21; 32]);
        }
        IdentityMutation::Profile => {
            model.build.profile = Sha256Digest::from_bytes([22; 32]);
        }
        IdentityMutation::Target => {
            model.build.target =
                TargetIdentity::new("aarch64-cache-mutation").expect("target identity");
        }
        IdentityMutation::Request => {
            model.build.request = Sha256Digest::from_bytes([23; 32]);
        }
    }
    model
        .validate()
        .expect("mutated identity remains valid FlowWir")
}

fn build_identity(byte: u8) -> BuildIdentity {
    let digest = Sha256Digest::from_bytes([byte; 32]);
    BuildIdentity {
        compiler: digest,
        language: LanguageRevision::Design0_1,
        target: TargetIdentity::aarch64_qemu_virt_uefi(),
        target_package: digest,
        standard_library: digest,
        source_graph: digest,
        request: digest,
        profile: digest,
    }
}

fn flow_fixture(build: BuildIdentity) -> ValidatedFlowWir {
    FlowWir {
        version: FLOW_WIR_VERSION,
        name: "cache-image".to_owned(),
        build,
        source_summary: SourceSummary {
            semantic_wir_version: 13,
            semantic_functions: 1,
            hir_files: 1,
            hir_declarations: 1,
            reachable_declarations: 1,
            monomorphized_instantiations: 1,
            resolved_interface_calls: 0,
        },
        types: vec![FlowType {
            id: TypeId(0),
            kind: FlowTypeKind::Unit,
            name: Some("unit".to_owned()),
            copyable: true,
            strict_linear: false,
        }],
        globals: Vec::new(),
        functions: vec![FlowFunction {
            id: FunctionId(0),
            name: "entry".to_owned(),
            origin: FunctionOrigin::GeneratedImageEntry {
                semantic_function: 0,
                constructor: 0,
            },
            role: FunctionRole::ImageEntry,
            color: FunctionColor::Sync,
            parameters: Vec::new(),
            result_types: Vec::new(),
            values: Vec::new(),
            blocks: vec![Block {
                id: BlockId(0),
                parameters: Vec::new(),
                instructions: Vec::new(),
                terminator: Terminator::Return(Vec::new()),
                source: None,
            }],
            entry: BlockId(0),
            stack_bound: 0,
            frame_bound: 0,
            proofs: Vec::new(),
            source: None,
        }],
        actors: Vec::new(),
        tasks: Vec::new(),
        devices: Vec::new(),
        pools: Vec::new(),
        regions: Vec::new(),
        activations: Vec::new(),
        schedulers: Vec::new(),
        proofs: Vec::new(),
        checkpoints: Vec::new(),
        tests: Vec::new(),
        compiled_test_group: None,
        startup_order: vec![PlanOwner::Runtime],
        shutdown_order: vec![PlanOwner::Runtime],
        image_entry: FunctionId(0),
        static_bytes: 0,
        peak_bytes: 0,
    }
    .validate()
    .expect("valid cache FlowWir fixture")
}

struct TestDirectory {
    root: PathBuf,
}

impl TestDirectory {
    fn new() -> Self {
        let base = fs::canonicalize(std::env::temp_dir()).expect("canonical temporary root");
        for _ in 0..128 {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let root = base.join(format!(
                "wrela-artifact-cache-{}-{sequence:016x}",
                std::process::id()
            ));
            match fs::create_dir(&root) {
                Ok(()) => {
                    return Self {
                        root: fs::canonicalize(root).expect("canonical fixture root"),
                    };
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("cannot create fixture: {error}"),
            }
        }
        panic!("cannot allocate cache fixture directory")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
