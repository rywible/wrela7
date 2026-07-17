//! Reproducible producer for the static AArch64 Linux headless engine.
//!
//! This producer intentionally stops at an independently inspected ELF.  The
//! Linux appliance/QEMU execution proof is a separate immediate-consumer gate;
//! a Darwin build or a host execution probe is not evidence for that contract.

use crate::llvm;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

const HELP: &str = "\
usage: cargo xtask linux-engine [--plan | --record-output | --reenroll-cargo] [--offline]\n\
\n\
Without a producer mode, validate and reuse the enrolled content-addressed\n\
engine bundle without reopening the Darwin bootstrap or Rust target closure.\n\
With --plan or --record-output, build-authority validation covers the complete\n\
authenticated inputs; --record-output builds the real wrela-engine process for\n\
aarch64-unknown-linux-musl in two path-distinct, environment-cleared,\n\
locked/offline lanes.  The producer\n\
accepts only the Rust target component authenticated by the enrolled 1.95.0\n\
release manifest and publishes only byte-identical, independently inspected\n\
static ELF64 AArch64 output.  The maintainer-only --reenroll-cargo mode\n\
authenticates an identity-preserving Cargo authority rollover and requires\n\
--offline.  Creating build/toolchain/linux-engine/cancel cooperatively cancels\n\
and reaps active work.  This command does not claim Linux execution.\n";

const LOCK_PATH: &str = "toolchain/linux-engine.lock.toml";
const OUTPUT_PATH: &str = "toolchain/linux-engine.outputs.toml";
const RUST_OUTPUT_PATH: &str = "toolchain/rust.outputs.toml";
const CARGO_OUTPUT_PATH: &str = "toolchain/cargo.outputs.toml";
const IMPLEMENTATION_PATH: &str = "xtask/src/linux_engine.rs";
const TARGET: &str = "aarch64-unknown-linux-musl";
const HOST: &str = "aarch64-apple-darwin";
const CHANNEL: &str = "1.95.0";
const PROFILE: &str = "dist";
const PACKAGE: &str = "wrela-engine";
const RELEASE_MANIFEST: &str = "lib/rustlib/multirust-channel-manifest.toml";
const TARGET_ARCHIVE_NAME: &str = "rust-std-1.95.0-aarch64-unknown-linux-musl.tar.xz";
const TARGET_ARCHIVE_ROOT: &str = "rust-std-1.95.0-aarch64-unknown-linux-musl";
const TARGET_ARCHIVE_SUBTREE: &str =
    "rust-std-aarch64-unknown-linux-musl/lib/rustlib/aarch64-unknown-linux-musl";
const XZ_LIBLZMA_PATH: &str = "/opt/homebrew/Cellar/xz/5.8.3/lib/liblzma.5.dylib";
const MAX_LOCK_BYTES: u64 = 128 * 1024;
const MAX_BINARY_BYTES: u64 = 128 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_TREE_FILES: u64 = 1_000_000;
const MAX_TREE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const MAX_DEPTH: u32 = 128;
const MAX_ARCHIVE_MEMBERS: u64 = 4096;
const MAX_ARCHIVE_FILES: u64 = 1024;
const MAX_ARCHIVE_EXPANDED_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_ARCHIVE_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PROCESS_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const BUILD_TIMEOUT_SECONDS: u64 = 60 * 60;
const RELEASE_TREE_MAGIC: &[u8; 8] = b"WRELDST\0";
const RELEASE_TREE_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Options {
    help: bool,
    plan: bool,
    record_output: bool,
    reenroll_cargo: bool,
    offline: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Lock {
    channel: String,
    host: String,
    target: String,
    release_date: String,
    release_version: String,
    release_manifest_sha256: String,
    release_manifest_bytes: u64,
    target_archive_url: String,
    target_archive_sha256: String,
    target_archive_bytes: u64,
    target_tree_sha256: String,
    target_files: u64,
    target_bytes: u64,
    rust_output_sha256: String,
    cargo_output_sha256: String,
    cargo_lock_sha256: String,
    cargo_vendor_tree_sha256: String,
    cargo_vendor_files: u64,
    cargo_vendor_bytes: u64,
    cargo_sha256: String,
    cargo_bytes: u64,
    rustc_sha256: String,
    rustc_bytes: u64,
    rustdoc_sha256: String,
    rustdoc_bytes: u64,
    rust_sysroot_tree_sha256: String,
    rust_sysroot_files: u64,
    rust_sysroot_bytes: u64,
    rust_lld_sha256: String,
    rust_lld_bytes: u64,
    xz_sha256: String,
    xz_bytes: u64,
    xz_liblzma_sha256: String,
    xz_liblzma_bytes: u64,
    package: String,
    profile: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Output {
    input_sha256: String,
    source_tree_sha256: String,
    source_files: u64,
    source_bytes: u64,
    target_tree_sha256: String,
    target_files: u64,
    target_bytes: u64,
    binary_sha256: String,
    binary_bytes: u64,
    receipt_sha256: String,
    receipt_bytes: u64,
    artifact_path: String,
    execution_proven: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileMeasurement {
    sha256: String,
    bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileRecord {
    path: String,
    bytes: u64,
    sha256: String,
    executable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TreeMeasurement {
    sha256: String,
    files: u64,
    bytes: u64,
    records: Vec<FileRecord>,
}

#[derive(Debug, Clone)]
struct Tools {
    cargo: PathBuf,
    rustc: PathBuf,
    rustdoc: PathBuf,
    rust_lld: PathBuf,
    xz: PathBuf,
    xz_liblzma: PathBuf,
    cargo_measurement: FileMeasurement,
    rustc_measurement: FileMeasurement,
    rustdoc_measurement: FileMeasurement,
    rust_lld_measurement: FileMeasurement,
    xz_measurement: FileMeasurement,
    xz_liblzma_measurement: FileMeasurement,
    sysroot: PathBuf,
    sysroot_tree: TreeMeasurement,
    native: llvm::VerifiedNativeEnvironment,
    native_receipt: PathBuf,
    native_receipt_measurement: FileMeasurement,
    native_witnesses: Vec<(PathBuf, FileMeasurement)>,
}

#[derive(Debug)]
struct Plan {
    root: PathBuf,
    lock: Lock,
    lock_measurement: FileMeasurement,
    rust_output_measurement: FileMeasurement,
    cargo_output_measurement: FileMeasurement,
    cargo_lock_measurement: FileMeasurement,
    implementation_measurement: FileMeasurement,
    running: PathBuf,
    running_measurement: FileMeasurement,
    archive: PathBuf,
    archive_measurement: FileMeasurement,
    vendor: PathBuf,
    vendor_tree: TreeMeasurement,
    source_tree: TreeMeasurement,
    tools: Tools,
    input_sha256: String,
    enrolled: Option<(FileMeasurement, Output)>,
    cancellation: Cancellation,
}

#[derive(Debug, Clone)]
struct Cancellation {
    marker: PathBuf,
}

impl Cancellation {
    fn for_root(root: &Path) -> Self {
        Self {
            marker: root.join("build/toolchain/linux-engine/cancel"),
        }
    }

    fn check(&self, phase: &str) -> Result<(), String> {
        match fs::symlink_metadata(&self.marker) {
            Ok(metadata)
                if metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && metadata.len() <= 64 =>
            {
                Err(format!(
                    "Linux-engine operation cancelled during {phase} by {}",
                    self.marker.display()
                ))
            }
            Ok(_) => Err(format!(
                "Linux-engine cancellation marker is a link, special entry, or oversized: {}",
                self.marker.display()
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!(
                "cannot inspect Linux-engine cancellation marker {}: {error}",
                self.marker.display()
            )),
        }
    }
}

#[derive(Debug)]
struct LaneResult {
    binary: PathBuf,
    measurement: FileMeasurement,
    target_tree: TreeMeasurement,
    staging: Staging,
}

#[derive(Debug)]
struct ProcessOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Debug)]
struct Staging {
    path: PathBuf,
    keep: bool,
}

impl Staging {
    fn create(parent: &Path, label: &str) -> Result<Self, String> {
        ensure_directory(parent)?;
        for nonce in 0_u32..1024 {
            let path = parent.join(format!(".{}-{}-{nonce}", label, std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => {
                    set_directory_mode(&path, 0o700)?;
                    return Ok(Self { path, keep: false });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(format!(
                        "cannot create private Linux-engine staging {}: {error}",
                        path.display()
                    ));
                }
            }
        }
        Err("cannot allocate a bounded unique Linux-engine staging directory".to_owned())
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if !self.keep {
            let _ = make_tree_writable(&self.path);
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[derive(Debug)]
struct TemporaryFile {
    path: PathBuf,
}

#[derive(Debug)]
struct ProducerLease {
    path: PathBuf,
}

impl ProducerLease {
    fn acquire(root: &Path) -> Result<Self, String> {
        let directory = root.join("build/toolchain/linux-engine");
        ensure_directory(&directory)?;
        let path = directory.join("producer.lock");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| {
                format!(
                    "cannot acquire exclusive Linux-engine producer lease {}: {error}; inspect and remove it only after proving no producer is active",
                    path.display()
                )
            })?;
        let lease = Self { path };
        let record = format!("pid = {}\n", std::process::id());
        file.write_all(record.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("cannot seal Linux-engine producer lease: {error}"))?;
        Ok(lease)
    }
}

impl Drop for ProducerLease {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        if let Some(parent) = self.path.parent() {
            let _ = sync_directory(parent);
        }
    }
}

impl TemporaryFile {
    fn new(path: PathBuf) -> Result<(Self, File), String> {
        let file = new_file(&path)?;
        Ok((Self { path }, file))
    }
}

impl Drop for TemporaryFile {
    fn drop(&mut self) {
        let _ = set_file_mode(&self.path, 0o600);
        let _ = fs::remove_file(&self.path);
    }
}

pub(crate) fn run(root: &Path, arguments: &[String]) -> Result<(), String> {
    let options = parse_options(arguments)?;
    if options.help {
        print!("{HELP}");
        return Ok(());
    }
    if options.reenroll_cargo {
        let _lease = ProducerLease::acquire(root)?;
        return reenroll_cargo(root);
    }
    if !options.plan && !options.record_output {
        let output = validate_enrolled_artifact(root)?;
        println!(
            "reused inspected Linux engine {} (execution_proven=false)",
            root.join(&output.artifact_path).display()
        );
        return Ok(());
    }
    let _lease = ProducerLease::acquire(root)?;
    let plan = load_plan(root, options.offline)?;
    if options.plan {
        print_plan(&plan);
        revalidate_plan(&plan)?;
        return Ok(());
    }
    build_and_record(plan)
}

fn parse_options(arguments: &[String]) -> Result<Options, String> {
    let mut options = Options {
        help: false,
        plan: false,
        record_output: false,
        reenroll_cargo: false,
        offline: false,
    };
    for argument in arguments {
        match argument.as_str() {
            "-h" | "--help" => options.help = true,
            "--plan" if !options.plan => options.plan = true,
            "--record-output" if !options.record_output => options.record_output = true,
            "--reenroll-cargo" if !options.reenroll_cargo => options.reenroll_cargo = true,
            "--offline" if !options.offline => options.offline = true,
            "--plan" | "--record-output" | "--reenroll-cargo" | "--offline" => {
                return Err(format!("duplicate linux-engine option {argument}"));
            }
            _ => return Err(format!("unknown linux-engine option {argument:?}")),
        }
    }
    if usize::from(options.plan)
        + usize::from(options.record_output)
        + usize::from(options.reenroll_cargo)
        > 1
    {
        return Err(
            "--plan, --record-output, and --reenroll-cargo are mutually exclusive".to_owned(),
        );
    }
    if options.reenroll_cargo && !options.offline {
        return Err("--reenroll-cargo requires --offline".to_owned());
    }
    if options.help && arguments.len() != 1 {
        return Err("--help must be the only linux-engine option".to_owned());
    }
    Ok(options)
}

fn reenroll_cargo(root: &Path) -> Result<(), String> {
    let root = exact_directory(root, "workspace root")?;
    let cancellation = Cancellation::for_root(&root);
    cancellation.check("Cargo reenrollment preflight")?;
    let lock_path = root.join(LOCK_PATH);
    let lock_measurement = measure_file(&lock_path, MAX_LOCK_BYTES, false, false)?;
    let old_lock = parse_lock(&read_exact(&lock_path, &lock_measurement)?)?;
    validate_lock_constants(&old_lock)?;

    let rust_path = root.join(RUST_OUTPUT_PATH);
    let rust_measurement = measure_file(&rust_path, MAX_LOCK_BYTES, false, false)?;
    if rust_measurement.sha256 != old_lock.rust_output_sha256 {
        return Err("Rust output authority is stale for linux-engine.lock.toml".to_owned());
    }
    validate_rust_output(&read_exact(&rust_path, &rust_measurement)?, &old_lock)?;

    let cargo_output_path = root.join(CARGO_OUTPUT_PATH);
    let cargo_output_measurement = measure_file(&cargo_output_path, MAX_LOCK_BYTES, false, false)?;
    let cargo_fields =
        canonical_cargo_output(&read_exact(&cargo_output_path, &cargo_output_measurement)?)?;
    let cargo_lock_path = root.join("Cargo.lock");
    let cargo_lock_measurement = measure_file(&cargo_lock_path, MAX_LOCK_BYTES, false, false)?;
    let implementation_path = root.join(IMPLEMENTATION_PATH);
    let implementation_measurement =
        measure_file(&implementation_path, MAX_FILE_BYTES, false, false)?;
    let running = exact_file(
        &env::current_exe().map_err(|error| format!("cannot locate running xtask: {error}"))?,
        "running Linux-engine producer",
    )?;
    let running_measurement = measure_file(&running, MAX_FILE_BYTES, true, false)?;

    let cargo = current_cargo_path(&old_lock)?;
    let cargo_measurement = measure_file(&cargo, MAX_FILE_BYTES, true, false)?;
    let old_vendor = exact_directory(
        &root
            .join("build/toolchain/cargo/prefixes")
            .join(&old_lock.cargo_lock_sha256)
            .join("vendor"),
        "old enrolled Cargo vendor closure",
    )?;
    let new_vendor = exact_directory(
        &root
            .join("build/toolchain/cargo/prefixes")
            .join(&cargo_fields.cargo_lock_sha256)
            .join("vendor"),
        "current enrolled Cargo vendor closure",
    )?;
    let old_tree = measure_tree(&old_vendor, MAX_TREE_FILES, MAX_TREE_BYTES, true)?;
    let new_tree = measure_tree(&new_vendor, MAX_TREE_FILES, MAX_TREE_BYTES, true)?;
    let new_lock = validate_cargo_rollover(
        &old_lock,
        &cargo_output_measurement,
        &cargo_lock_measurement,
        &cargo_fields,
        &cargo_measurement,
        &old_tree,
        &new_tree,
    )?;
    let encoded = encode_lock(&new_lock);

    revalidate_cargo_rollover_inputs(
        &root,
        &cancellation,
        &lock_measurement,
        &rust_measurement,
        &cargo_output_measurement,
        &cargo_lock_measurement,
        &implementation_measurement,
        &running,
        &running_measurement,
        &cargo,
        &cargo_measurement,
        &old_vendor,
        &old_tree,
        &new_vendor,
        &new_tree,
    )?;
    atomically_replace_lock(&root, &cancellation, &lock_measurement, encoded.as_bytes())?;
    revalidate_cargo_rollover_inputs(
        &root,
        &cancellation,
        &FileMeasurement {
            sha256: sha256_bytes(encoded.as_bytes()),
            bytes: encoded.len() as u64,
        },
        &rust_measurement,
        &cargo_output_measurement,
        &cargo_lock_measurement,
        &implementation_measurement,
        &running,
        &running_measurement,
        &cargo,
        &cargo_measurement,
        &old_vendor,
        &old_tree,
        &new_vendor,
        &new_tree,
    )?;
    let published = parse_lock(
        &fs::read(&lock_path)
            .map_err(|error| format!("cannot read published Linux-engine lock: {error}"))?,
    )?;
    if published != new_lock {
        return Err("published Linux-engine lock differs from authenticated rollover".to_owned());
    }
    println!("reenrolled unchanged Cargo vendor authority in {LOCK_PATH}");
    Ok(())
}

#[derive(Debug)]
struct CargoAuthority {
    cargo_lock_sha256: String,
    cargo_sha256: String,
    vendor_tree_sha256: String,
    vendor_files: u64,
    vendor_bytes: u64,
}

fn canonical_cargo_output(bytes: &[u8]) -> Result<CargoAuthority, String> {
    let fields = canonical_assignments(bytes, "Cargo output")?;
    if fields.len() != 6 || parse_u64(required(&fields, "schema")?, "schema")? != 1 {
        return Err("Cargo output has an unsupported schema or fields".to_owned());
    }
    Ok(CargoAuthority {
        cargo_lock_sha256: digest_field(&fields, "cargo_lock_sha256")?,
        cargo_sha256: digest_field(&fields, "cargo_sha256")?,
        vendor_tree_sha256: digest_field(&fields, "vendor_tree_sha256")?,
        vendor_files: positive_field(&fields, "vendor_files")?,
        vendor_bytes: positive_field(&fields, "vendor_bytes")?,
    })
}

fn current_cargo_path(lock: &Lock) -> Result<PathBuf, String> {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is absent while locating enrolled Cargo".to_owned())?;
    let rustup = env::var_os("RUSTUP_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".rustup"));
    exact_file(
        &rustup
            .join("toolchains")
            .join(format!("{}-{}", lock.channel, lock.host))
            .join("bin/cargo"),
        "enrolled Cargo",
    )
}

fn validate_cargo_rollover(
    old: &Lock,
    cargo_output: &FileMeasurement,
    cargo_lock: &FileMeasurement,
    authority: &CargoAuthority,
    cargo: &FileMeasurement,
    old_tree: &TreeMeasurement,
    new_tree: &TreeMeasurement,
) -> Result<Lock, String> {
    if cargo_output.sha256 == old.cargo_output_sha256
        || cargo_lock.sha256 == old.cargo_lock_sha256
        || authority.cargo_lock_sha256 == old.cargo_lock_sha256
    {
        return Err("Cargo authority rollover is stale or a no-op".to_owned());
    }
    if cargo_lock.sha256 != authority.cargo_lock_sha256 {
        return Err("current Cargo.lock is stale for cargo.outputs enrollment".to_owned());
    }
    if cargo.sha256 != old.cargo_sha256
        || cargo.bytes != old.cargo_bytes
        || authority.cargo_sha256 != old.cargo_sha256
    {
        return Err(
            "Cargo executable identity or bytes changed during authority rollover".to_owned(),
        );
    }
    if old_tree.sha256 != old.cargo_vendor_tree_sha256
        || old_tree.files != old.cargo_vendor_files
        || old_tree.bytes != old.cargo_vendor_bytes
        || new_tree != old_tree
        || authority.vendor_tree_sha256 != old.cargo_vendor_tree_sha256
        || authority.vendor_files != old.cargo_vendor_files
        || authority.vendor_bytes != old.cargo_vendor_bytes
    {
        return Err(
            "old and current Cargo vendor trees are not the identical authenticated closure"
                .to_owned(),
        );
    }
    let mut new = old.clone();
    new.cargo_output_sha256 = cargo_output.sha256.clone();
    new.cargo_lock_sha256 = cargo_lock.sha256.clone();
    Ok(new)
}

#[allow(clippy::too_many_arguments)]
fn revalidate_cargo_rollover_inputs(
    root: &Path,
    cancellation: &Cancellation,
    lock: &FileMeasurement,
    rust: &FileMeasurement,
    cargo_output: &FileMeasurement,
    cargo_lock: &FileMeasurement,
    implementation: &FileMeasurement,
    running: &Path,
    running_measurement: &FileMeasurement,
    cargo: &Path,
    cargo_measurement: &FileMeasurement,
    old_vendor: &Path,
    old_tree: &TreeMeasurement,
    new_vendor: &Path,
    new_tree: &TreeMeasurement,
) -> Result<(), String> {
    cancellation.check("Cargo reenrollment input revalidation")?;
    let lock_path = root.join(LOCK_PATH);
    let rust_path = root.join(RUST_OUTPUT_PATH);
    let cargo_output_path = root.join(CARGO_OUTPUT_PATH);
    let cargo_lock_path = root.join("Cargo.lock");
    let implementation_path = root.join(IMPLEMENTATION_PATH);
    let paths: [(&Path, &FileMeasurement, bool); 7] = [
        (&lock_path, lock, false),
        (&rust_path, rust, false),
        (&cargo_output_path, cargo_output, false),
        (&cargo_lock_path, cargo_lock, false),
        (&implementation_path, implementation, false),
        (running, running_measurement, true),
        (cargo, cargo_measurement, true),
    ];
    for (path, expected, executable) in paths {
        if measure_file(path, MAX_FILE_BYTES, executable, false)? != *expected {
            return Err(format!(
                "Cargo reenrollment authority mutated: {}",
                path.display()
            ));
        }
    }
    if measure_tree(old_vendor, MAX_TREE_FILES, MAX_TREE_BYTES, true)? != *old_tree
        || measure_tree(new_vendor, MAX_TREE_FILES, MAX_TREE_BYTES, true)? != *new_tree
    {
        return Err("Cargo vendor authority mutated during reenrollment".to_owned());
    }
    cancellation.check("Cargo reenrollment input revalidation completion")
}

fn atomically_replace_lock(
    root: &Path,
    cancellation: &Cancellation,
    before: &FileMeasurement,
    encoded: &[u8],
) -> Result<(), String> {
    let path = root.join(LOCK_PATH);
    if measure_file(&path, MAX_LOCK_BYTES, false, false)? != *before {
        return Err("Linux-engine lock changed during Cargo reenrollment".to_owned());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "lock path has no parent".to_owned())?;
    let temporary = parent.join(format!(".linux-engine.lock.{}.tmp", std::process::id()));
    if temporary.exists() {
        return Err("stale Linux-engine lock transaction exists".to_owned());
    }
    let (_guard, mut file) = TemporaryFile::new(temporary.clone())?;
    file.write_all(encoded)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot write Linux-engine lock transaction: {error}"))?;
    drop(file);
    let expected = FileMeasurement {
        sha256: sha256_bytes(encoded),
        bytes: encoded.len() as u64,
    };
    let transaction = read_exact(&temporary, &expected)?;
    if measure_file(&temporary, MAX_LOCK_BYTES, false, false)? != expected
        || encode_lock(&parse_lock(&transaction)?).as_bytes() != encoded
    {
        return Err("Linux-engine lock transaction is corrupt or noncanonical".to_owned());
    }
    cancellation.check("Cargo reenrollment publication")?;
    if measure_file(&path, MAX_LOCK_BYTES, false, false)? != *before {
        return Err("Linux-engine lock changed before Cargo reenrollment publication".to_owned());
    }
    fs::rename(&temporary, &path)
        .map_err(|error| format!("cannot atomically replace Linux-engine lock: {error}"))?;
    sync_directory(parent)?;
    Ok(())
}

fn load_plan(root: &Path, offline: bool) -> Result<Plan, String> {
    let root = exact_directory(root, "workspace root")?;
    let cancellation = Cancellation::for_root(&root);
    cancellation.check("plan preflight")?;
    let lock_path = root.join(LOCK_PATH);
    let lock_measurement = measure_file(&lock_path, MAX_LOCK_BYTES, false, false)?;
    let lock = parse_lock(&read_exact(&lock_path, &lock_measurement)?)?;
    validate_lock_constants(&lock)?;

    let rust_output_path = root.join(RUST_OUTPUT_PATH);
    let rust_output_measurement = measure_file(&rust_output_path, MAX_LOCK_BYTES, false, false)?;
    if rust_output_measurement.sha256 != lock.rust_output_sha256 {
        return Err("Rust output authority is stale for linux-engine.lock.toml".to_owned());
    }
    validate_rust_output(
        &read_exact(&rust_output_path, &rust_output_measurement)?,
        &lock,
    )?;

    let cargo_output_path = root.join(CARGO_OUTPUT_PATH);
    let cargo_output_measurement = measure_file(&cargo_output_path, MAX_LOCK_BYTES, false, false)?;
    if cargo_output_measurement.sha256 != lock.cargo_output_sha256 {
        return Err(format!(
            "Cargo vendor authority is stale: {} is {}, linux-engine.lock.toml requires {}",
            cargo_output_path.display(),
            cargo_output_measurement.sha256,
            lock.cargo_output_sha256
        ));
    }
    validate_cargo_output(
        &read_exact(&cargo_output_path, &cargo_output_measurement)?,
        &lock,
    )?;
    let cargo_lock_path = root.join("Cargo.lock");
    let cargo_lock_measurement = measure_file(&cargo_lock_path, MAX_LOCK_BYTES, false, false)?;
    if cargo_lock_measurement.sha256 != lock.cargo_lock_sha256 {
        return Err("Cargo.lock differs from the Linux-engine closure pin".to_owned());
    }

    let implementation_path = root.join(IMPLEMENTATION_PATH);
    let implementation_measurement =
        measure_file(&implementation_path, MAX_FILE_BYTES, false, false)?;
    let running = exact_file(
        &env::current_exe().map_err(|error| format!("cannot locate running xtask: {error}"))?,
        "running Linux-engine producer",
    )?;
    let running_measurement = measure_file(&running, MAX_FILE_BYTES, true, false)?;
    let tools = resolve_tools(&root, &lock)?;
    let archive = acquire_archive(&root, &lock, offline, &cancellation)?;
    let archive_measurement = measure_file(&archive, lock.target_archive_bytes, false, false)?;
    if archive_measurement.sha256 != lock.target_archive_sha256
        || archive_measurement.bytes != lock.target_archive_bytes
    {
        return Err("Rust Linux target archive differs from its release-manifest pin".to_owned());
    }

    let vendor = exact_directory(
        &root
            .join("build/toolchain/cargo/prefixes")
            .join(&lock.cargo_lock_sha256)
            .join("vendor"),
        "enrolled Cargo vendor closure",
    )?;
    let vendor_tree = measure_tree(&vendor, MAX_TREE_FILES, MAX_TREE_BYTES, true)?;
    if vendor_tree.sha256 != lock.cargo_vendor_tree_sha256
        || vendor_tree.files != lock.cargo_vendor_files
        || vendor_tree.bytes != lock.cargo_vendor_bytes
    {
        return Err("Cargo vendor tree differs from the exact Linux-engine closure pin".to_owned());
    }
    let source_tree = measure_source_tree(&root)?;
    let input_sha256 = input_digest(
        [
            &lock_measurement,
            &rust_output_measurement,
            &cargo_output_measurement,
            &cargo_lock_measurement,
            &implementation_measurement,
            &archive_measurement,
        ],
        &vendor_tree,
        &source_tree,
        &tools,
    );
    let enrolled = read_optional_output(&root.join(OUTPUT_PATH))?;
    Ok(Plan {
        root,
        lock,
        lock_measurement,
        rust_output_measurement,
        cargo_output_measurement,
        cargo_lock_measurement,
        implementation_measurement,
        running,
        running_measurement,
        archive,
        archive_measurement,
        vendor,
        vendor_tree,
        source_tree,
        tools,
        input_sha256,
        enrolled,
        cancellation,
    })
}

fn print_plan(plan: &Plan) {
    let state = match plan.enrolled.as_ref() {
        None => "absent",
        Some((_, output)) if output.input_sha256 == plan.input_sha256 => "current",
        Some(_) => "stale",
    };
    println!("linux_engine_target={TARGET}");
    println!("linux_engine_input_sha256={}", plan.input_sha256);
    println!(
        "rust_target_archive_sha256={}",
        plan.archive_measurement.sha256
    );
    println!("cargo_vendor_tree_sha256={}", plan.vendor_tree.sha256);
    println!("source_tree_sha256={}", plan.source_tree.sha256);
    println!("output_enrollment={state}");
    println!("lanes=2");
    println!("execution_proven=false");
}

fn build_and_record(plan: Plan) -> Result<(), String> {
    revalidate_plan(&plan)?;
    let staging_parent = plan.root.join("build/toolchain/linux-engine/staging");
    let first = build_lane(&plan, &staging_parent, "lane-a")?;
    revalidate_plan(&plan)?;
    let second = build_lane(&plan, &staging_parent, "lane-b")?;
    if first.measurement != second.measurement {
        return Err(format!(
            "path-distinct Linux-engine lanes are not byte-identical: {} != {}",
            first.measurement.sha256, second.measurement.sha256
        ));
    }
    if first.target_tree != second.target_tree {
        return Err(
            "path-distinct lanes extracted different authenticated target trees".to_owned(),
        );
    }
    inspect_elf(
        &read_exact(&first.binary, &first.measurement)?,
        &[
            first.staging.path.clone(),
            second.staging.path.clone(),
            plan.root.clone(),
            plan.vendor.clone(),
            plan.tools.sysroot.clone(),
        ],
    )?;
    inspect_elf(
        &read_exact(&second.binary, &second.measurement)?,
        &[
            first.staging.path.clone(),
            second.staging.path.clone(),
            plan.root.clone(),
            plan.vendor.clone(),
            plan.tools.sysroot.clone(),
        ],
    )?;
    revalidate_plan(&plan)?;

    let bundle_key = engine_bundle_key(&plan.input_sha256, &first.measurement.sha256);
    let artifact_path = format!(
        "build/toolchain/linux-engine/prefixes/{}/bin/wrela-engine",
        bundle_key
    );
    let receipt = encode_receipt(
        &plan,
        &first.target_tree,
        &first.measurement,
        &artifact_path,
    );
    let receipt_measurement = FileMeasurement {
        sha256: sha256_bytes(receipt.as_bytes()),
        bytes: u64::try_from(receipt.len()).map_err(|_| "receipt length overflow".to_owned())?,
    };
    revalidate_native_authority(&plan)?;
    publish_bundle(
        &plan,
        &first.binary,
        &first.measurement,
        receipt.as_bytes(),
        &receipt_measurement,
        &bundle_key,
    )?;
    let output = Output {
        input_sha256: plan.input_sha256.clone(),
        source_tree_sha256: plan.source_tree.sha256.clone(),
        source_files: plan.source_tree.files,
        source_bytes: plan.source_tree.bytes,
        target_tree_sha256: first.target_tree.sha256.clone(),
        target_files: first.target_tree.files,
        target_bytes: first.target_tree.bytes,
        binary_sha256: first.measurement.sha256.clone(),
        binary_bytes: first.measurement.bytes,
        receipt_sha256: receipt_measurement.sha256,
        receipt_bytes: receipt_measurement.bytes,
        artifact_path,
        execution_proven: false,
    };
    revalidate_plan(&plan)?;
    atomically_write_output(&plan, &output)?;
    validate_enrolled_output(&plan, &output)?;
    println!(
        "published static AArch64 Linux engine {} (execution_proven=false)",
        plan.root.join(&output.artifact_path).display()
    );
    Ok(())
}

fn build_lane(plan: &Plan, parent: &Path, label: &str) -> Result<LaneResult, String> {
    let staging = Staging::create(parent, label)?;
    let source = staging.path.join("source");
    let vendor = staging.path.join("vendor");
    let sysroot = staging.path.join("target-sysroot");
    let target_dir = staging.path.join("target");
    let cargo_home = staging.path.join("cargo-home");
    let home = staging.path.join("home");
    let temp = staging.path.join("tmp");
    for directory in [
        &source,
        &vendor,
        &sysroot,
        &target_dir,
        &cargo_home,
        &home,
        &temp,
    ] {
        ensure_directory(directory)?;
    }
    copy_measured_tree(&plan.root, &source, &plan.source_tree, &plan.cancellation)?;
    copy_measured_tree(&plan.vendor, &vendor, &plan.vendor_tree, &plan.cancellation)?;
    let target_tree = extract_target_archive(
        &plan.archive,
        &plan.tools.xz,
        &sysroot,
        &plan.lock,
        &plan.cancellation,
    )?;
    let cargo_directory = source.join(".cargo");
    ensure_directory(&cargo_directory)?;
    let config = cargo_config(plan, &source, &vendor, &sysroot, &target_dir)?;
    write_new(
        &cargo_directory.join("config.toml"),
        config.as_bytes(),
        false,
    )?;

    let mut command = Command::new(&plan.tools.cargo);
    command
        .current_dir(&source)
        .env_clear()
        .env("CARGO_HOME", &cargo_home)
        .env("CARGO_INCREMENTAL", "0")
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_TERM_COLOR", "never")
        .env("AR", &plan.tools.native.ar)
        .env("CC", &plan.tools.native.cxx)
        .env("CXX", &plan.tools.native.cxx)
        .env("HOME", &home)
        .env("LC_ALL", "C")
        .env("MACOSX_DEPLOYMENT_TARGET", "13.0")
        .env("PATH", "/wrela/no-ambient-path")
        .env("RUSTC", &plan.tools.rustc)
        .env("RUSTDOC", &plan.tools.rustdoc)
        .env("SOURCE_DATE_EPOCH", "1")
        .env("SDKROOT", &plan.tools.native.sysroot)
        .env("TMPDIR", &temp)
        .env("TZ", "UTC")
        .args([
            "build",
            "--frozen",
            "--locked",
            "--offline",
            "--package",
            PACKAGE,
            "--profile",
            PROFILE,
            "--target",
            TARGET,
        ])
        .arg("--manifest-path")
        .arg(source.join("Cargo.toml"))
        .arg("--target-dir")
        .arg(&target_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = run_bounded_command(
        &mut command,
        &format!("Linux-engine Cargo lane {label}"),
        &plan.cancellation,
        BUILD_TIMEOUT_SECONDS,
    )?;
    if !output.status.success() {
        return Err(format!(
            "Linux-engine Cargo lane {label} failed with {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            bounded_text(&output.stdout),
            bounded_text(&output.stderr)
        ));
    }
    let binary = exact_file(
        &target_dir.join(TARGET).join(PROFILE).join(PACKAGE),
        "Linux-engine lane output",
    )?;
    let measurement = measure_file(&binary, MAX_BINARY_BYTES, true, false)?;
    inspect_elf(
        &read_exact(&binary, &measurement)?,
        &[
            staging.path.clone(),
            plan.root.clone(),
            plan.vendor.clone(),
            plan.tools.sysroot.clone(),
        ],
    )?;
    Ok(LaneResult {
        binary,
        measurement,
        target_tree,
        staging,
    })
}

fn run_bounded_command(
    command: &mut Command,
    label: &str,
    cancellation: &Cancellation,
    timeout_seconds: u64,
) -> Result<ProcessOutput, String> {
    run_bounded_command_inner(command, label, cancellation, timeout_seconds, true, None)
}

fn run_bounded_watched_command(
    command: &mut Command,
    label: &str,
    cancellation: &Cancellation,
    timeout_seconds: u64,
    watched_path: &Path,
    watched_max_bytes: u64,
) -> Result<ProcessOutput, String> {
    run_bounded_command_inner(
        command,
        label,
        cancellation,
        timeout_seconds,
        true,
        Some((watched_path, watched_max_bytes)),
    )
}

fn run_bounded_redirected_command(
    command: &mut Command,
    label: &str,
    cancellation: &Cancellation,
    timeout_seconds: u64,
    watched_path: &Path,
    watched_max_bytes: u64,
) -> Result<ProcessOutput, String> {
    run_bounded_command_inner(
        command,
        label,
        cancellation,
        timeout_seconds,
        false,
        Some((watched_path, watched_max_bytes)),
    )
}

fn run_bounded_command_inner(
    command: &mut Command,
    label: &str,
    cancellation: &Cancellation,
    timeout_seconds: u64,
    capture_stdout: bool,
    watched_output: Option<(&Path, u64)>,
) -> Result<ProcessOutput, String> {
    if timeout_seconds == 0 || timeout_seconds > 24 * 60 * 60 {
        return Err(format!("{label} has an invalid bounded timeout"));
    }
    if let Some((path, max_bytes)) = watched_output {
        check_watched_output(path, max_bytes, label)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(not(unix))]
    {
        let _ = command;
        return Err("Linux-engine bounded process control requires Unix process groups".to_owned());
    }
    if capture_stdout {
        command.stdout(Stdio::piped());
    }
    command.stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot execute {label}: {error}"))?;
    let stdout = match (capture_stdout, child.stdout.take()) {
        (true, Some(stdout)) => Some(stdout),
        (true, None) => {
            return Err(terminate_child(
                &mut child,
                label,
                "stdout pipe unavailable",
            ));
        }
        (false, _) => None,
    };
    let stderr = match child.stderr.take() {
        Some(stderr) => stderr,
        None => {
            return Err(terminate_child(
                &mut child,
                label,
                "stderr pipe unavailable",
            ));
        }
    };
    let exceeded = Arc::new(AtomicBool::new(false));
    let stdout_reader = stdout.map(|stdout| spawn_bounded_reader(stdout, exceeded.clone()));
    let stderr_reader = spawn_bounded_reader(stderr, exceeded.clone());
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(timeout_seconds))
        .ok_or_else(|| terminate_child(&mut child, label, "timeout overflow"))?;
    let mut terminal_error = None;
    let status = loop {
        if let Err(error) = cancellation.check(label) {
            terminal_error = Some(error);
            break terminate_and_reap(&mut child, label)?;
        }
        if exceeded.load(Ordering::Acquire) {
            terminal_error = Some(format!(
                "{label} output exceeded {MAX_PROCESS_OUTPUT_BYTES} bytes per stream"
            ));
            break terminate_and_reap(&mut child, label)?;
        }
        if let Some((path, max_bytes)) = watched_output {
            if let Err(error) = check_watched_output(path, max_bytes, label) {
                terminal_error = Some(error);
                break terminate_and_reap(&mut child, label)?;
            }
        }
        if Instant::now() >= deadline {
            terminal_error = Some(format!("{label} exceeded its bounded timeout"));
            break terminate_and_reap(&mut child, label)?;
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                terminal_error = Some(format!("cannot observe {label}: {error}"));
                break terminate_and_reap(&mut child, label)?;
            }
        }
    };
    // Successful tools may not leave pipe-owning background descendants.
    terminate_background_group(child.id(), label)?;
    if let Some((path, max_bytes)) = watched_output {
        if let Err(error) = check_watched_output(path, max_bytes, label) {
            if terminal_error.is_none() {
                terminal_error = Some(error);
            }
        }
    }
    let stdout = stdout_reader
        .map(|reader| {
            reader
                .recv_timeout(Duration::from_secs(5))
                .map_err(|_| format!("{label} stdout pipe remained open after child exit"))?
                .map_err(|error| format!("cannot read {label} stdout: {error}"))
        })
        .transpose()?
        .unwrap_or_default();
    let stderr = stderr_reader
        .recv_timeout(Duration::from_secs(5))
        .map_err(|_| format!("{label} stderr pipe remained open after child exit"))?
        .map_err(|error| format!("cannot read {label} stderr: {error}"))?;
    if let Some(error) = terminal_error {
        return Err(format!(
            "{error}; child reaped with {status}\nstdout:\n{}\nstderr:\n{}",
            bounded_text(&stdout),
            bounded_text(&stderr)
        ));
    }
    if exceeded.load(Ordering::Acquire) {
        return Err(format!(
            "{label} output exceeded {MAX_PROCESS_OUTPUT_BYTES} bytes per stream"
        ));
    }
    Ok(ProcessOutput {
        status,
        stdout,
        stderr,
    })
}

fn check_watched_output(path: &Path, max_bytes: u64, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "cannot inspect {label} watched output {}: {error}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "{label} watched output is a link or special entry: {}",
            path.display()
        ));
    }
    if metadata.len() > max_bytes {
        return Err(format!(
            "{label} watched output {} exceeded its {max_bytes}-byte bound (observed {} bytes)",
            path.display(),
            metadata.len()
        ));
    }
    Ok(())
}

fn spawn_bounded_reader(
    mut reader: impl Read + Send + 'static,
    exceeded: Arc<AtomicBool>,
) -> mpsc::Receiver<std::io::Result<Vec<u8>>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let result = (|| {
            let mut captured = Vec::new();
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = reader.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                let remaining = MAX_PROCESS_OUTPUT_BYTES.saturating_sub(captured.len());
                let retained = remaining.min(read);
                captured.extend_from_slice(&buffer[..retained]);
                if retained != read {
                    exceeded.store(true, Ordering::Release);
                }
            }
            Ok(captured)
        })();
        let _ = sender.send(result);
    });
    receiver
}

fn terminate_and_reap(
    child: &mut std::process::Child,
    label: &str,
) -> Result<std::process::ExitStatus, String> {
    let process_group = child.id();
    if process_group_exists(process_group)? {
        signal_process_group(process_group, "-TERM")?;
    }
    for _ in 0..20 {
        match child.try_wait() {
            Ok(Some(status)) => {
                terminate_background_group(process_group, label)?;
                return Ok(status);
            }
            Ok(None) => thread::sleep(Duration::from_millis(25)),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("cannot reap {label}: {error}"));
            }
        }
    }
    if process_group_exists(process_group)? {
        signal_process_group(process_group, "-KILL")?;
    }
    let _ = child.kill();
    let status = child
        .wait()
        .map_err(|error| format!("cannot reap terminated {label}: {error}"))?;
    wait_for_process_group_exit(process_group, label)?;
    Ok(status)
}

fn terminate_background_group(process_group: u32, label: &str) -> Result<(), String> {
    if process_group_exists(process_group)? {
        signal_process_group(process_group, "-KILL")?;
    }
    wait_for_process_group_exit(process_group, label)
}

fn wait_for_process_group_exit(process_group: u32, label: &str) -> Result<(), String> {
    for _ in 0..40 {
        if !process_group_exists(process_group)? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err(format!(
        "{label} process group {process_group} survived termination"
    ))
}

fn signal_process_group(process_group: u32, signal: &str) -> Result<(), String> {
    let status = kill_status(signal, &format!("-{process_group}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "/bin/kill {signal} failed for process group {process_group} with {status}"
        ))
    }
}

fn process_group_exists(process_group: u32) -> Result<bool, String> {
    kill_status("-0", &format!("-{process_group}")).map(|status| status.success())
}

#[cfg(test)]
fn process_exists(process: u32) -> Result<bool, String> {
    kill_status("-0", &process.to_string()).map(|status| status.success())
}

fn kill_status(signal: &str, target: &str) -> Result<std::process::ExitStatus, String> {
    Command::new("/bin/kill")
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/wrela/no-ambient-path")
        .env("TZ", "UTC")
        .arg(signal)
        .arg(target)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("cannot execute /bin/kill {signal} {target}: {error}"))
}

fn terminate_child(child: &mut std::process::Child, label: &str, reason: &str) -> String {
    match terminate_and_reap(child, label) {
        Ok(status) => format!("{label} {reason}; child reaped with {status}"),
        Err(error) => format!("{label} {reason}; {error}"),
    }
}

fn cargo_config(
    plan: &Plan,
    source: &Path,
    vendor: &Path,
    sysroot: &Path,
    target_dir: &Path,
) -> Result<String, String> {
    for path in [
        source,
        vendor,
        sysroot,
        target_dir,
        &plan.tools.rust_lld,
        &plan.tools.native.cxx,
        &plan.tools.native.sysroot,
    ] {
        if !path.is_absolute() || path.to_str().is_none() {
            return Err("Cargo lane path is not absolute UTF-8".to_owned());
        }
    }
    let quote = |path: &Path| toml_string(path.to_str().expect("validated UTF-8"));
    Ok(format!(
        "[net]\noffline = true\n\n[source.crates-io]\nreplace-with = \"wrela-vendor\"\n\n[source.wrela-vendor]\ndirectory = {}\n\n[target.{}]\nlinker = {}\nrustflags = [\n  {},\n  {},\n  {},\n  \"-Clink-self-contained=yes\",\n  \"-Ctarget-feature=+crt-static\",\n  \"-Crelocation-model=static\",\n  \"-Clink-arg=--build-id=none\",\n  \"-Cpanic=abort\",\n  \"-Cstrip=symbols\",\n  \"--sysroot\",\n  {},\n]\n\n[target.{}]\nlinker = {}\nrustflags = [\n  {},\n  {},\n  {},\n  \"-Clink-arg=-isysroot\",\n  {},\n  \"-Clink-arg=-mmacosx-version-min=13.0\",\n]\n",
        quote(vendor),
        TARGET,
        quote(&plan.tools.rust_lld),
        toml_string(&format!(
            "--remap-path-prefix={}=/wrela/source",
            source.display()
        )),
        toml_string(&format!(
            "--remap-path-prefix={}=/wrela/vendor",
            vendor.display()
        )),
        toml_string(&format!(
            "--remap-path-prefix={}=/wrela/target",
            target_dir.display()
        )),
        quote(sysroot),
        HOST,
        quote(&plan.tools.native.cxx),
        toml_string(&format!(
            "--remap-path-prefix={}=/wrela/source",
            source.display()
        )),
        toml_string(&format!(
            "--remap-path-prefix={}=/wrela/vendor",
            vendor.display()
        )),
        toml_string(&format!(
            "--remap-path-prefix={}=/wrela/target",
            target_dir.display()
        )),
        toml_string(&format!(
            "-Clink-arg={}",
            plan.tools.native.sysroot.display()
        )),
    ))
}

fn publish_bundle(
    plan: &Plan,
    binary: &Path,
    binary_measurement: &FileMeasurement,
    receipt: &[u8],
    receipt_measurement: &FileMeasurement,
    bundle_key: &str,
) -> Result<(), String> {
    plan.cancellation.check("bundle publication preflight")?;
    let prefixes = plan.root.join("build/toolchain/linux-engine/prefixes");
    ensure_directory(&prefixes)?;
    let destination = prefixes.join(bundle_key);
    if destination.exists() {
        validate_bundle(&destination, binary_measurement, receipt_measurement)?;
        return plan.cancellation.check("bundle reuse completion");
    }
    let mut staging = Staging::create(&prefixes, "publish")?;
    let bin = staging.path.join("bin");
    ensure_directory(&bin)?;
    copy_file(
        binary,
        &bin.join(PACKAGE),
        binary_measurement,
        true,
        &plan.cancellation,
    )?;
    write_new(&staging.path.join("receipt.toml"), receipt, false)?;
    validate_bundle(&staging.path, binary_measurement, receipt_measurement)?;
    sync_tree(&staging.path)?;
    plan.cancellation.check("atomic bundle publication")?;
    match fs::rename(&staging.path, &destination) {
        Ok(()) => {
            sync_directory(&prefixes)?;
            staging.keep = true;
        }
        Err(error) if destination.exists() => {
            validate_bundle(&destination, binary_measurement, receipt_measurement).map_err(
                |validation| {
                    format!(
                        "Linux-engine publication race failed ({error}); winner invalid: {validation}"
                    )
                },
            )?;
        }
        Err(error) => return Err(format!("cannot atomically publish Linux engine: {error}")),
    }
    validate_bundle(&destination, binary_measurement, receipt_measurement)?;
    plan.cancellation.check("bundle publication completion")
}

fn validate_bundle(
    directory: &Path,
    binary: &FileMeasurement,
    receipt: &FileMeasurement,
) -> Result<(), String> {
    let directory = validate_private_directory(directory, "Linux-engine bundle")?;
    validate_private_directory(&directory.join("bin"), "Linux-engine bundle bin")?;
    if measure_private_file(
        &directory.join("bin/wrela-engine"),
        MAX_BINARY_BYTES,
        true,
        false,
        0o700,
    )? != *binary
        || measure_private_file(
            &directory.join("receipt.toml"),
            MAX_LOCK_BYTES,
            false,
            false,
            0o600,
        )? != *receipt
    {
        return Err("published Linux-engine bundle differs from its exact receipt".to_owned());
    }
    let names = bounded_relative_files(&directory, 3)?;
    if names != ["bin/wrela-engine", "receipt.toml"] {
        return Err(format!(
            "Linux-engine bundle contains unexpected files {names:?}"
        ));
    }
    Ok(())
}

fn validate_enrolled_artifact(root: &Path) -> Result<Output, String> {
    let root = exact_directory(root, "workspace root")?;
    exact_directory(&root.join("toolchain"), "Linux-engine output store")?;
    let output_path = root.join(OUTPUT_PATH);
    if !output_path.exists() {
        return Err(
            "Linux-engine output is not enrolled; run `cargo xtask linux-engine --record-output --offline` only after reviewing the authenticated inputs"
                .to_owned(),
        );
    }
    let output_measurement =
        measure_private_file(&output_path, MAX_LOCK_BYTES, false, false, 0o600)?;
    let output = parse_output(&read_exact(&output_path, &output_measurement)?)?;
    if output.execution_proven {
        return Err("Linux-engine output overclaims execution".to_owned());
    }
    let bundle_key = engine_bundle_key(&output.input_sha256, &output.binary_sha256);
    let expected_path = format!(
        "build/toolchain/linux-engine/prefixes/{}/bin/wrela-engine",
        bundle_key
    );
    if output.artifact_path != expected_path {
        return Err("Linux-engine output has a non-content-addressed artifact path".to_owned());
    }
    let binary = FileMeasurement {
        sha256: output.binary_sha256.clone(),
        bytes: output.binary_bytes,
    };
    let receipt = FileMeasurement {
        sha256: output.receipt_sha256.clone(),
        bytes: output.receipt_bytes,
    };
    let bundle = root
        .join("build/toolchain/linux-engine/prefixes")
        .join(&bundle_key);
    validate_private_directory(
        &root.join("build/toolchain/linux-engine/prefixes"),
        "Linux-engine prefix store",
    )?;
    validate_bundle(&bundle, &binary, &receipt)?;
    validate_receipt_for_output(
        &read_exact(&bundle.join("receipt.toml"), &receipt)?,
        &output,
    )?;
    inspect_elf(
        &read_exact(&bundle.join("bin/wrela-engine"), &binary)?,
        &[root],
    )?;
    Ok(output)
}

fn validate_receipt_for_output(bytes: &[u8], output: &Output) -> Result<(), String> {
    const KEYS: [&str; 31] = [
        "schema",
        "input_sha256",
        "target",
        "package",
        "profile",
        "source_tree_sha256",
        "source_files",
        "source_bytes",
        "cargo_vendor_tree_sha256",
        "cargo_vendor_files",
        "cargo_vendor_bytes",
        "target_archive_sha256",
        "target_archive_bytes",
        "target_tree_sha256",
        "target_files",
        "target_bytes",
        "rust_sysroot_tree_sha256",
        "rust_sysroot_files",
        "rust_sysroot_bytes",
        "cargo_sha256",
        "rustc_sha256",
        "rustdoc_sha256",
        "rust_lld_sha256",
        "xz_sha256",
        "xz_liblzma_sha256",
        "darwin_bootstrap_receipt_sha256",
        "binary_sha256",
        "binary_bytes",
        "artifact_path",
        "reproducible_lanes",
        "execution_proven",
    ];
    let fields = canonical_assignments(bytes, "Linux-engine receipt")?;
    let text = std::str::from_utf8(bytes).expect("canonical assignments validated UTF-8");
    let keys = text
        .lines()
        .map(|line| {
            line.split_once(" = ")
                .expect("canonical assignments validated separators")
                .0
        })
        .collect::<Vec<_>>();
    if keys != KEYS || parse_u64(required(&fields, "schema")?, "schema")? != 2 {
        return Err("Linux-engine receipt has an unsupported schema, fields, or order".to_owned());
    }
    for key in [
        "input_sha256",
        "source_tree_sha256",
        "cargo_vendor_tree_sha256",
        "target_archive_sha256",
        "target_tree_sha256",
        "rust_sysroot_tree_sha256",
        "cargo_sha256",
        "rustc_sha256",
        "rustdoc_sha256",
        "rust_lld_sha256",
        "xz_sha256",
        "xz_liblzma_sha256",
        "darwin_bootstrap_receipt_sha256",
        "binary_sha256",
    ] {
        digest_field(&fields, key)?;
    }
    for key in [
        "source_files",
        "source_bytes",
        "cargo_vendor_files",
        "cargo_vendor_bytes",
        "target_archive_bytes",
        "target_files",
        "target_bytes",
        "rust_sysroot_files",
        "rust_sysroot_bytes",
        "binary_bytes",
    ] {
        positive_field(&fields, key)?;
    }
    if string_field(&fields, "target")? != TARGET
        || string_field(&fields, "package")? != PACKAGE
        || string_field(&fields, "profile")? != PROFILE
        || required(&fields, "reproducible_lanes")? != "2"
        || required(&fields, "execution_proven")? != "false"
        || string_field(&fields, "input_sha256")? != output.input_sha256
        || string_field(&fields, "source_tree_sha256")? != output.source_tree_sha256
        || positive_field(&fields, "source_files")? != output.source_files
        || positive_field(&fields, "source_bytes")? != output.source_bytes
        || string_field(&fields, "target_tree_sha256")? != output.target_tree_sha256
        || positive_field(&fields, "target_files")? != output.target_files
        || positive_field(&fields, "target_bytes")? != output.target_bytes
        || string_field(&fields, "binary_sha256")? != output.binary_sha256
        || positive_field(&fields, "binary_bytes")? != output.binary_bytes
        || string_field(&fields, "artifact_path")? != output.artifact_path
    {
        return Err(
            "Linux-engine receipt does not canonically cross-bind its output enrollment".to_owned(),
        );
    }
    Ok(())
}

fn atomically_write_output(plan: &Plan, output: &Output) -> Result<(), String> {
    plan.cancellation.check("output enrollment preflight")?;
    let path = plan.root.join(OUTPUT_PATH);
    if let Some((before, _)) = plan.enrolled.as_ref() {
        if measure_file(&path, MAX_LOCK_BYTES, false, false)? != *before {
            return Err("Linux-engine output enrollment changed during the build".to_owned());
        }
    } else if path.exists() {
        return Err("Linux-engine output enrollment appeared during the build".to_owned());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "output path has no parent".to_owned())?;
    let temporary = parent.join(format!(".linux-engine.outputs.{}.tmp", std::process::id()));
    if temporary.exists() {
        return Err("stale Linux-engine output transaction exists".to_owned());
    }
    let encoded = encode_output(output);
    let (_temporary_guard, mut temporary_file) = TemporaryFile::new(temporary.clone())?;
    temporary_file
        .write_all(encoded.as_bytes())
        .and_then(|()| temporary_file.sync_all())
        .map_err(|error| format!("cannot write Linux-engine output transaction: {error}"))?;
    drop(temporary_file);
    if read_exact(
        &temporary,
        &FileMeasurement {
            sha256: sha256_bytes(encoded.as_bytes()),
            bytes: encoded.len() as u64,
        },
    )? != encoded.as_bytes()
    {
        return Err("Linux-engine output transaction changed before enrollment".to_owned());
    }
    plan.cancellation.check("atomic output enrollment")?;
    fs::rename(&temporary, &path)
        .map_err(|error| format!("cannot atomically enroll Linux-engine output: {error}"))?;
    sync_directory(parent)?;
    let (_, parsed) = read_optional_output(&path)?
        .ok_or_else(|| "Linux-engine output vanished after enrollment".to_owned())?;
    if parsed != *output {
        return Err("Linux-engine output changed during atomic enrollment".to_owned());
    }
    plan.cancellation.check("output enrollment completion")
}

fn validate_enrolled_output(plan: &Plan, output: &Output) -> Result<(), String> {
    if output.input_sha256 != plan.input_sha256
        || output.source_tree_sha256 != plan.source_tree.sha256
        || output.source_files != plan.source_tree.files
        || output.source_bytes != plan.source_tree.bytes
        || output.execution_proven
    {
        return Err("Linux-engine output enrollment is stale or overclaims execution".to_owned());
    }
    let bundle_key = engine_bundle_key(&output.input_sha256, &output.binary_sha256);
    let expected_path = format!(
        "build/toolchain/linux-engine/prefixes/{}/bin/wrela-engine",
        bundle_key
    );
    if output.artifact_path != expected_path {
        return Err("Linux-engine output has a non-content-addressed artifact path".to_owned());
    }
    let binary = FileMeasurement {
        sha256: output.binary_sha256.clone(),
        bytes: output.binary_bytes,
    };
    let receipt = FileMeasurement {
        sha256: output.receipt_sha256.clone(),
        bytes: output.receipt_bytes,
    };
    let bundle = plan
        .root
        .join("build/toolchain/linux-engine/prefixes")
        .join(&bundle_key);
    validate_bundle(&bundle, &binary, &receipt)?;
    let reuse_parent = plan.root.join("build/toolchain/linux-engine/staging");
    let target_staging = Staging::create(&reuse_parent, "reuse-target")?;
    let target_sysroot = target_staging.path.join("target-sysroot");
    ensure_directory(&target_sysroot)?;
    let target_tree = extract_target_archive(
        &plan.archive,
        &plan.tools.xz,
        &target_sysroot,
        &plan.lock,
        &plan.cancellation,
    )?;
    if target_tree.sha256 != output.target_tree_sha256
        || target_tree.files != output.target_files
        || target_tree.bytes != output.target_bytes
    {
        return Err(
            "Linux-engine target-tree enrollment differs from a fresh authenticated extraction"
                .to_owned(),
        );
    }
    let expected_receipt = encode_receipt(plan, &target_tree, &binary, &output.artifact_path);
    let receipt_bytes = read_exact(&bundle.join("receipt.toml"), &receipt)?;
    if receipt_bytes != expected_receipt.as_bytes() {
        return Err(
            "Linux-engine canonical receipt does not cross-bind output, inputs, target, and binary"
                .to_owned(),
        );
    }
    inspect_elf(
        &read_exact(&bundle.join("bin/wrela-engine"), &binary)?,
        &[
            plan.root.clone(),
            plan.vendor.clone(),
            plan.tools.sysroot.clone(),
        ],
    )
}

fn revalidate_plan(plan: &Plan) -> Result<(), String> {
    plan.cancellation.check("input revalidation")?;
    let checks = [
        (&plan.root.join(LOCK_PATH), &plan.lock_measurement, false),
        (
            &plan.root.join(RUST_OUTPUT_PATH),
            &plan.rust_output_measurement,
            false,
        ),
        (
            &plan.root.join(CARGO_OUTPUT_PATH),
            &plan.cargo_output_measurement,
            false,
        ),
        (
            &plan.root.join("Cargo.lock"),
            &plan.cargo_lock_measurement,
            false,
        ),
        (
            &plan.root.join(IMPLEMENTATION_PATH),
            &plan.implementation_measurement,
            false,
        ),
        (&plan.running, &plan.running_measurement, true),
        (&plan.archive, &plan.archive_measurement, false),
    ];
    for (path, expected, executable) in checks {
        if measure_file(path, MAX_FILE_BYTES, executable, false)? != *expected {
            return Err(format!(
                "authenticated input changed during build: {}",
                path.display()
            ));
        }
    }
    if measure_source_tree(&plan.root)? != plan.source_tree
        || measure_tree(&plan.vendor, MAX_TREE_FILES, MAX_TREE_BYTES, true)? != plan.vendor_tree
    {
        return Err("source or Cargo vendor input changed during Linux-engine build".to_owned());
    }
    validate_tools(&plan.tools, &plan.lock)?;
    plan.cancellation.check("input revalidation completion")
}

fn resolve_tools(root: &Path, lock: &Lock) -> Result<Tools, String> {
    let home = env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| "HOME is absent while locating enrolled Rust tools".to_owned())?;
    let rustup = env::var_os("RUSTUP_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".rustup"));
    let sysroot = exact_directory(
        &rustup
            .join("toolchains")
            .join(format!("{}-{}", lock.channel, lock.host)),
        "enrolled Rust sysroot",
    )?;
    let cargo = exact_file(&sysroot.join("bin/cargo"), "enrolled Cargo")?;
    let rustc = exact_file(&sysroot.join("bin/rustc"), "enrolled rustc")?;
    let rustdoc = exact_file(&sysroot.join("bin/rustdoc"), "enrolled rustdoc")?;
    let rust_lld = exact_file(
        &sysroot
            .join("lib/rustlib")
            .join(&lock.host)
            .join("bin/rust-lld"),
        "enrolled rust-lld",
    )?;
    let xz = env::var_os("WRELA_LINUX_ENGINE_XZ")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/opt/homebrew/bin/xz"));
    let xz = fs::canonicalize(&xz)
        .map_err(|error| format!("cannot resolve explicit xz {}: {error}", xz.display()))?;
    let xz = exact_file(&xz, "explicit xz")?;
    let xz_liblzma = exact_file(Path::new(XZ_LIBLZMA_PATH), "pinned xz liblzma")?;
    let sysroot_tree = measure_tree(&sysroot, MAX_TREE_FILES, MAX_TREE_BYTES, true)?;
    if sysroot_tree.sha256 != lock.rust_sysroot_tree_sha256
        || sysroot_tree.files != lock.rust_sysroot_files
        || sysroot_tree.bytes != lock.rust_sysroot_bytes
    {
        return Err(
            "complete enrolled Rust sysroot differs from linux-engine.lock.toml".to_owned(),
        );
    }
    let native = llvm::verified_environment_for_full_route(root)?;
    let native_receipt = exact_file(
        &native
            .prefix
            .parent()
            .ok_or_else(|| "verified LLVM prefix has no bundle parent".to_owned())?
            .join("provenance.txt"),
        "verified LLVM native-authority receipt",
    )?;
    let native_receipt_measurement = measure_file(&native_receipt, MAX_LOCK_BYTES, false, false)?;
    let native_witnesses = darwin_native_witnesses(&native)?;
    let tools = Tools {
        cargo_measurement: measure_file(&cargo, lock.cargo_bytes, true, false)?,
        rustc_measurement: measure_file(&rustc, lock.rustc_bytes, true, false)?,
        rustdoc_measurement: measure_file(&rustdoc, lock.rustdoc_bytes, true, false)?,
        rust_lld_measurement: measure_file(&rust_lld, lock.rust_lld_bytes, true, false)?,
        xz_measurement: measure_file(&xz, lock.xz_bytes, true, false)?,
        xz_liblzma_measurement: measure_file(&xz_liblzma, lock.xz_liblzma_bytes, false, false)?,
        cargo,
        rustc,
        rustdoc,
        rust_lld,
        xz,
        xz_liblzma,
        sysroot,
        sysroot_tree,
        native,
        native_receipt,
        native_receipt_measurement,
        native_witnesses,
    };
    validate_tools(&tools, lock)?;
    let manifest = tools.sysroot.join(RELEASE_MANIFEST);
    let measured = measure_file(&manifest, lock.release_manifest_bytes, false, false)?;
    if measured.sha256 != lock.release_manifest_sha256
        || measured.bytes != lock.release_manifest_bytes
    {
        return Err(
            "installed Rust release manifest differs from linux-engine.lock.toml".to_owned(),
        );
    }
    validate_release_manifest(&read_exact(&manifest, &measured)?, lock)?;
    Ok(tools)
}

fn validate_tools(tools: &Tools, lock: &Lock) -> Result<(), String> {
    for (path, expected, executable) in [
        (&tools.cargo, &tools.cargo_measurement, true),
        (&tools.rustc, &tools.rustc_measurement, true),
        (&tools.rustdoc, &tools.rustdoc_measurement, true),
        (&tools.rust_lld, &tools.rust_lld_measurement, true),
        (&tools.xz, &tools.xz_measurement, true),
        (&tools.xz_liblzma, &tools.xz_liblzma_measurement, false),
    ] {
        if measure_file(path, MAX_FILE_BYTES, executable, false)? != *expected {
            return Err(format!(
                "explicit producer tool changed: {}",
                path.display()
            ));
        }
    }
    if tools.cargo_measurement.sha256 != lock.cargo_sha256
        || tools.cargo_measurement.bytes != lock.cargo_bytes
        || tools.rustc_measurement.sha256 != lock.rustc_sha256
        || tools.rustc_measurement.bytes != lock.rustc_bytes
        || tools.rustdoc_measurement.sha256 != lock.rustdoc_sha256
        || tools.rustdoc_measurement.bytes != lock.rustdoc_bytes
        || tools.rust_lld_measurement.sha256 != lock.rust_lld_sha256
        || tools.rust_lld_measurement.bytes != lock.rust_lld_bytes
        || tools.xz_measurement.sha256 != lock.xz_sha256
        || tools.xz_measurement.bytes != lock.xz_bytes
        || tools.xz_liblzma_measurement.sha256 != lock.xz_liblzma_sha256
        || tools.xz_liblzma_measurement.bytes != lock.xz_liblzma_bytes
    {
        return Err(
            "Cargo, rustc, rustdoc, rust-lld, or xz differs from the exact Linux-engine pin"
                .to_owned(),
        );
    }
    if measure_tree(&tools.sysroot, MAX_TREE_FILES, MAX_TREE_BYTES, true)? != tools.sysroot_tree {
        return Err("complete enrolled Rust sysroot changed during Linux-engine work".to_owned());
    }
    if measure_file(&tools.native_receipt, MAX_LOCK_BYTES, false, false)?
        != tools.native_receipt_measurement
    {
        return Err(
            "authenticated Darwin bootstrap receipt changed during Linux-engine work".to_owned(),
        );
    }
    for (path, expected) in &tools.native_witnesses {
        if measure_file(
            path,
            MAX_FILE_BYTES,
            path == &tools.native.cxx || path == &tools.native.ar,
            false,
        )? != *expected
        {
            return Err(format!(
                "authenticated Darwin bootstrap witness changed: {}",
                path.display()
            ));
        }
    }
    inspect_xz_dependency_closure(tools)?;
    Ok(())
}

fn revalidate_native_authority(plan: &Plan) -> Result<(), String> {
    if llvm::verified_environment_for_full_route(&plan.root)? != plan.tools.native {
        return Err(
            "authenticated Darwin bootstrap linker authority changed during Linux-engine work"
                .to_owned(),
        );
    }
    validate_tools(&plan.tools, &plan.lock)
}

fn darwin_native_witnesses(
    native: &llvm::VerifiedNativeEnvironment,
) -> Result<Vec<(PathBuf, FileMeasurement)>, String> {
    let mut paths = vec![native.cxx.clone(), native.ar.clone()];
    for relative in [
        "SDKSettings.json",
        "System/Library/CoreServices/SystemVersion.plist",
        "usr/lib/libSystem.tbd",
        "usr/lib/libc++.tbd",
    ] {
        let selected = native.sysroot.join(relative);
        let canonical = fs::canonicalize(&selected).map_err(|error| {
            format!("cannot resolve authenticated macOS SDK witness {relative}: {error}")
        })?;
        if !canonical.starts_with(&native.sysroot) {
            return Err(format!(
                "authenticated macOS SDK witness {relative} escapes its verified SDK"
            ));
        }
        paths.push(exact_file(&canonical, "authenticated macOS SDK witness")?);
    }
    let mut witnesses = Vec::new();
    for path in paths {
        let executable = path == native.cxx || path == native.ar;
        witnesses.push((
            path.clone(),
            measure_file(&path, MAX_FILE_BYTES, executable, false)?,
        ));
    }
    Ok(witnesses)
}

fn acquire_archive(
    root: &Path,
    lock: &Lock,
    offline: bool,
    cancellation: &Cancellation,
) -> Result<PathBuf, String> {
    let sources = root.join("build/toolchain/linux-engine/sources");
    ensure_directory(&sources)?;
    let archive = sources.join(TARGET_ARCHIVE_NAME);
    if archive.exists() {
        return exact_file(&archive, "cached Rust Linux target archive");
    }
    if offline {
        return Err(format!(
            "offline Linux-engine plan requires authenticated archive {}",
            archive.display()
        ));
    }
    let curl = exact_file(Path::new("/usr/bin/curl"), "explicit curl")?;
    let temporary = sources.join(format!(".{TARGET_ARCHIVE_NAME}.{}.tmp", std::process::id()));
    let (_temporary_guard, temporary_file) = TemporaryFile::new(temporary.clone())?;
    drop(temporary_file);
    let mut command = Command::new(curl);
    command
        .env_clear()
        .env("HOME", "/wrela/no-home")
        .env("LC_ALL", "C")
        .env("PATH", "/wrela/no-ambient-path")
        .env("TZ", "UTC")
        .args([
            "--fail",
            "--location",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--max-filesize",
        ])
        .arg(lock.target_archive_bytes.to_string())
        .args(["--output"])
        .arg(&temporary)
        .arg(&lock.target_archive_url);
    let output = match run_bounded_watched_command(
        &mut command,
        "pinned Rust target acquisition",
        cancellation,
        10 * 60,
        &temporary,
        lock.target_archive_bytes,
    ) {
        Ok(output) => output,
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
    };
    if !output.status.success() {
        let _ = fs::remove_file(&temporary);
        return Err(format!(
            "pinned Rust target acquisition failed with {}: {}",
            output.status,
            bounded_text(&output.stderr)
        ));
    }
    let measured = measure_file(&temporary, lock.target_archive_bytes, false, false)?;
    if measured.sha256 != lock.target_archive_sha256 || measured.bytes != lock.target_archive_bytes
    {
        let _ = fs::remove_file(&temporary);
        return Err("acquired Rust target archive failed its release-manifest digest".to_owned());
    }
    fs::rename(&temporary, &archive)
        .map_err(|error| format!("cannot publish authenticated Rust target archive: {error}"))?;
    sync_directory(&sources)?;
    exact_file(&archive, "published Rust target archive")
}

fn extract_target_archive(
    archive: &Path,
    xz: &Path,
    sysroot: &Path,
    lock: &Lock,
    cancellation: &Cancellation,
) -> Result<TreeMeasurement, String> {
    cancellation.check("Rust target decompression preflight")?;
    let staging = sysroot
        .parent()
        .ok_or_else(|| "target sysroot has no staging parent".to_owned())?;
    let tar_path = staging.join("authenticated-rust-target.tar");
    let (_tar_guard, tar_output) = TemporaryFile::new(tar_path.clone())?;
    let mut command = Command::new(xz);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/wrela/no-ambient-path")
        .env("TZ", "UTC")
        .args(["--decompress", "--stdout", "--"])
        .arg(archive)
        .stdout(Stdio::from(tar_output));
    let output = run_bounded_redirected_command(
        &mut command,
        "authenticated Rust target decompression",
        cancellation,
        10 * 60,
        &tar_path,
        MAX_ARCHIVE_EXPANDED_BYTES,
    )?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(format!(
            "authenticated xz failed with {}: {}",
            output.status,
            bounded_text(&output.stderr)
        ));
    }
    cancellation.check("Rust target decompression completion")?;
    let tar_measurement = measure_file(&tar_path, MAX_ARCHIVE_EXPANDED_BYTES, false, false)?;
    let mut tar_input = File::open(&tar_path)
        .map_err(|error| format!("cannot open authenticated Rust target tar: {error}"))?;
    extract_tar(
        &mut tar_input,
        sysroot,
        ArchiveLimits {
            members: MAX_ARCHIVE_MEMBERS,
            files: MAX_ARCHIVE_FILES,
            bytes: MAX_ARCHIVE_EXPANDED_BYTES,
            file_bytes: MAX_ARCHIVE_FILE_BYTES,
        },
        cancellation,
    )?;
    drop(tar_input);
    if measure_file(&tar_path, MAX_ARCHIVE_EXPANDED_BYTES, false, false)? != tar_measurement {
        return Err("authenticated Rust target tar changed during extraction".to_owned());
    }
    cancellation.check("Rust target tree measurement preflight")?;
    let tree = measure_tree(
        sysroot,
        MAX_ARCHIVE_FILES,
        MAX_ARCHIVE_EXPANDED_BYTES,
        false,
    )?;
    cancellation.check("Rust target tree measurement completion")?;
    if tree.sha256 != lock.target_tree_sha256
        || tree.files != lock.target_files
        || tree.bytes != lock.target_bytes
    {
        return Err(
            "decompressed Rust target tree differs from its independent lock enrollment".to_owned(),
        );
    }
    Ok(tree)
}

#[derive(Debug, Clone, Copy)]
struct ArchiveLimits {
    members: u64,
    files: u64,
    bytes: u64,
    file_bytes: u64,
}

fn extract_tar(
    reader: &mut impl Read,
    destination: &Path,
    limits: ArchiveLimits,
    cancellation: &Cancellation,
) -> Result<(), String> {
    let mut members = 0_u64;
    let mut files = 0_u64;
    let mut bytes = 0_u64;
    let mut paths = BTreeSet::new();
    let mut zero_blocks = 0_u8;
    let mut pending_long_name = None;
    loop {
        cancellation.check("Rust target archive extraction")?;
        let Some(header) = read_tar_block(reader)? else {
            break;
        };
        if header.iter().all(|byte| *byte == 0) {
            if pending_long_name.is_some() {
                return Err("GNU tar long-name record lacks a following member".to_owned());
            }
            zero_blocks = zero_blocks.saturating_add(1);
            if zero_blocks == 2 {
                break;
            }
            continue;
        }
        if zero_blocks != 0 {
            return Err("tar contains data after a partial zero trailer".to_owned());
        }
        validate_tar_checksum(&header)?;
        members = members
            .checked_add(1)
            .ok_or_else(|| "tar member overflow".to_owned())?;
        if members > limits.members {
            return Err("Rust target archive exceeds its exact member limit".to_owned());
        }
        let size = parse_tar_octal(&header[124..136], "member size")?;
        let kind = header[156];
        if kind == b'L' {
            if !canonical_gnu_long_name_header(&header) {
                return Err("GNU tar long-name record has a noncanonical header name".to_owned());
            }
            if pending_long_name.is_some() {
                return Err("consecutive GNU tar long-name records are forbidden".to_owned());
            }
            pending_long_name = Some(read_gnu_long_name(reader, size, cancellation)?);
            skip_tar_padding(reader, size)?;
            continue;
        }
        if !matches!(kind, 0 | b'0' | b'5') {
            return Err(format!(
                "Rust target archive contains forbidden member type {kind}"
            ));
        }
        if kind == b'5' && size != 0 {
            return Err("tar directory has a payload".to_owned());
        }
        let header_path = tar_path(&header)?;
        let path = pending_long_name.take().unwrap_or(header_path);
        validate_archive_path(&path)?;
        if !paths.insert(path.clone()) {
            return Err(format!("duplicate tar member path {path:?}"));
        }
        let relative = path
            .strip_prefix(&format!("{TARGET_ARCHIVE_ROOT}/{TARGET_ARCHIVE_SUBTREE}/"))
            .or_else(|| {
                (path == format!("{TARGET_ARCHIVE_ROOT}/{TARGET_ARCHIVE_SUBTREE}")).then_some("")
            });
        if let Some(relative) = relative {
            let output = destination.join("lib/rustlib").join(TARGET).join(relative);
            if !output.starts_with(destination) {
                return Err("tar extraction escaped target sysroot".to_owned());
            }
            if kind == b'5' {
                ensure_directory(&output)?;
                skip_exact(reader, size, cancellation)?;
            } else {
                files = files
                    .checked_add(1)
                    .ok_or_else(|| "tar file overflow".to_owned())?;
                bytes = bytes
                    .checked_add(size)
                    .ok_or_else(|| "tar byte overflow".to_owned())?;
                if files > limits.files || bytes > limits.bytes || size > limits.file_bytes {
                    return Err(
                        "Rust target archive exceeds its file or expanded-byte limit".to_owned(),
                    );
                }
                let parent = output
                    .parent()
                    .ok_or_else(|| "tar output has no parent".to_owned())?;
                ensure_directory(parent)?;
                let mut file = new_file(&output)?;
                copy_exact(reader, &mut file, size, cancellation)?;
                file.sync_all()
                    .map_err(|error| format!("cannot sync tar output: {error}"))?;
                drop(file);
                set_file_mode(
                    &output,
                    if parse_tar_octal(&header[100..108], "member mode")? & 0o111 == 0 {
                        0o600
                    } else {
                        0o700
                    },
                )?;
            }
        } else {
            skip_exact(reader, size, cancellation)?;
        }
        skip_tar_padding(reader, size)?;
    }
    if zero_blocks != 2 || members == 0 || files == 0 || bytes == 0 {
        return Err("Rust target tar is empty or lacks its canonical two-block trailer".to_owned());
    }
    let mut trailer = [0_u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut trailer)
            .map_err(|error| format!("cannot read tar trailer: {error}"))?;
        if read == 0 {
            break;
        }
        if trailer[..read].iter().any(|byte| *byte != 0) {
            return Err("Rust target tar has nonzero trailing data".to_owned());
        }
    }
    Ok(())
}

fn read_gnu_long_name(
    reader: &mut impl Read,
    size: u64,
    cancellation: &Cancellation,
) -> Result<String, String> {
    let maximum = u64::try_from(MAX_PATH_BYTES)
        .map_err(|_| "host path limit does not fit u64".to_owned())?
        .checked_add(1)
        .ok_or_else(|| "GNU tar long-name limit overflow".to_owned())?;
    if size < 2 || size > maximum {
        return Err("GNU tar long-name payload exceeds its exact bound".to_owned());
    }
    let capacity =
        usize::try_from(size).map_err(|_| "GNU tar long-name size overflow".to_owned())?;
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(capacity)
        .map_err(|_| "cannot allocate bounded GNU tar long-name payload".to_owned())?;
    copy_exact(reader, &mut payload, size, cancellation)?;
    if payload.len() != capacity || payload.last() != Some(&0) {
        return Err("GNU tar long-name payload is not canonically NUL-terminated".to_owned());
    }
    payload.pop();
    if payload.contains(&0) {
        return Err("GNU tar long-name payload contains an interior NUL".to_owned());
    }
    let path = String::from_utf8(payload)
        .map_err(|_| "GNU tar long-name payload is not UTF-8".to_owned())?;
    validate_archive_path(&path)?;
    Ok(path)
}

fn inspect_elf(bytes: &[u8], forbidden_paths: &[PathBuf]) -> Result<(), String> {
    if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" {
        return Err("Linux engine is not an ELF file".to_owned());
    }
    if bytes[4] != 2 || bytes[5] != 1 || bytes[6] != 1 || bytes[7] != 0 {
        return Err("Linux engine is not little-endian ELF64 System V".to_owned());
    }
    if le_u16(bytes, 16)? != 2 || le_u16(bytes, 18)? != 183 || le_u32(bytes, 20)? != 1 {
        return Err("Linux engine is not an AArch64 executable ELF".to_owned());
    }
    let program_offset = as_usize(le_u64(bytes, 32)?, "program-header offset")?;
    let section_offset = as_usize(le_u64(bytes, 40)?, "section-header offset")?;
    let program_size = usize::from(le_u16(bytes, 54)?);
    let program_count = usize::from(le_u16(bytes, 56)?);
    let section_size = usize::from(le_u16(bytes, 58)?);
    let section_count = usize::from(le_u16(bytes, 60)?);
    let string_index = usize::from(le_u16(bytes, 62)?);
    if program_size != 56 || program_count == 0 || program_count > 128 {
        return Err("Linux engine has an invalid bounded ELF program-header table".to_owned());
    }
    checked_table(
        bytes,
        program_offset,
        program_size,
        program_count,
        "program headers",
    )?;
    let mut executable_load = false;
    for index in 0..program_count {
        let offset = program_offset + index * program_size;
        let kind = le_u32(bytes, offset)?;
        let flags = le_u32(bytes, offset + 4)?;
        let file_offset = as_usize(le_u64(bytes, offset + 8)?, "segment file offset")?;
        let file_size = as_usize(le_u64(bytes, offset + 32)?, "segment file size")?;
        match kind {
            2 => {
                inspect_dynamic_segment(checked_slice(
                    bytes,
                    file_offset,
                    file_size,
                    "PT_DYNAMIC",
                )?)?;
                return Err(
                    "Linux engine has PT_DYNAMIC and may load ambient dependencies".to_owned(),
                );
            }
            3 => return Err("Linux engine has PT_INTERP and an ambient loader".to_owned()),
            4 => reject_build_id_notes(checked_slice(bytes, file_offset, file_size, "PT_NOTE")?)?,
            1 if flags & 1 != 0 => executable_load = true,
            0x6474_e551 if flags & 1 != 0 => {
                return Err("Linux engine requests an executable stack".to_owned());
            }
            _ => {}
        }
    }
    if !executable_load {
        return Err("Linux engine has no executable PT_LOAD segment".to_owned());
    }
    if section_count != 0 {
        if section_size != 64 || section_count > 4096 || string_index >= section_count {
            return Err("Linux engine has an invalid bounded ELF section table".to_owned());
        }
        checked_table(
            bytes,
            section_offset,
            section_size,
            section_count,
            "section headers",
        )?;
        let strings = section(bytes, section_offset, section_size, string_index)?;
        for index in 0..section_count {
            let offset = section_offset + index * section_size;
            let name = elf_string(
                strings,
                as_usize(u64::from(le_u32(bytes, offset)?), "section name")?,
            )?;
            let kind = le_u32(bytes, offset + 4)?;
            if kind == 7 {
                reject_build_id_notes(section(bytes, section_offset, section_size, index)?)?;
            }
            if kind == 6
                || matches!(
                    name,
                    ".dynamic" | ".dynstr" | ".dynsym" | ".interp" | ".note.gnu.build-id"
                )
            {
                return Err(format!(
                    "Linux engine contains forbidden ELF section {name:?}"
                ));
            }
        }
    }
    for path in forbidden_paths {
        let needle = path
            .to_str()
            .ok_or_else(|| "forbidden path is not UTF-8".to_owned())?
            .as_bytes();
        if needle.len() > 1 && contains_bytes(bytes, needle) {
            return Err(format!(
                "Linux engine embeds forbidden build path {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn inspect_dynamic_segment(bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() % 16 != 0 || bytes.len() > 16 * 1024 * 1024 {
        return Err("Linux engine has a malformed bounded PT_DYNAMIC segment".to_owned());
    }
    let mut terminated = false;
    for entry in bytes.chunks_exact(16) {
        let tag = le_u64(entry, 0)? as i64;
        match tag {
            0 => {
                terminated = true;
                break;
            }
            1 => return Err("Linux engine has a DT_NEEDED dynamic dependency".to_owned()),
            15 => return Err("Linux engine contains forbidden DT_RPATH".to_owned()),
            29 => return Err("Linux engine contains forbidden DT_RUNPATH".to_owned()),
            _ => {}
        }
    }
    if !terminated {
        return Err("Linux engine PT_DYNAMIC lacks a bounded DT_NULL terminator".to_owned());
    }
    Ok(())
}

fn reject_build_id_notes(mut bytes: &[u8]) -> Result<(), String> {
    while !bytes.is_empty() {
        if bytes.iter().all(|byte| *byte == 0) {
            return Ok(());
        }
        if bytes.len() < 12 {
            return Err("Linux engine has a truncated ELF note".to_owned());
        }
        let name_size = as_usize(u64::from(le_u32(bytes, 0)?), "ELF note name size")?;
        let description_size = as_usize(u64::from(le_u32(bytes, 4)?), "ELF note description size")?;
        let note_type = le_u32(bytes, 8)?;
        let name_padded = align_four(name_size)?;
        let description_padded = align_four(description_size)?;
        let note_size = 12_usize
            .checked_add(name_padded)
            .and_then(|size| size.checked_add(description_padded))
            .ok_or_else(|| "ELF note size overflow".to_owned())?;
        if note_size > bytes.len() {
            return Err("Linux engine ELF note escapes its segment or section".to_owned());
        }
        let name = &bytes[12..12 + name_size];
        let canonical_name = name.strip_suffix(&[0]).unwrap_or(name);
        if canonical_name == b"GNU" && note_type == 3 && description_size != 0 {
            return Err("Linux engine contains a nonempty GNU build-id note".to_owned());
        }
        bytes = &bytes[note_size..];
    }
    Ok(())
}

fn align_four(value: usize) -> Result<usize, String> {
    value
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or_else(|| "ELF note alignment overflow".to_owned())
}

fn inspect_xz_dependency_closure(tools: &Tools) -> Result<(), String> {
    let xz = read_exact(&tools.xz, &tools.xz_measurement)?;
    let liblzma = read_exact(&tools.xz_liblzma, &tools.xz_liblzma_measurement)?;
    let xz_dependencies = macho_dependencies(&xz, "xz")?;
    let expected_xz = BTreeSet::from([
        XZ_LIBLZMA_PATH.to_owned(),
        "/usr/lib/libSystem.B.dylib".to_owned(),
    ]);
    if xz_dependencies != expected_xz {
        return Err(format!(
            "pinned xz has an unreviewed dynamic dependency closure: {xz_dependencies:?}"
        ));
    }
    let liblzma_dependencies = macho_dependencies(&liblzma, "xz liblzma")?;
    if liblzma_dependencies != BTreeSet::from(["/usr/lib/libSystem.B.dylib".to_owned()]) {
        return Err(format!(
            "pinned xz liblzma has an unreviewed dynamic dependency closure: {liblzma_dependencies:?}"
        ));
    }
    Ok(())
}

fn macho_dependencies(bytes: &[u8], label: &str) -> Result<BTreeSet<String>, String> {
    const MH_MAGIC_64: u32 = 0xfeed_facf;
    const CPU_TYPE_ARM64: u32 = 0x0100_000c;
    const LC_LOAD_DYLIB: u32 = 0x0c;
    const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
    const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
    const LC_REEXPORT_DYLIB: u32 = 0x8000_001f;
    const LC_LOAD_UPWARD_DYLIB: u32 = 0x8000_0023;
    const LC_RPATH: u32 = 0x8000_001c;
    if bytes.len() < 32 || le_u32(bytes, 0)? != MH_MAGIC_64 || le_u32(bytes, 4)? != CPU_TYPE_ARM64 {
        return Err(format!("{label} is not little-endian Mach-O64 ARM64"));
    }
    let command_count = as_usize(u64::from(le_u32(bytes, 16)?), "Mach-O command count")?;
    let command_bytes = as_usize(u64::from(le_u32(bytes, 20)?), "Mach-O command bytes")?;
    if command_count == 0 || command_count > 4096 || command_bytes > 16 * 1024 * 1024 {
        return Err(format!(
            "{label} has an invalid bounded Mach-O load-command table"
        ));
    }
    checked_slice(bytes, 32, command_bytes, "Mach-O load commands")?;
    let mut dependencies = BTreeSet::new();
    let mut offset = 32_usize;
    for _ in 0..command_count {
        let command = le_u32(bytes, offset)?;
        let command_size = as_usize(u64::from(le_u32(bytes, offset + 4)?), "Mach-O command size")?;
        if command_size < 8 || command_size % 4 != 0 {
            return Err(format!("{label} has a malformed Mach-O load command"));
        }
        let command_bytes = checked_slice(bytes, offset, command_size, "Mach-O load command")?;
        if command == LC_RPATH {
            return Err(format!("{label} contains a forbidden LC_RPATH"));
        }
        if matches!(
            command,
            LC_LOAD_DYLIB
                | LC_LOAD_WEAK_DYLIB
                | LC_LAZY_LOAD_DYLIB
                | LC_REEXPORT_DYLIB
                | LC_LOAD_UPWARD_DYLIB
        ) {
            if command_size < 24 {
                return Err(format!("{label} has a truncated dylib load command"));
            }
            let name_offset = as_usize(
                u64::from(le_u32(command_bytes, 8)?),
                "Mach-O dylib name offset",
            )?;
            if name_offset < 24 || name_offset >= command_bytes.len() {
                return Err(format!("{label} has an escaping dylib name"));
            }
            let tail = &command_bytes[name_offset..];
            let end = tail
                .iter()
                .position(|byte| *byte == 0)
                .ok_or_else(|| format!("{label} has an unterminated dylib name"))?;
            let dependency = std::str::from_utf8(&tail[..end])
                .map_err(|_| format!("{label} dylib name is not UTF-8"))?;
            if !dependency.starts_with('/')
                || dependency.contains("..")
                || dependency.chars().any(char::is_control)
                || !dependencies.insert(dependency.to_owned())
            {
                return Err(format!(
                    "{label} has a noncanonical or duplicate dylib dependency"
                ));
            }
        }
        offset = offset
            .checked_add(command_size)
            .ok_or_else(|| "Mach-O command offset overflow".to_owned())?;
    }
    if offset != 32 + command_bytes {
        return Err(format!(
            "{label} load commands do not consume sizeofcmds exactly"
        ));
    }
    Ok(dependencies)
}

fn section(bytes: &[u8], table: usize, size: usize, index: usize) -> Result<&[u8], String> {
    let offset = table
        .checked_add(
            index
                .checked_mul(size)
                .ok_or_else(|| "section offset overflow".to_owned())?,
        )
        .ok_or_else(|| "section offset overflow".to_owned())?;
    let file_offset = as_usize(le_u64(bytes, offset + 24)?, "section file offset")?;
    let file_size = as_usize(le_u64(bytes, offset + 32)?, "section file size")?;
    checked_slice(bytes, file_offset, file_size, "ELF section")
}

fn elf_string(strings: &[u8], offset: usize) -> Result<&str, String> {
    if offset >= strings.len() {
        return Err("ELF section name escapes string table".to_owned());
    }
    let tail = &strings[offset..];
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| "unterminated ELF section name".to_owned())?;
    std::str::from_utf8(&tail[..end]).map_err(|_| "ELF section name is not UTF-8".to_owned())
}

fn checked_table(
    bytes: &[u8],
    offset: usize,
    size: usize,
    count: usize,
    label: &str,
) -> Result<(), String> {
    let length = size
        .checked_mul(count)
        .ok_or_else(|| format!("{label} length overflow"))?;
    checked_slice(bytes, offset, length, label).map(|_| ())
}

fn checked_slice<'a>(
    bytes: &'a [u8],
    offset: usize,
    length: usize,
    label: &str,
) -> Result<&'a [u8], String> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| format!("{label} range overflow"))?;
    bytes
        .get(offset..end)
        .ok_or_else(|| format!("{label} escapes ELF file"))
}

fn le_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    let raw: [u8; 2] = checked_slice(bytes, offset, 2, "ELF u16")?
        .try_into()
        .map_err(|_| "ELF u16 width".to_owned())?;
    Ok(u16::from_le_bytes(raw))
}

fn le_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let raw: [u8; 4] = checked_slice(bytes, offset, 4, "ELF u32")?
        .try_into()
        .map_err(|_| "ELF u32 width".to_owned())?;
    Ok(u32::from_le_bytes(raw))
}

fn le_u64(bytes: &[u8], offset: usize) -> Result<u64, String> {
    let raw: [u8; 8] = checked_slice(bytes, offset, 8, "ELF u64")?
        .try_into()
        .map_err(|_| "ELF u64 width".to_owned())?;
    Ok(u64::from_le_bytes(raw))
}

fn as_usize(value: u64, label: &str) -> Result<usize, String> {
    usize::try_from(value).map_err(|_| format!("{label} does not fit host allocation"))
}

fn parse_lock(bytes: &[u8]) -> Result<Lock, String> {
    let fields = canonical_assignments(bytes, "Linux-engine lock")?;
    if fields.len() != 37 || parse_u64(required(&fields, "schema")?, "schema")? != 1 {
        return Err("Linux-engine lock has an unsupported schema or fields".to_owned());
    }
    let lock = Lock {
        channel: string_field(&fields, "channel")?,
        host: string_field(&fields, "host")?,
        target: string_field(&fields, "target")?,
        release_date: string_field(&fields, "release_date")?,
        release_version: string_field(&fields, "release_version")?,
        release_manifest_sha256: digest_field(&fields, "release_manifest_sha256")?,
        release_manifest_bytes: positive_field(&fields, "release_manifest_bytes")?,
        target_archive_url: string_field(&fields, "target_archive_url")?,
        target_archive_sha256: digest_field(&fields, "target_archive_sha256")?,
        target_archive_bytes: positive_field(&fields, "target_archive_bytes")?,
        target_tree_sha256: digest_field(&fields, "target_tree_sha256")?,
        target_files: positive_field(&fields, "target_files")?,
        target_bytes: positive_field(&fields, "target_bytes")?,
        rust_output_sha256: digest_field(&fields, "rust_output_sha256")?,
        cargo_output_sha256: digest_field(&fields, "cargo_output_sha256")?,
        cargo_lock_sha256: digest_field(&fields, "cargo_lock_sha256")?,
        cargo_vendor_tree_sha256: digest_field(&fields, "cargo_vendor_tree_sha256")?,
        cargo_vendor_files: positive_field(&fields, "cargo_vendor_files")?,
        cargo_vendor_bytes: positive_field(&fields, "cargo_vendor_bytes")?,
        cargo_sha256: digest_field(&fields, "cargo_sha256")?,
        cargo_bytes: positive_field(&fields, "cargo_bytes")?,
        rustc_sha256: digest_field(&fields, "rustc_sha256")?,
        rustc_bytes: positive_field(&fields, "rustc_bytes")?,
        rustdoc_sha256: digest_field(&fields, "rustdoc_sha256")?,
        rustdoc_bytes: positive_field(&fields, "rustdoc_bytes")?,
        rust_sysroot_tree_sha256: digest_field(&fields, "rust_sysroot_tree_sha256")?,
        rust_sysroot_files: positive_field(&fields, "rust_sysroot_files")?,
        rust_sysroot_bytes: positive_field(&fields, "rust_sysroot_bytes")?,
        rust_lld_sha256: digest_field(&fields, "rust_lld_sha256")?,
        rust_lld_bytes: positive_field(&fields, "rust_lld_bytes")?,
        xz_sha256: digest_field(&fields, "xz_sha256")?,
        xz_bytes: positive_field(&fields, "xz_bytes")?,
        xz_liblzma_sha256: digest_field(&fields, "xz_liblzma_sha256")?,
        xz_liblzma_bytes: positive_field(&fields, "xz_liblzma_bytes")?,
        package: string_field(&fields, "package")?,
        profile: string_field(&fields, "profile")?,
    };
    if encode_lock(&lock).as_bytes() != bytes {
        return Err("Linux-engine lock is not canonically encoded".to_owned());
    }
    Ok(lock)
}

fn encode_lock(lock: &Lock) -> String {
    format!(
        "schema = 1\nchannel = {}\nhost = {}\ntarget = {}\nrelease_date = {}\nrelease_version = {}\nrelease_manifest_sha256 = {}\nrelease_manifest_bytes = {}\ntarget_archive_url = {}\ntarget_archive_sha256 = {}\ntarget_archive_bytes = {}\ntarget_tree_sha256 = {}\ntarget_files = {}\ntarget_bytes = {}\nrust_output_sha256 = {}\ncargo_output_sha256 = {}\ncargo_lock_sha256 = {}\ncargo_vendor_tree_sha256 = {}\ncargo_vendor_files = {}\ncargo_vendor_bytes = {}\ncargo_sha256 = {}\ncargo_bytes = {}\nrustc_sha256 = {}\nrustc_bytes = {}\nrustdoc_sha256 = {}\nrustdoc_bytes = {}\nrust_sysroot_tree_sha256 = {}\nrust_sysroot_files = {}\nrust_sysroot_bytes = {}\nrust_lld_sha256 = {}\nrust_lld_bytes = {}\nxz_sha256 = {}\nxz_bytes = {}\nxz_liblzma_sha256 = {}\nxz_liblzma_bytes = {}\npackage = {}\nprofile = {}\n",
        toml_string(&lock.channel),
        toml_string(&lock.host),
        toml_string(&lock.target),
        toml_string(&lock.release_date),
        toml_string(&lock.release_version),
        toml_string(&lock.release_manifest_sha256),
        lock.release_manifest_bytes,
        toml_string(&lock.target_archive_url),
        toml_string(&lock.target_archive_sha256),
        lock.target_archive_bytes,
        toml_string(&lock.target_tree_sha256),
        lock.target_files,
        lock.target_bytes,
        toml_string(&lock.rust_output_sha256),
        toml_string(&lock.cargo_output_sha256),
        toml_string(&lock.cargo_lock_sha256),
        toml_string(&lock.cargo_vendor_tree_sha256),
        lock.cargo_vendor_files,
        lock.cargo_vendor_bytes,
        toml_string(&lock.cargo_sha256),
        lock.cargo_bytes,
        toml_string(&lock.rustc_sha256),
        lock.rustc_bytes,
        toml_string(&lock.rustdoc_sha256),
        lock.rustdoc_bytes,
        toml_string(&lock.rust_sysroot_tree_sha256),
        lock.rust_sysroot_files,
        lock.rust_sysroot_bytes,
        toml_string(&lock.rust_lld_sha256),
        lock.rust_lld_bytes,
        toml_string(&lock.xz_sha256),
        lock.xz_bytes,
        toml_string(&lock.xz_liblzma_sha256),
        lock.xz_liblzma_bytes,
        toml_string(&lock.package),
        toml_string(&lock.profile)
    )
}

fn validate_lock_constants(lock: &Lock) -> Result<(), String> {
    if lock.channel != CHANNEL
        || lock.host != HOST
        || lock.target != TARGET
        || lock.package != PACKAGE
        || lock.profile != PROFILE
        || lock.release_date != "2026-04-16"
        || lock.release_version != "1.95.0 (59807616e 2026-04-14)"
        || lock.target_archive_url
            != "https://static.rust-lang.org/dist/2026-04-16/rust-std-1.95.0-aarch64-unknown-linux-musl.tar.xz"
    {
        return Err("Linux-engine lock changes the reviewed Rust/target/build contract".to_owned());
    }
    Ok(())
}

fn parse_output(bytes: &[u8]) -> Result<Output, String> {
    let fields = canonical_assignments(bytes, "Linux-engine output")?;
    if fields.len() != 14 || parse_u64(required(&fields, "schema")?, "schema")? != 1 {
        return Err("Linux-engine output has an unsupported schema or fields".to_owned());
    }
    let execution = required(&fields, "execution_proven")?;
    let output = Output {
        input_sha256: digest_field(&fields, "input_sha256")?,
        source_tree_sha256: digest_field(&fields, "source_tree_sha256")?,
        source_files: positive_field(&fields, "source_files")?,
        source_bytes: positive_field(&fields, "source_bytes")?,
        target_tree_sha256: digest_field(&fields, "target_tree_sha256")?,
        target_files: positive_field(&fields, "target_files")?,
        target_bytes: positive_field(&fields, "target_bytes")?,
        binary_sha256: digest_field(&fields, "binary_sha256")?,
        binary_bytes: positive_field(&fields, "binary_bytes")?,
        receipt_sha256: digest_field(&fields, "receipt_sha256")?,
        receipt_bytes: positive_field(&fields, "receipt_bytes")?,
        artifact_path: string_field(&fields, "artifact_path")?,
        execution_proven: match execution {
            "false" => false,
            "true" => true,
            _ => return Err("execution_proven is not a canonical boolean".to_owned()),
        },
    };
    if encode_output(&output).as_bytes() != bytes {
        return Err("Linux-engine output is not canonically encoded".to_owned());
    }
    Ok(output)
}

fn encode_output(output: &Output) -> String {
    format!(
        "schema = 1\ninput_sha256 = {}\nsource_tree_sha256 = {}\nsource_files = {}\nsource_bytes = {}\ntarget_tree_sha256 = {}\ntarget_files = {}\ntarget_bytes = {}\nbinary_sha256 = {}\nbinary_bytes = {}\nreceipt_sha256 = {}\nreceipt_bytes = {}\nartifact_path = {}\nexecution_proven = {}\n",
        toml_string(&output.input_sha256),
        toml_string(&output.source_tree_sha256),
        output.source_files,
        output.source_bytes,
        toml_string(&output.target_tree_sha256),
        output.target_files,
        output.target_bytes,
        toml_string(&output.binary_sha256),
        output.binary_bytes,
        toml_string(&output.receipt_sha256),
        output.receipt_bytes,
        toml_string(&output.artifact_path),
        output.execution_proven
    )
}

fn read_optional_output(path: &Path) -> Result<Option<(FileMeasurement, Output)>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let measurement = measure_file(path, MAX_LOCK_BYTES, false, false)?;
    let output = parse_output(&read_exact(path, &measurement)?)?;
    Ok(Some((measurement, output)))
}

fn encode_receipt(
    plan: &Plan,
    target: &TreeMeasurement,
    binary: &FileMeasurement,
    artifact_path: &str,
) -> String {
    format!(
        "schema = 2\ninput_sha256 = {}\ntarget = {}\npackage = {}\nprofile = {}\nsource_tree_sha256 = {}\nsource_files = {}\nsource_bytes = {}\ncargo_vendor_tree_sha256 = {}\ncargo_vendor_files = {}\ncargo_vendor_bytes = {}\ntarget_archive_sha256 = {}\ntarget_archive_bytes = {}\ntarget_tree_sha256 = {}\ntarget_files = {}\ntarget_bytes = {}\nrust_sysroot_tree_sha256 = {}\nrust_sysroot_files = {}\nrust_sysroot_bytes = {}\ncargo_sha256 = {}\nrustc_sha256 = {}\nrustdoc_sha256 = {}\nrust_lld_sha256 = {}\nxz_sha256 = {}\nxz_liblzma_sha256 = {}\ndarwin_bootstrap_receipt_sha256 = {}\nbinary_sha256 = {}\nbinary_bytes = {}\nartifact_path = {}\nreproducible_lanes = 2\nexecution_proven = false\n",
        toml_string(&plan.input_sha256),
        toml_string(TARGET),
        toml_string(PACKAGE),
        toml_string(PROFILE),
        toml_string(&plan.source_tree.sha256),
        plan.source_tree.files,
        plan.source_tree.bytes,
        toml_string(&plan.vendor_tree.sha256),
        plan.vendor_tree.files,
        plan.vendor_tree.bytes,
        toml_string(&plan.archive_measurement.sha256),
        plan.archive_measurement.bytes,
        toml_string(&target.sha256),
        target.files,
        target.bytes,
        toml_string(&plan.tools.sysroot_tree.sha256),
        plan.tools.sysroot_tree.files,
        plan.tools.sysroot_tree.bytes,
        toml_string(&plan.tools.cargo_measurement.sha256),
        toml_string(&plan.tools.rustc_measurement.sha256),
        toml_string(&plan.tools.rustdoc_measurement.sha256),
        toml_string(&plan.tools.rust_lld_measurement.sha256),
        toml_string(&plan.tools.xz_measurement.sha256),
        toml_string(&plan.tools.xz_liblzma_measurement.sha256),
        toml_string(&plan.tools.native_receipt_measurement.sha256),
        toml_string(&binary.sha256),
        binary.bytes,
        toml_string(artifact_path)
    )
}

fn validate_rust_output(bytes: &[u8], lock: &Lock) -> Result<(), String> {
    let fields = canonical_assignments(bytes, "Rust output")?;
    for (key, expected) in [
        ("channel", lock.channel.as_str()),
        ("host", lock.host.as_str()),
        ("cargo_sha256", lock.cargo_sha256.as_str()),
        ("rustc_sha256", lock.rustc_sha256.as_str()),
    ] {
        if string_field(&fields, key)? != expected {
            return Err(format!("Rust output {key} differs from Linux-engine lock"));
        }
    }
    if positive_field(&fields, "cargo_bytes")? != lock.cargo_bytes
        || positive_field(&fields, "rustc_bytes")? != lock.rustc_bytes
        || string_field(&fields, "sysroot_tree_sha256")? != lock.rust_sysroot_tree_sha256
        || positive_field(&fields, "sysroot_files")? != lock.rust_sysroot_files
        || positive_field(&fields, "sysroot_bytes")? != lock.rust_sysroot_bytes
    {
        return Err("Rust output tools or sysroot differ from Linux-engine lock".to_owned());
    }
    Ok(())
}

fn validate_cargo_output(bytes: &[u8], lock: &Lock) -> Result<(), String> {
    let fields = canonical_assignments(bytes, "Cargo output")?;
    if string_field(&fields, "cargo_lock_sha256")? != lock.cargo_lock_sha256
        || string_field(&fields, "cargo_sha256")? != lock.cargo_sha256
        || string_field(&fields, "vendor_tree_sha256")? != lock.cargo_vendor_tree_sha256
        || positive_field(&fields, "vendor_files")? != lock.cargo_vendor_files
        || positive_field(&fields, "vendor_bytes")? != lock.cargo_vendor_bytes
    {
        return Err("Cargo output differs from the Linux-engine exact closure".to_owned());
    }
    Ok(())
}

fn validate_release_manifest(bytes: &[u8], lock: &Lock) -> Result<(), String> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| "Rust release manifest is not UTF-8".to_owned())?;
    for required in [
        format!("date = {}", toml_string(&lock.release_date)),
        format!("version = {}", toml_string(&lock.release_version)),
        format!("[pkg.rust-std.target.{}]", lock.target),
        format!("xz_url = {}", toml_string(&lock.target_archive_url)),
        format!("xz_hash = {}", toml_string(&lock.target_archive_sha256)),
    ] {
        if !text.contains(&required) {
            return Err(format!(
                "Rust release manifest lacks reviewed field {required:?}"
            ));
        }
    }
    Ok(())
}

fn canonical_assignments(bytes: &[u8], label: &str) -> Result<BTreeMap<String, String>, String> {
    let text = std::str::from_utf8(bytes).map_err(|_| format!("{label} is not UTF-8"))?;
    if text.is_empty() || !text.ends_with('\n') || text.contains('\r') || text.contains('\0') {
        return Err(format!("{label} is not canonical newline-delimited text"));
    }
    let mut fields = BTreeMap::new();
    for (index, line) in text.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
            return Err(format!(
                "{label} line {} is not a flat assignment",
                index + 1
            ));
        }
        let (key, value) = line
            .split_once(" = ")
            .ok_or_else(|| format!("{label} line {} lacks canonical separator", index + 1))?;
        let mut key_bytes = key.bytes();
        if !key_bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
            || !key_bytes
                .all(|byte| byte == b'_' || byte.is_ascii_lowercase() || byte.is_ascii_digit())
            || value.is_empty()
            || fields.insert(key.to_owned(), value.to_owned()).is_some()
        {
            return Err(format!(
                "{label} line {} has an invalid or duplicate field",
                index + 1
            ));
        }
    }
    Ok(fields)
}

fn required<'a>(fields: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, String> {
    fields
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("missing field {key}"))
}

fn string_field(fields: &BTreeMap<String, String>, key: &str) -> Result<String, String> {
    parse_string(required(fields, key)?, key)
}

fn digest_field(fields: &BTreeMap<String, String>, key: &str) -> Result<String, String> {
    let value = string_field(fields, key)?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(format!("{key} is not lowercase SHA-256"));
    }
    Ok(value)
}

fn positive_field(fields: &BTreeMap<String, String>, key: &str) -> Result<u64, String> {
    let value = parse_u64(required(fields, key)?, key)?;
    if value == 0 {
        return Err(format!("{key} must be positive"));
    }
    Ok(value)
}

fn parse_string(value: &str, label: &str) -> Result<String, String> {
    if value.len() < 2 || !value.starts_with('"') || !value.ends_with('"') {
        return Err(format!("{label} is not a canonical string"));
    }
    let inner = &value[1..value.len() - 1];
    if inner.is_empty()
        || inner.contains('"')
        || inner.contains('\\')
        || inner.chars().any(char::is_control)
    {
        return Err(format!("{label} has forbidden string content"));
    }
    Ok(inner.to_owned())
}

fn parse_u64(value: &str, label: &str) -> Result<u64, String> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(format!("{label} is not a canonical unsigned integer"));
    }
    value.parse().map_err(|_| format!("{label} overflows u64"))
}

fn toml_string(value: &str) -> String {
    format!("\"{value}\"")
}

fn input_digest(
    files: [&FileMeasurement; 6],
    vendor: &TreeMeasurement,
    source: &TreeMeasurement,
    tools: &Tools,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"WRELA-LINUX-ENGINE-INPUT\0\x01");
    for file in files {
        digest.update(file.sha256.as_bytes());
        digest.update([0]);
    }
    for value in [
        &vendor.sha256,
        &source.sha256,
        &tools.cargo_measurement.sha256,
        &tools.rustc_measurement.sha256,
        &tools.rustdoc_measurement.sha256,
        &tools.rust_lld_measurement.sha256,
        &tools.xz_measurement.sha256,
        &tools.xz_liblzma_measurement.sha256,
        &tools.sysroot_tree.sha256,
        &tools.native_receipt_measurement.sha256,
    ] {
        digest.update(value.as_bytes());
        digest.update([0]);
    }
    lower_hex(&digest.finalize())
}

fn measure_source_tree(root: &Path) -> Result<TreeMeasurement, String> {
    let mut records = Vec::new();
    for file in ["Cargo.toml", "Cargo.lock", "LICENSE", "rust-toolchain.toml"] {
        add_file_record(root, file, &mut records, false)?;
    }
    for directory in ["crates", "std", "tests", "toolchain/targets", "xtask"] {
        walk_tree(&root.join(directory), directory, 0, &mut records, false)?;
    }
    finish_tree(records, MAX_TREE_FILES, MAX_TREE_BYTES)
}

fn measure_tree(
    root: &Path,
    max_files: u64,
    max_bytes: u64,
    allow_empty: bool,
) -> Result<TreeMeasurement, String> {
    let mut records = Vec::new();
    walk_tree(root, "", 0, &mut records, allow_empty)?;
    finish_tree(records, max_files, max_bytes)
}

fn walk_tree(
    directory: &Path,
    prefix: &str,
    depth: u32,
    records: &mut Vec<FileRecord>,
    allow_empty: bool,
) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err("tree exceeds depth limit".to_owned());
    }
    let metadata = fs::symlink_metadata(directory)
        .map_err(|error| format!("cannot inspect tree {}: {error}", directory.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!(
            "tree entry is not an exact directory: {}",
            directory.display()
        ));
    }
    let mut entries = fs::read_dir(directory)
        .map_err(|error| format!("cannot read tree {}: {error}", directory.display()))?
        .map(|entry| {
            let entry = entry.map_err(|error| format!("cannot read tree entry: {error}"))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "tree name is not UTF-8".to_owned())?;
            if !portable_component(&name) {
                return Err(format!("nonportable tree component {name:?}"));
            }
            Ok((name, entry.path()))
        })
        .collect::<Result<Vec<_>, String>>()?;
    entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    if entries.is_empty() {
        return Err(format!(
            "tree contains empty directory {}",
            directory.display()
        ));
    }
    for (name, path) in entries {
        let relative = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect tree entry: {error}"))?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            walk_tree(&path, &relative, depth + 1, records, allow_empty)?;
        } else if metadata.is_file() && !metadata.file_type().is_symlink() {
            add_file_record_path(&path, relative, records, allow_empty)?;
        } else {
            return Err(format!(
                "tree contains link or special entry {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn add_file_record(
    root: &Path,
    relative: &str,
    records: &mut Vec<FileRecord>,
    allow_empty: bool,
) -> Result<(), String> {
    add_file_record_path(
        &root.join(relative),
        relative.to_owned(),
        records,
        allow_empty,
    )
}

fn add_file_record_path(
    path: &Path,
    relative: String,
    records: &mut Vec<FileRecord>,
    allow_empty: bool,
) -> Result<(), String> {
    if relative.len() > MAX_PATH_BYTES {
        return Err("tree path exceeds limit".to_owned());
    }
    let executable = is_executable(path)?;
    let measured = measure_file(path, MAX_FILE_BYTES, executable, allow_empty)?;
    records.push(FileRecord {
        path: relative,
        bytes: measured.bytes,
        sha256: measured.sha256,
        executable,
    });
    Ok(())
}

fn finish_tree(
    mut records: Vec<FileRecord>,
    max_files: u64,
    max_bytes: u64,
) -> Result<TreeMeasurement, String> {
    records.sort_unstable_by(|left, right| left.path.cmp(&right.path));
    if records.is_empty() || records.windows(2).any(|pair| pair[0].path >= pair[1].path) {
        return Err("tree is empty, duplicated, or unordered".to_owned());
    }
    let files = u64::try_from(records.len()).map_err(|_| "tree file count overflow".to_owned())?;
    let bytes = records.iter().try_fold(0_u64, |sum, record| {
        sum.checked_add(record.bytes)
            .ok_or_else(|| "tree byte count overflow".to_owned())
    })?;
    if files > max_files || bytes == 0 || bytes > max_bytes {
        return Err("tree exceeds exact file/byte limit".to_owned());
    }
    let mut digest = Sha256::new();
    digest.update(RELEASE_TREE_MAGIC);
    digest.update(RELEASE_TREE_VERSION.to_le_bytes());
    digest.update(files.to_le_bytes());
    for record in &records {
        let length =
            u64::try_from(record.path.len()).map_err(|_| "tree path length overflow".to_owned())?;
        digest.update(length.to_le_bytes());
        digest.update(record.path.as_bytes());
        digest.update(record.bytes.to_le_bytes());
        digest.update([u8::from(record.executable)]);
        digest.update(hex_bytes(&record.sha256)?);
    }
    Ok(TreeMeasurement {
        sha256: lower_hex(&digest.finalize()),
        files,
        bytes,
        records,
    })
}

fn copy_measured_tree(
    source: &Path,
    destination: &Path,
    tree: &TreeMeasurement,
    cancellation: &Cancellation,
) -> Result<(), String> {
    for record in &tree.records {
        cancellation.check("authenticated tree copy")?;
        copy_file(
            &source.join(&record.path),
            &destination.join(&record.path),
            &FileMeasurement {
                sha256: record.sha256.clone(),
                bytes: record.bytes,
            },
            record.executable,
            cancellation,
        )?;
    }
    if measure_tree(destination, MAX_TREE_FILES, MAX_TREE_BYTES, true)? != *tree {
        return Err("copied producer tree differs from frozen input".to_owned());
    }
    Ok(())
}

fn copy_file(
    source: &Path,
    destination: &Path,
    expected: &FileMeasurement,
    executable: bool,
    cancellation: &Cancellation,
) -> Result<(), String> {
    if measure_file(source, MAX_FILE_BYTES, executable, true)? != *expected {
        return Err("copy source changed".to_owned());
    }
    let parent = destination
        .parent()
        .ok_or_else(|| "copy destination has no parent".to_owned())?;
    ensure_directory(parent)?;
    let mut input =
        File::open(source).map_err(|error| format!("cannot open copy source: {error}"))?;
    let mut output = new_file(destination)?;
    let mut remaining = expected.bytes;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining != 0 {
        cancellation.check("authenticated file copy")?;
        let wanted = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| "copy byte count does not fit host".to_owned())?;
        let read = input
            .read(&mut buffer[..wanted])
            .map_err(|error| format!("cannot read authenticated copy source: {error}"))?;
        if read == 0 {
            return Err("authenticated copy source truncated".to_owned());
        }
        output
            .write_all(&buffer[..read])
            .map_err(|error| format!("cannot copy authenticated file: {error}"))?;
        remaining -= read as u64;
    }
    output
        .sync_all()
        .map_err(|error| format!("cannot sync copied file: {error}"))?;
    drop(output);
    set_file_mode(destination, if executable { 0o700 } else { 0o600 })?;
    if measure_file(destination, MAX_FILE_BYTES, executable, true)? != *expected {
        return Err("copy destination differs".to_owned());
    }
    Ok(())
}

fn measure_file(
    path: &Path,
    maximum: u64,
    executable: bool,
    allow_empty: bool,
) -> Result<FileMeasurement, String> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if !before.is_file()
        || before.file_type().is_symlink()
        || (!allow_empty && before.len() == 0)
        || before.len() > maximum
    {
        return Err(format!(
            "{} is not an exact bounded regular file",
            path.display()
        ));
    }
    if is_executable_metadata(&before) != executable {
        return Err(format!("{} has unexpected executable mode", path.display()));
    }
    let mut input =
        File::open(path).map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    let mut digest = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| "file length overflow".to_owned())?;
        if total > maximum {
            return Err(format!("{} exceeds byte limit", path.display()));
        }
        digest.update(&buffer[..read]);
    }
    let after = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot re-inspect {}: {error}", path.display()))?;
    if before.len() != total
        || before.modified().ok() != after.modified().ok()
        || before.len() != after.len()
    {
        return Err(format!("{} changed while measured", path.display()));
    }
    Ok(FileMeasurement {
        sha256: lower_hex(&digest.finalize()),
        bytes: total,
    })
}

fn measure_private_file(
    path: &Path,
    maximum: u64,
    executable: bool,
    allow_empty: bool,
    expected_mode: u32,
) -> Result<FileMeasurement, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let before = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect private file {}: {error}", path.display()))?;
        if before.mode() & 0o7777 != expected_mode || before.nlink() != 1 {
            return Err(format!(
                "{} does not have exact mode {expected_mode:o} and one link",
                path.display()
            ));
        }
        let measured = measure_file(path, maximum, executable, allow_empty)?;
        let after = fs::symlink_metadata(path).map_err(|error| {
            format!("cannot re-inspect private file {}: {error}", path.display())
        })?;
        if before.dev() != after.dev()
            || before.ino() != after.ino()
            || before.mode() != after.mode()
            || before.nlink() != after.nlink()
            || before.len() != after.len()
            || before.modified().ok() != after.modified().ok()
        {
            return Err(format!(
                "{} changed identity or policy while measured",
                path.display()
            ));
        }
        Ok(measured)
    }
    #[cfg(not(unix))]
    {
        let _ = (path, maximum, executable, allow_empty, expected_mode);
        Err("private Linux-engine artifacts require Unix metadata authority".to_owned())
    }
}

fn validate_private_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    let path = exact_directory(path, label)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect {label}: {error}"))?;
        if metadata.mode() & 0o7777 != 0o700 {
            return Err(format!("{label} does not have exact private mode 700"));
        }
    }
    #[cfg(not(unix))]
    {
        return Err(format!("{label} requires Unix metadata authority"));
    }
    Ok(path)
}

fn read_exact(path: &Path, measurement: &FileMeasurement) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|error| format!("cannot open {}: {error}", path.display()))?
        .take(measurement.bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if bytes.len() as u64 != measurement.bytes || sha256_bytes(&bytes) != measurement.sha256 {
        return Err(format!(
            "{} changed between measurement and read",
            path.display()
        ));
    }
    Ok(bytes)
}

fn exact_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    let canonical = fs::canonicalize(path)
        .map_err(|error| format!("cannot canonicalize {label} {}: {error}", path.display()))?;
    if canonical != path
        || !fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect {label}: {error}"))?
            .is_dir()
    {
        return Err(format!("{label} is not a canonical exact directory"));
    }
    Ok(canonical)
}

fn exact_file(path: &Path, label: &str) -> Result<PathBuf, String> {
    let canonical = fs::canonicalize(path)
        .map_err(|error| format!("cannot canonicalize {label} {}: {error}", path.display()))?;
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("cannot inspect {label}: {error}"))?;
    if canonical != path
        || !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
    {
        return Err(format!("{label} is not a canonical nonempty regular file"));
    }
    Ok(canonical)
}

fn ensure_directory(path: &Path) -> Result<(), String> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect directory: {error}"))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(format!(
                "directory path is a link or special entry: {}",
                path.display()
            ));
        }
        return Ok(());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "directory has no parent".to_owned())?;
    if !parent.exists() {
        ensure_directory(parent)?;
    }
    fs::create_dir(path)
        .map_err(|error| format!("cannot create directory {}: {error}", path.display()))?;
    set_directory_mode(path, 0o700)
}

fn new_file(path: &Path) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))
}

fn write_new(path: &Path, bytes: &[u8], executable: bool) -> Result<(), String> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_FILE_BYTES {
        return Err("refusing empty or oversized output".to_owned());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "output has no parent".to_owned())?;
    ensure_directory(parent)?;
    let mut file = new_file(path)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    drop(file);
    set_file_mode(path, if executable { 0o700 } else { 0o600 })
}

#[cfg(unix)]
fn set_file_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| format!("cannot set file mode: {error}"))
}

#[cfg(not(unix))]
fn set_file_mode(_path: &Path, _mode: u32) -> Result<(), String> {
    Err("Linux-engine producer requires Unix file modes".to_owned())
}

#[cfg(unix)]
fn set_directory_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| format!("cannot set directory mode: {error}"))
}

#[cfg(not(unix))]
fn set_directory_mode(_path: &Path, _mode: u32) -> Result<(), String> {
    Err("Linux-engine producer requires Unix directory modes".to_owned())
}

#[cfg(unix)]
fn is_executable(path: &Path) -> Result<bool, String> {
    Ok(is_executable_metadata(
        &fs::symlink_metadata(path).map_err(|error| format!("cannot inspect mode: {error}"))?,
    ))
}

#[cfg(not(unix))]
fn is_executable(_path: &Path) -> Result<bool, String> {
    Err("Linux-engine producer requires Unix modes".to_owned())
}

#[cfg(unix)]
fn is_executable_metadata(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable_metadata(_metadata: &fs::Metadata) -> bool {
    false
}

fn make_tree_writable(root: &Path) -> Result<(), String> {
    if !root.exists() {
        return Ok(());
    }
    for entry in
        fs::read_dir(root).map_err(|error| format!("cannot enumerate cleanup tree: {error}"))?
    {
        let path = entry
            .map_err(|error| format!("cannot read cleanup entry: {error}"))?
            .path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect cleanup entry: {error}"))?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            make_tree_writable(&path)?;
        } else if metadata.is_file() {
            set_file_mode(&path, 0o600)?;
        }
    }
    set_directory_mode(root, 0o700)
}

fn sync_tree(root: &Path) -> Result<(), String> {
    for entry in
        fs::read_dir(root).map_err(|error| format!("cannot enumerate sync tree: {error}"))?
    {
        let path = entry
            .map_err(|error| format!("cannot read sync entry: {error}"))?
            .path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect sync entry: {error}"))?;
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            sync_tree(&path)?;
        } else if metadata.is_file() {
            File::open(&path)
                .and_then(|file| file.sync_all())
                .map_err(|error| format!("cannot sync file: {error}"))?;
        }
    }
    sync_directory(root)
}

fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| format!("cannot sync directory {}: {error}", path.display()))
}

fn bounded_relative_files(root: &Path, max_depth: u32) -> Result<Vec<String>, String> {
    fn walk(
        root: &Path,
        directory: &Path,
        prefix: &str,
        depth: u32,
        max_depth: u32,
        out: &mut Vec<String>,
    ) -> Result<(), String> {
        if depth > max_depth {
            return Err("bundle exceeds depth limit".to_owned());
        }
        for entry in
            fs::read_dir(directory).map_err(|error| format!("cannot read bundle: {error}"))?
        {
            let entry = entry.map_err(|error| format!("cannot read bundle entry: {error}"))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "bundle name is not UTF-8".to_owned())?;
            let relative = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|error| format!("cannot inspect bundle: {error}"))?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                walk(root, &entry.path(), &relative, depth + 1, max_depth, out)?;
            } else if metadata.is_file() && !metadata.file_type().is_symlink() {
                out.push(relative);
            } else {
                return Err("bundle contains link or special entry".to_owned());
            }
        }
        let _ = root;
        Ok(())
    }
    let mut files = Vec::new();
    walk(root, root, "", 0, max_depth, &mut files)?;
    files.sort();
    Ok(files)
}

fn read_tar_block(reader: &mut impl Read) -> Result<Option<[u8; 512]>, String> {
    let mut block = [0_u8; 512];
    let mut read_total = 0;
    while read_total < block.len() {
        let read = reader
            .read(&mut block[read_total..])
            .map_err(|error| format!("cannot read tar header: {error}"))?;
        if read == 0 {
            return if read_total == 0 {
                Ok(None)
            } else {
                Err("truncated tar header".to_owned())
            };
        }
        read_total += read;
    }
    Ok(Some(block))
}

fn validate_tar_checksum(header: &[u8; 512]) -> Result<(), String> {
    let expected = parse_tar_octal(&header[148..156], "checksum")?;
    let actual: u64 = header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                u64::from(b' ')
            } else {
                u64::from(*byte)
            }
        })
        .sum();
    if actual == expected {
        Ok(())
    } else {
        Err("tar checksum mismatch".to_owned())
    }
}

fn parse_tar_octal(field: &[u8], label: &str) -> Result<u64, String> {
    if field.first().is_some_and(|byte| byte & 0x80 != 0) {
        return Err(format!("base-256 tar {label} is forbidden"));
    }
    let mut value = 0_u64;
    let mut saw_digit = false;
    let mut terminated = false;
    for byte in field.iter().copied() {
        match byte {
            b'0'..=b'7' if !terminated => {
                saw_digit = true;
                value = value
                    .checked_mul(8)
                    .and_then(|value| value.checked_add(u64::from(byte - b'0')))
                    .ok_or_else(|| format!("tar {label} overflow"))?;
            }
            b' ' if !saw_digit => {}
            0 | b' ' => terminated = true,
            _ => return Err(format!("invalid or noncanonical tar {label}")),
        }
    }
    Ok(value)
}

fn canonical_gnu_long_name_header(header: &[u8; 512]) -> bool {
    const NAME: &[u8] = b"././@LongLink";
    header[..NAME.len()] == *NAME
        && header[NAME.len()..100].iter().all(|byte| *byte == 0)
        && header[345..500].iter().all(|byte| *byte == 0)
}

fn tar_path(header: &[u8; 512]) -> Result<String, String> {
    let name = tar_text(&header[..100], "name")?;
    let prefix = tar_text(&header[345..500], "prefix")?;
    if name.is_empty() {
        return Err("tar path is empty".to_owned());
    }
    Ok(if prefix.is_empty() {
        name.to_owned()
    } else {
        format!("{prefix}/{name}")
    })
}

fn tar_text<'a>(field: &'a [u8], label: &str) -> Result<&'a str, String> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    if field[end..].iter().any(|byte| *byte != 0) {
        return Err(format!("tar {label} contains bytes after its terminator"));
    }
    let value =
        std::str::from_utf8(&field[..end]).map_err(|_| format!("tar {label} is not UTF-8"))?;
    if value.chars().any(char::is_control) {
        return Err(format!("tar {label} contains control"));
    }
    Ok(value)
}

fn validate_archive_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.len() > MAX_PATH_BYTES
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains(':')
        || path.chars().any(char::is_control)
    {
        return Err(format!("unsafe tar path {path:?}"));
    }
    let mut components = path.trim_end_matches('/').split('/');
    if components.next() != Some(TARGET_ARCHIVE_ROOT) {
        return Err("tar has an unexpected root".to_owned());
    }
    if components.any(|component| component.is_empty() || matches!(component, "." | "..")) {
        return Err(format!("unsafe tar path {path:?}"));
    }
    if Path::new(path)
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("unsafe native tar path {path:?}"));
    }
    Ok(())
}

fn copy_exact(
    reader: &mut impl Read,
    writer: &mut impl Write,
    size: u64,
    cancellation: &Cancellation,
) -> Result<(), String> {
    let mut remaining = size;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining != 0 {
        cancellation.check("Rust target archive member copy")?;
        let wanted = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| "copy size overflow".to_owned())?;
        let read = reader
            .read(&mut buffer[..wanted])
            .map_err(|error| format!("cannot read tar payload: {error}"))?;
        if read == 0 {
            return Err("truncated tar payload".to_owned());
        }
        writer
            .write_all(&buffer[..read])
            .map_err(|error| format!("cannot write tar payload: {error}"))?;
        remaining -= read as u64;
    }
    Ok(())
}

fn skip_exact(
    reader: &mut impl Read,
    size: u64,
    cancellation: &Cancellation,
) -> Result<(), String> {
    copy_exact(reader, &mut std::io::sink(), size, cancellation)
}

fn skip_tar_padding(reader: &mut impl Read, size: u64) -> Result<(), String> {
    let padding = ((512 - size % 512) % 512) as usize;
    let mut bytes = [0_u8; 512];
    reader
        .read_exact(&mut bytes[..padding])
        .map_err(|_| "truncated tar padding".to_owned())?;
    if bytes[..padding].iter().any(|byte| *byte != 0) {
        return Err("nonzero tar padding".to_owned());
    }
    Ok(())
}

fn portable_component(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 255
        || matches!(value, "." | "..")
        || value.ends_with('.')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
    {
        return false;
    }
    let stem = value.split('.').next().unwrap_or(value);
    ![
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ]
    .iter()
    .any(|reserved| stem.eq_ignore_ascii_case(reserved))
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    lower_hex(&digest.finalize())
}

fn engine_bundle_key(input_sha256: &str, binary_sha256: &str) -> String {
    let mut identity = b"WRELBND\0\x01\0\0\0".to_vec();
    identity.extend_from_slice(input_sha256.as_bytes());
    identity.extend_from_slice(binary_sha256.as_bytes());
    sha256_bytes(&identity)
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn hex_bytes(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err("digest length is not 64".to_owned());
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let digit = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            _ => None,
        };
        bytes[index] = digit(pair[0])
            .and_then(|high| digit(pair[1]).map(|low| high << 4 | low))
            .ok_or_else(|| "digest is not lowercase hexadecimal".to_owned())?;
    }
    Ok(bytes)
}

fn bounded_text(bytes: &[u8]) -> String {
    const LIMIT: usize = 64 * 1024;
    let retained = &bytes[..bytes.len().min(LIMIT)];
    let mut text = String::from_utf8_lossy(retained).into_owned();
    if bytes.len() > LIMIT {
        text.push_str("\n...[truncated]");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn options_are_closed_and_modes_are_disjoint() {
        assert_eq!(
            parse_options(&["--plan".into(), "--offline".into()]).unwrap(),
            Options {
                help: false,
                plan: true,
                record_output: false,
                reenroll_cargo: false,
                offline: true
            }
        );
        for invalid in [
            vec!["--plan".into(), "--record-output".into()],
            vec!["--reenroll-cargo".into()],
            vec![
                "--reenroll-cargo".into(),
                "--plan".into(),
                "--offline".into(),
            ],
            vec![
                "--reenroll-cargo".into(),
                "--record-output".into(),
                "--offline".into(),
            ],
            vec!["--offline".into(), "--offline".into()],
            vec!["--jobs".into(), "2".into()],
        ] {
            assert!(parse_options(&invalid).is_err());
        }
        assert!(parse_options(&["--reenroll-cargo".into(), "--offline".into()]).is_ok());
    }

    #[test]
    fn producer_lease_rejects_concurrent_authority_scans_and_cleans_up() {
        let temp = Temp::new("producer-lease");
        let first = ProducerLease::acquire(&temp.path).expect("first producer lease");
        assert!(ProducerLease::acquire(&temp.path).is_err());
        drop(first);
        drop(ProducerLease::acquire(&temp.path).expect("reacquired producer lease"));
        assert!(
            !temp
                .path
                .join("build/toolchain/linux-engine/producer.lock")
                .exists()
        );
    }

    #[test]
    fn cargo_rollover_changes_exactly_enrollment_digests() {
        let old = sample_lock();
        let tree = sample_tree();
        let cargo_output = FileMeasurement {
            sha256: "aa".repeat(32),
            bytes: 6,
        };
        let cargo_lock = FileMeasurement {
            sha256: "bb".repeat(32),
            bytes: 7,
        };
        let cargo = FileMeasurement {
            sha256: old.cargo_sha256.clone(),
            bytes: old.cargo_bytes,
        };
        let authority = CargoAuthority {
            cargo_lock_sha256: cargo_lock.sha256.clone(),
            cargo_sha256: old.cargo_sha256.clone(),
            vendor_tree_sha256: tree.sha256.clone(),
            vendor_files: tree.files,
            vendor_bytes: tree.bytes,
        };
        let new = validate_cargo_rollover(
            &old,
            &cargo_output,
            &cargo_lock,
            &authority,
            &cargo,
            &tree,
            &tree,
        )
        .expect("identity-preserving rollover");
        let mut expected = old;
        expected.cargo_output_sha256 = cargo_output.sha256;
        expected.cargo_lock_sha256 = cargo_lock.sha256;
        assert_eq!(new, expected);
    }

    #[test]
    fn cargo_rollover_rejects_corrupt_stale_noop_and_tree_or_tool_changes() {
        assert!(canonical_cargo_output(b"schema = 1\ncargo_lock_sha256 = nope\n").is_err());
        let old = sample_lock();
        let tree = sample_tree();
        let output = FileMeasurement {
            sha256: "aa".repeat(32),
            bytes: 1,
        };
        let cargo_lock = FileMeasurement {
            sha256: "bb".repeat(32),
            bytes: 1,
        };
        let cargo = FileMeasurement {
            sha256: old.cargo_sha256.clone(),
            bytes: old.cargo_bytes,
        };
        let authority = CargoAuthority {
            cargo_lock_sha256: cargo_lock.sha256.clone(),
            cargo_sha256: old.cargo_sha256.clone(),
            vendor_tree_sha256: tree.sha256.clone(),
            vendor_files: tree.files,
            vendor_bytes: tree.bytes,
        };
        let validate = |output: &FileMeasurement,
                        cargo_lock: &FileMeasurement,
                        authority: &CargoAuthority,
                        cargo: &FileMeasurement,
                        new_tree: &TreeMeasurement| {
            validate_cargo_rollover(&old, output, cargo_lock, authority, cargo, &tree, new_tree)
        };
        assert!(
            validate(
                &FileMeasurement {
                    sha256: old.cargo_output_sha256.clone(),
                    bytes: 1
                },
                &cargo_lock,
                &authority,
                &cargo,
                &tree
            )
            .is_err()
        );
        assert!(
            validate(
                &output,
                &FileMeasurement {
                    sha256: old.cargo_lock_sha256.clone(),
                    bytes: 1
                },
                &authority,
                &cargo,
                &tree
            )
            .is_err()
        );
        let changed_tree = TreeMeasurement {
            sha256: "cc".repeat(32),
            ..tree.clone()
        };
        assert!(validate(&output, &cargo_lock, &authority, &cargo, &changed_tree).is_err());
        let changed_cargo = FileMeasurement {
            sha256: "dd".repeat(32),
            bytes: cargo.bytes,
        };
        assert!(validate(&output, &cargo_lock, &authority, &changed_cargo, &tree).is_err());
        let stale_authority = CargoAuthority {
            cargo_lock_sha256: "ee".repeat(32),
            ..authority
        };
        assert!(validate(&output, &cargo_lock, &stale_authority, &cargo, &tree).is_err());
    }

    #[test]
    fn lock_replacement_is_atomic_canonical_and_rejects_stale_or_partial_state() {
        let temp = Temp::new("lock-rollover");
        fs::create_dir(temp.path.join("toolchain")).unwrap();
        fs::create_dir_all(temp.path.join("build/toolchain/linux-engine")).unwrap();
        let path = temp.path.join(LOCK_PATH);
        let old = sample_lock();
        fs::write(&path, encode_lock(&old)).unwrap();
        let before = measure_file(&path, MAX_LOCK_BYTES, false, false).unwrap();
        let cancellation = Cancellation::for_root(&temp.path);
        let mut new = old.clone();
        new.cargo_output_sha256 = "aa".repeat(32);
        new.cargo_lock_sha256 = "bb".repeat(32);
        atomically_replace_lock(
            &temp.path,
            &cancellation,
            &before,
            encode_lock(&new).as_bytes(),
        )
        .expect("atomic canonical replacement");
        assert_eq!(parse_lock(&fs::read(&path).unwrap()).unwrap(), new);
        assert!(
            atomically_replace_lock(
                &temp.path,
                &cancellation,
                &before,
                encode_lock(&old).as_bytes()
            )
            .is_err()
        );
        let current = measure_file(&path, MAX_LOCK_BYTES, false, false).unwrap();
        fs::write(
            temp.path.join("toolchain/.linux-engine.lock.0.tmp"),
            b"partial",
        )
        .unwrap();
        // A transaction at this process's exact name is rejected without touching the lock.
        let exact_temp = temp.path.join(format!(
            "toolchain/.linux-engine.lock.{}.tmp",
            std::process::id()
        ));
        fs::write(&exact_temp, b"partial").unwrap();
        assert!(
            atomically_replace_lock(
                &temp.path,
                &cancellation,
                &current,
                encode_lock(&old).as_bytes()
            )
            .is_err()
        );
        assert_eq!(
            measure_file(&path, MAX_LOCK_BYTES, false, false).unwrap(),
            current
        );
    }

    #[test]
    fn canonical_assignment_keys_allow_schema_digits_but_reject_invalid_starts_and_case() {
        let fields = canonical_assignments(
            b"schema = 1\ninput_sha256 = \"digest\"\nxz_liblzma_bytes = 1\n",
            "key grammar fixture",
        )
        .expect("canonical lowercase/digit/underscore keys");
        assert_eq!(fields.len(), 3);
        for invalid in [
            b"_leading = 1\n".as_slice(),
            b"1leading = 1\n",
            b"Uppercase = 1\n",
            b"mixed_Case = 1\n",
            b" = 1\n",
        ] {
            assert!(canonical_assignments(invalid, "invalid key fixture").is_err());
        }
    }

    #[test]
    fn checked_in_lock_is_canonical_and_future_or_stale_schema_fails() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let bytes = fs::read(root.join(LOCK_PATH)).expect("read Linux-engine lock");
        assert_eq!(
            canonical_assignments(&bytes, "lock cardinality")
                .expect("lock assignments")
                .len(),
            37
        );
        let lock = parse_lock(&bytes).expect("canonical lock");
        validate_lock_constants(&lock).expect("reviewed constants");
        let mut stale = bytes.clone();
        stale.splice(..10, b"schema = 0".iter().copied());
        assert!(parse_lock(&stale).is_err());
        let future = String::from_utf8(bytes)
            .unwrap()
            .replace("schema = 1", "schema = 2");
        assert!(parse_lock(future.as_bytes()).is_err());
    }

    #[test]
    fn output_receipt_rejects_future_schema_noncanonical_and_execution_claim() {
        let output = sample_output();
        let encoded = encode_output(&output);
        assert_eq!(
            canonical_assignments(encoded.as_bytes(), "output cardinality")
                .expect("output assignments")
                .len(),
            14
        );
        assert_eq!(parse_output(encoded.as_bytes()).unwrap(), output);
        assert!(parse_output(encoded.replace("schema = 1", "schema = 2").as_bytes()).is_err());
        assert!(
            parse_output(
                encoded
                    .replace("binary_bytes = 1", "binary_bytes = 01")
                    .as_bytes()
            )
            .is_err()
        );
        let claimed = encode_output(&Output {
            execution_proven: true,
            ..sample_output()
        });
        assert!(parse_output(claimed.as_bytes()).unwrap().execution_proven);
    }

    #[test]
    fn enrolled_artifact_reuse_is_self_contained_and_receipt_cross_bound() {
        let temp = Temp::new("artifact-reuse");
        let root = fs::canonicalize(&temp.path).expect("canonical fixture root");
        let binary_bytes = minimal_elf(1);
        let binary = FileMeasurement {
            sha256: sha256_bytes(&binary_bytes),
            bytes: binary_bytes.len() as u64,
        };
        let mut output = sample_output();
        output.binary_sha256.clone_from(&binary.sha256);
        output.binary_bytes = binary.bytes;
        let bundle_key = engine_bundle_key(&output.input_sha256, &output.binary_sha256);
        output.artifact_path = format!(
            "build/toolchain/linux-engine/prefixes/{}/bin/wrela-engine",
            bundle_key
        );
        let receipt_bytes = sample_receipt(&output);
        output.receipt_sha256 = sha256_bytes(receipt_bytes.as_bytes());
        output.receipt_bytes = receipt_bytes.len() as u64;

        let bundle = root
            .join("build/toolchain/linux-engine/prefixes")
            .join(&bundle_key);
        fs::create_dir_all(bundle.join("bin")).unwrap();
        fs::create_dir_all(root.join("toolchain")).unwrap();
        set_file_mode(&root.join("build/toolchain/linux-engine/prefixes"), 0o700).unwrap();
        set_file_mode(&bundle, 0o700).unwrap();
        set_file_mode(&bundle.join("bin"), 0o700).unwrap();
        fs::write(bundle.join("bin/wrela-engine"), &binary_bytes).unwrap();
        set_file_mode(&bundle.join("bin/wrela-engine"), 0o700).unwrap();
        fs::write(bundle.join("receipt.toml"), &receipt_bytes).unwrap();
        set_file_mode(&bundle.join("receipt.toml"), 0o600).unwrap();
        fs::write(root.join(OUTPUT_PATH), encode_output(&output)).unwrap();
        set_file_mode(&root.join(OUTPUT_PATH), 0o600).unwrap();

        assert_eq!(
            validate_enrolled_artifact(&root).expect("self-contained artifact reuse"),
            output
        );
        assert!(
            !root.join(LOCK_PATH).exists(),
            "artifact consumption must not require producer authority"
        );

        let changed = receipt_bytes.replace(
            &format!(
                "source_tree_sha256 = {}",
                toml_string(&output.source_tree_sha256)
            ),
            &format!("source_tree_sha256 = {}", toml_string(&"ff".repeat(32))),
        );
        assert!(validate_receipt_for_output(changed.as_bytes(), &output).is_err());
        let reordered = receipt_bytes.replace(
            &format!(
                "target = {}\npackage = {}",
                toml_string(TARGET),
                toml_string(PACKAGE)
            ),
            &format!(
                "package = {}\ntarget = {}",
                toml_string(PACKAGE),
                toml_string(TARGET)
            ),
        );
        assert!(validate_receipt_for_output(reordered.as_bytes(), &output).is_err());

        set_file_mode(&bundle.join("receipt.toml"), 0o644).unwrap();
        assert!(validate_enrolled_artifact(&root).is_err());
        set_file_mode(&bundle.join("receipt.toml"), 0o600).unwrap();

        let alias = root.join("engine-hardlink");
        fs::hard_link(bundle.join("bin/wrela-engine"), &alias).unwrap();
        assert!(validate_enrolled_artifact(&root).is_err());
        fs::remove_file(alias).unwrap();

        let external = root.join("substituted-bundle");
        fs::rename(&bundle, &external).unwrap();
        std::os::unix::fs::symlink(&external, &bundle).unwrap();
        assert!(validate_enrolled_artifact(&root).is_err());
        fs::remove_file(&bundle).unwrap();
        fs::rename(external, &bundle).unwrap();
        validate_enrolled_artifact(&root).expect("restored canonical bundle");

        let toolchain = root.join("toolchain");
        let external_toolchain = root.join("substituted-toolchain");
        fs::rename(&toolchain, &external_toolchain).unwrap();
        std::os::unix::fs::symlink(&external_toolchain, &toolchain).unwrap();
        assert!(validate_enrolled_artifact(&root).is_err());
        fs::remove_file(&toolchain).unwrap();
        fs::rename(external_toolchain, toolchain).unwrap();
    }

    #[test]
    fn tar_contract_rejects_traversal_links_specials_and_exact_limits() {
        let safe = tar(&[(
            &format!("{TARGET_ARCHIVE_ROOT}/{TARGET_ARCHIVE_SUBTREE}/libstd.rlib"),
            b'0',
            b"x".as_slice(),
        )]);
        let temp = Temp::new("safe-tar");
        let cancellation = Cancellation {
            marker: temp.path.join("cancel"),
        };
        extract_tar(
            &mut Cursor::new(&safe),
            &temp.path,
            ArchiveLimits {
                members: 1,
                files: 1,
                bytes: 1,
                file_bytes: 1,
            },
            &cancellation,
        )
        .expect("exact archive limits");
        for limits in [
            ArchiveLimits {
                members: 0,
                files: 1,
                bytes: 1,
                file_bytes: 1,
            },
            ArchiveLimits {
                members: 1,
                files: 0,
                bytes: 1,
                file_bytes: 1,
            },
            ArchiveLimits {
                members: 1,
                files: 1,
                bytes: 0,
                file_bytes: 1,
            },
            ArchiveLimits {
                members: 1,
                files: 1,
                bytes: 1,
                file_bytes: 0,
            },
        ] {
            let temp = Temp::new("over-limit");
            let cancellation = Cancellation {
                marker: temp.path.join("cancel"),
            };
            assert!(
                extract_tar(&mut Cursor::new(&safe), &temp.path, limits, &cancellation).is_err()
            );
        }
        for (path, kind) in [
            (format!("{TARGET_ARCHIVE_ROOT}/../escape"), b'0'),
            (
                format!("{TARGET_ARCHIVE_ROOT}/{TARGET_ARCHIVE_SUBTREE}/link"),
                b'2',
            ),
            (
                format!("{TARGET_ARCHIVE_ROOT}/{TARGET_ARCHIVE_SUBTREE}/long-link"),
                b'K',
            ),
            (
                format!("{TARGET_ARCHIVE_ROOT}/{TARGET_ARCHIVE_SUBTREE}/pax"),
                b'x',
            ),
            (
                format!("{TARGET_ARCHIVE_ROOT}/{TARGET_ARCHIVE_SUBTREE}/device"),
                b'3',
            ),
        ] {
            let fixture = tar(&[(&path, kind, b"".as_slice())]);
            let temp = Temp::new("unsafe-tar");
            let cancellation = Cancellation {
                marker: temp.path.join("cancel"),
            };
            assert!(
                extract_tar(
                    &mut Cursor::new(fixture),
                    &temp.path,
                    ArchiveLimits {
                        members: 8,
                        files: 8,
                        bytes: 8,
                        file_bytes: 8
                    },
                    &cancellation,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn gnu_long_name_is_bounded_single_use_and_canonical() {
        let path = format!("{TARGET_ARCHIVE_ROOT}/{TARGET_ARCHIVE_SUBTREE}/libstd.rlib");
        let mut long_name = path.as_bytes().to_vec();
        long_name.push(0);
        let fixture = tar(&[
            ("././@LongLink", b'L', long_name.as_slice()),
            ("ignored-placeholder", b'0', b"x".as_slice()),
        ]);
        let temp = Temp::new("gnu-long-name");
        let cancellation = Cancellation {
            marker: temp.path.join("cancel"),
        };
        extract_tar(
            &mut Cursor::new(&fixture),
            &temp.path,
            ArchiveLimits {
                members: 2,
                files: 1,
                bytes: 1,
                file_bytes: 1,
            },
            &cancellation,
        )
        .expect("bounded canonical GNU long name");
        assert_eq!(
            fs::read(
                temp.path
                    .join("lib/rustlib")
                    .join(TARGET)
                    .join("libstd.rlib")
            )
            .unwrap(),
            b"x"
        );

        let orphan = tar(&[("././@LongLink", b'L', long_name.as_slice())]);
        let consecutive = tar(&[
            ("././@LongLink", b'L', long_name.as_slice()),
            ("././@LongLink", b'L', long_name.as_slice()),
            ("ignored-placeholder", b'0', b"x".as_slice()),
        ]);
        for malformed in [orphan, consecutive] {
            let temp = Temp::new("malformed-gnu-long-name");
            let cancellation = Cancellation {
                marker: temp.path.join("cancel"),
            };
            assert!(
                extract_tar(
                    &mut Cursor::new(malformed),
                    &temp.path,
                    ArchiveLimits {
                        members: 3,
                        files: 1,
                        bytes: 1,
                        file_bytes: 1,
                    },
                    &cancellation,
                )
                .is_err()
            );
        }

        let mut interior_nul = path.as_bytes().to_vec();
        interior_nul.extend_from_slice(b"\0suffix\0");
        let mut traversal = format!("{TARGET_ARCHIVE_ROOT}/../escape").into_bytes();
        traversal.push(0);
        let mut oversized = vec![b'a'; MAX_PATH_BYTES + 1];
        oversized.push(0);
        for payload in [
            path.as_bytes().to_vec(),
            vec![0],
            vec![0xff, 0],
            interior_nul,
            traversal,
            oversized,
        ] {
            let malformed = tar(&[
                ("././@LongLink", b'L', payload.as_slice()),
                ("ignored-placeholder", b'0', b"x".as_slice()),
            ]);
            let temp = Temp::new("invalid-gnu-long-name");
            let cancellation = Cancellation {
                marker: temp.path.join("cancel"),
            };
            assert!(
                extract_tar(
                    &mut Cursor::new(malformed),
                    &temp.path,
                    ArchiveLimits {
                        members: 2,
                        files: 1,
                        bytes: 1,
                        file_bytes: 1,
                    },
                    &cancellation,
                )
                .is_err()
            );
        }

        let wrong_header = tar(&[
            ("not-long-link", b'L', long_name.as_slice()),
            ("ignored-placeholder", b'0', b"x".as_slice()),
        ]);
        let mut alternate_header = fixture.clone();
        alternate_header[..100].fill(0);
        alternate_header[..9].copy_from_slice(b"@LongLink");
        alternate_header[345..348].copy_from_slice(b"./.");
        recompute_tar_checksum(&mut alternate_header[..512]);
        let mut suffix_after_nul = fixture.clone();
        suffix_after_nul[20] = b'x';
        recompute_tar_checksum(&mut suffix_after_nul[..512]);
        let mut trailing_octal_garbage = fixture.clone();
        let malformed_size = format!("{:09o}\0x\0", long_name.len());
        trailing_octal_garbage[124..136].copy_from_slice(malformed_size.as_bytes());
        recompute_tar_checksum(&mut trailing_octal_garbage[..512]);
        let duplicate = tar(&[
            ("././@LongLink", b'L', long_name.as_slice()),
            ("ignored-placeholder", b'0', b"x".as_slice()),
            (&path, b'0', b"y".as_slice()),
        ]);
        for malformed in [
            wrong_header,
            alternate_header,
            suffix_after_nul,
            trailing_octal_garbage,
            duplicate,
        ] {
            let temp = Temp::new("ambiguous-gnu-long-name");
            let cancellation = Cancellation {
                marker: temp.path.join("cancel"),
            };
            assert!(
                extract_tar(
                    &mut Cursor::new(malformed),
                    &temp.path,
                    ArchiveLimits {
                        members: 3,
                        files: 2,
                        bytes: 2,
                        file_bytes: 1,
                    },
                    &cancellation,
                )
                .is_err()
            );
        }
    }

    #[test]
    fn elf_contract_accepts_only_static_aarch64_and_rejects_path_leaks() {
        let elf = minimal_elf(1);
        inspect_elf(&elf, &[]).expect("static ELF64 AArch64");
        assert!(inspect_elf(&minimal_elf(3), &[]).is_err());
        assert!(inspect_elf(&minimal_elf(2), &[]).is_err());
        assert!(
            inspect_elf(&elf_with_build_id(), &[])
                .expect_err("GNU build-id note must fail")
                .contains("build-id")
        );
        assert!(
            inspect_elf(&elf_with_dynamic_tag(29), &[])
                .expect_err("DT_RUNPATH must fail")
                .contains("DT_RUNPATH")
        );
        let mut leaked = elf;
        leaked.extend_from_slice(b"/private/build/lane");
        assert!(inspect_elf(&leaked, &[PathBuf::from("/private/build/lane")]).is_err());
    }

    #[test]
    fn pinned_xz_dependency_closure_is_exact_and_system_closed() {
        let xz_path = fs::canonicalize("/opt/homebrew/bin/xz").expect("resolve pinned xz");
        let xz_measurement = measure_file(&xz_path, 132336, true, false).expect("measure xz");
        assert_eq!(
            xz_measurement.sha256,
            "da717ab791111423963994a2eb9430fde62220ff49a60a19721e826da430e0f3"
        );
        let lib_path = PathBuf::from(XZ_LIBLZMA_PATH);
        let lib_measurement =
            measure_file(&lib_path, 185472, false, false).expect("measure liblzma");
        assert_eq!(
            lib_measurement.sha256,
            "701b6dd5c9cf5864ae39121d6b7218a2ed6a24f36d82cb8d79947cb220c0e2cc"
        );
        let xz_dependencies = macho_dependencies(
            &read_exact(&xz_path, &xz_measurement).unwrap(),
            "xz fixture",
        )
        .expect("xz Mach-O closure");
        assert_eq!(
            xz_dependencies,
            BTreeSet::from([
                XZ_LIBLZMA_PATH.to_owned(),
                "/usr/lib/libSystem.B.dylib".to_owned()
            ])
        );
        let lib_dependencies = macho_dependencies(
            &read_exact(&lib_path, &lib_measurement).unwrap(),
            "liblzma fixture",
        )
        .expect("liblzma Mach-O closure");
        assert_eq!(
            lib_dependencies,
            BTreeSet::from(["/usr/lib/libSystem.B.dylib".to_owned()])
        );
    }

    #[test]
    fn staging_cleanup_on_failure_publishes_nothing() {
        let parent = Temp::new("cleanup");
        let path;
        {
            let staging = Staging::create(&parent.path, "cancelled").expect("staging");
            path = staging.path.clone();
            write_new(&path.join("partial"), b"partial", false).expect("partial output");
        }
        assert!(!path.exists(), "cancelled/error staging must be removed");
        assert!(
            fs::read_dir(&parent.path).unwrap().next().is_none(),
            "no publication after cancellation/error"
        );
    }

    #[test]
    fn cooperative_cancellation_terminates_and_reaps_process_group() {
        let temp = Temp::new("process-cancel");
        let marker = temp.path.join("cancel");
        let parent_pid_path = temp.path.join("parent.pid");
        let child_pid_path = temp.path.join("child.pid");
        let cancellation = Cancellation {
            marker: marker.clone(),
        };
        let writer_parent = parent_pid_path.clone();
        let writer_child = child_pid_path.clone();
        let writer = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(2);
            while (!writer_parent.exists() || !writer_child.exists()) && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            assert!(writer_parent.exists() && writer_child.exists());
            write_new(&marker, b"cancel\n", false).expect("write cancellation marker");
        });
        let mut command = Command::new("/bin/sh");
        let script = format!(
            "trap '' TERM; echo $$ > {}; /bin/sh -c 'trap \"\" TERM; echo $$ > {}; while :; do /bin/sleep 1; done' & while :; do /bin/sleep 1; done",
            parent_pid_path.display(),
            child_pid_path.display()
        );
        command.env_clear().arg("-c").arg(script);
        let started = Instant::now();
        let error = run_bounded_command(&mut command, "cancellation fixture", &cancellation, 10)
            .expect_err("cancellation must terminate child group");
        writer.join().expect("cancellation writer");
        let parent_pid = read_pid(&parent_pid_path);
        let child_pid = read_pid(&child_pid_path);
        assert!(error.contains("cancelled") && error.contains("reaped"));
        assert!(started.elapsed() < Duration::from_secs(4));
        for _ in 0..40 {
            if !process_exists(parent_pid).unwrap() && !process_exists(child_pid).unwrap() {
                return;
            }
            thread::sleep(Duration::from_millis(25));
        }
        panic!("cancelled process group retained parent={parent_pid} child={child_pid}");
    }

    #[test]
    fn watched_output_bounds_accept_exact_reject_one_over_and_cleanup() {
        let temp = Temp::new("watched-output");
        let cancellation = Cancellation {
            marker: temp.path.join("cancel"),
        };

        let exact_path = temp.path.join("exact");
        {
            let (_guard, exact_file) = TemporaryFile::new(exact_path.clone()).expect("exact file");
            drop(exact_file);
            let mut command = Command::new("/bin/dd");
            command
                .env_clear()
                .arg("if=/dev/zero")
                .arg(format!("of={}", exact_path.display()))
                .args(["bs=1", "count=8"]);
            let output = run_bounded_watched_command(
                &mut command,
                "exact watched-output fixture",
                &cancellation,
                5,
                &exact_path,
                8,
            )
            .expect("exact watched-output bound");
            assert!(output.status.success());
            assert_eq!(fs::metadata(&exact_path).unwrap().len(), 8);
        }
        assert!(
            !exact_path.exists(),
            "exact watched temporary must be removed"
        );

        let over_path = temp.path.join("one-over");
        let pid_path = temp.path.join("one-over.pid");
        let parent_pid;
        {
            let (_guard, over_file) = TemporaryFile::new(over_path.clone()).expect("over file");
            drop(over_file);
            let mut command = Command::new("/bin/sh");
            command
                .env_clear()
                .arg("-c")
                .arg(
                    "trap '' TERM; echo $$ > \"$1\"; /bin/dd if=/dev/zero of=\"$2\" bs=1 count=9 2>/dev/null; while :; do /bin/sleep 1; done",
                )
                .arg("watched-output-fixture")
                .arg(&pid_path)
                .arg(&over_path);
            let started = Instant::now();
            let error = run_bounded_watched_command(
                &mut command,
                "one-over watched-output fixture",
                &cancellation,
                10,
                &over_path,
                8,
            )
            .expect_err("one-over watched-output bound must terminate the writer");
            assert!(error.contains("exceeded its 8-byte bound") && error.contains("reaped"));
            assert!(started.elapsed() < Duration::from_secs(4));
            parent_pid = read_pid(&pid_path);
            for _ in 0..40 {
                if !process_exists(parent_pid).unwrap() {
                    break;
                }
                thread::sleep(Duration::from_millis(25));
            }
            assert!(
                !process_exists(parent_pid).unwrap(),
                "one-over writer {parent_pid} survived bounded termination"
            );
        }
        assert!(
            !over_path.exists(),
            "one-over watched temporary must be removed"
        );
    }

    #[test]
    fn tree_limits_accept_exact_and_reject_one_over() {
        let records = vec![FileRecord {
            path: "a".into(),
            bytes: 1,
            sha256: sha256_bytes(b"x"),
            executable: false,
        }];
        finish_tree(records.clone(), 1, 1).expect("exact tree limits");
        assert!(finish_tree(records.clone(), 0, 1).is_err());
        assert!(finish_tree(records, 1, 0).is_err());
    }

    fn sample_lock() -> Lock {
        Lock {
            channel: CHANNEL.into(), host: HOST.into(), target: TARGET.into(),
            release_date: "2026-04-16".into(),
            release_version: "1.95.0 (59807616e 2026-04-14)".into(),
            release_manifest_sha256: "01".repeat(32), release_manifest_bytes: 1,
            target_archive_url: "https://static.rust-lang.org/dist/2026-04-16/rust-std-1.95.0-aarch64-unknown-linux-musl.tar.xz".into(),
            target_archive_sha256: "02".repeat(32), target_archive_bytes: 1,
            target_tree_sha256: "03".repeat(32), target_files: 1, target_bytes: 1,
            rust_output_sha256: "04".repeat(32), cargo_output_sha256: "05".repeat(32),
            cargo_lock_sha256: "06".repeat(32), cargo_vendor_tree_sha256: "07".repeat(32),
            cargo_vendor_files: 1, cargo_vendor_bytes: 1, cargo_sha256: "08".repeat(32),
            cargo_bytes: 9, rustc_sha256: "09".repeat(32), rustc_bytes: 1,
            rustdoc_sha256: "0a".repeat(32), rustdoc_bytes: 1,
            rust_sysroot_tree_sha256: "0b".repeat(32), rust_sysroot_files: 1,
            rust_sysroot_bytes: 1, rust_lld_sha256: "0c".repeat(32), rust_lld_bytes: 1,
            xz_sha256: "0d".repeat(32), xz_bytes: 1,
            xz_liblzma_sha256: "0e".repeat(32), xz_liblzma_bytes: 1,
            package: PACKAGE.into(), profile: PROFILE.into(),
        }
    }

    fn sample_tree() -> TreeMeasurement {
        TreeMeasurement {
            sha256: "07".repeat(32),
            files: 1,
            bytes: 1,
            records: vec![FileRecord {
                path: "crate".into(),
                bytes: 1,
                sha256: "0f".repeat(32),
                executable: false,
            }],
        }
    }

    fn sample_output() -> Output {
        let mut output = Output {
            input_sha256: "11".repeat(32),
            source_tree_sha256: "22".repeat(32),
            source_files: 1,
            source_bytes: 1,
            target_tree_sha256: "33".repeat(32),
            target_files: 1,
            target_bytes: 1,
            binary_sha256: "44".repeat(32),
            binary_bytes: 1,
            receipt_sha256: "55".repeat(32),
            receipt_bytes: 1,
            artifact_path: String::new(),
            execution_proven: false,
        };
        output.artifact_path = format!(
            "build/toolchain/linux-engine/prefixes/{}/bin/wrela-engine",
            engine_bundle_key(&output.input_sha256, &output.binary_sha256)
        );
        output
    }

    fn sample_receipt(output: &Output) -> String {
        format!(
            "schema = 2\ninput_sha256 = {}\ntarget = {}\npackage = {}\nprofile = {}\nsource_tree_sha256 = {}\nsource_files = {}\nsource_bytes = {}\ncargo_vendor_tree_sha256 = {}\ncargo_vendor_files = 1\ncargo_vendor_bytes = 1\ntarget_archive_sha256 = {}\ntarget_archive_bytes = 1\ntarget_tree_sha256 = {}\ntarget_files = {}\ntarget_bytes = {}\nrust_sysroot_tree_sha256 = {}\nrust_sysroot_files = 1\nrust_sysroot_bytes = 1\ncargo_sha256 = {}\nrustc_sha256 = {}\nrustdoc_sha256 = {}\nrust_lld_sha256 = {}\nxz_sha256 = {}\nxz_liblzma_sha256 = {}\ndarwin_bootstrap_receipt_sha256 = {}\nbinary_sha256 = {}\nbinary_bytes = {}\nartifact_path = {}\nreproducible_lanes = 2\nexecution_proven = false\n",
            toml_string(&output.input_sha256),
            toml_string(TARGET),
            toml_string(PACKAGE),
            toml_string(PROFILE),
            toml_string(&output.source_tree_sha256),
            output.source_files,
            output.source_bytes,
            toml_string(&"66".repeat(32)),
            toml_string(&"77".repeat(32)),
            toml_string(&output.target_tree_sha256),
            output.target_files,
            output.target_bytes,
            toml_string(&"88".repeat(32)),
            toml_string(&"99".repeat(32)),
            toml_string(&"aa".repeat(32)),
            toml_string(&"bb".repeat(32)),
            toml_string(&"cc".repeat(32)),
            toml_string(&"dd".repeat(32)),
            toml_string(&"ee".repeat(32)),
            toml_string(&"12".repeat(32)),
            toml_string(&output.binary_sha256),
            output.binary_bytes,
            toml_string(&output.artifact_path),
        )
    }

    fn read_pid(path: &Path) -> u32 {
        fs::read_to_string(path)
            .expect("read fixture pid")
            .trim()
            .parse()
            .expect("parse fixture pid")
    }

    fn minimal_elf(program_type: u32) -> Vec<u8> {
        let mut bytes = vec![0_u8; 120];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&183_u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1_u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&program_type.to_le_bytes());
        bytes[68..72].copy_from_slice(&5_u32.to_le_bytes());
        bytes
    }

    fn elf_with_build_id() -> Vec<u8> {
        let mut note = Vec::new();
        note.extend_from_slice(&4_u32.to_le_bytes());
        note.extend_from_slice(&4_u32.to_le_bytes());
        note.extend_from_slice(&3_u32.to_le_bytes());
        note.extend_from_slice(b"GNU\0");
        note.extend_from_slice(&[1, 2, 3, 4]);
        elf_with_second_segment(4, &note)
    }

    fn elf_with_dynamic_tag(tag: u64) -> Vec<u8> {
        let mut dynamic = Vec::new();
        dynamic.extend_from_slice(&tag.to_le_bytes());
        dynamic.extend_from_slice(&1_u64.to_le_bytes());
        dynamic.extend_from_slice(&0_u64.to_le_bytes());
        dynamic.extend_from_slice(&0_u64.to_le_bytes());
        elf_with_second_segment(2, &dynamic)
    }

    fn elf_with_second_segment(kind: u32, payload: &[u8]) -> Vec<u8> {
        let payload_offset = 64 + 2 * 56;
        let mut bytes = vec![0_u8; payload_offset + payload.len()];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[6] = 1;
        bytes[16..18].copy_from_slice(&2_u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&183_u16.to_le_bytes());
        bytes[20..24].copy_from_slice(&1_u32.to_le_bytes());
        bytes[32..40].copy_from_slice(&64_u64.to_le_bytes());
        bytes[52..54].copy_from_slice(&64_u16.to_le_bytes());
        bytes[54..56].copy_from_slice(&56_u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&2_u16.to_le_bytes());
        bytes[64..68].copy_from_slice(&1_u32.to_le_bytes());
        bytes[68..72].copy_from_slice(&5_u32.to_le_bytes());
        let second = 120;
        bytes[second..second + 4].copy_from_slice(&kind.to_le_bytes());
        bytes[second + 4..second + 8].copy_from_slice(&4_u32.to_le_bytes());
        bytes[second + 8..second + 16].copy_from_slice(&(payload_offset as u64).to_le_bytes());
        bytes[second + 32..second + 40].copy_from_slice(&(payload.len() as u64).to_le_bytes());
        bytes[payload_offset..].copy_from_slice(payload);
        bytes
    }

    fn tar(entries: &[(&str, u8, &[u8])]) -> Vec<u8> {
        let mut archive = Vec::new();
        for (path, kind, payload) in entries {
            let mut header = [0_u8; 512];
            if path.len() < 100 {
                header[..path.len()].copy_from_slice(path.as_bytes());
            } else {
                let split = path[..path.len().min(155)]
                    .rfind('/')
                    .expect("fixture path has USTAR split");
                let (prefix, name) = path.split_at(split);
                let name = &name[1..];
                assert!(prefix.len() <= 155 && name.len() < 100);
                header[..name.len()].copy_from_slice(name.as_bytes());
                header[345..345 + prefix.len()].copy_from_slice(prefix.as_bytes());
            }
            write_octal(&mut header[100..108], 0o644);
            write_octal(&mut header[124..136], payload.len() as u64);
            header[156] = *kind;
            header[257..263].copy_from_slice(b"ustar\0");
            header[263..265].copy_from_slice(b"00");
            header[148..156].fill(b' ');
            let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
            write_octal(&mut header[148..156], checksum);
            archive.extend_from_slice(&header);
            archive.extend_from_slice(payload);
            archive.resize(archive.len().next_multiple_of(512), 0);
        }
        archive.resize(archive.len() + 1024, 0);
        archive
    }

    fn write_octal(field: &mut [u8], value: u64) {
        field.fill(0);
        let text = format!("{:0width$o}", value, width = field.len() - 1);
        field[..text.len()].copy_from_slice(text.as_bytes());
    }

    fn recompute_tar_checksum(header: &mut [u8]) {
        assert_eq!(header.len(), 512);
        header[148..156].fill(b' ');
        let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
        write_octal(&mut header[148..156], checksum);
    }

    struct Temp {
        path: PathBuf,
    }
    impl Temp {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = env::temp_dir().join(format!(
                "wrela-linux-engine-{label}-{}-{nonce}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self { path }
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = make_tree_writable(&self.path);
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
