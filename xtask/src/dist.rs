//! Authenticated, reproducible distribution assembly.
//!
//! This module deliberately does not acquire or trust an ambient emulator.
//! `toolchain/emulation.outputs.toml` must enroll one complete, source-built
//! QEMU payload for the current host.  The enrolled payload is independently
//! remeasured here before any byte is copied into a release.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use sha2::{Digest, Sha256};

use crate::llvm;

pub(crate) const HELP: &str = "\
usage: cargo xtask dist [options]\n\
\n\
Build, test, archive, and atomically publish one self-contained Wrela toolchain.\n\
\n\
options:\n\
  --plan                    validate enrolled inputs and print the release plan\n\
  --integration-qemu        build one private lane and execute current QEMU contracts\n\
  --integration-qemu-case <current-tranche|runtime-timeout>\n\
                            execute only one named QEMU integration contract\n\
  --output <directory>      publication directory (default: build/toolchain/distributions)\n\
  --qemu-bundle <directory> exact enrolled QEMU payload (default: content-addressed build path)\n\
  --cargo <executable>      exact Cargo executable (or WRELA_DIST_CARGO)\n\
  --rustc <executable>      exact rustc executable (or WRELA_DIST_RUSTC)\n\
  --cargo-home <directory>  offline Cargo cache (or CARGO_HOME)\n\
  --jobs <1..=256>          bounded Cargo parallelism\n\
  -h, --help                show this help\n\
\n\
The command never searches PATH. QEMU must be enrolled by the strict canonical\n\
toolchain/emulation.outputs.toml contract and must match emulation.lock.toml.\n";

pub(crate) const CARGO_VENDOR_HELP: &str = "\
usage: cargo xtask cargo-vendor [options]\n\
\n\
Acquire the Cargo.lock dependency closure with the enrolled Rust toolchain,\n\
verify it against toolchain/cargo.outputs.toml, and atomically publish it. The\n\
record/reuse mode performs an exact offline reenrollment without invoking tools.\n\
\n\
options:\n\
  --record-output           maintainer-only replacement of a stale Cargo.lock enrollment\n\
  --reuse-enrolled          reuse only the exactly authenticated old vendor tree\n\
  --cargo <executable>      exact enrolled Cargo executable (or WRELA_DIST_CARGO)\n\
  --rustc <executable>      exact enrolled rustc executable (or WRELA_DIST_RUSTC)\n\
  --cargo-home <directory>  Rust toolchain selector home (or CARGO_HOME)\n\
  -h, --help                show this help\n";

const MAX_JOBS: u32 = 256;
const DEFAULT_JOBS: u32 = 8;
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_TREE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_TREE_FILES: u64 = 1_000_000;
const MAX_TREE_ENTRIES: u64 = 1_100_000;
const MAX_PATH_BYTES: usize = 4096;
const MAX_DEPTH: u32 = 128;
const MAX_PROCESS_OUTPUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
const MAX_LOCK_BYTES: u64 = 4 * 1024 * 1024;
const MAX_RUNTIME_OBJECT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SMOKE_IMAGE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_SMOKE_SERIAL_BYTES: u64 = 4 * 1024 * 1024;
const MAX_RUNTIME_TIMEOUT_IMAGE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_RUNTIME_TIMEOUT_REPORT_BYTES: u64 = 16 * 1024 * 1024;
// The immediate harness canonicalizes exported event frames into the same
// bounded buffer used for its canonical report consumer.
const MAX_RUNTIME_TIMEOUT_EVENT_STREAM_BYTES: u64 = 16 * 1024 * 1024;
const MAX_RUNTIME_TIMEOUT_EVIDENCE_LINE_BYTES: usize = 1024;
const MACOS_DEPLOYMENT_TARGET: &str = "13.0";
const MACHO_LINKER_ARGUMENTS: [&str; 2] = ["-Wl,-reproducible", "-Wl,-no_uuid"];
const RELEASE_TREE_MAGIC: &[u8; 8] = b"WRELDST\0";
const RELEASE_TREE_VERSION: u32 = 1;
const DIST_IMPLEMENTATION_MAGIC: &[u8; 8] = b"WRELDIM\0";
const DIST_IMPLEMENTATION_VERSION: u32 = 2;
const CANONICAL_TREE_MAGIC: &[u8; 8] = b"WRELTRE\0";
const CANONICAL_TREE_VERSION: u32 = 1;
const PACKAGE_CONTENT_MAGIC: &[u8; 8] = b"WRELPKG\0";
const PACKAGE_CONTENT_VERSION: u32 = 1;
const TOOLCHAIN_MANIFEST_SCHEMA: u32 = 1;
const RELEASE_RECEIPT_SCHEMA: u32 = 4;
const EMULATION_OUTPUT_SCHEMA: u32 = 1;
const RUNTIME_ABI_VERSION: u32 = 2;
const LLVM_PROJECT_REVISION: &str = "llvmorg-22.1.3";
const TARGET_IDENTITY: &str = "aarch64-qemu-virt-uefi";
const CORE_COMPONENT: &str = "wrela-core-0.1";
const CORE_NAME: &str = "wrela-core";
const CORE_VERSION: &str = "0.1.0";
const CORE_MANIFEST_SHA256: &str =
    "7eda3d023a968b8302de6a2d5bea13270be3fbdba58d57ca93d74007a1a65786";
const CORE_SOURCE_DIGEST: &str = "5da2bae2f9089643c235c54bf229e67a995f16ce9a0596c24604bd389661afd5";
const CARGO_LICENSE_FILES: &[&str] = &[
    "COPYING",
    "COPYRIGHT",
    "LICENSE",
    "LICENSE-APACHE",
    "LICENSE-APACHE.md",
    "LICENSE-MIT",
    "LICENSE-MIT.md",
    "LICENSE-UNICODE",
    "LICENSE-ZLIB.md",
    "UNLICENSE",
];
const CARGO_LICENSE_OVERRIDE_PACKAGE: &str = "inkwell_internals-0.14.0";
const CARGO_LICENSE_OVERRIDE_SOURCE: &str = "inkwell-0.9.0/LICENSE";
const CARGO_VENDOR_EXECUTABLE_PATHS: &[&str] = &[
    "inkwell-0.9.0/.codecov.yml",
    "unicode-normalization-0.1.24/scripts/unicode.py",
];
const RUST_CRATE_LICENSE_TREE_SHA256: &str =
    "a3c8134269c4d54682838c0034477023ba311cc0c953e89aa1d560609ac1dde0";
const RUST_CRATE_LICENSE_FILES: u64 = 92;
const RUST_CRATE_LICENSE_BYTES: u64 = 475_031;
const RUST_TOOLCHAIN_LICENSE_PATHS: &[&str] = &[
    "lib/rustlib/src/rust/library/backtrace/LICENSE-APACHE",
    "lib/rustlib/src/rust/library/backtrace/LICENSE-MIT",
    "lib/rustlib/src/rust/library/compiler-builtins/LICENSE.txt",
    "lib/rustlib/src/rust/library/compiler-builtins/libm/LICENSE.txt",
    "lib/rustlib/src/rust/library/portable-simd/LICENSE-APACHE",
    "lib/rustlib/src/rust/library/portable-simd/LICENSE-MIT",
    "lib/rustlib/src/rust/library/portable-simd/crates/core_simd/LICENSE-APACHE",
    "lib/rustlib/src/rust/library/portable-simd/crates/core_simd/LICENSE-MIT",
    "lib/rustlib/src/rust/library/stdarch/LICENSE-APACHE",
    "lib/rustlib/src/rust/library/stdarch/LICENSE-MIT",
    "lib/rustlib/src/rust/library/stdarch/crates/core_arch/LICENSE-APACHE",
    "lib/rustlib/src/rust/library/stdarch/crates/core_arch/LICENSE-MIT",
    "lib/rustlib/src/rust/src/llvm-project/libunwind/LICENSE.TXT",
    "share/doc/rust/COPYRIGHT-library.html",
    "share/doc/rust/COPYRIGHT.html",
    "share/doc/rust/README.md",
    "share/doc/rust/licenses/Apache-2.0.txt",
    "share/doc/rust/licenses/BSD-2-Clause.txt",
    "share/doc/rust/licenses/CC-BY-SA-4.0.txt",
    "share/doc/rust/licenses/GCC-exception-3.1.txt",
    "share/doc/rust/licenses/GPL-2.0-only.txt",
    "share/doc/rust/licenses/GPL-3.0-or-later.txt",
    "share/doc/rust/licenses/ISC.txt",
    "share/doc/rust/licenses/LLVM-exception.txt",
    "share/doc/rust/licenses/MIT.txt",
    "share/doc/rust/licenses/NCSA.txt",
    "share/doc/rust/licenses/OFL-1.1.txt",
    "share/doc/rust/licenses/Unicode-3.0.txt",
];
const RUST_TOOLCHAIN_LICENSE_TREE_SHA256: &str =
    "c3801cdf711c1269e499ce7800278d29264a7ce32633c7c2f4913b484cdd38cb";
const RUST_TOOLCHAIN_LICENSE_FILES: u64 = 28;
const RUST_TOOLCHAIN_LICENSE_BYTES: u64 = 14_896_866;
const RUST_LICENSE_TREE_SHA256: &str =
    "ca04cc94e084a63d096d24bc7c2d83f757d84204c14a88f670e0adb863133ffd";
const RUST_LICENSE_FILES: u64 = 120;
const RUST_LICENSE_BYTES: u64 = 15_371_897;
const EXPECTED_SMOKE_FRAMES: &[&[u8]] = &[
    &[
        0x57, 0x52, 0x45, 0x4c, 0x54, 0x53, 0x54, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0xb0, 0x6d,
        0x85, 0xe7, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
    ],
    &[
        0x57, 0x52, 0x45, 0x4c, 0x54, 0x53, 0x54, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0xbf, 0x72,
        0x9a, 0x25, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0xc0, 0xdb, 0x00, 0x00,
    ],
    &[
        0x57, 0x52, 0x45, 0x4c, 0x54, 0x53, 0x54, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0xb6, 0xd2,
        0xa1, 0x6c, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04,
        0xc0, 0xdb, 0x00, 0x00, 0x03, 0x00,
    ],
    &[
        0x57, 0x52, 0x45, 0x4c, 0x54, 0x53, 0x54, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
        0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0xad, 0x30,
        0x72, 0xd7, 0x03, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    ],
];
const DIST_IMPLEMENTATION_INPUTS: &[(&str, &[u8])] = &[
    (
        ".cargo/config.toml",
        include_bytes!("../../.cargo/config.toml"),
    ),
    ("Cargo.lock", include_bytes!("../../Cargo.lock")),
    ("xtask/Cargo.toml", include_bytes!("../Cargo.toml")),
    ("xtask/src/dist.rs", include_bytes!("dist.rs")),
    ("xtask/src/llvm.rs", include_bytes!("llvm.rs")),
    ("xtask/src/main.rs", include_bytes!("main.rs")),
];

static NEXT_STAGING: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
struct Options {
    help: bool,
    plan: bool,
    integration_qemu: bool,
    integration_qemu_case: Option<IntegrationQemuCase>,
    output: Option<PathBuf>,
    qemu_bundle: Option<PathBuf>,
    cargo: Option<PathBuf>,
    rustc: Option<PathBuf>,
    cargo_home: Option<PathBuf>,
    jobs: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IntegrationQemuCase {
    CurrentTranche,
    RuntimeTimeout,
}

impl IntegrationQemuCase {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "current-tranche" => Ok(Self::CurrentTranche),
            "runtime-timeout" => Ok(Self::RuntimeTimeout),
            _ => Err(format!(
                "--integration-qemu-case must be exactly `current-tranche` or `runtime-timeout`, got {value:?}"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DistExecutionMode {
    Plan,
    IntegrationQemu,
    Release,
}

impl Options {
    const fn mode(&self) -> DistExecutionMode {
        if self.plan {
            DistExecutionMode::Plan
        } else if self.integration_qemu {
            DistExecutionMode::IntegrationQemu
        } else {
            DistExecutionMode::Release
        }
    }
}

impl DistExecutionMode {
    const fn build_lanes(self) -> u8 {
        match self {
            Self::Plan => 0,
            Self::IntegrationQemu => 1,
            Self::Release => 2,
        }
    }

    const fn replays_public_or_archive_consumers(self) -> bool {
        matches!(self, Self::Release)
    }

    const fn publishes(self) -> bool {
        matches!(self, Self::Release)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CargoVendorOptions {
    help: bool,
    record_output: bool,
    reuse_enrolled: bool,
    cargo: Option<PathBuf>,
    rustc: Option<PathBuf>,
    cargo_home: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EmulationLock {
    bytes_sha256: String,
    qemu_version: String,
    source: String,
    source_sha256: String,
    signature: String,
    signing_key_fingerprint: String,
    machine_contract: String,
    cpu_contract: String,
    accelerator_contract: String,
    firmware_code: FirmwarePin,
    firmware_variables: FirmwarePin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FirmwarePin {
    name: String,
    source_path: String,
    install_path: String,
    sha256: String,
    license_manifest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EmulationOutput {
    emulation_lock_sha256: String,
    native_input_sha256: String,
    qemu_version: String,
    host: String,
    bundle_tree_sha256: String,
    bundle_files: u64,
    bundle_bytes: u64,
    qemu_sha256: String,
    qemu_bytes: u64,
    firmware_code_sha256: String,
    firmware_code_bytes: u64,
    firmware_variables_sha256: String,
    firmware_variables_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeLock {
    target: String,
    runtime_abi_version: u32,
    compiler_identity: String,
    compiler_sha256: String,
    builder_sha256: String,
    source_sha256: String,
    object_sha256: String,
    object_bytes: u64,
    coff_machine: String,
    relocations: u64,
    undefined_symbols: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RustOutput {
    rust_toolchain_sha256: String,
    channel: String,
    host: String,
    cargo_sha256: String,
    cargo_bytes: u64,
    rustc_sha256: String,
    rustc_bytes: u64,
    cargo_version_sha256: String,
    rustc_version_sha256: String,
    sysroot_tree_sha256: String,
    sysroot_files: u64,
    sysroot_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CargoOutput {
    cargo_lock_sha256: String,
    cargo_sha256: String,
    vendor_tree_sha256: String,
    vendor_files: u64,
    vendor_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CargoRegistryPackage {
    directory: String,
    checksum: String,
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

#[derive(Debug)]
struct TreeBudget {
    files: u64,
    bytes: u64,
    max_files: u64,
    max_bytes: u64,
    traversal: TraversalBudget,
}

#[derive(Debug)]
struct TraversalBudget {
    entries: u64,
    max_entries: u64,
}

impl TraversalBudget {
    fn new(max_entries: u64) -> Result<Self, String> {
        if max_entries == 0 {
            return Err("tree traversal limit must be nonzero".to_owned());
        }
        Ok(Self {
            entries: 0,
            max_entries,
        })
    }

    fn record_entry(&mut self) -> Result<(), String> {
        let entries = self
            .entries
            .checked_add(1)
            .ok_or_else(|| "tree traversal entry count overflow".to_owned())?;
        if entries > self.max_entries {
            return Err("tree exceeds its finite traversal entry limit".to_owned());
        }
        self.entries = entries;
        Ok(())
    }
}

impl TreeBudget {
    fn new(max_files: u64, max_bytes: u64) -> Result<Self, String> {
        let max_entries = max_files
            .saturating_mul(2)
            .saturating_add(u64::from(MAX_DEPTH))
            .min(MAX_TREE_ENTRIES);
        Self::with_entry_limit(max_files, max_bytes, max_entries)
    }

    fn with_entry_limit(max_files: u64, max_bytes: u64, max_entries: u64) -> Result<Self, String> {
        if max_files == 0 || max_bytes == 0 {
            return Err("tree limits must be nonzero".to_owned());
        }
        Ok(Self {
            files: 0,
            bytes: 0,
            max_files,
            max_bytes,
            traversal: TraversalBudget::new(max_entries)?,
        })
    }

    fn record_entry(&mut self) -> Result<(), String> {
        self.traversal.record_entry()
    }

    fn file_limit(&self) -> Result<u64, String> {
        if self.files >= self.max_files || self.bytes >= self.max_bytes {
            return Err("tree exceeds its finite file or byte limit".to_owned());
        }
        Ok(MAX_FILE_BYTES.min(self.max_bytes - self.bytes))
    }

    fn record_file(&mut self, bytes: u64) -> Result<(), String> {
        let files = self
            .files
            .checked_add(1)
            .ok_or_else(|| "tree file count overflow".to_owned())?;
        let total_bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| "tree byte count overflow".to_owned())?;
        if files > self.max_files || total_bytes > self.max_bytes {
            return Err("tree exceeds its finite file or byte limit".to_owned());
        }
        self.files = files;
        self.bytes = total_bytes;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileMeasurement {
    sha256: String,
    bytes: u64,
}

#[derive(Debug)]
struct ProcessOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

#[derive(Debug)]
struct BuildTools {
    cargo: PathBuf,
    rustc: PathBuf,
    cargo_home: PathBuf,
    rust_sysroot: PathBuf,
    rust_sysroot_tree: TreeMeasurement,
    cargo_digest: String,
    rustc_digest: String,
    cargo_version: String,
    rustc_version: String,
}

#[derive(Debug)]
struct ReleasePlan {
    release: String,
    host: String,
    rust_toolchain: String,
    rust_output: RustOutput,
    cargo_output: CargoOutput,
    cargo_vendor: PathBuf,
    cargo_vendor_tree: TreeMeasurement,
    rust_crate_licenses: TreeMeasurement,
    rust_toolchain_licenses: TreeMeasurement,
    rust_licenses: TreeMeasurement,
    output: PathBuf,
    qemu_bundle: PathBuf,
    emulation: EmulationLock,
    emulation_output: EmulationOutput,
    runtime: RuntimeLock,
    native: llvm::VerifiedNativeEnvironment,
    native_authority: llvm::VerifiedDistributionAuthority,
    llvm_licenses: TreeMeasurement,
    llvm_provenance: FileMeasurement,
    llvm_prefix_tree_sha256: String,
    tools: BuildTools,
    orchestrator: PathBuf,
    orchestrator_measurement: FileMeasurement,
    dist_implementation_sha256: String,
    source: TreeMeasurement,
    qemu: TreeMeasurement,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PublicGateEvidence {
    build: TreeMeasurement,
    test: TreeMeasurement,
}

struct ReleaseEvidence<'a> {
    frontend_a: &'a FileMeasurement,
    frontend_b: &'a FileMeasurement,
    backend_a: &'a FileMeasurement,
    backend_b: &'a FileMeasurement,
    installed_public: &'a PublicGateEvidence,
    extracted_public: &'a PublicGateEvidence,
    runtime_boot: &'a RuntimeBootEvidence,
    installed_real_qemu: &'a RealQemuEvidence,
    extracted_real_qemu: &'a RealQemuEvidence,
    installed_stdlib_time_qemu: &'a StdlibTimeQemuEvidence,
    extracted_stdlib_time_qemu: &'a StdlibTimeQemuEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeBootEvidence {
    image: FileMeasurement,
    frame_sha256: String,
    frame_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RealQemuEvidence {
    image_sha256: String,
    image_bytes: u64,
    report_sha256: String,
    report_bytes: u64,
    event_stream_sha256: String,
    event_stream_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StdlibTimeQemuEvidence {
    source: FileMeasurement,
    manifest: FileMeasurement,
    lock: FileMeasurement,
    pass: RealQemuEvidence,
    invalid_count: RealQemuEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CheckedShiftQemuEvidence {
    pass: RealQemuEvidence,
    assertion_failure: RealQemuEvidence,
    result_loss: RealQemuEvidence,
    invalid_count: RealQemuEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeResultQemuEvidence {
    ok: RealQemuEvidence,
    propagated_err: RealQemuEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CurrentTrancheQemuEvidence {
    timeout: RealQemuEvidence,
    stdlib_time: StdlibTimeQemuEvidence,
    checked_shift: CheckedShiftQemuEvidence,
    runtime_result: RuntimeResultQemuEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct QemuIntegrationEvidence {
    source: TreeMeasurement,
    qemu_bundle_sha256: String,
    qemu_native_input_sha256: String,
    installation: TreeMeasurement,
    frontend: FileMeasurement,
    backend: FileMeasurement,
    bootstrap: RealQemuEvidence,
    stdlib_time: StdlibTimeQemuEvidence,
    checked_shift: CheckedShiftQemuEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeTimeoutIntegrationEvidence {
    source: TreeMeasurement,
    qemu_bundle_sha256: String,
    qemu_native_input_sha256: String,
    installation: TreeMeasurement,
    frontend: FileMeasurement,
    backend: FileMeasurement,
    run_binding_sha256: String,
    timeout: RealQemuEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CurrentTrancheIntegrationEvidence {
    source: TreeMeasurement,
    qemu_bundle_sha256: String,
    qemu_native_input_sha256: String,
    installation: TreeMeasurement,
    frontend: FileMeasurement,
    backend: FileMeasurement,
    run_binding_sha256: String,
    qemu: CurrentTrancheQemuEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum QemuIntegrationOutput {
    Full(Box<QemuIntegrationEvidence>),
    CurrentTranche(Box<CurrentTrancheIntegrationEvidence>),
    RuntimeTimeout(Box<RuntimeTimeoutIntegrationEvidence>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CargoValidationPolicy {
    PerCommand,
    Bracketed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EnrolledQemuEvidence {
    bootstrap: RealQemuEvidence,
    stdlib_time: StdlibTimeQemuEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LaneBQemuEvidence {
    bootstrap: RealQemuEvidence,
    stdlib_time: StdlibTimeQemuEvidence,
    checked_shift: CheckedShiftQemuEvidence,
}

#[derive(Debug)]
struct IsolatedRustTools {
    cargo: PathBuf,
    rustc: PathBuf,
    rustdoc: PathBuf,
    sysroot: PathBuf,
}

struct CargoExecution<'a> {
    root: &'a Path,
    rust_tools: &'a IsolatedRustTools,
    cargo_home: &'a Path,
    target: &'a Path,
    work: &'a Path,
}

#[derive(Debug)]
struct PrivateStaging {
    path: PathBuf,
    published: bool,
}

#[derive(Debug)]
struct CargoEnrollmentLease {
    path: PathBuf,
    measurement: FileMeasurement,
    released: bool,
}

impl Drop for CargoEnrollmentLease {
    fn drop(&mut self) {
        if !self.released
            && measure_file(&self.path, MAX_LOCK_BYTES, false)
                .ok()
                .as_ref()
                == Some(&self.measurement)
        {
            let _ = fs::remove_file(&self.path);
            if let Some(parent) = self.path.parent() {
                let _ = sync_directory(parent);
            }
        }
    }
}

impl Drop for PrivateStaging {
    fn drop(&mut self) {
        if !self.published {
            let _ = make_directories_writable(&self.path);
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

pub(crate) fn run(root: &Path, arguments: &[String]) -> Result<(), String> {
    let options = parse_options(arguments)?;
    if options.help {
        print!("{HELP}");
        return Ok(());
    }
    let running = exact_file(
        &env::current_exe().map_err(|error| format!("cannot locate running xtask: {error}"))?,
        "running distribution orchestrator",
    )?;
    let before = measure_file(&running, MAX_FILE_BYTES, true)?;
    let dist_implementation_sha256 = validate_dist_implementation(root)?;
    let plan = load_plan(
        root,
        &options,
        running.clone(),
        before.clone(),
        dist_implementation_sha256,
    )?;
    match options.mode() {
        DistExecutionMode::Plan => {
            print_plan(&plan);
            if measure_file(&running, MAX_FILE_BYTES, true)? != before {
                return Err("running distribution orchestrator changed during planning".to_owned());
            }
            Ok(())
        }
        DistExecutionMode::IntegrationQemu => {
            run_qemu_integration(root, plan, options.jobs, options.integration_qemu_case)
        }
        DistExecutionMode::Release => assemble(root, plan, options.jobs),
    }
}

pub(crate) fn run_cargo_vendor(root: &Path, arguments: &[String]) -> Result<(), String> {
    let options = parse_cargo_vendor_options(arguments)?;
    if options.help {
        print!("{CARGO_VENDOR_HELP}");
        return Ok(());
    }
    let root = exact_directory(root, "workspace root")?;
    let running = exact_file(
        &env::current_exe().map_err(|error| format!("cannot locate running xtask: {error}"))?,
        "running Cargo vendor producer",
    )?;
    let running_measurement = measure_file(&running, MAX_FILE_BYTES, true)?;
    validate_dist_implementation(&root)?;
    if options.record_output {
        record_reused_cargo_vendor(&root, &running, &running_measurement)?;
        return Ok(());
    }
    let source = measure_source_tree(&root)?;
    let host = host_identity()?;
    let channel = rust_toolchain_channel(&root)?;
    let rust_output = parse_rust_output(&read_bounded_file(
        &root.join("toolchain/rust.outputs.toml"),
        MAX_LOCK_BYTES,
    )?)?;
    let cargo_output = parse_cargo_output(&read_bounded_file(
        &root.join("toolchain/cargo.outputs.toml"),
        MAX_LOCK_BYTES,
    )?)?;
    if rust_output.host != host
        || rust_output.channel != channel
        || measure_file(&root.join("rust-toolchain.toml"), MAX_LOCK_BYTES, false)?.sha256
            != rust_output.rust_toolchain_sha256
        || measure_file(&root.join("Cargo.lock"), MAX_LOCK_BYTES, false)?.sha256
            != cargo_output.cargo_lock_sha256
        || cargo_output.cargo_sha256 != rust_output.cargo_sha256
    {
        return Err(
            "Cargo vendor producer enrollments do not match this source and host".to_owned(),
        );
    }

    let publication_parent = root
        .join("build/toolchain/cargo/prefixes")
        .join(&cargo_output.cargo_lock_sha256);
    prepare_output_root(&publication_parent)?;
    let published = publication_parent.join("vendor");
    if published.exists() {
        let tree = measure_closure_tree(&published, MAX_TREE_FILES, MAX_TREE_BYTES)?;
        validate_cargo_vendor_measurement(&tree, &cargo_output)?;
        seal_measured_tree(&published, &tree)?;
        sync_tree(&published)?;
        sync_directory(&publication_parent)?;
        validate_published_cargo_vendor(&published, &cargo_output)?;
        require_same_tree(
            &source,
            &measure_source_tree(&root)?,
            "Cargo vendor reuse source tree",
        )?;
        println!(
            "reused authenticated Cargo vendor tree {}",
            published.display()
        );
        return Ok(());
    }

    let build_options = Options {
        help: false,
        plan: false,
        integration_qemu: false,
        integration_qemu_case: None,
        output: None,
        qemu_bundle: None,
        cargo: options.cargo,
        rustc: options.rustc,
        cargo_home: options.cargo_home,
        jobs: 1,
    };
    let tools = resolve_build_tools(&build_options, &host, &rust_output)?;
    validate_rust_toolchain(&tools, &channel)?;

    let temporary_parent = fs::canonicalize(env::temp_dir())
        .map_err(|error| format!("cannot canonicalize Cargo vendor build parent: {error}"))?;
    let temporary_parent = exact_directory(&temporary_parent, "Cargo vendor build parent")?;
    if temporary_parent.starts_with(&root) || root.starts_with(&temporary_parent) {
        return Err("Cargo vendor build parent overlaps the source checkout".to_owned());
    }
    let mut private = PrivateStaging::create(&temporary_parent)?;
    let work = private.path.join("work");
    create_private_directory(&work)?;
    let isolated =
        isolate_enrolled_rust_tools(&tools, &rust_output, &private.path.join("rust-toolchain"))?;
    let acquisition_home = private.path.join("cargo-home");
    create_private_directory(&acquisition_home)?;
    let temp = private.path.join("tmp");
    create_private_directory(&temp)?;
    reject_ancestor_cargo_configuration(&work)?;

    let mut staging = PrivateStaging::create(&publication_parent)?;
    let vendor = staging.path.join("vendor");
    validate_enrolled_rust_tools(&tools, &rust_output, &isolated)?;
    require_same_tree(
        &source,
        &measure_source_tree(&root)?,
        "Cargo vendor acquisition source preflight",
    )?;
    let mut command = Command::new(&isolated.cargo);
    command
        .current_dir(&work)
        .env_clear()
        .env("CARGO_HOME", &acquisition_home)
        .env("CARGO_REGISTRIES_CRATES_IO_PROTOCOL", "sparse")
        .env("CARGO_TERM_COLOR", "never")
        .env("HOME", &temp)
        .env("LC_ALL", "C")
        .env("PATH", "/wrela/no-ambient-path")
        .env("RUSTC", &isolated.rustc)
        .env("RUSTDOC", &isolated.rustdoc)
        .env("TMPDIR", &temp)
        .env("TZ", "UTC")
        .args(["vendor", "--locked", "--versioned-dirs"]);
    command
        .arg("--manifest-path")
        .arg(root.join("Cargo.toml"))
        .arg(&vendor);
    let output = run_command(
        &mut command,
        "authenticated Cargo vendor acquisition",
        60 * 60,
    )?;
    require_success(&output, "authenticated Cargo vendor acquisition", false)?;
    validate_enrolled_rust_tools(&tools, &rust_output, &isolated)?;
    reject_ancestor_cargo_configuration(&work)?;
    require_same_tree(
        &source,
        &measure_source_tree(&root)?,
        "Cargo vendor acquisition source postflight",
    )?;
    normalize_acquired_vendor_modes(&vendor)?;
    let tree = measure_closure_tree(&vendor, MAX_TREE_FILES, MAX_TREE_BYTES)?;
    validate_cargo_vendor_measurement(&tree, &cargo_output)?;
    seal_measured_tree(&vendor, &tree)?;
    sync_tree(&vendor)?;
    validate_published_cargo_vendor(&vendor, &cargo_output)?;
    destroy_private_staging(&mut private, "Cargo vendor private acquisition tree")?;
    if measure_file(&running, MAX_FILE_BYTES, true)? != running_measurement {
        return Err("Cargo vendor producer changed during acquisition".to_owned());
    }
    validate_dist_implementation(&root)?;
    require_same_tree(
        &source,
        &measure_source_tree(&root)?,
        "Cargo vendor atomic publication source",
    )?;

    if published.exists() {
        validate_published_cargo_vendor(&published, &cargo_output)?;
        sync_tree(&published)?;
        sync_directory(&publication_parent)?;
        validate_published_cargo_vendor(&published, &cargo_output)?;
        destroy_private_staging(&mut staging, "reused Cargo vendor staging tree")?;
        println!(
            "reused concurrently authenticated Cargo vendor tree {}",
            published.display()
        );
        return Ok(());
    }
    match fs::rename(&vendor, &published) {
        Ok(()) => {
            sync_directory(&publication_parent)?;
            destroy_private_staging(&mut staging, "published Cargo vendor staging shell")?;
        }
        Err(rename_error) if published.exists() => {
            validate_published_cargo_vendor(&published, &cargo_output).map_err(|error| {
                format!(
                    "Cargo vendor publication race failed ({rename_error}); visible winner is invalid: {error}"
                )
            })?;
            destroy_private_staging(&mut staging, "losing Cargo vendor staging tree")?;
            sync_directory(&publication_parent)?;
        }
        Err(error) => {
            return Err(format!(
                "cannot atomically publish authenticated Cargo vendor tree: {error}"
            ));
        }
    }
    validate_published_cargo_vendor(&published, &cargo_output)?;
    println!(
        "published authenticated Cargo vendor tree {}",
        published.display()
    );
    Ok(())
}

fn record_reused_cargo_vendor(
    root: &Path,
    running: &Path,
    running_measurement: &FileMeasurement,
) -> Result<(), String> {
    let lease = CargoEnrollmentLease::acquire(root, running_measurement)?;
    record_reused_cargo_vendor_with_guard(root, running, running_measurement, &lease, &|| {
        validate_dist_implementation(root).map(|_| ())
    })?;
    lease.release()
}

fn record_reused_cargo_vendor_with_guard(
    root: &Path,
    running: &Path,
    running_measurement: &FileMeasurement,
    lease: &CargoEnrollmentLease,
    validate_implementation: &dyn Fn() -> Result<(), String>,
) -> Result<(), String> {
    lease.validate()?;
    let lock_path = root.join("Cargo.lock");
    let lock_measurement = measure_file(&lock_path, MAX_LOCK_BYTES, false)?;
    let lock_bytes = read_exact_measured_file(&lock_path, &lock_measurement)?;
    let registry_packages = parse_cargo_registry_packages(&lock_bytes)?;

    let output_path = root.join("toolchain/cargo.outputs.toml");
    let old_output_measurement = measure_file(&output_path, MAX_LOCK_BYTES, false)?;
    let old_output_bytes = read_exact_measured_file(&output_path, &old_output_measurement)?;
    let old_output = parse_cargo_output(&old_output_bytes)?;
    if old_output.cargo_lock_sha256 == lock_measurement.sha256 {
        return Err(
            "Cargo vendor output enrollment already names the current Cargo.lock; use ordinary cargo-vendor validation"
                .to_owned(),
        );
    }

    validate_cargo_reuse_rust_enrollment(root, &old_output)?;
    let old_vendor = exact_directory(
        &root
            .join("build/toolchain/cargo/prefixes")
            .join(&old_output.cargo_lock_sha256)
            .join("vendor"),
        "previously enrolled Cargo vendor tree",
    )?;
    let vendor_tree = measure_closure_tree(&old_vendor, MAX_TREE_FILES, MAX_TREE_BYTES)?;
    validate_cargo_vendor_measurement(&vendor_tree, &old_output)?;
    validate_sealed_installation_modes(&old_vendor, &vendor_tree)?;
    validate_cargo_registry_closure(&old_vendor, &vendor_tree, &registry_packages)?;

    revalidate_cargo_reuse_authority(
        running,
        running_measurement,
        &lock_path,
        &lock_measurement,
        &output_path,
        &old_output_measurement,
        &old_output,
        &old_vendor,
        &vendor_tree,
        lease,
        validate_implementation,
    )?;

    let new_prefix = root
        .join("build/toolchain/cargo/prefixes")
        .join(&lock_measurement.sha256);
    prepare_output_root(&new_prefix)?;
    let published = new_prefix.join("vendor");
    let existing_names = bounded_directory_names(
        &new_prefix,
        2,
        "current-lock Cargo vendor prefix before publication",
    )?;
    if (published.exists() && existing_names != ["vendor"])
        || (!published.exists() && !existing_names.is_empty())
    {
        return Err(
            "current-lock Cargo vendor prefix contains unreviewed partial-publication state"
                .to_owned(),
        );
    }
    if published.exists() {
        let published = exact_directory(&published, "reused current-lock Cargo vendor tree")?;
        require_same_tree(
            &vendor_tree,
            &measure_closure_tree(&published, MAX_TREE_FILES, MAX_TREE_BYTES)?,
            "existing current-lock Cargo vendor tree",
        )?;
        seal_reused_vendor_root(&published, &vendor_tree)?;
        validate_sealed_installation_modes(&published, &vendor_tree)?;
    } else {
        let mut staging = PrivateStaging::create(&new_prefix)?;
        let staged_vendor = staging.path.join("vendor");
        copy_exact_measured_tree(
            &old_vendor,
            &staged_vendor,
            &vendor_tree,
            "previously enrolled Cargo vendor tree",
        )?;
        seal_installation_directories(&staged_vendor)?;
        validate_sealed_installation_modes(&staged_vendor, &vendor_tree)?;
        sync_tree(&staged_vendor)?;
        require_same_tree(
            &vendor_tree,
            &measure_closure_tree(&old_vendor, MAX_TREE_FILES, MAX_TREE_BYTES)?,
            "old Cargo vendor tree after exact reuse copy",
        )?;
        revalidate_cargo_reuse_authority(
            running,
            running_measurement,
            &lock_path,
            &lock_measurement,
            &output_path,
            &old_output_measurement,
            &old_output,
            &old_vendor,
            &vendor_tree,
            lease,
            validate_implementation,
        )?;
        // Darwin requires the renamed directory itself to remain owner-writable.
        // Its complete contents and descendants are already sealed; the root is
        // resealed and remeasured before the enrollment lock can become visible.
        set_mode(&staged_vendor, 0o700)?;
        sync_directory(&staged_vendor)?;
        match fs::rename(&staged_vendor, &published) {
            Ok(()) => {
                seal_reused_vendor_root(&published, &vendor_tree)?;
                sync_directory(&new_prefix)?;
            }
            Err(_error) if published.exists() => {
                let concurrent = exact_directory(
                    &published,
                    "concurrently published current-lock Cargo vendor tree",
                )?;
                require_same_tree(
                    &vendor_tree,
                    &measure_closure_tree(&concurrent, MAX_TREE_FILES, MAX_TREE_BYTES)?,
                    "concurrently published current-lock Cargo vendor tree",
                )?;
                seal_reused_vendor_root(&concurrent, &vendor_tree)?;
                validate_sealed_installation_modes(&concurrent, &vendor_tree)?;
                sync_directory(&new_prefix)?;
            }
            Err(error) => {
                return Err(format!(
                    "cannot atomically publish reused Cargo vendor tree: {error}"
                ));
            }
        }
        destroy_private_staging(&mut staging, "Cargo vendor reuse staging tree")?;
    }

    let published = exact_directory(&published, "current-lock Cargo vendor tree")?;
    if bounded_directory_names(
        &new_prefix,
        1,
        "current-lock Cargo vendor prefix after publication",
    )? != ["vendor"]
    {
        return Err("current-lock Cargo vendor prefix has unexpected entries".to_owned());
    }
    require_same_tree(
        &vendor_tree,
        &measure_closure_tree(&published, MAX_TREE_FILES, MAX_TREE_BYTES)?,
        "published current-lock Cargo vendor tree",
    )?;
    validate_sealed_installation_modes(&published, &vendor_tree)?;
    validate_cargo_registry_closure(&published, &vendor_tree, &registry_packages)?;
    revalidate_cargo_reuse_authority(
        running,
        running_measurement,
        &lock_path,
        &lock_measurement,
        &output_path,
        &old_output_measurement,
        &old_output,
        &old_vendor,
        &vendor_tree,
        lease,
        validate_implementation,
    )?;

    let new_output = CargoOutput {
        cargo_lock_sha256: lock_measurement.sha256.clone(),
        ..old_output.clone()
    };
    replace_cargo_output_enrollment(
        &output_path,
        &old_output_measurement,
        &old_output,
        &new_output,
        &|| {
            revalidate_cargo_reuse_authority(
                running,
                running_measurement,
                &lock_path,
                &lock_measurement,
                &output_path,
                &old_output_measurement,
                &old_output,
                &old_vendor,
                &vendor_tree,
                lease,
                validate_implementation,
            )?;
            require_same_tree(
                &vendor_tree,
                &measure_closure_tree(&published, MAX_TREE_FILES, MAX_TREE_BYTES)?,
                "current-lock Cargo vendor tree immediately before enrollment",
            )?;
            validate_sealed_installation_modes(&published, &vendor_tree)
        },
    )?;
    if parse_cargo_output(&read_bounded_file(&output_path, MAX_LOCK_BYTES)?)? != new_output {
        return Err("new Cargo vendor enrollment failed exact revalidation".to_owned());
    }
    require_same_tree(
        &vendor_tree,
        &measure_closure_tree(&published, MAX_TREE_FILES, MAX_TREE_BYTES)?,
        "Cargo vendor tree after enrollment publication",
    )?;
    validate_sealed_installation_modes(&published, &vendor_tree)?;
    if measure_file(running, MAX_FILE_BYTES, true)? != *running_measurement
        || measure_file(&lock_path, MAX_LOCK_BYTES, false)? != lock_measurement
    {
        return Err("Cargo vendor reenrollment authority changed during publication".to_owned());
    }
    validate_implementation()?;
    println!("cargo_lock_sha256={}", new_output.cargo_lock_sha256);
    println!("cargo_vendor_tree_sha256={}", new_output.vendor_tree_sha256);
    println!("cargo_vendor_files={}", new_output.vendor_files);
    println!("cargo_vendor_bytes={}", new_output.vendor_bytes);
    println!("cargo_vendor={}", published.display());
    Ok(())
}

fn seal_reused_vendor_root(vendor: &Path, expected: &TreeMeasurement) -> Result<(), String> {
    require_same_tree(
        expected,
        &measure_closure_tree(vendor, MAX_TREE_FILES, MAX_TREE_BYTES)?,
        "reused Cargo vendor tree before root sealing",
    )?;
    let metadata = stable_metadata(vendor, "reused Cargo vendor root")?;
    #[cfg(unix)]
    if metadata.mode() & 0o7777 != 0o555 {
        if metadata.mode() & 0o7777 != 0o700 {
            return Err(
                "reused Cargo vendor root has an unsafe partial-publication mode".to_owned(),
            );
        }
        set_mode(vendor, 0o555)?;
    }
    #[cfg(not(unix))]
    return Err("Cargo vendor root sealing has no reviewed non-Unix contract".to_owned());
    sync_tree(vendor)?;
    require_same_tree(
        expected,
        &measure_closure_tree(vendor, MAX_TREE_FILES, MAX_TREE_BYTES)?,
        "reused Cargo vendor tree after root sealing",
    )?;
    validate_sealed_installation_modes(vendor, expected)
}

#[allow(clippy::too_many_arguments)]
fn revalidate_cargo_reuse_authority(
    running: &Path,
    running_measurement: &FileMeasurement,
    lock_path: &Path,
    lock_measurement: &FileMeasurement,
    output_path: &Path,
    output_measurement: &FileMeasurement,
    output: &CargoOutput,
    vendor: &Path,
    vendor_tree: &TreeMeasurement,
    lease: &CargoEnrollmentLease,
    validate_implementation: &dyn Fn() -> Result<(), String>,
) -> Result<(), String> {
    lease.validate()?;
    if measure_file(running, MAX_FILE_BYTES, true)? != *running_measurement
        || measure_file(lock_path, MAX_LOCK_BYTES, false)? != *lock_measurement
        || measure_file(output_path, MAX_LOCK_BYTES, false)? != *output_measurement
        || parse_cargo_output(&read_exact_measured_file(output_path, output_measurement)?)?
            != *output
    {
        return Err("Cargo vendor reuse authority changed during reenrollment".to_owned());
    }
    require_same_tree(
        vendor_tree,
        &measure_closure_tree(vendor, MAX_TREE_FILES, MAX_TREE_BYTES)?,
        "previously enrolled Cargo vendor tree",
    )?;
    validate_sealed_installation_modes(vendor, vendor_tree)?;
    validate_implementation()
}

fn validate_cargo_reuse_rust_enrollment(
    root: &Path,
    cargo_output: &CargoOutput,
) -> Result<(), String> {
    let rust_output = parse_rust_output(&read_bounded_file(
        &root.join("toolchain/rust.outputs.toml"),
        MAX_LOCK_BYTES,
    )?)?;
    if rust_output.cargo_sha256 != cargo_output.cargo_sha256
        || rust_output.channel != rust_toolchain_channel(root)?
        || rust_output.host != host_identity()?
        || rust_output.rust_toolchain_sha256
            != measure_file(&root.join("rust-toolchain.toml"), MAX_LOCK_BYTES, false)?.sha256
    {
        return Err(
            "old Cargo vendor enrollment is not bound to the exact current Rust enrollment"
                .to_owned(),
        );
    }
    Ok(())
}

fn replace_cargo_output_enrollment(
    path: &Path,
    old_measurement: &FileMeasurement,
    old_output: &CargoOutput,
    new_output: &CargoOutput,
    validate_publication: &dyn Fn() -> Result<(), String>,
) -> Result<(), String> {
    if old_output == new_output || old_output.cargo_lock_sha256 == new_output.cargo_lock_sha256 {
        return Err("Cargo vendor enrollment replacement does not change Cargo.lock".to_owned());
    }
    let parent = exact_directory(
        path.parent()
            .ok_or_else(|| "Cargo vendor enrollment has no parent".to_owned())?,
        "Cargo vendor enrollment directory",
    )?;
    let mut staging = PrivateStaging::create(&parent)?;
    let staged = staging.path.join("cargo.outputs.toml");
    let encoded = encode_cargo_output(new_output);
    write_new_bytes(&staged, encoded.as_bytes(), false)?;
    set_mode(&staged, 0o644)?;
    File::open(&staged)
        .and_then(|file| file.sync_all())
        .map_err(|error| format!("cannot sync staged Cargo vendor enrollment: {error}"))?;
    sync_directory(&staging.path)?;
    if parse_cargo_output(&read_bounded_file(&staged, MAX_LOCK_BYTES)?)? != *new_output
        || measure_file(path, MAX_LOCK_BYTES, false)? != *old_measurement
        || parse_cargo_output(&read_exact_measured_file(path, old_measurement)?)? != *old_output
    {
        return Err("Cargo vendor enrollment changed before atomic replacement".to_owned());
    }
    validate_publication()?;
    if measure_file(path, MAX_LOCK_BYTES, false)? != *old_measurement
        || parse_cargo_output(&read_exact_measured_file(path, old_measurement)?)? != *old_output
    {
        return Err(
            "Cargo vendor enrollment changed across the final publication guard".to_owned(),
        );
    }
    #[cfg(unix)]
    fs::rename(&staged, path)
        .map_err(|error| format!("cannot atomically replace Cargo vendor enrollment: {error}"))?;
    #[cfg(not(unix))]
    return Err("Cargo vendor enrollment replacement has no reviewed non-Unix contract".to_owned());
    sync_directory(&parent)?;
    destroy_private_staging(&mut staging, "Cargo vendor enrollment staging tree")?;
    if parse_cargo_output(&read_bounded_file(path, MAX_LOCK_BYTES)?)? != *new_output {
        return Err("atomically replaced Cargo vendor enrollment differs".to_owned());
    }
    Ok(())
}

fn parse_options(arguments: &[String]) -> Result<Options, String> {
    let mut options = Options {
        help: false,
        plan: false,
        integration_qemu: false,
        integration_qemu_case: None,
        output: None,
        qemu_bundle: None,
        cargo: None,
        rustc: None,
        cargo_home: None,
        jobs: default_jobs(),
    };
    let mut index = 0usize;
    while index < arguments.len() {
        let argument = &arguments[index];
        match argument.as_str() {
            "-h" | "--help" if !options.help => options.help = true,
            "--plan" if !options.plan => options.plan = true,
            "--integration-qemu" if !options.integration_qemu => {
                options.integration_qemu = true;
            }
            "--integration-qemu-case" if options.integration_qemu_case.is_none() => {
                let value = option_value(arguments, &mut index, "--integration-qemu-case")?;
                options.integration_qemu_case = Some(IntegrationQemuCase::parse(value)?);
            }
            "--output" if options.output.is_none() => {
                options.output = Some(option_path(arguments, &mut index, "--output")?);
            }
            "--qemu-bundle" if options.qemu_bundle.is_none() => {
                options.qemu_bundle = Some(option_path(arguments, &mut index, "--qemu-bundle")?);
            }
            "--cargo" if options.cargo.is_none() => {
                options.cargo = Some(option_path(arguments, &mut index, "--cargo")?);
            }
            "--rustc" if options.rustc.is_none() => {
                options.rustc = Some(option_path(arguments, &mut index, "--rustc")?);
            }
            "--cargo-home" if options.cargo_home.is_none() => {
                options.cargo_home = Some(option_path(arguments, &mut index, "--cargo-home")?);
            }
            "--jobs" => {
                let value = option_value(arguments, &mut index, "--jobs")?;
                options.jobs = value
                    .parse::<u32>()
                    .ok()
                    .filter(|jobs| (1..=MAX_JOBS).contains(jobs))
                    .ok_or_else(|| format!("--jobs must be an integer in 1..={MAX_JOBS}"))?;
            }
            _ => {
                return Err(format!(
                    "unknown or repeated dist option {argument:?}\n\n{HELP}"
                ));
            }
        }
        index = index
            .checked_add(1)
            .ok_or_else(|| "dist argument count overflow".to_owned())?;
    }
    if options.help && arguments.len() != 1 {
        return Err("--help cannot be combined with other dist options".to_owned());
    }
    if options.integration_qemu && options.plan {
        return Err("--integration-qemu cannot be combined with --plan".to_owned());
    }
    if options.integration_qemu_case.is_some() && !options.integration_qemu {
        return Err("--integration-qemu-case requires --integration-qemu".to_owned());
    }
    if options.integration_qemu && options.output.is_some() {
        return Err(
            "--integration-qemu is private and cannot be combined with --output".to_owned(),
        );
    }
    Ok(options)
}

fn parse_cargo_vendor_options(arguments: &[String]) -> Result<CargoVendorOptions, String> {
    let mut options = CargoVendorOptions {
        help: false,
        record_output: false,
        reuse_enrolled: false,
        cargo: None,
        rustc: None,
        cargo_home: None,
    };
    let mut index = 0usize;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "-h" | "--help" if !options.help => options.help = true,
            "--record-output" if !options.record_output => options.record_output = true,
            "--reuse-enrolled" if !options.reuse_enrolled => options.reuse_enrolled = true,
            "--cargo" if options.cargo.is_none() => {
                options.cargo = Some(option_path(arguments, &mut index, "--cargo")?);
            }
            "--rustc" if options.rustc.is_none() => {
                options.rustc = Some(option_path(arguments, &mut index, "--rustc")?);
            }
            "--cargo-home" if options.cargo_home.is_none() => {
                options.cargo_home = Some(option_path(arguments, &mut index, "--cargo-home")?);
            }
            argument => {
                return Err(format!(
                    "unknown or repeated cargo-vendor option {argument:?}\n\n{CARGO_VENDOR_HELP}"
                ));
            }
        }
        index = index
            .checked_add(1)
            .ok_or_else(|| "cargo-vendor argument count overflow".to_owned())?;
    }
    if options.help && arguments.len() != 1 {
        return Err("--help cannot be combined with other cargo-vendor options".to_owned());
    }
    if options.record_output != options.reuse_enrolled {
        return Err(
            "--record-output and --reuse-enrolled must be supplied together for explicit offline reenrollment"
                .to_owned(),
        );
    }
    if options.record_output
        && (options.cargo.is_some() || options.rustc.is_some() || options.cargo_home.is_some())
    {
        return Err(
            "offline Cargo vendor reenrollment does not accept or invoke Cargo, rustc, or Cargo home"
                .to_owned(),
        );
    }
    Ok(options)
}

fn option_path(arguments: &[String], index: &mut usize, name: &str) -> Result<PathBuf, String> {
    Ok(PathBuf::from(option_value(arguments, index, name)?))
}

fn option_value<'a>(
    arguments: &'a [String],
    index: &mut usize,
    name: &str,
) -> Result<&'a str, String> {
    *index = index
        .checked_add(1)
        .ok_or_else(|| "dist argument index overflow".to_owned())?;
    arguments
        .get(*index)
        .map(String::as_str)
        .ok_or_else(|| format!("{name} requires a value"))
}

fn default_jobs() -> u32 {
    thread::available_parallelism()
        .ok()
        .and_then(|count| u32::try_from(count.get()).ok())
        .unwrap_or(DEFAULT_JOBS)
        .min(MAX_JOBS)
}

fn host_identity() -> Result<String, String> {
    match (env::consts::ARCH, env::consts::OS) {
        ("aarch64", "macos") => Ok("aarch64-apple-darwin".to_owned()),
        ("x86_64", "macos") => Ok("x86_64-apple-darwin".to_owned()),
        (architecture, operating_system) => Err(format!(
            "distribution assembly has no authenticated host contract for {architecture}-{operating_system}"
        )),
    }
}

fn validate_dist_implementation(root: &Path) -> Result<String, String> {
    let embedded = dist_implementation_digest(DIST_IMPLEMENTATION_INPUTS)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(DIST_IMPLEMENTATION_INPUTS.len())
        .map_err(|_| "cannot reserve distribution implementation inputs".to_owned())?;
    for (path, _) in DIST_IMPLEMENTATION_INPUTS {
        bytes.push(read_bounded_file(&root.join(path), MAX_MANIFEST_BYTES)?);
    }
    let mut current = Vec::new();
    current
        .try_reserve_exact(DIST_IMPLEMENTATION_INPUTS.len())
        .map_err(|_| "cannot reserve current distribution implementation inputs".to_owned())?;
    for ((path, _), value) in DIST_IMPLEMENTATION_INPUTS.iter().zip(&bytes) {
        current.push((*path, value.as_slice()));
    }
    let current = dist_implementation_digest(&current)?;
    if current != embedded {
        return Err(
            "running xtask was not built from the current distribution implementation; rebuild xtask before planning or assembling a release"
                .to_owned(),
        );
    }
    Ok(embedded)
}

fn dist_implementation_digest(inputs: &[(&str, &[u8])]) -> Result<String, String> {
    let count = u64::try_from(inputs.len())
        .map_err(|_| "distribution implementation input count does not fit u64".to_owned())?;
    if inputs.len() != DIST_IMPLEMENTATION_INPUTS.len()
        || inputs.windows(2).any(|pair| pair[0].0 >= pair[1].0)
        || inputs.iter().any(|(path, bytes)| {
            bytes.is_empty() || !portable_tree_path(path) || path.starts_with("../")
        })
    {
        return Err("distribution implementation inputs are not exact and canonical".to_owned());
    }
    let mut digest = Sha256::new();
    digest.update(DIST_IMPLEMENTATION_MAGIC);
    digest.update(DIST_IMPLEMENTATION_VERSION.to_le_bytes());
    digest.update(count.to_le_bytes());
    for (path, bytes) in inputs {
        update_length_prefixed(&mut digest, path.as_bytes())?;
        update_length_prefixed(&mut digest, bytes)?;
    }
    Ok(lower_hex(&digest.finalize()))
}

fn load_plan(
    root: &Path,
    options: &Options,
    orchestrator: PathBuf,
    orchestrator_measurement: FileMeasurement,
    dist_implementation_sha256: String,
) -> Result<ReleasePlan, String> {
    let root = exact_directory(root, "workspace root")?;
    let host = host_identity()?;
    let release = workspace_release(&root)?;
    let source = measure_source_tree(&root)?;
    let emulation_path = root.join("toolchain/emulation.lock.toml");
    let emulation_bytes = read_bounded_file(&emulation_path, MAX_LOCK_BYTES)?;
    let emulation = parse_emulation_lock(&emulation_bytes)?;
    let output_lock_path = root.join("toolchain/emulation.outputs.toml");
    let output_lock_bytes = read_bounded_file(&output_lock_path, MAX_LOCK_BYTES).map_err(|error| {
        format!(
            "authenticated QEMU output enrollment is unavailable: {error}; build QEMU 10.1.5 from the signed pinned source and enroll its reviewed payload in toolchain/emulation.outputs.toml"
        )
    })?;
    let emulation_output = parse_emulation_output(&output_lock_bytes)?;
    validate_emulation_output(&emulation, &emulation_output, &host)?;
    let qemu_bundle = match options.qemu_bundle.as_ref() {
        Some(path) => exact_directory(path, "QEMU payload")?,
        None => root
            .join("build/toolchain/qemu/prefixes")
            .join(format!(
                "{}-{}",
                emulation.qemu_version, emulation_output.native_input_sha256
            ))
            .join("bundle"),
    };
    let qemu_bundle = exact_directory(&qemu_bundle, "enrolled QEMU payload")?;
    let qemu = measure_tree(&qemu_bundle, MAX_TREE_FILES, MAX_TREE_BYTES)?;
    validate_qemu_bundle(&qemu_bundle, &qemu, &emulation, &emulation_output)?;

    let native_authority = llvm::verified_authority_for_distribution(&root)?;
    let native = native_authority.environment().clone();
    let llvm_licenses = measure_tree(
        &native.prefix.join("share/wrela/licenses"),
        MAX_TREE_FILES,
        MAX_TREE_BYTES,
    )?;
    let llvm_provenance = measure_file(
        &native
            .prefix
            .parent()
            .ok_or_else(|| "verified LLVM prefix has no provenance parent".to_owned())?
            .join("provenance.txt"),
        MAX_LOCK_BYTES,
        false,
    )?;
    let llvm_prefix_tree_sha256 = enrolled_llvm_prefix_tree_sha256(&root)?;

    let runtime_path =
        root.join("toolchain/targets/aarch64-qemu-virt-uefi/runtime-src/runtime-object.lock.toml");
    let runtime = parse_runtime_lock(&read_bounded_file(&runtime_path, MAX_LOCK_BYTES)?)?;
    validate_runtime_inputs(&root, &runtime, &native.cxx)?;
    let rust_toolchain = rust_toolchain_channel(&root)?;
    let rust_output = parse_rust_output(&read_bounded_file(
        &root.join("toolchain/rust.outputs.toml"),
        MAX_LOCK_BYTES,
    )?)?;
    if rust_output.channel != rust_toolchain
        || rust_output.host != host
        || measure_file(&root.join("rust-toolchain.toml"), MAX_LOCK_BYTES, false)?.sha256
            != rust_output.rust_toolchain_sha256
    {
        return Err("Rust output enrollment differs from rust-toolchain.toml or host".to_owned());
    }
    let cargo_output = parse_cargo_output(&read_bounded_file(
        &root.join("toolchain/cargo.outputs.toml"),
        MAX_LOCK_BYTES,
    )?)?;
    if measure_file(&root.join("Cargo.lock"), MAX_LOCK_BYTES, false)?.sha256
        != cargo_output.cargo_lock_sha256
        || cargo_output.cargo_sha256 != rust_output.cargo_sha256
    {
        return Err(
            "Cargo vendor enrollment differs from Cargo.lock or Rust enrollment".to_owned(),
        );
    }
    let cargo_vendor = exact_directory(
        &root
            .join("build/toolchain/cargo/prefixes")
            .join(&cargo_output.cargo_lock_sha256)
            .join("vendor"),
        "enrolled Cargo vendor tree",
    )?;
    let cargo_vendor_tree = measure_closure_tree(&cargo_vendor, MAX_TREE_FILES, MAX_TREE_BYTES)?;
    if cargo_vendor_tree.sha256 != cargo_output.vendor_tree_sha256
        || cargo_vendor_tree.files != cargo_output.vendor_files
        || cargo_vendor_tree.bytes != cargo_output.vendor_bytes
    {
        return Err("Cargo vendor tree differs from its reviewed enrollment".to_owned());
    }
    validate_sealed_installation_modes(&cargo_vendor, &cargo_vendor_tree)?;
    let rust_crate_licenses = derive_cargo_license_tree(&cargo_vendor_tree)?;
    let tools = resolve_build_tools(options, &host, &rust_output)?;
    validate_rust_toolchain(&tools, &rust_toolchain)?;
    let rust_toolchain_licenses = derive_rust_toolchain_license_tree(&tools.rust_sysroot_tree)?;
    let rust_licenses = combine_rust_license_trees(&rust_crate_licenses, &rust_toolchain_licenses)?;
    let output = output_directory(&root, options.output.as_deref())?;
    Ok(ReleasePlan {
        release,
        host,
        rust_toolchain,
        rust_output,
        cargo_output,
        cargo_vendor,
        cargo_vendor_tree,
        rust_crate_licenses,
        rust_toolchain_licenses,
        rust_licenses,
        output,
        qemu_bundle,
        emulation,
        emulation_output,
        runtime,
        native,
        native_authority,
        llvm_licenses,
        llvm_provenance,
        llvm_prefix_tree_sha256,
        tools,
        orchestrator,
        orchestrator_measurement,
        dist_implementation_sha256,
        source,
        qemu,
    })
}

fn print_plan(plan: &ReleasePlan) {
    println!("release={}", plan.release);
    println!("host={}", plan.host);
    println!("rust_toolchain={}", plan.rust_toolchain);
    println!(
        "rust_sysroot_tree_sha256={}",
        plan.rust_output.sysroot_tree_sha256
    );
    println!("rust_sysroot_files={}", plan.rust_output.sysroot_files);
    println!("rust_sysroot_bytes={}", plan.rust_output.sysroot_bytes);
    println!("cargo_lock_sha256={}", plan.cargo_output.cargo_lock_sha256);
    println!(
        "cargo_vendor_tree_sha256={}",
        plan.cargo_output.vendor_tree_sha256
    );
    println!("cargo_vendor_files={}", plan.cargo_output.vendor_files);
    println!("cargo_vendor_bytes={}", plan.cargo_output.vendor_bytes);
    println!("rust_license_tree_sha256={}", plan.rust_licenses.sha256);
    println!("source_tree_sha256={}", plan.source.sha256);
    println!("source_files={}", plan.source.files);
    println!(
        "dist_implementation_sha256={}",
        plan.dist_implementation_sha256
    );
    println!(
        "dist_orchestrator_sha256={}",
        plan.orchestrator_measurement.sha256
    );
    println!("llvm_prefix={}", plan.native.prefix.display());
    println!("llvm_prefix_tree_sha256={}", plan.llvm_prefix_tree_sha256);
    println!(
        "qemu_native_input_sha256={}",
        plan.emulation_output.native_input_sha256
    );
    println!("qemu_bundle_tree_sha256={}", plan.qemu.sha256);
    println!("qemu_bundle={}", plan.qemu_bundle.display());
    println!("output={}", plan.output.display());
}

fn parse_emulation_lock(bytes: &[u8]) -> Result<EmulationLock, String> {
    let source = canonical_text(bytes, "toolchain/emulation.lock.toml")?;
    #[derive(Clone, Copy)]
    enum Section {
        Root,
        Qemu,
        Firmware(usize),
    }
    let mut section = Section::Root;
    let mut root = BTreeMap::new();
    let mut qemu = BTreeMap::new();
    let mut firmware = Vec::<BTreeMap<String, String>>::new();
    for (line_index, raw_line) in source.lines().enumerate() {
        let line_number = line_index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match line {
            "[qemu]" => {
                if !matches!(section, Section::Root) || !qemu.is_empty() {
                    return Err(format!(
                        "noncanonical emulation qemu table on line {line_number}"
                    ));
                }
                section = Section::Qemu;
            }
            "[[firmware]]" => {
                if matches!(section, Section::Root) || firmware.len() >= 2 {
                    return Err(format!(
                        "noncanonical emulation firmware table on line {line_number}"
                    ));
                }
                firmware.push(BTreeMap::new());
                section = Section::Firmware(firmware.len() - 1);
            }
            _ if line.starts_with('[') => {
                return Err(format!(
                    "unknown emulation table on line {line_number}: {line:?}"
                ));
            }
            _ => {
                let (key, value) = assignment(line, line_number)?;
                let fields = match section {
                    Section::Root => &mut root,
                    Section::Qemu => &mut qemu,
                    Section::Firmware(index) => firmware
                        .get_mut(index)
                        .ok_or_else(|| "emulation parser lost firmware table".to_owned())?,
                };
                if fields.insert(key.to_owned(), value.to_owned()).is_some() {
                    return Err(format!(
                        "duplicate emulation field {key:?} on line {line_number}"
                    ));
                }
            }
        }
    }
    require_keys(&root, &["schema"], "emulation root")?;
    if parse_u64(required(&root, "schema")?, "emulation schema")? != 1 {
        return Err("unsupported emulation lock schema".to_owned());
    }
    require_keys(
        &qemu,
        &[
            "version",
            "source",
            "sha256",
            "signature",
            "signing_key_fingerprint",
            "system_targets",
            "machine_contract",
            "cpu_contract",
            "accelerator_contract",
        ],
        "emulation qemu",
    )?;
    let qemu_version = parse_string(required(&qemu, "version")?, "qemu version")?;
    if qemu_version != "10.1.5" {
        return Err(format!(
            "emulation lock QEMU version {qemu_version:?} is not the revision-0.1 pin 10.1.5"
        ));
    }
    let source_url = parse_string(required(&qemu, "source")?, "qemu source")?;
    let expected_source = format!("https://download.qemu.org/qemu-{qemu_version}.tar.xz");
    if source_url != expected_source {
        return Err("emulation lock QEMU source URL is not the exact HTTPS release".to_owned());
    }
    let signature = parse_string(required(&qemu, "signature")?, "qemu signature")?;
    if signature != format!("{source_url}.sig") {
        return Err("emulation lock QEMU signature URL does not match its source".to_owned());
    }
    let source_sha256 = digest_string(required(&qemu, "sha256")?, "qemu source SHA-256")?;
    let signing_key_fingerprint = parse_string(
        required(&qemu, "signing_key_fingerprint")?,
        "qemu signing fingerprint",
    )?;
    if signing_key_fingerprint.len() != 40
        || !signing_key_fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'A'..=b'F'))
    {
        return Err(
            "QEMU signing key fingerprint is not canonical uppercase hexadecimal".to_owned(),
        );
    }
    if required(&qemu, "system_targets")? != "[\"aarch64-softmmu\"]" {
        return Err("emulation lock must build exactly aarch64-softmmu".to_owned());
    }
    if firmware.len() != 2 {
        return Err("emulation lock must declare exactly two firmware images".to_owned());
    }
    let firmware_code = parse_firmware_pin(&firmware[0])?;
    let firmware_variables = parse_firmware_pin(&firmware[1])?;
    if firmware_code.name != "code"
        || firmware_code.source_path != "pc-bios/edk2-aarch64-code.fd.bz2"
        || firmware_code.install_path != "targets/aarch64-qemu-virt-uefi/firmware/QEMU_EFI.fd"
        || firmware_variables.name != "variables-template"
        || firmware_variables.source_path != "pc-bios/edk2-arm-vars.fd.bz2"
        || firmware_variables.install_path != "targets/aarch64-qemu-virt-uefi/firmware/QEMU_VARS.fd"
        || firmware_code.license_manifest != "pc-bios/edk2-licenses.txt"
        || firmware_variables.license_manifest != firmware_code.license_manifest
    {
        return Err("emulation firmware entries do not match the fixed target layout".to_owned());
    }
    Ok(EmulationLock {
        bytes_sha256: sha256_bytes(bytes),
        qemu_version,
        source: source_url,
        source_sha256,
        signature,
        signing_key_fingerprint,
        machine_contract: parse_string(
            required(&qemu, "machine_contract")?,
            "qemu machine contract",
        )?,
        cpu_contract: parse_string(required(&qemu, "cpu_contract")?, "qemu CPU contract")?,
        accelerator_contract: parse_string(
            required(&qemu, "accelerator_contract")?,
            "qemu accelerator contract",
        )?,
        firmware_code,
        firmware_variables,
    })
}

fn parse_firmware_pin(fields: &BTreeMap<String, String>) -> Result<FirmwarePin, String> {
    require_keys(
        fields,
        &[
            "name",
            "source_path",
            "compression",
            "install_path",
            "sha256",
            "license_manifest",
        ],
        "emulation firmware",
    )?;
    if parse_string(required(fields, "compression")?, "firmware compression")? != "bzip2" {
        return Err("emulation firmware compression must be exactly bzip2".to_owned());
    }
    Ok(FirmwarePin {
        name: parse_string(required(fields, "name")?, "firmware name")?,
        source_path: parse_string(required(fields, "source_path")?, "firmware source path")?,
        install_path: parse_string(required(fields, "install_path")?, "firmware install path")?,
        sha256: digest_string(required(fields, "sha256")?, "firmware SHA-256")?,
        license_manifest: parse_string(
            required(fields, "license_manifest")?,
            "firmware license manifest",
        )?,
    })
}

fn parse_emulation_output(bytes: &[u8]) -> Result<EmulationOutput, String> {
    let source = canonical_text(bytes, "toolchain/emulation.outputs.toml")?;
    let fields = flat_assignments(source, "emulation output")?;
    require_keys(
        &fields,
        &[
            "schema",
            "emulation_lock_sha256",
            "native_input_sha256",
            "qemu_version",
            "host",
            "bundle_tree_sha256",
            "bundle_files",
            "bundle_bytes",
            "qemu_sha256",
            "qemu_bytes",
            "firmware_code_sha256",
            "firmware_code_bytes",
            "firmware_variables_sha256",
            "firmware_variables_bytes",
        ],
        "emulation output",
    )?;
    if parse_u64(required(&fields, "schema")?, "emulation output schema")?
        != u64::from(EMULATION_OUTPUT_SCHEMA)
    {
        return Err("unsupported emulation output schema".to_owned());
    }
    let output = EmulationOutput {
        emulation_lock_sha256: digest_string(
            required(&fields, "emulation_lock_sha256")?,
            "emulation lock SHA-256",
        )?,
        native_input_sha256: digest_string(
            required(&fields, "native_input_sha256")?,
            "QEMU native input SHA-256",
        )?,
        qemu_version: parse_string(required(&fields, "qemu_version")?, "QEMU version")?,
        host: parse_string(required(&fields, "host")?, "QEMU output host")?,
        bundle_tree_sha256: digest_string(
            required(&fields, "bundle_tree_sha256")?,
            "QEMU bundle tree SHA-256",
        )?,
        bundle_files: positive_u64(required(&fields, "bundle_files")?, "QEMU bundle files")?,
        bundle_bytes: positive_u64(required(&fields, "bundle_bytes")?, "QEMU bundle bytes")?,
        qemu_sha256: digest_string(required(&fields, "qemu_sha256")?, "QEMU SHA-256")?,
        qemu_bytes: positive_u64(required(&fields, "qemu_bytes")?, "QEMU bytes")?,
        firmware_code_sha256: digest_string(
            required(&fields, "firmware_code_sha256")?,
            "firmware code SHA-256",
        )?,
        firmware_code_bytes: positive_u64(
            required(&fields, "firmware_code_bytes")?,
            "firmware code bytes",
        )?,
        firmware_variables_sha256: digest_string(
            required(&fields, "firmware_variables_sha256")?,
            "firmware variables SHA-256",
        )?,
        firmware_variables_bytes: positive_u64(
            required(&fields, "firmware_variables_bytes")?,
            "firmware variables bytes",
        )?,
    };
    if encode_emulation_output(&output).as_bytes() != bytes {
        return Err("toolchain/emulation.outputs.toml is not canonical".to_owned());
    }
    Ok(output)
}

fn encode_emulation_output(output: &EmulationOutput) -> String {
    format!(
        "schema = {EMULATION_OUTPUT_SCHEMA}\n\
emulation_lock_sha256 = \"{}\"\n\
native_input_sha256 = \"{}\"\n\
qemu_version = \"{}\"\n\
host = \"{}\"\n\
bundle_tree_sha256 = \"{}\"\n\
bundle_files = {}\n\
bundle_bytes = {}\n\
qemu_sha256 = \"{}\"\n\
qemu_bytes = {}\n\
firmware_code_sha256 = \"{}\"\n\
firmware_code_bytes = {}\n\
firmware_variables_sha256 = \"{}\"\n\
firmware_variables_bytes = {}\n",
        output.emulation_lock_sha256,
        output.native_input_sha256,
        output.qemu_version,
        output.host,
        output.bundle_tree_sha256,
        output.bundle_files,
        output.bundle_bytes,
        output.qemu_sha256,
        output.qemu_bytes,
        output.firmware_code_sha256,
        output.firmware_code_bytes,
        output.firmware_variables_sha256,
        output.firmware_variables_bytes,
    )
}

fn validate_emulation_output(
    lock: &EmulationLock,
    output: &EmulationOutput,
    host: &str,
) -> Result<(), String> {
    if output.emulation_lock_sha256 != lock.bytes_sha256
        || output.qemu_version != lock.qemu_version
        || output.host != host
        || output.firmware_code_sha256 != lock.firmware_code.sha256
        || output.firmware_variables_sha256 != lock.firmware_variables.sha256
    {
        return Err(
            "authenticated QEMU output enrollment is stale for the current lock, host, or firmware"
                .to_owned(),
        );
    }
    Ok(())
}

fn parse_runtime_lock(bytes: &[u8]) -> Result<RuntimeLock, String> {
    let source = canonical_text(bytes, "runtime-object.lock.toml")?;
    let fields = flat_assignments(source, "runtime object lock")?;
    require_keys(
        &fields,
        &[
            "schema",
            "target",
            "runtime_abi_version",
            "compiler_identity",
            "compiler_sha256",
            "builder_sha256",
            "source_sha256",
            "object_sha256",
            "object_bytes",
            "coff_machine",
            "relocations",
            "undefined_symbols",
        ],
        "runtime object lock",
    )?;
    if parse_u64(required(&fields, "schema")?, "runtime lock schema")? != 1 {
        return Err("unsupported runtime object lock schema".to_owned());
    }
    Ok(RuntimeLock {
        target: parse_string(required(&fields, "target")?, "runtime target")?,
        runtime_abi_version: u32::try_from(parse_u64(
            required(&fields, "runtime_abi_version")?,
            "runtime ABI version",
        )?)
        .map_err(|_| "runtime ABI version does not fit u32".to_owned())?,
        compiler_identity: parse_string(
            required(&fields, "compiler_identity")?,
            "runtime compiler identity",
        )?,
        compiler_sha256: digest_string(
            required(&fields, "compiler_sha256")?,
            "runtime compiler SHA-256",
        )?,
        builder_sha256: digest_string(
            required(&fields, "builder_sha256")?,
            "runtime builder SHA-256",
        )?,
        source_sha256: digest_string(
            required(&fields, "source_sha256")?,
            "runtime source SHA-256",
        )?,
        object_sha256: digest_string(
            required(&fields, "object_sha256")?,
            "runtime object SHA-256",
        )?,
        object_bytes: positive_u64(required(&fields, "object_bytes")?, "runtime object bytes")?,
        coff_machine: parse_string(required(&fields, "coff_machine")?, "runtime COFF machine")?,
        relocations: positive_u64(required(&fields, "relocations")?, "runtime relocations")?,
        undefined_symbols: parse_u64(
            required(&fields, "undefined_symbols")?,
            "runtime undefined symbols",
        )?,
    })
}

fn parse_rust_output(bytes: &[u8]) -> Result<RustOutput, String> {
    let source = canonical_text(bytes, "Rust output enrollment")?;
    let fields = flat_assignments(source, "Rust output enrollment")?;
    if fields.len() != 13 || parse_u64(required(&fields, "schema")?, "Rust output schema")? != 1 {
        return Err("Rust output enrollment has an unsupported schema or fields".to_owned());
    }
    let output = RustOutput {
        rust_toolchain_sha256: digest_string(
            required(&fields, "rust_toolchain_sha256")?,
            "rust-toolchain SHA-256",
        )?,
        channel: parse_string(required(&fields, "channel")?, "Rust channel")?,
        host: parse_string(required(&fields, "host")?, "Rust host")?,
        cargo_sha256: digest_string(required(&fields, "cargo_sha256")?, "Cargo SHA-256")?,
        cargo_bytes: positive_u64(required(&fields, "cargo_bytes")?, "Cargo bytes")?,
        rustc_sha256: digest_string(required(&fields, "rustc_sha256")?, "rustc SHA-256")?,
        rustc_bytes: positive_u64(required(&fields, "rustc_bytes")?, "rustc bytes")?,
        cargo_version_sha256: digest_string(
            required(&fields, "cargo_version_sha256")?,
            "Cargo version SHA-256",
        )?,
        rustc_version_sha256: digest_string(
            required(&fields, "rustc_version_sha256")?,
            "rustc version SHA-256",
        )?,
        sysroot_tree_sha256: digest_string(
            required(&fields, "sysroot_tree_sha256")?,
            "Rust sysroot tree SHA-256",
        )?,
        sysroot_files: positive_u64(required(&fields, "sysroot_files")?, "Rust sysroot files")?,
        sysroot_bytes: positive_u64(required(&fields, "sysroot_bytes")?, "Rust sysroot bytes")?,
    };
    if !valid_release(&output.channel)
        || !valid_release(&output.host)
        || encode_rust_output(&output).as_bytes() != bytes
    {
        return Err(
            "Rust output enrollment is not in canonical field order or encoding".to_owned(),
        );
    }
    Ok(output)
}

fn encode_rust_output(output: &RustOutput) -> String {
    format!(
        "schema = 1\n\
rust_toolchain_sha256 = \"{}\"\n\
channel = \"{}\"\n\
host = \"{}\"\n\
cargo_sha256 = \"{}\"\n\
cargo_bytes = {}\n\
rustc_sha256 = \"{}\"\n\
rustc_bytes = {}\n\
cargo_version_sha256 = \"{}\"\n\
rustc_version_sha256 = \"{}\"\n\
sysroot_tree_sha256 = \"{}\"\n\
sysroot_files = {}\n\
sysroot_bytes = {}\n",
        output.rust_toolchain_sha256,
        output.channel,
        output.host,
        output.cargo_sha256,
        output.cargo_bytes,
        output.rustc_sha256,
        output.rustc_bytes,
        output.cargo_version_sha256,
        output.rustc_version_sha256,
        output.sysroot_tree_sha256,
        output.sysroot_files,
        output.sysroot_bytes,
    )
}

fn parse_cargo_output(bytes: &[u8]) -> Result<CargoOutput, String> {
    let source = canonical_text(bytes, "Cargo vendor output enrollment")?;
    let fields = flat_assignments(source, "Cargo vendor output enrollment")?;
    if fields.len() != 6 || parse_u64(required(&fields, "schema")?, "Cargo output schema")? != 1 {
        return Err(
            "Cargo vendor output enrollment has an unsupported schema or fields".to_owned(),
        );
    }
    let output = CargoOutput {
        cargo_lock_sha256: digest_string(
            required(&fields, "cargo_lock_sha256")?,
            "Cargo.lock SHA-256",
        )?,
        cargo_sha256: digest_string(required(&fields, "cargo_sha256")?, "Cargo SHA-256")?,
        vendor_tree_sha256: digest_string(
            required(&fields, "vendor_tree_sha256")?,
            "Cargo vendor tree SHA-256",
        )?,
        vendor_files: positive_u64(required(&fields, "vendor_files")?, "Cargo vendor files")?,
        vendor_bytes: positive_u64(required(&fields, "vendor_bytes")?, "Cargo vendor bytes")?,
    };
    if encode_cargo_output(&output).as_bytes() != bytes {
        return Err(
            "Cargo vendor output enrollment is not in canonical field order or encoding".to_owned(),
        );
    }
    Ok(output)
}

fn encode_cargo_output(output: &CargoOutput) -> String {
    format!(
        "schema = 1\n\
cargo_lock_sha256 = \"{}\"\n\
cargo_sha256 = \"{}\"\n\
vendor_tree_sha256 = \"{}\"\n\
vendor_files = {}\n\
vendor_bytes = {}\n",
        output.cargo_lock_sha256,
        output.cargo_sha256,
        output.vendor_tree_sha256,
        output.vendor_files,
        output.vendor_bytes,
    )
}

fn parse_cargo_registry_packages(bytes: &[u8]) -> Result<Vec<CargoRegistryPackage>, String> {
    const REGISTRY: &str = "registry+https://github.com/rust-lang/crates.io-index";

    fn finish_package(
        fields: &mut Option<BTreeMap<String, String>>,
        packages: &mut Vec<CargoRegistryPackage>,
    ) -> Result<(), String> {
        let Some(fields) = fields.take() else {
            return Ok(());
        };
        if fields.keys().any(|key| {
            !matches!(
                key.as_str(),
                "name" | "version" | "source" | "checksum" | "dependencies"
            )
        }) || fields.get("dependencies").is_some_and(|value| value != "[")
        {
            return Err(
                "Cargo.lock package contains an unknown or noncanonical format-4 field".to_owned(),
            );
        }
        let name = parse_string(required(&fields, "name")?, "Cargo.lock package name")?;
        let version = parse_string(required(&fields, "version")?, "Cargo.lock package version")?;
        match (fields.get("source"), fields.get("checksum")) {
            (None, None) => Ok(()),
            (Some(source), Some(checksum)) => {
                let source = parse_string(source, "Cargo.lock package source")?;
                if source != REGISTRY {
                    return Err(format!(
                        "Cargo.lock contains unsupported external package source {source:?}"
                    ));
                }
                let checksum = digest_string(checksum, "Cargo.lock package checksum")?;
                let directory = format!("{name}-{version}");
                if !portable_component(&directory) {
                    return Err(format!(
                        "Cargo.lock registry package directory is not portable: {directory:?}"
                    ));
                }
                packages
                    .try_reserve(1)
                    .map_err(|_| "cannot reserve Cargo.lock registry closure".to_owned())?;
                packages.push(CargoRegistryPackage {
                    directory,
                    checksum,
                });
                Ok(())
            }
            _ => Err(format!(
                "Cargo.lock package {name} {version} must contain both source and checksum or neither"
            )),
        }
    }

    let source = canonical_text(bytes, "Cargo.lock")?;
    let mut version = None;
    let mut package = None::<BTreeMap<String, String>>;
    let mut packages = Vec::new();
    let mut in_array = false;
    for (line_index, raw_line) in source.lines().enumerate() {
        let line_number = line_index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if in_array {
            if line == "]" {
                in_array = false;
            } else {
                let value = line.strip_suffix(',').ok_or_else(|| {
                    format!("Cargo.lock contains a malformed array item on line {line_number}")
                })?;
                parse_string(value, "Cargo.lock dependency").map_err(|_| {
                    format!("Cargo.lock contains a malformed array item on line {line_number}")
                })?;
            }
            continue;
        }
        if line == "[[package]]" {
            finish_package(&mut package, &mut packages)?;
            package = Some(BTreeMap::new());
            continue;
        }
        if line.starts_with('[') {
            return Err(format!(
                "Cargo.lock contains an unexpected table on line {line_number}"
            ));
        }
        let (key, value) = assignment(line, line_number)?;
        if let Some(fields) = package.as_mut() {
            if fields.insert(key.to_owned(), value.to_owned()).is_some() {
                return Err(format!(
                    "Cargo.lock package repeats field {key:?} on line {line_number}"
                ));
            }
            if value == "[" {
                in_array = true;
            }
        } else {
            if key != "version" || version.is_some() {
                return Err(format!(
                    "Cargo.lock contains an unexpected root field on line {line_number}"
                ));
            }
            version = Some(parse_u64(value, "Cargo.lock format version")?);
        }
    }
    if in_array {
        return Err("Cargo.lock ends inside an array".to_owned());
    }
    finish_package(&mut package, &mut packages)?;
    if version != Some(4) {
        return Err("Cargo.lock must use exact format version 4".to_owned());
    }
    packages.sort_unstable();
    if packages.is_empty()
        || packages.len() > usize::try_from(MAX_TREE_FILES).unwrap_or(usize::MAX)
        || packages.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err("Cargo.lock registry closure is empty, duplicated, or oversized".to_owned());
    }
    Ok(packages)
}

fn validate_cargo_registry_closure(
    vendor: &Path,
    vendor_tree: &TreeMeasurement,
    packages: &[CargoRegistryPackage],
) -> Result<(), String> {
    if packages.is_empty() || packages.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("Cargo registry closure is empty, duplicated, or unordered".to_owned());
    }
    let mut directories = BTreeSet::new();
    for record in &vendor_tree.records {
        let (directory, _) = record.path.split_once('/').ok_or_else(|| {
            "Cargo vendor tree contains a file outside a package directory".to_owned()
        })?;
        if !portable_component(directory) {
            return Err("Cargo vendor tree contains a nonportable package directory".to_owned());
        }
        directories.insert(directory.to_owned());
    }
    let expected = packages
        .iter()
        .map(|package| package.directory.clone())
        .collect::<BTreeSet<_>>();
    if directories != expected {
        return Err(
            "current Cargo.lock registry closure differs from the enrolled vendor packages"
                .to_owned(),
        );
    }
    for package in packages {
        let relative = format!("{}/.cargo-checksum.json", package.directory);
        let record = required_record(vendor_tree, &relative)?;
        if record.executable || record.bytes > MAX_MANIFEST_BYTES {
            return Err(format!(
                "Cargo vendor checksum manifest has invalid mode or size: {relative}"
            ));
        }
        let measurement = FileMeasurement {
            sha256: record.sha256.clone(),
            bytes: record.bytes,
        };
        let bytes = read_exact_measured_file(&vendor.join(&relative), &measurement)?;
        let decoded: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("cannot decode Cargo vendor {relative}: {error}"))?;
        if serde_json::to_vec(&decoded)
            .map_err(|error| format!("cannot reencode Cargo vendor {relative}: {error}"))?
            != bytes
        {
            return Err(format!(
                "Cargo vendor checksum manifest is not exact canonical JSON: {relative}"
            ));
        }
        let object = decoded.as_object().ok_or_else(|| {
            format!("Cargo vendor checksum manifest is not an object: {relative}")
        })?;
        if object.len() != 2 || !object.contains_key("files") || !object.contains_key("package") {
            return Err(format!(
                "Cargo vendor checksum manifest has unexpected fields: {relative}"
            ));
        }
        if object.get("package").and_then(serde_json::Value::as_str)
            != Some(package.checksum.as_str())
        {
            return Err(format!(
                "Cargo.lock checksum differs from enrolled vendor package {}",
                package.directory
            ));
        }
        let files = object
            .get("files")
            .and_then(serde_json::Value::as_object)
            .filter(|files| !files.is_empty())
            .ok_or_else(|| format!("Cargo vendor package has no file checksums: {relative}"))?;
        if files.len() > usize::try_from(MAX_TREE_FILES).unwrap_or(usize::MAX)
            || files.iter().any(|(path, digest)| {
                !portable_tree_path(path)
                    || digest
                        .as_str()
                        .is_none_or(|digest| !canonical_digest(digest))
            })
        {
            return Err(format!(
                "Cargo vendor package contains invalid file checksums: {relative}"
            ));
        }
    }
    require_same_tree(
        vendor_tree,
        &measure_closure_tree(vendor, MAX_TREE_FILES, MAX_TREE_BYTES)?,
        "Cargo vendor tree after registry closure validation",
    )
}

fn flat_assignments(source: &str, label: &str) -> Result<BTreeMap<String, String>, String> {
    let mut fields = BTreeMap::new();
    for (line_index, raw_line) in source.lines().enumerate() {
        let line_number = line_index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            return Err(format!(
                "{label} contains an unexpected table on line {line_number}"
            ));
        }
        let (key, value) = assignment(line, line_number)?;
        if fields.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(format!("{label} repeats field {key:?}"));
        }
    }
    Ok(fields)
}

fn assignment(line: &str, line_number: usize) -> Result<(&str, &str), String> {
    let (key, value) = line
        .split_once(" = ")
        .ok_or_else(|| format!("malformed assignment on line {line_number}"))?;
    if key.is_empty()
        || !key.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        || value.is_empty()
        || key
            .bytes()
            .any(|byte| !(byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'))
        || value.contains(" = ")
    {
        return Err(format!("noncanonical assignment on line {line_number}"));
    }
    Ok((key, value))
}

fn required<'a>(fields: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, String> {
    fields
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("missing required field {key}"))
}

fn require_keys(
    fields: &BTreeMap<String, String>,
    expected: &[&str],
    label: &str,
) -> Result<(), String> {
    let actual = fields.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    if actual != expected {
        return Err(format!("{label} fields differ from the canonical schema"));
    }
    Ok(())
}

fn canonical_text<'a>(bytes: &'a [u8], label: &str) -> Result<&'a str, String> {
    let source = std::str::from_utf8(bytes).map_err(|_| format!("{label} is not UTF-8"))?;
    if !source.ends_with('\n') || source.contains('\r') || source.contains('\0') {
        return Err(format!("{label} has noncanonical text encoding"));
    }
    Ok(source)
}

fn parse_string(value: &str, label: &str) -> Result<String, String> {
    let inner = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or_else(|| format!("{label} is not a canonical basic string"))?;
    if inner.is_empty()
        || inner.len() > MAX_PATH_BYTES
        || inner
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'"' | b'\\'))
    {
        return Err(format!("{label} contains an invalid character or length"));
    }
    Ok(inner.to_owned())
}

fn digest_string(value: &str, label: &str) -> Result<String, String> {
    let digest = parse_string(value, label)?;
    if !canonical_digest(&digest) {
        return Err(format!("{label} is not canonical lowercase hexadecimal"));
    }
    Ok(digest)
}

fn canonical_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn parse_u64(value: &str, label: &str) -> Result<u64, String> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(format!("{label} is not a canonical unsigned integer"));
    }
    value
        .parse::<u64>()
        .map_err(|_| format!("{label} does not fit u64"))
}

fn positive_u64(value: &str, label: &str) -> Result<u64, String> {
    let value = parse_u64(value, label)?;
    if value == 0 {
        Err(format!("{label} must be nonzero"))
    } else {
        Ok(value)
    }
}

fn workspace_release(root: &Path) -> Result<String, String> {
    let bytes = read_bounded_file(&root.join("Cargo.toml"), MAX_LOCK_BYTES)?;
    let source = canonical_text(&bytes, "workspace Cargo.toml")?;
    let mut in_workspace_package = false;
    let mut version = None;
    for raw_line in source.lines() {
        let line = raw_line.trim();
        if line.starts_with('[') {
            in_workspace_package = line == "[workspace.package]";
            continue;
        }
        if in_workspace_package && line.starts_with("version = ") {
            if version.is_some() {
                return Err("workspace Cargo.toml repeats workspace package version".to_owned());
            }
            version = Some(parse_string(
                line.strip_prefix("version = ")
                    .ok_or_else(|| "workspace version parser invariant".to_owned())?,
                "workspace release",
            )?);
        }
    }
    let version = version.ok_or_else(|| "workspace Cargo.toml omits release version".to_owned())?;
    if !valid_release(&version) {
        return Err(format!(
            "workspace release {version:?} is not a canonical version atom"
        ));
    }
    Ok(version)
}

fn enrolled_llvm_prefix_tree_sha256(root: &Path) -> Result<String, String> {
    let fields = flat_assignments(
        canonical_text(
            &read_bounded_file(&root.join("toolchain/llvm.outputs.toml"), MAX_LOCK_BYTES)?,
            "LLVM output lock",
        )?,
        "LLVM output lock",
    )?;
    digest_string(
        required(&fields, "prefix_tree_sha256")?,
        "LLVM prefix tree SHA-256",
    )
}

fn rust_toolchain_channel(root: &Path) -> Result<String, String> {
    let bytes = read_bounded_file(&root.join("rust-toolchain.toml"), MAX_LOCK_BYTES)?;
    let source = canonical_text(&bytes, "rust-toolchain.toml")?;
    let mut in_toolchain = false;
    let mut saw_toolchain = false;
    let mut channel = None;
    for (line_index, raw_line) in source.lines().enumerate() {
        let line_number = line_index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            if line != "[toolchain]" || saw_toolchain {
                return Err(format!(
                    "rust-toolchain.toml contains an unreviewed table on line {line_number}"
                ));
            }
            saw_toolchain = true;
            in_toolchain = true;
            continue;
        }
        let (key, value) = assignment(line, line_number)?;
        if !in_toolchain {
            return Err(format!(
                "rust-toolchain.toml has an assignment outside [toolchain] on line {line_number}"
            ));
        }
        if key == "channel" {
            if channel.is_some() {
                return Err("rust-toolchain.toml repeats channel".to_owned());
            }
            channel = Some(parse_string(value, "Rust toolchain channel")?);
        }
    }
    let channel = channel.ok_or_else(|| "rust-toolchain.toml omits channel".to_owned())?;
    if !channel
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
        || channel.starts_with('.')
        || channel.ends_with('.')
        || channel.split('.').count() != 3
        || channel.split('.').any(|part| {
            part.is_empty()
                || (part.len() > 1 && part.starts_with('0'))
                || !part.bytes().all(|byte| byte.is_ascii_digit())
        })
    {
        return Err("Rust toolchain channel is not an exact stable release".to_owned());
    }
    Ok(channel)
}

fn validate_rust_toolchain(tools: &BuildTools, channel: &str) -> Result<(), String> {
    let expected = format!("release: {channel}");
    for (label, version) in [
        ("Cargo", tools.cargo_version.as_str()),
        ("rustc", tools.rustc_version.as_str()),
    ] {
        if version.lines().filter(|line| *line == expected).count() != 1 {
            return Err(format!(
                "selected {label} does not match rust-toolchain.toml release {channel}"
            ));
        }
    }
    Ok(())
}

fn valid_release(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
}

fn output_directory(root: &Path, selected: Option<&Path>) -> Result<PathBuf, String> {
    let output = selected.map_or_else(
        || root.join("build/toolchain/distributions"),
        |path| {
            if path.is_absolute() {
                path.to_path_buf()
            } else {
                root.join(path)
            }
        },
    );
    normalized_absolute(&output, "distribution output")
}

fn resolve_build_tools(
    options: &Options,
    host: &str,
    enrolled: &RustOutput,
) -> Result<BuildTools, String> {
    let cargo_home = match options.cargo_home.as_ref() {
        Some(path) => exact_directory(path, "Cargo home")?,
        None => {
            let selected = env::var_os("CARGO_HOME").map_or_else(
                || {
                    env::var_os("HOME")
                        .map(PathBuf::from)
                        .map(|home| home.join(".cargo"))
                },
                |value| Some(PathBuf::from(value)),
            );
            exact_directory(
                &selected
                    .ok_or_else(|| "--cargo-home or absolute CARGO_HOME is required".to_owned())?,
                "Cargo home",
            )?
        }
    };
    let cargo = resolve_rust_tool(
        options.cargo.as_deref(),
        "WRELA_DIST_CARGO",
        "cargo",
        &cargo_home,
        enrolled,
    )?;
    let rustc = resolve_rust_tool(
        options.rustc.as_deref(),
        "WRELA_DIST_RUSTC",
        "rustc",
        &cargo_home,
        enrolled,
    )?;
    let cargo_measurement = measure_file(&cargo, MAX_FILE_BYTES, true)?;
    let rustc_measurement = measure_file(&rustc, MAX_FILE_BYTES, true)?;
    if cargo_measurement.sha256 != enrolled.cargo_sha256
        || cargo_measurement.bytes != enrolled.cargo_bytes
        || rustc_measurement.sha256 != enrolled.rustc_sha256
        || rustc_measurement.bytes != enrolled.rustc_bytes
    {
        return Err("selected Cargo/rustc binaries differ from reviewed enrollment".to_owned());
    }
    let cargo_digest = cargo_measurement.sha256;
    let rustc_digest = rustc_measurement.sha256;
    let rust_sysroot = derive_rust_sysroot(&cargo, &rustc)?;
    let rust_sysroot_tree = measure_closure_tree(&rust_sysroot, MAX_TREE_FILES, MAX_TREE_BYTES)?;
    if rust_sysroot_tree.sha256 != enrolled.sysroot_tree_sha256
        || rust_sysroot_tree.files != enrolled.sysroot_files
        || rust_sysroot_tree.bytes != enrolled.sysroot_bytes
    {
        return Err("selected Rust sysroot differs from reviewed enrollment".to_owned());
    }
    let cargo_version = tool_version(&cargo, &["-Vv"], "Cargo version")?;
    let rustc_version = tool_version(&rustc, &["-Vv"], "rustc version")?;
    if sha256_bytes(cargo_version.as_bytes()) != enrolled.cargo_version_sha256
        || sha256_bytes(rustc_version.as_bytes()) != enrolled.rustc_version_sha256
    {
        return Err("selected Cargo/rustc versions differ from reviewed enrollment".to_owned());
    }
    if !rustc_version
        .lines()
        .any(|line| line == format!("host: {host}"))
    {
        return Err(format!(
            "selected rustc does not target distribution host {host}"
        ));
    }
    let rust_sysroot_text = tool_version(&rustc, &["--print", "sysroot"], "rustc sysroot")?;
    if rust_sysroot_text.lines().count() != 1 {
        return Err("selected rustc returned a malformed sysroot path".to_owned());
    }
    if exact_directory(
        Path::new(&rust_sysroot_text),
        "reported Rust toolchain sysroot",
    )? != rust_sysroot
    {
        return Err("selected rustc reported a different authenticated sysroot".to_owned());
    }
    Ok(BuildTools {
        cargo,
        rustc,
        cargo_home,
        rust_sysroot,
        rust_sysroot_tree,
        cargo_digest,
        rustc_digest,
        cargo_version,
        rustc_version,
    })
}

fn derive_rust_sysroot(cargo: &Path, rustc: &Path) -> Result<PathBuf, String> {
    for (path, expected) in [(cargo, "cargo"), (rustc, "rustc")] {
        if path.file_name().and_then(|value| value.to_str()) != Some(expected) {
            return Err(format!(
                "selected {expected} does not have the reviewed sysroot-relative name bin/{expected}"
            ));
        }
    }
    let cargo_bin = cargo
        .parent()
        .ok_or_else(|| "selected Cargo has no bin directory".to_owned())?;
    let rustc_bin = rustc
        .parent()
        .ok_or_else(|| "selected rustc has no bin directory".to_owned())?;
    if cargo_bin != rustc_bin
        || cargo_bin.file_name().and_then(|value| value.to_str()) != Some("bin")
    {
        return Err(
            "selected Cargo and rustc are not the same canonical sysroot bin pair".to_owned(),
        );
    }
    exact_directory(
        cargo_bin
            .parent()
            .ok_or_else(|| "selected Rust toolchain bin directory has no sysroot".to_owned())?,
        "derived Rust toolchain sysroot",
    )
}

fn resolve_rust_tool(
    selected: Option<&Path>,
    variable: &str,
    tool: &str,
    cargo_home: &Path,
    enrolled: &RustOutput,
) -> Result<PathBuf, String> {
    if let Some(path) = selected {
        return exact_file(path, &format!("selected {tool}"));
    }
    if let Some(value) = env::var_os(variable) {
        return exact_file(Path::new(&value), variable);
    }
    let home = cargo_home
        .parent()
        .ok_or_else(|| "Cargo home has no parent for Rust toolchain selection".to_owned())?;
    let rustup_home = env::var_os("RUSTUP_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".rustup"));
    let rustup_home = exact_directory(&rustup_home, "rustup home")?;
    let toolchain_name = format!("{}-{}", enrolled.channel, enrolled.host);
    let toolchain = exact_directory(
        &rustup_home.join("toolchains").join(&toolchain_name),
        "enrolled Rust toolchain",
    )?;
    exact_file(
        &toolchain.join("bin").join(tool),
        &format!("enrolled {tool}"),
    )
}

fn tool_version(tool: &Path, arguments: &[&str], label: &str) -> Result<String, String> {
    let mut command = Command::new(tool);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/wrela/no-ambient-path")
        .env("TZ", "UTC")
        .args(arguments);
    let output = run_command(&mut command, label, 60)?;
    require_success(&output, label, false)?;
    if !output.stderr.is_empty() {
        return Err(format!("{label} wrote unexpected stderr"));
    }
    let text = String::from_utf8(output.stdout).map_err(|_| format!("{label} is not UTF-8"))?;
    if text.is_empty() || text.len() > 64 * 1024 || text.contains('\0') {
        return Err(format!("{label} has an invalid bounded response"));
    }
    Ok(text.trim_end().to_owned())
}

fn measure_source_tree(root: &Path) -> Result<TreeMeasurement, String> {
    validate_workspace_cargo_directory(root)?;
    let mut records = Vec::new();
    let mut budget = TreeBudget::new(MAX_TREE_FILES, MAX_TREE_BYTES)?;
    for file in [
        ".gitignore",
        "Cargo.toml",
        "Cargo.lock",
        ".cargo/config.toml",
        "LICENSE",
        "README.md",
        "rust-toolchain.toml",
        "rustfmt.toml",
    ] {
        let measurement = measure_file(&root.join(file), budget.file_limit()?, false)?;
        budget.record_file(measurement.bytes)?;
        records.push(FileRecord {
            path: file.to_owned(),
            bytes: measurement.bytes,
            sha256: measurement.sha256,
            executable: false,
        });
    }
    for directory in ["crates", "docs", "std", "tests", "toolchain", "xtask"] {
        walk_tree(
            &root.join(directory),
            directory,
            0,
            &mut records,
            &mut budget,
            false,
        )?;
    }
    finish_tree(records, MAX_TREE_FILES, MAX_TREE_BYTES)
}

fn measure_tree(root: &Path, max_files: u64, max_bytes: u64) -> Result<TreeMeasurement, String> {
    let mut records = Vec::new();
    let mut budget = TreeBudget::new(max_files, max_bytes)?;
    walk_tree(root, "", 0, &mut records, &mut budget, false)?;
    finish_tree(records, max_files, max_bytes)
}

fn measure_closure_tree(
    root: &Path,
    max_files: u64,
    max_bytes: u64,
) -> Result<TreeMeasurement, String> {
    let mut records = Vec::new();
    let mut budget = TreeBudget::new(max_files, max_bytes)?;
    walk_tree(root, "", 0, &mut records, &mut budget, true)?;
    finish_tree(records, max_files, max_bytes)
}

fn reject_embedded_paths_in_file(
    path: &Path,
    expected: &FileMeasurement,
    executable: bool,
    forbidden: &[PathBuf],
    label: &str,
) -> Result<(), String> {
    if measure_file(path, MAX_FILE_BYTES, executable)? != *expected {
        return Err(format!("{label} changed before absolute-path scan"));
    }
    let mut needles = forbidden
        .iter()
        .map(|path| {
            if !path.is_absolute() {
                return Err(format!(
                    "absolute-path scan received a relative path: {}",
                    path.display()
                ));
            }
            let value = path
                .to_str()
                .ok_or_else(|| "absolute-path scan input is not UTF-8".to_owned())?
                .as_bytes()
                .to_vec();
            if value.len() < 2 || value.len() > MAX_PATH_BYTES {
                return Err("absolute-path scan input has an invalid length".to_owned());
            }
            Ok(value)
        })
        .collect::<Result<Vec<_>, String>>()?;
    needles.sort();
    needles.dedup();
    let overlap = needles
        .iter()
        .map(Vec::len)
        .max()
        .unwrap_or(1)
        .saturating_sub(1);
    let mut input = File::open(path)
        .map_err(|error| format!("cannot open {label} for absolute-path scan: {error}"))?;
    let mut carry = Vec::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|error| format!("cannot scan {label} for absolute paths: {error}"))?;
        if read == 0 {
            break;
        }
        carry.extend_from_slice(&buffer[..read]);
        if let Some(needle) = needles.iter().find(|needle| {
            carry
                .windows(needle.len())
                .any(|window| window == needle.as_slice())
        }) {
            return Err(format!(
                "{label} embeds forbidden absolute path {}",
                String::from_utf8_lossy(needle)
            ));
        }
        if carry.len() > overlap {
            carry.drain(..carry.len() - overlap);
        }
    }
    if measure_file(path, MAX_FILE_BYTES, executable)? != *expected {
        return Err(format!("{label} changed during absolute-path scan"));
    }
    Ok(())
}

fn reject_embedded_paths_in_tree(
    root: &Path,
    expected: &TreeMeasurement,
    forbidden: &[PathBuf],
    label: &str,
) -> Result<(), String> {
    for record in &expected.records {
        reject_embedded_paths_in_file(
            &root.join(&record.path),
            &FileMeasurement {
                sha256: record.sha256.clone(),
                bytes: record.bytes,
            },
            record.executable,
            forbidden,
            &format!("{label} {}", record.path),
        )?;
    }
    require_same_tree(
        expected,
        &measure_tree(root, MAX_TREE_FILES, MAX_TREE_BYTES)?,
        &format!("{label} after absolute-path scan"),
    )
}

fn walk_tree(
    directory: &Path,
    prefix: &str,
    depth: u32,
    records: &mut Vec<FileRecord>,
    budget: &mut TreeBudget,
    allow_empty_files: bool,
) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err(format!(
            "tree {} exceeds depth {MAX_DEPTH}",
            directory.display()
        ));
    }
    let before = stable_metadata(directory, "tree directory")?;
    if !before.is_dir() {
        return Err(format!(
            "tree entry {} is not a directory",
            directory.display()
        ));
    }
    validate_directory_mode(directory, &before)?;
    let mut entries = Vec::new();
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("cannot enumerate {}: {error}", directory.display()))?
    {
        let entry = entry.map_err(|error| format!("cannot enumerate tree entry: {error}"))?;
        budget.record_entry()?;
        entries
            .try_reserve(1)
            .map_err(|_| "cannot reserve bounded tree-entry ordering scratch".to_owned())?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| format!("tree contains a non-UTF-8 name in {}", directory.display()))?;
        if !portable_component(&name) {
            return Err(format!("tree contains nonportable component {name:?}"));
        }
        entries.push((name, entry.path()));
    }
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
        if relative.len() > MAX_PATH_BYTES || !portable_tree_path(&relative) {
            return Err(format!("tree path is not portable: {relative:?}"));
        }
        let metadata = stable_metadata(&path, "tree entry")?;
        if metadata.is_dir() {
            validate_directory_mode(&path, &metadata)?;
            walk_tree(
                &path,
                &relative,
                depth.saturating_add(1),
                records,
                budget,
                allow_empty_files,
            )?;
        } else if metadata.is_file() {
            let executable = executable_mode(&path, &metadata)?;
            let measurement = if allow_empty_files {
                measure_file_allow_empty(&path, budget.file_limit()?, executable)?
            } else {
                measure_file(&path, budget.file_limit()?, executable)?
            };
            budget.record_file(measurement.bytes)?;
            records
                .try_reserve(1)
                .map_err(|_| "cannot reserve bounded tree measurement".to_owned())?;
            records.push(FileRecord {
                path: relative,
                bytes: measurement.bytes,
                sha256: measurement.sha256,
                executable,
            });
        } else {
            return Err(format!(
                "tree contains unsupported entry {}",
                path.display()
            ));
        }
    }
    let after = stable_metadata(directory, "tree directory")?;
    if !same_metadata(&before, &after) {
        return Err(format!(
            "tree directory changed while read: {}",
            directory.display()
        ));
    }
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
    let bytes = records.iter().try_fold(0u64, |total, record| {
        total
            .checked_add(record.bytes)
            .ok_or_else(|| "tree byte count overflow".to_owned())
    })?;
    if files > max_files || bytes == 0 || bytes > max_bytes {
        return Err("tree exceeds its finite limits or has zero content".to_owned());
    }
    let mut digest = Sha256::new();
    digest.update(RELEASE_TREE_MAGIC);
    digest.update(RELEASE_TREE_VERSION.to_le_bytes());
    digest.update(files.to_le_bytes());
    for record in &records {
        update_length_prefixed(&mut digest, record.path.as_bytes())?;
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

fn canonical_component_tree(records: &[FileRecord]) -> Result<FileMeasurement, String> {
    if records.is_empty() || records.windows(2).any(|pair| pair[0].path >= pair[1].path) {
        return Err("canonical component tree is empty or unordered".to_owned());
    }
    let count = u64::try_from(records.len())
        .map_err(|_| "canonical component record count overflow".to_owned())?;
    let bytes = records.iter().try_fold(0u64, |total, record| {
        total
            .checked_add(record.bytes)
            .ok_or_else(|| "canonical component byte count overflow".to_owned())
    })?;
    if bytes == 0 {
        return Err("canonical component tree has zero bytes".to_owned());
    }
    let mut digest = Sha256::new();
    digest.update(CANONICAL_TREE_MAGIC);
    digest.update(CANONICAL_TREE_VERSION.to_le_bytes());
    digest.update(count.to_le_bytes());
    for record in records {
        update_length_prefixed(&mut digest, record.path.as_bytes())?;
        digest.update(record.bytes.to_le_bytes());
        digest.update(hex_bytes(&record.sha256)?);
    }
    Ok(FileMeasurement {
        sha256: lower_hex(&digest.finalize()),
        bytes,
    })
}

fn measure_file(
    path: &Path,
    maximum: u64,
    require_executable: bool,
) -> Result<FileMeasurement, String> {
    measure_file_with_policy(path, maximum, require_executable, false)
}

fn measure_file_allow_empty(
    path: &Path,
    maximum: u64,
    require_executable: bool,
) -> Result<FileMeasurement, String> {
    measure_file_with_policy(path, maximum, require_executable, true)
}

fn measure_file_with_policy(
    path: &Path,
    maximum: u64,
    require_executable: bool,
    allow_empty: bool,
) -> Result<FileMeasurement, String> {
    let before = stable_metadata(path, "file")?;
    if !before.is_file() || (!allow_empty && before.len() == 0) || before.len() > maximum {
        return Err(format!(
            "{} is not a permitted regular file within {maximum} bytes",
            path.display()
        ));
    }
    validate_file_mode(path, &before, require_executable)?;
    let mut file =
        File::open(path).map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("cannot inspect opened {}: {error}", path.display()))?;
    if !same_metadata(&before, &opened) {
        return Err(format!("{} changed while being opened", path.display()));
    }
    let mut digest = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| "file read count overflow".to_owned())?)
            .ok_or_else(|| "file byte count overflow".to_owned())?;
        if total > maximum {
            return Err(format!("{} exceeded {maximum} bytes", path.display()));
        }
        digest.update(&buffer[..read]);
    }
    let after = stable_metadata(path, "file")?;
    if total != before.len() || !same_metadata(&before, &after) {
        return Err(format!("{} changed while being measured", path.display()));
    }
    Ok(FileMeasurement {
        sha256: lower_hex(&digest.finalize()),
        bytes: total,
    })
}

fn read_bounded_file(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    let measurement = measure_file(path, maximum, false)?;
    read_exact_measured_file(path, &measurement)
}

fn read_exact_measured_file(path: &Path, measurement: &FileMeasurement) -> Result<Vec<u8>, String> {
    let capacity = usize::try_from(measurement.bytes)
        .map_err(|_| format!("{} does not fit host allocation", path.display()))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| format!("cannot allocate {} bytes", path.display()))?;
    let mut file = File::open(path)
        .map_err(|error| format!("cannot open {} for bounded read: {error}", path.display()))?;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        let next = bytes
            .len()
            .checked_add(read)
            .ok_or_else(|| format!("{} changed beyond its bounded extent", path.display()))?;
        if next > capacity {
            return Err(format!(
                "{} grew beyond its measured bounded extent",
                path.display()
            ));
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    if bytes.len() != capacity || sha256_bytes(&bytes) != measurement.sha256 {
        return Err(format!(
            "{} changed between measurement and read",
            path.display()
        ));
    }
    Ok(bytes)
}

fn validate_qemu_bundle(
    root: &Path,
    measured: &TreeMeasurement,
    lock: &EmulationLock,
    enrolled: &EmulationOutput,
) -> Result<(), String> {
    if measured.sha256 != enrolled.bundle_tree_sha256
        || measured.files != enrolled.bundle_files
        || measured.bytes != enrolled.bundle_bytes
    {
        return Err("QEMU payload differs from its authenticated output enrollment".to_owned());
    }
    for record in &measured.records {
        let accepted = matches!(
            record.path.as_str(),
            "bin/qemu-system-aarch64"
                | "firmware/QEMU_EFI.fd"
                | "firmware/QEMU_VARS.fd"
                | "provenance.txt"
        ) || record.path.starts_with("licenses/");
        if !accepted {
            return Err(format!(
                "enrolled QEMU payload contains undeclared runtime input {:?}",
                record.path
            ));
        }
    }
    let qemu = required_record(measured, "bin/qemu-system-aarch64")?;
    let code = required_record(measured, "firmware/QEMU_EFI.fd")?;
    let variables = required_record(measured, "firmware/QEMU_VARS.fd")?;
    let provenance = required_record(measured, "provenance.txt")?;
    if !qemu.executable
        || qemu.sha256 != enrolled.qemu_sha256
        || qemu.bytes != enrolled.qemu_bytes
        || code.executable
        || code.sha256 != lock.firmware_code.sha256
        || code.sha256 != enrolled.firmware_code_sha256
        || code.bytes != enrolled.firmware_code_bytes
        || variables.executable
        || variables.sha256 != lock.firmware_variables.sha256
        || variables.sha256 != enrolled.firmware_variables_sha256
        || variables.bytes != enrolled.firmware_variables_bytes
        || provenance.executable
    {
        return Err("QEMU executable, firmware, or provenance measurement is stale".to_owned());
    }
    for required_license in ["licenses/COPYING", "licenses/edk2-licenses.txt"] {
        let license = required_record(measured, required_license)?;
        if license.executable {
            return Err(format!("QEMU license {required_license} is executable"));
        }
    }
    let provenance_bytes = read_bounded_file(&root.join("provenance.txt"), MAX_LOCK_BYTES)?;
    let provenance_text = canonical_text(&provenance_bytes, "QEMU provenance")?;
    for required_value in [
        enrolled.native_input_sha256.as_str(),
        lock.bytes_sha256.as_str(),
        lock.source_sha256.as_str(),
        lock.signing_key_fingerprint.as_str(),
    ] {
        if !provenance_text.contains(required_value) {
            return Err("QEMU provenance does not bind every enrolled native identity".to_owned());
        }
    }
    // `emulation.outputs.toml` binds the complete measured tree, including
    // provenance.txt. Requiring provenance.txt to contain that final tree digest
    // would create an infeasible SHA-256 fixed point rather than more evidence.
    inspect_macho_dependencies(&root.join("bin/qemu-system-aarch64"))?;
    probe_qemu(root, lock)
}

fn required_record<'a>(tree: &'a TreeMeasurement, path: &str) -> Result<&'a FileRecord, String> {
    tree.records
        .binary_search_by(|record| record.path.as_str().cmp(path))
        .ok()
        .and_then(|index| tree.records.get(index))
        .ok_or_else(|| format!("authenticated tree omits required file {path}"))
}

fn required_file_measurement(
    tree: &TreeMeasurement,
    path: &str,
) -> Result<FileMeasurement, String> {
    let record = required_record(tree, path)?;
    Ok(FileMeasurement {
        sha256: record.sha256.clone(),
        bytes: record.bytes,
    })
}

fn run_command(
    command: &mut Command,
    label: &str,
    timeout_seconds: u64,
) -> Result<ProcessOutput, String> {
    if timeout_seconds == 0 || timeout_seconds > 24 * 60 * 60 {
        return Err(format!("invalid timeout for {label}"));
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_child_process_group(command);
    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot spawn {label}: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| terminate_child(&mut child, label, "stdout unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| terminate_child(&mut child, label, "stderr unavailable"))?;
    let exceeded = std::sync::Arc::new(AtomicBool::new(false));
    let stdout_reader = spawn_bounded_reader(stdout, exceeded.clone());
    let stderr_reader = spawn_bounded_reader(stderr, exceeded.clone());
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(timeout_seconds))
        .ok_or_else(|| terminate_child(&mut child, label, "timeout overflow"))?;
    let status = loop {
        if exceeded.load(Ordering::Acquire) {
            return Err(terminate_child(
                &mut child,
                label,
                "output exceeded the bounded capture limit",
            ));
        }
        if Instant::now() >= deadline {
            return Err(terminate_child(
                &mut child,
                label,
                "execution exceeded its timeout",
            ));
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(error) => {
                return Err(terminate_child(
                    &mut child,
                    label,
                    &format!("cannot observe child status: {error}"),
                ));
            }
        }
    };
    // A successful command is not allowed to leave background descendants behind.
    // Closing the whole private process group also guarantees inherited pipe ends
    // cannot keep the bounded readers alive indefinitely.
    terminate_child_process_group(&mut child);
    let stdout = stdout_reader
        .recv_timeout(Duration::from_secs(5))
        .map_err(|_| terminate_child(&mut child, label, "stdout pipe remained open after exit"))?
        .map_err(|error| format!("cannot read {label} stdout: {error}"))?;
    let stderr = stderr_reader
        .recv_timeout(Duration::from_secs(5))
        .map_err(|_| terminate_child(&mut child, label, "stderr pipe remained open after exit"))?
        .map_err(|error| format!("cannot read {label} stderr: {error}"))?;
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

fn spawn_bounded_reader(
    mut reader: impl Read + Send + 'static,
    exceeded: std::sync::Arc<AtomicBool>,
) -> mpsc::Receiver<std::io::Result<Vec<u8>>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let result = (|| {
            let mut captured = Vec::new();
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let read = reader.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                let remaining = MAX_PROCESS_OUTPUT_BYTES.saturating_sub(captured.len());
                let retain = remaining.min(read);
                if retain != 0 {
                    captured.extend_from_slice(&buffer[..retain]);
                }
                if retain != read {
                    exceeded.store(true, Ordering::Release);
                }
            }
            Ok(captured)
        })();
        let _ = sender.send(result);
    });
    receiver
}

fn terminate_child(child: &mut std::process::Child, label: &str, reason: &str) -> String {
    terminate_child_process_group(child);
    let _ = child.wait();
    format!("{label} failed: {reason}")
}

#[cfg(unix)]
fn configure_child_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_child_process_group(_command: &mut Command) {}

#[cfg(unix)]
fn terminate_child_process_group(child: &mut std::process::Child) {
    // `process_group(0)` makes the spawned child's PID its process-group ID.  Use
    // the absolute platform utility because this crate forbids unsafe FFI and the
    // standard library does not expose killpg.  The numeric argument is generated
    // locally and cannot be influenced by release inputs.
    let group = format!("-{}", child.id());
    let _ = Command::new("/bin/kill")
        .args(["-KILL", &group])
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = child.kill();
}

#[cfg(not(unix))]
fn terminate_child_process_group(child: &mut std::process::Child) {
    let _ = child.kill();
}

fn require_success(
    output: &ProcessOutput,
    label: &str,
    require_silent: bool,
) -> Result<(), String> {
    if !output.status.success() {
        return Err(format!(
            "{label} exited with {}:\n{}{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    if require_silent && (!output.stdout.is_empty() || !output.stderr.is_empty()) {
        return Err(format!(
            "{label} produced unexpected output:\n{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

fn probe_qemu(root: &Path, lock: &EmulationLock) -> Result<(), String> {
    let qemu = root.join("bin/qemu-system-aarch64");
    let mut version = Command::new(&qemu);
    version
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/wrela/no-ambient-path")
        .env("TZ", "UTC")
        .arg("--version");
    let output = run_command(&mut version, "enrolled QEMU version probe", 60)?;
    require_success(&output, "enrolled QEMU version probe", false)?;
    if !output.stderr.is_empty()
        || String::from_utf8_lossy(&output.stdout)
            .lines()
            .next()
            .is_none_or(|line| line != format!("QEMU emulator version {}", lock.qemu_version))
    {
        return Err("enrolled QEMU executable does not report the exact pinned version".to_owned());
    }
    let mut machines = Command::new(&qemu);
    machines
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/wrela/no-ambient-path")
        .env("TZ", "UTC")
        .args(["-machine", "help"]);
    let output = run_command(&mut machines, "enrolled QEMU machine probe", 60)?;
    require_success(&output, "enrolled QEMU machine probe", false)?;
    let machines = String::from_utf8(output.stdout)
        .map_err(|_| "QEMU machine list is not UTF-8".to_owned())?;
    if !machines
        .lines()
        .any(|line| line.split_ascii_whitespace().next() == Some(lock.machine_contract.as_str()))
    {
        return Err(format!(
            "enrolled QEMU omits machine contract {}",
            lock.machine_contract
        ));
    }
    let mut cpus = Command::new(&qemu);
    cpus.env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/wrela/no-ambient-path")
        .env("TZ", "UTC")
        .args(["-machine", &lock.machine_contract, "-cpu", "help"]);
    let output = run_command(&mut cpus, "enrolled QEMU CPU probe", 60)?;
    require_success(&output, "enrolled QEMU CPU probe", false)?;
    let cpus =
        String::from_utf8(output.stdout).map_err(|_| "QEMU CPU list is not UTF-8".to_owned())?;
    if !cpus
        .split_ascii_whitespace()
        .any(|cpu| cpu == lock.cpu_contract)
    {
        return Err(format!(
            "enrolled QEMU omits CPU contract {}",
            lock.cpu_contract
        ));
    }
    Ok(())
}

fn inspect_macho_dependencies(path: &Path) -> Result<(), String> {
    let before = stable_metadata(path, "Mach-O executable")?;
    let mut file = File::open(path)
        .map_err(|error| format!("cannot open Mach-O {}: {error}", path.display()))?;
    let mut header = [0u8; 32];
    file.read_exact(&mut header)
        .map_err(|error| format!("cannot read Mach-O header {}: {error}", path.display()))?;
    if read_u32(&header, 0)? != 0xfeed_facf {
        return Err(format!(
            "{} is not a little-endian 64-bit Mach-O",
            path.display()
        ));
    }
    let expected_cpu = if env::consts::ARCH == "aarch64" {
        0x0100_000cu32
    } else {
        0x0100_0007u32
    };
    if read_u32(&header, 4)? != expected_cpu {
        return Err(format!("{} has the wrong Mach-O host CPU", path.display()));
    }
    let commands = read_u32(&header, 16)?;
    let command_bytes = read_u32(&header, 20)?;
    if commands == 0 || commands > 65_536 || command_bytes == 0 || command_bytes > 16 * 1024 * 1024
    {
        return Err(format!(
            "{} has invalid Mach-O load-command bounds",
            path.display()
        ));
    }
    let mut bytes = vec![
        0u8;
        usize::try_from(command_bytes)
            .map_err(|_| "Mach-O command bytes do not fit host".to_owned())?
    ];
    file.read_exact(&mut bytes)
        .map_err(|error| format!("cannot read Mach-O load commands: {error}"))?;
    let mut offset = 0usize;
    let mut code_signatures = 0u32;
    for _ in 0..commands {
        let command = read_u32(&bytes, offset)?;
        let size = usize::try_from(read_u32(&bytes, offset + 4)?)
            .map_err(|_| "Mach-O command size does not fit host".to_owned())?;
        let end = offset
            .checked_add(size)
            .ok_or_else(|| "Mach-O command extent overflow".to_owned())?;
        if size < 8 || end > bytes.len() || size % 8 != 0 {
            return Err("Mach-O load command escapes its declared table".to_owned());
        }
        let base_command = command & 0x7fff_ffff;
        if base_command == 0x1b {
            return Err(format!(
                "{} contains forbidden nondeterministic LC_UUID metadata",
                path.display()
            ));
        } else if base_command == 0x1d {
            if size != 16 {
                return Err("Mach-O code-signature command has the wrong size".to_owned());
            }
            let signature_offset = u64::from(read_u32(&bytes, offset + 8)?);
            let signature_bytes = u64::from(read_u32(&bytes, offset + 12)?);
            let signature_end = signature_offset
                .checked_add(signature_bytes)
                .ok_or_else(|| "Mach-O code-signature extent overflow".to_owned())?;
            let load_commands_end = 32u64
                .checked_add(u64::from(command_bytes))
                .ok_or_else(|| "Mach-O load-command extent overflow".to_owned())?;
            if signature_bytes == 0
                || signature_offset < load_commands_end
                || signature_end > before.len()
            {
                return Err("Mach-O code signature escapes the executable".to_owned());
            }
            code_signatures = code_signatures
                .checked_add(1)
                .ok_or_else(|| "Mach-O code-signature count overflow".to_owned())?;
        } else if matches!(base_command, 0x0c | 0x18 | 0x1f | 0x20 | 0x23) {
            if size < 24 {
                return Err("truncated Mach-O dylib load command".to_owned());
            }
            let name = macho_command_string(&bytes[offset..end], 8)?;
            if !(name.starts_with("/usr/lib/") || name.starts_with("/System/Library/")) {
                return Err(format!(
                    "{} has undeclared non-system dynamic dependency {name:?}",
                    path.display()
                ));
            }
        } else if base_command == 0x1c {
            let rpath = macho_command_string(&bytes[offset..end], 8)?;
            if !(rpath.starts_with("/usr/lib") || rpath.starts_with("/System/Library/")) {
                return Err(format!(
                    "{} has undeclared runtime search path {rpath:?}",
                    path.display()
                ));
            }
        }
        offset = end;
    }
    if offset != bytes.len() {
        return Err("Mach-O load commands do not exactly consume sizeofcmds".to_owned());
    }
    if code_signatures != 1 {
        return Err(format!(
            "{} must contain exactly one LC_CODE_SIGNATURE command",
            path.display()
        ));
    }
    let after = stable_metadata(path, "Mach-O executable")?;
    if !same_metadata(&before, &after) {
        return Err(format!(
            "{} changed during Mach-O inspection",
            path.display()
        ));
    }
    Ok(())
}

fn macho_command_string(command: &[u8], field_offset: usize) -> Result<String, String> {
    let string_offset = usize::try_from(read_u32(command, field_offset)?)
        .map_err(|_| "Mach-O string offset does not fit host".to_owned())?;
    if string_offset < 12 || string_offset >= command.len() {
        return Err("Mach-O load command has an invalid string offset".to_owned());
    }
    let tail = &command[string_offset..];
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| "Mach-O load command string is unterminated".to_owned())?;
    let value = std::str::from_utf8(&tail[..end])
        .map_err(|_| "Mach-O load command string is not UTF-8".to_owned())?;
    if value.is_empty() || value.len() > MAX_PATH_BYTES {
        return Err("Mach-O load command string has invalid length".to_owned());
    }
    Ok(value.to_owned())
}

fn validate_runtime_inputs(
    root: &Path,
    lock: &RuntimeLock,
    authenticated_compiler: &Path,
) -> Result<(), String> {
    if lock.target != "aarch64-unknown-uefi"
        || lock.runtime_abi_version != RUNTIME_ABI_VERSION
        || lock.coff_machine != "arm64"
        || lock.undefined_symbols != 0
    {
        return Err("runtime object lock is incompatible with revision 0.1".to_owned());
    }
    let runtime_root = root.join("toolchain/targets/aarch64-qemu-virt-uefi");
    for (relative, expected) in [
        ("runtime-src/build_runtime.py", &lock.builder_sha256),
        ("runtime-src/runtime.S", &lock.source_sha256),
        ("runtime/wrela-runtime-aarch64.obj", &lock.object_sha256),
    ] {
        let measured = measure_file(
            &runtime_root.join(relative),
            MAX_RUNTIME_OBJECT_BYTES,
            false,
        )?;
        if &measured.sha256 != expected {
            return Err(format!(
                "runtime provenance input {relative} differs from its lock"
            ));
        }
        if relative.ends_with(".obj") && measured.bytes != lock.object_bytes {
            return Err("runtime object length differs from its lock".to_owned());
        }
    }
    let compiler = measure_file(authenticated_compiler, MAX_FILE_BYTES, true)?;
    if compiler.sha256 != lock.compiler_sha256 {
        return Err(
            "runtime lock compiler differs from authenticated LLVM host compiler".to_owned(),
        );
    }
    let identity = tool_version(
        authenticated_compiler,
        &["--version"],
        "runtime compiler version",
    )?;
    if identity.lines().next() != Some(lock.compiler_identity.as_str()) {
        return Err("runtime compiler identity differs from its lock".to_owned());
    }
    let object = read_bounded_file(
        &runtime_root.join("runtime/wrela-runtime-aarch64.obj"),
        MAX_RUNTIME_OBJECT_BYTES,
    )?;
    let observed = inspect_runtime_coff(&object)?;
    if observed.0 != lock.relocations || observed.1 != lock.undefined_symbols {
        return Err("runtime COFF facts differ from its provenance lock".to_owned());
    }
    Ok(())
}

fn inspect_runtime_coff(bytes: &[u8]) -> Result<(u64, u64), String> {
    if bytes.len() < 20 || read_u16(bytes, 0)? != 0xaa64 {
        return Err("runtime object is not ordinary ARM64 COFF".to_owned());
    }
    let sections = usize::from(read_u16(bytes, 2)?);
    let timestamp = read_u32(bytes, 4)?;
    let symbols_offset = usize::try_from(read_u32(bytes, 8)?)
        .map_err(|_| "COFF symbol offset does not fit host".to_owned())?;
    let symbols = usize::try_from(read_u32(bytes, 12)?)
        .map_err(|_| "COFF symbol count does not fit host".to_owned())?;
    if sections == 0
        || sections > 32
        || timestamp != 0
        || read_u16(bytes, 16)? != 0
        || read_u16(bytes, 18)? != 0
    {
        return Err("runtime COFF header is noncanonical".to_owned());
    }
    let section_end = 20usize
        .checked_add(
            sections
                .checked_mul(40)
                .ok_or_else(|| "COFF section overflow".to_owned())?,
        )
        .ok_or_else(|| "COFF section overflow".to_owned())?;
    let symbol_end = symbols_offset
        .checked_add(
            symbols
                .checked_mul(18)
                .ok_or_else(|| "COFF symbol overflow".to_owned())?,
        )
        .ok_or_else(|| "COFF symbol overflow".to_owned())?;
    if section_end > symbols_offset || symbol_end + 4 > bytes.len() {
        return Err("runtime COFF tables escape the object".to_owned());
    }
    let string_bytes = usize::try_from(read_u32(bytes, symbol_end)?)
        .map_err(|_| "COFF string table does not fit host".to_owned())?;
    if string_bytes < 4 || symbol_end.checked_add(string_bytes) != Some(bytes.len()) {
        return Err("runtime COFF string table is not exact-consumption canonical".to_owned());
    }
    let mut relocations = 0u64;
    for section in 0..sections {
        let offset = 20 + section * 40;
        let raw_bytes = usize::try_from(read_u32(bytes, offset + 16)?)
            .map_err(|_| "COFF raw section size does not fit host".to_owned())?;
        let raw_offset = usize::try_from(read_u32(bytes, offset + 20)?)
            .map_err(|_| "COFF raw section offset does not fit host".to_owned())?;
        let relocation_offset = usize::try_from(read_u32(bytes, offset + 24)?)
            .map_err(|_| "COFF relocation offset does not fit host".to_owned())?;
        let relocation_count = usize::from(read_u16(bytes, offset + 32)?);
        let characteristics = read_u32(bytes, offset + 36)?;
        if raw_bytes != 0 {
            if characteristics & 0x80 != 0 {
                if raw_offset != 0 {
                    return Err("runtime BSS unexpectedly has file-backed bytes".to_owned());
                }
            } else if raw_offset < section_end
                || raw_offset
                    .checked_add(raw_bytes)
                    .is_none_or(|end| end > symbols_offset)
            {
                return Err("runtime COFF section data escapes the object".to_owned());
            }
        }
        if relocation_count != 0 {
            let end = relocation_offset
                .checked_add(
                    relocation_count
                        .checked_mul(10)
                        .ok_or_else(|| "runtime relocation extent overflow".to_owned())?,
                )
                .ok_or_else(|| "runtime relocation extent overflow".to_owned())?;
            if relocation_offset < section_end || end > symbols_offset {
                return Err("runtime COFF relocations escape the object".to_owned());
            }
        }
        relocations = relocations
            .checked_add(
                u64::try_from(relocation_count)
                    .map_err(|_| "relocation count overflow".to_owned())?,
            )
            .ok_or_else(|| "relocation count overflow".to_owned())?;
    }
    let required = [
        "wrela_rt_v2_image_enter",
        "wrela_rt_v2_image_exit",
        "wrela_rt_v2_fatal",
        "wrela_rt_v2_cpu_idle",
        "wrela_rt_v2_interrupt_mask",
        "wrela_rt_v2_interrupt_restore",
        "wrela_rt_v2_cache_maintain",
        "wrela_rt_v2_record_event",
        "wrela_rt_v2_replay_event",
        "wrela_rt_v2_test_emit",
        "wrela_rt_v2_test_finish",
        "wrela_rt_v2_test_assertion_fail",
    ];
    let mut definitions = BTreeSet::new();
    let mut undefined = 0u64;
    let mut index = 0usize;
    while index < symbols {
        let offset = symbols_offset + index * 18;
        let name = coff_name(bytes, offset, symbol_end, string_bytes)?;
        let section = read_i16(bytes, offset + 12)?;
        let storage = *bytes
            .get(offset + 16)
            .ok_or_else(|| "truncated COFF storage class".to_owned())?;
        let auxiliary = usize::from(
            *bytes
                .get(offset + 17)
                .ok_or_else(|| "truncated COFF auxiliary count".to_owned())?,
        );
        if storage == 2 && section == 0 {
            undefined = undefined
                .checked_add(1)
                .ok_or_else(|| "undefined symbol count overflow".to_owned())?;
        } else if storage == 2 && section > 0 && required.contains(&name.as_str()) {
            definitions.insert(name);
        }
        index = index
            .checked_add(1 + auxiliary)
            .ok_or_else(|| "COFF symbol index overflow".to_owned())?;
        if index > symbols {
            return Err("COFF auxiliary symbols escape the symbol table".to_owned());
        }
    }
    if required.iter().any(|symbol| !definitions.contains(*symbol)) {
        return Err("runtime COFF omits a required ABI-v2 definition".to_owned());
    }
    Ok((relocations, undefined))
}

fn coff_name(
    bytes: &[u8],
    offset: usize,
    string_base: usize,
    string_bytes: usize,
) -> Result<String, String> {
    let raw = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| "truncated COFF symbol name".to_owned())?;
    if raw[..4] == [0, 0, 0, 0] {
        let relative = usize::try_from(read_u32(raw, 4)?)
            .map_err(|_| "COFF string offset does not fit host".to_owned())?;
        if relative < 4 || relative >= string_bytes {
            return Err("COFF symbol string offset escapes its table".to_owned());
        }
        c_string(bytes, string_base + relative, string_base + string_bytes)
    } else {
        let end = raw.iter().position(|byte| *byte == 0).unwrap_or(raw.len());
        std::str::from_utf8(&raw[..end])
            .map(str::to_owned)
            .map_err(|_| "COFF short symbol name is not UTF-8".to_owned())
    }
}

fn c_string(bytes: &[u8], start: usize, limit: usize) -> Result<String, String> {
    let tail = bytes
        .get(start..limit)
        .ok_or_else(|| "COFF string range escapes the object".to_owned())?;
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| "COFF string is unterminated".to_owned())?;
    std::str::from_utf8(&tail[..end])
        .map(str::to_owned)
        .map_err(|_| "COFF string is not UTF-8".to_owned())
}

fn revalidate_release_authority(
    authority_root: &Path,
    source_root: &Path,
    plan: &ReleasePlan,
    label: &str,
) -> Result<(), String> {
    let authority_root = exact_directory(authority_root, "release authority root")?;
    let source_root = exact_directory(source_root, "release source root")?;
    require_same_tree(
        &plan.source,
        &measure_source_tree(&authority_root)?,
        &format!("{label}: authority source"),
    )?;
    if source_root != authority_root {
        require_same_tree(
            &plan.source,
            &measure_source_tree(&source_root)?,
            &format!("{label}: isolated source snapshot"),
        )?;
    }
    if workspace_release(&source_root)? != plan.release
        || rust_toolchain_channel(&source_root)? != plan.rust_toolchain
        || host_identity()? != plan.host
    {
        return Err(format!(
            "{label}: release, Rust toolchain, or host identity changed after planning"
        ));
    }
    if validate_dist_implementation(&source_root)? != plan.dist_implementation_sha256 {
        return Err(format!(
            "{label}: distribution implementation changed after planning"
        ));
    }
    if exact_file(&plan.orchestrator, "running distribution orchestrator")? != plan.orchestrator
        || measure_file(&plan.orchestrator, MAX_FILE_BYTES, true)? != plan.orchestrator_measurement
    {
        return Err(format!(
            "{label}: running distribution orchestrator changed after planning"
        ));
    }

    let qemu_bundle = exact_directory(&plan.qemu_bundle, "enrolled QEMU payload")?;
    if qemu_bundle != plan.qemu_bundle {
        return Err(format!(
            "{label}: enrolled QEMU path changed after planning"
        ));
    }
    let qemu = measure_tree(&qemu_bundle, MAX_TREE_FILES, MAX_TREE_BYTES)?;
    require_same_tree(&plan.qemu, &qemu, &format!("{label}: QEMU payload"))?;
    validate_qemu_bundle(&qemu_bundle, &qemu, &plan.emulation, &plan.emulation_output)?;

    llvm::revalidate_distribution_authority(&authority_root, &plan.native_authority)
        .map_err(|error| format!("{label}: {error}"))?;
    let native = &plan.native;
    if measure_tree(
        &native.prefix.join("share/wrela/licenses"),
        MAX_TREE_FILES,
        MAX_TREE_BYTES,
    )? != plan.llvm_licenses
        || measure_file(
            &native
                .prefix
                .parent()
                .ok_or_else(|| "verified LLVM prefix has no provenance parent".to_owned())?
                .join("provenance.txt"),
            MAX_LOCK_BYTES,
            false,
        )? != plan.llvm_provenance
        || enrolled_llvm_prefix_tree_sha256(&source_root)? != plan.llvm_prefix_tree_sha256
    {
        return Err(format!(
            "{label}: verified LLVM distribution inputs changed after planning"
        ));
    }
    validate_runtime_inputs(&source_root, &plan.runtime, &native.cxx)?;

    if exact_directory(&plan.tools.cargo_home, "Cargo home")? != plan.tools.cargo_home {
        return Err(format!("{label}: Cargo home changed after planning"));
    }
    if parse_rust_output(&read_bounded_file(
        &source_root.join("toolchain/rust.outputs.toml"),
        MAX_LOCK_BYTES,
    )?)? != plan.rust_output
        || parse_cargo_output(&read_bounded_file(
            &source_root.join("toolchain/cargo.outputs.toml"),
            MAX_LOCK_BYTES,
        )?)? != plan.cargo_output
    {
        return Err(format!(
            "{label}: Rust or Cargo output enrollment changed after planning"
        ));
    }
    if exact_directory(&plan.cargo_vendor, "enrolled Cargo vendor tree")? != plan.cargo_vendor
        || measure_closure_tree(&plan.cargo_vendor, MAX_TREE_FILES, MAX_TREE_BYTES)?
            != plan.cargo_vendor_tree
    {
        return Err(format!(
            "{label}: enrolled Cargo vendor tree changed after planning"
        ));
    }
    validate_sealed_installation_modes(&plan.cargo_vendor, &plan.cargo_vendor_tree)?;
    if exact_directory(&plan.tools.rust_sysroot, "Rust toolchain sysroot")?
        != plan.tools.rust_sysroot
        || measure_closure_tree(&plan.tools.rust_sysroot, MAX_TREE_FILES, MAX_TREE_BYTES)?
            != plan.tools.rust_sysroot_tree
    {
        return Err(format!(
            "{label}: Rust toolchain closure changed after planning"
        ));
    }
    for (name, path, digest, bytes) in [
        (
            "Cargo",
            plan.tools.cargo.as_path(),
            plan.tools.cargo_digest.as_str(),
            plan.rust_output.cargo_bytes,
        ),
        (
            "rustc",
            plan.tools.rustc.as_path(),
            plan.tools.rustc_digest.as_str(),
            plan.rust_output.rustc_bytes,
        ),
    ] {
        let measured = measure_file(path, MAX_FILE_BYTES, true)?;
        if exact_file(path, &format!("{name} executable"))? != path
            || measured.sha256 != digest
            || measured.bytes != bytes
        {
            return Err(format!(
                "{label}: authenticated {name} executable changed after planning"
            ));
        }
    }
    let rust_sysroot = tool_version(
        &plan.tools.rustc,
        &["--print", "sysroot"],
        "rustc sysroot revalidation",
    )?;
    if rust_sysroot.lines().count() != 1
        || exact_directory(Path::new(&rust_sysroot), "reported Rust toolchain sysroot")?
            != plan.tools.rust_sysroot
    {
        return Err(format!(
            "{label}: rustc reported a different authenticated sysroot"
        ));
    }
    if tool_version(&plan.tools.cargo, &["-Vv"], "Cargo version revalidation")?
        != plan.tools.cargo_version
        || tool_version(&plan.tools.rustc, &["-Vv"], "rustc version revalidation")?
            != plan.tools.rustc_version
    {
        return Err(format!(
            "{label}: authenticated Rust tool version changed after planning"
        ));
    }
    if sha256_bytes(plan.tools.cargo_version.as_bytes()) != plan.rust_output.cargo_version_sha256
        || sha256_bytes(plan.tools.rustc_version.as_bytes())
            != plan.rust_output.rustc_version_sha256
        || plan.tools.rust_sysroot_tree.sha256 != plan.rust_output.sysroot_tree_sha256
        || plan.tools.rust_sysroot_tree.files != plan.rust_output.sysroot_files
        || plan.tools.rust_sysroot_tree.bytes != plan.rust_output.sysroot_bytes
    {
        return Err(format!(
            "{label}: Rust toolchain differs from reviewed output enrollment"
        ));
    }
    validate_rust_toolchain(&plan.tools, &plan.rust_toolchain)?;
    Ok(())
}

/// Recheck the sealed transaction's direct witnesses without replaying the
/// release threat model. Complete source trees are intentionally small and
/// remain exact; multi-gigabyte producer closures are consumed through their
/// already-authenticated private copies and receive one final full rescan at
/// the publication boundary.
fn revalidate_release_witness(
    source_root: &Path,
    plan: &ReleasePlan,
    label: &str,
) -> Result<(), String> {
    let source_root = exact_directory(source_root, "release source witness root")?;
    require_same_tree(
        &plan.source,
        &measure_source_tree(&source_root)?,
        &format!("{label}: sealed source witness"),
    )?;
    if workspace_release(&source_root)? != plan.release
        || rust_toolchain_channel(&source_root)? != plan.rust_toolchain
        || host_identity()? != plan.host
        || validate_dist_implementation(&source_root)? != plan.dist_implementation_sha256
    {
        return Err(format!(
            "{label}: sealed release, toolchain, host, or distributor identity changed"
        ));
    }
    if exact_file(&plan.orchestrator, "running distribution orchestrator")? != plan.orchestrator
        || measure_file(&plan.orchestrator, MAX_FILE_BYTES, true)? != plan.orchestrator_measurement
    {
        return Err(format!(
            "{label}: running distribution orchestrator changed after planning"
        ));
    }
    llvm::revalidate_distribution_witness(&plan.native_authority)
        .map_err(|error| format!("{label}: {error}"))?;
    for (path, kind) in [
        (&plan.qemu_bundle, "enrolled QEMU payload"),
        (&plan.cargo_vendor, "enrolled Cargo vendor tree"),
        (&plan.tools.cargo_home, "Cargo home"),
        (&plan.tools.rust_sysroot, "Rust toolchain sysroot"),
    ] {
        if exact_directory(path, kind)? != *path {
            return Err(format!("{label}: {kind} path changed after planning"));
        }
    }
    for (path, kind) in [
        (&plan.tools.cargo, "authenticated Cargo executable"),
        (&plan.tools.rustc, "authenticated rustc executable"),
    ] {
        if exact_file(path, kind)? != *path {
            return Err(format!("{label}: {kind} path changed after planning"));
        }
    }
    if parse_rust_output(&read_bounded_file(
        &source_root.join("toolchain/rust.outputs.toml"),
        MAX_LOCK_BYTES,
    )?)? != plan.rust_output
        || parse_cargo_output(&read_bounded_file(
            &source_root.join("toolchain/cargo.outputs.toml"),
            MAX_LOCK_BYTES,
        )?)? != plan.cargo_output
        || enrolled_llvm_prefix_tree_sha256(&source_root)? != plan.llvm_prefix_tree_sha256
    {
        return Err(format!(
            "{label}: sealed release enrollment changed after planning"
        ));
    }
    Ok(())
}

fn isolate_rust_tools(plan: &ReleasePlan, destination: &Path) -> Result<IsolatedRustTools, String> {
    isolate_enrolled_rust_tools(&plan.tools, &plan.rust_output, destination)
}

fn isolate_enrolled_rust_tools(
    tools: &BuildTools,
    output: &RustOutput,
    destination: &Path,
) -> Result<IsolatedRustTools, String> {
    copy_exact_measured_tree(
        &tools.rust_sysroot,
        destination,
        &tools.rust_sysroot_tree,
        "Rust toolchain sysroot",
    )?;
    seal_installation_directories(destination)?;
    let cargo_relative = tools
        .cargo
        .strip_prefix(&tools.rust_sysroot)
        .map_err(|_| "enrolled Cargo is outside its Rust sysroot".to_owned())?;
    let rustc_relative = tools
        .rustc
        .strip_prefix(&tools.rust_sysroot)
        .map_err(|_| "enrolled rustc is outside its Rust sysroot".to_owned())?;
    let isolated = IsolatedRustTools {
        cargo: destination.join(cargo_relative),
        rustc: destination.join(rustc_relative),
        rustdoc: destination.join("bin/rustdoc"),
        sysroot: destination.to_owned(),
    };
    measure_file(&isolated.rustdoc, MAX_FILE_BYTES, true)?;
    if measure_file(&isolated.cargo, MAX_FILE_BYTES, true)?.sha256 != output.cargo_sha256
        || measure_file(&isolated.rustc, MAX_FILE_BYTES, true)?.sha256 != output.rustc_sha256
        || tool_version(&isolated.cargo, &["-Vv"], "isolated Cargo version")? != tools.cargo_version
        || tool_version(&isolated.rustc, &["-Vv"], "isolated rustc version")? != tools.rustc_version
        || tool_version(
            &isolated.rustc,
            &["--print", "sysroot"],
            "isolated rustc sysroot",
        )? != destination.display().to_string()
    {
        return Err("isolated Rust toolchain differs from reviewed enrollment".to_owned());
    }
    validate_enrolled_rust_tools(tools, output, &isolated)?;
    Ok(isolated)
}

fn validate_isolated_rust_tools(
    plan: &ReleasePlan,
    isolated: &IsolatedRustTools,
) -> Result<(), String> {
    validate_enrolled_rust_tools(&plan.tools, &plan.rust_output, isolated)
}

fn validate_enrolled_rust_tools(
    tools: &BuildTools,
    output: &RustOutput,
    isolated: &IsolatedRustTools,
) -> Result<(), String> {
    if measure_closure_tree(&isolated.sysroot, MAX_TREE_FILES, MAX_TREE_BYTES)?
        != tools.rust_sysroot_tree
        || measure_file(&isolated.cargo, MAX_FILE_BYTES, true)?.sha256 != output.cargo_sha256
        || measure_file(&isolated.rustc, MAX_FILE_BYTES, true)?.sha256 != output.rustc_sha256
    {
        return Err("isolated Rust toolchain changed after exact copy".to_owned());
    }
    Ok(())
}

fn validate_cargo_vendor_measurement(
    tree: &TreeMeasurement,
    output: &CargoOutput,
) -> Result<(), String> {
    if tree.sha256 != output.vendor_tree_sha256
        || tree.files != output.vendor_files
        || tree.bytes != output.vendor_bytes
    {
        return Err("Cargo vendor tree differs from its reviewed enrollment".to_owned());
    }
    Ok(())
}

fn derive_cargo_license_tree(vendor: &TreeMeasurement) -> Result<TreeMeasurement, String> {
    let mut packages = BTreeSet::new();
    let mut licensed = BTreeSet::new();
    let mut records = Vec::new();
    for record in &vendor.records {
        let mut components = record.path.split('/');
        let package = components
            .next()
            .ok_or_else(|| "Cargo vendor record omits a package directory".to_owned())?;
        let file = components.next();
        packages.insert(package.to_owned());
        if let Some(file) = file
            && components.next().is_none()
            && CARGO_LICENSE_FILES.contains(&file)
        {
            licensed.insert(package.to_owned());
            records.push(FileRecord {
                path: format!("crates/{package}/{file}"),
                bytes: record.bytes,
                sha256: record.sha256.clone(),
                executable: false,
            });
        }
    }
    if packages.is_empty() {
        return Err("Cargo vendor enrollment contains no packages".to_owned());
    }
    let missing = packages.difference(&licensed).cloned().collect::<Vec<_>>();
    if missing != [CARGO_LICENSE_OVERRIDE_PACKAGE] {
        return Err(format!(
            "Cargo dependency license review has unexpected packages without root notices: {missing:?}"
        ));
    }
    let override_record = required_record(vendor, CARGO_LICENSE_OVERRIDE_SOURCE)?;
    records.push(FileRecord {
        path: format!("crates/{CARGO_LICENSE_OVERRIDE_PACKAGE}/LICENSE"),
        bytes: override_record.bytes,
        sha256: override_record.sha256.clone(),
        executable: false,
    });
    let tree = finish_tree(records, MAX_TREE_FILES, MAX_TREE_BYTES)?;
    if tree.sha256 != RUST_CRATE_LICENSE_TREE_SHA256
        || tree.files != RUST_CRATE_LICENSE_FILES
        || tree.bytes != RUST_CRATE_LICENSE_BYTES
    {
        return Err(
            "Cargo dependency license selection differs from the reviewed Cargo.lock closure"
                .to_owned(),
        );
    }
    Ok(tree)
}

fn cargo_license_source_path(destination: &str) -> Result<String, String> {
    let override_destination = format!("crates/{CARGO_LICENSE_OVERRIDE_PACKAGE}/LICENSE");
    if destination == override_destination {
        return Ok(CARGO_LICENSE_OVERRIDE_SOURCE.to_owned());
    }
    destination
        .strip_prefix("crates/")
        .filter(|relative| portable_tree_path(relative))
        .map(str::to_owned)
        .ok_or_else(|| "derived Cargo license destination is not canonical".to_owned())
}

fn derive_rust_toolchain_license_tree(
    sysroot: &TreeMeasurement,
) -> Result<TreeMeasurement, String> {
    let records = RUST_TOOLCHAIN_LICENSE_PATHS
        .iter()
        .map(|source| {
            let record = required_record(sysroot, source)?;
            Ok(FileRecord {
                path: format!("toolchain/{source}"),
                bytes: record.bytes,
                sha256: record.sha256.clone(),
                executable: false,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let tree = finish_tree(records, MAX_TREE_FILES, MAX_TREE_BYTES)?;
    if tree.sha256 != RUST_TOOLCHAIN_LICENSE_TREE_SHA256
        || tree.files != RUST_TOOLCHAIN_LICENSE_FILES
        || tree.bytes != RUST_TOOLCHAIN_LICENSE_BYTES
    {
        return Err(
            "Rust toolchain license selection differs from the reviewed sysroot closure".to_owned(),
        );
    }
    Ok(tree)
}

fn combine_rust_license_trees(
    crates: &TreeMeasurement,
    toolchain: &TreeMeasurement,
) -> Result<TreeMeasurement, String> {
    let mut records = crates.records.clone();
    records.extend(toolchain.records.clone());
    let tree = finish_tree(records, MAX_TREE_FILES, MAX_TREE_BYTES)?;
    if tree.sha256 != RUST_LICENSE_TREE_SHA256
        || tree.files != RUST_LICENSE_FILES
        || tree.bytes != RUST_LICENSE_BYTES
    {
        return Err("combined Rust license tree differs from its reviewed identity".to_owned());
    }
    Ok(tree)
}

fn validate_published_cargo_vendor(vendor: &Path, output: &CargoOutput) -> Result<(), String> {
    let vendor = exact_directory(vendor, "published Cargo vendor tree")?;
    let tree = measure_closure_tree(&vendor, MAX_TREE_FILES, MAX_TREE_BYTES)?;
    validate_cargo_vendor_measurement(&tree, output)?;
    validate_sealed_installation_modes(&vendor, &tree)
}

fn normalize_acquired_vendor_modes(root: &Path) -> Result<(), String> {
    let mut budget = TreeBudget::new(MAX_TREE_FILES, MAX_TREE_BYTES)?;
    let mut executables = BTreeSet::new();
    normalize_acquired_vendor_directory(root, "", 0, &mut budget, &mut executables)?;
    let expected = CARGO_VENDOR_EXECUTABLE_PATHS
        .iter()
        .map(|path| (*path).to_owned())
        .collect::<BTreeSet<_>>();
    if executables != expected {
        return Err("Cargo vendor executable-mode review differs from acquired tree".to_owned());
    }
    Ok(())
}

fn normalize_acquired_vendor_directory(
    directory: &Path,
    prefix: &str,
    depth: u32,
    budget: &mut TreeBudget,
    executables: &mut BTreeSet<String>,
) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err(format!(
            "acquired Cargo vendor tree exceeds depth {MAX_DEPTH}"
        ));
    }
    let metadata = stable_metadata(directory, "acquired Cargo vendor directory")?;
    if !metadata.is_dir() {
        return Err("acquired Cargo vendor entry is not a directory".to_owned());
    }
    #[cfg(unix)]
    if metadata.mode() & 0o7000 != 0 {
        return Err("acquired Cargo vendor directory has special permission bits".to_owned());
    }
    let mut entries = Vec::new();
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("cannot enumerate acquired Cargo vendor tree: {error}"))?
    {
        let entry = entry
            .map_err(|error| format!("cannot inspect acquired Cargo vendor entry: {error}"))?;
        budget.record_entry()?;
        entries
            .try_reserve(1)
            .map_err(|_| "cannot reserve bounded Cargo vendor ordering scratch".to_owned())?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "acquired Cargo vendor entry is not UTF-8".to_owned())?;
        if !portable_component(&name) {
            return Err(format!(
                "acquired Cargo vendor tree contains nonportable component {name:?}"
            ));
        }
        entries.push((name, entry.path()));
    }
    entries.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    if entries.is_empty() {
        return Err("acquired Cargo vendor tree contains an empty directory".to_owned());
    }
    for (name, path) in entries {
        let relative = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        if !portable_tree_path(&relative) {
            return Err(format!(
                "acquired Cargo vendor path is not portable: {relative:?}"
            ));
        }
        let metadata = stable_metadata(&path, "acquired Cargo vendor entry")?;
        if metadata.is_dir() {
            normalize_acquired_vendor_directory(
                &path,
                &relative,
                depth.saturating_add(1),
                budget,
                executables,
            )?;
        } else if metadata.is_file() {
            #[cfg(unix)]
            if metadata.nlink() != 1 || metadata.mode() & 0o7000 != 0 {
                return Err(
                    "acquired Cargo vendor file has unsafe links or permission bits".to_owned(),
                );
            }
            if metadata.len() > budget.file_limit()? {
                return Err("acquired Cargo vendor file exceeds bounded closure limits".to_owned());
            }
            budget.record_file(metadata.len())?;
            let executable = CARGO_VENDOR_EXECUTABLE_PATHS.contains(&relative.as_str());
            if executable {
                executables.insert(relative);
            }
            set_mode(&path, if executable { 0o555 } else { 0o444 })?;
        } else {
            return Err("acquired Cargo vendor tree contains an unsupported entry".to_owned());
        }
    }
    set_mode(directory, 0o555)
}

fn seal_measured_tree(root: &Path, expected: &TreeMeasurement) -> Result<(), String> {
    for record in &expected.records {
        set_mode(
            &root.join(&record.path),
            if record.executable { 0o555 } else { 0o444 },
        )?;
    }
    seal_installation_directories(root)?;
    require_same_tree(
        expected,
        &measure_closure_tree(root, MAX_TREE_FILES, MAX_TREE_BYTES)?,
        "sealed authenticated tree",
    )
}

fn prepare_private_cargo_home(plan: &ReleasePlan, destination: &Path) -> Result<(), String> {
    create_private_directory(destination)?;
    copy_exact_measured_tree(
        &plan.cargo_vendor,
        &destination.join("vendor"),
        &plan.cargo_vendor_tree,
        "Cargo vendor tree",
    )?;
    let config = private_cargo_config(destination)?;
    write_new_bytes(&destination.join("config.toml"), &config, false)?;
    for name in [".global-cache", ".package-cache", ".package-cache-mutate"] {
        let path = destination.join(name);
        let file = new_file(&path)?;
        file.sync_all()
            .map_err(|error| format!("cannot sync private Cargo cache file: {error}"))?;
        drop(file);
        set_mode(&path, 0o600)?;
        measure_file_allow_empty(&path, MAX_MANIFEST_BYTES, false)?;
    }
    seal_installation_directories(&destination.join("vendor"))?;
    set_mode(destination, 0o555)?;
    validate_private_cargo_home(plan, destination)
}

fn validate_private_cargo_home(plan: &ReleasePlan, cargo_home: &Path) -> Result<(), String> {
    let names = bounded_directory_names(cargo_home, 5, "private Cargo home")?;
    if names
        != [
            ".global-cache",
            ".package-cache",
            ".package-cache-mutate",
            "config.toml",
            "vendor",
        ]
    {
        return Err("private Cargo home contains undeclared state".to_owned());
    }
    validate_private_cargo_config(cargo_home)?;
    let vendor = cargo_home.join("vendor");
    if measure_closure_tree(&vendor, MAX_TREE_FILES, MAX_TREE_BYTES)? != plan.cargo_vendor_tree {
        return Err("private Cargo home changed from its exact offline recipe".to_owned());
    }
    validate_sealed_installation_modes(&vendor, &plan.cargo_vendor_tree)?;
    let metadata = stable_metadata(cargo_home, "private Cargo home")?;
    #[cfg(unix)]
    if metadata.mode() & 0o7777 != 0o555 {
        return Err("private Cargo home is not sealed".to_owned());
    }
    for name in [".global-cache", ".package-cache", ".package-cache-mutate"] {
        let path = cargo_home.join(name);
        let measurement = measure_file_allow_empty(&path, MAX_MANIFEST_BYTES, false)?;
        if measurement.bytes != 0 || measurement.sha256 != sha256_bytes(&[]) {
            return Err("private Cargo home accumulated undeclared cache state".to_owned());
        }
        #[cfg(unix)]
        if stable_metadata(&path, "private Cargo cache lock")?.mode() & 0o7777 != 0o600 {
            return Err("private Cargo cache lock mode changed".to_owned());
        }
    }
    Ok(())
}

fn bounded_directory_names(
    directory: &Path,
    maximum: usize,
    label: &str,
) -> Result<Vec<String>, String> {
    if maximum == 0 {
        return Err(format!("{label} entry limit must be nonzero"));
    }
    let mut names = Vec::new();
    for entry in
        fs::read_dir(directory).map_err(|error| format!("cannot enumerate {label}: {error}"))?
    {
        if names.len() >= maximum {
            return Err(format!("{label} contains too many entries"));
        }
        names
            .try_reserve(1)
            .map_err(|_| format!("cannot reserve bounded {label} names"))?;
        let entry = entry.map_err(|error| format!("cannot inspect {label}: {error}"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| format!("{label} contains a non-UTF-8 name"))?;
        names.push(name);
    }
    names.sort_unstable();
    Ok(names)
}

fn validate_private_cargo_config(cargo_home: &Path) -> Result<(), String> {
    let path = cargo_home.join("config.toml");
    if read_bounded_file(&path, MAX_LOCK_BYTES)? != private_cargo_config(cargo_home)? {
        return Err("private Cargo configuration changed from its exact recipe".to_owned());
    }
    #[cfg(unix)]
    {
        let metadata = stable_metadata(&path, "private Cargo configuration")?;
        if metadata.mode() & 0o7777 != 0o444 || metadata.nlink() != 1 {
            return Err("private Cargo configuration has mode/link drift".to_owned());
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        Err("distribution assembly has no reviewed non-Unix Cargo-home contract".to_owned())
    }
}

fn private_cargo_config(cargo_home: &Path) -> Result<Vec<u8>, String> {
    let vendor = exact_directory(&cargo_home.join("vendor"), "private Cargo vendor directory")?;
    let path = vendor
        .to_str()
        .ok_or_else(|| "private Cargo vendor path is not UTF-8".to_owned())?;
    if path.len() > MAX_PATH_BYTES || path.chars().any(char::is_control) {
        return Err("private Cargo vendor path is not a bounded TOML string".to_owned());
    }
    let mut escaped = String::new();
    escaped
        .try_reserve(path.len())
        .map_err(|_| "cannot reserve private Cargo vendor path".to_owned())?;
    for character in path.chars() {
        match character {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            _ => escaped.push(character),
        }
    }
    Ok(format!(
        "[net]\noffline = true\n\n[source.crates-io]\nreplace-with = \"wrela-vendored\"\n\n[source.wrela-vendored]\ndirectory = \"{escaped}\"\n"
    )
    .into_bytes())
}

fn run_qemu_integration(
    root: &Path,
    plan: ReleasePlan,
    jobs: u32,
    selected_case: Option<IntegrationQemuCase>,
) -> Result<(), String> {
    let mode = DistExecutionMode::IntegrationQemu;
    if mode.build_lanes() != 1 || mode.replays_public_or_archive_consumers() || mode.publishes() {
        return Err("QEMU integration execution policy is inconsistent".to_owned());
    }
    let temporary_parent = fs::canonicalize(env::temp_dir())
        .map_err(|error| format!("cannot canonicalize private integration parent: {error}"))?;
    let temporary_parent = exact_directory(&temporary_parent, "private integration parent")?;
    if temporary_parent.starts_with(root) || root.starts_with(&temporary_parent) {
        return Err(
            "private integration parent overlaps the release authority checkout".to_owned(),
        );
    }
    let mut private = PrivateStaging::create(&temporary_parent)?;
    let result = (|| {
        let work = private.path.join("work");
        let source = work.join("source");
        let rust_toolchain = work.join("rust-toolchain");
        let cargo_home = work.join("cargo-home");
        let target = work.join("cargo-target");
        let installation = work.join("installation");
        create_private_directory(&work)?;
        copy_source_tree(root, &source, &plan.source)?;
        create_private_directory(&installation)?;

        let rust_tools = isolate_rust_tools(&plan, &rust_toolchain)?;
        prepare_private_cargo_home(&plan, &cargo_home)?;
        let execution = CargoExecution {
            root: &source,
            rust_tools: &rust_tools,
            cargo_home: &cargo_home,
            target: &target,
            work: &work,
        };
        let binaries = build_release_with_validation(
            &plan,
            &execution,
            jobs,
            "integration release build",
            CargoValidationPolicy::Bracketed,
        )?;
        let measurements = (
            measure_file(&binaries.0, MAX_FILE_BYTES, true)?,
            measure_file(&binaries.1, MAX_FILE_BYTES, true)?,
        );
        inspect_macho_dependencies(&binaries.0)?;
        inspect_macho_dependencies(&binaries.1)?;
        let forbidden = forbidden_release_paths(
            root,
            &plan,
            &[
                &private.path,
                &work,
                &source,
                &rust_toolchain,
                &cargo_home,
                &target,
                &installation,
            ],
        );
        for (path, measurement, label) in [
            (&binaries.0, &measurements.0, "integration frontend"),
            (&binaries.1, &measurements.1, "integration backend"),
        ] {
            reject_embedded_paths_in_file(path, measurement, true, &forbidden, label)?;
        }

        assemble_installation(&source, &plan, &installation, &binaries, &measurements)?;
        seal_installation_directories(&installation)?;
        validate_installation_tree(&installation)?;
        let installed = measure_tree(&installation, MAX_TREE_FILES, MAX_TREE_BYTES)?;
        retire_owned_cargo_target(&target, &work, "integration release-build Cargo target")?;

        let qemu = match selected_case {
            None => QemuIntegrationOutput::Full(Box::new({
                let qemu = run_enrolled_lane_b_qemu(
                    &source,
                    &plan,
                    &rust_tools,
                    &installation,
                    &work,
                    jobs,
                )?;
                QemuIntegrationEvidence {
                    source: TreeMeasurement {
                        sha256: String::new(),
                        files: 0,
                        bytes: 0,
                        records: Vec::new(),
                    },
                    qemu_bundle_sha256: plan.qemu.sha256.clone(),
                    qemu_native_input_sha256: plan.emulation_output.native_input_sha256.clone(),
                    installation: installed.clone(),
                    frontend: measurements.0.clone(),
                    backend: measurements.1.clone(),
                    bootstrap: qemu.bootstrap,
                    stdlib_time: qemu.stdlib_time,
                    checked_shift: qemu.checked_shift,
                }
            })),
            Some(IntegrationQemuCase::CurrentTranche) => {
                let run_binding_sha256 = runtime_timeout_run_binding(
                    &plan.source,
                    &installed,
                    &measurements.0,
                    &measurements.1,
                    &plan.qemu.sha256,
                    &plan.emulation_output.native_input_sha256,
                )?;
                let qemu = run_enrolled_current_tranche_qemu(
                    &source,
                    &plan,
                    &rust_tools,
                    &installation,
                    &work,
                    jobs,
                    &run_binding_sha256,
                )?;
                QemuIntegrationOutput::CurrentTranche(Box::new(CurrentTrancheIntegrationEvidence {
                    source: TreeMeasurement {
                        sha256: String::new(),
                        files: 0,
                        bytes: 0,
                        records: Vec::new(),
                    },
                    qemu_bundle_sha256: plan.qemu.sha256.clone(),
                    qemu_native_input_sha256: plan.emulation_output.native_input_sha256.clone(),
                    installation: installed.clone(),
                    frontend: measurements.0.clone(),
                    backend: measurements.1.clone(),
                    run_binding_sha256,
                    qemu,
                }))
            }
            Some(IntegrationQemuCase::RuntimeTimeout) => {
                let run_binding_sha256 = runtime_timeout_run_binding(
                    &plan.source,
                    &installed,
                    &measurements.0,
                    &measurements.1,
                    &plan.qemu.sha256,
                    &plan.emulation_output.native_input_sha256,
                )?;
                let timeout = run_enrolled_runtime_timeout_qemu(
                    &source,
                    &plan,
                    &rust_tools,
                    &installation,
                    &work,
                    jobs,
                    &run_binding_sha256,
                )?;
                QemuIntegrationOutput::RuntimeTimeout(Box::new(RuntimeTimeoutIntegrationEvidence {
                    source: TreeMeasurement {
                        sha256: String::new(),
                        files: 0,
                        bytes: 0,
                        records: Vec::new(),
                    },
                    qemu_bundle_sha256: plan.qemu.sha256.clone(),
                    qemu_native_input_sha256: plan.emulation_output.native_input_sha256.clone(),
                    installation: installed.clone(),
                    frontend: measurements.0.clone(),
                    backend: measurements.1.clone(),
                    run_binding_sha256,
                    timeout,
                }))
            }
        };
        validate_installation_tree(&installation)?;
        require_same_tree(
            &installed,
            &measure_tree(&installation, MAX_TREE_FILES, MAX_TREE_BYTES)?,
            "private installation after Lane B QEMU consumers",
        )?;
        revalidate_release_witness(&source, &plan, "one-build QEMU integration completion")?;
        let frozen_source = measure_source_tree(&source)?;
        require_same_tree(
            &plan.source,
            &frozen_source,
            "one-build QEMU integration final source snapshot",
        )?;
        Ok(match qemu {
            QemuIntegrationOutput::Full(mut evidence) => {
                evidence.source = frozen_source;
                QemuIntegrationOutput::Full(evidence)
            }
            QemuIntegrationOutput::CurrentTranche(mut evidence) => {
                evidence.source = frozen_source;
                QemuIntegrationOutput::CurrentTranche(evidence)
            }
            QemuIntegrationOutput::RuntimeTimeout(mut evidence) => {
                evidence.source = frozen_source;
                QemuIntegrationOutput::RuntimeTimeout(evidence)
            }
        })
    })()
    .and_then(|evidence| match evidence {
        QemuIntegrationOutput::Full(evidence) => encode_qemu_integration_evidence(&evidence),
        QemuIntegrationOutput::CurrentTranche(evidence) => {
            encode_current_tranche_integration_evidence(&evidence)
        }
        QemuIntegrationOutput::RuntimeTimeout(evidence) => {
            encode_runtime_timeout_integration_evidence(&evidence)
        }
    });
    let cleanup = destroy_private_staging(&mut private, "one-build QEMU integration tree");
    let line = match (result, cleanup) {
        (Ok(line), Ok(())) => line,
        (Err(error), Ok(())) => return Err(error),
        (Ok(_), Err(error)) => return Err(error),
        (Err(error), Err(cleanup)) => {
            return Err(format!(
                "{error}; private integration cleanup also failed: {cleanup}"
            ));
        }
    };
    println!("{line}");
    Ok(())
}

fn assemble(root: &Path, plan: ReleasePlan, jobs: u32) -> Result<(), String> {
    prepare_output_root(&plan.output)?;
    let mut staging = PrivateStaging::create(&plan.output)?;
    let temporary_parent = fs::canonicalize(env::temp_dir())
        .map_err(|error| format!("cannot canonicalize private build parent: {error}"))?;
    let temporary_parent = exact_directory(&temporary_parent, "private build parent")?;
    if temporary_parent.starts_with(root) || root.starts_with(&temporary_parent) {
        return Err("private build parent overlaps the release authority checkout".to_owned());
    }
    let mut private_build = PrivateStaging::create(&temporary_parent)?;
    let mut first_lane = PrivateStaging::create(&temporary_parent)?;
    let mut second_lane = PrivateStaging::create(&temporary_parent)?;
    let work = private_build.path.join("work");
    let first_work = first_lane.path.join("lane-a");
    let second_work = second_lane
        .path
        .join("independent-path-length-release-lane-b");
    let installation = staging.path.join("installation");
    create_private_directory(&work)?;
    create_private_directory(&first_work)?;
    create_private_directory(&second_work)?;
    create_private_directory(&installation)?;

    revalidate_release_witness(root, &plan, "distribution start")?;
    let first_source = first_work.join("source");
    let second_source_parent = second_work.join("path-independent-source-root");
    create_private_directory(&second_source_parent)?;
    let second_source = second_source_parent.join("source-copy-b");
    copy_source_tree(root, &first_source, &plan.source)?;
    copy_source_tree(root, &second_source, &plan.source)?;
    reject_ancestor_cargo_configuration(&first_work)?;
    reject_ancestor_cargo_configuration(&second_work)?;
    revalidate_release_witness(&first_source, &plan, "source snapshot A")?;
    revalidate_release_witness(&second_source, &plan, "source snapshot B")?;

    let first_rust_tools = isolate_rust_tools(&plan, &first_work.join("rust-toolchain"))?;
    let second_rust_tools = isolate_rust_tools(&plan, &second_work.join("rust-toolchain"))?;
    let first_cargo_home = first_work.join("cargo-home");
    let second_cargo_home = second_work.join("cargo-home");
    prepare_private_cargo_home(&plan, &first_cargo_home)?;
    prepare_private_cargo_home(&plan, &second_cargo_home)?;
    let first_target = first_work.join("cargo-target");
    let second_target = second_work.join("cargo-target");
    let first_execution = CargoExecution {
        root: &first_source,
        rust_tools: &first_rust_tools,
        cargo_home: &first_cargo_home,
        target: &first_target,
        work: &first_work,
    };
    let first = build_release(&plan, &first_execution, jobs, "release build A")?;
    validate_isolated_rust_tools(&plan, &first_rust_tools)?;
    revalidate_release_witness(&first_source, &plan, "release build A completion")?;
    let second_execution = CargoExecution {
        root: &second_source,
        rust_tools: &second_rust_tools,
        cargo_home: &second_cargo_home,
        target: &second_target,
        work: &second_work,
    };
    let second = build_release(&plan, &second_execution, jobs, "release build B")?;
    validate_isolated_rust_tools(&plan, &second_rust_tools)?;
    revalidate_release_witness(&second_source, &plan, "release build B completion")?;
    let first_measurements = (
        measure_file(&first.0, MAX_FILE_BYTES, true)?,
        measure_file(&first.1, MAX_FILE_BYTES, true)?,
    );
    let second_measurements = (
        measure_file(&second.0, MAX_FILE_BYTES, true)?,
        measure_file(&second.1, MAX_FILE_BYTES, true)?,
    );
    for (label, left, right, left_measurement, right_measurement) in [
        (
            "frontend",
            &first.0,
            &second.0,
            &first_measurements.0,
            &second_measurements.0,
        ),
        (
            "private backend",
            &first.1,
            &second.1,
            &first_measurements.1,
            &second_measurements.1,
        ),
    ] {
        inspect_macho_dependencies(left)?;
        inspect_macho_dependencies(right)?;
        if left_measurement != right_measurement {
            return Err(path_independent_build_mismatch(
                label,
                left_measurement,
                right_measurement,
            ));
        }
    }
    let binary_forbidden = forbidden_release_paths(
        root,
        &plan,
        &[
            &first_lane.path,
            &second_lane.path,
            &private_build.path,
            &staging.path,
            &first_source,
            &second_source,
            &first_target,
            &second_target,
            &first_cargo_home,
            &second_cargo_home,
            &first_rust_tools.sysroot,
            &second_rust_tools.sysroot,
        ],
    );
    for (path, measurement, label) in [
        (&first.0, &first_measurements.0, "release frontend build A"),
        (
            &second.0,
            &second_measurements.0,
            "release frontend build B",
        ),
        (&first.1, &first_measurements.1, "release backend build A"),
        (&second.1, &second_measurements.1, "release backend build B"),
    ] {
        reject_embedded_paths_in_file(path, measurement, true, &binary_forbidden, label)?;
    }
    let frozen = freeze_release_outputs(
        &first,
        &first_measurements,
        &first_target,
        &work.join("frozen-release-outputs"),
    )?;
    let first = (frozen.0, frozen.1);
    let frozen_lld_shim = frozen.2;
    let frozen_lld_shim_measurement = frozen.3;
    retire_owned_cargo_target(&first_target, &first_work, "release build A Cargo target")?;
    retire_owned_cargo_target(&second_target, &second_work, "release build B Cargo target")?;
    let gates_cargo_home = work.join("cargo-home-gates");
    prepare_private_cargo_home(&plan, &gates_cargo_home)?;
    run_repository_gates(
        &first_source,
        &plan,
        &first_rust_tools,
        &gates_cargo_home,
        &work,
        jobs,
    )?;
    validate_isolated_rust_tools(&plan, &first_rust_tools)?;
    revalidate_release_witness(&first_source, &plan, "repository gate completion")?;

    revalidate_release_witness(&first_source, &plan, "installation assembly start")?;
    assemble_installation(
        &first_source,
        &plan,
        &installation,
        &first,
        &first_measurements,
    )?;
    seal_installation_directories(&installation)?;
    validate_installation_tree(&installation)?;
    let assembled_tree = measure_tree(&installation, MAX_TREE_FILES, MAX_TREE_BYTES)?;
    let installed_forbidden = forbidden_release_paths(
        root,
        &plan,
        &[
            &first_lane.path,
            &second_lane.path,
            &private_build.path,
            &staging.path,
            &first_source,
            &second_source,
            &installation,
        ],
    );
    let installed_public = run_public_gates(
        &first_source,
        &installation,
        &work,
        "installed",
        &installed_forbidden,
    )?;
    let runtime_boot = run_runtime_boot_smoke(
        &first_source,
        &plan,
        &installation,
        &frozen_lld_shim,
        &frozen_lld_shim_measurement,
        &work,
    )?;
    let installed_qemu = run_enrolled_real_qemu_smoke(
        &first_source,
        &plan,
        &first_rust_tools,
        &installation,
        &work,
        jobs,
        "installed",
    )?;
    let installed_real_qemu = installed_qemu.bootstrap;
    let installed_stdlib_time_qemu = installed_qemu.stdlib_time;
    validate_isolated_rust_tools(&plan, &first_rust_tools)?;
    revalidate_release_witness(
        &first_source,
        &plan,
        "installed clean-environment rehearsal",
    )?;
    require_same_tree(
        &assembled_tree,
        &measure_tree(&installation, MAX_TREE_FILES, MAX_TREE_BYTES)?,
        "installation after installed public and QEMU routes",
    )?;
    validate_installation_tree(&installation)?;

    let tested_tree = assembled_tree;
    let archive_name = format!("wrela-{}-{}.tar", plan.release, plan.host);
    let archive = staging.path.join(&archive_name);
    let archive_prefix = format!("wrela-{}-{}", plan.release, plan.host);
    write_canonical_archive(&installation, &tested_tree, &archive, &archive_prefix)?;
    require_same_tree(
        &tested_tree,
        &measure_tree(&installation, MAX_TREE_FILES, MAX_TREE_BYTES)?,
        "tested installation after archive creation",
    )?;
    let archive_measurement = measure_file(&archive, MAX_TREE_BYTES, false)?;

    let clean = work.join("archive-clean-room");
    create_private_directory(&clean)?;
    extract_canonical_archive(&archive, &clean, &archive_prefix)?;
    let extracted = clean.join(&archive_prefix);
    require_same_tree(
        &tested_tree,
        &measure_tree(&extracted, MAX_TREE_FILES, MAX_TREE_BYTES)?,
        "archive extraction",
    )?;
    validate_installation_tree(&extracted)?;
    let extracted_forbidden = forbidden_release_paths(
        root,
        &plan,
        &[
            &first_lane.path,
            &second_lane.path,
            &private_build.path,
            &staging.path,
            &first_source,
            &second_source,
            &installation,
            &clean,
            &extracted,
        ],
    );
    let extracted_public = run_public_gates(
        &second_source,
        &extracted,
        &work,
        "extracted",
        &extracted_forbidden,
    )?;
    let extracted_qemu = run_enrolled_real_qemu_smoke(
        &second_source,
        &plan,
        &second_rust_tools,
        &extracted,
        &work,
        jobs,
        "extracted",
    )?;
    let extracted_real_qemu = extracted_qemu.bootstrap;
    let extracted_stdlib_time_qemu = extracted_qemu.stdlib_time;
    validate_isolated_rust_tools(&plan, &second_rust_tools)?;
    if installed_real_qemu != extracted_real_qemu {
        return Err(
            "installed/extracted real-QEMU image, report, or event evidence is not reproducible"
                .to_owned(),
        );
    }
    require_reproducible_stdlib_time_evidence(
        &installed_stdlib_time_qemu,
        &extracted_stdlib_time_qemu,
    )?;
    if extracted_public != installed_public {
        return Err(
            "installed/extracted public artifacts and reports are not path-independent".to_owned(),
        );
    }
    revalidate_release_witness(&second_source, &plan, "extracted clean-room rehearsal")?;
    require_same_tree(
        &tested_tree,
        &measure_tree(&extracted, MAX_TREE_FILES, MAX_TREE_BYTES)?,
        "extracted installation after public and QEMU routes",
    )?;
    validate_installation_tree(&extracted)?;
    require_same_tree(
        &tested_tree,
        &measure_tree(&installation, MAX_TREE_FILES, MAX_TREE_BYTES)?,
        "tested installation after clean-room rehearsal",
    )?;

    destroy_private_staging(&mut first_lane, "release build lane A")?;
    destroy_private_staging(&mut second_lane, "release build lane B")?;
    destroy_private_staging(&mut private_build, "distribution verification work tree")?;
    validate_installation_tree(&installation)?;
    let final_tree = measure_tree(&installation, MAX_TREE_FILES, MAX_TREE_BYTES)?;
    require_same_tree(&tested_tree, &final_tree, "final tested installation")?;
    revalidate_release_witness(root, &plan, "release receipt finalization")?;
    let evidence = ReleaseEvidence {
        frontend_a: &first_measurements.0,
        frontend_b: &second_measurements.0,
        backend_a: &first_measurements.1,
        backend_b: &second_measurements.1,
        installed_public: &installed_public,
        extracted_public: &extracted_public,
        runtime_boot: &runtime_boot,
        installed_real_qemu: &installed_real_qemu,
        extracted_real_qemu: &extracted_real_qemu,
        installed_stdlib_time_qemu: &installed_stdlib_time_qemu,
        extracted_stdlib_time_qemu: &extracted_stdlib_time_qemu,
    };
    let receipt = encode_release_receipt(&plan, &final_tree, &archive_measurement, &evidence)?;
    validate_release_receipt_schema(&receipt)?;
    write_new_bytes(&staging.path.join("release.txt"), receipt.as_bytes(), false)?;
    sync_tree(&staging.path)?;
    validate_existing_publication(
        &staging.path,
        &receipt,
        &archive_name,
        &final_tree,
        &archive_measurement,
    )?;
    revalidate_release_authority(root, root, &plan, "atomic publication boundary")?;

    let release_id = format!("wrela-{}-{}-{}", plan.release, plan.host, final_tree.sha256);
    let published = plan.output.join(&release_id);
    if published.exists() {
        validate_existing_publication(
            &published,
            &receipt,
            &archive_name,
            &final_tree,
            &archive_measurement,
        )?;
        sync_tree(&published)?;
        sync_directory(&plan.output).map_err(|error| {
            format!(
                "existing release {} is complete but output-directory durability could not be confirmed: {error}",
                published.display()
            )
        })?;
        validate_existing_publication(
            &published,
            &receipt,
            &archive_name,
            &final_tree,
            &archive_measurement,
        )?;
        make_directories_writable(&staging.path)?;
        fs::remove_dir_all(&staging.path)
            .map_err(|error| format!("cannot remove reused release staging tree: {error}"))?;
        staging.published = true;
        println!("reused verified distribution {}", published.display());
        return Ok(());
    }
    match fs::rename(&staging.path, &published) {
        Ok(()) => {
            // Visibility of the content-addressed final name is the commit point.
            // The complete staging tree was synced and validated immediately before
            // this rename, so it must never be rolled back after becoming visible.
            staging.published = true;
            sync_directory(&plan.output).map_err(|error| {
                format!(
                    "release {} committed atomically but output-directory durability could not be confirmed: {error}",
                    published.display()
                )
            })?;
        }
        Err(rename_error) if published.exists() => {
            validate_existing_publication(
                &published,
                &receipt,
                &archive_name,
                &final_tree,
                &archive_measurement,
            )
            .map_err(|validation_error| {
                format!(
                    "publication race for {} failed ({rename_error}); visible winner is invalid: {validation_error}",
                    published.display()
                )
            })?;
            sync_directory(&plan.output).map_err(|error| {
                format!(
                    "concurrent release {} is complete but output-directory durability could not be confirmed: {error}",
                    published.display()
                )
            })?;
            make_directories_writable(&staging.path)?;
            fs::remove_dir_all(&staging.path).map_err(|error| {
                format!("cannot remove losing concurrent release staging tree: {error}")
            })?;
            staging.published = true;
            println!(
                "reused concurrently published distribution {}",
                published.display()
            );
            return Ok(());
        }
        Err(error) => {
            return Err(format!(
                "cannot atomically publish distribution {}: {error}",
                published.display()
            ));
        }
    }
    println!(
        "published tested toolchain {}/installation",
        published.display()
    );
    println!(
        "published tested archive {}/{}",
        published.display(),
        archive_name
    );
    Ok(())
}

impl PrivateStaging {
    fn create(parent: &Path) -> Result<Self, String> {
        for _ in 0..128 {
            let sequence = NEXT_STAGING.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!(
                ".wrela-dist-staging-{}-{sequence}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    if let Err(error) = set_mode(&path, 0o700) {
                        let _ = fs::remove_dir(&path);
                        return Err(error);
                    }
                    return Ok(Self {
                        path,
                        published: false,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(format!(
                        "cannot create private distribution staging directory: {error}"
                    ));
                }
            }
        }
        Err("cannot allocate a unique distribution staging directory".to_owned())
    }
}

impl CargoEnrollmentLease {
    fn acquire(root: &Path, orchestrator: &FileMeasurement) -> Result<Self, String> {
        let parent = exact_directory(
            &root.join("toolchain"),
            "Cargo vendor enrollment authority directory",
        )?;
        let path = parent.join(".cargo-vendor-enrollment.lock");
        let bytes = format!(
            "schema = 1\npid = {}\norchestrator_sha256 = \"{}\"\n",
            std::process::id(),
            orchestrator.sha256
        );
        let mut file = match new_file(&path) {
            Ok(file) => file,
            Err(error) if path.exists() => {
                return Err(format!(
                    "Cargo vendor enrollment transaction already exists at {}; fail closed and remove it only after proving its owner cannot still publish: {error}",
                    path.display()
                ));
            }
            Err(error) => return Err(error),
        };
        file.write_all(bytes.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("cannot write Cargo vendor enrollment lease: {error}"))?;
        drop(file);
        set_mode(&path, 0o600)?;
        File::open(&path)
            .and_then(|file| file.sync_all())
            .map_err(|error| format!("cannot sync Cargo vendor enrollment lease: {error}"))?;
        sync_directory(&parent)?;
        let measurement = measure_file(&path, MAX_LOCK_BYTES, false)?;
        if measurement.sha256 != sha256_bytes(bytes.as_bytes()) {
            return Err("Cargo vendor enrollment lease differs after creation".to_owned());
        }
        Ok(Self {
            path,
            measurement,
            released: false,
        })
    }

    fn validate(&self) -> Result<(), String> {
        if self.released || measure_file(&self.path, MAX_LOCK_BYTES, false)? != self.measurement {
            return Err("Cargo vendor enrollment transaction lease changed".to_owned());
        }
        Ok(())
    }

    fn release(mut self) -> Result<(), String> {
        self.validate()?;
        fs::remove_file(&self.path).map_err(|error| {
            format!(
                "cannot release Cargo vendor enrollment transaction {}: {error}",
                self.path.display()
            )
        })?;
        sync_directory(
            self.path
                .parent()
                .ok_or_else(|| "Cargo vendor enrollment lease has no parent".to_owned())?,
        )?;
        self.released = true;
        Ok(())
    }
}

fn destroy_private_staging(staging: &mut PrivateStaging, label: &str) -> Result<(), String> {
    make_directories_writable(&staging.path)?;
    fs::remove_dir_all(&staging.path).map_err(|error| format!("cannot remove {label}: {error}"))?;
    staging.published = true;
    Ok(())
}

fn path_independent_build_mismatch(
    label: &str,
    lane_a: &FileMeasurement,
    lane_b: &FileMeasurement,
) -> String {
    format!(
        "two clean path-independent {label} builds were not byte-identical: lane A sha256={} bytes={}; lane B sha256={} bytes={}",
        lane_a.sha256, lane_a.bytes, lane_b.sha256, lane_b.bytes
    )
}

fn reject_ancestor_cargo_configuration(root: &Path) -> Result<(), String> {
    let root = exact_directory(root, "Cargo workspace snapshot")?;
    let mut ancestor = Some(root.as_path());
    while let Some(directory) = ancestor {
        for relative in [".cargo/config", ".cargo/config.toml"] {
            let candidate = directory.join(relative);
            match fs::symlink_metadata(&candidate) {
                Ok(_) => {
                    return Err(format!(
                        "Cargo workspace {} has undeclared ancestor configuration {}",
                        root.display(),
                        candidate.display()
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!(
                        "cannot inspect Cargo ancestor configuration {}: {error}",
                        candidate.display()
                    ));
                }
            }
        }
        ancestor = directory.parent();
    }
    Ok(())
}

fn validate_workspace_cargo_directory(root: &Path) -> Result<(), String> {
    let cargo_directory = exact_directory(&root.join(".cargo"), "workspace .cargo directory")?;
    let names = bounded_directory_names(&cargo_directory, 1, "workspace .cargo directory")?;
    if names != ["config.toml"] {
        return Err("workspace .cargo directory must contain exactly config.toml".to_owned());
    }
    exact_file(
        &cargo_directory.join("config.toml"),
        "workspace Cargo configuration",
    )?;
    Ok(())
}

fn forbidden_release_paths(
    authority_root: &Path,
    plan: &ReleasePlan,
    additional: &[&Path],
) -> Vec<PathBuf> {
    let mut paths = vec![
        authority_root.to_owned(),
        plan.output.clone(),
        plan.qemu_bundle.clone(),
        plan.cargo_vendor.clone(),
        plan.tools.cargo_home.clone(),
        plan.tools.rust_sysroot.clone(),
        plan.native.prefix.clone(),
        plan.native.sysroot.clone(),
        plan.native.ar.clone(),
        plan.native.cxx.clone(),
        plan.orchestrator.clone(),
    ];
    paths.extend(additional.iter().map(|path| (*path).to_owned()));
    paths.sort();
    paths.dedup();
    paths
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReleaseBuildProduct {
    Frontend,
    PrivateBackend,
}

fn release_build_arguments(
    manifest: &Path,
    target: &Path,
    jobs: u32,
    product: ReleaseBuildProduct,
) -> Vec<OsString> {
    let mut arguments = vec![
        OsString::from("rustc"),
        OsString::from("--locked"),
        OsString::from("--offline"),
        OsString::from("--manifest-path"),
        manifest.as_os_str().to_owned(),
        OsString::from("--profile"),
        OsString::from("dist"),
        OsString::from("--jobs"),
        OsString::from(jobs.to_string()),
        OsString::from("--target-dir"),
        target.as_os_str().to_owned(),
    ];
    match product {
        ReleaseBuildProduct::Frontend => arguments.extend([
            OsString::from("-p"),
            OsString::from("wrela-cli"),
            OsString::from("--bin"),
            OsString::from("wrela"),
        ]),
        ReleaseBuildProduct::PrivateBackend => arguments.extend([
            OsString::from("-p"),
            OsString::from("wrela-backend"),
            OsString::from("--bin"),
            OsString::from("wrela-backend"),
            OsString::from("--features"),
            OsString::from("wrela-backend/bundled-backend"),
        ]),
    }
    arguments.push(OsString::from("--"));
    arguments.extend(
        MACHO_LINKER_ARGUMENTS
            .iter()
            .map(|argument| OsString::from(format!("-Clink-arg={argument}"))),
    );
    arguments
}

fn run_release_build(
    plan: &ReleasePlan,
    execution: &CargoExecution<'_>,
    temp: &Path,
    jobs: u32,
    product: ReleaseBuildProduct,
    label: &str,
) -> Result<(), String> {
    let mut command = Command::new(&execution.rust_tools.cargo);
    command
        .current_dir(execution.work)
        .args(release_build_arguments(
            &execution.root.join("Cargo.toml"),
            execution.target,
            jobs,
            product,
        ));
    configure_cargo_environment(&mut command, plan, execution, temp);
    let output = run_command(&mut command, label, 3 * 60 * 60)?;
    require_success(&output, label, false)
}

fn build_release(
    plan: &ReleasePlan,
    execution: &CargoExecution<'_>,
    jobs: u32,
    label: &str,
) -> Result<(PathBuf, PathBuf), String> {
    build_release_with_validation(
        plan,
        execution,
        jobs,
        label,
        CargoValidationPolicy::PerCommand,
    )
}

fn build_release_with_validation(
    plan: &ReleasePlan,
    execution: &CargoExecution<'_>,
    jobs: u32,
    label: &str,
    validation: CargoValidationPolicy,
) -> Result<(PathBuf, PathBuf), String> {
    create_private_directory(execution.target)?;
    let temp = execution.target.join("tmp");
    create_private_directory(&temp)?;
    validate_cargo_execution(plan, execution, label)?;
    let frontend = execution.target.join("dist").join(executable_name("wrela"));
    let backend = execution
        .target
        .join("dist")
        .join(executable_name("wrela-backend"));

    let frontend_label = format!("{label} frontend");
    run_release_build(
        plan,
        execution,
        &temp,
        jobs,
        ReleaseBuildProduct::Frontend,
        &frontend_label,
    )?;
    if validation == CargoValidationPolicy::PerCommand {
        validate_cargo_execution(plan, execution, &frontend_label)?;
    }
    let frontend_measurement = measure_file(&frontend, MAX_FILE_BYTES, true)?;

    let backend_label = format!("{label} private backend");
    run_release_build(
        plan,
        execution,
        &temp,
        jobs,
        ReleaseBuildProduct::PrivateBackend,
        &backend_label,
    )?;
    if validation == CargoValidationPolicy::PerCommand {
        validate_cargo_execution(plan, execution, &backend_label)?;
    }
    if measure_file(&frontend, MAX_FILE_BYTES, true)? != frontend_measurement {
        return Err(format!(
            "{backend_label} changed the feature-isolated frontend artifact"
        ));
    }
    measure_file(&backend, MAX_FILE_BYTES, true)?;
    if validation == CargoValidationPolicy::Bracketed {
        validate_cargo_execution(plan, execution, &format!("{label} completion"))?;
    }
    Ok((frontend, backend))
}

fn freeze_release_outputs(
    binaries: &(PathBuf, PathBuf),
    binary_measurements: &(FileMeasurement, FileMeasurement),
    release_target: &Path,
    destination: &Path,
) -> Result<(PathBuf, PathBuf, PathBuf, FileMeasurement), String> {
    if destination.exists() {
        return Err("frozen release-output destination already exists".to_owned());
    }
    create_private_directory(destination)?;
    let frontend = destination.join(executable_name("wrela"));
    let backend = destination.join(executable_name("wrela-backend"));
    copy_exact_file(
        &binaries.0,
        &frontend,
        &binary_measurements.0,
        true,
        "release frontend selected for later consumers",
    )?;
    copy_exact_file(
        &binaries.1,
        &backend,
        &binary_measurements.1,
        true,
        "release backend selected for later consumers",
    )?;

    let shim_source = find_lld_shim(release_target)?;
    let shim_measurement = measure_file(&shim_source, MAX_FILE_BYTES, false)?;
    let shim = destination.join("libwrela_lld_shim.a");
    copy_exact_file(
        &shim_source,
        &shim,
        &shim_measurement,
        false,
        "release LLD shim selected for the runtime-smoke consumer",
    )?;
    Ok((frontend, backend, shim, shim_measurement))
}

fn retire_owned_cargo_target(target: &Path, owner: &Path, label: &str) -> Result<(), String> {
    let owner = exact_directory(owner, "Cargo-target owner")?;
    let target = exact_directory(target, label)?;
    if target.parent() != Some(owner.as_path()) {
        return Err(format!(
            "{label} is not an immediate child of its private owner"
        ));
    }
    make_directories_writable(&target)?;
    fs::remove_dir_all(&target).map_err(|error| format!("cannot retire {label}: {error}"))?;
    if target.exists() {
        return Err(format!("{label} remained after retirement"));
    }
    Ok(())
}

fn validate_cargo_execution(
    plan: &ReleasePlan,
    execution: &CargoExecution<'_>,
    label: &str,
) -> Result<(), String> {
    validate_isolated_rust_tools(plan, execution.rust_tools)?;
    validate_private_cargo_home(plan, execution.cargo_home)?;
    validate_cargo_invocation_context(execution.root, plan, execution.work, label)
}

fn validate_cargo_invocation_context(
    root: &Path,
    plan: &ReleasePlan,
    current_directory: &Path,
    label: &str,
) -> Result<(), String> {
    require_same_tree(
        &plan.source,
        &measure_source_tree(root)?,
        &format!("{label}: Cargo source tree"),
    )?;
    reject_ancestor_cargo_configuration(current_directory)
        .map_err(|error| format!("{label}: {error}"))
}

fn encoded_cargo_rustflags(
    source: &Path,
    target: &Path,
    work: &Path,
    linker: &Path,
    sysroot: &Path,
) -> String {
    [
        format!("--remap-path-prefix={}=/wrela/source", source.display()),
        format!("--remap-path-prefix={}=/wrela/build", target.display()),
        format!("--remap-path-prefix={}=/wrela/private", work.display()),
        format!("-Clinker={}", linker.display()),
        "-Clink-arg=-isysroot".to_owned(),
        format!("-Clink-arg={}", sysroot.display()),
        format!("-Clink-arg=-mmacosx-version-min={MACOS_DEPLOYMENT_TARGET}"),
    ]
    .join("\x1f")
}

fn configure_cargo_environment(
    command: &mut Command,
    plan: &ReleasePlan,
    execution: &CargoExecution<'_>,
    temp: &Path,
) {
    let flags = encoded_cargo_rustflags(
        execution.root,
        execution.target,
        execution.work,
        &plan.native.cxx,
        &plan.native.sysroot,
    );
    command
        .env_clear()
        .env("AR", &plan.native.ar)
        .env("CARGO_HOME", execution.cargo_home)
        .env("CARGO_INCREMENTAL", "0")
        .env("CARGO_NET_OFFLINE", "true")
        .env("CARGO_ENCODED_RUSTFLAGS", flags)
        .env("CC", &plan.native.cxx)
        .env("CXX", &plan.native.cxx)
        .env("HOME", temp)
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("LLVM_SYS_221_PREFIX", &plan.native.prefix)
        .env("MACOSX_DEPLOYMENT_TARGET", MACOS_DEPLOYMENT_TARGET)
        .env("PATH", "/wrela/no-ambient-path")
        .env("RUSTC", &execution.rust_tools.rustc)
        .env("RUSTDOC", &execution.rust_tools.rustdoc)
        .env("SDKROOT", &plan.native.sysroot)
        .env("SOURCE_DATE_EPOCH", "0")
        .env("TMPDIR", temp)
        .env("TZ", "UTC")
        .env("WRELA_LLVM_AR", &plan.native.ar)
        .env("WRELA_LLVM_CXX", &plan.native.cxx)
        .env("WRELA_LLVM_PREFIX", &plan.native.prefix)
        .env("WRELA_LLVM_SYSROOT", &plan.native.sysroot)
        .env("ZERO_AR_DATE", "1");
}

fn assemble_installation(
    root: &Path,
    plan: &ReleasePlan,
    installation: &Path,
    binaries: &(PathBuf, PathBuf),
    binary_measurements: &(FileMeasurement, FileMeasurement),
) -> Result<(), String> {
    let frontend = installation.join("bin").join(executable_name("wrela"));
    let backend = installation
        .join("libexec/wrela")
        .join(executable_name("wrela-backend"));
    let qemu = installation
        .join("libexec/wrela")
        .join(executable_name("qemu-system-aarch64"));
    copy_exact_file(
        &binaries.0,
        &frontend,
        &binary_measurements.0,
        true,
        "release frontend",
    )?;
    copy_exact_file(
        &binaries.1,
        &backend,
        &binary_measurements.1,
        true,
        "release backend",
    )?;
    copy_exact_tree_file(
        &plan.qemu_bundle,
        &plan.qemu,
        "bin/qemu-system-aarch64",
        &qemu,
    )?;

    let std_destination = installation.join("share/wrela/std").join(CORE_COMPONENT);
    copy_exact_tree_subtree(
        root,
        &plan.source,
        &format!("std/{CORE_COMPONENT}/"),
        &std_destination,
    )?;
    let target = installation
        .join("share/wrela/targets")
        .join(TARGET_IDENTITY);
    copy_exact_tree_file(
        root,
        &plan.source,
        &format!("toolchain/targets/{TARGET_IDENTITY}/target.toml"),
        &target.join("target.toml"),
    )?;
    copy_exact_tree_file(
        root,
        &plan.source,
        &format!("toolchain/targets/{TARGET_IDENTITY}/runtime/wrela-runtime-aarch64.obj"),
        &target.join("runtime/wrela-runtime-aarch64.obj"),
    )?;
    copy_exact_tree_file(
        &plan.qemu_bundle,
        &plan.qemu,
        "firmware/QEMU_EFI.fd",
        &target.join("firmware/QEMU_EFI.fd"),
    )?;
    copy_exact_tree_file(
        &plan.qemu_bundle,
        &plan.qemu,
        "firmware/QEMU_VARS.fd",
        &target.join("firmware/QEMU_VARS.fd"),
    )?;

    let appliance = installation.join("share/wrela/examples/virtio-storage");
    copy_exact_tree_file(
        root,
        &plan.source,
        "docs/language/examples/virtio-storage.wr",
        &appliance.join("virtio-storage.wr"),
    )?;
    copy_exact_tree_file(
        root,
        &plan.source,
        "docs/language/examples/virtio-storage-status.md",
        &appliance.join("STATUS.md"),
    )?;

    let licenses = installation.join("share/wrela/licenses");
    copy_exact_measured_tree(
        &plan.native.prefix.join("share/wrela/licenses"),
        &licenses,
        &plan.llvm_licenses,
        "LLVM license tree",
    )?;
    copy_exact_tree_file(
        root,
        &plan.source,
        "LICENSE",
        &licenses.join("wrela/LICENSE"),
    )?;
    for record in &plan.qemu.records {
        if let Some(relative) = record.path.strip_prefix("licenses/") {
            copy_exact_tree_file(
                &plan.qemu_bundle,
                &plan.qemu,
                &record.path,
                &licenses.join("qemu").join(relative),
            )?;
        }
    }
    let rust_licenses = licenses.join("rust");
    for record in &plan.rust_crate_licenses.records {
        let source = cargo_license_source_path(&record.path)?;
        copy_exact_tree_file(
            &plan.cargo_vendor,
            &plan.cargo_vendor_tree,
            &source,
            &rust_licenses.join(&record.path),
        )?;
    }
    require_same_tree(
        &plan.rust_crate_licenses,
        &measure_tree(&rust_licenses, MAX_TREE_FILES, MAX_TREE_BYTES)?,
        "installed Rust dependency license notices",
    )?;
    for record in &plan.rust_toolchain_licenses.records {
        let source = record
            .path
            .strip_prefix("toolchain/")
            .filter(|relative| portable_tree_path(relative))
            .ok_or_else(|| {
                "derived Rust toolchain license destination is not canonical".to_owned()
            })?;
        copy_exact_tree_file(
            &plan.tools.rust_sysroot,
            &plan.tools.rust_sysroot_tree,
            source,
            &rust_licenses.join(&record.path),
        )?;
    }
    require_same_tree(
        &plan.rust_licenses,
        &measure_tree(&rust_licenses, MAX_TREE_FILES, MAX_TREE_BYTES)?,
        "installed combined Rust license notices",
    )?;
    let provenance = installation.join("share/wrela/provenance");
    for (relative, name) in [
        ("toolchain/rust.outputs.toml", "rust.outputs.toml"),
        ("toolchain/cargo.outputs.toml", "cargo.outputs.toml"),
        ("toolchain/llvm.lock.toml", "llvm.lock.toml"),
        ("toolchain/llvm.outputs.toml", "llvm.outputs.toml"),
        ("toolchain/emulation.lock.toml", "emulation.lock.toml"),
        ("toolchain/emulation.outputs.toml", "emulation.outputs.toml"),
        (
            "toolchain/targets/aarch64-qemu-virt-uefi/runtime-src/runtime-object.lock.toml",
            "runtime-object.lock.toml",
        ),
    ] {
        copy_exact_tree_file(root, &plan.source, relative, &provenance.join(name))?;
    }
    copy_exact_file(
        &plan
            .native
            .prefix
            .parent()
            .ok_or_else(|| "verified LLVM prefix has no provenance parent".to_owned())?
            .join("provenance.txt"),
        &provenance.join("llvm-provenance.txt"),
        &plan.llvm_provenance,
        false,
        "LLVM provenance",
    )?;
    copy_exact_tree_file(
        &plan.qemu_bundle,
        &plan.qemu,
        "provenance.txt",
        &provenance.join("qemu-provenance.txt"),
    )?;
    let inputs = encode_installation_provenance(plan)?;
    write_new_bytes(
        &provenance.join("distribution-inputs.txt"),
        inputs.as_bytes(),
        false,
    )?;

    let standard_library = measure_tree(
        &installation.join("share/wrela/std"),
        MAX_TREE_FILES,
        MAX_TREE_BYTES,
    )?;
    require_same_tree(
        &exact_tree_subtree(&plan.source, &format!("std/{CORE_COMPONENT}/"))?,
        &measure_tree(&std_destination, MAX_TREE_FILES, MAX_TREE_BYTES)?,
        "installed standard-library source subtree",
    )?;
    validate_installed_core_inventory(installation)?;
    let standard_library_component = canonical_component_tree(&standard_library.records)?;
    let target_tree = measure_tree(&target, MAX_TREE_FILES, MAX_TREE_BYTES)?;
    let target_component = canonical_component_tree(&target_tree.records)?;
    let core_manifest = read_bounded_file(&std_destination.join("wrela.toml"), MAX_MANIFEST_BYTES)?;
    let core_image_source =
        read_bounded_file(&std_destination.join("src/image.wr"), MAX_FILE_BYTES)?;
    let core_result_source =
        read_bounded_file(&std_destination.join("src/result.wr"), MAX_FILE_BYTES)?;
    let core_time_source = read_bounded_file(&std_destination.join("src/time.wr"), MAX_FILE_BYTES)?;
    let core_manifest_digest = sha256_bytes(&core_manifest);
    let core_source_digest = package_source_digest(
        &core_manifest,
        &[
            ("image.wr", core_image_source.as_slice()),
            ("result.wr", core_result_source.as_slice()),
            ("time.wr", core_time_source.as_slice()),
        ],
    )?;
    if core_manifest_digest != CORE_MANIFEST_SHA256 || core_source_digest != CORE_SOURCE_DIGEST {
        return Err(
            "installed core package identity differs from the exact-current standard library"
                .to_owned(),
        );
    }
    let frontend_measurement = measure_file(&frontend, MAX_FILE_BYTES, true)?;
    let backend_measurement = measure_file(&backend, MAX_FILE_BYTES, true)?;
    let qemu_measurement = measure_file(&qemu, MAX_FILE_BYTES, true)?;
    let firmware_code = measure_file(&target.join("firmware/QEMU_EFI.fd"), MAX_FILE_BYTES, false)?;
    let firmware_variables =
        measure_file(&target.join("firmware/QEMU_VARS.fd"), MAX_FILE_BYTES, false)?;
    let runtime = measure_file(
        &target.join("runtime/wrela-runtime-aarch64.obj"),
        MAX_RUNTIME_OBJECT_BYTES,
        false,
    )?;
    for component in ["llvm", "lld"] {
        require_same_tree(
            &exact_tree_subtree(&plan.llvm_licenses, &format!("{component}/"))?,
            &measure_tree(&licenses.join(component), MAX_TREE_FILES, MAX_TREE_BYTES)?,
            &format!("installed {component} license notices"),
        )?;
    }
    if frontend_measurement != binary_measurements.0
        || backend_measurement != binary_measurements.1
        || qemu_measurement != required_file_measurement(&plan.qemu, "bin/qemu-system-aarch64")?
        || firmware_code != required_file_measurement(&plan.qemu, "firmware/QEMU_EFI.fd")?
        || firmware_variables != required_file_measurement(&plan.qemu, "firmware/QEMU_VARS.fd")?
        || runtime
            != (FileMeasurement {
                sha256: plan.runtime.object_sha256.clone(),
                bytes: plan.runtime.object_bytes,
            })
        || measure_file(
            &provenance.join("llvm-provenance.txt"),
            MAX_LOCK_BYTES,
            false,
        )? != plan.llvm_provenance
    {
        return Err("installed release inputs differ from their planned identities".to_owned());
    }
    let manifest = encode_toolchain_manifest(ManifestInputs {
        release: &plan.release,
        host: &plan.host,
        core_source_digest: &core_source_digest,
        core_manifest_digest: &core_manifest_digest,
        frontend: &frontend_measurement,
        backend: &backend_measurement,
        standard_library: &standard_library_component,
        qemu: &qemu_measurement,
        target: &target_component,
        firmware_code: &firmware_code,
        firmware_variables: &firmware_variables,
        runtime: &runtime,
    })?;
    write_new_bytes(
        &installation.join("share/wrela/toolchain.toml"),
        manifest.as_bytes(),
        false,
    )?;
    Ok(())
}

struct ManifestInputs<'a> {
    release: &'a str,
    host: &'a str,
    core_source_digest: &'a str,
    core_manifest_digest: &'a str,
    frontend: &'a FileMeasurement,
    backend: &'a FileMeasurement,
    standard_library: &'a FileMeasurement,
    qemu: &'a FileMeasurement,
    target: &'a FileMeasurement,
    firmware_code: &'a FileMeasurement,
    firmware_variables: &'a FileMeasurement,
    runtime: &'a FileMeasurement,
}

fn encode_toolchain_manifest(inputs: ManifestInputs<'_>) -> Result<String, String> {
    for atom in [inputs.release, inputs.host, LLVM_PROJECT_REVISION] {
        if atom.is_empty()
            || atom.len() > 4096
            || atom.chars().any(char::is_whitespace)
            || atom.chars().any(char::is_control)
        {
            return Err("toolchain manifest atom is invalid".to_owned());
        }
    }
    for digest in [
        inputs.core_source_digest,
        inputs.core_manifest_digest,
        &inputs.frontend.sha256,
        &inputs.backend.sha256,
        &inputs.standard_library.sha256,
        &inputs.qemu.sha256,
        &inputs.target.sha256,
        &inputs.firmware_code.sha256,
        &inputs.firmware_variables.sha256,
        &inputs.runtime.sha256,
    ] {
        if !canonical_digest(digest) {
            return Err("toolchain manifest contains a noncanonical digest".to_owned());
        }
    }
    Ok(format!(
        "schema = {TOOLCHAIN_MANIFEST_SCHEMA}\n\
release = \"{}\"\n\
host = \"{}\"\n\
llvm_project_revision = \"{LLVM_PROJECT_REVISION}\"\n\
\n\
[compatibility]\n\
language = \"0.1-design\"\n\
build_profile_encoding = 2\n\
backend_protocol = 5\n\
target_package = 1\n\
semantic_wir = 8\n\
flow_wir = 10\n\
flow_wir_wire = 10\n\
machine_wir = 10\n\
runtime_abi = 2\n\
image_report = 11\n\
test_plan = 2\n\
test_report = 2\n\
image_scenario = 1\n\
test_event = 3\n\
test_frame = 1\n\
\n\
[[standard_library_packages]]\n\
name = \"{CORE_NAME}\"\n\
version = \"{CORE_VERSION}\"\n\
source_digest = \"{}\"\n\
component = \"{CORE_COMPONENT}\"\n\
manifest_digest = \"{}\"\n\
\n\
[[components]]\n\
kind = \"frontend\"\n\
path = \"bin/{}\"\n\
digest = \"{}\"\n\
bytes = {}\n\
\n\
[[components]]\n\
kind = \"backend\"\n\
path = \"libexec/wrela/{}\"\n\
digest = \"{}\"\n\
bytes = {}\n\
\n\
[[components]]\n\
kind = \"standard_library\"\n\
path = \"share/wrela/std\"\n\
digest = \"{}\"\n\
bytes = {}\n\
\n\
[[components]]\n\
kind = \"aarch64_emulator\"\n\
path = \"libexec/wrela/{}\"\n\
digest = \"{}\"\n\
bytes = {}\n\
\n\
[[targets]]\n\
identity = \"{TARGET_IDENTITY}\"\n\
path = \"share/wrela/targets/{TARGET_IDENTITY}\"\n\
digest = \"{}\"\n\
bytes = {}\n\
\n\
[[targets.files]]\n\
path = \"firmware/QEMU_EFI.fd\"\n\
digest = \"{}\"\n\
bytes = {}\n\
\n\
[[targets.files]]\n\
path = \"firmware/QEMU_VARS.fd\"\n\
digest = \"{}\"\n\
bytes = {}\n\
\n\
[[targets.files]]\n\
path = \"runtime/wrela-runtime-aarch64.obj\"\n\
digest = \"{}\"\n\
bytes = {}\n",
        inputs.release,
        inputs.host,
        inputs.core_source_digest,
        inputs.core_manifest_digest,
        executable_name("wrela"),
        inputs.frontend.sha256,
        inputs.frontend.bytes,
        executable_name("wrela-backend"),
        inputs.backend.sha256,
        inputs.backend.bytes,
        inputs.standard_library.sha256,
        inputs.standard_library.bytes,
        executable_name("qemu-system-aarch64"),
        inputs.qemu.sha256,
        inputs.qemu.bytes,
        inputs.target.sha256,
        inputs.target.bytes,
        inputs.firmware_code.sha256,
        inputs.firmware_code.bytes,
        inputs.firmware_variables.sha256,
        inputs.firmware_variables.bytes,
        inputs.runtime.sha256,
        inputs.runtime.bytes,
    ))
}

fn package_source_digest(manifest: &[u8], sources: &[(&str, &[u8])]) -> Result<String, String> {
    if manifest.is_empty()
        || sources.len() != 3
        || sources[0].0 != "image.wr"
        || sources[1].0 != "result.wr"
        || sources[2].0 != "time.wr"
        || sources.iter().any(|(path, source)| {
            source.is_empty() || !portable_tree_path(path) || !path.ends_with(".wr")
        })
        || sources.windows(2).any(|pair| pair[0].0 >= pair[1].0)
    {
        return Err("standard-library package content is empty or noncanonical".to_owned());
    }
    let mut digest = Sha256::new();
    digest.update(PACKAGE_CONTENT_MAGIC);
    digest.update(PACKAGE_CONTENT_VERSION.to_le_bytes());
    update_length_prefixed(&mut digest, manifest)?;
    digest.update(
        u64::try_from(sources.len())
            .map_err(|_| "standard-library source count does not fit u64".to_owned())?
            .to_le_bytes(),
    );
    for (path, source) in sources {
        digest.update([0]);
        update_length_prefixed(&mut digest, path.as_bytes())?;
        digest.update(Sha256::digest(source));
    }
    Ok(lower_hex(&digest.finalize()))
}

fn encode_installation_provenance(plan: &ReleasePlan) -> Result<String, String> {
    Ok(format!(
        "schema = 3\n\
release = \"{}\"\n\
host = \"{}\"\n\
rust_toolchain = \"{}\"\n\
rust_toolchain_file_sha256 = \"{}\"\n\
source_tree_sha256 = \"{}\"\n\
dist_implementation_sha256 = \"{}\"\n\
llvm_prefix_tree_sha256 = \"{}\"\n\
qemu_native_input_sha256 = \"{}\"\n\
qemu_bundle_tree_sha256 = \"{}\"\n\
runtime_object_sha256 = \"{}\"\n\
cargo_sha256 = \"{}\"\n\
rustc_sha256 = \"{}\"\n\
rust_sysroot_tree_sha256 = \"{}\"\n\
rust_sysroot_files = {}\n\
rust_sysroot_bytes = {}\n\
cargo_lock_sha256 = \"{}\"\n\
cargo_vendor_tree_sha256 = \"{}\"\n\
cargo_vendor_files = {}\n\
cargo_vendor_bytes = {}\n\
rust_license_tree_sha256 = \"{}\"\n\
rust_license_files = {}\n\
rust_license_bytes = {}\n",
        plan.release,
        plan.host,
        plan.rust_toolchain,
        plan.rust_output.rust_toolchain_sha256,
        plan.source.sha256,
        plan.dist_implementation_sha256,
        plan.llvm_prefix_tree_sha256,
        plan.emulation_output.native_input_sha256,
        plan.qemu.sha256,
        plan.runtime.object_sha256,
        plan.tools.cargo_digest,
        plan.tools.rustc_digest,
        plan.rust_output.sysroot_tree_sha256,
        plan.rust_output.sysroot_files,
        plan.rust_output.sysroot_bytes,
        plan.cargo_output.cargo_lock_sha256,
        plan.cargo_output.vendor_tree_sha256,
        plan.cargo_output.vendor_files,
        plan.cargo_output.vendor_bytes,
        plan.rust_licenses.sha256,
        plan.rust_licenses.files,
        plan.rust_licenses.bytes,
    ))
}

fn run_repository_gates(
    root: &Path,
    plan: &ReleasePlan,
    rust_tools: &IsolatedRustTools,
    cargo_home: &Path,
    work: &Path,
    jobs: u32,
) -> Result<(), String> {
    if measure_file(&plan.orchestrator, MAX_FILE_BYTES, true)? != plan.orchestrator_measurement {
        return Err("distribution orchestrator changed before architecture gate".to_owned());
    }
    let workspace_target = work.join("cargo-gates-workspace");
    create_private_directory(&workspace_target)?;
    let workspace_temp = workspace_target.join("tmp");
    create_private_directory(&workspace_temp)?;
    let workspace_execution = CargoExecution {
        root,
        rust_tools,
        cargo_home,
        target: &workspace_target,
        work,
    };
    validate_cargo_execution(plan, &workspace_execution, "release architecture check")?;
    crate::check_architecture_with_tools(
        root,
        &rust_tools.cargo,
        &rust_tools.rustc,
        &rust_tools.rustdoc,
        cargo_home,
        work,
    )
    .map_err(|error| format!("release architecture check failed: {error}"))?;
    validate_cargo_execution(plan, &workspace_execution, "release architecture check")?;
    if measure_file(&plan.orchestrator, MAX_FILE_BYTES, true)? != plan.orchestrator_measurement {
        return Err("distribution orchestrator changed during architecture gate".to_owned());
    }

    validate_cargo_execution(plan, &workspace_execution, "release workspace tests")?;
    let mut tests = Command::new(&rust_tools.cargo);
    tests.current_dir(work).args([
        OsString::from("test"),
        OsString::from("--locked"),
        OsString::from("--offline"),
        OsString::from("--manifest-path"),
        root.join("Cargo.toml").into_os_string(),
        OsString::from("--workspace"),
        OsString::from("--all-targets"),
        OsString::from("--jobs"),
        OsString::from(jobs.to_string()),
        OsString::from("--target-dir"),
        workspace_target.as_os_str().to_owned(),
    ]);
    configure_cargo_environment(&mut tests, plan, &workspace_execution, &workspace_temp);
    let output = run_command(
        &mut tests,
        "release workspace unit and corruption tests",
        3 * 60 * 60,
    )?;
    require_success(
        &output,
        "release workspace unit and corruption tests",
        false,
    )?;
    validate_cargo_execution(plan, &workspace_execution, "release workspace tests")?;
    retire_owned_cargo_target(
        &workspace_target,
        work,
        "release workspace-test Cargo target",
    )?;

    let native_target = work.join("cargo-gates-native");
    create_private_directory(&native_target)?;
    let native_temp = native_target.join("tmp");
    create_private_directory(&native_temp)?;
    let native_execution = CargoExecution {
        root,
        rust_tools,
        cargo_home,
        target: &native_target,
        work,
    };
    validate_cargo_execution(plan, &native_execution, "release native backend tests")?;
    let mut native = Command::new(&rust_tools.cargo);
    native.current_dir(work).args([
        OsString::from("test"),
        OsString::from("--locked"),
        OsString::from("--offline"),
        OsString::from("--manifest-path"),
        root.join("Cargo.toml").into_os_string(),
        OsString::from("-p"),
        OsString::from("wrela-backend"),
        OsString::from("--all-targets"),
        OsString::from("--features"),
        OsString::from("bundled-backend"),
        OsString::from("--jobs"),
        OsString::from(jobs.to_string()),
        OsString::from("--target-dir"),
        native_target.as_os_str().to_owned(),
    ]);
    configure_cargo_environment(&mut native, plan, &native_execution, &native_temp);
    let output = run_command(&mut native, "release native backend tests", 3 * 60 * 60)?;
    require_success(&output, "release native backend tests", false)?;
    validate_cargo_execution(plan, &native_execution, "release native backend tests")?;
    retire_owned_cargo_target(&native_target, work, "release native-backend Cargo target")
}

fn run_public_gates(
    root: &Path,
    installation: &Path,
    work: &Path,
    installation_kind: &str,
    forbidden_paths: &[PathBuf],
) -> Result<PublicGateEvidence, String> {
    if !matches!(installation_kind, "installed" | "extracted") {
        return Err("public-gate installation kind is not reviewed".to_owned());
    }
    let frontend = installation.join("bin").join(executable_name("wrela"));
    let workspace = root.join("std/examples/minimal-image");
    let manifest = workspace.join("wrela.toml");
    let temp = work.join(format!("public-gates-{installation_kind}"));
    create_private_directory(&temp)?;
    for (label, arguments) in [
        ("public version", vec![OsString::from("version")]),
        ("public doctor", vec![OsString::from("doctor")]),
        (
            "public check",
            vec![
                OsString::from("check"),
                manifest.as_os_str().to_owned(),
                OsString::from("bootstrap"),
            ],
        ),
        (
            "public lint",
            vec![
                OsString::from("lint"),
                manifest.as_os_str().to_owned(),
                OsString::from("bootstrap"),
            ],
        ),
    ] {
        let output = run_public_command(
            &frontend,
            installation,
            &workspace,
            &temp,
            &arguments,
            label,
            30 * 60,
        )?;
        require_success(&output, label, false)?;
    }

    let first_output = temp.join("build-a");
    let second_output = temp.join("build-b");
    for (label, output_directory) in [
        ("public build A", &first_output),
        ("public build B", &second_output),
    ] {
        let output = run_public_command(
            &frontend,
            installation,
            &workspace,
            &temp,
            &[
                OsString::from("build"),
                manifest.as_os_str().to_owned(),
                OsString::from("bootstrap"),
                output_directory.as_os_str().to_owned(),
            ],
            label,
            60 * 60,
        )?;
        require_success(&output, label, false)?;
    }
    let first_build = measure_tree(&first_output, MAX_TREE_FILES, MAX_TREE_BYTES)?;
    let second_build = measure_tree(&second_output, MAX_TREE_FILES, MAX_TREE_BYTES)?;
    require_same_tree(
        &first_build,
        &second_build,
        "two public PATH-cleared builds",
    )?;
    for name in ["bootstrap.efi", "bootstrap.image-report.json"] {
        required_record(&first_build, name)?;
    }
    reject_embedded_paths_in_tree(
        &first_output,
        &first_build,
        forbidden_paths,
        &format!("{installation_kind} public build A"),
    )?;
    reject_embedded_paths_in_tree(
        &second_output,
        &second_build,
        forbidden_paths,
        &format!("{installation_kind} public build B"),
    )?;
    let format_workspace = temp.join("format-workspace");
    create_private_directory(&format_workspace)?;
    copy_tree_mutable(&workspace, &format_workspace)?;
    let format_manifest = format_workspace.join("wrela.toml");
    let format_source = format_workspace.join("src/bootstrap/image.wr");
    let format_arguments = [
        OsString::from("format"),
        format_manifest.as_os_str().to_owned(),
        format_source.as_os_str().to_owned(),
    ];
    let first_format = run_public_command(
        &frontend,
        installation,
        &format_workspace,
        &temp,
        &format_arguments,
        "public format A",
        30 * 60,
    )?;
    require_success(&first_format, "public format A", false)?;
    let formatted = measure_file(&format_source, MAX_FILE_BYTES, false)?;
    let second_format = run_public_command(
        &frontend,
        installation,
        &format_workspace,
        &temp,
        &format_arguments,
        "public format B",
        30 * 60,
    )?;
    require_success(&second_format, "public format B", false)?;
    if formatted != measure_file(&format_source, MAX_FILE_BYTES, false)? {
        return Err("public formatter is not idempotent".to_owned());
    }

    let test_output = temp.join("test-output");
    let output = run_public_command(
        &frontend,
        installation,
        &workspace,
        &temp,
        &[
            OsString::from("test"),
            manifest.as_os_str().to_owned(),
            OsString::from("bootstrap"),
            test_output.as_os_str().to_owned(),
        ],
        "public full-image test",
        60 * 60,
    )?;
    require_success(&output, "public full-image test", false)?;
    let test = measure_tree(&test_output, MAX_TREE_FILES, MAX_TREE_BYTES)?;
    required_record(&test, "test-report.bin")?;
    reject_embedded_paths_in_tree(
        &test_output,
        &test,
        forbidden_paths,
        &format!("{installation_kind} public test output"),
    )?;
    Ok(PublicGateEvidence {
        build: first_build,
        test,
    })
}

fn run_enrolled_real_qemu_smoke(
    root: &Path,
    plan: &ReleasePlan,
    rust_tools: &IsolatedRustTools,
    installation: &Path,
    work: &Path,
    jobs: u32,
    installation_kind: &str,
) -> Result<EnrolledQemuEvidence, String> {
    let (evidence, checked_shift) = run_enrolled_qemu_suite(
        root,
        plan,
        rust_tools,
        installation,
        work,
        jobs,
        installation_kind,
        CargoValidationPolicy::PerCommand,
        false,
    )?;
    if checked_shift.is_some() {
        return Err(
            "release QEMU route unexpectedly executed an integration-only contract".to_owned(),
        );
    }
    Ok(evidence)
}

fn run_enrolled_lane_b_qemu(
    root: &Path,
    plan: &ReleasePlan,
    rust_tools: &IsolatedRustTools,
    installation: &Path,
    work: &Path,
    jobs: u32,
) -> Result<LaneBQemuEvidence, String> {
    let (evidence, checked_shift) = run_enrolled_qemu_suite(
        root,
        plan,
        rust_tools,
        installation,
        work,
        jobs,
        "integration",
        CargoValidationPolicy::Bracketed,
        true,
    )?;
    Ok(LaneBQemuEvidence {
        bootstrap: evidence.bootstrap,
        stdlib_time: evidence.stdlib_time,
        checked_shift: checked_shift
            .ok_or_else(|| "Lane B QEMU route omitted checked-shift evidence".to_owned())?,
    })
}

#[allow(clippy::too_many_arguments)]
fn run_enrolled_current_tranche_qemu(
    root: &Path,
    plan: &ReleasePlan,
    rust_tools: &IsolatedRustTools,
    installation: &Path,
    work: &Path,
    jobs: u32,
    run_binding_sha256: &str,
) -> Result<CurrentTrancheQemuEvidence, String> {
    let smoke = work.join("real-qemu-smoke-current-tranche");
    create_private_directory(&smoke)?;
    let cargo_home = smoke.join("cargo-home");
    prepare_private_cargo_home(plan, &cargo_home)?;
    let target = smoke.join("cargo");
    create_private_directory(&target)?;
    let temp = target.join("tmp");
    create_private_directory(&temp)?;
    let execution = CargoExecution {
        root,
        rust_tools,
        cargo_home: &cargo_home,
        target: &target,
        work: &smoke,
    };
    validate_cargo_execution(plan, &execution, "current-tranche real-QEMU start")?;
    let timeout = run_enrolled_runtime_timeout_qemu_case(
        plan,
        &execution,
        installation,
        &target,
        &temp,
        jobs,
        run_binding_sha256,
    )?;
    let stdlib_time = run_enrolled_stdlib_time_qemu(
        plan,
        &execution,
        installation,
        &target,
        &temp,
        jobs,
        "integration",
        CargoValidationPolicy::Bracketed,
    )?;
    let (checked_shift, runtime_result) = run_enrolled_current_tranche_checked_shift_qemu(
        plan,
        &execution,
        installation,
        &target,
        &temp,
        jobs,
    )?;
    validate_cargo_execution(plan, &execution, "current-tranche real-QEMU completion")?;
    retire_owned_cargo_target(&target, &smoke, "current-tranche real-QEMU Cargo target")?;
    Ok(CurrentTrancheQemuEvidence {
        timeout,
        stdlib_time,
        checked_shift,
        runtime_result,
    })
}

#[allow(clippy::too_many_arguments)]
fn run_enrolled_qemu_suite(
    root: &Path,
    plan: &ReleasePlan,
    rust_tools: &IsolatedRustTools,
    installation: &Path,
    work: &Path,
    jobs: u32,
    installation_kind: &str,
    validation: CargoValidationPolicy,
    include_checked_shift: bool,
) -> Result<(EnrolledQemuEvidence, Option<CheckedShiftQemuEvidence>), String> {
    if !matches!(installation_kind, "installed" | "extracted" | "integration") {
        return Err("real-QEMU smoke installation kind is not reviewed".to_owned());
    }
    let smoke = work.join(format!("real-qemu-smoke-{installation_kind}"));
    create_private_directory(&smoke)?;
    let cargo_home = smoke.join("cargo-home");
    prepare_private_cargo_home(plan, &cargo_home)?;
    let target = smoke.join("cargo");
    create_private_directory(&target)?;
    let temp = target.join("tmp");
    create_private_directory(&temp)?;
    let run_root = smoke.join("run");
    if run_root.exists() {
        return Err("real-QEMU smoke run root unexpectedly exists".to_owned());
    }

    let execution = CargoExecution {
        root,
        rust_tools,
        cargo_home: &cargo_home,
        target: &target,
        work: &smoke,
    };
    validate_cargo_execution(plan, &execution, "real-QEMU smoke")?;
    let mut command = Command::new(&rust_tools.cargo);
    command.current_dir(&smoke).args([
        OsString::from("test"),
        OsString::from("--locked"),
        OsString::from("--offline"),
        OsString::from("--manifest-path"),
        root.join("Cargo.toml").into_os_string(),
        OsString::from("--color"),
        OsString::from("never"),
        OsString::from("--jobs"),
        OsString::from(jobs.to_string()),
        OsString::from("--target-dir"),
        target.as_os_str().to_owned(),
        OsString::from("-p"),
        OsString::from("wrela-test-runner"),
        OsString::from("--test"),
        OsString::from("real_qemu_smoke"),
        OsString::from("enrolled_bundle_executes_real_qemu_lifecycle"),
        OsString::from("--"),
        OsString::from("--ignored"),
        OsString::from("--exact"),
        OsString::from("--nocapture"),
        OsString::from("--test-threads=1"),
    ]);
    configure_cargo_environment(&mut command, plan, &execution, &temp);
    command
        .env("WRELA_SMOKE_RUN_ROOT", &run_root)
        .env("WRELA_SMOKE_TOOLCHAIN_ROOT", installation);
    let label = format!("{installation_kind} enrolled real-QEMU lifecycle smoke");
    let output = run_command(&mut command, &label, 2 * 60 * 60)?;
    require_success(&output, &label, false)?;
    if validation == CargoValidationPolicy::PerCommand {
        validate_cargo_execution(plan, &execution, "real-QEMU smoke")?;
    }
    require_exact_test_execution(
        &output.stdout,
        "enrolled_bundle_executes_real_qemu_lifecycle",
        &label,
    )?;
    let bootstrap = parse_real_qemu_evidence(&output.stdout, &label)?;
    if run_root.exists() {
        return Err(format!(
            "{label} left its private execution directory behind"
        ));
    }
    let stdlib_time = run_enrolled_stdlib_time_qemu(
        plan,
        &execution,
        installation,
        &target,
        &temp,
        jobs,
        installation_kind,
        validation,
    )?;
    let checked_shift = if include_checked_shift {
        Some(run_enrolled_checked_shift_qemu(
            plan,
            &execution,
            installation,
            &target,
            &temp,
            jobs,
            installation_kind,
            validation,
        )?)
    } else {
        None
    };
    if validation == CargoValidationPolicy::Bracketed {
        validate_cargo_execution(plan, &execution, "real-QEMU suite completion")?;
    }
    retire_owned_cargo_target(&target, &smoke, &format!("{label} Cargo target"))?;
    Ok((
        EnrolledQemuEvidence {
            bootstrap,
            stdlib_time,
        },
        checked_shift,
    ))
}

#[allow(clippy::too_many_arguments)]
fn run_enrolled_stdlib_time_qemu(
    plan: &ReleasePlan,
    execution: &CargoExecution<'_>,
    installation: &Path,
    target: &Path,
    temp: &Path,
    jobs: u32,
    installation_kind: &str,
    validation: CargoValidationPolicy,
) -> Result<StdlibTimeQemuEvidence, String> {
    const TEST: &str = "installed_core_time_source_executes_under_enrolled_qemu";
    let run_root = execution.work.join("stdlib-time-run");
    let evidence_root = execution.work.join("stdlib-time-evidence");
    if run_root.exists() || evidence_root.exists() {
        return Err(format!(
            "{installation_kind} stdlib-time real-QEMU roots unexpectedly exist"
        ));
    }

    let label = format!("{installation_kind} installed-stdlib core.time real-QEMU vertical");
    let result = (|| {
        let mut command = Command::new(&execution.rust_tools.cargo);
        command.current_dir(execution.work).args([
            OsString::from("test"),
            OsString::from("--locked"),
            OsString::from("--offline"),
            OsString::from("--manifest-path"),
            execution.root.join("Cargo.toml").into_os_string(),
            OsString::from("--color"),
            OsString::from("never"),
            OsString::from("--jobs"),
            OsString::from(jobs.to_string()),
            OsString::from("--target-dir"),
            target.as_os_str().to_owned(),
            OsString::from("-p"),
            OsString::from("wrela-test-runner"),
            OsString::from("--test"),
            OsString::from("stdlib_time_real_qemu"),
            OsString::from(TEST),
            OsString::from("--"),
            OsString::from("--ignored"),
            OsString::from("--exact"),
            OsString::from("--nocapture"),
            OsString::from("--test-threads=1"),
        ]);
        configure_cargo_environment(&mut command, plan, execution, temp);
        command
            .env("WRELA_STDLIB_TIME_EVIDENCE_ROOT", &evidence_root)
            .env("WRELA_STDLIB_TIME_RUN_ROOT", &run_root)
            .env("WRELA_STDLIB_TIME_TOOLCHAIN_ROOT", installation);
        let output = run_command(&mut command, &label, 2 * 60 * 60)?;
        require_success(&output, &label, false)?;
        if validation == CargoValidationPolicy::PerCommand {
            validate_cargo_execution(plan, execution, &label)?;
        }
        require_exact_test_execution(&output.stdout, TEST, &label)?;
        let parsed = parse_stdlib_time_qemu_evidence(&output.stdout, &label)?;
        let recomputed =
            recompute_stdlib_time_qemu_evidence(execution.root, &evidence_root, &label)?;
        if parsed != recomputed {
            return Err(format!(
                "{label} canonical line differs from independently measured source or runtime artifacts"
            ));
        }
        if run_root.exists() {
            return Err(format!("{label} left its private execution root behind"));
        }
        Ok(parsed)
    })();

    let cleanup = cleanup_stdlib_time_qemu_roots(execution.work, &run_root, &evidence_root, &label);
    match (result, cleanup) {
        (Ok(evidence), Ok(())) => Ok(evidence),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(format!(
            "{error}; stdlib-time QEMU cleanup also failed: {cleanup}"
        )),
    }
}

fn checked_shift_qemu_arguments(root: &Path, target: &Path, jobs: u32) -> Vec<OsString> {
    checked_shift_qemu_arguments_for_test(
        root,
        target,
        jobs,
        "enrolled_bundle_executes_checked_shift_runtime_contract",
    )
}

fn current_tranche_qemu_arguments(root: &Path, target: &Path, jobs: u32) -> Vec<OsString> {
    checked_shift_qemu_arguments_for_test(
        root,
        target,
        jobs,
        "enrolled_bundle_executes_current_tranche_runtime_contract",
    )
}

fn checked_shift_qemu_arguments_for_test(
    root: &Path,
    target: &Path,
    jobs: u32,
    test: &str,
) -> Vec<OsString> {
    vec![
        OsString::from("test"),
        OsString::from("--locked"),
        OsString::from("--offline"),
        OsString::from("--manifest-path"),
        root.join("Cargo.toml").into_os_string(),
        OsString::from("--color"),
        OsString::from("never"),
        OsString::from("--jobs"),
        OsString::from(jobs.to_string()),
        OsString::from("--target-dir"),
        target.as_os_str().to_owned(),
        OsString::from("-p"),
        OsString::from("wrela-test-runner"),
        OsString::from("--test"),
        OsString::from("real_qemu_smoke"),
        OsString::from(test),
        OsString::from("--"),
        OsString::from("--ignored"),
        OsString::from("--exact"),
        OsString::from("--nocapture"),
        OsString::from("--test-threads=1"),
    ]
}

fn runtime_timeout_qemu_arguments(root: &Path, target: &Path, jobs: u32) -> Vec<OsString> {
    vec![
        OsString::from("test"),
        OsString::from("--locked"),
        OsString::from("--offline"),
        OsString::from("--manifest-path"),
        root.join("Cargo.toml").into_os_string(),
        OsString::from("--color"),
        OsString::from("never"),
        OsString::from("--jobs"),
        OsString::from(jobs.to_string()),
        OsString::from("--target-dir"),
        target.as_os_str().to_owned(),
        OsString::from("-p"),
        OsString::from("wrela-test-runner"),
        OsString::from("--test"),
        OsString::from("real_qemu_smoke"),
        OsString::from("enrolled_bundle_executes_runtime_timeout_contract"),
        OsString::from("--"),
        OsString::from("--ignored"),
        OsString::from("--exact"),
        OsString::from("--nocapture"),
        OsString::from("--test-threads=1"),
    ]
}

fn runtime_timeout_run_binding(
    source: &TreeMeasurement,
    installation: &TreeMeasurement,
    frontend: &FileMeasurement,
    backend: &FileMeasurement,
    qemu_bundle_sha256: &str,
    qemu_native_input_sha256: &str,
) -> Result<String, String> {
    let digests = [
        source.sha256.as_str(),
        installation.sha256.as_str(),
        frontend.sha256.as_str(),
        backend.sha256.as_str(),
        qemu_bundle_sha256,
        qemu_native_input_sha256,
    ];
    if digests.iter().any(|digest| !canonical_digest(digest))
        || [
            source.files,
            source.bytes,
            installation.files,
            installation.bytes,
            frontend.bytes,
            backend.bytes,
        ]
        .contains(&0)
    {
        return Err(
            "runtime-timeout run binding contains an invalid identity or extent".to_owned(),
        );
    }
    let preimage = format!(
        "WRELA_RUNTIME_TIMEOUT_RUN_BINDING schema=1 source_sha256={} source_files={} source_bytes={} installation_sha256={} installation_files={} installation_bytes={} frontend_sha256={} frontend_bytes={} backend_sha256={} backend_bytes={} qemu_bundle_sha256={} qemu_native_input_sha256={}",
        source.sha256,
        source.files,
        source.bytes,
        installation.sha256,
        installation.files,
        installation.bytes,
        frontend.sha256,
        frontend.bytes,
        backend.sha256,
        backend.bytes,
        qemu_bundle_sha256,
        qemu_native_input_sha256,
    );
    Ok(sha256_bytes(preimage.as_bytes()))
}

fn run_enrolled_runtime_timeout_qemu(
    root: &Path,
    plan: &ReleasePlan,
    rust_tools: &IsolatedRustTools,
    installation: &Path,
    work: &Path,
    jobs: u32,
    run_binding_sha256: &str,
) -> Result<RealQemuEvidence, String> {
    let smoke = work.join("real-qemu-smoke-runtime-timeout");
    create_private_directory(&smoke)?;
    let cargo_home = smoke.join("cargo-home");
    prepare_private_cargo_home(plan, &cargo_home)?;
    let target = smoke.join("cargo");
    create_private_directory(&target)?;
    let temp = target.join("tmp");
    create_private_directory(&temp)?;
    let execution = CargoExecution {
        root,
        rust_tools,
        cargo_home: &cargo_home,
        target: &target,
        work: &smoke,
    };
    validate_cargo_execution(plan, &execution, "runtime-timeout real-QEMU smoke")?;
    let evidence = run_enrolled_runtime_timeout_qemu_case(
        plan,
        &execution,
        installation,
        &target,
        &temp,
        jobs,
        run_binding_sha256,
    )?;
    validate_cargo_execution(plan, &execution, "runtime-timeout real-QEMU completion")?;
    retire_owned_cargo_target(
        &target,
        &smoke,
        "integration runtime-timeout real-QEMU vertical Cargo target",
    )?;
    Ok(evidence)
}

#[allow(clippy::too_many_arguments)]
fn run_enrolled_runtime_timeout_qemu_case(
    plan: &ReleasePlan,
    execution: &CargoExecution<'_>,
    installation: &Path,
    target: &Path,
    temp: &Path,
    jobs: u32,
    run_binding_sha256: &str,
) -> Result<RealQemuEvidence, String> {
    const TEST: &str = "enrolled_bundle_executes_runtime_timeout_contract";
    let run_root = execution.work.join("runtime-timeout-run");
    if run_root.exists() {
        return Err("runtime-timeout real-QEMU run root unexpectedly exists".to_owned());
    }
    let mut command = Command::new(&execution.rust_tools.cargo);
    command
        .current_dir(execution.work)
        .args(runtime_timeout_qemu_arguments(execution.root, target, jobs));
    configure_cargo_environment(&mut command, plan, execution, temp);
    command
        .env("WRELA_SMOKE_RUN_ROOT", &run_root)
        .env("WRELA_SMOKE_TOOLCHAIN_ROOT", installation)
        .env("WRELA_RUNTIME_TIMEOUT_RUN_BINDING", run_binding_sha256);
    let label = "integration runtime-timeout real-QEMU vertical";
    let output = run_command(&mut command, label, 2 * 60 * 60)?;
    require_success(&output, label, false)?;
    require_exact_test_execution(&output.stdout, TEST, label)?;
    let evidence = parse_runtime_timeout_qemu_evidence(&output.stdout, label, run_binding_sha256)?;
    if run_root.exists() {
        return Err(format!("{label} left its private execution root behind"));
    }
    Ok(evidence)
}

#[allow(clippy::too_many_arguments)]
fn run_enrolled_checked_shift_qemu(
    plan: &ReleasePlan,
    execution: &CargoExecution<'_>,
    installation: &Path,
    target: &Path,
    temp: &Path,
    jobs: u32,
    installation_kind: &str,
    validation: CargoValidationPolicy,
) -> Result<CheckedShiftQemuEvidence, String> {
    const TEST: &str = "enrolled_bundle_executes_checked_shift_runtime_contract";
    let run_root = execution.work.join("checked-shift-run");
    if run_root.exists() {
        return Err(format!(
            "{installation_kind} checked-shift real-QEMU run root unexpectedly exists"
        ));
    }
    let label = format!("{installation_kind} checked-shift real-QEMU vertical");
    let mut command = Command::new(&execution.rust_tools.cargo);
    command
        .current_dir(execution.work)
        .args(checked_shift_qemu_arguments(execution.root, target, jobs));
    configure_cargo_environment(&mut command, plan, execution, temp);
    command
        .env("WRELA_SMOKE_RUN_ROOT", &run_root)
        .env("WRELA_SMOKE_TOOLCHAIN_ROOT", installation);
    let output = run_command(&mut command, &label, 4 * 60 * 60)?;
    require_success(&output, &label, false)?;
    if validation == CargoValidationPolicy::PerCommand {
        validate_cargo_execution(plan, execution, &label)?;
    }
    require_exact_test_execution(&output.stdout, TEST, &label)?;
    let evidence = parse_checked_shift_qemu_evidence(&output.stdout, &label)?;
    if run_root.exists() {
        return Err(format!("{label} left its private execution root behind"));
    }
    Ok(evidence)
}

#[allow(clippy::too_many_arguments)]
fn run_enrolled_current_tranche_checked_shift_qemu(
    plan: &ReleasePlan,
    execution: &CargoExecution<'_>,
    installation: &Path,
    target: &Path,
    temp: &Path,
    jobs: u32,
) -> Result<(CheckedShiftQemuEvidence, RuntimeResultQemuEvidence), String> {
    const TEST: &str = "enrolled_bundle_executes_current_tranche_runtime_contract";
    let run_root = execution.work.join("current-tranche-run");
    if run_root.exists() {
        return Err("current-tranche runtime run root unexpectedly exists".to_owned());
    }
    let label = "integration current-tranche checked-shift/assertion/Result real-QEMU vertical";
    let mut command = Command::new(&execution.rust_tools.cargo);
    command
        .current_dir(execution.work)
        .args(current_tranche_qemu_arguments(execution.root, target, jobs));
    configure_cargo_environment(&mut command, plan, execution, temp);
    command
        .env("WRELA_SMOKE_RUN_ROOT", &run_root)
        .env("WRELA_SMOKE_TOOLCHAIN_ROOT", installation);
    let output = run_command(&mut command, label, 4 * 60 * 60)?;
    require_success(&output, label, false)?;
    require_exact_test_execution(&output.stdout, TEST, label)?;
    let checked_shift = parse_checked_shift_qemu_evidence(&output.stdout, label)?;
    let runtime_result = parse_runtime_result_qemu_evidence(&output.stdout, label)?;
    if run_root.exists() {
        return Err(format!("{label} left its private execution root behind"));
    }
    Ok((checked_shift, runtime_result))
}

fn cleanup_stdlib_time_qemu_roots(
    work_root: &Path,
    run_root: &Path,
    evidence_root: &Path,
    label: &str,
) -> Result<(), String> {
    let work_root = exact_directory(work_root, &format!("{label} work root"))?;
    let run_root = normalized_absolute(run_root, &format!("{label} run root"))?;
    let evidence_root = normalized_absolute(evidence_root, &format!("{label} evidence root"))?;
    if run_root.parent() != Some(work_root.as_path())
        || run_root.file_name() != Some(OsStr::new("stdlib-time-run"))
        || evidence_root.parent() != Some(work_root.as_path())
        || evidence_root.file_name() != Some(OsStr::new("stdlib-time-evidence"))
        || run_root == evidence_root
    {
        return Err(format!(
            "{label} cleanup roots are not the dedicated children of their canonical work root"
        ));
    }
    let mut first = None;
    for (root, kind) in [(&run_root, "run"), (&evidence_root, "evidence")] {
        let metadata = match fs::symlink_metadata(root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                first.get_or_insert_with(|| {
                    format!("cannot inspect {label} {kind} root for cleanup: {error}")
                });
                continue;
            }
        };
        let removal = if metadata.is_dir() && !metadata.file_type().is_symlink() {
            make_directories_writable(root).and_then(|()| {
                fs::remove_dir_all(root)
                    .map_err(|error| format!("cannot remove {label} {kind} root: {error}"))
            })
        } else {
            fs::remove_file(root)
                .map_err(|error| format!("cannot remove substituted {label} {kind} root: {error}"))
        };
        if let Err(error) = removal {
            first.get_or_insert(error);
        }
    }
    if let Some(error) = first {
        Err(error)
    } else if run_root.exists() || evidence_root.exists() {
        Err(format!("{label} cleanup left an execution root behind"))
    } else {
        Ok(())
    }
}

fn parse_stdlib_time_qemu_evidence(
    stdout: &[u8],
    label: &str,
) -> Result<StdlibTimeQemuEvidence, String> {
    const MARKER: &str = "WRELA_STDLIB_TIME_QEMU_EVIDENCE";
    const PREFIX: &str = "WRELA_STDLIB_TIME_QEMU_EVIDENCE ";
    const MAX_LINE_BYTES: usize = 4096;
    let stdout = std::str::from_utf8(stdout)
        .map_err(|_| format!("{label} test-harness stdout is not UTF-8"))?;
    let mut line = None;
    for candidate in stdout.lines() {
        if candidate.starts_with(MARKER) {
            let payload = candidate.strip_prefix(PREFIX).ok_or_else(|| {
                format!("{label} emitted a stdlib-time evidence prefix collision")
            })?;
            if line.replace(payload).is_some() {
                return Err(format!(
                    "{label} did not emit exactly one canonical stdlib-time evidence line"
                ));
            }
        }
    }
    let line = line.ok_or_else(|| {
        format!("{label} did not emit exactly one canonical stdlib-time evidence line")
    })?;
    if line.len() > MAX_LINE_BYTES {
        return Err(format!(
            "{label} stdlib-time evidence line exceeds its bound"
        ));
    }
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let [
        schema,
        source_sha256,
        source_bytes,
        manifest_sha256,
        manifest_bytes,
        lock_sha256,
        lock_bytes,
        pass_image_sha256,
        pass_image_bytes,
        pass_report_sha256,
        pass_report_bytes,
        pass_event_sha256,
        pass_event_bytes,
        invalid_image_sha256,
        invalid_image_bytes,
        invalid_report_sha256,
        invalid_report_bytes,
        invalid_event_sha256,
        invalid_event_bytes,
    ] = fields.as_slice()
    else {
        return Err(format!("{label} emitted malformed stdlib-time evidence"));
    };
    if *schema != "schema=1" {
        return Err(format!(
            "{label} stdlib-time evidence has an unsupported schema"
        ));
    }
    let exact = |field: &str, key: &str| {
        field
            .strip_prefix(key)
            .map(str::to_owned)
            .ok_or_else(|| format!("{label} stdlib-time evidence omitted {key}"))
    };
    let file = |digest: &str, bytes: &str, digest_key: &str, bytes_key: &str| {
        let sha256 = exact(digest, digest_key)?;
        if !canonical_digest(&sha256) {
            return Err(format!(
                "{label} stdlib-time evidence contains a noncanonical digest"
            ));
        }
        Ok(FileMeasurement {
            sha256,
            bytes: positive_u64(&exact(bytes, bytes_key)?, bytes_key)?,
        })
    };
    let evidence = StdlibTimeQemuEvidence {
        source: file(
            source_sha256,
            source_bytes,
            "source_sha256=",
            "source_bytes=",
        )?,
        manifest: file(
            manifest_sha256,
            manifest_bytes,
            "manifest_sha256=",
            "manifest_bytes=",
        )?,
        lock: file(lock_sha256, lock_bytes, "lock_sha256=", "lock_bytes=")?,
        pass: RealQemuEvidence {
            image_sha256: file(
                pass_image_sha256,
                pass_image_bytes,
                "pass_image_sha256=",
                "pass_image_bytes=",
            )?
            .sha256,
            image_bytes: positive_u64(
                &exact(pass_image_bytes, "pass_image_bytes=")?,
                "pass image bytes",
            )?,
            report_sha256: file(
                pass_report_sha256,
                pass_report_bytes,
                "pass_report_sha256=",
                "pass_report_bytes=",
            )?
            .sha256,
            report_bytes: positive_u64(
                &exact(pass_report_bytes, "pass_report_bytes=")?,
                "pass report bytes",
            )?,
            event_stream_sha256: file(
                pass_event_sha256,
                pass_event_bytes,
                "pass_event_stream_sha256=",
                "pass_event_stream_bytes=",
            )?
            .sha256,
            event_stream_bytes: positive_u64(
                &exact(pass_event_bytes, "pass_event_stream_bytes=")?,
                "pass event stream bytes",
            )?,
        },
        invalid_count: RealQemuEvidence {
            image_sha256: file(
                invalid_image_sha256,
                invalid_image_bytes,
                "invalid_count_image_sha256=",
                "invalid_count_image_bytes=",
            )?
            .sha256,
            image_bytes: positive_u64(
                &exact(invalid_image_bytes, "invalid_count_image_bytes=")?,
                "invalid-count image bytes",
            )?,
            report_sha256: file(
                invalid_report_sha256,
                invalid_report_bytes,
                "invalid_count_report_sha256=",
                "invalid_count_report_bytes=",
            )?
            .sha256,
            report_bytes: positive_u64(
                &exact(invalid_report_bytes, "invalid_count_report_bytes=")?,
                "invalid-count report bytes",
            )?,
            event_stream_sha256: file(
                invalid_event_sha256,
                invalid_event_bytes,
                "invalid_count_event_stream_sha256=",
                "invalid_count_event_stream_bytes=",
            )?
            .sha256,
            event_stream_bytes: positive_u64(
                &exact(invalid_event_bytes, "invalid_count_event_stream_bytes=")?,
                "invalid-count event stream bytes",
            )?,
        },
    };
    if line != encode_stdlib_time_qemu_evidence(&evidence) {
        return Err(format!(
            "{label} emitted noncanonical stdlib-time evidence whitespace or field encoding"
        ));
    }
    Ok(evidence)
}

fn encode_stdlib_time_qemu_evidence(evidence: &StdlibTimeQemuEvidence) -> String {
    format!(
        "schema=1 source_sha256={} source_bytes={} manifest_sha256={} manifest_bytes={} lock_sha256={} lock_bytes={} pass_image_sha256={} pass_image_bytes={} pass_report_sha256={} pass_report_bytes={} pass_event_stream_sha256={} pass_event_stream_bytes={} invalid_count_image_sha256={} invalid_count_image_bytes={} invalid_count_report_sha256={} invalid_count_report_bytes={} invalid_count_event_stream_sha256={} invalid_count_event_stream_bytes={}",
        evidence.source.sha256,
        evidence.source.bytes,
        evidence.manifest.sha256,
        evidence.manifest.bytes,
        evidence.lock.sha256,
        evidence.lock.bytes,
        evidence.pass.image_sha256,
        evidence.pass.image_bytes,
        evidence.pass.report_sha256,
        evidence.pass.report_bytes,
        evidence.pass.event_stream_sha256,
        evidence.pass.event_stream_bytes,
        evidence.invalid_count.image_sha256,
        evidence.invalid_count.image_bytes,
        evidence.invalid_count.report_sha256,
        evidence.invalid_count.report_bytes,
        evidence.invalid_count.event_stream_sha256,
        evidence.invalid_count.event_stream_bytes,
    )
}

fn recompute_stdlib_time_qemu_evidence(
    root: &Path,
    evidence_root: &Path,
    label: &str,
) -> Result<StdlibTimeQemuEvidence, String> {
    let evidence_root = exact_directory(evidence_root, &format!("{label} evidence root"))?;
    #[cfg(unix)]
    if stable_metadata(&evidence_root, &format!("{label} evidence root"))?.mode() & 0o7777 != 0o700
    {
        return Err(format!("{label} evidence root is not mode 0700"));
    }
    let names = bounded_directory_names(&evidence_root, 6, &format!("{label} evidence root"))?;
    let expected = vec![
        "invalid-count.efi".to_owned(),
        "invalid-count.events".to_owned(),
        "invalid-count.report".to_owned(),
        "pass.efi".to_owned(),
        "pass.events".to_owned(),
        "pass.report".to_owned(),
    ];
    if names != expected {
        return Err(format!(
            "{label} evidence export has an unexpected inventory"
        ));
    }
    let source = measure_file(
        &root.join("std/examples/stdlib-time-runtime/src/runtime/time_test.wr"),
        MAX_LOCK_BYTES,
        false,
    )?;
    let manifest = measure_file(
        &root.join("std/examples/stdlib-time-runtime/wrela.toml"),
        MAX_LOCK_BYTES,
        false,
    )?;
    let lock = measure_file(
        &root.join("std/examples/stdlib-time-runtime/wrela.lock"),
        MAX_LOCK_BYTES,
        false,
    )?;
    let case = |name: &str| -> Result<RealQemuEvidence, String> {
        let image = measure_file(
            &evidence_root.join(format!("{name}.efi")),
            MAX_SMOKE_IMAGE_BYTES,
            false,
        )?;
        let report = measure_file(
            &evidence_root.join(format!("{name}.report")),
            MAX_MANIFEST_BYTES,
            false,
        )?;
        let events = measure_stdlib_time_event_preimage(
            &evidence_root.join(format!("{name}.events")),
            label,
        )?;
        Ok(RealQemuEvidence {
            image_sha256: image.sha256,
            image_bytes: image.bytes,
            report_sha256: report.sha256,
            report_bytes: report.bytes,
            event_stream_sha256: events.sha256,
            event_stream_bytes: events.bytes,
        })
    };
    Ok(StdlibTimeQemuEvidence {
        source,
        manifest,
        lock,
        pass: case("pass")?,
        invalid_count: case("invalid-count")?,
    })
}

fn measure_stdlib_time_event_preimage(path: &Path, label: &str) -> Result<FileMeasurement, String> {
    const MAGIC: &[u8; 8] = b"WRELEVS\0";
    const VERSION: u32 = 1;
    const EVENTS: u64 = 4;
    let measurement = measure_file(path, MAX_SMOKE_SERIAL_BYTES, false)?;
    let bytes = read_exact_measured_file(path, &measurement)?;
    if bytes.len() < 20 || bytes.get(..8) != Some(MAGIC.as_slice()) {
        return Err(format!(
            "{label} event evidence has invalid magic or extent"
        ));
    }
    let version = u32::from_le_bytes(
        bytes[8..12]
            .try_into()
            .map_err(|_| format!("{label} event evidence omitted its version"))?,
    );
    let count = u64::from_le_bytes(
        bytes[12..20]
            .try_into()
            .map_err(|_| format!("{label} event evidence omitted its count"))?,
    );
    if version != VERSION || count != EVENTS {
        return Err(format!(
            "{label} event evidence has an unsupported version or event count"
        ));
    }
    let mut cursor = 20_usize;
    let mut stream_bytes = 0_u64;
    for _ in 0..count {
        let end = cursor
            .checked_add(8)
            .ok_or_else(|| format!("{label} event evidence length offset overflow"))?;
        let length = u64::from_le_bytes(
            bytes
                .get(cursor..end)
                .ok_or_else(|| format!("{label} event evidence omitted a frame length"))?
                .try_into()
                .map_err(|_| format!("{label} event frame length is malformed"))?,
        );
        if length == 0 {
            return Err(format!("{label} event evidence contains an empty frame"));
        }
        cursor = end;
        let frame_bytes = usize::try_from(length)
            .map_err(|_| format!("{label} event frame length does not fit host allocation"))?;
        cursor = cursor
            .checked_add(frame_bytes)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| format!("{label} event evidence contains a truncated frame"))?;
        stream_bytes = stream_bytes
            .checked_add(length)
            .ok_or_else(|| format!("{label} event stream extent overflow"))?;
    }
    if cursor != bytes.len() || stream_bytes == 0 {
        return Err(format!(
            "{label} event evidence contains trailing bytes or an empty stream"
        ));
    }
    Ok(FileMeasurement {
        sha256: measurement.sha256,
        bytes: stream_bytes,
    })
}

fn parse_runtime_timeout_qemu_evidence(
    stdout: &[u8],
    label: &str,
    expected_run_binding_sha256: &str,
) -> Result<RealQemuEvidence, String> {
    const PREFIX: &str = "WRELA_RUNTIME_TIMEOUT_QEMU_EVIDENCE ";
    const TIMEOUT_NS: u64 = 65_000_000_000;
    let stdout = std::str::from_utf8(stdout)
        .map_err(|_| format!("{label} runtime-timeout stdout is not UTF-8"))?;
    let lines = stdout
        .lines()
        .filter_map(|line| line.strip_prefix(PREFIX))
        .collect::<Vec<_>>();
    let [line] = lines.as_slice() else {
        return Err(format!(
            "{label} did not emit exactly one runtime-timeout evidence line"
        ));
    };
    if !canonical_digest(expected_run_binding_sha256)
        || PREFIX
            .len()
            .checked_add(line.len())
            .is_none_or(|bytes| bytes > MAX_RUNTIME_TIMEOUT_EVIDENCE_LINE_BYTES)
    {
        return Err(format!(
            "{label} runtime-timeout expected binding or evidence line is invalid"
        ));
    }
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let [
        schema,
        outcome,
        timeout,
        run_binding,
        image_sha256,
        image_bytes,
        report_sha256,
        report_bytes,
        event_sha256,
        event_bytes,
    ] = fields.as_slice()
    else {
        return Err(format!(
            "{label} emitted malformed runtime-timeout evidence"
        ));
    };
    if *schema != "schema=1"
        || *outcome != "outcome=runtime-timeout"
        || *timeout != format!("timeout_ns={TIMEOUT_NS}")
    {
        return Err(format!(
            "{label} runtime-timeout evidence has a wrong schema, outcome, timeout, or order"
        ));
    }
    let exact = |field: &str, key: &str| {
        field
            .strip_prefix(key)
            .map(str::to_owned)
            .ok_or_else(|| format!("{label} runtime-timeout evidence omitted {key}"))
    };
    let run_binding_sha256 = exact(run_binding, "run_binding_sha256=")?;
    let image_sha256 = exact(image_sha256, "image_sha256=")?;
    let report_sha256 = exact(report_sha256, "report_sha256=")?;
    let event_stream_sha256 = exact(event_sha256, "event_stream_sha256=")?;
    if !canonical_digest(&run_binding_sha256)
        || run_binding_sha256 != expected_run_binding_sha256
        || !canonical_digest(&image_sha256)
        || !canonical_digest(&report_sha256)
        || !canonical_digest(&event_stream_sha256)
    {
        return Err(format!(
            "{label} runtime-timeout evidence contains a noncanonical digest"
        ));
    }
    let evidence = RealQemuEvidence {
        image_sha256,
        image_bytes: positive_u64(
            &exact(image_bytes, "image_bytes=")?,
            "runtime-timeout image bytes",
        )?,
        report_sha256,
        report_bytes: positive_u64(
            &exact(report_bytes, "report_bytes=")?,
            "runtime-timeout report bytes",
        )?,
        event_stream_sha256,
        event_stream_bytes: positive_u64(
            &exact(event_bytes, "event_stream_bytes=")?,
            "runtime-timeout event-stream bytes",
        )?,
    };
    if evidence.image_bytes > MAX_RUNTIME_TIMEOUT_IMAGE_BYTES
        || evidence.report_bytes > MAX_RUNTIME_TIMEOUT_REPORT_BYTES
        || evidence.event_stream_bytes > MAX_RUNTIME_TIMEOUT_EVENT_STREAM_BYTES
    {
        return Err(format!(
            "{label} runtime-timeout evidence exceeds an authoritative consumer bound"
        ));
    }
    let canonical = format!(
        "schema=1 outcome=runtime-timeout timeout_ns={TIMEOUT_NS} run_binding_sha256={run_binding_sha256} image_sha256={} image_bytes={} report_sha256={} report_bytes={} event_stream_sha256={} event_stream_bytes={}",
        evidence.image_sha256,
        evidence.image_bytes,
        evidence.report_sha256,
        evidence.report_bytes,
        evidence.event_stream_sha256,
        evidence.event_stream_bytes,
    );
    if *line != canonical {
        return Err(format!(
            "{label} emitted noncanonical runtime-timeout evidence whitespace"
        ));
    }
    Ok(evidence)
}

fn parse_checked_shift_qemu_evidence(
    stdout: &[u8],
    label: &str,
) -> Result<CheckedShiftQemuEvidence, String> {
    const PREFIX: &str = "WRELA_CHECKED_SHIFT_QEMU_EVIDENCE ";
    const CASES: [(&str, &str); 4] = [
        ("modular_shift_passes", "passed"),
        ("runtime_assertion_fails", "assertion-failed"),
        ("checked_shift_result_loss", "checked-shift-result-loss"),
        ("invalid_shift_count", "invalid-shift-count"),
    ];
    let stdout = std::str::from_utf8(stdout)
        .map_err(|_| format!("{label} checked-shift test stdout is not UTF-8"))?;
    let lines = stdout
        .lines()
        .filter_map(|line| line.strip_prefix(PREFIX))
        .collect::<Vec<_>>();
    if lines.len() != CASES.len() {
        return Err(format!(
            "{label} did not emit exactly four checked-shift/assertion evidence lines"
        ));
    }
    let mut parsed = Vec::new();
    parsed
        .try_reserve_exact(CASES.len())
        .map_err(|_| format!("{label} cannot reserve checked-shift evidence"))?;
    for (line, (expected_selector, expected_outcome)) in lines.into_iter().zip(CASES) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let [
            schema,
            selector,
            outcome,
            image_sha256,
            image_bytes,
            report_sha256,
            report_bytes,
            event_sha256,
            event_bytes,
        ] = fields.as_slice()
        else {
            return Err(format!("{label} emitted malformed checked-shift evidence"));
        };
        if *schema != "schema=1"
            || *selector != format!("selector={expected_selector}")
            || *outcome != format!("outcome={expected_outcome}")
        {
            return Err(format!(
                "{label} checked-shift evidence has a wrong schema, selector, outcome, or order"
            ));
        }
        let exact = |field: &str, key: &str| {
            field
                .strip_prefix(key)
                .map(str::to_owned)
                .ok_or_else(|| format!("{label} checked-shift evidence omitted {key}"))
        };
        let image_sha256 = exact(image_sha256, "image_sha256=")?;
        let report_sha256 = exact(report_sha256, "report_sha256=")?;
        let event_stream_sha256 = exact(event_sha256, "event_stream_sha256=")?;
        if !canonical_digest(&image_sha256)
            || !canonical_digest(&report_sha256)
            || !canonical_digest(&event_stream_sha256)
        {
            return Err(format!(
                "{label} checked-shift evidence contains a noncanonical digest"
            ));
        }
        let evidence = RealQemuEvidence {
            image_sha256,
            image_bytes: positive_u64(
                &exact(image_bytes, "image_bytes=")?,
                "checked-shift image bytes",
            )?,
            report_sha256,
            report_bytes: positive_u64(
                &exact(report_bytes, "report_bytes=")?,
                "checked-shift report bytes",
            )?,
            event_stream_sha256,
            event_stream_bytes: positive_u64(
                &exact(event_bytes, "event_stream_bytes=")?,
                "checked-shift event-stream bytes",
            )?,
        };
        let canonical = format!(
            "schema=1 selector={expected_selector} outcome={expected_outcome} image_sha256={} image_bytes={} report_sha256={} report_bytes={} event_stream_sha256={} event_stream_bytes={}",
            evidence.image_sha256,
            evidence.image_bytes,
            evidence.report_sha256,
            evidence.report_bytes,
            evidence.event_stream_sha256,
            evidence.event_stream_bytes,
        );
        if line != canonical {
            return Err(format!(
                "{label} emitted noncanonical checked-shift evidence whitespace"
            ));
        }
        parsed.push(evidence);
    }
    let [pass, assertion_failure, result_loss, invalid_count] = parsed.as_slice() else {
        return Err(format!("{label} checked-shift evidence count changed"));
    };
    Ok(CheckedShiftQemuEvidence {
        pass: pass.clone(),
        assertion_failure: assertion_failure.clone(),
        result_loss: result_loss.clone(),
        invalid_count: invalid_count.clone(),
    })
}

fn parse_runtime_result_qemu_evidence(
    stdout: &[u8],
    label: &str,
) -> Result<RuntimeResultQemuEvidence, String> {
    const PREFIX: &str = "WRELA_RUNTIME_RESULT_QEMU_EVIDENCE ";
    const SELECTORS: [&str; 2] = [
        "result_try_ok_yields_payload",
        "result_try_err_propagates_exact_error",
    ];
    const MAX_LINE_BYTES: usize = 1024;
    let stdout = std::str::from_utf8(stdout)
        .map_err(|_| format!("{label} runtime-result test stdout is not UTF-8"))?;
    let lines = stdout
        .lines()
        .filter_map(|line| line.strip_prefix(PREFIX))
        .collect::<Vec<_>>();
    if lines.len() != SELECTORS.len() {
        return Err(format!(
            "{label} did not emit exactly two runtime-result evidence lines"
        ));
    }
    let mut parsed = Vec::new();
    parsed
        .try_reserve_exact(SELECTORS.len())
        .map_err(|_| format!("{label} cannot reserve runtime-result evidence"))?;
    for (line, expected_selector) in lines.into_iter().zip(SELECTORS) {
        if line.len() > MAX_LINE_BYTES {
            return Err(format!(
                "{label} runtime-result evidence line exceeds its bound"
            ));
        }
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let [
            schema,
            selector,
            outcome,
            image_sha256,
            image_bytes,
            report_sha256,
            report_bytes,
            event_sha256,
            event_bytes,
        ] = fields.as_slice()
        else {
            return Err(format!("{label} emitted malformed runtime-result evidence"));
        };
        if *schema != "schema=1"
            || *selector != format!("selector={expected_selector}")
            || *outcome != "outcome=passed"
        {
            return Err(format!(
                "{label} runtime-result evidence has a wrong schema, selector, outcome, or order"
            ));
        }
        let exact = |field: &str, key: &str| {
            field
                .strip_prefix(key)
                .map(str::to_owned)
                .ok_or_else(|| format!("{label} runtime-result evidence omitted {key}"))
        };
        let image_sha256 = exact(image_sha256, "image_sha256=")?;
        let report_sha256 = exact(report_sha256, "report_sha256=")?;
        let event_stream_sha256 = exact(event_sha256, "event_stream_sha256=")?;
        if !canonical_digest(&image_sha256)
            || !canonical_digest(&report_sha256)
            || !canonical_digest(&event_stream_sha256)
        {
            return Err(format!(
                "{label} runtime-result evidence contains a noncanonical digest"
            ));
        }
        let evidence = RealQemuEvidence {
            image_sha256,
            image_bytes: positive_u64(
                &exact(image_bytes, "image_bytes=")?,
                "runtime-result image bytes",
            )?,
            report_sha256,
            report_bytes: positive_u64(
                &exact(report_bytes, "report_bytes=")?,
                "runtime-result report bytes",
            )?,
            event_stream_sha256,
            event_stream_bytes: positive_u64(
                &exact(event_bytes, "event_stream_bytes=")?,
                "runtime-result event-stream bytes",
            )?,
        };
        if evidence.image_bytes > MAX_RUNTIME_TIMEOUT_IMAGE_BYTES
            || evidence.report_bytes > MAX_RUNTIME_TIMEOUT_REPORT_BYTES
            || evidence.event_stream_bytes > MAX_RUNTIME_TIMEOUT_EVENT_STREAM_BYTES
        {
            return Err(format!(
                "{label} runtime-result evidence exceeds an authoritative consumer bound"
            ));
        }
        let canonical = format!(
            "schema=1 selector={expected_selector} outcome=passed image_sha256={} image_bytes={} report_sha256={} report_bytes={} event_stream_sha256={} event_stream_bytes={}",
            evidence.image_sha256,
            evidence.image_bytes,
            evidence.report_sha256,
            evidence.report_bytes,
            evidence.event_stream_sha256,
            evidence.event_stream_bytes,
        );
        if line != canonical {
            return Err(format!(
                "{label} emitted noncanonical runtime-result evidence whitespace"
            ));
        }
        parsed.push(evidence);
    }
    let [ok, propagated_err] = parsed.as_slice() else {
        return Err(format!("{label} runtime-result evidence count changed"));
    };
    Ok(RuntimeResultQemuEvidence {
        ok: ok.clone(),
        propagated_err: propagated_err.clone(),
    })
}

fn encode_runtime_timeout_integration_evidence(
    evidence: &RuntimeTimeoutIntegrationEvidence,
) -> Result<String, String> {
    const PREFIX: &str = "WRELA_DIST_QEMU_RUNTIME_TIMEOUT_EVIDENCE";
    const TIMEOUT_NS: u64 = 65_000_000_000;
    const MAXIMUM_BYTES: usize = 2048;
    let expected_run_binding = runtime_timeout_run_binding(
        &evidence.source,
        &evidence.installation,
        &evidence.frontend,
        &evidence.backend,
        &evidence.qemu_bundle_sha256,
        &evidence.qemu_native_input_sha256,
    )?;
    if evidence.run_binding_sha256 != expected_run_binding {
        return Err("runtime-timeout integration evidence has a stale run binding".to_owned());
    }
    let digests = [
        evidence.source.sha256.as_str(),
        evidence.qemu_bundle_sha256.as_str(),
        evidence.qemu_native_input_sha256.as_str(),
        evidence.installation.sha256.as_str(),
        evidence.frontend.sha256.as_str(),
        evidence.backend.sha256.as_str(),
        evidence.run_binding_sha256.as_str(),
        evidence.timeout.image_sha256.as_str(),
        evidence.timeout.report_sha256.as_str(),
        evidence.timeout.event_stream_sha256.as_str(),
    ];
    if digests.iter().any(|digest| !canonical_digest(digest)) {
        return Err("runtime-timeout integration evidence has a noncanonical digest".to_owned());
    }
    let extents = [
        evidence.source.files,
        evidence.source.bytes,
        evidence.installation.files,
        evidence.installation.bytes,
        evidence.frontend.bytes,
        evidence.backend.bytes,
        evidence.timeout.image_bytes,
        evidence.timeout.report_bytes,
        evidence.timeout.event_stream_bytes,
    ];
    if extents.contains(&0)
        || evidence.timeout.image_bytes > MAX_RUNTIME_TIMEOUT_IMAGE_BYTES
        || evidence.timeout.report_bytes > MAX_RUNTIME_TIMEOUT_REPORT_BYTES
        || evidence.timeout.event_stream_bytes > MAX_RUNTIME_TIMEOUT_EVENT_STREAM_BYTES
    {
        return Err("runtime-timeout integration evidence has an invalid extent".to_owned());
    }
    let line = format!(
        "{PREFIX} schema=1 source_sha256={} source_files={} source_bytes={} qemu_bundle_sha256={} qemu_native_input_sha256={} installation_sha256={} installation_files={} installation_bytes={} frontend_sha256={} frontend_bytes={} backend_sha256={} backend_bytes={} run_binding_sha256={} outcome=runtime-timeout timeout_ns={TIMEOUT_NS} image_sha256={} image_bytes={} report_sha256={} report_bytes={} event_stream_sha256={} event_stream_bytes={}",
        evidence.source.sha256,
        evidence.source.files,
        evidence.source.bytes,
        evidence.qemu_bundle_sha256,
        evidence.qemu_native_input_sha256,
        evidence.installation.sha256,
        evidence.installation.files,
        evidence.installation.bytes,
        evidence.frontend.sha256,
        evidence.frontend.bytes,
        evidence.backend.sha256,
        evidence.backend.bytes,
        evidence.run_binding_sha256,
        evidence.timeout.image_sha256,
        evidence.timeout.image_bytes,
        evidence.timeout.report_sha256,
        evidence.timeout.report_bytes,
        evidence.timeout.event_stream_sha256,
        evidence.timeout.event_stream_bytes,
    );
    if line.len() > MAXIMUM_BYTES
        || line.contains(['/', '\\', '\n', '\r'])
        || line.chars().any(char::is_control)
    {
        return Err("runtime-timeout integration evidence is oversized or path-bearing".to_owned());
    }
    Ok(line)
}

fn encode_current_tranche_integration_evidence(
    evidence: &CurrentTrancheIntegrationEvidence,
) -> Result<String, String> {
    const PREFIX: &str = "WRELA_DIST_QEMU_CURRENT_TRANCHE_EVIDENCE";
    // Schema 2 adds the two canonical recoverable Result executions to the
    // previously frozen development-tranche shape.
    const MAXIMUM_BYTES: usize = 8192;
    let expected_run_binding = runtime_timeout_run_binding(
        &evidence.source,
        &evidence.installation,
        &evidence.frontend,
        &evidence.backend,
        &evidence.qemu_bundle_sha256,
        &evidence.qemu_native_input_sha256,
    )?;
    if evidence.run_binding_sha256 != expected_run_binding {
        return Err("current-tranche integration evidence has a stale run binding".to_owned());
    }
    let cases = [
        ("runtime_timeout", &evidence.qemu.timeout),
        ("stdlib_time_pass", &evidence.qemu.stdlib_time.pass),
        (
            "stdlib_time_invalid_count",
            &evidence.qemu.stdlib_time.invalid_count,
        ),
        (
            "checked_shift_modular_assertion_pass",
            &evidence.qemu.checked_shift.pass,
        ),
        (
            "runtime_assertion_failure",
            &evidence.qemu.checked_shift.assertion_failure,
        ),
        (
            "checked_shift_result_loss",
            &evidence.qemu.checked_shift.result_loss,
        ),
        (
            "checked_shift_invalid_count",
            &evidence.qemu.checked_shift.invalid_count,
        ),
        (
            "result_try_ok_yields_payload",
            &evidence.qemu.runtime_result.ok,
        ),
        (
            "result_try_err_propagates_exact_error",
            &evidence.qemu.runtime_result.propagated_err,
        ),
    ];
    let common_digests = [
        evidence.source.sha256.as_str(),
        evidence.qemu_bundle_sha256.as_str(),
        evidence.qemu_native_input_sha256.as_str(),
        evidence.installation.sha256.as_str(),
        evidence.frontend.sha256.as_str(),
        evidence.backend.sha256.as_str(),
        evidence.run_binding_sha256.as_str(),
        evidence.qemu.stdlib_time.source.sha256.as_str(),
        evidence.qemu.stdlib_time.manifest.sha256.as_str(),
        evidence.qemu.stdlib_time.lock.sha256.as_str(),
    ];
    if common_digests
        .iter()
        .any(|digest| !canonical_digest(digest))
        || cases.iter().any(|(_, value)| {
            !canonical_digest(&value.image_sha256)
                || !canonical_digest(&value.report_sha256)
                || !canonical_digest(&value.event_stream_sha256)
        })
    {
        return Err("current-tranche integration evidence has a noncanonical digest".to_owned());
    }
    let common_extents = [
        evidence.source.files,
        evidence.source.bytes,
        evidence.installation.files,
        evidence.installation.bytes,
        evidence.frontend.bytes,
        evidence.backend.bytes,
        evidence.qemu.stdlib_time.source.bytes,
        evidence.qemu.stdlib_time.manifest.bytes,
        evidence.qemu.stdlib_time.lock.bytes,
    ];
    if common_extents.contains(&0)
        || cases.iter().any(|(_, value)| {
            value.image_bytes == 0
                || value.report_bytes == 0
                || value.event_stream_bytes == 0
                || value.image_bytes > MAX_RUNTIME_TIMEOUT_IMAGE_BYTES
                || value.report_bytes > MAX_RUNTIME_TIMEOUT_REPORT_BYTES
                || value.event_stream_bytes > MAX_RUNTIME_TIMEOUT_EVENT_STREAM_BYTES
        })
    {
        return Err("current-tranche integration evidence has an invalid extent".to_owned());
    }
    let mut line = format!(
        "{PREFIX} schema=2 source_sha256={} source_files={} source_bytes={} qemu_bundle_sha256={} qemu_native_input_sha256={} installation_sha256={} installation_files={} installation_bytes={} frontend_sha256={} frontend_bytes={} backend_sha256={} backend_bytes={} run_binding_sha256={} stdlib_source_sha256={} stdlib_source_bytes={} stdlib_manifest_sha256={} stdlib_manifest_bytes={} stdlib_lock_sha256={} stdlib_lock_bytes={}",
        evidence.source.sha256,
        evidence.source.files,
        evidence.source.bytes,
        evidence.qemu_bundle_sha256,
        evidence.qemu_native_input_sha256,
        evidence.installation.sha256,
        evidence.installation.files,
        evidence.installation.bytes,
        evidence.frontend.sha256,
        evidence.frontend.bytes,
        evidence.backend.sha256,
        evidence.backend.bytes,
        evidence.run_binding_sha256,
        evidence.qemu.stdlib_time.source.sha256,
        evidence.qemu.stdlib_time.source.bytes,
        evidence.qemu.stdlib_time.manifest.sha256,
        evidence.qemu.stdlib_time.manifest.bytes,
        evidence.qemu.stdlib_time.lock.sha256,
        evidence.qemu.stdlib_time.lock.bytes,
    );
    for (name, value) in cases {
        line.push_str(&format!(
            " {name}_image_sha256={} {name}_image_bytes={} {name}_report_sha256={} {name}_report_bytes={} {name}_event_stream_sha256={} {name}_event_stream_bytes={}",
            value.image_sha256,
            value.image_bytes,
            value.report_sha256,
            value.report_bytes,
            value.event_stream_sha256,
            value.event_stream_bytes,
        ));
    }
    if line.len() > MAXIMUM_BYTES
        || line.contains(['/', '\\', '\n', '\r'])
        || line.chars().any(char::is_control)
    {
        return Err("current-tranche integration evidence is oversized or path-bearing".to_owned());
    }
    Ok(line)
}

fn encode_qemu_integration_evidence(evidence: &QemuIntegrationEvidence) -> Result<String, String> {
    const PREFIX: &str = "WRELA_DIST_QEMU_INTEGRATION_EVIDENCE";
    const MAXIMUM_BYTES: usize = 4096;
    let digests = [
        evidence.source.sha256.as_str(),
        evidence.qemu_bundle_sha256.as_str(),
        evidence.qemu_native_input_sha256.as_str(),
        evidence.installation.sha256.as_str(),
        evidence.frontend.sha256.as_str(),
        evidence.backend.sha256.as_str(),
        evidence.bootstrap.image_sha256.as_str(),
        evidence.bootstrap.report_sha256.as_str(),
        evidence.bootstrap.event_stream_sha256.as_str(),
        evidence.stdlib_time.pass.image_sha256.as_str(),
        evidence.stdlib_time.pass.report_sha256.as_str(),
        evidence.stdlib_time.pass.event_stream_sha256.as_str(),
        evidence.stdlib_time.invalid_count.image_sha256.as_str(),
        evidence.stdlib_time.invalid_count.report_sha256.as_str(),
        evidence
            .stdlib_time
            .invalid_count
            .event_stream_sha256
            .as_str(),
        evidence.checked_shift.pass.image_sha256.as_str(),
        evidence.checked_shift.pass.report_sha256.as_str(),
        evidence.checked_shift.pass.event_stream_sha256.as_str(),
        evidence
            .checked_shift
            .assertion_failure
            .image_sha256
            .as_str(),
        evidence
            .checked_shift
            .assertion_failure
            .report_sha256
            .as_str(),
        evidence
            .checked_shift
            .assertion_failure
            .event_stream_sha256
            .as_str(),
        evidence.checked_shift.result_loss.image_sha256.as_str(),
        evidence.checked_shift.result_loss.report_sha256.as_str(),
        evidence
            .checked_shift
            .result_loss
            .event_stream_sha256
            .as_str(),
        evidence.checked_shift.invalid_count.image_sha256.as_str(),
        evidence.checked_shift.invalid_count.report_sha256.as_str(),
        evidence
            .checked_shift
            .invalid_count
            .event_stream_sha256
            .as_str(),
    ];
    if digests.iter().any(|digest| !canonical_digest(digest)) {
        return Err("QEMU integration evidence contains a noncanonical digest".to_owned());
    }
    let mut line = format!(
        "{PREFIX} schema=1 source_sha256={} source_files={} source_bytes={} qemu_bundle_sha256={} qemu_native_input_sha256={} installation_sha256={} installation_files={} installation_bytes={} frontend_sha256={} frontend_bytes={} backend_sha256={} backend_bytes={}",
        evidence.source.sha256,
        evidence.source.files,
        evidence.source.bytes,
        evidence.qemu_bundle_sha256,
        evidence.qemu_native_input_sha256,
        evidence.installation.sha256,
        evidence.installation.files,
        evidence.installation.bytes,
        evidence.frontend.sha256,
        evidence.frontend.bytes,
        evidence.backend.sha256,
        evidence.backend.bytes,
    );
    for (name, value) in [
        ("bootstrap", &evidence.bootstrap),
        ("stdlib_time_pass", &evidence.stdlib_time.pass),
        (
            "stdlib_time_invalid_count",
            &evidence.stdlib_time.invalid_count,
        ),
        ("checked_shift_pass", &evidence.checked_shift.pass),
        (
            "checked_shift_assertion_failure",
            &evidence.checked_shift.assertion_failure,
        ),
        (
            "checked_shift_result_loss",
            &evidence.checked_shift.result_loss,
        ),
        (
            "checked_shift_invalid_count",
            &evidence.checked_shift.invalid_count,
        ),
    ] {
        line.push_str(&format!(
            " {name}_image_sha256={} {name}_image_bytes={} {name}_report_sha256={} {name}_report_bytes={} {name}_event_stream_sha256={} {name}_event_stream_bytes={}",
            value.image_sha256,
            value.image_bytes,
            value.report_sha256,
            value.report_bytes,
            value.event_stream_sha256,
            value.event_stream_bytes,
        ));
    }
    let extents = [
        evidence.source.files,
        evidence.source.bytes,
        evidence.installation.files,
        evidence.installation.bytes,
        evidence.frontend.bytes,
        evidence.backend.bytes,
        evidence.bootstrap.image_bytes,
        evidence.bootstrap.report_bytes,
        evidence.bootstrap.event_stream_bytes,
        evidence.stdlib_time.pass.image_bytes,
        evidence.stdlib_time.pass.report_bytes,
        evidence.stdlib_time.pass.event_stream_bytes,
        evidence.stdlib_time.invalid_count.image_bytes,
        evidence.stdlib_time.invalid_count.report_bytes,
        evidence.stdlib_time.invalid_count.event_stream_bytes,
        evidence.checked_shift.pass.image_bytes,
        evidence.checked_shift.pass.report_bytes,
        evidence.checked_shift.pass.event_stream_bytes,
        evidence.checked_shift.assertion_failure.image_bytes,
        evidence.checked_shift.assertion_failure.report_bytes,
        evidence.checked_shift.assertion_failure.event_stream_bytes,
        evidence.checked_shift.result_loss.image_bytes,
        evidence.checked_shift.result_loss.report_bytes,
        evidence.checked_shift.result_loss.event_stream_bytes,
        evidence.checked_shift.invalid_count.image_bytes,
        evidence.checked_shift.invalid_count.report_bytes,
        evidence.checked_shift.invalid_count.event_stream_bytes,
    ];
    if extents.contains(&0)
        || line.len() > MAXIMUM_BYTES
        || line.contains(['/', '\\', '\n', '\r'])
        || line.chars().any(char::is_control)
    {
        return Err("QEMU integration evidence is empty, oversized, or path-bearing".to_owned());
    }
    Ok(line)
}

fn parse_real_qemu_evidence(stdout: &[u8], label: &str) -> Result<RealQemuEvidence, String> {
    const PREFIX: &str = "WRELA_REAL_QEMU_EVIDENCE ";
    let stdout = std::str::from_utf8(stdout)
        .map_err(|_| format!("{label} test-harness stdout is not UTF-8"))?;
    let lines = stdout
        .lines()
        .filter_map(|line| line.strip_prefix(PREFIX))
        .collect::<Vec<_>>();
    let [line] = lines.as_slice() else {
        return Err(format!(
            "{label} did not emit exactly one canonical real-QEMU evidence line"
        ));
    };
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let [
        schema,
        image_sha256,
        image_bytes,
        report_sha256,
        report_bytes,
        event_sha256,
        event_bytes,
    ] = fields.as_slice()
    else {
        return Err(format!("{label} emitted malformed real-QEMU evidence"));
    };
    let exact = |field: &str, key: &str| {
        field
            .strip_prefix(key)
            .map(str::to_owned)
            .ok_or_else(|| format!("{label} real-QEMU evidence omitted {key}"))
    };
    if *schema != "schema=1" {
        return Err(format!(
            "{label} real-QEMU evidence has an unsupported schema"
        ));
    }
    let image_sha256 = exact(image_sha256, "image_sha256=")?;
    let report_sha256 = exact(report_sha256, "report_sha256=")?;
    let event_stream_sha256 = exact(event_sha256, "event_stream_sha256=")?;
    if !canonical_digest(&image_sha256)
        || !canonical_digest(&report_sha256)
        || !canonical_digest(&event_stream_sha256)
    {
        return Err(format!(
            "{label} real-QEMU evidence contains a noncanonical digest"
        ));
    }
    let evidence = RealQemuEvidence {
        image_sha256,
        image_bytes: positive_u64(&exact(image_bytes, "image_bytes=")?, "smoke image bytes")?,
        report_sha256,
        report_bytes: positive_u64(&exact(report_bytes, "report_bytes=")?, "smoke report bytes")?,
        event_stream_sha256,
        event_stream_bytes: positive_u64(
            &exact(event_bytes, "event_stream_bytes=")?,
            "smoke event stream bytes",
        )?,
    };
    let canonical = format!(
        "schema=1 image_sha256={} image_bytes={} report_sha256={} report_bytes={} event_stream_sha256={} event_stream_bytes={}",
        evidence.image_sha256,
        evidence.image_bytes,
        evidence.report_sha256,
        evidence.report_bytes,
        evidence.event_stream_sha256,
        evidence.event_stream_bytes,
    );
    if *line != canonical {
        return Err(format!(
            "{label} emitted noncanonical real-QEMU evidence whitespace"
        ));
    }
    Ok(evidence)
}

fn require_exact_test_execution(stdout: &[u8], test: &str, label: &str) -> Result<(), String> {
    let stdout = std::str::from_utf8(stdout)
        .map_err(|_| format!("{label} test-harness stdout is not UTF-8"))?;
    let execution_start = format!("test {test} ...");
    let execution_starts = stdout
        .lines()
        .filter(|line| line.trim_end() == execution_start)
        .count();
    let execution_finishes = stdout.lines().filter(|line| *line == "ok").count();
    let result_lines = stdout
        .lines()
        .filter(|line| line.starts_with("test result:"))
        .collect::<Vec<_>>();
    if stdout.matches("running 1 test").count() != 1
        || execution_starts != 1
        || execution_finishes != 1
        || result_lines.len() != 1
        || !result_lines[0].starts_with("test result: ok. 1 passed; 0 failed; 0 ignored;")
    {
        return Err(format!(
            "{label} did not execute exactly the required ignored integration test"
        ));
    }
    Ok(())
}

fn run_public_command(
    frontend: &Path,
    installation: &Path,
    current_directory: &Path,
    temp: &Path,
    arguments: &[OsString],
    label: &str,
    timeout_seconds: u64,
) -> Result<ProcessOutput, String> {
    let mut command = Command::new(frontend);
    command
        .current_dir(current_directory)
        .env_clear()
        .env("HOME", temp)
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("PATH", "/wrela/no-ambient-path")
        .env("TMPDIR", temp)
        .env("TZ", "UTC")
        .env("WRELA_TOOLCHAIN_ROOT", installation)
        .args(arguments);
    run_command(&mut command, label, timeout_seconds)
}

fn validate_installation_tree(installation: &Path) -> Result<(), String> {
    let tree = measure_tree(installation, MAX_TREE_FILES, MAX_TREE_BYTES)?;
    validate_sealed_installation_modes(installation, &tree)?;
    for required in [
        format!("bin/{}", executable_name("wrela")),
        format!("libexec/wrela/{}", executable_name("wrela-backend")),
        format!("libexec/wrela/{}", executable_name("qemu-system-aarch64")),
        "share/wrela/toolchain.toml".to_owned(),
        format!("share/wrela/std/{CORE_COMPONENT}/wrela.toml"),
        format!("share/wrela/std/{CORE_COMPONENT}/src/image.wr"),
        format!("share/wrela/std/{CORE_COMPONENT}/src/result.wr"),
        format!("share/wrela/std/{CORE_COMPONENT}/src/time.wr"),
        "share/wrela/examples/virtio-storage/virtio-storage.wr".to_owned(),
        "share/wrela/examples/virtio-storage/STATUS.md".to_owned(),
        format!("share/wrela/targets/{TARGET_IDENTITY}/target.toml"),
    ] {
        required_record(&tree, &required)?;
    }
    validate_installed_core_inventory(installation)?;
    validate_installed_appliance_inventory(installation)?;
    inspect_macho_dependencies(&installation.join("bin").join(executable_name("wrela")))?;
    inspect_macho_dependencies(
        &installation
            .join("libexec/wrela")
            .join(executable_name("wrela-backend")),
    )?;
    inspect_macho_dependencies(
        &installation
            .join("libexec/wrela")
            .join(executable_name("qemu-system-aarch64")),
    )?;
    Ok(())
}

fn validate_installed_appliance_inventory(installation: &Path) -> Result<(), String> {
    let appliance = exact_directory(
        &installation.join("share/wrela/examples/virtio-storage"),
        "installed virtio-storage example",
    )?;
    if bounded_directory_names(&appliance, 3, "installed virtio-storage inventory")?
        != ["STATUS.md", "virtio-storage.wr"]
    {
        return Err("installed virtio-storage example inventory is not exact-current".to_owned());
    }
    Ok(())
}

fn validate_installed_core_inventory(installation: &Path) -> Result<(), String> {
    let core = exact_directory(
        &installation.join("share/wrela/std").join(CORE_COMPONENT),
        "installed core standard-library package",
    )?;
    if bounded_directory_names(&core, 3, "installed core package inventory")?
        != ["src", "wrela.toml"]
    {
        return Err("installed core package inventory is not exact-current".to_owned());
    }
    let source = exact_directory(&core.join("src"), "installed core source directory")?;
    if bounded_directory_names(&source, 4, "installed core source inventory")?
        != ["image.wr", "result.wr", "time.wr"]
    {
        return Err("installed core source inventory is not exact-current".to_owned());
    }
    Ok(())
}

#[cfg(unix)]
fn validate_sealed_installation_modes(
    installation: &Path,
    tree: &TreeMeasurement,
) -> Result<(), String> {
    for record in &tree.records {
        let path = installation.join(&record.path);
        let metadata = stable_metadata(&path, "sealed installation file")?;
        let expected = if record.executable { 0o555 } else { 0o444 };
        if metadata.mode() & 0o7777 != expected || metadata.nlink() != 1 {
            return Err(format!(
                "sealed installation file has mode/link drift: {}",
                path.display()
            ));
        }
    }
    let mut directories = Vec::new();
    collect_directories(installation, &mut directories, 0)?;
    for directory in directories {
        let metadata = stable_metadata(&directory, "sealed installation directory")?;
        if metadata.mode() & 0o7777 != 0o555 {
            return Err(format!(
                "sealed installation directory has mode drift: {}",
                directory.display()
            ));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_sealed_installation_modes(
    _installation: &Path,
    _tree: &TreeMeasurement,
) -> Result<(), String> {
    Err("distribution assembly has no reviewed non-Unix sealed-mode contract".to_owned())
}

fn copy_source_tree(
    source: &Path,
    destination: &Path,
    expected: &TreeMeasurement,
) -> Result<(), String> {
    create_private_directory(destination)?;
    for record in &expected.records {
        copy_new_file(
            &source.join(&record.path),
            &destination.join(&record.path),
            record.executable,
        )?;
    }
    require_same_tree(
        expected,
        &measure_source_tree(destination)?,
        "isolated source-tree copy",
    )?;
    require_same_tree(
        expected,
        &measure_source_tree(source)?,
        "source tree after isolated copy",
    )?;
    seal_installation_directories(destination)?;
    require_same_tree(
        expected,
        &measure_source_tree(destination)?,
        "sealed isolated source-tree copy",
    )
}

fn copy_exact_file(
    source: &Path,
    destination: &Path,
    expected: &FileMeasurement,
    executable: bool,
    label: &str,
) -> Result<(), String> {
    let measure = |path: &Path| {
        if expected.bytes == 0 {
            measure_file_allow_empty(path, MAX_FILE_BYTES, executable)
        } else {
            measure_file(path, MAX_FILE_BYTES, executable)
        }
    };
    if measure(source)? != *expected {
        return Err(format!("authenticated {label} changed before copy"));
    }
    if expected.bytes == 0 {
        copy_new_file_allow_empty(source, destination, executable)?;
    } else {
        copy_new_file(source, destination, executable)?;
    }
    if measure(source)? != *expected || measure(destination)? != *expected {
        return Err(format!("authenticated {label} changed during copy"));
    }
    Ok(())
}

fn copy_exact_measured_tree(
    source: &Path,
    destination: &Path,
    expected: &TreeMeasurement,
    label: &str,
) -> Result<(), String> {
    if destination.exists() {
        return Err(format!("authenticated {label} destination already exists"));
    }
    for record in &expected.records {
        let measurement = FileMeasurement {
            sha256: record.sha256.clone(),
            bytes: record.bytes,
        };
        copy_exact_file(
            &source.join(&record.path),
            &destination.join(&record.path),
            &measurement,
            record.executable,
            label,
        )?;
    }
    require_same_tree(
        expected,
        &measure_closure_tree(destination, MAX_TREE_FILES, MAX_TREE_BYTES)?,
        &format!("copied authenticated {label}"),
    )
}

fn copy_exact_tree_file(
    source_root: &Path,
    expected_tree: &TreeMeasurement,
    relative: &str,
    destination: &Path,
) -> Result<(), String> {
    let record = required_record(expected_tree, relative)?;
    let expected = FileMeasurement {
        sha256: record.sha256.clone(),
        bytes: record.bytes,
    };
    copy_exact_file(
        &source_root.join(relative),
        destination,
        &expected,
        record.executable,
        &format!("tree input {relative}"),
    )
}

fn copy_exact_tree_subtree(
    source_root: &Path,
    expected_tree: &TreeMeasurement,
    prefix: &str,
    destination: &Path,
) -> Result<(), String> {
    let expected = exact_tree_subtree(expected_tree, prefix)?;
    for record in &expected.records {
        copy_exact_tree_file(
            source_root,
            expected_tree,
            &format!("{prefix}{}", record.path),
            &destination.join(&record.path),
        )?;
    }
    require_same_tree(
        &expected,
        &measure_tree(destination, MAX_TREE_FILES, MAX_TREE_BYTES)?,
        &format!("copied authenticated subtree {prefix}"),
    )
}

fn exact_tree_subtree(
    expected_tree: &TreeMeasurement,
    prefix: &str,
) -> Result<TreeMeasurement, String> {
    if prefix.is_empty()
        || !prefix.ends_with('/')
        || !portable_tree_path(&prefix[..prefix.len() - 1])
    {
        return Err("authenticated subtree prefix is not canonical".to_owned());
    }
    let records = expected_tree
        .records
        .iter()
        .filter_map(|record| {
            record
                .path
                .strip_prefix(prefix)
                .map(|relative| (record, relative))
        })
        .map(|(record, relative)| {
            if relative.is_empty() {
                return Err("authenticated subtree contains an empty relative path".to_owned());
            }
            Ok(FileRecord {
                path: relative.to_owned(),
                bytes: record.bytes,
                sha256: record.sha256.clone(),
                executable: record.executable,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if records.is_empty() {
        return Err(format!("authenticated source tree omits subtree {prefix}"));
    }
    finish_tree(records, MAX_TREE_FILES, MAX_TREE_BYTES)
}

fn copy_tree_mutable(source: &Path, destination: &Path) -> Result<(), String> {
    let tree = measure_tree(source, MAX_TREE_FILES, MAX_TREE_BYTES)?;
    for record in &tree.records {
        copy_new_file(
            &source.join(&record.path),
            &destination.join(&record.path),
            record.executable,
        )?;
        set_mode(
            &destination.join(&record.path),
            if record.executable { 0o700 } else { 0o600 },
        )?;
    }
    Ok(())
}

fn copy_new_file(source: &Path, destination: &Path, executable: bool) -> Result<(), String> {
    copy_new_file_with_policy(source, destination, executable, false)
}

fn copy_new_file_allow_empty(
    source: &Path,
    destination: &Path,
    executable: bool,
) -> Result<(), String> {
    copy_new_file_with_policy(source, destination, executable, true)
}

fn copy_new_file_with_policy(
    source: &Path,
    destination: &Path,
    executable: bool,
    allow_empty: bool,
) -> Result<(), String> {
    let measure = |path: &Path| {
        if allow_empty {
            measure_file_allow_empty(path, MAX_FILE_BYTES, executable)
        } else {
            measure_file(path, MAX_FILE_BYTES, executable)
        }
    };
    let source_before = stable_metadata(source, "copy source")?;
    if !source_before.is_file() {
        return Err(format!("copy source is not a file: {}", source.display()));
    }
    validate_file_mode(source, &source_before, executable)?;
    let expected = measure(source)?;
    let parent = destination
        .parent()
        .ok_or_else(|| format!("destination has no parent: {}", destination.display()))?;
    create_private_directory_chain(parent)?;
    let mut input = open_read_only_no_follow(source)?;
    let opened = input
        .metadata()
        .map_err(|error| format!("cannot inspect opened {}: {error}", source.display()))?;
    if !same_metadata(&source_before, &opened) {
        return Err(format!(
            "copy source changed or traversed a link while opened: {}",
            source.display()
        ));
    }
    let mut output = new_file(destination)?;
    let mut digest = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = input
            .read(&mut buffer)
            .map_err(|error| format!("cannot read {}: {error}", source.display()))?;
        if read == 0 {
            break;
        }
        output
            .write_all(&buffer[..read])
            .map_err(|error| format!("cannot write {}: {error}", destination.display()))?;
        digest.update(&buffer[..read]);
        total = total
            .checked_add(u64::try_from(read).map_err(|_| "copy byte count overflow".to_owned())?)
            .ok_or_else(|| "copy byte count overflow".to_owned())?;
        if total > MAX_FILE_BYTES {
            return Err("copy exceeded the single-file byte limit".to_owned());
        }
    }
    output
        .sync_all()
        .map_err(|error| format!("cannot sync {}: {error}", destination.display()))?;
    drop(output);
    set_mode(destination, if executable { 0o555 } else { 0o444 })?;
    let actual = FileMeasurement {
        sha256: lower_hex(&digest.finalize()),
        bytes: total,
    };
    let source_after = stable_metadata(source, "copy source")?;
    if actual != expected
        || !same_metadata(&source_before, &source_after)
        || measure(source)? != expected
    {
        return Err(format!("{} changed while copied", source.display()));
    }
    if measure(destination)? != expected {
        return Err(format!("{} differs after copy", destination.display()));
    }
    sync_directory(parent)
}

#[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
const OPEN_NO_FOLLOW: i32 = 0x0000_0100;

#[cfg(any(target_os = "linux", target_os = "android"))]
const OPEN_NO_FOLLOW: i32 = 0x0002_0000;

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "linux",
    target_os = "android"
))]
fn open_read_only_no_follow(path: &Path) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(OPEN_NO_FOLLOW);
    options.open(path).map_err(|error| {
        format!(
            "cannot open {} without following links: {error}",
            path.display()
        )
    })
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "linux",
    target_os = "android"
)))]
fn open_read_only_no_follow(_path: &Path) -> Result<File, String> {
    Err("exact file copy has no reviewed non-Unix no-follow contract".to_owned())
}

fn write_new_bytes(path: &Path, bytes: &[u8], executable: bool) -> Result<(), String> {
    if bytes.is_empty()
        || u64::try_from(bytes.len())
            .ok()
            .is_none_or(|length| length > MAX_FILE_BYTES)
    {
        return Err(format!(
            "refusing empty or oversized output {}",
            path.display()
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("output has no parent: {}", path.display()))?;
    create_private_directory_chain(parent)?;
    let mut output = new_file(path)?;
    output
        .write_all(bytes)
        .and_then(|()| output.sync_all())
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    drop(output);
    set_mode(path, if executable { 0o555 } else { 0o444 })?;
    let expected = FileMeasurement {
        sha256: sha256_bytes(bytes),
        bytes: u64::try_from(bytes.len()).map_err(|_| "output length overflow".to_owned())?,
    };
    if measure_file(path, MAX_FILE_BYTES, executable)? != expected {
        return Err(format!("{} differs after publication", path.display()));
    }
    sync_directory(parent)
}

fn new_file(path: &Path) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    options
        .open(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))
}

fn seal_installation_directories(root: &Path) -> Result<(), String> {
    let mut directories = Vec::new();
    collect_directories(root, &mut directories, 0)?;
    directories.sort_unstable_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        set_mode(&directory, 0o555)?;
    }
    Ok(())
}

fn make_directories_writable(root: &Path) -> Result<(), String> {
    let mut directories = Vec::new();
    collect_directories(root, &mut directories, 0)?;
    for directory in directories {
        set_mode(&directory, 0o700)?;
    }
    Ok(())
}

fn collect_directories(path: &Path, output: &mut Vec<PathBuf>, depth: u32) -> Result<(), String> {
    let mut budget = TraversalBudget::new(MAX_TREE_ENTRIES)?;
    collect_directories_bounded(path, output, depth, &mut budget)
}

fn collect_directories_bounded(
    path: &Path,
    output: &mut Vec<PathBuf>,
    depth: u32,
    budget: &mut TraversalBudget,
) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err("installation directory depth exceeded".to_owned());
    }
    let metadata = stable_metadata(path, "installation directory")?;
    if !metadata.is_dir() {
        return Err(format!(
            "{} is not an installation directory",
            path.display()
        ));
    }
    output
        .try_reserve(1)
        .map_err(|_| "cannot reserve bounded installation-directory traversal".to_owned())?;
    output.push(path.to_path_buf());
    for entry in fs::read_dir(path)
        .map_err(|error| format!("cannot enumerate {}: {error}", path.display()))?
    {
        let entry = entry.map_err(|error| format!("cannot inspect directory entry: {error}"))?;
        budget.record_entry()?;
        let entry_path = entry.path();
        let metadata = stable_metadata(&entry_path, "installation entry")?;
        if metadata.is_dir() {
            collect_directories_bounded(&entry_path, output, depth.saturating_add(1), budget)?;
        }
    }
    Ok(())
}

fn run_runtime_boot_smoke(
    root: &Path,
    plan: &ReleasePlan,
    installation: &Path,
    frozen_lld_shim: &Path,
    frozen_lld_shim_measurement: &FileMeasurement,
    work: &Path,
) -> Result<RuntimeBootEvidence, String> {
    let smoke = work.join("runtime-boot-smoke");
    create_private_directory(&smoke)?;
    let lld = build_lld_smoke_driver(plan, frozen_lld_shim, frozen_lld_shim_measurement, &smoke)?;
    let source = root.join("toolchain/targets/aarch64-qemu-virt-uefi/runtime-src/smoke.S");
    let smoke_object = smoke.join("smoke.obj");
    let mut compile = Command::new(&plan.native.cxx);
    compile
        .current_dir(
            source
                .parent()
                .ok_or_else(|| "runtime smoke source has no parent".to_owned())?,
        )
        .env_clear()
        .env("HOME", &smoke)
        .env("LC_ALL", "C")
        .env("PATH", "/wrela/no-ambient-path")
        .env("SOURCE_DATE_EPOCH", "0")
        .env("TMPDIR", &smoke)
        .env("TZ", "UTC")
        .args([
            OsString::from("--target=aarch64-unknown-uefi"),
            OsString::from("-c"),
            OsString::from("-x"),
            OsString::from("assembler"),
            OsString::from("-nostdlib"),
            OsString::from("-nodefaultlibs"),
            OsString::from("-g0"),
            OsString::from("-Werror"),
            source.as_os_str().to_owned(),
            OsString::from("-o"),
            smoke_object.as_os_str().to_owned(),
        ]);
    let output = run_command(&mut compile, "runtime smoke consumer compilation", 10 * 60)?;
    require_success(&output, "runtime smoke consumer compilation", true)?;
    let image = smoke.join("BOOTAA64.EFI");
    let runtime = installation
        .join("share/wrela/targets")
        .join(TARGET_IDENTITY)
        .join("runtime/wrela-runtime-aarch64.obj");
    let mut link = Command::new(&lld);
    link.current_dir(&smoke)
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/wrela/no-ambient-path")
        .env("TZ", "UTC")
        .args([
            OsString::from("/machine:arm64"),
            OsString::from("/subsystem:efi_application"),
            OsString::from("/entry:wrela_image_entry"),
            OsString::from("/nodefaultlib"),
            OsString::from("/brepro"),
            OsString::from("/dynamicbase"),
            OsString::from("/lldignoreenv"),
            OsString::from("/WX"),
            OsString::from("/base:0"),
            OsString::from(format!("/out:{}", image.display())),
            smoke_object.as_os_str().to_owned(),
            runtime.as_os_str().to_owned(),
        ]);
    let output = run_command(&mut link, "runtime smoke EFI link", 30 * 60)?;
    require_success(&output, "runtime smoke EFI link", true)?;
    inspect_smoke_efi(&image)?;
    let image_measurement = measure_file(&image, MAX_SMOKE_IMAGE_BYTES, false)?;

    let esp_boot = smoke.join("esp/EFI/BOOT");
    create_private_directory_chain(&esp_boot)?;
    copy_new_file(&image, &esp_boot.join("BOOTAA64.EFI"), false)?;
    let target = installation
        .join("share/wrela/targets")
        .join(TARGET_IDENTITY);
    let firmware_code = target.join("firmware/QEMU_EFI.fd");
    let firmware_variables = target.join("firmware/QEMU_VARS.fd");
    let writable_variables = smoke.join("QEMU_VARS.fd");
    copy_new_file(&firmware_variables, &writable_variables, false)?;
    set_mode(&writable_variables, 0o600)?;
    let serial = smoke.join("serial.bin");
    let qemu = installation
        .join("libexec/wrela")
        .join(executable_name("qemu-system-aarch64"));
    let mut command = Command::new(&qemu);
    command
        .current_dir(&smoke)
        .env_clear()
        .env("HOME", &smoke)
        .env("LC_ALL", "C")
        .env("PATH", "/wrela/no-ambient-path")
        .env("TMPDIR", &smoke)
        .env("TZ", "UTC")
        .args(runtime_boot_qemu_arguments(
            &plan.emulation.machine_contract,
            &plan.emulation.cpu_contract,
            &plan.emulation.accelerator_contract,
            &firmware_code,
            &writable_variables,
            &smoke.join("esp"),
            &serial,
        ));
    let output = run_command(&mut command, "pinned QEMU runtime boot smoke", 60)?;
    require_success(&output, "pinned QEMU runtime boot smoke", true)?;
    let serial_bytes = read_bounded_file(&serial, MAX_SMOKE_SERIAL_BYTES)?;
    let frames = slip_frames(&serial_bytes)?;
    if frames.len() != EXPECTED_SMOKE_FRAMES.len()
        || !frames
            .iter()
            .zip(EXPECTED_SMOKE_FRAMES)
            .all(|(observed, expected)| observed.as_slice() == *expected)
    {
        return Err("runtime smoke PL011 stream did not contain exactly the four canonical test-protocol v3 frames".to_owned());
    }
    if !serial_bytes.windows(2).any(|pair| pair == [0xdb, 0xdc])
        || !serial_bytes.windows(2).any(|pair| pair == [0xdb, 0xdd])
    {
        return Err(
            "runtime smoke complete serial stream did not exercise both canonical SLIP escapes"
                .to_owned(),
        );
    }
    if measure_file(&image, MAX_SMOKE_IMAGE_BYTES, false)? != image_measurement {
        return Err("runtime smoke EFI image changed during QEMU execution".to_owned());
    }
    let frame_bytes = frames.iter().try_fold(0_u64, |total, frame| {
        total
            .checked_add(
                u64::try_from(frame.len())
                    .map_err(|_| "runtime smoke frame length does not fit u64".to_owned())?,
            )
            .ok_or_else(|| "runtime smoke frame-stream length overflows".to_owned())
    })?;
    let frame_capacity = usize::try_from(frame_bytes)
        .map_err(|_| "runtime smoke frame-stream length does not fit the host".to_owned())?;
    let mut frame_stream = Vec::new();
    frame_stream
        .try_reserve_exact(frame_capacity)
        .map_err(|_| "cannot allocate bounded runtime smoke frame stream".to_owned())?;
    for frame in &frames {
        frame_stream.extend_from_slice(frame);
    }
    Ok(RuntimeBootEvidence {
        image: image_measurement,
        frame_sha256: sha256_bytes(&frame_stream),
        frame_bytes,
    })
}

fn runtime_boot_qemu_arguments(
    machine_contract: &str,
    cpu_contract: &str,
    accelerator_contract: &str,
    firmware_code: &Path,
    firmware_variables: &Path,
    esp: &Path,
    serial: &Path,
) -> Vec<OsString> {
    vec![
        OsString::from("-machine"),
        OsString::from(format!("{machine_contract},gic-version=3,secure=off")),
        OsString::from("-cpu"),
        OsString::from(cpu_contract),
        OsString::from("-accel"),
        OsString::from(accelerator_contract),
        OsString::from("-m"),
        OsString::from("512"),
        OsString::from("-smp"),
        OsString::from("1"),
        OsString::from("-nic"),
        OsString::from("none"),
        OsString::from("-drive"),
        OsString::from(format!(
            "if=pflash,format=raw,unit=0,readonly=on,file={}",
            firmware_code.display()
        )),
        OsString::from("-drive"),
        OsString::from(format!(
            "if=pflash,format=raw,unit=1,file={}",
            firmware_variables.display()
        )),
        OsString::from("-drive"),
        OsString::from(format!(
            "if=none,format=raw,file=fat:rw:{},id=hd0",
            esp.display()
        )),
        OsString::from("-device"),
        OsString::from("virtio-blk-device,drive=hd0"),
        OsString::from("-serial"),
        OsString::from(format!("file:{}", serial.display())),
        OsString::from("-monitor"),
        OsString::from("none"),
        OsString::from("-display"),
        OsString::from("none"),
        OsString::from("-no-reboot"),
    ]
}

fn build_lld_smoke_driver(
    plan: &ReleasePlan,
    frozen_lld_shim: &Path,
    frozen_lld_shim_measurement: &FileMeasurement,
    output: &Path,
) -> Result<PathBuf, String> {
    let shim = exact_measured_frozen_lld_shim(frozen_lld_shim, frozen_lld_shim_measurement)?;
    let source = output.join("lld-smoke-main.cpp");
    let source_bytes = br#"#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <vector>
extern "C" {
struct WrelaLldResult {
  std::int32_t status;
  std::uint8_t can_run_again;
  std::uint8_t reserved[3];
  std::size_t captured_bytes;
  std::size_t total_bytes;
};
WrelaLldResult wrela_lld_link_coff(const char *const *, std::size_t, char *, std::size_t) noexcept;
}
int main(int argc, char **argv) {
  if (argc <= 1) return 2;
  std::vector<const char *> args;
  args.reserve(static_cast<std::size_t>(argc));
  args.push_back("lld-link");
  for (int index = 1; index < argc; ++index) args.push_back(argv[index]);
  std::vector<char> diagnostics(1024 * 1024);
  WrelaLldResult result = wrela_lld_link_coff(args.data(), args.size(), diagnostics.data(), diagnostics.size());
  if (result.captured_bytes != 0) std::fwrite(diagnostics.data(), 1, result.captured_bytes, stderr);
  if (result.total_bytes > diagnostics.size()) return 125;
  return result.status;
}
"#;
    write_new_bytes(&source, source_bytes, false)?;
    let llvm_config = plan.native.prefix.join("bin/llvm-config");
    let llvm_libraries = llvm_config_tokens(&llvm_config, &["--libs", "--link-static"])?;
    let system_libraries = llvm_config_tokens(&llvm_config, &["--system-libs", "--link-static"])?;
    let executable = output.join("lld-link-smoke");
    let mut arguments = vec![
        OsString::from("-std=c++17"),
        OsString::from("-O2"),
        OsString::from("-g0"),
        OsString::from("-Werror"),
        OsString::from(format!("-mmacosx-version-min={MACOS_DEPLOYMENT_TARGET}")),
    ];
    arguments.extend(MACHO_LINKER_ARGUMENTS.map(OsString::from));
    arguments.extend([
        source.as_os_str().to_owned(),
        shim.as_os_str().to_owned(),
        OsString::from(format!("-L{}", plan.native.prefix.join("lib").display())),
        OsString::from("-llldCOFF"),
        OsString::from("-llldCommon"),
    ]);
    arguments.extend(llvm_libraries.into_iter().map(OsString::from));
    arguments.extend(system_libraries.into_iter().map(OsString::from));
    arguments.extend([
        OsString::from("-lc++"),
        OsString::from("-isysroot"),
        plan.native.sysroot.as_os_str().to_owned(),
        OsString::from("-o"),
        executable.as_os_str().to_owned(),
    ]);
    let mut command = Command::new(&plan.native.cxx);
    command
        .current_dir(output)
        .env_clear()
        .env("LC_ALL", "C")
        .env("MACOSX_DEPLOYMENT_TARGET", MACOS_DEPLOYMENT_TARGET)
        .env("PATH", "/wrela/no-ambient-path")
        .env("SDKROOT", &plan.native.sysroot)
        .env("SOURCE_DATE_EPOCH", "0")
        .env("TMPDIR", output)
        .env("TZ", "UTC")
        .args(arguments);
    exact_measured_frozen_lld_shim(&shim, frozen_lld_shim_measurement)?;
    let result = run_command(&mut command, "LLD smoke-driver link", 30 * 60);
    exact_measured_frozen_lld_shim(&shim, frozen_lld_shim_measurement)?;
    let result = result?;
    require_success(&result, "LLD smoke-driver link", true)?;
    set_mode(&executable, 0o555)?;
    measure_file(&executable, MAX_FILE_BYTES, true)?;
    inspect_macho_dependencies(&executable)?;
    Ok(executable)
}

fn exact_measured_frozen_lld_shim(
    path: &Path,
    expected: &FileMeasurement,
) -> Result<PathBuf, String> {
    let path = exact_file(path, "frozen release LLD shim archive")?;
    if measure_file(&path, MAX_FILE_BYTES, false)? != *expected {
        return Err("frozen release LLD shim archive changed after authentication".to_owned());
    }
    Ok(path)
}

fn find_lld_shim(release_target: &Path) -> Result<PathBuf, String> {
    let build = release_target.join("dist/build");
    let mut budget = TraversalBudget::new(MAX_TREE_ENTRIES)?;
    let mut candidate = None;
    for entry in fs::read_dir(&build)
        .map_err(|error| format!("cannot enumerate release build scripts: {error}"))?
    {
        let entry =
            entry.map_err(|error| format!("cannot inspect release build entry: {error}"))?;
        budget.record_entry()?;
        let name = entry.file_name();
        if name
            .to_str()
            .is_some_and(|name| name.starts_with("wrela-lld-sys-"))
        {
            let path = entry.path().join("out/libwrela_lld_shim.a");
            if path.exists() {
                let path = exact_file(&path, "release LLD shim archive")?;
                if candidate.replace(path).is_some() {
                    return Err("release build produced more than one LLD shim archive".to_owned());
                }
            }
        }
    }
    candidate.ok_or_else(|| "release build produced no LLD shim archive".to_owned())
}

fn llvm_config_tokens(tool: &Path, arguments: &[&str]) -> Result<Vec<String>, String> {
    let mut command = Command::new(tool);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/wrela/no-ambient-path")
        .env("TZ", "UTC")
        .args(arguments);
    let output = run_command(&mut command, "authenticated llvm-config query", 60)?;
    require_success(&output, "authenticated llvm-config query", false)?;
    if !output.stderr.is_empty() {
        return Err("authenticated llvm-config query wrote stderr".to_owned());
    }
    let text = std::str::from_utf8(&output.stdout)
        .map_err(|_| "llvm-config output is not UTF-8".to_owned())?;
    let tokens = text
        .split_ascii_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if tokens.is_empty()
        || tokens.len() > 4096
        || tokens.iter().any(|token| {
            !token.starts_with("-l")
                || token.len() <= 2
                || token[2..].bytes().any(|byte| {
                    !(byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'+' | b'-' | b'.'))
                })
        })
    {
        return Err("llvm-config returned an invalid static link token list".to_owned());
    }
    Ok(tokens)
}

fn inspect_smoke_efi(path: &Path) -> Result<(), String> {
    let bytes = read_bounded_file(path, MAX_SMOKE_IMAGE_BYTES)?;
    if bytes.len() < 0x100 || bytes.get(..2) != Some(b"MZ") {
        return Err("runtime smoke output is not a PE image".to_owned());
    }
    let pe = usize::try_from(read_u32(&bytes, 0x3c)?)
        .map_err(|_| "PE header offset does not fit host".to_owned())?;
    if bytes.get(pe..pe + 4) != Some(b"PE\0\0") {
        return Err("runtime smoke output has an invalid PE signature".to_owned());
    }
    let coff = pe + 4;
    let optional_size = usize::from(read_u16(&bytes, coff + 16)?);
    let optional = coff + 20;
    if read_u16(&bytes, coff)? != 0xaa64
        || optional_size < 160
        || read_u16(&bytes, optional)? != 0x20b
        || read_u64(&bytes, optional + 24)? != 0
        || read_u16(&bytes, optional + 68)? != 10
    {
        return Err("runtime smoke output is not zero-base ARM64 PE32+ EFI".to_owned());
    }
    let relocation_rva = read_u32(&bytes, optional + 112 + 5 * 8)?;
    let relocation_bytes = read_u32(&bytes, optional + 112 + 5 * 8 + 4)?;
    if relocation_rva == 0 || relocation_bytes == 0 {
        return Err("runtime smoke output has no base relocation directory".to_owned());
    }
    Ok(())
}

fn slip_frames(serial: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let mut frames = Vec::new();
    let mut current = None::<Vec<u8>>;
    let mut index = 0usize;
    while index < serial.len() {
        let byte = serial[index];
        index += 1;
        if byte == 0xc0 {
            if let Some(frame) = current.take().filter(|frame| !frame.is_empty()) {
                frames.push(frame);
            }
            current = Some(Vec::new());
            continue;
        }
        let Some(frame) = &mut current else {
            continue;
        };
        if byte == 0xdb {
            let escaped = *serial
                .get(index)
                .ok_or_else(|| "runtime smoke ended inside a SLIP escape".to_owned())?;
            index += 1;
            match escaped {
                0xdc => frame.push(0xc0),
                0xdd => frame.push(0xdb),
                _ => return Err("runtime smoke contains a noncanonical SLIP escape".to_owned()),
            }
        } else {
            frame.push(byte);
        }
        if frame.len() > MAX_SMOKE_SERIAL_BYTES as usize {
            return Err("runtime smoke frame exceeds its byte limit".to_owned());
        }
    }
    if current.as_ref().is_some_and(|frame| !frame.is_empty()) {
        return Err("runtime smoke contains an unterminated SLIP frame".to_owned());
    }
    Ok(frames)
}

fn write_canonical_archive(
    installation: &Path,
    tree: &TreeMeasurement,
    archive: &Path,
    prefix: &str,
) -> Result<(), String> {
    if !portable_component(prefix) {
        return Err("archive prefix is not portable".to_owned());
    }
    let mut directories = BTreeSet::new();
    directories.insert(prefix.to_owned());
    for record in &tree.records {
        let mut relative = PathBuf::from(&record.path);
        relative.pop();
        while !relative.as_os_str().is_empty() {
            let parent = relative
                .to_str()
                .ok_or_else(|| "archive directory is not UTF-8".to_owned())?
                .replace(std::path::MAIN_SEPARATOR, "/");
            directories.insert(format!("{prefix}/{parent}"));
            relative.pop();
        }
    }
    let mut entries = BTreeMap::<String, Option<&FileRecord>>::new();
    for directory in directories {
        entries.insert(format!("{directory}/"), None);
    }
    for record in &tree.records {
        let path = format!("{prefix}/{}", record.path);
        if entries.insert(path, Some(record)).is_some() {
            return Err("archive entry collision".to_owned());
        }
    }
    let mut output = new_file(archive)?;
    let mut written = 0u64;
    for (path, record) in entries {
        let directory = record.is_none();
        let size = record.map_or(0, |record| record.bytes);
        let mode = if directory || record.is_some_and(|record| record.executable) {
            0o555
        } else {
            0o444
        };
        let header = tar_header(&path, mode, size, directory)?;
        output
            .write_all(&header)
            .map_err(|error| format!("cannot write archive header: {error}"))?;
        written = add_archive_bytes(written, 512)?;
        if let Some(record) = record {
            let source = installation.join(&record.path);
            let before = measure_file(&source, MAX_FILE_BYTES, record.executable)?;
            if before.sha256 != record.sha256 || before.bytes != record.bytes {
                return Err(format!(
                    "archive source {:?} changed before read",
                    record.path
                ));
            }
            let mut input = File::open(&source).map_err(|error| {
                format!("cannot open archive input {}: {error}", source.display())
            })?;
            let mut digest = Sha256::new();
            let mut remaining = record.bytes;
            let mut buffer = [0u8; 64 * 1024];
            while remaining != 0 {
                let request = usize::try_from(remaining.min(buffer.len() as u64))
                    .map_err(|_| "archive read size does not fit host".to_owned())?;
                let read = input
                    .read(&mut buffer[..request])
                    .map_err(|error| format!("cannot read archive input: {error}"))?;
                if read == 0 {
                    return Err(format!("archive input {:?} was truncated", record.path));
                }
                output
                    .write_all(&buffer[..read])
                    .map_err(|error| format!("cannot write archive data: {error}"))?;
                digest.update(&buffer[..read]);
                remaining -= u64::try_from(read)
                    .map_err(|_| "archive read count does not fit u64".to_owned())?;
                written = add_archive_bytes(
                    written,
                    u64::try_from(read).map_err(|_| "archive write count overflow".to_owned())?,
                )?;
            }
            let padding = (512 - record.bytes % 512) % 512;
            if padding != 0 {
                output
                    .write_all(
                        &[0u8; 512][..usize::try_from(padding)
                            .map_err(|_| "archive padding does not fit host".to_owned())?],
                    )
                    .map_err(|error| format!("cannot write archive padding: {error}"))?;
                written = add_archive_bytes(written, padding)?;
            }
            if lower_hex(&digest.finalize()) != record.sha256
                || measure_file(&source, MAX_FILE_BYTES, record.executable)? != before
            {
                return Err(format!(
                    "archive input {:?} changed while read",
                    record.path
                ));
            }
        }
    }
    output
        .write_all(&[0u8; 1024])
        .and_then(|()| output.sync_all())
        .map_err(|error| format!("cannot finalize canonical archive: {error}"))?;
    written = add_archive_bytes(written, 1024)?;
    drop(output);
    set_mode(archive, 0o444)?;
    let measured = measure_file(archive, MAX_TREE_BYTES, false)?;
    if measured.bytes != written {
        return Err("canonical archive length differs after finalization".to_owned());
    }
    sync_directory(
        archive
            .parent()
            .ok_or_else(|| "archive has no parent".to_owned())?,
    )
}

fn tar_header(path: &str, mode: u32, size: u64, directory: bool) -> Result<[u8; 512], String> {
    if path.is_empty() || path.len() > 255 || !path.is_ascii() {
        return Err(format!(
            "archive path cannot be represented in ustar: {path:?}"
        ));
    }
    let (name, prefix) = split_ustar_path(path)?;
    let mut header = [0u8; 512];
    copy_field(&mut header[0..100], name.as_bytes(), "tar name")?;
    write_octal(&mut header[100..108], u64::from(mode), "tar mode")?;
    write_octal(&mut header[108..116], 0, "tar uid")?;
    write_octal(&mut header[116..124], 0, "tar gid")?;
    write_octal(&mut header[124..136], size, "tar size")?;
    write_octal(&mut header[136..148], 0, "tar mtime")?;
    header[148..156].fill(b' ');
    header[156] = if directory { b'5' } else { b'0' };
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    copy_field(&mut header[345..500], prefix.as_bytes(), "tar prefix")?;
    let checksum = header.iter().map(|byte| u64::from(*byte)).sum::<u64>();
    let text = format!("{checksum:06o}\0 ");
    if text.len() != 8 {
        return Err("tar checksum does not fit canonical field".to_owned());
    }
    header[148..156].copy_from_slice(text.as_bytes());
    Ok(header)
}

fn split_ustar_path(path: &str) -> Result<(&str, &str), String> {
    if path.len() <= 100 {
        return Ok((path, ""));
    }
    for (index, _) in path.match_indices('/').rev() {
        let prefix = &path[..index];
        let name = &path[index + 1..];
        if !name.is_empty() && name.len() <= 100 && prefix.len() <= 155 {
            return Ok((name, prefix));
        }
    }
    Err(format!(
        "archive path does not fit ustar name/prefix: {path:?}"
    ))
}

fn copy_field(field: &mut [u8], value: &[u8], label: &str) -> Result<(), String> {
    if value.len() > field.len() {
        return Err(format!("{label} exceeds its field"));
    }
    field[..value.len()].copy_from_slice(value);
    Ok(())
}

fn write_octal(field: &mut [u8], value: u64, label: &str) -> Result<(), String> {
    if field.len() < 2 {
        return Err(format!("{label} field is too short"));
    }
    let digits = field.len() - 1;
    let text = format!("{value:0digits$o}");
    if text.len() != digits {
        return Err(format!("{label} value does not fit"));
    }
    field[..digits].copy_from_slice(text.as_bytes());
    field[digits] = 0;
    Ok(())
}

fn add_archive_bytes(total: u64, amount: u64) -> Result<u64, String> {
    let next = total
        .checked_add(amount)
        .ok_or_else(|| "archive byte count overflow".to_owned())?;
    if next > MAX_TREE_BYTES {
        return Err(format!("archive exceeds {MAX_TREE_BYTES} bytes"));
    }
    Ok(next)
}

fn extract_canonical_archive(
    archive: &Path,
    destination: &Path,
    expected_prefix: &str,
) -> Result<(), String> {
    let measured = measure_file(archive, MAX_TREE_BYTES, false)?;
    if measured.bytes < 1536 || measured.bytes % 512 != 0 {
        return Err("canonical archive has an invalid block extent".to_owned());
    }
    let mut input =
        File::open(archive).map_err(|error| format!("cannot open clean-room archive: {error}"))?;
    let mut seen = BTreeSet::new();
    let mut directories = Vec::new();
    let mut trailer_blocks = 0u8;
    let mut consumed = 0u64;
    loop {
        let mut header = [0u8; 512];
        input
            .read_exact(&mut header)
            .map_err(|error| format!("cannot read canonical archive header: {error}"))?;
        consumed = consumed
            .checked_add(512)
            .ok_or_else(|| "archive extraction byte count overflow".to_owned())?;
        if header.iter().all(|byte| *byte == 0) {
            trailer_blocks = trailer_blocks.saturating_add(1);
            if trailer_blocks == 2 {
                break;
            }
            continue;
        }
        if trailer_blocks != 0 {
            return Err("canonical archive has data between trailer blocks".to_owned());
        }
        validate_tar_checksum(&header)?;
        if &header[257..263] != b"ustar\0" || &header[263..265] != b"00" {
            return Err("canonical archive entry is not ustar".to_owned());
        }
        let name = tar_string(&header[0..100], "tar name")?;
        let prefix = tar_string(&header[345..500], "tar prefix")?;
        let path = if prefix.is_empty() {
            name
        } else {
            format!("{prefix}/{name}")
        };
        let directory = header[156] == b'5';
        if !directory && header[156] != b'0' {
            return Err("canonical archive contains a non-file entry".to_owned());
        }
        let normalized = path.strip_suffix('/').unwrap_or(&path);
        if normalized != expected_prefix
            && !normalized
                .strip_prefix(expected_prefix)
                .is_some_and(|suffix| suffix.starts_with('/'))
        {
            return Err("canonical archive entry escapes its release prefix".to_owned());
        }
        if !normalized.split('/').all(portable_component)
            || normalized.len() > MAX_PATH_BYTES
            || (directory != path.ends_with('/'))
            || !seen.insert(normalized.to_owned())
        {
            return Err("canonical archive contains a nonportable or duplicate path".to_owned());
        }
        let mode = parse_octal(&header[100..108], "tar mode")?;
        let size = parse_octal(&header[124..136], "tar size")?;
        if parse_octal(&header[108..116], "tar uid")? != 0
            || parse_octal(&header[116..124], "tar gid")? != 0
            || parse_octal(&header[136..148], "tar mtime")? != 0
            || size > MAX_FILE_BYTES
            || (directory && (size != 0 || mode != 0o555))
            || (!directory && !matches!(mode, 0o444 | 0o555))
        {
            return Err("canonical archive entry has invalid metadata".to_owned());
        }
        let output = destination.join(normalized);
        if directory {
            fs::create_dir(&output).map_err(|error| {
                format!(
                    "cannot create archive directory {}: {error}",
                    output.display()
                )
            })?;
            set_mode(&output, 0o700)?;
            directories.push(output);
            continue;
        }
        let parent = output
            .parent()
            .ok_or_else(|| "archive output file has no parent".to_owned())?;
        if !parent.is_dir() {
            return Err("canonical archive did not declare a parent directory first".to_owned());
        }
        let mut file = new_file(&output)?;
        let mut remaining = size;
        let mut buffer = [0u8; 64 * 1024];
        while remaining != 0 {
            let request = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| "archive extraction extent does not fit host".to_owned())?;
            input
                .read_exact(&mut buffer[..request])
                .map_err(|error| format!("cannot read archive file payload: {error}"))?;
            file.write_all(&buffer[..request])
                .map_err(|error| format!("cannot write archive file payload: {error}"))?;
            remaining -= u64::try_from(request)
                .map_err(|_| "archive extraction count overflow".to_owned())?;
            consumed = consumed
                .checked_add(
                    u64::try_from(request).map_err(|_| "archive count overflow".to_owned())?,
                )
                .ok_or_else(|| "archive count overflow".to_owned())?;
        }
        file.sync_all()
            .map_err(|error| format!("cannot sync extracted archive file: {error}"))?;
        drop(file);
        set_mode(
            &output,
            u32::try_from(mode).map_err(|_| "tar mode does not fit u32".to_owned())?,
        )?;
        let padding = (512 - size % 512) % 512;
        if padding != 0 {
            let mut zeros = [0u8; 512];
            let padding = usize::try_from(padding)
                .map_err(|_| "archive padding does not fit host".to_owned())?;
            input
                .read_exact(&mut zeros[..padding])
                .map_err(|error| format!("cannot read archive padding: {error}"))?;
            if zeros[..padding].iter().any(|byte| *byte != 0) {
                return Err("canonical archive has nonzero file padding".to_owned());
            }
            consumed = consumed
                .checked_add(
                    u64::try_from(padding).map_err(|_| "archive padding overflow".to_owned())?,
                )
                .ok_or_else(|| "archive padding overflow".to_owned())?;
        }
    }
    if consumed != measured.bytes {
        return Err("canonical archive has bytes after its exact two-block trailer".to_owned());
    }
    let mut extra = [0u8; 1];
    if input
        .read(&mut extra)
        .map_err(|error| format!("cannot check archive exact consumption: {error}"))?
        != 0
    {
        return Err("canonical archive has trailing bytes".to_owned());
    }
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        set_mode(&directory, 0o555)?;
    }
    if measure_file(archive, MAX_TREE_BYTES, false)? != measured {
        return Err("canonical archive changed during extraction".to_owned());
    }
    Ok(())
}

fn validate_tar_checksum(header: &[u8; 512]) -> Result<(), String> {
    let expected = parse_octal(&header[148..156], "tar checksum")?;
    let actual = header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                u64::from(b' ')
            } else {
                u64::from(*byte)
            }
        })
        .sum::<u64>();
    if actual != expected {
        return Err("canonical archive header checksum mismatch".to_owned());
    }
    Ok(())
}

fn tar_string(field: &[u8], label: &str) -> Result<String, String> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    if field[end..].iter().any(|byte| *byte != 0) {
        return Err(format!("{label} has nonzero suffix bytes"));
    }
    let value = std::str::from_utf8(&field[..end]).map_err(|_| format!("{label} is not UTF-8"))?;
    if value.is_empty() && label == "tar name" {
        return Err("tar name is empty".to_owned());
    }
    Ok(value.to_owned())
}

fn parse_octal(field: &[u8], label: &str) -> Result<u64, String> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    let digits = &field[..end];
    if digits.is_empty()
        || !digits.iter().all(|byte| matches!(byte, b'0'..=b'7' | b' '))
        || field[end..].iter().any(|byte| !matches!(byte, 0 | b' '))
    {
        return Err(format!("{label} is not canonical octal"));
    }
    let text = std::str::from_utf8(digits)
        .map_err(|_| format!("{label} is not ASCII"))?
        .trim();
    if text.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(text, 8).map_err(|_| format!("{label} does not fit u64"))
}

fn require_reproducible_stdlib_time_evidence(
    installed: &StdlibTimeQemuEvidence,
    extracted: &StdlibTimeQemuEvidence,
) -> Result<(), String> {
    if installed == extracted {
        Ok(())
    } else {
        Err(
            "installed/extracted stdlib-time source, image, report, or event evidence is not reproducible"
                .to_owned(),
        )
    }
}

fn encode_release_receipt(
    plan: &ReleasePlan,
    installation: &TreeMeasurement,
    archive: &FileMeasurement,
    evidence: &ReleaseEvidence<'_>,
) -> Result<String, String> {
    require_reproducible_stdlib_time_evidence(
        evidence.installed_stdlib_time_qemu,
        evidence.extracted_stdlib_time_qemu,
    )?;
    Ok(format!(
        "schema = {RELEASE_RECEIPT_SCHEMA}\n\
release = \"{}\"\n\
host = \"{}\"\n\
rust_toolchain = \"{}\"\n\
rust_toolchain_file_sha256 = \"{}\"\n\
source_tree_sha256 = \"{}\"\n\
dist_implementation_sha256 = \"{}\"\n\
llvm_prefix_tree_sha256 = \"{}\"\n\
qemu_native_input_sha256 = \"{}\"\n\
qemu_bundle_tree_sha256 = \"{}\"\n\
runtime_object_sha256 = \"{}\"\n\
installation_tree_sha256 = \"{}\"\n\
installation_files = {}\n\
installation_bytes = {}\n\
archive_sha256 = \"{}\"\n\
archive_bytes = {}\n\
cargo_sha256 = \"{}\"\n\
rustc_sha256 = \"{}\"\n\
cargo_version_sha256 = \"{}\"\n\
rustc_version_sha256 = \"{}\"\n\
rust_sysroot_tree_sha256 = \"{}\"\n\
rust_sysroot_files = {}\n\
rust_sysroot_bytes = {}\n\
cargo_lock_sha256 = \"{}\"\n\
cargo_vendor_tree_sha256 = \"{}\"\n\
cargo_vendor_files = {}\n\
cargo_vendor_bytes = {}\n\
rust_license_tree_sha256 = \"{}\"\n\
rust_license_files = {}\n\
rust_license_bytes = {}\n\
frontend_build_a_sha256 = \"{}\"\n\
frontend_build_a_bytes = {}\n\
frontend_build_b_sha256 = \"{}\"\n\
frontend_build_b_bytes = {}\n\
backend_build_a_sha256 = \"{}\"\n\
backend_build_a_bytes = {}\n\
backend_build_b_sha256 = \"{}\"\n\
backend_build_b_bytes = {}\n\
installed_public_build_tree_sha256 = \"{}\"\n\
installed_public_build_files = {}\n\
installed_public_build_bytes = {}\n\
installed_public_test_tree_sha256 = \"{}\"\n\
installed_public_test_files = {}\n\
installed_public_test_bytes = {}\n\
extracted_public_build_tree_sha256 = \"{}\"\n\
extracted_public_build_files = {}\n\
extracted_public_build_bytes = {}\n\
extracted_public_test_tree_sha256 = \"{}\"\n\
extracted_public_test_files = {}\n\
extracted_public_test_bytes = {}\n\
runtime_boot_image_sha256 = \"{}\"\n\
runtime_boot_image_bytes = {}\n\
runtime_boot_frame_sha256 = \"{}\"\n\
runtime_boot_frame_bytes = {}\n\
installed_real_qemu_image_sha256 = \"{}\"\n\
installed_real_qemu_image_bytes = {}\n\
installed_real_qemu_report_sha256 = \"{}\"\n\
installed_real_qemu_report_bytes = {}\n\
installed_real_qemu_event_stream_sha256 = \"{}\"\n\
installed_real_qemu_event_stream_bytes = {}\n\
extracted_real_qemu_image_sha256 = \"{}\"\n\
extracted_real_qemu_image_bytes = {}\n\
extracted_real_qemu_report_sha256 = \"{}\"\n\
extracted_real_qemu_report_bytes = {}\n\
extracted_real_qemu_event_stream_sha256 = \"{}\"\n\
extracted_real_qemu_event_stream_bytes = {}\n\
installed_stdlib_time_source_sha256 = \"{}\"\n\
installed_stdlib_time_source_bytes = {}\n\
installed_stdlib_time_manifest_sha256 = \"{}\"\n\
installed_stdlib_time_manifest_bytes = {}\n\
installed_stdlib_time_lock_sha256 = \"{}\"\n\
installed_stdlib_time_lock_bytes = {}\n\
installed_stdlib_time_pass_image_sha256 = \"{}\"\n\
installed_stdlib_time_pass_image_bytes = {}\n\
installed_stdlib_time_pass_report_sha256 = \"{}\"\n\
installed_stdlib_time_pass_report_bytes = {}\n\
installed_stdlib_time_pass_event_stream_sha256 = \"{}\"\n\
installed_stdlib_time_pass_event_stream_bytes = {}\n\
installed_stdlib_time_invalid_count_image_sha256 = \"{}\"\n\
installed_stdlib_time_invalid_count_image_bytes = {}\n\
installed_stdlib_time_invalid_count_report_sha256 = \"{}\"\n\
installed_stdlib_time_invalid_count_report_bytes = {}\n\
installed_stdlib_time_invalid_count_event_stream_sha256 = \"{}\"\n\
installed_stdlib_time_invalid_count_event_stream_bytes = {}\n\
extracted_stdlib_time_source_sha256 = \"{}\"\n\
extracted_stdlib_time_source_bytes = {}\n\
extracted_stdlib_time_manifest_sha256 = \"{}\"\n\
extracted_stdlib_time_manifest_bytes = {}\n\
extracted_stdlib_time_lock_sha256 = \"{}\"\n\
extracted_stdlib_time_lock_bytes = {}\n\
extracted_stdlib_time_pass_image_sha256 = \"{}\"\n\
extracted_stdlib_time_pass_image_bytes = {}\n\
extracted_stdlib_time_pass_report_sha256 = \"{}\"\n\
extracted_stdlib_time_pass_report_bytes = {}\n\
extracted_stdlib_time_pass_event_stream_sha256 = \"{}\"\n\
extracted_stdlib_time_pass_event_stream_bytes = {}\n\
extracted_stdlib_time_invalid_count_image_sha256 = \"{}\"\n\
extracted_stdlib_time_invalid_count_image_bytes = {}\n\
extracted_stdlib_time_invalid_count_report_sha256 = \"{}\"\n\
extracted_stdlib_time_invalid_count_report_bytes = {}\n\
extracted_stdlib_time_invalid_count_event_stream_sha256 = \"{}\"\n\
extracted_stdlib_time_invalid_count_event_stream_bytes = {}\n\
path_independent_source_roots = true\n\
path_independent_public_artifacts = true\n\
public_path_cleared = true\n\
installed_public_routes = true\n\
extracted_public_routes = true\n\
installed_real_qemu_smoke = true\n\
extracted_real_qemu_smoke = true\n\
installed_stdlib_time_real_qemu = true\n\
extracted_stdlib_time_real_qemu = true\n\
runtime_boot_smoke = true\n\
archive_clean_room = true\n",
        plan.release,
        plan.host,
        plan.rust_toolchain,
        plan.rust_output.rust_toolchain_sha256,
        plan.source.sha256,
        plan.dist_implementation_sha256,
        plan.llvm_prefix_tree_sha256,
        plan.emulation_output.native_input_sha256,
        plan.qemu.sha256,
        plan.runtime.object_sha256,
        installation.sha256,
        installation.files,
        installation.bytes,
        archive.sha256,
        archive.bytes,
        plan.tools.cargo_digest,
        plan.tools.rustc_digest,
        sha256_bytes(plan.tools.cargo_version.as_bytes()),
        sha256_bytes(plan.tools.rustc_version.as_bytes()),
        plan.rust_output.sysroot_tree_sha256,
        plan.rust_output.sysroot_files,
        plan.rust_output.sysroot_bytes,
        plan.cargo_output.cargo_lock_sha256,
        plan.cargo_output.vendor_tree_sha256,
        plan.cargo_output.vendor_files,
        plan.cargo_output.vendor_bytes,
        plan.rust_licenses.sha256,
        plan.rust_licenses.files,
        plan.rust_licenses.bytes,
        evidence.frontend_a.sha256,
        evidence.frontend_a.bytes,
        evidence.frontend_b.sha256,
        evidence.frontend_b.bytes,
        evidence.backend_a.sha256,
        evidence.backend_a.bytes,
        evidence.backend_b.sha256,
        evidence.backend_b.bytes,
        evidence.installed_public.build.sha256,
        evidence.installed_public.build.files,
        evidence.installed_public.build.bytes,
        evidence.installed_public.test.sha256,
        evidence.installed_public.test.files,
        evidence.installed_public.test.bytes,
        evidence.extracted_public.build.sha256,
        evidence.extracted_public.build.files,
        evidence.extracted_public.build.bytes,
        evidence.extracted_public.test.sha256,
        evidence.extracted_public.test.files,
        evidence.extracted_public.test.bytes,
        evidence.runtime_boot.image.sha256,
        evidence.runtime_boot.image.bytes,
        evidence.runtime_boot.frame_sha256,
        evidence.runtime_boot.frame_bytes,
        evidence.installed_real_qemu.image_sha256,
        evidence.installed_real_qemu.image_bytes,
        evidence.installed_real_qemu.report_sha256,
        evidence.installed_real_qemu.report_bytes,
        evidence.installed_real_qemu.event_stream_sha256,
        evidence.installed_real_qemu.event_stream_bytes,
        evidence.extracted_real_qemu.image_sha256,
        evidence.extracted_real_qemu.image_bytes,
        evidence.extracted_real_qemu.report_sha256,
        evidence.extracted_real_qemu.report_bytes,
        evidence.extracted_real_qemu.event_stream_sha256,
        evidence.extracted_real_qemu.event_stream_bytes,
        evidence.installed_stdlib_time_qemu.source.sha256,
        evidence.installed_stdlib_time_qemu.source.bytes,
        evidence.installed_stdlib_time_qemu.manifest.sha256,
        evidence.installed_stdlib_time_qemu.manifest.bytes,
        evidence.installed_stdlib_time_qemu.lock.sha256,
        evidence.installed_stdlib_time_qemu.lock.bytes,
        evidence.installed_stdlib_time_qemu.pass.image_sha256,
        evidence.installed_stdlib_time_qemu.pass.image_bytes,
        evidence.installed_stdlib_time_qemu.pass.report_sha256,
        evidence.installed_stdlib_time_qemu.pass.report_bytes,
        evidence.installed_stdlib_time_qemu.pass.event_stream_sha256,
        evidence.installed_stdlib_time_qemu.pass.event_stream_bytes,
        evidence
            .installed_stdlib_time_qemu
            .invalid_count
            .image_sha256,
        evidence
            .installed_stdlib_time_qemu
            .invalid_count
            .image_bytes,
        evidence
            .installed_stdlib_time_qemu
            .invalid_count
            .report_sha256,
        evidence
            .installed_stdlib_time_qemu
            .invalid_count
            .report_bytes,
        evidence
            .installed_stdlib_time_qemu
            .invalid_count
            .event_stream_sha256,
        evidence
            .installed_stdlib_time_qemu
            .invalid_count
            .event_stream_bytes,
        evidence.extracted_stdlib_time_qemu.source.sha256,
        evidence.extracted_stdlib_time_qemu.source.bytes,
        evidence.extracted_stdlib_time_qemu.manifest.sha256,
        evidence.extracted_stdlib_time_qemu.manifest.bytes,
        evidence.extracted_stdlib_time_qemu.lock.sha256,
        evidence.extracted_stdlib_time_qemu.lock.bytes,
        evidence.extracted_stdlib_time_qemu.pass.image_sha256,
        evidence.extracted_stdlib_time_qemu.pass.image_bytes,
        evidence.extracted_stdlib_time_qemu.pass.report_sha256,
        evidence.extracted_stdlib_time_qemu.pass.report_bytes,
        evidence.extracted_stdlib_time_qemu.pass.event_stream_sha256,
        evidence.extracted_stdlib_time_qemu.pass.event_stream_bytes,
        evidence
            .extracted_stdlib_time_qemu
            .invalid_count
            .image_sha256,
        evidence
            .extracted_stdlib_time_qemu
            .invalid_count
            .image_bytes,
        evidence
            .extracted_stdlib_time_qemu
            .invalid_count
            .report_sha256,
        evidence
            .extracted_stdlib_time_qemu
            .invalid_count
            .report_bytes,
        evidence
            .extracted_stdlib_time_qemu
            .invalid_count
            .event_stream_sha256,
        evidence
            .extracted_stdlib_time_qemu
            .invalid_count
            .event_stream_bytes,
    ))
}

fn validate_release_receipt_schema(receipt: &str) -> Result<(), String> {
    let expected = format!("schema = {RELEASE_RECEIPT_SCHEMA}");
    let mut lines = receipt.lines();
    if receipt.is_empty()
        || receipt.len() > usize::try_from(MAX_LOCK_BYTES).unwrap_or(usize::MAX)
        || !receipt.ends_with('\n')
        || receipt.contains('\r')
        || lines.next() != Some(expected.as_str())
        || receipt
            .lines()
            .filter(|line| line.starts_with("schema"))
            .count()
            != 1
    {
        return Err(format!(
            "release receipt is not exact-current schema {RELEASE_RECEIPT_SCHEMA}"
        ));
    }
    Ok(())
}

fn validate_existing_publication(
    published: &Path,
    expected_receipt: &str,
    archive_name: &str,
    installation: &TreeMeasurement,
    archive: &FileMeasurement,
) -> Result<(), String> {
    validate_release_receipt_schema(expected_receipt)?;
    let published = exact_directory(published, "published distribution")?;
    let names = bounded_directory_names(&published, 3, "published distribution")?;
    let mut expected = vec![
        "installation".to_owned(),
        "release.txt".to_owned(),
        archive_name.to_owned(),
    ];
    expected.sort_unstable();
    if names != expected {
        return Err("published distribution contains unexpected entries".to_owned());
    }
    let receipt = read_bounded_file(&published.join("release.txt"), MAX_LOCK_BYTES)?;
    if receipt != expected_receipt.as_bytes() {
        return Err("existing content-addressed distribution has a different receipt".to_owned());
    }
    validate_installation_tree(&published.join("installation"))?;
    require_same_tree(
        installation,
        &measure_tree(
            &published.join("installation"),
            MAX_TREE_FILES,
            MAX_TREE_BYTES,
        )?,
        "published installation",
    )?;
    if measure_file(&published.join(archive_name), MAX_TREE_BYTES, false)? != *archive {
        return Err("published archive differs from its tested measurement".to_owned());
    }
    Ok(())
}

fn prepare_output_root(path: &Path) -> Result<(), String> {
    let path = normalized_absolute(path, "distribution output")?;
    reject_existing_symlink_components(&path)?;
    let mut missing = Vec::new();
    let mut cursor = path.as_path();
    loop {
        match fs::symlink_metadata(cursor) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(format!(
                        "distribution output ancestor is not a directory: {}",
                        cursor.display()
                    ));
                }
                let canonical = fs::canonicalize(cursor).map_err(|error| {
                    format!(
                        "cannot canonicalize distribution output ancestor {}: {error}",
                        cursor.display()
                    )
                })?;
                if canonical != cursor {
                    return Err(format!(
                        "distribution output ancestor is not canonical: {}",
                        cursor.display()
                    ));
                }
                sync_directory(cursor)?;
                if let Some(parent) = cursor.parent() {
                    sync_directory(parent)?;
                }
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(cursor.to_path_buf());
                cursor = cursor.parent().ok_or_else(|| {
                    "distribution output has no existing filesystem ancestor".to_owned()
                })?;
            }
            Err(error) => {
                return Err(format!(
                    "cannot inspect distribution output ancestor {}: {error}",
                    cursor.display()
                ));
            }
        }
    }
    missing.reverse();
    for directory in missing {
        match fs::create_dir(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let metadata = stable_metadata(&directory, "concurrent distribution output")?;
                if !metadata.is_dir() {
                    return Err(format!(
                        "concurrent distribution output is not a directory: {}",
                        directory.display()
                    ));
                }
            }
            Err(error) => {
                return Err(format!(
                    "cannot create distribution output {}: {error}",
                    directory.display()
                ));
            }
        }
        set_mode(&directory, 0o700)?;
        sync_directory(&directory)?;
        let parent = directory
            .parent()
            .ok_or_else(|| "distribution output directory has no parent".to_owned())?;
        sync_directory(parent)?;
    }
    let metadata = stable_metadata(&path, "distribution output")?;
    if !metadata.is_dir() {
        return Err("distribution output is not a directory".to_owned());
    }
    validate_directory_mode(&path, &metadata)?;
    let canonical = fs::canonicalize(&path)
        .map_err(|error| format!("cannot canonicalize distribution output: {error}"))?;
    if canonical != path {
        return Err("distribution output is not a canonical path".to_owned());
    }
    sync_directory(&path)?;
    let parent = path
        .parent()
        .ok_or_else(|| "distribution output root has no parent".to_owned())?;
    sync_directory(parent)?;
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("private directory has no parent: {}", path.display()))?;
    if !parent.is_dir() {
        return Err(format!(
            "private directory parent is absent: {}",
            parent.display()
        ));
    }
    fs::create_dir(path).map_err(|error| {
        format!(
            "cannot create private directory {}: {error}",
            path.display()
        )
    })?;
    set_mode(path, 0o700)
}

fn create_private_directory_chain(path: &Path) -> Result<(), String> {
    if path.exists() {
        let metadata = stable_metadata(path, "private directory")?;
        if !metadata.is_dir() {
            return Err(format!("{} is not a directory", path.display()));
        }
        validate_directory_mode(path, &metadata)?;
        return Ok(());
    }
    let parent = path
        .parent()
        .ok_or_else(|| format!("directory has no parent: {}", path.display()))?;
    create_private_directory_chain(parent)?;
    match fs::create_dir(path) {
        Ok(()) => set_mode(path, 0o700),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = stable_metadata(path, "private directory")?;
            if metadata.is_dir() {
                validate_directory_mode(path, &metadata)
            } else {
                Err(format!("{} is not a directory", path.display()))
            }
        }
        Err(error) => Err(format!(
            "cannot create directory {}: {error}",
            path.display()
        )),
    }
}

fn exact_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    let path = normalized_absolute(path, label)?;
    let metadata = stable_metadata(&path, label)?;
    if !metadata.is_dir() {
        return Err(format!("{label} {} is not a directory", path.display()));
    }
    validate_directory_mode(&path, &metadata)?;
    let canonical = fs::canonicalize(&path)
        .map_err(|error| format!("cannot canonicalize {label} {}: {error}", path.display()))?;
    if canonical != path {
        return Err(format!("{label} {} is not canonical", path.display()));
    }
    Ok(path)
}

fn exact_file(path: &Path, label: &str) -> Result<PathBuf, String> {
    let path = normalized_absolute(path, label)?;
    let metadata = stable_metadata(&path, label)?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err(format!("{label} {} is not a nonempty file", path.display()));
    }
    let executable = executable_mode(&path, &metadata)?;
    validate_file_mode(&path, &metadata, executable)?;
    let canonical = fs::canonicalize(&path)
        .map_err(|error| format!("cannot canonicalize {label} {}: {error}", path.display()))?;
    if canonical != path {
        return Err(format!("{label} {} is not canonical", path.display()));
    }
    Ok(path)
}

fn normalized_absolute(path: &Path, label: &str) -> Result<PathBuf, String> {
    if !path.is_absolute() || path.as_os_str().as_encoded_bytes().len() > MAX_PATH_BYTES {
        return Err(format!("{label} must be a bounded absolute path"));
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir | Component::Normal(_) => {
                normalized.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if !matches!(
                    normalized.components().next_back(),
                    Some(Component::Normal(_))
                ) {
                    return Err(format!("{label} escapes its filesystem root"));
                }
                normalized.pop();
            }
        }
    }
    if normalized != path || normalized.components().count() <= 1 {
        return Err(format!("{label} is not normalized"));
    }
    Ok(normalized)
}

fn reject_existing_symlink_components(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!(
                    "path contains symlink component {}",
                    current.display()
                ));
            }
            Ok(metadata) => {
                if current != path && !metadata.is_dir() {
                    return Err(format!(
                        "path component is not a directory: {}",
                        current.display()
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(format!(
                    "cannot inspect path component {}: {error}",
                    current.display()
                ));
            }
        }
    }
    Ok(())
}

fn stable_metadata(path: &Path, label: &str) -> Result<fs::Metadata, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {label} {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!("{label} {} is a symlink", path.display()));
    }
    Ok(metadata)
}

#[cfg(unix)]
fn validate_file_mode(
    path: &Path,
    metadata: &fs::Metadata,
    require_executable: bool,
) -> Result<(), String> {
    let mode = metadata.mode();
    let executable = mode & 0o111;
    if mode & 0o7022 != 0
        || metadata.nlink() != 1
        || (require_executable && executable != 0o111)
        || (!require_executable && executable != 0)
    {
        return Err(format!(
            "file has unsafe mode or link count: {}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_file_mode(
    _path: &Path,
    _metadata: &fs::Metadata,
    _require_executable: bool,
) -> Result<(), String> {
    Err("distribution assembly has no reviewed non-Unix file-mode contract".to_owned())
}

#[cfg(unix)]
fn validate_directory_mode(path: &Path, metadata: &fs::Metadata) -> Result<(), String> {
    if metadata.mode() & 0o7022 != 0 {
        Err(format!("directory has unsafe mode: {}", path.display()))
    } else {
        Ok(())
    }
}

#[cfg(not(unix))]
fn validate_directory_mode(_path: &Path, _metadata: &fs::Metadata) -> Result<(), String> {
    Err("distribution assembly has no reviewed non-Unix directory-mode contract".to_owned())
}

#[cfg(unix)]
fn executable_mode(path: &Path, metadata: &fs::Metadata) -> Result<bool, String> {
    match metadata.mode() & 0o111 {
        0 => Ok(false),
        0o111 => Ok(true),
        _ => Err(format!(
            "file has nonportable executable mode: {}",
            path.display()
        )),
    }
}

#[cfg(not(unix))]
fn executable_mode(_path: &Path, _metadata: &fs::Metadata) -> Result<bool, String> {
    Err("distribution assembly has no reviewed non-Unix executable-mode contract".to_owned())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| format!("cannot set mode on {}: {error}", path.display()))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), String> {
    Err("distribution assembly has no reviewed non-Unix permission contract".to_owned())
}

#[cfg(unix)]
fn same_metadata(first: &fs::Metadata, second: &fs::Metadata) -> bool {
    first.file_type() == second.file_type()
        && first.dev() == second.dev()
        && first.ino() == second.ino()
        && first.len() == second.len()
        && first.mode() == second.mode()
        && first.mtime() == second.mtime()
        && first.mtime_nsec() == second.mtime_nsec()
}

#[cfg(not(unix))]
fn same_metadata(first: &fs::Metadata, second: &fs::Metadata) -> bool {
    first.file_type() == second.file_type()
        && first.len() == second.len()
        && first.modified().ok() == second.modified().ok()
}

fn portable_component(component: &str) -> bool {
    if component.is_empty()
        || component.len() > 255
        || matches!(component, "." | "..")
        || component.ends_with('.')
        || !component
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
    {
        return false;
    }
    let stem = component.split('.').next().unwrap_or(component);
    ![
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ]
    .iter()
    .any(|reserved| stem.eq_ignore_ascii_case(reserved))
}

fn portable_tree_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_PATH_BYTES
        && path.is_ascii()
        && !path.starts_with('/')
        && !path.ends_with('/')
        && path.split('/').all(portable_component)
}

fn sync_tree(root: &Path) -> Result<(), String> {
    let mut budget = TraversalBudget::new(MAX_TREE_ENTRIES)?;
    sync_tree_bounded(root, 0, &mut budget)
}

fn sync_tree_bounded(root: &Path, depth: u32, budget: &mut TraversalBudget) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err(format!("sync tree exceeds depth {MAX_DEPTH}"));
    }
    let metadata = stable_metadata(root, "sync tree")?;
    if metadata.is_file() {
        File::open(root)
            .and_then(|file| file.sync_all())
            .map_err(|error| format!("cannot sync {}: {error}", root.display()))?;
        return Ok(());
    }
    if !metadata.is_dir() {
        return Err(format!("cannot sync unsupported entry {}", root.display()));
    }
    for entry in fs::read_dir(root)
        .map_err(|error| format!("cannot enumerate {} for sync: {error}", root.display()))?
    {
        let entry = entry.map_err(|error| format!("cannot inspect sync entry: {error}"))?;
        budget.record_entry()?;
        sync_tree_bounded(&entry.path(), depth.saturating_add(1), budget)?;
    }
    sync_directory(root)
}

fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("cannot sync directory {}: {error}", path.display()))
}

fn require_same_tree(
    expected: &TreeMeasurement,
    actual: &TreeMeasurement,
    label: &str,
) -> Result<(), String> {
    if expected == actual {
        Ok(())
    } else {
        Err(format!(
            "{label} changed or differs from its exact measurement"
        ))
    }
}

fn update_length_prefixed(digest: &mut Sha256, value: &[u8]) -> Result<(), String> {
    let length = u64::try_from(value.len())
        .map_err(|_| "digest input length does not fit u64".to_owned())?;
    digest.update(length.to_le_bytes());
    digest.update(value);
    Ok(())
}

fn sha256_bytes(bytes: &[u8]) -> String {
    lower_hex(&Sha256::digest(bytes))
}

fn lower_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn hex_bytes(value: &str) -> Result<[u8; 32], String> {
    if !canonical_digest(value) {
        return Err("digest is not canonical lowercase hexadecimal".to_owned());
    }
    let mut bytes = [0u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("invalid hexadecimal nibble".to_owned()),
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, String> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| "truncated little-endian u16".to_owned())?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_i16(bytes: &[u8], offset: usize) -> Result<i16, String> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| "truncated little-endian i16".to_owned())?;
    Ok(i16::from_le_bytes([value[0], value[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, String> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| "truncated little-endian u32".to_owned())?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, String> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| "truncated little-endian u64".to_owned())?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

fn executable_name(stem: &str) -> String {
    if cfg!(windows) {
        format!("{stem}.exe")
    } else {
        stem.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDirectory {
        root: PathBuf,
    }

    impl TestDirectory {
        fn new(label: &str) -> Self {
            let base = fs::canonicalize(env::temp_dir()).expect("canonical temporary directory");
            for _ in 0..128 {
                let sequence = NEXT_STAGING.fetch_add(1, Ordering::Relaxed);
                let root = base.join(format!(
                    "wrela-dist-{label}-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&root) {
                    Ok(()) => {
                        set_mode(&root, 0o700).expect("private test mode");
                        return Self { root };
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("cannot create test directory: {error}"),
                }
            }
            panic!("cannot allocate test directory")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let mut directories = Vec::new();
            let _ = collect_directories(&self.root, &mut directories, 0);
            directories.sort_by_key(|path| path.components().count());
            for directory in directories {
                let _ = set_mode(&directory, 0o700);
            }
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn emulation_output() -> EmulationOutput {
        EmulationOutput {
            emulation_lock_sha256: "11".repeat(32),
            native_input_sha256: "22".repeat(32),
            qemu_version: "10.1.5".to_owned(),
            host: "aarch64-apple-darwin".to_owned(),
            bundle_tree_sha256: "33".repeat(32),
            bundle_files: 5,
            bundle_bytes: 123_456,
            qemu_sha256: "44".repeat(32),
            qemu_bytes: 100_000,
            firmware_code_sha256: "55".repeat(32),
            firmware_code_bytes: 4096,
            firmware_variables_sha256: "66".repeat(32),
            firmware_variables_bytes: 4096,
        }
    }

    fn fixture_file(byte: u8, bytes: u64) -> FileMeasurement {
        FileMeasurement {
            sha256: format!("{byte:02x}").repeat(32),
            bytes,
        }
    }

    fn fixture_real_qemu(byte: u8) -> RealQemuEvidence {
        RealQemuEvidence {
            image_sha256: format!("{byte:02x}").repeat(32),
            image_bytes: 4096 + u64::from(byte),
            report_sha256: format!("{:02x}", byte.saturating_add(1)).repeat(32),
            report_bytes: 512 + u64::from(byte),
            event_stream_sha256: format!("{:02x}", byte.saturating_add(2)).repeat(32),
            event_stream_bytes: 128 + u64::from(byte),
        }
    }

    fn fixture_stdlib_time_evidence() -> StdlibTimeQemuEvidence {
        StdlibTimeQemuEvidence {
            source: fixture_file(0x11, 701),
            manifest: fixture_file(0x22, 503),
            lock: fixture_file(0x33, 907),
            pass: fixture_real_qemu(0x44),
            invalid_count: fixture_real_qemu(0x55),
        }
    }

    fn fixture_checked_shift_evidence() -> CheckedShiftQemuEvidence {
        CheckedShiftQemuEvidence {
            pass: fixture_real_qemu(0x66),
            assertion_failure: fixture_real_qemu(0x70),
            result_loss: fixture_real_qemu(0x77),
            invalid_count: fixture_real_qemu(0x88),
        }
    }

    fn fixture_runtime_result_evidence() -> RuntimeResultQemuEvidence {
        RuntimeResultQemuEvidence {
            ok: fixture_real_qemu(0x91),
            propagated_err: fixture_real_qemu(0x99),
        }
    }

    fn fixture_current_tranche_integration_evidence() -> CurrentTrancheIntegrationEvidence {
        let common = fixture_integration_evidence();
        let mut evidence = CurrentTrancheIntegrationEvidence {
            source: common.source,
            qemu_bundle_sha256: common.qemu_bundle_sha256,
            qemu_native_input_sha256: common.qemu_native_input_sha256,
            installation: common.installation,
            frontend: common.frontend,
            backend: common.backend,
            run_binding_sha256: String::new(),
            qemu: CurrentTrancheQemuEvidence {
                timeout: fixture_real_qemu(0x41),
                stdlib_time: common.stdlib_time,
                checked_shift: common.checked_shift,
                runtime_result: fixture_runtime_result_evidence(),
            },
        };
        evidence.run_binding_sha256 = runtime_timeout_run_binding(
            &evidence.source,
            &evidence.installation,
            &evidence.frontend,
            &evidence.backend,
            &evidence.qemu_bundle_sha256,
            &evidence.qemu_native_input_sha256,
        )
        .expect("fixture current-tranche binding");
        evidence
    }

    fn checked_shift_line(selector: &str, outcome: &str, evidence: &RealQemuEvidence) -> String {
        format!(
            "WRELA_CHECKED_SHIFT_QEMU_EVIDENCE schema=1 selector={selector} outcome={outcome} image_sha256={} image_bytes={} report_sha256={} report_bytes={} event_stream_sha256={} event_stream_bytes={}\n",
            evidence.image_sha256,
            evidence.image_bytes,
            evidence.report_sha256,
            evidence.report_bytes,
            evidence.event_stream_sha256,
            evidence.event_stream_bytes,
        )
    }

    fn runtime_result_line(selector: &str, evidence: &RealQemuEvidence) -> String {
        format!(
            "WRELA_RUNTIME_RESULT_QEMU_EVIDENCE schema=1 selector={selector} outcome=passed image_sha256={} image_bytes={} report_sha256={} report_bytes={} event_stream_sha256={} event_stream_bytes={}\n",
            evidence.image_sha256,
            evidence.image_bytes,
            evidence.report_sha256,
            evidence.report_bytes,
            evidence.event_stream_sha256,
            evidence.event_stream_bytes,
        )
    }

    fn runtime_timeout_line(evidence: &RealQemuEvidence, run_binding_sha256: &str) -> String {
        format!(
            "WRELA_RUNTIME_TIMEOUT_QEMU_EVIDENCE schema=1 outcome=runtime-timeout timeout_ns=65000000000 run_binding_sha256={run_binding_sha256} image_sha256={} image_bytes={} report_sha256={} report_bytes={} event_stream_sha256={} event_stream_bytes={}\n",
            evidence.image_sha256,
            evidence.image_bytes,
            evidence.report_sha256,
            evidence.report_bytes,
            evidence.event_stream_sha256,
            evidence.event_stream_bytes,
        )
    }

    fn fixture_integration_evidence() -> QemuIntegrationEvidence {
        QemuIntegrationEvidence {
            source: TreeMeasurement {
                sha256: "91".repeat(32),
                files: 226,
                bytes: 10_000_000,
                records: Vec::new(),
            },
            qemu_bundle_sha256: "95".repeat(32),
            qemu_native_input_sha256: "96".repeat(32),
            installation: TreeMeasurement {
                sha256: "92".repeat(32),
                files: 149,
                bytes: 230_000_000,
                records: Vec::new(),
            },
            frontend: fixture_file(0x93, 3_500_000),
            backend: fixture_file(0x94, 44_000_000),
            bootstrap: fixture_real_qemu(0x31),
            stdlib_time: fixture_stdlib_time_evidence(),
            checked_shift: fixture_checked_shift_evidence(),
        }
    }

    fn fixture_runtime_timeout_integration_evidence() -> RuntimeTimeoutIntegrationEvidence {
        let mut evidence = RuntimeTimeoutIntegrationEvidence {
            source: TreeMeasurement {
                sha256: "91".repeat(32),
                files: 226,
                bytes: 10_000_000,
                records: Vec::new(),
            },
            qemu_bundle_sha256: "95".repeat(32),
            qemu_native_input_sha256: "96".repeat(32),
            installation: TreeMeasurement {
                sha256: "92".repeat(32),
                files: 149,
                bytes: 230_000_000,
                records: Vec::new(),
            },
            frontend: fixture_file(0x93, 3_500_000),
            backend: fixture_file(0x94, 44_000_000),
            run_binding_sha256: String::new(),
            timeout: fixture_real_qemu(0x41),
        };
        evidence.run_binding_sha256 = runtime_timeout_run_binding(
            &evidence.source,
            &evidence.installation,
            &evidence.frontend,
            &evidence.backend,
            &evidence.qemu_bundle_sha256,
            &evidence.qemu_native_input_sha256,
        )
        .expect("fixture runtime-timeout binding");
        evidence
    }

    fn event_preimage(frames: [&[u8]; 4]) -> Vec<u8> {
        let mut bytes = Vec::from(b"WRELEVS\0".as_slice());
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&4_u64.to_le_bytes());
        for frame in frames {
            bytes.extend_from_slice(
                &u64::try_from(frame.len())
                    .expect("fixture event frame fits u64")
                    .to_le_bytes(),
            );
            bytes.extend_from_slice(frame);
        }
        bytes
    }

    fn populate_stdlib_time_evidence(root: &Path, evidence_root: &Path) {
        for (relative, bytes) in [
            (
                "std/examples/stdlib-time-runtime/src/runtime/time_test.wr",
                b"module runtime.time_test\n".as_slice(),
            ),
            (
                "std/examples/stdlib-time-runtime/wrela.toml",
                b"schema = 1\n".as_slice(),
            ),
            (
                "std/examples/stdlib-time-runtime/wrela.lock",
                b"schema = 1\n[root]\n".as_slice(),
            ),
        ] {
            write_new_bytes(&root.join(relative), bytes, false)
                .expect("write stdlib-time source identity fixture");
        }
        create_private_directory(evidence_root).expect("create evidence export fixture");
        let events = event_preimage([b"first", b"second", b"third", b"fourth"]);
        for (relative, bytes) in [
            ("pass.efi", b"pass-efi".as_slice()),
            ("pass.report", b"pass-report".as_slice()),
            ("pass.events", events.as_slice()),
            ("invalid-count.efi", b"invalid-efi".as_slice()),
            ("invalid-count.report", b"invalid-report".as_slice()),
            ("invalid-count.events", events.as_slice()),
        ] {
            write_new_bytes(&evidence_root.join(relative), bytes, false)
                .expect("write stdlib-time runtime evidence fixture");
        }
    }

    fn stdlib_time_measurements(evidence: &StdlibTimeQemuEvidence) -> Vec<FileMeasurement> {
        vec![
            evidence.source.clone(),
            evidence.manifest.clone(),
            evidence.lock.clone(),
            FileMeasurement {
                sha256: evidence.pass.image_sha256.clone(),
                bytes: evidence.pass.image_bytes,
            },
            FileMeasurement {
                sha256: evidence.pass.report_sha256.clone(),
                bytes: evidence.pass.report_bytes,
            },
            FileMeasurement {
                sha256: evidence.pass.event_stream_sha256.clone(),
                bytes: evidence.pass.event_stream_bytes,
            },
            FileMeasurement {
                sha256: evidence.invalid_count.image_sha256.clone(),
                bytes: evidence.invalid_count.image_bytes,
            },
            FileMeasurement {
                sha256: evidence.invalid_count.report_sha256.clone(),
                bytes: evidence.invalid_count.report_bytes,
            },
            FileMeasurement {
                sha256: evidence.invalid_count.event_stream_sha256.clone(),
                bytes: evidence.invalid_count.event_stream_bytes,
            },
        ]
    }

    fn extend_final_event_frame(bytes: &mut Vec<u8>) {
        let mut cursor = 20_usize;
        let mut final_length = None;
        for index in 0..4 {
            let length_offset = cursor;
            let length = u64::from_le_bytes(
                bytes[cursor..cursor + 8]
                    .try_into()
                    .expect("fixture frame length"),
            );
            cursor += 8 + usize::try_from(length).expect("fixture frame extent");
            if index == 3 {
                final_length = Some((length_offset, length));
            }
        }
        assert_eq!(cursor, bytes.len());
        let (offset, length) = final_length.expect("fourth fixture frame");
        bytes[offset..offset + 8].copy_from_slice(&(length + 1).to_le_bytes());
        bytes.push(b'!');
    }

    fn populate_source_tree(root: &Path) {
        for file in [
            ".gitignore",
            "Cargo.toml",
            "Cargo.lock",
            ".cargo/config.toml",
            "LICENSE",
            "README.md",
            "rust-toolchain.toml",
            "rustfmt.toml",
        ] {
            write_new_bytes(&root.join(file), file.as_bytes(), false)
                .expect("write root policy input");
        }
        for tree in ["crates", "docs", "std", "tests", "toolchain", "xtask"] {
            write_new_bytes(&root.join(tree).join("fixture.txt"), tree.as_bytes(), false)
                .expect("write source-tree fixture");
        }
    }

    fn argument_strings(arguments: Vec<OsString>) -> Vec<String> {
        arguments
            .into_iter()
            .map(|argument| argument.into_string().expect("UTF-8 test argument"))
            .collect()
    }

    fn set_u32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn registry_lock(package: &str, version: &str, checksum: &str) -> Vec<u8> {
        format!(
            "# generated fixture\nversion = 4\n\n[[package]]\nname = \"workspace-member\"\nversion = \"0.1.0\"\n\n[[package]]\nname = \"{package}\"\nversion = \"{version}\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{checksum}\"\ndependencies = [\n \"workspace-member\",\n]\n"
        )
        .into_bytes()
    }

    fn synthetic_vendor(root: &Path, package: &CargoRegistryPackage) -> TreeMeasurement {
        let package_root = root.join(&package.directory);
        write_new_bytes(
            &package_root.join("src/lib.rs"),
            b"pub fn fixture() {}\n",
            false,
        )
        .expect("vendor source");
        let source_digest = sha256_bytes(b"pub fn fixture() {}\n");
        let checksum = format!(
            "{{\"files\":{{\"src/lib.rs\":\"{source_digest}\"}},\"package\":\"{}\"}}",
            package.checksum
        );
        write_new_bytes(
            &package_root.join(".cargo-checksum.json"),
            checksum.as_bytes(),
            false,
        )
        .expect("vendor checksum");
        seal_installation_directories(root).expect("seal vendor fixture");
        measure_closure_tree(root, MAX_TREE_FILES, MAX_TREE_BYTES).expect("vendor fixture tree")
    }

    fn populate_cargo_reuse_fixture(
        root: &Path,
        lock_checksum: &str,
        vendor_checksum: &str,
    ) -> (PathBuf, FileMeasurement, String) {
        let lock = registry_lock("fixture-crate", "1.2.3", lock_checksum);
        write_new_bytes(&root.join("Cargo.lock"), &lock, false).expect("current Cargo.lock");
        let current_lock_sha256 = sha256_bytes(&lock);
        let old_lock_sha256 = "11".repeat(32);
        let cargo_sha256 = "22".repeat(32);
        let vendor = root
            .join("build/toolchain/cargo/prefixes")
            .join(&old_lock_sha256)
            .join("vendor");
        create_private_directory_chain(&vendor).expect("old enrolled vendor root");
        let package = CargoRegistryPackage {
            directory: "fixture-crate-1.2.3".to_owned(),
            checksum: vendor_checksum.to_owned(),
        };
        let tree = synthetic_vendor(&vendor, &package);
        let output = CargoOutput {
            cargo_lock_sha256: old_lock_sha256,
            cargo_sha256: cargo_sha256.clone(),
            vendor_tree_sha256: tree.sha256,
            vendor_files: tree.files,
            vendor_bytes: tree.bytes,
        };
        write_new_bytes(
            &root.join("toolchain/cargo.outputs.toml"),
            encode_cargo_output(&output).as_bytes(),
            false,
        )
        .expect("old Cargo output enrollment");

        let rust_toolchain = b"[toolchain]\nchannel = \"1.95.0\"\n";
        write_new_bytes(&root.join("rust-toolchain.toml"), rust_toolchain, false)
            .expect("Rust toolchain fixture");
        let rust_output = RustOutput {
            rust_toolchain_sha256: sha256_bytes(rust_toolchain),
            channel: "1.95.0".to_owned(),
            host: host_identity().expect("reviewed test host"),
            cargo_sha256,
            cargo_bytes: 1,
            rustc_sha256: "33".repeat(32),
            rustc_bytes: 1,
            cargo_version_sha256: "44".repeat(32),
            rustc_version_sha256: "55".repeat(32),
            sysroot_tree_sha256: "66".repeat(32),
            sysroot_files: 1,
            sysroot_bytes: 1,
        };
        write_new_bytes(
            &root.join("toolchain/rust.outputs.toml"),
            encode_rust_output(&rust_output).as_bytes(),
            false,
        )
        .expect("Rust output enrollment fixture");

        let running = fs::canonicalize(env::current_exe().expect("current test executable"))
            .expect("canonical current test executable");
        let running_measurement =
            measure_file(&running, MAX_FILE_BYTES, true).expect("test executable measurement");
        (running, running_measurement, current_lock_sha256)
    }

    fn signed_macho(include_uuid: bool) -> Vec<u8> {
        let uuid_bytes = if include_uuid { 24usize } else { 0usize };
        let command_bytes = uuid_bytes + 16;
        let mut bytes = vec![0u8; 32 + command_bytes + 1];
        set_u32(&mut bytes, 0, 0xfeed_facf);
        set_u32(
            &mut bytes,
            4,
            if env::consts::ARCH == "aarch64" {
                0x0100_000c
            } else {
                0x0100_0007
            },
        );
        set_u32(&mut bytes, 16, if include_uuid { 2 } else { 1 });
        set_u32(
            &mut bytes,
            20,
            u32::try_from(command_bytes).expect("command bytes"),
        );
        let mut offset = 32usize;
        if include_uuid {
            set_u32(&mut bytes, offset, 0x1b);
            set_u32(&mut bytes, offset + 4, 24);
            offset += 24;
        }
        set_u32(&mut bytes, offset, 0x1d);
        set_u32(&mut bytes, offset + 4, 16);
        set_u32(
            &mut bytes,
            offset + 8,
            u32::try_from(32 + command_bytes).expect("signature offset"),
        );
        set_u32(&mut bytes, offset + 12, 1);
        *bytes.last_mut().expect("signature byte") = 0xfa;
        bytes
    }

    #[test]
    fn options_are_bounded_and_duplicate_free() {
        let options = parse_options(&[
            "--plan".to_owned(),
            "--jobs".to_owned(),
            "7".to_owned(),
            "--output".to_owned(),
            "release".to_owned(),
        ])
        .expect("valid options");
        assert!(options.plan);
        assert_eq!(options.mode(), DistExecutionMode::Plan);
        assert_eq!(options.jobs, 7);
        assert_eq!(options.output, Some(PathBuf::from("release")));
        let integration = parse_options(&[
            "--integration-qemu".to_owned(),
            "--jobs".to_owned(),
            "3".to_owned(),
        ])
        .expect("private QEMU integration options");
        assert_eq!(integration.mode(), DistExecutionMode::IntegrationQemu);
        assert_eq!(integration.integration_qemu_case, None);
        assert_eq!(integration.mode().build_lanes(), 1);
        assert!(!integration.mode().replays_public_or_archive_consumers());
        assert!(!integration.mode().publishes());
        let selected = parse_options(&[
            "--integration-qemu".to_owned(),
            "--integration-qemu-case".to_owned(),
            "runtime-timeout".to_owned(),
        ])
        .expect("selected QEMU integration options");
        assert_eq!(
            selected.integration_qemu_case,
            Some(IntegrationQemuCase::RuntimeTimeout)
        );
        let current = parse_options(&[
            "--integration-qemu".to_owned(),
            "--integration-qemu-case".to_owned(),
            "current-tranche".to_owned(),
        ])
        .expect("current-tranche QEMU integration options");
        assert_eq!(
            current.integration_qemu_case,
            Some(IntegrationQemuCase::CurrentTranche)
        );
        assert!(parse_options(&["--plan".to_owned(), "--plan".to_owned()]).is_err());
        assert!(
            parse_options(&[
                "--integration-qemu".to_owned(),
                "--integration-qemu".to_owned(),
            ])
            .is_err()
        );
        assert!(parse_options(&["--integration-qemu".to_owned(), "--plan".to_owned()]).is_err());
        assert!(
            parse_options(&[
                "--integration-qemu-case".to_owned(),
                "runtime-timeout".to_owned(),
            ])
            .is_err()
        );
        assert!(
            parse_options(&[
                "--integration-qemu".to_owned(),
                "--integration-qemu-case".to_owned(),
                "runtime-timeout".to_owned(),
                "--integration-qemu-case".to_owned(),
                "runtime-timeout".to_owned(),
            ])
            .is_err()
        );
        assert!(
            parse_options(&[
                "--integration-qemu".to_owned(),
                "--integration-qemu-case".to_owned(),
                "unknown".to_owned(),
            ])
            .is_err()
        );
        assert!(
            parse_options(&[
                "--integration-qemu".to_owned(),
                "--output".to_owned(),
                "release".to_owned(),
            ])
            .is_err()
        );
        assert!(parse_options(&["--jobs".to_owned(), (MAX_JOBS + 1).to_string(),]).is_err());
        assert!(parse_options(&["--unknown".to_owned()]).is_err());
    }

    #[test]
    fn distribution_policy_has_one_initial_and_one_prepublication_full_authority_scan() {
        let source = include_str!("dist.rs")
            .split_once("#[cfg(test)]\nmod tests {")
            .map(|(production, _)| production)
            .expect("production distribution source");
        assert_eq!(
            source
                .matches("llvm::verified_authority_for_distribution")
                .count(),
            1,
            "the sealed plan must perform exactly one initial full native scan"
        );
        assert_eq!(
            source.matches("revalidate_release_authority(").count(),
            2,
            "one definition and one prepublication full-rescan call are required"
        );
        assert_eq!(
            source
                .matches("llvm::verified_environment_for_full_route")
                .count(),
            0,
            "distribution must use the authority object rather than reopen LLVM planning"
        );
        let witness = source
            .split_once("fn revalidate_release_witness(")
            .and_then(|(_, tail)| tail.split_once("fn isolate_rust_tools("))
            .map(|(body, _)| body)
            .expect("bounded witness function source");
        assert!(witness.contains("llvm::revalidate_distribution_witness"));
        for forbidden in [
            "measure_closure_tree",
            "validate_qemu_bundle",
            "validate_rust_toolchain",
            "tool_version(",
        ] {
            assert!(
                !witness.contains(forbidden),
                "narrow witness unexpectedly replays {forbidden}"
            );
        }
    }

    #[test]
    fn checked_shift_qemu_command_is_exact_locked_offline_and_single_threaded() {
        let arguments = argument_strings(checked_shift_qemu_arguments(
            Path::new("/source"),
            Path::new("/private/target"),
            7,
        ));
        assert_eq!(
            arguments,
            [
                "test",
                "--locked",
                "--offline",
                "--manifest-path",
                "/source/Cargo.toml",
                "--color",
                "never",
                "--jobs",
                "7",
                "--target-dir",
                "/private/target",
                "-p",
                "wrela-test-runner",
                "--test",
                "real_qemu_smoke",
                "enrolled_bundle_executes_checked_shift_runtime_contract",
                "--",
                "--ignored",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ]
        );
        let current = argument_strings(current_tranche_qemu_arguments(
            Path::new("/source"),
            Path::new("/private/target"),
            7,
        ));
        let mut expected = arguments;
        expected[15] = "enrolled_bundle_executes_current_tranche_runtime_contract".to_owned();
        assert_eq!(current, expected);
    }

    #[test]
    fn runtime_timeout_qemu_command_is_exact_locked_offline_and_single_threaded() {
        let arguments = argument_strings(runtime_timeout_qemu_arguments(
            Path::new("/source"),
            Path::new("/private/target"),
            7,
        ));
        assert_eq!(
            arguments,
            [
                "test",
                "--locked",
                "--offline",
                "--manifest-path",
                "/source/Cargo.toml",
                "--color",
                "never",
                "--jobs",
                "7",
                "--target-dir",
                "/private/target",
                "-p",
                "wrela-test-runner",
                "--test",
                "real_qemu_smoke",
                "enrolled_bundle_executes_runtime_timeout_contract",
                "--",
                "--ignored",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ]
        );
    }

    #[test]
    fn runtime_timeout_qemu_evidence_is_exact_ordered_and_canonical() {
        let evidence = fixture_real_qemu(0x41);
        let run_binding = "97".repeat(32);
        let stdout = format!("noise\n{}", runtime_timeout_line(&evidence, &run_binding));
        assert_eq!(
            parse_runtime_timeout_qemu_evidence(stdout.as_bytes(), "fixture", &run_binding)
                .expect("canonical runtime-timeout evidence"),
            evidence
        );
        let at_limits = RealQemuEvidence {
            image_bytes: MAX_RUNTIME_TIMEOUT_IMAGE_BYTES,
            report_bytes: MAX_RUNTIME_TIMEOUT_REPORT_BYTES,
            event_stream_bytes: MAX_RUNTIME_TIMEOUT_EVENT_STREAM_BYTES,
            ..evidence.clone()
        };
        let at_limits_stdout = runtime_timeout_line(&at_limits, &run_binding);
        assert_eq!(
            parse_runtime_timeout_qemu_evidence(
                at_limits_stdout.as_bytes(),
                "fixture-at-limits",
                &run_binding,
            )
            .expect("runtime-timeout evidence at exact semantic maxima"),
            at_limits
        );
        let stale_binding = "98".repeat(32);
        for malformed in [
            "noise\n".to_owned(),
            format!("{stdout}{stdout}"),
            stdout.replacen("schema=1", "schema=2", 1),
            stdout.replacen("outcome=runtime-timeout", "outcome=passed", 1),
            stdout.replacen("timeout_ns=65000000000", "timeout_ns=64999999999", 1),
            stdout.replacen("image_bytes=4161", "image_bytes=0", 1),
            stdout.replacen("image_bytes=4161", "image_bytes=268435457", 1),
            stdout.replacen("report_bytes=577", "report_bytes=16777217", 1),
            stdout.replacen("event_stream_bytes=193", "event_stream_bytes=16777217", 1),
            stdout.replacen(&"41".repeat(32), &"AA".repeat(32), 1),
            stdout.replacen(&run_binding, &"AA".repeat(32), 1),
            stdout.replacen(&run_binding, &stale_binding, 1),
            stdout.replacen(" outcome=runtime-timeout", "  outcome=runtime-timeout", 1),
            stdout.replacen(
                " outcome=runtime-timeout timeout_ns=65000000000",
                " timeout_ns=65000000000 outcome=runtime-timeout",
                1,
            ),
            stdout.replacen(
                " outcome=runtime-timeout",
                " unknown=1 outcome=runtime-timeout",
                1,
            ),
            format!(
                "WRELA_RUNTIME_TIMEOUT_QEMU_EVIDENCE {}\n",
                "x".repeat(MAX_RUNTIME_TIMEOUT_EVIDENCE_LINE_BYTES)
            ),
        ] {
            assert!(
                parse_runtime_timeout_qemu_evidence(malformed.as_bytes(), "fixture", &run_binding)
                    .is_err(),
                "accepted malformed runtime-timeout evidence: {malformed}"
            );
        }
        assert!(
            parse_runtime_timeout_qemu_evidence(stdout.as_bytes(), "fixture", &stale_binding)
                .is_err()
        );
    }

    #[test]
    fn runtime_timeout_integration_evidence_is_bounded_path_free_and_complete() {
        let evidence = fixture_runtime_timeout_integration_evidence();
        let binding = runtime_timeout_run_binding(
            &evidence.source,
            &evidence.installation,
            &evidence.frontend,
            &evidence.backend,
            &evidence.qemu_bundle_sha256,
            &evidence.qemu_native_input_sha256,
        )
        .expect("canonical runtime-timeout binding");
        assert_eq!(binding, evidence.run_binding_sha256);
        let mut changed_source = evidence.source.clone();
        changed_source.files += 1;
        assert_ne!(
            runtime_timeout_run_binding(
                &changed_source,
                &evidence.installation,
                &evidence.frontend,
                &evidence.backend,
                &evidence.qemu_bundle_sha256,
                &evidence.qemu_native_input_sha256,
            )
            .expect("changed-source runtime-timeout binding"),
            binding
        );
        let first = encode_runtime_timeout_integration_evidence(&evidence)
            .expect("runtime-timeout integration evidence");
        let second = encode_runtime_timeout_integration_evidence(&evidence)
            .expect("repeat runtime-timeout integration evidence");
        assert_eq!(first, second);
        assert!(
            first.starts_with("WRELA_DIST_QEMU_RUNTIME_TIMEOUT_EVIDENCE schema=1 source_sha256=")
        );
        assert!(first.len() <= 2048);
        assert!(!first.contains('/') && !first.contains('\\'));
        for field in [
            "qemu_bundle_sha256=",
            "qemu_native_input_sha256=",
            "run_binding_sha256=",
            "outcome=runtime-timeout",
            "timeout_ns=65000000000",
            "image_sha256=",
            "report_sha256=",
            "event_stream_sha256=",
        ] {
            assert_eq!(first.matches(field).count(), 1, "missing {field}");
        }
        let mut bad_digest = evidence.clone();
        bad_digest.frontend.sha256.replace_range(..1, "A");
        assert!(encode_runtime_timeout_integration_evidence(&bad_digest).is_err());
        let mut stale_binding = evidence.clone();
        stale_binding.source.sha256 = "99".repeat(32);
        assert!(encode_runtime_timeout_integration_evidence(&stale_binding).is_err());
        let mut zero_extent = evidence;
        zero_extent.timeout.event_stream_bytes = 0;
        assert!(encode_runtime_timeout_integration_evidence(&zero_extent).is_err());
    }

    #[test]
    fn checked_shift_qemu_evidence_is_exact_ordered_and_canonical() {
        let evidence = fixture_checked_shift_evidence();
        let stdout = format!(
            "noise\n{}{}{}{}",
            checked_shift_line("modular_shift_passes", "passed", &evidence.pass),
            checked_shift_line(
                "runtime_assertion_fails",
                "assertion-failed",
                &evidence.assertion_failure,
            ),
            checked_shift_line(
                "checked_shift_result_loss",
                "checked-shift-result-loss",
                &evidence.result_loss,
            ),
            checked_shift_line(
                "invalid_shift_count",
                "invalid-shift-count",
                &evidence.invalid_count,
            ),
        );
        assert_eq!(
            parse_checked_shift_qemu_evidence(stdout.as_bytes(), "fixture")
                .expect("canonical checked-shift evidence"),
            evidence
        );
        let reordered = format!(
            "{}{}{}{}",
            checked_shift_line(
                "checked_shift_result_loss",
                "checked-shift-result-loss",
                &evidence.result_loss,
            ),
            checked_shift_line("modular_shift_passes", "passed", &evidence.pass),
            checked_shift_line(
                "runtime_assertion_fails",
                "assertion-failed",
                &evidence.assertion_failure,
            ),
            checked_shift_line(
                "invalid_shift_count",
                "invalid-shift-count",
                &evidence.invalid_count,
            ),
        );
        for malformed in [
            "noise\n".to_owned(),
            format!("{stdout}{stdout}"),
            reordered,
            stdout.replacen("schema=1", "schema=2", 1),
            stdout.replacen("selector=modular_shift_passes", "selector=other", 1),
            stdout.replacen("outcome=passed", "outcome=invalid-shift-count", 1),
            stdout.replacen("image_bytes=4198", "image_bytes=0", 1),
            stdout.replacen(&"66".repeat(32), &"AA".repeat(32), 1),
            stdout.replacen(" image_bytes=4198", "  image_bytes=4198", 1),
        ] {
            assert!(
                parse_checked_shift_qemu_evidence(malformed.as_bytes(), "fixture").is_err(),
                "accepted malformed checked-shift evidence: {malformed}"
            );
        }
    }

    #[test]
    fn runtime_result_qemu_evidence_is_exact_ordered_bounded_and_canonical() {
        let evidence = fixture_runtime_result_evidence();
        let first = runtime_result_line("result_try_ok_yields_payload", &evidence.ok);
        let second = runtime_result_line(
            "result_try_err_propagates_exact_error",
            &evidence.propagated_err,
        );
        let stdout = format!("noise\n{first}{second}");
        assert_eq!(
            parse_runtime_result_qemu_evidence(stdout.as_bytes(), "fixture")
                .expect("canonical runtime-result evidence"),
            evidence
        );
        let reordered = format!("{second}{first}");
        let duplicated = format!("{first}{second}{second}");
        let zero_extent = stdout.replacen(
            &format!("image_bytes={}", evidence.ok.image_bytes),
            "image_bytes=0",
            1,
        );
        let oversized_extent = stdout.replacen(
            &format!("image_bytes={}", evidence.ok.image_bytes),
            &format!("image_bytes={}", MAX_RUNTIME_TIMEOUT_IMAGE_BYTES + 1),
            1,
        );
        let oversized_line = format!(
            "WRELA_RUNTIME_RESULT_QEMU_EVIDENCE {}\n{second}",
            "x".repeat(1025)
        );
        for malformed in [
            "noise\n".to_owned(),
            duplicated,
            reordered,
            oversized_line,
            stdout.replacen("schema=1", "schema=2", 1),
            stdout.replacen(
                "selector=result_try_ok_yields_payload",
                "selector=result_try_err_propagates_exact_error",
                1,
            ),
            stdout.replacen("outcome=passed", "outcome=failed", 1),
            zero_extent,
            oversized_extent,
            stdout.replacen(&"91".repeat(32), &"AA".repeat(32), 1),
            stdout.replacen(" image_bytes=4241", "  image_bytes=4241", 1),
        ] {
            assert!(
                parse_runtime_result_qemu_evidence(malformed.as_bytes(), "fixture").is_err(),
                "accepted malformed runtime-result evidence: {malformed}"
            );
        }
    }

    #[test]
    fn integration_evidence_is_bounded_path_free_and_binds_every_qemu_case() {
        let evidence = fixture_integration_evidence();
        let first = encode_qemu_integration_evidence(&evidence).expect("integration evidence");
        let second = encode_qemu_integration_evidence(&evidence).expect("repeat evidence");
        assert_eq!(first, second);
        assert!(first.starts_with("WRELA_DIST_QEMU_INTEGRATION_EVIDENCE schema=1 "));
        assert!(first.len() <= 4096);
        assert!(!first.contains('/') && !first.contains('\\'));
        for field in [
            "qemu_bundle_sha256=",
            "qemu_native_input_sha256=",
            "bootstrap_image_sha256=",
            "stdlib_time_pass_image_sha256=",
            "stdlib_time_invalid_count_image_sha256=",
            "checked_shift_pass_image_sha256=",
            "checked_shift_assertion_failure_image_sha256=",
            "checked_shift_result_loss_image_sha256=",
            "checked_shift_invalid_count_image_sha256=",
        ] {
            assert_eq!(first.matches(field).count(), 1, "missing {field}");
        }
        let mut bad_digest = evidence.clone();
        bad_digest.frontend.sha256.replace_range(..1, "A");
        assert!(encode_qemu_integration_evidence(&bad_digest).is_err());
        let mut zero_extent = evidence;
        zero_extent.checked_shift.invalid_count.event_stream_bytes = 0;
        assert!(encode_qemu_integration_evidence(&zero_extent).is_err());
    }

    #[test]
    fn current_tranche_evidence_is_run_bound_ordered_bounded_and_complete() {
        let evidence = fixture_current_tranche_integration_evidence();
        let first = encode_current_tranche_integration_evidence(&evidence)
            .expect("current-tranche integration evidence");
        let second = encode_current_tranche_integration_evidence(&evidence)
            .expect("repeat current-tranche integration evidence");
        assert_eq!(first, second);
        assert!(first.starts_with("WRELA_DIST_QEMU_CURRENT_TRANCHE_EVIDENCE schema=2 "));
        assert!(first.len() <= 8192);
        assert!(!first.contains('/') && !first.contains('\\'));
        let mut cursor = 0;
        for field in [
            "runtime_timeout_image_sha256=",
            "stdlib_time_pass_image_sha256=",
            "stdlib_time_invalid_count_image_sha256=",
            "checked_shift_modular_assertion_pass_image_sha256=",
            "runtime_assertion_failure_image_sha256=",
            "checked_shift_result_loss_image_sha256=",
            "checked_shift_invalid_count_image_sha256=",
            "result_try_ok_yields_payload_image_sha256=",
            "result_try_err_propagates_exact_error_image_sha256=",
        ] {
            assert_eq!(first.matches(field).count(), 1, "missing {field}");
            let position = first.find(field).expect("ordered tranche evidence field");
            assert!(
                position > cursor,
                "tranche evidence field order changed at {field}"
            );
            cursor = position;
        }
        let mut stale = evidence.clone();
        stale.source.sha256 = "99".repeat(32);
        assert!(encode_current_tranche_integration_evidence(&stale).is_err());
        let mut zero = evidence.clone();
        zero.qemu.runtime_result.propagated_err.event_stream_bytes = 0;
        assert!(encode_current_tranche_integration_evidence(&zero).is_err());
        let mut over_limit = evidence.clone();
        over_limit.qemu.runtime_result.ok.report_bytes = MAX_RUNTIME_TIMEOUT_REPORT_BYTES + 1;
        assert!(encode_current_tranche_integration_evidence(&over_limit).is_err());
        let mut bad_digest = evidence;
        bad_digest
            .qemu
            .timeout
            .report_sha256
            .replace_range(..1, "A");
        assert!(encode_current_tranche_integration_evidence(&bad_digest).is_err());
    }

    #[test]
    fn private_integration_storage_is_removed_on_explicit_and_error_drop_cleanup() {
        let directory = TestDirectory::new("integration-cleanup");
        let mut explicit = PrivateStaging::create(&directory.root).expect("explicit staging");
        let explicit_path = explicit.path.clone();
        write_new_bytes(&explicit.path.join("private"), b"evidence", false)
            .expect("private evidence");
        destroy_private_staging(&mut explicit, "integration fixture")
            .expect("explicit integration cleanup");
        assert!(!explicit_path.exists());

        let dropped_path = {
            let dropped = PrivateStaging::create(&directory.root).expect("dropped staging");
            write_new_bytes(&dropped.path.join("private"), b"failure", false)
                .expect("failure fixture");
            dropped.path.clone()
        };
        assert!(!dropped_path.exists());
    }

    #[test]
    fn cargo_vendor_record_reuse_intent_is_explicit_and_tool_free() {
        let options = parse_cargo_vendor_options(&[
            "--record-output".to_owned(),
            "--reuse-enrolled".to_owned(),
        ])
        .expect("explicit offline reuse");
        assert!(options.record_output);
        assert!(options.reuse_enrolled);
        assert!(parse_cargo_vendor_options(&["--record-output".to_owned()]).is_err());
        assert!(parse_cargo_vendor_options(&["--reuse-enrolled".to_owned()]).is_err());
        assert!(
            parse_cargo_vendor_options(&[
                "--record-output".to_owned(),
                "--reuse-enrolled".to_owned(),
                "--cargo".to_owned(),
                "/bin/false".to_owned(),
            ])
            .is_err()
        );
    }

    #[test]
    fn cargo_enrollment_lease_blocks_concurrent_and_crashed_publishers() {
        let directory = TestDirectory::new("cargo-enrollment-lease");
        let checksum = "ab".repeat(32);
        let (_running, running_measurement, current_lock_sha256) =
            populate_cargo_reuse_fixture(&directory.root, &checksum, &checksum);
        let output_path = directory.root.join("toolchain/cargo.outputs.toml");
        let output_before =
            read_bounded_file(&output_path, MAX_LOCK_BYTES).expect("old enrollment bytes");
        let lease = CargoEnrollmentLease::acquire(&directory.root, &running_measurement)
            .expect("first exclusive lease");
        let concurrent_root = directory.root.clone();
        let concurrent_measurement = running_measurement.clone();
        let concurrent = std::thread::spawn(move || {
            CargoEnrollmentLease::acquire(&concurrent_root, &concurrent_measurement)
        })
        .join()
        .expect("concurrent lease thread");
        assert!(concurrent.is_err());
        assert_eq!(
            read_bounded_file(&output_path, MAX_LOCK_BYTES).expect("retained enrollment bytes"),
            output_before
        );
        assert!(
            !directory
                .root
                .join("build/toolchain/cargo/prefixes")
                .join(&current_lock_sha256)
                .exists(),
            "losing concurrent publisher must not create the new prefix"
        );
        lease.release().expect("release first lease");

        let crashed = CargoEnrollmentLease::acquire(&directory.root, &running_measurement)
            .expect("simulated crashed lease");
        std::mem::forget(crashed);
        assert!(CargoEnrollmentLease::acquire(&directory.root, &running_measurement).is_err());
        assert!(
            directory
                .root
                .join("toolchain/.cargo-vendor-enrollment.lock")
                .exists(),
            "a crash lease must remain fail-closed for explicit operator review"
        );
    }

    #[test]
    fn cargo_lock_registry_closure_is_exact_and_canonical() {
        let checksum = "ab".repeat(32);
        let packages =
            parse_cargo_registry_packages(&registry_lock("fixture-crate", "1.2.3+meta", &checksum))
                .expect("registry closure");
        assert_eq!(
            packages,
            [CargoRegistryPackage {
                directory: "fixture-crate-1.2.3+meta".to_owned(),
                checksum: checksum.clone(),
            }]
        );

        let duplicate = format!(
            "{}\n[[package]]\nname = \"fixture-crate\"\nversion = \"1.2.3+meta\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"{checksum}\"\n",
            String::from_utf8(registry_lock("fixture-crate", "1.2.3+meta", &checksum))
                .expect("UTF-8 lock")
                .trim_end()
        );
        assert!(parse_cargo_registry_packages(duplicate.as_bytes()).is_err());

        let unsupported = String::from_utf8(registry_lock("fixture-crate", "1.2.3", &checksum))
            .expect("UTF-8 lock")
            .replace(
                "registry+https://github.com/rust-lang/crates.io-index",
                "git+https://example.invalid/repository",
            );
        assert!(parse_cargo_registry_packages(unsupported.as_bytes()).is_err());

        let unknown_field = String::from_utf8(registry_lock("fixture-crate", "1.2.3", &checksum))
            .expect("UTF-8 lock")
            .replace(
                "dependencies = [",
                "future_format = \"forbidden\"\ndependencies = [",
            );
        assert!(parse_cargo_registry_packages(unknown_field.as_bytes()).is_err());

        let missing_checksum =
            String::from_utf8(registry_lock("fixture-crate", "1.2.3", &checksum))
                .expect("UTF-8 lock")
                .lines()
                .filter(|line| !line.starts_with("checksum = "))
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
        assert!(parse_cargo_registry_packages(missing_checksum.as_bytes()).is_err());

        let inline_dependencies =
            String::from_utf8(registry_lock("fixture-crate", "1.2.3", &checksum))
                .expect("UTF-8 lock")
                .replace(
                    "dependencies = [\n \"workspace-member\",\n]",
                    "dependencies = []",
                );
        assert!(parse_cargo_registry_packages(inline_dependencies.as_bytes()).is_err());

        let noncanonical_array_item =
            String::from_utf8(registry_lock("fixture-crate", "1.2.3", &checksum))
                .expect("UTF-8 lock")
                .replace(" \"workspace-member\",", " \"workspace-member\"");
        assert!(parse_cargo_registry_packages(noncanonical_array_item.as_bytes()).is_err());
    }

    #[test]
    fn checked_in_cargo_lock_registry_closure_is_bound() {
        let packages = parse_cargo_registry_packages(include_bytes!("../../Cargo.lock"))
            .expect("checked-in Cargo.lock closure");
        assert_eq!(packages.len(), 46);
        assert!(packages.iter().any(|package| {
            package.directory == "sha2-0.10.9"
                && package.checksum
                    == "a7507d819769d01a365ab707794a4084392c824f54a7a6a7862f8c3d0892b283"
        }));
        assert!(packages.iter().any(|package| {
            package.directory == "unicode-normalization-0.1.24"
                && package.checksum
                    == "5033c97c4262335cded6d6fc3e5c18ab755e1a3dc96376350f3d8e9f009ad956"
        }));
    }

    #[test]
    fn enrolled_vendor_reuse_proves_checksums_and_copies_without_links() {
        let directory = TestDirectory::new("cargo-vendor-reuse");
        let checksum = "cd".repeat(32);
        let packages =
            parse_cargo_registry_packages(&registry_lock("fixture-crate", "1.2.3", &checksum))
                .expect("registry closure");
        let vendor = directory.root.join("vendor-old");
        create_private_directory(&vendor).expect("old vendor root");
        let tree = synthetic_vendor(&vendor, &packages[0]);
        validate_cargo_registry_closure(&vendor, &tree, &packages).expect("exact vendor closure");

        let copy = directory.root.join("vendor-new");
        copy_exact_measured_tree(&vendor, &copy, &tree, "test Cargo vendor")
            .expect("exact no-follow copy");
        seal_installation_directories(&copy).expect("seal copied vendor");
        validate_sealed_installation_modes(&copy, &tree).expect("copied modes and link counts");
        require_same_tree(
            &tree,
            &measure_closure_tree(&copy, MAX_TREE_FILES, MAX_TREE_BYTES)
                .expect("copied vendor tree"),
            "copied vendor fixture",
        )
        .expect("byte-identical copied tree");
        #[cfg(unix)]
        assert_ne!(
            stable_metadata(
                &vendor.join("fixture-crate-1.2.3/src/lib.rs"),
                "old fixture",
            )
            .expect("old metadata")
            .ino(),
            stable_metadata(&copy.join("fixture-crate-1.2.3/src/lib.rs"), "new fixture",)
                .expect("new metadata")
                .ino(),
            "reuse copy must not hardlink"
        );

        let mut wrong = packages.clone();
        wrong[0].checksum = "ef".repeat(32);
        assert!(validate_cargo_registry_closure(&vendor, &tree, &wrong).is_err());
    }

    #[test]
    fn reused_vendor_root_recovers_only_the_exact_crash_mode() {
        let directory = TestDirectory::new("cargo-vendor-root-recovery");
        let checksum = "ab".repeat(32);
        let packages =
            parse_cargo_registry_packages(&registry_lock("fixture-crate", "1.2.3", &checksum))
                .expect("registry closure");
        let vendor = directory.root.join("vendor");
        create_private_directory(&vendor).expect("vendor root");
        let tree = synthetic_vendor(&vendor, &packages[0]);
        seal_installation_directories(&vendor).expect("seal vendor fixture");

        set_mode(&vendor, 0o700).expect("simulate crash between rename and root sealing");
        seal_reused_vendor_root(&vendor, &tree).expect("recover exact crash mode");
        validate_sealed_installation_modes(&vendor, &tree).expect("recovered vendor is sealed");

        set_mode(&vendor, 0o755).expect("simulate unreviewed mode drift");
        assert!(seal_reused_vendor_root(&vendor, &tree).is_err());
    }

    #[test]
    fn cargo_output_replacement_is_atomic_and_rejects_stale_authority() {
        let directory = TestDirectory::new("cargo-output-replace");
        let toolchain = directory.root.join("toolchain");
        create_private_directory(&toolchain).expect("toolchain directory");
        let path = toolchain.join("cargo.outputs.toml");
        let old = CargoOutput {
            cargo_lock_sha256: "11".repeat(32),
            cargo_sha256: "22".repeat(32),
            vendor_tree_sha256: "33".repeat(32),
            vendor_files: 7,
            vendor_bytes: 11,
        };
        write_new_bytes(&path, encode_cargo_output(&old).as_bytes(), false)
            .expect("old output enrollment");
        set_mode(&path, 0o644).expect("source enrollment mode");
        let mut old_measurement =
            measure_file(&path, MAX_LOCK_BYTES, false).expect("old measurement");
        let new = CargoOutput {
            cargo_lock_sha256: "44".repeat(32),
            ..old.clone()
        };
        assert!(
            replace_cargo_output_enrollment(&path, &old_measurement, &old, &new, &|| Err(
                "published vendor changed".to_owned()
            ),)
            .is_err()
        );
        assert_eq!(
            parse_cargo_output(
                &read_bounded_file(&path, MAX_LOCK_BYTES).expect("old bytes after guard failure")
            )
            .expect("old enrollment after guard failure"),
            old,
            "publication guard failure must precede the atomic lock replacement"
        );

        let independent = CargoOutput {
            cargo_lock_sha256: "66".repeat(32),
            ..old.clone()
        };
        let independent_bytes = encode_cargo_output(&independent);
        assert!(
            replace_cargo_output_enrollment(&path, &old_measurement, &old, &new, &|| {
                let mut authority = OpenOptions::new()
                    .write(true)
                    .truncate(true)
                    .open(&path)
                    .map_err(|error| format!("cannot simulate concurrent authority: {error}"))?;
                authority
                    .write_all(independent_bytes.as_bytes())
                    .and_then(|()| authority.sync_all())
                    .map_err(|error| format!("cannot sync concurrent authority: {error}"))?;
                Ok(())
            },)
            .is_err()
        );
        assert_eq!(
            parse_cargo_output(
                &read_bounded_file(&path, MAX_LOCK_BYTES).expect("independent authority bytes")
            )
            .expect("independent authority enrollment"),
            independent,
            "a concurrent independent authority must never be overwritten"
        );
        let old_bytes = encode_cargo_output(&old);
        let mut restored = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&path)
            .expect("open old authority restore");
        restored
            .write_all(old_bytes.as_bytes())
            .and_then(|()| restored.sync_all())
            .expect("restore old authority");
        drop(restored);
        old_measurement =
            measure_file(&path, MAX_LOCK_BYTES, false).expect("restored old authority measurement");
        replace_cargo_output_enrollment(&path, &old_measurement, &old, &new, &|| Ok(()))
            .expect("atomic replacement");
        assert_eq!(
            parse_cargo_output(&read_bounded_file(&path, MAX_LOCK_BYTES).expect("new bytes"))
                .expect("new enrollment"),
            new
        );

        let unexpected = CargoOutput {
            cargo_lock_sha256: "55".repeat(32),
            ..old.clone()
        };
        assert!(
            replace_cargo_output_enrollment(
                &path,
                &old_measurement,
                &old,
                &unexpected,
                &|| Ok(()),
            )
            .is_err()
        );
        assert_eq!(
            parse_cargo_output(&read_bounded_file(&path, MAX_LOCK_BYTES).expect("retained bytes"))
                .expect("retained enrollment"),
            new,
            "failed stale-authority replacement must preserve the visible enrollment"
        );
    }

    #[test]
    fn cargo_vendor_reenrollment_publishes_prefix_before_atomic_lock() {
        let directory = TestDirectory::new("cargo-reenroll-complete");
        let checksum = "ab".repeat(32);
        let (running, running_measurement, current_lock_sha256) =
            populate_cargo_reuse_fixture(&directory.root, &checksum, &checksum);
        let lease = CargoEnrollmentLease::acquire(&directory.root, &running_measurement)
            .expect("exclusive reenrollment lease");
        record_reused_cargo_vendor_with_guard(
            &directory.root,
            &running,
            &running_measurement,
            &lease,
            &|| Ok(()),
        )
        .expect("exact offline Cargo vendor reenrollment");
        lease.release().expect("release reenrollment lease");

        let output = parse_cargo_output(
            &read_bounded_file(
                &directory.root.join("toolchain/cargo.outputs.toml"),
                MAX_LOCK_BYTES,
            )
            .expect("new Cargo output bytes"),
        )
        .expect("new Cargo output enrollment");
        assert_eq!(output.cargo_lock_sha256, current_lock_sha256);
        let new_vendor = directory
            .root
            .join("build/toolchain/cargo/prefixes")
            .join(&current_lock_sha256)
            .join("vendor");
        let tree = measure_closure_tree(&new_vendor, MAX_TREE_FILES, MAX_TREE_BYTES)
            .expect("new vendor prefix exists before visible lock");
        validate_cargo_vendor_measurement(&tree, &output).expect("new prefix matches lock");
        validate_sealed_installation_modes(&new_vendor, &tree).expect("new prefix is sealed");
    }

    #[test]
    fn cargo_vendor_reenrollment_fails_before_publication_on_closure_drift() {
        let directory = TestDirectory::new("cargo-reenroll-fail-closed");
        let lock_checksum = "ab".repeat(32);
        let vendor_checksum = "cd".repeat(32);
        let (running, running_measurement, current_lock_sha256) =
            populate_cargo_reuse_fixture(&directory.root, &lock_checksum, &vendor_checksum);
        let output_path = directory.root.join("toolchain/cargo.outputs.toml");
        let before = read_bounded_file(&output_path, MAX_LOCK_BYTES).expect("old enrollment bytes");
        let lease = CargoEnrollmentLease::acquire(&directory.root, &running_measurement)
            .expect("exclusive reenrollment lease");
        assert!(
            record_reused_cargo_vendor_with_guard(
                &directory.root,
                &running,
                &running_measurement,
                &lease,
                &|| Ok(()),
            )
            .is_err()
        );
        lease.release().expect("release failed reenrollment lease");
        assert_eq!(
            read_bounded_file(&output_path, MAX_LOCK_BYTES).expect("retained enrollment bytes"),
            before
        );
        assert!(
            !directory
                .root
                .join("build/toolchain/cargo/prefixes")
                .join(current_lock_sha256)
                .exists(),
            "closure failure must precede creation of the new content-addressed prefix"
        );
    }

    #[test]
    fn runtime_boot_frames_are_exact_protocol_v3_stream_evidence() {
        assert_eq!(EXPECTED_SMOKE_FRAMES.len(), 4);
        for (sequence, frame) in EXPECTED_SMOKE_FRAMES.iter().enumerate() {
            assert_eq!(&frame[..8], b"WRELTST\0");
            assert_eq!(u32::from_le_bytes(frame[8..12].try_into().unwrap()), 1);
            assert_eq!(u32::from_le_bytes(frame[12..16].try_into().unwrap()), 3);
            assert_eq!(
                u64::from_le_bytes(frame[16..24].try_into().unwrap()),
                u64::try_from(sequence).unwrap()
            );
        }
        let frame_stream = EXPECTED_SMOKE_FRAMES.concat();
        assert_eq!(frame_stream.len(), 202);
        assert_eq!(
            sha256_bytes(&frame_stream),
            "35a25041f28500f5653bff29fdbcfe92e07e21e309a7ac1e05a54f9677288c20"
        );
    }

    #[test]
    fn runtime_boot_qemu_arguments_disable_the_uncontracted_default_nic() {
        let arguments = argument_strings(runtime_boot_qemu_arguments(
            "virt-10.0",
            "cortex-a57",
            "tcg,thread=single",
            Path::new("/private/QEMU_EFI.fd"),
            Path::new("/private/QEMU_VARS.fd"),
            Path::new("/private/esp"),
            Path::new("/private/serial.bin"),
        ));
        assert_eq!(
            arguments,
            [
                "-machine",
                "virt-10.0,gic-version=3,secure=off",
                "-cpu",
                "cortex-a57",
                "-accel",
                "tcg,thread=single",
                "-m",
                "512",
                "-smp",
                "1",
                "-nic",
                "none",
                "-drive",
                "if=pflash,format=raw,unit=0,readonly=on,file=/private/QEMU_EFI.fd",
                "-drive",
                "if=pflash,format=raw,unit=1,file=/private/QEMU_VARS.fd",
                "-drive",
                "if=none,format=raw,file=fat:rw:/private/esp,id=hd0",
                "-device",
                "virtio-blk-device,drive=hd0",
                "-serial",
                "file:/private/serial.bin",
                "-monitor",
                "none",
                "-display",
                "none",
                "-no-reboot",
            ]
        );
    }

    #[test]
    fn standalone_runtime_smoke_disables_the_uncontracted_default_nic() {
        let source = include_str!(
            "../../toolchain/targets/aarch64-qemu-virt-uefi/runtime-src/smoke_runtime.py"
        );
        assert_eq!(source.matches("\"-nic\", \"none\",").count(), 1);
        assert!(source.contains(
            "\"-smp\", \"1\",\n                    \"-nic\", \"none\",\n                    \"-drive\""
        ));
    }

    #[test]
    fn release_build_arguments_keep_frontend_features_isolated() {
        let manifest = Path::new("/lane/source/Cargo.toml");
        let target = Path::new("/lane/target");
        let frontend = argument_strings(release_build_arguments(
            manifest,
            target,
            7,
            ReleaseBuildProduct::Frontend,
        ));
        let backend = argument_strings(release_build_arguments(
            manifest,
            target,
            7,
            ReleaseBuildProduct::PrivateBackend,
        ));
        let common = [
            "rustc",
            "--locked",
            "--offline",
            "--manifest-path",
            "/lane/source/Cargo.toml",
            "--profile",
            "dist",
            "--jobs",
            "7",
            "--target-dir",
            "/lane/target",
        ];
        assert_eq!(&frontend[..common.len()], common);
        assert_eq!(&backend[..common.len()], common);
        assert_eq!(
            &frontend[common.len()..],
            [
                "-p",
                "wrela-cli",
                "--bin",
                "wrela",
                "--",
                "-Clink-arg=-Wl,-reproducible",
                "-Clink-arg=-Wl,-no_uuid",
            ]
        );
        assert_eq!(
            &backend[common.len()..],
            [
                "-p",
                "wrela-backend",
                "--bin",
                "wrela-backend",
                "--features",
                "wrela-backend/bundled-backend",
                "--",
                "-Clink-arg=-Wl,-reproducible",
                "-Clink-arg=-Wl,-no_uuid",
            ]
        );
        assert!(!frontend.iter().any(|argument| argument == "--features"));
        for arguments in [&frontend, &backend] {
            assert_eq!(
                &arguments[arguments.len() - 3..],
                [
                    "--",
                    "-Clink-arg=-Wl,-reproducible",
                    "-Clink-arg=-Wl,-no_uuid",
                ]
            );
        }
    }

    #[test]
    fn global_cargo_rustflags_exclude_executable_only_macho_policy() {
        let flags = encoded_cargo_rustflags(
            Path::new("/lane/source"),
            Path::new("/lane/target"),
            Path::new("/lane/work"),
            Path::new("/native/clang"),
            Path::new("/native/SDK"),
        );
        let fields = flags.split('\x1f').collect::<Vec<_>>();
        assert_eq!(
            fields,
            [
                "--remap-path-prefix=/lane/source=/wrela/source",
                "--remap-path-prefix=/lane/target=/wrela/build",
                "--remap-path-prefix=/lane/work=/wrela/private",
                "-Clinker=/native/clang",
                "-Clink-arg=-isysroot",
                "-Clink-arg=/native/SDK",
                "-Clink-arg=-mmacosx-version-min=13.0",
            ]
        );
        for executable_only in ["-Clink-arg=-Wl,-reproducible", "-Clink-arg=-Wl,-no_uuid"] {
            assert!(!fields.contains(&executable_only));
        }
    }

    #[test]
    fn release_outputs_are_frozen_before_their_owned_cargo_target_is_retired() {
        let directory = TestDirectory::new("frozen-release-outputs");
        let release_target = directory.root.join("release-target");
        let frontend = release_target.join("dist/wrela");
        let backend = release_target.join("dist/wrela-backend");
        let shim = release_target.join("dist/build/wrela-lld-sys-fixture/out/libwrela_lld_shim.a");
        write_new_bytes(&frontend, b"frontend", true).expect("write frontend");
        write_new_bytes(&backend, b"backend", true).expect("write backend");
        write_new_bytes(&shim, b"shim", false).expect("write shim");
        let measurements = (
            measure_file(&frontend, MAX_FILE_BYTES, true).expect("measure frontend"),
            measure_file(&backend, MAX_FILE_BYTES, true).expect("measure backend"),
        );

        let frozen = freeze_release_outputs(
            &(frontend, backend),
            &measurements,
            &release_target,
            &directory.root.join("frozen"),
        )
        .expect("freeze exact release consumers");
        retire_owned_cargo_target(&release_target, &directory.root, "fixture release target")
            .expect("retire release target");

        assert!(!release_target.exists());
        assert_eq!(
            measure_file(&frozen.0, MAX_FILE_BYTES, true).expect("frozen frontend"),
            measurements.0
        );
        assert_eq!(
            measure_file(&frozen.1, MAX_FILE_BYTES, true).expect("frozen backend"),
            measurements.1
        );
        assert_eq!(
            read_bounded_file(&frozen.2, MAX_FILE_BYTES).expect("frozen shim"),
            b"shim"
        );
        exact_measured_frozen_lld_shim(&frozen.2, &frozen.3)
            .expect("unchanged frozen shim remains authenticated");
        set_mode(&frozen.2, 0o600).expect("make frozen shim mutable for corruption fixture");
        fs::write(&frozen.2, b"evil").expect("corrupt frozen shim");
        set_mode(&frozen.2, 0o444).expect("restore frozen shim mode");
        let error = exact_measured_frozen_lld_shim(&frozen.2, &frozen.3)
            .expect_err("changed frozen shim must be rejected");
        assert!(error.contains("changed after authentication"));
    }

    #[test]
    fn deployment_target_is_exact_across_dist_and_the_lld_shim_producer() {
        assert_eq!(MACOS_DEPLOYMENT_TARGET, "13.0");
        let build_script = include_str!("../../crates/wrela-lld-sys/build.rs");
        assert!(build_script.contains("const MACOS_DEPLOYMENT_TARGET: &str = \"13.0\";"));
        assert!(build_script.contains("\"MACOSX_DEPLOYMENT_TARGET\""));
        assert!(build_script.contains("-mmacosx-version-min={MACOS_DEPLOYMENT_TARGET}"));
    }

    #[test]
    fn macho_policy_forbids_uuid_and_requires_a_signature() {
        let directory = TestDirectory::new("macho-policy");
        let accepted = directory.root.join("signed-no-uuid");
        write_new_bytes(&accepted, &signed_macho(false), true).expect("write accepted Mach-O");
        inspect_macho_dependencies(&accepted).expect("signed UUID-free Mach-O");

        let rejected = directory.root.join("signed-with-uuid");
        write_new_bytes(&rejected, &signed_macho(true), true).expect("write rejected Mach-O");
        let error = inspect_macho_dependencies(&rejected).expect_err("UUID must be rejected");
        assert!(error.contains("LC_UUID"));

        let unsigned = directory.root.join("unsigned");
        let mut bytes = signed_macho(false);
        set_u32(&mut bytes, 32, 0x2);
        write_new_bytes(&unsigned, &bytes, true).expect("write unsigned Mach-O");
        let error = inspect_macho_dependencies(&unsigned).expect_err("signature must be required");
        assert!(error.contains("exactly one LC_CODE_SIGNATURE"));
    }

    #[test]
    fn path_independent_mismatch_reports_both_measurements() {
        let lane_a = FileMeasurement {
            sha256: "11".repeat(32),
            bytes: 101,
        };
        let lane_b = FileMeasurement {
            sha256: "22".repeat(32),
            bytes: 102,
        };
        assert_eq!(
            path_independent_build_mismatch("frontend", &lane_a, &lane_b),
            format!(
                "two clean path-independent frontend builds were not byte-identical: lane A sha256={} bytes=101; lane B sha256={} bytes=102",
                lane_a.sha256, lane_b.sha256
            )
        );
    }

    #[cfg(unix)]
    #[test]
    fn output_root_creation_seals_every_new_ancestor() {
        let directory = TestDirectory::new("output-root");
        let first = directory.root.join("first");
        let second = first.join("second");
        let output = second.join("output");
        prepare_output_root(&output).expect("create durable output root");
        prepare_output_root(&output).expect("reuse durable output root");

        for path in [first, second, output] {
            let metadata = stable_metadata(&path, "durable output fixture")
                .expect("inspect durable output fixture");
            assert!(metadata.is_dir());
            assert_eq!(metadata.mode() & 0o7777, 0o700);
        }
    }

    #[test]
    fn running_dist_implementation_is_current_and_substitution_sensitive() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask manifest has a workspace parent");
        let current = validate_dist_implementation(root)
            .expect("test binary was built from current distribution sources");
        assert!(canonical_digest(&current));
        assert_eq!(
            current,
            dist_implementation_digest(DIST_IMPLEMENTATION_INPUTS)
                .expect("embedded implementation identity")
        );

        let mut substituted = DIST_IMPLEMENTATION_INPUTS.to_vec();
        substituted[0].1 = b"substituted cargo configuration";
        assert_ne!(
            current,
            dist_implementation_digest(&substituted).expect("substituted identity")
        );
        substituted.swap(0, 1);
        assert!(dist_implementation_digest(&substituted).is_err());
    }

    #[test]
    fn emulation_output_codec_is_canonical_and_corruption_sensitive() {
        let output = emulation_output();
        let encoded = encode_emulation_output(&output);
        assert_eq!(
            parse_emulation_output(encoded.as_bytes()).expect("canonical output"),
            output
        );
        let noncanonical = encoded.replacen("schema = 1", "schema=1", 1);
        assert!(parse_emulation_output(noncanonical.as_bytes()).is_err());
        let uppercase = encoded.replacen(&"11".repeat(32), &"AA".repeat(32), 1);
        assert!(parse_emulation_output(uppercase.as_bytes()).is_err());
        let duplicate = format!("{encoded}schema = 1\n");
        assert!(parse_emulation_output(duplicate.as_bytes()).is_err());
    }

    #[test]
    fn rust_and_cargo_output_enrollments_are_exact_canonical_codecs() {
        let rust_bytes = include_bytes!("../../toolchain/rust.outputs.toml");
        let rust = parse_rust_output(rust_bytes).expect("checked-in Rust output enrollment");
        assert_eq!(encode_rust_output(&rust).as_bytes(), rust_bytes);
        let cargo_bytes = include_bytes!("../../toolchain/cargo.outputs.toml");
        let cargo =
            parse_cargo_output(cargo_bytes).expect("checked-in Cargo vendor output enrollment");
        assert_eq!(encode_cargo_output(&cargo).as_bytes(), cargo_bytes);

        let reordered = encode_rust_output(&rust).replacen(
            "schema = 1\nrust_toolchain_sha256",
            "rust_toolchain_sha256",
            1,
        ) + "schema = 1\n";
        assert!(parse_rust_output(reordered.as_bytes()).is_err());
        let commented = format!("# comment\n{}", encode_cargo_output(&cargo));
        assert!(parse_cargo_output(commented.as_bytes()).is_err());
        let zero = encode_cargo_output(&cargo).replace(
            &format!("vendor_files = {}", cargo.vendor_files),
            "vendor_files = 0",
        );
        assert!(parse_cargo_output(zero.as_bytes()).is_err());
        let uppercase = encode_rust_output(&rust).replacen(
            &rust.cargo_sha256,
            &rust.cargo_sha256.to_ascii_uppercase(),
            1,
        );
        assert!(parse_rust_output(uppercase.as_bytes()).is_err());
    }

    #[test]
    fn absolute_path_scan_catches_matches_across_read_boundaries() {
        let directory = TestDirectory::new("path-scan");
        let forbidden = PathBuf::from("/private/wrela/authority-root");
        let mut bytes = vec![b'x'; 65_530];
        bytes.extend_from_slice(forbidden.as_os_str().as_encoded_bytes());
        bytes.extend_from_slice(b"suffix");
        let leaking = directory.root.join("leaking.bin");
        write_new_bytes(&leaking, &bytes, false).expect("write leaking fixture");
        let measurement = measure_file(&leaking, MAX_FILE_BYTES, false).expect("measure leak");
        assert!(
            reject_embedded_paths_in_file(
                &leaking,
                &measurement,
                false,
                std::slice::from_ref(&forbidden),
                "leaking fixture",
            )
            .is_err()
        );

        let clean = directory.root.join("clean.bin");
        write_new_bytes(&clean, b"portable /wrela/source payload", false)
            .expect("write clean fixture");
        let measurement = measure_file(&clean, MAX_FILE_BYTES, false).expect("measure clean");
        reject_embedded_paths_in_file(&clean, &measurement, false, &[forbidden], "clean fixture")
            .expect("portable fixture has no leak");
    }

    #[cfg(unix)]
    #[test]
    fn acquired_vendor_modes_are_normalized_independently_of_umask() {
        let directory = TestDirectory::new("vendor-modes");
        let first = directory.root.join(CARGO_VENDOR_EXECUTABLE_PATHS[0]);
        let second = directory.root.join(CARGO_VENDOR_EXECUTABLE_PATHS[1]);
        let ordinary = directory.root.join("anyhow-1.0.103/LICENSE-APACHE");
        for (path, bytes) in [
            (&first, b"first".as_slice()),
            (&second, b"second".as_slice()),
            (&ordinary, b"ordinary".as_slice()),
        ] {
            write_new_bytes(path, bytes, false).expect("write raw acquired vendor fixture");
        }
        set_mode(&first, 0o600).expect("restrict first executable as if umask removed execute");
        set_mode(&second, 0o700).expect("restrict second executable");
        set_mode(&ordinary, 0o600).expect("restrict ordinary file");

        normalize_acquired_vendor_modes(&directory.root).expect("normalize acquired modes");
        assert_eq!(
            stable_metadata(&first, "first normalized file")
                .expect("first metadata")
                .mode()
                & 0o7777,
            0o555
        );
        assert_eq!(
            stable_metadata(&second, "second normalized file")
                .expect("second metadata")
                .mode()
                & 0o7777,
            0o555
        );
        assert_eq!(
            stable_metadata(&ordinary, "ordinary normalized file")
                .expect("ordinary metadata")
                .mode()
                & 0o7777,
            0o444
        );
        let tree = measure_closure_tree(&directory.root, MAX_TREE_FILES, MAX_TREE_BYTES)
            .expect("normalized vendor closure is measurable");
        validate_sealed_installation_modes(&directory.root, &tree)
            .expect("normalized vendor closure is sealed");
        set_mode(&ordinary, 0o644).expect("introduce owner-write drift");
        assert!(validate_sealed_installation_modes(&directory.root, &tree).is_err());

        let overflow = TestDirectory::new("vendor-entry-budget");
        for name in ["one", "two", "three"] {
            write_new_bytes(&overflow.root.join(name), b"x", false)
                .expect("write acquired-vendor traversal fixture");
        }
        let mut budget =
            TreeBudget::with_entry_limit(3, 16, 2).expect("tiny vendor traversal budget");
        let mut executables = BTreeSet::new();
        let error = normalize_acquired_vendor_directory(
            &overflow.root,
            "",
            0,
            &mut budget,
            &mut executables,
        )
        .expect_err("third acquired-vendor entry must exceed traversal budget");
        assert!(error.contains("traversal entry limit"));
    }

    #[test]
    fn private_cargo_config_uses_the_exact_absolute_vendor_directory() {
        let directory = TestDirectory::new("cargo-config");
        let cargo_home = directory.root.join("cargo-home");
        let vendor = cargo_home.join("vendor");
        create_private_directory(&cargo_home).expect("create private Cargo home fixture");
        create_private_directory(&vendor).expect("create private Cargo vendor fixture");
        let vendor = exact_directory(&vendor, "private Cargo vendor fixture")
            .expect("canonicalize private Cargo vendor fixture");
        let config = String::from_utf8(
            private_cargo_config(&cargo_home).expect("encode private Cargo configuration"),
        )
        .expect("private Cargo configuration is UTF-8");
        let vendor = vendor
            .to_str()
            .expect("private Cargo vendor fixture path is UTF-8");

        assert_eq!(config.matches("directory = ").count(), 1);
        assert!(config.contains(&format!("directory = \"{vendor}\"\n")));
        assert!(!config.contains("directory = \"vendor\""));
    }

    #[cfg(unix)]
    #[test]
    fn private_cargo_config_rejects_mode_and_link_drift() {
        let directory = TestDirectory::new("cargo-config-seal");
        let cargo_home = directory.root.join("cargo-home");
        let vendor = cargo_home.join("vendor");
        create_private_directory(&cargo_home).expect("create private Cargo home fixture");
        create_private_directory(&vendor).expect("create private Cargo vendor fixture");
        let config = private_cargo_config(&cargo_home).expect("encode private Cargo config");
        let config_path = cargo_home.join("config.toml");
        write_new_bytes(&config_path, &config, false).expect("write private Cargo config");
        validate_private_cargo_config(&cargo_home).expect("validate sealed private Cargo config");

        set_mode(&config_path, 0o644).expect("introduce owner-write drift");
        assert!(validate_private_cargo_config(&cargo_home).is_err());
        set_mode(&config_path, 0o444).expect("restore private Cargo config mode");
        let alias = cargo_home.join("config-alias.toml");
        fs::hard_link(&config_path, &alias).expect("introduce private Cargo config hard link");
        assert!(validate_private_cargo_config(&cargo_home).is_err());
    }

    #[test]
    fn checked_in_emulation_and_runtime_locks_decode() {
        let emulation = parse_emulation_lock(include_bytes!("../../toolchain/emulation.lock.toml"))
            .expect("checked-in emulation lock");
        assert_eq!(emulation.qemu_version, "10.1.5");
        assert_eq!(emulation.machine_contract, "virt-10.0");
        assert_eq!(emulation.cpu_contract, "cortex-a57");
        let runtime = parse_runtime_lock(include_bytes!(
            "../../toolchain/targets/aarch64-qemu-virt-uefi/runtime-src/runtime-object.lock.toml"
        ))
        .expect("checked-in runtime lock");
        assert_eq!(runtime.runtime_abi_version, 2);
        assert_eq!(
            runtime.compiler_identity,
            "Apple clang version 17.0.0 (clang-1700.6.4.2)"
        );
        assert_eq!(
            runtime.compiler_sha256,
            "15339439a6be4a9d33d281ec040a7e0092190b1c8d7de5f94d824b50ffae0769"
        );
        assert_eq!(runtime.coff_machine, "arm64");
        assert_eq!(runtime.undefined_symbols, 0);
    }

    #[test]
    fn emulation_enrollment_rejects_stale_lock_host_and_firmware() {
        let lock = parse_emulation_lock(include_bytes!("../../toolchain/emulation.lock.toml"))
            .expect("checked-in emulation lock");
        let mut output = emulation_output();
        output.emulation_lock_sha256.clone_from(&lock.bytes_sha256);
        output.qemu_version.clone_from(&lock.qemu_version);
        output.host = "aarch64-apple-darwin".to_owned();
        output
            .firmware_code_sha256
            .clone_from(&lock.firmware_code.sha256);
        output
            .firmware_variables_sha256
            .clone_from(&lock.firmware_variables.sha256);
        validate_emulation_output(&lock, &output, "aarch64-apple-darwin")
            .expect("current enrollment");
        output.host = "x86_64-apple-darwin".to_owned();
        assert!(validate_emulation_output(&lock, &output, "aarch64-apple-darwin").is_err());
        output.host = "aarch64-apple-darwin".to_owned();
        output.firmware_code_sha256 = "aa".repeat(32);
        assert!(validate_emulation_output(&lock, &output, "aarch64-apple-darwin").is_err());
    }

    #[test]
    fn standard_library_identity_matches_the_checked_in_lock() {
        let manifest = include_bytes!("../../std/wrela-core-0.1/wrela.toml");
        let image = include_bytes!("../../std/wrela-core-0.1/src/image.wr");
        let result = include_bytes!("../../std/wrela-core-0.1/src/result.wr");
        let time = include_bytes!("../../std/wrela-core-0.1/src/time.wr");
        assert_eq!(manifest.len(), 638);
        assert_eq!(image.len(), 121);
        assert_eq!(result.len(), 61);
        assert_eq!(time.len(), 6_272);
        assert_eq!(
            manifest.len() + image.len() + result.len() + time.len(),
            7_092
        );
        assert_eq!(sha256_bytes(manifest), CORE_MANIFEST_SHA256);
        assert_eq!(
            sha256_bytes(image),
            "c9d457e958fc45c2e9098f1462da18c0e793d580a95cbc0025ecccc49e61064f"
        );
        assert_eq!(
            sha256_bytes(result),
            "95fd19e15b8d989b90f0ec8dedaae6446ebc3f29df59934a61c51fc034e134a3"
        );
        assert_eq!(
            sha256_bytes(time),
            "dd55aead7b0501021fb35ff32fd694c88545236ec862ecbaafe7d872becda195"
        );
        let sources = [
            ("image.wr", image.as_slice()),
            ("result.wr", result.as_slice()),
            ("time.wr", time.as_slice()),
        ];
        let digest =
            package_source_digest(manifest, &sources).expect("canonical core package digest");
        assert_eq!(digest, CORE_SOURCE_DIGEST);
        assert!(package_source_digest(manifest, &sources[..1]).is_err());
        assert!(
            package_source_digest(manifest, &sources.iter().rev().copied().collect::<Vec<_>>())
                .is_err()
        );
        assert!(package_source_digest(manifest, &[sources[0], sources[0]]).is_err());
    }

    #[test]
    fn installed_core_inventory_is_exact_current() {
        let directory = TestDirectory::new("installed-core-inventory");
        let core = directory.root.join("share/wrela/std").join(CORE_COMPONENT);
        for (relative, bytes) in [
            (
                "wrela.toml",
                include_bytes!("../../std/wrela-core-0.1/wrela.toml").as_slice(),
            ),
            (
                "src/image.wr",
                include_bytes!("../../std/wrela-core-0.1/src/image.wr").as_slice(),
            ),
            (
                "src/result.wr",
                include_bytes!("../../std/wrela-core-0.1/src/result.wr").as_slice(),
            ),
            (
                "src/time.wr",
                include_bytes!("../../std/wrela-core-0.1/src/time.wr").as_slice(),
            ),
        ] {
            write_new_bytes(&core.join(relative), bytes, false).expect("core package fixture");
        }
        validate_installed_core_inventory(&directory.root).expect("exact current core inventory");
        write_new_bytes(&core.join("src/legacy.wr"), b"module legacy\n", false)
            .expect("unexpected legacy source");
        assert!(validate_installed_core_inventory(&directory.root).is_err());
    }

    #[test]
    fn installed_virtio_storage_inventory_is_exact_current() {
        let directory = TestDirectory::new("installed-virtio-storage-inventory");
        let appliance = directory.root.join("share/wrela/examples/virtio-storage");
        write_new_bytes(
            &appliance.join("virtio-storage.wr"),
            include_bytes!("../../docs/language/examples/virtio-storage.wr"),
            false,
        )
        .expect("installed appliance source fixture");
        write_new_bytes(
            &appliance.join("STATUS.md"),
            include_bytes!("../../docs/language/examples/virtio-storage-status.md"),
            false,
        )
        .expect("installed appliance status fixture");
        validate_installed_appliance_inventory(&directory.root)
            .expect("exact current appliance inventory");
        write_new_bytes(
            &appliance.join("undeclared.wr"),
            b"module undeclared\n",
            false,
        )
        .expect("unexpected appliance source");
        assert!(validate_installed_appliance_inventory(&directory.root).is_err());
    }

    #[test]
    fn release_tree_identity_binds_paths_lengths_contents_and_modes() {
        let first = finish_tree(
            vec![FileRecord {
                path: "bin/tool".to_owned(),
                bytes: 4,
                sha256: sha256_bytes(b"tool"),
                executable: true,
            }],
            4,
            1024,
        )
        .expect("first tree");
        let mut changed_mode = first.records.clone();
        changed_mode[0].executable = false;
        let changed_mode = finish_tree(changed_mode, 4, 1024).expect("mode tree");
        assert_ne!(first.sha256, changed_mode.sha256);
        let mut changed_path = first.records.clone();
        changed_path[0].path = "bin/other".to_owned();
        let changed_path = finish_tree(changed_path, 4, 1024).expect("path tree");
        assert_ne!(first.sha256, changed_path.sha256);
    }

    #[test]
    fn source_tree_identity_binds_docs_contracts_and_root_policy() {
        let directory = TestDirectory::new("source-tree");
        populate_source_tree(&directory.root);

        let first = measure_source_tree(&directory.root).expect("measure complete source tree");
        for required in [
            "README.md",
            "rust-toolchain.toml",
            "rustfmt.toml",
            "docs/fixture.txt",
            "tests/fixture.txt",
        ] {
            assert!(
                first.records.iter().any(|record| record.path == required),
                "source identity omitted {required}"
            );
        }

        write_new_bytes(
            &directory.root.join("docs/additional.md"),
            b"additional normative input",
            false,
        )
        .expect("add normative input");
        let changed = measure_source_tree(&directory.root).expect("remeasure changed source tree");
        assert_ne!(first.sha256, changed.sha256);

        create_private_directory(&directory.root.join("crates/empty"))
            .expect("create empty source directory");
        assert!(
            measure_source_tree(&directory.root)
                .expect_err("empty source directory must fail closed")
                .contains("empty directory")
        );
    }

    #[test]
    fn source_snapshot_copy_is_exact_across_distinct_paths() {
        let directory = TestDirectory::new("source-snapshot");
        let source = directory.root.join("source-a");
        create_private_directory(&source).expect("source root");
        populate_source_tree(&source);
        let expected = measure_source_tree(&source).expect("source identity");

        let independent = directory.root.join("different-length-parent");
        create_private_directory(&independent).expect("independent parent");
        let copied = independent.join("source-copy-b");
        copy_source_tree(&source, &copied, &expected).expect("exact isolated source copy");
        assert_ne!(source, copied);
        assert_eq!(
            measure_source_tree(&copied).expect("copied source identity"),
            expected
        );
    }

    #[test]
    fn tree_budget_enforces_aggregate_limits_before_another_file_read() {
        let mut byte_budget = TreeBudget::new(3, 7).expect("byte budget");
        assert_eq!(byte_budget.file_limit().expect("initial allowance"), 7);
        byte_budget.record_file(5).expect("first file");
        assert_eq!(byte_budget.file_limit().expect("remaining allowance"), 2);
        byte_budget.record_file(2).expect("exact aggregate limit");
        assert!(byte_budget.file_limit().is_err());

        let mut file_budget = TreeBudget::new(1, 100).expect("file budget");
        file_budget.record_file(1).expect("only file");
        assert!(file_budget.file_limit().is_err());
        assert!(TreeBudget::new(0, 1).is_err());
        assert!(TreeBudget::new(1, 0).is_err());

        let directory = TestDirectory::new("tree-entry-budget");
        for name in ["one", "two", "three"] {
            write_new_bytes(&directory.root.join(name), b"x", false)
                .expect("write traversal-budget fixture");
        }
        let mut records = Vec::new();
        let mut traversal_limited =
            TreeBudget::with_entry_limit(3, 16, 2).expect("tiny traversal budget");
        let error = walk_tree(
            &directory.root,
            "",
            0,
            &mut records,
            &mut traversal_limited,
            false,
        )
        .expect_err("third directory entry must exceed traversal budget");
        assert!(error.contains("traversal entry limit"));
        assert!(records.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn bounded_second_read_rejects_growth_before_appending_it() {
        let directory = TestDirectory::new("bounded-reread");
        let path = directory.root.join("input");
        write_new_bytes(&path, b"a", false).expect("write bounded-read fixture");
        let measurement = measure_file(&path, 8, false).expect("measure bounded-read fixture");
        set_mode(&path, 0o600).expect("make bounded-read fixture writable");
        let mut file = OpenOptions::new()
            .append(true)
            .open(&path)
            .expect("open bounded-read fixture for growth");
        file.write_all(b"b").expect("grow bounded-read fixture");
        file.sync_all().expect("sync bounded-read fixture growth");
        drop(file);
        set_mode(&path, 0o444).expect("reseal bounded-read fixture");

        let error = read_exact_measured_file(&path, &measurement)
            .expect_err("grown file must not exceed its measured allocation");
        assert!(error.contains("grew beyond its measured bounded extent"));
    }

    #[cfg(unix)]
    #[test]
    fn bounded_runner_closes_pipe_holding_descendants() {
        let mut command = Command::new("/bin/sh");
        command.env_clear().args(["-c", "/bin/sleep 60 & exit 0"]);
        let started = Instant::now();
        let output = run_command(&mut command, "pipe-holding descendant fixture", 10)
            .expect("runner terminates the private process group");
        assert!(output.status.success());
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn ignored_real_smoke_requires_exactly_one_executed_test() {
        let test = "enrolled_bundle_executes_real_qemu_lifecycle";
        let exact = format!(
            "\nrunning 1 test\ntest {test} ... \n\
             WRELA_REAL_QEMU_EVIDENCE schema=1 image_sha256={} image_bytes=1 report_sha256={} report_bytes=1 event_stream_sha256={} event_stream_bytes=1\n\
             ok\n\n\
             test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 12 filtered out\n",
            "11".repeat(32),
            "22".repeat(32),
            "33".repeat(32),
        );
        require_exact_test_execution(exact.as_bytes(), test, "fixture")
            .expect("one exact ignored test execution");
        for invalid in [
            "running 0 tests\ntest result: ok. 0 passed; 0 failed; 1 ignored;\n",
            "running 1 test\ntest other ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n",
            "running 1 test\ntest enrolled_bundle_executes_real_qemu_lifecycle ... failed\ntest result: FAILED. 0 passed; 1 failed; 0 ignored;\n",
        ] {
            assert!(require_exact_test_execution(invalid.as_bytes(), test, "fixture").is_err());
        }
    }

    #[test]
    fn real_qemu_evidence_line_is_exact_and_canonical() {
        let image = "aa".repeat(32);
        let report = "22".repeat(32);
        let events = "33".repeat(32);
        let line = format!(
            "noise\nWRELA_REAL_QEMU_EVIDENCE schema=1 image_sha256={image} image_bytes=4096 report_sha256={report} report_bytes=512 event_stream_sha256={events} event_stream_bytes=128\n"
        );
        assert_eq!(
            parse_real_qemu_evidence(line.as_bytes(), "fixture").expect("canonical evidence"),
            RealQemuEvidence {
                image_sha256: image.clone(),
                image_bytes: 4096,
                report_sha256: report.clone(),
                report_bytes: 512,
                event_stream_sha256: events.clone(),
                event_stream_bytes: 128,
            }
        );
        assert!(
            parse_real_qemu_evidence(line.replace("schema=1", "schema=2").as_bytes(), "fixture")
                .is_err()
        );
        assert!(
            parse_real_qemu_evidence(
                line.replace("image_bytes=4096", "image_bytes=0").as_bytes(),
                "fixture"
            )
            .is_err()
        );
        assert!(
            parse_real_qemu_evidence(
                line.replace(&image, &image.to_ascii_uppercase()).as_bytes(),
                "fixture"
            )
            .is_err()
        );
        let duplicate = format!("{line}{line}");
        assert!(parse_real_qemu_evidence(duplicate.as_bytes(), "fixture").is_err());
        for whitespace_drift in [
            line.replace(" image_bytes=4096", "  image_bytes=4096"),
            line.replace(" image_bytes=4096", "\timage_bytes=4096"),
            line.replace(" event_stream_bytes=128\n", " event_stream_bytes=128 \n"),
        ] {
            assert!(parse_real_qemu_evidence(whitespace_drift.as_bytes(), "fixture").is_err());
        }
    }

    #[test]
    fn stdlib_time_evidence_line_round_trips_and_rejects_missing_duplicate_trailing_or_malformed() {
        let evidence = fixture_stdlib_time_evidence();
        let payload = encode_stdlib_time_qemu_evidence(&evidence);
        let line = format!("noise\nWRELA_STDLIB_TIME_QEMU_EVIDENCE {payload}\n");
        assert_eq!(
            parse_stdlib_time_qemu_evidence(line.as_bytes(), "fixture")
                .expect("canonical stdlib-time evidence"),
            evidence
        );
        assert!(parse_stdlib_time_qemu_evidence(b"noise\n", "fixture").is_err());
        assert!(parse_stdlib_time_qemu_evidence(&[0xff], "fixture").is_err());
        assert!(
            parse_stdlib_time_qemu_evidence(format!("{line}{line}").as_bytes(), "fixture").is_err()
        );
        for collision in [
            format!("{line}WRELA_STDLIB_TIME_QEMU_EVIDENCEX schema=1\n"),
            format!("{line}WRELA_STDLIB_TIME_QEMU_EVIDENCE\tschema=1\n"),
            format!("{line}WRELA_STDLIB_TIME_QEMU_EVIDENCE\n"),
        ] {
            assert!(parse_stdlib_time_qemu_evidence(collision.as_bytes(), "fixture").is_err());
        }
        let mut reordered = payload.split_whitespace().collect::<Vec<_>>();
        reordered.swap(1, 3);
        let reordered = format!("WRELA_STDLIB_TIME_QEMU_EVIDENCE {}\n", reordered.join(" "));
        for malformed in [
            line.replace("schema=1", "schema=2"),
            line.replace(" source_bytes=701", " source_bytes=0"),
            line.replace(" source_bytes=701", " source_bytes=0701"),
            line.replace(" source_bytes=701", " source_bytes=+701"),
            line.replace(&"11".repeat(32), &"AA".repeat(32)),
            line.replace("source_sha256=", "unknown_sha256="),
            line.replace("manifest_sha256=", "source_sha256="),
            reordered,
            line.replace(" source_bytes=701", "  source_bytes=701"),
            line.replace(
                " invalid_count_event_stream_bytes=213\n",
                " invalid_count_event_stream_bytes=213 trailing=true\n",
            ),
            format!(
                "WRELA_STDLIB_TIME_QEMU_EVIDENCE {} padding={}\n",
                payload,
                "x".repeat(4096)
            ),
        ] {
            assert!(
                parse_stdlib_time_qemu_evidence(malformed.as_bytes(), "fixture").is_err(),
                "accepted malformed evidence: {malformed}"
            );
        }
    }

    #[test]
    fn stdlib_time_evidence_is_recomputed_from_frozen_source_and_six_runtime_artifacts() {
        let directory = TestDirectory::new("stdlib-time-evidence");
        let root = directory.root.join("source");
        create_private_directory(&root).expect("source fixture root");
        let evidence_root = directory.root.join("evidence");
        populate_stdlib_time_evidence(&root, &evidence_root);

        let recomputed = recompute_stdlib_time_qemu_evidence(&root, &evidence_root, "fixture")
            .expect("independently recomputed stdlib-time evidence");
        let line = format!(
            "WRELA_STDLIB_TIME_QEMU_EVIDENCE {}\n",
            encode_stdlib_time_qemu_evidence(&recomputed)
        );
        assert_eq!(
            parse_stdlib_time_qemu_evidence(line.as_bytes(), "fixture")
                .expect("parse recomputed evidence"),
            recomputed
        );

        let stale = line.replacen(&recomputed.source.sha256, &"ab".repeat(32), 1);
        let stale = parse_stdlib_time_qemu_evidence(stale.as_bytes(), "fixture")
            .expect("stale but canonical line parses");
        assert_ne!(stale, recomputed, "stale source identity must not verify");

        let image = evidence_root.join("pass.efi");
        set_mode(&image, 0o600).expect("unseal substituted image fixture");
        fs::write(&image, b"substituted-pass-efi").expect("substitute image evidence");
        set_mode(&image, 0o444).expect("reseal substituted image fixture");
        let substituted = recompute_stdlib_time_qemu_evidence(&root, &evidence_root, "fixture")
            .expect("remeasure substituted evidence");
        assert_ne!(substituted.pass.image_sha256, recomputed.pass.image_sha256);

        write_new_bytes(&evidence_root.join("unexpected"), b"extra", false)
            .expect("add evidence inventory overflow");
        assert!(recompute_stdlib_time_qemu_evidence(&root, &evidence_root, "fixture").is_err());
    }

    #[test]
    fn stdlib_time_recomputation_binds_every_source_and_runtime_digest_and_extent() {
        let inputs = [
            "std/examples/stdlib-time-runtime/src/runtime/time_test.wr",
            "std/examples/stdlib-time-runtime/wrela.toml",
            "std/examples/stdlib-time-runtime/wrela.lock",
            "pass.efi",
            "pass.report",
            "pass.events",
            "invalid-count.efi",
            "invalid-count.report",
            "invalid-count.events",
        ];
        for (changed_index, relative) in inputs.iter().enumerate() {
            let directory = TestDirectory::new(&format!("stdlib-time-bind-{changed_index}"));
            let root = directory.root.join("source");
            create_private_directory(&root).expect("source fixture root");
            let evidence_root = directory.root.join("evidence");
            populate_stdlib_time_evidence(&root, &evidence_root);
            let baseline = recompute_stdlib_time_qemu_evidence(&root, &evidence_root, "fixture")
                .expect("baseline stdlib-time evidence");
            let path = if changed_index < 3 {
                root.join(relative)
            } else {
                evidence_root.join(relative)
            };
            let mut bytes = read_bounded_file(&path, MAX_SMOKE_SERIAL_BYTES)
                .expect("read sealed evidence fixture");
            if relative.ends_with(".events") {
                extend_final_event_frame(&mut bytes);
            } else {
                bytes.push(b'!');
            }
            set_mode(&path, 0o600).expect("unseal changed evidence fixture");
            fs::write(&path, bytes).expect("replace changed evidence fixture");
            set_mode(&path, 0o444).expect("reseal changed evidence fixture");

            let changed = recompute_stdlib_time_qemu_evidence(&root, &evidence_root, "fixture")
                .expect("remeasure changed stdlib-time evidence");
            let baseline = stdlib_time_measurements(&baseline);
            let changed = stdlib_time_measurements(&changed);
            assert_eq!(baseline.len(), inputs.len());
            for index in 0..inputs.len() {
                if index == changed_index {
                    assert_ne!(baseline[index].sha256, changed[index].sha256);
                    assert_ne!(baseline[index].bytes, changed[index].bytes);
                } else {
                    assert_eq!(baseline[index], changed[index]);
                }
            }
        }
    }

    #[test]
    fn stdlib_time_event_preimage_rejects_trailing_truncated_and_limit_evidence() {
        let directory = TestDirectory::new("stdlib-time-events");
        let path = directory.root.join("events");
        let valid = event_preimage([b"one", b"two", b"three", b"four"]);
        write_new_bytes(&path, &valid, false).expect("write valid event preimage");
        let measured = measure_stdlib_time_event_preimage(&path, "fixture")
            .expect("measure canonical event preimage");
        assert_eq!(measured.sha256, sha256_bytes(&valid));
        assert_eq!(measured.bytes, 15);

        for malformed in [
            {
                let mut bytes = valid.clone();
                bytes.push(0);
                bytes
            },
            {
                let mut bytes = valid.clone();
                bytes.truncate(bytes.len() - 1);
                bytes
            },
            {
                let mut bytes = valid.clone();
                bytes[12..20].copy_from_slice(&5_u64.to_le_bytes());
                bytes
            },
            {
                let mut bytes = valid.clone();
                bytes[20..28].copy_from_slice(&u64::MAX.to_le_bytes());
                bytes
            },
        ] {
            set_mode(&path, 0o600).expect("unseal malformed event fixture");
            fs::write(&path, malformed).expect("replace event fixture");
            set_mode(&path, 0o444).expect("reseal malformed event fixture");
            assert!(measure_stdlib_time_event_preimage(&path, "fixture").is_err());
        }

        set_mode(&path, 0o600).expect("unseal oversized event fixture");
        fs::write(
            &path,
            vec![0_u8; usize::try_from(MAX_SMOKE_SERIAL_BYTES + 1).expect("fixture limit fits")],
        )
        .expect("replace with oversized event evidence");
        set_mode(&path, 0o444).expect("reseal oversized event fixture");
        assert!(measure_stdlib_time_event_preimage(&path, "fixture").is_err());
    }

    #[test]
    fn stdlib_time_cancelled_rehearsal_cleanup_removes_partial_roots() {
        let directory = TestDirectory::new("stdlib-time-cleanup");
        let run = directory.root.join("stdlib-time-run");
        let evidence = directory.root.join("stdlib-time-evidence");
        write_new_bytes(&run.join("partial"), b"partial run", false).expect("partial run fixture");
        write_new_bytes(&evidence.join("partial"), b"partial evidence", false)
            .expect("partial evidence fixture");
        cleanup_stdlib_time_qemu_roots(&directory.root, &run, &evidence, "cancelled fixture")
            .expect("cancelled rehearsal cleanup");
        assert!(!run.exists() && !evidence.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let sentinel = directory.root.join("sentinel");
            write_new_bytes(&sentinel.join("keep"), b"keep", false).expect("substitution sentinel");
            symlink(&sentinel, &evidence).expect("substitute evidence root with symlink");
            cleanup_stdlib_time_qemu_roots(&directory.root, &run, &evidence, "substituted fixture")
                .expect("remove substituted root without following it");
            assert!(!evidence.exists());
            assert_eq!(
                read_bounded_file(&sentinel.join("keep"), 16).expect("sentinel remains"),
                b"keep"
            );

            let outside = TestDirectory::new("stdlib-time-cleanup-outside");
            write_new_bytes(&run.join("partial"), b"keep run", false).expect("recreated run root");
            write_new_bytes(&outside.root.join("keep"), b"keep outside", false)
                .expect("outside sentinel");
            assert!(
                cleanup_stdlib_time_qemu_roots(
                    &directory.root,
                    &run,
                    &outside.root,
                    "outside fixture",
                )
                .is_err()
            );
            assert!(run.exists());
            assert_eq!(
                read_bounded_file(&outside.root.join("keep"), 16)
                    .expect("outside sentinel remains"),
                b"keep outside"
            );
            cleanup_stdlib_time_qemu_roots(&directory.root, &run, &evidence, "final fixture")
                .expect("remove recreated dedicated root");
        }
    }

    #[test]
    fn stdlib_time_receipt_binding_rejects_any_installed_extracted_identity_drift() {
        let installed = fixture_stdlib_time_evidence();
        require_reproducible_stdlib_time_evidence(&installed, &installed)
            .expect("identical installed/extracted evidence");

        let mut source_drift = installed.clone();
        source_drift.source.bytes += 1;
        assert!(require_reproducible_stdlib_time_evidence(&installed, &source_drift).is_err());

        let mut pass_drift = installed.clone();
        pass_drift.pass.report_sha256 = "ab".repeat(32);
        assert!(require_reproducible_stdlib_time_evidence(&installed, &pass_drift).is_err());

        let mut fatal_drift = installed.clone();
        fatal_drift.invalid_count.event_stream_bytes += 1;
        assert!(require_reproducible_stdlib_time_evidence(&installed, &fatal_drift).is_err());
    }

    #[test]
    fn canonical_archive_round_trips_the_exact_tested_tree() {
        let directory = TestDirectory::new("archive");
        let installation = directory.root.join("installation");
        create_private_directory(&installation).expect("installation");
        write_new_bytes(&installation.join("bin/tool"), b"executable", true).expect("executable");
        write_new_bytes(&installation.join("share/data.txt"), b"data", false).expect("data");
        seal_installation_directories(&installation).expect("seal installation");
        let expected = measure_tree(&installation, 32, 1024).expect("measure installation");
        let archive = directory.root.join("release.tar");
        write_canonical_archive(&installation, &expected, &archive, "wrela-test")
            .expect("write archive");
        let clean = directory.root.join("clean");
        create_private_directory(&clean).expect("clean room");
        extract_canonical_archive(&archive, &clean, "wrela-test").expect("extract archive");
        assert_eq!(
            measure_tree(&clean.join("wrela-test"), 32, 1024).expect("measure extraction"),
            expected
        );
        #[cfg(unix)]
        {
            set_mode(&clean.join("wrela-test/bin/tool"), 0o755).expect("mode drift fixture");
            assert!(
                validate_sealed_installation_modes(&clean.join("wrela-test"), &expected).is_err()
            );
        }

        set_mode(&archive, 0o600).expect("mutable corruption fixture");
        let mut bytes = fs::read(&archive).expect("archive bytes");
        bytes[0] ^= 1;
        fs::write(&archive, bytes).expect("corrupt archive");
        set_mode(&archive, 0o444).expect("reseal corrupt archive");
        let corrupt = directory.root.join("corrupt-clean");
        create_private_directory(&corrupt).expect("corrupt clean room");
        assert!(extract_canonical_archive(&archive, &corrupt, "wrela-test").is_err());
    }

    #[test]
    fn slip_decoder_rejects_truncation_and_noncanonical_escapes() {
        let encoded = [0xc0, b'a', 0xdb, 0xdc, 0xdb, 0xdd, b'z', 0xc0];
        assert_eq!(
            slip_frames(&encoded).expect("canonical SLIP"),
            vec![vec![b'a', 0xc0, 0xdb, b'z']]
        );
        assert!(slip_frames(&[0xc0, 0xdb]).is_err());
        assert!(slip_frames(&[0xc0, 0xdb, 0x01, 0xc0]).is_err());
        assert!(slip_frames(&[0xc0, b'x']).is_err());
    }

    #[test]
    fn toolchain_manifest_encoder_uses_consumer_canonical_order() {
        let measurement = FileMeasurement {
            sha256: "77".repeat(32),
            bytes: 42,
        };
        let manifest = encode_toolchain_manifest(ManifestInputs {
            release: "0.1.0",
            host: "aarch64-apple-darwin",
            core_source_digest: &"11".repeat(32),
            core_manifest_digest: &"22".repeat(32),
            frontend: &measurement,
            backend: &measurement,
            standard_library: &measurement,
            qemu: &measurement,
            target: &measurement,
            firmware_code: &measurement,
            firmware_variables: &measurement,
            runtime: &measurement,
        })
        .expect("toolchain manifest");
        assert!(manifest.starts_with("schema = 1\nrelease = \"0.1.0\"\n"));
        assert!(manifest.contains("semantic_wir = 8\n"));
        assert!(manifest.contains("flow_wir = 10\n"));
        assert!(manifest.contains("flow_wir_wire = 10\n"));
        assert!(manifest.contains("machine_wir = 10\n"));
        assert!(manifest.contains("image_report = 11\n"));
        assert!(manifest.contains("test_report = 2\n"));
        assert!(manifest.contains("test_event = 3\n"));
        assert_eq!(manifest.matches("[[components]]").count(), 4);
        assert_eq!(manifest.matches("[[targets.files]]").count(), 3);
        assert!(
            manifest.find("kind = \"frontend\"").expect("frontend")
                < manifest.find("kind = \"backend\"").expect("backend")
        );
        assert!(manifest.ends_with("bytes = 42\n"));
    }
}
