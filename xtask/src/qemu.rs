//! Authenticated, content-addressed QEMU/firmware bootstrap.
//!
//! This is deliberately maintainer-only.  It never trusts an ambient QEMU,
//! never accepts an unauthenticated release archive, and never creates the
//! distribution enrollment except during an explicit fresh
//! `--record-output` build.

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

use sha2::{Digest, Sha256};

pub(crate) const HELP: &str = "\
usage: cargo xtask qemu [options]\n\
\n\
Authenticate and build the exact QEMU/firmware release pinned by\n\
toolchain/emulation.lock.toml.\n\
\n\
options:\n\
  --plan                         authenticate inputs and print the plan only\n\
  --offline                      forbid network acquisition\n\
  --record-output                fresh build that creates emulation.outputs.toml\n\
  --jobs <1..=256>               bounded native parallelism\n\
  --source-archive <absolute>    exact local QEMU release archive\n\
  --signature <absolute>         detached release signature\n\
  --signing-key <absolute>       armored release-manager public key\n\
  -h, --help                     show this help\n\
\n\
environment:\n\
  WRELA_QEMU_SOURCE_ARCHIVE      local archive alternative\n\
  WRELA_QEMU_SIGNATURE           local signature alternative\n\
  WRELA_QEMU_SIGNING_KEY         local signing-key alternative\n\
  WRELA_QEMU_JOBS                parallelism alternative\n\
  WRELA_QEMU_CURL                absolute HTTPS client\n\
  WRELA_QEMU_GPG                 absolute GnuPG executable\n\
  WRELA_QEMU_XZ                  absolute xz executable\n\
  WRELA_QEMU_BZIP2               absolute bzip2 executable\n\
  WRELA_QEMU_PYTHON              absolute Python interpreter\n\
  WRELA_QEMU_NINJA               absolute Ninja executable\n\
  WRELA_QEMU_PKG_CONFIG          absolute pkg-config executable\n\
  WRELA_QEMU_CC                  absolute C compiler\n\
  WRELA_QEMU_CXX                 absolute C++ compiler\n\
  WRELA_QEMU_LINKER              absolute host linker\n\
  WRELA_QEMU_AR                  absolute static archiver\n\
  WRELA_QEMU_RANLIB              absolute archive indexer\n\
  WRELA_QEMU_OTOOL               absolute Mach-O dependency inspector\n\
  WRELA_QEMU_CODESIGN            absolute deterministic ad-hoc signer\n\
  WRELA_QEMU_TOUCH               absolute timestamp normalizer\n\
  WRELA_QEMU_SYSROOT             absolute macOS SDK directory\n";

const LOCK_SCHEMA: u32 = 1;
const OUTPUT_SCHEMA: u32 = 1;
const BUILD_CONTRACT_VERSION: u32 = 20;
const TREE_MAGIC: &[u8; 8] = b"WRELDST\0";
const TREE_VERSION: u32 = 1;
const INPUT_MAGIC: &[u8; 8] = b"WRELQIN\0";
const MAX_JOBS: u32 = 256;
const DEFAULT_JOBS: u32 = 8;
const MAX_LOCK_BYTES: u64 = 1024 * 1024;
const MAX_ARCHIVE_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_SIGNATURE_BYTES: u64 = 1024 * 1024;
const MAX_KEY_BYTES: u64 = 4 * 1024 * 1024;
const MAX_PROCESS_OUTPUT: usize = 16 * 1024 * 1024;
const MAX_DISPLAYED_PROCESS_OUTPUT: usize = 16 * 1024;
const DISPLAYED_PROCESS_OUTPUT_PREFIX: usize = 4 * 1024;
const MAX_BZIP2_HELP_BYTES: usize = 4096;
const MAX_GPG_RECORDS: usize = 4_096;
const MAX_GPG_FIELDS: usize = 64;
const MAX_GPG_RECORD_BYTES: usize = 64 * 1024;
const MAX_RUST_LOCK_PACKAGES: usize = 100_000;
const MAX_ARCHIVE_MEMBERS: u64 = 1_000_000;
const MAX_ARCHIVE_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_ARCHIVE_TOTAL_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_ARCHIVE_PATH_BYTES: usize = 4096;
const MAX_PAX_BYTES: u64 = 1024 * 1024;
const MAX_TAR_TRAILER_BYTES: u64 = 1024 * 1024;
const MAX_TREE_FILES: u64 = 1_000_000;
const MAX_TREE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAX_TREE_DEPTH: u32 = 128;
const MAX_PATH_BYTES: usize = 4096;
const MAX_SDK_INPUT_BYTES: u64 = 128 * 1024 * 1024;
const MAX_SDK_LINK_BYTES: usize = 4096;
const MAX_SDK_TREE_FILES: u64 = 100_000;
const MAX_SDK_TREE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_NATIVE_LIBRARIES: usize = 4_096;
const MAX_NATIVE_LIBRARY_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_PKG_CONFIG_FILE_BYTES: u64 = 1024 * 1024;
const QEMU_KEY_URL_PREFIX: &str = "https://keys.openpgp.org/vks/v1/by-fingerprint/";
const OMITTED_ABSOLUTE_SYMLINK: (&str, &str) = (
    "roms/edk2/EmulatorPkg/Unix/Host/X11IncludeHack",
    "/opt/X11/include",
);
const QEMU_DARWIN_STATIC_MESON_ORIGINAL_SHA256: &str =
    "8b7aff866c7a82c9eea618be55f65d85dcf7ecaefc691d247f3e8b182d998ff4";
const QEMU_DARWIN_STATIC_MESON_ORIGINAL_BYTES: u64 = 185_755;
const QEMU_DARWIN_STATIC_MESON_PATCHED_SHA256: &str =
    "fac26c2b4c7f2efb7eb430e18a12b6cf4d88d4dd1ae8e56f8d05420dcc0e83e3";
const QEMU_DARWIN_STATIC_MESON_PATCHED_BYTES: u64 = 185_779;
const QEMU_DARWIN_STATIC_MESON_ORIGINAL_BLOCK: &[u8] = b"if get_option('prefer_static')\n  qemu_ldflags += get_option('b_pie') ? '-static-pie' : '-static'\nendif\n";
const QEMU_DARWIN_STATIC_MESON_PATCHED_BLOCK: &[u8] = b"if get_option('prefer_static') and host_os != 'darwin'\n  qemu_ldflags += get_option('b_pie') ? '-static-pie' : '-static'\nendif\n";
const DETERMINISTIC_DATE_SHIM: &[u8] = b"#!/bin/sh\n\
if test \"$#\" -ne 0; then\n\
    printf '%s\\n' 'wrela deterministic date accepts no arguments' >&2\n\
    exit 64\n\
fi\n\
printf '%s\\n' 'Thu Jan  1 00:00:01 UTC 1970'\n";
const HOST_UTILITY_CANDIDATES: &[(&str, &[&str])] = &[
    (
        "Rez",
        &["/Applications/Xcode.app/Contents/Developer/usr/bin/Rez"],
    ),
    (
        "SetFile",
        &["/Applications/Xcode.app/Contents/Developer/usr/bin/SetFile"],
    ),
    ("awk", &["/usr/bin/awk"]),
    ("basename", &["/usr/bin/basename"]),
    ("cat", &["/bin/cat"]),
    ("chmod", &["/bin/chmod"]),
    ("cp", &["/bin/cp"]),
    ("cut", &["/usr/bin/cut"]),
    ("diff", &["/usr/bin/diff"]),
    ("dirname", &["/usr/bin/dirname"]),
    ("env", &["/usr/bin/env"]),
    ("expr", &["/bin/expr", "/usr/bin/expr"]),
    ("find", &["/usr/bin/find"]),
    ("grep", &["/usr/bin/grep"]),
    ("head", &["/usr/bin/head"]),
    ("install", &["/usr/bin/install"]),
    ("lipo", &["/usr/bin/lipo"]),
    ("ln", &["/bin/ln"]),
    ("mkdir", &["/bin/mkdir"]),
    ("mv", &["/bin/mv"]),
    ("nm", &["/usr/bin/nm"]),
    ("pwd", &["/bin/pwd"]),
    ("rm", &["/bin/rm"]),
    ("sed", &["/usr/bin/sed"]),
    ("sort", &["/usr/bin/sort"]),
    ("tail", &["/usr/bin/tail"]),
    ("tr", &["/usr/bin/tr"]),
    ("uname", &["/usr/bin/uname"]),
    ("which", &["/usr/bin/which"]),
    ("xargs", &["/usr/bin/xargs"]),
];
const REQUIRED_SDK_INPUTS: &[(&str, Option<&str>)] = &[
    ("SDKSettings.json", None),
    ("System/Library/CoreServices/SystemVersion.plist", None),
    ("usr/include/zlib.h", None),
    ("usr/lib/libSystem.tbd", Some("libSystem.B.tbd")),
    ("usr/lib/libc++.tbd", Some("libc++.1.tbd")),
    ("usr/lib/libiconv.tbd", Some("libiconv.2.tbd")),
    ("usr/lib/libz.tbd", Some("libz.1.tbd")),
];
const REQUIRED_SDK_ALIAS_INPUTS: &[(&str, &str, &str)] = &[
    ("usr/lib/libm.tbd", "libSystem.tbd", "libSystem.B.tbd"),
    ("usr/lib/libpthread.tbd", "libSystem.tbd", "libSystem.B.tbd"),
];
const REQUIRED_SDK_FRAMEWORK_INPUTS: &[(&str, &str)] = &[
    ("AppKit", "C"),
    ("Carbon", "A"),
    ("CoreFoundation", "A"),
    ("Foundation", "C"),
    ("IOKit", "A"),
];
const ALLOWED_PKG_CONFIG_LIBRARIES: &[&str] = &[
    "fdt", "glib-2.0", "iconv", "intl", "m", "pcre2-8", "pthread", "z",
];
const ALLOWED_PKG_CONFIG_FRAMEWORKS: &[&str] =
    &["AppKit", "Carbon", "CoreFoundation", "Foundation"];
const SDK_PROVIDED_LIBRARIES: &[&str] = &["iconv", "m", "pthread", "z"];
const REQUIRED_STATIC_LIBRARIES: &[&str] = &["fdt", "glib-2.0"];
const REQUIRED_PKG_CONFIG_MODULES: &[&str] = &["glib-2.0", "libfdt", "libpcre2-8"];
const REQUIRED_MACHO_DEPENDENCIES: &[&str] = &[
    "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
    "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation",
    "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit",
    "/usr/lib/libSystem.B.dylib",
    "/usr/lib/libiconv.2.dylib",
    "/usr/lib/libobjc.A.dylib",
    "/usr/lib/libz.1.dylib",
];
const ZLIB_PKG_CONFIG: &[u8] = b"Name: zlib\n\
Description: zlib compression library from the measured macOS SDK\n\
Version: 1.2.12\n\
Libs: -lz\n\
Cflags:\n";
const BZIP2_HELP_PREFIX: &[u8] = b"bzip2, a block-sorting file compressor.  Version 1.0.8, 13-Jul-2019.\n\n   usage: bzip2 [flags and input files in any order]\n";
const CONTENT_ONLY_TOOL_IDENTITIES: &[&str] = &["ar", "linker", "ranlib", "shell", "touch"];

static NEXT_PRIVATE_DIRECTORY: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq)]
struct Options {
    help: bool,
    plan: bool,
    offline: bool,
    record_output: bool,
    jobs: u32,
    source_archive: Option<PathBuf>,
    signature: Option<PathBuf>,
    signing_key: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EmulationLock {
    bytes_sha256: String,
    version: String,
    source: String,
    source_sha256: String,
    signature: String,
    signing_key_fingerprint: String,
    system_targets: Vec<String>,
    machine_contract: String,
    cpu_contract: String,
    accelerator_contract: String,
    firmware: Vec<FirmwarePin>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FirmwarePin {
    name: String,
    source_path: String,
    compression: String,
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
struct ToolIdentity {
    path: PathBuf,
    sha256: String,
    bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NativeFileIdentity {
    path: PathBuf,
    sha256: String,
    bytes: u64,
}

#[derive(Debug)]
struct BuildTools {
    curl: ToolIdentity,
    gpg: ToolIdentity,
    xz: ToolIdentity,
    bzip2: ToolIdentity,
    python: ToolIdentity,
    ninja: ToolIdentity,
    pkg_config: ToolIdentity,
    cc: ToolIdentity,
    cxx: ToolIdentity,
    cxx_driver: PathBuf,
    linker: ToolIdentity,
    ar: ToolIdentity,
    ranlib: ToolIdentity,
    ranlib_driver: PathBuf,
    otool: ToolIdentity,
    codesign: ToolIdentity,
    touch: ToolIdentity,
    shell: ToolIdentity,
    utilities: Vec<(String, ToolIdentity)>,
    sysroot: DirectoryIdentity,
    apple_toolchain: DirectoryIdentity,
    python_runtime: DirectoryIdentity,
    host_system: NativeFileIdentity,
    dynamic_libraries: Vec<NativeFileIdentity>,
}

#[derive(Debug)]
struct BootstrapTools {
    curl: ToolIdentity,
    gpg: ToolIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectoryIdentity {
    path: PathBuf,
    sha256: String,
    files: u64,
    bytes: u64,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct SdkTreeRecord {
    path: String,
    kind: u8,
    bytes: u64,
    sha256: String,
    executable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StaticDependencyContract {
    sha256: String,
    include_directories: Vec<PathBuf>,
    library_directories: Vec<PathBuf>,
    pkg_config_modules: Vec<PkgConfigModule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PkgConfigModule {
    name: String,
    path: PathBuf,
    measurement: FileMeasurement,
}

#[derive(Debug)]
struct AuthenticatedInputs {
    archive: PathBuf,
    archive_measurement: FileMeasurement,
    signature: PathBuf,
    signature_measurement: FileMeasurement,
    signing_key: PathBuf,
    signing_key_measurement: FileMeasurement,
    signature_timestamp: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SigningKeyInventory {
    primary_key_id: String,
    created: u64,
    expires: u64,
}

#[derive(Debug)]
struct BuildPlan {
    root: PathBuf,
    host: String,
    lock: EmulationLock,
    lock_bytes: Vec<u8>,
    tools: BuildTools,
    inputs: AuthenticatedInputs,
    static_dependencies: StaticDependencyContract,
    implementation_sha256: String,
    bootstrap_executable: ToolIdentity,
    native_input_sha256: String,
    bundle: PathBuf,
    expected_output: Option<EmulationOutput>,
    jobs: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BootstrapImplementationProjection {
    qemu_source_sha256: String,
    dispatch_sha256: String,
    manifest_sha256: String,
    dependency_closure_sha256: String,
}

#[derive(Clone, Copy)]
struct BootstrapSources<'a> {
    qemu: &'a [u8],
    main: &'a [u8],
    manifest: &'a [u8],
    cargo_lock: &'a [u8],
}

#[derive(Clone, Debug, Default)]
struct CargoPackageBlock {
    name: Option<String>,
    version: Option<String>,
    source: Option<String>,
    checksum: Option<String>,
    dependencies: BTreeSet<String>,
}

#[derive(Debug)]
struct PrivateDirectory {
    path: PathBuf,
}

impl PrivateDirectory {
    fn create(parent: &Path, label: &str) -> Result<Self, String> {
        ensure_directory(parent)?;
        for _ in 0..256 {
            let sequence = NEXT_PRIVATE_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!(".{label}-{}-{sequence}", std::process::id()));
            match create_private_directory(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(format!(
                        "cannot create private QEMU directory {}: {error}",
                        path.display()
                    ));
                }
            }
        }
        Err("cannot allocate a unique private QEMU directory".to_owned())
    }
}

impl Drop for PrivateDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub(crate) fn run(root: &Path, arguments: &[String]) -> Result<(), String> {
    let options = parse_options(arguments)?;
    if options.help {
        print!("{HELP}");
        return Ok(());
    }
    let plan = load_plan(root, &options)?;
    if options.plan {
        print_plan(&plan);
        return Ok(());
    }
    execute_build(plan, options.record_output)
}

fn parse_options(arguments: &[String]) -> Result<Options, String> {
    let mut options = Options {
        help: false,
        plan: false,
        offline: false,
        record_output: false,
        jobs: default_jobs(),
        source_archive: None,
        signature: None,
        signing_key: None,
    };
    let mut jobs_seen = false;
    let mut index = 0usize;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "-h" | "--help" if !options.help => options.help = true,
            "--plan" if !options.plan => options.plan = true,
            "--offline" if !options.offline => options.offline = true,
            "--record-output" if !options.record_output => options.record_output = true,
            "--jobs" if !jobs_seen => {
                jobs_seen = true;
                index = index
                    .checked_add(1)
                    .ok_or_else(|| "QEMU argument index overflow".to_owned())?;
                options.jobs = parse_jobs(
                    arguments
                        .get(index)
                        .ok_or_else(|| "--jobs requires a value".to_owned())?,
                    "--jobs",
                )?;
            }
            "--source-archive" if options.source_archive.is_none() => {
                options.source_archive =
                    Some(option_file(arguments, &mut index, "--source-archive")?);
            }
            "--signature" if options.signature.is_none() => {
                options.signature = Some(option_file(arguments, &mut index, "--signature")?);
            }
            "--signing-key" if options.signing_key.is_none() => {
                options.signing_key = Some(option_file(arguments, &mut index, "--signing-key")?);
            }
            argument => {
                return Err(format!(
                    "unknown or repeated QEMU option {argument:?}\n\n{HELP}"
                ));
            }
        }
        index = index
            .checked_add(1)
            .ok_or_else(|| "QEMU argument count overflow".to_owned())?;
    }
    apply_environment_path(&mut options.source_archive, "WRELA_QEMU_SOURCE_ARCHIVE")?;
    apply_environment_path(&mut options.signature, "WRELA_QEMU_SIGNATURE")?;
    apply_environment_path(&mut options.signing_key, "WRELA_QEMU_SIGNING_KEY")?;
    if !jobs_seen {
        if let Ok(value) = env::var("WRELA_QEMU_JOBS") {
            options.jobs = parse_jobs(&value, "WRELA_QEMU_JOBS")?;
        }
    }
    if options.plan && options.record_output {
        return Err("--plan and --record-output are mutually exclusive".to_owned());
    }
    if options.help && arguments.len() != 1 {
        return Err("--help cannot be combined with other QEMU options".to_owned());
    }
    Ok(options)
}

fn option_file(arguments: &[String], index: &mut usize, name: &str) -> Result<PathBuf, String> {
    *index = index
        .checked_add(1)
        .ok_or_else(|| "QEMU argument index overflow".to_owned())?;
    let value = arguments
        .get(*index)
        .ok_or_else(|| format!("{name} requires a value"))?;
    absolute_regular_file(Path::new(value), name)
}

fn apply_environment_path(slot: &mut Option<PathBuf>, variable: &str) -> Result<(), String> {
    let Some(value) = env::var_os(variable) else {
        return Ok(());
    };
    if slot.is_some() {
        return Err(format!(
            "set only one command-line path and {variable} for the same input"
        ));
    }
    *slot = Some(absolute_regular_file(Path::new(&value), variable)?);
    Ok(())
}

fn parse_jobs(value: &str, source: &str) -> Result<u32, String> {
    let jobs = value
        .parse::<u32>()
        .map_err(|_| format!("{source} must be an unsigned decimal integer"))?;
    if jobs.to_string() != value || !(1..=MAX_JOBS).contains(&jobs) {
        return Err(format!(
            "{source} must be a canonical integer in 1..={MAX_JOBS}"
        ));
    }
    Ok(jobs)
}

fn default_jobs() -> u32 {
    thread::available_parallelism()
        .ok()
        .and_then(|count| u32::try_from(count.get()).ok())
        .unwrap_or(DEFAULT_JOBS)
        .min(MAX_JOBS)
}

fn load_plan(root: &Path, options: &Options) -> Result<BuildPlan, String> {
    let root = exact_directory(root, "workspace root")?;
    let lock_path = root.join("toolchain/emulation.lock.toml");
    let lock_bytes = read_bounded_file(&lock_path, MAX_LOCK_BYTES)?;
    let lock = decode_lock(&lock_bytes)?;
    let host = host_identity()?;

    // Authentication precedes expensive host-closure discovery.  A stale or
    // Unauthenticated or out-of-validity signing evidence must fail before it
    // can influence an output lock.
    let bootstrap_tools = BootstrapTools::discover()?;
    let inputs = acquire_and_authenticate(&root, &lock, options, &bootstrap_tools)?;
    let tools = BuildTools::discover(bootstrap_tools)?;
    let static_dependencies = measure_static_dependency_contract(&tools)?;
    let bootstrap_executable = identify_current_executable()?;
    let implementation_sha256 = implementation_digest(&root)?;
    let native_input_sha256 = native_input_digest(
        &host,
        &lock,
        &inputs,
        &tools,
        &static_dependencies.sha256,
        &implementation_sha256,
    )?;
    let bundle = root
        .join("build/toolchain/qemu/prefixes")
        .join(format!("{}-{native_input_sha256}", lock.version))
        .join("bundle");
    let expected_output = load_expected_output(&root)?;
    if let Some(output) = &expected_output {
        validate_expected_output_inputs(output, &lock, &host, &native_input_sha256)?;
    }
    Ok(BuildPlan {
        root,
        host,
        lock,
        lock_bytes,
        tools,
        inputs,
        static_dependencies,
        implementation_sha256,
        bootstrap_executable,
        native_input_sha256,
        bundle,
        expected_output,
        jobs: options.jobs,
    })
}

fn print_plan(plan: &BuildPlan) {
    println!("qemu_version={}", plan.lock.version);
    println!("host={}", plan.host);
    println!("emulation_lock_sha256={}", plan.lock.bytes_sha256);
    println!("source_sha256={}", plan.inputs.archive_measurement.sha256);
    println!(
        "signature_sha256={}",
        plan.inputs.signature_measurement.sha256
    );
    println!(
        "signing_key_sha256={}",
        plan.inputs.signing_key_measurement.sha256
    );
    println!("signature_timestamp={}", plan.inputs.signature_timestamp);
    println!("native_input_sha256={}", plan.native_input_sha256);
    println!("bundle={}", plan.bundle.display());
}

fn host_identity() -> Result<String, String> {
    match (env::consts::ARCH, env::consts::OS) {
        ("aarch64", "macos") => Ok("aarch64-apple-darwin".to_owned()),
        ("x86_64", "macos") => Ok("x86_64-apple-darwin".to_owned()),
        (architecture, operating_system) => Err(format!(
            "QEMU bootstrap has no reviewed static host contract for {architecture}-{operating_system}"
        )),
    }
}

fn decode_lock(bytes: &[u8]) -> Result<EmulationLock, String> {
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
    let mut qemu_seen = false;
    for (line_index, raw_line) in source.lines().enumerate() {
        let line_number = line_index + 1;
        if raw_line.trim_end() != raw_line {
            return Err(format!(
                "emulation lock has trailing whitespace on line {line_number}"
            ));
        }
        let line = raw_line.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line != raw_line {
            return Err(format!(
                "emulation lock has unexpected indentation on line {line_number}"
            ));
        }
        match line {
            "[qemu]" => {
                if !matches!(section, Section::Root) || qemu_seen {
                    return Err(format!("noncanonical [qemu] on line {line_number}"));
                }
                qemu_seen = true;
                section = Section::Qemu;
            }
            "[[firmware]]" => {
                if !qemu_seen || firmware.len() >= 2 {
                    return Err(format!("noncanonical [[firmware]] on line {line_number}"));
                }
                firmware.push(BTreeMap::new());
                section = Section::Firmware(firmware.len() - 1);
            }
            _ if line.starts_with('[') => {
                return Err(format!(
                    "unknown emulation lock table on line {line_number}: {line:?}"
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
                        "duplicate emulation lock field {key:?} on line {line_number}"
                    ));
                }
            }
        }
    }
    require_keys(&root, &["schema"], "emulation root")?;
    if parse_u64(required(&root, "schema")?, "emulation schema")? != u64::from(LOCK_SCHEMA) {
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
    if firmware.len() != 2 {
        return Err("emulation lock must contain exactly two firmware records".to_owned());
    }
    let version = parse_string(required(&qemu, "version")?, "QEMU version")?;
    if version != "10.1.5" {
        return Err(format!(
            "QEMU version {version:?} is not the revision-0.1 pin 10.1.5"
        ));
    }
    let source_url = parse_string(required(&qemu, "source")?, "QEMU source URL")?;
    let expected_url = format!("https://download.qemu.org/qemu-{version}.tar.xz");
    if source_url != expected_url {
        return Err("QEMU source URL is not the exact HTTPS release URL".to_owned());
    }
    let signature_url = parse_string(required(&qemu, "signature")?, "QEMU signature URL")?;
    if signature_url != format!("{source_url}.sig") {
        return Err("QEMU signature URL does not exactly match the source URL".to_owned());
    }
    let fingerprint = parse_string(
        required(&qemu, "signing_key_fingerprint")?,
        "QEMU signing key fingerprint",
    )?;
    if fingerprint.len() != 40
        || !fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte.is_ascii_uppercase())
        || !fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("QEMU signing key fingerprint is not uppercase SHA-style hex".to_owned());
    }
    let system_targets =
        parse_string_array(required(&qemu, "system_targets")?, "QEMU system targets")?;
    if system_targets != ["aarch64-softmmu"] {
        return Err("QEMU bootstrap must build exactly aarch64-softmmu".to_owned());
    }
    let firmware: Vec<_> = firmware
        .iter()
        .map(parse_firmware_pin)
        .collect::<Result<_, _>>()?;
    if firmware[0].name != "code"
        || firmware[0].source_path != "pc-bios/edk2-aarch64-code.fd.bz2"
        || firmware[0].install_path != "targets/aarch64-qemu-virt-uefi/firmware/QEMU_EFI.fd"
        || firmware[1].name != "variables-template"
        || firmware[1].source_path != "pc-bios/edk2-arm-vars.fd.bz2"
        || firmware[1].install_path != "targets/aarch64-qemu-virt-uefi/firmware/QEMU_VARS.fd"
        || firmware[0].license_manifest != "pc-bios/edk2-licenses.txt"
        || firmware[1].license_manifest != firmware[0].license_manifest
    {
        return Err("firmware records do not match the fixed target payload".to_owned());
    }
    Ok(EmulationLock {
        bytes_sha256: sha256_bytes(bytes),
        version,
        source: source_url,
        source_sha256: digest_string(required(&qemu, "sha256")?, "QEMU source SHA-256")?,
        signature: signature_url,
        signing_key_fingerprint: fingerprint,
        system_targets,
        machine_contract: parse_string(
            required(&qemu, "machine_contract")?,
            "QEMU machine contract",
        )?,
        cpu_contract: parse_string(required(&qemu, "cpu_contract")?, "QEMU CPU contract")?,
        accelerator_contract: parse_string(
            required(&qemu, "accelerator_contract")?,
            "QEMU accelerator contract",
        )?,
        firmware,
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
    let compression = parse_string(required(fields, "compression")?, "firmware compression")?;
    if compression != "bzip2" {
        return Err("firmware compression must be exactly bzip2".to_owned());
    }
    Ok(FirmwarePin {
        name: parse_string(required(fields, "name")?, "firmware name")?,
        source_path: parse_string(required(fields, "source_path")?, "firmware source path")?,
        compression,
        install_path: parse_string(required(fields, "install_path")?, "firmware install path")?,
        sha256: digest_string(required(fields, "sha256")?, "firmware SHA-256")?,
        license_manifest: parse_string(
            required(fields, "license_manifest")?,
            "firmware license manifest",
        )?,
    })
}

fn assignment(line: &str, line_number: usize) -> Result<(&str, &str), String> {
    let (key, value) = line
        .split_once(" = ")
        .ok_or_else(|| format!("malformed emulation assignment on line {line_number}: {line:?}"))?;
    if key.is_empty()
        || value.is_empty()
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(format!(
            "invalid emulation assignment on line {line_number}: {line:?}"
        ));
    }
    Ok((key, value))
}

fn require_keys(
    fields: &BTreeMap<String, String>,
    expected: &[&str],
    label: &str,
) -> Result<(), String> {
    let observed: BTreeSet<_> = fields.keys().map(String::as_str).collect();
    let expected: BTreeSet<_> = expected.iter().copied().collect();
    if observed == expected {
        Ok(())
    } else {
        Err(format!(
            "{label} fields differ: expected {expected:?}, observed {observed:?}"
        ))
    }
}

fn required<'a>(fields: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, String> {
    fields
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("missing required field {key}"))
}

fn parse_string(value: &str, label: &str) -> Result<String, String> {
    if value.len() < 2 || !value.starts_with('"') || !value.ends_with('"') {
        return Err(format!("{label} is not a quoted canonical string"));
    }
    let inner = &value[1..value.len() - 1];
    if inner.is_empty()
        || inner
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'"' | b'\\') || !byte.is_ascii())
    {
        return Err(format!("{label} contains unsupported string bytes"));
    }
    Ok(inner.to_owned())
}

fn parse_string_array(value: &str, label: &str) -> Result<Vec<String>, String> {
    if !value.starts_with('[') || !value.ends_with(']') {
        return Err(format!("{label} is not a canonical string array"));
    }
    let inner = &value[1..value.len() - 1];
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    let mut values = Vec::new();
    for item in inner.split(", ") {
        values.push(parse_string(item, label)?);
    }
    if values.is_empty() || values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(format!("{label} must be sorted and unique"));
    }
    Ok(values)
}

fn parse_u64(value: &str, label: &str) -> Result<u64, String> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| format!("{label} is not unsigned decimal"))?;
    if parsed.to_string() != value {
        return Err(format!("{label} is not canonical decimal"));
    }
    Ok(parsed)
}

fn digest_string(value: &str, label: &str) -> Result<String, String> {
    let digest = parse_string(value, label)?;
    if !valid_sha256(&digest) {
        return Err(format!("{label} is not lowercase SHA-256"));
    }
    Ok(digest)
}

fn canonical_text<'a>(bytes: &'a [u8], label: &str) -> Result<&'a str, String> {
    let source = std::str::from_utf8(bytes).map_err(|_| format!("{label} is not UTF-8"))?;
    if !source.ends_with('\n') || source.contains('\r') || source.contains('\0') {
        return Err(format!("{label} has noncanonical text encoding"));
    }
    Ok(source)
}

fn load_expected_output(root: &Path) -> Result<Option<EmulationOutput>, String> {
    let path = root.join("toolchain/emulation.outputs.toml");
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "cannot inspect authenticated QEMU output lock {}: {error}",
            path.display()
        )),
        Ok(metadata)
            if metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.len() <= MAX_LOCK_BYTES =>
        {
            decode_expected_output(&read_bounded_file(&path, MAX_LOCK_BYTES)?).map(Some)
        }
        Ok(_) => Err("emulation.outputs.toml is not a bounded regular file".to_owned()),
    }
}

fn decode_expected_output(bytes: &[u8]) -> Result<EmulationOutput, String> {
    let source = canonical_text(bytes, "toolchain/emulation.outputs.toml")?;
    let mut fields = BTreeMap::new();
    for (index, line) in source.lines().enumerate() {
        let (key, value) = assignment(line, index + 1)?;
        if fields.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(format!("duplicate output field {key:?}"));
        }
    }
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
    if parse_u64(required(&fields, "schema")?, "output schema")? != u64::from(OUTPUT_SCHEMA) {
        return Err("unsupported emulation output schema".to_owned());
    }
    let output = EmulationOutput {
        emulation_lock_sha256: digest_string(
            required(&fields, "emulation_lock_sha256")?,
            "emulation lock SHA-256",
        )?,
        native_input_sha256: digest_string(
            required(&fields, "native_input_sha256")?,
            "native input SHA-256",
        )?,
        qemu_version: parse_string(required(&fields, "qemu_version")?, "QEMU version")?,
        host: parse_string(required(&fields, "host")?, "QEMU host")?,
        bundle_tree_sha256: digest_string(
            required(&fields, "bundle_tree_sha256")?,
            "bundle tree SHA-256",
        )?,
        bundle_files: positive_u64(required(&fields, "bundle_files")?, "bundle files")?,
        bundle_bytes: positive_u64(required(&fields, "bundle_bytes")?, "bundle bytes")?,
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
    if encode_expected_output(&output).as_bytes() != bytes {
        return Err("toolchain/emulation.outputs.toml is not canonical".to_owned());
    }
    Ok(output)
}

fn positive_u64(value: &str, label: &str) -> Result<u64, String> {
    let parsed = parse_u64(value, label)?;
    if parsed == 0 {
        return Err(format!("{label} must be positive"));
    }
    Ok(parsed)
}

fn encode_expected_output(output: &EmulationOutput) -> String {
    format!(
        "schema = {OUTPUT_SCHEMA}\n\
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

fn validate_expected_output_inputs(
    output: &EmulationOutput,
    lock: &EmulationLock,
    host: &str,
    native_input_sha256: &str,
) -> Result<(), String> {
    if output.emulation_lock_sha256 != lock.bytes_sha256
        || output.native_input_sha256 != native_input_sha256
        || output.qemu_version != lock.version
        || output.host != host
        || output.firmware_code_sha256 != lock.firmware[0].sha256
        || output.firmware_variables_sha256 != lock.firmware[1].sha256
    {
        return Err(
            "toolchain/emulation.outputs.toml is stale for the exact lock, host, native inputs, or firmware"
                .to_owned(),
        );
    }
    Ok(())
}

impl BootstrapTools {
    fn discover() -> Result<Self, String> {
        Ok(Self {
            curl: resolve_tool(
                "WRELA_QEMU_CURL",
                &[
                    "/usr/bin/curl",
                    "/opt/homebrew/bin/curl",
                    "/usr/local/bin/curl",
                ],
            )?,
            gpg: resolve_tool(
                "WRELA_QEMU_GPG",
                &[
                    "/opt/homebrew/bin/gpg",
                    "/usr/local/bin/gpg",
                    "/usr/bin/gpg",
                ],
            )?,
        })
    }
}

impl BuildTools {
    fn discover(bootstrap: BootstrapTools) -> Result<Self, String> {
        if !cfg!(target_os = "macos") {
            return Err(
                "QEMU bootstrap currently supports only macOS; another host requires a reviewed static dependency and binary-closure contract"
                    .to_owned(),
            );
        }
        let cc = resolve_apple_tool("WRELA_QEMU_CC", "clang")?;
        let (cxx, cxx_driver) = resolve_apple_cxx()?;
        let linker = resolve_apple_tool("WRELA_QEMU_LINKER", "ld")?;
        let ar = resolve_apple_tool("WRELA_QEMU_AR", "ar")?;
        let (ranlib, ranlib_driver) = resolve_apple_ranlib()?;
        let apple_toolchain = resolve_apple_toolchain(
            &cc,
            &cxx,
            &cxx_driver,
            &linker,
            &ar,
            &ranlib,
            &ranlib_driver,
        )?;
        let python = resolve_tool(
            "WRELA_QEMU_PYTHON",
            &[
                "/opt/homebrew/bin/python3",
                "/usr/local/bin/python3",
                "/usr/bin/python3",
            ],
        )?;
        let python_runtime = resolve_python_runtime(&python)?;
        let mut tools = Self {
            curl: bootstrap.curl,
            gpg: bootstrap.gpg,
            xz: resolve_tool(
                "WRELA_QEMU_XZ",
                &["/opt/homebrew/bin/xz", "/usr/local/bin/xz", "/usr/bin/xz"],
            )?,
            bzip2: resolve_tool("WRELA_QEMU_BZIP2", &["/usr/bin/bzip2", "/bin/bzip2"])?,
            python,
            ninja: resolve_tool(
                "WRELA_QEMU_NINJA",
                &[
                    "/opt/homebrew/bin/ninja",
                    "/usr/local/bin/ninja",
                    "/usr/bin/ninja",
                ],
            )?,
            pkg_config: resolve_tool(
                "WRELA_QEMU_PKG_CONFIG",
                &[
                    "/opt/homebrew/bin/pkg-config",
                    "/usr/local/bin/pkg-config",
                    "/usr/bin/pkg-config",
                ],
            )?,
            cc,
            cxx,
            cxx_driver,
            linker,
            ar,
            ranlib,
            ranlib_driver,
            otool: resolve_tool("WRELA_QEMU_OTOOL", &["/usr/bin/otool"])?,
            codesign: resolve_tool("WRELA_QEMU_CODESIGN", &["/usr/bin/codesign"])?,
            touch: resolve_tool("WRELA_QEMU_TOUCH", &["/usr/bin/touch", "/bin/touch"])?,
            shell: identify_tool(Path::new("/bin/sh"))?,
            utilities: resolve_host_utilities()?,
            sysroot: resolve_apple_sysroot()?,
            apple_toolchain,
            python_runtime,
            host_system: resolve_host_system()?,
            dynamic_libraries: Vec::new(),
        };
        tools.dynamic_libraries = measure_dynamic_library_closure(&tools)?;
        Ok(tools)
    }
}

fn resolve_host_utilities() -> Result<Vec<(String, ToolIdentity)>, String> {
    HOST_UTILITY_CANDIDATES
        .iter()
        .map(|(name, candidates)| {
            let tool = candidates
                .iter()
                .map(Path::new)
                .find(|path| path.is_file())
                .ok_or_else(|| {
                    format!(
                        "cannot resolve controlled host utility {name:?} from reviewed candidates {candidates:?}"
                    )
                })?;
            Ok(((*name).to_owned(), identify_tool(tool)?))
        })
        .collect()
}

fn acquire_and_authenticate(
    root: &Path,
    lock: &EmulationLock,
    options: &Options,
    tools: &BootstrapTools,
) -> Result<AuthenticatedInputs, String> {
    let cache = root.join("build/toolchain/qemu/sources");
    let forbid_download = options.offline || options.plan;
    let archive = acquire_input(
        options.source_archive.as_deref(),
        &cache.join(format!("qemu-{}.tar.xz", lock.version)),
        &lock.source,
        MAX_ARCHIVE_BYTES,
        Some(&lock.source_sha256),
        forbid_download,
        &tools.curl,
        "QEMU source archive",
    )?;
    let signature = acquire_input(
        options.signature.as_deref(),
        &cache.join(format!("qemu-{}.tar.xz.sig", lock.version)),
        &lock.signature,
        MAX_SIGNATURE_BYTES,
        None,
        forbid_download,
        &tools.curl,
        "QEMU detached signature",
    )?;
    let key_url = format!("{QEMU_KEY_URL_PREFIX}{}", lock.signing_key_fingerprint);
    let signing_key = acquire_input(
        options.signing_key.as_deref(),
        &cache.join("qemu-signing-key.asc"),
        &key_url,
        MAX_KEY_BYTES,
        None,
        forbid_download,
        &tools.curl,
        "QEMU release signing key",
    )?;
    let archive_measurement = measure_file(&archive, MAX_ARCHIVE_BYTES, false)?;
    if archive_measurement.sha256 != lock.source_sha256 {
        return Err(format!(
            "QEMU source SHA-256 mismatch: expected {}, observed {}",
            lock.source_sha256, archive_measurement.sha256
        ));
    }
    let signature_measurement = measure_file(&signature, MAX_SIGNATURE_BYTES, false)?;
    let signing_key_measurement = measure_file(&signing_key, MAX_KEY_BYTES, false)?;
    let auth_parent = root.join("build/toolchain/qemu/auth");
    let signature_timestamp = verify_release_signature(
        &tools.gpg,
        &auth_parent,
        &signing_key,
        &signature,
        &archive,
        &lock.signing_key_fingerprint,
    )?;
    Ok(AuthenticatedInputs {
        archive,
        archive_measurement,
        signature,
        signature_measurement,
        signing_key,
        signing_key_measurement,
        signature_timestamp,
    })
}

#[allow(clippy::too_many_arguments)]
fn acquire_input(
    selected: Option<&Path>,
    cached: &Path,
    url: &str,
    maximum: u64,
    expected_sha256: Option<&str>,
    forbid_download: bool,
    curl: &ToolIdentity,
    label: &str,
) -> Result<PathBuf, String> {
    if let Some(path) = selected {
        let path = absolute_regular_file(path, label)?;
        validate_acquired_file(&path, maximum, expected_sha256, label)?;
        return Ok(path);
    }
    match fs::symlink_metadata(cached) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            validate_acquired_file(cached, maximum, expected_sha256, label)?;
            return Ok(cached.to_owned());
        }
        Ok(_) => return Err(format!("cached {label} is not a regular non-symlink file")),
        Err(error) if error.kind() != io::ErrorKind::NotFound => {
            return Err(format!("cannot inspect cached {label}: {error}"));
        }
        Err(_) => {}
    }
    if forbid_download {
        return Err(format!(
            "{label} is absent from {}; --plan/--offline never acquires network inputs",
            cached.display()
        ));
    }
    if !url.starts_with("https://") || url.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(format!("{label} URL is not exact HTTPS"));
    }
    let parent = cached
        .parent()
        .ok_or_else(|| format!("cached {label} has no parent"))?;
    ensure_directory(parent)?;
    let temporary = parent.join(format!(
        ".download-{}-{}",
        std::process::id(),
        NEXT_PRIVATE_DIRECTORY.fetch_add(1, Ordering::Relaxed)
    ));
    let mut command = Command::new(&curl.path);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/wrela/no-ambient-path")
        .env("TZ", "UTC")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--max-redirs",
            "3",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--output",
        ])
        .arg(&temporary)
        .arg(url);
    let output = run_bounded_output(&mut command, label, Duration::from_secs(30 * 60))?;
    if !output.status.success() || !output.stdout.is_empty() {
        let _ = fs::remove_file(&temporary);
        return Err(format!(
            "cannot acquire {label}: {}",
            bounded_text(&output.stderr)
        ));
    }
    if let Err(error) = validate_acquired_file(&temporary, maximum, expected_sha256, label) {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    match fs::rename(&temporary, cached) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&temporary);
            validate_acquired_file(cached, maximum, expected_sha256, label)?;
        }
        Err(error) => {
            let _ = fs::remove_file(&temporary);
            return Err(format!("cannot publish cached {label}: {error}"));
        }
    }
    sync_directory(parent)?;
    Ok(cached.to_owned())
}

fn validate_acquired_file(
    path: &Path,
    maximum: u64,
    expected_sha256: Option<&str>,
    label: &str,
) -> Result<FileMeasurement, String> {
    let measurement = measure_file(path, maximum, false)?;
    if expected_sha256.is_some_and(|expected| measurement.sha256 != expected) {
        return Err(format!(
            "{label} does not match its pinned SHA-256 at {}",
            path.display()
        ));
    }
    Ok(measurement)
}

fn verify_release_signature(
    gpg: &ToolIdentity,
    auth_parent: &Path,
    key: &Path,
    signature: &Path,
    archive: &Path,
    expected_fingerprint: &str,
) -> Result<u64, String> {
    let home = PrivateDirectory::create(auth_parent, "gnupg")?;
    #[cfg(unix)]
    fs::set_permissions(&home.path, fs::Permissions::from_mode(0o700)).map_err(|error| {
        format!(
            "cannot secure isolated GnuPG home {}: {error}",
            home.path.display()
        )
    })?;
    let common = [
        OsString::from("--batch"),
        OsString::from("--no-tty"),
        OsString::from("--no-options"),
        OsString::from("--homedir"),
        home.path.as_os_str().to_owned(),
    ];
    let mut import = Command::new(&gpg.path);
    import
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/wrela/no-ambient-path")
        .env("TZ", "UTC")
        .args(&common)
        .args([
            "--status-fd=1",
            "--import-options",
            "import-minimal",
            "--import",
        ])
        .arg(key);
    let imported = run_bounded_output(
        &mut import,
        "QEMU signing-key import",
        Duration::from_secs(60),
    )?;
    if !imported.status.success() {
        return Err(format!(
            "cannot import QEMU signing key: {}",
            bounded_text(&imported.stderr)
        ));
    }
    validate_import_status(&imported.stdout, expected_fingerprint)?;

    let mut list = Command::new(&gpg.path);
    list.env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/wrela/no-ambient-path")
        .env("TZ", "UTC")
        .args(&common)
        .args(["--with-colons", "--fixed-list-mode", "--list-keys"])
        .arg(expected_fingerprint);
    let listed = run_bounded_output(
        &mut list,
        "QEMU signing-key inventory",
        Duration::from_secs(60),
    )?;
    if !listed.status.success() {
        return Err("isolated QEMU signing-key inventory failed".to_owned());
    }
    let inventory = validate_key_inventory(&listed.stdout, expected_fingerprint)?;

    let mut verify = Command::new(&gpg.path);
    verify
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/wrela/no-ambient-path")
        .env("TZ", "UTC")
        .args(&common)
        .arg("--status-fd=1")
        .arg("--verify")
        .arg(signature)
        .arg(archive);
    let verified = run_bounded_output(
        &mut verify,
        "QEMU detached signature verification",
        Duration::from_secs(5 * 60),
    )?;
    validate_signature_status(
        &verified.stdout,
        verified.status.success(),
        expected_fingerprint,
        &inventory,
    )
}

fn validate_import_status(status: &[u8], expected_fingerprint: &str) -> Result<(), String> {
    let lines = gpg_status_lines(status)?;
    let mut import_count = 0usize;
    let mut imported_fingerprint = None;
    for line in &lines {
        match line.first().copied() {
            Some("IMPORT_OK") => {
                import_count = import_count
                    .checked_add(1)
                    .ok_or_else(|| "GnuPG import record count overflow".to_owned())?;
                imported_fingerprint = line.get(2).copied();
            }
            Some("IMPORT_PROBLEM" | "NODATA" | "FAILURE" | "ERROR") => {
                return Err("signing-key import emitted a failure status".to_owned());
            }
            _ => {}
        }
    }
    if import_count != 1 || imported_fingerprint != Some(expected_fingerprint) {
        return Err("signing-key import did not yield exactly the pinned fingerprint".to_owned());
    }
    Ok(())
}

fn validate_key_inventory(
    bytes: &[u8],
    expected_fingerprint: &str,
) -> Result<SigningKeyInventory, String> {
    let expected_key_id = primary_key_id_from_fingerprint(expected_fingerprint)?;
    let source =
        std::str::from_utf8(bytes).map_err(|_| "GnuPG key inventory is not UTF-8".to_owned())?;
    if source.contains('\0') || source.contains('\r') {
        return Err("GnuPG key inventory has noncanonical bytes".to_owned());
    }
    let mut record_count = 0usize;
    let mut primary_count = 0usize;
    let mut primary_key_id = None;
    let mut created_source = None;
    let mut expires_source = None;
    let mut in_primary = false;
    let mut primary_fingerprint_count = 0usize;
    let mut primary_fingerprint = None;
    for line in source.lines() {
        record_count = record_count
            .checked_add(1)
            .ok_or_else(|| "GnuPG key inventory record count overflow".to_owned())?;
        if record_count > MAX_GPG_RECORDS || line.len() > MAX_GPG_RECORD_BYTES || line.is_empty() {
            return Err("GnuPG key inventory exceeds its record bounds".to_owned());
        }
        if line.split(':').count() > MAX_GPG_FIELDS {
            return Err("GnuPG key inventory record exceeds its field limit".to_owned());
        }
        match colon_field(line, 0) {
            Some("pub") => {
                primary_count = primary_count
                    .checked_add(1)
                    .ok_or_else(|| "GnuPG primary key count overflow".to_owned())?;
                primary_key_id = colon_field(line, 4);
                created_source = colon_field(line, 5);
                expires_source = colon_field(line, 6);
                in_primary = true;
            }
            Some("sub") => in_primary = false,
            Some("sec" | "ssb") => {
                return Err(
                    "isolated public key inventory unexpectedly contains secret keys".to_owned(),
                );
            }
            Some("fpr") if in_primary => {
                primary_fingerprint_count = primary_fingerprint_count
                    .checked_add(1)
                    .ok_or_else(|| "GnuPG primary fingerprint count overflow".to_owned())?;
                primary_fingerprint = colon_field(line, 9);
            }
            _ => {}
        }
    }
    if record_count == 0 || primary_count != 1 {
        return Err("isolated keyring does not contain exactly the pinned primary key".to_owned());
    }
    let primary_key_id =
        primary_key_id.ok_or_else(|| "GnuPG primary key record omits its key ID".to_owned())?;
    if primary_key_id != expected_key_id
        || primary_key_id.len() != 16
        || !primary_key_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_lowercase())
    {
        return Err("isolated keyring primary key ID differs from the fingerprint pin".to_owned());
    }
    let created = parse_gpg_epoch(
        created_source
            .ok_or_else(|| "GnuPG primary key record omits its creation epoch".to_owned())?,
        "primary key creation",
    )?;
    let expires = parse_gpg_epoch(
        expires_source
            .ok_or_else(|| "GnuPG primary key record omits its expiry epoch".to_owned())?,
        "primary key expiry",
    )?;
    if expires <= created {
        return Err("GnuPG primary key expiry is not after its creation".to_owned());
    }
    if primary_fingerprint_count != 1 || primary_fingerprint != Some(expected_fingerprint) {
        return Err(
            "isolated keyring does not contain exactly the pinned primary fingerprint".to_owned(),
        );
    }
    Ok(SigningKeyInventory {
        primary_key_id: primary_key_id.to_owned(),
        created,
        expires,
    })
}

fn validate_signature_status(
    status: &[u8],
    command_succeeded: bool,
    expected_fingerprint: &str,
    inventory: &SigningKeyInventory,
) -> Result<u64, String> {
    let expected_key_id = primary_key_id_from_fingerprint(expected_fingerprint)?;
    if inventory.primary_key_id != expected_key_id
        || inventory.created == 0
        || inventory.expires <= inventory.created
    {
        return Err("QEMU signing-key inventory is not bound to the fingerprint pin".to_owned());
    }
    let lines = gpg_status_lines(status)?;
    if !command_succeeded {
        return Err("QEMU detached signature verification command failed".to_owned());
    }
    let mut good_count = 0usize;
    let mut good = None;
    let mut expired_count = 0usize;
    let mut expired = None;
    let mut key_expired_count = 0usize;
    let mut valid_count = 0usize;
    let mut valid = None;
    let mut newsig_count = 0usize;
    let mut sig_id_timestamp = None;
    for line in &lines {
        match line.first().copied() {
            Some(
                "BADSIG" | "ERRSIG" | "NO_PUBKEY" | "EXPSIG" | "REVKEYSIG" | "SIGEXPIRED"
                | "KEYREVOKED" | "NODATA" | "FAILURE" | "ERROR",
            ) => {
                return Err(format!(
                    "QEMU signature authentication rejected GnuPG status {}",
                    line.first().copied().unwrap_or("unknown")
                ));
            }
            Some("GOODSIG") => {
                good_count = good_count
                    .checked_add(1)
                    .ok_or_else(|| "QEMU GOODSIG count overflow".to_owned())?;
                good = Some(line);
            }
            Some("EXPKEYSIG") => {
                expired_count = expired_count
                    .checked_add(1)
                    .ok_or_else(|| "QEMU EXPKEYSIG count overflow".to_owned())?;
                expired = Some(line);
            }
            Some("KEYEXPIRED") => {
                key_expired_count = key_expired_count
                    .checked_add(1)
                    .ok_or_else(|| "QEMU KEYEXPIRED count overflow".to_owned())?;
                if line.len() != 2 {
                    return Err("QEMU KEYEXPIRED status is malformed".to_owned());
                }
                let expiry = parse_gpg_epoch(
                    line.get(1)
                        .copied()
                        .ok_or_else(|| "QEMU KEYEXPIRED status omits its epoch".to_owned())?,
                    "KEYEXPIRED epoch",
                )?;
                if expiry != inventory.expires {
                    return Err(
                        "QEMU KEYEXPIRED status differs from the primary key inventory".to_owned(),
                    );
                }
            }
            Some("VALIDSIG") => {
                valid_count = valid_count
                    .checked_add(1)
                    .ok_or_else(|| "QEMU VALIDSIG count overflow".to_owned())?;
                valid = Some(line);
            }
            Some("NEWSIG") => {
                newsig_count = newsig_count
                    .checked_add(1)
                    .ok_or_else(|| "QEMU NEWSIG count overflow".to_owned())?;
                if newsig_count != 1 || line.len() != 1 {
                    return Err("QEMU NEWSIG status is ambiguous or malformed".to_owned());
                }
            }
            Some("KEY_CONSIDERED") => {
                if line.len() != 3 || line.get(1).copied() != Some(expected_fingerprint) {
                    return Err(
                        "QEMU KEY_CONSIDERED status differs from the fingerprint pin".to_owned(),
                    );
                }
            }
            Some("SIG_ID") => {
                if line.len() != 4 || sig_id_timestamp.is_some() {
                    return Err("QEMU SIG_ID status is ambiguous or malformed".to_owned());
                }
                sig_id_timestamp = Some(parse_gpg_epoch(
                    line.get(3)
                        .copied()
                        .ok_or_else(|| "QEMU SIG_ID status omits its timestamp".to_owned())?,
                    "SIG_ID timestamp",
                )?);
            }
            Some(
                "TRUST_UNDEFINED" | "TRUST_NEVER" | "TRUST_MARGINAL" | "TRUST_FULLY"
                | "TRUST_ULTIMATE",
            ) => {}
            Some(keyword) => {
                return Err(format!(
                    "QEMU signature authentication rejected unrecognized GnuPG status {keyword}"
                ));
            }
            None => return Err("QEMU signature authentication saw an empty status".to_owned()),
        }
    }
    if valid_count != 1 {
        return Err("QEMU signature lacks exactly one VALIDSIG".to_owned());
    }
    let record = valid.ok_or_else(|| "QEMU signature omits VALIDSIG".to_owned())?;
    if record.len() != 11
        || record.get(1).copied() != Some(expected_fingerprint)
        || record.get(10).copied() != Some(expected_fingerprint)
    {
        return Err("QEMU signature was not made by the exact pinned primary key".to_owned());
    }
    let timestamp = record
        .get(3)
        .copied()
        .ok_or_else(|| "QEMU VALIDSIG omits signature timestamp".to_owned())?;
    let timestamp = parse_gpg_epoch(timestamp, "VALIDSIG timestamp")?;
    if timestamp < inventory.created || timestamp >= inventory.expires {
        return Err(format!(
            "QEMU signature timestamp {timestamp} is outside pinned primary-key validity [{}, {})",
            inventory.created, inventory.expires
        ));
    }
    if sig_id_timestamp.is_some_and(|sig_id| sig_id != timestamp) {
        return Err("QEMU SIG_ID and VALIDSIG timestamps differ".to_owned());
    }

    let current = good_count == 1 && expired_count == 0 && key_expired_count == 0;
    let historical = good_count == 0 && expired_count == 1 && key_expired_count != 0;
    if !current && !historical {
        return Err(
            "QEMU signature status is neither one exact current-key proof nor one exact historical-key proof"
                .to_owned(),
        );
    }
    let signature_record = if current {
        good.ok_or_else(|| "QEMU current signature omits GOODSIG".to_owned())?
    } else {
        expired.ok_or_else(|| "QEMU historical signature omits EXPKEYSIG".to_owned())?
    };
    if signature_record.get(1).copied() != Some(inventory.primary_key_id.as_str()) {
        return Err("QEMU signature status names a different primary key ID".to_owned());
    }
    Ok(timestamp)
}

fn parse_gpg_epoch(source: &str, label: &str) -> Result<u64, String> {
    let value = source
        .parse::<u64>()
        .map_err(|_| format!("GnuPG {label} is malformed"))?;
    if value == 0 || value.to_string() != source {
        return Err(format!("GnuPG {label} is not a canonical positive epoch"));
    }
    Ok(value)
}

fn primary_key_id_from_fingerprint(fingerprint: &str) -> Result<&str, String> {
    if fingerprint.len() != 40
        || !fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_lowercase())
    {
        return Err("pinned QEMU fingerprint is not exactly 40 uppercase hex digits".to_owned());
    }
    fingerprint
        .get(24..)
        .ok_or_else(|| "pinned QEMU fingerprint cannot yield a primary key ID".to_owned())
}

fn colon_field(record: &str, index: usize) -> Option<&str> {
    record.split(':').nth(index)
}

fn gpg_status_lines(bytes: &[u8]) -> Result<Vec<Vec<&str>>, String> {
    let source =
        std::str::from_utf8(bytes).map_err(|_| "GnuPG status stream is not UTF-8".to_owned())?;
    if source.contains('\0') || source.contains('\r') {
        return Err("GnuPG status stream has noncanonical bytes".to_owned());
    }
    let record_count = source.lines().count();
    if record_count == 0 || record_count > MAX_GPG_RECORDS {
        return Err("GnuPG status stream exceeds its record limit".to_owned());
    }
    let mut output = Vec::new();
    output
        .try_reserve_exact(record_count)
        .map_err(|_| "cannot reserve bounded GnuPG status records".to_owned())?;
    for line in source.lines() {
        if line.len() > MAX_GPG_RECORD_BYTES {
            return Err("GnuPG status record exceeds its byte limit".to_owned());
        }
        let body = line
            .strip_prefix("[GNUPG:] ")
            .ok_or_else(|| format!("unexpected non-status GnuPG output {line:?}"))?;
        if body.is_empty() {
            return Err("GnuPG emitted an empty status record".to_owned());
        }
        let field_count = body.split_ascii_whitespace().count();
        if field_count == 0 || field_count > MAX_GPG_FIELDS {
            return Err("GnuPG status record exceeds its field limit".to_owned());
        }
        let mut fields = Vec::new();
        fields
            .try_reserve_exact(field_count)
            .map_err(|_| "cannot reserve bounded GnuPG status fields".to_owned())?;
        fields.extend(body.split_ascii_whitespace());
        output.push(fields);
    }
    Ok(output)
}

fn resolve_tool(variable: &str, candidates: &[&str]) -> Result<ToolIdentity, String> {
    if let Some(value) = env::var_os(variable) {
        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Err(format!("{variable} must be an absolute executable path"));
        }
        return identify_tool(&path);
    }
    for candidate in candidates {
        let path = Path::new(candidate);
        if path.is_file() {
            return identify_tool(path);
        }
    }
    Err(format!(
        "cannot resolve {variable}; set it to an explicit absolute executable"
    ))
}

fn resolve_apple_tool(variable: &str, tool: &str) -> Result<ToolIdentity, String> {
    if let Some(value) = env::var_os(variable) {
        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Err(format!("{variable} must be absolute"));
        }
        return identify_tool(&path);
    }
    identify_tool(&xcrun_path(&["--find", tool])?)
}

fn resolve_apple_cxx() -> Result<(ToolIdentity, PathBuf), String> {
    let selected = match env::var_os("WRELA_QEMU_CXX") {
        Some(value) => PathBuf::from(value),
        None => xcrun_path(&["--find", "clang++"])?,
    };
    let identity = validate_apple_cxx_driver(&selected)?;
    Ok((identity, selected))
}

fn resolve_apple_ranlib() -> Result<(ToolIdentity, PathBuf), String> {
    let selected = match env::var_os("WRELA_QEMU_RANLIB") {
        Some(value) => PathBuf::from(value),
        None => xcrun_path(&["--find", "ranlib"])?,
    };
    let identity = validate_apple_ranlib_driver(&selected)?;
    Ok((identity, selected))
}

fn validate_apple_ranlib_driver(driver: &Path) -> Result<ToolIdentity, String> {
    if !driver.is_absolute() {
        return Err("WRELA_QEMU_RANLIB must be absolute".to_owned());
    }
    if driver.file_name() != Some(OsStr::new("ranlib")) {
        return Err(
            "WRELA_QEMU_RANLIB must preserve an exact ranlib invocation path; Apple's libtool selects archive-indexer mode from argv[0]"
                .to_owned(),
        );
    }
    let path = utf8_path(driver)?;
    if path.len() > MAX_PATH_BYTES || path.chars().any(char::is_control) {
        return Err("WRELA_QEMU_RANLIB path is malformed".to_owned());
    }
    let parent = driver
        .parent()
        .ok_or_else(|| "WRELA_QEMU_RANLIB has no parent directory".to_owned())?;
    let exact_parent = fs::canonicalize(parent).map_err(|error| {
        format!(
            "cannot resolve WRELA_QEMU_RANLIB parent {}: {error}",
            parent.display()
        )
    })?;
    if exact_parent != parent {
        return Err(
            "WRELA_QEMU_RANLIB parent must be an exact canonical directory so its driver path is unambiguous"
                .to_owned(),
        );
    }
    let metadata = fs::symlink_metadata(driver).map_err(|error| {
        format!(
            "cannot inspect WRELA_QEMU_RANLIB driver {}: {error}",
            driver.display()
        )
    })?;
    if !metadata.file_type().is_symlink() && !metadata.is_file() {
        return Err("WRELA_QEMU_RANLIB must name a regular executable or symbolic link".to_owned());
    }
    let identity = identify_tool(driver)?;
    if apple_toolchain_root(driver)? != apple_toolchain_root(&identity.path)? {
        return Err("QEMU ranlib driver resolves outside its Apple toolchain".to_owned());
    }
    Ok(identity)
}

fn validate_apple_cxx_driver(driver: &Path) -> Result<ToolIdentity, String> {
    if !driver.is_absolute() {
        return Err("WRELA_QEMU_CXX must be absolute".to_owned());
    }
    if driver.file_name() != Some(OsStr::new("clang++")) {
        return Err(
            "WRELA_QEMU_CXX must preserve an exact clang++ invocation path; the clang binary selects a different driver mode"
                .to_owned(),
        );
    }
    let path = utf8_path(driver)?;
    if path.len() > MAX_PATH_BYTES || path.chars().any(char::is_control) {
        return Err("WRELA_QEMU_CXX path is malformed".to_owned());
    }
    let parent = driver
        .parent()
        .ok_or_else(|| "WRELA_QEMU_CXX has no parent directory".to_owned())?;
    let exact_parent = fs::canonicalize(parent).map_err(|error| {
        format!(
            "cannot resolve WRELA_QEMU_CXX parent {}: {error}",
            parent.display()
        )
    })?;
    if exact_parent != parent {
        return Err(
            "WRELA_QEMU_CXX parent must be an exact canonical directory so its driver path is unambiguous"
                .to_owned(),
        );
    }
    let metadata = fs::symlink_metadata(driver).map_err(|error| {
        format!(
            "cannot inspect WRELA_QEMU_CXX driver {}: {error}",
            driver.display()
        )
    })?;
    if !metadata.file_type().is_symlink() && !metadata.is_file() {
        return Err("WRELA_QEMU_CXX must name a regular executable or symbolic link".to_owned());
    }
    let identity = identify_tool(driver)?;
    if apple_toolchain_root(driver)? != apple_toolchain_root(&identity.path)? {
        return Err("WRELA_QEMU_CXX driver resolves outside its Apple toolchain".to_owned());
    }
    Ok(identity)
}

fn resolve_apple_toolchain(
    cc: &ToolIdentity,
    cxx: &ToolIdentity,
    cxx_driver: &Path,
    linker: &ToolIdentity,
    ar: &ToolIdentity,
    ranlib: &ToolIdentity,
    ranlib_driver: &Path,
) -> Result<DirectoryIdentity, String> {
    let cc_toolchain = apple_toolchain_root(&cc.path)?;
    for tool in [cxx, linker, ar, ranlib] {
        if apple_toolchain_root(&tool.path)? != cc_toolchain {
            return Err(
                "QEMU compilers, linker, archiver, and indexer must come from one Apple toolchain"
                    .to_owned(),
            );
        }
    }
    if apple_toolchain_root(cxx_driver)? != cc_toolchain
        || validate_apple_cxx_driver(cxx_driver)? != *cxx
    {
        return Err(
            "QEMU C++ driver path does not identify the measured Apple compiler".to_owned(),
        );
    }
    if apple_toolchain_root(ranlib_driver)? != cc_toolchain
        || validate_apple_ranlib_driver(ranlib_driver)? != *ranlib
    {
        return Err(
            "QEMU ranlib invocation path does not identify the measured Apple archive indexer"
                .to_owned(),
        );
    }
    let cc_resource = clang_resource_directory(&cc.path, "C compiler")?;
    let cxx_resource = clang_resource_directory(cxx_driver, "C++ compiler")?;
    if cc_resource != cxx_resource {
        return Err("QEMU C and C++ compilers reported different resource directories".to_owned());
    }
    if !cc_resource.starts_with(&cc_toolchain) {
        return Err("QEMU compiler resource directory escapes its Apple toolchain".to_owned());
    }
    let resource = cc_resource
        .strip_prefix(&cc_toolchain)
        .map_err(|_| "QEMU compiler resource directory escaped its toolchain".to_owned())?;
    let resource = resource
        .to_str()
        .ok_or_else(|| "QEMU compiler resource path is not UTF-8".to_owned())?;
    let tree = measure_sdk_tree(&cc_toolchain)?;
    let mut digest = Sha256::new();
    let cxx_driver_relative = cxx_driver
        .strip_prefix(&cc_toolchain)
        .map_err(|_| "QEMU C++ driver escaped its Apple toolchain".to_owned())?
        .to_str()
        .ok_or_else(|| "QEMU C++ driver path is not UTF-8".to_owned())?;
    let ranlib_driver_relative = ranlib_driver
        .strip_prefix(&cc_toolchain)
        .map_err(|_| "QEMU ranlib driver escaped its Apple toolchain".to_owned())?
        .to_str()
        .ok_or_else(|| "QEMU ranlib driver path is not UTF-8".to_owned())?;
    digest.update(b"WRELQAPPLETOOLCHAIN\0\x03\0\0\0");
    update_length_prefixed(&mut digest, resource.as_bytes())?;
    update_length_prefixed(&mut digest, cxx_driver_relative.as_bytes())?;
    update_length_prefixed(&mut digest, ranlib_driver_relative.as_bytes())?;
    digest.update(hex_bytes(&tree.sha256)?);
    digest.update(tree.files.to_le_bytes());
    digest.update(tree.bytes.to_le_bytes());
    Ok(DirectoryIdentity {
        path: tree.path,
        sha256: lower_hex(&digest.finalize()),
        files: tree.files,
        bytes: tree.bytes,
    })
}

fn resolve_python_runtime(python: &ToolIdentity) -> Result<DirectoryIdentity, String> {
    let mut command = Command::new(&python.path);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/wrela/no-ambient-path")
        .env("TZ", "UTC")
        .args([
            "-I",
            "-S",
            "-c",
            "import sys; print(sys.base_prefix, end='')",
        ]);
    let output = run_bounded_output(
        &mut command,
        "Python runtime-directory probe",
        Duration::from_secs(60),
    )?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(format!(
            "Python runtime-directory probe failed: {}",
            bounded_text(&output.stderr)
        ));
    }
    let source = std::str::from_utf8(&output.stdout)
        .map_err(|_| "Python runtime-directory path is not UTF-8".to_owned())?;
    if source.is_empty()
        || source.len() > MAX_PATH_BYTES
        || source.contains(['\n', '\r', '\0'])
        || source.chars().any(char::is_control)
    {
        return Err("Python runtime-directory probe returned a malformed path".to_owned());
    }
    let base = exact_directory(Path::new(source), "Python base runtime")?;
    let root = python_formula_root(&base).unwrap_or_else(|| base.clone());
    let root = exact_directory(&root, "Python runtime closure")?;
    let tree = measure_sdk_tree(&root)?;
    let mut digest = Sha256::new();
    digest.update(b"WRELQPYTHONRUNTIME\0\x01\0\0\0");
    let base_relative = base
        .strip_prefix(&root)
        .map_err(|_| "Python base runtime escapes its measured closure".to_owned())?
        .to_str()
        .ok_or_else(|| "Python base runtime path is not UTF-8".to_owned())?;
    update_length_prefixed(&mut digest, base_relative.as_bytes())?;
    digest.update(hex_bytes(&tree.sha256)?);
    digest.update(tree.files.to_le_bytes());
    digest.update(tree.bytes.to_le_bytes());
    Ok(DirectoryIdentity {
        path: tree.path,
        sha256: lower_hex(&digest.finalize()),
        files: tree.files,
        bytes: tree.bytes,
    })
}

fn python_formula_root(base: &Path) -> Option<PathBuf> {
    base.ancestors()
        .find(|ancestor| {
            ancestor
                .parent()
                .and_then(Path::parent)
                .and_then(Path::file_name)
                == Some(OsStr::new("Cellar"))
        })
        .map(Path::to_owned)
}

fn resolve_host_system() -> Result<NativeFileIdentity, String> {
    let path = absolute_regular_file(
        Path::new("/System/Library/CoreServices/SystemVersion.plist"),
        "macOS system-build identity",
    )?;
    let measurement = measure_file(&path, 1024 * 1024, false)?;
    Ok(NativeFileIdentity {
        path,
        sha256: measurement.sha256,
        bytes: measurement.bytes,
    })
}

fn apple_toolchain_root(tool: &Path) -> Result<PathBuf, String> {
    tool.ancestors()
        .find(|ancestor| {
            ancestor
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".xctoolchain"))
        })
        .map(Path::to_owned)
        .ok_or_else(|| {
            format!(
                "QEMU native tool {} is not inside an Apple .xctoolchain",
                tool.display()
            )
        })
}

fn clang_resource_directory(tool: &Path, label: &str) -> Result<PathBuf, String> {
    let mut command = Command::new(tool);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/wrela/no-ambient-path")
        .env("TZ", "UTC")
        .arg("--print-resource-dir");
    let output = run_bounded_output(
        &mut command,
        &format!("{label} resource-directory probe"),
        Duration::from_secs(60),
    )?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(format!(
            "{label} resource-directory probe failed: {}",
            bounded_text(&output.stderr)
        ));
    }
    let source = std::str::from_utf8(&output.stdout)
        .map_err(|_| format!("{label} resource-directory path is not UTF-8"))?;
    let source = source.strip_suffix('\n').unwrap_or(source);
    if source.is_empty()
        || source.len() > MAX_PATH_BYTES
        || source.contains(['\n', '\r', '\0'])
        || source.chars().any(char::is_control)
    {
        return Err(format!(
            "{label} resource-directory probe returned a malformed path"
        ));
    }
    let path = PathBuf::from(source);
    if !path.is_absolute() {
        return Err(format!(
            "{label} resource-directory probe returned a relative path"
        ));
    }
    exact_directory(&path, &format!("{label} resource directory"))
}

fn xcrun_path(arguments: &[&str]) -> Result<PathBuf, String> {
    let xcrun = identify_tool(Path::new("/usr/bin/xcrun"))?;
    let mut command = Command::new(&xcrun.path);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/wrela/no-ambient-path")
        .env("TZ", "UTC")
        .args(arguments);
    let output = run_bounded_output(
        &mut command,
        "Apple tool selection",
        Duration::from_secs(60),
    )?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(format!(
            "Apple tool selection failed: {}",
            bounded_text(&output.stderr)
        ));
    }
    let source = std::str::from_utf8(&output.stdout)
        .map_err(|_| "Apple tool selection path is not UTF-8".to_owned())?;
    let path = PathBuf::from(source.trim_end());
    if !path.is_absolute() || source.trim_end().lines().count() != 1 {
        return Err("Apple tool selection returned a malformed path".to_owned());
    }
    Ok(path)
}

fn resolve_apple_sysroot() -> Result<DirectoryIdentity, String> {
    let selected = match env::var_os("WRELA_QEMU_SYSROOT") {
        Some(value) => {
            let path = PathBuf::from(value);
            if !path.is_absolute() {
                return Err("WRELA_QEMU_SYSROOT must be absolute".to_owned());
            }
            path
        }
        None => xcrun_path(&["--sdk", "macosx", "--show-sdk-path"])?,
    };
    let path = exact_directory(&selected, "macOS SDK")?;
    let mut digest = Sha256::new();
    digest.update(b"WRELQSDK\0\x04\0\0\0");
    let mut files = 0u64;
    let mut bytes = 0u64;
    for (relative, expected_link_target) in REQUIRED_SDK_INPUTS {
        let measurement = measure_sdk_input(&path, relative, *expected_link_target)?;
        update_length_prefixed(&mut digest, relative.as_bytes())?;
        digest.update(hex_bytes(&measurement.sha256)?);
        digest.update(measurement.bytes.to_le_bytes());
        files = files
            .checked_add(1)
            .ok_or_else(|| "SDK input file count overflow".to_owned())?;
        bytes = bytes
            .checked_add(measurement.bytes)
            .ok_or_else(|| "SDK input byte count overflow".to_owned())?;
    }
    for (framework, version) in REQUIRED_SDK_FRAMEWORK_INPUTS {
        let measurement = measure_sdk_framework(&path, framework, version)?;
        update_length_prefixed(&mut digest, framework.as_bytes())?;
        update_length_prefixed(&mut digest, version.as_bytes())?;
        digest.update(hex_bytes(&measurement.sha256)?);
        digest.update(measurement.bytes.to_le_bytes());
        files = files
            .checked_add(1)
            .ok_or_else(|| "SDK input file count overflow".to_owned())?;
        bytes = bytes
            .checked_add(measurement.bytes)
            .ok_or_else(|| "SDK input byte count overflow".to_owned())?;
    }
    for (relative, intermediate, final_target) in REQUIRED_SDK_ALIAS_INPUTS {
        let measurement = measure_sdk_alias_chain(&path, relative, intermediate, final_target)?;
        update_length_prefixed(&mut digest, relative.as_bytes())?;
        update_length_prefixed(&mut digest, intermediate.as_bytes())?;
        update_length_prefixed(&mut digest, final_target.as_bytes())?;
        digest.update(hex_bytes(&measurement.sha256)?);
        digest.update(measurement.bytes.to_le_bytes());
        files = files
            .checked_add(1)
            .ok_or_else(|| "SDK input file count overflow".to_owned())?;
        bytes = bytes
            .checked_add(measurement.bytes)
            .ok_or_else(|| "SDK input byte count overflow".to_owned())?;
    }
    let tree = measure_sdk_tree(&path)?;
    digest.update(files.to_le_bytes());
    digest.update(bytes.to_le_bytes());
    digest.update(hex_bytes(&tree.sha256)?);
    digest.update(tree.files.to_le_bytes());
    digest.update(tree.bytes.to_le_bytes());
    Ok(DirectoryIdentity {
        path,
        sha256: lower_hex(&digest.finalize()),
        files: tree.files,
        bytes: tree.bytes,
    })
}

fn measure_sdk_tree(root: &Path) -> Result<DirectoryIdentity, String> {
    let mut records = Vec::new();
    records
        .try_reserve(4096)
        .map_err(|_| "cannot reserve macOS SDK tree records".to_owned())?;
    let mut files = 0u64;
    let mut bytes = 0u64;
    walk_sdk_tree(root, root, "", 0, &mut files, &mut bytes, &mut records)?;
    records.sort_by(|left, right| left.path.cmp(&right.path));
    if records.is_empty()
        || records.windows(2).any(|pair| pair[0].path >= pair[1].path)
        || files != u64::try_from(records.len()).map_err(|_| "SDK tree size overflow".to_owned())?
        || bytes == 0
    {
        return Err("macOS SDK tree is empty, duplicated, or inconsistent".to_owned());
    }
    let mut digest = Sha256::new();
    digest.update(b"WRELQSDKTREE\0\x01\0\0\0");
    digest.update(files.to_le_bytes());
    digest.update(bytes.to_le_bytes());
    for record in records {
        update_length_prefixed(&mut digest, record.path.as_bytes())?;
        digest.update([record.kind, u8::from(record.executable)]);
        digest.update(record.bytes.to_le_bytes());
        digest.update(hex_bytes(&record.sha256)?);
    }
    Ok(DirectoryIdentity {
        path: root.to_owned(),
        sha256: lower_hex(&digest.finalize()),
        files,
        bytes,
    })
}

#[allow(clippy::too_many_arguments)]
fn walk_sdk_tree(
    root: &Path,
    directory: &Path,
    prefix: &str,
    depth: u32,
    files: &mut u64,
    bytes: &mut u64,
    records: &mut Vec<SdkTreeRecord>,
) -> Result<(), String> {
    if depth > MAX_TREE_DEPTH {
        return Err(format!("macOS SDK tree exceeds depth {MAX_TREE_DEPTH}"));
    }
    let before = fs::symlink_metadata(directory).map_err(|error| {
        format!(
            "cannot inspect SDK directory {}: {error}",
            directory.display()
        )
    })?;
    if before.file_type().is_symlink() || !before.is_dir() {
        return Err(format!(
            "SDK tree entry {} is not a regular directory",
            directory.display()
        ));
    }
    validate_safe_directory_mode(directory, &before)?;
    let mut entries = Vec::new();
    for entry in fs::read_dir(directory).map_err(|error| {
        format!(
            "cannot enumerate SDK directory {}: {error}",
            directory.display()
        )
    })? {
        let entry = entry.map_err(|error| format!("cannot enumerate SDK tree entry: {error}"))?;
        let name = entry.file_name().into_string().map_err(|_| {
            format!(
                "SDK tree contains a non-UTF-8 name in {}",
                directory.display()
            )
        })?;
        if !safe_sdk_component(&name) {
            return Err(format!("SDK tree contains unsafe component {name:?}"));
        }
        entries
            .try_reserve(1)
            .map_err(|_| "cannot grow SDK directory entries".to_owned())?;
        entries.push((name, entry.path()));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    for (name, path) in entries {
        let relative_bytes = prefix
            .len()
            .checked_add(usize::from(!prefix.is_empty()))
            .and_then(|size| size.checked_add(name.len()))
            .ok_or_else(|| "SDK tree path length overflow".to_owned())?;
        if relative_bytes > MAX_PATH_BYTES {
            return Err("SDK tree path exceeds its finite limit".to_owned());
        }
        let mut relative = String::new();
        relative
            .try_reserve_exact(relative_bytes)
            .map_err(|_| "cannot reserve SDK tree path".to_owned())?;
        if !prefix.is_empty() {
            relative.push_str(prefix);
            relative.push('/');
        }
        relative.push_str(&name);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect SDK tree entry {relative:?}: {error}"))?;
        if metadata.file_type().is_symlink() {
            let target = fs::read_link(&path)
                .map_err(|error| format!("cannot read SDK link {relative:?}: {error}"))?;
            let target_text = target
                .to_str()
                .ok_or_else(|| format!("SDK link {relative:?} is not UTF-8"))?;
            if target.is_absolute()
                || target_text.is_empty()
                || target_text.len() > MAX_PATH_BYTES
                || target_text.chars().any(char::is_control)
            {
                return Err(format!("SDK link {relative:?} has an unsafe target"));
            }
            let canonical = fs::canonicalize(&path)
                .map_err(|error| format!("cannot resolve SDK link {relative:?}: {error}"))?;
            if !canonical.starts_with(root) {
                return Err(format!("SDK link {relative:?} escapes the SDK root"));
            }
            let canonical_relative = canonical
                .strip_prefix(root)
                .map_err(|_| format!("SDK link {relative:?} escaped its root"))?;
            let canonical_text = canonical_relative
                .to_str()
                .ok_or_else(|| format!("SDK link {relative:?} resolves to non-UTF-8 path"))?;
            let after = fs::symlink_metadata(&path)
                .map_err(|error| format!("cannot re-inspect SDK link {relative:?}: {error}"))?;
            let target_after = fs::read_link(&path)
                .map_err(|error| format!("cannot re-read SDK link {relative:?}: {error}"))?;
            if !same_metadata(&metadata, &after)
                || target_after != target
                || fs::canonicalize(&path)
                    .map_err(|error| format!("cannot re-resolve SDK link {relative:?}: {error}"))?
                    != canonical
            {
                return Err(format!("SDK link {relative:?} changed while measured"));
            }
            let target_bytes = u64::try_from(target_text.len())
                .map_err(|_| "SDK link byte count overflow".to_owned())?;
            add_sdk_tree_record(
                files,
                bytes,
                records,
                SdkTreeRecord {
                    path: relative,
                    kind: 2,
                    bytes: target_bytes,
                    sha256: sdk_symlink_digest(target_text, canonical_text)?,
                    executable: false,
                },
            )?;
        } else if metadata.is_dir() {
            walk_sdk_tree(
                root,
                &path,
                &relative,
                depth.saturating_add(1),
                files,
                bytes,
                records,
            )?;
        } else if metadata.is_file() {
            let executable = is_executable(&metadata);
            let remaining = MAX_SDK_TREE_BYTES
                .checked_sub(*bytes)
                .ok_or_else(|| "SDK tree byte budget exhausted".to_owned())?;
            let measurement = measure_tree_file(&path, remaining, executable)?;
            add_sdk_tree_record(
                files,
                bytes,
                records,
                SdkTreeRecord {
                    path: relative,
                    kind: 1,
                    bytes: measurement.bytes,
                    sha256: measurement.sha256,
                    executable,
                },
            )?;
        } else {
            return Err(format!("SDK tree contains unsupported entry {relative:?}"));
        }
    }
    let after = fs::symlink_metadata(directory).map_err(|error| {
        format!(
            "cannot re-inspect SDK directory {}: {error}",
            directory.display()
        )
    })?;
    if !same_metadata(&before, &after) {
        return Err(format!(
            "SDK directory {} changed while measured",
            directory.display()
        ));
    }
    Ok(())
}

fn add_sdk_tree_record(
    files: &mut u64,
    bytes: &mut u64,
    records: &mut Vec<SdkTreeRecord>,
    record: SdkTreeRecord,
) -> Result<(), String> {
    *files = files
        .checked_add(1)
        .ok_or_else(|| "SDK tree file count overflow".to_owned())?;
    *bytes = bytes
        .checked_add(record.bytes)
        .ok_or_else(|| "SDK tree byte count overflow".to_owned())?;
    if *files > MAX_SDK_TREE_FILES || *bytes > MAX_SDK_TREE_BYTES {
        return Err("SDK tree exceeds its finite file or byte limit".to_owned());
    }
    records
        .try_reserve(1)
        .map_err(|_| "cannot grow SDK tree records".to_owned())?;
    records.push(record);
    Ok(())
}

fn sdk_symlink_digest(target: &str, canonical_target: &str) -> Result<String, String> {
    let mut digest = Sha256::new();
    digest.update(b"WRELQSDKSYMLINK\0\x01\0\0\0");
    update_length_prefixed(&mut digest, target.as_bytes())?;
    update_length_prefixed(&mut digest, canonical_target.as_bytes())?;
    Ok(lower_hex(&digest.finalize()))
}

fn safe_sdk_component(component: &str) -> bool {
    !component.is_empty()
        && component != "."
        && component != ".."
        && component.len() <= 255
        && !component.chars().any(char::is_control)
}

fn measure_sdk_alias_chain(
    root: &Path,
    relative: &str,
    intermediate: &str,
    final_target: &str,
) -> Result<FileMeasurement, String> {
    let relative_path = Path::new(relative);
    let parent_relative = relative_path
        .parent()
        .ok_or_else(|| format!("SDK alias {relative:?} has no parent"))?;
    let intermediate_relative = parent_relative.join(intermediate);
    let intermediate_relative = intermediate_relative
        .to_str()
        .ok_or_else(|| "SDK alias intermediate path is not UTF-8".to_owned())?;
    let (alias_before, alias_link) = inspect_exact_sdk_link(root, relative, intermediate)?;
    let (intermediate_before, intermediate_link) =
        inspect_exact_sdk_link(root, intermediate_relative, final_target)?;
    let final_path = root.join(parent_relative).join(final_target);
    let alias_path = root.join(relative_path);
    let canonical_alias = fs::canonicalize(&alias_path)
        .map_err(|error| format!("cannot resolve SDK alias {relative:?}: {error}"))?;
    if canonical_alias != final_path || !canonical_alias.starts_with(root) {
        return Err(format!(
            "SDK alias {relative:?} does not resolve to its exact pinned stub"
        ));
    }
    let measurement = measure_file(&final_path, MAX_SDK_INPUT_BYTES, false)?;
    let (alias_after, alias_link_after) = inspect_exact_sdk_link(root, relative, intermediate)?;
    let (intermediate_after, intermediate_link_after) =
        inspect_exact_sdk_link(root, intermediate_relative, final_target)?;
    if !same_metadata(&alias_before, &alias_after)
        || alias_link_after != alias_link
        || !same_metadata(&intermediate_before, &intermediate_after)
        || intermediate_link_after != intermediate_link
        || fs::canonicalize(&alias_path)
            .map_err(|error| format!("cannot re-resolve SDK alias {relative:?}: {error}"))?
            != canonical_alias
    {
        return Err(format!("SDK alias {relative:?} changed while measured"));
    }
    let link_bytes = alias_link
        .as_os_str()
        .as_encoded_bytes()
        .len()
        .checked_add(intermediate_link.as_os_str().as_encoded_bytes().len())
        .and_then(|size| u64::try_from(size).ok())
        .ok_or_else(|| "SDK alias link byte count overflow".to_owned())?;
    let bytes = measurement
        .bytes
        .checked_add(link_bytes)
        .ok_or_else(|| "SDK alias byte count overflow".to_owned())?;
    let mut digest = Sha256::new();
    digest.update(b"WRELQSDKALIAS\0\x01\0\0\0");
    update_length_prefixed(&mut digest, relative.as_bytes())?;
    update_length_prefixed(&mut digest, alias_link.as_os_str().as_encoded_bytes())?;
    update_length_prefixed(
        &mut digest,
        intermediate_link.as_os_str().as_encoded_bytes(),
    )?;
    digest.update(hex_bytes(&measurement.sha256)?);
    digest.update(measurement.bytes.to_le_bytes());
    Ok(FileMeasurement {
        sha256: lower_hex(&digest.finalize()),
        bytes,
    })
}

fn measure_sdk_framework(
    root: &Path,
    framework: &str,
    version: &str,
) -> Result<FileMeasurement, String> {
    if !portable_component(framework) || !portable_component(version) {
        return Err("unsafe required SDK framework identity".to_owned());
    }
    let base_relative = format!("System/Library/Frameworks/{framework}.framework");
    let top_relative = format!("{base_relative}/{framework}.tbd");
    let current_relative = format!("{base_relative}/Versions/Current");
    let final_relative = format!("{base_relative}/Versions/{version}/{framework}.tbd");
    let top_target = format!("Versions/Current/{framework}.tbd");
    let (top_before, top_link) = inspect_exact_sdk_link(root, &top_relative, &top_target)?;
    let (current_before, current_link) = inspect_exact_sdk_link(root, &current_relative, version)?;
    let top = root.join(&top_relative);
    let final_path = root.join(&final_relative);
    let canonical_top = fs::canonicalize(&top)
        .map_err(|error| format!("cannot resolve SDK framework {framework}: {error}"))?;
    if canonical_top != final_path || !canonical_top.starts_with(root) {
        return Err(format!(
            "SDK framework {framework} does not resolve to its exact pinned stub"
        ));
    }
    let measurement = measure_file(&final_path, MAX_SDK_INPUT_BYTES, false)?;
    let (top_after, top_link_after) = inspect_exact_sdk_link(root, &top_relative, &top_target)?;
    let (current_after, current_link_after) =
        inspect_exact_sdk_link(root, &current_relative, version)?;
    if !same_metadata(&top_before, &top_after)
        || top_link_after != top_link
        || !same_metadata(&current_before, &current_after)
        || current_link_after != current_link
        || fs::canonicalize(&top)
            .map_err(|error| format!("cannot re-resolve SDK framework {framework}: {error}"))?
            != canonical_top
    {
        return Err(format!(
            "SDK framework {framework} changed while being measured"
        ));
    }
    let link_bytes = top_link
        .as_os_str()
        .as_encoded_bytes()
        .len()
        .checked_add(current_link.as_os_str().as_encoded_bytes().len())
        .and_then(|size| u64::try_from(size).ok())
        .ok_or_else(|| "SDK framework link byte count overflow".to_owned())?;
    let bytes = measurement
        .bytes
        .checked_add(link_bytes)
        .ok_or_else(|| "SDK framework byte count overflow".to_owned())?;
    let mut digest = Sha256::new();
    digest.update(b"WRELQSDKFRAMEWORK\0\x01\0\0\0");
    update_length_prefixed(&mut digest, framework.as_bytes())?;
    update_length_prefixed(&mut digest, version.as_bytes())?;
    update_length_prefixed(&mut digest, top_link.as_os_str().as_encoded_bytes())?;
    update_length_prefixed(&mut digest, current_link.as_os_str().as_encoded_bytes())?;
    digest.update(hex_bytes(&measurement.sha256)?);
    digest.update(measurement.bytes.to_le_bytes());
    Ok(FileMeasurement {
        sha256: lower_hex(&digest.finalize()),
        bytes,
    })
}

fn inspect_exact_sdk_link(
    root: &Path,
    relative: &str,
    expected: &str,
) -> Result<(fs::Metadata, PathBuf), String> {
    if relative.is_empty()
        || relative.len() > MAX_PATH_BYTES
        || Path::new(relative).is_absolute()
        || !Path::new(relative)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(format!("unsafe SDK framework link path {relative:?}"));
    }
    validate_relative_link(relative, expected)
        .map_err(|error| format!("unsafe SDK framework link {relative:?}: {error}"))?;
    let path = root.join(relative);
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("cannot inspect SDK framework link {relative:?}: {error}"))?;
    if !metadata.file_type().is_symlink() {
        return Err(format!(
            "SDK framework input {relative:?} is not the required symbolic link"
        ));
    }
    let target = fs::read_link(&path)
        .map_err(|error| format!("cannot read SDK framework link {relative:?}: {error}"))?;
    if target.as_os_str().as_encoded_bytes() != expected.as_bytes() {
        return Err(format!(
            "SDK framework link {relative:?} does not match its pinned target"
        ));
    }
    Ok((metadata, target))
}

fn measure_sdk_input(
    root: &Path,
    relative: &str,
    expected_link_target: Option<&str>,
) -> Result<FileMeasurement, String> {
    if relative.is_empty()
        || relative.len() > MAX_PATH_BYTES
        || Path::new(relative).is_absolute()
        || !Path::new(relative)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
    {
        return Err(format!("unsafe macOS SDK input path {relative:?}"));
    }
    let input = root.join(relative);
    let Some(expected_link_target) = expected_link_target else {
        return measure_file(&input, MAX_SDK_INPUT_BYTES, false);
    };
    let before = fs::symlink_metadata(&input)
        .map_err(|error| format!("cannot inspect SDK input {}: {error}", input.display()))?;
    if !before.file_type().is_symlink() {
        return Err(format!(
            "SDK input {} is not the required symbolic link",
            input.display()
        ));
    }
    let link = fs::read_link(&input)
        .map_err(|error| format!("cannot read SDK link {}: {error}", input.display()))?;
    let link_text = link
        .to_str()
        .ok_or_else(|| format!("SDK link {} is not UTF-8", input.display()))?;
    if link_text.len() > MAX_SDK_LINK_BYTES {
        return Err(format!(
            "SDK link {} exceeds {MAX_SDK_LINK_BYTES} bytes",
            input.display()
        ));
    }
    validate_relative_link(relative, link_text)
        .map_err(|error| format!("unsafe SDK link {}: {error}", input.display()))?;
    if link_text != expected_link_target {
        return Err(format!(
            "SDK link {} has target {link_text:?}, expected {expected_link_target:?}",
            input.display()
        ));
    }
    let parent = input
        .parent()
        .ok_or_else(|| format!("SDK input {} has no parent", input.display()))?;
    let target = parent.join(&link);
    if !target.starts_with(root) {
        return Err(format!("SDK link {} escapes the SDK", input.display()));
    }
    let canonical_target = fs::canonicalize(&target)
        .map_err(|error| format!("cannot resolve SDK link {}: {error}", input.display()))?;
    if canonical_target != target || !canonical_target.starts_with(root) {
        return Err(format!(
            "SDK link {} does not resolve directly to its exact internal target",
            input.display()
        ));
    }
    let target_metadata = fs::symlink_metadata(&target)
        .map_err(|error| format!("cannot inspect SDK target {}: {error}", target.display()))?;
    if target_metadata.file_type().is_symlink() || !target_metadata.is_file() {
        return Err(format!(
            "SDK link {} target is not a direct regular file",
            input.display()
        ));
    }
    let target_measurement = measure_file(&target, MAX_SDK_INPUT_BYTES, false)?;
    let after = fs::symlink_metadata(&input)
        .map_err(|error| format!("cannot re-inspect SDK link {}: {error}", input.display()))?;
    let link_after = fs::read_link(&input)
        .map_err(|error| format!("cannot re-read SDK link {}: {error}", input.display()))?;
    let canonical_after = fs::canonicalize(&target)
        .map_err(|error| format!("cannot re-resolve SDK link {}: {error}", input.display()))?;
    if !same_metadata(&before, &after) || link_after != link || canonical_after != canonical_target
    {
        return Err(format!(
            "SDK link {} changed while being measured",
            input.display()
        ));
    }

    let link_bytes = u64::try_from(link_text.len())
        .map_err(|_| "SDK link byte count exceeds this host".to_owned())?;
    let bytes = target_measurement
        .bytes
        .checked_add(link_bytes)
        .ok_or_else(|| "SDK input byte count overflow".to_owned())?;
    let mut digest = Sha256::new();
    digest.update(b"WRELQSDKLINK\0\x01\0\0\0");
    update_length_prefixed(&mut digest, link_text.as_bytes())?;
    digest.update(hex_bytes(&target_measurement.sha256)?);
    digest.update(target_measurement.bytes.to_le_bytes());
    Ok(FileMeasurement {
        sha256: lower_hex(&digest.finalize()),
        bytes,
    })
}

fn identify_tool(path: &Path) -> Result<ToolIdentity, String> {
    let path = fs::canonicalize(path)
        .map_err(|error| format!("cannot resolve native tool {}: {error}", path.display()))?;
    let measurement = measure_file(&path, 2 * 1024 * 1024 * 1024, true)?;
    Ok(ToolIdentity {
        path,
        sha256: measurement.sha256,
        bytes: measurement.bytes,
    })
}

fn measure_dynamic_library_closure(tools: &BuildTools) -> Result<Vec<NativeFileIdentity>, String> {
    let mut pending = BTreeSet::new();
    for tool in native_tool_roots(tools)? {
        pending.insert(tool.path.clone());
    }
    let mut inspected = BTreeSet::new();
    let mut native_libraries = BTreeSet::new();
    while let Some(path) = pending.pop_first() {
        if !inspected.insert(path.clone()) {
            continue;
        }
        if inspected.len() > MAX_NATIVE_LIBRARIES {
            return Err(format!(
                "native Mach-O closure exceeds {MAX_NATIVE_LIBRARIES} files"
            ));
        }
        for dependency in macho_load_dependencies(&tools.otool, &path)? {
            if dependency.starts_with("/usr/lib/") || dependency.starts_with("/System/Library/") {
                continue;
            }
            let dependency =
                resolve_native_dependency(&path, &dependency, &tools.apple_toolchain.path)?;
            if homebrew_path(&dependency) {
                native_libraries.insert(dependency.clone());
            }
            pending.insert(dependency);
        }
    }
    if native_libraries.len() > MAX_NATIVE_LIBRARIES {
        return Err(format!(
            "native dynamic-library closure exceeds {MAX_NATIVE_LIBRARIES} files"
        ));
    }
    let mut identities = Vec::new();
    identities
        .try_reserve_exact(native_libraries.len())
        .map_err(|_| "cannot reserve native dynamic-library identities".to_owned())?;
    let mut bytes = 0u64;
    for path in native_libraries {
        let remaining = MAX_NATIVE_LIBRARY_BYTES
            .checked_sub(bytes)
            .ok_or_else(|| "native dynamic-library byte budget exhausted".to_owned())?;
        let measurement = measure_file(&path, remaining, false)?;
        bytes = bytes
            .checked_add(measurement.bytes)
            .ok_or_else(|| "native dynamic-library byte count overflow".to_owned())?;
        identities.push(NativeFileIdentity {
            path,
            sha256: measurement.sha256,
            bytes: measurement.bytes,
        });
    }
    Ok(identities)
}

fn native_tool_roots(tools: &BuildTools) -> Result<Vec<&ToolIdentity>, String> {
    let count = tool_inventory(tools)
        .len()
        .checked_add(tools.utilities.len())
        .ok_or_else(|| "native tool-root count overflow".to_owned())?;
    let mut roots = Vec::new();
    roots
        .try_reserve_exact(count)
        .map_err(|_| "cannot reserve native tool roots".to_owned())?;
    roots.extend(tool_inventory(tools).into_iter().map(|(_, tool)| tool));
    roots.extend(tools.utilities.iter().map(|(_, tool)| tool));
    Ok(roots)
}

fn macho_load_dependencies(otool: &ToolIdentity, path: &Path) -> Result<BTreeSet<String>, String> {
    let mut command = Command::new(&otool.path);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/wrela/no-ambient-path")
        .env("TZ", "UTC")
        .args([OsStr::new("-L"), path.as_os_str()]);
    let output = run_bounded_output(
        &mut command,
        "native Mach-O closure inspection",
        Duration::from_secs(60),
    )?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(format!(
            "cannot inspect native Mach-O closure for {}: {}",
            path.display(),
            bounded_text(&output.stderr)
        ));
    }
    let source = std::str::from_utf8(&output.stdout)
        .map_err(|_| "native Mach-O dependency inventory is not UTF-8".to_owned())?;
    if source.is_empty() || source.contains(['\r', '\0']) {
        return Err("native Mach-O dependency inventory is malformed".to_owned());
    }
    let mut dependencies = BTreeSet::new();
    let mut headers = 0usize;
    for line in source.lines() {
        if !line.starts_with('\t') {
            if line.is_empty() || !line.ends_with(':') {
                return Err(format!(
                    "malformed native Mach-O dependency header {line:?}"
                ));
            }
            headers = headers
                .checked_add(1)
                .ok_or_else(|| "native Mach-O header count overflow".to_owned())?;
            continue;
        }
        let entry = line
            .strip_prefix('\t')
            .ok_or_else(|| "malformed native Mach-O dependency indentation".to_owned())?;
        let (dependency, versions) = entry
            .split_once(" (compatibility version ")
            .ok_or_else(|| format!("malformed native Mach-O dependency line {line:?}"))?;
        if dependency.is_empty()
            || dependency.len() > MAX_PATH_BYTES
            || dependency.chars().any(char::is_control)
            || !versions.ends_with(')')
            || !versions.contains(", current version ")
        {
            return Err(format!("malformed native Mach-O dependency line {line:?}"));
        }
        dependencies.insert(dependency.to_owned());
        if dependencies.len() > 256 {
            return Err("native Mach-O file has more than 256 dependencies".to_owned());
        }
    }
    if headers == 0 || dependencies.is_empty() {
        return Err("native Mach-O dependency inventory is empty".to_owned());
    }
    Ok(dependencies)
}

fn resolve_native_dependency(
    origin: &Path,
    dependency: &str,
    apple_toolchain: &Path,
) -> Result<PathBuf, String> {
    let candidate = if let Some(relative) = dependency.strip_prefix("@rpath/") {
        if !origin.starts_with(apple_toolchain) || !safe_native_relative_path(relative) {
            return Err(format!(
                "unresolved native @rpath dependency {dependency:?} from {}",
                origin.display()
            ));
        }
        apple_toolchain.join("usr/lib").join(relative)
    } else if let Some(relative) = dependency.strip_prefix("@loader_path/") {
        if relative.is_empty()
            || relative.len() > MAX_PATH_BYTES
            || relative.contains(['\r', '\n', '\0'])
        {
            return Err(format!("unsafe native loader dependency {dependency:?}"));
        }
        origin
            .parent()
            .ok_or_else(|| format!("native Mach-O file {} has no parent", origin.display()))?
            .join(relative)
    } else {
        let path = PathBuf::from(dependency);
        if !path.is_absolute() {
            return Err(format!("unsupported native dependency {dependency:?}"));
        }
        path
    };
    let candidate = fs::canonicalize(&candidate).map_err(|error| {
        format!(
            "cannot resolve native dependency {dependency:?} from {}: {error}",
            origin.display()
        )
    })?;
    let metadata = fs::symlink_metadata(&candidate).map_err(|error| {
        format!(
            "cannot inspect native dependency {}: {error}",
            candidate.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!(
            "native dependency {} is not a regular file",
            candidate.display()
        ));
    }
    if !candidate.starts_with(apple_toolchain) && !homebrew_path(&candidate) {
        return Err(format!(
            "native dependency {} escapes the measured Apple/Homebrew closure",
            candidate.display()
        ));
    }
    Ok(candidate)
}

fn homebrew_path(path: &Path) -> bool {
    path.starts_with("/opt/homebrew/Cellar") || path.starts_with("/usr/local/Cellar")
}

fn safe_native_relative_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_PATH_BYTES
        && Path::new(path)
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
        && !path.chars().any(char::is_control)
}

fn absolute_regular_file(path: &Path, label: &str) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err(format!("{label} must be an absolute path"));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {label} {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!("{label} must be a regular non-symlink file"));
    }
    Ok(path.to_owned())
}

fn measure_pkg_config_modules(tools: &BuildTools) -> Result<Vec<PkgConfigModule>, String> {
    let mut modules = Vec::new();
    modules
        .try_reserve_exact(REQUIRED_PKG_CONFIG_MODULES.len())
        .map_err(|_| "cannot reserve pkg-config module identities".to_owned())?;
    for name in REQUIRED_PKG_CONFIG_MODULES {
        let mut command = Command::new(&tools.pkg_config.path);
        command
            .env_clear()
            .env("LC_ALL", "C")
            .env("PATH", "/wrela/no-ambient-path")
            .env("TZ", "UTC")
            .args(["--variable=pcfiledir", name]);
        let output = run_bounded_output(
            &mut command,
            "QEMU pkg-config module location",
            Duration::from_secs(60),
        )?;
        if !output.status.success() || !output.stderr.is_empty() {
            return Err(format!(
                "cannot locate required pkg-config module {name:?}: {}",
                bounded_text(&output.stderr)
            ));
        }
        let source = std::str::from_utf8(&output.stdout)
            .map_err(|_| format!("pkg-config location for {name:?} is not UTF-8"))?;
        let directory = source
            .strip_suffix('\n')
            .ok_or_else(|| format!("pkg-config location for {name:?} is not canonical text"))?;
        if directory.is_empty() || directory.contains(['\n', '\r', '\0']) {
            return Err(format!(
                "pkg-config location for {name:?} is not one exact path"
            ));
        }
        let directory =
            exact_directory(Path::new(directory), "required pkg-config module directory")?;
        let filename = format!("{name}.pc");
        let path = fs::canonicalize(directory.join(&filename)).map_err(|error| {
            format!("cannot resolve required pkg-config module {name:?}: {error}")
        })?;
        if path.parent() != Some(directory.as_path())
            || path.file_name() != Some(OsStr::new(&filename))
        {
            return Err(format!(
                "pkg-config module {name:?} escapes its measured package directory"
            ));
        }
        let path = absolute_regular_file(&path, "required pkg-config module")?;
        let measurement = measure_file(&path, MAX_PKG_CONFIG_FILE_BYTES, false)?;
        modules.push(PkgConfigModule {
            name: (*name).to_owned(),
            path,
            measurement,
        });
    }
    Ok(modules)
}

fn pkg_config_search_path(modules: &[PkgConfigModule]) -> Result<OsString, String> {
    let mut directories = BTreeSet::new();
    for module in modules {
        let directory = module
            .path
            .parent()
            .ok_or_else(|| format!("pkg-config module {:?} has no parent", module.name))?;
        directories.insert(directory);
    }
    env::join_paths(directories)
        .map_err(|error| format!("cannot represent controlled pkg-config search path: {error}"))
}

fn measure_static_dependency_contract(
    tools: &BuildTools,
) -> Result<StaticDependencyContract, String> {
    let pkg_config_modules = measure_pkg_config_modules(tools)?;
    let pkg_config_libdir = pkg_config_search_path(&pkg_config_modules)?;
    let mut command = Command::new(&tools.pkg_config.path);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/wrela/no-ambient-path")
        .env("PKG_CONFIG_ALLOW_SYSTEM_CFLAGS", "1")
        .env("PKG_CONFIG_ALLOW_SYSTEM_LIBS", "1")
        .env("PKG_CONFIG_LIBDIR", pkg_config_libdir)
        .env("TZ", "UTC")
        .args(["--static", "--cflags", "--libs", "glib-2.0", "libfdt"]);
    let output = run_bounded_output(
        &mut command,
        "QEMU static dependency closure",
        Duration::from_secs(60),
    )?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(format!(
            "static QEMU dependency query failed: {}",
            bounded_text(&output.stderr)
        ));
    }
    let source = std::str::from_utf8(&output.stdout)
        .map_err(|_| "static dependency response is not UTF-8".to_owned())?;
    if source.contains(['\r', '\0', '\'', '"', '`', '$']) {
        return Err("static dependency response contains unsafe shell syntax".to_owned());
    }
    let mut arguments = Vec::new();
    arguments
        .try_reserve(64)
        .map_err(|_| "cannot reserve static dependency arguments".to_owned())?;
    for argument in source.split_ascii_whitespace() {
        if arguments.len() >= 4096 {
            return Err("static dependency response has more than 4096 arguments".to_owned());
        }
        arguments
            .try_reserve(1)
            .map_err(|_| "cannot reserve static dependency argument".to_owned())?;
        arguments.push(argument);
    }
    if arguments.is_empty() {
        return Err("static dependency response is empty or oversized".to_owned());
    }
    validate_static_dependency_arguments(&arguments)?;
    let mut includes = BTreeSet::new();
    let mut library_dirs = BTreeSet::new();
    for argument in &arguments {
        if let Some(path) = argument.strip_prefix("-I") {
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                return Err("pkg-config returned a non-absolute include directory".to_owned());
            }
            includes.insert(exact_directory(
                &path,
                "static dependency include directory",
            )?);
        } else if let Some(path) = argument.strip_prefix("-L") {
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                return Err("pkg-config returned a non-absolute library directory".to_owned());
            }
            let directory = exact_directory(&path, "static dependency library directory")?;
            library_dirs.insert(directory);
        }
    }
    let mut static_libraries = BTreeSet::new();
    for argument in &arguments {
        let Some(name) = argument.strip_prefix("-l") else {
            continue;
        };
        if !ALLOWED_PKG_CONFIG_LIBRARIES.contains(&name) {
            return Err(format!("invalid pkg-config library argument {argument:?}"));
        }
        let library = library_dirs
            .iter()
            .map(|directory| directory.join(format!("lib{name}.a")))
            .find(|candidate| candidate.is_file());
        if let Some(library) = library {
            static_libraries.insert(fs::canonicalize(&library).map_err(|error| {
                format!(
                    "cannot resolve static library {}: {error}",
                    library.display()
                )
            })?);
        } else if !SDK_PROVIDED_LIBRARIES.contains(&name) {
            return Err(format!(
                "Homebrew dependency {name:?} has no static archive; a self-contained QEMU cannot be built"
            ));
        }
    }
    for required in REQUIRED_STATIC_LIBRARIES {
        if !static_libraries
            .iter()
            .any(|path| path.file_name() == Some(OsStr::new(&format!("lib{required}.a"))))
        {
            return Err(format!(
                "static dependency closure omits required lib{required}.a"
            ));
        }
    }
    let mut digest = Sha256::new();
    digest.update(b"WRELQDEP\0\x03\0\0\0");
    update_length_prefixed(&mut digest, source.as_bytes())?;
    update_length_prefixed(&mut digest, b"zlib")?;
    update_length_prefixed(&mut digest, ZLIB_PKG_CONFIG)?;
    for module in &pkg_config_modules {
        update_length_prefixed(&mut digest, module.name.as_bytes())?;
        update_length_prefixed(&mut digest, utf8_path(&module.path)?.as_bytes())?;
        digest.update(hex_bytes(&module.measurement.sha256)?);
        digest.update(module.measurement.bytes.to_le_bytes());
    }
    for directory in &includes {
        let identity = measure_directory_identity(directory, 100_000, 2 * 1024 * 1024 * 1024)?;
        update_length_prefixed(&mut digest, utf8_path(directory)?.as_bytes())?;
        digest.update(hex_bytes(&identity.sha256)?);
        digest.update(identity.files.to_le_bytes());
        digest.update(identity.bytes.to_le_bytes());
    }
    for library in static_libraries {
        let measurement = measure_file(&library, 2 * 1024 * 1024 * 1024, false)?;
        update_length_prefixed(&mut digest, utf8_path(&library)?.as_bytes())?;
        digest.update(hex_bytes(&measurement.sha256)?);
        digest.update(measurement.bytes.to_le_bytes());
    }
    Ok(StaticDependencyContract {
        sha256: lower_hex(&digest.finalize()),
        include_directories: includes.into_iter().collect(),
        library_directories: library_dirs.into_iter().collect(),
        pkg_config_modules,
    })
}

fn validate_static_dependency_arguments(arguments: &[&str]) -> Result<(), String> {
    let mut index = 0usize;
    while index < arguments.len() {
        let argument = arguments[index];
        if let Some(path) = argument
            .strip_prefix("-I")
            .or_else(|| argument.strip_prefix("-L"))
        {
            if !valid_pkg_config_absolute_path(path) {
                return Err(format!(
                    "invalid pkg-config directory argument {argument:?}"
                ));
            }
        } else if let Some(name) = argument.strip_prefix("-l") {
            if !ALLOWED_PKG_CONFIG_LIBRARIES.contains(&name) {
                return Err(format!("invalid pkg-config library argument {argument:?}"));
            }
        } else if argument == "-pthread" {
        } else if argument == "-framework" {
            index = index
                .checked_add(1)
                .ok_or_else(|| "pkg-config argument index overflow".to_owned())?;
            let framework = arguments
                .get(index)
                .ok_or_else(|| "pkg-config -framework has no name".to_owned())?;
            if !ALLOWED_PKG_CONFIG_FRAMEWORKS.contains(framework) {
                return Err(format!(
                    "invalid pkg-config framework argument {framework:?}"
                ));
            }
        } else {
            return Err(format!("unreviewed pkg-config argument {argument:?}"));
        }
        index = index
            .checked_add(1)
            .ok_or_else(|| "pkg-config argument index overflow".to_owned())?;
    }
    Ok(())
}

fn valid_pkg_config_absolute_path(path: &str) -> bool {
    path.len() <= MAX_PATH_BYTES
        && path.starts_with('/')
        && path.len() > 1
        && path[1..].split('/').all(portable_component)
}

fn append_dependency_search_directories(
    flags: &mut String,
    option: &str,
    directories: &[PathBuf],
) -> Result<(), String> {
    for directory in directories {
        let path = utf8_path(directory)?;
        if !valid_pkg_config_absolute_path(path) {
            return Err(format!(
                "static dependency search directory cannot be represented safely: {path:?}"
            ));
        }
        flags
            .try_reserve(
                1usize
                    .checked_add(option.len())
                    .and_then(|size| size.checked_add(path.len()))
                    .ok_or_else(|| "static dependency search flags are oversized".to_owned())?,
            )
            .map_err(|_| "cannot reserve static dependency search flags".to_owned())?;
        flags.push(' ');
        flags.push_str(option);
        flags.push_str(path);
    }
    Ok(())
}

fn prepare_controlled_pkg_config(
    build: &Path,
    contract: &StaticDependencyContract,
) -> Result<PathBuf, String> {
    let directory = build.join("wrela-pkg-config");
    create_private_directory(&directory).map_err(|error| {
        format!(
            "cannot create controlled pkg-config directory {}: {error}",
            directory.display()
        )
    })?;
    for module in &contract.pkg_config_modules {
        let bytes = read_bounded_file(&module.path, MAX_PKG_CONFIG_FILE_BYTES)?;
        let observed = FileMeasurement {
            sha256: sha256_bytes(&bytes),
            bytes: u64::try_from(bytes.len())
                .map_err(|_| "pkg-config module size overflow".to_owned())?,
        };
        if observed != module.measurement {
            return Err(format!(
                "pkg-config module {:?} changed before isolation",
                module.name
            ));
        }
        let filename = format!("{}.pc", module.name);
        let destination = directory.join(filename);
        write_new_file(&destination, &bytes, 0o600)?;
        if measure_file(&destination, MAX_PKG_CONFIG_FILE_BYTES, false)? != module.measurement {
            return Err(format!(
                "isolated pkg-config module {:?} changed while copied",
                module.name
            ));
        }
    }
    let zlib = directory.join("zlib.pc");
    write_new_file(&zlib, ZLIB_PKG_CONFIG, 0o600)?;
    let expected_zlib = FileMeasurement {
        sha256: sha256_bytes(ZLIB_PKG_CONFIG),
        bytes: u64::try_from(ZLIB_PKG_CONFIG.len())
            .map_err(|_| "generated zlib pkg-config module size overflow".to_owned())?,
    };
    if measure_file(&zlib, MAX_PKG_CONFIG_FILE_BYTES, false)? != expected_zlib {
        return Err("generated zlib pkg-config module changed while written".to_owned());
    }
    sync_directory(&directory)?;
    Ok(directory)
}

fn implementation_digest(root: &Path) -> Result<String, String> {
    let runtime_qemu = read_bounded_file(&root.join("xtask/src/qemu.rs"), 8 * 1024 * 1024)?;
    let runtime_main = read_bounded_file(&root.join("xtask/src/main.rs"), 4 * 1024 * 1024)?;
    let runtime_manifest = read_bounded_file(&root.join("xtask/Cargo.toml"), 1024 * 1024)?;
    let runtime_lock = read_bounded_file(&root.join("Cargo.lock"), 16 * 1024 * 1024)?;
    implementation_digest_from_sources(
        BootstrapSources {
            qemu: &runtime_qemu,
            main: &runtime_main,
            manifest: &runtime_manifest,
            cargo_lock: &runtime_lock,
        },
        BootstrapSources {
            qemu: include_bytes!("qemu.rs"),
            main: include_bytes!("main.rs"),
            manifest: include_bytes!("../Cargo.toml"),
            cargo_lock: include_bytes!("../../Cargo.lock"),
        },
    )
}

fn implementation_digest_from_sources(
    runtime: BootstrapSources<'_>,
    compiled: BootstrapSources<'_>,
) -> Result<String, String> {
    let runtime = implementation_projection(runtime)?;
    let compiled = implementation_projection(compiled)?;
    for (label, runtime_digest, compiled_digest) in [
        (
            "xtask/src/qemu.rs",
            &runtime.qemu_source_sha256,
            &compiled.qemu_source_sha256,
        ),
        (
            "the QEMU dispatch contract in xtask/src/main.rs",
            &runtime.dispatch_sha256,
            &compiled.dispatch_sha256,
        ),
        (
            "the QEMU dependency declaration in xtask/Cargo.toml",
            &runtime.manifest_sha256,
            &compiled.manifest_sha256,
        ),
        (
            "the QEMU bootstrap dependency closure in Cargo.lock",
            &runtime.dependency_closure_sha256,
            &compiled.dependency_closure_sha256,
        ),
    ] {
        if runtime_digest != compiled_digest {
            return Err(format!(
                "running xtask is stale relative to {label}; rebuild it before QEMU bootstrap"
            ));
        }
    }
    compiled.digest()
}

fn implementation_projection(
    sources: BootstrapSources<'_>,
) -> Result<BootstrapImplementationProjection, String> {
    Ok(BootstrapImplementationProjection {
        qemu_source_sha256: sha256_bytes(sources.qemu),
        dispatch_sha256: qemu_dispatch_contract_digest(sources.main)?,
        manifest_sha256: validate_xtask_manifest(sources.manifest)?,
        dependency_closure_sha256: rust_dependency_closure_digest(sources.cargo_lock)?,
    })
}

impl BootstrapImplementationProjection {
    fn digest(&self) -> Result<String, String> {
        let mut digest = Sha256::new();
        digest.update(b"WRELQIMP\0\x02\0\0\0");
        for (label, value) in [
            ("qemu-source", self.qemu_source_sha256.as_str()),
            ("qemu-dispatch", self.dispatch_sha256.as_str()),
            ("xtask-manifest", self.manifest_sha256.as_str()),
            (
                "bootstrap-dependency-closure",
                self.dependency_closure_sha256.as_str(),
            ),
        ] {
            update_length_prefixed(&mut digest, label.as_bytes())?;
            update_length_prefixed(&mut digest, value.as_bytes())?;
        }
        Ok(lower_hex(&digest.finalize()))
    }
}

fn qemu_dispatch_contract_digest(bytes: &[u8]) -> Result<String, String> {
    let source =
        std::str::from_utf8(bytes).map_err(|_| "xtask/src/main.rs is not UTF-8".to_owned())?;
    if !source.ends_with('\n') || source.contains('\r') || source.contains('\0') {
        return Err("xtask/src/main.rs has noncanonical text encoding".to_owned());
    }
    const MODULE: &str = "mod qemu;";
    const MAIN_PRELUDE: &str = "fn main() -> ExitCode {\n    let mut arguments = env::args().skip(1);\n    match arguments.next().as_deref() {";
    const ARM_START: &str = "        Some(\"qemu\") => {\n";
    const NEXT_ARM: &str = "\n        Some(";
    const ROOT_START: &str = "fn workspace_root() -> Result<PathBuf, String> {\n";
    const NEXT_FUNCTION: &str = "\n}\n\nfn ";

    let module_offset = unique_line_offset(source, MODULE, "QEMU module declaration")?;
    reject_outer_attribute(source, module_offset, "QEMU module declaration")?;
    let main_offset =
        unique_fragment_offset(source, MAIN_PRELUDE, "xtask command dispatch prelude")?;
    reject_outer_attribute(source, main_offset, "xtask command dispatcher")?;
    require_unique_fragment(source, "use std::env;", "standard environment import")?;
    require_std_item_import(source, "path", "Path")?;
    require_std_item_import(source, "path", "PathBuf")?;
    require_std_item_import(source, "process", "ExitCode")?;
    if source.contains("macro_rules! env") {
        return Err("xtask/src/main.rs may not shadow the built-in env! macro".to_owned());
    }

    let arm_start = unique_fragment_offset(source, ARM_START, "QEMU command dispatch arm")?;
    let arm_body_start = arm_start
        .checked_add(ARM_START.len())
        .ok_or_else(|| "QEMU command dispatch arm offset overflow".to_owned())?;
    let arm_tail = source
        .get(arm_body_start..)
        .ok_or_else(|| "QEMU command dispatch arm offset escaped source".to_owned())?;
    let arm_tail_len = arm_tail
        .find(NEXT_ARM)
        .ok_or_else(|| "QEMU command dispatch arm has no following command arm".to_owned())?;
    let arm_end = arm_body_start
        .checked_add(arm_tail_len)
        .ok_or_else(|| "QEMU command dispatch arm end overflow".to_owned())?;
    let arm = source
        .get(arm_start..arm_end)
        .ok_or_else(|| "QEMU command dispatch arm escaped source".to_owned())?;
    if !arm.ends_with("        }") {
        return Err("QEMU command dispatch arm is not a canonical braced arm".to_owned());
    }

    let root_start = unique_fragment_offset(source, ROOT_START, "workspace-root resolver")?;
    reject_outer_attribute(source, root_start, "workspace-root resolver")?;
    let root_tail = source
        .get(root_start..)
        .ok_or_else(|| "workspace-root resolver offset escaped source".to_owned())?;
    let root_end = root_tail
        .find(NEXT_FUNCTION)
        .ok_or_else(|| "workspace-root resolver has no canonical function boundary".to_owned())?
        .checked_add(2)
        .ok_or_else(|| "workspace-root resolver end overflow".to_owned())?;
    let root = root_tail
        .get(..root_end)
        .ok_or_else(|| "workspace-root resolver escaped source".to_owned())?;

    let mut digest = Sha256::new();
    digest.update(b"WRELQDSP\0\x01\0\0\0");
    for (label, fragment) in [
        ("module", MODULE),
        ("environment-binding", "std::env"),
        ("path-binding", "std::path::Path"),
        ("path-buffer-binding", "std::path::PathBuf"),
        ("exit-code-binding", "std::process::ExitCode"),
        ("main-prelude", MAIN_PRELUDE),
        ("qemu-arm", arm),
        ("workspace-root", root),
    ] {
        update_length_prefixed(&mut digest, label.as_bytes())?;
        update_length_prefixed(&mut digest, fragment.as_bytes())?;
    }
    Ok(lower_hex(&digest.finalize()))
}

fn require_unique_fragment(source: &str, fragment: &str, label: &str) -> Result<(), String> {
    unique_fragment_offset(source, fragment, label).map(|_| ())
}

fn unique_line_offset(source: &str, line: &str, label: &str) -> Result<usize, String> {
    let mut selected = None;
    for (offset, candidate) in source.match_indices(line) {
        let starts_line =
            offset == 0 || source.as_bytes().get(offset.wrapping_sub(1)) == Some(&b'\n');
        let end = offset
            .checked_add(candidate.len())
            .ok_or_else(|| format!("{label} offset overflow"))?;
        let ends_line = end == source.len() || source.as_bytes().get(end) == Some(&b'\n');
        if starts_line && ends_line && selected.replace(offset).is_some() {
            return Err(format!("xtask/src/main.rs repeats the canonical {label}"));
        }
    }
    selected.ok_or_else(|| format!("xtask/src/main.rs omits the canonical {label}"))
}

fn reject_outer_attribute(source: &str, offset: usize, label: &str) -> Result<(), String> {
    let before = source
        .get(..offset)
        .ok_or_else(|| format!("{label} offset escaped xtask/src/main.rs"))?;
    let mut block_comment = false;
    for line in before.lines().rev() {
        let line = line.trim();
        if block_comment {
            if line.contains("/*") {
                block_comment = false;
            }
            continue;
        }
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        if line.ends_with("*/") {
            block_comment = !line.contains("/*");
            continue;
        }
        if line.ends_with(']') {
            return Err(format!(
                "xtask/src/main.rs may not attach an outer attribute to the {label}"
            ));
        }
        break;
    }
    Ok(())
}

fn require_std_item_import(source: &str, module: &str, item: &str) -> Result<(), String> {
    let direct = format!("use std::{module}::{item};");
    let group_prefix = format!("use std::{module}::{{");
    let mut imports = 0usize;
    for line in source.lines().map(str::trim) {
        if line == direct {
            imports = imports
                .checked_add(1)
                .ok_or_else(|| "xtask import count overflow".to_owned())?;
            continue;
        }
        let Some(items) = line
            .strip_prefix(&group_prefix)
            .and_then(|items| items.strip_suffix("};"))
        else {
            continue;
        };
        imports = imports
            .checked_add(
                items
                    .split(", ")
                    .filter(|candidate| *candidate == item)
                    .count(),
            )
            .ok_or_else(|| "xtask import count overflow".to_owned())?;
    }
    if imports != 1 {
        return Err(format!(
            "xtask/src/main.rs must import exactly one unaliased std::{module}::{item} binding"
        ));
    }
    Ok(())
}

fn unique_fragment_offset(source: &str, fragment: &str, label: &str) -> Result<usize, String> {
    let mut matches = source.match_indices(fragment);
    let offset = matches
        .next()
        .map(|(offset, _)| offset)
        .ok_or_else(|| format!("xtask/src/main.rs omits the canonical {label}"))?;
    if matches.next().is_some() {
        return Err(format!("xtask/src/main.rs repeats the canonical {label}"));
    }
    Ok(offset)
}

fn validate_xtask_manifest(bytes: &[u8]) -> Result<String, String> {
    let source =
        std::str::from_utf8(bytes).map_err(|_| "xtask/Cargo.toml is not UTF-8".to_owned())?;
    if !source.ends_with('\n') || source.contains('\r') || source.contains('\0') {
        return Err("xtask/Cargo.toml has noncanonical text encoding".to_owned());
    }
    const EXPECTED: &str = "sha2 = { version = \"=0.10.9\", default-features = false }";
    let mut section = "";
    let mut found = false;
    for line in source.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            section = line;
            continue;
        }
        let references_sha2 = line.starts_with("sha2 ")
            || line.starts_with("sha2.")
            || line.contains("package = \"sha2\"");
        if !references_sha2 {
            continue;
        }
        if section != "[dependencies]" || line != EXPECTED || found {
            return Err(format!(
                "xtask manifest must contain exactly the reviewed dependency {EXPECTED:?} in [dependencies]"
            ));
        }
        found = true;
    }
    if !found {
        return Err(format!(
            "xtask manifest must contain exactly the reviewed dependency {EXPECTED:?} in [dependencies]"
        ));
    }
    let mut digest = Sha256::new();
    digest.update(b"WRELQMAN\0\x01\0\0\0");
    update_length_prefixed(&mut digest, EXPECTED.as_bytes())?;
    Ok(lower_hex(&digest.finalize()))
}

fn rust_dependency_closure_digest(bytes: &[u8]) -> Result<String, String> {
    let packages = parse_cargo_lock_packages(bytes)?;
    let sha2 = unique_package(&packages, "sha2", Some("0.10.9"))?;
    validate_registry_package(sha2, "xtask sha2")?;
    let xtask = unique_package(&packages, "xtask", None)?;
    if xtask.source.is_some()
        || xtask.checksum.is_some()
        || !dependency_resolves_to(&xtask.dependencies, sha2, &packages)?
    {
        return Err(
            "Cargo.lock must resolve the workspace xtask package directly to pinned sha2"
                .to_owned(),
        );
    }

    let start = packages
        .iter()
        .position(|package| std::ptr::eq(package, sha2))
        .ok_or_else(|| "cannot locate xtask sha2 package index".to_owned())?;
    let mut stack = vec![start];
    let mut visited = BTreeSet::new();
    while let Some(index) = stack.pop() {
        if !visited.insert(index) {
            continue;
        }
        if visited.len() > 128 {
            return Err("xtask sha2 dependency closure exceeds 128 packages".to_owned());
        }
        let package = packages
            .get(index)
            .ok_or_else(|| "xtask dependency closure index escaped package list".to_owned())?;
        validate_registry_package(package, "xtask bootstrap dependency")?;
        for dependency in &package.dependencies {
            let name = dependency
                .split(' ')
                .next()
                .filter(|name| !name.is_empty())
                .ok_or_else(|| "Cargo.lock contains an empty dependency reference".to_owned())?;
            stack.push(uniquely_resolved_dependency_index(
                &package.dependencies,
                name,
                &packages,
            )?);
        }
    }

    let mut closure = BTreeMap::new();
    for index in visited {
        let package = packages
            .get(index)
            .ok_or_else(|| "xtask dependency closure index escaped package list".to_owned())?;
        let key = cargo_package_identity(package)?;
        if closure.insert(key, index).is_some() {
            return Err("xtask dependency closure repeats a package identity".to_owned());
        }
    }
    let mut digest = Sha256::new();
    digest.update(b"WRELQRDP\0\x01\0\0\0");
    update_length_prefixed(&mut digest, b"xtask-direct-sha2")?;
    for (key, index) in closure {
        update_length_prefixed(&mut digest, key.as_bytes())?;
        let package = packages
            .get(index)
            .ok_or_else(|| "xtask dependency closure index escaped package list".to_owned())?;
        let checksum = package
            .checksum
            .as_deref()
            .ok_or_else(|| "xtask bootstrap dependency omits checksum".to_owned())?;
        update_length_prefixed(&mut digest, checksum.as_bytes())?;
        let mut dependencies = BTreeSet::new();
        for dependency in &package.dependencies {
            let name = dependency
                .split(' ')
                .next()
                .filter(|name| !name.is_empty())
                .ok_or_else(|| "Cargo.lock contains an empty dependency reference".to_owned())?;
            let target = uniquely_resolved_dependency(&package.dependencies, name, &packages)?;
            dependencies.insert(cargo_package_identity(target)?);
        }
        for dependency in dependencies {
            update_length_prefixed(&mut digest, dependency.as_bytes())?;
        }
    }
    Ok(lower_hex(&digest.finalize()))
}

fn parse_cargo_lock_packages(bytes: &[u8]) -> Result<Vec<CargoPackageBlock>, String> {
    let source = std::str::from_utf8(bytes).map_err(|_| "Cargo.lock is not UTF-8".to_owned())?;
    if !source.ends_with('\n') || source.contains('\r') || source.contains('\0') {
        return Err("Cargo.lock has noncanonical text encoding".to_owned());
    }
    let mut chunks = source.split("\n[[package]]\n");
    let header = chunks
        .next()
        .ok_or_else(|| "Cargo.lock is empty".to_owned())?;
    let mut header_values = header
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'));
    if header_values.next() != Some("version = 4") || header_values.next().is_some() {
        return Err("Cargo.lock must use generated lock format version 4".to_owned());
    }

    let mut packages = Vec::new();
    for chunk in chunks {
        if packages.len() >= MAX_RUST_LOCK_PACKAGES {
            return Err(format!(
                "Cargo.lock exceeds {MAX_RUST_LOCK_PACKAGES} package blocks"
            ));
        }
        let package = parse_cargo_package_block(chunk)?;
        packages
            .try_reserve(1)
            .map_err(|_| "cannot reserve bounded Cargo.lock package inventory".to_owned())?;
        packages.push(package);
    }
    Ok(packages)
}

fn parse_cargo_package_block(chunk: &str) -> Result<CargoPackageBlock, String> {
    let mut package = CargoPackageBlock::default();
    let mut in_dependencies = false;
    for raw_line in chunk.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if in_dependencies {
            if line == "]" {
                in_dependencies = false;
                continue;
            }
            let value = line.strip_suffix(',').unwrap_or(line);
            let dependency = parse_string(value, "Cargo.lock dependency")?;
            if !package.dependencies.insert(dependency) {
                return Err("Cargo.lock package repeats a dependency".to_owned());
            }
            continue;
        }
        if line == "dependencies = [" {
            in_dependencies = true;
            continue;
        }
        let Some((key, value)) = line.split_once(" = ") else {
            continue;
        };
        let slot = match key {
            "name" => Some((&mut package.name, "package.name")),
            "version" => Some((&mut package.version, "package.version")),
            "source" => Some((&mut package.source, "package.source")),
            "checksum" => Some((&mut package.checksum, "package.checksum")),
            _ => None,
        };
        if let Some((slot, label)) = slot {
            set_cargo_field(slot, parse_string(value, label)?, label)?;
        }
    }
    if in_dependencies || package.name.is_none() || package.version.is_none() {
        return Err("Cargo.lock contains an incomplete package block".to_owned());
    }
    Ok(package)
}

fn set_cargo_field<T>(slot: &mut Option<T>, value: T, label: &str) -> Result<(), String> {
    if slot.replace(value).is_some() {
        Err(format!("Cargo.lock repeats {label}"))
    } else {
        Ok(())
    }
}

fn unique_package<'a>(
    packages: &'a [CargoPackageBlock],
    name: &str,
    version: Option<&str>,
) -> Result<&'a CargoPackageBlock, String> {
    let mut selected = None;
    for package in packages {
        if package.name.as_deref() == Some(name)
            && version.is_none_or(|expected| package.version.as_deref() == Some(expected))
            && selected.replace(package).is_some()
        {
            return Err(format!(
                "Cargo.lock contains duplicate package identity {name} {}",
                version.unwrap_or("<any-version>")
            ));
        }
    }
    selected.ok_or_else(|| {
        format!(
            "Cargo.lock omits package identity {name} {}",
            version.unwrap_or("<any-version>")
        )
    })
}

fn validate_registry_package(package: &CargoPackageBlock, label: &str) -> Result<(), String> {
    if package.source.as_deref() != Some("registry+https://github.com/rust-lang/crates.io-index")
        || !package.checksum.as_deref().is_some_and(|checksum| {
            valid_sha256(checksum) && checksum.bytes().any(|byte| byte != b'0')
        })
    {
        return Err(format!(
            "Cargo.lock {label} package is not a checksummed crates.io registry release"
        ));
    }
    Ok(())
}

fn dependency_resolves_to(
    dependencies: &BTreeSet<String>,
    target: &CargoPackageBlock,
    packages: &[CargoPackageBlock],
) -> Result<bool, String> {
    let target_name = target
        .name
        .as_deref()
        .ok_or_else(|| "Cargo.lock dependency target omits name".to_owned())?;
    let target_version = target
        .version
        .as_deref()
        .ok_or_else(|| "Cargo.lock dependency target omits version".to_owned())?;
    let same_name_count = packages
        .iter()
        .filter(|package| package.name.as_deref() == Some(target_name))
        .count();
    let mut matches = 0u8;
    for dependency in dependencies {
        let mut parts = dependency.splitn(3, ' ');
        if parts.next() != Some(target_name) {
            continue;
        }
        let version = parts.next();
        let source = parts.next();
        let resolves = if version.is_none() {
            same_name_count == 1
        } else {
            version == Some(target_version)
                && source.is_none_or(|value| {
                    value
                        .strip_prefix('(')
                        .and_then(|value| value.strip_suffix(')'))
                        == target.source.as_deref()
                })
        };
        if resolves {
            matches = matches
                .checked_add(1)
                .ok_or_else(|| "Cargo.lock dependency match count overflow".to_owned())?;
        }
    }
    Ok(matches == 1)
}

fn uniquely_resolved_dependency<'a>(
    dependencies: &BTreeSet<String>,
    name: &str,
    packages: &'a [CargoPackageBlock],
) -> Result<&'a CargoPackageBlock, String> {
    let mut selected = None;
    for package in packages
        .iter()
        .filter(|package| package.name.as_deref() == Some(name))
    {
        if dependency_resolves_to(dependencies, package, packages)?
            && selected.replace(package).is_some()
        {
            return Err(format!(
                "Cargo.lock dependency resolves ambiguously to {name}"
            ));
        }
    }
    selected.ok_or_else(|| format!("Cargo.lock does not resolve dependency {name}"))
}

fn uniquely_resolved_dependency_index(
    dependencies: &BTreeSet<String>,
    name: &str,
    packages: &[CargoPackageBlock],
) -> Result<usize, String> {
    let target = uniquely_resolved_dependency(dependencies, name, packages)?;
    packages
        .iter()
        .position(|package| std::ptr::eq(package, target))
        .ok_or_else(|| format!("cannot locate resolved Cargo package {name}"))
}

fn cargo_package_identity(package: &CargoPackageBlock) -> Result<String, String> {
    let name = package
        .name
        .as_deref()
        .ok_or_else(|| "Cargo.lock package omits name".to_owned())?;
    let version = package
        .version
        .as_deref()
        .ok_or_else(|| "Cargo.lock package omits version".to_owned())?;
    let source = package
        .source
        .as_deref()
        .ok_or_else(|| "Cargo.lock registry package omits source".to_owned())?;
    Ok(format!("{name} {version} ({source})"))
}

fn identify_current_executable() -> Result<ToolIdentity, String> {
    let path = env::current_exe()
        .map_err(|error| format!("cannot resolve running xtask executable: {error}"))?;
    identify_tool(&path).map_err(|error| format!("cannot fingerprint running xtask: {error}"))
}

#[allow(clippy::too_many_arguments)]
fn native_input_digest(
    host: &str,
    lock: &EmulationLock,
    inputs: &AuthenticatedInputs,
    tools: &BuildTools,
    static_dependency_sha256: &str,
    implementation_sha256: &str,
) -> Result<String, String> {
    let mut digest = Sha256::new();
    digest.update(INPUT_MAGIC);
    digest.update(BUILD_CONTRACT_VERSION.to_le_bytes());
    for value in [
        host,
        &lock.bytes_sha256,
        &inputs.archive_measurement.sha256,
        &inputs.signature_measurement.sha256,
        &inputs.signing_key_measurement.sha256,
        &lock.signing_key_fingerprint,
        static_dependency_sha256,
        implementation_sha256,
    ] {
        update_length_prefixed(&mut digest, value.as_bytes())?;
    }
    digest.update(inputs.archive_measurement.bytes.to_le_bytes());
    digest.update(inputs.signature_measurement.bytes.to_le_bytes());
    digest.update(inputs.signing_key_measurement.bytes.to_le_bytes());
    digest.update(inputs.signature_timestamp.to_le_bytes());
    for argument in configure_contract() {
        update_length_prefixed(&mut digest, argument.as_bytes())?;
    }
    for (label, tool) in tool_inventory(tools) {
        update_length_prefixed(&mut digest, label.as_bytes())?;
        digest.update(hex_bytes(&tool.sha256)?);
        digest.update(tool.bytes.to_le_bytes());
        let version = tool_version(tool, label)?;
        update_length_prefixed(&mut digest, &version)?;
    }
    for (name, tool) in &tools.utilities {
        update_length_prefixed(&mut digest, name.as_bytes())?;
        digest.update(hex_bytes(&tool.sha256)?);
        digest.update(tool.bytes.to_le_bytes());
    }
    let cxx_driver_relative = tools
        .cxx_driver
        .strip_prefix(&tools.apple_toolchain.path)
        .map_err(|_| "QEMU C++ driver escaped the measured Apple toolchain".to_owned())?;
    update_length_prefixed(&mut digest, utf8_path(cxx_driver_relative)?.as_bytes())?;
    let ranlib_driver_relative = tools
        .ranlib_driver
        .strip_prefix(&tools.apple_toolchain.path)
        .map_err(|_| "QEMU ranlib driver escaped the measured Apple toolchain".to_owned())?;
    update_length_prefixed(&mut digest, utf8_path(ranlib_driver_relative)?.as_bytes())?;
    digest.update(hex_bytes(&tools.sysroot.sha256)?);
    digest.update(tools.sysroot.files.to_le_bytes());
    digest.update(tools.sysroot.bytes.to_le_bytes());
    for directory in [&tools.apple_toolchain, &tools.python_runtime] {
        digest.update(hex_bytes(&directory.sha256)?);
        digest.update(directory.files.to_le_bytes());
        digest.update(directory.bytes.to_le_bytes());
    }
    update_length_prefixed(&mut digest, utf8_path(&tools.host_system.path)?.as_bytes())?;
    digest.update(hex_bytes(&tools.host_system.sha256)?);
    digest.update(tools.host_system.bytes.to_le_bytes());
    digest.update(
        u64::try_from(tools.dynamic_libraries.len())
            .map_err(|_| "native dynamic-library count overflow".to_owned())?
            .to_le_bytes(),
    );
    for library in &tools.dynamic_libraries {
        update_length_prefixed(&mut digest, utf8_path(&library.path)?.as_bytes())?;
        digest.update(hex_bytes(&library.sha256)?);
        digest.update(library.bytes.to_le_bytes());
    }
    Ok(lower_hex(&digest.finalize()))
}

fn tool_inventory(tools: &BuildTools) -> [(&'static str, &ToolIdentity); 16] {
    [
        ("curl", &tools.curl),
        ("gpg", &tools.gpg),
        ("xz", &tools.xz),
        ("bzip2", &tools.bzip2),
        ("python", &tools.python),
        ("ninja", &tools.ninja),
        ("pkg-config", &tools.pkg_config),
        ("cc", &tools.cc),
        ("cxx", &tools.cxx),
        ("linker", &tools.linker),
        ("ar", &tools.ar),
        ("ranlib", &tools.ranlib),
        ("otool", &tools.otool),
        ("codesign", &tools.codesign),
        ("touch", &tools.touch),
        ("shell", &tools.shell),
    ]
}

fn tool_version(tool: &ToolIdentity, label: &str) -> Result<Vec<u8>, String> {
    if CONTENT_ONLY_TOOL_IDENTITIES.contains(&label) {
        return Ok(tool.sha256.as_bytes().to_vec());
    }
    let arguments: &[&str] = match label {
        "bzip2" => &["--help"],
        "python" => &["--version"],
        "codesign" => &["-h"],
        "otool" => &["-h"],
        _ => &["--version"],
    };
    let mut command = Command::new(&tool.path);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/wrela/no-ambient-path")
        .env("TZ", "UTC")
        .args(arguments);
    let output = run_bounded_output(
        &mut command,
        &format!("{label} identity probe"),
        Duration::from_secs(60),
    )?;
    if label == "bzip2" {
        return validate_bzip2_help(output.status.success(), &output.stdout, &output.stderr);
    }
    if !output.status.success() && !matches!(label, "codesign" | "otool") {
        return Err(format!("{label} identity probe failed"));
    }
    let mut bytes = output.stdout;
    bytes.extend_from_slice(&output.stderr);
    if bytes.is_empty() || bytes.contains(&0) {
        return Err(format!("{label} identity probe returned invalid output"));
    }
    Ok(bytes)
}

fn validate_bzip2_help(success: bool, stdout: &[u8], stderr: &[u8]) -> Result<Vec<u8>, String> {
    if !success {
        return Err("bzip2 identity probe failed".to_owned());
    }
    if !stdout.is_empty() {
        return Err("bzip2 identity probe emitted transforming stdout".to_owned());
    }
    if stderr.len() > MAX_BZIP2_HELP_BYTES
        || !stderr.starts_with(BZIP2_HELP_PREFIX)
        || !stderr.ends_with(b"\n")
        || !stderr
            .iter()
            .all(|byte| byte.is_ascii_graphic() || matches!(byte, b' ' | b'\t' | b'\n'))
    {
        return Err("bzip2 identity probe returned invalid help output".to_owned());
    }
    let mut identity = Vec::new();
    identity
        .try_reserve_exact(stderr.len())
        .map_err(|_| "cannot reserve bounded bzip2 identity output".to_owned())?;
    identity.extend_from_slice(stderr);
    Ok(identity)
}

fn configure_contract() -> &'static [&'static str] {
    &[
        "--target-list=aarch64-softmmu",
        "--without-default-features",
        "--enable-system",
        "--disable-user",
        "--enable-tcg",
        "--enable-fdt=system",
        // The frozen boot routes attach an ESP directory through rw vvfat;
        // QEMU implements its private write overlay with the qcow1 driver.
        "--enable-qcow1",
        "--enable-vvfat",
        "--static",
        "--disable-download",
        "--disable-docs",
        "--disable-tools",
        "--disable-guest-agent",
        "--disable-install-blobs",
        "--disable-modules",
        "--disable-plugins",
        "--disable-cocoa",
        "--disable-hvf",
        "--disable-slirp",
        "--disable-vnc",
        "--disable-gtk",
        "--disable-sdl",
        "--disable-opengl",
        "--disable-virglrenderer",
        "--disable-curses",
        "--disable-coreaudio",
        "--disable-pa",
        "--disable-oss",
        "--disable-jack",
        "--disable-pipewire",
        "--disable-spice",
        "--disable-usb-redir",
        "--disable-libiscsi",
        "--disable-libssh",
        "--disable-curl",
        "--disable-gnutls",
        "--disable-gcrypt",
        "--disable-nettle",
        "--disable-gettext",
        "--disable-rust",
        "--disable-debug-info",
        "--disable-strip",
        "--disable-relocatable",
        "--disable-werror",
    ]
}

fn execute_build(mut plan: BuildPlan, record_output: bool) -> Result<(), String> {
    match (record_output, plan.expected_output.is_some()) {
        (true, true) => {
            return Err(
                "--record-output requires toolchain/emulation.outputs.toml to be absent; remove it only for an intentional maintainer review build"
                    .to_owned(),
            );
        }
        (false, false) => {
            return Err(
                "trusted QEMU output enrollment is absent; a maintainer must run one fresh `cargo xtask qemu --record-output` after authenticating the pinned release signature"
                    .to_owned(),
            );
        }
        _ => {}
    }
    if let Some(expected) = &plan.expected_output {
        if plan.bundle.exists() {
            verify_bundle(&plan.bundle, &plan, expected)?;
            println!("reused verified QEMU payload {}", plan.bundle.display());
            return Ok(());
        }
    } else if plan.bundle.exists() {
        return Err(format!(
            "unenrolled QEMU payload already exists at {}; remove it before the explicit fresh review build",
            plan.bundle.display()
        ));
    }

    let staging_parent = plan.root.join("build/toolchain/qemu/staging");
    let staging = PrivateDirectory::create(&staging_parent, "build")?;
    let source = staging.path.join("source");
    let build = staging.path.join("build");
    let bundle = staging.path.join("bundle");
    fs::create_dir(&source)
        .map_err(|error| format!("cannot create QEMU source directory: {error}"))?;
    fs::create_dir(&build)
        .map_err(|error| format!("cannot create QEMU build directory: {error}"))?;
    fs::create_dir(&bundle)
        .map_err(|error| format!("cannot create QEMU bundle directory: {error}"))?;

    extract_authenticated_archive(
        &plan.inputs.archive,
        &plan.tools.xz,
        &source,
        &format!("qemu-{}/", plan.lock.version),
    )?;
    validate_source_payload(&source, &plan.lock)?;
    apply_reviewed_darwin_static_patch(&source)?;
    revalidate_plan_inputs(&plan)?;
    run_qemu_build(&plan, &source, &build)?;
    assemble_runtime_bundle(&plan, &source, &build, &bundle)?;
    revalidate_plan_inputs(&plan)?;
    let measurement = measure_tree(&bundle, MAX_TREE_FILES, MAX_TREE_BYTES)?;
    let generated = output_for_measurement(&plan, &bundle, &measurement)?;
    match &plan.expected_output {
        Some(expected) if expected != &generated => {
            return Err(format!(
                "fresh QEMU payload does not match trusted output enrollment: expected {}, observed {}",
                expected.bundle_tree_sha256, generated.bundle_tree_sha256
            ));
        }
        Some(_) => {}
        None if record_output => plan.expected_output = Some(generated.clone()),
        None => return Err("trusted QEMU output disappeared during build".to_owned()),
    }
    verify_bundle(
        &bundle,
        &plan,
        plan.expected_output
            .as_ref()
            .ok_or_else(|| "QEMU output measurement was not sealed".to_owned())?,
    )?;
    sync_tree(&bundle)?;
    publish_bundle(&bundle, &plan.bundle)?;
    let expected = plan
        .expected_output
        .as_ref()
        .ok_or_else(|| "published QEMU output lacks enrollment".to_owned())?;
    verify_bundle(&plan.bundle, &plan, expected)?;
    if record_output {
        record_expected_output(&plan.root, expected)?;
    } else if load_expected_output(&plan.root)?.as_ref() != Some(expected) {
        return Err("QEMU output enrollment changed during bootstrap".to_owned());
    }
    println!("published verified QEMU payload {}", plan.bundle.display());
    Ok(())
}

fn validate_source_payload(source: &Path, lock: &EmulationLock) -> Result<(), String> {
    for relative in [
        "configure",
        "COPYING",
        "meson.build",
        "VERSION",
        lock.firmware[0].source_path.as_str(),
        lock.firmware[0].license_manifest.as_str(),
        lock.firmware[1].source_path.as_str(),
    ] {
        let path = source.join(relative);
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("authenticated QEMU source omits {relative:?}: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
            return Err(format!(
                "authenticated QEMU source input {relative:?} is not a nonempty regular file"
            ));
        }
    }
    let version = read_bounded_file(&source.join("VERSION"), 1024)?;
    if version != format!("{}\n", lock.version).as_bytes() {
        return Err("authenticated source VERSION does not match emulation.lock.toml".to_owned());
    }
    Ok(())
}

fn apply_reviewed_darwin_static_patch(source: &Path) -> Result<(), String> {
    let path = source.join("meson.build");
    let input = read_bounded_file(&path, QEMU_DARWIN_STATIC_MESON_ORIGINAL_BYTES)?;
    let output = patch_darwin_static_meson(&input)?;
    let before = fs::symlink_metadata(&path)
        .map_err(|error| format!("cannot inspect reviewed QEMU Meson input: {error}"))?;
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    let mut file = options
        .open(&path)
        .map_err(|error| format!("cannot open reviewed QEMU Meson input: {error}"))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("cannot inspect opened QEMU Meson input: {error}"))?;
    if !same_metadata(&before, &opened) {
        return Err("reviewed QEMU Meson input changed before patching".to_owned());
    }
    let mut opened_input = Vec::new();
    opened_input
        .try_reserve_exact(input.len())
        .map_err(|_| "cannot reserve opened QEMU Meson input".to_owned())?;
    file.read_to_end(&mut opened_input)
        .map_err(|error| format!("cannot re-read opened QEMU Meson input: {error}"))?;
    let after_read = file
        .metadata()
        .map_err(|error| format!("cannot re-inspect opened QEMU Meson input: {error}"))?;
    if opened_input != input || !same_metadata(&before, &after_read) {
        return Err("reviewed QEMU Meson input changed while being opened".to_owned());
    }
    file.set_len(0)
        .map_err(|error| format!("cannot truncate reviewed QEMU Meson input: {error}"))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("cannot rewind reviewed QEMU Meson input: {error}"))?;
    file.write_all(&output)
        .map_err(|error| format!("cannot write reviewed QEMU Meson patch: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("cannot sync reviewed QEMU Meson patch: {error}"))?;
    drop(file);
    verify_reviewed_source_patch(source)?;
    sync_directory(source)
}

fn patch_darwin_static_meson(input: &[u8]) -> Result<Vec<u8>, String> {
    patch_reviewed_text(
        input,
        QEMU_DARWIN_STATIC_MESON_ORIGINAL_SHA256,
        QEMU_DARWIN_STATIC_MESON_ORIGINAL_BYTES,
        QEMU_DARWIN_STATIC_MESON_ORIGINAL_BLOCK,
        QEMU_DARWIN_STATIC_MESON_PATCHED_BLOCK,
        QEMU_DARWIN_STATIC_MESON_PATCHED_SHA256,
        QEMU_DARWIN_STATIC_MESON_PATCHED_BYTES,
    )
}

#[allow(clippy::too_many_arguments)]
fn patch_reviewed_text(
    input: &[u8],
    expected_input_sha256: &str,
    expected_input_bytes: u64,
    original_block: &[u8],
    patched_block: &[u8],
    expected_output_sha256: &str,
    expected_output_bytes: u64,
) -> Result<Vec<u8>, String> {
    if original_block.is_empty() || patched_block.is_empty() || original_block == patched_block {
        return Err("reviewed text patch has an invalid replacement contract".to_owned());
    }
    let input_bytes = u64::try_from(input.len())
        .map_err(|_| "reviewed text patch input size overflow".to_owned())?;
    if input_bytes != expected_input_bytes || sha256_bytes(input) != expected_input_sha256 {
        return Err("reviewed text patch input does not match its sealed identity".to_owned());
    }
    let original_offsets = input
        .windows(original_block.len())
        .enumerate()
        .filter_map(|(offset, window)| (window == original_block).then_some(offset))
        .collect::<Vec<_>>();
    if original_offsets.len() != 1
        || input
            .windows(patched_block.len())
            .any(|window| window == patched_block)
    {
        return Err("reviewed text patch site is absent, ambiguous, or prepatched".to_owned());
    }
    let offset = original_offsets[0];
    let patched_len = input
        .len()
        .checked_sub(original_block.len())
        .and_then(|length| length.checked_add(patched_block.len()))
        .ok_or_else(|| "reviewed text patch size overflow".to_owned())?;
    let mut output = Vec::new();
    output
        .try_reserve_exact(patched_len)
        .map_err(|_| "cannot reserve reviewed text patch output".to_owned())?;
    output.extend_from_slice(&input[..offset]);
    output.extend_from_slice(patched_block);
    output.extend_from_slice(&input[offset + original_block.len()..]);
    let output_bytes = u64::try_from(output.len())
        .map_err(|_| "reviewed text patch output size overflow".to_owned())?;
    if output_bytes != expected_output_bytes || sha256_bytes(&output) != expected_output_sha256 {
        return Err("reviewed text patch output does not match its sealed identity".to_owned());
    }
    Ok(output)
}

fn verify_reviewed_source_patch(source: &Path) -> Result<(), String> {
    let observed = measure_file(
        &source.join("meson.build"),
        QEMU_DARWIN_STATIC_MESON_PATCHED_BYTES,
        false,
    )?;
    if observed.bytes != QEMU_DARWIN_STATIC_MESON_PATCHED_BYTES
        || observed.sha256 != QEMU_DARWIN_STATIC_MESON_PATCHED_SHA256
    {
        return Err("reviewed QEMU Meson patch changed during native work".to_owned());
    }
    Ok(())
}

fn run_qemu_build(plan: &BuildPlan, source: &Path, build: &Path) -> Result<(), String> {
    verify_reviewed_source_patch(source)?;
    let controlled_path = prepare_controlled_path(build, &plan.tools)?;
    let controlled_pkg_config = prepare_controlled_pkg_config(build, &plan.static_dependencies)?;
    let controlled_clang_resource =
        prepare_controlled_clang_resource(build, &plan.tools, &plan.static_dependencies)?;
    let source_text = utf8_path(source)?;
    let build_text = utf8_path(build)?;
    let sysroot = utf8_path(&plan.tools.sysroot.path)?;
    for path in [source_text, build_text, sysroot] {
        if path.bytes().any(|byte| {
            byte.is_ascii_whitespace() || matches!(byte, b'\'' | b'"' | b'`' | b'$' | b':')
        }) {
            return Err(format!(
                "QEMU native path cannot be represented safely in configure arguments: {path:?}"
            ));
        }
    }
    let mut cflags = format!(
        "-isysroot {sysroot} -resource-dir={} -ffile-prefix-map={source_text}=/wrela/qemu/source -fdebug-prefix-map={source_text}=/wrela/qemu/source -ffile-prefix-map={build_text}=/wrela/qemu/build -fdebug-prefix-map={build_text}=/wrela/qemu/build",
        utf8_path(&controlled_clang_resource)?,
    );
    append_dependency_search_directories(
        &mut cflags,
        "-I",
        &plan.static_dependencies.include_directories,
    )?;
    let mut ldflags = format!("-isysroot {sysroot} -Wl,-no_uuid");
    append_dependency_search_directories(
        &mut ldflags,
        "-L",
        &plan.static_dependencies.library_directories,
    )?;
    let mut arguments: Vec<OsString> = configure_contract().iter().map(OsString::from).collect();
    arguments.extend([
        OsString::from(format!("--python={}", utf8_path(&plan.tools.python.path)?)),
        OsString::from(format!("--ninja={}", utf8_path(&plan.tools.ninja.path)?)),
        OsString::from(format!("--cc={}", utf8_path(&plan.tools.cc.path)?)),
        cxx_configure_argument(&plan.tools.cxx_driver)?,
        OsString::from(format!("--host-cc={}", utf8_path(&plan.tools.cc.path)?)),
        OsString::from(format!("--extra-cflags={cflags}")),
        OsString::from(format!("--extra-cxxflags={cflags}")),
        OsString::from(format!("--extra-ldflags={ldflags}")),
    ]);
    let environment =
        deterministic_environment(build, &controlled_path, &controlled_pkg_config, plan);
    let configure = CommandSpec {
        program: plan.tools.shell.path.clone(),
        arguments: std::iter::once(source.join("configure").into_os_string())
            .chain(arguments)
            .collect(),
        environment: environment.clone(),
        current_dir: build.to_owned(),
    };
    run_command(&configure, "QEMU configure", Duration::from_secs(30 * 60))?;
    verify_reviewed_source_patch(source)?;
    revalidate_plan_inputs(plan)?;
    let build_command = CommandSpec {
        program: plan.tools.ninja.path.clone(),
        arguments: vec![
            OsString::from("-C"),
            build.as_os_str().to_owned(),
            OsString::from(format!("-j{}", plan.jobs)),
            OsString::from("qemu-system-aarch64"),
        ],
        environment,
        current_dir: build.to_owned(),
    };
    run_command(
        &build_command,
        "QEMU aarch64-softmmu build",
        Duration::from_secs(8 * 60 * 60),
    )?;
    verify_reviewed_source_patch(source)?;
    Ok(())
}

fn prepare_controlled_clang_resource(
    build: &Path,
    tools: &BuildTools,
    contract: &StaticDependencyContract,
) -> Result<PathBuf, String> {
    let cc_resource = clang_resource_directory(&tools.cc.path, "C compiler")?;
    let cxx_resource = clang_resource_directory(&tools.cxx_driver, "C++ compiler")?;
    if cc_resource != cxx_resource || !cc_resource.starts_with(&tools.apple_toolchain.path) {
        return Err(
            "QEMU compilers no longer report the measured Apple resource directory".to_owned(),
        );
    }
    let directory = build.join("wrela-clang-resource");
    create_private_directory(&directory).map_err(|error| {
        format!(
            "cannot create controlled Clang resource directory {}: {error}",
            directory.display()
        )
    })?;
    let mut entries = fs::read_dir(&cc_resource)
        .map_err(|error| {
            format!(
                "cannot enumerate measured Clang resource directory {}: {error}",
                cc_resource.display()
            )
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("cannot inspect measured Clang resource entry: {error}"))?;
    if entries.len() > 64 {
        return Err("measured Clang resource directory has more than 64 root entries".to_owned());
    }
    entries.sort_by_key(fs::DirEntry::file_name);
    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "measured Clang resource entry name is not UTF-8".to_owned())?;
        if !portable_component(&name) || name == "libfdt.a" {
            return Err(format!(
                "measured Clang resource entry name {name:?} cannot be overlaid safely"
            ));
        }
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            format!(
                "cannot inspect measured Clang resource entry {}: {error}",
                path.display()
            )
        })?;
        if metadata.file_type().is_symlink() || (!metadata.is_dir() && !metadata.is_file()) {
            return Err(format!(
                "measured Clang resource entry {} is not a regular file or directory",
                path.display()
            ));
        }
        create_symbolic_link(utf8_path(&path)?, &directory.join(&name)).map_err(|error| {
            format!(
                "cannot expose measured Clang resource entry {}: {error}",
                path.display()
            )
        })?;
    }
    let fdt = required_static_library(contract, "fdt")?;
    create_symbolic_link(utf8_path(&fdt)?, &directory.join("libfdt.a")).map_err(|error| {
        format!(
            "cannot expose measured static libfdt archive {}: {error}",
            fdt.display()
        )
    })?;
    sync_directory(&directory)?;
    Ok(directory)
}

fn required_static_library(
    contract: &StaticDependencyContract,
    name: &str,
) -> Result<PathBuf, String> {
    if !REQUIRED_STATIC_LIBRARIES.contains(&name) {
        return Err(format!("unreviewed required static library {name:?}"));
    }
    let filename = format!("lib{name}.a");
    let mut matches = contract
        .library_directories
        .iter()
        .map(|directory| directory.join(&filename))
        .filter(|candidate| candidate.is_file());
    let library = matches
        .next()
        .ok_or_else(|| format!("measured dependency contract omits {filename}"))?;
    if matches.next().is_some() {
        return Err(format!(
            "measured dependency contract contains more than one {filename}"
        ));
    }
    let library = fs::canonicalize(&library)
        .map_err(|error| format!("cannot resolve measured {filename}: {error}"))?;
    absolute_regular_file(&library, &format!("measured {filename}"))
}

fn cxx_configure_argument(driver: &Path) -> Result<OsString, String> {
    Ok(OsString::from(format!("--cxx={}", utf8_path(driver)?)))
}

#[derive(Debug)]
struct CommandSpec {
    program: PathBuf,
    arguments: Vec<OsString>,
    environment: Vec<(OsString, OsString)>,
    current_dir: PathBuf,
}

fn deterministic_environment(
    build: &Path,
    controlled_path: &Path,
    controlled_pkg_config: &Path,
    plan: &BuildPlan,
) -> Vec<(OsString, OsString)> {
    vec![
        (OsString::from("LC_ALL"), OsString::from("C")),
        (OsString::from("LANG"), OsString::from("C")),
        (OsString::from("TZ"), OsString::from("UTC")),
        (OsString::from("SOURCE_DATE_EPOCH"), OsString::from("1")),
        (OsString::from("ZERO_AR_DATE"), OsString::from("1")),
        (OsString::from("PYTHONHASHSEED"), OsString::from("0")),
        (OsString::from("PYTHONNOUSERSITE"), OsString::from("1")),
        (
            OsString::from("PYTHONDONTWRITEBYTECODE"),
            OsString::from("1"),
        ),
        (OsString::from("TMPDIR"), build.as_os_str().to_owned()),
        (
            OsString::from("PATH"),
            controlled_path.as_os_str().to_owned(),
        ),
        (
            OsString::from("CC"),
            plan.tools.cc.path.clone().into_os_string(),
        ),
        (
            OsString::from("CXX"),
            plan.tools.cxx_driver.clone().into_os_string(),
        ),
        (
            OsString::from("LD"),
            plan.tools.linker.path.clone().into_os_string(),
        ),
        (
            OsString::from("AR"),
            plan.tools.ar.path.clone().into_os_string(),
        ),
        (
            OsString::from("RANLIB"),
            plan.tools.ranlib_driver.clone().into_os_string(),
        ),
        (
            OsString::from("PKG_CONFIG"),
            plan.tools.pkg_config.path.clone().into_os_string(),
        ),
        (
            OsString::from("PKG_CONFIG_LIBDIR"),
            controlled_pkg_config.as_os_str().to_owned(),
        ),
        (
            OsString::from("PKG_CONFIG_ALLOW_SYSTEM_CFLAGS"),
            OsString::from("1"),
        ),
        (
            OsString::from("PKG_CONFIG_ALLOW_SYSTEM_LIBS"),
            OsString::from("1"),
        ),
        (
            OsString::from("NINJA"),
            plan.tools.ninja.path.clone().into_os_string(),
        ),
    ]
}

fn prepare_controlled_path(build: &Path, tools: &BuildTools) -> Result<PathBuf, String> {
    let directory = build.join("wrela-host-tools/bin");
    fs::create_dir_all(&directory)
        .map_err(|error| format!("cannot create controlled QEMU PATH: {error}"))?;
    let mut entries: Vec<(&str, &Path)> = tools
        .utilities
        .iter()
        .map(|(name, tool)| (name.as_str(), tool.path.as_path()))
        .collect();
    entries.extend([
        ("codesign", tools.codesign.path.as_path()),
        ("sh", tools.shell.path.as_path()),
        ("touch", tools.touch.path.as_path()),
        ("python3", tools.python.path.as_path()),
        ("ninja", tools.ninja.path.as_path()),
        ("pkg-config", tools.pkg_config.path.as_path()),
        ("cc", tools.cc.path.as_path()),
        ("c++", tools.cxx_driver.as_path()),
        ("ar", tools.ar.path.as_path()),
        ("bzip2", tools.bzip2.path.as_path()),
        ("ranlib", tools.ranlib_driver.as_path()),
    ]);
    entries.sort_by(|left, right| left.0.cmp(right.0));
    if entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err("controlled QEMU PATH contains duplicate command names".to_owned());
    }
    for (name, tool) in entries {
        let destination = directory.join(name);
        create_symbolic_link(utf8_path(tool)?, &destination).map_err(|error| {
            format!(
                "cannot link controlled QEMU tool {name:?} to {}: {error}",
                tool.display()
            )
        })?;
    }
    write_deterministic_date_shim(&directory)?;
    sync_directory(&directory)?;
    Ok(directory)
}

fn write_deterministic_date_shim(directory: &Path) -> Result<(), String> {
    let destination = directory.join("date");
    let mut file = new_file(&destination, 0o755)?;
    file.write_all(DETERMINISTIC_DATE_SHIM)
        .map_err(|error| format!("cannot write deterministic QEMU date shim: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("cannot sync deterministic QEMU date shim: {error}"))
}

fn run_command(spec: &CommandSpec, label: &str, timeout: Duration) -> Result<(), String> {
    eprintln!(
        "native step {label}: {} {}",
        spec.program.display(),
        spec.arguments
            .iter()
            .map(|argument| argument.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    );
    let mut command = Command::new(&spec.program);
    command
        .env_clear()
        .args(&spec.arguments)
        .current_dir(&spec.current_dir)
        .stdin(Stdio::null());
    for (key, value) in &spec.environment {
        command.env(key, value);
    }
    let output = run_bounded_output(&mut command, label, timeout)?;
    if !output.status.success() {
        return Err(format!(
            "{label} failed with {}: stdout={} stderr={}",
            output.status,
            bounded_text(&output.stdout),
            bounded_text(&output.stderr)
        ));
    }
    Ok(())
}

fn assemble_runtime_bundle(
    plan: &BuildPlan,
    source: &Path,
    build: &Path,
    bundle: &Path,
) -> Result<(), String> {
    let binary_source = build.join("qemu-system-aarch64");
    let binary_measurement = measure_file(&binary_source, 2 * 1024 * 1024 * 1024, true)?;
    if binary_measurement.bytes == 0 {
        return Err("built QEMU binary is empty".to_owned());
    }
    let bin = bundle.join("bin");
    let firmware = bundle.join("firmware");
    let licenses = bundle.join("licenses");
    for directory in [&bin, &firmware, &licenses] {
        fs::create_dir(directory).map_err(|error| {
            format!(
                "cannot create QEMU bundle directory {}: {error}",
                directory.display()
            )
        })?;
    }
    let binary = bin.join("qemu-system-aarch64");
    copy_new_file(&binary_source, &binary, 0o755)?;
    sign_macho(plan, &binary)?;
    inspect_macho_dependencies(plan, &binary)?;
    probe_qemu(plan, &binary)?;

    let code = firmware.join("QEMU_EFI.fd");
    let variables = firmware.join("QEMU_VARS.fd");
    decompress_bzip2(
        &plan.tools.bzip2,
        &source.join(&plan.lock.firmware[0].source_path),
        &code,
        &plan.lock.firmware[0].sha256,
    )?;
    decompress_bzip2(
        &plan.tools.bzip2,
        &source.join(&plan.lock.firmware[1].source_path),
        &variables,
        &plan.lock.firmware[1].sha256,
    )?;
    copy_new_file(&source.join("COPYING"), &licenses.join("COPYING"), 0o644)?;
    copy_new_file(
        &source.join(&plan.lock.firmware[0].license_manifest),
        &licenses.join("edk2-licenses.txt"),
        0o644,
    )?;
    let qemu = measure_file(&binary, 2 * 1024 * 1024 * 1024, true)?;
    let code_measurement = measure_file(&code, 1024 * 1024 * 1024, false)?;
    let variables_measurement = measure_file(&variables, 1024 * 1024 * 1024, false)?;
    let provenance = encode_provenance(plan, &qemu, &code_measurement, &variables_measurement);
    write_new_file(&bundle.join("provenance.txt"), provenance.as_bytes(), 0o644)?;
    normalize_tree_timestamps(bundle, &plan.tools.touch)?;
    Ok(())
}

fn sign_macho(plan: &BuildPlan, binary: &Path) -> Result<(), String> {
    let mut command = Command::new(&plan.tools.codesign.path);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/wrela/no-ambient-path")
        .env("TZ", "UTC")
        .args(["--force", "--sign", "-", "--timestamp=none", "--identifier"])
        .arg("org.wrela.qemu-system-aarch64")
        .arg(binary);
    let output = run_bounded_output(
        &mut command,
        "QEMU ad-hoc code signing",
        Duration::from_secs(60),
    )?;
    if !output.status.success() {
        return Err(format!(
            "deterministic QEMU ad-hoc signing failed: {}",
            bounded_text(&output.stderr)
        ));
    }
    Ok(())
}

fn inspect_macho_dependencies(plan: &BuildPlan, binary: &Path) -> Result<(), String> {
    let mut command = Command::new(&plan.tools.otool.path);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/wrela/no-ambient-path")
        .env("TZ", "UTC")
        .arg("-L")
        .arg(binary);
    let output = run_bounded_output(
        &mut command,
        "QEMU Mach-O inspection",
        Duration::from_secs(60),
    )?;
    if !output.status.success() || !output.stderr.is_empty() {
        return Err(format!(
            "cannot inspect QEMU Mach-O dependencies: {}",
            bounded_text(&output.stderr)
        ));
    }
    let source = std::str::from_utf8(&output.stdout)
        .map_err(|_| "QEMU Mach-O dependency output is not UTF-8".to_owned())?;
    let mut dependencies = Vec::new();
    dependencies
        .try_reserve_exact(REQUIRED_MACHO_DEPENDENCIES.len().saturating_add(8))
        .map_err(|_| "cannot reserve QEMU Mach-O dependency inventory".to_owned())?;
    for line in source.lines().skip(1) {
        let dependency = line
            .trim()
            .split_ascii_whitespace()
            .next()
            .ok_or_else(|| "malformed QEMU Mach-O dependency line".to_owned())?;
        if dependencies.len() >= 64 {
            return Err("QEMU Mach-O dependency inventory exceeds 64 entries".to_owned());
        }
        dependencies
            .try_reserve(1)
            .map_err(|_| "cannot grow QEMU Mach-O dependency inventory".to_owned())?;
        dependencies.push(dependency);
    }
    dependencies.sort_unstable();
    if dependencies != REQUIRED_MACHO_DEPENDENCIES {
        return Err(format!(
            "QEMU Mach-O dependency inventory is not the exact reviewed SDK closure: {dependencies:?}"
        ));
    }
    Ok(())
}

fn probe_qemu(plan: &BuildPlan, binary: &Path) -> Result<(), String> {
    for (label, arguments, required) in [
        (
            "QEMU version probe",
            vec![OsString::from("--version")],
            format!("QEMU emulator version {}", plan.lock.version),
        ),
        (
            "QEMU machine probe",
            vec![OsString::from("-machine"), OsString::from("help")],
            plan.lock.machine_contract.clone(),
        ),
        (
            "QEMU CPU probe",
            vec![OsString::from("-cpu"), OsString::from("help")],
            plan.lock.cpu_contract.clone(),
        ),
    ] {
        let mut command = Command::new(binary);
        command
            .env_clear()
            .env("LC_ALL", "C")
            .env("PATH", "/wrela/no-ambient-path")
            .env("TZ", "UTC")
            .args(arguments);
        let output = run_bounded_output(&mut command, label, Duration::from_secs(60))?;
        if !output.status.success() {
            return Err(format!("{label} failed: {}", bounded_text(&output.stderr)));
        }
        let mut observed = output.stdout;
        observed.extend_from_slice(&output.stderr);
        let text =
            std::str::from_utf8(&observed).map_err(|_| format!("{label} returned non-UTF-8"))?;
        if !text.contains(&required) {
            return Err(format!("{label} omits exact contract {required:?}"));
        }
    }
    Ok(())
}

fn decompress_bzip2(
    bzip2: &ToolIdentity,
    source: &Path,
    destination: &Path,
    expected_sha256: &str,
) -> Result<(), String> {
    let mut command = Command::new(&bzip2.path);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/wrela/no-ambient-path")
        .env("TZ", "UTC")
        .args(["-d", "-c", "--"])
        .arg(source);
    stream_command_to_file(
        &mut command,
        destination,
        1024 * 1024 * 1024,
        "firmware decompression",
        Duration::from_secs(10 * 60),
    )?;
    let measurement = measure_file(destination, 1024 * 1024 * 1024, false)?;
    if measurement.sha256 != expected_sha256 {
        return Err(format!(
            "decompressed firmware {} does not match pinned SHA-256",
            destination.display()
        ));
    }
    Ok(())
}

fn encode_provenance(
    plan: &BuildPlan,
    qemu: &FileMeasurement,
    code: &FileMeasurement,
    variables: &FileMeasurement,
) -> String {
    format!(
        "schema = 1\n\
build_contract_version = {BUILD_CONTRACT_VERSION}\n\
qemu_version = \"{}\"\n\
host = \"{}\"\n\
emulation_lock_sha256 = \"{}\"\n\
source_sha256 = \"{}\"\n\
signature_sha256 = \"{}\"\n\
signing_key_fingerprint = \"{}\"\n\
signing_key_sha256 = \"{}\"\n\
signature_timestamp = {}\n\
native_input_sha256 = \"{}\"\n\
static_dependency_sha256 = \"{}\"\n\
implementation_sha256 = \"{}\"\n\
qemu_sha256 = \"{}\"\n\
qemu_bytes = {}\n\
firmware_code_sha256 = \"{}\"\n\
firmware_code_bytes = {}\n\
firmware_variables_sha256 = \"{}\"\n\
firmware_variables_bytes = {}\n",
        plan.lock.version,
        plan.host,
        plan.lock.bytes_sha256,
        plan.inputs.archive_measurement.sha256,
        plan.inputs.signature_measurement.sha256,
        plan.lock.signing_key_fingerprint,
        plan.inputs.signing_key_measurement.sha256,
        plan.inputs.signature_timestamp,
        plan.native_input_sha256,
        plan.static_dependencies.sha256,
        plan.implementation_sha256,
        qemu.sha256,
        qemu.bytes,
        code.sha256,
        code.bytes,
        variables.sha256,
        variables.bytes,
    )
}

fn output_for_measurement(
    plan: &BuildPlan,
    bundle: &Path,
    tree: &TreeMeasurement,
) -> Result<EmulationOutput, String> {
    let qemu = required_record(tree, "bin/qemu-system-aarch64")?;
    let code = required_record(tree, "firmware/QEMU_EFI.fd")?;
    let variables = required_record(tree, "firmware/QEMU_VARS.fd")?;
    if !qemu.executable || code.executable || variables.executable {
        return Err("QEMU bundle executable modes are not canonical".to_owned());
    }
    if code.sha256 != plan.lock.firmware[0].sha256
        || variables.sha256 != plan.lock.firmware[1].sha256
    {
        return Err("QEMU bundle firmware differs from emulation.lock.toml".to_owned());
    }
    let expected_paths = [
        "bin/qemu-system-aarch64",
        "firmware/QEMU_EFI.fd",
        "firmware/QEMU_VARS.fd",
        "licenses/COPYING",
        "licenses/edk2-licenses.txt",
        "provenance.txt",
    ];
    if tree.records.len() != expected_paths.len()
        || !tree
            .records
            .iter()
            .map(|record| record.path.as_str())
            .eq(expected_paths)
    {
        return Err(format!(
            "QEMU runtime bundle contains an undeclared file under {}",
            bundle.display()
        ));
    }
    Ok(EmulationOutput {
        emulation_lock_sha256: plan.lock.bytes_sha256.clone(),
        native_input_sha256: plan.native_input_sha256.clone(),
        qemu_version: plan.lock.version.clone(),
        host: plan.host.clone(),
        bundle_tree_sha256: tree.sha256.clone(),
        bundle_files: tree.files,
        bundle_bytes: tree.bytes,
        qemu_sha256: qemu.sha256.clone(),
        qemu_bytes: qemu.bytes,
        firmware_code_sha256: code.sha256.clone(),
        firmware_code_bytes: code.bytes,
        firmware_variables_sha256: variables.sha256.clone(),
        firmware_variables_bytes: variables.bytes,
    })
}

fn verify_bundle(
    bundle: &Path,
    plan: &BuildPlan,
    expected: &EmulationOutput,
) -> Result<(), String> {
    let bundle = exact_directory(bundle, "QEMU runtime bundle")?;
    let tree = measure_tree(&bundle, MAX_TREE_FILES, MAX_TREE_BYTES)?;
    let observed = output_for_measurement(plan, &bundle, &tree)?;
    if &observed != expected {
        return Err(format!(
            "QEMU payload differs from its authenticated output enrollment: expected {}, observed {}",
            expected.bundle_tree_sha256, observed.bundle_tree_sha256
        ));
    }
    let provenance = read_bounded_file(&bundle.join("provenance.txt"), MAX_LOCK_BYTES)?;
    let provenance = canonical_text(&provenance, "QEMU provenance")?;
    for identity in [
        plan.lock.bytes_sha256.as_str(),
        plan.lock.source_sha256.as_str(),
        plan.lock.signing_key_fingerprint.as_str(),
        plan.native_input_sha256.as_str(),
        expected.qemu_sha256.as_str(),
        expected.firmware_code_sha256.as_str(),
        expected.firmware_variables_sha256.as_str(),
    ] {
        if !provenance.contains(identity) {
            return Err("QEMU provenance omits an authenticated native identity".to_owned());
        }
    }
    let binary = bundle.join("bin/qemu-system-aarch64");
    inspect_macho_dependencies(plan, &binary)?;
    probe_qemu(plan, &binary)
}

fn required_record<'a>(tree: &'a TreeMeasurement, path: &str) -> Result<&'a FileRecord, String> {
    tree.records
        .binary_search_by(|record| record.path.as_str().cmp(path))
        .ok()
        .and_then(|index| tree.records.get(index))
        .ok_or_else(|| format!("QEMU payload omits required file {path}"))
}

fn revalidate_plan_inputs(plan: &BuildPlan) -> Result<(), String> {
    let lock_bytes = read_bounded_file(
        &plan.root.join("toolchain/emulation.lock.toml"),
        MAX_LOCK_BYTES,
    )?;
    if lock_bytes != plan.lock_bytes || decode_lock(&lock_bytes)? != plan.lock {
        return Err("emulation.lock.toml changed during QEMU bootstrap".to_owned());
    }
    for (path, expected, maximum, label) in [
        (
            plan.inputs.archive.as_path(),
            &plan.inputs.archive_measurement,
            MAX_ARCHIVE_BYTES,
            "source archive",
        ),
        (
            plan.inputs.signature.as_path(),
            &plan.inputs.signature_measurement,
            MAX_SIGNATURE_BYTES,
            "detached signature",
        ),
        (
            plan.inputs.signing_key.as_path(),
            &plan.inputs.signing_key_measurement,
            MAX_KEY_BYTES,
            "signing key",
        ),
    ] {
        if &measure_file(path, maximum, false)? != expected {
            return Err(format!("QEMU {label} changed during bootstrap"));
        }
    }
    for (label, tool) in tool_inventory(&plan.tools) {
        if identify_tool(&tool.path)? != *tool {
            return Err(format!("QEMU native tool {label} changed during bootstrap"));
        }
    }
    for (name, tool) in &plan.tools.utilities {
        if identify_tool(&tool.path)? != *tool {
            return Err(format!(
                "QEMU controlled host utility {name} changed during bootstrap"
            ));
        }
    }
    if resolve_apple_sysroot()? != plan.tools.sysroot {
        return Err("macOS SDK identity changed during QEMU bootstrap".to_owned());
    }
    if resolve_apple_toolchain(
        &plan.tools.cc,
        &plan.tools.cxx,
        &plan.tools.cxx_driver,
        &plan.tools.linker,
        &plan.tools.ar,
        &plan.tools.ranlib,
        &plan.tools.ranlib_driver,
    )? != plan.tools.apple_toolchain
    {
        return Err("Apple toolchain identity changed during QEMU bootstrap".to_owned());
    }
    let (cxx, cxx_driver) = resolve_apple_cxx()?;
    if cxx != plan.tools.cxx || cxx_driver != plan.tools.cxx_driver {
        return Err("Apple C++ driver selection changed during QEMU bootstrap".to_owned());
    }
    let (ranlib, ranlib_driver) = resolve_apple_ranlib()?;
    if ranlib != plan.tools.ranlib || ranlib_driver != plan.tools.ranlib_driver {
        return Err("Apple ranlib driver selection changed during QEMU bootstrap".to_owned());
    }
    if resolve_python_runtime(&plan.tools.python)? != plan.tools.python_runtime {
        return Err("Python runtime identity changed during QEMU bootstrap".to_owned());
    }
    if resolve_host_system()? != plan.tools.host_system {
        return Err("macOS system-build identity changed during QEMU bootstrap".to_owned());
    }
    if measure_dynamic_library_closure(&plan.tools)? != plan.tools.dynamic_libraries {
        return Err("native dynamic-library closure changed during QEMU bootstrap".to_owned());
    }
    if measure_static_dependency_contract(&plan.tools)? != plan.static_dependencies {
        return Err("static dependency closure changed during QEMU bootstrap".to_owned());
    }
    if identify_current_executable()? != plan.bootstrap_executable
        || implementation_digest(&plan.root)? != plan.implementation_sha256
    {
        return Err("QEMU bootstrap implementation changed while running".to_owned());
    }
    if let Some(expected) = &plan.expected_output {
        if load_expected_output(&plan.root)?.as_ref() != Some(expected) {
            return Err("emulation.outputs.toml changed during QEMU bootstrap".to_owned());
        }
    }
    Ok(())
}

fn record_expected_output(root: &Path, output: &EmulationOutput) -> Result<(), String> {
    let path = root.join("toolchain/emulation.outputs.toml");
    write_new_file(&path, encode_expected_output(output).as_bytes(), 0o644)?;
    sync_directory(
        path.parent()
            .ok_or_else(|| "emulation output lock has no parent".to_owned())?,
    )?;
    if load_expected_output(root)?.as_ref() != Some(output) {
        return Err("new emulation output lock failed exact revalidation".to_owned());
    }
    Ok(())
}

fn publish_bundle(staged: &Path, destination: &Path) -> Result<(), String> {
    let parent = destination
        .parent()
        .ok_or_else(|| "QEMU bundle destination has no parent".to_owned())?;
    ensure_directory(parent)?;
    if destination.exists() {
        return Err(format!(
            "QEMU bundle destination already exists: {}",
            destination.display()
        ));
    }
    fs::rename(staged, destination).map_err(|error| {
        format!(
            "cannot atomically publish QEMU bundle {}: {error}",
            destination.display()
        )
    })?;
    sync_directory(parent)
}

fn normalize_tree_timestamps(root: &Path, touch: &ToolIdentity) -> Result<(), String> {
    let mut paths = Vec::new();
    collect_paths(root, 0, &mut paths)?;
    paths.sort();
    for chunk in paths.chunks(128) {
        let mut command = Command::new(&touch.path);
        command
            .env_clear()
            .env("LC_ALL", "C")
            .env("PATH", "/wrela/no-ambient-path")
            .env("TZ", "UTC")
            .args(["-h", "-t", "197001010000.01", "--"])
            .args(chunk);
        let output = run_bounded_output(
            &mut command,
            "QEMU timestamp normalization",
            Duration::from_secs(5 * 60),
        )?;
        if !output.status.success() {
            return Err(format!(
                "cannot normalize QEMU timestamps: {}",
                bounded_text(&output.stderr)
            ));
        }
    }
    Ok(())
}

fn collect_paths(path: &Path, depth: u32, output: &mut Vec<PathBuf>) -> Result<(), String> {
    if depth > MAX_TREE_DEPTH {
        return Err("QEMU bundle exceeds path depth limit".to_owned());
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if metadata.is_dir() {
        for entry in fs::read_dir(path)
            .map_err(|error| format!("cannot enumerate {}: {error}", path.display()))?
        {
            let entry = entry.map_err(|error| format!("cannot enumerate path: {error}"))?;
            collect_paths(&entry.path(), depth.saturating_add(1), output)?;
        }
    }
    output.push(path.to_owned());
    Ok(())
}

#[derive(Debug)]
struct ProcessOutput {
    status: std::process::ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run_bounded_output(
    command: &mut Command,
    label: &str,
    timeout: Duration,
) -> Result<ProcessOutput, String> {
    if timeout.is_zero() || timeout > Duration::from_secs(24 * 60 * 60) {
        return Err(format!("invalid timeout for {label}"));
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_child_process_group(command);
    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot execute {label}: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| format!("{label} stdout is unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| format!("{label} stderr is unavailable"))?;
    let (sender, receiver) = mpsc::channel();
    let stdout_sender = sender.clone();
    let stdout_thread = thread::spawn(move || {
        let result = read_bounded_pipe(stdout, MAX_PROCESS_OUTPUT, "stdout");
        let _ = stdout_sender.send((false, result));
    });
    let stderr_thread = thread::spawn(move || {
        let result = read_bounded_pipe(stderr, MAX_PROCESS_OUTPUT, "stderr");
        let _ = sender.send((true, result));
    });
    let started = Instant::now();
    let mut status = None;
    let mut stdout_result = None;
    let mut stderr_result = None;
    let mut failure = None;
    while status.is_none() || stdout_result.is_none() || stderr_result.is_none() {
        if started.elapsed() >= timeout {
            failure = Some(format!("{label} exceeded {} seconds", timeout.as_secs()));
            break;
        }
        match receiver.recv_timeout(Duration::from_millis(20)) {
            Ok((is_stderr, Ok(bytes))) => {
                let slot = if is_stderr {
                    &mut stderr_result
                } else {
                    &mut stdout_result
                };
                if slot.replace(bytes).is_some() {
                    failure = Some(format!("{label} produced duplicate pipe completion"));
                    break;
                }
            }
            Ok((_, Err(error))) => {
                failure = Some(format!("{label} {error}"));
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if stdout_result.is_none() || stderr_result.is_none() {
                    failure = Some(format!("{label} output readers disconnected"));
                    break;
                }
            }
        }
        if status.is_none() {
            status = child
                .try_wait()
                .map_err(|error| format!("cannot poll {label}: {error}"))?;
            if status.is_some() {
                kill_process_group(child.id());
            }
        }
    }
    if failure.is_some() {
        kill_process_group(child.id());
        let _ = child.kill();
    }
    if status.is_none() {
        status = Some(
            child
                .wait()
                .map_err(|error| format!("cannot wait for {label}: {error}"))?,
        );
    }
    stdout_thread
        .join()
        .map_err(|_| format!("{label} stdout reader panicked"))?;
    stderr_thread
        .join()
        .map_err(|_| format!("{label} stderr reader panicked"))?;
    if let Some(error) = failure {
        return Err(error);
    }
    Ok(ProcessOutput {
        status: status.ok_or_else(|| format!("{label} has no exit status"))?,
        stdout: stdout_result.ok_or_else(|| format!("{label} has no stdout result"))?,
        stderr: stderr_result.ok_or_else(|| format!("{label} has no stderr result"))?,
    })
}

fn read_bounded_pipe(reader: impl Read, maximum: usize, label: &str) -> Result<Vec<u8>, String> {
    let limit =
        u64::try_from(maximum).map_err(|_| "process output limit does not fit u64".to_owned())?;
    let mut output = Vec::new();
    output
        .try_reserve(maximum.min(64 * 1024))
        .map_err(|_| format!("cannot reserve bounded {label} output"))?;
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut output)
        .map_err(|error| format!("cannot read process {label}: {error}"))?;
    if output.len() > maximum {
        return Err(format!("process {label} exceeds {maximum} bytes"));
    }
    Ok(output)
}

fn stream_command_to_file(
    command: &mut Command,
    destination: &Path,
    maximum: u64,
    label: &str,
    timeout: Duration,
) -> Result<(), String> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_child_process_group(command);
    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot execute {label}: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| format!("{label} stdout is unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| format!("{label} stderr is unavailable"))?;
    let destination_owned = destination.to_owned();
    let (sender, receiver) = mpsc::channel();
    let stdout_sender = sender.clone();
    let stdout_thread = thread::spawn(move || {
        let result = write_bounded_stream(stdout, &destination_owned, maximum);
        let _ = stdout_sender.send((false, result.map(|_| Vec::new())));
    });
    let stderr_thread = thread::spawn(move || {
        let result = read_bounded_pipe(stderr, MAX_PROCESS_OUTPUT, "stderr");
        let _ = sender.send((true, result));
    });
    let started = Instant::now();
    let mut status = None;
    let mut writer_done = false;
    let mut stderr_result = None;
    let mut failure = None;
    while status.is_none() || !writer_done || stderr_result.is_none() {
        if started.elapsed() >= timeout {
            failure = Some(format!("{label} exceeded {} seconds", timeout.as_secs()));
            break;
        }
        match receiver.recv_timeout(Duration::from_millis(20)) {
            Ok((false, Ok(_))) if !writer_done => writer_done = true,
            Ok((true, Ok(bytes))) if stderr_result.is_none() => stderr_result = Some(bytes),
            Ok((_, Ok(_))) => {
                failure = Some(format!("{label} produced duplicate stream completion"));
                break;
            }
            Ok((_, Err(error))) => {
                failure = Some(format!("{label} {error}"));
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                failure = Some(format!("{label} stream readers disconnected"));
                break;
            }
        }
        if status.is_none() {
            status = child
                .try_wait()
                .map_err(|error| format!("cannot poll {label}: {error}"))?;
            if status.is_some() {
                kill_process_group(child.id());
            }
        }
    }
    if failure.is_some() {
        kill_process_group(child.id());
        let _ = child.kill();
    }
    if status.is_none() {
        status = Some(
            child
                .wait()
                .map_err(|error| format!("cannot wait for {label}: {error}"))?,
        );
    }
    stdout_thread
        .join()
        .map_err(|_| format!("{label} output writer panicked"))?;
    stderr_thread
        .join()
        .map_err(|_| format!("{label} stderr reader panicked"))?;
    if let Some(error) = failure {
        let _ = fs::remove_file(destination);
        return Err(error);
    }
    let status = status.ok_or_else(|| format!("{label} has no exit status"))?;
    let stderr = stderr_result.ok_or_else(|| format!("{label} has no stderr result"))?;
    if !status.success() {
        let _ = fs::remove_file(destination);
        return Err(format!(
            "{label} failed with {status}: {}",
            bounded_text(&stderr)
        ));
    }
    Ok(())
}

fn write_bounded_stream(
    mut reader: impl Read,
    destination: &Path,
    maximum: u64,
) -> Result<(), String> {
    let mut output = new_file(destination, 0o644)?;
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| format!("cannot read decompressed stream: {error}"))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| "stream size overflow".to_owned())?)
            .ok_or_else(|| "stream size overflow".to_owned())?;
        if total > maximum {
            return Err(format!("decompressed stream exceeds {maximum} bytes"));
        }
        output
            .write_all(&buffer[..read])
            .map_err(|error| format!("cannot write {}: {error}", destination.display()))?;
    }
    if total == 0 {
        return Err("decompressed stream is empty".to_owned());
    }
    output
        .sync_all()
        .map_err(|error| format!("cannot sync {}: {error}", destination.display()))
}

#[cfg(unix)]
fn configure_child_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(not(unix))]
fn configure_child_process_group(_command: &mut Command) {}

#[cfg(unix)]
fn kill_process_group(process_id: u32) {
    let group = format!("-{process_id}");
    let _ = Command::new("/bin/kill")
        .env_clear()
        .args(["-KILL", &group])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

#[cfg(not(unix))]
fn kill_process_group(_process_id: u32) {}

fn bounded_text(bytes: &[u8]) -> String {
    let text = if bytes.len() <= MAX_DISPLAYED_PROCESS_OUTPUT {
        String::from_utf8_lossy(bytes).into_owned()
    } else {
        let suffix_bytes = MAX_DISPLAYED_PROCESS_OUTPUT - DISPLAYED_PROCESS_OUTPUT_PREFIX;
        let omitted = bytes.len() - DISPLAYED_PROCESS_OUTPUT_PREFIX - suffix_bytes;
        format!(
            "{}\n... omitted {omitted} process-output bytes ...\n{}",
            String::from_utf8_lossy(&bytes[..DISPLAYED_PROCESS_OUTPUT_PREFIX]),
            String::from_utf8_lossy(&bytes[bytes.len() - suffix_bytes..]),
        )
    };
    text.replace(['\r', '\0'], "?")
}

fn measure_file(
    path: &Path,
    maximum: u64,
    require_executable: bool,
) -> Result<FileMeasurement, String> {
    measure_file_inner(path, maximum, require_executable, false)
}

fn measure_tree_file(
    path: &Path,
    maximum: u64,
    require_executable: bool,
) -> Result<FileMeasurement, String> {
    measure_file_inner(path, maximum, require_executable, true)
}

fn measure_file_inner(
    path: &Path,
    maximum: u64,
    require_executable: bool,
    allow_empty: bool,
) -> Result<FileMeasurement, String> {
    let before = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if before.file_type().is_symlink()
        || !before.is_file()
        || (!allow_empty && before.len() == 0)
        || before.len() > maximum
    {
        return Err(format!(
            "{} is not a permitted regular file within {maximum} bytes",
            path.display()
        ));
    }
    validate_safe_file_mode(path, &before, require_executable)?;
    let file =
        File::open(path).map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("cannot inspect opened {}: {error}", path.display()))?;
    if !same_metadata(&before, &opened) {
        return Err(format!("{} changed while being opened", path.display()));
    }
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| "file size overflow".to_owned())?)
            .ok_or_else(|| "file size overflow".to_owned())?;
        if total > maximum {
            return Err(format!("{} exceeds {maximum} bytes", path.display()));
        }
        hasher.update(&buffer[..read]);
    }
    let after = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot re-inspect {}: {error}", path.display()))?;
    if total != before.len() || !same_metadata(&before, &after) {
        return Err(format!("{} changed while being measured", path.display()));
    }
    Ok(FileMeasurement {
        sha256: lower_hex(&hasher.finalize()),
        bytes: total,
    })
}

fn read_bounded_file(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    let measurement = measure_file(path, maximum, false)?;
    let capacity = usize::try_from(measurement.bytes)
        .map_err(|_| format!("{} is too large for this host", path.display()))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| format!("cannot reserve {} bytes", path.display()))?;
    File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if bytes.len() != capacity || sha256_bytes(&bytes) != measurement.sha256 {
        return Err(format!(
            "{} changed between measurement and read",
            path.display()
        ));
    }
    Ok(bytes)
}

fn measure_tree(root: &Path, max_files: u64, max_bytes: u64) -> Result<TreeMeasurement, String> {
    let mut records = Vec::new();
    let mut files = 0u64;
    let mut bytes = 0u64;
    walk_tree(
        root,
        "",
        0,
        max_files,
        max_bytes,
        &mut files,
        &mut bytes,
        &mut records,
    )?;
    records.sort_by(|left, right| left.path.cmp(&right.path));
    if records.is_empty()
        || records.windows(2).any(|pair| pair[0].path >= pair[1].path)
        || files != u64::try_from(records.len()).map_err(|_| "tree size overflow".to_owned())?
        || bytes == 0
    {
        return Err("tree is empty, duplicated, or internally inconsistent".to_owned());
    }
    let mut digest = Sha256::new();
    digest.update(TREE_MAGIC);
    digest.update(TREE_VERSION.to_le_bytes());
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

#[allow(clippy::too_many_arguments)]
fn walk_tree(
    directory: &Path,
    prefix: &str,
    depth: u32,
    max_files: u64,
    max_bytes: u64,
    files: &mut u64,
    bytes: &mut u64,
    records: &mut Vec<FileRecord>,
) -> Result<(), String> {
    if depth > MAX_TREE_DEPTH {
        return Err(format!("tree exceeds depth {MAX_TREE_DEPTH}"));
    }
    let before = fs::symlink_metadata(directory)
        .map_err(|error| format!("cannot inspect {}: {error}", directory.display()))?;
    if before.file_type().is_symlink() || !before.is_dir() {
        return Err(format!(
            "{} is not a regular directory",
            directory.display()
        ));
    }
    validate_safe_directory_mode(directory, &before)?;
    let mut entries = Vec::new();
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("cannot enumerate {}: {error}", directory.display()))?
    {
        let entry = entry.map_err(|error| format!("cannot enumerate tree entry: {error}"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| format!("tree contains a non-UTF-8 name in {}", directory.display()))?;
        if !portable_component(&name) {
            return Err(format!("tree contains nonportable component {name:?}"));
        }
        entries.push((name, entry.path()));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
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
        if relative.len() > MAX_PATH_BYTES {
            return Err(format!("tree path exceeds limit: {relative:?}"));
        }
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!("runtime tree contains symbolic link {relative:?}"));
        }
        if metadata.is_dir() {
            walk_tree(
                &path,
                &relative,
                depth.saturating_add(1),
                max_files,
                max_bytes,
                files,
                bytes,
                records,
            )?;
        } else if metadata.is_file() {
            let executable = is_executable(&metadata);
            let remaining = max_bytes
                .checked_sub(*bytes)
                .ok_or_else(|| "tree byte budget exhausted".to_owned())?;
            let measurement = measure_file(&path, remaining, executable)?;
            *files = files
                .checked_add(1)
                .ok_or_else(|| "tree file count overflow".to_owned())?;
            *bytes = bytes
                .checked_add(measurement.bytes)
                .ok_or_else(|| "tree byte count overflow".to_owned())?;
            if *files > max_files || *bytes > max_bytes {
                return Err("tree exceeds its finite file or byte limit".to_owned());
            }
            records.push(FileRecord {
                path: relative,
                bytes: measurement.bytes,
                sha256: measurement.sha256,
                executable,
            });
        } else {
            return Err(format!("tree contains unsupported entry {relative:?}"));
        }
    }
    let after = fs::symlink_metadata(directory)
        .map_err(|error| format!("cannot re-inspect {}: {error}", directory.display()))?;
    if !same_metadata(&before, &after) {
        return Err(format!(
            "tree directory changed while read: {}",
            directory.display()
        ));
    }
    Ok(())
}

fn measure_directory_identity(
    path: &Path,
    max_files: u64,
    max_bytes: u64,
) -> Result<DirectoryIdentity, String> {
    let tree = measure_tree(path, max_files, max_bytes)?;
    Ok(DirectoryIdentity {
        path: path.to_owned(),
        sha256: tree.sha256,
        files: tree.files,
        bytes: tree.bytes,
    })
}

#[cfg(unix)]
fn validate_safe_file_mode(
    path: &Path,
    metadata: &fs::Metadata,
    require_executable: bool,
) -> Result<(), String> {
    let mode = metadata.mode() & 0o7777;
    if mode & 0o022 != 0 || (require_executable && mode & 0o100 == 0) {
        return Err(format!(
            "{} has unsafe or nonexecutable mode {mode:04o}",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_safe_file_mode(
    _path: &Path,
    _metadata: &fs::Metadata,
    _require_executable: bool,
) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn validate_safe_directory_mode(path: &Path, metadata: &fs::Metadata) -> Result<(), String> {
    let mode = metadata.mode() & 0o7777;
    if mode & 0o022 != 0 {
        return Err(format!("{} has unsafe mode {mode:04o}", path.display()));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_safe_directory_mode(_path: &Path, _metadata: &fs::Metadata) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn same_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
        && left.mode() == right.mode()
}

#[cfg(not(unix))]
fn same_metadata(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    metadata.mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &fs::Metadata) -> bool {
    false
}

fn portable_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && value.len() <= 255
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'+' | b'-' | b',' | b'(' | b')' | b'@')
        })
}

fn exact_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    let path = fs::canonicalize(path)
        .map_err(|error| format!("cannot resolve {label} {}: {error}", path.display()))?;
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("cannot inspect {label} {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("{label} is not a non-symlink directory"));
    }
    Ok(path)
}

fn ensure_directory(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err(format!(
            "generated directory must be absolute: {}",
            path.display()
        ));
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        if matches!(component, Component::RootDir | Component::Prefix(_)) {
            continue;
        }
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(format!(
                    "generated directory chain contains unsafe entry {}",
                    current.display()
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(|error| {
                    format!("cannot create directory {}: {error}", current.display())
                })?;
            }
            Err(error) => {
                return Err(format!(
                    "cannot inspect directory {}: {error}",
                    current.display()
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn create_private_directory(path: &Path) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_directory(path: &Path) -> io::Result<()> {
    fs::create_dir(path)
}

fn copy_new_file(source: &Path, destination: &Path, mode: u32) -> Result<(), String> {
    let maximum = 4 * 1024 * 1024 * 1024;
    let expected = measure_file(source, maximum, false)?;
    let mut input =
        File::open(source).map_err(|error| format!("cannot open {}: {error}", source.display()))?;
    let mut output = new_file(destination, mode)?;
    let copied = io::copy(&mut input, &mut output)
        .map_err(|error| format!("cannot copy to {}: {error}", destination.display()))?;
    output
        .sync_all()
        .map_err(|error| format!("cannot sync {}: {error}", destination.display()))?;
    if copied != expected.bytes {
        return Err(format!("{} changed while copied", source.display()));
    }
    let observed = measure_file(destination, maximum, mode & 0o111 != 0)?;
    if observed != expected {
        return Err(format!(
            "copied file {} differs from source",
            destination.display()
        ));
    }
    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    if bytes.is_empty() {
        return Err(format!("refusing to create empty file {}", path.display()));
    }
    let mut file = new_file(path, mode)?;
    file.write_all(bytes)
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("cannot sync {}: {error}", path.display()))
}

fn new_file(path: &Path, mode: u32) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(mode);
    let file = options
        .open(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| format!("cannot set permissions on {}: {error}", path.display()))?;
    Ok(file)
}

fn sync_directory(path: &Path) -> Result<(), String> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("cannot sync directory {}: {error}", path.display()))
}

fn sync_tree(root: &Path) -> Result<(), String> {
    fn visit(path: &Path, depth: u32) -> Result<(), String> {
        if depth > MAX_TREE_DEPTH {
            return Err("sync tree exceeds depth limit".to_owned());
        }
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
        if metadata.is_file() {
            return File::open(path)
                .and_then(|file| file.sync_all())
                .map_err(|error| format!("cannot sync {}: {error}", path.display()));
        }
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(format!("cannot sync unsupported entry {}", path.display()));
        }
        let mut entries = Vec::new();
        for entry in fs::read_dir(path)
            .map_err(|error| format!("cannot enumerate {}: {error}", path.display()))?
        {
            entries.push(
                entry
                    .map_err(|error| format!("cannot enumerate sync entry: {error}"))?
                    .path(),
            );
        }
        entries.sort();
        for entry in entries {
            visit(&entry, depth.saturating_add(1))?;
        }
        sync_directory(path)
    }
    visit(root, 0)
}

fn utf8_path(path: &Path) -> Result<&str, String> {
    path.to_str()
        .ok_or_else(|| format!("path is not UTF-8: {}", path.display()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    lower_hex(&digest.finalize())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
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

fn hex_bytes(value: &str) -> Result<Vec<u8>, String> {
    if !valid_sha256(value) {
        return Err("invalid SHA-256 value".to_owned());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err("invalid lowercase hex digit".to_owned()),
    }
}

fn update_length_prefixed(digest: &mut Sha256, bytes: &[u8]) -> Result<(), String> {
    let length = u64::try_from(bytes.len()).map_err(|_| "identity length overflow".to_owned())?;
    digest.update(length.to_le_bytes());
    digest.update(bytes);
    Ok(())
}

fn extract_authenticated_archive(
    archive: &Path,
    xz: &ToolIdentity,
    destination: &Path,
    expected_root: &str,
) -> Result<(), String> {
    let mut command = Command::new(&xz.path);
    command
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/wrela/no-ambient-path")
        .env("TZ", "UTC")
        .args(["-d", "-c", "--"])
        .arg(archive)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    configure_child_process_group(&mut command);
    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot execute authenticated xz extraction: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "xz extraction stdout is unavailable".to_owned())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "xz extraction stderr is unavailable".to_owned())?;
    let destination = destination.to_owned();
    let expected_root = expected_root.to_owned();
    let (sender, receiver) = mpsc::channel();
    let parser_sender = sender.clone();
    let parser = thread::spawn(move || {
        let result = extract_tar_stream(stdout, &destination, &expected_root);
        let _ = parser_sender.send((false, result.map(|_| Vec::new())));
    });
    let error_reader = thread::spawn(move || {
        let result = read_bounded_pipe(stderr, MAX_PROCESS_OUTPUT, "stderr");
        let _ = sender.send((true, result));
    });
    let started = Instant::now();
    let timeout = Duration::from_secs(60 * 60);
    let mut status = None;
    let mut parsed = false;
    let mut stderr_result = None;
    let mut failure = None;
    while status.is_none() || !parsed || stderr_result.is_none() {
        if started.elapsed() >= timeout {
            failure = Some("authenticated QEMU extraction exceeded one hour".to_owned());
            break;
        }
        match receiver.recv_timeout(Duration::from_millis(20)) {
            Ok((false, Ok(_))) if !parsed => parsed = true,
            Ok((true, Ok(bytes))) if stderr_result.is_none() => stderr_result = Some(bytes),
            Ok((_, Ok(_))) => {
                failure = Some("QEMU extraction produced duplicate stream completion".to_owned());
                break;
            }
            Ok((_, Err(error))) => {
                failure = Some(error);
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                failure = Some("QEMU extraction stream readers disconnected".to_owned());
                break;
            }
        }
        if status.is_none() {
            status = child
                .try_wait()
                .map_err(|error| format!("cannot poll xz extraction: {error}"))?;
            if status.is_some() {
                kill_process_group(child.id());
            }
        }
    }
    if failure.is_some() {
        kill_process_group(child.id());
        let _ = child.kill();
    }
    if status.is_none() {
        status = Some(
            child
                .wait()
                .map_err(|error| format!("cannot wait for xz extraction: {error}"))?,
        );
    }
    parser
        .join()
        .map_err(|_| "QEMU tar parser panicked".to_owned())?;
    error_reader
        .join()
        .map_err(|_| "QEMU xz stderr reader panicked".to_owned())?;
    if let Some(error) = failure {
        return Err(error);
    }
    let status = status.ok_or_else(|| "xz extraction has no exit status".to_owned())?;
    let stderr = stderr_result.ok_or_else(|| "xz extraction has no stderr result".to_owned())?;
    if !status.success() || !stderr.is_empty() {
        return Err(format!(
            "authenticated xz extraction failed with {status}: {}",
            bounded_text(&stderr)
        ));
    }
    Ok(())
}

#[derive(Debug, Default)]
struct PendingTarMetadata {
    path: Option<String>,
    link_path: Option<String>,
}

fn extract_tar_stream(
    mut reader: impl Read,
    destination: &Path,
    expected_root: &str,
) -> Result<(), String> {
    if !expected_root.ends_with('/')
        || expected_root.starts_with('/')
        || expected_root[..expected_root.len() - 1].contains('/')
    {
        return Err("expected tar root is not one canonical component".to_owned());
    }
    let mut members = 0u64;
    let mut total_bytes = 0u64;
    let mut paths = BTreeSet::new();
    let mut portable_paths = BTreeSet::new();
    let mut pending = PendingTarMetadata::default();
    let mut zero_blocks = 0u8;
    let mut omitted_absolute_link = false;
    loop {
        let Some(header) = read_tar_block(&mut reader)? else {
            return Err("tar archive ended before two zero terminators".to_owned());
        };
        if header.iter().all(|byte| *byte == 0) {
            zero_blocks = zero_blocks.saturating_add(1);
            if zero_blocks == 2 {
                break;
            }
            continue;
        }
        if zero_blocks != 0 {
            return Err("tar archive contains data after its first zero terminator".to_owned());
        }
        validate_tar_checksum(&header)?;
        if &header[257..262] != b"ustar" {
            return Err("tar member is not ustar/GNU format".to_owned());
        }
        members = members
            .checked_add(1)
            .ok_or_else(|| "tar member count overflow".to_owned())?;
        if members > MAX_ARCHIVE_MEMBERS {
            return Err(format!("tar archive exceeds {MAX_ARCHIVE_MEMBERS} members"));
        }
        let size = parse_tar_octal(&header[124..136], "member size")?;
        if size > MAX_ARCHIVE_FILE_BYTES {
            return Err(format!("tar member exceeds {MAX_ARCHIVE_FILE_BYTES} bytes"));
        }
        total_bytes = total_bytes
            .checked_add(size)
            .ok_or_else(|| "tar aggregate size overflow".to_owned())?;
        if total_bytes > MAX_ARCHIVE_TOTAL_BYTES {
            return Err(format!(
                "tar archive exceeds {MAX_ARCHIVE_TOTAL_BYTES} payload bytes"
            ));
        }
        let kind = header[156];
        let header_path = tar_header_path(&header)?;
        match kind {
            b'g' => {
                if size > MAX_PAX_BYTES || pending.path.is_some() || pending.link_path.is_some() {
                    return Err("unexpected or oversized global PAX metadata".to_owned());
                }
                validate_pax_payload(&read_tar_payload(&mut reader, size)?)?;
            }
            b'x' => {
                if size > MAX_PAX_BYTES || pending.path.is_some() || pending.link_path.is_some() {
                    return Err("nested or oversized PAX metadata".to_owned());
                }
                pending = parse_pax_metadata(&read_tar_payload(&mut reader, size)?)?;
            }
            b'L' => {
                if size > MAX_PAX_BYTES || pending.path.is_some() {
                    return Err("nested or oversized GNU long-name metadata".to_owned());
                }
                pending.path = Some(parse_gnu_long_value(&read_tar_payload(&mut reader, size)?)?);
            }
            b'K' => {
                if size > MAX_PAX_BYTES || pending.link_path.is_some() {
                    return Err("nested or oversized GNU long-link metadata".to_owned());
                }
                pending.link_path =
                    Some(parse_gnu_long_value(&read_tar_payload(&mut reader, size)?)?);
            }
            b'0' | 0 | b'5' | b'2' => {
                let selected_path = pending.path.take().unwrap_or(header_path);
                let relative = validate_archive_path(&selected_path, expected_root)?;
                let header_link = tar_text_field(&header[157..257], "link target")?;
                let link_path = pending.link_path.take().unwrap_or(header_link);
                extract_tar_member(
                    &mut reader,
                    destination,
                    relative.as_deref(),
                    kind,
                    size,
                    &header,
                    &link_path,
                    &mut paths,
                    &mut portable_paths,
                    &mut omitted_absolute_link,
                )?;
            }
            b'1' => return Err("tar hard-link members are forbidden".to_owned()),
            b'3' | b'4' | b'6' => {
                return Err("tar device and FIFO members are forbidden".to_owned());
            }
            b'S' => return Err("GNU sparse tar members are forbidden".to_owned()),
            _ => return Err(format!("unsupported tar member type 0x{kind:02x}")),
        }
    }
    if pending.path.is_some() || pending.link_path.is_some() {
        return Err("tar archive ended with unapplied path metadata".to_owned());
    }
    if !omitted_absolute_link {
        return Err(
            "authenticated QEMU archive omitted its reviewed absolute-link record".to_owned(),
        );
    }
    let mut trailer = [0u8; 64 * 1024];
    let mut trailer_bytes = 0u64;
    loop {
        let read = reader
            .read(&mut trailer)
            .map_err(|error| format!("cannot read tar trailer: {error}"))?;
        if read == 0 {
            break;
        }
        trailer_bytes = trailer_bytes
            .checked_add(u64::try_from(read).map_err(|_| "tar trailer overflow".to_owned())?)
            .ok_or_else(|| "tar trailer overflow".to_owned())?;
        if trailer_bytes > MAX_TAR_TRAILER_BYTES || trailer[..read].iter().any(|byte| *byte != 0) {
            return Err("tar archive has an oversized or nonzero trailer".to_owned());
        }
    }
    if members == 0 || paths.is_empty() {
        return Err("tar archive is empty".to_owned());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn extract_tar_member(
    reader: &mut impl Read,
    destination: &Path,
    relative: Option<&str>,
    kind: u8,
    size: u64,
    header: &[u8; 512],
    link_path: &str,
    paths: &mut BTreeSet<String>,
    portable_paths: &mut BTreeSet<String>,
    omitted_absolute_link: &mut bool,
) -> Result<(), String> {
    let directory = kind == b'5';
    if (directory || kind == b'2') && size != 0 {
        return Err("tar directory or symbolic link has a nonzero payload".to_owned());
    }
    let Some(relative) = relative else {
        if !directory {
            return Err("tar archive root must be a directory".to_owned());
        }
        return skip_tar_padding(reader, size);
    };
    if !paths.insert(relative.to_owned()) || !portable_paths.insert(relative.to_ascii_lowercase()) {
        return Err(format!(
            "duplicate or portable-colliding tar path {relative:?}"
        ));
    }
    let output = destination.join(relative);
    if !output.starts_with(destination) {
        return Err("tar member escaped extraction root".to_owned());
    }
    if directory {
        fs::create_dir_all(&output)
            .map_err(|error| format!("cannot create extracted directory {relative:?}: {error}"))?;
        set_mode(&output, 0o755)?;
        return skip_tar_padding(reader, size);
    }
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create parent for {relative:?}: {error}"))?;
    }
    if kind == b'2' {
        if relative == OMITTED_ABSOLUTE_SYMLINK.0 && link_path == OMITTED_ABSOLUTE_SYMLINK.1 {
            if *omitted_absolute_link {
                return Err("duplicate reviewed absolute symbolic link".to_owned());
            }
            *omitted_absolute_link = true;
            return skip_tar_padding(reader, size);
        }
        validate_relative_link(relative, link_path)?;
        create_symbolic_link(link_path, &output).map_err(|error| {
            format!("cannot create safe symbolic link {relative:?} -> {link_path:?}: {error}")
        })?;
        return skip_tar_padding(reader, size);
    }
    let mode = parse_tar_octal(&header[100..108], "member mode")?;
    let normalized_mode = if mode & 0o111 != 0 { 0o755 } else { 0o644 };
    let mut file = new_file(&output, normalized_mode)?;
    copy_exact(reader, &mut file, size)?;
    file.sync_all()
        .map_err(|error| format!("cannot sync extracted file {relative:?}: {error}"))?;
    skip_tar_padding(reader, size)
}

fn validate_relative_link(relative: &str, target: &str) -> Result<(), String> {
    if target.is_empty()
        || target.starts_with('/')
        || target.contains('\\')
        || target.len() > MAX_ARCHIVE_PATH_BYTES
    {
        return Err(format!("unsafe tar symbolic-link target {target:?}"));
    }
    let mut depth = relative.split('/').count().saturating_sub(1);
    for component in target.split('/') {
        match component {
            "" | "." => {}
            ".." => {
                if depth == 0 {
                    return Err(format!(
                        "tar symbolic link {relative:?} escapes extraction root"
                    ));
                }
                depth -= 1;
            }
            value if portable_component(value) => depth = depth.saturating_add(1),
            _ => {
                return Err(format!(
                    "tar symbolic link has unsafe component {component:?}"
                ));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn create_symbolic_link(target: &str, output: &Path) -> io::Result<()> {
    std::os::unix::fs::symlink(target, output)
}

#[cfg(not(unix))]
fn create_symbolic_link(_target: &str, _output: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "safe QEMU source symlink extraction requires Unix",
    ))
}

fn read_tar_block(reader: &mut impl Read) -> Result<Option<[u8; 512]>, String> {
    let mut block = [0u8; 512];
    let mut filled = 0usize;
    while filled < block.len() {
        let read = reader
            .read(&mut block[filled..])
            .map_err(|error| format!("cannot read tar header: {error}"))?;
        if read == 0 {
            if filled == 0 {
                return Ok(None);
            }
            return Err("truncated tar header".to_owned());
        }
        filled += read;
    }
    Ok(Some(block))
}

fn validate_tar_checksum(header: &[u8; 512]) -> Result<(), String> {
    let expected = parse_tar_octal(&header[148..156], "header checksum")?;
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
    if actual != expected {
        return Err(format!(
            "tar checksum mismatch: expected {expected}, observed {actual}"
        ));
    }
    Ok(())
}

fn parse_tar_octal(field: &[u8], label: &str) -> Result<u64, String> {
    if field.first().is_some_and(|byte| byte & 0x80 != 0) {
        return Err(format!("base-256 tar {label} is forbidden"));
    }
    let source = field
        .iter()
        .copied()
        .skip_while(|byte| matches!(byte, 0 | b' '))
        .take_while(|byte| *byte != 0 && *byte != b' ')
        .collect::<Vec<_>>();
    if source.is_empty() {
        return Ok(0);
    }
    if !source.iter().all(|byte| matches!(byte, b'0'..=b'7')) {
        return Err(format!("tar {label} is not canonical octal"));
    }
    source.iter().try_fold(0u64, |value, byte| {
        value
            .checked_mul(8)
            .and_then(|value| value.checked_add(u64::from(byte - b'0')))
            .ok_or_else(|| format!("tar {label} overflow"))
    })
}

fn tar_header_path(header: &[u8; 512]) -> Result<String, String> {
    let name = tar_text_field(&header[0..100], "member name")?;
    let prefix = tar_text_field(&header[345..500], "member prefix")?;
    if prefix.is_empty() {
        Ok(name)
    } else if name.is_empty() {
        Err("tar member has prefix without name".to_owned())
    } else {
        Ok(format!("{prefix}/{name}"))
    }
}

fn tar_text_field(field: &[u8], label: &str) -> Result<String, String> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    if field[end..].iter().any(|byte| *byte != 0) {
        return Err(format!("tar {label} has bytes after NUL"));
    }
    let value =
        std::str::from_utf8(&field[..end]).map_err(|_| format!("tar {label} is not UTF-8"))?;
    if value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(format!("tar {label} contains control bytes"));
    }
    Ok(value.to_owned())
}

fn validate_archive_path(path: &str, expected_root: &str) -> Result<Option<String>, String> {
    if path.is_empty()
        || path.len() > MAX_ARCHIVE_PATH_BYTES
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains("//")
    {
        return Err(format!("unsafe tar member path {path:?}"));
    }
    let root_without_slash = &expected_root[..expected_root.len() - 1];
    if path == root_without_slash || path == expected_root {
        return Ok(None);
    }
    let relative = path
        .strip_prefix(expected_root)
        .ok_or_else(|| format!("tar member is outside exact root {expected_root:?}: {path:?}"))?
        .trim_end_matches('/');
    if relative.is_empty()
        || relative
            .split('/')
            .any(|component| !portable_component(component))
    {
        return Err(format!("tar member path is not portable: {path:?}"));
    }
    Ok(Some(relative.to_owned()))
}

fn read_tar_payload(reader: &mut impl Read, size: u64) -> Result<Vec<u8>, String> {
    let capacity = usize::try_from(size).map_err(|_| "tar metadata size overflow".to_owned())?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| "cannot reserve tar metadata".to_owned())?;
    reader
        .take(size)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read tar metadata: {error}"))?;
    if bytes.len() != capacity {
        return Err("truncated tar metadata".to_owned());
    }
    skip_tar_padding(reader, size)?;
    Ok(bytes)
}

fn validate_pax_payload(bytes: &[u8]) -> Result<(), String> {
    let _ = parse_pax_metadata(bytes)?;
    Ok(())
}

fn parse_pax_metadata(bytes: &[u8]) -> Result<PendingTarMetadata, String> {
    let source = std::str::from_utf8(bytes).map_err(|_| "PAX metadata is not UTF-8".to_owned())?;
    let mut offset = 0usize;
    let mut output = PendingTarMetadata::default();
    while offset < source.len() {
        let remaining = &source[offset..];
        let space = remaining
            .find(' ')
            .ok_or_else(|| "PAX record lacks length separator".to_owned())?;
        let length_source = &remaining[..space];
        let length = length_source
            .parse::<usize>()
            .map_err(|_| "PAX record length is malformed".to_owned())?;
        if length.to_string() != length_source || length <= space + 2 || length > remaining.len() {
            return Err("PAX record has noncanonical length".to_owned());
        }
        let record = &remaining[space + 1..length];
        let record = record
            .strip_suffix('\n')
            .ok_or_else(|| "PAX record lacks newline".to_owned())?;
        let (key, value) = record
            .split_once('=')
            .ok_or_else(|| "PAX record lacks assignment".to_owned())?;
        if value.is_empty() || value.contains('\0') {
            return Err("PAX record contains an invalid value".to_owned());
        }
        match key {
            "path" if output.path.is_none() => output.path = Some(value.to_owned()),
            "linkpath" if output.link_path.is_none() => output.link_path = Some(value.to_owned()),
            "mtime" | "atime" | "ctime" | "comment" => {}
            _ if key.starts_with("SCHILY.") => {}
            _ => return Err(format!("unsupported or duplicate PAX key {key:?}")),
        }
        offset = offset
            .checked_add(length)
            .ok_or_else(|| "PAX offset overflow".to_owned())?;
    }
    Ok(output)
}

fn parse_gnu_long_value(bytes: &[u8]) -> Result<String, String> {
    let bytes = bytes
        .strip_suffix(&[0])
        .ok_or_else(|| "GNU long-name metadata lacks NUL terminator".to_owned())?;
    let value =
        std::str::from_utf8(bytes).map_err(|_| "GNU long-name metadata is not UTF-8".to_owned())?;
    if value.is_empty() || value.contains('\0') || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err("GNU long-name metadata is malformed".to_owned());
    }
    Ok(value.to_owned())
}

fn copy_exact(reader: &mut impl Read, writer: &mut impl Write, size: u64) -> Result<(), String> {
    let copied = io::copy(&mut reader.take(size), writer)
        .map_err(|error| format!("cannot extract tar payload: {error}"))?;
    if copied != size {
        return Err("truncated tar payload".to_owned());
    }
    Ok(())
}

fn skip_tar_padding(reader: &mut impl Read, size: u64) -> Result<(), String> {
    let padding = (512 - (size % 512)) % 512;
    let mut remaining = padding;
    let mut buffer = [0u8; 512];
    while remaining != 0 {
        let requested = usize::try_from(remaining.min(512))
            .map_err(|_| "tar padding size overflow".to_owned())?;
        let read = reader
            .read(&mut buffer[..requested])
            .map_err(|error| format!("cannot read tar padding: {error}"))?;
        if read == 0 {
            return Err("truncated tar padding".to_owned());
        }
        if buffer[..read].iter().any(|byte| *byte != 0) {
            return Err("tar padding contains nonzero data".to_owned());
        }
        remaining -= u64::try_from(read).map_err(|_| "tar padding overflow".to_owned())?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| format!("cannot set mode on {}: {error}", path.display()))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[cfg(unix)]
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::{
        ALLOWED_PKG_CONFIG_FRAMEWORKS, ALLOWED_PKG_CONFIG_LIBRARIES, BUILD_CONTRACT_VERSION,
        BZIP2_HELP_PREFIX, BootstrapSources, CONTENT_ONLY_TOOL_IDENTITIES, DETERMINISTIC_DATE_SHIM,
        EmulationOutput, FileMeasurement, HOST_UTILITY_CANDIDATES, MAX_BZIP2_HELP_BYTES,
        MAX_DISPLAYED_PROCESS_OUTPUT, MAX_GPG_FIELDS, MAX_GPG_RECORD_BYTES, MAX_GPG_RECORDS,
        OMITTED_ABSOLUTE_SYMLINK, PkgConfigModule, QEMU_DARWIN_STATIC_MESON_ORIGINAL_BLOCK,
        QEMU_DARWIN_STATIC_MESON_ORIGINAL_BYTES, QEMU_DARWIN_STATIC_MESON_PATCHED_BLOCK,
        QEMU_DARWIN_STATIC_MESON_PATCHED_BYTES, REQUIRED_MACHO_DEPENDENCIES,
        REQUIRED_PKG_CONFIG_MODULES, REQUIRED_SDK_ALIAS_INPUTS, REQUIRED_SDK_FRAMEWORK_INPUTS,
        REQUIRED_SDK_INPUTS, REQUIRED_STATIC_LIBRARIES, SDK_PROVIDED_LIBRARIES,
        StaticDependencyContract, ToolIdentity, ZLIB_PKG_CONFIG,
        append_dependency_search_directories, bounded_text, configure_contract,
        cxx_configure_argument, decode_expected_output, decode_lock, encode_expected_output,
        exact_directory, extract_tar_stream, gpg_status_lines, identify_tool,
        implementation_digest_from_sources, measure_sdk_alias_chain, measure_sdk_framework,
        measure_sdk_input, measure_sdk_tree, parse_pax_metadata, patch_reviewed_text,
        prepare_controlled_pkg_config, required_static_library, resolve_apple_sysroot,
        resolve_host_utilities, sha256_bytes, tool_version, validate_archive_path,
        validate_bzip2_help, validate_key_inventory, validate_signature_status,
        validate_static_dependency_arguments, write_deterministic_date_shim,
    };

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);
    const FINGERPRINT: &str = "CEACC9E15534EBABB82D3FA03353C9CEF108B584";
    const PRIMARY_KEY_ID: &str = "3353C9CEF108B584";
    const KEY_CREATED: u64 = 1_382_105_359;
    const KEY_EXPIRES: u64 = 1_778_512_387;
    const QEMU_SOURCE: &[u8] = include_bytes!("qemu.rs");
    const XTASK_MAIN: &[u8] = include_bytes!("main.rs");
    const XTASK_MANIFEST: &[u8] = include_bytes!("../Cargo.toml");
    const CARGO_LOCK: &[u8] = include_bytes!("../../Cargo.lock");

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn create(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "wrela-qemu-{label}-{}-{}",
                std::process::id(),
                NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("create test directory");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn host_utility_candidates_are_reviewed_absolute_and_deterministic() {
        assert!(!HOST_UTILITY_CANDIDATES.is_empty());
        for pair in HOST_UTILITY_CANDIDATES.windows(2) {
            assert!(
                pair[0].0 < pair[1].0,
                "utility names must be unique and sorted"
            );
        }
        for (name, candidates) in HOST_UTILITY_CANDIDATES {
            assert!(!name.is_empty());
            assert!(
                !candidates.is_empty(),
                "{name} must have a reviewed candidate"
            );
            for (index, candidate) in candidates.iter().enumerate() {
                assert!(
                    Path::new(candidate).is_absolute(),
                    "{name} candidate must be absolute: {candidate}"
                );
                assert!(
                    !candidates[..index].contains(candidate),
                    "duplicate {name} candidate: {candidate}"
                );
            }
        }
        assert_eq!(
            HOST_UTILITY_CANDIDATES
                .iter()
                .find(|(name, _)| *name == "expr")
                .map(|(_, candidates)| *candidates),
            Some(&["/bin/expr", "/usr/bin/expr"][..])
        );
    }

    #[test]
    fn reviewed_text_patch_is_exact_and_fail_closed() {
        assert_eq!(
            QEMU_DARWIN_STATIC_MESON_ORIGINAL_BLOCK,
            b"if get_option('prefer_static')\n  qemu_ldflags += get_option('b_pie') ? '-static-pie' : '-static'\nendif\n"
        );
        assert_eq!(
            QEMU_DARWIN_STATIC_MESON_PATCHED_BLOCK,
            b"if get_option('prefer_static') and host_os != 'darwin'\n  qemu_ldflags += get_option('b_pie') ? '-static-pie' : '-static'\nendif\n"
        );
        assert_eq!(
            QEMU_DARWIN_STATIC_MESON_PATCHED_BYTES - QEMU_DARWIN_STATIC_MESON_ORIGINAL_BYTES,
            u64::try_from(
                QEMU_DARWIN_STATIC_MESON_PATCHED_BLOCK.len()
                    - QEMU_DARWIN_STATIC_MESON_ORIGINAL_BLOCK.len()
            )
            .expect("reviewed patch byte growth")
        );
        const ORIGINAL: &[u8] = b"old\n";
        const PATCHED: &[u8] = b"new content\n";
        fn apply(
            input: &[u8],
            original: &[u8],
            patched: &[u8],
            expected: &[u8],
        ) -> Result<Vec<u8>, String> {
            patch_reviewed_text(
                input,
                &sha256_bytes(input),
                u64::try_from(input.len()).expect("input length"),
                original,
                patched,
                &sha256_bytes(expected),
                u64::try_from(expected.len()).expect("output length"),
            )
        }

        let input = b"prefix\nold\nsuffix\n";
        let expected = b"prefix\nnew content\nsuffix\n";
        assert_eq!(
            apply(input, ORIGINAL, PATCHED, expected).expect("exact reviewed patch"),
            expected
        );
        assert!(apply(b"prefix\nsuffix\n", ORIGINAL, PATCHED, b"unused").is_err());
        assert!(apply(b"old\nold\n", ORIGINAL, PATCHED, b"unused").is_err());
        assert!(
            apply(
                b"prefix\nnew content\nsuffix\n",
                ORIGINAL,
                PATCHED,
                b"unused"
            )
            .is_err()
        );
        assert!(
            patch_reviewed_text(
                input,
                "0000000000000000000000000000000000000000000000000000000000000000",
                u64::try_from(input.len()).expect("input length"),
                ORIGINAL,
                PATCHED,
                &sha256_bytes(expected),
                u64::try_from(expected.len()).expect("output length"),
            )
            .is_err()
        );
    }

    #[test]
    fn generated_date_capability_is_constant_and_native_errors_retain_the_tail() {
        let temporary = TestDirectory::create("date-shim");
        write_deterministic_date_shim(&temporary.0).expect("write date shim");
        assert_eq!(
            fs::read(temporary.0.join("date")).expect("read date shim"),
            DETERMINISTIC_DATE_SHIM
        );
        assert_eq!(
            fs::metadata(temporary.0.join("date"))
                .expect("date shim metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );

        let mut native_output = vec![b'x'; MAX_DISPLAYED_PROCESS_OUTPUT * 2];
        native_output.extend_from_slice(b"fatal-tail-marker\n");
        let displayed = bounded_text(&native_output);
        assert!(displayed.starts_with("xxxx"));
        assert!(displayed.contains("omitted"));
        assert!(displayed.ends_with("fatal-tail-marker\n"));
    }

    #[test]
    fn pkg_config_argument_contract_accepts_only_the_reviewed_static_closure() {
        assert!(configure_contract().contains(&"--enable-fdt=system"));
        assert!(configure_contract().contains(&"--enable-qcow1"));
        assert!(configure_contract().contains(&"--enable-vvfat"));
        assert!(!configure_contract().contains(&"--enable-fdt=internal"));
        assert!(configure_contract().contains(&"--without-default-features"));
        for values in [
            ALLOWED_PKG_CONFIG_LIBRARIES,
            ALLOWED_PKG_CONFIG_FRAMEWORKS,
            SDK_PROVIDED_LIBRARIES,
            REQUIRED_STATIC_LIBRARIES,
            REQUIRED_PKG_CONFIG_MODULES,
            REQUIRED_MACHO_DEPENDENCIES,
        ] {
            for pair in values.windows(2) {
                assert!(
                    pair[0] < pair[1],
                    "reviewed allowlist must be sorted and unique"
                );
            }
        }
        assert_eq!(
            REQUIRED_MACHO_DEPENDENCIES,
            [
                "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
                "/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation",
                "/System/Library/Frameworks/IOKit.framework/Versions/A/IOKit",
                "/usr/lib/libSystem.B.dylib",
                "/usr/lib/libiconv.2.dylib",
                "/usr/lib/libobjc.A.dylib",
                "/usr/lib/libz.1.dylib",
            ]
        );
        validate_static_dependency_arguments(&[
            "-I/opt/homebrew/Cellar/glib/2.88.2/include/glib-2.0",
            "-L/opt/homebrew/Cellar/glib/2.88.2/lib",
            "-lglib-2.0",
            "-lintl",
            "-liconv",
            "-lm",
            "-framework",
            "Foundation",
            "-framework",
            "CoreFoundation",
            "-framework",
            "AppKit",
            "-framework",
            "Carbon",
            "-L/opt/homebrew/Cellar/pcre2/10.47_1/lib",
            "-lpcre2-8",
            "-pthread",
            "-lpthread",
            "-L/opt/homebrew/Cellar/dtc/1.8.1/lib",
            "-lfdt",
        ])
        .expect("reviewed static dependency arguments");

        let contract = StaticDependencyContract {
            sha256: "00".repeat(32),
            include_directories: vec![PathBuf::from("/opt/homebrew/Cellar/dtc/1.8.1/include")],
            library_directories: vec![PathBuf::from("/opt/homebrew/Cellar/dtc/1.8.1/lib")],
            pkg_config_modules: Vec::new(),
        };
        let mut cflags = "-isysroot /reviewed/sdk".to_owned();
        append_dependency_search_directories(&mut cflags, "-I", &contract.include_directories)
            .expect("render measured include directory");
        let mut ldflags = "-isysroot /reviewed/sdk".to_owned();
        append_dependency_search_directories(&mut ldflags, "-L", &contract.library_directories)
            .expect("render measured library directory");
        assert_eq!(
            cflags,
            "-isysroot /reviewed/sdk -I/opt/homebrew/Cellar/dtc/1.8.1/include"
        );
        assert_eq!(
            ldflags,
            "-isysroot /reviewed/sdk -L/opt/homebrew/Cellar/dtc/1.8.1/lib"
        );
    }

    #[test]
    fn controlled_pkg_config_catalog_exposes_only_measured_modules() {
        let temporary = TestDirectory::create("pkg-config-catalog");
        let source = temporary.0.join("source");
        fs::create_dir(&source).expect("create module source directory");
        let mut modules = Vec::new();
        for name in REQUIRED_PKG_CONFIG_MODULES {
            let bytes = format!("Name: {name}\nVersion: 1\n").into_bytes();
            let path = source.join(format!("{name}.pc"));
            fs::write(&path, &bytes).expect("write test pkg-config module");
            let path = fs::canonicalize(path).expect("canonical test pkg-config module");
            modules.push(PkgConfigModule {
                name: (*name).to_owned(),
                path,
                measurement: FileMeasurement {
                    sha256: sha256_bytes(&bytes),
                    bytes: u64::try_from(bytes.len()).expect("test module size"),
                },
            });
        }
        let contract = StaticDependencyContract {
            sha256: "00".repeat(32),
            include_directories: Vec::new(),
            library_directories: Vec::new(),
            pkg_config_modules: modules,
        };
        let catalog = prepare_controlled_pkg_config(&temporary.0, &contract)
            .expect("create controlled pkg-config catalog");
        let mut filenames = fs::read_dir(catalog)
            .expect("read controlled pkg-config catalog")
            .map(|entry| {
                entry
                    .expect("read catalog entry")
                    .file_name()
                    .into_string()
                    .expect("UTF-8 catalog filename")
            })
            .collect::<Vec<_>>();
        filenames.sort();
        let mut expected = REQUIRED_PKG_CONFIG_MODULES
            .iter()
            .map(|name| format!("{name}.pc"))
            .collect::<Vec<_>>();
        expected.push("zlib.pc".to_owned());
        expected.sort();
        assert_eq!(filenames, expected);
        assert!(!filenames.iter().any(|name| name == "gmp.pc"));
        assert_eq!(
            fs::read(temporary.0.join("wrela-pkg-config/zlib.pc"))
                .expect("read generated zlib module"),
            ZLIB_PKG_CONFIG
        );
        let pkg_config = super::resolve_tool(
            "WRELA_QEMU_PKG_CONFIG",
            &[
                "/opt/homebrew/bin/pkg-config",
                "/usr/local/bin/pkg-config",
                "/usr/bin/pkg-config",
            ],
        )
        .expect("resolve pkg-config for generated-module test");
        for (arguments, expected) in [
            (&["--modversion", "zlib"][..], &["1.2.12"][..]),
            (&["--libs", "zlib"][..], &["-lz"][..]),
        ] {
            let output = Command::new(&pkg_config.path)
                .env_clear()
                .env("LC_ALL", "C")
                .env("PATH", "/wrela/no-ambient-path")
                .env("PKG_CONFIG_LIBDIR", temporary.0.join("wrela-pkg-config"))
                .args(arguments)
                .output()
                .expect("query generated zlib module");
            assert!(output.status.success());
            assert!(output.stderr.is_empty());
            assert_eq!(
                std::str::from_utf8(&output.stdout)
                    .expect("UTF-8 pkg-config response")
                    .split_ascii_whitespace()
                    .collect::<Vec<_>>(),
                expected
            );
        }
    }

    #[test]
    fn pkg_config_argument_contract_rejects_options_response_files_and_unsafe_tokens() {
        let malicious: &[&[&str]] = &[
            &["-lgio-2.0;touch"],
            &["-l../../evil"],
            &["-lcrypto"],
            &["@response"],
            &["-Wl,-rpath,/tmp"],
            &["-DATTACK=1"],
            &["-I/opt/homebrew/../tmp"],
            &["-I//tmp"],
            &["-I/tmp/$HOME"],
            &["-Lrelative"],
            &["-framework"],
            &["-framework", "Metal"],
            &["-framework", "Foundation", "|"],
        ];
        for arguments in malicious {
            assert!(
                validate_static_dependency_arguments(arguments).is_err(),
                "accepted malicious pkg-config arguments {arguments:?}"
            );
        }
    }

    #[test]
    fn required_static_library_selection_is_exact_and_unambiguous() {
        let temporary = TestDirectory::create("required-static-library");
        let first = temporary.0.join("first");
        let second = temporary.0.join("second");
        fs::create_dir(&first).expect("create first static library directory");
        fs::create_dir(&second).expect("create second static library directory");
        let archive = first.join("libfdt.a");
        fs::write(&archive, b"measured static archive").expect("write static library fixture");
        let mut contract = StaticDependencyContract {
            sha256: "00".repeat(32),
            include_directories: Vec::new(),
            library_directories: vec![first.clone()],
            pkg_config_modules: Vec::new(),
        };
        assert_eq!(
            required_static_library(&contract, "fdt").expect("select exact static archive"),
            fs::canonicalize(&archive).expect("canonical archive fixture")
        );
        assert!(required_static_library(&contract, "not-reviewed").is_err());
        fs::write(second.join("libfdt.a"), b"ambiguous static archive")
            .expect("write ambiguous static library fixture");
        contract.library_directories.push(second);
        assert!(required_static_library(&contract, "fdt").is_err());
        fs::remove_file(&archive).expect("remove first static library fixture");
        contract.library_directories.pop();
        assert!(required_static_library(&contract, "fdt").is_err());
    }

    #[test]
    fn bzip2_identity_parser_rejects_transforming_spoofed_and_oversized_output() {
        let mut help = BZIP2_HELP_PREFIX.to_vec();
        help.extend_from_slice(b"   -h --help           print this message\n");
        assert_eq!(
            validate_bzip2_help(true, b"", &help).expect("exact bounded bzip2 help"),
            help
        );
        assert!(
            validate_bzip2_help(true, b"BZh9\x17rE8P\x90", BZIP2_HELP_PREFIX).is_err(),
            "a --version probe's transforming stdout must be rejected"
        );
        assert!(
            validate_bzip2_help(
                true,
                b"",
                b"bzip2, a block-sorting file compressor.  Version 9.9.9, 13-Jul-2019.\n\n   usage: bzip2 [flags and input files in any order]\n",
            )
            .is_err(),
            "a spoofed version must be rejected"
        );
        assert!(validate_bzip2_help(true, &help, b"").is_err());
        assert!(validate_bzip2_help(false, b"", &help).is_err());

        let mut oversized = BZIP2_HELP_PREFIX.to_vec();
        oversized.resize(MAX_BZIP2_HELP_BYTES + 1, b'x');
        let last = oversized.last_mut().expect("oversized fixture is nonempty");
        *last = b'\n';
        assert!(validate_bzip2_help(true, b"", &oversized).is_err());
        let mut binary_trailer = help;
        binary_trailer.push(0);
        assert!(validate_bzip2_help(true, b"", &binary_trailer).is_err());
    }

    #[test]
    fn bsd_archive_tools_use_exact_content_identity_without_process_probes() {
        for pair in CONTENT_ONLY_TOOL_IDENTITIES.windows(2) {
            assert!(
                pair[0] < pair[1],
                "content-only tool labels must be sorted and unique"
            );
        }
        let identity = ToolIdentity {
            path: PathBuf::from("/path/that/must/not/be/executed"),
            sha256: "a".repeat(64),
            bytes: 123,
        };
        for label in ["ar", "linker", "ranlib"] {
            assert_eq!(
                tool_version(&identity, label).expect("content-only archive tool identity"),
                identity.sha256.as_bytes()
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_bzip2_identity_uses_nontransforming_help_channel() {
        let bzip2 = identify_tool(Path::new("/usr/bin/bzip2")).expect("identify system bzip2");
        let identity = tool_version(&bzip2, "bzip2").expect("probe bzip2 help identity");
        assert!(identity.starts_with(BZIP2_HELP_PREFIX));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_host_utility_contract_resolves_required_platform_tools() {
        let utilities = resolve_host_utilities().expect("resolve controlled host utilities");
        let expr = utilities
            .iter()
            .find(|(name, _)| name == "expr")
            .expect("expr identity");
        assert_eq!(expr.1.path, Path::new("/bin/expr"));
        let lipo = utilities
            .iter()
            .find(|(name, _)| name == "lipo")
            .expect("lipo identity");
        assert_eq!(lipo.1.path, Path::new("/usr/bin/lipo"));
        let nm = utilities
            .iter()
            .find(|(name, _)| name == "nm")
            .expect("nm identity");
        assert_eq!(nm.1.path, Path::new("/usr/bin/nm"));
        let diff = utilities
            .iter()
            .find(|(name, _)| name == "diff")
            .expect("diff identity");
        assert_eq!(diff.1.path, Path::new("/usr/bin/diff"));
        let rez = utilities
            .iter()
            .find(|(name, _)| name == "Rez")
            .expect("Rez identity");
        assert_eq!(
            rez.1.path,
            Path::new("/Applications/Xcode.app/Contents/Developer/usr/bin/Rez")
        );
        let set_file = utilities
            .iter()
            .find(|(name, _)| name == "SetFile")
            .expect("SetFile identity");
        assert_eq!(
            set_file.1.path,
            Path::new("/Applications/Xcode.app/Contents/Developer/usr/bin/SetFile")
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_sdk_contract_resolves_reviewed_internal_links() {
        assert_eq!(
            REQUIRED_SDK_FRAMEWORK_INPUTS,
            [
                ("AppKit", "C"),
                ("Carbon", "A"),
                ("CoreFoundation", "A"),
                ("Foundation", "C"),
                ("IOKit", "A"),
            ]
        );
        let sdk = resolve_apple_sysroot().expect("measure controlled macOS SDK inputs");
        assert!(REQUIRED_SDK_INPUTS.contains(&("usr/include/zlib.h", None)));
        assert!(REQUIRED_SDK_INPUTS.contains(&("usr/lib/libz.tbd", Some("libz.1.tbd"))));
        assert_eq!(REQUIRED_SDK_ALIAS_INPUTS.len(), 2);
        let zlib_header =
            fs::read(sdk.path.join("usr/include/zlib.h")).expect("read measured SDK zlib header");
        assert!(
            zlib_header
                .windows(b"#define ZLIB_VERSION \"1.2.12\"".len())
                .any(|window| window == b"#define ZLIB_VERSION \"1.2.12\"")
        );
        assert!(sdk.files > 30_000);
        assert!(sdk.bytes > 700_000_000);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_native_runtime_contract_covers_toolchain_python_and_libraries() {
        let cc =
            super::resolve_apple_tool("WRELA_QEMU_CC", "clang").expect("resolve Apple C compiler");
        let (cxx, cxx_driver) = super::resolve_apple_cxx().expect("resolve Apple C++ compiler");
        assert_eq!(
            cxx_driver.file_name(),
            Some(std::ffi::OsStr::new("clang++"))
        );
        assert_eq!(
            cxx_configure_argument(&cxx_driver).expect("render C++ configure argument"),
            std::ffi::OsString::from(format!("--cxx={}", cxx_driver.display()))
        );
        let linker =
            super::resolve_apple_tool("WRELA_QEMU_LINKER", "ld").expect("resolve Apple linker");
        let ar = super::resolve_apple_tool("WRELA_QEMU_AR", "ar").expect("resolve Apple archiver");
        let (ranlib, ranlib_driver) =
            super::resolve_apple_ranlib().expect("resolve Apple archive indexer");
        assert_eq!(
            ranlib_driver.file_name(),
            Some(std::ffi::OsStr::new("ranlib"))
        );
        assert_eq!(
            ranlib.path.file_name(),
            Some(std::ffi::OsStr::new("libtool")),
            "the measured binary may resolve through Apple's mode-selecting symlink"
        );
        assert_eq!(
            super::validate_apple_ranlib_driver(&ranlib_driver)
                .expect("preserve ranlib invocation mode"),
            ranlib
        );
        assert!(super::validate_apple_ranlib_driver(&ranlib.path).is_err());
        let toolchain = super::resolve_apple_toolchain(
            &cc,
            &cxx,
            &cxx_driver,
            &linker,
            &ar,
            &ranlib,
            &ranlib_driver,
        )
        .expect("measure complete Apple toolchain");
        assert!(toolchain.files > 4_000);
        assert!(toolchain.bytes > 1_000_000_000);
        assert!(
            toolchain
                .path
                .starts_with(super::apple_toolchain_root(&cc.path).expect("Apple toolchain root"))
        );
        let python = super::resolve_tool(
            "WRELA_QEMU_PYTHON",
            &["/opt/homebrew/bin/python3", "/usr/local/bin/python3"],
        )
        .expect("resolve Python");
        let runtime = super::resolve_python_runtime(&python).expect("measure Python runtime");
        assert!(runtime.files > 1_000);
        assert!(runtime.bytes > 50_000_000);
    }

    #[cfg(unix)]
    #[test]
    fn sdk_internal_link_identity_includes_exact_target_and_contents() {
        let directory = TestDirectory::create("sdk-internal-link");
        let library = directory.0.join("usr/lib");
        fs::create_dir_all(&library).expect("create SDK library directory");
        let target = library.join("libSystem.B.tbd");
        fs::write(&target, b"first target contents").expect("write SDK target");
        symlink("libSystem.B.tbd", library.join("libSystem.tbd")).expect("create SDK link");
        let root = exact_directory(&directory.0, "test SDK").expect("canonical test SDK");

        let first = measure_sdk_input(&root, "usr/lib/libSystem.tbd", Some("libSystem.B.tbd"))
            .expect("measure exact internal SDK link");
        fs::write(&target, b"changed target contents").expect("change SDK target");
        let changed = measure_sdk_input(&root, "usr/lib/libSystem.tbd", Some("libSystem.B.tbd"))
            .expect("remeasure changed SDK target");
        assert_ne!(first.sha256, changed.sha256);
    }

    #[cfg(unix)]
    #[test]
    fn sdk_alias_identity_pins_both_links_and_final_stub() {
        let directory = TestDirectory::create("sdk-alias-chain");
        let library = directory.0.join("usr/lib");
        fs::create_dir_all(&library).expect("create SDK alias directory");
        let target = library.join("libSystem.B.tbd");
        fs::write(&target, b"system stub").expect("write SDK alias target");
        symlink("libSystem.B.tbd", library.join("libSystem.tbd"))
            .expect("create intermediate SDK alias");
        symlink("libSystem.tbd", library.join("libpthread.tbd")).expect("create top SDK alias");
        let root = exact_directory(&directory.0, "test SDK").expect("canonical test SDK");

        let first = measure_sdk_alias_chain(
            &root,
            "usr/lib/libpthread.tbd",
            "libSystem.tbd",
            "libSystem.B.tbd",
        )
        .expect("measure exact SDK alias chain");
        fs::write(&target, b"changed system stub").expect("change SDK alias target");
        let changed = measure_sdk_alias_chain(
            &root,
            "usr/lib/libpthread.tbd",
            "libSystem.tbd",
            "libSystem.B.tbd",
        )
        .expect("remeasure changed SDK alias chain");
        assert_ne!(first.sha256, changed.sha256);
    }

    #[cfg(unix)]
    #[test]
    fn sdk_tree_identity_covers_files_links_and_escape_rejection() {
        let directory = TestDirectory::create("sdk-tree");
        let include = directory.0.join("usr/include");
        fs::create_dir_all(&include).expect("create SDK include directory");
        let header = include.join("wrela.h");
        fs::write(&header, b"first header").expect("write SDK header");
        symlink("wrela.h", include.join("alias.h")).expect("create SDK header alias");
        let root = exact_directory(&directory.0, "test SDK").expect("canonical test SDK");

        let first = measure_sdk_tree(&root).expect("measure SDK tree");
        assert_eq!(first.files, 2);
        fs::write(&header, b"changed header").expect("change SDK header");
        let changed = measure_sdk_tree(&root).expect("remeasure SDK tree");
        assert_ne!(first.sha256, changed.sha256);

        let escaping = TestDirectory::create("sdk-tree-escape");
        fs::write(escaping.0.join("outside"), b"outside").expect("write external SDK target");
        let unsafe_sdk = escaping.0.join("sdk");
        fs::create_dir(&unsafe_sdk).expect("create unsafe SDK root");
        symlink("../outside", unsafe_sdk.join("escape")).expect("create escaping SDK tree link");
        let unsafe_root =
            exact_directory(&unsafe_sdk, "unsafe test SDK").expect("canonical unsafe test SDK");
        assert!(measure_sdk_tree(&unsafe_root).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn sdk_framework_identity_pins_both_links_and_final_stub() {
        let directory = TestDirectory::create("sdk-framework");
        let framework = directory
            .0
            .join("System/Library/Frameworks/Foundation.framework");
        let versions = framework.join("Versions");
        let version = versions.join("C");
        fs::create_dir_all(&version).expect("create SDK framework version");
        let stub = version.join("Foundation.tbd");
        fs::write(&stub, b"first framework stub").expect("write SDK framework stub");
        symlink("C", versions.join("Current")).expect("create current framework link");
        symlink(
            "Versions/Current/Foundation.tbd",
            framework.join("Foundation.tbd"),
        )
        .expect("create top-level framework link");
        let root = exact_directory(&directory.0, "test SDK").expect("canonical test SDK");

        let first = measure_sdk_framework(&root, "Foundation", "C")
            .expect("measure exact SDK framework chain");
        fs::write(&stub, b"changed framework stub").expect("change SDK framework stub");
        let changed = measure_sdk_framework(&root, "Foundation", "C")
            .expect("remeasure changed SDK framework chain");
        assert_ne!(first.sha256, changed.sha256);
        fs::remove_file(versions.join("Current")).expect("remove current framework link");
        symlink("B", versions.join("Current")).expect("retarget current framework link");
        assert!(measure_sdk_framework(&root, "Foundation", "C").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn sdk_link_rejects_traversal_and_external_targets() {
        let traversal = TestDirectory::create("sdk-link-traversal");
        let traversal_library = traversal.0.join("usr/lib");
        fs::create_dir_all(&traversal_library).expect("create traversal SDK directory");
        symlink(
            "../../../outside.tbd",
            traversal_library.join("libSystem.tbd"),
        )
        .expect("create traversal SDK link");
        let traversal_root =
            exact_directory(&traversal.0, "test SDK").expect("canonical traversal SDK");
        assert!(
            measure_sdk_input(
                &traversal_root,
                "usr/lib/libSystem.tbd",
                Some("libSystem.B.tbd"),
            )
            .is_err()
        );

        let external = TestDirectory::create("sdk-link-external");
        let outside_directory = TestDirectory::create("sdk-link-outside");
        let external_library = external.0.join("usr/lib");
        fs::create_dir_all(&external_library).expect("create external SDK directory");
        let outside = outside_directory.0.join("outside.tbd");
        fs::write(&outside, b"outside").expect("write external SDK target");
        symlink(&outside, external_library.join("libSystem.tbd"))
            .expect("create external SDK link");
        let external_root =
            exact_directory(&external.0, "test SDK").expect("canonical external SDK");
        assert!(
            measure_sdk_input(
                &external_root,
                "usr/lib/libSystem.tbd",
                Some("libSystem.B.tbd"),
            )
            .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn sdk_link_rejects_chains_and_retargeting() {
        let chain = TestDirectory::create("sdk-link-chain");
        let chain_library = chain.0.join("usr/lib");
        fs::create_dir_all(&chain_library).expect("create chain SDK directory");
        fs::write(chain_library.join("libSystem.C.tbd"), b"target")
            .expect("write chained SDK target");
        symlink("libSystem.C.tbd", chain_library.join("libSystem.B.tbd"))
            .expect("create chained SDK target");
        symlink("libSystem.B.tbd", chain_library.join("libSystem.tbd"))
            .expect("create SDK link to chain");
        let chain_root = exact_directory(&chain.0, "test SDK").expect("canonical chain SDK");
        assert!(
            measure_sdk_input(
                &chain_root,
                "usr/lib/libSystem.tbd",
                Some("libSystem.B.tbd"),
            )
            .is_err()
        );

        let changed = TestDirectory::create("sdk-link-retargeted");
        let changed_library = changed.0.join("usr/lib");
        fs::create_dir_all(&changed_library).expect("create changed SDK directory");
        fs::write(changed_library.join("libSystem.C.tbd"), b"target")
            .expect("write retargeted SDK target");
        symlink("libSystem.C.tbd", changed_library.join("libSystem.tbd"))
            .expect("create retargeted SDK link");
        let changed_root = exact_directory(&changed.0, "test SDK").expect("canonical changed SDK");
        assert!(
            measure_sdk_input(
                &changed_root,
                "usr/lib/libSystem.tbd",
                Some("libSystem.B.tbd"),
            )
            .is_err()
        );
    }

    #[test]
    fn checked_in_lock_is_strict_and_complete() {
        assert_eq!(BUILD_CONTRACT_VERSION, 20);
        let lock = decode_lock(include_bytes!("../../toolchain/emulation.lock.toml"))
            .expect("checked-in emulation lock");
        assert_eq!(lock.version, "10.1.5");
        assert_eq!(
            lock.source_sha256,
            "1f1209b4db82e6c4417eaf6e7e0b073563572a042d9fb7492b084ba65a9c0693"
        );
        assert_eq!(lock.system_targets, ["aarch64-softmmu"]);
        assert_eq!(lock.machine_contract, "virt-10.0");
        assert_eq!(lock.cpu_contract, "cortex-a57");
        assert_eq!(lock.accelerator_contract, "tcg,thread=single");
        assert_eq!(lock.firmware.len(), 2);
        assert_eq!(
            lock.firmware[0].sha256,
            "47765fe344818cbc464b1c14ae658fb4b854f5c2ceffa982411731eb4865594d"
        );
        assert_eq!(
            lock.firmware[1].sha256,
            "b3b855c5a80310168051164986855692d1bdb06e67619856177965cd87c6774f"
        );
        assert_eq!(lock.signing_key_fingerprint, FINGERPRINT);

        let mut unknown = include_bytes!("../../toolchain/emulation.lock.toml").to_vec();
        unknown.extend_from_slice(b"unknown = \"field\"\n");
        assert!(decode_lock(&unknown).is_err());
        let noncanonical =
            String::from_utf8(include_bytes!("../../toolchain/emulation.lock.toml").to_vec())
                .expect("UTF-8")
                .replace("schema = 1", "schema=1");
        assert!(decode_lock(noncanonical.as_bytes()).is_err());
    }

    #[test]
    fn output_codec_exactly_matches_distribution_schema() {
        let output = EmulationOutput {
            emulation_lock_sha256: "11".repeat(32),
            native_input_sha256: "22".repeat(32),
            qemu_version: "10.1.5".to_owned(),
            host: "aarch64-apple-darwin".to_owned(),
            bundle_tree_sha256: "33".repeat(32),
            bundle_files: 6,
            bundle_bytes: 1234,
            qemu_sha256: "44".repeat(32),
            qemu_bytes: 1000,
            firmware_code_sha256: "55".repeat(32),
            firmware_code_bytes: 100,
            firmware_variables_sha256: "66".repeat(32),
            firmware_variables_bytes: 100,
        };
        let encoded = encode_expected_output(&output);
        assert_eq!(
            decode_expected_output(encoded.as_bytes()).expect("canonical output"),
            output
        );
        assert!(decode_expected_output(encoded.replace(" = ", "=").as_bytes()).is_err());
        assert!(decode_expected_output(format!("{encoded}qemu_bytes = 1\n").as_bytes()).is_err());
    }

    #[test]
    fn bootstrap_identity_ignores_unrelated_xtask_command_manifest_and_lock_drift() {
        let compiled = BootstrapSources {
            qemu: QEMU_SOURCE,
            main: XTASK_MAIN,
            manifest: XTASK_MANIFEST,
            cargo_lock: CARGO_LOCK,
        };
        let baseline = implementation_digest_from_sources(compiled, compiled)
            .expect("current QEMU bootstrap identity");

        let main = String::from_utf8(XTASK_MAIN.to_vec())
            .expect("UTF-8 xtask main")
            .replace("Some(\"llvm\")", "Some(\"llvm-renamed\")");
        assert_ne!(main.as_bytes(), XTASK_MAIN, "fixture must change main.rs");
        let manifest = String::from_utf8(XTASK_MANIFEST.to_vec())
            .expect("UTF-8 xtask manifest")
            .replace(
                "description = \"Maintainer tasks for building and packaging the wrela toolchain\"",
                "description = \"Unrelated command documentation changed\"",
            );
        assert_ne!(
            manifest.as_bytes(),
            XTASK_MANIFEST,
            "fixture must change xtask/Cargo.toml"
        );
        let cargo_lock = String::from_utf8(CARGO_LOCK.to_vec())
            .expect("UTF-8 Cargo.lock")
            .replace(
                "name = \"itoa\"\nversion = \"1.0.18\"",
                "name = \"itoa\"\nversion = \"1.0.19\"",
            );
        assert_ne!(
            cargo_lock.as_bytes(),
            CARGO_LOCK,
            "fixture must change an unrelated lock package"
        );

        let runtime = BootstrapSources {
            qemu: QEMU_SOURCE,
            main: main.as_bytes(),
            manifest: manifest.as_bytes(),
            cargo_lock: cargo_lock.as_bytes(),
        };
        assert_eq!(
            implementation_digest_from_sources(runtime, compiled)
                .expect("unrelated drift must remain current"),
            baseline
        );
    }

    #[test]
    fn bootstrap_identity_rejects_qemu_dispatch_manifest_and_dependency_drift() {
        let compiled = BootstrapSources {
            qemu: QEMU_SOURCE,
            main: XTASK_MAIN,
            manifest: XTASK_MANIFEST,
            cargo_lock: CARGO_LOCK,
        };

        let mut qemu = QEMU_SOURCE.to_vec();
        qemu.extend_from_slice(b"// relevant implementation drift\n");
        let error = implementation_digest_from_sources(
            BootstrapSources {
                qemu: &qemu,
                ..compiled
            },
            compiled,
        )
        .expect_err("QEMU implementation drift must be stale");
        assert!(error.contains("xtask/src/qemu.rs"));

        let main = String::from_utf8(XTASK_MAIN.to_vec())
            .expect("UTF-8 xtask main")
            .replace(
                "qemu::run(&root, &arguments)",
                "qemu::changed(&root, &arguments)",
            );
        assert_ne!(main.as_bytes(), XTASK_MAIN, "fixture must change dispatch");
        let error = implementation_digest_from_sources(
            BootstrapSources {
                main: main.as_bytes(),
                ..compiled
            },
            compiled,
        )
        .expect_err("QEMU dispatch drift must be stale");
        assert!(error.contains("QEMU dispatch contract"));

        let manifest = String::from_utf8(XTASK_MANIFEST.to_vec())
            .expect("UTF-8 xtask manifest")
            .replace("version = \"=0.10.9\"", "version = \"=0.10.8\"");
        let error = implementation_digest_from_sources(
            BootstrapSources {
                manifest: manifest.as_bytes(),
                ..compiled
            },
            compiled,
        )
        .expect_err("bootstrap manifest drift must fail");
        assert!(error.contains("reviewed dependency"));

        let cargo_lock = String::from_utf8(CARGO_LOCK.to_vec())
            .expect("UTF-8 Cargo.lock")
            .replace(
                "a7507d819769d01a365ab707794a4084392c824f54a7a6a7862f8c3d0892b283",
                "b7507d819769d01a365ab707794a4084392c824f54a7a6a7862f8c3d0892b283",
            );
        assert_ne!(
            cargo_lock.as_bytes(),
            CARGO_LOCK,
            "fixture must change sha2 checksum"
        );
        let error = implementation_digest_from_sources(
            BootstrapSources {
                cargo_lock: cargo_lock.as_bytes(),
                ..compiled
            },
            compiled,
        )
        .expect_err("bootstrap dependency drift must be stale");
        assert!(error.contains("bootstrap dependency closure"));

        let disconnected_lock = String::from_utf8(CARGO_LOCK.to_vec())
            .expect("UTF-8 Cargo.lock")
            .replace(
                "name = \"xtask\"\nversion = \"0.1.0\"\ndependencies = [\n \"serde_json\",\n \"sha2\",\n]",
                "name = \"xtask\"\nversion = \"0.1.0\"\ndependencies = [\n \"serde_json\",\n]",
            );
        assert_ne!(
            disconnected_lock.as_bytes(),
            CARGO_LOCK,
            "fixture must disconnect xtask from sha2"
        );
        let error = implementation_digest_from_sources(
            BootstrapSources {
                cargo_lock: disconnected_lock.as_bytes(),
                ..compiled
            },
            compiled,
        )
        .expect_err("disconnected bootstrap dependency must fail");
        assert!(error.contains("directly to pinned sha2"));
    }

    fn key_inventory() -> String {
        format!(
            "tru::1:1784073223:0:3:1:5\npub:e:2048:1:{PRIMARY_KEY_ID}:{KEY_CREATED}:{KEY_EXPIRES}::-:::sc::::::23::0:\nfpr:::::::::{FINGERPRINT}:\nuid:e::::1715440387::hash::Michael Roth <michael.roth@amd.com>::::::::::0:\nsub:e:2048:1:3B0B7D75D7AC684E:{KEY_CREATED}:{KEY_EXPIRES}:::::e::::::23:\nfpr:::::::::B771E2672C6A23D7CC3CD7643B0B7D75D7AC684E:\n"
        )
    }

    #[test]
    fn key_inventory_returns_one_exact_primary_lifetime() {
        let source = key_inventory();
        let inventory =
            validate_key_inventory(source.as_bytes(), FINGERPRINT).expect("exact key inventory");
        assert_eq!(inventory.primary_key_id, PRIMARY_KEY_ID);
        assert_eq!(inventory.created, KEY_CREATED);
        assert_eq!(inventory.expires, KEY_EXPIRES);

        let duplicate = format!(
            "{source}pub:e:2048:1:{PRIMARY_KEY_ID}:{KEY_CREATED}:{KEY_EXPIRES}::-:::sc::::::23::0:\nfpr:::::::::{FINGERPRINT}:\n"
        );
        assert!(validate_key_inventory(duplicate.as_bytes(), FINGERPRINT).is_err());
        let missing_fingerprint = source.replace(&format!("fpr:::::::::{FINGERPRINT}:\n"), "");
        assert!(validate_key_inventory(missing_fingerprint.as_bytes(), FINGERPRINT).is_err());
        let wrong_id = source.replacen(PRIMARY_KEY_ID, "AA53C9CEF108B584", 1);
        assert!(validate_key_inventory(wrong_id.as_bytes(), FINGERPRINT).is_err());
        let malformed_creation = source.replacen(&KEY_CREATED.to_string(), "01382105359", 1);
        assert!(validate_key_inventory(malformed_creation.as_bytes(), FINGERPRINT).is_err());
        let nonincreasing = source.replacen(&KEY_EXPIRES.to_string(), &KEY_CREATED.to_string(), 1);
        assert!(validate_key_inventory(nonincreasing.as_bytes(), FINGERPRINT).is_err());
        assert!(validate_key_inventory(source.as_bytes(), "AA").is_err());

        let too_many_fields = format!("pub{}\n", ":field".repeat(MAX_GPG_FIELDS));
        assert!(validate_key_inventory(too_many_fields.as_bytes(), FINGERPRINT).is_err());
    }

    #[test]
    fn signature_status_accepts_exact_current_and_historical_primary_key() {
        let inventory = validate_key_inventory(key_inventory().as_bytes(), FINGERPRINT)
            .expect("exact key inventory");
        let valid = format!(
            "[GNUPG:] NEWSIG\n[GNUPG:] GOODSIG {PRIMARY_KEY_ID} signer\n[GNUPG:] VALIDSIG {FINGERPRINT} 2026-04-01 1775000000 0 4 0 1 10 00 {FINGERPRINT}\n"
        );
        assert_eq!(
            validate_signature_status(valid.as_bytes(), true, FINGERPRINT, &inventory)
                .expect("valid signature status"),
            1_775_000_000
        );
        let historical = format!(
            "[GNUPG:] NEWSIG\n[GNUPG:] KEYEXPIRED {KEY_EXPIRES}\n[GNUPG:] KEY_CONSIDERED {FINGERPRINT} 0\n[GNUPG:] KEYEXPIRED {KEY_EXPIRES}\n[GNUPG:] SIG_ID exact 2026-03-18 1773797546\n[GNUPG:] EXPKEYSIG {PRIMARY_KEY_ID} signer\n[GNUPG:] VALIDSIG {FINGERPRINT} 2026-03-18 1773797546 0 4 0 1 10 00 {FINGERPRINT}\n"
        );
        assert_eq!(
            validate_signature_status(historical.as_bytes(), true, FINGERPRINT, &inventory)
                .expect("historically valid expired-key status"),
            1_773_797_546
        );

        let post_expiry = historical.replace("1773797546", "1782519196");
        assert!(
            validate_signature_status(post_expiry.as_bytes(), true, FINGERPRINT, &inventory)
                .expect_err("post-expiry signature must fail")
                .contains("outside pinned primary-key validity")
        );
        let before_creation = historical.replace(
            "1773797546",
            &KEY_CREATED
                .checked_sub(1)
                .expect("nonzero creation epoch")
                .to_string(),
        );
        assert!(
            validate_signature_status(before_creation.as_bytes(), true, FINGERPRINT, &inventory)
                .expect_err("pre-creation signature must fail")
                .contains("outside pinned primary-key validity")
        );
        let at_expiry = historical.replace("1773797546", &KEY_EXPIRES.to_string());
        assert!(
            validate_signature_status(at_expiry.as_bytes(), true, FINGERPRINT, &inventory)
                .expect_err("signature at the exclusive expiry boundary must fail")
                .contains("outside pinned primary-key validity")
        );
        let missing_expiry =
            historical.replace(&format!("[GNUPG:] KEYEXPIRED {KEY_EXPIRES}\n"), "");
        assert!(
            validate_signature_status(missing_expiry.as_bytes(), true, FINGERPRINT, &inventory)
                .is_err()
        );
        let duplicate_signature =
            format!("{historical}[GNUPG:] EXPKEYSIG {PRIMARY_KEY_ID} duplicate\n");
        assert!(
            validate_signature_status(
                duplicate_signature.as_bytes(),
                true,
                FINGERPRINT,
                &inventory,
            )
            .is_err()
        );
        let duplicate_valid = format!(
            "{historical}[GNUPG:] VALIDSIG {FINGERPRINT} 2026-03-18 1773797546 0 4 0 1 10 00 {FINGERPRINT}\n"
        );
        assert!(
            validate_signature_status(duplicate_valid.as_bytes(), true, FINGERPRINT, &inventory,)
                .is_err()
        );
        let conflicting_expiry = historical.replacen(
            &format!("KEYEXPIRED {KEY_EXPIRES}"),
            "KEYEXPIRED 1778512388",
            1,
        );
        assert!(
            validate_signature_status(
                conflicting_expiry.as_bytes(),
                true,
                FINGERPRINT,
                &inventory,
            )
            .is_err()
        );
        let malformed_expiry = historical.replacen(
            &format!("KEYEXPIRED {KEY_EXPIRES}"),
            "KEYEXPIRED invalid",
            1,
        );
        assert!(
            validate_signature_status(malformed_expiry.as_bytes(), true, FINGERPRINT, &inventory,)
                .is_err()
        );
        let overlong_expiry = historical.replacen(
            &format!("KEYEXPIRED {KEY_EXPIRES}"),
            &format!("KEYEXPIRED {KEY_EXPIRES} extra"),
            1,
        );
        assert!(
            validate_signature_status(overlong_expiry.as_bytes(), true, FINGERPRINT, &inventory)
                .is_err()
        );
        let wrong_key_id = historical.replacen(
            &format!("EXPKEYSIG {PRIMARY_KEY_ID}"),
            "EXPKEYSIG AA53C9CEF108B584",
            1,
        );
        assert!(
            validate_signature_status(wrong_key_id.as_bytes(), true, FINGERPRINT, &inventory)
                .is_err()
        );
        let mismatched_sig_id = historical.replacen(
            "SIG_ID exact 2026-03-18 1773797546",
            "SIG_ID exact 2026-03-18 1773797547",
            1,
        );
        assert!(
            validate_signature_status(mismatched_sig_id.as_bytes(), true, FINGERPRINT, &inventory,)
                .is_err()
        );
        let ambiguous = format!("{historical}[GNUPG:] GOODSIG {PRIMARY_KEY_ID} signer\n");
        assert!(
            validate_signature_status(ambiguous.as_bytes(), true, FINGERPRINT, &inventory).is_err()
        );
        assert!(
            validate_signature_status(historical.as_bytes(), false, FINGERPRINT, &inventory)
                .is_err()
        );
        for forbidden in [
            "BADSIG",
            "ERRSIG",
            "NO_PUBKEY",
            "EXPSIG",
            "REVKEYSIG",
            "SIGEXPIRED",
            "KEYREVOKED",
            "NODATA",
            "FAILURE",
            "ERROR",
        ] {
            let rejected = format!("{historical}[GNUPG:] {forbidden} detail\n");
            assert!(
                validate_signature_status(rejected.as_bytes(), true, FINGERPRINT, &inventory)
                    .is_err(),
                "status {forbidden} must fail closed"
            );
        }
        let wrong = valid.replace(FINGERPRINT, &"AA".repeat(20));
        assert!(
            validate_signature_status(wrong.as_bytes(), true, FINGERPRINT, &inventory).is_err()
        );
        let duplicate_good = format!("{valid}[GNUPG:] GOODSIG {PRIMARY_KEY_ID} duplicate\n");
        assert!(
            validate_signature_status(duplicate_good.as_bytes(), true, FINGERPRINT, &inventory)
                .is_err()
        );
        let unknown = format!("{historical}[GNUPG:] FUTURE_AMBIGUOUS_STATUS detail\n");
        assert!(
            validate_signature_status(unknown.as_bytes(), true, FINGERPRINT, &inventory).is_err()
        );
        let wrong_considered = historical.replace(
            &format!("KEY_CONSIDERED {FINGERPRINT}"),
            &format!("KEY_CONSIDERED {}", "AA".repeat(20)),
        );
        assert!(
            validate_signature_status(wrong_considered.as_bytes(), true, FINGERPRINT, &inventory,)
                .is_err()
        );

        let mut forged_inventory = inventory.clone();
        forged_inventory.primary_key_id = "AA53C9CEF108B584".to_owned();
        assert!(
            validate_signature_status(valid.as_bytes(), true, FINGERPRINT, &forged_inventory)
                .is_err()
        );
        assert!(validate_signature_status(valid.as_bytes(), true, "AA", &inventory).is_err());
    }

    #[test]
    fn gpg_status_parser_rejects_oversized_records_and_fields() {
        let too_many_records = "[GNUPG:] NEWSIG\n".repeat(MAX_GPG_RECORDS + 1);
        assert!(gpg_status_lines(too_many_records.as_bytes()).is_err());

        let too_many_fields = format!("[GNUPG:] {}\n", "field ".repeat(MAX_GPG_FIELDS + 1));
        assert!(gpg_status_lines(too_many_fields.as_bytes()).is_err());

        let oversized_record = format!("[GNUPG:] STATUS {}\n", "x".repeat(MAX_GPG_RECORD_BYTES));
        assert!(gpg_status_lines(oversized_record.as_bytes()).is_err());
    }

    #[test]
    fn archive_paths_and_pax_metadata_are_bounded_and_canonical() {
        assert_eq!(
            validate_archive_path("qemu-10.1.5/pc-bios/edk2.fd", "qemu-10.1.5/")
                .expect("safe path")
                .as_deref(),
            Some("pc-bios/edk2.fd")
        );
        assert!(validate_archive_path("qemu-10.1.5/../escape", "qemu-10.1.5/").is_err());
        assert!(validate_archive_path("other/file", "qemu-10.1.5/").is_err());
        for path in [
            "qemu-10.1.5/roms/u-boot/doc/ti,sci.txt",
            "qemu-10.1.5/roms/skiboot/Infineon-OPTIGA(TM)_CA.pem",
            "qemu-10.1.5/roms/u-boot/board/sagem/f@st1704.c",
            "qemu-10.1.5/roms/u-boot/board/k+p/Kconfig",
        ] {
            assert!(
                validate_archive_path(path, "qemu-10.1.5/").is_ok(),
                "signed upstream path must be extractable: {path}"
            );
        }
        for path in [
            "qemu-10.1.5/space name",
            "qemu-10.1.5/colon:name",
            "qemu-10.1.5/percent%name",
            "qemu-10.1.5/dollar$name",
        ] {
            assert!(
                validate_archive_path(path, "qemu-10.1.5/").is_err(),
                "undeclared filename punctuation must remain rejected: {path}"
            );
        }
        let pax =
            parse_pax_metadata(b"28 path=pc-bios/firmware.fd\n").expect("canonical PAX metadata");
        assert_eq!(pax.path.as_deref(), Some("pc-bios/firmware.fd"));
        assert!(parse_pax_metadata(b"027 path=pc-bios/firmware.fd\n").is_err());
    }

    #[test]
    fn tar_extractor_materializes_files_and_omits_reviewed_absolute_link() {
        let temporary = TestDirectory::create("tar");
        let destination = temporary.0.join("source");
        fs::create_dir(&destination).expect("create extraction root");
        let mut archive = Vec::new();
        append_tar_member(&mut archive, "qemu-10.1.5/", b'5', b"", "");
        append_tar_member(
            &mut archive,
            &format!("qemu-10.1.5/{}", OMITTED_ABSOLUTE_SYMLINK.0),
            b'2',
            b"",
            OMITTED_ABSOLUTE_SYMLINK.1,
        );
        append_tar_member(
            &mut archive,
            "qemu-10.1.5/configure",
            b'0',
            b"#!/bin/sh\n",
            "",
        );
        archive.extend_from_slice(&[0u8; 1024]);
        extract_tar_stream(archive.as_slice(), &destination, "qemu-10.1.5/")
            .expect("extract canonical archive");
        assert_eq!(
            fs::read(destination.join("configure")).expect("read extracted file"),
            b"#!/bin/sh\n"
        );
        assert!(!destination.join(OMITTED_ABSOLUTE_SYMLINK.0).exists());
    }

    fn append_tar_member(archive: &mut Vec<u8>, path: &str, kind: u8, payload: &[u8], link: &str) {
        let mut header = [0u8; 512];
        write_field(&mut header[0..100], path.as_bytes());
        write_octal(
            &mut header[100..108],
            if kind == b'5' { 0o755 } else { 0o644 },
        );
        write_octal(&mut header[108..116], 0);
        write_octal(&mut header[116..124], 0);
        write_octal(
            &mut header[124..136],
            u64::try_from(payload.len()).expect("payload length"),
        );
        write_octal(&mut header[136..148], 1);
        header[148..156].fill(b' ');
        header[156] = kind;
        write_field(&mut header[157..257], link.as_bytes());
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
        let checksum_text = format!("{checksum:06o}\0 ");
        header[148..156].copy_from_slice(checksum_text.as_bytes());
        archive.extend_from_slice(&header);
        archive.extend_from_slice(payload);
        let padding = (512 - (payload.len() % 512)) % 512;
        archive.resize(archive.len() + padding, 0);
    }

    fn write_field(field: &mut [u8], value: &[u8]) {
        assert!(value.len() < field.len());
        field[..value.len()].copy_from_slice(value);
    }

    fn write_octal(field: &mut [u8], value: u64) {
        let text = format!("{:0width$o}\0", value, width = field.len() - 1);
        field.copy_from_slice(text.as_bytes());
    }
}
