use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use sha2::{Digest, Sha256};

const HELP: &str = "\
usage: cargo xtask llvm [--plan] [--record-output] [--jobs <1..=256>] [--source-archive <absolute>]

Build the exact LLVM/LLD release pinned by toolchain/llvm.lock.toml.

options:
  --plan                       validate inputs and print the content-addressed plan only
  --record-output              maintainer-only fresh build that creates the trusted output lock
  --jobs <count>               bounded native parallelism (default: host availability)
  --source-archive <absolute>  use a pre-fetched archive, verified identically
  -h, --help                   show this help

environment:
  WRELA_LLVM_SOURCE_ARCHIVE  offline archive alternative to --source-archive
  WRELA_LLVM_JOBS            parallelism alternative to --jobs
  WRELA_LLVM_CURL            absolute curl executable used only for HTTPS acquisition
  WRELA_LLVM_XZ              absolute xz executable
  WRELA_LLVM_CMAKE           absolute cmake executable
  WRELA_LLVM_NINJA           absolute ninja executable
  WRELA_LLVM_CC              absolute C compiler executable
  WRELA_LLVM_CXX             absolute C++ compiler executable
  WRELA_LLVM_AR              absolute static archiver executable
  WRELA_LLVM_RANLIB          absolute archive indexer executable
  WRELA_LLVM_PYTHON          absolute Python interpreter required by LLVM CMake
  WRELA_LLVM_LINKER          absolute host linker executable
  WRELA_LLVM_SYSROOT         absolute macOS SDK directory (macOS only)
  WRELA_LLVM_TOUCH           absolute touch utility used by CMake archive rules
";

const LOCK_SCHEMA: u32 = 2;
const OUTPUT_LOCK_SCHEMA: u32 = 1;
const RECEIPT_SCHEMA: u32 = 3;
const BUILD_CONTRACT_VERSION: u32 = 6;
const ARCHIVE_POLICY_VERSION: u32 = 2;
const MAX_JOBS: u32 = 256;
const DEFAULT_MAX_JOBS: u32 = 8;
const MAX_ARCHIVE_MEMBERS: u64 = 2_000_000;
const MAX_ARCHIVE_COMPRESSED_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_ARCHIVE_PATH_BYTES: usize = 4096;
const MAX_ARCHIVE_FILE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_ARCHIVE_TOTAL_BYTES: u64 = 24 * 1024 * 1024 * 1024;
const MAX_PAX_BYTES: u64 = 1024 * 1024;
const MAX_TAR_TRAILER_BYTES: u64 = 1024 * 1024;
const MAX_PREFIX_FILES: u64 = 20_000;
const MAX_PREFIX_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const MAX_PREFIX_PATH_BYTES: usize = 1024;
const MAX_PREFIX_DEPTH: u32 = 128;
const MAX_RUST_LOCK_PACKAGES: usize = 100_000;
const MAX_HOST_CLOSURE_ROOTS: usize = 32;
const MAX_HOST_CLOSURE_ENTRIES: u64 = 500_000;
const MAX_HOST_CLOSURE_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_HOST_CLOSURE_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_DYLD_CACHE_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_STAGING_DIRECTORIES: usize = 256;
const TREE_MAGIC: &[u8; 8] = b"WRELNAT\0";
const TREE_VERSION: u32 = 3;
const LLVM_22_1_3_SHA256: &str = "2488c33a959eafba1c44f253e5bbe7ac958eb53fa626298a3a5f4b87373767cd";
const REVIEWED_CMAKE_SHA256: &str =
    "3507604b18ccb48fab6347160f0e9da5559b3356e96563ca0b2e806af5d785cc";
// llvm-sys 221.0.1 invokes `llvm-config --libnames --link-static` without a
// component filter. This is the exact LLVM 22.1.3/AArch64 response, in linker
// order. Publishing fewer archives would make the pinned Rust binding fail;
// publishing any other LLVM archive would exceed its actual static link
// closure.
const REQUIRED_LLVM_STATIC_COMPONENTS: &[&str] = &[
    "LLVMWindowsManifest",
    "LLVMXRay",
    "LLVMLibDriver",
    "LLVMDlltoolDriver",
    "LLVMTelemetry",
    "LLVMTextAPIBinaryReader",
    "LLVMCoverage",
    "LLVMLineEditor",
    "LLVMAArch64Disassembler",
    "LLVMAArch64AsmParser",
    "LLVMAArch64CodeGen",
    "LLVMAArch64Desc",
    "LLVMAArch64Utils",
    "LLVMAArch64Info",
    "LLVMOrcDebugging",
    "LLVMOrcJIT",
    "LLVMWindowsDriver",
    "LLVMMCJIT",
    "LLVMJITLink",
    "LLVMInterpreter",
    "LLVMExecutionEngine",
    "LLVMRuntimeDyld",
    "LLVMOrcTargetProcess",
    "LLVMOrcShared",
    "LLVMDWP",
    "LLVMDWARFCFIChecker",
    "LLVMDebugInfoLogicalView",
    "LLVMOption",
    "LLVMObjCopy",
    "LLVMMCA",
    "LLVMMCDisassembler",
    "LLVMDTLTO",
    "LLVMLTO",
    "LLVMPlugins",
    "LLVMPasses",
    "LLVMHipStdPar",
    "LLVMCFGuard",
    "LLVMCoroutines",
    "LLVMipo",
    "LLVMVectorize",
    "LLVMSandboxIR",
    "LLVMLinker",
    "LLVMFrontendOpenMP",
    "LLVMFrontendOffloading",
    "LLVMObjectYAML",
    "LLVMFrontendOpenACC",
    "LLVMFrontendDriver",
    "LLVMInstrumentation",
    "LLVMFrontendDirective",
    "LLVMFrontendAtomic",
    "LLVMExtensions",
    "LLVMDWARFLinkerParallel",
    "LLVMDWARFLinkerClassic",
    "LLVMDWARFLinker",
    "LLVMGlobalISel",
    "LLVMMIRParser",
    "LLVMAsmPrinter",
    "LLVMSelectionDAG",
    "LLVMCodeGen",
    "LLVMTarget",
    "LLVMObjCARCOpts",
    "LLVMCodeGenTypes",
    "LLVMCGData",
    "LLVMCAS",
    "LLVMIRPrinter",
    "LLVMInterfaceStub",
    "LLVMFileCheck",
    "LLVMFuzzMutate",
    "LLVMScalarOpts",
    "LLVMInstCombine",
    "LLVMAggressiveInstCombine",
    "LLVMTransformUtils",
    "LLVMBitWriter",
    "LLVMAnalysis",
    "LLVMProfileData",
    "LLVMSymbolize",
    "LLVMDebugInfoBTF",
    "LLVMDebugInfoPDB",
    "LLVMDebugInfoMSF",
    "LLVMDebugInfoCodeView",
    "LLVMDebugInfoGSYM",
    "LLVMDebugInfoDWARF",
    "LLVMObject",
    "LLVMTextAPI",
    "LLVMMCParser",
    "LLVMIRReader",
    "LLVMAsmParser",
    "LLVMMC",
    "LLVMDebugInfoDWARFLowLevel",
    "LLVMBitReader",
    "LLVMFrontendHLSL",
    "LLVMFuzzerCLI",
    "LLVMABI",
    "LLVMCore",
    "LLVMRemarks",
    "LLVMBitstreamReader",
    "LLVMBinaryFormat",
    "LLVMTargetParser",
    "LLVMTableGen",
    "LLVMSupportLSP",
    "LLVMSupport",
    "LLVMDemangle",
];
const REQUIRED_LLD_STATIC_COMPONENTS: &[&str] = &["lldCommon", "lldCOFF"];
const FORBIDDEN_LLD_STATIC_COMPONENTS: &[&str] = &["lldELF", "lldMachO", "lldMinGW", "lldWasm"];
const REQUIRED_LICENSE_NOTICES: &[(&str, &str, &str)] = &[
    (
        "llvm/LICENSE.TXT",
        "share/wrela/licenses/llvm/LICENSE.TXT",
        "8d85c1057d742e597985c7d4e6320b015a9139385cff4cbae06ffc0ebe89afee",
    ),
    (
        "lld/LICENSE.TXT",
        "share/wrela/licenses/lld/LICENSE.TXT",
        "f7891568956e34643eb6a0db1462db30820d40d7266e2a78063f2fe233ece5a0",
    ),
    (
        "llvm/include/llvm/Support/LICENSE.TXT",
        "share/wrela/licenses/llvm/Support-LICENSE.TXT",
        "54cbc326a78b9400065bfc5830a57fdcdaf808286d4ac35d8a9e324aa77b7241",
    ),
    (
        "llvm/lib/Support/BLAKE3/LICENSE",
        "share/wrela/licenses/llvm/BLAKE3-LICENSE",
        "6a94bedb8b707ed97f6e310d0d015ab14e0683ffa0a612b02958581b9cc9fc0e",
    ),
    (
        "llvm/lib/Support/COPYRIGHT.regex",
        "share/wrela/licenses/llvm/COPYRIGHT.regex",
        "0424e57d4303164dc59a8509c20dae0518b853692e5c2b0e98b11816fdbc97c7",
    ),
];
const LLVM_22_1_3_OMITTED_SYMLINKS: &[(&str, &str)] = &[
    (
        "clang/test/Driver/Inputs/CUDA-symlinks/usr/bin/ptxas",
        "../../opt/cuda/bin/ptxas",
    ),
    (
        "clang/test/Driver/Inputs/basic_cross_linux_tree/usr/bin/i386-unknown-linux-gnu-ld",
        "i386-unknown-linux-gnu-ld.gold",
    ),
    (
        "clang/test/Driver/Inputs/basic_cross_linux_tree/usr/bin/x86_64-unknown-linux-gnu-ld",
        "x86_64-unknown-linux-gnu-ld.gold",
    ),
    (
        "clang/test/Driver/Inputs/basic_cross_linux_tree/usr/i386-unknown-linux-gnu/bin/ld",
        "ld.gold",
    ),
    (
        "clang/test/Driver/Inputs/basic_cross_linux_tree/usr/x86_64-unknown-linux-gnu/bin/ld",
        "ld.gold",
    ),
    (
        "clang/test/Driver/Inputs/basic_cross_linux_tree/usr/x86_64-unknown-linux-gnu/bin/lld-wrapper",
        "ld.lld",
    ),
    (
        "clang/test/Driver/Inputs/multilib_32bit_linux_tree/usr/bin/as",
        "i386-unknown-linux-gnu-as",
    ),
    (
        "clang/test/Driver/Inputs/multilib_32bit_linux_tree/usr/bin/ld",
        "i386-unknown-linux-gnu-ld",
    ),
    (
        "clang/test/Driver/Inputs/multilib_32bit_linux_tree/usr/i386-unknown-linux/bin/as",
        "../../bin/i386-unknown-linux-gnu-as",
    ),
    (
        "clang/test/Driver/Inputs/multilib_32bit_linux_tree/usr/i386-unknown-linux/bin/ld",
        "../../bin/i386-unknown-linux-gnu-ld",
    ),
    (
        "clang/test/Driver/Inputs/multilib_64bit_linux_tree/usr/bin/as",
        "x86_64-unknown-linux-gnu-as",
    ),
    (
        "clang/test/Driver/Inputs/multilib_64bit_linux_tree/usr/bin/ld",
        "x86_64-unknown-linux-gnu-ld",
    ),
    (
        "clang/test/Driver/Inputs/multilib_64bit_linux_tree/usr/x86_64-unknown-linux/bin/as",
        "../../bin/x86_64-unknown-linux-gnu-as",
    ),
    (
        "clang/test/Driver/Inputs/multilib_64bit_linux_tree/usr/x86_64-unknown-linux/bin/ld",
        "../../bin/x86_64-unknown-linux-gnu-ld",
    ),
    (
        "lldb/test/API/functionalities/breakpoint/breakpoint_with_realpath_and_source_map/symlink1/foo.h",
        "../real/foo.h",
    ),
    (
        "lldb/test/API/functionalities/breakpoint/breakpoint_with_realpath_and_source_map/symlink2",
        "real",
    ),
    (
        "llvm/utils/mlgo-utils/combine_training_corpus.py",
        "mlgo/corpus/combine_training_corpus.py",
    ),
    (
        "llvm/utils/mlgo-utils/extract_ir.py",
        "mlgo/corpus/extract_ir.py",
    ),
    (
        "llvm/utils/mlgo-utils/make_corpus.py",
        "mlgo/corpus/make_corpus.py",
    ),
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct Options {
    plan_only: bool,
    record_output: bool,
    jobs: u32,
    source_archive: Option<PathBuf>,
    help: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LlvmLock {
    schema: u32,
    version: String,
    tag: String,
    commit: String,
    source: String,
    sha256: String,
    archive_bytes: u64,
    projects: Vec<String>,
    targets: Vec<String>,
    linkage: String,
    inkwell_version: String,
    inkwell_llvm_feature: String,
    inkwell_target_features: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LockError {
    InvalidUtf8,
    Malformed { line: usize, reason: &'static str },
    UnknownField(String),
    DuplicateField(String),
    MissingField(&'static str),
    InvalidValue(&'static str),
    NonCanonical,
}

impl std::fmt::Display for LockError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUtf8 => formatter.write_str("LLVM lock is not UTF-8"),
            Self::Malformed { line, reason } => {
                write!(formatter, "malformed LLVM lock line {line}: {reason}")
            }
            Self::UnknownField(field) => write!(formatter, "unknown LLVM lock field {field}"),
            Self::DuplicateField(field) => write!(formatter, "duplicate LLVM lock field {field}"),
            Self::MissingField(field) => write!(formatter, "LLVM lock is missing field {field}"),
            Self::InvalidValue(field) => write!(formatter, "invalid LLVM lock value for {field}"),
            Self::NonCanonical => formatter.write_str("LLVM lock bytes are not canonical"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ToolIdentity {
    path: PathBuf,
    digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NativeTools {
    xz: ToolIdentity,
    cmake: ToolIdentity,
    ninja: ToolIdentity,
    cc: ToolIdentity,
    cxx: ToolIdentity,
    ar: ToolIdentity,
    ranlib: ToolIdentity,
    python: ToolIdentity,
    linker: ToolIdentity,
    sysroot: Option<DirectoryIdentity>,
    touch: ToolIdentity,
    shell: ToolIdentity,
    host_closure: HostClosureIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectoryIdentity {
    path: PathBuf,
    digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HostRootIdentity {
    role: String,
    path: PathBuf,
    digest: String,
    entries: u64,
    bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HostClosureIdentity {
    digest: String,
    roots: Vec<HostRootIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BuildPlan {
    workspace_root: PathBuf,
    lock: LlvmLock,
    lock_digest: String,
    cmake_contract: PathBuf,
    cmake_bytes: Vec<u8>,
    cmake_digest: String,
    codegen_binding_digest: String,
    rust_binding_digest: String,
    flags_digest: String,
    implementation_digest: String,
    bootstrap_executable: ToolIdentity,
    host: String,
    input_digest: String,
    key: String,
    bundle: PathBuf,
    prefix: PathBuf,
    expected_output: Option<ExpectedOutput>,
    license_notices: Vec<LicenseNotice>,
    tools: NativeTools,
    jobs: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LicenseNotice {
    destination: String,
    digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BootstrapImplementationProjection {
    llvm_source_digest: String,
    dispatch_digest: String,
    manifest_digest: String,
    dependency_closure_digest: String,
}

#[derive(Clone, Copy)]
struct BootstrapSources<'a> {
    llvm: &'a [u8],
    main: &'a [u8],
    manifest: &'a [u8],
    cargo_lock: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommandSpec {
    program: PathBuf,
    arguments: Vec<OsString>,
    environment: Vec<(OsString, OsString)>,
    current_dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TreeMeasurement {
    digest: String,
    files: u64,
    bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExpectedOutput {
    input_digest: String,
    llvm_version: String,
    host: String,
    prefix_tree_sha256: String,
    prefix_files: u64,
    prefix_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProvenanceReceipt {
    input_digest: String,
    llvm_version: String,
    llvm_tag: String,
    llvm_commit: String,
    source_url: String,
    archive_sha256: String,
    archive_bytes: u64,
    lock_sha256: String,
    cmake_sha256: String,
    codegen_binding_sha256: String,
    rust_binding_sha256: String,
    flags_sha256: String,
    implementation_sha256: String,
    host: String,
    xz_sha256: String,
    cmake_tool_sha256: String,
    ninja_sha256: String,
    cc_sha256: String,
    cxx_sha256: String,
    ar_sha256: String,
    ranlib_sha256: String,
    python_sha256: String,
    linker_sha256: String,
    sysroot_sha256: String,
    touch_sha256: String,
    shell_sha256: String,
    host_closure_sha256: String,
    prefix_tree_sha256: String,
    prefix_files: u64,
    prefix_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedNativeEnvironment {
    pub(crate) prefix: PathBuf,
    pub(crate) cxx: PathBuf,
    pub(crate) ar: PathBuf,
    pub(crate) sysroot: PathBuf,
}

// WRELA-DIST-CONSUMER-BEGIN native-authority-types
/// Full Darwin native authority retained by the distribution producer.
///
/// The ordinary LLVM cache consumer intentionally receives only
/// [`VerifiedNativeEnvironment`].  Distribution assembly additionally retains
/// stable observations of the exact paths selected by the full authority scan
/// so it can cheaply reject replacement between the initial scan and the final
/// pre-publication rescan.  These witnesses are change detectors, not a
/// substitute for either full scan.
#[derive(Debug)]
pub(crate) struct VerifiedDistributionAuthority {
    environment: VerifiedNativeEnvironment,
    input_digest: String,
    host_closure_digest: String,
    prefix_tree_digest: String,
    witnesses: Vec<StablePathWitness>,
}

impl VerifiedDistributionAuthority {
    pub(crate) fn environment(&self) -> &VerifiedNativeEnvironment {
        &self.environment
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WitnessKind {
    File,
    Directory,
    Symlink,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StablePathWitness {
    label: String,
    path: PathBuf,
    kind: WitnessKind,
    mode: u32,
    device: u64,
    inode: u64,
    links: u64,
    user: u32,
    group: u32,
    bytes: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    link_target: Option<PathBuf>,
    require_single_link: bool,
}
// WRELA-DIST-CONSUMER-END native-authority-types
pub(crate) fn run(root: &Path, arguments: &[String]) -> Result<(), String> {
    let options = parse_options(arguments)?;
    if options.help {
        print!("{HELP}");
        return Ok(());
    }
    let mut plan = load_plan(root, options.jobs)?;
    if options.plan_only {
        print_plan(&plan, options.source_archive.as_deref());
        return Ok(());
    }

    ensure_non_symlink_directory_chain(root, Path::new("build/toolchain/llvm/staging"))?;
    ensure_non_symlink_directory_chain(root, Path::new("build/toolchain/llvm/prefixes"))?;
    match (options.record_output, plan.expected_output.is_some()) {
        (true, true) => {
            return Err(
                "--record-output requires toolchain/llvm.outputs.toml to be absent; remove it only as an intentional maintainer review operation"
                    .to_owned(),
            );
        }
        (false, false) => {
            return Err(
                "toolchain/llvm.outputs.toml has no trusted output for these exact inputs; a maintainer must run one fresh `cargo xtask llvm --record-output` build and review the resulting lock"
                    .to_owned(),
            );
        }
        _ => {}
    }

    if options.record_output {
        quarantine_untrusted_published_bundle(&plan)?;
    } else {
        if let Some(prefix) = verify_or_quarantine_published_bundle(&plan)? {
            println!("reused verified LLVM prefix {}", prefix.display());
            return Ok(());
        }
    }

    let archive = acquire_archive(root, &plan, options.source_archive.as_deref())?;
    let archive_file = open_verified_archive(&archive, &plan.lock.sha256, plan.lock.archive_bytes)?;
    let staging = StagingDirectory::create(root, &plan.key)?;
    if !options.record_output {
        if let Some(prefix) = verify_or_quarantine_published_bundle(&plan)? {
            println!("reused verified LLVM prefix {}", prefix.display());
            return Ok(());
        }
    }
    let source = staging.path.join("source");
    fs::create_dir(&source)
        .map_err(|error| format!("cannot create LLVM source staging directory: {error}"))?;
    extract_verified_archive(archive_file, &plan.tools.xz.path, &source, &plan.lock)?;
    revalidate_native_tools(&plan.tools)?;
    patch_deterministic_source(&source)?;
    normalize_source_timestamps(&source, &plan.tools.touch.path)?;

    let build = staging.path.join("build");
    let bundle = staging.path.join("bundle");
    let prefix = bundle.join("prefix");
    fs::create_dir(&build)
        .map_err(|error| format!("cannot create LLVM build staging directory: {error}"))?;
    fs::create_dir_all(&prefix)
        .map_err(|error| format!("cannot create LLVM prefix staging directory: {error}"))?;
    prepare_controlled_tool_path(&build, &plan.tools)?;
    let staged_cmake_contract = stage_cmake_contract(&build, &plan)?;

    let (configure, build_llvm_config, install) =
        build_commands(&plan, &source, &build, &prefix, &staged_cmake_contract)?;
    revalidate_native_tools(&plan.tools)?;
    run_command(&configure, "LLVM CMake configure", 30 * 60)?;
    revalidate_native_tools(&plan.tools)?;
    canonicalize_llvm_config_build_variables(&source, &build)?;
    run_command(&build_llvm_config, "LLVM llvm-config build", 2 * 60 * 60)?;
    revalidate_native_tools(&plan.tools)?;
    run_command(&install, "LLVM/LLD build and install", 8 * 60 * 60)?;
    revalidate_native_tools(&plan.tools)?;
    stage_llvm_config(&build, &prefix)?;
    stage_license_notices(&source, &prefix)?;
    canonicalize_installed_archives(&prefix, &plan.tools.ranlib.path)?;
    normalize_prefix_permissions(&prefix)?;
    normalize_prefix_timestamps(&prefix, &plan.tools.touch.path)?;
    revalidate_native_tools(&plan.tools)?;
    validate_static_prefix(&prefix)?;
    validate_required_prefix(&prefix, &plan.license_notices)?;
    revalidate_plan_inputs(root, &plan)?;
    let measurement = measure_tree(&prefix)?;
    match &plan.expected_output {
        Some(expected) => validate_expected_measurement(expected, &measurement)?,
        None if options.record_output => {
            let expected = expected_output_for_measurement(&plan, &measurement);
            record_expected_output(root, &expected)?;
            plan.expected_output = Some(expected);
        }
        None => return Err("trusted LLVM output disappeared during bootstrap".to_owned()),
    }
    validate_llvm_config_semantics(&prefix, &plan.lock, &plan.host)?;
    let receipt = receipt_for_plan(&plan, &measurement);
    let receipt_bytes = encode_receipt(&receipt);
    let receipt_path = bundle.join("provenance.txt");
    write_new_file(&receipt_path, &receipt_bytes)?;
    normalize_prefix_permissions(&bundle)?;
    normalize_prefix_timestamps(&bundle, &plan.tools.touch.path)?;
    revalidate_native_tools(&plan.tools)?;
    revalidate_host_closure(&plan.tools)?;
    revalidate_expected_output(root, &plan)?;
    if measure_tree(&prefix)? != measurement {
        return Err("LLVM prefix changed while finalizing its provenance bundle".to_owned());
    }
    sync_tree(&bundle)?;
    sync_directory(&staging.path)?;
    publish_bundle(&staging.path, &bundle, &plan)?;
    let prefix = verify_published_bundle(&plan)?
        .ok_or_else(|| "published LLVM bundle did not verify after rename".to_owned())?;
    println!("published verified LLVM prefix {}", prefix.display());
    Ok(())
}

pub(crate) fn verified_environment_for_full_route(
    root: &Path,
) -> Result<VerifiedNativeEnvironment, String> {
    validate_non_symlink_directory_chain(root, Path::new("build/toolchain/llvm/prefixes"))?;
    let plan = load_plan(root, default_jobs()?)?;
    let prefix = verify_published_bundle(&plan)?.ok_or_else(|| {
        format!(
            "verified LLVM prefix {} is absent; run `cargo xtask llvm` first",
            plan.prefix.display()
        )
    })?;
    revalidate_native_tools(&plan.tools)?;
    revalidate_host_closure(&plan.tools)?;
    let cxx = fs::canonicalize(&plan.tools.cxx.path)
        .map_err(|error| format!("cannot resolve verified C++ compiler: {error}"))?;
    let ar = fs::canonicalize(&plan.tools.ar.path)
        .map_err(|error| format!("cannot resolve verified archiver: {error}"))?;
    let sysroot = plan
        .tools
        .sysroot
        .as_ref()
        .ok_or_else(|| "verified native environment omits macOS SDK".to_owned())?
        .path
        .clone();
    Ok(VerifiedNativeEnvironment {
        prefix,
        cxx,
        ar,
        sysroot,
    })
}

// WRELA-DIST-CONSUMER-BEGIN native-authority-implementation
/// Perform the full enrolled LLVM/native-authority validation once and retain
/// bounded stable observations for distribution assembly.
pub(crate) fn verified_authority_for_distribution(
    root: &Path,
) -> Result<VerifiedDistributionAuthority, String> {
    validate_non_symlink_directory_chain(root, Path::new("build/toolchain/llvm/prefixes"))?;
    // `load_plan` performs the complete authenticated host-closure scan.  Do
    // not immediately repeat that multi-gigabyte scan here: the distribution
    // retains exact direct-path observations until its one final full rescan.
    let plan = load_plan(root, default_jobs()?)?;
    let prefix = verify_published_bundle_once(&plan)?.ok_or_else(|| {
        format!(
            "verified LLVM prefix {} is absent; run `cargo xtask llvm` first",
            plan.prefix.display()
        )
    })?;
    let authority = distribution_authority_from_verified_plan(root, &plan, prefix)?;
    revalidate_distribution_witness(&authority)?;
    Ok(authority)
}

fn verify_published_bundle_once(plan: &BuildPlan) -> Result<Option<PathBuf>, String> {
    validate_plan_prefix_cache(plan)?;
    let expected_output = plan.expected_output.as_ref().ok_or_else(|| {
        "trusted toolchain/llvm.outputs.toml is absent; cached LLVM reuse is forbidden".to_owned()
    })?;
    if !plan.bundle.exists() {
        return Ok(None);
    }
    let metadata = fs::symlink_metadata(&plan.bundle).map_err(|error| {
        format!(
            "cannot inspect published LLVM bundle {}: {error}",
            plan.bundle.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "published LLVM bundle {} is not a non-symlink directory",
            plan.bundle.display()
        ));
    }
    let observed = measure_tree(&plan.prefix)?;
    validate_expected_measurement(expected_output, &observed)?;
    let trusted_measurement = TreeMeasurement {
        digest: expected_output.prefix_tree_sha256.clone(),
        files: expected_output.prefix_files,
        bytes: expected_output.prefix_bytes,
    };
    let receipt_path = plan.bundle.join("provenance.txt");
    let receipt = decode_receipt(&read_bounded_regular_file(&receipt_path, 64 * 1024)?)?;
    let expected_inputs = receipt_for_plan(plan, &trusted_measurement);
    if receipt != expected_inputs {
        return Err(format!(
            "LLVM provenance {} does not match current pinned inputs",
            receipt_path.display()
        ));
    }
    validate_required_prefix(&plan.prefix, &plan.license_notices)?;
    validate_static_prefix(&plan.prefix)?;
    validate_llvm_config_semantics(&plan.prefix, &plan.lock, &plan.host)?;
    Ok(Some(plan.prefix.clone()))
}

/// Recheck only the selected stable path observations retained by the initial
/// full scan.  This performs no hashing, recursive traversal, command
/// execution, or plan loading.
pub(crate) fn revalidate_distribution_witness(
    authority: &VerifiedDistributionAuthority,
) -> Result<(), String> {
    revalidate_stable_path_witnesses(&authority.witnesses)
}

fn revalidate_stable_path_witnesses(witnesses: &[StablePathWitness]) -> Result<(), String> {
    for expected in witnesses {
        let observed = observe_stable_path_with_policy(
            &expected.path,
            &expected.label,
            expected.require_single_link,
        )?;
        if &observed != expected {
            return Err(format!(
                "distribution native-authority witness changed: {} ({})",
                expected.label,
                expected.path.display()
            ));
        }
    }
    Ok(())
}

/// Repeat the complete enrolled LLVM/native-authority validation immediately
/// before distribution publication and require the exact planned authority.
pub(crate) fn revalidate_distribution_authority(
    root: &Path,
    authority: &VerifiedDistributionAuthority,
) -> Result<(), String> {
    revalidate_distribution_witness(authority)?;
    let observed = verified_authority_for_distribution(root)?;
    if observed.environment != authority.environment
        || observed.input_digest != authority.input_digest
        || observed.host_closure_digest != authority.host_closure_digest
        || observed.prefix_tree_digest != authority.prefix_tree_digest
        || observed.witnesses != authority.witnesses
    {
        return Err(
            "distribution native authority differs from the fully verified plan".to_owned(),
        );
    }
    revalidate_distribution_witness(authority)
}

fn environment_from_verified_plan(
    plan: &BuildPlan,
    prefix: PathBuf,
) -> Result<VerifiedNativeEnvironment, String> {
    let cxx = fs::canonicalize(&plan.tools.cxx.path)
        .map_err(|error| format!("cannot resolve verified C++ compiler: {error}"))?;
    let ar = fs::canonicalize(&plan.tools.ar.path)
        .map_err(|error| format!("cannot resolve verified archiver: {error}"))?;
    let sysroot = plan
        .tools
        .sysroot
        .as_ref()
        .ok_or_else(|| "verified native environment omits macOS SDK".to_owned())?
        .path
        .clone();
    Ok(VerifiedNativeEnvironment {
        prefix,
        cxx,
        ar,
        sysroot,
    })
}

fn distribution_authority_from_verified_plan(
    root: &Path,
    plan: &BuildPlan,
    prefix: PathBuf,
) -> Result<VerifiedDistributionAuthority, String> {
    let environment = environment_from_verified_plan(plan, prefix)?;
    let expected = plan.expected_output.as_ref().ok_or_else(|| {
        "trusted toolchain/llvm.outputs.toml is absent after full native verification".to_owned()
    })?;
    let mut selected = Vec::<(String, PathBuf)>::new();
    let mut add = |label: &str, path: &Path| {
        selected.push((label.to_owned(), path.to_owned()));
    };
    add("verified LLVM prefix", &environment.prefix);
    add("verified C++ compiler", &environment.cxx);
    add("verified archiver", &environment.ar);
    add("verified macOS SDK", &environment.sysroot);
    add(
        "LLVM output enrollment",
        &root.join("toolchain/llvm.outputs.toml"),
    );
    add("LLVM input lock", &root.join("toolchain/llvm.lock.toml"));
    add("LLVM CMake contract", &plan.cmake_contract);
    add("LLVM bootstrap executable", &plan.bootstrap_executable.path);
    add(
        "LLVM provenance receipt",
        &plan.bundle.join("provenance.txt"),
    );
    for (label, tool) in [
        ("native xz", &plan.tools.xz),
        ("native CMake", &plan.tools.cmake),
        ("native Ninja", &plan.tools.ninja),
        ("native C compiler", &plan.tools.cc),
        ("native C++ compiler", &plan.tools.cxx),
        ("native archiver", &plan.tools.ar),
        ("native archive indexer", &plan.tools.ranlib),
        ("native Python", &plan.tools.python),
        ("native linker", &plan.tools.linker),
        ("native touch", &plan.tools.touch),
        ("native shell", &plan.tools.shell),
    ] {
        add(label, &tool.path);
    }
    selected.sort_by(|left, right| left.1.cmp(&right.1).then_with(|| left.0.cmp(&right.0)));
    selected.dedup_by(|left, right| left.1 == right.1);
    let mut witnesses = Vec::new();
    for (label, path) in selected {
        let witness = observe_stable_path(&path, &label)?;
        let is_symlink = witness.kind == WitnessKind::Symlink;
        witnesses.push(witness);
        if is_symlink {
            let target = fs::canonicalize(&path).map_err(|error| {
                format!(
                    "cannot resolve distribution native-authority invocation link {}: {error}",
                    path.display()
                )
            })?;
            witnesses.push(observe_stable_path(
                &target,
                &format!("{label} canonical target"),
            )?);
        }
    }
    let mut host_entries = 0_u64;
    for root in &plan.tools.host_closure.roots {
        collect_stable_tree_witnesses(
            &root.path,
            &format!("native host closure {}", root.role),
            &mut witnesses,
            &mut host_entries,
            0,
        )?;
    }
    witnesses.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.label.cmp(&right.label))
    });
    witnesses.dedup_by(|left, right| left.path == right.path);
    Ok(VerifiedDistributionAuthority {
        environment,
        input_digest: plan.input_digest.clone(),
        host_closure_digest: plan.tools.host_closure.digest.clone(),
        prefix_tree_digest: expected.prefix_tree_sha256.clone(),
        witnesses,
    })
}

#[cfg(unix)]
fn observe_stable_path(path: &Path, label: &str) -> Result<StablePathWitness, String> {
    observe_stable_path_with_policy(path, label, true)
}

#[cfg(unix)]
fn observe_stable_path_with_policy(
    path: &Path,
    label: &str,
    require_single_link: bool,
) -> Result<StablePathWitness, String> {
    use std::os::unix::fs::MetadataExt as _;

    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(format!(
            "distribution native-authority witness {label} is not an exact absolute path: {}",
            path.display()
        ));
    }
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        format!(
            "cannot inspect distribution native-authority witness {label} at {}: {error}",
            path.display()
        )
    })?;
    let (kind, link_target) = if metadata.file_type().is_symlink() {
        let target = fs::read_link(path).map_err(|error| {
            format!(
                "cannot read distribution native-authority witness link {label} at {}: {error}",
                path.display()
            )
        })?;
        (WitnessKind::Symlink, Some(target))
    } else if metadata.is_file() {
        let canonical = fs::canonicalize(path).map_err(|error| {
            format!(
                "cannot resolve distribution native-authority witness {label} at {}: {error}",
                path.display()
            )
        })?;
        if canonical != path {
            return Err(format!(
                "distribution native-authority witness {label} is not an exact canonical path: {}",
                path.display()
            ));
        }
        if require_single_link && metadata.nlink() != 1 {
            return Err(format!(
                "distribution native-authority file witness {label} has {} links: {}",
                metadata.nlink(),
                path.display()
            ));
        }
        (WitnessKind::File, None)
    } else if metadata.is_dir() {
        let canonical = fs::canonicalize(path).map_err(|error| {
            format!(
                "cannot resolve distribution native-authority witness {label} at {}: {error}",
                path.display()
            )
        })?;
        if canonical != path {
            return Err(format!(
                "distribution native-authority witness {label} is not an exact canonical path: {}",
                path.display()
            ));
        }
        (WitnessKind::Directory, None)
    } else {
        return Err(format!(
            "distribution native-authority witness {label} has unsupported type: {}",
            path.display()
        ));
    };
    Ok(StablePathWitness {
        label: label.to_owned(),
        path: path.to_owned(),
        kind,
        mode: metadata.mode(),
        device: metadata.dev(),
        inode: metadata.ino(),
        links: metadata.nlink(),
        user: metadata.uid(),
        group: metadata.gid(),
        bytes: metadata.size(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
        link_target,
        require_single_link,
    })
}

fn collect_stable_tree_witnesses(
    path: &Path,
    label: &str,
    witnesses: &mut Vec<StablePathWitness>,
    entries: &mut u64,
    depth: u32,
) -> Result<(), String> {
    if depth > MAX_PREFIX_DEPTH {
        return Err(format!(
            "distribution native-authority witness exceeds directory depth {MAX_PREFIX_DEPTH}"
        ));
    }
    *entries = entries
        .checked_add(1)
        .ok_or_else(|| "distribution native-authority witness count overflow".to_owned())?;
    if *entries > MAX_HOST_CLOSURE_ENTRIES {
        return Err(format!(
            "distribution native-authority witness exceeds {MAX_HOST_CLOSURE_ENTRIES} entries"
        ));
    }
    let witness = observe_stable_path_with_policy(path, label, false)?;
    let directory = witness.kind == WitnessKind::Directory;
    witnesses
        .try_reserve(1)
        .map_err(|_| "cannot reserve distribution native-authority witnesses".to_owned())?;
    witnesses.push(witness);
    if directory {
        let mut children = Vec::new();
        for entry in fs::read_dir(path).map_err(|error| {
            format!(
                "cannot read distribution native-authority directory {}: {error}",
                path.display()
            )
        })? {
            children.push(
                entry
                    .map_err(|error| {
                        format!("cannot inspect distribution native-authority entry: {error}")
                    })?
                    .path(),
            );
        }
        children.sort();
        for child in children {
            collect_stable_tree_witnesses(&child, label, witnesses, entries, depth + 1)?;
        }
    }
    Ok(())
}

fn distribution_partitioned_llvm_source_digest(bytes: &[u8]) -> Result<String, String> {
    const BEGIN: &str = "// WRELA-DIST-CONSUMER-BEGIN ";
    const END: &str = "// WRELA-DIST-CONSUMER-END ";
    const CURRENT_PROJECTION: &str =
        "        llvm_source_digest: distribution_partitioned_llvm_source_digest(sources.llvm)?,\n";
    const LEGACY_PROJECTION: &str = "        llvm_source_digest: sha256_bytes(sources.llvm),\n";

    let source = std::str::from_utf8(bytes)
        .map_err(|_| "xtask/src/llvm.rs is not canonical UTF-8".to_owned())?;
    if !source.ends_with('\n') || source.contains('\r') || source.contains('\0') {
        return Err("xtask/src/llvm.rs has noncanonical text encoding".to_owned());
    }
    let mut projected = String::new();
    projected
        .try_reserve(source.len())
        .map_err(|_| "cannot reserve LLVM producer-source projection".to_owned())?;
    let mut section: Option<&str> = None;
    for line in source.split_inclusive('\n') {
        let marker = line.trim_start();
        if let Some(name) = marker
            .strip_prefix(BEGIN)
            .and_then(|value| value.strip_suffix('\n'))
        {
            if section.is_some()
                || name.is_empty()
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'-')
            {
                return Err("LLVM source has malformed distribution-consumer markers".to_owned());
            }
            section = Some(name);
            continue;
        }
        if let Some(name) = marker
            .strip_prefix(END)
            .and_then(|value| value.strip_suffix('\n'))
        {
            if section != Some(name) {
                return Err("LLVM source has mismatched distribution-consumer markers".to_owned());
            }
            section = None;
            continue;
        }
        if section.is_none() {
            projected.push_str(line);
        }
    }
    if section.is_some() {
        return Err("LLVM source has an unterminated distribution-consumer section".to_owned());
    }
    if projected.matches(CURRENT_PROJECTION).count() != 1 {
        return Err("LLVM producer-source projection call is not exact".to_owned());
    }
    Ok(sha256_bytes(
        projected
            .replacen(CURRENT_PROJECTION, LEGACY_PROJECTION, 1)
            .as_bytes(),
    ))
}

#[cfg(not(unix))]
fn observe_stable_path(_path: &Path, _label: &str) -> Result<StablePathWitness, String> {
    Err("distribution native-authority witnesses require Unix metadata".to_owned())
}

#[cfg(not(unix))]
fn observe_stable_path_with_policy(
    _path: &Path,
    _label: &str,
    _require_single_link: bool,
) -> Result<StablePathWitness, String> {
    Err("distribution native-authority witnesses require Unix metadata".to_owned())
}
// WRELA-DIST-CONSUMER-END native-authority-implementation
fn parse_options(arguments: &[String]) -> Result<Options, String> {
    let mut plan_only = false;
    let mut record_output = false;
    let mut help = false;
    let mut jobs = None;
    let mut source_archive = None;
    let mut index = 0_usize;
    while index < arguments.len() {
        match arguments[index].as_str() {
            "--plan" if !plan_only => plan_only = true,
            "--record-output" if !record_output => record_output = true,
            "-h" | "--help" if !help => help = true,
            "--jobs" if jobs.is_none() => {
                index += 1;
                let value = arguments
                    .get(index)
                    .ok_or_else(|| "--jobs requires a value".to_owned())?;
                jobs = Some(parse_jobs(value, "--jobs")?);
            }
            "--source-archive" if source_archive.is_none() => {
                index += 1;
                let value = arguments
                    .get(index)
                    .ok_or_else(|| "--source-archive requires a path".to_owned())?;
                source_archive = Some(absolute_existing_file(
                    Path::new(value),
                    "--source-archive",
                )?);
            }
            argument => {
                return Err(format!(
                    "unknown or duplicate LLVM option {argument:?}\n{HELP}"
                ));
            }
        }
        index += 1;
    }

    if source_archive.is_none() {
        if let Some(value) = env::var_os("WRELA_LLVM_SOURCE_ARCHIVE") {
            source_archive = Some(absolute_existing_file(
                Path::new(&value),
                "WRELA_LLVM_SOURCE_ARCHIVE",
            )?);
        }
    } else if env::var_os("WRELA_LLVM_SOURCE_ARCHIVE").is_some() {
        return Err("set only one of --source-archive and WRELA_LLVM_SOURCE_ARCHIVE".to_owned());
    }
    if jobs.is_none() {
        jobs = env::var("WRELA_LLVM_JOBS")
            .ok()
            .map(|value| parse_jobs(&value, "WRELA_LLVM_JOBS"))
            .transpose()?;
    }
    if plan_only && record_output {
        return Err("--plan and --record-output are mutually exclusive".to_owned());
    }
    Ok(Options {
        plan_only,
        record_output,
        jobs: jobs.unwrap_or(default_jobs()?),
        source_archive,
        help,
    })
}

fn parse_jobs(value: &str, source: &str) -> Result<u32, String> {
    let jobs = value
        .parse::<u32>()
        .map_err(|_| format!("{source} must be an unsigned decimal integer"))?;
    if !(1..=MAX_JOBS).contains(&jobs) {
        return Err(format!("{source} must be in 1..={MAX_JOBS}"));
    }
    Ok(jobs)
}

fn default_jobs() -> Result<u32, String> {
    let jobs = std::thread::available_parallelism()
        .map_err(|error| format!("cannot determine native build parallelism: {error}"))?
        .get()
        .min(DEFAULT_MAX_JOBS as usize);
    u32::try_from(jobs).map_err(|_| "native build parallelism does not fit u32".to_owned())
}

fn absolute_existing_file(path: &Path, source: &str) -> Result<PathBuf, String> {
    if !path.is_absolute() {
        return Err(format!("{source} must be an absolute path"));
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {source} {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!("{source} must name a regular non-symlink file"));
    }
    Ok(path.to_owned())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockSection {
    Root,
    Llvm,
    Inkwell,
}

#[derive(Default)]
struct LockBuilder {
    schema: Option<u32>,
    version: Option<String>,
    tag: Option<String>,
    commit: Option<String>,
    source: Option<String>,
    sha256: Option<String>,
    archive_bytes: Option<u64>,
    projects: Option<Vec<String>>,
    targets: Option<Vec<String>>,
    linkage: Option<String>,
    inkwell_version: Option<String>,
    inkwell_llvm_feature: Option<String>,
    inkwell_target_features: Option<Vec<String>>,
}

fn decode_lock(bytes: &[u8]) -> Result<LlvmLock, LockError> {
    let source = std::str::from_utf8(bytes).map_err(|_| LockError::InvalidUtf8)?;
    let mut builder = LockBuilder::default();
    let mut section = LockSection::Root;
    let mut llvm_seen = false;
    let mut inkwell_seen = false;
    for (line_index, raw_line) in source.lines().enumerate() {
        let line_number = line_index + 1;
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') {
            return Err(LockError::NonCanonical);
        }
        if line.starts_with('[') {
            match line {
                "[llvm]" if !llvm_seen && !inkwell_seen => {
                    llvm_seen = true;
                    section = LockSection::Llvm;
                }
                "[inkwell]" if llvm_seen && !inkwell_seen => {
                    inkwell_seen = true;
                    section = LockSection::Inkwell;
                }
                "[llvm]" | "[inkwell]" => {
                    return Err(LockError::DuplicateField(line.to_owned()));
                }
                _ => return Err(LockError::UnknownField(line.to_owned())),
            }
            continue;
        }
        let (key, value) = line.split_once('=').ok_or(LockError::Malformed {
            line: line_number,
            reason: "expected key/value assignment",
        })?;
        let key = key.trim();
        let value = value.trim();
        let path = match section {
            LockSection::Root => key.to_owned(),
            LockSection::Llvm => format!("llvm.{key}"),
            LockSection::Inkwell => format!("inkwell.{key}"),
        };
        match (section, key) {
            (LockSection::Root, "schema") => set_lock_field(
                &mut builder.schema,
                &path,
                parse_lock_u32(value, line_number)?,
            )?,
            (LockSection::Llvm, "version") => set_lock_field(
                &mut builder.version,
                &path,
                parse_lock_string(value, line_number)?,
            )?,
            (LockSection::Llvm, "tag") => set_lock_field(
                &mut builder.tag,
                &path,
                parse_lock_string(value, line_number)?,
            )?,
            (LockSection::Llvm, "commit") => set_lock_field(
                &mut builder.commit,
                &path,
                parse_lock_string(value, line_number)?,
            )?,
            (LockSection::Llvm, "source") => set_lock_field(
                &mut builder.source,
                &path,
                parse_lock_string(value, line_number)?,
            )?,
            (LockSection::Llvm, "sha256") => set_lock_field(
                &mut builder.sha256,
                &path,
                parse_lock_string(value, line_number)?,
            )?,
            (LockSection::Llvm, "bytes") => set_lock_field(
                &mut builder.archive_bytes,
                &path,
                parse_lock_u64(value, line_number)?,
            )?,
            (LockSection::Llvm, "projects") => set_lock_field(
                &mut builder.projects,
                &path,
                parse_lock_array(value, line_number)?,
            )?,
            (LockSection::Llvm, "targets") => set_lock_field(
                &mut builder.targets,
                &path,
                parse_lock_array(value, line_number)?,
            )?,
            (LockSection::Llvm, "linkage") => set_lock_field(
                &mut builder.linkage,
                &path,
                parse_lock_string(value, line_number)?,
            )?,
            (LockSection::Inkwell, "version") => set_lock_field(
                &mut builder.inkwell_version,
                &path,
                parse_lock_string(value, line_number)?,
            )?,
            (LockSection::Inkwell, "llvm_feature") => set_lock_field(
                &mut builder.inkwell_llvm_feature,
                &path,
                parse_lock_string(value, line_number)?,
            )?,
            (LockSection::Inkwell, "target_features") => set_lock_field(
                &mut builder.inkwell_target_features,
                &path,
                parse_lock_array(value, line_number)?,
            )?,
            _ => return Err(LockError::UnknownField(path)),
        }
    }
    if !llvm_seen {
        return Err(LockError::MissingField("llvm"));
    }
    if !inkwell_seen {
        return Err(LockError::MissingField("inkwell"));
    }
    let lock = LlvmLock {
        schema: required_lock(builder.schema, "schema")?,
        version: required_lock(builder.version, "llvm.version")?,
        tag: required_lock(builder.tag, "llvm.tag")?,
        commit: required_lock(builder.commit, "llvm.commit")?,
        source: required_lock(builder.source, "llvm.source")?,
        sha256: required_lock(builder.sha256, "llvm.sha256")?,
        archive_bytes: required_lock(builder.archive_bytes, "llvm.bytes")?,
        projects: required_lock(builder.projects, "llvm.projects")?,
        targets: required_lock(builder.targets, "llvm.targets")?,
        linkage: required_lock(builder.linkage, "llvm.linkage")?,
        inkwell_version: required_lock(builder.inkwell_version, "inkwell.version")?,
        inkwell_llvm_feature: required_lock(builder.inkwell_llvm_feature, "inkwell.llvm_feature")?,
        inkwell_target_features: required_lock(
            builder.inkwell_target_features,
            "inkwell.target_features",
        )?,
    };
    validate_lock(&lock)?;
    if encode_lock(&lock) != bytes {
        return Err(LockError::NonCanonical);
    }
    Ok(lock)
}

fn validate_lock(lock: &LlvmLock) -> Result<(), LockError> {
    if lock.schema != LOCK_SCHEMA {
        return Err(LockError::InvalidValue("schema"));
    }
    if !valid_version(&lock.version) {
        return Err(LockError::InvalidValue("llvm.version"));
    }
    let expected_tag = format!("llvmorg-{}", lock.version);
    if lock.tag != expected_tag {
        return Err(LockError::InvalidValue("llvm.tag"));
    }
    if lock.commit.len() != 40
        || !lock
            .commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(LockError::InvalidValue("llvm.commit"));
    }
    let expected_source = format!(
        "https://github.com/llvm/llvm-project/releases/download/{}/llvm-project-{}.src.tar.xz",
        lock.tag, lock.version
    );
    if lock.source != expected_source {
        return Err(LockError::InvalidValue("llvm.source"));
    }
    if !valid_sha256(&lock.sha256) {
        return Err(LockError::InvalidValue("llvm.sha256"));
    }
    if !(1..=MAX_ARCHIVE_COMPRESSED_BYTES).contains(&lock.archive_bytes) {
        return Err(LockError::InvalidValue("llvm.bytes"));
    }
    if lock.projects != ["lld"] {
        return Err(LockError::InvalidValue("llvm.projects"));
    }
    if lock.targets != ["AArch64"] {
        return Err(LockError::InvalidValue("llvm.targets"));
    }
    if lock.linkage != "static" {
        return Err(LockError::InvalidValue("llvm.linkage"));
    }
    if lock.inkwell_version != "0.9.0" {
        return Err(LockError::InvalidValue("inkwell.version"));
    }
    if lock.inkwell_llvm_feature != "llvm22-1-force-static" {
        return Err(LockError::InvalidValue("inkwell.llvm_feature"));
    }
    if lock.inkwell_target_features != ["target-aarch64"] {
        return Err(LockError::InvalidValue("inkwell.target_features"));
    }
    Ok(())
}

fn encode_lock(lock: &LlvmLock) -> Vec<u8> {
    format!(
        "schema = {}\n\n[llvm]\nversion = \"{}\"\ntag = \"{}\"\ncommit = \"{}\"\nsource = \"{}\"\nsha256 = \"{}\"\nbytes = {}\nprojects = {}\ntargets = {}\nlinkage = \"{}\"\n\n[inkwell]\nversion = \"{}\"\nllvm_feature = \"{}\"\ntarget_features = {}\n",
        lock.schema,
        lock.version,
        lock.tag,
        lock.commit,
        lock.source,
        lock.sha256,
        lock.archive_bytes,
        encode_string_array(&lock.projects),
        encode_string_array(&lock.targets),
        lock.linkage,
        lock.inkwell_version,
        lock.inkwell_llvm_feature,
        encode_string_array(&lock.inkwell_target_features),
    )
    .into_bytes()
}

fn load_expected_output(root: &Path) -> Result<Option<ExpectedOutput>, String> {
    let path = root.join("toolchain/llvm.outputs.toml");
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "cannot inspect trusted LLVM output lock {}: {error}",
            path.display()
        )),
        Ok(metadata)
            if metadata.is_file()
                && !metadata.file_type().is_symlink()
                && metadata.len() <= 64 * 1024 =>
        {
            decode_expected_output(&read_bounded_regular_file(&path, 64 * 1024)?).map(Some)
        }
        Ok(_) => Err(format!(
            "trusted LLVM output lock {} is not a bounded regular non-symlink file",
            path.display()
        )),
    }
}

fn decode_expected_output(bytes: &[u8]) -> Result<ExpectedOutput, String> {
    let source = std::str::from_utf8(bytes)
        .map_err(|_| "trusted LLVM output lock is not UTF-8".to_owned())?;
    if !source.ends_with('\n') || source.contains('\r') || source.contains('\0') {
        return Err("trusted LLVM output lock has noncanonical text encoding".to_owned());
    }
    let mut fields = BTreeMap::new();
    for (index, line) in source.lines().enumerate() {
        let (key, value) = line.split_once(" = ").ok_or_else(|| {
            format!(
                "malformed trusted LLVM output assignment on line {}",
                index + 1
            )
        })?;
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            || value.is_empty()
            || fields.insert(key, value).is_some()
        {
            return Err(format!(
                "invalid or duplicate trusted LLVM output field on line {}",
                index + 1
            ));
        }
    }
    let schema_source = take_output_field(&mut fields, "schema")?;
    let schema = schema_source
        .parse::<u32>()
        .map_err(|_| "trusted LLVM output schema is not decimal".to_owned())?;
    if schema != OUTPUT_LOCK_SCHEMA || schema.to_string() != schema_source {
        return Err(format!(
            "unsupported trusted LLVM output schema {schema_source}"
        ));
    }
    let output = ExpectedOutput {
        input_digest: parse_output_string(&mut fields, "input_sha256")?,
        llvm_version: parse_output_string(&mut fields, "llvm_version")?,
        host: parse_output_string(&mut fields, "host")?,
        prefix_tree_sha256: parse_output_string(&mut fields, "prefix_tree_sha256")?,
        prefix_files: parse_output_u64(&mut fields, "prefix_files")?,
        prefix_bytes: parse_output_u64(&mut fields, "prefix_bytes")?,
    };
    if !fields.is_empty() {
        return Err(format!(
            "unknown trusted LLVM output fields: {:?}",
            fields.keys().collect::<Vec<_>>()
        ));
    }
    if !valid_sha256(&output.input_digest)
        || !valid_sha256(&output.prefix_tree_sha256)
        || !valid_version(&output.llvm_version)
        || output.host.is_empty()
        || !output
            .host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || !(1..=MAX_PREFIX_FILES).contains(&output.prefix_files)
        || !(1..=MAX_PREFIX_BYTES).contains(&output.prefix_bytes)
    {
        return Err("trusted LLVM output lock contains an invalid value".to_owned());
    }
    if encode_expected_output(&output) != bytes {
        return Err("trusted LLVM output lock is not canonical".to_owned());
    }
    Ok(output)
}

fn take_output_field<'a>(
    fields: &mut BTreeMap<&'a str, &'a str>,
    key: &str,
) -> Result<&'a str, String> {
    fields
        .remove(key)
        .ok_or_else(|| format!("trusted LLVM output lock is missing {key}"))
}

fn parse_output_string<'a>(
    fields: &mut BTreeMap<&'a str, &'a str>,
    key: &str,
) -> Result<String, String> {
    parse_lock_string(take_output_field(fields, key)?, 0)
        .map_err(|_| format!("trusted LLVM output field {key} is not a canonical string"))
}

fn parse_output_u64<'a>(fields: &mut BTreeMap<&'a str, &'a str>, key: &str) -> Result<u64, String> {
    let source = take_output_field(fields, key)?;
    let value = source
        .parse::<u64>()
        .map_err(|_| format!("trusted LLVM output field {key} is not decimal"))?;
    if value.to_string() != source {
        return Err(format!(
            "trusted LLVM output field {key} is not canonical decimal"
        ));
    }
    Ok(value)
}

fn encode_expected_output(output: &ExpectedOutput) -> Vec<u8> {
    format!(
        "schema = {OUTPUT_LOCK_SCHEMA}\ninput_sha256 = \"{}\"\nllvm_version = \"{}\"\nhost = \"{}\"\nprefix_tree_sha256 = \"{}\"\nprefix_files = {}\nprefix_bytes = {}\n",
        output.input_digest,
        output.llvm_version,
        output.host,
        output.prefix_tree_sha256,
        output.prefix_files,
        output.prefix_bytes,
    )
    .into_bytes()
}

fn validate_expected_output_inputs(
    output: &ExpectedOutput,
    input_digest: &str,
    llvm_version: &str,
    host: &str,
) -> Result<(), String> {
    if output.input_digest != input_digest
        || output.llvm_version != llvm_version
        || output.host != host
    {
        return Err(
            "toolchain/llvm.outputs.toml does not match the exact current bootstrap inputs; remove and regenerate it only through intentional maintainer review"
                .to_owned(),
        );
    }
    Ok(())
}

fn expected_output_for_measurement(
    plan: &BuildPlan,
    measurement: &TreeMeasurement,
) -> ExpectedOutput {
    ExpectedOutput {
        input_digest: plan.input_digest.clone(),
        llvm_version: plan.lock.version.clone(),
        host: plan.host.clone(),
        prefix_tree_sha256: measurement.digest.clone(),
        prefix_files: measurement.files,
        prefix_bytes: measurement.bytes,
    }
}

fn validate_expected_measurement(
    expected: &ExpectedOutput,
    measurement: &TreeMeasurement,
) -> Result<(), String> {
    if measurement.digest != expected.prefix_tree_sha256
        || measurement.files != expected.prefix_files
        || measurement.bytes != expected.prefix_bytes
    {
        return Err(format!(
            "LLVM prefix tree does not match trusted toolchain/llvm.outputs.toml: expected {} files / {} bytes / {}, observed {} files / {} bytes / {}",
            expected.prefix_files,
            expected.prefix_bytes,
            expected.prefix_tree_sha256,
            measurement.files,
            measurement.bytes,
            measurement.digest,
        ));
    }
    Ok(())
}

fn record_expected_output(root: &Path, output: &ExpectedOutput) -> Result<(), String> {
    ensure_non_symlink_directory_chain(root, Path::new("toolchain"))?;
    let path = root.join("toolchain/llvm.outputs.toml");
    write_new_file(&path, &encode_expected_output(output))?;
    sync_directory(
        path.parent()
            .ok_or_else(|| "trusted LLVM output lock has no parent".to_owned())?,
    )?;
    let observed = load_expected_output(root)?
        .ok_or_else(|| "new trusted LLVM output lock disappeared".to_owned())?;
    if &observed != output {
        return Err("new trusted LLVM output lock failed exact revalidation".to_owned());
    }
    Ok(())
}

fn revalidate_expected_output(root: &Path, plan: &BuildPlan) -> Result<(), String> {
    if load_expected_output(root)? != plan.expected_output {
        return Err("trusted LLVM output lock changed during native bootstrap".to_owned());
    }
    Ok(())
}

fn encode_string_array(values: &[String]) -> String {
    let mut output = String::from("[");
    for (index, value) in values.iter().enumerate() {
        if index != 0 {
            output.push_str(", ");
        }
        output.push('"');
        output.push_str(value);
        output.push('"');
    }
    output.push(']');
    output
}

fn set_lock_field<T>(slot: &mut Option<T>, path: &str, value: T) -> Result<(), LockError> {
    if slot.is_some() {
        Err(LockError::DuplicateField(path.to_owned()))
    } else {
        *slot = Some(value);
        Ok(())
    }
}

fn required_lock<T>(slot: Option<T>, path: &'static str) -> Result<T, LockError> {
    slot.ok_or(LockError::MissingField(path))
}

fn parse_lock_u32(value: &str, line: usize) -> Result<u32, LockError> {
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return Err(LockError::Malformed {
            line,
            reason: "invalid unsigned integer",
        });
    }
    value.parse::<u32>().map_err(|_| LockError::Malformed {
        line,
        reason: "invalid unsigned integer",
    })
}

fn parse_lock_u64(value: &str, line: usize) -> Result<u64, LockError> {
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return Err(LockError::Malformed {
            line,
            reason: "invalid unsigned integer",
        });
    }
    value.parse::<u64>().map_err(|_| LockError::Malformed {
        line,
        reason: "invalid unsigned integer",
    })
}

fn parse_lock_string(value: &str, line: usize) -> Result<String, LockError> {
    let inner = value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .ok_or(LockError::Malformed {
            line,
            reason: "expected a quoted string",
        })?;
    if inner.is_empty()
        || inner
            .chars()
            .any(|character| character.is_control() || matches!(character, '"' | '\\'))
    {
        return Err(LockError::Malformed {
            line,
            reason: "invalid canonical string",
        });
    }
    Ok(inner.to_owned())
}

fn parse_lock_array(value: &str, line: usize) -> Result<Vec<String>, LockError> {
    let inner = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .ok_or(LockError::Malformed {
            line,
            reason: "expected a string array",
        })?;
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    let mut values = Vec::new();
    for item in inner.split(", ") {
        values.push(parse_lock_string(item, line)?);
    }
    Ok(values)
}

fn valid_version(value: &str) -> bool {
    let mut components = value.split('.');
    let valid = components.by_ref().take(3).all(|component| {
        !component.is_empty()
            && (component == "0" || !component.starts_with('0'))
            && component.bytes().all(|byte| byte.is_ascii_digit())
    });
    valid && components.next().is_none() && value.matches('.').count() == 2
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        && value.bytes().any(|byte| byte != b'0')
}

fn load_plan(root: &Path, jobs: u32) -> Result<BuildPlan, String> {
    let lock_path = root.join("toolchain/llvm.lock.toml");
    let lock_bytes = read_bounded_regular_file(&lock_path, 64 * 1024)?;
    let lock = decode_lock(&lock_bytes).map_err(|error| error.to_string())?;
    let (codegen_binding_digest, rust_binding_digest) = validate_inkwell_dependency(root, &lock)?;
    let cmake_contract = root.join("toolchain/cmake/WrelaLLVM.cmake");
    let cmake_bytes = read_bounded_regular_file(&cmake_contract, 1024 * 1024)?;
    validate_cmake_contract(&cmake_bytes, &lock)?;
    let tools = NativeTools::discover()?;
    let host = canonical_host_triple()?;
    let lock_digest = sha256_bytes(&lock_bytes);
    let cmake_digest = sha256_bytes(&cmake_bytes);
    let flags_digest = normalized_flags_digest(&lock);
    let bootstrap_executable = identify_current_executable()?;
    let implementation_digest = bootstrap_implementation_digest(root)?;
    let input_digest = build_input_digest(
        &lock,
        &lock_digest,
        &cmake_digest,
        &codegen_binding_digest,
        &rust_binding_digest,
        &flags_digest,
        &implementation_digest,
        &host,
        &tools,
    );
    let key = format!("{}-{input_digest}", lock.version);
    let bundle = root.join("build/toolchain/llvm/prefixes").join(&key);
    let prefix = bundle.join("prefix");
    let expected_output = load_expected_output(root)?;
    if let Some(expected) = &expected_output {
        validate_expected_output_inputs(expected, &input_digest, &lock.version, &host)?;
    }
    Ok(BuildPlan {
        workspace_root: root.to_owned(),
        lock,
        lock_digest,
        cmake_contract,
        cmake_bytes,
        cmake_digest,
        codegen_binding_digest,
        rust_binding_digest,
        flags_digest,
        implementation_digest,
        bootstrap_executable,
        host,
        input_digest,
        key,
        bundle,
        prefix,
        expected_output,
        license_notices: reviewed_license_notices(),
        tools,
        jobs,
    })
}

fn revalidate_plan_inputs(root: &Path, plan: &BuildPlan) -> Result<(), String> {
    let lock_bytes = read_bounded_regular_file(&root.join("toolchain/llvm.lock.toml"), 64 * 1024)?;
    if sha256_bytes(&lock_bytes) != plan.lock_digest
        || decode_lock(&lock_bytes).map_err(|error| error.to_string())? != plan.lock
    {
        return Err("LLVM lock changed during native bootstrap".to_owned());
    }
    let cmake_bytes =
        read_bounded_regular_file(&root.join("toolchain/cmake/WrelaLLVM.cmake"), 1024 * 1024)?;
    validate_cmake_contract(&cmake_bytes, &plan.lock)?;
    if sha256_bytes(&cmake_bytes) != plan.cmake_digest {
        return Err("LLVM CMake contract changed during native bootstrap".to_owned());
    }
    let (codegen_binding, rust_binding) = validate_inkwell_dependency(root, &plan.lock)?;
    if codegen_binding != plan.codegen_binding_digest || rust_binding != plan.rust_binding_digest {
        return Err("LLVM Rust binding contract changed during native bootstrap".to_owned());
    }
    let bootstrap_executable = identify_current_executable()?;
    if bootstrap_executable != plan.bootstrap_executable
        || bootstrap_implementation_digest(root)? != plan.implementation_digest
    {
        return Err("LLVM bootstrap implementation changed during native build".to_owned());
    }
    Ok(())
}

fn canonical_host_triple() -> Result<String, String> {
    match (env::consts::ARCH, env::consts::OS) {
        ("aarch64", "macos") => Ok("arm64-apple-darwin".to_owned()),
        ("x86_64", "macos") => Ok("x86_64-apple-darwin".to_owned()),
        ("aarch64", "linux") => Ok("aarch64-unknown-linux-gnu".to_owned()),
        ("x86_64", "linux") => Ok("x86_64-unknown-linux-gnu".to_owned()),
        (architecture, operating_system) => Err(format!(
            "unsupported LLVM bootstrap host {architecture}-{operating_system}"
        )),
    }
}

fn validate_inkwell_dependency(root: &Path, lock: &LlvmLock) -> Result<(String, String), String> {
    let manifest_path = root.join("crates/wrela-codegen-llvm/Cargo.toml");
    let manifest = read_bounded_regular_file(&manifest_path, 1024 * 1024)?;
    let codegen_binding_digest = validate_codegen_manifest(&manifest, lock)?;

    let cargo_lock_path = root.join("Cargo.lock");
    let cargo_lock = read_bounded_regular_file(&cargo_lock_path, 16 * 1024 * 1024)?;
    let rust_binding_digest = validate_resolved_inkwell_lock(&cargo_lock, lock)?;

    Ok((codegen_binding_digest, rust_binding_digest))
}

fn validate_codegen_manifest(bytes: &[u8], lock: &LlvmLock) -> Result<String, String> {
    let source = std::str::from_utf8(bytes)
        .map_err(|_| "wrela-codegen-llvm Cargo.toml is not UTF-8".to_owned())?;
    if !source.ends_with('\n') || source.contains('\r') || source.contains('\0') {
        return Err("wrela-codegen-llvm Cargo.toml has noncanonical text encoding".to_owned());
    }

    let mut section = "";
    let mut dependency_section_seen = false;
    let mut package_name = None;
    let mut default_feature = None;
    let mut llvm_feature = None;
    let mut dependency = BTreeMap::new();
    for (index, raw_line) in source.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            if !line.ends_with(']') || line.contains('#') {
                return Err(format!(
                    "malformed wrela-codegen-llvm Cargo.toml section on line {line_number}"
                ));
            }
            section = line;
            if section == "[dependencies.inkwell]" {
                if dependency_section_seen {
                    return Err("duplicate [dependencies.inkwell] section".to_owned());
                }
                dependency_section_seen = true;
            } else if section.ends_with("dependencies.inkwell]") {
                return Err(
                    "Inkwell must be an unconditional normal dependency, not dev/build/target-only"
                        .to_owned(),
                );
            }
            continue;
        }
        let Some((key, value)) = line.split_once(" = ") else {
            if matches!(
                section,
                "[package]" | "[features]" | "[dependencies.inkwell]"
            ) {
                return Err(format!(
                    "noncanonical wrela-codegen-llvm Cargo.toml assignment on line {line_number}"
                ));
            }
            continue;
        };
        if key.trim() != key || value.trim() != value || key.is_empty() || value.is_empty() {
            return Err(format!(
                "noncanonical wrela-codegen-llvm Cargo.toml assignment on line {line_number}"
            ));
        }
        if section.contains("dependencies")
            && (key == "package"
                || key.ends_with(".package")
                || key.contains("\"package\"")
                || key.contains("'package'")
                || key.contains('\\')
                || manifest_inline_table_contains_package_key(value))
        {
            return Err(
                "renamed Cargo dependencies are forbidden in the reviewed codegen manifest"
                    .to_owned(),
            );
        }
        if section.contains("dependencies") && key == "inkwell" {
            return Err(
                "Inkwell must appear only in the reviewed [dependencies.inkwell] table".to_owned(),
            );
        }
        match (section, key) {
            ("[package]", "name") => {
                set_manifest_value(
                    &mut package_name,
                    parse_manifest_string(value, line_number)?,
                    "package.name",
                )?;
            }
            ("[features]", "llvm") => {
                set_manifest_value(
                    &mut llvm_feature,
                    parse_manifest_array(value, line_number)?,
                    "features.llvm",
                )?;
            }
            ("[features]", "default") => {
                set_manifest_value(
                    &mut default_feature,
                    parse_manifest_array(value, line_number)?,
                    "features.default",
                )?;
            }
            ("[dependencies.inkwell]", key) => {
                if !matches!(
                    key,
                    "version" | "optional" | "default-features" | "features"
                ) {
                    return Err(format!("unknown Inkwell dependency field {key:?}"));
                }
                if dependency.insert(key, value).is_some() {
                    return Err(format!("duplicate Inkwell dependency field {key:?}"));
                }
            }
            _ => {}
        }
    }

    if package_name.as_deref() != Some("wrela-codegen-llvm") {
        return Err("codegen manifest package name is not wrela-codegen-llvm".to_owned());
    }
    if default_feature != Some(Vec::new()) {
        return Err("wrela-codegen-llvm default feature set must remain empty".to_owned());
    }
    if llvm_feature != Some(vec!["dep:inkwell".to_owned()]) {
        return Err("feature llvm must forward exactly dep:inkwell".to_owned());
    }
    if !dependency_section_seen || dependency.len() != 4 {
        return Err("Inkwell dependency table is incomplete".to_owned());
    }
    let expected_version = format!("={}", lock.inkwell_version);
    let version = parse_manifest_string(
        dependency
            .get("version")
            .ok_or_else(|| "Inkwell dependency omits version".to_owned())?,
        0,
    )?;
    if version != expected_version {
        return Err(format!(
            "LLVM lock Inkwell {} disagrees with Cargo requirement {version}",
            lock.inkwell_version
        ));
    }
    if dependency.get("optional") != Some(&"true")
        || dependency.get("default-features") != Some(&"false")
    {
        return Err("Inkwell must remain optional with default features disabled".to_owned());
    }
    let actual = parse_manifest_array(
        dependency
            .get("features")
            .ok_or_else(|| "Inkwell dependency omits features".to_owned())?,
        0,
    )?;
    let mut expected = vec![lock.inkwell_llvm_feature.clone()];
    expected.extend(lock.inkwell_target_features.iter().cloned());
    if actual != expected {
        return Err(format!(
            "LLVM lock Inkwell features {expected:?} disagree with Cargo {actual:?}"
        ));
    }
    let mut identity = b"WRELCGB\0\x01\x00\x00\x00".to_vec();
    for value in [
        "wrela-codegen-llvm",
        "dependencies.inkwell",
        "features.default=[]",
        "features.llvm=[dep:inkwell]",
        version.as_str(),
        "optional=true",
        "default-features=false",
    ] {
        append_length_prefixed(&mut identity, value.as_bytes());
    }
    for feature in actual {
        append_length_prefixed(&mut identity, feature.as_bytes());
    }
    Ok(sha256_bytes(&identity))
}

fn manifest_inline_table_contains_package_key(value: &str) -> bool {
    if value.contains("\"package\"") || value.contains("'package'") {
        return true;
    }
    value.match_indices("package").any(|(index, _)| {
        let before = value[..index].bytes().next_back();
        let after = value[index + "package".len()..].trim_start();
        matches!(
            before,
            None | Some(b'{') | Some(b',') | Some(b' ') | Some(b'\t')
        ) && after.starts_with('=')
    })
}

fn set_manifest_value<T>(slot: &mut Option<T>, value: T, label: &str) -> Result<(), String> {
    if slot.replace(value).is_some() {
        Err(format!("duplicate codegen manifest field {label}"))
    } else {
        Ok(())
    }
}

fn parse_manifest_string(value: &str, line: usize) -> Result<String, String> {
    parse_lock_string(value, line)
        .map_err(|_| format!("invalid canonical Cargo string on line {line}"))
}

fn parse_manifest_array(value: &str, line: usize) -> Result<Vec<String>, String> {
    parse_lock_array(value, line)
        .map_err(|_| format!("invalid canonical Cargo string array on line {line}"))
}

#[derive(Clone, Debug, Default)]
struct CargoPackageBlock {
    name: Option<String>,
    version: Option<String>,
    source: Option<String>,
    checksum: Option<String>,
    dependencies: BTreeSet<String>,
}

fn validate_resolved_inkwell_lock(bytes: &[u8], lock: &LlvmLock) -> Result<String, String> {
    let packages = parse_cargo_lock_packages(bytes)?;
    let codegen = unique_package(&packages, "wrela-codegen-llvm", None)?;
    if codegen.source.is_some() || codegen.checksum.is_some() {
        return Err("Cargo.lock codegen package must remain a workspace package".to_owned());
    }
    let inkwell = unique_package(&packages, "inkwell", Some(&lock.inkwell_version))?;
    validate_registry_package(inkwell, "Inkwell")?;
    if !dependency_resolves_to(&codegen.dependencies, inkwell, &packages)? {
        return Err("Cargo.lock disconnects wrela-codegen-llvm from pinned Inkwell".to_owned());
    }

    let llvm_sys = uniquely_resolved_dependency(&inkwell.dependencies, "llvm-sys", &packages)?;
    validate_registry_package(llvm_sys, "llvm-sys")?;
    let expected_series = llvm_sys_series(lock)?;
    let actual_version = llvm_sys
        .version
        .as_deref()
        .ok_or_else(|| "Cargo.lock llvm-sys package omits version".to_owned())?;
    if actual_version.split('.').next() != Some(expected_series.as_str()) {
        return Err(format!(
            "Cargo.lock llvm-sys version {actual_version} is outside LLVM {}.{} series {expected_series}",
            lock.version.split('.').next().unwrap_or("?"),
            lock.version.split('.').nth(1).unwrap_or("?")
        ));
    }

    let mut identity = b"WRELRBR\0\x01\x00\x00\x00".to_vec();
    for value in [
        "wrela-codegen-llvm->inkwell",
        inkwell
            .version
            .as_deref()
            .ok_or_else(|| "Cargo.lock Inkwell package omits version".to_owned())?,
        inkwell
            .source
            .as_deref()
            .ok_or_else(|| "Cargo.lock Inkwell package omits source".to_owned())?,
        inkwell
            .checksum
            .as_deref()
            .ok_or_else(|| "Cargo.lock Inkwell package omits checksum".to_owned())?,
        "inkwell->llvm-sys",
        actual_version,
        llvm_sys
            .source
            .as_deref()
            .ok_or_else(|| "Cargo.lock llvm-sys package omits source".to_owned())?,
        llvm_sys
            .checksum
            .as_deref()
            .ok_or_else(|| "Cargo.lock llvm-sys package omits checksum".to_owned())?,
    ] {
        append_length_prefixed(&mut identity, value.as_bytes());
    }
    Ok(sha256_bytes(&identity))
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
    let header_values: Vec<_> = header
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    if header_values != ["version = 4"] {
        return Err("Cargo.lock must use generated lock format version 4".to_owned());
    }

    let mut packages = Vec::new();
    for chunk in chunks {
        let package = parse_cargo_package_block(chunk)?;
        if packages.len() >= MAX_RUST_LOCK_PACKAGES {
            return Err(format!(
                "Cargo.lock exceeds {MAX_RUST_LOCK_PACKAGES} package blocks"
            ));
        }
        packages
            .try_reserve(1)
            .map_err(|_| "cannot reserve bounded Cargo.lock package inventory".to_owned())?;
        packages.push(package);
    }

    Ok(packages)
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
        || !package.checksum.as_deref().is_some_and(valid_sha256)
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
    let mut matches = 0_u8;
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

fn llvm_sys_series(lock: &LlvmLock) -> Result<String, String> {
    let mut components = lock.version.split('.');
    let major = components
        .next()
        .ok_or_else(|| "LLVM lock version omits major".to_owned())?;
    let minor = components
        .next()
        .ok_or_else(|| "LLVM lock version omits minor".to_owned())?;
    Ok(format!("{major}{minor}"))
}

fn bootstrap_implementation_digest(root: &Path) -> Result<String, String> {
    let runtime_llvm = read_bounded_regular_file(&root.join("xtask/src/llvm.rs"), 8 * 1024 * 1024)?;
    let runtime_main = read_bounded_regular_file(&root.join("xtask/src/main.rs"), 4 * 1024 * 1024)?;
    let runtime_manifest = read_bounded_regular_file(&root.join("xtask/Cargo.toml"), 1024 * 1024)?;
    let runtime_lock = read_bounded_regular_file(&root.join("Cargo.lock"), 16 * 1024 * 1024)?;
    bootstrap_implementation_digest_from_sources(
        BootstrapSources {
            llvm: &runtime_llvm,
            main: &runtime_main,
            manifest: &runtime_manifest,
            cargo_lock: &runtime_lock,
        },
        BootstrapSources {
            llvm: include_bytes!("llvm.rs"),
            main: include_bytes!("main.rs"),
            manifest: include_bytes!("../Cargo.toml"),
            cargo_lock: include_bytes!("../../Cargo.lock"),
        },
    )
}

fn bootstrap_implementation_digest_from_sources(
    runtime: BootstrapSources<'_>,
    compiled: BootstrapSources<'_>,
) -> Result<String, String> {
    let runtime = bootstrap_implementation_projection(runtime)?;
    let compiled = bootstrap_implementation_projection(compiled)?;
    for (label, runtime_digest, compiled_digest) in [
        (
            "xtask/src/llvm.rs",
            &runtime.llvm_source_digest,
            &compiled.llvm_source_digest,
        ),
        (
            "the LLVM dispatch contract in xtask/src/main.rs",
            &runtime.dispatch_digest,
            &compiled.dispatch_digest,
        ),
        (
            "the LLVM dependency declaration in xtask/Cargo.toml",
            &runtime.manifest_digest,
            &compiled.manifest_digest,
        ),
        (
            "the LLVM bootstrap dependency closure in Cargo.lock",
            &runtime.dependency_closure_digest,
            &compiled.dependency_closure_digest,
        ),
    ] {
        if runtime_digest != compiled_digest {
            return Err(format!(
                "running xtask is stale relative to {label}; rebuild it before LLVM bootstrap"
            ));
        }
    }
    Ok(compiled.digest())
}

fn bootstrap_implementation_projection(
    sources: BootstrapSources<'_>,
) -> Result<BootstrapImplementationProjection, String> {
    Ok(BootstrapImplementationProjection {
        llvm_source_digest: distribution_partitioned_llvm_source_digest(sources.llvm)?,
        dispatch_digest: llvm_dispatch_contract_digest(sources.main)?,
        manifest_digest: validate_xtask_manifest(sources.manifest)?,
        dependency_closure_digest: xtask_bootstrap_dependency_digest(sources.cargo_lock)?,
    })
}

impl BootstrapImplementationProjection {
    fn digest(&self) -> String {
        let mut identity = b"WRELIMP\0\x04\x00\x00\x00".to_vec();
        for (label, digest) in [
            ("llvm-source", self.llvm_source_digest.as_str()),
            ("llvm-dispatch", self.dispatch_digest.as_str()),
            ("xtask-manifest", self.manifest_digest.as_str()),
            (
                "bootstrap-dependency-closure",
                self.dependency_closure_digest.as_str(),
            ),
        ] {
            append_length_prefixed(&mut identity, label.as_bytes());
            append_length_prefixed(&mut identity, digest.as_bytes());
        }
        sha256_bytes(&identity)
    }
}

fn llvm_dispatch_contract_digest(bytes: &[u8]) -> Result<String, String> {
    let source =
        std::str::from_utf8(bytes).map_err(|_| "xtask/src/main.rs is not UTF-8".to_owned())?;
    if !source.ends_with('\n') || source.contains('\r') || source.contains('\0') {
        return Err("xtask/src/main.rs has noncanonical text encoding".to_owned());
    }
    const MODULE: &str = "mod llvm;";
    const MAIN_PRELUDE: &str = "fn main() -> ExitCode {\n    let mut arguments = env::args().skip(1);\n    match arguments.next().as_deref() {";
    const ARM_START: &str = "        Some(\"llvm\") => {\n";
    const NEXT_ARM: &str = "\n        Some(";
    const ROOT_START: &str = "fn workspace_root() -> Result<PathBuf, String> {\n";
    const NEXT_FUNCTION: &str = "\n}\n\nfn ";

    let module_offset = unique_line_offset(source, MODULE, "LLVM module declaration")?;
    reject_outer_attribute(source, module_offset, "LLVM module declaration")?;
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
    let arm_start = unique_fragment_offset(source, ARM_START, "LLVM command dispatch arm")?;
    let arm_tail = source
        .get(arm_start + ARM_START.len()..)
        .ok_or_else(|| "LLVM command dispatch arm offset escaped source".to_owned())?;
    let arm_end = arm_tail
        .find(NEXT_ARM)
        .ok_or_else(|| "LLVM command dispatch arm has no following command arm".to_owned())?;
    let arm = source
        .get(arm_start..arm_start + ARM_START.len() + arm_end)
        .ok_or_else(|| "LLVM command dispatch arm escaped source".to_owned())?;
    if !arm.ends_with("        }") {
        return Err("LLVM command dispatch arm is not a canonical braced arm".to_owned());
    }

    let root_start = unique_fragment_offset(source, ROOT_START, "workspace-root resolver")?;
    reject_outer_attribute(source, root_start, "workspace-root resolver")?;
    let root_tail = source
        .get(root_start..)
        .ok_or_else(|| "workspace-root resolver offset escaped source".to_owned())?;
    let root_end = root_tail
        .find(NEXT_FUNCTION)
        .ok_or_else(|| "workspace-root resolver has no canonical function boundary".to_owned())?
        + 2;
    let root = root_tail
        .get(..root_end)
        .ok_or_else(|| "workspace-root resolver escaped source".to_owned())?;

    let mut identity = b"WRELDSP\0\x01\x00\x00\x00".to_vec();
    for (label, fragment) in [
        ("module", MODULE),
        ("environment-binding", "std::env"),
        ("path-binding", "std::path::Path"),
        ("path-buffer-binding", "std::path::PathBuf"),
        ("exit-code-binding", "std::process::ExitCode"),
        ("main-prelude", MAIN_PRELUDE),
        ("llvm-arm", arm),
        ("workspace-root", root),
    ] {
        append_length_prefixed(&mut identity, label.as_bytes());
        append_length_prefixed(&mut identity, fragment.as_bytes());
    }
    Ok(sha256_bytes(&identity))
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
    let mut imports = 0_usize;
    for line in source.lines().map(str::trim) {
        if line == direct {
            imports += 1;
            continue;
        }
        let Some(items) = line
            .strip_prefix(&group_prefix)
            .and_then(|items| items.strip_suffix("};"))
        else {
            continue;
        };
        imports += items
            .split(", ")
            .filter(|candidate| *candidate == item)
            .count();
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

fn xtask_bootstrap_dependency_digest(bytes: &[u8]) -> Result<String, String> {
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

    let mut identity = b"WRELDEP\0\x01\x00\x00\x00".to_vec();
    append_length_prefixed(&mut identity, b"xtask-direct-sha2");
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
    for (key, index) in closure {
        append_length_prefixed(&mut identity, key.as_bytes());
        let package = packages
            .get(index)
            .ok_or_else(|| "xtask dependency closure index escaped package list".to_owned())?;
        let checksum = package
            .checksum
            .as_deref()
            .ok_or_else(|| "xtask bootstrap dependency omits checksum".to_owned())?;
        append_length_prefixed(&mut identity, checksum.as_bytes());
        let mut dependencies = BTreeSet::new();
        for dependency in &package.dependencies {
            let name = dependency
                .split(' ')
                .next()
                .ok_or_else(|| "Cargo.lock contains an empty dependency reference".to_owned())?;
            let target = uniquely_resolved_dependency(&package.dependencies, name, &packages)?;
            dependencies.insert(cargo_package_identity(target)?);
        }
        for dependency in dependencies {
            append_length_prefixed(&mut identity, dependency.as_bytes());
        }
    }
    Ok(sha256_bytes(&identity))
}

fn identify_current_executable() -> Result<ToolIdentity, String> {
    let path = env::current_exe()
        .map_err(|error| format!("cannot resolve running xtask executable: {error}"))?;
    identify_tool(&path).map_err(|error| format!("cannot fingerprint running xtask: {error}"))
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
    let mut identity = b"WRELMAN\0\x01\x00\x00\x00".to_vec();
    append_length_prefixed(&mut identity, EXPECTED.as_bytes());
    Ok(sha256_bytes(&identity))
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
            let dependency = parse_manifest_string(value, 0)?;
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
            set_manifest_value(slot, parse_manifest_string(value, 0)?, label)?;
        }
    }
    if in_dependencies || package.name.is_none() || package.version.is_none() {
        return Err("Cargo.lock contains an incomplete package block".to_owned());
    }
    Ok(package)
}

fn validate_cmake_contract(bytes: &[u8], lock: &LlvmLock) -> Result<(), String> {
    let source = std::str::from_utf8(bytes)
        .map_err(|_| "toolchain/cmake/WrelaLLVM.cmake is not UTF-8".to_owned())?;
    if !source.ends_with('\n') || source.contains('\r') || source.contains('\0') {
        return Err("toolchain/cmake/WrelaLLVM.cmake has noncanonical text encoding".to_owned());
    }
    let actual_digest = sha256_bytes(bytes);
    if actual_digest != REVIEWED_CMAKE_SHA256 {
        return Err(format!(
            "LLVM CMake contract digest {actual_digest} is not the reviewed {REVIEWED_CMAKE_SHA256}"
        ));
    }
    let required = [
        "set(CMAKE_BUILD_TYPE Release CACHE STRING \"\")",
        "set(LLVM_ENABLE_PROJECTS \"lld\" CACHE STRING \"\")",
        "set(LLVM_TARGETS_TO_BUILD \"AArch64\" CACHE STRING \"\")",
        "set(LLVM_STRICT_DISTRIBUTIONS ON CACHE BOOL \"\")",
        "set(LLVM_BUILD_LLVM_DYLIB OFF CACHE BOOL \"\")",
        "set(LLVM_BUILD_TOOLS OFF CACHE BOOL \"\")",
        "set(LLVM_BUILD_UTILS OFF CACHE BOOL \"\")",
        "set(LLVM_INCLUDE_BENCHMARKS OFF CACHE BOOL \"\")",
        "set(LLVM_INCLUDE_EXAMPLES OFF CACHE BOOL \"\")",
        "set(LLVM_INCLUDE_TESTS OFF CACHE BOOL \"\")",
        "set(LLVM_INCLUDE_UTILS OFF CACHE BOOL \"\")",
        "set(LLVM_BUILD_DOCS OFF CACHE BOOL \"\")",
        "set(LLVM_BUILD_EXAMPLES OFF CACHE BOOL \"\")",
        "set(LLVM_BUILD_TESTS OFF CACHE BOOL \"\")",
        "set(LLVM_LINK_LLVM_DYLIB OFF CACHE BOOL \"\")",
        "set(LLD_BUILD_TOOLS OFF CACHE BOOL \"\")",
        "set(LLVM_TOOL_LTO_BUILD OFF CACHE BOOL \"\")",
        "set(LLVM_TOOL_REMARKS_SHLIB_BUILD OFF CACHE BOOL \"\")",
        "set(LLVM_ENABLE_BINDINGS OFF CACHE BOOL \"\")",
        "set(LLVM_ENABLE_LIBEDIT OFF CACHE BOOL \"\")",
        "set(LLVM_ENABLE_LIBPFM OFF CACHE BOOL \"\")",
        "set(BUILD_SHARED_LIBS OFF CACHE BOOL \"\")",
    ];
    for fragment in required {
        if !source.lines().any(|line| line.trim() == fragment) {
            return Err(format!(
                "LLVM CMake contract is missing exact setting {fragment:?}"
            ));
        }
    }
    let components = required_distribution_components();
    let unique: BTreeSet<_> = components.iter().copied().collect();
    if unique.len() != components.len()
        || FORBIDDEN_LLD_STATIC_COMPONENTS
            .iter()
            .any(|component| unique.contains(component))
    {
        return Err("reviewed LLVM distribution component closure is invalid".to_owned());
    }
    let distribution = format!(
        "set(LLVM_DISTRIBUTION_COMPONENTS \"{}\" CACHE STRING \"\")",
        components.join(";")
    );
    if source
        .lines()
        .filter(|line| line.trim() == distribution)
        .count()
        != 1
    {
        return Err(
            "LLVM CMake contract does not select the exact reviewed static distribution closure"
                .to_owned(),
        );
    }
    if lock.projects != ["lld"] || lock.targets != ["AArch64"] || lock.linkage != "static" {
        return Err("LLVM lock cannot be represented by the CMake contract".to_owned());
    }
    Ok(())
}

impl NativeTools {
    fn discover() -> Result<Self, String> {
        if !cfg!(target_os = "macos") {
            return Err(
                "LLVM bootstrap currently supports only macOS hosts with a fully measured Xcode toolchain; Linux requires a pinned explicit sysroot/toolchain closure"
                    .to_owned(),
            );
        }
        let xz = resolve_tool(
            "WRELA_LLVM_XZ",
            &["/usr/bin/xz", "/opt/homebrew/bin/xz", "/usr/local/bin/xz"],
        )?;
        let cmake = resolve_tool(
            "WRELA_LLVM_CMAKE",
            &[
                "/usr/bin/cmake",
                "/opt/homebrew/bin/cmake",
                "/usr/local/bin/cmake",
            ],
        )?;
        let ninja = resolve_tool(
            "WRELA_LLVM_NINJA",
            &[
                "/usr/bin/ninja",
                "/opt/homebrew/bin/ninja",
                "/usr/local/bin/ninja",
            ],
        )?;
        let cc = resolve_apple_tool("WRELA_LLVM_CC", "clang")?;
        let cxx = resolve_apple_tool("WRELA_LLVM_CXX", "clang++")?;
        let ar = resolve_apple_tool("WRELA_LLVM_AR", "ar")?;
        let ranlib = resolve_apple_tool("WRELA_LLVM_RANLIB", "ranlib")?;
        let python = resolve_apple_tool("WRELA_LLVM_PYTHON", "python3")?;
        let linker = resolve_apple_tool("WRELA_LLVM_LINKER", "ld")?;
        let sysroot = resolve_apple_sysroot()?;
        let touch = resolve_tool("WRELA_LLVM_TOUCH", &["/usr/bin/touch", "/bin/touch"])?;
        let shell = identify_tool(Path::new("/bin/sh"))?;
        let host_closure = discover_apple_host_closure(
            &xz, &cmake, &ninja, &cc, &cxx, &ar, &ranlib, &python, &linker, &sysroot,
        )?;
        Ok(Self {
            xz,
            cmake,
            ninja,
            cc,
            cxx,
            ar,
            ranlib,
            python,
            linker,
            sysroot: Some(sysroot),
            touch,
            shell,
            host_closure,
        })
    }
}

fn resolve_apple_tool(variable: &str, tool: &str) -> Result<ToolIdentity, String> {
    let identity = if env::var_os(variable).is_some() {
        resolve_tool(variable, &[])?
    } else {
        identify_tool(&xcrun_path(&["--find", tool])?)?
    };
    if identity.digest == sha256_file(Path::new("/usr/bin/xcrun"))? {
        return Err(format!(
            "{variable} resolved to an Apple xcrun shim rather than the real {tool} executable"
        ));
    }
    Ok(identity)
}

fn resolve_apple_sysroot() -> Result<DirectoryIdentity, String> {
    let selected = if let Some(value) = env::var_os("WRELA_LLVM_SYSROOT") {
        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Err("WRELA_LLVM_SYSROOT must be an absolute path".to_owned());
        }
        path
    } else {
        xcrun_path(&["--sdk", "macosx", "--show-sdk-path"])?
    };
    identify_apple_sysroot(&selected)
}

fn identify_apple_sysroot(selected: &Path) -> Result<DirectoryIdentity, String> {
    let path = fs::canonicalize(selected)
        .map_err(|error| format!("cannot resolve macOS SDK {}: {error}", selected.display()))?;
    let metadata = fs::symlink_metadata(&path)
        .map_err(|error| format!("cannot inspect macOS SDK {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "macOS SDK {} is not a non-symlink directory",
            path.display()
        ));
    }
    let required = [
        "SDKSettings.json",
        "System/Library/CoreServices/SystemVersion.plist",
        "usr/lib/libSystem.tbd",
        "usr/lib/libc++.tbd",
    ];
    let mut identity = b"WRELSDK\0\x01\x00\x00\x00".to_vec();
    append_length_prefixed(&mut identity, utf8_path(&path)?.as_bytes());
    for relative in required {
        let file = fs::canonicalize(path.join(relative)).map_err(|error| {
            format!("cannot resolve required macOS SDK input {relative:?}: {error}")
        })?;
        append_length_prefixed(&mut identity, relative.as_bytes());
        append_length_prefixed(&mut identity, sha256_file(&file)?.as_bytes());
    }
    Ok(DirectoryIdentity {
        path,
        digest: sha256_bytes(&identity),
    })
}

#[allow(clippy::too_many_arguments)]
fn discover_apple_host_closure(
    xz: &ToolIdentity,
    cmake: &ToolIdentity,
    ninja: &ToolIdentity,
    cc: &ToolIdentity,
    cxx: &ToolIdentity,
    ar: &ToolIdentity,
    ranlib: &ToolIdentity,
    python: &ToolIdentity,
    linker: &ToolIdentity,
    sysroot: &DirectoryIdentity,
) -> Result<HostClosureIdentity, String> {
    let cc_target = fs::canonicalize(&cc.path)
        .map_err(|error| format!("cannot resolve C compiler closure path: {error}"))?;
    let toolchain = cc_target
        .ancestors()
        .find(|path| path.extension() == Some(OsStr::new("xctoolchain")))
        .map(Path::to_owned)
        .ok_or_else(|| {
            format!(
                "Apple C compiler {} is not inside an .xctoolchain root",
                cc_target.display()
            )
        })?;
    for (label, tool) in [
        ("C++ compiler", cxx),
        ("archiver", ar),
        ("archive indexer", ranlib),
        ("linker", linker),
    ] {
        let target = fs::canonicalize(&tool.path)
            .map_err(|error| format!("cannot resolve Apple {label}: {error}"))?;
        if !target.starts_with(&toolchain) {
            return Err(format!(
                "Apple {label} {} is outside measured toolchain {}",
                target.display(),
                toolchain.display()
            ));
        }
    }

    let clang_resources = validate_clang_resource_dir(cc, &toolchain)?;
    let cxx_resources = validate_clang_resource_dir(cxx, &toolchain)?;
    if clang_resources != cxx_resources {
        return Err("C and C++ compiler resource directories disagree".to_owned());
    }
    let cmake_root = homebrew_install_root(&cmake.path, "CMake")?;
    let ninja_root = homebrew_install_root(&ninja.path, "Ninja")?;
    let xz_root = homebrew_install_root(&xz.path, "xz")?;
    let python_root = apple_python_runtime_root(&python.path)?;
    if !cmake_root.join("share").is_dir() {
        return Err(format!(
            "measured CMake installation {} omits its share/module tree",
            cmake_root.display()
        ));
    }

    let roots = vec![
        ("macos-sdk".to_owned(), sysroot.path.clone()),
        ("xcode-clang-resources".to_owned(), clang_resources),
        (
            "xcode-toolchain-headers".to_owned(),
            toolchain.join("usr/include"),
        ),
        (
            "xcode-toolchain-info".to_owned(),
            toolchain.join("ToolchainInfo.plist"),
        ),
        (
            "xcode-linker-liblto".to_owned(),
            toolchain.join("usr/lib/libLTO.dylib"),
        ),
        (
            "xcode-linker-libtapi".to_owned(),
            toolchain.join("usr/lib/libtapi.dylib"),
        ),
        (
            "xcode-linker-codedirectory".to_owned(),
            toolchain.join("usr/lib/libcodedirectory.dylib"),
        ),
        (
            "xcode-linker-swift-demangle".to_owned(),
            toolchain.join("usr/lib/libswiftDemangle.dylib"),
        ),
        ("cmake-install".to_owned(), cmake_root),
        ("ninja-install".to_owned(), ninja_root),
        ("xz-install".to_owned(), xz_root),
        ("python-runtime".to_owned(), python_root),
        (
            "macos-version".to_owned(),
            PathBuf::from("/System/Library/CoreServices/SystemVersion.plist"),
        ),
        ("macos-dyld".to_owned(), PathBuf::from("/usr/lib/dyld")),
        ("process-group-kill".to_owned(), PathBuf::from("/bin/kill")),
        ("process-status".to_owned(), PathBuf::from("/bin/ps")),
    ];
    let mut closure = measure_host_closure(&roots)?;
    closure.roots.push(measure_macos_dyld_cache()?);
    finalize_host_closure(closure.roots)
}

fn validate_clang_resource_dir(
    compiler: &ToolIdentity,
    toolchain: &Path,
) -> Result<PathBuf, String> {
    let mut command = Command::new(&compiler.path);
    command
        .args(["--no-default-config", "--print-resource-dir"])
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("TZ", "UTC")
        .stdin(Stdio::null());
    let (status, stdout, stderr) = run_bounded_output(
        &mut command,
        64 * 1024,
        std::time::Duration::from_secs(10),
        "Clang resource-directory probe",
    )?;
    if !status.success() || !stderr.is_empty() {
        return Err(format!(
            "Clang resource-directory probe failed with {status}: {}",
            String::from_utf8_lossy(&stderr)
        ));
    }
    let text = std::str::from_utf8(&stdout)
        .map_err(|_| "Clang resource-directory probe returned non-UTF-8".to_owned())?;
    let resource = PathBuf::from(text.trim_end_matches(['\r', '\n']));
    if !resource.is_absolute() {
        return Err("Clang resource-directory probe returned a non-absolute path".to_owned());
    }
    let resource = fs::canonicalize(&resource).map_err(|error| {
        format!(
            "cannot resolve Clang resource directory {}: {error}",
            resource.display()
        )
    })?;
    if !resource.starts_with(toolchain) {
        return Err(format!(
            "Clang resource directory {} is outside measured toolchain {}",
            resource.display(),
            toolchain.display()
        ));
    }
    Ok(resource)
}

fn homebrew_install_root(tool: &Path, label: &str) -> Result<PathBuf, String> {
    let canonical = fs::canonicalize(tool).map_err(|error| {
        format!(
            "cannot resolve {label} executable {}: {error}",
            tool.display()
        )
    })?;
    for ancestor in canonical.ancestors().skip(1).take(8) {
        let receipt = ancestor.join("INSTALL_RECEIPT.json");
        if let Ok(metadata) = fs::symlink_metadata(&receipt)
            && metadata.is_file()
            && !metadata.file_type().is_symlink()
        {
            return Ok(ancestor.to_owned());
        }
    }
    Err(format!(
        "{label} executable {} is not inside a measurable Homebrew installation root",
        canonical.display()
    ))
}

fn apple_python_runtime_root(python: &Path) -> Result<PathBuf, String> {
    let canonical = fs::canonicalize(python).map_err(|error| {
        format!(
            "cannot resolve Apple Python executable {}: {error}",
            python.display()
        )
    })?;
    canonical
        .ancestors()
        .skip(1)
        .find(|path| path.parent().and_then(Path::file_name) == Some(OsStr::new("Versions")))
        .map(Path::to_owned)
        .ok_or_else(|| {
            format!(
                "Apple Python {} is not inside a versioned framework runtime",
                canonical.display()
            )
        })
}

fn measure_host_closure(roots: &[(String, PathBuf)]) -> Result<HostClosureIdentity, String> {
    if roots.is_empty() || roots.len() > MAX_HOST_CLOSURE_ROOTS {
        return Err(format!(
            "host closure must contain 1..={MAX_HOST_CLOSURE_ROOTS} roots"
        ));
    }
    let mut canonical_roots = Vec::new();
    for (role, selected) in roots {
        if role.is_empty() || !selected.is_absolute() {
            return Err("host closure roles must be nonempty and paths absolute".to_owned());
        }
        let path = fs::canonicalize(selected).map_err(|error| {
            format!(
                "cannot resolve host closure root {role} at {}: {error}",
                selected.display()
            )
        })?;
        canonical_roots.push((role.clone(), path));
    }
    canonical_roots.sort_by(|first, second| first.0.cmp(&second.0));
    for window in canonical_roots.windows(2) {
        if window[0].0 == window[1].0 {
            return Err(format!("duplicate host closure role {}", window[0].0));
        }
    }
    let allowed_paths: Vec<_> = canonical_roots
        .iter()
        .map(|(_, path)| path.clone())
        .collect();
    let mut total_entries = 0_u64;
    let mut total_bytes = 0_u64;
    let mut measured = Vec::new();
    for (role, path) in canonical_roots {
        let before_entries = total_entries;
        let before_bytes = total_bytes;
        let mut hasher = Sha256::new();
        hasher.update(b"WRELHRT\0\x01\x00\x00\x00");
        append_hash_value(&mut hasher, role.as_bytes())?;
        append_hash_value(&mut hasher, utf8_path(&path)?.as_bytes())?;
        hash_host_entry(
            &path,
            &path,
            &allowed_paths,
            &mut hasher,
            &mut total_entries,
            &mut total_bytes,
            0,
        )?;
        measured.push(HostRootIdentity {
            role,
            path,
            digest: lower_hex(&hasher.finalize()),
            entries: total_entries - before_entries,
            bytes: total_bytes - before_bytes,
        });
    }
    finalize_host_closure(measured)
}

fn finalize_host_closure(
    mut measured: Vec<HostRootIdentity>,
) -> Result<HostClosureIdentity, String> {
    measured.sort_by(|first, second| first.role.cmp(&second.role));
    let mut identity = b"WRELHCL\0\x02\x00\x00\x00".to_vec();
    for root in &measured {
        append_length_prefixed(&mut identity, root.role.as_bytes());
        append_length_prefixed(&mut identity, utf8_path(&root.path)?.as_bytes());
        append_length_prefixed(&mut identity, root.digest.as_bytes());
        identity.extend_from_slice(&root.entries.to_le_bytes());
        identity.extend_from_slice(&root.bytes.to_le_bytes());
    }
    Ok(HostClosureIdentity {
        digest: sha256_bytes(&identity),
        roots: measured,
    })
}

fn measure_macos_dyld_cache() -> Result<HostRootIdentity, String> {
    let path = fs::canonicalize("/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld")
        .map_err(|error| format!("cannot resolve macOS dyld cache directory: {error}"))?;
    let prefix = match env::consts::ARCH {
        "aarch64" => "dyld_shared_cache_arm64e",
        "x86_64" => "dyld_shared_cache_x86_64",
        architecture => {
            return Err(format!(
                "unsupported macOS dyld cache architecture {architecture}"
            ));
        }
    };
    let mut entries = Vec::new();
    for entry in fs::read_dir(&path)
        .map_err(|error| format!("cannot read macOS dyld cache directory: {error}"))?
    {
        let entry = entry.map_err(|error| format!("cannot inspect dyld cache entry: {error}"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "macOS dyld cache entry name is not UTF-8".to_owned())?;
        let suffix = name.strip_prefix(prefix);
        let selected = name == prefix
            || suffix.is_some_and(|suffix| {
                suffix == ".atlas"
                    || suffix == ".map"
                    || suffix.strip_prefix('.').is_some_and(|number| {
                        !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
                    })
            });
        if selected {
            entries.push((name, entry.path()));
        }
    }
    entries.sort_by(|first, second| first.0.cmp(&second.0));
    if !entries.iter().any(|(name, _)| name == prefix)
        || !entries.iter().any(|(name, _)| name.ends_with(".atlas"))
        || !entries.iter().any(|(name, _)| name.ends_with(".map"))
    {
        return Err("macOS native dyld cache set is incomplete".to_owned());
    }
    let mut hasher = Sha256::new();
    hasher.update(b"WRELDYC\0\x02\x00\x00\x00");
    append_hash_value(&mut hasher, utf8_path(&path)?.as_bytes())?;
    let mut logical_bytes = 0_u64;
    for (name, entry) in &entries {
        let before = fs::symlink_metadata(entry)
            .map_err(|error| format!("cannot inspect dyld cache {}: {error}", entry.display()))?;
        if before.file_type().is_symlink() || !before.is_file() || before.len() < 4096 {
            return Err(format!(
                "macOS dyld cache {} is not a nonempty regular file",
                entry.display()
            ));
        }
        logical_bytes = logical_bytes
            .checked_add(before.len())
            .ok_or_else(|| "macOS dyld cache byte count overflow".to_owned())?;
        if before.len() > MAX_DYLD_CACHE_FILE_BYTES || logical_bytes > MAX_HOST_CLOSURE_BYTES {
            return Err("macOS dyld cache set exceeds host-closure byte limits".to_owned());
        }
        append_hash_value(&mut hasher, name.as_bytes())?;
        hasher.update(permission_mode(&before).to_le_bytes());
        hasher.update(before.len().to_le_bytes());
        let (seconds, nanoseconds) = metadata_timestamp(&before);
        hasher.update(seconds.to_le_bytes());
        hasher.update(nanoseconds.to_le_bytes());
        append_hash_value(&mut hasher, sha256_file(entry)?.as_bytes())?;
        let after = fs::symlink_metadata(entry).map_err(|error| {
            format!("cannot re-inspect dyld cache {}: {error}", entry.display())
        })?;
        if !stable_metadata_equal(&before, &after) {
            return Err(format!(
                "macOS dyld cache {} changed while measured",
                entry.display()
            ));
        }
    }
    Ok(HostRootIdentity {
        role: "macos-dyld-cache".to_owned(),
        path,
        digest: lower_hex(&hasher.finalize()),
        entries: u64::try_from(entries.len())
            .map_err(|_| "macOS dyld cache entry count overflow".to_owned())?,
        bytes: logical_bytes,
    })
}

fn hash_host_entry(
    root: &Path,
    path: &Path,
    allowed_roots: &[PathBuf],
    hasher: &mut Sha256,
    total_entries: &mut u64,
    total_bytes: &mut u64,
    depth: u32,
) -> Result<(), String> {
    if depth > MAX_PREFIX_DEPTH {
        return Err(format!(
            "host closure exceeds directory depth {MAX_PREFIX_DEPTH}"
        ));
    }
    *total_entries = total_entries
        .checked_add(1)
        .ok_or_else(|| "host closure entry count overflow".to_owned())?;
    if *total_entries > MAX_HOST_CLOSURE_ENTRIES {
        return Err(format!(
            "host closure exceeds {MAX_HOST_CLOSURE_ENTRIES} entries"
        ));
    }
    let before = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect host input {}: {error}", path.display()))?;
    let relative = path
        .strip_prefix(root)
        .map_err(|_| format!("host input escaped root: {}", path.display()))?;
    let relative = relative
        .to_str()
        .ok_or_else(|| format!("host input path is not UTF-8: {}", path.display()))?
        .replace(std::path::MAIN_SEPARATOR, "/");
    if relative.len() > MAX_ARCHIVE_PATH_BYTES {
        return Err(format!("host input path is oversized: {relative:?}"));
    }
    let kind = if before.file_type().is_symlink() {
        b'L'
    } else if before.is_dir() {
        b'D'
    } else if before.is_file() {
        b'F'
    } else {
        return Err(format!(
            "host closure contains unsupported entry {}",
            path.display()
        ));
    };
    hasher.update([kind]);
    append_hash_value(hasher, relative.as_bytes())?;
    hasher.update(permission_mode(&before).to_le_bytes());
    let (modified_seconds, modified_nanoseconds) = metadata_timestamp(&before);
    hasher.update(modified_seconds.to_le_bytes());
    hasher.update(modified_nanoseconds.to_le_bytes());

    if before.file_type().is_symlink() {
        let target = fs::read_link(path)
            .map_err(|error| format!("cannot read host symlink {}: {error}", path.display()))?;
        let target_text = target.to_str().ok_or_else(|| {
            format!(
                "host symlink target is not UTF-8: {} -> {:?}",
                path.display(),
                target
            )
        })?;
        if target_text.len() > MAX_ARCHIVE_PATH_BYTES {
            return Err(format!("host symlink target is oversized: {target_text:?}"));
        }
        let resolved = fs::canonicalize(path)
            .map_err(|error| format!("cannot resolve host symlink {}: {error}", path.display()))?;
        if !allowed_roots
            .iter()
            .any(|allowed| resolved.starts_with(allowed))
        {
            return Err(format!(
                "host symlink {} resolves outside every measured root to {}",
                path.display(),
                resolved.display()
            ));
        }
        append_hash_value(hasher, target_text.as_bytes())?;
    } else if before.is_dir() {
        let mut children = Vec::new();
        for entry in fs::read_dir(path)
            .map_err(|error| format!("cannot read host directory {}: {error}", path.display()))?
        {
            children.push(
                entry
                    .map_err(|error| format!("cannot inspect host directory entry: {error}"))?
                    .path(),
            );
        }
        children.sort();
        for child in children {
            hash_host_entry(
                root,
                &child,
                allowed_roots,
                hasher,
                total_entries,
                total_bytes,
                depth + 1,
            )?;
        }
    } else {
        if before.len() > MAX_HOST_CLOSURE_FILE_BYTES {
            return Err(format!(
                "host input {} exceeds {MAX_HOST_CLOSURE_FILE_BYTES} bytes",
                path.display()
            ));
        }
        *total_bytes = total_bytes
            .checked_add(before.len())
            .ok_or_else(|| "host closure byte count overflow".to_owned())?;
        if *total_bytes > MAX_HOST_CLOSURE_BYTES {
            return Err(format!(
                "host closure exceeds {MAX_HOST_CLOSURE_BYTES} bytes"
            ));
        }
        hasher.update(before.len().to_le_bytes());
        append_hash_value(hasher, sha256_file(path)?.as_bytes())?;
    }
    let after = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot re-inspect host input {}: {error}", path.display()))?;
    if !stable_metadata_equal(&before, &after) {
        return Err(format!(
            "host input {} changed while it was measured",
            path.display()
        ));
    }
    Ok(())
}

fn append_hash_value(hasher: &mut Sha256, value: &[u8]) -> Result<(), String> {
    let length = u64::try_from(value.len())
        .map_err(|_| "host closure identity value length overflow".to_owned())?;
    hasher.update(length.to_le_bytes());
    hasher.update(value);
    Ok(())
}

#[cfg(unix)]
fn stable_metadata_equal(first: &fs::Metadata, second: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    first.file_type() == second.file_type()
        && first.dev() == second.dev()
        && first.ino() == second.ino()
        && first.len() == second.len()
        && first.mode() == second.mode()
        && first.mtime() == second.mtime()
        && first.mtime_nsec() == second.mtime_nsec()
}

#[cfg(not(unix))]
fn stable_metadata_equal(first: &fs::Metadata, second: &fs::Metadata) -> bool {
    first.file_type() == second.file_type()
        && first.len() == second.len()
        && first.modified().ok() == second.modified().ok()
}

fn revalidate_native_tools(tools: &NativeTools) -> Result<(), String> {
    for (label, expected) in [
        ("xz", &tools.xz),
        ("CMake", &tools.cmake),
        ("Ninja", &tools.ninja),
        ("C compiler", &tools.cc),
        ("C++ compiler", &tools.cxx),
        ("archiver", &tools.ar),
        ("archive indexer", &tools.ranlib),
        ("Python", &tools.python),
        ("linker", &tools.linker),
        ("touch", &tools.touch),
        ("shell", &tools.shell),
    ] {
        let observed = identify_tool(&expected.path)?;
        if &observed != expected {
            return Err(format!(
                "fingerprinted native {label} changed during LLVM bootstrap: {}",
                expected.path.display()
            ));
        }
    }
    if let Some(expected) = &tools.sysroot {
        let observed = identify_apple_sysroot(&expected.path)?;
        if &observed != expected {
            return Err(format!(
                "fingerprinted macOS SDK changed during LLVM bootstrap: {}",
                expected.path.display()
            ));
        }
    }
    Ok(())
}

fn revalidate_host_closure(tools: &NativeTools) -> Result<(), String> {
    let roots: Vec<_> = tools
        .host_closure
        .roots
        .iter()
        .filter(|root| root.role != "macos-dyld-cache")
        .map(|root| (root.role.clone(), root.path.clone()))
        .collect();
    let mut observed = measure_host_closure(&roots)?;
    observed.roots.push(measure_macos_dyld_cache()?);
    let observed = finalize_host_closure(observed.roots)?;
    if observed != tools.host_closure {
        return Err("measured host toolchain closure changed during LLVM bootstrap".to_owned());
    }
    Ok(())
}

fn xcrun_path(arguments: &[&str]) -> Result<PathBuf, String> {
    let mut command = Command::new("/usr/bin/xcrun");
    command
        .args(arguments)
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/wrela/no-ambient-path")
        .stdin(Stdio::null());
    let (status, stdout, stderr) = run_bounded_output(
        &mut command,
        64 * 1024,
        std::time::Duration::from_secs(10),
        "fixed /usr/bin/xcrun",
    )?;
    if !status.success() || !stderr.is_empty() {
        return Err(format!(
            "fixed /usr/bin/xcrun {arguments:?} failed with {status}: {}",
            String::from_utf8_lossy(&stderr)
        ));
    }
    let text =
        std::str::from_utf8(&stdout).map_err(|_| "xcrun returned a non-UTF-8 path".to_owned())?;
    let path = PathBuf::from(text.trim_end_matches(['\r', '\n']));
    if !path.is_absolute() || path.as_os_str().is_empty() {
        return Err("xcrun returned a non-absolute tool path".to_owned());
    }
    Ok(path)
}

fn resolve_tool(variable: &str, candidates: &[&str]) -> Result<ToolIdentity, String> {
    let selected = if let Some(value) = env::var_os(variable) {
        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Err(format!("{variable} must be an absolute path"));
        }
        path
    } else {
        candidates
            .iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
            .ok_or_else(|| {
                format!(
                    "no fixed candidate exists for {variable}; set it to an absolute executable"
                )
            })?
    };
    identify_tool(&selected)
}

fn identify_tool(selected: &Path) -> Result<ToolIdentity, String> {
    let name = selected
        .file_name()
        .ok_or_else(|| format!("tool path has no invocation name: {}", selected.display()))?;
    let parent = fs::canonicalize(
        selected
            .parent()
            .ok_or_else(|| format!("tool path has no parent: {}", selected.display()))?,
    )
    .map_err(|error| format!("cannot resolve tool parent {}: {error}", selected.display()))?;
    let invocation = parent.join(name);
    let canonical = fs::canonicalize(&invocation)
        .map_err(|error| format!("cannot resolve {}: {error}", invocation.display()))?;
    let metadata = fs::metadata(&canonical)
        .map_err(|error| format!("cannot inspect {}: {error}", canonical.display()))?;
    if !metadata.is_file() || !metadata_is_executable(&metadata) {
        return Err(format!(
            "{} is not a regular executable file",
            canonical.display()
        ));
    }
    let digest = sha256_file(&canonical)?;
    Ok(ToolIdentity {
        path: invocation,
        digest,
    })
}

#[cfg(unix)]
fn metadata_is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn metadata_is_executable(_metadata: &fs::Metadata) -> bool {
    true
}

fn required_distribution_components() -> Vec<&'static str> {
    let mut components = Vec::with_capacity(
        2 + REQUIRED_LLVM_STATIC_COMPONENTS.len() + REQUIRED_LLD_STATIC_COMPONENTS.len(),
    );
    components.extend(["llvm-headers", "lld-headers"]);
    components.extend(REQUIRED_LLVM_STATIC_COMPONENTS.iter().copied());
    components.extend(REQUIRED_LLD_STATIC_COMPONENTS.iter().copied());
    components
}

fn reviewed_license_notices() -> Vec<LicenseNotice> {
    REQUIRED_LICENSE_NOTICES
        .iter()
        .map(|(_, destination, digest)| LicenseNotice {
            destination: (*destination).to_owned(),
            digest: (*digest).to_owned(),
        })
        .collect()
}

fn expected_llvm_static_archive_names() -> Vec<String> {
    let static_suffix = if cfg!(windows) { ".lib" } else { ".a" };
    let static_prefix = if cfg!(windows) { "" } else { "lib" };
    REQUIRED_LLVM_STATIC_COMPONENTS
        .iter()
        .map(|component| format!("{static_prefix}{component}{static_suffix}"))
        .collect()
}

fn normalized_configure_flags(lock: &LlvmLock) -> Vec<String> {
    vec![
        "-G=Ninja".to_owned(),
        "-C=<CMAKE_CONTRACT>".to_owned(),
        "-S=<SOURCE>/llvm".to_owned(),
        "-B=<BUILD>".to_owned(),
        "-DCMAKE_INSTALL_PREFIX=<PREFIX>".to_owned(),
        "-DCMAKE_BUILD_TYPE=Release".to_owned(),
        "-DCMAKE_C_COMPILER=<CC>".to_owned(),
        "-DCMAKE_C_COMPILER_ARG1=--no-default-config".to_owned(),
        "-DCMAKE_CXX_COMPILER=<CXX>".to_owned(),
        "-DCMAKE_CXX_COMPILER_ARG1=--no-default-config".to_owned(),
        "-DCMAKE_AR=<AR>".to_owned(),
        "-DCMAKE_RANLIB=<RANLIB>".to_owned(),
        "-DCMAKE_LINKER=<LINKER>".to_owned(),
        "-DCMAKE_EXE_LINKER_FLAGS=--ld-path=<LINKER>;-Wl,-reproducible-on-macos".to_owned(),
        "-DCMAKE_SHARED_LINKER_FLAGS=--ld-path=<LINKER>;-Wl,-reproducible-on-macos".to_owned(),
        "-DCMAKE_MODULE_LINKER_FLAGS=--ld-path=<LINKER>;-Wl,-reproducible-on-macos".to_owned(),
        "-DCMAKE_STATIC_LINKER_FLAGS=-D-on-macos".to_owned(),
        "-DCMAKE_OSX_SYSROOT=<MACOS_SDK_OR_NONE>".to_owned(),
        "-DPython3_EXECUTABLE=<PYTHON>".to_owned(),
        "-DCMAKE_MAKE_PROGRAM=<NINJA>".to_owned(),
        "-DCMAKE_C_FLAGS=<REPRODUCIBLE_PREFIX_MAPS>".to_owned(),
        "-DCMAKE_CXX_FLAGS=<REPRODUCIBLE_PREFIX_MAPS>".to_owned(),
        format!("-DLLVM_ENABLE_PROJECTS={}", lock.projects.join(";")),
        format!("-DLLVM_TARGETS_TO_BUILD={}", lock.targets.join(";")),
        format!(
            "-DLLVM_DISTRIBUTION_COMPONENTS={}",
            required_distribution_components().join(";")
        ),
        "-DLLVM_STRICT_DISTRIBUTIONS=ON".to_owned(),
        "-DLLVM_HOST_TRIPLE=<CANONICAL_HOST_TRIPLE>".to_owned(),
        "-DLLVM_DEFAULT_TARGET_TRIPLE=<CANONICAL_HOST_TRIPLE>".to_owned(),
        "-DWRELA_CANONICAL_HOST_TRIPLE=<CANONICAL_HOST_TRIPLE>".to_owned(),
        "-DCMAKE_OSX_ARCHITECTURES=<HOST_ARCH_OR_NONE>".to_owned(),
        "-DCMAKE_OSX_DEPLOYMENT_TARGET=13.0-or-none".to_owned(),
        "-DCMAKE_DISABLE_FIND_PACKAGE_Git=TRUE".to_owned(),
        "-DCMAKE_FIND_USE_PACKAGE_REGISTRY=FALSE".to_owned(),
        "-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=FALSE".to_owned(),
        format!("-DLLVM_FORCE_VC_REVISION={}", lock.commit),
        "-DLLVM_FORCE_VC_REPOSITORY=https://github.com/llvm/llvm-project.git".to_owned(),
        "-DLLVM_ENABLE_RUNTIMES=".to_owned(),
        "-DBUILD_SHARED_LIBS=OFF".to_owned(),
        "-DLLVM_BUILD_LLVM_DYLIB=OFF".to_owned(),
        "-DLLVM_BUILD_TOOLS=OFF".to_owned(),
        "-DLLVM_BUILD_UTILS=OFF".to_owned(),
        "-DLLVM_LINK_LLVM_DYLIB=OFF".to_owned(),
        "-DLLD_BUILD_TOOLS=OFF".to_owned(),
        "-DLLVM_TOOL_LTO_BUILD=OFF".to_owned(),
        "-DLLVM_TOOL_REMARKS_SHLIB_BUILD=OFF".to_owned(),
        "-DLLVM_ENABLE_ASSERTIONS=OFF".to_owned(),
        "-DLLVM_ENABLE_CURL=OFF".to_owned(),
        "-DLLVM_ENABLE_FFI=OFF".to_owned(),
        "-DLLVM_ENABLE_HTTPLIB=OFF".to_owned(),
        "-DLLVM_ENABLE_LIBPFM=OFF".to_owned(),
        "-DLLVM_ENABLE_ZLIB=OFF".to_owned(),
        "-DLLVM_ENABLE_ZSTD=OFF".to_owned(),
        "-DLLVM_ENABLE_LIBXML2=OFF".to_owned(),
        "-DLLVM_ENABLE_TERMINFO=OFF".to_owned(),
        "-DLLVM_ENABLE_Z3_SOLVER=OFF".to_owned(),
        "environment.PYTHONHASHSEED=0".to_owned(),
        "environment.PYTHONNOUSERSITE=1".to_owned(),
        "environment.PYTHONDONTWRITEBYTECODE=1".to_owned(),
        "source.timestamps=SOURCE_DATE_EPOCH".to_owned(),
        "prefix.timestamps=SOURCE_DATE_EPOCH".to_owned(),
    ]
}

fn normalized_flags_digest(lock: &LlvmLock) -> String {
    let mut bytes = b"WRELCMF\0\x01\x00\x00\x00".to_vec();
    for flag in normalized_configure_flags(lock) {
        append_length_prefixed(&mut bytes, flag.as_bytes());
    }
    sha256_bytes(&bytes)
}

#[allow(clippy::too_many_arguments)]
fn build_input_digest(
    lock: &LlvmLock,
    lock_digest: &str,
    cmake_digest: &str,
    codegen_binding_digest: &str,
    rust_binding_digest: &str,
    flags_digest: &str,
    implementation_digest: &str,
    host: &str,
    tools: &NativeTools,
) -> String {
    let mut bytes = b"WRELLVM\0".to_vec();
    bytes.extend_from_slice(&BUILD_CONTRACT_VERSION.to_le_bytes());
    bytes.extend_from_slice(&ARCHIVE_POLICY_VERSION.to_le_bytes());
    for value in [
        lock.version.as_str(),
        lock.tag.as_str(),
        lock.commit.as_str(),
        lock.source.as_str(),
        lock.sha256.as_str(),
        lock_digest,
        cmake_digest,
        codegen_binding_digest,
        rust_binding_digest,
        flags_digest,
        implementation_digest,
        host,
    ] {
        append_length_prefixed(&mut bytes, value.as_bytes());
    }
    for tool in [
        &tools.xz,
        &tools.cmake,
        &tools.ninja,
        &tools.cc,
        &tools.cxx,
        &tools.ar,
        &tools.ranlib,
        &tools.python,
        &tools.linker,
        &tools.touch,
        &tools.shell,
    ] {
        append_path_identity(&mut bytes, &tool.path);
        append_length_prefixed(&mut bytes, tool.digest.as_bytes());
    }
    if let Some(sysroot) = &tools.sysroot {
        bytes.push(1);
        append_path_identity(&mut bytes, &sysroot.path);
        append_length_prefixed(&mut bytes, sysroot.digest.as_bytes());
    } else {
        bytes.push(0);
    }
    append_length_prefixed(&mut bytes, tools.host_closure.digest.as_bytes());
    for root in &tools.host_closure.roots {
        append_length_prefixed(&mut bytes, root.role.as_bytes());
        append_path_identity(&mut bytes, &root.path);
        append_length_prefixed(&mut bytes, root.digest.as_bytes());
        bytes.extend_from_slice(&root.entries.to_le_bytes());
        bytes.extend_from_slice(&root.bytes.to_le_bytes());
    }
    sha256_bytes(&bytes)
}

fn append_length_prefixed(bytes: &mut Vec<u8>, value: &[u8]) {
    let length = u64::try_from(value.len()).unwrap_or(u64::MAX);
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(value);
}

#[cfg(unix)]
fn append_path_identity(bytes: &mut Vec<u8>, path: &Path) {
    use std::os::unix::ffi::OsStrExt;
    append_length_prefixed(bytes, path.as_os_str().as_bytes());
}

#[cfg(windows)]
fn append_path_identity(bytes: &mut Vec<u8>, path: &Path) {
    use std::os::windows::ffi::OsStrExt;
    let mut encoded = Vec::new();
    for unit in path.as_os_str().encode_wide() {
        encoded.extend_from_slice(&unit.to_le_bytes());
    }
    append_length_prefixed(bytes, &encoded);
}

#[cfg(not(any(unix, windows)))]
fn append_path_identity(bytes: &mut Vec<u8>, path: &Path) {
    append_length_prefixed(bytes, path.to_string_lossy().as_bytes());
}

fn print_plan(plan: &BuildPlan, source_archive: Option<&Path>) {
    println!("LLVM bootstrap plan");
    println!("  release: {} ({})", plan.lock.version, plan.lock.tag);
    println!("  source commit: {}", plan.lock.commit);
    println!("  source: {}", plan.lock.source);
    println!("  archive SHA-256: {}", plan.lock.sha256);
    println!("  archive bytes: {}", plan.lock.archive_bytes);
    println!("  projects: {}", plan.lock.projects.join(","));
    println!("  targets: {}", plan.lock.targets.join(","));
    println!("  linkage: {}", plan.lock.linkage);
    println!("  jobs: {}", plan.jobs);
    println!(
        "  acquisition: {}",
        source_archive.map_or_else(
            || "verified HTTPS download".to_owned(),
            |path| { format!("verified local archive {}", path.display()) }
        )
    );
    println!("  input digest: {}", plan.input_digest);
    println!(
        "  bootstrap implementation SHA-256: {}",
        plan.implementation_digest
    );
    println!(
        "  bootstrap executable: {} ({})",
        plan.bootstrap_executable.path.display(),
        plan.bootstrap_executable.digest
    );
    if let Some(expected) = &plan.expected_output {
        println!(
            "  trusted output: {} files, {} bytes, {}",
            expected.prefix_files, expected.prefix_bytes, expected.prefix_tree_sha256
        );
    } else {
        println!("  trusted output: absent (maintainer enrollment required)");
    }
    println!("  prefix: {}", plan.prefix.display());
    println!("  cmake: {}", plan.tools.cmake.path.display());
    println!("  ninja: {}", plan.tools.ninja.path.display());
    println!("  C compiler: {}", plan.tools.cc.path.display());
    println!("  C++ compiler: {}", plan.tools.cxx.path.display());
    println!("  archiver: {}", plan.tools.ar.path.display());
    println!("  archive indexer: {}", plan.tools.ranlib.path.display());
    println!("  Python: {}", plan.tools.python.path.display());
    println!("  linker: {}", plan.tools.linker.path.display());
    println!("  touch: {}", plan.tools.touch.path.display());
    println!("  shell: {}", plan.tools.shell.path.display());
    println!("  host closure SHA-256: {}", plan.tools.host_closure.digest);
    for root in &plan.tools.host_closure.roots {
        println!(
            "    {}: {} ({} entries, {} bytes)",
            root.role,
            root.path.display(),
            root.entries,
            root.bytes
        );
    }
    if let Some(sysroot) = &plan.tools.sysroot {
        println!("  macOS SDK: {}", sysroot.path.display());
    }
}

fn build_commands(
    plan: &BuildPlan,
    source: &Path,
    build: &Path,
    prefix: &Path,
    cmake_contract: &Path,
) -> Result<(CommandSpec, CommandSpec, CommandSpec), String> {
    for path in [source, build, prefix, cmake_contract] {
        if !path.is_absolute() {
            return Err(format!(
                "LLVM command path must be absolute: {}",
                path.display()
            ));
        }
    }
    let source_llvm = source.join("llvm");
    let prefix_maps = reproducible_prefix_maps(source, build)?;
    let mut host_linker_flags = format!("--ld-path={}", utf8_path(&plan.tools.linker.path)?);
    if plan.tools.sysroot.is_some() {
        host_linker_flags.push_str(" -Wl,-reproducible");
    }
    let mut configure_arguments = vec![
        OsString::from("-G"),
        OsString::from("Ninja"),
        OsString::from("-C"),
        cmake_contract.as_os_str().to_owned(),
        OsString::from("-S"),
        source_llvm.into_os_string(),
        OsString::from("-B"),
        build.as_os_str().to_owned(),
        OsString::from(format!("-DCMAKE_INSTALL_PREFIX={}", utf8_path(prefix)?)),
        OsString::from("-DCMAKE_BUILD_TYPE=Release"),
        OsString::from(format!(
            "-DCMAKE_C_COMPILER={}",
            utf8_path(&plan.tools.cc.path)?
        )),
        OsString::from("-DCMAKE_C_COMPILER_ARG1=--no-default-config"),
        OsString::from(format!(
            "-DCMAKE_CXX_COMPILER={}",
            utf8_path(&plan.tools.cxx.path)?
        )),
        OsString::from("-DCMAKE_CXX_COMPILER_ARG1=--no-default-config"),
        OsString::from(format!("-DCMAKE_AR={}", utf8_path(&plan.tools.ar.path)?)),
        OsString::from(format!(
            "-DCMAKE_RANLIB={}",
            utf8_path(&plan.tools.ranlib.path)?
        )),
        OsString::from(format!(
            "-DCMAKE_LINKER={}",
            utf8_path(&plan.tools.linker.path)?
        )),
        OsString::from(format!("-DCMAKE_EXE_LINKER_FLAGS={host_linker_flags}")),
        OsString::from(format!("-DCMAKE_SHARED_LINKER_FLAGS={host_linker_flags}")),
        OsString::from(format!("-DCMAKE_MODULE_LINKER_FLAGS={host_linker_flags}")),
        OsString::from(format!(
            "-DPython3_EXECUTABLE={}",
            utf8_path(&plan.tools.python.path)?
        )),
        OsString::from(format!(
            "-DCMAKE_MAKE_PROGRAM={}",
            utf8_path(&plan.tools.ninja.path)?
        )),
        OsString::from(format!("-DCMAKE_C_FLAGS={prefix_maps}")),
        OsString::from(format!("-DCMAKE_CXX_FLAGS={prefix_maps}")),
        OsString::from(format!(
            "-DLLVM_ENABLE_PROJECTS={}",
            plan.lock.projects.join(";")
        )),
        OsString::from(format!(
            "-DLLVM_TARGETS_TO_BUILD={}",
            plan.lock.targets.join(";")
        )),
        OsString::from(format!(
            "-DLLVM_DISTRIBUTION_COMPONENTS={}",
            required_distribution_components().join(";")
        )),
        OsString::from("-DLLVM_STRICT_DISTRIBUTIONS=ON"),
        OsString::from(format!("-DLLVM_HOST_TRIPLE={}", plan.host)),
        OsString::from(format!("-DLLVM_DEFAULT_TARGET_TRIPLE={}", plan.host)),
        OsString::from(format!("-DWRELA_CANONICAL_HOST_TRIPLE={}", plan.host)),
        OsString::from("-DCMAKE_DISABLE_FIND_PACKAGE_Git=TRUE"),
        OsString::from("-DCMAKE_FIND_USE_PACKAGE_REGISTRY=FALSE"),
        OsString::from("-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=FALSE"),
        OsString::from(format!("-DLLVM_FORCE_VC_REVISION={}", plan.lock.commit)),
        OsString::from("-DLLVM_FORCE_VC_REPOSITORY=https://github.com/llvm/llvm-project.git"),
        OsString::from("-DLLVM_ENABLE_RUNTIMES="),
        OsString::from("-DBUILD_SHARED_LIBS=OFF"),
        OsString::from("-DLLVM_BUILD_LLVM_DYLIB=OFF"),
        OsString::from("-DLLVM_BUILD_TOOLS=OFF"),
        OsString::from("-DLLVM_BUILD_UTILS=OFF"),
        OsString::from("-DLLVM_LINK_LLVM_DYLIB=OFF"),
        OsString::from("-DLLD_BUILD_TOOLS=OFF"),
        OsString::from("-DLLVM_TOOL_LTO_BUILD=OFF"),
        OsString::from("-DLLVM_TOOL_REMARKS_SHLIB_BUILD=OFF"),
        OsString::from("-DLLVM_ENABLE_ASSERTIONS=OFF"),
        OsString::from("-DLLVM_ENABLE_CURL=OFF"),
        OsString::from("-DLLVM_ENABLE_FFI=OFF"),
        OsString::from("-DLLVM_ENABLE_HTTPLIB=OFF"),
        OsString::from("-DLLVM_ENABLE_LIBPFM=OFF"),
        OsString::from("-DLLVM_ENABLE_ZLIB=OFF"),
        OsString::from("-DLLVM_ENABLE_ZSTD=OFF"),
        OsString::from("-DLLVM_ENABLE_LIBXML2=OFF"),
        OsString::from("-DLLVM_ENABLE_TERMINFO=OFF"),
        OsString::from("-DLLVM_ENABLE_Z3_SOLVER=OFF"),
    ];
    if let Some(sysroot) = &plan.tools.sysroot {
        let architecture = if plan.host.starts_with("arm64-") {
            "arm64"
        } else if plan.host.starts_with("x86_64-") {
            "x86_64"
        } else {
            return Err(format!("unsupported macOS host triple {}", plan.host));
        };
        configure_arguments.push(OsString::from(format!(
            "-DCMAKE_OSX_ARCHITECTURES={architecture}"
        )));
        configure_arguments.push(OsString::from("-DCMAKE_OSX_DEPLOYMENT_TARGET=13.0"));
        configure_arguments.push(OsString::from(format!(
            "-DCMAKE_OSX_SYSROOT={}",
            utf8_path(&sysroot.path)?
        )));
        configure_arguments.push(OsString::from("-DCMAKE_STATIC_LINKER_FLAGS=-D"));
    }
    let common_environment = deterministic_environment(build);
    let configure = CommandSpec {
        program: plan.tools.cmake.path.clone(),
        arguments: configure_arguments,
        environment: common_environment.clone(),
        current_dir: build.to_owned(),
    };
    let build_llvm_config = CommandSpec {
        program: plan.tools.cmake.path.clone(),
        arguments: vec![
            OsString::from("--build"),
            build.as_os_str().to_owned(),
            OsString::from("--target"),
            OsString::from("llvm-config"),
            OsString::from("--parallel"),
            OsString::from(plan.jobs.to_string()),
        ],
        environment: common_environment.clone(),
        current_dir: build.to_owned(),
    };
    let install = CommandSpec {
        program: plan.tools.cmake.path.clone(),
        arguments: vec![
            OsString::from("--build"),
            build.as_os_str().to_owned(),
            OsString::from("--target"),
            OsString::from("install-distribution"),
            OsString::from("--parallel"),
            OsString::from(plan.jobs.to_string()),
        ],
        environment: common_environment,
        current_dir: build.to_owned(),
    };
    Ok((configure, build_llvm_config, install))
}

fn stage_cmake_contract(build: &Path, plan: &BuildPlan) -> Result<PathBuf, String> {
    if sha256_bytes(&plan.cmake_bytes) != plan.cmake_digest {
        return Err("in-memory LLVM CMake contract no longer matches its input digest".to_owned());
    }
    let directory = build.join("wrela-inputs");
    fs::create_dir(&directory)
        .map_err(|error| format!("cannot create staged native input directory: {error}"))?;
    let path = directory.join("WrelaLLVM.cmake");
    write_new_file(&path, &plan.cmake_bytes)?;
    sync_directory(&directory)?;
    Ok(path)
}

fn canonicalize_llvm_config_build_variables(source: &Path, build: &Path) -> Result<(), String> {
    let path = build.join("tools/llvm-config/BuildVariables.inc");
    let bytes = fs::read(&path)
        .map_err(|error| format!("cannot read generated {}: {error}", path.display()))?;
    if bytes.len() > 1024 * 1024 {
        return Err("generated LLVM BuildVariables.inc exceeds 1 MiB".to_owned());
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "generated LLVM BuildVariables.inc is not UTF-8".to_owned())?;
    let source_line = format!(
        "#define LLVM_SRC_ROOT \"{}\"",
        utf8_path(&source.join("llvm"))?
    );
    let build_line = format!("#define LLVM_OBJ_ROOT \"{}\"", utf8_path(build)?);
    let mut source_seen = 0_u8;
    let mut build_seen = 0_u8;
    let mut canonical = String::with_capacity(text.len());
    for line in text.lines() {
        if line == source_line {
            canonical.push_str("#define LLVM_SRC_ROOT \"/wrela/llvm/source/llvm\"\n");
            source_seen += 1;
        } else if line == build_line {
            canonical.push_str("#define LLVM_OBJ_ROOT \"/wrela/llvm/build\"\n");
            build_seen += 1;
        } else {
            canonical.push_str(line);
            canonical.push('\n');
        }
    }
    if source_seen != 1 || build_seen != 1 || !text.ends_with('\n') {
        return Err(
            "generated LLVM BuildVariables.inc lacks exact canonical source/object roots"
                .to_owned(),
        );
    }
    for path in [utf8_path(source)?, utf8_path(build)?] {
        if canonical.contains(path) {
            return Err(format!(
                "generated LLVM BuildVariables.inc retains host staging path {path:?}"
            ));
        }
    }
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .map_err(|error| format!("cannot rewrite generated {}: {error}", path.display()))?;
    file.write_all(canonical.as_bytes())
        .map_err(|error| format!("cannot canonicalize generated {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("cannot sync generated {}: {error}", path.display()))
}

fn patch_host_triple_probe(source: &Path) -> Result<(), String> {
    const ORIGINAL: &str = "      set(config_guess ${LLVM_MAIN_SRC_DIR}/cmake/config.guess)\n      execute_process(COMMAND sh ${config_guess}\n        RESULT_VARIABLE TT_RV\n        OUTPUT_VARIABLE TT_OUT\n        OUTPUT_STRIP_TRAILING_WHITESPACE)\n      if( NOT TT_RV EQUAL 0 )\n        message(FATAL_ERROR \"Failed to execute ${config_guess}\")\n      endif( NOT TT_RV EQUAL 0 )\n      set( value ${TT_OUT} )";
    const REPLACEMENT: &str = "      if(NOT DEFINED WRELA_CANONICAL_HOST_TRIPLE)\n        message(FATAL_ERROR \"WRELA_CANONICAL_HOST_TRIPLE is required\")\n      endif()\n      set(value ${WRELA_CANONICAL_HOST_TRIPLE})";
    let path = source.join("llvm/cmake/modules/GetHostTriple.cmake");
    let bytes = fs::read(&path).map_err(|error| {
        format!(
            "cannot read {} for deterministic patch: {error}",
            path.display()
        )
    })?;
    if bytes.len() > 1024 * 1024 {
        return Err("LLVM GetHostTriple.cmake exceeds 1 MiB".to_owned());
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "LLVM GetHostTriple.cmake is not UTF-8".to_owned())?;
    if text.matches(ORIGINAL).count() != 1 {
        return Err("LLVM host-triple probe does not match the reviewed patch contract".to_owned());
    }
    let patched = text.replace(ORIGINAL, REPLACEMENT);
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .map_err(|error| format!("cannot patch {}: {error}", path.display()))?;
    file.write_all(patched.as_bytes())
        .map_err(|error| format!("cannot patch {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("cannot sync patched {}: {error}", path.display()))
}

fn patch_deterministic_source(source: &Path) -> Result<(), String> {
    patch_host_triple_probe(source)?;
    patch_lld_alias_install(source)
}

fn patch_lld_alias_install(source: &Path) -> Result<(), String> {
    const ORIGINAL: &str =
        "foreach(link ${LLD_SYMLINKS_TO_CREATE})\n  add_lld_symlink(${link} lld)\nendforeach()";
    const REPLACEMENT: &str = "if(LLD_BUILD_TOOLS)\n  foreach(link ${LLD_SYMLINKS_TO_CREATE})\n    add_lld_symlink(${link} lld)\n  endforeach()\nendif()";
    let path = source.join("lld/tools/lld/CMakeLists.txt");
    let bytes = fs::read(&path).map_err(|error| {
        format!(
            "cannot read {} for deterministic patch: {error}",
            path.display()
        )
    })?;
    if bytes.len() > 1024 * 1024 {
        return Err("LLD tools CMakeLists.txt exceeds 1 MiB".to_owned());
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "LLD tools CMakeLists.txt is not UTF-8".to_owned())?;
    if text.matches(ORIGINAL).count() != 1 {
        return Err("LLD alias install rules do not match the reviewed patch contract".to_owned());
    }
    let patched = text.replace(ORIGINAL, REPLACEMENT);
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)
        .map_err(|error| format!("cannot patch {}: {error}", path.display()))?;
    file.write_all(patched.as_bytes())
        .map_err(|error| format!("cannot patch {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("cannot sync patched {}: {error}", path.display()))
}

fn stage_llvm_config(build: &Path, prefix: &Path) -> Result<(), String> {
    let suffix = if cfg!(windows) { ".exe" } else { "" };
    let source = build.join(format!("bin/llvm-config{suffix}"));
    let metadata = fs::symlink_metadata(&source)
        .map_err(|error| format!("cannot inspect built {}: {error}", source.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
        return Err(format!(
            "built {} is not a nonempty regular file",
            source.display()
        ));
    }
    let bin = prefix.join("bin");
    fs::create_dir_all(&bin)
        .map_err(|error| format!("cannot create LLVM prefix bin directory: {error}"))?;
    let destination = bin.join(format!("llvm-config{suffix}"));
    let mut input = File::open(&source)
        .map_err(|error| format!("cannot open built {}: {error}", source.display()))?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&destination)
        .map_err(|error| format!("cannot stage {}: {error}", destination.display()))?;
    io::copy(&mut input, &mut output)
        .map_err(|error| format!("cannot copy {}: {error}", destination.display()))?;
    output
        .sync_all()
        .map_err(|error| format!("cannot sync {}: {error}", destination.display()))?;
    set_staged_executable_permissions(&destination)?;
    sync_directory(&bin)
}

fn stage_license_notices(source: &Path, prefix: &Path) -> Result<(), String> {
    for (source_relative, destination_relative, expected_digest) in REQUIRED_LICENSE_NOTICES {
        let source_path = source.join(source_relative);
        let bytes = read_bounded_regular_file(&source_path, 64 * 1024)?;
        let observed_digest = sha256_bytes(&bytes);
        if observed_digest != *expected_digest {
            return Err(format!(
                "LLVM license notice {source_relative:?} digest {observed_digest} does not match reviewed {expected_digest}"
            ));
        }
        let destination = prefix.join(destination_relative);
        let parent_relative = Path::new(destination_relative)
            .parent()
            .ok_or_else(|| "LLVM license destination has no parent".to_owned())?;
        ensure_non_symlink_directory_chain(prefix, parent_relative)?;
        write_new_file(&destination, &bytes)?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_staged_executable_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .map_err(|error| format!("cannot set executable mode on {}: {error}", path.display()))
}

#[cfg(not(unix))]
fn set_staged_executable_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

fn reproducible_prefix_maps(source: &Path, build: &Path) -> Result<String, String> {
    let source = utf8_path(source)?;
    let build = utf8_path(build)?;
    for path in [source, build] {
        if path
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'"' | b'\'' | b'`' | b'$'))
        {
            return Err(format!(
                "native LLVM staging path cannot be represented safely in compiler prefix maps: {path:?}"
            ));
        }
    }
    Ok([
        format!("-ffile-prefix-map={source}=/wrela/llvm/source"),
        format!("-fdebug-prefix-map={source}=/wrela/llvm/source"),
        format!("-fmacro-prefix-map={source}=/wrela/llvm/source"),
        format!("-ffile-prefix-map={build}=/wrela/llvm/build"),
        format!("-fdebug-prefix-map={build}=/wrela/llvm/build"),
        format!("-fmacro-prefix-map={build}=/wrela/llvm/build"),
    ]
    .join(" "))
}

fn deterministic_environment(staging: &Path) -> Vec<(OsString, OsString)> {
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
        (
            OsString::from("PATH"),
            staging.join("wrela-host-tools/bin").into_os_string(),
        ),
        (OsString::from("TMPDIR"), staging.as_os_str().to_owned()),
    ]
}

fn prepare_controlled_tool_path(build: &Path, tools: &NativeTools) -> Result<(), String> {
    let directory = build.join("wrela-host-tools/bin");
    fs::create_dir_all(&directory)
        .map_err(|error| format!("cannot create controlled native PATH: {error}"))?;
    let destination = directory.join(if cfg!(windows) { "touch.exe" } else { "touch" });

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&tools.touch.path, &destination).map_err(|error| {
            format!(
                "cannot link controlled {} to {}: {error}",
                destination.display(),
                tools.touch.path.display()
            )
        })?;
        sync_directory(&directory)
    }

    #[cfg(not(unix))]
    {
        let mut input = File::open(&tools.touch.path).map_err(|error| {
            format!(
                "cannot open controlled touch {}: {error}",
                tools.touch.path.display()
            )
        })?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination)
            .map_err(|error| {
                format!(
                    "cannot create controlled {}: {error}",
                    destination.display()
                )
            })?;
        io::copy(&mut input, &mut output).map_err(|error| {
            format!("cannot copy controlled {}: {error}", destination.display())
        })?;
        output.sync_all().map_err(|error| {
            format!("cannot sync controlled {}: {error}", destination.display())
        })?;
        set_staged_executable_permissions(&destination)?;
        sync_directory(&directory)
    }
}

fn run_command(spec: &CommandSpec, label: &str, maximum_seconds: u64) -> Result<(), String> {
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
        .args(&spec.arguments)
        .current_dir(&spec.current_dir)
        .env_clear()
        .stdin(Stdio::null());
    for (key, value) in &spec.environment {
        command.env(key, value);
    }
    configure_child_process_group(&mut command);
    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot execute {label}: {error}"))?;
    let started = std::time::Instant::now();
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| format!("cannot poll {label}: {error}"))?
        {
            break status;
        }
        if started.elapsed() >= std::time::Duration::from_secs(maximum_seconds) {
            terminate_child_process_group(&mut child);
            let _ = child.wait();
            return Err(format!("{label} exceeded {maximum_seconds} seconds"));
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    if status.success() {
        Ok(())
    } else {
        Err(format!("{label} failed with {status}"))
    }
}

fn utf8_path(path: &Path) -> Result<&str, String> {
    path.to_str()
        .ok_or_else(|| format!("native path is not UTF-8: {}", path.display()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    lower_hex(&hasher.finalize())
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let file = File::open(path)
        .map_err(|error| format!("cannot open {} for hashing: {error}", path.display()))?;
    let mut reader = BufReader::new(file);
    sha256_reader(&mut reader).map_err(|error| format!("cannot hash {}: {error}", path.display()))
}

fn sha256_reader(reader: &mut impl Read) -> io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(lower_hex(&hasher.finalize()))
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

fn acquire_archive(
    root: &Path,
    plan: &BuildPlan,
    source_archive: Option<&Path>,
) -> Result<PathBuf, String> {
    if let Some(path) = source_archive {
        return Ok(path.to_owned());
    }
    let archive_directory = root.join(".cache/wrela/llvm/archives");
    ensure_non_symlink_directory_chain(root, Path::new(".cache/wrela/llvm/archives"))?;
    let archive = archive_directory.join(format!("{}.tar.xz", plan.lock.sha256));
    match fs::symlink_metadata(&archive) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            match verify_file_digest_and_size(&archive, &plan.lock.sha256, plan.lock.archive_bytes)
            {
                Ok(()) => return Ok(archive),
                Err(_) => fs::remove_file(&archive).map_err(|error| {
                    format!(
                        "cannot remove corrupted cached archive {}: {error}",
                        archive.display()
                    )
                })?,
            }
        }
        Ok(metadata) if metadata.is_file() || metadata.file_type().is_symlink() => {
            fs::remove_file(&archive).map_err(|error| {
                format!(
                    "cannot remove unsafe cached archive entry {}: {error}",
                    archive.display()
                )
            })?;
        }
        Ok(_) => {
            return Err(format!(
                "LLVM archive cache destination {} is not a regular file",
                archive.display()
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(format!(
                "cannot inspect LLVM archive cache destination {}: {error}",
                archive.display()
            ));
        }
    }

    let curl = resolve_tool("WRELA_LLVM_CURL", &["/usr/bin/curl", "/usr/local/bin/curl"])?;
    let (partial, mut partial_file) = create_download_file(&archive_directory, &plan.lock.sha256)?;
    eprintln!("native acquisition: {}", plan.lock.source);
    if let Err(error) = stream_verified_https_download(
        &curl.path,
        &plan.lock.source,
        plan.lock.archive_bytes,
        &plan.lock.sha256,
        &mut partial_file,
    ) {
        drop(partial_file);
        let _ = fs::remove_file(&partial);
        return Err(error);
    }
    if !path_refers_to_open_file(&partial, &partial_file)? {
        drop(partial_file);
        let _ = fs::remove_file(&partial);
        return Err(format!(
            "LLVM download path {} changed during acquisition",
            partial.display()
        ));
    }
    drop(partial_file);
    match fs::rename(&partial, &archive) {
        Ok(()) => {}
        Err(error)
            if verify_file_digest_and_size(
                &archive,
                &plan.lock.sha256,
                plan.lock.archive_bytes,
            )
            .is_ok() =>
        {
            verify_file_digest_and_size(&archive, &plan.lock.sha256, plan.lock.archive_bytes)?;
            let _ = fs::remove_file(&partial);
            eprintln!("archive publication raced safely: {error}");
        }
        Err(error) => {
            return Err(format!(
                "cannot publish verified archive {}: {error}",
                archive.display()
            ));
        }
    }
    sync_directory(&archive_directory)?;
    verify_file_digest_and_size(&archive, &plan.lock.sha256, plan.lock.archive_bytes)?;
    Ok(archive)
}

fn ensure_non_symlink_directory_chain(root: &Path, relative: &Path) -> Result<(), String> {
    let root_metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("cannot inspect workspace root {}: {error}", root.display()))?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(format!(
            "workspace root {} is not a non-symlink directory",
            root.display()
        ));
    }
    let mut directory = root.to_owned();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err("LLVM cache path is not canonical and relative".to_owned());
        };
        let parent = directory.clone();
        directory.push(name);
        match fs::symlink_metadata(&directory) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => {
                return Err(format!(
                    "LLVM cache component {} is not a non-symlink directory",
                    directory.display()
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&directory).map_err(|error| {
                    format!(
                        "cannot create LLVM cache directory {}: {error}",
                        directory.display()
                    )
                })?;
                sync_directory(&parent)?;
                let metadata = fs::symlink_metadata(&directory).map_err(|error| {
                    format!(
                        "cannot re-inspect new LLVM cache directory {}: {error}",
                        directory.display()
                    )
                })?;
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    return Err(format!(
                        "new LLVM cache component {} is not a non-symlink directory",
                        directory.display()
                    ));
                }
            }
            Err(error) => {
                return Err(format!(
                    "cannot inspect LLVM cache directory {}: {error}",
                    directory.display()
                ));
            }
        }
    }
    Ok(())
}

fn validate_non_symlink_directory_chain(root: &Path, relative: &Path) -> Result<(), String> {
    let root_metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("cannot inspect workspace root {}: {error}", root.display()))?;
    if root_metadata.file_type().is_symlink() || !root_metadata.is_dir() {
        return Err(format!(
            "workspace root {} is not a non-symlink directory",
            root.display()
        ));
    }
    let mut directory = root.to_owned();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err("LLVM cache path is not canonical and relative".to_owned());
        };
        directory.push(name);
        let metadata = fs::symlink_metadata(&directory).map_err(|error| {
            format!(
                "cannot inspect required LLVM cache directory {}: {error}",
                directory.display()
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(format!(
                "LLVM cache component {} is not a non-symlink directory",
                directory.display()
            ));
        }
    }
    Ok(())
}

fn create_download_file(directory: &Path, digest: &str) -> Result<(PathBuf, File), String> {
    for attempt in 0_u32..128 {
        let path = directory.join(format!(
            ".{digest}.{}.{}.partial",
            std::process::id(),
            attempt
        ));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(format!(
                    "cannot create exclusive LLVM download {}: {error}",
                    path.display()
                ));
            }
        }
    }
    Err("cannot allocate an exclusive LLVM download name after 128 attempts".to_owned())
}

fn stream_verified_https_download(
    curl: &Path,
    source: &str,
    expected_bytes: u64,
    expected_digest: &str,
    output: &mut File,
) -> Result<(), String> {
    let archive_bytes = expected_bytes.to_string();
    let mut child = Command::new(curl)
        .args([
            OsStr::new("--disable"),
            OsStr::new("--fail"),
            OsStr::new("--location"),
            OsStr::new("--silent"),
            OsStr::new("--show-error"),
            OsStr::new("--proto"),
            OsStr::new("=https"),
            OsStr::new("--proto-redir"),
            OsStr::new("=https"),
            OsStr::new("--tlsv1.2"),
            OsStr::new("--connect-timeout"),
            OsStr::new("30"),
            OsStr::new("--max-time"),
            OsStr::new("3600"),
            OsStr::new("--max-filesize"),
            OsStr::new(&archive_bytes),
            OsStr::new("--retry"),
            OsStr::new("3"),
            OsStr::new("--"),
            OsStr::new(source),
        ])
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/wrela/no-ambient-path")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|error| format!("cannot execute verified HTTPS downloader: {error}"))?;
    let result = (|| {
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| "HTTPS downloader stdout pipe is unavailable".to_owned())?;
        let mut total = 0_u64;
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let remaining = expected_bytes
                .checked_sub(total)
                .ok_or_else(|| "LLVM download byte count overflow".to_owned())?;
            let wanted = usize::try_from((remaining + 1).min(buffer.len() as u64))
                .map_err(|_| "LLVM download read length overflow".to_owned())?;
            let read = stdout
                .read(&mut buffer[..wanted])
                .map_err(|error| format!("cannot read HTTPS downloader output: {error}"))?;
            if read == 0 {
                break;
            }
            total = total
                .checked_add(
                    u64::try_from(read)
                        .map_err(|_| "LLVM download read count overflow".to_owned())?,
                )
                .ok_or_else(|| "LLVM download byte count overflow".to_owned())?;
            if total > expected_bytes {
                return Err(format!(
                    "LLVM HTTPS download exceeded pinned size {expected_bytes}"
                ));
            }
            output
                .write_all(&buffer[..read])
                .map_err(|error| format!("cannot write exclusive LLVM download: {error}"))?;
            hasher.update(&buffer[..read]);
        }
        let status = child
            .wait()
            .map_err(|error| format!("cannot wait for HTTPS downloader: {error}"))?;
        if !status.success() {
            return Err(format!("LLVM HTTPS download failed with {status}"));
        }
        if total != expected_bytes {
            return Err(format!(
                "LLVM HTTPS download has {total} bytes; expected {expected_bytes}"
            ));
        }
        let digest = lower_hex(&hasher.finalize());
        if digest != expected_digest {
            return Err(format!(
                "LLVM HTTPS download SHA-256 mismatch: expected {expected_digest}, observed {digest}"
            ));
        }
        output
            .sync_all()
            .map_err(|error| format!("cannot sync exclusive LLVM download: {error}"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

#[cfg(unix)]
fn path_refers_to_open_file(path: &Path, file: &File) -> Result<bool, String> {
    use std::os::unix::fs::MetadataExt;

    let path_metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect download path {}: {error}", path.display()))?;
    let file_metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect open download {}: {error}", path.display()))?;
    Ok(!path_metadata.file_type().is_symlink()
        && path_metadata.is_file()
        && file_metadata.is_file()
        && path_metadata.dev() == file_metadata.dev()
        && path_metadata.ino() == file_metadata.ino()
        && path_metadata.len() == file_metadata.len())
}

#[cfg(not(unix))]
fn path_refers_to_open_file(path: &Path, file: &File) -> Result<bool, String> {
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect download path {}: {error}", path.display()))?;
    let file_metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect open download {}: {error}", path.display()))?;
    Ok(!path_metadata.file_type().is_symlink()
        && path_metadata.is_file()
        && file_metadata.is_file()
        && path_metadata.len() == file_metadata.len())
}

#[cfg(test)]
fn verify_file_digest(path: &Path, expected: &str) -> Result<(), String> {
    let actual = sha256_file(path)?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "SHA-256 mismatch for {}: expected {expected}, observed {actual}",
            path.display()
        ))
    }
}

fn verify_file_digest_and_size(
    path: &Path,
    expected: &str,
    expected_bytes: u64,
) -> Result<(), String> {
    let _ = open_verified_archive(path, expected, expected_bytes)?;
    Ok(())
}

fn open_verified_archive(path: &Path, expected: &str, expected_bytes: u64) -> Result<File, String> {
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(format!(
            "LLVM archive {} is not a regular non-symlink file",
            path.display()
        ));
    }
    let mut file = File::open(path)
        .map_err(|error| format!("cannot open {} for verification: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("cannot inspect open archive {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() != expected_bytes {
        return Err(format!(
            "LLVM archive {} has {} bytes; expected {expected_bytes}",
            path.display(),
            metadata.len()
        ));
    }
    let actual = sha256_reader(&mut file)
        .map_err(|error| format!("cannot hash {}: {error}", path.display()))?;
    if actual != expected {
        return Err(format!(
            "SHA-256 mismatch for {}: expected {expected}, observed {actual}",
            path.display()
        ));
    }
    file.rewind()
        .map_err(|error| format!("cannot rewind verified archive {}: {error}", path.display()))?;
    Ok(file)
}

struct StagingDirectory {
    path: PathBuf,
    armed: bool,
}

impl StagingDirectory {
    fn create(root: &Path, key: &str) -> Result<Self, String> {
        let parent = root.join("build/toolchain/llvm/staging");
        ensure_non_symlink_directory_chain(root, Path::new("build/toolchain/llvm/staging"))?;
        cleanup_stale_staging_directories(&parent)?;
        let pid = std::process::id();
        let token = process_start_token(pid)?
            .ok_or_else(|| "cannot determine running xtask process start identity".to_owned())?;
        for attempt in 0_u32..128 {
            let path = parent.join(format!("{key}.{pid}.{token}.{attempt}"));
            match fs::create_dir(&path) {
                Ok(()) => {
                    sync_directory(&parent)?;
                    return Ok(Self { path, armed: true });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(format!(
                        "cannot create exclusive LLVM staging directory {}: {error}",
                        path.display()
                    ));
                }
            }
        }
        Err("cannot allocate an exclusive LLVM staging directory after 128 attempts".to_owned())
    }
}

impl Drop for StagingDirectory {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.path);
            if let Some(parent) = self.path.parent() {
                let _ = sync_directory(parent);
            }
        }
    }
}

fn cleanup_stale_staging_directories(parent: &Path) -> Result<(), String> {
    let mut entries = Vec::new();
    for entry in
        fs::read_dir(parent).map_err(|error| format!("cannot read LLVM staging parent: {error}"))?
    {
        if entries.len() >= MAX_STAGING_DIRECTORIES {
            return Err(format!(
                "LLVM staging parent exceeds {MAX_STAGING_DIRECTORIES} bounded entries"
            ));
        }
        entries.push(entry.map_err(|error| format!("cannot inspect LLVM staging entry: {error}"))?);
    }
    entries.sort_by_key(fs::DirEntry::file_name);
    let mut live = 0_usize;
    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "LLVM staging entry name is not UTF-8".to_owned())?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("cannot inspect LLVM staging entry {name:?}: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(format!(
                "LLVM staging entry {name:?} is not a non-symlink directory"
            ));
        }
        let (pid, token) = parse_staging_owner(&name).ok_or_else(|| {
            format!("LLVM staging entry {name:?} has an unrecognized ownership identity")
        })?;
        if process_start_token(pid)?.as_deref() == Some(token) {
            live = live
                .checked_add(1)
                .ok_or_else(|| "LLVM staging live-owner count overflow".to_owned())?;
            continue;
        }
        fs::remove_dir_all(entry.path()).map_err(|error| {
            format!("cannot remove crashed LLVM staging entry {name:?}: {error}")
        })?;
        sync_directory(parent)?;
    }
    if live >= MAX_STAGING_DIRECTORIES {
        return Err(format!(
            "LLVM staging parent already contains {live} live builds"
        ));
    }
    Ok(())
}

fn parse_staging_owner(name: &str) -> Option<(u32, &str)> {
    let mut pieces = name.rsplitn(4, '.');
    let attempt = pieces.next()?;
    let token = pieces.next()?;
    let pid = pieces.next()?;
    let key = pieces.next()?;
    let (_, key_digest) = key.rsplit_once('-')?;
    if attempt.parse::<u32>().ok()? >= 128 || !valid_sha256(token) || !valid_sha256(key_digest) {
        return None;
    }
    Some((pid.parse::<u32>().ok()?, token))
}

fn process_start_token(pid: u32) -> Result<Option<String>, String> {
    if pid == 0 {
        return Ok(None);
    }
    let pid_text = pid.to_string();
    let mut command = Command::new("/bin/ps");
    command
        .args(["-p", &pid_text, "-o", "lstart="])
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("TZ", "UTC")
        .stdin(Stdio::null());
    let (status, stdout, stderr) = run_bounded_output(
        &mut command,
        4096,
        std::time::Duration::from_secs(5),
        "fixed /bin/ps process-start probe",
    )?;
    let start = std::str::from_utf8(&stdout)
        .map_err(|_| "fixed /bin/ps returned non-UTF-8 process identity".to_owned())?
        .trim();
    if !status.success() {
        if start.is_empty() {
            return Ok(None);
        }
        return Err(format!(
            "fixed /bin/ps process-start probe failed with {status}: {}",
            String::from_utf8_lossy(&stderr)
        ));
    }
    if !stderr.is_empty() || start.is_empty() || start.chars().any(char::is_control) {
        return Err("fixed /bin/ps returned an invalid process-start identity".to_owned());
    }
    Ok(Some(sha256_bytes(start.as_bytes())))
}

fn extract_verified_archive(
    archive: File,
    xz: &Path,
    destination: &Path,
    lock: &LlvmLock,
) -> Result<(), String> {
    // The caller has already streamed and compared the complete compressed
    // archive SHA-256. Only those verified bytes reach the decompressor.
    let mut child = Command::new(xz)
        .args([
            OsStr::new("--decompress"),
            OsStr::new("--stdout"),
            OsStr::new("--threads=1"),
            OsStr::new("--memlimit-decompress=1GiB"),
        ])
        .env_clear()
        .env("LC_ALL", "C")
        .env("PATH", "/wrela/no-ambient-path")
        .stdin(Stdio::from(archive))
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|error| format!("cannot execute verified xz decompressor: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "xz decompressor did not expose stdout".to_owned())?;
    let expected_root = format!("llvm-project-{}.src", lock.version);
    let omitted_symlinks = omitted_symlink_policy(lock)?;
    let extraction = extract_tar_stream(
        BufReader::new(stdout),
        destination,
        &expected_root,
        Some(&lock.commit),
        omitted_symlinks,
    );
    if extraction.is_err() {
        let _ = child.kill();
    }
    let status = child
        .wait()
        .map_err(|error| format!("cannot wait for xz decompressor: {error}"))?;
    extraction?;
    if !status.success() {
        return Err(format!("xz decompressor failed with {status}"));
    }
    Ok(())
}

#[derive(Debug)]
struct TarState {
    members: u64,
    total_bytes: u64,
    paths: BTreeSet<String>,
    portable_paths: BTreeSet<String>,
    pending_path: Option<String>,
    global_pax_seen: bool,
    omitted_symlinks: BTreeSet<String>,
}

fn extract_tar_stream(
    mut reader: impl Read,
    destination: &Path,
    expected_root: &str,
    expected_global_comment: Option<&str>,
    omitted_symlinks: &[(&str, &str)],
) -> Result<(), String> {
    if omitted_symlinks
        .windows(2)
        .any(|pair| pair[0].0 >= pair[1].0)
    {
        return Err("verified symlink omission policy is not sorted and unique".to_owned());
    }
    let expected_symlinks: BTreeMap<_, _> = omitted_symlinks.iter().copied().collect();
    if expected_symlinks.len() != omitted_symlinks.len() {
        return Err("verified symlink omission policy contains duplicates".to_owned());
    }
    let mut state = TarState {
        members: 0,
        total_bytes: 0,
        paths: BTreeSet::new(),
        portable_paths: BTreeSet::new(),
        pending_path: None,
        global_pax_seen: false,
        omitted_symlinks: BTreeSet::new(),
    };
    let mut zero_blocks = 0_u8;
    loop {
        let Some(header) = read_tar_block(&mut reader)? else {
            return Err("tar archive ended before its two zero terminators".to_owned());
        };
        if header.iter().all(|byte| *byte == 0) {
            zero_blocks += 1;
            if zero_blocks == 2 {
                break;
            }
            continue;
        }
        if zero_blocks != 0 {
            return Err("tar archive has a nonzero block after its first terminator".to_owned());
        }
        validate_tar_checksum(&header)?;
        if &header[257..262] != b"ustar" {
            return Err("tar member does not use the ustar/GNU header contract".to_owned());
        }
        state.members = state
            .members
            .checked_add(1)
            .ok_or_else(|| "tar member count overflow".to_owned())?;
        if state.members > MAX_ARCHIVE_MEMBERS {
            return Err(format!("tar archive exceeds {MAX_ARCHIVE_MEMBERS} members"));
        }
        let size = parse_tar_octal(&header[124..136], "member size")?;
        if size > MAX_ARCHIVE_FILE_BYTES {
            return Err(format!("tar member exceeds {MAX_ARCHIVE_FILE_BYTES} bytes"));
        }
        state.total_bytes = state
            .total_bytes
            .checked_add(size)
            .ok_or_else(|| "tar aggregate byte count overflow".to_owned())?;
        if state.total_bytes > MAX_ARCHIVE_TOTAL_BYTES {
            return Err(format!(
                "tar archive exceeds {MAX_ARCHIVE_TOTAL_BYTES} payload bytes"
            ));
        }
        let kind = header[156];
        let header_path = tar_header_path(&header)?;
        if kind == b'g' {
            if state.global_pax_seen
                || state.members != 1
                || state.pending_path.is_some()
                || header_path != "pax_global_header"
                || size > MAX_PAX_BYTES
            {
                return Err("unexpected or oversized global PAX metadata".to_owned());
            }
            let expected = expected_global_comment.ok_or_else(|| {
                "global PAX metadata is forbidden without an exact commit policy".to_owned()
            })?;
            let data = read_tar_payload(&mut reader, size)?;
            validate_global_pax(&data, expected)?;
            state.global_pax_seen = true;
            continue;
        }
        validate_archive_path(&header_path, expected_root)?;
        match kind {
            b'x' => {
                if state.pending_path.is_some() || size > MAX_PAX_BYTES {
                    return Err("nested or oversized PAX metadata is forbidden".to_owned());
                }
                let data = read_tar_payload(&mut reader, size)?;
                state.pending_path = parse_pax_path(&data)?;
            }
            b'L' => {
                if state.pending_path.is_some() || size > MAX_PAX_BYTES {
                    return Err(
                        "nested or oversized GNU long-name metadata is forbidden".to_owned()
                    );
                }
                let data = read_tar_payload(&mut reader, size)?;
                state.pending_path = Some(parse_gnu_long_name(&data)?);
            }
            b'0' | 0 | b'5' => {
                let selected_path = state.pending_path.take().unwrap_or(header_path);
                let relative = validate_archive_path(&selected_path, expected_root)?;
                extract_tar_member(
                    &mut reader,
                    destination,
                    relative.as_deref(),
                    kind,
                    size,
                    &header,
                    &mut state,
                )?;
            }
            b'1' => return Err("tar hard-link members are forbidden".to_owned()),
            b'2' => {
                let selected_path = state.pending_path.take().unwrap_or(header_path);
                let relative = validate_archive_path(&selected_path, expected_root)?
                    .ok_or_else(|| "tar archive root cannot be a symbolic link".to_owned())?;
                omit_verified_symlink(
                    &mut reader,
                    &relative,
                    size,
                    &header,
                    &expected_symlinks,
                    &mut state,
                )?;
            }
            b'3' | b'4' | b'6' => {
                return Err("tar device and FIFO members are forbidden".to_owned());
            }
            b'S' => return Err("GNU sparse tar members are forbidden".to_owned()),
            _ => return Err(format!("unsupported tar member type 0x{kind:02x}")),
        }
    }
    if state.pending_path.is_some() {
        return Err("tar archive ended with unapplied path metadata".to_owned());
    }
    if expected_global_comment.is_some() && !state.global_pax_seen {
        return Err("verified archive lacks its required global PAX commit metadata".to_owned());
    }
    let expected_paths: BTreeSet<_> = expected_symlinks
        .keys()
        .map(|path| (*path).to_owned())
        .collect();
    if state.omitted_symlinks != expected_paths {
        return Err(
            "verified archive did not contain the exact omitted symlink inventory".to_owned(),
        );
    }
    let mut trailing = [0_u8; 64 * 1024];
    let mut trailing_bytes = 0_u64;
    loop {
        let read = reader
            .read(&mut trailing)
            .map_err(|error| format!("cannot read tar trailer: {error}"))?;
        if read == 0 {
            break;
        }
        trailing_bytes = trailing_bytes
            .checked_add(u64::try_from(read).map_err(|_| "tar trailer length overflow".to_owned())?)
            .ok_or_else(|| "tar trailer length overflow".to_owned())?;
        if trailing_bytes > MAX_TAR_TRAILER_BYTES {
            return Err(format!(
                "tar zero trailer exceeds {MAX_TAR_TRAILER_BYTES} bytes"
            ));
        }
        if trailing[..read].iter().any(|byte| *byte != 0) {
            return Err("tar archive has nonzero trailing data".to_owned());
        }
    }
    if state.members == 0 {
        return Err("tar archive is empty".to_owned());
    }
    Ok(())
}

fn omitted_symlink_policy(
    lock: &LlvmLock,
) -> Result<&'static [(&'static str, &'static str)], String> {
    if lock.version == "22.1.3"
        && lock.sha256 == LLVM_22_1_3_SHA256
        && lock.commit == "e9846648fd6183ee6d8cbdb4502213fcf902a211"
    {
        Ok(LLVM_22_1_3_OMITTED_SYMLINKS)
    } else {
        Ok(&[])
    }
}

fn omit_verified_symlink(
    reader: &mut impl Read,
    relative: &str,
    size: u64,
    header: &[u8; 512],
    expected: &BTreeMap<&str, &str>,
    state: &mut TarState,
) -> Result<(), String> {
    if size != 0 {
        return Err("tar symbolic-link member has a nonzero payload".to_owned());
    }
    let target = tar_text_field(&header[157..257], "symbolic-link target")?;
    if expected.get(relative).copied() != Some(target) {
        return Err(format!(
            "unreviewed tar symbolic-link member {relative:?} -> {target:?}"
        ));
    }
    if !state.paths.insert(relative.to_owned()) {
        return Err(format!("duplicate tar member path {relative:?}"));
    }
    if !state.portable_paths.insert(relative.to_ascii_lowercase()) {
        return Err(format!("portable tar path collision for {relative:?}"));
    }
    if !state.omitted_symlinks.insert(relative.to_owned()) {
        return Err(format!(
            "duplicate omitted symbolic-link member {relative:?}"
        ));
    }
    skip_tar_padding(reader, size)
}

fn extract_tar_member(
    reader: &mut impl Read,
    destination: &Path,
    relative: Option<&str>,
    kind: u8,
    size: u64,
    header: &[u8; 512],
    state: &mut TarState,
) -> Result<(), String> {
    let directory = kind == b'5';
    if directory && size != 0 {
        return Err("tar directory member has a nonzero payload".to_owned());
    }
    let Some(relative) = relative else {
        if !directory {
            return Err("tar archive root must be a directory".to_owned());
        }
        skip_tar_padding(reader, size)?;
        return Ok(());
    };
    if !state.paths.insert(relative.to_owned()) {
        return Err(format!("duplicate tar member path {relative:?}"));
    }
    if !state.portable_paths.insert(relative.to_ascii_lowercase()) {
        return Err(format!("portable tar path collision for {relative:?}"));
    }
    let output = destination.join(relative);
    if !output.starts_with(destination) {
        return Err("tar member escaped extraction root".to_owned());
    }
    if directory {
        fs::create_dir_all(&output)
            .map_err(|error| format!("cannot create extracted directory {relative:?}: {error}"))?;
        skip_tar_padding(reader, size)?;
        return Ok(());
    }
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create parent for {relative:?}: {error}"))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output)
        .map_err(|error| format!("cannot create extracted file {relative:?}: {error}"))?;
    copy_exact(reader, &mut file, size)?;
    set_extracted_permissions(&output, parse_tar_octal(&header[100..108], "member mode")?)?;
    skip_tar_padding(reader, size)
}

fn read_tar_block(reader: &mut impl Read) -> Result<Option<[u8; 512]>, String> {
    let mut block = [0_u8; 512];
    let mut filled = 0_usize;
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
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "tar header checksum mismatch: expected {expected}, observed {actual}"
        ))
    }
}

fn parse_tar_octal(field: &[u8], label: &str) -> Result<u64, String> {
    if field.first().is_some_and(|byte| byte & 0x80 != 0) {
        return Err(format!("base-256 tar {label} is forbidden"));
    }
    let value = field
        .iter()
        .copied()
        .skip_while(|byte| matches!(byte, b' ' | 0))
        .take_while(|byte| !matches!(byte, b' ' | 0))
        .try_fold(0_u64, |current, byte| {
            if !(b'0'..=b'7').contains(&byte) {
                return Err(format!("invalid octal tar {label}"));
            }
            current
                .checked_mul(8)
                .and_then(|value| value.checked_add(u64::from(byte - b'0')))
                .ok_or_else(|| format!("tar {label} overflow"))
        })?;
    Ok(value)
}

fn tar_header_path(header: &[u8; 512]) -> Result<String, String> {
    let name = tar_text_field(&header[0..100], "member name")?;
    let prefix = tar_text_field(&header[345..500], "member prefix")?;
    if name.is_empty() {
        return Err("tar member name is empty".to_owned());
    }
    let path = if prefix.is_empty() {
        name.to_owned()
    } else {
        format!("{prefix}/{name}")
    };
    if path.len() > MAX_ARCHIVE_PATH_BYTES {
        return Err(format!(
            "tar member path exceeds {MAX_ARCHIVE_PATH_BYTES} bytes"
        ));
    }
    Ok(path)
}

fn tar_text_field<'a>(field: &'a [u8], label: &str) -> Result<&'a str, String> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    let value =
        std::str::from_utf8(&field[..end]).map_err(|_| format!("tar {label} is not UTF-8"))?;
    if value.chars().any(char::is_control) {
        return Err(format!("tar {label} contains a control character"));
    }
    Ok(value)
}

fn validate_archive_path(path: &str, expected_root: &str) -> Result<Option<String>, String> {
    if path.is_empty()
        || path.len() > MAX_ARCHIVE_PATH_BYTES
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.contains('\\')
        || path.contains(':')
        || path.chars().any(char::is_control)
    {
        return Err(format!("unsafe tar member path {path:?}"));
    }
    let path = path.strip_suffix('/').unwrap_or(path);
    let mut components = path.split('/');
    let root = components
        .next()
        .ok_or_else(|| "tar member path is empty".to_owned())?;
    if root != expected_root {
        return Err(format!(
            "tar member root {root:?} does not match {expected_root:?}"
        ));
    }
    let mut relative = String::new();
    for component in components {
        if component.is_empty() || matches!(component, "." | "..") {
            return Err(format!("unsafe tar member path {path:?}"));
        }
        if !relative.is_empty() {
            relative.push('/');
        }
        relative.push_str(component);
    }
    if relative.is_empty() {
        Ok(None)
    } else {
        let native = Path::new(&relative);
        if native
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(format!("unsafe native tar path {path:?}"));
        }
        Ok(Some(relative))
    }
}

fn read_tar_payload(reader: &mut impl Read, size: u64) -> Result<Vec<u8>, String> {
    let capacity = usize::try_from(size).map_err(|_| "tar metadata is too large".to_owned())?;
    let mut payload = Vec::new();
    payload
        .try_reserve_exact(capacity)
        .map_err(|_| "cannot reserve tar metadata buffer".to_owned())?;
    let mut limited = reader.take(size);
    limited
        .read_to_end(&mut payload)
        .map_err(|error| format!("cannot read tar metadata: {error}"))?;
    if payload.len() != capacity {
        return Err("truncated tar metadata payload".to_owned());
    }
    skip_tar_padding(reader, size)?;
    Ok(payload)
}

fn parse_gnu_long_name(bytes: &[u8]) -> Result<String, String> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    if bytes[end..].iter().any(|byte| *byte != 0)
        || bytes[..end].last().is_some_and(|byte| *byte == b'\n')
    {
        return Err("noncanonical GNU long-name payload".to_owned());
    }
    let path = std::str::from_utf8(&bytes[..end])
        .map_err(|_| "GNU long-name path is not UTF-8".to_owned())?;
    if path.is_empty() || path.len() > MAX_ARCHIVE_PATH_BYTES {
        return Err("GNU long-name path is empty or oversized".to_owned());
    }
    Ok(path.to_owned())
}

fn parse_pax_path(bytes: &[u8]) -> Result<Option<String>, String> {
    let mut values = parse_pax_fields(bytes)?;
    if values.keys().any(|key| *key != "path") {
        return Err(format!(
            "unsupported local PAX keys: {:?}",
            values.keys().collect::<Vec<_>>()
        ));
    }
    values
        .remove("path")
        .map(|path| {
            if path.is_empty() || path.len() > MAX_ARCHIVE_PATH_BYTES {
                Err("PAX path is empty or oversized".to_owned())
            } else {
                Ok(path.to_owned())
            }
        })
        .transpose()
}

fn validate_global_pax(bytes: &[u8], expected_comment: &str) -> Result<(), String> {
    let mut values = parse_pax_fields(bytes)?;
    let comment = values
        .remove("comment")
        .ok_or_else(|| "global PAX metadata lacks its release commit comment".to_owned())?;
    if !values.is_empty() || comment != expected_comment {
        return Err("unexpected global PAX metadata".to_owned());
    }
    Ok(())
}

fn parse_pax_fields(bytes: &[u8]) -> Result<BTreeMap<&str, &str>, String> {
    let mut cursor = 0_usize;
    let mut values = BTreeMap::new();
    while cursor < bytes.len() {
        let space = bytes[cursor..]
            .iter()
            .position(|byte| *byte == b' ')
            .map(|offset| cursor + offset)
            .ok_or_else(|| "malformed PAX record length".to_owned())?;
        let length_text = std::str::from_utf8(&bytes[cursor..space])
            .map_err(|_| "PAX record length is not ASCII".to_owned())?;
        if length_text.is_empty() || (length_text.len() > 1 && length_text.starts_with('0')) {
            return Err("noncanonical PAX record length".to_owned());
        }
        let length = length_text
            .parse::<usize>()
            .map_err(|_| "invalid PAX record length".to_owned())?;
        if length == 0
            || cursor
                .checked_add(length)
                .is_none_or(|end| end > bytes.len())
        {
            return Err("PAX record length escapes metadata payload".to_owned());
        }
        let end = cursor + length;
        if bytes[end - 1] != b'\n' {
            return Err("PAX record lacks newline terminator".to_owned());
        }
        let record = &bytes[space + 1..end - 1];
        let equals = record
            .iter()
            .position(|byte| *byte == b'=')
            .ok_or_else(|| "PAX record lacks key/value separator".to_owned())?;
        let key = std::str::from_utf8(&record[..equals])
            .map_err(|_| "PAX key is not UTF-8".to_owned())?;
        let value = std::str::from_utf8(&record[equals + 1..])
            .map_err(|_| "PAX value is not UTF-8".to_owned())?;
        if key.is_empty()
            || key.chars().any(char::is_control)
            || value.chars().any(char::is_control)
        {
            return Err("PAX record contains an invalid key or value".to_owned());
        }
        if values.insert(key, value).is_some() {
            return Err(format!("duplicate PAX key {key:?}"));
        }
        cursor = end;
    }
    Ok(values)
}

fn copy_exact(reader: &mut impl Read, writer: &mut impl Write, size: u64) -> Result<(), String> {
    let mut remaining = size;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining != 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| "tar copy length does not fit usize".to_owned())?;
        let read = reader
            .read(&mut buffer[..wanted])
            .map_err(|error| format!("cannot read tar member payload: {error}"))?;
        if read == 0 {
            return Err("truncated tar member payload".to_owned());
        }
        writer
            .write_all(&buffer[..read])
            .map_err(|error| format!("cannot write extracted member: {error}"))?;
        remaining -= u64::try_from(read).map_err(|_| "tar read count overflow".to_owned())?;
    }
    Ok(())
}

fn skip_tar_padding(reader: &mut impl Read, size: u64) -> Result<(), String> {
    let padding = (512 - (size % 512)) % 512;
    let mut buffer = [0_u8; 512];
    let length = usize::try_from(padding).map_err(|_| "tar padding overflow".to_owned())?;
    reader
        .read_exact(&mut buffer[..length])
        .map_err(|error| format!("truncated tar padding: {error}"))?;
    Ok(())
}

#[cfg(unix)]
fn set_extracted_permissions(path: &Path, archive_mode: u64) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if archive_mode & 0o111 == 0 {
        0o644
    } else {
        0o755
    };
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| format!("cannot set permissions on {}: {error}", path.display()))
}

#[cfg(not(unix))]
fn set_extracted_permissions(_path: &Path, _archive_mode: u64) -> Result<(), String> {
    Ok(())
}

#[derive(Debug)]
struct TreeEntry {
    relative: String,
    path: PathBuf,
    bytes: u64,
    mode: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    directory: bool,
}

fn measure_tree(root: &Path) -> Result<TreeMeasurement, String> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| format!("cannot inspect native prefix {}: {error}", root.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "native prefix {} is not a non-symlink directory",
            root.display()
        ));
    }
    let (modified_seconds, modified_nanoseconds) = metadata_timestamp(&metadata);
    let mut entries = vec![TreeEntry {
        relative: String::new(),
        path: root.to_owned(),
        bytes: 0,
        mode: permission_mode(&metadata),
        modified_seconds,
        modified_nanoseconds,
        directory: true,
    }];
    let mut inventory_bytes = 0_u64;
    let mut inventory_entries = 1_u64;
    collect_tree_entries(
        root,
        root,
        &mut entries,
        &mut inventory_bytes,
        &mut inventory_entries,
        0,
    )?;
    entries.sort_by(|first, second| first.relative.cmp(&second.relative));
    let mut hasher = Sha256::new();
    hasher.update(TREE_MAGIC);
    hasher.update(TREE_VERSION.to_le_bytes());
    let mut total_files = 0_u64;
    let mut total_bytes = 0_u64;
    for entry in &entries {
        let path_bytes = entry.relative.as_bytes();
        let path_length = u32::try_from(path_bytes.len())
            .map_err(|_| "native prefix path exceeds u32".to_owned())?;
        hasher.update([if entry.directory { b'D' } else { b'F' }]);
        hasher.update(path_length.to_le_bytes());
        hasher.update(path_bytes);
        hasher.update(entry.mode.to_le_bytes());
        hasher.update(entry.modified_seconds.to_le_bytes());
        hasher.update(entry.modified_nanoseconds.to_le_bytes());
        if !entry.directory {
            total_files = total_files
                .checked_add(1)
                .ok_or_else(|| "native prefix file count overflow".to_owned())?;
            total_bytes = total_bytes
                .checked_add(entry.bytes)
                .ok_or_else(|| "native prefix byte count overflow".to_owned())?;
            if total_bytes > MAX_PREFIX_BYTES {
                return Err(format!("native prefix exceeds {MAX_PREFIX_BYTES} bytes"));
            }
            hasher.update(entry.bytes.to_le_bytes());
            let digest = sha256_file(&entry.path)?;
            hasher.update(digest.as_bytes());
        }
    }
    Ok(TreeMeasurement {
        digest: lower_hex(&hasher.finalize()),
        files: total_files,
        bytes: total_bytes,
    })
}

fn collect_tree_entries(
    root: &Path,
    directory: &Path,
    output: &mut Vec<TreeEntry>,
    total_bytes: &mut u64,
    total_entries: &mut u64,
    depth: u32,
) -> Result<(), String> {
    if depth > MAX_PREFIX_DEPTH {
        return Err(format!(
            "native prefix exceeds directory depth {MAX_PREFIX_DEPTH}"
        ));
    }
    let mut entries = Vec::new();
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("cannot read native prefix {}: {error}", directory.display()))?
    {
        *total_entries = total_entries
            .checked_add(1)
            .ok_or_else(|| "native prefix entry count overflow".to_owned())?;
        if *total_entries > MAX_PREFIX_FILES {
            return Err(format!("native prefix exceeds {MAX_PREFIX_FILES} entries"));
        }
        entries
            .try_reserve(1)
            .map_err(|_| "cannot reserve native prefix directory inventory".to_owned())?;
        entries
            .push(entry.map_err(|error| format!("cannot inspect native prefix entry: {error}"))?);
    }
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!("native prefix contains symlink {}", path.display()));
        }
        let relative = path
            .strip_prefix(root)
            .map_err(|_| format!("native prefix entry escaped root: {}", path.display()))?;
        let relative = relative
            .to_str()
            .ok_or_else(|| format!("native prefix path is not UTF-8: {}", path.display()))?
            .replace(std::path::MAIN_SEPARATOR, "/");
        if relative.is_empty() || relative.len() > MAX_PREFIX_PATH_BYTES {
            return Err(format!(
                "native prefix path is invalid or oversized: {relative:?}"
            ));
        }
        if metadata.is_dir() {
            let (modified_seconds, modified_nanoseconds) = metadata_timestamp(&metadata);
            output
                .try_reserve(1)
                .map_err(|_| "cannot reserve native prefix inventory".to_owned())?;
            output.push(TreeEntry {
                relative,
                path: path.clone(),
                bytes: 0,
                mode: permission_mode(&metadata),
                modified_seconds,
                modified_nanoseconds,
                directory: true,
            });
            collect_tree_entries(root, &path, output, total_bytes, total_entries, depth + 1)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(format!(
                "native prefix contains unsupported entry {}",
                path.display()
            ));
        }
        *total_bytes = total_bytes
            .checked_add(metadata.len())
            .ok_or_else(|| "native prefix byte count overflow".to_owned())?;
        if *total_bytes > MAX_PREFIX_BYTES {
            return Err(format!("native prefix exceeds {MAX_PREFIX_BYTES} bytes"));
        }
        if output.len() as u64 >= MAX_PREFIX_FILES {
            return Err(format!("native prefix exceeds {MAX_PREFIX_FILES} files"));
        }
        output
            .try_reserve(1)
            .map_err(|_| "cannot reserve native prefix inventory".to_owned())?;
        let (modified_seconds, modified_nanoseconds) = metadata_timestamp(&metadata);
        output.push(TreeEntry {
            relative,
            path,
            bytes: metadata.len(),
            mode: permission_mode(&metadata),
            modified_seconds,
            modified_nanoseconds,
            directory: false,
        });
    }
    Ok(())
}

#[cfg(unix)]
fn permission_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn permission_mode(_metadata: &fs::Metadata) -> u32 {
    0
}

#[cfg(unix)]
fn metadata_timestamp(metadata: &fs::Metadata) -> (i64, i64) {
    use std::os::unix::fs::MetadataExt;
    (metadata.mtime(), metadata.mtime_nsec())
}

#[cfg(not(unix))]
fn metadata_timestamp(_metadata: &fs::Metadata) -> (i64, i64) {
    (0, 0)
}

fn receipt_for_plan(plan: &BuildPlan, measurement: &TreeMeasurement) -> ProvenanceReceipt {
    ProvenanceReceipt {
        input_digest: plan.input_digest.clone(),
        llvm_version: plan.lock.version.clone(),
        llvm_tag: plan.lock.tag.clone(),
        llvm_commit: plan.lock.commit.clone(),
        source_url: plan.lock.source.clone(),
        archive_sha256: plan.lock.sha256.clone(),
        archive_bytes: plan.lock.archive_bytes,
        lock_sha256: plan.lock_digest.clone(),
        cmake_sha256: plan.cmake_digest.clone(),
        codegen_binding_sha256: plan.codegen_binding_digest.clone(),
        rust_binding_sha256: plan.rust_binding_digest.clone(),
        flags_sha256: plan.flags_digest.clone(),
        implementation_sha256: plan.implementation_digest.clone(),
        host: plan.host.clone(),
        xz_sha256: plan.tools.xz.digest.clone(),
        cmake_tool_sha256: plan.tools.cmake.digest.clone(),
        ninja_sha256: plan.tools.ninja.digest.clone(),
        cc_sha256: plan.tools.cc.digest.clone(),
        cxx_sha256: plan.tools.cxx.digest.clone(),
        ar_sha256: plan.tools.ar.digest.clone(),
        ranlib_sha256: plan.tools.ranlib.digest.clone(),
        python_sha256: plan.tools.python.digest.clone(),
        linker_sha256: plan.tools.linker.digest.clone(),
        sysroot_sha256: plan.tools.sysroot.as_ref().map_or_else(
            || sha256_bytes(b"wrela:no-host-sysroot"),
            |value| value.digest.clone(),
        ),
        touch_sha256: plan.tools.touch.digest.clone(),
        shell_sha256: plan.tools.shell.digest.clone(),
        host_closure_sha256: plan.tools.host_closure.digest.clone(),
        prefix_tree_sha256: measurement.digest.clone(),
        prefix_files: measurement.files,
        prefix_bytes: measurement.bytes,
    }
}

fn encode_receipt(receipt: &ProvenanceReceipt) -> Vec<u8> {
    format!(
        "schema={RECEIPT_SCHEMA}\ninput_digest={}\nllvm_version={}\nllvm_tag={}\nllvm_commit={}\nsource_url={}\narchive_sha256={}\narchive_bytes={}\nlock_sha256={}\ncmake_sha256={}\ncodegen_binding_sha256={}\nrust_binding_sha256={}\nflags_sha256={}\nimplementation_sha256={}\nhost={}\nxz_sha256={}\ncmake_tool_sha256={}\nninja_sha256={}\ncc_sha256={}\ncxx_sha256={}\nar_sha256={}\nranlib_sha256={}\npython_sha256={}\nlinker_sha256={}\nsysroot_sha256={}\ntouch_sha256={}\nshell_sha256={}\nhost_closure_sha256={}\nprefix_tree_sha256={}\nprefix_files={}\nprefix_bytes={}\n",
        receipt.input_digest,
        receipt.llvm_version,
        receipt.llvm_tag,
        receipt.llvm_commit,
        receipt.source_url,
        receipt.archive_sha256,
        receipt.archive_bytes,
        receipt.lock_sha256,
        receipt.cmake_sha256,
        receipt.codegen_binding_sha256,
        receipt.rust_binding_sha256,
        receipt.flags_sha256,
        receipt.implementation_sha256,
        receipt.host,
        receipt.xz_sha256,
        receipt.cmake_tool_sha256,
        receipt.ninja_sha256,
        receipt.cc_sha256,
        receipt.cxx_sha256,
        receipt.ar_sha256,
        receipt.ranlib_sha256,
        receipt.python_sha256,
        receipt.linker_sha256,
        receipt.sysroot_sha256,
        receipt.touch_sha256,
        receipt.shell_sha256,
        receipt.host_closure_sha256,
        receipt.prefix_tree_sha256,
        receipt.prefix_files,
        receipt.prefix_bytes,
    )
    .into_bytes()
}

fn decode_receipt(bytes: &[u8]) -> Result<ProvenanceReceipt, String> {
    let source = std::str::from_utf8(bytes)
        .map_err(|_| "LLVM provenance receipt is not UTF-8".to_owned())?;
    if !source.ends_with('\n') {
        return Err("LLVM provenance receipt lacks canonical final newline".to_owned());
    }
    let mut fields = BTreeMap::new();
    for line in source.lines() {
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| "malformed LLVM provenance receipt assignment".to_owned())?;
        if key.is_empty()
            || value.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            || value.chars().any(char::is_control)
        {
            return Err("invalid LLVM provenance receipt atom".to_owned());
        }
        if fields.insert(key, value).is_some() {
            return Err(format!("duplicate LLVM provenance field {key}"));
        }
    }
    let schema = take_receipt_field(&mut fields, "schema")?
        .parse::<u32>()
        .map_err(|_| "invalid provenance schema".to_owned())?;
    if schema != RECEIPT_SCHEMA {
        return Err(format!("unsupported LLVM provenance schema {schema}"));
    }
    let receipt = ProvenanceReceipt {
        input_digest: take_receipt_field(&mut fields, "input_digest")?.to_owned(),
        llvm_version: take_receipt_field(&mut fields, "llvm_version")?.to_owned(),
        llvm_tag: take_receipt_field(&mut fields, "llvm_tag")?.to_owned(),
        llvm_commit: take_receipt_field(&mut fields, "llvm_commit")?.to_owned(),
        source_url: take_receipt_field(&mut fields, "source_url")?.to_owned(),
        archive_sha256: take_receipt_field(&mut fields, "archive_sha256")?.to_owned(),
        archive_bytes: take_receipt_field(&mut fields, "archive_bytes")?
            .parse::<u64>()
            .map_err(|_| "invalid provenance archive_bytes".to_owned())?,
        lock_sha256: take_receipt_field(&mut fields, "lock_sha256")?.to_owned(),
        cmake_sha256: take_receipt_field(&mut fields, "cmake_sha256")?.to_owned(),
        codegen_binding_sha256: take_receipt_field(&mut fields, "codegen_binding_sha256")?
            .to_owned(),
        rust_binding_sha256: take_receipt_field(&mut fields, "rust_binding_sha256")?.to_owned(),
        flags_sha256: take_receipt_field(&mut fields, "flags_sha256")?.to_owned(),
        implementation_sha256: take_receipt_field(&mut fields, "implementation_sha256")?.to_owned(),
        host: take_receipt_field(&mut fields, "host")?.to_owned(),
        xz_sha256: take_receipt_field(&mut fields, "xz_sha256")?.to_owned(),
        cmake_tool_sha256: take_receipt_field(&mut fields, "cmake_tool_sha256")?.to_owned(),
        ninja_sha256: take_receipt_field(&mut fields, "ninja_sha256")?.to_owned(),
        cc_sha256: take_receipt_field(&mut fields, "cc_sha256")?.to_owned(),
        cxx_sha256: take_receipt_field(&mut fields, "cxx_sha256")?.to_owned(),
        ar_sha256: take_receipt_field(&mut fields, "ar_sha256")?.to_owned(),
        ranlib_sha256: take_receipt_field(&mut fields, "ranlib_sha256")?.to_owned(),
        python_sha256: take_receipt_field(&mut fields, "python_sha256")?.to_owned(),
        linker_sha256: take_receipt_field(&mut fields, "linker_sha256")?.to_owned(),
        sysroot_sha256: take_receipt_field(&mut fields, "sysroot_sha256")?.to_owned(),
        touch_sha256: take_receipt_field(&mut fields, "touch_sha256")?.to_owned(),
        shell_sha256: take_receipt_field(&mut fields, "shell_sha256")?.to_owned(),
        host_closure_sha256: take_receipt_field(&mut fields, "host_closure_sha256")?.to_owned(),
        prefix_tree_sha256: take_receipt_field(&mut fields, "prefix_tree_sha256")?.to_owned(),
        prefix_files: take_receipt_field(&mut fields, "prefix_files")?
            .parse::<u64>()
            .map_err(|_| "invalid provenance prefix_files".to_owned())?,
        prefix_bytes: take_receipt_field(&mut fields, "prefix_bytes")?
            .parse::<u64>()
            .map_err(|_| "invalid provenance prefix_bytes".to_owned())?,
    };
    if !fields.is_empty() {
        return Err(format!(
            "unknown LLVM provenance fields: {:?}",
            fields.keys().collect::<Vec<_>>()
        ));
    }
    for digest in [
        &receipt.input_digest,
        &receipt.archive_sha256,
        &receipt.lock_sha256,
        &receipt.cmake_sha256,
        &receipt.codegen_binding_sha256,
        &receipt.rust_binding_sha256,
        &receipt.flags_sha256,
        &receipt.implementation_sha256,
        &receipt.xz_sha256,
        &receipt.cmake_tool_sha256,
        &receipt.ninja_sha256,
        &receipt.cc_sha256,
        &receipt.cxx_sha256,
        &receipt.ar_sha256,
        &receipt.ranlib_sha256,
        &receipt.python_sha256,
        &receipt.linker_sha256,
        &receipt.sysroot_sha256,
        &receipt.touch_sha256,
        &receipt.shell_sha256,
        &receipt.host_closure_sha256,
        &receipt.prefix_tree_sha256,
    ] {
        if !valid_sha256(digest) {
            return Err("LLVM provenance receipt contains an invalid digest".to_owned());
        }
    }
    if receipt.llvm_commit.len() != 40
        || !receipt
            .llvm_commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || !(1..=MAX_ARCHIVE_COMPRESSED_BYTES).contains(&receipt.archive_bytes)
    {
        return Err("LLVM provenance receipt contains invalid source metadata".to_owned());
    }
    if receipt.prefix_files == 0 || receipt.prefix_bytes == 0 {
        return Err("LLVM provenance receipt contains an empty prefix".to_owned());
    }
    if encode_receipt(&receipt) != bytes {
        return Err("LLVM provenance receipt is noncanonical".to_owned());
    }
    Ok(receipt)
}

fn take_receipt_field<'a>(
    fields: &mut BTreeMap<&'a str, &'a str>,
    key: &str,
) -> Result<&'a str, String> {
    fields
        .remove(key)
        .ok_or_else(|| format!("LLVM provenance receipt is missing {key}"))
}

fn verify_published_bundle(plan: &BuildPlan) -> Result<Option<PathBuf>, String> {
    validate_plan_prefix_cache(plan)?;
    let expected_output = plan.expected_output.as_ref().ok_or_else(|| {
        "trusted toolchain/llvm.outputs.toml is absent; cached LLVM reuse is forbidden".to_owned()
    })?;
    if !plan.bundle.exists() {
        return Ok(None);
    }
    let metadata = fs::symlink_metadata(&plan.bundle).map_err(|error| {
        format!(
            "cannot inspect published LLVM bundle {}: {error}",
            plan.bundle.display()
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "published LLVM bundle {} is not a non-symlink directory",
            plan.bundle.display()
        ));
    }
    let observed = measure_tree(&plan.prefix)?;
    validate_expected_measurement(expected_output, &observed)?;
    let trusted_measurement = TreeMeasurement {
        digest: expected_output.prefix_tree_sha256.clone(),
        files: expected_output.prefix_files,
        bytes: expected_output.prefix_bytes,
    };
    let receipt_path = plan.bundle.join("provenance.txt");
    let receipt = decode_receipt(&read_bounded_regular_file(&receipt_path, 64 * 1024)?)?;
    let expected_inputs = receipt_for_plan(plan, &trusted_measurement);
    if receipt != expected_inputs {
        return Err(format!(
            "LLVM provenance {} does not match current pinned inputs",
            receipt_path.display()
        ));
    }
    validate_required_prefix(&plan.prefix, &plan.license_notices)?;
    validate_static_prefix(&plan.prefix)?;
    validate_llvm_config_semantics(&plan.prefix, &plan.lock, &plan.host)?;
    validate_expected_measurement(expected_output, &measure_tree(&plan.prefix)?)?;
    Ok(Some(plan.prefix.clone()))
}

fn verify_or_quarantine_published_bundle(plan: &BuildPlan) -> Result<Option<PathBuf>, String> {
    match verify_published_bundle(plan) {
        Ok(prefix) => Ok(prefix),
        Err(error) => {
            eprintln!(
                "discarding invalid LLVM prefix bundle {}: {error}",
                plan.bundle.display()
            );
            quarantine_published_bundle(plan)?;
            Ok(None)
        }
    }
}

fn quarantine_untrusted_published_bundle(plan: &BuildPlan) -> Result<(), String> {
    validate_plan_prefix_cache(plan)?;
    match fs::symlink_metadata(&plan.bundle) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "cannot inspect untrusted LLVM bundle {}: {error}",
            plan.bundle.display()
        )),
        Ok(_) => quarantine_published_bundle(plan),
    }
}

fn quarantine_published_bundle(plan: &BuildPlan) -> Result<(), String> {
    validate_plan_prefix_cache(plan)?;
    let parent = plan
        .bundle
        .parent()
        .ok_or_else(|| "LLVM bundle path has no parent".to_owned())?;
    match fs::symlink_metadata(&plan.bundle) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "cannot inspect invalid LLVM bundle {}: {error}",
                plan.bundle.display()
            ));
        }
        Ok(_) => {}
    }
    for attempt in 0_u32..128 {
        let quarantine = parent.join(format!(
            ".{}.invalid.{}.{}",
            plan.key,
            std::process::id(),
            attempt
        ));
        match fs::rename(&plan.bundle, &quarantine) {
            Ok(()) => {
                sync_directory(parent)?;
                let metadata = fs::symlink_metadata(&quarantine).map_err(|error| {
                    format!(
                        "cannot inspect quarantined LLVM bundle {}: {error}",
                        quarantine.display()
                    )
                })?;
                if metadata.is_dir() && !metadata.file_type().is_symlink() {
                    fs::remove_dir_all(&quarantine).map_err(|error| {
                        format!(
                            "cannot remove quarantined LLVM bundle {}: {error}",
                            quarantine.display()
                        )
                    })?;
                } else {
                    fs::remove_file(&quarantine).map_err(|error| {
                        format!(
                            "cannot remove quarantined LLVM entry {}: {error}",
                            quarantine.display()
                        )
                    })?;
                }
                sync_directory(parent)?;
                return Ok(());
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => {
                return Err(format!(
                    "cannot quarantine invalid LLVM bundle {}: {error}",
                    plan.bundle.display()
                ));
            }
        }
    }
    Err("cannot allocate an invalid LLVM bundle quarantine name".to_owned())
}

fn publish_bundle(staging: &Path, bundle: &Path, plan: &BuildPlan) -> Result<(), String> {
    validate_plan_prefix_cache(plan)?;
    let parent = plan
        .bundle
        .parent()
        .ok_or_else(|| "LLVM bundle path has no parent".to_owned())?;
    sync_directory(parent)?;
    for _ in 0..2 {
        match fs::rename(bundle, &plan.bundle) {
            Ok(()) => {
                sync_directory(staging)?;
                sync_directory(parent)?;
                return Ok(());
            }
            Err(error) => match verify_published_bundle(plan) {
                Ok(Some(_)) => return Ok(()),
                Ok(None) => continue,
                Err(invalid) => {
                    eprintln!(
                        "replacing invalid raced LLVM bundle {}: {invalid}",
                        plan.bundle.display()
                    );
                    quarantine_published_bundle(plan)?;
                    if !bundle.is_dir() {
                        return Err(format!(
                            "LLVM publication source {} disappeared after race: {error}",
                            bundle.display()
                        ));
                    }
                }
            },
        }
    }
    Err(format!(
        "cannot atomically publish LLVM bundle {} after a verified retry",
        plan.bundle.display()
    ))
}

fn validate_plan_prefix_cache(plan: &BuildPlan) -> Result<(), String> {
    let expected_parent = plan.workspace_root.join("build/toolchain/llvm/prefixes");
    if plan.bundle.parent() != Some(expected_parent.as_path())
        || plan.prefix != plan.bundle.join("prefix")
    {
        return Err("LLVM build plan contains a noncanonical prefix-cache path".to_owned());
    }
    validate_non_symlink_directory_chain(
        &plan.workspace_root,
        Path::new("build/toolchain/llvm/prefixes"),
    )
}

fn read_bounded_regular_file(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() > maximum {
        return Err(format!(
            "{} is not a bounded regular file of at most {maximum} bytes",
            path.display()
        ));
    }
    let file =
        File::open(path).map_err(|error| format!("cannot open {}: {error}", path.display()))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(
            usize::try_from(metadata.len())
                .map_err(|_| "bounded file length overflow".to_owned())?,
        )
        .map_err(|_| "cannot reserve bounded file buffer".to_owned())?;
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    if bytes.len() as u64 > maximum || bytes.len() as u64 != metadata.len() {
        return Err(format!("{} changed during bounded read", path.display()));
    }
    Ok(bytes)
}

fn validate_required_prefix(
    prefix: &Path,
    license_notices: &[LicenseNotice],
) -> Result<(), String> {
    let executable_suffix = if cfg!(windows) { ".exe" } else { "" };
    let static_suffix = if cfg!(windows) { ".lib" } else { ".a" };
    let static_prefix = if cfg!(windows) { "" } else { "lib" };
    let llvm_config = prefix.join(format!("bin/llvm-config{executable_suffix}"));
    let required = [
        llvm_config.clone(),
        prefix.join("include/llvm/IR/Module.h"),
        prefix.join("include/lld/Common/Driver.h"),
        prefix.join(format!("lib/{static_prefix}LLVMCore{static_suffix}")),
        prefix.join(format!(
            "lib/{static_prefix}LLVMAArch64CodeGen{static_suffix}"
        )),
        prefix.join(format!("lib/{static_prefix}lldCOFF{static_suffix}")),
        prefix.join(format!("lib/{static_prefix}lldCommon{static_suffix}")),
    ];
    for path in required {
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            format!(
                "required LLVM install file {} is absent: {error}",
                path.display()
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() == 0 {
            return Err(format!(
                "required LLVM install file {} is not a nonempty regular file",
                path.display()
            ));
        }
    }
    let metadata = fs::metadata(&llvm_config)
        .map_err(|error| format!("cannot inspect {}: {error}", llvm_config.display()))?;
    if !metadata_is_executable(&metadata) {
        return Err(format!(
            "required LLVM install tool {} is not executable",
            llvm_config.display()
        ));
    }
    validate_static_archive_inventory(prefix)?;
    validate_license_notices(prefix, license_notices)?;
    Ok(())
}

fn validate_static_archive_inventory(prefix: &Path) -> Result<(), String> {
    let static_suffix = if cfg!(windows) { ".lib" } else { ".a" };
    let static_prefix = if cfg!(windows) { "" } else { "lib" };
    let expected: BTreeSet<String> = REQUIRED_LLVM_STATIC_COMPONENTS
        .iter()
        .chain(REQUIRED_LLD_STATIC_COMPONENTS)
        .map(|component| format!("{static_prefix}{component}{static_suffix}"))
        .collect();
    let expected_count =
        REQUIRED_LLVM_STATIC_COMPONENTS.len() + REQUIRED_LLD_STATIC_COMPONENTS.len();
    if expected.len() != expected_count {
        return Err(
            "reviewed LLVM static archive closure contains duplicate components".to_owned(),
        );
    }
    let forbidden: BTreeSet<String> = FORBIDDEN_LLD_STATIC_COMPONENTS
        .iter()
        .map(|component| format!("{static_prefix}{component}{static_suffix}"))
        .collect();
    let library_directory = prefix.join("lib");
    let mut observed = BTreeSet::new();
    let mut tree = Vec::new();
    let mut inventory_bytes = 0_u64;
    let mut inventory_entries = 1_u64;
    collect_tree_entries(
        prefix,
        prefix,
        &mut tree,
        &mut inventory_bytes,
        &mut inventory_entries,
        0,
    )?;
    for entry in tree.into_iter().filter(|entry| !entry.directory) {
        let bytes = entry.bytes;
        let path = entry.path;
        let name = path
            .file_name()
            .and_then(OsStr::to_str)
            .ok_or_else(|| format!("LLVM library name is not UTF-8: {}", path.display()))?
            .to_owned();
        if !name.ends_with(static_suffix) {
            continue;
        }
        if bytes == 0 || path.parent() != Some(library_directory.as_path()) {
            return Err(format!(
                "LLVM install contains an empty or misplaced static archive: {}",
                path.display()
            ));
        }
        if !observed.insert(name.clone()) {
            return Err(format!("LLVM static archive inventory repeats {name:?}"));
        }
        if forbidden.contains(&name) {
            return Err(format!(
                "LLVM install contains forbidden unused LLD flavor archive {name:?}"
            ));
        }
        if observed.len() > expected.len() {
            return Err(format!(
                "LLVM install contains an unreviewed static archive {name:?}"
            ));
        }
    }
    if observed != expected {
        let missing: Vec<_> = expected.difference(&observed).cloned().collect();
        let extra: Vec<_> = observed.difference(&expected).cloned().collect();
        return Err(format!(
            "LLVM static archive closure differs from llvm-sys: missing {missing:?}, extra {extra:?}"
        ));
    }
    Ok(())
}

fn validate_license_notices(
    prefix: &Path,
    license_notices: &[LicenseNotice],
) -> Result<(), String> {
    if license_notices.is_empty() || license_notices.len() > 32 {
        return Err("LLVM license policy must contain 1..=32 notices".to_owned());
    }
    let mut destinations = BTreeSet::new();
    for notice in license_notices {
        if !valid_sha256(&notice.digest) || !destinations.insert(notice.destination.as_str()) {
            return Err("LLVM license policy contains an invalid or duplicate entry".to_owned());
        }
        let relative = Path::new(&notice.destination);
        if relative.is_absolute()
            || relative
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err("LLVM license policy contains a noncanonical destination".to_owned());
        }
        let path = prefix.join(relative);
        let bytes = read_bounded_regular_file(&path, 64 * 1024)?;
        let observed = sha256_bytes(&bytes);
        if observed != notice.digest {
            return Err(format!(
                "LLVM license notice {} digest {observed} does not match reviewed {}",
                path.display(),
                notice.digest
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn normalize_prefix_permissions(prefix: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    fn normalize(path: &Path, depth: u32, entries: &mut u64) -> Result<(), String> {
        use std::os::unix::fs::PermissionsExt;

        if depth > MAX_PREFIX_DEPTH {
            return Err(format!(
                "native prefix exceeds directory depth {MAX_PREFIX_DEPTH}"
            ));
        }
        *entries = entries
            .checked_add(1)
            .ok_or_else(|| "native prefix permission entry count overflow".to_owned())?;
        if *entries > MAX_PREFIX_FILES {
            return Err(format!("native prefix exceeds {MAX_PREFIX_FILES} entries"));
        }
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!("native prefix contains symlink {}", path.display()));
        }
        if metadata.is_dir() {
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).map_err(|error| {
                format!(
                    "cannot normalize directory mode {}: {error}",
                    path.display()
                )
            })?;
            let mut children = Vec::new();
            for entry in fs::read_dir(path)
                .map_err(|error| format!("cannot read native prefix {}: {error}", path.display()))?
            {
                children.push(
                    entry
                        .map_err(|error| format!("cannot inspect native prefix entry: {error}"))?
                        .path(),
                );
            }
            children.sort();
            for child in children {
                normalize(&child, depth + 1, entries)?;
            }
            return Ok(());
        }
        if !metadata.is_file() {
            return Err(format!(
                "native prefix contains unsupported entry {}",
                path.display()
            ));
        }
        let mode = if metadata.permissions().mode() & 0o111 == 0 {
            0o644
        } else {
            0o755
        };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(|error| format!("cannot normalize file mode {}: {error}", path.display()))
    }

    let mut entries = 0_u64;
    normalize(prefix, 0, &mut entries)?;
    let metadata = fs::metadata(prefix)
        .map_err(|error| format!("cannot inspect normalized {}: {error}", prefix.display()))?;
    if metadata.permissions().mode() & 0o777 != 0o755 {
        return Err("native prefix root mode normalization failed".to_owned());
    }
    Ok(())
}

#[cfg(not(unix))]
fn normalize_prefix_permissions(_prefix: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
fn normalize_tree_timestamps(
    root: &Path,
    touch: &Path,
    maximum_entries: u64,
    maximum_depth: u32,
    label: &str,
) -> Result<(), String> {
    fn collect_postorder(
        path: &Path,
        depth: u32,
        entries: &mut u64,
        paths: &mut Vec<PathBuf>,
        maximum_entries: u64,
        maximum_depth: u32,
        label: &str,
    ) -> Result<(), String> {
        if depth > maximum_depth {
            return Err(format!("{label} exceeds directory depth {maximum_depth}"));
        }
        *entries = entries
            .checked_add(1)
            .ok_or_else(|| format!("{label} timestamp entry count overflow"))?;
        if *entries > maximum_entries {
            return Err(format!("{label} exceeds {maximum_entries} entries"));
        }
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!("{label} contains symlink {}", path.display()));
        }
        if metadata.is_dir() {
            let mut children = Vec::new();
            for entry in fs::read_dir(path)
                .map_err(|error| format!("cannot read {label} {}: {error}", path.display()))?
            {
                children.push(
                    entry
                        .map_err(|error| format!("cannot inspect {label} entry: {error}"))?
                        .path(),
                );
            }
            children.sort();
            for child in children {
                collect_postorder(
                    &child,
                    depth + 1,
                    entries,
                    paths,
                    maximum_entries,
                    maximum_depth,
                    label,
                )?;
            }
        } else if !metadata.is_file() {
            return Err(format!(
                "{label} contains unsupported entry {}",
                path.display()
            ));
        }
        paths
            .try_reserve(1)
            .map_err(|_| format!("cannot reserve {label} timestamp inventory"))?;
        paths.push(path.to_owned());
        Ok(())
    }

    let mut entries = 0_u64;
    let mut paths = Vec::new();
    collect_postorder(
        root,
        0,
        &mut entries,
        &mut paths,
        maximum_entries,
        maximum_depth,
        label,
    )?;
    for chunk in paths.chunks(256) {
        let status = Command::new(touch)
            .arg("-t")
            .arg("197001010000.01")
            .args(chunk)
            .current_dir(root)
            .env_clear()
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .env("TZ", "UTC")
            .env("SOURCE_DATE_EPOCH", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .status()
            .map_err(|error| {
                format!(
                    "cannot normalize {label} timestamps with {}: {error}",
                    touch.display()
                )
            })?;
        if !status.success() {
            return Err(format!(
                "{label} timestamp normalizer {} failed with {status}",
                touch.display()
            ));
        }
    }
    for path in &paths {
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect normalized {}: {error}", path.display()))?;
        if metadata_timestamp(&metadata) != (1, 0) {
            return Err(format!(
                "{label} timestamp normalization failed for {}",
                path.display()
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn normalize_prefix_timestamps(prefix: &Path, touch: &Path) -> Result<(), String> {
    normalize_tree_timestamps(
        prefix,
        touch,
        MAX_PREFIX_FILES,
        MAX_PREFIX_DEPTH,
        "native prefix",
    )
}

#[cfg(unix)]
fn normalize_source_timestamps(source: &Path, touch: &Path) -> Result<(), String> {
    normalize_tree_timestamps(
        source,
        touch,
        MAX_ARCHIVE_MEMBERS,
        MAX_PREFIX_DEPTH,
        "LLVM source tree",
    )
}

#[cfg(not(unix))]
fn normalize_prefix_timestamps(_prefix: &Path, _touch: &Path) -> Result<(), String> {
    Err("LLVM prefix timestamp normalization requires a supported Unix host".to_owned())
}

#[cfg(not(unix))]
fn normalize_source_timestamps(_source: &Path, _touch: &Path) -> Result<(), String> {
    Err("LLVM source timestamp normalization requires a supported Unix host".to_owned())
}

fn canonicalize_installed_archives(prefix: &Path, ranlib: &Path) -> Result<(), String> {
    fn collect(
        path: &Path,
        depth: u32,
        entries: &mut u64,
        archives: &mut Vec<PathBuf>,
    ) -> Result<(), String> {
        if depth > MAX_PREFIX_DEPTH {
            return Err(format!(
                "native prefix exceeds directory depth {MAX_PREFIX_DEPTH}"
            ));
        }
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!("native prefix contains symlink {}", path.display()));
        }
        if metadata.is_dir() {
            let mut children = Vec::new();
            for entry in fs::read_dir(path)
                .map_err(|error| format!("cannot read native prefix {}: {error}", path.display()))?
            {
                *entries = entries
                    .checked_add(1)
                    .ok_or_else(|| "native prefix archive inventory overflow".to_owned())?;
                if *entries > MAX_PREFIX_FILES {
                    return Err(format!("native prefix exceeds {MAX_PREFIX_FILES} entries"));
                }
                children.push(
                    entry
                        .map_err(|error| format!("cannot inspect native prefix entry: {error}"))?
                        .path(),
                );
            }
            children.sort();
            for child in children {
                collect(&child, depth + 1, entries, archives)?;
            }
            return Ok(());
        }
        if !metadata.is_file() {
            return Err(format!(
                "native prefix contains unsupported entry {}",
                path.display()
            ));
        }
        if path.extension() == Some(OsStr::new("a")) {
            archives
                .try_reserve(1)
                .map_err(|_| "cannot reserve static archive inventory".to_owned())?;
            archives.push(path.to_owned());
        }
        Ok(())
    }

    let mut entries = 0_u64;
    let mut archives = Vec::new();
    collect(prefix, 0, &mut entries, &mut archives)?;
    archives.sort();
    if archives.is_empty() {
        return Err("LLVM install contains no static archives to canonicalize".to_owned());
    }
    for archive in archives {
        let status = Command::new(ranlib)
            .arg("-D")
            .arg(&archive)
            .current_dir(prefix)
            .env_clear()
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .env("TZ", "UTC")
            .env("ZERO_AR_DATE", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .status()
            .map_err(|error| {
                format!(
                    "cannot canonicalize installed archive {} with {}: {error}",
                    archive.display(),
                    ranlib.display()
                )
            })?;
        if !status.success() {
            return Err(format!(
                "archive indexer {} failed for {} with {status}",
                ranlib.display(),
                archive.display()
            ));
        }
    }
    Ok(())
}

fn validate_static_prefix(prefix: &Path) -> Result<(), String> {
    fn visit(path: &Path, depth: u32, entries: &mut u64) -> Result<(), String> {
        if depth > MAX_PREFIX_DEPTH {
            return Err(format!(
                "native prefix exceeds directory depth {MAX_PREFIX_DEPTH}"
            ));
        }
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!("native prefix contains symlink {}", path.display()));
        }
        if metadata.is_dir() {
            for entry in fs::read_dir(path)
                .map_err(|error| format!("cannot read native prefix {}: {error}", path.display()))?
            {
                *entries = entries
                    .checked_add(1)
                    .ok_or_else(|| "native prefix validation entry count overflow".to_owned())?;
                if *entries > MAX_PREFIX_FILES {
                    return Err(format!("native prefix exceeds {MAX_PREFIX_FILES} entries"));
                }
                visit(
                    &entry
                        .map_err(|error| format!("cannot inspect native prefix entry: {error}"))?
                        .path(),
                    depth + 1,
                    entries,
                )?;
            }
            return Ok(());
        }
        if !metadata.is_file() {
            return Err(format!(
                "native prefix contains unsupported entry {}",
                path.display()
            ));
        }
        let name = path.file_name().and_then(OsStr::to_str).ok_or_else(|| {
            format!(
                "native prefix has a non-UTF-8 file name: {}",
                path.display()
            )
        })?;
        if name.ends_with(".dylib")
            || name.ends_with(".so")
            || name.contains(".so.")
            || name.ends_with(".dll")
            || name.ends_with(".tbd")
        {
            return Err(format!(
                "static LLVM prefix contains shared library {}",
                path.display()
            ));
        }
        if name.ends_with(".a") {
            validate_deterministic_archive(path)?;
        }
        Ok(())
    }

    let mut entries = 0_u64;
    visit(prefix, 0, &mut entries)
}

fn validate_deterministic_archive(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("cannot inspect archive {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() < 8 + 60
        || metadata.len() > MAX_PREFIX_BYTES
    {
        return Err(format!(
            "installed static archive {} has an invalid size or type",
            path.display()
        ));
    }
    let mut file = File::open(path)
        .map_err(|error| format!("cannot open archive {}: {error}", path.display()))?;
    let mut magic = [0_u8; 8];
    file.read_exact(&mut magic)
        .map_err(|error| format!("cannot read archive {}: {error}", path.display()))?;
    if &magic != b"!<arch>\n" {
        return Err(format!(
            "installed static archive {} lacks ar magic",
            path.display()
        ));
    }
    let mut position = 8_u64;
    let mut members = 0_u64;
    while position < metadata.len() {
        if metadata.len() - position < 60 {
            return Err(format!("archive {} has a truncated header", path.display()));
        }
        let mut header = [0_u8; 60];
        file.read_exact(&mut header)
            .map_err(|error| format!("cannot read archive {}: {error}", path.display()))?;
        if &header[58..60] != b"`\n" {
            return Err(format!(
                "archive {} has invalid member magic",
                path.display()
            ));
        }
        let name = std::str::from_utf8(&header[..16])
            .map_err(|_| format!("archive {} has a non-ASCII member name", path.display()))?
            .trim();
        if name.is_empty() || name.chars().any(char::is_control) {
            return Err(format!(
                "archive {} has an invalid member name",
                path.display()
            ));
        }
        let timestamp = parse_ar_number(&header[16..28], 10, "timestamp", path)?;
        let uid = parse_ar_number(&header[28..34], 10, "uid", path)?;
        let gid = parse_ar_number(&header[34..40], 10, "gid", path)?;
        let mode = parse_ar_number(&header[40..48], 8, "mode", path)?;
        let size = parse_ar_number(&header[48..58], 10, "size", path)?;
        let permissions = mode & 0o7777;
        let reserved_metadata_member = matches!(
            name,
            "/" | "//"
                | "/SYM64/"
                | "__.SYMDEF"
                | "__.SYMDEF/"
                | "__.SYMDEF SORTED"
                | "__.SYMDEF SORTED/"
                | "__.SYMDEF_64"
                | "__.SYMDEF_64/"
                | "__.SYMDEF_64 SORTED"
                | "__.SYMDEF_64 SORTED/"
        );
        let canonical_permissions =
            permissions == 0o644 || (reserved_metadata_member && permissions == 0);
        if timestamp != 0 || uid != 0 || gid != 0 || !canonical_permissions {
            return Err(format!(
                "archive {} member {name:?} has noncanonical metadata timestamp={timestamp} uid={uid} gid={gid} mode={mode:o}",
                path.display()
            ));
        }
        members = members
            .checked_add(1)
            .ok_or_else(|| "static archive member count overflow".to_owned())?;
        if members > MAX_ARCHIVE_MEMBERS {
            return Err(format!(
                "installed archive {} exceeds {MAX_ARCHIVE_MEMBERS} members",
                path.display()
            ));
        }
        position = position
            .checked_add(60)
            .and_then(|value| value.checked_add(size))
            .and_then(|value| value.checked_add(size & 1))
            .ok_or_else(|| "static archive offset overflow".to_owned())?;
        if position > metadata.len() {
            return Err(format!("archive {} has a truncated member", path.display()));
        }
        file.seek(SeekFrom::Start(position))
            .map_err(|error| format!("cannot seek archive {}: {error}", path.display()))?;
    }
    if position != metadata.len() || members == 0 {
        return Err(format!(
            "installed archive {} is empty or has trailing bytes",
            path.display()
        ));
    }
    Ok(())
}

fn parse_ar_number(field: &[u8], radix: u32, label: &str, path: &Path) -> Result<u64, String> {
    let text = std::str::from_utf8(field)
        .map_err(|_| format!("archive {} has non-ASCII {label}", path.display()))?
        .trim();
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "archive {} has invalid {label} field",
            path.display()
        ));
    }
    u64::from_str_radix(text, radix)
        .map_err(|_| format!("archive {} has invalid {label} value", path.display()))
}

fn validate_llvm_config_semantics(
    prefix: &Path,
    lock: &LlvmLock,
    host: &str,
) -> Result<(), String> {
    let executable_suffix = if cfg!(windows) { ".exe" } else { "" };
    let llvm_config = prefix.join(format!("bin/llvm-config{executable_suffix}"));
    let queries = [
        ("--version", lock.version.as_str()),
        ("--targets-built", "AArch64"),
        ("--shared-mode", "static"),
        ("--host-target", host),
    ];
    for (argument, expected) in queries {
        let mut command = Command::new(&llvm_config);
        command
            .arg(argument)
            .current_dir(prefix)
            .env_clear()
            .env("LC_ALL", "C")
            .env("LANG", "C")
            .env("TZ", "UTC")
            .stdin(Stdio::null());
        let (status, stdout, stderr) = run_bounded_output(
            &mut command,
            4096,
            std::time::Duration::from_secs(10),
            &format!("installed {} {argument}", llvm_config.display()),
        )?;
        if !status.success() {
            let stderr = String::from_utf8_lossy(&stderr);
            return Err(format!(
                "installed {} {argument} failed with {}: {stderr}",
                llvm_config.display(),
                status
            ));
        }
        if !stderr.is_empty() {
            return Err(format!(
                "installed {} {argument} emitted stderr",
                llvm_config.display()
            ));
        }
        let text = std::str::from_utf8(&stdout).map_err(|_| {
            format!(
                "installed {} {argument} output is not UTF-8",
                llvm_config.display()
            )
        })?;
        let observed = text.strip_suffix('\n').unwrap_or(text);
        if observed.is_empty()
            || observed.contains('\n')
            || observed.contains('\r')
            || observed != expected
        {
            return Err(format!(
                "installed {} {argument} returned {observed:?}, expected {expected:?}",
                llvm_config.display()
            ));
        }
    }
    let mut command = Command::new(&llvm_config);
    command
        .args(["--libnames", "--link-static"])
        .current_dir(prefix)
        .env_clear()
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("TZ", "UTC")
        .stdin(Stdio::null());
    let (status, stdout, stderr) = run_bounded_output(
        &mut command,
        64 * 1024,
        std::time::Duration::from_secs(10),
        &format!(
            "installed {} --libnames --link-static",
            llvm_config.display()
        ),
    )?;
    if !status.success() || !stderr.is_empty() {
        return Err(format!(
            "installed {} --libnames --link-static failed or emitted stderr with {status}",
            llvm_config.display()
        ));
    }
    let observed = std::str::from_utf8(&stdout)
        .map_err(|_| "installed llvm-config static library closure is not UTF-8".to_owned())?
        .strip_suffix('\n')
        .ok_or_else(|| {
            "installed llvm-config static library closure lacks one final newline".to_owned()
        })?;
    let expected = expected_llvm_static_archive_names().join(" ");
    if observed != expected {
        return Err(format!(
            "installed llvm-config static closure differs from reviewed llvm-sys closure: observed {observed:?}, expected {expected:?}"
        ));
    }
    Ok(())
}

fn run_bounded_output(
    command: &mut Command,
    maximum: usize,
    timeout: std::time::Duration,
    label: &str,
) -> Result<(std::process::ExitStatus, Vec<u8>, Vec<u8>), String> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    configure_child_process_group(command);
    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot execute {label}: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| format!("{label} stdout pipe is unavailable"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| format!("{label} stderr pipe is unavailable"))?;
    let (sender, receiver) = std::sync::mpsc::channel();
    let stdout_sender = sender.clone();
    let stdout_thread = std::thread::spawn(move || {
        let result = read_bounded_pipe(stdout, maximum, "stdout");
        let _ = stdout_sender.send((false, result));
    });
    let stderr_thread = std::thread::spawn(move || {
        let result = read_bounded_pipe(stderr, maximum, "stderr");
        let _ = sender.send((true, result));
    });

    let started = std::time::Instant::now();
    let mut status = None;
    let mut stdout_bytes = None;
    let mut stderr_bytes = None;
    let mut failure = None;
    while status.is_none() || stdout_bytes.is_none() || stderr_bytes.is_none() {
        if started.elapsed() >= timeout {
            failure = Some(format!("{label} exceeded {} seconds", timeout.as_secs()));
            break;
        }
        match receiver.recv_timeout(std::time::Duration::from_millis(20)) {
            Ok((is_stderr, Ok(bytes))) => {
                let slot = if is_stderr {
                    &mut stderr_bytes
                } else {
                    &mut stdout_bytes
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
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                if stdout_bytes.is_none() || stderr_bytes.is_none() {
                    failure = Some(format!("{label} output reader disconnected"));
                    break;
                }
            }
        }
        if status.is_none() {
            status = child
                .try_wait()
                .map_err(|error| format!("cannot poll {label}: {error}"))?;
        }
    }
    if failure.is_some() {
        terminate_child_process_group(&mut child);
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
    Ok((
        status.ok_or_else(|| format!("{label} has no exit status"))?,
        stdout_bytes.ok_or_else(|| format!("{label} has no stdout result"))?,
        stderr_bytes.ok_or_else(|| format!("{label} has no stderr result"))?,
    ))
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
    if child.try_wait().ok().flatten().is_none() {
        let group = format!("-{}", child.id());
        let _ = Command::new("/bin/kill")
            .args(["-KILL", &group])
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
}

#[cfg(not(unix))]
fn terminate_child_process_group(child: &mut std::process::Child) {
    let _ = child.kill();
}

fn read_bounded_pipe(reader: impl Read, maximum: usize, label: &str) -> Result<Vec<u8>, String> {
    let limit = u64::try_from(maximum)
        .map_err(|_| "bounded process output limit does not fit u64".to_owned())?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve(maximum.min(64 * 1024))
        .map_err(|_| format!("cannot reserve bounded process {label}"))?;
    reader
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read bounded process {label}: {error}"))?;
    if bytes.len() > maximum {
        return Err(format!("produced more than {maximum} bytes on {label}"));
    }
    Ok(bytes)
}

fn write_new_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("cannot create {}: {error}", path.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("cannot sync {}: {error}", path.display()))
}

fn sync_directory(path: &Path) -> Result<(), String> {
    let directory = File::open(path)
        .map_err(|error| format!("cannot open directory {} for sync: {error}", path.display()))?;
    directory
        .sync_all()
        .map_err(|error| format!("cannot sync directory {}: {error}", path.display()))
}

fn sync_tree(root: &Path) -> Result<(), String> {
    fn visit(path: &Path, depth: u32, entries: &mut u64) -> Result<(), String> {
        if depth > MAX_PREFIX_DEPTH {
            return Err(format!(
                "native bundle exceeds directory depth {MAX_PREFIX_DEPTH}"
            ));
        }
        *entries = entries
            .checked_add(1)
            .ok_or_else(|| "native bundle sync entry count overflow".to_owned())?;
        if *entries > MAX_PREFIX_FILES {
            return Err(format!("native bundle exceeds {MAX_PREFIX_FILES} entries"));
        }
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| format!("cannot inspect bundle entry {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!("native bundle contains symlink {}", path.display()));
        }
        if metadata.is_dir() {
            let mut children = Vec::new();
            for entry in fs::read_dir(path)
                .map_err(|error| format!("cannot read native bundle {}: {error}", path.display()))?
            {
                children.push(
                    entry
                        .map_err(|error| format!("cannot inspect native bundle entry: {error}"))?
                        .path(),
                );
            }
            children.sort();
            for child in children {
                visit(&child, depth + 1, entries)?;
            }
        } else if metadata.is_file() {
            File::open(path)
                .and_then(|file| file.sync_all())
                .map_err(|error| {
                    format!("cannot sync native bundle file {}: {error}", path.display())
                })?;
            return Ok(());
        } else {
            return Err(format!(
                "native bundle contains unsupported entry {}",
                path.display()
            ));
        }
        sync_directory(path)
    }

    let mut entries = 0_u64;
    visit(root, 0, &mut entries)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Cursor;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{
        BootstrapSources, BuildPlan, CommandSpec, ExpectedOutput, HostClosureIdentity,
        LicenseNotice, LockError, NativeTools, ProvenanceReceipt, RECEIPT_SCHEMA,
        REQUIRED_LLD_STATIC_COMPONENTS, REQUIRED_LLVM_STATIC_COMPONENTS, StagingDirectory,
        ToolIdentity, bootstrap_implementation_digest_from_sources, build_commands,
        build_input_digest, decode_expected_output, decode_lock, decode_receipt,
        encode_expected_output, encode_lock, encode_receipt, expected_output_for_measurement,
        extract_tar_stream, identify_tool, measure_tree, normalized_flags_digest,
        patch_deterministic_source, prepare_controlled_tool_path, receipt_for_plan,
        run_bounded_output, sha256_bytes, stage_cmake_contract, validate_archive_path,
        validate_cmake_contract, validate_codegen_manifest, validate_deterministic_archive,
        validate_resolved_inkwell_lock, validate_static_archive_inventory, validate_static_prefix,
        verify_file_digest, verify_published_bundle,
    };

    const LOCK: &[u8] = include_bytes!("../../toolchain/llvm.lock.toml");
    const CODEGEN_MANIFEST: &[u8] = include_bytes!("../../crates/wrela-codegen-llvm/Cargo.toml");
    const CMAKE_CONTRACT: &[u8] = include_bytes!("../../toolchain/cmake/WrelaLLVM.cmake");
    const LLVM_SOURCE: &[u8] = include_bytes!("llvm.rs");
    const XTASK_MAIN: &[u8] = include_bytes!("main.rs");
    const XTASK_MANIFEST: &[u8] = include_bytes!("../Cargo.toml");
    const CARGO_LOCK: &[u8] = include_bytes!("../../Cargo.lock");
    static TEMP_NONCE: AtomicU64 = AtomicU64::new(0);

    struct TempDirectory(PathBuf);

    impl TempDirectory {
        fn new(label: &str) -> Self {
            let nonce = TEMP_NONCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "wrela-llvm-test-{label}-{}-{nonce}",
                std::process::id()
            ));
            if path.exists() {
                fs::remove_dir_all(&path).expect("remove stale test directory");
            }
            fs::create_dir(&path).expect("create test directory");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn complete_lock_decodes_and_reencodes_exactly() {
        let lock = decode_lock(LOCK).expect("canonical LLVM lock");
        assert_eq!(lock.version, "22.1.3");
        assert_eq!(lock.tag, "llvmorg-22.1.3");
        assert_eq!(lock.projects, ["lld"]);
        assert_eq!(lock.targets, ["AArch64"]);
        assert_eq!(lock.inkwell_version, "0.9.0");
        assert_eq!(lock.inkwell_llvm_feature, "llvm22-1-force-static");
        assert_eq!(encode_lock(&lock), LOCK);
    }

    #[test]
    fn cmake_contract_selects_only_the_reviewed_distribution_closure() {
        let lock = decode_lock(LOCK).expect("canonical LLVM lock");
        assert_eq!(REQUIRED_LLVM_STATIC_COMPONENTS.len(), 102);
        assert_eq!(REQUIRED_LLD_STATIC_COMPONENTS, ["lldCommon", "lldCOFF"]);
        validate_cmake_contract(CMAKE_CONTRACT, &lock).expect("reviewed CMake contract");
        let forbidden = String::from_utf8(CMAKE_CONTRACT.to_vec())
            .expect("UTF-8 CMake contract")
            .replace(";lldCommon;lldCOFF\"", ";lldCommon;lldCOFF;lldELF\"");
        assert_ne!(forbidden.as_bytes(), CMAKE_CONTRACT);
        assert!(validate_cmake_contract(forbidden.as_bytes(), &lock).is_err());
    }

    #[test]
    fn trusted_output_lock_is_exact_and_canonical() {
        let output = ExpectedOutput {
            input_digest: "11".repeat(32),
            llvm_version: "22.1.3".to_owned(),
            host: "arm64-apple-darwin".to_owned(),
            prefix_tree_sha256: "22".repeat(32),
            prefix_files: 123,
            prefix_bytes: 456,
        };
        let encoded = encode_expected_output(&output);
        assert_eq!(
            decode_expected_output(&encoded).expect("output lock"),
            output
        );
        let leading_zero = String::from_utf8(encoded.clone())
            .expect("UTF-8 output lock")
            .replace("prefix_files = 123", "prefix_files = 0123");
        assert!(decode_expected_output(leading_zero.as_bytes()).is_err());
        let mut unknown = encoded;
        unknown.extend_from_slice(b"future = \"forbidden\"\n");
        assert!(decode_expected_output(&unknown).is_err());
    }

    // WRELA-DIST-CONSUMER-BEGIN native-authority-tests
    #[cfg(unix)]
    #[test]
    fn distribution_witness_rejects_file_directory_mode_and_link_substitution() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let temp = TempDirectory::new("distribution-witness");
        let file = temp.path().join("tool");
        let directory = temp.path().join("prefix");
        fs::write(&file, b"authenticated tool").expect("write witness file");
        fs::create_dir(&directory).expect("create witness directory");
        let file = fs::canonicalize(file).expect("canonical witness file");
        let directory = fs::canonicalize(directory).expect("canonical witness directory");
        let witnesses = vec![
            super::observe_stable_path(&file, "tool").expect("file witness"),
            super::observe_stable_path(&directory, "prefix").expect("directory witness"),
        ];
        super::revalidate_stable_path_witnesses(&witnesses).expect("unchanged witnesses");

        let displaced = temp.path().join("displaced-tool");
        fs::rename(&file, &displaced).expect("displace witness file");
        fs::write(&file, b"authenticated tool").expect("substitute witness file");
        assert!(super::revalidate_stable_path_witnesses(&witnesses).is_err());

        let mode_file = temp.path().join("mode-tool");
        fs::write(&mode_file, b"mode witness").expect("write mode witness");
        let mode_file = fs::canonicalize(mode_file).expect("canonical mode witness");
        let mode_witness =
            super::observe_stable_path(&mode_file, "mode tool").expect("mode witness");
        fs::set_permissions(&mode_file, fs::Permissions::from_mode(0o400))
            .expect("change witness mode");
        assert!(super::revalidate_stable_path_witnesses(&[mode_witness]).is_err());

        let linked = temp.path().join("linked-tool");
        let link_source = temp.path().join("link-source");
        fs::write(&link_source, b"link witness").expect("write link witness");
        fs::hard_link(&link_source, &linked).expect("create witness hardlink");
        assert!(super::observe_stable_path(&link_source, "hardlinked tool").is_err());

        let alias = temp.path().join("tool-alias");
        symlink(&link_source, &alias).expect("create witness symlink");
        let link = super::observe_stable_path(&alias, "aliased tool").expect("symlink witness");
        super::revalidate_stable_path_witnesses(std::slice::from_ref(&link))
            .expect("unchanged invocation symlink");
        fs::remove_file(&alias).expect("remove witness symlink");
        symlink(&directory, &alias).expect("retarget witness symlink");
        assert!(super::revalidate_stable_path_witnesses(&[link]).is_err());

        let displaced_directory = temp.path().join("displaced-prefix");
        fs::rename(&directory, &displaced_directory).expect("displace witness directory");
        fs::create_dir(&directory).expect("substitute witness directory");
        assert!(super::revalidate_stable_path_witnesses(&witnesses).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn distribution_host_tree_witness_rejects_nested_input_mutation() {
        let temp = TempDirectory::new("distribution-host-tree-witness");
        let root = temp.path().join("sdk");
        let include = root.join("usr/include");
        fs::create_dir_all(&include).expect("create host tree");
        let header = include.join("stdint.h");
        fs::write(&header, b"authenticated header\n").expect("write host input");
        let root = fs::canonicalize(root).expect("canonical host tree");
        let mut witnesses = Vec::new();
        let mut entries = 0;
        super::collect_stable_tree_witnesses(
            &root,
            "fixture host closure",
            &mut witnesses,
            &mut entries,
            0,
        )
        .expect("collect exact host witnesses");
        assert_eq!(entries, 4);
        super::revalidate_stable_path_witnesses(&witnesses).expect("unchanged host tree");
        fs::write(&header, b"substituted header\n").expect("mutate nested host input");
        assert!(super::revalidate_stable_path_witnesses(&witnesses).is_err());
    }

    #[test]
    fn distribution_consumer_code_is_excluded_from_llvm_producer_identity() {
        const ENROLLED_SOURCE_SHA256: &str =
            "8776497a8e3c581408fca90b95f2f9f8d25f7b60d2b6fa2167e3f3b898393724";
        let baseline = super::distribution_partitioned_llvm_source_digest(LLVM_SOURCE)
            .expect("partition current LLVM source");
        assert_eq!(baseline, ENROLLED_SOURCE_SHA256);
        let mutated = String::from_utf8(LLVM_SOURCE.to_vec())
            .expect("UTF-8 LLVM source")
            .replacen(
                "Full Darwin native authority retained by the distribution producer.",
                "Full Darwin native authority retained solely by the distribution producer.",
                1,
            );
        assert_ne!(mutated.as_bytes(), LLVM_SOURCE);
        assert_eq!(
            super::distribution_partitioned_llvm_source_digest(mutated.as_bytes())
                .expect("partition consumer-only mutation"),
            baseline
        );
    }
    // WRELA-DIST-CONSUMER-END native-authority-tests
    #[cfg(unix)]
    #[test]
    fn bounded_process_timeout_kills_pipe_holding_descendants() {
        let mut command = std::process::Command::new("/bin/sh");
        command
            .args(["-c", "/bin/sleep 30 & wait"])
            .env_clear()
            .stdin(std::process::Stdio::null());
        let started = std::time::Instant::now();
        let error = run_bounded_output(
            &mut command,
            1024,
            std::time::Duration::from_millis(100),
            "descendant containment fixture",
        )
        .expect_err("timeout must fail");
        assert!(error.contains("exceeded"));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn crashed_staging_lease_is_removed_before_allocation() {
        let temp = TempDirectory::new("staging-lease");
        let parent = temp.path().join("build/toolchain/llvm/staging");
        fs::create_dir_all(&parent).expect("staging parent");
        let key = format!("22.1.3-{}", "11".repeat(32));
        let stale = parent.join(format!("{key}.4294967295.{}.0", "22".repeat(32)));
        fs::create_dir(&stale).expect("stale staging");
        fs::write(stale.join("payload"), b"crashed").expect("stale payload");
        let staging = StagingDirectory::create(temp.path(), &key).expect("new staging");
        assert!(!stale.exists());
        assert!(staging.path.is_dir());
        drop(staging);
        assert_eq!(fs::read_dir(parent).expect("empty staging").count(), 0);
    }

    #[test]
    fn rust_binding_inputs_are_exact_but_ignore_unrelated_lock_drift() {
        let lock = decode_lock(LOCK).expect("canonical LLVM lock");
        let manifest_digest =
            validate_codegen_manifest(CODEGEN_MANIFEST, &lock).expect("binding manifest");
        let resolution_digest =
            validate_resolved_inkwell_lock(CARGO_LOCK, &lock).expect("binding resolution");
        assert_eq!(manifest_digest.len(), 64);
        assert_eq!(resolution_digest.len(), 64);

        let unrelated_manifest = String::from_utf8(CODEGEN_MANIFEST.to_vec())
            .expect("UTF-8 manifest")
            .replace(
                "description = \"Mechanical translation from validated MachineWir into AArch64 COFF\"",
                "description = \"Changed documentation only\"",
            );
        assert_eq!(
            validate_codegen_manifest(unrelated_manifest.as_bytes(), &lock)
                .expect("unrelated manifest metadata"),
            manifest_digest
        );

        let unrelated_lock = String::from_utf8(CARGO_LOCK.to_vec())
            .expect("UTF-8 Cargo.lock")
            .replace(
                "name = \"itoa\"\nversion = \"1.0.18\"",
                "name = \"itoa\"\nversion = \"1.0.19\"",
            );
        assert_eq!(
            validate_resolved_inkwell_lock(unrelated_lock.as_bytes(), &lock)
                .expect("unrelated lock package"),
            resolution_digest
        );
    }

    #[test]
    fn rust_binding_inputs_reject_feature_kind_and_resolution_drift() {
        let lock = decode_lock(LOCK).expect("canonical LLVM lock");
        for manifest in [
            String::from_utf8(CODEGEN_MANIFEST.to_vec())
                .expect("UTF-8 manifest")
                .replace("llvm = [\"dep:inkwell\"]", "llvm = []"),
            String::from_utf8(CODEGEN_MANIFEST.to_vec())
                .expect("UTF-8 manifest")
                .replace("default = []", "default = [\"llvm\"]"),
            String::from_utf8(CODEGEN_MANIFEST.to_vec())
                .expect("UTF-8 manifest")
                .replace("[dependencies.inkwell]", "[dev-dependencies.inkwell]"),
            String::from_utf8(CODEGEN_MANIFEST.to_vec())
                .expect("UTF-8 manifest")
                .replace("target-aarch64", "target-x86"),
            format!(
                "{}\n[dependencies.renamed-inkwell]\npackage = \"inkwell\"\nversion = \"=0.9.0\"\n",
                String::from_utf8(CODEGEN_MANIFEST.to_vec()).expect("UTF-8 manifest")
            ),
            String::from_utf8(CODEGEN_MANIFEST.to_vec())
                .expect("UTF-8 manifest")
                .replace(
                    "[dependencies]",
                    "[dependencies]\nrenamed-inkwell = { package = \"inkwell\", version = \"=0.9.0\" }",
                ),
        ] {
            assert!(validate_codegen_manifest(manifest.as_bytes(), &lock).is_err());
        }

        let wrong_schema = String::from_utf8(CARGO_LOCK.to_vec())
            .expect("UTF-8 Cargo.lock")
            .replace("version = 4", "version = 3");
        assert!(validate_resolved_inkwell_lock(wrong_schema.as_bytes(), &lock).is_err());

        let disconnected = String::from_utf8(CARGO_LOCK.to_vec())
            .expect("UTF-8 Cargo.lock")
            .replacen(" \"inkwell\",\n", "", 1);
        assert!(validate_resolved_inkwell_lock(disconnected.as_bytes(), &lock).is_err());

        let wrong_llvm_sys = String::from_utf8(CARGO_LOCK.to_vec())
            .expect("UTF-8 Cargo.lock")
            .replace(
                "name = \"llvm-sys\"\nversion = \"221.0.1\"",
                "name = \"llvm-sys\"\nversion = \"181.0.0\"",
            );
        assert!(validate_resolved_inkwell_lock(wrong_llvm_sys.as_bytes(), &lock).is_err());
    }

    #[test]
    fn bootstrap_identity_ignores_unrelated_xtask_command_manifest_and_lock_drift() {
        let compiled = BootstrapSources {
            llvm: LLVM_SOURCE,
            main: XTASK_MAIN,
            manifest: XTASK_MANIFEST,
            cargo_lock: CARGO_LOCK,
        };
        let baseline = bootstrap_implementation_digest_from_sources(compiled, compiled)
            .expect("current bootstrap identity");

        let main = String::from_utf8(XTASK_MAIN.to_vec())
            .expect("UTF-8 xtask main")
            .replace("Some(\"qemu\")", "Some(\"qemu-renamed\")");
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
            llvm: LLVM_SOURCE,
            main: main.as_bytes(),
            manifest: manifest.as_bytes(),
            cargo_lock: cargo_lock.as_bytes(),
        };
        assert_eq!(
            bootstrap_implementation_digest_from_sources(runtime, compiled)
                .expect("unrelated drift must remain current"),
            baseline
        );
    }

    #[test]
    fn bootstrap_identity_rejects_llvm_dispatch_manifest_and_dependency_drift() {
        let compiled = BootstrapSources {
            llvm: LLVM_SOURCE,
            main: XTASK_MAIN,
            manifest: XTASK_MANIFEST,
            cargo_lock: CARGO_LOCK,
        };

        let mut llvm = LLVM_SOURCE.to_vec();
        llvm.extend_from_slice(b"// relevant implementation drift\n");
        let error = bootstrap_implementation_digest_from_sources(
            BootstrapSources {
                llvm: &llvm,
                ..compiled
            },
            compiled,
        )
        .expect_err("LLVM implementation drift must be stale");
        assert!(error.contains("xtask/src/llvm.rs"));

        let main = String::from_utf8(XTASK_MAIN.to_vec())
            .expect("UTF-8 xtask main")
            .replace(
                "llvm::run(&root, &arguments)",
                "llvm::changed(&root, &arguments)",
            );
        assert_ne!(main.as_bytes(), XTASK_MAIN, "fixture must change dispatch");
        let error = bootstrap_implementation_digest_from_sources(
            BootstrapSources {
                main: main.as_bytes(),
                ..compiled
            },
            compiled,
        )
        .expect_err("LLVM dispatch drift must be stale");
        assert!(error.contains("LLVM dispatch contract"));

        let manifest = String::from_utf8(XTASK_MANIFEST.to_vec())
            .expect("UTF-8 xtask manifest")
            .replace("version = \"=0.10.9\"", "version = \"=0.10.8\"");
        let error = bootstrap_implementation_digest_from_sources(
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
        let error = bootstrap_implementation_digest_from_sources(
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
        let error = bootstrap_implementation_digest_from_sources(
            BootstrapSources {
                cargo_lock: disconnected_lock.as_bytes(),
                ..compiled
            },
            compiled,
        )
        .expect_err("disconnected bootstrap dependency must fail");
        assert!(error.contains("directly to pinned sha2"));
    }

    #[test]
    fn native_input_digest_still_commits_flags_tools_and_implementation() {
        let temp = TempDirectory::new("native-input-projection");
        let plan = fake_plan(temp.path(), 1);
        let digest = |flags: &str, implementation: &str, tools: &NativeTools| {
            build_input_digest(
                &plan.lock,
                &plan.lock_digest,
                &plan.cmake_digest,
                &plan.codegen_binding_digest,
                &plan.rust_binding_digest,
                flags,
                implementation,
                &plan.host,
                tools,
            )
        };
        let baseline = digest(&plan.flags_digest, &plan.implementation_digest, &plan.tools);
        assert_ne!(
            digest(&"41".repeat(32), &plan.implementation_digest, &plan.tools),
            baseline,
            "configure/build flag identity must remain native input"
        );
        assert_ne!(
            digest(&plan.flags_digest, &"42".repeat(32), &plan.tools),
            baseline,
            "bootstrap implementation must remain native input"
        );
        let mut tools = plan.tools.clone();
        tools.cmake.digest = "43".repeat(32);
        assert_ne!(
            digest(&plan.flags_digest, &plan.implementation_digest, &tools),
            baseline,
            "native tool identity must remain native input"
        );
    }

    #[test]
    fn lock_rejects_unknown_duplicate_missing_and_noncanonical_values() {
        let unknown = String::from_utf8(LOCK.to_vec())
            .expect("UTF-8 lock")
            .replace(
                "linkage = \"static\"",
                "future = \"no\"\nlinkage = \"static\"",
            );
        assert!(matches!(
            decode_lock(unknown.as_bytes()),
            Err(LockError::UnknownField(field)) if field == "llvm.future"
        ));

        let duplicate = String::from_utf8(LOCK.to_vec())
            .expect("UTF-8 lock")
            .replace(
                "version = \"22.1.3\"",
                "version = \"22.1.3\"\nversion = \"22.1.3\"",
            );
        assert!(matches!(
            decode_lock(duplicate.as_bytes()),
            Err(LockError::DuplicateField(field)) if field == "llvm.version"
        ));

        let missing = String::from_utf8(LOCK.to_vec())
            .expect("UTF-8 lock")
            .replace("linkage = \"static\"\n", "");
        assert_eq!(
            decode_lock(missing.as_bytes()),
            Err(LockError::MissingField("llvm.linkage"))
        );

        let noncanonical = String::from_utf8(LOCK.to_vec())
            .expect("UTF-8 lock")
            .replace("schema = 2", "schema=2");
        assert_eq!(
            decode_lock(noncanonical.as_bytes()),
            Err(LockError::NonCanonical)
        );

        let wrong_target = String::from_utf8(LOCK.to_vec())
            .expect("UTF-8 lock")
            .replace("targets = [\"AArch64\"]", "targets = [\"X86\"]");
        assert_eq!(
            decode_lock(wrong_target.as_bytes()),
            Err(LockError::InvalidValue("llvm.targets"))
        );
    }

    #[test]
    fn archive_digest_mismatch_is_fatal() {
        let temp = TempDirectory::new("digest");
        let archive = temp.path().join("archive.tar.xz");
        fs::write(&archive, b"not llvm").expect("write archive fixture");
        let error =
            verify_file_digest(&archive, &"11".repeat(32)).expect_err("digest mismatch must fail");
        assert!(error.contains("SHA-256 mismatch"));
        assert!(error.contains(&sha256_bytes(b"not llvm")));
    }

    #[test]
    fn archive_paths_and_member_types_fail_closed() {
        for path in [
            "/absolute",
            "llvm-project-22.1.3.src/../escape",
            "llvm-project-22.1.3.src/nested\\escape",
            "other-root/file",
        ] {
            assert!(
                validate_archive_path(path, "llvm-project-22.1.3.src").is_err(),
                "accepted unsafe path {path:?}"
            );
        }
        assert_eq!(
            validate_archive_path(
                "llvm-project-22.1.3.src/llvm/CMakeLists.txt",
                "llvm-project-22.1.3.src"
            )
            .expect("safe member"),
            Some("llvm/CMakeLists.txt".to_owned())
        );

        let temp = TempDirectory::new("tar-policy");
        let symlink = tar_archive(&[("llvm-project-22.1.3.src/link", b'2', &b""[..])]);
        let error = extract_tar_stream(
            Cursor::new(symlink),
            temp.path(),
            "llvm-project-22.1.3.src",
            None,
            &[],
        )
        .expect_err("symlink member must fail");
        assert!(error.contains("symbolic-link"));

        let traversal = tar_archive(&[("llvm-project-22.1.3.src/../escape", b'0', &b""[..])]);
        assert!(
            extract_tar_stream(
                Cursor::new(traversal),
                temp.path(),
                "llvm-project-22.1.3.src",
                None,
                &[],
            )
            .is_err()
        );
    }

    #[test]
    fn safe_regular_tar_member_extracts_beneath_root() {
        let temp = TempDirectory::new("tar-success");
        let archive = tar_archive(&[
            ("llvm-project-22.1.3.src/", b'5', &b""[..]),
            (
                "llvm-project-22.1.3.src/llvm/CMakeLists.txt",
                b'0',
                &b"project(LLVM)\n"[..],
            ),
        ]);
        extract_tar_stream(
            Cursor::new(archive),
            temp.path(),
            "llvm-project-22.1.3.src",
            None,
            &[],
        )
        .expect("safe archive");
        assert_eq!(
            fs::read(temp.path().join("llvm/CMakeLists.txt")).expect("extracted file"),
            b"project(LLVM)\n"
        );
    }

    #[test]
    fn global_pax_is_narrowly_bounded_to_the_release_commit_comment() {
        let temp = TempDirectory::new("global-pax");
        let commit = "a".repeat(40);
        let comment = pax_record("comment", &commit);
        let archive = tar_archive(&[
            ("pax_global_header", b'g', comment.as_slice()),
            ("llvm-project-22.1.3.src/", b'5', &b""[..]),
            (
                "llvm-project-22.1.3.src/llvm/CMakeLists.txt",
                b'0',
                &b"project(LLVM)\n"[..],
            ),
        ]);
        extract_tar_stream(
            Cursor::new(archive),
            temp.path(),
            "llvm-project-22.1.3.src",
            Some(&commit),
            &[],
        )
        .expect("bounded release metadata");

        let temp = TempDirectory::new("global-pax-path");
        let path = pax_record("path", "../../escape");
        let archive = tar_archive(&[("pax_global_header", b'g', path.as_slice())]);
        assert!(
            extract_tar_stream(
                Cursor::new(archive),
                temp.path(),
                "llvm-project-22.1.3.src",
                Some(&commit),
                &[],
            )
            .is_err()
        );
    }

    #[test]
    fn verified_symlink_inventory_is_omitted_exactly_and_never_materialized() {
        let temp = TempDirectory::new("verified-symlink");
        let path = "llvm-project-22.1.3.src/llvm/optional-link";
        let relative = "llvm/optional-link";
        let archive = tar_symlink_archive(path, "real-file");
        extract_tar_stream(
            Cursor::new(archive),
            temp.path(),
            "llvm-project-22.1.3.src",
            None,
            &[(relative, "real-file")],
        )
        .expect("exact verified symlink omission");
        assert!(!temp.path().join(relative).exists());

        let temp = TempDirectory::new("wrong-symlink-target");
        let archive = tar_symlink_archive(path, "other-file");
        assert!(
            extract_tar_stream(
                Cursor::new(archive),
                temp.path(),
                "llvm-project-22.1.3.src",
                None,
                &[(relative, "real-file")],
            )
            .is_err()
        );
    }

    #[test]
    fn command_plan_is_static_aarch64_only_and_bounded() {
        let temp = TempDirectory::new("command-plan");
        let plan = fake_plan(temp.path(), 7);
        let source = temp.path().join("source");
        let build = temp.path().join("build");
        let prefix = temp.path().join("prefix");
        for directory in [&source, &build, &prefix] {
            fs::create_dir(directory).expect("command directory");
        }
        let (configure, build_llvm_config, install) =
            build_commands(&plan, &source, &build, &prefix, &plan.cmake_contract)
                .expect("command plan");
        let arguments = strings(&configure);
        assert!(arguments.contains(&"-DLLVM_ENABLE_PROJECTS=lld".to_owned()));
        assert!(arguments.contains(&"-DLLVM_TARGETS_TO_BUILD=AArch64".to_owned()));
        assert!(arguments.contains(&"-DBUILD_SHARED_LIBS=OFF".to_owned()));
        assert!(arguments.contains(&"-DLLVM_BUILD_LLVM_DYLIB=OFF".to_owned()));
        assert!(arguments.contains(&"-DLLD_BUILD_TOOLS=OFF".to_owned()));
        assert!(arguments.contains(&format!("-DLLVM_FORCE_VC_REVISION={}", plan.lock.commit)));
        assert!(!arguments.iter().any(|argument| argument.contains("X86")));
        assert_eq!(
            strings(&build_llvm_config),
            [
                "--build",
                build.to_str().expect("UTF-8"),
                "--target",
                "llvm-config",
                "--parallel",
                "7"
            ]
        );
        assert_eq!(
            strings(&install),
            [
                "--build",
                build.to_str().expect("UTF-8"),
                "--target",
                "install-distribution",
                "--parallel",
                "7"
            ]
        );
        let distribution = format!(
            "-DLLVM_DISTRIBUTION_COMPONENTS={}",
            super::required_distribution_components().join(";")
        );
        assert!(arguments.contains(&distribution));
        assert!(arguments.contains(&"-DLLVM_STRICT_DISTRIBUTIONS=ON".to_owned()));
        for forbidden in super::FORBIDDEN_LLD_STATIC_COMPONENTS {
            assert!(
                !distribution
                    .split(';')
                    .any(|component| component == *forbidden)
            );
        }
        assert!(
            configure
                .environment
                .iter()
                .any(|(key, value)| key == "SOURCE_DATE_EPOCH" && value == "1")
        );
    }

    #[test]
    fn deterministic_source_patches_are_exact_and_fail_closed() {
        const HOST_PROBE: &str = "      set(config_guess ${LLVM_MAIN_SRC_DIR}/cmake/config.guess)\n      execute_process(COMMAND sh ${config_guess}\n        RESULT_VARIABLE TT_RV\n        OUTPUT_VARIABLE TT_OUT\n        OUTPUT_STRIP_TRAILING_WHITESPACE)\n      if( NOT TT_RV EQUAL 0 )\n        message(FATAL_ERROR \"Failed to execute ${config_guess}\")\n      endif( NOT TT_RV EQUAL 0 )\n      set( value ${TT_OUT} )";
        const LLD_ALIASES: &str =
            "foreach(link ${LLD_SYMLINKS_TO_CREATE})\n  add_lld_symlink(${link} lld)\nendforeach()";
        let temp = TempDirectory::new("source-patches");
        let host_path = temp.path().join("llvm/cmake/modules/GetHostTriple.cmake");
        let lld_path = temp.path().join("lld/tools/lld/CMakeLists.txt");
        fs::create_dir_all(host_path.parent().expect("host parent")).expect("host parent");
        fs::create_dir_all(lld_path.parent().expect("lld parent")).expect("lld parent");
        fs::write(&host_path, format!("before\n{HOST_PROBE}\nafter\n")).expect("host source");
        fs::write(&lld_path, format!("before\n{LLD_ALIASES}\nafter\n")).expect("lld source");

        patch_deterministic_source(temp.path()).expect("reviewed source patches");
        let host = fs::read_to_string(&host_path).expect("patched host source");
        assert!(host.contains("set(value ${WRELA_CANONICAL_HOST_TRIPLE})"));
        let lld = fs::read_to_string(&lld_path).expect("patched lld source");
        assert!(lld.contains("if(LLD_BUILD_TOOLS)\n  foreach(link"));
        assert!(patch_deterministic_source(temp.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn controlled_path_links_only_the_fingerprinted_touch() {
        let temp = TempDirectory::new("controlled-touch");
        let plan = fake_plan(temp.path(), 1);
        fs::write(&plan.tools.touch.path, b"touch fixture").expect("touch fixture");
        let build = temp.path().join("build");
        fs::create_dir(&build).expect("build directory");
        prepare_controlled_tool_path(&build, &plan.tools).expect("controlled native PATH");
        let link = build.join("wrela-host-tools/bin/touch");
        assert!(
            fs::symlink_metadata(&link)
                .expect("touch link metadata")
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read_link(link).expect("touch link target"),
            plan.tools.touch.path
        );
    }

    #[cfg(unix)]
    #[test]
    fn tool_identity_preserves_multicall_symlink_basename() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temp = TempDirectory::new("tool-basename");
        let target = temp.path().join("multicall-driver");
        fs::write(&target, b"reviewed executable bytes").expect("tool target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).expect("tool mode");
        let invocation = temp.path().join("clang++");
        symlink(&target, &invocation).expect("tool symlink");

        let identity = identify_tool(&invocation).expect("tool identity");
        assert_eq!(
            identity.path.file_name(),
            Some(std::ffi::OsStr::new("clang++"))
        );
        assert_ne!(identity.path.file_name(), target.file_name());
        assert_eq!(identity.digest, sha256_bytes(b"reviewed executable bytes"));
    }

    #[test]
    fn deterministic_archive_metadata_is_validated_member_by_member() {
        let temp = TempDirectory::new("archive-metadata");
        let archive = temp.path().join("library.a");

        fs::write(
            &archive,
            ar_member("fixture.o/", 0, 0, 0, 0o100644, b"object"),
        )
        .expect("canonical archive");
        validate_deterministic_archive(&archive).expect("canonical object metadata");

        fs::write(
            &archive,
            ar_member("__.SYMDEF", 0, 0, 0, 0, b"symbol-index"),
        )
        .expect("canonical symbol table");
        validate_deterministic_archive(&archive).expect("reserved mode-zero metadata");

        fs::write(&archive, ar_member("fixture.o/", 0, 0, 0, 0, b"object"))
            .expect("bad object mode");
        assert!(validate_deterministic_archive(&archive).is_err());

        fs::write(
            &archive,
            ar_member("fixture.o/", 0, 501, 20, 0o100644, b"object"),
        )
        .expect("ambient ownership");
        assert!(validate_deterministic_archive(&archive).is_err());
    }

    #[test]
    fn static_prefix_rejects_shared_library_payloads() {
        let temp = TempDirectory::new("shared-library");
        let shared = temp.path().join("libLLVM.dylib");
        fs::write(shared, b"not allowed").expect("shared fixture");
        assert!(validate_static_prefix(temp.path()).is_err());
    }

    #[test]
    fn static_archive_inventory_is_exact_and_rejects_unused_lld_flavors() {
        let temp = TempDirectory::new("static-install-closure");
        let plan = fake_plan(temp.path(), 1);
        write_fake_prefix(&plan);
        validate_static_archive_inventory(&plan.prefix).expect("exact static closure");

        let forbidden = plan.prefix.join("lib/liblldELF.a");
        fs::write(&forbidden, canonical_ar(b"forbidden ELF flavor"))
            .expect("forbidden archive fixture");
        let error = validate_static_archive_inventory(&plan.prefix)
            .expect_err("unused LLD flavor must fail");
        assert!(error.contains("forbidden unused LLD flavor"));

        fs::remove_file(&forbidden).expect("remove top-level forbidden archive");
        let nested = plan.prefix.join("lib/hidden/liblldELF.a");
        fs::create_dir_all(nested.parent().expect("nested parent"))
            .expect("create nested archive directory");
        fs::write(&nested, canonical_ar(b"nested forbidden ELF flavor"))
            .expect("nested forbidden archive fixture");
        let error = validate_static_archive_inventory(&plan.prefix)
            .expect_err("nested static archive must fail");
        assert!(error.contains("empty or misplaced static archive"));
    }

    #[cfg(unix)]
    #[test]
    fn tree_measurement_commits_directory_and_file_modes() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDirectory::new("tree-modes");
        let directory = temp.path().join("empty");
        let file = temp.path().join("file");
        fs::create_dir(&directory).expect("empty directory");
        fs::write(&file, b"payload").expect("tree file");
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755)).expect("root mode");
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).expect("directory mode");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).expect("file mode");
        let baseline = measure_tree(temp.path()).expect("baseline tree");

        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .expect("changed dir mode");
        let directory_changed = measure_tree(temp.path()).expect("directory mode tree");
        assert_ne!(directory_changed.digest, baseline.digest);

        fs::set_permissions(&directory, fs::Permissions::from_mode(0o755)).expect("restore dir");
        fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).expect("changed file mode");
        let file_changed = measure_tree(temp.path()).expect("file mode tree");
        assert_ne!(file_changed.digest, baseline.digest);
    }

    #[test]
    fn cmake_uses_a_create_new_copy_of_the_hashed_bytes() {
        let temp = TempDirectory::new("staged-cmake");
        let mut plan = fake_plan(temp.path(), 1);
        plan.cmake_bytes = b"set(WRELA_REVIEWED_CONTRACT ON)\n".to_vec();
        plan.cmake_digest = sha256_bytes(&plan.cmake_bytes);
        let build = temp.path().join("build");
        fs::create_dir(&build).expect("build directory");
        let staged = stage_cmake_contract(&build, &plan).expect("stage CMake contract");
        assert_eq!(fs::read(&staged).expect("staged bytes"), plan.cmake_bytes);
        assert!(stage_cmake_contract(&build, &plan).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn receipt_reuse_rehashes_complete_prefix_and_rejects_mutation() {
        let temp = TempDirectory::new("receipt");
        let mut plan = fake_plan(temp.path(), 1);
        write_fake_prefix(&plan);
        let measurement = measure_tree(&plan.prefix).expect("measure fake prefix");
        plan.expected_output = Some(expected_output_for_measurement(&plan, &measurement));
        let receipt = receipt_for_plan(&plan, &measurement);
        fs::write(plan.bundle.join("provenance.txt"), encode_receipt(&receipt))
            .expect("write receipt");
        assert_eq!(
            verify_published_bundle(&plan).expect("verified reuse"),
            Some(plan.prefix.clone())
        );
        fs::write(plan.prefix.join("include/llvm/IR/Module.h"), b"mutated").expect("mutate prefix");
        assert!(verify_published_bundle(&plan).is_err());
    }

    #[test]
    fn receipt_decoder_rejects_unknown_and_noncanonical_data() {
        let receipt = fake_receipt();
        let encoded = encode_receipt(&receipt);
        assert_eq!(decode_receipt(&encoded).expect("receipt"), receipt);
        let mut unknown = encoded.clone();
        unknown.extend_from_slice(b"future=value\n");
        assert!(decode_receipt(&unknown).is_err());
        let noncanonical = String::from_utf8(encoded)
            .expect("UTF-8 receipt")
            .replace("prefix_files=1", "prefix_files=01");
        assert!(decode_receipt(noncanonical.as_bytes()).is_err());
        assert_eq!(RECEIPT_SCHEMA, 3);
    }

    fn fake_plan(root: &Path, jobs: u32) -> BuildPlan {
        let lock = decode_lock(LOCK).expect("lock");
        let digest = "11".repeat(32);
        let tools = NativeTools {
            xz: fake_tool(root, "xz", &digest),
            cmake: fake_tool(root, "cmake", &"12".repeat(32)),
            ninja: fake_tool(root, "ninja", &"13".repeat(32)),
            cc: fake_tool(root, "clang", &"14".repeat(32)),
            cxx: fake_tool(root, "clang++", &"15".repeat(32)),
            ar: fake_tool(root, "ar", &"16".repeat(32)),
            ranlib: fake_tool(root, "ranlib", &"17".repeat(32)),
            python: fake_tool(root, "python3", &"18".repeat(32)),
            linker: fake_tool(root, "ld", &"19".repeat(32)),
            sysroot: None,
            touch: fake_tool(root, "touch", &"20".repeat(32)),
            shell: fake_tool(root, "sh", &"31".repeat(32)),
            host_closure: HostClosureIdentity {
                digest: "32".repeat(32),
                roots: Vec::new(),
            },
        };
        let bundle = root.join("build/toolchain/llvm/prefixes").join("test-key");
        BuildPlan {
            workspace_root: root.to_owned(),
            lock: lock.clone(),
            lock_digest: "21".repeat(32),
            cmake_contract: root.join("WrelaLLVM.cmake"),
            cmake_bytes: b"fixture CMake contract".to_vec(),
            cmake_digest: "22".repeat(32),
            codegen_binding_digest: "29".repeat(32),
            rust_binding_digest: "30".repeat(32),
            flags_digest: normalized_flags_digest(&lock),
            implementation_digest: "20".repeat(32),
            bootstrap_executable: fake_tool(root, "xtask", &"33".repeat(32)),
            host: "test-host".to_owned(),
            input_digest: "23".repeat(32),
            key: "test-key".to_owned(),
            prefix: bundle.join("prefix"),
            bundle,
            expected_output: None,
            license_notices: vec![LicenseNotice {
                destination: "share/wrela/licenses/test/LICENSE.TXT".to_owned(),
                digest: sha256_bytes(b"reviewed test license\n"),
            }],
            tools,
            jobs,
        }
    }

    fn fake_tool(root: &Path, name: &str, digest: &str) -> ToolIdentity {
        ToolIdentity {
            path: root.join(name),
            digest: digest.to_owned(),
        }
    }

    fn fake_receipt() -> ProvenanceReceipt {
        ProvenanceReceipt {
            input_digest: "11".repeat(32),
            llvm_version: "22.1.3".to_owned(),
            llvm_tag: "llvmorg-22.1.3".to_owned(),
            llvm_commit: "e9846648fd6183ee6d8cbdb4502213fcf902a211".to_owned(),
            source_url: "https://example.invalid/llvm.tar.xz".to_owned(),
            archive_sha256: "12".repeat(32),
            archive_bytes: 1,
            lock_sha256: "13".repeat(32),
            cmake_sha256: "14".repeat(32),
            codegen_binding_sha256: "29".repeat(32),
            rust_binding_sha256: "30".repeat(32),
            flags_sha256: "15".repeat(32),
            implementation_sha256: "16".repeat(32),
            host: "test-host".to_owned(),
            xz_sha256: "17".repeat(32),
            cmake_tool_sha256: "18".repeat(32),
            ninja_sha256: "19".repeat(32),
            cc_sha256: "20".repeat(32),
            cxx_sha256: "21".repeat(32),
            ar_sha256: "22".repeat(32),
            ranlib_sha256: "23".repeat(32),
            python_sha256: "24".repeat(32),
            linker_sha256: "25".repeat(32),
            sysroot_sha256: "26".repeat(32),
            touch_sha256: "27".repeat(32),
            shell_sha256: "31".repeat(32),
            host_closure_sha256: "32".repeat(32),
            prefix_tree_sha256: "28".repeat(32),
            prefix_files: 1,
            prefix_bytes: 1,
        }
    }

    #[cfg(unix)]
    fn write_fake_prefix(plan: &BuildPlan) {
        let prefix = &plan.prefix;
        let static_suffix = if cfg!(windows) { ".lib" } else { ".a" };
        let static_prefix = if cfg!(windows) { "" } else { "lib" };
        let llvm_config = prefix.join("bin/llvm-config");
        fs::create_dir_all(llvm_config.parent().expect("bin parent")).expect("create bin");
        let library_names = REQUIRED_LLVM_STATIC_COMPONENTS
            .iter()
            .map(|component| format!("{static_prefix}{component}{static_suffix}"))
            .collect::<Vec<_>>()
            .join(" ");
        let script = format!(
            "#!/bin/sh\ncase \"$1\" in\n  --version) printf '22.1.3\\n' ;;\n  --targets-built) printf 'AArch64\\n' ;;\n  --shared-mode) printf 'static\\n' ;;\n  --host-target) printf 'test-host\\n' ;;\n  --libnames) [ \"$2\" = --link-static ] || exit 64; printf '%s\\n' '{library_names}' ;;\n  *) exit 64 ;;\nesac\n"
        );
        fs::write(&llvm_config, script).expect("write llvm-config fixture");
        super::set_staged_executable_permissions(&llvm_config)
            .expect("mark fake llvm-config executable");

        for (relative, contents) in [
            ("include/llvm/IR/Module.h", b"LLVM module header".as_slice()),
            (
                "include/lld/Common/Driver.h",
                b"LLD driver header".as_slice(),
            ),
        ] {
            let path = prefix.join(relative);
            fs::create_dir_all(path.parent().expect("include parent")).expect("create include");
            fs::write(path, contents).expect("write include fixture");
        }
        for component in REQUIRED_LLVM_STATIC_COMPONENTS
            .iter()
            .chain(REQUIRED_LLD_STATIC_COMPONENTS)
        {
            let path = prefix.join(format!("lib/{static_prefix}{component}{static_suffix}"));
            fs::create_dir_all(path.parent().expect("library parent")).expect("create library");
            fs::write(&path, canonical_ar(component.as_bytes())).expect("write static archive");
        }
        for notice in &plan.license_notices {
            let path = prefix.join(&notice.destination);
            fs::create_dir_all(path.parent().expect("license parent")).expect("create license");
            fs::write(path, b"reviewed test license\n").expect("write license fixture");
        }
    }

    fn canonical_ar(payload: &[u8]) -> Vec<u8> {
        ar_member("fixture.o/", 0, 0, 0, 0o100644, payload)
    }

    fn ar_member(
        name: &str,
        timestamp: u64,
        uid: u64,
        gid: u64,
        mode: u64,
        payload: &[u8],
    ) -> Vec<u8> {
        let timestamp = timestamp.to_string();
        let uid = uid.to_string();
        let gid = gid.to_string();
        let mode = format!("{mode:o}");
        let size = payload.len().to_string();
        let header = format!(
            "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
            name, timestamp, uid, gid, mode, size
        );
        assert_eq!(header.len(), 60);
        let mut archive = b"!<arch>\n".to_vec();
        archive.extend_from_slice(header.as_bytes());
        archive.extend_from_slice(payload);
        if payload.len() % 2 != 0 {
            archive.push(b'\n');
        }
        archive
    }

    fn strings(spec: &CommandSpec) -> Vec<String> {
        spec.arguments
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect()
    }

    fn tar_archive(entries: &[(&str, u8, &[u8])]) -> Vec<u8> {
        let mut archive = Vec::new();
        for (path, kind, payload) in entries {
            let mut header = [0_u8; 512];
            assert!(path.len() <= 100);
            header[..path.len()].copy_from_slice(path.as_bytes());
            write_octal(&mut header[100..108], 0o644);
            write_octal(&mut header[108..116], 0);
            write_octal(&mut header[116..124], 0);
            write_octal(&mut header[124..136], payload.len() as u64);
            write_octal(&mut header[136..148], 0);
            header[148..156].fill(b' ');
            header[156] = *kind;
            header[257..263].copy_from_slice(b"ustar\0");
            header[263..265].copy_from_slice(b"00");
            let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
            let checksum_text = format!("{checksum:06o}\0 ");
            header[148..156].copy_from_slice(checksum_text.as_bytes());
            archive.extend_from_slice(&header);
            archive.extend_from_slice(payload);
            let padding = (512 - payload.len() % 512) % 512;
            archive.resize(archive.len() + padding, 0);
        }
        archive.resize(archive.len() + 1024, 0);
        archive
    }

    fn tar_symlink_archive(path: &str, target: &str) -> Vec<u8> {
        assert!(target.len() <= 100);
        let mut archive = tar_archive(&[(path, b'2', &b""[..])]);
        archive[157..157 + target.len()].copy_from_slice(target.as_bytes());
        archive[148..156].fill(b' ');
        let checksum: u64 = archive[..512].iter().map(|byte| u64::from(*byte)).sum();
        let checksum_text = format!("{checksum:06o}\0 ");
        archive[148..156].copy_from_slice(checksum_text.as_bytes());
        archive
    }

    fn write_octal(field: &mut [u8], value: u64) {
        let digits = format!("{:0width$o}\0", value, width = field.len() - 1);
        field.copy_from_slice(digits.as_bytes());
    }

    fn pax_record(key: &str, value: &str) -> Vec<u8> {
        let body = format!("{key}={value}\n");
        let mut length = body.len() + 2;
        loop {
            let record = format!("{length} {body}");
            if record.len() == length {
                return record.into_bytes();
            }
            length = record.len();
        }
    }
}
