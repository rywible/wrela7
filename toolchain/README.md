# Private toolchain inputs

This directory contains declarative, reviewable inputs used to construct wrela
release bundles. It is not itself the installed layout.

- `llvm.lock.toml` pins the source and linkage contract for LLVM, LLD, and
  Inkwell.
- `llvm.outputs.toml` authenticates the complete installed prefix for one exact
  reviewed bootstrap-input digest and supported host.
- `emulation.lock.toml` pins the signed QEMU source, AArch64-only system target,
  versioned machine/CPU/TCG contract, and exact decompressed EDK2 code/variable
  firmware digests and license manifest.
- `emulation.outputs.toml`, when present, authenticates one complete measured
  QEMU/firmware payload for the exact source, signature, signing key, host-tool,
  dynamic-runtime, static-library, SDK, configuration, and
  bootstrap-implementation identity.
- `rust.outputs.toml` authenticates the exact host Cargo/rustc binaries, their
  canonical version reports, and the complete Rust sysroot closure selected by
  `rust-toolchain.toml`.
- `cargo.outputs.toml` binds `Cargo.lock`, the enrolled Cargo executable, and
  the complete versioned dependency-vendor tree used by every offline release
  build and gate.
- `cmake/WrelaLLVM.cmake` contains the common LLVM distribution cache settings.
- `targets/` contains the package copied under `share/wrela/targets` by the
  distribution task. Revision 0.1 ships only the full-image
  `aarch64-qemu-virt-uefi` machine profile, including its runtime and firmware.
- the distribution also ships a pinned `qemu-system-aarch64` for full-image
  integration and image tests.

The current Darwin-native distributor is a bootstrap path, not the final host
architecture. Its supported bootstrap host is Apple Silicon macOS 13.0 or
newer: the enrolled LLVM/LLD archives, C++ LLD shim, Rust native compilation,
and final host links share the exact macOS 13.0 deployment target, and a missing
or mismatched target fails closed. A two-lane producer now enrolls the real
static AArch64 Linux-musl `wrela-engine` as an independently inspected,
content-addressed private bundle. Its default command is a narrow artifact
consumer: it validates the output lock, exact bundle/receipt identity and
policy, and static ELF contract without reopening the multi-gigabyte Darwin
bootstrap closure. Full build-authority checks remain in planning, enrollment,
and release gates. This artifact has not yet executed on Linux or in the
immutable appliance (`execution_proven=false`), and its receipt still binds the
Darwin bootstrap identity. Linux direct/appliance modes and the thin
Virtualization.framework macOS launcher therefore remain open. After those
routes and their conformance gates pass, the Darwin-native
compiler/backend/QEMU payload is removed without a compatibility shim. In that
final architecture, ordinary public compiler identity binds the measured Linux
engine environment, not the Darwin launcher, its code signature, or its
notarization envelope.

`cargo xtask llvm` is the supported LLVM/LLD bootstrap. It strictly decodes the
canonical schema-2 lock, checks the exact Inkwell feature contract, downloads
the exact HTTPS release into `.cache/wrela/llvm` (or accepts an explicit local
archive), verifies byte count and SHA-256 before extraction, and rejects archive
links and unsafe member paths. The build uses fingerprinted absolute host tools,
bounded parallelism, the checked-in CMake contract, and only static AArch64 LLVM
plus LLD.

Successful installs are published atomically under the full native-input digest
in `build/toolchain/llvm/prefixes`. The input identity includes the exact LLVM
bootstrap source, its projected command-dispatch/workspace-root contract, the
pinned `sha2` manifest declaration and resolved checksum closure, normalized
LLVM build flags, and the complete measured macOS SDK, Clang resources, linker
libraries, Python/CMake/Ninja/xz installations, system metadata, and full
architecture dyld-cache contents. Unrelated xtask commands are deliberately
outside that identity; the running executable is still fingerprinted before
and after native work to reject replacement during a build. Source and
installed-tree timestamps are normalized to the declared epoch. A canonical
provenance receipt binds those inputs and a complete mode/timestamp/content
measurement of the prefix.

Ordinary reuse is fail-closed: `toolchain/llvm.outputs.toml` must independently
pin that exact input digest and prefix tree before any cached `llvm-config` is
executed. Maintainers use `--record-output` only when the lock is intentionally
absent; it performs a fresh exclusive build, creates and fsyncs the strict lock,
then permits atomic publication. Stale crashed staging leases are removed only
after their PID/start identity is no longer live. Run `cargo xtask llvm --help`
for the offline archive and explicit tool overrides; run `--plan` to validate
and print the plan without downloading, creating caches, or building.

`cargo xtask qemu` is the supported emulator bootstrap. It strictly decodes the
schema-1 emulation lock, obtains the exact HTTPS release archive and detached
signature (or accepts explicit absolute local files), and imports only the
pinned release-manager key into a new private GnuPG home. Authentication
requires either one current `GOODSIG` or one historically valid `EXPKEYSIG`,
plus exactly one `VALIDSIG`, from the exact primary fingerprint and key ID. The
historical path additionally requires a successful GnuPG command, one or more
mutually consistent `KEYEXPIRED` records matching the isolated key inventory,
and a signature epoch from key creation (inclusive) to key expiry (exclusive).
Bad, missing, ambiguous, revoked, signature-expired, or error statuses remain
fatal. The archive SHA-256 is checked independently before extraction.

Extraction is a bounded in-process ustar/PAX/GNU parser. It rejects traversal,
portable-path collisions, hard links, devices, FIFOs, sparse files, unsafe
symbolic links, malformed padding/checksums, oversized members/aggregates, and
nonzero trailers. The one absolute X11 include symlink in the authenticated
vendored EDK2 source is matched exactly and omitted because it is not a build
input. The build uses an empty environment, absolute content-fingerprinted
tools, the complete measured Apple toolchain and Clang resources, the complete
Python runtime, a recursively inspected and measured Homebrew dynamic-library
closure, the sealed macOS build identity for system libraries, the complete
macOS SDK, a generated SDK-backed zlib pkg-config contract, and a static
GLib/libfdt closure. A deterministic Clang resource overlay exposes only the
measured compiler runtime and static `libfdt.a` to Meson's static-library
discovery. The exact `clang++` invocation path is retained so Clang
selects its C++ driver mode, and bzip2 plus Apple's `nm`, `diff`, `Rez`,
`SetFile`, and `codesign` are available only through the controlled host-tool
directory. The exact authenticated QEMU 10.1.5 `meson.build` is transformed by
a whole-file-digest-checked reviewed patch that retains static dependency
selection while suppressing the impossible global `-static` linker flag only
on Darwin; the final Mach-O closure independently rejects dynamic third-party
libraries. Deterministic prefix maps,
`SOURCE_DATE_EPOCH`, no network/subproject downloads, and exactly the
`aarch64-softmmu` system target are mandatory. Optional displays, accelerators,
tools, agents, plugins, network backends, and dynamic third-party integrations
are disabled. The writable `fat:rw:` ESP contract requires QEMU's vvfat block
driver and vvfat's internal qcow1 write overlay, so build contract 20 explicitly
compiles in both `vvfat` and `qcow1` while modules remain disabled. The contract
commits those inputs, the exact QEMU bootstrap source, its projected
command-dispatch/workspace-root contract, and the pinned `sha2` manifest
declaration plus resolved checksum closure. The whole running xtask executable
is fingerprinted only before and after native work as a replacement guard, so
unrelated xtask commands do not invalidate an otherwise identical QEMU build.

The Apple archive indexer is invoked through the exact measured `ranlib`
driver path rather than its canonical `libtool` target. Xcode selects ranlib
mode from `argv[0]`; the invocation-relative path and the underlying binary are
both authenticated so canonicalization cannot silently change tool behavior.

The payload contains only `bin/qemu-system-aarch64`, the two exact decompressed
firmware blobs, QEMU/EDK2 licenses, and canonical provenance. The bootstrap
requires the exact measured seven-entry system Mach-O closure (CoreFoundation,
Foundation, IOKit, libSystem, libiconv, libobjc, and libz), rejects every other
dependency, probes the pinned
version/machine/CPU contracts, normalizes modes and timestamps, measures the
same whole-tree identity consumed by `cargo xtask dist`, and publishes under
`build/toolchain/qemu/prefixes/<version>-<native-input>/bundle` by atomic rename.
The current revision-20 enrollment binds native input
`1d126075a4feb7e6778f63ecf51557c9b1901cd3b83dee28bbcc53567832d71b`, bundle
tree `b654622277aae1175b2bd58f82092d4e939d63722c30a77227c3957b3f828f54`
(6 files / 166,762,675 bytes), and executable
`c5df7919a0853f1fd525803a157d49c8f2edd4120888b6ba4d04a0998eaa602e`
(32,482,992 bytes). The firmware digests remain the exact lock-pinned values.
No optional PCI option ROM is shipped. Networking is absent from the target
runner contract, so the distributor runtime boot, production test harness, and
standalone target runtime smoke all pass exact `-nic none` and never instantiate
QEMU's implicit default `virtio-net-pci` device.

`--plan` authenticates already-local inputs and prints identities without
network acquisition or building. `--offline` also forbids acquisition;
`--source-archive`, `--signature`, and `--signing-key` select verified local
inputs explicitly. Ordinary runs require an existing matching output lock. A
maintainer may use `--record-output` only while
`toolchain/emulation.outputs.toml` is absent; it performs a fresh build and
creates that canonical lock with create-new and fsync semantics. Run
`cargo xtask qemu --help` for all explicit tool overrides.

The QEMU source pin is 10.1.5. Its detached signature epoch, `1773797546`
(2026-03-18 UTC), is within the exact isolated primary-key lifetime
`[1382105359, 1778512387)`, even though that key is expired at verification time.
The rejected 10.0.11 signature was made after the same expiry and remains
invalid under the historical policy. QEMU 10.1.5 retains the reviewed
`virt-10.0` compatibility machine, `cortex-a57` CPU, and single-threaded TCG
contract; the two decompressed 64 MiB firmware blobs remain byte-identical to
the prior pin.

The target runtime object is enrolled separately by
`targets/aarch64-qemu-virt-uefi/runtime-src/runtime-object.lock.toml`. Its
receipt binds the exact compiler digest and first version line, builder and
assembly source digests, runtime ABI, object digest/length, ARM64 machine,
relocation count, and absence of undefined symbols. `build_runtime.py` accepts
only an absolute digest-matched compiler, builds twice in independent private
directories with a cleared environment, requires byte-identical COFF, and
reopens the result to enforce the closed symbol and relocation policy. The
distribution planner then requires that compiler identity to equal the host
compiler authenticated by the enrolled LLVM bootstrap; a host-tool rotation
therefore needs an intentional runtime rebuild and lock review even when the
resulting object bytes remain unchanged.

`cargo xtask cargo-vendor` is the supported clean-checkout dependency
acquisition route. It never executes `rustup`: Cargo and rustc are selected by
their exact enrolled sysroot paths, the entire sysroot is measured before either
tool executes, and a private exact sysroot copy performs acquisition from a
fresh Cargo home. Cargo runs outside the source checkout with an explicit
manifest, cleared environment, bounded output/time, and the sparse crates.io
protocol. The resulting versioned vendor tree is normalized independently of
the caller's umask, checked byte-for-byte and mode-for-mode against
`cargo.outputs.toml`, fsynced, and published under
`build/toolchain/cargo/prefixes/<Cargo.lock-sha256>/vendor` by atomic rename.
Once that authenticated tree exists, distribution builds and all release gates
are strictly locked and offline; they copy it into fresh sealed Cargo homes and
do not consult registry caches or network services.

An intentional `Cargo.lock` rewrite can change only workspace dependency edges
while retaining the exact registry closure. In that case maintainers use the
paired `cargo xtask cargo-vendor --record-output --reuse-enrolled` mode. The two
flags are required together and cannot be combined with Cargo, rustc, or Cargo
home options. This mode invokes no external tool and performs no network access:
it authenticates the exact current-schema old output enrollment and sealed
vendor tree, strictly decodes the current format-4 lock, and requires an exact
one-to-one match of every registry package name, version, and package checksum.
It then copies every enrolled file through bounded no-follow reads into a new
content-addressed prefix, forbids hard links, remeasures and seals the result,
and publishes that prefix before atomically replacing and fsyncing
`cargo.outputs.toml`. A create-new transaction lease in `toolchain/` is held
across both operations, so a second publisher cannot enter the authority window
or overwrite an independently reviewed enrollment. Normal completion and error
unwinding remove and fsync the lease; a process crash deliberately leaves it in
place and later attempts fail closed until an operator proves that publisher is
gone and removes the lease. A closure or checksum change fails before any new
prefix is created. A crash can therefore leave either the old enrollment
authoritative or an unreferenced exact new prefix, never an enrollment that
names an absent or unsealed dependency tree. This is exact-current
reenrollment, not a reader for older schemas or artifact formats.

Every release Cargo invocation receives a fresh private `CARGO_HOME` inside its
own isolated work root. Its exact configuration uses the canonical absolute
path of that home's copied vendor directory, enables offline mode, and replaces
`crates-io` with only that directory source. The home contains exactly the
configuration, the sealed vendor tree, and Cargo's three pre-created zero-byte
cache-lock files. Post-command validation rechecks contents, modes, link counts,
and the complete entry inventory; Cargo 1.95 is exercised from an unrelated
working directory with the public environment and `PATH` cleared.

Rust notices are fail-closed too. The reviewed Cargo.lock closure contributes
an exact 92-file crate-license tree, including the explicit Apache-2.0 notice
override for `inkwell_internals-0.14.0`; the enrolled Rust sysroot contributes
an exact 28-file standard-library/runtime notice tree. The combined 120-file
identity is remeasured after installation and bound into provenance and the
release receipt.

Distribution reproducibility uses two independent lanes, each with its own
sealed source snapshot, copied Rust sysroot, private Cargo home, target tree,
temporary home, and working directory. Their public compiler and backend bytes
must match before a separate verification tree runs installed and extracted
public commands, runtime boot, and real-QEMU smoke. Installation provenance
uses schema 3 and the current release receipt uses schema 4. They bind the
enrolled Rust/Cargo identities, vendor and license closures, both lane
measurements, installed-versus-extracted public output trees, and canonical
boot/QEMU evidence. The current producer requires both the bootstrap and
selected `core.time` real-QEMU harnesses on installed and extracted routes;
their existence is not successful current-schema runtime evidence. Planning
performs one complete LLVM/native authority seal, internal checkpoints use the
bounded source plus frozen metadata for selected direct paths, and a publishing
release performs one complete rescan immediately before publication. This does
not weaken ordinary LLVM cache reuse, which still authenticates the enrolled
input and complete prefix tree. Forbidden authority, staging, checkout, SDK,
native-prefix, sysroot, vendor, and emulator paths are scanned across the public
artifacts and reports before publication.
The real one-pass plan currently completes in 209.67 seconds and binds source
`9b925c…880c`, LLVM tree `e5460d…de3d`, and QEMU tree `b65462…28f54`; the
137-test xtask suite and warnings-denied all-target Clippy pass.
Every QEMU route also sets `TMPDIR` to an already-owned cleanup root: the runner
uses its per-group directory, the target runtime-smoke script uses its private
temporary directory, and the distributor's direct runtime routes use their
private smoke directory. Emulator scratch therefore remains inside the same
bounded, residue-checked lifecycle as the corresponding run.

`cargo xtask dist --integration-qemu --jobs 8` is the nonpublishing one-lane
integration route for the packaged-QEMU bootstrap, `core.time` pass and typed
fatal, and checked-shift pass and both typed fatals. It emits one bounded
path-free evidence line only after exact cleanup. The real command passes in
681.82 seconds against QEMU tree `b65462…28f54`; private installation
`e42956…24b2` executes the bootstrap, both `core.time` outcomes, and all three
checked-shift outcomes, then every private root is removed. This is integration
evidence, not two-lane release or publication evidence.

The following attempt-nine and attempt-ten paragraphs are historical failure
evidence. Attempt thirteen subsequently published the schema-3 Darwin
bootstrap. The current SemanticWir 6 / FlowWir 8 / wire 8 / MachineWir 8 and
schema-4 distribution source has not yet completed a fresh distribution.

The ninth full distribution attempt froze source
`382726349541c06c13fcd8d8d677f0fa40e7aa524a4cb6ae3a53da77900ed4c8`
(223 files), crossed the prior release-lane and repository/installed/runtime
gates, and failed closed at the pinned runtime QEMU before publication. The
emulator requested `efi-virtio.rom` for its implicit default `virtio-net-pci`;
the explicit virtio-block boot device was not the cause. Cleanup left the
distribution root empty and published no installation, receipt, or archive.
Against the same enrolled six-file bundle, an A/B launch probe reproduces the
failure without `-nic none` and reaches QMP capability negotiation plus clean
`quit` with it. The bundle and provenance are unchanged. The repaired exact
argument routes are covered by xtask 92/92 in 128.75 s, runner 30/30 plus 13/13
nonignored smoke tests (1 installed-system test ignored), strict Clippy, and
`cargo xgate testing` in 3.140 s. A complete runtime boot and full distribution
publication retry remain pending. The next complete attempt froze source
`f04d6d8df0f54f4ad55c39649430b62fd0b956b9a574d81845be2fa2cb07c8d8`
(223 files), crossed that repaired direct runtime boot, and failed closed in the
installed real-QEMU lifecycle. Installed public `wrela test` returned exit 1
with exact stdout `test failed\n` and empty stderr. Static tracing found the
generated entry called test runtime operations without first performing the
runtime ABI's mandatory `ImageEnter(image_handle, system_table)` transition.
Cleanup removed all attempt processes and private/publication paths, leaving no
installation, receipt, archive, or staging residue. The MachineWir v6 repair
introduced that prologue for minimum, ordinary, and generated-test entries,
reached the prior body only after zero status, and propagated nonzero
`EFI_STATUS` unchanged. The exact-current MachineWir v10 contract retains those
activation requirements with no v6 compatibility path. Its independent
validator rejects structural substitutions; exact resource/cancellation tests
include generated-test report bytes, and the COFF consumer requires the exact
instruction-aligned ARM64 branch relocation to `ImageEnter`. Pinned LLVM 22.1.3
tests and the machine, artifact, and testing gates pass. Selected generated-test
runtime assertions reach native ABI2 objects; current packaged-QEMU assertion,
bootstrap, `core.time`, and checked-shift replay plus schema-4 receipt/archive
audit remain required for the current source.

`cargo xtask dist` is the sole supported distribution assembly path. Cargo
package build scripts must not download LLVM or consult a global
`llvm-config`/`PATH` installation.
