# Toolchain architecture

Status: implementation architecture for the revision 0.1 compiler.

## Product contract

An installed wrela release is a **toolchain**, not a compiler frontend that asks
the host to supply missing pieces. A user can unpack or install one supported
host archive and run `wrela build` without installing Rust, LLVM, LLD, a C++
compiler, CMake, or Ninja. The toolchain does not find `llvm-config`, `lld`, or
an LLVM shared library through `PATH` or another global search path.

Self-contained means one atomic directory tree, not necessarily one executable
file. Keeping private components as separate processes gives better crash
containment and lets commands such as `wrela check` start without mapping LLVM.
The public command discovers the installation root relative to its own
executable. `WRELA_TOOLCHAIN_ROOT` exists only as an explicit development and
test override.

The initial release layout is:

```text
wrela-<release>-<host>/
├── bin/
│   └── wrela[.exe]
├── libexec/wrela/
│   └── wrela-backend[.exe]
└── share/
    ├── licenses/
    │   ├── wrela/
    │   ├── llvm/
    │   └── ...
    └── wrela/
        ├── toolchain.toml
        ├── std/
        └── targets/
            └── x86_64-uefi/
```

`share/wrela/toolchain.toml` is generated during packaging. It records a schema
version, frontend/backend protocol version, release and host triples, LLVM and
LLD revisions, supported targets, and hashes of shipped components. `wrela
doctor` validates the manifest and component hashes. A release is installed or
updated as a whole; mixing a frontend and backend from different releases is an
error.

## Workspace boundaries

The workspace uses crates to enforce the independently workable layer boundaries
of the compiler. A layer owns its output model; a separate transformation crate
owns conversion when keeping that conversion out of the model prevents a
dependency inversion. Every layer can be exercised with hand-built input
fixtures without constructing the layers before it.

| Crate | Responsibility | LLVM-linked |
|---|---|---:|
| `wrela-cli` | Thin public command, argument handling, exit status | No |
| `wrela-driver` | Build session and phase orchestration | No |
| `wrela-source` | Stable file IDs, source text, byte ranges, and spans | No |
| `wrela-diagnostics` | Structured diagnostics, labels, why-chains, and repair notes | No |
| `wrela-syntax` | Lexer, recoverable parser, syntax tree, and syntax dumps | No |
| `wrela-hir` | Pure normalized high-level source model | No |
| `wrela-hir-lower` | Desugaring and name resolution from syntax to HIR | No |
| `wrela-sema` | Types, effects, ownership, regions, actors, async, capacity, and hardware proofs | No |
| `wrela-target` | Validated host-independent target package contract | No |
| `wrela-wir` | Pure typed whole-image IR model | No |
| `wrela-wir-lower` | Analyzed-image to WIR lowering | No |
| `wrela-wir-passes` | WIR verifier, specialization, layout, and semantic optimizations | No |
| `wrela-wir-codec` | Deterministic versioned WIR serialization | No |
| `wrela-image-report` | Machine-readable report schema and readable rendering | No |
| `wrela-codegen-llvm` | Verified WIR to LLVM and COFF through private Inkwell | Yes, feature-gated |
| `wrela-lld-sys` | Raw unsafe C ABI boundary to the pinned LLD C++ shim | LLD only |
| `wrela-link-efi` | Safe target-owned COFF-to-UEFI link policy | LLD only |
| `wrela-backend-protocol` | Versioned private process request/response and artifact contract | No |
| `wrela-toolchain` | Bundle discovery, target/standard-library lookup, integrity checks | No |
| `wrela-backend` | Private composition process for codec, verifier, codegen, linker, and report | Transitively |
| `xtask` | Maintainer-only LLVM build, licensing, packaging, release QA | No |

The enforced dependency flow is:

```text
wrela-source
    ├──→ wrela-diagnostics
    └──→ wrela-syntax
             ↓
      wrela-hir-lower → wrela-hir
                              ↓
                         wrela-sema ← wrela-target
                              ↓
                       wrela-wir-lower
                              ↓
                         wrela-wir
                         ├──────────────→ wrela-wir-codec
                         └──────────────→ wrela-wir-passes
                                                   ↓
                                      wrela-codegen-llvm → COFF
                                                   ↓
                       wrela-lld-sys ← wrela-link-efi → .efi
```

The data crates (`source`, `hir`, `target`, `wir`, and `image-report`) do not
depend on the transformation that produces or consumes them. For example,
`wrela-wir` cannot depend on semantic lowering, verification, serialization, or
LLVM. This keeps models constructible in unit tests and prevents a backend type
from leaking upstream.

`wrela-sema` is intentionally one crate. Type, effect, ownership, region, actor,
async, capacity, and hardware analyses are expected to participate in a shared
fixed point. They begin as internal modules and split only when a real acyclic
contract emerges. The same rule keeps the lexer and parser together in
`wrela-syntax` and the individual WIR transformations together in
`wrela-wir-passes`.

All language-level safety and capacity properties are established and
re-verified in WIR before LLVM sees the program. Backend IR receives only proven
alignment, range, aliasing, and reachability facts. This prevents
backend-specific conveniences from becoming the de facto language semantics.

### Layer contract rules

Each boundary follows these rules:

1. IDs and owned data cross a layer; Rust references into another layer's
   private storage do not.
2. Recoverable frontend stages return a best-effort value plus structured
   diagnostics, allowing language tooling to continue after errors.
3. A `VerifiedModule` can be constructed only by `wrela-wir-passes`; LLVM
   codegen accepts that wrapper instead of arbitrary WIR.
4. Serialized WIR and backend messages carry explicit format/protocol versions
   and reject unknown versions rather than guessing compatibility.
5. Inkwell and LLVM types never appear in a public signature outside
   `wrela-codegen-llvm`.
6. Raw LLD declarations and unsafe FFI remain in `wrela-lld-sys`; target flags
   and safe linker policy remain in `wrela-link-efi`.
7. The driver is the frontend composition root and the private backend is the
   backend composition root. Neither is a second home for phase logic.

Every layer gets deterministic text or binary dumps, small fixture builders,
and contract tests runnable with `cargo test -p <crate>`. Checked-in boundary
fixtures will let syntax, semantic, WIR, LLVM, and linking work proceed without
waiting for the preceding stage to be implemented.

## Build pipeline

```text
source graph
    → source database
    → recoverable syntax
    → desugared and resolved HIR
    → type/effect/access/region/actor/hardware analysis
    → closed-world specialization and capacity analysis
    → typed WIR
    → verify and optimize WIR
    → serialize WIR and launch private backend
    → decode and re-verify WIR
    → Inkwell/LLVM code generation
    → COFF object(s)
    → embedded LLD COFF driver
    → PE/COFF .efi + machine-readable image report
```

The frontend serializes versioned WIR into a per-build directory and launches
the backend by its exact path under `libexec/wrela`. The first exchange checks
the protocol and compiler build identity. Requests and responses use a framed,
length-delimited format; stdout is not the protocol, so diagnostics and crash
reports cannot corrupt it. Backend inputs are content-addressed to support
future incremental reuse while preserving the full-image semantic boundary.

The process boundary is an implementation detail. The toolchain still behaves
as one product and `wrela build` owns diagnostics, cleanup, and the final report.

## LLVM and Inkwell

The initial backend uses Rust with Inkwell over one pinned LLVM 22.1 release.
Only `wrela-codegen-llvm` depends on Inkwell. Its dependency is exact, disables
Inkwell's default all-target feature, and enables only
`llvm22-1-force-static` plus `target-x86`. The feature is off for ordinary
workspace development and enabled only while building the bundled backend
against the private LLVM prefix. An unconstrained system LLVM feature is not
permitted in distribution builds.

LLVM and LLD come from the same pinned `llvm-project` source release. Maintainer
builds enable the `lld` project and only the LLVM targets wrela can emit. The
revision 0.1 reference target needs X86; AArch64 is added when its UEFI target is
implemented. Clang, LLDB, MLIR, Polly, examples, tests, and developer tools are
not release components.

We start with static LLVM linkage for every host. This gives one uniform model,
avoids finding a shared LLVM at runtime, and follows LLVM's distribution advice
for performance. It makes `wrela-backend` large, but the public CLI remains
small and LLVM is mapped only during code generation. A private shared `libLLVM`
may later be evaluated for POSIX archive size, but it is not the initial design:
LLVM's monolithic dylib is not supported on Windows and has a documented
performance cost.

Inkwell does not expose LLD's driver as a stable Rust API. A very small C++ shim
owned by `wrela-lld-sys` will expose a narrow C ABI and call LLD's supported
library entry point (`lldMain`) with only the COFF driver linked. This is the one
intentional C++ island in the project. `wrela-link-efi` is its safe Rust policy
layer, contains no LLVM dependency, and can be tested from checked-in COFF
fixtures without code generation.

## Producing `.efi`

We do need a linker operation, but we do not need a separately installed linker
or even a separately shipped `lld` executable. LLVM emits one or more COFF
objects. The backend then invokes the statically linked LLD COFF driver in
process with the selected target package's entry point, subsystem, section,
alignment, relocation, and library policy. Its output is the final UEFI PE/COFF
application.

Keeping the link step is valuable even for a sealed image: it resolves symbols,
lays out sections, applies relocations, performs compatible dead stripping and
identical-code folding, and writes a standards-conforming PE/COFF image. Writing
our own PE/COFF linker would add a large correctness and reproducibility burden
without improving the language.

The target package, not source code or ambient host configuration, owns all LLD
flags. Distribution tests inspect the resulting PE/COFF headers and boot it in
UEFI/QEMU. We should also keep the pre-link object and linker response file when
requested by a developer diagnostics flag.

## Building and packaging the private backend

LLVM is not downloaded from a Cargo build script. `cargo xtask llvm` will:

1. read `toolchain/llvm.lock.toml`;
2. download the exact source archive into a content-addressed cache;
3. verify its cryptographic hash and, in release CI, its upstream attestation;
4. configure a release LLVM + LLD build with CMake and Ninja;
5. install the private headers and static libraries into a host-specific prefix;
6. build `wrela-backend` against only that prefix; and
7. record the effective CMake configuration and source identities.

Developers therefore need a C++ build toolchain, CMake, and Ninja only when
building the backend from source. Ordinary frontend development and workspace
tests do not. End users need none of them.

`cargo xtask dist` will construct a clean staging tree, copy the public and
private binaries, standard library, target packages, generated manifest, and
all third-party license notices, then test from that tree with `PATH` cleared of
LLVM tools. It rejects dynamic references outside the operating system's base
runtime and checks that an absent system LLVM/LLD cannot change output.

## Release hosts and targets

Host and emitted target are separate concepts. A host archive contains native
toolchain executables; its target packages describe machines the compiler can
emit. The first target is `x86_64-uefi`. The release matrix can grow across
macOS arm64/x86_64, Linux x86_64/aarch64, and Windows x86_64 without changing
source semantics.

Reproducible releases pin Rust, Cargo dependencies, LLVM/LLD, Inkwell, target
packages, and standard-library inputs. Unsigned output and the image report must
be byte-identical for the same declared inputs. Signing is an explicit final
packaging phase because signatures may intentionally carry external identity or
timestamp policy.
