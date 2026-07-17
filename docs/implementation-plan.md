# Revision 0.1 implementation plan

This is the integration owner's living, dependency-aware plan. It records
implementation state, not design intent. A milestone is complete only when its
real producer output is accepted by its immediate real consumer and its focused
gate passes. The normative language and architecture documents remain the
authority.

## Current implementation state (2026-07-16)

The repository is not yet a conforming revision-0.1 release, but its supported
minimum vertical is executable rather than contract-only:

- `cargo xgate` now provides reviewed, offline fast gates, closure-drift and
  fixture checks, explicit full routes, and timing budgets for every named
  slice and exact workspace crate.
- The real one-shot `wrela-engine` now also has an enrolled static AArch64
  Linux-musl payload. Its producer authenticates the Rust 1.95.0 Linux target,
  Cargo/vendor/source closure, Darwin bootstrap tools, and bounded archive
  extraction; builds in two path-distinct cleared-environment lanes; requires
  identical 2,565,760-byte ELF output
  `b0859cdfd317debbcae47a06da2fdb44b3439bb7854950d5b4366a444bfe8252`;
  independently rejects dynamic linkage, build IDs, and path leaks; then
  publishes an exact private content-addressed bundle and canonical receipt.
  Ordinary reuse is a separate fast artifact-consumer path: it authenticates
  the output lock, exact private directory/file policy, bundle bytes, receipt
  cross-bindings, and ELF contract without rescanning the producer's Rust,
  vendor, target, Xcode, or LLVM closures. Full closure validation remains in
  `--plan`, enrollment, and release evidence. `execution_proven=false` remains
  explicit: Linux direct execution, the immutable appliance, persistent vsock,
  in-flight cancellation, the thin Darwin launcher, and cross-route equality
  are still open. The receipt currently binds the authenticated Darwin
  bootstrap receipt identity and is therefore not yet a path-independent
  clean-host Linux authority.
- The current `wrela-engine` source builds the `direct` adapter into the same
  ELF, with no second launcher artifact or duplicate `xtask` codec. Unsupported
  builds refuse before argv or
  filesystem observation. The adapter validates the sealed request, requires
  launcher/engine identity to equal its measured executable, self-spawns the
  exact Linux-only `direct-child` under a cleared environment, bounds
  timeout/cancellation and all stdio, reaps every child path, validates and
  flushes the response, and only then create-new publishes a strict path-free
  schema-2 candidate receipt. A new schema-1 `LinuxPayloadAuthority` derives the
  request payload identity from exact canonical manifest and frontend witnesses.
  The child binds those witnesses inside the existing single verifier scan;
  receipt publication requires its validated toolchain-verification finish and
  independently reconstructs the authority. The candidate now truthfully says
  `payload_authority_proven=true` while execution and runner authority remain
  false. This is fast development closure, not Linux execution evidence: the
  enrolled `b085…252` ELF predates this source change and must eventually be
  reproduced/re-enrolled, and no enrolled Linux payload authority or
  authenticated native runner/appliance envelope exists yet. Re-enrollment is
  deliberately deferred until those direct-route
  inputs are settled so the two-lane native producer is not rerun for an
  intermediate adapter revision.
- Canonical manifests/locks/scenarios/reports, software SHA-256, bounded
  symlink-denying workspace/toolchain providers, the revision-0.1 parser,
  package-wide HIR, bounded minimum semantics, SemanticWir v8, FlowWir v10 and
  its private wire v10, deterministic proof-preserving
  `none`/`development`/`performance`/`size` optimization, MachineWir v10,
  native COFF/EFI production, post-link inspection, and schema-v11 image
  reporting are real
  implementations rather than fixture successes.
- The first recoverable-spine substrate includes a deliberately nongeneric closed
  enum: 1–256 uniquely named variants, one shared public positional copy-scalar
  payload, exhaustive unguarded constructor-only matching, and canonical
  `{u8,payload}` lowering. The checked-in `runtime-result` workspace reaches
  canonical backend preparation; authenticated native emission and independent
  COFF remeasurement are reserved for the next tranche integration snapshot.
  The authenticated `core.result.Result[T,E]` declaration now has one bounded
  runtime specialization: `Result[S,S]` for a supported copy scalar, with
  contextual constructors, exact semantic interning, and metadata erasure into
  the unchanged 8/10/10/10 representation tuple. Unequal/nonscalar/wrong-arity,
  forged non-core, and context-free forms fail closed. Postfix `?` now consumes
  an owned rvalue of that exact specialization: `Ok` yields its scalar payload,
  while `Err` reconstructs the same error and takes the ordinary early-return
  path through SemanticWir, FlowWir, wire, and MachineWir without a version
  change. Named-place consumption is rejected until its ownership and cleanup
  contract exists. General `Result[T,E]`, conversion through `From`, `Option`,
  recoverable library APIs, authenticated native emission, and packaged-QEMU
  execution remain open.
- `std/wrela-core-0.1` is a real loadable package, and
  `std/examples/minimal-image` is a real canonical two-package workspace. Its
  checked-in source passes the real parser and HIR lowerer with exact `core`
  package resolution. The installed package now publicly exports the bounded
  function-based `core.time.Duration` surface: runtime ns/us/ms/seconds/minutes/
  hours/days/weeks constructors, `as_nanoseconds`, `add`, `subtract`, `scale`,
  `less_than`, `less_than_or_equal`, `greater_than`, `greater_than_or_equal`,
  `min`, `max`, and `clamp`, plus explicitly suffixed comptime equivalents.
  `Duration` is nominal with a private u64 field. Its exact 8-byte,
  8-aligned scalar-backed ABI retains the source type ID/name and uses explicit
  construction/projection bitcasts.
  `std/examples/stdlib-time-scalar` is a second canonical workspace whose
  manifest-declared tests import those installed functions directly, with no
  local representation or duplicate implementation. It proves exact comptime
  conversion/add/scale thresholds, zero scale, minute/hour/day/week maxima and
  max-plus-one source-aware failures, exact-zero subtraction, underflow and
  inverted-clamp rejection, total-order equality/endpoint behavior, nested
  helpers, name selection, and deterministic reruns. Arithmetic retains exact
  1,350/1,349-step and 896/895-byte boundaries; ordering adds exact
  3,019/3,018-step, 1,568/1,567-byte, and depth-3/2 boundaries; the
  subtraction/clamp case passes at 2,793 steps, 1,344 bytes, and depth 3 and
  fails at 2,792/1,343/depth 2. All three cancel at repeatable polls and retain
  stable unsupported-operation classification. A
  selected runtime test carries the reachable installed ordinary functions
  through the prior tuple's SemanticWir, FlowWir, canonical wire v9, backend revalidation, and
  MachineWir v9 with exact unsigned comparisons, four branches, eight checked
  multiplies, two checked adds, two checked subtracts, twenty-two
  construction/projection/scalar-copy bitcasts, and the exact 70-edge fully qualified call
  multiset, then emits deterministic independently validated ARM64 COFF under
  the authenticated LLVM lane. This source-to-object path is now consumed by
  the historical private one-lane integration route: the selected installed `core.time`
  pass and typed invalid-count bodies execute in booted images through the
  exact packaged QEMU and firmware, with canonical report/event evidence and
  exact cleanup under the prior tuple. Runtime copy expressions, the broader
  time contract, and class construction execution remain unsupported. Selected
  generated-test runtime assertions now lower through native ABI2 objects;
  current packaged-QEMU replay and non-test/actor assertion supervision remain
  open.
- The planner preserves the exact standard-library package separately from its
  installed component digest. The public composition root implements real
  `doctor`, `check`, `build`, `test`, `lint`, and `format`; source and output
  paths are normalized once, diagnostics are stable, and artifacts/reports use
  create-new atomic publication. `doctor` retains its missing-component table,
  but a complete-looking installation is healthy only after the bounded local
  verifier authenticates its manifest, compatibility tuple, target, runtime,
  firmware, standard library, emulator, and backend and binds the running
  frontend identity; existence alone is not health evidence.
- Local builds now operationally cache the canonical FlowWir frame below the
  authorized output directory. Cold builds publish a private atomic v1 entry;
  hits recheck the full build key, extent, digest, canonical codec, FlowWir
  validity, and equality with the current producer, then feed those reopened
  bytes to the real private backend. Source/profile/target/request mutation and
  stale/future/corrupt/truncated/oversized entries miss and recompute;
  cancellation leaves no staging file. This is artifact reuse only. Real HIR
  and semantic `ChangeSet` reuse remains a separate current work item, and the
  compiler-wide integration gate is pending the parallel ChangeSet work.
- Test discovery evaluates comptime tests and seals selected generated or
  declared image groups. Generated synchronous tests carry exact descriptors,
  canonical protocol frames, calls, and terminal effects through SemanticWir
  FlowWir, MachineWir, LLVM IR, and emitted COFF. Their exact compiled-group
  identity is retained in analysis facts and image reports without backend
  reconstruction. Async tests and richer runtime bodies fail explicitly.
- The private backend independently decodes and validates FlowWir, optimizes,
  lowers, emits AArch64 COFF with the pinned native LLVM lane, invokes bundled
  LLD, reopens and inspects the EFI image, emits a canonical report, and returns
  only digest-bound private outputs. The checked-in target includes a real
  inspected runtime object and a boot-smoke path.
- The test runner stages exact artifact/firmware inputs, launches only the
  target-owned QEMU command, decodes interleaved serial/SLIP frames, executes
  bounded scenarios under one protocol/output policy, uses a private bounded
  QMP channel for explicit shutdown, synchronously reaps process groups on
  every exit path, rejects partial or cross-group lifecycle evidence, cleans
  private staging roots, and seals compile/link/boot/runtime/shutdown/protocol
  evidence in a canonical report. A QMP socket path must be normal absolute,
  NUL-free, and at most 103 encoded bytes. Compiler-owned run directories are
  atomically created mode 0700 under the canonical output parent when the
  maximum group suffix fits, otherwise under canonical `/tmp`; bounded
  collision retry, canonical/non-symlink/mode revalidation, and RAII cleanup
  preserve privacy and cancellation safety without changing normalized
  `$WORK` command evidence. The runner explicitly passes `-nic none`; networking
  is absent from the target contract, so QEMU cannot synthesize a default
  `virtio-net-pci` device or request its optional EFI ROM.
- `cargo xtask llvm` and `cargo xtask qemu` are real pinned, authenticated,
  content-addressed native bootstraps. LLVM 22.1.3 is enrolled as prefix tree
  `e5460d…de3d`; QEMU 10.1.5 contract revision 20 is enrolled as native input
  `1d126075…32d71b` and exact six-file bundle tree `b6546222…28f54`, with
  compiled-in qcow1/vvfat support for the required writable ESP. The bundle
  remains exactly six files and does not acquire an unused option ROM.
- `rust.outputs.toml` enrolls Rust/Cargo 1.95.0 for
  `aarch64-apple-darwin`, including exact Cargo/rustc binaries, canonical
  version reports, and the 2,479-file sysroot tree `fdeae0…7504`.
  `cargo.outputs.toml` binds Cargo.lock `762992…4db` and sealed 1,883-file
  vendor tree `0fc37b…389`; `cargo xtask cargo-vendor` is the authenticated
  clean-checkout producer and reuse path.
- `cargo xtask dist` implements two path-distinct clean source/build lanes with
  independent copied sysroots, Cargo homes, targets, and work roots; requires
  byte-identical frontend/backend binaries; rejects embedded authority/private
  paths; rehearses installed and extracted public and real-QEMU routes;
  archives the exact tested tree; and publishes atomically. Schema-3
  installation provenance binds Rust/Cargo/vendor/license inputs, while the
  schema-4 release receipt additionally records both build lanes and
  installed/extracted artifact, report, runtime-boot, bootstrap-QEMU, and
  `core.time` QEMU evidence.
  Host binaries are built in separate frontend and bundled-backend Cargo
  invocations so Cargo feature unification cannot pull LLVM/LLD into the public
  frontend. The two shipped executables and the standalone LLD smoke executable
  use the ordered Apple-linker policy `-reproducible`, then `-no_uuid`;
  inspection rejects `LC_UUID` and requires exactly one bounded
  `LC_CODE_SIGNATURE`. The policy is passed only to selected executable links:
  private build scripts and proc-macro dylibs retain UUIDs because Darwin dyld
  requires `LC_UUID` on loadable dylibs. Omitting UUIDs is deliberate for the
  stripped, SHA-addressed release artifacts and means UUID-based dSYM or
  crash-log association is not available. Distribution authority validation is
  now layered: planning seals the full LLVM/native authority once; internal
  checkpoints remeasure the bounded source and inspect frozen metadata for the
  selected native, enrollment, and direct-tool paths; and a publishing release
  repeats the complete authority scan exactly once immediately before atomic
  publication. Ordinary `cargo xtask llvm` cache reuse remains independently
  fail-closed over its enrolled input and complete prefix tree.
  The authenticated plan now passes in 209.67 seconds with source
  `9b925c…880c`, LLVM tree `e5460d…de3d`, and QEMU tree `b65462…28f54`;
  the 137-test xtask suite and warnings-denied all-target Clippy pass.
  `cargo xtask dist --integration-qemu --jobs 8` is a separate nonpublishing
  integration route. It builds one private lane, installs it privately, and is
  wired to execute the packaged-QEMU bootstrap, `core.time` pass and typed
  fatal, and checked-shift pass and both typed fatals before emitting one
  bounded path-free evidence line and removing the private tree. Its focused
  policy, witness, CLI, parser, and cleanup tests pass. The current real command
  passes in 685.69 seconds from source `73766a…e221`: private installation
  `5fc192…35ed` executes the packaged-QEMU bootstrap, both `core.time` outcomes,
  and all three checked-shift outcomes. The checked-shift passing selector also
  executes a second time under a sibling path-distinct root and requires exact
  EFI, report, canonical event-frame, digest, and extent equality. Every private
  root is removed before the one canonical evidence line is emitted. Attempt
  thirteen published the historical schema-3 Darwin bootstrap. The current
  compiler tuple is SemanticWir 7 / FlowWir 9 / wire 9 / MachineWir 9 /
  runtime ABI 2 / image report 11 / test plan 2; a fresh schema-4 two-lane
  release remains open.
  A strict development-ready selector,
  `--integration-qemu --integration-qemu-case runtime-timeout`, now retains the
  same one-build/private-install policy while launching only the ordinary
  `runtime-timeout` source test. Its fast producer proof pins the selected
  call's unsigned-u8 operands to 255 and 1, preserves the reachable checked add
  through optimized Flow and Machine arithmetic-fatal code 1, and its immediate
  consumer requires the exact 65-second Runtime timeout and complete two-event
  prefix. Child evidence is cross-bound to the current source, installation,
  frontend/backend, and both QEMU identities, with exact semantic extent caps
  and cleanup before the sole receipt. Focused tests, strict Clippy, and the
  2.057-second historical `testing` gate pass. The ignored packaged-QEMU
  execution has not run, so timeout execution, cancellation, and malformed
  lifecycle remain open.
  Runtime assertions now have a complete development producer/consumer path:
  parsed selected source retains exact bounded assertion descriptors through
  test plan 2, SemanticWir 7, FlowWir/wire 9, MachineWir 9, textual LLVM,
  inspected ARM64 COFF, and the allocation-free runtime ABI 2 assertion fatal.
  The checked-in runtime object is 9,894 bytes with 169 relocations and 12
  exact definitions. The current semantic, codegen, and testing fast gates
  pass; no packaged-QEMU assertion execution has run. The earlier 685.69-second
  QEMU evidence belongs to the prior compatibility tuple and is not current
  runtime-ABI-2 execution evidence. Assertion failure execution, the two typed
  checked-shift fatal replays, timeout, cancellation, and malformed lifecycle
  rejection therefore remain integration-open for one batched private route.

- The adopted atomic language-surface revision remains open as a whole. The
  current syntax contract v3 and sole `syntax/v3` fixture family subsume the
  completed alias-free `init` dimension and now make `mut`/`take` call operands
  explicit places. Syntax rejects literal, call, binary, and other rvalue
  operands with `syntax-access-place`; HIR distinguishes ordinary value
  expressions from exclusive places, and sema/SemanticWir consume the exact
  place binding while preserving overlap, double-take, and use-after-take
  behavior. HIR ChangeSet reuse contract v2 rejects stale v1 snapshots. No
  SemanticWir, FlowWir, or MachineWir schema changed, and projected exclusive
  access remains explicitly unsupported pending aggregate place ownership
  lowering. Initializer execution and class construction remain unsupported.
  Orthogonal role/trigger dimensions, unified layout, implicit rvalue moves,
  projection-result shapes, attribute constitution, and the shared bracket
  protocol remain open.

The implemented source-semantic surface remains intentionally small but is no
longer unit-only: real scalar bodies support typed locals and reassignment,
direct helper calls and returns, natural nested `if`/`else` value joins, boolean,
integer, and floating unary operations, checked and wrapping integer arithmetic,
division, remainder, shifts, bitwise operations, all comparisons, and checked
widening. Natural branch assignments now produce distinct typed join values for
`unit`, `bool`, every fixed and pointer-sized integer, `f32`, and `f64`; those
values survive SemanticWir and FlowWir as exact yields, SSA block parameters,
incoming edge arguments, nested joins, and post-join uses. A parameterized
diamond with a post-join use also reaches sealed MachineWir. The canonical
generated-test producer carries two nested joins and a copied post-join helper
argument through MachineWir and exact textual/native LLVM for the complete
16-primitive matrix. Zero-sized `unit` is erased from MachineWir SSA, CFG edges,
function/call ABI slots, returns, and passive signatures while the effectful
helper call remains; no integer sentinel or schema change is used. MachineWir v5
additionally represents every checked integer
add/subtract/multiply/divide/remainder/shift and checked numeric conversion with
explicit width, signedness, source span, failure class, and exact Flow
function/instruction provenance. Machine lowering selects the closed `Fatal`
runtime ABI for those sites instead of relying on LLVM undefined behavior or
implicit trap conventions.
Checked-left-shift semantics now have a canonical selected-source fixture with
three independent cases: modular pass, checked result loss, and invalid count.
The real source path retains `<<` versus `<<%` through parse, HIR, sema,
SemanticWir, canonical FlowWir, optimization, MachineWir, and authenticated
LLVM 22.1.3 COFF. Runtime fatal codes 5 and 6 remain distinct at the single
`Fatal` call site, and test protocol v3/report schema 2 project them into typed
host and guest outcomes. The checked-in runtime object emits the exact active
four-event terminal lifecycle without allocation. Focused model/codec/runtime/
runner/compiler gates and the authenticated native artifact gate pass. The
private one-lane integration route subsequently executed all three selectors
through the exact packaged QEMU and firmware, and replayed the passing selector
under a sibling path-distinct root with byte-identical EFI, report, and event
evidence. That 685.69-second integration proof is frozen and is not a routine
development gate; installed/extracted schema-4 release replay remains pending.
The source-level comptime test evaluator additionally supports nominal,
nongeneric flat structures containing scalar fields. Real manifest-declared
tests import production constructors and functions across modules, pass and
return aggregate values, project public scalar fields, and exercise nested
calls. Multi-field construction is completely named, one-field positional
construction is admitted, nominal identity and field privacy are preserved,
and owned-local move/explicit-copy plus branch definite-initialization rules are
checked before execution. Canonical header/field memory charges, complete
cleanup/projection polling, exact and one-under bounds, cancellation, and
source-aware failures are covered. Text and Image payload teardown is likewise
explicit: Image uses one name arena plus copyable actor ranges, so interrupted
cleanup has constant-work host destruction, and every arena transfer is
chunk-polled. All production analyzer sorts use bounded stable cancellable
merge/index ordering rather than uninterruptible host sorting. Classes/methods,
  generics, nested aggregates, non-test/actor runtime assertions, and current
  runtime-image execution remain explicit follow-on work. Selected generated
  tests already lower runtime assertions through native ABI2 objects.
The ordinary runtime-body subset now also admits nominal, nongeneric flat
structures with scalar fields. Real manifest-declared runtime tests import
production constructors and readers, preserve nominal identity and field
privacy, reject implicit aggregate copies, and lower exact Aggregate/Project
operations through SemanticWir and MakeAggregate/ExtractField through FlowWir.
Type-interning and named-field lookup work is globally bounded and
cancellation-polled; an eight-field source fixture performs 72 field-name
comparisons within an exact 155-unit complete lookup budget and rejects 154.
  Nested/generic aggregates, mutation/take, class/method construction,
  non-test/actor assertion supervision, and emitted current-tuple runtime-image
  execution are still unsupported; selected generated-test assertions reach
  native ABI2 objects.
The minimum public zero-argument `@image comptime` constructor, comptime
assertion tests, synchronous no-argument integration tests in generated
harnesses, manifest-declared scenarios, and bounded stateless actor/service
installations also exist with non-reentrant turns, fixed async frames/tasks,
mailbox capacities, and a concrete acyclic wait graph. Genuine parsed actor
source reaches FlowWir with exact actor-turn `ACTOR_CALL|SUSPEND` and static-task
`TASK_SPAWN|SUSPEND` authority. Prior-tuple SemanticWir v7 and FlowWir/wire v9 bind each
supported immediate ordinary-helper call to a dense source plan, one exact
activation `TaskFrame` region, maximum-live/cancellation facts, its cleanup and capacity
proofs, the caller's proof attachment, and strict immediate activation
suspend/resume delivery. Startup/shutdown membership, base plus activation
static/peak bytes, exact limits, and cancellation are independently sealed;
synthetic fixtures that omitted role authority or activation capacity were
  corrected. This bounded slice admits one activation per non-reentrant actor
  turn or single-slot task entry. Prior-tuple MachineWir v9 retains both source plans and
  their exact frame/capacity/cleanup authority, lowers the immediate unit helper
  to a private call/resume edge, invokes the task entry once on successful image
  startup, and emits the actor turn as deliberately dormant native code. It also
  gives every closed mailbox/root-frame/activation-frame region one exact
  aligned byte-array type, zero-initialized global, private symbol, and canonical
  writable section, preserving the source and capacity-proof joins through
  independent native measurement. The fixture reserves 96 bytes; its 16-byte
  mailbox slot is only the current scalar-message envelope. Mailbox
  admission/dispatch, recurring runtime scheduling or storage consumption,
  actor methods, cross-actor requests, multi-slot concurrency, dynamic spawning,
hardware authority, supervision, specialization, the broader time/`Duration`
contract beyond the exported function subset, and the normative standard
library remain incomplete. Every unsupported surface remains an explicit
diagnostic or unsupported error. In particular, the analyzer now performs a
bounded pre-semantic census: it preserves the six built-ins with real consumers
and rejects every other recognized built-in attribute at its exact span before
publishing graph, function, or proof success.

## Integration order

### M0 — trustworthy focused development gates

Implement `cargo xgate <slice-or-crate>` and `--full`, authoritative slice
metadata, dependency-closure drift checks, fixture inventory, and timing
records. Fast gates run format, all-target check, unit/contract tests, Clippy
with warnings denied, and architecture checks without native work.

Acceptance: all ten named fast gates pass independently and print their exact
selected and closure packages. Consumer: `cargo xgate cli` exercises the wide
composition closure without enabling LLVM.

### M1 — hermetic input to lossless syntax

Implement canonical manifest/lock codecs, a workspace provider/host, SHA-256,
and the complete Unicode/layout/literal scanner and normative parser. Add
versioned minimum, representative, maximum-policy, malformed, noncanonical,
limit, cancellation, and stale-identity fixtures.

Acceptance: `cargo xgate input` and `cargo xgate syntax`. Consumer:
`cargo xgate hir` over checked-in real parser output.

### M2 — resolved HIR and diagnostics

Implement package-wide name collection/resolution, normalized HIR lowering,
module/import visibility, generic signatures, source effects, recovery, and
world-class stable diagnostics. Compile every non-ellipsis normative syntax
example into HIR or its asserted diagnostic.

Acceptance: `cargo xgate hir`. Consumer: `cargo xgate semantic` using both
real producer output and versioned HIR fixtures.

### M3 — whole-image semantics and comptime

Implement the fixed semantic phases: typed bodies, comptime evaluation and
budgets, image construction, specialization, ownership/loan/region analysis,
actors and non-reentrancy, async frames and wait-for graph, cleanup,
supervision, hardware/DMA/ISR authority, capacity proofs, test discovery, and
analysis facts. No successful image may contain an error placeholder.

Acceptance: `cargo xgate semantic`; targeted conformance and adversarial suites.
Consumer: `cargo xgate flow` on real sealed `AnalyzedImage` output.

### M4 — proof-preserving IR pipeline

Implement SemanticWir, FlowWir SSA, the canonical frontend/backend frame,
independent backend validation, verified optimization, and AArch64 MachineWir
lowering. Add round-trip, mutation, corruption, maximum-bound, cancellation,
and producer/consumer fixtures at every boundary.

Current implemented sub-milestone: real scalar branch assignments lower through
SemanticWir and FlowWir to typed SSA block parameters, including nested joins
and a post-join use for every supported primitive scalar type. A canonical
producer proves every one of those joins through sealed MachineWir and its real
LLVM consumer. Machine lowering preserves dense identities while erasing
zero-sized unit definitions and uses; MachineWir and LLVM validation reject any
remaining void SSA value. Exact post-erasure instruction/model-edge/payload
limits, max-minus-one rejection, deterministic output, and late cancellation
are covered, including a 4,096-unit adversarial fixture that proves retained-only
construction rather than allocate-then-erase behavior. MachineWir meters every
retained target/stack-slot payload and edge. Its graph validators, Machine
lowering's independently recomputed full-output seal, and the immediate LLVM
consumer now poll inside project-sized fills, scans, sorts, text/byte copies,
deep equality, and nested CFG argument walks. MachineWir v5 carries the checked scalar surface without
reconstructing signedness or failure provenance in the backend. Producer/consumer,
substitution, exact-limit, maximum-plus-one, late-cancellation, and public-seal
tests are green across the four boundaries.

Acceptance: `cargo xgate flow` and `cargo xgate machine`. Consumer:
`cargo xgate artifact` on real MachineWir.

### M5 — smallest genuine bootable image

Implement mechanical LLVM AArch64 COFF emission, the target runtime object,
safe bundled LLD invocation, PE/COFF object and EFI inspection, canonical image
report assembly, backend process framing, and atomic publication. Integrate a
minimal supported Wrela image through the public `build` command and boot it
under the pinned target-owned emulator and firmware.

Current implemented sub-milestone: textual LLVM emits explicit failure edges
for checked overflow, zero divisors, signed `MIN / -1`, invalid shifts, and
numeric conversion range/infinity failures, preserving the exact MachineWir v5
failure code and detail into `Fatal`. The i128 division/remainder and i128/float
paths are closed software expansions and introduce no undeclared compiler-rt
symbols. The current 57-test native suite emits and inspects ARM64 COFF against the exact
LLVM 22.1.3 input `6fae96…bf2cc` and prefix tree `e5460d…de3d`, including
deterministic independently remeasured COFF for the complete primitive
nested-join matrix. It also proves an aligned, zero-initialized private
byte-storage subset: `.data` retains exact raw zero bytes, `.bss` retains exact
virtual extent with no raw payload, and both retain exact symbol offsets and
extents. The 47-test default suite includes the corresponding exact textual
LLVM assertions plus cancellation inside long target fields, CFG scans, true
merge sorts, COFF name searches, writable/zero-fill section walks, scratch
fills, and bounded artifact copies. Prior-tuple MachineWir v9 uses the initialized
writable form—not BSS/zero-fill—to preserve one distinct measured section for
each fixed actor region. This proves compiler synthesis of the bounded
reservations, not runtime admission, dispatch, scheduling, or frame consumption.
`cargo xgate wrela-codegen-llvm --full` is green through verified-prefix reuse
and the feature-enabled LLVM/bundled-LLD artifact check. This exact-crate full
route does not by itself replace the remaining public build/boot acceptance
steps below.

Acceptance: `cargo xgate artifact --full`, `cargo xgate backend --full`, and a
checked-in compile/link/inspect/boot fixture. Consumer: real public CLI build.

### M6 — runtime and standard-library semantics

Implement the compiler-owned ABI and standard contracts for results/options,
actors, completion/receipts, time, tasks/nurseries/races, bounded collections
and formatting, interrupt state, MMIO, DMA, virtqueues, construction, and
scopes. Expand generated scheduler, cancellation, recovery, replay, shutdown,
and failure paths without introducing an ambient heap.

Acceptance: machine/backend full gates plus runtime conformance images.
Consumer: real image tests through the test runner.

### M7 — production commands and conformance

Wire production `check`, `build`, `test`, `lint`, and `format` through one
composition root with stable exit categories, bounded structured output,
caching, cancellation, and atomic publication. Execute comptime tests in the
compiler and integration/image tests only through emitted AArch64 images.

Acceptance: `cargo xgate testing --full`, `cargo xgate cli --full`, all
non-illustrative normative examples, malformed-input suites, and representative
appliances.

### M8 — pinned native supply chain and distribution

Implement verified acquisition/build of LLVM, LLD, QEMU, and firmware;
runtime/stdlib/target packaging; notices and licenses; compatibility and digest
manifests; clean-room install validation; tested-tree archival; and the honest
supported host matrix.

Current sub-milestone: verified LLVM/LLD and QEMU acquisition, exact Rust/Cargo
enrollment, the authenticated Cargo-vendor producer, runtime/target packaging,
complete Rust/LLVM/QEMU notice closure, two-lane assembly, clean-room
validation, schema-3 installation provenance/schema-4 release receipt
generation, canonical archival, and
atomic publication are implemented. Exact LLVM 22.1.3, QEMU 10.1.5,
Rust/Cargo 1.95.0, the 2,479-file Rust sysroot, and the 1,883-file vendor tree
are enrolled for `aarch64-apple-darwin`. The first full assembly attempt reached
both clean release lanes and failed closed before publication because Apple ld
generated different `LC_UUID` values, which in turn changed the ad-hoc code
signature page digest. A retained two-lane reproduction isolated exactly that
metadata class: `-reproducible` alone was insufficient, while `-no_uuid`
produced byte-identical binaries that still passed strict code-signature
verification. The first repair applied both flags globally; the next full
attempt then failed closed in lane A's private-backend build when rustc could
not load `thiserror_impl`. A retained exact reproduction proved that the dylib
was signed correctly but dyld rejected it specifically because it lacked
`LC_UUID`, with Cargo surfacing the loader failure as E0463. The release builder
now keeps remapping/linker/sysroot flags global and uses separate `cargo rustc`
invocations to apply the UUID policy only to the selected shipped frontend and
backend. The direct LLD smoke executable retains the same policy; loadable
private proc macros retain UUIDs. Two clean path-distinct candidate backend
builds are byte-identical at `6f0ac9…86598` (44,376,624 bytes), UUID-free, and
strictly code-signature valid, while the retained proc macro has one UUID, one
valid signature, and loads successfully. Focused distribution tests, the
complete 90-test maintainer suite, formatting, and strict Clippy pass after the
scoping repair. A third full attempt passed both scoped-link release lanes,
Mach-O inspection, byte identity, and forbidden-path checks, then failed closed
in the repository runner gate before publication: the gate's deliberately long
private `TMPDIR` made `qmp.sock` exceed Darwin's 104-byte `sun_path` storage and
exposed the same risk for production roots beneath arbitrary output paths. The
runner now centralizes the exact portable 103-byte, NUL-free absolute-path
contract at both harness and executor boundaries. The compiler keeps an
output-local root only when worst-case `group-4294967295/qmp.sock` fits and
otherwise uses canonical `/tmp`, with atomic mode-0700 creation, bounded
collision retries, post-create revalidation/cancellation polling, and RAII
cleanup. The formerly failing QMP negotiation test passes under a 140-plus-byte
`TMPDIR`; focused compiler/runner tests, full workspace tests, formatting, and
strict workspace Clippy pass. A fourth full attempt crossed those repaired
build and repository gates, produced byte-identical frontend and backend lanes,
and then failed closed during installed public validation before publication.
The exact 120-file Rust notice tree contains four reviewed Cargo package
directories with canonical SemVer `+` build metadata, but the installed
toolchain observer's filesystem-name grammar alone omitted `+`. That observer
now admits the literal supported-host filename while the manifest's package
component grammar remains stricter. A full installed-tree fixture covers the
exact `toml_writer-1.1.2+spec-1.1.0` notice path; the Cargo/vendor enrollment,
license tree identity, provenance schema, and receipt schema are unchanged.
The exact `wrela-toolchain` gate, formatting, and strict Clippy pass. A fifth
full attempt measured release source identity `5616f862…9026` (220 files,
8,509,826 bytes; unchanged WRELDIM policy `46f751…`), reproduced frontend
`2e6ac0…e0fee` (3,317,664 bytes) and backend `4ee4ef…e59d0` (44,376,624 bytes)
across both lanes, passed the repository gates and installed public `check`,
and then failed closed in public build A before publication. Pinned LLD merges
input BSS last into output `.data`; the checked-in runtime therefore produced
a valid section with virtual size 65,664, raw size/pointer zero, and exact
initialized-data permissions, while the independent inspector still required
every initialized section's raw size to equal its aligned virtual size. The
inspector now confines the relaxation to exact `.data`: its raw extent must be
file-aligned and no larger than the aligned virtual extent, with zero raw bytes
requiring a zero pointer and nonzero bytes requiring the exact file cursor and
in-file range. All other section, permission, aggregate, directory, and padding
rules remain closed. Relocation-provenance reinspection bounds compact COFF
zero-fill by the declared image resource, and the same policy now caps PE
`SizeOfImage` so multiple inputs cannot exceed a custom loaded-image limit.
The public artifact sealer independently repeats the same section-aligned
loaded-image ceiling for injected inspectors, and COFF limit exhaustion remains
a structured resource error through relocation-provenance mapping.
Twenty ordinary and 23 bundled-LLD tests, including exact checked-runtime
zero-only and initialized-prefix/BSS-tail native links, pass with strict Clippy;
exact/max-minus-one virtual-image and BSS bounds are covered. A sixth full
attempt sealed source `6fb2b729…d6f4e` (220 files / 8,533,541 bytes), crossed
both release lanes and the repository gates, and completed both installed
PATH-cleared public builds. Their final tree-identity comparison failed closed
before publication because `base_relocation_provenance_sha256` included the raw
LLD contribution-map digest, whose otherwise canonical input keys contain
absolute private object paths. An independent native reproduction proved the
generated COFF, EFI, and ordinary map byte-identical across distinct roots;
only `.lldmap` path spellings and therefore that report field differed. The v2
provenance seal still fully parses, reopens, and authenticates the path-bearing
map, but digests its resolved path-independent graph: artifact identity, sealed
object and section ordinals/content/layout, output-section ordinals and RVAs,
and exact `ADDR64` tuples. Synthetic and real bundled-LLD short/long-root tests
now require complete `ImageMeasurements`, EFI, and ordinary-map equality while
all missing, duplicate, substituted, relocation, limit, and cancellation cases
remain closed. A seventh full attempt sealed source `a6fc660d…a4830ef` (220
files), crossed both release lanes, repository gates, installation assembly,
and installed PATH-cleared public gates, then failed closed before QEMU because
pinned LLD created the runtime-smoke `BOOTAA64.EFI` with Unix mode `0755`.
Distribution measurement correctly rejected that host-executable file. LLVM's
COFF output buffer deliberately requests executable host mode, so the shared
LLD C++ boundary now requires one direct `/out:` before running, reopens the
successful output with no link following, requires a one-link regular file,
sets exact private non-executable mode `0600`, and revalidates descriptor and
path identity. This reaches both normal Rust links and the distributor's direct
smoke driver without weakening the frozen distribution policy. A native
regression checks mode and link count after repeated links; the complete 23-test
bundled-LLD suite, strict Clippy, and exact five-crate gate pass. An eighth full
attempt sealed source `4065e971…539fd6` (220 files), crossed the repaired lanes,
repository gates, installation assembly, installed PATH-cleared public gates,
and runtime-image mode validation, then reached the first actual QEMU launch.
The enrolled contract-19 emulator rejected the required `fat:rw:` ESP with
`Unknown protocol 'fat'`: default features and modules were disabled without
explicitly compiling in vvfat. The attempt again removed all staging and
published no installation, receipt, or archive. QEMU build-contract revision 20
now explicitly compiles in both `qcow1` and `vvfat`, because writable vvfat uses
QEMU's qcow1 overlay internally, while retaining the AArch64-only, module-free,
offline/static-dependency closure. A fresh authenticated enrollment binds native
input `1d126075…32d71b`, bundle tree `b6546222…28f54` (6 files / 166,762,675
bytes), and emulator `c5df7919…a602e` (32,482,992 bytes); the firmware identities
remain unchanged. An independent QMP probe with private `HOME`/`TMPDIR` accepted
the exact `fat:rw:` drive, negotiated capabilities, quit cleanly, and left no
scratch residue. The runner, target runtime-smoke script, and distributor direct
runtime routes now each bind QEMU `TMPDIR` to their existing owned per-group,
  temporary, or smoke cleanup root. A ninth full attempt froze source
  `382726349541c06c13fcd8d8d677f0fa40e7aa524a4cb6ae3a53da77900ed4c8`
  (223 files), crossed the prior two-lane, repository, installation, installed
  public, and runtime-image gates, and then failed closed at the pinned runtime
  QEMU before publication with `failed to find romfile "efi-virtio.rom"`.
  QEMU had synthesized its implicit default `virtio-net-pci` NIC, which requests
  that optional ROM even though networking is not part of the target contract.
  Cleanup left no staging or distribution residue and published no installation,
  receipt, or archive. The distributor runtime boot, production runner, and
  standalone target runtime-smoke script now all pass exact `-nic none`; the
  authenticated six-file bundle and provenance are unchanged. An A/B probe
  against that same binary and explicit virtio-block device reproduces the ROM
  failure without the pair and reaches QMP capability negotiation plus clean
  `quit` with it. The complete xtask suite passes 92/92 in 128.75 s, runner
  suites pass 30/30 plus 13/13 nonignored smoke tests (1 installed-system test
  remains ignored), strict Clippy is green, and `cargo xgate testing` passes in
  3.140 s. A successful full runtime boot/publication retry,
  installed/extracted `doctor`/compile/inspect/boot/test rehearsal, and
  receipt-backed byte-for-byte lane evidence remain open; cross-host evidence
  is required only before claiming another host. The tenth attempt froze source
  `f04d6d8df0f54f4ad55c39649430b62fd0b956b9a574d81845be2fa2cb07c8d8`
  (223 files), used implementation `d92f867b…cf73` and orchestrator
  `4d1ba87e…bb51`, crossed the repaired direct runtime boot, and failed closed in
  the later installed real-QEMU lifecycle when public `wrela test` returned
  exact stdout `test failed\n`. Static producer-to-runtime tracing found that
  generated image entries invoked `TestEmit` and `TestFinish` without the ABI's
  mandatory `ImageEnter(image_handle, system_table)` transition, leaving
  runtime state uninitialized. Cleanup removed all private/publication state;
  no installation, receipt, or archive exists. MachineWir v6 now enrolls
  `ImageEnter` for every generated UEFI entry, executes it as an exact
  dominating prologue, reaches the prior body only on zero, and returns every
  nonzero `EFI_STATUS` unchanged. The validator independently rejects omission,
  duplication, wrong arguments/context, bypass, and status remapping. Minimum,
  scalar, and generated-test paths preserve exact model, payload, instruction,
  report, and cancellation limits; the COFF consumer additionally requires an
  instruction-aligned ARM64 `BL` branch relocation to the exact external
  symbol. Failed wrappers retain only bounded, path-free outcome classes before
  cleanup. Focused machine/artifact/testing gates and pinned LLVM 22.1.3 tests
  pass. A subsequent generated-harness audit found a second fail-open edge:
  Machine lowering recorded each returning `TestEmit` result but allowed later
  frame emission and `TestFinish` to continue without inspecting it. The
  canonical lowering now ends each emit block with an exact-zero success switch
  and returns every nonzero `EFI_STATUS` unchanged. Two generated blocks per
  emit, the switch case, and failure return are included in exact construction
  accounting and cancellation work. MachineWir requires each guard to consume
  its own call result with single-predecessor success/failure blocks and rejects
  omission, borrowing, remapping, post-call work, and bypass mutations. Exact
  textual LLVM and pinned native ARM64 evidence retain both emit guards. The
  focused suites now pass MachineWir 17/17, machine lowering 43/43, default
  codegen 44/44, pinned LLVM codegen 53/53, and compiler 90/90 with strict
  Clippy and fast machine/codegen gates. This establishes compiler-to-object
  transport failure propagation. Selected generated-test runtime assertions
  now lower through native ABI2 objects, but successful current-tuple QEMU
  test-image execution remains pending. The full publication retry
  and independent installed/archive receipt audit remain required evidence.

Attempt thirteen closes the Darwin-bootstrap distribution chain without changing
the target architecture. It authenticated source
`63f7e09c306434fbab63406bc0d215870174cee7852d2ebed20e4216eeb1befb`,
distribution implementation
`8e04e97f23214b106751e5ad4c4ccb22b479ba9da2488bfc1c90a68e1a79f84e`,
and the enrolled LLVM/QEMU trees; reproduced the 3,531,712-byte frontend and
44,488,144-byte backend across both path-distinct lanes; passed the repository,
runtime-boot, installed, extracted, public, and real-QEMU gates; and atomically
published installation tree `1a2fb78c…a4d1` plus archive
`2d0afb7b…1a97`. Installed and extracted public build, public test, EFI,
canonical report, and event-stream identities are pairwise equal in the
schema-3 receipt. This is a completed bootstrap milestone only: M8 still
requires the immutable Linux engine payload, Linux direct/appliance execution,
the thin Apple-Silicon launcher, their cross-route conformance, and retirement
of Darwin compiler/backend/QEMU authority.

Acceptance: `cargo xtask llvm`, `cargo xtask qemu --offline`,
`cargo xtask cargo-vendor`, `cargo xtask dist`, installed `wrela doctor` with
public `PATH` cleared, and unpacked-archive compile/inspect/boot/test rehearsal
with the schema-4 receipt proving both clean build lanes and
installed/extracted evidence.

### M9 — release closure

Run all focused/full gates, workspace gates, conformance, corruption,
property/fuzz, performance, object, QEMU, reproducibility, and distribution
suites. Resolve every blocker from independent correctness, soundness, safety,
diagnostics, optimizer, native supply-chain, developer-velocity, and usability
reviews. Documentation must describe only shipped behavior.

## Interface-change rule

Any boundary change updates the model and sealer, real producer, immediate
consumer, canonical/version identity, limits, cancellation, corrupt/stale
fixtures, dependency allowlist, documentation, and both focused gates in the
same integration step.
