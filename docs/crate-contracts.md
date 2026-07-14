# Compiler crate contracts

Status: normative implementation architecture for the revision 0.1 toolchain.

The language specification owns observable behavior. This document fixes the
Rust crate boundaries, exact direct-dependency graph, and the data handed from
each producer to each consumer. `cargo xtask architecture-check` enforces the
inventory and dependency edges below.

## 1. Rules shared by every crate

1. Model crates own data. Transformation crates own conversion and return only
   owned IDs/values, never references into a private arena, interner, query
   cache, LLVM context, filesystem handle, or child process.
2. A recoverable source phase returns partial output and structured diagnostics.
   A sealed success type (`AnalyzedImage`, `ValidatedSemanticWir`,
   `ValidatedFlowWir`, `OptimizedFlowWir`, or `ValidatedMachineWir`) exists only
   after every invariant required by its consumer is established. A rejected
   semantic database is prefix-closed: it may omit facts or contain explicit
   error placeholders, but every exposed ID resolves and every exposed
   collection remains canonical.
3. Cancellation is an explicit callback at transformation boundaries. A
   cancelled phase never publishes a sealed output. Incremental inputs contain
   content identities and change sets; the query engine remains private.
4. Every resource controlled by hostile or project-supplied input has a finite
   request limit. Limits cover top-level counts, aggregate collection edges,
   UTF-8/binary payload, recursive depth, diagnostics, reports, objects, maps,
   images, and test process/event output. Size/count conversion and aggregate
   addition are checked before allocation or use.
5. Input order is semantic or canonical. Host path spelling, directory order,
   hash-map iteration, locale, clock, randomness, environment variables, and
   `PATH` cannot affect an artifact unless declared and hashed.
6. Pure model crates perform no filesystem, process, network, clock, random,
   LLVM, LLD, firmware, or terminal I/O. Host capabilities are injected into
   package loading, test execution, and driver orchestration.
7. Unsafe Rust and the raw LLD C/C++ ABI are confined to `wrela-lld-sys`.
   LLVM/Inkwell values never leave `wrela-codegen-llvm`.
8. The only serialized compiler IR is `FlowWir`. Its private wire format has
   magic, independent model/wire versions, canonical encoding, finite limits,
   exact consumption, and backend revalidation. External report, manifest,
   lockfile, target, and test-event schemas are independently versioned.
9. The frontend and backend independently validate FlowWir. Machine lowering
   is a target/ABI phase; LLVM is not allowed to invent a language proof.
10. Revision 0.1 has one full-image target:
    `aarch64-qemu-virt-uefi`. There is no hosted target and no x86 target.
11. Syntax is a lossless typed AST plus a token/trivia table. There is no public
    CST, no LSP crate, and no editor protocol in the compiler dependency graph.
12. A declared Cargo dependency must be used by the current interface or
    implementation; speculative future edges are forbidden. Architecture checks
    consume Cargo metadata (not a handwritten TOML approximation), enforce the
    exact workspace, normal/dev/build graph, feature forwarding, and reviewed
    registry dependency/feature allowlist, and reject non-workspace path or Git
    dependencies.
13. Successful transformation outputs seal their validated model, canonical
    non-error diagnostics, and cross-checked report as one value. Report counts,
    pipeline identity, runtime uses, layout totals, artifact sections, and
    symbols cannot be replaced independently after validation.
14. A phase sealer receives the original request value, not a restated subset
   of its fields. Large pure operations and blocking capabilities receive the
   same cancellation callback as their owning phase. A caller cannot seal a
   self-consistent result for different input, limits, target, or policy.
15. Candidate collections are validated with adjacent-range checks, ordered
   maps, or ordered sets. Maximum-bound validation and producer/consumer joins
   must remain O(n) or O(n log n); quadratic duplicate, overlap, provenance,
   section, symbol, package, or test-artifact scans are forbidden.

## 2. Exact direct-dependency graph

`A -> B` means crate `A` may have a normal dependency on workspace crate `B`.
`A -[dev]-> B` means the edge is test-only. Third-party dependencies are
omitted.

<!-- architecture-check: dependency graph begin -->
```text
wrela-backend -> wrela-backend-protocol, wrela-build-model, wrela-codegen-llvm, wrela-flow-opt, wrela-flow-wir, wrela-flow-wir-codec, wrela-image-report, wrela-link-efi, wrela-machine-lower, wrela-target
wrela-backend-protocol -> wrela-build-model
wrela-build-model -> no workspace dependencies
wrela-cli -> wrela-build-model, wrela-compiler, wrela-driver
wrela-codegen-llvm -> wrela-build-model, wrela-machine-wir, wrela-target
wrela-compiler -> wrela-backend, wrela-build-model, wrela-driver, wrela-flow-lower, wrela-flow-wir-codec, wrela-format, wrela-hir-lower, wrela-image-report, wrela-lint, wrela-package, wrela-package-loader, wrela-sema, wrela-semantic-lower, wrela-syntax, wrela-target, wrela-test-model, wrela-test-runner, wrela-toolchain
wrela-diagnostics -> wrela-source
wrela-driver -> wrela-build-model, wrela-diagnostics, wrela-format, wrela-image-report, wrela-lint, wrela-test-model
wrela-flow-lower -> wrela-diagnostics, wrela-flow-wir, wrela-semantic-wir
wrela-flow-opt -> wrela-build-model, wrela-flow-wir
wrela-flow-wir -> wrela-build-model, wrela-source
wrela-flow-wir-codec -> wrela-build-model, wrela-flow-wir
wrela-format -> wrela-source, wrela-syntax
wrela-hir -> wrela-package, wrela-source
wrela-hir -[dev]-> wrela-build-model
wrela-hir-lower -> wrela-build-model, wrela-diagnostics, wrela-hir, wrela-package, wrela-source, wrela-syntax
wrela-image-report -> wrela-build-model
wrela-link-efi -> wrela-build-model, wrela-lld-sys, wrela-target
wrela-lld-sys -> no workspace dependencies
wrela-lint -> wrela-diagnostics, wrela-hir, wrela-sema, wrela-syntax
wrela-machine-lower -> wrela-build-model, wrela-flow-opt, wrela-flow-wir, wrela-machine-wir, wrela-runtime-abi, wrela-target
wrela-machine-wir -> wrela-build-model, wrela-runtime-abi, wrela-source, wrela-target
wrela-package -> wrela-build-model, wrela-source
wrela-package-loader -> wrela-build-model, wrela-package, wrela-source
wrela-runtime-abi -> no workspace dependencies
wrela-sema -> wrela-build-model, wrela-diagnostics, wrela-hir, wrela-source, wrela-target, wrela-test-model
wrela-semantic-lower -> wrela-sema, wrela-semantic-wir
wrela-semantic-wir -> wrela-build-model, wrela-source
wrela-source -> wrela-build-model
wrela-syntax -> wrela-build-model, wrela-diagnostics, wrela-source
wrela-target -> wrela-build-model, wrela-runtime-abi
wrela-test-model -> wrela-build-model, wrela-source
wrela-test-protocol -> wrela-test-model
wrela-test-runner -> wrela-build-model, wrela-target, wrela-test-model, wrela-toolchain
wrela-toolchain -> wrela-build-model
xtask -> no workspace dependencies
```
<!-- architecture-check: dependency graph end -->

Workspace build dependencies are forbidden. Native acquisition and
distribution assembly belong to `xtask`, never a Cargo build script.

## 3. End-to-end producer/consumer chain

```text
wrela.toml + wrela.lock + injected package provider
    -> LoadedWorkspace { PackageGraph, SourceDatabase, manifests, graph digest }
    -> ParsedFile[] { lossless typed AST + ordered token/trivia }
    -> LoweredProgram { resolved HIR + source resolution index }
    -> AnalysisOutput { partial facts, diagnostics, optional AnalyzedImage }
    -> ValidatedSemanticWir
    -> ValidatedFlowWir
    -> canonical FlowWir bytes
    -> private backend decode + independent FlowWir validation
    -> OptimizedFlowWir
    -> ValidatedMachineWir (AArch64 layout + runtime requirements)
    -> AArch64 COFF image object + pinned target runtime object
    -> PE/COFF UEFI application + canonical ImageReport
```

The test vertical shares the same chain:

```text
@test comptime fn -> compiler evaluator -> TestCaseResult
@test runtime fn  -> generated @image harness -> ordinary backend pipeline
manifest image test -> declared @image root -> ordinary backend pipeline
full-image artifact -> target-owned QEMU profile -> framed guest events
all results -> TestReport
```

No runtime test function is executed as a host function. Integration and image
tests boot the same AArch64 UEFI semantics used by production images.

`wrela-compiler` is the sole production composition root. Its wide fan-in is
intentional and terminal: model and transformation crates never depend back on
it. It injects phase implementations and bounded host capabilities, while
`wrela-driver` remains the small public command/event/outcome API.

## 4. Foundational and input contracts

### `wrela-build-model`

- Input: already decoded language revision, target identity, SHA-256 digests,
  and scalar profile policy.
- Output: `BuildProfile`, `BuildIdentity`, and validated
  `BuildConfiguration`; `BuildProfile::canonical_bytes` is the sole profile
  hash input.
- Consumer needs met: every artifact-affecting input has a named digest,
  including a canonical request digest over the selected image root, command
  intent, and test selection/filter;
  comptime, memory, recovery, record/replay, optimization, and diagnostic limits
  are explicit. CPU and LLVM feature policy is target-owned, never a mutable
  profile field or host inference.
- Does not hash, parse TOML, resolve profile names, discover a target, or read
  environment state.

### `wrela-source`

- Input: `SourceInput { canonical path, UTF-8 text, verified digest }` in strict
  canonical path order.
- Output: immutable `SourceDatabase`, dense `FileId`, `SourceFile`, `Span`,
  byte-exact slicing, and line/byte-column lookup.
- Consumer needs met: parsed files can prove freshness by digest; diagnostics
  and formatting can recover exact bytes; portable path collisions and invalid
  ranges are rejected.
- Does not walk directories, compute digests, resolve modules, lex, or normalize
  source text.

### `wrela-package`

- Input: already decoded scalar manifest/lockfile data and graph-builder calls.
- Output: validated `PackageManifest`, `Lockfile`, package/source locators,
  profiles, full-image declarations, image-test declarations, and immutable
  `PackageGraph` with canonical dense IDs.
- Consumer needs met: an image names its module/entry, AArch64 target, and build
  profile; an image test names an existing image and declared scenario plus
  nonzero boot, shutdown, event-count, and aggregate-output limits; every
  module source is explicit; locked transitive dependencies bind identity,
  locator, manifest digest, aliases, and content digest.
- Does not parse TOML, acquire packages, walk a source root, or perform network
  I/O.

### `wrela-package-loader`

- Input: root manifest and canonical lockfile bytes, root locator, finite
  `LoadLimits`, injected `PackageSourceProvider`, `ContentHasher`, and canonical
  package codec. Provider acquisition receives cancellation directly.
- Output: `LoadedWorkspace { graph, sources, declared scenario bytes/digests,
  manifests, lockfile, canonical_lockfile, source_graph_digest }`.
- The sole constructor receives the original `LoadRequest` and re-decodes its
  root manifest and lockfile. Their semantics and selected root locator must
  match the graph/manifests/lockfile being sealed; a self-consistent workspace
  for different caller input cannot be substituted. The lockfile's complete
  input bytes must equal its canonical encoding. Per-package manifest bytes and
  aggregate graph manifest bytes have distinct ceilings.
- Implementations submit one `LoadedWorkspaceCandidate`; decode, canonical
  encode, acquisition, sealing, content hashing, and graph hashing all receive
  the same cancellation callback before `LoadedWorkspace` can exist.
- Consumer needs met: syntax receives only declared, digest-checked sources and
  test discovery receives only declared, digest-checked scenario inputs;
  the build identity receives one digest covering lockfile, manifests, paths,
  and source digests; acquisition is testable without filesystem/network use.
- Failure: distinguishes decoding, provider, digest, undeclared/missing source,
  graph, limit, and cancellation failures. No partial graph is sealed.

### `wrela-diagnostics`

- Input: phase facts and source spans.
- Output: deterministic `Diagnostic` values with stable category/code,
  severity, primary/secondary labels, why-notes, help, related locations, and
  atomic structured repairs; `WithDiagnostics<T>` carries best-effort output.
- Consumer needs met: CLI, linter, tests, and future tools never parse prose or
  depend on terminal rendering.
- Does not print, colorize, read sources, or suppress errors.

### `wrela-target`

- Input: selected, digest-checked target TOML through `TargetPackageCodec` with
  explicit byte/string/MMIO/feature limits, or the built-in AArch64 reference
  constructor.
- Output: one `TargetPackage` with noninterchangeable semantic, backend, and
  runner views.
- `decode_and_verify_target_package` is the only decoded-package handoff: it
  applies input limits, validates all three views, binds both consumer digests
  to the verified file digest, and requires canonical re-encoding to reproduce
  the complete target TOML bytes. Decode, canonical encode, and verification
  receive the same cancellation callback.
- Semantic consumer gets: architecture, pointer/endian/UEFI facts, DMA/IOMMU
  policy, and canonical MMIO/interrupt bindings—never LLVM/linker switches.
- Backend consumer gets: AArch64 LLVM triple, ARM64 COFF machine, entry,
  subsystem, pinned LLVM data layout and `cortex-a57,+reserve-x18`, safe link
  policy, and target-relative runtime object/ABI.
- Interrupt consumers get GICv3/non-nesting proof facts plus a cross-checked
  backend contract pinning 2 KiB vector-table alignment, 16-byte exception
  stack alignment, no SIMD save/use, and the spurious-INTID range.
- Test consumer gets: versioned QEMU `virt` machine, CPU, TCG policy, memory,
  vCPU count, firmware code/variables components, boot medium, and PL011 framed
  transport.
- Rejects unknown/duplicate target fields, mismatched views, unsafe link policy,
  overlapping MMIO or duplicate/invalid interrupt identities, non-AArch64
  triples, runtime ABI mismatch, and unversioned or incomplete runner policy.

## 5. Frontend contracts

### `wrela-syntax`

- Input: `ParseRequest { SourceDatabase, FileId, ParseLimits }` and cancellation.
- Output: `WithDiagnostics<ParsedFile>` for exactly one file.
- `ParsedFile` contains source digest, ordered token/trivia table, typed `AstFile`,
  recovery nodes, and recovery-complete state.
- Consumer needs met: the AST covers every normative declaration, member,
  statement, expression, pattern, type, attribute, interpolation, and generic
  form. Exact token intervals preserve comments, literal spelling,
  parentheses, semicolon origin, physical newlines, and recovery insertions for
  formatting without a CST.
- Parser does not resolve names, classify ambiguous bracket arguments, discover
  modules, or consult the target.
- The parser sealer receives the original request and callback, so a producer
  cannot publish a candidate after its invocation is cancelled.

### `wrela-format`

- Input: matching `ParsedFile` and `SourceFile`, canonical `FormatOptions`,
  optional source range, and cancellation.
- Output: complete formatted text plus sorted nonoverlapping `TextEdit`s and a
  changed flag. Parse diagnostics remain owned by the parser output.
- Consumer needs met: whole-file and range formatting preserve comments and
  literal spelling while normalizing four-space layout, semicolons, line
  endings, and trailing newline. It never requires HIR or a CST.
- Failure: stale/malformed AST, out-of-file range, invalid options, or bounded
  output overflow, or cancellation.
- The formatter sealer receives the original request and callback; its
  text/edit/effective-range tuple cannot be sealed after cancellation.

### `wrela-hir`

- Input: none directly; constructed by HIR lowering or fixtures.
- Output: pure `Program` arenas for modules, declarations, bodies, statements,
  expressions, patterns, locals, generics, resolved definitions, captures, and
  source provenance.
- Every HIR module retains its exact `(PackageId, ModulePath)` graph identity.
  `ValidatedProgram::manifest_declaration` and
  `LoweredProgram::image_entry` are the sole manifest `(module, entry)` to
  `ResolvedDeclaration` bridge; orchestration never rebuilds a private name
  table or guesses by source spelling.
- Consumer needs met: all imports are resolved; generic arguments are
  classified as type/constant/region/bounded-capacity; sugar and parentheses
  are gone; no inferred type/effect/ownership fact is prematurely encoded.
- Does not depend on syntax, target, semantic analysis, or WIR.

### `wrela-hir-lower`

- Input: owned `PackageGraph`, matching digest-current `ParsedFile` set,
  `SourceDatabase`, graph digest, `ChangeSet`, limits, and cancellation.
- Output: `WithDiagnostics<LoweredProgram>` containing HIR, source-facing
  resolved-use index, per-module resolution summary, reuse markers, and source
  graph digest.
- Consumer needs met: sema receives complete normalized bodies and stable
  resolution; lint receives source-use information; missing/duplicate/stale or
  out-of-graph files are phase failures rather than semantic guesses.
- The seal applies request ceilings to every arena, aggregate model edge,
  retained literal/name byte, resolved use, diagnostic byte, and nested type or
  projection carrier before recursive model validation.
- Does not type-check, run arbitrary comptime, establish ownership/hardware
  proofs, or expose its SCC/query implementation.

### `wrela-sema`

- Input: borrowed sealed HIR, semantic target view, validated build
  configuration, change set/limits/cancellation, and exactly one
  `AnalysisMode`: production image, test discovery, or compilation of one
  dense group from a `ValidatedTestPlan`. A declared root carries the exact
  manifest-resolved `DeclarationId`; a generated harness carries an
  `ImageGroupId` and never forges a HIR declaration/body.
- Partial output: complete type table, monomorphized function instances,
  dense image-wide typed values owned by exact function instances,
  function-qualified expression and statement facts, ownership/loan
  transitions, resolved scope
  protocols and activation/cleanup dependencies, proof records, baked
  artifacts, optional image graph/test plan, comptime test results, and
  deterministic diagnostics. Every function has a fixed-size content key,
  source/generated origin, semantic role, source provenance, and stack/frame/
  work bounds. Actor turns, task entries, ISRs, cleanup, image entry, and tests
  are exact graph relations, not conventions inferred by a lowerer.
- Sealed output: `AnalyzedImage`, created only when no error exists and a closed
  image graph has been proved.
- The seal checks every type/constant/value/function/expression/statement/scope/
  image/proof/test reference, effect bit, canonical set, placement owner, and
  bound. Proof IDs are a deterministic topological order, so cycles and forward
  dependencies cannot cross into SemanticWir lowering.
- The seal also binds each device exactly once to the selected target's MMIO
  table, requires an interrupt-capable target binding for every ISR, and binds
  successful discovery/test execution to the exact sealed plan/group/function
  key set. Test counts, scenarios, steps, plan/report bytes, per-group events,
  process output, and execution time are independently bounded.
- Partial and successful outcomes share one owned fact database: the private
  result sum cannot pair an unrelated partial database and sealed image or clone
  image-sized facts. Diagnostics are canonicalized before that outcome is
  sealed, so an error diagnostic and `AnalyzedImage` cannot coexist. Even an
  error result passes the prefix-closed structural validator; consumers never
  receive dangling “best effort” facts.
- Consumer needs met: SemanticWir lowering has types, constants, exact call and
  intrinsic resolutions, argument access, regions, actors/tasks/devices/pools,
  capacities, startup/shutdown, stack/frame/work bounds, hardware bindings,
  proof dependencies, artifacts, and tests. It need not rerun semantic queries.
- Owns the mutually dependent fixed point: types, const generics, interfaces,
  effects, initialization, ownership/views/regions, comptime/image evaluation,
  actors/async/cancellation, wait and cleanup graphs, capacities, scheduling,
  ISR/MMIO/DMA/wire rules, supervision, and build-contract proofs.
- Does not depend on any WIR, LLVM, linker, backend protocol, filesystem, or
  process state.

### `wrela-lint`

- Input: one explicitly selected layer—parsed AST set, HIR program, or sealed
  semantic image—plus the linter's exact registry, canonical lint
  configuration, finite limits, and cancellation.
- Output: sorted `LintFinding`s with stable names, effective levels, structured
  diagnostics/repairs, and a `denied` result.
- Consumer needs met: lints declare their required layer and cannot silently
  run on weaker information. Formatting and compilation correctness remain
  independent of advisory lint policy.
- The sealed output is request-bound: a finding cannot be validated against a
  registry other than the one selected by orchestration for that invocation.
- Every frontend/transformation sealer receives the same cancellation callback
  as its trait method and checks it before and after bounded validation.

## 6. Named IR contracts

### `wrela-semantic-wir`

- Input/output model: fully specialized, syntax-free structured whole-image IR.
- Retains: language types/linearity/effects, structured control flow, exact
  ownership/access operations, regions and complete scope cleanup plans,
  actors/reservations/receipts,
  async/tasks/cancellation/checkpoints, DMA/MMIO/interrupt/queue operations,
  image graph, source summary, startup/shutdown order, proof records, baked
  globals, and discovered tests.
- Function origin/role, actor turn functions, task entry functions, device ISR
  functions, queue limits, region provenance/proofs, frame bounds, and the
  image static/peak memory plan are explicit and cross-checked against the
  analyzed input during sealing.
- Excludes: unresolved names, generics/interfaces, parser nodes, target layout,
  runtime ABI calls, LLVM concepts, and optimization decisions.
- `ValidatedSemanticWir` establishes model version, dense IDs, all references,
  function/value ownership, image entry, proof graph, and plan consistency.

### `wrela-semantic-lower`

- Input: sealed `AnalyzedImage`, finite lowering limits, cancellation.
- Output: `ValidatedSemanticWir` and a count/report summary.
- Its sole sealer receives the original `LowerRequest`; an implementation
  cannot validate an output against a different analysis or limit policy.
- Consumer needs met: Flow lowering never queries sema or HIR and sees every
  source-semantic ordering/failure/proof fact explicitly.
- Limits cover aggregate model edges, retained UTF-8/binary payload, constant
  nesting, structured-region nesting, and ordinary arena/operation counts;
  these are checked before recursive SemanticWir validation.
- This conversion is total for valid analyzed input; a missing semantic fact is
  an internal phase error, not a synthesized fallback.

### `wrela-flow-wir`

- Input/output model: target-layout-independent typed SSA plus whole-image plan.
- Retains: explicit blocks/block parameters, async states, cleanup and suspend
  edges, ownership/access/drop, actor admission/mailbox/reply/receipt behavior,
  task slots/park/wake, checkpoints, logical capacities, regions, DMA/MMIO,
  record/replay, generated test emit/finish, supervision/recovery facts,
  startup/shutdown order, source summary, and traceable proofs.
- Excludes: structured source syntax, target data layout/calling convention,
  runtime ABI, LLVM attributes, object sections, and linker policy.
- `ValidatedFlowWir` proves all dense IDs and definitions, type/value/block/
  function/proof/plan references, CFG edge and call arity/types, acyclic proof
  dependencies, image entry, plan integrity, and operation operands.
- Each base function records its exact SemanticWir function provenance and
  role; generated async/cleanup functions record their semantic owner. Actor
  state types, device ISR sets, source/plan summaries, and static/peak memory
  remain explicit. Flow lowering seals all immutable image-plan fields against
  SemanticWir rather than merely comparing counts.

### `wrela-flow-lower`

- Input: `ValidatedSemanticWir`, limits, cancellation.
- Output: `ValidatedFlowWir`, lowering metrics, and non-fatal diagnostics.
- Its sole sealer receives the original `LowerRequest`; the IR, report, and
  non-error diagnostics are bound to that exact SemanticWir and limit policy.
- Owns: CFG/SSA construction, async state machines, cleanup paths, logical
  scheduler operations, and translation of semantic proofs.
- The seal independently bounds all blocks/instructions plus aggregate operand,
  edge, feature/proof, and UTF-8/immediate payload retained in FlowWir.
- Does not optimize, fix ABI/layout, choose runtime intrinsics, or serialize.

### `wrela-flow-opt`

- Input: `ValidatedFlowWir`, exact `OptimizationProfile` and pipeline identity,
  cancellation.
- Output: sealed `OptimizedFlowWir`, the exact requested profile, deterministic
  pass statistics, and canonically ordered decisions with relied-on proof IDs
  and complete pipeline name/revision/implementation identity.
- Its sole sealer receives the original `OptimizationRequest`, preventing a
  result from being sealed under a substituted input, profile, or limit set.
- Consumer needs met: Machine lowering cannot accidentally consume an
  unverified intermediate pass result; all actor-as-if, check-removal, storage,
  and control-flow decisions remain explainable.
- Ordinary optimizations remain FlowWir. There is no new IR name for each pass.
- Optimization may rewrite function bodies and global initializers, but cannot
  change types, proofs, checkpoints, provenance, signatures, roles, bounds, or
  the image plan. The seal requires the actual IR-change bit, changed passes,
  and decision records to agree; optimization level `none` preserves the input
  model exactly.
- Optimizer limits also bound variable-length body/global edges and immediate/
  value-name payload, so instruction-count growth is not the sole
  denial-of-service guard.

### `wrela-flow-wir-codec`

- Input: `ValidatedFlowWir` plus `CodecLimits`, or bytes plus expected
  `BuildIdentity` and limits, together with cancellation for encoding and
  decoding the potentially image-sized frame.
- Output: canonical bytes/header or newly `ValidatedFlowWir`.
- Header binds wire version, FlowWir model version, payload size, and complete
  build identity. Decoder rejects invalid UTF-8/tags, noncanonical order,
  duplicate/non-dense IDs, overflow, trailing bytes, limit violations, and
  build mismatch before returning a sealed value.
- Frontend sealing proves the frame decodes to the exact input model and that a
  second encode is byte-identical. Backend decoding canonically re-encodes the
  validated model and requires the complete received frame and inspected header
  to match, so ignored or alternate encodings cannot cross the wire boundary.

### `wrela-runtime-abi`

- Input/output model: closed compiler-only runtime intrinsic set, exact scalar
  signatures, ABI version, and canonical `RuntimeRequirements`.
- Current surface: image enter/exit/fatal, idle, interrupt mask/restore, DMA
  cache maintenance, record/replay, and test emit/finish.
- Every intrinsic has a versioned stable COFF symbol spelling as well as an
  exact scalar signature; MachineWir validates calls against both.
- The same ABI fixes one always-present, 8-byte-aligned read-only route-table
  symbol: an 8-byte `(count, reserved-zero)` header followed by 16-byte
  `(INTID, reserved-zero, handler-address)` records. Integers are little-endian,
  handler addresses use ARM64 COFF relocations, and records are sorted by INTID.
  This lets codegen and the target runtime object implement exception dispatch
  independently without an inferred metadata or zero-length-symbol convention.
- Source cannot name these intrinsics. The target ships one digest-checked
  AArch64 runtime object implementing this ABI. Adding/changing a signature
  increments the ABI and target/toolchain compatibility.

### `wrela-machine-wir`

- Input/output model: LLVM-independent, AArch64-laid-out machine IR.
- Fixes: data layout, size/alignment/field offsets, sections/symbols/linkage,
  calling conventions, the canonical target-binding/INTID/handler route for
  every interrupt, stack slots/overlay groups, memory/atomic/device semantics,
  runtime calls, and every UB-bearing backend fact with proof ID.
- Signless machine integers never force codegen to guess: each conversion names
  truncation/extension signedness, integer/float direction, pointer conversion,
  or bitcast explicitly. Standalone fences use a closed atomic/device fence enum
  and cannot encode meaningless ordinary/volatile fences.
- Every function names its exact code section; every fixed section-offset
  symbol names both offset and extent; globals name section, offset, type size,
  and alignment. Validation rejects overlapping global placements, so codegen
  has no residual section-ownership decision.
- Every machine function retains its dense one-to-one FlowWir provenance and
  role. Interrupt records retain both the semantic device ID and target
  binding; Machine lowering cross-checks handler provenance, target route,
  image entry, source span, and proved stack bound before sealing.
- `ValidatedMachineWir` establishes all references, layouts, definitions,
  runtime requirements, the unique UEFI entry, the closed set of no-argument
  interrupt handlers, and target/build consistency. Firmware and interrupt
  entries cannot be ordinary direct or tail-call targets.
- Codegen may translate facts; it may not strengthen them.

### `wrela-machine-lower`

- Input: a borrowed `OptimizedFlowWir`, the complete validated target package, build
  configuration, explicit machine limits, cancellation. This is the deliberate
  join point between previously checked semantic binding names and backend
  interrupt/ABI facts; codegen receives only the backend view afterward.
- Output: a sealed `ValidatedMachineWir` and layout/runtime-use report whose
  build, target, type/function/section/stack counts, runtime requirement set,
  and exact runtime call-site counts are cross-checked against the output IR.
- Owns: AArch64 ABI/type layout, stack/frame objects, section placement,
  resolution of every ISR device binding to one target interrupt route,
  runtime-intrinsic selection, and conversion of Flow proofs into backend facts.
- Rejects target/build mismatch, overflow, resource excess, unsupported target,
  or any required intrinsic without a target runtime implementation.
- Machine limits cover aggregate instruction operands, stack-state lists,
  target/section/symbol/proof text, immediate bytes, and top-level counts before
  target validation walks the candidate.

## 7. Backend, artifact, and report contracts

### `wrela-codegen-llvm`

- Input: `ValidatedMachineWir`, matching backend target view, `CodegenOptions`
  with object/section/symbol/measurement ceilings, and cancellation.
- Output: a sealed ordinary AArch64 COFF artifact with inherited
  `BuildIdentity`, target triple, object format, exact emitted sections, and
  canonical section-relative symbol measurements. The seal checks those sets
  against MachineWir, including section alignment/reservation and each fixed
  symbol placement, and checks every range/non-overlap against the object bytes
  and section address space.
- The object sealer receives the original `CodegenRequest`; test doubles cannot
  return an artifact validated against a different MachineWir, target, or
  options value.
- Consumer needs met: linker receives no LLVM object; report generation can map
  symbols; output is bounded. LLVM verification failure and unsupported machine
  operation are explicit.
- LLVM performs mechanical translation and backend optimization only. It cannot
  establish a language capacity/safety proof or invent `noalias`, `inbounds`,
  non-null, alignment, or overflow facts.
- The target machine is created only from target-owned
  `aarch64-unknown-uefi`, pinned data layout, `cortex-a57`, and
  `+reserve-x18`; LLVM's reported layout must equal the package before codegen.
  MachineWir's `UefiAarch64` entry marker maps to LLVM's AAPCS C convention
  after its UEFI-specific signature/visibility checks; Windows ARM64
  conventions are forbidden.
- Each `InterruptHandler` marker maps to an ordinary AAPCS64 body reached only
  from the target runtime's exception trampoline. MachineWir contains the
  always-present, exactly sized runtime-metadata section and table symbol;
  codegen fills its ABI-v1 header/records and ARM64 relocations from the sealed
  routes. It does not synthesize or rediscover identities, storage, or symbols.
- Revision 0.1 always runs LLVM verification and emits neither language
  unwinding nor caller-selected debug policy; adding artifact-affecting debug
  modes requires an explicitly hashed profile/request contract.

### `wrela-lld-sys`

- Input: raw LLD COFF argument vector from `wrela-link-efi` only.
- Output: success or captured native LLD failure.
- Owns all workspace unsafe/native FFI. It knows no Wrela model or policy.

### `wrela-link-efi`

- Input: matching `BuildIdentity`, deterministic generated COFF object list,
  exactly one target runtime object with target digest/runtime ABI, backend
  target view, distinct output/map paths, object/image/map/count/measurement
  limits, cancellation, and bounded
  `CoffObjectInspector`/`LinkedImageInspector` capabilities.
- Output: `EfiArtifact` containing paths, build identity, artifact SHA-256,
  verified ARM64/EFI/entry/relocation facts, and canonical final section/symbol
  measurements.
- Consumer needs met: no caller injects linker switches; dynamic/default-library
  linking is impossible; `/machine:arm64`, EFI subsystem/entry, reproducible
  mode, relocations, runtime, and outputs come from validated contracts. Link
  inputs have dense ordinals, unique normalized absolute paths, and runtime-last
  ordering. Every object is re-opened immediately before LLD and its bounded
  byte count, SHA-256, and ARM64 COFF machine are checked against the sealed
  generated artifact or verified target component. Link success is impossible
  until the emitted PE32+ image and map are re-opened and a shared artifact seal
  validates all section and symbol ranges. A tiny image cannot smuggle an
  unbounded map-derived section/symbol table.
- The artifact sealer receives the original `LinkRequest`; cancellation is
  checked before object inspection, native LLD invocation, and post-link
  inspection, and a cancelled invocation cannot publish an `EfiArtifact`.
- Object/image inspectors receive cancellation directly. Section overlap and
  symbol ownership use sorted ranges and an indexed section table, never
  pairwise scans.

### `wrela-image-report`

- Input: build identity; semantic/Flow proof and image facts; optimization
  decisions; MachineWir/runtime facts; final section/symbol/link measurements;
  target-variable exclusions; and artifact digest.
- Output: sealed schema-versioned `ImageReport`, canonical fixed-order JSON,
  and stable readable summary. It retains dense proof IDs, structured
  proof-linked optimization decisions, and the pipeline's exact
  name/revision/implementation digest. Construction canonicalizes unordered
  fact sets and rejects invalid versions, incomplete facts, out-of-section
  symbols, duplicate names, and noncanonical external lists.
- `ValidatedAnalysisFacts` retains the exact build, image name, and fact-limit
  policy used to seal it. Analysis and backend fact collections have separate
  item, nested-proof-edge, and UTF-8 payload ceilings; `ImageReport` retains
  both policies and rejects cross-build or cross-image substitution. Fact
  assembly, construction, validation, and canonical JSON encoding receive
  cancellation.
- Consumer needs met: the report exposes logical image topology and physical
  lowering, bounds, proof why-chains, actor paths, stack/frame/work/checkpoints,
  hardware/recovery, startup/shutdown, all IR/ABI versions, runtime intrinsics,
  target-variable exclusions, sections/symbols, and exact artifact identity.
- Does not compute proofs, inspect LLVM, hash/read artifacts, or fabricate
  measurements.

### `wrela-backend-protocol`

- Input/output: one bounded framed `BackendRequest` or `BackendResponse` with
  request ID, complete build configuration, controlled relative input/output
  paths, exact canonical FlowWir digest, artifact/report digests, and typed
  failure category.
- Guarantees: magic/version/length, exact consumption, finite text/profile data,
  profile validation, no parent/absolute paths, and no ambient filesystem
  authority.
- This is exact-version internal IPC, not an external SDK compatibility promise.

### `wrela-backend`

- Input: backend request bytes/files, validated target package/build, concrete
  Flow codec/optimizer/Machine lowerer/codegen/link/report services, cancellation.
- Output: response plus atomically published EFI/report artifacts on success.
- Publication success is sealed against the request's controlled paths, the
  inspector's artifact digest, the canonical report digest, and one build
  identity. The final execution result has private variants constructed from
  that seal, so its protocol response cannot disagree with the local
  artifact/report or failure.
- `BackendExecutionRequest`, sealed `BackendJobPaths`, `BackendReportRequest`,
  `BackendPublisher`, and `BackendExecutor` define the full vertical; temporary
  object/image/map paths cannot alias final paths or escape the private root.
  A mutable `BackendJobPathCandidate` crosses the host boundary once; its
  validated path capability is immutable afterward. `PreparedBackendInput`
  likewise keeps the related optimized Flow/Machine pair private.
- `BackendReportAssembler` returns only `VerifiedBackendReport`, sealed against
  the exact optimized FlowWir, wire digest, pipeline identity, MachineWir,
  target, object, linked artifact, fact limits, and canonical report byte
  ceiling. Runtime symbols and every linked section/symbol measurement must
  match; publication repeats the FlowWir/artifact cross-check.
- One `BackendLimits` value keeps codec, optimizer, machine, codegen, link,
  image/map, and canonical report ceilings consistent. Report JSON is bounded
  before publication and rechecked when publication is sealed.
- Report section/symbol joins use ordered indexes, and report construction,
  materialization, publication, and success sealing share job cancellation.
- Pipeline: re-hash FlowWir -> decode -> independent Flow validation ->
  optimize -> Machine lower -> Machine validation -> LLVM/COFF -> runtime link
  -> measure/report -> hash -> publish.
- No LLVM/LLD work starts before build/target/WIR agreement. A failure cannot
  leave a success response or partially published artifact.

## 8. Testing, toolchain, and command contracts

### `wrela-test-model`

- Input/output model: dense test, scenario, and image-group identities,
  compiler unit-test plan, fixed-size content-addressed monomorphized function
  key for every generated
  harness test, distinct declared-scenario invocation, framed events, assertion
  details, outcomes, execution evidence, and aggregate `TestReport`.
- `TestPlan` and `TestReport` are candidates; only `ValidatedTestPlan` and
  `ValidatedTestReport` cross compilation/runner/driver boundaries. Plans have
  explicit ceilings for tests, groups, scenarios, steps, aggregate plan/report
  bytes, and per-group events/process output/execution time. The validated plan
  retains the exact limit policy used to seal it, so report validation cannot
  silently fall back to looser defaults. Compiled artifacts and results bind
  to `ImageGroupId`, never a loose display-name string.
- Image scenarios have a stable schema/codec boundary and typed bounded
  serial-send, serial-expect, test-event, exit, and shutdown steps; their digest
  is carried into execution evidence. Scenarios have checked aggregate wait
  budgets, one terminal observation, no action after exit, and test-event IDs
  scoped to the consuming image group.
- Scenario decoding is bound to the request's dense ID, declared name/path,
  verified digest, total bytes, step count, and per-step payload limit; canonical
  re-encoding must reproduce the complete declared scenario bytes.
- Scenario and report codecs receive cancellation during bounded decode,
  encode, and canonical round trips.
- `TestReport::validate_against` proves that results describe exactly the plan;
  an infrastructure-failed image may contain only a completed result prefix.
  Each image group owns one global protocol stream with dense sequence numbers,
  one run start, legal per-test lifecycles, and exactly one terminal event on
  non-infrastructure completion; case-local duplicate event copies are absent.
  Guest terminal outcomes are a closed runtime-only type and cannot impersonate
  host discovery, compile, link, boot, shutdown, or process-crash failures.
- Report sealing independently bounds each encoded event, retained group
  payload plus stderr, and the complete report payload against the sealed plan.
- `TestReportCodec` owns the canonical external report schema. Publication
  accepts only `EncodedTestReport`, produced after bounded encode, complete
  decode/equality, and byte-for-byte canonical re-encode checks. The encoding
  owns its validated report until a sealed publication binds both to one
  path/digest/byte-count receipt, preventing report/bytes substitution.
- Distinguishes test failure from discovery/compile/link/boot/protocol/shutdown
  infrastructure failure. Evidence binds image, complete target package,
  emulator, command, event-stream digests, exit status, and bounded stderr.
  Evidence is phase-accurate: pre-link failures require absent image/emulator/
  command/event evidence, while any launched run requires those identities.

### `wrela-test-protocol`

- Input: one `TestEvent` or one PL011 frame plus protocol limits.
- Output: private `EncodedEvent` sealed from a candidate only after independent
  header inspection and canonical decode/re-encode, or an inbound event returned
  only by `decode_and_verify_event` after the same complete-frame round trip.
- Guarantees: independent frame/event versions, magic, sequence agreement,
  bounded lengths, canonical tags/UTF-8, CRC32C, exact consumption, and
  corruption rejection. This schema is stable external test tooling data.
- Encode, header inspection, decode, and canonical round trips receive the
  runner's cancellation callback.

### `wrela-toolchain`

- Input: explicit installation root or executable-relative discovery; bounded
  canonical manifest bytes through `ToolchainManifestCodec`, the single
  `ToolchainCompatibility::current()` tuple, and driver-observed byte/digest
  evidence for every declared component, target, and target-relative file.
- Output: `VerifiedToolchain`, the only capability accepted by the test runner,
  plus controlled content-addressed paths for frontend, private backend,
  standard library, AArch64 emulator, target package, and doctor checks.
- Manifest decoding is request-bound: after limit and compatibility validation,
  canonical re-encoding must reproduce the complete supplied manifest bytes
  before component observation can create `VerifiedToolchain`; decode and
  re-encode receive cancellation.
- Every shipped component and target-relative runtime/firmware file carries a
  nonzero byte count and digest. Consumers resolve only manifest-declared
  target files, never arbitrary children of a trusted directory. `VerifiedPath`
  fields are private and only `VerifiedToolchain` can derive one.
- Compatibility independently fixes language, build-profile encoding, target
  package, backend protocol, all three IR models, Flow wire, runtime ABI, image
  report, test plan/report/scenario, test event, and test frame versions.
- Does not search `PATH`. The target digest covers firmware and runtime; the
  emulator is a separately digest-checked shipped component.

### `wrela-test-runner`

- Input: `ValidatedTestPlan`, compiler-evaluated results, one EFI artifact per
  full-image group, selected target and `VerifiedToolchain`, private work
  directory, injected
  bounded `ProcessExecutor`, target harness, and cancellation.
- Output: `ValidatedTestReport` containing compiler and QEMU cases plus
  reproducibility evidence.
- Consumer needs met: orchestration is independently fakeable; target command
  generation and event decoding are separately testable; ambient environment is
  not inherited; the executable, working directory, canonical environment,
  checked aggregate timeout, output ceiling, and event ceiling are revalidated
  before/after execution. Each `ImageArtifact` is sealed against an exact plan
  group, build identity, path, digest, measured byte count, and image limit.
  The process executor reverifies the emulator and hashes the EFI image plus
  both firmware inputs while staging private per-run copies; only the variable
  store copy is writable. Shipped firmware templates are never launched in
  place. Artifact build identity and compiler, standard
  library, target, and emulator digests must match the verified installation.
  Canonical command and event-stream digests and the summarizer's retained
  event stream are independently compared. Missing emulator or firmware is an
  infrastructure error, never a pass result.
- `RunnerLimits` independently bounds argument count, environment count,
  aggregate command bytes, and aggregate path bytes. Executor duration cannot
  exceed the sealed timeout. A private `VerifiedProcessFile` can originate only
  from a verified toolchain path or sealed image artifact; arbitrary paths
  cannot be smuggled into process staging.
- The command harness receives a least-authority `ImageExecutionComponents`
  view containing only the verified emulator, selected target package, and the
  two exact firmware files; it cannot discover compiler or unrelated toolchain
  paths. Command construction, event decoding, summarization, and reproducible
  digest construction all receive the same cancellation callback.
- `ImageCommandRequest` and `ImageSummaryRequest` keep harness invocations
  cohesive and extensible. `ImageArtifactRequest` binds artifact sealing to the
  exact plan, group, build, path, digest, measured byte count, image ceiling,
  and cancellation state. Artifact digests must be nonzero; duplicate group or
  path sets are indexed and rejected before execution.

### `wrela-driver`

- Input: typed `Command`, explicit workspace/image/AArch64 target/profile,
  output directory, diagnostic/test/format/lint selection, event sink, and
  cancellation.
- Output: typed doctor/check/build/test/format/lint outcome. Published artifacts
  include paths and digests; rejection returns the complete deterministic
  diagnostic set.
- Owns the stable public command, event, error, and sealed outcome vocabulary.
  Doctor checks and all successful outcomes have private fields and validating
  constructors; build/test publication paths, byte counts, digests, report
  measurements, build identity, diagnostics, and analysis cannot disagree. It
  has no dependency on the filesystem-aware toolchain implementation or private
  phase crates and does not redefine their data.
- `BuildOutcome` hashes the cancellable canonical `ImageReport` encoding;
  `TestOutcome` consumes the sealed `EncodedTestReport`. Receipt byte counts and
  digests must match those exact encodings. Successful format outcomes have
  normalized absolute paths and bounded, canonical file/diagnostic sets.

### `wrela-compiler`

- Input: `CompilerServices` containing every independently replaceable phase
  trait (including the analysis-fact assembler, image-scenario codec, and
  test-report codec), an opaque `ArtifactCache`, a bounded
  `CompilerHost`, exact `PipelineLimits`, and public driver commands.
- Output: a concrete `CompilerDriver` composition. The host is the only source
  of bounded verified file bytes, declared package acquisition, private build
  directories, target packages, and verified toolchains.
- Owns build planning, phase/cancellation/event orchestration, cache lookup,
  backend lifetime, test-group fan-out, and atomic publication. `VerifiedInput`
  can only be sealed against its exact `InputReadRequest` after normalized-path,
  byte-count, SHA-256, and cancellation checks. Every blocking host operation
  receives cancellation directly.
- Persistent cache entries are keyed by the complete `BuildIdentity`, artifact
  kind, schema version, and group/root subject digest. Loaded bytes are bounded,
  rehashed, and key-checked before a phase codec may decode them; corruption is
  a miss/recompute, never a semantic result. Frontend arenas/query caches remain
  private and use the existing source/HIR/semantic change sets rather than a
  second serialized IR.
  Keys expose their schema version and are hashable, so independent filesystem,
  database, and in-memory cache implementations need no private-field access.
- `BuildPlanner` receives the sealed `LoadedWorkspace`, exact root-manifest
  `ImageDeclaration`, concrete `BuildProfile`, command/test intent, target, and
  verified toolchain evidence. It never reopens a manifest or resolves a
  display name behind another phase's back. Its private-output `PlannedBuild`
  can only be constructed by hashing the canonical profile and canonical
  image/intent/test-selection request, then cross-checking every build-identity
  digest against the workspace, target, and verified installation.
- `PipelineLimits` covers cache/package/parse/HIR/semantic/analysis-fact/format/
  lint/test-plan/test-runner/SemanticWir/FlowWir/wire/backend/target/toolchain
  ceilings. It rejects frontend/backend codec disagreement, frontend/backend
  report-policy disagreement, and semantic/test-plan policy drift.
  The cache entry ceiling must accommodate the canonical Flow frame and final
  image ceilings; a cache policy cannot truncate a product accepted elsewhere.
  Formatting has separate file-count, aggregate-input, per-file-output, and
  aggregate-output ceilings; diagnostic selection rejects a zero result cap.
- Formatter replacements and encoded test reports pass through one sealed
  atomic-file request. New outputs use create-new semantics; source formatting
  uses compare-and-replace against the exact input digest. Host receipts are
  cross-checked for path, digest, and byte count before a driver outcome exists.
  Test publication retains the original `EncodedTestReport` in the private file
  payload and returns it intact after receipt sealing; the driver handoff needs
  neither an image-sized byte clone nor an untyped report/encoding join.
- This is the only wide fan-in crate and no lower layer may depend on it.

### `wrela-cli`

- Input: command-line arguments for doctor, check, build, test, lint, and format.
- Output: typed driver command and stable exit category; renders already
  structured outcomes.
- Depends on the production `wrela-compiler` composition root to execute a
  command; it never installs compiler services into the public model/API crate.
- Does not parse manifests, compile, colorize phase-internal state, or search for
  LLVM/QEMU itself.

### `xtask`

- Input: maintainer command and checked-in lock/configuration.
- Output: architecture validation, pinned LLVM/LLD/QEMU acquisition/build, and
  atomic distribution assembly.
- `architecture-check` reads Cargo's own locked metadata and rejects a
  missing/extra crate, workspace edge, dev edge, workspace build dependency,
  source-unused workspace edge, untested interface crate, unreviewed
  registry/Git/path dependency, feature-forwarding change, missing native lock,
  inconsistent AArch64 triple/CPU/X18/machine pin, or reintroduced x86 target.
  Named `check`, `test`, and `lint` boundaries—and any exact crate name—give
  each vertical the smallest reviewed package set while Cargo supplies its
  dependency closure. `cargo xfmt` is the formatting handoff gate.
  Distribution work verifies digests, signatures, licenses, target
  firmware/runtime, emulator, and boots conformance images with public `PATH`
  cleared.

## 9. Independent implementation rule

Every transformation team can work from its input model crate, output model
crate, original request, limits, cancellation callback, and checked-in
contract fixtures. Each concrete implementation must add fixtures for valid
minimum/representative/maximum-bound input and for stale identity, corrupt
reference, limit, cancellation, and consumer-facing failure cases. Interface
crates test their sealers even before a concrete producer exists. Cross-crate
integration may require small versioned interface adjustments, but no consumer
may depend on a producer's private arena, query, filesystem, LLVM, QEMU, linker,
or toolchain-discovery state.
