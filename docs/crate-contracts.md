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
   lockfile, target, and test-event boundaries carry independent exact-current
   schema discriminators so stale or corrupt inputs fail closed.
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

The reviewed external registry contract separately pins `sha2 =0.10.9` with
default features disabled for `wrela-backend`, `wrela-link-efi`, and `xtask`;
these owners use it for production artifact/provenance hashing. Any feature,
kind, optionality, version, or additional external edge drift is rejected by
`architecture-check`.

<!-- architecture-check: dependency graph begin -->
```text
wrela-backend -> wrela-backend-protocol, wrela-build-model, wrela-codegen-llvm, wrela-flow-opt, wrela-flow-wir, wrela-flow-wir-codec, wrela-image-report, wrela-link-efi, wrela-machine-lower, wrela-target
wrela-backend -[dev]-> wrela-source
wrela-backend-protocol -> wrela-build-model
wrela-build-model -> no workspace dependencies
wrela-cli -> wrela-build-model, wrela-compiler, wrela-driver
wrela-cli -[dev]-> wrela-package, wrela-package-loader, wrela-test-model, wrela-toolchain
wrela-codegen-llvm -> wrela-build-model, wrela-machine-wir, wrela-runtime-abi, wrela-target
wrela-codegen-llvm -[dev]-> wrela-flow-lower, wrela-flow-opt, wrela-machine-lower, wrela-semantic-wir, wrela-source, wrela-test-model, wrela-test-protocol
wrela-compiler -> wrela-backend, wrela-build-model, wrela-diagnostics, wrela-driver, wrela-flow-lower, wrela-flow-wir-codec, wrela-format, wrela-hir, wrela-hir-lower, wrela-image-report, wrela-lint, wrela-package, wrela-package-loader, wrela-sema, wrela-semantic-lower, wrela-source, wrela-syntax, wrela-target, wrela-test-model, wrela-test-runner, wrela-toolchain
wrela-compiler -[dev]-> wrela-link-efi
wrela-diagnostics -> wrela-source
wrela-driver -> wrela-build-model, wrela-diagnostics, wrela-format, wrela-image-report, wrela-lint, wrela-source, wrela-test-model
wrela-flow-lower -> wrela-diagnostics, wrela-flow-wir, wrela-semantic-wir
wrela-flow-lower -[dev]-> wrela-build-model, wrela-source, wrela-test-model, wrela-test-protocol
wrela-flow-opt -> wrela-build-model, wrela-flow-wir, wrela-test-model
wrela-flow-opt -[dev]-> wrela-flow-lower, wrela-semantic-wir, wrela-source
wrela-flow-wir -> wrela-build-model, wrela-source, wrela-test-model
wrela-flow-wir-codec -> wrela-build-model, wrela-flow-wir, wrela-source, wrela-test-model
wrela-format -> wrela-source, wrela-syntax
wrela-hir -> wrela-package, wrela-source
wrela-hir -[dev]-> wrela-build-model
wrela-hir-lower -> wrela-build-model, wrela-diagnostics, wrela-hir, wrela-package, wrela-source, wrela-syntax
wrela-image-report -> wrela-build-model, wrela-source, wrela-test-model
wrela-link-efi -> wrela-build-model, wrela-lld-sys, wrela-target
wrela-lld-sys -> no workspace dependencies
wrela-lint -> wrela-diagnostics, wrela-hir, wrela-sema, wrela-syntax
wrela-machine-lower -> wrela-build-model, wrela-flow-opt, wrela-flow-wir, wrela-machine-wir, wrela-runtime-abi, wrela-target, wrela-test-model, wrela-test-protocol
wrela-machine-lower -[dev]-> wrela-flow-lower, wrela-semantic-wir, wrela-source
wrela-machine-wir -> wrela-build-model, wrela-runtime-abi, wrela-source, wrela-target, wrela-test-model, wrela-test-protocol
wrela-package -> wrela-build-model, wrela-source
wrela-package-loader -> wrela-build-model, wrela-package, wrela-source
wrela-runtime-abi -> no workspace dependencies
wrela-sema -> wrela-build-model, wrela-diagnostics, wrela-hir, wrela-package, wrela-source, wrela-target, wrela-test-model
wrela-sema -[dev]-> wrela-hir-lower, wrela-syntax
wrela-semantic-lower -> wrela-hir, wrela-sema, wrela-semantic-wir, wrela-test-model, wrela-test-protocol
wrela-semantic-lower -[dev]-> wrela-build-model, wrela-hir-lower, wrela-package, wrela-source, wrela-syntax, wrela-target
wrela-semantic-wir -> wrela-build-model, wrela-source, wrela-test-model
wrela-source -> wrela-build-model
wrela-syntax -> wrela-build-model, wrela-diagnostics, wrela-source
wrela-target -> wrela-build-model, wrela-runtime-abi
wrela-test-model -> wrela-build-model, wrela-source
wrela-test-protocol -> wrela-source, wrela-test-model
wrela-test-runner -> wrela-build-model, wrela-target, wrela-test-model, wrela-test-protocol, wrela-toolchain
wrela-test-runner -[dev]-> wrela-package, wrela-package-loader
wrela-toolchain -> wrela-build-model, wrela-package, wrela-package-loader, wrela-target
xtask -> no workspace dependencies
```
<!-- architecture-check: dependency graph end -->

Workspace build dependencies are forbidden. LLVM/LLD and QEMU are resolved
from the developer's own machine, never acquired or assembled by this
repository: the native backend feature (`wrela-backend/bundled-backend`) links
the system LLVM via `.cargo/config.toml`'s `LLVM_SYS_221_PREFIX` and shells out
to the system `lld-link`; full-image tests invoke the system
`qemu-system-aarch64` and system EDK2 firmware, resolved at runtime.

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

No runtime test function is executed as a host function. The implemented unit
route evaluates manifest-declared `@test comptime fn` source against imported
production declarations and publishes canonical comptime cases. Generated
runtime harnesses, declared image plans, and selected generated-test runtime
assertions share the ordinary backend model; those assertions now reach native
ABI2 objects. Current system-QEMU execution and general non-test/actor
assertion supervision are not complete. Enabled forms must boot the same
AArch64 UEFI semantics used by production images.

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
- Revision 0.1 source-facing manifest names—every module-path segment,
  dependency alias, and image entry—use the pinned Unicode 16 XID/NFC
  identifier rules, reject every language keyword, `_`, and default-ignorable
  or bidi format control. Package, version, profile, image, and image-test names
  remain nominal manifest atoms rather than source identifiers.
- Lockfiles and finished graphs contain exactly the packages reachable from the
  declared root. Closure checks and cycle checks are iterative and bounded by
  `MAX_PACKAGES`; project-controlled values retained by manifest diagnostics
  are truncated to `MAX_MANIFEST_ERROR_VALUE_BYTES` on a UTF-8 boundary.
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

- Input: an exact shared sealed HIR (`Arc<ValidatedProgram>`), the exact
  `PackageId` selected by the root's reserved `core` dependency, semantic
  target view, validated build configuration, change set/limits/cancellation,
  and exactly one
  `AnalysisMode`: production image, test discovery, or compilation of one
  dense group from a `ValidatedTestPlan`. A declared root carries the exact
  manifest selector name and resolved `DeclarationId`; the selector is not
  conflated with the runtime `Image(name=...)` value. A generated harness carries an
  `ImageGroupId` and never forges a HIR declaration/body.
- The analyzer verifies that the selected package is the root graph's `core`
  edge and resolves compiler-recognized standard declarations by that package
  ID. It never compares a package source digest with the whole installed
  standard-library component digest.
- Partial output: complete type table, monomorphized function instances,
  dense image-wide typed values owned by exact function instances,
  function-qualified expression and statement facts, ownership/loan
  transitions, resolved scope
  protocols and activation/cleanup dependencies, proof records, baked
  artifacts, optional image graph/test plan, comptime test results, and
  deterministic diagnostics. Every function has a fixed-size content key,
  source/generated origin (including source closures), exact function color,
  semantic role, source provenance, and stack/frame/work bounds. Actor turns,
  task entries, ISRs, cleanup, image entry, and tests
  are exact graph relations, not conventions inferred by a lowerer.
- Sealed output: `AnalyzedImage`, created only when no error exists and a closed
  image graph has been proved. It retains the exact request HIR through an Arc
  clone, never an image-sized model clone, so SemanticWir lowering can consume
  executable body order while fact provenance remains independently sealed.
- The seal checks every type/constant/value/function/expression/statement/scope/
  image/proof/test reference, effect bit, canonical set, placement owner, and
  bound. Proof IDs are a deterministic topological order, so cycles and forward
  dependencies cannot cross into SemanticWir lowering.
- The seal also binds each device exactly once to the selected target's MMIO
  table, requires an interrupt-capable target binding for every ISR, and binds
  successful discovery/test execution to the exact sealed plan/group/function
  key set. Test counts, scenarios, steps, plan/report bytes, per-group events,
  process output, and execution time are independently bounded.
- The source-unit evaluator first checks the selected test's complete direct
  call closure and then executes ordinary resolved HIR declarations. Its active
  value subset is target scalars plus nominal nongeneric flat structures with
  scalar fields. Construction, privacy-checked projection, parameters/results,
  owned-local move and explicit-copy behavior, branch initialization, nested
  calls, exact target arithmetic/boolean operations, assertions, source-aware
  stacks, and deterministic selection are bounded, cancellable, and covered by
  real cross-module source. Generic or nested aggregates, classes/methods,
  floating point, `Result`, loops, and non-test/actor assertion supervision
  remain fail-closed follow-on work. Selected generated-test assertions are
  implemented through native ABI2 objects; system-QEMU execution is pending.
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
- A declared source `@image comptime fn` is retained only as constructor
  provenance. The sole runtime `ImageEntry` has the explicit
  `GeneratedImageEntry { constructor }` origin; a source-origin function cannot
  claim that role, and generated test harnesses remain a distinct origin.
- Excludes: unresolved names, generics/interfaces, parser nodes, target layout,
  runtime ABI calls, LLVM concepts, and optimization decisions.
- `ValidatedSemanticWir`'s exact-current schema establishes dense IDs, all references,
  function/value ownership, image entry, proof graph, and plan consistency. It
  preserves the analyzer's exact proof-kind vocabulary and every proof source,
  as well as function instance keys, attached proof IDs, recursive-depth
  bounds, and the HIR declaration/file bounds used to validate provenance.
- The current schema retains the exact compiled `FullImageTestGroup`, including its
  plan identity, generated-harness function keys or declared-image/scenario
  binding, descriptors, seed, and execution policy. Validation joins generated
  descriptors to generated function origins and executable bodies and rejects
  role, function-key, plan, root-image, or scenario substitution.
- It defines `reachable_declarations` as the number of distinct HIR
  declaration IDs retained by the closed runtime semantic model (constructor,
  source-function, scope, type, and brand provenance), not inferred call-graph
  reachability. The minimum generated image derives the singleton constructor
  provenance set exactly.
- It also records each supported source async call as one dense
  `ActivationPlan`: caller, ordinary async callee, exact activation task-frame region and
  byte bound, maximum live count, cancellation disposition, capacity proof,
  and source span. The source operation carries that plan ID, so capacity is
  tied to an executable call site instead of inferred from an aggregate count.
- Public model sealing accepts an explicit finite validation policy, polls
  deterministic cancellation during resource and core passes, caps retained
  errors, allocates scratch storage fallibly, and walks constants, structured
  regions, and dependency DAGs iteratively.

### `wrela-semantic-lower`

- Input: sealed `AnalyzedImage`, finite lowering limits, cancellation.
- Output: `ValidatedSemanticWir` and a count/report summary.
- Its sole sealer receives the original `LowerRequest`; an implementation
  cannot validate an output against a different analysis or limit policy.
- Consumer needs met: Flow lowering never queries sema or HIR and sees every
  source-semantic ordering/failure/proof fact explicitly.
- Limits cover aggregate model edges, retained UTF-8/binary payload, constant
  nesting, structured-region nesting, and ordinary arena/operation counts;
  these are checked before the allocation-fallible SemanticWir core validator.
- The production lowerer accepts the analyzer's minimum generated image,
  compiler-generated synchronous test groups, and declared-image test groups.
  Generated groups retain exact descriptors, canonical protocol frames, real
  test calls, and one terminal test-finish effect; declared groups retain the
  real selected image root. The additional actor subset admits the real parsed
  stateless service graph described below: one instance, a non-reentrant turn,
  a single-slot task, their fixed base regions, and one immediate ordinary
  async-helper activation per caller. Async tests, richer source-authored
  executable bodies, actor methods/cross-actor requests, devices/pools, baked
  artifacts, and every runtime graph outside that closed subset remain explicit
  unsupported-feature errors; no facts or proofs are fabricated.

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
  role and function color; generated async/cleanup functions record their
  semantic owner. Actor
  state types, device ISR sets, source/plan summaries, and static/peak memory
  remain explicit. Flow lowering seals all immutable image-plan fields against
  SemanticWir rather than merely comparing counts.
- The exact-current FlowWir preserves generated image-entry versus generated test-entry
  provenance, the exact compiled image-test group, and a dense executable test
  table binding each test ID, global plan ID, monomorphized function key, kind,
  descriptor, source, timeout, and function. Validation rejects role/origin,
  plan, function-key, root-image, and scenario substitution or any test table
  that disagrees with executable operations.
- It represents one in-flight async call as a strict-linear
  `Activation { result }` value. `AsyncCall` creates exactly one activation;
  `Suspend` consumes that activation, names the async state and resume block,
  and requires the resume block's explicit result parameter even for `unit`.
  Activations are not scheduler or queue handles and cannot be copied, dropped,
  returned, or consumed by another operation.
- It mirrors every SemanticWir activation plan, binds it directly to the
  producing `AsyncCall`, retains each function's exact attached proof IDs, and
  closes the base actor/task memory proof over every source-linked activation-frame
  region. The currently produced subset requires an immediate matching
  `Suspend`, one live helper activation, a non-reentrant actor turn or
  single-slot task entry, and `DropCalleeThenPropagate` cancellation. General
  path-sensitive activations, concurrent task slots, actor methods, and runtime
  scheduling remain outside this bounded schema vertical.
- Every region records its closed class, owner, byte capacity, alignment,
  exact `CapacityBound` proof, and source span. Validation joins those fields
  rather than allowing report or Machine consumers to infer region provenance.

### `wrela-flow-lower`

- Input: `ValidatedSemanticWir`, limits, cancellation.
- Output: `ValidatedFlowWir`, lowering metrics, and non-fatal diagnostics.
- Its sole sealer receives the original `LowerRequest`; the IR, report, and
  non-error diagnostics are bound to that exact SemanticWir and limit policy.
- Owns: CFG/SSA construction, async state machines, cleanup paths, logical
  scheduler operations, and translation of semantic proofs.
- For the bounded parsed-actor subset, it canonicalizes one strict-linear
  activation type per distinct helper result type, gives each semantic plan and
  call its own activation value, and lowers one plan-bound `AsyncCall` with its
  immediate matching `Suspend`/resume delivery. It retains the exact
  source-linked activation task-frame region and unchanged capacity/cleanup/function proof
  attachments. Its sealer compares these records field by field against
  SemanticWir and does not infer missing actor capacity.
- Generated synchronous test groups lower canonical frame globals, explicit
  test-emission operations, real function calls, a terminal test-finish effect,
  and the exact FlowWir test table. Declared groups use ordinary image lowering
  without fabricating function tests.
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
- Canonical pipeline revision 2 implements `none`, `development`,
  `performance`, and `size`.
  `none` moves the validated input into the sealed output without an image-sized
  clone and emits an empty canonical pass/decision report. `development` runs
  deterministic scalar/control-flow transforms, revalidates function-role and
  proof links, and retains the exact test table while reporting every pass.
  `performance` and `size` run those four passes plus proof-linked removal of
  checks whose exact canonical condition is `Bool(true)`; performance permits
  its declared growth budget while size permits none. Profile-guided
  optimization remains an explicit unsupported profile rather than silently
  selecting another pipeline.
- Consumer needs met: Machine lowering cannot accidentally consume an
  unverified intermediate pass result; all actor-as-if, check-removal, storage,
  and control-flow decisions remain explainable.
- Ordinary optimizations remain FlowWir. There is no new IR name for each pass.
- Optimization may rewrite function bodies and global initializers, but cannot
  change types, proofs, checkpoints, provenance, signatures, roles, bounds, or
  the image plan. The seal requires the actual IR-change bit, changed passes,
  and decision records to agree; optimization level `none` preserves the input
  model exactly.
- Optimizer limits bound every variable-length FlowWir edge, all retained
  UTF-8/immediate payload, report payload, and conservative scan/comparison
  work, so instruction-count growth is not the sole denial-of-service guard.
  The `none` and transforming sealers compare the complete model and report
  through schema-specific, zero-scratch streaming visitors rather than derived
  whole-model equality. Every retained string/byte payload is compared in
  bounded chunks with cancellation, and an embedded `FullImageTestGroup` is
  independently checked against both optimizer and test-plan edge/payload
  ceilings before comparison.

### `wrela-flow-wir-codec`

- Input: `ValidatedFlowWir` plus `CodecLimits`, or bytes plus expected
  `BuildIdentity` and limits, together with cancellation for encoding and
  decoding the potentially image-sized frame.
- Output: canonical bytes/header or newly `ValidatedFlowWir`.
- The exact-current wire header binds the FlowWir model, SemanticWir
  provenance, payload size, and complete build identity. Its schema
  discriminator exists only to reject stale or corrupt input; the decoder
  accepts one shape and has no legacy reader or migration path. It rejects
  invalid UTF-8/tags, noncanonical order,
  duplicate/non-dense IDs, overflow, trailing bytes, limit violations, and
  build mismatch before returning a sealed value.
- Frontend sealing proves the frame decodes to the exact input model and that a
  second encode is byte-identical. Backend decoding canonically re-encodes the
  validated model and requires the complete received frame and inspected header
  to match, so ignored or alternate encodings cannot cross the wire boundary.

### `wrela-runtime-abi`

- Input/output model: closed compiler-only runtime intrinsic set, exact scalar
  signatures, an exact-current ABI discriminator, and canonical
  `RuntimeRequirements`.
- Current surface: image enter/exit/fatal, idle, interrupt mask/restore, DMA
  cache maintenance, record/replay, and test emit/finish.
- Fatal detail uses one closed compiler-owned `RuntimeFatalCode`: arithmetic 1,
  conversion 2, actor-mailbox-full 3, actor-mailbox-mismatch 4,
  checked-left-shift-result-loss 5, and invalid-shift-count 6. Machine lowering
  selects the code; LLVM may implement the check but may not collapse the two
  shift causes or infer a code from emitted text. The existing Flow
  function/instruction pair remains the source-site detail.
- Every intrinsic has one current COFF symbol spelling and one exact scalar
  signature; MachineWir validates calls against both. The discriminator in the
  spelling is a fail-closed identity guard, not a promise to retain an older
  symbol set.
- The same ABI fixes one always-present, 8-byte-aligned read-only route-table
  symbol: an 8-byte `(count, reserved-zero)` header followed by 16-byte
  `(INTID, reserved-zero, handler-address)` records. Integers are little-endian,
  handler addresses use ARM64 COFF relocations, and records are sorted by INTID.
  This lets codegen and the target runtime object implement exception dispatch
  independently without an inferred metadata or zero-length-symbol convention.
- Source cannot name these intrinsics. The target ships one digest-checked
  AArch64 runtime object implementing this ABI. Adding or changing a signature
  replaces the exact-current interface identity, runtime object, target
  manifest, and all consumers in the same change; no compatibility shim is
  retained.

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
- MachineWir version 5 introduced the exact dense FlowWir test table and
  compiler-generated test-harness origin. Its closed operation set includes
  addresses of measured globals and runtime calls, allowing codegen to emit
  static protocol frames without reconstructing test identity or payloads.
  Validation requires every listed test function to have the test role, every
  test runtime call to occur in the generated image-entry harness, every emit
  payload to resolve to a matching byte-array global, and every nonreturning
  runtime intrinsic to terminate its block.
- MachineWir version 6 makes target-runtime activation part of the sealed
  generated-entry contract. Every ordinary or test image entry has exactly one
  dominating `ImageEnter(image_handle, system_table)` call, admits the original
  body only through the zero-status edge, and returns a nonzero `EFI_STATUS`
  unchanged. Validation rejects omission, duplication, argument reordering,
  bypass, status remapping, and calls outside the generated UEFI entry. The
  runtime ABI remains version 1 because the intrinsic and signature were
  already present; version 6 tightens which MachineWir programs are valid.
- The active version-7 contract retains the version-6 generated-test rule that
  consumes every returning
  `TestEmit` status instead of treating emission as fire-and-forget. The call is
  the final instruction in its block and its sole `EFI_STATUS` result drives an
  exact one-case switch: zero alone reaches a parameter-free continuation,
  while the default reaches an empty single-predecessor block that returns that
  same status from the UEFI entry. The success block is likewise
  single-predecessor, so an edge cannot bypass the check. Validation rejects an
  ignored result, a nonzero success case, a status borrowed from another emit,
  post-call work in the producer block, a remapped failure return, or an extra
  predecessor. Runtime-call results, `Switch`, and `Return` were already
  representable when this rule landed; version 7 retains the narrowed valid
  generated-harness shape without a compatibility reader.
- MachineWir version 7 adds the exact downstream consumer for the bounded
  FlowWir activation subset. One installed stateless actor turn and one
  single-slot static task each retain their source plan, caller/callee,
  immediate unit-helper call/resume edge, frame region/layout, maximum-live
  bound, cancellation disposition, and capacity/cleanup proof authority. The
  strict-linear Flow token is erased only after those joins: the helper becomes
  an ordinary private internal call and the suspend becomes its named resume
  edge. The task entry is invoked exactly once on the successful `ImageEnter`
  path; the actor turn is emitted but remains `DormantMailbox` and has no
  invented caller. Proof dependencies are dense, sorted, strict-backward edges,
  and the unique `ImageClosed` root must close over activation capacities and a
  `TypeChecked`/`EffectsAllowed` ancestry. This is a compiled startup-task
  subset, not mailbox admission, recurring scheduling, or cancellation
  execution.
- Floating not-equal is explicitly unordered-or-not-equal, matching the source
  language rule that NaN compares unequal to itself. Version 5 also makes
  boolean not, integer bitwise not, and floating negation first-class unary
  operations; floating negation retains the canonical-NaN result contract.
  The stale ordered-only predicate is not representable. Checked integer
  add/subtract/multiply/divide/remainder/shift and checked numeric conversions
  are likewise first-class: each retains its exact signedness or source and
  destination kinds plus Flow function/instruction failure provenance, and
  lowers failure to the closed fatal runtime ABI instead of LLVM undefined
  behavior or a guessed result.
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
- The revision 0.1 production lowerer accepts the canonical minimum image and
  the sealed synchronous scalar/control-flow surface after `none` or any
  canonical revision-2 development/performance/size profile. It preserves the
  exact Flow function origins,
  roles, source spans, dense test table, and proof closure while lowering
  supported scalar immediates, wrapping arithmetic and comparisons, bitcasts,
  selects, ordinary loads/stores, calls, fences, and control-flow edges. The
  image entry alone receives the exact AArch64 UEFI two-pointer/`EFI_STATUS`
  boundary and an implicit `EFI_SUCCESS` value for a unit return.
- Generated test harnesses receive a measured read-only global for every
  canonical protocol frame. MachineWir uses explicit global-address values and
  exact `TestEmit(address, length)` / nonreturning `TestFinish(outcome)` runtime
  calls, and retains the dense mapping from each test descriptor to its
  `MachineFunctionRole::Test` body. Static payload placement, exclusive use,
  runtime-call context, terminal finish, and runtime-symbol requirements are
  validated before sealing. Lowering allocates two deterministic blocks per
  emit for the exact-zero continuation and unchanged-status return, meters the
  added blocks/case/return edges before construction, recanonicalizes dense
  instruction IDs after expansion, and polls cancellation during every new
  scan. The separate closed actor slice accepts exactly the version-7
  one-actor/one-task immediate-unit-helper contract above. Richer aggregates,
  ownership operations, mailbox/actor-method dispatch, multi-slot or recurring
  task scheduling, device operations, interrupt functions, and dynamic test
  payloads fail explicitly with `UnsupportedInput` until their exact lowering
  exists.
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
- For a generated harness, codegen mechanically preserves each sealed
  `TestEmit` result, exact-zero switch, and unchanged-status return. It cannot
  erase, merge, or substitute those guards; independent textual and native
  evidence checks the two-emission fixture before accepting the object.
- The implemented writable-storage subset is deliberately narrow. Private,
  dense, exactly covering byte-array globals may use `WritableData` with a
  typed zero initializer in exact `.data` or in the canonical
  `.data$wrela$region$N` actor-region namespace; `ZeroFill` uses the same
  initializer in exact `.bss`. Type and global alignment must be the same power
  of two, no greater than the target maximum, and the extent must be an alignment
  multiple. Textual LLVM uses aligned `internal global` zero initializers for
  both forms. Independent COFF measurement requires writable-data sections to
  carry their exact raw zero payload, while `.bss` has zero raw bytes and raw
  pointer but retains its exact logical extent and symbol ranges.
- Writable/zero-fill traversal, sorting, symbol lookup, and project-sized
  section scans remain resource-bounded and cancellation-polled. The backend
  code generator does not infer actor storage. Machine lowering now consumes
  the sealed actor regions and emits one exact byte-array type, global, private
  symbol, and writable section per mailbox/root-frame/activation-frame region,
  retaining capacity-proof and source joins. It can emit the bounded actor-turn,
  startup-task, immediate-helper functions, and those reservations as native
  COFF. Nonzero initializers, relocatable data, typed aggregate storage, mailbox
  dispatch/admission, and recurring runtime consumption remain unsupported
  producer/runtime work.
- Each `InterruptHandler` marker maps to an ordinary AAPCS64 body reached only
  from the target runtime's exception trampoline. MachineWir contains the
  always-present, exactly sized runtime-metadata section and table symbol;
  codegen fills its ABI-v1 header/records and ARM64 relocations from the sealed
  routes. It does not synthesize or rediscover identities, storage, or symbols.
- Revision 0.1 always runs LLVM verification and emits neither language
  unwinding nor caller-selected debug policy; adding artifact-affecting debug
  modes requires an explicitly hashed profile/request contract.
- Independent COFF validation accepts only the two reviewed ARM64 unwind
  encodings: one full pdata/xdata record with exact relocations, or LLVM's
  canonical one-relocation packed pdata record with defined flag/register/code
  extents and empty xdata bookkeeping. Reserved packed flags, nonzero addends,
  mismatched function extents, or orphan xdata are malformed artifacts.

### `wrela-lld-sys`

- Input: raw LLD COFF argument vector from `wrela-link-efi`, with exactly one
  direct `/out:` path.
- Output: `Ok(())` only after the system `lld-link` child process exits
  successfully with empty combined stdout/stderr, or a captured driver
  failure (nonzero exit, unexpected diagnostic output, or a bounded
  diagnostic-size overflow).
- The only crate permitted to shell out to the system `lld-link` executable
  (resolved from `WRELA_LLD_LINK`, then `PATH`, then a fixed Homebrew
  fallback); it contains no unsafe code, no Wrela model, and no target
  policy. Behind the `bundled-lld` feature; without it, `link_coff` returns
  `LldError::NotLinked`.

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
- Production wiring uses `CanonicalCoffObjectInspector` and
  `CanonicalLinkedImageInspector`. The latter implements
  `LinkedImageInspector::inspect(image, map, provenance_map, inputs, target,
  ImageInspectLimits, cancellation)` so PE32+, both maps, and the sealed COFF
  inputs share the exact target and bounded image/map/section/symbol/measurement
  policy. The linker derives a private `<map>.lldmap` path and requests LLD's
  contribution map itself; callers cannot inject that path or substitute input
  provenance. `LinkLimits::argument_bytes`
  independently caps the aggregate bytes retained for the fixed LLD COFF
  argument vector before the native boundary is invoked;
  `LinkLimits::exception_records` is projected exactly into the image inspector
  and bounds ARM64 pdata/xdata decoding before record retention.
- The PE32+ inspector validates all 16 data-directory slots and admits only the
  exact exception, base-relocation, and type-16 reproducibility records emitted
  by the pinned lane. Imports/IAT/delay imports, exports, TLS, CLR, load config,
  certificates, resources, bound imports, and global pointers are rejected.
  Target-fixed optional-header fields, checksum, stack/heap reservations,
  section allowlist, permissions, raw/virtual ordering, zero padding, absence
  of overlays, REPRO/timestamp binding, and the one measured LLD retained header
  page are checked exactly; writable executable sections are impossible.
- ARM64 exception validation accepts bounded canonical packed or full unwind
  records, checks sorted nonoverlapping exact function coverage and instruction
  extents, parses supported xdata opcodes, and rejects language-specific
  handlers and custom assembly unwind forms until their runtime contract is
  implemented.
- Post-link inspection reopens every sealed input COFF, parses its ARM64
  `ADDR64` sources and exact external definitions, and joins them to canonical
  LLD input-section contributions. The translated sites must equal the PE
  `DIR64` base-relocation sites exactly, with no missing, extra, duplicate,
  overlapping, dead-section, or foreign-object evidence. The artifact exposes
  a domain-separated digest over the EFI image, contribution map, sealed object
  identities/sections, and resolved relocation provenance; all native outputs
  are removed on failure or cancellation.

### `wrela-image-report`

- Input: build identity; semantic/Flow proof and image facts; optimization
  decisions; MachineWir/runtime facts; final section/symbol/link measurements;
  target-variable exclusions; and artifact digest.
- Output: a sealed exact-current `ImageReport`, canonical fixed-order JSON,
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
- The current report schema retains the optional compiled `FullImageTestGroup` verbatim,
  including its generated-harness or declared-image root, ordered descriptors,
  typed invocations, scenario identity, seed, and execution policy. Sealing
  validates the standalone binding and requires its root image name to match
  the report image; canonical JSON round trips every generated and declared
  field without reconstruction.
- That schema is the only accepted report shape. Its tag rejects stale or
  mismatched artifacts at the trust boundary; there is no legacy reader,
  migration, adapter, or fallback contract. Its embedded interface facts must
  be exactly SemanticWir 5, FlowWir 7, Flow wire 7, MachineWir 7, and runtime
  ABI 1; nonzero stale or future values are rejected rather than tolerated.
- Schema v10 also projects sealed actor, task, reportable region, and async
  activation plans into
  canonical dense-ID-qualified nodes, supervision edges, and capacity/frame/
  alignment bounds. Every `ProofFact` retains its exact optional bound, source
  identities, proof dependencies, and why-chain rather than only a category
  label. Region nodes retain the exact Flow source span; backend
  assembly authenticates each `RegionPlan.capacity_proof` against the sealed
  Flow model before projection. Every reportable region carries one canonical
  capacity-evidence row that joins its exact `RegionPlan.capacity_proof` to the
  matching capacity `ProofFact`, byte `BoundFact`, and dense region node;
  independent report validation rejects missing, duplicate, substituted, or
  category/owner/byte-mismatched links. Every activation carries one canonical
  evidence row joining its dense plan and activation `TaskFrame` region to the
  exact caller, ordinary async callee, owner, source span, frame-byte bound,
  maximum-live value, closed cancellation disposition, capacity proof, and the
  callee's cleanup proof dependency. Validation requires a one-to-one plan,
  region, and evidence join; checked `frame_bytes * maximum_live` equality;
  canonical `.async-activation-frame` naming; and matching Work/Capacity/
  CleanupAcyclic proof provenance. Actor/task plans currently
  retain structural plan provenance rather than declaration spans, so the
  report says `FlowWir.ActorPlan` or `FlowWir.TaskPlan` instead of inventing a
  source location or proof link.
- The report retains the exact decoded PE base-relocation directory byte extent,
  canonical block count, AArch64 `DIR64` entry count, and nonzero
  domain-separated provenance digest from the sealed link artifact. Independent
  report validation checks their bounded structural relationship and backend
  assembly requires byte-for-byte equality with that artifact; individual
  relocation rows are intentionally not claimed by this report schema.
- The schema also carries whole-image region-inference facts (ch03 §7–§8): a
  `RegionAssignmentFact` records one allocation's assigned `RegionClass` (image,
  task-frame, call, request, pool, or static), and a `PromotionFact` records one
  promoted allocation's identity, source and destination region, reason, and the
  dense proof reference. Assignment identities form a unique dense
  `alloc:<u32>:<name>` set. Every promotion joins to the same allocation's final
  assignment and to an exact `region-bound`/`proved` proof whose subject is that
  allocation and whose finite bound is nonzero. Both vectors are canonicalized,
  item/payload bounded, cancellation-aware, and round-trip through canonical
  JSON and the decoder. The compiler frontend does not yet populate them (Lane
  B task B2b), so ordinary builds leave both empty. Adding the arrays produced
  schema v12; exact identity/assignment/proof sealing bumps 12 to 13. The decoder
  accepts only the exact current version.
- Consumer needs met: the report exposes logical image topology and physical
  lowering, bounds, proof why-chains, actor paths, stack/frame/work/checkpoints,
  hardware/recovery, startup/shutdown, all IR/ABI versions, runtime intrinsics,
  target-variable exclusions, sections/symbols, and exact artifact identity.
- Does not compute proofs, inspect LLVM, hash/read artifacts, or fabricate
  measurements.

### `wrela-backend-protocol`

- Input/output: one bounded framed `BackendRequest` or `BackendResponse` with
  request ID, complete build configuration, controlled relative input/output
  paths, exact canonical FlowWir digest, frontend-verified target-runtime
  SHA-256 and byte length, artifact/report digests, and typed failure category.
- Guarantees: magic/exact-current-schema/length, exact consumption, finite
  text/profile data, profile validation, no parent/absolute paths, and no
  ambient filesystem authority. The current protocol requires the private backend to re-open and
  COFF-inspect the runtime object, then match both request digest and length
  before linking.
- This is exact-current internal IPC, not a public compatibility surface.

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
- Report assembly copies the validated FlowWir compiled test-group binding
  exactly into analysis facts; it does not infer group identity from dense IDs,
  local test tables, harness names, or scenario paths.
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
  Protocol version 3 and report schema 2 add the closed
  `LanguageFatalCause::{CheckedShiftResultLoss, InvalidShiftCount}` outcome.
  During an active test either cause has exactly four events: run started, test
  started, the typed failed test result, and run finished with zero passes and
  one failure. Inactive, foreign, duplicate, late, or post-terminal fatal
  evidence cannot be promoted into a valid report.
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

- Input: one `TestEvent`, one unescaped binary frame, or a dense binary frame
  stream plus protocol limits. PL011 transport escaping is outside this codec.
- Output: private `EncodedEvent` sealed from a candidate only after independent
  header inspection and canonical decode/re-encode, or an inbound event returned
  only by `decode_and_verify_event` after the same complete-frame round trip.
- The 32-byte header is exactly the eight-byte `WRELTST\0` magic, little-endian
  frame-version `u32`, event-version `u32`, sequence `u64`, payload-length
  `u32`, and payload CRC32C `u32`, followed by the canonical tagged payload.
- Guarantees: independent frame/event versions, dense zero-based stream
  sequencing, bounded lengths, canonical tags/UTF-8/spans, CRC32C, exact
  consumption, and corruption rejection. The checked-in `protocol/v1` fixture
  drives canonical, corruption, limit, and cancellation coverage without a
  second fixture-only codec. This schema is stable external test tooling data.
- Depends on `wrela-source` for canonical assertion-span decoding rather than
  maintaining a second source-location representation in the protocol layer.
- Event version 3 gives the two language-fatal causes canonical payload tags 0
  and 1. Cause tags are semantic protocol data, not host strings, exit-code
  inference, or a QEMU stderr convention.
- Encode, header inspection, decode, and canonical round trips receive the
  runner's cancellation callback.

### `wrela-toolchain`

- Input: explicit installation root or executable-relative discovery; bounded
  canonical manifest bytes through `ToolchainManifestCodec`, the single
  `ToolchainCompatibility::current()` tuple, and driver-observed byte/digest
  evidence for every declared component, target, and target-relative file.
- Output: `VerifiedToolchain`, the only capability accepted by the test runner,
  plus controlled content-addressed paths for frontend, private backend,
  standard library, target package, and doctor checks.
- Manifest decoding is request-bound: after limit and exact interface-identity validation,
  canonical re-encoding must reproduce the complete supplied manifest bytes
  before component observation can create `VerifiedToolchain`; decode and
  re-encode receive cancellation.
- Schema 1 carries a nonempty, identity-ordered standard-library package index.
  Each record reuses `PackageIdentity`, requires one portable direct-child
  `Toolchain` locator beneath `share/wrela/std`, and pins the canonical package
  manifest digest. The verified whole-directory digest and index together let
  consumers reject package identity, locator, or manifest substitutions.
- Every shipped component and target-relative runtime file carries a nonzero
  byte count and digest. Consumers resolve only manifest-declared target
  files, never arbitrary children of a trusted directory. `VerifiedPath`
  fields are private and only `VerifiedToolchain` can derive one.
- The exact interface-identity tuple independently fixes language,
  build-profile encoding, target
  package, backend protocol, all three IR models, Flow wire, runtime ABI, image
  report, test plan/report/scenario, test event, and test frame versions.
- Does not search `PATH` for its own manifest-sealed components. The target
  digest covers the pinned runtime object; QEMU and EDK2 firmware are resolved
  from the developer's system (`system_qemu`, `system_firmware_code`,
  `system_firmware_vars`, overridable by `WRELA_QEMU`,
  `WRELA_QEMU_FIRMWARE_CODE`, and `WRELA_QEMU_FIRMWARE_VARS`) and are not
  sealed by the manifest.
- In schema 1, the standard-library component and target-package directory use
  canonical tree digest v1 (`WRELTRE\0`, version 1); executables and declared
  target files use raw SHA-256. Reinterpreting either requires a schema bump.

### `wrela-test-runner`

- Input: `ValidatedTestPlan`, compiler-evaluated results, and exactly one of a
  sealed EFI artifact or a phase-accurate pre-execution failure for every image
  group, plus the selected target, `VerifiedToolchain`, private work directory,
  bounded `ProcessExecutor`, target harness, and cancellation.
- Output: `ValidatedTestReport` containing compiler and QEMU cases plus
  reproducibility evidence.
- The production target harness delegates canonical frame validation to
  `wrela-test-protocol`; it owns only the target's RFC 1055 PL011 transport,
  verified QEMU invocation, and event-to-report projection.
- Consumer needs met: orchestration is independently fakeable; target command
  generation and event decoding are separately testable; ambient environment is
  not inherited; the executable, working directory, canonical environment,
  checked aggregate timeout, output ceiling, and event ceiling are revalidated
  before/after execution. Each `ImageArtifact` is sealed against an exact plan
  group, build identity, path, digest, measured byte count, and image limit.
  The process executor reverifies the system-resolved emulator and hashes the
  EFI image plus both firmware inputs while staging private per-run copies;
  only the variable store copy is writable. Installed firmware is never
  launched in place. Artifact build identity and compiler, standard library,
  and target digests must match the verified installation; the emulator and
  firmware are not manifest-sealed, so they are freshly hashed and reverified
  each run rather than matched against a pinned digest. Canonical command and
  event-stream digests and the summarizer's retained event stream are
  independently compared. Missing emulator or firmware is an infrastructure
  error, never a pass result.
- The local executor observes serial output incrementally while the guest is
  live, writes bounded scenario input to the guest serial channel, enforces each
  step deadline, and issues explicit QMP `qmp_capabilities`/`quit` only for a
  declared shutdown step over a private command-bound Unix socket. QMP JSON
  bytes, messages, nesting, greeting, and replies are bounded and unambiguous.
  It clears the ambient environment, creates a private process-group leader,
  synchronously terminates and reaps that complete group on cancellation,
  limit, timeout, protocol error, or success, and reports cleanup failure or
  unexpected staging/QMP residue. Raw firmware serial segments may interleave
  with SLIP frames; bytes using the reserved test magic remain strict and
  corruption is never downgraded to raw output.
- Compiler/link failures may bypass emulator and firmware resolution only when
  their exact pre-execution results cover the corresponding plan groups. These
  results cannot contain guest cases/events or image/command/emulator evidence.
- `RunnerLimits` independently bounds argument count, environment count,
  aggregate command bytes, and aggregate path bytes. Executor duration cannot
  exceed the sealed timeout. One group-derived `ProtocolLimits` and its exact
  maximum stream bytes bind command evidence, live serial observation, final
  decoding, and output collection. Complete prefixes from crash/timeout may be
  retained; successful execution rejects a truncated reserved frame. A private
  `VerifiedProcessFile` can originate only
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
- `LocalWorkspaceProvider` binds one existing absolute, canonical,
  symlink-free workspace root. It supports only locked workspace locators,
  reads exactly manifest-declared source and scenario paths without directory
  walking, hashes raw bytes during checked streaming reads before UTF-8
  interpretation, and revalidates root/file identity plus canonical
  containment before and after each read. Archive and toolchain locators
  require separate explicit capabilities and fail closed here.
- This portable standard-library provider detects observable pathname or file
  replacement but is not an `openat`-style race-free directory capability. A
  hostile concurrently mutating filesystem still requires an OS capability or
  sandbox, or a stronger injected provider. `LocalFrontendService` composes
  that boundary with the canonical workspace loader and parser and preserves
  the exact graph-module/FileId mapping.
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
- The planner resolves the root graph's reserved direct `core` dependency to
  one toolchain-located package and retains that `PackageId` in `PlannedBuild`.
  `BuildIdentity::standard_library` remains the whole verified component
  digest; semantic phases consume the selected package ID and never conflate
  those two identities.
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
- Every source command accepts only the pinned
  `aarch64-qemu-virt-uefi` target, an explicit bounded profile atom, and the
  same warnings/result-count diagnostic policy. `test` additionally exposes
  mutually exclusive `--comptime`, `--integration`, `--images`, and bounded
  `--name-contains` selection. A sealed failed test report renders normally but
  exits unsuccessfully.
- Does not parse manifests, compile, colorize phase-internal state, or search for
  LLVM/QEMU itself.

### `xtask`

- Input: maintainer command (`architecture-check`, `slices`, `check`, `test`,
  `lint`, `gate`) and Cargo's own locked metadata.
- Output: architecture validation and the focused-slice check/test/lint/gate
  commands. `xtask` no longer acquires, builds, or assembles anything; it does
  not touch LLVM, LLD, QEMU, firmware, or a distribution tree. LLVM, LLD, and
  QEMU are resolved from the developer's own machine.
- `architecture-check` reads Cargo's own locked metadata and rejects a
  missing/extra crate, workspace edge, dev edge, workspace build dependency,
  source-unused workspace edge, untested interface crate, unreviewed
  registry/Git/path dependency, feature-forwarding change, inconsistent
  AArch64 triple/CPU/X18/machine pin, or reintroduced x86 target.
  `cargo xgate <slice-or-crate>` validates the locked, host-filtered Cargo
  resolution against reviewed workspace and versioned external/transitive
  closures, prints the complete slice contract, then runs scoped formatting,
  all-target checks, unfiltered unit/contract tests, Clippy with warnings
  denied, and architecture validation under forced offline mode. It rejects
  arbitrary extra arguments; a slice/crate whose `full_route` is native routes
  `--full` to `cargo test` with the `wrela-backend/bundled-backend` feature
  enabled against the system LLVM/LLD (and, for the `testing`/`cli` slices,
  system QEMU and firmware) instead of silently skipping that work.
  `cargo xtask slices` is the authoritative package, boundary, fixture, native
  requirement, command, closure, and timing-budget inventory. Named `check`,
  `test`, and `lint` remain lower-level direct commands; `cargo xfmt` remains
  the whole-workspace formatting handoff gate.

## 9. Independent implementation rule

Every transformation team can work from its input model crate, output model
crate, original request, limits, cancellation callback, and checked-in
contract fixtures. Each concrete implementation must add fixtures for valid
minimum/representative/maximum-bound input and for stale identity, corrupt
reference, limit, cancellation, and consumer-facing failure cases. Interface
crates test their sealers even before a concrete producer exists. Cross-crate
integration may require small exact-current interface adjustments, but no consumer
may depend on a producer's private arena, query, filesystem, LLVM, QEMU, linker,
or toolchain-discovery state.
