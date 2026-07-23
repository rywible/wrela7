# Lowering refusal tag index

Every `feature` string the lowering pipeline can put in an
`UnsupportedInput` refusal, with the crate that owns it. The list is derived
from workspace source, never from running the compiler, and
`cargo xtask diagnostic-index` (`cargo xdiag`) fails the build when source and
this file disagree in either direction.

This is a **second, disjoint namespace** from the
[diagnostic code index](diagnostic-index.md). A `feature` string never reaches
`wrela_diagnostics::Diagnostic::code`; it is the name a lowering phase gives a
deferred tail, and it is what
[the conformance inventory](conformance-inventory.md) and the toolchain plans
cite when they say a feature "stays fail-closed". The two indexes are kept
apart because the code index's own scope statement excludes these strings, and
merging them would make "code" mean two different things.

## What a tag is here

A *lowering refusal tag* is the `feature` field of an `UnsupportedInput`
variant. Four crates declare such a variant, and all four are covered:

- `wrela-semantic-lower` — `LowerError::UnsupportedInput`
- `wrela-flow-lower` — `LowerError::UnsupportedInput`
- `wrela-machine-lower` — `MachineLowerError::UnsupportedInput`
- `wrela-compiler` — `AnalysisFactAssemblyError::UnsupportedInput`
  (`crates/wrela-compiler/src/analysis_facts.rs`)

912 distinct tags exist: **156 named tags** and **756 prose reasons**. The two
are listed separately below, partitioned by a mechanical rule, not by judgement.

### Named tags versus prose reasons

A tag is *named* when the part before an optional parenthesised qualifier is
code-shaped — two or more `-`-separated lowercase alphanumeric segments, the
same shape the diagnostic code index requires. Everything else is a prose
fragment of the refusal message, which reads `… does not yet support {feature}`.

- named: `machine-async-result-delivery-pending`,
  `semantic-with-owner-lowering-pending (non-actor source function)`
- prose: `a binary operation with an unknown type`,
  `FlowWir cleanup helper identity`

Both lists are drift-checked identically. The split exists because only the
named tags are cited as stable deferral names elsewhere in the documentation;
the prose reasons are enumerated so that nothing in the namespace is silently
omitted, and so that a prose reason that later becomes a named tag shows up as
drift in both blocks.

## Index key

The key is the **full `feature` string**, including any parenthesised
qualifier — not the bare name before the parenthesis. That is deliberate:

- the full string is the observable value. It is what `LowerError` carries, what
  tests pin with `feature == expected`, and what a user sees in the message.
- the same bare name legitimately carries many different qualifiers
  (`machine-async-outcome-authentication` appears with 22 distinct qualifiers,
  `semantic-async-outcome-authentication` with 42). Each qualifier marks a
  different deferred check. Keying on the bare name would collapse them and
  make adding, removing, or re-wording a qualifier invisible to the check.

Lines are formatted `<owning crate>[,<crate>…] <tag>`, owners first, because a
tag contains spaces and a crate name does not; the tag therefore runs
unambiguously to the end of the line. Entries are sorted by tag.

## How the index is derived

`xtask` masks comments and string contents (byte offsets preserved), drops
`#[cfg(test)]` items, and then locates every `UnsupportedInput { … }` **in a
function body**. An occurrence outside a function body is the enum's own field
declaration, and one whose closing brace is followed by `=>` is a `match`
pattern; neither constructs a refusal. A construction site with no readable
`feature` field is **rejected**, not skipped.

Each `feature` expression must reduce to string literals by one of five
admitted rules:

1. a string literal, optionally followed by `.to_owned()`, `.to_string()`, or
   `.into()`;
2. a file-local `const NAME: &str = "...";`;
3. an `if`/`else` that selects between tag expressions — both branches count;
4. an identifier bound as a **parameter** of the enclosing function, which makes
   that function a *carrier*: its call sites **across the whole owning crate**
   are then resolved at the matching argument position, transitively. Crate-wide
   resolution is required because `fn unsupported(feature)` is defined in one
   file and called from others. A carrier declared plain `pub` is **refused**
   instead — its call sites could live in a crate this index would then
   misattribute. `pub(crate)`, `pub(super)`, and `pub(in path)` cannot be
   re-exported more widely than they are declared, so they stay resolvable;
5. an identifier bound by a `let` binder in the enclosing function, read through
   at its initializer.

Rule 3 over-approximates a selection rather than guessing which branch runs, so
the index can never miss a tag a site can emit. Anything that does not reduce is
**rejected by name** — the check names the file, line, and expression and fails.
Nothing is silently skipped.

## What this index does not cover

- **`Diagnostic::code` values.** A different namespace with a different owner
  and a different check; see [the diagnostic code index](diagnostic-index.md).
- **The other `LowerError` variants.** `Cancelled`, `ResourceLimit { resource }`,
  and `InvalidSemanticFacts` carry their own strings; only `UnsupportedInput` is
  claimed here.
- **Any claim of quality.** Tags and owners are listed and nothing else. The
  index does not assert that a tag is well-named, that its qualifier is
  accurate, that two similar tags should be one, or that a refusal is correctly
  placed. It asserts only that the set is stable, owned, and cannot drift
  unnoticed.
- **Test-only literals.** Refusals asserted inside `#[cfg(test)]` items are
  ignored; only production construction sites define the index.

## Regenerating after a source change

One command, then paste:

```
cargo xdiag
```

On drift it prints, for each affected block, the exact replacement text after
`replace the marked block with:`. Both the named and the prose block are
reported in a single run. Replace the contents between the corresponding
`<!-- refusal-tag-index: … begin -->` / `… end -->` markers with the printed
block verbatim, and re-run `cargo xdiag` to confirm. Nothing here is
hand-maintained.

## Enforcement

- `cargo xdiag` (`cargo xtask diagnostic-index`) re-extracts and reconciles both
  indexes, naming added, removed, duplicated, and re-owned tags. `cargo xnightly`
  runs it as a step.
- `xtask` tests: `refusal_tag_extraction_reads_every_admitted_carrier_form`,
  `refusal_tag_extraction_confines_a_carrier_to_its_own_crate`,
  `refusal_tag_extraction_fails_closed_on_unreadable_refusal_sites`,
  `refusal_tag_extraction_fails_closed_on_a_carrier_that_escapes_its_crate`,
  `named_refusal_tags_are_separated_from_prose_refusal_reasons`,
  `refusal_tag_reconciliation_accepts_an_exact_index_and_names_drift_in_each_direction`,
  `refusal_tag_exclusion_reconciliation_rejects_undeclared_and_stale_sites`,
  `workspace_refusal_tags_have_only_the_declared_non_literal_exclusions`, and
  `documented_refusal_tag_index_matches_workspace_sources`.

## Named tags

<!-- refusal-tag-index: named begin -->
```text
wrela-flow-lower flow-async-outcome-authentication (activation plan)
wrela-flow-lower flow-async-outcome-authentication (await result)
wrela-flow-lower flow-async-outcome-authentication (call position)
wrela-flow-lower flow-async-outcome-authentication (call source)
wrela-flow-lower flow-async-outcome-authentication (callee identity)
wrela-flow-lower flow-async-outcome-authentication (declared Result shape)
wrela-flow-lower flow-async-outcome-authentication (declared Result)
wrela-flow-lower flow-async-outcome-authentication (direct call protocol)
wrela-flow-lower flow-async-outcome-authentication (function metadata)
wrela-flow-lower flow-async-outcome-authentication (proof)
wrela-flow-lower flow-async-outcome-authentication (type and await identity)
wrela-flow-lower flow-async-outcome-callee-reuse-pending (helper has multiple call sites)
wrela-flow-lower flow-async-outcome-consumer-pending (nested await region)
wrela-flow-lower flow-async-outcome-consumer-pending (non-immediate match or is)
wrela-flow-lower flow-async-outcome-consumer-pending (scoped outcome consumer)
wrela-flow-lower flow-async-outcome-producer-pending (noncanonical helper body)
wrela-flow-lower flow-async-outcome-producer-pending (noncanonical helper values)
wrela-flow-lower flow-async-outcome-producer-pending (only direct Ok[u64])
wrela-flow-lower flow-async-outcome-profile-pending (multiple or partial authenticated outcomes)
wrela-flow-lower flow-enum-nominal-payload-lowering-pending (flat-structure enum payload)
wrela-flow-lower flow-scope-cleanup-form-lowering-pending (non-pass exit helper)
wrela-flow-lower flow-static-bytes-lowering-pending (async/actor byte values)
wrela-flow-lower flow-static-bytes-lowering-pending (nonlocal byte binding provenance)
wrela-flow-lower flow-with-abnormal-cleanup-lowering-pending (abort or suspension-safe scope)
wrela-machine-lower machine-async-outcome-authentication (activation and proof)
wrela-machine-lower machine-async-outcome-authentication (activation capacity)
wrela-machine-lower machine-async-outcome-authentication (activation plan)
wrela-machine-lower machine-async-outcome-authentication (activation region)
wrela-machine-lower machine-async-outcome-authentication (activation type)
wrela-machine-lower machine-async-outcome-authentication (authority source)
wrela-machine-lower machine-async-outcome-authentication (call and suspend)
wrela-machine-lower machine-async-outcome-authentication (callee)
wrela-machine-lower machine-async-outcome-authentication (caller entry)
wrela-machine-lower machine-async-outcome-authentication (caller)
wrela-machine-lower machine-async-outcome-authentication (canonical tag type)
wrela-machine-lower machine-async-outcome-authentication (cleanup proof)
wrela-machine-lower machine-async-outcome-authentication (core-zero scheduler)
wrela-machine-lower machine-async-outcome-authentication (direct-is tag)
wrela-machine-lower machine-async-outcome-authentication (exact nominal type graph)
wrela-machine-lower machine-async-outcome-authentication (proof authority)
wrela-machine-lower machine-async-outcome-authentication (region alignment)
wrela-machine-lower machine-async-outcome-authentication (single activation)
wrela-machine-lower machine-async-outcome-authentication (single actor)
wrela-machine-lower machine-async-outcome-authentication (single call)
wrela-machine-lower machine-async-outcome-authentication (single suspend)
wrela-machine-lower machine-async-outcome-authentication (single task)
wrela-machine-lower machine-async-outcome-consumer-pending (nested AsyncExit match)
wrela-machine-lower machine-async-outcome-consumer-pending (non-immediate direct is)
wrela-machine-lower machine-async-outcome-lowering-pending (scheduler cancellation and deadline delivery)
wrela-machine-lower machine-async-result-delivery-pending
wrela-machine-lower machine-bounded-string-lowering-pending (runtime storage and formatting ABI)
wrela-machine-lower machine-enum-nominal-payload-lowering-pending (flat-structure enum payload)
wrela-machine-lower machine-flat-structure-construction-lowering-pending
wrela-machine-lower machine-flat-structure-extraction-lowering-pending
wrela-machine-lower machine-flat-structure-field-update-lowering-pending
wrela-machine-lower machine-flat-structure-function-boundary-lowering-pending
wrela-machine-lower machine-flat-structure-operation-lowering-pending
wrela-machine-lower machine-flat-structure-type-lowering-pending
wrela-machine-lower machine-generated-cleanup-boundary-authentication
wrela-machine-lower machine-region-reset-lowering-pending (only exact completed immediate activation frames are admitted)
wrela-machine-lower machine-static-bytes-lowering-pending (runtime byte storage and consumer ABI)
wrela-machine-lower machine-structured-scope-activation-boundary-authentication
wrela-machine-lower machine-supervision-policy-lowering-pending (nested actor parents)
wrela-semantic-lower semantic-actor-reply-control-flow-pending
wrela-semantic-lower semantic-actor-reply-missing-return
wrela-semantic-lower semantic-actor-reply-payload-pending
wrela-semantic-lower semantic-actor-reply-receiver-pending
wrela-semantic-lower semantic-actor-reply-return-shape
wrela-semantic-lower semantic-admission-result-lowering-pending (try-send outcome dispatch)
wrela-semantic-lower semantic-async-outcome-authentication (AsyncExit declaration)
wrela-semantic-lower semantic-async-outcome-authentication (AsyncExit enumeration)
wrela-semantic-lower semantic-async-outcome-authentication (AsyncExit generic)
wrela-semantic-lower semantic-async-outcome-authentication (AsyncExit identity)
wrela-semantic-lower semantic-async-outcome-authentication (AsyncExit lowering payloads)
wrela-semantic-lower semantic-async-outcome-authentication (AsyncExit lowering type)
wrela-semantic-lower semantic-async-outcome-authentication (AsyncExit lowering variants)
wrela-semantic-lower semantic-async-outcome-authentication (AsyncExit payload)
wrela-semantic-lower semantic-async-outcome-authentication (AsyncExit source payload)
wrela-semantic-lower semantic-async-outcome-authentication (AsyncExit source)
wrela-semantic-lower semantic-async-outcome-authentication (AsyncExit type)
wrela-semantic-lower semantic-async-outcome-authentication (AsyncExit variant identity)
wrela-semantic-lower semantic-async-outcome-authentication (Result declaration)
wrela-semantic-lower semantic-async-outcome-authentication (Result source)
wrela-semantic-lower semantic-async-outcome-authentication (await producer)
wrela-semantic-lower semantic-async-outcome-authentication (await source)
wrela-semantic-lower semantic-async-outcome-authentication (await syntax)
wrela-semantic-lower semantic-async-outcome-authentication (cause module)
wrela-semantic-lower semantic-async-outcome-authentication (cause source type)
wrela-semantic-lower semantic-async-outcome-authentication (cause source)
wrela-semantic-lower semantic-async-outcome-authentication (cause type)
wrela-semantic-lower semantic-async-outcome-authentication (core package)
wrela-semantic-lower semantic-async-outcome-authentication (core.actor module)
wrela-semantic-lower semantic-async-outcome-authentication (declared Result identity)
wrela-semantic-lower semantic-async-outcome-authentication (declared Result)
wrela-semantic-lower semantic-async-outcome-authentication (declared type)
wrela-semantic-lower semantic-async-outcome-authentication (direct callee)
wrela-semantic-lower semantic-async-outcome-authentication (direct nullary async helper)
wrela-semantic-lower semantic-async-outcome-authentication (distinct cause identities)
wrela-semantic-lower semantic-async-outcome-authentication (effective Result identity)
wrela-semantic-lower semantic-async-outcome-authentication (effective Result)
wrela-semantic-lower semantic-async-outcome-authentication (effective arguments)
wrela-semantic-lower semantic-async-outcome-authentication (effective lowering arguments)
wrela-semantic-lower semantic-async-outcome-authentication (effective lowering identity)
wrela-semantic-lower semantic-async-outcome-authentication (effective lowering type)
wrela-semantic-lower semantic-async-outcome-authentication (effective type)
wrela-semantic-lower semantic-async-outcome-authentication (immediate match or is consumer)
wrela-semantic-lower semantic-async-outcome-authentication (non-actor direct call)
wrela-semantic-lower semantic-async-outcome-authentication (operation error payload)
wrela-semantic-lower semantic-async-outcome-authentication (proof authority)
wrela-semantic-lower semantic-async-outcome-authentication (sealed cause identity)
wrela-semantic-lower semantic-async-outcome-authentication (u64 payload)
wrela-semantic-lower semantic-async-outcome-lowering-pending (structured async exit delivery)
wrela-semantic-lower semantic-enum-heterogeneous-lowering-pending (per-variant differing scalar enum payloads)
wrela-semantic-lower semantic-enum-nominal-payload-lowering-pending (flat-struct or nongeneric-enum nominal enum payloads)
wrela-semantic-lower semantic-fixed-array-type-lowering-pending (noncanonical or non-scalar array)
wrela-semantic-lower semantic-for-array-abnormal-control-lowering-pending (lowered early exit)
wrela-semantic-lower semantic-for-array-abnormal-control-lowering-pending (return, break, or continue)
wrela-semantic-lower semantic-for-array-suspension-lowering-pending (await in loop body)
wrela-semantic-lower semantic-for-range-abnormal-control-lowering-pending (lowered early exit)
wrela-semantic-lower semantic-for-range-abnormal-control-lowering-pending (return, break, or continue)
wrela-semantic-lower semantic-for-range-suspension-lowering-pending (await in loop body)
wrela-semantic-lower semantic-generic-function-argument-lowering-pending (non-type or non-scalar specialization)
wrela-semantic-lower semantic-generic-function-kind-lowering-pending (methods, interfaces, async, or generated specialization)
wrela-semantic-lower semantic-generic-function-parameter-lowering-pending (const, region, bounded, or unauthenticated specialization)
wrela-semantic-lower semantic-generic-function-signature-lowering-pending (unsupported or unauthenticated substitution)
wrela-semantic-lower semantic-generic-structure-argument-lowering-pending (non-type or non-scalar specialization)
wrela-semantic-lower semantic-generic-structure-parameter-lowering-pending (const, bounded, or unauthenticated specialization)
wrela-semantic-lower semantic-match-alternative-guard-fallback-lowering-pending
wrela-semantic-lower semantic-match-alternative-wildcard-lowering-pending
wrela-semantic-lower semantic-match-multiple-alternative-groups-lowering-pending
wrela-semantic-lower semantic-match-wildcard-guard-fallback-lowering-pending (guarded variant requires an explicit unguarded cover before the catch-all)
wrela-semantic-lower semantic-method-call-argument-lowering-pending (mutate or take argument)
wrela-semantic-lower semantic-method-call-receiver-lowering-pending (mutate or take receiver)
wrela-semantic-lower semantic-projection-lowering-pending (outside generated read-only scalar projection subset)
wrela-semantic-lower semantic-projection-lowering-pending (projection activation outside authenticated context)
wrela-semantic-lower semantic-projection-lowering-pending (projection protocols in actor images)
wrela-semantic-lower semantic-projection-lowering-pending (projection protocols)
wrela-flow-lower semantic-region-reset-lowering-pending (only exact completed immediate activation frames are admitted)
wrela-semantic-lower semantic-runtime-field-assignment-projection-pending
wrela-semantic-lower semantic-runtime-field-compound-assignment-pending
wrela-semantic-lower semantic-scope-cleanup-form-lowering-pending (non-pass scope phase)
wrela-semantic-lower semantic-scope-cleanup-helper-key-collision
wrela-semantic-lower semantic-scope-enter-lowering-pending (nested or parameter state field)
wrela-semantic-lower semantic-scope-enter-lowering-pending (non-aggregate state)
wrela-semantic-lower semantic-scope-enter-lowering-pending (non-scalar state field)
wrela-semantic-lower semantic-scope-parameter-lowering-pending (parameterized acquisition)
wrela-semantic-lower semantic-scope-protocol-lowering-pending (multiple scope protocols)
wrela-semantic-lower semantic-with-abnormal-cleanup-lowering-pending (await, failure, or question exit)
wrela-semantic-lower semantic-with-abnormal-cleanup-lowering-pending (scope abort phase)
wrela-semantic-lower semantic-with-cleanup-lowering-pending (scope protocols and activations in generated tests)
wrela-semantic-lower semantic-with-cleanup-lowering-pending (scope protocols and activations)
wrela-semantic-lower semantic-with-owner-lowering-pending (non-actor source function)
wrela-semantic-lower semantic-with-region-lowering-pending (branded scope region)
```
<!-- refusal-tag-index: named end -->

## Prose reasons

<!-- refusal-tag-index: prose begin -->
```text
wrela-machine-lower Flow operations or nonempty control flow
wrela-flow-lower FlowWir cleanup helper identity
wrela-flow-lower FlowWir committed scope identity
wrela-flow-lower FlowWir duplicate scope enter
wrela-flow-lower FlowWir entered scope identity
wrela-flow-lower FlowWir exited scope identity
wrela-flow-lower FlowWir function returns with an active scope
wrela-flow-lower FlowWir loop control with an active scope
wrela-flow-lower FlowWir scope commit state
wrela-flow-lower FlowWir scope exit without commit
wrela-machine-lower a FIFO activation without actor ownership
wrela-machine-lower a FlowWir image closure without reachable typed effect authority
wrela-machine-lower a binary operation with an unknown type
wrela-machine-lower a binary operation with differing operand types
wrela-machine-lower a bit-and operation on an unsupported type
wrela-machine-lower a bool immediate with a non-bool result
wrela-machine-lower a byte immediate outside a generated test frame
wrela-machine-lower a call with multiple results
wrela-machine-lower a checked conversion on non-numeric scalars
wrela-machine-lower a checked integer operation on a non-integer type
wrela-machine-lower a checked integer operation with a mismatched result type
wrela-machine-lower a closed enum without the canonical u8 tag type
wrela-machine-lower a comparison on a non-scalar value
wrela-machine-lower a comparison with a non-bool result
wrela-machine-lower a copy with mismatched value types
wrela-machine-lower a cyclic, forward, or noncanonical FlowWir proof dependency
wrela-machine-lower a direct call to the UEFI image entry
wrela-machine-lower a field extraction with an invalid field or result type
wrela-machine-lower a field extraction with mismatched result type
wrela-machine-lower a first-class function-typed scalar value
wrela-machine-lower a fixed array with an unknown element type
wrela-machine-lower a fixed-array index without an exact array type
wrela-machine-lower a fixed-array index without exact stack storage
wrela-machine-lower a fixed-array index without exact storage
wrela-machine-lower a flat aggregate with an unknown field type
wrela-machine-lower a float32 immediate with a different result type
wrela-machine-lower a float64 immediate with a different result type
wrela-machine-lower a function returning unit without a unit type
wrela-machine-lower a function-address immediate with a non-address result
wrela-machine-lower a generated image-entry status allocation that is not canonical
wrela-machine-lower a generated test harness without frames, one finish, and executable tests
wrela-machine-lower a missing image entry
wrela-machine-lower a non-UTF-8 generated identifier
wrela-machine-lower a non-adjacent actor unit commit
wrela-machine-lower a non-checked integer operation
wrela-machine-lower a non-comparison floating operation
wrela-machine-lower a non-comparison signed operation
wrela-machine-lower a non-comparison unsigned operation
wrela-machine-lower a non-dense FlowWir proof graph
wrela-machine-lower a non-dense actor region storage global
wrela-machine-lower a non-dense actor region storage section
wrela-machine-lower a non-dense actor region storage symbol
wrela-machine-lower a non-dense actor region storage type
wrela-machine-lower a non-dense actor storage byte type
wrela-machine-lower a non-dense assertion payload global
wrela-machine-lower a non-dense assertion storage type
wrela-machine-lower a non-enum tagged representation
wrela-machine-lower a non-wrapping arithmetic operation
wrela-machine-lower a noncanonical closed enum type
wrela-machine-lower a noncanonical enum construction
wrela-machine-lower a noncanonical enum variant shape
wrela-machine-lower a noncanonical generated TestEmit block allocation
wrela-machine-lower a noncanonical generated TestEmit block expansion
wrela-machine-lower a noncanonical generated TestEmit control-flow expansion
wrela-machine-lower a noncanonical static actor region identity
wrela-machine-lower a planned test payload that changed shape
wrela-machine-lower a planned test payload with an unknown block
wrela-machine-lower a planned test payload with an unknown definition
wrela-machine-lower a planned test payload with an unknown function
wrela-machine-lower a result-bearing side-effect operation
wrela-machine-lower a returning or nonterminal generated test finish
wrela-machine-lower a runtime assertion outside one selected generated source-test closure
wrela-machine-lower a scalar conversion that is not universally lossless
wrela-machine-lower a scalar conversion whose result differs from its destination
wrela-machine-lower a scalar tail call without an exact synchronous callee
wrela-machine-lower a static test payload without exactly one address result
wrela-machine-lower a substituted actor region capacity proof
wrela-machine-lower a substituted actor region name or capacity
wrela-machine-lower a substituted generated test payload
wrela-machine-lower a substituted image-wired actor capability
wrela-machine-lower a substituted machine actor commit
wrela-machine-lower a substituted machine actor reply request
wrela-machine-lower a substituted machine actor reply resolve
wrela-machine-lower a substituted machine actor reservation
wrela-machine-lower a substituted machine mailbox receive
wrela-machine-lower a substituted one-shot mailbox turn
wrela-machine-lower a substituted or duplicate actor mailbox receive
wrela-machine-lower a substituted or duplicate actor reply resolve
wrela-machine-lower a tail call from the UEFI image entry
wrela-machine-lower a tail call involving the UEFI image entry
wrela-machine-lower a test emission outside block expansion
wrela-machine-lower a test finish without an exact generated-harness u32 outcome
wrela-machine-lower a test payload consumed by more than one emission
wrela-machine-lower a test payload in an unknown function
wrela-machine-lower a test payload that is not a static byte-array immediate
wrela-machine-lower a test payload that is not exclusively consumed by its adjacent emission
wrela-machine-lower a test payload whose type is not a byte array
wrela-machine-lower a test payload with an unknown array type
wrela-machine-lower a test payload with an unknown element type
wrela-machine-lower a test payload with an unknown value
wrela-machine-lower a test payload without an immediately preceding static definition
wrela-machine-lower a test payload without the exact static unsigned-byte-array type
wrela-machine-lower a type outside scalar lowering
wrela-machine-lower a unary operation on an incompatible scalar type
wrela-machine-lower a unary operation whose result type differs from its operand
wrela-machine-lower a unit immediate without an exact zero-sized unit result
wrela-machine-lower a wrapping operation on a non-integer type
wrela-semantic-lower actor activation call-site substitution
wrela-flow-lower actor activation callee identity
wrela-flow-lower,wrela-semantic-lower actor activation caller identity
wrela-machine-lower actor activation images outside the exact one-actor or image-wired two-actor plan
wrela-machine-lower actor activation images with exactly one static task
wrela-flow-lower actor activation region identity
wrela-flow-lower actor activation result type identity
wrela-semantic-lower actor and task entry identity aliasing
wrela-semantic-lower actor await type, effect, or proof substitution
wrela-semantic-lower actor base closed-image proof
wrela-semantic-lower actor base closed-image proof substitution
wrela-flow-lower actor bounded string construction type
wrela-flow-lower actor bounded string result arity
wrela-flow-lower actor branch scope state drift
wrela-semantic-lower actor calls outside closed ordinary helper functions
wrela-flow-lower actor capability result arity
wrela-flow-lower actor capability target
wrela-compiler,wrela-semantic-lower actor capacity proof or region substitution
wrela-semantic-lower actor class state declaration
wrela-semantic-lower actor class state identity
wrela-compiler,wrela-semantic-lower actor closed-image proof substitution
wrela-flow-lower actor committed scope identity
wrela-flow-lower actor control flow changed after shape validation
wrela-flow-lower actor copy result arity
wrela-flow-lower actor copy type
wrela-flow-lower actor entered scope identity
wrela-compiler,wrela-semantic-lower actor entry omits a capacity proof
wrela-semantic-lower actor entry without its receiver
wrela-flow-lower actor exited scope identity
wrela-compiler,wrela-semantic-lower actor function ownership proof substitution
wrela-flow-lower actor functions outside the scalar/call/await slice
wrela-semantic-lower actor graphs outside the stateless app/service and static-task slice
wrela-flow-lower actor image closure proof
wrela-semantic-lower actor image entry effect or proof substitution
wrela-flow-lower,wrela-semantic-lower actor image entry identity
wrela-flow-lower actor image entry origin
wrela-compiler,wrela-semantic-lower actor image static or peak capacity substitution
wrela-compiler,wrela-semantic-lower actor images compiled as declared scenarios
wrela-compiler actor images compiled as generated test harnesses
wrela-flow-lower actor images outside the stateless actor/task/region plan slice
wrela-semantic-lower actor images with generated test harnesses
wrela-compiler actor images without canonical unit
wrela-semantic-lower actor images without the canonical unit type
wrela-flow-lower actor mailbox region identity
wrela-machine-lower actor message payload lowering
wrela-semantic-lower actor message type substitution
wrela-flow-lower actor no-phi branch contract
wrela-flow-lower actor non-fallthrough source region
wrela-flow-lower actor operation changed after shape validation
wrela-flow-lower actor parent scope identity
wrela-flow-lower actor primitive type changed after validation
wrela-machine-lower actor region storage outside the exact actor plan
wrela-machine-lower actor region storage without exact static and peak closure
wrela-machine-lower actor region storage without its canonical byte type
wrela-machine-lower actor region storage without one task
wrela-semantic-lower actor reply exactly-once proof
wrela-semantic-lower actor reply mailbox proof
wrela-semantic-lower actor reply permit
wrela-flow-lower actor reply request result
wrela-semantic-lower actor reply request source
wrela-semantic-lower actor reply result type
wrela-semantic-lower actor reply result value
wrela-semantic-lower actor reply target identity
wrela-machine-lower actor reservations without an exact mailbox dispatch lowering
wrela-semantic-lower actor runtime enum semantic facts differ from source
wrela-flow-lower actor runtime operation without exact FlowWir lowering
wrela-semantic-lower actor runtime structure semantic facts differ from source
wrela-flow-lower actor scalar call arguments
wrela-flow-lower actor scalar call results
wrela-flow-lower actor scalar call target
wrela-flow-lower actor scalar constant result arity
wrela-flow-lower actor scalar constant result type
wrela-flow-lower actor scalar constant type
wrela-flow-lower actor scope activation census
wrela-flow-lower actor scope cleanup dependency order
wrela-flow-lower actor scope commit marker
wrela-flow-lower actor scope enter marker
wrela-flow-lower actor scope exit marker
wrela-flow-lower actor scope state aggregate result
wrela-flow-lower actor scope state aggregate shape
wrela-flow-lower actor scope state aggregate type
wrela-flow-lower actor source parameter identity
wrela-flow-lower actor source region parameters or depth
wrela-flow-lower actor source return
wrela-flow-lower actor source root terminator
wrela-flow-lower actor source value identity
wrela-flow-lower actor state address type
wrela-compiler actor state capacity proof substitution
wrela-semantic-lower actor state declaration outside the sealed zero-u64 subset
wrela-flow-lower actor state load authentication
wrela-flow-lower actor state load result
wrela-flow-lower actor state promotion authentication
wrela-flow-lower actor state promotion owner
wrela-flow-lower actor state promotion result
wrela-flow-lower actor state promotion source
wrela-flow-lower actor state region identity
wrela-semantic-lower actor state region substitution
wrela-flow-lower actor state store authentication
wrela-flow-lower actor state store result
wrela-flow-lower actor statements after terminator
wrela-compiler actor suspension or cleanup proof substitution
wrela-flow-lower actor task entry identity
wrela-flow-lower actor task-frame region identity
wrela-semantic-lower actor turn frame identity
wrela-semantic-lower actor turn relation substitution
wrela-flow-lower actor turn-frame function identity
wrela-flow-lower actor turn-frame region identity
wrela-flow-lower actor type changed after shape validation
wrela-flow-lower actor types outside the stateless scalar slice
wrela-semantic-lower actor types outside the validated scalar subset
wrela-compiler,wrela-semantic-lower actor wait-graph proof substitution
wrela-machine-lower actor, task, or interrupt functions
wrela-machine-lower aggregate, handle, or target-defined scalar types
wrela-machine-lower aggregate, ownership, runtime, device, async, or test operations
wrela-flow-lower ambiguous image-wired actor capability target
wrela-semantic-lower ambiguous image-wired actor capability type
wrela-machine-lower an activation call absent from its caller
wrela-machine-lower an activation caller outside actor/task authority
wrela-machine-lower an activation caller without an async call
wrela-machine-lower an activation caller without its async call
wrela-machine-lower an activation caller without one entry and resume block
wrela-machine-lower an activation capacity proof without one cleanup dependency
wrela-machine-lower an activation frame alignment outside machine range
wrela-machine-lower an activation plan used by multiple async calls
wrela-machine-lower an activation with an unknown callee
wrela-machine-lower an activation with an unknown caller
wrela-machine-lower an activation with an unknown capacity proof
wrela-machine-lower an activation with an unknown cleanup proof
wrela-machine-lower an activation with an unknown frame region
wrela-machine-lower an actor activation-frame region without a plan
wrela-machine-lower an actor admission without exact target and capacity authority
wrela-machine-lower an actor commit without its exact reserve
wrela-machine-lower an actor dispatch without mailbox storage
wrela-machine-lower an actor image closure with ambiguous base capacity authority
wrela-machine-lower an actor image closure with substituted activation capacity authority
wrela-machine-lower an actor image closure without base capacity authority
wrela-machine-lower an actor image closure without exact activation authority
wrela-machine-lower an actor image closure without its exact static byte bound
wrela-machine-lower an actor region alignment outside the machine domain
wrela-machine-lower an actor region capacity proof without one source
wrela-machine-lower an actor region with an unknown capacity proof
wrela-machine-lower an actor reply request with the wrong result type
wrela-machine-lower an actor reply request without exact target and proof authority
wrela-machine-lower an actor reply request without one result
wrela-machine-lower an actor reply request without one u64 result
wrela-machine-lower an actor reply resolve outside its actor turn
wrela-machine-lower an actor reply resolve with a non-u64 outcome
wrela-machine-lower an actor reply resolve without reply authority
wrela-machine-lower an actor reservation with the wrong result type
wrela-machine-lower an actor reservation without its adjacent unit commit
wrela-machine-lower an actor reservation without one strict-linear result
wrela-machine-lower an actor state address with a non-address result
wrela-machine-lower an actor-state promotion outside its turn
wrela-machine-lower an aggregate constructor outside flat u64 lowering
wrela-machine-lower an aggregate constructor with a mismatched result type
wrela-machine-lower an aggregate constructor with mismatched field or result types
wrela-machine-lower an aggregate constructor with mismatched fields
wrela-machine-lower an aggregate constructor without exactly one field value
wrela-machine-lower an array constructor with mismatched element or result types
wrela-machine-lower an array type outside generated static test payloads
wrela-machine-lower an array with an unknown element type
wrela-machine-lower an assertion without sealed expression storage
wrela-machine-lower an assertion without sealed message storage
wrela-machine-lower an async call result without activation type
wrela-machine-lower an async call with an unknown activation token
wrela-machine-lower an async call with an unknown resume block
wrela-machine-lower an async call without its exact suspend edge
wrela-machine-lower an async call without one strict-linear token
wrela-machine-lower an asynchronous call outside immediate activation lowering
wrela-machine-lower an asynchronous call without an exact scheduler/runtime lowering
wrela-machine-lower an asynchronous, interrupt, or trapping scalar terminator
wrela-machine-lower an effectful zero-sized unit definition outside a direct call
wrela-machine-lower an empty FlowWir function table
wrela-machine-lower an entry block with block parameters
wrela-machine-lower an enum construction with mismatched tag or payload
wrela-machine-lower an enum construction without a valid enum variant
wrela-machine-lower an enum exceeding 256 variants
wrela-machine-lower an enum payload projection with mismatched types
wrela-machine-lower an enum tag projection with mismatched types
wrela-machine-lower an enum with an unknown logical payload type
wrela-machine-lower an enum with an unknown payload type
wrela-machine-lower an erased non-unit operation with results
wrela-machine-lower an erased zero-sized value in a retained MachineWir operation
wrela-machine-lower an exact final FlowWir image-closure root
wrela-machine-lower an executable unit-message actor without one mailbox slot
wrela-machine-lower an illegal scalar bitcast
wrela-machine-lower an image entry return value
wrela-machine-lower an image entry with source parameters or return values
wrela-machine-lower an image-wired startup activation message shape
wrela-machine-lower an immediate outside scalar lowering
wrela-machine-lower an immediate with an unknown result type
wrela-machine-lower an incomplete actor reserve, commit, and receive chain
wrela-machine-lower an integer immediate whose width differs from its result
wrela-machine-lower an invalid UTF-8 chunk boundary
wrela-machine-lower an invalid generated decimal digit
wrela-machine-lower an operation on a non-scalar type
wrela-machine-lower an operation outside scalar lowering
wrela-machine-lower an operation without exactly one result
wrela-machine-lower an ordinary scalar call without an exact synchronous callee
wrela-machine-lower an unauthenticated actor state address
wrela-machine-lower an unauthenticated actor-state promotion
wrela-machine-lower an unauthenticated fixed-array index
wrela-machine-lower an unknown FlowWir value
wrela-machine-lower an unknown FlowWir value during value erasure
wrela-machine-lower an unknown FlowWir value type
wrela-machine-lower an unknown actor turn-frame owner
wrela-machine-lower an unknown indexed test payload
wrela-machine-lower an unknown retained FlowWir value
wrela-machine-lower an unnamed canonical unit type
wrela-machine-lower an unplanned generated test emission
wrela-machine-lower an unplanned static test payload
wrela-semantic-lower anonymous actor runtime enums
wrela-semantic-lower anonymous closed runtime enums
wrela-semantic-lower anonymous flat actor runtime structures
wrela-semantic-lower anonymous flat runtime structures
wrela-machine-lower assertion payload without its sealed storage type
wrela-machine-lower assertion storage without a byte type
wrela-machine-lower async activation values without an exact scheduler/runtime lowering
wrela-semantic-lower async actor activation callee
wrela-semantic-lower async actor activation cleanup proof
wrela-semantic-lower async actor activation without source provenance
wrela-semantic-lower async actor calls without an immediate await
wrela-semantic-lower async actor suspension or cleanup proof substitution
wrela-flow-lower async await result delivery
wrela-flow-lower async call activation identity
wrela-flow-lower async call activation result
wrela-flow-lower async call activation type
wrela-flow-lower async call result type identity
wrela-flow-lower async call without activation plan
wrela-semantic-lower async helper calls outside actor turns and static tasks
wrela-flow-lower async-outcome producer variant range
wrela-machine-lower asynchronous or interrupt-colored functions without an exact runtime lowering
wrela-semantic-lower await fact substitution
wrela-semantic-lower await facts outside async actor functions
wrela-semantic-lower baked artifacts
wrela-semantic-lower baked artifacts in actor images
wrela-semantic-lower baked artifacts in generated tests
wrela-flow-lower bit-and scalar binary type contract
wrela-flow-lower bounded string construction type
wrela-flow-lower bounded string result arity
wrela-semantic-lower branch-local semantic value escape
wrela-semantic-lower calls outside reachable ordinary scalar helpers
wrela-flow-lower canonical enum match arm
wrela-flow-lower checked conversion requires numeric scalar types
wrela-machine-lower checked integer negation without an explicit trap edge
wrela-flow-lower closed enum constructor payload
wrela-flow-lower closed enum constructor type
wrela-flow-lower closed enum result arity
wrela-compiler compiled test metadata in actor images
wrela-machine-lower compiler-only test intrinsics in a non-test image
wrela-machine-lower control-flow graphs other than one empty block
wrela-semantic-lower cyclic actor wait graph with an acyclicity proof
wrela-compiler declared image as a generated test harness
wrela-semantic-lower declared images as generated test harnesses
wrela-compiler declared scenarios in a generated harness
wrela-semantic-lower declared scenarios in a generated test harness
wrela-semantic-lower duplicated actor await activation
wrela-flow-lower enum match canonical u8 tag type
wrela-flow-lower enum match exhaustiveness
wrela-flow-lower enum match payload binding
wrela-flow-lower enum match scrutinee type
wrela-flow-lower enum match scrutinee value
wrela-flow-lower enum match variant range
wrela-flow-lower enum match variant type
wrela-flow-lower enum match wildcard binding
wrela-flow-lower enum match wildcard binding coverage
wrela-flow-lower enum match wildcard binding type
wrela-flow-lower enum match wildcard uniqueness
wrela-flow-lower enum variant exceeds canonical u8 tag
wrela-flow-lower field insertion aggregate
wrela-flow-lower field insertion field
wrela-flow-lower field insertion result arity
wrela-flow-lower field insertion type
wrela-flow-lower fixed-array aggregate arity
wrela-flow-lower fixed-array aggregate element type
wrela-semantic-lower fixed-array element type is outside the semantic type table
wrela-flow-lower fixed-array index authentication
wrela-flow-lower fixed-array index base
wrela-flow-lower fixed-array index result arity
wrela-flow-lower fixed-array pattern binding order
wrela-flow-lower fixed-array pattern binding provenance
wrela-flow-lower fixed-array pattern branch condition
wrela-flow-lower fixed-array pattern branch cycle
wrela-flow-lower fixed-array pattern branch-local binding
wrela-flow-lower fixed-array pattern duplicate arm position
wrela-flow-lower fixed-array pattern equality definition
wrela-flow-lower fixed-array pattern equality result
wrela-flow-lower fixed-array pattern equality type
wrela-flow-lower fixed-array pattern exact position constant
wrela-flow-lower fixed-array pattern has no positional extraction
wrela-flow-lower fixed-array pattern index result
wrela-flow-lower fixed-array pattern inline aggregate
wrela-flow-lower fixed-array pattern inline element definition
wrela-flow-lower fixed-array pattern inline literal aggregate
wrela-flow-lower fixed-array pattern irrefutable binding prefix
wrela-flow-lower fixed-array pattern irrefutable binding region
wrela-flow-lower fixed-array pattern left fold order
wrela-flow-lower fixed-array pattern literal comparison
wrela-flow-lower fixed-array pattern literal definition
wrela-flow-lower fixed-array pattern literal fold
wrela-flow-lower fixed-array pattern literal fold result
wrela-flow-lower fixed-array pattern literal result
wrela-flow-lower fixed-array pattern position definition
wrela-flow-lower fixed-array pattern positional extraction
wrela-flow-lower fixed-array pattern proof authority
wrela-flow-lower fixed-array pattern proof extent
wrela-flow-lower fixed-array pattern proof identity
wrela-flow-lower fixed-array pattern result identity
wrela-flow-lower fixed-array pattern root branch
wrela-flow-lower fixed-array pattern single definition
wrela-flow-lower fixed-array pattern source position order
wrela-flow-lower fixed-array pattern source-ordered branch chain
wrela-flow-lower fixed-array pattern unique inline aggregate
wrela-flow-lower flat aggregate field type
wrela-flow-lower flat aggregate result arity
wrela-flow-lower flat aggregate result type
wrela-flow-lower flat aggregate type
wrela-flow-lower flat projection base
wrela-flow-lower flat projection field
wrela-flow-lower flat projection result arity
wrela-flow-lower flat projection type or access
wrela-flow-lower flow scope cleanup proof identity
wrela-flow-lower flow scope exit helper identity
wrela-machine-lower functions with multiple return values
wrela-compiler,wrela-semantic-lower generated functions outside the test harness
wrela-compiler generated harness as a declared image
wrela-flow-lower generated test assertion
wrela-flow-lower generated test bounded string types
wrela-flow-lower generated test closed enum types
wrela-flow-lower generated test enum payload type
wrela-flow-lower generated test event count
wrela-flow-lower generated test flat structure fields
wrela-flow-lower generated test flat structure types
wrela-flow-lower generated test frame constant
wrela-flow-lower generated test frame emission
wrela-flow-lower generated test frame identity
wrela-flow-lower generated test frame types
wrela-flow-lower generated test frame value
wrela-flow-lower generated test function identity
wrela-flow-lower generated test function role changed after validation
wrela-flow-lower generated test function selection
wrela-semantic-lower generated test functions
wrela-flow-lower generated test functions outside the synchronous scalar subset
wrela-compiler,wrela-semantic-lower generated test functions outside the synchronous zero-argument unit subset
wrela-flow-lower generated test harness
wrela-flow-lower generated test harness calls
wrela-flow-lower generated test harness origin
wrela-flow-lower generated test harness statement sequence
wrela-flow-lower generated test harness values
wrela-semantic-lower generated test harnesses
wrela-flow-lower generated test identity
wrela-flow-lower generated test operation changed after shape validation
wrela-flow-lower generated test outcome identity
wrela-flow-lower generated test primitive type
wrela-flow-lower generated test scalar function types
wrela-flow-lower generated test scalar types
wrela-flow-lower generated test source-function closure
wrela-flow-lower generated test statement count
wrela-flow-lower generated test static bytes types
wrela-flow-lower generated test static string types
wrela-flow-lower generated test terminal outcome
wrela-flow-lower generated test terminator
wrela-flow-lower generated test type table
wrela-flow-lower generated test types changed after validation
wrela-flow-lower generated test types outside the scalar subset
wrela-flow-lower generated test uninterrupted-work bound
wrela-flow-lower generated test unit type
wrela-flow-lower generated test value count
wrela-semantic-lower generated tests without the unit type
wrela-machine-lower global-address immediates
wrela-machine-lower globals, runtime plans, devices, checkpoints, or image memory
wrela-machine-lower globals, runtime plans, devices, checkpoints, or image memory in scalar lowering
wrela-compiler image owners outside the actor/task/pool slice
wrela-semantic-lower inline `if` elif chains in ordinary source lowering
wrela-semantic-lower integer constants wider than SemanticWir
wrela-flow-lower integer scalar binary type contract
wrela-machine-lower integer widths outside 8, 16, 32, 64, and 128 bits
wrela-compiler iso pool handle type is absent
wrela-compiler iso pool payloads outside flat structures
wrela-compiler iso pools outside ordinary declared images
wrela-flow-lower lossy scalar conversion without universally exact lowering
wrela-semantic-lower mailbox receive outside its actor turn
wrela-flow-lower mismatched scalar conversion result type
wrela-semantic-lower missing actor mailbox region
wrela-semantic-lower missing actor state region
wrela-semantic-lower missing actor turn-frame region
wrela-semantic-lower missing non-unit return value
wrela-semantic-lower missing task frame region
wrela-machine-lower more than one FlowWir image-closure root
wrela-semantic-lower more than one admitted startup message for one actor turn
wrela-machine-lower more than one machine actor mailbox
wrela-machine-lower more than one mailbox-capacity authority for an actor
wrela-machine-lower more than one per-core FIFO actor drain
wrela-machine-lower more than one recurring actor admission
wrela-semantic-lower more than one reply authority for one actor turn
wrela-machine-lower more than one single mailbox activation caller
wrela-machine-lower more than one startup activation caller
wrela-machine-lower more than one startup actor admission
wrela-semantic-lower multi-branch source if statements
wrela-flow-lower multi-slot task activation capacity
wrela-semantic-lower multi-target scalar assignment
wrela-semantic-lower multiple actor closed-image proofs
wrela-semantic-lower multiple actor wait-graph proofs
wrela-semantic-lower multiple async actor activation cleanup proofs
wrela-machine-lower multiple image-entry functions
wrela-machine-lower multiple or missing Flow functions
wrela-compiler,wrela-semantic-lower multiple runtime function instances
wrela-flow-lower multiple semantic function instances
wrela-semantic-lower multiple static supervision topology proofs
wrela-semantic-lower nested or preplanned async actor activation sites
wrela-semantic-lower nested static actor supervision topology
wrela-semantic-lower non-direct actor await operands
wrela-semantic-lower non-enum source declaration for actor runtime enum
wrela-semantic-lower non-enum source declaration for runtime enum
wrela-flow-lower non-fallthrough scalar source region
wrela-compiler,wrela-semantic-lower non-function actor source origins
wrela-semantic-lower non-function source origins
wrela-semantic-lower non-function source provenance
wrela-semantic-lower non-local scalar assignment
wrela-machine-lower non-minimum semantic source summaries
wrela-flow-lower non-minimum source and specialization summaries
wrela-flow-lower non-read scalar function type parameter
wrela-flow-lower non-scalar actor temporaries
wrela-semantic-lower non-scalar source constants
wrela-flow-lower non-scalar source operation
wrela-compiler,wrela-semantic-lower non-source functions in actor runtime closure
wrela-semantic-lower non-source functions selected as integration tests
wrela-semantic-lower non-source integration test bodies
wrela-semantic-lower non-source integration tests
wrela-semantic-lower non-structure source declaration for actor runtime structure
wrela-semantic-lower non-structure source declaration for runtime structure
wrela-semantic-lower non-unit source functions without an exact return
wrela-semantic-lower non-value scalar semantic values
wrela-flow-lower noncanonical actor activation capacity plan
wrela-semantic-lower noncanonical actor activation source order
wrela-compiler noncanonical actor capacity graph or owner order
wrela-semantic-lower noncanonical actor capacity regions
wrela-compiler,wrela-semantic-lower noncanonical actor class types
wrela-semantic-lower noncanonical actor function identity order
wrela-compiler noncanonical actor identity or owner order
wrela-flow-lower noncanonical actor image closure proof
wrela-flow-lower noncanonical actor mailbox capacity plan
wrela-flow-lower noncanonical actor mailbox/frame region plan
wrela-flow-lower noncanonical actor memory or ownership order
wrela-semantic-lower noncanonical actor node identity or ordering
wrela-semantic-lower noncanonical actor reply admission
wrela-flow-lower noncanonical actor reply request
wrela-flow-lower noncanonical actor reply resolve
wrela-semantic-lower noncanonical actor reservation type
wrela-semantic-lower noncanonical actor runtime enum semantic facts
wrela-semantic-lower noncanonical actor runtime structure semantic facts
wrela-compiler noncanonical actor source functions
wrela-semantic-lower noncanonical actor startup or shutdown order
wrela-flow-lower noncanonical actor state capacity plan
wrela-flow-lower noncanonical actor task-frame capacity plan
wrela-flow-lower noncanonical actor turn-frame capacity plan
wrela-semantic-lower noncanonical actor-owned receiver authority
wrela-machine-lower noncanonical assertion payload order
wrela-semantic-lower noncanonical bounded actor drain profile
wrela-semantic-lower noncanonical compiler-minted BoundedString type
wrela-semantic-lower noncanonical compiler-minted Static[Bytes[N]] type
wrela-semantic-lower noncanonical compiler-minted Static[Str] type
wrela-compiler noncanonical generated actor image entries
wrela-semantic-lower noncanonical generated actor image entry
wrela-compiler,wrela-flow-lower,wrela-semantic-lower noncanonical generated image entries
wrela-machine-lower noncanonical generated passing test lifecycle frames
wrela-compiler noncanonical generated pool image entry
wrela-machine-lower noncanonical generated synchronous image entries
wrela-flow-lower noncanonical generated test harness
wrela-compiler,wrela-semantic-lower noncanonical generated test harness entry
wrela-flow-lower noncanonical image-wired actor capability
wrela-semantic-lower noncanonical image-wired actor capability type
wrela-compiler noncanonical iso pool image capacity or owner order
wrela-compiler noncanonical iso pool/brand/region contract
wrela-machine-lower noncanonical minimum image-entry provenance
wrela-compiler,wrela-flow-lower,wrela-semantic-lower noncanonical minimum-image proof sets
wrela-semantic-lower noncanonical one-way actor admission
wrela-flow-lower noncanonical one-way actor commit
wrela-flow-lower noncanonical one-way actor reservation
wrela-flow-lower noncanonical one-way mailbox receive
wrela-compiler noncanonical pool proof closure
wrela-semantic-lower noncanonical runtime enum semantic facts
wrela-semantic-lower noncanonical runtime structure semantic facts
wrela-semantic-lower noncanonical scalar integer identity
wrela-flow-lower noncanonical scalar unary operation
wrela-semantic-lower noncanonical source function identity order
wrela-flow-lower noncanonical stateless actor image entry
wrela-flow-lower noncanonical wrapping scalar binary operation
wrela-compiler,wrela-semantic-lower nonempty runtime image graphs
wrela-flow-lower nonempty runtime ownership or memory plans
wrela-flow-lower nonempty runtime ownership or memory plans in generated tests
wrela-flow-lower nonempty runtime plans, scopes, globals, or tests
wrela-flow-lower nonempty runtime plans, scopes, or globals in generated tests
wrela-semantic-lower nonterminal generated test harness identity
wrela-machine-lower nonzero scalar function stack or frame bounds
wrela-machine-lower one actor turn-frame owner
wrela-machine-lower one actor-turn and one startup-task activation
wrela-semantic-lower one-way actor admission proof
wrela-semantic-lower one-way actor drain has more than two edges
wrela-semantic-lower one-way actor identity
wrela-semantic-lower one-way actor mailbox capacity proof
wrela-flow-lower one-way actor message argument access
wrela-flow-lower one-way actor operation census
wrela-semantic-lower one-way actor producer identity
wrela-semantic-lower one-way actor request source
wrela-semantic-lower one-way actor reservation type
wrela-semantic-lower one-way actor reservation value
wrela-semantic-lower one-way actor turn target
wrela-flow-lower one-way reservation result arity
wrela-flow-lower one-way reservation type
wrela-semantic-lower one-way send payloads outside unit messages
wrela-semantic-lower one-way sends outside bounded actor producers
wrela-semantic-lower one-way task actor ownership
wrela-machine-lower optimizer-derived or noncanonical minimum Flow proofs
wrela-semantic-lower ordinary source expressions outside scalar bodies
wrela-semantic-lower ordinary source operations outside scalar bodies
wrela-compiler pool images with source runtime functions
wrela-machine-lower proof sets other than the minimum image proof set
wrela-flow-lower question match enum type
wrela-semantic-lower recursive actor helper calls
wrela-compiler,wrela-semantic-lower recursive scalar helper calls
wrela-machine-lower region storage outside actor activation lowering
wrela-flow-lower result match arm terminator
wrela-machine-lower runtime assertions require exactly one selected generated source test
wrela-semantic-lower runtime enum semantic facts differ from source
wrela-semantic-lower runtime enum semantic facts differ from source payload
wrela-semantic-lower runtime enum semantic facts differ from source payload shape
wrela-compiler runtime expressions outside bounded direct calls and flat structures
wrela-compiler runtime graphs outside the pool-only slice
wrela-compiler runtime graphs outside the stateless actor/task slice
wrela-compiler runtime images without canonical unit
wrela-compiler runtime statements outside bounded-value ownership state
wrela-semantic-lower runtime structure semantic facts differ from source
wrela-compiler runtime structures outside the bounded flat-value subset
wrela-compiler runtime types outside the bounded flat-value subset
wrela-compiler runtime values outside the bounded-value subset
wrela-flow-lower scalar binary operand type
wrela-flow-lower scalar binary result arity
wrela-flow-lower scalar binary result type
wrela-flow-lower scalar branch condition type
wrela-flow-lower scalar branch result type
wrela-flow-lower scalar branch yield arity or position
wrela-flow-lower scalar branch yield destination
wrela-flow-lower scalar branch yield position
wrela-flow-lower scalar branch yield terminator
wrela-flow-lower scalar branch yield type
wrela-flow-lower scalar call arguments
wrela-flow-lower scalar call results
wrela-flow-lower scalar call target
wrela-flow-lower scalar comparison operand contract
wrela-flow-lower scalar comparison type contract
wrela-flow-lower scalar constant result arity
wrela-flow-lower scalar constant result type
wrela-flow-lower scalar conversion destination type
wrela-flow-lower scalar conversion result arity
wrela-flow-lower scalar conversion source type
wrela-flow-lower scalar copy result arity
wrela-flow-lower scalar fallthrough region terminator
wrela-flow-lower scalar loop carried-value contract
wrela-flow-lower scalar loop carried-value type
wrela-flow-lower scalar loop control destination
wrela-flow-lower scalar loop control position
wrela-flow-lower scalar source region parameters or depth
wrela-flow-lower scalar source return
wrela-flow-lower scalar source root terminator
wrela-flow-lower scalar unary operand type
wrela-flow-lower scalar unary result arity
wrela-flow-lower scalar unary result type
wrela-machine-lower scheduler ownership beyond the exact core-zero partition
wrela-semantic-lower scope finite f32 constant
wrela-semantic-lower scope finite f64 constant
wrela-semantic-lower scope integer constant width
wrela-compiler scope protocols or baked artifacts
wrela-semantic-lower scope signed integer constant
wrela-semantic-lower scope state literal type
wrela-semantic-lower scope unsigned integer constant
wrela-flow-lower semantic operations or structured bodies
wrela-flow-lower,wrela-semantic-lower semantic type sets other than the minimum unit type
wrela-compiler semantic type sets other than unit
wrela-compiler,wrela-semantic-lower semantic types other than canonical unit
wrela-flow-lower,wrela-semantic-lower semantic types other than the canonical unit type
wrela-semantic-lower semantic types outside the bounded actor scalar subset
wrela-flow-lower source copy type
wrela-semantic-lower source executable bodies
wrela-semantic-lower source function bodies
wrela-flow-lower source function parameters outside scalar or flat structures
wrela-semantic-lower source function roles outside scalar, actor-turn, and static-task entries
wrela-flow-lower source function values outside scalar or flat structures
wrela-flow-lower source functions or generated test harnesses
wrela-compiler source functions outside selected tests and reachable bounded-value helpers
wrela-compiler source functions outside the synchronous bounded-value subset
wrela-flow-lower source functions outside the synchronous scalar or flat-structure subset
wrela-compiler source runtime bodies in declared images
wrela-semantic-lower source semantic types outside the scalar or flat-structure subset
wrela-semantic-lower source statements after return
wrela-flow-lower statements after a scalar source terminator
wrela-flow-lower statements after generated test terminator
wrela-semantic-lower static supervision topology proof substitution
wrela-semantic-lower static task supervision parent substitution
wrela-flow-lower stored fixed-array canonical loop identity
wrela-flow-lower stored fixed-array exact initializer
wrela-flow-lower stored fixed-array index result arity
wrela-flow-lower stored fixed-array literal aggregate
wrela-flow-lower stored fixed-array literal definition
wrela-flow-lower stored fixed-array loop condition
wrela-flow-lower stored fixed-array loop condition result
wrela-flow-lower stored fixed-array loop increment arity
wrela-flow-lower stored fixed-array loop increment suffix
wrela-flow-lower stored fixed-array loop length
wrela-flow-lower stored fixed-array loop source
wrela-flow-lower stored fixed-array loop start
wrela-flow-lower stored fixed-array proof authority
wrela-flow-lower stored fixed-array proof extent
wrela-flow-lower stored fixed-array proof identity
wrela-flow-lower stored fixed-array single canonical loop
wrela-flow-lower stored fixed-array unique capacity proof
wrela-flow-lower stored fixed-array unique indexed consumer
wrela-flow-lower stored fixed-array unique initializer
wrela-flow-lower stored fixed-array user body
wrela-flow-lower stored fixed-array user-body control flow
wrela-machine-lower substituted or non-passing compiler-generated test lifecycle frames
wrela-machine-lower suspending or trapping scalar control flow
wrela-flow-lower synchronous call with activation plan
wrela-flow-lower synchronous loop uninterrupted-work proof
wrela-semantic-lower task capacity proof or identity substitution
wrela-compiler task capacity proof or region substitution
wrela-semantic-lower task entry relation substitution
wrela-flow-lower terminal closed enum match contract
wrela-flow-lower terminal closed enum match coverage
wrela-semantic-lower test discovery facts in compiled test images
wrela-semantic-lower test discovery images
wrela-machine-lower test emission outside the generated image-entry harness
wrela-semantic-lower test metadata in actor images
wrela-compiler test-discovery facts in executable images
wrela-machine-lower the canonical actor state capacity proof
wrela-machine-lower the canonical actor state region
wrela-machine-lower the complete actor mailbox, root-frame, and activation-frame region set
wrela-machine-lower the exact actor activation-frame region
wrela-machine-lower the fixed actor turn-frame region
wrela-machine-lower the fixed client actor mailbox region
wrela-machine-lower the fixed scalar actor mailbox region
wrela-machine-lower the fixed task entry-frame region
wrela-machine-lower the one-actor, one-single-slot-task immediate activation contract
wrela-machine-lower the selected optimization policy is not implemented
wrela-machine-lower types other than the canonical unit type
wrela-compiler types outside the bounded actor scalar subset
wrela-semantic-lower unreachable or noncanonical actor source functions
wrela-semantic-lower unreachable or noncanonical scalar source functions
wrela-compiler unreachable scalar helper functions
wrela-flow-lower unregistered actor cleanup helper
```
<!-- refusal-tag-index: prose end -->

## Declared exclusions

Construction sites the source-based extractor cannot read, each with the reason
it is admitted anyway. The list is currently **empty**: every workspace site
reduces to literals. An entry that stops existing in source also fails the
check, so this block cannot go stale.

<!-- refusal-tag-index: exclusions begin -->
```text
```
<!-- refusal-tag-index: exclusions end -->
