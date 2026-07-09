# Lexing and `.wr` Source Consumption

- Status: proposed
- Scope: source ingestion, diagnostics foundations, lexical analysis, and compiler-repository hygiene
- Implementation status: no compiler implementation exists yet

# 1. Summary

This feature establishes the first executable stage of the Wrela compiler. A user will be able to
give the compiler one or more `.wr` source files, have each file read into an immutable source
manager, and have those sources converted in parallel into deterministic token streams with precise
source ranges and useful diagnostics. The lexer will implement the layout implied by the language
sketch: colon-oriented, indentation-delimited suites; `#` line comments; significant logical
newlines; and newline suppression inside `()` and `[]`.

The parser will receive no whitespace or comment trivia and no CST is required. Comments will not
be discarded irrecoverably, however. The preferred design records a bounded, zero-copy side index
of comment blocks and their neighboring tokens. This preserves documentation and future tooling
options without putting trivia in the parser's hot path or allowing comments to carry safety
semantics.

The lexical contract also reserves `use` and `from` and supports the future module spelling:

```wr
use PciAddress, PciIdentity from platform.pci
```

Loading the imported modules, resolving exports, and constructing the whole-image module graph are
later parser/resolver work. This feature recognizes the syntax and establishes the immutable
per-file/session boundaries, deterministic ordering, and local diagnostic buffers needed to lex a
future resolved module set in parallel. The initial `lex` CLI accepts one or more explicit roots;
the driver API is deliberately multi-file from its first version.

The repository is currently documentation-only. The design therefore also defines a clean C++23
foundation: target-scoped CMake, strict dependency boundaries, diagnostics independent of output
formatting, unit/integration/fuzz/benchmark test surfaces, sanitizers, format/lint configuration,
and an explicit boundary that keeps LLVM/MLIR out of the source and lexer libraries. LLVM remains
the intended backend, but no backend dependency is needed to read or lex Wrela.

# 2. Goals

1. Accept one regular root source path with the exact, case-sensitive `.wr` extension and preserve
   the bytes actually compiled in immutable owned storage.
2. Produce a deterministic token stream for the lexical forms evidenced by the language sketch,
   including identifiers, keywords, integer/string/byte literals, punctuation, operators, logical
   newlines, indentation, dedentation, and EOF.
3. Lex `use <names> from <module.path>` with `use` and `from` as reserved keywords while leaving
   module lookup and name resolution to later stages.
4. Drop whitespace and comments from the parser token stream while retaining comments in an
   optional bounded side index with no copied comment text.
5. Diagnose source I/O, encoding, layout, literal, delimiter, and invalid-character failures with
   stable source ranges; recover where useful; and never pass an erroneous or incomplete token
   stream to a future parser.
6. Guarantee forward progress and linear work in source size plus emitted tokens/comments, subject
   to explicit resource limits.
7. Avoid per-token lexeme allocation. Tokens must refer to immutable source through compact source
   IDs and half-open byte ranges.
8. Make source lifetime and ownership explicit so tokens, diagnostics, comments, and future AST
   nodes cannot retain dangling string views.
9. Lex the entire worked `docs/language/examples/virtio-appliance.wr` corpus and curated lexical
   fixtures drawn from `core-model.md` and `image-runtime.md` without lexical diagnostics. This is
   lexical coverage only; the sources remain aspirational and need not parse or type-check.
10. Support decimal and scientific floating-point literals, including optional explicit `f32`/`f64`
    suffixes, without confusing them with ranges, member access, or unit methods.
11. Make per-file lexing, comment indexing, and diagnostic collection safe to run in parallel while
    producing identical results and diagnostic ordering for one or many workers.
12. Create separable `Basic`, `Source`, `Diagnostics`, `Lex`, and `Driver` build targets that can be
    built and tested without LLVM or MLIR.
13. Establish automated unit, integration, sanitizer, fuzz, and benchmark coverage before later
    compiler phases depend on the source representation.
14. Leave a stable adapter boundary for later mapping Wrela source spans into MLIR/LLVM diagnostic
    and debug locations.

# 3. Non-Goals

- Parsing, AST construction, a CST, formatting, refactoring, or lossless round-tripping.
- Loading modules named by `use ... from ...`, resolving package roots, exports, aliases, wildcard
  imports, cycles, or visibility.
- Defining an `export` declaration. The language sketch mentions exports but provides no syntax.
- Semantic validation of declaration forms, including whether `abi` declarations are permitted in
  user modules.
- Type checking, arbitrary-precision evaluation of integer literals, unit-method resolution,
  ownership/effect/provenance analysis, monomorphization, runtime-graph construction, or code
  generation.
- LLVM, MLIR, target package, linker, object-file, or machine-code integration.
- Unicode identifiers or Unicode string values in V1. Source and comments may be UTF-8, but code
  identifiers and decoded literals are deliberately ASCII/byte-oriented in this design.
- Block comments, nested comments, doc-comment semantics, comment-based lint suppressions, or
  comment-based compiler directives.
- Standard input, editor overlays, incremental re-lexing, or filesystem watching. The in-memory
  source API should not prevent those later, but the first CLI consumes a file path.
- Restoring deleted historical scaffolding. Repository history is evidence, not an implementation
  to revive wholesale.

# 4. Current System Analysis

## 4.1 Current repository

The current repository has no compiler implementation. Its tracked content is the license, two
language documents, and one worked `.wr` example. There is no root build configuration, C++ source,
public API, CLI, dependency declaration, test suite, benchmark, CI configuration, or checked-in
EBNF. Consequently there is no current executable data flow, control flow, or API compatibility
surface to preserve.

The three language artifacts explicitly disclaim executable status:

- `docs/language/core-model.md:3-9` calls the model aspirational rather than current compiler input.
- `docs/language/image-runtime.md:3-10` repeats that status.
- `docs/language/examples/virtio-appliance.wr:1-8` says the worked source is not current compiler
  input.

`docs/language/core-model.md:936-942` says a versioned EBNF and deterministic resolution
specification will exist, but neither is present. This feature therefore cannot claim to implement
an existing formal grammar. The lexical choices in this design are the proposed V1 baseline and
must be written into an authoritative lexical reference before implementation is called conformant.

`docs/language/core-model.md:67` also refers to a now-absent `architecture.md`, while the worked
example's header still names pre-move `docs/core-model.md` and `docs/image-runtime.md` paths at
`docs/language/examples/virtio-appliance.wr:4-5`. Implementation documentation work must repair
these stale links rather than silently relying on deleted or moved documents.

## 4.2 Language evidence relevant to lexing

The source sketch is indentation-oriented:

- A declaration suite appears as `type PciAddress:` followed by indented fields at
  `docs/language/examples/virtio-appliance.wr:15-18`.
- `image WrelaOS:` and its `boot fn` suite appear at
  `docs/language/examples/virtio-appliance.wr:1026-1029`.
- Multiline calls and literals occur inside `()` and `[]`, including
  `docs/language/examples/virtio-appliance.wr:464-467`, `591-596`, and `1059-1072`.
- Inline suites also exist, such as `guard: require ... else: return` at
  `docs/language/examples/virtio-appliance.wr:819`; a colon cannot by itself force a following
  indentation token.

The only evidenced comment spelling is `#` through the physical end of line. Both whole-line
comments (`docs/language/examples/virtio-appliance.wr:1-13`) and trailing comments
(`docs/language/examples/virtio-appliance.wr:102-103`) occur. Comment-only and blank lines occur
inside suites. No `//`, `/* ... */`, doc-comment prefix, or block-comment nesting is specified.

Lexically relevant literal and operator evidence includes:

- Decimal, hexadecimal, and binary integers, with `_` separators in binary values, at
  `docs/language/examples/virtio-appliance.wr:40-43` and `60-66`.
- Core-model code examples add the evidenced compound assignment `-=` at
  `docs/language/core-model.md:1231`, alongside `+=` in both the core model and worked example.
- A lowercase typed suffix in `0_u8` at `docs/language/core-model.md:1182-1187`.
- Unit-member forms such as `4.MiB` and `1.ms`, specified as const method calls on integer literals
  at `docs/language/core-model.md:969-973`.
- Exact/contextual integer semantics at `docs/language/core-model.md:936-942`; machine-width
  conversion therefore belongs after lexing.
- `F32` and `F64` primitive types are present, although the sketch does not define literal syntax;
  target support for runtime floating point remains conditional at
  `docs/language/core-model.md:1078-1083`. This design adds lexical float spelling only and leaves
  target acceptance/type selection to semantic analysis.
- ASCII byte literal `b'\n'` and an explicit statement that other character/string encoding is
  outside V1 at `docs/language/core-model.md:1063-1068`.
- Immutable `StaticString` literal storage at `docs/language/core-model.md:1090-1097`.
- `.`, `..`, and `..=` uses for members, inferred variants, units, ranges, and slices; maximal
  munch must prefer `..=` and `..` over `.`.
- Wrapping operators `+%`, `-%`, `*%` and saturating operators `+|`, `-|` at
  `docs/language/core-model.md:982-986`.
- `->`, postfix `?`, `@`, comparisons, arithmetic, bitwise `&`/`|`, and compound `+=` throughout
  the example.

The lexical evidence base is all three language artifacts, not only the worked file. Before the
token table is frozen, implementation must sweep fenced Wrela snippets in `core-model.md` and
`image-runtime.md`, record each contributed form in the evidence manifest, and add a curated fixture
for forms absent from `virtio-appliance.wr`.

Some target DSL atoms look unusual but should remain ordinary token sequences. For example,
`virtio-pci-common` at `docs/language/examples/virtio-appliance.wr:69` is identifier, minus,
identifier, minus, identifier; `00:03.0` at lines 960-974 is integer, colon, integer, dot, integer.
Context-specific grouping belongs to a future parser, not the lexer.

The corpus also demonstrates why not every grammar word should be globally reserved: `driver` is a
layer modifier but is also a `DeviceStatus` bitflag member at
`docs/language/examples/virtio-appliance.wr:60-66`. Modifier words need contextual recognition.
The same rule applies to `ok` and `err`: they are Result construction sugar over ordinary enum
variants (`docs/language/core-model.md:969-971`), and `ok = 0` is an enum member at
`docs/language/examples/virtio-appliance.wr:334-337`.

## 4.3 Modules and extension points

`docs/language/core-model.md:159-168` says declarations live in modules, exports control visibility,
modules do not grant authority, and V1 has no module-level mutable storage. It gives no module,
import, path, or export grammar. The requested `use ... from ...` surface is therefore new. The
lexer's extension point is a centralized keyword/token definition table; the source layer's
extension point is a future module loader that can add buffers to the same `SourceManager`.

Other conceptual future inputs are the sealed intrinsic prelude
(`docs/language/core-model.md:149-157`), sealed ABI/target packages
(`docs/language/core-model.md:246-256`), and the service layer
(`docs/language/image-runtime.md:103-106`). None should be conflated with ordinary filesystem
imports during this feature.

## 4.4 Existing tests

There are no executable tests. The only testing guidance is prose about binding mock drivers on a
host target at `docs/language/examples/virtio-appliance.wr:1007-1011` and
`docs/language/image-runtime.md:889-895`. The commented illegal-source example at
`docs/language/core-model.md:1463-1487` is useful semantic calibration but is not a lexer fixture.

## 4.5 Historical, non-current scaffolding

Repository history before commit `47f7938` contained a small C++/CMake prototype. It was explicitly
deleted and imposes no compatibility requirement. It used an owning `std::string` per token,
line/column fields on every token, brace/semicolon syntax, `//` comments, the `.wrela` extension,
and required LLVM/MLIR at configure time. These choices conflict with the current `.wr` sketch and
the performance/safety requirements. The useful historical lesson is the concern split
(`Basic`/`Source`/`Diagnostics`/`Lex`/`Driver`), not the deleted APIs or lexical behavior.

# 5. Options Considered

## 5.1 Option A: owned source snapshots and a compact batch lexer

**Description.** Read each source into an immutable owned byte string, identify it with a dense
`SourceId`, emit compact span-based tokens into a contiguous vector, and retain optional comments
in a separate range index. Use only C++23 and the standard library in the frontend foundation.

**Benefits.** File mutation after loading cannot invalidate memory or cause an mmap fault. Tokens
need no lexeme allocations. Ownership is explicit. Batch output matches the future parser's need
for lookahead and random access. Source/lexer unit tests build quickly without LLVM. The backend may
later adapt source spans without making LLVM own frontend state.

**Drawbacks.** It copies file bytes into process memory and requires Wrela to implement a small
source manager, line table, diagnostic renderer, and file abstraction. Very large files cannot be
processed with a bounded sliding window.

**Complexity and risk.** Medium implementation complexity and low architectural risk. The hard
parts are layout recovery, source limits, and exact span invariants rather than buffer ownership.

**Performance.** One owned file allocation plus contiguous line/token/comment buffers; no
per-token allocation; sequential scans with good locality. Source memory remains resident while
its tokens/AST are live. Explicit file and token limits bound the worst case.

**Maintainability.** High. Public APIs contain Wrela types, not backend types. A single token
definition table prevents keyword/spelling drift.

**Migration.** Greenfield; there is no live API to migrate. A later LLVM adapter is additive.

**Testability.** High. An in-memory filesystem and `LoadedSource` request path can exercise every source and
lexer edge without disk or LLVM.

**Fit.** Best fit for a documentation-only repository, a batch whole-image compiler, and the stated
safety/performance goals.

## 5.2 Option B: use LLVM Support source-management types immediately

**Description.** Base source ownership and possibly diagnostics on LLVM Support memory buffers,
string references, source manager, and error types before introducing MLIR/code generation.

**Benefits.** Reuses mature LLVM utilities, may use optimized file reading, and reduces the amount
of infrastructure Wrela owns. Later diagnostic/debug-location bridging may require less adapter
code.

**Drawbacks.** The first frontend build becomes dependent on a correctly configured LLVM
installation even though lexing has no backend need. LLVM types can leak through public APIs and
make the frontend track backend version churn. Memory-mapped implementations can have awkward
behavior if files are concurrently truncated unless an owned-buffer mode is enforced.

**Complexity and risk.** Low initial coding complexity but medium-to-high dependency and lifecycle
risk. The old deleted scaffold already demonstrated the cost of requiring LLVM/MLIR for every
configure.

**Performance.** Potentially excellent, but not inherently better than an owned sequential scan;
token representation still needs custom design. Configure/build latency and deployment size are
worse for lexer-only work.

**Maintainability.** Mixed. Less utility code, more external API coupling.

**Migration.** Easy if chosen now; expensive to remove later if backend types spread through
tokens, diagnostics, and tests.

**Testability.** Good once LLVM is available, but hermetic small frontend tests become harder to
run on systems without the exact toolchain.

**Fit.** Plausible for a compiler already built around LLVM, but premature in the current repo.

## 5.3 Option C: streaming/pull lexer over mmap or buffered input

**Description.** Do not retain an owned complete source or token vector. Yield tokens from a pull
API over a mapped file or refillable buffer, copying only data that crosses buffer boundaries.

**Benefits.** Lower theoretical memory for very large inputs and fast startup before the entire
file is read. A parser can consume tokens immediately.

**Drawbacks.** Diagnostics, comments, arbitrary lookahead, source excerpts, future AST ranges, and
whole-image proof hashing all still need stable source access. Buffer-boundary logic complicates
UTF-8, strings, CRLF, and layout. Mapped files can become unsafe under concurrent mutation. Parser
recovery often needs retained tokens.

**Complexity and risk.** High complexity and high correctness risk for little benefit under a
64 MiB source limit.

**Performance.** May save a source copy, but introduces branches and boundary cases in the hottest
loop. It can also force later re-reading to render diagnostics or hash the exact input.

**Maintainability.** Low relative to the other options; more state and lifetime coupling.

**Migration.** Hard to evolve toward IDE overlays and stable AST spans without eventually adding
owned snapshots.

**Testability.** Requires a matrix of artificial chunk boundaries in addition to ordinary lexical
tests.

**Fit.** Poor for a whole-file/whole-image compiler with explicit bounded inputs.

## 5.4 Comment handling alternatives

Three comment treatments were considered independently of source storage.

### Drop all comments

**Description.** Recognize `#` only to skip through the physical line and record nothing.

**Benefits and drawbacks.** This is the smallest parser and memory surface, but it destroys the
valuable design/ABI commentary in the only corpus and forces any documentation tool to rescan raw
source with a second comment recognizer.

**Complexity and risk.** Implementation complexity is low. Product/maintainability risk is medium:
later tooling can drift from the compiler's literal/comment rules, and there is no attachment
metadata.

**Performance.** Best constant factors and no comment-proportional memory, although comments still
must be scanned once to find line endings.

**Maintainability and migration.** The lexer stays small, but adding documentation support later
requires a new side structure/API and downstream migration.

**Testability and fit.** Easy to test for parser-token equivalence, but unable to test or serve
comment consumers. It fits a compile-only tool, not the commentary-heavy current corpus or expected
compiler tooling.

### Emit comments as ordinary tokens

**Description.** Insert one token per comment into the same sequence consumed by the parser.

**Benefits and drawbacks.** Comment order and ranges are explicit and lossless, but every parser
production and recovery path must skip trivia. It approximates a CST contract despite the explicit
non-goal and makes token indices depend heavily on commentary.

**Complexity and risk.** Lexer complexity is low-to-medium; parser and downstream complexity/risk
is high because trivia handling becomes cross-cutting and easy to omit.

**Performance.** No text copy is required with spans, but comment-dense files enlarge the hot token
vector, parser working set, and lookahead traffic.

**Maintainability and migration.** One sequence is conceptually direct, but every future token
consumer inherits comment policy. Removing comment tokens later would be a parser/token-index API
migration.

**Testability and fit.** Token dumps make comments easy to test, while every grammar test must also
exercise trivia interleavings. This fits a lossless/CST parser, which Wrela does not currently need.

### Record a bounded side index (preferred)

**Description.** Keep parser tokens trivia-free and store comment-block ranges, neighboring token
indices, indentation, and placement flags separately; text remains in owned source.

**Benefits and drawbacks.** It preserves tooling value without parser overhead and makes retention
optional. The cost is one extra bounded vector and a small amount of neighbor-patching/coalescing
logic.

**Complexity and risk.** Complexity is medium and correctness risk is low-to-medium. The main risks
are memory amplification and accidentally allowing semantic behavior to depend on index presence;
explicit caps and equivalence tests mitigate both.

**Performance.** Parser hot data stays compact. Comment recording is sequential, zero-copy, and
bounded; it has higher constant cost than dropping comments but much lower parser cost than comment
tokens.

**Maintainability and migration.** Comment policy has one isolated API. Future doc-comment tooling
can be added without changing parser tokens; current consumers have no migration because the repo is
greenfield.

**Testability and fit.** Retention on/off equivalence, coalescing, neighbors, and truncation are
directly testable. This best fits the existing architecture goals and commentary-heavy corpus. It
also enforces an important policy: comments are never compiler directives or proof facts.

# 6. Preferred Design

## 6.1 Decision criteria

Option A wins because it provides the clearest ownership model, the smallest trusted dependency
surface, predictable failure behavior under file mutation, contiguous data for performance, and
independent frontend tests. The choice is driven by safety, deterministic diagnostics, bounded
resource use, and maintainable dependency direction. Avoiding LLVM in this stage is not a rejection
of LLVM as the backend; it keeps the backend downstream of checked Wrela semantics.

## 6.2 Decision summary

The detailed tradeoffs are in Section 5. This is the short version of the ambiguous choices and the
decision made for V1:

| Decision          | Viable options                                                                       | Chosen design                                                       | Why                                                                                                                |
| ----------------- | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Source storage    | owned snapshot; LLVM-owned buffer; streaming/mmap                                    | immutable owned snapshot                                            | It gives stable spans and diagnostics without coupling lexing to LLVM or risking mapped-file mutation faults.      |
| Parser trivia     | drop comments; comment tokens; side index                                            | bounded zero-copy comment index                                     | It preserves useful commentary without turning the parser into a CST/trivia consumer.                              |
| Layout            | braces/semicolons; insignificant newline; indentation tokens                         | `Newline`/`Indent`/`Dedent` outside `()`/`[]`                       | The existing `.wr` corpus consistently uses colon-plus-indentation suites.                                         |
| Keywords          | reserve every syntax word; all contextual; mixed                                     | hard core words plus contextual modifiers                           | `driver` and `ok` are valid member names, so reserving every word would make existing source awkward.               |
| Source text       | strict ASCII; UTF-8 source with ASCII code tokens; full Unicode identifiers/literals | UTF-8 source, ASCII identifiers and V1 decoded literals             | This accepts human comments while avoiding Unicode identifier normalization/security policy before it is designed. |
| Floating literals | decimal only; decimal plus scientific notation; full C/hex/leading-dot grammar       | decimal plus scientific notation, optional `_f32`/`_f64`            | It covers practical values while preserving unambiguous `4.MiB`, `0..N`, `.variant`, and member access.            |
| Module spelling   | string/file paths; dotted logical names; implicit filesystem imports                 | `use A, B from a.b` with dotted logical names                       | The lexer stays hermetic and auditable; a later resolver owns filesystem/package policy.                           |
| Multi-file work   | one shared mutable lexer/session; immutable per-file jobs with deterministic merge   | immutable snapshots, local results/diagnostics, deterministic merge | It permits parallel scaling without races or nondeterministic diagnostics.                                         |
| Source intake     | parallel reads with a shared aggregate budget; sorted serial intake then parallel lex | sorted serial intake in V1, then parallel lex                       | It makes source IDs, limits, and load failures deterministic; parallel I/O can be added later with a proven admission policy. |
| LLVM timing       | require LLVM now; isolate it until backend work                                      | isolate Source/Lex from LLVM/MLIR                                   | Frontend tests remain portable and quick; LLVM remains available as the downstream backend.                        |

## 6.3 Repository and target architecture

The implementation should establish the following acyclic dependency direction (`A -> B` means
"A depends on B"), without treating the names as exact patch instructions:

```text
Basic                                      no project dependencies
Source      -> Basic                       buffers, line indexes, filesystem boundary
Diagnostics -> Basic + Source              records/sinks and source-aware rendering
Lex         -> Basic + Source + Diagnostics token table, lexer, comment index
Driver      -> Source + Diagnostics + Lex   invocation, `.wr` policy, exit status, CLI

Parser/Sema/Wrela IR/MLIR/LLVM (future) depend on these layers; none of these layers depend back
```

In concrete build terms:

- Use C++23 with extensions off, target-scoped includes/options, and no directory-global warning or
  include mutations.
- Provide namespaced library aliases such as `wrela::basic`, `wrela::source`,
  `wrela::diagnostics`, `wrela::lex`, and `wrela::driver`.
- Keep public headers under `include/wrela/<Concern>/` and implementation under
  `lib/<Concern>/`. Do not expose LLVM or MLIR types from these public headers.
- Keep the compiler executable thin: argument parsing and stream selection in the tool, compilation
  orchestration in `Driver`.
- Make tests and tooling optional target groups, but keep unit/integration tests on by default when
  `BUILD_TESTING` is enabled. Benchmarks and fuzzers are opt-in.
- Provide portable CMake presets without checked-in machine-specific LLVM/Homebrew paths.
- Add `.clang-format`, `.clang-tidy`, `.editorconfig`, warning profiles, ASan/UBSan presets, and CI
  jobs for at least supported Clang and GCC configurations. Add an opt-in ThreadSanitizer preset on
  supported platforms for batch-parallel tests. `-Werror` is a CI/preset policy, not a forced
  consumer setting.
- Use explicit source lists rather than recursive globs. Pin minimum tool versions only after
  checking the supported compiler/LLVM toolchain matrix.
- Add an authoritative `docs/language/lexical-grammar.md` and a current compiler-architecture
  document. Repair the stale architecture link in the language model and the moved companion links
  in the worked example; do not recover deleted text blindly.

LLVM Support may later be used behind an adapter or in backend-only targets. Configuring and testing
`Source` and `Lex` must not require LLVM or MLIR.

## 6.4 Ownership and lifecycle

A `CompilerSession` owns one `SourceManager`, the session-level diagnostic renderer, and all
per-file lexical results. `SourceManager` owns immutable source snapshots until the session ends.
Tokens and comments contain IDs and offsets, never owning strings, raw pointers, or `string_view`
members.

Parallelism is designed around a freeze boundary, not a shared mutable manager:

1. `Driver` receives `SourceRequest`s with stable source keys (a normalized root path now; a logical
   module identity after a resolver exists), sorts them, and diagnoses duplicate keys.
2. The driver loads, validates, applies aggregate source limits, assigns dense `SourceId`s, and
   installs snapshots into `SourceManager` in that deterministic source-key order.
3. `SourceManager` freezes. Its buffers and eagerly built line indexes are then read-only.
4. Independent lexer workers consume frozen `SourceId`s, write one `LexedFile` and local diagnostic
   buffer per output slot, and never mutate another file's state.
5. The driver merges results and diagnostics in `SourceId`, byte-offset, diagnostic-ID order.

This gives identical externally visible results for one worker and many workers. It also avoids
mutexes or lazy line-index initialization in the lexer hot path. Source reading remains deterministic
in V1; it is usually I/O-bound, and parallel reads can be designed later only with a deterministic
aggregate-memory admission policy. The current command may create one request; the API and result
model must accept an ordered collection from day one.

Conceptual core types:

```cpp
struct SourceId { std::uint32_t value; };

struct SourceKey { std::string normalizedIdentity; };

struct SourceRequest {
  SourceKey key;
  std::filesystem::path path;
};

struct SourceSpan {
  SourceId source;
  std::uint32_t begin;
  std::uint32_t length; // half-open [begin, begin + length)
};

class SourceBuffer {
public:
  SourceId id() const;
  std::string_view displayName() const;
  std::string_view bytes() const;
  LineAndColumn lineAndColumn(std::uint32_t offset) const;
};

class SourceManager {
public:
  // Collecting state only; Driver assigns IDs deterministically before insertion.
  SourceId addOwned(SourceKey key, std::string displayName, std::string bytes);
  void freeze();
  const SourceBuffer& get(SourceId) const;
  std::string_view slice(SourceSpan) const;
};
```

Exact constructors should preserve invariants: callers cannot forge an out-of-range span through a
public unchecked API. `SourceManager` uses dense IDs, validates every ID in debug/assertion builds,
and performs checked narrowing only after enforcing source limits. `addOwned` and `freeze` are
driver-private/session-setup operations; parallel lexer workers receive only a frozen const view.

Files are read in binary mode into owned storage. The production filesystem implementation opens
the input once, checks the opened object is a regular file when the host API exposes that property,
and rejects directories and devices. A metadata size query may reserve capacity but is only a hint;
the loader reads in bounded chunks and enforces the byte limit on bytes actually read. The read cap
remains the safety boundary on a platform that cannot query the opened object. This avoids an
unbounded special file and avoids depending on a stale pre-open size. The source snapshot is
authoritative even if the filesystem path later changes. A future proof manifest can hash exactly
this snapshot.

The source layer itself is format-agnostic. `Driver` enforces the exact `.wr` root extension before
loading. This keeps in-memory tests and future sealed package inputs from inheriting CLI filename
policy. Tests can create `LoadedSource` values directly; they must pass through the same deterministic
sort/install/freeze path before parallel lexing.

## 6.5 Source text contract

- The file is UTF-8. Identifiers and language punctuation are ASCII. Valid non-ASCII UTF-8 is
  allowed in comments but not in identifiers or decoded V1 literals.
- One UTF-8 BOM is accepted only at byte offset zero and treated as source trivia. Its raw bytes
  remain in the snapshot and in any future source hash. Indentation measurement and displayed column
  one begin immediately after it; a first-line token span still uses its raw post-BOM byte offset. A
  BOM elsewhere is an invalid character.
- Raw NUL bytes are rejected everywhere. `\0` remains a legal literal escape.
- LF and CRLF are accepted. CRLF is one physical newline. A lone CR is diagnosed and treated as a
  newline for recovery.
- A final newline is optional. The lexer synthesizes the same logical termination sequence either
  way.
- Horizontal tabs in code are diagnosed. A tab in leading indentation expands to the next
  four-column boundary only to make error recovery deterministic; the file still fails. Tabs inside
  comments are allowed. Leading whitespace on a comment-only line follows the comment rule: it is
  allowed and never changes indentation. Literal tabs and other ASCII control bytes must use an
  escape; raw control bytes in a literal are diagnosed.
- The default limits are 64 MiB per source, 512 MiB total loaded source bytes, 4,096 sources per
  session, 16 million emitted tokens per source, 1 million retained comment blocks per source,
  4,096 indentation levels, 4,096 open delimiters, and 100 rendered errors per invocation. Limits
  are named configuration values so tests can lower them. Raising them requires revisiting offset
  width, aggregate memory budgets, and source-ID policy.
- Before dispatching lexer workers, the driver reserves a conservative session-wide result budget
  for each source in source-key order. A source that cannot reserve enough token/comment result
  capacity receives a deterministic resource diagnostic and is not scheduled. The exact reservation
  formula is an implementation-planning item, but it must upper-bound the chosen vector capacities;
  worker scheduling must never decide which file exceeds a shared memory limit.

Source ranges remain byte-based. Line and display column are computed only for diagnostics from a
line-start index. Display columns count decoded Unicode scalar values and expand tabs at a fixed
renderer tab stop; token storage never pays that cost.

## 6.6 Token representation and lexical table

`TokenKind` is a fixed-width enum generated from one declarative definition file that also provides
canonical spellings and keyword lookup. A token is conceptually:

```cpp
struct Token {
  SourceSpan span;
  TokenKind kind;
  TokenFlags flags;
};
```

The intended compact budget is 16 bytes per token (`12` for `SourceSpan`, `2` for kind, `2` for
flags), enforced with a `static_assert` on supported ABIs. If ABI alignment prevents that size, the
implementation must measure and document the replacement rather than apply unsafe packing.

Concrete token spans are ordered, in bounds, and non-empty except EOF. Synthetic `Newline`,
`Indent`, and `Dedent` tokens have a zero-length anchor and a synthetic flag. EOF is always anchored
at `source.size()`. The raw spelling is recovered through `SourceManager::slice`; identifier and
literal text is not copied or interned during lexing.

The initial kinds are grouped as:

- Data: `Identifier` (with an optional contextual-keyword-candidate flag), `IntegerLiteral`,
  `FloatLiteral`, `StringLiteral`, `ByteLiteral`, `Invalid`.
- Layout: `Newline`, `Indent`, `Dedent`, `EndOfFile`.
- Delimiters/punctuation: `(`, `)`, `[`, `]`, comma, colon, semicolon, dot, `@`, `?`.
- Operators, using longest match: `..=`, `..`, `->`, `==`, `!=`, `<=`, `>=`, `<<`, `>>`, `+=`,
  `-=`, `+%`, `-%`, `*%`, `+|`, `-|`, followed by the relevant single-character
  `= + - * / % < > & |`. Other compound assignments and operators are not accepted until specified.
- Hard keywords. The proposed globally reserved set is exactly:

  ```text
  Self and async await bitflags class const consume discard else emit enum false fn for forall
  from guard if iff image implements in interface into invariant is layer let linear loop match
  needs not or parse pass phase registers require return schedule select self storage target true
  type use var where while widen wire zeroed
  ```

The contextual modifier set is exactly `abi`, `boot`, `constructor`, `driver`, `executor`, `fault`,
`kernel`, `ok`, `err`, `open`, `primitive`, `private`, `runtime`, and `service`. These spellings
emit `Identifier` plus a candidate flag; a future parser recognizes them only in the grammar
positions that require them. In particular, `ok x`/`err e` construction sugar is a parser-level
pattern over an ordinary contextual identifier and expression, never lexer-level special casing.
All other target/ABI DSL vocabulary, such as `hardware`, `contract`, `sealed_write`, `packed`,
`remaining`, and package fragments, emits an ordinary `Identifier`.

Both lists must appear in the lexical reference and token-definition table in the same
implementation change. `Self` and `self` are case-sensitive distinct hard keywords. Recognition is
exact: `fromage` remains an identifier, and `driver`, `ok`, and `err` remain usable as declared
members. An identifier is exactly `[A-Za-z_][A-Za-z0-9_]*`. `_` is therefore an ordinary identifier
token; a future parser gives it wildcard meaning only in permitted pattern/binding positions. `*`
remains the multiplication operator. The scanner consumes the complete identifier candidate before
performing hard-keyword/contextual-candidate lookup. Classification uses explicit ASCII predicates,
never locale-dependent `std::isalpha` behavior.

The lexer is hand-written rather than generated. Its layout state, comment index, and source-span
requirements make one explicit iterative state machine easier to audit than a split generated-token
scanner plus handwritten layout layer.

## 6.7 Layout rules

The lexer emits a parser-facing logical layout stream:

1. Maintain an indentation stack beginning with zero and an opener stack for `(` and `[`.
2. At the beginning of a physical line while the opener stack is empty, count spaces before the
   first code token. Blank and comment-only lines emit no layout token and never change the stack.
3. If indentation is greater than the stack top, push it and emit one `Indent`.
4. If it is smaller, emit `Dedent` while popping. It must equal a prior stack value. Otherwise
   diagnose inconsistent dedent and recover at the greatest prior indentation smaller than the
   observed width.
5. Emit one `Newline` after each non-empty logical line, including a line ending in a trailing
  comment. Its zero-length span is anchored at the first newline byte (the `\r` in CRLF). Physical
  newlines inside `()` or `[]` are whitespace and do not affect indentation.
6. A colon is always an ordinary token. A future parser decides whether it begins an indented or
   inline suite.
7. At EOF, emit a final `Newline` if the last logical line contained code, unwind all `Dedent`s, and
   emit EOF. Diagnose unclosed delimiters before the unwind.

The opener stack stores kinds and spans so mismatched closing delimiters get precise notes. It is
iterative and bounded; no recursive scanning is used.

## 6.8 Literals

Numeric scanning consumes a contiguous candidate and validates its shape without converting its
value:

- Decimal, `0x` hexadecimal, and `0b` binary forms are supported. There is no octal form.
- Leading decimal zeroes are accepted because the target DSL uses values such as `00` and `03`.
- `_` separators must occur between digits. They cannot repeat, begin/end the digit sequence, or
  immediately follow a radix prefix.
- An optional suffix is separated from the digits by `_` and is one of lowercase `u8`, `i8`,
  `u16`, `i16`, `u32`, `i32`, `u64`, `i64`, `usize`, or `isize`. This makes `0_u8` one token.
- Decimal floating literals are supported in these forms: `digits '.' digits [exponent]`,
  `digits exponent`, and `digits` followed by lowercase `_f32` or `_f64`; `exponent` is `e` or `E`,
  an optional `+`/`-`, and digits. Digit groups use the same underscore rule as decimal integers.
  The float suffix may also follow a fraction or exponent. Examples: `1.0`, `6.02e23`, `1_000.5_0`,
  `1_f32`, and `1e-3_f32`.
- A decimal point starts a float only when it is followed by a decimal digit. Thus `4.MiB`, `0..N`,
  `.ok`, `1.method()`, and `00:03.0` tokenize compositionally, while `1.0..N` is float, range,
  identifier. Leading-dot `.5`, trailing-dot `1.`, hexadecimal floats, and `NaN`/`Inf` literals are
  not V1 literal forms.
- Invalid radix digits, separators, or suffixes produce one invalid-literal diagnostic over the
  whole candidate. Malformed exponents and float suffixes similarly produce `lex.invalid_float`.
  Integer range checking and IEEE-754 conversion/rounding remain semantic and exact.

Double-quoted strings form `StaticString` source literals. `b'...'` is the only byte literal form;
plain single-quoted character literals are invalid. The V1 escapes are `\\`, the matching quote,
`\n`, `\r`, `\t`, `\0`, and `\xNN` with exactly two hexadecimal digits. A byte literal must decode
to exactly one byte. Raw non-ASCII content and Unicode escapes are rejected. Literal tokens retain
raw ranges; decoding occurs in a later literal utility/AST stage so lexing does not allocate decoded
strings. A newline or EOF terminates recovery from an unterminated literal rather than consuming
the rest of the file. `#` inside a valid literal is data, not a comment marker.

## 6.9 Module lexical surface

The reserved future grammar is:

```ebnf
use-declaration = "use", identifier, { ",", identifier }, "from", module-path, NEWLINE ;
module-path     = identifier, { ".", identifier } ;
```

Examples:

```wr
use Clock from wrela.clock
use PciAddress, PciIdentity from platform.pci
```

There are no wildcards, aliases, string paths, relative `.`/`..` segments, or `.wr` suffixes in this
V1 source spelling. Those constraints make imports auditable and leave filesystem policy to a
resolver. The lexer only emits keyword, identifier, comma, dot, and newline tokens. It never opens
another file in response to tokens.

## 6.10 Comment side index

When comment retention is enabled (the default), `#` through but not including the physical line
ending is excluded from the token stream and represented in a `CommentIndex`; the line ending still
drives ordinary layout. Consecutive whole-line comments at the
same indentation with no blank line between them are coalesced into one block. The block has one
enclosing range beginning at the first `#` and ending after the last comment's content; the range
includes only the intervening line endings and indentation. A block records:

- its enclosing source range and comment-line count;
- first physical line and indentation;
- preceding and following non-layout token indices when present;
- flags for whole-line versus trailing and blank-line separation;
- whether the index is complete.

Raw text is read lazily from `SourceManager`; no comment text is copied. The index deliberately
records neighbors rather than declaring a semantic attachment. Documentation tools can decide
whether a block documents the following declaration, trails the previous statement, or is detached.
The parser and semantic analyzer never inspect this index.

Comment retention has its own memory budget. When normal compilation reaches the block budget, the
lexer continues compiling, stops adding comment entries, and marks the index incomplete. A tool
that explicitly requires complete comments (for example, a future doc extractor) must treat that
as a resource error. Normal compilation semantics cannot change based on comment retention.

No comment spelling has directive meaning. In particular, comments cannot suppress safety errors,
declare proof facts, or configure code generation. This aligns with
`docs/language/core-model.md:258-292` and `475-486`, which require machine-visible summaries rather
than English comments for safety obligations.

## 6.11 Diagnostics and failure policy

Diagnostics are structured records with a stable ID, severity, primary span or path location,
message arguments, optional related spans, and optional fix-it. Formatting and terminal color are
CLI renderer concerns. `Source` returns typed load errors and does not print. `Lex` reports through
a sink and does not access stdout/stderr.

Representative IDs include:

- `source.invalid_extension`, `source.open_failed`, `source.not_regular`, `source.read_failed`,
  `source.too_large`, `source.total_limit`;
- `lex.invalid_utf8`, `lex.raw_nul`, `lex.invalid_character`, `lex.tab_in_code`;
- `lex.inconsistent_dedent`, `lex.unmatched_delimiter`, `lex.unclosed_delimiter`;
- `lex.invalid_integer`, `lex.invalid_float`, `lex.invalid_escape`, `lex.unterminated_string`,
  `lex.invalid_byte_literal`;
- `lex.token_limit`, `lex.indent_limit`, `lex.delimiter_limit`, `lex.session_result_limit`.

Every recoverable lexical error consumes at least one input byte or drains a queued synthetic token.
Invalid UTF-8 consumes one offending byte for recovery. Invalid characters consume one Unicode
scalar when validly encoded. Invalid runs may be coalesced to avoid one diagnostic per byte.
Diagnostics stop rendering after the configured cap and emit one suppression note, but the scanner
continues until EOF or a hard resource limit. A token-limit failure emits a final EOF-anchored
partial result marked incomplete. Driver success requires source-load success, a complete lexer
result, and zero errors.

The initial explicit CLI surface should be a `lex` command rather than pretending later phases
exist:

```text
wrela lex [--jobs=N] path/to/root.wr [additional-root.wr ...]
wrela lex --dump-tokens [--jobs=N] path/to/root.wr [additional-root.wr ...]
```

`lex` exits `0` on complete error-free lexing of every requested source, `1` on source/lex
diagnostics, and `2` for CLI usage. `--jobs` bounds the worker pool and defaults to a conservative
hardware-derived value. Diagnostics go to stderr. `--dump-tokens` writes a stable, escaped source-key
ordered representation to stdout for debugging and integration tests. It must never print raw
control bytes. A future resolver-backed `check` or `build` command will call the same batch stage.

## 6.12 Key APIs

The exact C++ names may evolve, but responsibility boundaries should resemble:

```cpp
struct LexOptions {
  CommentMode comments = CommentMode::Index;
  LexLimits limits;
};

struct LexedFile {
  SourceId source;
  std::vector<Token> tokens;
  CommentIndex comments;
  bool complete;
  std::uint32_t errorCount;
};

struct LexBatchResult {
  std::vector<LexedFile> files; // source-key / SourceId order
  std::vector<Diagnostic> diagnostics; // deterministic merged order
  bool complete;
};

LexedFile lex(SourceId source,
              const SourceManager& sources,
              DiagnosticSink& diagnostics,
              const LexOptions& options);

LexBatchResult lexFiles(std::span<const SourceRequest> requests,
                        const LexOptions& options,
                        WorkerCount workers);
```

`Lexer` has no I/O, global state, interning, output streams, module recursion, or backend context.
It is one-shot per source. `lexFiles` owns the load/sort/install/freeze/parallel-lex/merge sequence;
workers use independent lexers and diagnostic buffers, then merge deterministically by source key and
byte offset.

## 6.13 Backward compatibility, performance, and safety

There is no current executable behavior to preserve. `.wrela` from deleted history is not an alias;
the accepted extension is `.wr` as requested and as used by the current sample.

Expected work is `O(source bytes + emitted tokens + retained comment blocks)`. Memory is the owned
source plus line starts, tokens, and bounded comment blocks. There are no per-token strings, numeric
big integers, decoded strings, maps, or virtual calls in the hot scan. Vectors reserve from
conservative size hints and grow geometrically; they must not reserve a worst-case token count based
solely on an untrusted file size.

All byte-offset arithmetic is checked before narrowing to 32 bits. Character classification is
explicit and locale-independent. Delimiter/indentation stacks and diagnostic/comment/token counts
are bounded. The lexer never recurses and never trusts a sentinel outside the source range.
Untrusted source must not trigger undefined behavior, excessive diagnostic amplification, or an
unbounded allocation. ASan/UBSan and fuzzing are release gates for this foundation.

# 7. Tricky Implementation Details

## 7.1 Source loading without a time-of-check/time-of-use assumption

Do not treat `filesystem::file_size` as authoritative. It may be unavailable, stale, or describe a
file that changes before/during reading. Use it only to reject an already oversized regular file or
reserve capacity. Read through one opened binary stream/handle in chunks, stopping at `limit + 1`.
Check both end-of-file and read-error state. The resulting owned bytes are the compilation snapshot.
This is deterministic and avoids mapped-memory faults if the path is later truncated.

An input that changes during reading may yield a consistent snapshot of the bytes actually read but
not an atomic filesystem snapshot. That is acceptable for the first local CLI. Reproducible package
builds should later use content-addressed module/package inputs and record the snapshot hash.

## 7.2 Span arithmetic

Required invariants:

```text
begin <= source_size
length <= source_size - begin
non-synthetic, non-EOF token length > 0
synthetic token length == 0
token spans are monotonically nondecreasing
EOF.begin == source_size && EOF.length == 0
```

Use subtraction-based checks (`length <= size - begin`) rather than unchecked `begin + length`.
Synthetic layout tokens can share anchors, so ordering is nondecreasing, not strictly increasing.
Diagnostics may cover whitespace/comment ranges not represented by tokens.

## 7.3 Layout state machine

Layout must distinguish physical lines from logical lines. A precise sketch is:

```text
indent_stack = [0]
openers = []
line_has_code = false
at_physical_line_start = true

while not eof:
  if at_physical_line_start and openers.empty:
    measure leading spaces (diagnose/recover tabs)
    if next is newline or '#':
      scan blank/comment line; emit no layout; continue
    reconcile indentation stack and queue INDENT/DEDENT

  scan next token/comment
  line_has_code |= token is a concrete non-layout token

  on physical newline:
    if openers.empty and line_has_code:
      emit NEWLINE anchored at newline start
      line_has_code = false
    at_physical_line_start = true

at eof:
  diagnose every remaining opener
  if line_has_code: emit NEWLINE
  emit DEDENT until stack is [0]
  emit EOF
```

Comment-only lines must be recognized before indentation changes. On the first line, skip an accepted
BOM before measuring indentation; on a comment-only line, leading tabs are comment trivia rather
than indentation. A trailing comment retains the line's pending logical newline. Within `()`/`[]`,
physical indentation and comment-only lines are trivia; after the matching closer, ordinary layout
resumes at the next physical line.

For a dedent width not in the stack, pop to the greatest smaller known indentation, emit one error,
and ignore the residual spaces for layout. Since erroneous results never reach a parser, recovery
is optimized for useful subsequent diagnostics rather than inventing a valid program.

## 7.4 Delimiter mismatch and recovery

Openers store kind and source span. A matching closer pops. For a mismatched closer:

- if its opener exists deeper in the stack, diagnose intervening unclosed openers, pop through the
  matching opener, and emit the closer token;
- if no corresponding opener exists, diagnose the closer and leave the existing stack intact;
- at EOF, diagnose remaining openers and clear the stack before layout unwind.

The first rule avoids one typo suppressing layout for the entire remainder of a file. Delimiter
depth is checked before push. All diagnostics should have one primary range and opener notes, not a
cascade at every later newline.

## 7.5 Maximal munch around dots and numbers

Order matters:

1. After decimal digits, first recognize `..=` and `..` as ranges.
2. Recognize a decimal float only for `digits '.' digits` or `digits exponent`; a dot followed by
   anything other than a digit is not part of the number.
3. At every remaining `.`, emit dot after preferring `..=` then `..`.
4. For `-`, prefer `->`, `-=`, `-%`, `-|`, then `-`. For `+`, prefer `+=`, `+%`, `+|`, then `+`.

Therefore:

```text
4.MiB     Integer(4) Dot Identifier(MiB)
0..N      Integer(0) Range Identifier(N)
0..=N     Integer(0) InclusiveRange Identifier(N)
.ok       Dot Identifier(ok)
1.0       Float(1.0)
1e-3_f32  Float(1e-3_f32)
1.0..N    Float(1.0) Range Identifier(N)
00:03.0   Integer(00) Colon Integer(03) Dot Integer(0)
```

Hyphens likewise remain operators outside literals. Negative values are unary minus plus an integer
or float token; a signed literal is never scanned as one token.

## 7.6 Numeric candidate recovery

If the scanner stopped at the first invalid radix character, `0xGG` could become several misleading
tokens. Instead scan the contiguous ASCII alphanumeric/underscore candidate after a numeric start,
then validate it as a whole, stopping at punctuation such as comma, colon, range, or unrelated
operator. Decimal scanning treats one dot-plus-digit fraction and one exponent as part of the
candidate. Emit one `Invalid` token and diagnostic for `0xGG`, `12__3`, `0b012`, `9_bad`, `1e`, or
`1.0_f16`. This is bounded by the source length and does not parse magnitude or IEEE value.

## 7.7 Literal recovery

Literal scanning must distinguish raw and decoded length without allocating. Maintain a small
decoded-byte count and validate escape shape. At the first unescaped physical newline, emit an
unterminated-literal diagnostic, end the invalid token before the newline, and let layout process
the line break normally. At EOF, end at EOF. This prevents an early missing quote from hiding every
later declaration. For `b'...'`, continue to the closing quote so one too-long literal produces one
diagnostic.

## 7.8 Comments without a CST

Comment coalescing must not make parser behavior depend on retention. The lexer first identifies the
comment boundary as part of normal scanning. An optional recorder then consumes metadata. If the
recorder reaches its budget, it becomes a no-op and marks incomplete; lexical control flow is
unchanged.

Neighbor token indices should refer to concrete non-layout tokens, because synthetic indentation
tokens are an implementation detail and poor documentation anchors. A trailing comment can record
its previous concrete token immediately. A whole-line block records the preceding token and is
patched with the next concrete token when it appears. Blank-line flags preserve enough information
for future attachment policy without embedding that policy now.

## 7.9 Diagnostics ordering and future concurrency

Diagnostics must not rely on emission order from global mutable state. Every worker owns a local
buffer for one source; the driver merges buffers in stable `(SourceId, primary begin, diagnostic ID)`
order. When a diagnostic has no `SourceId` (open failure), use the preassigned source key and request
order. This makes one-worker and multi-worker lexing byte-for-byte reproducible.

## 7.10 Exception and allocation policy

Recoverable source and compiler failures use typed results/diagnostics, not exceptions. RAII owns
all handles and buffers. The project must decide one consistent response to allocation failure at
the process boundary; ordinary lexer code must not catch and continue after `std::bad_alloc` with
partially violated invariants. LLVM is commonly built without RTTI and sometimes without
exceptions, so frontend design must not require either for routine control flow.

## 7.11 Likely bug locations

- Blank/comment-only lines incorrectly emitting `Dedent`.
- A BOM being counted as indentation or as display column one on the first line.
- Leading tabs on a comment-only line accidentally affecting indentation or producing a code-tab error.
- CRLF counted as two newlines or source spans normalized away from raw bytes.
- EOF after code versus EOF after newline producing different layout.
- A delimiter typo suppressing every later newline.
- `0..N` consumed as a malformed float or `4.MiB` consumed as one numeric token.
- A malformed exponent swallowing a following identifier or range.
- `_` suffix/separator ambiguity in `0_u8`.
- `#` inside a string starting a comment.
- Invalid UTF-8 causing signed-char indexing or failure to advance.
- Zero-length invalid tokens causing an infinite loop.
- Source or comment views outliving their manager.
- Token/comment reservation multiplying memory on adversarial one-character tokens/comments.
- Diagnostic rendering reading beyond a line when the final line has no newline.

# 8. Acceptance Criteria

## 8.1 Functional behavior

- `wrela lex valid.wr [other.wr ...]` loads one or more `.wr` files, emits no stdout by default,
  and exits `0` after complete error-free lexing of every requested source.
- The exact current `docs/language/examples/virtio-appliance.wr` lexes with zero lexical diagnostics
  and satisfies all token/span invariants. Curated fixtures from `core-model.md` and
  `image-runtime.md` cover every lexical form used as evidence only in those documents, including
  `0_u8`, `..=`, `-=`, `+%`/`-%`/`+|`/`-|`, and `b'\n'`. No parsing assertion is made.
- A fixture containing `use PciAddress, PciIdentity from platform.pci` emits `use`, identifiers,
  comma, `from`, identifiers/dots, newline, EOF as specified.
- LF, CRLF, and missing-final-newline forms produce equivalent logical token kinds and correct raw
  spans.
- Blank and comment-only lines inside a suite do not change indentation. Multiline `()`/`[]`
  contents do not emit layout changes. EOF emits required dedents.
- Hex, binary, decimal, decimal/scientific floating literals, underscore separators, typed suffixes,
  unit-member sequences, ranges, string literals, byte literals, and specified operators tokenize
  as documented.
- An enum fixture containing `ok = 0` and `.ok(value)`/`.err(_)` yields contextual `Identifier`
  tokens for `ok`/`err`; bare `_` yields an ordinary `Identifier` token without a lexical wildcard
  kind.
- The parser-facing token stream contains no whitespace or comment tokens.
- With comment indexing enabled, whole-line and trailing comments are recoverable from source,
  coalescing/neighbor metadata is correct, and disabling retention produces the identical parser
  token stream.
- A BOM before an indented or comment-only first line does not alter layout; leading tabs on a
  comment-only line are accepted and do not alter layout.

## 8.2 Error handling

- Missing, unreadable, non-regular, oversized, wrong-extension, and read-failing inputs produce a
  structured diagnostic, nonzero exit, and no crash.
- Invalid UTF-8, raw NUL, tabs in code, inconsistent dedent, delimiter mismatch/depth, malformed
  integer/float/escape, unterminated literal, invalid byte literal, and invalid character cases each
  have targeted tests with stable primary ranges.
- Every recovery path advances or drains a queued synthetic token. Fuzzing demonstrates no hangs,
  unbounded recursion, assertion failures, or sanitizer findings.
- Diagnostic and resource caps work at lowered test limits and do not overflow counters.
- An incomplete lex result is never reported as success and is not eligible for parser handoff.

## 8.3 Integration behavior

- Frontend foundation and lexer configure, build, and test without LLVM/MLIR installed.
- CMake target dependencies follow the documented DAG and no lower layer depends on `Driver`, a
  parser, or a backend.
- `--dump-tokens` is stable, escaped, deterministic, and separates stdout from stderr diagnostics.
- In-memory buffers and a fake/test filesystem can use the same lexer API as CLI-loaded sources.
- A batch lexed with one worker and with multiple workers produces identical source IDs, tokens,
  comment indexes, diagnostic IDs/order, exit status, and token dump.
- Frozen source buffers are read-only during lexing; no source-manager mutation or diagnostic-engine
  lock is on the per-token hot path.
- Public frontend headers contain no LLVM/MLIR types; a later location adapter can consume
  `SourceSpan` without changing token layout.

## 8.4 Migration and backward compatibility

- `.wr` is the only accepted source extension. A `.wrela` input receives an explicit extension
  diagnostic rather than silently compiling.
- No deleted historical API or brace/`//` grammar is reintroduced as compatibility behavior.
- Because no current executable exists, no existing user output or persisted data needs migration.

## 8.5 Tests

- Unit tests cover source manager, line lookup, diagnostics, every token family, layout, comments,
  integers/floats/strings/bytes, errors, limits, and EOF boundaries.
- Integration/golden tests cover the CLI, exit codes, stdout/stderr separation, and stable token
  dumps.
- The worked `.wr` file is a lexical smoke/regression fixture.
- A fuzz target runs the lexer on arbitrary bytes under ASan/UBSan with reduced configurable limits.
- Parallel batch tests and supported-platform ThreadSanitizer runs detect data races and verify
  one-worker/many-worker deterministic equivalence.
- Property tests assert span bounds/order, one EOF, balanced synthetic indentation on complete
  input, retention-independent tokens, deterministic output, and progress.
- Benchmarks cover the worked corpus plus generated token-dense, comment-dense, long-identifier,
  long-number, deep-layout, and delimiter-heavy inputs.

## 8.6 Documentation

- `docs/language/lexical-grammar.md` records the accepted encoding, identifiers, comments, layout,
  literals, operators, keywords, module import spelling, and error boundaries.
- A current architecture document records the target dependency DAG, ownership model, future
  Wrela-IR/MLIR/LLVM boundary, and proof-artifact direction; the stale link in `core-model.md` and
  the moved companion links in the worked example are repaired.
- Build/test/fuzz/benchmark commands and supported toolchains are documented without host-specific
  paths.

## 8.7 Performance

- Token storage is 16 bytes on supported release ABIs or any deviation is measured and approved.
- Profiling confirms no allocation per token, identifier, literal, or comment text.
- Runtime and peak memory scale linearly: on generated 1x and 10x inputs below limits, median
  runtime and measured peak memory are no more than 12x, using a pinned benchmark environment.
- A release benchmark baseline records bytes/second, tokens/second, allocations, and peak bytes for
  every corpus. CI alerts on a reproducible regression greater than 10% after noise calibration;
  it does not enforce an uncalibrated hardware-independent throughput number.
- ASan/UBSan builds and fuzz targets pass at the configured continuous and scheduled durations;
  ThreadSanitizer is an opt-in supported-platform job for batch-parallel code.

# 9. Testing Strategy

## 9.1 Unit tests

`Source` tests should cover empty files, exact byte preservation, BOM, UTF-8 comments, CRLF, final
line without newline, chunk boundaries, file-size hint mismatch, cap crossing,
missing/unreadable/non-regular files, embedded NUL, and line/column lookup at every boundary. Use
injected in-memory files for failure paths rather than relying only on platform permissions.

`Diagnostics` tests should cover path-only and span locations, related opener notes, line excerpts,
UTF-8 display columns, tab expansion, final-line rendering, escaped control bytes, deterministic
ordering, and suppression after the error cap.

Lexer table tests should enumerate every hard keyword, contextual candidate, punctuator, and
operator from the declarative token file. Each spelling needs positive boundaries (`use`, `use1`,
`fromage`), contextual-name cases such as `driver` and `ok` members, bare `_`, and longest-match
cases (`.`, `..`, `..=`, `+`, `+=`, `+%`, `+|`, `-`, `->`, `-=`, `-%`, `-|`).

Layout tests should be compact source-to-token-kind tables covering nested suites, multiple dedents,
blank/comment lines, trailing comments, inline suites, multiline calls/lists, leading indentation,
bad dedent, tabs (including leading tabs on comment-only lines), BOM plus indentation/comment-only
first lines, unmatched/mismatched/unclosed delimiters, and all EOF variants.

Literal tests should cover each integer radix, decimal fraction, scientific exponent, float suffix,
separator, integer suffix, escape, ASCII boundary, invalid digit/exponent/suffix, byte decoded
length, quote/comment interaction, range/unit/member ambiguity, and recovery at newline/EOF.

Comment-index tests should verify coalescing, trailing/whole-line flags, neighboring concrete tokens,
blank-line separation, indentation metadata, retention off, and truncation at a low comment budget.

Evidence fixtures must include a curated extraction of every fenced Wrela snippet whose unique
lexical forms are used by this design from `core-model.md` and `image-runtime.md`. Keep a small
machine-readable evidence manifest mapping each fixture to source document/line and the forms it
covers; this makes future lexical-evidence sweeps reviewable instead of implicit.

## 9.2 Integration and golden tests

Use small checked-in `.wr` fixtures with golden stderr and token dumps for:

- a valid module-use header and nested declaration;
- mixed layout/comments/integer-and-float literals/operators;
- `ok = 0`, `.ok(value)`, `.err(_)`, `len -= 1`, and `_ = await value` regressions;
- the same multi-file batch under one and multiple `--jobs` values;
- each source-load error class that is portable to simulate;
- multiple lexical errors demonstrating recovery and diagnostic order;
- wrong extension and CLI misuse.

Golden output should use stable diagnostic IDs or normalized paths where platform text differs. Do
not snapshot implementation addresses, raw enum integers, terminal colors, or OS-specific error
phrasing. Construct CRLF and missing-final-newline variants programmatically from canonical fixture
bytes in the test, rather than relying on checked-in newline-sensitive files that Git/editor settings
may normalize.

The full worked example is a smoke test that asserts zero lex errors and a stable digest of token
kinds/spans only if the language docs and fixture are versioned together. Prefer readable targeted
goldens over one enormous token dump.

## 9.3 Regression tests

Every discovered crash, infinite loop, span overflow, layout cascade, or ambiguity receives a
minimal fixture. Particularly preserve regressions for `0..N`, `4.MiB`, `0_u8`, `1.0..N`,
`1e-3_f32`, CRLF after trailing comments, comments inside suites, `#` inside literals, missing final
newline, malformed opener stacks, and one-worker/many-worker output mismatches.

## 9.4 Property and fuzz tests

For arbitrary byte strings and reduced limits, assert:

- the lexer terminates;
- every span is in bounds and token order is nondecreasing;
- there is exactly one EOF, at source size;
- each scanning transition advances input or emits a previously queued synthetic token;
- re-lexing the same immutable bytes is identical;
- lexing the same ordered source batch with one and many workers is identical after deterministic
  merge;
- comment retention mode does not alter token kinds/spans or diagnostics;
- successful complete results have a fully unwound indentation stack;
- no ASan, UBSan, signed-overflow, or debug-iterator finding occurs.

Seed the corpus with the worked example and every unit/golden fixture. Add structure-aware mutation
later, but raw-byte fuzzing is essential for UTF-8 and recovery paths.

## 9.5 Performance tests

Microbenchmarks should separately measure source load, line-index construction, lexing with comments
off, and lexing with the comment index. Inputs must include:

- the 49,033-byte (approximately 47.9 KiB) worked example;
- a many-file batch with varied source sizes to separate work scheduling from filesystem effects;
- repeated source at 1 MiB, 10 MiB, and near the configured cap;
- maximum-density one-character tokens;
- long identifiers and numeric candidates;
- comment-only and alternating code/comment lines;
- deeply nested indentation and delimiters below limits;
- valid and invalid input with diagnostics captured by a non-rendering sink.

Track throughput, token count, total allocations, peak resident/allocated bytes, result sizes, and
batch wall time for one versus N workers. Measure release builds on a pinned runner. Sanitizer jobs
check correctness, not throughput; parallel speedup is reported rather than gated until representative
multi-module workloads exist.

## 9.6 Manual verification

No correctness requirement should depend on manual testing. One manual review of diagnostics on the
worked source and representative errors is still useful for message clarity and caret alignment,
but automated goldens remain authoritative.

# 10. Migration / Rollout Plan

No user-data or API migration is needed because the current repository has no executable compiler.
The change should nevertheless be introduced in reviewable layers:

1. Land the lexical reference and build/tooling foundation so implementation and review use the
   same contract.
2. Land `Basic`, owned `Source`, structured `Diagnostics`, and the deterministic
   load/sort/install/freeze lifecycle with unit tests.
3. Land token definitions, layout/numeric lexer, comment index, parallel batch orchestration, fuzz
   target, and benchmarks.
4. Land the multi-file `wrela lex` driver/CLI and integration fixtures.
5. Enable sanitizer and supported compiler CI; establish benchmark baselines after correctness is
   stable.

The compatibility strategy is explicit and phase-appropriate: only `.wr` is accepted, unsupported
lexical forms receive lexer diagnostics, and there is no old `.wrela` or brace compatibility mode.
`//` is two slash tokens rather than a comment; a future parser will reject it where no two-division
sequence is grammatical. Semicolon remains an ordinary token because the current sketch uses it in
array-repeat syntax; whether a semicolon appears in a legal grammar position is likewise a future
parser decision, not a lexer compatibility promise.

There is no feature flag needed for the lexer command. Comment indexing has an internal option for
tests/measurement and a bounded default, but must not change language semantics.

Rollback is code/config removal because no persistent outputs are created. If a later stage depends
on the token ABI, incompatible rollback must occur before that stage lands or include the dependent
change. The lexical reference and regression evidence should remain available even if an
implementation is reverted.

# 11. Risks and Mitigations

| Risk                                                            | Why it matters                                                       | Likelihood                 | Impact | Mitigation                                                                                  | Early detection                                                    |
| --------------------------------------------------------------- | -------------------------------------------------------------------- | -------------------------- | ------ | ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| The aspirational corpus is mistaken for a complete grammar      | It contains specification-only `abi` forms and bodyless declarations | High                       | High   | Call this lexical-only; write an authoritative lexical reference before coding              | Review grammar against all three docs and run the corpus smoke lex |
| Lexical evidence is sampled rather than covered                 | Forms in prose code blocks can be omitted from the table             | Medium                     | High   | Curated cross-document fixtures plus an evidence manifest                                    | Fixture manifest review and lexical-form coverage test             |
| Layout rules differ from intended language                      | Layout decisions affect every future parser production               | Medium                     | High   | Specify logical/physical newline rules and reserve a design amendment for changes           | Targeted layout goldens, especially blank/comments and delimiters  |
| Float/range/member boundaries are mis-tokenized                  | Numeric spelling can silently change expression meaning              | Medium                     | High   | Require digits on both sides of a decimal point; test ranges, units, members, and exponents | Numeric boundary table tests and fuzz seeds                         |
| `use from` grammar later needs aliases/wildcards/relative paths | Reserved syntax can constrain module design                          | Medium                     | Medium | Keep V1 narrow and compositional; no filesystem meaning in lexer                            | Resolve with parser/module ADR before module loader work           |
| Comment retention creates memory amplification                  | Comment-dense adversarial files could dominate token memory          | Medium                     | Medium | Coalesce blocks, use ranges only, cap retention, mark incomplete without changing semantics | Comment-dense benchmarks and low-limit tests                       |
| Comment semantics become a safety backdoor                      | Hidden directives would undermine proof visibility                   | Low                        | High   | Prohibit compiler/proof directives in comments; use explicit future attributes              | Semantic review and tests showing retention-independent results    |
| 32-bit spans overflow                                           | Overflow could corrupt diagnostics or later IR locations             | Low under limits           | High   | 64 MiB limit, checked arithmetic/narrowing, static invariants                               | Boundary unit/property tests and sanitizers                        |
| Error recovery fails to advance                                 | Malformed input can hang a build/fuzzer                              | Medium                     | High   | Central progress invariant; each error consumes input or queued token                       | Raw-byte fuzzing and debug assertions                              |
| One delimiter typo suppresses later layout                      | Diagnostics become misleading and parser recovery unusable           | Medium                     | Medium | Typed opener stack and mismatch resynchronization                                           | Mismatched/nested delimiter regression matrix                      |
| LLVM coupling enters frontend APIs early                        | Builds and future refactors become toolchain-bound                   | Medium                     | Medium | CMake boundary and public-header checks; backend adapter later                              | Configure/test frontend in CI without LLVM                         |
| Locale/encoding behavior differs by host                        | Same source could tokenize differently                               | Medium if using libc ctype | High   | Explicit ASCII tables, UTF-8 validation, byte spans                                         | Cross-compiler/platform fixtures and fuzzing                       |
| Source mutation during load yields surprising content           | Reproducibility and diagnostics could refer to mixed file versions   | Low for local use          | Medium | Owned snapshot, bounded single-handle read, future content hash                             | Injected changing/short-read filesystem tests where possible       |
| Parallel work changes observable order or races                 | Builds become flaky and diagnostics cannot be reproduced             | Medium                     | High   | Sort/install/freeze before lexing; local worker outputs; deterministic merge                | One-worker/many-worker goldens and ThreadSanitizer                 |
| Performance claims remain anecdotal                             | Later stages may inherit an allocation-heavy frontend                | Medium                     | Medium | Token size/allocation invariants and pinned benchmark baseline                              | Allocation-count and scaling benchmarks in CI                      |
| Historical scaffold is accidentally revived                     | It conflicts with `.wr`, layout, `#`, and dependency goals           | Medium                     | Medium | Treat history as negative evidence; implement from current design/tests                     | Review target/source diff against lexical reference                |

# 12. Assumption Ledger

| Assumption                                                        | Confidence  | Evidence                                                                            | What invalidates it                                                            | Implementation response                                                                           |
| ----------------------------------------------------------------- | ----------- | ----------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------- |
| The compiler implementation is greenfield                         | High        | Current tree has docs only; no build/code/tests                                     | Concurrent work adds compiler files before implementation starts               | Re-run discovery, compare APIs, and update this design if boundaries conflict                     |
| `.wr` is the canonical source extension                           | High        | Feature request and current worked example                                          | Product decision adopts another extension or multiple extensions               | Stop and amend CLI/migration sections before coding compatibility                                 |
| Wrela uses indentation-delimited suites                           | High        | Consistent colon+indent corpus at example lines 15-18 and 1026-1029                 | Formal grammar chooses explicit delimiters or insignificant newlines           | Stop; token stream and parser contract require redesign                                           |
| `()` and `[]` suppress layout newlines                            | Medium-high | Corpus contains multiline calls/lists with visual continuation                      | Formal grammar requires explicit continuation or significant inner newlines    | Update lexical reference/design and fixtures before parser work                                   |
| `#` is the only V1 comment marker                                 | High        | Hundreds of whole/trailing uses; no other comment form                              | Language adds block/doc/`//` comments                                          | Add via versioned lexical amendment and fuzz/layout cases                                         |
| Comments are non-semantic                                         | High        | Proof summaries must not be comments at core-model lines 258-292 and 475-486        | Language deliberately introduces pragmas/doc attributes in comments            | Stop for safety review; prefer explicit attribute tokens                                          |
| Valid source encoding is UTF-8 with ASCII identifiers             | Medium      | Corpus is ASCII; general identifier encoding is unspecified                         | Language selects raw bytes, strict ASCII source, or Unicode identifiers        | Update source validator, column policy, normalization/security review                             |
| V1 decoded string/byte content is ASCII/bytes                     | Medium      | `b'\n'` is ASCII and other encoding is out of scope                                 | StaticString is defined as UTF-8/Unicode                                       | Amend literal grammar and add normalization/escape decisions before code lands                    |
| Decimal/scientific float forms and `_f32`/`_f64` suffixes are sufficient for V1 | Medium | User direction plus existing `F32`/`F64` primitive declarations | Product needs hex, leading-dot, trailing-dot, or special-value literals | Extend through a versioned numeric grammar and re-test dot/range/unit boundaries |
| Decimal, hex, and binary are the only integer bases               | Medium-high | These are the only evidenced bases                                                  | Formal grammar adds octal or arbitrary radix                                   | Amend numeric validator/tests; no source-storage redesign needed                                  |
| Lowercase suffixes such as `_u8` are intended                     | Medium      | One explicit `0_u8` example                                                         | The example is illustrative/stale or suffixes use another case                 | Change lexical reference/table before implementation; preserve a diagnostic migration note        |
| `<<` and `>>` are the shift spellings                             | Medium      | Shifts are specified semantically, spelling is omitted                              | Grammar chooses named or different operators                                   | Adjust reserved operator table before parser arithmetic support; amend design if already released |
| Modifier words should be contextual rather than globally reserved | High        | `driver` is both a class-layer modifier and a bitflag member in the worked source   | Formal grammar introduces escaping or forbids such name reuse                  | Amend both keyword tables and parser name rules together; retain a regression for the collision   |
| `ok`/`err` are contextual ordinary enum-member names              | High        | `ok = 0` in the worked source; Result is specified as an ordinary enum              | Formal grammar reserves them and supplies a member-escape mechanism             | Amend keyword table, construction-sugar grammar, and fixtures together                            |
| Bare `_` is an ordinary identifier token                          | High        | Pattern/binding uses occur in the worked and core-model examples                    | Formal grammar introduces a distinct wildcard token                             | Change token table before parser work and add migration fixtures                                   |
| `use A, B from a.b` is the V1 import surface                      | Medium-high | Explicit feature constraint plus this design's chosen narrow grammar                | Product chooses one-import-per-line, string paths, aliases, or wildcard syntax | Stop module/parser work and amend grammar; lexer changes may be versioned                         |
| The lexer does not load imported files                            | High        | Clean phase separation; no parser/module grammar exists                             | Product demands scan-time dependency discovery                                 | Reject silent drift; design a module header parser/loader boundary first                          |
| A 64 MiB per-file cap is operationally sufficient                 | Medium      | Current corpus is 49,033 bytes (about 47.9 KiB); generated code is not yet expected | Real packages contain larger generated `.wr` files                             | Measure, then raise with offset/memory review or add generated-source strategy                    |
| 32-bit source IDs/offsets are sufficient under limits             | High        | Per-file cap and realistic module counts                                            | Module scale or source cap approaches 32-bit boundaries                        | Move to wider spans before AST/IR ABI stabilizes; update token-size target                        |
| Owned snapshots are preferable to mmap for V1                     | High        | Bounded inputs and safety under mutation                                            | Profiling proves copy dominates real builds and stable mapping is guaranteed   | Replace storage privately or add an owned/mapped abstraction without changing spans               |
| LLVM is downstream and unnecessary for lexing                     | High        | No backend exists; lexer uses no LLVM semantics                                     | A repo-wide toolchain mandate requires LLVM Support utilities                  | Re-evaluate dependency boundary; keep LLVM types out of public token APIs                         |
| Source requests can be keyed deterministically before parallel lexing | Medium-high | Driver controls initial root inputs; future resolver can provide logical module identities | Resolver needs discovery whose identity cannot be stabilized before load | Add an explicit discovery phase, then retain sort/install/freeze before parallel lexing |
| No current compatibility contract exists                          | High        | No executable/tests in current tree                                                 | Concurrent release or downstream consumer appears                              | Inventory actual usage and add migration/deprecation plan before landing                          |

# 13. Open Questions

## Blocking Questions

None, provided approval of this document establishes the proposed V1 lexical baseline. The missing
formal lexical grammar is handled by requiring `docs/language/lexical-grammar.md` to be written from
these decisions before lexer implementation. If reviewers do not accept the layout, encoding,
literal, or `use ... from ...` decisions, those are blocking design changes rather than details for
an implementation agent to guess.

## Non-Blocking Questions

1. **What is the eventual module/package root and filesystem mapping?** Answer during module-loader
   design using a package manifest proposal, canonicalization/symlink threat model, and tests for
   duplicate identity/root escape. It does not affect tokenization of dotted paths.
2. **What is the export syntax?** Answer in parser/name-resolution design by reconciling the module
   visibility prose with concrete examples. Do not reserve a spelling speculatively here.
3. **Will imports later support aliases, wildcard sets, or re-exports?** Evaluate real stdlib/package
   ergonomics before adding grammar. Extend through a versioned language change.
4. **Should a future `##` spelling denote documentation?** Use the comment index to prototype doc
   extraction without changing the lexer first. If semantics are required, specify them explicitly
   and keep proof/compiler directives out of comments.
5. **Will StaticString become UTF-8 or another explicit encoding?** Resolve with the string/text
   standard-library design. Update literal validation and security tests before accepting non-ASCII
   literal content.
6. **How are unsuffixed floating literals typed and rounded?** Resolve in numeric type/inference
   design: lexical acceptance is defined here, while contextual `F32`/`F64` selection, exact IEEE
   rounding, constant folding, and target FP availability remain semantic questions.
7. **Are more compound/bitwise operators needed?** Derive the list from the formal expression
   grammar, not convention. Add longest-match regression cases for any extension.
8. **Should stdin and editor overlays be supported?** Decide in driver/tooling design. A
   `LoadedSource`/source-key request already supplies the ownership mechanism; reproducible module
   identity needs separate policy.
9. **Which exact CMake/compiler/test dependency versions are supported?** Establish a toolchain
   matrix in implementation planning from available CI runners and the future LLVM release target.
   Do not hard-code a developer machine path.
10. **When should source hashes be computed?** Add them when module caching/proof manifests need
    content identity. Benchmark whether to compute during load or lazily over the immutable snapshot.

# 14. Discovery Protocol for Implementation

Implementation must begin by re-reading the current tree and `git status`; this design was written
against a documentation-only repository. Do not overwrite concurrent scaffolding or assume the
historical prototype has returned.

## Acceptable drift

The following may change without a design amendment if dependency direction and behavior remain
the same and the implementation plan records the evidence:

- exact class/file/target names;
- private helper decomposition;
- vector reserve heuristics;
- diagnostic wording while IDs/ranges remain stable;
- whether line starts are built during load or in one dedicated source-analysis pass;
- exact CMake minimum/version choices justified by the supported toolchain;
- token/comment struct layout when ABI measurements make the proposed size impossible, provided
  the performance budget and measurement are recorded.

## Drift requiring this design to be updated

Update the design before merging if implementation changes:

- accepted encoding, comment, layout, identifier, literal, operator, keyword, or module syntax;
- the `.wr` extension policy;
- source/token ownership or lifetime;
- source-key ordering, freeze boundary, worker-local result ownership, or deterministic merge;
- byte-span width or source-size limits materially;
- comments from a non-semantic side index into parser/semantic inputs;
- error recovery/progress/resource-limit invariants;
- the public API dependency direction or LLVM-free frontend requirement;
- CLI success semantics or parser-handoff rules;
- asymptotic time/memory expectations.

The update must cite the conflicting repository evidence, new tests, and the chosen alternative.

## Drift requiring implementation to stop

Stop and return to design review when:

- a newly discovered formal grammar contradicts the proposed layout, literals, or `use from`
  spelling;
- concurrent repository code establishes a public API or compatibility surface this design would
  break;
- a safety invariant cannot be implemented without undefined behavior, unbounded work, or hidden
  comment semantics;
- a required source size makes 32-bit spans unsafe before a wider representation is agreed;
- implementation would require Source/Lex public APIs to depend on MLIR/LLVM;
- module loading becomes required for feature acceptance despite its path/cycle/security policy
  remaining undefined;
- stable source identities cannot be assigned before worker scheduling without changing observable
  output;
- benchmarks show the selected owned/batch architecture is materially unfit and fixing it would
  change ownership or API contracts.

## Recording discoveries

Minor decisions go in the implementation plan and commit/PR rationale with links to tests or
measurements. Durable architecture/language decisions go in an ADR or an amended design and lexical
reference. A discovered ambiguity must never be resolved only in code or a test name. The lexical
reference, token table, tests, and this design must agree in the same change.

When details change, preserve the spirit of the design: immutable source snapshots, compact spans,
deterministic trivia-free parser tokens, bounded non-semantic comment retention, explicit resource
limits, structured diagnostics, guaranteed progress, deterministic parallel per-file work, and a
frontend that remains independently testable from the LLVM backend.

# 15. Implementation Guidance

1. Freeze the lexical contract in a checked-in language reference and turn representative snippets
   into proposed token/layout fixtures.
2. Establish target-scoped C++23/CMake hygiene, warning/sanitizer/format/lint presets, and empty test
   target structure without adding LLVM/MLIR.
3. Implement strong IDs/spans, source keys, owned bounded source loading, eager line indexing, the
   deterministic sort/install/freeze lifecycle, and structured diagnostics with in-memory tests.
4. Add the declarative token/keyword table and compact token representation.
5. Implement the iterative lexer in layers: ASCII/punctuation, comments/newlines, layout,
   integers/floats, strings/bytes, UTF-8/error recovery, and resource limits. Add boundary tests
   for floats, units, ranges, and member access with each behavior.
6. Add the bounded comment side index and prove through tests that retention mode does not alter
   tokens or diagnostics.
7. Add the multi-file `wrela lex` driver, bounded worker selection, stable token dump, `.wr` policy,
   exit codes, and one-worker/many-worker CLI goldens.
8. Lex the worked example, add raw-byte fuzzing and parallel determinism tests under sanitizers,
   establish release benchmarks, and document the measured baseline.
9. Only after this stage is stable should a separate design/plan add parsing, module loading,
   semantic analysis, Wrela-specific IR/MLIR, or LLVM lowering.

# 16. Recommended Follow-Up Implementation Plan Prompt

Ask the implementation-planning agent to re-inspect the current repository, verify that no
concurrent compiler scaffold now exists, and convert this design into a staged file-level plan. The
plan should begin with the lexical reference and build hygiene, identify exact CMake targets and
test/fuzz/benchmark fixtures, preserve the dependency, ownership, float-boundary, and deterministic
parallelism invariants above, and call out any repository fact that requires a documented design
amendment. It must not expand into parsing, module resolution, MLIR, or code generation.
