# Lexing and .wr Source Consumption — Implementation Plan

- Design: docs/designs/lexing-and-wr-source-consumption.md
- Repository baseline inspected: main at 8bb9ad1
- Plan status: ready for orchestrated execution after the discovery gates in T00
- Scope: implementation planning only; parsing, module resolution, semantic analysis, MLIR, LLVM, and code generation remain out of scope

# 1. Implementation Summary

Implement the feature as a greenfield, LLVM-free C++23 frontend foundation in dependency order:
Basic, Source, Diagnostics, Lex, Driver, then the thin wrela CLI. Source bytes are loaded once into
immutable owned snapshots, installed in deterministic source-key order, frozen before lexing, and
read concurrently by independent per-file lexer jobs. Tokens carry only compact kinds, flags, and
checked byte spans. Comments stay out of the parser-facing stream and are optionally retained in a
bounded zero-copy side index. Diagnostics are structured and worker-local, then merged with an
explicit total ordering.

The lexer should be one iterative state machine with a central progress invariant. Implement it in
serialized slices—token table/scanner, layout and delimiters, literals and recovery, then comments
and limits—because those slices share cursor state and must not be patched concurrently. Driver
work follows only after per-file lexing is stable. Property tests, fuzzing, sanitizer runs, and
benchmarks are release gates, not follow-up polish.

Current repository verification:

- HEAD tracks only LICENSE and the three language artifacts. There is no CMake, C++, test, CI,
  dependency, lexical grammar, or compiler architecture implementation to preserve.
- The supplied design is currently untracked in the working tree. It is input owned by the user;
  implementation agents must not overwrite or delete it.
- docs/language/examples/virtio-appliance.wr is exactly 49,033 bytes and is the canonical full-file
  lexical smoke fixture.
- The stale architecture.md reference in core-model.md and the stale docs/core-model.md and
  docs/image-runtime.md references in the worked example are present as described.
- The local machine has CMake 4.3.4, Apple Clang 17, and Ninja 1.13.2. clang-format and clang-tidy
  were not found locally. These observations are not a support matrix; T00 must select and verify
  portable minimum versions and CI images.
- There are no existing executable tests to preserve or run.

The design is internally strong but leaves several implementation decisions open. They are
pre-code gates, not permission to guess:

1. Define the session result-memory budget and a checked reservation/growth formula that accounts
   for token-vector capacity, comment-vector capacity, line indexes, and retained diagnostics.
   The design names lex.session_result_limit but gives no default byte budget.
2. Define whether the 100-error cap limits stored diagnostics, rendered diagnostics, or both.
   A bounded worker-local buffer is required to avoid diagnostic memory amplification; suppressed
   errors must still make the result unsuccessful.
3. Define normalized CLI source keys and duplicate-key behavior without accidentally introducing
   symlink/package-resolution policy. The chosen spelling must be deterministic across worker
   counts and documented in token dumps.
4. Verify which platforms can inspect the already-open file object for regular-file status and
   define the bounded-read fallback for others.
5. Freeze the diagnostic catalog for unsupported plain character literals, non-ASCII literal
   content, misplaced BOMs, lone CR recovery, duplicate roots, and resource failures before golden
   tests are written. Lone CR must receive a stable ID and a primary span on the CR byte while
   recovery treats it as one physical newline.
6. Select pinned test and benchmark dependencies, CMake/compiler minimums, sanitizer availability,
   and a real pinned benchmark runner. AC-P04 cannot be declared complete with a fake baseline or
   an uncalibrated shared runner.
7. Define the project-wide exception, RTTI, and allocation-failure policy: whether frontend targets
   enable exceptions/RTTI, the noexcept convention for public APIs, and the one process-boundary
   response to std::bad_alloc. Routine source/lexer/diagnostic control flow must use typed results,
   must not require exceptions or RTTI, and must not catch allocation failure in a lower layer and
   continue with partially violated invariants.

Decisions 1–5 and 7 are implementation-plan refinements if they preserve the design’s externally
stated behavior. Record them in
docs/implementation/lexing-and-wr-source-consumption-decisions.md before implementation. Decision 6
is an environment gate: if no pinned runner exists, report AC-P04 as blocked rather than weakening
it.

# 2. Acceptance Criteria Ledger

This ledger preserves all 40 acceptance bullets from design section 8. Completion evidence should
be attached to the implementation PR or equivalent handoff and referenced from the decision log.

## Functional behavior

- [ ] **AC-F01 — Multi-file successful CLI invocation.** wrela lex accepts one or more valid .wr
  roots, writes no stdout by default, completely lexes every source, and exits 0.
  - Implementation tasks: T04, T07–T11.
  - Verification: invoke one-file and multi-file cases with jobs 1 and greater than 1; inspect exit
    status and both streams.
  - Tests required: LexCli_ValidSingleRoot, LexCli_ValidMultipleRoots, LexCli_DefaultStdoutEmpty.
  - Evidence expected: passing CTest entries plus captured empty stdout and exit code 0.

- [ ] **AC-F02 — Corpus and cross-document lexical evidence.** The exact worked example has zero
  lexical diagnostics and valid token/span invariants; curated fixtures cover every form used as
  evidence only in core-model.md or image-runtime.md, including 0_u8, ..=, -=, +%/-%/+|/-|, and
  b'\n'. No parse/type assertion is added.
  - Implementation tasks: T01, T06–T09, T11, T12.
  - Verification: review the machine-readable evidence manifest against every fenced source block,
    lex every manifest fixture, and run the full worked-file smoke test.
  - Tests required: LexerEvidenceManifest_AllEntriesLex, LexerCorpus_VirtioAppliance,
    TokenSpanProperties_VirtioAppliance.
  - Evidence expected: reviewed manifest with source line references, zero-diagnostic test output,
    and invariant-check output.

- [ ] **AC-F03 — use/from token surface.** The exact fixture
  “use PciAddress, PciIdentity from platform.pci” emits the two hard keywords, identifiers, comma,
  dots, logical newline, and EOF in the specified order.
  - Implementation tasks: T01, T06, T07, T11.
  - Verification: compare token kinds, raw spans, and keyword boundary cases such as use1 and
    fromage.
  - Tests required: LexerModuleUse_ExactSequence, TokenTable_HardKeywordBoundaries.
  - Evidence expected: readable token expectation and stable CLI token-dump golden.

- [ ] **AC-F04 — Physical newline equivalence with raw spans.** LF, CRLF, and no-final-newline
  variants produce equivalent logical token kinds while retaining correct raw byte offsets.
  - Implementation tasks: T04, T07.
  - Verification: construct byte variants programmatically, compare logical kinds, and assert that
    CRLF Newline anchors at the CR and EOF anchors at raw size.
  - Tests required: LexerNewlines_LfCrLfEquivalent,
    LexerNewlines_MissingFinalNewlineEquivalent, SourceLineIndex_CrLfAndFinalLine.
  - Evidence expected: passing variant table with explicit offset assertions.

- [ ] **AC-F05 — Layout behavior.** Blank/comment-only suite lines do not affect indentation;
  newlines inside parentheses/brackets are suppressed; and EOF emits all required dedents.
  - Implementation tasks: T07, T09, T11.
  - Verification: table-driven expected layout streams and CLI mixed-layout golden.
  - Tests required: LexerLayout_BlankAndCommentLines, LexerLayout_MultilineDelimiters,
    LexerLayout_EofDedents, LexerLayout_InlineSuite.
  - Evidence expected: expected/actual token-kind sequences with span anchors.

- [ ] **AC-F06 — Complete documented literal/operator families.** Decimal, hex, binary,
  decimal/scientific floats, separators, integer/float suffixes, unit-member sequences, ranges,
  strings, bytes, punctuation, and all specified operators tokenize exactly as documented.
  - Implementation tasks: T01, T06, T08.
  - Verification: exhaustive declarative spelling tests and ambiguity tables for dots, ranges,
    exponents, suffixes, plus, and minus.
  - Tests required: TokenTable_AllOperatorsAndPunctuation, LexerInteger_AllValidForms,
    LexerFloat_AllValidForms, LexerNumeric_DotRangeMemberBoundaries,
    LexerLiteral_AllValidEscapes.
  - Evidence expected: complete spelling table coverage and targeted passing tests.

- [ ] **AC-F07 — Contextual names and underscore.** ok and err remain Identifier tokens with the
  contextual-candidate flag in declarations and member forms; bare underscore is an ordinary
  Identifier with no wildcard kind.
  - Implementation tasks: T01, T06, T07, T11.
  - Verification: inspect token kinds, flags, and raw spans for ok = 0, .ok(value), .err(_), driver,
    and underscore.
  - Tests required: TokenTable_ContextualCandidates, LexerContextual_OkErrMembers,
    LexerIdentifier_BareUnderscore.
  - Evidence expected: token/flag assertions and a CLI regression golden.

- [ ] **AC-F08 — Trivia-free parser stream.** Whitespace and comments never appear as ordinary
  parser-facing tokens.
  - Implementation tasks: T07, T09.
  - Verification: scan token kinds for whitespace/comment fixtures with retention both on and off.
  - Tests required: LexerTrivia_NoWhitespaceOrCommentTokens,
    LexerComments_RetentionIndependentTokens.
  - Evidence expected: identical token vectors and an enum audit showing no trivia token kinds.

- [ ] **AC-F09 — Bounded recoverable comment index.** Whole-line and trailing comment text is
  recoverable from source; coalescing, placement, indentation, blank-line, and concrete-token
  neighbors are correct; disabling retention leaves parser tokens unchanged.
  - Implementation tasks: T09, T12.
  - Verification: compare exact source slices and metadata, force a low comment limit, and compare
    retained/off token and diagnostic results.
  - Tests required: CommentIndex_CoalescesWholeLineBlocks, CommentIndex_TrailingAndNeighbors,
    CommentIndex_BlankLineAndIndentMetadata, CommentIndex_TruncatesWithoutSemanticChange,
    CommentIndex_DisabledEquivalent.
  - Evidence expected: metadata assertions, incomplete-index assertion at the cap, and vector
    equality results.

- [ ] **AC-F10 — BOM and comment-line tab edge cases.** A single leading BOM does not alter first
  line layout, including an indented or comment-only first line; leading tabs on a comment-only
  line are accepted and never alter layout.
  - Implementation tasks: T04, T07, T09.
  - Verification: raw-byte fixtures with post-BOM span assertions and code/comment tab comparison.
  - Tests required: LexerBom_IndentedFirstLine, LexerBom_CommentOnlyFirstLine,
    LexerTabs_CommentOnlyAccepted, LexerTabs_CodeDiagnosed.
  - Evidence expected: identical logical layout to BOM-free forms and correct raw offsets.

## Error handling

- [ ] **AC-E01 — Structured source-load failures.** Missing, unreadable, non-regular, oversized,
  wrong-extension, and injected read-failing inputs produce structured diagnostics, nonzero exit,
  and no crash.
  - Implementation tasks: T04, T05, T10, T11.
  - Verification: fake-filesystem failure injection for every branch plus portable CLI cases.
  - Tests required: SourceLoader_Missing, SourceLoader_Unreadable,
    SourceLoader_NotRegular, SourceLoader_TooLarge, SourceLoader_ReadFailure,
    LexCli_WrongExtension.
  - Evidence expected: diagnostic ID/range or path assertions, exit code 1, sanitizer-clean output.

- [ ] **AC-E02 — Targeted lexical failures with stable ranges.** Invalid UTF-8, raw NUL, code tabs,
  inconsistent dedent, delimiter mismatch/depth, malformed integer/float/escape, unterminated
  literal, invalid byte literal, and invalid character each have a focused test and stable primary
  range.
  - Implementation tasks: T01, T05, T07, T08.
  - Verification: assert ID, severity, source ID, begin/length, related opener note, and recovery
    token boundary for each case.
  - Tests required: the LexerError_* and DiagnosticRelatedSpan_* matrix in section 8.
    Also require LexerLayout_LoneCrDiagnosedAndRecoversAsNewline because the source-text contract
    mandates a diagnostic even though lone CR is omitted from design section 8’s error bullet.
  - Evidence expected: structured-record assertions and normalized diagnostic goldens.

- [ ] **AC-E03 — Guaranteed progress and hostile-input safety.** Every recovery transition consumes
  input or drains a previously queued synthetic token; arbitrary bytes do not hang, recurse
  without bound, assert, or trigger sanitizer findings.
  - Implementation tasks: T07, T08, T12.
  - Verification: debug progress assertions, raw-byte fuzzing, timeout-guarded regression seeds,
    ASan, and UBSan.
  - Tests required: LexerProgress_AllRecoverySeeds, LexerFuzz, reduced-limit property suite.
  - Evidence expected: continuous and scheduled fuzz logs with corpus/crash directories empty and
    sanitizer jobs green.

- [ ] **AC-E04 — Diagnostic and resource limits.** Lowered token, comment, indentation, delimiter,
  source/session-result, diagnostic, and source-count limits behave deterministically without
  counter overflow.
  - Implementation tasks: T00, T03–T10, T12.
  - Verification: one-over-boundary tests for every named limit, checked arithmetic review, and
    same result under one/many workers.
  - Tests required: SourceLimits_*, LexerLimits_*, Diagnostics_SuppressionCap,
    LexBatch_SessionResultAdmissionOrder.
  - Evidence expected: exact resource diagnostic IDs, incomplete flags, no overflow under UBSan.

- [ ] **AC-E05 — Incomplete results never succeed or reach a parser boundary.** Any hard resource
  stop yields a final EOF-anchored partial result marked incomplete; driver success and any future
  parser-handoff eligibility remain false.
  - Implementation tasks: T07, T08, T10, T11.
  - Verification: force token/session-result limits and inspect LexedFile, LexBatchResult, exit
    status, and explicit eligibility API/predicate.
  - Tests required: LexerTokenLimit_IncompleteWithEof, LexBatch_IncompleteFails,
    LexCli_IncompleteExitOne.
  - Evidence expected: complete=false, error count greater than zero, EOF at source size, exit 1.

## Integration behavior

- [ ] **AC-I01 — LLVM/MLIR-free configure, build, and test.** The frontend foundation and lexer
  require neither package.
  - Implementation tasks: T02, T14.
  - Verification: clean configure/build/test in an environment without LLVM/MLIR discovery and
    dependency scans of link interfaces.
  - Tests required: NoLlvmConfigure CTest/CI smoke and public-header compile checks.
  - Evidence expected: successful clean CI job and no LLVM/MLIR references in generated link
    commands or public headers.

- [ ] **AC-I02 — Enforced acyclic target DAG.** Build dependencies are exactly downstream:
  Basic; Source to Basic; Diagnostics to Basic+Source; Lex to Basic+Source+Diagnostics; Driver to
  Source+Diagnostics+Lex. Lower layers never depend on Driver, parser, or backend.
  - Implementation tasks: T02, T14.
  - Verification: inspect target_link_libraries scope and generated graph; run an architecture
    dependency check in CI.
  - Tests required: CMakeTargetDagCheck.
  - Evidence expected: checked graph artifact and passing forbidden-dependency scan.

- [ ] **AC-I03 — Stable safe token dump.** --dump-tokens is source-key ordered, escaped,
  deterministic, and keeps stdout separate from stderr.
  - Implementation tasks: T06, T10, T11.
  - Verification: byte-compare repeated one/many-worker dumps, feed control bytes, and compare
    simultaneous diagnostics.
  - Tests required: TokenDump_EscapesAllControlBytes, LexCli_DumpStable,
    LexCli_DumpStdoutDiagnosticsStderr.
  - Evidence expected: checked-in goldens containing no raw control bytes and byte-identical runs.

- [ ] **AC-I04 — Shared in-memory and filesystem API path.** Tests can provide owned in-memory
  sources or a fake filesystem and still use the same deterministic install/freeze/lex lifecycle
  as CLI sources.
  - Implementation tasks: T04, T07, T10.
  - Verification: compare the same bytes loaded through both adapters.
  - Tests required: LexBatch_InMemoryAndFilesystemEquivalent,
    SourceLoader_FakeFilesystemFailures.
  - Evidence expected: identical SourceId, token, comment, and diagnostic results.

- [ ] **AC-I05 — One-worker/many-worker deterministic equivalence.** Source IDs, tokens, comment
  indexes, diagnostic IDs/order, exit status, and token dump are identical.
  - Implementation tasks: T10–T12.
  - Verification: deep equality on a mixed valid/invalid many-file batch and repeated stress runs.
  - Tests required: LexBatch_WorkerCountEquivalent, LexCli_JobsGoldenEquivalent,
    LexBatchProperty_Deterministic.
  - Evidence expected: byte-identical serialized results and TSan-clean parallel runs.

- [ ] **AC-I06 — Frozen read-only hot path.** Lexing cannot mutate SourceManager and has no shared
  diagnostic lock or source-manager lock per token.
  - Implementation tasks: T04, T10, T12.
  - Verification: const API review, freeze-state negative tests, profiling/TSan, and source-object
    checksum or immutable-state assertions before/after lex.
  - Tests required: SourceManager_RejectsAddAfterFreeze,
    LexBatch_SourceStateUnchanged, LexBatch_TSanStress.
  - Evidence expected: API/diff review plus TSan and profiling evidence showing worker-local sinks.

- [ ] **AC-I07 — Backend-neutral public boundary.** Public frontend headers expose no LLVM/MLIR
  type and SourceSpan can be consumed later by an adapter without changing Token layout.
  - Implementation tasks: T03, T06, T14.
  - Verification: standalone public-header compile, forbidden-include/type scan, and Token ABI
    assertions.
  - Tests required: PublicHeaders_SelfContained, FrontendHeaders_NoBackendReferences,
    TokenLayout_StaticAssertions.
  - Evidence expected: passing header checks and documented span/adapter contract.

## Migration and backward compatibility

- [ ] **AC-M01 — Exact .wr-only extension policy.** .wr is accepted case-sensitively; .wrela and
  other spellings receive source.invalid_extension rather than compiling.
  - Implementation tasks: T01, T10, T11.
  - Verification: extension matrix including .wr, .WR, .wrela, no extension, and misleading
    multi-suffix paths.
  - Tests required: DriverExtension_ExactWrOnly, LexCli_WrelaRejected.
  - Evidence expected: stable structured diagnostics and exit 1 for every rejected spelling.

- [ ] **AC-M02 — No historical grammar/API compatibility.** Deleted brace/semicolon-as-layout,
  //-comment, owning-token-string, or .wrela behavior is not restored. Semicolon remains only an
  ordinary token and // remains two slash tokens.
  - Implementation tasks: T01, T06, T07, T11.
  - Verification: token tests for // and semicolon plus public API/diff review against the current
    design rather than deleted history.
  - Tests required: LexerSlashSlash_IsTwoOperators, LexerSemicolon_IsOrdinaryToken,
    LexCli_WrelaRejected.
  - Evidence expected: tests and no compatibility branches/options in the final diff.

- [ ] **AC-M03 — No fabricated migration.** No user-output or persisted-data migration machinery is
  introduced because no executable contract exists.
  - Implementation tasks: T00, T14.
  - Verification: final diff review for aliases, deprecation shims, migration commands, or format
    conversion.
  - Tests required: none beyond AC-M01/M02; this is an architecture review criterion.
  - Evidence expected: clean review finding and explicit release note that this is the first
    executable surface.

## Required test surfaces

- [ ] **AC-T01 — Comprehensive unit tests.** Unit coverage includes source manager, lines,
  diagnostics, every token family, layout, comments, literals, errors, limits, and EOF boundaries.
  - Implementation tasks: T03–T09.
  - Verification: test inventory review against section 8 and coverage report where supported.
  - Tests required: every tests/Basic, tests/Source, tests/Diagnostics, and tests/Lex target listed
    in section 8.
  - Evidence expected: all unit CTest labels green and no ledger row without a test owner.

- [ ] **AC-T02 — CLI integration and golden tests.** Exit codes, stdout/stderr separation, and
  stable dumps are exercised end to end.
  - Implementation tasks: T11.
  - Verification: run integration tests against the built executable, never an in-process shortcut.
  - Tests required: tests/Integration/LexCliTest plus normalized golden fixtures.
  - Evidence expected: integration CTest logs and reviewed goldens.

- [ ] **AC-T03 — Worked-source regression.** The existing worked .wr source is a direct lexical
  smoke fixture.
  - Implementation tasks: T01, T11.
  - Verification: lex the repository file in a test that fails on any lexical error or invariant
    violation.
  - Tests required: LexerCorpus_VirtioAppliance and LexCli_VirtioAppliance.
  - Evidence expected: zero diagnostics and exit 0.

- [ ] **AC-T04 — Raw-byte fuzz target under sanitizers.** Arbitrary bytes are lexed with reduced
  configurable limits under ASan/UBSan.
  - Implementation tasks: T12.
  - Verification: run seeded continuous and scheduled fuzz jobs for the durations chosen in T00.
  - Tests required: fuzz/LexerFuzz.cpp and its seed corpus.
  - Evidence expected: fuzz command line, duration, corpus count, and sanitizer-clean logs.

- [ ] **AC-T05 — Parallel and TSan coverage.** Batch parallelism is stress-tested and supported
  platforms run TSan while comparing one/many-worker output.
  - Implementation tasks: T10, T12, T14.
  - Verification: repeated mixed batches under TSan; skip only when the T00 support matrix proves
    the platform unsupported and another supported CI job runs it.
  - Tests required: LexBatch_WorkerCountEquivalent, LexBatch_TSanStress.
  - Evidence expected: TSan CI job or documented supported-platform result, never a silent skip.

- [ ] **AC-T06 — Property tests.** Bounds/order, exactly one EOF, balanced synthetic indentation,
  retention-independent tokens, repeatability, parallel equivalence, and progress are properties.
  - Implementation tasks: T12.
  - Verification: deterministic seeded generation plus fuzz assertions over reduced limits.
  - Tests required: tests/Lex/LexerPropertyTest.cpp and tests/Driver/LexBatchPropertyTest.cpp.
  - Evidence expected: seeds and iteration counts in test logs, with regression seeds retained.

- [ ] **AC-T07 — Benchmark matrix.** Worked, token-dense, comment-dense, long-identifier,
  long-number, deep-layout, delimiter-heavy, scaled, and many-file inputs are benchmarked.
  - Implementation tasks: T13.
  - Verification: list registered benchmark cases and inspect a release run on the pinned runner.
  - Tests required: benchmark smoke CTest plus the full benchmark job.
  - Evidence expected: versioned result artifact containing every required corpus and metric.

## Documentation

- [ ] **AC-D01 — Authoritative lexical grammar.** docs/language/lexical-grammar.md specifies
  encoding, identifiers, comments, layout, literals, operators, hard/contextual keywords, module
  import spelling, and error boundaries.
  - Implementation tasks: T01.
  - Verification: cross-review against token definitions, evidence manifest, and all lexical tests.
  - Tests required: generated/table consistency check between docs and declarative token data.
  - Evidence expected: reviewed document and passing consistency test.

- [ ] **AC-D02 — Current compiler architecture and repaired links.** Architecture documentation
  records the target DAG, ownership/freeze model, future Wrela-IR/backend boundary, and proof
  direction; all three confirmed stale links are fixed.
  - Implementation tasks: T01, T14.
  - Verification: link checker plus architecture review against CMake targets/public APIs.
  - Tests required: DocsLinkCheck and CMakeTargetDagCheck.
  - Evidence expected: no broken internal links and diagram/text matching the implementation.

- [ ] **AC-D03 — Portable contributor commands and toolchains.** Configure/build/test, fuzz,
  sanitizer, TSan, and benchmark commands and supported toolchains are documented without
  machine-specific paths.
  - Implementation tasks: T02, T12–T14.
  - Verification: execute commands from a clean checkout/CI image using presets.
  - Tests required: preset smoke jobs.
  - Evidence expected: command transcript for every documented path and no Homebrew/local absolute
    paths in tracked files.

## Performance

- [ ] **AC-P01 — Token ABI budget.** Token is 16 bytes on every supported release ABI, or a measured
  deviation is explicitly approved and documented.
  - Implementation tasks: T00, T03, T06, T13.
  - Verification: compile-time size/alignment assertions in each supported compiler job and a
    benchmark metadata record.
  - Tests required: TokenLayout_StaticAssertions, TokenLayout_Report.
  - Evidence expected: size/alignment per supported ABI or an approved design amendment.

- [ ] **AC-P02 — No per-token/text allocations.** Token, identifier, literal, and comment text are
  source-backed; profiling confirms no allocation for each emitted item.
  - Implementation tasks: T03, T06–T09, T13.
  - Verification: allocation-count benchmark around pre-reserved lexing and source-slice API audit.
  - Tests required: LexAllocation_NoPerTokenGrowth and comment-on/off allocation benchmarks.
  - Evidence expected: allocation counts explained by bounded vector growth only, with no lexeme
    string ownership in public/private token structures.

- [ ] **AC-P03 — Linear scaling bound.** On a pinned environment, generated 1x and 10x inputs below
  limits have median runtime and peak memory no greater than 12x.
  - Implementation tasks: T13.
  - Verification: repeated release measurements with warmup, median calculation, and peak-memory
    capture.
  - Tests required: BenchmarkScaling_OneToTen.
  - Evidence expected: raw samples, median calculation, and pass/fail report for time and memory.

- [ ] **AC-P04 — Calibrated baseline and regression alert.** A release baseline records bytes/s,
  tokens/s, allocations, and peak bytes for every corpus; pinned-runner CI alerts on reproducible
  regressions greater than 10 percent after noise calibration.
  - Implementation tasks: T00, T13, T14.
  - Verification: establish runner identity, collect calibration samples, deliberately exercise the
    comparison script with a synthetic regression, then run the real baseline.
  - Tests required: BenchmarkComparator_ThresholdAndNoise and pinned benchmark workflow smoke.
  - Evidence expected: baseline artifact, runner/config identity, calibration rationale, comparator
    test, and working CI alert. If the runner is unavailable, this criterion remains open.

- [ ] **AC-P05 — Sanitizer/fuzz release gates and supported TSan.** ASan/UBSan builds and fuzz
  targets pass configured continuous/scheduled durations; TSan covers batch parallelism where
  supported.
  - Implementation tasks: T12, T14.
  - Verification: CI workflow results and local reproduction command.
  - Tests required: sanitizer-labeled CTest suite, LexerFuzz, LexBatch_TSanStress.
  - Evidence expected: green required jobs with durations and toolchain versions recorded.

# 3. Task Graph

File names below are the intended ownership boundaries for delegation. Private helper splits may
change through the drift protocol, but an agent must not expand into another task’s files without
the orchestrator first serializing the work and recording the ownership change.

## T00 — Reconfirm baseline and close pre-code decisions

- Description: Re-read git status, the design, all language evidence, and any newly added files.
  Produce the decision log covering the session result budget/accounting formula, stored/rendered
  diagnostic cap, source-key normalization and duplicates, platform file-handle policy, diagnostic
  catalog gaps (including lone CR), toolchain/dependency matrix, sanitizer durations, pinned
  benchmark runner, and the project-wide exception/RTTI/allocation-failure policy.
- Rationale: The repository is greenfield today, but the design explicitly requires discovery and
  leaves resource and environment choices unresolved.
- Expected files/modules touched: read-only research; then the orchestrator creates only
  docs/implementation/lexing-and-wr-source-consumption-decisions.md. Update this plan or the design
  only if the drift protocol requires it.
- Dependencies: none.
- Parallel: its three read-only research streams may run in parallel; decision consolidation is
  serialized.
- Delegate: yes, to SA-R1 (Terra/medium), SA-R2 (Terra/medium), and SA-R3 (Luna/low); the
  orchestrator owns consolidation.
- Acceptance criteria: AC-E04, AC-M03, AC-P01, AC-P04.
- Verification: every open item has a decision, evidence, owner, and impact; no source code begins
  while a blocking item is unresolved.

## T01 — Freeze the lexical contract and evidence corpus

- Description: Write docs/language/lexical-grammar.md, create a machine-readable evidence manifest
  and small .wr fixtures from the fenced Wrela snippets, create docs/compiler-architecture.md, and
  repair the three stale links. Include the exact hard/contextual keyword lists, operators, token
  boundaries, layout rules, source contract, module spelling, diagnostic IDs, and unsupported-form
  recovery decisions from T00.
- Rationale: The current prose explicitly disclaims being a formal grammar. Tests and code need one
  authoritative contract before token kinds are frozen.
- Expected files/modules touched: docs/language/lexical-grammar.md,
  docs/compiler-architecture.md, docs/language/core-model.md,
  docs/language/examples/virtio-appliance.wr,
  tests/Fixtures/evidence/manifest.json, tests/Fixtures/evidence/*.wr. Do not change the worked
  example except its stale header links.
- Dependencies: T00.
- Parallel: may run in parallel with T02 only; no other language/evidence task.
- Delegate: yes, SA-DOC (Terra/medium).
- Acceptance criteria: AC-F02, AC-F03, AC-F06, AC-F07, AC-M01, AC-M02, AC-T03, AC-D01, AC-D02.
- Verification: a reviewer traces every manifest form to a current document line, confirms every
  keyword/operator exactly once, and rejects semantic/parser assertions in lexical fixtures.

## T02 — Establish build, test, and tooling skeleton

- Description: Add target-scoped C++23 CMake, aliases for all five libraries, explicit source
  lists, CTest structure, options for fuzzing/benchmarks, warning and sanitizer interface targets,
  portable presets, format/lint/editor configuration, and dependency acquisition selected in T00.
  Create parent add_subdirectory wiring up front so later agents edit only their module-local
  CMakeLists. If configuration requires placeholder translation units, name and mark them
  unambiguously; every T03–T11 task must remove or replace any T02 placeholder in the target it
  touches before that task passes its diff gate.
- Rationale: Later tasks need stable target and file ownership boundaries; global flags and
  last-minute CMake edits would make safe parallelism impossible.
- Expected files/modules touched: CMakeLists.txt, CMakePresets.json, cmake/*.cmake,
  include/CMakeLists.txt, lib/CMakeLists.txt, lib/*/CMakeLists.txt,
  tests/CMakeLists.txt, tests/*/CMakeLists.txt, tools/CMakeLists.txt, fuzz/CMakeLists.txt,
  benchmarks/CMakeLists.txt, .clang-format, .clang-tidy, .editorconfig, and the pinned dependency
  declaration chosen by T00.
- Dependencies: T00.
- Parallel: may run in parallel with T01; afterward parent build files are integration-owned.
- Delegate: yes, SA-BUILD (Terra/low).
- Acceptance criteria: AC-I01, AC-I02, AC-D03.
- Verification: a clean skeleton configures with BUILD_TESTING on and fuzz/bench off, every alias
  exists, extensions are off, and no target contains LLVM/MLIR or machine-specific paths.

## T03 — Implement Basic IDs, spans, and checked arithmetic

- Description: Implement fixed-width SourceId, checked half-open SourceSpan construction, and
  checked narrowing/arithmetic helpers. Keep SourceLimits, LexLimits, and Driver/session limits in
  their owning higher layers so Basic does not learn frontend concepts. Enforce size and validity
  invariants at constructors and debug boundaries.
- Rationale: Source, diagnostics, tokens, and future adapters must share one safe value vocabulary.
- Expected files/modules touched: include/wrela/Basic/SourceId.h,
  include/wrela/Basic/SourceSpan.h, include/wrela/Basic/CheckedArithmetic.h,
  lib/Basic/*, tests/Basic/*, and only module-local CMakeLists.
- Dependencies: T02.
- Parallel: no; it defines APIs used everywhere else.
- Delegate: yes, first phase of SA-BASIC-SOURCE (Terra/low).
- Acceptance criteria: AC-E04, AC-I07, AC-P01, AC-T01.
- Verification: boundary tests cover zero, exact end, subtraction-based overflow rejection, invalid
  IDs, 32-bit narrowing, and supported ABI size/alignment; any Basic placeholder from T02 is gone.

## T04 — Implement owned Source layer and deterministic freeze lifecycle

- Description: Implement SourceKey/SourceRequest, SourceBuffer with eager line starts,
  SourceManager collecting/frozen states, immutable slicing and line/column lookup, injected
  filesystem/file-handle interfaces, bounded chunked binary loading, regular-file checks where
  supported, exact-byte preservation, and per/aggregate/source-count limits. Keep UTF-8/NUL lexical
  validation out of the format-agnostic loader.
- Rationale: Stable owned bytes and a true freeze boundary are prerequisites for safe spans,
  rendering, and parallel lexing.
- Expected files/modules touched: include/wrela/Source/{SourceKey,SourceBuffer,SourceManager,
  FileSystem,SourceLoader}.h, lib/Source/*.cpp, tests/Source/*.cpp,
  tests/TestSupport/FakeFileSystem.*, and module-local CMakeLists.
- Dependencies: T03.
- Parallel: no; freeze the public Source API before Diagnostics or Lex work.
- Delegate: yes, second phase of SA-BASIC-SOURCE (Terra/medium).
- Acceptance criteria: AC-F04, AC-F10, AC-E01, AC-E04, AC-I04, AC-I06, AC-T01.
- Verification: fake file tests exercise short reads, changed size hints, cap crossing, non-regular
  handles, errors after partial reads, CRLF/final-line lookup, and mutation rejection after freeze;
  any Source placeholder from T02 is gone.

## T05 — Implement structured diagnostics and deterministic rendering

- Description: Implement stable DiagnosticId values, severity, path/span location variants,
  arguments, related spans, fix-its, worker-local bounded sinks, deterministic local ordinals,
  source-aware rendering, escaping, display columns, tab stops, suppression behavior, and
  deterministic comparison/merge helpers.
- Rationale: Lexical recovery needs structured reporting before scanner behavior is implemented;
  rendering must not infect Source or Lex.
- Expected files/modules touched: include/wrela/Diagnostics/{DiagnosticId,Diagnostic,
  DiagnosticSink,DiagnosticRenderer}.h, lib/Diagnostics/*.cpp, tests/Diagnostics/*.cpp, diagnostic
  golden fixtures, and module-local CMakeLists.
- Dependencies: T04 and T00 diagnostic-cap decision.
- Parallel: may run in parallel with T06 because files and concepts are disjoint; neither may edit
  parent CMake files.
- Delegate: yes, SA-DIAG (Terra/low; escalate to Terra/medium only if diagnostic total-order or
  rendering semantics remain ambiguous after T00).
- Acceptance criteria: AC-E01, AC-E02, AC-E04, AC-T01.
- Verification: path-only and span records, opener notes, Unicode scalar display columns, tabs,
  final line without newline, control-byte escaping, tie ordering, and suppression are all tested;
  any Diagnostics placeholder from T02 is gone.

## T06 — Implement declarative token definitions and compact Token

- Description: Add one token definition source for kinds, canonical spellings, keyword class,
  dump names, and longest-match lookup. Generate or include the enum/string/keyword functions from
  it. Implement Token as SourceSpan plus fixed-width kind/flags and freeze the stable token-dump
  record contract.
- Rationale: A single definition prevents drift among scanner, docs, dumps, and tests and makes the
  16-byte ABI measurable.
- Expected files/modules touched: include/wrela/Lex/{TokenKinds.def,TokenKind,Token,
  TokenFlags}.h, lib/Lex/TokenKind.cpp, tests/Lex/TokenTableTest.cpp,
  tests/Lex/TokenLayoutTest.cpp, and module-local CMakeLists.
- Dependencies: T01, T03, T04.
- Parallel: may run in parallel with T05 only.
- Delegate: yes, first phase of SA-LEX (Terra/low).
- Acceptance criteria: AC-F03, AC-F06–F08, AC-I03, AC-I07, AC-M02, AC-P01, AC-P02, AC-T01, AC-D01.
- Verification: exhaustive table iteration checks uniqueness, spelling boundaries, contextual flags,
  longest match, serialization names, source-backed spelling, and Token size/alignment; any Lex
  placeholder from T02 is gone.

## T07 — Implement scanner core, layout, delimiters, and progress invariant

- Description: Implement the one-shot iterative Lexer over a frozen source: BOM handling, explicit
  ASCII predicates, identifiers/keywords, punctuation/operators, physical newline handling,
  indentation stack, logical layout queue, parentheses/bracket opener stack and mismatch recovery,
  comments as skipped boundaries, invalid character/UTF-8 recovery, EOF finalization, and central
  progress assertions.
- Rationale: Layout, delimiter recovery, cursor advancement, and newline suppression share state and
  must be reasoned about together.
- Expected files/modules touched: include/wrela/Lex/Lexer.h, lib/Lex/Lexer.cpp and private helpers,
  tests/Lex/{LexerIdentifier,LexerOperator,LexerLayout,LexerDelimiter,LexerError}.Test.cpp.
- Dependencies: T05, T06.
- Parallel: no; serialize with T08 and T09 and keep one agent on the lexer state machine.
- Delegate: yes, second phase of SA-LEX (Terra/medium).
- Acceptance criteria: AC-F01, AC-F03–F05, AC-F07, AC-F08, AC-F10, AC-E02, AC-E03, AC-M02,
  AC-T01.
- Verification: table-driven layout streams cover all EOF variants, BOM/comment/tab edges,
  mismatches, depth limits, LF/CRLF plus diagnosed lone-CR recovery, invalid UTF-8, and every branch
  advances or drains a queue.

## T08 — Implement numeric/string/byte scanning and lexical resource stops

- Description: Add whole-candidate numeric scanning and validation for integer/float forms,
  suffixes and separators; dot/range/member disambiguation; string and byte-literal validation
  without decoded allocation; newline/EOF recovery; token, indentation, delimiter, and diagnostic
  limits; and partial-result EOF behavior. Keep signed values as operator plus literal.
- Rationale: Numeric maximal munch and literal recovery are high-risk extensions to the same cursor
  state and should land only after core progress/layout tests are stable.
- Expected files/modules touched: lib/Lex/Lexer.cpp and private Lex helpers,
  tests/Lex/{LexerInteger,LexerFloat,LexerLiteral,LexerLimit,LexerError}.Test.cpp.
- Dependencies: T07.
- Parallel: no; same files and state machine as T07/T09.
- Delegate: yes, third phase of SA-LEX (Terra/medium).
- Acceptance criteria: AC-F02, AC-F06, AC-E02–E05, AC-P02, AC-T01.
- Verification: exhaustive valid/invalid candidate tables, one-diagnostic recovery, exact spans,
  newline resumption, lowered limits, EOF-on-partial, and no magnitude/decoded-string allocations.

## T09 — Implement bounded CommentIndex without semantic coupling

- Description: Add CommentBlock/CommentIndex and an optional recorder that observes already
  recognized comment boundaries; coalesce eligible whole-line blocks, record concrete non-layout
  neighbors and metadata, patch following neighbors, cap entries, mark incompleteness, and become a
  no-op after the cap without changing lexer control flow.
- Rationale: Comment retention is useful but must not contaminate tokenization or compiler safety.
- Expected files/modules touched: include/wrela/Lex/CommentIndex.h, lib/Lex/CommentIndex.cpp,
  minimal integration in lib/Lex/Lexer.cpp, tests/Lex/CommentIndexTest.cpp,
  tests/Lex/LexerCommentEquivalenceTest.cpp, tests/Lex/LexerCorpusTest.cpp.
- Dependencies: T08.
- Parallel: no; same lexer concept and integration point.
- Delegate: yes, final phase of SA-LEX (Terra/medium).
- Acceptance criteria: AC-F02, AC-F05, AC-F08–F10, AC-E04, AC-P02, AC-T01.
- Verification: exact source slices, line counts, indentation, placement, blank separators,
  concrete-token neighbors, truncation, and bit-for-bit tokens/diagnostics with retention off. The
  evidence-manifest suite and canonical worked-file smoke test are explicit T09 exit deliverables.

## T10 — Implement deterministic batch Driver and result admission

- Description: Implement extension validation, source-key normalization and duplicate diagnostics,
  sorted load/install/freeze, aggregate source and result-memory admission in source-key order,
  bounded worker selection/pool, one output slot and diagnostic buffer per SourceId, deterministic
  merge with a complete tie-break key, result completeness/error aggregation, an explicit
  CompilerSession/result owner that keeps SourceManager alive for every token/comment/diagnostic,
  and the in-memory request path.
- Rationale: Concurrency is safe only after per-file behavior is frozen and shared budgets are
  decided before scheduling.
- Expected files/modules touched: include/wrela/Driver/{CompilerSession,LexBatch,DriverOptions}.h,
  lib/Driver/{LexBatch,ResultAdmission}.cpp, tests/Driver/{LexBatch,ResultAdmission,
  LexBatchProperty}.Test.cpp, and module-local CMakeLists.
- Dependencies: T04, T05, T09, and T00 budget/key decisions.
- Parallel: no; it owns ordering, admission, and concurrency concepts.
- Delegate: yes, first phase of SA-DRIVER (Terra/medium).
- Acceptance criteria: AC-F01, AC-E01, AC-E04, AC-E05, AC-I03–I06, AC-M01, AC-T05.
- Verification: shuffled input order, duplicates, mixed load/lex failures, cap competition, jobs
  values, repeated scheduling, and deep one/many-worker equality; any Driver placeholder from T02
  is gone.

## T11 — Implement thin wrela lex CLI and integration goldens

- Description: Add argument parsing for lex, --jobs=N, --dump-tokens, one or more paths, usage exit
  2, diagnostic exit 1, success exit 0, stable escaped token dumps, stderr rendering, and no default
  stdout. The executable delegates orchestration to Driver.
- Rationale: The CLI must prove the public batch path end to end without placing logic in main.
- Expected files/modules touched: tools/wrela/main.cpp, include/wrela/Driver/TokenDump.h,
  lib/Driver/TokenDump.cpp, tests/Integration/LexCliTest.*, tests/Integration/fixtures/*,
  tests/Integration/golden/*, and module-local CMakeLists.
- Dependencies: T10.
- Parallel: no; goldens freeze observable behavior.
- Delegate: yes, second phase of SA-DRIVER (Terra/low).
- Acceptance criteria: AC-F01–F03, AC-F05, AC-F07, AC-E01, AC-E05, AC-I03, AC-I05,
  AC-M01, AC-M02, AC-T02, AC-T03.
- Verification: built-process tests check all exit codes, option errors, stream separation, path
  normalization, stable dumps, invalid control bytes, and jobs equivalence; any wrela-tool
  placeholder from T02 is gone.

The token dump should be frozen before goldens as an ASCII-only tab-separated record format:
one source header record containing the escaped normalized source key, followed by token records
containing begin, length, stable kind name, stable flags, and a quoted escaped raw spelling.
Escape backslash, quote, tab, CR, LF, NUL, all other controls as fixed hexadecimal bytes, and
non-ASCII bytes as fixed hexadecimal bytes. Synthetic tokens and EOF have an empty spelling.
Changing this format after T11 is observable drift and requires golden/document updates.

## T12 — Add property, fuzz, sanitizer, and TSan gates

- Description: Add deterministic property generators, raw-byte libFuzzer entry points, reduced
  limits, seeded corpora from every regression/fixture, timeout regressions, sanitizer presets, and
  parallel TSan stress. Assertions must validate results rather than merely avoid crashing.
- Rationale: Recovery, encoding, limits, and concurrency cannot be exhaustively covered by examples.
- Expected files/modules touched: tests/Lex/LexerPropertyTest.cpp,
  tests/Driver/LexBatchPropertyTest.cpp, fuzz/LexerFuzz.cpp, fuzz/LexBatchFuzz.cpp,
  fuzz/corpus/**, sanitizer-specific local CMake files. Do not edit shared presets/workflows; T14
  integrates them.
- Dependencies: T11.
- Parallel: may run in parallel with T13; files and concepts are disjoint.
- Delegate: yes, SA-QUALITY (Luna/low for property/fuzz test construction; use Terra/low for the
  batch-concurrency harness if implementing its assertions requires production-concurrency
  judgment).
- Acceptance criteria: AC-E03, AC-E04, AC-I05, AC-I06, AC-T04–T06, AC-D03, AC-P05.
- Verification: seeded deterministic runs, continuous/scheduled fuzz duration, ASan/UBSan clean
  suites, and TSan one/many-worker stress on a supported platform.

## T13 — Add benchmarks, allocation instrumentation, scaling, and comparator

- Description: Add source-load, line-index, lexer comment-on/off, many-file, generated-density,
  long-token, deep-layout/delimiter, invalid-input, 1 MiB/10 MiB/near-cap, and 1x/10x benchmarks.
  Record throughput, tokens, allocations, result sizes, peak memory, and batch wall time. Add a
  calibrated baseline schema and reproducible greater-than-10-percent comparator.
- Rationale: The compact/linear architecture and session budgets require measurement before later
  phases depend on them.
- Expected files/modules touched: benchmarks/{SourceBench,LexBench,BatchBench,
  BenchmarkInputs,AllocationTracker}.*, benchmarks/baselines/*,
  tools/compare-benchmarks.*, benchmark-local CMake files. Do not edit shared CI/presets; T14 does.
- Dependencies: T11 and T00 pinned-runner decision.
- Parallel: may run in parallel with T12.
- Delegate: yes, SA-PERF (Terra/medium).
- Acceptance criteria: AC-T07, AC-D03, AC-P01–P04.
- Verification: release smoke, allocation sanity checks, 1x/10x bound, comparator unit tests,
  calibration repeats, and complete metric/corpus inventory on the pinned runner.

## T14 — Integrate CI, presets, contributor docs, and final architecture consistency

- Description: Integrate module targets and quality commands into shared presets/CI after all
  feature files exist; document supported compilers/platforms and exact commands; add Clang and GCC
  builds, no-LLVM build, format/lint, ASan/UBSan, scheduled fuzz, supported TSan, docs link check,
  target-DAG/header checks, and pinned benchmark workflow. Reconcile architecture and lexical docs
  with final APIs and measurements without changing language behavior silently.
- Rationale: Cross-cutting files must have one owner after parallel feature work to avoid conflicts
  and incomplete release gates.
- Expected files/modules touched: CMakeLists.txt, CMakePresets.json, cmake/*,
  .github/workflows/* or the repository’s selected CI equivalent, README.md or
  docs/development.md, docs/compiler-architecture.md, docs/language/lexical-grammar.md,
  tools/check-*.*
- Dependencies: T12, T13.
- Parallel: no.
- Delegate: no; the orchestrator or one integration owner handles all cross-cutting edits.
- Acceptance criteria: AC-I01, AC-I02, AC-I07, AC-M03, AC-T05, AC-D02, AC-D03, AC-P04, AC-P05.
- Verification: execute every documented preset in clean CI, inspect dependency graphs/public
  headers, validate links, and confirm every required job is required or explicitly scheduled.

## T15 — Independent clean-room review and remediation

- Description: Give the design, this plan, decision log, final diff, and test evidence to an agent
  that did not implement the feature. It reviews acceptance criteria, lifetime/overflow/progress,
  state machines, diagnostics, concurrency, build boundaries, test validity, and performance
  evidence. The orchestrator triages and fixes every valid finding, reruns affected gates, then asks
  the reviewer to confirm closure.
- Rationale: This foundation becomes a trust boundary for all future compiler phases.
- Expected files/modules touched: review is read-only; remediation is limited to the owning task’s
  files and is serialized.
- Dependencies: T14.
- Parallel: the review itself may inspect areas in parallel only if reviewers are independent and
  read-only; fixes are serialized by file/concept owner.
- Delegate: yes, SA-REVIEW (Sol/xhigh).
- Acceptance criteria: AC-F01–F10, AC-E01–E05, AC-I01–I07, AC-M01–M03, AC-T01–T07,
  AC-D01–D03, and AC-P01–P05.
- Verification: no valid unresolved finding, full affected suites rerun, final ledger checked item
  by item.

# 4. Parallelization Plan

Use these waves. Do not start a later wave because an agent is idle; dependency and ownership
boundaries take priority.

1. **Wave 0 — read-only discovery:** SA-R1, SA-R2, and SA-R3 may inspect in parallel. They may not
   edit. The orchestrator serially consolidates T00 decisions and stops on invalid design evidence.
2. **Wave 1 — contract/build:** T01 and T02 may run in parallel. T01 owns only docs and evidence
   fixtures; T02 owns only build/tooling skeletons. Neither edits the other’s files.
3. **Wave 2 — foundational values:** T03 runs alone because every public layer consumes its types.
4. **Wave 3 — source ownership:** T04 runs alone. Its public API and freeze semantics are reviewed
   and fixed before downstream work.
5. **Wave 4 — disjoint consumers:** T05 Diagnostics and T06 token definitions may run in parallel.
   They touch different modules and test directories. T02 must already have parent CMake wiring so
   neither edits shared build registries.
6. **Wave 5 — lexer state machine:** T07, then T08, then T09 are strictly serialized and should stay
   with the same agent. They overlap lib/Lex/Lexer.cpp, cursor/progress rules, token emission, and
   comment boundaries.
7. **Wave 6 — batch/concurrency:** T10 runs alone. No CLI or fuzz agent changes ordering, result
   admission, or worker state.
8. **Wave 7 — observable CLI:** T11 runs alone and freezes goldens/dump behavior.
9. **Wave 8 — disjoint quality work:** T12 and T13 may run in parallel. T12 owns property/fuzz/
   sanitizer-local files; T13 owns benchmark/baseline/comparator files. Neither edits shared
   presets, CI, production state machines, or Driver.
10. **Wave 9 — cross-cutting integration:** T14 runs alone and owns shared CMake, presets, CI, and
    final docs synchronization.
11. **Wave 10 — clean-room review:** T15 is read-only until findings are accepted. Each remediation
    is routed back to one owner and serialized; rerun review afterward.

Forbidden parallel pairs include T03/T04; T04/T05; any pair among T07/T08/T09; T09/T10; T10/T11;
T11 with any golden-changing task; and T14 with any edit task. Research may be parallel even when it
examines overlapping files because it is read-only.

# 5. Subagent Prompts

Launch these only in the wave specified above. Each agent must first read the complete design, this
plan, the decision log if it exists, and current git status. Agents must preserve unrelated/user
changes and report any file outside their allowlist before touching it. Every implementation agent
must follow T00’s exception/RTTI/allocation-failure policy; lower layers may not catch bad_alloc and
continue or use exceptions/RTTI for routine control flow.

## SA-R1 — Repository drift and evidence audit

> Model/reasoning: Terra, medium.
> Scope: Perform T00’s repository and lexical-evidence audit. Re-read the current tree, git status,
> design, core-model.md, image-runtime.md, and the entire worked .wr file. Map every fenced
> Wrela-like snippet to lexical forms and identify forms not present in the worked source.
> Constraints: This is lexical evidence only; do not infer parser legality or restore historical
> scaffolding. Verify all 40 acceptance criteria are represented.
> Allowed files: Read any repository file. Edit none.
> May edit: No.
> Acceptance criteria: AC-F02, AC-F03, AC-F06, AC-F07, AC-M02, AC-D01.
> Output: A report with current-tree drift, evidence table (document, exact line range, form),
> stale/contradictory claims, and proposed fixture boundaries.
> Quality bar: No sampled-only audit; inspect every fenced block and distinguish source-like blocks
> from diagrams/pseudocode with reasons.
> Tests/commands: rg/git status/read-only scripts only; no generated files.
> Report back: Blocking contradictions first, then fixture/evidence recommendations and unresolved
> lexical questions.

## SA-R2 — Resource, ABI, and determinism audit

> Model/reasoning: Terra, medium.
> Scope: Close T00 decisions for capacities and ordering. Derive checked worst-case bounds for
> tokens, synthetic layout, comments, line starts, diagnostics, and vector capacity growth under
> the stated source limits. Propose a session-result byte budget/admission algorithm, stored versus
> rendered diagnostic cap, Token ABI verification, a total diagnostic tie-break order, and the
> project-wide process-boundary response to allocation failure plus exception/RTTI/noexcept policy.
> Constraints: Preserve 32-bit spans, source limits, deterministic source-key admission, no
> per-token strings, and no scheduling-dependent shared budget.
> Allowed files: Read repository files; edit none. Scratch calculations must remain outside the
> repository.
> May edit: No.
> Acceptance criteria: AC-E04, AC-I05, AC-I06, AC-P01–P03.
> Output: Formulae with overflow-safe pseudocode, numeric assumptions clearly labeled, vector
> growth/accounting rules, ABI measurements possible on available compilers, allocation-failure/
> exception policy recommendation, and design gaps.
> Quality bar: Prove the reservation upper-bounds actual allowed capacity; do not claim physical
> memory guarantees the implementation cannot enforce.
> Tests/commands: Read-only compiler probes are allowed; record compiler/ABI. No source edits.
> Report back: Recommended decision-log entries and any issue that requires a design amendment.

## SA-R3 — Toolchain, CI, and benchmark-environment audit

> Model/reasoning: Luna, low.
> Scope: Determine a supportable CMake/C++23/compiler/platform matrix, pinned test/benchmark
> dependency strategy, format/lint versions, ASan/UBSan/fuzzer/TSan support, CI provider state, and
> whether a pinned performance runner actually exists.
> Constraints: Frontend configure/build/test must not require LLVM/MLIR; no host-specific paths;
> benchmarks cannot gate a noisy shared runner as if it were pinned.
> Allowed files: Read repository and available environment/CI metadata; edit none.
> May edit: No.
> Acceptance criteria: AC-I01, AC-D03, AC-P04, AC-P05.
> Output: Proposed versions/presets/jobs with evidence, dependency pinning/offline behavior, fuzz
> durations, benchmark runner identity or explicit blocker.
> Quality bar: Separate locally observed tools from supported versions. Do not invent external
> infrastructure.
> Tests/commands: Version/configuration probes only.
> Report back: Decision-log entries, environment blockers, and commands T02/T14 should implement.

## SA-DOC — Lexical contract and evidence fixtures

> Model/reasoning: Terra, medium.
> Scope: Execute T01 only. Write the lexical grammar and compiler architecture documents, repair
> confirmed stale links, and create the curated evidence manifest/fixtures.
> Constraints: Preserve every accepted lexical behavior in the design, exact hard/contextual lists,
> .wr-only policy, comments as non-semantic, and parser/module-loader non-goals. Do not change
> language behavior to make fixtures easier.
> Allowed files: docs/language/lexical-grammar.md, docs/compiler-architecture.md,
> docs/language/core-model.md (link only), docs/language/examples/virtio-appliance.wr (header links
> only), tests/Fixtures/evidence/**.
> Acceptance criteria: AC-F02, AC-F03, AC-F06, AC-F07, AC-M01, AC-M02, AC-T03, AC-D01, AC-D02.
> Output: Patch plus manifest coverage report.
> Quality bar: The lexical reference is authoritative, internally consistent, line/range precise,
> and contains explicit error boundaries; fixtures retain source citations and make no parse claim.
> May edit: Yes, only allowed files.
> Tests/inspection: Link check if available; manifest syntax validation; manual cross-check against
> every fenced block.
> Report back: Files changed, evidence coverage, questions resolved from T00, and any contradiction.

## SA-BUILD — Build/tooling skeleton

> Model/reasoning: Terra, low.
> Scope: Execute T02 only. Create target-scoped C++23 CMake, five library aliases, thin tool target,
> CTest hierarchy, optional fuzz/benchmark groups, presets, warnings/sanitizers, formatting/linting,
> and the dependency pins approved in T00.
> Constraints: No LLVM/MLIR; no recursive globs; no directory-global warnings/includes; extensions
> off; Werror only in CI/presets; explicit source lists; portable paths; apply the T00 exception/
> RTTI policy consistently without making routine typed-result code depend on either facility.
> Allowed files: Root/shared build files listed in T02, .clang-format, .clang-tidy, .editorconfig,
> and empty placeholder source files only if required to prove configuration. Do not implement
> compiler behavior.
> Acceptance criteria: AC-I01, AC-I02, AC-D03.
> Output: Configurable skeleton and command transcript.
> Quality bar: Clean configure with BUILD_TESTING on, optional groups off by default, install/build
> interfaces correct, and no network fetch unless the approved dependency strategy permits it.
> Any necessary placeholder translation unit is unmistakably named/marked and assigned to its
> first real implementation task for removal.
> May edit: Yes, only allowed files.
> Tests: Configure/build/test each approved base preset; inspect target graph.
> Report back: Version decisions used, commands/results, target DAG, and any portability issue.

## SA-BASIC-SOURCE — Value types and immutable source lifecycle

> Model/reasoning: Terra/low for T03; Terra/medium for T04. Treat the T04 phase as a separate launch
> or explicit reasoning escalation after the T03 review gate.
> Scope: Execute T03 and, only after its review gate, T04. Implement Basic checked IDs/spans/
> arithmetic, then owned SourceBuffer/SourceManager, line index, injected filesystem, bounded
> loader, and freeze.
> Constraints: Binary exact-byte snapshots; source layer format-agnostic; subtraction-based span
> checks; checked narrowing; opened-object regular check where supported; size hints non-authoritative;
> no lazy mutation after freeze; no LLVM/MLIR.
> Allowed files: include/wrela/Basic/**, lib/Basic/**, tests/Basic/**,
> include/wrela/Source/**, lib/Source/**, tests/Source/**,
> tests/TestSupport/FakeFileSystem.*, and their module-local CMakeLists.
> Acceptance criteria: AC-F04, AC-F10, AC-E01, AC-E04, AC-I04, AC-I06, AC-I07, AC-P01, AC-T01.
> Output: Patch in two reviewable phases with API/invariant notes.
> Quality bar: No unchecked public span construction, dangling views, TOCTOU size assumption,
> unbounded special-file read, or source mutation visible to workers.
> May edit: Yes, only allowed files.
> Tests: All Basic/Source tests named in section 8, ASan/UBSan targeted run, public-header compile.
> Report back: APIs, invariants, platform file policy, test results, memory accounting, and deviations.

## SA-DIAG — Structured diagnostics

> Model/reasoning: Terra, low. Escalate to Terra/medium only if total-order or renderer edge cases
> remain ambiguous after the T00 catalog/cap decisions.
> Scope: Execute T05. Implement diagnostic records, bounded local sink, stable IDs, arguments,
> related spans/fix-its, deterministic order metadata, and escaped source-aware renderer.
> Constraints: Source returns typed errors and never prints; Lex reports through a sink and never
> owns streams; tie order must be total; display columns count Unicode scalars and expand tabs;
> raw byte spans stay unchanged.
> Allowed files: include/wrela/Diagnostics/**, lib/Diagnostics/**, tests/Diagnostics/**,
> diagnostics fixtures, and module-local CMakeLists.
> Acceptance criteria: AC-E01, AC-E02, AC-E04, AC-T01.
> Output: Patch, diagnostic catalog, rendering examples, and test report.
> Quality bar: No locale-dependent classification, out-of-line excerpt reads, OS-specific golden
> text, unbounded retained diagnostics, or output from lower layers.
> May edit: Yes, only allowed files.
> Tests: Diagnostic record/order/suppression/UTF-8/tab/final-line/control-byte/opener-note tests.
> Report back: Exact cap semantics, total-order key, catalog IDs, tests, and unresolved wording only.

## SA-LEX — Token table and serialized lexer implementation

> Model/reasoning: Terra/low for T06; Terra/medium for T07–T09. Escalate before entering T07 and
> retain the same Terra/medium context across all shared lexer-state slices.
> Scope: Execute T06, T07, T08, and T09 in order with a review/test checkpoint after each. Build
> the declarative token table and compact Token, then scanner/layout/delimiters/progress, then
> numbers/strings/bytes/limits, then CommentIndex.
> Constraints: One iterative one-shot lexer; frozen sources; no I/O/global state/interning/decoded
> allocation/backend context; explicit ASCII predicates; whole-candidate numeric recovery;
> comments never become semantic/parser tokens; every recovery advances or drains queued layout.
> Allowed files: include/wrela/Lex/**, lib/Lex/**, tests/Lex/**, Lex module-local CMakeLists.
> Acceptance criteria: AC-F02–F10, AC-E02–E05, AC-I03, AC-I07, AC-M02, AC-P01, AC-P02, AC-T01.
> Output: Four checkpoint patches or clearly separated diffs, invariant document, and test report.
> Quality bar: Exact raw spans, one EOF, nondecreasing tokens, bounded stacks/vectors, correct
> delimiter resynchronization, range/float/unit disambiguation, retention-independent results, and
> no parser assumptions.
> May edit: Yes, only allowed files.
> Tests: Every Token/Lex/Comment test in section 8 after each checkpoint; targeted ASan/UBSan.
> Report back: State invariants, branch/recovery coverage, token ABI, comment metadata, test results,
> and any lexical-reference mismatch before changing behavior.

## SA-DRIVER — Deterministic batch and CLI

> Model/reasoning: Terra/medium for T10; Terra/low for T11 after the T10 review gate.
> Scope: Execute T10, review it, then T11. Implement deterministic request normalization, duplicate
> handling, sort/load/freeze/admit/schedule/merge, worker-local results, then the thin lex CLI,
> renderer, token dump, exit codes, and process-level goldens.
> Constraints: No module loading; result budget decided before workers; one slot per source;
> diagnostics use a total stable order; no hot-path shared lock; CLI contains no lex orchestration;
> .wr exact and case-sensitive.
> Allowed files: include/wrela/Driver/**, lib/Driver/**, tests/Driver/**, tools/wrela/**,
> tests/Integration/**, and module-local CMakeLists. Read access to tests/TestSupport/** is allowed.
> If batch tests need a new FakeFileSystem capability, stop and ask the orchestrator to serialize
> an edit by the Source test-support owner or explicitly transfer that one file before editing it.
> Acceptance criteria: AC-F01–F03, AC-F05, AC-F07, AC-E01, AC-E04, AC-E05, AC-I03–I06,
> AC-M01, AC-M02, AC-T02, AC-T03, AC-T05.
> Output: Two reviewable phases, result-admission proof, deep-equivalence report, and goldens.
> Quality bar: Identical output for one/many workers and repeated schedules; usage 2, diagnostics 1,
> success 0; no raw controls; no stdout by default; no incomplete success.
> May edit: Yes, only allowed files.
> Tests: All Driver and Integration tests in section 8, repeated stress, targeted TSan if available.
> Report back: Key normalization, admission formula use, ordering tie-break, CLI contract, test results.

## SA-QUALITY — Properties, fuzzing, and sanitizers

> Model/reasoning: Luna, low for property/fuzz tests from the frozen criteria. Use Terra/low for the
> batch-fuzz harness if expressing concurrency assertions requires implementation judgment.
> Scope: Execute T12. Add property tests and raw-byte/per-batch fuzz harnesses with reduced limits,
> seed corpora, ASan/UBSan runs, and supported TSan stress.
> Constraints: Harnesses call production APIs, assert full invariants, bound their own resources,
> and preserve every discovered reproducer as a minimal regression. Do not patch production code;
> report findings to the orchestrator.
> Allowed files: tests/Lex/LexerPropertyTest.cpp, tests/Driver/LexBatchPropertyTest.cpp, fuzz/**,
> and sanitizer-local CMake files.
> Acceptance criteria: AC-E03, AC-E04, AC-I05, AC-I06, AC-T04–T06, AC-P05.
> Output: Test/fuzz patch, corpus inventory, exact commands/durations, and findings.
> Quality bar: No crash-only harnesses; assert span/order/EOF/progress/repeatability/retention/
> concurrency properties and use deterministic seeds for non-fuzz property runs.
> May edit: Yes, only allowed files.
> Tests: Continuous configured fuzz duration, scheduled-duration dry-run if feasible, all sanitizer
> suites, supported TSan stress.
> Report back: Executed durations/toolchains, coverage corpus, sanitizer logs, and minimal reproducers.

## SA-PERF — Benchmarks and regression comparator

> Model/reasoning: Terra, medium.
> Scope: Execute T13 on the T00-approved pinned runner. Add the complete benchmark corpus,
> allocation/result-size/peak-memory measurement, scaling test, versioned output schema/baseline,
> and calibrated regression comparator.
> Constraints: Release builds only for performance; sanitizers are correctness only; do not gate
> shared noisy hardware; do not alter production code merely to improve a synthetic score.
> Allowed files: benchmarks/**, tools/compare-benchmarks.*, benchmark-local CMake files and baseline
> artifacts. Production changes require a new orchestrator-owned task.
> Acceptance criteria: AC-T07, AC-P01–P04, AC-D03.
> Output: Patch plus raw and summarized measurements, calibration, runner identity, and comparator
> self-tests.
> Quality bar: Every required corpus/metric present; warmups and sample counts documented; 1x/10x
> median bound checked; allocations attributed; regression threshold reproducible.
> May edit: Yes, only allowed files.
> Tests: Benchmark smoke, comparator pass/fail/noise cases, full pinned release run.
> Report back: Results, variance, baselines, any failed performance criterion, and suspected cause.

## SA-REVIEW — Independent clean-room final review

> Model/reasoning: Sol, xhigh.
> Scope: Execute T15 read-only. Assume no implementation intent beyond the design, plan, and
> decision log. Audit the complete diff, APIs, tests/goldens, fuzz/CI logs, and benchmark evidence
> against all 40 acceptance criteria.
> Constraints: Do not edit or accept “covered by another test” without tracing the assertion.
> Treat stubs, fake tests, silent skips, mutable lifetime leaks, overflow, nondeterministic ties,
> and uncalibrated performance claims as findings.
> Allowed files: Read all repository files and evidence; edit none.
> May edit: No.
> Acceptance criteria: AC-F01–F10, AC-E01–E05, AC-I01–I07, AC-M01–M03, AC-T01–T07,
> AC-D01–D03, and AC-P01–P05.
> Output: Findings ordered by severity with file/symbol, violated criterion, concrete failure mode,
> and required verification; then a criterion-by-criterion pass/open matrix.
> Quality bar: Review behavior and test validity, not style alone. Reproduce high-risk findings when
> safe and distinguish blockers from suggestions.
> Tests/commands: Read-only builds/tests/reproducers are allowed.
> Report back: Blocking findings first. After remediation, re-review affected areas and explicitly
> close or retain each finding.

# 6. Detailed Implementation Steps

1. Capture git status, branch/HEAD, and the complete file list. Treat the current untracked design
   and any new concurrent files as user-owned. If compiler scaffolding now exists, stop before
   assuming this greenfield file map and run the drift protocol.
2. Run SA-R1, SA-R2, and SA-R3 concurrently as read-only work. Do not start T01/T02 until their
   reports return.
3. Consolidate T00 in
   docs/implementation/lexing-and-wr-source-consumption-decisions.md. For each decision record date,
   evidence, chosen behavior, rejected alternatives, acceptance/test impact, and whether design
   text must change.
4. Pause and re-evaluate. Stop for design review if layout, encoding, literal, keyword, module
   spelling, ownership, LLVM-free boundaries, or benchmark feasibility contradict the design.
5. Run T01 and T02 in parallel with strict file allowlists. T01 freezes language/evidence; T02
   freezes parent build ownership. Neither may implement compiler behavior.
6. Review T01 first: compare lexical-grammar tables against the design lists, inspect every evidence
   citation, validate the manifest syntax, and confirm the worked .wr content changed only at its
   stale header links.
7. Review T02: configure every base preset, inspect target properties and alias names, prove
   BUILD_TESTING defaults work, and confirm no LLVM/MLIR discovery or global compiler flags.
   Inventory every placeholder translation unit and assign its deletion/replacement to the first
   T03–T11 task that supplies real sources for that target.
8. Inspect both diffs together for path/CMake conflicts. Run the link/manifest checks available at
   this stage. Do not accept placeholder tests that always pass.
9. Implement T03 test-first. Add Basic boundary tests, confirm they fail to compile or fail
   behavior before definitions exist, then implement checked value types. Inspect public headers
   for self-containment and constructor invariant enforcement.
10. Run Basic targeted tests under debug and UBSan. Inspect sizeof/alignof results before any Token
    API assumes the 16-byte budget.
11. Implement T04 test-first. Begin with in-memory SourceManager/freeze/slice/line lookup, then the
    filesystem abstraction and bounded loader. Loader tests must inject failures; do not rely on
    chmod behavior or platform-specific device files as the only coverage.
12. Run Source tests with ASan/UBSan and inspect the diff for raw pointers/views stored beyond the
    manager lifetime, authoritative file_size use, unchecked capacity arithmetic, lazy line-index
    mutation, and post-freeze writes.
13. Pause at the Source API gate. Diagnostics and Lex may start only after SourceId assignment,
    span slicing, line tables, loader errors, and freeze semantics are stable. Update this plan if
    public file/module ownership changed.
14. Run T05 and T06 in parallel. T05 owns diagnostics only. T06 owns token definitions only. Parent
    CMake files remain untouched.
15. Review T05’s cap semantics against T00 and ensure suppressed diagnostics still increment an
    error indicator without growing the retained buffer. Test ordering ties with an explicit local
    ordinal.
16. Review T06 by enumerating every declarative entry. Confirm docs, kind names, keyword lookup,
    contextual flags, dump names, and longest-match spelling derive from or are checked against the
    single table. Measure Token on every available configured ABI.
17. Merge T05/T06 only after their targeted suites pass separately. Run combined Basic/Source/
    Diagnostics/Token tests and inspect dependency links.
18. Keep one owner for T07–T09. For T07, first add compact source-to-token tables for identifiers,
    operators, newline/layout/EOF, delimiters, BOM, tabs, invalid UTF-8, raw NUL, and invalid
    characters. Add a debug assertion around the outer loop: each iteration changes byte position
    or drains/emits a pre-existing synthetic item.
19. Implement T07 in small branches: BOM/start state; line start/indent measurement; comment and
    blank-line recognition; identifiers/keywords; punctuation/maximal munch; delimiters; newline;
    invalid scalar recovery; EOF. Run the relevant table after each branch.
20. Inspect T07 for signed-char table indexing, locale ctype calls, recursion, sentinel reads,
    incorrect CRLF normalization, and layout changes on comment-only lines. Run ASan/UBSan before
    adding literals.
21. For T08, land numeric boundary tests before scanning code. Use whole-candidate validation while
    explicitly stopping at punctuation/range boundaries. Test 0..N, 0..=N, 4.MiB, 1.method(),
    00:03.0, 1.0..N, 1e-3_f32, and all invalid examples as a single review table.
22. Add string/byte tests before literal code, including raw newline/EOF recovery, matching escapes,
    exact two-digit hex escapes, decoded byte counts, non-ASCII content, plain single quotes, and #
    inside literals. Then implement allocation-free validation.
23. Add one-below/exact/one-above tests for per-file lexer limits and counter maxima. Implement
    partial EOF result behavior and verify incomplete results retain useful diagnostics but cannot
    become success.
24. Inspect and test the complete T08 diff under ASan/UBSan. Add every crash/hang/span failure as a
    minimal regression before continuing.
25. For T09, add comment metadata expectations before implementation. Integrate the recorder only
    after the scanner has determined comment boundaries. Compare the full tokens and diagnostics
    with retention Index versus Off for every fixture/property seed.
26. Run the complete per-file lexer unit suite, evidence fixtures, and the 49,033-byte worked file.
    Pause if the corpus requires an undocumented token/operator/keyword. Do not silently add it;
    invoke the drift protocol.
27. Before delegating T10, confirm tests/TestSupport/FakeFileSystem supports mid-batch and per-file
    failure injection. If not, serialize an extension through the Source test-support owner. Then
    implement T10 test-first around deterministic orchestration: start with sorted in-memory
    requests and one worker, then filesystem loads/failures, source/result admissions, duplicate
    keys, and finally the worker pool. Use fixed result slots rather than concurrent append.
28. Deep-compare complete batch results at jobs 1, 2, a value larger than source count, and repeated
    runs. Include tied diagnostics and mixed load/lex failures. Run supported TSan as soon as
    concurrency exists.
29. Inspect T10 capacity accounting: the T00 formula must upper-bound every allowed vector growth,
    line index, and retained diagnostic/comment buffer. Admission must happen in source-key order
    before dispatch, with checked multiplication/addition.
30. Implement T11 token-dump unit tests and CLI process tests before goldens. Cover no command/no
    path, unknown options, malformed/zero/overflow jobs, -- separator, repeated options policy,
    wrong extension, missing file, diagnostics, default empty stdout, and every exit code.
31. Review goldens for only stable IDs/names/normalized paths and escaped bytes. Exclude enum
    integers, addresses, terminal color, timings, worker completion order, and OS error prose.
32. Run all unit and integration tests in debug, release, ASan/UBSan, and the no-LLVM clean
    configuration. Inspect the cumulative diff before launching quality agents.
33. Run T12 and T13 in parallel with disjoint files. T12 may report production defects but must not
    patch production while T13 is measuring it. Route fixes to the original owner, serialize them,
    rerun both affected tracks, and discard stale baselines after any production change.
34. For T12, seed fuzzing with all fixtures and regressions, run deterministic properties first,
    then continuous fuzz duration, then scheduled-duration CI. Minimize every reproducer and add a
    named regression.
35. For T13, verify instrumentation overhead separately, then collect warmups/repeats on the pinned
    runner. Establish baseline only after correctness and production code are frozen. Test the
    comparator using synthetic within-noise, 11-percent regression, missing-metric, and mismatched-
    environment inputs.
36. Pause at the performance gate. If 1x/10x exceeds 12x or token/allocation targets fail, profile
    and return to the owning implementation task. If the architecture itself is unfit, stop and
    amend the design rather than hiding the result.
37. Execute T14 as one integration owner. Wire the already-tested commands into CI/presets, add
    contributor docs, update architecture details/measurements, and run docs link/token-table/
    target-DAG/public-header checks.
38. From a clean build directory, run all verification gates in section 10. Inspect git diff and
    git status after generated tools to ensure no build products/baselines outside approved paths
    entered the repository.
39. Launch SA-REVIEW with no implementation context beyond the artifacts. Triage every finding
    against an acceptance ID. Fix valid findings through the original owner or a single serialized
    remediation task; rerun targeted and downstream gates.
40. Perform the final ledger review with evidence links. The feature is not complete while any
    criterion is unchecked, a benchmark runner is missing, a sanitizer/fuzz duration is unrun, or a
    review finding is merely deferred.

# 7. Tricky Code Paths

## Open-once bounded source loading

- Why tricky: metadata can be stale, path status can differ from the opened object, streams can
  short-read/fail after returning bytes, and devices can be unbounded.
- Expected invariant: one opened handle supplies the authoritative bounded snapshot; size metadata
  is only a hint; at most limit+1 bytes are attempted for limit detection; partial read errors never
  install a buffer.
- Failure mode: TOCTOU regular-file acceptance, infinite special-file read, silently truncated
  snapshot, or wrong diagnostic class.
- Coverage: fake handle status, hint smaller/larger than bytes, exact/exact+1 cap, short reads,
  error after partial data, directory/device status, path mutation after load.
- Orchestrator verification: review platform backend calls, RAII, read-state branches, and
  SourceLoader tests; confirm the loaded snapshot remains unchanged after path mutation.

## Span construction and offset arithmetic

- Why tricky: begin+length and vector-size narrowing can overflow before checks; synthetic tokens
  legitimately share anchors.
- Expected invariant: begin <= size, length <= size-begin, concrete non-EOF length > 0, synthetic
  length 0, tokens nondecreasing, EOF exactly at size.
- Failure mode: out-of-bounds slices/rendering, wrapped offsets, false strict-order assertion.
- Coverage: maximum uint32 values, exact end, over-end, zero concrete span, shared synthetic anchors,
  source cap boundary, property/fuzz invariants.
- Orchestrator verification: insist on subtraction-based checks and UBSan/property evidence; search
  for unchecked begin+length and static casts.

## Line starts, BOM, CRLF, and display columns

- Why tricky: raw byte spans, logical physical newlines, BOM-hidden first column, Unicode scalar
  columns, tabs, and final no-newline lines use different coordinate concepts.
- Expected invariant: raw offsets never normalize; CRLF is one line break anchored at CR; BOM is
  skipped only at offset zero and not counted as visible column; a lone CR produces its frozen
  diagnostic ID/span and still recovers as one newline; renderer never reads past EOF.
- Failure mode: off-by-one carets, double line increments, BOM treated as indentation, final-line
  overflow.
- Coverage: offset lookup at every byte boundary, BOM+indent/comment, LF/CRLF/lone CR, multibyte
  comment before diagnostic, tabs, empty/final line.
- Orchestrator verification: compare byte offsets and rendered line/column separately; inspect
  golden carets and ASan final-line tests.

## Layout around blank/comment lines and delimiter suppression

- Why tricky: indentation is reconciled only for code lines while physical lines inside openers are
  trivia; leading tabs on comment-only lines are allowed.
- Expected invariant: blank/comment-only lines never push/pop; only non-empty logical lines emit
  Newline; opener depth suppresses layout; EOF deterministically emits final Newline and dedents.
- Failure mode: spurious Dedent, code-tab diagnostic on comment indentation, missing trailing
  Newline, or swallowed suite after a multiline expression.
- Coverage: nested suites with interspersed blank/comments, trailing comments, inline suite,
  multiline list/call, closer then next-line code, every EOF variant.
- Orchestrator verification: review source-to-kind tables and anchor offsets, not only token counts.

## Delimiter mismatch recovery

- Why tricky: an incorrect closer can leave layout suppression active for the entire file or create
  diagnostic cascades.
- Expected invariant: matching deeper opener pops/intermediately diagnoses in deterministic order;
  absent opener diagnoses only closer and preserves stack; EOF diagnoses each remaining opener then
  clears before dedent.
- Failure mode: all later newlines suppressed, duplicate errors, wrong opener notes, depth overflow.
- Coverage: ], ), ([)], [(]), stray closer with existing other opener, nested unclosed openers,
  depth exact/over limit.
- Orchestrator verification: inspect stack transition expectations and ensure one typo permits later
  layout recovery.

## Maximal munch at numeric/dot/range/member boundaries

- Why tricky: the same dot participates in floats, ranges, member/unit access, inferred variants,
  and target DSL atoms.
- Expected invariant: ..= then .. win; decimal point joins a number only when followed by a digit;
  exponent rules are exact; signed values remain two tokens.
- Failure mode: 0..N malformed float, 4.MiB numeric candidate, 00:03.0 float, or malformed exponent
  swallowing a range/identifier.
- Coverage: the complete ambiguity list in step 21 plus punctuation after every valid/invalid form.
- Orchestrator verification: review a single declarative expectation table and confirm scanner
  branch order matches it.

## Whole-candidate numeric recovery

- Why tricky: stopping at the first bad digit creates misleading token cascades, while consuming too
  much can swallow valid following punctuation.
- Expected invariant: contiguous ASCII alphanumeric/underscore candidate is validated as one;
  documented fraction/exponent components join it; unrelated punctuation stops it; one Invalid
  token/diagnostic covers the candidate.
- Failure mode: 0xGG becomes integer+identifiers, 9_bad hides later tokens, 1e swallows minus/range,
  or repeated diagnostics amplify.
- Coverage: 0xGG, 0b012, 12__3, 9_bad, 1e, 1e+, 1.0_f16, invalid suffix followed by comma/colon/
  range/operator.
- Orchestrator verification: assert exact invalid span and first recovered token for each case.

## Literal escape validation and newline recovery

- Why tricky: raw length differs from decoded byte count; matching quote varies; # is data inside a
  literal; an unterminated literal must not hide the file.
- Expected invariant: validation allocates nothing; allowed escapes are exact; b'...' decodes to
  one byte; unescaped newline terminates invalid token before newline and returns layout control.
- Failure mode: comment begins inside string, too-long byte yields cascades, invalid hex reads past
  quote, or missing quote consumes the rest of source.
- Coverage: each escape, zero/one/two/many decoded bytes, wrong quote, raw control/non-ASCII,
  invalid hex lengths, #, CRLF, EOF.
- Orchestrator verification: compare invalid spans and subsequent Newline/next declaration tokens;
  use allocation instrumentation.

## UTF-8 and invalid-character progress

- Why tricky: char signedness, malformed prefix/continuation sequences, overlong encodings, and
  valid non-ASCII comments have different policies.
- Expected invariant: globally valid UTF-8 is accepted in comments; invalid UTF-8 consumes one
  offending byte; valid but disallowed non-ASCII code consumes one scalar; raw NUL always errors;
  no zero-length Invalid token.
- Failure mode: table underflow, infinite loop, one error per continuation cascade, or comments
  incorrectly rejected.
- Coverage: every UTF-8 sequence-length boundary, truncated/overlong/surrogate/out-of-range bytes,
  valid multibyte comments, non-ASCII identifier/literal, NUL in code/comment/literal.
- Orchestrator verification: raw-byte unit tests and fuzz progress assertions under ASan/UBSan.

## Comment block coalescing and neighbor patching

- Why tricky: a single enclosing span includes intervening newlines/indentation; layout tokens are
  excluded from neighbors; blank lines and indentation break coalescing; following neighbors arrive
  later.
- Expected invariant: only consecutive whole-line comments at equal indentation with no blank line
  coalesce; trailing comments remain distinct; neighbor indices name concrete tokens; disabling or
  truncating the recorder cannot alter lexing.
- Failure mode: wrong source slice, synthetic neighbor, cross-blank coalescing, dangling pending
  patch, or semantic difference after cap.
- Coverage: beginning/end of file, consecutive/equal/different indentation, blank separator,
  trailing then whole-line, no preceding/following token, cap during pending block.
- Orchestrator verification: inspect exact metadata and deep equality between retention modes.

## Session result admission and vector growth

- Why tricky: token limits allow large vectors, line indexes/comment/diagnostic capacities consume
  additional memory, and geometric growth can exceed a nominal accounting estimate.
- Expected invariant: a checked formula approved in T00 upper-bounds each allowed capacity; sources
  are admitted in key order before scheduling; vectors never grow beyond their reserved/debited
  envelope; failures are deterministic.
- Failure mode: schedule-dependent winner, arithmetic overflow, unexpected allocation above budget,
  or a worker failing after another consumed shared memory.
- Coverage: small configurable budgets with competing sources, exact/exact+1 capacity, high
  line/comment/token density, growth-boundary cases, one/many workers.
- Orchestrator verification: independently recompute formula from sizeof values, inspect growth
  helper, and compare admissions across worker counts.

## Diagnostic suppression and total ordering

- Why tricky: rendering cap versus retained records can diverge; path-only load errors lack
  SourceId; multiple diagnostics can share source, offset, and ID.
- Expected invariant: stored/rendered policy matches T00; suppressed errors still fail compilation;
  merge key includes source-key/request order, source ID/location, byte offset, diagnostic ID, and
  deterministic local ordinal as applicable.
- Failure mode: unbounded buffer, success after suppressed errors, unstable equal-key sort, or
  worker completion order leaking.
- Coverage: cap exact/over, equal ID/span duplicates, path-only plus source diagnostics, shuffled
  inputs, one/many workers.
- Orchestrator verification: inspect the comparator as a total order and byte-compare repeated
  goldens.

## Source-key normalization and duplicate requests

- Why tricky: absolute/canonical/lexical normalization has different missing-file, symlink, case,
  and display consequences; module identity policy is intentionally future work.
- Expected invariant: T00-defined normalization is pure/deterministic for CLI roots, does not imply
  package security, produces stable display/dump order, and diagnoses duplicate keys before work.
- Failure mode: same path gets two SourceIds, missing path cannot be keyed, symlink resolution changes
  semantics, or platform separators alter goldens.
- Coverage: relative segments, repeated path spelling, separator variants where portable, missing
  files, case variants, duplicate input order.
- Orchestrator verification: compare docs, normalization tests, source order, and golden path
  normalization; reject implicit canonicalization not in the decision log.

## Freeze/lifetime and parallel ownership

- Why tricky: tokens/comments/diagnostics expose slices indirectly while workers run concurrently;
  lazy caches or shared sinks can race.
- Expected invariant: SourceManager owns bytes/line starts through all results; workers receive const
  frozen access; each writes one preassigned slot/local sink; no stored string_view/raw pointer in
  durable result types.
- Failure mode: dangling lexemes after source move/destruction, data race on lazy line table,
  concurrent vector append, or mutex in token loop.
- Coverage: move/lifetime compile/API tests, mutation-after-freeze negative tests, state checksum,
  many-file TSan stress.
- Orchestrator verification: type/API review, TSan, and profiling; search durable structs for view/
  pointer members.

## Stable escaped CLI output

- Why tricky: source contains arbitrary bytes and paths/OS errors vary; stdout is also a machine-
  comparable debug surface.
- Expected invariant: dump is ASCII-only, source-key ordered, stable-name based, and fully escaped;
  diagnostics alone use stderr; usage has exit 2.
- Failure mode: terminal control injection, raw newline in spelling, enum-number drift, nondeterministic
  order, or mixed streams.
- Coverage: every control byte, quote/backslash, non-ASCII bytes, synthetic/EOF, multiple files,
  simultaneous lexical errors, unknown/malformed options.
- Orchestrator verification: byte-level golden comparison and a test rejecting any unescaped byte
  outside the permitted ASCII set.

# 8. Test Plan

T00 must choose the test framework, but these locations and behaviors are stable. Tests should be
registered with CTest labels unit, integration, property, sanitizer, fuzz-smoke, and benchmark-smoke.
Because the repository currently has no implementation or test harness, the “before” state for the
first test in each group is target/header absence or a deliberate compile/behavior failure. Do not
fake green tests while APIs are missing.

## Basic and Source unit tests

| File | Test names / behavior | Expected before | Expected after |
| --- | --- | --- | --- |
| tests/Basic/SourceSpanTest.cpp | SourceSpan_EmptyAtEnd; SourceSpan_RejectsBeginPastEnd; SourceSpan_RejectsLengthOverflow; SourceSpan_AllowsSharedSyntheticAnchor; CheckedNarrowing_U32Boundary | Header/constructor absent or invalid cases accepted | Checked construction enforces every span invariant without overflow |
| tests/Basic/ValueTypeAbiTest.cpp | SourceId_FixedWidth; SourceSpan_SizeAndAlignment; CheckedArithmetic_AddMultiplyOverflow | Types absent | Supported ABI facts match decision log without introducing a Basic-to-Lex dependency |
| tests/Source/SourceManagerTest.cpp | SourceManager_PreservesExactBytes; DenseIdsInInstallOrder; SliceChecked; FreezeRejectsMutation; FrozenReadsStable; EmptySource | SourceManager absent | Immutable ownership/freeze behavior passes |
| tests/Source/LineIndexTest.cpp | Empty; Lf; CrLf; LoneCr; MissingFinalNewline; BomFirstColumn; Utf8DisplayColumn; TabExpansion; EveryOffsetBoundary | Lookup absent | Raw offsets map to correct physical line/display column |
| tests/Source/SourceLoaderTest.cpp | Missing; Unreadable; NotRegular; ExactLimit; LimitPlusOne; TotalLimit; SourceCountLimit; HintTooSmall; HintTooLarge; ShortReads; ReadErrorAfterBytes; PathMutationAfterLoad | Loader/fake FS absent | Correct typed load result and no partial install |

## Diagnostics unit tests

| File | Test names / behavior | Expected before | Expected after |
| --- | --- | --- | --- |
| tests/Diagnostics/DiagnosticRecordTest.cpp | PathLocation; SpanLocation; RelatedOpener; FixIt; StableId; TotalOrderIncludingTies | Records absent | Structured fields and deterministic comparator match catalog |
| tests/Diagnostics/DiagnosticSinkTest.cpp | CapExact; CapPlusOneSuppression; SuppressedErrorsStillCount; WorkerLocalOrdinal; CounterSaturation | Sink absent | T00 cap policy is bounded and deterministic |
| tests/Diagnostics/DiagnosticRendererTest.cpp | FinalLineNoNewline; CrLfCaret; Utf8ScalarColumns; TabExpansion; EscapesControls; NoColorGolden; SuppressionNote | Renderer absent | Stable normalized text and no out-of-bounds access |

## Token table and lexer unit tests

| File | Test names / behavior | Expected before | Expected after |
| --- | --- | --- | --- |
| tests/Lex/TokenTableTest.cpp | EveryHardKeyword; EveryContextualCandidate; KeywordBoundaries; EveryPunctuator; EveryOperator; LongestMatch; SelfVsSelfCase; OrdinaryDslWords; DumpNameUnique | Token table absent | Single declarative table covers exactly the lexical reference |
| tests/Lex/TokenLayoutTest.cpp | TokenIs16BytesOrApproved; KindAndFlagsFixedWidth; ConcreteSpansNonEmpty; SyntheticSpansEmpty; SourceBackedSpelling | Token absent | ABI and source-backed representation pass |
| tests/Lex/LexerIdentifierTest.cpp | AsciiIdentifier; UseFrom; Use1Fromage; DriverOkErrContextual; BareUnderscore; NonAsciiRejected; LocaleIndependent | Scanner absent | Correct kinds/flags/spans |
| tests/Lex/LexerOperatorTest.cpp | DotRangeInclusiveRange; ArrowAndMinusFamily; PlusFamily; Comparisons; Shifts; SlashSlashTwoTokens; SemicolonToken; NegativeNumberTwoTokens | Scanner absent | Exact maximal-munch sequences |
| tests/Lex/LexerLayoutTest.cpp | NestedSuites; MultipleDedents; BlankLine; CommentOnlyLine; TrailingComment; InlineSuite; MultilineParen; MultilineBracket; EofAfterCode; EofAfterNewline; Empty; LeadingIndent; InconsistentDedent; BomIndentedFirstLine; BomCommentFirstLine; CommentTabAccepted; CodeTabRejected; LoneCrDiagnosedAndRecoversAsNewline | Layout absent | Expected logical tokens/anchors pass, and lone CR has the T00-frozen diagnostic ID with a one-byte primary span |
| tests/Lex/LexerDelimiterTest.cpp | Match; StrayCloser; DeepMatchingCloser; CrossMismatch; UnclosedAtEof; DepthExact; DepthExceeded; RecoveryRestoresLayout | Delimiter state absent | Precise diagnostics/notes and later layout recovery |
| tests/Lex/LexerIntegerTest.cpp | DecimalLeadingZeros; Hex; Binary; Separators; EveryIntegerSuffix; ZeroU8; InvalidRadixDigit; PrefixWithoutDigit; RepeatedSeparator; BadSuffix; CandidateStopsAtPunctuation | Numeric scanner absent | One token/diagnostic per documented candidate |
| tests/Lex/LexerFloatTest.cpp | Fraction; ExponentCases; EveryFloatSuffix; SeparatorCases; FloatRange; IntegerRange; UnitMember; DeviceAtom; LeadingDotRejectedCompositionally; TrailingDotCompositionally; InvalidExponent; InvalidSuffix | Float scanner absent | Exact dot/range/exponent boundaries |
| tests/Lex/LexerLiteralTest.cpp | EmptyString; EveryEscape; HashInsideString; StringNewlineRecovery; StringEofRecovery; ByteEveryEscape; ByteExactlyOne; ByteEmpty; ByteTooLong; HexEscapeLengths; RawControl; RawNonAscii; PlainSingleQuotePolicy | Literal scanner absent | Allocation-free validation, correct IDs/spans/recovery |
| tests/Lex/LexerEncodingTest.cpp | ValidUtf8Comment; InvalidPrefix; InvalidContinuation; TruncatedSequence; Overlong; Surrogate; OutOfRange; MisplacedBom; RawNulCode; RawNulComment; RawNulLiteral | UTF-8 path absent | Policy and guaranteed advancement pass |
| tests/Lex/LexerErrorTest.cpp | One fixture per AC-E02 ID plus LoneCrStableDiagnostic; MultipleErrorsRecoverInOrder; InvalidRunCoalescing; ZeroLengthInvalidImpossible | Diagnostics absent | Stable structured ranges, mandatory lone-CR diagnosis, and useful recovery |
| tests/Lex/LexerLimitTest.cpp | TokenExactAndPlusOne; IndentExactAndPlusOne; DelimiterExactAndPlusOne; CommentExactAndPlusOne; DiagnosticExactAndPlusOne; CountersNearMax; IncompleteHasEof | Limits absent | Deterministic resource IDs/incomplete semantics |
| tests/Lex/CommentIndexTest.cpp | WholeLineSingle; CoalescesEqualIndent; DoesNotCoalesceBlank; DoesNotCoalesceDifferentIndent; Trailing; ConcreteNeighbors; MissingNeighbors; SourceSlice; LineCount; Indent; CapIncomplete; OffEquivalent | Comment index absent | Metadata exact and no semantic/token change |

## Driver and integration tests

| File | Test names / behavior | Expected before | Expected after |
| --- | --- | --- | --- |
| tests/Driver/ResultAdmissionTest.cpp | ExactBudget; OneByteOver; TokenDense; LineDense; CommentDense; DiagnosticDense; CompetingSourcesKeyOrder; ArithmeticOverflow | Admission absent | T00 accounting formula enforced before scheduling |
| tests/Driver/LexBatchTest.cpp | InMemorySingle; InMemoryAndFilesystemEquivalent; SortsSourceKeys; DuplicateKeys; MixedLoadFailures; MixedLexFailures; JobsOne; JobsMany; JobsAboveCount; WorkerCountDeepEquality; SourceStateUnchanged; IncompleteNeverSuccess | Driver absent | Deterministic complete batch semantics |
| tests/Driver/TokenDumpTest.cpp | StableRecordFields; EscapesBackslashQuoteControls; EscapesNonAsciiBytes; SyntheticEmptySpelling; MultipleSourcesSorted; RepeatedSerializationIdentical | Dump absent | ASCII-only contract frozen |
| tests/Integration/LexCliTest.* | UsageNoCommand; UsageNoPath; UsageUnknownOption; JobsZero; JobsMalformed; JobsOverflow; DashDash; ValidSingle; ValidMultiple; DefaultStdoutEmpty; DumpGolden; DiagnosticGolden; StreamSeparation; WrongExtensionMatrix; Missing; LexicalFailure; Incomplete; JobsGoldenEquivalent; VirtioAppliance | Executable absent | Exit 0/1/2 and exact normalized streams |

Integration fixtures/goldens should live under:

- tests/Integration/fixtures/use-and-nested.wr
- tests/Integration/fixtures/mixed-layout-literals.wr
- tests/Integration/fixtures/contextual-regressions.wr
- tests/Integration/fixtures/multiple-errors.wr
- tests/Integration/golden/*.tokens
- tests/Integration/golden/*.stderr

Construct CRLF and missing-final-newline variants in test code from canonical byte strings; do not
check in newline-sensitive duplicates.

## Corpus, property, fuzz, and benchmark tests

| File | Test names / behavior | Expected before | Expected after |
| --- | --- | --- | --- |
| tests/Lex/LexerCorpusTest.cpp | EvidenceManifest_AllEntries; VirtioAppliance_ZeroDiagnostics; VirtioAppliance_AllInvariants | Manifest/lexer absent | Every curated form and full existing .wr source pass lexically |
| tests/Lex/LexerPropertyTest.cpp | SpansInBoundsAndOrdered; ExactlyOneEofAtSize; CompleteLayoutUnwound; Repeatable; RetentionIndependent; TransitionProgress | Generator absent | Thousands of deterministic seeded cases pass |
| tests/Driver/LexBatchPropertyTest.cpp | InputPermutationUsesKeyOrder; WorkerCountsEquivalent; DiagnosticsTotalOrder; BudgetAdmissionDeterministic | Batch absent | Deep equality for generated batches |
| fuzz/LexerFuzz.cpp | Arbitrary bytes through in-memory frozen source and both comment modes under reduced limits | Target absent | No finding; all invariants asserted |
| fuzz/LexBatchFuzz.cpp | Bounded decoded many-file inputs across jobs 1/N | Target absent | No race/crash/invariant finding |
| benchmarks/SourceBench.cpp | load, line index, byte sizes, failure sink | Target absent | Required metrics emitted |
| benchmarks/LexBench.cpp | worked, 1/10 MiB/near-cap, token/comment dense, long identifier/number, deep layout/delimiters, valid/invalid, comments on/off | Target absent | Required metrics emitted |
| benchmarks/BatchBench.cpp | varied many-file batch jobs 1/N | Target absent | Scheduling metrics emitted |
| tools/compare-benchmarks.* tests | noise band, 10 percent boundary, reproducible regression, missing/mismatched metadata | Comparator absent | Correct alert behavior |

Seed fuzz corpora with every unit/integration/evidence fixture and all minimized regressions. Do not
copy the 49,033-byte source into another tracked fixture; reference the canonical repository path
for tests and seed it into generated build output for fuzz runs.

## Existing tests and commands

There are currently no executable tests. After T02 creates presets, the standard command contract
should be:

1. cmake --preset dev-debug
2. cmake --build --preset dev-debug
3. ctest --preset dev-debug --output-on-failure
4. cmake --preset ci-clang and cmake --build/ctest --preset ci-clang
5. cmake --preset ci-gcc and cmake --build/ctest --preset ci-gcc
6. cmake --preset asan-ubsan and cmake --build/ctest --preset asan-ubsan
7. cmake --preset tsan and the TSan-labeled batch tests on a supported platform
8. cmake --preset fuzz and the documented continuous/scheduled fuzzer commands
9. cmake --preset bench-release and the benchmark/comparator commands on the pinned runner

T00 may change preset names only before T02, and the final names must be used consistently in CI and
docs. “No LLVM” must be verified in a clean environment, not only by omitting an option on a machine
where LLVM happens to be installed.

# 9. Discovery and Drift Protocol

No silent drift is allowed. The orchestrator owns a live decision record at
docs/implementation/lexing-and-wr-source-consumption-decisions.md and rechecks git status before
every task wave.

## Acceptable drift

The following may change without amending the design when behavior, dependency direction, and
acceptance coverage remain identical:

- exact private class/helper/file names and decomposition;
- test framework or benchmark framework selected and pinned in T00;
- vector reserve hints, provided the admitted maximum-capacity proof remains valid;
- diagnostic prose, provided stable IDs, severity, ranges, ordering, and golden intent remain;
- eager line-start construction during load versus one explicit pre-freeze pass;
- CMake minimum and supported compiler versions justified by the verified matrix;
- CLI parsing library/internal implementation while the command/stream/exit contract stays exact;
- a measured Token size/alignment deviation when unsafe packing is avoided, the performance effect
  is approved, AC-P01 evidence is updated, and public span semantics do not change.

Even acceptable drift must be recorded when it affects file ownership, commands, measurements, or
tests.

## Mandatory decision record

For every meaningful deviation or discovery, add one entry with:

1. unique decision ID and date;
2. task/agent and affected files/symbols;
3. what changed from this plan or the design;
4. why it changed;
5. evidence from current code, tests, toolchain, or measurements;
6. alternatives considered;
7. affected acceptance criteria;
8. tests/evidence added or changed;
9. whether design, lexical reference, architecture doc, and this plan were updated;
10. reviewer approval and any follow-up.

Do not use a code comment or test name as the only record of an ambiguity.

## Changes that require updating this implementation plan

Update this file before continuing when:

- tasks are split/merged/reordered or their dependency/parallel safety changes;
- an agent needs to edit outside its file allowlist;
- public API/file/target boundaries differ materially from T03–T11;
- a required test moves, is replaced, or needs a different evidence method;
- a new environment gate changes verification commands or completion sequencing;
- an acceptance criterion needs additional tasks even if its language meaning is unchanged.

The update must preserve the original criterion ID and explain how execution/evidence changes.

## Changes that require updating the design

Amend docs/designs/lexing-and-wr-source-consumption.md before merging when implementation would
change:

- encoding, BOM/NUL policy, comments, layout, identifiers, literals, operators, keywords, or
  use/from syntax;
- exact .wr extension behavior or CLI success/incomplete semantics;
- immutable source ownership, token/span width/lifetime, freeze boundary, deterministic source-key
  order, worker-local ownership, or merge determinism;
- comments from a bounded non-semantic side index into tokens or semantic inputs;
- progress, asymptotic complexity, resource-limit safety, or parser-handoff invariants;
- dependency direction or the LLVM/MLIR-free public frontend;
- a material source-size/result-budget policy or performance architecture.

The lexical reference, token table, tests, plan, and design must change in the same reviewed patch.
Do not weaken an acceptance criterion to make an implementation pass.

## Stop conditions: the design is invalid for implementation

Stop source changes and return to design review when:

- current formal grammar or newly authoritative product direction contradicts layout, literals,
  encoding, keyword policy, or use/from spelling;
- concurrent repository work creates a real public API/compatibility contract this greenfield plan
  would break;
- source/result bounds cannot be implemented with checked finite memory and guaranteed progress;
- actual required source sizes make 32-bit spans unsafe;
- opened-source safety on a required platform cannot meet the design without an ownership/API
  change;
- frontend public APIs would have to expose LLVM/MLIR;
- module loading becomes a feature requirement before its identity/path/cycle/security design;
- stable source identities/admission cannot be chosen before worker scheduling;
- the pinned performance results show the owned batch architecture materially violates the required
  scale and cannot be repaired privately;
- AC-P04 is required for release but no pinned/calibrated runner can be provided.

Stopping is not failure handling through a hidden workaround. Record the evidence and which
acceptance criteria are blocked.

## Preserving original requirements under implementation changes

When implementation details change, start from the acceptance ledger rather than the old class
sketch. Maintain immutable exact-byte snapshots, compact checked spans, trivia-free deterministic
tokens, bounded non-semantic comment retention, structured stable diagnostics, finite resources,
linear/progress guarantees, one/many-worker equivalence, .wr-only CLI behavior, and an LLVM-free
frontend. Update task/test ownership so every original criterion still has executable evidence.

# 10. Verification Gates

No gate may be waived silently. A failed gate returns work to the owning task; downstream evidence
collected against changed production code is stale and must be rerun.

## Gate 0 — Design/readiness

- T00 decision log exists and all seven pre-code topics in section 1 are resolved or formally
  blocked.
- Current git status/tree still supports the greenfield plan.
- Lexical reference/evidence plan has no unresolved language contradiction.
- Toolchain, dependency, sanitizer, and benchmark-runner facts are evidence-backed.

## Gate 1 — Per-task diff inspection

After every edit task:

- inspect git status and the complete task-scoped diff;
- verify only allowlisted files changed and no user/unrelated changes were overwritten;
- inspect new public headers for self-containment, ownership, exception/RTTI assumptions, and
  backend leakage;
- verify build flags, noexcept conventions, and process-boundary allocation handling match the T00
  policy; reject lower-layer bad_alloc catches that attempt to continue;
- inspect new CMake for explicit sources, private/public link scope, target-scoped flags, and
  missing install/build interfaces as applicable;
- search for TODO, FIXME, stub, placeholder, disabled-test, unconditional success, sleep-based
  synchronization, raw stdout/stderr in lower layers, locale ctype, unchecked casts/arithmetic,
  stored string_view/raw-pointer lexemes, and LLVM/MLIR references;
- run the task’s targeted tests and inspect test assertions, not only the exit status;
- update decision/evidence records before marking the task complete.

## Gate 2 — Foundation

After T04:

- Basic and Source targeted tests pass in debug and ASan/UBSan.
- Clean no-LLVM configuration builds Basic and Source.
- Source lifecycle/freeze and file-failure tests pass.
- Public API review finds no dangling view path, unchecked span, or lazy mutation.

After T05/T06:

- Diagnostics and token-table suites pass separately and together.
- Diagnostic caps/order and token ABI are documented.
- Token definition and lexical-reference consistency check passes.
- Target DAG still matches Basic, Source, Diagnostics, Lex, Driver.

## Gate 3 — Per-file lexer correctness

After each of T07, T08, and T09:

- run only the newly affected lexer tests first, then all Lex unit tests;
- run ASan/UBSan on invalid/recovery/EOF/limit matrices;
- inspect the scanner diff and state invariants;
- run property smoke over deterministic seeds;
- after T09, lex all evidence fixtures and the canonical worked file with zero diagnostics.

Do not begin Driver if any token/span/progress/comment-retention invariant is open.

## Gate 4 — Batch and CLI integration

After T10/T11:

- all Driver deep-equality and result-admission tests pass;
- repeated one/many-worker runs are byte-identical;
- supported TSan stress is clean;
- integration process tests pass for exit 0/1/2 and stream separation;
- token dumps are ASCII-only, stable, source-key ordered, and golden-reviewed;
- a clean no-LLVM full unit/integration run passes.

## Gate 5 — Static and full-suite checks

Run, where configured by T00/T02:

- format check on all C++/CMake/JSON/Markdown files covered by project policy;
- clang-tidy or the selected static analysis on production targets;
- supported Clang debug/release build and tests;
- supported GCC debug/release build and tests;
- public-header self-containment compile;
- forbidden dependency/include scan;
- no placeholder translation unit or T02 placeholder marker remains in any production/test target;
- CMake target-DAG check;
- docs link and token-doc consistency checks;
- full CTest suite with no skipped required test;
- ASan/UBSan full suite.

Local absence of clang-format/clang-tidy is not a waiver; their pinned CI jobs supply evidence.

## Gate 6 — Fuzz/concurrency

- deterministic property suites pass with recorded seed/iteration counts;
- continuous and scheduled lexer fuzz durations selected in T00 run under ASan/UBSan;
- batch fuzz/property tests compare jobs 1/N;
- supported TSan stress runs repeatedly with no race;
- every found crash/hang/assertion/invariant issue has a minimized permanent regression;
- no crash artifact or unexplained timeout remains.

## Gate 7 — Performance

- supported Token size/alignment meets AC-P01 or approved measured deviation is documented;
- allocation profiling shows no per-token/identifier/literal/comment-text allocation;
- every benchmark corpus/metric is present;
- pinned 1x/10x median runtime and peak memory are both no greater than 12x;
- runner identity and calibration are stored with the baseline;
- comparator tests prove the greater-than-10-percent reproducible alert and noise behavior;
- CI benchmark workflow is operational on the pinned runner.

Performance evidence is invalidated by any later production-code change in Source, Lex, or Driver.

## Gate 8 — Final acceptance and clean-room review

- Re-run the complete configured suite from a clean build directory.
- Inspect the final cumulative diff and git status, including generated/untracked files.
- Walk all 40 ledger entries and attach concrete evidence.
- Run SA-REVIEW after implementation is otherwise complete.
- Fix every valid finding, rerun affected gates and downstream full checks, and obtain reviewer
  confirmation.
- Confirm docs, decision log, lexical reference, token table, APIs, tests, and measured behavior
  agree.

# 11. Rollback / Failure Handling

## Identify partial changes

At task start and end, capture git status, task-owned paths, and the task-scoped diff. Keep separate
review checkpoints per task/wave. If the implementation workflow uses commits, use one intentional
commit per accepted task or tightly coupled serialized lexer slice; do not mix unrelated user
changes. If it does not use commits, retain patch artifacts/diff summaries in the task report.

## Recover from a bad subagent patch

1. Stop dependent agents before they build on the patch.
2. Inspect the exact diff and separate user/pre-existing changes from the agent’s paths.
3. Preserve useful tests, minimized reproducers, measurements, and decision discoveries outside the
   rejected production patch when they remain valid.
4. Revert only the agent-owned hunks with an inverse patch or, when the task has an isolated commit,
   a non-destructive revert. Never use a hard reset or path checkout that can destroy user work.
5. Restore the last passing gate and rerun it.
6. Reassign the task with the failure mode, reproducer, allowed files, and unchanged acceptance
   requirements made explicit.

An agent may not “fix” a failed test by weakening/removing its assertion, broadening an accepted
syntax, raising a limit, disabling a sanitizer, or updating a golden without explaining the
behavioral cause.

## Avoid dead or half-wired code

- Do not merge unused alternate scanners, inactive compatibility branches, placeholder adapters,
  empty test targets, fake feature flags, or comments promising later correctness.
- A hard-limit path must be reachable and tested in the same task that adds it.
- New public APIs must have a production caller or a clearly required boundary test.
- If a task is abandoned, remove its unreachable source/build registration while preserving the
  documented discovery and valid regression tests for the replacement path.
- Re-run forbidden-stub and unused/dead-code checks after rollback.

## Preserve useful discoveries

Keep the decision-log entry, evidence citations, benchmark/fuzz reproducer, and root-cause analysis
even if code is reverted. Mark measurements from reverted code as stale. If the discovery changes a
durable language/architecture decision, amend the design before trying another implementation.

## When to abandon a path

Abandon the current implementation approach when:

- two fixes preserve neither progress nor span/lifetime/resource invariants and evidence shows the
  helper/state decomposition is wrong;
- the capacity proof cannot bound real vector/metadata growth;
- the chosen portable file API cannot satisfy opened-object/bounded-read policy on required
  platforms;
- the selected test/benchmark dependency prevents the promised offline/portable build and a
  supported alternative is available;
- profiling shows a structural allocation/scaling problem, not a local optimization issue;
- sanitizer/fuzz findings reveal an ownership or recursive-state architecture flaw.

Private alternatives—different helpers, bounded container/growth strategy, file backend, test
framework, or worker-pool implementation—may be selected through the decision log while preserving
the design. Switching from owned snapshots to LLVM buffers/streaming, from comment side index to
drop/comment tokens, from layout tokens to another grammar, or from deterministic pre-admission to
shared scheduling changes the design and requires stopping for a formal amendment. Do not choose an
option from design section 5 merely because the preferred implementation is temporarily difficult.

# 12. Final Completion Criteria

Implementation is complete only when all statements below are true:

- [ ] All 40 acceptance criteria in section 2 are checked with traceable evidence.
- [ ] T00 decisions are recorded; all meaningful drift entries include change, reason, codebase
  evidence, acceptance impact, and test impact.
- [ ] Any required design, lexical-reference, architecture, and plan amendments are reviewed and
  agree with implementation.
- [ ] Basic, Source, Diagnostics, Lex, Driver, and CLI targets follow the required acyclic DAG and
  configure/build/test without LLVM or MLIR.
- [ ] All targeted unit, integration, golden, property, no-LLVM, Clang, GCC, ASan/UBSan, supported
  TSan, fuzz-duration, docs/static, and benchmark-comparator gates pass.
- [ ] The exact worked .wr file and every evidence-manifest fixture lex with zero diagnostics and
  satisfy token/span invariants.
- [ ] One-worker and many-worker batches are deeply and byte-for-byte equivalent for tokens,
  comments, diagnostics, dumps, IDs, completion, and exit behavior.
- [ ] Incomplete results cannot report success or cross the future parser-handoff boundary.
- [ ] Token ABI/allocation/linear-scaling/baseline/regression-alert evidence satisfies AC-P01–P05 on
  the approved environments.
- [ ] The final cumulative diff and git status have been inspected; no generated build products or
  unrelated/user changes are included.
- [ ] Independent clean-room review has completed, every valid finding is fixed, affected gates are
  rerun, and no valid finding remains open.
- [ ] No stubs, TODO correctness gaps, hacks, fake or assertion-free tests, blanket golden updates,
  silent required-test skips, placeholder behavior, compatibility shims, or dead code remain.
- [ ] No parsing, module loading/resolution, AST/sema, Wrela IR, MLIR, LLVM lowering, or other
  out-of-scope behavior has been added.

If any item is false—including unavailable pinned performance infrastructure—the implementation is
not complete. Report the specific open acceptance criterion and evidence needed; do not relabel it
as follow-up work.
