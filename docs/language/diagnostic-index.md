# Diagnostic code index

Every stable source diagnostic code the workspace can attach to a
`wrela_diagnostics::Diagnostic`, with the crate that owns it. The list is
derived from workspace source, never from running the compiler, and
`cargo xtask diagnostic-index` fails the build when source and this file
disagree in either direction.

## What a code is here

A *source diagnostic code* is a value assigned to
`wrela_diagnostics::Diagnostic::code` (`crates/wrela-diagnostics/src/lib.rs`).
That is the field CI policy, the engine protocol, and every conformance fixture
key on, so it is the only namespace this index claims to cover.

Codes are listed, owners are listed, and nothing else is. Descriptions are
deliberately absent: no per-code description exists in source that can be
extracted mechanically, and 578 hand-written summaries would rot silently
against the messages they claim to paraphrase. A smaller true index beats a
larger speculative one.

## How the index is derived

`xtask` masks comments and string contents (byte offsets preserved), drops
`#[cfg(test)]` items, and then resolves every position that writes
`Diagnostic::code` — an assignment `diagnostic.code = Some(...)` or a
`Diagnostic { code: Some(...) }` field inside a function body. Each such
expression must reduce to string literals by one of eight admitted rules:

1. a string literal, optionally followed by `.to_owned()`, `.to_string()`, or
   `.into()`;
2. a file-local `const NAME: &str = "...";`;
3. a bounded-copy helper (`copy_static_analysis_text`, `clone_text`,
   `copy_builtin_attribute_diagnostic_text`, `try_copy_string_cancellable`),
   read through at its first argument;
4. an `if`/`else` that selects between code expressions — both branches count;
5. the identifier `code` bound as a parameter of the enclosing function, which
   makes that function a *carrier*: its same-file call sites are then resolved
   at the matching argument position, transitively. An **exported** carrier is
   refused instead — its call sites could live in another file, and searching
   only the defining file would under-report;
6. the identifier `code` bound by a `let` or `for` binder whose initializer
   selects among code-shaped literals — all of them count;
7. a call whose arguments are all code-shaped literals (a selector such as
   `form.code("...", "...")`) — all of them count;
8. a field access ending in `.code`, which makes the file's struct-literal
   `code:` initializers additional code positions.

Rules 4, 6, and 7 over-approximate a selection rather than guessing which branch
runs, so the index can never miss a code a site can emit. Anything that does not
reduce is **rejected by name** — the check names the file, line, and expression
and fails. Nothing is silently skipped.

## What this index does not cover

These are real, user-visible strings, but they are *not* `Diagnostic::code`
values and are out of scope here:

- **Lint names.** `crates/wrela-compiler/src/local_lint.rs` copies the
  registered `LintName` into `Diagnostic::code` for lint findings. The lint
  registry, not a phase, owns those names. Recorded as an exclusion below.
- **Lowering refusal tags.** `wrela-semantic-lower`, `wrela-flow-lower`, and
  `wrela-machine-lower` reject unsupported input with
  `LowerError::UnsupportedInput { feature }` / `MachineLowerError`, whose
  `feature` strings are code-shaped prose such as
  `"semantic-enum-heterogeneous-lowering-pending (per-variant differing scalar
  enum payloads)"`. They never reach `Diagnostic::code`.
- **Engine protocol synthetic codes.** `crates/wrela-compiler/src/engine.rs`
  pushes `engine-*` codes onto `EngineEvent::Diagnostic`, a transport event
  rather than a source diagnostic.
- **Test-only literals.** Codes asserted inside `#[cfg(test)]` items are
  ignored; only production construction sites define the index.

## Enforcement

- `cargo xdiag` (`cargo xtask diagnostic-index`) re-extracts and reconciles,
  naming added, removed, duplicated, and re-owned codes. `cargo xnightly` runs
  it as a step.
- `xtask` tests: `extraction_reads_every_admitted_code_carrier_form`,
  `extraction_records_the_owning_crate_of_every_code`,
  `extraction_fails_closed_on_a_non_literal_construction_site`,
  `extraction_fails_closed_on_an_exported_code_carrier`,
  `reconciliation_accepts_an_exact_index_and_names_drift_in_each_direction`,
  `exclusion_reconciliation_rejects_undeclared_and_stale_non_literal_sites`,
  `workspace_diagnostic_codes_have_only_the_declared_non_literal_exclusions`,
  and `documented_diagnostic_index_matches_workspace_sources`.

## Codes

<!-- diagnostic-index: codes begin -->
```text
hir-ambiguous-import-name wrela-hir-lower
hir-assert-message-string wrela-hir-lower
hir-capacity-argument-kind wrela-hir-lower
hir-closure-receiver wrela-hir-lower
hir-comparison-chain wrela-hir-lower
hir-conflicting-entry-attribute wrela-hir-lower
hir-duplicate-attribute-argument wrela-hir-lower
hir-duplicate-closure-parameter wrela-hir-lower
hir-duplicate-declaration wrela-hir-lower
hir-duplicate-field wrela-hir-lower
hir-duplicate-generic-parameter wrela-hir-lower
hir-duplicate-parameter wrela-hir-lower
hir-duplicate-scope-exit-binding wrela-hir-lower
hir-duplicate-variant wrela-hir-lower
hir-duplicate-variant-field wrela-hir-lower
hir-extra-generic-argument wrela-hir-lower
hir-field-member-name-conflict wrela-hir-lower
hir-generic-argument-count wrela-hir-lower
hir-import-name-conflict wrela-hir-lower
hir-invalid-assignment-target wrela-hir-lower
hir-invalid-call-arguments wrela-hir-lower
hir-invalid-entry-attribute wrela-hir-lower
hir-invalid-literal wrela-hir-lower
hir-invalid-place-expression wrela-hir-lower
hir-invalid-receiver wrela-hir-lower
hir-invalid-statement-attribute wrela-hir-lower
hir-invalid-test-attribute-argument wrela-hir-lower
hir-invalid-uninterrupted-attribute wrela-hir-lower
hir-local-redeclaration-requires-shadow wrela-hir-lower
hir-missing-closure-parameter-type wrela-hir-lower
hir-missing-parameter-type wrela-hir-lower
hir-module-path-mismatch wrela-hir-lower
hir-nonnamespace-qualified-name wrela-hir-lower
hir-pattern-binding-without-scope wrela-hir-lower
hir-positional-after-named-attribute-argument wrela-hir-lower
hir-qualified-name-kind wrela-hir-lower
hir-reexport-name-conflict wrela-hir-lower
hir-region-argument-name wrela-hir-lower
hir-region-qualified-name wrela-hir-lower
hir-region-used-as-type wrela-hir-lower
hir-region-used-as-value wrela-hir-lower
hir-self-type-arguments wrela-hir-lower
hir-self-type-outside-nominal-context wrela-hir-lower
hir-shadow-without-binding wrela-hir-lower
hir-statement-attribute-requires-loop wrela-hir-lower
hir-unknown-attribute wrela-hir-lower
hir-unknown-import-module wrela-hir-lower
hir-unknown-import-name wrela-hir-lower
hir-unresolved-dot-variant wrela-hir-lower
hir-unresolved-name wrela-hir-lower
hir-unresolved-pattern-constructor wrela-hir-lower
hir-unresolved-qualified-base wrela-hir-lower
hir-unresolved-qualified-name wrela-hir-lower
semantic-access-marker-mismatch wrela-sema
semantic-access-temporary wrela-sema
semantic-actor-body-not-supported wrela-sema
semantic-actor-empty wrela-sema
semantic-actor-handle-shape wrela-sema
semantic-actor-install-class wrela-sema
semantic-actor-install-role wrela-sema
semantic-actor-install-shape wrela-sema
semantic-actor-instance-ambiguous wrela-sema
semantic-actor-mailbox-capacity wrela-sema
semantic-actor-mailbox-constant wrela-sema
semantic-actor-mailbox-shape wrela-sema
semantic-actor-member-kind wrela-sema
semantic-actor-method-attribute wrela-sema
semantic-actor-method-body wrela-sema
semantic-actor-method-shape wrela-sema
semantic-actor-method-signature wrela-sema
semantic-actor-private-helper-not-supported wrela-sema
semantic-actor-receiver wrela-sema
semantic-actor-reply-definite-result wrela-sema
semantic-actor-reply-single-flight wrela-sema
semantic-actor-reply-type-mismatch wrela-sema
semantic-actor-reply-type-pending wrela-sema
semantic-actor-reply-unconsumed wrela-sema
semantic-actor-role wrela-sema
semantic-actor-send-call wrela-sema
semantic-actor-send-chain wrela-sema
semantic-actor-send-mailbox-over-bound wrela-sema
semantic-actor-send-payload-not-supported wrela-sema
semantic-actor-send-producer wrela-sema
semantic-actor-send-receiver wrela-sema
semantic-actor-send-reply-discarded wrela-sema
semantic-actor-send-single-message-bound wrela-sema
semantic-actor-send-target wrela-sema
semantic-actor-state-authority wrela-sema
semantic-actor-state-compound-assignment-pending wrela-sema
semantic-actor-state-field-pending wrela-sema
semantic-actor-state-field-type wrela-sema
semantic-actor-state-initializer-pending wrela-sema
semantic-actor-state-initializer-required wrela-sema
semantic-actor-state-place-shape-pending wrela-sema
semantic-actor-state-receiver wrela-sema
semantic-actor-state-region-missing wrela-sema
semantic-actor-state-root-pending wrela-sema
semantic-actor-state-shape-pending wrela-sema
semantic-actor-struct-shape wrela-sema
semantic-actor-try-send-recurring-pending wrela-sema
semantic-actor-try-send-single-attempt-bound wrela-sema
semantic-actor-wiring-field wrela-sema
semantic-actor-wiring-handle wrela-sema
semantic-actor-wiring-missing wrela-sema
semantic-actor-wiring-name wrela-sema
semantic-actor-wiring-shape wrela-sema
semantic-actor-wiring-target wrela-sema
semantic-admission-result-consumer-pending wrela-sema
semantic-admission-result-core-shape wrela-sema
semantic-argument-duplicate wrela-sema
semantic-argument-label-forbidden wrela-sema
semantic-argument-label-required wrela-sema
semantic-argument-unknown-label wrela-sema
semantic-assignment-ownership wrela-sema
semantic-assignment-target wrela-sema
semantic-assignment-uninitialized wrela-sema
semantic-async-call-in-sync-function wrela-sema
semantic-async-outcome-consumer-pending wrela-sema
semantic-async-outcome-core-shape wrela-sema
semantic-async-outcome-question-pending wrela-sema
semantic-async-outcome-type-pending wrela-sema
semantic-async-result-not-awaited wrela-sema
semantic-await-in-sync-function wrela-sema
semantic-await-operand wrela-sema
semantic-await-result-type wrela-sema
semantic-binary-operand wrela-sema
semantic-binary-result wrela-sema
semantic-binary-type wrela-sema
semantic-binary-type-mismatch wrela-sema
semantic-bounded-interpolation-context-pending wrela-sema
semantic-bounded-interpolation-expression-pending wrela-sema
semantic-bounded-interpolation-format-pending wrela-sema
semantic-bounded-interpolation-isr wrela-sema
semantic-bounded-interpolation-persistence-pending wrela-sema
semantic-bounded-interpolation-value-required wrela-sema
semantic-bounded-interpolation-value-type wrela-sema
semantic-bounded-string-consumer-pending wrela-sema
semantic-branch-ownership-mismatch wrela-sema
semantic-branch-value-join-state wrela-sema
semantic-branch-value-type-mismatch wrela-sema
semantic-builtin-attribute-not-implemented wrela-sema
semantic-cleanup-cycle wrela-sema
semantic-compound-assignment-type wrela-sema
semantic-compound-overlap wrela-sema
semantic-comptime-aggregate-not-supported wrela-sema
semantic-comptime-arithmetic wrela-sema
semantic-comptime-assertion wrela-sema
semantic-comptime-body wrela-sema
semantic-comptime-borrowed-value-move wrela-sema
semantic-comptime-call-argument wrela-sema
semantic-comptime-call-target wrela-sema
semantic-comptime-constructor-argument wrela-sema
semantic-comptime-expression wrela-sema
semantic-comptime-field wrela-sema
semantic-comptime-field-private wrela-sema
semantic-comptime-integer-literal wrela-sema
semantic-comptime-local wrela-sema
semantic-comptime-missing-return wrela-sema
semantic-comptime-operation-not-implemented wrela-sema
semantic-comptime-parameter wrela-sema
semantic-comptime-resource-limit wrela-sema
semantic-comptime-shift-count wrela-sema
semantic-comptime-shift-result-loss wrela-sema
semantic-comptime-signature-not-supported wrela-sema
semantic-comptime-statement wrela-sema
semantic-comptime-type-mismatch wrela-sema
semantic-comptime-uninitialized wrela-sema
semantic-comptime-use-after-move wrela-sema
semantic-constructor-result-type wrela-sema
semantic-conversion-result wrela-sema
semantic-conversion-type wrela-sema
semantic-core-outcome-construction-forbidden wrela-sema
semantic-derived-eq-required wrela-sema
semantic-derived-from-argument wrela-sema
semantic-derived-from-required wrela-sema
semantic-derived-from-result-type wrela-sema
semantic-deriving-eq-shape-pending wrela-sema
semantic-deriving-from-profile-pending wrela-sema
semantic-deriving-from-shape wrela-sema
semantic-deriving-unknown wrela-sema
semantic-dot-variant-context-required wrela-sema
semantic-dot-variant-unknown-variant wrela-sema
semantic-double-take wrela-sema
semantic-driver-handler-waits wrela-sema
semantic-ephemeral-question-forbidden wrela-sema
semantic-exclusive-place-projection wrela-sema
semantic-explicit-copy-required wrela-sema
semantic-float-context-required wrela-sema
semantic-for-array-element-shape wrela-sema
semantic-for-array-element-type wrela-sema
semantic-for-array-empty-type-pending wrela-sema
semantic-for-array-take-pending wrela-sema
semantic-for-binding-mutated wrela-sema
semantic-for-inclusive-range-too-large wrela-sema
semantic-for-iteration-target wrela-sema
semantic-for-loop-carried-state-pending wrela-sema
semantic-for-range-bound-not-constant wrela-sema
semantic-for-range-take-forbidden wrela-sema
semantic-for-stored-array-async-pending wrela-sema
semantic-for-stored-array-element-shape wrela-sema
semantic-for-stored-array-element-type wrela-sema
semantic-for-stored-array-empty-type-pending wrela-sema
semantic-for-stored-array-multiple-uses-pending wrela-sema
semantic-for-stored-array-reassigned wrela-sema
semantic-for-stored-array-take-pending wrela-sema
semantic-for-stored-array-unavailable wrela-sema
semantic-for-stored-array-use-pending wrela-sema
semantic-generic-function-argument-count wrela-sema
semantic-generic-function-argument-type wrela-sema
semantic-generic-function-inference-conflict wrela-sema
semantic-generic-function-inference-required wrela-sema
semantic-generic-function-parameter-count wrela-sema
semantic-generic-function-parameter-kind wrela-sema
semantic-generic-function-signature-pending wrela-sema
semantic-generic-function-specialization-key wrela-sema
semantic-generic-interface-argument-count wrela-sema
semantic-generic-interface-argument-type wrela-sema
semantic-generic-interface-parameter-kind wrela-sema
semantic-generic-method-argument-type wrela-sema
semantic-generic-method-inference-conflict wrela-sema
semantic-generic-method-inference-required wrela-sema
semantic-generic-method-parameter-count wrela-sema
semantic-generic-method-parameter-kind wrela-sema
semantic-generic-method-receiver-pending wrela-sema
semantic-generic-method-shape-pending wrela-sema
semantic-generic-method-signature-pending wrela-sema
semantic-hardware-actor-not-supported wrela-sema
semantic-if-expression-type wrela-sema
semantic-image-constructor-body wrela-sema
semantic-image-constructor-color wrela-sema
semantic-image-constructor-kind wrela-sema
semantic-image-constructor-missing wrela-sema
semantic-image-install-base wrela-sema
semantic-image-name wrela-sema
semantic-image-name-mismatch wrela-sema
semantic-image-result wrela-sema
semantic-image-target wrela-sema
semantic-init-argument wrela-sema
semantic-init-assignment-shape wrela-sema
semantic-init-control-flow-pending wrela-sema
semantic-init-fallible-rollback-pending wrela-sema
semantic-init-field-contract-pending wrela-sema
semantic-init-generic-pending wrela-sema
semantic-init-linearity-pending wrela-sema
semantic-init-owner wrela-sema
semantic-init-parameter-shape wrela-sema
semantic-init-partial wrela-sema
semantic-init-receiver-shape wrela-sema
semantic-init-zero-sized-pending wrela-sema
semantic-interface-duplicate-impl wrela-sema
semantic-interface-impl-visibility wrela-sema
semantic-interface-operator-missing wrela-sema
semantic-interface-orphan wrela-sema
semantic-interface-signature-mismatch wrela-sema
semantic-interface-unsupported wrela-sema
semantic-iso-pool-actor-integration-pending wrela-sema
semantic-iso-pool-base wrela-sema
semantic-iso-pool-brand wrela-sema
semantic-iso-pool-brand-reused wrela-sema
semantic-iso-pool-capacity wrela-sema
semantic-iso-pool-capacity-overflow wrela-sema
semantic-iso-pool-payload-capacity wrela-sema
semantic-iso-pool-shape wrela-sema
semantic-isr-not-supported wrela-sema
semantic-linear-value-not-consumed wrela-sema
semantic-literal-type-mismatch wrela-sema
semantic-method-call-ambiguous wrela-sema
semantic-method-call-argument-count wrela-sema
semantic-method-call-not-found wrela-sema
semantic-method-call-receiver-access-pending wrela-sema
semantic-method-call-receiver-expression-pending wrela-sema
semantic-method-call-result-type wrela-sema
semantic-method-call-shape-pending wrela-sema
semantic-mutate-read-only wrela-sema
semantic-no-promote-escape wrela-sema
semantic-no-promote-target wrela-sema
semantic-overlapping-access wrela-sema
semantic-projected-assignment-base wrela-sema
semantic-projected-assignment-compound-pending wrela-sema
semantic-projected-assignment-field wrela-sema
semantic-projected-assignment-nested-pending wrela-sema
semantic-projected-assignment-root-pending wrela-sema
semantic-projected-assignment-shape-pending wrela-sema
semantic-projection-argument-place-pending wrela-sema
semantic-projection-await wrela-sema
semantic-projection-body-form-pending wrela-sema
semantic-projection-body-required wrela-sema
semantic-projection-call-signature wrela-sema
semantic-projection-carrier-rebound wrela-sema
semantic-projection-condition-pending wrela-sema
semantic-projection-generic-pending wrela-sema
semantic-projection-multiple-yields wrela-sema
semantic-projection-mutable-source wrela-sema
semantic-projection-receiver-call-pending wrela-sema
semantic-projection-source-taken wrela-sema
semantic-projection-wrapped-carrier-pending wrela-sema
semantic-projection-yield-field wrela-sema
semantic-projection-yield-required wrela-sema
semantic-projection-yield-source wrela-sema
semantic-projection-yield-type wrela-sema
semantic-runtime-aggregate-not-supported wrela-sema
semantic-runtime-array-match-alternatives-pending wrela-sema
semantic-runtime-array-match-arity wrela-sema
semantic-runtime-array-match-element-alternatives-pending wrela-sema
semantic-runtime-array-match-element-shape wrela-sema
semantic-runtime-array-match-element-type wrela-sema
semantic-runtime-array-match-empty-type-pending wrela-sema
semantic-runtime-array-match-guard-pending wrela-sema
semantic-runtime-array-match-literal-type wrela-sema
semantic-runtime-array-match-negative-literal-pending wrela-sema
semantic-runtime-array-match-nonexhaustive wrela-sema
semantic-runtime-array-match-pattern-shape wrela-sema
semantic-runtime-array-match-take-pending wrela-sema
semantic-runtime-assertion-expression-limit wrela-sema
semantic-runtime-assertion-message-limit wrela-sema
semantic-runtime-assertion-not-supported wrela-sema
semantic-runtime-assertion-selection wrela-sema
semantic-runtime-constructor-access wrela-sema
semantic-runtime-constructor-argument wrela-sema
semantic-runtime-enum-constructor-access wrela-sema
semantic-runtime-enum-constructor-argument wrela-sema
semantic-runtime-enum-generic-not-supported wrela-sema
semantic-runtime-enum-payload-shape wrela-sema
semantic-runtime-enum-payload-type wrela-sema
semantic-runtime-enum-recursive-payload wrela-sema
semantic-runtime-enum-unit-constructor-shape wrela-sema
semantic-runtime-enum-variant-count wrela-sema
semantic-runtime-field wrela-sema
semantic-runtime-field-access wrela-sema
semantic-runtime-field-base wrela-sema
semantic-runtime-field-private wrela-sema
semantic-runtime-field-type wrela-sema
semantic-runtime-function-body-not-supported wrela-sema
semantic-runtime-function-color-not-supported wrela-sema
semantic-runtime-generic-enum-argument-count wrela-sema
semantic-runtime-generic-enum-argument-type wrela-sema
semantic-runtime-generic-enum-constructor-context wrela-sema
semantic-runtime-generic-enum-inference-required wrela-sema
semantic-runtime-generic-enum-parameter wrela-sema
semantic-runtime-generic-enum-payload-type wrela-sema
semantic-runtime-generic-structure-argument-count wrela-sema
semantic-runtime-generic-structure-argument-type wrela-sema
semantic-runtime-generic-structure-inference-argument-type wrela-sema
semantic-runtime-generic-structure-inference-conflict wrela-sema
semantic-runtime-generic-structure-inference-required wrela-sema
semantic-runtime-generic-structure-inference-shape wrela-sema
semantic-runtime-generic-structure-parameter wrela-sema
semantic-runtime-is-binding-pending wrela-sema
semantic-runtime-is-pattern-shape wrela-sema
semantic-runtime-is-pattern-type wrela-sema
semantic-runtime-is-result wrela-sema
semantic-runtime-is-scrutinee wrela-sema
semantic-runtime-match-alternative-binding-shape wrela-sema
semantic-runtime-match-alternative-guard-pending wrela-sema
semantic-runtime-match-alternative-payload-type wrela-sema
semantic-runtime-match-alternative-shape wrela-sema
semantic-runtime-match-alternatives-not-supported wrela-sema
semantic-runtime-match-constructor-only wrela-sema
semantic-runtime-match-guarded-wildcard wrela-sema
semantic-runtime-match-nonexhaustive wrela-sema
semantic-runtime-match-payload-shape wrela-sema
semantic-runtime-match-scrutinee wrela-sema
semantic-runtime-match-state-change-not-supported wrela-sema
semantic-runtime-match-take-not-supported wrela-sema
semantic-runtime-match-unreachable-arm wrela-sema
semantic-runtime-option-question-enclosing wrela-sema
semantic-runtime-option-question-payload wrela-sema
semantic-runtime-recursive-call-pending wrela-sema
semantic-runtime-result-argument-count wrela-sema
semantic-runtime-result-argument-type wrela-sema
semantic-runtime-result-constructor-context wrela-sema
semantic-runtime-result-not-core wrela-sema
semantic-runtime-test-body-not-supported wrela-sema
semantic-runtime-try-access wrela-sema
semantic-runtime-try-enclosing-result wrela-sema
semantic-runtime-try-result-required wrela-sema
semantic-runtime-try-rvalue-required wrela-sema
semantic-runtime-type-not-supported wrela-sema
semantic-scalar-type-mismatch wrela-sema
semantic-scope-abort-await wrela-sema
semantic-scope-call-outside-with wrela-sema
semantic-scope-call-signature wrela-sema
semantic-scope-cleanup-form-pending wrela-sema
semantic-scope-enter-constructor-access wrela-sema
semantic-scope-enter-constructor-argument wrela-sema
semantic-scope-enter-form-pending wrela-sema
semantic-scope-enter-type wrela-sema
semantic-scope-exit-await wrela-sema
semantic-scope-setup-form-pending wrela-sema
semantic-static-data-consumer-pending wrela-sema
semantic-static-data-context-pending wrela-sema
semantic-static-data-persistence-pending wrela-sema
semantic-struct-construction-not-supported wrela-sema
semantic-supervision-policy-pending wrela-sema
semantic-sync-while-bound-unproved wrela-sema
semantic-take-borrowed wrela-sema
semantic-test-body-missing wrela-sema
semantic-test-color wrela-sema
semantic-test-group-name-reserved wrela-sema
semantic-test-kind wrela-sema
semantic-test-missing wrela-sema
semantic-test-parameters-not-supported wrela-sema
semantic-test-result-not-supported wrela-sema
semantic-test-runtime-forced wrela-sema
semantic-unary-type wrela-sema
semantic-use-after-take wrela-sema
semantic-use-before-initialize wrela-sema
semantic-view-across-await wrela-sema
semantic-view-control-flow-pending wrela-sema
semantic-view-escape wrela-sema
semantic-view-read-only wrela-sema
semantic-view-source-mutated wrela-sema
semantic-view-terminal-use-pending wrela-sema
semantic-wait-cycle wrela-sema
semantic-with-binding-type wrela-sema
semantic-with-receiver-scope-pending wrela-sema
semantic-with-region-pending wrela-sema
semantic-with-scope-call-required wrela-sema
semantic-with-scope-callee wrela-sema
syntax-access-place wrela-syntax
syntax-array-type-semicolon wrela-syntax
syntax-assert-message wrela-syntax
syntax-assignment-target wrela-syntax
syntax-attribute-line wrela-syntax
syntax-bounded-capacity-argument wrela-syntax
syntax-closure-close wrela-syntax
syntax-closure-open wrela-syntax
syntax-closure-parameter-name wrela-syntax
syntax-closure-parameter-type wrela-syntax
syntax-comparison-chain wrela-syntax
syntax-comptime-else-colon wrela-syntax
syntax-comptime-if-colon wrela-syntax
syntax-constant-assignment wrela-syntax
syntax-duplicate-initializer wrela-syntax
syntax-empty-comptime-branch wrela-syntax
syntax-empty-enum-suite wrela-syntax
syntax-empty-generic-parameters wrela-syntax
syntax-empty-implementation-suite wrela-syntax
syntax-empty-import-list wrela-syntax
syntax-empty-interface-suite wrela-syntax
syntax-empty-interpolation-format wrela-syntax
syntax-empty-match wrela-syntax
syntax-empty-parentheses wrela-syntax
syntax-empty-struct-suite wrela-syntax
syntax-empty-suite wrela-syntax
syntax-empty-tuple-pattern wrela-syntax
syntax-empty-type-argument wrela-syntax
syntax-empty-type-arguments wrela-syntax
syntax-enum-payload-field wrela-syntax
syntax-expected-assert wrela-syntax
syntax-expected-assignment wrela-syntax
syntax-expected-attribute-name wrela-syntax
syntax-expected-brand-name wrela-syntax
syntax-expected-constant-name wrela-syntax
syntax-expected-dedent wrela-syntax
syntax-expected-deriving-list wrela-syntax
syntax-expected-deriving-name wrela-syntax
syntax-expected-dot-variant-name wrela-syntax
syntax-expected-enum-name wrela-syntax
syntax-expected-enum-variant wrela-syntax
syntax-expected-expression wrela-syntax
syntax-expected-field wrela-syntax
syntax-expected-fn wrela-syntax
syntax-expected-function-name wrela-syntax
syntax-expected-if-expression-colon wrela-syntax
syntax-expected-if-expression-else wrela-syntax
syntax-expected-import wrela-syntax
syntax-expected-import-keyword wrela-syntax
syntax-expected-import-name wrela-syntax
syntax-expected-import-path wrela-syntax
syntax-expected-indent wrela-syntax
syntax-expected-interface-name wrela-syntax
syntax-expected-local-name wrela-syntax
syntax-expected-module-path wrela-syntax
syntax-expected-name-segment wrela-syntax
syntax-expected-newline wrela-syntax
syntax-expected-parameter-name wrela-syntax
syntax-expected-parameter-type wrela-syntax
syntax-expected-parameters wrela-syntax
syntax-expected-pattern wrela-syntax
syntax-expected-projection-name wrela-syntax
syntax-expected-scope-name wrela-syntax
syntax-expected-suite-colon wrela-syntax
syntax-expected-suite-newline wrela-syntax
syntax-expected-type wrela-syntax
syntax-expected-type-name wrela-syntax
syntax-field-type wrela-syntax
syntax-for-binding wrela-syntax
syntax-for-in wrela-syntax
syntax-forbidden-code-point wrela-syntax
syntax-fragment-trailing-tokens wrela-syntax
syntax-function-type-arrow wrela-syntax
syntax-function-type-fn wrela-syntax
syntax-function-type-parameters wrela-syntax
syntax-generic-const-type wrela-syntax
syntax-generic-parameter wrela-syntax
syntax-generic-parameter-name wrela-syntax
syntax-implementation-for wrela-syntax
syntax-implementation-member wrela-syntax
syntax-implementation-member-pub wrela-syntax
syntax-inconsistent-dedent wrela-syntax
syntax-initializer-attribute wrela-syntax
syntax-initializer-context wrela-syntax
syntax-initializer-receiver wrela-syntax
syntax-initializer-visibility wrela-syntax
syntax-inline-attribute-order wrela-syntax
syntax-inline-attribute-target wrela-syntax
syntax-interface-member wrela-syntax
syntax-interpolation-format-ascii wrela-syntax
syntax-interpolation-format-brace wrela-syntax
syntax-interpolation-token wrela-syntax
syntax-invalid-character-literal wrela-syntax
syntax-invalid-escape wrela-syntax
syntax-invalid-identifier-start wrela-syntax
syntax-invalid-indentation wrela-syntax
syntax-invalid-number wrela-syntax
syntax-invalid-unicode-escape wrela-syntax
syntax-iso-brand wrela-syntax
syntax-leading-tab wrela-syntax
syntax-legacy-comptime-fn-color wrela-syntax
syntax-legacy-variant-pattern wrela-syntax
syntax-match-arm wrela-syntax
syntax-missing-module wrela-syntax
syntax-negative-pattern-literal wrela-syntax
syntax-non-ascii-byte-string wrela-syntax
syntax-non-nfc-identifier wrela-syntax
syntax-option-carrier wrela-syntax
syntax-pass-with-members wrela-syntax
syntax-projection-arrow wrela-syntax
syntax-projection-carrier wrela-syntax
syntax-projection-carrier-leaf wrela-syntax
syntax-removed-initializer-spelling wrela-syntax
syntax-reserved-multiline-string wrela-syntax
syntax-result-carrier wrela-syntax
syntax-scope-abort-colon wrela-syntax
syntax-scope-arrow wrela-syntax
syntax-scope-enter wrela-syntax
syntax-scope-enter-newline wrela-syntax
syntax-scope-exit wrela-syntax
syntax-scope-exit-binding wrela-syntax
syntax-scope-exit-colon wrela-syntax
syntax-semicolon-before-suite wrela-syntax
syntax-semicolon-declaration wrela-syntax
syntax-semicolon-match-arm wrela-syntax
syntax-semicolon-statement-boundary wrela-syntax
syntax-send-call wrela-syntax
syntax-statement-attribute-newline wrela-syntax
syntax-tail-if-suite wrela-syntax
syntax-tail-match-arm-value wrela-syntax
syntax-try-send-call wrela-syntax
syntax-tuple-pattern-comma wrela-syntax
syntax-tuple-type-comma wrela-syntax
syntax-unclosed-array wrela-syntax
syntax-unclosed-array-pattern wrela-syntax
syntax-unclosed-array-type wrela-syntax
syntax-unclosed-attribute wrela-syntax
syntax-unclosed-call wrela-syntax
syntax-unclosed-delimiter wrela-syntax
syntax-unclosed-deriving-list wrela-syntax
syntax-unclosed-enum-payload wrela-syntax
syntax-unclosed-generic-parameters wrela-syntax
syntax-unclosed-import-list wrela-syntax
syntax-unclosed-index wrela-syntax
syntax-unclosed-parameters wrela-syntax
syntax-unclosed-parentheses wrela-syntax
syntax-unclosed-pattern-constructor wrela-syntax
syntax-unclosed-tuple wrela-syntax
syntax-unclosed-tuple-pattern wrela-syntax
syntax-unclosed-tuple-type wrela-syntax
syntax-unclosed-type-arguments wrela-syntax
syntax-unexpected-character wrela-syntax
syntax-unmatched-delimiter wrela-syntax
syntax-unmatched-interpolation-brace wrela-syntax
syntax-unsupported-declaration wrela-syntax
syntax-unsupported-member wrela-syntax
syntax-unterminated-literal wrela-syntax
syntax-with-binding wrela-syntax
syntax-with-region wrela-syntax
```
<!-- diagnostic-index: codes end -->

## Known exclusions

Construction sites whose code the extractor cannot read. Each is declared in
`DIAGNOSTIC_CODE_EXCLUSIONS` (`xtask/src/main.rs`); the check fails both when an
undeclared non-literal site appears and when a declared one disappears.

<!-- diagnostic-index: exclusions begin -->
```text
crates/wrela-compiler/src/local_lint.rs `lint.as_str().to_owned()` — lint findings carry the registered lint name, not a phase-owned code
```
<!-- diagnostic-index: exclusions end -->
