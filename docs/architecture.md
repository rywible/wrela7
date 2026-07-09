# Wrela Compiler Architecture

Wrela is set up as a C++23 compiler that lowers a custom language through MLIR
before producing LLVM IR. LLVM will not monomorphize Wrela generics for us:
monomorphization belongs in the frontend or middle-end, before lowering to LLVM
IR. The initial architecture reserves an MLIR layer for that work.

The intended pipeline is:

1. Source loading and diagnostics
2. Lexing and parsing
3. AST construction
4. Semantic analysis and type checking
5. Effect/provenance graph construction
6. Generic specialization and monomorphization
7. Static runtime graph generation
8. Wrela-specific MLIR dialects and pre-LLVM optimization passes
9. Lowering to LLVM dialect / LLVM IR
10. LLVM optimization, code generation, and linking
11. Final machine-code translation validation and proof-manifest emission

The semantic middle end produces proof artifacts, not just lowered code:

- a sealed intrinsic identity table for compiler-provided declarations;
- structural summaries for linearity, needs-drop, defaultability, zeroability,
  droppability, foreign-derived values, effect summaries, no-trap regions, and
  bounded-work cost;
- a provenance DAG for capabilities, DMA memory, MMIO mappings, executor-wired
  `needs` handles, and recovery authority;
- a loan/projection graph for each synchronous call tree;
- a sealed-helper contract table: preconditions, consumed resources,
  publication points, failure/fatal behavior, ordering, and cleanup obligations;
- a generated-edge call graph including deinit, token redemption, executor
  source hooks, doorbells, panic, and fault paths;
- a token/event registry shape for each driver that mints tokens or waits;
- invariant/refinement obligations over storage ranges, ghost counters/sets,
  descriptor state, and guard postconditions;
- a target-theorem record for DMA coherence, MMIO boundedness, reset
  quiescence, interrupt masking, CPU count, extra devices, physical placement,
  and panic/fault behavior.

Monomorphization freezes those artifacts into concrete per-image summaries
before stack, frame, liveness, phase, provenance, and target-contract checks
run. The Wrela MLIR dialect should carry the checked summaries forward so later
passes cannot erase the evidence the safety theorem depends on. Each
Wrela-specific lowering pass has a verifier that checks it preserved linear
obligations, provenance edges, loan/projection scopes, volatile and DMA
publication ordering, token registry transitions, and the no-loan-across-await
frame invariant before the pipeline can continue.

LLVM is not treated as proof-preserving merely because Wrela MLIR was checked.
Lowering avoids LLVM undefined behavior and models MMIO/DMA with target-specific
address spaces, volatile operations, atomics/fences, and access widths from the
certified target package. After optimization and linking, an independent final
validator checks the emitted machine code and relocation map against the frozen
manifest: control-flow edges, stack/frame bounds, static object placement,
sealed helper hashes, MMIO/DMA access sites and widths, fence/publication
sequences, fault/doorbell entries, and absence of foreign executable sections.
Any property the validator cannot reconstruct remains an explicit target-package
assumption; a mismatch is a build failure.

The proof manifest binds compiler version, target-package hash, intrinsic/ABI
package hashes, source-module hashes, monomorphization set, memory placement,
and all discharged/assumed theorem obligations. Target packages are signed and
version their supported firmware, hypervisor, CPU, and device profiles; an image
cannot self-assert target evidence in its source DSL.

The repo starts with small libraries by compiler concern: `Basic`,
`Diagnostics`, `Source`, `Lex`, `IR`, and `Driver`. That keeps each stage
testable while leaving room to split larger compiler subsystems as the language
solidifies.
