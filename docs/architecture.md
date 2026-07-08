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
5. Generic specialization and monomorphization
6. Wrela-specific MLIR dialects and pre-LLVM optimization passes
7. Lowering to LLVM dialect / LLVM IR
8. LLVM optimization, code generation, and linking

The repo starts with small libraries by compiler concern: `Basic`,
`Diagnostics`, `Source`, `Lex`, `IR`, and `Driver`. That keeps each stage
testable while leaving room to split larger compiler subsystems as the language
solidifies.
