# wrela standard library

The standard library is a pinned part of the toolchain rather than a host
dependency: an installed wrela toolchain seals its validated standard-library
closure at `share/wrela/std`.

## Bootstrap surface

`wrela-core-0.1` is the minimum real schema-1 package consumed by the current
source-to-semantic compiler path. Its public surface includes
`core.image.Image`, `core.image.Target`, `core.result.Result[T, E]`, and the
bounded function-based `core.time.Duration` subset described below. The sole
supported target variant is `Target.aarch64_qemu_virt_uefi`. The compiler
recognizes these public declarations in the package selected by the reserved
`core` dependency alias.

The package manifest and source are production inputs, not generated test
stubs. `examples/minimal-image` is a loadable two-package workspace: its
canonical lockfile binds root locator `.` to the checked-in application and
binds dependency alias `core` to toolchain component `wrela-core-0.1`. Its
source shows the complete form currently accepted by the semantic evaluator: a
public, zero-argument `@image comptime` function returning
`Image(name=..., target=...)`.

## Implemented bounded Result specialization

`core.result` publicly declares `Result[T, E]` with positional `Ok(T)` and
`Err(E)` variants. The current runtime specialization is intentionally narrow:
it accepts only `Result[S, S]` where `S` is one supported copy scalar. The
semantic model retains the exact pair `[Type(S), Type(S)]`, interns repeated
identical uses once, and lowers the selected specialization to the existing
canonical `{u8,payload}` enum representation without changing SemanticWir,
FlowWir, wire, or MachineWir versions. Constructor arguments come from an
explicit contextual `Result[S, S]` type; context-free inference is rejected.
Postfix `?` is implemented for an owned rvalue of this exact specialization.
`Ok` yields the scalar payload and `Err` reconstructs the exact same error and
returns it from an enclosing function with the identical `Result[S, S]` type.
Named-place `?` is rejected until its move and cleanup contract is implemented.

This is development substrate for the recoverable spine, not general generic
execution. Checked-in verticals independently specialize `Result[u8, u8]`,
`Result[bool, bool]`, and `Result[u64, u64]`; the u64 case proves the exact
16-byte, 8-aligned `{u8 tag, u64 payload}` target layout and, when the native
backend is enabled (`wrela-backend/bundled-backend`, system LLVM), emits
byte-identical independently inspected ARM64 COFF twice. Unequal or nonscalar
payloads, wrong generic arity, forged non-core generic enums, and
context-free constructors fail with stable diagnostics.
General `Result[T, E]`, error conversion, `Option`, recoverable
standard-library operations, EFI/QEMU execution, and installed-distribution
coverage remain open.

## Implemented flat-duration surface

`core.time` publicly exports the nominal `Duration` type with a private `u64`
nanosecond field, the named constructors `ns`, `us`, `ms`, `seconds`,
`minutes`, `hours`, `days`, and `weeks`, the accessor `as_nanoseconds`, and
the utilities `scale`, `min`, `max`, and `clamp`. Every function is one
phase-neutral surface: the same body is comptime-evaluated when called from a
comptime context and compiled for runtime otherwise. There are no suffixed
comptime twins.

Duration arithmetic and ordering are the `core.ops` operator interfaces:
`impl Add for Duration`, `impl Sub for Duration`, and `impl Ord for Duration`
in `core.time`, reached through the desugared `+`, `-`, `<`, `<=`, `>`, and
`>=` operators. There are no named arithmetic or comparison functions; `min`,
`max`, and `clamp` use the operators internally. Overflow and underflow come
from checked arithmetic (a comptime overflow is a build error; a runtime
overflow abandons), and `clamp` asserts `lower <= upper`.

`examples/stdlib-time-scalar` is the canonical consumer workspace for the
installed API. Its manifest-declared test module imports the public surface
directly from `core.time` and proves construction, projection, operator
arithmetic and ordering (including exact unit maxima, underflow rejection, and
total-order endpoints), and nested `min`/`max`/`clamp` through the production
loader, parser, HIR, semantic analyzer, and comptime evaluator. Exact
evaluator step/byte/call-depth bounds are asserted by
`crates/wrela-compiler/tests/stdlib_time_scalar.rs`; that test is the
authority for the current exact quotas rather than this document.

A runtime test in `examples/stdlib-time-runtime` imports the same installed
module and carries its reachable functions through SemanticWir, FlowWir, the
canonical Flow wire, backend revalidation, and MachineWir; with the native
backend enabled against the system LLVM it emits byte-identical independently
validated ARM64 COFF twice
(`crates/wrela-compiler/tests/stdlib_time_runtime_vertical.rs`). A separate
ignored `stdlib_time_real_qemu` gate builds the manifest-declared workspace
and executes it against the system-resolved `qemu-system-aarch64` and EDK2
firmware; its ordinary failure path remains non-ignored and verifies bounded
path-free diagnostics.

This does not claim the complete time contract: recoverable
`Result`-returning checked forms, units larger than a week, `Instant`, `now`,
method-call syntax, and executed runtime-image unit tests remain follow-on
work.

## Not implemented

This bootstrap package does not claim the broader standard-library surface.
Apart from the bounded `core.result` specialization and `core.time` functions
above, there are currently no
public runtime, collections, allocation, actor, task, scope, I/O, networking,
DMA, MMIO, synchronization, testing, formatting, or hardware-driver modules
here. Those modules must be added only with their real language, semantic,
runtime, and target contracts.
