# wrela standard library

Distribution builds copy the validated standard-library closure into
`share/wrela/std`; it is a pinned part of the toolchain rather than a host
dependency.

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
16-byte, 8-aligned `{u8 tag, u64 payload}` target layout and, when the enrolled
LLVM backend is available, emits byte-identical independently inspected ARM64
COFF twice. Unequal or nonscalar payloads, wrong generic arity, forged non-core
generic enums, and context-free constructors fail with stable diagnostics.
General `Result[T, E]`, error conversion, `Option`, recoverable
standard-library operations, EFI/QEMU execution, and installed-distribution
coverage remain open.

## Implemented flat-duration surface

`core.time` publicly exports the nominal `Duration` type with a private `u64`
nanosecond field. Runtime code can use `ns`, `us`, `ms`, `seconds`, `minutes`,
`hours`, `days`, `weeks`, `as_nanoseconds`, `add`, `subtract`, `scale`,
`less_than`, `less_than_or_equal`, `greater_than`, `greater_than_or_equal`,
`min`, `max`, and `clamp`. Comptime code uses the corresponding explicitly
suffixed functions. The suffixed comptime names are part of the current bounded
surface; Wrela does not yet provide overload resolution or method syntax that
could present one shared spelling. `clamp` requires `lower <= upper`; runtime
code preflights that invariant with checked target subtraction, and comptime
code rejects inversion with a source-aware failed assertion.

`examples/stdlib-time-scalar` is the canonical consumer workspace for that
installed API. Its manifest-declared test module imports the public functions
directly from `core.time`; there is no local representation or duplicate
production implementation. Genuine comptime tests cover construction,
projection through the public reader, nested calls, explicit aggregate copies,
exact ns/us/ms/s/minute/hour/day/week maxima, addition/scaling maxima and zero
scaling, exact-zero and maximum subtraction, underflow rejection, total-order
equality and endpoint cases, and nested `min`/`max`/`clamp`/subtraction. The
minute, hour, day, and week max-plus-one cases retain the imported production
assertion and call spans.
Selection by test-name substring and deterministic reruns pass through the
production loader, parser, HIR, semantic analyzer, and evaluator. The arithmetic
case passes at exactly 1,350 evaluator steps and 896 bytes and fails at
1,349/895. The ordering case passes at exactly 3,019 steps, 1,568 bytes, and
call depth 3 and fails at 3,018/1,567/depth 2. The subtraction/clamp case passes
at exactly 2,793 steps, 1,344 bytes, and depth 3 and fails at
2,792/1,343/depth 2. All three poll for deterministic cancellation; a loop
remains classified as `semantic-comptime-operation-not-implemented`.

A runtime test imports the same installed module and carries its reachable
ordinary functions through SemanticWir, FlowWir, canonical Flow wire v10,
backend revalidation, and MachineWir. The ordering helpers use the implemented
scalar projection/comparison/local/branch subset and reconstruct their selected
result through `ns`; this does not claim runtime copy-expression lowering. With
the authenticated LLVM 22.1.3 lane enabled, the prepared model retains exactly
three unsigned less comparisons, one unsigned less-equal comparison, four
source branches, eight checked multiplies, two checked adds, two checked
subtracts, twenty-two construction/projection/scalar-copy bitcasts, and the
exact 70-edge fully qualified harness/test/core call multiset before emitting
byte-identical independently validated ARM64 COFF twice. The source `@test fn`
is compiled as the selected test group; this fixture does not boot an image or
execute the test under the runtime runner. A separate ignored
`stdlib_time_real_qemu` gate builds the manifest-declared installed-source
workspace and executes it with an explicitly enrolled toolchain; its ordinary
failure path remains non-ignored and verifies bounded path-free diagnostics.
The repository does not treat an absent enrollment environment variable as
QEMU evidence.

MachineWir v10 now consumes the supported one-field u64 representation as an
exact 8-byte, 8-aligned scalar-backed ABI value with explicit construction and
projection bitcasts. Runtime unit multiplication is checked and retains the
compiler's closed fatal-failure path; runtime `add` and `scale` likewise use
checked addition/multiplication; `subtract` uses checked target subtraction and
abandons on underflow. Its comptime form classifies underflow with a stable
source-aware failed assertion before subtraction. The constructor comptime
forms prove exact u64 thresholds before multiplication. This does not claim the
complete time contract: recoverable `Result`-returning checked forms, units
larger than a week, `Instant`, `now`, class/method presentation, runtime copy or
assertion lowering, and executed runtime-image unit tests remain follow-on work.

## Not implemented

This bootstrap package does not claim the broader standard-library surface.
Apart from the bounded `core.result` specialization and `core.time` functions
above, there are currently no
public runtime, collections, allocation, actor, task, scope, I/O, networking,
DMA, MMIO, synchronization, testing, formatting, or hardware-driver modules
here. Those modules must be added only with their real language, semantic,
runtime, and target contracts.
