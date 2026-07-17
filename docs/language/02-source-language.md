# Source language

## 1. Source files

Wrela source is UTF-8 and uses the `.wr` suffix. Identifiers are case-sensitive.
Revision 0.1 fixes its character database to Unicode 16.0.0. Identifiers use the
Unicode 16.0.0 XID start/continue properties and MUST be in Normalization Form C
(NFC); a non-NFC spelling is rejected rather than silently normalized. Keywords
are ASCII and cannot be identifiers. A future Unicode database is a language
revision because it may change which source files are accepted.

Bidirectional-format controls and Unicode default-ignorable code points are
forbidden in identifiers and structural source. Their presence is a build error
naming the code point and byte range. Strings and comments may contain them only
through an explicit Unicode escape. Diagnostics, source viewers, and the
canonical formatter MUST render those escaped and MUST isolate displayed string
and comment contents so that their visual order cannot disguise surrounding
tokens. Tooling MUST diagnose confusable identifier skeletons across the entire
visible name-resolution scope, including dependencies, and mixed scripts outside
an explicit project allowlist. Two canonically equivalent identifiers are the
same identifier and, because source is NFC, cannot have distinct spellings.
These diagnostics are warnings in the base profile and errors in the sealed
deployment profile; no conforming profile may suppress them silently.

`#` begins a comment outside a string and continues to the end of the physical
line. Blocks use a trailing `:` and significant indentation. Tabs in leading
indentation are a compile error. Every block indentation level is exactly four
spaces deeper than its parent; other increases and inconsistent dedents are
errors. A formatter MUST use the same four-space form.

A newline terminates a simple statement unless it occurs inside `()`, `[]`, or
`{}`. A semicolon MAY separate simple statements on one physical line, but the
canonical formatter expands them to separate lines.

Comma-delimited lists inside delimiters may have a trailing comma. A declaration
header may use hanging indentation to continue from its closing parameter list
through `-> return_type` to the terminating `:`.

A physical newline after the closing `)` of a declaration header is suppressed
only when the next nonblank line is indented beyond the declaration and begins
with `->`; the following `:` ends that logical header. No other
outside-delimiter line continuation exists. Inside delimiters indentation is
ignored for parsing but tabs in leading whitespace remain forbidden.

Integer literals may be decimal, `0x` hexadecimal, `0o` octal, or `0b` binary;
underscores are allowed only between two digits of the literal's base; every
prefix is followed by at least one digit. Their type comes from context. An unconstrained
nonnegative literal defaults to `i64` when it fits and otherwise to `u64`; an
unconstrained negative literal defaults to `i64`. A value outside those ranges
requires an explicit contextual integer type. A decimal floating literal is
`digits.digits` with an optional `e`/`E` signed exponent, or `digits`
followed by a required exponent; digits are required on both sides of a decimal
point and underscores follow the integer rule. It requires a contextual `f32`
or `f64` type; an
unconstrained floating literal defaults to `f64`. Hexadecimal floating literals
are not in revision 0.1. String literals are UTF-8, character literals hold
exactly one Unicode scalar, a plain text literal has type `Static[Str]`, and a
`b"..."` literal of decoded length `N` has type `Static[Bytes[N]]`. The
boolean literals are `true` and `false`. The only escapes are backslash,
double quote, single quote, newline, carriage return, tab, zero, `\xNN` in
byte strings, and `\u{H...}` with one to six hexadecimal digits in
text/character literals. Surrogates, out-of-range scalars, malformed escapes,
and `\xNN` in a text literal are build errors.

Text, byte, character, and interpolated literals do not contain raw physical
newlines; revision 0.1 has no multiline/raw literal. A byte string permits only
ASCII source characters plus escapes, so every decoded element is unambiguously
one byte. In an interpolated string, `{{` and `}}` emit literal braces and a
single `{` begins `{ expression [ : format_spec ] }`. The expression follows
the ordinary grammar with balanced delimiters; `format_spec` is a nonempty
ASCII sequence without braces whose meaning is checked by the selected
`Format` implementation. An unmatched brace is a syntax error.

An interpolated string begins with `f"`. Every interpolation is type-checked and
must have a compile-time maximum formatted length, supplied by its type or an
explicit format width. The resulting `String[..N]` bound is computed at build
time. Unbounded formatting, formatting a `Secret`, and interpolation in ISR
code are rejected. Formatting contracts are specified in
[Standard library contracts](10-standard-library-contracts.md).

```wrela
module example.counter

pub class Counter:
    value: u64

    pub fn get(read self) -> u64:
        return self.value

    pub fn increment(mut self, by: u64):
        self.value += by
```

## 2. Modules

Every source file begins with one module declaration. A module path is a
dot-separated sequence of identifiers and MUST match the file's path beneath a
package source root.

```wrela
# src/storage/extentfs.wr
module storage.extentfs

from core.bytes import Bytes
from storage.block import BlockDevice
import core.time as time
```

Imports are absolute. Wildcard imports are forbidden. `from` imports one or more
named declarations; `import` binds a qualified module name, optionally under an
alias. A multi-line `from` list uses parentheses and may have a trailing comma.
Imports are compile-time name bindings and never execute runtime code.

Declarations are module-private unless marked `pub`. A public import re-exports
a name:

```wrela
pub from core.bytes import Bytes
```

Import cycles are allowed. The compiler resolves each strongly connected module
component as a unit because imports are name bindings and modules have no runtime
initialization. Cycles through constant evaluation, type layout, generic
instantiation, or image construction remain errors and the diagnostic MUST show
the semantic cycle. Runtime construction belongs in class initializers and the
image graph.

A package has the canonical identity `(name, version, source_digest)` recorded by
the package manifest. The manifest fixes one UTF-8 NFC source root and an exact
dependency graph; two dependencies may share a name only under distinct local
aliases. Before module lookup, every path component is decoded as UTF-8 and
checked for NFC, exact case, separators, `.`/`..`, and platform-independent
uniqueness. A package containing paths that collide under Unicode normalization
or ASCII case folding is rejected on every host.

The manifest sees only declarations reachable through imports from the module
containing `@image`. Closed-world linkage does not bypass visibility.

### 2.1 Package manifest and lockfile

Package configuration uses UTF-8 TOML. The root files are named `wrela.toml`
and `wrela.lock`. Duplicate keys, unknown fields, invalid UTF-8, non-NFC text in
names/paths, absolute or parent paths, and an unsupported schema are errors;
implementations do not silently ignore configuration from a newer schema.

`wrela.toml` schema 1 declares exactly:

- `schema = 1` and `language = "0.1-design"`;
- package `name`, `version`, and one portable relative `source_root`;
- an explicit, strictly ordered list mapping every module path to one source
  path beneath that root; directory walking never discovers source implicitly;
- dependency local alias, nominal package name, and version requirement;
- exactly one direct dependency under the reserved alias `core`; this selects
  the semantic standard-library package, while its locked toolchain locator
  selects the package bytes inside the verified standard-library component;
- one or more finite named build profiles containing comptime, memory,
  recovery, DMA, record/replay, optimization, and diagnostic policy;
- full-image entries, each naming an image name, module, `@image` function,
  target, and profile; and
- optional full-image test entries, each naming a declared image, host scenario,
  nonzero boot/shutdown/event/output bounds, and optional deterministic seed.

Every module-path segment, dependency alias, and image `entry` is a
revision-0.1 source identifier: Unicode 16.0.0 XID start/continue, NFC, not `_`,
not a language keyword, and free of default-ignorable and bidirectional-format
controls. Package/version/profile/image/image-test names are nominal manifest
atoms and do not acquire source-identifier semantics.

`core` is the sole reserved dependency alias in revision 0.1. A custom atomic
toolchain may provide a differently named or implemented standard-library
package, but the root still binds it explicitly as `core`; package selection is
therefore never inferred from a package name or from equality with the
toolchain component digest.

`maximum_output_bytes` is one aggregate ceiling across all captured emulator
stdout and stderr, not a separate allowance per stream. Scenario files are
explicit package inputs: their canonical package/path/digest tuples participate
in the source-graph and build-request identities.

Every list is stored in the canonical order defined by its stable name or
identity; a canonical formatter may reorder TOML entries but doing so does not
change semantics. Revision 0.1 accepts only full-image target entries and only
`aarch64-qemu-virt-uefi`.

An illustrative shape is:

```toml
schema = 1
language = "0.1-design"

[package]
name = "appliance"
version = "0.1.0"
source_root = "src"

[[module]]
name = "appliance.image"
path = "appliance/image.wr"

[[dependency]]
alias = "core"
package = "wrela-core"
requirement = "=0.1.0"

[[profile]]
name = "development"
mode = "development"
comptime_steps = 10000000
comptime_memory_bytes = 67108864
comptime_call_depth = 256
static_bytes = 268435456
peak_bytes = 536870912
event_log_bytes = 0
dma_coherent = false
require_iommu = false
reset_timeout_ns = 5000000000
quarantine_bytes = 16777216
recording = "disabled"
optimization = "development"
sealed_deployment = false
warnings_as_errors = false
watchdogs = true

[[image]]
name = "appliance"
module = "appliance.image"
entry = "image"
target = "aarch64-qemu-virt-uefi"
profile = "development"

[[image_test]]
name = "boots-and-serves"
image = "appliance"
scenario = "fixtures/boots-and-serves.toml"
boot_timeout_ns = 30000000000
shutdown_timeout_ns = 5000000000
maximum_events = 10000
maximum_output_bytes = 1048576
deterministic_seed = 1
```

`wrela.lock` schema 1 is generated canonical TOML. It names the exact root
identity and strictly orders the complete transitive package closure by
`(name, version, source_digest)`. Each entry records that identity, an explicit
workspace/archive/toolchain locator, the canonical manifest digest, and its
strictly ordered `(alias, exact dependency identity)` edges. An archive locator
names an explicitly configured provider and opaque key; it is not an implicit
registry URL. A toolchain locator names a shipped component such as the standard
library. Every listed package MUST be reachable from the root through those
edges; isolated packages and disconnected subgraphs, including disconnected
cycles, are invalid rather than additional lockfile inputs. The exact raw bytes
of every acquired manifest are hashed before TOML decoding, and every source is
hashed before source-language parsing. A raw manifest digest is an
acquisition-integrity artifact, distinct from the lockfile's canonical
manifest digest: after semantic TOML decoding, the manifest is canonically
encoded and that canonical digest is checked against the lock. Equivalent
noncanonical TOML spellings therefore remain valid without weakening the raw
acquisition boundary. A digest, identity, alias, dependency, missing/extra
source, or canonical-lock mismatch is a build error. Package acquisition may
use a driver-selected local or network provider, but undeclared resolution and
ambient registry configuration are not part of the build.

## 3. Declaration forms

The principal declarations are:

- `const` for a compile-time constant;
- `fn`, `async fn`, `isr fn`, and `comptime fn` for the three runtime colors and
  compile-time evaluation;
- `struct` for structural values;
- `brand` for a proof-only name bound exactly once by image construction;
- `class` for uniquely owned state and behavior;
- `enum` for closed sums;
- `iface` and `impl` for static constraints and their implementations;
- `projection` and `scope` for computed loans and deterministic scoped effects;
- compiler-recognized attributed declarations such as `@image` and `@dma`.

Names at module scope cannot be overloaded in revision 0.1. A class can have
methods with distinct names; generic specialization does not create source-level
overloads.

### 3.1 Functions and colors

```wrela
fn checksum(data: Bytes) -> u64:
    ...

async fn fetch(client: ClientHandle) -> Result[iso[NetPackets] Bytes, NetError]:
    ...

isr fn on_queue(self):
    ...

comptime fn queue_bytes(depth: usize) -> usize:
    return depth * 16
```

`fn` is synchronous. `async fn` may suspend with `await`. `isr fn` is an
interrupt top half with the effect restrictions in
[Hardware safety](05-hardware-safety.md). `comptime fn` runs only during a
compile-time phase and is governed by
[Comptime and images](06-comptime-and-images.md).

`await` MUST occur in an `async fn`. An async function cannot be invoked as a
detached future value: it is either awaited, sent one-way through an actor API,
or installed into a statically bounded task slot by the image or a nursery.
Every async activation's awaitable has the explicit `AsyncExit[E]` cancellation
and deadline outcome defined by chapter 04; these causes are never hidden
exceptions or implicit returns from a canceled frame.

Function color describes the callee body. Calling even a synchronous public
`fn` through `Actor[T]` produces the actor awaitable described by chapter 04;
it must be awaited or used by `send`/`try send`. A direct call on an ordinary
owned value remains synchronous.

An image-installed `@task` entry may return `unit` or `Result[unit, E]`.
Returning `Err` is a recoverable task failure delivered to its declared
supervisor policy; it is not silently discarded and is distinct from actor
abandonment. See [Faults and reliability](07-faults-and-reliability.md) and
[Standard library contracts](10-standard-library-contracts.md).

Revision 0.1 uses prefix `await`:

```wrela
data = await storage.read(path)?
```

The earlier postfix spelling `call().await` is not part of this revision.

### 3.2 Structs

A `struct` is a product value with no observable object identity.

```wrela
pub struct Point:
    x: i32
    y: i32
```

Struct fields are private to their defining module unless marked `pub`. A
struct may define methods. It is copyable only when every field is copyable and
it owns no linear resource. Except for scalar values, duplication is always
written `copy value`; assignment without `copy` moves a non-scalar value even
when that value is copyable. This makes the cost of large aggregate duplication
source-visible. Physical copies and moves may be elided so long as value behavior
and teardown are preserved.
An empty struct uses `pass` and is an ordinary zero-sized value. It is not a
pool, request, device, or vector brand; those identities are generative. Map
instance IDs are likewise minted by `SlotMap`, not supplied by a zero-sized
struct.

A module-scope `brand Name` declaration introduces a proof-only name with no
constructible value or runtime representation. The image builder may bind that
name to exactly one pool/device/vector node. Before binding it cannot appear in a
runtime type, and after binding its identity is the minted node rather than the
source spelling. Reusing one brand declaration for two nodes is a build error.

A struct declaration generates a named-field constructor. All fields must be
provided exactly once unless they have defaults. Positional construction is
forbidden except for a one-field struct, preventing field order from becoming
an accidental public ABI:

```wrela
p = Point(x=10, y=20)
```

### 3.3 Classes

A `class` is a uniquely owned stateful value. It may own resources, nested
classes, and methods. Its fields are private to the defining module unless
marked `pub`. Class values do not implicitly copy.

```wrela
pub class Cache:
    lines: [CacheLine; 256]

    init(mut self):
        ...
```

`init` establishes every field before the instance becomes observable. It is a
dedicated class declaration, not a named function or actor message, and it must
begin with exactly one `mut self` receiver. Initializers cannot be public,
generic, attributed, or conditionally declared, and each class declares at most
one.
Partial initialization is tracked. A `take` from a field makes that field
temporarily uninitialized; every normal control-flow path must replace it before
the containing value is used as a whole or the turn returns.

Construction uses `Type(named_arguments...)` and invokes `init`; classes
without an explicit initializer receive a named-field initializer subject to
field visibility. `init` MAY return `Result[unit, E]`. If it returns `Err`,
the compiler tears down already-initialized reclaimable fields in reverse field
initialization order. Every initialized strict-linear field must already be
protected by a scope, moved into a manifest restart provision, or explicitly
consumed on each error edge. The same rule applies to boot rollback.

A class marked `@app`, `@service`, or `@driver` is an actor root and follows the
additional rules in [Actors and async](04-actors-and-async.md). Apps are
top-level workload leaves, services are image-wired reusable dependencies, and
drivers alone receive hardware authority as defined by the image graph.

A method declaration without a `self` parameter is associated with its type and
is called as `Type.method(...)`. It has no implicit receiver authority.

### 3.4 Enums and matching

An `enum` is a closed sum. Variants may carry values.

```wrela
enum Lookup[T]:
    found(T)
    absent
    failed(IoError)
```

`match` is exhaustive. A wildcard arm is allowed only when it covers at least
one variant or value not already covered. Matching a known closed enum does not
require, and the formatter does not invent, a default arm.

```wrela
match lookup(key):
    case found(value):
        use(value)
    case absent:
        return None
    case failed(error):
        return Err(error)
```

Exhaustiveness is checked after comptime specialization.

Patterns include enum variants, tuple and fixed-array destructuring, literals,
the wildcard `_`, alternatives joined with `|`, and guards introduced by `if`.
Alternatives must bind the same names with the same types and access modes.
A guard runs only after its pattern matches and may read those bindings. A
guarded arm contributes nothing to exhaustiveness unless specialization proves
its guard is the literal `true`; a later unguarded arm must cover the same
constructor/value space. Fixed-array patterns have exactly the statically known
array length; revision 0.1 has no rest/slice pattern.

```wrela
match state:
    case clean(found) if found == lba:
        use(found)
    case dirty(found) if found == lba:
        use(found)
    case clean(_) | dirty(_) | invalid:
        pass
```

A bare identifier at the top of an arm is never an implicit catch-all binding.
It must resolve to a zero-payload variant of the scrutinee's closed enum or it is
an error. A bare identifier in a constructor/tuple/array payload position
introduces a binding unless that payload's expected enum type has a zero-payload
variant of the same name; `bind name` forces a binding in that ambiguous case
or at arm top level. This ensures that removing or renaming a variant cannot
silently turn `case absent` into a match-all arm.

`is` performs a refutable pattern test. Bindings introduced by the pattern are
available only in the success-dominated right operand of `and` and in the
corresponding `if` suite; they are unavailable in `else` and after the `if`:

```wrela
if lookup(key) is Some(index):
    use(index)
```

Matching a `mut` or linear value does not implicitly copy its payload. A
payload move uses `take` in the payload pattern; otherwise the arm receives the
least read access needed by its body.

### 3.5 Interfaces

An `iface` is a static contract, never a runtime object type.

```wrela
pub iface Hashable:
    fn hash(read self) -> u64

pub fn hash_pair[T: Hashable](a: T, b: T) -> u64:
    return a.hash() ^ b.hash()
```

Every generic use is monomorphized. An `impl I for T` is legal only in a package
that declares nominal interface `I` or nominal type constructor `T`.
Implementing two foreign declarations requires a local nominal wrapper. This
orphan rule makes adding a dependency unable to introduce an implementation
conflict into an otherwise unchanged package.

After generic substitution, no two visible implementations may apply to the same
`(interface, concrete type)` pair. Revision 0.1 has no specialization, negative
implementation, or overlapping blanket implementation. The compiler checks
potential overlap symbolically over generic constraints, then repeats the check
over the closed image; uncertainty is an error naming both blocks and a witness
instantiation when one exists.

An implementation's declared access effects MUST match the interface exactly.
Its body may require less authority—for example, a `mut self` contract may have
an implementation that happens not to mutate—but callers and substitutability
still observe the declared interface effect. An implementation can never widen
an interface effect.

Any nominal type may implement an interface in an explicit implementation
block. `Self` denotes the type after `for`. Implementations are compile-time
coherence facts, not runtime values, and are not independently exported:

```wrela
pub iface From[Source]:
    fn from(take value: Source) -> Self

impl From[ParseError] for FsError:
    fn from(take error: ParseError) -> FsError:
        return FsError.invalid_input(error.kind)
```

A class's `implements` clause is declaration-local shorthand for the same
obligation when its method bodies are defined in the class. Structs, enums, and
implementations kept separate from a class use `impl`. The whole image permits
at most one implementation of an instantiated interface for a concrete type;
an ambiguous pair is a build error naming both blocks.
`impl` blocks are visible through their interface/type packages and cannot be
marked `pub`; the parser accepts the uniform top-level modifier position, then
semantic checking rejects that combination.

An interface cannot be used as a field type or runtime parameter without a
concrete generic type. Runtime heterogeneity is represented with an explicit
closed enum:

```wrela
enum Backend:
    memory(MemoryBackend)
    block(BlockBackend)
```

This rule guarantees that dispatch is a direct specialized call or an explicit
exhaustive branch. There is no `dyn` escape.

`==` and `!=` are generated structurally for copyable structs and enums when
all fields support equality. Ordering and operators on other user types resolve
through the closed static interfaces `Eq`, `Ord`, `Add`, `Sub`, `Mul`, and their
named peers; they never perform runtime dispatch. Implementations follow the
same package orphan, symbolic non-overlap, and final image-coherence rules as
other interfaces.

Error conversion for postfix `?` is also explicit. The propagated error must
be the enclosing error type or have exactly one visible implementation of
`From[SourceError]` for that enclosing type. Conversion chains and implicit
numeric or enum widening are not considered. The selected conversion is
monomorphized and shown by tooling. Propagation consumes the source error; the
conversion therefore always has a `take` parameter.

### 3.6 Projections and scopes

A `projection` is the only declaration form that may return a `view`. It is a
synchronous accessor that yields one or more `view T`/`mut view T` leaves
inside a second-class projection carrier. A carrier is a view leaf, a tuple of
carriers, `Option[carrier]`, or `Result[carrier, E]`; `E` is an ordinary
owned type. The declaration's mandatory `from` clause lists the
receiver/parameters whose storage may back any yielded leaf. Its activation
remains until all caller views end. Every successful path executes exactly one
`yield`; every error/`None` path executes zero. It cannot suspend, and code
before an unsuccessful return must leave no active loan.

```wrela
projection item(mut self, index: usize) -> mut view Item from self:
    yield self.items[index]

projection entry(mut self, key: Key)
    -> Result[mut view Item, MissingKey] from self:
    index = self.resolve(key)?
    yield self.items[index]
```

Projection carriers have no ordinary runtime type or storable layout. They may
appear only as the immediate result of a projection call consumed by a view
binding/destructure, postfix `?`, or `match`. They cannot be assigned as
ordinary values, returned from a function, placed in a non-carrier aggregate,
captured, sent, or kept across suspension. A projection may yield multiple
mutable leaves only when it proves their storage paths disjoint on every
successful path.

The `from` set is part of the public type/effect and MUST match an interface
declaration exactly. A caller conservatively retains access to every named source
until all yielded leaves end, even when a runtime branch selected only one. A
projection cannot yield storage rooted in a local, temporary, image-global not
named in the set, or transitive mutable global. Ordinary `fn`, `async fn`,
`isr fn`, and `comptime fn` return types cannot contain `view` at any
nesting depth.

A `scope` defines the acquisition and exit protocol used by `with`. It has an
ordinary parameter list and result type, an acquisition prefix ending in
`enter`, an optional `abort` clause for paths that leave a partially mutated
acquisition, and an `exit` clause. Abort/exit clauses do not suspend. The abort
clause covers every pre-enter mutation/move/resource obligation; the exit clause
is registered atomically when `enter` succeeds. If exit transfers a sealed
device obligation into generated recovery, the owning driver may finish it in a
later turn while affected regions remain quarantined; source code cannot observe
the scope as completed until its cleanup dependency graph is empty.

```wrela
@suspend_safe
scope replace(mut self, index: usize) -> Replacement:
    enter self.begin_replace(index)
    exit replacement:
        self.finish_or_rollback(mut replacement)
```

A suspend-safe actor-local scope may carry a sealed repair token for actor-owned
state across `await`; that token is not a view, cannot be inspected or sent, and
is usable only by the generated exit action in the same non-reentrant turn.
Other mutable access to the protected state remains unavailable until commit or
exit.

## 4. Parameter access effects

Every parameter has one access mode:

```wrela
fn inspect(packet: Packet):             # read is the default
    ...

fn fill(mut buffer: Bytes):             # exclusive in-place mutation
    ...

fn enqueue(take packet: iso[NetPackets] Packet):  # ownership transfer
    ...
```

The default `read` mode may alias other reads. `mut` grants exclusive access for
the call. `take` consumes the argument.

A receiver, when present, is the first parameter and appears exactly once. It is
legal only in a declaration nested in a nominal type or its `impl`; module
functions and receiver-free associated functions have no implicit receiver.

Non-receiver `mut` and `take` effects MUST be mirrored at the call site:

```wrela
inspect(packet)
fill(mut buffer)
enqueue(take packet)

# Named arguments place the effect after `=`.
driver.submit(queue=0, payload=take packet)
fs.read_file(ino=7, out=mut output)
```

The compiler rejects a missing, extra, or incorrect access marker. `read` is not
written at call sites. An operand introduced by `mut` or `take` MUST be an
explicit place: a name, a field or index projection rooted in a place, or a
parenthesized place. Literals, calls, operators, and every other rvalue form are
rejected by syntax before HIR lowering. An unmarked argument remains an
ordinary expression; this revision does not add implicit move semantics.

Arguments bind positionally until the first named argument; every later argument
must be named. A parameter may be supplied exactly once, names are resolved
against the selected declaration before evaluation, and revision 0.1 has no
variadic or runtime keyword-argument collection. Constructor fields follow the
same duplicate/order rule. Named arguments affect binding only, never source
evaluation order.

For parameters, bare `T` under the default `read` mode means whole-value read
access for the call; it does not copy `T`. `mut T` means whole-value exclusive
access. The spellings `view T` and `mut view T` are therefore forbidden as
parameter types: `view` is reserved for projection results and lexical
bindings. A caller may pass an existing view to a compatible read parameter,
and the call cannot extend that view's lifetime.

For an explicit ownership transfer of a linear local outside a call, `take` is
an expression. A copyable non-scalar used by assignment or value construction
instead moves when `copy` is absent, as specified in sections 3.2 and 6:

```wrela
next = take current
# `current` is uninitialized here.
current = Packet.empty()
```

### 4.1 Receiver effects

Receiver effects precede `self`:

```wrela
fn length(read self) -> usize
fn clear(mut self)
fn finish(take self) -> Product
```

Every `pub` method, interface method, actor message handler, driver entry, and
projection accessor MUST spell its receiver effect. A private method may write
plain `self`; the compiler infers its least effect over the whole call graph and
tooling MUST display that inferred effect. `--strict-mut` promotes omitted
private receiver effects to a lint error.

An `isr fn` is the sole exception. Its `self` spelling denotes the restricted
ISR receiver fixed by the function color, not an ordinary whole-actor `read` or
`mut` loan. Its accessible fields and operations are determined by the ISR
effect rules, so it writes plain `self` and cannot widen that authority.

The receiver is the sole call-site exception: `cache.clear()` does not require a
second `mut` marker before `cache`. Its public declaration, documentation, and
tooling carry the effect. All explicit arguments still mirror their effects.

Changing an exported receiver from `read` to `mut` or from `mut` to `take` is an
API-breaking change.

## 5. Types

### 5.1 Primitive types

The core scalar types are:

- `bool`;
- unsigned integers `u8`, `u16`, `u32`, `u64`, `u128`, and target-width
  `usize`;
- signed integers `i8`, `i16`, `i32`, `i64`, `i128`, and `isize`;
- `f32` and `f64` where the target enables floating point;
- `char`, a Unicode scalar value;
- `unit`, written as the value `unit`; and
- `Never`, the uninhabited return type.

Floating point is forbidden in ISR code. A target may further disable it in
runtime code.

Ordinary integer addition, subtraction, multiplication, unary negation, and
signed division of `MIN / -1` abandon on overflow in every build profile.
There is no arithmetic undefined behavior and optimization may not assume
overflow is impossible. Wrapping operators are explicit (`+%`, `-%`, `*%`);
they reduce modulo `2^width`. Division truncates toward zero and remainder has
the dividend's sign. Division or remainder by zero abandons. A shift count must
be nonnegative and less than the left operand's bit width or the operation
abandons; right shift is logical for unsigned values and sign-extending for
signed values. Checked standard-library forms return `Result` instead of
abandoning.

Apart from contextual typing of literals, there are no implicit numeric
conversions, including widening. `value as T` is a checked
conversion: a comptime out-of-range value is a build error and a runtime
out-of-range value abandons. `value.checked_as(T)` returns a recoverable result;
`value.truncate_as(T)` is an explicit bit truncation for driver code.
`as` is numeric-only in revision 0.1: it does not expose enum discriminants,
addresses, brands, or representations. Integer-to-float and float narrowing use
round-to-nearest ties-to-even and abandon if a finite source would become
infinity; float widening is exact. Enum/wire conversions use named checked APIs.

`f32` and `f64` follow IEEE 754 binary32 and binary64 with round-to-nearest,
ties-to-even. Implementations may use hardware only when it produces the same
observable result. Every arithmetic NaN result is canonicalized to one quiet NaN
per width; NaN compares unequal to every value including itself, and ordered
comparisons with NaN are false. Floating contraction, reassociation, flush to
zero, and other fast-math changes require an explicit future profile and are not
allowed in revision 0.1. Float-to-integer `as` abandons for NaN, infinity, or an
out-of-range result and otherwise truncates toward zero.

### 5.2 Compound and standard types

Core spellings include:

- `[T; N]` — a fixed-size array;
- `(A, B, ...)` — a fixed-arity tuple;
- `Option[T]` — `Some(T)` or `None`;
- `Result[T, E]` — `Ok(T)` or `Err(E)`;
- `Bytes[N]` — exactly `N` bytes;
- `Bytes[..N]` — a byte value with runtime length at most `N`;
- `List[T, N]` — at most `N` region-homogeneous values;
- `String[..N]` — owned, validated UTF-8 with capacity `N`;
- `Bytes` and `Str` — unsized byte and validated UTF-8 **shape types**;
- `Static[T]` — a copyable read-only handle to immutable image data of shape
  `T`;
- `view T` and `mut view T` — lexical projections; and
- `iso[P] T` — a movable, uniquely owned region handle branded by pool `P`.

Shape types have no standalone field or local layout. They may occur only as a
whole-value `read`/`mut` parameter, behind `view`/`mut view`, or as the payload
of a branded `iso` or `Static`. A pool or enclosing bounded value supplies the maximum
extent. Thus `fn hash(data: Bytes)` reads an entire byte shape, while
`result: view Str` is a lexical projection. Converting foreign bytes to
`String` validates UTF-8 and returns a `Result`.

`Static[T]` is minted only for immutable values reachable from image read-only
data. It exposes read access to `T`, has no mutable conversion or address
identity, and may cross actor boundaries as a scalar handle. A public actor
signature that accepts runtime-sized immutable `Bytes` or `Str` MUST say
`Static[Bytes]`/`Static[Str]`; bare shape parameters are local-call accesses,
not an implicit claim that arbitrary runtime data is static.

The pool brand in `iso[P] T` is usually inferred in private code and always
displayed by tooling. It is mandatory in exported signatures and actor methods.
A request-local brand cannot be stored in an image-lifetime field or cross the
request boundary. A durable image-declared pool brand may be stored and moved
between actors. Pool branding and reclaim semantics are defined in
[Values, views, and regions](03-values-views-regions.md).

Tuples have no nominal identity. Their elements are evaluated left-to-right and
ownership is tracked element by element. A tuple is copyable exactly when every
element is copyable. Tuple destructuring may move selected linear elements only
when the source is consumed or the remaining elements stay definitely
initialized. The one-element tuple is written `(T,)` / `(value,)`; parentheses
without the comma only group.

There is no `null`. Optionality uses `Option`.

Bracket forms are structurally distinct. `[T; N]` is an array type because it
starts a type production and contains `;`; `Name[T, N]` supplies generic
arguments in a type/specialization position; and `value[index]` is postfix
indexing on an expression. `Bytes[SECTOR]` in a field type and `self.desc[i]` in
an expression therefore do not rely on capitalization or name lookup to parse.

### 5.3 Generics

Generic type and constant parameters are compile-time parameters:

```wrela
class Ring[T, const N: usize]:
    items: [Option[T]; N]
```

Every ordinary type/constant instantiation is concrete and monomorphized.
Runtime type variables, variance through subtyping, and erased generic
containers do not exist. The one proof-only exception is a `region R` parameter:
it is universally quantified, has no runtime representation, and may occur only
as the brand of `RequestContext[R]`, `iso[R] T`, or another sealed
request-scoped type. Source cannot choose its value; request creation mints it
and actor admission preserves it. A function generic only over region brands is
compiled once because the brands are erased after static checking.

A constant generic argument has type `bool`, `char`, an integer type, or a
fieldless enum with a fixed representation. It is evaluated by the comptime
engine after type substitution. Equality is equality of the typed resulting
value, not source-text equality. Array lengths and capacity arguments must be
nonnegative `usize` values. Generic instantiation is rejected when its
substitution graph recurs without reaching an already completed identical
instantiation; diagnostics show the substitution cycle. Const expressions do
not participate in interface overlap by theorem proving: the implementation
must be disjoint by nominal/type constraints or by unequal fully evaluated
constants.

## 6. Bindings and definite initialization

The first assignment to a local name in a block introduces it. An annotation is
optional when the type is inferable:

```wrela
count: u32 = 0
packet = Packet.empty()
```

Locals may be reassigned with the same type. Shadowing an outer local is a lint
error by default and requires `shadow name = value` when intentional.
In a tuple destructuring assignment, every bare target not already local is
introduced simultaneously after the right side succeeds; existing and new
targets cannot be mixed. This is the immediate binding form for a multi-view
projection carrier.

Core scalar values may be duplicated implicitly. Duplicating any other copyable
value uses the prefix expression `copy`; it evaluates its operand once and
produces an independent value while leaving the source initialized. `copy` of
a linear value is a compile error. Assignment, argument passing to a consuming
parameter, and aggregate construction move a non-scalar operand unless `copy`
is written.

The compiler tracks initialization on every control-flow edge. Reading a moved
or not-yet-initialized local or field is a compile error. A value with a pending
linear resource cannot be silently overwritten.

Moving from an array through a runtime-computed index is forbidden: the
definite-initialization state would depend on an unbounded set of runtime index
histories. A constant index may be tracked separately. Dynamic code consumes an
array as a whole with `for take element in take array`, or uses the sealed
`map_take`/whole-array builder contract that consumes each element exactly once
and returns a fully initialized array. A consuming loop leaves the source array
uninitialized as a whole when it starts; `break`, `return`, or `?` must consume
or reclaim the remaining elements according to their linear class.

## 7. Control flow

Revision 0.1 provides `if`/`else`, `match`, `for`, `while`, `loop`, `break`,
`continue`, `return`, `pass`, `assert`, `send`, and `with`.

Ranges use `start .. end` for a half-open range and `start ..= end` for an
inclusive range. Bounds have the same integer type after literal
contextualization. A half-open range is empty when `start >= end`; an inclusive
range is empty when `start > end` and yields its maximum endpoint without
performing an overflowing increment. The compiler uses constant bounds in work
and memory analyses.

```wrela
for i in 0 .. entries.len():
    ...

for take buffer in take buffers:
    install(take buffer)

with request(deadline=now() + ms(50)) as req:
    result = await disk.read(req, lba)?
```

`pass` is an explicit no-op. `send actor.method(...)` enqueues a one-way actor
message; the method must return `unit`, and capacity must be proven as described
in [Actors and async](04-actors-and-async.md). `try send actor.method(...)` is
an expression returning the second-class `AdmissionResult` control-flow carrier
with the lazy argument evaluation specified below.

`comptime if` may guard statements or declarations. Only the selected branch
exists after specialization.

`with` has deterministic exit semantics described in
[Values, views, and regions](03-values-views-regions.md).

A `for` iterable is evaluated once before iteration. Its binding is freshly
initialized each iteration and torn down before `continue`, the semantic
async back-edge checkpoint (when present), or the next binding; `break` tears down the current
binding and iterator. A `while` condition is a new full expression on every
iteration. `break`, `continue`, `return`, and `?` run all exited cleanup
nodes before transferring control. Loop `else` clauses and value-producing
`break` are not in revision 0.1.

## 8. Expressions and precedence

From tightest to loosest binding, the relevant operators are:

1. member access, call, and indexing;
2. unary `-`, `~`, prefix `await`, prefix `take`, and prefix `copy`;
3. postfix `?`;
4. checked conversion `as Type`;
5. multiplicative `*`, `/`, `%`, `*%`;
6. additive `+`, `-`, `+%`, `-%`;
7. shifts `<<`, `<<%`, `>>`;
8. bitwise `&`, `^`, `|`;
9. ranges `..` and `..=`;
10. comparisons, membership, and identity-pattern tests;
11. boolean `not`;
12. boolean `and`; and
13. boolean `or`.

This ordering makes `await operation()?` mean `(await operation())?`, while a
plain `operation()?` still propagates the call's result.

This is the only use of `&` in revision 0.1: binary bitwise AND. There is no
reference declarator.

`and`, `or`, and `not` require `bool`. Bitwise/shift operators require
integer operands of the same type. Core numeric comparisons require compatible
types after explicit conversion; user equality/ordering uses the static
`Eq`/`Ord` contracts described above. `item in container` is the direct
specialized call `container.contains(item)` through `Contains[Item]` and
`not in` negates that result; its declared access effects still apply. Pattern
`is` is built in and does not invoke a user method.

Left shifts never mask or reduce their count: both `left << count` and
`left <<% count` fail when `count` is negative or is not less than the bit width
of `left`. The checked `<<` additionally fails when its exact mathematical
result is not representable in the operand type, so it never discards result
bits. `<<%` instead wraps the result to that type's bit width. `<<%=` is not an
assignment operator in revision 0.1.

Except where short-circuiting or assignment is stated below, operands and
subexpressions are evaluated exactly once from left to right as written. A call
evaluates its receiver first, then argument expressions in source order; named
argument order is source order, not parameter order. Constructors evaluate field
initializers in source order. Array/tuple elements and string interpolations are
likewise left-to-right. `and` and `or` evaluate the right operand only when
required. A match evaluates its scrutinee once, tests arms in source order, and
evaluates an arm guard only after that arm's pattern bindings are established.
Comparisons do not chain in revision 0.1; write `a < b and b < c` explicitly.

A call through `Actor[T]` is the one admission-aware call form. It evaluates
the actor receiver and reads any designated `RequestContext[R]` bare binding,
reserves/validates a logical mailbox and request-child slot,
and only after successful reservation evaluates argument expressions left to
right and atomically commits the message. Rejection, cancellation, or deadline
failure before reservation therefore evaluates no argument and moves no value.
There is no suspension/checkpoint between argument evaluation and commit.
`send` uses the same order with build-proven reservation. The expression
`try send actor.method(...)` performs a nonblocking reservation and returns
the second-class `AdmissionResult` carrier without evaluating arguments when
unavailable; on success it evaluates/commits. The carrier must be consumed by an
immediate `match`/`is` test. In `admitted`, moved sources are uninitialized;
in `rejected(reason)`, they remain initialized. At a control-flow join a source
is initialized only if every incoming arm restores it. For a linear source, all
joining arms must agree that it is initialized or uninitialized (or leave the
control flow); otherwise the match is rejected rather than creating a hidden
runtime drop flag.

An awaited actor call with `take` arguments uses the same immediate
ownership-conditioned carrier rule: `not_admitted` leaves sources initialized;
every other actor-call result consumes them. It must be consumed immediately by
`?` or `match`, whose arms obey the same convergence rule.

For a call argument, `mut` access becomes active and `take` moves its source
when that argument expression finishes evaluation; the access remains active
through the call. Consequently later arguments cannot touch overlapping storage.
An assignment evaluates its right-hand expression first and then its destination
place exactly once. A compound assignment evaluates and reserves its destination
place first, evaluates the right operand, then performs the read-modify-write.
Overlapping accesses that cannot satisfy these rules are compile errors rather
than invitations to reorder.

A **full expression** is an initializer, assignment right-hand side, expression
statement, condition, loop iterable, return/send/yield operand, match scrutinee or
guard, or one argument/default expression of an outer comptime evaluation.
Ordinary temporaries are torn down in reverse completion order at the end of
their full expression. A temporary moved into a result is not torn down there.
Lexical views end at their last use as specified by chapter 03; source exit
actions and strict-linear obligations run before reclaimable temporary teardown
when dependency order requires it. These orders are observable and part of
record/replay.

Postfix `?` applies to `Result`; it also unwraps a second-class fallible
projection result in an immediate view binding. `Ok(value)?` yields `value`;
`Err(error)?` runs lexical teardown, applies the unique explicit `From`
conversion when required, and returns `Err(converted)` from the enclosing
function. It is legal only when the enclosing function returns `Result` and the
conversion is defined. `Option` propagation is legal only in an
`Option`-returning function; converting `None` to an error requires an explicit
`ok_or`/`match` contract, including for view carriers.

## 9. Closures

A closure uses `|parameters| expression` for a single expression or
`|parameters|: suite` for a statement body; `async |` introduces an async
closure, and `take |` (or `async take |`) moves every captured non-scalar
value when the closure is created. Parameter access modes use the same syntax as functions. Its structural
function type is `fn(read T, mut U, take V) -> R`, with an optional leading
`async`. The parameter names are not part of the type. A closure is
non-escaping by default. As the sole exception to the normal parameter-type
rule, a non-escaping closure invoked synchronously by a projection/iteration
operation may declare `view T` or `mut view T` parameters; those views cannot
be returned or captured. A closure cannot outlive any access it captures.

A statically named module function or receiver-free associated function may be
passed where a non-escaping function type with exactly matching access modes and
result is required, as in `array.map_take(CacheLine.invalid)`. It is a
compile-time function item, not a storable code pointer; the call remains direct
after specialization. Bound receiver methods are not function values.

An escaping closure MUST use the `take |` form, cannot
capture a view, and is allocated in an explicit bounded `iso` or task-frame
region. It moves captured non-scalars, copies scalar captures, and leaves source
places uninitialized at creation. To retain a copyable aggregate, source first
creates `snapshot = copy value` and lets the closure move `snapshot`. An async
closure also consumes a statically reserved task slot. The
compiler rejects an escaping closure whose region or activation count is not
bounded.

Revision 0.1 provides no runtime code generation or textual macro system.

## 10. Attributes

Attributes begin with `@`, are resolved names, and take compile-time values.
Built-in revision 0.1 attributes include:

| Attribute | Meaning |
|---|---|
| `@image` | The unique compile-time image constructor. |
| `@app` | An application actor root. |
| `@service` | A service actor root. |
| `@driver` | A hardware-authorized driver actor root. |
| `@task(...)` | A statically bounded task entry and scheduling contract. |
| `@isr_safe` | Verify that a helper's transitive effect set is legal in ISR context. |
| `@receipt_handoff(input=name)` | Verify a driver proxy that creates caller-owned recovery atomically with admission of one moved input. |
| `@dma` | A device-visible layout checked by the target ABI. |
| `@wire(...)` | A persistent/network byte layout with fixed endian, version, offsets, and padding. |
| `@mmio` | A typed MMIO register layout checked by the target ABI. |
| `@offset` | A target-ABI field offset inside an MMIO or device layout. |
| `@layout_assert` | A read-only assertion evaluated after image layout. |
| `@test` | Declares a test. The bounded source-unit delivery contract covers module-level `comptime fn` tests; the complete revision 0.1 design also reserves full-image runtime forms described in chapter 06. |
| `@suspend_safe` | A scope whose owned state and exit action may remain active across `await`. |
| `@no_promote` | Reject image-region promotion at the annotated allocation or scope. |
| `@budget(...)` | Require a build-proven uninterrupted-work or memory bound. |
| `@uninterrupted(bound=...)` | Replace an async loop checkpoint, or document a sync loop, with a proven finite uninterrupted bound. |

Attributes do not expand arbitrary source text or introduce unhygienic names.
They attach typed metadata consumed in the fixed build phases. Unknown
attributes are a compile error unless imported from a tool namespace explicitly
declared as non-semantic.

The complete revision 0.1 declaration contract permits `@test` only on a
zero-argument `comptime fn`, `fn`, or `async fn` whose result is `unit` or
`Result[unit, E]`. It is not legal on an `isr fn`, method requiring a receiver,
generic function without manifest-supplied concrete arguments, `@image`
function, or function whose test activation/resource bounds cannot be proved.

The bounded source-level unit-test implementation gate is deliberately
narrower. To satisfy it, the compiler must accept a non-generic, module-level,
zero-argument `@test comptime fn` returning `unit` from a module declared by the
root package manifest. Production and test modules both appear in the
manifest's ordinary ordered module list; there is no implicit test-source scan
or hidden test-only module graph. Such a test may import and call ordinary
public production `comptime fn` declarations whose parameters, locals, and
result use `unit`, `bool`, a fixed-width or target-pointer-width integer, or a
nominal nongeneric flat `struct` containing only those scalar fields. The
implemented body subset includes typed or inferred locals and assignment,
scalar-field projection, complete named construction (or the sole positional
field of a one-field structure), flat-aggregate move and explicit-copy
behavior, branch definite initialization, returns, nested direct calls with
positional or declaration-matched named arguments, exact signed-minimum integer
literals, integer and boolean operations, comparisons, and `comptime assert` as
specified in chapter 06. Cross-module field access observes ordinary visibility
and equal layouts do not erase nominal type identity.

This is not a claim for class construction or values, receiver or associated
methods, generics, nested or non-scalar aggregates, aggregate equality,
floating-point values, `Result`/`Ok`/`Err`, non-test/actor assertion
supervision, or generated runtime-image execution. Selected generated-test
runtime assertions are implemented through native ABI2 objects, but their
packaged-QEMU execution remains pending.
Test execution, effective limits, result classification, and the exact current
boundary are specified in chapter 06.
Ordinary semantic float-literal lowering remains separately available to the
language; bounding its source spelling is not evidence that float values have
entered this comptime unit-test evaluator subset.

Of the built-ins, only `@uninterrupted(bound=...)` may be a statement attribute,
and it must immediately precede `for`, `while`, or `loop` at the same
indentation. Other statement attributes and an uninterrupted attribute on a
non-loop are errors.

Target packages may define additional semantic ABI attributes under their
qualified namespace. Such attributes are type-checked and are part of the
target contract; they are not arbitrary user macros.

An attribute on a field may appear at the start of the same logical field line,
as in `@offset(0x10) status: ReadWrite[u32]`; it still attaches only to that
field.

## 11. Normative grammar

The following EBNF is normative. The UTF-8 scanner performs escape validation,
removes comments, converts semicolons outside delimiters to `NEWLINE`, suppresses
physical newlines inside delimiters, and emits `NEWLINE`, `INDENT`, `DEDENT`,
and `EOF`. Blank/comment-only lines emit no layout token. Indentation must
match a previous level on dedent; an inconsistent dedent is an error. `{x}`
means zero or more, `[x]` means optional, and terminals are quoted. A trailing
comma is accepted exactly where `[ "," ]` appears below.
At a same-indent continuation the physical line ending emits `NEWLINE`. At a
dedent it emits no leading separator; for each closed indentation level it emits
`DEDENT` followed by `NEWLINE`, which terminates the completed compound
statement/declaration in its parent suite. A suite accepts that final separator
before its own `DEDENT`. At end of file the scanner acts as if a physical
newline occurred: it emits `NEWLINE` for a root-level simple construct or the
required `DEDENT, NEWLINE` pairs for open suites, then `EOF`.

Before semicolon conversion the scanner records its origin. After parsing, both
adjacent statements at such a boundary MUST be `simple_stmt`; otherwise the
semicolon is a syntax error. A semicolon never supplies the newline/indent
required after a compound-statement colon.

```ebnf
file             = module_decl, NEWLINE, { import_decl, NEWLINE },
                   { top_decl, NEWLINE }, EOF ;
module_decl      = "module", module_path ;
module_path      = IDENT, { ".", IDENT } ;
import_decl      = [ "pub" ], "import", module_path, [ "as", IDENT ]
                 | [ "pub" ], "from", module_path, "import",
                   import_list ;
import_list      = import_name, { ",", import_name }, [ "," ]
                 | "(", [ import_name, { ",", import_name }, [ "," ] ], ")" ;
import_name      = IDENT, [ "as", IDENT ] ;

top_decl         = { attribute, NEWLINE }, [ "pub" ], top_declaration ;
top_declaration  = const_decl | fn_decl | struct_decl | class_decl
                 | enum_decl | iface_decl | impl_decl
                 | projection_decl | scope_decl | brand_decl
                 | comptime_top_if ;
attribute        = "@", qualified_name,
                   [ "(", [ attribute_arguments ], ")" ] ;
attribute_arguments = attribute_argument, { ",", attribute_argument }, [ "," ] ;
attribute_argument = [ IDENT, "=" ], expression ;
const_decl       = "const", IDENT, [ ":", type ], "=", expression ;
brand_decl       = "brand", IDENT ;

fn_decl          = fn_prefix, "fn", IDENT, [ generic_params ],
                   "(", [ parameters ], ")", [ "->", type ], ":", suite ;
fn_prefix        = [ "async" | "isr" | "comptime" ] ;
parameters       = parameter, { ",", parameter }, [ "," ] ;
parameter        = receiver | [ access_mode ], IDENT, ":", type ;
receiver         = [ access_mode ], "self" ;
access_mode      = "read" | "mut" | "take" ;

struct_decl      = "struct", IDENT, [ generic_params ], ":", type_suite ;
class_decl       = "class", IDENT, [ generic_params ],
                   [ "implements", type_list ], ":", class_member_suite ;
enum_decl        = "enum", IDENT, [ generic_params ], ":", enum_suite ;
iface_decl       = "iface", IDENT, [ generic_params ], ":", iface_suite ;
impl_decl        = "impl", type, "for", type, ":", impl_suite ;
projection_decl  = "projection", IDENT, [ generic_params ],
                   "(", [ parameters ], ")",
                   "->", projection_carrier, "from", provenance_set,
                   ":", projection_suite ;
provenance_set   = IDENT, { ",", IDENT } ;
scope_decl       = "scope", IDENT, "(", [ parameters ], ")",
                   "->", type, ":", scope_suite ;
comptime_top_if  = "comptime", "if", expression, ":", top_decl_suite,
                   [ "comptime", "else", ":", top_decl_suite ] ;

field_decl       = { attribute }, IDENT, ":", type, [ "=", expression ] ;
initializer_decl = "init", "(", "mut", "self",
                   { ",", initializer_parameter }, [ "," ], ")",
                   [ "->", type ], ":", suite ;
initializer_parameter = [ access_mode ], IDENT, ":", type ;
member_decl      = { attribute, NEWLINE }, [ "pub" ], member_declaration ;
member_declaration = field_decl | fn_decl | projection_decl | scope_decl
                   | const_decl | comptime_member_if ;
comptime_member_if = "comptime", "if", expression, ":", member_decl_suite,
                     [ "comptime", "else", ":", member_decl_suite ] ;
enum_variant     = IDENT, [ "(", [ variant_payload ], ")" ] ;
variant_payload  = type, { ",", type }, [ "," ]
                 | variant_field, { ",", variant_field }, [ "," ] ;
variant_field    = IDENT, ":", type ;
iface_member     = { attribute, NEWLINE },
                   ( fn_prefix, "fn", IDENT, [ generic_params ],
                     "(", [ parameters ], ")", [ "->", type ]
                   | "projection", IDENT, [ generic_params ],
                     "(", [ parameters ], ")", "->",
                     projection_carrier, "from", provenance_set ) ;

type_suite       = NEWLINE, INDENT,
                   ( "pass" | member_decl, { NEWLINE, member_decl } ),
                   [ NEWLINE ], DEDENT ;
member_suite     = NEWLINE, INDENT, member_decl,
                   { NEWLINE, member_decl }, [ NEWLINE ], DEDENT ;
class_member_suite = NEWLINE, INDENT, class_member_decl,
                     { NEWLINE, class_member_decl }, [ NEWLINE ], DEDENT ;
class_member_decl = initializer_decl | member_decl ;
enum_suite       = NEWLINE, INDENT, enum_variant,
                   { NEWLINE, enum_variant }, [ NEWLINE ], DEDENT ;
iface_suite      = NEWLINE, INDENT, iface_member,
                   { NEWLINE, iface_member }, [ NEWLINE ], DEDENT ;
impl_suite       = NEWLINE, INDENT, impl_member,
                   { NEWLINE, impl_member }, [ NEWLINE ], DEDENT ;
impl_member      = { attribute, NEWLINE }, ( fn_decl | projection_decl ) ;
top_decl_suite   = NEWLINE, INDENT, top_decl,
                   { NEWLINE, top_decl }, [ NEWLINE ], DEDENT ;
member_decl_suite = NEWLINE, INDENT, member_decl,
                    { NEWLINE, member_decl }, [ NEWLINE ], DEDENT ;
projection_suite = suite ;  (* one yield on success; zero on error/None *)
scope_suite      = NEWLINE, INDENT, { statement, NEWLINE },
                   "enter", expression, NEWLINE,
                   [ "abort", ":", suite, NEWLINE ],
                   "exit", IDENT, ":", suite, [ NEWLINE ], DEDENT ;

generic_params   = "[", generic_param, { ",", generic_param }, [ "," ], "]" ;
generic_param    = IDENT, [ ":", type ]
                 | "const", IDENT, ":", type
                 | "region", IDENT ;
type_list        = type, { ",", type }, [ "," ] ;

type             = qualified_name, [ "[", type_args, "]" ]
                 | "[", type, ";", expression, "]"
                 | "(", type, ",", [ type_list ], ")"
                 | "view", type | "mut", "view", type
                 | "iso", "[", type, "]", type
                 | function_type ;
function_type    = [ "async" ], "fn", "(", [ function_type_params ], ")",
                   "->", type ;
function_type_params = function_type_param, { ",", function_type_param },
                       [ "," ] ;
function_type_param = [ access_mode ], type ;
type_args        = type_arg, { ",", type_arg }, [ "," ] ;
type_arg         = type | expression | "..", expression ;
projection_carrier = "view", type | "mut", "view", type
                   | "(", projection_carrier, ",",
                     [ projection_carrier,
                       { ",", projection_carrier }, [ "," ] ], ")"
                   | "Option", "[", projection_carrier, "]"
                   | "Result", "[", projection_carrier, ",", type, "]" ;

suite            = NEWLINE, INDENT, statement, { NEWLINE, statement },
                   [ NEWLINE ], DEDENT ;
statement        = { statement_attribute, NEWLINE },
                   ( simple_stmt | compound_stmt ) ;
statement_attribute = attribute ;
compound_stmt    = if_stmt | match_stmt | for_stmt | while_stmt | loop_stmt
                 | with_stmt | comptime_if ;
simple_stmt      = assignment | return_stmt | break_stmt | continue_stmt
                 | pass_stmt | assert_stmt | send_stmt | yield_stmt | comptime_assert
                 | expression ;

assignment       = local_assignment | place_assignment ;
local_assignment = [ "shadow" ], IDENT, [ ":", type ], "=", expression ;
place_assignment = assignment_target, assignment_op, expression ;
assignment_target = place_expression
                  | "(", assignment_target, ",",
                    [ assignment_target, { ",", assignment_target },
                      [ "," ] ], ")" ;
assignment_op    = "=" | "+=" | "-=" | "*=" | "/=" | "%="
                 | "&=" | "|=" | "^=" | "<<=" | ">>=" ;
return_stmt      = "return", [ expression ] ;
break_stmt       = "break" ;
continue_stmt    = "continue" ;
pass_stmt        = "pass" ;
assert_stmt      = "assert", expression, [ ",", STRING_LITERAL ] ;
send_stmt        = "send", call_expression ;
yield_stmt       = "yield", expression ;
comptime_assert  = "comptime", "assert", expression,
                   [ ",", STRING_LITERAL ] ;

if_stmt          = "if", expression, ":", suite,
                   { "elif", expression, ":", suite },
                   [ "else", ":", suite ] ;
match_stmt       = "match", expression, ":", NEWLINE, INDENT,
                   match_arm, { NEWLINE, match_arm }, DEDENT ;
match_arm        = "case", pattern, [ "if", expression ], ":", suite ;
pattern          = primary_pattern, { "|", primary_pattern } ;
primary_pattern  = "_" | literal_pattern | qualified_name,
                   [ "(", [ pattern_arguments ], ")" ]
                 | "bind", IDENT
                 | "(", pattern, ",", [ pattern_arguments ], ")"
                 | "[", [ pattern_arguments ], "]" ;
pattern_arguments = pattern_argument, { ",", pattern_argument }, [ "," ] ;
pattern_argument = [ "take" ], pattern ;
for_stmt         = "for", [ "take" ], IDENT, "in", [ "take" ],
                   expression, ":", suite ;
while_stmt       = "while", expression, ":", suite ;
loop_stmt        = "loop", ":", suite ;
with_stmt        = "with", expression, [ "as", with_binding ], ":", suite ;
with_binding     = IDENT, [ "[", "region", IDENT, "]" ] ;
comptime_if      = "comptime", "if", expression, ":", suite,
                   [ "comptime", "else", ":", suite ] ;

arguments        = argument, { ",", argument }, [ "," ] ;
argument         = [ IDENT, "=" ],
                   ( ( "mut" | "take" ), place_expression | expression ) ;
qualified_name   = IDENT, { ".", IDENT } ;

expression       = closure_expression | or_expression ;
closure_expression = [ "async" ], [ "take" ], "|",
                     [ closure_parameters ], "|",
                     ( expression | ":", suite ) ;
closure_parameters = closure_parameter, { ",", closure_parameter }, [ "," ] ;
closure_parameter = [ access_mode ], IDENT, ":", type ;
or_expression    = and_expression, { "or", and_expression } ;
and_expression   = not_expression, { "and", not_expression } ;
not_expression   = { "not" }, comparison_expression ;
comparison_expression = range_expression, [ comparison_tail ] ;
comparison_tail  = ( "==" | "!=" | "<" | "<=" | ">" | ">="
                   | "in" | "not", "in" ), range_expression
                 | "is", [ "not" ], pattern ;
range_expression = bit_or_expression,
                   [ ( ".." | "..=" ), bit_or_expression ] ;
bit_or_expression = bit_xor_expression, { "|", bit_xor_expression } ;
bit_xor_expression = bit_and_expression, { "^", bit_and_expression } ;
bit_and_expression = shift_expression, { "&", shift_expression } ;
shift_expression = additive_expression,
                   { ( "<<" | "<<%" | ">>" ), additive_expression } ;
additive_expression = multiplicative_expression,
                      { ( "+" | "-" | "+%" | "-%" ),
                        multiplicative_expression } ;
multiplicative_expression = cast_expression,
                            { ( "*" | "/" | "%" | "*%" ),
                              cast_expression } ;
cast_expression  = try_expression, { "as", type } ;
try_expression   = unary_expression, { "?" } ;
unary_expression = ( "-" | "~" | "await" | "take" | "copy"
                   | "comptime" ), unary_expression
                 | postfix_expression ;
postfix_expression = primary_expression, { postfix_suffix } ;
postfix_suffix   = ".", IDENT
                 | "(", [ arguments ], ")"
                 | "[", expression, "]" ;
primary_expression = literal | qualified_name
                   | "(", expression, ")"
                   | "(", expression, ",",
                     [ expression, { ",", expression }, [ "," ] ], ")"
                   | "[", [ expression,
                     { ",", expression }, [ "," ] ], "]"
                   | race_expression | try_send_expression ;
race_expression  = "race", "(", expression, ",", expression,
                   { ",", expression }, [ "," ], ")" ;
try_send_expression = "try", "send", call_expression ;

place_expression = place_atom, { ".", IDENT | "[", expression, "]" } ;
place_atom       = IDENT | "(", place_expression, ")" ;
call_expression = postfix_expression, "(", [ arguments ], ")" ;

literal          = INTEGER_LITERAL | FLOAT_LITERAL | STRING_LITERAL
                 | BYTE_STRING_LITERAL | CHAR_LITERAL
                 | "true" | "false" | "unit" ;
literal_pattern  = literal | "-", ( INTEGER_LITERAL | FLOAT_LITERAL ) ;
```

The parser resolves a bare arm-top identifier only as a fieldless variant; a
non-variant there is an error. In a constructor/tuple/array payload position, a
bare identifier is a fieldless variant when the expected payload enum has one
and otherwise introduces a binding. A constructor-head name followed by `(`
must resolve to a variant. `bind name` always introduces a binding and is
required to shadow a fieldless variant or bind at arm top level. These rules use
the expected static type, never capitalization or import order.

The `type_arg = type | expression | .. expression` choice is resolved contextually from the
declared generic parameter at the named type constructor. Parsing produces an
unclassified bracket argument; name resolution classifies it and reports a type
argument in a constant position or the reverse. It never guesses from
capitalization. The prefix `..N` form is accepted only by a standard bounded
capacity parameter such as `Bytes[..N]` or `String[..N]`; it is not a runtime
range expression.
