# Linux engine and host launchers

Status: proposed greenfield distribution direction. The current Darwin-native
distribution remains a bootstrap path until this design's conformance gates
pass; it is not a compatibility contract.

## 1. Product contract

Wrela has one public command language and one compiler engine, but a small
launcher per supported host:

```text
Darwin arm64 package                 Linux arm64 package
--------------------                 -------------------
signed native launcher               native launcher
immutable Linux arm64 payload   ==   immutable Linux arm64 payload
Virtualization.framework adapter     direct-process adapter

Linux x86_64 package
--------------------
native launcher
immutable Linux x86_64 payload
```

All packages expose the same `wrela` commands, diagnostics, event stream,
reports, cache rules, and AArch64 PE/COFF output contract. A host launcher is
not a second compiler implementation. It validates a payload, translates a
terminal invocation into the canonical engine protocol, and materializes only
validated outputs.

Apple Silicon Darwin and arm64 Linux use the same Linux engine bytes. Linux
x86_64 has a separately measured engine payload and must pass cross-engine
output-conformance tests. Intel Darwin is not a revision-0.1 release host.

There are no legacy protocol readers, payload adapters, migration modes, or
fallback engines. Every boundary carries an exact current schema identifier so
stale or untrusted artifacts fail before execution.

## 2. Authority boundary

The Darwin launcher owns only:

- signature/notarization delivery of the native launcher and outer bundle;
- validation of the immutable engine payload and boot components;
- lifecycle of one persistent, per-user Linux virtual machine;
- terminal input, terminal events, cancellation, and exit status;
- bounded import of declared inputs and atomic publication of outputs; and
- validation and eviction of a non-authoritative content cache.

The launcher never parses Wrela source, selects compiler passes, invokes host
LLVM/LLD/QEMU, interprets a report, or decides whether an image is valid.

The Linux engine owns the compiler, private backend, LLVM/LLD, QEMU, firmware,
runtime object, target packages, standard library, report/test codecs, and all
semantic decisions. The guest has no network device. Its root filesystem and
toolchain payload are read-only. It runs requests as an unprivileged identity
with a bounded writable request area and a separate bounded cache volume.

Apple's code signature is an authenticated delivery envelope, not part of the
compiler's reproducibility claim. The release manifest binds the signed
launcher package to the exact engine-payload, kernel, initial-filesystem, and
protocol digests. Compiler reproducibility is stated over a canonical request,
the immutable engine identity, and the resulting public output tree.

## 3. Input and output transport

The host filesystem is not compiler authority. A build does not compile from a
live VirtioFS tree. Before submitting a request, the launcher:

1. resolves only manifest-declared input paths under the selected workspace;
2. rejects links, special files, path traversal, collisions, unstable reads,
   excessive bytes, excessive records, and noncanonical text where required;
3. records each regular file as a canonical path, byte length, mode class, and
   SHA-256 digest;
4. writes a canonical content-addressed request bundle; and
5. sends the sealed request identity to the engine.

The engine opens only records in that bundle. Host absolute paths, inode
numbers, clocks, locale, environment, ownership, extended attributes, resource
forks, and directory enumeration order never enter build identity.

The engine returns a canonical event stream followed by a sealed output-tree
manifest. The launcher independently checks frame ordering, request identity,
path safety, record and byte limits, file digests, tree digest, terminal event,
and engine exit status before publishing any output. Publication uses a private
staging directory and same-filesystem atomic rename. Failure or cancellation
publishes no partial output.

Virtual sockets are the production transport on Darwin. VirtioFS may be used
only for explicitly non-authoritative bulk staging after both sides verify the
same canonical records; it is never the namespace from which the compiler
discovers inputs or directly publishes results.

## 4. Exact engine protocol

The engine transport is a bounded, ordered frame stream:

```text
ClientHello(current schema, launcher identity, payload identity, nonce)
ServerHello(current schema, engine identity, payload identity, nonce proof)
RequestHeader(request identity, command, policy, input-tree identity)
InputRecord* / InputChunk*
InputFinish(input-tree identity)
Event*
OutputHeader(output-tree policy)
OutputRecord* / OutputChunk*
OutputFinish(output-tree identity)
Terminal(outcome, report identities, exact resource use)
```

Every frame has a fixed magic, exact current version, kind, sequence number,
payload length, request identity, and digest. Decoders reject unknown kinds,
unknown fields, duplicate fields, sequence gaps, trailing bytes, oversized
payloads, noncanonical encodings, and version mismatch. An authenticated local
transport does not relax frame validation.

Cancellation is an explicit control frame bound to the request identity. The
engine polls cancellation through package loading, parsing, semantic work,
comptime evaluation, lowering, optimization, code generation, linking, QEMU,
report construction, and output framing. The launcher waits for a bounded
terminal cancellation acknowledgement, then terminates and replaces an
unresponsive engine process. Replacing a process does not mutate the immutable
payload.

The protocol version is a corruption/staleness guard, not a promise to read an
older format. A release contains exactly one launcher protocol and one engine
protocol.

## 5. Engine payload

The arm64 payload is one canonical measured tree containing:

- a statically linked or fully private-loader Linux `wrela-engine`;
- the private backend and its exact LLVM/LLD closure;
- the pinned AArch64 QEMU binary and private runtime libraries;
- exact firmware, target, runtime-object, and standard-library trees;
- canonical licenses, component manifest, and exact component-identity tuple; and
- no package manager, shell authority, downloader, network configuration, or
  mutable toolchain directory.

The Darwin bundle additionally contains a minimal arm64 Linux kernel and
initial/root filesystem whose digests are bound by the release manifest. The
guest boots directly into a small engine supervisor. It does not run a general
login service.

The Linux launcher validates the same component manifest and executes the
engine directly with an explicit payload root and cleared environment. A
release gate also runs the arm64 payload in appliance mode on Linux; direct and
appliance modes must produce identical public events and output trees for the
same canonical requests.

The current single-ELF `direct` mode is the first adapter slice, not that
release evidence. It is compiled only for the enrolled AArch64 Linux-musl ABI,
self-spawns the measured engine with a cleared environment, and validates the
complete engine-v1 response before publishing a canonical candidate receipt.
The candidate explicitly records `execution_proven=false`,
`payload_authority_proven=true`, and `runner_authority_proven=false`. The true
payload claim is narrow: an exact schema-1 authority envelope binds route, host,
protocol, canonical toolchain-manifest witness, and frontend-engine witness;
the direct child binds those witnesses during the existing single toolchain
scan, and schema-2 receipt publication requires the validated
`toolchain-verification` phase to finish. The current enrolled ELF predates this
source and no enrolled payload has produced that authority envelope yet. The
target ABI also cannot distinguish a native host from user-mode emulation, so
the authoritative integration consumer must still bind the real enrolled
payload and runner/appliance envelope before claiming execution.

The development toolchain now has a canonical schema-1 acquisition request and
receipt for the exact inputs that consumer still lacks. It separately binds the
static engine, Linux toolchain manifest and backend, Linux system QEMU, both
firmware images, portable standard-library/target/runtime inputs, and an
external native-runner authority envelope. The fixed contract rejects Darwin,
wrong-host, qemu-user, missing, reordered, aliased, stale, noncanonical, and
substituted identities. Its receipt can derive the existing payload authority
for the local manifest/frontend consumer, but both execution and runner proof
remain false. The name and digest of a runner envelope are not evidence that
native hardware ran the engine; that fact must come from the separately
authenticated runner or immutable-appliance boundary.

The local verifier now consumes that contract without repeating its expensive
toolchain observation. After an exact Linux-host/target preflight, it maps nine
payload inputs from its retained manifest, component-tree, target-tree, and
target-file measurements. It reads only the separately stored runner envelope,
once, as an opaque bounded stable regular file; then it seals the receipt and
requires the derived payload authority to bind back to the same verification.
Symlinks, nonregular files, replacement, zero/one-over length, cancellation,
and any requested-identity substitution fail closed. This implements the local
input-assembly consumer but does not close it with native integration evidence:
nothing in this path inspects the envelope as native-hardware evidence or
executes the engine.

## 6. Cache model

The cache is optional, content-addressed, bounded, and never authoritative.
Keys contain the complete engine identity, target identity, build policy, and
canonical input identities. A hit is accepted only after the engine revalidates
the record header, exact schema, lengths, content digest, and transitive input
identity. Corruption becomes a miss and a stable diagnostic is recorded for
doctor/reporting; it never changes compiler semantics.

Darwin keeps the cache on a separate writable virtual disk. Linux keeps it
under an explicitly selected Wrela state root. Cache records contain no host
absolute paths. LRU metadata may use host time for eviction only and is excluded
from build identity and public reports.

## 7. Virtual-machine lifecycle on Darwin

The production launcher uses Apple's Virtualization framework directly. A
separately installed container runtime is not required. The bundle carries the
virtualization entitlement required by the framework.

One VM may remain resident per logged-in user to avoid cold starts. The
launcher serializes VM creation with a create-new lease, verifies the running
supervisor handshake on every connection, and replaces a VM whose payload or
protocol identity differs from the current bundle. Requests have separate
directories and cancellation state; a failed request cannot contaminate a
later request.

The VM configuration is fixed and measured: virtual CPU count, memory limit,
read-only payload disk, bounded cache disk, socket device, console policy, and
absence of network devices. Resource policy is also carried per request, so a
persistent VM cannot turn process-global leftovers into undeclared authority.

## 8. Release and conformance gates

This design is shippable only after all of these are real:

1. A headless Linux engine accepts canonical requests without reading the host
   workspace or ambient environment.
2. Linux arm64 direct and appliance execution produce byte-identical public
   output trees for passing, failing, cancelled, exact-bound, and over-bound
   requests.
3. Darwin arm64 and Linux arm64 use the same measured engine payload and
   produce byte-identical events, EFI images, reports, and test reports for the
   same canonical request corpus.
4. Linux x86_64 produces the same target artifacts and canonical reports,
   except for explicitly host-envelope metadata that is kept outside compiler
   output identity.
5. Input mutation during capture, unsafe paths, frame corruption, stale
   schemas, payload substitution, cache corruption, quota exhaustion, guest
   crash, cancellation, and output substitution all fail closed with no
   partial publication.
6. The Darwin launcher is signed/notarized, the outer release manifest binds
   its exact Linux payload, and clean machines need no Homebrew, Docker,
   globally installed LLVM/QEMU, or ambient Cargo registry.
7. Two clean release builds reproduce the engine payload and public toolchain
   tree; separately signed Darwin envelopes authenticate those exact bytes
   without being used as byte-identity evidence.

## 9. Implementation order

1. Extract the existing composition root into a headless `wrela-engine`
   command that consumes only canonical request bundles and emits canonical
   event/output frames.
2. Implement the exact-current engine protocol and corruption/limit/
   cancellation contract tests.
3. Produce and exercise the Linux arm64 direct package in the existing clean
   distribution lanes.
4. Build the minimal immutable arm64 Linux payload and prove direct/appliance
   equivalence on Linux.
5. Add the signed Darwin Virtualization.framework launcher and persistent VM
   supervisor.
6. Add Linux x86_64 and cross-engine target-output conformance.
7. Remove the Darwin-native compiler/backend/QEMU payload after the new Darwin
   package passes the full release gates. No compatibility shim remains.

Apple's `container` project is useful for prototyping Linux virtual-machine
lifecycle and payload behavior, but it is not a production dependency. The
shipping Darwin launcher talks to Virtualization.framework itself.

Primary platform references:

- [Apple Virtualization framework](https://developer.apple.com/documentation/virtualization)
- [Creating and running a Linux virtual machine](https://developer.apple.com/documentation/virtualization/creating-and-running-a-linux-virtual-machine)
- [Virtio host/guest socket device](https://developer.apple.com/documentation/virtualization/vzvirtiosocketdevice)
- [Adding the virtualization entitlement](https://developer.apple.com/documentation/virtualization/adding-the-virtualization-entitlement-to-your-project)
- [Apple container technical overview](https://github.com/apple/container/blob/main/docs/technical-overview.md)
