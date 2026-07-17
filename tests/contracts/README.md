# Compiler layer contract fixtures

This tree holds versioned, checked-in inputs and expected outputs at compiler
layer boundaries. Fixtures let work proceed inside a layer without requiring all
preceding layers to be operational.

Current and planned fixture families:

```text
package/      manifest/lock TOML → canonical package models and bytes
syntax/       source text → lossless syntax + diagnostics
hir/          syntax fixture → normalized HIR dump + diagnostics
sema/         hand-built/decoded HIR → analysis facts + diagnostics
semantic-wir/ analyzed image → validated SemanticWir + exact lowering report
flow-wir/     SemanticWir → validated/optimized FlowWir + proof/pass reports
machine-wir/  optimized FlowWir + target → validated MachineWir + layout report
codegen/      verified WIR → inspected COFF object
link/         COFF object(s) → inspected and QEMU-booted .efi
target/       canonical target package TOML and rejection cases
toolchain/    canonical atomic-toolchain manifest and rejection cases
toolchain/linux-payload-authority/ canonical Linux payload authority and rejection cases
protocol/     canonical test-event frames and corruption cases
```

Serialized trust-boundary formats carry an exact-current schema discriminator.
Only the current encoder/decoder and its rejection fixtures are retained: when
an unreleased format changes, its fixture directory is replaced in the same
change. Stale-schema mutations prove fail-closed behavior; they do not create a
legacy reader, migration path, or compatibility promise.
