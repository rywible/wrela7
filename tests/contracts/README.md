# Compiler layer contract fixtures

This tree will hold versioned, checked-in inputs and expected outputs at compiler
layer boundaries. Fixtures let work proceed inside a layer without requiring all
preceding layers to be operational.

Planned fixture families:

```text
syntax/       source text → syntax dump + diagnostics
hir/          syntax fixture → normalized HIR dump + diagnostics
sema/         hand-built/decoded HIR → analysis facts + diagnostics
wir/          WIR input → verified/optimized WIR + proof report
codegen/      verified WIR → inspected COFF object
link/         COFF object(s) → inspected and QEMU-booted .efi
protocol/     frontend/backend compatibility and corruption cases
```

Serialized formats are versioned. A fixture remains under its original schema
directory when a format changes, allowing compatibility and rejection behavior
to be tested explicitly.

