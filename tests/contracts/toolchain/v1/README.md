# Toolchain manifest schema 1 fixtures

`minimum.toml` and `representative.toml` are byte-canonical complete manifests.
The `invalid` fixtures distinguish malformed, duplicate, unknown,
noncanonical, corrupted digest/path/measurement, limit, and cancellation
behavior. The schema-1 standard-library component and target-package directory
digests use canonical tree digest v1 (`WRELTRE\0`, version 1); executable
components and target-file records use raw SHA-256. Changing either meaning
requires a schema change.
