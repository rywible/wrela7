# Target package contract fixtures

Fixtures are grouped by target package schema. `v1/representative.toml` is a
byte-for-byte copy of the production AArch64 target package. Schema changes
must use a new version directory rather than silently changing old fixtures.

`minimum.toml` exercises every required field without descriptive comments;
it is decodable but intentionally not the canonical production encoding.
Files under `invalid/` each isolate one rejection boundary.
