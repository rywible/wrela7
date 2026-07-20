# Package codec schema 1 fixtures

These files pin the production `wrela.toml` and generated `wrela.lock` schema-1
spellings. `representative.*` and `minimal.*` are byte-exact canonical output;
`noncanonical.*` are valid inputs whose decoded models re-encode differently,
and `equivalent.*` exercise TOML 1.0 quoted and dotted keys, literal and
multiline strings, alternate integer radices, inline tables, and inline arrays
of tables. The `invalid/` files exercise closed-schema, duplicate-key,
signed-nondecimal, and default recursion-depth rejection classes.

The production codec applies a hard 16 MiB ceiling to each manifest or
lockfile before entering the TOML parser. This bounds the parser's residual
noncooperative region independently of larger host loader limits; cancellation
is polled before parsing and throughout semantic-DOM projection.

Model-level unit regressions additionally pin Unicode 16 source identifiers for
module segments, dependency aliases, and image entries; exhaustive keyword and
default-ignorable rejection; root-reachable lock/graph closure; and bounded
manifest-error previews. Those invariants do not require alternate TOML fixture
spellings.

These manifests declare no `[[module]]` block: `wrela_package_loader`'s
workspace loader derives modules from a deterministic, portable walk of
`source_root`, mapping every `*.wr` file to the module path given by its
root-relative path (`/` becomes `.`, the `.wr` suffix drops). A manifest
containing `[[module]]` is now an unknown-field error, exercised the same way
as any other unrecognized key by `invalid/unknown.toml`.

Every `[[profile]]` key besides `name` and `mode` is optional and defaults to
`wrela_build_model::PROFILE_DEFAULTS` when a manifest block omits it; the
fixtures above keep every key explicit because the canonical encoder always
materializes every field, so byte-exact round-tripping is unaffected by
whether the *source* TOML stated a key or relied on its default.
