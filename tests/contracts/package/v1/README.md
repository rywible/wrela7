# Package codec schema 1 fixtures

These files pin the production `wrela.toml` schema-1 spelling. Revision 0.1
has no lockfile: the dependency graph is fully determined by `wrela.toml`
together with the toolchain-shipped `core` component
(`docs/language/02-source-language.md` §2.1), so there is no generated
`wrela.lock` fixture to also pin. `representative.toml` and `minimal.toml` are
byte-exact canonical output; `noncanonical.toml` is a valid input whose decoded
model re-encodes differently, and `equivalent.toml` exercises TOML 1.0 quoted
and dotted keys, literal and multiline strings, alternate integer radices,
inline tables, and inline arrays of tables. The `invalid/` files exercise
closed-schema, duplicate-key, signed-nondecimal, and default recursion-depth
rejection classes.

The production codec applies a hard 16 MiB ceiling to each manifest before
entering the TOML parser. This bounds the parser's residual noncooperative
region independently of larger host loader limits; cancellation is polled
before parsing and throughout semantic-DOM projection.

Model-level unit regressions additionally pin Unicode 16 source identifiers for
module segments, dependency aliases, and image entries; exhaustive keyword and
default-ignorable rejection; root-reachable package-graph closure; and bounded
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
