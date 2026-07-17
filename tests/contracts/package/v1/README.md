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
