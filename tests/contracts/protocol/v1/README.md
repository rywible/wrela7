# Test-event frame fixtures, schema 1

`run-started.hex` is the lowercase hexadecimal canonical binary frame for a
test-protocol version 2 `RunStarted { test_count: 2 }` event at sequence zero.
The frame contains the fixed `WRELTST\0` header, little-endian versions and
lengths, CRC32C payload checksum, and the complete canonical payload.

The `wrela-test-protocol` tests decode this checked-in fixture indirectly by
requiring production encoding to reproduce it exactly. They also construct all
event variants through the same codec and apply targeted magic, version,
length, checksum, tag, UTF-8, sequence, trailing-byte, resource-limit, and
cancellation corruption. Mutation inputs are derived from this small canonical
fixture so corrupted binaries are not duplicated as opaque repository assets.
