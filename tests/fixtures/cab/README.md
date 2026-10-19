These tiny synthetic CAB fixtures come from the libarchive **v3.7.7** regression
suite, under the libarchive notices retained in `docs/vendor/libarchive/`.
They contain demonstration text/zero-filled files, not endpoint diagnostics.

- `test_read_format_cab_1.cab`: stored.
- `test_read_format_cab_2.cab`: MSZIP, including a multi-block 33,000-byte file.
- `test_read_format_cab_3.cab`: LZX, including a multi-block 33,000-byte file.

Source: `https://github.com/libarchive/libarchive/tree/v3.7.7/libarchive/test`
The upstream `.cab.uu` files were decoded without changing their CAB contents.
