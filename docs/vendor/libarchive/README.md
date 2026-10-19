# Local CAB decoder notices

This directory bundles the decoder so no CDN or diagnostic-upload service is used.

- JavaScript factory and WebAssembly: `libarchive-wasm` **1.2.0**, npm tarball
  `https://registry.npmjs.org/libarchive-wasm/-/libarchive-wasm-1.2.0.tgz`.
  Upstream: <https://github.com/ofk/libarchive-wasm>.
- Runtime reports **libarchive 3.7.7**, **zlib 1.3.1**, **liblzma 5.6.4**, and
  **bz2lib 1.0.8**. Their notice/license files are retained alongside the engine.
- `engine.js` preserves the upstream factory and adds an ESM export and
  Node-only loader selectors for automated tests. Browser execution does not
  load Node modules. `cab-extractor.js` supplies an explicit local WASM asset URL,
  reads archive bytes in memory, and never extracts paths to a filesystem.
- The application validates CAB structure, paths and byte limits before calling
  the decoder. Tests include stored, MSZIP and LZX samples.

Original WASM SHA-256:
`99889a4e7c3d1968303ef334a0ca89efffaf8867eb7cbd7c265602d8e0b50e63`

Notice sources (matching versions):

- <https://raw.githubusercontent.com/ofk/libarchive-wasm/main/LICENSE>
- <https://raw.githubusercontent.com/libarchive/libarchive/v3.7.7/COPYING>
- <https://raw.githubusercontent.com/madler/zlib/v1.3.1/LICENSE>
- <https://raw.githubusercontent.com/tukaani-project/xz/v5.6.4/COPYING>
- <https://raw.githubusercontent.com/libarchive/bzip2/bzip2-1.0.8/LICENSE>
