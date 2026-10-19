/** Read CAB member bytes locally. No archive path is written to any filesystem. */
import createLibarchive from './vendor/libarchive/engine.js';
import { inspectCabinet, CAB_LIMITS } from './cab-format.js';

let runtimePromise;
async function runtime() {
  if (!runtimePromise) runtimePromise = (async () => {
    const url = new URL('./vendor/libarchive/libarchive.wasm', import.meta.url);
    let wasmBinary;
    if (typeof process !== 'undefined' && process.versions?.node) {
      wasmBinary = await (await import('node:fs/promises')).readFile(url);
    } else {
      // Only this fixed, same-origin application asset is fetched, never diagnostics.
      const response = await fetch(url);
      if (!response.ok) throw new Error('The local CAB decoder asset could not be loaded. Refresh the page and try again.');
      wasmBinary = new Uint8Array(await response.arrayBuffer());
    }
    const module = await createLibarchive({ wasmBinary, locateFile: () => url.href, print: () => {}, printErr: () => {} });
    const bind = (name, result, args) => module.cwrap(name, result, args);
    return {
      module,
      open: bind('archive_read_new_memory', 'number', ['number', 'number', 'string']),
      next: bind('archive_read_next_entry', 'number', ['number']),
      size: bind('archive_entry_size', 'number', ['number']),
      name: bind('archive_entry_pathname_utf8', 'string', ['number']),
      type: bind('archive_entry_filetype', 'number', ['number']),
      symlink: bind('archive_entry_symlink_utf8', 'string', ['number']),
      hardlink: bind('archive_entry_hardlink_utf8', 'string', ['number']),
      read: bind('archive_read_data', 'number', ['number', 'number', 'number']),
      skip: bind('archive_read_data_skip', 'number', ['number']),
      error: bind('archive_error_string', 'string', ['number']),
      close: bind('archive_read_free', 'number', ['number'])
    };
  })().catch(error => { runtimePromise = undefined; throw error; });
  return runtimePromise;
}

const normalized = name => String(name).replace(/\\/g, '/').replace(/^(?:\.\/)+/, '');

/**
 * Metadata is revalidated at the trust boundary. Entries are yielded in CAB
 * file-table order; shouldExtract decides which data needs an output buffer.
 */
export async function* extractCabEntries(input, suppliedMetadata, shouldExtract = () => true) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  const metadata = inspectCabinet(bytes);
  if (suppliedMetadata && (suppliedMetadata.declaredBytes !== metadata.declaredBytes || suppliedMetadata.entries.length !== metadata.entries.length)) throw new Error('CAB inventory changed before extraction.');
  const api = await runtime(), mod = api.module;
  let pointer = 0, archive = 0, expanded = 0;
  const problem = fallback => new Error(api.error(archive) || fallback);
  try {
    pointer = mod._malloc(metadata.declaredBytes);
    if (!pointer) throw new Error('The browser could not allocate bounded CAB input memory.');
    mod.HEAPU8.set(bytes.subarray(0, metadata.declaredBytes), pointer);
    // Empty-string passphrases are invalid in libarchive; null means no password.
    archive = api.open(pointer, metadata.declaredBytes, null);
    if (!archive) throw new Error('The CAB decoder could not open this cabinet. It may be damaged or use unsupported compression.');
    for (const expected of metadata.entries) {
      const entry = api.next(archive);
      if (!entry) throw problem('The CAB ended before all listed files could be read.');
      const size = api.size(entry), name = api.name(entry);
      if (!Number.isSafeInteger(size) || size < 0 || size !== expected.size || size > CAB_LIMITS.entryBytes) throw new Error('CAB decoder size disagrees with the validated member table.');
      // This WASM build's C locale may not return a UTF-8 pathname for Unicode
      // members. Their original names were decoded and validated by preflight;
      // keep file-table order/size checks and never use names as output paths.
      if (!expected.unsafe && /^[\x00-\x7f]*$/.test(expected.name) && normalized(name) !== normalized(expected.name)) throw new Error('CAB decoder order or member names disagree with the validated file table.');
      if (expected.unsafe || !shouldExtract(expected)) {
        if (api.skip(archive) < 0) throw problem('The CAB could not advance past a skipped entry.');
        yield { index: expected.index, name: expected.name, size, bytes: null, skipped: true };
        continue;
      }
      if (api.type(entry) !== 32768 || api.symlink(entry) || api.hardlink(entry)) {
        if (api.skip(archive) < 0) throw problem('The CAB could not skip a non-regular entry.');
        yield { index: expected.index, name: expected.name, size, bytes: null, error: 'Only regular diagnostic files are read; links and special entries are skipped.' };
        continue;
      }
      if (expanded + size > CAB_LIMITS.expandedBytes) throw new Error('Extracted data exceeds the expanded CAB byte limit.');
      let output = 0;
      try {
        output = mod._malloc(Math.max(1, size));
        if (!output) throw new Error('The browser could not allocate bounded member memory.');
        let offset = 0;
        while (offset < size) {
          const count = api.read(archive, output + offset, Math.min(size - offset, 1024 * 1024));
          if (count < 0) throw problem('CAB decompression failed.');
          if (count === 0 || count > size - offset) throw new Error('CAB member data is truncated or exceeds its declared size.');
          offset += count;
        }
        // Verify EOF for this member with one bounded extra byte.
        const extra = api.read(archive, output, 1);
        if (extra < 0) throw problem('CAB checksum or decompression verification failed.');
        if (extra !== 0) throw new Error('CAB member output exceeds its validated size.');
        const data = mod.HEAPU8.slice(output, output + size);
        expanded += data.byteLength;
        yield { index: expected.index, name: expected.name, size, bytes: data };
      } finally { if (output) mod._free(output); }
    }
    if (api.next(archive)) throw new Error('The CAB contains more decoded entries than its validated inventory.');
    const finalError = api.error(archive);
    if (finalError) throw new Error(finalError);
  } finally {
    if (archive) { try { api.close(archive); } catch { /* Preserve the original decode failure. */ } }
    if (pointer) mod._free(pointer);
  }
}
