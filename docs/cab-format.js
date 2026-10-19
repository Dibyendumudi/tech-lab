/** Bounded, metadata-only Microsoft Cabinet validation before local extraction. */
export const CAB_LIMITS = Object.freeze({
  fileBytes: 100 * 1024 * 1024,
  expandedBytes: 256 * 1024 * 1024,
  entries: 2000,
  entryBytes: 64 * 1024 * 1024
});

const MAX_BLOCKS = 65536;
const MAX_NAME_BYTES = 1024;
const MAX_BLOCK_OUTPUT = 32768;
const MAX_BLOCK_INPUT = 38912;
const fail = message => { throw new Error(`CAB: ${message}`); };

function boundedLimits(overrides) {
  const result = { ...CAB_LIMITS };
  for (const key of Object.keys(result)) {
    if (overrides[key] === undefined) continue;
    if (!Number.isSafeInteger(overrides[key]) || overrides[key] < 1) fail(`Invalid ${key} limit.`);
    result[key] = Math.min(result[key], overrides[key]);
  }
  return result;
}

function compressionInfo(type) {
  const compression = type & 0x000f, level = (type >>> 4) & 0x000f, windowBits = (type >>> 8) & 0x001f;
  if ((type & 0xe000) || compression > 3) fail('Unsupported or invalid folder compression metadata.');
  if (compression <= 1 && type !== compression) fail('Invalid stored/MSZIP compression parameters.');
  if (compression === 2 && (level < 1 || level > 7 || windowBits < 10 || windowBits > 21)) fail('Invalid Quantum compression parameters.');
  if (compression === 3 && (level !== 0 || windowBits < 15 || windowBits > 21)) fail('Invalid LZX compression window.');
  return { compression, compressionName: ['stored', 'MSZIP', 'Quantum', 'LZX'][compression], level, windowBits };
}

function unsafeName(name, tooLong, invalidUtf8) {
  if (tooLong) return 'Member name exceeds the 1024-byte safety limit.';
  if (invalidUtf8) return 'Member name has invalid UTF-8 encoding.';
  if (!name || /[\x00-\x1f\x7f]/.test(name)) return 'Member name is empty or contains control characters.';
  const path = name.replace(/\\/g, '/');
  if (path.startsWith('/') || /^[a-z]:/i.test(path)) return 'Absolute member paths are not allowed.';
  if (path.split('/').some(part => part === '..')) return 'Parent-directory member paths are not allowed.';
  if (path.includes(':')) return 'Member name contains a drive or alternate-stream separator.';
  if (path.endsWith('/')) return 'Directory entries are not analyzed.';
  return '';
}

/**
 * Inspect header, file table and every CFDATA block without decompressing data.
 * Structural errors throw. Unsafe names remain enumerated for explicit skipping.
 * Limits may be lowered by a caller, but never exceed the hard resource bounds.
 */
export function inspectCabinet(input, overrides = {}) {
  const limits = boundedLimits(overrides);
  let bytes;
  if (input instanceof Uint8Array) bytes = input;
  else if (input instanceof ArrayBuffer) bytes = new Uint8Array(input);
  else if (ArrayBuffer.isView(input)) bytes = new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
  else fail('Expected cabinet bytes.');
  if (bytes.byteLength > limits.fileBytes) fail('Archive exceeds the compressed-file size limit.');
  if (bytes.byteLength < 36) fail('Truncated cabinet header.');
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.getUint32(0, true) !== 0x4643534d) fail('Missing MSCF cabinet signature.');
  const declaredBytes = view.getUint32(8, true);
  if (declaredBytes < 36 || declaredBytes > bytes.byteLength) fail('Declared archive size is invalid or the cabinet is truncated.');
  if (declaredBytes > limits.fileBytes) fail('Archive exceeds the compressed-file size limit.');
  const requireRange = (offset, length, what) => {
    if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset < 0 || length < 0 || offset > declaredBytes - length) fail(`Truncated or invalid ${what}.`);
  };
  if (view.getUint32(4, true) || view.getUint32(12, true) || view.getUint32(20, true)) fail('Reserved header fields must be zero.');
  if (bytes[24] !== 3 || bytes[25] !== 1) fail('Only Microsoft Cabinet version 1.3 is supported.');
  const fileTableOffset = view.getUint32(16, true), folderCount = view.getUint16(26, true), fileCount = view.getUint16(28, true), flags = view.getUint16(30, true);
  if (flags & ~7) fail('Unknown cabinet header flags.');
  if ((flags & 3) || view.getUint16(34, true)) fail('Multipart or spanned cabinets are not supported. Select a complete single cabinet.');
  if (fileCount > limits.entries || folderCount > limits.entries) fail(`Archive exceeds the ${limits.entries}-entry/folder limit.`);
  let offset = 36, folderReserve = 0, dataReserve = 0;
  if (flags & 4) {
    requireRange(offset, 4, 'reserve header');
    const headerReserve = view.getUint16(offset, true);
    folderReserve = bytes[offset + 2]; dataReserve = bytes[offset + 3];
    offset += 4;
    requireRange(offset, headerReserve, 'header reserve data'); offset += headerReserve;
  }
  const folders = [];
  requireRange(offset, folderCount * (8 + folderReserve), 'folder table');
  let totalBlocks = 0;
  for (let index = 0; index < folderCount; index++) {
    const start = view.getUint32(offset, true), blockCount = view.getUint16(offset + 4, true), typeCompress = view.getUint16(offset + 6, true);
    totalBlocks += blockCount;
    if (totalBlocks > MAX_BLOCKS) fail('Archive exceeds the 65,536 data-block scan limit.');
    const info = compressionInfo(typeCompress);
    folders.push({ index, offset: start, blockCount, typeCompress, ...info, uncompressedBytes: 0, blocks: [] });
    offset += 8 + folderReserve;
  }
  if (fileTableOffset < offset) fail('File table overlaps the cabinet header or folder table.');
  requireRange(fileTableOffset, fileCount * 17, 'file table');
  offset = fileTableOffset;
  const entries = [];
  let totalExpandedBytes = 0;
  for (let index = 0; index < fileCount; index++) {
    requireRange(offset, 16, 'file entry');
    const size = view.getUint32(offset, true), fileOffset = view.getUint32(offset + 4, true), folder = view.getUint16(offset + 8, true), attributes = view.getUint16(offset + 14, true);
    if (folder >= 0xfffd) fail('Continued or spanned cabinet members are not supported.');
    if (folder >= folders.length) fail('Member references an invalid folder.');
    if (size > limits.entryBytes) fail('A cabinet member exceeds the expanded member-size limit.');
    totalExpandedBytes += size;
    if (totalExpandedBytes > limits.expandedBytes) fail('Declared member sizes exceed the expanded-data limit.');
    offset += 16;
    const nameStart = offset;
    while (offset < declaredBytes && bytes[offset] !== 0) offset++;
    if (offset === declaredBytes) fail('Unterminated or truncated member name.');
    const nameBytes = bytes.subarray(nameStart, offset), tooLong = nameBytes.length > MAX_NAME_BYTES;
    // Preserve bounded names only: an attacker-controlled multi-megabyte name
    // must not be decoded or copied into a result manifest.
    let name, invalidUtf8 = false;
    try { name = new TextDecoder(attributes & 0x80 ? 'utf-8' : 'windows-1252', { fatal: true }).decode(nameBytes.subarray(0, MAX_NAME_BYTES)); }
    catch { invalidUtf8 = true; name = new TextDecoder('utf-8').decode(nameBytes.subarray(0, MAX_NAME_BYTES)); }
    const reason = unsafeName(name, tooLong, invalidUtf8);
    entries.push({ index, name, size, folder, offset: fileOffset, attributes, unsafe: Boolean(reason), reason });
    offset++;
  }
  const fileTableEnd = offset, dataRanges = [];
  let blockExpandedBytes = 0;
  for (const folder of folders) {
    let cursor = folder.offset;
    if (cursor < fileTableEnd) fail('Folder data overlaps the cabinet metadata.');
    for (let index = 0; index < folder.blockCount; index++) {
      requireRange(cursor, 8 + dataReserve, 'data-block header');
      const checksum = view.getUint32(cursor, true), compressedBytes = view.getUint16(cursor + 4, true), uncompressedBytes = view.getUint16(cursor + 6, true), dataOffset = cursor + 8 + dataReserve;
      if (!uncompressedBytes) fail('Split or empty continuation data blocks are not supported.');
      if (uncompressedBytes > MAX_BLOCK_OUTPUT || !compressedBytes || compressedBytes > MAX_BLOCK_INPUT) fail('Invalid compressed or expanded data-block size.');
      requireRange(dataOffset, compressedBytes, 'compressed data block');
      if (folder.compression === 0 && compressedBytes !== uncompressedBytes) fail('Stored block compressed and expanded sizes differ.');
      if (folder.compression === 1 && (compressedBytes < 2 || bytes[dataOffset] !== 0x43 || bytes[dataOffset + 1] !== 0x4b)) fail('MSZIP data block is missing its CK signature.');
      folder.uncompressedBytes += uncompressedBytes; blockExpandedBytes += uncompressedBytes;
      if (blockExpandedBytes > limits.expandedBytes) fail('Folder data blocks exceed the expanded-data limit.');
      folder.blocks.push({ offset: cursor, dataOffset, compressedBytes, uncompressedBytes, checksum });
      cursor = dataOffset + compressedBytes;
    }
    if (folder.blockCount) dataRanges.push({ start: folder.offset, end: cursor });
  }
  dataRanges.sort((a, b) => a.start - b.start);
  for (let index = 1; index < dataRanges.length; index++) if (dataRanges[index].start < dataRanges[index - 1].end) fail('Folder data ranges overlap.');
  for (const entry of entries) {
    if (entry.offset + entry.size > folders[entry.folder].uncompressedBytes) fail('Member range extends beyond its folder expanded data.');
  }
  return { entries, folders, declaredBytes, totalExpandedBytes };
}
