import test from 'node:test';
import assert from 'node:assert/strict';
import { CAB_LIMITS, inspectCabinet } from '../docs/cab-format.js';

/** Small valid stored cabinet; metadata patches exercise malformed boundaries. */
function cabinet(members = [{ name: 'AppWorkload.log', text: 'Install failed 1603' }], options = {}) {
  const encode = value => new TextEncoder().encode(value);
  const headerReserve = options.reserve ? new Uint8Array([1, 2]) : new Uint8Array();
  const folderReserve = options.reserve ? 2 : 0, dataReserve = options.reserve ? 3 : 0;
  const data = members.map(member => encode(member.text ?? 'x'));
  const names = members.map(member => encode(member.name));
  const filesOffset = 36 + (options.reserve ? 4 + headerReserve.length : 0) + 8 + folderReserve;
  const dataOffset = filesOffset + names.reduce((sum, name) => sum + 17 + name.length, 0);
  const payload = new Uint8Array(data.reduce((sum, value) => sum + value.length, 0));
  let payloadOffset = 0;
  for (const value of data) { payload.set(value, payloadOffset); payloadOffset += value.length; }
  const bytes = new Uint8Array(dataOffset + 8 + dataReserve + payload.length), view = new DataView(bytes.buffer);
  view.setUint32(0, 0x4643534d, true); view.setUint32(8, bytes.length, true); view.setUint32(16, filesOffset, true);
  bytes[24] = 3; bytes[25] = 1; view.setUint16(26, 1, true); view.setUint16(28, members.length, true);
  let offset = 36;
  if (options.reserve) {
    view.setUint16(30, 4, true); view.setUint16(offset, headerReserve.length, true); bytes[offset + 2] = folderReserve; bytes[offset + 3] = dataReserve;
    bytes.set(headerReserve, offset + 4); offset += 4 + headerReserve.length;
  }
  const folderOffset = offset;
  view.setUint32(offset, dataOffset, true); view.setUint16(offset + 4, 1, true); view.setUint16(offset + 6, options.compression ?? 0, true);
  offset = filesOffset; let fileOffset = 0;
  for (let index = 0; index < members.length; index++) {
    view.setUint32(offset, data[index].length, true); view.setUint32(offset + 4, fileOffset, true); view.setUint16(offset + 14, 0x80, true);
    bytes.set(names[index], offset + 16); offset += names[index].length + 17; fileOffset += data[index].length;
  }
  view.setUint16(dataOffset + 4, payload.length, true); view.setUint16(dataOffset + 6, payload.length, true);
  bytes.set(payload, dataOffset + 8 + dataReserve);
  return { bytes, view, filesOffset, folderOffset, dataOffset };
}

test('stored cabinet exposes bounded member and data-block metadata', () => {
  const input = cabinet([{ name: 'logs/AppWorkload.log', text: 'failed 1603' }, { name: 'logs/CBS.log', text: 'source missing' }]);
  const result = inspectCabinet(input.bytes);
  assert.equal(result.declaredBytes, input.bytes.length);
  assert.equal(result.totalExpandedBytes, 25);
  assert.equal(result.entries.length, 2);
  assert.deepEqual(result.entries.map(entry => [entry.name, entry.offset, entry.size, entry.unsafe]), [['logs/AppWorkload.log', 0, 11, false], ['logs/CBS.log', 11, 14, false]]);
  assert.equal(result.folders[0].compressionName, 'stored');
  assert.equal(result.folders[0].blocks[0].dataOffset, input.dataOffset + 8);
  assert.equal(result.folders[0].uncompressedBytes, 25);
});

test('reserve sections and byte views respect their exact input offsets', () => {
  const input = cabinet(undefined, { reserve: true });
  const padded = new Uint8Array(input.bytes.length + 9); padded.set(input.bytes, 5);
  const result = inspectCabinet(new DataView(padded.buffer, 5, input.bytes.length));
  assert.equal(result.entries[0].name, 'AppWorkload.log');
  assert.equal(result.folders[0].blocks[0].dataOffset, input.dataOffset + 11);
});

test('cabinet members are independent of the 20 selected-file limit', () => {
  assert.equal(inspectCabinet(cabinet(Array.from({ length: 30 }, (_, index) => ({ name: `${index}.log`, text: 'x' }))).bytes).entries.length, 30);
  const fixture = cabinet([{ name: 'a.log' }, { name: 'b.log' }]);
  assert.throws(() => inspectCabinet(fixture.bytes, { entries: 1 }), /entry\/folder limit/);
});

test('unsafe traversal, absolute, drive, stream and overly long names remain visible but skipped', () => {
  const names = ['../CBS.log', '..\\CBS.log', '/CBS.log', '\\\\server\\CBS.log', 'C:\\CBS.log', 'safe.log:stream', 'a'.repeat(1100) + '.log', 'folder/'];
  const result = inspectCabinet(cabinet(names.map(name => ({ name }))).bytes);
  assert.equal(result.entries.length, names.length);
  for (const entry of result.entries) { assert.equal(entry.unsafe, true, entry.name); assert.ok(entry.reason); assert.ok(entry.name.length <= 1024); }
});

test('truncated signature, header, declared size, reserves, tables and data are rejected', () => {
  assert.throws(() => inspectCabinet(new Uint8Array(35)), /Truncated/);
  const mutations = [
    input => input.view.setUint32(0, 0, true),
    input => input.view.setUint32(8, input.bytes.length + 1, true),
    input => input.view.setUint32(16, input.bytes.length - 1, true),
    input => input.view.setUint32(input.folderOffset, input.bytes.length - 1, true),
    input => input.view.setUint16(input.dataOffset + 4, 32768, true)
  ];
  for (const mutate of mutations) { const input = cabinet(); mutate(input); assert.throws(() => inspectCabinet(input.bytes)); }
  const input = cabinet(undefined, { reserve: true }); input.view.setUint16(36, 65535, true);
  assert.throws(() => inspectCabinet(input.bytes), /reserve/);
});

test('multipart headers and continued-file markers are rejected before extraction', () => {
  for (const flag of [1, 2, 3]) { const input = cabinet(); input.view.setUint16(30, flag, true); assert.throws(() => inspectCabinet(input.bytes), /Multipart/); }
  const numbered = cabinet(); numbered.view.setUint16(34, 1, true); assert.throws(() => inspectCabinet(numbered.bytes), /Multipart/);
  for (const folder of [0xfffd, 0xfffe, 0xffff]) { const input = cabinet(); input.view.setUint16(input.filesOffset + 8, folder, true); assert.throws(() => inspectCabinet(input.bytes), /spanned/); }
  const split = cabinet(); split.view.setUint16(split.dataOffset + 6, 0, true); assert.throws(() => inspectCabinet(split.bytes), /continuation/);
});

test('version, reserved and compression metadata are strict and all known methods are enumerated', () => {
  for (const type of [0x0f, 0x0101, 0x0003, 0x0e03, 0x1603, 0x0f13, 0x0002, 0x0a82, 0x8000]) {
    assert.throws(() => inspectCabinet(cabinet(undefined, { compression: type }).bytes), /compression|LZX|Quantum/);
  }
  assert.equal(inspectCabinet(cabinet(undefined, { compression: 0x0f03 }).bytes).folders[0].compressionName, 'LZX');
  assert.equal(inspectCabinet(cabinet(undefined, { compression: 0x0a12 }).bytes).folders[0].compressionName, 'Quantum');
  const mszip = cabinet([{ name: 'one.log', text: 'CKxx' }], { compression: 1 });
  assert.equal(inspectCabinet(mszip.bytes).folders[0].compressionName, 'MSZIP');
  const badMszip = cabinet(undefined, { compression: 1 }); assert.throws(() => inspectCabinet(badMszip.bytes), /CK/);
  const version = cabinet(); version.bytes[24] = 2; assert.throws(() => inspectCabinet(version.bytes), /version/);
  const reserved = cabinet(); reserved.view.setUint32(12, 1, true); assert.throws(() => inspectCabinet(reserved.bytes), /Reserved/);
});

test('limits reject input bytes, declared files and unlisted expanded block output', () => {
  const input = cabinet([{ name: 'a.log', text: '0123456789' }]);
  assert.throws(() => inspectCabinet(input.bytes, { fileBytes: input.bytes.length - 1 }), /compressed-file size/);
  assert.throws(() => inspectCabinet(input.bytes, { entryBytes: 9 }), /member-size/);
  assert.throws(() => inspectCabinet(input.bytes, { expandedBytes: 9 }), /member sizes/);
  input.view.setUint32(input.filesOffset, 1, true);
  assert.throws(() => inspectCabinet(input.bytes, { expandedBytes: 9 }), /Folder data blocks/);
  assert.equal(CAB_LIMITS.fileBytes, 100 * 1024 * 1024);
  assert.throws(() => inspectCabinet(input.bytes, { entries: Infinity }), /Invalid/);
});

test('file ranges cannot escape folder output and data cannot overlap metadata', () => {
  const input = cabinet(); input.view.setUint32(input.filesOffset + 4, 1, true);
  assert.throws(() => inspectCabinet(input.bytes), /Member range/);
  const overlap = cabinet(); overlap.view.setUint32(overlap.folderOffset, overlap.filesOffset, true);
  assert.throws(() => inspectCabinet(overlap.bytes), /overlaps.*metadata/);
  const stored = cabinet(); stored.view.setUint16(stored.dataOffset + 6, 1, true);
  assert.throws(() => inspectCabinet(stored.bytes), /sizes differ/);
});

test('overlapping folders and excessive block scans are rejected independently of file sizes', () => {
  const source = cabinet(), bytes = new Uint8Array(source.bytes.length + 8);
  bytes.set(source.bytes.subarray(0, source.filesOffset)); bytes.set(source.bytes.subarray(source.filesOffset), source.filesOffset + 8);
  const view = new DataView(bytes.buffer);
  view.setUint32(8, bytes.length, true); view.setUint32(16, source.filesOffset + 8, true); view.setUint16(26, 2, true);
  view.setUint32(source.folderOffset, source.dataOffset + 8, true);
  view.setUint32(source.filesOffset, source.dataOffset + 8, true); view.setUint16(source.filesOffset + 4, 1, true);
  assert.throws(() => inspectCabinet(bytes), /ranges overlap/);
  view.setUint16(source.folderOffset + 4, 65535, true); view.setUint16(source.filesOffset + 4, 2, true);
  assert.throws(() => inspectCabinet(bytes), /block scan limit/);
});

test('invalid UTF-8 names are enumerated as unsafe and block output cannot exceed 32 KiB', () => {
  const name = cabinet([{ name: 'x.log' }]); name.bytes[name.filesOffset + 16] = 0xff;
  const entry = inspectCabinet(name.bytes.buffer).entries[0];
  assert.equal(entry.unsafe, true); assert.match(entry.reason, /UTF-8/);
  const block = cabinet(); block.view.setUint16(block.dataOffset + 6, 32769, true);
  assert.throws(() => inspectCabinet(block.bytes), /data-block size/);
});
