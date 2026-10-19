import { deflateRawSync } from 'node:zlib';

/** Synthetic cabinet writer for integration tests; never used by the application. */
export function makeCabinet(members, { compression = 'stored' } = {}) {
  const encode = value => new TextEncoder().encode(value);
  const files = members.map(member => ({ name: encode(member.name), data: member.bytes ? new Uint8Array(member.bytes) : encode(member.text ?? 'A diagnostic observation') }));
  const fileOffset = 44, dataOffset = fileOffset + files.reduce((sum, file) => sum + 17 + file.name.length, 0);
  const payload = new Uint8Array(files.reduce((sum, file) => sum + file.data.length, 0));
  let cursor = 0;
  for (const file of files) { payload.set(file.data, cursor); cursor += file.data.length; }
  const blocks = [];
  for (let start = 0; start < payload.length; start += 32768) {
    const data = payload.subarray(start, start + 32768);
    const body = compression === 'mszip' ? new Uint8Array([67, 75, ...deflateRawSync(data, start ? { dictionary: payload.subarray(Math.max(0, start - 32768), start) } : {})]) : data;
    blocks.push({ body, length: data.length });
  }
  const bytes = new Uint8Array(dataOffset + blocks.reduce((sum, block) => sum + 8 + block.body.length, 0));
  const view = new DataView(bytes.buffer);
  view.setUint32(0, 0x4643534d, true); view.setUint32(8, bytes.length, true); view.setUint32(16, fileOffset, true);
  bytes[24] = 3; bytes[25] = 1;
  view.setUint16(26, 1, true); view.setUint16(28, files.length, true);
  view.setUint32(36, dataOffset, true); view.setUint16(40, blocks.length, true); view.setUint16(42, compression === 'mszip' ? 1 : 0, true);
  cursor = fileOffset; let offset = 0;
  for (const file of files) {
    view.setUint32(cursor, file.data.length, true); view.setUint32(cursor + 4, offset, true); view.setUint16(cursor + 14, 0x80, true);
    bytes.set(file.name, cursor + 16); cursor += 17 + file.name.length; offset += file.data.length;
  }
  cursor = dataOffset;
  for (const block of blocks) {
    view.setUint16(cursor + 4, block.body.length, true); view.setUint16(cursor + 6, block.length, true);
    bytes.set(block.body, cursor + 8); cursor += 8 + block.body.length;
  }
  return bytes;
}

/** One unsupported member, with much larger valid folder output, without a huge fixture allocation. */
export function makeExpansionCabinet(blockCount = 8192) {
  const name = new TextEncoder().encode('trace.etl');
  const raw = new Uint8Array(32768), compressed = new Uint8Array([67, 75, ...deflateRawSync(raw)]);
  const dataOffset = 44 + 17 + name.length;
  const bytes = new Uint8Array(dataOffset + blockCount * (8 + compressed.length)), view = new DataView(bytes.buffer);
  view.setUint32(0, 0x4643534d, true); view.setUint32(8, bytes.length, true); view.setUint32(16, 44, true);
  bytes[24] = 3; bytes[25] = 1; view.setUint16(26, 1, true); view.setUint16(28, 1, true);
  view.setUint32(36, dataOffset, true); view.setUint16(40, blockCount, true); view.setUint16(42, 1, true);
  view.setUint32(44, 1, true); view.setUint16(58, 0x80, true); bytes.set(name, 60);
  let cursor = dataOffset;
  for (let i = 0; i < blockCount; i++) {
    view.setUint16(cursor + 4, compressed.length, true); view.setUint16(cursor + 6, 32768, true);
    bytes.set(compressed, cursor + 8); cursor += 8 + compressed.length;
  }
  return bytes;
}
