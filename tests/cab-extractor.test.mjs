import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { extractCabEntries } from '../docs/cab-extractor.js';
import { inspectCabinet } from '../docs/cab-format.js';
import { makeCabinet } from './helpers/cab-fixtures.mjs';

test('real libarchive regression cabinets decode stored, MSZIP and LZX payloads locally', async () => {
  const outputs = [];
  for (const index of [1, 2, 3]) {
    const bytes = readFileSync(new URL(`./fixtures/cab/test_read_format_cab_${index}.cab`, import.meta.url));
    const metadata = inspectCabinet(bytes), entries = [];
    for await (const entry of extractCabEntries(bytes, metadata)) entries.push(entry);
    assert.equal(entries.length, metadata.entries.length);
    assert.ok(entries.every(entry => entry.bytes.length === entry.size));
    const first = entries.find(entry => entry.name === 'dir1\\file1' || entry.name === 'dir1/file1');
    assert.equal(first.bytes.length, 60);
    outputs.push(first.bytes);
    if (index > 1) assert.deepEqual(entries.find(entry => entry.name === 'zero').bytes, new Uint8Array(33000));
  }
  assert.deepEqual(outputs[0], outputs[1]);
  assert.deepEqual(outputs[1], outputs[2]);
});

test('selection callbacks skip bytes without flattening nested names', async () => {
  const bytes = makeCabinet([{ name: 'a/sample.log', text: 'first' }, { name: 'b/sample.log', text: 'second' }], { compression: 'mszip' });
  const result = [];
  for await (const entry of extractCabEntries(bytes, inspectCabinet(bytes), entry => entry.index === 1)) result.push(entry);
  assert.equal(result[0].bytes, null);
  assert.equal(result[0].skipped, true);
  assert.equal(new TextDecoder().decode(result[1].bytes), 'second');
  assert.equal(result[1].name, 'b/sample.log');
});

test('an invalid MSZIP deflate stream fails rather than returning fabricated evidence', async () => {
  const bytes = makeCabinet([{ name: 'sample.log', text: 'A real diagnostic message'.repeat(5) }], { compression: 'mszip' });
  const metadata = inspectCabinet(bytes);
  const firstDeflateByte = metadata.folders[0].blocks[0].dataOffset + 2;
  bytes[firstDeflateByte] = (bytes[firstDeflateByte] & ~6) | 6; // Reserved BTYPE=3.
  await assert.rejects(async () => { for await (const entry of extractCabEntries(bytes, metadata)) void entry; });
});
