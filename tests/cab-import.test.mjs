import test from 'node:test';
import assert from 'node:assert/strict';
import { importDiagnosticFiles } from '../docs/importer.js';
import { buildDashboard } from '../docs/analytics.js';
import { executiveBrief } from '../docs/executive.js';
import { makeCabinet, makeExpansionCabinet } from './helpers/cab-fixtures.mjs';

const cab = (members, options, name = 'AutopilotDiag.cab') => new File([makeCabinet(members, options)], name, { type: 'application/vnd.ms-cab-compressed' });

test('one stored CAB with thirty logs is analyzed without selecting individual members', async () => {
  const input = cab(Array.from({ length: 30 }, (_, index) => ({ name: `logs/update-${index}.log`, text: 'Windows Update request failed 0x80072ee2' })));
  const result = await importDiagnosticFiles([input]);
  assert.deepEqual(result.errors, []);
  assert.equal(result.archives.length, 1);
  assert.equal(result.archives[0].entryCount, 30);
  assert.equal(result.archives[0].analyzed, 30);
  assert.equal(result.archives[0].complete, true);
  assert.equal(result.reports.length, 1);
  assert.equal(buildDashboard(result.reports).metrics.eventsCount, 30);
  assert.ok(result.reports[0].events.every(event => event.source.startsWith('AutopilotDiag.cab / logs/')));
});

test('a multi-block MSZIP CAB decodes a shared compression dictionary and analyzes all members', async () => {
  const lines = Array.from({ length: 1700 }, (_, index) => `Windows Update scan observation ${index}\n`).join('');
  const result = await importDiagnosticFiles([cab([
    { name: 'scan.txt', text: lines },
    { name: 'AppWorkload.log', text: 'Detection failed with 0x87D1041C' },
    { name: 'CBS.log', text: 'CBS source missing 0x800f081f' }
  ], { compression: 'mszip' })]);
  assert.deepEqual(result.errors, []);
  assert.equal(result.archives[0].analyzed, 3);
  assert.equal(result.archives[0].complete, true);
  assert.equal(result.reports[0].events.length, 1702);
  assert.ok(result.reports[0].findings.some(finding => /detected after installation/.test(finding.title)));
});

test('mixed cabinets preserve per-entry gaps and do not mistake archive opening for complete analysis', async () => {
  const result = await importDiagnosticFiles([cab([
    { name: 'a/AppWorkload.log', text: 'Detection failed 0x87D1041C' },
    { name: 'b/AppWorkload.log', text: 'Installer exit code 1603' },
    { name: 'events.evtx', bytes: new Uint8Array([69, 108, 102, 70, 105, 108, 101, 0]) },
    { name: 'trace.etl', text: 'binary trace' },
    { name: 'inner.cab', text: 'nested archive' },
    { name: '../escape.log', text: 'must not be parsed 0x87D1041C' },
    { name: 'MDMDiagReport.xml', text: '<MDMDiagnostics><DeviceName>example-device</DeviceName></MDMDiagnostics>' },
    { name: 'bad.json', text: '{broken' }
  ], { compression: 'mszip' })]);
  assert.deepEqual(result.errors, []);
  const archive = result.archives[0];
  assert.equal(archive.entryCount, 8);
  assert.equal(archive.analyzed, 2);
  assert.equal(archive.skipped, 5);
  assert.equal(archive.failed, 1);
  assert.equal(archive.complete, false);
  assert.equal(result.reports[0].events.length, 2);
  assert.notEqual(result.reports[0].events[0].source, result.reports[0].events[1].source);
  assert.ok(archive.entries.find(entry => entry.name === 'events.evtx').reason.includes('EVTX'));
  assert.ok(archive.entries.find(entry => entry.name === '../escape.log').reason.includes('Parent'));
  assert.ok(result.reports[0].warnings.some(warning => /events\.evtx.*skipped/.test(warning)));
  const html = executiveBrief(buildDashboard(result.reports), 'CAB case', result.archives);
  assert.ok(html.includes('events.evtx'));
  assert.ok(html.includes('trace.etl'));
  assert.ok(html.includes('Partial / unavailable coverage'));
});

test('a corrupt CAB keeps its failed attempt visible while a separate valid log remains usable', async () => {
  const result = await importDiagnosticFiles([
    new File(['MSCFbroken'], 'broken.cab'),
    new File(['Windows Update scan failed 0x80072ee2'], 'good.log')
  ]);
  assert.equal(result.errors.length, 1);
  assert.equal(result.archives.length, 1);
  assert.equal(result.archives[0].complete, false);
  assert.match(result.archives[0].error, /Truncated/);
  assert.equal(result.reports.length, 1);
  assert.ok(result.reports[0].warnings.some(warning => /broken\.cab/.test(warning)));
});

test('a CAB with no supported evidence lists every file without inventing records or clearing earlier data', async () => {
  const result = await importDiagnosticFiles([cab([{ name: 'trace.etl' }, { name: 'registry.reg' }])]);
  assert.deepEqual(result.errors, []);
  assert.equal(result.reports.length, 0);
  assert.equal(result.archives[0].entries.length, 2);
  assert.equal(result.archives[0].skipped, 2);
  assert.equal(result.archives[0].analyzed, 0);
  assert.equal(result.archives[0].complete, false);
});

test('duplicate cabinet selection does not double-count its contents', async () => {
  const same = cab([{ name: 'WindowsUpdate.log', text: 'Windows Update failed 0x80072ee2' }]);
  const result = await importDiagnosticFiles([same, same]);
  assert.equal(result.archives.length, 2);
  assert.equal(result.archives[1].duplicates, 1);
  assert.equal(buildDashboard(result.reports).metrics.eventsCount, 1);
});

test('Unicode CAB member names retain file-table provenance and import their evidence', async () => {
  const result = await importDiagnosticFiles([cab([
    { name: 'café.log', text: 'Windows Update request failed 0x80072ee2' },
    { name: '日志.log', text: 'Detection failed 0x87D1041C' }
  ], { compression: 'mszip' })]);
  assert.deepEqual(result.errors, []);
  assert.equal(result.archives[0].analyzed, 2);
  assert.equal(result.archives[0].complete, true);
  assert.ok(result.reports[0].events.some(event => event.source.endsWith('café.log')));
  assert.ok(result.reports[0].events.some(event => event.source.endsWith('日志.log')));
});

test('CAB resource limits are checked before decompression and unsafe payload sizes remain visible', async () => {
  let reads = 0;
  const oversized = await importDiagnosticFiles([{ name: 'huge.cab', size: 101 * 1024 * 1024, arrayBuffer: () => { reads++; } }]);
  assert.match(oversized.archives[0].error, /100 MiB/);
  assert.equal(reads, 0);
  const bytes = makeCabinet([{ name: 'huge.log', text: 'x' }]);
  new DataView(bytes.buffer).setUint32(44, 65 * 1024 * 1024, true);
  const result = await importDiagnosticFiles([new File([bytes], 'bad-size.cab')]);
  assert.equal(result.reports.length, 0);
  assert.equal(result.archives[0].complete, false);
  assert.ok(result.archives[0].error);
});

test('selection-wide budgets include every cabinet and charge unlisted expanded folder output', async () => {
  const result = await importDiagnosticFiles([
    new File([makeExpansionCabinet()], 'large-folder.cab'),
    cab([{ name: 'small.log', text: 'A recorded observation' }], {}, 'second.cab')
  ]);
  assert.equal(result.archives[0].skipped, 1);
  assert.equal(result.archives[0].expandedBytes, 1);
  assert.match(result.archives[1].error, /Selection-wide CAB budget/);
  assert.equal(result.reports.length, 0);
});

test('many native reports share bounded archive summaries rather than multiplying every member notice', async () => {
  const members = Array.from({ length: 20 }, (_, index) => ({
    name: `report-${index}.json`, text: JSON.stringify({ started_at: '2026-10-19T00:00:00Z', sources: [`source-${index}.log`], warnings: ['Provided report notice'], events: [], findings: [] })
  }));
  members.push(...Array.from({ length: 40 }, (_, index) => ({ name: `registry-${index}.reg`, text: 'Unsupported registry data' })));
  const result = await importDiagnosticFiles([cab(members)]);
  assert.equal(result.reports.length, 20);
  assert.equal(result.archives[0].skipped, 40);
  assert.ok(result.reports.every(report => report.warnings.length < 6));
  assert.equal(result.archives[0].entries.length, 60);
});
