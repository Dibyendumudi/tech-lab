import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { decodeLogBytes, importDiagnosticFiles, readDiagnosticFiles, IMPORT_EXTENSIONS } from '../docs/importer.js';
import { buildDashboard, sanitizeText } from '../docs/analytics.js';
import { executiveBrief } from '../docs/executive.js';

const file = (name, text, type = 'application/octet-stream') => new File([text], name, { type });
const nativeReport = () => ({
  started_at: '2026-10-19T08:00:00Z', synthetic: false, sources: ['previous.log'],
  events: [{ uid: 'previous-event', source: 'previous.log', category: 'Enterprise', message: 'Recorded observation', timestamp: '2026-10-19T07:00:00Z' }],
  findings: [{ id: 'existing-finding', title: 'Existing diagnosis', category: 'Enterprise', severity: 'info', evidence: ['previous-event'], checks: [], recommendations: [] }]
});

function utf16(text, bigEndian = false, bom = true) {
  const bytes = new Uint8Array(text.length * 2 + (bom ? 2 : 0));
  if (bom) { bytes[0] = bigEndian ? 0xfe : 0xff; bytes[1] = bigEndian ? 0xff : 0xfe; }
  const view = new DataView(bytes.buffer);
  for (let i = 0; i < text.length; i++) view.setUint16(i * 2 + (bom ? 2 : 0), text.charCodeAt(i), !bigEndian);
  return bytes;
}

test('all seven readable formats produce real linked dashboard evidence in a mixed batch', async () => {
  const files = [
    file('AppWorkload.log', '<![LOG[Detection failed after installation with 0x87D1041C]LOG]!><time="08:00:00.000" date="10-19-2026" component="AppWorkload" context="" type="3" thread="1" file="">'),
    file('CBS.txt', '2026-10-19 08:01:00, Error CBS source missing 0x800f081f'),
    file('events.json', JSON.stringify([{ TimeCreated: '2026-10-19T08:02:00Z', ProviderName: 'WindowsUpdateClient', Id: 20, Message: 'Update scan failed 0x80072ee2' }])),
    file('signins.jsonl', JSON.stringify({ createdDateTime: '2026-10-19T08:03:00Z', status: { errorCode: 53000 }, conditionalAccessStatus: 'failure' })),
    file('events.ndjson', JSON.stringify({ timestamp: '2026-10-19T08:04:00Z', Message: 'ESP timed out waiting for app installation' })),
    file('signins.csv', 'Date (UTC),Sign-in error code,Correlation ID\r\n2026-10-19T08:05:00Z,53003,opaque-request-42\r\n'),
    file('updates.xml', '<Events><Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-WindowsUpdateClient"/><EventID>20</EventID><TimeCreated SystemTime="2026-10-19T08:06:00Z"/></System><RenderingInfo><Message>Update request failed: 0x8024402c</Message></RenderingInfo></Event></Events>')
  ];
  const result = await importDiagnosticFiles(files);
  assert.deepEqual(result.errors, []);
  assert.equal(result.reports.length, 1);
  const report = result.reports[0], dashboard = buildDashboard(result.reports);
  assert.equal(report.synthetic, false);
  assert.equal(dashboard.metrics.eventsCount, 7);
  assert.equal(report.sources.length, 7);
  for (const expected of ['0x87d1041c', '0x800f081f', 'aadsts53000', 'aadsts53003']) assert.ok(report.events.some(event => event.codes.some(code => code.toLowerCase() === expected)), expected);
  assert.ok(report.findings.length >= 6);
  assert.ok(report.findings.every(finding => finding.evidenceIds.length && finding.evidenceIds.every(id => report.events.some(event => event.id === id))));
  assert.ok(dashboard.metrics.categoriesCount >= 4);
});

test('Windows UTF-16 little/big endian exports work with BOM or a detectable BOM-less encoding', async () => {
  const text = 'TimeCreated,ProviderName,Message\r\n2026-10-19T08:00:00Z,WindowsUpdateClient,"Update failed 0x80072ee2"\r\n';
  for (const bigEndian of [false, true]) for (const bom of [false, true]) {
    const bytes = utf16(text, bigEndian, bom);
    assert.equal(decodeLogBytes(bytes).text, text);
    const result = await importDiagnosticFiles([file('export.csv', bytes)]);
    assert.deepEqual(result.errors, []);
    assert.equal(result.reports[0].events.length, 1);
    assert.ok(result.reports[0].findings.length);
  }
});

test('UTF-8 BOM, macOS-style names and empty MIME types do not block recognized files', async () => {
  const result = await importDiagnosticFiles([file('Mac log export.LOG', '\uFEFFInstaller exit code 1603; failure recorded', '')]);
  assert.deepEqual(result.errors, []);
  assert.equal(result.reports[0].events.length, 1);
});

test('existing diagnostic report JSON retains supplied findings alongside raw event JSON', async () => {
  const result = await importDiagnosticFiles([
    file('existing.json', JSON.stringify(nativeReport())),
    file('raw.json', JSON.stringify({ Message: 'Windows Update failed 0x80072ee2', TimeCreated: '2026-10-19T09:00:00Z' }))
  ]);
  assert.deepEqual(result.errors, []);
  assert.equal(result.reports.length, 2);
  assert.ok(result.reports.some(report => report.findings.some(finding => finding.title === 'Existing diagnosis')));
  assert.equal(buildDashboard(result.reports).metrics.eventsCount, 2);
});

test('a malformed report cannot masquerade as raw JSON; valid files in a partial batch survive', async () => {
  const result = await importDiagnosticFiles([
    file('malformed.json', JSON.stringify({ ...nativeReport(), findings: 'invalid' })),
    file('unknown.json', JSON.stringify({ id: 'inventory-only', name: 'ordinaryobject' })),
    file('valid.txt', 'Windows Update scan failed with 0x80072ee2')
  ]);
  assert.equal(result.errors.length, 2);
  assert.equal(result.reports.length, 1);
  assert.equal(result.reports[0].events.length, 1);
});

test('binary archives and native event traces get actionable errors, including renamed archives', async () => {
  const result = await importDiagnosticFiles([
    file('diagnostics.cab', 'MSCFarchive'), file('events.evtx', 'ElfFile\0data'), file('trace.etl', 'binary'),
    file('renamed.log', new Uint8Array([77, 83, 67, 70, 0, 0, 0, 0])),
    file('zeros.txt', new Uint8Array([0, 0, 0, 1, 0, 0, 0, 0]))
  ]);
  assert.equal(result.reports.length, 0);
  assert.equal(result.errors.length, 5);
  assert.ok(result.errors[0].includes('Extract'));
  assert.ok(result.errors[1].includes('JSON/XML'));
  assert.ok(result.errors[3].includes('binary'));
});

test('malformed structured exports are rejected, and JSONL reports partial-record loss', async () => {
  const result = await importDiagnosticFiles([
    file('bad.json', '{broken'), file('bad.csv', 'Message,Id\n"unterminated,2'),
    file('bad.xml', '<Events><Event></Events>'),
    file('partial.ndjson', '{bad}\n' + JSON.stringify({ Message: 'A valid observed event' }))
  ]);
  assert.equal(result.errors.length, 3);
  assert.equal(result.reports.length, 1);
  assert.equal(result.reports[0].events.length, 1);
  assert.ok(result.reports[0].warnings.some(warning => /line|record|invalid/i.test(warning)));
});

test('sensitive structured metadata and macOS user paths are redacted before rendering or export', async () => {
  const result = await importDiagnosticFiles([file('signins.json', JSON.stringify({
    createdDateTime: '2026-10-19T08:00:00Z', status: { errorCode: 53003 },
    userDisplayName: 'Sensitive Person', deviceDetail: { displayName: 'Secret-Laptop', deviceId: 'opaque-device-42' },
    userPrincipalName: 'person@example.test', correlationId: 'opaque-request-42', client_secret: 'super secret credential',
    Message: 'See /Users/sensitiveaccount/Desktop/log.txt; <img src=x onerror=alert(1)>'
  }))]);
  assert.deepEqual(result.errors, []);
  const output = JSON.stringify(result.reports);
  for (const secret of ['Sensitive Person', 'Secret-Laptop', 'opaque-device-42', 'opaque-request-42', 'person@example.test', 'super secret credential', 'sensitiveaccount']) assert.equal(output.includes(secret), false, secret);
  const html = executiveBrief(buildDashboard(result.reports), 'Imported raw logs');
  assert.equal(html.includes('<img '), false);
  assert.equal(html.includes('onerror='), false); // brief contains findings, not raw HTML evidence
  assert.ok(output.includes('AADSTS53003'));
  assert.equal(sanitizeText('"password": "quoted secret with spaces"').includes('quoted secret'), false);
});

test('repeated files do not double-count; local timestamps stay out of UTC charts', async () => {
  const same = file('sample.log', '2026-10-19 08:00:00 Windows Update scan failed 0x80072ee2');
  const result = await importDiagnosticFiles([same, same]);
  assert.equal(result.reports[0].events.length, 1);
  assert.equal(result.notices.length, 1);
  assert.equal(buildDashboard(result.reports).timeline.length, 0);
  assert.ok(result.reports[0].events[0].timestampIssue);
});

test('quoted credentials containing escaped quotes are fully removed on native report import', async () => {
  const raw = nativeReport();
  raw.events[0].message = JSON.stringify({ password: 'example"visible-tail', client_secret: 'credential\\"another-visible-tail', deviceName: 'host"private-tail' });
  const result = await importDiagnosticFiles([file('report.json', JSON.stringify(raw))]);
  assert.deepEqual(result.errors, []);
  const output = JSON.stringify(result.reports);
  for (const value of ['visible-tail', 'another-visible-tail', 'private-tail']) assert.equal(output.includes(value), false, value);
});

test('oversized selections fail before reading files', async () => {
  let reads = 0;
  const fake = { name: 'huge.log', size: 21 * 1024 * 1024, arrayBuffer: () => { reads++; throw new Error('should not read'); } };
  await assert.rejects(() => importDiagnosticFiles([fake]), /20 MiB/);
  await assert.rejects(() => importDiagnosticFiles(Array.from({ length: 21 }, () => ({ ...fake, size: 1 }))), /20 log files/);
  assert.equal(reads, 0);
  assert.deepEqual(await importDiagnosticFiles([]), { reports: [], errors: [], notices: [] });
});

test('the no-Worker fallback and actual picker share the supported format contract', async () => {
  const result = await readDiagnosticFiles([file('example.txt', 'A recorded observation')]);
  assert.equal(result.reports[0].events.length, 1);
  const html = readFileSync(new URL('../docs/index.html', import.meta.url), 'utf8');
  const accept = /id="exec-file-input"[^>]+accept="([^"]+)"/.exec(html)?.[1] || '';
  for (const ext of IMPORT_EXTENSIONS) assert.ok(accept.split(',').includes(ext), ext);
  assert.ok(html.includes('Import logs / reports'));
  assert.ok(html.includes('CAB, EVTX and ETL'));
});
