import test from 'node:test';
import assert from 'node:assert/strict';
import {parseHTML} from 'linkedom';
import {importDiagnosticFiles, IMPORT_LIMITS} from '../docs/importer.js';
import {buildDashboard, parseReport} from '../docs/analytics.js';
import {buildExecutiveSummary, executiveSummaryHTML} from '../docs/executive-summary.js';
import {executiveBrief, timelineSVG} from '../docs/executive.js';
import {makeCabinet} from './helpers/cab-fixtures.mjs';

const largeLog = () => '2026-06-23 10:00:00 Observed operation\n'.repeat(60000);

test('large early CAB log preserves later diagnostic evidence and discloses truncated coverage', async () => {
  const bytes = makeCabinet([
    {name:'early.log', text:largeLog()},
    {name:'IntuneManagementExtension.log', text:'2026-06-23T10:01:00Z Detection failed 0x87D1041C\n'.repeat(100)}
  ], {compression:'mszip'});
  const result = await importDiagnosticFiles([new File([bytes], 'synthetic.cab')]);
  assert.deepEqual(result.errors, []);
  const archive = result.archives[0];
  assert.equal(archive.entries[0].status, 'partial');
  assert.equal(archive.entries[1].status, 'analyzed');
  assert.equal(archive.entries[1].eventCount, 100);
  assert.equal(archive.complete, false);
  assert.equal(archive.failed, 0);
  const data = buildDashboard(result.reports);
  assert.ok(data.events.length <= IMPORT_LIMITS.rawEvents);
  assert.equal(data.events.length, 25100);
  assert.match(timelineSVG(data), /100 timestamped records shown out of 25100 recorded events/);
  assert.ok(data.findings.some(finding => finding.diagnosis.ruleId === 'win32-detection'));
  assert.ok(result.reports[0].warnings.some(warning => /first 25,000 of 60,000/.test(warning)));
  const summary = buildExecutiveSummary(data, result.archives);
  assert.equal(summary.readiness.status, 'Limited');
  assert.match(summary.readiness.checks.find(check => check.name === 'UTC timeline').detail, /100 of 25100/);
  assert.equal(summary.readiness.checks.find(check => check.name === 'Import integrity').status, 'Limited');
  const html = executiveBrief(data, 'Synthetic regression', result.archives);
  assert.match(html, /Analysis readiness · Limited/);
  assert.match(html, /IntuneManagementExtension.log/);
  assert.match(html, /first 25,000 of 60,000/);
});

test('a large selected file also reserves capacity for a later selected log', async () => {
  const result = await importDiagnosticFiles([
    new File([largeLog()], 'early.log'),
    new File(['Windows Update failed 0x80072ee2'], 'WindowsUpdate.log')
  ]);
  assert.deepEqual(result.errors, []);
  assert.ok(result.reports[0].events.some(event => event.source === 'WindowsUpdate.log'));
  assert.ok(result.reports[0].events.length <= IMPORT_LIMITS.rawEvents);
});

test('readiness reports no evidence for empty filters and keeps latest archive inventory separate', () => {
  const empty = buildDashboard([]);
  const summary = buildExecutiveSummary(empty, [{error:'failed latest import', entries:[]}]);
  assert.equal(summary.readiness.status, 'No evidence');
  assert.equal(summary.readiness.checks.find(check => check.name === 'UTC timeline').status, 'Unknown');
  assert.match(executiveSummaryHTML(summary), /not an endpoint health test/);
});

test('readiness uses canonical UTC timestamps, missing sources and the current filters', () => {
  const report = parseReport({started_at:'2026-01-01T10:00:00Z', sources:[{name:'missing.log', available:false}, 'available.log'], events:[
    {uid:'a', source:'available.log', message:'timed', timestamp:'2026-01-01T10:00:00+05:30'},
    {uid:'b', source:'available.log', message:'local', timestamp:'2026-01-01T10:00:00'}
  ], findings:[]});
  const summary = buildExecutiveSummary(buildDashboard([report]));
  assert.equal(summary.readiness.status, 'Limited');
  assert.match(summary.readiness.checks.find(check => check.name === 'UTC timeline').detail, /1 of 2/);
  assert.equal(summary.readiness.checks.find(check => check.name === 'Source availability').status, 'Limited');
  const filtered = buildExecutiveSummary(buildDashboard([report], {query:'no-matching-record'}));
  assert.equal(filtered.readiness.status, 'No evidence');
  const {document} = parseHTML(executiveSummaryHTML(summary));
  assert.equal(document.querySelectorAll('.exec-readiness tbody tr').length, 5);
});
