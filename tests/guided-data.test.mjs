import test from 'node:test';
import assert from 'node:assert/strict';
import { parseReport } from '../docs/analytics.js';
import { casesFromReports, reportFromCase } from '../docs/guided-data.js';
import { reportHTML } from '../docs/app.js';

function imported(overrides = {}) {
  return parseReport({
    started_at: '2026-10-19T07:00:00Z',
    synthetic: false,
    sources: [{name:'AppWorkload.log',available:true,note:'Collected copy'}, {name:'Missing.log',available:false,note:'Not supplied'}],
    events: [
      {uid:'e1',timestamp:'2026-10-19T07:00:01Z',source:'AppWorkload.log',category:'Win32 apps',message:'Install returned 1603',line:5,codes:['1603'],stage:'result',correlation_ids:['activity-a','activity-b']},
      {uid:'e2',timestamp:'2026-10-19T07:00:02',source:'AppWorkload.log',category:'Win32 apps',message:'Local timestamp without zone',line:6,stage:'execution',correlation_ids:['activity-b']},
      {uid:'e3',source:'AppWorkload.log',category:'Win32 apps',message:'No time supplied',stage:'unknown'},
    ],
    findings: [{id:'f1',title:'Installer failed',category:'Win32 apps',severity:'error',confidence:'Medium',summary:'1603 recorded',root_cause:'Cause needs installer log verification',evidence:['e1','unknown-id'],checks:['Review installer output'],recommendations:['Prepare one approved remediation']}],
    warnings: ['Installer log absent'],
    ...overrides,
  }, 'Test CAB / readable logs');
}

test('imported case preserves report IDs, finding evidence and all correlation identifiers', () => {
  const report = imported();
  const [item] = casesFromReports([report]);
  assert.equal(item.id, report.id);
  assert.equal(item.report, report);
  assert.equal(item.imported, true);
  assert.equal(item.synthetic, false);
  assert.equal(item.category, 'Win32 apps');
  assert.equal(item.title, 'Test CAB / readable logs');
  assert.equal(item.findings[0].observation, report.findings[0].summary);
  assert.deepEqual(item.findings[0].evidenceIds, [item.events[0].id]);
  assert.deepEqual(item.events[0].correlationIds, report.events[0].correlationIds);
  assert.equal(item.traceId, report.events[0].correlationIds[0]);
  assert.equal(item.code, '1603');
  assert.deepEqual(item.expectedSources.map(({recordCount, ...source}) => source), report.sources);
  assert.equal(item.expectedSources[0].recordCount, 3);
  assert.equal(item.expectedSources[1].recordCount, 0);
  assert.equal(item.expectedSources.find(source => source.name === 'Missing.log').available, false);
});

test('local and absent timestamps remain distinct from UTC evidence', () => {
  const [item] = casesFromReports([imported()]);
  assert.equal(item.events[0].time, '2026-10-19T07:00:01.000Z');
  assert.equal(item.events[0].timeNote, '');
  assert.equal(item.events[1].time, '2026-10-19T07:00:02');
  assert.equal(item.events[1].timeNote, 'timezone unspecified');
  assert.equal(item.events[2].time, 'Time unspecified');
  assert.equal(item.events[2].timeNote, 'Time unspecified');
  assert.match(item.stageNote.correlate, /without a timezone/);
});

test('missing evidence remains warned and never turns into a fabricated linked record', () => {
  const report = imported();
  const [item] = casesFromReports([report]);
  assert.equal(item.findings[0].evidenceIds.length, 1);
  assert.ok(item.warnings.some(warning => warning.includes('could not be linked')));
  assert.deepEqual(item.warnings, report.warnings);
  assert.match(item.stageNote.findings, /hypotheses/);
  assert.match(item.stageNote.findings, /2 import limitations/);
});

test('mixed workstreams use Enterprise while individual record categories remain intact', () => {
  const report = imported({events:[
    {uid:'a',source:'CBS.log',message:'Servicing record',category:'Windows patching'},
    {uid:'b',source:'AppWorkload.log',message:'Install record',category:'Win32 apps'},
  ],findings:[]});
  const [item] = casesFromReports([report]);
  assert.equal(item.category, 'Enterprise');
  assert.deepEqual(item.events.map(event => event.category), ['Windows patching','Win32 apps']);
  assert.equal(item.traceId, '');
  assert.match(item.stageNote.correlate, /No shared correlation identifier/);
});

test('native guided export reparses as real data with linked evidence and original timestamp limitations', () => {
  const report = imported();
  const [item] = casesFromReports([report]);
  const selected = `${item.findings[0].id}:0`;
  const output = reportFromCase(item, [selected]);
  assert.equal(Object.hasOwn(output, 'scenario'), false);
  assert.equal(output.synthetic, false);
  assert.equal(output.report_metadata.synthetic, false);
  assert.equal(output.report_metadata.read_only, true);
  assert.equal(output.report_metadata.remediations_executed, false);
  assert.equal(output.started_at, report.generatedAt);
  assert.equal(output.events[1].timestamp, '2026-10-19T07:00:02');
  assert.equal(output.events[2].timestamp, null);
  assert.deepEqual(output.review_selections, [selected]);
  assert.deepEqual(output.findings[0].evidence, [output.events[0].uid]);
  const again = parseReport(output);
  assert.equal(again.synthetic, false);
  assert.equal(again.events.length, 3);
  assert.equal(again.events[1].timestamp, null);
  assert.equal(again.events[1].timestampIssue, 'timezone unspecified');
  assert.equal(again.events[2].timestamp, null);
  assert.deepEqual(again.findings[0].evidenceIds, [again.events[0].id]);
  assert.deepEqual(again.events[0].correlationIds, report.events[0].correlationIds);
  assert.deepEqual(output.warnings, report.warnings);
});

test('synthetic imported reports remain synthetic when viewed and exported', () => {
  const [item] = casesFromReports([imported({synthetic:true})]);
  assert.equal(item.imported, true);
  assert.equal(item.synthetic, true);
  assert.equal(parseReport(reportFromCase(item)).synthetic, true);
});

test('empty report cases have honest defaults and export without fabricated evidence or start time', () => {
  const report = parseReport({started_at:'',sources:[],events:[],findings:[]});
  const [item] = casesFromReports([report]);
  assert.equal(item.category, 'Enterprise');
  assert.equal(item.code, 'No recorded code');
  assert.equal(item.traceId, '');
  assert.deepEqual(item.events, []);
  assert.deepEqual(item.findings, []);
  assert.deepEqual(casesFromReports([]), []);
  const output = reportFromCase(item, new Set());
  assert.equal(output.started_at, '');
  assert.deepEqual(parseReport(output).events, []);
  assert.equal(parseReport(output).synthetic, false);
  assert.throws(() => reportFromCase({}), /imported diagnostic report/);
});

test('imported HTML preserves the report title, local timestamps, limitations and safe evidence links', () => {
  const report = imported();
  report.label = 'Endpoint <img src=x onerror=alert(1)>';
  report.events[0].message = '<script>untrusted</script>';
  const [item] = casesFromReports([report]);
  const html = reportHTML(reportFromCase(item));
  assert.ok(html.includes('Endpoint &lt;img'));
  assert.ok(html.includes('IMPORTED EVIDENCE · NO DEVICE CONNECTED'));
  assert.equal(html.includes('SYNTHETIC DEMO'), false);
  assert.equal(html.includes('<img'), false);
  assert.equal(html.includes('<script>'), false);
  assert.ok(html.includes('2026-10-19T07:00:02'));
  assert.ok(html.includes('Installer log absent'));
  assert.ok(html.includes(`href="#${item.events[0].id}"`));
});
