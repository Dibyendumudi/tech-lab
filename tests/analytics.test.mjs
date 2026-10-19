import test from 'node:test';
import assert from 'node:assert/strict';
import { CATEGORIES, sampleReports, parseReport, buildDashboard, sanitizeText } from '../docs/analytics.js';
import { scenarios } from '../docs/scenarios.js';
import { DemoWorkflow } from '../docs/app.js';

const native = (overrides = {}) => ({
  started_at: '2026-10-16T12:00:00Z', synthetic: false,
  sources: ['AppWorkload.log', 'AppActionProcessor.log'], warnings: [],
  events: [
    { uid: 'event-1', category: 'Win32 apps', source: 'AppWorkload.log', message: 'Detection failed with 0x87D1041C', timestamp: '2026-10-13T23:30:00-01:00', line: 8, codes: ['0x87D1041C'], stage: 'result', correlation_ids: ['trace-1'] },
    { uid: 'event-2', category: 'Windows patching', source: 'WindowsUpdateClient', message: 'Update scan request recorded', timestamp: '2026-10-15T10:00:00Z', line: 10, codes: [], stage: 'execution' },
    { uid: 'event-3', category: 'Enterprise', source: 'Unknown inventory', message: 'Untimed inventory record', timestamp: null, line: 0, codes: [], stage: 'unknown' }
  ],
  findings: [
    { id: 'finding-1', title: 'Detection rule review', category: 'Win32 apps', severity: 'error', confidence: 'Medium', summary: 'Detection did not succeed', root_cause: 'The configured path needs verification', evidence: ['event-1'], checks: ['Read configured detection'], recommendations: ['Prepare a reviewed proposal'] },
    { id: 'finding-2', title: 'Scan observation', category: 'Windows patching', severity: 'warning', confidence: 'Unknown', summary: 'Inspect update scan', root_cause: 'Cause not established', evidence: ['event-2'], checks: [], recommendations: [] },
    { id: 'finding-3', title: 'Inventory limitation', category: 'Enterprise', severity: 'info', confidence: 'Low', summary: 'Insufficient timed data', root_cause: '', evidence: ['event-3'], checks: [], recommendations: [] }
  ], ...overrides
});

test('the executive sample includes exactly the existing four scenarios with accurate totals', () => {
  const reports = sampleReports(scenarios);
  const data = buildDashboard(reports);
  assert.equal(reports.length, 4);
  assert.deepEqual(data.metrics, { reportsCount: 4, eventsCount: 29, findingsCount: 5, priorityCount: 4, categoriesCount: 4, availableSourcesCount: 12 });
  assert.deepEqual(data.severityCounts, { error: 4, warning: 1, info: 0 });
  assert.deepEqual(data.stageCounts.map(item => item.count), [4, 7, 10, 8, 0]);
  assert.equal(data.domainCounts.find(item => item.category === 'Conditional Access').total, 2);
  assert.equal(data.domainCounts.find(item => item.category === 'Enterprise').total, 0);
  assert.equal(data.coverage.syntheticReports, 4);
  assert.equal(data.coverage.importedReports, 0);
  assert.equal(data.coverage.missing, 3);
  assert.equal(data.timeline.reduce((sum, item) => sum + item.events, 0), 29);
  assert.equal(data.timeline.reduce((sum, item) => sum + item.results, 0), 8);
  assert.ok(data.timeline.every(item => new Date(item.key).toISOString() === item.key));
  assert.equal('deviceCount' in data.metrics, false);
  assert.equal('healthScore' in data.metrics, false);
});

test('domain and severity filters use records and only linked evidence for severity', () => {
  const reports = sampleReports(scenarios);
  const ca = buildDashboard(reports, { category: 'Conditional Access' });
  assert.equal(ca.metrics.eventsCount, 6);
  assert.equal(ca.metrics.findingsCount, 2);
  assert.equal(ca.metrics.reportsCount, 1);
  const warnings = buildDashboard(reports, { severity: 'warning' });
  assert.equal(warnings.metrics.findingsCount, 1);
  assert.equal(warnings.metrics.eventsCount, 4);
  assert.ok(warnings.events.every(event => warnings.findings[0].evidenceIds.includes(event.id)));
  assert.equal(warnings.metrics.priorityCount, 0);
  const info = buildDashboard(reports, { severity: 'info' });
  assert.equal(info.metrics.eventsCount, 0);
  assert.equal(info.metrics.findingsCount, 0);
});

test('native imports preserve severities, uncertain confidence and unknown timestamps', () => {
  const report = parseReport(native(), 'Pilot endpoint report');
  assert.equal(report.synthetic, false);
  assert.equal(report.label, 'Pilot endpoint report');
  assert.equal(report.findings[1].confidence, 'Unknown');
  assert.equal(report.events[0].timestamp, '2026-10-14T00:30:00.000Z');
  assert.equal(report.findings[0].rootCause, 'The configured path needs verification');
  assert.equal(report.events[2].line, 0);
  const data = buildDashboard([report]);
  assert.deepEqual(data.severityCounts, { error: 1, warning: 1, info: 1 });
  assert.equal(data.coverage.missingTimestampEvents, 1);
  assert.equal(data.coverage.missingTimestampFindings, 1);
  assert.equal(data.coverage.importedReports, 1);
  assert.deepEqual(data.dateRange, { from: '2026-10-14', to: '2026-10-15' });
});

test('UTC dates are inclusive and use evidence dates rather than generation time', () => {
  const report = parseReport(native());
  const data = buildDashboard([report], { from: '2026-10-14', to: '2026-10-14' });
  assert.equal(data.events.length, 1);
  assert.equal(data.findings.length, 1);
  assert.equal(data.events[0].timestamp, '2026-10-14T00:30:00.000Z');
  assert.equal(data.findings[0].severity, 'error');
  assert.equal(buildDashboard([report], { from: '2026-10-16' }).findings.length, 0);
  assert.equal(buildDashboard([report], { to: '2026-10-13' }).events.length, 0);
  assert.ok(data.notes.some(note => note.includes('without timed evidence are excluded')));
  const invalid = native();
  invalid.events[0].timestamp = '2026-02-30T08:00:00Z';
  invalid.events[1].timestamp = '2026-10-15T10:00:00';
  assert.ok(parseReport(invalid).events.every(event => event.timestamp === null));
});

test('search matches findings and linked events without conflating separate reports', () => {
  const reports = sampleReports(scenarios);
  const code = buildDashboard(reports, { query: '0x80072ee7' });
  assert.equal(code.findings.length, 1);
  assert.ok(code.events.length >= 2);
  assert.ok(code.events.every(event => event.category === 'Windows patching'));
  const cause = buildDashboard([parseReport(native())], { query: 'configured path needs verification' });
  assert.equal(cause.findings.length, 1);
  assert.equal(cause.events.length, 1);
  assert.equal(buildDashboard(reports, { query: 'not-existing-text-123' }).events.length, 0);
});

test('browser workflow exports import with all evidence linked and sources retained', () => {
  const workflow = new DemoWorkflow();
  while (workflow.advance()) {}
  const report = parseReport(workflow.report(), 'Win32 workflow export');
  assert.equal(report.synthetic, true);
  assert.equal(report.events.length, 8);
  assert.equal(report.findings.length, 1);
  assert.equal(report.findings[0].evidenceIds.length, 5);
  assert.ok(report.events.every(event => event.category === 'Win32 apps'));
  assert.ok(report.findings[0].evidenceIds.every(id => report.events.some(event => event.id === id)));
  assert.equal(report.warnings.length, 0);
});

test('IDs are deterministic, report-scoped and never cross-link colliding native IDs', () => {
  const first = parseReport(native());
  const secondRaw = native(); secondRaw.events[0].message = 'Different endpoint evidence';
  const second = parseReport(secondRaw);
  assert.notEqual(first.id, second.id);
  assert.notEqual(first.events[0].id, second.events[0].id);
  const data = buildDashboard([first, second]);
  assert.equal(data.metrics.eventsCount, 6);
  assert.ok(data.priorityFindings.every(finding => finding.events.every(event => event.reportId === finding.reportId)));
  const exportedLater = native({ started_at: '2026-10-20T00:00:00Z' });
  assert.equal(parseReport(exportedLater).id, first.id);
  assert.equal(buildDashboard([first, parseReport(exportedLater)]).metrics.eventsCount, 3);
});

test('orphan evidence is counted, not matched by line, time or another report ID', () => {
  const raw = native(); raw.findings[0].evidence = ['event-1', 'missing-event'];
  const report = parseReport(raw);
  assert.equal(report.findings[0].evidenceIds.length, 1);
  assert.ok(report.warnings.some(warning => warning.includes('1 evidence reference')));
});

test('sensitive identifiers and token values are pseudonymized consistently; errors remain readable', () => {
  const raw = native();
  const email = 'person@example.com', guid = '12345678-1234-1234-1234-123456789abc';
  raw.events[0].message = `${email} ${guid} 192.168.1.20 2001:db8:85a3::8a2e:370:7334 C:\\Users\\Alice\\data token access_token=supersecret 0x87D1041C AADSTS53000 09:02:00 UTC`;
  raw.events[0].correlation_ids = [guid];
  raw.findings[0].summary = `${email} ${guid}`;
  const report = parseReport(raw);
  const output = JSON.stringify(report);
  for (const value of [email, guid, '192.168.1.20', '2001:db8:85a3::8a2e:370:7334', 'Alice', 'supersecret']) assert.equal(output.includes(value), false, value);
  assert.ok(output.includes('0x87D1041C'));
  assert.ok(output.includes('AADSTS53000'));
  assert.ok(output.includes('09:02:00 UTC'));
  assert.ok(report.findings[0].summary.includes(report.events[0].correlationIds[0]));
  assert.equal(sanitizeText('Bearer abc.def.ghi'), '[redacted bearer token]');
});

test('untrusted HTML remains inert text and prototype or arbitrary extra fields are not copied', () => {
  const raw = JSON.parse(JSON.stringify(native()));
  raw.events[0].message = '<img src=x onerror=alert(1)>';
  raw.events[0].__proto__ = { dangerous: 'inherited' };
  raw.findings[0].extraHTML = '<script>alert(1)</script>';
  const report = parseReport(raw, '<b>Untrusted label</b>');
  assert.equal(report.events[0].message, '<img src=x onerror=alert(1)>');
  assert.equal(report.label, '<b>Untrusted label</b>');
  assert.equal('dangerous' in report.events[0], false);
  assert.equal('extraHTML' in report.findings[0], false);
  assert.equal(Object.prototype.dangerous, undefined);
});

test('unknown schemas, malformed records, duplicates and excessive reports fail clearly', () => {
  for (const raw of [null, [], {}, { events: [], findings: [] }, { events: [], findings: [], random: 'data' }, native({ events: [null] })]) assert.throws(() => parseReport(raw), /report|event|JSON/i);
  const duplicate = native(); duplicate.events.push({ ...duplicate.events[0] });
  assert.throws(() => parseReport(duplicate), /Duplicate event IDs/);
  assert.throws(() => parseReport(native({ events: Array(50001).fill({}) })), /at most 50,000 events/);
  assert.throws(() => parseReport(native({ findings: Array(1001).fill({}) })), /1,000 findings/);
  const empty = parseReport(native({ events: [], findings: [], sources: [] }));
  assert.equal(buildDashboard([empty]).metrics.reportsCount, 1);
  assert.equal(buildDashboard([]).coverage.note, 'No diagnostic reports loaded.');
});

test('coverage identifies missing sources and mixed synthetic and operational datasets', () => {
  const reports = sampleReports(scenarios);
  const data = buildDashboard([...reports, parseReport(native())]);
  assert.equal(data.coverage.syntheticReports, 4);
  assert.equal(data.coverage.importedReports, 1);
  assert.ok(data.notes.some(note => note.includes('both synthetic samples and imported reports')));
  assert.equal(data.sourceCoverage.find(source => source.name === 'Autopilot diagnostic CAB').available, false);
  assert.ok(data.domainCounts.every(domain => CATEGORIES.includes(domain.category)));
  assert.equal(data.metrics.findingsCount, 8);
});

test('the sample timeline includes a zero 10:00 UTC bucket without inventing events', () => {
  const data = buildDashboard(sampleReports(scenarios));
  const gap = data.timeline.find(bucket => bucket.key === '2026-10-13T10:00:00.000Z');
  assert.deepEqual(gap, { key: '2026-10-13T10:00:00.000Z', label: '10-13 10:00', events: 0, results: 0 });
  assert.equal(data.timeline.length, 5);
  assert.equal(data.timeline.reduce((sum, bucket) => sum + bucket.events, 0), 29);
});

test('timeline gap filling is bounded for hour, day and month ranges', () => {
  const raw = native();
  raw.events[0].timestamp = '2026-10-01T00:00:00Z';
  raw.events[1].timestamp = '2026-10-03T00:00:00Z';
  const hourly = buildDashboard([parseReport(raw)]);
  assert.equal(hourly.timelineGranularity, 'hour');
  assert.equal(hourly.timeline.length, 49);
  raw.events[1].timestamp = '2026-12-30T00:00:00Z';
  const daily = buildDashboard([parseReport(raw)]);
  assert.equal(daily.timelineGranularity, 'day');
  assert.equal(daily.timeline.length, 91);
  raw.events[1].timestamp = '2027-02-01T00:00:00Z';
  const monthly = buildDashboard([parseReport(raw)]);
  assert.equal(monthly.timelineGranularity, 'month');
  assert.equal(monthly.timeline.length, 5);
  raw.events[0].timestamp = '2000-01-01T00:00:00Z';
  raw.events[1].timestamp = '9999-12-31T00:00:00Z';
  const extreme = buildDashboard([parseReport(raw)]);
  assert.equal(extreme.timelineGranularity, 'month');
  assert.equal(extreme.timeline.length, 2);
});

test('native listed-only files are unknown inventory and untimed source values remain inspectable', () => {
  const raw = native();
  raw.events[0].timestamp = '2026-10-14T00:30:00';
  const report = parseReport(raw);
  assert.equal(report.hasExpectedInventory, false);
  assert.equal(report.events[0].timestamp, null);
  assert.equal(report.events[0].rawTimestamp, '2026-10-14T00:30:00');
  assert.equal(report.events[0].timestampIssue, 'timezone unspecified');
  const data = buildDashboard([report]);
  assert.equal(data.coverage.expectedInventoryKnown, false);
  assert.equal(data.sourceCoverage.find(source => source.name === 'AppActionProcessor.log').available, null);
  assert.equal(data.coverage.listedOnly, 1);
  assert.equal(data.coverage.missing, 0);
  assert.ok(data.notes.some(note => note.includes('coverage percentage cannot be established')));
  assert.ok(data.notes.some(note => note.includes('unspecified timestamps are not converted')));
  assert.ok(sampleReports(scenarios).every(report => report.hasExpectedInventory));
  assert.equal(buildDashboard(sampleReports(scenarios)).coverage.expectedInventoryKnown, true);
});
