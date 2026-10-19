import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeRawEvents } from '../docs/raw-analysis.js';
import { parseReport } from '../docs/analytics.js';

const event = (message, source = 'IntuneManagementExtension.log', extra = {}) => ({ uid: 'record-' + message, source, line: 1, message, timestamp: '2026-10-19T09:00:00Z', ...extra });
test('produces a canonical native-compatible report with sanitized evidence', () => {
  const report = analyzeRawEvents([event('AppId=abc-123 exit code 1603 password=hunter2 user@example.com')]);
  const parsed = parseReport(report);
  assert.equal(parsed.synthetic, false);
  assert.equal(parsed.findings.length, 1);
  assert.equal(parsed.findings[0].evidenceIds[0], parsed.events[0].id);
  assert.equal(report.events[0].message.includes('hunter2'), false);
  assert.equal(report.events[0].message.includes('user@example.com'), false);
  assert.equal(report.events[0].correlation_ids[0].includes('abc-123'), false);
  assert.match(report.findings[0].root_cause, /does not establish a unique root cause/);
});
test('reboot success codes are informational and return-code configuration is not execution', () => {
  const report = analyzeRawEvents([event('Installer exit code: 3010'), event('Installer returned code 1641'), event('Configured return codes: 3010=soft reboot, 1641=hard reboot')]);
  assert.equal(report.findings.length, 2);
  assert.deepEqual(report.findings.map(finding => finding.severity), ['info', 'info']);
  assert.match(report.findings[0].root_cause, /not an installation failure/);
});
test('unrelated numeric IDs, row counts and configured mappings are not installer results', () => {
  const report = analyzeRawEvents([
    event('User event ID 1603; 3010 rows processed'), event('Configured return codes: 1603=failed, 3010=soft reboot, 1641=hard reboot')
  ]);
  assert.equal(report.findings.some(finding => /Installer returned|Installation succeeded/.test(finding.title)), false);
});
test('success and no-error records do not create generic failures', () => {
  for (const message of ['No errors. Installation completed successfully.', 'Failed=0; Error code=0', 'MFA completed successfully.']) {
    const report = analyzeRawEvents([event(message)]);
    assert.equal(report.findings.length, 0, message);
  }
});
test('CA codes remain separate observations and use complete token boundaries', () => {
  const report = analyzeRawEvents([
    event('AADSTS53000 DeviceNotCompliant', 'signins.json'), event('AADSTS53001 DeviceNotDomainJoined', 'signins.json'),
    event('AADSTS53003 BlockedByConditionalAccess', 'signins.json'), event('AADSTS530030 similar unknown code', 'signins.json')
  ]);
  assert.equal(report.findings.length, 3);
  assert.equal(report.findings.every(finding => finding.category === 'Conditional Access'), true);
  assert.match(report.findings[1].root_cause, /does not prove the device is entirely unregistered/);
  assert.match(report.findings[2].root_cause, /does not identify which policy/);
});
test('MFA required is not represented as a confirmed failed challenge', () => {
  const report = analyzeRawEvents([event('AADSTS50076 MFA required', 'signins.json')]);
  assert.equal(report.findings.length, 1);
  assert.match(report.findings[0].root_cause, /not proof that a user failed a challenge/);
});
test('unknown failure codes remain conservative and do not imply detection failure', () => {
  const report = analyzeRawEvents([event('Install failed with error code 0xdeadbeef')]);
  assert.equal(report.findings.length, 1);
  assert.equal(report.findings[0].confidence, 'low');
  assert.equal(report.findings[0].title.includes('detection'), false);
  assert.match(report.findings[0].root_cause, /unconfirmed/);
});
test('specific detection error is separate from generic MSI1603 and context mismatch is explicit', () => {
  const report = analyzeRawEvents([
    event('Install completed but detection returned 0x87D1041C'), event('MSI error 1603'),
    event('Expected SYSTEM context but running User context'), event('SYSTEM context; user signed in')
  ]);
  assert.equal(report.findings.length, 3);
  assert.equal(report.findings.filter(finding => /context mismatch/.test(finding.title)).length, 1);
});
test('source/provider context distinguishes update, Autopilot and unrelated network failures', () => {
  const report = analyzeRawEvents([
    event('Scan failed with 0x80072EE2', 'WindowsUpdateClient.xml'),
    event('Connection failed 0x80072EE2', 'Autopilot.log'),
    event('Connection failed 0x80072EE2', 'custom.log'),
    event('Error 0x800F081F', 'CBS.log'), event('Scan failed 0x8024402C', 'WindowsUpdate.log')
  ]);
  assert.deepEqual(report.events.map(item => item.category), ['Windows patching', 'Autopilot & ESP', 'Enterprise', 'Windows patching', 'Windows patching']);
  assert.equal(report.findings.length, 5);
  assert.equal(report.findings.filter(finding => finding.confidence === 'low').length, 1);
});
test('no time-only linkage and repeated generic events remain separate', () => {
  const report = analyzeRawEvents([event('Process failed', 'one.log'), event('Process failed', 'two.log')]);
  assert.equal(report.findings.length, 2);
  assert.equal(report.findings.every(finding => finding.evidence.length === 1), true);
  assert.match(report.warnings.join(' '), /not linked merely because their timestamps are close/);
});
test('stable identifiers, grouping by source/context, and explicit correlation remain consistent', () => {
  const inputs = [event('AppId=test-app exit code 1603', 'one.log'), event('AppId=test-app exit code 1603', 'two.log')];
  inputs.forEach(input => input.category = 'Win32 apps');
  const first = analyzeRawEvents(inputs), second = analyzeRawEvents(inputs);
  assert.deepEqual(first.events.map(item => item.uid), second.events.map(item => item.uid));
  assert.deepEqual(first.findings.map(item => item.id), second.findings.map(item => item.id));
  assert.deepEqual(first.events[0].correlation_ids, first.events[1].correlation_ids);
  assert.equal(first.findings.length, 2);
});
test('finding limits and event message caps are enforced', () => {
  const report = analyzeRawEvents(Array.from({ length: 1005 }, (_, index) => event('failure ' + index + ' ' + 'a'.repeat(21000), 'test.log', { uid: 'e-' + index })));
  assert.equal(report.findings.length, 1000);
  assert.equal(report.events.every(item => item.message.length <= 20000), true);
  assert.equal(report.events.every(item => item.message.endsWith(' [message truncated]')), true);
  assert.match(report.warnings.join(' '), /finding limit was reached/);
  assert.match(report.warnings.join(' '), /event message\(s\) were truncated/);
});
test('late error codes within the 20k parser limit remain visible and analyzed', () => {
  const report = analyzeRawEvents([event('A'.repeat(17000) + ' failed 0x80072ee7', 'WindowsUpdateClient.json')]);
  assert.equal(report.findings.length, 1);
  assert.equal(report.findings[0].confidence, 'high');
  assert.equal(report.events[0].codes.includes('0x80072ee7'), true);
  assert.match(report.events[0].message, /failed 0x80072ee7$/);
});
test('codes outside retained evidence are not inferred from parser metadata', () => {
  const report = analyzeRawEvents([event('A'.repeat(21000) + ' failed 0x80072ee7', 'WindowsUpdateClient.json', { codes: ['0x80072ee7'] })]);
  assert.equal(report.findings.length, 0);
  assert.equal(report.events[0].codes.length, 0);
  assert.equal(report.events[0].message.endsWith(' [message truncated]'), true);
  assert.match(report.warnings.join(' '), /event message\(s\) were truncated/);
});
test('parser truncation suffix and warning survive analysis without further truncation', () => {
  const report = analyzeRawEvents([event('A'.repeat(19980) + ' [message truncated]', 'WindowsUpdateClient.json')]);
  assert.equal(report.events[0].message.endsWith(' [message truncated]'), true);
  assert.match(report.warnings.join(' '), /event message\(s\) were truncated/);
});
