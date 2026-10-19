import test from 'node:test';
import assert from 'node:assert/strict';
import {parseRawLog} from '../docs/raw-parsers.js';

const xml = `<?xml version="1.0"?><ev:Events xmlns:ev="http://schemas.microsoft.com/win/2004/08/events/event">
<ev:Event><ev:System><ev:Provider Name="Microsoft-Windows-WindowsUpdateClient"/><ev:EventID Qualifiers="0">25</ev:EventID><ev:Level>2</ev:Level><ev:TimeCreated SystemTime="2026-10-19T10:01:02.1234567Z"/><ev:Correlation ActivityID="11111111-2222-3333-4444-555555555555"/></ev:System><ev:EventData><ev:Data Name="ErrorCode">0x80072EE7</ev:Data><ev:Data Name="URL">https://test.invalid?a=1&amp;b=2</ev:Data></ev:EventData><ev:RenderingInfo><ev:Message>Scan failed &lt;DNS&gt; &#x26; proxy</ev:Message></ev:RenderingInfo></ev:Event>
<ev:Event><ev:System><ev:EventID>21</ev:EventID><ev:TimeCreated SystemTime="2026-10-19T11:00:00+05:30"/></ev:System><ev:EventData><ev:Data Name="Result">Reboot required</ev:Data></ev:EventData></ev:Event></ev:Events>`;

test('CMTrace multiline records preserve file lines, installer context, codes and local time', () => {
  const text = `<![LOG[Installing in SYSTEM context\nexit code: 1603]LOG]!><time="08:42:00.1234567+60" date="10-13-2026" component="AppActionProcessor" type="3">\r\n<![LOG[Detection failed: 0x87D1041C]LOG]!><time="08:43:00.000-330" date="10-13-2026" type="3">`;
  const {events, warnings} = parseRawLog(text, 'C:\\Logs\\AppActionProcessor.log');
  assert.equal(events.length, 2);
  assert.equal(events[0].line, 1);
  assert.equal(events[1].line, 3);
  assert.equal(events[0].timestamp, '2026-10-13T08:42:00.1234567');
  assert.equal(events[0].context, 'SYSTEM');
  assert.equal(events[0].category, 'Win32 apps');
  assert.equal(events[0].level, 'Error');
  assert.ok(events[0].message.includes('\nexit code: 1603'));
  assert.deepEqual(events[0].codes, ['1603']);
  assert.deepEqual(events[1].codes, ['0x87d1041c']);
  assert.deepEqual(warnings, []);
});

test('CBS and plain text keep naive timestamps naive and explicit offsets intact', () => {
  const {events} = parseRawLog('\uFEFF2026-10-19 09:32:10, Error CBS HRESULT = -2146498529\r\n\r\n2026-10-19T09:33:00+0530 Failed 0x800f081f\nContinuation text', 'CBS.log');
  assert.equal(events.length, 3);
  assert.equal(events[1].line, 3);
  assert.equal(events[0].timestamp, '2026-10-19T09:32:10');
  assert.equal(events[1].timestamp, '2026-10-19T09:33:00+05:30');
  assert.equal(events[2].timestamp, null);
  assert.deepEqual(events[0].codes, ['0x800f081f']);
  assert.equal(events[0].category, 'Windows patching');
});

test('Windows event JSON supports PowerShell wrappers and .NET absolute timestamps', () => {
  const {events} = parseRawLog(JSON.stringify({Events: [{Id: 25, TimeCreated: {DateTime: '2026-10-19T14:00:00Z'}, ProviderName: 'Microsoft-Windows-WindowsUpdateClient', Message: 'Scan failed: 0x80072ee7'}, {EventId: 404, TimeCreated: '/Date(0+0530)/', Message: 'Enrollment failed'}]}), 'events.json');
  assert.equal(events[0].event_id, '25');
  assert.equal(events[0].provider, 'Microsoft-Windows-WindowsUpdateClient');
  assert.equal(events[0].timestamp, '2026-10-19T14:00:00Z');
  assert.equal(events[1].timestamp, '1970-01-01T00:00:00.000Z');
});

test('nested Windows Event JSON preserves System and EventData fields', () => {
  const {events} = parseRawLog(JSON.stringify({Event: {System: {Provider: {'@Name': 'WindowsUpdateClient'}, EventID: {'#text': 25}, TimeCreated: {'@SystemTime': '2026-10-19T10:00:00Z'}, Correlation: {'@ActivityID': 'activity-123'}}, EventData: {Data: [{'@Name': 'Error', '#text': '0x80072ee7'}]}}}), 'event.json');
  assert.equal(events[0].provider, 'WindowsUpdateClient');
  assert.equal(events[0].event_id, '25');
  assert.equal(events[0].timestamp, '2026-10-19T10:00:00Z');
  assert.ok(events[0].correlation_ids.includes('activity-123'));
  assert.deepEqual(events[0].codes, ['0x80072ee7']);
});

test('Graph Entra records retain failure policy evidence and normalize AADSTS codes', () => {
  const records = [53000, 53001, 53003].map(errorCode => ({createdDateTime: '2026-10-19T10:00:00Z', correlationId: 'request-' + errorCode, status: {errorCode, failureReason: 'Blocked'}, conditionalAccessStatus: 'failure', deviceDetail: {isCompliant: false}, appliedConditionalAccessPolicies: [{displayName: 'Require compliance', result: 'failure'}]}));
  const {events} = parseRawLog(JSON.stringify({value: records}), 'SignIns.json');
  assert.equal(events.length, 3);
  assert.deepEqual(events.map(event => event.codes[0]), ['AADSTS53000', 'AADSTS53001', 'AADSTS53003']);
  assert.ok(events.every(event => event.category === 'Conditional Access'));
  assert.ok(events[0].message.includes('Require compliance'));
  assert.ok(events[0].message.includes('"isCompliant":false'));
  assert.ok(events[0].correlation_ids.includes('request-53000'));
});

test('JSONL retains valid lines, source line numbers and concise partial-import warnings', () => {
  const text = '{"Message":"First event"}\n{broken}\n\n42\n{"Message":"Final event","Id":9}';
  const {events, warnings} = parseRawLog(text, 'events.ndjson');
  assert.equal(events.length, 2);
  assert.deepEqual(events.map(event => event.line), [1, 5]);
  assert.equal(warnings.length, 2);
  assert.match(warnings[0], /line 2/);
  assert.match(warnings[1], /line 4/);
  assert.throws(() => parseRawLog('bad\n[]', 'events.jsonl'), /No usable event records/);
});

test('CSV reads BOM, quoted commas, doubled quotes, multiline messages and physical lines', () => {
  const text = '\uFEFFTimeCreated,Id,Message\r\n2026-10-19T10:00:00Z,25,"Failed, proxy said ""no""\r\nTry DNS: 0x80072EE7"\r\n2026-10-19 10:01:00,26,"=HYPERLINK(""https://example.invalid"")"\r\n';
  const {events} = parseRawLog(text, 'events.csv');
  assert.equal(events.length, 2);
  assert.equal(events[0].message.split('\n')[0], 'Failed, proxy said "no"\r');
  assert.equal(events[0].line, 2);
  assert.equal(events[1].line, 4);
  assert.equal(events[0].event_id, '25');
  assert.equal(events[1].timestamp, '2026-10-19T10:01:00');
  assert.ok(events[1].message.startsWith('=HYPERLINK(')); // Treated only as text.
});

test('Entra CSV aliases expose sign-in failure code, status and correlation', () => {
  const {events} = parseRawLog('Date (UTC),Sign-in error code,Correlation ID,User principal name,Conditional Access\n2026-10-19T10:00:00Z,53003,request-abc,user@example.test,Failure', 'Signin.csv');
  assert.deepEqual(events[0].codes, ['AADSTS53003']);
  assert.equal(events[0].timestamp, '2026-10-19T10:00:00Z');
  assert.ok(events[0].correlation_ids.includes('request-abc'));
  assert.equal(events[0].category, 'Conditional Access');
});

test('explicit Date (UTC) column supplies UTC only when its cell has no zone', () => {
  const {events} = parseRawLog('Date (UTC),Sign-in error code\n2026-10-19 09:00:00,53000\n10/19/2026 9:00:00 AM,53001\n2026-10-19T09:00:00+05:30,53003', 'SignIns.csv');
  assert.deepEqual(events.map(event => event.timestamp), ['2026-10-19T09:00:00Z', '2026-10-19T09:00:00Z', '2026-10-19T09:00:00+05:30']);
  const local = parseRawLog('Date,Message\n2026-10-19 09:00:00,local clock', 'events.csv');
  assert.equal(local.events[0].timestamp, '2026-10-19T09:00:00');
  const selected = parseRawLog(JSON.stringify({TimeCreated: '2026-10-19 09:00:00', 'Date (UTC)': '2026-10-19 08:00:00', Message: 'Two time fields'}), 'events.json');
  assert.equal(selected.events[0].timestamp, '2026-10-19T09:00:00');
});

test('malformed CSV rejects mismatched rows, quote errors and unnamed headers', () => {
  for (const text of ['Id,Message\n1,test,extra', 'Id,Message\n1,"unterminated', 'Id,Message\n1,un"quoted', 'Id,Message\n1,"done"oops', 'Id,Id\n1,2', ',Message\n1,test', 'Name,Color\nfirst,blue', 'Id,Name\nabc,ordinary']) {
    assert.throws(() => parseRawLog(text, 'events.csv'), /CSV/);
  }
});

test('Windows Event XML handles namespaces, entities, multiple events and offsets', () => {
  const {events} = parseRawLog(xml, 'WindowsUpdateClient.xml');
  assert.equal(events.length, 2);
  assert.equal(events[0].event_id, '25');
  assert.equal(events[0].provider, 'Microsoft-Windows-WindowsUpdateClient');
  assert.equal(events[0].timestamp, '2026-10-19T10:01:02.1234567Z');
  assert.equal(events[1].timestamp, '2026-10-19T11:00:00+05:30');
  assert.deepEqual(events[0].codes, ['0x80072ee7']);
  assert.ok(events[0].message.includes('Scan failed <DNS> & proxy'));
  assert.ok(events[0].message.includes('https://test.invalid?a=1&b=2'));
  assert.ok(events[0].correlation_ids.includes('11111111-2222-3333-4444-555555555555'));
  assert.equal(events[0].line, 2);
  assert.equal(events[1].line, 3);
});

test('XML CDATA remains inert diagnostic text', () => {
  const {events} = parseRawLog('<Event><RenderingInfo><Message><![CDATA[<script>alert("test")</script> & still text]]></Message></RenderingInfo></Event>', 'event.xml');
  assert.ok(events[0].message.startsWith('<script>alert("test")</script> & still text'));
});

test('XML rejects DTD/entity attacks and malformed markup rather than returning partial data', () => {
  const bad = [
    '<!DOCTYPE Events [<!ENTITY x SYSTEM "file:///etc/passwd">]><Events><Event><Message>&x;</Message></Event></Events>',
    '<!DOCTYPE Event SYSTEM "https://example.invalid/dtd"><Event/>',
    '<Events><Event><Message>safe</Message></Event><Event></Events>',
    '<Event><Message>&unknown;</Message></Event>',
    '<Event><Message>&amp</Message></Event>',
    '<Event><Message>&#0;</Message></Event>',
    '<Event><Message>&#x110000;</Message></Event>',
    '<Event><Provider Name="a" Name="b"/></Event>',
    '<Event bad=unquoted/>',
    '<Event/><Event/>',
    '<Events/>',
    '<Event><Message>bad]]></Message></Event>',
    '<Event><Message>safe</Message></Event>trailing',
    '<Event><Event/></Event>',
    '<unknown:Event><Message>bad</Message></unknown:Event>',
    '<Event><Message/> / >',
    '<Event><Message / ></Event>',
    '<Event xmlns:a="same" xmlns:b="same" a:field="a" b:field="b"/>',
    '<?xml invalid?><Event><Message>bad</Message></Event>',
    '<Event/>'
  ];
  for (const text of bad) assert.throws(() => parseRawLog(text, 'event.xml'), /XML|Event/);
});

test('input rejection is readable for unsupported, binary, empty and malformed records', () => {
  for (const name of ['archive.cab', 'events.evtx', 'trace.etl', 'package.zip', 'no-extension']) assert.throws(() => parseRawLog('test', name), /Unsupported file type/);
  assert.throws(() => parseRawLog('MSCF archive bytes', 'fake.txt'), /binary/);
  assert.throws(() => parseRawLog('\0\u0001data', 'fake.log'), /binary/);
  assert.throws(() => parseRawLog(' \uFEFF\n', 'empty.txt'), /empty/);
  assert.throws(() => parseRawLog({Message: 'event'}, 'event.json'), /decoded text/);
  assert.throws(() => parseRawLog('{"Message":', 'event.json'), /Malformed JSON/);
  for (const text of ['null', '[]', '["plain"]', '{}', '{"arbitrary":"metadata"}', '{"id":"inventory-only","name":"ordinaryobject"}']) assert.throws(() => parseRawLog(text, 'event.json'), /JSON|records/);
});

test('bounded import caps event count and message sizes and warns about omitted records', () => {
  const {events, warnings} = parseRawLog(['x'.repeat(21_000), 'second', 'third'].join('\n'), 'large.log', {maxEvents: 2});
  assert.equal(events.length, 2);
  assert.equal(events[0].message.length, 20_000);
  assert.match(events[0].message, /truncated\]$/);
  assert.match(warnings[0], /first 2 of 3 records/);
  assert.throws(() => parseRawLog('line', 'log.txt', {maxEvents: 0}), /positive integer/);
  assert.throws(() => parseRawLog('a'.repeat(20 * 1024 * 1024 + 1), 'large.log'), /20 MiB/);
  const large = parseRawLog('line\n'.repeat(50_001), 'large.log', {maxEvents: 100_000});
  assert.equal(large.events.length, 50_000);
  assert.match(large.warnings[0], /first 50,000 of 50,001/);
});

test('stable per-file unique event IDs and no input mutation', () => {
  const text = '{"Message":"same"}\n{"Message":"same"}';
  const first = parseRawLog(text, 'a.jsonl');
  assert.notEqual(first.events[0].uid, first.events[1].uid);
  assert.deepEqual(parseRawLog(text, 'a.jsonl'), first);
  assert.notEqual(parseRawLog(text, 'b.jsonl').events[0].uid, first.events[0].uid);
  assert.equal(text, '{"Message":"same"}\n{"Message":"same"}');
});

test('invalid calendar timestamps are not treated as real times', () => {
  const {events} = parseRawLog('[{"Message":"event","timestamp":"2026-02-30T10:00:00Z"},{"Message":"event","timestamp":"2026-10-19T24:00:00Z"}]', 'events.json');
  assert.ok(events.every(event => event.timestamp === null));
});

test('standalone Windows Event XML and CSV exports work without timezone guessing', () => {
  const event = parseRawLog('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="MDM"/><EventID>404</EventID><TimeCreated SystemTime="2026-10-19T09:00:00"/></System><EventData><Data Name="Result">Enrollment failed</Data></EventData></Event>', 'DeviceManagement.xml').events[0];
  assert.equal(event.event_id, '404');
  assert.equal(event.timestamp, '2026-10-19T09:00:00');
  assert.ok(event.message.includes('Enrollment failed'));
  const csv = parseRawLog('Message\n"One event"', 'single-column.csv');
  assert.equal(csv.events[0].message, 'One event');
});
