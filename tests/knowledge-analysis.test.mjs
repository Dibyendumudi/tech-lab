import test from 'node:test';
import assert from 'node:assert/strict';
import {parseRawLog} from '../docs/raw-parsers.js';
import {analyzeRawEvents,getKnowledgeBase} from '../docs/raw-analysis.js';
import {parseReport,buildDashboard} from '../docs/analytics.js';
import {buildExecutiveSummary,executiveSummaryHTML,knowledgeBaseHTML,knowledgeCatalog} from '../docs/executive-summary.js';
import {runValidationCases} from '../docs/validation-cases.js';
import {executiveBrief} from '../docs/executive.js';
const ev=(message,source='AppWorkload.log',extra={})=>({uid:message,source,message,...extra});
const dataFor=events=>buildDashboard([parseReport(analyzeRawEvents(events))]);

test('bundled checks exercise the parser, analyzer and canonical report for all advertised examples',()=>{
  const results=runValidationCases();
  assert.equal(results.length,55);
  assert.deepEqual(results.filter(result=>!result.passed),[]);
  assert.ok(results.some(result=>result.name.includes('Zero error code')));
  assert.ok(results.some(result=>result.category==='Autopilot & ESP'));
});
test('structured HRESULTs and MSI codes produce specific explanations instead of generic fallback',()=>{
  const parsed=parseRawLog(JSON.stringify([{Message:'Operation result',HRESULT:-2147024891},{Message:'Installer result',ExitCode:1603}]),'AppWorkload.json');
  const report=analyzeRawEvents(parsed.events);
  assert.equal(report.findings.length,2);
  assert.ok(report.findings.some(finding=>/denied access/.test(finding.title)));
  assert.ok(report.findings.some(finding=>/generic failure 1603/.test(finding.title)));
  assert.ok(report.findings.every(finding=>finding.diagnosis.type==='rule'));
});
test('a generic status object does not turn an application result into an Entra sign-in',()=>{
  const {events}=parseRawLog(JSON.stringify({Message:'Installer result',status:{errorCode:1603}}),'AppWorkload.json');
  assert.equal(events[0].category,'Win32 apps');
  assert.equal(events[0].message.includes('AADSTS'),false);
  assert.ok(analyzeRawEvents(events).findings.some(finding=>finding.diagnosis.rule_id==='win32-1603'));
});
test('real configuration failures remain findings, while mapping examples and zero results do not',()=>{
  const report=analyzeRawEvents([
    ev('Failed to apply configuration policy','WindowsUpdateClient.log'),
    ev('Configured return codes: 1603=failed'),
    ev('No errors. Successful request.',undefined,{level:'Error'}),
    ev('Access is denied by the operation with error 0x80070005')
  ]);
  assert.equal(report.findings.length,2);
  assert.ok(report.findings.some(finding=>finding.diagnosis.rule_id==='patch-policy'));
});
test('repeated unknown codes retain every evidence reference in one source/context pattern',()=>{
  const events=Array.from({length:1200},(_,index)=>ev('Request failed with 0xdeadbeef','custom.log',{uid:'e'+index}));
  const report=analyzeRawEvents(events);
  assert.equal(report.findings.length,1);
  assert.equal(report.findings[0].evidence.length,1200);
  assert.equal(report.findings[0].diagnosis.type,'unclassified');
  const canonical=parseReport(report);
  assert.equal(canonical.findings[0].evidenceIds.length,1200);
  assert.equal(new Set(canonical.findings[0].evidenceIds).size,1200);
  assert.equal(report.warnings.some(warning=>/finding limit was reached/.test(warning)),false);
});
test('the summary separates rule explanation, unknown signals and unrelated evidence',()=>{
  const data=dataFor([
    ev('Denied 0x80070005','AppWorkload.log',{timestamp:'2026-01-01T10:00:00Z',correlation_ids:['operation-a']}),
    ev('Failed 0xdeadbeef','AppWorkload.log'),
    ev('Installation completed successfully.','AppWorkload.log')
  ]);
  const summary=buildExecutiveSummary(data);
  assert.equal(summary.metrics.total,3);
  assert.equal(summary.metrics.explained,1);
  assert.equal(summary.metrics.unexplained,1);
  assert.equal(summary.metrics.timed,1);
  assert.equal(summary.metrics.withIds,1);
  assert.equal(summary.issues.length,2);
  assert.match(summary.issues[0].impact,/may/);
  assert.match(summary.limitations.join(' '),/does not independently confirm root causes/);
});
test('summary and knowledge matches respect filtered data and do not infer a healthy endpoint',()=>{
  const report=parseReport(analyzeRawEvents([ev('Scan failed 0x800f081f','CBS.log'),ev('Detection failed 0x87d1041c','AppWorkload.log')]));
  const filtered=buildDashboard([report],{category:'Windows patching'});
  const summary=buildExecutiveSummary(filtered);
  assert.equal(summary.metrics.total,1);
  assert.equal(summary.issues.length,1);
  assert.equal(summary.issues[0].category,'Windows patching');
  assert.ok(!summary.overview.includes('2 evidence'));
  const empty=buildExecutiveSummary(buildDashboard([report],{query:'nomatch-knowledge'}));
  assert.equal(empty.issues.length,0);
  assert.match(empty.decision,/does not establish endpoint health/);
});
test('partial CAB coverage and simulation remain explicit, independent of chart filters',()=>{
  const data=dataFor([ev('Scan failed 0x800f081f','CBS.log')]);
  const summary=buildExecutiveSummary(data,[{name:'diag.cab',entries:[{status:'analyzed'},{status:'skipped'},{status:'partial'},{status:'failed'}],complete:false}]);
  assert.deepEqual(summary.archive,{archives:1,entries:4,analyzed:1,skipped:1,partial:1,failed:1});
  assert.match(summary.limitations.join(' '),/independent of filters/);
  const simulated=structuredClone(data);simulated.reports[0].synthetic=true;
  assert.equal(buildExecutiveSummary(simulated).synthetic,1);
});
test('executive brief includes the problem analysis and safely escapes imported descriptions',()=>{
  const data=dataFor([ev('Denied 0x80070005','AppWorkload.log')]);
  data.priorityFindings[0].title='<img src=x onerror=alert(1)>';
  data.priorityFindings[0].rootCause='<script>test</script>';
  const html=executiveBrief(data,'Imported output');
  assert.ok(html.includes('Executive problem analysis'));
  assert.ok(html.includes('Management next step'));
  assert.ok(html.includes('Rule-explained records'));
  assert.ok(html.includes('&lt;img'));
  assert.equal(html.includes('<img'),false);
  assert.equal(html.includes('<script>'),false);
  assert.equal(/(?:src|href)="https?:\/\//.test(html),false);
});
test('searchable knowledge shows its meaning, verification checks, source reference and match state',()=>{
  const data=dataFor([ev('Denied 0x80070005')]);
  const html=knowledgeBaseHTML(data,'0x80070005');
  assert.ok(html.includes('Matched in this selection'));
  assert.ok(html.includes('Verify with evidence'));
  assert.ok(html.includes('Microsoft troubleshooting reference'));
  assert.ok(knowledgeCatalog().length>=50);
  assert.ok(getKnowledgeBase().length>knowledgeCatalog().length);
  const untouched=knowledgeBaseHTML(buildDashboard([]),'0x80070005');
  assert.ok(untouched.includes('Not matched in this selection'));
  assert.equal(executiveSummaryHTML(buildExecutiveSummary(buildDashboard([]))).includes('No diagnostic evidence'),true);
});

test('unmapped nonzero process exit codes remain visible without inventing a Win32 cause',()=>{
  const report=analyzeRawEvents([ev('Process exit code: 42'),ev('Process exit code: 0')]);
  assert.equal(report.findings.length,1);
  assert.equal(report.findings[0].diagnosis.type,'unclassified');
  assert.ok(report.findings[0].title.includes('42'));
  assert.match(report.findings[0].root_cause,/unconfirmed/);
});


test('explicit error tags are retained while ordinary error-handling descriptions stay informational',()=>{
  const report=analyzeRawEvents([ev('[ERROR] Unmapped operation problem'),ev('Error: Unmapped provider problem'),ev('Error handling initialized')]);
  assert.equal(report.findings.length,2);
  assert.ok(report.findings.every(finding=>finding.diagnosis.type==='unclassified'));
});


test('leading timestamps do not turn an identical unknown message into separate problem patterns',()=>{
  const report=analyzeRawEvents([ev('2026-01-01T10:00:00Z Process failed','custom.log'),ev('2026-01-01T10:01:00Z Process failed','custom.log')]);
  assert.equal(report.findings.length,1);
  assert.equal(report.findings[0].evidence.length,2);
});
