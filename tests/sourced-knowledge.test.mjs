import test from 'node:test';
import assert from 'node:assert/strict';
import {parseRawLog} from '../docs/raw-parsers.js';
import {analyzeRawEvents,getKnowledgeBase} from '../docs/raw-analysis.js';
import {SOURCED_CODE_KNOWLEDGE,STATE_KNOWLEDGE,KNOWLEDGE_SOURCES} from '../docs/sourced-knowledge.js';
import {buildDashboard,parseReport} from '../docs/analytics.js';
import {buildExecutiveSummary,knowledgeBaseHTML} from '../docs/executive-summary.js';
import {executiveBrief} from '../docs/executive.js';
const analyze=(message,filename='events.log')=>analyzeRawEvents(parseRawLog(message,filename).events);

test('all added code rules retain reviewed provenance and recognize generic logs inside Autopilot CAB paths',()=>{
  for(const entry of SOURCED_CODE_KNOWLEDGE){
    const report=analyze('Operation result '+entry.code,'Autopilot.cab / events.log');
    const finding=report.findings.find(finding=>finding.diagnosis.rule_id===entry.id+':'+entry.categories[0]);
    assert.ok(finding,entry.code);
    assert.equal(finding.severity,entry.severity);
    assert.deepEqual(finding.references,[entry.reference]);
    const rule=getKnowledgeBase().find(rule=>rule.id===finding.diagnosis.rule_id);
    assert.equal(rule.sourceId,entry.sourceId);
    assert.equal(rule.reviewed,'2026-11-02');
    assert.ok(Object.values(KNOWLEDGE_SOURCES).some(source=>source.reference===rule.reference));
  }
});
test('decimal and signed HRESULTs follow the same Windows Update rule',()=>{
  const code=0x8024401b;
  for(const value of [code,code|0]){
    const report=analyze('HRESULT='+value,'events.log');
    assert.ok(report.findings.some(finding=>finding.diagnosis.rule_id==='code-0x8024401b:Windows patching'));
  }
});
test('AppX provider identifies software deployment without a descriptive source filename',()=>{
  const events=parseRawLog(JSON.stringify({Message:'Operation failed 0x80073D02',Provider:'Microsoft-Windows-AppXDeploymentServer'}),'events.json').events;
  assert.ok(analyzeRawEvents(events).findings.some(finding=>finding.diagnosis.rule_id==='code-0x80073d02:Win32 apps'));
});
test('device auth check execution error is distinct from disabled/deleted status',()=>{
  for(const entry of STATE_KNOWLEDGE){
    const report=analyze(entry.example,'Entra-device-status.txt');
    assert.equal(report.findings.length,1);
    assert.equal(report.findings[0].diagnosis.rule_id,entry.id);
    assert.equal(report.findings[0].severity,entry.severity);
    assert.deepEqual(report.findings[0].references,[entry.reference]);
  }
  const report=analyze('DeviceAuthStatus : FAILED. ERROR');
  assert.match(report.findings[0].root_cause,/does not establish/);
  assert.doesNotMatch(report.findings[0].diagnosis.rule_id,/auth-failed$/);
});
test('new rules exclude successful status, quoted examples and configuration mappings',()=>{
  for(const message of ['DeviceAuthStatus : SUCCESS','AzureAdPrt : YES','Documentation example: AzureAdPrt : NO','Configured return codes: 0x80073D02','Configured error codes: 0x8024401B']){
    assert.equal(analyze(message).findings.length,0,message);
  }
});
test('no-applicable-update is informational rather than a fabricated servicing failure',()=>{
  const report=analyze('Windows Update result 0x80240017','WindowsUpdate.log');
  assert.equal(report.findings.length,1);
  assert.equal(report.findings[0].severity,'info');
});
test('source links and reviewed dates are visible in knowledge and the exported interpretation',()=>{
  const data=buildDashboard([parseReport(analyze('Windows Update failed 0x8024401b','WindowsUpdate.log'))]);
  const html=knowledgeBaseHTML(data,'0x8024401b');
  assert.match(html,/Reviewed 2026-11-02/);
  assert.ok(html.includes(KNOWLEDGE_SOURCES.wu.reference));
  const brief=executiveBrief(data,'Synthetic provenance test');
  assert.ok(brief.includes(KNOWLEDGE_SOURCES.wu.reference));
  assert.match(brief,/Documented interpretation/);
  assert.equal(buildExecutiveSummary(data).metrics.explained,1);
});
