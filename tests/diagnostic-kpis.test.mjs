import test from 'node:test';
import assert from 'node:assert/strict';
import {parseReport,buildDashboard} from '../docs/analytics.js';
import {analyzeRawEvents} from '../docs/raw-analysis.js';
import {buildExecutiveSummary,executiveSummaryHTML} from '../docs/executive-summary.js';
import {buildDiagnosticKPIs} from '../docs/diagnostic-kpis.js';
const report=(events)=>parseReport(analyzeRawEvents(events));
const ev=(uid,source,message,extra={})=>({uid,source,message,...extra});

test('signal coverage excludes ordinary records and counts overlapping evidence only once',()=>{
  const data=buildDashboard([report([
    ev('known','WindowsUpdate.log','Operation failed 0x8024401b',{timestamp:'2026-01-01T10:00:00Z'}),
    ev('unknown','WindowsUpdate.log','Operation failed 0xdeadbeef'),
    ev('ordinary','WindowsUpdate.log','Observing operation')
  ])]);
  // The same evidence can appear in multiple findings; it must not inflate denominators.
  const original=data.priorityFindings[0];
  data.priorityFindings.push({...original,id:original.id+'-copy'});
  const metrics=buildExecutiveSummary(data).diagnostics;
  assert.equal(metrics.signalTotal,2);
  assert.equal(metrics.cards[0].value,'50.0%');
  assert.equal(metrics.priorityRecords,2);
  assert.equal(metrics.timedPriority,1);
  assert.equal(metrics.cards[1].value,'50.0%');
});
test('shared identifiers require different sources in the same report and deduplicate per record',()=>{
  const data=buildDashboard([report([
    ev('a','AppWorkload.log','Observed',{correlation_ids:['activity-a','activity-a','same-source-only']}),
    ev('b','AppActionProcessor.log','Observed',{correlation_ids:['activity-a']}),
    ev('c','AppWorkload.log','Observed again',{correlation_ids:['same-source-only']})
  ])]);
  const metrics=buildExecutiveSummary(data).diagnostics;
  assert.equal(metrics.sharedCount,1);
  assert.equal(metrics.shared[0].records,2);
  assert.deepEqual(metrics.shared[0].sources,['AppActionProcessor.log','AppWorkload.log']);
  const html=executiveSummaryHTML(buildExecutiveSummary(data));
  assert.match(html,/do not establish one operation, a retry or causation/);
});
test('matching identifiers in separate reports are never joined',()=>{
  const data=buildDashboard([
    report([ev('a','one.log','Observed',{correlation_ids:['shared']})]),
    report([ev('b','two.log','Observed',{correlation_ids:['shared']})])
  ]);
  assert.equal(buildExecutiveSummary(data).diagnostics.sharedCount,0);
});
test('filters recompute signal, timing and shared-source denominators',()=>{
  const data=report([
    ev('a','WindowsUpdate.log','Operation failed 0x8024401b',{correlation_ids:['operation'],timestamp:'2026-01-01T10:00:00Z'}),
    ev('b','AppWorkload.log','Operation failed 0x87D1041C',{correlation_ids:['operation']})
  ]);
  assert.equal(buildExecutiveSummary(buildDashboard([data])).diagnostics.sharedCount,1);
  const filtered=buildExecutiveSummary(buildDashboard([data],{category:'Windows patching'})).diagnostics;
  assert.equal(filtered.sharedCount,0);
  assert.equal(filtered.priorityRecords,1);
  assert.equal(filtered.cards[1].value,'100.0%');
  const empty=buildExecutiveSummary(buildDashboard([data],{query:'nomatch'})).diagnostics;
  assert.equal(empty.cards[0].value,'—');
  assert.equal(empty.cards[1].value,'—');
});
test('bounded identifier indexing discloses lower bounds and escapes display text',()=>{
  const events=Array.from({length:1001},(_,index)=>({id:'e'+index,reportId:'r',source:index%2?'a':'b',correlationIds:Array.from({length:100},(_,i)=>'id'+i)}));
  const metrics=buildDiagnosticKPIs({events});
  assert.equal(metrics.truncated,true);
  assert.equal(metrics.sharedCount,100);
  assert.match(metrics.cards[2].value,/^≥/);
  const summary=buildExecutiveSummary(buildDashboard([]));
  summary.diagnostics={...metrics,shared:[{reportId:'<img>',identifier:'<script>',records:2,sources:['<svg>','b']}]};
  const html=executiveSummaryHTML(summary);
  assert.doesNotMatch(html,/<(?:script|img|svg)[ >]/);
  assert.match(html,/count is a lower bound/);
});
