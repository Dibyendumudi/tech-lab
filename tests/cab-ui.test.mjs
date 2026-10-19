import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { archiveCoverageHTML, createExecutiveState, executiveBrief } from '../docs/executive.js';
import { buildDashboard } from '../docs/analytics.js';

function archive(overrides={}) {
  return {name:'AutopilotDiag.cab',entryCount:5,analyzed:1,partial:1,skipped:1,failed:1,duplicates:1,expandedBytes:512,complete:false,entries:[
    {name:'IntuneManagementExtension.log',size:100,status:'analyzed',reason:'Readable log analyzed',eventCount:2},
    {name:'CBS.log',size:200,status:'partial',reason:'Only the supported records were parsed',eventCount:1},
    {name:'WindowsUpdate.etl',size:60,status:'skipped',reason:'Binary ETL is not decoded',eventCount:0},
    {name:'broken.xml',size:52,status:'failed',reason:'Invalid XML',eventCount:0},
    {name:'duplicate.log',size:100,status:'duplicate',reason:'Duplicate content, already analyzed',eventCount:0}
  ],...overrides};
}

test('file picker accepts a CAB directly and explains automatic per-file coverage',async()=>{
  const html=await readFile(new URL('../docs/index.html',import.meta.url),'utf8');
  const input=html.match(/<input[^>]*id="exec-file-input"[^>]*>/)?.[0];
  assert.match(input,/\.cab/);
  assert.match(input,/application\/vnd\.ms-cab-compressed/);
  assert.match(html,/Import CAB \/ logs/);
  assert.match(html,/Select one CAB/);
  assert.match(html,/coverage shown for every file/);
  assert.doesNotMatch(html,/CAB archives must be extracted first/);
});

test('coverage shows all analysis outcomes and retains binary limitations independently of charts',()=>{
  const html=archiveCoverageHTML([archive()]);
  assert.match(html,/Latest CAB import coverage/);
  assert.match(html,/1 analyzed · 1 partial · 1 skipped · 1 failed · 1 duplicates/);
  assert.match(html,/Partial \/ unavailable coverage/);
  assert.match(html,/Binary ETL is not decoded/);
  assert.match(html,/Partial coverage is not a complete diagnosis/);
  assert.match(html,/independent of chart filters/);
  assert.match(html,/Charts may still use earlier reports/);
  for(const entry of archive().entries)assert.ok(html.includes(entry.name));
  assert.equal((html.match(/<tr>/g)||[]).length,6);
  assert.equal(createExecutiveState().archives.length,0);
});

test('archive coverage escapes names, reasons and unsafe status values',()=>{
  const html=archiveCoverageHTML([archive({name:'<img src=x onerror=alert(1)>.cab',reason:'<script>reason</script>',entries:[{name:'<svg onload=alert(1)>',size:1,status:'analyzed" onclick="bad()',reason:'<iframe src=x></iframe>',eventCount:0}]})]);
  assert.doesNotMatch(html,/<(?:script|img|svg|iframe)[ >]/);
  assert.match(html,/&lt;img/);
  assert.match(html,/&lt;script&gt;reason/);
  assert.match(html,/&lt;iframe/);
  assert.doesNotMatch(html,/onclick=/);
  assert.match(html,/exec-archive-status failed/);
});

test('coverage never truncates the archive inventory to chart or source limits',()=>{
  const entries=Array.from({length:75},(_,index)=>({name:`member-${index}.log`,size:1,status:'analyzed',reason:'Analyzed',eventCount:1}));
  const html=archiveCoverageHTML([archive({entryCount:75,entries,analyzed:75,partial:0,skipped:0,failed:0,duplicates:0,complete:true})]);
  assert.match(html,/member-74\.log/);
  assert.equal((html.match(/<tr>/g)||[]).length,76);
  assert.match(html,/endpoint coverage is not established/);
});

test('rejected CAB coverage and its reason survive in a zero-event executive brief',()=>{
  const failed=archive({name:'broken.cab',entryCount:0,analyzed:0,partial:0,skipped:0,failed:1,duplicates:0,expandedBytes:0,entries:[],reason:'CAB header is invalid <not trusted>'});
  const data=buildDashboard([]);
  assert.equal(data.metrics.eventsCount,0);
  const html=executiveBrief(data,'Earlier dataset unchanged',[failed]);
  assert.match(html,/Latest CAB import coverage/);
  assert.match(html,/broken\.cab/);
  assert.match(html,/CAB header is invalid &lt;not trusted&gt;/);
  assert.match(html,/No file inventory is available/);
  assert.match(html,/No complete archive analysis can be claimed/);
  assert.doesNotMatch(html,/<not trusted>/);
});

test('brief exports complete file coverage, while legacy reports export without an archive section',()=>{
  const data=buildDashboard(createExecutiveState().sample,{query:'a-filter-that-matches-nothing'});
  const legacy=executiveBrief(data,'Demonstration dataset');
  assert.doesNotMatch(legacy,/Latest CAB import coverage/);
  const html=executiveBrief(data,'Demonstration dataset',[archive()]);
  assert.match(html,/charts include demonstration data/);
  assert.match(html,/Binary ETL is not decoded/);
  assert.match(html,/duplicate\.log/);
  assert.match(html,/Invalid XML/);
  assert.doesNotMatch(html,/<details class="exec-archive"/);
  assert.doesNotMatch(html,/(?:src|href)="https?:\/\//);
});
