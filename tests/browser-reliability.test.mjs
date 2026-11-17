import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {parseHTML} from 'linkedom';
import {downloadBlob} from '../docs/downloads.js';
import {hashText,formatNumber} from '../docs/utils.js';
import {archiveCoverageHTML,createExecutiveState,executiveBrief} from '../docs/executive.js';
import {buildDashboard,sanitizeText} from '../docs/analytics.js';
import {parseRawLog} from '../docs/raw-parsers.js';
import {importDiagnosticFiles} from '../docs/importer.js';
import {makeCabinet} from './helpers/cab-fixtures.mjs';

const fixture=name=>JSON.parse(readFileSync(new URL('./fixtures/'+name,import.meta.url),'utf8'));
test('shared hash profiles preserve exported identities for ASCII, Unicode and surrogate edge cases',()=>{
  for(const [profile,cases] of Object.entries(fixture('hash-compatibility.json')))
    for(const {value,expected} of cases) assert.equal(hashText(value,profile),expected,profile+' '+JSON.stringify(value));
});
test('redaction preserves existing pseudonyms and address boundaries without regex lookbehind',()=>{
  for(const {value,expected} of fixture('redaction-compatibility.json'))assert.equal(sanitizeText(value),expected);
});
test('dashboard, archive rendering and XML parsing work without Object.hasOwn or Array.at',()=>{
  const own=Object.hasOwn,at=Array.prototype.at;
  let data,html,parsed;
  try {
    Object.hasOwn=undefined;Array.prototype.at=undefined;
    data=buildDashboard(createExecutiveState().sample);
    html=archiveCoverageHTML([{name:'example.cab',entries:[{name:'safe.log',status:'constructor',size:1,eventCount:0}]}]);
    parsed=parseRawLog('<Events><Event><System><EventID>12</EventID></System><RenderingInfo><Message>Observed event</Message></RenderingInfo></Event></Events>','events.xml');
  } finally {Object.hasOwn=own;Array.prototype.at=at;}
  assert.equal(data.metrics.eventsCount,29);
  assert.equal(parsed.events.length,1);
  assert.match(html,/exec-archive-status failed/);
});
test('executive counts use the same en-US grouping as diagnostic import notices',()=>{
  assert.equal(formatNumber(100000),'100,000');
  const html=archiveCoverageHTML([{name:'example.cab',entries:[{name:'safe.log',status:'analyzed',size:100000,eventCount:100000}]}]);
  assert.match(html,/100,000/);assert.doesNotMatch(html,/1,00,000/);
});
test('download URLs survive delayed Save dialogs and bfcache, then release on document unload',t=>{
  t.mock.timers.enable({apis:['setTimeout']});
  const {document,window}=parseHTML('<html><body></body></html>');
  let index=0;
  t.mock.method(URL,'createObjectURL',()=>`blob:test-${++index}`);
  const revoke=t.mock.method(URL,'revokeObjectURL',()=>{});
  const downloads=[];
  document.addEventListener('click',event=>{if(event.target.download)downloads.push(event.target.download);});
  downloadBlob(new Blob(['html']),'brief.html',document);
  downloadBlob(new Blob(['json']),'investigation.json',document);
  t.mock.timers.tick(60*60*1000);
  assert.equal(revoke.mock.callCount(),0);
  assert.deepEqual(downloads,['brief.html','investigation.json']);
  assert.equal(document.querySelectorAll('a').length,0);
  const cached=new window.Event('pagehide');Object.defineProperty(cached,'persisted',{value:true});window.dispatchEvent(cached);
  assert.equal(revoke.mock.callCount(),0);
  window.dispatchEvent(new window.Event('pagehide'));
  assert.deepEqual(revoke.mock.calls.map(call=>call.arguments[0]),['blob:test-1','blob:test-2']);
  window.dispatchEvent(new window.Event('pagehide'));assert.equal(revoke.mock.callCount(),2);
});
test('failed download handoffs clean up their anchor and object URL immediately',t=>{
  const {document}=parseHTML('<html><body></body></html>');
  t.mock.method(URL,'createObjectURL',()=> 'blob:failed');
  const revoke=t.mock.method(URL,'revokeObjectURL',()=>{});
  const create=document.createElement.bind(document);
  t.mock.method(document,'createElement',name=>{const element=create(name);element.click=()=>{throw new Error('Download blocked');};return element;});
  assert.throws(()=>downloadBlob(new Blob(['data']),'brief.html',document),/Download blocked/);
  assert.equal(document.querySelectorAll('a').length,0);
  assert.equal(revoke.mock.callCount(),1);
});
const native=(uid)=>JSON.stringify({started_at:'2026-01-01T10:00:00Z',sources:[uid+'.log'],warnings:['Common limitation','Common limitation'],events:[{uid,source:uid+'.log',message:'Observed '+uid,timestamp:'2026-01-01T10:00:00Z'}],findings:[]});
test('archive warnings are scoped to contributing reports and deduplicated in the combined brief',async()=>{
  const a=new File([makeCabinet([{name:'a.json',text:native('a')},{name:'b.json',text:native('b')},{name:'binary.etl',text:'unsupported'}])],'a.cab');
  const b=new File([makeCabinet([{name:'c.json',text:native('c')}])],'b.cab');
  const result=await importDiagnosticFiles([a,b,new File([native('outside')],'outside.json')]);
  assert.deepEqual(result.errors,[]);assert.equal(result.reports.length,4);
  for(const report of result.reports){
    const uid=report.events[0].source;
    assert.equal(report.warnings.filter(note=>note==='Common limitation').length,1);
    if(['a.log','b.log'].includes(uid)) {assert.ok(report.warnings.some(note=>note.startsWith('a.cab:')));assert.ok(!report.warnings.some(note=>note.startsWith('b.cab:')));}
    if(uid==='outside.log')assert.ok(!report.warnings.some(note=>/^[ab]\.cab:/.test(note)));
  }
  const html=executiveBrief(buildDashboard(result.reports),'Imported test');
  const {document}=parseHTML(html);
  const notes=[...document.querySelectorAll('li')].map(item=>item.textContent);
  assert.equal(notes.filter(note=>note==='Common limitation').length,1);
  assert.equal(notes.filter(note=>note.startsWith('a.cab:')).length,1);
  assert.equal(notes.filter(note=>note.startsWith('b.cab:')).length,1);
});
