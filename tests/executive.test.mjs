import test from 'node:test';
import assert from 'node:assert/strict';
import { buildDashboard, parseReport } from '../docs/analytics.js';
import { createExecutiveState, chartBuckets, timelineSVG, severityGradient, executiveBrief } from '../docs/executive.js';

test('executive view begins with the exact existing sample output, not invented fleet data',()=>{
  const state=createExecutiveState();
  const data=buildDashboard(state.sample);
  assert.equal(state.mode,'sample');
  assert.equal(state.imported.length,0);
  assert.equal(data.metrics.reportsCount,4);
  assert.equal(data.metrics.eventsCount,29);
  assert.equal(data.metrics.findingsCount,5);
  assert.equal(data.metrics.priorityCount,4);
  assert.equal(data.coverage.syntheticReports,4);
});

test('display grouping preserves record totals while limiting chart complexity',()=>{
  const input=Array.from({length:91},(_,index)=>({key:new Date(Date.UTC(2026,0,index+1)).toISOString(),label:`Day ${index+1}`,events:index+1,results:1}));
  const groups=chartBuckets(input);
  assert.ok(groups.length<=30);
  assert.equal(groups.reduce((sum,item)=>sum+item.events,0),input.reduce((sum,item)=>sum+item.events,0));
  assert.equal(groups.reduce((sum,item)=>sum+item.results,0),91);
  assert.equal(groups[0].key,input[0].key);
});

test('timeline uses elapsed time for horizontal positions instead of compressing gaps',()=>{
  const data={timeline:[{key:'2026-10-13T08:00:00Z',label:'08:00',events:3,results:1},{key:'2026-10-13T09:00:00Z',label:'09:00',events:2,results:1},{key:'2026-10-13T12:00:00Z',label:'12:00',events:1,results:0}],timelineGranularity:'hour',metrics:{eventsCount:6}};
  const svg=timelineSVG(data);
  const positions=[...svg.matchAll(/<circle cx="([\d.]+)"/g)].map(match=>Number(match[1]));
  assert.equal(positions.length,3);
  assert.ok(Math.abs((positions[1]-positions[0])*3-(positions[2]-positions[1]))<0.0001);
  assert.ok(svg.includes('role="img"'));
  assert.ok(svg.includes('View chart data'));
});

test('severity chart represents finding counts and handles an empty selection',()=>{
  assert.equal(severityGradient({error:0,warning:0,info:0}),'#e9eff3');
  const gradient=severityGradient({error:4,warning:1,info:0});
  assert.ok(gradient.includes('0% 80%'));
  assert.ok(gradient.includes('80% 100%'));
});

test('executive brief safely escapes imported output and labels hypotheses and scope',()=>{
  const data=buildDashboard([parseReport({started_at:'2026-10-16T08:00:00Z',synthetic:false,sources:['example.log'],events:[{uid:'e1',source:'example.log',category:'Win32 apps',message:'Untrusted <img src=x onerror=alert(1)>',timestamp:'2026-10-16T07:00:00Z',stage:'result'}],findings:[{id:'f1',title:'<script>alert(1)</script>',category:'Win32 apps',severity:'error',summary:'Reported symptom',root_cause:'Unconfirmed cause',evidence:['e1'],checks:['Inspect <b>configuration</b>'],recommendations:['Prepare a reviewed proposal']} ]})]);
  const html=executiveBrief(data,'<img src=x onerror=alert(1)>');
  assert.equal(html.includes('<script>'),false);
  assert.equal(html.includes('<img '),false);
  assert.ok(html.includes('&lt;script&gt;'));
  assert.ok(html.includes('MANAGED BY DIBYENDU'));
  assert.ok(html.includes('Imported report output · no live endpoint connection'));
  assert.ok(html.includes('Suggested resolution · not executed'));
  assert.ok(html.includes('Review this brief before sharing'));
  assert.ok(html.includes('Full record detail remains in the original diagnostic report'));
});

test('empty filtered brief makes no clean-health assertion and contains no remote assets',()=>{
  const data=buildDashboard([],{});
  const html=executiveBrief(data,'Empty selection');
  assert.ok(html.includes('This does not establish endpoint health'));
  assert.equal(/(?:src|href)="https?:\/\//.test(html),false);
});
