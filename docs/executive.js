import {artifactInvestigationHTML} from './artifact-investigation.js?v=1.6.5';
import { escapeHTML as e, hasOwn, last, formatNumber as number, uniqueMessages, reportWarnings } from './utils.js?v=1.6.5';
import { downloadBlob } from './downloads.js?v=1.6.5';
import { scenarios } from './scenarios.js?v=1.6.5';
import { initWorkflow } from './app.js?v=1.6.5';
import { CATEGORIES, sampleReports, parseReport, buildDashboard, sanitizeText } from './analytics.js?v=1.6.5';
import { readDiagnosticFiles } from './importer.js?v=1.6.5';
import { buildExecutiveSummary, executiveSummaryHTML, knowledgeBaseHTML } from './executive-summary.js?v=1.6.5';
import { runValidationCases } from './validation-cases.js?v=1.6.5';

const COLORS = { error: '#bc6871', warning: '#d6ab61', info: '#769ab7' };
const LABELS = { error: 'Error / high / critical', warning: 'Warning / medium', info: 'Informational / low' };
const SHORT = { error: 'Error', warning: 'Warning', info: 'Info' };
const formatTime = value => value ? new Intl.DateTimeFormat('en-GB', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'UTC' }).format(new Date(value)) + ' UTC' : 'Time unspecified';
const evidenceTime = event => event.timestamp ? formatTime(event.timestamp) : event.rawTimestamp ? `${event.rawTimestamp} · ${event.timestampIssue==='invalid timestamp'?'invalid timestamp':'local clock; timezone unverified'}` : 'Time unspecified';
const badge = severity => `<span class="exec-severity-badge ${e(severity)}">${e(SHORT[severity] || 'Info')}</span>`;
const ARCHIVE_STATUSES = {analyzed:'Analyzed',partial:'Partial',skipped:'Skipped',failed:'Failed',duplicate:'Duplicate'};
const count = value => number(Number.isFinite(Number(value)) ? Math.max(0,Math.trunc(Number(value))) : 0);
const fileSize = value => Number.isFinite(Number(value)) && Number(value)>=0 ? `${count(value)} bytes` : 'Unknown';

export function archiveCoverageHTML(archives, {sample=false,brief=false}={}) {
  if(!Array.isArray(archives)||!archives.length)return '';
  return `<div class="exec-panel-head"><div><h2 id="exec-archive-heading">Latest CAB import coverage</h2><p class="exec-panel-sub">${sample?'The charts include demonstration data. This inventory describes the latest CAB import attempt only.':'The latest CAB import attempt, independent of chart filters. Charts may still use earlier reports if no records were loaded.'}</p></div><span class="exec-panel-tag">${count(archives.length)} ARCHIVE${archives.length===1?'':'S'}</span></div><div class="exec-archive-body"><p class="exec-archive-note">Partial coverage is not a complete diagnosis. Skipped or failed entries contribute no evidence; analyzed entries may still have limited diagnostic context.</p>${archives.map((archive,index)=>{
    const entries=Array.isArray(archive.entries)?archive.entries:[];
    const summary=`${count(archive.analyzed)} analyzed · ${count(archive.partial)} partial · ${count(archive.skipped)} skipped · ${count(archive.failed)} failed · ${count(archive.duplicates)} duplicates`;
    const complete=archive.complete===true;
    const body=`<p class="exec-archive-counts">${summary}</p><p class="exec-archive-meta">${count(archive.entryCount)} entries listed · ${fileSize(archive.expandedBytes)} expanded · ${complete?'All listed entries analyzed; endpoint coverage is not established.':'Partial or unavailable archive analysis. Review the entry reasons below.'}</p>${archive.reason||archive.error?`<p class="exec-archive-error">${e(String(archive.reason||archive.error))}</p>`:''}${entries.length?`<div class="exec-archive-table-scroll" role="region" aria-label="Archive ${index+1} file coverage" tabindex="0"><table class="exec-archive-table"><thead><tr><th scope="col">Archive file</th><th scope="col">Size</th><th scope="col">Analysis</th><th scope="col">Records</th><th scope="col">Coverage / reason</th></tr></thead><tbody>${entries.map(entry=>{const status=hasOwn(ARCHIVE_STATUSES,entry.status)?entry.status:'failed';return `<tr><td>${e(String(entry.name??'Unnamed entry'))}</td><td>${fileSize(entry.size)}</td><td><span class="exec-archive-status ${status}">${ARCHIVE_STATUSES[status]}</span></td><td>${count(entry.eventCount)}</td><td>${e(String(entry.reason||'No additional coverage information supplied.'))}</td></tr>`;}).join('')}</tbody></table></div>`:'<p class="exec-archive-error">No file inventory is available for this archive. No complete archive analysis can be claimed.</p>'}`;
    return brief?`<article class="exec-archive"><h3>${e(String(archive.name??'Unnamed CAB'))} · ${complete?'Listed entries analyzed':'Partial / unavailable coverage'}</h3>${body}</article>`:`<details class="exec-archive" open><summary><span>${e(String(archive.name??'Unnamed CAB'))}</span><span class="exec-archive-state ${complete?'complete':'partial'}">${complete?'Listed entries analyzed':'Partial / unavailable coverage'}</span></summary>${body}</details>`;
  }).join('')}</div>`;
}

export function chartBuckets(timeline, maximum = 30) {
  if (timeline.length <= maximum) return timeline;
  const size = Math.ceil(timeline.length / maximum), result = [];
  for (let index = 0; index < timeline.length; index += size) {
    const group = timeline.slice(index, index + size);
    result.push({key:group[0].key,label:`${group[0].label} – ${last(group).label}`,events:group.reduce((sum,item)=>sum+item.events,0),results:group.reduce((sum,item)=>sum+item.results,0)});
  }
  return result;
}

export function timelineSVG(data) {
  const values = chartBuckets(data.timeline);
  if (!values.length) return '<div class="exec-empty-state">No timestamped evidence in this selection.<span>Unspecified or local timestamps are kept out of the UTC timeline.</span></div>';
  const plotted = values.reduce((sum, value) => sum + value.events, 0);
  const width=640, height=200, left=36, right=18, top=15, bottom=32;
  const plotWidth=width-left-right, plotHeight=height-top-bottom;
  const maximum = Math.max(4, Math.ceil(Math.max(...values.map(value=>value.events))/4)*4);
  const firstTime=Date.parse(values[0].key), lastTime=Date.parse(last(values).key);
  const x = index => left + (firstTime===lastTime ? plotWidth/2 : (Date.parse(values[index].key)-firstTime)/(lastTime-firstTime)*plotWidth);
  const y = value => top + plotHeight - value/maximum*plotHeight;
  const points = key => values.map((value,index)=>`${x(index)},${y(value[key])}`).join(' ');
  const area = `M${x(0)},${y(0)} L${values.map((value,index)=>`${x(index)},${y(value.events)}`).join(' L')} L${x(values.length-1)},${y(0)} Z`;
  const grid = Array.from({length:5},(_,index)=>{const value=maximum*index/4;return `<line x1="${left}" y1="${y(value)}" x2="${width-right}" y2="${y(value)}" stroke="#e9eff3" stroke-dasharray="3 4"/><text class="exec-axis-label" x="${left-10}" y="${y(value)+3}" text-anchor="end">${value}</text>`;}).join('');
  const tickEvery = Math.max(1,Math.ceil(values.length/5));
  const labels = values.map((value,index)=>{
    if(index%tickEvery && index!==values.length-1)return '';
    const label = data.timelineGranularity==='month' ? value.key.slice(0,7) : data.timelineGranularity==='hour' && data.timeline.length<=30 ? `${values[0].key.slice(0,10)!==last(values).key.slice(0,10)?value.key.slice(8,10)+' / ':''}${value.key.slice(11,16)}` : value.key.slice(5,10);
    return `<text class="exec-axis-label" x="${x(index)}" y="${height-9}" text-anchor="middle">${e(label)}</text>`;
  }).join('');
  return `<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="${plotted} timestamped records shown out of ${data.metrics.eventsCount} recorded events. Teal shows all records and the lighter line shows result-stage records. Evidence timestamps are UTC."><defs><linearGradient id="exec-evidence-fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#169aa1" stop-opacity=".15"/><stop offset="100%" stop-color="#169aa1" stop-opacity=".015"/></linearGradient></defs>${grid}<path d="${area}" fill="url(#exec-evidence-fill)"/><polyline points="${points('results')}" fill="none" stroke="#afcfcc" stroke-width="2.5" stroke-dasharray="4 3"/><polyline points="${points('events')}" fill="none" stroke="#148f9b" stroke-width="2.5" stroke-linejoin="round"/>${values.map((value,index)=>`<circle cx="${x(index)}" cy="${y(value.events)}" r="4" fill="white" stroke="#148f9b" stroke-width="2"><title>${e(value.label)} UTC: ${value.events} evidence records, ${value.results} result-stage records</title></circle>`).join('')}${labels}</svg><details class="exec-chart-data"><summary>View chart data${data.timeline.length>30 ? ' · adjacent buckets grouped for display' : ''}</summary><table aria-label="Evidence activity data in UTC"><thead><tr><th scope="col">Evidence bucket · UTC</th><th scope="col">Records</th><th scope="col">Result stage</th></tr></thead><tbody>${values.map(value=>`<tr><td>${e(value.label)}</td><td>${value.events}</td><td>${value.results}</td></tr>`).join('')}</tbody></table></details>`;
}

export function severityGradient(counts) {
  const total=counts.error+counts.warning+counts.info;
  if(!total)return '#e9eff3';
  let start=0;
  return `conic-gradient(${['error','warning','info'].map(severity=>{const end=start+counts[severity]/total*100;const stop=`${COLORS[severity]} ${start}% ${end}%`;start=end;return stop;}).join(',')})`;
}

export function executiveBrief(data, datasetLabel, archives=[]) {
  const made = new Intl.DateTimeFormat('en-IN',{dateStyle:'medium',timeStyle:'short',timeZone:'Asia/Kolkata'}).format(new Date());
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Windows Diagnostics · Executive brief</title><style>body{font:14px/1.65 'Segoe UI',system-ui,sans-serif;color:#21374c;background:#f4f7fa;margin:0}header{padding:30px max(24px,calc((100vw - 1040px)/2));background:#10243a;color:white}header small{color:#a3d9cb}h1{font-size:30px;margin:9px 0}main{max-width:1040px;margin:auto;padding:24px}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.card,section{background:white;border:1px solid #dfe8ef;border-radius:10px;padding:21px;margin-bottom:16px}.card strong{font-size:30px;display:block;color:#087f7c}.card span,.meta{font-size:11px;color:#6b7e8c}h2{font-size:19px}h3{font-size:14px}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:12px;border-bottom:1px solid #e5edf3;font-size:12px;vertical-align:top}li{margin-bottom:7px}svg{max-height:260px;width:100%}.exec-axis-label{font:10px 'Segoe UI',sans-serif;fill:#8194a3}.exec-chart-data{font-size:11px}.note{border-left:4px solid #cfac68}.finding{break-inside:avoid}.exec-summary-body{padding:6px 0 20px}.exec-summary-headline{font-size:23px}.exec-summary-kpis{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin:18px 0}.exec-summary-kpi{background:#f3f8fa;border:1px solid #dde8ef;padding:16px;border-radius:8px}.exec-summary-kpi>span,.exec-summary-kpi>small{display:block;font-size:10px;color:#6b7f8d}.exec-summary-kpi>strong{display:block;font-size:26px;color:#087f7c;margin:5px 0}.exec-summary-decision{background:#eaf5f0;padding:16px;border-left:3px solid #168571;margin:18px 0}.exec-summary-issue{background:white;border:1px solid #dfe8ef;padding:20px;border-radius:8px;margin:12px 0;break-inside:avoid}.exec-summary-issue-heading{display:flex;gap:12px}.exec-summary-issue-heading h3{margin:0;font-size:17px}.exec-summary-issue-heading p,.exec-summary-scope,.exec-summary-sources{font-size:11px;color:#748795}.exec-summary-number{font-size:19px;color:#087f7c}.exec-summary-issue dt{font-weight:600;font-size:12px;margin-top:12px}.exec-summary-issue dd{margin:4px 0;font-size:12px}.exec-summary-limitations{margin:18px 0;font-size:11px}.exec-archive-export{overflow-wrap:anywhere}.exec-archive-table td:first-child{max-width:280px}.exec-archive-table td:last-child{min-width:180px}.exec-archive-counts{font-weight:600}.exec-archive-meta,.exec-panel-sub,.exec-archive-note{font-size:11px;color:#6b7e8c}.exec-archive-error{color:#a45b61}.exec-archive-status{font-weight:600}.exec-archive-status.partial,.exec-archive-status.skipped{color:#966d2a}.exec-archive-status.failed{color:#a45b61}.exec-archive-status.analyzed{color:#137665}.exec-archive-export{break-inside:auto}footer{font-size:11px;color:#718390}@media print{body{background:white}section{break-inside:avoid}.cards{grid-template-columns:repeat(4,1fr)}}@media(max-width:650px){.cards{grid-template-columns:repeat(2,1fr)}} </style></head><body><header><small>WINDOWS DIAGNOSTICS / MANAGED BY DIBYENDU</small><h1>Executive diagnostics brief</h1><p>${e(datasetLabel)} · Generated ${e(made)} IST</p></header><main><section class="note"><strong>${data.coverage.syntheticReports ? 'Includes synthetic demonstration records' : 'Imported report output · no live endpoint connection'}</strong><p>Counts summarize supplied diagnostic reports, rather than fleet size, compliance or confirmed device health. Findings describe recorded observations and hypotheses; no remediation is performed by this dashboard. Reports remain local to the browser session.</p><p class="meta">Filters: ${e(data.filters.category)} workstreams · ${e(data.filters.severity)} severities · ${e(data.filters.from || 'all dates')} to ${e(data.filters.to || 'all dates')} UTC · Search: ${e(data.filters.query || 'none')}.</p></section>${executiveSummaryHTML(buildExecutiveSummary(data,archives))}${archives.length?`<section class="exec-archive-export">${archiveCoverageHTML(archives,{sample:Boolean(data.coverage.syntheticReports),brief:true})}</section>`:''}<div class="cards">${[['Diagnostic reports',data.metrics.reportsCount],['Priority findings',data.metrics.priorityCount],['Evidence records',data.metrics.eventsCount],['Workstreams',data.metrics.categoriesCount]].map(([label,value])=>`<div class="card"><span>${label}</span><strong>${number(value)}</strong></div>`).join('')}</div><section><h2>Findings by workstream</h2><table><thead><tr><th>Workstream</th><th>Error / high / critical</th><th>Warning / medium</th><th>Informational / low</th><th>Evidence records</th></tr></thead><tbody>${data.domainCounts.filter(domain=>domain.total||domain.eventCount).map(domain=>`<tr><td>${e(domain.category)}</td><td>${domain.error}</td><td>${domain.warning}</td><td>${domain.info}</td><td>${number(domain.eventCount)}</td></tr>`).join('')}</tbody></table></section>${artifactInvestigationHTML(data.events,archives)}<section><h2>Evidence activity · UTC</h2>${timelineSVG(data)}<p class="meta">Result-stage records can describe success, failure or an unknown outcome.</p></section><section><h2>Review priorities</h2>${data.priorityFindings.map(finding=>`<article class="finding"><h3>${e(finding.title)}</h3><p class="meta">${e(finding.category)} · ${e(LABELS[finding.severity])} · Confidence: ${e(finding.confidence)} · ${e(finding.reportLabel)}</p><p>${e(finding.summary)}</p><p><strong>Likely cause / what to confirm:</strong> ${e(finding.rootCause || 'Not established in the supplied report.')}</p><h3>Verification checks</h3><ol>${finding.checks.map(check=>`<li>${e(check)}</li>`).join('')}</ol><h3>Suggested resolution · not executed</h3><ol>${finding.recommendations.map(item=>`<li>${e(item)}</li>`).join('')}</ol><p class="meta">${finding.evidenceIds.length} linked evidence references. Full record detail remains in the original diagnostic report.</p></article>`).join('') || '<p>No findings in this selection. This does not establish endpoint health.</p>'}</section><section><h2>Scope and limitations</h2><ul>${uniqueMessages([...data.notes,...reportWarnings(data.reports)]).map(note=>`<li>${e(note)}</li>`).join('')}</ul><p>Redaction is best-effort. Review this brief before sharing. A source inventory does not establish complete log coverage.</p></section><footer>Windows Diagnostics · Managed by Dibyendu · Suggestions only; no endpoint actions.</footer></main></body></html>`;
}

export function createExecutiveState() {
  return {mode:'sample',sample:sampleReports(scenarios),imported:[],archives:[],filters:{category:'all',severity:'all',from:'',to:'',query:''},busy:false,view:'dashboard',evidencePage:0};
}

export function initExecutive({readFiles=readDiagnosticFiles}={}) {
  const state=createExecutiveState();
  const workflow=initWorkflow({getArchives:()=>state.archives});
  const $=id=>document.getElementById(id);
  function closeDetail() {
    const dialog=$('exec-detail');
    if (typeof dialog.close==='function') dialog.close();
    else dialog.removeAttribute('open');
    if (detailTrigger?.isConnected) detailTrigger.focus();
  }
  function showDetail() {
    const dialog=$('exec-detail');
    if (typeof dialog.showModal==='function') dialog.showModal();
    else {
      // Older Safari gets a nonmodal, named dialog with an explicit close control.
      dialog.classList.add('exec-dialog-fallback');dialog.setAttribute('role','dialog');
      dialog.setAttribute('open','');dialog.setAttribute('tabindex','-1');dialog.focus();
    }
  }
  const reports=()=>state.mode==='sample'?state.sample:state.imported;
  let current=buildDashboard(reports());
  let searchTimer, detailTrigger=null;
  function showStatus(message,error=false){for(const id of ['exec-import-status','workflow-import-status']){const status=$(id);status.textContent=message;status.classList.toggle('error',error);status.hidden=false;}}
  function datasetLabel(){return state.mode==='sample'?'Demonstration dataset':current.coverage.syntheticReports?'Imported sample / mixed report data':'Imported diagnostic reports';}
  function syncWorkflow(){workflow.setReports(reports(),{mode:state.mode});for(const id of ['exec-dataset','workflow-dataset']){const select=$(id);select.options[1].disabled=!state.imported.length;select.options[1].textContent=`Imported reports (${state.imported.length})`;select.value=state.mode;}}
  function changeDataset(mode){state.mode=mode;resetFilters();$('exec-import-status').hidden=true;$('workflow-import-status').hidden=true;syncWorkflow();render();}
  function openInvestigation(reportId,findingId){
    if(state.mode==='sample'){
      const reportIndex=state.sample.findIndex(report=>report.id===reportId);
      const sample=state.sample[reportIndex],scenario=scenarios[reportIndex];
      const findingIndex=sample?.findings.findIndex(finding=>finding.id===findingId)??-1;
      if(scenario)workflow.openReport(scenario.id,scenario.findings[findingIndex]?.id);
    }else workflow.openReport(reportId,findingId);
    closeDetail();setView('workflow');
  }
  function setView(view){
    state.view=['dashboard','evidence','workflow'].includes(view)?view:'dashboard';
    const executive=state.view!=='workflow';
    $('executive-view').hidden=!executive;$('workflow-view').hidden=executive;$('scenario-group').hidden=executive;
    $('executive-view').setAttribute('data-view',state.view);
    $('exec-evidence-panel').hidden=state.view!=='evidence';
    document.querySelectorAll('[data-exec-view]').forEach(button=>{const active=button.dataset.execView===state.view;button.classList.toggle('active',active);if(active)button.setAttribute('aria-current','page');else button.removeAttribute('aria-current');});
    if(state.view==='evidence')renderEvidence();
  }
  function renderEvidence(){
    if(state.view!=='evidence')return;
    const pageSize=100,total=current.events.length,pages=Math.max(1,Math.ceil(total/pageSize));
    state.evidencePage=Math.max(0,Math.min(state.evidencePage,pages-1));
    const start=state.evidencePage*pageSize,records=current.events.slice(start,start+pageSize);
    $('exec-evidence-content').innerHTML=`<div class="exec-panel-head"><div><h2>Evidence &amp; findings</h2><p class="exec-panel-sub">${e(datasetLabel())} · ${number(total)} records · ${number(current.findings.length)} findings in the current filters</p></div></div><div class="exec-evidence-body"><p>${state.mode==='sample'?'Demonstration records are shown. Import your CAB or logs above to replace them with your evidence.':'These records and findings come from your imported files. Switching views keeps this dataset; reloading the page clears the browser session.'}</p><h3>Findings · ${number(current.findings.length)}</h3>${current.priorityFindings.length?`<div class="exec-evidence-table-scroll" role="region" aria-label="Findings in the current selection" tabindex="0"><table class="exec-evidence-table"><thead><tr><th scope="col">Finding</th><th scope="col">Workstream</th><th scope="col">Severity</th><th scope="col">Linked records</th></tr></thead><tbody>${current.priorityFindings.slice(0,60).map(finding=>`<tr><td><button type="button" class="exec-finding-open" data-exec-finding="${e(finding.id)}">${e(finding.title)}</button></td><td>${e(finding.category)}</td><td>${badge(finding.severity)}</td><td>${number(finding.events.length)}</td></tr>`).join('')}</tbody></table></div>${current.findings.length>60?'<p>Showing the first 60 ranked findings. Narrow the filters or export the brief for all findings.</p>':''}`:'<p>No findings match the current selection. Evidence may still be present; no matched finding does not establish endpoint health.</p>'}<h3>Evidence records · ${number(total)}</h3><p role="status">${total?`Showing ${number(start+1)}–${number(start+records.length)} of ${number(total)} records`:'No evidence matches the current selection.'}</p><div class="exec-evidence-table-scroll" role="region" aria-label="Imported or demonstration evidence records" tabindex="0"><table class="exec-evidence-table"><thead><tr><th scope="col">Time · UTC or labelled local clock</th><th scope="col">Source / line</th><th scope="col">Stage</th><th scope="col">Codes</th><th scope="col">Evidence</th></tr></thead><tbody>${records.map(record=>`<tr><td>${e(evidenceTime(record))}</td><td>${e(record.source)}${record.line!==null?':'+e(record.line):''}</td><td>${e(record.stage)}</td><td>${e(record.codes.join(', '))}</td><td><pre>${e(record.message)}</pre></td></tr>`).join('')}</tbody></table></div><div class="exec-evidence-pagination"><button type="button" class="exec-btn" id="exec-evidence-prev" ${state.evidencePage===0?'disabled':''}>Previous records</button><span>Page ${number(state.evidencePage+1)} of ${number(pages)}</span><button type="button" class="exec-btn" id="exec-evidence-next" ${state.evidencePage>=pages-1?'disabled':''}>Next records</button></div></div>`;
  }
  function renderGauges(data){
    const el=$('exec-gauges');
    if(!el)return;
    const totalSources=data.sourceCoverage.length;
    const observedSources=data.sourceCoverage.filter(s=>s.eventCount>0).length;
    const covPct=Math.min(100,Math.round(observedSources/(totalSources||1)*100));
    const totalEvents=data.events.length;
    const timedEvents=data.events.filter(e=>e.timestamp).length;
    const timedPct=Math.min(100,Math.round(timedEvents/(totalEvents||1)*100));
    const totalFindings=data.metrics.findingsCount;
    const highConf=data.findings.filter(f=>['high','medium'].includes(String(f.confidence).toLowerCase())).length;
    const confPct=Math.min(100,Math.round(highConf/(totalFindings||1)*100));
    const gaugeItem=(label,pct,color,desc,hint)=>{
      const circ=113;
      const offset=Math.max(0,Math.round(circ*(1-(pct||0)/100)));
      return `<article class="exec-gauge-card"><div class="exec-gauge-top"><svg viewBox="0 0 100 58" class="exec-gauge-svg" role="img" aria-label="${e(label)}: ${pct===null?'not available':pct+'%'}; ${e(desc)}"><path class="gauge-track" d="M 14 52 A 36 36 0 0 1 86 52" fill="none" stroke-width="8"/><path class="gauge-fill" d="M 14 52 A 36 36 0 0 1 86 52" fill="none" stroke="${color}" stroke-width="8" stroke-linecap="round" stroke-dasharray="${circ}" stroke-dashoffset="${offset}"/><text x="50" y="48" text-anchor="middle" class="exec-gauge-val">${pct===null?'—':pct+'%'}</text></svg><div class="exec-gauge-meta"><strong class="exec-gauge-title">${e(label)}</strong><span class="exec-gauge-desc">${e(desc)}</span></div></div><p class="exec-gauge-hint">${e(hint)}</p></article>`;
    };
    el.innerHTML=[
      gaugeItem('Listed sources with records',totalSources?covPct:null,'#087f7c',`${observedSources} / ${totalSources} sources active`,'Inventory presence only; collection completeness is unknown'),
      gaugeItem('Timed UTC evidence',totalEvents?timedPct:null,'#4779c8',`${timedEvents} / ${totalEvents} records timed`,'Records eligible for chronological correlation'),
      gaugeItem('Reported confidence',totalFindings?confPct:null,'#51a99c',`${highConf} / ${totalFindings} findings rated high or medium`,'Supplied finding ratings; not independent validation or a health score')
    ].join('');
  }
  function renderTreemap(data){
    const el=$('exec-source-treemap');
    if(!el)return;
    const observed=data.sourceCoverage.filter(s=>s.eventCount>0);
    const total=observed.reduce((sum,s)=>sum+s.eventCount,0);
    if(!total){el.innerHTML='';return;}
    const colors=['#087f7c','#4779c8','#51a99c','#d3a34b','#7a69a5','#6d91c1','#c3646d','#8190a2'];
    el.innerHTML=`<div class="exec-treemap-label"><span>SOURCE RECORD DISTRIBUTION</span><strong>${observed.length} ACTIVE SOURCES · ${total} EVENTS</strong></div><div class="exec-treemap-track" role="img" aria-label="${e(observed.map(s=>`${s.name}: ${s.eventCount} records`).join('; '))}">${observed.map((s,idx)=>{
      const w=(s.eventCount/total*100).toFixed(3);
      const color=colors[idx%colors.length];
      return `<span class="exec-treemap-bar" style="flex:${s.eventCount} 1 0;min-width:0;background:${color}" title="${e(s.name)}: ${s.eventCount} records (${w}%)">${parseFloat(w)>12?`<small>${e(s.name.slice(0,16))}</small>`:''}</span>`;
    }).join('')}</div>`;
  }
  function renderDensityHeatmap(data){
    const el=$('exec-density-heatmap');
    if(!el)return;
    const buckets=chartBuckets(data.timeline,24);
    if(!buckets.length){el.innerHTML='';return;}
    const max=Math.max(1,...buckets.map(b=>b.events));
    const colors=['#eef2f7','#a4ded6','#52bdb1','#148f9b','#087f7c'];
    el.innerHTML=`<div class="exec-heatmap-row"><span class="exec-heatmap-title">Activity density:</span><div class="exec-heatmap-cells" role="img" aria-label="${e(buckets.map(b=>`${b.label}: ${b.events} records`).join('; '))}">${buckets.map(b=>{
      const idx=b.events===0?0:Math.min(4,Math.ceil((b.events/max)*4));
      return `<span class="exec-heatmap-cell" style="background:${colors[idx]}" title="${e(b.label)}: ${b.events} records"></span>`;
    }).join('')}</div><span class="exec-heatmap-legend">Peak: ${max}</span></div>`;
  }
  function resetFilters(){clearTimeout(searchTimer);state.evidencePage=0;state.filters={category:'all',severity:'all',from:'',to:'',query:''};for(const [key,id] of Object.entries({category:'exec-category',severity:'exec-severity',from:'exec-from',to:'exec-to',query:'exec-search'}))$(id).value=state.filters[key];}
  function render(){
    current=buildDashboard(reports(),state.filters);
    const metrics=current.metrics;
    const artifacts=artifactInvestigationHTML(current.events,state.archives,{findings:current.priorityFindings});
    $('exec-artifact-panel').hidden=!artifacts;$('exec-artifact-panel').innerHTML=artifacts;
    renderEvidence();
    renderGauges(current);renderTreemap(current);renderDensityHeatmap(current);
    $('exec-problem-analysis').innerHTML=executiveSummaryHTML(buildExecutiveSummary(current,state.archives),{interactive:true});
    $('exec-knowledge-list').innerHTML=knowledgeBaseHTML(current,$('exec-knowledge-query').value);
    const imported=state.mode==='imported';
    $('exec-archive-coverage').hidden=!state.archives.length;
    $('exec-archive-coverage').innerHTML=archiveCoverageHTML(state.archives,{sample:!imported});
    $('exec-data-banner').classList.toggle('imported',imported&&!current.coverage.syntheticReports);
    $('exec-data-label').textContent=imported?(current.coverage.syntheticReports?'IMPORTED SAMPLE / MIXED DATA':'LOCAL REPORT DATA'):'DEMONSTRATION DATA';
    $('exec-data-note').textContent=imported?`${reports().length} report${reports().length===1?'':'s'} in this browser session. No endpoint or tenant connection.`:'Four sample investigations. No device or tenant is connected.';
    $('sidebar-data-mode').textContent=imported?'Imported reports stay in browser memory. No endpoint is connected.':'Synthetic records only. No endpoint is connected.';
    $('exec-kpis').innerHTML=[['Diagnostic reports',metrics.reportsCount,'Reports contributing to this selection','▤','M2,14 C12,8 24,14 46,6',metrics.reportsCount>0?'Session scope':'No reports','neutral'],['Priority findings',metrics.priorityCount,'Reported as error, high or critical','◇','M2,14 C14,12 24,6 46,4',metrics.priorityCount>0?'Review required':'No priority findings',metrics.priorityCount>0?'alert':'success'],['Evidence records',metrics.eventsCount,'Individual records in the current view','⌁','M2,14 C14,8 26,12 46,3',metrics.eventsCount>0?'Records in scope':'No records','info'],['Workstreams',metrics.categoriesCount,'Diagnostic categories represented','▦','M2,11 C12,5 24,10 46,7',`${metrics.categoriesCount} active`,'accent']].map(([label,value,hint,mark,sparkPath,badgeText,badgeType],index)=>`<article class="exec-kpi ${index===1&&(metrics.priorityCount>0)?'alert':''}"><span class="exec-kpi-icon ${index===1?'priority':''}" aria-hidden="true">${mark}</span><div class="exec-kpi-label">${label}</div><div class="exec-kpi-main"><strong class="exec-kpi-value">${number(value)}</strong><span class="exec-kpi-badge ${badgeType}">${badgeText}</span></div>${index===2&&current.timeline.length?`<svg class="exec-kpi-sparkline" viewBox="0 0 48 16" role="img" aria-label="Timed evidence activity across UTC buckets"><polyline points="${current.timeline.map((bucket,i)=>`${current.timeline.length===1?24:i/(current.timeline.length-1)*48},${15-bucket.events/Math.max(1,...current.timeline.map(b=>b.events))*14}`).join(' ')}" fill="none" stroke="currentColor" stroke-width="2"/></svg>`:''}<p class="exec-kpi-foot">${hint}</p></article>`).join('');
    const dated=current.events.filter(event=>event.timestamp).map(event=>event.timestamp).sort();
    $('exec-window').textContent=dated.length?`${dated[0].slice(0,10)}${last(dated).slice(0,10)!==dated[0].slice(0,10)?' – '+last(dated).slice(0,10):''} · UTC`:'NO TIMED EVIDENCE';
    $('exec-timeline').innerHTML=timelineSVG(current);
    const total=metrics.findingsCount;
    $('exec-severity-chart').innerHTML=`<div class="exec-donut-layout"><div class="exec-donut" style="background:${severityGradient(current.severityCounts)}" role="img" aria-label="${total} findings: ${current.severityCounts.error} error, ${current.severityCounts.warning} warning, ${current.severityCounts.info} informational."><div class="exec-donut-center"><strong>${number(total)}</strong><span>recorded findings</span></div></div><div class="exec-severity-list">${['error','warning','info'].map(severity=>`<button type="button" class="exec-severity-item ${state.filters.severity===severity?'active':''}" data-exec-severity="${severity}" aria-label="Filter ${e(SHORT[severity])} findings: ${current.severityCounts[severity]} of ${total} visible findings" aria-pressed="${state.filters.severity===severity}"><i class="exec-dot" aria-hidden="true" style="background:${COLORS[severity]}"></i><span>${SHORT[severity]}<small>${e(LABELS[severity])}</small></span><strong>${current.severityCounts[severity]}</strong><em>${total?Math.round(current.severityCounts[severity]/total*100):0}%</em></button>`).join('')}</div></div><p class="exec-chart-note">Percentages refer to visible findings, not devices or fleet health.</p>`;
    const maximum=Math.max(1,...current.domainCounts.map(domain=>domain.total));
    $('exec-domain-chart').innerHTML=current.domainCounts.filter(domain=>domain.total||domain.eventCount||state.filters.category==='all').map(domain=>`<div class="exec-domain-row"><button class="exec-domain-label ${state.filters.category===domain.category?'active':''}" type="button" data-exec-category="${e(domain.category)}" aria-pressed="${state.filters.category===domain.category}" aria-label="${e(domain.category)}: ${domain.total} findings">${e(domain.category)}</button><div class="exec-stack-track" role="img" aria-label="${e(domain.category)}: ${domain.error} errors, ${domain.warning} warnings, ${domain.info} informational">${['error','warning','info'].map(severity=>`<span class="exec-stack-segment" style="width:${domain[severity]/maximum*100}%;background:${COLORS[severity]}"></span>`).join('')}</div><strong class="exec-domain-total">${domain.total}</strong></div>`).join('')+'<div class="exec-chart-legend">'+['error','warning','info'].map(severity=>`<span class="exec-legend-item"><i class="exec-dot" aria-hidden="true" style="background:${COLORS[severity]}"></i>${SHORT[severity]}</span>`).join('')+'</div><p class="exec-chart-note">Bars compare recorded finding counts. A workstream with no findings is not automatically healthy.</p>';
    const stages=current.stageCounts.filter(stage=>stage.stage!=='unknown'||stage.count);
    const stageMax=Math.max(1,...stages.map(stage=>stage.count));
    $('exec-stage-chart').innerHTML=`<div class="exec-stage-grid" style="--stage-columns:${stages.length}">${stages.map((stage,index)=>`<div class="exec-stage-item"><span class="exec-stage-label">${index+1}. ${e(stage.stage)}</span><strong class="exec-stage-count">${number(stage.count)}</strong><div class="exec-stage-meter" role="img" aria-label="${e(stage.stage)}: ${stage.count} observed records"><span aria-hidden="true" style="width:${stage.count/stageMax*100}%"></span></div><span class="exec-stage-pct">${Math.round(stage.count/stageMax*100)}% of peak stage count</span></div>`).join('')}</div><p class="exec-stage-note">Stage counts describe observations in logs. They are not success rates or a conversion funnel.</p><div class="exec-lifecycle-note"><span>◈</span><div><strong>Evidence, then action</strong><p>Trace assignment → policy → execution → result. Verify the earliest supported failure before proposing a change.</p></div></div>`;
    $('exec-priority-count').textContent=`${metrics.findingsCount} FINDING${metrics.findingsCount===1?'':'S'}`;
    $('exec-priority-table').innerHTML=current.priorityFindings.length?`<table><thead><tr><th>FINDING / REVIEW ITEM</th><th>WORKSTREAM</th><th>SEVERITY</th><th>EVIDENCE</th></tr></thead><tbody>${current.priorityFindings.slice(0,60).map(finding=>`<tr><td><button type="button" class="exec-finding-open" data-exec-finding="${e(finding.id)}">${e(finding.title)} <span aria-hidden="true">↗</span></button><p class="exec-row-summary">${e(finding.summary.slice(0,125))}${finding.summary.length>125?'…':''}</p></td><td><span class="exec-category-label">${e(finding.category)}</span></td><td>${badge(finding.severity)}</td><td><span class="exec-evidence-count">${finding.events.length}</span></td></tr>`).join('')}</tbody></table>${current.priorityFindings.length>60?'<p class="exec-chart-note">Showing 60 ranked findings. Narrow the filters or export the brief for the complete selection.</p>':''}`:'<div class="exec-empty-state">No findings in the current selection.<span>Clear the filters or import more evidence. This does not establish endpoint health.</span></div>';
    const observed=current.sourceCoverage.filter(source=>source.eventCount>0).length;
    $('exec-source-count').textContent=`${observed} WITH RECORDS`;
    $('exec-source-list').innerHTML=current.sourceCoverage.slice(0,40).map(source=>`<div class="exec-source-row"><span class="exec-source-records">${number(source.eventCount)}</span><div><strong>${e(source.name)}</strong><small>${source.eventCount?'Observed records':source.available===false?'Marked unavailable in source inventory':'Listed only · no records in this view'}</small></div><span class="exec-source-status ${source.eventCount?'observed':source.available===false?'missing':''}" aria-label="${source.eventCount?'Records observed':source.available===false?'Not included':'Listed only'}">${source.eventCount?'✓':source.available===false?'!':'—'}</span></div>`).join('')||'<div class="exec-empty-state">No source inventory for this selection.</div>';
    const notes=uniqueMessages([...current.notes,...reportWarnings(current.reports)]);
    $('exec-note-count').textContent=`(${notes.length})`;
    $('exec-notes').innerHTML='<ul>'+notes.slice(0,40).map(note=>`<li>${e(note)}</li>`).join('')+'</ul>';
    $('exec-export').disabled=state.busy||(!reports().length&&!state.archives.length);
  }
  function updateFilter(key,value){state.evidencePage=0;state.filters[key]=value;if(key==='category')$('exec-category').value=value;if(key==='severity')$('exec-severity').value=value;render();}
  function openFinding(id,trigger){
    detailTrigger=trigger || document.activeElement;
    const finding=current.priorityFindings.find(item=>item.id===id);if(!finding)return;
    $('exec-dialog-domain').textContent=finding.category.toUpperCase();$('exec-dialog-title').textContent=finding.title;
    $('exec-detail-content').innerHTML=`<button type="button" class="exec-btn" data-exec-investigate-report="${e(finding.reportId)}" data-exec-investigate-finding="${e(finding.id)}">⌁ Open in guided investigation</button><div class="exec-detail-meta">${badge(finding.severity)}<span class="exec-report-chip">${e(finding.reportLabel)}</span><span>Confidence: ${e(finding.confidence)}</span></div><section class="exec-detail-block"><div class="exec-detail-label">WHAT THE EVIDENCE SHOWS</div><p>${e(finding.summary||'No summary was supplied.')}</p></section><section class="exec-detail-block cause"><div class="exec-detail-label">LIKELY CAUSE / WHAT TO CONFIRM</div><p>${e(finding.rootCause||'A root cause was not established in this report.')}</p></section>${artifactInvestigationHTML(finding.events,state.archives)}<section class="exec-detail-block"><div class="exec-detail-label">VERIFICATION CHECKS</div><ol class="exec-suggestion-list">${finding.checks.map(check=>`<li>${e(check)}</li>`).join('')||'<li>No verification checks were supplied.</li>'}</ol></section><section class="exec-detail-block"><div class="exec-detail-label">SUGGESTED RESOLUTION · NOT EXECUTED</div><ol class="exec-suggestion-list">${finding.recommendations.map(item=>`<li>${e(item)}</li>`).join('')||'<li>No resolution was supplied. Review the original report.</li>'}</ol></section><section class="exec-detail-block"><div class="exec-detail-label">LINKED EVIDENCE · ${finding.events.length} RECORDS IN THE CURRENT SCOPE</div>${finding.events.slice(0,40).map(event=>`<article class="exec-evidence-record"><div class="exec-evidence-meta"><strong>${e(event.source)}${event.line!==null?':'+event.line:''}</strong><span>${e(evidenceTime(event))}</span></div><p class="exec-evidence-stage">${e(event.stage)} · ${e(event.context)}${event.codes.length?' · '+e(event.codes.join(', ')):''}</p><pre>${e(event.message)}</pre></article>`).join('')||'<p>No matching evidence records are available in the current filter. Review the original report and its import notices.</p>'}${finding.events.length>40?'<p>Showing the first 40 linked records. The original report contains the full evidence.</p>':''}</section><p class="exec-notice">Review one approved remediation at a time. This dashboard applies no changes and cannot confirm that an imported endpoint is healthy.</p>`;
    showDetail();
  }
  async function importFiles(files){
    if(!files.length||state.busy)return;
    const localUtcOffset=$('exec-local-offset').value.trim();
    if(localUtcOffset&&!/^[+-](?:(?:0\d|1[0-3]):[0-5]\d|14:00)$/.test(localUtcOffset)){showStatus('Enter the verified source UTC offset as ±HH:MM, such as +02:00, or leave it blank. Your dataset is unchanged.',true);return;}
    state.busy=true;$('exec-import').disabled=true;$('workflow-import').disabled=true;$('workflow-dataset').disabled=true;$('exec-dataset').disabled=true;$('exec-export').disabled=true;showStatus('Reading logs and analyzing evidence locally in this browser…');
    try{
      const {reports:imported,errors,notices,archives=[]}=await readFiles(files,{localUtcOffset});
      state.archives=archives;
      if(imported.length){state.imported=[...new Map(imported.map(report=>[report.id,report])).values()];state.mode='imported';resetFilters();syncWorkflow();}
      render();
      const eventCount=imported.reduce((sum,report)=>sum+report.events.length,0),findingCount=imported.reduce((sum,report)=>sum+report.findings.length,0);
      const message=imported.length?`${number(eventCount)} evidence records and ${number(findingCount)} findings loaded in ${state.imported.length} report${state.imported.length===1?'':'s'}. Files stay in this browser session; nothing is uploaded.`:'No readable logs or valid reports were loaded. Your current dataset is unchanged.';
      showStatus([message,archives.length?'CAB file coverage is listed below, including skipped or failed entries.':'',...notices,...errors].filter(Boolean).join(' '),errors.length>0||archives.some(archive=>!archive.complete));
    }catch(error){showStatus(`${sanitizeText(error.message)} Your current dataset is unchanged.`,true);
    }finally{state.busy=false;$('exec-import').disabled=false;$('workflow-import').disabled=false;$('workflow-dataset').disabled=false;$('exec-dataset').disabled=false;$('exec-export').disabled=!reports().length&&!state.archives.length;$('exec-file-input').value='';}
  }
  $('exec-knowledge-query').addEventListener('input',event=>{$('exec-knowledge-list').innerHTML=knowledgeBaseHTML(current,event.target.value);});
  $('exec-run-validation').addEventListener('click',()=>{
    const results=runValidationCases(),passed=results.filter(result=>result.passed).length;
    const status=$('exec-validation-status');status.hidden=false;status.classList.toggle('error',passed!==results.length);
    status.textContent=`${passed} / ${results.length} bundled interpretation checks passed. These checks use synthetic examples only; imported evidence and endpoint settings are unchanged.`;
    $('exec-validation-results').hidden=false;
    $('exec-validation-results').innerHTML=`<table><thead><tr><th>Bundled use case</th><th>Workstream</th><th>Result</th><th>Observed interpretation</th></tr></thead><tbody>${results.map(result=>`<tr><td>${e(result.name)}</td><td>${e(result.category)}</td><td class="${result.passed?'exec-validation-pass':'exec-validation-fail'}">${result.passed?'PASS':'FAIL'}</td><td>${e(result.observed.join('; ') || 'No failure finding')}</td></tr>`).join('')}</tbody></table>`;
  });
  $('exec-import').addEventListener('click',()=>$('exec-file-input').click());
  $('workflow-import').addEventListener('click',()=>$('exec-file-input').click());
  $('exec-investigate').addEventListener('click',()=>setView('workflow'));
  $('exec-file-input').addEventListener('change',event=>importFiles([...event.target.files]));
  $('exec-dataset').addEventListener('change',event=>changeDataset(event.target.value));
  $('workflow-dataset').addEventListener('change',event=>changeDataset(event.target.value));
  $('exec-category').addEventListener('change',event=>updateFilter('category',event.target.value));
  $('exec-severity').addEventListener('change',event=>updateFilter('severity',event.target.value));
  function changeDates(){const from=$('exec-from').value,to=$('exec-to').value;if(from&&to&&from>to){showStatus('The start date must be on or before the end date. The previous filter remains active.',true);return;}state.evidencePage=0;state.filters.from=from;state.filters.to=to;$('exec-import-status').hidden=true;render();}
  $('exec-from').addEventListener('change',changeDates);$('exec-to').addEventListener('change',changeDates);
  $('exec-search').addEventListener('input',event=>{const query=event.target.value;clearTimeout(searchTimer);searchTimer=setTimeout(()=>updateFilter('query',query),200);});
  $('exec-reset').addEventListener('click',()=>{clearTimeout(searchTimer);resetFilters();$('exec-import-status').hidden=true;render();});
  $('exec-all-domains').addEventListener('click',()=>updateFilter('category','all'));
  $('exec-detail').addEventListener('keydown',event=>{if(event.key==='Escape' && typeof $('exec-detail').close!=='function') closeDetail();});
  $('exec-close-detail').addEventListener('click',()=>closeDetail());
  $('exec-detail').addEventListener('click',event=>{if(event.target===$('exec-detail')){const bounds=$('exec-detail').getBoundingClientRect();if(event.clientX<bounds.left||event.clientX>bounds.right||event.clientY<bounds.top||event.clientY>bounds.bottom)closeDetail();}});
  document.addEventListener('click',event=>{const button=event.target.closest('button');if(!button||button.disabled)return;if(button.id==='exec-evidence-prev'||button.id==='exec-evidence-next'){state.evidencePage+=button.id==='exec-evidence-next'?1:-1;renderEvidence();}else if(button.dataset.execInvestigateReport)openInvestigation(button.dataset.execInvestigateReport,button.dataset.execInvestigateFinding);else if(button.dataset.execView)setView(button.dataset.execView);else if(button.dataset.execCategory)updateFilter('category',button.dataset.execCategory);else if(button.dataset.execSeverity)updateFilter('severity',state.filters.severity===button.dataset.execSeverity?'all':button.dataset.execSeverity);else if(button.dataset.execFinding)openFinding(button.dataset.execFinding,button);});
  $('exec-export').addEventListener('click',()=>{try{const blob=new Blob([executiveBrief(current,datasetLabel(),state.archives)],{type:'text/html;charset=utf-8'});downloadBlob(blob,`windows-diagnostics-executive-brief${state.mode==='sample'?'-sample':''}.html`);showStatus('Executive brief download started. Review redaction and scope before sharing. No endpoint changes were applied.');}catch(error){showStatus(`Export could not start: ${sanitizeText(error.message)}`,true);}});
  function applyTheme(theme){
    const isDark=theme==='dark';
    if(typeof document!=='undefined'&&document.body){
      document.body.classList.toggle('dark-theme',isDark);
      const icon=$('exec-theme-icon'),label=$('exec-theme-label');
      if(icon)icon.textContent=isDark?'☀️':'🌙';
      if(label)label.textContent=isDark?'Light':'Dark';
      const toggle=$('exec-theme-toggle');if(toggle)toggle.setAttribute('aria-pressed',String(isDark));
    }
    try{localStorage.setItem('techlab-theme',theme);}catch{}
  }
  const themeToggle=$('exec-theme-toggle');
  if(themeToggle){
    let currentTheme='light';
    try{currentTheme=localStorage.getItem('techlab-theme')||(window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light');}catch{}
    applyTheme(currentTheme);
    themeToggle.addEventListener('click',()=>{
      const next=document.body.classList.contains('dark-theme')?'light':'dark';
      applyTheme(next);
    });
  }
  setView(document.defaultView?.location?.hash==='#evidence'?'evidence':'dashboard');render();
  return {state,workflow,importFiles,setView};
}

if(typeof document!=='undefined')initExecutive();
