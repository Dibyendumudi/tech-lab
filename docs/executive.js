import { scenarios } from './scenarios.js';
import { escapeHTML as e } from './app.js';
import { CATEGORIES, sampleReports, parseReport, buildDashboard, sanitizeText } from './analytics.js';
import { readDiagnosticFiles } from './importer.js';

const COLORS = { error: '#bc6871', warning: '#d6ab61', info: '#769ab7' };
const LABELS = { error: 'Error / high / critical', warning: 'Warning / medium', info: 'Informational / low' };
const SHORT = { error: 'Error', warning: 'Warning', info: 'Info' };
const number = value => Number(value || 0).toLocaleString('en-IN');
const formatTime = value => value ? new Intl.DateTimeFormat('en-GB', { day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'UTC' }).format(new Date(value)) + ' UTC' : 'Time unspecified';
const badge = severity => `<span class="exec-severity-badge ${e(severity)}">${e(SHORT[severity] || 'Info')}</span>`;

export function chartBuckets(timeline, maximum = 30) {
  if (timeline.length <= maximum) return timeline;
  const size = Math.ceil(timeline.length / maximum), result = [];
  for (let index = 0; index < timeline.length; index += size) {
    const group = timeline.slice(index, index + size);
    result.push({key:group[0].key,label:`${group[0].label} – ${group.at(-1).label}`,events:group.reduce((sum,item)=>sum+item.events,0),results:group.reduce((sum,item)=>sum+item.results,0)});
  }
  return result;
}

export function timelineSVG(data) {
  const values = chartBuckets(data.timeline);
  if (!values.length) return '<div class="exec-empty-state">No timestamped evidence in this selection.<span>Unspecified or local timestamps are kept out of the UTC timeline.</span></div>';
  const width=640, height=200, left=36, right=18, top=15, bottom=32;
  const plotWidth=width-left-right, plotHeight=height-top-bottom;
  const maximum = Math.max(4, Math.ceil(Math.max(...values.map(value=>value.events))/4)*4);
  const firstTime=Date.parse(values[0].key), lastTime=Date.parse(values.at(-1).key);
  const x = index => left + (firstTime===lastTime ? plotWidth/2 : (Date.parse(values[index].key)-firstTime)/(lastTime-firstTime)*plotWidth);
  const y = value => top + plotHeight - value/maximum*plotHeight;
  const points = key => values.map((value,index)=>`${x(index)},${y(value[key])}`).join(' ');
  const area = `M${x(0)},${y(0)} L${values.map((value,index)=>`${x(index)},${y(value.events)}`).join(' L')} L${x(values.length-1)},${y(0)} Z`;
  const grid = Array.from({length:5},(_,index)=>{const value=maximum*index/4;return `<line x1="${left}" y1="${y(value)}" x2="${width-right}" y2="${y(value)}" stroke="#e9eff3" stroke-dasharray="3 4"/><text class="exec-axis-label" x="${left-10}" y="${y(value)+3}" text-anchor="end">${value}</text>`;}).join('');
  const tickEvery = Math.max(1,Math.ceil(values.length/5));
  const labels = values.map((value,index)=>{
    if(index%tickEvery && index!==values.length-1)return '';
    const label = data.timelineGranularity==='month' ? value.key.slice(0,7) : data.timelineGranularity==='hour' && data.timeline.length<=30 ? `${values[0].key.slice(0,10)!==values.at(-1).key.slice(0,10)?value.key.slice(8,10)+' / ':''}${value.key.slice(11,16)}` : value.key.slice(5,10);
    return `<text class="exec-axis-label" x="${x(index)}" y="${height-9}" text-anchor="middle">${e(label)}</text>`;
  }).join('');
  return `<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="${data.metrics.eventsCount} recorded events. Teal shows all records and the lighter line shows result-stage records. Evidence timestamps are UTC."><defs><linearGradient id="exec-evidence-fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#169aa1" stop-opacity=".15"/><stop offset="100%" stop-color="#169aa1" stop-opacity=".015"/></linearGradient></defs>${grid}<path d="${area}" fill="url(#exec-evidence-fill)"/><polyline points="${points('results')}" fill="none" stroke="#afcfcc" stroke-width="2.5" stroke-dasharray="4 3"/><polyline points="${points('events')}" fill="none" stroke="#148f9b" stroke-width="2.5" stroke-linejoin="round"/>${values.map((value,index)=>`<circle cx="${x(index)}" cy="${y(value.events)}" r="4" fill="white" stroke="#148f9b" stroke-width="2"><title>${e(value.label)} UTC: ${value.events} evidence records, ${value.results} result-stage records</title></circle>`).join('')}${labels}</svg><details class="exec-chart-data"><summary>View chart data${data.timeline.length>30 ? ' · adjacent buckets grouped for display' : ''}</summary><table><thead><tr><th>Evidence bucket · UTC</th><th>Records</th><th>Result stage</th></tr></thead><tbody>${values.map(value=>`<tr><td>${e(value.label)}</td><td>${value.events}</td><td>${value.results}</td></tr>`).join('')}</tbody></table></details>`;
}

export function severityGradient(counts) {
  const total=counts.error+counts.warning+counts.info;
  if(!total)return '#e9eff3';
  let start=0;
  return `conic-gradient(${['error','warning','info'].map(severity=>{const end=start+counts[severity]/total*100;const stop=`${COLORS[severity]} ${start}% ${end}%`;start=end;return stop;}).join(',')})`;
}

export function executiveBrief(data, datasetLabel) {
  const made = new Intl.DateTimeFormat('en-IN',{dateStyle:'medium',timeStyle:'short',timeZone:'Asia/Kolkata'}).format(new Date());
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Windows Diagnostics · Executive brief</title><style>body{font:14px/1.65 'Segoe UI',system-ui,sans-serif;color:#21374c;background:#f4f7fa;margin:0}header{padding:30px max(24px,calc((100vw - 1040px)/2));background:#10243a;color:white}header small{color:#a3d9cb}h1{font-size:30px;margin:9px 0}main{max-width:1040px;margin:auto;padding:24px}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.card,section{background:white;border:1px solid #dfe8ef;border-radius:10px;padding:21px;margin-bottom:16px}.card strong{font-size:30px;display:block;color:#087f7c}.card span,.meta{font-size:11px;color:#6b7e8c}h2{font-size:19px}h3{font-size:14px}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:12px;border-bottom:1px solid #e5edf3;font-size:12px;vertical-align:top}li{margin-bottom:7px}svg{max-height:260px;width:100%}.exec-axis-label{font:10px 'Segoe UI',sans-serif;fill:#8194a3}.exec-chart-data{font-size:11px}.note{border-left:4px solid #cfac68}.finding{break-inside:avoid}footer{font-size:11px;color:#718390}@media print{body{background:white}section{break-inside:avoid}.cards{grid-template-columns:repeat(4,1fr)}}@media(max-width:650px){.cards{grid-template-columns:repeat(2,1fr)}} </style></head><body><header><small>WINDOWS DIAGNOSTICS / MANAGED BY DIBYENDU</small><h1>Executive diagnostics brief</h1><p>${e(datasetLabel)} · Generated ${e(made)} IST</p></header><main><section class="note"><strong>${data.coverage.syntheticReports ? 'Includes synthetic demonstration records' : 'Imported report output · no live endpoint connection'}</strong><p>Counts summarize supplied diagnostic reports, rather than fleet size, compliance or confirmed device health. Findings describe recorded observations and hypotheses; no remediation is performed by this dashboard. Reports remain local to the browser session.</p><p class="meta">Filters: ${e(data.filters.category)} workstreams · ${e(data.filters.severity)} severities · ${e(data.filters.from || 'all dates')} to ${e(data.filters.to || 'all dates')} UTC · Search: ${e(data.filters.query || 'none')}.</p></section><div class="cards">${[['Diagnostic reports',data.metrics.reportsCount],['Priority findings',data.metrics.priorityCount],['Evidence records',data.metrics.eventsCount],['Workstreams',data.metrics.categoriesCount]].map(([label,value])=>`<div class="card"><span>${label}</span><strong>${number(value)}</strong></div>`).join('')}</div><section><h2>Findings by workstream</h2><table><thead><tr><th>Workstream</th><th>Error / high / critical</th><th>Warning / medium</th><th>Informational / low</th><th>Evidence records</th></tr></thead><tbody>${data.domainCounts.filter(domain=>domain.total||domain.eventCount).map(domain=>`<tr><td>${e(domain.category)}</td><td>${domain.error}</td><td>${domain.warning}</td><td>${domain.info}</td><td>${number(domain.eventCount)}</td></tr>`).join('')}</tbody></table></section><section><h2>Evidence activity · UTC</h2>${timelineSVG(data)}<p class="meta">Result-stage records can describe success, failure or an unknown outcome.</p></section><section><h2>Review priorities</h2>${data.priorityFindings.map(finding=>`<article class="finding"><h3>${e(finding.title)}</h3><p class="meta">${e(finding.category)} · ${e(LABELS[finding.severity])} · Confidence: ${e(finding.confidence)} · ${e(finding.reportLabel)}</p><p>${e(finding.summary)}</p><p><strong>Likely cause / what to confirm:</strong> ${e(finding.rootCause || 'Not established in the supplied report.')}</p><h3>Verification checks</h3><ol>${finding.checks.map(check=>`<li>${e(check)}</li>`).join('')}</ol><h3>Suggested resolution · not executed</h3><ol>${finding.recommendations.map(item=>`<li>${e(item)}</li>`).join('')}</ol><p class="meta">${finding.evidenceIds.length} linked evidence references. Full record detail remains in the original diagnostic report.</p></article>`).join('') || '<p>No findings in this selection. This does not establish endpoint health.</p>'}</section><section><h2>Scope and limitations</h2><ul>${[...data.notes,...data.reports.flatMap(report=>report.warnings)].map(note=>`<li>${e(note)}</li>`).join('')}</ul><p>Redaction is best-effort. Review this brief before sharing. A source inventory does not establish complete log coverage.</p></section><footer>Windows Diagnostics · Managed by Dibyendu · Suggestions only; no endpoint actions.</footer></main></body></html>`;
}

export function createExecutiveState() {
  return {mode:'sample',sample:sampleReports(scenarios),imported:[],filters:{category:'all',severity:'all',from:'',to:'',query:''},busy:false};
}

function init() {
  const state=createExecutiveState();
  const $=id=>document.getElementById(id);
  const reports=()=>state.mode==='sample'?state.sample:state.imported;
  let current=buildDashboard(reports());
  let searchTimer;
  function showStatus(message,error=false){const status=$('exec-import-status');status.textContent=message;status.classList.toggle('error',error);status.hidden=false;}
  function datasetLabel(){return state.mode==='sample'?'Demonstration dataset':current.coverage.syntheticReports?'Imported sample / mixed report data':'Imported diagnostic reports';}
  function setView(view){const dashboard=view==='dashboard';$('executive-view').hidden=!dashboard;$('workflow-view').hidden=dashboard;$('scenario-group').hidden=dashboard;document.querySelectorAll('[data-exec-view]').forEach(button=>{const active=button.dataset.execView===view;button.classList.toggle('active',active);if(active)button.setAttribute('aria-current','page');else button.removeAttribute('aria-current');});}
  function resetFilters(){state.filters={category:'all',severity:'all',from:'',to:'',query:''};for(const [key,id] of Object.entries({category:'exec-category',severity:'exec-severity',from:'exec-from',to:'exec-to',query:'exec-search'}))$(id).value=state.filters[key];}
  function render(){
    current=buildDashboard(reports(),state.filters);
    const metrics=current.metrics;
    const imported=state.mode==='imported';
    $('exec-data-banner').classList.toggle('imported',imported&&!current.coverage.syntheticReports);
    $('exec-data-label').textContent=imported?(current.coverage.syntheticReports?'IMPORTED SAMPLE / MIXED DATA':'LOCAL REPORT DATA'):'DEMONSTRATION DATA';
    $('exec-data-note').textContent=imported?`${reports().length} report${reports().length===1?'':'s'} in this browser session. No endpoint or tenant connection.`:'Four sample investigations. No device or tenant is connected.';
    $('sidebar-data-mode').textContent=imported?'Imported reports stay in browser memory. No endpoint is connected.':'Synthetic records only. No endpoint is connected.';
    $('exec-kpis').innerHTML=[['Diagnostic reports',metrics.reportsCount,'Reports contributing to this selection','▤'],['Priority findings',metrics.priorityCount,'Reported as error, high or critical','◇'],['Evidence records',metrics.eventsCount,'Individual records in the current view','⌁'],['Workstreams',metrics.categoriesCount,'Diagnostic categories represented','▦']].map(([label,value,hint,mark],index)=>`<article class="exec-kpi"><span class="exec-kpi-icon ${index===1?'priority':''}" aria-hidden="true">${mark}</span><div class="exec-kpi-label">${label}</div><strong class="exec-kpi-value">${number(value)}</strong><p class="exec-kpi-foot">${hint}</p></article>`).join('');
    const dated=current.events.filter(event=>event.timestamp).map(event=>event.timestamp).sort();
    $('exec-window').textContent=dated.length?`${dated[0].slice(0,10)}${dated.at(-1).slice(0,10)!==dated[0].slice(0,10)?' – '+dated.at(-1).slice(0,10):''} · UTC`:'NO TIMED EVIDENCE';
    $('exec-timeline').innerHTML=timelineSVG(current);
    const total=metrics.findingsCount;
    $('exec-severity-chart').innerHTML=`<div class="exec-donut-layout"><div class="exec-donut" style="background:${severityGradient(current.severityCounts)}" role="img" aria-label="${total} findings: ${current.severityCounts.error} error, ${current.severityCounts.warning} warning, ${current.severityCounts.info} informational."><div class="exec-donut-center"><strong>${number(total)}</strong><span>recorded findings</span></div></div><div class="exec-severity-list">${['error','warning','info'].map(severity=>`<button type="button" class="exec-severity-item ${state.filters.severity===severity?'active':''}" data-exec-severity="${severity}" aria-pressed="${state.filters.severity===severity}"><i class="exec-dot" style="background:${COLORS[severity]}"></i><span>${SHORT[severity]}<small>${e(LABELS[severity])}</small></span><strong>${current.severityCounts[severity]}</strong><em>${total?Math.round(current.severityCounts[severity]/total*100):0}%</em></button>`).join('')}</div></div><p class="exec-chart-note">Percentages refer to visible findings, not devices or fleet health.</p>`;
    const maximum=Math.max(1,...current.domainCounts.map(domain=>domain.total));
    $('exec-domain-chart').innerHTML=current.domainCounts.filter(domain=>domain.total||domain.eventCount||state.filters.category==='all').map(domain=>`<div class="exec-domain-row"><button class="exec-domain-label ${state.filters.category===domain.category?'active':''}" type="button" data-exec-category="${e(domain.category)}" aria-label="${e(domain.category)}: ${domain.total} findings">${e(domain.category)}</button><div class="exec-stack-track" role="img" aria-label="${domain.error} errors, ${domain.warning} warnings, ${domain.info} informational">${['error','warning','info'].map(severity=>`<span class="exec-stack-segment" style="width:${domain[severity]/maximum*100}%;background:${COLORS[severity]}"></span>`).join('')}</div><strong class="exec-domain-total">${domain.total}</strong></div>`).join('')+'<div class="exec-chart-legend">'+['error','warning','info'].map(severity=>`<span class="exec-legend-item"><i class="exec-dot" style="background:${COLORS[severity]}"></i>${SHORT[severity]}</span>`).join('')+'</div><p class="exec-chart-note">Bars compare recorded finding counts. A workstream with no findings is not automatically healthy.</p>';
    const stages=current.stageCounts.filter(stage=>stage.stage!=='unknown'||stage.count);
    const stageMax=Math.max(1,...stages.map(stage=>stage.count));
    $('exec-stage-chart').innerHTML=`<div class="exec-stage-grid" style="--stage-columns:${stages.length}">${stages.map((stage,index)=>`<div class="exec-stage-item"><span class="exec-stage-label">${index+1}. ${e(stage.stage)}</span><strong class="exec-stage-count">${number(stage.count)}</strong><div class="exec-stage-meter"><span style="width:${stage.count/stageMax*100}%"></span></div></div>`).join('')}</div><p class="exec-stage-note">Stage counts describe observations in logs. They are not success rates or a conversion funnel.</p><div class="exec-lifecycle-note"><span>◈</span><div><strong>Evidence, then action</strong><p>Trace assignment → policy → execution → result. Verify the earliest supported failure before proposing a change.</p></div></div>`;
    $('exec-priority-count').textContent=`${metrics.findingsCount} FINDING${metrics.findingsCount===1?'':'S'}`;
    $('exec-priority-table').innerHTML=current.priorityFindings.length?`<table><thead><tr><th>FINDING / REVIEW ITEM</th><th>WORKSTREAM</th><th>SEVERITY</th><th>EVIDENCE</th></tr></thead><tbody>${current.priorityFindings.slice(0,60).map(finding=>`<tr><td><button type="button" class="exec-finding-open" data-exec-finding="${e(finding.id)}">${e(finding.title)} <span aria-hidden="true">↗</span></button><p class="exec-row-summary">${e(finding.summary.slice(0,125))}${finding.summary.length>125?'…':''}</p></td><td><span class="exec-category-label">${e(finding.category)}</span></td><td>${badge(finding.severity)}</td><td><span class="exec-evidence-count">${finding.events.length}</span></td></tr>`).join('')}</tbody></table>${current.priorityFindings.length>60?'<p class="exec-chart-note">Showing 60 ranked findings. Narrow the filters or export the brief for the complete selection.</p>':''}`:'<div class="exec-empty-state">No findings in the current selection.<span>Clear the filters or import more evidence. This does not establish endpoint health.</span></div>';
    const observed=current.sourceCoverage.filter(source=>source.eventCount>0).length;
    $('exec-source-count').textContent=`${observed} WITH RECORDS`;
    $('exec-source-list').innerHTML=current.sourceCoverage.slice(0,40).map(source=>`<div class="exec-source-row"><span class="exec-source-records">${number(source.eventCount)}</span><div><strong>${e(source.name)}</strong><small>${source.eventCount?'Observed records':source.available===false?'Marked unavailable in source inventory':'Listed only · no records in this view'}</small></div><span class="exec-source-status ${source.eventCount?'observed':source.available===false?'missing':''}" aria-label="${source.eventCount?'Records observed':source.available===false?'Not included':'Listed only'}">${source.eventCount?'✓':source.available===false?'!':'—'}</span></div>`).join('')||'<div class="exec-empty-state">No source inventory for this selection.</div>';
    const notes=[...current.notes,...current.reports.flatMap(report=>report.warnings)];
    $('exec-note-count').textContent=`(${notes.length})`;
    $('exec-notes').innerHTML='<ul>'+notes.slice(0,40).map(note=>`<li>${e(note)}</li>`).join('')+'</ul>';
    $('exec-export').disabled=state.busy||!reports().length;
  }
  function updateFilter(key,value){state.filters[key]=value;if(key==='category')$('exec-category').value=value;if(key==='severity')$('exec-severity').value=value;render();}
  function openFinding(id){
    const finding=current.priorityFindings.find(item=>item.id===id);if(!finding)return;
    $('exec-dialog-domain').textContent=finding.category.toUpperCase();$('exec-dialog-title').textContent=finding.title;
    $('exec-detail-content').innerHTML=`<div class="exec-detail-meta">${badge(finding.severity)}<span class="exec-report-chip">${e(finding.reportLabel)}</span><span>Confidence: ${e(finding.confidence)}</span></div><section class="exec-detail-block"><div class="exec-detail-label">WHAT THE EVIDENCE SHOWS</div><p>${e(finding.summary||'No summary was supplied.')}</p></section><section class="exec-detail-block cause"><div class="exec-detail-label">LIKELY CAUSE / WHAT TO CONFIRM</div><p>${e(finding.rootCause||'A root cause was not established in this report.')}</p></section><section class="exec-detail-block"><div class="exec-detail-label">VERIFICATION CHECKS</div><ol class="exec-suggestion-list">${finding.checks.map(check=>`<li>${e(check)}</li>`).join('')||'<li>No verification checks were supplied.</li>'}</ol></section><section class="exec-detail-block"><div class="exec-detail-label">SUGGESTED RESOLUTION · NOT EXECUTED</div><ol class="exec-suggestion-list">${finding.recommendations.map(item=>`<li>${e(item)}</li>`).join('')||'<li>No resolution was supplied. Review the original report.</li>'}</ol></section><section class="exec-detail-block"><div class="exec-detail-label">LINKED EVIDENCE · ${finding.events.length} RECORDS IN THE CURRENT SCOPE</div>${finding.events.slice(0,40).map(event=>`<article class="exec-evidence-record"><div class="exec-evidence-meta"><strong>${e(event.source)}${event.line!==null?':'+event.line:''}</strong><span>${e(formatTime(event.timestamp))}</span></div><p class="exec-evidence-stage">${e(event.stage)} · ${e(event.context)}${event.codes.length?' · '+e(event.codes.join(', ')):''}</p><pre>${e(event.message)}</pre></article>`).join('')||'<p>No matching evidence records are available in the current filter. Review the original report and its import notices.</p>'}${finding.events.length>40?'<p>Showing the first 40 linked records. The original report contains the full evidence.</p>':''}</section><p class="exec-notice">Review one approved remediation at a time. This dashboard applies no changes and cannot confirm that an imported endpoint is healthy.</p>`;
    $('exec-detail').showModal();
  }
  async function importFiles(files){
    if(!files.length||state.busy)return;
    state.busy=true;$('exec-import').disabled=true;$('exec-dataset').disabled=true;$('exec-export').disabled=true;showStatus('Reading logs and analyzing evidence locally in this browser…');
    try{
      const {reports:imported,errors,notices}=await readDiagnosticFiles(files);
      if(imported.length){state.imported=[...new Map(imported.map(report=>[report.id,report])).values()];state.mode='imported';$('exec-dataset').options[1].disabled=false;$('exec-dataset').options[1].textContent=`Imported reports (${state.imported.length})`;$('exec-dataset').value='imported';resetFilters();render();}
      const eventCount=imported.reduce((sum,report)=>sum+report.events.length,0),findingCount=imported.reduce((sum,report)=>sum+report.findings.length,0);
      const message=imported.length?`${number(eventCount)} evidence records and ${number(findingCount)} findings loaded in ${state.imported.length} report${state.imported.length===1?'':'s'}. Files stay in this browser session; nothing is uploaded.`:'No readable logs or valid reports were loaded. Your current dataset is unchanged.';
      showStatus([message,...notices,...errors].join(' '),errors.length>0);
    }catch(error){showStatus(`${sanitizeText(error.message)} Your current dataset is unchanged.`,true);
    }finally{state.busy=false;$('exec-import').disabled=false;$('exec-dataset').disabled=false;$('exec-export').disabled=!reports().length;$('exec-file-input').value='';}
  }
  $('exec-import').addEventListener('click',()=>$('exec-file-input').click());
  $('exec-file-input').addEventListener('change',event=>importFiles([...event.target.files]));
  $('exec-dataset').addEventListener('change',event=>{state.mode=event.target.value;resetFilters();$('exec-import-status').hidden=true;render();});
  $('exec-category').addEventListener('change',event=>updateFilter('category',event.target.value));
  $('exec-severity').addEventListener('change',event=>updateFilter('severity',event.target.value));
  function changeDates(){const from=$('exec-from').value,to=$('exec-to').value;if(from&&to&&from>to){showStatus('The start date must be on or before the end date. The previous filter remains active.',true);return;}state.filters.from=from;state.filters.to=to;$('exec-import-status').hidden=true;render();}
  $('exec-from').addEventListener('change',changeDates);$('exec-to').addEventListener('change',changeDates);
  $('exec-search').addEventListener('input',event=>{const query=event.target.value;clearTimeout(searchTimer);searchTimer=setTimeout(()=>updateFilter('query',query),200);});
  $('exec-reset').addEventListener('click',()=>{clearTimeout(searchTimer);resetFilters();$('exec-import-status').hidden=true;render();});
  $('exec-all-domains').addEventListener('click',()=>updateFilter('category','all'));
  $('exec-close-detail').addEventListener('click',()=>$('exec-detail').close());
  $('exec-detail').addEventListener('click',event=>{if(event.target===$('exec-detail')){const bounds=$('exec-detail').getBoundingClientRect();if(event.clientX<bounds.left||event.clientX>bounds.right||event.clientY<bounds.top||event.clientY>bounds.bottom)$('exec-detail').close();}});
  document.addEventListener('click',event=>{const button=event.target.closest('button');if(!button||button.disabled)return;if(button.dataset.execView)setView(button.dataset.execView);else if(button.dataset.execCategory)updateFilter('category',button.dataset.execCategory);else if(button.dataset.execSeverity)updateFilter('severity',state.filters.severity===button.dataset.execSeverity?'all':button.dataset.execSeverity);else if(button.dataset.execFinding)openFinding(button.dataset.execFinding);});
  $('exec-export').addEventListener('click',()=>{const blob=new Blob([executiveBrief(current,datasetLabel())],{type:'text/html;charset=utf-8'});const url=URL.createObjectURL(blob);const anchor=document.createElement('a');anchor.href=url;anchor.download=`windows-diagnostics-executive-brief${state.mode==='sample'?'-sample':''}.html`;document.body.append(anchor);anchor.click();anchor.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);showStatus('Executive brief downloaded. Review redaction and scope before sharing. No endpoint changes were applied.');});
  setView('dashboard');render();
}

if(typeof document!=='undefined')init();
