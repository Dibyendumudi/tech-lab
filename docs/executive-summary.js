/** Evidence-based management narrative. All quantities describe the visible records. */
import { getKnowledgeBase } from './raw-analysis.js?v=1.5.0';
const e = value => String(value ?? '').replace(/[&<>"']/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const uniq = values => [...new Set(values)];
const stages = ['assignment','policy','execution','result'];
const owners = {
  'Win32 apps':['Application packaging / endpoint team','Application delivery or availability may be delayed; affected users and devices cannot be counted from these records.','AppWorkload / AppActionProcessor / IME logs, exact command, detection rule and verbose installer output'],
  'Windows patching':['Windows servicing / patching team','Patch readiness may be delayed; security exposure and the affected fleet cannot be quantified from these records.','WindowsUpdateClient, CBS, UpdateOrchestrator and effective update-source/ring policy'],
  'Conditional Access':['Identity / Conditional Access team','Access may be interrupted; sign-in records do not establish the number of affected people.','The same Entra sign-in’s policy evaluation, authentication steps, device compliance and join state'],
  'Autopilot & ESP':['Provisioning / enrollment team','Device provisioning may be delayed; no fleet-wide deployment delay is established.','Autopilot / ESP phase, blocking app, enrollment event and TPM/network evidence'],
  'Enterprise':['Endpoint support / relevant service owner','The recorded operation may need attention; business criticality and actual impact require owner review.','The complete provider log, first failing operation and related activity identifiers']
};
export function isUnexplained(finding) {
  return finding.diagnosis?.type === 'unclassified' || /^(?:Error recorded; root cause unconfirmed|Warning or error code requires review)$/i.test(finding.title || '');
}
export function knowledgeCatalog() {
  const groups = new Map();
  for (const rule of getKnowledgeBase()) {
    const id = rule.id.split(':')[0];
    if (!groups.has(id)) groups.set(id,{...rule,id,categories:[],ruleIds:[]});
    const group=groups.get(id);group.categories.push(rule.category);group.ruleIds.push(rule.id);
  }
  return [...groups.values()];
}
export function buildExecutiveSummary(data, archives=[]) {
  const events=data.events || [], findings=data.priorityFindings || [], catalog=getKnowledgeBase();
  const ruleIds=new Set(catalog.map(rule=>rule.id)), visibleIds=new Set(events.map(event=>event.id));
  const explained=new Set(), unresolved=new Set(), linked=new Set(), groups=new Map(), matched=new Set();
  let provided=0;
  for (const finding of findings) {
    const evidence=(finding.events || []).filter(event=>visibleIds.has(event.id));
    const known=ruleIds.has(finding.diagnosis?.ruleId) && finding.diagnosis?.type==='rule';
    if(known)matched.add(finding.diagnosis.ruleId);
    const generic=isUnexplained(finding);
    if(!known&&!generic)provided++;
    for(const event of evidence){linked.add(event.id);if(known)explained.add(event.id);if(generic)unresolved.add(event.id);}
    const codes=uniq(evidence.flatMap(event=>event.codes || []).filter(code=>!/^0x0+$/.test(code)));
    const key=generic ? [finding.category,'unexplained',codes.slice().sort().join(',') || finding.title].join('|') : [finding.category,finding.title].join('|');
    if(!groups.has(key))groups.set(key,{id:'issue-'+groups.size,title:generic?`${finding.category}: ${codes.length?codes.join(', '):'unexplained diagnostic signals'}`:finding.title,category:finding.category,severity:finding.severity,generic,findings:[],events:new Map()});
    const group=groups.get(key);group.findings.push(finding);for(const event of evidence)group.events.set(event.id,event);
    if(['error','warning','info'].indexOf(finding.severity)<['error','warning','info'].indexOf(group.severity))group.severity=finding.severity;
  }
  const issues=[...groups.values()].sort((a,b)=>['error','warning','info'].indexOf(a.severity)-['error','warning','info'].indexOf(b.severity)||b.events.size-a.events.size).map(group=>{
    const first=group.findings[0], evidence=[...group.events.values()];
    const [owner,impact,needed]=owners[group.category] || owners.Enterprise;
    return {id:group.id,title:group.title,category:group.category,severity:group.severity,findingCount:group.findings.length,evidenceCount:evidence.length,
      sources:uniq(evidence.map(event=>event.source)),codes:uniq(evidence.flatMap(event=>event.codes || [])),
      observation:group.generic?`${evidence.length} visible record(s) support ${group.findings.length} unexplained signal group(s). A documented interpretation has not been established.`:first.summary || 'The supplied report identifies this finding. Inspect its evidence.',
      interpretation:group.generic?`Identify the first failing operation and exact provider/code. Obtain ${needed}.`:first.rootCause || 'The supplied report does not explain the cause; inspect its linked records.',
      confidence:uniq(group.findings.map(finding=>finding.confidence || 'Unknown')).join(', '),
      impact:group.severity==='info'?'Follow-up may be needed; this informational finding does not establish a service interruption.':impact,
      owner, nextCheck:first.checks?.[0] || `Review ${needed}.`,
      decision:group.generic?'Assign a technical owner to obtain and interpret the missing evidence before approving a change.':first.recommendations?.[0] || 'Have the owner verify the evidence and prepare one reviewed resolution proposal.',
      findingIds:group.findings.map(finding=>finding.id),reportId:first.reportId};
  });
  const timed=events.filter(event=>event.timestamp).length, withIds=events.filter(event=>event.correlationIds?.length).length;
  const observed=stages.filter(stage=>events.some(event=>event.stage===stage));
  const entries=archives.flatMap(archive=>archive.entries || []);
  const archive={archives:archives.length,entries:entries.length,analyzed:entries.filter(entry=>entry.status==='analyzed').length,partial:entries.filter(entry=>entry.status==='partial').length,skipped:entries.filter(entry=>entry.status==='skipped').length,failed:entries.filter(entry=>entry.status==='failed').length};
  const synthetic=(data.reports || []).filter(report=>report.synthetic).length;
  const limitations=[
    'Problem patterns group observations for review; they are not incident, device or user counts. Shared codes do not prove a shared cause.',
    'Confidence describes the supplied interpretation. This app does not independently confirm root causes or business impact.'
  ];
  if(timed<events.length)limitations.push(`${events.length-timed} visible record(s) have no usable UTC timestamp.`);
  if(withIds<events.length)limitations.push(`${events.length-withIds} visible record(s) have no explicit correlation identifier; time proximity does not establish a relationship.`);
  if(observed.length<4&&events.length)limitations.push(`Lifecycle stages not observed in this selection: ${stages.filter(stage=>!observed.includes(stage)).join(', ')}.`);
  if(archives.length)limitations.push(`Latest CAB inventory: ${archive.analyzed} analyzed, ${archive.partial} partial, ${archive.skipped} skipped, ${archive.failed} failed entries. The inventory describes the latest import and is independent of filters and selected dataset.`);
  if(archives.some(archive=>archive.error))limitations.push('At least one CAB could not be inventoried; file coverage is unknown for that archive.');
  const warningCount=uniq((data.reports || []).flatMap(report=>report.warnings || [])).length;
  if(warningCount)limitations.push(`${warningCount} supplied import/analysis limitation(s) remain in Scope and limitations; review them before a decision.`);
  if(synthetic)limitations.push(`${synthetic} visible report(s) contain synthetic demonstration evidence. Do not treat them as operational outcomes.`);
  const unexplained=[...unresolved].filter(id=>!explained.has(id)).length;
  return {
    headline:issues.length?`${issues.length} problem pattern${issues.length===1?'':'s'} to review${issues[0].severity==='info'?'':' · '+issues[0].category}`:events.length?'Evidence loaded; no reported problem pattern in this selection':'No diagnostic evidence in this selection',
    overview:`${events.length} evidence record(s) and ${findings.length} reported finding(s) from ${data.reports?.length || 0} report(s). ${explained.size} record(s) are linked to recognized local knowledge rules; ${unexplained} record(s) remain unexplained. ${provided} finding(s) retain the supplied report’s interpretation.`,
    issues,decision:issues.length?`First priority: ${issues[0].owner}. ${issues[0].nextCheck}`:'Obtain the relevant diagnostic sources or clear the filters before making an operational decision. No findings does not establish endpoint health.',
    metrics:{explained:explained.size,unexplained,timed,withIds,total:events.length,stages:observed.length,observedStages:observed,linked:linked.size,provided,matched:matched.size,catalog:knowledgeCatalog().length,sources:(data.sourceCoverage || []).filter(source=>source.eventCount>0).length},
    archive,limitations,synthetic,
    filtersText:`Current selection: ${data.filters?.category || 'all'} workstreams · ${data.filters?.severity || 'all'} severities · ${data.filters?.from || 'all dates'} to ${data.filters?.to || 'all dates'} UTC · search ${data.filters?.query || 'none'}`
  };
}
export function executiveSummaryHTML(summary,{interactive=false}={}) {
  const m=summary.metrics;
  const kpis=[['Rule-explained records',m.explained,'Unique evidence linked to a recognized rule'],['Unexplained records',m.unexplained,'Signals without a local rule interpretation'],['UTC-ready records',`${m.timed} / ${m.total}`,'Usable UTC timestamps in this selection'],['Records with identifiers',`${m.withIds} / ${m.total}`,'An identifier does not prove causation'],['Lifecycle stages observed',`${m.stages} / 4`,'Stages may belong to different operations'],['Sources with records',m.sources,'In the current filters; not complete collection']];
  return `<div class="exec-summary"><div class="exec-panel-head"><div><h2>Executive problem analysis</h2><p class="exec-panel-sub">${summary.synthetic?'Includes demonstration evidence · ':''}Evidence, possible consequences and decisions</p></div><span class="exec-panel-tag">${m.matched} DOMAIN RULE MATCHES</span></div><div class="exec-summary-body"><h3 class="exec-summary-headline">${e(summary.headline)}</h3><p>${e(summary.overview)}</p><p class="exec-summary-scope">${e(summary.filtersText)}</p><div class="exec-summary-kpis">${kpis.map(([label,value,note])=>`<div class="exec-summary-kpi"><span>${e(label)}</span><strong>${e(value)}</strong><small>${e(note)}</small></div>`).join('')}</div><div class="exec-summary-decision"><strong>Management next step</strong><p>${e(summary.decision)}</p></div><div class="exec-summary-issues">${summary.issues.slice(0,5).map((issue,index)=>`<article class="exec-summary-issue"><div class="exec-summary-issue-heading"><span class="exec-summary-number">${index+1}</span><div><h3>${e(issue.title)}</h3><p>${e(issue.category)} · ${e(issue.severity)} · ${issue.evidenceCount} linked record(s) · Reported confidence: ${e(issue.confidence)}</p></div></div><dl><div><dt>What the evidence shows</dt><dd>${e(issue.observation)}</dd></div><div><dt>Interpretation / what remains to verify</dt><dd>${e(issue.interpretation)}</dd></div><div><dt>Possible operational consequence</dt><dd>${e(issue.impact)}</dd></div><div><dt>Suggested owner and next check</dt><dd>${e(issue.owner)}. ${e(issue.nextCheck)}</dd></div><div><dt>Resolution proposal / decision</dt><dd>${e(issue.decision)}</dd></div></dl><p class="exec-summary-sources">${e(issue.codes.join(', ') || 'No explicit code in linked evidence')} · ${e(issue.sources.slice(0,4).join(' · ') || 'No linked source in the current filters')}${issue.sources.length>4?` · +${issue.sources.length-4} more sources`:''}</p>${interactive?`<button type="button" class="exec-btn" data-exec-finding="${e(issue.findingIds[0])}">Review supporting evidence ↗</button>`:''}</article>`).join('')}</div>${summary.issues.length>5?`<p class="exec-summary-scope">Showing the first 5 of ${summary.issues.length} patterns. Review priorities contains the detailed findings; use filters to focus the analysis.</p>`:''}<details class="exec-summary-limitations"><summary>Interpretation and coverage limits</summary><ul>${summary.limitations.map(note=>`<li>${e(note)}</li>`).join('')}</ul></details></div></div>`;
}
export function knowledgeBaseHTML(data,query='') {
  const selected=new Set((data.findings || []).filter(finding=>finding.diagnosis?.type==='rule').map(finding=>finding.diagnosis.ruleId));
  const needle=query.toLowerCase().trim();
  const catalog=knowledgeCatalog();
  const items=catalog.filter(rule=>!needle || [rule.title,rule.meaning,...rule.categories,rule.id].join(' ').toLowerCase().includes(needle));
  return `<p class="exec-summary-scope">${items.length} of ${catalog.length} knowledge patterns. A match explains an observed signal; it does not confirm its underlying cause. Existing JSON reports keep supplied findings; import the original logs/CAB to apply the current rules.</p>${items.map(rule=>`<details class="exec-knowledge-rule"><summary><span>${e(rule.title)}</span><small>${rule.ruleIds.some(id=>selected.has(id))?'Matched in this selection':'Not matched in this selection'}</small></summary><p class="exec-summary-scope">${e(rule.categories.join(' · '))} · ${e(rule.id)}</p><p>${e(rule.meaning)}</p><h4>Verify with evidence</h4><ul>${rule.checks.map(check=>`<li>${e(check)}</li>`).join('')}</ul><h4>Suggested resolution review</h4><ul>${rule.recommendations.map(value=>`<li>${e(value)}</li>`).join('')}</ul><a href="${e(rule.reference)}" target="_blank" rel="noopener noreferrer">Microsoft troubleshooting reference ↗</a></details>`).join('') || '<p>No built-in knowledge pattern matches this search.</p>'}`;
}
