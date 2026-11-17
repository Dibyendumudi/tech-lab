/** Evidence-selection metrics. These are not upstream health scores or causal correlations. */
const MAX_IDENTIFIER_REFERENCES = 100000;
export function buildDiagnosticKPIs(data, {explained=0, unexplained=0}={}) {
  const events=data.events || [], visible=new Map(events.map(event=>[event.id,event]));
  const priority=new Map();
  for (const finding of data.priorityFindings || []) {
    if (finding.severity !== 'error') continue;
    for (const event of finding.events || []) if (visible.has(event.id)) priority.set(event.id,visible.get(event.id));
  }
  const timedPriority=[...priority.values()].filter(event=>event.timestamp).length;
  const groups=new Map();
  let references=0, truncated=false;
  outer: for (const event of events) {
    if (!event.reportId) continue; // Never join records without report scope.
    const seen=new Set();
    for (const rawId of event.correlationIds || []) {
      if (references >= MAX_IDENTIFIER_REFERENCES) {truncated=true;break outer;}
      references++;
      const identifier=String(rawId).trim();
      if (!identifier || seen.has(identifier)) continue;
      seen.add(identifier);
      const key=JSON.stringify([event.reportId,identifier]);
      if (!groups.has(key)) groups.set(key,{reportId:event.reportId,identifier,sources:new Set(),records:0});
      const group=groups.get(key);group.sources.add(event.source);group.records++;
    }
  }
  const shared=[...groups.values()].filter(group=>group.sources.size>1)
    .sort((a,b)=>b.sources.size-a.sources.size||b.records-a.records||a.identifier.localeCompare(b.identifier)||a.reportId.localeCompare(b.reportId));
  const signalTotal=explained+unexplained;
  const percent=(numerator,denominator)=>denominator ? (100*numerator/denominator).toFixed(1)+'%' : '—';
  const cards=[
    {label:'Explained signal coverage',value:percent(explained,signalTotal),note:`${explained} / ${signalTotal} unique rule-explained or unexplained signal records. Other records and supplied-only interpretations are excluded.`},
    {label:'Priority evidence timed',value:percent(timedPriority,priority.size),note:`${timedPriority} / ${priority.size} unique linked records for error/high/critical findings have usable UTC times.`},
    {label:'Shared identifiers across sources',value:(truncated?'≥':'')+shared.length,note:`Report-scoped identifiers observed in two or more sources. Device/app IDs may span unrelated operations.${truncated?' Index limited to the first '+MAX_IDENTIFIER_REFERENCES+' identifier references.':''}`}
  ];
  return {cards,signalTotal,explained,unexplained,timedPriority,priorityRecords:priority.size,sharedCount:shared.length,truncated,
    shared:shared.slice(0,5).map(group=>({...group,sources:[...group.sources].sort()}))};
}
