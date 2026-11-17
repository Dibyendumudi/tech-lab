import {escapeHTML as e} from './utils.js?v=1.6.5';

const MDM='https://learn.microsoft.com/en-us/windows/client-management/mdm-collect-logs';
const OOBE='https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/oobexml-in-windows-11';
const clean=value=>String(value||'').trim().slice(0,2000);
const basename=value=>clean(value).replace(/\\/g,'/').split('/').pop().trim().toLowerCase();

/** Interpret the operation actually named by a not-found record, never an adjacent unrelated path. */
export function describeMissingArtifact(event) {
  const message=String(event.message||'');
  if(!/0x8007000[23]\b/i.test(message)||! /\bfailed\b/i.test(message))return null;
  const source=basename(event.source);
  let match;
  if(source==='mdmlogcollectorfootprint.txt'&&(match=/\bto CollectFileEntry:\s*([^\r\n]+)/i.exec(message)))return {
    kind:'collector-file',operation:'CollectFileEntry',target:clean(match[1]),targetType:/[*?]/.test(match[1])?'File pattern':'File',
    title:'Diagnostic collection could not read a requested file or path',severity:'warning',reference:MDM,
    interpretation:'The diagnostic collector reported a not-found result for this collection target. This is a collection gap; the record does not identify a failed application install or a missing servicing package.',
    check:'Compare the exact collection target with the collection configuration and the matching CAB inventory. Verify whether this artifact is expected for the deployment method.',
    recommendation:'Review the collection gap with the diagnostics owner; obtain the expected artifact if applicable before proposing a package or servicing-source change.'
  };
  if(source==='mdmlogcollectorfootprint.txt'&&(match=/\bto dump\s+(HKCU|HKLM)\s+registry:\s*([^\r\n]+)/i.exec(message)))return {
    kind:'collector-registry',operation:`Export ${match[1].toUpperCase()} registry key`,target:match[1].toUpperCase()+'\\'+clean(match[2]),targetType:'Registry key',
    title:'Diagnostic collection could not export a requested registry key',severity:'warning',reference:MDM,
    interpretation:'The collector could not export this registry key. ERROR_FILE_NOT_FOUND in this operation describes a registry lookup, not an identified missing disk file or package.',
    check:'Check the named hive, key, collection identity and whether that key is expected for this device and collection context.',
    recommendation:'Obtain the relevant registry export if it is expected. Do not replace an application package based only on this collection result.'
  };
  if(source==='setupact.log'&&(match=/Failed to load oobe\.xml file at\s+(.+?)\s+with\s+hr\s*=/i.exec(message)))return {
    kind:'oobe-config',operation:'Load OOBE customization XML',target:clean(match[1]),targetType:'Configuration file',
    title:'OOBE customization XML lookup returned not found',severity:/\bInfo\b/.test(message)?'info':'warning',reference:OOBE,
    interpretation:'Setup could not load the named OOBE customization XML at this probe location. The record alone does not establish that customization was required, that OOBE stopped, or that a servicing package is missing.',
    check:'Compare the exact XML path with the intended OEM/deployment image customization and language/region layout, then check later setup outcomes.',
    recommendation:'Have the image owner confirm whether this customization is expected. Propose an image-content correction only after establishing that requirement and impact.'
  };
  if(source==='setupact.log'&&(match=/DoCleanup:\s*Failed to calculate size of\s*\[([^\]]+)\]/i.exec(message)))return {
    kind:'cleanup-directory',operation:'DoCleanup: calculate directory size',target:clean(match[1]),targetType:'Directory',
    title:'Setup cleanup could not measure a directory',severity:'warning',reference:MDM,
    interpretation:'The cleanup operation could not measure the named directory because its path was unavailable. This does not identify a missing installation package or prove an installation failure.',
    check:'Compare the directory with setup/cleanup phase and retention policy; check subsequent cleanup results before treating its absence as a deployment blocker.',
    recommendation:'Review cleanup context with the deployment owner. No package or servicing-source replacement is justified by this record alone.'
  };
  return null;
}

export function missingArtifactRows(events,archives=[]) {
  const rows=new Map();
  for(const event of events){
    const detail=describeMissingArtifact(event);if(!detail)continue;
    const source=clean(event.source),key=[source,detail.operation,detail.target.toLowerCase()].join('\0');
    if(!rows.has(key)){
      let comparison='No package or servicing source is named by this operation; a package/version comparison is not established.';
      if(detail.targetType==='Registry key')comparison='Registry export target, not a file. Package comparison is not applicable to this record.';
      else if(detail.targetType==='File pattern')comparison='Wildcard collection target. A flattened CAB inventory cannot verify the source directory or all matching files.';
      else if(detail.kind==='collector-file'){
        const archive=archives.find(a=>source.startsWith(a.name+' / '));
        if(archive){
          const candidates=archive.entries.filter(entry=>basename(entry.name)===basename(detail.target));
          comparison=candidates.length?`${candidates.length} same-name CAB member(s): ${candidates.slice(0,5).map(c=>c.name).join(', ')}. Name match only; original path, version and content equivalence are unverified.`:'No same-name member is listed in this CAB. Absence from the CAB does not independently verify the source filesystem or package contents.';
        }else comparison='No matching CAB inventory is available for comparison. The source filesystem and package contents remain unverified.';
      }
      rows.set(key,{...detail,source,comparison,occurrences:0,evidence:[]});
    }
    const row=rows.get(key);row.occurrences++;row.evidence.push({id:event.id||event.uid||'',line:event.line});
  }
  return [...rows.values()];
}

export function artifactInvestigationHTML(events,archives=[],{limit=100,findings=[]}={}) {
  const rows=missingArtifactRows(events,archives);if(!rows.length)return '';
  return `<div class="exec-panel-head"><div><h2>Exact targets &amp; failing operations</h2><p class="exec-panel-sub">${rows.length} distinct source/operation/target combinations · Derived from explicit not-found records in the current selection</p></div></div><div class="exec-artifact-body"><p>Collection gaps, registry exports, configuration lookups and cleanup checks are shown separately. Package or servicing-source changes require evidence of a package reference and a verified content mismatch.</p><div class="exec-artifact-scroll" role="region" aria-label="Exact missing targets and operation comparison" tabindex="0"><table class="exec-artifact-table" style="width:100%;table-layout:fixed"><thead><tr><th scope="col">Exact target / type</th><th scope="col">Failing operation / evidence</th><th scope="col">Comparison / what remains unverified</th><th scope="col">Next check</th></tr></thead><tbody>${rows.slice(0,limit).map(row=>`<tr><td><code style="white-space:pre-wrap;overflow-wrap:anywhere">${e(row.target)}</code><small>${e(row.targetType)}</small></td><td><strong>${e(row.operation)}</strong><small>${e(row.source)} · line${row.evidence.length>1?'s':''} ${e(row.evidence.slice(0,12).map(x=>x.line??'?').join(', '))}${row.evidence.length>12?'…':''} · ${row.occurrences} occurrence(s)</small>${(()=>{const ids=new Set(row.evidence.map(x=>x.id));const finding=findings.find(f=>f.evidenceIds?.some(id=>ids.has(id)));return finding?`<button type="button" class="exec-btn" data-exec-finding="${e(finding.id)}">Review source evidence ↗</button>`:'';})()}</td><td>${e(row.comparison)}<p>${e(row.interpretation)}</p></td><td>${e(row.check)}<p><a href="${e(row.reference)}" target="_blank" rel="noopener noreferrer">Microsoft format/context reference ↗</a></p></td></tr>`).join('')}</tbody></table></div>${rows.length>limit?`<p>Showing ${limit} of ${rows.length} targets. Narrow the filters for other targets.</p>`:''}</div>`;
}
