import test from 'node:test';
import assert from 'node:assert/strict';
import {describeMissingArtifact,missingArtifactRows,artifactInvestigationHTML} from '../docs/artifact-investigation.js';
import {parseRawLog} from '../docs/raw-parsers.js';
import {analyzeRawEvents} from '../docs/raw-analysis.js';
import {parseReport,buildDashboard} from '../docs/analytics.js';
import {executiveBrief} from '../docs/executive.js';
import {casesFromReports,reportFromCase} from '../docs/guided-data.js';
import {reportHTML} from '../docs/app.js';

const collector='Example.cab / MdmLogCollectorFootPrint.txt';
const setup='Example.cab / setupact.log';
const examples=[
 {id:'file',source:collector,line:52,message:'Failed (HResult: 0x80070002) to CollectFileEntry:c:\\windows\\provisioning\\autopilot\\autopilotconfigurationfile.json'},
 {id:'registry',source:collector,line:77,message:'Failed (HResult:0x80070002) to dump HKCU registry:software\\microsoft\\example'},
 {id:'oobe',source:setup,line:147,message:'2026-06-23 10:22:04, Info [msoobe.exe] Failed to load oobe.xml file at C:\\Windows\\system32\\oobe\\info\\oobe.xml with hr=0x80070002'},
 {id:'cleanup',source:setup,line:734,message:'2026-07-02 10:06:43, Warning DoCleanup: Failed to calculate size of [C:\\Windows.old]. hr = 0x80070003'}
];

test('not-found operations distinguish collected files, registry exports, OOBE probes and cleanup',()=>{
 const rows=missingArtifactRows(examples);
 assert.deepEqual(rows.map(r=>r.kind),['collector-file','collector-registry','oobe-config','cleanup-directory']);
 assert.equal(rows[0].target,'c:\\windows\\provisioning\\autopilot\\autopilotconfigurationfile.json');
 assert.equal(rows[1].target,'HKCU\\software\\microsoft\\example');
 assert.match(rows[1].comparison,/not a file/);
 assert.match(rows[2].check,/OEM\/deployment image/);
 assert.equal(rows[2].severity,'info');
 assert.equal(rows[3].target,'C:\\Windows.old');
 assert.equal(describeMissingArtifact({source:setup,message:'Read C:\\other.txt then another event returned 0x80070002'}),null);
 assert.equal(describeMissingArtifact({source:'other.log',message:examples[0].message}),null);
});

test('archive comparison is scoped and a filename match does not imply content equivalence',()=>{
 const rows=missingArtifactRows([examples[0]],[{name:'Different.cab',entries:[{name:'AutopilotConfigurationFile.json'}]}]);
 assert.match(rows[0].comparison,/No matching CAB inventory/);
 const matched=missingArtifactRows([examples[0]],[{name:'Example.cab',entries:[{name:'AutopilotConfigurationFile.json'}]}]);
 assert.match(matched[0].comparison,/Name match only/);
 assert.match(matched[0].comparison,/content equivalence are unverified/);
 const other=missingArtifactRows([examples[0]],[{name:'Example.cab',entries:[{name:'AutopilotDDSZTDFile.json'}]}]);
 assert.match(other[0].comparison,/No same-name member/);
});

test('context-aware rules stop describing collection and OOBE records as required-package failures',()=>{
 const raw=examples.flatMap(e=>parseRawLog(e.message,e.source).events);
 const report=analyzeRawEvents(raw);
 assert.ok(report.findings.every(f=>f.severity!=='error'));
 assert.ok(report.findings.some(f=>/registry key/.test(f.title)));
 assert.ok(report.findings.some(f=>/OOBE/.test(f.title)&&f.severity==='info'));
 assert.ok(report.findings.some(f=>/cleanup/.test(f.title)));
 assert.ok(report.findings.every(f=>f.checks.every(c=>!c.startsWith('Identify the exact file'))));
});

test('exact target tables survive canonical mapping and both report export paths',()=>{
 const analyzed=analyzeRawEvents(examples.flatMap(e=>parseRawLog(e.message,e.source).events));
 const canonical=parseReport(analyzed),data=buildDashboard([canonical]);
 assert.match(executiveBrief(data,'Imported evidence'),/HKCU\\software\\microsoft\\example/);
 const output=reportFromCase(casesFromReports([canonical])[0]);
 assert.match(reportHTML(output),/Load OOBE customization XML/);
 const html=artifactInvestigationHTML([{...examples[0],message:examples[0].message+'<img src=x onerror=alert(1)>'}]);
 assert.ok(!html.includes('<img'));
 assert.match(html,/&lt;img/);
});
