/** Bundled synthetic interpretation checks. No supplied dataset is read or changed. */
import { EXTRA_KNOWLEDGE } from './knowledge-base.js';
import { analyzeRawEvents } from './raw-analysis.js?v=1.5.0';
import { parseRawLog } from './raw-parsers.js?v=1.5.0';
import { parseReport } from './analytics.js?v=1.5.0';
const sources={'Win32 apps':'AppWorkload.json','Windows patching':'WindowsUpdateClient.json','Conditional Access':'SignIns.json','Autopilot & ESP':'Autopilot.json',Enterprise:'events.json'};
const make=(name,category,message,expected,extra={})=>({name,category,filename:sources[category],content:JSON.stringify({TimeCreated:'2026-01-01T10:00:00Z',Message:message,...extra}),expected});
export const VALIDATION_CASES = [
  make('App detection after installation','Win32 apps','Detection failed with 0x87D1041C','win32-detection'),
  make('Generic installer failure','Win32 apps','Installer exit code: 1603','win32-1603'),
  make('Concurrent installer','Win32 apps','Installer returned code 1618','win32-1618'),
  make('Successful install awaiting restart','Win32 apps','Installer returned code 3010','win32-3010'),
  make('Dependency is missing','Win32 apps','App dependency is missing','win32-dependency'),
  make('Assignment is absent','Win32 apps','No applicable assignment','win32-assignment'),
  make('Explicit execution context mismatch','Win32 apps','Expected SYSTEM context but running User context','win32-context'),
  make('Missing servicing source','Windows patching','CBS failed with 0x800F081F','patch-0x800f081f'),
  make('Servicing manifest/component error','Windows patching','CBS failed with 0x800F0831','patch-0x800f0831'),
  make('Update DNS failure','Windows patching','Scan failed with 0x80072EE7','patch-0x80072ee7'),
  make('Update request timeout','Windows patching','Scan failed with 0x80072EE2','patch-0x80072ee2'),
  make('Update restart requirement','Windows patching','Reboot required','patch-restart'),
  make('Update policy delivery failure','Windows patching','Update policy not received','patch-policy'),
  make('Compliance control blocked sign-in','Conditional Access','AADSTS53000 DeviceNotCompliant','ca-aadsts53000'),
  make('Required join condition not satisfied','Conditional Access','AADSTS53001 DeviceNotDomainJoined','ca-aadsts53001'),
  make('CA evaluation blocked sign-in','Conditional Access','AADSTS53003 BlockedByConditionalAccess','ca-aadsts53003'),
  make('MFA requirement','Conditional Access','AADSTS50076 MFA required','ca-mfa'),
  make('ESP waiting limit','Autopilot & ESP','ESP timed out waiting for blocking app','autopilot-esp'),
  make('TPM attestation error','Autopilot & ESP','TPM attestation failed','autopilot-tpm'),
  make('MDM enrollment failure','Autopilot & ESP','MDM enrollment failed','autopilot-enrollment'),
  make('Autopilot profile not assigned','Autopilot & ESP','Autopilot profile not assigned','autopilot-profile'),
  make('Autopilot request DNS failure','Autopilot & ESP','Connectivity failed with 0x80072EE7','autopilot-network'),
  make('Observed join state','Enterprise','AzureAdJoined : NO','join-observation'),
  ...EXTRA_KNOWLEDGE.map(entry=>make(entry.title,entry.categories[0],/^\d+$/.test(entry.code)?`Installer exit code ${entry.code}`:`Operation failed with ${entry.code}`,entry.id+':'+entry.categories[0])),
  make('Success text is not an error','Win32 apps','Installation completed successfully. No errors.',null),
  make('Zero error code in JSON is not a failure','Win32 apps','Operation complete.',null,{ErrorCode:0,Level:2}),
  make('Null diagnostic fields are not failures','Enterprise','Operation complete.',null,{status:{errorCode:0,failureReason:null},Exception:null}),
  make('Configured return codes are not execution results','Win32 apps','Configured return codes: 1603=failed, 3010=soft reboot',null),
  make('Informational mentions are not a context mismatch','Win32 apps','SYSTEM context; user signed in',null)
];
export function runValidationCases() {
  return VALIDATION_CASES.map(item=>{
    try {
      const parsed=parseRawLog(item.content,item.filename);
      const report=parseReport(analyzeRawEvents(parsed.events,[item.filename],parsed.warnings),'Synthetic validation only');
      const matched=report.findings.map(finding=>finding.diagnosis.ruleId);
      return {name:item.name,category:item.category,passed:item.expected===null?report.findings.length===0:matched.includes(item.expected),expected:item.expected || 'No failure finding',observed:report.findings.map(finding=>finding.title)};
    } catch(error){return {name:item.name,category:item.category,passed:false,expected:item.expected || 'No failure finding',observed:[String(error.message)]};}
  });
}
