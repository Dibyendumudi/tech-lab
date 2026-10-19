/** Local observations from imported text exports. Never executes a resolution. */
import { CATEGORIES, sanitizeText } from './analytics.js';

const MAX_EVENTS = 50000;
const MAX_FINDINGS = 1000;
const MAX_MESSAGE = 20000;
const TRUNCATION_SUFFIX = ' [message truncated]';
const LIMITATIONS = [
  'Imported text is analyzed locally in this browser. No fixes, deletions, commands or settings changes are executed.',
  'These findings describe supplied records, not endpoint health or complete tenant coverage. Verify proposed causes against complete logs and effective tenant configuration.',
  'Redaction is heuristic and best effort. Review the report before sharing; pseudonyms preserve correlation and are not anonymous.',
  'Events are not linked merely because their timestamps are close. A shared error pattern is not proof of a shared root cause.'
];
const DOCS = {
  'Win32 apps': 'https://learn.microsoft.com/en-us/intune/app-management/deployment/troubleshoot-win32',
  'Windows patching': 'https://learn.microsoft.com/en-us/windows/deployment/update/windows-update-troubleshooting',
  'Conditional Access': 'https://learn.microsoft.com/en-us/entra/identity/conditional-access/troubleshoot-conditional-access',
  'Autopilot & ESP': 'https://learn.microsoft.com/en-us/autopilot/troubleshooting-faq'
};
const text = value => typeof value === 'string' ? value : value == null ? '' : String(value);
const safe = value => sanitizeText(text(value)).slice(0, MAX_MESSAGE);
const boundedMessage = value => value.length > MAX_MESSAGE ? value.slice(0, MAX_MESSAGE - TRUNCATION_SUFFIX.length) + TRUNCATION_SUFFIX : value;
const unique = values => [...new Set(values)];
function hash(value) {
  let a = 2166136261, b = 2246822519;
  for (const character of value) {
    a = Math.imul(a ^ character.charCodeAt(0), 16777619);
    b = Math.imul(b ^ character.charCodeAt(0), 3266489917);
  }
  return (a >>> 0).toString(16).padStart(8, '0') + (b >>> 0).toString(16).padStart(8, '0');
}
const has = (event, pattern) => pattern.test(event.message);
const code = (event, value) => event.codes.some(item => item.toLowerCase() === value.toLowerCase());
function successOnly(event) {
  const message = event.message;
  const success = /\b(?:no errors?|no failures?|successful|successfully|succeeded)\b|"succeeded"\s*:\s*true/i.test(message);
  return success && !/\b(?:failed|failure|not successful)\b/i.test(message) && !/\berror code\s*[=:]?\s*(?!0(?:x0+)?\b)(?:0x[0-9a-f]+|[1-9]\d*)\b/i.test(message);
}
function installerResult(event, value) {
  if (/\b(?:configured|configuration|mapping|mappings|return codes)\b/i.test(event.message) && !/\b(?:returned|exited|completed with|process exit|execution result)\b/i.test(event.message)) return false;
  return new RegExp('\\b(?:lpExitCode|exit\\s*(?:code)?|return(?:ed)?\\s*(?:code)?|msi\\s*(?:error|code)|installer\\s*(?:error|code|returned)|installer exited with code)\\s*(?:is\\b|was\\b|equals\\b|[=:])?\\s*' + value + '\\b', 'i').test(event.message);
}
function inferCategory(event) {
  if (CATEGORIES.includes(event.category) && event.category !== 'Enterprise') return event.category;
  const source = `${text(event.source)} ${text(event.provider)}`.toLowerCase();
  const message = text(event.message).toLowerCase();
  const all = source + ' ' + message;
  if (/\baadsts\d+\b/.test(all)) return 'Conditional Access';
  if (/appworkload|intunemanagementextension|appactionprocessor/.test(source)) return 'Win32 apps';
  if (/conditional.?access|sign.?in|\bentra\b/.test(all)) return 'Conditional Access';
  if (/autopilot|enrollment status page|\besp\b|moderndeployment|provisioning-diagnostics|tpm attestation/.test(all)) return 'Autopilot & ESP';
  if (/windowsupdate|windows update|updateorchestrator|cbs\.log|\bservicing\b|update ring|0x800f081f|0x800f0831|0x8024402c/.test(all)) return 'Windows patching';
  if (/\bwin32\b|\bmsiexec\b|\bmsi\b|0x87d1041c|detection rule/.test(all)) return 'Win32 apps';
  if (/enroll(?:ment|ing)\b.{0,100}\b(?:failed|failure|error)/.test(all)) return 'Autopilot & ESP';
  return 'Enterprise';
}
function inferStage(message) {
  if (/\b(?:lpexitcode|exitcode|returncode|exit code|return code|result|succeeded|success|failed|failure|detected|detection)\b/i.test(message)) return 'result';
  if (/\b(?:install(?:ing|ation)?|execut(?:e|ing|ion)|command line|download(?:ing)?)\b/i.test(message)) return 'execution';
  if (/\b(?:assignment|assigned|targeting|targeted|excluded)\b/i.test(message)) return 'assignment';
  if (/\b(?:policy|profile|ring|deadline)\b/i.test(message)) return 'policy';
  return 'unknown';
}
function inferContext(message) {
  const system = /\bSYSTEM\s+context\b|\b(?:context|running as|run as|executing as)\s*[=:]?\s*(?:NT AUTHORITY\\)?SYSTEM\b/i.test(message);
  const user = /\bUSER\s+context\b|\b(?:context|running as|run as|executing as)\s*[=:]?\s*USER\b/i.test(message);
  return system && user ? 'mixed' : system ? 'SYSTEM' : user ? 'User' : 'unknown';
}
function extractCodes(message) {
  const codes = Array.from(message.matchAll(/\b(?:0x[0-9a-f]{8}|AADSTS\d{5,8})\b/gi), match => /^aadsts/i.test(match[0]) ? match[0].toUpperCase() : match[0].toLowerCase());
  for (const match of message.matchAll(/\b(?:lpExitCode|exit\s*(?:code)?|return(?:ed)?\s*(?:code)?|installer\s*(?:error|code)|msi\s*(?:error|code))\s*(?:is\b|was\b|equals\b|[=:])?\s*(1603|1618|3010|1641)\b/gi)) codes.push(match[1]);
  for (const match of message.matchAll(/\b(?:HRESULT|(?:error|result|return|exit)\s*code|lpExitCode)\s*(?:is\b|was\b|equals\b|[=:])?\s*(-?\d{6,10})\b/gi)) {
    const value = Number(match[1]);
    if ((value >= -2147483648 && value < 0) || (value > 65535 && value <= 4294967295)) codes.push('0x' + (value >>> 0).toString(16).padStart(8, '0'));
  }
  return unique(codes);
}
function extractIds(event, message) {
  const supplied = Array.isArray(event.correlation_ids) ? event.correlation_ids : Array.isArray(event.correlationIds) ? event.correlationIds : [];
  const values = supplied.slice(0, 100).map(text);
  for (const match of message.matchAll(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi)) values.push(match[0]);
  for (const match of message.matchAll(/\b(?:correlation|activity|relatedactivity|request|session|device|app(?:lication)?|tenant|object)[ _-]?id["']?\s*[=:]\s*["'{]?([\w.-]{3,})/gi)) values.push(match[1]);
  return unique(values.filter(Boolean).map(value => /^\[id:[a-f0-9]+\]$/i.test(value) ? value : `[id:${hash(value.toLowerCase()).slice(0, 10)}]`));
}
function contextMismatch(event) {
  if (successOnly(event)) return false;
  if (/\bcontext mismatch\b|\b(?:user|system) context\b[^.;\n]{0,80}\b(?:unsupported|incorrect|wrong)\b/i.test(event.message)) return true;
  const expected = /\b(?:expected|requires?|configured for|must run (?:as|in))\b[^.;\n]{0,40}?\b(user|system)\b/i.exec(event.message);
  if (!expected) return false;
  const actual = /\b(?:actual|but|instead|running|executed)\b[^.;\n]{0,40}?\b(user|system)\b/i.exec(event.message.slice(expected.index + expected[0].length));
  return !!actual && expected[1].toLowerCase() !== actual[1].toLowerCase();
}

// A rule states what is observed and what remains unproven. No rule repairs it.
const RULES = [];
function rule(key, category, title, test, root, checks, recommendations, severity = 'warning', confidence = 'medium') {
  RULES.push({ key, category, title, test, root, checks, recommendations, severity, confidence });
}
rule('win32-detection', 'Win32 apps', 'Win32 app not detected after installation', e => code(e, '0x87d1041c'),
  '0x87D1041C reports that the application was not detected after installation. It does not identify whether the detection condition, installed state or installer behavior caused the mismatch.',
  ['Compare the configured file, registry, MSI or script detection rule with the installed state and version.', 'Review detection script exit code/output, 32/64-bit paths, install context and installer result.'],
  ['Propose one detection or packaging adjustment only after the mismatch is confirmed by an authorized administrator.'], 'error', 'high');
rule('win32-1603', 'Win32 apps', 'Installer returned generic failure 1603', e => installerResult(e, '1603'),
  '1603 is a generic Windows Installer failure; it does not establish a unique root cause. The preceding error and verbose MSI log are needed.',
  ['Find the first error before the final 1603 result (often before Return value 3).', 'Review the exact command, prerequisites, permissions and SYSTEM/User context.'],
  ['Collect a verbose installer log in a separate diagnostic folder and prepare a recommendation for the confirmed preceding error.'], 'error');
rule('win32-1618', 'Win32 apps', 'Another installation is in progress (1618)', e => installerResult(e, '1618'),
  'Windows Installer reported an installation already in progress. The competing package is unknown unless explicitly identified by the logs.',
  ['Compare other deployment/servicing events and dependency ordering at the recorded time.'],
  ['Suggest a controlled retry after the competing installation completes; do not terminate installer processes.'], 'warning', 'high');
for (const [value, action] of [['3010', 'required'], ['1641', 'initiated']]) rule('win32-' + value, 'Win32 apps', `Installation succeeded; restart ${action} (${value})`, e => installerResult(e, value),
  `${value} indicates successful installation with a restart ${action}. This return code is not an installation failure.`,
  ['Review the configured return-code mapping and post-restart detection/dependent app evidence.'],
  ['Use the existing approved restart process if needed. This app never initiates a restart.'], 'info', 'high');
rule('win32-dependency', 'Win32 apps', 'App dependency failure or missing dependency recorded', e => has(e, /\bdependenc(?:y|ies)\b.{0,100}\b(?:failed|failure|not installed|unresolved|missing|blocked|timeout|timed out)\b|\b(?:failed|blocked|unresolved)\b.{0,60}\bdependenc(?:y|ies)\b/i) && !successOnly(e),
  'An explicit dependency problem was recorded. The parent app may be a downstream symptom; verify the dependency’s own first error.',
  ['Trace the dependency app ID through assignment, detection, execution context and exit code.', 'Review dependency order, requirements and architecture.'],
  ['Prepare one correction for the confirmed dependency problem and validate the dependent app in a controlled test.']);
rule('win32-assignment', 'Win32 apps', 'Assignment or requirements prevent deployment', e => has(e, /\b(?:no applicable assignment|no assignments? (?:found|received)|assignment.{0,50}(?:excluded|not applicable|missing)|(?:excluded|not targeted).{0,50}(?:assignment|app|group)|requirements? (?:not met|failed))\b/i) && !successOnly(e),
  'The log records absent, excluded or inapplicable assignment/requirements. Tenant targeting and filters must be verified to establish why.',
  ['Compare include/exclude groups, assignment filters, device/user targeting and requirement evaluations with delivery time.'],
  ['Prepare a targeting or requirements recommendation after verifying the evaluated device/user.']);
rule('win32-context', 'Win32 apps', 'Explicit SYSTEM/User context mismatch', contextMismatch,
  'The event explicitly records a context mismatch. Mere mentions of SYSTEM and a user elsewhere do not establish a mismatch.',
  ['Compare intended install behavior with process identity, per-user files, mapped drives and HKCU dependencies.'],
  ['Propose a context/package change only after testing the exact command in the intended context.']);
for (const [value, title, root] of [
  ['0x800f081f', 'Servicing source files were not found', 'CBS_E_SOURCE_MISSING identifies unavailable servicing source files. It does not by itself prove component-store corruption or a policy error.'],
  ['0x800f0831', 'Servicing reported component-store corruption', 'CBS_E_STORE_CORRUPTION is recorded, commonly with a missing package manifest/dependency. Verify the first CBS error and named package before proposing repair.'],
  ['0x8024402c', 'Update request name resolution or proxy error', 'Windows Update reported a name-resolution/proxy request error (0x8024402C). The code alone does not distinguish the configured proxy, target hostname or network path responsible.'],
  ['0x80072ee2', 'Update request timed out', 'The update-related operation timed out (0x80072EE2). DNS, proxy, firewall, endpoint availability and client configuration remain hypotheses without accompanying evidence.'],
  ['0x80072ee7', 'Update request name resolution failed', 'The update-related name-resolution operation failed (0x80072EE7). Identify the hostname and response before attributing the cause.'],
  ['0x80072efd', 'Update connection could not be established', 'The update-related connection failed (0x80072EFD). The code alone does not identify the responsible endpoint, proxy or network control.']
]) rule('patch-' + value, 'Windows patching', title, e => code(e, value), root,
  ['Review the first associated CBS/WindowsUpdateClient/UpdateOrchestrator error, operation and package or endpoint.', 'Compare effective update/source policy and recorded DNS/proxy evidence with this operation.'],
  ['Prepare an evidence-backed servicing or connectivity recommendation for administrator review; preserve settings.'], 'error', 'high');
rule('patch-restart', 'Windows patching', 'Update is waiting for a restart', e => has(e, /\b(?:restart|reboot)\b.{0,50}\b(?:required|pending|overdue)\b|\b(?:pending|required)\b.{0,30}\b(?:restart|reboot)\b/i) && !has(e, /\b(?:no|not)\s+(?:restart|reboot)\b|\b(?:restart|reboot) (?:not required|complete|completed)\b/i),
  'An update-related restart requirement is explicitly recorded. It is not proof of an update download or installation failure.',
  ['Review installation status, recorded boot time, effective restart deadline and active hours.'],
  ['Plan a restart through the existing approved process if needed; this app does not restart devices.'], 'info', 'high');
rule('patch-policy', 'Windows patching', 'Update policy or deadline issue recorded', e => has(e, /\b(?:policy|update ring|deadline)\b.{0,100}\b(?:failed|failure|not received|not applied|conflict|expired|overdue|missed)\b/i) && !successOnly(e),
  'The log explicitly records a policy, conflict or deadline issue. Local evidence does not establish all assigned rings or tenant policy precedence.',
  ['Compare assignment, MDM delivery, effective policy, deadlines and execution/result timestamps.'],
  ['Prepare one policy or scheduling recommendation after effective settings are verified.']);
for (const [value, title, root] of [
  ['AADSTS53000', 'Conditional Access: device not compliant', 'DeviceNotCompliant (AADSTS53000) means the sign-in compliance requirement was not satisfied at evaluation time. Verify the specific failed compliance setting in Intune.'],
  ['AADSTS53001', 'Conditional Access: required join state not satisfied', 'DeviceNotDomainJoined (AADSTS53001) means the required join condition was not satisfied for this sign-in. It does not prove the device is entirely unregistered or not Entra joined; the policy may require hybrid join.'],
  ['AADSTS53003', 'Conditional Access blocked the sign-in', 'BlockedByConditionalAccess (AADSTS53003) identifies a blocked evaluation. It does not identify which policy or grant control caused the block.']
]) rule('ca-' + value.toLowerCase(), 'Conditional Access', title, e => code(e, value), root,
  ['Review the failed applied policy, grant controls, device ID/state and authentication details in this same sign-in record.', 'Compare compliance and join evidence with sign-in time and the actual failed requirement.'],
  ['Prepare a device or authentication recommendation for the failed control; do not disable Conditional Access or bypass MFA.'], 'error', 'high');
rule('ca-mfa', 'Conditional Access', 'Additional MFA or registration required, or MFA failure recorded', e => code(e, 'AADSTS50076') || code(e, 'AADSTS50079') || (has(e, /\b(?:mfa|multifactor|multi-factor)\b[^.;\n]{0,80}\b(?:failed|denied|interrupted|required)\b/i) && !successOnly(e) && !has(e, /\b(?:policy name|displayName)\b/i)),
  'Additional MFA/registration is required or an explicit MFA outcome was recorded. A requirement is not proof that a user failed a challenge.',
  ['Review authentication steps, challenge outcome, registration requirements and the recorded failure reason.'],
  ['Suggest completing the recorded authentication or registration requirement through the existing organizational process.']);
rule('join-observation', 'Enterprise', 'Collected device reports AzureAdJoined: NO', e => has(e, /\bAzureAdJoined\s*:\s*NO\b/i),
  'The imported device-status output reports AzureAdJoined: NO. This observation does not prove that a Conditional Access policy blocked a sign-in.',
  ['Review DomainJoined, WorkplaceJoined, collection context and intended join design together.', 'Compare this state with the actual requirement and timestamp of any relevant Entra sign-in.'],
  ['Review the intended join/enrollment design with an authorized administrator before considering any change.'], 'info', 'high');
rule('autopilot-tpm', 'Autopilot & ESP', 'TPM or attestation failure recorded', e => has(e, /\b(?:tpm|attestation)\b.{0,100}\b(?:failed|failure|error|not ready|not available|timeout|timed out|unsupported)\b/i) && !successOnly(e),
  'A TPM readiness or attestation problem is recorded. Hardware, firmware, certificate/endpoint connectivity and deployment-mode requirements must be distinguished.',
  ['Review exact attestation error, TPM readiness, deployment mode and recorded endpoint requests.'],
  ['Prepare a targeted readiness or connectivity recommendation; never clear the TPM or reset the device from this app.']);
rule('autopilot-esp', 'Autopilot & ESP', 'Enrollment Status Page timeout recorded', e => has(e, /\b(?:esp|enrollment status page)\b.{0,120}\b(?:timeout|timed out|time limit|exceeded)\b|\b(?:timeout|timed out)\b.{0,60}\b(?:esp|enrollment status page)\b/i) && !successOnly(e),
  'ESP exceeded a recorded wait/time limit. A timeout is a symptom; identify the blocking app, policy or enrollment phase before assigning a root cause.',
  ['Identify the ESP phase and blocking app IDs, then trace assignment, dependency, execution, detection and exit-code evidence.'],
  ['Propose one change for the confirmed blocker and validate in a controlled deployment; do not bypass ESP.']);
rule('autopilot-enrollment', 'Autopilot & ESP', 'MDM enrollment failure recorded', e => has(e, /\b(?:mdm )?enroll(?:ment|ing)\b.{0,100}\b(?:failed|failure|error|denied|blocked)\b/i) && !successOnly(e),
  'Enrollment explicitly failed. Scope, permissions, restrictions, licensing and connectivity remain hypotheses unless the accompanying error establishes them.',
  ['Review the first enrollment code, MDM event, profile timestamp, restrictions and intended identity.'],
  ['Prepare a recommendation for the confirmed enrollment error while preserving registration and settings.']);
rule('autopilot-profile', 'Autopilot & ESP', 'Autopilot profile or registration issue recorded', e => has(e, /\b(?:profile|hardware hash|registration)\b[^.;\n]{0,100}\b(?:not assigned|not found|not received|missing|duplicate|failed|failure)\b/i) && !successOnly(e),
  'The log records a profile or registration problem. It does not establish the complete tenant assignment state or justify deleting/reuploading a hardware hash.',
  ['Verify registration identity, target profile, group membership and assignment/delivery timing in the tenant.'],
  ['Have an authorized administrator verify registration and targeting before proposing a change.']);
rule('autopilot-network', 'Autopilot & ESP', 'Autopilot connectivity failure recorded', e => ['0x80072ee2', '0x80072ee7', '0x80072efd', '0x8024402c'].some(value => code(e, value)) || (has(e, /\b(?:dns|proxy|connectivity|connection)\b.{0,90}\b(?:failed|failure|error|unreachable|timeout|timed out)\b/i) && !successOnly(e)),
  'An Autopilot-stage request records a connectivity failure. Identify the affected endpoint and DNS/proxy response before selecting a remediation.',
  ['Compare the failing request with enrollment, profile and attestation evidence using explicit identifiers where available.'],
  ['Propose a narrowly scoped connectivity review for the recorded endpoint; do not reset networking or alter the proxy.']);

function genericSeverity(event) {
  if (successOnly(event)) return null;
  if (has(event, /\b(?:no errors?|no failures?|error(?:\s+code)?\s*[=:]?\s*0(?:x0+)?\b|failed\s*[=:]\s*(?:false|0)\b)/i) && !has(event, /\b(?:exception|denied|blocked)\b|\b(?:failed|failure)\b(?!\s*[=:]\s*(?:false|0)\b)/i)) return null;
  if (has(event, /\b(?:failed|failure|exception|fatal|denied|blocked)\b/i) || ['critical', 'error', '1', '2'].includes(text(event.level).toLowerCase())) return 'error';
  if (has(event, /\b(?:warning|warn)\b/i) || ['warning', 'warn', '3'].includes(text(event.level).toLowerCase())) return 'warning';
  if (event.codes.some(value => /^0x[89a-f][a-f0-9]{7}$/i.test(value))) return 'warning';
  return null;
}

/** Return a desktop-compatible report. Findings are observations with manual checks. */
export function analyzeRawEvents(inputEvents, sources = [], warnings = []) {
  const input = Array.isArray(inputEvents) ? inputEvents : [];
  const seenIds = new Set();
  let truncatedMessages = 0;
  const events = input.slice(0, MAX_EVENTS).filter(event => event && typeof event === 'object').map((event, index) => {
    const originalMessage = text(event.message);
    const rawMessage = boundedMessage(originalMessage);
    let uid = 'raw-' + hash(text(event.uid) || `${text(event.source)}\0${event.line ?? index}\0${rawMessage}`);
    if (seenIds.has(uid)) uid += '-' + index;
    seenIds.add(uid);
    const sanitizedMessage = sanitizeText(rawMessage);
    const message = boundedMessage(sanitizedMessage);
    if (originalMessage.length > MAX_MESSAGE || sanitizedMessage.length > MAX_MESSAGE || originalMessage.endsWith(TRUNCATION_SUFFIX)) truncatedMessages++;
    return {
      uid, source: safe(event.source) || 'Imported text', message,
      line: Number.isSafeInteger(event.line) && event.line >= 0 ? event.line : index + 1,
      timestamp: event.timestamp ? safe(event.timestamp) : null,
      event_id: event.event_id == null ? null : safe(event.event_id), provider: safe(event.provider), level: safe(event.level),
      // Classify only retained, visible evidence. A code discarded by a size
      // limit must not generate a finding whose supporting text is absent.
      category: inferCategory({ ...event, message }), codes: extractCodes(message), correlation_ids: extractIds(event, rawMessage),
      stage: inferStage(message), context: inferContext(message)
    };
  });
  const findings = [];
  const matchedEvents = new Set();
  let dropped = 0;
  const add = finding => { if (findings.length < MAX_FINDINGS) findings.push(finding); else dropped++; };
  for (const item of RULES) {
    const groups = new Map();
    for (const event of events) {
      if (event.category !== item.category || !item.test(event)) continue;
      matchedEvents.add(event.uid);
      // Same source and context, same explicit pattern; no time-based causation.
      const key = `${event.source}\0${event.context}`;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(event.uid);
    }
    for (const [group, evidence] of groups) add({
      id: 'finding-' + hash(item.key + '\0' + group), title: item.title, category: item.category,
      severity: item.severity, confidence: item.confidence,
      summary: `${evidence.length} imported event(s) independently show this pattern. Grouping does not establish a shared root cause. Review the linked evidence and proposed checks.`,
      root_cause: item.root, evidence, checks: item.checks, recommendations: item.recommendations,
      references: DOCS[item.category] ? [DOCS[item.category]] : []
    });
  }
  for (const event of events) {
    if (matchedEvents.has(event.uid)) continue;
    const severity = genericSeverity(event);
    if (!severity) continue;
    add({
      id: 'finding-' + hash('unclassified\0' + event.uid), title: severity === 'error' ? 'Error recorded; root cause unconfirmed' : 'Warning or error code requires review',
      category: event.category, severity, confidence: 'low',
      summary: 'An imported record explicitly contains an error/warning signal or an unrecognized failure code. No specific diagnostic rule establishes its cause.',
      root_cause: 'Root cause is unconfirmed from this record. The error may be a downstream symptom; inspect preceding events, the failing operation and any matching activity/app identifier.',
      evidence: [event.uid], checks: ['Review this record and preceding entries from the same operation.', 'Look up the exact error code/provider and compare assignment, policy, execution and result evidence using explicit identifiers.'],
      recommendations: ['Prepare one recommendation only after the first supported cause is verified. No repair or setting change is executed.'], references: []
    });
  }
  const reportWarnings = [...(Array.isArray(warnings) ? warnings.map(safe) : []), ...LIMITATIONS];
  if (truncatedMessages) reportWarnings.push(`${truncatedMessages} event message(s) were truncated at the ${MAX_MESSAGE}-character analysis limit or by the parser. Review the original logs for omitted evidence.`);
  if (input.length > MAX_EVENTS) reportWarnings.push(`Only the first ${MAX_EVENTS} events were analyzed; split the input to inspect the remainder.`);
  if (dropped) reportWarnings.push(`The ${MAX_FINDINGS}-finding limit was reached; additional observations were omitted. Split the input for complete review.`);
  if (!events.length) reportWarnings.push('No supported events were imported. Select readable text logs or exported event/sign-in JSON, CSV or XML.');
  else {
    if (!events.some(event => event.timestamp)) reportWarnings.push('No timestamps were found. A chronological or cross-source timeline cannot be established.');
    else if (events.some(event => !event.timestamp)) reportWarnings.push('Some events lack timestamps and cannot be placed reliably on the timeline.');
    if (!events.some(event => event.correlation_ids.length)) reportWarnings.push('No correlation/activity/device/app identifiers were found. Time proximity alone cannot establish causation.');
    if (!findings.length) reportWarnings.push('No known failure or explicit error pattern matched. This is not a clean bill of health; review complete diagnostic exports.');
    const win32 = events.filter(event => event.category === 'Win32 apps');
    if (win32.length) {
      const missing = ['assignment', 'policy', 'execution', 'result'].filter(stage => !win32.some(event => event.stage === stage));
      if (missing.length) reportWarnings.push('Win32 trace is incomplete: missing observed ' + missing.join(', ') + ' stage(s). Include targeting/policy and command, detection, dependency and context evidence.');
    }
    if (events.some(event => event.timestamp && !/(?:Z|[+-]\d{2}:?\d{2})$/i.test(event.timestamp))) reportWarnings.push('Some timestamps have no timezone. Verify device timezone before comparing local times with UTC exports.');
    if (events.some(event => event.category === 'Conditional Access')) reportWarnings.push('Local Windows logs do not establish complete tenant Conditional Access evaluation. Include relevant Entra sign-in policy and authentication details.');
    if (events.some(event => event.category === 'Windows patching')) reportWarnings.push('Update ring assignment, effective settings and complete CBS/WindowsUpdateClient/MDM history may be absent.');
    if (events.some(event => event.category === 'Autopilot & ESP')) reportWarnings.push('Confirm Autopilot profile assignment, ESP phase and blocking app details; snippets may omit the initial blocker.');
  }
  return {
    started_at: new Date().toISOString(), synthetic: false,
    report_metadata: { application: 'Windows Diagnostics', analyzer: 'Local browser text analysis', managed_by: 'Dibyendu', analysis_version: '1', synthetic: false },
    sources: unique([...(Array.isArray(sources) ? sources.slice(0, 1000).map(source => safe(typeof source === 'string' ? source : source?.name)) : []), ...events.map(event => event.source)].filter(Boolean)),
    warnings: unique(reportWarnings.filter(Boolean)).slice(0, 1100), events, findings
  };
}
