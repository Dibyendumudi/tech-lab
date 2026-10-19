/**
 * Local executive analytics for Windows Diagnostics. No device calls or mutations.
 *
 * parseReport() accepts the desktop JSON export or the browser workflow export;
 * sampleReports() adapts the existing scenarios to that same canonical contract.
 * All identifiers are report-scoped. Strings remain text, never trusted markup.
 *
 * buildDashboard() returns filtered events/findings plus metrics, domainCounts,
 * severityCounts, stageCounts, timeline, sourceCoverage, priorityFindings,
 * coverage, dateRange and notes. Counts describe supplied records, not devices,
 * health, successful remediations or tenant-wide policy compliance.
 *
 * Category filters use each record's category. Dates are UTC, inclusive, and use
 * evidence timestamps (never report generation time). With a severity filter,
 * events are restricted to evidence of the selected findings. Query matches a
 * finding or its linked evidence, retaining matching evidence in the event view.
 * Untimed findings remain visible only when no date range is selected.
 */
export const CATEGORIES = Object.freeze(['Win32 apps', 'Windows patching', 'Conditional Access', 'Autopilot & ESP', 'Enterprise']);
export const STAGES = Object.freeze(['assignment', 'policy', 'execution', 'result', 'unknown']);
const MAX_EVENTS = 50000;
const MAX_FINDINGS = 1000;
const MAX_TEXT = 20000;
const OWN = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const str = value => typeof value === 'string' ? value.slice(0, MAX_TEXT) : '';

// Stable, deterministic pseudonyms keep repeated identifiers linkable locally.
// This heuristic is not a guarantee of anonymization; review before sharing.
function hash(value) {
  let a = 2166136261, b = 2246822519;
  for (let i = 0; i < value.length; i++) {
    a = Math.imul(a ^ value.charCodeAt(i), 16777619);
    b = Math.imul(b ^ value.charCodeAt(i), 3266489917);
  }
  return (a >>> 0).toString(16).padStart(8, '0') + (b >>> 0).toString(16).padStart(8, '0');
}
const pseudonym = (kind, value) => `[${kind}:${hash(value.toLowerCase()).slice(0, 10)}]`;
export function sanitizeText(value) {
  return str(value)
    .replace(/\bBearer\s+[A-Za-z0-9._~+/=-]+/gi, '[redacted bearer token]')
    .replace(/\bBasic\s+[A-Za-z0-9+/=]+/gi, '[redacted basic credentials]')
    .replace(/(["']?\b(?:authorization|password|passwd|pwd|client[_ -]?secret|access[_ -]?token|refresh[_ -]?token|api[_ -]?key|token|secret|sig)["']?\s*[:=]\s*)(?:"(?:\\.|[^"\\\r\n])*"|'(?:\\.|[^'\\\r\n])*'|[^\s,;}]+)/gi, '$1[redacted]')
    .replace(/(["']?\b(?:correlation[ _-]?id|request[ _-]?id|session[ _-]?id|activity[ _-]?id|related[ _-]?activity[ _-]?id|device[ _-]?(?:id|name)|tenant[ _-]?id|app(?:lication)?[ _-]?id|object[ _-]?id|user[ _-]?(?:id|name|display[ _-]?name|principal[ _-]?name)|upn|account[ _-]?name|computer(?:[ _-]?name)?|machine[ _-]?name|hostname|serial[ _-]?number|hardware[ _-]?hash|display[ _-]?name|service[ _-]?principal[ _-]?id)["']?\s*[:=]\s*)(?:"((?:\\.|[^"\\\r\n])*)"|'((?:\\.|[^'\\\r\n])*)'|([^\s,;}]+))/gi, (match, prefix, quoted, single, bare) => {
      let original = quoted ?? single ?? bare;
      if (quoted !== undefined) { try { original = JSON.parse('"' + quoted + '"'); } catch { /* Keep the bounded literal if it is not a JSON string. */ } }
      return original.startsWith('[') || /^(?:true|false|null|none|unknown|n\/a)$/i.test(original) ? match : prefix + pseudonym('id', original);
    })
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[redacted token]')
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, value => pseudonym('email', value))
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi, value => pseudonym('id', value))
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, value => value.split('.').every(part => Number(part) <= 255) ? pseudonym('ip', value) : value)
    .replace(/(?<![\w:])(?:[0-9a-f]{1,4}:){4,}[0-9a-f:]*|(?<![\w:])(?:[0-9a-f]{1,4}:)*:[0-9a-f:]*:[0-9a-f:]+/gi, value => pseudonym('ip', value))
    .replace(/(\b[A-Z]:[\\/]Users[\\/]|\/(?:Users|home)\/)([^\\/\s"'<>]+)/gi, (match, prefix, user) => user.startsWith('[') ? match : prefix + pseudonym('user', user));
}
function textList(value) {
  return Array.isArray(value) ? value.filter(item => typeof item === 'string').slice(0, 1000).map(sanitizeText) : [];
}
function rawId(value, fallback) {
  return (typeof value === 'string' && value.length > 0 ? value.slice(0, 1000) : fallback);
}
function scopedId(reportId, kind, value) {
  // Hash the raw ID so sensitive IDs never appear in DOM IDs or exported links.
  return `${reportId}:${kind}:${hash(value)}`;
}
function normalizeCategory(value) {
  const category = str(value).trim().toLowerCase();
  if (['win32 apps', 'win32 app deployment', 'win32', 'win32 applications'].includes(category)) return CATEGORIES[0];
  if (['windows patching', 'windows updates', 'patching', 'updates'].includes(category)) return CATEGORIES[1];
  if (['conditional access', 'conditional-access'].includes(category)) return CATEGORIES[2];
  if (['windows autopilot & esp', 'autopilot & esp', 'autopilot', 'autopilot and esp'].includes(category)) return CATEGORIES[3];
  return CATEGORIES[4];
}
function normalizeSeverity(value) {
  const severity = str(value).trim().toLowerCase();
  if (['critical', 'high', 'error'].includes(severity)) return 'error';
  if (['warning', 'warn', 'medium', 'moderate'].includes(severity)) return 'warning';
  return 'info';
}
function timestamp(value) {
  const input = str(value).trim();
  // Unspecified local time cannot be placed on a cross-report UTC timeline.
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})$/i.exec(input);
  if (!match) return null;
  const [, year, month, day, hour, minute, second] = match.map(Number);
  const daysInMonth = new Date(Date.UTC(year, month, 0)).getUTCDate();
  if (month < 1 || month > 12 || day < 1 || day > daysInMonth || hour > 23 || minute > 59 || second > 59) return null;
  const number = Date.parse(input);
  return Number.isFinite(number) ? new Date(number).toISOString() : null;
}
function schemaError(message) { throw new Error(message); }

/** Import only the known desktop/browser JSON report structures. */
export function parseReport(raw, label = 'Imported report') {
  if (!isObject(raw) || !OWN(raw, 'events') || !OWN(raw, 'findings') || !Array.isArray(raw.events) || !Array.isArray(raw.findings)) {
    schemaError('Choose a Windows Diagnostics JSON report containing events and findings arrays.');
  }
  const meta = isObject(raw.report_metadata) ? raw.report_metadata : {};
  const scenario = isObject(raw.scenario) ? raw.scenario : {};
  const browser = typeof scenario.id === 'string' && typeof scenario.category === 'string';
  const native = typeof raw.started_at === 'string' || meta.application === 'Windows Diagnostics' ||
    (Array.isArray(raw.sources) && raw.events.some(event => isObject(event) && OWN(event, 'uid') && OWN(event, 'category')));
  if (!browser && !native) schemaError('This JSON structure is not a recognized Windows Diagnostics report export.');
  if (raw.events.length > MAX_EVENTS || raw.findings.length > MAX_FINDINGS) schemaError(`A report may contain at most ${MAX_EVENTS.toLocaleString('en-US')} events and ${MAX_FINDINGS.toLocaleString('en-US')} findings.`);
  for (const event of raw.events) {
    if (!isObject(event) || typeof event.message !== 'string' || typeof event.source !== 'string' || (typeof event.uid !== 'string' && typeof event.id !== 'string')) {
      schemaError('Every event must include a text ID, source and message.');
    }
  }
  for (const finding of raw.findings) {
    if (!isObject(finding) || typeof finding.id !== 'string' || typeof finding.title !== 'string') schemaError('Every finding must include a text ID and title.');
  }
  // Generation time is deliberately excluded from the report identity: exporting
  // the same evidence twice should not double-count it in the dashboard.
  const identity = JSON.stringify({ scenario: scenario.id || '', events: raw.events, findings: raw.findings, sources: raw.sources || [] });
  const id = `report-${hash(identity)}`;
  const warnings = textList(raw.warnings);
  const eventIds = new Map();
  const events = raw.events.map((event, index) => {
    const originId = rawId(event.uid ?? event.id, `event-${index + 1}`);
    if (eventIds.has(originId)) schemaError('Duplicate event IDs in a report prevent reliable evidence linking.');
    const eventId = scopedId(id, 'event', originId);
    eventIds.set(originId, eventId);
    const stage = str(event.stage).toLowerCase();
    const originalTimestamp = str(event.timestamp ?? event.time);
    const utcTimestamp = timestamp(originalTimestamp);
    return {
      id: eventId, reportId: id, timestamp: utcTimestamp,
      rawTimestamp: utcTimestamp ? null : sanitizeText(originalTimestamp) || null,
      timestampIssue: !originalTimestamp || utcTimestamp ? null : /(?:Z|[+-]\d{2}:?\d{2})$/i.test(originalTimestamp) ? 'invalid timestamp' : 'timezone unspecified',
      source: sanitizeText(event.source) || 'Unknown source', category: normalizeCategory(event.category ?? scenario.category),
      message: sanitizeText(event.message), line: Number.isSafeInteger(event.line) && event.line >= 0 ? event.line : null,
      codes: textList(Array.isArray(event.codes) ? event.codes : typeof event.code === 'string' ? [event.code] : []),
      stage: STAGES.includes(stage) ? stage : 'unknown', context: sanitizeText(event.context) || 'Unknown',
      correlationIds: textList(Array.isArray(event.correlation_ids) ? event.correlation_ids : Array.isArray(event.correlationIds) ? event.correlationIds : typeof event.correlationId === 'string' ? [event.correlationId] : []).map(value => value.startsWith('[') ? value : pseudonym('id', value))
    };
  });
  let orphanCount = 0, unknownSeverityCount = 0;
  const findingIds = new Set();
  const findings = raw.findings.map((finding, index) => {
    const originId = rawId(finding.id, `finding-${index + 1}`);
    if (findingIds.has(originId)) schemaError('Duplicate finding IDs are not supported in one report.');
    findingIds.add(originId);
    const refs = Array.isArray(finding.evidence) ? finding.evidence : Array.isArray(finding.evidenceIds) ? finding.evidenceIds : [];
    const evidenceIds = [];
    for (const ref of refs) {
      if (typeof ref !== 'string' || !eventIds.has(ref)) orphanCount++;
      else if (!evidenceIds.includes(eventIds.get(ref))) evidenceIds.push(eventIds.get(ref));
    }
    if (!['critical', 'high', 'error', 'warning', 'warn', 'medium', 'moderate', 'info', 'information', 'informational', 'low'].includes(str(finding.severity).toLowerCase())) unknownSeverityCount++;
    return {
      id: scopedId(id, 'finding', originId), reportId: id, title: sanitizeText(finding.title),
      category: normalizeCategory(finding.category ?? scenario.category), severity: normalizeSeverity(finding.severity),
      confidence: sanitizeText(finding.confidence) || 'Unknown', summary: sanitizeText(finding.summary ?? finding.observation),
      rootCause: sanitizeText(finding.root_cause ?? finding.rootCause), evidenceIds,
      checks: textList(finding.checks), recommendations: textList(finding.recommendations)
    };
  });
  if (orphanCount) warnings.push(`${orphanCount} evidence reference${orphanCount === 1 ? '' : 's'} could not be linked within this report.`);
  if (unknownSeverityCount) warnings.push(`${unknownSeverityCount} finding${unknownSeverityCount === 1 ? '' : 's'} had no recognized severity and appear under informational findings; inspect the source report.`);
  const hasExpectedInventory = browser && Array.isArray(raw.sources) && raw.sources.length > 0 && raw.sources.every(source => isObject(source) && typeof source.name === 'string' && typeof source.available === 'boolean');
  const sourceMap = new Map();
  for (const source of Array.isArray(raw.sources) ? raw.sources.slice(0, 1000) : []) {
    const name = sanitizeText(typeof source === 'string' ? source : isObject(source) ? source.name : '');
    if (!name) continue;
    sourceMap.set(name, { name, available: isObject(source) && typeof source.available === 'boolean' ? source.available : null, note: sanitizeText(source.note) });
  }
  for (const event of events) {
    const source = sourceMap.get(event.source);
    // A source with records is available even if contradictory input metadata
    // marked it missing. Preserve the contradiction in the warning list.
    if (source?.available === false) warnings.push(`Source metadata marked ${event.source} unavailable, but the report includes records from it.`);
    sourceMap.set(event.source, { name: event.source, available: true, note: source?.note || '' });
  }
  return {
    id, label: sanitizeText(label) || sanitizeText(scenario.title) || 'Imported report',
    synthetic: raw.synthetic === true || meta.synthetic === true || browser,
    generatedAt: timestamp(raw.started_at ?? meta.generated_at), events, findings,
    sources: [...sourceMap.values()], hasExpectedInventory, warnings
  };
}

/** Exactly the four supplied synthetic scenarios, never invented outcomes. */
export function sampleReports(scenarios) {
  if (!Array.isArray(scenarios)) return [];
  return scenarios.map(scenario => parseReport({
    report_metadata: { application: 'Windows Diagnostics', synthetic: true },
    scenario: { id: scenario.id, category: scenario.category, title: scenario.title },
    sources: scenario.expectedSources, events: scenario.events, findings: scenario.findings
  }, scenario.shortLabel || scenario.title));
}

function dateBoundary(value, end = false) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return null;
  const iso = timestamp(`${value}T${end ? '23:59:59.999' : '00:00:00'}Z`);
  return iso ? Date.parse(iso) : null;
}
function eventText(event) {
  return [event.source, event.category, event.message, event.stage, event.context, ...event.codes, ...event.correlationIds].join(' ').toLowerCase();
}
function findingText(finding) {
  return [finding.title, finding.category, finding.severity, finding.confidence, finding.summary, finding.rootCause, ...finding.checks, ...finding.recommendations].join(' ').toLowerCase();
}

/** Pure, deterministic summaries of canonical reports. See module contract. */
export function buildDashboard(inputReports, filters = {}) {
  const reports = [...new Map((Array.isArray(inputReports) ? inputReports : []).map(report => [report.id, report])).values()];
  const allEvents = reports.flatMap(report => report.events);
  const allFindings = reports.flatMap(report => report.findings);
  const byId = new Map(allEvents.map(event => [event.id, event]));
  const reportMap = new Map(reports.map(report => [report.id, report]));
  const category = !filters.category || filters.category === 'all' ? 'all' : normalizeCategory(filters.category);
  const severity = ['error', 'warning', 'info'].includes(filters.severity) ? filters.severity : 'all';
  const query = str(filters.query).trim().toLowerCase();
  const from = dateBoundary(filters.from), to = dateBoundary(filters.to, true);
  const dateFiltered = from !== null || to !== null;
  const categoryMatch = item => category === 'all' || item.category === category;
  const dateMatch = event => !dateFiltered || (event.timestamp !== null && (from === null || Date.parse(event.timestamp) >= from) && (to === null || Date.parse(event.timestamp) <= to));
  const eligibleEvents = allEvents.filter(event => categoryMatch(event) && dateMatch(event));
  const eligibleIds = new Set(eligibleEvents.map(event => event.id));
  const evidenceFor = finding => finding.evidenceIds.map(id => byId.get(id)).filter(event => event && event.reportId === finding.reportId);
  const findings = allFindings.filter(finding => {
    if (!categoryMatch(finding) || (severity !== 'all' && finding.severity !== severity)) return false;
    const evidence = evidenceFor(finding);
    if (dateFiltered && !evidence.some(event => dateMatch(event))) return false;
    return !query || findingText(finding).includes(query) || evidence.some(event => eligibleIds.has(event.id) && eventText(event).includes(query));
  });
  const selectedEvidence = new Set(findings.flatMap(finding => finding.evidenceIds));
  const events = eligibleEvents.filter(event => {
    if (severity !== 'all') return selectedEvidence.has(event.id);
    return !query || eventText(event).includes(query) || selectedEvidence.has(event.id);
  });
  const activeIds = new Set([...events, ...findings].map(item => item.reportId));
  if (category === 'all' && severity === 'all' && !dateFiltered && !query) reports.forEach(report => activeIds.add(report.id));
  const activeReports = reports.filter(report => activeIds.has(report.id));
  const severityCounts = { error: 0, warning: 0, info: 0 };
  const domainCounts = CATEGORIES.map(category => ({ category, error: 0, warning: 0, info: 0, total: 0, eventCount: 0 }));
  for (const finding of findings) {
    severityCounts[finding.severity]++;
    const domain = domainCounts.find(domain => domain.category === finding.category);
    domain[finding.severity]++; domain.total++;
  }
  for (const event of events) domainCounts.find(domain => domain.category === event.category).eventCount++;
  const stageCounts = STAGES.map(stage => ({ stage, count: events.filter(event => event.stage === stage).length }));
  const times = events.filter(event => event.timestamp).map(event => Date.parse(event.timestamp));
  const timeBounds = times.reduce((range, time) => [Math.min(range[0], time), Math.max(range[1], time)], [Infinity, -Infinity]);
  const span = times.length ? timeBounds[1] - timeBounds[0] : 0;
  const timelineGranularity = span <= 48 * 60 * 60 * 1000 ? 'hour' : span <= 90 * 86400000 ? 'day' : 'month';
  const buckets = new Map();
  const emptyBucket = key => ({ key, label: timelineGranularity === 'hour' ? `${key.slice(5, 10)} ${key.slice(11, 16)}` : timelineGranularity === 'day' ? key.slice(5, 10) : key.slice(0, 7), events: 0, results: 0 });
  for (const event of events) {
    if (!event.timestamp) continue;
    const date = new Date(event.timestamp);
    if (timelineGranularity === 'hour') date.setUTCMinutes(0, 0, 0);
    else if (timelineGranularity === 'day') date.setUTCHours(0, 0, 0, 0);
    else { date.setUTCDate(1); date.setUTCHours(0, 0, 0, 0); }
    const key = date.toISOString();
    if (!buckets.has(key)) buckets.set(key, emptyBucket(key));
    const bucket = buckets.get(key); bucket.events++; if (event.stage === 'result') bucket.results++;
  }
  // Fill observed-range gaps only when bounded. An extreme imported date range
  // never allocates an unbounded sequence of empty buckets.
  if (buckets.size > 1) {
    const keys = [...buckets.keys()].sort();
    const first = new Date(keys[0]), last = new Date(keys.at(-1));
    const bucketCount = timelineGranularity === 'hour' ? (last - first) / 3600000 + 1 : timelineGranularity === 'day' ? (last - first) / 86400000 + 1 : (last.getUTCFullYear() - first.getUTCFullYear()) * 12 + last.getUTCMonth() - first.getUTCMonth() + 1;
    const limit = { hour: 49, day: 91, month: 120 }[timelineGranularity];
    if (bucketCount <= limit) {
      const cursor = new Date(first);
      for (let i = 0; i < bucketCount; i++) {
        const key = cursor.toISOString();
        if (!buckets.has(key)) buckets.set(key, emptyBucket(key));
        if (timelineGranularity === 'hour') cursor.setUTCHours(cursor.getUTCHours() + 1);
        else if (timelineGranularity === 'day') cursor.setUTCDate(cursor.getUTCDate() + 1);
        else cursor.setUTCMonth(cursor.getUTCMonth() + 1);
      }
    }
  }
  const sourceMap = new Map();
  for (const report of activeReports) for (const source of report.sources) {
    if (!sourceMap.has(source.name)) sourceMap.set(source.name, { name: source.name, eventCount: 0, reportIds: new Set(), available: null });
    const entry = sourceMap.get(source.name); entry.reportIds.add(report.id);
    if (source.available === true || (source.available === false && entry.available !== true)) entry.available = source.available;
  }
  for (const event of events) {
    if (!sourceMap.has(event.source)) sourceMap.set(event.source, { name: event.source, eventCount: 0, reportIds: new Set(), available: true });
    const entry = sourceMap.get(event.source); entry.eventCount++; entry.reportIds.add(event.reportId); entry.available = true;
  }
  const sourceCoverage = [...sourceMap.values()].map(source => ({ name: source.name, eventCount: source.eventCount, reportCount: source.reportIds.size, available: source.available })).sort((a, b) => b.eventCount - a.eventCount || a.name.localeCompare(b.name));
  const missingTimestampEvents = allEvents.filter(event => event.timestamp === null).length;
  const missingTimestampFindings = allFindings.filter(finding => !evidenceFor(finding).some(event => event.timestamp)).length;
  const sourceTimes = allEvents.filter(event => event.timestamp).map(event => event.timestamp).sort();
  const notes = [
    'Counts describe supplied diagnostic records and reported findings; they are not a measure of fleet size, device health or completed resolutions.',
    'Timeline buckets count recorded events and result-stage records. A result record can describe success, failure or an unknown outcome.',
    'Sources list the report inventory; a listed source can have zero records in the current filter.'
  ];
  if (severity !== 'all') notes.push('A severity filter restricts event counts to evidence linked to the selected findings.');
  if (dateFiltered) notes.push('Date filtering uses UTC evidence timestamps; findings without timed evidence are excluded.');
  if (missingTimestampEvents || missingTimestampFindings) notes.push(`${missingTimestampEvents} event(s) cannot be placed on the UTC timeline; ${missingTimestampFindings} finding(s) have no timed evidence. Local or unspecified timestamps are not converted automatically.`);
  const importedReports = reports.filter(report => !report.synthetic).length;
  const syntheticReports = reports.length - importedReports;
  if (syntheticReports && importedReports) notes.push('This view includes both synthetic samples and imported reports. Use a separate dataset for operational decisions.');
  const expectedInventoryKnown = activeReports.length > 0 && activeReports.every(report => report.hasExpectedInventory === true);
  if (activeReports.some(report => !report.hasExpectedInventory)) notes.push('Native report source lists are an observed inventory, not an expected-source checklist. Listed-only files may be missing, unsupported or contain no recognized records; a coverage percentage cannot be established.');
  const coverage = {
    expectedInventoryKnown,
    available: sourceCoverage.filter(source => source.available === true).length,
    total: sourceCoverage.length,
    missing: sourceCoverage.filter(source => source.available === false).length,
    listedOnly: sourceCoverage.filter(source => source.available === null).length,
    syntheticReports, importedReports, missingTimestampEvents, missingTimestampFindings,
    note: reports.length === 0 ? 'No diagnostic reports loaded.' : importedReports ? `${importedReports} imported report(s)${syntheticReports ? ` and ${syntheticReports} synthetic sample(s)` : ''}. Scope is limited to the provided report inventory.` : 'Synthetic sample data only. No endpoint or tenant is connected.'
  };
  return {
    reports: activeReports, events, findings,
    metrics: { reportsCount: activeReports.length, eventsCount: events.length, findingsCount: findings.length, priorityCount: severityCounts.error, categoriesCount: domainCounts.filter(domain => domain.total || domain.eventCount).length, availableSourcesCount: coverage.available },
    domainCounts, severityCounts, stageCounts,
    timeline: [...buckets.values()].sort((a, b) => a.key.localeCompare(b.key)), timelineGranularity,
    sourceCoverage,
    priorityFindings: [...findings].sort((a, b) => ({ error: 0, warning: 1, info: 2 }[a.severity] - { error: 0, warning: 1, info: 2 }[b.severity])).map(finding => ({ ...finding, events: evidenceFor(finding).filter(event => eligibleIds.has(event.id)), reportLabel: reportMap.get(finding.reportId)?.label || 'Imported report' })),
    coverage, dateRange: { from: sourceTimes[0]?.slice(0, 10) || '', to: sourceTimes.at(-1)?.slice(0, 10) || '' },
    notes, filters: { category, severity, from: from === null ? '' : filters.from, to: to === null ? '' : filters.to, query: str(filters.query).trim() }
  };
}
