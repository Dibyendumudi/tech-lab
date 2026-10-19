/** Browser-local file decoding, raw evidence analysis and report validation. */
import { parseReport, sanitizeText } from './analytics.js';
import { parseRawLog } from './raw-parsers.js';
import { analyzeRawEvents } from './raw-analysis.js';

export const IMPORT_LIMITS = Object.freeze({ files: 20, fileBytes: 20 * 1024 * 1024, totalBytes: 50 * 1024 * 1024, rawEvents: 50000, events: 100000, findings: 3000 });
export const IMPORT_EXTENSIONS = Object.freeze(['.log', '.txt', '.json', '.jsonl', '.ndjson', '.csv', '.xml']);
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const extension = name => /\.[^.\\/]+$/.exec(String(name).toLowerCase())?.[0] || '';

function fingerprint(value) {
  let a = 2166136261, b = 2246822519;
  for (let i = 0; i < value.length; i++) { a = Math.imul(a ^ value.charCodeAt(i), 16777619); b = Math.imul(b ^ value.charCodeAt(i), 3266489917); }
  return (a >>> 0).toString(16).padStart(8, '0') + (b >>> 0).toString(16).padStart(8, '0');
}

function formatError(name) {
  const ext = extension(name);
  if (ext === '.cab') return new Error('CAB is an archive. Extract it on Windows, then select its readable logs. Convert any EVTX files to event JSON/XML first.');
  if (ext === '.evtx') return new Error('EVTX is a binary event log. Export or convert its events to JSON/XML on Windows before importing.');
  if (ext === '.etl') return new Error('ETL is a binary trace. Decode it with Windows tracing tools and import a readable text export.');
  return new Error('Select .log, .txt, .json, .jsonl, .ndjson, .csv or Windows event .xml files.');
}

/** UTF-8 / UTF-16 Windows exports; browser MIME guesses are deliberately ignored. */
export function decodeLogBytes(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (!bytes.length) throw new Error('The file is empty.');
  const signature = Array.from(bytes.slice(0, 8), byte => String.fromCharCode(byte)).join('');
  if (/^(MSCF|ElfFile\x00|PK\x03\x04|MZ)/.test(signature) || (bytes[0] === 0x1f && bytes[1] === 0x8b)) {
    throw new Error('This file contains a binary archive, executable or event log. Extract or convert it to a supported readable log; changing the extension does not convert it.');
  }
  if ((bytes[0] === 0xff && bytes[1] === 0xfe && bytes[2] === 0 && bytes[3] === 0) || (bytes[0] === 0 && bytes[1] === 0 && bytes[2] === 0xfe && bytes[3] === 0xff)) {
    throw new Error('UTF-32 is not supported. Save a copy as UTF-8 or UTF-16 and import that copy.');
  }
  let encoding = 'utf-8', start = 0;
  const warnings = [];
  if (bytes[0] === 0xff && bytes[1] === 0xfe) { encoding = 'utf-16le'; start = 2; }
  else if (bytes[0] === 0xfe && bytes[1] === 0xff) { encoding = 'utf-16be'; start = 2; }
  else if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) start = 3;
  else {
    const pairs = Math.floor(Math.min(bytes.length, 1024) / 2);
    let even = 0, odd = 0;
    for (let i = 0; i < pairs * 2; i += 2) { even += bytes[i] === 0; odd += bytes[i + 1] === 0; }
    if (pairs > 2 && odd / pairs > .3 && even / pairs < .05) encoding = 'utf-16le';
    else if (pairs > 2 && even / pairs > .3 && odd / pairs < .05) encoding = 'utf-16be';
  }
  let text;
  try { text = new TextDecoder(encoding, { fatal: true }).decode(bytes.subarray(start)); }
  catch {
    if (encoding !== 'utf-8') throw new Error('The UTF-16 text is incomplete or invalid. Export a fresh text copy.');
    text = new TextDecoder('windows-1252').decode(bytes.subarray(start));
    warnings.push('Text was decoded using Windows-1252 because it was not valid UTF-8. Verify non-English characters against the original log.');
  }
  const sample = text.slice(0, 65536);
  if (sample.includes('\0') || (sample.match(/[\x01-\x08\x0b\x0c\x0e-\x1f]/g) || []).length > Math.max(2, sample.length * .01)) {
    throw new Error('The content appears binary rather than a readable log. Export its records to text, JSON or event XML first.');
  }
  if (!text.trim()) throw new Error('The file contains no readable records.');
  return { text: text.replace(/^\uFEFF/, ''), encoding, warnings };
}

function reportCandidate(value) {
  return isObject(value) && ('findings' in value || 'report_metadata' in value || 'scenario' in value || ('started_at' in value && 'sources' in value));
}

/** Returns only canonical, redacted reports. No fetch, storage or endpoint calls. */
export async function importDiagnosticFiles(selection) {
  const files = Array.from(selection || []);
  if (!files.length) return { reports: [], errors: [], notices: [] };
  if (files.length > IMPORT_LIMITS.files) throw new Error('Select at most 20 log files or diagnostic reports at a time.');
  if (files.some(file => !Number.isFinite(file.size) || file.size < 0 || file.size > IMPORT_LIMITS.fileBytes) || files.reduce((sum, file) => sum + file.size, 0) > IMPORT_LIMITS.totalBytes) {
    throw new Error('Import limit: 20 MiB per file and 50 MiB per selection. Choose a smaller diagnostic window.');
  }
  const reports = [], errors = [], notices = [], rawEvents = [], rawSources = [], rawWarnings = [], seen = new Set();
  let eventCount = 0, findingCount = 0;
  for (const file of files) {
    const label = sanitizeText(String(file.name || 'Unnamed file'));
    try {
      if (!IMPORT_EXTENSIONS.includes(extension(file.name))) throw formatError(file.name);
      const decoded = decodeLogBytes(await file.arrayBuffer());
      const fileId = fingerprint(String(file.name) + '\0' + decoded.text);
      if (seen.has(fileId)) { notices.push(`${label}: duplicate file skipped.`); continue; }
      let raw;
      if (extension(file.name) === '.json') {
        try { raw = JSON.parse(decoded.text); }
        catch { throw new Error('Invalid JSON. Export a valid JSON document, or use .jsonl/.ndjson for one JSON record per line.'); }
      }
      if (reportCandidate(raw)) {
        const report = parseReport(raw, label);
        if (eventCount + report.events.length + rawEvents.length > IMPORT_LIMITS.events || findingCount + report.findings.length > IMPORT_LIMITS.findings - (rawEvents.length ? 1000 : 0)) {
          throw new Error('Selection exceeds the evidence or finding limit. Import a smaller set of reports.');
        }
        report.warnings.push(...decoded.warnings.map(sanitizeText));
        reports.push(report); eventCount += report.events.length; findingCount += report.findings.length;
      } else {
        const parsed = parseRawLog(decoded.text, String(file.name), { maxEvents: IMPORT_LIMITS.rawEvents });
        if (!parsed.events.length) throw new Error('No readable event records were found in this file.');
        if (rawEvents.length + parsed.events.length > IMPORT_LIMITS.rawEvents || eventCount + rawEvents.length + parsed.events.length > IMPORT_LIMITS.events || findingCount > IMPORT_LIMITS.findings - 1000) {
          throw new Error('Raw evidence is limited to 50,000 records per selection. Select fewer files or a narrower export.');
        }
        rawEvents.push(...parsed.events.map(event => ({ ...event, uid: `${fileId}:${event.uid}` })));
        rawSources.push(String(file.name));
        rawWarnings.push(...decoded.warnings.map(warning => `${label}: ${warning}`), ...parsed.warnings.map(warning => `${label}: ${warning}`));
      }
      seen.add(fileId);
    } catch (error) { errors.push(`${label}: ${sanitizeText(error.message || 'Could not read this file.')}`); }
    await new Promise(resolve => setTimeout(resolve, 0));
  }
  if (rawEvents.length) {
    try {
      const analysis = analyzeRawEvents(rawEvents, [...new Set(rawSources)], rawWarnings);
      reports.push(parseReport(analysis, rawSources.length === 1 ? rawSources[0] : `Raw logs · ${rawSources.length} files`));
    } catch (error) { errors.push(`Raw log analysis: ${sanitizeText(error.message || 'Could not analyze the selected records.')}`); }
  }
  return { reports: [...new Map(reports.map(report => [report.id, report])).values()], errors, notices };
}

/** Module workers keep large Windows text exports off the interface thread. */
export function readDiagnosticFiles(files) {
  if (typeof Worker === 'undefined') return importDiagnosticFiles(files);
  return new Promise((resolve, reject) => {
    let worker, timeout;
    const finish = (callback, value) => { clearTimeout(timeout); worker?.terminate(); callback(value); };
    try {
      worker = new Worker(new URL('./import-worker.js', import.meta.url), { type: 'module' });
      timeout = setTimeout(() => finish(reject, new Error('Import timed out. Select fewer files or a smaller export.')), 180000);
      worker.onmessage = event => event.data.error ? finish(reject, new Error(event.data.error)) : finish(resolve, event.data.result);
      worker.onerror = () => finish(reject, new Error('The local import worker could not start. Refresh the page and try again. No files were uploaded.'));
      worker.postMessage({ files: Array.from(files) });
    } catch { finish(reject, new Error('The browser could not start local analysis. Refresh the page and try again.')); }
  });
}
