/** Browser-local file decoding, raw evidence analysis and report validation. */
import { parseReport, sanitizeText } from './analytics.js';
import { parseRawLog } from './raw-parsers.js';
import { analyzeRawEvents } from './raw-analysis.js';
import { inspectCabinet, CAB_LIMITS } from './cab-format.js';
import { extractCabEntries } from './cab-extractor.js';

export const IMPORT_LIMITS = Object.freeze({ files: 20, fileBytes: 20 * 1024 * 1024, totalBytes: 50 * 1024 * 1024, rawEvents: 50000, events: 100000, findings: 3000 });
export const IMPORT_EXTENSIONS = Object.freeze(['.cab', '.log', '.txt', '.json', '.jsonl', '.ndjson', '.csv', '.xml']);
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const extension = name => /\.[^.\\/]+$/.exec(String(name).toLowerCase())?.[0] || '';

function fingerprint(value) {
  let a = 2166136261, b = 2246822519;
  for (let i = 0; i < value.length; i++) { a = Math.imul(a ^ value.charCodeAt(i), 16777619); b = Math.imul(b ^ value.charCodeAt(i), 3266489917); }
  return (a >>> 0).toString(16).padStart(8, '0') + (b >>> 0).toString(16).padStart(8, '0');
}

function formatError(name) {
  const ext = extension(name);
  if (ext === '.evtx') return new Error('EVTX is a binary event log. Export or convert its events to JSON/XML on Windows before importing.');
  if (ext === '.etl') return new Error('ETL is a binary trace. Decode it with Windows tracing tools and import a readable text export.');
  return new Error('Select a CAB archive, .log, .txt, .json, .jsonl, .ndjson, .csv or Windows event .xml files.');
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
  if (!files.length) return { reports: [], errors: [], notices: [], archives: [] };
  const hasCab = files.some(file => extension(file.name) === '.cab');
  const rejectSelection = message => {
    if (!hasCab) throw new Error(message);
    return { reports: [], errors: [message], notices: [], archives: files.filter(file => extension(file.name) === '.cab').slice(0, IMPORT_LIMITS.files).map(file => ({ name: sanitizeText(file.name), entryCount: 0, analyzed: 0, partial: 0, skipped: 0, failed: 0, duplicates: 0, expandedBytes: 0, complete: false, entries: [], error: 'Selection was rejected before reading archive contents. ' + message })) };
  };
  if (files.length > IMPORT_LIMITS.files) return rejectSelection('Select at most 20 log files, CAB archives or diagnostic reports at a time. Archive contents do not count against this selection limit.');
  if (files.some(file => !Number.isFinite(file.size) || file.size < 0 || file.size > (extension(file.name) === '.cab' ? CAB_LIMITS.fileBytes : IMPORT_LIMITS.fileBytes)) || files.reduce((sum, file) => sum + file.size, 0) > (hasCab ? 150 * 1024 * 1024 : IMPORT_LIMITS.totalBytes)) {
    return rejectSelection('Import limit: 100 MiB per CAB, 20 MiB per readable file; 150 MiB combined when selecting CABs, otherwise 50 MiB combined.');
  }
  const reports = [], errors = [], notices = [], archives = [], rawEvents = [], rawSources = [], rawWarnings = [], seen = new Set(), seenReports = new Set(), seenArchives = new Set(), unavailableSources = [];
  const archiveSummaries = [], archiveDetails = [];
  let eventCount = 0, findingCount = 0, cabEntries = 0, cabExpandedBytes = 0;

  async function readEvidence(bytes, source) {
    const label = sanitizeText(source), decoded = decodeLogBytes(bytes);
    const fileId = fingerprint(source + '\0' + decoded.text);
    if (seen.has(fileId)) return { status: 'duplicate', eventCount: 0, reason: 'Identical source content was already included in this selection.' };
    let raw;
    if (extension(source) === '.json') {
      try { raw = JSON.parse(decoded.text); }
      catch { throw new Error('Invalid JSON. Use .jsonl/.ndjson for one JSON record per line.'); }
    }
    let count, partial = false;
    if (reportCandidate(raw)) {
      const report = parseReport(raw, label);
      if (seenReports.has(report.id)) return { status: 'duplicate', eventCount: 0, reason: 'An identical diagnostic report is already included in this selection.' };
      if (reports.length >= 100) throw new Error('The selection reached the 100-report limit. This report was not loaded.');
      if (eventCount + report.events.length + rawEvents.length > IMPORT_LIMITS.events || findingCount + report.findings.length > IMPORT_LIMITS.findings - (rawEvents.length ? 1000 : 0)) {
        throw new Error('Selection exceeds the evidence or finding limit. Import a smaller set of reports.');
      }
      report.warnings.push(...decoded.warnings.map(sanitizeText));
      reports.push(report); seenReports.add(report.id); eventCount += report.events.length; findingCount += report.findings.length; count = report.events.length;
    } else {
      const remaining = Math.min(IMPORT_LIMITS.rawEvents - rawEvents.length, IMPORT_LIMITS.events - eventCount - rawEvents.length);
      if (remaining <= 0 || findingCount > IMPORT_LIMITS.findings - 1000) throw new Error('The 50,000-record raw evidence limit was reached; this source was not analyzed.');
      const parsed = parseRawLog(decoded.text, source, { maxEvents: remaining });
      if (!parsed.events.length) throw new Error('No readable diagnostic event records were found.');
      rawEvents.push(...parsed.events.map(event => ({ ...event, uid: `${fileId}:${event.uid}` })));
      rawSources.push(source); count = parsed.events.length;
      rawWarnings.push(...decoded.warnings.map(warning => `${label}: ${warning}`), ...parsed.warnings.map(warning => `${label}: ${warning}`));
      partial = parsed.warnings.some(warning => /skipped|showing the first|truncat|omitted/i.test(warning)) || parsed.events.some(event => /\[message truncated\]/i.test(event.message));
    }
    seen.add(fileId);
    return { status: partial ? 'partial' : 'analyzed', eventCount: count, reason: partial ? 'Only part of this source was parsed. Review its record-limit or malformed-record notices.' : '' };
  }

  function archiveSummary(archive) {
    for (const key of ['analyzed', 'partial', 'skipped', 'failed', 'duplicates']) archive[key] = 0;
    for (const row of archive.entries) {
      if (row.status === 'analyzed') archive.analyzed++;
      else if (row.status === 'partial') archive.partial++;
      else if (row.status === 'duplicate') archive.duplicates++;
      else if (row.status === 'skipped') archive.skipped++;
      else archive.failed++;
    }
    archive.complete = !archive.error && archive.entryCount > 0 && archive.analyzed === archive.entryCount;
    const summary = `${archive.name}: ${archive.entryCount} archive entries; ${archive.analyzed} analyzed, ${archive.partial} partial, ${archive.skipped} skipped, ${archive.failed} failed, ${archive.duplicates} duplicates. Opening an archive does not establish complete device coverage.`;
    notices.push(summary); archiveSummaries.push(summary);
    if (archive.error) archiveSummaries.push(`${archive.name}: ${archive.error}`);
    for (const row of archive.entries) if (row.status !== 'analyzed') {
      const source = `${archive.name} / ${row.name}`;
      archiveDetails.push(`${source}: ${row.status}. ${row.reason}`);
      if (!row.eventCount) unavailableSources.push({ name: source, available: false, note: row.reason });
    }
  }

  async function readCab(file) {
    const archive = { name: sanitizeText(file.name), entryCount: 0, analyzed: 0, partial: 0, skipped: 0, failed: 0, duplicates: 0, expandedBytes: 0, complete: false, entries: [] };
    archives.push(archive);
    try {
      const bytes = new Uint8Array(await file.arrayBuffer()), metadata = inspectCabinet(bytes);
      archive.entryCount = metadata.entries.length; archive.expandedBytes = metadata.totalExpandedBytes;
      const expansionCost = Math.max(metadata.totalExpandedBytes, metadata.folders.reduce((sum, folder) => sum + folder.uncompressedBytes, 0));
      if (cabEntries + metadata.entries.length > CAB_LIMITS.entries || cabExpandedBytes + expansionCost > CAB_LIMITS.expandedBytes) throw new Error('Selection-wide CAB budget exceeded (2,000 entries and 256 MiB expanded data combined). This archive was not decompressed; select it separately.');
      cabEntries += metadata.entries.length; cabExpandedBytes += expansionCost;
      archive.entries = metadata.entries.map(entry => {
        const ext = extension(entry.name);
        let reason = entry.unsafe ? entry.reason || 'Unsafe archive path.' : '';
        if (!reason && !IMPORT_EXTENSIONS.includes(ext)) reason = ext === '.evtx' ? 'Binary EVTX is not decoded by this text analyzer. Its event records require conversion to JSON/XML.' : ext === '.etl' ? 'Binary ETL requires Windows tracing tools; it does not contribute decoded evidence.' : 'This file type is not a supported diagnostic text export.';
        if (!reason && ext === '.cab') reason = 'Nested archives are not unpacked recursively.';
        if (!reason && entry.size > IMPORT_LIMITS.fileBytes) reason = 'This member exceeds the 20 MiB readable-file limit.';
        return { name: sanitizeText(entry.name), size: entry.size, status: reason ? 'skipped' : 'pending', reason, eventCount: 0 };
      });
      // A small deterministic digest is used only for duplicate detection, not security.
      let a = 2166136261, b = 2246822519;
      for (const byte of bytes) { a = Math.imul(a ^ byte, 16777619); b = Math.imul(b ^ byte, 3266489917); }
      const archiveId = `${file.name}:${bytes.length}:${a >>> 0}:${b >>> 0}`;
      if (seenArchives.has(archiveId)) {
        for (const row of archive.entries) Object.assign(row, { status: 'duplicate', reason: 'This CAB was already included in the same selection.' });
        archiveSummary(archive); return;
      }
      seenArchives.add(archiveId);
      if (!archive.entries.some(row => row.status === 'pending')) { archiveSummary(archive); return; }
      const visited = new Set();
      for await (const entry of extractCabEntries(bytes, metadata, item => archive.entries[item.index]?.status === 'pending')) {
        if (!Number.isInteger(entry.index) || !archive.entries[entry.index] || visited.has(entry.index)) throw new Error('The CAB decoder returned an inconsistent entry inventory.');
        visited.add(entry.index);
        const row = archive.entries[entry.index], original = metadata.entries[entry.index];
        if (row.status !== 'pending') continue;
        if (entry.error) { row.status = 'failed'; row.reason = sanitizeText(entry.error); continue; }
        try {
          if (!(entry.bytes instanceof Uint8Array) || entry.bytes.byteLength !== original.size || entry.bytes.byteLength > IMPORT_LIMITS.fileBytes) throw new Error('Extracted data does not match the bounded CAB file size.');
          const source = `${file.name} / ${original.name}`;
          Object.assign(row, await readEvidence(entry.bytes, source));
        } catch (error) {
          row.status = /no .*records|does not contain supported|no windows event|requires named|contains no readable|empty/i.test(error.message) ? 'skipped' : 'failed';
          row.reason = sanitizeText(error.message || 'Could not analyze this archive member.');
        }
      }
      for (const row of archive.entries) if (row.status === 'pending') { row.status = 'failed'; row.reason = 'The decoder did not return this expected archive entry.'; }
    } catch (error) {
      archive.error = sanitizeText(error.message || 'The CAB could not be opened.');
      errors.push(`${archive.name}: ${archive.error}`);
      for (const row of archive.entries) if (row.status === 'pending') { row.status = 'failed'; row.reason = archive.error; }
    }
    archiveSummary(archive);
  }

  for (const file of files) {
    const label = sanitizeText(String(file.name || 'Unnamed file'));
    try {
      if (!IMPORT_EXTENSIONS.includes(extension(file.name))) throw formatError(file.name);
      if (extension(file.name) === '.cab') await readCab(file);
      else {
        const result = await readEvidence(await file.arrayBuffer(), String(file.name));
        if (result.status === 'duplicate') notices.push(`${label}: duplicate file skipped.`);
      }
    } catch (error) { errors.push(`${label}: ${sanitizeText(error.message || 'Could not read this file.')}`); }
    await new Promise(resolve => setTimeout(resolve, 0));
  }
  if (rawEvents.length) {
    try {
      const analysis = analyzeRawEvents(rawEvents, [...new Set(rawSources)], rawWarnings);
      analysis.sources.push(...unavailableSources);
      analysis.warnings.push(...archiveDetails.slice(0, 200));
      if (archiveDetails.length > 200) analysis.warnings.push(`${archiveDetails.length - 200} additional archive entry notices are listed in the full CAB coverage inventory.`);
      reports.push(parseReport(analysis, rawSources.length === 1 ? rawSources[0] : `Raw logs · ${rawSources.length} files`));
    } catch (error) { errors.push(`Raw log analysis: ${sanitizeText(error.message || 'Could not analyze the selected records.')}`); }
  }
  for (const report of reports) report.warnings.push(...archiveSummaries);
  return { reports: [...new Map(reports.map(report => [report.id, report])).values()], errors, notices, archives };
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
