import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseHTML } from 'linkedom';
import { initExecutive } from '../docs/executive.js';
import { importDiagnosticFiles } from '../docs/importer.js';

const page = readFileSync(new URL('../docs/index.html', import.meta.url), 'utf8');

// Run the real controllers against the shipped document. Linkedom emulates DOM
// events, not a browser: fill its select-value and dialog API gaps in this harness.
function mount(t, options = {}) {
  const { document, window } = parseHTML(page);
  Object.defineProperty(window.HTMLSelectElement.prototype, 'value', {
    configurable: true,
    get() { return [...this.options].find(option => option.hasAttribute('selected'))?.getAttribute('value') ?? this.options[0]?.getAttribute('value') ?? this.options[0]?.textContent ?? ''; },
    set(value) { for (const option of this.options) option.toggleAttribute('selected', (option.getAttribute('value') ?? option.textContent) === String(value)); }
  });
  Object.defineProperty(window.HTMLInputElement.prototype, 'checked', {
    configurable: true,
    get() { return this.hasAttribute('checked'); },
    set(value) { this.toggleAttribute('checked', Boolean(value)); }
  });
  const dialog = document.getElementById('exec-detail');
  dialog.showModal = () => { dialog.open = true; };
  dialog.close = () => { dialog.open = false; };
  const previousDocument = globalThis.document;
  globalThis.document = document;
  const blobs = new Map(), downloads = [], timers = new Set();
  const originalCreate = URL.createObjectURL, originalRevoke = URL.revokeObjectURL;
  URL.createObjectURL = blob => { const url = `blob:guided-ui-${blobs.size + 1}`; blobs.set(url, blob); return url; };
  URL.revokeObjectURL = () => {};
  document.addEventListener('click', event => {
    const anchor = event.target.closest('a');
    if (anchor?.download) downloads.push({ name: anchor.download, blob: blobs.get(anchor.href) });
  });
  const originalTimer = globalThis.setTimeout;
  globalThis.setTimeout = (callback, delay, ...args) => {
    const timer = originalTimer(callback, delay, ...args);
    timers.add(timer);
    return timer;
  };
  t.after(() => {
    for (const timer of timers) clearTimeout(timer);
    globalThis.setTimeout = originalTimer;
    URL.createObjectURL = originalCreate;
    URL.revokeObjectURL = originalRevoke;
    if (previousDocument === undefined) delete globalThis.document; else globalThis.document = previousDocument;
  });
  const app = initExecutive({ readFiles: importDiagnosticFiles, ...options });
  const $ = selector => {
    const element = document.querySelector(selector);
    assert.ok(element, `Expected control ${selector} in the shipped document`);
    return element;
  };
  const click = selector => { const element = $(selector); assert.equal(Boolean(element.disabled), false, `${selector} should be enabled`); element.click(); };
  const change = (selector, value) => { const element = $(selector); element.value = value; element.dispatchEvent(new window.Event('change', { bubbles: true })); };
  const search = value => { const element = $('#search-input'); element.value = value; element.dispatchEvent(new window.Event('input', { bubbles: true })); };
  return { app, document, window, $, click, change, search, downloads };
}

function endpointReport() {
  return {
    started_at: '2026-10-19T08:00:00Z', synthetic: false,
    sources: ['AppWorkload.log', 'AppActionProcessor.log'],
    events: [
      { uid: 'installed', source: 'AppWorkload.log', timestamp: '2026-10-19T07:00:00Z', category: 'Win32 apps', stage: 'execution', context: 'SYSTEM', message: 'Endpoint installer returned exit code 0.', line: 12, correlation_ids: ['incident-one'] },
      { uid: 'detect-failed', source: 'AppActionProcessor.log', timestamp: '2026-10-19T07:01:00Z', category: 'Win32 apps', stage: 'result', context: 'SYSTEM', message: 'Detection failed: 0x87D1041C <img src=x onerror=alert(1)>', codes: ['0x87D1041C'], line: 18, correlation_ids: ['incident-one'] }
    ],
    findings: [{ id: 'detection', title: 'Endpoint detection mismatch', severity: 'error', category: 'Win32 apps', confidence: 'Medium', summary: 'Installation completed before detection failed.', root_cause: 'Compare the deployed detection rule with the installed artifact.', evidence: ['installed', 'detect-failed'], checks: ['Confirm the file or registry detection target.', 'Compare SYSTEM and user context.'], recommendations: ['Review a proposed detection rule adjustment before applying it.'] }]
  };
}

const reportFile = () => new File([JSON.stringify(endpointReport())], 'endpoint-evidence.json', { type: 'application/json' });

test('the shipped sidebar and all five guided stages respond to DOM controls', async t => {
  const { app, $, click, search, window, downloads } = mount(t);
  assert.equal($('#executive-view').hidden, false);
  assert.equal($('#workflow-view').hidden, true);
  click('[data-exec-view="workflow"]');
  assert.equal($('#workflow-view').hidden, false);
  assert.equal($('#executive-view').hidden, true);
  assert.equal($('#scenario-group').hidden, false);
  assert.equal(app.workflow.state.step, 0);
  assert.equal($('#export-btn').disabled, true);
  assert.equal($('[data-step="3"]').disabled, true);
  click('#next-btn');
  assert.equal(app.workflow.state.step, 1);
  assert.ok($('#stage-content').textContent.includes('Source coverage'));
  click('#next-btn');
  assert.equal(app.workflow.state.step, 2);
  const events = app.workflow.state.scenario.events;
  assert.equal($('#stage-content tbody').children.length, events.length);
  click(`#stage-content tr[data-event="${events.at(-1).id}"]`);
  assert.equal(app.workflow.state.selectedEventId, events.at(-1).id);
  assert.ok($('.timeline-details').textContent.includes(events.at(-1).message));
  search('no-such-evidence-ui-regression');
  assert.equal($('#stage-content tbody').children.length, 0);
  search('');
  assert.equal($('#stage-content tbody').children.length, events.length);
  click('#next-btn');
  assert.equal(app.workflow.state.step, 3);
  const finding = app.workflow.state.scenario.findings[0];
  assert.ok($('#stage-content').textContent.includes(finding.title));
  click(`[data-evidence="${finding.evidenceIds[0]}"]`);
  assert.equal(app.workflow.state.step, 2);
  assert.equal(app.workflow.state.selectedEventId, finding.evidenceIds[0]);
  click('#next-btn');
  click('#next-btn');
  assert.equal(app.workflow.state.step, 4);
  const check = $('#check-0');
  check.checked = true;
  check.dispatchEvent(new window.Event('change', { bubbles: true }));
  assert.equal(app.workflow.state.reviewed.size, 1);
  assert.equal($('#check-0').checked, true);
  click('#export-btn');
  assert.equal(downloads.length, 1);
  const report = JSON.parse(await downloads[0].blob.text());
  assert.equal(report.report_metadata.synthetic, true);
  assert.equal(report.report_metadata.read_only, true);
  assert.equal(report.report_metadata.remediations_executed, false);
  assert.equal(report.events.length, events.length);
  click('#back-btn');
  assert.equal(app.workflow.state.step, 3);
  click('[data-step="0"]');
  assert.equal(app.workflow.state.step, 0);
  click('#reset-btn');
  assert.equal(app.workflow.state.maxStep, 0);
  assert.equal(app.workflow.state.reviewed.size, 0);
  click('[data-scenario="patching"]');
  assert.equal(app.workflow.state.scenario.id, 'patching');
  click('[data-exec-view="dashboard"]');
  assert.equal($('#executive-view').hidden, false);
  assert.equal($('#workflow-view').hidden, true);
});

test('real imported endpoint evidence populates guided stages and exports with its actual scope', async t => {
  const { app, $, click, search, change, downloads } = mount(t);
  await app.importFiles([reportFile()]);
  assert.equal(app.state.mode, 'imported');
  assert.equal(app.state.imported.length, 1);
  click('[data-exec-view="workflow"]');
  assert.equal(app.workflow.state.step, 1);
  assert.equal(app.workflow.state.scenario.events.length, 2);
  assert.equal(app.workflow.state.scenario.findings[0].title, 'Endpoint detection mismatch');
  assert.equal($('#workflow-dataset').value, 'imported');
  assert.match($('#workflow-tag').textContent, /imported|local/i);
  click('#next-btn');
  assert.equal(app.workflow.state.step, 2);
  assert.equal($('#stage-content tbody').children.length, 2);
  search('0x87D1041C');
  assert.equal($('#stage-content tbody').children.length, 1);
  assert.equal($('#stage-content').querySelector('img'), null);
  assert.match($('.timeline-details').textContent, /0x87D1041C/);
  click('#next-btn');
  assert.equal(app.workflow.state.step, 3);
  assert.ok($('#stage-content').textContent.includes('Endpoint detection mismatch'));
  assert.ok($('#stage-content').textContent.includes('Compare the deployed detection rule'));
  click('#export-btn');
  const report = JSON.parse(await downloads.at(-1).blob.text());
  assert.equal(report.report_metadata.synthetic, false);
  assert.equal(report.report_metadata.read_only, true);
  assert.equal(report.report_metadata.device_connected, false);
  assert.equal(report.report_metadata.remediations_executed, false);
  assert.equal(report.events.length, 2);
  assert.equal(report.findings[0].title, 'Endpoint detection mismatch');
  change('#workflow-dataset', 'sample');
  assert.equal(app.state.mode, 'sample');
  assert.equal(app.workflow.state.step, 0);
  assert.notEqual(app.workflow.state.scenario.findings[0].title, 'Endpoint detection mismatch');
  change('#workflow-dataset', 'imported');
  assert.equal(app.state.mode, 'imported');
  assert.equal(app.workflow.state.step, 1);
  assert.equal(app.workflow.state.scenario.findings[0].title, 'Endpoint detection mismatch');
});

test('dashboard handoff opens imported investigation and a failed import preserves its progress', async t => {
  const { app, $, click } = mount(t);
  await app.importFiles([reportFile()]);
  click('#exec-investigate');
  assert.equal($('#workflow-view').hidden, false);
  assert.equal(app.workflow.state.scenario.events.length, 2);
  click('#next-btn');
  click('#next-btn');
  const scenarioId = app.workflow.state.scenario.id;
  assert.equal(app.workflow.state.step, 3);
  await app.importFiles([new File(['not a recognized report'], 'bad.json', { type: 'application/json' })]);
  assert.equal(app.state.mode, 'imported');
  assert.equal(app.workflow.state.scenario.id, scenarioId);
  assert.equal(app.workflow.state.step, 3);
  assert.equal(app.workflow.state.scenario.events.length, 2);
  assert.match($('#exec-import-status').textContent, /unchanged/i);
  assert.equal($('#workflow-import-status').hidden, false);
  assert.match($('#workflow-import-status').textContent, /unchanged/i);
  click('[data-exec-view="dashboard"]');
  assert.ok($('#exec-priority-table').textContent.includes('Endpoint detection mismatch'));
  click('#exec-priority-table [data-exec-finding]');
  assert.equal($('#exec-detail').open, true);
  click('[data-exec-investigate-report]');
  assert.equal($('#exec-detail').open, false);
  assert.equal($('#workflow-view').hidden, false);
  assert.equal(app.workflow.state.step, 3);
  assert.equal(app.workflow.state.scenario.findings.find(finding => finding.id === app.workflow.state.selectedFindingId)?.title, 'Endpoint detection mismatch');
});

test('the guided import button uses the shared file picker and updates the current investigation', async t => {
  let receivedFiles;
  const { app, $, click, window } = mount(t, { readFiles: async files => {
    receivedFiles = files;
    return importDiagnosticFiles(files);
  } });
  click('[data-exec-view="workflow"]');
  let pickerClicks = 0;
  const picker = $('#exec-file-input');
  picker.addEventListener('click', () => pickerClicks++);
  click('#workflow-import');
  assert.equal(pickerClicks, 1);
  const files = [reportFile()];
  Object.defineProperty(picker, 'files', { configurable: true, value: files });
  picker.dispatchEvent(new window.Event('change', { bubbles: true }));
  assert.equal(app.state.busy, true);
  for (let attempt = 0; attempt < 50 && app.state.busy; attempt++) await new Promise(resolve => setImmediate(resolve));
  assert.equal(app.state.busy, false, 'file-picker analysis should complete');
  assert.deepEqual(receivedFiles, files);
  assert.equal(app.state.mode, 'imported');
  assert.equal($('#workflow-view').hidden, false);
  assert.equal(app.workflow.state.step, 1);
  assert.equal(app.workflow.state.scenario.findings[0].title, 'Endpoint detection mismatch');
});

test('a sample priority opens the corresponding case and finding in guided investigation', t => {
  const { app, document, $, click } = mount(t);
  const priority = [...document.querySelectorAll('#exec-priority-table [data-exec-finding]')].at(-1);
  assert.ok(priority);
  const selected = app.state.sample.flatMap(report => report.findings).find(finding => finding.id === priority.dataset.execFinding);
  priority.click();
  assert.equal($('#exec-dialog-title').textContent, selected.title);
  click('[data-exec-investigate-report]');
  assert.equal($('#workflow-view').hidden, false);
  assert.equal($('#exec-detail').open, false);
  assert.equal(app.workflow.state.step, 3);
  assert.equal(app.workflow.state.scenario.findings.find(finding => finding.id === app.workflow.state.selectedFindingId)?.title, selected.title);
});

test('a finding selected by search remains the reviewed finding in the next stage', async t => {
  const { app, $, click, search } = mount(t);
  const raw = endpointReport();
  raw.findings.push({
    ...raw.findings[0], id: 'context', title: 'Endpoint context mismatch',
    summary: 'A second independent observation needs review.',
    checks: ['Inspect the targeted app user context.'],
    recommendations: ['Review the proposed execution context with the application owner.']
  });
  await app.importFiles([new File([JSON.stringify(raw)], 'two-findings.json')]);
  click('[data-exec-view="workflow"]');
  click('#next-btn');
  click('#next-btn');
  search('Endpoint context mismatch');
  assert.equal($('#stage-content').querySelectorAll('.finding-card').length, 1);
  assert.equal(app.workflow.state.scenario.findings.find(finding => finding.id === app.workflow.state.selectedFindingId)?.title, 'Endpoint context mismatch');
  click('#next-btn');
  assert.equal(app.workflow.state.step, 4);
  assert.ok($('#stage-content').textContent.includes('Inspect the targeted app user context.'));
  assert.equal($('#stage-content').textContent.includes('Confirm the file or registry detection target.'), false);
});

test('large imported timelines paginate, search all records and open off-page finding evidence', async t => {
  const { app, $, click, search } = mount(t);
  const raw = endpointReport();
  raw.events = Array.from({ length: 205 }, (_, index) => ({
    ...raw.events[0], uid: `paging-${index + 1}`, line: index + 1,
    message: `Paging record ${index + 1}.`, codes: []
  }));
  raw.findings[0].evidence = ['paging-205'];
  await app.importFiles([new File([JSON.stringify(raw)], 'large-timeline.json')]);
  click('[data-exec-view="workflow"]');
  click('#next-btn');
  assert.equal($('#stage-content tbody').children.length, 100);
  assert.equal($('[data-event-page="-1"]').disabled, true);
  click('[data-event-page="1"]');
  assert.equal($('#stage-content tbody').children.length, 100);
  assert.ok($('#stage-content tbody tr:first-child').textContent.includes('Paging record 101.'));
  click('[data-event-page="2"]');
  assert.equal($('#stage-content tbody').children.length, 5);
  assert.equal($('[data-event-page="3"]').disabled, true);
  click('[data-event-page="1"]');
  assert.equal($('#stage-content tbody').children.length, 100);
  search('Paging record 205.');
  assert.equal($('#stage-content tbody').children.length, 1);
  assert.ok($('#stage-content tbody').textContent.includes('Paging record 205.'));
  search('');
  assert.equal($('#stage-content tbody').children.length, 100);
  click('#next-btn');
  const targetId = app.state.imported[0].events.at(-1).id;
  click(`[data-evidence="${targetId}"]`);
  assert.equal(app.workflow.state.step, 2);
  assert.equal(app.workflow.state.eventPage, 2);
  assert.equal(app.workflow.state.selectedEventId, targetId);
  assert.equal($('#stage-content tbody').children.length, 5);
  assert.ok($(`#stage-content tr[data-event="${targetId}"]`).classList.contains('selected'));
  assert.ok($('.timeline-details').textContent.includes('Paging record 205.'));
});
