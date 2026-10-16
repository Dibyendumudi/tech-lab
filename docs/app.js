import { scenarios } from './scenarios.js';

export const steps = [
  { label: 'Select case', hint: 'Choose the signal', title: 'Start with a specific incident.', action: 'Load sample logs →' },
  { label: 'Collect logs', hint: 'Read the sources', title: 'Read the right sources.', action: 'Correlate evidence →' },
  { label: 'Correlate', hint: 'Connect the lifecycle', title: 'Connect the lifecycle.', action: 'View findings →' },
  { label: 'Findings', hint: 'Identify the failing stage', title: 'Identify the failing stage.', action: 'Review suggestions →' },
  { label: 'Review', hint: 'Validate the next step', title: 'Review before changing anything.', action: 'Export HTML report ↗' },
];

export function escapeHTML(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
}
const e = escapeHTML;
const icon = { win32: '▦', patching: '↻', 'conditional-access': '◇', autopilot: '⌁' };

export class DemoWorkflow {
  constructor(items = scenarios) {
    if (!Array.isArray(items) || !items.length) throw new Error('At least one sample scenario is required.');
    this.items = items;
    this.selectScenario(items[0].id);
  }
  get scenario() { return this.items.find(item => item.id === this.scenarioId); }
  selectScenario(id) {
    if (!this.items.some(item => item.id === id)) return false;
    this.scenarioId = id;
    this.step = 0;
    this.maxStep = 0;
    this.query = '';
    this.selectedEventId = this.scenario.events[0]?.id;
    this.selectedFindingId = this.scenario.findings[0]?.id;
    this.reviewed = new Set();
    return true;
  }
  advance() {
    if (this.step >= steps.length - 1) return false;
    this.step += 1;
    this.maxStep = Math.max(this.step, this.maxStep);
    return true;
  }
  back() { return this.goTo(this.step - 1); }
  goTo(step) {
    if (!Number.isInteger(step) || step < 0 || step > this.maxStep || step >= steps.length) return false;
    this.step = step;
    return true;
  }
  filterEvents(query = this.query) {
    const text = query.trim().toLowerCase();
    return this.scenario.events.filter(event => !text || Object.values(event).some(value => String(value).toLowerCase().includes(text)));
  }
  filterFindings(query = this.query) {
    const text = query.trim().toLowerCase();
    return this.scenario.findings.filter(finding => {
      const evidence = this.scenario.events.filter(event => finding.evidenceIds.includes(event.id));
      return !text || JSON.stringify({ finding, evidence }).toLowerCase().includes(text);
    });
  }
  reviewKey(findingId, index) { return `${findingId}:${index}`; }
  toggleReview(findingId, index, checked) {
    const finding = this.scenario.findings.find(item => item.id === findingId);
    if (this.maxStep < 4 || !finding || !Number.isInteger(index) || index < 0 || index >= finding.checks.length) return false;
    const key = this.reviewKey(findingId, index);
    if (checked) this.reviewed.add(key); else this.reviewed.delete(key);
    return true;
  }
  report() {
    if (this.maxStep < 3) throw new Error('Load the sample logs and inspect the findings before exporting.');
    return {
      report_metadata: { application: 'Windows Diagnostics', managed_by: 'Dibyendu', generated_at: new Date().toISOString(), synthetic: true, read_only: true, device_connected: false, remediations_executed: false },
      disclaimer: 'SYNTHETIC DEMO. These records do not describe your device or tenant. Review selections track the walkthrough only; they do not verify actual device state.',
      scenario: { id: this.scenario.id, category: this.scenario.category, title: this.scenario.title },
      sources: this.scenario.expectedSources,
      events: this.scenario.events,
      findings: this.scenario.findings,
      demo_review_selections: [...this.reviewed],
    };
  }
}

export function reportHTML(report) {
  const findings = report.findings.map(finding => `<section><p class="meta">${e(finding.severity)} · ${e(finding.confidence)} confidence</p><h2>${e(finding.title)}</h2><p>${e(finding.observation)}</p><h3>Likely root cause</h3><p>${e(finding.rootCause)}</p><h3>Evidence</h3>${finding.evidenceIds.map(id => { const record = report.events.find(event => event.id === id); return record ? `<p><a href="#${e(record.id)}">${e(record.source)} · line ${e(record.line)} · ${e(record.time)}</a></p>` : ''; }).join('')}<h3>Verification checks</h3><ol>${finding.checks.map(check => `<li>${e(check)}</li>`).join('')}</ol><h3>Suggested resolution · not executed</h3><ol>${finding.recommendations.map(value => `<li>${e(value)}</li>`).join('')}</ol></section>`).join('');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Windows Diagnostics · Demo report</title><style>body{font:14px/1.7 'Segoe UI',system-ui,sans-serif;background:#f3f7fa;color:#21374c;margin:0}header{background:#10243a;color:white;padding:35px max(24px,calc((100vw - 960px)/2))}main{max-width:960px;margin:auto;padding:24px}section{background:white;border:1px solid #e1e8f0;padding:24px;margin-bottom:18px;border-radius:10px}h1{font-size:28px}h2{font-size:21px}h3{font-size:14px;margin-top:25px}.meta{font-size:11px;color:#668374;text-transform:uppercase}.notice{border-left:4px solid #c69335}a{color:#087f7c}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:12px/1.7 Consolas,monospace}.event{border-top:1px solid #e1e8f0;padding:18px 0}</style></head><body><header><small>WINDOWS DIAGNOSTICS / MANAGED BY DIBYENDU</small><h1>${e(report.scenario.title)}</h1><p>Read-only · Synthetic demonstration report</p></header><main><section class="notice"><strong>SYNTHETIC DEMO · NO DEVICE CONNECTED</strong><p>${e(report.disclaimer)}</p><p>Generated ${e(report.report_metadata.generated_at)}. Changes applied: 0.</p></section>${findings}<section><h2>Evidence timeline</h2>${report.events.map(event => `<div id="${e(event.id)}" class="event"><strong>${e(event.time)} · ${e(event.source)}:${e(event.line)}</strong><p class="meta">${e(event.stage)} · ${e(event.context)} · ${e(event.code || 'No error code')}</p><pre>${e(event.message)}</pre><small>${e(event.correlationId)}</small></div>`).join('')}</section><p>Windows Diagnostics · Managed by Dibyendu. This report contains demonstration data only.</p></main></body></html>`;
}

function init() {
  const state = new DemoWorkflow();
  const $ = id => document.getElementById(id);
  let toastTimer;
  const badge = (value, type = '') => `<span class="badge ${e(type)}">${e(value)}</span>`;
  const sources = () => state.scenario.expectedSources.map(source => `<div class="source-row"><span class="source-icon" aria-hidden="true">${source.available ? '▤' : '○'}</span><div><h4>${e(source.name)}</h4><p>${e(source.note)}</p></div>${badge(source.available ? 'Sample available' : 'Not included', source.available ? 'success' : 'warning')}</div>`).join('');
  const note = (title, text) => `<div class="note-card"><h4>${e(title)}</h4><p>${e(text)}</p></div>`;
  function toast(message) {
    $('toast').textContent = message;
    $('toast').hidden = false;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { $('toast').hidden = true; }, 4000);
  }
  function download(format) {
    try {
      const report = state.report();
      const content = format === 'html' ? reportHTML(report) : JSON.stringify(report, null, 2);
      const blob = new Blob([content], { type: format === 'html' ? 'text/html;charset=utf-8' : 'application/json;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `windows-diagnostics-demo-${state.scenario.id}.${format}`;
      document.body.append(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      toast(`Synthetic ${format.toUpperCase()} report downloaded. No changes were applied.`);
    } catch (error) { toast(error.message); }
  }
  function renderStage() {
    const scenario = state.scenario;
    const title = `<div class="scenario-illustration"><span class="illustration-box" aria-hidden="true">${icon[scenario.id]}</span><div><div class="eyebrow">${e(scenario.category)}</div><h4>${e(scenario.shortLabel)}</h4></div></div>`;
    if (state.step === 0) {
      return `<div class="split"><article class="panel scenario-overview">${title}<h3>The signal is the starting point.</h3><p class="intro-text">${e(scenario.subtitle)} Follow this sample through its source logs, shared identifiers, recorded results and verification steps.</p><ul class="mini-list"><li><span>✓</span>Identify the first recorded failure, rather than the last symptom.</li><li><span>✓</span>Compare assignment, policy, execution and result.</li><li><span>✓</span>Keep observed evidence separate from an unconfirmed cause.</li></ul>${note('A guided investigation', 'Load sample logs to begin. You can revisit completed stages, switch cases, search records and export a demo report.')}</article><aside class="panel"><div class="panel-header"><h4>Sources in this scenario</h4>${badge('Synthetic')}</div><div class="source-list">${sources()}</div><div class="panel-padding">${note('Read-only throughout', 'No computer is connected. Collection here means loading the bundled sample records, not reading your device or accessing an Intune tenant.')}</div></aside></div>`;
    }
    if (state.step === 1) {
      return `<div class="split"><article class="panel"><div class="panel-header"><h4>Source coverage</h4>${badge('Sample logs loaded', 'success')}</div><div class="source-list">${sources()}</div></article><aside class="panel panel-padding"><div class="eyebrow">COLLECTION NOTES</div><h3>Know what the evidence covers.</h3><p class="intro-text">${e(scenario.stageNote.collect)}</p>${note('Protect the original logs', 'The desktop collector creates new diagnostic copies. Raw files can contain sensitive values; analyze redacted copies and review reports before sharing.')}${note('What happens next', 'Correlate the records using timestamps and a shared app, activity or sign-in identifier. Close timestamps alone do not prove causation.')}</aside></div>`;
    }
    if (state.step === 2) {
      const events = state.filterEvents();
      const selected = events.find(event => event.id === state.selectedEventId) || events[0];
      const observed = new Set(scenario.events.filter(event => event.correlationId === scenario.traceId).map(event => event.stage));
      const rows = events.map(event => `<tr class="event-row ${selected?.id === event.id ? 'selected' : ''}" data-event="${e(event.id)}"><td class="event-time">${e(event.time.split('T')[1]?.replace('Z', ' UTC') || event.time)}</td><td class="source-cell"><strong>${e(event.source)}</strong><div class="message-preview">${e(event.message.slice(0, 110))}${event.message.length > 110 ? '…' : ''}</div><button class="text-button" data-event="${e(event.id)}" type="button" style="margin:4px 0 0;color:var(--teal);padding:0">Inspect record ↗</button></td><td><span class="stage-badge">${e(event.stage)}</span><div class="mono" style="margin-top:6px;color:var(--amber)">${e(event.code || '—')}</div></td></tr>`).join('');
      return `<div class="split"><article class="panel"><div class="panel-header"><h4>Evidence timeline</h4>${badge(`${events.length} of ${scenario.events.length} records`)}</div><div class="table-scroll"><table><thead><tr><th>TIME / UTC</th><th>SOURCE & SIGNAL</th><th>STAGE</th></tr></thead><tbody>${rows}</tbody></table>${!events.length ? '<div class="empty">No sample records match this search. Clear the search to review the timeline.</div>' : ''}</div><div class="trace"><span class="trace-id">${e(scenario.traceId)}</span><div class="trace-stages">${['assignment', 'policy', 'execution', 'result'].map((stage, index) => `${index ? '<span aria-hidden="true">→</span>' : ''}<span class="${observed.has(stage) ? 'observed' : ''}">${stage} ${observed.has(stage) ? '✓' : '—'}</span>`).join('')}</div><p>Shared identifiers show a relationship. Verify the record type and order before attributing cause.</p></div></article><aside class="panel timeline-details"><div class="eyebrow">SELECTED RECORD</div>${selected ? `<h4>${e(selected.source)}</h4><div class="detail-meta">${e(selected.time)}<br>Line ${e(selected.line)} · ${e(selected.stage)} · ${e(selected.context)}<br><span class="mono">${e(selected.correlationId)}</span></div><pre class="code-block">${e(selected.message)}</pre>${note('Correlation insight', scenario.stageNote.correlate)}` : '<p class="intro-text">Select a matching record to inspect its source, timestamp and message.</p>'}</aside></div>`;
    }
    if (state.step === 3) {
      const findings = state.filterFindings();
      const selected = findings.find(finding => finding.id === state.selectedFindingId) || findings[0];
      const cards = findings.map(finding => `<button type="button" class="finding-card ${selected?.id === finding.id ? 'selected' : ''}" data-finding="${e(finding.id)}">${badge(finding.severity.toUpperCase(), finding.severity)}<h4>${e(finding.title)}</h4><p>${e(finding.observation)}</p><div class="confidence">${e(finding.confidence)} confidence · ${finding.evidenceIds.length} evidence records</div></button>`).join('');
      return `<div class="finding-grid">${cards || '<div class="panel empty">No findings match the search. Clear it to inspect all sample findings.</div>'}</div>${selected ? `<article class="panel panel-padding finding-detail"><div class="review-title"><h4>${e(selected.title)}</h4>${badge('Suggested resolution only', 'success')}</div><p>${e(selected.observation)}</p><div class="cause"><div class="eyebrow">LIKELY ROOT CAUSE</div><p>${e(selected.rootCause)}</p></div><div class="eyebrow">LINKED EVIDENCE · SELECT TO INSPECT</div>${selected.evidenceIds.map(id => { const record = scenario.events.find(event => event.id === id); return record ? `<button type="button" class="evidence-link" data-evidence="${e(id)}">${e(record.source)}:${e(record.line)} ↗</button>` : ''; }).join('')}${note('Interpretation limits', scenario.stageNote.findings)}</article>` : ''}`;
    }
    const selected = scenario.findings.find(finding => finding.id === state.selectedFindingId) || scenario.findings[0];
    if (!selected) return '<div class="panel empty">No recognized finding is available. Add the right source evidence before choosing a remediation.</div>';
    const checked = selected.checks.filter((_, index) => state.reviewed.has(state.reviewKey(selected.id, index))).length;
    return `<div class="split"><article class="panel panel-padding"><div class="review-title"><h4>Verification checklist</h4>${badge(`${checked} / ${selected.checks.length} reviewed`, 'success')}</div><p class="intro-text">${e(selected.title)}. Mark the questions you have considered in this walkthrough.</p><ul class="checklist">${selected.checks.map((check, index) => `<li><input type="checkbox" id="check-${index}" data-check="${index}" data-check-finding="${e(selected.id)}" ${state.reviewed.has(state.reviewKey(selected.id, index)) ? 'checked' : ''}><label for="check-${index}">${e(check)}</label></li>`).join('')}</ul>${note('Demo review only', 'These selections track your walkthrough. They do not verify a real device, resolve an incident or apply a remediation.')}</article><aside class="panel panel-padding"><div class="review-title"><h4>Suggested resolution</h4>${badge('Not executed', 'warning')}</div>${selected.recommendations.map((item, index) => `<div class="review-suggestion"><span>${index + 1}</span><p>${e(item)}</p></div>`).join('')}${note('One approved step at a time', scenario.stageNote.review)}<div class="export-actions"><button type="button" class="button secondary" data-action="export-html">Export HTML ↗</button><button type="button" class="button secondary" data-action="export-json">Export JSON ↗</button></div></aside></div>`;
  }
  function renderContent() {
    $('stage-content').innerHTML = renderStage();
    $('action-note').textContent = state.step === 0 ? 'Choose a scenario, then load its sample logs.' : state.step === 4 ? 'Review complete in the demo. No changes have been applied.' : 'Inspect the sample evidence, then continue to the next stage.';
  }
  function render() {
    const scenario = state.scenario;
    $('scenario-nav').innerHTML = scenarios.map(item => `<button type="button" class="scenario-button ${item.id === scenario.id ? 'active' : ''}" data-scenario="${e(item.id)}" ${item.id === scenario.id ? 'aria-current="true"' : ''}><span class="nav-icon" aria-hidden="true">${icon[item.id]}</span><span>${e(item.shortLabel)}</span><span class="scenario-arrow" aria-hidden="true">›</span></button>`).join('');
    $('stepper').innerHTML = steps.map((step, index) => `<button type="button" class="step ${state.step === index ? 'active' : state.maxStep > index ? 'complete' : ''}" data-step="${index}" ${index > state.maxStep ? 'disabled' : ''} ${state.step === index ? 'aria-current="step"' : ''}><span class="step-number">${state.maxStep > index ? '✓' : index + 1}</span><span>${e(step.label)}<small>${e(step.hint)}</small></span></button>`).join('');
    const loaded = state.maxStep >= 1;
    const metrics = [
      ['LOG SOURCES', loaded ? scenario.expectedSources.filter(source => source.available).length : 0, 'Sample sources in this case', '', '▤'],
      ['EVIDENCE EVENTS', loaded ? scenario.events.length : 0, 'Records available for correlation', '', '⌁'],
      ['FINDINGS', state.maxStep >= 3 ? scenario.findings.length : 0, 'Evidence-backed diagnostic leads', 'accent', '◇'],
      ['CHANGES APPLIED', 0, 'Read-only throughout the workflow', 'accent', '◈'],
    ];
    $('metrics').innerHTML = metrics.map(([label, value, hint, type, mark]) => `<div class="metric ${type}"><div class="eyebrow">${label}</div><strong>${value}</strong><p>${hint}</p><span class="metric-icon" aria-hidden="true">${mark}</span></div>`).join('');
    $('case-domain').textContent = scenario.category.toUpperCase();
    $('case-domain').style.color = 'var(--teal)';
    $('case-title').textContent = scenario.title;
    $('case-subtitle').textContent = scenario.subtitle;
    $('case-code').textContent = scenario.code;
    $('step-kicker').textContent = `STEP ${state.step + 1} OF ${steps.length}`;
    $('step-title').textContent = steps[state.step].title;
    $('search-input').value = state.query;
    $('search-input').disabled = ![2, 3].includes(state.step);
    $('export-btn').disabled = state.maxStep < 3;
    $('back-btn').disabled = state.step === 0;
    $('next-btn').textContent = steps[state.step].action;
    renderContent();
  }
  document.addEventListener('click', event => {
    const button = event.target.closest('button');
    if (!button || button.disabled) return;
    if (button.dataset.scenario) { state.selectScenario(button.dataset.scenario); render(); }
    else if (button.dataset.step != null) { state.goTo(Number(button.dataset.step)); render(); }
    else if (button.dataset.event) { state.selectedEventId = button.dataset.event; renderContent(); }
    else if (button.dataset.finding) { state.selectedFindingId = button.dataset.finding; renderContent(); }
    else if (button.dataset.evidence) { state.selectedEventId = button.dataset.evidence; state.query = ''; state.goTo(2); render(); }
    else if (button.dataset.action === 'export-html') download('html');
    else if (button.dataset.action === 'export-json') download('json');
  });
  $('next-btn').addEventListener('click', () => {
    if (state.step === 4) { download('html'); return; }
    state.query = '';
    state.advance();
    render();
    if (state.step === 1) toast(`${state.scenario.events.length} synthetic records loaded. No device was accessed.`);
  });
  $('back-btn').addEventListener('click', () => { state.query = ''; state.back(); render(); });
  $('reset-btn').addEventListener('click', () => { state.selectScenario(state.scenarioId); render(); toast('Walkthrough reset. Choose a case and load its sample logs.'); });
  $('export-btn').addEventListener('click', () => download('json'));
  $('search-input').addEventListener('input', event => { state.query = event.target.value; renderContent(); });
  $('stage-content').addEventListener('change', event => {
    const target = event.target;
    if (target.dataset.check != null) {
      state.toggleReview(target.dataset.checkFinding, Number(target.dataset.check), target.checked);
      const position = Number(target.dataset.check);
      renderContent();
      $(`check-${position}`)?.focus();
    }
  });
  $('stage-content').addEventListener('click', event => {
    if (event.target.closest('button,input,label')) return;
    const row = event.target.closest('[data-event]');
    if (row) { state.selectedEventId = row.dataset.event; renderContent(); }
  });
  render();
}

if (typeof document !== 'undefined') init();
