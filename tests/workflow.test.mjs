import test from 'node:test';
import assert from 'node:assert/strict';
import { DemoWorkflow, reportHTML, escapeHTML, steps } from '../docs/app.js';
import { scenarios } from '../docs/scenarios.js';
import { readFileSync } from 'node:fs';

test('all four cases have consistent evidence references and synthetic identities', () => {
  assert.equal(scenarios.length, 4);
  for (const scenario of scenarios) {
    assert.ok(scenario.events.length > 3 && scenario.events.length <= 8);
    assert.ok(scenario.expectedSources.length > 0);
    const ids = new Set(scenario.events.map(event => event.id));
    assert.equal(ids.size, scenario.events.length);
    for (const event of scenario.events) assert.ok(Number.isFinite(Date.parse(event.time)));
    for (const finding of scenario.findings) {
      assert.ok(finding.evidenceIds.length > 0);
      for (const id of finding.evidenceIds) assert.ok(ids.has(id));
      assert.ok(finding.checks.length > 0);
      assert.ok(finding.recommendations.length > 0);
    }
  }
});

test('users cannot skip unloaded stages or export uninspected findings', () => {
  const workflow = new DemoWorkflow();
  assert.equal(workflow.step, 0);
  assert.equal(workflow.goTo(3), false);
  assert.equal(workflow.goTo(-1), false);
  assert.equal(workflow.goTo(0.5), false);
  assert.throws(() => workflow.report(), /findings before exporting/);
  assert.equal(workflow.advance(), true);
  assert.equal(workflow.step, 1);
  assert.throws(() => workflow.report(), /findings before exporting/);
});

test('all scenarios complete the five stages and preserve read-only metadata', () => {
  const workflow = new DemoWorkflow();
  for (const scenario of scenarios) {
    workflow.selectScenario(scenario.id);
    while (workflow.advance()) {}
    assert.equal(workflow.step, steps.length - 1);
    const report = workflow.report();
    assert.equal(report.report_metadata.managed_by, 'Dibyendu');
    assert.equal(report.report_metadata.application, 'Windows Diagnostics');
    assert.equal(report.report_metadata.synthetic, true);
    assert.equal(report.report_metadata.read_only, true);
    assert.equal(report.report_metadata.device_connected, false);
    assert.equal(report.report_metadata.remediations_executed, false);
    assert.equal(report.events.length, scenario.events.length);
    assert.equal(report.findings.length, scenario.findings.length);
  }
});

test('switching or resetting a case clears stage and review progress', () => {
  const workflow = new DemoWorkflow();
  while (workflow.advance()) {}
  const finding = workflow.scenario.findings[0];
  assert.equal(workflow.toggleReview(finding.id, 0, true), true);
  assert.equal(workflow.reviewed.size, 1);
  workflow.selectScenario('patching');
  assert.equal(workflow.step, 0);
  assert.equal(workflow.maxStep, 0);
  assert.equal(workflow.reviewed.size, 0);
  assert.equal(workflow.selectScenario('unknown'), false);
  assert.equal(workflow.scenario.id, 'patching');
});

test('review selections are restricted to valid checks and do not mutate findings', () => {
  const workflow = new DemoWorkflow();
  const original = JSON.stringify(workflow.scenario.findings);
  const finding = workflow.scenario.findings[0];
  assert.equal(workflow.toggleReview(finding.id, 0, true), false);
  while (workflow.advance()) {}
  assert.equal(workflow.toggleReview(finding.id, 999, true), false);
  assert.equal(workflow.toggleReview(finding.id, 0, true), true);
  assert.equal(workflow.toggleReview(finding.id, 0, false), true);
  assert.equal(workflow.reviewed.size, 0);
  assert.equal(JSON.stringify(workflow.scenario.findings), original);
});

test('search finds error codes in records and their linked findings', () => {
  const workflow = new DemoWorkflow();
  assert.ok(workflow.filterEvents('0x87d1041c').length > 0);
  assert.ok(workflow.filterFindings('0x87d1041c').length > 0);
  assert.equal(workflow.filterEvents('nonexistent-source-string').length, 0);
  assert.equal(workflow.filterFindings('nonexistent-source-string').length, 0);
});

test('earlier completed stages remain accessible', () => {
  const workflow = new DemoWorkflow();
  while (workflow.advance()) {}
  assert.equal(workflow.goTo(2), true);
  assert.equal(workflow.step, 2);
  assert.equal(workflow.goTo(4), true);
  assert.equal(workflow.back(), true);
  assert.equal(workflow.step, 3);
});

test('HTML report marks simulation, links evidence, and escapes untrusted text', () => {
  const workflow = new DemoWorkflow();
  while (workflow.advance()) {}
  const report = structuredClone(workflow.report());
  report.events[0].message = '<script>alert("test")</script>';
  const html = reportHTML(report);
  assert.ok(html.includes('SYNTHETIC DEMO · NO DEVICE CONNECTED'));
  assert.ok(html.includes('MANAGED BY DIBYENDU'));
  assert.ok(html.includes('Changes applied: 0'));
  assert.ok(html.includes('&lt;script&gt;'));
  assert.equal(html.includes('<script>'), false);
  for (const id of report.findings[0].evidenceIds) assert.ok(html.includes(`href="#${id}"`));
  assert.equal(escapeHTML(`'"&<>`), '&#39;&quot;&amp;&lt;&gt;');
});

test('demo has no device calls, third-party assets or automatic remediation', () => {
  const html = readFileSync(new URL('../docs/index.html', import.meta.url), 'utf8');
  const code = readFileSync(new URL('../docs/app.js', import.meta.url), 'utf8');
  assert.equal(/(?:src|href)="https?:\/\//.test(html), false);
  assert.equal(/\bfetch\s*\(|XMLHttpRequest|WebSocket|sendBeacon/.test(code), false);
  assert.ok(html.includes('No changes are applied'));
});
