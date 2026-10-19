/** Adapt already parsed, redacted report output to the guided investigation UI. */
export function casesFromReports(reports) {
  return reports.map(report => {
    const categories = new Set();
    let firstCode = '', traceId = '';
    const sourceCounts = new Map();
    const events = report.events.map(event => {
      sourceCounts.set(event.source, (sourceCounts.get(event.source) || 0) + 1);
      if (event.category) categories.add(event.category);
      if (!firstCode && event.codes.length) firstCode = event.codes[0];
      if (!traceId) traceId = event.correlationIds.find(Boolean) || '';
      return {
        ...event,
        time: event.timestamp || event.rawTimestamp || 'Time unspecified',
        timeNote: event.timestampIssue || (event.timestamp ? '' : 'Time unspecified'),
        code: event.codes.join(', '),
        correlationId: event.correlationIds[0] || '',
        correlationIds: [...event.correlationIds],
      };
    });
    const findings = report.findings.map(finding => {
      if (finding.category) categories.add(finding.category);
      return {
        ...finding,
        observation: finding.summary,
        evidenceIds: [...finding.evidenceIds],
        checks: [...finding.checks],
        recommendations: [...finding.recommendations],
      };
    });
    const category = categories.size === 1 ? [...categories][0] : 'Enterprise';
    const label = report.label || 'Imported diagnostic report';
    const warnings = [...report.warnings];
    const warningNote = warnings.length ? ` ${warnings.length} import limitation${warnings.length === 1 ? '' : 's'} require review.` : '';
    return {
      id: report.id,
      category,
      shortLabel: label,
      label,
      title: label,
      subtitle: `${events.length} supplied evidence record${events.length === 1 ? '' : 's'} and ${findings.length} diagnostic finding${findings.length === 1 ? '' : 's'}. Scope is limited to the imported report.`,
      code: firstCode || 'No recorded code',
      imported: true,
      synthetic: report.synthetic === true,
      report,
      warnings,
      expectedSources: report.sources.map(source => ({...source, recordCount: sourceCounts.get(source.name) || 0})),
      events,
      findings,
      traceId,
      stageNote: {
        collect: `${report.sources.length} source inventory entr${report.sources.length === 1 ? 'y' : 'ies'} supplied. A listed source does not establish complete collection or endpoint coverage.${warningNote}`,
        correlate: traceId ? 'Compare shared identifiers, record types and timestamps. A shared identifier establishes a relationship, not a confirmed cause; timestamps without a timezone remain local or unspecified.' : 'No shared correlation identifier is supplied. Record order and close timestamps alone do not establish a causal chain; timestamps without a timezone remain local or unspecified.',
        findings: `${findings.length} finding${findings.length === 1 ? '' : 's'} supplied by the report analysis. Treat causes as hypotheses to verify against linked evidence; missing findings do not establish endpoint health.${warningNote}`,
        review: 'Review one approved remediation at a time. Checklist selections record your review only; they do not verify device state. This app applies no repairs, deletions or settings changes.',
      },
    };
  });
}

/** Export imported cases in the native report format, keeping real evidence real. */
export function reportFromCase(item, reviewed = []) {
  const report = item.report;
  if (!report) throw new Error('An imported diagnostic report is required.');
  const synthetic = report.synthetic === true;
  return {
    started_at: report.generatedAt || '',
    synthetic,
    report_metadata: {
      application: 'Windows Diagnostics',
      managed_by: 'Dibyendu',
      title: item.title,
      generated_at: new Date().toISOString(),
      synthetic,
      read_only: true,
      device_connected: false,
      remediations_executed: false,
    },
    disclaimer: `${synthetic ? 'Includes synthetic demonstration evidence. ' : ''}Imported report output only. No live endpoint or tenant connection. Review selections record reviewer notes, not verified device state or completed remediation.`,
    sources: report.sources.map(source => ({...source})),
    events: report.events.map(event => ({
      uid: event.id,
      timestamp: event.timestamp || event.rawTimestamp || null,
      source: event.source,
      category: event.category,
      message: event.message,
      line: event.line,
      codes: [...event.codes],
      stage: event.stage,
      context: event.context,
      correlation_ids: [...event.correlationIds],
    })),
    findings: report.findings.map(finding => ({
      id: finding.id,
      title: finding.title,
      category: finding.category,
      severity: finding.severity,
      confidence: finding.confidence,
      summary: finding.summary,
      root_cause: finding.rootCause,
      evidence: [...finding.evidenceIds],
      checks: [...finding.checks],
      recommendations: [...finding.recommendations],
    })),
    warnings: [...report.warnings],
    review_selections: Array.from(reviewed),
  };
}
