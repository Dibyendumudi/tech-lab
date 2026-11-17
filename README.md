# tech-lab

## Windows Diagnostics dashboard

Managed by Dibyendu. The browser dashboard is in `docs/`; the Windows desktop app remains in its original ZIP.

Open the [Windows Diagnostics dashboard](https://dibyendumudi.github.io/tech-lab/). 

Start with the demonstration data, or choose **Import CAB / logs** to select a single Windows diagnostic `.cab`. The browser opens the archive and analyzes supported readable entries together; you do not need to extract or select each member. CAB member counts are separate from the 20 selected-file limit. The persistent **Latest CAB import coverage** table lists every entry, record count, skipped/failed source and reason. Coverage is also included in **Export brief**.

Direct `.log`, `.txt`, `.json`, `.jsonl`, `.ndjson`, `.csv`, Windows event `.xml`, and existing Windows Diagnostics JSON reports also work on macOS and Windows. UTF-8 and UTF-16 text are supported. Limits: 100 MiB per CAB, with 2,000 members and 256 MiB expanded across selected CABs; readable files are capped at 20 MiB each. Selections with CABs are capped at 150 MiB combined; other selections at 50 MiB. Raw analysis includes up to 50,000 records. The remaining budget is shared with unread supported CAB members and later selected files so one large early log cannot exhaust it. Retained records are source prefixes, not a representative sample; allocations depend on source order and can leave budget unused. Partial-source notices identify omitted records. Import affected logs separately for deeper analysis.

The **Executive problem analysis** panel explains the leading problem patterns, possible operational consequences, supplied interpretation, suggested owner and next decision. Its nine additional KPIs show rule-explained records, unexplained records, UTC-ready records, records with explicit identifiers, lifecycle stages observed, sources containing records, explained-signal coverage, timed priority evidence and identifiers shared across sources. These measures follow the dashboard filters and describe evidence quality, not fleet health or confirmed causes. The same analysis appears in **Export brief**.

Open **Knowledge base & interpretation checks** to search documented code meanings and verification steps, including common installer, access, file/path, capacity, servicing, enrollment and authentication errors. **Run built-in checks** executes 73 bundled synthetic parser/analyzer examples locally without replacing imported evidence or accessing endpoints. These checks demonstrate the supported examples; they do not establish recognition of every real incident. Unknown signals remain visible and repeated patterns are grouped within the same source/context, preserving evidence links. Existing JSON reports retain their supplied findings; re-import original logs/CAB files to apply the current analyzer.

After importing, choose **Investigate evidence** or **Guided investigation**. The selected dataset feeds both views: choose a report in the sidebar, review source coverage, correlate records, inspect findings and review suggestions. Dashboard finding details also open the corresponding report and finding directly. Switch between sample and imported data using the dataset control in either view. Search covers all evidence; long timelines are paginated. JSON and HTML investigation exports preserve imported evidence and its limitations.

Raw logs are analyzed together into one investigation with linked evidence and suggested checks. Existing report exports keep their supplied findings. Binary EVTX/ETL, nested archives, HTML reports, registry dumps and other unsupported entries are listed in CAB coverage rather than treated as analyzed. Arbitrary JSON, CSV or XML documents are not diagnostic records. Selecting a CAB does not guarantee that its diagnostic evidence is fully supported or complete.

Selected files are read locally in browser memory and are not uploaded or stored by the site. Redaction is best-effort: review evidence and exports before sharing. Do not commit real diagnostic logs to this public repository. Reloading the page clears imported evidence.

The dashboard suggests investigation and resolution steps without executing repairs or changing endpoint settings. Updates to `main` are published through GitHub Actions. See [GitHub Pages publishing instructions](DEPLOY-GITHUB-PAGES.md) for deployment details.

For development, run `npm ci` and then `npm test` with Node.js. The DOM test dependency is used only by tests; the published site requires no installation or build.

The **Analysis readiness** test result in the executive analysis and exported brief checks evidence presence, UTC timeline usability, unavailable sources, import truncation notices and unexplained signals. It follows the current filters and contributing reports; latest CAB coverage is shown separately. Results describe evidence usability and required review, never a device-health pass or a confirmed cause.

Version 1.6 adds 13 reviewed knowledge patterns: six Windows Update outcomes, four AppX deployment results and three Entra device-status observations. Source links and review dates are visible in the knowledge base; recognized executive interpretations also include a Microsoft source link. See [knowledge sources and KPI definitions](KNOWLEDGE-SOURCES.md). AppX/MSIX deployment records share the existing software-delivery workstream named Win32 apps. A missing PRT is informational and context dependent; a device-auth check execution error is distinguished from a failed device status.

Explained-signal coverage divides unique rule-explained records by the union of explained and unexplained signal records, excluding ordinary records and supplied-only interpretations. Priority evidence timing uses unique visible linked records for error/high/critical findings. Shared identifiers are grouped within each report across different sources; device, app and tenant IDs can span unrelated operations. The index stops after 100,000 identifier references and labels its count as a lower bound when capped. Percentages with no eligible denominator display an em dash. All three metrics follow the dashboard filters and appear in exported briefs. These are locally defined evidence metrics, not externally validated diagnostic accuracy or endpoint-health scores.

Version 1.6.1 improves browser compatibility, exports and accessibility. The UI no longer requires `Object.hasOwn`, `Array.at` or regex lookbehind; finding details use a named nonmodal fallback when native dialog methods are unavailable. Counts use en-US grouping and all first-party script/style entry points carry the release cache version. Chart labels now include workstream or lifecycle context and filter buttons expose their selected state. Shared escaping and hashing helpers retain the legacy identifier algorithms, including Unicode edge cases.

Exports retain their Blob URLs for the lifetime of the document so delayed browser Save dialogs can still use them. Closing or reloading the page releases those resources; repeated exports retain their data in memory until then. Failed export handoffs release their URL immediately. Browser API guidance: [Blob URL lifecycle](https://developer.mozilla.org/en-US/docs/Web/URI/Reference/Schemes/blob).

Archive summaries are scoped to the native reports that came from each CAB. Combined raw investigations retain selection-wide coverage limitations, including unread CABs. Relevant warnings stay in individual exports; combined dashboard/brief views deduplicate identical messages. Regression tests exercise missing modern JS APIs, export lifecycle, legacy ID stability, scoped archive notices, contextual chart names and dialog fallback. These checks do not certify every historical Safari/Chrome build.

### v1.6.2 executive dashboard update

Integrates the recovered dashboard design on top of v1.6.1: persistent dark/light theme, source inventory and UTC evidence gauges, supplied confidence ratings, proportional source distribution, evidence activity density, and stage counts relative to the peak stage. Gauges describe the current selection, not endpoint health or independently validated root causes. Empty denominators show an em dash. The evidence sparkline uses timed records; other KPI badges describe scope rather than invented trends.

`docs/dashboard-showcase.html` is an explicitly labelled, synthetic design showcase. Its Tailwind utilities are precompiled into `docs/showcase.css`, so no third-party runtime script is needed. Rebuild with `npx --yes --package tailwindcss@3.4.17 tailwindcss --content ./docs/dashboard-showcase.html --output ./docs/showcase.css --minify`.

### v1.6.3 live evidence and findings

The former static showcase URL now opens `index.html#evidence`. The Evidence & findings sidebar view shares imported reports, filters, finding details and exports with Executive dashboard and Guided investigation. It lists source records in pages of 100 and up to 60 ranked findings; filters cover all records, not only the visible page. Switch views inside the app to retain imported data. Files remain in memory for the current page session; opening another tab or reloading requires re-import. Demonstration data remains explicitly labelled until an import succeeds. The old synthetic showcase metrics are no longer served.
