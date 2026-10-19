# tech-lab

## Windows Diagnostics dashboard

Managed by Dibyendu. The browser dashboard is in `docs/`; the Windows desktop app remains in its original ZIP.

Open the [Windows Diagnostics dashboard](https://dibyendumudi.github.io/tech-lab/). 

Start with the demonstration data, or choose **Import CAB / logs** to select a single Windows diagnostic `.cab`. The browser opens the archive and analyzes supported readable entries together; you do not need to extract or select each member. CAB member counts are separate from the 20 selected-file limit. The persistent **Latest CAB import coverage** table lists every entry, record count, skipped/failed source and reason. Coverage is also included in **Export brief**.

Direct `.log`, `.txt`, `.json`, `.jsonl`, `.ndjson`, `.csv`, Windows event `.xml`, and existing Windows Diagnostics JSON reports also work on macOS and Windows. UTF-8 and UTF-16 text are supported. Limits: 100 MiB per CAB, with 2,000 members and 256 MiB expanded across selected CABs; readable files are capped at 20 MiB each. Selections with CABs are capped at 150 MiB combined; other selections at 50 MiB. Raw analysis includes up to 50,000 records, with partial-source notices when capped.

After importing, choose **Investigate evidence** or **Guided investigation**. The selected dataset feeds both views: choose a report in the sidebar, review source coverage, correlate records, inspect findings and review suggestions. Dashboard finding details also open the corresponding report and finding directly. Switch between sample and imported data using the dataset control in either view. Search covers all evidence; long timelines are paginated. JSON and HTML investigation exports preserve imported evidence and its limitations.

Raw logs are analyzed together into one investigation with linked evidence and suggested checks. Existing report exports keep their supplied findings. Binary EVTX/ETL, nested archives, HTML reports, registry dumps and other unsupported entries are listed in CAB coverage rather than treated as analyzed. Arbitrary JSON, CSV or XML documents are not diagnostic records. Selecting a CAB does not guarantee that its diagnostic evidence is fully supported or complete.

Selected files are read locally in browser memory and are not uploaded or stored by the site. Redaction is best-effort: review evidence and exports before sharing. Do not commit real diagnostic logs to this public repository. Reloading the page clears imported evidence.

The dashboard suggests investigation and resolution steps without executing repairs or changing endpoint settings. Updates to `main` are published through GitHub Actions. See [GitHub Pages publishing instructions](DEPLOY-GITHUB-PAGES.md) for deployment details.

For development, run `npm ci` and then `npm test` with Node.js. The DOM test dependency is used only by tests; the published site requires no installation or build.
