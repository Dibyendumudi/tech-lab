# tech-lab

## Windows Diagnostics dashboard

Managed by Dibyendu. The browser dashboard is in `docs/`; the Windows desktop app remains in its original ZIP.

Open the [Windows Diagnostics dashboard](https://dibyendumudi.github.io/tech-lab/). 

Start with the demonstration data, or choose **Import logs / reports** to analyze `.log`, `.txt`, `.json`, `.jsonl`, `.ndjson`, `.csv`, or Windows event `.xml` exports directly in your browser on macOS or Windows. Existing Windows Diagnostics JSON reports also work. UTF-8 and UTF-16 text are supported; select at most 20 files, 20 MiB each and 50 MiB combined.

Raw logs are analyzed together into one investigation with linked evidence and suggested checks. Existing report exports keep their supplied findings. CAB archives need extraction first; binary EVTX and ETL require conversion with Windows tools. Arbitrary JSON, CSV or XML documents are not diagnostic records. Choose **Export brief** to download an executive summary.

Selected files are read locally in browser memory and are not uploaded or stored by the site. Redaction is best-effort: review evidence and exports before sharing. Do not commit real diagnostic logs to this public repository. Reloading the page clears imported evidence.

The dashboard suggests investigation and resolution steps without executing repairs or changing endpoint settings. Updates to `main` are published through GitHub Actions. See [GitHub Pages publishing instructions](DEPLOY-GITHUB-PAGES.md) for deployment details.

Run the browser parser, analysis, import and dashboard regression checks with `npm test` (Node.js, no dependencies to install).
