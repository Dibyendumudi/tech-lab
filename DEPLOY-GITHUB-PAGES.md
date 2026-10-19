# Windows Diagnostics on GitHub Pages

Managed by Dibyendu.

Target repository: <https://github.com/Dibyendumudi/tech-lab>

Expected public website after a successful deployment:
<https://dibyendumudi.github.io/tech-lab/>

This package prepares the site for that address. It does not create or verify a
live deployment, register a domain, or change the existing ChatGPT-hosted site.

## Package contents

```text
docs/
  .nojekyll
  index.html
  app.js
  scenarios.js
  analytics.js
  executive.js
  importer.js
  import-worker.js
  raw-parsers.js
  raw-analysis.js
  cab-format.js
  cab-extractor.js
  vendor/
    libarchive/
      (local decoder JavaScript, WebAssembly and license notices)
  styles.css
  executive.css
.github/
  workflows/
    deploy-pages.yml
DEPLOY-GITHUB-PAGES.md
```

The dashboard files and local import worker are in `docs/`.
Their relative asset and module URLs support the `/tech-lab/` project path.
There are no application secrets, dependencies to install, or build commands.
The existing repository README and desktop ZIP are not replaced.

## Option A: publish with the supplied workflow

1. Extract this ZIP. Copy its contents into your local checkout of `tech-lab`,
   preserving the `docs/` and `.github/workflows/` folder paths. Enable hidden
   files in your file manager so `.github` and `docs/.nojekyll` are included.
   Commit and push these files to `main` with your normal GitHub sign-in.
2. In the repository, open **Settings → Pages**. Under **Build and deployment**,
   set **Source → GitHub Actions**. You need repository admin or maintainer
   permissions to change this setting.
3. Open **Actions → Deploy Windows Diagnostics to GitHub Pages → Run workflow**,
   select `main`, and run it. If the push ran before Pages was enabled, run it
   again after completing step 2. Future pushes to `main` deploy automatically.
4. Allow GitHub to create the default `github-pages` environment. In
   **Settings → Environments → github-pages**, ensure its deployment branch rules
   allow `main`. The workflow also restricts deployment to `main`.
5. Wait for a successful workflow, then open the URL shown in **Settings → Pages**
   or in the deployment job. Test it in a private browser window.

The workflow uses GitHub's automatic `GITHUB_TOKEN` with `contents: read`,
`pages: write`, and `id-token: write`. Do not create or upload a personal access
token, Intune credential, or application secret for this static deployment.

The workflow deploys only `docs/`; desktop archives and other repository files
are not part of the website artifact. This does not make other files in a
public repository private.

### Uploading with the GitHub website

GitHub's **Add file → Upload files** does not extract ZIP contents. Extract this
package first and upload the actual `docs/` folder. Confirm that the repository
shows `docs/index.html`, rather than a ZIP or an extra parent folder.

Some browser or file-manager upload flows skip hidden folders. If
`.github/workflows/deploy-pages.yml` is missing, use **Add file → Create new
file**, enter that complete path as the filename, and paste the supplied
workflow. Create `docs/.nojekyll` the same way if needed; a comment such as
`# Static site: skip Jekyll.` is sufficient. Alternatively, use Option B and
omit the custom workflow entirely.

## Option B: publish directly from main /docs

This simpler option requires no custom workflow file.

1. Upload the extracted `docs/` folder to the root of `main`. Confirm
   `docs/index.html` exists. Include `docs/.nojekyll`; use GitHub's **Create new
   file** if your upload omitted this hidden file.
2. Do not add `.github/workflows/deploy-pages.yml` when choosing this option.
   If already added, disable **Deploy Windows Diagnostics to GitHub Pages** in
   the **Actions** tab so it does not compete with branch publishing.
3. In **Settings → Pages → Build and deployment**, select **Deploy from a
   branch**, choose **main** and **/docs**, then click **Save**.
4. Wait for GitHub's **pages build and deployment** workflow to finish. Open
   the published URL shown in Pages settings.

Choose one publishing method. Both publish the same dashboard files to the same
expected address. Public repositories can use GitHub Pages with GitHub Free.
GitHub account sign-in is required to manage deployment; the public dashboard
itself does not require a ChatGPT account or an application sign-in.

## Use the dashboard

The default dataset consists of synthetic demonstration reports. To display
diagnostic output, choose **Import CAB / logs**. A single `.cab` is opened locally
and its supported readable entries analyzed automatically. There is no need to
extract or select archive members one at a time. Readable `.log`, `.txt`,
`.json`, `.jsonl`, `.ndjson`, `.csv`, and Windows event `.xml` exports can be
analyzed directly in a macOS or Windows browser, together with JSON reports
from the Windows Diagnostics desktop app. UTF-8 and UTF-16 text are supported.
Select up to 20 files. CAB limits are 100 MiB compressed per archive, 2,000 entries
and 256 MiB expanded across selected cabinets; archive members do not count as selected files. Text files are capped
at 20 MiB each. Selections containing CABs are capped at 150 MiB combined; other
selections at 50 MiB. Use **Export brief** for an executive summary and the full
archive coverage inventory.

JSON/CSV/XML files must contain diagnostic event or Entra sign-in fields.
CAB extraction and local decoding use bundled assets under `docs/vendor/`.
Do not omit the WebAssembly or license files when copying/deploying the website.
Binary EVTX and ETL, nested archives and unsupported report/configuration files
are listed as skipped; they are not silently counted as analyzed. Multipart
or invalid cabinets are rejected with a visible reason. Raw imports are combined into one investigation (up to 50,000
records); existing reports keep their supplied findings. Any record truncation,
unreadable files or skipped JSONL lines are reported in import/source notices.
The archive file-by-file inventory remains visible independently of chart
filters and transient status messages, including when no records were loaded.

Imported reports are processed in memory in the browser session and are not
uploaded by this application. Reloading the page clears them. The host still
serves the dashboard files and may record normal site access information.
Do not commit real diagnostic reports, identifiers, credentials, or raw logs to
the public repository. Review redaction before sharing exported reports.

This dashboard does not connect directly to Intune or operate on endpoints.
Counts describe the imported reports and selected evidence, not tenant-wide
device health or complete fleet coverage. It suggests investigation and
resolution steps without executing repairs, deletions, or configuration changes.

## If deployment does not complete

- **Pages settings are unavailable:** confirm you are signed into an account
  with admin or maintainer access to this repository and Pages is permitted by
  the account or organization.
- **Workflow missing:** confirm `.github/workflows/deploy-pages.yml` is an actual
  file on `main`, not inside a ZIP or a parent folder.
- **Pages not configured:** select the publishing source in Settings, then run
  the workflow again.
- **Deployment waiting for approval or rejected:** inspect the `github-pages`
  environment's protection and branch rules; allow `main` and complete any
  approval required by the repository's existing policy.
- **Website returns 404:** check the workflow result and the URL in Pages
  settings. The project path is `/tech-lab/`; the repository URL ending in `.git`
  is a source URL, not the website.
- **Files look unstyled or modules fail:** ensure all browser files are
  together under `docs/`. Preserve their relative paths and open the site over
  HTTPS, rather than double-clicking `index.html` locally.

No custom domain is required for the `github.io` address. A company domain can
be connected separately if you own it and can edit its DNS records.

Official references:

- [Custom workflows with GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages)
- [Configure a publishing source](https://docs.github.com/en/pages/getting-started-with-github-pages/configuring-a-publishing-source-for-your-github-pages-site)
