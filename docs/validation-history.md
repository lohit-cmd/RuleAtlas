# v0.1.2 Windows extraction fix validation

Tested on 2026-09-21 with Python 3.12 on Linux.

- **47 automated tests passed.** Added regression tests for omitting deep Sigma test
  logs, preserving Panther companion files, traversal protection with filters,
  selective symlink rejection, Windows drive/UNC path formatting, extraction and
  ingestion of selected paths longer than 260 characters, cleanup, and preserving
  indexed rules after directory read failures.
- A fresh live HTTPS Sigma import extracted and indexed **3,760 rules**, with zero
  skipped configured files, at `2e8fd89f82d9104c1b30321a307254ddeea17de2`.
  This matches the prior full-archive import count at the same revision.
- The screenshot's failure happened after download during extraction of an unrelated
  regression `.evtx` file. Its deeply nested path is consistent with Windows MAX_PATH
  restrictions. v0.1.2 omits these files and uses extended-length Windows paths for
  selected rule content.
- Windows execution remains unverified locally. Path-format tests run here, but only
  the included Windows CI matrix or testing on Windows can validate the OS-specific
  filesystem behavior. The long-path test is included in that matrix.
- No change to token handling, retrieval ranking, or source credibility assessments.
- Earlier release validation below is historical; browser flows were checked for
  v0.1.1 and were not changed beyond the displayed version number in this patch.

---

# v0.1.1 sync fix validation

Tested on 2026-09-21 with Python 3.12 on Linux.

- 40 automated tests passed, including download failure preserving existing rules,
  commit-pinned archive ingestion without Git, download/extraction bounds, unsafe ZIP
  paths and links, secret redaction, Git diagnostics, and failed/partial/success job states.
- Live default HTTPS archive sync indexed **3,760 Sigma records**, with zero skipped
  configured files, at `2e8fd89f82d9104c1b30321a307254ddeea17de2`.
- Chromium browser smoke checks passed, including archive default, both transport
  selections sent to the API, failed-job display and re-enabled retry button, plus
  existing search, evidence, assessment and export flows.
- Windows and macOS execution remain unverified locally. The reported Git exit 128
  alone cannot establish the original network/checkout failure cause.
- The archive method needs GitHub API and codeload HTTPS access; it does not remedy
  blocked network access or missing trusted certificates.

The earlier release's import results below are retained as historical evidence;
only Sigma was tested live using the new archive transport for this patch.

---

# Validation performed for v0.1.0

Tested on 2026-09-21 using Python 3.12.14 on Linux.

## Automated checks

- 27 Python unit/integration tests passed.
- Editable Python package installation succeeded.
- JavaScript syntax check passed.
- Real Chromium browser checks passed: exact sub-technique search, optional parent expansion, source filter, scenario-evidence lines, CSV download, 25-source catalog, six evidence fields, assessment save/restore, mobile width, and no browser runtime errors.
- Mobile viewport: 430 pixels; document scroll width: 430 pixels.
- GitHub repository discovery succeeded without an API token for a bounded SigmaHQ query.
- Official Enterprise ATT&CK 18.1 download/import succeeded: 849 technique/tactic records, including historical/deprecated/revoked objects present in that bundle.

## Live upstream imports

These counts describe records extracted by the configured paths/adapters at the exact revisions below. They are not totals of all vendor-product detections or proof that the detection logic works in production.

| Source | Indexed records | Files producing no supported record | Tested revision |
|---|---:|---:|---|
| sigma | 3760 | 0 | `2e8fd89f82d9104c1b30321a307254ddeea17de2` |
| splunk | 2169 | 0 | `7b6385a2f27505500c8d18cebca9a83513d33b39` |
| elastic | 2141 | 106 | `c66b12c9493f4bf1121a59b8c705da894ff380e8` |
| chronicle | 917 | 0 | `234e9223c3b8f3d1c30209d9663797ba69057533` |
| sublime | 1284 | 0 | `1a4de55cd279f5630ea287d116cb556d5316dd89` |
| ctid-cloud | 13 | 4 | `6106cc1db4470c63aff856e5bb177efeeca4c4de` |
| falco | 95 | 0 | `e822409d8a2a28c9719f56ace66e8cadebfd2bc3` |

**10,379 upstream records** were indexed across seven repositories. Eight original synthetic demo records were also used for UI checks. Neither the live index nor downloaded third-party repositories are included in the source ZIP.

## Practical limits

- Live end-to-end import was verified for seven of the 25 configured seed sources; the remaining source/path combinations need validation against their current upstream revision.
- Elastic entries without a supported rule query and non-detection CTID YAML files are reported as skipped. The import report records their paths.
- Parsing and retrieving a rule is not detection-engine syntax validation or attack replay validation. Imported rules remain untested.
- Semantic embedding search and automated behavioral proof are not included in v0.1. Keyword/ATT&CK retrieval and literal evidence inspection are implemented.
- Windows/macOS launchers are supplied; those operating systems were not available for local execution. GitHub CI is configured for Windows and Linux but was not run on GitHub.
- The local server is an evaluation server, not a public multi-user deployment.

## Fixes found during validation

- YAML date objects are normalized before JSON persistence.
- Null publisher references no longer stop a complete source import.
- Package discovery explicitly excludes local data/cache content.
- Technique IDs in ordinary reference URLs are not promoted to structured ATT&CK mappings.
- Rule detail controls are replaced while a new record loads, preventing edits to stale fields.
