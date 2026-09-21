# RuleAtlas v0.1.3 validation

Tested on 2026-09-21, Linux x86_64, Python 3.12.14, SQLite 3.53.1. These are observed results for a finite test scope; they are not a guarantee that every possible defect or upstream rule has been covered.

## Results

- **25/25 configured sources passed live default HTTPS archive ingestion and retrieval checks: 31,584 indexed records.** The table links tested commits; full commits, configured paths, timestamps and checks are in [live-archive-results.json](audit/live-archive-results.json).
- **81/81 offline automated tests passed**, zero skips, failures or errors. [Platform report](audit/self-check.json). Coverage: 86.9% statements, 77.1% branches (84.0% combined). Coverage is measured for the offline suite, not the live browser or download runs.
- Chromium passed 12 demo smoke checks and 13 populated-index checks. All 25 source filters, original logic and revision links were exercised. The live browser check also covers Splunk technique retrieval, pagination, JSON export, HTML injection protection, unsafe links, stale detail responses, visible parse warnings, ATT&CK download and mobile width. [Smoke evidence](audit/browser-smoke.json), [live browser evidence](audit/browser-live.json).
- Alternative transports: Git passed for Sigma, GCP analytics and ELITEWOLF; selective HTTPS files passed for GCP analytics and ELITEWOLF. A repeated GCP Git sync also succeeded. This is **not** a claim that every transport was live-tested against all 25 sources. [Git](audit/live-git-results.json), [selected files](audit/live-files-results.json).
- Official ATT&CK imports passed for Enterprise 19.1 (873 objects), Enterprise 18.1 (849), Mobile 18.1 (190), and ICS 18.1 (95). Counts include the technique/tactic objects retained from each bundle, including historical entries. Bounded live repository discovery returned 23 candidates. Browser discovery rendering used a stub; the separate discovery service call was live. [Service evidence](audit/live-services.json).
- The v0.1.3 wheel installed into an isolated virtual environment. Its entry point, demo/search commands, 25-source registry and packaged web assets passed checks executed outside the source directory. [Packaging evidence](audit/package.json).

## Per-source live results

Every row passed import, record/index consistency, nonempty content, all-record repository/commit/permalink checks, source filtering, detail retrieval, sampled keyword retrieval, ATT&CK retrieval where IDs exist, and CSV/JSON serialization. Browser checks additionally opened each source. Sampled retrieval does not assert relevance for every possible question.

“Records” is adapter output, not a vendor's total rule count: one file may contain several records, or several signatures may be retained as one source-file record. “Candidates” means files matching the configured patterns, before parsing. “Skipped” means candidate files producing no supported record. “Warnings” identifies explicitly retained parse failures.

| Source | Records | Candidates | Skipped | Warnings | Tested commit |
|---|---:|---:|---:|---:|---|
| SigmaHQ | 3,760 | 3,760 | 0 | 0 | [2e8fd89f82d9](https://github.com/SigmaHQ/sigma/commit/2e8fd89f82d9104c1b30321a307254ddeea17de2) |
| Splunk Security Content | 2,169 | 2,169 | 0 | 0 | [7b6385a2f275](https://github.com/splunk/security_content/commit/7b6385a2f27505500c8d18cebca9a83513d33b39) |
| Elastic Security | 2,247 | 2,247 | 0 | 0 | [c66b12c9493f](https://github.com/elastic/detection-rules/commit/c66b12c9493f4bf1121a59b8c705da894ff380e8) |
| Microsoft Sentinel | 5,023 | 5,544 | 521 | 0 | [20c2848aa784](https://github.com/Azure/Azure-Sentinel/commit/20c2848aa78467a4d6fd8a0af6e3c32aaf9578fe) |
| Google SecOps | 917 | 917 | 0 | 0 | [234e9223c3b8](https://github.com/chronicle/detection-rules/commit/234e9223c3b8f3d1c30209d9663797ba69057533) |
| Google Community Security Analytics | 13 | 13 | 0 | 0 | [2dd8565557e0](https://github.com/GoogleCloudPlatform/security-analytics/commit/2dd8565557e043e25d16df8f7743b9e69374d6f3) |
| Panther | 1,024 | 1,024 | 0 | 0 | [a15eae672776](https://github.com/panther-labs/panther-analysis/commit/a15eae67277660941884d9053d6d654395b64e17) |
| Sekoia Community | 30 | 30 | 0 | 0 | [fa3a9630ef9c](https://github.com/SEKOIA-IO/Community/commit/fa3a9630ef9ce484fb1b945480a43f989e6865d4) |
| Sublime Security | 1,284 | 1,284 | 0 | 0 | [1a4de55cd279](https://github.com/sublime-security/sublime-rules/commit/1a4de55cd279f5630ea287d116cb556d5316dd89) |
| CTID Cloud Analytics | 13 | 17 | 4 | 0 | [6106cc1db447](https://github.com/center-for-threat-informed-defense/cloud-analytics/commit/6106cc1db4470c63aff856e5bb177efeeca4c4de) |
| Bert-Jan KQL | 840 | 459 | 8 | 0 | [60a829ba4629](https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules/commit/60a829ba4629f6d63866146f0a1b9cb90f31bb03) |
| reprise99 KQL | 562 | 470 | 5 | 0 | [660895f644b2](https://github.com/reprise99/Sentinel-Queries/commit/660895f644b2a149009820f653978620f65ef56c) |
| Yamato Security | 4,987 | 4,984 | 0 | 0 | [10d1b6dc3ec8](https://github.com/Yamato-Security/hayabusa-rules/commit/10d1b6dc3ec884daf04d736a7fc78bf2ee898664) |
| Elastic Endpoint | 1,327 | 1,327 | 0 | 0 | [ce99f77ba7cc](https://github.com/elastic/protections-artifacts/commit/ce99f77ba7cc2e442589d49e01b9db262d31ae91) |
| Falco | 95 | 3 | 0 | 0 | [e822409d8a2a](https://github.com/falcosecurity/rules/commit/e822409d8a2a28c9719f56ace66e8cadebfd2bc3) |
| Aqua Tracee | 117 | 117 | 0 | 0 | [932ca4485fd8](https://github.com/aquasecurity/tracee/commit/932ca4485fd881b11acc8e16d7002e2dde8f4998) |
| Wazuh | 4,512 | 168 | 0 | 0 | [a42268a27c55](https://github.com/wazuh/wazuh/commit/a42268a27c555d9348d5598fb8751eaf4c8e9024) |
| Zeek | 157 | 157 | 0 | 0 | [7061894b1a26](https://github.com/zeek/zeek/commit/7061894b1a266c052acafa307dfeeb35acd73b45) |
| NSA ELITEWOLF | 52 | 4 | 1 | 0 | [f0c4c951ef4b](https://github.com/nsacyber/ELITEWOLF/commit/f0c4c951ef4b8233015259fe5af7c71355c04c4a) |
| Signature Base | 748 | 751 | 3 | 0 | [94a1c48d7ab4](https://github.com/Neo23x0/signature-base/commit/94a1c48d7ab499879287ff611dfe7f9c56376030) |
| ReversingLabs | 310 | 310 | 0 | 0 | [e0a0be54aa1e](https://github.com/reversinglabs/reversinglabs-yara-rules/commit/e0a0be54aa1e11ccfd6854e4f19e9476f328fd84) |
| Mandiant Countermeasures | 172 | 172 | 0 | 0 | [3561b71724db](https://github.com/mandiant/red_team_tool_countermeasures/commit/3561b71724dbfa3e2bb78106aaa2d7f8b892c43b) |
| Mandiant capa | 1,054 | 1,057 | 3 | 0 | [805f9eaccfb6](https://github.com/mandiant/capa-rules/commit/805f9eaccfb6a4e1ddffc809d71d1e2b5ccc15e5) |
| Joe Security | 119 | 119 | 0 | 7 | [cb91be06c8c9](https://github.com/joesecurity/sigma-rules/commit/cb91be06c8c95ce63aa9aa5006a7835678136a96) |
| The DFIR Report YARA | 52 | 53 | 1 | 0 | [9034e24193b3](https://github.com/The-DFIR-Report/Yara-Rules/commit/9034e24193b38aad1fbc0912ace3683eb5728a92) |
| **Total records** | **31,584** | | | | |

Every source's complete skipped-path and warning lists are supplied in `docs/audit/*-import-report.json`. The metadata reports are included; downloaded third-party rule content and live databases are not bundled.

## Fixes found during the audit

- Corrected GCP analytics and ELITEWOLF paths. Selected Wazuh v4.14.7 explicitly after upstream layout migration; preserved Wazuh regex text during XML parsing.
- Corrected Windows-incompatible archive names while preserving original source paths and links; retained selective extraction and extended Windows paths for long names.
- Added a bounded 4 GiB archive allowance specifically for Sentinel. Its tested archive exceeded 3 GiB. An optional selected-files transport downloads configured files, verifies Git blob hashes, and reuses verified local blobs.
- Recovered Elastic ML configurations without query strings. Corrected Markdown code-fence extraction so intervening prose is excluded and commented KQL queries remain searchable.
- Recognized current Splunk `mitre_attack_id`, Sentinel additional technique fields, Joe Security `mitreattack`, and capa `att&ck` metadata. A final scan of technique-related top-level metadata exposed the Splunk omission; regression tests and affected-source live imports were repeated after fixing it. Source-authored mappings remain claims from the source, not independent validation.
- Kept seven malformed Joe Security YAML files as explicit raw reference records with visible warnings. They are not treated as parsed detections.
- Prevented temporary cleanup failures from masking successful imports, kept CLI JSON stdout clean, rejected non-object API JSON, and prevented a late detail response from overwriting empty results.

## Exclusions and remaining test gaps

- **Windows and macOS were not executed here.** Windows path regressions were exercised on Linux; native filesystem, launcher and antivirus interactions remain unverified. Run `verify_windows.bat` on Windows. The supplied GitHub Actions matrix defines Linux/Windows/macOS with Python 3.11–3.14, but it has not been run on GitHub.
- **No vendor engine syntax validation or attack replay was performed.** Imported entries remain `untested`. Splunk macros, runtime helpers, connectors, ML jobs and environmental prerequisites require deployment-specific review. This tool's tests validate indexing and retrieval, not whether a rule detects an attack.
- Sentinel's **521 excluded files were individually classified as migration/deprecation or retirement notices without a query**. [Review evidence](audit/sentinel-skipped-review.json). Other skipped candidate paths include documentation and unsupported/helper files, listed per source. Files outside configured paths are not counted as candidates.
- Joe Security's 119 records comprise 112 parsed records and seven raw references. Wazuh support is pinned to v4.14.7 XML; Wazuh 5.x content is outside that adapter's scope.
- A source being listed or successfully imported does not establish community credibility, complete product coverage, or all six evidence checks. Missing evidence stays unknown. The catalog records ownership, adoption, engineering quality, maintenance, traceability and rule validation separately.
- Retrieval is lexical plus ATT&CK matching and literal evidence inspection. Embedding search and proof of behavioral equivalence are not implemented. No internal-policy comparison is included.
- Live checks depend on network availability, GitHub rate limits and upstream revisions. Optional GitHub token support uses a process environment variable; an actual user token was not supplied for this audit. Authentication/error handling has offline tests. See [GitHub's official rate-limit documentation](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api).
- A repeat Sentinel archive download exhausted temporary workspace disk space; the prior index was preserved. Disposable test caches were cleared before retrying. Keep sufficient free disk space for archives and cleanup warnings.
- The app is a local evaluation server. Public multi-user hosting, large concurrent workloads, private repositories and comprehensive penetration testing are outside this release's validation scope.

## Reproduce

```bash
python tests/self_check.py
python tests/live_sources.py --data-dir test-results/live-audit --workers 3
python tests/live_sources.py --data-dir test-results/git-audit --transport git --sources sigma gcp-analytics elitewolf
python tests/live_sources.py --data-dir test-results/files-audit --transport files --sources gcp-analytics elitewolf
```

For browser smoke tests, follow the README. To test a populated index, start the server with the same `--data-dir` used by the live audit, then run `node tests/browser_live.cjs`. Use a separate test directory: browser tests import ATT&CK data and edit temporary assessment values. They never execute upstream rules.

Historical release results are retained separately in [validation-history.md](validation-history.md).
