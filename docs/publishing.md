# Publish RuleAtlas on GitHub

These instructions publish the project source for people to download and run locally. They do not deploy a hosted RuleAtlas service. Replace `YOUR_USERNAME`, sample names, email and paths with your own values. The application code remains v0.1.3; this preparation adds documentation.

## 1. Prepare a clean project folder

Download the documentation-updated `RuleAtlas_v0.1.3.zip` and extract it into a new folder, such as `C:\Tools\RuleAtlas`. Use the inner directory containing `README.md`, `pyproject.toml`, `start_windows.bat`, `ruleatlas`, `tests`, `docs` and `.github` as the repository root.

Publish the extracted source files. A repository containing only the ZIP will not display the source tree or run the included workflows. The ZIP can be attached separately to a GitHub release.

Keep the supplied `LICENSE`, `.gitignore`, `CONTRIBUTING.md`, `SECURITY.md`, documentation and tests. Your runtime `data` folder, downloaded upstream repositories, tokens, `.env`, `.venv` and test exports do not belong in the published source. Use this clean extracted copy instead of copying your populated working index.

## 2. Create the repository

1. Sign in at [GitHub](https://github.com/).
2. Select **New repository** (or open [github.com/new](https://github.com/new)).
3. Name the repository `RuleAtlas`.
4. Suggested description: **Search public detection rules by ATT&CK ID and keywords, inspect original logic and source evidence, and export candidates.**
5. Select **Public** for the open-source project you want to publish.
6. Leave automatic README, license and gitignore initialization off; the project already includes those files.
7. Create the repository and copy its HTTPS URL.

GitHub's [local project import instructions](https://docs.github.com/en/migrations/importing-source-code/using-the-command-line-to-import-source-code/adding-locally-hosted-code-to-github) describe this workflow.

## 3. Upload the source using Git on Windows

Install [Git for Windows](https://git-scm.com/downloads/win), including its Git Credential Manager option, and open a new PowerShell window. Run commands from the extracted project root:

```powershell
cd C:\Tools\RuleAtlas
git --version
git init -b main
git config user.name "YOUR NAME"
git config user.email "YOUR GITHUB COMMIT EMAIL"
git add README.md LICENSE CONTRIBUTING.md SECURITY.md .gitignore pyproject.toml requirements.txt package.json start_windows.bat start_unix.sh verify_windows.bat ruleatlas tests docs .github
git diff --cached --stat
git status --short
git commit -m "Initial RuleAtlas v0.1.3 open-source release"
git remote add origin https://github.com/YOUR_USERNAME/RuleAtlas.git
git push -u origin main
```

Use an email associated with your GitHub account or the no-reply commit email shown in GitHub's email settings. Complete Git Credential Manager's browser sign-in when prompted. GitHub documents this [credential workflow](https://docs.github.com/en/get-started/git-basics/caching-your-github-credentials-in-git). The optional public-read token used by RuleAtlas is not intended to authorize this push, especially changes to `.github/workflows`.

Before the commit, the staged file list should contain source code, docs and tests, with no populated database or credentials. Do not execute the `remote add` example with the placeholder username still present. These commands assume a fresh local folder and empty remote repository; an existing project or remote needs its current Git state reviewed first.

### Alternative: browser upload

On an empty repository page, choose the link to upload existing files; in an initialized repository use **Add file → Upload files**. Upload the project contents at the repository root, then commit them. Ensure `.github/workflows/test.yml` and `.gitignore` are included; dot-prefixed files can be overlooked in file pickers. Git is the clearer route for preserving the complete project structure.

## 4. Check the published repository

- The root README should render the problem statement, intended users, installation instructions, screenshot and usage details.
- Open the **Actions** tab and inspect the `Test` workflow. It defines Python tests on Linux, Windows and macOS, plus a Linux browser smoke test. A workflow existing in the repository is not a passing result; inspect the completed jobs and their artifacts.
- The routine workflow does not download all 25 repositories. Live source checks are opt-in because they require network access, bandwidth and disk space.
- Your local Windows check: run `verify_windows.bat`, then `start_windows.bat`, open `http://127.0.0.1:8765`, synchronize a source and search its records. Sync all 25 if you want a complete test of the sources on your own machine.
- Set repository topics, for example: `detection-engineering`, `threat-hunting`, `sigma`, `mitre-attack`, `siem`, `security`, `python`.
- Update `SECURITY.md` with your chosen reporting channel and enable GitHub private vulnerability reporting if you want to accept private reports.

## 5. Create a downloadable release

After reviewing your test results, open **Releases → Draft a new release**. Create tag `v0.1.3` on the intended `main` commit. Use title **RuleAtlas v0.1.3 — Community evaluation release**. Mark it as a pre-release while presenting it as an evaluation build. Attach the matching source ZIP if desired, then publish when ready. GitHub also supplies source archives for the tag. See [GitHub release instructions](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository).

Suggested release notes:

> RuleAtlas provides local search across configured public detection repositories using ATT&CK IDs and keywords. It preserves original logic, source revisions and evidence assessments, and exports candidate results as CSV or JSON.
>
> The recorded Linux v0.1.3 audit passed live archive ingestion and retrieval checks for 25 configured sources (31,584 records), 81 offline automated tests and browser checks. Counts describe the tested commits and can change with upstream updates. See docs/validation.md for scope and exceptions.
>
> Imported detection content is not independently replay-validated. Native Windows/macOS execution was not part of the recorded Linux audit; see current CI jobs and local test reports for additional platform evidence.

Do not advertise a passing Windows/macOS CI run before it completes. Routine CI also does not prove all downloads and launchers work on every user's workstation.

## 6. Installation instructions for your users

Your README already includes the full setup. The short path is:

1. Install stable Python 3.11+ from [python.org](https://www.python.org/downloads/).
2. Download the release ZIP or select **Code → Download ZIP** on your repository.
3. Extract it completely.
4. Windows: run `start_windows.bat`. macOS/Linux: run `sh start_unix.sh` from the project folder.
5. Open [http://127.0.0.1:8765](http://127.0.0.1:8765).
6. Go to **Source catalog**, select sources, choose a download method and synchronize.
7. Load an explicit ATT&CK domain/release, such as the previously tested Enterprise 19.1, if technique/tactic validation is needed.
8. Search a technique ID such as `T1059.001`, or a keyword such as `lockbit`. Review source logic and prerequisites before using the candidate.

The first launcher run includes eight synthetic demo examples. The release does not bundle the 31,584-record test index; every user synchronizes their own selected sources. Git is optional for the default HTTPS downloads. The normal application does not need Node.js, a separate database server, PyGithub, an AI subscription or an LLM API key.

Sentinel's tested archive exceeded 3 GiB. Allow room for the archive and extracted files, or select **HTTPS selected files** to reduce downloaded content. Selected-files mode can be slower on its first run. If a source fails, inspect its error; do not infer that a displayed old record count means the latest sync succeeded.

## 7. Optional GitHub API setup

There is no separate API installation. Each user may create their own fine-grained public-read personal access token, set the process environment variable `GITHUB_TOKEN`, and launch RuleAtlas from that same terminal. The README contains the creation steps, hidden-input PowerShell prompt and a rate-limit check:

- [Optional GitHub token](../README.md#optional-github-token)
- [GitHub token documentation](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
- [GitHub REST rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)

Never ship your personal token to users. GitHub Actions' automatically issued `GITHUB_TOKEN` is a separate credential; the ordinary offline workflow does not need you to publish or add your personal discovery token.

## 8. Project positioning

**Problem statement:** Public detection content is fragmented across repositories, formats and vendors. Finding relevant candidates, inspecting their logic and prerequisites, and verifying their provenance requires repeated manual work.

**Intended users:** Detection engineers, threat hunters, SOC analysts, security architects, researchers, learners and open-source contributors.

**Value:** A unified local search interface, ATT&CK and keyword retrieval, original rule logic and revision links, explicit source evidence, identical-logic grouping and portable candidate exports.

**Boundaries:** Configured paths and supported formats define coverage. Search relevance is not detection fidelity. Natural-language semantic reasoning, internal-policy comparison and automatic attack replay are outside the implemented scope. Third-party content retains its upstream license; the supplied MIT license covers original RuleAtlas code, docs and synthetic fixtures.

GitHub hosts the repository and release downloads. Uploading the project does not create an online RuleAtlas application. [GitHub Pages](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages) hosts static sites and cannot run RuleAtlas's Python backend; users run this release locally.
