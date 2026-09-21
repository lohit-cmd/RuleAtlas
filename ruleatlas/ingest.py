import fnmatch
import json
import ntpath
import os
import re
import shutil
import subprocess
import stat
import tempfile
import time
import zipfile
import hashlib
import concurrent.futures
from contextlib import contextmanager
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath

from .catalog import REPO_PATTERN
from .parsers import parse_file, MAX_FILE
from .paths import portable_relative_path
from .store import now


def github_json(path, params=None):
    if not path.startswith("/") or path.startswith("//"):
        raise ValueError("Expected GitHub API path")
    url = "https://api.github.com" + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "RuleAtlas/0.1"}
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if token:
        headers["Authorization"] = "Bearer " + token
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, hdrs, newurl):
            return None
    try:
        with urllib.request.build_opener(NoRedirect).open(urllib.request.Request(url, headers=headers), timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as e:
        if e.code in {403, 429}:
            raise RuntimeError(f'GitHub access/rate limit ({e.code}); retry-after={e.headers.get("Retry-After", "not supplied")}, reset={e.headers.get("X-RateLimit-Reset", "not supplied")}. Retry later; existing index is preserved.') from None
        raise RuntimeError(f"GitHub API returned HTTP {e.code}") from None


def discover(query, pages=2):
    items, incomplete, total = {}, False, 0
    for page in range(1, min(max(pages, 1), 10) + 1):
        data = github_json("/search/repositories", {"q": query, "per_page": 100, "page": page})
        total = data.get("total_count", 0)
        incomplete |= data.get("incomplete_results", False)
        for item in data.get("items", []):
            items[item["full_name"]] = {"repo": item["full_name"], "url": item["html_url"], "description": item.get("description"),
                "archived": item["archived"], "fork": item["fork"], "pushed_at": item.get("pushed_at"),
                "stars": item["stargazers_count"], "review_status": "unreviewed; not added to catalog"}
        if len(data.get("items", [])) < 100:
            break
    return {"query": query, "reported_total": total, "returned": len(items), "incomplete": incomplete or len(items) < total,
            "notice": "Discovery is bounded by GitHub search limits. Popularity does not establish credibility.", "candidates": list(items.values())}


def fetch_attack(store, domain, version):
    if domain not in {"enterprise", "mobile", "ics"} or not re.fullmatch(r"\d{1,2}\.\d{1,2}", version):
        raise ValueError("Choose enterprise/mobile/ics and an explicit release, such as 18.1")
    url = f"https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{domain}-attack/{domain}-attack-{version}.json"
    with urllib.request.urlopen(url, timeout=60) as response:
        raw = response.read(60 * 1024 * 1024 + 1)
    if len(raw) > 60 * 1024 * 1024:
        raise ValueError("ATT&CK bundle exceeds the 60 MiB import limit")
    count = store.import_attack(json.loads(raw), f"{domain}-{version}")
    return {"records": count, "version": f"{domain}-{version}", "source_url": url}


def safe_diagnostic(error):
    text = str(error)
    for name, value in os.environ.items():
        if value and len(value) >= 6 and any(s in name.upper() for s in ("TOKEN", "PASSWORD", "SECRET")):
            text = text.replace(value, "[redacted]")
    text = re.sub(r"(https?://)[^\s/@]+@", r"\1[redacted]@", text)
    text = re.sub(r"(?i)(authorization\s*[:=]\s*).*", r"\1[redacted]", text)
    text = re.sub(r"(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]+", "[redacted]", text)
    text = re.sub(r"(?i)([?&](?:token|access_token|key)=)[^&\s]+", r"\1[redacted]", text)
    return " ".join(text.split())[:1600]


def git_run(args, cwd=None):
    # Preserve system TLS/proxy settings. An empty native directory disables hooks on every OS.
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    try:
        with tempfile.TemporaryDirectory(prefix="ruleatlas-hooks-") as hooks:
            result = subprocess.run(["git", "-c", f"core.hooksPath={Path(hooks).as_posix()}",
                "-c", "core.longpaths=true", *args], cwd=cwd, env=env,
                capture_output=True, text=True, errors="replace", timeout=300)
    except FileNotFoundError:
        raise RuntimeError("Git was not found. Select HTTPS archive download, or install Git and restart RuleAtlas.") from None
    except subprocess.TimeoutExpired:
        raise RuntimeError("Git timed out after 300 seconds. Check your network/proxy, or select HTTPS archive download.") from None
    if result.returncode:
        detail = safe_diagnostic(result.stderr or result.stdout or "No diagnostic supplied by Git")
        raise RuntimeError(f"Git failed (exit {result.returncode}): {detail}. Try HTTPS archive download; check TLS/proxy settings if both methods fail.")
    return result.stdout.strip()


MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_EXTRACTED_BYTES = 1024 * 1024 * 1024


def windows_extended_path(path):
    """Normalize an absolute Windows path for Unicode file APIs, including UNC."""
    path = ntpath.normpath(str(path))
    if path.startswith("\\\\?\\"):
        return path
    if path.startswith("\\\\"):
        return "\\\\?\\UNC\\" + path[2:]
    drive, tail = ntpath.splitdrive(path)
    if not drive or not tail.startswith("\\"):
        raise ValueError("An absolute Windows path is required")
    return "\\\\?\\" + path


def native_path(path):
    path = Path(path).resolve()
    return Path(windows_extended_path(path)) if os.name == "nt" else path


@contextmanager
def download_workspace(cache, prefix, progress=None):
    temporary = Path(tempfile.mkdtemp(prefix=prefix, dir=cache))
    try:
        yield temporary
    finally:
        for attempt in range(3):
            try:
                shutil.rmtree(temporary)
                break
            except FileNotFoundError:
                break
            except OSError:
                if attempt == 2:
                    if progress:
                        progress(f"Cleanup warning: could not remove temporary folder {temporary.name}; indexed results are unaffected. Remove it after stopping the app.")


def resolve_revision(source):
    ref = urllib.parse.quote(source.get("ref", "HEAD"), safe="")
    revision = github_json(f'/repos/{source["repo"]}/commits/{ref}').get("sha", "")
    if not re.fullmatch(r"[a-fA-F0-9]{40}", revision):
        raise ValueError("GitHub did not return a full commit SHA; import cancelled")
    return revision


def sync_files(store, source, cache, progress=None):
    """Select immutable blobs from the Git tree; avoid downloading repository assets."""
    repo = source["repo"]
    if progress:
        progress(f"Resolving {repo} for selective HTTPS download")
    revision = resolve_revision(source)
    tree = github_json(f"/repos/{repo}/git/trees/{revision}", {"recursive": "1"})
    if tree.get("truncated"):
        raise ValueError("GitHub tree is truncated; use Git transport to avoid an incomplete import")
    entries = [e for e in tree.get("tree", []) if e.get("type") == "blob" and (
        any(fnmatch.fnmatch(e["path"], p) for p in source["patterns"])
        or (source["adapter"] == "panther" and e["path"].lower().endswith(".py")))]
    if not entries:
        raise ValueError("No files matched configured source paths; previous snapshot preserved")
    if len(entries) > 100000 or sum(e.get("size", MAX_FILE + 1) for e in entries) > MAX_EXTRACTED_BYTES:
        raise ValueError("Selected files exceed import limits")
    blobs = cache / "blobs"
    blobs.mkdir(exist_ok=True)
    with download_workspace(cache, source["id"] + "-files-", progress) as root:
        path_map = {portable_relative_path(e["path"]): e["path"] for e in entries}
        def download(entry):
            name, sha = entry["path"], entry["sha"]
            parts = PurePosixPath(name).parts
            if not parts or name.startswith("/") or ".." in parts or "\\" in name or ":" in name or ".git" in parts:
                raise ValueError("Unsafe path in GitHub tree")
            if entry.get("mode") not in {"100644", "100755"} or not re.fullmatch(r"[a-f0-9]{40}", sha):
                raise ValueError("Selected GitHub entry is not a regular file")
            if entry.get("size", MAX_FILE + 1) > MAX_FILE:
                raise ValueError(f"Selected file exceeds 2 MiB: {name}")
            cached = blobs / sha
            raw = cached.read_bytes() if cached.is_file() else None
            def digest(data):
                return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
            if raw is None or digest(raw) != sha:
                url = f'https://raw.githubusercontent.com/{repo}/{revision}/{urllib.parse.quote(name, safe="/")}'
                request = urllib.request.Request(url, headers={"User-Agent": "RuleAtlas"})
                with urllib.request.urlopen(request, timeout=60) as response:
                    raw = response.read(MAX_FILE + 1)
                if len(raw) > MAX_FILE or digest(raw) != sha:
                    raise ValueError(f"Downloaded blob hash/size mismatch: {name}")
                with tempfile.NamedTemporaryFile(dir=blobs, delete=False) as out:
                    out.write(raw)
                    temp_name = out.name
                try:
                    os.replace(temp_name, cached)
                finally:
                    Path(temp_name).unlink(missing_ok=True)
            target = root / portable_relative_path(name)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            for i, _ in enumerate(pool.map(download, entries), 1):
                if progress and (i == 1 or i % 100 == 0 or i == len(entries)):
                    progress(f"Downloaded/verified {repo}: {i}/{len(entries)} files")
        return ingest_directory(store, source, root, revision, progress, path_map=path_map)


def extract_archive(archive, destination, patterns=None, adapter=None, path_map=None):
    """Extract a GitHub ZIP without links, traversal, or unbounded expansion."""
    destination = native_path(destination)
    with zipfile.ZipFile(archive) as bundle:
        entries = bundle.infolist()
        if len(entries) > 100000:
            raise ValueError("Archive exceeds the extraction limit (100,000 entries)")
        roots, targets = set(), set()
        extracted, selected_bytes = 0, 0
        for entry in entries:
            name = entry.filename
            parts = PurePosixPath(name).parts
            if not parts or name.startswith("/") or "\\" in name or ":" in name or ".." in parts:
                raise ValueError("Unsafe path in repository archive")
            roots.add(parts[0])
            if len(roots) > 1:
                raise ValueError("Expected one repository root in archive")
            if len(parts) < 2:
                if not entry.is_dir():
                    raise ValueError("Expected a repository root directory")
                continue
            if ".git" in parts[1:]:
                raise ValueError("Unexpected Git metadata in archive")
            relative = PurePosixPath(*parts[1:]).as_posix()
            # Mirror the ingestion patterns. Panther additionally reads Python companion files.
            # Do not unpack test logs, binaries, documentation, or empty directory trees.
            if patterns is not None and (entry.is_dir() or not (
                any(fnmatch.fnmatch(relative, pattern) for pattern in patterns)
                or (adapter == "panther" and relative.lower().endswith(".py"))
            )):
                continue
            if path_map is None and any(p.endswith((".", " ")) or re.fullmatch(r"(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", p) for p in parts):
                raise ValueError("Archive contains a selected path incompatible with Windows; use offline ingestion on a compatible OS")
            if stat.S_IFMT(entry.external_attr >> 16) not in {0, stat.S_IFREG, stat.S_IFDIR}:
                raise ValueError("Links or special files selected in repository archive are unsupported; use Git sync")
            selected_bytes += entry.file_size
            if selected_bytes > MAX_EXTRACTED_BYTES:
                raise ValueError("Selected files exceed the extraction limit (1 GiB)")
            physical = portable_relative_path(relative) if path_map is not None else relative
            if path_map is not None:
                path_map[physical] = relative
            target = destination.joinpath(*PurePosixPath(physical).parts).resolve()
            if not target.is_relative_to(destination):
                raise ValueError("Archive path escapes destination")
            key = str(target).casefold() if os.name == "nt" else str(target)
            if key in targets:
                raise ValueError("Duplicate archive destination")
            targets.add(key)
            if entry.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(entry) as src, target.open("xb") as dst:
                    shutil.copyfileobj(src, dst, 1024 * 1024)
                extracted += 1
        return extracted


def sync_archive(store, source, cache, progress=None):
    repo = source["repo"]
    if progress:
        progress(f"Resolving {repo} default branch revision via GitHub API")
    revision = resolve_revision(source)
    # A separate unauthenticated request keeps API tokens away from the download host.
    url = f"https://codeload.github.com/{repo}/zip/{revision}"
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, hdrs, newurl):
            return None
    with download_workspace(cache, source["id"] + "-archive-", progress) as temp:
        archive = Path(temp) / "source.zip"
        root = Path(temp) / "source"
        if progress:
            progress(f"Downloading {repo} via HTTPS archive at {revision[:12]}")
        request = urllib.request.Request(url, headers={"User-Agent": "RuleAtlas/0.1.3"})
        limit = min(int(source.get("archive_max_mib", MAX_ARCHIVE_BYTES // (1024 * 1024))), 4096) * 1024 * 1024 if "archive_max_mib" in source else MAX_ARCHIVE_BYTES
        started, size, reported = time.monotonic(), 0, 0
        with urllib.request.build_opener(NoRedirect).open(request, timeout=60) as response, archive.open("wb") as out:
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                if size > limit or time.monotonic() - started > 600:
                    raise ValueError(f"Archive download exceeds {limit // (1024 * 1024)} MiB or 10 minutes; use selected-files HTTPS, Git or offline ingestion")
                out.write(chunk)
                if progress and size - reported >= (100 if limit > MAX_ARCHIVE_BYTES else 5) * 1024 * 1024:
                    progress(f"Downloading {repo}: {size // (1024 * 1024)} MiB")
                    reported = size
        if progress:
            progress(f"Extracting configured rule files from {repo}")
        path_map = {}
        extracted = extract_archive(archive, root, source["patterns"], source["adapter"], path_map)
        if not extracted:
            raise ValueError("No files matched configured source paths; previous snapshot preserved")
        if progress:
            progress(f"Extracted {extracted} rule/support files; unrelated archive files omitted")
        return ingest_directory(store, source, root, revision, progress, path_map=path_map)


def ingest_directory(store, source, root, commit="", progress=None, path_map=None):
    root = native_path(root)
    if not root.is_dir():
        raise ValueError("Source directory does not exist")
    if commit and not re.fullmatch(r"[a-fA-F0-9]{40,64}", commit):
        raise ValueError("Commit must be a full Git revision hash")
    if (root / ".git").is_dir():
        actual = git_run(["rev-parse", "HEAD"], cwd=root)
        if commit and commit.lower() != actual.lower():
            raise ValueError("Supplied revision differs from the source checkout")
        commit = actual
    candidates, errors, records, skipped = [], [], [], []
    patterns = source["patterns"]
    def walk_error(error):
        raise error  # An unreadable directory must not silently create a partial snapshot.
    for directory, dirs, names in os.walk(root, followlinks=False, onerror=walk_error):
        dirs[:] = sorted(d for d in dirs if d not in {".git", "node_modules", ".venv", "__pycache__"} and not (Path(directory) / d).is_symlink())
        for name in sorted(names):
            p = Path(directory) / name
            physical = p.relative_to(root).as_posix()
            relative = path_map.get(physical, physical) if path_map is not None else physical
            if any(fnmatch.fnmatch(relative, pattern) for pattern in patterns):
                candidates.append(p)
    if not candidates:
        raise ValueError("No files matched this source's configured paths; previous snapshot preserved")
    companions = {logical: root / physical for physical, logical in path_map.items()} if path_map is not None else None
    for i, path in enumerate(candidates):
        physical = path.relative_to(root).as_posix()
        relative = path_map.get(physical, physical) if path_map is not None else physical
        try:
            parsed = parse_file(source, root, path, commit, original_path=relative, companions=companions)
            records.extend(parsed)
            if not parsed:
                skipped.append(relative)
        except Exception as error:
            errors.append({"path": relative, "error": str(error)[:300]})
        if progress and i % 100 == 0:
            progress(f'Parsing {source["id"]}: {i+1}/{len(candidates)} files')
    if not records:
        raise ValueError("No supported detection/reference records found; previous snapshot preserved")
    # Do not replace a previously good snapshot with a partially parsed one.
    if errors:
        report = {"source_id": source["id"], "candidate_files": len(candidates), "parsed_records": len(records), "errors": errors}
        report_path = Path(store.path).parent / f'{source["id"]}-import-errors.json'
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        raise ValueError(f'{len(errors)} file(s) failed; previous snapshot preserved. Inspect {report_path.name}.')
    warnings = [{"path": r["path"], "error": r["metadata"].get("parse_error", "")} for r in records if r["parse_status"].startswith("parse failed")]
    status = {"source_id": source["id"], "status": "indexed with warnings" if warnings else "indexed", "count": len(records), "candidate_files": len(candidates),
        "warning_count": len(warnings), "parse_warnings": warnings,
        "skipped_file_count": len(skipped), "skipped_file_examples": skipped[:50],
        "commit": commit or "unknown local revision", "last_success": now(), "last_attempt": now(), "last_error": None,
        "notice": "Complete for configured paths and supported formats; not a claim of full vendor coverage."}
    report_path = Path(store.path).parent / f'{source["id"]}-import-report.json'
    report_path.write_text(json.dumps({**status, "skipped_files": skipped}, indent=2), encoding="utf-8")
    store.replace_source(source["id"], records, status)
    return status


def sync_source(store, source, cache, progress=None, transport="archive"):
    if not REPO_PATTERN.fullmatch(source["repo"]):
        raise ValueError("Only public GitHub owner/repository sources are accepted")
    if transport not in {"archive", "files", "git"}:
        raise ValueError("Choose archive, files or git transport")
    cache = native_path(cache)
    cache.mkdir(parents=True, exist_ok=True)
    dest = cache / source["id"]
    url = f'https://github.com/{source["repo"]}.git'
    try:
        if transport == "files" or (transport == "archive" and source.get("download_strategy") == "files"):
            return sync_files(store, source, cache, progress)
        if transport == "archive":
            return sync_archive(store, source, cache, progress)
        if not (dest / ".git").is_dir():
            temporary = cache / (source["id"] + "-download")
            if temporary.exists():
                shutil.rmtree(temporary)
            if progress:
                progress(f'Downloading {source["repo"]}')
            ref_args = ["--branch", source["ref"]] if source.get("ref") else []
            git_run(["clone", "--depth", "1", *ref_args, "--", url, str(temporary)])
            if dest.exists():
                raise RuntimeError("Cache destination exists but is not a Git checkout")
            temporary.rename(dest)
        else:
            remote = git_run(["remote", "get-url", "origin"], cwd=dest)
            if remote != url:
                raise RuntimeError("Cached repository origin differs from catalog")
            if progress:
                progress(f'Updating {source["repo"]}')
            git_run(["fetch", "--depth", "1", "origin", source.get("ref", "HEAD")], cwd=dest)
            git_run(["reset", "--hard", "FETCH_HEAD"], cwd=dest)
        commit = git_run(["rev-parse", "HEAD"], cwd=dest)
        return ingest_directory(store, source, dest, commit, progress)
    except Exception as error:
        detail = safe_diagnostic(error)
        if isinstance(error, (urllib.error.URLError, TimeoutError)):
            detail = f"HTTPS download failed: {detail}. Check GitHub access, proxy and trusted CA certificates; existing index is preserved."
        store.record_failure(source["id"], detail)
        raise RuntimeError(detail) from None


def evidence(rule, requirements):
    """Literal checks provide evidence leads, never automatic behavioral proof."""
    checks = []
    lines = rule["logic"].splitlines()
    for req in requirements[:20]:
        req = str(req).strip()[:200]
        if not req:
            continue
        matches = [{"line": i, "text": line[:500]} for i, line in enumerate(lines, 1) if req.casefold() in line.casefold()][:5]
        checks.append({"requirement": req, "status": "literal evidence found; review semantics" if matches else "not established by literal search", "evidence": matches})
    return {"checks": checks, "verdict": "Manual behavioral review required. Absence of a phrase does not prove absence of behavior; presence may be in a comment or exclusion."}
