import csv
import io
import json
import secrets
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .catalog import CHECKS, load_catalog
from .ingest import discover, evidence, fetch_attack, sync_source
from .store import now


class Application:
    def __init__(self, store, catalog, cache):
        self.store, self.catalog, self.cache = store, Path(catalog), cache
        self.csrf = secrets.token_urlsafe(32)
        self.lock = threading.Lock()
        self.job = {"status": "idle", "messages": [], "results": []}

    def sources(self):
        items = load_catalog(self.catalog)
        states = {s["source_id"]: s for s in self.store.stats()["syncs"]}
        return [{**s, "sync": states.get(s["id"], {"status": "not indexed", "count": 0})} for s in items]

    def write_catalog(self, sources):
        temporary = self.catalog.with_suffix(".tmp")
        temporary.write_text(json.dumps({"schema_version": 1, "sources": sources}, indent=2), encoding="utf-8")
        load_catalog(temporary)
        temporary.replace(self.catalog)

    def start_sync(self, ids, transport="archive"):
        if transport not in {"archive", "files", "git"}:
            raise ValueError("Choose archive, files or git transport")
        sources = {s["id"]: s for s in load_catalog(self.catalog)}
        if not isinstance(ids, list) or not ids or len(ids) > 100 or any(i not in sources for i in ids):
            raise ValueError("Select valid catalog sources")
        with self.lock:
            if self.job["status"] == "running":
                raise ValueError("A synchronization is already running")
            self.job = {"status": "running", "started": now(), "messages": [], "results": []}

        def progress(message):
            with self.lock:
                self.job["messages"] = (self.job["messages"] + [message])[-30:]

        def run():
            for source_id in dict.fromkeys(ids):
                try:
                    result = sync_source(self.store, sources[source_id], self.cache, progress, transport=transport)
                except Exception as error:
                    result = {"source_id": source_id, "status": "failed", "error": str(error)}
                with self.lock:
                    self.job["results"].append(result)
            with self.lock:
                failures = sum(r["status"] == "failed" for r in self.job["results"])
                self.job["status"] = "failed" if failures == len(self.job["results"]) else "completed with errors" if failures else "completed"
                if not failures and any(r.get("warning_count") for r in self.job["results"]):
                    self.job["status"] = "completed with warnings"
        threading.Thread(target=run, daemon=True).start()


def export_csv(rows):
    def safe(value):
        if isinstance(value, (dict, list)):
            value = json.dumps(value, ensure_ascii=False)
        value = str(value)
        return "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) or value.startswith(("\t", "\r", "\n")) else value
    out = io.StringIO(newline="")
    fields = ["title", "source_id", "language", "kind", "attack_ids", "telemetry", "validation", "source_url", "commit", "license"]
    writer = csv.DictWriter(out, fieldnames=fields)
    writer.writeheader()
    writer.writerows({f: safe(r.get(f, "")) for f in fields} for r in rows)
    return out.getvalue().encode("utf-8-sig")


def make_handler(app):
    static = Path(__file__).with_name("static")
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass  # Query text and upstream content are not logged.

        def valid_host(self):
            port = self.server.server_address[1]
            return self.headers.get("Host") in {f"127.0.0.1:{port}", f"localhost:{port}"}

        def reply(self, value, status=200, content_type="application/json", attachment=None):
            payload = value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False).encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'")
            if attachment:
                self.send_header("Content-Disposition", f'attachment; filename="{attachment}"')
            self.end_headers()
            self.wfile.write(payload)

        def search_args(self, params):
            one = lambda key, default="": params.get(key, [default])[0]
            return dict(query=one("q"), method=one("method", "hybrid"), source=one("source"), language=one("language"),
                kind=one("kind"), platform=one("platform"), expand=one("expand") == "true", group=one("group", "true") == "true",
                limit=max(1, min(int(one("limit", "50")), 200)), offset=max(0, int(one("offset", "0"))))

        def do_GET(self):
            if not self.valid_host():
                return self.reply({"error": "Use the localhost URL printed at startup"}, 403)
            parsed = urlparse(self.path)
            try:
                if parsed.path == "/api/session":
                    return self.reply({"csrf": app.csrf})
                if parsed.path == "/api/stats":
                    return self.reply(app.store.stats())
                if parsed.path == "/api/sources":
                    return self.reply(app.sources())
                if parsed.path == "/api/job":
                    with app.lock:
                        job = json.loads(json.dumps(app.job))
                    return self.reply(job)
                if parsed.path == "/api/search":
                    return self.reply(app.store.search(**self.search_args(parse_qs(parsed.query))))
                if parsed.path == "/api/export":
                    params = parse_qs(parsed.query)
                    args = self.search_args(params)
                    args.update(limit=1000000, offset=0)
                    result = app.store.search(**args)
                    if params.get("format", ["csv"])[0] == "json":
                        return self.reply(result, attachment="ruleatlas-results.json")
                    return self.reply(export_csv(result["results"]), content_type="text/csv; charset=utf-8", attachment="ruleatlas-results.csv")
                if parsed.path.startswith("/api/rule/"):
                    rule = app.store.get(parsed.path.rsplit("/", 1)[1])
                    return self.reply(rule if rule else {"error": "Rule not found"}, 200 if rule else 404)
                files = {"/": ("index.html", "text/html; charset=utf-8"), "/app.js": ("app.js", "text/javascript; charset=utf-8"), "/style.css": ("style.css", "text/css; charset=utf-8")}
                if parsed.path in files:
                    filename, mime = files[parsed.path]
                    return self.reply((static / filename).read_bytes(), content_type=mime)
                return self.reply({"error": "Not found"}, 404)
            except (ValueError, KeyError) as error:
                self.reply({"error": str(error)}, 400)
            except Exception:
                self.reply({"error": "Server error; inspect local configuration"}, 500)

        def do_POST(self):
            origin = self.headers.get("Origin")
            expected = "http://" + self.headers.get("Host", "")
            if not self.valid_host() or (origin and origin != expected) or self.headers.get("X-RuleAtlas-CSRF") != app.csrf:
                return self.reply({"error": "Invalid local request"}, 403)
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 1024 * 1024 or self.headers.get("Content-Type", "").split(";")[0] != "application/json":
                    raise ValueError("Expected a JSON body under 1 MiB")
                data = json.loads(self.rfile.read(length))
                if not isinstance(data, dict):
                    raise ValueError("Expected a JSON object")
                if self.path == "/api/sync":
                    app.start_sync(data.get("sources"), data.get("transport", "archive"))
                    return self.reply({"status": "started"}, 202)
                if self.path == "/api/evidence":
                    rule = app.store.get(str(data.get("uid", "")))
                    if not rule or not isinstance(data.get("requirements"), list):
                        raise ValueError("Select a rule and provide requirement phrases")
                    return self.reply(evidence(rule, data["requirements"]))
                if self.path == "/api/assessment":
                    with app.lock:
                        sources = load_catalog(app.catalog)
                        source = next((s for s in sources if s["id"] == data.get("source_id")), None)
                        if source is None:
                            raise ValueError("Unknown source")
                        for check in CHECKS:
                            entry = data.get("assessment", {}).get(check)
                            if not isinstance(entry, dict) or entry.get("status") not in {"evidence_recorded", "needs_review"}:
                                raise ValueError("All six checks must be supplied")
                            if not isinstance(entry.get("evidence"), list) or any(not isinstance(u, str) or not u.startswith("https://") for u in entry["evidence"]):
                                raise ValueError("Evidence links must use HTTPS")
                            if not isinstance(entry.get("note"), str):
                                raise ValueError("Each check requires a note")
                        source["assessment"] = data["assessment"]
                        source["reviewed_on"] = now()
                        app.write_catalog(sources)
                    return self.reply({"saved": True})
                if self.path == "/api/add-source":
                    with app.lock:
                        sources = load_catalog(app.catalog)
                        source = {"id": str(data["id"]), "name": str(data["name"]), "repo": str(data["repo"]),
                            "adapter": str(data["adapter"]), "patterns": data["patterns"], "category": "user-added",
                            "notes": "User-added source; credibility review pending", "reviewed_on": "not reviewed",
                            "assessment": {c: {"status": "needs_review", "note": "Review pending", "evidence": []} for c in CHECKS}}
                        if source["adapter"] not in {"sigma", "splunk", "elastic", "sentinel", "panther", "falco", "sublime", "yaral", "yara", "wazuh", "kql_markdown", "code", "snort", "capa"}:
                            raise ValueError("Unsupported adapter")
                        if not isinstance(source["patterns"], list) or not source["patterns"] or any(not isinstance(p, str) for p in source["patterns"]):
                            raise ValueError("Supply at least one file pattern")
                        app.write_catalog([*sources, source])
                    return self.reply({"saved": True})
                if self.path == "/api/discover":
                    return self.reply(discover(str(data.get("query", "detection rules"))[:256], pages=1))
                if self.path == "/api/attack-fetch":
                    return self.reply(fetch_attack(app.store, str(data.get("domain", "enterprise")), str(data.get("version", "18.1"))))
                return self.reply({"error": "Not found"}, 404)
            except (ValueError, KeyError, TypeError) as error:
                self.reply({"error": str(error)}, 400)
            except Exception as error:
                self.reply({"error": str(error)[:300]}, 502)
    return Handler


def serve(store, catalog, cache, port=8765):
    app = Application(store, catalog, cache)
    server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(app))
    print(f"RuleAtlas is ready: http://127.0.0.1:{server.server_address[1]}", flush=True)
    print("Local evaluation server. Press Ctrl+C to stop.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
