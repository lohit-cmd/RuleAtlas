import hashlib
import json
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

ATTACK_ID = re.compile(r"(?<![A-Za-z0-9])(?:TA\d{4}|T\d{4}(?:\.\d{3})?)(?![A-Za-z0-9.])", re.I)


def now():
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, path):
        self.path = str(path)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript("""
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS rules(
              uid TEXT PRIMARY KEY, source_id TEXT NOT NULL, title TEXT NOT NULL,
              description TEXT NOT NULL, logic TEXT NOT NULL, document TEXT NOT NULL,
              content_hash TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS rule_source ON rules(source_id);
            CREATE INDEX IF NOT EXISTS rule_hash ON rules(content_hash);
            CREATE VIRTUAL TABLE IF NOT EXISTS search_index USING fts5(uid UNINDEXED, title, description, logic);
            CREATE TABLE IF NOT EXISTS syncs(source_id TEXT PRIMARY KEY, document TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS attack(id TEXT PRIMARY KEY, document TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        try:
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def replace_source(self, source_id, rules, status):
        """Atomically replace one complete snapshot; failure leaves the old snapshot intact."""
        with self.connect() as db:
            db.execute("DELETE FROM search_index WHERE uid IN (SELECT uid FROM rules WHERE source_id=?)", (source_id,))
            db.execute("DELETE FROM rules WHERE source_id=?", (source_id,))
            for r in rules:
                r["source_id"] = source_id
                r["uid"] = hashlib.sha256(f'{source_id}:{r["path"]}:{r["rule_id"]}'.encode()).hexdigest()
                # Exact logic grouping only: never equate queries across platforms by guessed semantics.
                r["content_hash"] = hashlib.sha256((r["language"] + "\0" + r["logic"].strip()).encode()).hexdigest()
                values = (r["uid"], source_id, r["title"], r["description"], r["logic"], json.dumps(r), r["content_hash"])
                db.execute("INSERT INTO rules VALUES(?,?,?,?,?,?,?)", values)
                db.execute("INSERT INTO search_index VALUES(?,?,?,?)", (r["uid"], r["title"], r["description"], r["logic"]))
            db.execute("INSERT OR REPLACE INTO syncs VALUES(?,?)", (source_id, json.dumps(status)))

    def record_failure(self, source_id, error):
        with self.connect() as db:
            row = db.execute("SELECT document FROM syncs WHERE source_id=?", (source_id,)).fetchone()
            status = json.loads(row[0]) if row else {"source_id": source_id, "count": 0}
            status.update(last_attempt=now(), last_error=error, status="failed")
            db.execute("INSERT OR REPLACE INTO syncs VALUES(?,?)", (source_id, json.dumps(status)))

    def stats(self):
        with self.connect() as db:
            syncs = [json.loads(r[0]) for r in db.execute("SELECT document FROM syncs")]
            count = db.execute("SELECT count(*) FROM rules").fetchone()[0]
            unique = db.execute("SELECT count(DISTINCT content_hash) FROM rules").fetchone()[0]
            meta = dict(db.execute("SELECT key,value FROM meta"))
        return {"rules": count, "unique_logic": unique, "syncs": syncs, "attack_version": meta.get("attack_version", "not loaded")}

    def get(self, uid):
        with self.connect() as db:
            row = db.execute("SELECT document FROM rules WHERE uid=?", (uid,)).fetchone()
            if not row:
                return None
            result = json.loads(row[0])
            mapped = {r["id"]: json.loads(r["document"]) for r in db.execute("SELECT * FROM attack")}
            result["attack_validation"] = [{"id": a, "name": mapped.get(a, {}).get("name", ""),
                "status": "dataset not loaded" if not mapped else "unknown in selected dataset" if a not in mapped else
                "revoked" if mapped[a].get("revoked") else "deprecated" if mapped[a].get("deprecated") else "present"} for a in result["attack_ids"]]
            result["equivalent_logic"] = [json.loads(r[0]) for r in db.execute(
                "SELECT document FROM rules WHERE content_hash=? AND uid!=?", (result["content_hash"], uid))]
            return result

    def search(self, query="", *, method="hybrid", source="", language="", kind="", platform="", expand=False,
               group=True, limit=50, offset=0):
        if method not in {"hybrid", "keyword", "attack"}:
            raise ValueError("Unknown search method")
        query = query.strip()[:1000]
        requested_ids = {m.group().upper() for m in ATTACK_ID.finditer(query)}
        remaining = ATTACK_ID.sub(" ", query) if method != "keyword" else query
        tokens = re.findall(r"[\w-]+", remaining.lower())
        ignored = {"find", "detect", "detection", "rules", "rule", "the", "a", "an", "for", "of", "in", "and", "or", "to", "with", "show", "me"}
        tokens = list(dict.fromkeys(t for t in tokens if t not in ignored))[:30]
        if method == "attack" and not requested_ids:
            return {"results": [], "total": 0, "message": "Enter a tactic, technique or sub-technique ID.", "query": query}
        with self.connect() as db:
            mapped = {r["id"]: json.loads(r["document"]) for r in db.execute("SELECT * FROM attack")}
            ranks = {}
            if tokens and method != "attack":
                # Quote each token: user input is never FTS syntax or SQL.
                fts = " OR ".join('"' + t.replace('"', '""') + '"' for t in tokens)
                ranks = {r[0]: -r[1] for r in db.execute(
                    "SELECT uid,bm25(search_index,0,5,2,1) FROM search_index WHERE search_index MATCH ?", (fts,))}
            clauses, params = [], []
            if source:
                clauses.append("source_id=?")
                params.append(source)
            sql = "SELECT document FROM rules" + (" WHERE " + " AND ".join(clauses) if clauses else "")
            candidates = [json.loads(r[0]) for r in db.execute(sql, params)]
        results = []
        for r in candidates:
            if language and r["language"] != language or kind and r["kind"] != kind:
                continue
            if platform and platform.casefold() not in json.dumps(r["telemetry"]).casefold():
                continue
            authored = set(r["attack_ids"])
            derived = {t for a in authored for t in mapped.get(a, {}).get("tactics", [])}
            exact = requested_ids & (authored | derived)
            parent_matches = {a for a in authored for target in requested_ids if expand and a.startswith(target + ".")}
            if method != "keyword" and requested_ids and not (exact or parent_matches):
                continue
            score = ranks.get(r["uid"], 0)
            if tokens and method != "attack" and not score:
                continue
            r["rank_score"] = round(score + (10 if exact else 5 if parent_matches else 0), 5)
            r["match"] = {"exact_ids": sorted(exact), "expanded_subtechniques": sorted(parent_matches),
                          "derived_tactics": sorted(requested_ids & derived),
                          "matched_terms": [t for t in tokens if t in (r["title"] + " " + r["description"] + " " + r["logic"]).lower()],
                          "assessment": "Candidate match; behavioral coverage not validated"}
            r["attack_validation"] = [{"id": a, "status": ("not loaded" if not mapped else "unknown in selected dataset" if a not in mapped else
                "revoked" if mapped[a].get("revoked") else "deprecated" if mapped[a].get("deprecated") else "present"),
                "name": mapped.get(a, {}).get("name", "")} for a in r["attack_ids"]]
            r["duplicates"] = []
            results.append(r)
        results.sort(key=lambda r: (-r["rank_score"], r["title"].casefold(), r["uid"]))
        matched_count = len(results)
        if group:
            groups = {}
            for r in results:
                if r["content_hash"] in groups:
                    groups[r["content_hash"]]["duplicates"].append({"uid": r["uid"], "title": r["title"], "source_id": r["source_id"]})
                else:
                    groups[r["content_hash"]] = r
            results = list(groups.values())
        total = len(results)
        return {"results": results[offset:offset + limit], "total": total, "matched_records": matched_count,
                "query": query, "message": "No matching rule found in the indexed sources." if not total else "Ranking indicates retrieval relevance, not detection fidelity."}

    def import_attack(self, bundle, version):
        objects = bundle.get("objects", [])
        tactics = {}
        for o in objects:
            if o.get("type") == "x-mitre-tactic":
                ids = [x["external_id"] for x in o.get("external_references", []) if x.get("source_name") == "mitre-attack" and "external_id" in x]
                if ids:
                    tactics[o.get("x_mitre_shortname")] = ids[0]
        records = []
        for o in objects:
            if o.get("type") not in {"attack-pattern", "x-mitre-tactic"}:
                continue
            for x in o.get("external_references", []):
                if x.get("source_name") == "mitre-attack" and "external_id" in x:
                    records.append({"id": x["external_id"], "name": o.get("name", ""),
                        "tactics": sorted({tactics[p["phase_name"]] for p in o.get("kill_chain_phases", []) if p.get("phase_name") in tactics}),
                        "revoked": o.get("revoked", False), "deprecated": o.get("x_mitre_deprecated", False)})
        if not records:
            raise ValueError("No ATT&CK records found; existing dataset preserved")
        with self.connect() as db:
            db.execute("DELETE FROM attack")
            db.executemany("INSERT INTO attack VALUES(?,?)", [(r["id"], json.dumps(r)) for r in records])
            db.execute("INSERT OR REPLACE INTO meta VALUES('attack_version',?)", (version,))
        return len(records)
