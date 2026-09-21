import argparse
import json
import shutil
import sys
from pathlib import Path

from .catalog import load_catalog, source_by_id
from .demo import seed
from .ingest import discover, fetch_attack, ingest_directory, sync_source
from .server import serve
from .store import Store


def main():
    parser = argparse.ArgumentParser(description="RuleAtlas — public detection discovery")
    parser.add_argument("--data-dir", default="data", help="Local index and cache directory")
    parser.add_argument("--catalog", help="Custom source catalog JSON")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("demo", help="Load original synthetic examples")
    web = commands.add_parser("serve", help="Start the local web interface")
    web.add_argument("--port", type=int, default=8765)
    commands.add_parser("sources", help="List configured sources")
    sync = commands.add_parser("sync", help="Synchronize selected public repositories")
    sync.add_argument("sources", nargs="+", help="Source IDs, or all")
    sync.add_argument("--transport", choices=["archive", "files", "git"], default="archive", help="HTTPS archive, selective files, or Git checkout")
    imp = commands.add_parser("ingest", help="Index a downloaded source directory")
    imp.add_argument("source")
    imp.add_argument("path")
    imp.add_argument("--commit", default="", help="Actual Git commit, if known")
    find = commands.add_parser("search")
    find.add_argument("query")
    find.add_argument("--method", choices=["keyword", "attack", "hybrid"], default="hybrid")
    find.add_argument("--source", default="")
    find.add_argument("--expand", action="store_true")
    find.add_argument("--limit", type=int, default=50)
    disc = commands.add_parser("discover", help="Search GitHub for unreviewed candidate repositories")
    disc.add_argument("query")
    disc.add_argument("--pages", type=int, default=2)
    attack = commands.add_parser("attack-import", help="Load a versioned official ATT&CK STIX bundle")
    attack.add_argument("file")
    attack.add_argument("--version", required=True, help="Label of the actual imported release, e.g. enterprise-18.1")
    af = commands.add_parser("attack-fetch", help="Download an explicit release from MITRE's official repository")
    af.add_argument("--version", default="18.1")
    af.add_argument("--domain", choices=["enterprise", "mobile", "ics"], default="enterprise")
    args = parser.parse_args()
    directory = Path(args.data_dir)
    directory.mkdir(parents=True, exist_ok=True)
    catalog = Path(args.catalog) if args.catalog else directory / "catalog.json"
    if not catalog.exists() and not args.catalog:
        shutil.copyfile(Path(__file__).with_name("sources.json"), catalog)
    store = Store(directory / "ruleatlas.db")
    try:
        sources = load_catalog(catalog)
        if args.command == "demo":
            print(f"Loaded {seed(store)} original synthetic examples. These are not upstream detections.")
        elif args.command == "serve":
            serve(store, catalog, directory / "cache", args.port)
        elif args.command == "sources":
            print(json.dumps(sources, indent=2))
        elif args.command == "sync":
            ids = [s["id"] for s in sources] if args.sources == ["all"] else args.sources
            failures = 0
            for sid in ids:
                source = source_by_id(sid, catalog)
                if source is None:
                    raise ValueError(f"Unknown source: {sid}")
                try:
                    print(json.dumps(sync_source(store, source, directory / "cache", lambda message: print(message, file=sys.stderr), transport=args.transport), indent=2))
                except Exception as error:
                    failures += 1
                    print(f"{sid}: {error}", file=sys.stderr)
            if failures:
                return sys.exit(1)
        elif args.command == "ingest":
            source = source_by_id(args.source, catalog)
            if source is None:
                raise ValueError("Unknown source ID")
            print(json.dumps(ingest_directory(store, source, args.path, args.commit, lambda message: print(message, file=sys.stderr)), indent=2))
        elif args.command == "search":
            print(json.dumps(store.search(args.query, method=args.method, source=args.source, expand=args.expand, limit=max(1, min(args.limit, 10000))), indent=2))
        elif args.command == "discover":
            print(json.dumps(discover(args.query, args.pages), indent=2))
        elif args.command == "attack-fetch":
            print(json.dumps(fetch_attack(store, args.domain, args.version), indent=2))
        elif args.command == "attack-import":
            print(f'Imported {store.import_attack(json.loads(Path(args.file).read_text(encoding="utf-8-sig")), args.version)} ATT&CK records.')
    except (ValueError, RuntimeError, OSError) as error:
        parser.exit(1, f"Error: {error}\n")
