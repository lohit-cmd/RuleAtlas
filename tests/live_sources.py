"""Opt-in live integration audit; downloads public sources, never executes rules.

Run: python tests/live_sources.py --data-dir audit-data --workers 3
Results are evidence for configured paths at recorded revisions, not engine validation.
"""
import argparse
import concurrent.futures
import json
import re
import sys
import threading
import time
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ruleatlas.catalog import load_catalog
from ruleatlas.ingest import sync_source
from ruleatlas.server import export_csv
from ruleatlas.store import Store, now


def verify_source(store, source, imported):
    sid = source['id']
    with store.connect() as db:
        rows = [json.loads(r[0]) for r in db.execute('SELECT document FROM rules WHERE source_id=?', (sid,))]
        fts_count = db.execute('SELECT count(*) FROM search_index WHERE uid IN (SELECT uid FROM rules WHERE source_id=?)', (sid,)).fetchone()[0]
    assert len(rows) == imported['count'] > 0, 'Record count mismatch'
    assert fts_count == len(rows), 'Missing full-text index records'
    for row in rows:
        assert row['title'].strip() and row['logic'].strip(), f'Empty title or logic: {row["path"]}'
        assert row['source_id'] == sid and row['repository'] == source['repo']
        assert row['commit'] == imported['commit']
        assert row['source_url'] == f'https://github.com/{source["repo"]}/blob/{row["commit"]}/{quote(row["path"], safe="/")}'
        assert row['validation'] == 'untested', 'Import must not claim engine validation'
    all_results = store.search(source=sid, group=False, limit=1)
    assert all_results['total'] == len(rows), 'Source filter count mismatch'
    sample = rows[len(rows) // 2]
    assert store.get(sample['uid'])['logic'] == sample['logic'], 'Detail lost logic'
    words = re.findall(r'\w{3,}', sample['title'])
    words = [w for w in words if w.lower() not in {'find','detect','detection','rules','rule','the','for','and','with','show'}]
    keyword = words[0] if words else ''
    if keyword:
        found = store.search(keyword, method='keyword', source=sid, group=False, limit=len(rows))
        assert any(r['uid'] == sample['uid'] for r in found['results']), 'Keyword retrieval failed'
    tagged = next((r for r in rows if r['attack_ids']), None)
    if tagged:
        found = store.search(tagged['attack_ids'][0], method='attack', source=sid, group=False, limit=len(rows))
        assert any(r['uid'] == tagged['uid'] for r in found['results']), 'ATT&CK retrieval failed'
    assert export_csv([sample]).startswith(b'\xef\xbb\xbf'), 'CSV export failed'
    json.dumps(sample)
    return {'records_checked': len(rows), 'fts_records': fts_count,
            'checks': ['counts', 'nonempty content', 'all record provenance', 'source filter', 'detail', 'keyword retrieval' if keyword else 'keyword not applicable', 'ATT&CK retrieval' if tagged else 'no ATT&CK tags', 'CSV/JSON export'],
            'sample_uid': sample['uid'], 'sample_url': sample['source_url']}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--data-dir', required=True)
    parser.add_argument('--workers', type=int, default=1)
    parser.add_argument('--sources', nargs='*')
    parser.add_argument('--transport', choices=['archive', 'files', 'git'], default='archive')
    args = parser.parse_args()
    directory = Path(args.data_dir).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    sources = load_catalog()
    if args.sources:
        assert set(args.sources) <= {s['id'] for s in sources}, 'Unknown source'
        sources = [s for s in sources if s['id'] in args.sources]
    store = Store(directory / 'ruleatlas.db')
    result_file = directory / f'live-{args.transport}-results.json'
    previous = json.loads(result_file.read_text()) if result_file.exists() else {}
    results = previous.get('sources', {})
    lock = threading.Lock()
    def run(source):
        start = time.monotonic()
        sid = source['id']
        def progress(message):
            if not message.startswith('Parsing') or ': 1/' in message:
                print(f'[{sid}] {message}', flush=True)
        try:
            imported = sync_source(store, source, directory / 'cache', progress, args.transport)
            checked = verify_source(store, source, imported)
            result = {'status': 'passed', 'repo': source['repo'], 'adapter': source['adapter'], 'patterns': source['patterns'], 'import': imported, 'verification': checked}
        except Exception as error:
            result = {'status': 'failed', 'repo': source['repo'], 'error': str(error)}
        result.update(tested_at=now(), seconds=round(time.monotonic()-start, 2), transport=args.transport)
        with lock:
            results[sid] = result
            result_file.write_text(json.dumps({'tested_at': now(), 'platform': sys.platform, 'python': sys.version.split()[0], 'sources': results}, indent=2))
        print(f'[{sid}] {result["status"].upper()}: {result.get("error", result.get("import", {}).get("count"))}', flush=True)
        return result['status']
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1,min(args.workers,4))) as pool:
        statuses = list(pool.map(run, sources))
    print(json.dumps({'passed': statuses.count('passed'), 'failed': statuses.count('failed'), 'report': str(result_file)}), flush=True)
    return bool(statuses.count('failed'))


if __name__ == '__main__':
    sys.exit(main())
