import io
import json
import os
import stat
import subprocess
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

from ruleatlas.catalog import load_catalog
from ruleatlas.demo import seed
from ruleatlas.ingest import extract_archive, git_run, ingest_directory, native_path, safe_diagnostic, sync_source, windows_extended_path
from ruleatlas.server import Application
from ruleatlas.store import Store


RULE = b'title: Archive example\ntags: [attack.t1059.001]\ndetection: {selection: {Image: pwsh.exe}, condition: selection}\n'
SHA = 'a' * 40


def zip_bytes(entries):
    out = io.BytesIO()
    with zipfile.ZipFile(out, 'w') as z:
        for name, content in entries:
            z.writestr(name, content)
    return out.getvalue()


class SyncTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = Store(self.root / 'index.db')
        self.source = {'id': 'test', 'repo': 'test/rules', 'adapter': 'sigma', 'patterns': ['rules/*.yml']}

    def tearDown(self):
        self.temp.cleanup()

    def mock_archive(self, raw):
        opener = Mock()
        opener.open.return_value = io.BytesIO(raw)
        return opener

    def test_archive_sync_needs_no_git_and_keeps_exact_revision(self):
        opener = self.mock_archive(zip_bytes([('repo/rules/example.yml', RULE)]))
        with patch('ruleatlas.ingest.github_json', return_value={'sha': SHA}), patch('ruleatlas.ingest.urllib.request.build_opener', return_value=opener), patch('ruleatlas.ingest.git_run', side_effect=AssertionError('Git must not run')):
            status = sync_source(self.store, self.source, self.root / 'cache')
        self.assertEqual(status['count'], 1)
        self.assertEqual(status['commit'], SHA)
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, f'https://codeload.github.com/test/rules/zip/{SHA}')
        self.assertIsNone(request.get_header('Authorization'))
        row = self.store.search('T1059.001', method='attack')['results'][0]
        self.assertIn(SHA, row['source_url'])
        self.assertEqual(list((self.root / 'cache').iterdir()), [])

    def test_failed_download_preserves_existing_snapshot(self):
        seed(self.store)
        source = {**self.source, 'id': 'demo'}
        with patch('ruleatlas.ingest.github_json', side_effect=RuntimeError('API unavailable')):
            with self.assertRaisesRegex(RuntimeError, 'API unavailable'):
                sync_source(self.store, source, self.root / 'cache')
        self.assertEqual(self.store.stats()['rules'], 8)
        self.assertEqual(self.store.stats()['syncs'][0]['status'], 'failed')

    def test_bad_archive_preserves_existing_snapshot(self):
        seed(self.store)
        opener = self.mock_archive(b'not a zip')
        with patch('ruleatlas.ingest.github_json', return_value={'sha': SHA}), patch('ruleatlas.ingest.urllib.request.build_opener', return_value=opener):
            with self.assertRaises(RuntimeError):
                sync_source(self.store, {**self.source, 'id': 'demo'}, self.root / 'cache')
        self.assertEqual(self.store.stats()['rules'], 8)

    def test_archive_size_limit(self):
        opener = self.mock_archive(b'12345')
        with patch('ruleatlas.ingest.github_json', return_value={'sha': SHA}), patch('ruleatlas.ingest.urllib.request.build_opener', return_value=opener), patch('ruleatlas.ingest.MAX_ARCHIVE_BYTES', 4):
            with self.assertRaisesRegex(RuntimeError, 'exceeds'):
                sync_source(self.store, self.source, self.root / 'cache')

    def test_archive_rejects_path_traversal_and_windows_paths(self):
        for name in ['root/../../escape', '/absolute', 'root/C:/escape', 'root/..\\escape', 'root/.git/config', 'root/NUL.yml', 'root/aux', 'root/file.']:
            with self.subTest(name=name), self.assertRaises(ValueError):
                extract_archive(io.BytesIO(zip_bytes([(name, b'bad')])), self.root / 'out')
        self.assertFalse((self.root / 'escape').exists())

    def test_archive_rejects_links(self):
        entry = zipfile.ZipInfo('root/link')
        entry.create_system = 3
        entry.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.assertRaisesRegex(ValueError, 'Links'):
            extract_archive(io.BytesIO(zip_bytes([(entry, b'../../outside')])), self.root / 'out')

    def test_archive_extraction_limit(self):
        with patch('ruleatlas.ingest.MAX_EXTRACTED_BYTES', 4), self.assertRaisesRegex(ValueError, 'extraction limit'):
            extract_archive(io.BytesIO(zip_bytes([('root/file', b'12345')])), self.root / 'out')

    def test_invalid_revision_never_downloads(self):
        with patch('ruleatlas.ingest.github_json', return_value={'sha': 'main'}), patch('ruleatlas.ingest.urllib.request.build_opener') as opener:
            with self.assertRaisesRegex(RuntimeError, 'full commit SHA'):
                sync_source(self.store, self.source, self.root / 'cache')
            opener.assert_not_called()

    def test_git_diagnostic_preserves_cause_and_redacts_credentials(self):
        result = subprocess.CompletedProcess([], 128, '', 'fatal: SSL certificate problem https://user:password@github.com/x ghp_example123 secret-example')
        with patch.dict(os.environ, {'GITHUB_TOKEN': 'secret-example'}), patch('ruleatlas.ingest.subprocess.run', return_value=result):
            with self.assertRaisesRegex(RuntimeError, 'SSL certificate problem') as ctx:
                git_run(['clone', 'https://github.com/test/rules.git'])
        self.assertNotIn('password', str(ctx.exception))
        self.assertNotIn('secret-example', str(ctx.exception))
        self.assertNotIn('ghp_example123', str(ctx.exception))

    def test_git_preserves_system_config_and_uses_native_hooks_directory(self):
        def run(args, **kwargs):
            self.assertNotIn('/dev/null', ' '.join(args))
            self.assertTrue(Path(next(a.split('=', 1)[1] for a in args if a.startswith('core.hooksPath='))).is_dir())
            self.assertNotIn('GIT_CONFIG_NOSYSTEM', kwargs['env'])
            return subprocess.CompletedProcess(args, 0, SHA, '')
        with patch.dict(os.environ, {}, clear=True), patch('ruleatlas.ingest.subprocess.run', side_effect=run):
            self.assertEqual(git_run(['rev-parse', 'HEAD']), SHA)

    def test_missing_git_and_timeout_are_actionable(self):
        for error, message in [(FileNotFoundError(), 'Git was not found'), (subprocess.TimeoutExpired('git', 300), 'timed out')]:
            with self.subTest(error=error), patch('ruleatlas.ingest.subprocess.run', side_effect=error), self.assertRaisesRegex(RuntimeError, message):
                git_run(['--version'])

    def test_job_status_reports_failure_partial_and_success(self):
        catalog = self.root / 'catalog.json'
        catalog.write_text(json.dumps({'sources': load_catalog()}))
        for outcomes, expected in [([RuntimeError('unavailable')], 'failed'), ([{'status': 'indexed'}, RuntimeError('unavailable')], 'completed with errors'), ([{'status': 'indexed'}], 'completed')]:
            app = Application(self.store, catalog, self.root / 'cache')
            done = threading.Event()
            # Execute the worker synchronously to check final state without timing sleeps.
            class ImmediateThread:
                def __init__(self, target, **kw): self.target = target
                def start(self): self.target(); done.set()
            with patch('ruleatlas.server.sync_source', side_effect=outcomes) as sync, patch('ruleatlas.server.threading.Thread', ImmediateThread):
                app.start_sync(['sigma', 'splunk'][:len(outcomes)], transport='archive')
            self.assertEqual(app.job['status'], expected)
            self.assertEqual(sync.call_args.kwargs['transport'], 'archive')

    def test_unknown_transport_is_rejected_before_download(self):
        with self.assertRaises(ValueError):
            sync_source(self.store, self.source, self.root / 'cache', transport='unknown')

    def test_sigma_omits_deep_regression_logs_and_empty_directories(self):
        regression = 'repo/regression_data/rules-emerging-threats/2024/TA/SlashAndGrab-Exploitation-In-Wild/file_event_win_apt_unknown_exploitation_indicators/' + 'a' * 36 + '.evtx'
        raw = zip_bytes([('repo/rules/windows/example.yml', RULE), (regression, b'event data'), ('repo/regression_data/empty/', b''), ('repo/README.md', b'docs')])
        real_open = Path.open
        def checked_open(path, *args, **kwargs):
            self.assertNotIn('regression_data', str(path), 'Regression data must never be opened for extraction')
            return real_open(path, *args, **kwargs)
        with patch.object(Path, 'open', checked_open):
            count = extract_archive(io.BytesIO(raw), self.root / 'out', self.source['patterns'], 'sigma')
        self.assertEqual(count, 1)
        self.assertFalse((self.root / 'out/regression_data').exists())
        status = ingest_directory(self.store, self.source, self.root / 'out', SHA)
        self.assertEqual(status['count'], 1)

    def test_panther_companion_python_is_extracted_without_execution(self):
        raw = zip_bytes([('repo/rules/example.yml', b'AnalysisType: rule\nRuleID: example\nFilename: example.py\n'), ('repo/rules/example.py', b'raise RuntimeError("never execute")\ndef rule(event):\n return True\n'), ('repo/test_data/log.json', b'{}')])
        source = {**self.source, 'adapter': 'panther'}
        self.assertEqual(extract_archive(io.BytesIO(raw), self.root / 'out', source['patterns'], 'panther'), 2)
        self.assertEqual(ingest_directory(self.store, source, self.root / 'out', SHA)['count'], 1)
        self.assertFalse((self.root / 'out/test_data').exists())

    def test_filtered_extraction_still_rejects_traversal(self):
        raw = zip_bytes([('repo/rules/good.yml', RULE), ('repo/tests/../../../../outside.txt', b'bad')])
        with self.assertRaisesRegex(ValueError, 'Unsafe path'):
            extract_archive(io.BytesIO(raw), self.root / 'out', self.source['patterns'], 'sigma')

    def test_unrelated_link_is_omitted_but_selected_link_rejected(self):
        entry = zipfile.ZipInfo('repo/test_data/link')
        entry.create_system = 3
        entry.external_attr = (stat.S_IFLNK | 0o777) << 16
        raw = zip_bytes([('repo/rules/good.yml', RULE), (entry, b'../../outside')])
        self.assertEqual(extract_archive(io.BytesIO(raw), self.root / 'out', self.source['patterns']), 1)
        entry.filename = 'repo/rules/link.yml'
        with self.assertRaisesRegex(ValueError, 'Links'):
            extract_archive(io.BytesIO(zip_bytes([(entry, b'../../outside')])), self.root / 'other', self.source['patterns'])

    def test_windows_drive_unc_and_already_extended_paths(self):
        self.assertEqual(windows_extended_path('C:/Users/Test/../Example/cache'), '\\\\?\\C:\\Users\\Example\\cache')
        self.assertEqual(windows_extended_path('\\\\server\\share\\cache'), '\\\\?\\UNC\\server\\share\\cache')
        self.assertEqual(windows_extended_path('\\\\?\\C:\\cache'), '\\\\?\\C:\\cache')
        with self.assertRaises(ValueError):
            windows_extended_path('relative/cache')

    def test_deep_selected_rule_extracts_and_ingests(self):
        # Exceeds MAX_PATH even when the temporary base is short.
        relative = 'rules/' + '/'.join(['nested-directory-' + str(i) for i in range(18)]) + '/rule.yml'
        self.assertGreater(len(relative), 260)
        root = native_path(self.root / 'deep')
        extract_archive(io.BytesIO(zip_bytes([('repo/' + relative, RULE)])), root, self.source['patterns'])
        self.assertEqual(ingest_directory(self.store, self.source, root, SHA)['count'], 1)
        row = self.store.search('T1059.001', method='attack')['results'][0]
        self.assertIn(relative, row['source_url'])
        # Explicit native cleanup covers Windows with long paths disabled globally.
        import shutil
        shutil.rmtree(root)
        self.assertFalse(root.exists())

    def test_directory_read_failure_cannot_replace_snapshot(self):
        seed(self.store)
        def failing_walk(root, **kwargs):
            kwargs['onerror'](PermissionError('Cannot read source directory'))
            return iter(())
        with patch('ruleatlas.ingest.os.walk', side_effect=failing_walk), self.assertRaises(PermissionError):
            ingest_directory(self.store, {**self.source, 'id': 'demo'}, self.root, SHA)
        self.assertEqual(self.store.stats()['rules'], 8)


if __name__ == '__main__':
    unittest.main()
