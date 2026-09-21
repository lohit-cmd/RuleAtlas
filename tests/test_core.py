import copy
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from ruleatlas.catalog import CHECKS, load_catalog
from ruleatlas.demo import seed
from ruleatlas.ingest import evidence, ingest_directory
from ruleatlas.parsers import parse_file
from ruleatlas.server import Application, export_csv, make_handler
from ruleatlas.store import Store


class Workspace(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = Store(self.root / 'index.db')
    def tearDown(self):
        self.tmp.cleanup()
    def parse(self, adapter, content, suffix='.yml'):
        file = self.root / ('rule' + suffix)
        file.write_text(content, encoding='utf-8')
        return parse_file({'id': 'test', 'repo': 'test/rules', 'adapter': adapter}, self.root, file, 'a' * 40)


class SearchTests(Workspace):
    def setUp(self):
        super().setUp()
        seed(self.store)
    def test_parent_does_not_implicitly_cover_subtechnique(self):
        exact = self.store.search('T1059', method='attack')
        expanded = self.store.search('T1059', method='attack', expand=True)
        self.assertEqual(exact['total'], 1)
        self.assertEqual(expanded['total'], 2)
        self.assertEqual(self.store.search('T1059.001', method='attack')['total'], 1)
    def test_platform_and_kind_filter(self):
        results = self.store.search('group', platform='google_workspace', kind='hunting')
        self.assertEqual(results['total'], 1)
        self.assertIn('audit hunt', results['results'][0]['title'])
    def test_user_fts_syntax_is_literal(self):
        result = self.store.search('" OR * NOT (')
        self.assertIsInstance(result['results'], list)
        self.assertEqual(self.store.stats()['rules'], 8)
    def test_tactic_from_imported_stix(self):
        bundle = {'objects': [
            {'type': 'x-mitre-tactic', 'name': 'Execution', 'x_mitre_shortname': 'execution', 'external_references': [{'source_name': 'mitre-attack', 'external_id': 'TA0002'}]},
            {'type': 'attack-pattern', 'name': 'PowerShell', 'external_references': [{'source_name': 'mitre-attack', 'external_id': 'T1059.001'}], 'kill_chain_phases': [{'phase_name': 'execution', 'kill_chain_name': 'mitre-attack'}]}]}
        self.store.import_attack(bundle, 'test-fixture-not-an-official-release')
        result = self.store.search('TA0002', method='attack')
        self.assertEqual(result['total'], 1)
        self.assertEqual(result['results'][0]['match']['derived_tactics'], ['TA0002'])
    def test_failed_attack_import_keeps_dataset(self):
        with self.assertRaises(ValueError):
            self.store.import_attack({'objects': []}, 'bad')
        self.assertEqual(self.store.stats()['attack_version'], 'not loaded')
    def test_grouping_retains_source_lineage(self):
        original = self.store.search('T1059.001', method='attack')['results'][0]
        duplicate = copy.deepcopy(original)
        self.store.replace_source('another', [duplicate], {'source_id': 'another'})
        grouped = self.store.search('T1059.001', method='attack')
        self.assertEqual(grouped['total'], 1)
        self.assertEqual(grouped['matched_records'], 2)
        self.assertEqual(len(grouped['results'][0]['duplicates']), 1)
        self.assertEqual(self.store.search('T1059.001', method='attack', group=False)['total'], 2)
    def test_partial_snapshot_cannot_erase_existing_rules(self):
        source = {'id': 'demo', 'repo': 'test/rules', 'adapter': 'sigma', 'patterns': ['*.yml']}
        (self.root / 'good.yml').write_text('title: Good\ndetection:\n  condition: selection\n  selection:\n    event: test\n')
        (self.root / 'broken.yml').write_text('title: [unterminated')
        with self.assertRaises(ValueError):
            ingest_directory(self.store, source, self.root)
        self.assertEqual(self.store.stats()['rules'], 8)
    def test_literal_evidence_is_not_coverage_claim(self):
        rule = self.store.search('OAuth')['results'][0]
        result = evidence(rule, ['Consent', 'rare ASN'])
        self.assertTrue(result['checks'][0]['evidence'])
        self.assertFalse(result['checks'][1]['evidence'])
        self.assertIn('Manual behavioral review', result['verdict'])
    def test_csv_formula_is_escaped(self):
        data = export_csv([{'title': '=HYPERLINK("https://example.com")'}]).decode('utf-8-sig')
        self.assertIn("'=HYPERLINK", data)


class AdapterTests(Workspace):
    def test_sigma_multidoc_and_correlation(self):
        rows = self.parse('sigma', 'title: Process\nid: one\ntags: [attack.t1059.001]\nlogsource: {product: windows}\ndetection: {selection: {Image: pwsh.exe}, condition: selection}\n---\ntitle: Sequence\nid: two\ncorrelation: {type: event_count, rules: [one]}')
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]['attack_ids'], ['T1059.001'])
        self.assertEqual(rows[1]['kind'], 'correlation')
        self.assertIn('/' + 'a' * 40 + '/', rows[0]['source_url'])
    def test_splunk_preserves_macro_dependency(self):
        rows = self.parse('splunk', 'name: Test\nsearch: "index=test | `filter(test)`"\ntags: {mitre_attack_id: [T1098]}')
        self.assertEqual(rows[0]['dependencies'][0]['name'], 'filter')
        self.assertEqual(rows[0]['attack_ids'], ['T1098'])
    def test_reference_url_is_not_a_mapping(self):
        rows = self.parse('sigma', 'title: Example\nreferences: [https://attack.mitre.org/techniques/T1059/]\ndetection: {selection: {event: example}, condition: selection}')
        self.assertEqual(rows[0]['attack_ids'], [])
    def test_elastic_nested_metadata(self):
        rows = self.parse('elastic', '[metadata]\nintegration=["aws"]\n[rule]\nname="Test"\nquery="event.action:StopLogging"\nlanguage="kuery"\n[[rule.threat.technique]]\nid="T1562"\n', '.toml')
        self.assertEqual(rows[0]['language'], 'kuery')
        self.assertEqual(rows[0]['telemetry']['integration'], ['aws'])
    def test_sentinel(self):
        rows = self.parse('sentinel', 'id: sentinel-test\nname: Audit\nquery: "AuditLogs | take 10"\nrequiredDataConnectors: [{connectorId: AzureActiveDirectory}]')
        self.assertEqual(rows[0]['language'], 'KQL')
        self.assertTrue(rows[0]['telemetry']['connectors'])
    def test_yaml_dates_and_null_references_are_serializable(self):
        rows = self.parse('sublime', 'name: Example\nsource: "type.inbound"\nreferences: null\ndate: 2026-01-01')
        self.store.replace_source('sublime', rows, {'source_id': 'sublime'})
        self.assertEqual(self.store.stats()['rules'], 1)
    def test_falco_filters_macros(self):
        rows = self.parse('falco', '- macro: shell\n  condition: proc.name=sh\n- rule: Shell\n  desc: Example\n  condition: shell\n  tags: [T1059]')
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['title'], 'Shell')
    def test_panther_never_executes_python(self):
        (self.root / 'rule.py').write_text('raise RuntimeError("must not execute")\ndef rule(event):\n return True\n')
        rows = self.parse('panther', 'AnalysisType: rule\nRuleID: example\nDisplayName: Example\nFilename: rule.py\nLogTypes: [AWS.CloudTrail]')
        self.assertIn('must not execute', rows[0]['logic'])
    def test_panther_rejects_escaping_paths(self):
        with self.assertRaises(ValueError):
            self.parse('panther', 'AnalysisType: rule\nRuleID: test\nFilename: ../outside.py')
    def test_yaml_object_execution_rejected(self):
        with self.assertRaises(Exception):
            self.parse('sigma', '!!python/object/apply:os.system ["echo unsafe"]')
    def test_wazuh_multiple_xml_groups(self):
        rows = self.parse('wazuh', '<group name="a"><rule id="1"><description>First</description><mitre><id>T1098</id></mitre></rule></group><group name="b"><rule id="2"><description>Second</description></rule></group>', '.xml')
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]['attack_ids'], ['T1098'])
    def test_yara_preserves_raw_source(self):
        text = 'rule example { strings: $a="demo" condition: $a }'
        rows = self.parse('yara', text, '.yar')
        self.assertEqual(rows[0]['logic'], text)
        self.assertEqual(rows[0]['validation'], 'untested')
    def test_markdown_without_query_not_counted(self):
        self.assertEqual(self.parse('kql_markdown', '# This is just a README', '.md'), [])
    def test_catalog_has_all_six_checks(self):
        sources = load_catalog()
        self.assertEqual(len(sources), 25)
        for source in sources:
            self.assertEqual(set(source['assessment']), set(CHECKS))


class HttpTests(Workspace):
    def setUp(self):
        super().setUp()
        seed(self.store)
        catalog = self.root / 'catalog.json'
        catalog.write_text(json.dumps({'sources': load_catalog()}))
        self.app = Application(self.store, catalog, self.root / 'cache')
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), make_handler(self.app))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = 'http://127.0.0.1:' + str(self.server.server_address[1])
    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        super().tearDown()
    def test_search_and_static_app(self):
        with urllib.request.urlopen(self.url + '/api/search?q=T1059.001&method=attack') as response:
            self.assertEqual(json.load(response)['total'], 1)
        with urllib.request.urlopen(self.url + '/') as response:
            self.assertIn(b'RuleAtlas', response.read())
            self.assertIn("frame-ancestors 'none'", response.headers['Content-Security-Policy'])
    def test_post_requires_local_csrf(self):
        request = urllib.request.Request(self.url + '/api/sync', data=b'{"sources":["sigma"]}', headers={'Content-Type':'application/json'})
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request)
        self.assertEqual(caught.exception.code, 403)
    def test_assessment_roundtrip(self):
        assessment = {key: {'status': 'needs_review', 'note': 'Reviewed in test', 'evidence': []} for key in CHECKS}
        request = urllib.request.Request(self.url + '/api/assessment', data=json.dumps({'source_id':'sigma','assessment':assessment}).encode(), headers={'Content-Type':'application/json','X-RuleAtlas-CSRF':self.app.csrf})
        with urllib.request.urlopen(request) as response:
            self.assertTrue(json.load(response)['saved'])
        self.assertEqual(load_catalog(self.app.catalog)[0]['assessment']['maintenance']['note'], 'Reviewed in test')
    def test_arbitrary_host_rejected(self):
        request = urllib.request.Request(self.url + '/api/session', headers={'Host': 'attacker.example'})
        with self.assertRaises(urllib.error.HTTPError) as caught:
            urllib.request.urlopen(request)
        self.assertEqual(caught.exception.code, 403)


if __name__ == '__main__':
    unittest.main()
