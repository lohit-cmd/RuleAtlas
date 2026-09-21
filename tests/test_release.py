import io
import json
import hashlib
import os
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import Mock, patch

from ruleatlas.catalog import load_catalog, migrate_source
from ruleatlas.cli import main
from ruleatlas.ingest import download_workspace, sync_source, extract_archive, ingest_directory
from ruleatlas.paths import portable_relative_path
from ruleatlas.parsers import parse_file
from ruleatlas.store import Store


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)
        self.store=Store(self.root/'index.db')
        self.source={'id':'test','repo':'test/rules','adapter':'sigma','patterns':['rules/*.yml']}
    def tearDown(self):self.temp.cleanup()
    def parse(self,content,adapter='sigma',**extra):
        file=self.root/('rule.xml' if adapter=='wazuh' else 'rule.yml');file.write_text(content)
        return parse_file({**self.source,'adapter':adapter,**extra},self.root,file,'a'*40)
    def test_malformed_yaml_is_explicit_reference_only_when_configured(self):
        content='title: Broken\ndetection:\n  selection: [unterminated'
        with self.assertRaises(Exception):self.parse(content)
        rows=self.parse(content,malformed_yaml='retain_reference')
        self.assertEqual(rows[0]['logic'],content)
        self.assertEqual(rows[0]['kind'],'reference')
        self.assertEqual(rows[0]['attack_ids'],[])
        self.assertTrue(rows[0]['parse_status'].startswith('parse failed'))
    def test_unsafe_yaml_constructor_is_never_accepted_as_detection(self):
        with self.assertRaises(Exception):self.parse('!!python/object/apply:os.system ["unsafe"]',malformed_yaml='retain_reference')
    def test_wazuh_backslash_angle_preserves_regex(self):
        import xml.etree.ElementTree as ET
        regex=r'Set-.+VirtualDirectory.+?Url.+\<\w+.*\>.*?\<\/\w+\>'
        rows=self.parse('<group><rule id="1"><regex>'+regex+'</regex><description>Test</description></rule></group>','wazuh')
        self.assertEqual(ET.fromstring(rows[0]['logic']).findtext('regex'),regex)
    def test_wazuh_regex_trailing_backslash_does_not_escape_closing_tag(self):
        import xml.etree.ElementTree as ET
        regex='C:\\Windows\\'
        rows=self.parse('<group><rule id="1"><regex>'+regex+'</regex><description>Path</description></rule></group>','wazuh')
        self.assertEqual(ET.fromstring(rows[0]['logic']).findtext('regex'),regex)
    def test_capa_attack_key_is_recognized(self):
        rows=self.parse('rule:\n  meta:\n    name: Test\n    att&ck: ["Execution::PowerShell [T1059.001]"]\n  features: []','capa')
        self.assertEqual(rows[0]['attack_ids'],['T1059.001'])
    def test_vendor_top_level_attack_mappings_are_searchable(self):
        cases = [('splunk', 'mitre_attack_id'), ('sentinel', 'subTechniques'),
                 ('sentinel', 'techniques'), ('sentinel', 'threatAnalysisTechniques'),
                 ('sigma', 'mitreattack')]
        for adapter, key in cases:
            with self.subTest(adapter=adapter, key=key):
                content = 'name: Test\ntitle: Test\nsearch: process\nquery: DeviceEvents\ndetection: {selection: {Image: test}, condition: selection}\n'
                row = self.parse(content + key + ': [T1059.001]\nreferences: [https://example.org/T1003]\n', adapter)[0]
                self.assertEqual(row['attack_ids'], ['T1059.001'])
    def test_markdown_does_not_index_prose_between_code_fences(self):
        text='# Hunt\n```python\nprint("example")\n```\nThis prose is not a query.\n```kql\nDeviceEvents | take 5\n```\n'
        rows=self.parse(text,'kql_markdown')
        self.assertEqual(len(rows),1);self.assertEqual(rows[0]['logic'],'DeviceEvents | take 5')
    def test_unlabelled_markdown_requires_query_structure(self):
        rows=self.parse('```\njust an example\n```\n```\nDeviceEvents\n| take 5\n```\n','kql_markdown')
        self.assertEqual(len(rows),1)
    def test_unlabelled_query_with_interleaved_comments_is_kept(self):
        rows=self.parse('```\nDeviceEvents\n// Explanation\n| where EventID == 1\n```\n','kql_markdown')
        self.assertEqual(len(rows),1)
        self.assertIn('// Explanation',rows[0]['logic'])
    def test_elastic_ml_configuration_is_searchable_without_query(self):
        rows=self.parse('[rule]\nname="Anomaly"\ntype="machine_learning"\nmachine_learning_job_id=["job"]\n','elastic')
        self.assertEqual(rows[0]['kind'],'configuration')
        self.assertIn('job',rows[0]['logic'])
    def test_portable_filenames_preserve_original_path_and_permalink(self):
        import zipfile
        payload=io.BytesIO()
        with zipfile.ZipFile(payload,'w') as z:
            z.writestr('repo/rules/question?.yml','title: Portable\ndetection: {selection: {Image: test}, condition: selection}')
            z.writestr('repo/rules/question%3F.yml','title: Literal percent\ndetection: {selection: {Image: other}, condition: selection}')
        payload.seek(0);mapping={};root=self.root/'portable'
        self.assertEqual(extract_archive(payload,root,self.source['patterns'],'sigma',mapping),2)
        self.assertTrue((root/'rules/question%3F.yml').exists())
        self.assertTrue((root/'rules/question%253F.yml').exists())
        self.assertEqual(ingest_directory(self.store,self.source,root,'a'*40,path_map=mapping)['count'],2)
        row=self.store.search('Portable')['results'][0]
        self.assertEqual(row['path'],'rules/question?.yml')
        self.assertTrue(row['source_url'].endswith('/rules/question%3F.yml'))
    def test_portable_windows_devices_and_long_components(self):
        for name in ['rules/NUL.yml','rules/file.','rules/file ', 'rules/'+'x'*300+'.yml']:
            safe=portable_relative_path(name)
            self.assertNotEqual(safe,name)
            self.assertLessEqual(max(map(len,safe.split('/'))),255)
        with self.assertRaises(ValueError):portable_relative_path('../outside')
    def test_migration_preserves_custom_paths_and_assessments(self):
        s={'repo':'GoogleCloudPlatform/security-analytics','patterns':['custom/*.yaral'],'assessment':{'note':'mine'}}
        self.assertEqual(migrate_source(s)['patterns'],['custom/*.yaral'])
        self.assertEqual(s['assessment'],{'note':'mine'})
        s={'repo':'wazuh/wazuh','adapter':'wazuh','patterns':['ruleset/rules/*.xml']}
        self.assertEqual(migrate_source(s)['ref'],'v4.14.7')
    def test_cleanup_failure_does_not_mask_success_or_original_failure(self):
        messages=[]
        with patch('ruleatlas.ingest.shutil.rmtree',side_effect=OSError('busy')):
            with download_workspace(self.root,'cleanup-',messages.append) as root:pass
        self.assertIn('Cleanup warning',messages[0])
        with patch('ruleatlas.ingest.shutil.rmtree',side_effect=OSError('busy')):
            with self.assertRaisesRegex(ValueError,'original'):
                with download_workspace(self.root,'cleanup-',messages.append):raise ValueError('original')
    def test_selective_download_integrity_cache_and_no_credentials(self):
        raw=b'title: Selected\ndetection: {selection: {Image: pwsh.exe}, condition: selection}\n'
        sha=hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
        tree={'truncated':False,'tree':[{'type':'blob','mode':'100644','path':'rules/test.yml','sha':sha,'size':len(raw)}]}
        def api(path,params=None):return tree if '/git/trees/' in path else {'sha':'a'*40}
        with patch('ruleatlas.ingest.github_json',side_effect=api),patch('ruleatlas.ingest.urllib.request.urlopen',return_value=io.BytesIO(raw)) as remote,patch.dict(os.environ,{'GITHUB_TOKEN':'secret-token'}):
            result=sync_source(self.store,self.source,self.root/'cache',transport='files')
            self.assertEqual(result['count'],1)
            self.assertIsNone(remote.call_args.args[0].get_header('Authorization'))
            remote.reset_mock()
            result=sync_source(self.store,self.source,self.root/'cache',transport='files')
            remote.assert_not_called()
            self.assertEqual(self.store.stats()['rules'],1)
    def test_selective_download_rejects_hash_mismatch_and_truncation(self):
        entry={'type':'blob','mode':'100644','path':'rules/test.yml','sha':'b'*40,'size':5}
        for tree,message in [({'truncated':True},'truncated'),({'tree':[entry]},'hash/size mismatch')]:
            def api(path,params=None):return tree if '/git/trees/' in path else {'sha':'a'*40}
            with patch('ruleatlas.ingest.github_json',side_effect=api),patch('ruleatlas.ingest.urllib.request.urlopen',return_value=io.BytesIO(b'wrong')):
                with self.assertRaisesRegex(RuntimeError,message):sync_source(self.store,self.source,self.root/'cache',transport='files')
        self.assertEqual(self.store.stats()['rules'],0)
    def test_selective_download_rejects_symlink_or_oversized_blob(self):
        for change in [{'mode':'120000'},{'size':3000000},{'path':'rules/../../escape.yml'}]:
            entry={'type':'blob','mode':'100644','path':'rules/test.yml','sha':'b'*40,'size':5,**change}
            def api(path,params=None):return {'tree':[entry]} if '/git/trees/' in path else {'sha':'a'*40}
            with patch('ruleatlas.ingest.github_json',side_effect=api),patch('ruleatlas.ingest.urllib.request.urlopen') as remote:
                with self.assertRaises(RuntimeError):sync_source(self.store,self.source,self.root/'cache',transport='files')
                remote.assert_not_called()
    def test_transaction_failure_retains_old_source_and_fts(self):
        row=self.parse('title: Example\ndetection: {selection: {Image: pwsh.exe}, condition: selection}')[0]
        self.store.replace_source('test',[row],{'source_id':'test'})
        with self.assertRaises(Exception):self.store.replace_source('test',[row,row],{'source_id':'test'})
        self.assertEqual(self.store.search('Example')['total'],1)
    def cli(self,*args):
        output=io.StringIO()
        with patch('sys.argv',['ruleatlas','--data-dir',str(self.root/'cli'),*args]),redirect_stdout(output),redirect_stderr(io.StringIO()):main()
        return output.getvalue()
    def test_cli_demo_search_sources_and_ingest(self):
        self.assertIn('8',self.cli('demo'))
        self.assertEqual(json.loads(self.cli('search','T1059.001','--method','attack'))['total'],1)
        self.assertEqual(len(json.loads(self.cli('sources'))),25)
        directory=self.root/'offline';(directory/'rules').mkdir(parents=True)
        (directory/'rules/test.yml').write_text('title: CLI test\ndetection: {selection: {EventID: 1}, condition: selection}')
        self.assertEqual(json.loads(self.cli('ingest','sigma',str(directory),'--commit','a'*40))['count'],1)
    def test_cli_network_routes_and_sync_error_exit(self):
        with patch('ruleatlas.cli.discover',return_value={'returned':0}):self.assertIn('returned',self.cli('discover','sigma'))
        with patch('ruleatlas.cli.fetch_attack',return_value={'records':1}):self.assertIn('records',self.cli('attack-fetch','--version','18.1'))
        with patch('ruleatlas.cli.sync_source',return_value={'count':1}) as action:
            self.cli('sync','sigma','--transport','files');self.assertEqual(action.call_args.kwargs['transport'],'files')
        with patch('ruleatlas.cli.sync_source',side_effect=RuntimeError('offline')),self.assertRaises(SystemExit) as ctx:self.cli('sync','sigma')
        self.assertEqual(ctx.exception.code,1)
        with self.assertRaises(SystemExit):self.cli('sync','unknown')
        with patch('ruleatlas.cli.serve') as serve:self.cli('serve','--port','8769');self.assertEqual(serve.call_args.args[-1],8769)


if __name__=='__main__':unittest.main()
