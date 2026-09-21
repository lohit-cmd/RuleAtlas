import io
import json
import os
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import Mock, patch

from ruleatlas.catalog import load_catalog
from ruleatlas.demo import seed
from ruleatlas.ingest import discover, fetch_attack, github_json
from ruleatlas.server import Application, make_handler
from ruleatlas.store import Store


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.store = Store(self.root/'index.db')
        seed(self.store)
        catalog = self.root/'catalog.json'
        catalog.write_text(json.dumps({'sources':load_catalog()}))
        self.app = Application(self.store,catalog,self.root/'cache')
        self.http = ThreadingHTTPServer(('127.0.0.1',0),make_handler(self.app))
        self.thread = threading.Thread(target=self.http.serve_forever,daemon=True)
        self.thread.start()
        self.url = 'http://127.0.0.1:'+str(self.http.server_address[1])
    def tearDown(self):
        self.http.shutdown(); self.http.server_close(); self.thread.join(); self.tmp.cleanup()
    def request(self,path,data=None,headers=None):
        h={'Content-Type':'application/json','X-RuleAtlas-CSRF':self.app.csrf}
        h.update(headers or {})
        request=urllib.request.Request(self.url+path,data=None if data is None else json.dumps(data).encode(),headers=h)
        try: response=urllib.request.urlopen(request,timeout=10)
        except urllib.error.HTTPError as error: response=error
        with response:
            raw=response.read()
            return response.status,json.loads(raw) if response.headers['Content-Type'].startswith('application/json') else raw
    def test_bad_json_shape_and_parameters(self):
        for data in [[],None,'hello',7]:
            if data is None: continue
            self.assertEqual(self.request('/api/sync',data)[0],400)
        for path in ['/api/search?limit=abc','/api/search?method=bogus']:
            self.assertEqual(self.request(path)[0],400)
    def test_cross_origin_and_invalid_csrf_are_rejected(self):
        self.assertEqual(self.request('/api/sync',{'sources':['sigma']},{'Origin':'https://attacker.example'})[0],403)
        self.assertEqual(self.request('/api/sync',{'sources':['sigma']},{'X-RuleAtlas-CSRF':'wrong'})[0],403)
    def test_add_source_and_duplicate_preserves_catalog(self):
        data={'id':'sample','name':'Sample','repo':'test/rules','adapter':'sigma','patterns':['rules/*.yml']}
        self.assertEqual(self.request('/api/add-source',data)[0],200)
        self.assertEqual(self.request('/api/add-source',data)[0],400)
        self.assertEqual(len(load_catalog(self.app.catalog)),26)
        self.assertEqual(load_catalog(self.app.catalog)[-1]['assessment']['ownership']['status'],'needs_review')
    def test_invalid_sources_never_touch_catalog(self):
        original=self.app.catalog.read_bytes()
        for change in [{'id':'../escape'},{'repo':'file:///tmp/test'},{'patterns':[]},{'adapter':'execute'},{'patterns':'*.yml'}]:
            data={'id':'sample','name':'Sample','repo':'test/rules','adapter':'sigma','patterns':['rules/*.yml'],**change}
            self.assertEqual(self.request('/api/add-source',data)[0],400)
            self.assertEqual(self.app.catalog.read_bytes(),original)
    def test_assessment_invalid_link_keeps_previous_values(self):
        source=load_catalog(self.app.catalog)[0]
        assessment=source['assessment']
        assessment['ownership']['evidence']=['javascript:alert(1)']
        original=self.app.catalog.read_bytes()
        self.assertEqual(self.request('/api/assessment',{'source_id':'sigma','assessment':assessment})[0],400)
        self.assertEqual(self.app.catalog.read_bytes(),original)
    def test_exports_respect_filters_and_include_provenance(self):
        code,data=self.request('/api/export?format=json&q=T1059.001&method=attack&source=demo')
        self.assertEqual(code,200);self.assertEqual(data['total'],1)
        self.assertEqual(data['results'][0]['source_id'],'demo')
        code,data=self.request('/api/export?format=csv&q=T1059.001&method=attack')
        self.assertEqual(code,200);self.assertIn(b'source_url,commit,license',data)
    def test_missing_rule_and_unknown_paths(self):
        for path in ['/api/rule/absent','/../../README.md','/data/ruleatlas.db','/api/unknown']:
            self.assertEqual(self.request(path)[0],404)
    def test_invalid_sync_selection_and_running_job(self):
        for data in [{'sources':[]},{'sources':['unknown']},{'sources':['sigma'],'transport':'bad'}]:
            self.assertEqual(self.request('/api/sync',data)[0],400)
        self.app.job['status']='running'
        self.assertEqual(self.request('/api/sync',{'sources':['sigma']})[0],400)
    def test_discover_and_attack_routes(self):
        with patch('ruleatlas.server.discover',return_value={'candidates':[]}) as action:
            self.assertEqual(self.request('/api/discover',{'query':'sigma'})[0],200)
            action.assert_called_once_with('sigma',pages=1)
        with patch('ruleatlas.server.fetch_attack',return_value={'records':2}) as action:
            self.assertEqual(self.request('/api/attack-fetch',{'domain':'enterprise','version':'18.1'})[0],200)
            self.assertEqual(action.call_args.args[1:],('enterprise','18.1'))
    def test_evidence_requires_existing_rule(self):
        self.assertEqual(self.request('/api/evidence',{'uid':'missing','requirements':['test']})[0],400)
        rule=self.store.search('OAuth')['results'][0]
        code,data=self.request('/api/evidence',{'uid':rule['uid'],'requirements':['rare ASN']})
        self.assertEqual(code,200);self.assertFalse(data['checks'][0]['evidence'])


class RemoteApiTests(unittest.TestCase):
    def test_token_is_sent_to_github_api_only(self):
        opener=Mock();opener.open.return_value=io.BytesIO(b'{"sha":"test"}')
        with patch.dict(os.environ,{'GITHUB_TOKEN':'test-secret-token'}),patch('ruleatlas.ingest.urllib.request.build_opener',return_value=opener):
            github_json('/repos/test/rules/commits/HEAD')
        req=opener.open.call_args.args[0]
        self.assertTrue(req.full_url.startswith('https://api.github.com/'))
        self.assertEqual(req.get_header('Authorization'),'Bearer test-secret-token')
        with self.assertRaises(ValueError): github_json('//attacker.example')
    def test_rate_limit_and_auth_errors_are_reported(self):
        for code in [401,403,429,404]:
            opener=Mock();opener.open.side_effect=urllib.error.HTTPError('https://api.github.com/test',code,'blocked',{'Retry-After':'60'},None)
            with patch('ruleatlas.ingest.urllib.request.build_opener',return_value=opener),self.assertRaisesRegex(RuntimeError,str(code)):
                github_json('/test')
    def test_discovery_bounds_and_deduplicates_results(self):
        item={'full_name':'test/rules','html_url':'https://github.com/test/rules','archived':False,'fork':False,'stargazers_count':1}
        with patch('ruleatlas.ingest.github_json',return_value={'items':[item]*100,'total_count':2000}) as call:
            result=discover('detection',pages=100)
        self.assertEqual(call.call_count,10)
        self.assertEqual(result['returned'],1);self.assertTrue(result['incomplete'])
    def test_attack_invalid_domain_or_version_never_downloads(self):
        with patch('ruleatlas.ingest.urllib.request.urlopen') as call:
            for domain,version in [('other','18.1'),('enterprise','../../file')]:
                with self.assertRaises(ValueError): fetch_attack(None,domain,version)
            call.assert_not_called()


if __name__=='__main__':unittest.main()
