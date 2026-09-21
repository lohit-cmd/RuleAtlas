// Run against an isolated fully populated audit index, not your personal catalog.
const {chromium}=require(process.env.RULEATLAS_PLAYWRIGHT || 'playwright');
const assert=require('node:assert/strict');
const fs=require('node:fs');
(async()=>{
 const options={headless:true,args:['--no-sandbox']};
 if(process.env.RULEATLAS_CHROMIUM){options.executablePath=process.env.RULEATLAS_CHROMIUM;options.args=(await import(process.env.RULEATLAS_CHROMIUM_HELPER)).default.args;}
 const browser=await chromium.launch(options);
 const page=await browser.newPage({viewport:{width:1440,height:1080},acceptDownloads:true});
 const errors=[];page.on('pageerror',e=>errors.push(e.message));
 const url=process.env.RULEATLAS_URL || 'http://127.0.0.1:8765';
 for(let i=0;i<20;i++){try{await page.goto(url);break;}catch(e){if(i===19)throw e;await new Promise(r=>setTimeout(r,250));}}
 await page.locator('.result').first().waitFor({timeout:60000});
 const sources=await page.evaluate(async()=>await (await fetch('/api/sources')).json());
 assert.equal(sources.length,25);
 const sourceChecks=[];
 for(const source of sources){
  assert.ok(source.sync.count>0,source.id+' has no indexed records');
  const response=page.waitForResponse(r=>r.url().includes('/api/search?')&&new URL(r.url()).searchParams.get('source')===source.id);
  await page.selectOption('#source-filter',source.id);await response;
  await page.waitForFunction(id=>document.querySelector('#rule-detail .detail-source')?.textContent===id,source.name);
  assert.ok(await page.locator('.result').count()>0,source.id);
  const href=await page.getByRole('link',{name:'Open exact source revision'}).getAttribute('href');
  assert.ok(href.includes('github.com/'+source.repo+'/blob/'),href);
  assert.ok((await page.locator('#rule-detail pre').first().textContent()).trim().length>0);
  sourceChecks.push({source:source.id,records:source.sync.count});
 }
 await page.selectOption('#source-filter','splunk');
 await page.selectOption('#method','attack');
 await page.fill('#query','T1059');
 const mappedResponse=page.waitForResponse(r=>r.url().includes('/api/search?')&&new URL(r.url()).searchParams.get('q')==='T1059');
 await page.click('#search-form button[type=submit]');
 const mapped=await (await mappedResponse).json();
 assert.ok(mapped.total>0,'Splunk technique mapping missing');
 assert.ok(mapped.results.every(r=>r.attack_ids.includes('T1059')));
 await page.fill('#query','');await page.selectOption('#method','hybrid');
 await page.selectOption('#source-filter','sigma');
 await page.waitForFunction(()=>document.querySelector('#rule-detail .detail-source')?.textContent==='SigmaHQ');
 await page.click('#next');await page.waitForFunction(()=>document.querySelector('#page-number').textContent.startsWith('2 /'));
 await page.click('#previous');await page.waitForFunction(()=>document.querySelector('#page-number').textContent.startsWith('1 /'));
 const downloadWait=page.waitForEvent('download');await page.click('#export-json');const download=await downloadWait;
 fs.mkdirSync('test-results',{recursive:true});await download.saveAs('test-results/live-export.json');
 const exported=JSON.parse(fs.readFileSync('test-results/live-export.json','utf8'));
 assert.ok(exported.results.length>100);assert.ok(exported.results.every(r=>r.source_id==='sigma'));
 // Upstream strings must remain text and unsafe reference schemes must not become links.
 await page.route('**/api/rule/*',async route=>{
  const r=await route.fetch();const body=await r.json();body.title='<img src=x onerror="window.__injected=true">';body.references=['javascript:alert(1)'];
  await route.fulfill({json:body});
 });
 await page.locator('.result').first().click();
 await page.waitForFunction(()=>document.querySelector('#rule-detail h2')?.textContent.startsWith('<img'));
 assert.equal(await page.locator('#rule-detail img').count(),0);
 assert.equal(await page.locator('#rule-detail a[href^="javascript:"]').count(),0);
 assert.equal(await page.evaluate(()=>!!window.__injected),false);
 await page.unroute('**/api/rule/*');
 // A late detail response must not overwrite a completed no-results search.
 let release;let ready;const readyPromise=new Promise(r=>ready=r);
 await page.route('**/api/rule/*',async route=>{const response=await route.fetch();await new Promise(r=>{release=r;ready();});await route.fulfill({response});});
 await page.locator('.result').first().click();await readyPromise;
 await page.fill('#query','zzzznonsensetermnotpresent');await page.click('#search-form button[type=submit]');
 await page.waitForFunction(()=>document.querySelector('#results-count').textContent==='0 results');release();
 await page.waitForTimeout(300);assert.equal(await page.locator('#rule-detail h2').textContent(),'No candidate selected');
 await page.unroute('**/api/rule/*');
 await page.click('[data-tab=sources]');
 const joe=page.locator('.source-card').filter({has:page.locator('a',{hasText:'joesecurity/sigma-rules'})});
 assert.match(await joe.textContent(),/7 unparsed files/);
 await joe.getByRole('button').click();assert.match(await page.locator('#source-dialog-body').textContent(),/Upstream parse warnings/);await page.click('#close-dialog');
 await page.locator('#attack-form').evaluate(el=>el.closest('details').open=true);
 await page.locator('#attack-form input[name=version]').fill('19.1');
 const attackResponse=page.waitForResponse(r=>r.url().endsWith('/api/attack-fetch'),{timeout:120000});
 await page.locator('#attack-form button').click();
 const attackResult=await (await attackResponse).json();assert.equal(attackResult.version,'enterprise-19.1');assert.ok(attackResult.records>0);
 await page.waitForFunction(()=>document.querySelector('#attack-version').textContent==='enterprise-19.1',{},{timeout:120000});
 await page.click('[data-tab=discover]');
 await page.route('**/api/discover',route=>route.fulfill({json:{returned:1,reported_total:1,incomplete:false,candidates:[{repo:'test/rules',url:'https://github.com/test/rules',description:'Example',review_status:'unreviewed',archived:false,pushed_at:'2026-01-01'}]}}));
 await page.locator('#discovery-form button').click();await page.locator('#discovery-results .source-card').waitFor();
 assert.match(await page.locator('#discovery-results').textContent(),/unreviewed/);
 await page.unroute('**/api/discover');
 await page.click('[data-tab=sources]');await page.setViewportSize({width:430,height:900});
 const dimensions=await page.evaluate(()=>({width:document.documentElement.clientWidth,scroll:document.documentElement.scrollWidth}));
 assert.ok(dimensions.scroll<=dimensions.width+1,JSON.stringify(dimensions));assert.deepEqual(errors,[]);
 const report={sourceChecks,checks:['25 live source filters and original logic','25 exact-revision links','Splunk authored technique retrieval','pagination','full filtered JSON export','upstream HTML rendered as text','unsafe links not clickable','stale detail response ignored','parse warnings visible','live ATT&CK form import','discovery rendering with stubbed response','mobile source catalog','no browser runtime errors'],dimensions};
 fs.writeFileSync('test-results/browser-live.json',JSON.stringify(report,null,2));console.log(JSON.stringify(report,null,2));await browser.close();
})().catch(e=>{console.error(e);process.exit(1)});
