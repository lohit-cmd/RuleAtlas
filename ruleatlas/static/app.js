'use strict';
const $ = id => document.getElementById(id);
const state = {csrf: '', sources: [], offset: 0, total: 0, selected: '', searchController: null, selectedSources: new Set()};
const checks = ['ownership', 'community_adoption', 'engineering_quality', 'maintenance', 'traceability', 'rule_validation'];
function node(tag, text, className) { const el = document.createElement(tag); if (text !== undefined) el.textContent = text; if (className) el.className = className; return el; }
function link(text, href) { const el = node('a', text); try { const url = new URL(href); if (url.protocol === 'https:') { el.href = url.href; el.target = '_blank'; el.rel = 'noopener noreferrer'; } } catch (_) {} return el; }
function badge(text, type = '') { return node('span', text, 'badge ' + type); }
function notify(message, error = false) { $('notice').textContent = message; $('notice').hidden = false; $('notice').className = error ? 'error' : ''; }
async function api(path, data, signal) { const response = await fetch(path, data === undefined ? {signal} : {method: 'POST', headers: {'Content-Type': 'application/json', 'X-RuleAtlas-CSRF': state.csrf}, body: JSON.stringify(data), signal}); const result = await response.json(); if (!response.ok) throw new Error(result.error || 'Request failed'); return result; }
function tab(name) { document.querySelectorAll('.tab').forEach(el => el.hidden = el.id !== name + '-tab'); document.querySelectorAll('.nav').forEach(el => el.classList.toggle('active', el.dataset.tab === name)); $('page-label').textContent = {search: 'Rule search', sources: 'Source catalog', discover: 'Discover sources'}[name]; }
document.querySelectorAll('[data-tab]').forEach(el => el.addEventListener('click', () => tab(el.dataset.tab)));
$('open-sources').addEventListener('click', () => tab('sources'));
function queryParams() { return new URLSearchParams({q: $('query').value, method: $('method').value, source: $('source-filter').value, kind: $('kind-filter').value, platform: $('platform-filter').value, expand: $('expand').checked, group: $('group').checked, limit: 25, offset: state.offset}); }
async function refresh() {
  const [stats, sources] = await Promise.all([api('/api/stats'), api('/api/sources')]); state.sources = sources;
  $('record-count').textContent = stats.rules.toLocaleString(); $('logic-count').textContent = stats.unique_logic.toLocaleString();
  $('source-count').textContent = stats.syncs.filter(s => s.source_id !== 'demo' && s.count > 0).length;
  $('attack-version').textContent = stats.attack_version; $('demo-notice').hidden = !stats.syncs.some(s => s.source_id === 'demo');
  const old = $('source-filter').value; $('source-filter').replaceChildren(node('option', 'All indexed sources')); $('source-filter').firstChild.value = '';
  for (const s of sources) { const o = node('option', s.name); o.value = s.id; $('source-filter').append(o); }
  if (stats.syncs.some(s => s.source_id === 'demo')) { const o = node('option', 'Synthetic demo examples'); o.value = 'demo'; $('source-filter').append(o); }
  $('source-filter').value = old; renderSources();
}
async function search(reset = true) {
  if (reset) state.offset = 0;
  if (state.searchController) state.searchController.abort(); state.searchController = new AbortController();
  $('results-count').textContent = 'Searching…';
  try {
    const data = await api('/api/search?' + queryParams(), undefined, state.searchController.signal); state.total = data.total;
    $('results-count').textContent = `${data.total.toLocaleString()} results`; $('results-note').textContent = data.matched_records ? `${data.matched_records.toLocaleString()} matching records` : '';
    $('results').replaceChildren();
    for (const r of data.results) {
      const button = node('button', undefined, 'result'); button.dataset.uid = r.uid;
      const top = node('div', undefined, 'result-top'); top.append(node('span', sourceName(r.source_id)), badge(r.language));
      const tags = node('div', undefined, 'badges'); r.attack_ids.slice(0, 5).forEach(a => tags.append(badge(a, 'teal'))); tags.append(badge(r.kind));
      if (r.duplicates.length) tags.append(badge(`+${r.duplicates.length} identical`, 'amber'));
      button.append(top, node('h3', r.title), node('p', r.description || 'Inspect source logic and metadata.'), tags);
      button.addEventListener('click', () => openRule(r.uid)); $('results').append(button);
    }
    if (!data.results.length) { state.selected = ''; $('results').append(node('p', data.message, 'info-box')); $('rule-detail').replaceChildren(node('h2', 'No candidate selected'), node('p', 'Try different terms, broaden filters, or synchronize more sources. Source failures are visible in the catalog.')); }
    $('previous').disabled = !state.offset; $('next').disabled = state.offset + 25 >= state.total;
    $('page-number').textContent = data.total ? `${Math.floor(state.offset / 25) + 1} / ${Math.ceil(data.total / 25)}` : '0 / 0';
    if (data.results.length) await openRule(data.results.some(r => r.uid === state.selected) ? state.selected : data.results[0].uid);
  } catch (e) { if (e.name !== 'AbortError') notify(e.message, true); }
}
function sourceName(id) { return id === 'demo' ? 'SYNTHETIC DEMO' : state.sources.find(s => s.id === id)?.name || id; }
async function openRule(uid) {
  state.selected = uid;
  $('rule-detail').replaceChildren(node('p', 'Loading source details…', 'muted'));
  try {
    const r = await api('/api/rule/' + uid); if (state.selected !== uid) return;
    document.querySelectorAll('.result').forEach(el => el.classList.toggle('selected', el.dataset.uid === uid));
    const root = $('rule-detail'); root.replaceChildren(node('div', sourceName(r.source_id), 'detail-source'), node('h2', r.title));
    const tags = node('div', undefined, 'badges'); tags.append(badge(r.kind), badge(r.language, 'teal'), badge(r.validation, 'amber')); r.attack_ids.forEach(a => tags.append(badge(a, 'teal'))); root.append(tags);
    root.append(node('p', r.description), node('p', 'Candidate relevance is not proof of behavioral coverage. Inspect conditions, exclusions, thresholds, and telemetry.', 'info-box'));
    if (r.attack_validation?.length) { root.append(node('h3', 'ATT&CK identifiers'), node('p', 'Origin: ' + (r.attack_id_origin || 'source metadata'), 'compact-note')); r.attack_validation.forEach(a => root.append(node('p', `${a.id} · ${a.name || 'Name unavailable'} · ${a.status}`))); }
    root.append(node('h3', 'Original detection logic'), node('pre', r.logic));
    const copy = node('button', 'Copy logic', 'secondary'); copy.onclick = async () => { try { await navigator.clipboard.writeText(r.logic); copy.textContent = 'Copied'; } catch (_) { notify('Select and copy the logic from the panel.'); } }; root.append(copy);
    const dl = node('dl');
    for (const [title, value] of [['Author', r.author], ['Maturity', r.maturity], ['Validation', r.validation], ['Format', r.parse_status], ['Revision', r.commit], ['Path', r.path], ['License', r.license]]) dl.append(node('dt', title), node('dd', value)); root.append(dl);
    if (r.source_url) root.append(link('Open exact source revision ↗', r.source_url));
    root.append(node('h3', 'Telemetry requirements'), node('pre', JSON.stringify(r.telemetry, null, 2)));
    if (r.dependencies.length) { root.append(node('h3', 'Dependencies'), node('pre', JSON.stringify(r.dependencies, null, 2))); }
    if (r.references.length) { root.append(node('h3', 'Publisher references')); const ul = node('ul'); r.references.forEach(ref => { const li = node('li'); li.append(link(ref, ref)); ul.append(li); }); root.append(ul); }
    if (r.equivalent_logic.length) { root.append(node('h3', 'Identical logic in other records')); r.equivalent_logic.forEach(other => { const b = node('button', sourceName(other.source_id) + ': ' + other.title, 'text-button'); b.onclick = () => openRule(other.uid); root.append(b); }); }
    root.append(node('h3', 'Inspect scenario requirements'), node('p', 'Enter one phrase or event name per line. This finds literal evidence in the logic; it does not automatically validate semantics.'));
    const input = node('textarea'); input.placeholder = 'ADD_GROUP_MEMBER\nsensitive_groups\nexternal_domain'; input.setAttribute('aria-label', 'Scenario requirement phrases');
    const check = node('button', 'Find supporting lines', 'primary'), output = node('div');
    check.onclick = async () => { check.disabled = true; try { const data = await api('/api/evidence', {uid, requirements: input.value.split('\n')}); output.replaceChildren(); for (const item of data.checks) { const row = node('div', undefined, 'review-line'); row.append(node('strong', item.requirement), node('span', item.status)); item.evidence.forEach(e => row.append(node('pre', `Line ${e.line}: ${e.text}`))); output.append(row); } output.append(node('p', data.verdict)); } catch (e) { notify(e.message, true); } finally { check.disabled = false; } };
    root.append(input, check, output);
  } catch (e) { notify(e.message, true); }
}
function renderSources() {
  const root = $('source-list'); root.replaceChildren();
  for (const s of state.sources) {
    const card = node('article', undefined, 'source-card'), top = node('label', undefined, 'source-select');
    const checkbox = node('input'); checkbox.type = 'checkbox'; checkbox.checked = state.selectedSources.has(s.id); checkbox.setAttribute('aria-label', 'Select ' + s.name); checkbox.onchange = () => checkbox.checked ? state.selectedSources.add(s.id) : state.selectedSources.delete(s.id);
    top.append(badge(s.category), checkbox); card.append(top, node('h3', s.name), link(s.repo, 'https://github.com/' + s.repo), node('p', s.notes));
    const tags = node('div', undefined, 'badges'); tags.append(badge(s.sync.status, s.sync.status === 'failed' || s.sync.warning_count ? 'amber' : 'teal'), badge(`${s.sync.count || 0} records`), badge(s.adapter)); card.append(tags);
    card.append(node('div', `${checks.filter(c => s.assessment[c].status === 'evidence_recorded').length}/6 checks have recorded evidence`, 'small'));
    if (s.sync.warning_count) card.append(node('p', `${s.sync.warning_count} unparsed files retained as reference content; inspect source evidence.`, 'error'));
    if (s.sync.last_error) card.append(node('p', s.sync.last_error, 'error'));
    const button = node('button', 'Inspect source evidence ↗', 'secondary'); button.onclick = () => sourceDialog(s); card.append(button); root.append(card);
  }
}
function sourceDialog(s) {
  $('source-dialog-title').textContent = s.name; const root = $('source-dialog-body'); root.replaceChildren(link('https://github.com/' + s.repo, 'https://github.com/' + s.repo));
  root.firstChild.className = 'source-link'; root.append(node('p', s.notes, 'muted'));
  root.append(node('p', `Last successful import: ${s.sync.last_success || 'not imported'} · Revision: ${s.sync.commit || 'not recorded'}`, 'compact-note'));
  root.append(node('p', `Candidate files: ${s.sync.candidate_files ?? 'unknown'} · Files without extracted records: ${s.sync.skipped_file_count ?? 'unknown'}. Full import reports are available in the local data directory.`, 'compact-note'));
  if (s.sync.parse_warnings?.length) { root.append(node('h3', 'Upstream parse warnings')); for (const w of s.sync.parse_warnings) root.append(node('p', w.path + ': ' + w.error, 'error')); }
  const form = node('form'), controls = {};
  for (const key of checks) {
    const entry = s.assessment[key], section = node('section', undefined, 'assessment'); section.append(node('h3', key.replaceAll('_', ' ')));
    const select = node('select'); for (const [value, title] of [['needs_review', 'Needs review'], ['evidence_recorded', 'Evidence recorded']]) { const opt = node('option', title); opt.value = value; select.append(opt); } select.value = entry.status; select.setAttribute('aria-label', key + ' status');
    const note = node('textarea'); note.value = entry.note; note.setAttribute('aria-label', key + ' note'); const urls = node('textarea'); urls.value = entry.evidence.join('\n'); urls.placeholder = 'Evidence URLs, one HTTPS URL per line'; urls.setAttribute('aria-label', key + ' evidence links');
    const row = node('div', undefined, 'assessment-controls'); row.append(select, note); section.append(row, urls); entry.evidence.forEach(url => { const a = link('View recorded evidence ↗', url); a.className = 'source-link'; section.append(a); }); form.append(section); controls[key] = {select, note, urls};
  }
  const submit = node('button', 'Save local assessment', 'primary'); form.append(submit); form.onsubmit = async event => { event.preventDefault(); submit.disabled = true; try { const assessment = {}; for (const [key, c] of Object.entries(controls)) assessment[key] = {status: c.select.value, note: c.note.value, evidence: c.urls.value.split('\n').map(x => x.trim()).filter(Boolean)}; await api('/api/assessment', {source_id: s.id, assessment}); $('source-dialog').close(); await refresh(); notify('Source assessment saved.'); } catch(e) { notify(e.message, true); } finally { submit.disabled = false; } }; root.append(form); $('source-dialog').showModal();
}
$('close-dialog').onclick = () => $('source-dialog').close();
$('search-form').onsubmit = e => { e.preventDefault(); search(); };
for (const id of ['method', 'source-filter', 'kind-filter', 'expand', 'group']) $(id).onchange = () => search();
$('previous').onclick = () => { state.offset = Math.max(0, state.offset - 25); search(false); };
$('next').onclick = () => { state.offset += 25; search(false); };
for (const fmt of ['csv', 'json']) $('export-' + fmt).onclick = () => { const params = queryParams(); params.set('format', fmt); window.location.href = '/api/export?' + params; };
$('attack-form').onsubmit = async e => { e.preventDefault(); const button = e.target.querySelector('button'); button.disabled = true; button.textContent = 'Downloading…'; try { const result = await api('/api/attack-fetch', Object.fromEntries(new FormData(e.target))); await refresh(); await search(); notify(`Loaded ${result.records} ATT&CK records from ${result.version}.`); } catch(e) { notify(e.message, true); } finally { button.disabled = false; button.textContent = 'Download from MITRE'; } };
let polling = false;
async function pollJob() {
  if (polling) return; polling = true;
  try { while (true) { const job = await api('/api/job'); if (job.status === 'idle') break; $('job-status').hidden = false; $('job-status').textContent = [job.status.toUpperCase(), ...job.messages.slice(-3), ...job.results.map(r => r.source_id + ': ' + (r.error || `${r.count} records indexed${r.warning_count ? `; ${r.warning_count} parse warnings` : ""}`))].join('\n'); if (job.status !== 'running') { $('sync-selected').disabled = false; await refresh(); await search(); break; } await new Promise(resolve => setTimeout(resolve, 1500)); } } catch(e) { notify(e.message, true); $('sync-selected').disabled = false; } finally { polling = false; }
}
$('sync-selected').onclick = async () => { if (!state.selectedSources.size) return notify('Select one or more sources to synchronize.'); try { await api('/api/sync', {sources: [...state.selectedSources], transport: $('sync-transport').value}); $('sync-selected').disabled = true; pollJob(); } catch(e) { notify(e.message, true); } };
$('add-source-form').onsubmit = async e => { e.preventDefault(); const data = Object.fromEntries(new FormData(e.target)); data.patterns = data.patterns.split('\n').map(x => x.trim()).filter(Boolean); try { await api('/api/add-source', data); e.target.reset(); await refresh(); notify('Source added with all six checks marked needs review.'); } catch(e) { notify(e.message, true); } };
$('discovery-form').onsubmit = async e => { e.preventDefault(); const button = e.target.querySelector('button'); button.disabled = true; $('discovery-results').replaceChildren(node('p', 'Searching GitHub…')); try { const data = await api('/api/discover', {query: $('discovery-query').value}); $('discovery-results').replaceChildren(); notify(`${data.returned} candidates returned; ${data.reported_total} reported by GitHub. ${data.incomplete ? 'Results are incomplete.' : ''} Candidates require credibility review.`); for (const item of data.candidates) { const card = node('article', undefined, 'source-card'); card.append(link(item.repo, item.url), node('p', item.description || 'No description'), badge(item.archived ? 'archived' : 'not archived'), node('p', item.review_status), node('p', `Last repository push: ${item.pushed_at || 'unknown'}`)); $('discovery-results').append(card); } } catch(e) { $('discovery-results').replaceChildren(node('p', e.message, 'info-box error')); } finally { button.disabled = false; } };
(async () => { try { state.csrf = (await api('/api/session')).csrf; await refresh(); await search(); pollJob(); } catch(e) { notify(e.message, true); } })();
