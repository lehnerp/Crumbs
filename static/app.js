'use strict';

/* ------------------------------------------------------------ utilities --- */
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmtN = n => (n == null ? '–' : Number(n).toLocaleString());
const fmtB = b => {
  if (b == null) return '–';
  const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0;
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
  return (i ? b.toFixed(1) : b) + ' ' + u[i];
};
const ago = iso => {
  if (!iso) return 'never';
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 60) return 'just now';
  if (s < 3600) return Math.round(s / 60) + ' min ago';
  if (s < 86400) return Math.round(s / 3600) + ' h ago';
  return new Date(iso).toLocaleDateString();
};
const plural = (n, one, many = one + 's') => `${fmtN(n)} ${n === 1 ? one : many}`;
const qs = o => new URLSearchParams(Object.entries(o).filter(([, v]) => v !== '' && v != null && v !== false)).toString();

async function api(url, opts) {
  const r = await fetch(url, opts);
  let data = null;
  try { data = await r.json(); } catch (e) { /* not json */ }
  if (!r.ok) throw new Error((data && data.error) || `${r.status} ${r.statusText}`);
  return data;
}
const post = (url, body, method = 'POST') => api(url, { method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });

let toastTimer;
function toast(msg, err = false) {
  const t = $('#toast');
  t.textContent = msg; t.className = 'toast' + (err ? ' err' : ''); t.hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => (t.hidden = true), err ? 6000 : 2600);
}

const ENTITY = {
  ipv4: ['IPv4', '#56ccf2'], ipv6: ['IPv6', '#2d9cdb'], domain: ['Domain', '#bb6bd9'], url: ['URL', '#9b8afb'],
  email: ['Email', '#f78fb3'], md5: ['MD5', '#6fcf97'], sha1: ['SHA-1', '#5fbf8a'], sha256: ['SHA-256', '#4fae7d'],
  mac: ['MAC', '#c8d46b'], cve: ['CVE', '#eb5757'], win_path: ['Windows path', '#d9a870'], user: ['User', '#f7b7a3'],
};
const eLabel = t => (ENTITY[t] || [t])[0];
const eColor = t => (ENTITY[t] || [0, '#8c9aae'])[1];
const etag = t => `<span class="etag" style="color:${eColor(t)}">${esc(eLabel(t))}</span>`;
const sevTag = s => s ? `<span class="sev ${esc(s)}">${esc(s)}</span>` : '<span class="faint">–</span>';

/** Wrap [start,end) spans of text in <mark>. */
function markSpans(text, spans) {
  if (!spans || !spans.length) return esc(text);
  let out = '', pos = 0;
  for (const [a, b] of spans) {
    if (a < pos) continue;
    out += esc(text.slice(pos, a)) + '<mark>' + esc(text.slice(a, b)) + '</mark>';
    pos = b;
  }
  return out + esc(text.slice(pos));
}
/** Client-side span finder used by the viewer. */
function queryTerms(q) {
  const out = [], rx = /(-)?(?:(\w+):)?(?:"((?:[^"]|"")*)"|(\S+))/g;
  const fields = /^(file|path|ext|after|from|since|before|to|until|rule|sev|severity|cat|category|has)$/i;
  let m;
  while ((m = rx.exec(q))) {
    const [, neg, field, quoted, bare] = m;
    if (neg || (field && fields.test(field))) continue;
    let v = quoted != null ? quoted.replace(/""/g, '"') : bare;
    if (field) v = field + ':' + v;
    if (quoted == null && v === 'OR') continue;
    if (v) out.push(v);
  }
  return out;
}
function findSpans(text, q, mode) {
  if (!q) return [];
  if (mode === 'query') {
    const terms = queryTerms(q).sort((a, b) => b.length - a.length);
    if (!terms.length) return [];
    const spans = [], rx = new RegExp(terms.map(t => t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|'), 'gi');
    let m; while ((m = rx.exec(text)) && spans.length < 100) spans.push([m.index, m.index + m[0].length]);
    return spans;
  }
  const spans = [];
  if (mode === 'regex') {
    let src = q, flags = 'g';
    if (src.startsWith('(?i)')) { src = src.slice(4); flags += 'i'; }
    let rx; try { rx = new RegExp(src, flags); } catch (e) { return []; }
    let m; while ((m = rx.exec(text)) && spans.length < 100) {
      if (!m[0].length) { rx.lastIndex++; continue; }
      spans.push([m.index, m.index + m[0].length]);
    }
    return spans;
  }
  const hay = mode === 'case' ? text : text.toLowerCase();
  const needle = mode === 'case' ? q : q.toLowerCase();
  let i = hay.indexOf(needle);
  while (i >= 0 && spans.length < 100) { spans.push([i, i + needle.length]); i = hay.indexOf(needle, i + needle.length); }
  return spans;
}

/* ---------------------------------------------------------------- state --- */
const S = { q: '', mode: 'substring', file_id: null, offset: 0, results: [], files: [], total: null, capped: false };
const loaded = {};
let current = null;
let lastStatus = null;

function filters() {
  return { ext: $('#fExt').value.trim(), path: $('#fPath').value.trim(), from: $('#fFrom').value, to: $('#fTo').value };
}

/* --------------------------------------------------------------- routing --- */
const VIEWS = {
  overview: renderOverview, search: renderSearch, files: renderFiles, triage: renderTriage, findings: renderFindings,
  entities: renderEntities, host: renderHost, episodes: renderEpisodes, fs: renderFs, tamper: renderTamper, timeline: renderTimeline, graph: renderGraph, board: renderBoard, tools: renderTools, settings: renderSettings, index: renderIndex,
};
function show(view, opts = {}) {
  if (!VIEWS[view]) view = 'overview';
  current = view;
  $$('.rail [data-view]').forEach(b => b.dataset.view === view ? b.setAttribute('aria-current', 'page') : b.removeAttribute('aria-current'));
  $$('main .view').forEach(s => (s.hidden = s.id !== 'v-' + view));
  if (location.hash !== '#' + view) history.replaceState(null, '', '#' + view);
  if (!loaded[view] || opts.refresh) { loaded[view] = true; VIEWS[view](opts); }
  $('#main').scrollTop = 0;
}
$$('.rail [data-view]').forEach(b => b.addEventListener('click', () => show(b.dataset.view, { refresh: true })));
window.addEventListener('hashchange', () => show(location.hash.slice(1)));

/* ------------------------------------------------------------- overview --- */
async function showReport() {
  let md;
  try { md = (await api('/api/report')).markdown; } catch (e) { toast(e.message, true); return; }
  const ov = document.createElement('div');
  ov.className = 'modal-overlay';
  ov.innerHTML = `<div class="modal"><div class="row" style="margin-bottom:8px">
      <h2 style="margin:0">Investigation report</h2><span class="grow"></span>
      <a class="btn small" href="/api/report?download=1" download>Download .md</a>
      <button class="btn small" id="rpCopy">Copy</button><button class="btn small ghost" id="rpClose">Close</button></div>
    <pre class="report">${esc(md)}</pre></div>`;
  document.body.appendChild(ov);
  ov.onclick = e => { if (e.target === ov) ov.remove(); };
  $('#rpClose', ov).onclick = () => ov.remove();
  $('#rpCopy', ov).onclick = () => navigator.clipboard.writeText(md).then(() => toast('Report copied'));
}
async function renderOverview() {
  const el = $('#v-overview');
  let d;
  try { d = await api('/api/overview'); } catch (e) { el.innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
  $('#cFiles').textContent = d.files ? fmtN(d.files) : '';
  const sev = Object.fromEntries(d.severity.map(s => [s.severity, s.n]));
  $('#cFindings').textContent = (sev.high || sev.medium) ? fmtN((sev.high || 0) + (sev.medium || 0)) : '';
  $('#cEntities').textContent = d.entity_types.length ? fmtN(d.entity_types.reduce((a, b) => a + b.n, 0)) : '';
  const tHigh = (d.tamper || []).reduce((a, c) => a + (c.high || 0), 0);
  $('#cTamper').textContent = tHigh ? fmtN(tHigh) : '';
  api('/api/host').then(h => {
    if (h.empty) { $('#cHost').textContent = ''; return; }
    const n = h.accounts.filter(a => a.flags.some(f => f[0] === 'high')).length + h.integrity.filter(i => i.severity === 'high').length +
      h.persistence.filter(p => p.level === 'high').length + h.sources.filter(s => s.guessed).length + h.unknown_keys.length;
    $('#cHost').textContent = n ? fmtN(n) : '';
  }).catch(() => {});

  if (!d.files) {
    el.innerHTML = `<div class="panel empty">
      <h2>Point Crumbs at a folder of evidence</h2>
      <p>Every text file inside it (logs, JSON, CSV, configs, gzipped logs) is split into lines, indexed for substring search,
      and scanned for IPs, domains, hashes, secrets and attack patterns.</p>
      <div class="row" style="justify-content:center;margin-top:14px">
        <input class="input" id="ovRoot" placeholder="/cases/incident-42 or C:\\cases\\incident-42" size="44" value="${esc(d.root || '')}">
        <button class="btn primary" id="ovGo">Index folder</button>
      </div></div>`;
    $('#ovGo').onclick = () => startIndex($('#ovRoot').value, false);
    return;
  }
  const max = (arr, k) => Math.max(1, ...arr.map(x => x[k]));
  const tr = d.time_range || {};
  el.innerHTML = `
    <div class="ov-head">
      <div><h1>Case overview</h1>
        <p class="sub mono" style="margin:0">${esc(d.root || '')}</p></div>
      <span class="grow"></span>
      <button class="btn small" id="ovReport">Investigation report</button>
      <p class="muted" style="margin:6px 0 0;width:100%">Indexed ${esc(ago(d.last_indexed))}${tr.first ? ` · events from ${esc(tr.first)} to ${esc(tr.last)}` : ''}</p>
    </div>
    <div class="figures">
      <div class="figure"><b>${fmtN(d.files)}</b><span>files</span></div>
      <div class="figure"><b>${fmtN(d.lines)}</b><span>lines</span></div>
      <div class="figure"><b>${fmtB(d.bytes)}</b><span>on disk</span></div>
      <div class="figure"><b>${fmtN(d.entity_types.reduce((a, b) => a + b.n, 0))}</b><span>unique entities</span></div>
      <div class="figure sev-high"><b>${fmtN(sev.high || 0)}</b><span>high findings</span></div>
      <div class="figure sev-medium"><b>${fmtN(sev.medium || 0)}</b><span>medium findings</span></div>
      <div class="figure"><b>${fmtN(sev.low || 0)}</b><span>low findings</span></div>
    </div>
    <div id="ovLoginMap"></div>
    ${d.tamper && d.tamper.length ? `<div class="panel" style="margin-bottom:16px">
      <div class="row" style="margin-bottom:8px"><h2 style="margin:0">Tampering signals</h2><span class="grow"></span>
        <button class="btn small primary" id="ovTamper">Open the tampering timeline</button></div>
      <div class="bars">${d.tamper.map(c => `
        <div class="barrow" data-tcat="${esc(c.category)}"><span class="label">${esc(d.categories[c.category] || c.category)}
          <span class="faint" style="font-size:12.5px">${c.first ? esc(c.first.slice(0, 16)) + (c.last && c.last !== c.first ? ' to ' + esc(c.last.slice(0, 16)) : '') : 'undated'}</span></span>
          <span class="track"><span class="fill ${c.high ? 'high' : 'medium'}" style="width:${(100 * c.n / Math.max(...d.tamper.map(x => x.n))).toFixed(1)}%;display:block"></span></span>
          <span class="num">${c.high ? `<b style="color:var(--high)">${fmtN(c.high)}</b> / ` : ''}${fmtN(c.n)}</span></div>`).join('')}</div></div>` : ''}
    <div class="grid2">
      <div class="panel"><h2>What fired</h2>
        ${d.top_rules.length ? `<div class="bars">${d.top_rules.map(r => `
          <div class="barrow" data-rule="${esc(r.rule)}" title="${esc(r.description)}">
            <span class="label">${sevTag(r.severity)} &nbsp;${esc(r.description)}</span>
            <span class="track"><span class="fill ${esc(r.severity)}" style="width:${(100 * r.n / max(d.top_rules, 'n')).toFixed(1)}%;display:block"></span></span>
            <span class="num">${fmtN(r.n)}</span></div>`).join('')}</div>` : '<p class="muted">No detection rules matched.</p>'}
      </div>
      <div class="panel"><h2>Shared across files</h2>
        <p class="muted" style="margin:-4px 0 10px;font-size:13.5px">Entities that show up in more than one file are good pivots.</p>
        ${entityList(d.pivots, 'files')}
      </div>
      <div class="panel"><h2>Files with the most findings</h2>
        ${d.hot_files.length ? `<div class="bars">${d.hot_files.map(f => `
          <div class="barrow" data-fid="${f.id}"><span class="label mono" title="${esc(f.rel)}">${esc(f.rel)}</span>
          <span class="track"><span class="fill ${f.high ? 'high' : 'medium'}" style="width:${(100 * f.n / max(d.hot_files, 'n')).toFixed(1)}%;display:block"></span></span>
          <span class="num">${f.high ? `<b style="color:var(--high)">${fmtN(f.high)}</b> / ` : ''}${fmtN(f.n)}</span></div>`).join('')}</div>` : '<p class="muted">Nothing flagged.</p>'}
      </div>
      <div class="panel"><h2>Public IP addresses</h2>${entityList(d.public_ips, 'hits')}</div>
      <div class="panel"><h2>Private / internal IP addresses</h2>${d.private_ips && d.private_ips.length ? entityList(d.private_ips, 'hits') : '<p class="muted">None seen.</p>'}</div>
      <div class="panel"><h2>Domains</h2>${d.top_domains && d.top_domains.length ? entityList(d.top_domains, 'hits') : '<p class="muted">None extracted.</p>'}</div>
      <div class="panel"><h2>URLs</h2>${d.top_urls && d.top_urls.length ? entityList(d.top_urls, 'hits') : '<p class="muted">None extracted.</p>'}</div>
      ${d.top_tools && d.top_tools.length ? `<div class="panel ov-tools-panel"><h2>Non-standard tools found <span class="faint" style="font-size:13px">(by incidence)</span></h2>
        <p class="muted" style="margin:-4px 0 8px;font-size:13px">Sorted by total evidence weight: package installs and dropped binaries count more than log mentions.</p>
        <div class="bars">${d.top_tools.sort((a,b) => b.total_hits - a.total_hits).map(t => {
          const maxH = Math.max(1, ...d.top_tools.map(x => x.total_hits));
          const badges = [];
          if (t.dropped) badges.push(`<span class="hflag high">dropped</span>`);
          else if ((t.binaries||[]).length) badges.push(`<span class="hflag medium">binary</span>`);
          if ((t.packages||[]).length) badges.push(`<span class="hflag medium">installed</span>`);
          if ((t.configs||[]).length) badges.push(`<span class="hflag medium">config</span>`);
          const ips = (t.assoc_ips||[]).filter(ip => ip.meta !== 'loopback' && ip.value !== '0.0.0.0').slice(0,4);
          return `<div class="barrow" style="height:auto;flex-direction:column;align-items:stretch;gap:3px;padding:5px 0"><div class="row" style="gap:6px">
              <span class="label mono" style="min-width:120px"><b>${esc(t.tool)}</b></span>
              <span style="display:flex;gap:4px">${badges.join('')}</span>
              <span class="grow"></span>
              <span class="track" style="min-width:60px"><span class="fill ${t.dropped ? 'high' : (t.packages||[]).length ? 'medium' : ''}" style="width:${(100*t.total_hits/maxH).toFixed(1)}%;display:block"></span></span>
              <span class="num">${fmtN(t.total_hits)}</span></div>
            ${t.description ? `<div class="faint" style="font-size:12px;padding-left:4px">${esc(t.description.split('.')[0])}.</div>` : ''}
            ${ips.length ? `<div style="font-size:12px;padding-left:4px">${ips.map(ip =>
              `<span class="tchip ${ip.meta==='public'?'':'private-ip'}">${esc(ip.value)}<span class="faint"> ×${fmtN(ip.hits)}</span></span>`).join(' ')}</div>` : ''}</div>`;
        }).join('')}</div>
        <button class="btn small" style="margin-top:8px" data-view-go3="tools">See all tools ↗</button></div>` : ''}
      <div class="panel"><h2>File types</h2><div class="bars">${d.by_ext.map(x => `
          <div class="barrow" data-ext="${esc(x.ext)}"><span class="label mono">${esc(x.ext)}</span>
          <span class="track"><span class="fill" style="width:${(100 * x.n / max(d.by_ext, 'n')).toFixed(1)}%;display:block"></span></span>
          <span class="num">${fmtN(x.n)}</span></div>`).join('')}</div></div>
      <div class="panel"><h2>Entity types</h2><div class="bars">${d.entity_types.map(x => `
          <div class="barrow" data-etype="${esc(x.type)}"><span class="label">${etag(x.type)}</span>
          <span class="track"><span class="fill" style="width:${(100 * x.n / max(d.entity_types, 'n')).toFixed(1)}%;display:block;background:${eColor(x.type)}"></span></span>
          <span class="num">${fmtN(x.n)}</span></div>`).join('')}</div></div>
    </div>`;
  $$('[data-rule]', el).forEach(r => r.onclick = () => { FS.rule = r.dataset.rule; FS.sev = new Set(); show('findings', { refresh: true }); });
  if ($('#ovTamper')) $('#ovTamper').onclick = () => show('tamper', { refresh: true });
  if ($('#ovReport')) $('#ovReport').onclick = showReport;
  $$('[data-tcat]', el).forEach(r => r.onclick = () => { T.cats = new Set([r.dataset.tcat]); show('tamper', { refresh: true }); });
  $$('[data-fid]', el).forEach(r => r.onclick = () => openViewer(+r.dataset.fid, 1));
  $$('[data-ext]', el).forEach(r => r.onclick = () => { FT.filter = ''; FT.ext = r.dataset.ext; show('files', { refresh: true }); });
  $$('[data-etype]', el).forEach(r => r.onclick = () => { ES.types = new Set([r.dataset.etype]); ES.selected = null; show('entities', { refresh: true }); });
  bindEntityRows(el);
  mountLoginMap($('#ovLoginMap'), { panel: true });
  $$('[data-view-go3]', el).forEach(b => b.onclick = () => show(b.dataset.viewGo3, { refresh: true }));
}
function entityList(list, metric) {
  if (!list.length) return '<p class="muted">None found.</p>';
  return `<div class="list">${list.map(e => `
    <div class="item" data-eid="${e.id}" style="grid-template-columns:auto 1fr auto">
      ${etag(e.type)}<span class="v" title="${esc(e.value)}">${esc(e.value)} ${e.meta ? `<span class="meta-tag ${esc(e.meta)}">${esc(e.meta)}</span>` : ''}</span>
      <span class="num muted">${metric === 'files' ? plural(e.files, 'file') : plural(e.hits, 'hit')}</span></div>`).join('')}</div>`;
}
function bindEntityRows(el) {
  $$('[data-eid]', el).forEach(r => r.onclick = () => { ES.selected = +r.dataset.eid; show('entities', { refresh: true }); });
}

/* --------------------------------------------------------------- search --- */
function setMode(m) {
  S.mode = m;
  $$('.seg [data-mode]').forEach(b => b.setAttribute('aria-pressed', b.dataset.mode === m));
}
$$('.seg [data-mode]').forEach(b => b.onclick = () => { setMode(b.dataset.mode); if ($('#q').value.trim()) doSearch(); });
$('#searchForm').addEventListener('submit', e => { e.preventDefault(); doSearch(); });
$('#filtersBtn').onclick = () => {
  const f = $('#filters'); f.hidden = !f.hidden; $('#filtersBtn').setAttribute('aria-expanded', !f.hidden);
};
$('#fClear').onclick = () => { ['#fExt', '#fPath', '#fFrom', '#fTo'].forEach(s => ($(s).value = '')); if (S.q) doSearch(); };
['#fExt', '#fPath', '#fFrom', '#fTo'].forEach(s => $(s).addEventListener('keydown', e => { if (e.key === 'Enter') doSearch(); }));

function doSearch(extra = {}) {
  S.q = $('#q').value;
  S.file_id = extra.file_id ?? null;
  S.offset = 0; S.results = [];
  loaded.search = true;
  show('search');
  runSearch();
}
async function runSearch() {
  const el = $('#v-search');
  const f = filters();
  if (!S.q && !f.from && !f.to && !S.file_id) {
    el.innerHTML = `<div class="empty"><h2>Search across the whole case</h2>
      <p>Type any string above: an IP, a username, an error code, part of a hash. Results show the exact file and line.<br>
      <b>Contains</b> ignores case, <b>Match case</b> is exact, <b>Regex</b> takes Python syntax (prefix <code>(?i)</code> to ignore case).<br>
      Leave the box empty and set a time range under Filters to read every file in time order.</p>
      <div class="panel" style="text-align:left;max-width:760px;margin:18px auto 0">
        <h2>Boolean search</h2>
        <p class="muted" style="margin:0 0 8px">All words must appear, in any order. Encoded content that Crumbs decoded (base64, hex, auditd arguments) is searched too.</p>
        <dl class="kv" style="grid-template-columns:260px 1fr;font-size:13.5px">
          <dt class="mono">wget /tmp</dt><dd>lines containing both</dd>
          <dt class="mono">"history -c"</dt><dd>exact phrase</dd>
          <dt class="mono">curl OR wget</dt><dd>either term</dd>
          <dt class="mono">185.220.101.4 -Failed</dt><dd>exclude lines with a term</dd>
          <dt class="mono">file:auth.log ext:log</dt><dd>limit to paths or extensions (<code>*</code> wildcard)</dd>
          <dt class="mono">after:2024-03-14T02:30 before:2024-03-14T03:00</dt><dd>time window (as written in the logs)</dd>
          <dt class="mono">rule:ssh_* sev:high cat:persistence</dt><dd>only lines where a rule fired</dd>
          <dt class="mono">has:finding has:decoded has:time</dt><dd>lines with a finding, decoded content, or a time</dd>
          <dt class="mono">ep:1  ep:1,2  -ep:2</dt><dd>lines tagged with a flood / starvation episode (see Host view)</dd>
        </dl></div>
      <div class="row" style="justify-content:center;margin-top:14px"><button class="btn" id="sSweepOpen">IOC sweep: check a list of indicators</button></div></div>`;
    $('#sSweepOpen').onclick = renderSweep;
    return;
  }
  if (S.offset === 0) el.innerHTML = '<p class="muted">Searching…</p>';
  let d;
  try {
    d = await api('/api/search?' + qs({ q: S.q, mode: S.mode, limit: 200, offset: S.offset, file_id: S.file_id, ...f }));
  } catch (e) { el.innerHTML = `<div class="panel empty" style="color:var(--high)">${esc(e.message)}</div>`; return; }
  if (S.offset === 0) { S.files = d.files || []; S.total = d.total; S.capped = d.capped; S.decoded = d.decoded || []; }
  S.results = S.results.concat(d.results);
  S.hasMore = d.results.length === 200;
  S.took = d.took_ms; S.engine = d.engine;
  $('#cSearch').textContent = S.total != null ? fmtN(S.total) + (S.capped ? '+' : '') : '';
  drawSearch();
}
function drawSearch() {
  const el = $('#v-search');
  const totalTxt = S.total == null ? 'Many matches' : `${fmtN(S.total)}${S.capped ? '+' : ''} matching lines`;
  const label = S.q ? `“${esc(S.q)}”` : 'lines in the selected time range';
  const decHtml = (S.decoded || []).length ? `<div class="panel" style="margin-bottom:14px;border-color:var(--info)">
      <h2 style="margin-bottom:6px">Found inside decoded content (${fmtN(S.decoded.length)}${S.decoded.length >= 100 ? '+' : ''})</h2>
      <p class="muted" style="margin:0 0 8px;font-size:13.5px">These lines only contain the term once their base64, hex or auditd arguments are decoded.</p>
      ${S.decoded.map(h => `<div class="hit" data-fid="${h.file_id}" data-line="${h.line}">
        <span class="ln">${h.line}</span><code><span class="tchip decoded" style="margin-right:6px">${esc(h.method)}</span>${h.cut_left ? '<span class="cut">… </span>' : ''}${markSpans(h.snippet, h.spans)}${h.cut_right ? '<span class="cut"> …</span>' : ''}</code>
        <span class="ts">${esc(h.rel)}</span></div>`).join('')}</div>` : '';
  if (!S.results.length) {
    el.innerHTML = decHtml + `<div class="empty"><h2>No ${decHtml ? 'raw ' : ''}lines match ${label}</h2>
      <p>${S.mode === 'case' ? 'Try <b>Contains</b> to ignore case, or ' : ''}check the filters. Terms shorter than 3 characters use a slower full scan.</p></div>`;
    return;
  }
  const groups = [];
  for (const r of S.results) {
    const g = groups[groups.length - 1];
    if (g && g.file_id === r.file_id) g.hits.push(r); else groups.push({ file_id: r.file_id, rel: r.rel, hits: [r] });
  }
  el.innerHTML = `
    <div class="row" style="margin-bottom:14px">
      <h1 style="margin:0">${totalTxt}</h1>
      <span class="muted">for ${label} in ${fmtN(S.files.length)}${S.capped ? '+' : ''} files · ${S.took} ms · ${S.engine === 'fts' ? 'index' : 'full scan'}</span>
      <span class="grow"></span>
      ${S.file_id ? '<button class="btn small" id="sAll">Show all files</button>' : ''}
      <button class="btn small" id="sSweep">IOC sweep</button>
    </div>
    ${decHtml}
    <div class="search-layout">
      <div class="facets">${S.files.map(f => `
        <div class="facet ${S.file_id === f.file_id ? 'on' : ''}" data-ff="${f.file_id}" title="${esc(f.rel)}">
          <span class="p mono">${esc(f.rel)}</span><span class="c">${fmtN(f.count)}</span></div>`).join('')}</div>
      <div>${groups.map(g => `
        <div class="hitgroup">
          <div class="hitfile" data-open="${g.file_id}">${esc(g.rel)}</div>
          ${g.hits.map(h => `<div class="hit" data-fid="${h.file_id}" data-line="${h.line}">
            <span class="ln">${h.line}</span>
            <code>${h.cut_left ? '<span class="cut">… </span>' : ''}${markSpans(h.snippet, h.spans)}${h.cut_right ? '<span class="cut"> …</span>' : ''}</code>
            <span class="ts">${esc(h.ts || '')}</span></div>`).join('')}
        </div>`).join('')}
        ${S.hasMore ? '<div class="more"><button class="btn" id="sMore">Load 200 more</button></div>' : ''}
      </div>
    </div>`;
  $$('.hit', el).forEach(h => h.onclick = () => openViewer(+h.dataset.fid, +h.dataset.line, { q: S.q, mode: S.mode }));
  $$('[data-open]', el).forEach(h => h.onclick = () => openViewer(+h.dataset.open, 1, { q: S.q, mode: S.mode }));
  $$('[data-ff]', el).forEach(h => h.onclick = () => { const id = +h.dataset.ff; S.file_id = S.file_id === id ? null : id; S.offset = 0; S.results = []; runSearch(); });
  if ($('#sMore')) $('#sMore').onclick = () => { S.offset += 200; runSearch(); };
  if ($('#sAll')) $('#sAll').onclick = () => { S.file_id = null; S.offset = 0; S.results = []; runSearch(); };
  $('#sSweep').onclick = renderSweep;
}
function bindDecodedHits(el) {}

/* ------------------------------------------------------------ IOC sweep --- */
const SW = { text: '', results: null };
function renderSweep() {
  show('search');
  const el = $('#v-search');
  el.innerHTML = `<div class="row" style="margin-bottom:10px"><h1 style="margin:0">IOC sweep</h1><span class="grow"></span>
      <button class="btn small" id="swBack">Back to search</button></div>
    <p class="sub">Paste indicators, one per line: IPs, domains, hashes, file names, usernames, commands. Each is looked up in every line and in decoded content.</p>
    <textarea id="swText" spellcheck="false" style="width:100%;min-height:150px;font:13px var(--mono);background:var(--surface);color:var(--text);border:1px solid var(--line);border-radius:var(--radius);padding:10px">${esc(SW.text)}</textarea>
    <div class="row" style="margin:10px 0 16px"><button class="btn primary" id="swRun">Sweep</button><span class="muted" id="swInfo"></span></div>
    <div id="swOut"></div>`;
  $('#swBack').onclick = () => { S.results.length ? drawSearch() : runSearch(); };
  $('#swRun').onclick = async () => {
    SW.text = $('#swText').value;
    const terms = SW.text.split(/[\n,;]+/).map(t => t.trim()).filter(Boolean);
    if (!terms.length) return;
    $('#swInfo').textContent = `Checking ${terms.length} indicators…`;
    try { SW.results = (await post('/api/sweep', { terms })).results; } catch (e) { toast(e.message, true); return; }
    drawSweep();
  };
  if (SW.results) drawSweep();
}
function drawSweep() {
  const r = SW.results, hit = r.filter(x => x.lines || x.decoded).length;
  $('#swInfo').textContent = `${hit} of ${r.length} indicators found`;
  $('#swOut').innerHTML = `<div class="list">${[...r].sort((a, b) => (b.lines + b.decoded) - (a.lines + a.decoded)).map(x => `
    <div class="item" data-sw="${esc(x.term)}" style="grid-template-columns:minmax(160px,1.4fr) 90px 80px 90px 1.2fr;${x.lines || x.decoded ? '' : 'opacity:.55'}">
      <span class="v mono">${esc(x.term)}${x.entity ? ` <span class="faint">${esc(x.entity)}</span>` : ''}</span>
      <span>${x.lines ? `<b>${fmtN(x.lines)}</b> lines` : '<span class="faint">no lines</span>'}</span>
      <span>${x.files ? plural(x.files, 'file') : ''}</span>
      <span>${x.decoded ? `<span class="tchip decoded">${fmtN(x.decoded)} decoded</span>` : ''}</span>
      <span class="mono faint" style="font-size:12.5px">${x.first ? esc(x.first) + (x.last && x.last !== x.first ? ' → ' + esc(x.last) : '') : ''}${x.error ? ' ' + esc(x.error) : ''}</span></div>`).join('')}</div>`;
  $$('[data-sw]').forEach(r => r.onclick = () => { $('#q').value = '"' + r.dataset.sw.replace(/"/g, '""') + '"'; setMode('query'); doSearch(); });
}
function renderSearch() { S.offset = 0; S.results = []; runSearch(); }
function searchFor(value) {
  $('#q').value = value; setMode('substring'); doSearch();
}

/* ---------------------------------------------------------------- files --- */
const FT = { filter: '', ext: '', data: null };
async function renderFiles() {
  const el = $('#v-files');
  try { FT.data = (await api('/api/files')).files; } catch (e) { el.innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
  el.innerHTML = `
    <div class="row" style="margin-bottom:14px"><h1 style="margin:0">Files</h1>
      <span class="muted">${fmtN(FT.data.length)} files</span><span class="grow"></span>
      <input class="input" id="ftFilter" placeholder="Filter by path" value="${esc(FT.filter)}" size="28">
      <input class="input" id="ftExt" placeholder="Type, e.g. .log" value="${esc(FT.ext)}" size="12">
    </div>
    <div class="frow" style="cursor:default;color:var(--faint);font-size:12.5px;padding-top:0">
      <span>Name</span><span class="r">Findings</span><span class="r hide-sm">Lines</span><span class="r">Size</span><span class="r hide-sm">Status</span></div>
    <div class="tree" id="tree"></div>`;
  $('#ftFilter').oninput = e => { FT.filter = e.target.value; drawTree(); };
  $('#ftExt').oninput = e => { FT.ext = e.target.value; drawTree(); };
  drawTree();
}
function drawTree() {
  const f = FT.filter.toLowerCase(), x = FT.ext.toLowerCase().trim();
  const files = FT.data.filter(r => (!f || r.rel.toLowerCase().includes(f)) && (!x || r.ext.includes(x)));
  const root = { dirs: {}, files: [], n: 0, find: 0 };
  for (const r of files) {
    const parts = r.rel.split('/'); parts.pop();
    let node = root; node.n++; node.find += r.findings;
    for (const p of parts) { node = node.dirs[p] ??= { dirs: {}, files: [], n: 0, find: 0 }; node.n++; node.find += r.findings; }
    node.files.push(r);
  }
  const open = !!(f || x) || files.length < 300;
  const draw = (node, depth) => Object.keys(node.dirs).sort().map(k => {
    const d = node.dirs[k];
    return `<details ${open || depth === 0 ? 'open' : ''}><summary><span class="mono">${esc(k)}/</span>
      <span class="faint" style="font-size:12.5px">${plural(d.n, 'file')}${d.find ? ` · ${plural(d.find, 'finding')}` : ''}</span></summary>
      ${draw(d, depth + 1)}</details>`;
  }).join('') + node.files.map(r => `
      <div class="frow ${r.status !== 'ok' ? 'dim' : ''}" data-fid="${r.id}" title="${esc(r.rel)}${r.note ? '\n' + esc(r.note) : ''}">
        <span class="name">${esc(r.name)}</span>
        <span class="r">${r.findings ? sevTag(r.severity) + ' ' + fmtN(r.findings) : ''}</span>
        <span class="r hide-sm">${r.status === 'ok' ? fmtN(r.line_count) : ''}</span>
        <span class="r">${fmtB(r.size)}</span>
        <span class="r hide-sm">${r.status === 'ok' ? '' : esc(r.status)}</span></div>`).join('');
  $('#tree').innerHTML = files.length ? draw(root, 0) : '<div class="empty">No files match.</div>';
  $$('#tree .frow').forEach(r => r.onclick = () => openViewer(+r.dataset.fid, 1));
}

/* ------------------------------------------------------------- findings --- */
const FS = { sev: new Set(), rule: '', q: '', offset: 0, items: [], dismissed: false };
async function renderFindings() {
  const el = $('#v-findings');
  let sum;
  try { sum = (await api('/api/findings/summary')).rules; } catch (e) { el.innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
  if (!sum.length) { el.innerHTML = '<div class="empty"><h2>No findings</h2><p>None of the detection rules matched. Rules live in <code>analyzers.py</code> and are easy to extend.</p></div>'; return; }
  el.innerHTML = `
    <h1>Findings</h1>
    <p class="sub">Lines matched by the built-in detection rules. Click a rule to narrow the list, click a line to open it.</p>
    <div class="list" style="margin-bottom:18px">${sum.map(r => `
      <div class="item ${FS.rule === r.rule ? 'active' : ''}" data-rule="${esc(r.rule)}" style="grid-template-columns:90px 1fr 110px 90px">
        ${sevTag(r.severity)}<span>${esc(r.description)} <span class="faint mono" style="font-size:12px">${esc(r.rule)}</span></span>
        <span class="num muted" style="text-align:right">${plural(r.files, 'file')}</span><span class="num" style="text-align:right">${fmtN(r.n)}</span></div>`).join('')}</div>
    <div class="row" style="margin-bottom:10px">
      <div class="chips">${['high', 'medium', 'low', 'info'].map(s => `<button class="chip" data-sev="${s}" aria-pressed="${FS.sev.has(s)}">${s}</button>`).join('')}</div>
      ${FS.rule ? `<button class="chip" id="fsRule" aria-pressed="true">${esc(FS.rule)} ✕</button>` : ''}
      <span class="grow"></span>
      <input class="input" id="fsQ" placeholder="Filter by text or path" value="${esc(FS.q)}" size="26">
    </div>
    <div id="fsList"></div>`;
  $$('[data-rule]', el).forEach(r => r.onclick = () => { FS.rule = FS.rule === r.dataset.rule ? '' : r.dataset.rule; renderFindings(); });
  $$('[data-sev]', el).forEach(b => b.onclick = () => { FS.sev.has(b.dataset.sev) ? FS.sev.delete(b.dataset.sev) : FS.sev.add(b.dataset.sev); b.setAttribute('aria-pressed', FS.sev.has(b.dataset.sev)); loadFindings(); });
  if ($('#fsRule')) $('#fsRule').onclick = () => { FS.rule = ''; renderFindings(); };
  let t; $('#fsQ').oninput = e => { clearTimeout(t); t = setTimeout(() => { FS.q = e.target.value; loadFindings(); }, 250); };
  loadFindings();
}
async function loadFindings(append = false) {
  if (!append) { FS.offset = 0; FS.items = []; }
  const d = await api('/api/findings?' + qs({ severity: [...FS.sev].join(','), rule: FS.rule, q: FS.q, limit: 200, offset: FS.offset, dismissed: FS.dismissed ? 1 : '' }));
  FS.items = FS.items.concat(d.findings);
  const el = $('#fsList');
  el.innerHTML = `<p class="muted" style="margin:0 0 8px">${fmtN(d.total)} lines
      <label style="margin-left:12px;font-size:13px"><input type="checkbox" id="fsDis" ${FS.dismissed ? 'checked' : ''}> show dismissed (false positives)</label></p>
    <div class="list">${FS.items.map(x => `
      <div class="item" data-fid="${x.file_id || ''}" data-line="${x.line_no || 1}" style="grid-template-columns:80px minmax(160px,300px) 1fr 150px">
        ${sevTag(x.severity)}<span class="v" title="${esc(x.rel || 'case-wide')}${x.line_no ? ':' + x.line_no : ''}">${x.rel ? esc(x.rel) : '<span class="faint">case-wide</span>'}${x.line_no ? `<span class="faint">:${x.line_no}</span>` : ''}</span>
        <span class="v" title="${esc(x.description)}" style="${x.verdict === 'fp' ? 'opacity:.5;text-decoration:line-through' : ''}">${vchip(x.verdict)} ${esc(x.snippet)}</span><span class="mono faint" style="font-size:12px">${esc(x.ts || '')}</span></div>`).join('')}</div>
    ${FS.items.length < d.total ? '<div class="more"><button class="btn" id="fsMore">Load 200 more</button></div>' : ''}`;
  $$('.item', el).forEach(r => r.onclick = () => r.dataset.fid ? openViewer(+r.dataset.fid, +r.dataset.line) : show('tamper', { refresh: true }));
  if ($('#fsMore')) $('#fsMore').onclick = () => { FS.offset += 200; loadFindings(true); };
  $('#fsDis').onchange = e => { FS.dismissed = e.target.checked; loadFindings(); };
}

/* ------------------------------------------------------------- entities --- */
const ES = { types: new Set(), q: '', meta: '', minFiles: 1, sort: 'files', selected: null };
async function renderEntities() {
  const el = $('#v-entities');
  el.innerHTML = `
    <h1>Entities</h1>
    <p class="sub">Indicators pulled out of every line: IPs, domains, URLs, emails, hashes, users, paths, CVEs.</p>
    <div class="row" style="margin-bottom:12px">
      <div class="chips" id="esTypes"></div><span class="grow"></span>
      <input class="input" id="esQ" placeholder="Filter values" value="${esc(ES.q)}" size="22">
      <select class="input" id="esMeta"><option value="">Any IP class</option>
        ${['public', 'private', 'loopback', 'reserved', 'multicast'].map(m => `<option ${ES.meta === m ? 'selected' : ''}>${m}</option>`).join('')}</select>
      <select class="input" id="esSort"><option value="files" ${ES.sort === 'files' ? 'selected' : ''}>Most files</option><option value="hits" ${ES.sort === 'hits' ? 'selected' : ''}>Most hits</option></select>
      <label class="muted row" style="gap:6px;font-size:13.5px">In at least <input class="input" id="esMin" type="number" min="1" value="${ES.minFiles}" style="width:64px"> files</label>
    </div>
    <div class="ent-layout"><div id="esList"></div><div class="detail" id="esDetail"></div></div>`;
  let t;
  $('#esQ').oninput = e => { clearTimeout(t); t = setTimeout(() => { ES.q = e.target.value; loadEntities(); }, 250); };
  $('#esMeta').onchange = e => { ES.meta = e.target.value; loadEntities(); };
  $('#esSort').onchange = e => { ES.sort = e.target.value; loadEntities(); };
  $('#esMin').onchange = e => { ES.minFiles = Math.max(1, +e.target.value || 1); loadEntities(); };
  await loadEntities();
  if (ES.selected) loadEntity(ES.selected);
  else $('#esDetail').innerHTML = '<div class="panel muted">Pick an entity to see every file it appears in and what it travels with.</div>';
}
async function loadEntities() {
  const d = await api('/api/entities?' + qs({ type: [...ES.types].join(','), q: ES.q, meta: ES.meta, sort: ES.sort, min_files: ES.minFiles, limit: 500 }));
  $('#esTypes').innerHTML = d.types.map(t => `<button class="chip" data-t="${esc(t.type)}" aria-pressed="${ES.types.has(t.type)}"><span style="color:${eColor(t.type)}">●</span> ${esc(eLabel(t.type))} <span class="faint">${fmtN(t.n)}</span></button>`).join('');
  $$('#esTypes [data-t]').forEach(b => b.onclick = () => { const t = b.dataset.t; ES.types.has(t) ? ES.types.delete(t) : ES.types.add(t); loadEntities(); });
  const list = $('#esList');
  ES._keys = d.intel_keys || {};
  list.innerHTML = d.entities.length ? `<div class="list">${d.entities.map(e => `
    <div class="item ${ES.selected === e.id ? 'active' : ''}" data-e="${e.id}" style="grid-template-columns:110px 1fr auto 72px 64px">
      <span>${etag(e.type)}</span>
      <span class="v" title="${esc(e.value)}">${esc(e.value)} ${e.meta ? `<span class="meta-tag ${esc(e.meta)}">${esc(e.meta)}</span>` : ''}</span>
      <span class="entintel">${entIntelChip(e)}${corrBadge(e.corr_score, e.corr_kinds, true)}</span>
      <span class="num muted" style="text-align:right">${plural(e.files, 'file')}</span><span class="num muted" style="text-align:right">${plural(e.hits, 'hit')}</span></div>`).join('')}</div>
    ${d.entities.length === 500 ? '<p class="faint">Showing the first 500. Narrow with filters.</p>' : ''}`
    : '<div class="empty">No entities match these filters.</div>';
  $$('[data-e]', list).forEach(r => r.onclick = () => {
    ES.selected = +r.dataset.e;
    $$('[data-e]', list).forEach(x => x.classList.toggle('active', x === r));
    loadEntity(ES.selected);
  });
  $$('[data-elook]', list).forEach(b => b.onclick = async ev => {
    ev.stopPropagation();
    const ent = d.entities.find(x => x.id === +b.dataset.elook);
    b.textContent = 'looking up…';
    const kind = { ipv4: 'ip', ipv6: 'ip', md5: 'hash', sha1: 'hash', sha256: 'hash', domain: 'domain', url: 'url' }[ent.type];
    try { const r = await post('/api/intel', { indicator: ent.value, type: kind }); toast(`${ent.value}: ${r.assessment.level}${r.assessment.notes.length ? ' — ' + r.assessment.notes.join(', ') : ''}`, r.assessment.level === 'malicious'); loadEntities(); }
    catch (e) { toast(e.message, true); b.textContent = 'look up'; }
  });
}
function corrBadge(score, kinds, compact=false) {
  if (!score || score < 2) return '';
  const cls = score >= 6 ? 'high' : score >= 4 ? 'medium' : 'low';
  const label = score >= 6 ? `confirmed by ${score} sources` : score >= 4 ? `${score} sources` : `${score} sources`;
  const tip = (kinds || []).join(', ');
  if (compact) return `<span class="corr-badge ${cls}" title="Corroboration: ${esc(tip)}">${esc(label)}</span>`;
  return `<div class="corr-block ${cls}"><b>Corroborated by ${score} independent log source${score>1?'s':''}:</b> ${esc(tip)}</div>`;
}

function entIntelChip(e) {
  if (!e.intel_providers || !e.intel_providers.length) return '';
  if (!e.intel) {
    const canLook = (e.meta === 'public' || e.type.startsWith('sha') || e.type === 'md5' || e.type === 'domain' || e.type === 'url');
    if (!canLook) return '';
    return `<button class="ipill" data-elook="${e.id}" title="Look up with ${e.intel_providers.join(', ')}">intel: look up</button>`;
  }
  const lvl = e.intel.level;
  const cls = lvl === 'malicious' ? 'bad' : lvl === 'suspicious' ? 'warn' : 'okpill';
  const label = lvl === 'unknown' ? 'intel: clean/unknown' : lvl;
  return `<span class="ipill ${cls}" title="${esc((e.intel.notes || []).join(', '))}">${esc(label)}${e.intel.notes && e.intel.notes.length ? ' · ' + esc(e.intel.notes[0]) : ''}</span>`;
}
async function loadEntity(id) {
  const box = $('#esDetail');
  let d;
  try { d = await api('/api/entity/' + id); } catch (e) { box.innerHTML = `<div class="panel">${esc(e.message)}</div>`; return; }
  const e = d.entity;
  box.innerHTML = `<div class="panel">
    <div class="row" style="margin-bottom:6px">${etag(e.type)} ${e.meta ? `<span class="meta-tag ${esc(e.meta)}">${esc(e.meta)}</span>` : ''}</div>
    <div class="v" style="font-size:16px;margin-bottom:12px">${esc(e.value)}</div>
    <div class="row" style="margin-bottom:16px">
      <button class="btn small primary" id="edSearch">Search all lines</button>
      <button class="btn small" id="edGraph">Show in graph</button>
      <button class="btn small" id="edCopy">Copy</button>
    </div>
    ${corrBadge(d.corr_score, d.corr_kinds)}
    ${entIntelPanel(d.intel)}
    <h2>Seen in ${plural(d.files.length, 'file')}</h2>
    <div style="display:flex;flex-direction:column;gap:10px;margin-bottom:18px">${d.files.map(f => `
      <div><div class="mono" style="font-size:13px;cursor:pointer;word-break:break-all" data-of="${f.id}" data-l="${f.first_line}">${esc(f.rel)} <span class="faint">${plural(f.hits, 'hit')}</span></div>
      <div class="linelinks">${f.lines.slice(0, 24).map(l => `<button data-of="${f.id}" data-l="${l}">${l}</button>`).join('')}${f.lines.length > 24 || f.hits > f.lines.length ? '<span class="faint" style="font-size:12px">…</span>' : ''}</div></div>`).join('')}
    </div>
    ${d.related.length ? `<h2>Found alongside</h2><p class="muted" style="margin:-6px 0 8px;font-size:13px">Other entities in the same files, by number of shared files.</p>
    <div class="list">${d.related.map(r => `<div class="item" data-rel="${r.id}" style="grid-template-columns:auto 1fr auto">${etag(r.type)}<span class="v">${esc(r.value)}</span><span class="num muted">${r.shared}</span></div>`).join('')}</div>` : ''}
  </div>`;
  $$('[data-of]', box).forEach(b => b.onclick = () => openViewer(+b.dataset.of, +b.dataset.l, { q: e.value, mode: 'substring' }));
  $$('[data-rel]', box).forEach(b => b.onclick = () => { ES.selected = +b.dataset.rel; loadEntity(ES.selected); });
  $('#edSearch').onclick = () => searchFor(e.value);
  $('#edGraph').onclick = () => { G.focus = e.id; show('graph', { refresh: true }); };
  $('#edCopy').onclick = () => navigator.clipboard.writeText(e.value).then(() => toast('Copied'));
  bindEntIntel(box, d.intel ? { ...d.intel, value: e.value } : null, () => loadEntity(id));
}
function entIntelPanel(it) {
  if (!it) return '';
  const names = { virustotal: 'VirusTotal', shodan: 'Shodan', abuseipdb: 'AbuseIPDB' };
  const rows = it.providers.map(p => {
    const r = it.cached[p];
    if (!r) return `<div class="intelrow"><div class="row" style="gap:8px"><b>${names[p]}</b><span class="faint">${it.keys[p] ? 'not looked up yet' : 'needs API key'}</span>
      <span class="grow"></span><button class="btn small" data-elook1="${p}" ${it.keys[p] ? '' : 'disabled'}>Look up</button></div></div>`;
    return `<div class="intelrow">${intelProviderCard(p, names[p], r)}</div>`;
  }).join('');
  const asm = it.assessment;
  return `<div class="intel" style="margin:0 0 16px"><div class="row" style="gap:8px;margin-bottom:4px">
      <b>Threat intel</b>${asm ? ` <span class="hflag ${asm.level === 'malicious' ? 'high' : asm.level === 'suspicious' ? 'medium' : 'low'}">${asm.level}</span>` : ''}
      <span class="grow"></span><button class="btn small" id="edIntelAll">Look up all</button><button class="btn small ghost" data-view-go2="settings">Keys…</button></div>
    ${rows}</div>`;
}
function intelProviderCard(p, label, r) {
  if (!r.ok) return `<div class="row" style="gap:8px"><b>${label}</b><span class="faint">${esc(r.summary || 'error')}</span><span class="grow"></span><button class="btn small" data-elook1="${p}">Retry</button></div>`;
  const d = r.data || {};
  let body = `<span class="faint">${esc(r.summary || '')}</span>`;
  if (p === 'shodan' && d.found !== false) {
    body = `<div class="kv2">
      ${d.ports && d.ports.length ? `<div><span class="faint">Open ports</span> <span class="mono">${d.ports.join(', ')}</span></div>` : ''}
      ${d.products && d.products.length ? `<div><span class="faint">Services</span> ${esc(d.products.join(', '))}</div>` : ''}
      ${d.vulns && d.vulns.length ? `<div><span class="faint">Known CVEs</span> <span class="mono" style="color:var(--high)">${d.vulns.slice(0, 12).map(esc).join(', ')}${d.vulns.length > 12 ? ' +' + (d.vulns.length - 12) : ''}</span></div>` : ''}
      ${d.org || d.isp ? `<div><span class="faint">Network</span> ${esc(d.org || d.isp)}${d.asn ? ' (' + esc(d.asn) + ')' : ''}</div>` : ''}
      ${d.country ? `<div><span class="faint">Location</span> ${esc([d.city, d.country].filter(Boolean).join(', '))}</div>` : ''}
      ${d.hostnames && d.hostnames.length ? `<div><span class="faint">Hostnames</span> <span class="mono">${d.hostnames.map(esc).join(', ')}</span></div>` : ''}
      ${d.tags && d.tags.length ? `<div><span class="faint">Tags</span> ${d.tags.map(t => `<span class="tchip">${esc(t)}</span>`).join(' ')}</div>` : ''}</div>`;
  } else if (p === 'abuseipdb') {
    body = `<div class="kv2">
      <div><span class="faint">Abuse score</span> <b style="color:${d.score >= 50 ? 'var(--high)' : d.score >= 15 ? 'var(--medium)' : 'inherit'}">${d.score || 0}/100</b> from ${fmtN(d.reports || 0)} report(s)${d.whitelisted ? ' <span class="hflag low">allowlisted</span>' : ''}${d.tor ? ' <span class="hflag medium">Tor exit</span>' : ''}</div>
      ${d.categories && d.categories.length ? `<div><span class="faint">Reported for</span> ${d.categories.map(c => `<span class="tchip">${esc(c.name)} ×${c.n}</span>`).join(' ')}</div>` : ''}
      ${d.usage ? `<div><span class="faint">Usage</span> ${esc(d.usage)}${d.isp ? ' · ' + esc(d.isp) : ''}</div>` : ''}
      ${d.last_reported ? `<div><span class="faint">Last reported</span> <span class="mono">${esc(d.last_reported)}</span></div>` : ''}</div>`;
  } else if (p === 'virustotal' && d.found !== false) {
    body = `<div class="kv2">
      <div><span class="faint">Detections</span> <b style="color:${d.malicious >= 1 ? 'var(--high)' : 'inherit'}">${d.malicious || 0}/${d.total || '?'}</b>${d.suspicious ? ' +' + d.suspicious + ' suspicious' : ''}${d.label ? ` <span class="hflag ${d.malicious >= 3 ? 'high' : 'medium'}">${esc(d.label)}</span>` : ''}</div>
      ${d.type ? `<div><span class="faint">Type</span> ${esc(d.type)}</div>` : ''}
      ${d.names && d.names.length ? `<div><span class="faint">Names</span> <span class="mono">${d.names.map(esc).join(', ')}</span></div>` : ''}
      ${d.as_owner ? `<div><span class="faint">Network</span> ${esc(d.as_owner)}${d.country ? ' (' + esc(d.country) + ')' : ''}</div>` : ''}
      ${d.reputation != null ? `<div><span class="faint">Reputation</span> ${d.reputation}</div>` : ''}</div>`;
  }
  const link = (r.data && r.data.link) ? ` <a class="lnk" href="${esc(r.data.link)}" target="_blank" rel="noopener">open ↗</a>` : '';
  return `<div><div class="row" style="gap:8px"><b>${label}</b><span class="faint" style="font-size:12px">${esc(r.fetched || '')}${link}</span><span class="grow"></span><button class="btn small ghost" data-elook1="${p}">Refresh</button></div>${body}</div>`;
}
function bindEntIntel(box, it, reload) {
  if (!it) return;
  const run = async (prov) => {
    toast('Looking up ' + it.value + '…');
    try { const r = await post('/api/intel', { indicator: it.value, type: it.type, providers: prov ? [prov] : null, force: !!prov }); toast(`${it.value}: ${r.assessment.level}${r.assessment.notes.length ? ' — ' + r.assessment.notes.join(', ') : ''}`, r.assessment.level === 'malicious'); reload(); }
    catch (e) { toast(e.message, true); }
  };
  $$('[data-elook1]', box).forEach(b => b.onclick = () => run(b.dataset.elook1));
  if ($('#edIntelAll')) $('#edIntelAll').onclick = () => run(null);
  $$('[data-view-go2]', box).forEach(b => b.onclick = () => show(b.dataset.viewGo2, { refresh: true }));
}

/* ------------------------------------------------------------- timeline --- */
const TL = { bucket: 'day', sel: null };
async function renderTimeline() {
  const el = $('#v-timeline');
  el.innerHTML = `
    <div class="row" style="margin-bottom:6px"><h1 style="margin:0">Timeline</h1><span class="grow"></span>
      <div class="seg" id="tlBucket">${['month', 'day', 'hour', 'minute'].map(b => `<button type="button" data-b="${b}" aria-pressed="${TL.bucket === b}" style="height:32px">${b[0].toUpperCase() + b.slice(1)}</button>`).join('')}</div></div>
    <p class="sub">Lines with a recognised timestamp across all files. Grey bars are events, the strip below shows findings (red = high). Click a bar to read that slice in time order.</p>
    <div class="tl-wrap" id="tlChart"><p class="muted">Loading…</p></div>
    <div id="tlLines" style="margin-top:18px"></div>`;
  $$('#tlBucket [data-b]').forEach(b => b.onclick = () => { TL.bucket = b.dataset.b; renderTimeline(); });
  const f = filters();
  const d = await api('/api/timeline?' + qs({ bucket: TL.bucket, from: f.from, to: f.to }));
  drawTimeline(d);
}
function drawTimeline(d) {
  const box = $('#tlChart');
  const s = d.series;
  if (!s.length) { box.innerHTML = '<div class="empty">No timestamps were recognised in the indexed lines.</div>'; return; }
  const W = Math.max(box.clientWidth - 24, s.length * 6 + 60), H = 260, top = 10, mainH = 170, fTop = 200, fH = 36, left = 50;
  const bw = Math.min(48, (W - left - 10) / s.length);
  const maxE = Math.max(...s.map(x => x.events)), maxF = Math.max(1, ...s.map(x => x.findings));
  const ticks = [0, .5, 1].map(k => Math.round(maxE * k));
  const every = Math.max(1, Math.ceil(s.length / Math.floor((W - left) / 90)));
  let svg = `<svg width="${W}" height="${H}" role="img" aria-label="Events over time">`;
  ticks.forEach(t => { const y = top + mainH - (t / maxE) * mainH; svg += `<line class="tl-grid" x1="${left}" x2="${W}" y1="${y}" y2="${y}"/><text class="tl-axis" x="${left - 6}" y="${y + 4}" text-anchor="end">${t >= 1000 ? (t / 1000).toFixed(t >= 10000 ? 0 : 1) + 'k' : t}</text>`; });
  s.forEach((x, i) => {
    const X = left + i * bw, h = Math.max(1, (x.events / maxE) * mainH);
    svg += `<rect class="tl-bar ${TL.sel === x.b ? 'sel' : ''}" data-i="${i}" x="${X + .5}" y="${top + mainH - h}" width="${Math.max(1, bw - 1)}" height="${h}"><title>${x.b}: ${fmtN(x.events)} lines, ${fmtN(x.findings)} findings</title></rect>`;
    if (x.findings) { const fh = Math.max(2, (x.findings / maxF) * fH); svg += `<rect class="tl-find ${x.high ? 'hi' : ''}" data-i="${i}" x="${X + .5}" y="${fTop + fH - fh}" width="${Math.max(1, bw - 1)}" height="${fh}"><title>${x.b}: ${fmtN(x.findings)} findings (${fmtN(x.high)} high)</title></rect>`; }
    if (i % every === 0) svg += `<text class="tl-axis" x="${X}" y="${H - 6}">${esc(x.b.slice(TL.bucket === 'minute' ? 5 : TL.bucket === 'hour' ? 5 : 0))}</text>`;
  });
  svg += `<text class="tl-axis" x="${left - 6}" y="${fTop + fH}" text-anchor="end">finds</text></svg>`;
  box.innerHTML = svg + (d.truncated ? '<p class="faint">Showing the latest 3000 buckets. Use a coarser bucket or a time filter.</p>' : '');
  $$('[data-i]', box).forEach(r => r.onclick = () => { TL.sel = s[+r.dataset.i].b; drawTimeline(d); loadSlice(TL.sel); });
}
async function loadSlice(b, offset = 0) {
  const pad = { month: ['-01 00:00', '-31 23:59'], day: [' 00:00', ' 23:59'], hour: [':00', ':59'], minute: ['', ''] }[TL.bucket];
  const from = b + pad[0], to = b + pad[1];
  const el = $('#tlLines');
  const d = await api('/api/search?' + qs({ from, to, limit: 300, offset, facets: offset ? 0 : 1, q: '' }));
  const rowsHtml = d.results.map(h => `<div class="hit" data-fid="${h.file_id}" data-line="${h.line}" style="grid-template-columns:130px minmax(120px,260px) 1fr">
      <span class="ts" style="padding-left:12px">${esc(h.ts)}</span><span class="mono faint" style="font-size:12.5px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(h.rel)}:${h.line}">${esc(h.rel)}:${h.line}</span>
      <code>${esc(h.snippet)}${h.cut_right ? '<span class="cut"> …</span>' : ''}</code></div>`).join('');
  if (!offset) {
    el.innerHTML = `<h2>${esc(b)} <span class="muted" style="font-weight:400">${d.total != null ? fmtN(d.total) + (d.capped ? '+' : '') + ' lines' : ''}, in time order</span></h2>
      <div class="hitgroup" id="tlRows">${rowsHtml}</div><div class="more" id="tlMoreBox"></div>`;
  } else {
    $('#tlRows').insertAdjacentHTML('beforeend', rowsHtml);
  }
  $$('#tlRows .hit').forEach(h => h.onclick = () => openViewer(+h.dataset.fid, +h.dataset.line));
  $('#tlMoreBox').innerHTML = d.results.length === 300 ? '<button class="btn" id="tlMore">Load 300 more</button>' : '';
  if ($('#tlMore')) $('#tlMore').onclick = () => loadSlice(b, offset + 300);
}

/* ---------------------------------------------------------------- graph --- */
const G = { types: new Set(['ipv4', 'ipv6', 'domain', 'url', 'email', 'md5', 'sha1', 'sha256', 'user', 'cve']), minFiles: 2, limit: 120, focus: null, cy: null };
async function renderGraph() {
  const el = $('#v-graph');
  if (!window.cytoscape) {
    el.innerHTML = `<div class="panel empty"><h2>The graph library didn't load</h2>
      <p>It comes from cdnjs. For offline machines, download <code>cytoscape.min.js</code> (3.x) into <code>static/vendor/</code> and reload.</p></div>`;
    return;
  }
  el.innerHTML = `
    <div class="row" style="margin-bottom:6px"><h1 style="margin:0">Connections</h1><span class="grow"></span>
      ${G.focus ? '<button class="btn small" id="gAll">Back to overview graph</button>' : ''}
      <label class="muted row" style="gap:6px;font-size:13.5px">Shared by at least <input class="input" id="gMin" type="number" min="1" value="${G.minFiles}" style="width:60px"> files</label>
      <label class="muted row" style="gap:6px;font-size:13.5px">Max entities <input class="input" id="gLim" type="number" min="5" max="1000" value="${G.limit}" style="width:74px"></label>
      <button class="btn small" id="gRelayout">Re-arrange</button></div>
    <div class="chips" id="gTypes" style="margin-bottom:4px">${Object.keys(ENTITY).map(t => `<button class="chip" data-t="${t}" aria-pressed="${G.types.has(t)}"><span style="color:${eColor(t)}">●</span> ${esc(eLabel(t))}</button>`).join('')}</div>
    <div class="legend"><span><i class="sq"></i>File (border = worst finding)</span><span>Circles are entities, sized by how many files share them. Click to inspect, double-click an entity to expand around it.</span></div>
    <div class="graph-wrap"><div id="cy"></div><div class="graph-side" id="gSide" hidden></div></div>`;
  $$('#gTypes [data-t]').forEach(b => b.onclick = () => { const t = b.dataset.t; G.types.has(t) ? G.types.delete(t) : G.types.add(t); b.setAttribute('aria-pressed', G.types.has(t)); loadGraph(); });
  $('#gMin').onchange = e => { G.minFiles = Math.max(1, +e.target.value || 1); loadGraph(); };
  $('#gLim').onchange = e => { G.limit = Math.max(5, +e.target.value || 120); loadGraph(); };
  $('#gRelayout').onclick = () => G.cy && runLayout();
  if ($('#gAll')) $('#gAll').onclick = () => { G.focus = null; renderGraph(); };
  loadGraph();
}
function cssVar(n) { return getComputedStyle(document.documentElement).getPropertyValue(n).trim(); }
async function loadGraph() {
  const d = await api('/api/graph?' + qs({ types: [...G.types].join(','), min_files: G.minFiles, limit: G.limit, focus: G.focus }));
  const sevC = { high: cssVar('--high'), medium: cssVar('--medium'), low: cssVar('--low'), info: cssVar('--info') };
  const elements = [];
  for (const f of d.files) elements.push({ data: { id: 'f' + f.id, label: f.name, rel: f.rel, kind: 'file', fid: f.id, border: sevC[f.severity] || cssVar('--faint'), sev: f.severity } });
  for (const e of d.entities) elements.push({ data: { id: 'e' + e.id, label: e.value.length > 30 ? e.value.slice(0, 28) + '…' : e.value, value: e.value, kind: 'entity', eid: e.id, type: e.type, meta: e.meta, files: e.files, color: eColor(e.type), size: 14 + Math.min(40, Math.sqrt(e.files) * 7), focus: G.focus === e.id } });
  for (const x of d.edges) elements.push({ data: { id: `x${x.entity_id}_${x.file_id}`, source: 'e' + x.entity_id, target: 'f' + x.file_id, w: Math.min(6, 1 + Math.log10(x.hits + 1) * 1.6) } });
  if (G.cy) G.cy.destroy();
  if (!d.entities.length) { $('#cy').innerHTML = '<div class="empty">No entities meet these settings. Lower “shared by at least” or enable more types.</div>'; return; }
  G.cy = cytoscape({
    container: $('#cy'), elements, wheelSensitivity: 0.25, minZoom: 0.08, maxZoom: 4,
    style: [
      { selector: 'node', style: { label: 'data(label)', color: cssVar('--text'), 'font-family': 'JetBrains Mono, monospace', 'font-size': 9, 'text-valign': 'bottom', 'text-margin-y': 4, 'text-outline-color': cssVar('--bg'), 'text-outline-width': 2, 'min-zoomed-font-size': 7 } },
      { selector: 'node[kind="entity"]', style: { 'background-color': 'data(color)', width: 'data(size)', height: 'data(size)', 'border-width': 0 } },
      { selector: 'node[kind="entity"][?focus]', style: { 'border-width': 3, 'border-color': cssVar('--accent') } },
      { selector: 'node[kind="file"]', style: { shape: 'round-rectangle', 'background-color': cssVar('--raised'), 'border-color': 'data(border)', 'border-width': 2.5, width: 22, height: 16, color: cssVar('--muted') } },
      { selector: 'edge', style: { width: 'data(w)', 'line-color': cssVar('--line'), 'curve-style': 'haystack', opacity: .8 } },
      { selector: '.dim', style: { opacity: .12 } },
      { selector: 'node:selected', style: { 'border-width': 3, 'border-color': cssVar('--accent') } },
      { selector: 'edge.hl', style: { 'line-color': cssVar('--accent'), opacity: 1 } },
    ],
  });
  runLayout();
  G.cy.on('tap', 'node', ev => graphSelect(ev.target));
  G.cy.on('tap', ev => { if (ev.target === G.cy) { G.cy.elements().removeClass('dim hl'); $('#gSide').hidden = true; } });
  G.cy.on('dbltap', 'node[kind="entity"]', ev => { G.focus = ev.target.data('eid'); renderGraph(); });
  G.cy.on('dbltap', 'node[kind="file"]', ev => openViewer(ev.target.data('fid'), 1));
}
function runLayout() {
  const n = G.cy.nodes().length;
  G.cy.layout({ name: 'cose', animate: n < 250, animationDuration: 500, nodeRepulsion: () => 9000, idealEdgeLength: () => 70, gravity: 0.3, numIter: 1500, padding: 30, randomize: true }).run();
}
function graphSelect(node) {
  const cy = G.cy, hood = node.closedNeighborhood();
  cy.elements().addClass('dim').removeClass('hl'); hood.removeClass('dim'); node.connectedEdges().addClass('hl');
  const side = $('#gSide'); side.hidden = false;
  const d = node.data();
  if (d.kind === 'file') {
    const ents = node.neighborhood('node').map(n => n.data());
    side.innerHTML = `<div class="panel"><div class="mono" style="word-break:break-all;font-size:13px;margin-bottom:8px">${esc(d.rel)}</div>
      ${d.sev ? `<p style="margin:0 0 8px">Worst finding: ${sevTag(d.sev)}</p>` : ''}
      <button class="btn small primary" id="gsOpen">Open file</button>
      <p class="muted" style="margin:12px 0 6px;font-size:13px">${ents.length} connected entities</p>
      <div class="list">${ents.slice(0, 40).map(e => `<div class="item" data-ge="${e.id}" style="grid-template-columns:auto 1fr">${etag(e.type)}<span class="v">${esc(e.value)}</span></div>`).join('')}</div></div>`;
    $('#gsOpen').onclick = () => openViewer(d.fid, 1);
  } else {
    const files = node.neighborhood('node').map(n => n.data());
    side.innerHTML = `<div class="panel"><div class="row" style="margin-bottom:6px">${etag(d.type)} ${d.meta ? `<span class="meta-tag ${esc(d.meta)}">${esc(d.meta)}</span>` : ''}</div>
      <div class="mono" style="word-break:break-all;margin-bottom:10px">${esc(d.value)}</div>
      <div class="row" style="margin-bottom:10px"><button class="btn small primary" id="gsExpand">Expand</button><button class="btn small" id="gsSearch">Search</button><button class="btn small" id="gsEnt">Details</button></div>
      <p class="muted" style="margin:0 0 6px;font-size:13px">In ${fmtN(d.files)} files</p>
      <div class="list">${files.slice(0, 40).map(f => `<div class="item" data-gf="${f.fid}" style="grid-template-columns:1fr"><span class="v" title="${esc(f.rel)}">${esc(f.rel)}</span></div>`).join('')}</div></div>`;
    $('#gsExpand').onclick = () => { G.focus = d.eid; renderGraph(); };
    $('#gsSearch').onclick = () => searchFor(d.value);
    $('#gsEnt').onclick = () => { ES.selected = d.eid; show('entities', { refresh: true }); };
    $$('[data-gf]', side).forEach(r => r.onclick = () => openViewer(+r.dataset.gf, 1, { q: d.value, mode: 'substring' }));
  }
  $$('[data-ge]', side).forEach(r => r.onclick = () => graphSelect(G.cy.$id(r.dataset.ge)));
}

/* ---------------------------------------------------------------- board --- */
async function renderBoard() {
  const el = $('#v-board');
  const d = await api('/api/pins');
  $('#cPins').textContent = d.pins.length || '';
  el.innerHTML = `
    <div class="row" style="margin-bottom:6px"><h1 style="margin:0">Evidence board</h1><span class="grow"></span>
      ${d.pins.length ? '<button class="btn small" id="bMd">Export Markdown</button><button class="btn small" id="bCsv">Export CSV</button>' : ''}</div>
    <p class="sub">Lines you pinned from the file viewer, with your notes. Pins survive re-indexing.</p>
    ${d.pins.length ? d.pins.map(p => `
      <div class="pin-card" data-pid="${p.id}">
        <div class="row"><span class="mono" style="font-size:13px;cursor:pointer" data-open="${p.file_id || ''}" data-line="${p.line_no}">${esc(p.rel)}<span class="faint">:${p.line_no}</span></span>
          <span class="grow"></span><span class="faint" style="font-size:12.5px">${esc(p.created.replace('T', ' '))}</span>
          <button class="btn small ghost danger" data-del="${p.id}">Remove</button></div>
        <code>${esc(p.text)}</code>
        <textarea data-note="${p.id}" placeholder="Why this matters">${esc(p.note)}</textarea>
      </div>`).join('') : '<div class="empty"><h2>Nothing pinned yet</h2><p>Open any file, hover a line and click its line number to pin it here.</p></div>'}`;
  $$('[data-open]', el).forEach(x => x.onclick = () => x.dataset.open ? openViewer(+x.dataset.open, +x.dataset.line) : toast('That file is no longer in the index', true));
  $$('[data-del]', el).forEach(x => x.onclick = async () => { await api('/api/pins/' + x.dataset.del, { method: 'DELETE' }); renderBoard(); });
  $$('[data-note]', el).forEach(x => x.onchange = async () => { await post('/api/pins/' + x.dataset.note, { note: x.value }, 'PATCH'); toast('Note saved'); });
  const dl = (name, text, type) => { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([text], { type })); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000); };
  if ($('#bMd')) $('#bMd').onclick = () => dl('evidence-board.md', '# Evidence board\n\n' + d.pins.map(p => `## ${p.rel}:${p.line_no}\n\n${p.note || '_no note_'}\n\n\`\`\`\n${p.text}\n\`\`\`\n\n_Pinned ${p.created}_\n`).join('\n'), 'text/markdown');
  if ($('#bCsv')) $('#bCsv').onclick = () => {
    const c = v => '"' + String(v ?? '').replace(/"/g, '""') + '"';
    dl('evidence-board.csv', 'file,line,note,text,pinned\n' + d.pins.map(p => [p.rel, p.line_no, p.note, p.text, p.created].map(c).join(',')).join('\n'), 'text/csv');
  };
}

/* ---------------------------------------------------------------- index --- */
async function renderIndex() {
  const el = $('#v-index');
  const [st, ov] = await Promise.all([api('/api/index/status'), api('/api/overview')]);
  el.innerHTML = `
    <h1>Index settings</h1>
    <p class="sub">Crumbs keeps everything in one SQLite file. Updating only re-reads files whose size or modified time changed.</p>
    <div class="panel" style="max-width:820px">
      <label class="field" style="margin-bottom:12px">Evidence folder
        <input id="ixRoot" class="mono" value="${esc(st.root_indexed || st.root || '')}" placeholder="/path/to/folder"></label>
      <label class="field" style="margin-bottom:16px;max-width:240px">Skip files larger than (MB)
        <input id="ixMax" type="number" min="1" value="200"></label>
      <div class="row">
        <button class="btn primary" id="ixUpdate">Update index</button>
        <button class="btn" id="ixFull">Rebuild from scratch</button>
        ${st.running ? '<button class="btn danger" id="ixCancel">Stop indexing</button>' : ''}
      </div>
      <p class="faint" style="font-size:12.5px;margin:10px 0 0">
        <b>What a rebuild keeps:</b> your Triage verdicts, confirmed IOCs, evidence-board pins, threat-intel lookups (VirusTotal / Shodan / AbuseIPDB results and API keys) — all of these live in a separate part of the database and are never touched by a rebuild.<br>
        <b>What gets re-read:</b> every file in the evidence folder. Findings, entities, timelines and host facts are rebuilt from scratch from the files.
      </p>
      ${st.running ? `<div class="progress"><div style="width:${st.progress || 0}%"></div></div>
        <p class="muted mono" style="font-size:12.5px;word-break:break-all">${esc(st.message)}: ${fmtN(st.files_done)} / ${fmtN(st.files_total)} files · ${fmtN(st.lines)} lines · ${esc(st.current || '')}</p>` :
        `<p class="muted">${esc(st.message || '')}</p>`}
      ${st.errors && st.errors.length ? `<h2 style="margin-top:14px">Problems</h2><div class="errors">${st.errors.map(esc).join('<br>')}</div>` : ''}
      <dl class="kv" style="margin-top:18px">
        <dt>Database</dt><dd class="mono">${esc(ov.db_path)} (${fmtB(ov.db_size)})</dd>
        <dt>Search engine</dt><dd>${ov.fts ? 'SQLite FTS5 trigram index (fast substring search)' : 'Full table scan (SQLite older than 3.34, upgrade Python for speed)'}</dd>
        <dt>Last indexed</dt><dd>${esc(ov.last_indexed || 'never')}</dd>
        <dt>File states</dt><dd>${ov.files_by_status.map(s => `${esc(s.status)}: ${fmtN(s.n)}`).join(', ') || '–'}</dd>
      </dl>
    </div>`;
  $('#ixUpdate').onclick = () => startIndex($('#ixRoot').value, false, +$('#ixMax').value);
  $('#ixFull').onclick = () => { if (confirm('Re-read every file from scratch?\n\nYour Triage verdicts, IOCs, threat-intel lookups and API keys are kept.\nFindings, entities and timelines are rebuilt from the files.')) startIndex($('#ixRoot').value, true, +$('#ixMax').value); };
  if ($('#ixCancel')) $('#ixCancel').onclick = async () => { await post('/api/index/cancel'); toast('Stopping after the current file'); };
}
async function startIndex(root, full, max_mb) {
  try { await post('/api/index', { root: root.trim(), full, max_mb }); toast('Indexing started'); pollStatus(true); if (current === 'index') renderIndex(); }
  catch (e) { toast(e.message, true); }
}
let pollTimer;
async function pollStatus(soon) {
  clearTimeout(pollTimer);
  let st;
  try { st = await api('/api/index/status'); } catch (e) { pollTimer = setTimeout(pollStatus, 5000); return; }
  const dot = $('#indexChip .dot'), txt = $('#indexText');
  if (st.running) {
    dot.className = 'dot run';
    txt.textContent = `Indexing ${st.progress != null ? st.progress + '%' : ''} ${st.current ? '· ' + st.current : ''}`;
    if (current === 'index') renderIndex();
  } else {
    dot.className = 'dot' + (st.last_indexed ? ' ok' : '');
    txt.textContent = st.last_indexed ? `Indexed ${ago(st.last_indexed)}` : 'Not indexed';
    if (lastStatus && lastStatus.running) {
      toast(st.message || 'Indexing finished');
      Object.keys(loaded).forEach(k => delete loaded[k]);
      show(current || 'overview', { refresh: true });
    }
  }
  lastStatus = st;
  pollTimer = setTimeout(pollStatus, st.running || soon ? 1500 : 15000);
}
$('#indexChip').onclick = () => show('index', { refresh: true });

/* --------------------------------------------------------------- viewer --- */
const V = { fid: null, file: null, lo: 0, hi: 0, target: null, find: { q: '', mode: 'substring', hits: [], idx: -1 }, busy: false, side: 'f', data: null };
const WINDOW = 400;

async function openViewer(fid, line = 1, find = null) {
  let d;
  try { d = await api('/api/file/' + fid); } catch (e) { toast(e.message, true); return; }
  V.fid = fid; V.data = d; V.file = d.file; V.target = line;
  V.lineN = null; V.lineData = null; if (V.side === 'l') V.side = 'f';
  $('#viewer').hidden = false; $('#scrim').hidden = false;
  const f = d.file;
  $('#vPath').textContent = f.rel; $('#vPath').title = f.path;
  $('#vMeta').innerHTML = `<span>${fmtB(f.size)}</span><span>${fmtN(f.line_count)} lines</span><span>${esc(f.encoding || '')}</span>
    ${f.sha256 ? `<span>SHA-256 <button id="vSha" title="Copy hash">${esc(f.sha256.slice(0, 16))}…</button></span>` : ''}
    ${f.note ? `<span>${esc(f.note)}</span>` : ''}${f.status !== 'ok' ? `<span style="color:var(--medium)">${esc(f.status)}</span>` : ''}`;
  if ($('#vSha')) $('#vSha').onclick = () => navigator.clipboard.writeText(f.sha256).then(() => toast('SHA-256 copied'));
  $('#vRaw').href = `/api/file/${fid}/raw`;
  V.find = { q: '', mode: 'substring', hits: [], idx: -1 };
  $('#vFind').value = ''; $('#vFindInfo').textContent = '';
  drawSide();
  if (!f.line_count) {
    $('#vCode').innerHTML = f.status === 'archive'
      ? `<div class="empty">${esc(f.note || 'Archive')}.<br>Its files are listed under <b class="mono">${esc(f.rel)}!/</b> in Files, and are searchable like any other file.</div>`
      : `<div class="empty">This file was not indexed (${esc(f.status)}${f.note ? ': ' + esc(f.note) : ''}). You can still download the original.</div>`;
    return;
  }
  await loadWindow(line);
  if (find && find.q) { $('#vFind').value = find.q; V.find.mode = find.mode; await runFind(line); }
}
function closeViewer() { $('#viewer').hidden = true; $('#scrim').hidden = true; V.fid = null; }
$('#vClose').onclick = closeViewer;
$('#scrim').onclick = closeViewer;

function tmCell(l) {
  if (!l.ts) return '<span class="tm"></span>';
  const short = l.ts.slice(5, 19);
  if (l.back) return `<span class="tm back" title="Written ${esc(l.ts)}: ${esc(l.back.label)} earlier than the lines above it (they reach ${esc(l.back.latest)}). Inserted, edited, or written after a clock change.">⟲ ${esc(short)}</span>`;
  return `<span class="tm" title="Written ${esc(l.ts)}">${esc(short)}</span>`;
}
function chipsHtml(times) {
  if (!times || !times.length) return '';
  return '<span class="tchips">' + times.map(x => {
    const lab = x.role === 'set' ? (x.ts ? 'claims ' + x.ts : 'copies times') : x.role === 'previous' ? 'original ' + x.ts
      : `${x.raw.length > 22 ? x.raw.slice(0, 20) + '…' : x.raw} → ${x.ts}`;
    return `<span class="tchip ${x.role}" title="${esc(x.kind)}${x.raw ? ': ' + esc(x.raw) : ''}">${esc(lab)}</span>`;
  }).join('') + '</span>';
}
function lineHtml(l, marks) {
  const m = marks[l.n];
  const live = m ? m.filter(x => x.verdict !== 'fp') : null;
  const worst = live && live.length ? live.map(x => x.severity).sort((a, b) => ['high', 'medium', 'low', 'info'].indexOf(a) - ['high', 'medium', 'low', 'info'].indexOf(b))[0] : null;
  const spans = V.find.q ? findSpans(l.text, V.find.q, V.find.mode) : [];
  const gap = l.gap ? `<div class="gapsep">⋯ ${esc(l.gap.label)} with no entries, ${esc(l.gap.from)} to ${esc(l.ts)}</div>` : '';
  const epPrev = V.lastEp; V.lastEp = l.ep || null;
  const epSep = l.ep && l.ep !== epPrev ? `<div class="epsep" data-epjump="${l.ep}" title="Click to open episode details">▼ Episode #${l.ep}: ${esc(l.ep_title)} starts here — <span style="text-decoration:underline">click to investigate</span></div>` : '';
  const epEnd = !l.ep && epPrev ? `<div class="epsep end" data-epjump="${epPrev}" title="Click to open episode details">▲ End of episode #${epPrev} — <span style="text-decoration:underline">click to investigate</span></div>` : '';
  return `${epEnd}${gap}${epSep}<div class="l${l.n === V.target ? ' target' : ''}${l.n === V.lineN ? ' picked' : ''}${l.ep ? ' ep' : ''}" data-n="${l.n}"${l.ep ? ` title="Episode #${l.ep}: ${esc(l.ep_title)}"` : ''}>
    <span class="m">${worst ? `<i class="${worst}" title="${esc(m.map(x => x.rule).join(', '))}"></i>` : ''}</span>
    <span class="g" title="Pin this line">${l.n}</span>${tmCell(l)}<span class="tx">${l.ep ? `<span class="eptag" data-epjump="${l.ep}" title="EP#${l.ep}: ${esc(l.ep_title)} — click to open episode details">EP#${l.ep}</span>` : ''}<span class="t">${markSpans(l.text, spans)}</span>${chipsHtml(l.times)}</span></div>`;
}
async function fetchLines(start, count) {
  return api(`/api/file/${V.fid}/lines?start=${start}&count=${count}`);
}
async function loadWindow(center) {
  const start = Math.max(1, center - Math.floor(WINDOW / 3));
  const d = await fetchLines(start, WINDOW);
  const code = $('#vCode');
  V.lo = d.lines.length ? d.lines[0].n : start; V.hi = d.lines.length ? d.lines[d.lines.length - 1].n : start - 1;
  V.lastEp = null;
  code.innerHTML = edgeTop() + d.lines.map(l => lineHtml(l, d.marks)).join('') + edgeBottom();
  scrollToLine(center, false);
}
const edgeTop = () => `<div class="edge" id="edgeTop">${V.lo > 1 ? `Lines 1–${V.lo - 1} load as you scroll up` : 'Start of file'}</div>`;
const edgeBottom = () => `<div class="edge" id="edgeBot">${V.hi < V.file.line_count ? `${fmtN(V.file.line_count - V.hi)} more lines below` : 'End of file'}</div>`;
function scrollToLine(n, flash = true) {
  const row = $(`#vCode .l[data-n="${n}"]`);
  if (!row) return;
  $$('#vCode .l.target').forEach(r => r.classList.remove('target'));
  row.classList.add('target'); V.target = n;
  const code = $('#vCode');
  code.scrollTop = row.offsetTop - code.clientHeight / 3;
  if (flash) { row.classList.remove('flash'); void row.offsetWidth; row.classList.add('flash'); }
}
async function gotoLine(n) {
  if (!V.fid) return;
  n = Math.max(1, Math.min(n, V.file.line_count || 1));
  if (n >= V.lo && n <= V.hi) scrollToLine(n); else { V.target = n; await loadWindow(n); scrollToLine(n); }
}
$('#vCode').addEventListener('scroll', async () => {
  const c = $('#vCode');
  if (V.busy || !V.fid) return;
  if (c.scrollTop < 300 && V.lo > 1) {
    V.busy = true;
    const start = Math.max(1, V.lo - 300);
    const d = await fetchLines(start, V.lo - start);
    const before = c.scrollHeight;
    $('#edgeTop').remove();
    const keep = V.lastEp; V.lastEp = null;
    c.insertAdjacentHTML('afterbegin', d.lines.map(l => lineHtml(l, d.marks)).join(''));
    V.lastEp = keep;
    V.lo = start;
    c.insertAdjacentHTML('afterbegin', edgeTop());
    c.scrollTop += c.scrollHeight - before;
    V.busy = false;
  } else if (c.scrollHeight - c.scrollTop - c.clientHeight < 400 && V.hi < V.file.line_count) {
    V.busy = true;
    const d = await fetchLines(V.hi + 1, 300);
    $('#edgeBot').remove();
    c.insertAdjacentHTML('beforeend', d.lines.map(l => lineHtml(l, d.marks)).join(''));
    if (d.lines.length) V.hi = d.lines[d.lines.length - 1].n; else V.hi = V.file.line_count;
    c.insertAdjacentHTML('beforeend', edgeBottom());
    V.busy = false;
  }
});
$('#vCode').addEventListener('click', async e => {
  const ep = e.target.closest('[data-epjump]');
  if (ep) { e.stopPropagation(); closeViewer(); jumpToEpisode(+ep.dataset.epjump); return; }  const g = e.target.closest('.g');
  if (!g) {
    const row = e.target.closest('.l');
    if (row && !String(window.getSelection() || '')) openLine(+row.dataset.n);
    return;
  }
  const n = +g.textContent;
  const note = prompt(`Pin line ${n} to the evidence board. Add a note (optional):`, '');
  if (note === null) return;
  try { await post('/api/pins', { file_id: V.fid, line: n, note }); toast(`Pinned line ${n}`); $('#cPins').textContent = (+$('#cPins').textContent || 0) + 1; }
  catch (err) { toast(err.message, true); }
});
$('#vGoto').addEventListener('keydown', e => { if (e.key === 'Enter' && e.target.value) gotoLine(+e.target.value); });
$('#vTimes').onclick = () => { const off = $('#vCode').classList.toggle('notime'); $('#vTimes').setAttribute('aria-pressed', !off); };
$('#vWrap').onclick = () => { const w = $('#vCode').classList.toggle('wrap'); $('#vWrap').setAttribute('aria-pressed', w); };

async function runFind(near) {
  const q = $('#vFind').value;
  V.find.q = q; V.find.hits = []; V.find.idx = -1;
  rehighlight();
  if (!q) { $('#vFindInfo').textContent = ''; return; }
  let d;
  try { d = await api('/api/search?' + qs({ q, mode: V.find.mode, file_id: V.fid, limit: 1000, facets: 0 })); }
  catch (e) { $('#vFindInfo').textContent = e.message; return; }
  V.find.hits = d.results.map(r => r.line);
  if (!V.find.hits.length) { $('#vFindInfo').textContent = 'No matches'; return; }
  const from = near || V.target || 1;
  V.find.idx = Math.max(0, V.find.hits.findIndex(n => n >= from));
  updateFindInfo();
  gotoLine(V.find.hits[V.find.idx]);
}
function updateFindInfo() {
  const h = V.find.hits;
  $('#vFindInfo').textContent = h.length ? `${V.find.idx + 1} of ${h.length}${h.length === 1000 ? '+' : ''}` : '';
}
function stepFind(dir) {
  const h = V.find.hits; if (!h.length) return;
  V.find.idx = (V.find.idx + dir + h.length) % h.length;
  updateFindInfo(); gotoLine(h[V.find.idx]);
}
function rehighlight() {
  $$('#vCode .l').forEach(row => {
    const t = $('.t', row);
    const text = t.textContent;
    t.innerHTML = markSpans(text, V.find.q ? findSpans(text, V.find.q, V.find.mode) : []);
  });
}
$('#vFind').addEventListener('keydown', e => {
  if (e.key !== 'Enter') return;
  e.preventDefault();
  if (V.find.q === e.target.value && V.find.hits.length) stepFind(e.shiftKey ? -1 : 1);
  else { V.find.mode = S.mode; runFind(V.target); }
});
$('#vNext').onclick = () => stepFind(1);
$('#vPrev').onclick = () => stepFind(-1);

function drawSide() {
  const d = V.data;
  $('#tabF').textContent = `Findings (${d.findings.length})`;
  $('#tabE').textContent = `Entities (${d.entities.length})`;
  $('#tabF').setAttribute('aria-selected', V.side === 'f');
  $('#tabE').setAttribute('aria-selected', V.side === 'e');
  $('#tabI').setAttribute('aria-selected', V.side === 'i');
  $('#tabL').setAttribute('aria-selected', V.side === 'l');
  const box = $('#vSide');
  if (V.side === 'i') { box.innerHTML = integrityHtml(d); bindIntegrity(box); return; }
  if (V.side === 'l') { box.innerHTML = lineDetailHtml(); bindLineDetail(box); return; }
  if (V.side === 'f') {
    box.innerHTML = d.findings.length ? d.findings.map(x => `
      <div class="sitem" data-l="${x.line_no || 1}"><div class="row" style="gap:8px">${sevTag(x.severity)}<span class="faint mono" style="font-size:12px">${x.line_no ? 'line ' + x.line_no : 'whole file'}${x.ts ? ' · ' + esc(x.ts) : ''}</span></div>
      <div>${esc(x.description)} ${vchip(x.verdict)}</div><div class="s" style="${x.verdict === 'fp' ? 'opacity:.5' : ''}">${esc(x.snippet)}</div>
      <button class="btn small ghost" data-judge="${x.id}" style="margin-top:4px">Judge in Triage</button></div>`).join('') : '<div class="empty">No rules matched in this file.</div>';
  } else {
    box.innerHTML = d.entities.length ? d.entities.map(e => `
      <div class="sitem" data-l="${e.first_line}" data-q="${esc(e.value)}"><div class="row" style="gap:8px">${etag(e.type)}<span class="faint" style="font-size:12px">${fmtN(e.hits)} here · ${fmtN(e.files)} files</span>
        <span class="grow"></span><button class="btn small ghost" data-pivot="${e.id}" title="Open entity details">Pivot</button></div>
      <div class="v">${esc(e.value)}</div></div>`).join('') : '<div class="empty">No entities found in this file.</div>';
  }
  $$('.sitem', box).forEach(s => s.onclick = ev => {
    if (ev.target.dataset.pivot) { closeViewer(); ES.selected = +ev.target.dataset.pivot; show('entities', { refresh: true }); return; }
    if (ev.target.dataset.judge) { closeViewer(); judgeFinding(+ev.target.dataset.judge); return; }
    if (s.dataset.q) { $('#vFind').value = s.dataset.q; V.find.mode = 'substring'; runFind(+s.dataset.l); }
    else gotoLine(+s.dataset.l);
  });
}
$('#tabF').onclick = () => { V.side = 'f'; drawSide(); };
$('#tabE').onclick = () => { V.side = 'e'; drawSide(); };
$('#tabI').onclick = () => { V.side = 'i'; drawSide(); };
$('#tabL').onclick = () => { V.side = 'l'; drawSide(); };

function searchEpisode(n) {
  $('#q').value = `ep:${n}`; setMode('query'); doSearch();
}
function jumpToEpisode(n) {
  show('host', { refresh: true });
  // Wait for the host view to render, then scroll to the episode card
  const attempt = (tries) => {
    const card = [...$$('.eptag.big')].find(el => el.textContent.trim() === `EP#${n}`);
    if (card) {
      card.closest('.epcard').scrollIntoView({ behavior: 'smooth', block: 'start' });
      card.closest('.epcard').classList.add('ep-highlight');
      setTimeout(() => card.closest('.epcard')?.classList.remove('ep-highlight'), 2000);
    } else if (tries > 0) {
      setTimeout(() => attempt(tries - 1), 300);
    }
  };
  setTimeout(() => attempt(8), 200);
}
function windowSearch(a, b) {
  $('#fFrom').value = a.replace(' ', 'T').slice(0, 16); $('#fTo').value = b.replace(' ', 'T').slice(0, 16);
  $('#filters').hidden = false; $('#filtersBtn').setAttribute('aria-expanded', true);
  $('#q').value = ''; doSearch();
}
function aroundTime(ts, minutes) {
  const t = Date.parse(ts.replace(' ', 'T') + 'Z');
  const f = d => new Date(d).toISOString().slice(0, 16);
  $('#fFrom').value = f(t - minutes * 60e3); $('#fTo').value = f(t + minutes * 60e3);
  $('#filters').hidden = false; $('#filtersBtn').setAttribute('aria-expanded', true);
  $('#q').value = ''; closeViewer(); doSearch();
  toast(`Every timed line from all files within ${minutes} minutes of ${ts}, in time order`);
}
async function openLine(n) {
  V.lineN = n;
  $$('#vCode .l.picked').forEach(r => r.classList.remove('picked'));
  const row = $(`#vCode .l[data-n="${n}"]`); if (row) row.classList.add('picked');
  V.side = 'l'; V.lineData = null; drawSide();
  try { V.lineData = await api(`/api/line?file_id=${V.fid}&n=${n}`); } catch (e) { toast(e.message, true); return; }
  if (V.lineN === n && V.side === 'l') drawSide();
}
const ROLE_LABEL = { line: 'written', set: 'claimed', previous: 'original', decoded: 'decoded', written: 'mentioned' };
function timesHtml(times) {
  if (!times.length) return '<div class="faint">No times on this line.</div>';
  return times.map(x => `<div class="trow"><span class="role ${x.role}">${ROLE_LABEL[x.role]}</span>
    <span class="mono">${esc(x.ts || '—')}</span><div class="k">${esc(x.kind)}${x.raw && x.raw !== x.ts ? ' · <span class="mono">' + esc(x.raw) + '</span>' : ''}</div></div>`).join('');
}
function decodedHtml(list) {
  if (!list.length) return '<div class="faint">No encoded or obfuscated content recognised.</div>';
  return list.map((x, i) => `<div class="dec"><div class="row" style="gap:6px"><b style="font-weight:600;font-size:12.5px">${esc(x.method)}</b><span class="grow"></span>
    <button class="btn small ghost" data-copy="${i}">Copy</button>${V.lineData ? `<button class="btn small ghost" data-pinfrom="${i}">Pin</button>` : ''}</div>
    <div class="faint mono" style="font-size:11.5px;overflow-wrap:anywhere">${esc(x.input)}</div><pre>${esc(x.output)}</pre></div>`).join('');
}
function lineDetailHtml() {
  const L = V.lineData;
  if (!V.lineN) return '<div class="empty">Click any line to see when it was written, every time it mentions, and what its encoded parts decode to.</div>';
  if (!L) return '<div class="empty">Loading line…</div>';
  let order = '';
  if (L.back) order = `<div class="warnbox">Dated <b>${esc(L.back.label)}</b> earlier than the lines above it, which already reach ${esc(L.back.latest)}. It was inserted, edited in, or written after a clock change.</div>`;
  else if (L.gap) order = `<div class="warnbox">Comes after <b>${esc(L.gap.label)}</b> with no entries (since ${esc(L.gap.from)}). Entries may have been removed here.</div>`;
  const nav = (x, label) => x ? `<button class="btn small ghost" data-il="${x.n}">${label} ${x.n}</button> <span class="mono faint" style="font-size:12px">${esc(x.ts)}</span>` : '';
  const claimed = L.times.filter(t => t.role === 'set'), orig = L.times.filter(t => t.role === 'previous');
  const eps = (L.episodes || []).map(e => `<div class="epbox"><div class="row" style="gap:6px;flex-wrap:wrap;align-items:baseline">
    <span class="eptag" style="cursor:pointer" data-epjump="${e.n}">EP#${e.n}</span><b>${esc(e.title)}</b></div>
    <span class="mono faint" style="font-size:12px">${esc(e.start)} → ${esc(e.end)}</span>${e.in_file ? '' : '<br><span class="faint">(this file is not one of the episode sources; the time overlaps)</span>'}
    <div class="row" style="gap:6px;margin-top:6px">
      <button class="btn small" data-epq="${e.n}">All tagged lines</button>
      <button class="btn small" data-epall="${e.n}">Everything in this window</button>
      <button class="btn small primary" data-epjump="${e.n}">↗ Episode details</button></div></div>`).join('');
  const summary = claimed.length ? `<div class="claimline" style="margin-top:6px">Real time of the action: <b class="real">${esc(L.ts || 'unknown')}</b><br>
    Time it tries to plant: ${claimed.map(c => `<b class="fake">${esc(c.ts || c.kind)}</b>`).join(', ')}${orig.length ? `<br>Original value it overwrote: ${orig.map(c => `<b class="real">${esc(c.ts)}</b>`).join(', ')}` : ''}</div>` : '';
  return `<div class="isec"><h3>Line ${L.n}</h3>
      <div>Written <span class="mono">${esc(L.ts || 'no time on this line')}</span></div>${order}${eps}${summary}
      <div style="margin-top:8px;display:flex;flex-direction:column;gap:3px">${nav(L.prev, 'Previous timed line')}${nav(L.next, 'Next timed line')}</div>
      ${L.ts ? `<div class="row" style="margin-top:8px;gap:6px;flex-wrap:wrap"><span class="faint" style="font-size:12.5px">Everything, all files:</span>
        <button class="btn small" data-around="5">±5 min</button><button class="btn small" data-around="30">±30 min</button>
        <button class="btn small" data-around="120">±2 h</button></div>` : ''}</div>
    <div class="isec"><h3>Times on this line</h3>${timesHtml(L.times)}
      <div class="faint" style="font-size:12px;margin-top:6px"><b>Written</b> is when the entry was logged. <b>Claimed</b> is a time a command
      writes onto a file or clock (the fake one). <b>Original</b> is the value before the change. <b>Decoded</b> numbers are shown in UTC.</div></div>
    <div class="isec"><h3>Decoded content</h3>${decodedHtml(L.decoded)}</div>
    ${L.findings.length ? `<div class="isec"><h3>Rules on this line</h3>${L.findings.map(x => `<div style="margin-bottom:6px">${sevTag(x.severity)} ${esc(x.description)}</div>`).join('')}</div>` : ''}
    <div class="isec"><h3>Decode other text</h3><textarea id="decodeBox" spellcheck="false" placeholder="Paste anything: base64, hex, char codes, a script…"></textarea>
      <div class="row" style="margin-top:6px"><button class="btn small" id="decodeBtn">Decode</button></div><div id="decodeOut" style="margin-top:8px"></div></div>`;
}
function bindLineDetail(box) {
  const L = V.lineData;
  $$('[data-il]', box).forEach(b => b.onclick = () => { gotoLine(+b.dataset.il); openLine(+b.dataset.il); });
  $$('[data-around]', box).forEach(b => b.onclick = () => aroundTime(L.ts, +b.dataset.around));
  $$('[data-epq]', box).forEach(b => b.onclick = () => { closeViewer(); searchEpisode(+b.dataset.epq); });
  $$('[data-epall]', box).forEach(b => b.onclick = () => { const e = L.episodes.find(x => x.n === +b.dataset.epall); closeViewer(); windowSearch(e.start, e.end); });
  $$('[data-epjump]', box).forEach(b => b.onclick = () => { closeViewer(); jumpToEpisode(+b.dataset.epjump); });
  $$('[data-ephost]', box).forEach(b => b.onclick = () => { closeViewer(); show('host', { refresh: true }); setTimeout(() => $('#h-dos')?.scrollIntoView({ block: 'start' }), 400); });
  const bindDec = (root, list) => {
    $$('[data-copy]', root).forEach(b => b.onclick = () => navigator.clipboard.writeText(list[+b.dataset.copy].output).then(() => toast('Copied')));
    $$('[data-pinfrom]', root).forEach(b => b.onclick = async () => {
      const x = list[+b.dataset.pinfrom];
      try { await post('/api/pins', { file_id: V.fid, line: L.n, note: `Decoded (${x.method}): ${x.output.slice(0, 1500)}` }); toast(`Pinned line ${L.n} with the decoded text`);
        $('#cPins').textContent = (+$('#cPins').textContent || 0) + 1; } catch (e) { toast(e.message, true); }
    });
  };
  if (L) bindDec(box, L.decoded);
  const btn = $('#decodeBtn', box);
  if (btn) btn.onclick = async () => {
    const text = $('#decodeBox', box).value;
    if (!text.trim()) return;
    try {
      const d = await post('/api/decode', { text });
      const out = $('#decodeOut', box);
      out.innerHTML = decodedHtml(d.decoded).replace(/<button class="btn small ghost" data-pinfrom="\d+">Pin<\/button>/g, '') +
        (d.times.length ? '<h3 style="margin-top:8px">Times found</h3>' + timesHtml(d.times) : '');
      bindDec(out, d.decoded);
    } catch (e) { toast(e.message, true); }
  };
}

function integrityHtml(d) {
  const f = d.file, g = f.integrity || {};
  const row = (k, v) => v ? `<dt>${k}</dt><dd>${v}</dd>` : '';
  const ent = f.entropy;
  const lineBtn = (n, label) => `<button class="btn small ghost" data-il="${n}" style="height:auto;padding:1px 6px;font-family:var(--mono);font-size:12px">${label}</button>`;
  let h = `<div class="isec"><h3>Filesystem times (UTC)</h3><dl class="kv">
    ${row('Modified', esc(f.mtime_ts))}${row(f.ctime_kind === 'creation' ? 'Created' : 'Changed', esc(f.ctime_ts))}
    ${row('Born', esc(f.birth_ts))}${row('Accessed', esc(f.atime_ts) + ' <span class="faint">(unreliable)</span>')}${row('Inode', f.inode)}</dl></div>
    <div class="isec"><h3>Content</h3><dl class="kv">${row('Type', esc(f.magic || (f.kind === 'text' ? 'text' : f.kind)))}
    ${row('Encoding', esc(f.encoding))}${row('NUL bytes', f.nul_bytes ? fmtN(f.nul_bytes) : '')}${row('SHA-256', `<span style="word-break:break-all">${esc(f.sha256 || '')}</span>`)}</dl>
    ${ent != null ? `<div style="font-size:12.5px;margin-top:6px">Entropy ${ent.toFixed(2)} bits/byte ${ent > 7.2 ? '<b style="color:var(--high)">random-looking</b>' : ''}
      <div class="meter ${ent > 7.2 ? 'hot' : ''}"><div style="width:${(ent / 8 * 100).toFixed(0)}%"></div></div></div>` : ''}</div>`;
  if (f.first_ts) h += `<div class="isec"><h3>Entries</h3><dl class="kv">${row('First', esc(f.first_ts))}${row('Last', esc(f.last_ts))}
    ${row('Timestamped', fmtN(f.ts_count) + ' lines')}${row('Usual spacing', g.cadence_seconds != null ? g.cadence_seconds + ' s' : '')}
    ${g.interleaved ? row('Order', 'several sources interleaved') : ''}</dl></div>`;
  const list = (title, arr, fn) => arr && arr.length ? `<div class="isec"><h3>${title}</h3>${arr.map(fn).join('')}</div>` : '';
  h += list('Silences', g.gaps, x => `<div style="margin-bottom:5px">${lineBtn(x.line, 'line ' + x.line)} ${esc(x.from)} → ${esc(x.to)}</div>`);
  h += list('Time runs backwards', g.backwards, x => `<div style="margin-bottom:5px">${lineBtn(x.line, 'line ' + x.line)} back to ${esc(x.to)}</div>`);
  h += list('Missing record numbers', g.record_gaps, x => `<div style="margin-bottom:5px" class="mono">${esc(x.kind)} ${x.after} → ${x.before} <span class="faint">(${fmtN(x.missing)} missing)</span></div>`);
  h += list('NUL regions', g.nul_regions, x => `<div style="margin-bottom:5px">${lineBtn(x.line, 'line ' + x.line)} ${fmtN(x.length)} bytes at offset ${fmtN(x.offset)}</div>`);
  if (g.evtx) h += `<div class="isec"><h3>Event log header</h3><dl class="kv">${row('Records read', fmtN(g.evtx.records))}${row('Chunks', fmtN(g.evtx.chunks))}
    ${row('Next record', fmtN(g.evtx.next_record_id))}${row('Closed cleanly', g.evtx.dirty ? '<b style="color:var(--medium)">no</b>' : 'yes')}</dl></div>`;
  const fileLevel = d.findings.filter(x => x.scope !== 'line');
  h += list('File-level signals', fileLevel, x => `<div style="margin-bottom:8px">${sevTag(x.severity)} ${esc(x.description)}<div class="faint mono" style="font-size:12px;overflow-wrap:anywhere">${esc(x.snippet)}</div></div>`);
  return h;
}
function bindIntegrity(box) { $$('[data-il]', box).forEach(b => b.onclick = () => gotoLine(+b.dataset.il)); }

/* ------------------------------------------------------------ tampering --- */
const T = { cats: new Set(), sev: new Set(['high', 'medium', 'low']), zoom: null, data: null, sel: null, limit: 400 };
const tEpoch = s => s ? Date.parse(s.replace(' ', 'T') + 'Z') : null;
const fmtWhen = s => s ? s.slice(0, 19) : '';
function tFiltered() {
  const d = T.data;
  return d.events.filter(e => (!T.cats.size || T.cats.has(e.category)) && T.sev.has(e.severity) &&
    (!T.zoom || (tEpoch(e.ts_end || e.ts) >= T.zoom[0] && tEpoch(e.ts) <= T.zoom[1])));
}
/* ----------------------------------------------------------- login map --- */
const flagOf = cc => cc && /^[A-Z]{2}$/.test(cc) ? String.fromCodePoint(...[...cc].map(c => 0x1F1E6 + c.charCodeAt(0) - 65)) : '🌐';

async function mountLoginMap(host, opts = {}) {
  if (!host) return;
  let d;
  try { d = await api('/api/loginmap'); } catch (e) { host.innerHTML = ''; return; }
  if (!d.total) { host.innerHTML = ''; return; }
  const W = 1000, H = Math.round(W * (d.top - d.bottom) / 360);
  const X = lon => (lon + 180) / 360 * W, Y = lat => (d.top - lat) / (d.top - d.bottom) * H;
  // markers: one per place (addresses in the same city share a marker)
  const groups = {};
  d.points.forEach(p => {
    const k = `${(+p.lat).toFixed(1)},${(+p.lon).toFixed(1)}`;
    (groups[k] = groups[k] || { lat: p.lat, lon: p.lon, items: [] }).items.push(p);
  });
  const G = Object.values(groups).map(g => {
    const ok = g.items.reduce((a, x) => a + x.success, 0), bad = g.items.reduce((a, x) => a + x.failed, 0);
    const x0 = g.items[0];
    return Object.assign(g, { ok, bad, total: ok + bad, place: [x0.city, x0.country].filter(Boolean).join(', ') || 'Unknown',
      cc: x0.cc, hostile: g.items.some(x => x.ioc || (x.intel && x.intel.level === 'malicious')),
      guessed: g.items.some(x => x.guessed), precise: g.items.some(x => x.precise) });
  }).sort((a, b) => (a.ok > 0) - (b.ok > 0) || b.total - a.total);   // failed-only first (big to small), logins on top
  const R = g => Math.min(26, 4 + 2.1 * Math.sqrt(g.total));
  const dots = 'M' + d.dots.map(([lon, lat]) => `${X(lon).toFixed(1)} ${Y(lat).toFixed(1)}h0`).join('M');
  const succ = d.points.filter(p => p.success).length;
  const okPlaces = G.filter(g => g.ok).sort((a, b) => b.ok - a.ok);
  const label = g => g.ok ? `<text class="lmlabel" x="${X(g.lon) + R(g) + 4}" y="${Y(g.lat) + 4}">${esc(g.place)}</text>` : '';

  const svg = `<svg class="lmsvg" viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet" role="img" aria-label="World map of login sources">
    <path d="${dots}" class="lmland"/>
    ${G.map((g, i) => `<g class="lmmark ${g.ok ? 'ok' : 'fail'} ${g.hostile ? 'hostile' : ''}" data-g="${i}" transform="translate(${X(g.lon).toFixed(1)},${Y(g.lat).toFixed(1)})">
      ${g.ok ? `<circle class="lmpulse" r="${R(g)}"/>` : ''}<circle class="lmdot" r="${R(g)}"/>
      ${g.ok ? `<text class="lmnum" y="4">${g.ok}</text>` : ''}</g>`).join('')}
    ${G.slice(0, 40).map(label).join('')}
  </svg>`;

  const geoNote = d.geo.database
    ? `Located offline with <b>${esc(d.geo.database_type || d.geo.database)}</b>.`
    : `Places come from your threat-intel lookups (Shodan city, or AbuseIPDB / VirusTotal country centre). For city-level positions without any lookups, put a free <b>DB-IP City Lite</b> or GeoLite2-City <code>.mmdb</code> file in <code>${esc(d.geo.folder)}</code> and reload.`;
  const ipRow = x => `<div class="lmip">
      <div class="row" style="gap:6px;flex-wrap:wrap;align-items:baseline"><a class="lnk mono" data-q="${esc(x.ip)}"><b>${esc(x.ip)}</b></a>
        ${x.guessed ? '<span class="hflag high">password guessed</span>' : ''}${x.ioc ? '<span class="hflag high">confirmed IOC</span>' : ''}
        ${x.intel && ['malicious', 'suspicious'].includes(x.intel.level) ? `<span class="hflag ${x.intel.level === 'malicious' ? 'high' : 'medium'}">${x.intel.level}</span>` : ''}</div>
      ${x.country ? `<div class="faint" style="font-size:12px">${flagOf(x.cc)} ${esc([x.city, x.country].filter(Boolean).join(', '))}${x.source ? ` · ${esc(x.source)}${x.precise ? '' : ', country level'}` : ''}</div>` : ''}
      <div style="font-size:12.5px;margin-top:3px">${x.success ? `<span class="lmok">✓ ${x.success} login${x.success > 1 ? 's' : ''}</span> as <b>${esc(x.users_ok.join(', '))}</b>` : ''}
        ${x.failed ? `${x.success ? ' · ' : ''}<span class="lmbad">✗ ${x.failed} failed</span>${x.users_tried.length ? ` <span class="faint">(${esc(x.users_tried.slice(0, 6).join(', '))}${x.users_tried.length > 6 ? '…' : ''})</span>` : ''}` : ''}</div>
      <div class="mono faint" style="font-size:11.5px">${esc(x.first || '?')} → ${esc(x.last || '?')}${x.first_success ? ` · first success ${esc(x.first_success)}` : ''}</div>
      ${x.file_id ? `<button class="btn small" data-lmopen="${x.file_id}" data-lmline="${x.line || 1}">${x.success ? 'Open first login' : 'Open first attempt'}</button>` : ''}</div>`;

  const sideDefault = `<div class="faint" style="font-size:13px">Click a marker or a country to see every address, the accounts used and when.</div>
    ${okPlaces.length ? `<h4 style="margin:12px 0 4px">Successful logins from</h4>` + okPlaces.map(g =>
      `<div class="lmplace" data-g="${G.indexOf(g)}">${flagOf(g.cc)} <b>${esc(g.place)}</b> <span class="lmok">${g.ok}✓</span> ${g.bad ? `<span class="lmbad">${g.bad}✗</span>` : ''}</div>`).join('') : ''}`;

  host.innerHTML = `<div class="${opts.panel ? 'panel ' : ''}lmap" ${opts.panel ? 'style="margin-bottom:16px"' : ''}>
    <div class="row" style="align-items:baseline;gap:10px;flex-wrap:wrap;margin-bottom:6px">
      ${opts.panel ? '<h2 style="margin:0">Where logins came from</h2>' : '<h3 style="margin:0">Login sources on the map</h3>'}
      <span class="muted">${fmtN(d.points.length)} address${d.points.length === 1 ? '' : 'es'} placed in ${fmtN(d.countries.length)} countr${d.countries.length === 1 ? 'y' : 'ies'}${succ ? ` · <b class="lmok">${succ} with successful logins</b>` : ''}</span>
      <span class="grow"></span>
      <span class="lmlegend"><i class="ok"></i>logged in <i class="fail"></i>failed only <i class="hostile"></i>IOC / malicious</span></div>
    <div class="lmbody"><div class="lmmapwrap">${svg}<div class="lmtip" hidden></div>
      ${!d.points.length ? `<div class="lmempty">No public login source could be placed yet.${d.unlocated.length ? ' Look them up below, or add an offline database.' : ''}</div>` : ''}</div>
      <div class="lmside" id="lmSide">${sideDefault}</div></div>
    ${d.countries.length ? `<div class="lmcountries">${d.countries.slice(0, 14).map(c => `<div class="lmc" data-cc="${esc(c.cc || '')}" title="${esc(c.country)}">
        <span class="lmflag">${flagOf(c.cc)}</span><span class="lmcn">${esc(c.country)}</span>
        <span class="faint">${c.ips} IP${c.ips > 1 ? 's' : ''}</span>${c.success ? `<span class="lmok">${c.success}✓</span>` : ''}${c.failed ? `<span class="lmbad">${fmtN(c.failed)}✗</span>` : ''}</div>`).join('')}</div>` : ''}
    <div class="lmfoot">
      ${d.internal.length ? `<div><b>Internal network</b> <span class="faint">(not on the map)</span>: ${d.internal.map(x =>
        `<a class="lnk mono" data-q="${esc(x.ip)}">${esc(x.ip)}</a> <span class="faint">${x.success ? x.success + '✓' : ''}${x.failed ? ' ' + x.failed + '✗' : ''}</span>`).join(' · ')}</div>` : ''}
      ${d.unlocated.length ? `<div><b>Not located</b>: ${d.unlocated.slice(0, 12).map(x => `<a class="lnk mono" data-q="${esc(x.ip)}">${esc(x.ip)}</a> <span class="faint">${x.success ? x.success + '✓' : ''}${x.failed ? ' ' + x.failed + '✗' : ''}</span>`).join(' · ')}${d.unlocated.length > 12 ? ' …' : ''}
        <button class="btn small" id="lmLookup">Look up ${d.unlocated.length} with your intel keys</button></div>` : ''}
      <div class="faint" style="font-size:12px">${geoNote}</div></div>
  </div>`;

  const tip = $('.lmtip', host), side = $('#lmSide', host), wrap = $('.lmmapwrap', host);
  const showGroup = list => {
    side.innerHTML = `<button class="btn small ghost" id="lmBack">← all places</button>` + list.map(g =>
      `<h4 style="margin:10px 0 4px">${flagOf(g.cc)} ${esc(g.place)}</h4>` + g.items.map(ipRow).join('')).join('');
    $('#lmBack', side).onclick = () => { side.innerHTML = sideDefault; bindSide(); $$('.lmmark', host).forEach(m => m.classList.remove('sel')); };
    bindSide();
  };
  const bindSide = () => {
    $$('[data-lmopen]', side).forEach(b => b.onclick = () => openViewer(+b.dataset.lmopen, +b.dataset.lmline));
    $$('[data-q]', side).forEach(a => a.onclick = e => { e.stopPropagation(); searchFor(a.dataset.q); });
    $$('.lmplace', side).forEach(r => r.onclick = () => select([+r.dataset.g]));
  };
  const select = idx => {
    $$('.lmmark', host).forEach(m => m.classList.toggle('sel', idx.includes(+m.dataset.g)));
    showGroup(idx.map(i => G[i]));
  };
  $$('.lmmark', host).forEach(m => {
    const g = G[+m.dataset.g];
    m.onmouseenter = () => {
      tip.innerHTML = `${flagOf(g.cc)} <b>${esc(g.place)}</b><br>${g.items.length} address${g.items.length > 1 ? 'es' : ''}`
        + (g.ok ? ` · <span class="lmok">${g.ok} login${g.ok > 1 ? 's' : ''}</span>` : '') + (g.bad ? ` · <span class="lmbad">${fmtN(g.bad)} failed</span>` : '')
        + (g.precise ? '' : '<br><span class="faint">country centre</span>');
      tip.hidden = false;
    };
    m.onmousemove = e => { const r = wrap.getBoundingClientRect(); tip.style.left = (e.clientX - r.left + 14) + 'px'; tip.style.top = (e.clientY - r.top + 10) + 'px'; };
    m.onmouseleave = () => { tip.hidden = true; };
    m.onclick = () => select([+m.dataset.g]);
  });
  $$('.lmc', host).forEach(c => c.onclick = () => select(G.map((g, i) => g.cc === (c.dataset.cc || undefined) || g.cc === c.dataset.cc ? i : -1).filter(i => i >= 0)));
  $$('.lmfoot [data-q]', host).forEach(a => a.onclick = () => searchFor(a.dataset.q));
  bindSide();
  const lk = $('#lmLookup', host);
  if (lk) lk.onclick = async () => {
    lk.disabled = true; lk.textContent = 'Looking up…';
    try {
      const r = await post('/api/intel/bulk', { indicators: d.unlocated.map(x => ({ value: x.ip, type: 'ipv4' })) });
      const any = (r.results || []).some(x => Object.values(x.results || {}).some(v => v && v.ok));
      toast(any ? `Looked up ${r.results.length} address(es)${r.stopped ? ' — ' + r.stopped : ''}` : 'No lookups succeeded: add Shodan, AbuseIPDB or VirusTotal keys in Settings & keys', !any);
      mountLoginMap(host, opts);
    } catch (e) { toast(e.message, true); lk.disabled = false; }
  };
}

/* ------------------------------------------------------------ episodes --- */
async function renderEpisodes() {
  const el = $('#v-episodes');
  el.innerHTML = '<p class="sub" style="margin:16px">Loading episodes…</p>';
  const d = await api('/api/host');
  const eps = d.episodes || [];
  if (!eps.length) { el.innerHTML = '<p class="sub" style="margin:16px">No episodes detected yet. Run a Rebuild to detect activity clusters.</p>'; return; }

  // Count by kind for the filter bar
  const kinds = {};
  eps.forEach(e => { const k = e.kind || 'flood'; kinds[k] = (kinds[k] || 0) + 1; });
  const KIND_LABEL = { flood: 'Mail & floods', dhcp_flood: 'DHCP attacks', sniffing: 'Eavesdropping & MITM' };
  const allKinds = Object.keys(kinds);

  // Update sidebar count
  $('#cEpisodes').textContent = eps.length;

  let activeKind = null;   // null = show all

  const render = () => {
    const show = activeKind ? eps.filter(e => (e.kind || 'flood') === activeKind) : eps;
    el.innerHTML = `
      <div class="row" style="align-items:baseline;gap:10px;padding:16px 16px 0">
        <h1 style="margin:0">Episodes</h1>
        <span class="muted">${eps.length} detected</span>
        <span class="grow"></span>
        <button class="btn small ${activeKind ? 'ghost' : ''}" id="epAll">All</button>
        ${allKinds.map(k => `<button class="btn small ${activeKind === k ? '' : 'ghost'}" data-epkind="${k}">${esc(KIND_LABEL[k] || k)} <span class="faint">${kinds[k]}</span></button>`).join('')}
      </div>
      <p class="sub" style="padding:4px 16px 12px">
        Detected clusters of related activity. Click any episode to jump to it in the Host view.
        Use <code>ep:N</code> in Search to find all lines across every log file in that window.
      </p>
      <div class="ep-list">
        ${show.map(e => {
          const kind = e.kind || 'flood';
          const color = kind === 'dhcp_flood' || e.mitm ? 'var(--high)' : kind === 'sniffing' ? 'var(--medium)' : 'var(--accent)';
          const sus = e.suspects || {};
          const corr = e.corr_score || 0;
          const corrCls = corr >= 6 ? 'high' : corr >= 4 ? 'medium' : corr >= 2 ? 'low' : '';
          const detail = kind === 'dhcp_flood'
            ? `${fmtN(sus.unique_macs || 0)} unique MACs${sus.exhausted ? ' — pool exhausted' : ''}${sus.suspect_oui ? ` · prefix ${esc(sus.suspect_oui)}:xx:xx` : ''}`
            : kind === 'sniffing'
              ? (e.techniques || []).map(t => t.label).join(' · ')
              : (() => { const t = e.totals || {}; const bits = []; if (t.msg) bits.push(`${fmtN(t.msg)} messages`); if (t.nofree) bits.push('pool exhausted'); return bits.join(' · '); })();
          const files = (e.files || []).map(f => `<span class="mono faint" style="font-size:11px">${esc(f.rel||'')}</span>`).join(' ');
          return `<div class="eprow" data-epjump="${e.n}" style="border-left-color:${color}">
            <div class="row" style="gap:8px;align-items:baseline;flex-wrap:wrap">
              <span class="eptag" style="background:${color}">EP#${e.n}</span>
              <b>${esc(e.title)}</b>
              <span class="mono faint" style="font-size:12px">${esc(e.start||'')} → ${esc((e.end||'').slice(0,10)===(e.start||'').slice(0,10)?(e.end||'').slice(11):e.end||'')}</span>
              <span class="muted">${e.minutes ? e.minutes + ' min' : ''}</span>
              <span class="grow"></span>
              ${corrCls ? `<span class="corr-badge ${corrCls}">${corr} sources</span>` : ''}
              <a class="btn small" href="/api/export/episodes?episodes=${e.n}&format=pdf" download>PDF</a>
              <a class="btn small" href="/api/export/episodes?episodes=${e.n}&format=xlsx" download>XLSX</a>
            </div>
            ${detail ? `<div style="font-size:12.5px;margin-top:3px;color:var(--muted)">${detail}</div>` : ''}
            ${files ? `<div style="margin-top:3px;display:flex;gap:6px;flex-wrap:wrap">${files}</div>` : ''}
          </div>`;
        }).join('')}
      </div>`;

    // Bindings
    $('#epAll', el).onclick = () => { activeKind = null; render(); };
    $$('[data-epkind]', el).forEach(b => b.onclick = () => { activeKind = b.dataset.epkind; render(); });
    $$('[data-epjump]', el).forEach(b => b.onclick = e => { e.stopPropagation(); jumpToEpisode(+b.dataset.epjump); });
    // Don't intercept clicks on export links
    $$('a.btn', el).forEach(a => a.onclick = e => e.stopPropagation());
  };
  render();
}

/* ---------------------------------------------------------- filesystem --- */
async function renderFs() {
  const el = $('#v-fs');
  el.innerHTML = '<p class="sub" style="margin:16px">Loading…</p>';
  const d = await api('/api/fsweep');
  if (!d.available) {
    el.innerHTML = `<div style="padding:16px"><h1>Filesystem</h1><p class="sub">This evidence folder is not a full Debian
      filesystem (no <code>var/lib/dpkg/status</code> next to <code>etc/</code> and <code>usr/</code>). Point Crumbs at the root of
      the dump to check every file against its Debian package, find deleted files and reset timestamps.</p></div>`;
    return;
  }
  const S = d.summary, F = d.findings;
  $('#cFs').textContent = F.length || '';
  const GROUPS = [
    ['What was deleted', 'Files, logs, tools, packages and accounts that are gone, and the moment each disappeared where the evidence shows it.',
      x => ['deletion', 'defense_evasion'].includes(x.category) || x.rule === 'account_removed'],
    ['Timestamps that were changed', 'Files whose times were set back or copied to hide when they were really changed.',
      x => x.category === 'timestomp'],
    ['Hidden, misplaced or planted', 'Hidden names in system folders, programs in temporary folders, kernel modules and links that swallow logs.',
      x => ['hiding', 'rootkit', 'execution', 'log_tampering'].includes(x.category)],
  ];
  const ok = (good, yes, no) => `<span class="fsflag ${good ? 'ok' : 'bad'}">${good ? '✓' : '✗'}</span> ${good ? yes : no}`;
  const days = Object.entries(S.timeline_days || {});
  const maxDay = Math.max(1, ...days.map(([, n]) => n));
  const row = x => `<div class="fsrow ${x.file_id ? 'click' : ''}" data-fid="${x.file_id || ''}" data-line="${x.line_no || 1}">
      ${sevTag(x.severity)}<span class="mono faint fsts">${esc(x.ts || 'time unknown')}</span>
      <div class="fsbody"><b>${esc(x.description)}</b><div class="mono fssnip">${esc(x.snippet)}</div></div></div>`;
  el.innerHTML = `<div style="padding:16px 16px 28px">
    <div class="row" style="align-items:baseline;gap:10px;flex-wrap:wrap"><h1 style="margin:0">Filesystem</h1>
      <span class="muted">${esc(S.os || 'Debian')} · ${fmtN(S.files)} files · ${fmtN(S.packages)} packages</span><span class="grow"></span>
      ${S.timeline_file_id ? `<button class="btn small primary" id="fsTl">Open filesystem timeline</button>` : ''}</div>
    <p class="sub">Every file, folder, link and device node checked against dpkg's own records from this dump.
      ${fmtN(S.pristine)} files are byte-identical to their Debian package; they are verified but their text is not indexed.</p>
    <div class="panel" style="margin-bottom:14px"><h2 style="margin-top:0">What the timestamps can tell you</h2>
      <div class="fsgrid">
        <div>${ok(true, 'Modified times (mtime) are used for everything below', '')}</div>
        <div>${ok(S.ctime_reliable, 'Inode change times (ctime) look original: used to expose reset modified times',
          `Inode change times were reset when the evidence was copied${S.copy_time ? ' (around ' + esc(S.copy_time) + ' UTC)' : ''}; not used`)}</div>
        <div>${ok(S.complete, `${Math.round(S.coverage * 100)}% of the files dpkg installed are present: a full filesystem, so missing files mean deletion`,
          `Only ${Math.round(S.coverage * 100)}% of package files are present: partial collection, missing-file checks skipped`)}</div>
        <div>${ok(S.subsecond_share >= 0.5, `${Math.round(S.subsecond_share * 100)}% of locally written files have sub-second times, so whole-second times stand out`,
          `Only ${Math.round(S.subsecond_share * 100)}% of local files have sub-seconds; touch-style detection is off`)}</div>
        <div>${S.os_install ? `<span class="fsflag ok">✓</span> System installed around <b>${esc(S.os_install)}</b> UTC (oldest dpkg record)` : ''}</div>
        <div>${S.bodyfile ? ok(true, `Bodyfile ${esc(S.bodyfile.file)}: ${fmtN(S.bodyfile.entries)} entries, ${fmtN(S.bodyfile.deleted)} deleted names, birth times checked`, '')
          : `<span class="fsflag">+</span> For deleted file names and creation times, run <code>fls -r -m / disk.img &gt; bodyfile.txt</code> (Sleuth Kit) on the disk image, put it in the evidence folder and update the index.`}</div>
      </div>
      ${(S.notes || []).map(n => `<div class="callout" style="margin-top:8px">${esc(n)}</div>`).join('')}
    </div>
    ${days.length ? `<div class="panel" style="margin-bottom:14px"><h2 style="margin-top:0">Changes by day <span class="faint" style="font-size:13px">(files that differ from Debian, folder and package changes; click a day to open the timeline there)</span></h2>
      <div class="fsdays">${days.map(([day, n]) => `<div class="fsday" data-day="${day}" title="${day}: ${fmtN(n)} change(s)">
        <span class="fsbar" style="height:${Math.max(3, Math.round(60 * n / maxDay))}px"></span><span class="fsdlab">${day.slice(2)}</span></div>`).join('')}</div></div>` : ''}
    ${GROUPS.map(([title, sub, test]) => { const xs = F.filter(test); return `<div class="panel" style="margin-bottom:14px">
      <h2 style="margin-top:0">${title} <span class="muted" style="font-size:14px">${xs.length}</span></h2><p class="sub" style="margin-top:-4px">${sub}</p>
      ${xs.length ? xs.map(row).join('') : '<p class="muted">Nothing found.</p>'}</div>`; }).join('')}
  </div>`;
  const tl = S.timeline_file_id;
  if ($('#fsTl')) $('#fsTl').onclick = () => openViewer(tl, 1);
  $$('.fsday', el).forEach(b => b.onclick = () => openViewer(tl, d.day_line[b.dataset.day] || 1));
  $$('.fsrow.click', el).forEach(r => r.onclick = () => openViewer(+r.dataset.fid, +r.dataset.line || 1));
}

async function renderTamper() {
  const el = $('#v-tamper');
  el.innerHTML = '<p class="muted">Loading…</p>';
  let d;
  T.set = T.set || 'tamper';
  try { d = T.data = await api('/api/tamper?set=' + T.set); } catch (e) { el.innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
  const SETS = { tamper: ['Covering tracks', 'Tampering timeline', 'Traces of deletion, wiping, log editing, timestamp manipulation, rootkits and hiding, placed in time.'],
    intrusion: ['Intrusion', 'Intrusion timeline', 'How they got in and what they did: logins, privilege, persistence, tooling, rootkits, web shells, lateral movement.'],
    all: ['Everything', 'Full attack timeline', 'Intrusion and covering-tracks signals together.'] };
  const seg = `<div class="seg" role="group" aria-label="Signal set" style="margin-bottom:12px">${Object.entries(SETS).map(([k, v]) =>
    `<button type="button" data-tset="${k}" aria-pressed="${T.set === k}">${v[0]}</button>`).join('')}</div>`;
  const bindSet = () => $$('[data-tset]', el).forEach(b => b.onclick = () => { T.set = b.dataset.tset; T.zoom = null; T.cats = new Set(); renderTamper(); });
  if (!d.events.length && !d.undated.length) {
    el.innerHTML = seg + `<div class="empty"><h2>No ${SETS[T.set][0].toLowerCase()} signals</h2><p>${T.set === 'tamper'
      ? 'Nothing in this case points to deletion, wiping, log editing, timestamp changes or hiding.'
      : 'No intrusion signals.'} Absence of evidence is not proof: check that the folder includes logs, shell history and event logs.</p></div>`;
    bindSet();
    return;
  }
  const s = d.story, pk = s.peak;
  el.innerHTML = `
    ${seg}
    <h1>${SETS[T.set][1]}</h1>
    <p class="sub">${SETS[T.set][2]}
      Times come from the logs themselves (as written) and from the filesystem (UTC).</p>
    ${d.notes.map(n => `<div class="callout">${esc(n)}</div>`).join('')}
    ${s.headline ? `<div class="story">
      <div class="panel">
        <p class="big"><b>${fmtN(s.headline.count)}</b> medium or high signals, <b style="color:var(--high)">${fmtN(s.headline.high)}</b> high,
          from <span class="mono">${esc(fmtWhen(s.headline.first))}</span> to <span class="mono">${esc(fmtWhen(s.headline.last))}</span>.</p>
        <p>The busiest hour runs from <span class="mono">${esc(fmtWhen(pk.from))}</span> to <span class="mono">${esc(fmtWhen(pk.to))}</span>:
          ${fmtN(pk.count)} signals across ${plural(pk.files, 'file')}, mostly ${pk.categories.slice(0, 3).map(c => `${esc(c.label.toLowerCase())} (${c.n})`).join(', ')}.</p>
        <div class="row" style="margin-top:10px"><button class="btn small primary" id="tPeak">Zoom to that hour</button>
          <button class="btn small" id="tAll">Show everything</button></div>
      </div>
      <div class="panel"><h2>First sign of each kind</h2><div class="firsts">${s.firsts.map((x, i) => `
        <div class="item" data-first="${i}"><span class="mono" style="font-size:12.5px">${esc(fmtWhen(x.ts))}</span>
          <span><b style="font-weight:600">${esc(d.categories[x.category])}</b>: ${esc(x.description)}
          <span class="faint mono" style="font-size:12px;display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(x.rel || 'case-wide')}${x.line_no ? ':' + x.line_no : ''}</span></span></div>`).join('')}</div></div>
    </div>` : ''}
    <div class="row" style="margin-bottom:10px">
      <div class="chips" id="tCats">${d.summary.map(c => `<button class="chip" data-c="${esc(c.category)}" aria-pressed="${T.cats.has(c.category)}">${esc(c.label)}
        <span class="faint">${fmtN(c.n)}</span></button>`).join('')}</div>
      <span class="grow"></span>
      <div class="chips">${['high', 'medium', 'low'].map(v => `<button class="chip" data-sv="${v}" aria-pressed="${T.sev.has(v)}">${v}</button>`).join('')}</div>
    </div>
    <div class="lanes" id="tChart"></div>
    <p class="faint" style="font-size:12.5px;margin:6px 0 18px">Drag across the chart to zoom in. Click a mark to jump to it in the list.
      The bottom strip counts file modifications on disk.</p>
    <div class="row" style="margin-bottom:8px"><h2 style="margin:0" id="tCount"></h2><span class="grow"></span>
      <button class="btn small" id="tReset" hidden>Clear zoom</button></div>
    <div class="list" id="tList"></div>
    <div id="tMore" class="more"></div>
    ${d.undated.length ? `<h2 style="margin-top:24px">Signals without a time (${fmtN(d.undated.length)})</h2>
      <div class="list" id="tUndated">${d.undated.map(evRow).join('')}</div>` : ''}`;
  $$('#tCats [data-c]').forEach(b => b.onclick = () => { const c = b.dataset.c; T.cats.has(c) ? T.cats.delete(c) : T.cats.add(c); b.setAttribute('aria-pressed', T.cats.has(c)); drawTamper(); });
  $$('[data-sv]', el).forEach(b => b.onclick = () => { const v = b.dataset.sv; T.sev.has(v) ? T.sev.delete(v) : T.sev.add(v); b.setAttribute('aria-pressed', T.sev.has(v)); drawTamper(); });
  if ($('#tPeak')) $('#tPeak').onclick = () => { T.zoom = [tEpoch(pk.from) - 300000, tEpoch(pk.to) + 300000]; drawTamper(); };
  if ($('#tAll')) $('#tAll').onclick = () => { T.zoom = 'all'; drawTamper(); };
  $('#tReset').onclick = () => { T.zoom = null; drawTamper(); };
  $$('[data-first]', el).forEach(r => r.onclick = () => { const x = s.firsts[+r.dataset.first]; openEvent(x); });
  if ($('#tUndated')) bindEvRows($('#tUndated'), d.undated);
  drawTamper();
  bindSet();
}
function evRow(e, i) {
  const sameDay = e.ts_end && e.ts && e.ts_end.slice(0, 10) === e.ts.slice(0, 10);
  const files = Array.isArray(e.detail) ? e.detail : null;
  return `<div class="evrow ${T.sel === e.id ? 'sel' : ''}" data-ev="${i}" id="ev${e.id}">
    <div class="when">${esc(fmtWhen(e.ts)) || '<span>no time</span>'}${e.ts_end ? `<span>to ${esc(sameDay ? e.ts_end.slice(11, 19) : fmtWhen(e.ts_end))}</span>` : ''}</div>
    <div>${sevTag(e.severity)}</div>
    <div><div>${esc(e.description)}</div><div class="snip">${esc(e.snippet)}</div>${e.claims ? `<div class="claimline">Done at <b class="real">${esc(fmtWhen(e.ts))}</b> · ${e.claims.map(c => c.role === 'set'
      ? `claims <b class="fake">${esc(c.ts || c.kind)}</b>` : `original <b class="real">${esc(c.ts)}</b>`).join(' · ')}</div>` : ''}<div class="cat">${esc(T.data.categories[e.category] || e.category)}</div></div>
    <div class="where">${e.rel ? esc(e.rel) + (e.line_no ? `<span class="faint">:${e.line_no}</span>` : '') : '<span class="faint">case-wide</span>'}</div>
    ${files ? `<div class="evfiles">${files.slice(0, 60).map(f => `<button data-evf="${f.id}">${esc(f.rel)}</button>`).join('')}${files.length > 60 ? '<span class="faint">…</span>' : ''}</div>` : ''}
  </div>`;
}
function openEvent(e) {
  if (e.file_id) openViewer(e.file_id, e.line_no || 1);
  else toast('This signal covers several files; pick one from its list.');
}
function bindEvRows(box, list) {
  $$('.evrow', box).forEach(r => r.onclick = ev => {
    const b = ev.target.closest('[data-evf]');
    if (b) { openViewer(+b.dataset.evf, 1); return; }
    openEvent(list[+r.dataset.ev]);
  });
}
function tDomain(events) {
  const pts = [];
  for (const e of events) { pts.push(tEpoch(e.ts)); if (e.ts_end) pts.push(tEpoch(e.ts_end)); }
  pts.sort((a, b) => a - b);
  if (!pts.length) return null;
  if (Array.isArray(T.zoom)) return T.zoom;
  let lo = pts[0], hi = pts[pts.length - 1];
  if (T.zoom !== 'all' && pts.length >= 8) {
    const q = p => pts[Math.min(pts.length - 1, Math.max(0, Math.round(p * (pts.length - 1))))];
    const a = q(0.05), b = q(0.95);
    if ((hi - lo) > 8 * Math.max(b - a, 3600e3)) { lo = a; hi = b; }
  }
  const pad = Math.max((hi - lo) * 0.04, 30 * 60e3);
  return [lo - pad, hi + pad];
}
function niceStep(span) {
  const m = 60e3, h = 3600e3, dd = 86400e3;
  const steps = [m, 5 * m, 15 * m, 30 * m, h, 3 * h, 6 * h, 12 * h, dd, 2 * dd, 7 * dd, 30 * dd, 91 * dd, 365 * dd];
  return steps.find(s => span / s <= 9) || 365 * dd;
}
function drawTamper() {
  const d = T.data;
  const shown = tFiltered();
  const all = d.events.filter(e => (!T.cats.size || T.cats.has(e.category)) && T.sev.has(e.severity));
  const dom = tDomain(all);
  $('#tReset').hidden = !T.zoom;
  // ---- chart
  const box = $('#tChart');
  const cats = d.summary.map(c => c.category).filter(c => (!T.cats.size || T.cats.has(c)) && all.some(e => e.category === c));
  if (!dom || !cats.length) { box.innerHTML = '<div class="empty">No dated signals match the filters.</div>'; }
  else {
    const W = Math.max(640, box.clientWidth - 20), L = 190, R = 16, laneH = 30, top = 24, fsH = 34;
    const H = top + cats.length * laneH + 12 + fsH + 22;
    const x = t => L + (t - dom[0]) / (dom[1] - dom[0]) * (W - L - R);
    const step = niceStep(dom[1] - dom[0]);
    let svg = `<svg viewBox="0 0 ${W} ${H}" height="${H}" id="tSvg" role="img" aria-label="Tampering signals over time">`;
    const first = Math.ceil(dom[0] / step) * step;
    for (let t = first; t <= dom[1]; t += step) {
      const X = x(t), iso = new Date(t).toISOString();
      const lab = step >= 86400e3 ? iso.slice(0, 10) : (iso.slice(5, 10) + ' ' + iso.slice(11, 16));
      svg += `<line x1="${X}" x2="${X}" y1="${top - 4}" y2="${H - 4}" class="tl-grid"/><text class="tl-axis" x="${X + 3}" y="${top - 10}">${lab}</text>`;
    }
    let outL = 0, outR = 0;
    cats.forEach((c, i) => {
      const y = top + i * laneH;
      svg += `<rect class="lane-bg" x="${L}" y="${y + 3}" width="${W - L - R}" height="${laneH - 6}" rx="3"/>
        <text class="lane-label" x="0" y="${y + laneH / 2 + 4}">${esc(d.categories[c])}</text>`;
      all.filter(e => e.category === c).forEach(e => {
        const a = tEpoch(e.ts), b = e.ts_end ? tEpoch(e.ts_end) : null;
        if ((b || a) < dom[0]) { outL++; return; }
        if (a > dom[1]) { outR++; return; }
        const idx = shown.indexOf(e), cy = y + laneH / 2;
        const tip = `${fmtWhen(e.ts)}${e.ts_end ? ' to ' + fmtWhen(e.ts_end) : ''}\n${e.description}\n${e.rel || 'case-wide'}${e.line_no ? ':' + e.line_no : ''}`;
        if (b && b > a) {
          const x1 = Math.max(L, x(a)), x2 = Math.min(W - R, x(b));
          svg += `<rect class="ev ${e.severity}" data-eid="${e.id}" x="${x1}" y="${cy - 6}" width="${Math.max(4, x2 - x1)}" height="12" rx="3" opacity=".75"><title>${esc(tip)}</title></rect>`;
        } else {
          const r = e.severity === 'high' ? 6 : e.severity === 'medium' ? 5 : 4;
          svg += `<circle class="ev ${e.severity}" data-eid="${e.id}" cx="${x(a)}" cy="${cy}" r="${r}"><title>${esc(tip)}</title></circle>`;
        }
      });
    });
    // file modification strip
    const fy = top + cats.length * laneH + 12;
    const bins = 90, cnt = new Array(bins).fill(0);
    for (const f of d.fs) { const t = tEpoch(f.t); if (t >= dom[0] && t <= dom[1]) cnt[Math.min(bins - 1, Math.floor((t - dom[0]) / (dom[1] - dom[0]) * bins))]++; }
    const mx = Math.max(1, ...cnt), bw = (W - L - R) / bins;
    svg += `<text class="lane-label" x="0" y="${fy + fsH / 2 + 4}">File changes on disk</text>`;
    cnt.forEach((c, i) => { if (c) { const h = Math.max(2, c / mx * fsH); svg += `<rect class="fsbar" x="${L + i * bw + .5}" y="${fy + fsH - h}" width="${Math.max(1, bw - 1)}" height="${h}"><title>${c} files modified</title></rect>`; } });
    if (outL) svg += `<text class="edge-count" x="${L + 2}" y="${H - 3}">◀ ${outL} earlier</text>`;
    if (outR) svg += `<text class="edge-count" x="${W - R}" y="${H - 3}" text-anchor="end">${outR} later ▶</text>`;
    svg += `<rect class="brush" id="tBrush" y="${top - 4}" height="${H - top - 14}" x="0" width="0" visibility="hidden"/></svg>`;
    box.innerHTML = svg;
    const svgEl = $('#tSvg');
    const toT = cx => { const r = svgEl.getBoundingClientRect(); const X = (cx - r.left) / r.width * W; return dom[0] + (X - L) / (W - L - R) * (dom[1] - dom[0]); };
    const toX = cx => { const r = svgEl.getBoundingClientRect(); return (cx - r.left) / r.width * W; };
    let startX = null;
    svgEl.addEventListener('pointerdown', ev => { if (ev.target.classList.contains('ev')) return; startX = ev.clientX; svgEl.setPointerCapture(ev.pointerId); });
    svgEl.addEventListener('pointermove', ev => {
      if (startX == null) return;
      const a = Math.max(L, Math.min(toX(startX), toX(ev.clientX))), b = Math.min(W - R, Math.max(toX(startX), toX(ev.clientX)));
      const br = $('#tBrush'); br.setAttribute('visibility', 'visible'); br.setAttribute('x', a); br.setAttribute('width', Math.max(0, b - a));
    });
    svgEl.addEventListener('pointerup', ev => {
      if (startX == null) return;
      const a = Math.min(startX, ev.clientX), b = Math.max(startX, ev.clientX);
      startX = null;
      if (b - a > 6) { T.zoom = [toT(a), toT(b)]; drawTamper(); } else $('#tBrush').setAttribute('visibility', 'hidden');
    });
    $$('.ev', svgEl).forEach(m => m.addEventListener('click', () => {
      T.sel = +m.dataset.eid;
      const i = shown.findIndex(e => e.id === T.sel);
      if (i >= T.limit) T.limit = i + 50;
      drawList(shown);
      const row = $('#ev' + T.sel);
      if (row) row.scrollIntoView({ block: 'center', behavior: 'smooth' });
    }));
  }
  drawList(shown);
}
function drawList(shown) {
  $('#tCount').textContent = `${fmtN(shown.length)} dated signals${T.zoom && T.zoom !== 'all' ? ' in the zoomed range' : ''}`;
  $('#tList').innerHTML = shown.length ? shown.slice(0, T.limit).map(evRow).join('') : '<div class="empty">Nothing in this range.</div>';
  bindEvRows($('#tList'), shown);
  $('#tMore').innerHTML = shown.length > T.limit ? `<button class="btn" id="tMoreBtn">Show ${fmtN(Math.min(400, shown.length - T.limit))} more</button>` : '';
  if ($('#tMoreBtn')) $('#tMoreBtn').onclick = () => { T.limit += 400; drawList(shown); };
}

/* ------------------------------------------------------------ keyboard --- */
document.addEventListener('keydown', e => {
  const typing = /INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName);
  if (e.key === 'Escape' && !$('#viewer').hidden) { closeViewer(); return; }
  if (typing) return;
  if (e.key === '/') { e.preventDefault(); ($('#viewer').hidden ? $('#q') : $('#vFind')).focus(); }
  if (!$('#viewer').hidden && (e.key === 'n' || e.key === 'N')) stepFind(e.key === 'n' ? 1 : -1);
});

/* ---------------------------------------------------------------- theme --- */
function applyThemeLabel() { $('#themeBtn').textContent = document.documentElement.dataset.theme === 'light' ? 'Dark theme' : 'Light theme'; }
$('#themeBtn').onclick = () => {
  const light = document.documentElement.dataset.theme !== 'light';
  if (light) document.documentElement.dataset.theme = 'light'; else delete document.documentElement.dataset.theme;
  try { localStorage.setItem('crumbs-theme', light ? 'light' : 'dark'); } catch (e) { /* ignore */ }
  applyThemeLabel();
  if (current === 'graph' && G.cy) loadGraph();
};
applyThemeLabel();

/* ----------------------------------------------------------------- boot --- */
show(location.hash.slice(1) || 'overview');
pollStatus();
api('/api/pins').then(d => ($('#cPins').textContent = d.pins.length || '')).catch(() => {});

/* ----------------------------------------------------------------- host --- */
const H = { data: null, cmdFilter: '' };
const flagTag = f => `<span class="hflag ${f[0]}">${esc(f[1])}</span>`;
const src = x => x.file_id ? `data-hf="${x.file_id}" data-hl="${x.line || 1}"` : '';
function hsection(id, title, count, sub, body) {
  return `<section class="hsec" id="h-${id}"><div class="row" style="margin-bottom:6px"><h2 style="margin:0">${title}</h2>
    ${count != null ? `<span class="muted">${fmtN(count)}</span>` : ''}</div>${sub ? `<p class="sub" style="margin:0 0 10px">${sub}</p>` : ''}${body}</section>`;
}
function htable(cols, rowsHtml, empty = 'Nothing found in the collected files.') {
  if (!rowsHtml.length) return `<p class="faint" style="margin:4px 0 0">${empty}</p>`;
  return `<div class="tblwrap"><table class="tbl"><thead><tr>${cols.map(c => `<th>${c}</th>`).join('')}</tr></thead>
    <tbody>${rowsHtml.join('')}</tbody></table></div>`;
}
async function renderHost() {
  const el = $('#v-host');
  el.innerHTML = '<p class="muted">Loading…</p>';
  let d;
  try { d = H.data = await api('/api/host'); } catch (e) { el.innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
  let bl = null; try { bl = await api('/api/baseline'); } catch (e) { /* older index */ }
  if (d.empty) {
    el.innerHTML = `<div class="empty"><h2>No Linux host artifacts found</h2>
      <p>Crumbs recognises Linux files by their path. Index a copy of the system that keeps the folder layout, for example
      <code>etc/</code>, <code>var/log/</code> (including <code>audit/</code>, <code>wtmp</code>, <code>btmp</code>, <code>lastlog</code>),
      <code>var/lib/dpkg/</code>, <code>var/spool/cron/</code>, <code>home/</code>, <code>root/</code>, <code>tmp/</code>, <code>var/tmp/</code>
      and the system program folders. A mounted disk image works as-is.</p></div>`;
    return;
  }
  const h = d.host;
  d._relIds = {};
  (d.episodes || []).forEach(e => (e.files || []).forEach(f => { if (f.rel) d._relIds[f.rel] = f.file_id; }));
  (d.captures || []).forEach(c => { /* rel present; id unknown, resolved via episodes when possible */ });
  const dosEps = (d.episodes || []).filter(e => e.kind !== 'sniffing' && e.kind !== 'dhcp_flood');
  const dhcpEps = (d.episodes || []).filter(e => e.kind === 'dhcp_flood');
  const az_desc = { tunnel_installed: 'Tunnel / VPN / Tor config', covert_tunnel: 'Covert tunnel', dns_tunnel: 'DNS tunnel', icmp_tunnel: 'ICMP tunnel',
    suspicious_socket: 'Suspicious live socket', ssh_forwarding_log: 'SSH port forwarding', tunnel: 'Tunnel / proxy tool', reverse_shell: 'Reverse shell',
    beaconing: 'Beaconing', http_tunnel: 'HTTP tunnel through script', http_tunnel_request: 'reGeorg-style requests', internal_control: 'Used from inside',
    internal_new_source: 'New internal source', long_control: 'Control over days' };
  const sniffEps = (d.episodes || []).filter(e => e.kind === 'sniffing');
  const hi = d.accounts.filter(a => a.flags.some(f => f[0] === 'high')).length + d.integrity.filter(i => i.severity === 'high').length +
    d.persistence.filter(p => p.level === 'high').length + d.sources.filter(s => s.guessed).length + d.unknown_keys.length;
  $('#cHost').textContent = hi ? fmtN(hi) : '';

  const attention = [];
  (d.initial_access || []).filter(h => h.likely).forEach(h => attention.push(['high', `Most likely way in: ${h.kind} at ${h.ts} from ${h.ip || '?'}`, h]));
  (d.channels || []).filter(c => c.internal).slice(0, 5).forEach(c => attention.push(['high', `Attacker channel used from inside the network: ${c.source} → ${c.kind} ${c.target} (${fmtN(c.n)}×, ${c.first} → ${c.last})`, c]));
  dosEps.forEach(e => { const f = (e.files||[])[0]; attention.push(['high', `Episode #${e.n}, ${e.title}: ${e.start} → ${e.end.slice(11)} (${e.minutes} min)`, f ? { file_id: f.file_id, line: f.first_line } : null]); });
  dhcpEps.forEach(e => { const f = (e.files||[])[0]; attention.push(['high', `Episode #${e.n}, ${e.title}: ${e.start} → ${e.end.slice(11)} (${e.minutes} min, ${(e.suspects||{}).unique_macs||0} unique MACs)`, f ? { file_id: f.file_id, line: 1 } : null]); });
  sniffEps.forEach(e => { const f = (e.files||[])[0]; attention.push([e.mitm ? 'high' : 'high', `Episode #${e.n}, ${e.title}${e.start ? ': ' + e.start + (e.end ? ' → ' + e.end.slice(11) : '') : ' (configuration left in place)'}`, f ? { file_id: f.file_id, line: f.first_line } : null]); });
  d.sources.filter(s => s.guessed).forEach(s => attention.push(['high', `${s.ip} guessed a password: ${s.failed} failures, then logged in (first success ${s.first_success}; accounts used: ${s.users_ok.join(', ')})`, s]));
  d.accounts.forEach(a => a.flags.filter(f => f[0] === 'high').forEach(f => attention.push(['high', `Account ${a.name}: ${f[1]}`, a])));
  d.unknown_keys.forEach(k => attention.push(['medium', `${k.users.join(', ')} logged in from ${k.ips.join(', ')} with an SSH key that is no longer authorised anywhere (${k.first_use})`, k]));
  d.persistence.filter(p => p.level === 'high').forEach(p => attention.push(['high', `${p.mechanism}: ${p.entry.slice(0, 140)}`, p]));
  d.integrity.filter(i => i.severity === 'high' && !['pam_suspicious', 'ld_preload'].includes(i.rule)).forEach(i => attention.push(['high', `${i.description}: ${i.snippet.slice(0, 140)}`, { file_id: i.file_id, line: i.line_no }]));

  const risky = d.sshd.filter(x => x.risky);
  const priv = [
    ...d.sudo.map(x => ({ ...x, what: `sudo → ${x.target}`, text: x.command, bad: !x.ok, note: x.ok ? `in ${x.cwd}` : x.problem })),
    ...d.su.map(x => ({ ...x, what: `su → ${x.target}`, text: x.tty || '', bad: !x.ok, note: x.ok ? '' : 'failed' })),
    ...d.account_changes.map(x => ({ ...x, what: 'account', text: x.change, bad: /created|group|UID|0/.test(x.change), note: x.via || '' })),
  ].sort((a, b) => (a.ts || '').localeCompare(b.ts || ''));
  const cmds = d.commands;

  el.innerHTML = `
    <div class="row" style="align-items:baseline;flex-wrap:wrap">
      <h1 style="margin:0">${esc(h.hostname || 'Linux host')}</h1>
      <span class="muted">${esc(h.pretty_name || '')}${h.debian_version ? ' · Debian ' + esc(h.debian_version) : ''}</span>
    </div>
    <div class="callout" style="margin-top:10px">Time zone: <b>${esc(h.timezone || h.tz_rule || 'unknown')}</b>${h.tz_rule && h.timezone ? ` <span class="mono faint">${esc(h.tz_rule)}</span>` : ''}.
      Syslog-style logs (auth.log, syslog, kern.log, apt) are written in this <b>local time</b>; wtmp, btmp, lastlog, auditd, shadow dates,
      decoded epochs and file times are <b>UTC</b>. Keep this in mind when lining up events.</div>
    <nav class="hnav">${[['attn', 'Attention'], ...((d.initial_access || []).length ? [['entry', 'How they got in']] : []),
      ...(bl ? [['base', 'Debian baseline']] : []),
      ...((d.channels || []).length || (d.tunnels || []).length ? [['ctrl', 'Remote control & tunnels']] : []), ...(dhcpEps.length ? [['dhcp', 'DHCP attacks']] : []), ...(dosEps.length || (d.dos_tools || []).length ? [['dos', 'Floods & starvation']] : []),
      ...(sniffEps.length || (d.sniff_signals || []).length ? [['sniff', 'Eavesdropping & MITM']] : []), ['acc', 'Accounts'], ['src', 'Logins'], ['keys', 'SSH'], ['priv', 'Privilege'], ['pers', 'Persistence'],
      ['integ', 'System files'], ['pkg', 'Packages'], ['cmd', 'Commands'], ['net', 'Contacts & edits']].map(([k, v]) => `<a href="#h-${k}" data-hj="${k}">${v}</a>`).join('')}</nav>

    ${hsection('attn', 'Needs attention', attention.length, 'The strongest host signals. Click one to open the evidence.',
      attention.length ? `<div class="list">${attention.map(([sv, t, x]) => `<div class="item" style="grid-template-columns:80px 1fr" ${src(x)}>${sevTag(sv)}<span>${esc(t)}</span></div>`).join('')}</div>`
        : '<p class="faint">No strong host signals.</p>')}

    ${(d.initial_access || []).length ? hsection('entry', 'How they got in', d.initial_access.length,
      'Candidate ways in, in time order. The most likely foothold is the earliest high-confidence step; earlier successful steps are often reconnaissance. Steps more than 6 hours later are later stages, not alternatives.' +
      (d.compromise_start ? ` Compromise activity starts <b class="mono">${esc(d.compromise_start)}</b>.` : ''),
      `<div class="entry">${d.initial_access.map(h => `<div class="entryrow ${h.likely ? 'likely' : ''} ${h.stage === 'later' ? 'later' : ''}" ${src(h)}>
        <div class="mono">${esc(h.ts)}</div>
        <div><div class="row" style="gap:6px;flex-wrap:wrap"><b>${esc(h.kind)}</b>${h.likely ? '<span class="hflag high">most likely foothold</span>' : ''}${h.earliest && !h.likely ? '<span class="hflag medium">first successful step</span>' : ''}${h.stage === 'later' ? '<span class="hflag low">later stage</span>' : ''}
          <span class="faint">${esc(h.confidence)} confidence</span>${h.ip ? ` <a class="lnk mono" data-q="${esc(h.ip)}">${esc(h.ip)}</a>` : ''}</div>
          ${h.evidence.map(e => `<div class="mono faint" style="font-size:12.5px">· ${esc(e)}</div>`).join('')}</div></div>`).join('')}</div>`) : ''}

    ${bl && bl.available ? baselineSection(bl) : (bl ? hsection('base', 'Debian baseline', null,
      'Compares every system file and installed package against what Debian shipped.', `<p class="faint">${esc(bl.reason || 'No dpkg data collected.')}</p>`) : '')}

    ${(d.channels || []).length || (d.tunnels || []).length ? hsection('ctrl', 'Remote control & tunnels', (d.channels || []).length,
      'How the attacker kept control: web shells and how long they were used, regular polling (beaconing), HTTP tunnels through scripts, SSH from inside the network, and tunnel / VPN / Tor evidence on the host. Rows from inside the network after the compromise began are marked.',
      ((d.channels || []).length ? htable(['Channel', 'From', 'To / through', 'Uses', 'First', 'Last', ''], d.channels.map(c => `<tr ${src(c)} class="${c.internal ? 'bad' : ''}">
        <td><b>${esc(c.kind)}</b>${c.interval ? ` <span class="faint">every ~${c.interval >= 120 ? Math.round(c.interval / 60) + ' min' : c.interval + ' s'}</span>` : ''}</td>
        <td class="mono"><a class="lnk" data-q="${esc(c.source)}">${esc(c.source)}</a></td><td class="mono">${esc(c.target)}</td><td>${fmtN(c.n)}</td>
        <td class="mono">${esc(c.first || '')}</td><td class="mono">${esc(c.last || '')}</td>
        <td>${c.internal ? '<span class="hflag high">from inside the network</span>' : ''}${c.confirmed ? ' <span class="vchip valid">confirmed IOC</span>' : ''}</td></tr>`)) : '') +
      ((d.tunnels || []).length ? `<h3 style="margin:16px 0 6px">Tunnel, beacon and covert-channel evidence</h3>` + htable(['', 'Signal', 'Detail', 'Where', 'Time'],
        d.tunnels.map(t => `<tr ${src(t)}><td>${sevTag(t.severity)}</td><td>${esc((az_desc[t.rule] || t.rule.replace(/_/g, ' ')))}</td>
          <td class="mono">${esc(t.snippet)}</td><td class="mono faint">${esc((t.rel || 'case-wide').split('/').slice(-2).join('/'))}${t.line ? ':' + t.line : ''}</td>
          <td class="mono">${esc(t.ts || '')}${t.ts_end && t.ts_end !== t.ts ? '<br>→ ' + esc(t.ts_end) : ''}</td></tr>`)) : '')) : ''}

    ${dhcpEps.length ? hsection('dhcp', 'DHCP attacks', dhcpEps.length,
      'DHCP DISCOVER flood or pool starvation — attacker sends thousands of DISCOVER packets with spoofed MAC addresses to exhaust the IP lease pool, denying addresses to legitimate hosts.',
      dhcpEps.map(dhcpCard).join('')) : ''}
    ${dosEps.length || (d.dos_tools || []).length ? hsection('dos', 'Floods & starvation', dosEps.length,
      'Mail and connection bursts far above this machine\'s normal rate, grouped into numbered episodes. Each episode is tagged in the files that show it (EP#n in the viewer; search <code>ep:1</code>). Times as written in the logs.',
      dosEps.map(episodeCard).join('') +
      ((d.dos_tools || []).length ? `<h3 style="margin:16px 0 6px">Flooding tools, scripts and loops found</h3>` + htable(['', 'Signal', 'Where', 'Line', 'Time'],
        d.dos_tools.map(t => `<tr ${src(t)}><td>${sevTag(t.severity)}</td><td>${esc(t.rule.replace(/_/g, ' '))}</td><td class="mono faint">${esc(t.rel)}:${t.line}</td>
          <td class="mono">${esc(t.snippet)}</td><td class="mono">${esc(t.ts || '')}</td></tr>`)) : '')) : ''}

    ${sniffEps.length || (d.sniff_signals || []).length ? hsection('sniff', 'Eavesdropping & traffic manipulation', sniffEps.length,
      'Signs of packet capture, promiscuous mode, ARP spoofing, IP forwarding, DNS or TLS tampering, and captured plaintext credentials. Grouped into numbered episodes and tagged in the files (EP#n; search <code>ep:' + (sniffEps[0] ? sniffEps[0].n : 'n') + '</code>).',
      sniffEps.map(sniffCard).join('') +
      ((d.captures || []).length ? `<h3 style="margin:16px 0 6px">Capture files</h3>` + htable(['File', 'Packets', 'Size', 'Captured (UTC)', 'Top talkers', 'Top ports'],
        d.captures.map(c => `<tr ${src({file_id:c.file_id, line:1})}><td class="mono"><b>${esc(c.rel)}</b></td><td>${fmtN(c.packets)}</td><td>${(c.bytes/1e6).toFixed(1)} MB</td>
          <td class="mono">${esc(c.first || '')}${c.last && c.last !== c.first ? ' → ' + esc(c.last) : ''}</td>
          <td class="mono faint">${(c.top_talkers||[]).slice(0,3).map(t => esc(t[0]) + ' ×' + t[1]).join('<br>')}</td>
          <td class="mono faint">${(c.services||[]).slice(0,4).map(t => t[0] + ' ×' + t[1]).join(', ')}</td></tr>`)) : '') +
      ((d.sniffed_creds || []).length ? `<h3 style="margin:16px 0 6px">Plaintext credentials seen in captured traffic <span class="hflag high">${d.sniffed_creds.length}</span></h3>` +
        htable(['Kind', 'Value', 'Flow', 'Capture'], d.sniffed_creds.slice(0, 300).map(c => `<tr ${src({file_id:c.file_id, line:c.line})}><td>${esc(c.subject || c.kind || '')}</td>
          <td class="mono"><b>${esc(c.detail)}</b></td><td class="mono faint">${esc(c.flow)}</td><td class="mono faint">${esc((c.file||'').split('/').pop())}</td></tr>`)) : '') +
      ((d.sniff_signals || []).length ? `<h3 style="margin:16px 0 6px">All eavesdropping / manipulation signals</h3>` + htable(['', 'Signal', 'Where', 'Detail', 'Time'],
        d.sniff_signals.map(t => `<tr ${src(t)}><td>${sevTag(t.severity)}</td><td>${esc(t.rule.replace(/_/g, ' '))}</td><td class="mono faint">${esc(t.rel)}:${t.line}</td>
          <td class="mono">${esc(t.snippet)}</td><td class="mono">${esc(t.ts || '')}</td></tr>`)) : '')) : ''}

    ${hsection('acc', 'Accounts', d.accounts.length, 'From passwd, shadow and group, with password state, groups and login history. Flagged accounts first.',
      htable(['Account', 'UID', 'Shell', 'Home', 'Groups', 'Password', 'Changed (UTC)', 'Logins', 'Last login', 'Flags'],
        d.accounts.map(a => `<tr ${src(a)} class="${a.interactive ? '' : 'dim'}"><td class="mono"><b>${esc(a.name)}</b></td><td>${a.uid}</td>
          <td class="mono">${esc(a.shell)}</td><td class="mono">${esc(a.home)}</td><td>${esc(a.groups.join(', '))}</td>
          <td>${a.password === 'empty' ? '<b style="color:var(--high)">empty</b>' : esc(a.password || '?')}${a.algo ? ` <span class="faint">${esc(a.algo)}</span>` : ''}</td>
          <td class="mono">${esc((a.pw_changed || '').slice(0, 10))}</td><td>${a.logins || ''}</td>
          <td class="mono">${esc(a.last_login || '')}${a.last_from ? `<br><span class="faint">${esc(a.last_from)}</span>` : ''}</td>
          <td>${a.flags.map(flagTag).join(' ')}</td></tr>`)))}

    ${hsection('src', 'Logins by source', d.sources.length, 'sshd, auditd, wtmp and btmp together. Password guessing that ended in a login is marked. Click an address to search it everywhere.',
      '<div id="hostLoginMap" style="margin-bottom:12px"></div>' + htable(['Source', 'Logged in', 'Failed', 'Accounts used', 'Accounts tried', 'Method', 'First seen', 'First success', 'Last seen'],
        d.sources.map(s => `<tr ${src(s)}><td class="mono"><a class="lnk" data-q="${esc(s.ip)}">${esc(s.ip)}</a> ${s.public ? '<span class="faint">public</span>' : ''}
          ${s.guessed ? '<span class="hflag high">guessed</span>' : ''}</td><td>${s.success || ''}</td><td>${s.failed || ''}</td>
          <td>${esc(s.users_ok.join(', '))}</td><td class="faint">${esc(s.users_tried.slice(0, 8).join(', '))}${s.users_tried.length > 8 ? '…' : ''}</td>
          <td>${esc(s.methods.join(', '))}</td><td class="mono">${esc(s.first || '')}</td><td class="mono">${esc(s.first_success || '')}</td>
          <td class="mono">${esc(s.last || '')}</td></tr>`)))}

    ${hsection('keys', 'SSH access', d.keys.length, 'Authorised keys and whether each was used. A key used for a login that is in no collected authorized_keys was probably removed afterwards.',
      htable(['Account', 'Key', 'Comment', 'Options', 'File changed (UTC)', 'Used', 'From', 'First / last use'],
        d.keys.map(k => `<tr ${src(k)}><td class="mono">${esc(k.owner)}</td><td class="mono" style="font-size:12px">${esc(k.type)}<br>${esc(k.fingerprint || '')}</td>
          <td>${esc(k.comment)}</td><td class="mono" style="font-size:12px">${esc(k.options || '')}</td><td class="mono">${esc(k.file_changed || '')}</td>
          <td>${k.uses || '<span class="faint">never seen</span>'}</td><td class="mono">${esc(k.ips.join(', '))}</td>
          <td class="mono">${esc(k.first_use || '')}${k.last_use && k.last_use !== k.first_use ? '<br>' + esc(k.last_use) : ''}</td></tr>`)) +
      (d.unknown_keys.length ? `<h3 style="margin:14px 0 6px;color:var(--medium)">Keys used but no longer authorised</h3>` +
        htable(['Fingerprint', 'Accounts', 'Uses', 'From', 'First use', 'Last use'], d.unknown_keys.map(k => `<tr ${src(k)}>
          <td class="mono" style="font-size:12px">${esc(k.type || '')} ${esc(k.fingerprint)}</td><td>${esc(k.users.join(', '))}</td><td>${k.uses}</td>
          <td class="mono">${esc(k.ips.join(', '))}</td><td class="mono">${esc(k.first_use)}</td><td class="mono">${esc(k.last_use)}</td></tr>`)) : '') +
      `<h3 style="margin:14px 0 6px">SSH server settings${risky.length ? ` <span class="hflag medium">${risky.length} risky</span>` : ''}</h3>` +
      htable(['Setting', 'Value', 'File'], d.sshd.map(x => `<tr ${src(x)} class="${x.risky ? 'bad' : ''}"><td class="mono">${esc(x.subject)}</td>
        <td class="mono">${esc(x.value)}</td><td class="mono faint">${esc(x.rel)}:${x.line}</td></tr>`)) +
      (d.listen.length ? `<p class="muted" style="margin-top:8px">sshd reported listening on: ${d.listen.map(l => `<span class="mono">${esc(l.address)}:${esc(l.subject)}</span> (${esc(l.ts || '')})`).join(', ')}</p>` : ''))}

    ${hsection('priv', 'Privileged activity', priv.length, 'sudo, su and account changes in time order. sudo rules are listed below.',
      htable(['Time', 'Who', 'What', 'Command / change', 'Note'], priv.map(x => `<tr ${src(x)} class="${x.bad ? 'bad' : ''}">
        <td class="mono">${esc(x.ts || '')}</td><td class="mono">${esc(x.subject)}</td><td>${esc(x.what)}</td>
        <td class="mono">${esc(x.text || '')}</td><td class="faint">${esc(x.note || '')}</td></tr>`)) +
      (d.sudo_rules.length ? `<h3 style="margin:14px 0 6px">sudo rules</h3>` + htable(['Who', 'Rule', 'File'], d.sudo_rules.map(r => `<tr ${src(r)} class="${r.nopasswd || /!\s*(syslog|logfile)/.test(r.rule) ? 'bad' : ''}">
        <td class="mono">${esc(r.subject)}</td><td class="mono">${esc(r.rule)}</td><td class="mono faint">${esc(r.rel)}</td></tr>`)) : ''))}

    ${hsection('pers', 'Persistence', d.persistence.length, 'Everything that starts code automatically: cron, systemd, rc.local, shell startup files, ld.so.preload, PAM, kernel modules. Times are when the file was last changed (UTC).',
      htable(['', 'Mechanism', 'Where', 'Entry', 'Why it stands out', 'File changed'], d.persistence.map(p => `<tr ${src(p)} class="${p.level === 'high' ? 'bad' : 'dim'}">
        <td>${sevTag(p.level === 'high' ? 'high' : 'low')}</td><td>${esc(p.mechanism)}</td><td class="mono">${esc(p.subject)}</td>
        <td class="mono">${esc(p.entry)}</td><td>${esc((p.reasons || []).join(', '))}</td><td class="mono">${esc(p.ts || '')}</td></tr>`)))}

    ${hsection('integ', 'System files', d.integrity.length, 'Programs that differ from their Debian package (dpkg checksums), programs no package installed, SUID files, programs in temporary folders, wiped login records, deceptive names.',
      htable(['', 'Signal', 'Detail', 'Time'], d.integrity.map(i => `<tr ${src({ file_id: i.file_id, line: i.line_no })}>
        <td>${sevTag(i.severity)}</td><td>${esc(i.description)}</td><td class="mono">${esc(i.snippet)}</td><td class="mono">${esc(i.ts || '')}</td></tr>`),
        'No problems found. Package verification needs var/lib/dpkg/info collected together with the program folders.'))}

    ${hsection('pkg', 'Packages', d.packages.length, 'Installs and removals from apt history and dpkg.log (local time), with who asked for them.',
      htable(['Time', 'Action', 'Package', 'Version', 'Requested by', 'Command line'], d.packages.map(p => `<tr ${src(p)} class="${/remove|purge/.test(p.action) ? 'bad' : ''}">
        <td class="mono">${esc(p.ts || '')}</td><td>${esc(p.action)}</td><td class="mono"><b>${esc(p.subject)}</b></td><td class="mono faint">${esc(p.version || '')}</td>
        <td>${esc(p.requested_by || '')}</td><td class="mono">${esc(p.commandline || '')}</td></tr>`)))}

    ${hsection('cmd', 'Executed commands', cmds.length, 'Rebuilt from auditd (hex arguments decoded, auid mapped to the logged-in user) and from vim command history. Shell histories are searchable as normal files.',
      (cmds.length > 20 ? `<input id="hCmdF" class="input" placeholder="Filter commands…" value="${esc(H.cmdFilter)}" style="margin-bottom:8px;max-width:360px">` : '') +
      `<div id="hCmds"></div>`)}

    ${hsection('net', 'Contacts and edited files', d.net.length + d.edited.length, 'Hosts reached with wget (HSTS cache) and SSH (known_hosts), and files edited in vim (viminfo).',
      htable(['Time', 'Host / file', 'How', 'Account'], [...d.net.map(n => ({ ...n, how: n.via })), ...d.edited.map(e => ({ ...e, how: 'edited in ' + e.via }))]
        .map(n => `<tr ${src(n)}><td class="mono">${esc(n.ts || '')}</td><td class="mono">${n.subject === '(hashed)' ? '<span class="faint">(hashed host name)</span>' : `<a class="lnk" data-q="${esc(n.subject)}">${esc(n.subject)}</a>`}</td>
          <td>${esc(n.how)}</td><td>${esc(n.owner || '')}</td></tr>`)))}
  `;
  const drawCmds = () => {
    const f = H.cmdFilter.toLowerCase();
    const list = cmds.filter(c => !f || (c.command + ' ' + c.user + ' ' + (c.exe || '')).toLowerCase().includes(f));
    $('#hCmds').innerHTML = htable(['Time (UTC)', 'User', 'Command', 'Program', 'Folder', 'Source'], list.slice(-1500).map(c => `<tr ${src(c)}>
      <td class="mono">${esc(c.ts || '')}</td><td class="mono">${esc(c.user)}${c.uid != null && c.uid !== undefined ? `<span class="faint"> as uid ${esc(c.uid)}</span>` : ''}</td>
      <td class="mono"><b>${esc(c.command)}</b></td><td class="mono faint">${esc(c.exe || '')}</td><td class="mono faint">${esc(c.cwd || '')}</td><td class="faint">${esc(c.via)}</td></tr>`));
    bindHostRows($('#hCmds'));
  };
  drawCmds();
  if ($('#hCmdF')) $('#hCmdF').oninput = e => { H.cmdFilter = e.target.value; drawCmds(); };
  bindHostRows(el);
  mountLoginMap($('#hostLoginMap'), { panel: false });
  $$('[data-epq]', el).forEach(b => b.onclick = e => { e.stopPropagation(); searchEpisode(+b.dataset.epq); });
  $$('[data-epw]', el).forEach(b => b.onclick = e => { e.stopPropagation(); const x = d.episodes.find(y => y.n === +b.dataset.epw); windowSearch(x.start, x.end); });
  $$('[data-blq]', el).forEach(b => b.onclick = e => { e.stopPropagation(); searchFor(b.dataset.blq); });
  $$('[data-hj]', el).forEach(a => a.onclick = e => { e.preventDefault(); $('#h-' + a.dataset.hj).scrollIntoView({ behavior: 'smooth', block: 'start' }); });
}
function bindHostRows(root) {
  $$('[data-q]', root).forEach(a => a.onclick = e => { e.stopPropagation(); searchFor(a.dataset.q); });
  $$('[data-hf]', root).forEach(r => r.onclick = e => { e.stopPropagation(); if (r.dataset.hf) openViewer(+r.dataset.hf, +r.dataset.hl); });
  $$('[data-epjump]', root).forEach(b => b.onclick = e => { e.stopPropagation(); jumpToEpisode(+b.dataset.epjump); });
}

function episodeChart(chart) {
  const W = 640, H = 90, n = chart.length, bw = W / Math.max(1, n), max = Math.max(1, ...chart.map(c => c[1]));
  const bars = chart.map((c, i) => {
    const h = Math.max(c[1] ? 1.5 : 0, (c[1] / max) * (H - 18));
    return `<rect x="${(i * bw).toFixed(1)}" y="${(H - 14 - h).toFixed(1)}" width="${Math.max(1, bw - 1).toFixed(1)}" height="${h.toFixed(1)}" class="${c[2] ? 'epbar on' : 'epbar'}"><title>${c[0]}: ${c[1]} events</title></rect>`;
  }).join('');
  const step = Math.ceil(n / 8);
  const ticks = chart.map((c, i) => i % step === 0 ? `<span style="left:${(i / n * 100).toFixed(2)}%">${c[0]}</span>` : '').join('');
  return `<div class="epchartwrap"><svg viewBox="0 0 ${W} ${H - 14}" class="epchart" preserveAspectRatio="none" role="img" aria-label="Events per minute">${bars}</svg>
    <div class="epticks">${ticks}</div></div>`;
}
function episodeCard(e) {
  const t = e.totals || {}, top = (k, lab) => (e.top||{})[k] && e.top[k].length ? `<dt>${lab}</dt><dd class="mono">${e.top[k].slice(0, 5).map(([x, c]) => `<a class="lnk" data-q="${esc(x.replace(/:\d+$/, ''))}">${esc(x)}</a> <span class="faint">×${fmtN(c)}</span>`).join(', ')}</dd>` : '';
  const facts = [];
  if (t.msg) facts.push(['Messages', fmtN(t.msg)]);
  if (t.out || t.defer || t.fail) facts.push(['Deliveries', `${fmtN(t.out || 0)} sent · ${fmtN(t.defer || 0)} deferred · ${fmtN(t.fail || 0)} failed`]);
  if (t.net_out) facts.push(['Outbound SMTP connections', fmtN(t.net_out)]);
  const sat = ['conn', 'drop', 'timeout', 'refused', 'limit', 'net_in'].reduce((a, k) => a + (t[k] || 0), 0);
  if (sat) facts.push(['Inbound SMTP connection events', fmtN(sat)]);
  const res = ['syn_flood', 'conntrack_full', 'oom', 'nospace', 'fork_fail', 'fd_exhaust', 'kernel_mem'].filter(k => t[k]);
  if (res.length) facts.push(['Resource exhaustion', res.map(k => `${k.replace(/_/g, ' ')} ×${t[k]}`).join(', ')]);
  (e.aspects || []).filter(a => a.series !== 'resource').forEach(a => facts.push([a.label, `peak ${fmtN(a.peak)}/min`]));
  return `<div class="epcard">
    <div class="row" style="align-items:baseline;flex-wrap:wrap;gap:8px">
      <span class="eptag big">EP#${e.n}</span><h3 style="margin:0">${esc(e.title)}</h3>
      <span class="mono">${esc(e.start)} → ${esc(e.end.slice(0, 10) === e.start.slice(0, 10) ? e.end.slice(11) : e.end)}</span><span class="muted">${e.minutes} min</span>
      <span class="grow"></span><button class="btn small" data-epq="${e.n}">All tagged lines</button><button class="btn small" data-epw="${e.n}">Everything in this window</button>
      <a class="btn small" href="/api/export/episodes?episodes=${e.n}&format=pdf" download title="Download this episode as PDF evidence">PDF</a>
      <a class="btn small" href="/api/export/episodes?episodes=${e.n}&format=xlsx" download title="Download this episode as Excel evidence">XLSX</a></div>
    ${corrBadge(e.corr_score, e.corr_kinds)}
    ${episodeChart(e.chart || [])}
    <div class="epgrid"><dl class="kv">${facts.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>
      <dl class="kv">${top('user', 'Submitted by')}${top('sender', 'Sender')}${top('dom', 'Recipient domains')}${top('relay', 'Remote servers')}${top('dst', 'Targets')}${top('peer', 'Connecting from')}</dl></div>
    ${(e.scripts||[]).length ? `<h4>Submitted from</h4>` + e.scripts.map(x => `<div class="mono epline" ${src(x)}>${esc(x.cwd)} <span class="faint">${esc(x.args)} ×${fmtN(x.count)}</span></div>`).join('') : ''}
    ${(e.related||[]).length ? `<h4>What started it (15 min before → end)</h4>` + e.related.map(r => `<div class="epline ep-clickrow" data-hf="${r.file_id}" data-hl="${r.line}">${sevTag(r.severity)}
      <span class="mono faint">${esc(r.ts || '')}</span> <a class="lnk mono faint" data-hf="${r.file_id}" data-hl="${r.line}">${esc(r.rel)}:${r.line}</a>
      <br><span class="mono">${esc(r.snippet)}</span></div>`).join('') : ''}
    <h4>Tagged in</h4>${(e.files||[]).map(f => `<div class="epline ep-clickrow" data-hf="${f.file_id}" data-hl="${f.first_line}"><span class="mono">${esc(f.rel)}</span> <span class="faint">${fmtN(f.events)} events — <a class="lnk mono">open at line ${f.first_line}</a></span></div>`).join('')}
    ${(e.overlaps || []).length ? `<h4>Running at the same time</h4><div class="ep-overlaps">${e.overlaps.map(o =>
      `<div class="row" style="gap:8px;align-items:baseline"><span class="eptag" style="cursor:pointer" data-epjump="${o.n}">EP#${o.n}</span><b>${esc(o.title)}</b>
       <span class="mono faint" style="font-size:12px">${esc(o.start)} → ${esc(o.end)}</span>
       <button class="btn small ghost" data-epjump="${o.n}">View ↗</button></div>`).join('')}</div>` : ''}
  </div>`;
}

function srcRel(d, rel) {
  const f = (d._fileByRel || (d._fileByRel = {}));
  if (!Object.keys(f).length) { /* built lazily below */ }
  return rel && d._relIds && d._relIds[rel] ? `data-hf="${d._relIds[rel]}" data-hl="1"` : '';
}
function sniffCard(e) {
  const tech = (e.techniques||[]).map(t => `<span class="tchip" style="border-color:var(--high);color:var(--high)">${esc(t.label)}${t.count > 1 ? ' ×' + t.count : ''}</span>`).join(' ');
  const when = e.start ? `<span class="mono">${esc(e.start)}${e.end ? ' → ' + esc(e.end.slice(0, 10) === e.start.slice(0, 10) ? e.end.slice(11) : e.end) : ''}</span>${e.minutes ? `<span class="muted">${e.minutes} min</span>` : ''}`
    : '<span class="muted">time unknown — reconstructed from configuration left in place</span>';
  const creds = (e.signals||[]).filter(s => s.rule === 'cleartext_creds');
  const rest = (e.signals||[]).filter(s => s.rule !== 'cleartext_creds');
  return `<div class="epcard" style="border-left-color:${e.mitm ? 'var(--high)' : 'var(--medium)'}">
    <div class="row" style="align-items:baseline;flex-wrap:wrap;gap:8px">
      <span class="eptag big" style="${e.mitm ? '' : 'background:var(--medium)'}">EP#${e.n}</span><h3 style="margin:0">${esc(e.title)}</h3>
      ${when}<span class="grow"></span>
      <button class="btn small" data-epq="${e.n}">All tagged lines</button>${e.start ? `<button class="btn small" data-epw="${e.n}">Everything in this window</button>` : ''}
      <a class="btn small" href="/api/export/episodes?episodes=${e.n}&format=pdf" download title="Download this episode as PDF evidence">PDF</a>
      <a class="btn small" href="/api/export/episodes?episodes=${e.n}&format=xlsx" download title="Download this episode as Excel evidence">XLSX</a></div>
    ${corrBadge(e.corr_score, e.corr_kinds)}
    <div style="margin:8px 0 4px">${tech}</div>
    ${creds.length ? `<h4>Plaintext credentials captured (${creds.length})</h4>` + creds.slice(0, 20).map(s => `<div class="epline mono" ${src(s)}>${esc(s.snippet)}</div>`).join('') : ''}
    <h4>Signals</h4>${rest.slice(0, 30).map(s => `<div class="epline ep-clickrow" data-hf="${s.file_id}" data-hl="${s.line}">${sevTag(s.severity)}
      <span class="mono faint">${esc(s.ts || '(from config)')}</span> <a class="lnk mono faint" data-hf="${s.file_id}" data-hl="${s.line}">${esc(s.rel)}:${s.line}</a>
      <br><span class="mono">${esc(s.snippet)}</span></div>`).join('')}
    <h4>Tagged in</h4>${(e.files||[]).map(f => `<div class="epline ep-clickrow" data-hf="${f.file_id}" data-hl="${f.first_line}"><span class="mono">${esc(f.rel || '')}</span> <span class="faint">${fmtN(f.events)} signal(s) — <a class="lnk mono">open at line ${f.first_line}</a></span></div>`).join('')}
    ${(e.overlaps || []).length ? `<h4>Running at the same time</h4><div class="ep-overlaps">${e.overlaps.map(o =>
      `<div class="row" style="gap:8px;align-items:baseline"><span class="eptag" style="cursor:pointer" data-epjump="${o.n}">EP#${o.n}</span><b>${esc(o.title)}</b>
       <span class="mono faint" style="font-size:12px">${esc(o.start)} → ${esc(o.end)}</span>
       <button class="btn small ghost" data-epjump="${o.n}">View ↗</button></div>`).join('')}</div>` : ''}
  </div>`;
}

function dhcpCard(e) {
  const sus = e.suspects || {};
  const exhausted = sus.exhausted;
  const color = exhausted ? 'var(--high)' : 'var(--medium)';
  const macs = (sus.sample_macs || []).slice(0, 8);
  const iface = (sus.interfaces || []).join(', ') || 'unknown';
  const oui = sus.suspect_oui;

  const suspectBlock = `
    <div class="dhcp-suspect">
      <div class="row" style="gap:10px;flex-wrap:wrap;align-items:baseline">
        <span class="faint" style="font-size:12px">Interface:</span>
        <code style="font-size:12px">${esc(iface)}</code>
        <span class="faint" style="font-size:12px">Unique MACs seen:</span>
        <b>${fmtN(sus.unique_macs || 0)}</b>
        ${oui ? `<span class="faint" style="font-size:12px">Dominant prefix:</span>
          <code style="color:var(--high);font-size:12px">${esc(oui)}:xx:xx</code>
          <span class="faint" style="font-size:12px">(${sus.top_oui_count} of ${sus.unique_macs} MACs — tool-generated)</span>` : ''}
      </div>
      ${macs.length ? `<div style="margin-top:6px;display:flex;flex-wrap:wrap;gap:5px">${macs.map(m =>
        `<code class="tchip" style="font-size:11px;border-color:var(--high)">${esc(m)}</code>`).join('')}
        ${(sus.unique_macs||0) > macs.length ? `<span class="faint" style="font-size:12px;align-self:center">+${(sus.unique_macs||0) - macs.length} more…</span>` : ''}</div>` : ''}
      ${exhausted ? `<div class="callout" style="margin-top:8px;border-color:var(--high);color:var(--high)">
        <b>Pool exhausted</b> — 'no free leases' responses detected. Legitimate hosts were denied IP addresses during this window.</div>` : ''}
    </div>`;

  return `<div class="epcard" style="border-left-color:${color}">
    <div class="row" style="align-items:baseline;flex-wrap:wrap;gap:8px">
      <span class="eptag big" style="background:${color}">EP#${e.n}</span>
      <h3 style="margin:0">${esc(e.title)}</h3>
      <span class="mono">${esc(e.start)} → ${esc(e.end.slice(0,10)===e.start.slice(0,10)?e.end.slice(11):e.end)}</span>
      <span class="muted">${e.minutes} min</span>
      <span class="grow"></span>
      <button class="btn small" data-epq="${e.n}">All tagged lines</button>
      <a class="btn small" href="/api/export/episodes?episodes=${e.n}&format=pdf" download>PDF</a>
      <a class="btn small" href="/api/export/episodes?episodes=${e.n}&format=xlsx" download>XLSX</a></div>
    ${corrBadge(e.corr_score, e.corr_kinds)}
    <div style="margin:10px 0 4px"><b>Suspect traffic:</b></div>
    ${suspectBlock}
    ${e.related && e.related.length ? `<h4>Related findings (15 min before → end)</h4>` +
      e.related.map(r => `<div class="epline ep-clickrow" data-hf="${r.file_id}" data-hl="${r.line}">${sevTag(r.severity)}
        <span class="mono faint">${esc(r.ts||'')}</span>
        <a class="lnk mono faint" data-hf="${r.file_id}" data-hl="${r.line}">${esc(r.rel)}:${r.line}</a>
        <br><span class="mono">${esc(r.snippet)}</span></div>`).join('') : ''}
    <h4>Tagged in</h4>${(e.files||[]).map(f =>
      `<div class="epline ep-clickrow" data-hf="${f.file_id}" data-hl="${f.first_line||1}">
        <span class="mono">${esc(f.rel||'')}</span>
        <span class="faint"> — open at line ${f.first_line||1}</span></div>`).join('')}
    ${(e.overlaps||[]).length ? `<h4>Running at the same time</h4><div class="ep-overlaps">${e.overlaps.map(o =>
      `<div class="row" style="gap:8px;align-items:baseline"><span class="eptag" style="cursor:pointer" data-epjump="${o.n}">EP#${o.n}</span><b>${esc(o.title)}</b>
       <span class="mono faint" style="font-size:12px">${esc(o.start)} → ${esc(o.end)}</span>
       <button class="btn small ghost" data-epjump="${o.n}">View ↗</button></div>`).join('')}</div>` : ''}
  </div>`;
}

/* ---------------------------------------------------------------- triage --- */
const TR = { status: 'unreviewed', sev: '', cat: '', q: '', sort: 'score', items: [], total: 0, offset: 0, pageSize: 200, sel: 0, cur: null, scope: 'this', value: '', panel: null, stats: null, timeline: null };
const SCOPE_LABEL = { this: 'Just this finding', pattern: 'Same text pattern, everywhere', rule_file: 'This rule in this file',
  rule: 'This rule everywhere', value: 'Any finding mentioning a value' };
async function renderTriage() {
  const el = $('#v-triage');
  el.innerHTML = `<div class="row" style="align-items:baseline;flex-wrap:wrap;gap:10px">
      <h1 style="margin:0">Triage</h1><span class="muted" id="trProg"></span><span class="grow"></span>
      <button class="btn small" id="trLeads">Leads</button><button class="btn small" id="trLearn">What Crumbs learned</button></div>
    <div class="trbar"><div id="trBar"></div></div>
    <p class="sub">Judge each finding. A verdict can reach further than one finding; dismissed findings leave the timelines and Host view,
      confirmed ones turn their IPs, domains, files and accounts into IOCs that re-rank the queue and surface leads.
      Keys: <kbd>J</kbd>/<kbd>K</kbd> move · <kbd>V</kbd> valid · <kbd>F</kbd> false positive · <kbd>U</kbd> unsure · <kbd>1</kbd>–<kbd>5</kbd> reach · <kbd>O</kbd> open file</p>
    <div class="row" style="gap:8px;flex-wrap:wrap;margin-bottom:8px">
      <div class="seg" role="group">${['unreviewed', 'valid', 'fp', 'unsure', 'all'].map(s => `<button type="button" data-trs="${s}" aria-pressed="${TR.status === s}">${{ unreviewed: 'To review', valid: 'Valid', fp: 'False positive', unsure: 'Unsure', all: 'All' }[s]}</button>`).join('')}</div>
      <select id="trSort" class="input" style="width:auto" title="Order">${[['score', 'Most important'], ['newest', 'Newest first'], ['oldest', 'Oldest first'], ['severity', 'By severity']].map(([v, l]) => `<option value="${v}" ${TR.sort === v ? 'selected' : ''}>${l}</option>`).join('')}</select>
      <select id="trSev" class="input" style="width:auto"><option value="">All severities</option>${['high', 'medium', 'low', 'high,medium'].map(v => `<option ${TR.sev === v ? 'selected' : ''} value="${v}">${v === 'high,medium' ? 'high + medium' : v}</option>`).join('')}</select>
      <select id="trCat" class="input" style="width:auto"><option value="">All categories</option>${(TR._cats || []).map(c => `<option ${TR.cat === c ? 'selected' : ''} value="${esc(c)}">${esc(c)}</option>`).join('')}</select>
      <input id="trQ" class="input" placeholder="Filter text or path…" value="${esc(TR.q)}" style="max-width:240px">
    </div>
    <div id="trTimeline" class="trtl"></div>
    <div id="trPanel"></div>
    <div class="trgrid"><div id="trList" class="trlist"></div><div id="trDetail" class="trdetail"></div></div>`;
  $$('[data-trs]', el).forEach(b => b.onclick = () => { TR.status = b.dataset.trs; TR.sel = 0; TR.offset = 0; renderTriage(); });
  $('#trSort').onchange = e => { TR.sort = e.target.value; TR.sel = 0; TR.offset = 0; loadQueue(); };
  $('#trSev').onchange = e => { TR.sev = e.target.value; TR.sel = 0; TR.offset = 0; loadQueue(); };
  $('#trCat').onchange = e => { TR.cat = e.target.value; TR.sel = 0; TR.offset = 0; loadQueue(); };
  let tq; $('#trQ').oninput = e => { clearTimeout(tq); tq = setTimeout(() => { TR.q = e.target.value; TR.sel = 0; TR.offset = 0; loadQueue(); }, 250); };
  $('#trLeads').onclick = () => togglePanel('leads');
  $('#trLearn').onclick = () => togglePanel('learn');
  if (TR.panel) drawPanel();
  await loadQueue();
}
async function loadStats() {
  TR.stats = await api('/api/triage/stats');
  const s = TR.stats, done = s.total - s.unreviewed;
  $('#trProg').textContent = `${fmtN(done)} of ${fmtN(s.total)} judged · ${fmtN(s.valid)} valid · ${fmtN(s.fp)} false positive · ${fmtN(s.unsure)} unsure`;
  $('#trBar').style.width = (s.total ? (100 * done / s.total) : 0).toFixed(1) + '%';
  $('#cTriage').textContent = s.unreviewed ? fmtN(s.unreviewed) : '';
}
async function loadQueue() {
  const p = new URLSearchParams({ status: TR.status, sort: TR.sort, limit: TR.pageSize, offset: TR.offset });
  if (TR.sev) p.set('severity', TR.sev); if (TR.cat) p.set('category', TR.cat); if (TR.q) p.set('q', TR.q);
  const [d] = await Promise.all([api('/api/triage?' + p), loadStats()]);
  TR.items = d.items; TR.total = d.total; TR.timeline = d.timeline; TR.undated = d.undated;
  TR._cats = d.categories; TR.sel = 0;
  const cat = $('#trCat');
  if (cat && cat.children.length !== (d.categories.length + 1)) cat.innerHTML = '<option value="">All categories</option>' + d.categories.map(c => `<option ${TR.cat === c ? 'selected' : ''} value="${esc(c)}">${esc(c)}</option>`).join('');
  drawTimeline();
  drawQueue();
  if (TR.items.length) selectItem(0); else $('#trDetail').innerHTML = `<div class="empty"><h2>${TR.status === 'unreviewed' ? 'Nothing left to review here' : 'Nothing here'}</h2></div>`;
}
function drawTimeline() {
  const box = $('#trTimeline'); if (!box) return;
  const tl = TR.timeline || [];
  if (!tl.length) { box.innerHTML = ''; return; }
  const max = Math.max(1, ...tl.map(d => d.n));
  box.innerHTML = `<div class="trtlbars">${tl.map(d => `<div class="trtlbar" title="${d.day}: ${d.n} finding(s), ${d.unreviewed} to review" data-day="${d.day}">
      <div class="trtlfill" style="height:${Math.max(2, d.n / max * 42)}px"><div class="trtlrev" style="height:${d.unreviewed / max * 42}px"></div></div></div>`).join('')}</div>
    <div class="trtlaxis"><span>${tl[0].day}</span><span class="faint">${fmtN(tl.reduce((a, d) => a + d.n, 0))} dated${TR.undated ? ` · ${fmtN(TR.undated.n)} undated` : ''}</span><span>${tl[tl.length - 1].day}</span></div>`;
  $$('[data-day]', box).forEach(b => b.onclick = () => { TR.q = b.dataset.day; TR.sort = 'oldest'; TR.offset = 0; renderTriage(); });
}
function vchip(v) { return v ? `<span class="vchip ${v}">${{ valid: 'valid', fp: 'false positive', unsure: 'unsure' }[v]}</span>` : ''; }
function drawQueue() {
  const from = TR.total ? TR.offset + 1 : 0, to = Math.min(TR.offset + TR.pageSize, TR.total);
  const pager = TR.total > TR.pageSize ? `<div class="row" style="gap:6px;margin:6px 0 4px">
      <button class="btn small" id="trPrev" ${TR.offset === 0 ? 'disabled' : ''}>‹ Prev</button>
      <span class="faint" style="font-size:12px">${fmtN(from)}–${fmtN(to)} of ${fmtN(TR.total)}</span>
      <button class="btn small" id="trNext" ${to >= TR.total ? 'disabled' : ''}>Next ›</button></div>` : '';
  const sortLabel = { score: 'most important first', newest: 'newest first', oldest: 'oldest first', severity: 'by severity' }[TR.sort];
  $('#trList').innerHTML = `<div class="faint" style="font-size:12.5px;margin:0 0 6px">${fmtN(TR.total)} finding(s), ${sortLabel}</div>${pager}` +
    TR.items.map((x, i) => `<div class="tritem${i === TR.sel ? ' on' : ''}" data-tri="${i}">
      <div class="row" style="gap:6px">${sevTag(x.severity)}<b style="font-size:13px">${esc(x.description)}</b>${vchip(x.verdict)}</div>
      <div class="mono faint" style="font-size:11.5px">${esc((x.rel || 'case-wide').split('/').slice(-2).join('/'))}${x.line_no ? ':' + x.line_no : ''} ${esc(x.ts || '')}</div>
      ${x.why.length ? `<div class="trwhy">${x.why.map(w => esc(w)).join(' · ')}</div>` : ''}
      ${(x.corr_score >= 2) ? `<div class="trwhy" style="color:var(--ok,#5fbf8f)">${corrBadge(x.corr_score, x.corr_kinds, true)}</div>` : ''}</div>`).join('');
  $$('[data-tri]').forEach(r => r.onclick = () => selectItem(+r.dataset.tri));
  if ($('#trPrev')) $('#trPrev').onclick = () => { TR.offset = Math.max(0, TR.offset - TR.pageSize); loadQueue(); };
  if ($('#trNext')) $('#trNext').onclick = () => { TR.offset += TR.pageSize; loadQueue(); };
}
async function selectItem(i) {
  TR.sel = i;
  $$('.tritem').forEach((r, j) => r.classList.toggle('on', j === i));
  const it = TR.items[i]; if (!it) return;
  $$('.tritem')[i]?.scrollIntoView({ block: 'nearest' });
  const f = TR.cur = await api('/api/finding/' + it.id);
  f.why = it.why; f.linked = it.linked || []; f.corr_score = it.corr_score; f.corr_kinds = it.corr_kinds;
  if (!f.values.includes(TR.value)) TR.value = f.linked[0] || f.values[0] || '';
  drawDetail();
}
function intelPanel(f) {
  const targets = f.intel || [];
  if (!targets.length) return '';
  const keys = f.intel_keys || {};
  return `<div class="intel"><div class="row" style="gap:8px"><b style="font-size:13px">Threat intel</b>
      <span class="grow"></span><button class="btn small" id="intelAll">Look up all</button>
      <button class="btn small ghost" data-view-go="settings">Keys…</button></div>
    ${targets.map((t, i) => intelRow(t, i, keys)).join('')}</div>`;
}
function intelRow(t, i, keys) {
  const provs = t.providers || [];
  const cached = t.cached || {};
  const body = provs.map(p => {
    const r = cached[p];
    const lab = { virustotal: 'VirusTotal', shodan: 'Shodan', abuseipdb: 'AbuseIPDB' }[p] || p;
    if (!r) return `<span class="ipill" data-intel="${esc(t.value)}" data-type="${esc(t.type)}" data-prov="${p}">${lab}: <span class="faint">${keys[p] ? 'look up' : 'needs key'}</span></span>`;
    const cls = intelClass(p, r);
    return `<span class="ipill ${cls}" title="${esc(r.summary || '')} (${esc(r.fetched || '')})" data-intel="${esc(t.value)}" data-type="${esc(t.type)}" data-prov="${p}">${lab}: ${esc(intelShort(p, r))}</span>`;
  }).join(' ');
  return `<div class="intelrow"><div class="mono" style="font-size:12.5px">${esc(t.value)}${t.note ? ` <span class="faint">${esc(t.note)}</span>` : ` <span class="faint">${esc(t.type)}</span>`}</div><div class="ipills">${body}</div></div>`;
}
function intelShort(p, r) {
  if (!r.ok) return r.summary || 'error';
  const d = r.data || {};
  if (p === 'virustotal') return d.found === false ? 'not seen' : `${d.malicious || 0}/${d.total || '?'}${d.label ? ' ' + d.label : ''}`;
  if (p === 'shodan') return d.found === false ? 'no data' : `${(d.ports || []).length} ports${(d.vulns || []).length ? ', ' + d.vulns.length + ' CVEs' : ''}`;
  if (p === 'abuseipdb') return `${d.score || 0}/100 (${d.reports || 0} reports)`;
  return r.summary;
}
function intelClass(p, r) {
  if (!r.ok) return '';
  const d = r.data || {};
  if (p === 'virustotal' && d.malicious >= 1) return d.malicious >= 3 ? 'bad' : 'warn';
  if (p === 'abuseipdb' && !d.whitelisted && d.score >= 50) return 'bad';
  if (p === 'abuseipdb' && !d.whitelisted && d.score >= 15) return 'warn';
  if (p === 'shodan' && (d.vulns || []).length) return 'warn';
  return 'okpill';
}
async function intelLookup(value, type, provider) {
  toast('Looking up ' + value + '…');
  try {
    const r = await post('/api/intel', { indicator: value, type, providers: provider ? [provider] : null });
    const asm = r.assessment;
    toast(`${value}: ${asm.level}${asm.notes.length ? ' — ' + asm.notes.join(', ') : ''}`, asm.level === 'malicious');
    // refresh the detail so cached pills show
    if (TR.cur && TR.cur.id) { const keep = TR.sel; TR.cur = await api('/api/finding/' + TR.cur.id); drawDetail(); }
  } catch (e) { toast(e.message, true); }
}
function drawDetail() {
  const f = TR.cur, reach = f.reach;
  const ctx = f.context.length ? `<div class="trctx">${f.context.map(c => `<div class="${c.n === f.line_no ? 'on' : ''}"><span class="ln">${c.n}</span><span class="mono">${esc(c.text)}</span></div>`).join('')}</div>`
    : `<div class="trctx"><div class="on"><span class="mono">${esc(f.snippet || '')}</span></div></div>`;
  const scopes = ['this', 'pattern', 'rule_file', 'rule', 'value'].map((s, k) => `<label class="trscope${TR.scope === s ? ' on' : ''}"><input type="radio" name="trsc" value="${s}" ${TR.scope === s ? 'checked' : ''}>
      <kbd>${k + 1}</kbd> ${SCOPE_LABEL[s]}${s !== 'value' ? ` <span class="faint">(${fmtN(reach[s])})</span>` : ''}
      ${s === 'value' ? `<select id="trVal" class="input" style="width:auto;margin-left:6px">${(f.values.length ? f.values : ['']).map(v => `<option ${v === TR.value ? 'selected' : ''}>${esc(v)}</option>`).join('')}</select>
        <input id="trValTxt" class="input" style="width:170px;margin-left:4px" placeholder="or type a value" value="">` : ''}</label>`).join('');
  $('#trDetail').innerHTML = `
    <div class="row" style="gap:8px;align-items:baseline;flex-wrap:wrap">${sevTag(f.severity)}<h2 style="margin:0">${esc(f.description)}</h2>
      <span class="mono faint">${esc(f.rule)}</span>${vchip(f.verdict)}<span class="grow"></span>
      ${f.file_id ? `<button class="btn small" id="trOpen">Open file <kbd>O</kbd></button>` : ''}</div>
    <div class="mono faint" style="margin:4px 0 8px">${esc(f.rel || 'case-wide')}${f.line_no ? ':' + f.line_no : ''} · ${esc(f.ts || 'no time')}${f.ts_end ? ' → ' + esc(f.ts_end) : ''}</div>
    ${f.why && f.why.length ? `<div class="trwhy big">${f.why.map(w => esc(w)).join('<br>')}</div>` : ''}
    <div class="trsnip mono">${esc(f.snippet || '')}</div>
    ${ctx}
    ${f.values.length ? `<div style="margin:8px 0"><span class="faint" style="font-size:12.5px">Values on this line:</span> ${f.values.map(v => `<span class="tchip trv" data-v="${esc(v)}" title="Search everywhere">${esc(v)}</span>`).join(' ')}</div>` : ''}
    ${(f.tools || []).length ? `<div class="callout" style="margin:8px 0"><b>Non-standard tool here:</b> ${f.tools.map(t => `${esc(t.tool)} <span class="faint">(${esc(t.category)})</span>`).join(', ')}</div>` : ''}
    ${corrBadge(f.corr_score, f.corr_kinds)}
    ${intelPanel(f)}
    ${f.verdict ? `<div class="callout" style="margin:8px 0">Judged <b>${{ valid: 'valid', fp: 'false positive', unsure: 'unsure' }[f.verdict]}</b> by a verdict on ${esc(f.how === 'this' ? 'this finding' : SCOPE_LABEL[f.how].toLowerCase())}.
      <button class="btn small" id="trUndo" style="margin-left:8px">Undo that verdict</button></div>` : ''}
    <h4 style="margin:12px 0 4px">Applies to</h4><div class="trscopes">${scopes}</div>
    <input id="trNote" class="input" placeholder="Note (optional): why" style="margin:8px 0;width:100%">
    <div class="row" style="gap:8px">
      <button class="btn vbtn valid" data-vd="valid">✓ Valid <kbd>V</kbd></button>
      <button class="btn vbtn fp" data-vd="fp">✗ False positive <kbd>F</kbd></button>
      <button class="btn vbtn unsure" data-vd="unsure">? Unsure <kbd>U</kbd></button></div>
    <div id="trPrev"></div>`;
  $$('input[name=trsc]').forEach(r => r.onchange = () => { TR.scope = r.value; drawDetail(); });
  if ($('#trVal')) $('#trVal').onchange = e => { TR.value = e.target.value; };
  $$('[data-vd]').forEach(b => b.onclick = () => judge(b.dataset.vd));
  $$('.trv').forEach(c => c.onclick = () => searchFor(c.dataset.v));
  if ($('#trOpen')) $('#trOpen').onclick = () => openViewer(f.file_id, f.line_no || 1);
  $$('[data-intel]', $('#trDetail')).forEach(b => b.onclick = () => intelLookup(b.dataset.intel, b.dataset.type, b.dataset.prov));
  if ($('#intelAll')) $('#intelAll').onclick = async () => { for (const t of (f.intel || [])) await intelLookup(t.value, t.type, null); };
  $$('[data-view-go]', $('#trDetail')).forEach(b => b.onclick = () => show(b.dataset.viewGo, { refresh: true }));
  if ($('#trUndo')) $('#trUndo').onclick = async () => { await post('/api/verdicts/' + f.verdict_id, null, 'DELETE'); toast('Verdict removed'); loadQueue(); };
}
async function judge(verdict, confirmed = false) {
  const f = TR.cur; if (!f) return;
  const value = TR.scope === 'value' ? (($('#trValTxt') && $('#trValTxt').value.trim()) || TR.value) : null;
  if (TR.scope === 'value' && !value) { toast('Choose or type a value first', true); return; }
  const body = { finding_id: f.id, verdict, scope: TR.scope, value, note: $('#trNote').value || null };
  const broad = TR.scope === 'value' || (TR.scope !== 'this' && (f.reach[TR.scope] || 0) > 1);
  if (broad && !confirmed && verdict !== 'unsure') {
    const p = await post('/api/verdicts/preview', body);
    $('#trPrev').innerHTML = `<div class="trpreview ${p.warnings.length ? 'warn' : ''}">
      <b>This verdict would mark ${plural(p.count, 'finding')} ${verdict === 'fp' ? 'as false positive' : 'as valid'}</b>
      <span class="faint">(${Object.entries(p.severity).map(([k, v]) => `${v} ${k}`).join(', ')}${p.already_judged ? `; ${p.already_judged} already judged` : ''})</span>
      ${p.warnings.map(w => `<div class="trwarn">⚠ ${esc(w)}</div>`).join('')}
      <div style="margin:6px 0">${p.samples.map(x => `<div class="mono faint" style="font-size:12px">${sevTag(x.severity)} ${esc((x.rel || '').split('/').pop())}:${x.line || ''} ${esc(x.snippet)}</div>`).join('')}</div>
      <div class="row" style="gap:8px"><button class="btn primary small" id="trGo">Apply to all ${fmtN(p.count)}</button><button class="btn small" id="trCancel">Cancel</button></div></div>`;
    $('#trGo').onclick = () => judge(verdict, true);
    $('#trCancel').onclick = () => { $('#trPrev').innerHTML = ''; };
    return;
  }
  let r;
  try { r = await post('/api/verdicts', body); } catch (e) { toast(e.message, true); return; }
  toast(`${{ valid: 'Valid', fp: 'False positive', unsure: 'Unsure' }[verdict]}: ${plural(r.covers, 'finding')}${verdict === 'valid' ? ' — its values are now confirmed IOCs' : ''}`);
  TR.scope = 'this';
  const keepSel = TR.sel;
  await loadQueue();
  if (TR.status !== 'all' && keepSel < TR.items.length) selectItem(keepSel);
  if (TR.panel) drawPanel();
}
function togglePanel(which) { TR.panel = TR.panel === which ? null : which; drawPanel(); }
async function drawPanel() {
  const box = $('#trPanel'); if (!box) return;
  if (!TR.panel) { box.innerHTML = ''; return; }
  if (TR.panel === 'learn') {
    const s = TR.stats || await api('/api/triage/stats');
    box.innerHTML = `<div class="panel trpanel"><div class="row"><h2 style="margin:0">What Crumbs learned from you</h2><span class="grow"></span><button class="btn small" data-close>Close</button></div>
      <div class="epgrid">
        <div><h4>Your verdicts (${s.verdicts.length})</h4>${s.verdicts.length ? s.verdicts.map(v => `<div class="trlearn"><span class="vchip ${v.verdict}">${v.verdict === 'fp' ? 'false positive' : v.verdict}</span>
          ${esc(SCOPE_LABEL[v.scope])}: <b>${esc(v.scope === 'value' ? v.value : (v.description || v.rule))}</b>${v.rel && v.scope !== 'rule' ? ` <span class="mono faint">${esc(v.rel.split('/').pop())}${v.line_no ? ':' + v.line_no : ''}</span>` : ''}
          <span class="faint">covers ${fmtN(v.covers)}</span>${v.note ? `<div class="faint" style="font-size:12px">${esc(v.note)}</div>` : ''}
          <button class="btn small ghost" data-undo="${v.id}">Undo</button></div>`).join('') : '<p class="faint">None yet.</p>'}</div>
        <div><h4>Confirmed IOCs (${s.iocs.length})</h4>
          <div class="row" style="gap:6px;margin-bottom:6px"><input id="iocAdd" class="input" placeholder="Add an IOC by hand (IP, domain, hash, path…)"><button class="btn small" id="iocAddBtn">Add</button></div>
          ${s.iocs.map(i => `<div class="trlearn"><span class="mono"><a class="lnk" data-q="${esc(i.value)}">${esc(i.value)}</a></span> <span class="faint">${esc(i.type)} · ${esc(i.source)}</span>
            ${i.source === 'added by you' ? `<button class="btn small ghost" data-iocdel="${esc(i.value)}">Remove</button>` : ''}</div>`).join('') || '<p class="faint">Mark findings valid and their values appear here.</p>'}
          <h4>Rule reliability here</h4>${s.rules.length ? htable(['Rule', 'Valid', 'FP', 'Precision'], s.rules.map(r => `<tr><td>${esc(r.description)}</td><td>${r.valid}</td><td>${r.fp}</td>
            <td><span class="${r.precision < 0.35 ? 'hflag low' : r.precision > 0.65 ? 'hflag high' : 'hflag medium'}">${Math.round(r.precision * 100)}%</span></td></tr>`)) : '<p class="faint">Grows as you judge findings.</p>'}</div></div></div>`;
    $$('[data-undo]', box).forEach(b => b.onclick = async () => { await post('/api/verdicts/' + b.dataset.undo, null, 'DELETE'); toast('Verdict removed'); await loadQueue(); drawPanel(); });
    $$('[data-iocdel]', box).forEach(b => b.onclick = async () => { await post('/api/iocs?value=' + encodeURIComponent(b.dataset.iocdel), null, 'DELETE'); await loadQueue(); drawPanel(); });
    $('#iocAddBtn').onclick = async () => { const v = $('#iocAdd').value.trim(); if (!v) return; await post('/api/iocs', { value: v }); toast('IOC added: the queue is re-ranked'); await loadQueue(); drawPanel(); };
  } else {
    box.innerHTML = '<div class="panel trpanel"><p class="muted">Looking for leads…</p></div>';
    const L = (await api('/api/triage/leads')).leads;
    box.innerHTML = `<div class="panel trpanel"><div class="row"><h2 style="margin:0">Leads from confirmed evidence</h2><span class="grow"></span><button class="btn small" data-close>Close</button></div>
      <p class="sub" style="margin:4px 0 10px">Lines that mention your confirmed IOCs but are not part of any finding you judged. Unflagged lines are where the analysis missed something.</p>
      ${L.length ? L.map(l => `<div class="lead"><div class="row" style="gap:8px;flex-wrap:wrap"><b class="mono">${esc(l.value)}</b><span class="faint">${esc(l.type)}</span>
          <span>${plural(l.lines, 'line')} in ${plural(l.files, 'file')}</span>${l.unreviewed_findings ? `<span class="hflag medium">${l.unreviewed_findings} unreviewed finding(s)</span>` : ''}
          <span class="mono faint">${esc(l.first || '')}${l.last && l.last !== l.first ? ' → ' + esc(l.last) : ''}</span><span class="grow"></span>
          ${l.unreviewed_findings ? `<button class="btn small" data-lq="${esc(l.value)}">Review its findings</button>` : ''}<button class="btn small" data-ls="${esc(l.value)}">Search everywhere</button></div>
        <div class="faint" style="font-size:12px;margin:3px 0">${l.top_files.map(([r, n]) => `${esc(r)} ×${n}`).join(' · ')}</div>
        ${l.samples.map(x => `<div class="epline mono" data-hf="${x.file_id}" data-hl="${x.line}" style="font-size:12px"><span class="faint">${esc(x.rel.split('/').pop())}:${x.line} ${esc(x.ts || '')}</span> ${esc(x.text)}</div>`).join('')}</div>`).join('')
        : '<p class="faint">No leads yet. Mark findings valid (or add IOCs) and Crumbs will look for every other place those values appear.</p>'}</div>`;
    $$('[data-lq]', box).forEach(b => b.onclick = () => { TR.q = b.dataset.lq; TR.status = 'unreviewed'; TR.panel = null; renderTriage(); });
    $$('[data-ls]', box).forEach(b => b.onclick = () => { $('#q').value = '"' + b.dataset.ls + '"'; setMode('query'); doSearch(); });
    $$('[data-hf]', box).forEach(r => r.onclick = () => openViewer(+r.dataset.hf, +r.dataset.hl));
  }
  $$('[data-close]', box).forEach(b => b.onclick = () => { TR.panel = null; drawPanel(); });
  $$('[data-q]', box).forEach(a => a.onclick = () => searchFor(a.dataset.q));
}
document.addEventListener('keydown', e => {
  if (current !== 'triage' || !TR.items.length) return;
  if (['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName)) return;
  if ($('#viewer') && !$('#viewer').hidden && $('#viewer').classList.contains('open')) return;
  const k = e.key.toLowerCase();
  if (k === 'j' || e.key === 'ArrowDown') { e.preventDefault(); if (TR.sel >= TR.items.length - 1 && TR.offset + TR.pageSize < TR.total) { TR.offset += TR.pageSize; loadQueue(); } else selectItem(Math.min(TR.items.length - 1, TR.sel + 1)); }
  else if (k === 'k' || e.key === 'ArrowUp') { e.preventDefault(); selectItem(Math.max(0, TR.sel - 1)); }
  else if (k === 'v') judge('valid'); else if (k === 'f') judge('fp'); else if (k === 'u') judge('unsure');
  else if (k === 'o' && TR.cur && TR.cur.file_id) openViewer(TR.cur.file_id, TR.cur.line_no || 1);
  else if ('12345'.includes(k) && k) { TR.scope = ['this', 'pattern', 'rule_file', 'rule', 'value'][+k - 1]; drawDetail(); }
});

async function judgeFinding(id) {
  // open Triage focused on one finding, whatever its status
  TR.status = 'all'; TR.q = ''; TR.sev = '';
  show('triage', { refresh: true });
  await new Promise(r => setTimeout(r, 300));
  const p = new URLSearchParams({ status: 'all', limit: 1000 });
  const d = await api('/api/triage?' + p);
  TR.items = d.items; TR.total = d.total;
  const i = TR.items.findIndex(x => x.id === id);
  drawQueue(); selectItem(i >= 0 ? i : 0);
}

/* ---------------------------------------------------------------- tools --- */
const CAT_ICON = { 'tunnel/proxy': '🔀', 'vpn/mesh/anon': '🕸', 'censorship-evasion/C2 transport': '📡', 'dns/icmp tunnel': '🧪',
  'web tunnel': '🌐', 'sniffer/MITM': '👂', 'scanner/recon': '🔎', 'exploit/cracking': '💥', 'post-exploitation/privesc': '⬆',
  rootkit: '🫥', miner: '⛏', 'offensive web middleware': '🧩' };
const TLS = { open: {}, filter: '' };
async function renderTools() {
  const el = $('#v-tools');
  el.innerHTML = '<p class="muted">Loading…</p>';
  let d;
  try { d = await api('/api/tools'); } catch (e) { el.innerHTML = `<div class="empty">${esc(e.message)}</div>`; return; }
  $('#cTools').textContent = d.tools.length ? fmtN(d.tools.length) : '';
  if (!d.tools.length) {
    el.innerHTML = `<div class="empty"><h2>No non-standard tools found</h2><p>Crumbs looks for tools that are not part of a base Debian install —
      proxies and tunnellers (socat, chisel, frp, sshuttle), VPN/mesh/anon (Tor, WireGuard, ZeroTier), sniffers and MITM (tcpdump, ettercap, sslstrip),
      scanners, exploit and post-exploitation kits, rootkits and miners — as dropped binaries, extra packages, config files, or mentions in logs, history and scripts.</p></div>`;
    return;
  }
  TLS.tools = d.tools;
  renderToolsBody();
}
function renderToolsBody() {
  const el = $('#v-tools');
  const f = TLS.filter.toLowerCase();
  const tools = TLS.tools.filter(t => !f || (t.tool + ' ' + t.category + ' ' + (t.locations || []).map(l => l.rel).join(' ')).toLowerCase().includes(f));
  const byCat = {};
  tools.forEach(t => (byCat[t.category] = byCat[t.category] || []).push(t));
  const strongN = TLS.tools.filter(t => t.dropped || (t.configs || []).length || (t.packages || []).length).length;
  el.innerHTML = `<div class="row" style="align-items:baseline;gap:10px"><h1 style="margin:0">Non-standard tools</h1>
      <span class="muted">${fmtN(TLS.tools.length)} found${strongN ? ` · ${strongN} installed or configured on the host` : ''}</span>
      <span class="grow"></span><input id="tlFilter" class="input" placeholder="Filter tools or paths…" value="${esc(TLS.filter)}" style="max-width:260px">
      <button class="btn small" id="tlExpand">Expand all</button></div>
    <p class="sub">Sorted by incidence: package installs and dropped binaries count more than log mentions. A dropped binary, config file or package install is stronger evidence than a log mention. Click any file to open it, or a line number to jump straight to it.</p>
    ${Object.keys(byCat).sort().map(cat => `<section class="hsec"><h2>${CAT_ICON[cat] || '•'} ${esc(cat)} <span class="muted">${byCat[cat].length}</span></h2>
      <div class="toollist">${byCat[cat].map(toolCard).join('')}</div></section>`).join('') || '<div class="empty">Nothing matches that filter.</div>'}`;
  let ft; $('#tlFilter').oninput = e => { clearTimeout(ft); ft = setTimeout(() => { TLS.filter = e.target.value; renderToolsBody(); }, 200); };
  $('#tlExpand').onclick = () => { const all = {}; tools.forEach(t => all[t.tool] = true); TLS.open = (Object.keys(TLS.open).length >= tools.length) ? {} : all; renderToolsBody(); };
  bindToolCards(el);
}
function toolCard(t) {
  const open = !!TLS.open[t.tool];
  const badges = [];
  if (t.dropped) badges.push(`<span class="hflag high">${t.dropped} dropped binary</span>`);
  else if ((t.binaries || []).length) badges.push(`<span class="hflag medium">packaged binary</span>`);
  if ((t.packages || []).length) badges.push(`<span class="hflag medium">apt/dpkg install</span>`);
  if ((t.configs || []).length) badges.push(`<span class="hflag medium">${t.configs.length} config</span>`);
  if (t.mentions) badges.push(`<span class="faint">${fmtN(t.mentions)} mention(s) in ${plural(t.files, 'file')}</span>`);
  (t.mitre || []).forEach(m => badges.push(`<span class="tchip mitre" title="MITRE ATT&CK ${m[1]}">${m[0]} ${esc(m[1])}</span>`));
  const totalHits = t.total_hits || (t.mentions || 0) + ((t.binaries||[]).length)*5 + ((t.packages||[]).length)*10 + ((t.configs||[]).length)*10;
  const locs = t.locations || [];
  const assocIps = (t.assoc_ips || []).filter(ip => ip.meta !== 'loopback' && ip.value !== '0.0.0.0' && ip.value !== '255.255.255.255');
  const body = open ? `<div class="toolbody">
    ${assocIps.length ? `<div class="toolloc"><div class="row" style="gap:8px;flex-wrap:wrap;align-items:center">
        <span class="toolkind">associated addresses</span>
        <span class="faint" style="font-size:12px">IPs seen in the same files as this tool</span></div>
      <div style="display:flex;flex-wrap:wrap;gap:5px;margin-top:4px">${assocIps.map(ip =>
        `<span class="tchip ${ip.meta==='public'?'':'private-ip'}" title="${esc(ip.meta||'')} · ${fmtN(ip.hits)} hits">${esc(ip.value)} <span class="faint">×${fmtN(ip.hits)}</span></span>`).join('')}</div></div>` : ''}
    ${locs.map(l => toolLocation(l)).join('')}
    ${t.location_total > locs.length ? `<div class="faint" style="padding:4px 8px">+${t.location_total - locs.length} more locations</div>` : ''}</div>` : '';
  return `<div class="toolcard ${open ? 'open' : ''}">
    <div class="toolhead" data-tool="${esc(t.tool)}">
      <span class="twist">${open ? '▾' : '▸'}</span>
      <div class="toolhead-main">
        <div class="row" style="gap:8px;flex-wrap:wrap;align-items:center">
          <b class="mono">${esc(t.tool)}</b>
          <span class="toolbadges">${badges.join(' ')}</span>
          <span class="grow"></span>
          <span class="faint" style="font-size:12px" title="Incidence score: package=×10, config=×10, binary=×5, mention=×1">score ${fmtN(totalHits)}</span>
          <span class="mono faint" style="font-size:12px">${esc(t.first || '')}${t.last && t.last !== t.first ? ' → ' + esc(t.last) : ''}</span>
          <button class="btn small ghost" data-toolq="${esc(t.tool)}" title="Search every line mentioning ${esc(t.tool)}">Search all</button>
        </div>
        ${t.description ? `<div class="tooldesc">${esc(t.description)}</div>` : ''}
      </div>
    </div>${body}</div>`;
}
function toolLocation(l) {
  const sev = l.strong ? 'high' : 'low';
  const lineBtns = (l.lines && l.lines.length) ? `<div class="toollines">${l.lines.slice(0, 40).map(n =>
    `<button data-tf="${l.file_id}" data-tl="${n}" ${l.file_id ? '' : 'disabled'}>${n}</button>`).join('')}${l.lines.length > 40 ? '<span class="faint">…</span>' : ''}</div>` : '';
  const head = l.file_id
    ? `<a class="lnk mono" data-tf="${l.file_id}" data-tl="${l.line || 1}">${esc(l.rel)}</a>`
    : `<span class="mono faint">${esc(l.rel)}</span>`;
  return `<div class="toolloc">
    <div class="row" style="gap:8px;align-items:baseline;flex-wrap:wrap">${sevTag(sev)}<span class="toolkind">${esc(l.kind)}</span>
      ${head}${l.count > 1 ? ` <span class="faint">×${fmtN(l.count)}</span>` : ''}
      <span class="grow"></span><span class="mono faint" style="font-size:12px">${esc(l.ts || '')}</span></div>
    ${l.sample ? `<div class="toolsample mono" data-tf="${l.file_id || ''}" data-tl="${l.line || 1}">${esc(l.sample)}</div>` : (l.detail ? `<div class="faint" style="font-size:12.5px;margin:2px 0 0 26px">${esc(l.detail)}</div>` : '')}
    ${lineBtns}</div>`;
}
function bindToolCards(el) {
  $$('.toolhead[data-tool]', el).forEach(h => h.onclick = e => {
    if (e.target.closest('[data-toolq]')) return;
    const t = h.dataset.tool; TLS.open[t] ? delete TLS.open[t] : (TLS.open[t] = true); renderToolsBody();
  });
  $$('[data-toolq]', el).forEach(b => b.onclick = e => { e.stopPropagation(); searchFor(b.dataset.toolq); });
  $$('[data-tf]', el).forEach(b => b.onclick = e => { e.stopPropagation(); if (b.dataset.tf) openViewer(+b.dataset.tf, +(b.dataset.tl || 1)); });
}

/* -------------------------------------------------------------- settings --- */
async function renderSettings() {
  const el = $('#v-settings');
  el.innerHTML = '<p class="muted">Loading…</p>';
  const d = await api('/api/intel/keys');
  el.innerHTML = `<h1 style="margin:0 0 4px">Settings &amp; API keys</h1>
    <p class="sub">Threat-intel lookups use your own API keys. Keys are stored only in this case's database and are sent only to the matching service. Crumbs never calls out on its own — you trigger each lookup.</p>
    <div class="panel" style="max-width:760px">
      <h2 style="margin-top:0">Threat intelligence</h2>
      ${Object.entries(d.providers).map(([p, info]) => `<div class="setrow">
        <div><b>${esc(info.label)}</b> <span class="faint">${esc(info.kinds.join(', '))}</span><div class="faint" style="font-size:12px">${esc(info.key_hint)}</div></div>
        <div class="row" style="gap:6px"><input type="password" class="input" id="key-${p}" placeholder="${d.keys[p] ? '•••••• (set)' : 'paste API key'}" style="width:260px">
          <button class="btn small" data-savekey="${p}">Save</button>${d.keys[p] ? `<button class="btn small ghost" data-delkey="${p}">Remove</button>` : ''}</div></div>`).join('')}
      <p class="faint" style="font-size:12.5px;margin-top:10px">Free keys: VirusTotal (virustotal.com/gui/my-apikey), Shodan (account.shodan.io), AbuseIPDB (abuseipdb.com/account/api).</p>
    </div>
    <div class="panel" style="max-width:760px"><h2 style="margin-top:0">Bulk enrichment</h2>
      <p class="sub" style="margin-top:0">Look up every confirmed IOC at once. The free VirusTotal tier is slow (about 4/min), so this paces itself and stops cleanly if a service rate-limits.</p>
      <button class="btn" id="bulkIntel">Enrich all confirmed IOCs</button><span class="muted" id="bulkInfo" style="margin-left:10px"></span>
      <div id="bulkOut" style="margin-top:10px"></div></div>`;
  $$('[data-savekey]', el).forEach(b => b.onclick = async () => {
    const p = b.dataset.savekey, k = $('#key-' + p).value.trim();
    if (!k) { toast('Paste a key first', true); return; }
    await post('/api/intel/keys', { provider: p, key: k }); toast(d.providers[p].label + ' key saved'); renderSettings();
  });
  $$('[data-delkey]', el).forEach(b => b.onclick = async () => { await post('/api/intel/keys', { provider: b.dataset.delkey, key: '' }); toast('Key removed'); renderSettings(); });
  $('#bulkIntel').onclick = async () => {
    const stats = await api('/api/triage/stats');
    const iocs = stats.iocs.filter(i => ['ip', 'ipv4', 'hash', 'md5', 'sha1', 'sha256', 'domain', 'url'].includes(i.type));
    if (!iocs.length) { toast('No confirmed IOCs yet — mark findings valid first', true); return; }
    $('#bulkInfo').textContent = `Enriching ${iocs.length}…`;
    const r = await post('/api/intel/bulk', { indicators: iocs.map(i => ({ value: i.value, type: i.type })) });
    $('#bulkInfo').textContent = r.stopped || `Done: ${r.results.length} enriched`;
    $('#bulkOut').innerHTML = htable(['Indicator', 'Assessment', 'Detail'], r.results.map(x => `<tr>
      <td class="mono"><a class="lnk" data-q="${esc(x.indicator)}">${esc(x.indicator)}</a></td>
      <td><span class="hflag ${x.assessment.level === 'malicious' ? 'high' : x.assessment.level === 'suspicious' ? 'medium' : 'low'}">${x.assessment.level}</span></td>
      <td class="faint">${esc(x.assessment.notes.join(', ') || Object.values(x.results).map(v => v.summary).join(' · '))}</td></tr>`));
    $$('[data-q]', $('#bulkOut')).forEach(a => a.onclick = () => searchFor(a.dataset.q));
  };
}

function baselineSection(bl) {
  const c = bl.counts, total = c.standard + c.modified + c.unowned + c.unverifiable;
  const pct = n => total ? Math.round(n / total * 100) : 0;
  const bar = `<div class="blbar" title="${fmtN(c.standard)} standard, ${fmtN(c.modified)} modified, ${fmtN(c.unowned)} unowned, ${fmtN(c.unverifiable)} unverifiable">
      <span class="blseg ok" style="width:${pct(c.standard)}%"></span><span class="blseg bad" style="width:${pct(c.modified)}%"></span>
      <span class="blseg warn" style="width:${pct(c.unowned)}%"></span><span class="blseg faint" style="width:${pct(c.unverifiable)}%"></span></div>
    <div class="row bllegend"><span><i class="ok"></i> ${fmtN(c.standard)} standard</span><span><i class="bad"></i> ${fmtN(c.modified)} modified</span>
      <span><i class="warn"></i> ${fmtN(c.unowned)} unowned</span><span><i class="faint"></i> ${fmtN(c.unverifiable)} unverifiable</span>${bl.missing ? `<span><i class="faint"></i> ${fmtN(bl.missing)} missing</span>` : ''}</div>`;
  const warn = bl.version_warning ? `<div class="callout" style="border-color:var(--medium);margin:8px 0">Most package files differ — the collected dpkg records are probably for different package versions than the binaries. Treat individual "modified" rows with care and re-collect <code>/var/lib/dpkg</code> from the same system state.</div>` : '';
  const modRows = [...(bl.conffiles_changed || []).map(x => ({ ...x, kind: 'config changed' })),
                   ...bl.modified.map(x => ({ ...x, kind: x.elf ? 'program changed' : (x.conffile ? 'config changed' : 'file changed') }))];
  const modTbl = (modRows.length ? htable(['', 'Path', 'Package', 'What', 'Modified'], modRows.slice(0, 300).map(m => `<tr data-hf="${m.file_id}" data-hl="1">
      <td>${sevTag(m.elf ? 'high' : 'medium')}</td><td class="mono"><b>${esc(m.path)}</b></td><td class="mono faint">${esc(m.package || '')}</td>
      <td>${esc(m.kind)}</td><td class="mono">${esc(m.ts || '')}</td></tr>`)) : '<p class="faint">Nothing differs from its package.</p>');
  const unoRows = (bl.unowned.length ? htable(['', 'Path', 'Type', 'Added', 'Size'], bl.unowned.slice(0, 300).map(u => `<tr data-hf="${u.file_id}" data-hl="1">
      <td>${sevTag(u.in_bin || u.elf ? 'high' : 'medium')}</td><td class="mono"><b>${esc(u.path)}</b></td>
      <td>${u.elf ? 'ELF program' : 'file'}${u.in_bin ? ' <span class="hflag high">in a program folder</span>' : ''}</td>
      <td class="mono">${esc(u.ts || '')}</td><td class="mono faint">${fmtN(u.size)}</td></tr>`)) : '<p class="faint">Every file in the system folders belongs to a package.</p>');
  const pkgChip = p => `<span class="tchip" data-blq="${esc(p.package)}" title="search for ${esc(p.package)}">${esc(p.package)}${p.version ? ` <span class="faint">${esc(p.version)}</span>` : ''}</span>`;
  const extra = `${bl.extra_suspicious.length ? `<h3 style="margin:14px 0 6px;color:var(--high)">Offensive / dual-use packages installed (${bl.extra_suspicious.length})</h3><div class="blchips">${bl.extra_suspicious.map(pkgChip).join(' ')}</div>` : ''}
    ${bl.extra_other.length ? `<h3 style="margin:14px 0 6px">Other extra packages (${bl.extra_other_total})</h3><div class="blchips">${bl.extra_other.map(pkgChip).join(' ')}${bl.extra_other_total > bl.extra_other.length ? ` <span class="faint">+${bl.extra_other_total - bl.extra_other.length} more</span>` : ''}</div>` : ''}
    ${bl.extra_common.length ? `<h3 style="margin:14px 0 6px">Common server packages <span class="faint">(normal for a web server)</span></h3><div class="blchips faint">${bl.extra_common.map(pkgChip).join(' ')}</div>` : ''}`;
  return hsection('base', 'Debian baseline', c.modified + c.unowned,
    'Every system file and installed package compared against what Debian shipped. Standard files match their package; modified and unowned files, and offensive extra packages, are where an intruder leaves marks.',
    `${warn}${bar}
     <h3 style="margin:16px 0 6px">Changed from their package (${modRows.length})</h3>${modTbl}
     <h3 style="margin:16px 0 6px">Not installed by any package (${fmtN(bl.unowned_total)})</h3>
     <p class="sub" style="margin:0 0 8px">Local config (your network settings, host keys, certificates, cron.d drop-ins, /var, /usr/local/share) is expected and excluded. What remains is genuinely extra.</p>${unoRows}
     <h3 style="margin:16px 0 6px">Installed packages vs a base Debian set <span class="faint">(${fmtN(bl.installed_total)} installed)</span></h3>${extra || '<p class="faint">No packages beyond a base install were recorded.</p>'}`);
}
