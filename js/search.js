/* ==========================================================================
   Global search — one box that finds anything in the app.
   Cases, vault entries, evidence, indicators, notes, tools, queries,
   detections, playbooks, CTF challenges, news, pages and actions.
   Syntax: "exact phrase", -exclude, in:tools, case:TN-2026-014, and the
   timeline filters (host: verdict: type: tag: after: before:) which offer
   to filter the current case's timeline.
   ========================================================================== */
const SCOPES = [['all','All','search'], ['case','Cases','folder-open'], ['entry','Vault','layers'], ['record','Evidence','clock'], ['ent','Indicators','fingerprint'], ['note','Notes','sticky-note'],
  ['tool','Tools','wrench'], ['query','Queries','scan-search'], ['rule','Detections','file-code'], ['playbook','Playbooks','list-checks'], ['chal','CTF','flag'], ['feed','News','rss'], ['action','Actions','command']];
const SCOPE_ALIAS = {cases:'case', case:'case', vault:'entry', entry:'entry', entries:'entry', evidence:'record', record:'record', records:'record', timeline:'record', indicator:'ent', indicators:'ent', ioc:'ent', iocs:'ent', entity:'ent', entities:'ent',
  note:'note', notes:'note', tool:'tool', tools:'tool', query:'query', queries:'query', dork:'query', dorks:'query', rule:'rule', rules:'rule', detection:'rule', detections:'rule', sigma:'rule', yara:'rule',
  playbook:'playbook', playbooks:'playbook', ctf:'chal', chal:'chal', challenge:'chal', challenges:'chal', flag:'chal', news:'feed', feed:'feed', intel:'feed', action:'action', actions:'action', command:'action'};
const TL_FIELD = /^(host|source|from|tag|type|kind|ent|verdict|after|before|is|has):/i;
const S = {open:false, q:'', scope:'all', at:0, flat:[], index:null};
function srchIndex(){
  const I = [], add = (kind, o) => I.push({kind, ...o});
  const nav = [['#/home','Dashboard','layout-dashboard'],['#/cases','Cases','folder-open'],['#/notes','Notes','sticky-note'],['#/toolbox','Toolbox','wrench'],['#/queries','Query library','scan-search'],
    ['#/ctf','CTF','flag'],['#/lab','Forensics kit','file-search'],['#/decoder','Decoder','binary'],['#/feeds','Threat Intel','rss'],['#/detections','Detections','file-code'],['#/entities','Entities','fingerprint'],
    ['#/reference','Reference','book-open'],['#/playbooks','Playbooks','list-checks'],['#/help','Help','circle-help'],['#/settings','Settings','settings']];
  for(const [h, l, i] of nav) add('action', {id:'go' + h, title:'Go to ' + l, sub:'Page', icon:i, text:l + ' page open go', run:() => go(h), w:2});
  const c0 = theCase();
  if(c0) for(const [k, l, i] of CASE_TABS) add('action', {id:'tab' + k, title:c0.code + ' · ' + l, sub:'Tab in ' + c0.name.split(' — ')[0], icon:i, text:l + ' ' + c0.name + ' ' + c0.code, run:() => go(caseHash(c0.id, k)), w:1});
  const acts = [['Capture evidence','plus','capture paste log new record', () => openCapture()], ['Add a vault entry','layers','new entry add person domain ip', () => entryDlg()], ['New case','folder-plus','create case', () => caseDlg()],
    ['New note','sticky-note','note todo', () => go('#/notes')], ['New CTF challenge','flag','ctf challenge add', () => { go('#/ctf'); setTimeout(() => clickAct('ctfNew'), 50); }],
    ['Inspect a file','file-search','file forensics exif hash strings', () => { UI.labTab = 'file'; go('#/lab'); }], ['Convert a timestamp','clock-3','epoch unix filetime webkit time', () => { UI.labTab = 'time'; go('#/lab'); }],
    ['Identify a hash','fingerprint','hash md5 ntlm bcrypt hashcat', () => { UI.labTab = 'hash'; go('#/lab'); }], ['Convert coordinates','compass','gps dms map geolocation', () => { UI.labTab = 'geo'; go('#/lab'); }],
    ['Export IOCs of this case','download','ioc csv stix export indicators', () => { go(caseHash(DB.active, 'report')); }], ['Print the report','file-text','pdf print report', () => { go(caseHash(DB.active, 'report')); setTimeout(printReport, 200); }],
    ['Run a playbook on this case','list-checks','playbook checklist', () => go('#/playbooks')], ['Export a backup of everything','download','backup export json', () => clickAct('exportAll')],
    ['Import a backup','upload','restore import backup', () => clickAct('importAll')], ['Import a case','upload','import case json', () => clickAct('importCase')],
    ['Switch theme','moon','dark light theme mode', () => clickAct('theme')], ['Add a tool','wrench','tool add new', () => toolDlg()]];
  if(DB.sample) acts.push(['Remove sample data','trash-2','sample demo delete remove', () => clickAct('removeSample')]);
  for(const [t, i, x, fn] of acts) add('action', {id:'a' + t, title:t, sub:'Action', icon:i, text:t + ' ' + x, run:fn, w:3});
  for(const c of DB.cases) add('case', {id:c.id, title:c.name, sub:c.code + ' · ' + ({active:'Active', review:'In review', closed:'Archived'}[c.status] || c.status), icon:c.icon, color:c.color, text:c.name + ' ' + c.code + ' ' + (c.scope || ''), body:c.scope, caseId:c.id, w:6});
  for(const e of DB.entries){ const t = TYPES[e.type]; if(!t) continue; const c = theCase(e.caseId);
    add('entry', {id:e.id, title:primary(e), sub:t.label + (c ? ' · ' + c.code : ''), icon:t.icon, tcolor:t.color, text:Object.values(e.fields).join(' ') + ' ' + e.tags.join(' ') + ' ' + (e.notes || '') + ' ' + t.label, body:e.notes || Object.entries(e.fields).map(([k, v]) => k + ': ' + v).join(' · '), caseId:e.caseId, mono:MONO_TYPES.has(e.type), w:5}); }
  for(const r of DB.records){ const c = theCase(r.caseId);
    add('record', {id:r.id, title:r.title, sub:typeLabel(r.type) + (c ? ' · ' + c.code : '') + (r.host ? ' · ' + r.host : '') + (r.ts ? ' · ' + E.fmtDate(r.ts, tz()) : ''), icon:(EVTYPE[r.type] || EVTYPE.note)[0], text:r.title + ' ' + r.body + ' ' + r.host + ' ' + r.source + ' ' + (r.tags || []).join(' ') + ' ' + (r.answer || ''), body:r.answer ? r.answer : r.body, caseId:r.caseId, w:4}); }
  for(const [id, g] of globalEnts()) add('ent', {id, title:g.v, sub:(E.LABEL[g.k] || g.k) + ' · ' + g.recs.length + ' record' + (g.recs.length === 1 ? '' : 's') + ' · ' + g.cases.size + ' case' + (g.cases.size === 1 ? '' : 's') + (verdictOf(id) ? ' · ' + verdictOf(id) : ''), icon:'fingerprint', text:g.v + ' ' + (E.LABEL[g.k] || g.k), mono:true, w:5});
  for(const n of DB.notes || []){ const c = n.caseId ? theCase(n.caseId) : null; add('note', {id:n.id, title:n.text.split('\n')[0].slice(0, 120), sub:'Note' + (c ? ' · ' + c.code : ' · General'), icon:'sticky-note', text:n.text, body:n.text, w:3}); }
  for(const t of DB.tools) add('tool', {id:t.id, title:t.name, sub:hostOf(t.url) + ' · ' + toolSub(t), icon:'wrench', text:t.name + ' ' + t.desc + ' ' + t.tags.join(' ') + ' ' + hostOf(t.url) + ' ' + toolSub(t), body:t.desc, w:3});
  for(const x of DB.queries || []) add('query', {id:x.id, title:x.name, sub:qcat(x.cat)[0] + ' · ' + x.engines.map(e => ENGINES[e] ? ENGINES[e][0] : e).join(', '), icon:'scan-search', text:x.name + ' ' + x.desc + ' ' + x.query + ' ' + x.tags.join(' '), body:x.query, codeBody:true, w:2});
  for(const r of DB.rules || []) add('rule', {id:r.id, title:r.title, sub:RTYPE[r.type][0] + ' · ' + sevOf(r.severity)[0] + (r.technique ? ' · ' + r.technique : ''), icon:RTYPE[r.type][1], text:r.title + ' ' + r.desc + ' ' + r.technique + ' ' + r.tags.join(' ') + ' ' + r.code, body:r.desc, w:2});
  for(const p of DB.playbooks || []) add('playbook', {id:p.id, title:p.name, sub:'Playbook · ' + p.steps.length + ' steps', icon:p.icon || 'list-checks', text:p.name + ' ' + p.desc + ' ' + p.steps.map(s => s.t + ' ' + s.h).join(' '), body:p.desc, w:2});
  for(const c of (DB.ctf || {}).chals || []) add('chal', {id:c.id, title:c.name, sub:ctfCat(c.cat)[0] + ' · ' + (c.points || 0) + ' pts · ' + ({todo:'To do', working:'Working', solved:'Solved'}[c.status]), icon:ctfCat(c.cat)[2], text:c.name + ' ' + c.notes + ' ' + c.flag + ' ' + ctfCat(c.cat)[0], body:c.flag || c.notes, w:3});
  for(const f of DB.feed) add('feed', {id:f.id, title:f.title, sub:f.source + ' · ' + E.fmtAgo(Math.max(0, Date.now() - f.ts)), icon:'rss', text:f.title + ' ' + f.body + ' ' + f.source, body:f.body, w:1});
  return I;
}
function srchParse(q){
  const out = {terms:[], neg:[], scope:null, caseCode:null, tl:[]};
  const re = /(-?)"([^"]+)"|(\S+)/g; let m;
  while((m = re.exec(q))){ const neg = m[1] === '-' || (m[3] && m[3].startsWith('-') && m[3].length > 1), raw = m[2] || m[3].replace(/^-/, '');
    const inm = !m[2] && raw.match(/^(?:in|is):(\w+)$/i); if(inm && SCOPE_ALIAS[inm[1].toLowerCase()]){ out.scope = SCOPE_ALIAS[inm[1].toLowerCase()]; continue; }
    const cm = !m[2] && raw.match(/^case:(\S+)$/i); if(cm){ out.caseCode = cm[1].toLowerCase(); continue; }
    if(!m[2] && TL_FIELD.test(raw)){ out.tl.push(m[0]); continue; }
    (neg ? out.neg : out.terms).push(raw.toLowerCase()); }
  return out;
}
/* typo tolerance: a title word within one edit (two for long words) of the term — swaps count as one */
function dl(a, b, max){ if(Math.abs(a.length - b.length) > max) return max + 1; const d = Array.from({length:a.length + 1}, (_, i) => [i, ...Array(b.length).fill(0)]); for(let j = 1; j <= b.length; j++) d[0][j] = j;
  for(let i = 1; i <= a.length; i++){ let best = 99; for(let j = 1; j <= b.length; j++){ const c = a[i - 1] === b[j - 1] ? 0 : 1; d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + c);
    if(i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1); best = Math.min(best, d[i][j]); } if(best > max) return max + 1; } return d[a.length][b.length]; }
const fuzzy = (title, t) => { const max = t.length >= 7 ? 2 : 1; return title.split(/[^a-z0-9]+/).some(w => w.length >= 3 && (dl(w, t, max) <= max || (w.length > t.length && dl(w.slice(0, t.length), t, max) <= max))); };
function srchScore(it, P){
  const title = it.title.toLowerCase(), text = (it.title + ' ' + it.sub + ' ' + it.text).toLowerCase();
  for(const n of P.neg) if(text.includes(n)) return 0;
  if(P.caseCode){ const c = it.caseId ? theCase(it.caseId) : null; if(!c || !(c.code.toLowerCase().includes(P.caseCode) || c.name.toLowerCase().includes(P.caseCode))) return 0; }
  if(!P.terms.length) return P.caseCode || P.scope ? it.w : 0;
  let s = 0;
  for(const t of P.terms){
    if(title === t) s += 120; else if(title.startsWith(t)) s += 70; else if(new RegExp('(^|[^a-z0-9])' + t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).test(title)) s += 45; else if(title.includes(t)) s += 30;
    else if(text.includes(t)) s += 12; else if(t.length >= 4 && t.length <= 24 && fuzzy(title, t)) s += 8; else return 0;
  }
  return s + it.w + (it.caseId && it.caseId === DB.active ? 3 : 0);
}
function hl(s, terms){ let h = esc(s); for(const t of terms.filter(x => x.length > 1).sort((a, b) => b.length - a.length)){ const e = esc(t).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); h = h.replace(new RegExp('(' + e + ')(?![^<]*>)', 'gi'), '<mark>$1</mark>'); } return h; }
function snippet(body, terms){
  const b = String(body || '').replace(/\s+/g, ' '); if(!b) return ''; const lb = b.toLowerCase(); let i = -1;
  for(const t of terms){ i = lb.indexOf(t); if(i >= 0) break; }
  const s = i > 60 ? '…' + b.slice(i - 50, i + 110) : b.slice(0, 160); return hl(s + (b.length > (i > 60 ? i + 110 : 160) ? '…' : ''), terms);
}
function srchRun(){
  const q = S.q.trim(), P = srchParse(q), scope = P.scope || S.scope;
  const all = S.index.map(it => ({it, s:srchScore(it, P)})).filter(x => x.s > 0).sort((a, b) => b.s - a.s);
  const counts = {}; for(const {it} of all) counts[it.kind] = (counts[it.kind] || 0) + 1;
  const special = [];
  const ioc = q && !P.tl.length ? E.extract(q).find(e => e.v.toLowerCase() === refang(q).toLowerCase() || e.v.toLowerCase() === q.toLowerCase()) : null;
  if(ioc) special.push({kind:'ioc', id:'ioc', title:ioc.v, sub:'Indicator · ' + (E.LABEL[ioc.k] || ioc.k), icon:'crosshair', mono:true, k:ioc.k, v:ioc.v});
  if(P.tl.length || (q && UI.route.area === 'case' && UI.route.tab === 'timeline')) special.push({kind:'tl', id:'tl', title:'Filter the ' + theCase().code + ' timeline', sub:(P.tl.concat(P.terms)).join(' ') || q, icon:'filter', q});
  let groups;
  if(scope === 'all'){ const order = ['action','case','entry','ent','record','note','chal','tool','query','rule','playbook','feed'];
    groups = order.map(k => ({k, items:all.filter(x => x.it.kind === k).slice(0, k === 'action' ? 4 : 5).map(x => x.it), total:counts[k] || 0})).filter(g => g.items.length);
    groups.sort((a, b) => (Math.max(...all.filter(x => x.it.kind === b.k).slice(0, 1).map(x => x.s)) || 0) - (Math.max(...all.filter(x => x.it.kind === a.k).slice(0, 1).map(x => x.s)) || 0));
  } else groups = [{k:scope, items:all.filter(x => x.it.kind === scope).slice(0, 80).map(x => x.it), total:counts[scope] || 0}];
  if(!q && scope === 'all') groups = [{k:'action', items:S.index.filter(x => x.kind === 'action' && x.w >= 2).slice(0, 18), total:0}];
  if(special.length) groups.unshift({k:'special', items:special, total:0});
  return {groups, counts, total:all.length, P, scope};
}
const KIND_LABEL = {special:'Best match', action:'Go to & actions', case:'Cases', entry:'Vault entries', record:'Evidence & questions', ent:'Indicators', note:'Notes', tool:'Tools', query:'Queries', rule:'Detections', playbook:'Playbooks', chal:'CTF challenges', feed:'News'};
function srchPaint(){
  const R = srchRun(), terms = R.P.terms; S.flat = []; let h = '';
  $('srScopes').innerHTML = SCOPES.map(([k, l, i]) => { const n = k === 'all' ? R.total : R.counts[k] || 0;
    return `<button data-act="srScope" data-v="${k}" aria-pressed="${R.scope === k}"${k !== 'all' && S.q.trim() && !n ? ' class="zero"' : ''}>${ico(i,'sm')}${l}${S.q.trim() ? `<span>${n}</span>` : ''}</button>`; }).join('');
  for(const g of R.groups){
    h += `<div class="sr-g"><span>${esc(KIND_LABEL[g.k] || g.k)}</span>${R.scope === 'all' && g.total > g.items.length ? `<button data-act="srScope" data-v="${g.k}">Show all ${g.total} ${ico('arrow-right','sm')}</button>` : ''}</div>`;
    for(const it of g.items){ const i = S.flat.length; S.flat.push(it);
      const c = it.caseId ? theCase(it.caseId) : null;
      h += `<button class="sr-it" data-sr="${i}" aria-selected="${i === S.at}" role="option"><span class="sr-ic"${it.color ? ` style="--c:${esc(it.color)}"` : it.tcolor ? ` style="--c:var(${it.tcolor})"` : ''}>${ico(it.icon || 'search','sm')}</span>
        <span class="sr-tx"><b class="${it.mono ? 'mono' : ''}">${hl(it.title, terms)}</b><small>${esc(it.sub)}</small>${terms.length && it.body && !it.title.toLowerCase().includes(terms[0]) ? `<em class="${it.codeBody ? 'mono' : ''}">${snippet(it.body, terms)}</em>` : ''}</span>
        ${c && R.scope !== 'case' ? `<span class="sr-case" style="--cc:${esc(c.color)}">${esc(c.code)}</span>` : ''}<span class="sr-go">${ico('arrow-right','sm')}</span></button>`; }
  }
  if(!S.flat.length) h = `<div class="sr-empty">${ico('search')}<b>Nothing found for “${esc(S.q)}”</b><span>Try fewer words, another scope, or check the spelling. Tip: <code>in:tools</code>, <code>case:TN-2026-014</code>, <code>"exact phrase"</code>, <code>-exclude</code>.</span></div>`;
  if(!S.q.trim() && S.scope === 'all'){ const rec = (DB.prefs.recentQ || []).slice(0, 8);
    h = (rec.length ? `<div class="sr-g"><span>Recent searches</span><button data-act="srClearRecent">Clear</button></div><div class="sr-recent">${rec.map(r => `<button data-act="srRecent" data-v="${esc(r)}">${ico('clock','sm')}${esc(r)}</button>`).join('')}</div>` : '')
      + `<div class="sr-tips"><div><b>Search everything</b><span>Cases, vault, evidence, indicators, notes, tools, queries, rules, playbooks, CTF and news.</span></div>
        <div><code>in:tools shodan</code><code>case:TN-2026-014 dns</code><code>"lamp loader"</code><code>beacon -firewall</code><code>host:DC01 verdict:malicious</code><code>203.0.113.47</code></div></div>` + h; }
  $('srList').innerHTML = h; srchPreview();
  const s = $('srList').querySelector('[aria-selected=true]'); if(s) s.scrollIntoView({block:'nearest'});
}
function srchPreview(){
  const el = $('srPrev'); if(!el) return; const it = S.flat[S.at], terms = srchParse(S.q).terms;
  if(!it){ el.innerHTML = `<div class="sp-empty">${ico('search')}<span>Select a result to preview it here.</span></div>`; return; }
  let b = '';
  const row = (k, v, mono) => v ? `<div class="sp-kv"><span>${esc(k)}</span><b class="${mono ? 'mono' : ''}">${hl(String(v), terms)}</b></div>` : '';
  if(it.kind === 'ioc' || it.kind === 'ent'){ const id = it.kind === 'ioc' ? it.k + ':' + it.v : it.id, g = globalEnts().get(id), {k, v} = entSplit(id), m = E.meaning(k, v);
    b = `${m ? `<p>${esc(m.t)}</p>` : ''}${row('Verdict', verdictOf(id) || 'Not judged')}${row('Seen in', g ? g.recs.length + ' records · ' + g.cases.size + ' cases' : 'Not in any case yet')}
      ${g ? `<div class="sp-list">${g.recs.slice(0, 6).map(r => `<span>${esc(r.title)} <i>${esc((theCase(r.caseId) || {}).code || '')}</i></span>`).join('')}</div>` : ''}${pivotSection(k, v)}`; }
  else if(it.kind === 'entry'){ const e = entryById(it.id); b = Object.entries(e.fields).map(([kk, vv]) => row((TYPES[e.type].fields.find(f => f[0] === kk) || [kk, kk])[1], vv, MONO_TYPES.has(e.type) && kk === TYPES[e.type].fields[0][0])).join('') + (e.tags.length ? row('Tags', e.tags.join(', ')) : '') + (e.notes ? `<p>${hl(e.notes, terms)}</p>` : '') + (entryKey(e) ? pivotSection(entSplit(entryKey(e)).k, entSplit(entryKey(e)).v) : ''); }
  else if(it.kind === 'record'){ const r = recById(it.id); b = `${row('When', r.ts ? E.fmtFull(r.ts, tz()) : '')}${row('Host', r.host)}${row('Source', r.source)}${r.answer ? row('Answer', r.answer) : ''}<pre class="sp-pre">${hl(r.body || '', terms)}</pre>`; }
  else if(it.kind === 'case'){ const c = theCase(it.id), D = derive(c.id); b = `<p>${hl(c.scope || 'No scope written yet.', terms)}</p>${row('Entries', D.entries.length)}${row('Records', D.recs.length)}${row('Open questions', D.recs.filter(r => r.type === 'lead' && !r.answer).length)}`; }
  else if(it.kind === 'tool'){ const t = DB.tools.find(x => x.id === it.id), u = E.safeUrl(t.url); b = `<p>${hl(t.desc, terms)}</p>${row('Address', t.url, true)}${row('Category', toolSub(t))}${t.tags.length ? row('Tags', t.tags.join(', ')) : ''}${u ? `<a class="btn primary sm" href="${esc(u)}" target="_blank" rel="noopener noreferrer" data-act="toolOpen" data-id="${t.id}">Open ${esc(hostOf(u))} ${ico('arrow-up-right','sm')}</a>` : ''}`; }
  else if(it.kind === 'query'){ const x = DB.queries.find(z => z.id === it.id); b = `<p>${hl(x.desc || '', terms)}</p><pre class="sp-pre">${qMark(x.query)}</pre>`; }
  else if(it.kind === 'rule'){ const r = DB.rules.find(z => z.id === it.id); b = `<p>${hl(r.desc || '', terms)}</p><pre class="sp-pre code">${hlCode(r.type, r.code.split('\n').slice(0, 18).join('\n'))}</pre>`; }
  else if(it.kind === 'playbook'){ const p = DB.playbooks.find(z => z.id === it.id); b = `<p>${hl(p.desc, terms)}</p><ol class="sp-steps">${p.steps.map(s => `<li>${hl(s.t, terms)}</li>`).join('')}</ol>`; }
  else if(it.kind === 'chal'){ const c = DB.ctf.chals.find(z => z.id === it.id); b = `${row('Flag', c.flag, true)}${row('Points', c.points)}${c.notes ? `<pre class="sp-pre">${hl(c.notes, terms)}</pre>` : ''}`; }
  else if(it.kind === 'note'){ b = `<pre class="sp-pre">${hl(it.body, terms)}</pre>`; }
  else if(it.kind === 'feed'){ b = `<p>${hl(it.body, terms)}</p>`; }
  else if(it.kind === 'tl'){ b = `<p>Shows only the records in <b>${esc(theCase().name)}</b> that match. Filters you can combine:</p><div class="sp-list">${['host:DC01','verdict:malicious','type:finding','tag:c2','after:2026-09-14','before:2026-09-15','ent:203.0.113.47','source:sysmon'].map(x => `<span class="mono">${x}</span>`).join('')}</div>`; }
  else b = `<p>${esc(it.sub)}</p>`;
  el.innerHTML = `<div class="sp-h"><span class="sr-ic"${it.color ? ` style="--c:${esc(it.color)}"` : ''}>${ico(it.icon || 'search','sm')}</span><div><h3 class="${it.mono ? 'mono' : ''}">${hl(it.title, terms)}</h3><small>${esc(it.sub)}</small></div></div><div class="sp-b">${b}</div>
    <div class="sp-f"><span><kbd>Enter</kbd> ${it.kind === 'tool' ? 'open site' : 'open'}</span>${it.kind === 'tool' ? '<span><kbd>Shift</kbd> <kbd>Enter</kbd> show in Toolbox</span>' : ''}</div>`;
}
function srchOpen(prefill){
  S.index = srchIndex(); S.open = true; S.at = 0; S.scope = 'all'; S.q = prefill || '';
  let w = $('srch'); if(!w){ w = document.createElement('div'); w.id = 'srch'; document.body.appendChild(w); }
  w.hidden = false;
  w.innerHTML = `<div class="sr-scrim" data-act="srClose"></div><div class="sr-box" role="dialog" aria-modal="true" aria-label="Search everything">
    <div class="sr-top">${ico('search')}<label class="sr" for="srQ">Search everything</label><input id="srQ" placeholder="Search cases, evidence, indicators, tools, notes, rules, CTF…" autocomplete="off" spellcheck="false" value="${esc(S.q)}">
      <kbd class="hide-m">Esc</kbd><button class="iconbtn sr-x" data-act="srClose" aria-label="Close search">${ico('x')}</button></div>
    <div class="sr-scopes" id="srScopes" role="tablist"></div>
    <div class="sr-body"><div class="sr-list" id="srList" role="listbox"></div><aside class="sr-prev" id="srPrev"></aside></div>
    <div class="sr-foot hide-m"><span><kbd>↑</kbd><kbd>↓</kbd> move</span><span><kbd>Enter</kbd> open</span><span><kbd>Tab</kbd> next scope</span><span><kbd>Esc</kbd> close</span><span class="t3">${S.index.length.toLocaleString()} items indexed</span></div></div>`;
  const i = $('srQ'); i.focus(); i.setSelectionRange(i.value.length, i.value.length);
  i.oninput = () => { S.q = i.value; S.at = 0; srchPaint(); };
  i.onkeydown = ev => {
    if(ev.key === 'ArrowDown'){ ev.preventDefault(); S.at = Math.min(S.flat.length - 1, S.at + 1); srchMove(); }
    else if(ev.key === 'ArrowUp'){ ev.preventDefault(); S.at = Math.max(0, S.at - 1); srchMove(); }
    else if(ev.key === 'Enter'){ ev.preventDefault(); srchGo(S.flat[S.at], ev.shiftKey); }
    else if(ev.key === 'Tab'){ ev.preventDefault(); const ks = SCOPES.map(x => x[0]); S.scope = ks[(ks.indexOf(S.scope) + (ev.shiftKey ? ks.length - 1 : 1)) % ks.length]; S.at = 0; S.q = S.q.replace(/\b(?:in|is):\w+\s*/gi, ''); i.value = S.q; srchPaint(); }
    else if(ev.key === 'Escape'){ ev.preventDefault(); ev.stopPropagation(); srchClose(); } };
  $('srList').onmousemove = ev => { const b = ev.target.closest('[data-sr]'); if(b && +b.dataset.sr !== S.at){ S.at = +b.dataset.sr; srchMove(); } };
  $('srList').onclick = ev => { const b = ev.target.closest('[data-sr]'); if(b) srchGo(S.flat[+b.dataset.sr], ev.shiftKey); };
  srchPaint();
}
function srchMove(){ document.querySelectorAll('#srList [data-sr]').forEach(b => b.setAttribute('aria-selected', String(+b.dataset.sr === S.at))); const s = $('srList').querySelector('[aria-selected=true]'); if(s) s.scrollIntoView({block:'nearest'}); srchPreview(); }
function srchClose(){ const w = $('srch'); if(w){ w.hidden = true; w.innerHTML = ''; } S.open = false; }
function srchRemember(){ const q = S.q.trim(); if(!q) return; DB.prefs.recentQ = [q].concat((DB.prefs.recentQ || []).filter(x => x !== q)).slice(0, 8); save(); }
function srchGo(it, alt){
  if(!it) return; srchRemember(); srchClose();
  const openIn = (caseId, tab, sel) => { DB.active = caseId; if(sel){ UI.sel = sel; UI.inspOpen = true; } go(caseHash(caseId, tab)); };
  switch(it.kind){
    case 'action': return it.run();
    case 'tl': { const q = S.q.replace(/\b(?:in|is):\w+|case:\S+/gi, '').trim(); UI.q = q; UI.ast = E.parseQuery(q); UI.tlMode = 'events'; return go(caseHash(DB.active, 'timeline')); }
    case 'ioc': { const id = it.k + ':' + it.v; if(globalEnts().has(id)){ go('#/entities'); return setTimeout(() => select('ent', id), 60); } return openCapture(it.v); }
    case 'case': return go(caseHash(it.id));
    case 'entry': return openIn(it.caseId, 'vault', {kind:'entry', id:it.id});
    case 'record': { const r = recById(it.id); return openIn(r.caseId, r.type === 'lead' ? 'questions' : 'timeline', {kind:'rec', id:r.id}); }
    case 'ent': go('#/entities'); return setTimeout(() => select('ent', it.id), 60);
    case 'note': go('#/notes'); return setTimeout(() => noteDlg(it.id), 60);
    case 'tool': { const t = DB.tools.find(x => x.id === it.id); if(alt){ UI.tq = t.name; UI.tcat = 'all'; return go('#/toolbox'); } const u = E.safeUrl(t.url); if(u){ t.uses++; save(); window.open(u, '_blank', 'noopener,noreferrer'); } return; }
    case 'query': UI.qsel = it.id; UI.qopen = true; return go('#/queries');
    case 'rule': UI.rule = it.id; UI.ropen = true; return go('#/detections');
    case 'playbook': UI.pb = it.id; return go('#/playbooks');
    case 'chal': UI.ctfSel = it.id; return go('#/ctf');
    case 'feed': go('#/feeds'); return setTimeout(() => select('feed', it.id), 60);
  }
}
