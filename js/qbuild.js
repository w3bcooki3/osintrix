/* ==========================================================================
   Query library → Build a search: pick what you are looking for, row by row
   (words, an exact phrase, any of several, words to leave out, a site, a file
   type, words in the title or address, a date range, a port, an organisation,
   a country, a certificate name, a code language or path…), and see the query
   written for Google, Bing, DuckDuckGo, Shodan, Censys and GitHub at once —
   with what each engine cannot do said plainly instead of silently dropped.
   Blanks like {{DOMAIN_NAME}} stay blanks, so a built search saves to the
   library as a template; a saved one reopens here and is rewritten for
   whichever engine you search it with.
   ========================================================================== */
const QB_ENG = ['google', 'bing', 'duckduckgo', 'shodan', 'censys', 'github'];
/* a value as one token: blanks pass through, anything with a space or quote is quoted */
const qbQ = v => { v = String(v).trim().replace(/"/g, ''); return /^\{\{\s*[A-Z0-9_]+\s*\}\}$/i.test(v) || !/[\s()]/.test(v) ? v : `"${v}"`; };
const qbWords = v => String(v).trim().split(/\s+/).filter(Boolean);
const qbList = v => String(v).split(/[,|]| OR /i).map(s => s.trim()).filter(Boolean);
const QB_WEB = ['google', 'bing', 'duckduckgo'];
/* each kind: label, help, placeholder, a check, and how each engine writes it (missing = the engine cannot) */
const QB_KINDS = {
  words:{l:'All these words', ph:'invoice password', w:Object.fromEntries(QB_ENG.map(e => [e, v => qbWords(v).map(e === 'censys' ? qbQ : x => x).join(e === 'censys' ? ' and ' : ' ')]))},
  phrase:{l:'This exact phrase', ph:'internal use only', w:Object.fromEntries(QB_ENG.map(e => [e, v => `"${String(v).trim().replace(/"/g, '')}"`]))},
  any:{l:'Any of these', h:'Separate with commas', ph:'confidential, secret, private', w:{google:v => qbOr(v, 'OR'), bing:v => qbOr(v, 'OR'), duckduckgo:v => qbOr(v, 'OR'), censys:v => qbOr(v, 'or'), github:v => qbOr(v, 'OR')}},
  not:{l:'None of these', ph:'jobs careers', w:{google:v => qbWords(v).map(x => '-' + qbQ(x)).join(' '), bing:v => qbWords(v).map(x => '-' + qbQ(x)).join(' '), duckduckgo:v => qbWords(v).map(x => '-' + qbQ(x)).join(' '),
    censys:v => qbWords(v).map(x => 'not ' + qbQ(x)).join(' and '), github:v => qbWords(v).map(x => 'NOT ' + qbQ(x)).join(' ')}},
  site:{l:'On this site or domain', ph:'{{DOMAIN_NAME}}', chk:v => /^(\{\{\s*[A-Z0-9_]+\s*\}\}|[\w*.-]+\.[a-z]{2,}|[\w.-]+\.[a-z]{2,}\/\S*)$/i.test(v) ? '' : 'A domain, like example.com',
    w:{google:v => 'site:' + qbQ(v), bing:v => 'site:' + qbQ(v), duckduckgo:v => 'site:' + qbQ(v), shodan:v => 'hostname:' + qbQ(v), censys:v => 'dns.names: ' + qbQ(v)}},
  filetype:{l:'File type', h:'pdf, xlsx, env…', ph:'pdf', chk:v => /^(\{\{\s*[A-Z0-9_]+\s*\}\}|\.?[a-z0-9]{1,8})$/i.test(v) ? '' : 'An extension, like pdf',
    w:{google:v => 'filetype:' + v.replace(/^\./, ''), bing:v => 'filetype:' + v.replace(/^\./, ''), duckduckgo:v => 'filetype:' + v.replace(/^\./, ''), github:v => 'path:*.' + v.replace(/^\./, '')}},
  intitle:{l:'In the page title', ph:'index of', w:{google:v => 'intitle:' + qbQ(v), bing:v => 'intitle:' + qbQ(v), duckduckgo:v => 'intitle:' + qbQ(v), shodan:v => 'http.title:' + qbQ(v), censys:v => 'services.http.response.html_title: ' + qbQ(v)}},
  inurl:{l:'In the address', ph:'admin', w:{google:v => 'inurl:' + qbQ(v), duckduckgo:v => 'inurl:' + qbQ(v), github:v => 'path:' + qbQ(v)}},
  intext:{l:'In the page text', ph:'api_key', w:{google:v => 'intext:' + qbQ(v), bing:v => 'inbody:' + qbQ(v), shodan:v => 'http.html:' + qbQ(v), censys:v => 'services.http.response.body: ' + qbQ(v)}},
  after:{l:'Published after', h:'YYYY-MM-DD', ph:'2025-01-01', chk:v => /^\d{4}-\d{2}-\d{2}$/.test(v) ? '' : 'A date like 2025-01-01', w:{google:v => 'after:' + v}},
  before:{l:'Published before', h:'YYYY-MM-DD', ph:'2026-01-01', chk:v => /^\d{4}-\d{2}-\d{2}$/.test(v) ? '' : 'A date like 2026-01-01', w:{google:v => 'before:' + v}},
  port:{l:'Open port', ph:'3389', chk:v => /^(\{\{\s*[A-Z0-9_]+\s*\}\}|\d{1,5}(\s*,\s*\d{1,5})*)$/.test(v) && v.split(',').every(p => /\{/.test(p) || +p <= 65535) ? '' : 'A port number, or several with commas',
    w:{shodan:v => 'port:' + v.replace(/\s+/g, ''), censys:v => { const p = qbList(v); return p.length > 1 ? '(' + p.map(x => 'services.port: ' + x).join(' or ') + ')' : 'services.port: ' + p[0]; }}},
  org:{l:'Organisation or network owner', ph:'Acme Corp', w:{shodan:v => 'org:' + `"${v.trim().replace(/"/g, '')}"`, censys:v => 'autonomous_system.name: ' + `"${v.trim().replace(/"/g, '')}"`, github:v => 'org:' + v.trim().replace(/\s+/g, '')}},
  country:{l:'Country', h:'Two-letter code', ph:'DE', chk:v => /^(\{\{\s*[A-Z0-9_]+\s*\}\}|[A-Za-z]{2})$/.test(v) ? '' : 'A two-letter code, like DE', w:{shodan:v => 'country:' + v.toUpperCase(), censys:v => 'location.country_code: ' + v.toUpperCase()}},
  product:{l:'Software or product', ph:'Apache httpd', w:{shodan:v => 'product:' + `"${v.trim().replace(/"/g, '')}"`, censys:v => 'services.software.product: ' + `"${v.trim().replace(/"/g, '')}"`}},
  net:{l:'IP range', h:'CIDR', ph:'203.0.113.0/24', chk:v => /^(\{\{\s*[A-Z0-9_]+\s*\}\}|\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?)$/.test(v) ? '' : 'An address or range, like 203.0.113.0/24', w:{shodan:v => 'net:' + v, censys:v => 'ip: ' + v}},
  cert:{l:'Certificate name', ph:'*.example.com', w:{shodan:v => 'ssl.cert.subject.cn:' + qbQ(v), censys:v => 'services.tls.certificates.leaf_data.subject.common_name: ' + qbQ(v)}},
  lang:{l:'Code language', ph:'python', w:{github:v => 'language:' + qbQ(v)}},
  repo:{l:'Repository', h:'owner/name', ph:'acme/website', w:{github:v => 'repo:' + v.trim()}},
};
const qbOr = (v, or) => { const p = qbList(v).map(qbQ); return p.length > 1 ? '(' + p.join(` ${or} `) + ')' : p[0] || ''; };
const QB_GROUPS = [['Words', ['words', 'phrase', 'any', 'not']], ['Web pages', ['site', 'filetype', 'intitle', 'inurl', 'intext', 'after', 'before']], ['Hosts & services', ['port', 'org', 'country', 'product', 'net', 'cert']], ['Code', ['lang', 'repo']]];
/* build for one engine: {q, dropped:[kind labels], bad:[row index]} */
function qbBuild(rows, eng){
  const parts = [], dropped = [], bad = [];
  (rows || []).forEach((r, i) => { const K = QB_KINDS[r.k], v = String(r.v || '').trim(); if(!K || !v) return;
    if(K.chk && K.chk(v)) bad.push(i);
    const f = K.w[eng]; if(!f){ dropped.push(K.l); return; } const s = f(v); if(s) parts.push(s); });
  /* Censys joins its fields with "and" */
  return {q:parts.join(eng === 'censys' ? ' and ' : ' '), dropped:[...new Set(dropped)], bad};
}
const qbFits = rows => QB_ENG.filter(e => { const B = qbBuild(rows, e); return B.q && !B.dropped.length; });
/* the engine a set of rows is mostly for */
const qbBest = rows => { const ks = (rows || []).filter(r => r.v && String(r.v).trim()).map(r => r.k);
  return ks.some(k => ['lang', 'repo'].includes(k)) ? 'github' : ks.some(k => ['port', 'org', 'country', 'product', 'net', 'cert'].includes(k)) ? 'shodan' : 'google'; };

function qbOpen(id){
  const x = id ? DB.queries.find(z => z.id === id) : null;
  UI.qb = {id:x ? x.id : null, rows:x && x.b ? JSON.parse(JSON.stringify(x.b)) : [{k:'site', v:''}, {k:'words', v:''}], eng:x && x.b ? (x.engines[0] || qbBest(x.b)) : 'google'};
  openDlg(dhead(x ? 'Edit search — ' + x.name : 'Build a search') + `<div class="in qb" id="qbIn"></div><footer id="qbFt"></footer>`, true);
  qbPaint(true);
}
function qbPaint(focus){
  const S = UI.qb, el = $('qbIn'); if(!S || !el) return;
  const kopt = cur => QB_GROUPS.map(([g, ks]) => `<optgroup label="${g}">${ks.map(k => `<option value="${k}"${k === cur ? ' selected' : ''}>${esc(QB_KINDS[k].l)}${QB_KINDS[k].w[S.eng] || k === cur ? '' : ' (not on ' + esc(ENGINES[S.eng][0]) + ')'}</option>`).join('')}</optgroup>`).join('');
  const B = qbBuild(S.rows, S.eng), vs = varsOf(B.q), url = B.q && !vs.length ? engineUrl(S.eng, B.q) : '';
  const row = (r, i) => { const K = QB_KINDS[r.k], off = !K.w[S.eng], err = r.v && K.chk ? K.chk(String(r.v).trim()) : '';
    return `<div class="qb-r${off ? ' off' : ''}" data-i="${i}"><label class="sr" for="qbk${i}">What</label><select id="qbk${i}" class="inp qb-k" data-qbk="${i}">${kopt(r.k)}</select>
      <label class="sr" for="qbv${i}">${esc(K.l)}</label><input id="qbv${i}" class="inp mono qb-v" data-qbv="${i}" value="${esc(r.v || '')}" placeholder="${esc(K.ph)}" autocomplete="off" spellcheck="false"${err ? ` aria-invalid="true" aria-describedby="qbe${i}"` : ''}>
      <button type="button" class="iconbtn sm" data-act="qbDel" data-v="${i}" aria-label="Remove this row" title="Remove">${ico('x','sm')}</button>
      ${off ? `<span class="qb-n">Not on ${esc(ENGINES[S.eng][0])}, so left out here${(() => { const o = QB_ENG.filter(e => K.w[e]).map(e => ENGINES[e][0]); return o.length ? ' · works on ' + esc(o.join(', ')) : ''; })()}</span>` : err ? `<span class="qb-n bad" id="qbe${i}">${esc(err)}</span>` : K.h ? `<span class="qb-n">${esc(K.h)}</span>` : ''}</div>`; };
  el.innerHTML = `<div class="qb-eng" role="tablist" aria-label="Engine">${QB_ENG.map(e => { const b = qbBuild(S.rows, e); return `<button role="tab" id="qbt-${e}" aria-selected="${e === S.eng}" data-act="qbEng" data-v="${e}">${esc(ENGINES[e][0])}${b.dropped.length ? `<span class="qb-d" title="${esc(b.dropped.join(', '))} left out">${b.dropped.length}</span>` : ''}</button>`; }).join('')}</div>
    <div class="qb-grid"><div class="qb-rows" role="tabpanel" aria-labelledby="qbt-${S.eng}">${S.rows.map(row).join('')}
      <div class="qb-add">${['words', 'phrase', 'not', ...(S.eng === 'github' ? ['lang', 'filetype'] : ['shodan', 'censys'].includes(S.eng) ? ['port', 'country'] : ['site', 'filetype', 'intitle'])].map(k => `<button type="button" class="btn xs ghost" data-act="qbAdd" data-v="${k}">${ico('plus','sm')}${esc(QB_KINDS[k].l)}</button>`).join('')}<button type="button" class="btn xs ghost" data-act="qbAdd" data-v="">${ico('plus','sm')}Something else…</button></div>
      <p class="hint qb-tip">Leave a blank to fill later, like <span class="mono">{{DOMAIN_NAME}}</span> or <span class="mono">{{FULL_NAME}}</span> — it is filled from a vault entry when you run the saved search.</p></div>
    <aside class="qb-out"><h4>${esc(ENGINES[S.eng][0])}</h4><pre class="qb-q mono" id="qbQ" aria-live="polite">${B.q ? esc(B.q) : '<span class="t3">Fill a row to see the search.</span>'}</pre>
      ${B.dropped.length ? `<p class="qb-w">${ico('triangle-alert','sm')}<span>Left out — ${esc(ENGINES[S.eng][0])} cannot search by: ${esc(B.dropped.join(', ').toLowerCase())}.</span></p>` : ''}
      ${B.bad.length ? `<p class="qb-w">${ico('triangle-alert','sm')}<span>${B.bad.length === 1 ? 'One row looks wrong' : B.bad.length + ' rows look wrong'} — see the note under ${B.bad.length === 1 ? 'it' : 'them'}.</span></p>` : ''}
      <div class="qb-go">${url ? `<a class="btn primary" href="${esc(url)}" target="_blank" rel="noopener noreferrer" id="qbRun">${ico('external-link','sm')}Search ${esc(ENGINES[S.eng][0])}</a>` : `<button type="button" class="btn primary" disabled title="${vs.length ? 'Fill the blanks when you run the saved search' : 'Fill a row first'}">${ico('external-link','sm')}Search ${esc(ENGINES[S.eng][0])}</button>`}<button type="button" class="btn" data-act="qbCopy"${B.q ? '' : ' disabled'}>${ico('copy','sm')}Copy</button></div>
      ${vs.length ? `<p class="hint">${vs.length === 1 ? 'One blank' : vs.length + ' blanks'} to fill: ${esc(vs.join(', '))}. Save it, then run it from the library.</p>` : ''}
      <details class="qb-all"><summary>Every engine</summary><dl>${QB_ENG.filter(e => e !== S.eng).map(e => { const b = qbBuild(S.rows, e); return `<dt>${esc(ENGINES[e][0])}</dt><dd class="mono">${b.q ? esc(b.q) : '<span class="t3">nothing it can search by</span>'}${b.dropped.length ? `<small>left out: ${esc(b.dropped.join(', ').toLowerCase())}</small>` : ''}</dd>`; }).join('')}</dl></details></aside></div>`;
  const x = S.id && DB.queries.find(z => z.id === S.id);
  $('qbFt').innerHTML = `<button type="button" class="btn" data-act="dclose">Cancel</button><span class="qb-sv"><label class="sr" for="qbName">Name</label><input id="qbName" class="inp" placeholder="Name it to save it" maxlength="120" value="${esc(S.name != null ? S.name : x ? x.name : '')}"><button type="button" class="btn primary" data-act="qbSave"${B.q ? '' : ' disabled'}>${ico('bookmark','sm')}${x ? 'Save changes' : 'Save to library'}</button></span>`;
  /* keep typing smooth: rows repaint only the output side */
  el.querySelectorAll('[data-qbv]').forEach(i => i.oninput = () => { S.rows[+i.dataset.qbv].v = i.value; qbPaintOut(); });
  el.querySelectorAll('[data-qbk]').forEach(s => s.onchange = () => { S.rows[+s.dataset.qbk].k = s.value; qbPaint(); const v = $('qbv' + s.dataset.qbk); if(v) v.focus(); });
  const nm = $('qbName'); if(nm) nm.oninput = () => { S.name = nm.value; };
  if(focus){ const first = el.querySelector('.qb-v'); if(first) first.focus(); }
}
/* repaint without losing the caret: everything but the row being typed in */
function qbPaintOut(){ const a = document.activeElement, id = a && a.id, s = a && a.selectionStart, e = a && a.selectionEnd; qbPaint();
  const b = id && $(id); if(b){ b.focus(); try{ b.setSelectionRange(s, e); }catch(x){} } }
function qbSave(){
  const S = UI.qb; if(!S) return; const name = ($('qbName').value || '').trim().replace(/\s+/g, ' ');
  if(!name) return fieldErr('qbName', 'Give it a name to save it.');
  const rows = S.rows.filter(r => String(r.v || '').trim()).map(r => ({k:r.k, v:String(r.v).trim().slice(0, 500)})).slice(0, 30);
  const B = qbBuild(rows, S.eng); if(!B.q) return toast('Fill a row first');
  if(B.q.length > 2000) return toast('That search is too long to save (over 2,000 characters)');
  if(clash(DB.queries, name, 'name', S.id)) return fieldErr('qbName', `A query called “${name}” already exists in the library.`);
  const fits = qbFits(rows), engines = [S.eng, ...fits.filter(e => e !== S.eng)];
  const kinds = rows.map(r => r.k), cat = kinds.some(k => ['lang', 'repo'].includes(k)) ? 'code & files' : kinds.some(k => ['port', 'org', 'country', 'product', 'net', 'cert'].includes(k)) ? 'iot' : kinds.includes('filetype') ? 'files' : 'osint';
  const x = S.id && DB.queries.find(z => z.id === S.id);
  if(x) Object.assign(x, {name, query:B.q, b:rows, engines});
  else DB.queries.unshift({id:uid('q'), name, desc:'Built with the search builder.', query:B.q, b:rows, cat, engines, tags:['built'], starred:false, uses:0, custom:true});
  const id = x ? x.id : DB.queries[0].id; UI.qsel = id; UI.qopen = true; UI.runFor = null;
  mutate('saved query ' + name); closeDlg(); renderAll(); toast(x ? 'Saved' : `Saved “${name}” to My queries`);
}
const QB_ACTS = {
  qbOpen:id => qbOpen(id || null),
  qbEng:(id, v) => { if(UI.qb && ENGINES[v]){ UI.qb.eng = v; qbPaint(); const t = $('qbt-' + v); if(t) t.focus(); } },
  qbAdd:(id, v) => { const S = UI.qb; if(!S) return; if(S.rows.length >= 30) return toast('Up to 30 rows');
    const k = v || Object.keys(QB_KINDS).find(k => QB_KINDS[k].w[S.eng] && !S.rows.some(r => r.k === k)) || 'words'; S.rows.push({k, v:''}); qbPaint();
    const n = $('qbv' + (S.rows.length - 1)); if(n){ n.focus(); if(!v){ const s = $('qbk' + (S.rows.length - 1)); if(s) s.focus(); } } },
  qbDel:(id, v) => { const S = UI.qb; if(!S) return; S.rows.splice(+v, 1); if(!S.rows.length) S.rows.push({k:'words', v:''}); qbPaint(); const n = $('qbv' + Math.min(+v, S.rows.length - 1)); if(n) n.focus(); },
  qbCopy:() => { const S = UI.qb; if(!S) return; const B = qbBuild(S.rows, S.eng); if(B.q) copyText(B.q); },
  qbSave:() => qbSave(),
};
