/* ==========================================================================
   Case report — templates, redaction, embedded relationship map.
   One section model renders to HTML (screen / print) and Markdown.
   ========================================================================== */
const REP_T = [['full','Full','file-text'],['exec','Executive','briefcase'],['tech','Technical','cpu'],['ctf','CTF write-up','flag']];
/* redaction: emails, phone numbers, IPv4/IPv6, @handles and names of Person entries */
function redactor(D, on){
  if(!on) return s => String(s == null ? '' : s);
  const names = D.entries.filter(e => e.type === 'person').map(primary).filter(n => n && n.length > 2).sort((a, b) => b.length - a.length), alias = new Map(names.map((n, i) => [n.toLowerCase(), 'Person ' + String.fromCharCode(65 + i % 26) + (i >= 26 ? Math.floor(i / 26) : '')]));
  const nameRe = names.length ? new RegExp('\\b(' + names.map(n => n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|') + ')\\b', 'gi') : null;
  return s => { s = String(s == null ? '' : s);
    s = s.replace(/\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b/g, (m, a) => a + '•••@' + '•••.' + m.split('.').pop());
    s = s.replace(/\b(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}\b/g, '$1.$2.x.x');
    s = s.replace(/\b([0-9a-f]{1,4}:[0-9a-f]{1,4}):[0-9a-f:]{2,}\b/gi, '$1:…');
    s = s.replace(/(\+?\d[\d ().-]{7,}\d)/g, m => m.replace(/\d(?=[\d ().-]{4})/g, '•'));
    s = s.replace(/(^|[\s(])@([A-Za-z0-9_.]{2,})/g, (m, p, h) => p + '@' + h[0] + '•••');
    if(nameRe) s = s.replace(nameRe, m => alias.get(m.toLowerCase()) || '[name]');
    return s; };
}
function reportMap(c, D, red, w = 760, h = 380){
  const ents = D.entries.filter(e => e.pos), byId = new Map(ents.map(e => [e.id, e]));
  if(ents.length < 2) return '';
  const xs = ents.map(e => e.pos.x), ys = ents.map(e => e.pos.y), pad = 56;
  const x0 = Math.min(...xs), x1 = Math.max(...xs), y0 = Math.min(...ys), y1 = Math.max(...ys);
  const k = Math.min((w - pad * 2) / Math.max(1, x1 - x0), (h - pad * 2) / Math.max(1, y1 - y0)), ox = (w - (x1 - x0) * k) / 2, oy = (h - (y1 - y0) * k) / 2;
  const P = e => [ox + (e.pos.x - x0) * k, oy + (e.pos.y - y0) * k];
  let s = `<svg class="repmap" viewBox="0 0 ${w} ${h}" role="img" aria-label="Relationship map: ${ents.length} entries, ${D.links.length} relationships" xmlns="http://www.w3.org/2000/svg">`;
  for(const l of D.links){ const a = byId.get(l.a), b = byId.get(l.b); if(!a || !b) continue; const [ax, ay] = P(a), [bx, by] = P(b);
    s += `<line x1="${ax.toFixed(1)}" y1="${ay.toFixed(1)}" x2="${bx.toFixed(1)}" y2="${by.toFixed(1)}" stroke="#8a93a6" stroke-opacity=".6" stroke-width="${l.conf >= 3 ? 1.8 : 1.1}"${l.conf <= 1 ? ' stroke-dasharray="4 3"' : ''}/>`; }
  for(const e of ents){ const [x, y] = P(e), v = entryVerdict(e), col = getComputedStyle(document.documentElement).getPropertyValue(TYPES[e.type].color).trim() || '#5b6cff', lab = red(primary(e)); const t = lab.length > 26 ? lab.slice(0, 25) + '…' : lab;
    s += `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="7" fill="${col}" stroke="${v === 'malicious' ? '#e03131' : '#fff'}" stroke-width="2"/><text x="${x.toFixed(1)}" y="${(y + 20).toFixed(1)}" text-anchor="middle" font-size="10.5" font-family="Inter,sans-serif" fill="#4a5163">${esc(t)}</text>`; }
  return s + '</svg>';
}
function reportModel(c, D, tpl, redact){
  const red = redactor(D, redact), cites = [], S = [];
  const cite = id => { if(!id || !recById(id)) return ''; let i = cites.indexOf(id); if(i < 0){ cites.push(id); i = cites.length - 1; } return {n:i + 1, id}; };
  const f = D.recs.filter(r => r.type === 'finding'), ans = D.recs.filter(r => r.type === 'lead' && r.answer), open = D.recs.filter(r => r.type === 'lead' && !r.answer);
  const mal = D.entries.filter(e => entryVerdict(e) === 'malicious'), key = D.recs.filter(r => r.tags.includes('key-evidence'));
  const timed = D.recs.filter(r => r.ts && r.type !== 'lead');
  const para = (b, t, c2) => ({k:'p', b, t, c:c2});
  const row = (l, t, c2, mono) => ({k:'row', l, t, c:c2, mono});
  const add = (h, items, extra) => { if(items && items.length) S.push(Object.assign({h, items}, extra || {})); };
  const scale = `${D.recs.length} records, ${D.entries.length} vault entries (${mal.length} malicious), ${D.links.length} relationships${timed.length > 1 ? ', spanning ' + E.fmtGap(timed[timed.length - 1].ts - timed[0].ts) : ''}.`;
  if(tpl === 'ctf'){
    const flags = [...new Set(D.recs.flatMap(r => findFlags(r.title + '\n' + r.body + '\n' + (r.answer || ''))))].filter(x => !/\{\s*(\.\.\.|…|x+|flag)?\s*\}$/i.test(x));
    add('Challenge', [para('', red(c.scope || c.name))]);
    add('Flags', flags.map(x => row('Flag', red(x), null, true)));
    add('Answers', ans.map(a => para(red(a.title), red(a.answer), cite(a.id))));
    add('Solve path', D.recs.filter(r => r.type !== 'lead').map((r, i) => ({k:'step', n:i + 1, t:red(r.title), body:red(r.body).slice(0, 600), src:r.source, c:cite(r.id)})));
    add('Tools and sources used', [...new Set(D.recs.map(r => r.source).filter(Boolean))].map(s => row('Source', red(s))));
    add('Still open', open.map(a => para('', '☐ ' + red(a.title))));
  } else {
    add('Summary', [para('', red(c.scope || 'No scope written yet.')), para('Scale. ', scale)]);
    add('Findings', f.length ? f.map(x => para(red(x.title) + '. ', red(x.body), cite(x.id))) : [para('', 'None recorded.')]);
    if(tpl !== 'exec' || key.length) add('Key evidence', key.map(r => row(r.ts ? E.fmtFull(r.ts, tz()).slice(0, 16) : '—', red(r.title), cite(r.id))));
    add('Answers', ans.map(a => para(red(a.title) + ' — ', red(a.answer), cite(a.id))));
    add('Still open', open.map(a => para('', '☐ ' + red(a.title))));
    if(tpl !== 'exec'){
      add('Relationship map', [{k:'map'}]);
      add('Malicious entities', mal.map(e => row(TYPES[e.type].label, red(primary(e)), cite(e.src), true)));
      add('Key relationships', D.links.filter(l => l.conf >= 2).slice(0, tpl === 'tech' ? 60 : 12).map(l => row(l.label, red(primary(entryById(l.a))) + ' → ' + red(primary(entryById(l.b))), cite(l.src))));
    }
    if(tpl === 'exec' && timed.length) add('Timeline at a glance', [timed[0], ...E.chapters(timed).map(ch => ch[0]).slice(1, 6), timed[timed.length - 1]].filter((r, i, a) => a.indexOf(r) === i).map(r => row(E.fmtFull(r.ts, tz()).slice(0, 16), red(r.title), cite(r.id))));
    if(tpl === 'full') add('Chronology', timed.slice(0, 40).map(r => row(E.fmtFull(r.ts, tz()), red(r.title), cite(r.id), true)));
    if(tpl === 'tech'){
      add('Chronology', timed.map(r => row(E.fmtFull(r.ts, tz()), red(r.title) + (r.host ? ' · ' + red(r.host) : ''), cite(r.id), true)));
      add('Indicators', caseIOCs(c.id).filter(x => x.verdict !== 'benign').slice(0, 200).map(x => row((E.LABEL[x.k] || x.k) + (x.verdict ? ' · ' + x.verdict : ''), red(x.v), null, true)));
      const rules = (DB.rules || []).filter(r => r.type === 'sigma' || (r.type === 'yara' && D.recs.length <= 2000)), hits = [];
      for(const r of rules){ const t = testRule(r, c.id); if(t.hits && t.hits.length) hits.push(row(r.type.toUpperCase(), r.title + ' — ' + t.hits.length + ' record' + (t.hits.length > 1 ? 's' : ''), cite(t.hits[0].id))); }
      add('Detection rules that match', hits);
      add('Files', D.recs.flatMap(r => (r.att || []).map(a => row(fmtBytes(a.size), red(a.name) + ' · sha256 ' + a.sha256, cite(r.id), true))));
    }
  }
  add('Evidence cited', cites.map((id, i) => { const r = recById(id); return {k:'src', n:i + 1, t:red(r.title), s:red(r.source || ''), h:(r.hash || '').slice(0, 16)}; }));
  return {S, cites, red};
}
function reportHTML(c, D, M){
  const ci = x => x && x.n ? ` <sup><a data-act="selRec" data-id="${x.id}">[${x.n}]</a></sup>` : '';
  const item = it => it.k === 'p' ? `<p>${it.b ? `<b style="color:var(--text)">${esc(it.b)}</b>` : ''}${esc(it.t)}${ci(it.c)}</p>`
    : it.k === 'row' ? `<div class="ev2"><span class="${it.mono ? 'mono ' : ''}t3" style="font-size:13px">${esc(it.l)}</span><span${it.mono ? ' class="mono" style="font-size:13.5px;overflow-wrap:anywhere"' : ''}>${esc(it.t)}${ci(it.c)}</span></div>`
    : it.k === 'step' ? `<div class="rstep"><span class="n">${it.n}</span><div><b>${esc(it.t)}</b>${ci(it.c)}${it.src ? ` <span class="t3" style="font-size:12.5px">· ${esc(it.src)}</span>` : ''}${it.body && it.body !== it.t ? `<pre>${esc(it.body)}</pre>` : ''}</div></div>`
    : it.k === 'map' ? `<figure class="repfig">${reportMap(c, D, M.red)}<figcaption>Entries from the vault and the relationships you drew. Solid lines are medium/high confidence, dashed are low; a red ring marks malicious.</figcaption></figure>`
    : it.k === 'src' ? `<p style="font-size:13.5px">[${it.n}] ${esc(it.t)} · ${esc(it.s)} <span class="mono t3">sha256 ${esc(it.h)}…</span></p>` : '';
  return M.S.map(s => `<h2>${esc(s.h)}</h2>${s.items.map(item).join('')}`).join('');
}
function reportMdText(c, D, M, tplName){
  const ci = x => x && x.n ? ' [' + x.n + ']' : '', L = ['# ' + M.red(c.name), '', '_' + c.code + ' · ' + tplName + ' report · ' + tz() + (UI.redact ? ' · redacted' : '') + '_', ''];
  for(const s of M.S){ L.push('## ' + s.h, '');
    for(const it of s.items){
      if(it.k === 'p') L.push((it.b ? '**' + it.b.trim() + '** ' : '') + it.t + ci(it.c), '');
      else if(it.k === 'row') L.push('- ' + (it.mono ? '`' + it.l + '`' : it.l) + ' — ' + (it.mono ? '`' + it.t + '`' : it.t) + ci(it.c));
      else if(it.k === 'step') L.push(it.n + '. **' + it.t + '**' + ci(it.c) + (it.src ? ' _(' + it.src + ')_' : ''), ...(it.body && it.body !== it.t ? ['', '   ```', ...it.body.split('\n').map(l => '   ' + l), '   ```', ''] : []));
      else if(it.k === 'map') L.push('_Relationship map: open the case graph in OSINTrix, or print this report to PDF to include it._');
      else if(it.k === 'src') L.push('[' + it.n + '] ' + it.t + ' · ' + it.s + ' · sha256 `' + it.h + '…`');
    }
    L.push(''); }
  return L.join('\n').replace(/\n{3,}/g, '\n\n');
}
function caseReport(c, D){
  const tpl = DB.prefs.repT || (c.id === 'c-lab' || /ctf/i.test(c.name) ? 'ctf' : 'full'), M = reportModel(c, D, tpl, !!UI.redact);
  return `<div class="scroll"><div class="page">
    <div class="toolbar rep-tb"><div class="seg" role="group" aria-label="Template">${REP_T.map(([v, l, i]) => `<button data-act="repT" data-v="${v}" aria-pressed="${tpl === v}">${ico(i,'sm')}${l}</button>`).join('')}</div>
      <label class="chk swl"><span class="sw"><input type="checkbox" data-act="repRedact"${UI.redact ? ' checked' : ''}><span></span></span>Redact personal data</label>
      <span class="sp"></span><button class="btn primary" data-act="exportMd">${ico('download','sm')}Markdown</button><button class="btn" data-act="printReport">${ico('file-text','sm')}Print / PDF</button><button class="btn" data-act="iocMenu">${ico('fingerprint','sm')}IOCs &amp; case data${ico('chevron-down','sm')}</button></div>
    ${UI.redact ? `<p class="note" style="margin:0 0 14px"><span class="ic">${ico('eye-off','sm')}</span><span>Emails, phone numbers, IP addresses, @handles and the names of Person entries are masked in this view, the Markdown and the PDF. Check it before sharing — free-text can still hold personal details.</span></p>` : ''}
    <article class="doc"><h1>${esc(M.red(c.name))}</h1><p class="mono t3" style="font-size:13px">${esc(c.code)} · ${esc(REP_T.find(x => x[0] === tpl)[1])} report · generated from ${D.recs.length} records and ${D.entries.length} vault entries · ${esc(tz())}${UI.redact ? ' · redacted' : ''}</p>
      ${reportHTML(c, D, M)}</article></div></div>`;
}
function reportMd(){ const c = theCase(), D = derive(), tpl = DB.prefs.repT || (c.id === 'c-lab' ? 'ctf' : 'full'); return reportMdText(c, D, reportModel(c, D, tpl, !!UI.redact), REP_T.find(x => x[0] === tpl)[1]); }
const REP_ACTS = {
  repT:(id, v) => { DB.prefs.repT = v; save(); renderMain(); },
  repRedact:(id, v, t) => { UI.redact = t.checked; renderMain(); }
};
