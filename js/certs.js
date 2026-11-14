/* ==========================================================================
   Certificates: decode certificates, chains and signing requests, see what
   an investigator can learn from them, and learn how certificates work.
   Parsing and signature checks are in x509.js; nothing leaves the browser.
   What you keep is saved as an evidence record in the open case.
   ========================================================================== */
const CX_TABS = [['decoder', 'Decoder', 'scroll-text'], ['chain', 'Chain', 'link-2'], ['csr', 'CSR', 'file-text'], ['compare', 'Compare', 'git-compare'], ['ct', 'Transparency logs', 'radar'], ['guide', 'How certificates work', 'book-open']];
const cxS = () => (UI.cx = UI.cx || {tab:'decoder', input:'', R:null, sel:0, ch:'tls', rec:null, cmpA:'', cmpB:'', cmpX:[], ct:null, ctF:'', ctSort:['last', -1], ctDom:'', host:'', when:''});
const CX_REC = new Map();   // record id → parsed (cached by hash)
const cxRecs = () => DB.records.filter(r => r.caseId === DB.active && r.source === 'certificate').sort((a, b) => (b.addedAt || 0) - (a.addedAt || 0));
const cxDays = ms => Math.round(ms / 864e5);
const cxDate = t => isFinite(t) ? new Date(t).toISOString().replace('T', ' ').slice(0, 16) + ' UTC' : '—';
const cxDay = t => isFinite(t) ? new Date(t).toLocaleDateString(undefined, {day:'numeric', month:'short', year:'numeric'}) : '—';
const cxYmd = t => isFinite(t) ? new Date(t).toISOString().slice(0, 10) : '—';
const cxWorst = F => F.some(f => f.s === 'bad') ? 'bad' : F.some(f => f.s === 'warn') ? 'warn' : 'ok';
const cxKh = c => (c._kh = c._kh || X5.hex(c.key.der));
const cxId = c => c.serialHex + '|' + c.issuer.raw;
const cxBytes = n => n >= 1048576 ? (n / 1048576).toFixed(1) + ' MB' : n >= 1024 ? Math.round(n / 1024) + ' KB' : n + ' bytes';
const cxChk = (s, t, d) => `<div class="crt-fd"><span class="crt-sv ${s}">${ico(s === 'ok' ? 'check' : s === 'inf' ? 'info' : 'triangle-alert','sm')}</span><div><b>${t}</b>${d ? `<small>${d}</small>` : ''}</div></div>`;

/* ---------- reading input ---------- */
function cxLoad(input, opts = {}){
  const S = cxS(), R = X5.read(input);
  if(R.keys.length){ S.keyWarn = true; if(typeof input === 'string') S.input = input.replace(/-----BEGIN ([A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*)-----[\s\S]*?-----END \1-----\s*/g, ''); }
  else S.keyWarn = false;
  if(!R.certs.length && !R.csrs.length && !R.pe){ if(!R.keys.length) toast(R.errors[0] || 'No certificate found'); S.R = R.keys.length ? null : S.R; return cxPaint(); }
  R.at = Date.now(); R.rec = opts.rec || null; S.sel = 0; S.rec = opts.rec || null;
  if(!opts.rec && !/^Example/.test(opts.src || '')) cxKeep(opts.name || (typeof input === 'string' ? cxNameOf(R) : 'certificate'), input, opts.cmp ? 'cmp' : '');
  R.src = opts.src || (opts.rec ? 'Saved in ' + ((theCase(DB.active) || {}).code || 'this case') : opts.name || 'Pasted');
  if(R.pe){ R.pe.name = opts.name || 'program'; R.u = input; }
  if(opts.cmp){ R.certs.forEach(c => { if(!S.cmpX.some(x => cxId(x) === cxId(c))) S.cmpX.push(c); }); if(R.certs[0]) S.cmpB = 'x:' + cxId(R.certs[0]); S.tab = 'compare'; cxPaint(); return Promise.all(R.certs.map(c => X5.prints(c))).then(() => cxPaint()); }
  S.R = R;
  if(!R.certs.length && R.csrs.length) S.tab = 'csr'; else if(opts.tab) S.tab = opts.tab; else if(['guide', 'ct', 'compare'].includes(S.tab) || (S.tab === 'csr' && !R.csrs.length) || (S.tab === 'chain' && R.certs.length < 2)) S.tab = 'decoder';
  cxPaint(); return cxEnrich(R);
}
async function cxEnrich(R){
  try{
    if(R.pe && R.u){ await X5.peCheck(R.pe, R.u); R.u = null; }
    await Promise.all([...R.certs, ...R.csrs].map(c => X5.prints(c)));
    for(const c of R.certs) if(c.selfIssued) c.selfOk = await X5.verify(c, c);
    for(const c of R.csrs) c.selfOk = await X5.verify(c, c);
    if(R.certs.length){ R.chain = await X5.chain(R.certs); const lead = R.pe ? cxPeSigner(R) : null, leaf = lead || R.chain.order[0]; cxS().sel = Math.max(0, R.certs.indexOf(leaf)); }
  }catch(e){ console.error(e); }
  R.ready = true; if(cxS().R === R) cxPaint();
}
/* ---------- history: everything opened here is kept in this browser (never a private key) ---------- */
let CX_NOKEEP = false;
const cxNameOf = R => { const c = R.certs[0] || R.csrs[0]; return c ? (c.kind === 'csr' ? 'CSR · ' : '') + (c.title || 'certificate') : R.pe ? 'program' : 'certificate'; };
const cxStripKeys = t => t.replace(/-----BEGIN ([A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*)-----[\s\S]*?-----END \1-----\s*/g, '');
function cxKeep(name, data, mode){
  if(CX_NOKEEP || typeof recentAdd !== 'function') return;
  if(typeof data === 'string'){ data = cxStripKeys(data); if(/PRIVATE KEY-----|PuTTY-User-Key-File/.test(data)) return; }
  recentAdd('certs', name, data, {mode}).then(() => { const b = document.querySelector('[data-act=cxSaved] .crt-cnt'); if(b) b.textContent = cxHistN(); });
}
const cxHistN = () => (typeof recentOf === 'function' ? recentOf('certs').length : 0) + cxRecs().length;
if(typeof RECENT_OPEN !== 'undefined'){
  RECENT_OPEN.certs = async (it, data, restoring) => {
    if(UI.route.area !== 'certs' && !restoring){ go('#/certs'); await new Promise(r => setTimeout(r, 30)); }
    CX_NOKEEP = true;
    try{
      const S = cxS();
      if(it.mode === 'ct'){ const A = ctParse(data); if(A){ S.ct = A; S.ctF = ''; S.ctRec = null; S.ctDom = S.ctDom || A.dom; if(!restoring || !S.R) S.tab = 'ct'; cxPaint(); } return; }
      if(data instanceof File) return await cxReadFile(data, it.mode);
      if(it.mode === 'cmp') return cxLoad(data, {cmp:true, src:it.name});
      S.input = data; S.rec = null; return cxLoad(data, {name:it.name, src:restoring ? 'Reopened · ' + it.name : it.name});
    }finally{ CX_NOKEEP = false; }
  };
  RECENT_AFTER_DEL.certs = x => { const S = cxS();
    if(!x || x.wasOpen){ if(!x || x.mode === 'ct') S.ct = null; if((!x || x.mode !== 'ct') && S.R && !S.rec){ S.R = null; S.input = ''; } if(UI.route.area === 'certs') cxPaint(); }
    const b = document.querySelector('[data-act=cxSaved] .crt-cnt'); if(b) b.textContent = cxHistN(); };
}
/* the History window: recent inputs in this browser, and what is saved in the case — each one deletable */
function cxHistory(){
  const extra = () => { const recs = cxRecs();
    return `<section><h3>Saved in ${esc(theCase(DB.active) ? theCase(DB.active).code : 'this case')}<small>${recs.length}</small></h3>
      ${recs.length ? `<ul class="rc-l">${recs.slice(0, 60).map(rec => `<li class="rc-r"><span class="rc-ic">${ico('archive','sm')}</span><button class="rc-o" data-act="cxHistRec" data-id="${rec.id}"><b>${esc(rec.title.replace(/^(Certificate|Signing request|Signed program): /, ''))}</b><small>${esc(rec.title.split(':')[0])} · ${esc(E.fmtAgo(Math.max(0, Date.now() - (rec.addedAt || rec.ts || 0))))}${cxS().rec === rec.id ? ' · open now' : ''}</small></button>
        <button class="iconbtn rc-d" data-act="cxHistDel" data-id="${rec.id}" aria-label="Move ${esc(rec.title)} to the trash" title="Move to trash">${ico('trash-2','sm')}</button></li>`).join('')}</ul>` : '<p class="rc-none">Nothing saved in this case yet. Use Save to case on a certificate to keep it as evidence.</p>'}
      <p class="rc-note">${ico('info','sm')}Saved items are evidence records. Deleting one moves it to the trash, where it can be restored for 30 days.</p></section>`; };
  UI.rcExtraFn = extra; recentDlg('certs', extra());
}
const cxFindings = c => (c._F = c._F || X5.findings(c));
function cxRecParse(r){ const k = r.id + ':' + (r.hash || r.body.length); if(CX_REC.has(k)) return CX_REC.get(k); const R = X5.read(r.body); CX_REC.set(k, R); return R; }
/* crt.sh JSON (or anything shaped like it) pasted instead of a certificate */
const cxLooksCt = t => /^\s*[[{]/.test(t) && /"(name_value|common_name|issuer_name)"/.test(t.slice(0, 4000));
function cxIngest(text, opts = {}){
  if(cxLooksCt(text)){ const A = ctParse(text); if(A){ const S = cxS(); S.ct = A; S.ctF = ''; S.ctDom = S.ctDom || A.dom; S.tab = 'ct'; cxKeep('crt.sh · ' + (A.dom || 'names'), text, 'ct'); return cxPaint(); } return toast('That JSON is not a crt.sh result list'); }
  const S = cxS(); if(!opts.cmp){ S.input = text; S.rec = null; } return cxLoad(text, Object.assign({src:'Pasted'}, opts));
}

/* ---------- view ---------- */
function viewCerts(){
  const S = cxS();
  return `<div class="crtw"><div class="crt-tabs" role="tablist" aria-label="Certificates">
      <span class="crt-t">${ico('shield-check')}Certificates</span>
      ${CX_TABS.map(([k, l, i]) => `<button role="tab" id="cxt-${k}" aria-selected="${S.tab === k}" aria-controls="cxBody" data-act="cxTab" data-v="${k}">${ico(i,'sm')}${l}</button>`).join('')}</div>
    <div class="crt-body" id="cxBody" role="tabpanel" aria-labelledby="cxt-${S.tab}">${cxBodyHtml()}</div>
    <div class="crt-dropov" aria-hidden="true"><div>${ico('upload')}<b>Drop to open</b><span>Certificates, chains, requests, crt.sh JSON, or a signed .exe / .dll</span></div></div></div>`;
}
function cxBodyHtml(){
  const S = cxS(); if(S.tab === 'guide') return cxGuide();
  const main = S.tab === 'decoder' ? cxDecoder() : S.tab === 'chain' ? cxChain() : S.tab === 'csr' ? cxCsr() : S.tab === 'compare' ? cxCompare() : cxCt();
  return `<div class="crt-main">${cxBar()}<div class="crt-g${(S.tab === 'decoder' && S.R && S.R.certs.length) || (S.tab === 'ct' && S.ct) ? '' : ' two'}">${main}</div></div>`;
}
function cxPaint(){ const b = $('cxBody'); if(!b) return; const S = cxS(), ae = document.activeElement, fid = ae && b.contains(ae) && ae.id, sc = (b.querySelector('.crt-c') || {}).scrollTop || 0;
  b.innerHTML = cxBodyHtml(); b.setAttribute('aria-labelledby', 'cxt-' + S.tab);
  document.querySelectorAll('.crt-tabs [role=tab]').forEach(t => t.setAttribute('aria-selected', t.dataset.v === S.tab)); bindCerts();
  const c = b.querySelector('.crt-c'); if(c && sc && cxPaint.keep) c.scrollTop = sc; cxPaint.keep = false;
  if(fid && /^(cxCtDom|cxCtF)$/.test(fid) && $(fid)){ const el = $(fid); el.focus({preventScroll:true}); if(el.setSelectionRange && /^(text|search|)$/.test(el.type || '') && el.tagName === 'INPUT'){ const n = el.value.length; el.setSelectionRange(n, n); } } }

/* the input along the top: paste box, file, examples, saved certificates */
function cxBar(){
  const S = cxS(), n = cxRecs().length;
  if(S.tab === 'ct'){ const d = (S.ctDom || '').trim();
    return `<div class="crt-inb" id="cxDrop"><div class="crt-inf"><span class="crt-ini">${ico('globe','sm')}</span><label class="sr" for="cxCtDom">Domain to look up</label>
        <input id="cxCtDom" value="${esc(S.ctDom || '')}" placeholder="Domain to look up, e.g. example.com" spellcheck="false" autocomplete="off"></div>
      <a class="btn sm" id="cxCtLink" target="_blank" rel="noopener noreferrer"${d ? ` href="${esc(cxCtUrl(d))}"` : ' aria-disabled="true"'}>${ico('external-link','sm')}Open on crt.sh as JSON</a>
      <button class="btn sm primary" data-act="cxPaste" data-v="ct">${ico('clipboard-paste','sm')}Paste the results</button>
      <button class="btn sm" data-act="cxFile" data-v="ct">${ico('upload','sm')}Open .json</button>
      <button class="btn sm ghost" data-act="cxSample" data-v="ct">${ico('sparkles','sm')}Example</button></div>`; }
  const R = S.R, cmp = S.tab === 'compare', items = R ? (R.pe ? 1 : R.certs.length + R.csrs.length) : 0;
  const lead = R && (R.pe ? null : R.certs.length ? (R.chain ? R.chain.order[0] : leafGuess(R.certs)) : R.csrs[0]);
  const label = cmp ? 'Add certificates to compare' : !R ? 'Nothing open yet' : R.pe ? R.pe.name : lead.title + (items > 1 ? ' + ' + (items - 1) + ' more' : '');
  const sub = cmp ? 'Paste, drop or open a file — it joins the list you can compare' : !R ? 'Paste with Ctrl+V anywhere on this page, drop a file, or open one' : esc(R.src || '') + ' · ' + (R.pe ? 'signed program' : [R.certs.length ? R.certs.length + ' certificate' + (R.certs.length > 1 ? 's' : '') : '', R.csrs.length ? R.csrs.length + ' request' + (R.csrs.length > 1 ? 's' : '') : ''].filter(Boolean).join(', ')) + ' · opened ' + esc(ago(R.at));
  return `<div class="crt-inb" id="cxDrop"><div class="crt-src"><span class="crt-srci ${R && !cmp ? 'on' : ''}">${ico(R && R.pe && !cmp ? 'app-window' : R && !cmp ? 'scroll-text' : 'upload')}</span><div><b>${esc(label)}</b><small>${sub}</small></div></div>
    <button class="btn primary" data-act="cxPaste" data-v="${cmp ? 'cmp' : 'decode'}">${ico('clipboard-paste','sm')}Paste${R && !cmp ? ' another' : ''}…</button>
    <button class="btn" data-act="cxFile">${ico('upload','sm')}Open file</button>
    <button class="btn ghost" data-act="cxExamples" aria-haspopup="menu">${ico('sparkles','sm')}Examples${ico('chevron-down','sm')}</button>
    <button class="btn ghost" data-act="cxSaved" aria-haspopup="dialog">${ico('history','sm')}History<span class="crt-cnt">${cxHistN()}</span></button>
    ${R && !cmp ? `<button class="iconbtn" data-act="cxClear" aria-label="Close this certificate" title="Close">${ico('x','sm')}</button>` : ''}</div>
  ${S.keyWarn ? `<p class="crt-key" role="alert">${ico('triangle-alert','sm')}<span>That included a <b>private key</b>. It was not read, kept or saved. If it came from anywhere public, treat it as exposed.</span></p>` : ''}`;
}
function cxPasteDlg(mode){
  const T = {decode:['Paste certificates', 'Certificates, a chain, a signing request, openssl s_client output — or crt.sh JSON. Private keys are refused.', 'Decode'], cmp:['Add a certificate to compare', 'Paste the certificate to compare against. It is kept for this comparison only.', 'Compare'], ct:['Paste crt.sh results', 'Open crt.sh with “output=json” (the button on the page builds the link), select all, copy, and paste here.', 'Analyse']}[mode] || [];
  openDlg(`${dhead(T[0])}<div class="in crt-pd" id="cxPd"><p class="t3">${T[1]}</p><label class="sr" for="cxPdIn">${T[0]}</label>
      <textarea id="cxPdIn" class="inp" spellcheck="false" placeholder="${mode === 'ct' ? '[{&quot;issuer_ca_id&quot;: …, &quot;name_value&quot;: …}]' : '-----BEGIN CERTIFICATE-----'}"></textarea>
      <p class="t3 crt-pdh">${ico('upload','sm')}You can also drop a file onto this box.</p></div>
    <footer><span class="t3">Ctrl+Enter</span><button class="btn" data-act="dclose">Cancel</button><button class="btn" data-act="cxPdFile" data-v="${mode}">${ico('upload','sm')}Open file</button><button class="btn primary" data-act="cxPdGo" data-v="${mode}">${T[2]}</button></footer>`, true, () => {
    const pd = $('cxPd'), ta = $('cxPdIn');
    ta.addEventListener('keydown', ev => { if(ev.key === 'Enter' && (ev.ctrlKey || ev.metaKey)){ ev.preventDefault(); CX_ACTS.cxPdGo(null, mode); } });
    pd.addEventListener('dragover', ev => { if([...(ev.dataTransfer.types || [])].includes('Files')){ ev.preventDefault(); ev.stopPropagation(); pd.classList.add('over'); } });
    pd.addEventListener('dragleave', () => pd.classList.remove('over'));
    pd.addEventListener('drop', ev => { const f = ev.dataTransfer.files[0]; if(!f) return; ev.preventDefault(); ev.stopPropagation(); closeDlg(); cxReadFile(f, mode); });
  });
  $('dlg').setAttribute('aria-label', T[0]);
}
const leafGuess = certs => certs.find(c => !c.isCA) || certs[0];
const cxDropZone = (t, d, mode = 'decode') => `<button class="crt-dz" data-act="cxPaste" data-v="${mode}"><span>${ico('upload')}</span><b>${t}</b><small>${d}</small><em>Click to paste · Ctrl+V anywhere · or drop a file on this page</em></button>`;

/* ---------- decoder ---------- */
function cxDecoder(){
  const S = cxS(), R = S.R;
  if(R && R.pe && !R.certs.length) return `<div class="crt-c">${cxPeCard(R)}</div><aside class="crt-r"></aside>`;
  if(!R || !R.certs.length) return `<div class="crt-c">${cxDropZone('Open a certificate to investigate', 'A certificate, chain, signing request or openssl output — or a signed .exe / .dll. You get who it belongs to, the infrastructure it names, where else those names appear in your cases, ready-made pivots and hunting queries, and anything suspicious.')}
    <div class="crt-try"><span>Or try a fictional example:</span><button class="chip" data-act="cxSample" data-v="phish">${ico('scroll-text','sm')}Phishing site</button><button class="chip" data-act="cxSample" data-v="cs">${ico('scroll-text','sm')}Cobalt Strike server</button><button class="chip" data-act="cxSample" data-v="pe">${ico('app-window','sm')}Signed program</button><button class="chip" data-act="cxSample" data-v="chain">${ico('link-2','sm')}Chain</button><button class="chip" data-act="cxTab" data-v="guide">${ico('book-open','sm')}How certificates work</button></div></div>`;
  const c = R.certs[S.sel] || R.certs[0], F = cxFindings(c), w = cxWorst(F), now = Date.now(), left = c.notAfter - now, bad = F.filter(f => f.s === 'bad').length;
  const exp = now > c.notAfter, pre = now < c.notBefore, life = Math.min(100, Math.max(0, (now - c.notBefore) / (c.notAfter - c.notBefore) * 100));
  const org = (c.subject.map.O || [])[0], iss = [(c.issuer.map.CN || [])[0], (c.issuer.map.O || [])[0]].filter(Boolean).join(' · ') || c.issuer.text;
  const looks = new Set(F.filter(f => f.t === 'Lookalike name').length ? c.san.filter(s => s.t === 'DNS' && Object.entries(X5.BRANDS).some(([t, own]) => s.v.toLowerCase().includes(t) && !own.includes(X5.regDom(s.v)))).map(s => s.v) : []);
  const strip = R.certs.length > 1 ? `<div class="crt-strip"><span>${R.certs.length} certificates in this input:</span>${(R.chain ? R.chain.order.concat(R.chain.extra) : R.certs).map(x => `<button class="chip${x === c ? ' on' : ''}" data-act="cxSel" data-v="${R.certs.indexOf(x)}"${x === c ? ' aria-pressed="true"' : ' aria-pressed="false"'}>${esc(x.title)}</button>`).join('')}<button class="btn xs ghost" data-act="cxTab" data-v="chain">${ico('link-2','sm')}See the chain</button></div>` : '';
  const kv = c.subject.parts.map(([k, v]) => `<span>${esc(k === 'CN' ? 'Common name' : X5L(k))}</span><b${k === 'CN' ? ' class="mono"' : ''}>${esc(v)}</b>`).join('');
  const reuse = cxReuse(c), inds = cxInds(c), seen = cxSeen(inds);
  return `<div class="crt-c">
    ${R.pe ? cxPeCard(R) : ''}${strip}
    <section class="card crt-hero"><span class="crt-big ${exp ? 'warn' : w}">${ico(exp ? 'clock' : w === 'ok' ? 'shield-check' : 'shield-alert')}</span>
      <div class="crt-hm"><h1>${esc(c.title)}</h1><p>Issued by <b>${esc(iss)}</b>${c.selfIssued ? ' (itself)' : ''} · ${org ? 'to <b>' + esc(org) + '</b>' : c.isCA ? 'a certificate authority' : 'to no organisation (domain validated)'}</p>
        <div class="crt-pills">${exp ? `<span class="crt-pill amber">${ico('clock','sm')}Expired ${cxDays(-left)} days ago</span>` : pre ? `<span class="crt-pill amber">Not valid until ${cxDay(c.notBefore)}</span>` : `<span class="crt-pill green">${ico('check','sm')}Valid · ${cxDays(left)} days left</span>`}
          ${c.isCA ? `<span class="crt-pill">${c.selfIssued ? 'Root' : 'Intermediate'} CA${c.bc && c.bc.pathLen != null ? ' · path length ' + c.bc.pathLen : ''}</span>` : c.level ? `<span class="crt-pill">${esc(c.level)} · ${cxDays(c.notAfter - c.notBefore)}-day</span>` : ''}
          ${cxKind(c) ? `<button class="crt-pill crt-kind" data-act="cxType" data-v="${cxKind(c)}" title="What this type of certificate is for">${ico('book-open','sm')}${esc(CX_KIND[cxKind(c)])}</button>` : ''}
          <span class="crt-pill">${esc(c.key.label)}</span><span class="crt-pill">${esc(c.sigAlg.name)}</span>${c.selfIssued ? `<span class="crt-pill">Self-signed${c.selfOk === true ? ' ✓' : ''}</span>` : ''}
          ${bad ? `<span class="crt-pill red">${ico('triangle-alert','sm')}${bad} red flag${bad > 1 ? 's' : ''}</span>` : ''}${reuse.length ? `<span class="crt-pill blue">${ico('key-round','sm')}Key shared with ${reuse.length}</span>` : ''}</div></div>
      <div class="crt-ha">${S.rec ? `<span class="crt-pill green">${ico('check','sm')}Saved</span>` : `<button class="btn sm primary" data-act="cxSave">${ico('plus','sm')}Save to case</button>`}<button class="btn sm" data-act="cxCopyPem">${ico('copy','sm')}Copy PEM</button><button class="btn sm ghost" data-act="cxExport" aria-haspopup="menu">${ico('download','sm')}Export${ico('chevron-down','sm')}</button></div></section>
    ${cxAssessCard(c, R, F, reuse, inds, seen)}
    <div class="crt-2">
      <section class="card crt-s"><h3>${ico('user','sm')}Subject and issuer</h3><div class="crt-kv">${kv || '<span>Subject</span><b>(empty)</b>'}<span>Issuer</span><b>${esc(c.issuer.text)}</b><span>Serial</span><b class="mono">${esc(c.serial.length > 30 ? c.serial.slice(0, 29) + '…' : c.serial)}</b></div>
        <div class="crt-life"><div class="crt-bar" role="img" aria-label="${Math.round(life)}% of its lifetime used"><i style="width:${life}%"></i>${!exp && !pre ? `<em style="left:${life}%"></em>` : ''}</div>
          <div class="crt-lg"><span>From ${esc(cxDate(c.notBefore))}</span><span>To ${esc(cxDate(c.notAfter))}</span></div></div></section>
      <section class="card crt-s"><h3>${ico('globe','sm')}Names it covers${c.san.length ? `<span class="crt-n">${c.san.length}</span>` : ''}</h3>
        ${c.san.length ? `<div class="crt-chips">${c.san.slice(0, 80).map(s => `<span class="chip mono${looks.has(s.v) ? ' hl' : ''}" title="${esc(s.t)}">${looks.has(s.v) ? ico('triangle-alert','sm') : ''}${s.t !== 'DNS' && s.t !== 'IP' ? `<i>${esc(s.t)}</i>` : ''}${esc(s.v)}</span>`).join('')}${c.san.length > 80 ? `<span class="chip">+${c.san.length - 80} more</span>` : ''}</div>
          <div class="crt-ba">${S.rec ? '' : `<button class="btn sm" data-act="cxSave">${ico('plus','sm')}Add ${c.san.length} to case as entities</button>`}<button class="btn sm ghost" data-act="cxCopyNames">${ico('copy','sm')}Copy list</button></div>`
          : `<p class="crt-e">No subject alternative names.${c.cn ? ' Only the common name: <span class="mono">' + esc(c.cn) + '</span>' : ''}</p>`}</section></div>
    ${cxIndCard(c, inds, seen)}
    <div class="crt-2">${cxTestCard(c)}${reuse.length ? cxReuseCard(c, reuse) : cxCompareHint(c)}</div>
    <section class="card crt-s"><h3>${ico('list','sm')}Extensions, in plain English</h3>${c.exts.length ? `<div class="crt-ext">${c.exts.map(cxExtRow).join('')}</div>` : '<p class="crt-e">None — a version 1 certificate or one made by hand.</p>'}</section>
    <section class="card crt-s crt-fp"><h3>${ico('fingerprint','sm')}Fingerprints</h3>${c.fp ? [['SHA-256', c.fp.sha256.toUpperCase().match(/../g).join(':'), c.fp.sha256], ['SHA-1', c.fp.sha1.toUpperCase().match(/../g).join(':'), c.fp.sha1], ['Key SHA-256', c.fp.spki256, c.fp.spki256], ['Key pin', 'pin-sha256="' + c.fp.pin + '"', c.fp.pin]].map(([l, v, raw]) => `<div class="crt-fr"><span>${l}</span><code>${esc(v)}</code><button class="iconbtn" data-act="cxCopy" data-v="${esc(raw)}" aria-label="Copy ${l}">${ico('copy','sm')}</button></div>`).join('') : '<p class="crt-e">Working them out…</p>'}</section>
    ${c.fp ? cxHunt(c) : ''}
    <details class="card crt-s crt-raw"><summary>${ico('binary','sm')}Raw structure (ASN.1)</summary><div class="crt-asn" tabindex="0" role="region" aria-label="ASN.1 structure">${cxAsn(X5.parse(c.der))}</div></details>
  </div>${cxRight(c, F, reuse)}`;
}

/* ---------- the investigation side: indicators, where else they appear, an assessment ---------- */
function cxInds(c){
  const out = [], seen = new Set(), add = (k, v, label, from) => { v = String(v || '').trim(); if(!v) return; const key = k + ':' + v.toLowerCase(); if(seen.has(key)) return; seen.add(key); out.push({k, v, label, from}); };
  for(const n of c.san){ if(n.t === 'DNS') add('domain', n.v.replace(/^\*\./, ''), n.v.startsWith('*.') ? 'Domain (wildcard)' : 'Domain', n.v); else if(n.t === 'IP') add(n.v.includes(':') ? 'ipv6' : 'ipv4', n.v, 'IP address'); else if(n.t === 'Email') add('email', n.v, 'Email'); else if(n.t === 'URI') add('url', n.v, 'URL'); else if(n.t === 'UPN') add('email', n.v, 'Windows account (UPN)'); }
  if(c.cn && /^[a-z0-9*.-]+\.[a-z]{2,}$/i.test(c.cn)) add('domain', c.cn.replace(/^\*\./, ''), 'Domain (common name)');
  for(const e of c.subject.map.emailAddress || []) add('email', e, 'Email in the subject');
  const regs = [...new Set(out.filter(x => x.k === 'domain').map(x => X5.regDom(x.v)))]; for(const d of regs) add('domain', d, 'Registered domain');
  for(const o of c.subject.map.O || []) if(!c.isCA) add('organization', o, 'Organisation named');
  return out;
}
/* every record in every case that mentions one of these indicators (or a fingerprint of this certificate) */
const cxMemo = (k, fn) => { const key = k + '|' + STORE.gen + '|' + DB.records.length; cxMemo.m = cxMemo.m || new Map(); if(cxMemo.m.has(key)) return cxMemo.m.get(key); if(cxMemo.m.size > 50) cxMemo.m.clear(); const v = fn(); cxMemo.m.set(key, v); return v; };
function cxSeen(inds){ const c0 = cxCur(); return cxMemo('seen:' + cxS().rec + ':' + (c0 ? cxId(c0) + (c0.fp ? 1 : 0) : '') + inds.map(x => x.v).join(','), () => cxSeen0(inds)); }
function cxSeen0(inds){
  const S = cxS(), c = cxCur(), want = new Map(inds.filter(x => x.k !== 'organization').map(x => [x.v.toLowerCase(), x]));
  if(c && c.fp){ want.set(c.fp.sha256, {k:'sha256', v:c.fp.sha256, label:'This certificate (SHA-256)'}); want.set(c.fp.sha1, {k:'sha1', v:c.fp.sha1, label:'This certificate (SHA-1)'}); }
  const regs = new Map(inds.filter(x => x.k === 'domain').map(x => [X5.regDom(x.v), x])), hits = [];
  for(const r of DB.records){ if(r.id === S.rec || !r.ents) continue; const exact = new Set(), near = new Set();
    for(const e of r.ents){ const v = String(e.v || '').toLowerCase(); if(want.has(v)) exact.add(want.get(v).v); else if(e.k === 'domain' && regs.has(X5.regDom(v))) near.add(e.v); }
    if(exact.size || near.size) hits.push({r, exact:[...exact], near:[...near]}); }
  return hits.sort((a, b) => b.exact.length - a.exact.length || (b.r.ts || 0) - (a.r.ts || 0));
}
const cxIndCount = (seen, v) => seen.filter(h => h.exact.some(x => x.toLowerCase() === v.toLowerCase())).length;
function cxIndCard(c, inds, seen){
  if(!inds.length) return '';
  const S = cxS(), pick = S.indPick || (S.indPick = new Set());
  const row = x => { const L = pivotLinks(x.k, x.v), n = cxIndCount(seen, x.v), id = x.k + ':' + x.v;
    return `<tr><td class="crt-ck"><input type="checkbox" data-act="cxIndPick" data-v="${esc(id)}" aria-label="Select ${esc(x.v)}"${pick.has(id) ? ' checked' : ''}></td><td><b class="mono">${esc(x.v)}</b><small>${esc(x.label)}${x.from && x.from !== x.v ? ' · ' + esc(x.from) : ''}</small></td>
      <td>${n ? `<button class="crt-seen" data-act="cxSeenGo" data-v="${esc(x.v)}">${ico('folder-open','sm')}In ${n} record${n > 1 ? 's' : ''}</button>` : '<span class="t3">New</span>'}</td>
      <td class="crt-pvs">${L.slice(0, 3).map(([nm, u]) => `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(nm)}</a>`).join('')}${L.length > 3 ? `<button class="btn xs ghost" data-act="cxPivMenu" data-v="${esc(id)}" aria-haspopup="menu">+${L.length - 3}</button>` : ''}</td></tr>`; };
  return `<section class="card crt-s" id="cxInd"><h3>${ico('crosshair','sm')}Indicators and pivots<span class="crt-n">${inds.length}</span></h3>
    <p class="crt-e">Everything in this certificate you can look up. “In N records” means it already appears in your cases; links open the service in a new tab.</p>
    <div class="tblwrap" tabindex="0" role="region" aria-label="Indicators"><table class="crt-tbl crt-it"><thead><tr><th scope="col"><span class="sr">Select</span></th><th scope="col">Indicator</th><th scope="col">Your cases</th><th scope="col">Look it up</th></tr></thead><tbody>${inds.map(row).join('')}</tbody></table></div>
    <div class="crt-ba"><button class="btn sm" data-act="cxIndAll">${pick.size ? 'Clear selection' : 'Select all'}</button><button class="btn sm" data-act="cxIndGraph"${pick.size ? '' : ' disabled'}>${ico('share-2','sm')}Add ${pick.size || ''} to graph</button><button class="btn sm ghost" data-act="cxIndCopy" data-v="d">${ico('copy','sm')}Copy defanged</button><button class="btn sm ghost" data-act="cxIndCopy">${ico('copy','sm')}Copy</button></div></section>
    ${seen.length ? cxSeenCard(seen) : ''}`;
}
function cxSeenCard(seen){
  return `<section class="card crt-s" id="cxSeen"><h3>${ico('folder-open','sm')}Already in your cases<span class="crt-n">${seen.length}</span></h3>
    <div class="crt-sl">${seen.slice(0, 12).map(h => { const cs = theCase(h.r.caseId) || {}; return `<button class="crt-sli" data-act="cxOpenRec" data-id="${h.r.id}"><span class="crt-cc">${esc(cs.code || '?')}</span><span><b>${esc(h.r.title || '(untitled)')}</b><small>${h.exact.length ? 'Mentions ' + h.exact.slice(0, 3).map(esc).join(', ') + (h.exact.length > 3 ? ' +' + (h.exact.length - 3) : '') : 'Same registered domain: ' + h.near.slice(0, 2).map(esc).join(', ')}${h.r.ts ? ' · ' + esc(cxYmd(h.r.ts)) : ''}</small></span>${ico('arrow-right','sm')}</button>`; }).join('')}</div>
    ${seen.length > 12 ? `<p class="crt-e">+${seen.length - 12} more records</p>` : ''}</section>`;
}
/* a plain-English read of the certificate for the case notes or a report */
function cxAssess(c, R, F, reuse, inds, seen){
  const bad = F.filter(f => f.s === 'bad'), warn = F.filter(f => f.s === 'warn'), now = Date.now(), dns = inds.filter(x => x.k === 'domain' && x.label !== 'Registered domain'), regs = [...new Set(dns.map(x => X5.regDom(x.v)))].map(v => ({v})), ips = inds.filter(x => /^ipv/.test(x.k));
  const org = (c.subject.map.O || [])[0], code = (c.eku || []).some(e => e.oid === '1.3.6.1.5.5.7.3.3'), age = cxDays(now - c.notBefore);
  const tone = bad.length ? 'bad' : warn.length ? 'warn' : 'ok';
  const head = bad.some(f => /Cobalt|Lookalike|brand/.test(f.t)) ? 'Looks like attacker infrastructure' : bad.length ? 'Red flags — treat as suspicious' : warn.length ? 'Unusual — needs context' : 'Nothing suspicious in the certificate itself';
  const P = [], kind = cxKind(c), priv = !c.scts.length && !c.selfIssued;
  const KP = {server:'proves a server’s name to clients', client:'logs a person or program in to a server (VPN, Wi‑Fi, mutual TLS)', device:'proves a machine is a managed company device', ca:'issues other certificates', code:'signs software', smime:'signs and encrypts email', smartcard:'logs on to Windows and Active Directory', docsign:'signs documents', tsa:'signs trusted timestamps'};
  if(kind) P.push('A ' + CX_KIND[kind].toLowerCase().replace('tls', 'TLS').replace('(s/mime)', '(S/MIME)') + ' certificate: it ' + KP[kind] + '.');
  P.push(c.selfIssued ? 'Self-signed: nobody vouches for who made it.' : org ? `Issued to “${org}”${c.level === 'EV' || c.level === 'OV' ? ', and the CA checked that organisation' : ''}.` : code ? 'A code signing certificate.' : 'Domain-validated: the CA only checked that the requester controlled ' + (dns.length > 1 ? 'the names' : 'the name') + ', not who they are.');
  if(dns.length || ips.length) P.push(`Names ${dns.length ? dns.length + ' host' + (dns.length > 1 ? 's' : '') + (regs.length > 1 ? ' across ' + regs.length + ' registered domains (' + regs.slice(0, 3).map(x => x.v).join(', ') + ')' : '') : ''}${ips.length ? (dns.length ? ' and ' : '') + ips.length + ' IP address' + (ips.length > 1 ? 'es' : '') + ' (' + ips.map(x => x.v).join(', ') + ')' : ''}.`);
  if(!c.isCA) P.push(`Issued ${cxYmd(c.notBefore)}${age >= 0 && age < 400 ? ' — ' + age + ' day' + (age === 1 ? '' : 's') + ' ago' : ''}, ${now > c.notAfter ? 'expired ' + cxYmd(c.notAfter) : 'valid until ' + cxYmd(c.notAfter)}${c.scts.length ? '; publicly logged, so its history is searchable' : ''}.`);
  for(const f of bad.concat(warn).slice(0, 3)) P.push(f.t + ': ' + f.d.replace(/\s*$/, '') + (/[.!?]$/.test(f.d) ? '' : '.'));
  if(reuse.length) P.push(`Its private key is also in ${reuse.length} other certificate${reuse.length > 1 ? 's' : ''} (${reuse.slice(0, 2).map(x => x.c.title).join(', ')}) — the same operator.`);
  if(seen.length) P.push(`${seen.length} record${seen.length > 1 ? 's' : ''} in your cases already mention${seen.length > 1 ? '' : 's'} these indicators.`);
  const N = [];
  if(regs.length && !(priv && /client|device|smartcard|smime|docsign/.test(kind))) N.push(['radar', 'List every certificate ever issued for ' + regs[0].v, 'cxCtFor', regs[0].v]);
  if(priv && /client|device|smartcard/.test(kind)) P.push('Issued by a private company CA, so it is not in public Certificate Transparency logs — the trail is in that CA’s issued-certificates database and on the endpoints that hold the key.');
  if(kind) N.push(['book-open', 'What ' + CX_KIND[kind].toLowerCase().replace('tls', 'TLS').replace('(s/mime)', '(S/MIME)') + ' certificates are for, and how they are abused', 'cxType', kind]);
  if(dns.length || ips.length) N.push(['crosshair', 'Look up the hosts: hosting, WHOIS, reputation', 'cxGoInd', '']);
  if(c.fp && !c.isCA && (!kind || kind === 'server')) N.push(['server', 'Find other servers presenting it (Shodan, Censys)', 'cxGoHunt', '']);
  if(code) N.push(['app-window', 'Find files signed with it on your devices', 'cxGoHunt', '']);
  if(bad.some(f => f.t === 'Lookalike name')) N.push(['flag', 'Report the lookalike domain to its registrar and to the brand', '', '']);
  if(!cxS().rec) N.push(['plus', 'Save it to the case so the names become entities on the timeline and graph', 'cxSave', '']);
  return {tone, head, P, N};
}
function cxAssessCard(c, R, F, reuse, inds, seen){
  const A = cxAssess(c, R, F, reuse, inds, seen);
  return `<section class="card crt-as"><div class="crt-ash"><span class="crt-big ${A.tone}">${ico(A.tone === 'ok' ? 'shield-check' : 'shield-alert')}</span><div><p class="crt-k">Investigator’s read</p><h2>${esc(A.head)}</h2></div>
      <button class="btn sm ghost" data-act="cxReport">${ico('copy','sm')}Copy for a report</button></div>
    <div class="crt-asb"><ul class="crt-asp">${A.P.map(p => `<li>${esc(p)}</li>`).join('')}</ul>
      <div class="crt-nx"><h4>Next steps</h4>${A.N.map(([i, t, act, v]) => act ? `<button class="crt-nxi" data-act="${act}" data-v="${esc(v)}">${ico(i,'sm')}<span>${esc(t)}</span>${ico('arrow-right','sm')}</button>` : `<div class="crt-nxi">${ico(i,'sm')}<span>${esc(t)}</span></div>`).join('')}</div></div></section>`;
}

/* what job a certificate is for, as a section of the "Types of certificates" chapter */
const CX_KIND = {server:'Website (TLS server)', client:'Client authentication', device:'Device / machine', ca:'Certificate authority', code:'Code signing', smime:'Email (S/MIME)', smartcard:'Windows logon', docsign:'Document signing', tsa:'Timestamping authority'};
function cxKind(c){
  if(c.isCA) return 'ca';
  const ek = (c.eku || []).map(e => e.oid), has = o => ek.includes(o);
  if(has('1.3.6.1.4.1.311.20.2.2')) return 'smartcard';
  if(has('1.3.6.1.5.5.7.3.3')) return 'code';
  if(has('1.3.6.1.5.5.7.3.8')) return 'tsa';
  if(has('1.3.6.1.5.5.7.3.36') || has('1.3.6.1.4.1.311.10.3.12')) return 'docsign';
  if(has('1.3.6.1.5.5.7.3.1') || (!ek.length && c.san.some(s => s.t === 'DNS' || s.t === 'IP'))) return 'server';
  if(has('1.3.6.1.5.5.7.3.4') && !has('1.3.6.1.5.5.7.3.2')) return 'smime';
  if(has('1.3.6.1.5.5.7.3.2')) return c.san.some(s => s.t === 'DNS') || /\.[a-z]{2,}$/i.test(c.cn || '') ? 'device' : 'client';
  return '';
}

/* signed Windows programs: what the Authenticode signature says, and whether the file still matches it */
const cxPeSigner = R => { const s = R.pe && R.pe.sigs[0] && R.pe.sigs[0].signers[0]; return s && s.cert; };
function cxPeCard(R){
  const P = R.pe, sd = P.sigs[0], sg = sd && sd.signers[0], ck = P.checked;
  const head = `<div class="crt-ch"><span class="crt-big ${!sd ? 'warn' : !ck ? 'inf' : sd.fileOk === false || (sg && sg.sigOk === false) ? 'bad' : 'ok'}">${ico('app-window')}</span><div><h2>${esc(P.name)}</h2>
      <p>${P.dll ? 'Windows library (DLL)' : 'Windows program'} · ${esc(P.machine)} · ${cxBytes(P.size)}${isFinite(P.compiled) && P.compiled > 0 ? ' · built ' + esc(cxDate(P.compiled)) + ' (from the header, easy to fake)' : ''}</p></div>
    ${sd && !S_rec() ? `<div class="crt-ha"><button class="btn sm primary" data-act="cxSave">${ico('plus','sm')}Save to case</button></div>` : ''}</div>`;
  const hash = P.sha256 ? `<div class="crt-fr"><span>File SHA-256</span><code>${esc(P.sha256)}</code><button class="iconbtn" data-act="cxCopy" data-v="${P.sha256}" aria-label="Copy the file's SHA-256">${ico('copy','sm')}</button><a class="btn xs ghost" href="https://www.virustotal.com/gui/file/${P.sha256}" target="_blank" rel="noopener noreferrer">${ico('external-link','sm')}VirusTotal</a></div>` : '';
  if(!sd) return `<section class="card crt-csr crt-pe">${head}<div class="crt-checks">${cxChk('warn', P.err ? esc(P.err) : 'Not signed', P.err ? '' : 'There is no Authenticode signature in this file, so nothing vouches for who made it. Most legitimate software from large vendors is signed; unsigned programs are common in malware and in-house tools.')}</div>${hash}</section>`;
  const pub = sg && sg.cert ? [(sg.cert.subject.map.O || sg.cert.subject.map.CN || [sg.cert.title])[0], (sg.cert.issuer.map.CN || [])[0]] : null;
  const ts = sg && sg.counter[0];
  const rows = [];
  rows.push(!ck ? cxChk('inf', 'Checking the file against its signature…', '') : sd.fileOk ? cxChk('ok', 'The file is unchanged since it was signed', 'Its Authenticode hash (' + esc(sd.spc.alg) + ') matches the one inside the signature') : sd.fileOk === false ? cxChk('bad', 'The file was changed after signing', 'Its hash does not match the signature — patched, infected or damaged. Windows reports the signature as invalid') : cxChk('inf', 'File hash could not be checked', esc(sd.spc ? sd.spc.alg : 'no hash in the signature')));
  if(ck && sg) rows.push(sg.sigOk && sg.mdOk === false ? cxChk('bad', 'The signature does not cover this content', 'The signer’s signature is valid, but over a different hash than the one in this file — the signature was transplanted from another file') : sg.sigOk ? cxChk('ok', 'Signed with the publisher certificate’s key', 'The signature verifies with “' + esc(sg.cert.title) + '”') : sg.sigOk === false ? cxChk('bad', 'The signature does not verify', 'The signer certificate’s key did not make this signature') : cxChk('inf', 'Signature type can’t be checked in the browser', ''));
  rows.push(pub ? cxChk('inf', 'Publisher: ' + esc(pub[0]), 'Certificate issued by ' + esc(pub[1] || sg.cert.issuer.text)) : cxChk('warn', 'The signer’s certificate is not in the file', ''));
  if(sg && (sg.program || sg.url)) rows.push(cxChk('inf', 'Program description: ' + esc(sg.program || '(none)'), sg.url ? 'More information link: <span class="mono">' + esc(sg.url) + '</span>' : ''));
  rows.push(ts ? cxChk('ok', 'Timestamped ' + esc(cxDate(ts.time)), esc(ts.kind) + (ts.cert ? ' by ' + esc(ts.cert.title) : '') + ' — the signature stays valid after the certificate expires') : cxChk(sg && sg.cert && Date.now() > sg.cert.notAfter ? 'warn' : 'inf', 'No timestamp', sg && isFinite(sg.time) ? 'The signer’s own clock says ' + esc(cxDate(sg.time)) + ' — that is not proof. Without a timestamp the signature stops being trusted when the certificate expires' : 'The signature stops being trusted when the certificate expires'));
  if(P.sigs.length > 1) rows.push(cxChk('inf', P.sigs.length + ' signatures', P.sigs.map(x => x.spc ? x.spc.alg : '?').join(' + ') + ' — dual signing is normal for older Windows support'));
  if(P.after > 8) rows.push(cxChk('warn', cxBytes(P.after) + ' after the signature', 'Bytes appended after the signature are not covered by it. Installers keep settings there; it is also a known way to smuggle content into a signed file'));
  return `<section class="card crt-csr crt-pe">${head}<div class="crt-checks">${rows.join('')}</div>${hash}
    <p class="crt-e crt-pen">Not checked here: whether Windows trusts the publisher’s CA, and revocation. Certificates from the signature are listed below${R.certs.length > 1 ? ' and in the Chain tab' : ''}.</p></section>`;
}
const S_rec = () => !!cxS().rec;

/* does it cover a host? was it valid on a date? */
function cxTestCard(c){
  const S = cxS();
  return `<section class="card crt-s"><h3>${ico('target','sm')}Test it</h3>
    <div class="crt-tst"><label for="cxHost">Does it cover this host?</label><input id="cxHost" class="inp" value="${esc(S.host || '')}" placeholder="login.example.com, an IP or a URL" spellcheck="false" autocomplete="off"><p class="crt-res" id="cxHostR" aria-live="polite">${cxHostRes(c)}</p></div>
    <div class="crt-tst"><label for="cxWhen">Was it valid at this moment? <small>(your local time)</small></label><input id="cxWhen" class="inp" type="datetime-local" value="${esc(S.when || '')}"><p class="crt-res" id="cxWhenR" aria-live="polite">${cxWhenRes(c)}</p></div></section>`;
}
function cxHostRes(c){ const h = cxS().host; if(!h || !h.trim()) return '<span class="t3">Type a host name — wildcards are matched the way browsers do.</span>';
  const r = X5.covers(c, h); if(!r) return '';
  return r.ok === true ? `<span class="crt-y">${ico('circle-check','sm')}Yes — ${esc(r.h)} is covered by <span class="mono">${esc(r.by)}</span></span>`
    : r.ok === 'cn' ? `<span class="crt-m">${ico('info','sm')}Only through the common name — old software accepts that, browsers do not</span>`
    : `<span class="crt-n2">${ico('circle-x','sm')}No — ${esc(r.why)}</span>`; }
function cxWhenRes(c){ const v = cxS().when; if(!v) return '<span class="t3">Pick a date and time, e.g. when an incident happened.</span>'; const t = new Date(v).getTime(); if(!isFinite(t)) return '';
  if(t < c.notBefore) return `<span class="crt-n2">${ico('circle-x','sm')}No — it was not valid yet; it starts ${esc(cxDate(c.notBefore))} (${cxDays(c.notBefore - t)} days later)</span>`;
  if(t > c.notAfter) return `<span class="crt-n2">${ico('circle-x','sm')}No — it had expired ${cxDays(t - c.notAfter)} days earlier, on ${esc(cxDate(c.notAfter))}</span>`;
  return `<span class="crt-y">${ico('circle-check','sm')}Yes — day ${cxDays(t - c.notBefore) + 1} of its ${cxDays(c.notAfter - c.notBefore)}-day life${c.selfIssued ? '' : '. Revocation is not checked here'}</span>`; }

/* the same public key elsewhere in the case (renewals keep it; on attacker infrastructure it ties servers together) */
function cxReuse(c){
  const out = [], seen = new Set([cxId(c)]), kh = cxKh(c), S = cxS();
  for(const x of (S.R ? S.R.certs : [])) if(!seen.has(cxId(x)) && cxKh(x) === kh){ seen.add(cxId(x)); out.push({c:x, where:'this input'}); }
  for(const r of cxRecs()) for(const x of cxRecParse(r).certs) if(!seen.has(cxId(x)) && cxKh(x) === kh){ seen.add(cxId(x)); out.push({c:x, where:'saved', id:r.id}); }
  return out;
}
function cxReuseCard(c, reuse){
  return `<section class="card crt-s"><h3>${ico('key-round','sm')}Same key in ${reuse.length} other certificate${reuse.length > 1 ? 's' : ''}</h3>
    <p class="crt-e">Whoever holds this private key also holds theirs. Renewals often keep the key; across unrelated names it links infrastructure together.</p>
    <div class="crt-rl">${reuse.slice(0, 12).map(x => `<button class="crt-rli" data-act="${x.id ? 'cxRec' : 'cxSel'}" data-${x.id ? 'id' : 'v'}="${x.id || cxS().R.certs.indexOf(x.c)}"><b>${esc(x.c.title)}</b><small>${x.where === 'saved' ? 'Saved' : 'In this input'} · ${esc(cxYmd(x.c.notBefore))} to ${esc(cxYmd(x.c.notAfter))}</small></button>`).join('')}</div>
    <button class="btn sm ghost" data-act="cxCmpWith" data-v="${esc(x0key(reuse[0]))}">${ico('git-compare','sm')}Compare with the first</button></section>`;
}
const x0key = x => (x.id ? x.id : 'in') + ':' + cxId(x.c);
function cxCompareHint(c){
  const n = cxRecs().length;
  return `<section class="card crt-s"><h3>${ico('git-compare','sm')}Compare</h3><p class="crt-e">See what changed between this certificate and another one — a renewal, the certificate a server showed last week, or a suspected copy. Names, key, dates, issuer and every extension are lined up side by side.</p>
    <div class="crt-ba"><button class="btn sm" data-act="cxTab" data-v="compare">${ico('git-compare','sm')}Compare with${n ? ' a saved one' : '…'}</button><button class="btn sm ghost" data-act="cxPaste" data-v="cmp">${ico('clipboard-paste','sm')}Paste another</button></div>
    <p class="crt-e crt-pen">No other certificate in this case uses the same key.</p></section>`;
}

/* ready-made queries to find the same certificate elsewhere */
function cxHunt(c){
  const fp = c.fp, clean = v => String(v).replace(/["';\\]/g, '').slice(0, 80), icn = (c.issuer.map.CN || [])[0], sha1c = fp.sha1.match(/../g).join(':'), ser = c.serialHex.toUpperCase().match(/../g).join(':');
  const ek = (c.eku || []).map(e => e.oid), code = ek.includes('1.3.6.1.5.5.7.3.3'), Q = [], sid = 9000000 + parseInt(fp.sha1.slice(0, 6), 16) % 900000 * 2;   // stable per certificate, so rules for different certificates do not clash
  Q.push(['Shodan', 'Servers presenting this certificate', 'ssl.cert.fingerprint:' + fp.sha256]);
  if(c.cn) Q.push(['Shodan', 'Same subject name', 'ssl.cert.subject.cn:"' + c.cn + '"']);
  if(icn && (c.selfIssued || cxWorst(cxFindings(c)) !== 'ok')) Q.push(['Shodan', 'Same issuer name — finds sibling servers built the same way', 'ssl.cert.issuer.cn:"' + icn + '"']);
  Q.push(['Censys', 'Hosts with this certificate', 'services.tls.certificates.leaf_data.fingerprint: ' + fp.sha256]);
  Q.push(['crt.sh', 'Every logged certificate with this same key', 'https://crt.sh/?spkisha256=' + fp.spki256]);
  Q.push(['Suricata', 'Alert when it crosses the network (visible in TLS 1.2 and older)', 'alert tls any any -> any any (msg:"Certificate ' + clean(c.title) + '"; tls.cert_fingerprint; content:"' + sha1c + '"; classtype:bad-unknown; sid:' + sid + '; rev:1;)']);
  Q.push(['Suricata', 'The same, by serial number', 'alert tls any any -> any any (msg:"Certificate serial ' + clean(c.title) + '"; tls.cert_serial; content:"' + ser + '"; classtype:bad-unknown; sid:' + (sid + 1) + '; rev:1;)']);
  if(code) Q.push(['Defender / Sentinel', 'Files on your devices signed with it', 'DeviceFileCertificateInfo\n| where SignerHash =~ "' + fp.sha1 + '"\n| summarize Devices = dcount(DeviceId), Files = dcount(SHA1) by Signer, Issuer']);
  if(c.isCA || c.selfIssued) Q.push(['PowerShell', 'Is it installed on this computer? (a planted root)', "Get-ChildItem Cert:\\ -Recurse | Where-Object Thumbprint -eq '" + fp.sha1.toUpperCase() + "'"]);
  return `<section class="card crt-s" id="cxHunt"><h3>${ico('crosshair','sm')}Hunt for it</h3><div class="crt-hq">${Q.map(([t, d, q]) => `<div class="crt-hr"><div><b>${esc(t)}</b><small>${esc(d)}</small></div><code>${esc(q)}</code><button class="iconbtn" data-act="cxCopy" data-v="${esc(q)}" aria-label="Copy the ${esc(t)} query">${ico('copy','sm')}</button></div>`).join('')}</div>
    <p class="crt-e crt-pen">Copy and run them in those tools. Nothing is sent from here.</p></section>`;
}
const X5L = k => ({C:'Country', L:'Locality', ST:'State', O:'Organisation', OU:'Unit', emailAddress:'Email', serialNumber:'Registration no.', DC:'Domain part', jurisdictionC:'Jurisdiction', businessCategory:'Category'}[k] || k);
const CX_NOTE = {'Server authentication (TLS server)':'website and server certificates', 'Client authentication':'logging in with the certificate', 'Code signing':'signing programs', 'Smart card logon (Windows)':'Windows logon'};
function cxExtRow(e){
  let v = esc(e.text || ''), note = '';
  if(e.oid === '2.5.29.19') note = e.note;
  else if(e.oid === '2.5.29.15') note = e.usages && e.usages.includes('Certificate signing') ? 'May sign other certificates' : e.usages && e.usages.includes('Key encipherment') ? 'Normal for an RSA TLS server certificate' : '';
  else if(e.oid === '2.5.29.37') v = e.ekus.map(k => esc(k.name)).join(', ');
  else if(e.oid === '2.5.29.32'){ v = e.policies.map(p => `<span class="mono">${esc(p.oid)}</span>${p.name !== p.oid ? ' — ' + esc(p.name) : ''}`).join('<br>'); note = e.policies.some(p => p.level === 'DV') ? 'The CA only checked control of the domain, not who owns it' : e.policies.some(p => p.level === 'OV') ? 'The CA checked the organisation exists' : e.policies.some(p => p.level === 'EV') ? 'The strictest identity checks' : ''; }
  else if(e.oid === '1.3.6.1.5.5.7.1.1') v = e.access.map(a => `${esc(a.how)} <span class="mono">${esc(a.url)}</span>`).join('<br>');
  else if(e.oid === '2.5.29.31') v = e.urls.map(u => `<span class="mono">${esc(u)}</span>`).join('<br>') || '(none)';
  else if(e.oid === '1.3.6.1.4.1.11129.2.4.2'){ v = e.scts.map(s => `${esc(cxDate(s.time))} · log <span class="mono">${esc(s.logId.slice(0, 12))}…</span>`).join('<br>'); note = 'Published in Certificate Transparency — searchable on crt.sh'; }
  else if(e.oid === '2.5.29.17' || e.oid === '2.5.29.18') v = e.names.length + ' name' + (e.names.length === 1 ? '' : 's') + ' (listed above)';
  else if(e.oid === '2.5.29.14' || e.oid === '2.5.29.35') v = `<span class="mono">${v}</span>`;
  else if(!e.known) v = `<span class="mono">${v}</span>`;
  return `<div class="crt-er"><span>${esc(e.name)}${e.critical ? ' <i class="crt-crit" title="Critical: software that does not understand it must reject the certificate">critical</i>' : ''}</span><div><b>${v}</b>${note ? `<small>${esc(note)}</small>` : ''}</div></div>`;
}
function cxAsn(n, depth = 0, cnt = {n:0}){
  if(++cnt.n > 600) return cnt.n === 601 ? '<div class="crt-a">… (cut short)</div>' : '';
  const U = ['EOC', 'BOOLEAN', 'INTEGER', 'BIT STRING', 'OCTET STRING', 'NULL', 'OID', '', '', '', 'ENUMERATED', '', 'UTF8String', '', '', '', 'SEQUENCE', 'SET', 'NumericString', 'PrintableString', 'T61String', '', 'IA5String', 'UTCTime', 'GeneralizedTime', '', '', '', 'UniversalString', '', 'BMPString'];
  const tag = n.cls === 0 ? (U[n.tag] || 'tag ' + n.tag) : n.cls === 2 ? '[' + n.tag + ']' : 'class ' + n.cls + ' tag ' + n.tag, b = n.b.subarray(n.cs, n.ce);
  let val = '';
  if(!n.cons){ try{
    if(n.cls === 0 && n.tag === 6){ const o = asnOid(b); val = o + (CX_OID[o] ? ' — ' + CX_OID[o] : ''); }
    else if(n.cls === 0 && [12, 19, 22, 23, 24, 20, 18].includes(n.tag)) val = '“' + new TextDecoder().decode(b) + '”';
    else if(n.cls === 0 && n.tag === 1) val = b[0] ? 'TRUE' : 'FALSE';
    else val = X5.hex(b.subarray(0, 24), ' ') + (b.length > 24 ? ' … (' + b.length + ' bytes)' : ''); }catch(e){} }
  return `<div class="crt-a" style="--d:${depth}"><b>${esc(tag)}</b>${n.cons ? ` <small>${n.kids.length} item${n.kids.length === 1 ? '' : 's'}</small>` : ` <span>${esc(val)}</span>`}</div>` + (n.cons ? n.kids.map(k => cxAsn(k, depth + 1, cnt)).join('') : '');
}
function asnOid(b){ const out = [Math.min(2, Math.floor(b[0] / 40)), b[0] >= 80 ? b[0] - 80 : b[0] % 40]; let v = 0; for(let i = 1; i < b.length; i++){ v = v * 128 + (b[i] & 0x7f); if(!(b[i] & 0x80)){ out.push(v); v = 0; } } return out.join('.'); }
const CX_OID = {'2.5.4.3':'common name', '2.5.4.6':'country', '2.5.4.10':'organisation', '2.5.4.11':'unit', '2.5.4.7':'locality', '2.5.4.8':'state', '1.2.840.113549.1.1.11':'sha256WithRSA', '1.2.840.113549.1.1.1':'rsaEncryption', '1.2.840.10045.2.1':'ecPublicKey',
  '1.2.840.10045.4.3.2':'ecdsa-with-SHA256', '2.5.29.17':'subjectAltName', '2.5.29.19':'basicConstraints', '2.5.29.15':'keyUsage', '2.5.29.37':'extKeyUsage', '2.5.29.14':'subjectKeyIdentifier', '2.5.29.35':'authorityKeyIdentifier', '2.5.29.31':'cRLDistributionPoints',
  '2.5.29.32':'certificatePolicies', '1.3.6.1.5.5.7.1.1':'authorityInfoAccess', '1.3.6.1.4.1.11129.2.4.2':'SCT list', '1.3.6.1.5.5.7.3.1':'serverAuth', '1.3.6.1.5.5.7.3.2':'clientAuth', '1.3.6.1.5.5.7.48.1':'OCSP', '1.3.6.1.5.5.7.48.2':'caIssuers'};

function cxRight(c, F, reuse = []){
  if(reuse.length) F = [{s:reuse.some(x => x.c.cn !== c.cn) ? 'warn' : 'info', t:'Key shared with ' + reuse.length + ' other certificate' + (reuse.length > 1 ? 's' : ''), d:reuse.slice(0, 3).map(x => x.c.title).join(', ') + (reuse.some(x => x.c.cn !== c.cn) ? ' — different names on one key tie them to the same owner' : ' — likely renewals')}].concat(F);
  const dns = c.san.filter(s => s.t === 'DNS').map(s => s.v.replace(/^\*\./, '')), host = dns[0] || (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(c.cn) ? c.cn : (c.san.find(s => s.t === 'IP') || {}).v || 'HOST'), regs = [...new Set(dns.map(X5.regDom))].slice(0, 3), fp = c.fp;
  const link = (u, icon, t, d) => `<a class="crt-pv" href="${esc(u)}" target="_blank" rel="noopener noreferrer">${ico(icon,'sm')}<span>${t}<small>${d}</small></span>${ico('external-link','sm')}</a>`;
  return `<aside class="crt-r" aria-label="Findings and pivots" tabindex="0">
    <section><h4>${ico('triangle-alert','sm')}Findings</h4>${F.length ? F.map(f => `<div class="crt-fd"><span class="crt-sv ${f.s === 'info' ? 'inf' : f.s}">${ico(f.s === 'bad' || f.s === 'warn' ? 'triangle-alert' : 'info','sm')}</span><div><b>${esc(f.t)}</b><small>${esc(f.d)}</small></div></div>`).join('')
      : `<div class="crt-fd"><span class="crt-sv ok">${ico('check','sm')}</span><div><b>Nothing unusual</b><small>Structure, key, dates and names look normal for this kind of certificate</small></div></div>`}</section>
    <section><h4>${ico('search','sm')}Pivot</h4>
      ${fp ? link('https://crt.sh/?q=' + fp.sha256, 'scroll-text', 'crt.sh · this certificate', 'Where and when it was logged') : ''}
      ${regs.map(d => link('https://crt.sh/?q=' + encodeURIComponent('%.' + d), 'scroll-text', 'crt.sh · ' + esc(d), 'Every logged certificate for this domain')).join('')}
      ${fp ? link('https://crt.sh/?spkisha256=' + fp.spki256, 'key-round', 'crt.sh · same key', 'Other certificates with this public key') : ''}
      ${fp ? link('https://search.censys.io/search?resource=hosts&q=' + encodeURIComponent('services.tls.certificates.leaf_data.fingerprint: ' + fp.sha256), 'server', 'Censys', 'Servers presenting this exact certificate') : ''}
      ${fp ? link('https://www.shodan.io/search?query=' + encodeURIComponent('ssl.cert.fingerprint:' + fp.sha256), 'server', 'Shodan', 'Search by fingerprint') : ''}
      ${regs[0] ? link('https://www.virustotal.com/gui/domain/' + encodeURIComponent(regs[0]), 'shield', 'VirusTotal · ' + esc(regs[0]), 'Reputation and passive DNS') : ''}
      <p class="crt-e">These open the site in a new tab; the app itself sends nothing.</p></section>
${(dns.length || c.san.some(x => x.t === 'IP')) && (!cxKind(c) || cxKind(c) === 'server') ? `    <section><h4>${ico('binary','sm')}Grab it from the server</h4><div class="crt-cmd">openssl s_client -connect ${esc(host)}:443 -servername ${esc(host)} -showcerts &lt;/dev/null</div>
      <button class="btn xs ghost" data-act="cxCopy" data-v="${esc('openssl s_client -connect ' + host + ':443 -servername ' + host + ' -showcerts </dev/null')}">${ico('copy','sm')}Copy</button> <span class="crt-e">then paste the output here.</span></section>` : ''}
    <section><h4>${ico('book-open','sm')}Learn</h4><button class="crt-learn" data-act="cxCh" data-v="inside">What every field means</button><button class="crt-learn" data-act="cxCh" data-v="bad">Malicious certificate patterns</button><button class="crt-learn" data-act="cxCh" data-v="osint">Pivoting from a certificate</button></section>
  </aside>`;
}

/* ---------- chain ---------- */
function cxChain(){
  const S = cxS(), R = S.R;
  if(!R || !R.certs.length) return `<div class="crt-c">${empty('link-2', 'Check a chain', 'Paste several certificates in any order — a server’s chain from openssl s_client -showcerts, a .p7b bundle, or a leaf with its intermediates. They are put in order and every signature is checked.', `<button class="btn primary" data-act="cxSample" data-v="chain">${ico('sparkles','sm')}Try an example chain</button>`)}</div>`;
  if(!R.chain) return `<div class="crt-c"><p class="crt-e">Checking signatures…</p></div>`;
  const now = Date.now(), O = R.chain.order;
  const node = (c, i) => { const exp = now > c.notAfter, F = cxFindings(c), w = cxWorst(F), role = i === 0 && !c.isCA ? 'Leaf' : c.selfIssued ? 'Root CA' : c.isCA ? 'Intermediate CA' : 'Certificate';
    const notCA = i > 0 && !c.isCA, outside = i > 0 && (O[i - 1].notAfter > c.notAfter || O[i - 1].notBefore < c.notBefore);
    return `<div class="card crt-node"><span class="crt-big ${notCA ? 'bad' : exp ? 'warn' : role === 'Leaf' ? w : 'ok'}">${ico(role === 'Leaf' ? (w === 'ok' ? 'shield-check' : 'shield-alert') : c.selfIssued ? 'shield' : 'building-2')}</span>
      <div><h3>${esc(c.title)}</h3><p>${role}${(c.subject.map.O || [])[0] ? ' · ' + esc(c.subject.map.O[0]) : ''}</p>
        <div class="crt-pills">${exp ? `<span class="crt-pill amber">Expired ${cxDay(c.notAfter)}</span>` : `<span class="crt-pill green">Valid to ${cxDay(c.notAfter)}</span>`}<span class="crt-pill">${esc(c.key.label)}</span>
          ${c.isCA ? `<span class="crt-pill blue">CA${c.bc.pathLen != null ? ' · path length ' + c.bc.pathLen : ''}</span>` : '<span class="crt-pill">Not a CA</span>'}${notCA ? '<span class="crt-pill red">Issued certificates but is not a CA</span>' : ''}
          ${outside ? '<span class="crt-pill amber">The certificate above outlives this one</span>' : ''}</div></div>
      <button class="btn xs ghost" data-act="cxOpenIn" data-v="${R.certs.indexOf(c)}">${ico('scroll-text','sm')}Decode</button></div>`; };
  const link = l => l.missing ? `<div class="crt-lnk warn">${ico('info','sm')}Root not pasted — issued by “${esc((l.issuer.map.CN || l.issuer.map.O || [l.issuer.text])[0])}”</div>`
    : l.self ? `<div class="crt-lnk ${l.ok ? 'ok' : l.ok === false ? 'bad' : ''}">${ico(l.ok ? 'circle-check' : 'info','sm')}${l.ok ? 'Self-signed root — trust ends here if your system trusts it' : l.ok === false ? 'Claims to be self-signed, but its signature does not verify' : 'Self-signed — signature type can’t be checked in the browser'}</div>`
    : `<div class="crt-lnk ${l.ok ? 'ok' : l.ok === false ? 'bad' : ''}">${ico(l.ok ? 'circle-check' : l.ok === false ? 'triangle-alert' : 'info','sm')}${l.ok ? 'Signed by the certificate below — signature checked' : l.ok === false ? 'Signature does not match: the certificate below did not sign this one' : 'Signed by the certificate below — this signature type can’t be checked in the browser'}</div>`;
  return `<div class="crt-c crt-chainw"><p class="crt-cap">Chain · ${R.certs.length} certificate${R.certs.length > 1 ? 's' : ''} pasted · ordered for you</p>
    <div class="crt-chain">${O.map((c, i) => node(c, i) + link(R.chain.links[i])).join('')}
      ${R.chain.links[O.length - 1] && R.chain.links[O.length - 1].missing ? `<div class="card crt-node ghost"><span class="crt-big inf">${ico('shield')}</span><div><h3>${esc((O[O.length - 1].issuer.map.CN || [O[O.length - 1].issuer.text])[0])}</h3><p>Not included. If it is a public root, it ships with browsers and operating systems; if not, someone had to install it as trusted.</p></div></div>` : ''}</div>
    ${R.chain.extra.length ? `<p class="crt-cap">Not part of this chain</p><div class="crt-chips">${R.chain.extra.map(c => `<button class="chip" data-act="cxOpenIn" data-v="${R.certs.indexOf(c)}">${esc(c.title)}</button>`).join('')}</div>` : ''}
    <section class="card crt-s" style="margin-top:14px"><h3>${ico('info','sm')}What was checked</h3><ul class="crt-ul"><li>Each certificate’s issuer name matches the next one’s subject (and key identifiers, when present).</li><li>Each signature is verified with the next certificate’s public key, using the browser’s own cryptography.</li><li>Not checked here: whether the root is trusted on your systems, and revocation — both need information this offline app does not have.</li></ul></section></div>`;
}

/* ---------- CSR ---------- */
function cxCsr(){
  const S = cxS(), R = S.R;
  if(!R || !R.csrs.length) return `<div class="crt-c">${empty('file-text', 'Check a signing request', 'Paste a CSR (-----BEGIN CERTIFICATE REQUEST-----) to see what it asks for, confirm its signature, and catch problems before it goes to a CA. Paste a certificate with it to check they share the same key.', `<button class="btn primary" data-act="cxSample" data-v="csr">${ico('sparkles','sm')}Try an example request</button>`)}</div>`;
  return `<div class="crt-c">${R.csrs.map(q => { const F = cxFindings(q), match = R.certs.find(c => X5.hex(c.key.der) === X5.hex(q.key.der));
    const chk = (s, t, d) => `<div class="crt-fd"><span class="crt-sv ${s}">${ico(s === 'ok' ? 'check' : s === 'inf' ? 'info' : 'triangle-alert','sm')}</span><div><b>${t}</b><small>${d}</small></div></div>`;
    const keyOk = !(q.key.type === 'RSA' && q.key.bits < 2048);
    return `<section class="card crt-csr"><div class="crt-ch"><span class="crt-big inf">${ico('file-text')}</span><div><h2>Signing request · ${esc(q.title)}</h2><p>A request for a certificate — nothing has been issued yet</p></div>
        <div class="crt-ha">${S.rec ? `<span class="crt-pill green">${ico('check','sm')}Saved</span>` : `<button class="btn sm primary" data-act="cxSave">${ico('plus','sm')}Save to case</button>`}<button class="btn sm" data-act="cxCopyPem">${ico('copy','sm')}Copy</button></div></div>
      <div class="crt-kv"><span>Subject</span><b>${esc(q.subject.text || '(empty)')}</b><span>Asks for</span><b class="mono">${esc(q.san.map(s => s.v).join(', ') || '— no SAN extension')}</b><span>Key</span><b>${esc(q.key.label)}${q.key.detail ? ' · ' + esc(q.key.detail) : ''}</b><span>Signed with</span><b>${esc(q.sigAlg.name)}</b>
        ${q.eku ? `<span>Usage</span><b>${esc(q.eku.map(e => e.name).join(', '))}</b>` : ''}${q.attrs.map(a => `<span>${esc(a.name)}</span><b>${esc(a.oid === '1.2.840.113549.1.9.7' ? a.value.slice(0, 3) + '…' : a.value)}</b>`).join('')}
        ${q.fp ? `<span>Key SHA-256</span><b class="mono">${esc(q.fp.spki256)}</b>` : ''}</div>
      <div class="crt-checks">
        ${q.selfOk === undefined ? chk('inf', 'Checking the signature…', '') : q.selfOk ? chk('ok', 'Signature is valid', 'The request was not changed after it was made, and the requester holds the private key') : q.selfOk === false ? chk('bad', 'Signature does not verify', 'The request was altered, or is broken') : chk('inf', 'Signature type can’t be checked in the browser', esc(q.sigAlg.name))}
        ${chk(keyOk ? 'ok' : 'bad', keyOk ? 'Key is strong enough' : 'Key is too weak', keyOk ? esc(q.key.label) + ' meets the CA/Browser Forum minimum' : 'RSA under 2048 bits will be refused')}
        ${q.san.length ? chk('ok', 'Names are in the SAN extension', 'Browsers ignore the CN — SANs are what count') : ''}
        ${F.map(f => chk(f.s === 'info' ? 'inf' : f.s, esc(f.t), esc(f.d))).join('')}
        ${R.certs.length ? chk(match ? 'ok' : 'inf', match ? 'Same key as “' + esc(match.title) + '”' : 'Key does not match the pasted certificate' + (R.certs.length > 1 ? 's' : ''), match ? 'This request and that certificate belong together' : 'A new key — or the wrong certificate') : ''}
      </div></section>`; }).join('')}</div>`;
}

/* ---------- compare two certificates ---------- */
function cxPool(){
  const S = cxS(), P = [], seen = new Set(), add = (k, c, where) => { const id = cxId(c); if(seen.has(id)) return; seen.add(id); P.push({k, c, where}); };
  if(S.R) S.R.certs.forEach(c => add('in:' + cxId(c), c, 'In the box'));
  for(const r of cxRecs()) cxRecParse(r).certs.forEach(c => add(r.id + ':' + cxId(c), c, 'Saved'));
  S.cmpX.forEach(c => add('x:' + cxId(c), c, 'Added to compare'));
  return P;
}
function cxCompare(){
  const S = cxS(), P = cxPool();
  if(P.length < 2) return `<div class="crt-c">${cxDropZone(P.length ? 'Add a second certificate' : 'Compare two certificates', 'Line them up field by field: a renewal against the old one, what a server showed today against last week, or a suspected copy against the real thing. Certificates you opened, saved ones in this case and any you add here can be compared.' + (P.length ? ' One is ready.' : ''), 'cmp')}
    <div class="crt-try"><span>Or:</span><button class="chip" data-act="cxSample" data-v="cmp">${ico('sparkles','sm')}Compare two examples</button></div></div>`;
  const get = k => k && (P.find(x => x.k === k) || P.find(x => x.k.slice(x.k.indexOf(':')) === k.slice(k.indexOf(':'))));
  let A = get(S.cmpA) || P[0], B = get(S.cmpB) || P.find(x => x !== A); if(B === A) B = P.find(x => x !== A); S.cmpA = A.k; S.cmpB = B.k;
  const a = A.c, b = B.c, now = Date.now();
  const same = X5.hex(a.der) === X5.hex(b.der), sk = cxKh(a) === cxKh(b), si = a.issuer.raw === b.issuer.raw;
  const nm = c => new Set(c.san.map(s => s.v.toLowerCase())), nA = nm(a), nB = nm(b), both = [...nA].filter(x => nB.has(x)), onlyA = [...nA].filter(x => !nB.has(x)), onlyB = [...nB].filter(x => !nA.has(x));
  const rdA = new Set([...nA].map(X5.regDom)), sharedReg = [...new Set([...nB].map(X5.regDom))].filter(d => rdA.has(d)), oA = (a.subject.map.O || [])[0], oB = (b.subject.map.O || [])[0];
  const R = same ? ['ok', 'link', 'The same certificate', 'Byte for byte identical — the same certificate seen twice.']
    : b.subject.raw === a.issuer.raw ? ['inf', 'link-2', 'B issued A', 'B is the certificate authority whose name is on A as its issuer. Check the Chain tab to confirm the signature.']
    : a.subject.raw === b.issuer.raw ? ['inf', 'link-2', 'A issued B', 'A is the certificate authority whose name is on B as its issuer. Check the Chain tab to confirm the signature.']
    : sk && both.length ? ['ok', 'refresh-cw', 'A renewal that kept the same key', 'Same private key and the same names with new dates: the owner renewed without generating a new key.']
    : sk ? ['bad', 'key-round', 'Same owner — one private key, different names', 'Whoever holds this key runs both. On attacker infrastructure this is one of the strongest links you can find between servers.']
    : both.length && si ? ['ok', 'refresh-cw', 'A renewal with a new key', 'Same names from the same CA with a fresh key — routine, especially with automated CAs such as Let’s Encrypt.']
    : both.length ? ['warn', 'shuffle', 'Same names, different certificate authority', 'The names moved to another CA: a change of hosting or provider — or someone else obtained a certificate for these names. Check which one the real servers present.']
    : sharedReg.length ? ['warn', 'globe', 'Related domains', 'Different hosts under the same registered domain' + (sharedReg.length > 1 ? 's' : '') + ' (' + sharedReg.slice(0, 3).join(', ') + ').']
    : oA && oA === oB ? ['inf', 'building-2', 'Same organisation named', 'Both name “' + oA + '” but share no names or key.']
    : ['inf', 'circle-dot', 'No direct link between them', 'Different keys, names and issuers. Any connection has to come from elsewhere: hosting, timing, registrant or content.'];
  const card = (X, c, id, lab) => { const exp = now > c.notAfter, pre = now < c.notBefore, w = cxWorst(cxFindings(c));
    return `<div class="card crt-cc2"><div class="crt-cct"><span class="crt-ab">${lab}</span><label class="sr" for="${id}">Certificate ${lab}</label><select id="${id}">${P.map(x => `<option value="${esc(x.k)}"${x === X ? ' selected' : ''}>${esc(x.c.title)} · ${esc(x.where)}</option>`).join('')}</select></div>
      <h3>${esc(c.title)}</h3><p>${esc((c.issuer.map.CN || [c.issuer.text])[0])}${(c.subject.map.O || [])[0] ? ' → ' + esc(c.subject.map.O[0]) : ''}</p>
      <div class="crt-pills">${exp ? `<span class="crt-pill amber">Expired</span>` : pre ? `<span class="crt-pill amber">Not yet valid</span>` : `<span class="crt-pill green">Valid</span>`}<span class="crt-pill">${esc(c.key.label)}</span><span class="crt-pill">${c.san.length} name${c.san.length === 1 ? '' : 's'}</span>${c.isCA ? '<span class="crt-pill blue">CA</span>' : ''}${w !== 'ok' ? `<span class="crt-pill ${w === 'bad' ? 'red' : 'amber'}">${cxFindings(c).filter(f => f.s === w).length} ${w === 'bad' ? 'red flag' : 'warning'}${cxFindings(c).filter(f => f.s === w).length > 1 ? 's' : ''}</span>` : ''}</div>
      <dl><dt>Valid</dt><dd>${esc(cxYmd(c.notBefore))} → ${esc(cxYmd(c.notAfter))}</dd><dt>Serial</dt><dd class="mono">${esc(c.serial.length > 26 ? c.serial.slice(0, 25) + '…' : c.serial)}</dd><dt>Key</dt><dd class="mono">${c.fp ? esc(c.fp.spki256.slice(0, 16)) + '…' : '…'}</dd></dl></div>`; };
  /* both lifetimes on one axis */
  const t0 = Math.min(a.notBefore, b.notBefore, now), t1 = Math.max(a.notAfter, b.notAfter, now), pct = t => ((t - t0) / (t1 - t0) * 100).toFixed(2), bar = (c, l) => `<div class="crt-tlr"><span>${l}</span><div><i class="${now > c.notAfter ? 'old' : ''}" style="left:${pct(c.notBefore)}%;width:${Math.max(.6, pct(c.notAfter) - pct(c.notBefore))}%"></i></div></div>`;
  const [o, n] = a.notBefore <= b.notBefore ? [a, b] : [b, a], gap = cxDays(n.notBefore - o.notAfter);
  /* field groups; DN values are compared part by part */
  const dn = (x, y) => { const ys = new Set(y.parts.map(p => p.join('='))), some = x.parts.some(p => ys.has(p.join('='))); return x.parts.map(p => { const t = p[0] + '=' + p[1]; return ys.has(t) || !some ? esc(t) : `<b class="crt-chg">${esc(t)}</b>`; }).join(', ') || '—'; };
  const ext = (c, o) => { const e = c.exts.find(x => x.oid === o); return e ? (e.oid === '2.5.29.37' ? e.ekus.map(k => k.name).join(', ') : e.oid === '1.3.6.1.4.1.11129.2.4.2' ? e.scts.length + ' timestamps' : e.text || '') + (e.critical ? ' (critical)' : '') : ''; };
  const oids = [...new Set([...a.exts, ...b.exts].map(e => e.oid))].filter(o => !['2.5.29.17', '2.5.29.14', '2.5.29.35'].includes(o));
  const G = [['Identity', [['Subject', a.subject.text, b.subject.text, 'dn', 'subject'], ['Issuer', a.issuer.text, b.issuer.text, 'dn', 'issuer'], ['Serial', a.serial, b.serial, 'mono']]],
    ['Validity', [['Valid from', cxDate(a.notBefore), cxDate(b.notBefore)], ['Valid to', cxDate(a.notAfter), cxDate(b.notAfter)], ['Lifetime', cxDays(a.notAfter - a.notBefore) + ' days', cxDays(b.notAfter - b.notBefore) + ' days']]],
    ['Key and signature', [['Key', a.key.label + (a.key.detail ? ' · ' + a.key.detail : ''), b.key.label + (b.key.detail ? ' · ' + b.key.detail : '')], ['Key SHA-256', a.fp ? a.fp.spki256 : '…', b.fp ? b.fp.spki256 : '…', 'mono'], ['Signature', a.sigAlg.name, b.sigAlg.name], ['Subject key ID', a.ski, b.ski, 'mono'], ['Issuer key ID', a.aki, b.aki, 'mono']]],
    ['Extensions', oids.map(o => [(a.exts.find(e => e.oid === o) || b.exts.find(e => e.oid === o)).name, ext(a, o), ext(b, o)])],
    ['Fingerprints', [['SHA-256', a.fp ? a.fp.sha256 : '…', b.fp ? b.fp.sha256 : '…', 'mono'], ['SHA-1', a.fp ? a.fp.sha1 : '…', b.fp ? b.fp.sha1 : '…', 'mono']]]];
  const all = !!S.cmpAll, diffN = G.reduce((t, [, rows]) => t + rows.filter(r => r[1] !== r[2]).length, 0) + (onlyA.length || onlyB.length ? 1 : 0);
  const cell = (r, x, y, sideB) => r[3] === 'dn' ? dn(sideB ? b[r[4]] : a[r[4]], sideB ? a[r[4]] : b[r[4]]) : esc(x || '—');
  const chip = x => `<span class="chip mono">${esc(x)}</span>`;
  return `<div class="crt-c crt-cmpw">
    <section class="card crt-verdict"><span class="crt-big ${R[0]}">${ico(R[1])}</span><div><p class="crt-k">How they relate</p><h2>${esc(R[2])}</h2><p>${esc(R[3])}</p>
      <div class="crt-pills">${same ? '' : `<span class="crt-pill${diffN ? ' amber' : ''}">${diffN} difference${diffN === 1 ? '' : 's'}</span>`}<span class="crt-pill${sk ? ' green' : ''}">${ico('key-round','sm')}${sk ? 'Same key' : 'Different keys'}</span><span class="crt-pill${si ? ' green' : ''}">${si ? 'Same issuer' : 'Different issuers'}</span><span class="crt-pill${both.length ? ' green' : ''}">${both.length} shared name${both.length === 1 ? '' : 's'}</span></div></div></section>
    <div class="crt-vs">${card(A, a, 'cxCmpA', 'A')}<button class="crt-vsb" data-act="cxCmpSwap" aria-label="Swap A and B" title="Swap A and B">${ico('arrow-left-right','sm')}<span>vs</span></button>${card(B, b, 'cxCmpB', 'B')}</div>
    <div class="crt-addc"><button class="btn sm" data-act="cxPaste" data-v="cmp">${ico('plus','sm')}Add another certificate</button><span class="t3">${P.length} available: opened, saved in this case, or added here</span></div>
    <section class="card crt-s"><h3>${ico('calendar','sm')}Lifetimes<span class="crt-tlg">${same ? '' : gap > 0 ? gap + '-day gap between them' : 'Overlap of ' + (-gap) + ' days'}</span></h3>
      <div class="crt-tlx">${bar(a, 'A')}${bar(b, 'B')}<em style="left:calc(28px + (100% - 28px) * ${pct(now) / 100})" title="Today"></em></div>
      <div class="crt-lg crt-tlx2"><span>${esc(cxYmd(t0))}</span><span>today</span><span>${esc(cxYmd(t1))}</span></div></section>
    <section class="card crt-s"><h3>${ico('globe','sm')}Names</h3><div class="crt-n3">
      <div><h4><b>${onlyA.length}</b>only in A</h4><div class="crt-chips">${onlyA.map(chip).join('') || '<span class="crt-e">None</span>'}</div></div>
      <div><h4><b>${both.length}</b>in both</h4><div class="crt-chips">${both.map(chip).join('') || '<span class="crt-e">None</span>'}</div></div>
      <div><h4><b>${onlyB.length}</b>only in B</h4><div class="crt-chips">${onlyB.map(chip).join('') || '<span class="crt-e">None</span>'}</div></div></div></section>
    <section class="card crt-s crt-cmpt"><h3>${ico('list','sm')}Field by field<span class="crt-seg" role="group" aria-label="Rows to show"><button data-act="cxCmpAll" data-v="0" aria-pressed="${!all}">Differences</button><button data-act="cxCmpAll" data-v="1" aria-pressed="${all}">All fields</button></span></h3>
      <div class="tblwrap" tabindex="0" role="region" aria-label="Field by field comparison"><table class="crt-tbl"><thead><tr><th scope="col">Field</th><th scope="col">A</th><th scope="col">B</th></tr></thead>
      ${G.map(([g, rows]) => { const rs = rows.filter(r => all || r[1] !== r[2]); return rs.length ? `<tbody><tr class="crt-grp"><th scope="rowgroup" colspan="3">${esc(g)}</th></tr>${rs.map(r => `<tr><th scope="row">${esc(r[0])}${r[1] === r[2] ? ' <span class="crt-y">same</span>' : ''}</th><td${r[3] === 'mono' ? ' class="mono"' : ''}>${cell(r, r[1], r[2], false)}</td><td${r[3] === 'mono' ? ' class="mono"' : ''}>${cell(r, r[2], r[1], true)}</td></tr>`).join('')}</tbody>` : ''; }).join('')}
      </table></div>${!all && !diffN ? '<p class="crt-e">No differences.</p>' : ''}</section></div>`;
}
/* ---------- Certificate Transparency: crt.sh JSON ---------- */
const cxCtUrl = d => 'https://crt.sh/?q=' + encodeURIComponent('%.' + d.trim().replace(/^\*\./, '').replace(/^[a-z]+:\/\//i, '').replace(/\/.*$/, '')) + '&output=json';
const CT_HOT = /(^|[.-])(vpn|sso|login|signin|auth|adfs|admin|adm|dev|develop|staging|stage|stg|test|uat|qa|preprod|jenkins|gitlab|git|jira|confluence|grafana|kibana|internal|intranet|citrix|owa|remote|rdp|backup|bak|db|sql|ftp|sftp|old|legacy|beta|demo|vault|k8s|kube|api)([.-]|\d|$)/;
function ctParse(text){
  let a; try{ a = JSON.parse(String(text).trim()); }catch(e){ return null; }
  if(a && !Array.isArray(a)) a = a.results || a.data || null;
  if(!Array.isArray(a) || !a.length || !a.some(x => x && typeof x === 'object' && (x.name_value || x.common_name))) return null;
  const T = s => { if(!s) return NaN; s = String(s); return Date.parse(/(Z|[+-]\d\d:?\d\d)$/.test(s) ? s : s + 'Z'); };
  const M = new Map();
  for(const x of a.slice(0, 100000)){ if(!x || typeof x !== 'object') continue;
    const k = (x.serial_number || x.id) + '|' + (x.issuer_ca_id != null ? x.issuer_ca_id : x.issuer_name), e = M.get(k) || {id:x.id, issuer:String(x.issuer_name || ''), nb:T(x.not_before), na:T(x.not_after), logged:T(x.entry_timestamp), names:new Set(), serial:String(x.serial_number || ''), n:0};
    String((x.name_value || '') + '\n' + (x.common_name || '')).toLowerCase().split(/[\r\n]+/).map(v => v.trim().replace(/\.$/, '')).filter(v => v && v.length < 254).forEach(v => e.names.add(v));
    e.n++; const lg = T(x.entry_timestamp); if(lg < e.logged || !isFinite(e.logged)) e.logged = lg; if(x.id < e.id) e.id = x.id; M.set(k, e); }
  const certs = [...M.values()].filter(e => isFinite(e.nb)), now = Date.now(); if(!certs.length) return null;
  const N = new Map(), emails = new Set(), iss = new Map();
  for(const e of certs){ const il = cxIssuerLabel(e.issuer); iss.set(il, (iss.get(il) || 0) + 1);
    for(const v of e.names){ if(v.includes('@')){ emails.add(v); continue; } const r = N.get(v) || {name:v, n:0, first:Infinity, last:-Infinity, until:-Infinity}; r.n++; r.first = Math.min(r.first, e.nb); r.last = Math.max(r.last, e.nb); r.until = Math.max(r.until, e.na); N.set(v, r); } }
  const names = [...N.values()], doms = new Map(); names.forEach(r => { const d = X5.regDom(r.name); doms.set(d, (doms.get(d) || 0) + r.n); });
  const first = Math.min(...certs.map(e => e.nb)), last = Math.max(...certs.map(e => e.nb));
  names.forEach(r => { r.live = r.until > now; r.wild = r.name.startsWith('*.'); r.hot = CT_HOT.test(r.name.replace(/^\*\./, '')); r.fresh = last - r.first < 31 * 864e5; r.look = Object.entries(X5.BRANDS).some(([t, own]) => r.name.includes(t) && !own.includes(X5.regDom(r.name))); });
  /* issuance per month (per quarter beyond five years) */
  const span = (new Date(last).getUTCFullYear() - new Date(first).getUTCFullYear()) * 12 + new Date(last).getUTCMonth() - new Date(first).getUTCMonth() + 1, q = span > 60 ? 3 : 1, bins = [];
  for(let i = 0; i < Math.ceil(span / q); i++){ const d = new Date(Date.UTC(new Date(first).getUTCFullYear(), new Date(first).getUTCMonth() + i * q, 1)); bins.push({t:d.getTime(), n:0, label:q === 3 ? d.getUTCFullYear() + ' Q' + (Math.floor(d.getUTCMonth() / 3) + 1) : d.toLocaleDateString(undefined, {month:'short', year:'numeric', timeZone:'UTC'})}); }
  for(const e of certs){ const d = new Date(e.nb), i = Math.floor(((d.getUTCFullYear() - new Date(first).getUTCFullYear()) * 12 + d.getUTCMonth() - new Date(first).getUTCMonth()) / q); if(bins[i]) bins[i].n++; }
  return {rows:a.length, certs, names, emails:[...emails], issuers:[...iss.entries()].sort((x, y) => y[1] - x[1]), doms:[...doms.entries()].sort((x, y) => y[1] - x[1]), dom:([...doms.entries()].sort((x, y) => y[1] - x[1])[0] || [''])[0], first, last, bins, q, live:certs.filter(e => e.na > now).length, at:now};
}
function cxIssuerLabel(s){ const o = (s.match(/(?:^|,\s*)O="?([^,"]+)/) || [])[1], cn = (s.match(/(?:^|,\s*)CN="?([^,"]+)/) || [])[1]; return o && cn && !cn.startsWith(o) ? o + ' · ' + cn : cn || o || s || 'Unknown issuer'; }
function cxCt(){
  const S = cxS(), A = S.ct;
  if(!A) return `<div class="crt-c">${empty('radar', 'Every certificate ever issued for a domain', 'Public CAs must log each certificate they issue in Certificate Transparency logs, so the logs list a domain’s subdomains — including forgotten test, VPN and admin hosts — and every CA it has used. Type a domain above, open the crt.sh results as JSON, then paste them here. The analysis runs in this browser.',
    `<button class="btn primary" data-act="cxSample" data-v="ct">${ico('sparkles','sm')}Try an example domain</button><button class="btn" data-act="cxCh" data-v="ct">${ico('book-open','sm')}How the logs work</button>`)}</div>`;
  const hot = A.names.filter(r => r.hot), fresh = A.names.filter(r => r.fresh).sort((x, y) => y.first - x.first), look = A.names.filter(r => r.look), wild = A.names.filter(r => r.wild).length, max = Math.max(1, ...A.bins.map(b => b.n));
  const stat = (v, l, d) => `<div class="crt-st"><b>${v}</b><span>${l}</span>${d ? `<small>${d}</small>` : ''}</div>`;
  return `<div class="crt-c">
    <section class="card crt-hero crt-cth"><span class="crt-big inf">${ico('radar')}</span><div class="crt-hm"><h1>${esc(A.dom || 'Transparency results')}</h1><p>${A.rows} log entries · ${A.certs.length} distinct certificates (precertificate and final copies merged) · ${esc(cxYmd(A.first))} to ${esc(cxYmd(A.last))}</p></div>
      <div class="crt-ha">${S.ctRec ? `<span class="crt-pill green">${ico('check','sm')}Saved</span>` : `<button class="btn sm primary" data-act="cxCtSave">${ico('plus','sm')}Add ${A.names.length} names to case</button>`}<button class="btn sm" data-act="cxCtCopy">${ico('copy','sm')}Copy names</button><button class="btn sm ghost" data-act="cxCtCsv">${ico('download','sm')}CSV</button></div></section>
    <div class="crt-sts">${stat(A.names.length, 'unique names', A.doms.length > 1 ? A.doms.length + ' registered domains' : '')}${stat(A.live, 'certificates valid now', A.certs.length - A.live + ' expired')}${stat(wild, 'wildcard names', wild ? 'hide which hosts exist' : '')}${stat(A.issuers.length, 'issuing CAs', esc(A.issuers[0][0]) + ' most')}</div>
    <section class="card crt-s"><h3>${ico('chart-column','sm')}Certificates issued per ${A.q === 3 ? 'quarter' : 'month'}</h3>
      <div class="crt-tl" role="img" aria-label="Issuance over time: ${A.bins.filter(b => b.n).length} active ${A.q === 3 ? 'quarters' : 'months'}, busiest ${esc(A.bins.reduce((m, b) => b.n > m.n ? b : m, A.bins[0]).label)} with ${max}">${A.bins.map(b => `<i style="height:${Math.max(b.n ? 6 : 1, b.n / max * 100)}%" title="${esc(b.label)}: ${b.n}"></i>`).join('')}</div>
      <div class="crt-lg"><span>${esc(A.bins[0].label)}</span><span>${esc(A.bins[A.bins.length - 1].label)}</span></div>
      <p class="crt-e">Bursts usually mean new services or a CA switch. Short-lived certificates (90 days) renew on a steady rhythm; a gap is a server that stopped renewing.</p></section>
    <section class="card crt-s"><h3>${ico('globe','sm')}Names<span class="crt-n">${A.names.length}</span></h3>
      <div class="crt-ctf"><label class="sr" for="cxCtF">Filter names</label><input id="cxCtF" class="inp" type="search" placeholder="Filter, e.g. vpn or dev" value="${esc(S.ctF || '')}" autocomplete="off" spellcheck="false">
        ${['all', 'live', 'hot', 'fresh'].map(k => `<button class="chip${(S.ctK || 'all') === k ? ' on' : ''}" data-act="cxCtK" data-v="${k}" aria-pressed="${(S.ctK || 'all') === k}">${{all:'All', live:'Valid now', hot:'Interesting', fresh:'New in the last month'}[k]}</button>`).join('')}</div>
      <div id="cxCtT">${cxCtTable()}</div></section>
  </div>
  <aside class="crt-r" aria-label="Highlights" tabindex="0">
    <section><h4>${ico('triangle-alert','sm')}Worth a look</h4>
      ${look.length ? cxChk('bad', look.length + ' lookalike name' + (look.length > 1 ? 's' : ''), look.slice(0, 6).map(r => '<span class="mono">' + esc(r.name) + '</span>').join('<br>')) : ''}
      ${hot.length ? cxChk('warn', hot.length + ' interesting host name' + (hot.length > 1 ? 's' : ''), 'VPN, login, admin, development and build systems are the first things attackers probe:<br>' + hot.slice(0, 8).map(r => '<span class="mono">' + esc(r.name) + '</span>').join('<br>') + (hot.length > 8 ? '<br>+' + (hot.length - 8) + ' more — use the Interesting filter' : '')) : ''}
      ${fresh.length ? cxChk('inf', fresh.length + ' name' + (fresh.length > 1 ? 's' : '') + ' first seen in the last month', fresh.slice(0, 5).map(r => '<span class="mono">' + esc(r.name) + '</span> · ' + esc(cxYmd(r.first))).join('<br>')) : ''}
      ${(() => { const k = cxKnownDomains(), m = A.names.filter(r => k.has(r.name.replace(/^\*\./, ''))); return m.length ? cxChk('inf', m.length + ' name' + (m.length > 1 ? 's' : '') + ' already in your cases', m.slice(0, 5).map(r => '<span class="mono">' + esc(r.name) + '</span>').join('<br>')) : ''; })()}
      ${A.emails.length ? cxChk('inf', A.emails.length + ' email address' + (A.emails.length > 1 ? 'es' : ''), A.emails.slice(0, 4).map(esc).join(', ')) : ''}
      ${!look.length && !hot.length && !fresh.length ? cxChk('ok', 'Nothing stands out', 'No lookalikes, no obviously sensitive host names') : ''}</section>
    <section><h4>${ico('building-2','sm')}Issuers</h4>${A.issuers.slice(0, 8).map(([l, n]) => `<div class="crt-ib"><span>${esc(l)}</span><b>${n}</b><i style="width:${n / A.issuers[0][1] * 100}%"></i></div>`).join('')}</section>
    ${A.doms.length > 1 ? `<section><h4>${ico('layers','sm')}Registered domains</h4>${A.doms.slice(0, 8).map(([d, n]) => `<div class="crt-ib"><span class="mono">${esc(d)}</span><b>${n}</b><i style="width:${n / A.doms[0][1] * 100}%"></i></div>`).join('')}</section>` : ''}
    <section><h4>${ico('book-open','sm')}Next steps</h4><p class="crt-e">Resolve the names to find live hosts (Kit › DNS), check each for a login page, and compare issuers against what the organisation says it uses — an unexpected CA is a lead.</p></section>
  </aside>`;
}
function cxCtRows(){
  const S = cxS(), A = S.ct, f = (S.ctF || '').trim().toLowerCase(), k = S.ctK || 'all', [sk, sd] = S.ctSort || ['last', -1];
  return A.names.filter(r => (!f || r.name.includes(f)) && (k === 'all' || (k === 'live' && r.live) || (k === 'hot' && (r.hot || r.look)) || (k === 'fresh' && r.fresh)))
    .sort((x, y) => (sk === 'name' ? x.name.localeCompare(y.name) : x[sk] - y[sk]) * sd || x.name.localeCompare(y.name));
}
function cxKnownDomains(){ return cxMemo('known', cxKnownDomains0); }
function cxKnownDomains0(){ const k = new Set(); for(const r of DB.records) if(r.source !== 'ct-log') for(const e of r.ents || []) if(e.k === 'domain') k.add(String(e.v).toLowerCase()); return k; }
function cxCtTable(){
  const S = cxS(), rows = cxCtRows(), [sk, sd] = S.ctSort || ['last', -1], now = Date.now();
  const th = (k, l) => `<th scope="col" aria-sort="${sk === k ? (sd > 0 ? 'ascending' : 'descending') : 'none'}"><button data-act="cxCtSort" data-v="${k}">${l}${sk === k ? ico(sd > 0 ? 'arrow-up' : 'arrow-down','sm') : ''}</button></th>`;
  if(!rows.length) return '<p class="crt-e">No names match.</p>';
  const known = cxKnownDomains();
  return `<div class="tblwrap crt-ctw" tabindex="0" role="region" aria-label="Names from the logs"><table class="crt-tbl crt-ctt"><thead><tr>${th('name', 'Name')}${th('n', 'Certificates')}${th('first', 'First seen')}${th('last', 'Last issued')}${th('until', 'Covered until')}<th scope="col"><span class="sr">Look up</span></th></tr></thead><tbody>
    ${rows.slice(0, 400).map(r => `<tr><td class="mono">${esc(r.name)}${r.look ? ' <span class="crt-tag bad">lookalike</span>' : r.hot ? ' <span class="crt-tag">interesting</span>' : ''}${r.fresh ? ' <span class="crt-tag inf">new</span>' : ''}${known.has(r.name.replace(/^\*\./, '')) ? ' <span class="crt-tag ok">in your cases</span>' : ''}</td><td>${r.n}</td><td>${esc(cxYmd(r.first))}</td><td>${esc(cxYmd(r.last))}</td><td>${r.live ? `<span class="crt-y">${esc(cxYmd(r.until))}</span>` : `<span class="t3">expired ${esc(cxYmd(r.until))}</span>`}</td><td><button class="iconbtn" data-act="cxPivMenu" data-v="domain:${esc(r.name.replace(/^\*\./, ''))}" aria-haspopup="menu" aria-label="Look up ${esc(r.name)}">${ico('external-link','sm')}</button></td></tr>`).join('')}</tbody></table></div>
    ${rows.length > 400 ? `<p class="crt-e">Showing 400 of ${rows.length} — narrow the filter to see the rest. Copy names and CSV include all of them.</p>` : ''}`;
}
function cxCtSummary(A){
  return ['Certificate Transparency results for ' + (A.dom || 'a domain') + ' (crt.sh JSON, imported ' + new Date(A.at).toISOString() + ')', A.rows + ' log entries, ' + A.certs.length + ' distinct certificates, ' + cxYmd(A.first) + ' to ' + cxYmd(A.last) + ', ' + A.live + ' valid when imported',
    'Issuers: ' + A.issuers.map(([l, n]) => l + ' (' + n + ')').join('; '), '', 'Names (first seen, last issued, certificates):',
    ...A.names.slice().sort((x, y) => x.name.localeCompare(y.name)).map(r => r.name + '  ' + cxYmd(r.first) + '  ' + cxYmd(r.last) + '  ' + r.n + (r.look ? '  LOOKALIKE' : r.hot ? '  interesting' : ''))].join('\n');
}

/* ---------- guide ---------- */
function cxGuide(){
  const S = cxS(), ch = CERT_GUIDE.find(c => c.id === S.ch) || CERT_GUIDE[0], i = CERT_GUIDE.indexOf(ch);
  return `<div class="crt-gd"><nav class="crt-toc" aria-label="Chapters">${CERT_GUIDE.map((c, j) => `<button data-act="cxCh" data-v="${c.id}"${c === ch ? ' aria-current="true" class="on"' : ''}><span class="n">${j + 1}</span>${esc(c.title)}</button>`).join('')}</nav>
    <article class="crt-art" id="cxArt"><p class="crt-k">Chapter ${i + 1} of ${CERT_GUIDE.length}</p><h1>${esc(ch.title)}</h1><p class="crt-lead">${esc(ch.lead)}</p>${ch.body}
      <div class="crt-nav">${i > 0 ? `<button class="btn sm" data-act="cxCh" data-v="${CERT_GUIDE[i - 1].id}">${ico('arrow-left','sm')}${esc(CERT_GUIDE[i - 1].title)}</button>` : '<span></span>'}${i < CERT_GUIDE.length - 1 ? `<button class="btn sm" data-act="cxCh" data-v="${CERT_GUIDE[i + 1].id}">${esc(CERT_GUIDE[i + 1].title)}${ico('arrow-right','sm')}</button>` : ''}</div></article>
    <aside class="crt-r" aria-label="Try it" tabindex="0">
      <section><h4>${ico('sparkles','sm')}Try it</h4><button class="btn sm crt-wide" data-act="cxSample" data-v="${ch.sample}">${ico('scroll-text','sm')}Open the example in the decoder</button><p class="crt-e">${esc(CERT_SAMPLES[ch.sample].label)} — fictional.</p></section>
      <section><h4>${ico('book-open','sm')}Flashcards from this chapter</h4>${ch.cards.map(([q, a]) => `<div class="crt-qa"><b>${esc(q)}</b>${esc(a)}</div>`).join('')}
        <button class="btn sm crt-wide" data-act="cxToNb">${ico('plus','sm')}Add ${ch.cards.length} cards to my Notebook</button></section>
      <section><h4>${ico('binary','sm')}Command for this chapter</h4><div class="crt-cmd">${esc(ch.cmd)}</div><button class="btn xs ghost" data-act="cxCopy" data-v="${esc(ch.cmd)}">${ico('copy','sm')}Copy</button></section>
    </aside></div>`;
}

/* ---------- saving ---------- */
function cxPeLines(P){
  const sd = P.sigs[0], sg = sd && sd.signers[0], ts = sg && sg.counter[0], L = ['Signed program: ' + P.name, 'Type: ' + (P.dll ? 'DLL' : 'program') + ', ' + P.machine + ', ' + P.size + ' bytes'];
  if(P.sha256) L.push('File SHA-256: ' + P.sha256);
  if(!sd) L.push('Signature: none'); else {
    L.push('Signature: ' + (sd.fileOk ? 'file matches its signature' : sd.fileOk === false ? 'FILE CHANGED AFTER SIGNING (hash mismatch)' : 'not checked') + (sd.spc ? ' (Authenticode ' + sd.spc.alg + ' ' + sd.spc.digest + ')' : ''));
    if(sg && sg.cert) L.push('Publisher: ' + sg.cert.subject.text, 'Publisher certificate SHA-1: ' + (sg.cert.fp ? sg.cert.fp.sha1 : ''));
    if(sg && sg.program) L.push('Program description: ' + sg.program); if(sg && sg.url) L.push('More information: ' + sg.url);
    L.push(ts ? 'Timestamp: ' + cxDate(ts.time) + ' (' + ts.kind + ')' : 'Timestamp: none' + (sg && isFinite(sg.time) ? '; signer clock says ' + cxDate(sg.time) : ''));
    if(P.after > 8) L.push('Data after the signature: ' + P.after + ' bytes (not covered)'); }
  return L.concat('');
}
function cxSummary(R){
  const L = R.pe ? cxPeLines(R.pe) : [], certs = R.chain ? R.chain.order.concat(R.chain.extra) : R.certs;
  for(const c of [...certs, ...R.csrs]){
    L.push((c.kind === 'csr' ? 'Signing request: ' : 'Certificate: ') + c.title, 'Subject: ' + (c.subject.text || '(empty)'));
    if(c.kind === 'cert') L.push('Issuer: ' + c.issuer.text, 'Valid: ' + cxDate(c.notBefore) + ' to ' + cxDate(c.notAfter), 'Serial: ' + c.serial);
    if(c.san.length) L.push('Names: ' + c.san.map(s => s.v).join(', '));
    L.push('Key: ' + c.key.label + ' · signature ' + c.sigAlg.name);
    if(c.fp) L.push('SHA-256: ' + c.fp.sha256, 'SHA-1: ' + c.fp.sha1, 'Key SHA-256: ' + c.fp.spki256);
    const F = cxFindings(c).filter(f => f.s !== 'info'); if(F.length) L.push('Findings:', ...F.map(f => '- ' + f.t + ': ' + f.d));
    L.push('');
  }
  L.push('Source: ' + (R.src || 'pasted') + ' · examined ' + new Date().toISOString() + ' with OSINTrix ' + BRAND.version + ' (parsed in the browser; no network lookups)', '');
  L.push('PEM:', ...certs.map(c => X5.toPem(c.der)), ...R.csrs.map(q => X5.toPem(q.der, 'CERTIFICATE REQUEST')));
  return L.join('\n');
}
async function cxSave(){
  const S = cxS(), R = S.R; if(!R) return; if(!R.ready) await cxEnrich(R);
  const lead = R.pe ? cxPeSigner(R) : null, c = lead || (R.chain ? R.chain.order[0] : R.certs[0] || R.csrs[0]); if(!c) return;
  const cid = DB.active, body = cxSummary(R), F = c.kind === 'cert' ? cxFindings(c) : [], bad = F.some(f => f.s === 'bad') || (R.pe && R.pe.sigs[0] && R.pe.sigs[0].fileOk === false);
  const title = R.pe ? 'Signed program: ' + R.pe.name + ' (' + ((c.subject.map.O || [c.title])[0]) + ')' : (c.kind === 'csr' ? 'Signing request: ' : 'Certificate: ') + c.title;
  const r = {id:uid('r'), caseId:cid, type:'evidence', title, body, tsRaw:c.kind === 'cert' && isFinite(c.notBefore) ? new Date(c.notBefore).toISOString() : '', tsZone:'explicit', ts:c.kind === 'cert' && isFinite(c.notBefore) ? c.notBefore : null,
    source:'certificate', host:'', tags:['certificate', 'tls'].concat(c.kind === 'csr' ? ['csr'] : [], R.pe ? ['authenticode', 'code-signing'] : [], bad ? ['suspicious'] : []), ents:extractRich(body), answer:'', addedBy:'You', addedAt:Date.now(), hash:'', pv:1, att:[]};
  DB.records.push(r); mutate('saved certificate ' + c.title); await hashRecords(); S.rec = r.id; R.rec = r.id; cxPaint(); renderNav();
  toast('Saved to ' + theCase(cid).code + ' — names and fingerprints are now entities', 'Open', () => { UI.sel = {kind:'rec', id:r.id}; UI.inspOpen = true; go(caseHash(cid, 'timeline')); });
}
async function cxCtSave(){
  const S = cxS(), A = S.ct; if(!A) return; const cid = DB.active, body = cxCtSummary(A);
  const r = {id:uid('r'), caseId:cid, type:'evidence', title:'Certificate Transparency: ' + (A.dom || 'names') + ' (' + A.names.length + ' names)', body, tsRaw:new Date(A.last).toISOString(), tsZone:'explicit', ts:A.last,
    source:'ct-log', host:'crt.sh', tags:['certificate', 'ct', 'subdomains'], ents:extractRich(body), answer:'', addedBy:'You', addedAt:Date.now(), hash:'', pv:1, att:[]};
  DB.records.push(r); mutate('saved CT results ' + A.dom); await hashRecords(); S.ctRec = r.id; cxPaint(); renderNav();
  toast(A.names.length + ' names saved to ' + theCase(cid).code, 'Open', () => { UI.sel = {kind:'rec', id:r.id}; UI.inspOpen = true; go(caseHash(cid, 'timeline')); });
}
/* exports: a JSON description and a text report in the style of openssl x509 -text */
function cxJson(c){
  return {subject:c.subject.text, subjectFields:Object.fromEntries(Object.entries(c.subject.map)), issuer:c.issuer.text, serial:c.serial, version:c.version, notBefore:cxIso(c.notBefore), notAfter:cxIso(c.notAfter),
    key:{type:c.key.type, bits:c.key.bits || null, curve:c.key.curve || null, exponent:c.key.e != null ? c.key.e : null, sha256:c.fp ? c.fp.spki256 : null, pin:c.fp ? c.fp.pin : null}, signature:c.sigAlg.name,
    names:c.san.map(s => ({type:s.t, value:s.v})), ca:c.isCA, selfSigned:c.selfIssued, level:c.level || null,
    extensions:c.exts.map(e => ({oid:e.oid, name:e.name, critical:e.critical, value:e.ekus ? e.ekus.map(k => k.name) : e.usages || e.names && e.names.map(n => n.v) || e.urls || e.access || e.policies && e.policies.map(p => p.oid) || e.scts && e.scts.map(x => ({log:x.logId, time:cxIso(x.time)})) || e.text || ''})),
    fingerprints:c.fp ? {sha256:c.fp.sha256, sha1:c.fp.sha1} : null, findings:cxFindings(c).map(f => ({severity:f.s, title:f.t, detail:f.d})), pem:X5.toPem(c.der)};
}
const cxIso = t => isFinite(t) ? new Date(t).toISOString() : null;
function cxText(c){
  const I = '        ', d = t => isFinite(t) ? new Date(t).toUTCString().replace(/^\w+, /, '') : '?';
  const L = ['Certificate:', '    Data:', I + 'Version: ' + c.version + ' (0x' + (c.version - 1) + ')', I + 'Serial Number:', I + '    ' + c.serial, I + 'Signature Algorithm: ' + c.sigAlg.name, I + 'Issuer: ' + c.issuer.text, I + 'Validity',
    I + '    Not Before: ' + d(c.notBefore), I + '    Not After : ' + d(c.notAfter), I + 'Subject: ' + c.subject.text, I + 'Subject Public Key Info:', I + '    Public Key: ' + c.key.label + (c.key.detail ? ' (' + c.key.detail + ')' : '')];
  if(c.exts.length){ L.push(I + 'X509v3 extensions:'); for(const e of c.exts) L.push(I + '    ' + e.name + (e.critical ? ': critical' : ':'), I + '        ' + (e.ekus ? e.ekus.map(k => k.name).join(', ') : e.policies ? e.policies.map(p => p.oid + (p.name !== p.oid ? ' (' + p.name + ')' : '')).join(', ') : e.scts ? e.scts.map(x => cxDate(x.time) + ' log ' + x.logId).join('\n' + I + '        ') : e.text || '')); }
  L.push('    Signature Algorithm: ' + c.sigAlg.name);
  if(c.fp) L.push('', 'SHA-256 Fingerprint=' + c.fp.sha256.toUpperCase().match(/../g).join(':'), 'SHA1 Fingerprint=' + c.fp.sha1.toUpperCase().match(/../g).join(':'));
  const F = cxFindings(c); if(F.length) L.push('', 'Findings (Osintrix):', ...F.map(f => '  [' + f.s + '] ' + f.t + ' — ' + f.d));
  return L.join('\n') + '\n\n' + X5.toPem(c.der);
}
function cxToNb(){
  const S = cxS(), ch = CERT_GUIDE.find(c => c.id === S.ch) || CERT_GUIDE[0]; ensureNB();
  let b = DB.nb.books.find(x => x.name === 'Certificates'); if(!b) b = nbNewBook({name:'Certificates', kind:'Study', color:'#0284c7'});
  const s = nbSecsOf(b.id).find(x => x.name === 'How certificates work') || nbNewSec(b.id, 'How certificates work');
  let p = nbPagesOf(s.id).find(x => x.title === ch.title);
  const html = nbClean(`<p>${esc(ch.lead)}</p>${ch.body}<h3>Flashcards</h3>${ch.cards.map(([q, a]) => `<p>Q: ${esc(q)}</p><p>A: ${esc(a)}</p>`).join('')}<pre>${esc(ch.cmd)}</pre>`);
  if(p){ p.html = html; nbTouch(p); } else p = nbNewPage(s.id, {title:ch.title, html, tags:['certificates', 'tls'], src:'Certificates guide'});
  mutate('certificate flashcards to notebook'); renderNav();
  toast(ch.cards.length + ' flashcards added to Notebook › Certificates', 'Open', () => { UI.nbPage = p.id; UI.nbView = 'page'; go('#/notebook'); });
}

/* ---------- events ---------- */
async function cxReadFile(f, mode){
  if(/\.(pfx|p12|key|ppk|jks|keystore)$/i.test(f.name)){ cxS().keyWarn = true; if(UI.route.area === 'certs') cxPaint(); return toast('Key files and PKCS#12 bundles hold private keys — they are not opened here. Export just the certificate (.cer / .pem) instead.'); }
  const pe = /\.(exe|dll|sys|ocx|scr|efi|cpl|mui)$/i.test(f.name), lim = pe ? 200 : 40;
  if(f.size > lim * 1048576) return toast(pe ? 'Programs over ' + lim + ' MB are not read here' : 'That file is too big to be a certificate');
  const u = new Uint8Array(await f.arrayBuffer()); if(!u.length) return toast('That file is empty');
  if(UI.route.area !== 'certs'){ go('#/certs'); await new Promise(r => setTimeout(r, 30)); }
  const S = cxS(), isPe = u[0] === 0x4d && u[1] === 0x5a, bin = isPe || (u[0] === 0x30 && /\.(der|cer|crt|p7b|p7c|p7s|cat|spc)$/i.test(f.name));
  if(!bin){ const t = new TextDecoder().decode(u.subarray(0, 50 * 1048576)); if(mode === 'ct' || cxLooksCt(t)){ const A = ctParse(t); if(!A) return toast('That file is not a crt.sh JSON result list'); S.ct = A; S.ctF = ''; S.ctRec = null; S.ctDom = S.ctDom || A.dom; S.tab = 'ct'; cxKeep(f.name, t, 'ct'); return cxPaint(); } }
  if(mode === 'cmp') return cxLoad(bin ? u : new TextDecoder().decode(u), {cmp:true, name:f.name});
  S.input = bin ? '' : new TextDecoder().decode(u.subarray(0, 400000)); S.rec = null;
  return cxLoad(u, {name:f.name});
}
function bindCerts(){
  { const S = cxS(); if(!S.R && !S.ct && typeof recentRestore === 'function') recentRestore('certs'); }
  const dom = $('cxCtDom'); if(dom) dom.addEventListener('input', () => { const S = cxS(), l = $('cxCtLink'); S.ctDom = dom.value; if(!l) return; const d = dom.value.trim(); if(d){ l.href = cxCtUrl(d); l.removeAttribute('aria-disabled'); } else { l.removeAttribute('href'); l.setAttribute('aria-disabled', 'true'); } });
  const R = cxS().R, cur = () => R && (R.certs[cxS().sel] || R.certs[0]);
  const h = $('cxHost'); if(h) h.addEventListener('input', () => { cxS().host = h.value; const c = cur(); if(c) $('cxHostR').innerHTML = cxHostRes(c); });
  const w = $('cxWhen'); if(w) w.addEventListener('input', () => { cxS().when = w.value; const c = cur(); if(c) $('cxWhenR').innerHTML = cxWhenRes(c); });
  const f = $('cxCtF'); if(f) f.addEventListener('input', () => { cxS().ctF = f.value; $('cxCtT').innerHTML = cxCtTable(); });
  for(const [id, k] of [['cxCmpA', 'cmpA'], ['cxCmpB', 'cmpB']]){ const el = $(id); if(el) el.addEventListener('change', () => { cxS()[k] = el.value; cxPaint(); }); }
}
/* paste or drop anywhere on the Certificates page */
const cxHere = () => UI.route && UI.route.area === 'certs' && $('scrim') && $('scrim').hidden;
document.addEventListener('paste', ev => {
  if(!cxHere()) return; const t = ev.target; if(t && t.closest && t.closest('input,textarea,select,[contenteditable="true"]')) return;
  const cd = ev.clipboardData; if(!cd) return; const f = cd.files && cd.files[0];
  if(f){ ev.preventDefault(); return cxReadFile(f, cxS().tab === 'compare' ? 'cmp' : cxS().tab === 'ct' ? 'ct' : ''); }
  const s = cd.getData('text/plain'); if(!s || !s.trim()) return; ev.preventDefault(); cxIngest(s, cxS().tab === 'compare' ? {cmp:true} : {});
});
const cxFilesDrag = ev => [...((ev.dataTransfer && ev.dataTransfer.types) || [])].includes('Files');
document.addEventListener('dragover', ev => { if(!cxHere() || !cxFilesDrag(ev)) return; ev.preventDefault(); const w = document.querySelector('.crtw'); if(w) w.classList.add('dropping'); });
document.addEventListener('dragleave', ev => { if(ev.relatedTarget && document.documentElement.contains(ev.relatedTarget)) return; const w = document.querySelector('.crtw'); if(w) w.classList.remove('dropping'); });
document.addEventListener('drop', ev => { const w = document.querySelector('.crtw'); if(w) w.classList.remove('dropping'); if(!cxHere() || !cxFilesDrag(ev)) return; const f = ev.dataTransfer.files[0]; if(!f) return; ev.preventDefault();
  cxReadFile(f, cxS().tab === 'compare' ? 'cmp' : cxS().tab === 'ct' ? 'ct' : ''); });
const CX_FILES = '.pem,.crt,.cer,.der,.csr,.req,.p7b,.p7c,.p7s,.cat,.txt,.html,.htm,.json,.exe,.dll,.sys,.ocx,.scr,.efi';
const cxCur = () => { const R = cxS().R; return R && (R.certs[cxS().sel] || R.certs[0]); };
const CX_ACTS = {
  cxTab:(id, v) => { cxS().tab = v; cxPaint(); },
  cxClear:() => { const S = cxS(); S.R = null; S.rec = null; S.keyWarn = false; S.input = ''; if(typeof recentSetLast === 'function'){ recentSetLast('certs', null); save(); } cxPaint(); },
  cxPaste:(id, v) => cxPasteDlg(v || 'decode'),
  cxPdGo:(id, v) => { const t = ($('cxPdIn') || {}).value || ''; if(!t.trim()) return toast('Paste something first'); closeDlg();
    if(v === 'ct'){ const A = ctParse(t); if(!A) return toast('That is not crt.sh JSON — open the link with output=json and copy everything'); const S = cxS(); S.ct = A; S.ctF = ''; S.ctRec = null; S.ctDom = S.ctDom || A.dom; S.tab = 'ct'; cxKeep('crt.sh · ' + (A.dom || 'names'), t, 'ct'); return cxPaint(); }
    if(v === 'cmp') return cxLoad(t, {cmp:true});
    cxIngest(t); },
  cxPdFile:(id, v) => { closeDlg(); pickFiles(v === 'ct' ? '.json,.txt' : CX_FILES, fs => fs[0] && cxReadFile(fs[0], v)); },
  cxFile:(id, v) => pickFiles(v === 'ct' ? '.json,.txt' : CX_FILES, fs => fs[0] && cxReadFile(fs[0], v || (cxS().tab === 'compare' ? 'cmp' : ''))),
  cxExamples:(id, v, t) => { const r = t.getBoundingClientRect(); showMenu(r.left, r.bottom + 6, Object.entries(CERT_SAMPLES).map(([k, s]) => ({label:s.label, icon:k === 'csr' ? 'file-text' : k === 'ct' ? 'radar' : k === 'pe' ? 'app-window' : k === 'reuse' ? 'git-compare' : 'scroll-text', fn:() => CX_ACTS.cxSample(null, k === 'reuse' ? 'cmp' : k)})), 'Fictional examples'); },
  cxSaved:() => cxHistory(),
  cxHistRec:id => { closeDlg(); CX_ACTS.cxRec(id); },
  cxHistDel:id => { const r = DB.records.find(x => x.id === id); if(!r) return; const S = cxS(); if(S.rec === id){ S.rec = null; if(S.R) S.R.rec = null; }
    delRecord([id]); cxHistory(); if(UI.route.area === 'certs') cxPaint(); },
  cxSample:(id, v) => { const S = cxS();
    if(v === 'ct'){ S.ct = ctParse(JSON.stringify(CERT_SAMPLES.ct.data)); S.ctF = ''; S.ctK = 'all'; S.ctRec = null; S.ctDom = S.ct.dom; S.tab = 'ct'; return cxPaint(); }
    if(v === 'pe'){ const b = atob(CERT_SAMPLES.pe.b64), u = new Uint8Array(b.length); for(let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i); S.input = ''; S.rec = null; return cxLoad(u, {name:CERT_SAMPLES.pe.name, src:'Example · ' + CERT_SAMPLES.pe.label, tab:'decoder'}); }
    if(v === 'cmp'){ const [a, b2] = X5.read(CERT_SAMPLES.reuse.pem).certs; [a, b2].forEach(c => { if(c && !S.cmpX.some(x => cxId(x) === cxId(c))) S.cmpX.push(c); });
      S.cmpA = 'x:' + cxId(a); S.cmpB = 'x:' + cxId(b2); S.tab = 'compare'; cxPaint(); return Promise.all([a, b2].map(c => X5.prints(c))).then(() => cxPaint()); }
    const s = CERT_SAMPLES[v]; if(!s) return; S.input = s.pem; S.rec = null; cxLoad(s.pem, {src:'Example · ' + s.label, tab:v === 'chain' ? 'chain' : v === 'csr' ? 'csr' : 'decoder'}); },
  cxSel:(id, v) => { cxS().sel = +v; cxS().tab = 'decoder'; cxPaint(); },
  cxOpenIn:(id, v) => { const S = cxS(); S.sel = +v; S.tab = 'decoder'; cxPaint(); },
  cxRec:id => { const r = DB.records.find(x => x.id === id); if(!r) return; const S = cxS(); S.input = ''; cxLoad(r.body, {rec:id, tab:'decoder'}); },
  cxSave:() => cxSave(),
  cxCopy:(id, v) => copyText(v),
  cxCopyPem:() => { const R = cxS().R; if(!R) return; copyText(R.certs.length && cxS().tab === 'decoder' ? X5.toPem(cxCur().der) : R.csrs.map(q => X5.toPem(q.der, 'CERTIFICATE REQUEST')).join('') || R.certs.map(c => X5.toPem(c.der)).join('')); },
  cxCopyNames:() => { const c = cxCur(); if(c) copyText(c.san.map(s => s.v).join('\n')); },
  cxDl:() => { const c = cxCur(); if(c) download(nbSlug(c.title) + '.pem', X5.toPem(c.der), 'application/x-pem-file'); },
  cxExport:(id, v, t) => { const c = cxCur(); if(!c) return; const r = t.getBoundingClientRect(), n = nbSlug(c.title) || 'certificate';
    showMenu(r.left, r.bottom + 6, [{label:'PEM (.pem)', icon:'file-text', fn:() => download(n + '.pem', X5.toPem(c.der), 'application/x-pem-file')}, {label:'DER (.cer)', icon:'binary', fn:() => download(n + '.cer', c.der, 'application/pkix-cert')},
      {label:'Text report (.txt)', icon:'list', fn:() => download(n + '.txt', cxText(c))}, {label:'JSON (.json)', icon:'braces', fn:() => download(n + '.json', JSON.stringify(cxJson(c), null, 2), 'application/json')},
      {label:'Whole chain (.pem)', icon:'link-2', disabled:cxS().R.certs.length < 2, fn:() => download(n + '-chain.pem', (cxS().R.chain ? cxS().R.chain.order : cxS().R.certs).map(x => X5.toPem(x.der)).join(''), 'application/x-pem-file')},
      {label:'Copy as JSON', icon:'copy', fn:() => copyText(JSON.stringify(cxJson(c), null, 2))}], 'Export'); },
  cxIndPick:(id, v, t) => { const S = cxS(), P = S.indPick || (S.indPick = new Set()); t.checked ? P.add(v) : P.delete(v); cxPaint.keep = true; cxPaint(); },
  cxIndAll:() => { const S = cxS(), c = cxCur(); if(!c) return; S.indPick = S.indPick && S.indPick.size ? new Set() : new Set(cxInds(c).map(x => x.k + ':' + x.v)); cxPaint.keep = true; cxPaint(); },
  cxIndCopy:(id, v) => { const c = cxCur(); if(!c) return; const S = cxS(), all = cxInds(c), L = S.indPick && S.indPick.size ? all.filter(x => S.indPick.has(x.k + ':' + x.v)) : all; copyText(L.map(x => v === 'd' ? defang(x.v) : x.v).join('\n')); },
  cxIndGraph:() => { const S = cxS(), c = cxCur(); if(!c || !S.indPick || !S.indPick.size) return; const D = derive(), made = [];
    for(const x of cxInds(c)){ const id = x.k + ':' + x.v; if(!S.indPick.has(id)) continue; const type = x.k === 'organization' ? 'organization' : KIND_TO_TYPE[x.k]; if(!type || !TYPES[type]) continue;
      if(DB.entries.some(e => e.caseId === DB.active && e.type === type && String(Object.values(e.fields)[0] || '').toLowerCase() === x.v.toLowerCase())) continue;
      made.push({id:uid('v'), caseId:DB.active, type, fields:{[TYPES[type].fields[0][0]]:x.v}, priority:cxWorst(cxFindings(c)) === 'bad' ? 'high' : 'medium', starred:false, tags:['certificate'], notes:'From the certificate “' + c.title + '”' + (c.fp ? ' (SHA-256 ' + c.fp.sha256 + ')' : ''), src:S.rec || '', created:Date.now(), pos:null}); }
    if(!made.length) return toast('Those are already on the graph');
    DB.entries.push(...made); ensurePositions(); S.indPick = new Set(); mutate('added ' + made.length + ' certificate indicators to the graph'); cxPaint.keep = true; cxPaint(); renderNav();
    toast(made.length + ' added to ' + theCase(DB.active).code + '’s graph', 'Open graph', () => go(caseHash(DB.active, 'graph'))); },
  cxPivMenu:(id, v, t) => { const i = v.indexOf(':'), L = pivotLinks(v.slice(0, i), v.slice(i + 1)), r = t.getBoundingClientRect(); showMenu(r.left, r.bottom + 6, L.map(([n, u]) => ({label:n, icon:'external-link', fn:() => { const w = window.open(u, '_blank', 'noopener'); if(w) w.opener = null; }})), 'Look up ' + v.slice(i + 1)); },
  cxSeenGo:() => { const el = $('cxSeen'); if(el) el.scrollIntoView({behavior:'smooth', block:'start'}); },
  cxOpenRec:id => { const r = DB.records.find(x => x.id === id); if(!r) return; DB.active = r.caseId; UI.sel = {kind:'rec', id}; UI.inspOpen = true; go(caseHash(r.caseId, 'timeline')); },
  cxGoInd:() => { const el = $('cxInd'); if(el) el.scrollIntoView({behavior:'smooth', block:'start'}); },
  cxGoHunt:() => { const el = $('cxHunt'); if(el) el.scrollIntoView({behavior:'smooth', block:'start'}); },
  cxCtFor:(id, v) => { const S = cxS(); S.ctDom = v; S.tab = 'ct'; cxPaint(); const d = $('cxCtDom'); if(d) d.focus(); },
  cxReport:() => { const c = cxCur(); if(!c) return; const R = cxS().R, F = cxFindings(c), reuse = cxReuse(c), inds = cxInds(c), A = cxAssess(c, R, F, reuse, inds, cxSeen(inds));
    copyText(['Certificate: ' + c.title + (c.fp ? ' (SHA-256 ' + c.fp.sha256 + ')' : ''), 'Assessment: ' + A.head, '', ...A.P.map(p => '- ' + p), '', 'Indicators (defanged):', ...inds.map(x => '- ' + defang(x.v) + ' (' + x.label + ')')].join('\n')); },
  cxCmpAll:(id, v) => { cxS().cmpAll = v === '1'; cxPaint.keep = true; cxPaint(); },
  cxCmpSwap:() => { const S = cxS(); [S.cmpA, S.cmpB] = [S.cmpB, S.cmpA]; cxPaint(); },
  cxCmpWith:(id, v) => { const S = cxS(), c = cxCur(); if(!c) return; S.cmpA = 'in:' + cxId(c); const [rid, ...rest] = v.split(':'), key = rest.join(':'); S.cmpB = rid === 'in' ? 'in:' + key : rid + ':' + key; S.tab = 'compare'; cxPaint(); },
  cxCtSort:(id, v) => { const S = cxS(), [k, d] = S.ctSort || ['last', -1]; S.ctSort = [v, k === v ? -d : v === 'name' ? 1 : -1]; $('cxCtT').innerHTML = cxCtTable(); const b = document.querySelector(`#cxCtT [data-v="${v}"]`); if(b) b.focus(); },
  cxCtK:(id, v) => { cxS().ctK = v; document.querySelectorAll('[data-act=cxCtK]').forEach(b => { b.classList.toggle('on', b.dataset.v === v); b.setAttribute('aria-pressed', b.dataset.v === v); }); $('cxCtT').innerHTML = cxCtTable(); },
  cxCtCopy:() => { const A = cxS().ct; if(A) copyText(cxCtRows().map(r => r.name).join('\n')); },
  cxCtCsv:() => { const A = cxS().ct; if(!A) return; const q = v => csvCell(v);
    download('ct-' + (nbSlug(A.dom) || 'names') + '.csv', 'name,certificates,first_seen,last_issued,covered_until,valid_now,interesting\n' + A.names.map(r => [q(r.name), r.n, cxYmd(r.first), cxYmd(r.last), cxYmd(r.until), r.live, r.look ? 'lookalike' : r.hot ? 'yes' : ''].join(',')).join('\n') + '\n', 'text/csv'); },
  cxCtSave:() => cxCtSave(),
  cxType:(id, v) => { const S = cxS(); S.ch = 'types'; S.tab = 'guide'; cxPaint(); CX_ACTS.cxJump(null, v); },
  cxJump:(id, v) => { const el = $('crtg-ty-' + v), a = $('cxArt'); if(!el) return; if(a && a.scrollHeight > a.clientHeight + 4) a.scrollTop += el.getBoundingClientRect().top - a.getBoundingClientRect().top - 12; else el.scrollIntoView({block:'start'}); const h = el.querySelector('h3') || el; h.setAttribute('tabindex', '-1'); h.focus({preventScroll:true}); },
  cxCh:(id, v) => { const S = cxS(); S.ch = v; S.tab = 'guide'; cxPaint(); const a = $('cxArt'); if(a) a.scrollTop = 0; },
  cxToNb:() => cxToNb(),
  pcCerts:(id, v) => { const x = UI.pcap && UI.pcap.tls[+v]; if(!x || !x.certs.length) return; const pem = x.certs.map(d => X5.toPem(d)).join(''); const S = cxS(); S.input = pem; S.rec = null; S.tab = 'decoder'; go('#/certs'); setTimeout(() => cxLoad(pem, {src:'From the packet capture · ' + (x.sni || x.srv)}), 30); }
};
