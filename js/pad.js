/* ==========================================================================
   Scratchpad — a smart notepad. Paste or type logs and notes; it detects
   indicators live (IPs, domains, hashes, ports, protocols, timestamps, …) and
   groups them into lanes. Select any across lanes to copy, defang, or send to a
   case. Text is saved in this browser. Uses the app's extraction engine.
   ========================================================================== */
const PAD_LANES = [
  {id: 'net',   name: 'Network',         icon: 'network',         kinds: ['ipv4', 'ipv6', 'domain', 'url', 'mac', 'asn']},
  {id: 'ports', name: 'Ports',           icon: 'binary',          custom: 'port'},
  {id: 'proto', name: 'Protocols',       icon: 'arrow-right-left', custom: 'proto'},
  {id: 'time',  name: 'Timeline',        icon: 'clock',           custom: 'time'},
  {id: 'id',    name: 'Identity',        icon: 'user',            kinds: ['email', 'handle', 'social', 'phone', 'account', 'sid', 'btc', 'eth', 'xmr', 'ltc', 'trx', 'doge', 'iban']},
  {id: 'hash',  name: 'Hashes',          icon: 'file-digit',      kinds: ['md5', 'sha1', 'sha256', 'sha512']},
  {id: 'vuln',  name: 'Vulnerabilities', icon: 'shield-alert',    kinds: ['cve', 'ttp']},
  {id: 'host',  name: 'Files & hosts',   icon: 'file-text',       kinds: ['file', 'path', 'regkey', 'eventid']},
  {id: 'place', name: 'Locations',       icon: 'map-pin',         kinds: ['coords']}
];
const PAD_KIND2LANE = (() => { const m = {}; PAD_LANES.forEach(L => (L.kinds || []).forEach(k => m[k] = L.id)); return m; })();
const PROTO_RE = /\b(TCP|UDP|ICMP|HTTPS?|DNS|TLS|SSL|SSH|FTP|SFTP|SMTP|IMAP|POP3|RDP|SMB|LDAPS?|SNMP|NTP|DHCP|TELNET|VNC|MQTT|QUIC|KERBEROS|WINRM|SIP|RADIUS)\b/gi;
const TIME_RE = /\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b|\b\d{4}\/\d{2}\/\d{2}[ T]\d{2}:\d{2}(?::\d{2})?\b|\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b/g;
const PORT_RE = /\b(?:dport|dpt|sport|spt|port|pt)\s*[=:]?\s*(\d{1,5})\b|(?:\d{1,3}\.){3}\d{1,3}:(\d{1,5})\b|\]:(\d{1,5})\b|->\s*[\w.:\[\]]+?:(\d{1,5})\b/gi;

/* detect everything in the text, return {laneId: [{v, n}]} sorted, plus a flat count */
function padDetect(text){
  const lanes = {}; PAD_LANES.forEach(L => lanes[L.id] = new Map());
  const bump = (laneId, v, inc) => { if(!v) return; const m = lanes[laneId]; m.set(v, (m.get(v) || 0) + (inc || 1)); };
  if(text && text.trim()){
    // engine indicators
    const ents = (typeof E !== 'undefined' && E.extract) ? E.extract(text) : [];
    const count = v => { try{ return text.split(v).length - 1; }catch(e){ return 1; } };
    ents.forEach(e => { const lane = PAD_KIND2LANE[e.k]; if(lane){ bump(lane, e.v, Math.max(1, count(e.v))); }
      if(e.k === 'hostport'){ const p = e.v.slice(e.v.lastIndexOf(':') + 1); if(/^\d{1,5}$/.test(p)) bump('ports', p, 1); } });
    // ports
    let m; PORT_RE.lastIndex = 0; while((m = PORT_RE.exec(text))){ const p = m[1] || m[2] || m[3] || m[4]; if(p && +p >= 1 && +p <= 65535) bump('ports', p, 1); }
    // protocols
    PROTO_RE.lastIndex = 0; while((m = PROTO_RE.exec(text))){ bump('proto', m[1].toUpperCase().replace('HTTPS', 'HTTPS').replace(/^HTTP$/, 'HTTP'), 1); }
    // timestamps
    TIME_RE.lastIndex = 0; while((m = TIME_RE.exec(text))){ bump('time', m[0], 1); }
  }
  const out = {}; let total = 0;
  PAD_LANES.forEach(L => { const list = [...lanes[L.id].entries()].map(([v, n]) => ({v, n}));
    if(L.id === 'ports') list.sort((a, b) => (+a.v) - (+b.v)); else if(L.id === 'time') list.sort((a, b) => a.v < b.v ? -1 : 1); else list.sort((a, b) => b.n - a.n || (a.v < b.v ? -1 : 1));
    out[L.id] = list; total += list.length; });
  return {lanes: out, total};
}

function viewPad(){
  const text = UI.padText != null ? UI.padText : (DB.pad || '');
  UI.padText = text; if(!UI.padSel) UI.padSel = new Set();
  return `<div class="pad">
    <header class="pad-h"><div><span class="ix">Workspace</span><h1>Scratchpad</h1><p>Paste logs or notes — indicators are detected and grouped as you type. Select any to copy, defang or send to a case. Saved in this browser.</p></div>
      <div class="pad-ha"><button class="btn" data-act="padClear">${ico('trash-2','sm')}Clear</button></div></header>
    <div class="pad-grid">
      <div class="pad-edit"><label class="sr" for="padText">Scratchpad</label><textarea id="padText" class="pad-ta mono" spellcheck="false" placeholder="Paste a log line, a WHOIS record, a note…\n\ne.g.  2026-10-24T09:06:00Z  src=203.0.113.9 dport=4444 proto=TCP\n      c2 at update-lamp.test  sha256 e3b0c442...  CVE-2024-3400">${esc(text)}</textarea>
        <div class="pad-foot"><span id="padCount" class="t3"></span><span class="pad-hint">${ico('shield-check','sm')}Nothing leaves this browser</span></div></div>
      <aside class="pad-side"><div class="pad-side-h"><h2>Detected</h2><span id="padTotal" class="pad-total"></span></div>
        <div class="pad-bulk" id="padBulk" hidden></div>
        <div id="padEnts" class="pad-ents">${padEntsHtml()}</div></aside>
    </div></div>`;
}

function padEntsHtml(){
  const {lanes, total} = padDetect(UI.padText || '');
  if(!total) return `<div class="pad-empty">${ico('fingerprint')}<b>Nothing detected yet</b><p>Type or paste above. IPs, domains, URLs, emails, hashes, ports, protocols, timestamps, CVEs and more are picked out automatically.</p></div>`;
  const sel = UI.padSel || new Set();
  return PAD_LANES.filter(L => lanes[L.id].length).map(L => {
    const chips = lanes[L.id].map(e => { const id = L.id + '\u0001' + e.v, on = sel.has(id);
      return `<button class="pad-chip${on ? ' on' : ''}" data-act="padPick" data-v="${esc(id)}" aria-pressed="${on}" title="${esc(e.v)}"><span class="pad-chip-v">${esc(e.v)}</span>${e.n > 1 ? `<span class="pad-chip-n">${e.n}</span>` : ''}</button>`; }).join('');
    return `<section class="pad-lane"><header><span class="pad-lane-t">${ico(L.icon, 'sm')}${esc(L.name)}<span class="pad-lane-n">${lanes[L.id].length}</span></span><button class="pad-lane-c" data-act="padLaneCopy" data-v="${L.id}" title="Copy all ${esc(L.name)}">${ico('copy','sm')}</button></header><div class="pad-chips">${chips}</div></section>`;
  }).join('');
}

function padSelValues(){
  const {lanes} = padDetect(UI.padText || ''), sel = UI.padSel || new Set(), out = [];
  PAD_LANES.forEach(L => lanes[L.id].forEach(e => { if(sel.has(L.id + '\u0001' + e.v)) out.push(e.v); }));
  return out;
}
function padRefresh(){
  const e = $('padEnts'); if(e) e.innerHTML = padEntsHtml();
  const {total} = padDetect(UI.padText || ''), t = $('padTotal'); if(t) t.textContent = total ? total + ' indicator' + (total === 1 ? '' : 's') : '';
  const c = $('padCount'); if(c){ const txt = UI.padText || ''; c.textContent = txt ? (txt.length + ' char' + (txt.length === 1 ? '' : 's') + ' · ' + (txt.split('\n').length) + ' line' + (txt.split('\n').length === 1 ? '' : 's')) : ''; }
  padBulkPaint();
}
function padBulkPaint(){
  const el = $('padBulk'); if(!el) return; const n = (UI.padSel || new Set()).size;
  el.hidden = !n; if(!n) return;
  el.innerHTML = `<b>${n} selected</b><span class="pad-bulk-sp"></span><button class="btn xs" data-act="padCopy">${ico('copy','sm')}Copy</button><button class="btn xs" data-act="padDefang">${ico('shield-alert','sm')}Defang</button>${DB.cases.length ? `<button class="btn xs" data-act="padToCase">${ico('list-plus','sm')}To ${esc((theCase() || DB.cases[0]).code)}</button>` : ''}<button class="iconbtn" data-act="padSelClear" aria-label="Clear selection">${ico('x','sm')}</button>`;
}

function bindPad(){
  const ta = $('padText'); if(!ta) return;
  ta.oninput = () => { UI.padText = ta.value; DB.pad = ta.value; save(); clearTimeout(bindPad.t); bindPad.t = setTimeout(padRefresh, 180); };
  padRefresh();
}

const PAD_ACTS = {
  padPick:(id, v) => { const s = UI.padSel || (UI.padSel = new Set()); s.has(v) ? s.delete(v) : s.add(v); const btn = document.querySelector(`[data-act=padPick][data-v="${CSS.escape(v)}"]`); if(btn){ const on = s.has(v); btn.classList.toggle('on', on); btn.setAttribute('aria-pressed', on); } padBulkPaint(); },
  padSelClear:() => { UI.padSel = new Set(); padRefresh(); },
  padLaneCopy:(id, v) => { const {lanes} = padDetect(UI.padText || ''); const vals = (lanes[v] || []).map(e => e.v); if(vals.length) copyText(vals.join('\n')); },
  padCopy:() => { const v = padSelValues(); if(v.length) copyText(v.join('\n')); },
  padDefang:() => { const v = padSelValues(); if(v.length) copyText(v.map(x => (typeof defang === 'function' ? defang(x) : x)).join('\n')); },
  padClear:() => { if(!(UI.padText || '').trim()) return; confirmDlg('Clear the scratchpad?', 'This empties the note. It is not saved to any case unless you sent it there.', 'Clear', () => { UI.padText = ''; DB.pad = ''; UI.padSel = new Set(); save(); renderMain(); }); },
  padToCase:() => {
    const vals = padSelValues(); const text = UI.padText || ''; const cid = DB.active && theCase() ? DB.active : (DB.cases[0] && DB.cases[0].id);
    if(!cid) return toast('Create a case first');
    if(!text.trim()) return toast('Nothing to send');
    const ents = (typeof extractRich === 'function' ? extractRich(text) : (E.extract ? E.extract(text) : [])).filter(e => !vals.length || vals.includes(e.v));
    const r = {id:uid('r'), caseId:cid, type:'note', title:'Scratchpad — ' + (vals.length ? vals.length + ' selected indicator' + (vals.length === 1 ? '' : 's') : 'notes'), body:text,
      tsRaw:'', tsZone:'', ts:null, source:'scratchpad', host:'', tags:['scratchpad'], ents, answer:'', addedBy:'You', addedAt:Date.now(), hash:'', pv:1, att:[]};
    DB.records.push(r); mutate('scratchpad to ' + theCase(cid).code); hashRecords().then(renderAll);
    toast('Sent to ' + theCase(cid).code + ' · ' + ents.length + ' indicator' + (ents.length === 1 ? '' : 's'), 'Open', () => { UI.sel = {kind:'rec', id:r.id}; UI.inspOpen = true; go(caseHash(cid, 'timeline')); });
  }
};
