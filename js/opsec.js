/* ==========================================================================
   OPSEC, inside the app (shown on the Tradecraft page)
   · What this browser tells every site — read here, locally, nothing is sent:
     time zone, languages, screen and window, platform, WebRTC (and whether it
     gives away a local address), a canvas fingerprint, and the combinations
     that make a browser stand out. Public address: only a leak test can see it.
   · Research personas and their log — which persona looked at what, for which
     case, on which platform, when. Warns when one persona touches many cases,
     is used heavily on one subject, wakes from a long sleep, or was burned.
     No passwords are kept here.
   ========================================================================== */
const OP = {rtc:null, rtcAt:0};
const OP_CONT = {US:'America', CA:'America', MX:'America', BR:'America', AR:'America', CO:'America', CL:'America', PE:'America', VE:'America',
  GB:'Europe', IE:'Europe', DE:'Europe', FR:'Europe', ES:'Europe', IT:'Europe', NL:'Europe', BE:'Europe', PL:'Europe', UA:'Europe', RU:'Europe', SE:'Europe', NO:'Europe', FI:'Europe', DK:'Europe', PT:'Europe', AT:'Europe', CH:'Europe', CZ:'Europe', RO:'Europe', GR:'Europe', HU:'Europe', BY:'Europe', RS:'Europe', BG:'Europe', TR:'Europe',
  CN:'Asia', JP:'Asia', KR:'Asia', KP:'Asia', IN:'Asia', PK:'Asia', IR:'Asia', IL:'Asia', SA:'Asia', AE:'Asia', VN:'Asia', TH:'Asia', ID:'Asia', MY:'Asia', SG:'Asia', PH:'Asia', TW:'Asia', HK:'Asia', KZ:'Asia', BD:'Asia',
  AU:'Australia', NZ:'Pacific', ZA:'Africa', NG:'Africa', EG:'Africa', KE:'Africa', MA:'Africa'};
const OP_LANG = {ru:'Europe', uk:'Europe', de:'Europe', fr:'Europe', it:'Europe', pl:'Europe', nl:'Europe', sv:'Europe', fi:'Europe', cs:'Europe', ro:'Europe', el:'Europe', hu:'Europe', tr:'Europe',
  zh:'Asia', ja:'Asia', ko:'Asia', hi:'Asia', fa:'Asia', he:'Asia', vi:'Asia', th:'Asia', id:'Asia', ms:'Asia', bn:'Asia', ur:'Asia'};
function opFacts(){
  const n = navigator, tz = (() => { try{ return Intl.DateTimeFormat().resolvedOptions().timeZone || ''; }catch(e){ return ''; } })(), langs = [...(n.languages || [n.language || ''])].filter(Boolean);
  const off = -new Date().getTimezoneOffset(), offS = 'UTC' + (off >= 0 ? '+' : '−') + String(Math.floor(Math.abs(off) / 60)).padStart(2, '0') + ':' + String(Math.abs(off) % 60).padStart(2, '0');
  const W = window.innerWidth, H = window.innerHeight, letter = W % 200 === 0 && H % 100 === 0;
  let canvas = ''; try{ const c = document.createElement('canvas'); c.width = 220; c.height = 30; const g = c.getContext('2d'); g.textBaseline = 'top'; g.font = '14px Arial'; g.fillStyle = '#f60'; g.fillRect(100, 1, 62, 20); g.fillStyle = '#069'; g.fillText('OSINTrix fingerprint ✓', 2, 15);
    const d = c.toDataURL(); canvas = E.sha1([...d].map(ch => ch.charCodeAt(0) & 255)).slice(0, 12); }catch(e){ canvas = ''; }
  return {tz, offS, langs, lang:langs[0] || '', screen:`${screen.width} × ${screen.height}`, dpr:window.devicePixelRatio || 1, win:`${W} × ${H}`, letter, plat:(n.userAgentData && n.userAgentData.platform) || n.platform || '', ua:n.userAgent || '',
    cores:n.hardwareConcurrency || 0, mem:n.deviceMemory || 0, rtc:typeof RTCPeerConnection !== 'undefined', cookies:n.cookieEnabled, gpc:!!n.globalPrivacyControl, dnt:n.doNotTrack === '1', canvas};
}
/* WebRTC with no servers: the browser lists its own local candidates without sending anything. A raw private address here is
   what any page can read; modern browsers show a random name ending in .local instead. */
function opRtcProbe(){
  if(OP.rtc || typeof RTCPeerConnection === 'undefined') return; OP.rtc = {state:'probing'};
  let pc; try{ pc = new RTCPeerConnection({iceServers:[]}); }catch(e){ OP.rtc = {state:'blocked'}; return; }
  const ips = new Set(), mdns = new Set(); const done = () => { try{ pc.close(); }catch(e){} OP.rtc = {state:'done', ips:[...ips], mdns:mdns.size}; if(UI.route.area === 'tradecraft') renderMain(); };
  pc.onicecandidate = ev => { if(!ev.candidate){ done(); return; } const c = ev.candidate.candidate || '', m = / (\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f:]{6,}|[\w-]+\.local) \d+ typ /i.exec(c); if(m){ if(/\.local$/i.test(m[1])) mdns.add(m[1]); else ips.add(m[1]); } };
  try{ pc.createDataChannel('x'); pc.createOffer().then(o => pc.setLocalDescription(o)).catch(() => { OP.rtc = {state:'blocked'}; }); }catch(e){ OP.rtc = {state:'blocked'}; }
  setTimeout(() => { if(OP.rtc && OP.rtc.state === 'probing') done(); }, 2500);
}
/* a time zone's country, for the zones most people are in — enough to see a language that does not fit */
const OP_TZ = {'Europe/London':'GB', 'Europe/Dublin':'IE', 'Europe/Berlin':'DE', 'Europe/Paris':'FR', 'Europe/Madrid':'ES', 'Europe/Rome':'IT', 'Europe/Amsterdam':'NL', 'Europe/Brussels':'BE', 'Europe/Warsaw':'PL', 'Europe/Kiev':'UA', 'Europe/Kyiv':'UA', 'Europe/Moscow':'RU',
  'Europe/Stockholm':'SE', 'Europe/Oslo':'NO', 'Europe/Helsinki':'FI', 'Europe/Copenhagen':'DK', 'Europe/Lisbon':'PT', 'Europe/Vienna':'AT', 'Europe/Zurich':'CH', 'Europe/Prague':'CZ', 'Europe/Bucharest':'RO', 'Europe/Athens':'GR', 'Europe/Budapest':'HU', 'Europe/Minsk':'BY', 'Europe/Istanbul':'TR', 'Europe/Belgrade':'RS', 'Europe/Sofia':'BG',
  'America/New_York':'US', 'America/Chicago':'US', 'America/Denver':'US', 'America/Los_Angeles':'US', 'America/Phoenix':'US', 'America/Toronto':'CA', 'America/Vancouver':'CA', 'America/Mexico_City':'MX', 'America/Sao_Paulo':'BR', 'America/Argentina/Buenos_Aires':'AR', 'America/Bogota':'CO', 'America/Santiago':'CL', 'America/Lima':'PE', 'America/Caracas':'VE',
  'Asia/Shanghai':'CN', 'Asia/Tokyo':'JP', 'Asia/Seoul':'KR', 'Asia/Pyongyang':'KP', 'Asia/Kolkata':'IN', 'Asia/Calcutta':'IN', 'Asia/Karachi':'PK', 'Asia/Tehran':'IR', 'Asia/Jerusalem':'IL', 'Asia/Riyadh':'SA', 'Asia/Dubai':'AE', 'Asia/Ho_Chi_Minh':'VN', 'Asia/Bangkok':'TH', 'Asia/Jakarta':'ID', 'Asia/Kuala_Lumpur':'MY', 'Asia/Singapore':'SG', 'Asia/Manila':'PH', 'Asia/Taipei':'TW', 'Asia/Hong_Kong':'HK', 'Asia/Almaty':'KZ', 'Asia/Dhaka':'BD',
  'Australia/Sydney':'AU', 'Australia/Melbourne':'AU', 'Pacific/Auckland':'NZ', 'Africa/Johannesburg':'ZA', 'Africa/Lagos':'NG', 'Africa/Cairo':'EG', 'Africa/Nairobi':'KE', 'Africa/Casablanca':'MA'};
/* where a language without a region is mostly spoken; English, Spanish, Arabic and Portuguese are too widespread to judge */
const OP_LANGCC = {ru:['RU', 'BY', 'KZ', 'UA'], uk:['UA'], de:['DE', 'AT', 'CH'], fr:['FR', 'BE', 'CH', 'CA', 'MA'], it:['IT', 'CH'], pl:['PL'], nl:['NL', 'BE'], sv:['SE', 'FI'], fi:['FI'], cs:['CZ'], ro:['RO'], el:['GR'], hu:['HU'], tr:['TR'], da:['DK'], nb:['NO'], no:['NO'],
  zh:['CN', 'TW', 'HK', 'SG'], ja:['JP'], ko:['KR', 'KP'], fa:['IR'], he:['IL'], vi:['VN'], th:['TH'], id:['ID'], ms:['MY', 'SG'], bn:['BD', 'IN'], ur:['PK', 'IN'], hi:['IN']};
function opFindings(F){
  const out = [], torish = F.tz === 'UTC' && /^en(-US)?$/.test(F.lang) && F.letter;
  if(torish) out.push(['good', 'Looks like Tor Browser (or Firefox resisting fingerprinting)', 'UTC time zone, English, window in fixed steps — the same as many others.']);
  if(F.rtc){ const R = OP.rtc || {}; if(R.state === 'done' && R.ips.length) out.push(['bad', 'WebRTC gives away a local address: ' + R.ips.join(', '), 'Any page can read it without asking. Turn WebRTC off (Firefox: media.peerconnection.enabled = false) and check again.']);
    else out.push(['warn', 'WebRTC is on', R.state === 'done' ? 'Local addresses are hidden behind random .local names here, but through a VPN WebRTC can still reveal your public address to a page that asks a server. Turn it off for research.' : 'Through a VPN it can reveal your real address. Turn it off for research.']); }
  else out.push(['good', 'WebRTC is off', 'Pages cannot use it to learn your addresses.']);
  const lr = (/-([A-Z]{2})$/.exec(F.lang) || [])[1], base = F.lang.split('-')[0].toLowerCase(), tcc = OP_TZ[F.tz], tc = F.tz.split('/')[0];
  let fits = true;
  if(tcc) fits = lr ? lr === tcc || (OP_LANGCC[base] || []).includes(tcc) : OP_LANGCC[base] ? OP_LANGCC[base].includes(tcc) : true;
  else { const lc = lr ? OP_CONT[lr] : OP_LANG[base]; fits = !lc || !tc || tc === 'UTC' || tc === 'Etc' || lc === tc; }
  if(!fits) out.push(['warn', `Language ${F.lang} with time zone ${F.tz}`, 'An unusual pair that every site sees — a ' + F.lang + ' browser set to ' + F.tz.split('/').pop().replace(/_/g, ' ') + ' time. Fine if it fits the persona; a fingerprint if not.']);
  if(F.langs.length >= 3) out.push(['warn', F.langs.length + ' languages listed', 'Every site receives the list. Few people have three or more — it narrows you down.']);
  if(!torish && F.tz && F.tz !== 'UTC') out.push(['info', 'Time zone ' + F.tz + ' (' + F.offS + ')', 'Sent to every page that asks and stamped on what you post. Set the VM to the persona’s zone, or UTC.']);
  if(F.dpr > 1 && !torish) out.push(['info', 'High-density screen (×' + F.dpr + ')', 'Together with screen size this narrows the device down — common on laptops and phones, rarer on research VMs.']);
  if(F.gpc || F.dnt) out.push(['info', (F.gpc ? 'Global Privacy Control' : 'Do Not Track') + ' is on', 'Honest, but it is one more bit that sets you apart.']);
  return out;
}
function opExposureHtml(){
  const F = opFacts(); opRtcProbe(); const L = opFindings(F);
  const row = (k, v) => `<div><dt>${k}</dt><dd>${v}</dd></div>`;
  return `<section class="op-x" id="opX"><header><h2>${ico('eye','sm')}What this browser tells every site</h2><span class="t3 small">read here, nothing sent</span></header>
    <div class="op-xg"><dl class="op-kv">${row('Time zone', esc(F.tz || '—') + ' · ' + esc(F.offS))}${row('Languages', esc(F.langs.join(', ') || '—'))}${row('Screen', esc(F.screen) + (F.dpr !== 1 ? ' ×' + F.dpr : ''))}${row('Window', esc(F.win) + (F.letter ? ' <span class="t3">· in fixed steps</span>' : ''))}${row('Platform', esc(F.plat || '—'))}${F.cores ? row('Processor threads', F.cores + (F.mem ? ' · ' + F.mem + ' GB memory' : '')) : ''}${row('WebRTC', F.rtc ? 'on' : 'off')}${row('Canvas fingerprint', F.canvas ? `<span class="mono">${F.canvas}</span> <span class="t3">· the same on every site unless your browser varies it</span>` : 'blocked')}</dl>
    <ul class="op-f">${L.map(([l, t, w]) => `<li class="${l}"><span class="op-i">${ico(l === 'bad' ? 'shield-alert' : l === 'warn' ? 'triangle-alert' : l === 'good' ? 'check' : 'info','sm')}</span><div><b>${esc(t)}</b><small>${esc(w)}</small></div></li>`).join('')}</ul></div>
    <p class="t3 small op-note">Your public address cannot be seen from inside the page without contacting a server — check it on browserleaks.com or dnsleaktest.com from the research environment. How rare this combination is needs a large sample: coveryourtracks.eff.org measures it.</p>
    <p class="op-clean"><button class="btn sm" data-act="opClean">${ico('eraser','sm')}Clean a file before sending it</button><span class="t3 small">Photos and documents carry your camera, location, name, company and folders — take them out first.</span></p></section>`;
}
/* what the readiness check can confirm by itself */
function opReadyHint(id){ const F = opFacts();
  if(id === 'webrtc') return F.rtc ? (OP.rtc && OP.rtc.ips && OP.rtc.ips.length ? '<em class="bad">This browser: WebRTC on, local address visible</em>' : '<em class="warn">This browser: WebRTC on</em>') : '<em class="good">This browser: WebRTC off</em>';
  if(id === 'tz') return `<em>This browser: ${esc(F.tz || '?')}, ${esc(F.lang || '?')}</em>`;
  return ''; }

/* ---------- research personas and their log ---------- */
function opDB(){ const P = DB.personas = DB.personas && typeof DB.personas === 'object' && !Array.isArray(DB.personas) ? DB.personas : {}; if(!Array.isArray(P.list)) P.list = []; if(!Array.isArray(P.log)) P.log = []; return P; }
function pnClean(P){ if(!P || typeof P !== 'object' || Array.isArray(P)) return undefined; const s = (v, n) => typeof v === 'string' ? v.slice(0, n) : '', num = v => Number.isFinite(+v) ? +v : 0, id = v => typeof v === 'string' && /^[\w-]{1,60}$/.test(v) ? v : '';
  return {list:(Array.isArray(P.list) ? P.list : []).filter(x => x && id(x.id)).slice(0, 500).map(x => ({id:x.id, name:s(x.name, 120) || 'Persona', plat:s(x.plat, 300), egress:s(x.egress, 120), notes:s(x.notes, 2000), at:num(x.at), ...(x.burned && typeof x.burned === 'object' ? {burned:{at:num(x.burned.at), why:s(x.burned.why, 400)}} : {})})),
    log:(Array.isArray(P.log) ? P.log : []).filter(x => x && id(x.id) && id(x.p)).slice(-20000).map(x => ({id:x.id, p:x.p, c:id(x.c), at:num(x.at), plat:s(x.plat, 80), what:s(x.what, 600), url:s(x.url, 800)}))}; }
const opUses = id => opDB().log.filter(x => x.p === id);
function opWarn(p){
  const U = opUses(p.id), cases = new Set(U.map(x => x.c).filter(Boolean)), now = Date.now(), out = [];
  if(p.burned) out.push(['bad', 'Burned ' + E.fmtDate(p.burned.at, tz()) + (p.burned.why ? ' — ' + p.burned.why : ''), 'Do not use it again, and reuse none of its details.']);
  if(cases.size >= 3) out.push(['warn', 'Used on ' + cases.size + ' cases', 'If it is burned on one subject, every case it touched is exposed with it. Keep personas to one investigation where you can.']);
  const wk = new Map(); for(const u of U.filter(x => now - x.at < 7 * 864e5)) wk.set(u.c, (wk.get(u.c) || 0) + 1);
  for(const [c, n] of wk) if(n >= 10) out.push(['warn', n + ' uses on ' + (theCase(c) ? caseNm(theCase(c), 30) : 'one case') + ' this week', 'Heavy, repeated viewing of one subject is a pattern platforms and subjects notice.']);
  const last = U.length ? Math.max(...U.map(x => x.at)) : p.at; if(!p.burned && last && now - last > 60 * 864e5) out.push(['info', 'Asleep for ' + Math.round((now - last) / 864e5) + ' days', 'Accounts that wake up and go straight to a target draw checks. Use it normally for a while first.']);
  return out;
}
function opPersonasHtml(){
  const P = opDB(), L = P.list.slice().sort((a, b) => !!a.burned - !!b.burned || (Math.max(0, ...opUses(b.id).map(x => x.at)) - Math.max(0, ...opUses(a.id).map(x => x.at)))), recent = P.log.slice(-8).reverse();
  return `<section class="op-p" id="opP"><header><h2>${ico('user','sm')}Your research personas</h2><span class="t3 small">which persona looked at what, for which case — no passwords kept here</span>
      <span class="sp"></span><button class="btn sm" data-act="opNew">${ico('plus','sm')}New persona</button>${P.list.some(p => !p.burned) ? `<button class="btn sm primary" data-act="opLog">${ico('list-plus','sm')}Log a use</button>` : ''}</header>
    ${L.length ? `<div class="op-pl">${L.map(p => { const U = opUses(p.id), W = opWarn(p), cs = new Set(U.map(x => x.c).filter(Boolean)), last = U.length ? Math.max(...U.map(x => x.at)) : 0;
      return `<article class="op-pc${p.burned ? ' burned' : ''}"><div class="op-ph"><b>${esc(p.name)}</b>${p.burned ? '<span class="op-burn">Burned</span>' : ''}<span class="sp"></span>${p.burned ? '' : `<button class="btn xs" data-act="opLog" data-id="${p.id}">Log a use</button><button class="btn xs ghost" data-act="opBurn" data-id="${p.id}">Burn…</button>`}</div>
        <small>${esc([p.plat, p.egress ? 'exits ' + p.egress : ''].filter(Boolean).join(' · ') || 'No platforms noted')}</small>
        <div class="op-ps">${U.length} use${U.length === 1 ? '' : 's'} · ${cs.size} case${cs.size === 1 ? '' : 's'}${last ? ' · last ' + esc(E.fmtAgo(Date.now() - last)) : ' · not used yet'}</div>
        ${W.length ? `<ul class="op-f">${W.map(([l, t, w]) => `<li class="${l}"><span class="op-i">${ico(l === 'bad' ? 'shield-alert' : l === 'warn' ? 'triangle-alert' : 'info','sm')}</span><div><b>${esc(t)}</b><small>${esc(w)}</small></div></li>`).join('')}</ul>` : ''}</article>`; }).join('')}</div>` : '<p class="t3">No personas yet. Add each research account you use — its name and platforms only — then log what it is used for.</p>'}
    ${recent.length ? `<h3 class="op-h3">Latest uses</h3><ul class="op-log">${recent.map(u => { const p = P.list.find(x => x.id === u.p); return `<li><span class="mono t3">${esc(E.fmtDate(u.at, tz()))}</span><b>${esc(p ? p.name : '?')}</b><span>${esc(u.plat || '')}</span><span class="t2">${esc(u.what)}</span>${u.c && theCase(u.c) ? `<a href="${caseHash(u.c)}">${esc(caseNm(theCase(u.c), 26))}</a>` : '<span></span>'}</li>`; }).join('')}</ul>` : ''}</section>`;
}
function opNewDlg(){
  openDlg(dhead('New research persona') + `<div class="in"><div class="field"><label for="opN">Name it goes by</label><input id="opN" maxlength="120" required placeholder="e.g. marta.k (Instagram)"></div>
    <div class="field"><label for="opPl">Platforms it has accounts on</label><input id="opPl" maxlength="300" placeholder="Instagram, Telegram, Dread"></div><div class="field"><label for="opEg">Where it connects from</label><input id="opEg" maxlength="120" placeholder="NL residential, Tor, VPN Frankfurt…"></div>
    <div class="field"><label for="opNo">Notes</label><textarea id="opNo" rows="3" maxlength="2000" placeholder="Backstory in a line, which VM or browser profile, when it was made. Never passwords."></textarea></div></div>
    <footer><button class="btn" data-act="dclose">Cancel</button><button class="btn primary" data-act="opNewSave">Add persona</button></footer>`); setTimeout(() => $('opN') && $('opN').focus(), 30);
}
function opLogDlg(pid){
  const P = opDB(), live = P.list.filter(p => !p.burned); if(!live.length) return opNewDlg();
  const plats = [...new Set(P.list.flatMap(p => p.plat.split(/\s*,\s*/)).filter(Boolean))];
  openDlg(dhead('Log a persona use') + `<div class="in"><div class="field"><label for="opLp">Persona</label><select id="opLp">${live.map(p => `<option value="${p.id}"${p.id === pid ? ' selected' : ''}>${esc(p.name)}</option>`).join('')}</select></div>
    <div class="field"><label for="opLc">Case</label><select id="opLc"><option value="">— none —</option>${DB.cases.filter(c => !c.stash).map(c => `<option value="${c.id}"${c.id === DB.active ? ' selected' : ''}>${esc(caseNm(c))}</option>`).join('')}</select></div>
    <div class="field"><label for="opLpl">Platform</label><input id="opLpl" list="opPlats" maxlength="80"><datalist id="opPlats">${plats.map(x => `<option value="${esc(x)}">`).join('')}</datalist></div>
    <div class="field"><label for="opLw">What you looked at</label><input id="opLw" maxlength="600" required placeholder="Viewed @subject's followers list; saved 3 posts"></div>
    <div class="field"><label for="opLu">Address (optional)</label><input id="opLu" maxlength="800" placeholder="https://…"></div></div>
    <footer><button class="btn" data-act="dclose">Cancel</button><button class="btn primary" data-act="opLogSave">Log it</button></footer>`); setTimeout(() => $('opLw') && $('opLw').focus(), 30);
}
const OP_ACTS = {
  opNew:() => opNewDlg(),
  opNewSave:() => { const n = ($('opN').value || '').trim(); if(!n) return $('opN').focus(); const P = opDB(); if(P.list.some(p => p.name.toLowerCase() === n.toLowerCase())) return toast('You already have a persona called ' + n);
    P.list.push({id:uid('pn'), name:n.slice(0, 120), plat:($('opPl').value || '').trim().slice(0, 300), egress:($('opEg').value || '').trim().slice(0, 120), notes:($('opNo').value || '').slice(0, 2000), at:Date.now()}); mutate('added a research persona'); closeDlg(); renderMain(); },
  opLog:id => opLogDlg(id),
  opLogSave:() => { const w = ($('opLw').value || '').trim(); if(!w) return $('opLw').focus(); const P = opDB(), p = P.list.find(x => x.id === $('opLp').value); if(!p) return;
    P.log.push({id:uid('pl'), p:p.id, c:$('opLc').value || '', at:Date.now(), plat:($('opLpl').value || '').trim().slice(0, 80), what:w.slice(0, 600), url:($('opLu').value || '').trim().slice(0, 800)}); mutate('logged a persona use'); closeDlg(); renderMain();
    const W = opWarn(p).filter(x => x[0] !== 'info'); toast(W.length ? 'Logged — ' + W[0][1].toLowerCase() : 'Logged'); },
  opBurn:id => { const p = opDB().list.find(x => x.id === id); if(!p) return; openDlg(dhead('Burn ' + esc(p.name) + '?') + `<div class="in"><p style="margin:0 0 10px">A burned persona is kept in the log as a record, and flagged so it is never used again.</p><div class="field"><label for="opBw">What happened</label><input id="opBw" maxlength="400" placeholder="Subject blocked it; platform asked for ID…"></div></div>
    <footer><button class="btn" data-act="dclose">Cancel</button><button class="btn danger" data-act="opBurnOk" data-id="${p.id}">Burn it</button></footer>`); },
  opBurnOk:id => { const p = opDB().list.find(x => x.id === id); if(!p) return; p.burned = {at:Date.now(), why:($('opBw').value || '').trim().slice(0, 400)}; const cs = new Set(opUses(p.id).map(x => x.c).filter(Boolean)); mutate('burned a research persona'); closeDlg(); renderMain();
    toast(cs.size > 1 ? `${p.name} burned — it touched ${cs.size} cases; check each for exposure` : p.name + ' burned'); },
};
