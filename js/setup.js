/* ==========================================================================
   First-run setup — two minutes to a working investigation desk.
     1. How OSINTrix uses the internet: offline, free sources, or free + your relay
     2. Lookup sources: which services may see the indicators you investigate
     3. Your relay (only if chosen): address, token, test
     4. Threat intel: news, known-exploited CVEs, exploit odds, CVE records, ATT&CK
     5. Protect and start: a passphrase, and where to begin
   Nothing is switched on without a click here. Re-run any time from Settings.
   ========================================================================== */
const SU = {step:0, mode:''};
const SU_STEPS = ['Internet', 'Lookups', 'Relay', 'Threat intel', 'Start'];
function setupOpen(step){ SU.step = step || 0; SU.mode = SU.mode || (LK_PROVIDERS.some(lkOn) ? (lkRelay() ? 'relay' : 'free') : ''); setupPaint(); }
function setupPaint(){
  const S = lkSettings(), st = SU.step, skipRelay = SU.mode !== 'relay';
  const dots = `<ol class="su-dots" aria-label="Setup steps">${SU_STEPS.map((l, i) => `<li class="${i < st ? 'done' : i === st ? 'cur' : ''}${i === 2 && skipRelay ? ' skip' : ''}"${i === st ? ' aria-current="step"' : ''}><i>${i < st ? ico('check','sm') : i + 1}</i><span>${l}</span></li>`).join('')}</ol>`;
  let body = '', next = 'Continue', canNext = true;
  if(st === 0){
    const card = (k, icon, t, d, rec) => `<button type="button" class="su-card" data-act="suMode" data-v="${k}" aria-pressed="${SU.mode === k}">${ico(icon)}<b>${t}${rec ? ' <span class="chip sq green">recommended</span>' : ''}</b><span>${d}</span></button>`;
    body = `<h2>How should OSINTrix use the internet?</h2><p class="t2">Your cases, evidence and files never leave this browser. What changes is whether the indicators you <i>choose to investigate</i> may be looked up online — and only with the services you pick next.</p>
      <div class="su-cards">${card('off', 'wifi-off', 'Offline only', 'Nothing is ever sent. Analysis, graphs, reports and the forensics kit all still work; verdicts come only from you.')}
        ${card('free', 'globe', 'Free sources', 'DNS, registration data, Shodan InternetDB, certificate logs, AlienVault OTX and more — no accounts, no keys. Asked only when you investigate.', true)}
        ${card('relay', 'server', 'Free sources + my relay', 'Adds VirusTotal, AbuseIPDB, GreyNoise, urlscan and abuse.ch through a small Cloudflare Worker you run, which keeps your API keys.')}</div>`;
    canNext = !!SU.mode;
  } else if(st === 1){
    const P = LK_PROVIDERS.filter(p => p.via === 'direct' || (SU.mode === 'relay' && p.via !== 'direct'));
    body = `<h2>Which services may see what you investigate?</h2><p class="t2">Only the indicator you investigate is sent — an IP, a domain, a hash — and only to the services ticked here. You can change this any time in Threat Intel → Sources.</p>
      <div class="wrap" style="margin:0 0 10px"><button class="btn sm" data-act="suAll" data-v="1">Tick all</button><button class="btn sm ghost" data-act="suAll" data-v="0">Untick all</button></div>
      <div class="su-list">${P.map(p => `<label class="su-row"><input type="checkbox" data-act="suProv" data-id="${p.id}" ${S.on[p.id] ? 'checked' : ''}><div><b>${esc(p.name)}</b><small>${esc(p.about)}</small><small class="mono t3">${p.via === 'relay' ? 'through your relay → ' : ''}${esc(p.host)}</small></div></label>`).join('')}</div>`;
  } else if(st === 2){
    const r = S.relay;
    body = `<h2>Connect your relay</h2><p class="t2">The relay is a tiny Cloudflare Worker in your own account (free plan). It holds your API keys and reaches the services that refuse browsers. The steps are in <span class="mono">tools/relay/README.md</span> of the OSINTrix repository — about five minutes. You can also skip this and add it later.</p>
      <div class="field"><label for="suRU">Relay address</label><input id="suRU" class="inp mono" type="url" data-lkrelay="url" value="${esc(r.url || '')}" placeholder="https://osintrix-relay.you.workers.dev" autocomplete="off" spellcheck="false"></div>
      <div class="field"><label for="suRT">Relay token</label><input id="suRT" class="inp" type="password" data-lkrelay="token" value="${esc(r.token || '')}" placeholder="the RELAY_TOKEN you set" autocomplete="off"></div>
      <div class="wrap"><button class="btn sm" data-act="suRelayTest">${ico('activity','sm')}Test relay</button><span id="lkRelayRes" class="t3 small" role="status"></span></div>`;
    next = r.url ? 'Continue' : 'Skip for now';
  } else if(st === 3){
    const src = id => ctiSrc(id), row = (id, t, d) => { const s = src(id); return s ? `<label class="su-row"><input type="checkbox" data-act="suSrc" data-id="${id}" ${s.on ? 'checked' : ''}><div><b>${t}</b><small>${d}</small><small class="mono t3">${esc(s.host)}</small></div></label>` : ''; };
    body = `<h2>Keep up with threats</h2><p class="t2">These download public data — nothing about your cases is sent. Each is fetched when you press Refresh in Threat Intel.</p>
      <div class="su-list"><label class="su-row"><input type="checkbox" data-act="suNews" ${DB.prefs.liveFeeds ? 'checked' : ''}><div><b>Security news</b><small>Advisories and research from CISA, NCSC, Talos, Unit 42 and others, read for CVEs, actors and indicators, and ranked for you.</small><small class="mono t3">api.rss2json.com (feed addresses only)</small></div></label>
        ${row('kev', 'Known exploited vulnerabilities', 'CISA\'s catalog of CVEs attackers are using, checked against your stack and cases.')}
        ${row('epss', 'Exploit probability (EPSS)', 'How likely each CVE is to be exploited in the next 30 days.')}
        ${row('nvd', 'CVE records', 'The official record for a CVE when you open it, with CISA\'s exploitation assessment.')}
        ${row('attack', 'MITRE ATT&CK updates', 'The latest groups, software and techniques, checked at most weekly (about 45 MB).')}</div>`;
  } else {
    const locked = typeof SEC !== 'undefined' && SEC.key, on = LK_PROVIDERS.filter(lkOn).length;
    body = `<h2>You are set up</h2>
      <ul class="su-sum"><li>${ico(on ? 'globe' : 'wifi-off','sm')}${on ? on + ' lookup source' + (on > 1 ? 's' : '') + ' on' + (lkRelay() ? ', relay connected' : '') : 'Offline — no lookups'}</li>
        <li>${ico('rss','sm')}${DB.prefs.liveFeeds ? 'Security news on' : 'Security news off'} · ${['kev', 'epss', 'nvd', 'attack'].filter(id => ctiSrc(id) && ctiSrc(id).on).length} threat-data sources</li>
        <li>${ico('hard-drive-download','sm')}${typeof fbOn === 'function' && fbOn() ? 'Backing up to “' + esc(fbGet().name) + '”' : 'No automatic backup yet'}</li>
        <li>${ico(locked ? 'lock' : 'lock-open','sm')}${locked ? 'Workspace encrypted' : 'Not encrypted yet — anyone with this browser profile can read your cases'}</li></ul>
      ${typeof fbSupported === 'function' && fbSupported() && !fbOn() ? `<div class="note"><span class="ic">${ico('hard-drive-download','sm')}</span><div><b>Keep a backup without thinking about it.</b> Pick a folder (Documents, or a OneDrive or Google Drive folder) and OSINTrix saves a copy there a few minutes after each change. <button class="btn xs" data-act="fbChoose">${ico('folder-open','sm')}Choose a folder</button></div></div>` : ''}
      ${locked ? '' : `<div class="note amber"><span class="ic">${ico('key-round','sm')}</span><div><b>Protect your cases with a passphrase.</b> Evidence, keys and lookups are then encrypted in this browser. <button class="btn xs" data-act="suLock">Set a passphrase</button></div></div>`}
      <h3>Where to start</h3><div class="su-cards">
        <button type="button" class="su-card" data-act="suGo" data-v="demo">${ico('sparkles')}<b>Take the guided tour</b><span>Eight stops through Op Lantern, a finished case: the copilot, patterns in the timeline, the graph, media and automations.</span></button>
        <button type="button" class="su-card" data-act="suGo" data-v="look">${ico('radar')}<b>Investigate an indicator</b><span>Paste an IP, domain, hash or CVE and get one verdict from every source.</span></button>
        <button type="button" class="su-card" data-act="suGo" data-v="new">${ico('folder-plus')}<b>Open your own case</b><span>Name it, then press N and paste evidence — indicators come out on their own.</span></button></div>`;
    next = 'Finish';
  }
  openDlg(dhead('Set up OSINTrix') + `<div class="in su">${dots}${body}</div>
    <footer>${st ? `<button class="btn ghost" data-act="suBack" style="margin-right:auto">${ico('arrow-left','sm')}Back</button>` : `<button class="btn ghost" data-act="suLater" style="margin-right:auto">Later</button>`}
      <button class="btn primary" data-act="suNext" ${canNext ? '' : 'disabled'}>${esc(next)}${st < 4 ? ico('arrow-right','sm') : ''}</button></footer>`, true);
}
function setupStep(d){ let s = SU.step + d; if(s === 2 && SU.mode !== 'relay') s += d; if(s === 1 && SU.mode === 'off') s += d; if(s === 2 && SU.mode === 'off') s += d; SU.step = Math.max(0, Math.min(4, s)); setupPaint(); }
function setupDone(){ DB.prefs.setupDone = Date.now(); mutate('finished setup'); closeDlg(); renderAll(); }
const SU_ACTS = {
  setupOpen:() => setupOpen(0),
  suMode:(id, v) => { SU.mode = v; const S = lkSettings();
    if(v === 'off') S.on = {}; else { LK_PROVIDERS.filter(p => p.via === 'direct').forEach(p => { if(S.on[p.id] == null) S.on[p.id] = true; }); if(v === 'relay') LK_PROVIDERS.filter(p => p.via !== 'direct').forEach(p => { if(S.on[p.id] == null) S.on[p.id] = true; }); else LK_PROVIDERS.filter(p => p.via === 'relay').forEach(p => delete S.on[p.id]); }
    save(); setupPaint(); },
  suProv:(id, v, t) => { const S = lkSettings(); if(t.checked) S.on[id] = true; else delete S.on[id]; save(); },
  suAll:(id, v) => { const S = lkSettings(); LK_PROVIDERS.filter(p => p.via === 'direct' || SU.mode === 'relay').forEach(p => { if(v === '1') S.on[p.id] = true; else delete S.on[p.id]; }); save(); setupPaint(); },
  suSrc:(id, v, t) => { ctiEnsure(); let s = DB.intel.sources.find(x => x.id === id); if(!s){ s = {id, on:false}; DB.intel.sources.push(s); } s.on = t.checked; save(); },
  suNews:(id, v, t) => { DB.prefs.liveFeeds = t.checked; save(); },
  suRelayTest:() => lkRelayTest(),
  suBack:() => setupStep(-1), suNext:() => SU.step >= 4 ? setupDone() : setupStep(1),
  suLater:() => { DB.prefs.setupLater = Date.now(); save(); closeDlg(); renderAll(); },
  suLock:() => { setupDone(); go('#/security'); },
  suGo:(id, v) => { setupDone(); if(v === 'demo' && theCase('c-lantern')) setTimeout(tourStart, 80); else if(v === 'look'){ UI.itab = 'look'; UI.look = null; go('#/feeds'); } else { go('#/cases'); setTimeout(() => typeof caseDlg === 'function' && caseDlg(), 60); } },
  setupHide:() => { DB.prefs.setupLater = Date.now(); save(); renderMain(); },
};
/* a gentle nudge on the dashboard until setup is done or put off */
function setupBanner(){
  if(DB.prefs.setupDone || (DB.prefs.setupLater && Date.now() - DB.prefs.setupLater < 14 * 864e5)) return '';
  return `<div class="note accent su-ban"><span class="ic">${ico('sparkles','sm')}</span><div><b>Two minutes to a smarter workspace.</b> Choose which free sources may check indicators, switch on threat news and protect your cases.</div><button class="btn sm primary" data-act="setupOpen">Set up</button><button class="iconbtn" data-act="setupHide" aria-label="Not now">${ico('x','sm')}</button></div>`;
}
