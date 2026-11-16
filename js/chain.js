/* ==========================================================================
   Attack chain — a case's events in ATT&CK order (Timeline → Chain).
   Each event is placed on the stages it shows, from: technique IDs in the
   evidence, what the evidence reader recognises (encoded PowerShell, a
   disguised attachment, cleared logs…), tags like "persistence", and your
   Sigma rules that fire on it. Empty stages say what to look for next.
   ========================================================================== */
const CH_TAGS = [[/^(recon|reconnaissance|scan(ning)?)$/, 'reconnaissance'], [/^(infra|infrastructure|resource-development)$/, 'resource-development'], [/^(phish(ing)?|lure|initial-access|delivery|exploit)$/, 'initial-access'],
  [/^(execution|exec|encoded|powershell|macro|script)$/, 'execution'], [/^(persistence|autorun|scheduled-task|service)$/, 'persistence'], [/^(privesc|privilege-escalation|uac)$/, 'privilege-escalation'],
  [/^(defense-evasion|evasion|masquerade|obfuscation|stealth)$/, 'stealth'], [/^(anti-forensics|log-clearing|defense-impairment|av-tamper)$/, 'defense-impairment'], [/^(credential(s)?|credential-access|mimikatz|lsass|kerberoast(ing)?|password-spray)$/, 'credential-access'],
  [/^(discovery|enum(eration)?)$/, 'discovery'], [/^(lateral(-movement)?|psexec|rdp|smb)$/, 'lateral-movement'], [/^(collection|staging|archive)$/, 'collection'],
  [/^(c2|command-and-control|beacon(ing)?|download)$/, 'command-and-control'], [/^(exfil(tration)?|data-theft|upload)$/, 'exfiltration'], [/^(impact|ransom(ware)?|wiper|encrypt(ion)?|defacement)$/, 'impact']];
const CH_LOOK = {'reconnaissance':'Scans of your perimeter, searches for your staff, lookups of your domains.', 'resource-development':'Registered look-alike domains, new certificates, hosting the attacker set up.',
  'initial-access':'The phishing email, the exploited service, the stolen login — how they got in.', 'execution':'Process creation (Sysmon 1 / 4688): scripts, LOLBins, Office spawning shells.',
  'persistence':'Run keys, scheduled tasks, services, WMI subscriptions, new accounts.', 'privilege-escalation':'UAC bypass, token theft, vulnerable drivers, new admin group members.',
  'defense-evasion':'Cleared logs, disabled AV, masquerading binaries, encoded commands.', 'stealth':'Masquerading binaries, encoded or obfuscated commands, hidden files and processes, signed-binary proxy execution.', 'defense-impairment':'Cleared or stopped logs, disabled antivirus or EDR, tampered audit policy, firewall changes.', 'credential-access':'LSASS access, SAM/NTDS copies, Kerberoasting, password spraying.',
  'discovery':'whoami, net, nltest, AD queries, network scans from inside.', 'lateral-movement':'RDP, SMB/admin shares, PsExec, WinRM, logons type 3 and 10 to other hosts.',
  'collection':'Archives being made (7z, rar), mailbox exports, file share crawling.', 'command-and-control':'Regular beacons, rare domains, unusual ports, DNS tunnelling.',
  'exfiltration':'Large uploads, cloud storage clients, transfers out over C2.', 'impact':'Encryption, shadow copy deletion, wiped disks, defaced sites.'};
const CHC = {sig:'', v:null};
function chainOf(c, D){
  const sig = c.id + ':' + rev + ':' + DB.rules.length; if(CHC.sig === sig) return CHC.v;
  const tech = new Map(ATTACK.tech.map(t => [t[0], t])), order = ATTACK.tactics.map(t => t[1]), at = new Map(order.map(s => [s, []]));
  /* ATT&CK split Defense Evasion into Stealth and Defense Impairment: older names are moved to the stage that exists */
  const has = x => at.has(x), alias = (st, why) => has(st) ? st : st === 'defense-evasion' ? (/log|clear|disabl|tamper|impair|anti-forensic/i.test(why) && has('defense-impairment') ? 'defense-impairment' : has('stealth') ? 'stealth' : st) : st;
  const add = (stage0, r, why) => { const stage = alias(stage0, why); const L = at.get(stage); if(!L) return; const x = L.find(z => z.r === r); if(x){ if(!x.why.includes(why)) x.why.push(why); } else L.push({r, why:[why]}); };
  const byTech = (id, r, src) => { const t = tech.get(id) || tech.get(id.split('.')[0]); if(t) for(const s of t[2]) add(s, r, id + ' ' + t[1] + (src ? ' (' + src + ')' : '')); };
  const ev = D.recs.filter(r => r.type !== 'lead');
  /* Sigma rules that carry a technique, run over the case if it is not huge */
  const rules = ev.length <= 3000 ? DB.rules.filter(r => r.type === 'sigma' && /T\d{4}/.test(r.technique || '')).map(r => { try{ return {r, p:sigmaParse(r.code)}; }catch(e){ return null; } }).filter(x => x && x.p.cond) : [];
  for(const r of ev){
    for(const o of E.observations(r)){ const ids = o.t.match(/T\d{4}(?:\.\d{3})?/g) || []; ids.forEach(id => byTech(id, r)); if(!ids.length && typeof RW_TAG !== 'undefined' && RW_TAG[o.tag]) add(RW_TAG[o.tag][1], r, RW_TAG[o.tag][0]); }
    for(const e of r.ents || []) if(e.k === 'ttp') byTech(e.v.toUpperCase(), r);
    for(const tg of r.tags || []){ const m = CH_TAGS.find(([re]) => re.test(tg.toLowerCase())); if(m) add(m[1], r, 'tagged “' + tg + '”'); }
  }
  if(rules.length){ const F = ev.map(recFields), I = sigmaIndex(F);
    for(const x of rules){ const C = sigmaCands(I, x.p), idx = C ? [...C].sort((a, b) => a - b) : F.map((_, i) => i);
      for(const i of idx){ let hit = false; try{ hit = sigmaEval(x.p, F[i]); }catch(e){} if(hit) for(const id of x.r.technique.match(/T\d{4}(?:\.\d{3})?/g)) byTech(id, ev[i], 'rule “' + x.r.title + '”'); } } }
  const stages = ATTACK.tactics.map(([tid, short, name]) => { const L = at.get(short).sort((a, b) => (a.r.ts || 9e15) - (b.r.ts || 9e15)); return {tid, short, name, L, first:L.find(x => x.r.ts)}; });
  const seen = stages.filter(s => s.L.length), lastIdx = Math.max(-1, ...stages.map((s, i) => s.L.length ? i : -1)), firstIdx = stages.findIndex(s => s.L.length);
  /* stages in the middle of the chain with nothing: the likely blind spots */
  const gaps = stages.filter((s, i) => !s.L.length && i > firstIdx && i < lastIdx && !['reconnaissance', 'resource-development'].includes(s.short));
  /* order surprises: a later stage seen before an earlier one began */
  const odd = []; for(let i = 0; i < stages.length; i++) for(let j = i + 1; j < stages.length; j++){ const a = stages[i].first, b = stages[j].first; if(a && b && b.r.ts < a.r.ts - 36e5 && ['initial-access', 'execution'].includes(stages[i].short)) odd.push({early:stages[j], late:stages[i]}); }
  CHC.sig = sig; CHC.v = {stages, seen, gaps, odd:odd.slice(0, 3), ruled:rules.length}; return CHC.v;
}
function chainView(c, D){
  const C = chainOf(c, D), f = ts => ts ? esc(E.fmtFull(ts, tz())) : 'no time';
  if(!C.seen.length) return `<div class="page wide">${empty('route', 'No attack stages recognised yet', 'Stages come from ATT&CK technique IDs in your evidence, what OSINTrix recognises (encoded PowerShell, disguised attachments, cleared logs…), tags such as “persistence” or “lateral-movement”, and your Sigma rules that carry a technique.')}</div>`;
  const col = s => `<section class="ch-s${s.L.length ? ' on' : ''}${C.gaps.includes(s) ? ' ch-gap' : ''}" aria-label="${esc(s.name)}"><header><span class="ch-n">${esc(s.tid)}</span><h3>${esc(s.name)}</h3><span class="ch-c">${s.L.length || ''}</span></header>
    ${s.L.length ? `<p class="ch-first t3">${s.first ? 'First ' + f(s.first.r.ts) : ''}</p><ul>${s.L.slice(0, 6).map(x => `<li><button class="ch-e" data-act="tlxRec" data-id="${x.r.id}"><span class="mono t3">${x.r.ts ? esc(E.fmtClock(x.r.ts, tz())) : '—'}${x.r.host ? ' · ' + esc(x.r.host) : ''}</span><b>${esc(x.r.title)}</b><small>${esc(x.why.slice(0, 2).join(' · '))}</small></button></li>`).join('')}</ul>${s.L.length > 6 ? `<p class="t3 small">and ${s.L.length - 6} more</p>` : ''}`
      : `<p class="ch-none">${C.gaps.includes(s) ? '<b>Nothing yet — but the stages around it are seen.</b> ' : ''}${esc(CH_LOOK[s.short] || '')}</p><button class="btn xs ghost" data-act="chRules" data-v="${esc(s.short)}">${ico('shield-check','sm')}Rules for this stage</button>`}</section>`;
  return `<div class="page wide ch">
    <section class="card ch-sum"><div class="tlx-kpi"><div><b>${C.seen.length}</b><span>of ${C.stages.length} stages seen</span></div><div class="${C.gaps.length ? 'r' : ''}"><b>${C.gaps.length}</b><span>missing in the middle</span></div>${C.stages.find(s => s.short === 'exfiltration' && s.L.length) ? '<div class="r"><b>Yes</b><span>exfiltration seen</span></div>' : ''}${C.stages.find(s => s.short === 'impact' && s.L.length) ? '<div class="r"><b>Yes</b><span>impact seen</span></div>' : ''}</div>
      <ol class="ch-bar" aria-label="Stages">${C.stages.map(s => `<li class="${s.L.length ? 'on' : ''}${C.gaps.includes(s) ? ' ch-gap' : ''}" title="${esc(s.name)}${s.L.length ? ' — ' + s.L.length + ' event' + (s.L.length > 1 ? 's' : '') : C.gaps.includes(s) ? ' — missing' : ''}"><span>${esc(s.name.split(' ')[0])}</span></li>`).join('')}</ol>
      ${C.gaps.length ? `<p class="t2 ch-p">${ico('circle-help','sm')} The attacker had to pass through <b>${C.gaps.map(s => esc(s.name)).join(', ')}</b> to get from ${esc(C.seen[0].name)} to ${esc(C.seen[C.seen.length - 1].name)}, but nothing in the case shows it yet. That is where to look next.</p>` : ''}
      ${C.odd.map(o => `<p class="t2 ch-p">${ico('clock-alert','sm')} ${esc(o.early.name)} is seen at ${f(o.early.first.r.ts)}, before the first ${esc(o.late.name)} (${f(o.late.first.r.ts)}) — the way in may be earlier than you have evidence for, or a clock is off.</p>`).join('')}
      <p class="t3 small">Placed from technique IDs in the evidence, what OSINTrix recognises, tags, and ${C.ruled ? C.ruled + ' of your Sigma rules that carry a technique' : 'your Sigma rules (none carry a technique yet)'}.</p></section>
    <div class="ch-g">${C.stages.map(col).join('')}</div></div>`;
}
const CH_ACTS = {
  chRules:(id, v) => { UI.dview = 'rules'; UI.dtac = v; UI.dq = ''; UI.dtype = 'all'; go('#/detections'); },
  dtacOff:() => { UI.dtac = null; renderMain(); },
};
