/* ==========================================================================
   Detections intelligence
     • Coverage: your rules on the ATT&CK tactics, against the techniques your cases
       actually show — the gaps are the techniques seen with no rule
     • Health: every rule linted (structure, unused selections, values too broad or too
       short, missing level / false positives / id) and run over the evidence of every
       case: noisy rules, rules that never fire, and rules that duplicate each other
     • Tuning: for a noisy Sigma rule, the field values its hits share become a ready
       filter to paste in
   All of it runs in the page on your own rules and evidence.
   ========================================================================== */
const DQ = {health:null, running:false};
const ruleTechs = r => { const s = new Set(); for(const m of String((r.technique || '') + ' ' + (r.tags || []).join(' ') + ' ' + (r.code || '')).matchAll(/\b(?:attack\.)?(t\d{4}(?:\.\d{3})?)\b/gi)) s.add(m[1].toUpperCase()); return [...s]; };
const techBase = id => id.split('.')[0];

/* techniques your cases show: observations with T-codes, ATT&CK IDs in evidence, OTX answers */
function seenTechs(){
  const M = new Map(), put = (id, caseId, r) => { id = id.toUpperCase(); const x = M.get(id) || {cases:new Set(), recs:[]}; x.cases.add(caseId); if(r && x.recs.length < 5) x.recs.push(r); M.set(id, x); };
  for(const r of DB.records){ if(r.type === 'lead') continue;
    for(const o of E.observations(r)) for(const id of o.t.match(/T\d{4}(?:\.\d{3})?/g) || []) put(id, r.caseId, r);
    for(const e of r.ents || []) if(e.k === 'ttp') put(e.v, r.caseId, r); }
  return M;
}
function coverage(){
  if(typeof ATTACK === 'undefined') return null;
  if(DQ.cov && DQ.cov.rev === rev && DQ.cov.n === DB.rules.length && DQ.cov.v === ATTACK.v) return DQ.cov.val;
  const val = coverage0(); DQ.cov = {rev, n:DB.rules.length, v:ATTACK.v, val}; return val;
}
function coverage0(){
  const tech = new Map(ATTACK.tech.map(t => [t[0], t])), byT = new Map();
  for(const r of DB.rules) for(const id of ruleTechs(r)){ if(!byT.has(id)) byT.set(id, new Set()); byT.get(id).add(r); }
  /* a rule for a sub-technique covers it; a rule for the parent technique covers its sub-techniques too */
  const rulesFor = id => [...new Set([...(byT.get(id) || []), ...(id.includes('.') ? byT.get(techBase(id)) || [] : [])])];
  const seen = seenTechs(), tac = ATTACK.tactics.map(([tid, short, name]) => ({tid, short, name, covered:[], gaps:[]}));
  const tacOf = new Map(tac.map(t => [t.short, t])), rows = new Map();
  for(const id of new Set([...byT.keys(), ...seen.keys()])){ const t = tech.get(id) || tech.get(techBase(id)); if(!t) continue; const key = tech.has(id) ? id : t[0];
    const o = rows.get(key) || {id:key, name:t[1], phases:t[2], rules:rulesFor(key), seen:null}; o.seen = o.seen || seen.get(id) || null; rows.set(key, o); }
  for(const x of rows.values()) for(const ph of x.phases){ const T = tacOf.get(ph); if(!T) continue; (x.rules.length ? T.covered : T.gaps).push(x); }
  for(const T of tac){ T.covered.sort((a, b) => (!!b.seen - !!a.seen) || b.rules.length - a.rules.length); T.gaps.sort((a, b) => b.seen.cases.size - a.seen.cases.size); }
  const all = [...rows.values()], gaps = all.filter(x => !x.rules.length && x.seen), seenCovered = all.filter(x => x.rules.length && x.seen);
  return {tac, all, gaps, seenCovered, techN:all.filter(x => x.rules.length).length, tacN:tac.filter(t => t.covered.length).length, noTech:DB.rules.filter(r => !ruleTechs(r).length).length};
}
function covView(){
  const C = coverage(); if(!C) return empty('grid-3x3', 'ATT&CK is not loaded', '');
  const cell = (x, gap) => `<button class="cv-c${gap ? ' gap' : x.seen ? ' seen' : ''}" data-act="${gap ? 'cvGap' : 'cvTech'}" data-v="${esc(x.id)}" title="${esc(x.id + ' ' + x.name + (gap ? ' — seen in ' + x.seen.cases.size + ' case(s), no rule' : ' — ' + x.rules.length + ' rule(s)' + (x.seen ? ', seen in your cases' : '')))}">
      <b class="mono">${esc(x.id)}</b><span>${esc(x.name)}</span><i>${gap ? 'no rule' : x.rules.length}</i></button>`;
  return `<div class="cv-sum"><div><b>${C.techN}</b><span>techniques covered</span></div><div><b>${C.tacN}<small>/${C.tac.length}</small></b><span>tactics with a rule</span></div>
      <div class="${C.gaps.length ? 'r' : ''}"><b>${C.gaps.length}</b><span>seen in your cases, no rule</span></div><div><b>${C.seenCovered.length}</b><span>seen and covered</span></div>${C.noTech ? `<div><b>${C.noTech}</b><span>rules with no technique</span></div>` : ''}</div>
    ${C.gaps.length ? `<section class="card cv-gaps"><header><h3>${ico('triangle-alert','sm')}Gaps that matter</h3><span class="t3">techniques your evidence shows that no rule detects</span></header><div class="body">
      ${C.gaps.map(x => `<div class="cv-g"><div><b class="mono">${esc(x.id)}</b> ${esc(x.name)}<small>${esc([...x.seen.cases].map(id => (theCase(id) || {}).code).filter(Boolean).join(', '))} · e.g. ${esc(x.seen.recs[0] ? x.seen.recs[0].title : '')}</small></div><button class="btn sm" data-act="cvGap" data-v="${esc(x.id)}">${ico('plus','sm')}Draft a rule</button></div>`).join('')}</div></section>` : ''}
    <div class="cv-m">${C.tac.map(T => `<section class="cv-t"><header><b>${esc(T.name)}</b><span class="t3">${T.covered.length}${T.gaps.length ? ` · <em>${T.gaps.length} gap${T.gaps.length > 1 ? 's' : ''}</em>` : ''}</span></header>
      ${T.gaps.map(x => cell(x, true)).join('')}${T.covered.slice(0, 40).map(x => cell(x)).join('')}${T.covered.length > 40 ? `<small class="t3">+${T.covered.length - 40} more</small>` : ''}${!T.covered.length && !T.gaps.length ? '<small class="t3">No rules</small>' : ''}</section>`).join('')}</div>
    <p class="heur">Techniques come from each rule's technique field and attack.* tags; "seen" comes from the ATT&CK IDs that your evidence and its observations carry.</p>`;
}

/* ---------- lint ---------- */
const LINT_COMMON = /^(\.exe|\.dll|cmd|cmd\.exe|powershell|powershell\.exe|http|https|\.com|\\windows\\|c:\\|svchost\.exe|explorer\.exe|admin|user|test|\*|\.)$/i;
function ruleLint(r){
  let L = validateRule(r.type, r.code, r.title).map(t => ({sev:'err', t}));
  if(r.type === 'yara') L = L.map(l => /^Unbalanced braces/.test(l.t) && !(yaraScan(r.code, new Uint8Array(0)).find(z => z.error && !/Not supported/.test(z.error))) ? {sev:'info', t:l.t + ' — but the rule compiles (braces inside strings or regexes)'} : l);
  const add = (sev, t) => L.push({sev, t}), c = r.code || '';
  if(r.type === 'sigma'){
    const p = sigmaParse(c), names = Object.keys(p.det), used = new Set();
    const cond = (p.cond || '').split('|')[0];          /* “| count() by … > n” is an aggregation, not selections */
    if(cond){ for(const t of cond.match(/\b(?:1|all|any)\s+of\s+[\w*]+|[\w*]+/gi) || []){ const m = /^(?:1|all|any)\s+of\s+([\w*]+)$/i.exec(t); if(m){ names.filter(k => m[1] === 'them' || (m[1].endsWith('*') ? k.startsWith(m[1].slice(0, -1)) : k === m[1])).forEach(k => used.add(k)); } else if(!/^(and|or|not|1|all|any|of|them)$/i.test(t)){ if(!p.det[t]) add('err', 'Condition names “' + t + '”, which is not defined'); used.add(t); } } }
    for(const n of names) if(!used.has(n)) add('warn', 'Selection “' + n + '” is never used in the condition');
    for(const [n, s] of Object.entries(p.det)){ for(const fl of s.fields){ const mods = fl.f.split('|').slice(1);
        for(const v of fl.vals){ const bare = String(v).replace(/\*/g, ''), alone = s.fields.length === 1 && !(mods.includes('all') && fl.vals.length > 1); if(!bare.length) add('warn', fl.f + ' matches anything (“' + v + '”)'); else if(alone && mods.includes('contains') && bare.trim().length < 3) add('warn', fl.f + ' contains “' + v + '” — too short, will match a lot'); else if(alone && LINT_COMMON.test(bare) && (mods.includes('contains') || mods.includes('endswith'))) add('warn', fl.f + ' “' + v + '” is very common on its own'); }
        if(mods.includes('re')) for(const v of fl.vals){ try{ new RegExp(v); }catch(e){ add('info', 'The regular expression in ' + fl.f + ' is not JavaScript syntax — fine in most SIEMs, but it cannot be tested here'); } } }
      if(!s.fields.length && s.keywords.some(k => k.replace(/\*/g, '').length < 5)) add('warn', 'Keyword search “' + s.keywords.find(k => k.replace(/\*/g, '').length < 5) + '” in “' + n + '” is very broad'); }
    if(!/^\s*level\s*:/m.test(c)) add('info', 'No “level:” — triage cannot sort its alerts');
    if(!/^\s*falsepositives\s*:/m.test(c)) add('info', 'No “falsepositives:” — note what legitimately triggers it');
    if(!/^\s*id\s*:/m.test(c)) add('info', 'No “id:” — it cannot be tracked across tools');
  } else {
    const strs = [...c.matchAll(/\$\w*\s*=\s*("(?:[^"\\]|\\.)*"|\{[^}]*\}|\/(?:[^/\\]|\\.)+\/)/g)].map(m => m[1]);
    for(const s of strs){ const len = s.startsWith('"') ? s.slice(1, -1).replace(/\\./g, '.').length : s.startsWith('{') ? s.replace(/[^0-9a-f?]/gi, '').length / 2 : 99; if(len < 4) add('warn', 'String ' + s.slice(0, 20) + ' is shorter than 4 bytes — slow and noisy'); }
    if(/any of them/.test(c) && strs.length === 1) add('info', '“any of them” with a single string — say “$name” instead');
    if(!/\bmeta\s*:/.test(c)) add('info', 'No “meta:” — add a description and author');
    if(!strs.length && !/\bfilesize|uint(8|16|32)|pe\./.test(c)) add('warn', 'No strings and no structural check — it may match every file');
  }
  if(!ruleTechs(r).length) add('info', 'No ATT&CK technique — it will not count towards coverage');
  return L;
}

/* ---------- health: run every rule over every case ---------- */
/* the words of a rule's detection logic (Sigma: the detection block; YARA: strings and condition), without YAML and operator words */
const RT_STOP = new Set(['condition', 'selection', 'filter', 'contains', 'endswith', 'startswith', 'all', 'and', 'not', 'them', 'any', 'one', 'windash', 'base64', 'base64offset', 'cidr', 'detection', 'strings', 'ascii', 'wide', 'nocase', 'fullword', 'true', 'false', 'null', 'sel', 'selection_img', 'selection_cli']);
const RT_C = new Map();
function ruleTokens(r){ const code = String(r.code || ''), k = r.id + ':' + code.length + ':' + (r.updated || 0); if(RT_C.has(k)) return RT_C.get(k);
  const part = r.type === 'yara' ? (code.match(/strings:([\s\S]*)/) || [, code])[1] : (code.match(/detection:([\s\S]*?)(?:\n(?:falsepositives|level|fields|tags|status|references):|$)/) || [, ''])[1];
  const t = new Set(part.toLowerCase().split(/[^a-z0-9_.\\-]+/).map(x => x.replace(/^[\\.-]+|[\\.-]+$/g, '')).filter(x => x.length >= 3 && !RT_STOP.has(x) && !/^(selection|filter)_?\w*$/.test(x)));
  if(RT_C.size > 3000) RT_C.clear(); RT_C.set(k, t); return t; }
async function ruleHealth(){
  if(DQ.running) return; DQ.running = true; DQ.health = {done:0, total:DB.rules.length, rows:[]}; renderMain();
  const recs = DB.records.filter(r => r.type !== 'lead').slice(-5000), F = new Map(), id2 = new Map(recs.map((r, i) => [r.id, i]));
  const field = r => { let f = F.get(r.id); if(!f){ f = recFields(r); F.set(r.id, f); } return f; };
  const benign = r => (r.ents || []).length && r.ents.every(e => verdictOf(e.k + ':' + e.v) === 'benign');
  const yaraOk = recs.length <= 2000, rows = [], I = sigmaIndex(recs.map(field));
  for(let i = 0; i < DB.rules.length; i++){ const r = DB.rules[i]; let hits = [], err = '';
    try{ if(r.type === 'sigma'){ const p = sigmaParse(r.code); if(p.cond && Object.keys(p.det).length){ const C = sigmaCands(I, p); hits = (C ? [...C].sort((a, b) => a - b).map(i => recs[i]) : recs).filter(x => { try{ return sigmaEval(p, field(x)); }catch(e){ err = e.message; return false; } }); } }
      else if(yaraOk){ for(const x of recs){ const res = yaraScan(r.code, new TextEncoder().encode(x.title + '\n' + x.body)); if(res.some(z => z.error)){ err = res.find(z => z.error).error; break; } if(res.some(z => z.match)) hits.push(x); } } }
    catch(e){ err = e.message; }
    let unsup = ''; if(/Not supported in the browser engine/.test(err)){ unsup = err; err = ''; }
    const lint = ruleLint(r), cases = new Set(hits.map(h => h.caseId)), ratio = recs.length ? hits.length / recs.length : 0, ben = hits.filter(benign).length;
    const noisy = hits.length >= 5 && (ratio > 0.2 || ben / hits.length > 0.5);
    const TR = r.tests && r.tests.length && typeof dlRunTests === 'function' ? dlRunTests(r) : [], tfail = TR.filter(x => !x.ok).length, trend = typeof dlTrend === 'function' ? dlTrend(r) : null;
    rows.push({r, hits:hits.map(h => id2.get(h.id)), n:hits.length, cases, err, unsup, lint, noisy, ben, ratio, tests:TR.length, tfail, regressed:!!(tfail && trend && (trend.regressed || trend.now))});
    if(i % 25 === 24){ DQ.health.done = i + 1; if(UI.dview === 'health') renderMain(); await new Promise(res => setTimeout(res, 0)); } }
  /* duplicates: rules that fire on (nearly) the same records */
  const fired = rows.filter(x => x.n >= 3), dup = [];
  for(let a = 0; a < fired.length; a++){ const A = new Set(fired[a].hits); for(let b = a + 1; b < fired.length; b++){ const B = fired[b].hits; let inter = 0; for(const h of B) if(A.has(h)) inter++; const j = inter / (A.size + B.length - inter); if(j >= 0.8) dup.push({a:fired[a], b:fired[b], j}); } }
  for(const d of dup){ (d.a.dups = d.a.dups || []).push(d.b.r); (d.b.dups = d.b.dups || []).push(d.a.r); }
  /* look-alikes: rules whose detection logic is nearly the same text, found even with no evidence to fire on */
  const tok = rows.map(x => ({x, t:ruleTokens(x.r)})).filter(o => o.t.size >= 2);
  for(let a = 0; a < tok.length; a++) for(let b = a + 1; b < tok.length; b++){ const A = tok[a], B = tok[b]; if(A.x.r.type !== B.x.r.type) continue;
    const small = Math.min(A.t.size, B.t.size), big = Math.max(A.t.size, B.t.size); if(small / big < 0.8) continue;
    let inter = 0; for(const t of A.t) if(B.t.has(t)) inter++; if(inter / (A.t.size + B.t.size - inter) >= 0.85){ (A.x.alike = A.x.alike || []).push(B.x.r); (B.x.alike = B.x.alike || []).push(A.x.r); } }
  /* this check against the last one */
  const sum = {at:Date.now(), rules:rows.length, fired:rows.filter(x => x.n).length, noisy:rows.filter(x => x.noisy).length, broken:rows.filter(x => x.err || x.lint.some(l => l.sev === 'err')).length,
    tfail:rows.filter(x => x.tfail).length, untested:rows.filter(x => !x.r.builtin && !x.tests).length, alike:rows.filter(x => x.alike).length};
  const hist = Array.isArray(DB.prefs.dqHist) ? DB.prefs.dqHist.filter(h => h && +h.at) : [], prev = hist[hist.length - 1] || null;
  DB.prefs.dqHist = [...hist, sum].slice(-30); save();
  DQ.health = {prev, sum, done:DB.rules.length, total:DB.rules.length, rows, recs, dup, at:Date.now(), yaraSkipped:!yaraOk};
  DQ.running = false; if(UI.dview === 'health') renderMain();
}
/* field values the hits of a noisy rule share → a filter to exclude them */
function tuneSuggest(row){
  const H = DQ.health; if(!H || row.r.type !== 'sigma' || !row.n) return null;
  const hits = row.hits.map(i => H.recs[i]), F = hits.map(recFields), cnt = new Map();
  for(const f of F) for(const [k, v] of Object.entries(f)){ if(k === '_raw' || k === 'source' || !v || v.length > 120) continue; const key = k + '\u0000' + v; cnt.set(key, (cnt.get(key) || 0) + 1); }
  const top = [...cnt.entries()].filter(([, n]) => n >= Math.max(3, hits.length * 0.6)).map(([k, n]) => { const [f, v] = k.split('\u0000'); return {f, v, n}; })
    .filter(x => !/^(eventid|computer)$/.test(x.f) || hits.length > 10).sort((a, b) => b.n - a.n).slice(0, 2);
  if(!top.length) return null;
  const cap1 = s => s.replace(/^./, c => c.toUpperCase());
  return {top, yaml:`    filter_common:\n${top.map(x => `        ${cap1(x.f)}: '${x.v.replace(/'/g, "''")}'`).join('\n')}\n    condition: (${sigmaParse(row.r.code).cond || 'selection'}) and not filter_common`};
}
/* the summary of this check against the previous one: only what moved */
function dqDelta(H){ const P = H.prev, S = H.sum; if(!P || !S) return '';
  const L = [['noisy', 'noisy', 1], ['broken', 'broken', 1], ['tfail', 'with failing tests', 1], ['alike', 'look-alike', 1], ['untested', 'of yours untested', 1], ['fired', 'firing on your evidence', -1], ['rules', 'rules in all', 0]]
    .filter(([k]) => +P[k] !== +S[k] && P[k] != null).map(([k, l, bad]) => { const up = S[k] > P[k], tone = !bad ? '' : (up === (bad > 0)) ? 'r' : 'g'; return `<span class="dq-dl ${tone}">${esc(l)} ${P[k]} → <b>${S[k]}</b></span>`; });
  return `<p class="t3 dq-delta">${L.length ? 'Since the check ' + esc(iAgo(P.at)) + ': ' + L.join('') : 'Nothing changed since the check ' + esc(iAgo(P.at)) + '.'}</p>`; }
function healthView(){
  const H = DQ.health;
  if(!H) return `<section class="card"><div class="body"><p class="t2">Lint every rule and run it over the evidence of every case, to find rules that are broken, too noisy, never fire, or duplicate another.</p><button class="btn primary" data-act="dqRun">${ico('activity','sm')}Check ${DB.rules.length} rules</button></div></section>`;
  if(DQ.running) return `<section class="card"><div class="body"><p>Checking ${H.done} of ${H.total} rules…</p><div class="lk-prog" role="progressbar" aria-label="Checking rules" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${Math.round(H.done / H.total * 100)}"><i style="width:${Math.round(H.done / H.total * 100)}%"></i></div></div></section>`;
  const R = H.rows, err = R.filter(x => x.err || x.lint.some(l => l.sev === 'err')), noisy = R.filter(x => x.noisy), warn = R.filter(x => x.lint.some(l => l.sev === 'warn')), fired = R.filter(x => x.n), mine = R.filter(x => !x.r.builtin);
  const f = UI.dqf || 'problems', tfail = R.filter(x => x.tfail), untested = mine.filter(x => !x.tests), alike = R.filter(x => x.alike);
  const list = f === 'tests' ? tfail.sort((a, b) => b.regressed - a.regressed) : f === 'untested' ? untested : f === 'alike' ? alike : f === 'noisy' ? noisy : f === 'broken' ? err : f === 'dups' ? R.filter(x => x.dups) : f === 'fired' ? fired.sort((a, b) => b.n - a.n) : f === 'warn' ? warn : f === 'mine' ? mine : [...new Set([...tfail, ...err, ...noisy, ...R.filter(x => x.dups), ...alike, ...mine.filter(x => x.lint.some(l => l.sev === 'warn'))])];
  const tab = (k, l, n) => `<button data-act="dqf" data-v="${k}" aria-pressed="${f === k}">${l} <b>${n}</b></button>`;
  return `<div class="cv-sum"><div><b>${fired.length}</b><span>rules fired on your evidence</span></div><div class="${noisy.length ? 'a' : ''}"><b>${noisy.length}</b><span>noisy</span></div><div class="${err.length ? 'r' : ''}"><b>${err.length}</b><span>broken</span></div><div><b>${H.dup.length}</b><span>duplicate pairs</span></div><div><b>${H.recs.length.toLocaleString()}</b><span>records tested</span></div></div>
    ${dqDelta(H)}
    <div class="toolbar"><div class="seg">${tab('problems', 'Needs attention', [...new Set([...tfail, ...err, ...noisy, ...R.filter(x => x.dups), ...alike])].length)}${tab('tests', 'Tests failing', tfail.length)}${tab('untested', 'Your rules without tests', untested.length)}${tab('alike', 'Look alike', alike.length)}${tab('fired', 'Fired', fired.length)}${tab('noisy', 'Noisy', noisy.length)}${tab('broken', 'Broken', err.length)}${tab('dups', 'Duplicates', R.filter(x => x.dups).length)}${tab('warn', 'Warnings', warn.length)}${tab('mine', 'Yours', mine.length)}</div>
      <span class="sp"></span><span class="t3">${esc(iAgo(H.at))}${H.yaraSkipped ? ' · YARA skipped (over 2,000 records)' : ''}</span><button class="btn sm" data-act="dqRun">${ico('refresh-cw','sm')}Check again</button></div>
    ${list.length ? `<div class="dq-list">${list.slice(0, 150).map(x => { const tune = x.noisy ? tuneSuggest(x) : null;
      return `<article class="dq-r"><header><button class="dq-t" data-act="dqOpen" data-id="${esc(x.r.id)}"><b>${esc(x.r.title)}</b></button><span class="pill" style="--c:${RTYPE[x.r.type][2]}">${RTYPE[x.r.type][0]}</span>
        ${x.noisy ? '<span class="chip amber sq">noisy</span>' : ''}${x.tfail ? `<span class="chip red sq">${x.regressed ? 'was passing — ' : ''}${x.tfail} of ${x.tests} test${x.tests > 1 ? 's' : ''} fail</span>` : ''}${!x.r.builtin && !x.tests ? '<span class="chip sq">no tests</span>' : ''}${x.err ? '<span class="chip red sq">error</span>' : ''}<span class="t3">${x.n ? x.n + ' hit' + (x.n > 1 ? 's' : '') + ' in ' + x.cases.size + ' case' + (x.cases.size > 1 ? 's' : '') + (x.ben ? ' · ' + x.ben + ' on benign-only evidence' : '') : 'never fired'}</span></header>
        ${x.err ? `<p class="dq-e">${esc(x.err)}</p>` : ''}${x.unsup ? `<p class="t3" style="margin:6px 0 0">${esc(x.unsup.replace('Not supported in the browser engine', 'Cannot be tested in the browser'))} — your scanner will run it.</p>` : ''}
        ${x.lint.length ? `<ul class="dq-l">${x.lint.slice(0, 6).map(l => `<li class="${l.sev}">${esc(l.t)}</li>`).join('')}</ul>` : ''}
        ${x.alike ? `<p class="t2 dq-d">${ico('copy','sm')}Nearly the same logic as ${x.alike.slice(0, 3).map(d => `<button class="lnk" data-act="dqOpen" data-id="${esc(d.id)}">${esc(d.title)}</button>`).join(', ')} — keep one, or make them differ</p>` : ''}
        ${x.dups ? `<p class="t2 dq-d">${ico('copy','sm')}Fires on the same records as ${x.dups.slice(0, 3).map(d => `<button class="lnk" data-act="dqOpen" data-id="${esc(d.id)}">${esc(d.title)}</button>`).join(', ')}</p>` : ''}
        ${tune ? `<div class="dq-tune"><b>Suggested tuning</b><span class="t3">${esc(tune.top.map(t => t.n + ' of ' + x.n + ' hits share ' + t.f + ' = ' + t.v).join('; '))}</span><pre class="mono">${esc(tune.yaml)}</pre><button class="btn xs" data-act="dqCopy" data-v="${esc(tune.yaml)}">${ico('copy','sm')}Copy</button></div>` : ''}</article>`; }).join('')}</div>`
      : `<p class="t3">${f === 'problems' ? 'No rule needs attention.' : 'None.'}</p>`}`;
}
/* a starter Sigma rule for a technique seen in a case with no rule */
function gapRule(id){
  const seen = seenTechs().get(id) || {recs:[]}, t = (ATTACK.tech.find(x => x[0] === id) || [id, id]), r = seen.recs[0], f = r ? recFields(r) : {};
  const pick = ['image', 'commandline', 'parentimage', 'targetfilename', 'destinationhostname', 'queryname', 'destinationip', 'eventid'].filter(k => f[k]).slice(0, 2);
  const now = Date.now(), cat = f.image ? 'process_creation' : f.queryname ? 'dns_query' : f.destinationip ? 'network_connection' : 'process_creation';
  const code = `title: ${t[1]} (${id})\nid: ${crypto.randomUUID ? crypto.randomUUID() : 'gap-' + now}\nstatus: experimental\ndescription: Drafted by OSINTrix from ${r ? '“' + r.title.replace(/\n/g, ' ') + '”' : 'a case'} — generalise the values before use.\nreferences:\n    - https://attack.mitre.org/techniques/${id.replace('.', '/')}/\nauthor: You\ntags:\n    - attack.${id.toLowerCase()}\nlogsource:\n    category: ${cat}\n    product: windows\ndetection:\n    selection:\n${(pick.length ? pick : ['commandline']).map(k => `        ${k.replace(/^./, c => c.toUpperCase())}|contains: '${String(f[k] || 'CHANGE-ME').slice(0, 80).replace(/'/g, "''")}'`).join('\n')}\n    condition: selection\nfalsepositives:\n    - Unknown — review\nlevel: medium`;
  const rule = {id:uid('r'), type:'sigma', title:t[1] + ' (' + id + ')', desc:'Drafted for a coverage gap: ' + id + ' is seen in your cases with no rule.', code, severity:'medium', category:'process', technique:id, author:'You', platform:'Windows', tags:['gap', 'draft'], refs:[], created:now, modified:now, starred:false, caseId:r ? r.caseId : null};
  DB.rules.unshift(rule); mutate('drafted a rule for ' + id); UI.dview = 'rules'; UI.rule = rule.id; UI.ropen = true; renderMain(); toast('Draft rule for ' + id + ' — edit the values, then test it');
}
const DQ_ACTS = {
  dview:(id, v) => { UI.dview = v; renderMain(); if(v === 'health' && !DQ.health) ruleHealth(); },
  dqOpen:id => { UI.dview = 'rules'; UI.rule = id; UI.ropen = true; renderMain(); },
  dqRun:() => ruleHealth(), dqf:(id, v) => { UI.dqf = v; renderMain(); },
  dqCopy:async (id, v) => { try{ await navigator.clipboard.writeText(v); toast('Copied'); }catch(e){ toast('Copy failed'); } },
  cvGap:(id, v) => gapRule(v),
  cvTech:(id, v) => { UI.dview = 'rules'; UI.dq = v.toLowerCase(); renderMain(); },
};
