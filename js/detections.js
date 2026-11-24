/* ==========================================================================
   Detections — write, keep, import and export Sigma and YARA rules.
   Seeded from the original threat-rules.json. Validation is structural
   (required sections present), not a full compiler — and says so.
   ========================================================================== */
const SEV = {critical:['Critical','var(--red)'], high:['High','#f97316'], medium:['Medium','var(--amber)'], low:['Low','var(--green)'], informational:['Info','var(--text-3)']};
const RULE_TPL = {
  sigma:`title: New detection
id: ${'00000000-0000-4000-8000-000000000000'}
status: experimental
description: What this detects and why it matters
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\\\example.exe'
    condition: selection
level: medium`,
  yara:`rule new_detection {
    meta:
        description = "What this detects"
        author = "You"
    strings:
        $s1 = "example" ascii wide
    condition:
        any of them
}`};
const ruleFromSeed = r => ({id:r.id, type:r.type, title:r.title, desc:r.description || '', code:r.code || '', severity:(r.severity || 'medium').toLowerCase(), category:r.category || '', technique:r.technique || '',
  author:r.author || '', platform:r.platform || '', tags:r.tags || [], refs:r.references || [], level:r.level || '', builtin:true, created:Date.parse(r.created) || Date.now(), modified:Date.parse(r.modified) || Date.now(), starred:!!r.starred, caseId:null});
const RULE_BUILTIN = () => RULE_SEED.concat(typeof RULE_PACK !== 'undefined' ? RULE_PACK : []);
let RULES_MERGED = false;
/* Built-in rules are added once; later versions add the new ones without touching rules you changed or deleted. */
function ensureRules(){
  if(!DB.rules) DB.rules = [];
  if(RULES_MERGED) return; if(typeof RULE_PACK !== 'undefined') RULES_MERGED = true;   // until the pack has loaded, only the starter rules are merged
  const have = new Set(DB.rules.map(r => r.id)), gone = new Set(DB.deletedRules || []), add = RULE_BUILTIN().filter(r => !have.has(r.id) && !gone.has(r.id)).map(ruleFromSeed);
  /* a built-in rule that was improved: update copies still holding the old, unedited text; edited copies are left alone */
  let fixed = 0;
  for(const seed of RULE_BUILTIN()) if(seed.replaces){ const r = DB.rules.find(x => x.id === seed.id);
    if(r && seed.replaces.some(c => String(c).trim() === String(r.code).trim())){ const n = ruleFromSeed(seed); Object.assign(r, {code:n.code, desc:n.desc, title:n.title, modified:n.modified, severity:n.severity}); fixed++; } }
  if(add.length) DB.rules.push(...add);
  if((add.length && have.size) || fixed) save();
}
const RULE_HAY = new WeakMap();
const ruleHay = r => { let h = RULE_HAY.get(r); if(!h || h.m !== r.modified){ h = {m:r.modified, t:(r.title + ' ' + r.desc + ' ' + (r.tags || []).join(' ') + ' ' + r.technique + ' ' + r.platform + ' ' + r.category + ' ' + r.author + ' ' + r.code).toLowerCase()}; RULE_HAY.set(r, h); } return h.t; };
function validateRule(type, code, title){
  const c = String(code || ''), issues = [];
  if(type === 'sigma'){
    if(!/^\s*title\s*:/m.test(c) && !String(title || '').trim()) issues.push('Missing “title:”');
    if(!/^\s*logsource\s*:/m.test(c)) issues.push('Missing “logsource:” section');
    if(!/^\s*detection\s*:/m.test(c)) issues.push('Missing “detection:” section');
    if(!/^\s+condition\s*:/m.test(c)) issues.push('Missing “condition:” inside detection');
    if(/\t/.test(c)) issues.push('Tabs found — YAML needs spaces');
  } else {
    const m = c.match(/\brule\s+([A-Za-z_][A-Za-z0-9_]*)/); if(!m) issues.push('Missing “rule <name> {”');
    if(!/\bcondition\s*:/.test(c)) issues.push('Missing “condition:”');
    const o = (c.match(/\{/g) || []).length, cl = (c.match(/\}/g) || []).length; if(o !== cl) issues.push('Unbalanced braces (' + o + ' “{” vs ' + cl + ' “}”)');
  }
  return issues;
}
/* Sigma rules keep their title in the rule record; put it back into the YAML on the way out */
function ruleText(r, code){ const c = code == null ? r.code : code;
  return r.type === 'sigma' && !/^\s*title\s*:/m.test(c) && r.title ? 'title: ' + r.title + '\n' + c : c; }
/* tiny, safe syntax highlighter — every token is escaped */
const YARA_KW = /^(rule|private|global|meta|strings|condition|import|include|and|or|not|any|all|none|of|them|for|in|at|filesize|entrypoint|true|false|ascii|wide|nocase|fullword|xor|base64|base64wide|private|matches|contains|startswith|endswith|icontains|uint8|uint16|uint32|int8|int16|int32|uint16be|uint32be)$/;
function hlLine(type, line){
  const out = [], push = (cls, s) => out.push(cls ? `<span class="${cls}">${esc(s)}</span>` : esc(s));
  if(type === 'sigma'){
    const cm = line.match(/^(\s*)(#.*)$/); if(cm){ push('', cm[1]); push('k-c', cm[2]); return out.join(''); }
    let m = line.match(/^(\s*)(-\s+)?([A-Za-z0-9_.\-|*]+)(\s*:)(?=\s|$)/), rest = line;
    if(m){ push('', m[1]); if(m[2]) push('k-p', m[2]); const [k, ...mods] = m[3].split('|'); push(m[1].length ? 'k-k' : 'k-t', k); for(const md of mods){ push('k-p', '|'); push('k-m', md); } push('k-p', m[4]); rest = line.slice(m[0].length); }
    else { const d = line.match(/^(\s*)(-\s+)/); if(d){ push('', d[1]); push('k-p', d[2]); rest = line.slice(d[0].length); } }
    const isCond = m && m[3] === 'condition';
    rest.replace(/('[^']*'?|"[^"]*"?)|(#.*$)|(\b\d+(?:\.\d+)?\b)|(\b(?:and|or|not|of|them|all|1)\b)|([^'"#\d]+?(?=['"#]|\b\d|\b(?:and|or|not|of|them|all)\b|$))|([\s\S])/g, (all, str, com, num, kw, txt, ch) => {
      if(str) push('k-s', str); else if(com) push('k-c', com); else if(num) push('k-n', num); else if(kw) push(isCond ? 'k-w' : '', kw); else push(m && !isCond ? 'k-v' : isCond ? 'k-i' : 'k-v', txt || ch); return ''; });
    return out.join('');
  }
  line.replace(/(\/\/.*$)|(\/\*.*?(?:\*\/|$))|("(?:\\.|[^"\\])*"?)|(\{[0-9A-Fa-f?\s\[\]\-|()~]*\})|(\/(?:\\.|[^/\\\n])+\/[is]*)|([$#@!][A-Za-z0-9_]*\*?)|(\b0x[0-9A-Fa-f]+\b|\b\d+(?:KB|MB)?\b)|([A-Za-z_][A-Za-z0-9_]*)|([\s\S])/g, (all, lc, bc, str, hex, re, v, num, word, ch) => {
    if(lc || bc) push('k-c', all); else if(str) push('k-s', str); else if(hex) push('k-h', hex); else if(re) push('k-r', re); else if(v) push('k-i', v); else if(num) push('k-n', num);
    else if(word) push(YARA_KW.test(word) ? 'k-w' : '', word); else push(/[{}():=]/.test(ch) ? 'k-p' : '', ch); return ''; });
  return out.join('');
}
const hlCode = (type, code) => String(code).split('\n').map(l => hlLine(type, l)).join('\n');
const RTYPE = {sigma:['Sigma','scroll-text','#14b8a6','Log detection'], yara:['YARA','binary','#a78bfa','File & memory']};
const sevOf = s => SEV[s] || SEV.medium;
const rLay = () => ['table','gallery','ide'].includes(DB.prefs.rlay) ? DB.prefs.rlay : 'table';
const SEV_ORDER = {critical:4, high:3, medium:2, low:1, informational:0};
/* the ATT&CK stages a rule's techniques belong to */
const ruleTactics = r => { if(typeof ATTACK === 'undefined') return []; const T = ruleTactics.m || (ruleTactics.m = new Map(ATTACK.tech.map(t => [t[0], t[2]]))); return [...new Set((String(r.technique || '').match(/T\d{4}(?:\.\d{3})?/g) || []).flatMap(id => T.get(id) || T.get(id.split('.')[0]) || []))]; };
function viewDetections(){
  ensureRules();
  const lay = rLay(), q = (UI.dq || '').toLowerCase(), t = UI.dtype || 'all', sv = UI.dsev || '', dc = UI.dcat || '', pf = UI.dplat || '', lv = UI.dlvl || '';
  const words = q.split(/\s+/).filter(Boolean);
  let list = DB.rules.filter(r => (t === 'all' || r.type === t || (t === 'fav' && r.starred) || (t === 'case' && r.caseId === DB.active)) && (!sv || r.severity === sv) && (!dc || (r.category || 'other') === dc)
    && (!pf || r.platform === pf) && (!lv || (lv === 'mine' ? !r.builtin : (r.level || 'common') === lv)) && (!words.length || ((h) => words.every(w => h.includes(w)))(ruleHay(r))) && (!UI.dtac || ruleTactics(r).includes(UI.dtac)));
  const LIM = UI.dlim || 120, total = list.length;
  const sk = UI.rsk || 'modified', sd = UI.rsd || -1;
  const cmp = {title:(a, b) => a.title.localeCompare(b.title), type:(a, b) => a.type.localeCompare(b.type), severity:(a, b) => (SEV_ORDER[a.severity] || 0) - (SEV_ORDER[b.severity] || 0), technique:(a, b) => (a.technique || '~').localeCompare(b.technique || '~'), modified:(a, b) => a.modified - b.modified}[sk];
  list.sort((a, b) => lay === 'table' ? (cmp(a, b) * sd || a.title.localeCompare(b.title)) : (b.starred - a.starred) || b.modified - a.modified);
  UI.rShown = list.map(r => r.id);
  let cur = DB.rules.find(r => r.id === UI.rule) || null;
  if(lay === 'ide' && !cur && list[0]){ cur = list[0]; UI.rule = cur.id; }
  const open = cur && (lay === 'ide' || UI.ropen);
  const n = k => DB.rules.filter(r => r.type === k).length;
  const seg = layoutSeg('rLay', lay, [['table','table-2','Table'],['gallery','layout-grid','Gallery'],['ide','columns-3','IDE']]);
  const head = libHead('Detections', `${DB.rules.length} rules · ${n('sigma')} Sigma, ${n('yara')} YARA · ${DB.rules.filter(r => r.caseId).length} linked to cases${typeof lzHas === 'function' && !lzHas('rules') && !LZ.rules.failed ? ' · loading the built-in rules…' : ''}`,
    (typeof DQ_ACTS !== 'undefined' ? `<div class="seg dv-seg" role="group" aria-label="View">${[['rules','Rules','list'],['coverage','Coverage','grid-3x3'],['health','Health','activity'],['hunts','Hunts','crosshair']].map(([k, l, i]) => `<button data-act="dview" data-v="${k}" aria-pressed="${(UI.dview || 'rules') === k}">${ico(i,'sm')}${l}</button>`).join('')}</div>` : '') + `<button class="btn" data-act="rImport">${ico('upload','sm')}Import</button><button class="btn" data-act="rExportAll">${ico('download','sm')}Export</button><button class="btn" data-act="rFromCase">${ico('folder-open','sm')}From case</button><button class="btn primary" data-act="rNew">${ico('plus','sm')}New rule</button>`, seg);
  if(UI.dview === 'coverage' || UI.dview === 'health' || UI.dview === 'hunts') return `<div class="scroll"><div class="page wide">${head}${UI.dview === 'coverage' ? covView() : UI.dview === 'hunts' ? huntsView() : healthView()}</div></div>`;
  const search = `<div class="search-in">${ico('search')}<label class="sr" for="dq">Search rules</label><input id="dq" class="inp" placeholder="Search title, technique, content…" value="${esc(UI.dq || '')}"></div>`;
  const typeSeg = `<div class="seg">${[['all','All'],['sigma','Sigma'],['yara','YARA'],['fav','Starred'],['case','This case']].map(([v, l]) => `<button data-act="dtype" data-v="${v}" aria-pressed="${t === v}">${l}</button>`).join('')}</div>`;
  const plats = countBy(DB.rules, r => r.platform || '').filter(([k]) => k);
  const platSel = `<label class="sr" for="dplat">Platform</label><select id="dplat" class="gsel bord"><option value="">Any platform</option>${plats.map(([k, c]) => `<option value="${esc(k)}"${pf === k ? ' selected' : ''}>${esc(k)} (${c})</option>`).join('')}</select>`;
  const lvlSel = `<label class="sr" for="dlvl">Level</label><select id="dlvl" class="gsel bord"><option value="">Any level</option>${[['common','Common'],['advanced','Advanced'],['mine','Written by you']].map(([k, l]) => `<option value="${k}"${lv === k ? ' selected' : ''}>${l}</option>`).join('')}</select>`;
  const more = total > LIM ? `<div class="dmore"><span class="t3">Showing ${LIM} of ${total}</span><button class="btn" data-act="dMore">Show ${Math.min(200, total - LIM)} more</button></div>` : '';
  const sevSel = `<label class="sr" for="dsev">Severity</label><select id="dsev" class="gsel bord"><option value="">Any severity</option>${Object.entries(SEV).map(([k, [l]]) => `<option value="${k}"${sv === k ? ' selected' : ''}>${l}</option>`).join('')}</select>`;
  const typeTag = r => { const [tl, ti, tc] = RTYPE[r.type]; return `<span class="pill" style="--c:${tc}">${ico(ti,'sm')}${tl}</span>`; };
  const sevTag = r => { const [sl, sc] = sevOf(r.severity); return `<span class="sevt" style="--c:${sc}">${sl}</span>`; };
  const ago = r => esc(E.fmtAgo(Math.max(0, Date.now() - r.modified)));
  const none = empty('file-code','No rules match','Try another filter, write a new rule, or generate starter rules from the malicious entities in your case.', `<button class="btn primary" data-act="rNew">${ico('plus','sm')}New rule</button><button class="btn" data-act="rFromCase">${ico('folder-open','sm')}Generate from case</button>`);

  if(lay === 'gallery' && open) return `<div class="scroll"><div class="page fpage">
    <div class="fp-bar"><button class="btn ghost" data-act="rClose">${ico('arrow-left','sm')}All rules</button><span class="t3">${esc(RTYPE[cur.type][0])} rule</span></div>
    <section class="card fp-card">${ruleEditor(cur)}</section></div></div>`;

  if(lay === 'ide'){
    const cats = t2 => countBy(DB.rules.filter(r => r.type === t2), r => r.category || 'other');
    const node = (tv, cv, l, cnt, icon, sub) => `<button class="ide-n${sub ? ' sub' : ''}" data-act="dtree" data-v="${tv}|${cv}" aria-pressed="${t === tv && dc === cv}">${icon ? ico(icon,'sm') : '<i></i>'}<span>${esc(l)}</span><b>${cnt}</b></button>`;
    const cap = s => s.charAt(0).toUpperCase() + s.slice(1).replace(/[-_]/g, ' ');
    return `<div class="ide-wrap">${head}<div class="ide">
      <nav class="ide-tree" aria-label="Rule folders"><div class="ide-h">Rules</div>${node('all','','All rules',DB.rules.length,'layers')}${node('fav','','Starred',DB.rules.filter(r => r.starred).length,'star')}${node('case','','This case',DB.rules.filter(r => r.caseId === DB.active).length,'folder-open')}
        <div class="ide-h">Sigma</div>${node('sigma','','All Sigma',n('sigma'),'scroll-text')}${cats('sigma').map(([c, k]) => node('sigma', c, cap(c), k, '', true)).join('')}
        <div class="ide-h">YARA</div>${node('yara','','All YARA',n('yara'),'binary')}${cats('yara').map(([c, k]) => node('yara', c, cap(c), k, '', true)).join('')}</nav>
      <div class="ide-list"><div class="ide-lh">${search}<button class="iconbtn" data-act="rNew" aria-label="New rule" title="New rule">${ico('plus','sm')}</button></div>
        <div class="ide-items" data-vlsc>${list.length ? vlist('ideV', list.map(r => ({k:r.id, h:62, r:() => `<button class="ide-i" data-act="rSel" data-id="${esc(r.id)}" aria-current="${!!(cur && cur.id === r.id)}"><b>${esc(r.title)}${r.starred ? ` <span class="tstar">${ico('star','sm')}</span>` : ''}</b><small>${sevTag(r)}${esc([RTYPE[r.type][0], r.technique].filter(Boolean).join(' · '))}</small></button>`})), {focus:cur ? cur.id : null}) : '<p class="t3" style="padding:16px">No rules match.</p>'}</div></div>
      <section class="ide-ed">${cur ? ruleEditor(cur) : none}</section></div></div>`;
  }

  const body = !list.length ? none : lay === 'gallery'
    ? `<div class="gal">${list.slice(0, LIM).map(r => `<article class="gcard${rPicked(r.id) ? ' picked' : ''}" data-pick="${esc(r.id)}"><button class="gcard-hit" data-act="rSel" data-id="${esc(r.id)}" aria-label="Open ${esc(r.title)}"></button>
        <div class="gcard-h">${rPickBox(r)}${typeTag(r)}${sevTag(r)}<span style="flex:1"></span><button class="tb-ic${r.starred ? ' on star' : ''}" data-act="rStar" data-id="${esc(r.id)}" aria-label="Star">${ico('star','sm')}</button></div>
        <h3>${esc(r.title)}</h3>${r.desc ? `<p>${esc(r.desc)}</p>` : ''}
        <pre class="gcode hl">${hlCode(r.type, r.code.split('\n').slice(0, 7).join('\n'))}</pre>
        <div class="gcard-f"><span class="mono t3">${esc(r.technique || '—')}</span>${r.platform ? `<span class="t3">· ${esc(r.platform)}</span>` : ''}<span style="flex:1"></span><span class="t3">${ago(r)}</span></div></article>`).join('')}</div>${more}`
    : `<div class="card dtw"><table class="dt"><thead><tr><th class="c-pick"><label class="tpk"><span class="sr">Select all ${total} shown</span><input type="checkbox" data-act="rPickAll" aria-label="Select all ${total} shown"${total && list.every(r => rPicked(r.id)) ? ' checked' : ''}></label></th><th class="c-star"></th>${sortTh('rSort','title',sk,sd,'Rule')}${sortTh('rSort','type',sk,sd,'Type','c-cat')}${sortTh('rSort','severity',sk,sd,'Severity','c-sev')}${sortTh('rSort','technique',sk,sd,'Technique','c-tech')}<th class="c-plat">Platform</th>${sortTh('rSort','modified',sk,sd,'Updated','c-upd')}<th class="c-act"></th></tr></thead>
      ${vlist('dtV', list.map(r => ({k:r.id, h:66, r:() => { const c = r.caseId ? theCase(r.caseId) : null;
        return `<tr data-act="rSel" data-id="${esc(r.id)}" data-pick="${esc(r.id)}" class="${rPicked(r.id) ? 'sel' : ''}" aria-current="${!!(open && cur.id === r.id)}" tabindex="0">
          <td class="c-pick">${rPickBox(r)}</td><td class="c-star"><button class="tb-ic${r.starred ? ' on star' : ''}" data-act="rStar" data-id="${esc(r.id)}" aria-label="Star">${ico('star','sm')}</button></td>
          <td class="c-name"><b>${esc(r.title)}</b><span>${esc(r.desc || '')}</span>${c ? `<em class="c-case" style="--c:${esc(c.color)}">${esc(caseNm(c))}</em>` : ''}</td>
          <td class="c-cat">${typeTag(r)}</td><td class="c-sev">${sevTag(r)}</td><td class="c-tech mono">${esc(r.technique || '—')}</td><td class="c-plat">${esc(r.platform || '—')}</td><td class="c-upd">${ago(r)}</td>
          <td class="c-act">${ico('chevron-right','sm')}</td></tr>`; }})), {tbody:true, cols:9})}</table></div>`;
  return `<div class="scroll"><div class="page wide">${head}
    <div class="toolbar ltb">${search}${typeSeg}${sevSel}${platSel}${lvlSel}${UI.dtac ? `<span class="chip accent">Stage: ${esc((ATTACK.tactics.find(t => t[1] === UI.dtac) || [,,UI.dtac])[2])} <button data-act="dtacOff" aria-label="Clear stage filter">${ico('x','sm')}</button></span>` : ''}<span style="flex:1"></span><span class="t3 lcount">${total} rule${total === 1 ? '' : 's'}</span></div>
    <div class="tbk rbk" id="rbk" role="toolbar" aria-label="Selected rules"${rPickN() ? '' : ' hidden'}>${rBulkInner()}</div>
    ${body}</div></div>${lay === 'table' && open ? drawer(ruleEditor(cur), 'rClose', cur.title, ico(RTYPE[cur.type][1],'sm') + RTYPE[cur.type][0] + ' rule') : ''}`;
}
function ruleEditor(r){
  const issues = validateRule(r.type, r.code, r.title), [tl, ti, tc, td] = RTYPE[r.type], [sl, sc] = sevOf(r.severity), c = r.caseId ? theCase(r.caseId) : null;
  const tab = UI.rtab || 'rule';
  return `<form data-form="rule" data-id="${esc(r.id)}" class="rx">
    <div class="rx-h"><span class="pill" style="--c:${tc}">${ico(ti,'sm')}${tl} · ${td}</span><span class="pill" style="--c:${sc}" id="rSevPill">${sl}</span>${c ? `<a class="pill" href="${caseHash(c.id)}" style="--c:${esc(c.color)}">${ico('folder-open','sm')}${esc(caseNm(c))}</a>` : ''}
      <span style="flex:1"></span><span class="rx-dirty">Unsaved changes</span>
      <button type="button" class="iconbtn${r.starred ? ' on' : ''}" data-act="rStar" data-id="${esc(r.id)}" aria-label="${r.starred ? 'Unstar' : 'Star'}" title="Star">${ico('star','sm')}</button>
      <button type="button" class="iconbtn" data-act="rMenu" data-id="${esc(r.id)}" aria-label="More actions" title="More">${ico('ellipsis','sm')}</button></div>
    <div class="rx-ttw"><label class="sr" for="rTitle">Title</label><input id="rTitle" class="rx-title" value="${esc(r.title)}" required autocomplete="off" placeholder="Rule title" aria-describedby="rTitleWarn"><p class="ferr" id="rTitleWarn" role="status" hidden></p></div>
    <label class="sr" for="rDesc">Description</label><input id="rDesc" class="rx-desc" value="${esc(r.desc)}" placeholder="What does this detect, and why does it matter?" autocomplete="off">
    ${typeof ruleSummary === 'function' ? ruleSummary(r) : ''}
    <div class="rx-tabs" role="tablist"><button type="button" role="tab" data-rtab="rule" aria-selected="${tab === 'rule'}">${ico('code','sm')}Rule</button><button type="button" role="tab" data-rtab="meta" aria-selected="${tab === 'meta'}">${ico('tag','sm')}Details</button><button type="button" role="tab" data-rtab="tests" aria-selected="${tab === 'tests'}">${ico('circle-check','sm')}Tests${(r.tests || []).length ? ' <span class="t3">' + r.tests.length + '</span>' : ''}</button><button type="button" role="tab" data-rtab="history" aria-selected="${tab === 'history'}">${ico('history','sm')}History${typeof rvList === 'function' && rvList(r).length ? ' <span class="t3">' + rvList(r).length + '</span>' : ''}</button>${r.type === 'sigma' ? `<button type="button" role="tab" data-rtab="queries" aria-selected="${tab === 'queries'}">${ico('terminal','sm')}Queries</button><button type="button" role="tab" data-rtab="evasion" aria-selected="${tab === 'evasion'}">${ico('shield-alert','sm')}Evasion</button>` : ''}
      <span style="flex:1"></span><span class="rx-edited">Edited ${esc(E.fmtAgo(Math.max(0, Date.now() - r.modified)))}</span></div>
    <div class="rx-pane" data-pane="rule"${tab === 'rule' || !/^(meta|tests|queries|evasion|history)$/.test(tab) ? '' : ' hidden'}>
      <div class="cx"><div class="cx-g" id="rGut" aria-hidden="true"></div><div class="cx-ed"><pre class="cx-hl" id="rHl" aria-hidden="true"></pre>
        <label class="sr" for="rCode">Rule source</label><textarea id="rCode" spellcheck="false" autocapitalize="off" autocomplete="off" wrap="off">${esc(r.code)}</textarea></div></div>
      <div class="cx-bar" id="rStatus"></div>
      <div class="rtest"><button type="button" class="btn sm" data-act="rTest" data-id="${esc(r.id)}">${ico('play','sm')}Test against ${esc((caseNm(theCase()) || 'case'))} evidence</button>${r.type === 'yara' ? `<button type="button" class="btn sm" data-act="rTestFile" data-id="${esc(r.id)}">${ico('file-search','sm')}Scan a file…</button>` : ''}<span class="t3">Runs locally on the current rule text — saved or not.</span></div>
      <div id="rTestOut"></div>
      ${r.type === 'sigma' && !/^\s*title\s*:/m.test(r.code) ? `<p class="hint rx-note">${ico('circle-help','sm')}The title above is added as <span class="mono">title:</span> when you copy or download this rule.</p>` : ''}</div>
    <div class="rx-pane" data-pane="lab"${/^(tests|queries|evasion|history)$/.test(tab) ? '' : ' hidden'}><div id="dlPane" aria-live="polite"></div></div>
    <div class="rx-pane" data-pane="meta"${tab === 'meta' ? '' : ' hidden'}>
      <div class="frow"><div class="field"><label for="rSev">Severity</label><select id="rSev">${Object.entries(SEV).map(([k, [l]]) => `<option value="${k}"${r.severity === k ? ' selected' : ''}>${l}</option>`).join('')}</select></div>
        <div class="field"><label for="rTech">ATT&amp;CK technique</label><input id="rTech" value="${esc(r.technique)}" placeholder="T1059.001" class="mono"></div></div>
      <div class="frow"><div class="field"><label for="rPlat">Platform</label><input id="rPlat" value="${esc(r.platform)}" placeholder="Windows, Linux, Any…"></div>
        <div class="field"><label for="rCase">Linked case</label><select id="rCase"><option value="">None</option>${DB.cases.map(x => `<option value="${x.id}"${r.caseId === x.id ? ' selected' : ''}>${esc(x.name)}</option>`).join('')}</select></div></div>
      <div class="frow"><div class="field"><label for="rAuthor">Author</label><input id="rAuthor" value="${esc(r.author)}"></div>
        <div class="field"><label for="rTags">Tags</label><input id="rTags" value="${esc(r.tags.join(', '))}" placeholder="comma, separated"></div></div>
      <p class="hint">Created ${esc(new Date(r.created).toISOString().slice(0, 10))} · ${r.code.split('\n').length} lines · ${esc(r.id)}</p></div>
    <div class="rx-f"><span class="t3 rx-kb"><kbd>Ctrl</kbd> <kbd>S</kbd> to save</span><span style="flex:1"></span>
      <button class="btn" type="button" data-act="rRevert" data-id="${esc(r.id)}" disabled title="Throw away the edits you have not saved and go back to the saved rule">Discard changes</button><button class="btn primary" type="submit">${ico('check','sm')}Save rule</button></div></form>`;
}
function bindRuleEditor(){
  const ta = $('rCode'), r = DB.rules.find(z => z.id === UI.rule); if(!ta || !r) return;
  const f = ta.form, hl = $('rHl'), gut = $('rGut'), st = $('rStatus');
  const snap = () => [...f.querySelectorAll('input,select,textarea')].filter(i => !i.closest('#dlPane')).map(i => i.value).join('\u0001'); const base = snap();
  let vt = null;
  const status = () => { const iss = validateRule(r.type, ta.value, $('rTitle').value), n = ta.value.split('\n').length;
    st.className = 'cx-bar ' + (iss.length ? 'bad' : 'ok');
    st.innerHTML = `<span class="cx-v">${ico(iss.length ? 'triangle-alert' : 'circle-check','sm')}${iss.length ? iss.map(esc).join(' · ') : 'Structure OK'}</span><span style="flex:1"></span><span>${n} line${n > 1 ? 's' : ''}</span><span>${RTYPE[r.type][0]}</span><span class="hide-m" title="Checks required sections only — test in your SIEM or with yara before deploying">Structural check only</span>`; };
  const paint = () => { hl.innerHTML = hlCode(r.type, ta.value) + '\n'; const n = ta.value.split('\n').length; ta.rows = n;
    gut.innerHTML = Array.from({length:n}, (_, i) => `<span>${i + 1}</span>`).join(''); };
  const rv = f.querySelector('[data-act=rRevert]'), dirty = () => { const d = snap() !== base; f.classList.toggle('dirty', d); if(rv) rv.disabled = !d; };
  ta.addEventListener('input', () => { paint(); dirty(); clearTimeout(vt); vt = setTimeout(status, 200); });
  const tw = $('rTitleWarn'), tcheck = () => { if(!tw) return; const v = $('rTitle').value.trim().replace(/\s+/g, ' '), x = v && clash(DB.rules, v, 'title', r.id); tw.hidden = !x; tw.textContent = x ? `A rule called “${v}” already exists — rename this one before saving.` : ''; $('rTitle').classList.toggle('invalid', !!x); };
  f.addEventListener('input', ev => { if(ev.target !== ta) dirty(); if(ev.target.id === 'rTitle'){ tcheck(); clearTimeout(vt); vt = setTimeout(status, 200); } });
  f.addEventListener('change', ev => { dirty(); if(ev.target.id === 'rSev'){ const [l, c] = sevOf(ev.target.value), p = $('rSevPill'); if(p){ p.textContent = l; p.style.setProperty('--c', c); } } });
  ta.addEventListener('keydown', ev => {
    if(ev.key === 'Tab' && !ev.shiftKey && !ev.ctrlKey && !ev.altKey){ ev.preventDefault(); const s = ta.selectionStart; ta.setRangeText('    ', s, ta.selectionEnd, 'end'); ta.dispatchEvent(new Event('input', {bubbles:true})); }
    if(ev.key === 'Enter' && !ev.ctrlKey && !ev.metaKey){ const s = ta.selectionStart, ls = ta.value.lastIndexOf('\n', s - 1) + 1, ind = (ta.value.slice(ls, s).match(/^\s*/) || [''])[0] + (/[:{]\s*$/.test(ta.value.slice(ls, s)) ? '    ' : '');
      if(ind){ ev.preventDefault(); ta.setRangeText('\n' + ind, s, ta.selectionEnd, 'end'); ta.dispatchEvent(new Event('input', {bubbles:true})); } } });
  f.addEventListener('keydown', ev => { if((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 's'){ ev.preventDefault(); f.requestSubmit(); } });
  f.querySelectorAll('[data-rtab]').forEach(b => b.onclick = () => { UI.rtab = b.dataset.rtab; f.querySelectorAll('[data-rtab]').forEach(x => x.setAttribute('aria-selected', String(x === b)));
    const pane = /^(tests|queries|evasion|history)$/.test(UI.rtab) ? 'lab' : UI.rtab; f.querySelectorAll('[data-pane]').forEach(p => p.hidden = p.dataset.pane !== pane); if(pane === 'lab') dlPaneFill(); });
  paint(); status(); tcheck(); if(/^(tests|queries|evasion|history)$/.test(UI.rtab || '')) dlPaneFill();
}
/* picking several rules at once: star, download or delete them together */
const rPicked = id => !!(UI.rpick && UI.rpick.has(id));
const rPickBox = r => `<label class="tpk"><span class="sr">Select ${esc(r.title)}</span><input type="checkbox" data-act="rPick" data-id="${esc(r.id)}"${rPicked(r.id) ? ' checked' : ''}></label>`;
const rPickedRules = () => UI.rpick ? DB.rules.filter(r => UI.rpick.has(r.id)) : [];
const rPickN = () => rPickedRules().length;
function rBulkInner(){
  const xs = rPickedRules(), n = xs.length, shown = (UI.rShown || []).length; if(!n) return '';
  const allOn = xs.every(r => r.starred);
  return `<b>${n} selected</b>${shown > n ? `<button class="btn xs" data-act="rbAll">Select all ${shown} shown</button>` : ''}<span class="sep"></span>
    <button class="btn xs" data-act="rbStar">${ico('star','sm')}${allOn ? 'Unstar' : 'Star'}</button><button class="btn xs" data-act="rbDl">${ico('download','sm')}Download</button>
    <button class="btn xs rd" data-act="rbDel">${ico('trash-2','sm')}Delete</button><button class="iconbtn" data-act="rbClear" aria-label="Clear selection">${ico('x','sm')}</button>`;
}
function paintRBulk(){
  const el = $('rbk'); if(!el) return; const n = rPickN(); el.hidden = !n; el.innerHTML = rBulkInner();
  const all = document.querySelector('[data-act=rPickAll]'), shown = UI.rShown || []; if(all){ all.checked = !!shown.length && shown.every(rPicked); all.indeterminate = !all.checked && shown.some(rPicked); }
}
const ruleExportObj = r => ({type:r.type, title:r.title, description:r.desc, code:ruleText(r), severity:r.severity, category:r.category, technique:r.technique, author:r.author, platform:r.platform, tags:r.tags, refs:r.refs || [], starred:!!r.starred, caseId:r.caseId || null, created:r.created, tests:r.tests && r.tests.length ? r.tests : undefined, versions:typeof rvList === 'function' && rvList(r).length ? rvList(r) : undefined, testHist:typeof dlHist === 'function' && dlHist(r).length ? dlHist(r) : undefined});
const ruleFileName = r => safeName(slug(r.title) || 'rule').slice(0, 60) + (r.type === 'yara' ? '.yar' : '.yml');
/* one rule: its .yml / .yar file. Several: a zip with each rule's file, and a JSON bundle that Import reads back with tests and metadata */
function rulesDownload(xs){
  if(!xs.length) return; if(xs.length === 1) return download(ruleFileName(xs[0]), ruleText(xs[0]), 'text/plain');
  const used = new Set(), files = xs.map(r => { let n = ruleFileName(r), i = 2; while(used.has(n)) n = ruleFileName(r).replace(/(\.\w+)$/, '-' + i++ + '$1'); used.add(n); return {name:'osintrix-rules/' + (r.type === 'yara' ? 'yara/' : 'sigma/') + n, data:ruleText(r)}; });
  files.push({name:'osintrix-rules/osintrix-detections.json', data:JSON.stringify(xs.map(ruleExportObj), null, 2)});
  try{ const blob = nbZip(files), a = document.createElement('a'), u = URL.createObjectURL(blob); a.href = u; a.download = 'osintrix-rules-' + xs.length + '.zip'; document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(u); a.remove(); }, 150); toast('Saved ' + xs.length + ' rules as a zip'); }
  catch(e){ toast('The browser blocked the download'); }
}
const RB_ACTS = {
  rPick:(id, v, t) => { const s = UI.rpick || (UI.rpick = new Set()); t.checked ? s.add(id) : s.delete(id); const c = t.closest('[data-pick]'); if(c) c.classList.toggle(c.tagName === 'TR' ? 'sel' : 'picked', t.checked); paintRBulk(); },
  rPickAll:(id, v, t) => { const s = UI.rpick || (UI.rpick = new Set()); (UI.rShown || []).forEach(x => t.checked ? s.add(x) : s.delete(x)); renderMain(); },
  rbAll:() => { const s = UI.rpick || (UI.rpick = new Set()); (UI.rShown || []).forEach(x => s.add(x)); renderMain(); },
  rbClear:() => { UI.rpick = new Set(); renderMain(); },
  rbStar:() => { const xs = rPickedRules(), on = !xs.every(r => r.starred); xs.forEach(r => r.starred = on); mutate((on ? 'starred ' : 'unstarred ') + xs.length + ' rules'); renderMain(); toast(xs.length + ' rule' + (xs.length > 1 ? 's ' : ' ') + (on ? 'starred' : 'unstarred')); },
  rbDl:() => rulesDownload(rPickedRules()),
  rbDel:() => { const xs = rPickedRules(); if(!xs.length) return; const bi = xs.filter(r => r.builtin).length;
    confirmDlg('Delete ' + xs.length + ' rule' + (xs.length > 1 ? 's' : '') + '?', (bi ? bi + ' of them came with OSINTrix and stay deleted when the app updates its rules. ' : '') + 'You can undo right after.', 'Delete ' + xs.length, () => {
      const prev = DB.rules.slice(), prevGone = (DB.deletedRules || []).slice(), gone = new Set(xs.map(r => r.id));
      DB.rules = DB.rules.filter(r => !gone.has(r.id)); if(bi) DB.deletedRules = [...new Set([...prevGone, ...xs.filter(r => r.builtin).map(r => r.id)])];
      if(gone.has(UI.rule)){ UI.rule = null; UI.ropen = false; } UI.rpick = new Set(); const txs = xs.map(r => trashPut('rule', r.title, {r})); closeDlg(); mutate('deleted ' + xs.length + ' rules'); renderAll();
      toast('Deleted ' + xs.length + ' rule' + (xs.length > 1 ? 's' : '') + ' — in the trash', 'Undo', () => { txs.forEach(trashUndo); DB.rules = prev; DB.deletedRules = prevGone; mutate('restored ' + xs.length + ' rules'); renderAll(); }); }); },
};
const ruleDirty = () => { const f = document.querySelector('form.rx'); return !!(f && f.classList.contains('dirty')); };
function ruleFromCase(){
  const c = theCase(), D = derive(); const mal = new Map();
  for(const e of D.entries) if(entryVerdict(e) === 'malicious'){ const k = entryKey(e); if(k) mal.set(k, primary(e)); }
  for(const [id] of D.ents) if(verdictOf(id) === 'malicious') mal.set(id, entSplit(id).v);
  if(!mal.size) return toast('Mark some entities malicious in this case first');
  const by = k => [...mal.keys()].filter(id => id.startsWith(k + ':')).map(id => mal.get(id));
  const ips = by('ipv4'), doms = by('domain'), urls = by('url'), hashes = by('sha256').concat(by('md5'), by('sha1')), ports = by('hostport');
  const slugId = c.code.toLowerCase().replace(/[^a-z0-9]+/g, '_');
  const sig = `title: ${c.name.split(' — ')[0]} — network indicators\nid: ${crypto.randomUUID ? crypto.randomUUID() : slugId}\nstatus: experimental\ndescription: Connections to infrastructure judged malicious in ${c.code}. Generated by OSINTrix — review before use.\nreferences:\n    - ${c.code}\nlogsource:\n    category: network_connection\n    product: windows\ndetection:\n    selection_ip:\n        DestinationIp:\n${(ips.length ? ips : ['0.0.0.0']).map(v => '            - ' + v).join('\n')}\n${doms.length ? `    selection_dns:\n        DestinationHostname|endswith:\n${doms.map(v => '            - ' + v).join('\n')}\n` : ''}    condition: 1 of selection_*\nlevel: high`;
  const strs = [...doms, ...urls, ...ips].slice(0, 20).map((v, i) => `        $n${i} = "${v.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}" ascii wide nocase`);
  const yar = `rule ${slugId}_indicators {\n    meta:\n        description = "Strings from ${c.name.split(' — ')[0].replace(/"/g, '')}. Generated by OSINTrix — review before use."\n        author = "You"\n        case = "${c.code}"\n${hashes.length ? hashes.map(h => `        hash = "${h}"`).join('\n') + '\n' : ''}    strings:\n${strs.join('\n')}\n    condition:\n        any of them\n}`;
  const now = Date.now();
  const a = {id:uid('r'), type:'sigma', title:c.name.split(' — ')[0] + ' — network indicators', desc:'Generated from ' + mal.size + ' malicious entities in ' + c.code, code:sig, severity:'high', category:'network', technique:'T1071', author:'You', platform:'Windows', tags:['generated', c.code], refs:[], created:now, modified:now, starred:false, caseId:c.id};
  const b = {id:uid('r'), type:'yara', title:c.name.split(' — ')[0] + ' — indicator strings', desc:'Generated from ' + mal.size + ' malicious entities in ' + c.code, code:yar, severity:'high', category:'malware', technique:'', author:'You', platform:'Any', tags:['generated', c.code], refs:[], created:now, modified:now, starred:false, caseId:c.id};
  DB.rules.unshift(a, b); UI.rule = a.id; UI.ropen = true; UI.dview = 'rules'; UI.rtab = 'rule'; UI.dtype = 'all'; UI.dcat = ''; mutate('generated 2 rules from ' + caseNm(c));
  if(UI.route.area !== 'detections') go('#/detections'); else renderMain();
  toast('Two starter rules generated from ' + mal.size + ' malicious entities — review before use');
}
/* importRules() lives in rulepack.js: a preview of what is new, already here, or clashes, before anything changes */
