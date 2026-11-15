/* ==========================================================================
   Rule packs — move your rules between computers (or keep a set aside) with
   their tests and history. Export: pick rules → Download (a zip with each
   rule's file and a JSON bundle), or Export all. Import: .yml / .yar / .json
   files or that zip. Before anything changes you see what is new, what you
   already have (identical logic — skipped, but tests it brings are added),
   and what clashes with one of yours (same title, different logic): keep
   both, replace yours (yours stays in the rule's history), or skip.
   One Undo takes the whole import back.
   ========================================================================== */
const rpNorm = x => String(x || '').replace(/\r\n?/g, '\n').replace(/[ \t]+$/gm, '').replace(/^\s*title\s*:.*\n/m, '').trim();
/* one file → candidate rules */
function rpParse(name, txt){
  const out = [];
  if(/\.json$/i.test(name)){ let d; try{ d = JSON.parse(txt); }catch(e){ return out; }
    for(const r of (Array.isArray(d) ? d : d && Array.isArray(d.rules) ? d.rules : [d])) if(r && typeof r.code === 'string' && r.code.trim() && /^(sigma|yara)$/.test(r.type) && r.code.length <= 200000)
      out.push({src:name, rich:true, type:r.type, title:String(r.title || name).trim().slice(0, 150), desc:String(r.description || r.desc || '').slice(0, 2000), code:r.code, severity:/^(informational|low|medium|high|critical)$/i.test(r.severity || '') ? String(r.severity).toLowerCase() : 'medium',
        category:String(r.category || '').slice(0, 60), technique:String(r.technique || '').slice(0, 200), author:String(r.author || '').slice(0, 120), platform:String(r.platform || '').slice(0, 60), tags:Array.isArray(r.tags) ? r.tags.map(String).slice(0, 30) : [],
        refs:Array.isArray(r.refs) ? r.refs.filter(u => typeof u === 'string' && E.safeUrl(u)).slice(0, 30) : [], starred:r.starred === true, created:+r.created || Date.now(), tests:typeof normRuleTests === 'function' ? normRuleTests(r.tests) : [],
        versions:typeof rvList === 'function' ? rvList({versions:r.versions}).map(v => ({at:+v.at, title:String(v.title || '').slice(0, 150), code:v.code, severity:String(v.severity || ''), technique:String(v.technique || ''), desc:String(v.desc || '').slice(0, 2000)})) : [],
        testHist:Array.isArray(r.testHist) ? r.testHist.filter(h => h && +h.at && +h.total > 0 && +h.pass >= 0 && +h.pass <= +h.total).map(h => ({at:+h.at, pass:+h.pass, total:+h.total})).slice(-30) : []});
    return out; }
  if(txt.length > 1048576) return out;
  const yara = /\brule\s+\w+\s*[:{]/.test(txt) && !/^\s*title\s*:/m.test(txt);
  for(const part of yara ? [txt] : txt.split(/^---\s*$/m).filter(p => p.trim())){
    if(!yara && !/^\s*detection\s*:/m.test(part)) continue;
    const title = yara ? ((part.match(/\brule\s+(\w+)/) || [])[1] || name) : ((part.match(/^\s*title\s*:\s*(.+)$/m) || [])[1] || name);
    out.push({src:name, type:yara ? 'yara' : 'sigma', title:title.trim().replace(/^['"]|['"]$/g, '').slice(0, 150), desc:((part.match(/^\s*description\s*:\s*(.+)$/m) || part.match(/description\s*=\s*"([^"]+)"/) || [])[1] || '').trim().slice(0, 2000), code:part.trim(),
      severity:((part.match(/^\s*level\s*:\s*(\w+)/m) || [])[1] || 'medium').toLowerCase().replace(/^(?!informational|low|medium|high|critical).*$/, 'medium'), category:'', technique:((part.match(/attack\.(t\d{4}(?:\.\d{3})?)/gi) || []).map(t => t.split('.').slice(1).join('.').toUpperCase()).join(', ')), author:((part.match(/^\s*author\s*:\s*(.+)$/m) || [])[1] || '').trim().slice(0, 120), platform:'', tags:[], refs:[], tests:[], versions:[], testHist:[]}); }
  return out;
}
async function rpRead(files){
  const C = [];
  for(const f of [...files].slice(0, 50)){ if(f.size > 20 * 1048576) continue;
    if(/\.zip$/i.test(f.name)){ let Z; try{ Z = await nbUnzip(new Uint8Array(await f.arrayBuffer())); }catch(e){ toast('Could not open ' + f.name + ': ' + e.message); continue; }
      /* the JSON bundle first: it carries tests and history; the loose files then repeat it and are folded in */
      const names = Z.names.filter(n => /\.(json|ya?ml|yara?|txt)$/i.test(n) && !/(^|\/)(__MACOSX|\.)/.test(n)).sort((a, b) => /\.json$/i.test(b) - /\.json$/i.test(a)).slice(0, 2000);
      for(const n of names){ try{ const u = await Z.get(n); if(u && u.length <= 1048576 * 5) C.push(...rpParse(n.split('/').pop(), new TextDecoder().decode(u))); }catch(e){} } }
    else C.push(...rpParse(f.name, await f.text())); }
  return C;
}
/* what each candidate would do */
function rpPlan(C){
  const byCode = new Map(DB.rules.map(r => [rpNorm(r.code), r])), byTitle = new Map(DB.rules.map(r => [normName(r.title), r])), seen = new Map(), P = [];
  for(const c of C){ const k = rpNorm(c.code); if(!k) continue;
    if(seen.has(k)){ const x = seen.get(k); if(c.rich && !x.c.rich) x.c = c; continue; }                   // the same rule twice in the pack
    const same = byCode.get(k), clash = !same && byTitle.get(normName(c.title));
    const item = {c, kind:same ? 'same' : clash && clash.type === c.type ? 'clash' : 'new', mine:same || clash || null, choice:'both'}; seen.set(k, item); P.push(item); }
  for(const it of P) if(it.kind === 'same'){ const have = new Set((it.mine.tests || []).map(t => t.kind + '\u0000' + t.text)); it.newTests = (it.c.tests || []).filter(t => !have.has(t.kind + '\u0000' + t.text)); }
  return P;
}
let RP = null;
function rpDlg(){
  const P = RP, nw = P.filter(x => x.kind === 'new'), same = P.filter(x => x.kind === 'same'), cl = P.filter(x => x.kind === 'clash'), tadd = same.reduce((n, x) => n + x.newTests.length, 0);
  const row = x => `<li><span class="pill" style="--c:${RTYPE[x.c.type][2]}">${RTYPE[x.c.type][0]}</span><b>${esc(x.c.title)}</b>${x.c.tests && x.c.tests.length ? `<span class="t3">${x.c.tests.length} test${x.c.tests.length > 1 ? 's' : ''}</span>` : ''}${x.c.versions && x.c.versions.length ? `<span class="t3">${x.c.versions.length} earlier version${x.c.versions.length > 1 ? 's' : ''}</span>` : ''}</li>`;
  openDlg(dhead('Import rules') + `<div class="in rp">
    <div class="tlx-kpi"><div><b>${nw.length}</b><span>new</span></div><div><b>${same.length}</b><span>already here</span></div><div class="${cl.length ? 'a' : ''}"><b>${cl.length}</b><span>same title, different logic</span></div></div>
    ${cl.length ? `<h3>Same title as one of yours, different logic</h3><ul class="rp-l">${cl.map((x, i) => `<li><div><b>${esc(x.c.title)}</b><small class="t3">Yours was last changed ${esc(iAgo(x.mine.modified || x.mine.created || Date.now()))}${x.c.src ? ' · from ' + esc(x.c.src) : ''}</small></div>
      <label class="sr" for="rpC${i}">What to do with ${esc(x.c.title)}</label><select id="rpC${i}" class="gsel bord" data-rp="${i}"><option value="both">Keep both</option><option value="replace">Replace mine (mine stays in its history)</option><option value="skip">Skip</option></select></li>`).join('')}</ul>` : ''}
    ${nw.length ? `<h3>New</h3><ul class="rp-l plain">${nw.slice(0, 200).map(row).join('')}</ul>${nw.length > 200 ? `<p class="t3">and ${nw.length - 200} more</p>` : ''}` : ''}
    ${same.length ? `<p class="t2">${same.length} rule${same.length > 1 ? 's are' : ' is'} already here with the same logic and will be skipped${tadd ? ` — ${tadd} test${tadd > 1 ? 's' : ''} they bring will be added to yours` : ''}.</p>` : ''}
    ${!P.length ? '<p class="t2">No Sigma or YARA rules found in those files.</p>' : ''}</div>
    <footer><button class="btn" data-act="dclose">Cancel</button>${P.length ? `<button class="btn primary" data-act="rpGo">${ico('download','sm')}Import</button>` : ''}</footer>`);
}
function rpApply(){
  const P = RP; if(!P) return; const before = JSON.parse(JSON.stringify(DB.rules)), cl = P.filter(x => x.kind === 'clash'); let n = 0, rep = 0, tests = 0;
  document.querySelectorAll('#dlg [data-rp]').forEach(s => { const x = cl[+s.dataset.rp]; if(x) x.choice = s.value; });
  const add = c => { DB.rules.unshift({id:uid('r'), type:c.type, title:importName(c.title, DB.rules.map(x => x.title)), desc:c.desc, code:c.code, severity:c.severity, category:c.category, technique:c.technique, author:c.author, platform:c.platform, tags:c.tags, refs:c.refs,
    created:c.created || Date.now(), modified:Date.now(), starred:!!c.starred, caseId:null, tests:c.tests, ...(c.versions.length ? {versions:c.versions} : {}), ...(c.testHist.length ? {testHist:c.testHist} : {})}); n++; };
  for(const x of P){
    if(x.kind === 'new' || (x.kind === 'clash' && x.choice === 'both')) add(x.c);
    else if(x.kind === 'clash' && x.choice === 'replace'){ const r = x.mine; if(typeof rvKeep === 'function') rvKeep(r, x.c);
      Object.assign(r, {code:x.c.code, desc:x.c.desc || r.desc, severity:x.c.severity, technique:x.c.technique || r.technique, modified:Date.now()});
      const have = new Set((r.tests || []).map(t => t.kind + '\u0000' + t.text)); r.tests = [...(r.tests || []), ...x.c.tests.filter(t => !have.has(t.kind + '\u0000' + t.text))]; rep++; }
    else if(x.kind === 'same' && x.newTests.length){ x.mine.tests = [...(x.mine.tests || []), ...x.newTests]; tests += x.newTests.length; } }
  RP = null; closeDlg(); if(!n && !rep && !tests) return toast('Nothing to import — you have all of these');
  mutate('imported rules'); UI.rule = n ? DB.rules[0].id : UI.rule; renderAll();
  toast([n ? n + ' rule' + (n > 1 ? 's' : '') + ' added' : '', rep ? rep + ' replaced' : '', tests ? tests + ' test' + (tests > 1 ? 's' : '') + ' added to yours' : ''].filter(Boolean).join(', '), 'Undo', () => { DB.rules = before; mutate('undid a rule import'); renderAll(); });
}
function importRules(){
  const i = document.createElement('input'); i.type = 'file'; i.multiple = true; i.accept = '.yml,.yaml,.yar,.yara,.json,.txt,.zip';
  i.onchange = async () => { RP = rpPlan(await rpRead(i.files)); rpDlg(); };
  i.click();
}
const RP_ACTS = { rpGo:() => rpApply() };
