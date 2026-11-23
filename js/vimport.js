/* ==========================================================================
   Vault → Import: bring earlier work from other tools into a case, as vault
   entries and the links between them —
     · Maltego (.mtgx, or a graph exported as GraphML)
     · any GraphML (yEd, Gephi, an OSINTrix export)
     · SpiderFoot scan results (CSV)
     · any CSV of values, or of links (source, target, relationship)
   Every kind of thing in the file is matched to an entry type you can change
   (or skip) before anything is added; values already in the case are reused,
   not duplicated; the whole import can be undone. Read here, nothing sent.
   ========================================================================== */
const VIM = {MAX_BYTES:60 << 20, MAX_NODES:20000, MAX_EDGES:60000, MAX_VAL:2000};
/* a source kind → our entry type, by the words in its name */
const VIM_GUESS = [[/ipv?[46]?[ _-]?addr|^ip$|ipaddress|^ipv[46]$/i, 'ip'], [/e-?mail/i, 'email'], [/^url$|linked url|\burl\b|website|webpage/i, 'url'], [/domain|dns ?name|internet name|fqdn|hostname|mx ?record|ns ?record|co-hosted/i, 'domain'],
  [/phone|telephone|mobile/i, 'phone'], [/person|human name|^name$|full ?name/i, 'person'], [/compan|organi[sz]ation|^org$/i, 'organization'], [/alias|nick/i, 'alias'],
  [/twitter|instagram|facebook|linkedin|github|reddit|telegram|tiktok|youtube|affiliation|social|account|username|user ?name|handle/i, 'username'],
  [/bitcoin|btc|ethereum|crypto|wallet/i, 'crypto'], [/hash|md5|sha-?1|sha-?256/i, 'file'], [/cve|vulnerab/i, 'vulnerability'], [/location|address|city|country|gps|coordinates/i, 'location'],
  [/document|file ?name/i, 'document'], [/image|photo|picture/i, 'media'], [/mac ?addr|device/i, 'device'], [/breach|leak/i, 'breach'], [/threat|malware|actor/i, 'threat']];
const vimGuess = name => { const n = String(name || '').replace(/^maltego\./i, '').replace(/^sfp_/i, '').trim();
  const own = TYPE_LIST.find(t => t[0] === n.toLowerCase() || t[1].toLowerCase() === n.toLowerCase()); if(own) return own[0];   /* our own names, from an OSINTrix export */
  for(const [re, t] of VIM_GUESS) if(re.test(n) && TYPES[t]) return t; return 'auto'; };
/* a value of unknown kind: what it looks like, or nothing */
const vimAuto = v => { const x = E.extract(v).find(z => z.v.length >= v.trim().length * .9); return x && KIND_TO_TYPE[x.k] ? KIND_TO_TYPE[x.k] : null; };

/* ---------- reading the formats: → {fmt, nodes:[{id, kind, v, props}], edges:[{a, b, label}], notes:[]} ---------- */
function vimGraphML(xml, fmt){
  const doc = new DOMParser().parseFromString(xml, 'application/xml'); if(doc.querySelector('parsererror')) throw new Error('This GraphML file could not be read — it is not well-formed XML.');
  const keys = {}; for(const k of doc.getElementsByTagName('key')) keys[k.getAttribute('id')] = (k.getAttribute('attr.name') || k.getAttribute('yfiles.type') || '').toLowerCase();
  const nodes = [], edges = [], local = n => n.localName || n.nodeName.replace(/^.*:/, '');
  let maltego = false;
  for(const n of [...doc.getElementsByTagName('node')].slice(0, VIM.MAX_NODES + 1)){
    const id = n.getAttribute('id'), props = {}; let kind = '', v = '';
    /* Maltego keeps the entity inside the data: <mtg:MaltegoEntity type="maltego.Domain"><mtg:Properties><mtg:Property name="fqdn"><mtg:Value>… */
    const me = [...n.getElementsByTagName('*')].find(x => local(x) === 'MaltegoEntity');
    if(me){ maltego = true; kind = me.getAttribute('type') || ''; const ps = [...me.getElementsByTagName('*')].filter(x => local(x) === 'Property');
      for(const p of ps){ const val = [...p.getElementsByTagName('*')].find(x => local(x) === 'Value'); const t = val ? val.textContent.trim() : ''; if(t) props[p.getAttribute('displayName') || p.getAttribute('name')] = t; }
      const main = ps.find(p => /^(fqdn|ipv4-address|ipv6-address|email|url|person\.fullname|phonenumber|alias|title|location\.name|twitter\.screen-name|affiliation\.uid|cryptocurrency\.address|bitcoin\.address|properties\.\w+|text|value)$/i.test(p.getAttribute('name') || '') && ([...p.getElementsByTagName('*')].find(x => local(x) === 'Value') || {}).textContent);
      v = main ? (([...main.getElementsByTagName('*')].find(x => local(x) === 'Value') || {}).textContent || '').trim() : Object.values(props)[0] || ''; }
    else for(const d of n.getElementsByTagName('data')){ const k = keys[d.getAttribute('key')] || d.getAttribute('key') || '', t = d.textContent.trim(); if(!t) continue;
      if(/^(label|name|title|value|nodelabel|nodegraphics)$/.test(k) && !v) v = t; else if(/^(type|kind|category|class)$/.test(k)) kind = t; else if(!/^(x|y|size|color|r|g|b)$/.test(k)) props[k] = t; }
    if(!v) v = n.getAttribute('label') || '';
    nodes.push({id, kind:kind || 'Node', v:v.replace(/\s+/g, ' ').slice(0, VIM.MAX_VAL), props});
  }
  for(const e of [...doc.getElementsByTagName('edge')].slice(0, VIM.MAX_EDGES + 1)){ let label = '';
    const ml = [...e.getElementsByTagName('*')].find(x => local(x) === 'MaltegoLink');
    if(ml){ const p = [...ml.getElementsByTagName('*')].filter(x => local(x) === 'Property').find(p => (/^maltego\.link\.(manual\.type|label)$/i.test(p.getAttribute('name') || '') || /^label$/i.test(p.getAttribute('displayName') || '')) && p.textContent.trim());   /* not "Show Label", which is a 0/1 switch */ if(p) label = p.textContent.trim(); }
    else for(const d of e.getElementsByTagName('data')){ const k = keys[d.getAttribute('key')] || ''; if(/label|relation|type|name/.test(k) && d.textContent.trim()){ label = d.textContent.trim(); break; } }
    edges.push({a:e.getAttribute('source'), b:e.getAttribute('target'), label}); }
  return {fmt:maltego ? 'Maltego' : fmt || 'GraphML', nodes, edges, notes:[]};
}
function vimCSV(text){
  const head = text.slice(0, 4096), delim = (head.match(/\t/g) || []).length > (head.match(/,/g) || []).length ? '\t' : (head.match(/;/g) || []).length > (head.match(/,/g) || []).length ? ';' : ',';
  const rows = csvParse(text, delim); if(rows.length < 2) throw new Error('There is nothing under the header row.');
  const H = rows[0].map(h => h.trim()), col = re => H.findIndex(h => re.test(h)), body = rows.slice(1, VIM.MAX_NODES + 2);
  /* SpiderFoot: Scan Name, Updated, Type, Module, Source, F/P, Data */
  const sfT = col(/^type$/i), sfD = col(/^data$/i), sfS = col(/^source$/i), sfM = col(/^module$/i), sfFP = col(/^f\/p$/i);
  if(sfT >= 0 && sfD >= 0 && sfS >= 0 && sfM >= 0){
    const nodes = new Map(), edges = [], key = (k, v) => k + '\u0000' + v; let fp = 0;
    const node = (kind, v) => { v = String(v || '').trim().slice(0, VIM.MAX_VAL); if(!v) return null; const k = key(kind, v); if(!nodes.has(k)) nodes.set(k, {id:k, kind, v, props:{}}); return k; };
    const byData = new Map();   /* SpiderFoot names the source by its value only */
    for(const r of body){ if(sfFP >= 0 && /^1$/.test((r[sfFP] || '').trim())){ fp++; continue; } const kind = (r[sfT] || '').trim(); if(!kind || /^(root|raw|scan)/i.test(kind)) continue;
      const id = node(kind, r[sfD]); if(!id) continue; nodes.get(id).props.module = (r[sfM] || '').trim(); byData.set((r[sfD] || '').trim(), id); }
    for(const r of body){ const kind = (r[sfT] || '').trim(), d = (r[sfD] || '').trim(), s = (r[sfS] || '').trim(); const b = nodes.has(key(kind, d)) ? key(kind, d) : null, a = byData.get(s);
      if(a && b && a !== b) edges.push({a, b, label:'led to'}); }
    return {fmt:'SpiderFoot', nodes:[...nodes.values()], edges, notes:fp ? [`${fp} row${fp === 1 ? '' : 's'} marked false positive in SpiderFoot ${fp === 1 ? 'was' : 'were'} left out.`] : []};
  }
  /* links: source, target (and a relationship) — an OSINTrix edges export, or anyone's */
  const eA = col(/^(source(_label)?|from|src)$/i), eB = col(/^(target(_label)?|to|dst|destination)$/i);
  if(eA >= 0 && eB >= 0){ const la = col(/^source_label$/i), lb = col(/^target_label$/i), ia = la >= 0 ? la : eA, ib = lb >= 0 ? lb : eB, rel = col(/^(relationship|relation|label|type|edge)$/i);
    const nodes = new Map(), edges = [];
    const node = v => { v = String(v || '').trim().slice(0, VIM.MAX_VAL); if(!v) return null; if(!nodes.has(v)) nodes.set(v, {id:v, kind:'Value', v, props:{}}); return v; };
    for(const r of body){ const a = node(r[ia]), b = node(r[ib]); if(a && b && a !== b) edges.push({a, b, label:rel >= 0 ? (r[rel] || '').trim() : ''}); }
    return {fmt:'CSV of links', nodes:[...nodes.values()], edges, notes:[]}; }
  /* values: the first column that looks like one, or label/value/name; a type column if there is one */
  const vC = [col(/^(value|label|name|indicator|ioc|entity|data|observable)$/i)].concat(H.map((_, i) => i)).find(i => i >= 0 && body.some(r => (r[i] || '').trim()));
  const tC = col(/^(type|kind|category|entity ?type|ioc ?type)$/i), nC = col(/^(notes?|description|comment|context)$/i), gC = col(/^(tags?|labels?)$/i);
  const nodes = body.map((r, i) => ({id:'r' + i, kind:tC >= 0 && tC !== vC ? (r[tC] || '').trim() || 'Value' : 'Value', v:String(r[vC] || '').trim().slice(0, VIM.MAX_VAL), props:Object.fromEntries(H.map((h, j) => [h, (r[j] || '').trim()]).filter(([h, x], j) => x && ![vC, tC, nC, gC].includes(j))), notes:nC >= 0 ? (r[nC] || '').trim() : '', tags:gC >= 0 ? (r[gC] || '').split(/[\s,;|]+/).filter(Boolean) : []})).filter(n => n.v);
  return {fmt:'CSV', nodes, edges:[], notes:[`Values from the “${H[vC]}” column${tC >= 0 && tC !== vC ? `, kinds from “${H[tC]}”` : ''}.`]};
}
/* a .mtgx is a zip of GraphML files: the biggest one is the graph */
async function vimZip(b){
  const Z = zipOpen(b); if(!Z) throw new Error('This file is not a Maltego graph (.mtgx).');
  const g = Z.files.filter(f => /\.graphml$/i.test(f.name) && !f.enc).sort((x, y) => y.size - x.size)[0]; if(!g) throw new Error('There is no graph inside this .mtgx file.');
  if(g.size > VIM.MAX_BYTES) throw new Error('The graph inside is too big to import here.');
  const xml = await Z.read(g.name, VIM.MAX_BYTES); if(xml == null) throw new Error('The graph inside this .mtgx file could not be read.');
  return xml;
}
async function vimRead(file){
  if(file.size > VIM.MAX_BYTES) throw new Error('Up to 60 MB.');
  const name = file.name.toLowerCase();
  if(/\.mtgx$/.test(name)) return vimGraphML(await vimZip(new Uint8Array(await file.arrayBuffer())), 'Maltego');
  const text = await file.text();
  if(/\.(graphml|xml)$/.test(name) || /^\s*<\?xml[\s\S]{0,400}<graphml|^\s*<graphml/i.test(text.slice(0, 600))) return vimGraphML(text);
  if(/\.(csv|tsv|txt)$/.test(name) || text.includes(',') || text.includes('\t')) return vimCSV(text);
  throw new Error('Import a Maltego graph (.mtgx or GraphML), a GraphML file, a SpiderFoot CSV, or a CSV.');
}

/* ---------- the plan: what would be added, before anything is ---------- */
function vimPlan(){
  const I = UI.vim, c = theCase(), D = derive(c.id), have = new Map();
  for(const e of D.entries){ const k = e.type + '\u0000' + primary(e).trim().toLowerCase(); have.set(k, e); }
  const plan = new Map(), made = new Map(), add = [], skip = {};
  for(const n of I.src.nodes){ let t = I.map[n.kind]; if(t === 'auto') t = vimAuto(n.v);
    if(!t || !TYPES[t] || !n.v){ skip[n.kind] = (skip[n.kind] || 0) + 1; continue; }
    const k = t + '\u0000' + n.v.trim().toLowerCase(); let target = have.get(k) || made.get(k);
    if(!target){ target = {_new:true, type:t, v:n.v, n}; made.set(k, target); add.push(target); }
    plan.set(n.id, target); }
  /* each end is an existing entry (by id) or a new one (by its place in the list); a link already in the case, or twice in the file, is added once */
  const ref = x => x._new ? 'n' + add.indexOf(x) : 'e' + x.id, links = [], seen = new Set(D.links.map(l => 'e' + l.a + '|e' + l.b + '|' + l.label.toLowerCase()));
  for(const e of I.src.edges){ const a = plan.get(e.a), b = plan.get(e.b); if(!a || !b || a === b) continue; const label = (e.label || 'linked to').trim().slice(0, 80) || 'linked to';
    const k = ref(a) + '|' + ref(b) + '|' + label.toLowerCase(); if(seen.has(k)) continue; seen.add(k); links.push({a, b, label}); }
  return {add, reuse:new Set([...plan.values()].filter(x => !x._new)).size, links, skip};
}
function vimDlg(){
  const I = UI.vim; if(!I) return; const P = vimPlan(), kinds = countBy(I.src.nodes, n => n.kind);
  const opts = cur => [['auto', 'By what it looks like'], ['', 'Skip']].concat(TYPE_LIST.map(t => [t[0], t[1]])).map(([v, l]) => `<option value="${v}"${cur === v ? ' selected' : ''}>${esc(l)}</option>`).join('');
  const sample = k => I.src.nodes.filter(n => n.kind === k).slice(0, 2).map(n => n.v.length > 40 ? n.v.slice(0, 38) + '…' : n.v).join(', ');
  const skipped = Object.values(P.skip).reduce((a, b) => a + b, 0);
  openDlg(dhead('Import into ' + esc(theCase().code)) + `<div class="in vim">
    <p class="vim-src">${ico('file-text','sm')}<b>${esc(I.name)}</b><span class="t3">${esc(I.src.fmt)} · ${I.src.nodes.length.toLocaleString()} ${I.src.nodes.length === 1 ? 'thing' : 'things'}${I.src.edges.length ? ' · ' + I.src.edges.length.toLocaleString() + ' links' : ''}</span></p>
    ${I.src.notes.map(n => `<p class="hint">${esc(n)}</p>`).join('')}
    <table class="tbl vim-t"><thead><tr><th>In the file</th><th>How many</th><th>Becomes</th></tr></thead><tbody>${kinds.slice(0, 60).map(([k, n], i) => `<tr><td><b>${esc(k.replace(/^maltego\./i, ''))}</b><small class="t3 mono">${esc(sample(k))}</small></td><td>${n.toLocaleString()}</td>
      <td><label class="sr" for="vimk${i}">${esc(k)} becomes</label><select id="vimk${i}" class="gsel bord" data-vimk="${esc(k)}">${opts(I.map[k])}</select></td></tr>`).join('')}</tbody></table>
    <div class="vim-sum" aria-live="polite"><div><b>${P.add.length.toLocaleString()}</b><span>new entr${P.add.length === 1 ? 'y' : 'ies'}</span></div><div><b>${P.reuse.toLocaleString()}</b><span>already in the case</span></div><div><b>${P.links.length.toLocaleString()}</b><span>new link${P.links.length === 1 ? '' : 's'}</span></div>${skipped ? `<div><b>${skipped.toLocaleString()}</b><span>left out</span></div>` : ''}</div>
    <p class="hint">Entries already in this case are reused — the file’s links join them — and nothing in them is changed. New entries are tagged <span class="mono">${esc(I.tag)}</span>.</p></div>
    <footer><button class="btn" data-act="dclose">Cancel</button><button class="btn primary" data-act="vimGo"${P.add.length || P.links.length ? '' : ' disabled'}>${ico('upload','sm')}Import ${P.add.length ? P.add.length.toLocaleString() + ' entr' + (P.add.length === 1 ? 'y' : 'ies') : ''}${P.add.length && P.links.length ? ' and ' : ''}${P.links.length ? P.links.length.toLocaleString() + ' link' + (P.links.length === 1 ? '' : 's') : ''}</button></footer>`, true);
  document.querySelectorAll('[data-vimk]').forEach(s => s.onchange = () => { UI.vim.map[s.dataset.vimk] = s.value; const id = s.id; vimDlg(); const n = $(id); if(n) n.focus(); });
}
async function vimGo(){
  const I = UI.vim; if(!I) return; const P = vimPlan(), c = theCase(), now = Date.now();
  if(!await stoGuard(JSON.stringify(P.add.map(x => [x.v, x.n && x.n.props])).length * 2 + P.links.length * 200, 'import this')) return;
  const ents = P.add.map(x => { const n = x.n, t = TYPES[x.type], props = Object.entries(n.props || {}).filter(([k, v]) => v && String(v).trim() !== x.v).slice(0, 12);
    const e = {id:uid('v'), caseId:c.id, type:x.type, fields:{[t.fields[0][0]]:x.v}, priority:'medium', starred:false, tags:[...new Set([I.tag].concat((n.tags || []).map(s => s.slice(0, 40))))].slice(0, 20),
      notes:[n.notes || '', props.length ? `From ${I.src.fmt}: ` + props.map(([k, v]) => `${k}: ${String(v).slice(0, 200)}`).join(' · ') : ''].filter(Boolean).join('\n').slice(0, 4000), src:'', created:now, pos:null};
    x.id = e.id; return e; });
  const links = P.links.map(l => ({id:uid('l'), caseId:c.id, a:l.a.id, b:l.b.id, label:l.label, conf:2, src:'', auto:false}));
  DB.entries.push(...ents); DB.links.push(...links); UI.vim = null; closeDlg();
  mutate(`imported ${ents.length} entries and ${links.length} links from ${I.src.fmt}`); renderAll();
  const eIds = new Set(ents.map(e => e.id)), lIds = new Set(links.map(l => l.id));
  toast(`Imported ${ents.length.toLocaleString()} entr${ents.length === 1 ? 'y' : 'ies'} and ${links.length.toLocaleString()} link${links.length === 1 ? '' : 's'} from ${I.name}`, 'Undo', () => {
    DB.entries = DB.entries.filter(e => !eIds.has(e.id)); DB.links = DB.links.filter(l => !lIds.has(l.id)); mutate('undid the import'); renderAll(); });
}
async function vimFile(file){
  try{ const src = await vimRead(file);
    if(!src.nodes.length) throw new Error('Nothing to import was found in this file.');
    if(src.nodes.length > VIM.MAX_NODES) throw new Error(`This file has more than ${VIM.MAX_NODES.toLocaleString()} things — split it, or import the part you need.`);
    const map = {}; for(const n of src.nodes) if(!(n.kind in map)) map[n.kind] = vimGuess(n.kind);
    UI.vim = {name:file.name, src, map, tag:'import:' + slug(src.fmt).slice(0, 20)}; vimDlg(); }
  catch(e){ toast(e.message || 'This file could not be read'); }
}
const VIM_ACTS = {
  vimOpen:() => { const i = document.createElement('input'); i.type = 'file'; i.accept = '.mtgx,.graphml,.xml,.csv,.tsv,.txt'; i.onchange = () => { const f = i.files && i.files[0]; if(f) vimFile(f); }; i.click(); },
  vimGo:() => vimGo(),
};
