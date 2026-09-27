/* ==========================================================================
   Brand — OSINTrix. "Follow every thread."
   The mark: a lens (the O of OSINT) with a dotted thread running through it
   from a known point to a new lead (cyan). Gradient squircle, white line.
   ========================================================================== */
const BRAND = {name:'OSINTrix', tagline:'Follow every thread.', version:'v1.4'};
function logoMark(size = 32, id = 'lg' + Math.random().toString(36).slice(2, 6)){
  return `<svg class="mark" width="${size}" height="${size}" viewBox="0 0 32 32" aria-hidden="true">
    <defs><linearGradient id="${id}" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#5468ff"/><stop offset=".6" stop-color="#7c5cff"/><stop offset="1" stop-color="#a855f7"/></linearGradient>
      <radialGradient id="${id}h" cx=".25" cy=".15" r=".9"><stop offset="0" stop-color="#fff" stop-opacity=".35"/><stop offset=".5" stop-color="#fff" stop-opacity="0"/></radialGradient></defs>
    <rect x="1" y="1" width="30" height="30" rx="9" fill="url(#${id})"/><rect x="1" y="1" width="30" height="30" rx="9" fill="url(#${id}h)"/>
    <circle cx="15" cy="15" r="6.6" fill="none" stroke="#fff" stroke-width="2.4"/>
    <path d="M7.4 23.2C10 20 11 17.6 15 15s5.2-5 9.4-7.4" fill="none" stroke="#67e8f9" stroke-width="1.7" stroke-linecap="round"/>
    <path d="M19.8 19.8l4.3 4.3" stroke="#fff" stroke-width="2.6" stroke-linecap="round"/>
    <circle cx="7.4" cy="23.2" r="2.1" fill="#fff"/><circle cx="24.4" cy="7.6" r="2.3" fill="#67e8f9" stroke="#fff" stroke-width="1.3"/><circle cx="15" cy="15" r="2" fill="#fff"/></svg>`;
}
const wordmark = () => `<span class="wordmark">OSINT<span>rix</span></span>`;
const FAVICON = 'data:image/svg+xml,' + encodeURIComponent(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#5468ff"/><stop offset="1" stop-color="#a855f7"/></linearGradient></defs><rect x="1" y="1" width="30" height="30" rx="9" fill="url(#g)"/><circle cx="15" cy="15" r="6.6" fill="none" stroke="#fff" stroke-width="2.6"/><path d="M19.8 19.8l4.3 4.3" stroke="#fff" stroke-width="2.8" stroke-linecap="round"/><circle cx="24.4" cy="7.6" r="2.5" fill="#67e8f9"/><circle cx="15" cy="15" r="2.1" fill="#fff"/></svg>`);

/* Empty-state illustrations: line art in the brand colours, drawn with currentColor + accents */
const ILLUS = {
  graph:`<svg viewBox="0 0 160 110" fill="none" aria-hidden="true"><g stroke="var(--border)" stroke-width="1.5" stroke-dasharray="3 4"><path d="M30 70 70 30M70 30l52 18M70 30l6 58M122 48 76 88M30 70l46 18"/></g>
    <circle cx="70" cy="30" r="13" fill="var(--surface-2)" stroke="var(--accent)" stroke-width="2"/><circle cx="30" cy="70" r="10" fill="var(--surface-2)" stroke="var(--t-identity)" stroke-width="2"/>
    <circle cx="122" cy="48" r="10" fill="var(--surface-2)" stroke="var(--t-contact)" stroke-width="2"/><circle cx="76" cy="88" r="11" fill="var(--surface-2)" stroke="var(--t-finance)" stroke-width="2"/><circle cx="70" cy="30" r="4" fill="var(--accent)"/></svg>`,
  vault:`<svg viewBox="0 0 160 110" fill="none" aria-hidden="true"><rect x="34" y="26" width="92" height="66" rx="12" fill="var(--surface-2)" stroke="var(--border)" stroke-width="1.5"/>
    <rect x="46" y="40" width="30" height="8" rx="4" fill="var(--accent)" opacity=".8"/><rect x="46" y="56" width="68" height="6" rx="3" fill="var(--border)"/><rect x="46" y="68" width="52" height="6" rx="3" fill="var(--border)"/>
    <circle cx="118" cy="30" r="14" fill="var(--surface)" stroke="var(--accent)" stroke-width="2"/><path d="M118 24v12M112 30h12" stroke="var(--accent)" stroke-width="2.2" stroke-linecap="round"/></svg>`,
  time:`<svg viewBox="0 0 160 110" fill="none" aria-hidden="true"><path d="M40 16v80" stroke="var(--border)" stroke-width="2" stroke-dasharray="2 5"/>
    <circle cx="40" cy="28" r="6" fill="var(--surface)" stroke="var(--green)" stroke-width="2.5"/><rect x="56" y="20" width="70" height="16" rx="8" fill="var(--surface-2)" stroke="var(--border)"/>
    <rect x="36" y="52" width="8" height="8" rx="2" transform="rotate(45 40 56)" fill="var(--amber)"/><rect x="56" y="48" width="84" height="16" rx="8" fill="var(--surface-2)" stroke="var(--border)"/>
    <circle cx="40" cy="84" r="6" fill="var(--surface)" stroke="var(--accent)" stroke-width="2.5"/><rect x="56" y="76" width="56" height="16" rx="8" fill="var(--surface-2)" stroke="var(--border)"/></svg>`,
  search:`<svg viewBox="0 0 160 110" fill="none" aria-hidden="true"><circle cx="72" cy="50" r="26" fill="var(--surface-2)" stroke="var(--accent)" stroke-width="2.5"/><path d="m92 70 20 20" stroke="var(--accent)" stroke-width="5" stroke-linecap="round"/>
    <path d="M60 50h24M72 38v24" stroke="var(--border)" stroke-width="2" stroke-linecap="round"/></svg>`,
  tools:`<svg viewBox="0 0 160 110" fill="none" aria-hidden="true"><rect x="36" y="24" width="40" height="40" rx="11" fill="var(--surface-2)" stroke="var(--border)"/><rect x="84" y="24" width="40" height="40" rx="11" fill="var(--accent-soft)" stroke="var(--accent)" stroke-width="1.5"/>
    <rect x="36" y="70" width="88" height="16" rx="8" fill="var(--surface-2)" stroke="var(--border)"/><path d="M98 44h12M104 38v12" stroke="var(--accent)" stroke-width="2.4" stroke-linecap="round"/></svg>`,
};

/* A static mini-map of a case graph from saved node positions — cheap and pretty */
function caseMap(caseId, w = 360, h = 220){
  const ents = DB.entries.filter(e => e.caseId === caseId && e.pos), links = DB.links.filter(l => l.caseId === caseId);
  if(ents.length < 2) return `<div class="mapempty">${ILLUS.graph}</div>`;
  const xs = ents.map(e => e.pos.x), ys = ents.map(e => e.pos.y), pad = 18;
  const x0 = Math.min(...xs), x1 = Math.max(...xs), y0 = Math.min(...ys), y1 = Math.max(...ys);
  const k = Math.min((w - pad * 2) / Math.max(1, x1 - x0), (h - pad * 2) / Math.max(1, y1 - y0));
  const ox = (w - (x1 - x0) * k) / 2, oy = (h - (y1 - y0) * k) / 2;
  const P = e => [ox + (e.pos.x - x0) * k, oy + (e.pos.y - y0) * k];
  const byId = new Map(ents.map(e => [e.id, e]));
  let s = `<svg class="casemap" viewBox="0 0 ${w} ${h}" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Map of ${ents.length} entries and ${links.length} relationships">`;
  for(const l of links){ const a = byId.get(l.a), b = byId.get(l.b); if(!a || !b) continue; const [ax, ay] = P(a), [bx, by] = P(b);
    s += `<line x1="${ax.toFixed(1)}" y1="${ay.toFixed(1)}" x2="${bx.toFixed(1)}" y2="${by.toFixed(1)}" stroke="var(--accent)" stroke-opacity=".45" stroke-width="1.2"/>`; }
  for(const e of ents){ const [x, y] = P(e), v = entryVerdict(e), r = e.priority === 'critical' ? 6 : e.priority === 'high' ? 5 : 4;
    s += `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${r + 3}" fill="var(${TYPES[e.type].color})" opacity=".16"/><circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${r}" fill="var(${TYPES[e.type].color})" stroke="${v === 'malicious' ? 'var(--red)' : 'var(--surface)'}" stroke-width="1.6"/>`; }
  return s + '</svg>';
}
/* compute positions for any case that has never been opened in the graph (headless Cytoscape) */
function ensurePositions(){
  if(typeof cytoscape === 'undefined') return;
  for(const c of DB.cases){
    const ents = DB.entries.filter(e => e.caseId === c.id); if(!ents.length || ents.every(e => e.pos)) continue;
    const h = cytoscape({headless:true, styleEnabled:true, style:[{selector:'node', style:{width:56, height:56}}], elements:[...ents.map(e => ({data:{id:e.id}, position:e.pos || undefined})),
      ...DB.links.filter(l => l.caseId === c.id).map(l => ({data:{id:l.id, source:l.a, target:l.b}}))]});
    h.layout({name:'cose', animate:false, randomize:true, nodeRepulsion:() => 40000, idealEdgeLength:() => 110, nodeOverlap:40, numIter:2500, gravity:.6, componentSpacing:120}).run();
    h.nodes().forEach(n => { const e = entryById(n.id()); if(e && !e.pos) e.pos = {...n.position()}; }); h.destroy();
  }
}
function sparkline(values, color = 'var(--accent)', w = 96, h = 30){
  const mx = Math.max(1, ...values), step = w / Math.max(1, values.length - 1);
  const pts = values.map((v, i) => [i * step, h - 3 - (v / mx) * (h - 6)]);
  const d = pts.map((p, i) => (i ? 'L' : 'M') + p[0].toFixed(1) + ' ' + p[1].toFixed(1)).join(' ');
  const gid = 'sp' + Math.random().toString(36).slice(2, 7);
  return `<svg class="spark" viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" aria-hidden="true"><defs><linearGradient id="${gid}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="${color}" stop-opacity=".35"/><stop offset="1" stop-color="${color}" stop-opacity="0"/></linearGradient></defs>
    <path d="${d} L${w} ${h} L0 ${h}Z" fill="url(#${gid})"/><path d="${d}" stroke="${color}" stroke-width="1.8" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
}
function donut(parts, size = 132){
  const total = parts.reduce((a, p) => a + p.n, 0) || 1, r = 50, c = 2 * Math.PI * r; let off = 0;
  let s = `<svg class="donut" viewBox="0 0 120 120" width="${size}" height="${size}" role="img" aria-label="${parts.map(p => p.label + ' ' + p.n).join(', ')}"><circle cx="60" cy="60" r="${r}" fill="none" stroke="var(--surface-2)" stroke-width="14"/>`;
  for(const p of parts){ const len = c * p.n / total; s += `<circle cx="60" cy="60" r="${r}" fill="none" stroke="${p.color}" stroke-width="14" stroke-dasharray="${Math.max(0, len - 2).toFixed(2)} ${c.toFixed(2)}" stroke-dashoffset="${(-off).toFixed(2)}" transform="rotate(-90 60 60)" stroke-linecap="butt"/>`; off += len; }
  return s + `<text x="60" y="58" text-anchor="middle" class="dn">${total}</text><text x="60" y="76" text-anchor="middle" class="dl">entries</text></svg>`;
}
