/* ==========================================================================
   Case map — Leaflet (BSD-2) with an offline country layer (Natural Earth,
   public domain). Street, light and satellite tiles are opt-in: turning one
   on lets that provider see which areas you look at, never your case data.
   ========================================================================== */
let WORLD = null, WORLD_LOADING = null, lmap = null;
function topoToGeo(t){
  const [sx, sy] = t.transform.scale, [tx, ty] = t.transform.translate;
  const arcs = t.arcs.map(a => { let x = 0, y = 0; return a.map(([dx, dy]) => { x += dx; y += dy; return [x * sx + tx, y * sy + ty]; }); });
  const arc = i => i >= 0 ? arcs[i] : arcs[~i].slice().reverse();
  const ring = r => { const pts = []; for(const i of r){ const a = arc(i); pts.push(...(pts.length ? a.slice(1) : a)); }
    /* unwrap rings that cross the antimeridian so they do not draw lines across the whole map */
    let off = 0; return pts.map((p, k) => { if(k){ const d = p[0] + off - pts[k - 1][0] - (pts[k - 1].off || 0); if(d > 180) off -= 360; else if(d < -180) off += 360; } p.off = off; return [p[0] + off, p[1]]; }); };
  return {type:'FeatureCollection', features:t.objects.countries.geometries.filter(g => g.arcs).map(g => ({type:'Feature', properties:{name:g.properties.name, id:g.id},
    geometry:g.type === 'Polygon' ? {type:'Polygon', coordinates:g.arcs.map(ring)} : {type:'MultiPolygon', coordinates:g.arcs.map(p => p.map(ring))}}))};
}
async function worldLoad(){
  if(WORLD) return WORLD; if(WORLD_LOADING) return WORLD_LOADING;
  WORLD_LOADING = (async () => { try{ const bin = Uint8Array.from(atob(WORLD_B64), c => c.charCodeAt(0));
    WORLD = topoToGeo(JSON.parse(await new Response(new Blob([bin]).stream().pipeThrough(new DecompressionStream('gzip'))).text())); }catch(e){ WORLD = {type:'FeatureCollection', features:[]}; } return WORLD; })();
  return WORLD_LOADING;
}
const CTRY_ALIAS = {'us':'United States of America','usa':'United States of America','united states':'United States of America','america':'United States of America','uk':'United Kingdom','great britain':'United Kingdom','england':'United Kingdom','britain':'United Kingdom',
  'russia':'Russia','russian federation':'Russia','uae':'United Arab Emirates','south korea':'South Korea','korea':'South Korea','north korea':'North Korea','czech republic':'Czechia','türkiye':'Turkey','turkiye':'Turkey','holland':'Netherlands','the netherlands':'Netherlands',
  'ivory coast':"Côte d'Ivoire",'dr congo':'Dem. Rep. Congo','drc':'Dem. Rep. Congo','bosnia':'Bosnia and Herz.','hong kong':'Hong Kong','macau':'Macao'};
const ISO2 = {US:'United States of America',GB:'United Kingdom',UK:'United Kingdom',DE:'Germany',FR:'France',NL:'Netherlands',RU:'Russia',CN:'China',IN:'India',BR:'Brazil',CA:'Canada',AU:'Australia',JP:'Japan',KR:'South Korea',KP:'North Korea',IR:'Iran',UA:'Ukraine',PL:'Poland',ES:'Spain',IT:'Italy',SE:'Sweden',NO:'Norway',FI:'Finland',DK:'Denmark',CH:'Switzerland',AT:'Austria',BE:'Belgium',IE:'Ireland',PT:'Portugal',RO:'Romania',BG:'Bulgaria',HU:'Hungary',CZ:'Czechia',TR:'Turkey',IL:'Israel',AE:'United Arab Emirates',SA:'Saudi Arabia',SG:'Singapore',HK:'Hong Kong',VN:'Vietnam',TH:'Thailand',ID:'Indonesia',MY:'Malaysia',PH:'Philippines',PK:'Pakistan',BD:'Bangladesh',NG:'Nigeria',ZA:'South Africa',EG:'Egypt',KE:'Kenya',MX:'Mexico',AR:'Argentina',CO:'Colombia',CL:'Chile',PE:'Peru',VE:'Venezuela',NZ:'New Zealand',LT:'Lithuania',LV:'Latvia',EE:'Estonia',BY:'Belarus',MD:'Moldova',KZ:'Kazakhstan',GE:'Georgia',AM:'Armenia',AZ:'Azerbaijan',SC:'Seychelles',PA:'Panama',BZ:'Belize',CY:'Cyprus',LU:'Luxembourg',IS:'Iceland',MA:'Morocco',TW:'Taiwan'};
function ctryName(s){ if(!s) return null; const t = String(s).trim(); if(/^[A-Z]{2}$/.test(t) && ISO2[t]) return ISO2[t]; const low = t.toLowerCase().replace(/\s*\(\+\d+\)$/, '');
  if(CTRY_ALIAS[low]) return CTRY_ALIAS[low]; if(!WORLD) return null; const f = WORLD.features.find(c => c.properties.name.toLowerCase() === low) || WORLD.features.find(c => low.length > 4 && c.properties.name.toLowerCase().startsWith(low)); return f ? f.properties.name : null; }
const ccCountry = v => { const c = phoneCountry(v); if(!c) return null; const n = c.replace(/\s*\(\+\d+\)$/, ''); return n.includes('/') ? 'United States of America' : n; };
const haversine = (a, b) => { const R = 6371, r = x => x * Math.PI / 180, dLa = r(b.la - a.la), dLo = r(b.lo - a.lo), s = Math.sin(dLa / 2) ** 2 + Math.cos(r(a.la)) * Math.cos(r(b.la)) * Math.sin(dLo / 2) ** 2; return 2 * R * Math.asin(Math.sqrt(s)); };

function mapData(caseId){
  const D = derive(caseId), pts = new Map(), ctr = new Map();
  const addPt = (la, lo, o) => { la = +la; lo = +lo; if(!isFinite(la) || !isFinite(lo) || Math.abs(la) > 90 || Math.abs(lo) > 180) return; const k = la.toFixed(4) + ',' + lo.toFixed(4);
    const p = pts.get(k) || {k, la, lo, label:'', entries:[], recs:[], ts:null, src:new Set()}; if(o.entry){ p.entries.push(o.entry); p.label = o.label || p.label; } if(o.rec && !p.recs.includes(o.rec)){ p.recs.push(o.rec); if(o.rec.ts && (!p.ts || o.rec.ts < p.ts)) p.ts = o.rec.ts; }
    if(!p.label && o.label) p.label = o.label; p.src.add(o.src); pts.set(k, p); };
  const addC = (name, why, ref) => { const n = ctryName(name); if(!n) return; const c = ctr.get(n) || {name:n, why:new Map(), refs:[]}; c.why.set(why, (c.why.get(why) || 0) + 1); if(ref && c.refs.length < 12) c.refs.push(ref); ctr.set(n, c); };
  for(const e of D.entries){
    if(e.type === 'location'){ const m = (e.fields.coordinates || '').match(/(-?\d+(?:\.\d+)?)\s*,\s*(-?\d+(?:\.\d+)?)/); if(m) addPt(m[1], m[2], {entry:e, label:e.fields.address || e.fields.city || 'Location', src:'Location entry'}); }
    for(const f of ['country', 'nationality']) if(e.fields[f]) addC(e.fields[f], TYPES[e.type].label.toLowerCase() + ' ' + f, {kind:'entry', id:e.id});
    if(e.type === 'phone'){ const n = ccCountry(E.norm('phone', e.fields.number || '')); if(n) addC(n, 'phone country code', {kind:'entry', id:e.id}); }
  }
  for(const r of D.recs){
    for(const x of r.ents){ if(x.k === 'coords'){ const [la, lo] = x.v.split(','); addPt(la, lo, {rec:r, label:r.title.replace(/^(Photo|Screenshot|Image): /, '').slice(0, 60), src:/EXIF GPS/i.test(r.body) ? 'Photo GPS' : 'In evidence'}); }
      if(x.k === 'phone'){ const n = ccCountry(x.v); if(n) addC(n, 'phone country code', {kind:'rec', id:r.id}); } }
    const P = r.body && r.body.length < 20000 ? parseLog(r.body.split('\n')[0]) : null;
    if(P) for(const [k, v] of Object.entries(P.fields)) if(/country/i.test(k) && v && !/^(reserved|unknown|-|n\/a)$/i.test(v)) addC(v, 'log field ' + k, {kind:'rec', id:r.id});
  }
  return {pts:[...pts.values()], ctr:[...ctr.values()].sort((a, b) => b.refs.length - a.refs.length)};
}
const BASES = {
  outline:{name:'Outline', note:'Offline — country borders only', online:false},
  streets:{name:'Streets', url:'https://{s}.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}{r}.png', attr:'© OpenStreetMap contributors © CARTO', host:'CARTO', max:20, sub:'abcd'},
  light:{name:'Light', url:'https://{s}.basemaps.cartocdn.com/{v}/{z}/{x}/{y}{r}.png', attr:'© OpenStreetMap contributors © CARTO', host:'CARTO', max:20, sub:'abcd'},
  satellite:{name:'Satellite', url:'https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}', attr:'Imagery © Esri, Maxar, Earthstar Geographics', host:'Esri', max:19}
};

function caseMapView(c, D){
  if(!WORLD){ worldLoad().then(() => { if(UI.route.tab === 'map') renderMain(); }); return `<div class="scroll"><div class="page"><p class="t3">Loading the map…</p></div></div>`; }
  const M = mapData(c.id), mp = UI.map || (UI.map = {ctr:true, path:false, sel:null}); UI.mapData = M;
  const base = mapBaseNow();
  if(!M.pts.length && !M.ctr.length) return `<div class="scroll">${empty('map', 'Nothing to place on the map yet', 'Points come from Location entries with coordinates, coordinates written in evidence (51.5074, -0.1278) and GPS in photos you attach. Countries come from country fields, phone country codes and country fields in logs.', `<button class="btn primary" data-act="mapAdd">${ico('plus','sm')}Add a location</button>`)}</div>`;
  const T = M.pts.filter(p => p.ts).sort((a, b) => a.ts - b.ts);
  const legs = T.slice(1).map((p, i) => { const a = T[i], km = haversine(a, p), h = (p.ts - a.ts) / 36e5; return {a, b:p, km, h, kmh:h > 0 ? km / h : Infinity}; });
  return `<div class="mapwrap">
    <div class="gtools maptools">
      <div class="seg mapbase" role="group" aria-label="Base map">${Object.entries(BASES).map(([k, b]) => `<button data-act="mapBase" data-v="${k}" aria-pressed="${base === k}" title="${esc(b.online === false ? b.note : 'Loads map tiles from ' + b.host)}">${b.online === false ? ico('globe','sm') : ''}${b.name}</button>`).join('')}</div>
      <div class="gset"><button class="gbtn${mp.ctr ? ' on' : ''}" data-act="mapCtr" aria-pressed="${mp.ctr}">${ico('flag','sm')}<span>Countries</span></button><button class="gbtn${mp.path ? ' on' : ''}" data-act="mapPath" aria-pressed="${mp.path}"${T.length < 2 ? ' disabled' : ''} title="Join timed places in time order">${ico('route','sm')}<span>Movement</span></button></div>
      <span style="flex:1"></span><button class="gbtn" data-act="mapAdd">${ico('plus','sm')}<span>Add location</span></button></div>
    <div class="mapbody"><div class="mapcanvas"><div id="lmap"></div>${base !== 'outline' ? `<div class="mapnote">${ico('globe','sm')}Tiles from ${esc(BASES[base].host)} — they see which area you view, not your case.</div>` : ''}</div>
      <aside class="mapside">
        <div class="mapsum"><div><b>${M.pts.length}</b><span>place${M.pts.length === 1 ? '' : 's'}</span></div><div><b>${M.ctr.length}</b><span>countr${M.ctr.length === 1 ? 'y' : 'ies'}</span></div><div><b>${T.length}</b><span>with a time</span></div></div>
        ${M.pts.length ? `<h5>Places</h5>${M.pts.map(p => `<button class="mplace${mp.sel === p.k ? ' on' : ''}" data-act="mapSel" data-v="${esc(p.k)}"><span class="mdot ${p.entries.length ? 'e' : 'r'}"></span><span class="mp-t"><b>${esc(p.label || 'Point')}</b><small class="mono">${p.la.toFixed(5)}, ${p.lo.toFixed(5)}</small><small>${esc([...p.src].join(' · '))}${p.ts ? ' · ' + esc(E.fmtFull(p.ts, tz()).slice(0, 16)) : ''}</small></span></button>`).join('')}` : ''}
        ${mp.path && legs.length ? `<h5>Movement</h5>${legs.map((l, i) => `<div class="mleg${l.kmh > 900 ? ' warn' : ''}"><span class="mleg-n">${i + 1}→${i + 2}</span><span><b>${l.km < 1 ? Math.round(l.km * 1000) + ' m' : Math.round(l.km).toLocaleString() + ' km'}</b> in ${esc(E.fmtGap(l.b.ts - l.a.ts))}${isFinite(l.kmh) && l.km > 1 ? ` · ${Math.round(l.kmh).toLocaleString()} km/h` : ''}${l.kmh > 900 ? '<small>Faster than a plane — check the times or the places</small>' : ''}</span></div>`).join('')}` : ''}
        ${M.ctr.length ? `<h5>Countries</h5>${M.ctr.map(x => `<div class="mctry"><b>${esc(x.name)}</b><small>${esc([...x.why.entries()].map(([w, n]) => w + (n > 1 ? ' ×' + n : '')).join(' · '))}</small></div>`).join('')}` : ''}
      </aside></div></div>`;
}
function mountMap(){
  const el = $('lmap'); if(!el || typeof L === 'undefined' || !WORLD || el.dataset.m) return; el.dataset.m = '1';
  if(lmap){ try{ lmap.remove(); }catch(e){} lmap = null; }
  const M = UI.mapData, mp = UI.map, base = mapBaseNow(), dark = document.documentElement.dataset.theme === 'dark', hot = new Set(M.ctr.map(c => c.name));
  lmap = L.map(el, {zoomControl:false, worldCopyJump:true, attributionControl:true, minZoom:2, maxZoom:base === 'outline' ? 9 : BASES[base].max, zoomSnap:.5, preferCanvas:false});
  L.control.zoom({position:'bottomright'}).addTo(lmap);
  lmap.attributionControl.setPrefix(false);
  const fit = () => { if(M.pts.length === 1) lmap.setView([M.pts[0].la, M.pts[0].lo], base === 'outline' ? 5 : 12);
    else if(M.pts.length) lmap.fitBounds(L.latLngBounds(M.pts.map(p => [p.la, p.lo])).pad(.25), {maxZoom:base === 'outline' ? 6 : 14});
    else { const hotF = WORLD.features.filter(f => hot.has(f.properties.name)); if(hotF.length) lmap.fitBounds(L.geoJSON({type:'FeatureCollection', features:hotF}).getBounds().pad(.2)); else lmap.setView([25, 10], 2); } };
  if(mp.view && mp.view.base === base && mp.view.case === DB.active) lmap.setView(mp.view.c, mp.view.z); else fit();
  if(base === 'outline'){ el.classList.add('offline');
    L.geoJSON(WORLD, {style:f => ({color:dark ? '#3a4260' : '#c9cfe0', weight:.8, fillColor:mp.ctr && hot.has(f.properties.name) ? cssVar('--accent') : (dark ? '#1c2233' : '#ffffff'), fillOpacity:mp.ctr && hot.has(f.properties.name) ? .28 : 1}),
      onEachFeature:(f, l) => { const c = M.ctr.find(x => x.name === f.properties.name); l.bindTooltip(esc(f.properties.name) + (c ? ` — ${[...c.why.keys()].join(', ')}` : ''), {sticky:true, className:'mtip'}); }}).addTo(lmap);
    lmap.attributionControl.addAttribution('Borders: Natural Earth'); }
  else { el.classList.remove('offline'); const b = BASES[base];
    const tl = L.tileLayer(b.url, {attribution:b.attr, maxZoom:b.max, subdomains:b.sub || 'abc', v:dark ? 'dark_all' : 'light_all', r:L.Browser.retina ? '@2x' : '', crossOrigin:false, referrerPolicy:'strict-origin-when-cross-origin'}).addTo(lmap);
    /* tiles that never arrive (offline, blocked by a firewall, refused by the server): say so and go back to the offline map instead of showing a wall of errors */
    let ok = 0, bad = 0; const me = lmap;
    tl.on('tileload', () => { ok++; }); tl.on('tileerror', () => { bad++;
      if(bad >= 4 && !ok && lmap === me && mapBaseNow() === base){ DB.prefs.mapBase = 'outline'; save(); renderMain(); toast(b.name + ' map tiles could not be loaded from ' + b.host + ' — offline, or blocked on this network. Showing the outline map.'); } });
    if(mp.ctr) L.geoJSON({type:'FeatureCollection', features:WORLD.features.filter(f => hot.has(f.properties.name))}, {style:{color:cssVar('--accent'), weight:1.2, fillColor:cssVar('--accent'), fillOpacity:.12}, interactive:false}).addTo(lmap); }
  const mk = {};
  for(const p of M.pts){ const sel = mp.sel === p.k, col = sel ? cssVar('--red') : p.entries.length ? cssVar('--accent') : cssVar('--amber');
    const m = L.circleMarker([p.la, p.lo], {radius:sel ? 9 : 7, color:'#fff', weight:2, fillColor:col, fillOpacity:1}).addTo(lmap);
    m.bindTooltip(esc(p.label || 'Point'), {direction:'top', offset:[0, -8], className:'mtip'});
    m.bindPopup(() => `<div class="mpop"><b>${esc(p.label || 'Point')}</b><span class="mono">${p.la.toFixed(6)}, ${p.lo.toFixed(6)}</span><span class="t3">${esc([...p.src].join(' · '))}${p.ts ? ' · ' + esc(E.fmtFull(p.ts, tz()).slice(0, 16)) : ''}</span>
      <div class="mpop-l"><a href="https://www.google.com/maps?q=${p.la},${p.lo}" target="_blank" rel="noopener noreferrer">Google Maps</a><a href="https://www.google.com/maps/@?api=1&amp;map_action=pano&amp;viewpoint=${p.la},${p.lo}" target="_blank" rel="noopener noreferrer">Street View</a><a href="https://www.openstreetmap.org/?mlat=${p.la}&amp;mlon=${p.lo}#map=17/${p.la}/${p.lo}" target="_blank" rel="noopener noreferrer">OSM</a></div>
      ${p.entries[0] || p.recs[0] ? `<button class="btn xs" data-act="mapOpen" data-v="${esc(p.k)}">Open details</button>` : ''}</div>`, {maxWidth:280});
    m.on('click', () => { mp.sel = p.k; document.querySelectorAll('.mplace').forEach(b => b.classList.toggle('on', b.dataset.v === p.k)); });
    mk[p.k] = m; }
  mountMap.mk = mk;
  if(mp.path){ const T = M.pts.filter(p => p.ts).sort((a, b) => a.ts - b.ts);
    if(T.length > 1){ L.polyline(T.map(p => [p.la, p.lo]), {color:cssVar('--red'), weight:2.5, dashArray:'6 6', opacity:.85}).addTo(lmap);
      T.forEach((p, i) => L.marker([p.la, p.lo], {icon:L.divIcon({className:'mnum', html:String(i + 1), iconSize:[18, 18], iconAnchor:[-6, 18]}), interactive:false}).addTo(lmap)); } }
  lmap.on('moveend', () => { mp.view = {c:lmap.getCenter(), z:lmap.getZoom(), base, case:DB.active}; });
  mountMap.fit = fit; const me = lmap; setTimeout(() => { if(lmap === me && el.isConnected) lmap.invalidateSize(); }, 60);
}
function mapSelect(k){
  const p = UI.mapData.pts.find(q => q.k === k); if(!p || !lmap) return; UI.map.sel = k;
  document.querySelectorAll('.mplace').forEach(b => b.classList.toggle('on', b.dataset.v === k));
  lmap.flyTo([p.la, p.lo], Math.max(lmap.getZoom(), mapBaseNow() === 'outline' ? 6 : 14), {duration:.6});
  const m = mountMap.mk && mountMap.mk[k]; if(m) setTimeout(() => m.openPopup(), 650);
}
function mapBaseNow(){ const v = DB.prefs.mapBase || 'outline', b = BASES[v]; return b && (v === 'outline' || (DB.prefs.mapOk || {})[b.host]) ? v : 'outline'; }
function mapBaseSet(v){
  if(v !== 'outline' && !(DB.prefs.mapOk || {})[BASES[v].host]){ const b = BASES[v];
    return confirmDlg('Load map tiles from ' + b.host + '?', `The ${b.name.toLowerCase()} map is made of image tiles downloaded from ${b.host}. They will see the areas you look at and your IP address — never your case data. The outline map stays fully offline.`, 'Use ' + b.name.toLowerCase() + ' map', () => { DB.prefs.mapOk = Object.assign(DB.prefs.mapOk || {}, {[b.host]:1}); DB.prefs.mapBase = v; save(); renderMain(); }, true); }
  DB.prefs.mapBase = v; save(); renderMain();
}
const MAP_ACTS = {
  mapCtr:() => { UI.map.ctr = !UI.map.ctr; renderMain(); }, mapPath:() => { UI.map.path = !UI.map.path; renderMain(); },
  mapBase:(id, v) => mapBaseSet(v),
  mapSel:(id, v) => mapSelect(v),
  mapOpen:(id, v) => { const p = UI.mapData.pts.find(q => q.k === v); if(!p) return; if(p.entries[0]) selectEntry(p.entries[0].id); else if(p.recs[0]) select('rec', p.recs[0].id); },
  mapAdd:() => entryDlg(null, {type:'location', fields:{}})
};
