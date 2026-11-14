/* ==========================================================================
   Case places: every location and country found in a case, an offline
   overview (Natural Earth borders, public domain) and one-click links to
   Google Maps, Street View, Earth, OpenStreetMap and other map services.
   ========================================================================== */
let WORLD = null, WORLD_LOADING = null;
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
/* ---------- Places: an investigation view of every location in a case ----------
   No map tiles are loaded. A small offline overview (Natural Earth borders) shows where
   things are; each place opens in the map service you choose, in a new tab. */
const MAP_W = 1000, MAP_H = 500, mx = lo => (lo + 180) / 360 * MAP_W, my = la => (90 - la) / 180 * MAP_H;
let WORLD_PATH = null;
function worldPath(){
  if(WORLD_PATH) return WORLD_PATH; const out = [];
  const ring = r => { let d = '', px = null, py = null; for(const [lo, la] of r){ const x = Math.round(mx(lo) * 10) / 10, y = Math.round(my(la) * 10) / 10; if(x === px && y === py) continue; d += (d ? 'L' : 'M') + x + ' ' + y; px = x; py = y; } return d + 'Z'; };
  for(const f of WORLD.features){ const g = f.geometry, polys = g.type === 'Polygon' ? [g.coordinates] : g.coordinates; out.push([f.properties.name, polys.map(p => p.map(ring).join('')).join('')]); }
  return WORLD_PATH = out;
}
const PLACE_LINKS = [
  ['Google Maps', (la, lo) => `https://www.google.com/maps/search/?api=1&query=${la},${lo}`, 'map'],
  ['Street View', (la, lo) => `https://www.google.com/maps/@?api=1&map_action=pano&viewpoint=${la},${lo}`, 'eye'],
  ['Google Earth', (la, lo) => `https://earth.google.com/web/@${la},${lo},400a,1200d,35y,0h,0t,0r`, 'globe'],
  ['OpenStreetMap', (la, lo) => `https://www.openstreetmap.org/?mlat=${la}&mlon=${lo}#map=17/${la}/${lo}`, 'map'],
  ['Bing aerial', (la, lo) => `https://www.bing.com/maps?cp=${la}~${lo}&lvl=18&style=h`, 'image'],
  ['Apple Maps', (la, lo) => `https://maps.apple.com/?ll=${la},${lo}&q=${la},${lo}`, 'map-pin'],
  ['Yandex', (la, lo) => `https://yandex.com/maps/?pt=${lo},${la}&z=17&l=map`, 'map'],
  ['Mapillary', (la, lo) => `https://www.mapillary.com/app/?lat=${la}&lng=${lo}&z=17`, 'image'],
  ['Satellite history', (la, lo) => `https://apps.sentinel-hub.com/eo-browser/?zoom=15&lat=${la}&lng=${lo}`, 'globe'],
  ['Wikimapia', (la, lo) => `https://wikimapia.org/#lat=${la}&lon=${lo}&z=17`, 'globe'],
  ['Overpass turbo', (la, lo) => `https://overpass-turbo.eu/?C=${la};${lo};16`, 'scan-search'],
  ['Sun position', (la, lo, ts) => { const d = ts ? new Date(ts) : new Date(), z = n => String(n).padStart(2, '0'); return `https://www.suncalc.org/#/${la},${lo},17/${d.getUTCFullYear()}.${z(d.getUTCMonth() + 1)}.${z(d.getUTCDate())}/${z(d.getUTCHours())}:${z(d.getUTCMinutes())}/1/3`; }, 'sun']];
const ext = (href, label, i) => `<a class="plink" href="${esc(href)}" target="_blank" rel="noopener noreferrer">${ico(i || 'arrow-up-right','sm')}<span>${esc(label)}</span></a>`;
const kmText = km => km < 1 ? Math.round(km * 1000) + ' m' : km < 10 ? km.toFixed(1) + ' km' : Math.round(km).toLocaleString() + ' km';

function placesOverview(M, sel, legs){
  const hot = new Set(M.ctr.map(c => c.name)), P = M.pts;
  let x0, x1, y0, y1;
  if(P.length){ x0 = Math.min(...P.map(p => mx(p.lo))); x1 = Math.max(...P.map(p => mx(p.lo))); y0 = Math.min(...P.map(p => my(p.la))); y1 = Math.max(...P.map(p => my(p.la))); }
  else { x0 = 0; x1 = MAP_W; y0 = 40; y1 = MAP_H - 40; }
  let w = Math.max(x1 - x0, 60), h = Math.max(y1 - y0, 30); w *= 1.6; h *= 1.6; if(w / h > 2.4) h = w / 2.4; else w = h * 2.4;
  const cx = (x0 + x1) / 2, cy = (y0 + y1) / 2, vb = [cx - w / 2, cy - h / 2, w, h].map(n => n.toFixed(1)).join(' '), r = (w / 130).toFixed(2);
  const T = P.filter(p => p.ts).sort((a, b) => a.ts - b.ts);
  return `<svg class="pov" viewBox="${vb}" preserveAspectRatio="xMidYMid slice" role="img" aria-label="Overview of ${P.length} places">
    ${worldPath().map(([n, d]) => `<path d="${d}" class="${hot.has(n) ? 'hot' : ''}" vector-effect="non-scaling-stroke"><title>${esc(n)}</title></path>`).join('')}
    ${T.length > 1 ? `<polyline class="pmove" vector-effect="non-scaling-stroke" points="${T.map(p => mx(p.lo).toFixed(2) + ',' + my(p.la).toFixed(2)).join(' ')}"/>` : ''}
    ${P.map((p, i) => `<g class="pdot${sel === p.k ? ' on' : ''}${legs.some(l => l.kmh > 900 && (l.a === p || l.b === p)) ? ' warn' : ''}" data-act="mapSel" data-v="${esc(p.k)}"><circle cx="${mx(p.lo).toFixed(2)}" cy="${my(p.la).toFixed(2)}" r="${r}"/><title>${esc(p.label || 'Point')}</title></g>`).join('')}
  </svg>`;
}
function caseMapView(c, D){
  if(!WORLD){ worldLoad().then(() => { if(UI.route.tab === 'map') renderMain(); }); return `<div class="scroll"><div class="page"><p class="t3">Loading places…</p></div></div>`; }
  const M = mapData(c.id), mp = UI.map || (UI.map = {sel:null}); UI.mapData = M;
  if(!M.pts.length && !M.ctr.length) return `<div class="scroll">${empty('map-pin', 'No places in this case yet', 'Places come from Location entries with coordinates, coordinates written in evidence (51.5074, -0.1278) and GPS in photos you attach. Countries come from country fields, phone country codes and country fields in logs.', `<button class="btn primary" data-act="mapAdd">${ico('plus','sm')}Add a location</button>`)}</div>`;
  const T = M.pts.filter(p => p.ts).sort((a, b) => a.ts - b.ts);
  const legs = T.slice(1).map((p, i) => { const a = T[i], km = haversine(a, p), h = (p.ts - a.ts) / 36e5; return {a, b:p, km, h, kmh:h > 0 ? km / h : Infinity}; });
  const fast = legs.filter(l => l.kmh > 900 && l.km > 50).length;
  if(!mp.sel || !M.pts.some(p => p.k === mp.sel)) mp.sel = M.pts[0] ? M.pts[0].k : null;
  const order = new Map(T.map((p, i) => [p.k, i + 1]));
  const near = p => M.pts.filter(q => q !== p).map(q => [q, haversine(p, q)]).sort((a, b) => a[1] - b[1])[0];
  const card = p => { const la = p.la.toFixed(6), lo = p.lo.toFixed(6), n = near(p), on = mp.sel === p.k, ref = p.entries.length + p.recs.length;
    return `<article class="pcard${on ? ' on' : ''}" id="pl-${esc(p.k.replace(/[^\w]/g, '_'))}">
      <header data-act="mapSel" data-v="${esc(p.k)}">${order.has(p.k) ? `<span class="pord">${order.get(p.k)}</span>` : `<span class="pord none">${ico('map-pin','sm')}</span>`}
        <div class="ph-t"><h3>${esc(p.label || 'Unnamed place')}</h3><div class="ph-m"><button class="pcoord mono" data-act="flagCopy" data-v="${la}, ${lo}" title="Copy coordinates">${la}, ${lo}${ico('copy','sm')}</button>
          ${[...p.src].map(s => `<span class="chip">${esc(s)}</span>`).join('')}${p.ts ? `<span class="chip">${ico('clock','sm')}${esc(E.fmtFull(p.ts, tz()).slice(0, 16))}</span>` : ''}</div></div>
        ${ref ? `<button class="btn sm" data-act="mapOpen" data-v="${esc(p.k)}">${ico('panel-right','sm')}Details</button>` : ''}</header>
      <div class="plinks">${PLACE_LINKS.map(([l, f, i]) => ext(f(la, lo, p.ts), l, i)).join('')}</div>
      ${n ? `<p class="pnear">${ico('route','sm')}Nearest other place: <b>${esc(n[0].label || 'Point')}</b>, ${kmText(n[1])} away</p>` : ''}
    </article>`; };
  return `<div class="scroll"><div class="page places">
    <div class="psum">
      <div class="pstat"><b>${M.pts.length}</b><span>place${M.pts.length === 1 ? '' : 's'}</span></div>
      <div class="pstat"><b>${M.ctr.length}</b><span>countr${M.ctr.length === 1 ? 'y' : 'ies'}</span></div>
      <div class="pstat"><b>${T.length}</b><span>with a time</span></div>
      <div class="pstat${fast ? ' warn' : ''}"><b>${fast}</b><span>impossible travel</span></div>
      <span class="sp"></span><div class="pacts"><button class="btn" data-act="placesKml"${M.pts.length ? '' : ' disabled'}>${ico('download','sm')}Export KML</button><button class="btn" data-act="placesCsv"${M.pts.length ? '' : ' disabled'}>${ico('download','sm')}CSV</button><button class="btn primary" data-act="mapAdd">${ico('plus','sm')}Add location</button></div>
    </div>
    <div class="pgrid">
      <div class="pmain">
        ${M.pts.length ? `<figure class="pmap card">${placesOverview(M, mp.sel, legs)}<figcaption>${ico('globe','sm')}Offline overview · borders from Natural Earth. Links open the place in a new tab; that site sees the coordinates, not your case.</figcaption></figure>` : ''}
        ${M.pts.map(card).join('')}
      </div>
      <aside class="pside">
        ${legs.length ? `<section class="card psec"><h4>${ico('route','sm')}Movement in time order</h4>${legs.map((l, i) => `<div class="pleg${l.kmh > 900 && l.km > 50 ? ' warn' : ''}"><span class="pleg-n">${i + 1}→${i + 2}</span><div><b>${kmText(l.km)}</b> in ${esc(E.fmtGap(l.b.ts - l.a.ts))}${isFinite(l.kmh) && l.km > 1 ? ` · ${Math.round(l.kmh).toLocaleString()} km/h` : ''}${l.kmh > 900 && l.km > 50 ? '<small>Faster than a plane. Check the times, the time zones or the places.</small>' : ''}</div></div>`).join('')}</section>` : ''}
        ${M.ctr.length ? `<section class="card psec"><h4>${ico('flag','sm')}Countries</h4>${M.ctr.map(x => `<div class="pctry"><div><b>${esc(x.name)}</b><small>${esc([...x.why.entries()].map(([w, n]) => w + (n > 1 ? ' ×' + n : '')).join(' · '))}</small></div>${ext('https://www.google.com/maps/search/?api=1&query=' + encodeURIComponent(x.name), 'Map', 'map')}</div>`).join('')}</section>` : ''}
        <section class="card psec"><h4>${ico('scan-search','sm')}Geolocation helpers</h4><p class="t3">For working out where a photo or video was taken.</p>
          <div class="phelp">${[['SunCalc','https://www.suncalc.org/','Sun angle and shadows at a time'],['PeakVisor','https://peakvisor.com/','Match mountain skylines'],['GeoHints','https://geohints.com/','Bollards, plates, road lines by country'],['Overpass turbo','https://overpass-turbo.eu/','Query OpenStreetMap features'],['Mapillary','https://www.mapillary.com/app/','Street-level photos worldwide'],['Sentinel EO Browser','https://apps.sentinel-hub.com/eo-browser/','Satellite images by date']].map(([n, u, d]) => `<a href="${u}" target="_blank" rel="noopener noreferrer"><b>${n}</b><small>${d}</small>${ico('arrow-up-right','sm')}</a>`).join('')}</div></section>
      </aside>
    </div></div></div>`;
}
function mountMap(){}
function mapSelect(k){
  UI.map.sel = k; document.querySelectorAll('.pcard').forEach(c => c.classList.remove('on')); document.querySelectorAll('.pdot').forEach(d => d.classList.toggle('on', d.dataset.v === k));
  const el = document.getElementById('pl-' + k.replace(/[^\w]/g, '_')); if(el){ el.classList.add('on'); el.scrollIntoView({block:'nearest', behavior:'smooth'}); }
}
function placesExport(kind){
  const M = UI.mapData, c = DB.cases.find(x => x.id === DB.active); if(!M || !M.pts.length) return;
  const name = (c ? c.code || c.name : 'case').replace(/[^\w.-]+/g, '_');
  if(kind === 'csv'){ const q = v => '"' + String(v == null ? '' : csvFormula(v)).replace(/"/g, '""') + '"';
    return download(name + '-places.csv', ['name,latitude,longitude,time_utc,source'].concat(M.pts.map(p => [q(p.label), p.la, p.lo, q(p.ts ? new Date(p.ts).toISOString() : ''), q([...p.src].join('; '))].join(','))).join('\n'), 'text/csv'); }
  const x = s => String(s == null ? '' : s).replace(/[<>&'"]/g, ch => ({'<':'&lt;','>':'&gt;','&':'&amp;',"'":'&apos;','"':'&quot;'})[ch]);
  const T = M.pts.filter(p => p.ts).sort((a, b) => a.ts - b.ts);
  const kml = `<?xml version="1.0" encoding="UTF-8"?>\n<kml xmlns="http://www.opengis.net/kml/2.2"><Document><name>${x(c ? c.name : 'Places')}</name>\n` +
    M.pts.map(p => `<Placemark><name>${x(p.label || 'Point')}</name><description>${x([...p.src].join(', '))}</description>${p.ts ? `<TimeStamp><when>${new Date(p.ts).toISOString()}</when></TimeStamp>` : ''}<Point><coordinates>${p.lo},${p.la},0</coordinates></Point></Placemark>`).join('\n') +
    (T.length > 1 ? `\n<Placemark><name>Movement</name><LineString><coordinates>${T.map(p => p.lo + ',' + p.la + ',0').join(' ')}</coordinates></LineString></Placemark>` : '') + '\n</Document></kml>';
  download(name + '-places.kml', kml, 'application/vnd.google-earth.kml+xml');
}
const MAP_ACTS = {
  mapSel:(id, v) => mapSelect(v),
  mapOpen:(id, v) => { const p = UI.mapData.pts.find(q => q.k === v); if(!p) return; if(p.entries[0]) selectEntry(p.entries[0].id); else if(p.recs[0]) select('rec', p.recs[0].id); },
  mapAdd:() => entryDlg(null, {type:'location', fields:{}}),
  placesKml:() => placesExport('kml'), placesCsv:() => placesExport('csv')
};
