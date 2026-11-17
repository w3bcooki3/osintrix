/* ==========================================================================
   Where was this taken? — a geolocation workbench for a picture or video.
   You write down what you see (signs, script, road markings, buildings,
   plants and terrain, sun and shadows, landmarks) and the places you think it
   could be. For each place you mark which clues fit and which do not; the sun's
   direction and height at that place, at the moment the file says it was made,
   are worked out for you, and the file's own GPS, camera direction and place
   names are put next to your candidates. A confirmed place goes on the case's
   map and can be added to the vault. Everything stays in this browser; links
   open the coordinates (not your case) in the map site you choose.
   ========================================================================== */
const GEO_KINDS = [['sign', 'Sign or text'], ['lang', 'Language or script'], ['road', 'Road, traffic, plates'], ['build', 'Buildings'], ['nature', 'Plants, terrain, coast'], ['sky', 'Sun, shadows, weather'], ['mark', 'Landmark'], ['other', 'Other']];
const GEO_VERDICT = [['confirmed', 'Confirmed', 'red'], ['likely', 'Likely', 'amber'], ['', 'Possible', ''], ['out', 'Ruled out', '']];
const GEO_LINKS = ['Google Maps', 'Street View', 'Google Earth', 'Bing aerial', 'OpenStreetMap', 'Mapillary', 'Yandex', 'Overpass turbo'];
/* a record's geolocation work, checked every time it is read: it comes back from imports and backups */
function geoOf(r){
  const g = r && r.geo && typeof r.geo === 'object' ? r.geo : {}, kinds = new Set(GEO_KINDS.map(k => k[0])), verd = new Set(GEO_VERDICT.map(v => v[0]));
  const clues = (Array.isArray(g.clues) ? g.clues : []).filter(c => c && typeof c.id === 'string' && typeof c.text === 'string' && c.text.trim()).slice(0, 200).map(c => ({id:c.id.slice(0, 40), kind:kinds.has(c.kind) ? c.kind : 'other', text:c.text.slice(0, 500)}));
  const ids = new Set(clues.map(c => c.id));
  const cands = (Array.isArray(g.cands) ? g.cands : []).filter(c => c && typeof c.id === 'string' && isFinite(c.lat) && isFinite(c.lon) && Math.abs(c.lat) <= 90 && Math.abs(c.lon) <= 180).slice(0, 100)
    .map(c => ({id:c.id.slice(0, 40), name:String(c.name || '').slice(0, 160), lat:+c.lat, lon:+c.lon, verdict:verd.has(c.verdict) ? c.verdict : '', note:String(c.note || '').slice(0, 1000),
      fit:Object.fromEntries(Object.entries(c.fit && typeof c.fit === 'object' ? c.fit : {}).filter(([k, v]) => ids.has(k) && (v === 'y' || v === 'n'))), entry:typeof c.entry === 'string' ? c.entry : ''}));
  return {clues, cands, note:String(g.note || '').slice(0, 4000)};
}
/* coordinates as people paste them: decimal, degrees-minutes-seconds, or a map link */
function geoParse(s){
  s = String(s || '').trim(); if(!s) return null; let m;
  const ok = (la, lo) => isFinite(la) && isFinite(lo) && Math.abs(la) <= 90 && Math.abs(lo) <= 180 ? {lat:+(+la).toFixed(6), lon:+(+lo).toFixed(6)} : null;
  if((m = s.match(/!3d(-?\d+(?:\.\d+)?)!4d(-?\d+(?:\.\d+)?)/))) return ok(m[1], m[2]);
  if((m = s.match(/@(-?\d+(?:\.\d+)?),(-?\d+(?:\.\d+)?)/))) return ok(m[1], m[2]);
  if((m = s.match(/[?&](?:q|query|ll|viewpoint|center)=(-?\d+(?:\.\d+)?)(?:,|%2C)\s*(-?\d+(?:\.\d+)?)/i))) return ok(m[1], m[2]);
  if((m = s.match(/mlat=(-?\d+(?:\.\d+)?).*?mlon=(-?\d+(?:\.\d+)?)/))) return ok(m[1], m[2]);
  if((m = s.match(/#map=\d+\/(-?\d+(?:\.\d+)?)\/(-?\d+(?:\.\d+)?)/))) return ok(m[1], m[2]);
  const dms = /(\d{1,3})\s*[°º:\s]\s*(\d{1,2})\s*['′:\s]\s*(\d{1,2}(?:[.,]\d+)?)\s*(?:["″]|'')?\s*([NSEW])/gi, D = [...s.matchAll(dms)];
  if(D.length === 2){ const v = x => (+x[1] + +x[2] / 60 + +String(x[3]).replace(',', '.') / 3600) * (/[SW]/i.test(x[4]) ? -1 : 1); const a = /[NS]/i.test(D[0][4]) ? D[0] : D[1], b = a === D[0] ? D[1] : D[0]; return ok(v(a), v(b)); }
  if((m = s.match(/^\s*(-?\d{1,2}(?:\.\d+)?)\s*°?\s*([NS])?\s*[,;\s]\s*(-?\d{1,3}(?:\.\d+)?)\s*°?\s*([EW])?\s*$/i))) return ok(+m[1] * (/S/i.test(m[2] || '') ? -1 : 1), +m[3] * (/W/i.test(m[4] || '') ? -1 : 1));
  return null;
}
/* the sun at a place and moment (the SunCalc formulas): compass direction and height above the horizon, in degrees */
function sunAt(ms, lat, lon){
  const rad = Math.PI / 180, d = ms / 864e5 - 0.5 + 2440588 - 2451545, M = rad * (357.5291 + 0.98560028 * d);
  const L = M + rad * (1.9148 * Math.sin(M) + 0.02 * Math.sin(2 * M) + 0.0003 * Math.sin(3 * M)) + rad * 102.9372 + Math.PI, e = rad * 23.4397;
  const dec = Math.asin(Math.sin(e) * Math.sin(L)), ra = Math.atan2(Math.sin(L) * Math.cos(e), Math.cos(L)), phi = rad * lat, H = rad * (280.16 + 360.9856235 * d) - rad * -lon - ra;
  const az = Math.atan2(Math.sin(H), Math.cos(H) * Math.sin(phi) - Math.tan(dec) * Math.cos(phi)), alt = Math.asin(Math.sin(phi) * Math.sin(dec) + Math.cos(phi) * Math.cos(dec) * Math.cos(H));
  return {az:((az / rad + 180) % 360 + 360) % 360, alt:alt / rad};
}
const geoDir = a => ['north', 'north-north-east', 'north-east', 'east-north-east', 'east', 'east-south-east', 'south-east', 'south-south-east', 'south', 'south-south-west', 'south-west', 'west-south-west', 'west', 'west-north-west', 'north-west', 'north-north-west'][Math.round(((a % 360) + 360) % 360 / 22.5) % 16];
/* when the file says it was made, and whether that moment is exact */
function geoWhen(r){
  const a = (r.att || [])[0], M = a && a.meta; if(!M || M.taken == null || !isFinite(M.taken)) return null;
  return {ms:M.taken, exact:M.tz !== 'assumed'};
}
function geoSunText(r, c){
  const w = geoWhen(r); if(!w) return '';
  /* without a time zone the camera's clock is local time: the sun is worked out for the zone the longitude suggests, and said so */
  const off = w.exact ? 0 : Math.round(c.lon / 15), ms = w.ms - off * 36e5, S = sunAt(ms, c.lat, c.lon);
  if(S.alt < -6) return `At that moment the sun was down (${Math.round(S.alt)}°) — it was night there${w.exact ? '' : ` (time zone not recorded; assumed UTC${off >= 0 ? '+' : ''}${off} from the longitude)`}.`;
  const sh = (S.az + 180) % 360, len = S.alt > 0.5 ? 1 / Math.tan(S.alt * Math.PI / 180) : null;
  return `Sun at ${Math.round(S.az)}° (${geoDir(S.az)}), ${Math.round(S.alt)}° up; shadows point ${Math.round(sh)}° (${geoDir(sh)})${len != null && len < 40 ? `, about ${len < 10 ? len.toFixed(1) : Math.round(len)}× as long as the object is tall` : ''}.${w.exact ? '' : ` Time zone not recorded: assumed UTC${off >= 0 ? '+' : ''}${off} from the longitude.`}`;
}
function geoScore(c){ const v = Object.values(c.fit); return {y:v.filter(x => x === 'y').length, n:v.filter(x => x === 'n').length}; }
function geoSorted(G){ const o = {confirmed:0, likely:1, '':2, out:3}; return [...G.cands].sort((a, b) => o[a.verdict] - o[b.verdict] || (geoScore(b).y - geoScore(b).n) - (geoScore(a).y - geoScore(a).n)); }
/* one line for the evidence panel */
function geoSummary(r){ const G = geoOf(r), c = G.cands.find(x => x.verdict === 'confirmed') || G.cands.find(x => x.verdict === 'likely');
  if(!G.clues.length && !G.cands.length) return ''; return `${G.clues.length} clue${G.clues.length === 1 ? '' : 's'} · ${G.cands.length} place${G.cands.length === 1 ? '' : 's'}${c ? ` · ${c.verdict === 'confirmed' ? 'Confirmed' : 'Likely'}: ${c.name || c.lat + ', ' + c.lon}` : ''}`; }
function geoSection(r){
  const a = (r.att || []).find(x => typeof mediaKind === 'function' && /image|video/.test(mediaKind(x))); if(!a && !r.geo) return '';
  const s = geoSummary(r);
  return `<div class="isec"><h4>Where was this taken?</h4>${s ? `<p class="t2 small" style="margin:0 0 8px">${esc(s)}</p>` : ''}<button class="btn sm" data-act="geoOpen" data-id="${esc(r.id)}">${ico('scan-search','sm')}${s ? 'Continue geolocating' : 'Geolocate'}</button></div>`;
}
function geoDlg(rid){
  const r = recById(rid); if(!r) return; UI.geo = {rid}; const G = geoOf(r), a = (r.att || []).find(x => typeof mediaKind === 'function' && /image|video/.test(mediaKind(x))) || (r.att || [])[0], M = a && a.meta;
  const fileGps = a && a.gps && isFinite(a.gps.lat) ? {la:+a.gps.lat, lo:+a.gps.lon} : null, mf = k => M && M.fields ? (M.fields.find(f => f.k === k) || {}).v || '' : '';
  const facts = [['Location in the file', fileGps ? `${fileGps.la}, ${fileGps.lo}` : ''], ['Camera facing', mf('Camera facing')], ['Taken', M && M.taken != null ? E.fmtFull(M.taken, tz()) + (M.tz === 'assumed' ? ' (camera clock, time zone not recorded)' : '') : ''],
    ['Place names in the file', [mf('Sub-location') || mf('Place'), mf('City'), mf('State / province'), mf('Country')].filter(Boolean).join(', ')], ['Device', [mf('Make'), mf('Model')].filter(Boolean).join(' ')]].filter(x => x[1]);
  const kind = a && typeof mediaKind === 'function' ? mediaKind(a) : '';
  const fit = (c, cl) => { const v = c.fit[cl.id] || ''; return `<button type="button" class="geo-fit ${v === 'y' ? 'y' : v === 'n' ? 'n' : ''}" data-act="geoFit" data-id="${esc(c.id)}" data-v="${esc(cl.id)}" aria-label="${esc(cl.text)}: ${v === 'y' ? 'fits' : v === 'n' ? 'does not fit' : 'not checked'} — change" title="${v === 'y' ? 'Fits' : v === 'n' ? 'Does not fit' : 'Not checked'} — click to change">${ico(v === 'y' ? 'check' : v === 'n' ? 'x' : 'circle-help','sm')}<span>${esc(cl.text.length > 48 ? cl.text.slice(0, 46) + '…' : cl.text)}</span></button>`; };
  const cand = c => { const sc = geoScore(c), la = c.lat.toFixed(6), lo = c.lon.toFixed(6), d = fileGps && typeof haversine === 'function' ? haversine(fileGps, {la:c.lat, lo:c.lon}) : null, sun = geoSunText(r, c);
    return `<article class="geo-c${c.verdict === 'out' ? ' out' : ''}"><header><div><b>${esc(c.name || 'Unnamed place')}</b> <button class="lnk mono small" data-act="geoCopy" data-v="${la}, ${lo}" title="Copy coordinates">${la}, ${lo}</button>${d != null ? `<span class="t3 small"> · ${typeof kmText === 'function' ? kmText(d) : d.toFixed(1) + ' km'} from the file's GPS</span>` : ''}</div>
      <button class="iconbtn" data-act="geoDelC" data-id="${esc(c.id)}" aria-label="Remove ${esc(c.name || 'this place')}">${ico('trash-2','sm')}</button></header>
      <div class="seg geo-v" role="radiogroup" aria-label="Verdict for ${esc(c.name || 'this place')}">${GEO_VERDICT.map(([v, l]) => `<button type="button" data-act="geoVerdict" data-id="${esc(c.id)}" data-v="${v}" aria-pressed="${c.verdict === v}">${l}</button>`).join('')}</div>
      ${G.clues.length ? `<div class="geo-fits"><span class="t3 small">${sc.y} fit · ${sc.n} do not · ${G.clues.length - sc.y - sc.n} not checked</span><div class="wrap">${G.clues.map(cl => fit(c, cl)).join('')}</div></div>` : ''}
      ${sun ? `<p class="geo-sun small">${ico('sun','sm')}<span>${esc(sun)}</span></p>` : ''}
      <div class="plinks">${typeof PLACE_LINKS !== 'undefined' ? PLACE_LINKS.filter(([l]) => GEO_LINKS.includes(l)).map(([l, f, i]) => ext(f(la, lo), l, i)).join('') + ext((PLACE_LINKS.find(x => x[0] === 'Sun position') || [, () => ''])[1](la, lo, M && M.taken), 'Sun position', 'sun') : ''}</div>
      <label class="geo-note"><span class="sr">Notes on ${esc(c.name || 'this place')}</span><textarea rows="1" data-geonote="${esc(c.id)}" placeholder="Why — what matches, what does not">${esc(c.note)}</textarea></label></article>`; };
  const html = dhead(`Where was this taken? <span class="t3">${esc(a ? a.name : r.title)}</span>`) + `<div class="in geo">
    <div class="geo-l">
      ${a && (kind === 'image') ? `<img class="geo-img" data-fid="${esc(a.id)}" alt="${esc(a.name)}">` : a && kind === 'video' ? `<div class="geo-img geo-vid t3">${ico('play')} Video — open it from the evidence panel to look frame by frame</div>` : ''}
      ${facts.length ? `<dl class="geo-facts">${facts.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>${fileGps && !G.cands.some(c => Math.abs(c.lat - fileGps.la) < 1e-6 && Math.abs(c.lon - fileGps.lo) < 1e-6) ? `<button class="btn xs" data-act="geoFromFile">${ico('map-pin','sm')}Add the file's location as a place to check</button>` : ''}` : '<p class="t3 small">The file records no place, direction or time — work from what you can see.</p>'}
      <p class="t3 small">A location in the file can be wrong or planted: treat it as one more candidate and check it against what you see.</p>
    </div>
    <div class="geo-r">
      <section><h4>What you see <span class="t3">${G.clues.length}</span></h4>
        ${G.clues.length ? `<ul class="geo-cl">${G.clues.map(c => `<li><span class="chip sq">${esc((GEO_KINDS.find(k => k[0] === c.kind) || [, 'Other'])[1])}</span><span>${esc(c.text)}</span><button class="iconbtn" data-act="geoDelClue" data-id="${esc(c.id)}" aria-label="Remove the clue ${esc(c.text)}">${ico('x','sm')}</button></li>`).join('')}</ul>` : ''}
        <form class="geo-add" data-form="geoClue"><label class="sr" for="geoK">Kind</label><select id="geoK">${GEO_KINDS.map(([k, l]) => `<option value="${k}"${UI.geoK === k ? ' selected' : ''}>${l}</option>`).join('')}</select>
          <label class="sr" for="geoT">Clue</label><input id="geoT" maxlength="500" placeholder="e.g. Cyrillic shop sign “АПТЕКА”, cars drive on the left, palm trees" autocomplete="off"><button class="btn sm" type="submit">${ico('plus','sm')}Add clue</button></form></section>
      <section><h4>Places it could be <span class="t3">${G.cands.length}</span></h4>
        ${geoSorted(G).map(cand).join('')}
        <form class="geo-add" data-form="geoCand"><label class="sr" for="geoN">Place name</label><input id="geoN" maxlength="160" placeholder="Name — e.g. Harbour Rd near the ferry pier" autocomplete="off">
          <label class="sr" for="geoP">Coordinates or map link</label><input id="geoP" class="mono" placeholder="51.7624, -0.3179 · 51°45'44.7&quot;N 0°19'04.4&quot;W · a Google Maps or OSM link" autocomplete="off" spellcheck="false"><button class="btn sm" type="submit">${ico('plus','sm')}Add place</button></form></section>
    </div></div>
    <footer><span class="t3 small">${esc(geoSummary(r) || 'Nothing yet')}</span><span class="sp"></span>${G.cands.some(c => c.verdict === 'confirmed' && !c.entry) ? `<button class="btn" data-act="geoVault">${ico('map-pin','sm')}Add the confirmed place to the vault</button>` : ''}<button class="btn primary" type="button" data-act="dclose">Done</button></footer>`;
  const keep = $('dlg') && $('dlg').querySelector('.in') ? $('dlg').querySelector('.in').scrollTop : 0, open = !$('scrim').hidden && $('dlg').querySelector('.geo');
  if(open){ $('dlg').innerHTML = html; const i = $('dlg').querySelector('.in'); if(i) i.scrollTop = keep; } else openDlg(html, true);
  if(typeof hydrateThumbs === 'function') hydrateThumbs($('dlg'));
}
function geoSave(r, G, what){ r.geo = G; mutate(what); if(typeof renderInsp === 'function') renderInsp(); geoDlg(r.id); }
function geoSubmit(kind){
  const r = recById(UI.geo && UI.geo.rid); if(!r) return; const G = geoOf(r);
  if(kind === 'geoClue'){ const t = String($('geoT').value || '').replace(/\s+/g, ' ').trim(), k = $('geoK').value; UI.geoK = k; if(!t) return fieldErr('geoT', 'Write what you see.');
    if(G.clues.some(c => normName(c.text) === normName(t))) return fieldErr('geoT', 'That clue is already on the list.'); G.clues.push({id:uid('gc'), kind:k, text:t}); geoSave(r, G, 'added a geolocation clue'); setTimeout(() => $('geoT') && $('geoT').focus(), 0); return; }
  const n = String($('geoN').value || '').replace(/\s+/g, ' ').trim(), p = geoParse($('geoP').value);
  if(!p) return fieldErr('geoP', 'Paste coordinates (51.7624, -0.3179 or 51°45\'44.7"N 0°19\'04.4"W) or a Google Maps or OpenStreetMap link.');
  const dup = G.cands.find(c => typeof haversine === 'function' ? haversine({la:c.lat, lo:c.lon}, {la:p.lat, lo:p.lon}) < 0.025 : c.lat === p.lat && c.lon === p.lon);
  if(dup) return fieldErr('geoP', `That is within 25 m of “${dup.name || dup.lat + ', ' + dup.lon}”, already on the list.`);
  G.cands.push({id:uid('gp'), name:n, lat:p.lat, lon:p.lon, verdict:'', note:'', fit:{}}); geoSave(r, G, 'added a place to check');
}
const GEO_ACTS = {
  geoOpen:id => geoDlg(id),
  geoFit:(id, v) => { const r = recById(UI.geo.rid), G = geoOf(r), c = G.cands.find(x => x.id === id); if(!c) return; c.fit[v] = c.fit[v] === 'y' ? 'n' : c.fit[v] === 'n' ? undefined : 'y'; if(!c.fit[v]) delete c.fit[v]; geoSave(r, G, 'checked a clue against a place'); },
  geoVerdict:(id, v) => { const r = recById(UI.geo.rid), G = geoOf(r), c = G.cands.find(x => x.id === id); if(!c) return; c.verdict = v;
    if(v === 'confirmed') for(const o of G.cands) if(o !== c && o.verdict === 'confirmed') o.verdict = 'likely';       // one place is where it was taken
    geoSave(r, G, 'set a geolocation verdict'); },
  geoDelC:id => { const r = recById(UI.geo.rid), G = geoOf(r), c = G.cands.find(x => x.id === id); if(!c) return; G.cands = G.cands.filter(x => x !== c); geoSave(r, G, 'removed a place'); toast('Place removed', 'Undo', () => { const G2 = geoOf(r); G2.cands.push(c); geoSave(r, G2, 'restored a place'); }); },
  geoDelClue:id => { const r = recById(UI.geo.rid), G = geoOf(r); G.clues = G.clues.filter(x => x.id !== id); for(const c of G.cands) delete c.fit[id]; geoSave(r, G, 'removed a clue'); },
  geoFromFile:() => { const r = recById(UI.geo.rid), a = (r.att || []).find(x => x.gps), G = geoOf(r); if(!a) return; G.cands.push({id:uid('gp'), name:'Location in the file', lat:+(+a.gps.lat).toFixed(6), lon:+(+a.gps.lon).toFixed(6), verdict:'', note:'', fit:{}}); geoSave(r, G, 'added the file location as a place'); },
  geoCopy:(id, v) => copyText(v),
  geoVault:() => { const r = recById(UI.geo.rid), G = geoOf(r), c = G.cands.find(x => x.verdict === 'confirmed'); if(!c || c.entry) return;
    const e = {id:uid('v'), caseId:r.caseId, type:'location', fields:{address:c.name || 'Geolocated: ' + ((r.att || [])[0] || {}).name, coordinates:c.lat + ', ' + c.lon}, priority:'high', starred:false, tags:['geolocated'], notes:`Where ${((r.att || [])[0] || {}).name || 'the evidence'} was taken — confirmed by geolocation.${c.note ? '\n' + c.note : ''}`, src:r.id, created:Date.now(), pos:null};
    DB.entries.push(e); c.entry = e.id; geoSave(r, G, 'added a geolocated place to the vault'); toast('Added to the vault'); },
};
/* notes save as you type, without redrawing */
document.addEventListener('input', ev => { const t = ev.target; if(!t || !t.dataset || !t.dataset.geonote || !UI.geo) return; const r = recById(UI.geo.rid); if(!r) return; const G = geoOf(r), c = G.cands.find(x => x.id === t.dataset.geonote); if(!c) return;
  c.note = t.value.slice(0, 1000); r.geo = G; clearTimeout(UI.geoT); UI.geoT = setTimeout(() => { rev++; cache = {}; save(); }, 400); });
