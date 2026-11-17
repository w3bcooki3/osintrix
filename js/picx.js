/* ==========================================================================
   Picture intelligence — what a case's pictures say, and where else they appear.
   Works on the stored originals, in this browser only:
     · the same or a near-identical picture (cropped, resized, re-saved) in
       this case or in another case, by visual fingerprint (dHash)
     · the same camera — by body serial number, or by make and model — across cases
     · pictures taken within 250 m of each other across cases (EXIF GPS)
     · signs of editing: an editing program in the metadata, changed after it
       was taken, a capture date in the future, a GPS date that disagrees,
       and metadata stripped (typical of pictures saved from social media)
   Fingerprints and metadata are read once per picture and kept with it.
   ========================================================================== */
const PIC_EDIT = /photoshop|gimp|lightroom|snapseed|pixelmator|affinity|canva|picsart|facetune|paint\.net|krita|photopea|luminar|vsco|meitu|remini|faceapp|photo ?director|picasa|fotor|befunky/i;
const PIC = {busy:false, done:0, total:0};
const exifDate = s => { const m = String(s || '').match(/^(\d{4}):(\d{2}):(\d{2})[ T](\d{2}):(\d{2}):(\d{2})/); return m ? Date.UTC(+m[1], m[2] - 1, +m[3], +m[4], +m[5], +m[6]) : null; };
/* the parts of the metadata worth keeping with a picture */
function picMeta(x){
  if(!x) return {none:true}; const s = v => v == null ? '' : String(v).slice(0, 120);
  return {make:s(x.Make), model:s(x.Model), serial:s(x['Body serial']), lens:s(x.Lens), soft:s(x.Software), taken:s(x.Taken), mod:s(x.Modified), gpsDate:s(x['GPS date'])};
}
function picAll(){
  const out = []; for(const r of DB.records) for(const a of r.att || []) if(mediaKind(a) === 'image') out.push({r, a, c:theCase(r.caseId)});
  return out;
}
/* read fingerprints and metadata for pictures that do not have them yet (older files) */
async function picScan(onStep){
  if(PIC.busy) return; const todo = picAll().filter(x => !x.a.dhash || !x.a.psig || x.a.x == null); if(!todo.length) return;
  PIC.busy = true; PIC.done = 0; PIC.total = todo.length;
  try{ for(const {a} of todo){ const b = await fileBlob(a.id);
      if(b){ if(!a.dhash) a.dhash = await dhashBlob(b); if(!a.psig && typeof picSigBlob === 'function') a.psig = await picSigBlob(b) || '';
        if(a.x == null){ let x = null; if(/jpe?g|tiff|heic/i.test(a.type || a.name)){ try{ x = exif(new Uint8Array(await b.slice(0, 256 * 1024).arrayBuffer())); }catch(e){} } a.x = picMeta(x);
          if(x && x.GPS && !a.gps) a.gps = x.GPS; if(x && !a.cam) a.cam = [x.Make, x.Model].filter(Boolean).join(' '); } }
      else a.x = a.x || {missing:true};
      PIC.done++; if(onStep) onStep(); }
    save(); }
  finally { PIC.busy = false; }
}
/* union-find over visual fingerprints */
function picGroups(all){
  const L = all.filter(x => x.a.dhash), P = L.map((_, i) => i), f = i => P[i] === i ? i : (P[i] = f(P[i]));
  for(let i = 0; i < L.length; i++) for(let j = i + 1; j < L.length; j++){ const A = L[i].a, B = L[j].a;
    const ok = A.id === B.id || A.sha256 === B.sha256 || (A.psig && B.psig && typeof picMatch === 'function' ? !!picMatch(A.psig, B.psig) : hamming(A.dhash, B.dhash) <= 10); if(ok){ P[f(i)] = f(j); } }
  const G = new Map(); L.forEach((x, i) => { const k = f(i); if(!G.has(k)) G.set(k, []); G.get(k).push(x); });
  return [...G.values()].filter(g => new Set(g.map(x => x.a.sha256)).size > 1 || new Set(g.map(x => x.r.id)).size > 1);
}
function picFlags(a){
  const x = a.x || {}, out = [], tk = exifDate(x.taken), md = exifDate(x.mod);
  if(x.soft && PIC_EDIT.test(x.soft)) out.push(['red', 'Edited in ' + x.soft]);
  else if(x.soft && !/^(ver\.?|v)?\s*[\d.]+\w*$/i.test(x.soft) && !(x.make && x.soft.toLowerCase().includes(x.make.toLowerCase().split(' ')[0]))) out.push(['amber', 'Saved by ' + x.soft]);
  if(tk && md && md - tk > 6e4) out.push(['amber', 'Changed ' + E.fmtGap(md - tk) + ' after it was taken']);
  if(tk && tk > Date.now() + 864e5) out.push(['red', 'Capture date in the future']);
  if(tk && x.gpsDate){ const g = String(x.gpsDate).match(/^(\d{4}):(\d{2}):(\d{2})/); if(g){ const gd = Date.UTC(+g[1], g[2] - 1, +g[3]); if(Math.abs(gd - Date.UTC(new Date(tk).getUTCFullYear(), new Date(tk).getUTCMonth(), new Date(tk).getUTCDate())) > 864e5 * 1.5) out.push(['amber', 'GPS date disagrees with the capture date']); } }
  if(x.none && /jpe?g/i.test(a.type || a.name)) out.push(['', 'No camera metadata — typical of pictures saved from social media or messaging apps']);
  return out;
}
const picLoc = a => a.gps && isFinite(a.gps.lat) && isFinite(a.gps.lon) ? {la:a.gps.lat, lo:a.gps.lon} : null;
function picInsight(caseId){
  const all = picAll(), mine = all.filter(x => x.r.caseId === caseId);
  const groups = picGroups(all).filter(g => g.some(x => x.r.caseId === caseId)).map(g => ({g, cross:new Set(g.map(x => x.r.caseId)).size > 1, exact:new Set(g.map(x => x.a.sha256)).size === 1}))
    .sort((a, b) => b.cross - a.cross || b.g.length - a.g.length);
  const camKey = a => a.x && a.x.serial ? 'sn:' + a.x.serial : a.x && (a.x.make || a.x.model) ? 'mm:' + [a.x.make, a.x.model].filter(Boolean).join(' ') : '';
  const cams = new Map(); for(const x of mine){ const k = camKey(x.a); if(!k) continue; if(!cams.has(k)) cams.set(k, {k, n:0, other:[]}); cams.get(k).n++; }
  for(const c of cams.values()) c.other = [...new Set(all.filter(x => x.r.caseId !== caseId && camKey(x.a) === c.k).map(x => x.r.caseId))].map(theCase).filter(Boolean);
  const places = []; const others = all.filter(x => x.r.caseId !== caseId && picLoc(x.a));
  for(const x of mine){ const p = picLoc(x.a); if(!p) continue; for(const y of others){ if(y.a.sha256 === x.a.sha256) continue; const km = haversine(p, picLoc(y.a)); if(km <= 0.25) places.push({x, y, m:Math.round(km * 1000)}); } }
  const flagged = mine.map(x => ({...x, f:picFlags(x.a)})).filter(x => x.f.length);
  return {n:mine.length, groups, cams:[...cams.values()].sort((a, b) => b.other.length - a.other.length || b.n - a.n), places:places.slice(0, 12), flagged, unread:mine.filter(x => !x.a.dhash || x.a.x == null).length, withGps:mine.filter(x => picLoc(x.a)).length};
}
function picView(c){
  const I = picInsight(c.id), th = x => `<button class="md-th pic-th" data-act="mdOpen" data-id="${x.r.id}" data-v="${esc(x.a.id)}" aria-label="Open ${esc(x.a.name)}"><img data-pid="${esc(x.a.id)}" data-pk="image" alt=""><span class="md-ic">${ico('image')}</span></button>`;
  const where = x => x.r.caseId === c.id ? '<span class="t3">this case</span>' : `<button class="linkbtn" data-act="picCase" data-id="${x.r.caseId}">${esc(x.c ? x.c.code + ' · ' + x.c.name.split(' — ')[0] : 'another case')}</button>`;
  const card = (icon, tone, title, body) => `<section class="card tlx-c ${tone}"><div class="tlx-h"><span class="tb sm">${ico(icon,'sm')}</span><h3>${title}</h3></div><div class="tlx-b">${body}</div></section>`;
  if(!I.n) return `<div class="page wide">${empty('scan-face', 'No pictures in this case yet', 'Add pictures to the case and this view compares them with every other case: the same picture, the same camera, the same place, and signs of editing.')}</div>`;
  if(I.unread && !PIC.busy) setTimeout(() => picScan(() => { const el = $('picProg'); if(el) el.textContent = `Reading pictures… ${PIC.done} of ${PIC.total}`; }).then(() => { if(UI.route.tab === 'media' && UI.mdV === 'pic') renderMain(); }), 30);
  const parts = [];
  parts.push(`<section class="card tlx-sum"><div class="tlx-kpi"><div><b>${I.n}</b><span>picture${I.n === 1 ? '' : 's'}</span></div><div class="${I.groups.some(g => g.cross) ? 'r' : ''}"><b>${I.groups.length}</b><span>repeated or near-identical</span></div><div><b>${I.cams.length}</b><span>camera${I.cams.length === 1 ? '' : 's'} named</span></div><div><b>${I.withGps}</b><span>with a location</span></div><div class="${I.flagged.some(x => x.f.some(f => f[0] === 'red')) ? 'r' : ''}"><b>${I.flagged.length}</b><span>with something to check</span></div></div>
    ${I.unread ? `<p class="t3" id="picProg" role="status">Reading pictures… ${PIC.done} of ${PIC.total || I.unread}</p>` : '<p class="t3 small" style="margin:0">Compared with every picture in every case on this browser. Nothing is sent anywhere.</p>'}</section>`);
  if(I.groups.length) parts.push(card('copy', I.groups.some(g => g.cross) ? 'red' : 'amber', 'The same picture, more than once', `<ul class="tlx-l">${I.groups.slice(0, 8).map(G => `<li><div><b>${G.exact ? 'Identical file' : 'Near-identical — cropped, resized or re-saved'}</b>${G.cross ? ' <span class="chip sq red">also in another case</span>' : ''}</div>
      <div class="pic-row">${G.g.slice(0, 6).map(x => `<div class="pic-it">${th(x)}<small>${esc(x.a.name)}</small>${where(x)}</div>`).join('')}</div></li>`).join('')}</ul>
    <p class="t3 small">The same picture in two cases often links the people or accounts behind them. Near-identical copies show a picture was edited or re-shared.</p>`));
  if(I.cams.length) parts.push(card('camera', I.cams.some(x => x.other.length) ? 'amber' : '', 'Cameras', `<ul class="tlx-l">${I.cams.slice(0, 8).map(x => `<li><div><b>${esc(x.k.slice(3))}</b>${x.k.startsWith('sn:') ? ' <span class="t3">body serial</span>' : ''} · ${x.n} picture${x.n === 1 ? '' : 's'}</div>${x.other.length ? `<div>Also in ${x.other.map(o => `<button class="linkbtn" data-act="picCase" data-id="${o.id}">${esc(o.code)}</button>`).join(', ')}${x.k.startsWith('sn:') ? ' — <b>the same physical camera</b>' : ' — same make and model, not necessarily the same device'}</div>` : ''}</li>`).join('')}</ul>`));
  if(I.places.length) parts.push(card('map-pin', 'amber', 'Taken at the same place as pictures in other cases', `<ul class="tlx-l">${I.places.map(p => `<li><div class="pic-row">${[p.x, p.y].map(x => `<div class="pic-it">${th(x)}<small>${esc(x.a.name)}</small>${where(x)}</div>`).join('')}</div><div class="t2">${p.m < 5 ? 'The same spot' : p.m + ' m apart'}</div></li>`).join('')}</ul>`));
  if(I.flagged.length) parts.push(card('scan-face', I.flagged.some(x => x.f.some(f => f[0] === 'red')) ? 'red' : '', 'Worth a closer look', `<ul class="tlx-l">${I.flagged.slice(0, 20).map(x => `<li><div class="pic-row"><div class="pic-it">${th(x)}</div><div><b>${esc(x.a.name)}</b>${x.f.map(([t, l]) => `<div>${t ? `<span class="chip sq ${t}">${esc(l)}</span>` : `<span class="t2">${esc(l)}</span>`}</div>`).join('')}${x.a.x && (x.a.x.make || x.a.x.taken) ? `<div class="t3 small">${esc([x.a.x.make, x.a.x.model].filter(Boolean).join(' '))}${x.a.x.taken ? ' · taken ' + esc(x.a.x.taken) : ''}</div>` : ''}<button class="btn xs" data-act="picEla" data-id="${x.r.id}" data-v="${esc(x.a.id)}">${ico('scan','sm')}Check for editing in the Lab</button></div></div></li>`).join('')}</ul>
    <p class="t3 small">Metadata can be removed or forged, so treat these as leads. The Lab's error-level analysis shows which parts of a JPEG were changed.</p>`));
  if(parts.length === 1) parts.push(card('check', '', 'Nothing stands out', '<p>No repeats, shared cameras, shared places or signs of editing among these pictures.</p>'));
  return `<div class="page wide tlx">${parts.join('')}</div>`;
}
const PIC_ACTS = {
  mdView:(id, v) => { UI.mdV = v; renderMain(); },
  picCase:id => { if(theCase(id)){ UI.mdV = 'pic'; go(caseHash(id, 'media')); } },
  picEla:async (id, v) => { const b = await fileBlob(v), r = recById(id), a = r && (r.att || []).find(x => x.id === v); if(!b || !a) return toast('That picture is missing from this browser');
    UI.labTab = 'image'; go('#/lab'); setTimeout(() => imgLoad(new File([b], a.name, {type:a.type})), 80); },
};

/* in the evidence panel: where else this picture is — cropped, mirrored, framed, re-saved — in any case */
function picSameSection(r){
  const own = (r.att || []).filter(a => typeof mediaKind === 'function' && mediaKind(a) === 'image'); if(!own.length) return '';
  const all = picAll(), rows = [];
  for(const a of own){ for(const y of all){ if(y.a.id === a.id) continue; let m = null;
      if(y.a.sha256 && y.a.sha256 === a.sha256) m = {d:0, how:'exact'}; else if(a.psig && y.a.psig && typeof picMatch === 'function') m = picMatch(y.a.psig, a.psig);   /* said from the other picture's side */ else if(a.dhash && y.a.dhash && hamming(a.dhash, y.a.dhash) <= 10) m = {d:hamming(a.dhash, y.a.dhash), how:'same'};
      if(m) rows.push({a, y, m}); } }
  rows.sort((p, q) => (q.y.r.caseId !== r.caseId) - (p.y.r.caseId !== r.caseId) || p.m.d - q.m.d);
  const pending = own.some(a => !a.psig);
  if(pending && !PIC.busy) setTimeout(() => picScan().then(() => { if(typeof renderInsp === 'function') renderInsp(); }), 0);
  const how = m => m.how === 'exact' ? 'the identical file' : (PIC_HOW[m.how] || m.how);
  return `<div class="isec"><h4>The same picture elsewhere ${rows.length ? `<span class="t3">${rows.length}</span>` : ''}</h4>
    ${rows.length ? `<ul class="ps-l">${rows.slice(0, 12).map(x => `<li><button class="md-th ps-th" data-act="selRec" data-id="${x.y.r.id}" aria-label="Open ${esc(x.y.a.name)}"><img data-pid="${esc(x.y.a.id)}" data-pk="image" alt=""></button>
      <div><button class="lnk" data-act="selRec" data-id="${x.y.r.id}">${esc(x.y.a.name)}</button><div class="t3 small">${x.y.r.caseId === r.caseId ? 'this case' : esc(((x.y.c || {}).code || 'another case') + ' · ' + ((x.y.c || {}).name || '').split(' — ')[0])} · ${esc(how(x.m))}</div></div></li>`).join('')}</ul>`
      : `<p class="t3 small" style="margin:0 0 8px">${pending ? 'Fingerprinting this picture…' : 'Not in any other evidence — cropped, mirrored, framed in a screenshot or re-saved copies would show here.'}</p>`}
    <div class="t3 small" style="margin:8px 0 4px">Look for it on the web — opens the site; drop the picture in yourself:</div>
    <div class="pivots">${[['Google Lens', 'https://lens.google.com/'], ['Bing Visual Search', 'https://www.bing.com/visualsearch'], ['Yandex Images', 'https://yandex.com/images/'], ['TinEye', 'https://tineye.com/']].map(([l, u]) => `<a class="btn xs" href="${u}" target="_blank" rel="noopener noreferrer">${esc(l)}</a>`).join('')}</div></div>`;
}
