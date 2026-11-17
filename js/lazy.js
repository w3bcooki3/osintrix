/* ==========================================================================
   Background loading for the big data files.
   The reference data (the MAC vendor list, the CISA KEV catalogue, the built-in
   rules and playbooks, the graph and map libraries, sample files…) is more than
   half of what the app downloads, and few screens need it. index.html lists
   them as low-priority prefetches, so they do not hold up the first screen;
   once the app has drawn, they are added in the background (from the cache when
   the prefetch already fetched them). Code that needs one sooner asks for it
   with lazyNeed(), which adds it right away. When a
   file arrives, its follow-up runs (e.g. merging the built-in rules) and the
   screen is redrawn if it is one that uses it — but never under someone typing.
   ========================================================================== */
const LZ = {
  cy:{f:'cytoscape.min.js', has:() => typeof cytoscape !== 'undefined', then:() => { if(typeof ensurePositions === 'function') ensurePositions(); }, shows:r => r.area === 'case' && r.tab === 'graph'},
  rules:{f:'detections-pack.js', has:() => typeof RULE_PACK !== 'undefined', then:() => { if(DB && typeof ensureRules === 'function') ensureRules(); }, shows:r => r.area === 'detections' || r.area === 'today' || (r.area === 'case' && r.tab === 'timeline')},
  kev:{f:'kev-snapshot.js', has:() => typeof KEV_SNAPSHOT !== 'undefined', then:() => { if(typeof CTI !== 'undefined' && !CTI.kevLive && typeof ctiKevIndex === 'function') ctiKevIndex(); }, shows:r => ['feeds','home','case','today'].includes(r.area)},
  pb:{f:'playbooks-pack.js', has:() => typeof PB_PACK !== 'undefined', then:() => { if(DB && typeof ensurePlaybooks === 'function') ensurePlaybooks(); }, shows:r => r.area === 'playbooks'},
  ref:{f:'reference-pack.js', has:() => typeof REFPACK !== 'undefined', then:() => { if(typeof REF_ALL !== 'undefined') REF_ALL = null; }, shows:r => r.area === 'reference'},
  cloud:{f:'cloudguide-pack.js', has:() => typeof CLOUDGUIDE_PACK !== 'undefined', then:() => { if(typeof CG_ALL !== 'undefined') CG_ALL = null; }, shows:r => r.area === 'cloud'},
  certs:{f:'cert-samples.js', has:() => typeof CERT_SAMPLES !== 'undefined', shows:r => r.area === 'certs'},
  nbdemo:{f:'notebook-demo.js', has:() => typeof NB_DEMO_SHOT !== 'undefined', shows:r => r.area === 'notebook'},
  world:{f:'world-map.js', has:() => typeof WORLD_B64 !== 'undefined', only:true},
  oui:{f:'oui-vendors.js', has:() => typeof OUI_B64 !== 'undefined', only:true},
  enrich:{f:'enrich-data.js', has:() => typeof ENRICH_B64 !== 'undefined', only:true},
  qr:{f:'jsqr.min.js', has:() => typeof jsQR === 'function', only:true},
  phone:{f:'libphonenumber-max.js', has:() => typeof libphonenumber !== 'undefined' && typeof libphonenumber.parsePhoneNumberFromString === 'function', only:true},
};
const lzHas = k => { try{ return !!(LZ[k] && LZ[k].has()); }catch(e){ return false; } };
/* add the file's script (once); resolves when it has run, or failed to load — callers then fall back as before */
function lazyNeed(k){
  const L = LZ[k]; if(!L || lzHas(k)) return Promise.resolve(true);
  return L.p || (L.p = new Promise(res => {
    const pre = [...document.querySelectorAll('link[data-lazy]')].find(l => (l.getAttribute('href') || '').split('?')[0].endsWith('/' + L.f));
    const old = [...document.scripts].find(s => (s.getAttribute('src') || '').split('?')[0].endsWith('/' + L.f));
    if(!pre && !old) return res(false);
    const el = old || document.createElement('script');
    el.addEventListener('load', () => res(true), {once:true}); el.addEventListener('error', () => { L.failed = true; res(false); }, {once:true});
    if(!old){ el.src = pre.getAttribute('href'); el.async = true; document.head.appendChild(el); }
    if(lzHas(k)) res(true);                                   // it ran between the check above and here
  }));
}
const lazyPending = () => Object.keys(LZ).filter(k => !lzHas(k) && !LZ[k].failed && !LZ[k].only).length;
let LZ_REDRAW = false;
const lzBusy = () => { const a = document.activeElement; return !!(a && a.closest && a.closest('#main') && (a.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName)) && !(a.type === 'checkbox' || a.type === 'radio')); };
function lzRedraw(){
  if(LZ_REDRAW) return; LZ_REDRAW = true;
  const go = () => { LZ_REDRAW = false; if(lzBusy()){ document.addEventListener('focusout', () => setTimeout(lzRedraw, 0), {once:true}); return; } if(typeof renderMain === 'function') renderMain(); if(typeof renderNav === 'function') renderNav(); };
  requestAnimationFrame(go);
}
/* called once the app has started: after the first screen is drawn, add every file in the background, with its follow-up.
   Files marked "only" (the MAC vendor list, the world map, enrichment data, the QR reader) are fetched only by the tool that needs them. */
function lazyWatch(){
  const start = () => { for(const [k, L] of Object.entries(LZ)){ if(lzHas(k) || L.only) continue;
    lazyNeed(k).then(ok => { if(!ok) return; try{ L.then && L.then(); }catch(e){ console.warn('after loading ' + L.f, e); }
      if(L.shows && UI && UI.route && L.shows(UI.route)) lzRedraw(); }); } };
  /* two frames: the first screen paints before anything else is fetched or parsed */
  requestAnimationFrame(() => setTimeout(start, 0));
}
