/* OSINTrix offline helper (service worker).
   Keeps a copy of the app's own files — never your data, which stays in this browser's storage — so the app
   opens instantly on repeat visits and works with no connection.
   - The page itself (index.html) comes from the network when it can, so updates show up at once; the copy is
     used when offline or when the network takes more than 3 seconds.
   - Scripts and styles have a fingerprint in their address that changes with their content, so a cached copy
     is always the right one and is served without asking the network.
   - Nothing from other sites is ever cached.
   The list below is rewritten by tools/stamp.py on every build; a new list means a new cache and the old one
   is deleted. */
/* build:start */
const BUILD = '1.52-e2d79723327b';
const FILES = [
  'css/app.css?v=1.52-26577523',
  'css/design.css?v=1.52-6c44850c',
  'css/fonts.css?v=1.52-6b722f46',
  'css/theme.css?v=1.52-dd4eb1ee',
  'js/ach.js?v=1.52-ee81d8ef',
  'js/activity.js?v=1.52-7438453f',
  'js/app.js?v=1.52-13129e56',
  'js/areas.js?v=1.52-7f458524',
  'js/auto.js?v=1.52-cb17a519',
  'js/brand.js?v=1.52-8dd430e6',
  'js/caseents.js?v=1.52-5576b2d8',
  'js/caserules.js?v=1.52-510f59b7',
  'js/certs.js?v=1.52-16bfc0f0',
  'js/chain.js?v=1.52-9d2efc8a',
  'js/changes.js?v=1.52-048b6413',
  'js/checklist.js?v=1.52-7d86951b',
  'js/cloud.js?v=1.52-22a425cf',
  'js/cloudlogs.js?v=1.52-1cc3239b',
  'js/cloudscan.js?v=1.52-c32baedc',
  'js/copilot.js?v=1.52-c63ab18e',
  'js/core.js?v=1.52-7bdecdb9',
  'js/ctf.js?v=1.52-a0fdd8e1',
  'js/cti.js?v=1.52-3792c593',
  'js/data/attack.js?v=1.52-c1562fb4',
  'js/data/cert-guide.js?v=1.52-4398ad03',
  'js/data/cert-samples.js?v=1.52-0299cc85',
  'js/data/changelog.js?v=1.52-02fbddc7',
  'js/data/cloudguide-pack.js?v=1.52-7f7b86e0',
  'js/data/cloudguide.js?v=1.52-f4e2ee0a',
  'js/data/ctf-cheats.js?v=1.52-a94afc1e',
  'js/data/detection-rules.js?v=1.52-b4a16c10',
  'js/data/detections-pack.js?v=1.52-fbe0bb54',
  'js/data/kev-snapshot.js?v=1.52-00aad734',
  'js/data/notebook-demo.js?v=1.52-d0996dc4',
  'js/data/playbooks-pack.js?v=1.52-47498e78',
  'js/data/query-templates.js?v=1.52-d96de4aa',
  'js/data/reference-pack.js?v=1.52-4c093c4b',
  'js/data/reference.js?v=1.52-232bff13',
  'js/data/sample-osint.js?v=1.52-a8480d68',
  'js/data/tools.js?v=1.52-8fffec7b',
  'js/demo.js?v=1.52-d81efcbb',
  'js/detections.js?v=1.52-870c9880',
  'js/detiq.js?v=1.52-8accc6ef',
  'js/detlab.js?v=1.52-8e61fc50',
  'js/dupes.js?v=1.52-77aafeeb',
  'js/endpoint.js?v=1.52-c4886a1f',
  'js/engine.js?v=1.52-efdd9802',
  'js/evnote.js?v=1.52-127a26a3',
  'js/evtx.js?v=1.52-4993a790',
  'js/extras.js?v=1.52-c87ff721',
  'js/fbackup.js?v=1.52-54b3d4db',
  'js/footprint.js?v=1.52-c193c308',
  'js/geoloc.js?v=1.52-c6d2c256',
  'js/graph.js?v=1.52-b3cee403',
  'js/graphiq.js?v=1.52-82531632',
  'js/hours.js?v=1.52-3f8fb74b',
  'js/hunts.js?v=1.52-40e79704',
  'js/icons.js?v=1.52-6ac1f4a5',
  'js/identity.js?v=1.52-795f7202',
  'js/imgx.js?v=1.52-37da06c7',
  'js/infra.js?v=1.52-82d1e06d',
  'js/insp.js?v=1.52-4559aad0',
  'js/integrity.js?v=1.52-68f3d3b7',
  'js/intel.js?v=1.52-87be7aa8',
  'js/investigate.js?v=1.52-91febe6a',
  'js/kit.js?v=1.52-580ff95a',
  'js/lab.js?v=1.52-dd24b7b4',
  'js/layouts.js?v=1.52-82c05eda',
  'js/lazy.js?v=1.52-dc1aced0',
  'js/limits.js?v=1.52-00cc2dd4',
  'js/links.js?v=1.52-61b0383d',
  'js/lookups.js?v=1.52-a8852adb',
  'js/map.js?v=1.52-3d33ea23',
  'js/media.js?v=1.52-7db6eda2',
  'js/meta.js?v=1.52-40dfe377',
  'js/model.js?v=1.52-2ee86688',
  'js/nbexport.js?v=1.52-8b6265ff',
  'js/nlq.js?v=1.52-556b5b3a',
  'js/notebook.js?v=1.52-02ce0b58',
  'js/notes.js?v=1.52-88f10397',
  'js/oldoffice.js?v=1.52-18f81939',
  'js/osint.js?v=1.52-a39db509',
  'js/pad.js?v=1.52-c8b45d98',
  'js/parse.js?v=1.52-15518b9f',
  'js/pcap.js?v=1.52-4458a5b0',
  'js/phone.js?v=1.52-6ec6eeff',
  'js/picx.js?v=1.52-4a0a1911',
  'js/playbooks.js?v=1.52-8ced2006',
  'js/queries.js?v=1.52-a780bdc3',
  'js/recent.js?v=1.52-697df5e8',
  'js/regexb.js?v=1.52-29b65f1d',
  'js/relate.js?v=1.52-00452cbc',
  'js/report.js?v=1.52-e4c120e2',
  'js/repwriter.js?v=1.52-a5691d65',
  'js/rulepack.js?v=1.52-3cb44b16',
  'js/rulever.js?v=1.52-bab684ef',
  'js/rxengine.js?v=1.52-641afc4b',
  'js/safety.js?v=1.52-c077fb35',
  'js/search.js?v=1.52-c2801692',
  'js/security.js?v=1.52-bf5337c7',
  'js/setup.js?v=1.52-215cd8c0',
  'js/share.js?v=1.52-7d3e015a',
  'js/sources.js?v=1.52-96e11d79',
  'js/sqlite.js?v=1.52-1f0a62c8',
  'js/storage.js?v=1.52-1899670c',
  'js/textin.js?v=1.52-25c20484',
  'js/tl.js?v=1.52-0aa0b388',
  'js/tlx.js?v=1.52-c2675c04',
  'js/tlx2.js?v=1.52-cb2dad96',
  'js/today.js?v=1.52-ab34fca5',
  'js/tour.js?v=1.52-8dbbf2d6',
  'js/triage.js?v=1.52-b48624cc',
  'js/validate.js?v=1.52-481647ce',
  'js/vdecay.js?v=1.52-bfca184e',
  'js/vendor/cytoscape.min.js?v=1.52-83e8c54a',
  'js/vendor/enrich-data.js?v=1.52-3c974ff3',
  'js/vendor/js-yaml.min.js?v=1.52-45dc3dd0',
  'js/vendor/jsqr.min.js?v=1.52-41fdad3e',
  'js/vendor/libphonenumber-max.js?v=1.52-49963114',
  'js/vendor/oui-vendors.js?v=1.52-c0e66aaa',
  'js/vendor/world-map.js?v=1.52-417768fe',
  'js/verdict.js?v=1.52-b8ccb240',
  'js/views.js?v=1.52-58b6a122',
  'js/vlist.js?v=1.52-b357021a',
  'js/wallet.js?v=1.52-8e6a63b8',
  'js/watch.js?v=1.52-94b854ce',
  'js/webpage.js?v=1.52-90026d66',
  'js/whatsnew.js?v=1.52-16300cd3',
  'js/x509.js?v=1.52-0b97c484',
  'fonts/inter-variable.woff2',
  'fonts/jetbrains-mono-400.woff2',
  'fonts/jetbrains-mono-500-700.woff2'
];
/* build:end */
const CACHE = 'osintrix-' + BUILD;

self.addEventListener('install', ev => {
  ev.waitUntil(caches.open(CACHE).then(c => c.addAll(['./', ...FILES])).then(() => self.skipWaiting()));
});
self.addEventListener('activate', ev => {
  ev.waitUntil(caches.keys().then(K => Promise.all(K.filter(k => k.startsWith('osintrix-') && k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
const timeout = (p, ms) => new Promise((res, rej) => { const t = setTimeout(() => rej(new Error('slow')), ms); p.then(v => { clearTimeout(t); res(v); }, e => { clearTimeout(t); rej(e); }); });
self.addEventListener('fetch', ev => {
  const req = ev.request, url = new URL(req.url);
  if(req.method !== 'GET' || url.origin !== self.location.origin) return;              // other sites: straight to the network
  if(req.mode === 'navigate' || /\/(index\.html)?$/.test(url.pathname)){
    ev.respondWith((async () => {
      const c = await caches.open(CACHE);
      try{ const r = await timeout(fetch(req, {cache:'no-cache'}), 3000); if(r && r.ok && r.type === 'basic') c.put('./', r.clone()); return r; }
      catch(e){ return (await c.match('./')) || (await c.match(req, {ignoreSearch:true})) || Response.error(); }
    })());
    return;
  }
  const fresh = r => { if(r && r.ok && r.type === 'basic') caches.open(CACHE).then(c => c.put(req, r.clone())); return r; };
  if(/\?v=[\d.]+-[0-9a-f]{8}$/.test(url.search)){                                      // fingerprinted: the copy is always right
    ev.respondWith(caches.match(req).then(hit => hit || fetch(req).then(fresh)));
  } else if(FILES.some(f => url.pathname.endsWith('/' + f))){                            // fonts: the copy now, a fresh one for next time
    ev.respondWith(caches.match(req).then(hit => { const net = fetch(req).then(fresh).catch(() => hit); return hit || net; }));
  }
});
