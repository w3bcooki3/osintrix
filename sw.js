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
const BUILD = '1.53-69729f64996c';
const FILES = [
  'css/app.css?v=1.53-26577523',
  'css/design.css?v=1.53-55c39f3d',
  'css/fonts.css?v=1.53-6b722f46',
  'css/theme.css?v=1.53-c7d9472f',
  'js/ach.js?v=1.53-ee81d8ef',
  'js/activity.js?v=1.53-7438453f',
  'js/app.js?v=1.53-3837f2c2',
  'js/areas.js?v=1.53-ab8f5bce',
  'js/auto.js?v=1.53-cb17a519',
  'js/brand.js?v=1.53-da21421a',
  'js/caseents.js?v=1.53-5576b2d8',
  'js/caserules.js?v=1.53-510f59b7',
  'js/certs.js?v=1.53-16bfc0f0',
  'js/chain.js?v=1.53-9d2efc8a',
  'js/changes.js?v=1.53-048b6413',
  'js/checklist.js?v=1.53-7d86951b',
  'js/cloud.js?v=1.53-22a425cf',
  'js/cloudlogs.js?v=1.53-1cc3239b',
  'js/cloudscan.js?v=1.53-c32baedc',
  'js/copilot.js?v=1.53-c63ab18e',
  'js/core.js?v=1.53-7bdecdb9',
  'js/ctf.js?v=1.53-a0fdd8e1',
  'js/cti.js?v=1.53-3792c593',
  'js/data/attack.js?v=1.53-c1562fb4',
  'js/data/cert-guide.js?v=1.53-4398ad03',
  'js/data/cert-samples.js?v=1.53-0299cc85',
  'js/data/changelog.js?v=1.53-dca5d4ee',
  'js/data/cloudguide-pack.js?v=1.53-7f7b86e0',
  'js/data/cloudguide.js?v=1.53-f4e2ee0a',
  'js/data/ctf-cheats.js?v=1.53-a94afc1e',
  'js/data/detection-rules.js?v=1.53-b4a16c10',
  'js/data/detections-pack.js?v=1.53-fbe0bb54',
  'js/data/kev-snapshot.js?v=1.53-00aad734',
  'js/data/notebook-demo.js?v=1.53-d0996dc4',
  'js/data/playbooks-pack.js?v=1.53-47498e78',
  'js/data/query-templates.js?v=1.53-d96de4aa',
  'js/data/reference-pack.js?v=1.53-4c093c4b',
  'js/data/reference.js?v=1.53-232bff13',
  'js/data/sample-osint.js?v=1.53-a8480d68',
  'js/data/tools.js?v=1.53-8fffec7b',
  'js/demo.js?v=1.53-d81efcbb',
  'js/detections.js?v=1.53-870c9880',
  'js/detiq.js?v=1.53-8accc6ef',
  'js/detlab.js?v=1.53-8e61fc50',
  'js/dupes.js?v=1.53-77aafeeb',
  'js/endpoint.js?v=1.53-c4886a1f',
  'js/engine.js?v=1.53-efdd9802',
  'js/evnote.js?v=1.53-127a26a3',
  'js/evtx.js?v=1.53-4993a790',
  'js/extras.js?v=1.53-a53e5031',
  'js/fbackup.js?v=1.53-54b3d4db',
  'js/footprint.js?v=1.53-c193c308',
  'js/geoloc.js?v=1.53-c6d2c256',
  'js/graph.js?v=1.53-ed700956',
  'js/graphiq.js?v=1.53-82531632',
  'js/hours.js?v=1.53-3f8fb74b',
  'js/hunts.js?v=1.53-40e79704',
  'js/icons.js?v=1.53-dc8ac907',
  'js/identity.js?v=1.53-795f7202',
  'js/imgx.js?v=1.53-37da06c7',
  'js/infra.js?v=1.53-82d1e06d',
  'js/insp.js?v=1.53-435dca78',
  'js/integrity.js?v=1.53-6bd6a56b',
  'js/intel.js?v=1.53-87be7aa8',
  'js/investigate.js?v=1.53-91febe6a',
  'js/kit.js?v=1.53-580ff95a',
  'js/lab.js?v=1.53-dd24b7b4',
  'js/layouts.js?v=1.53-82c05eda',
  'js/lazy.js?v=1.53-dc1aced0',
  'js/limits.js?v=1.53-00cc2dd4',
  'js/links.js?v=1.53-61b0383d',
  'js/lookups.js?v=1.53-a8852adb',
  'js/map.js?v=1.53-3d33ea23',
  'js/mask.js?v=1.53-8bde180c',
  'js/media.js?v=1.53-7db6eda2',
  'js/meta.js?v=1.53-40dfe377',
  'js/model.js?v=1.53-2ee86688',
  'js/nbexport.js?v=1.53-8b6265ff',
  'js/nlq.js?v=1.53-556b5b3a',
  'js/notebook.js?v=1.53-02ce0b58',
  'js/notes.js?v=1.53-88f10397',
  'js/oldoffice.js?v=1.53-18f81939',
  'js/osint.js?v=1.53-a39db509',
  'js/pad.js?v=1.53-76b424fe',
  'js/parse.js?v=1.53-15518b9f',
  'js/pcap.js?v=1.53-4458a5b0',
  'js/phone.js?v=1.53-6ec6eeff',
  'js/picx.js?v=1.53-4a0a1911',
  'js/playbooks.js?v=1.53-1098b072',
  'js/qbuild.js?v=1.53-4e62a10c',
  'js/queries.js?v=1.53-57c58329',
  'js/recent.js?v=1.53-697df5e8',
  'js/regexb.js?v=1.53-0333c8cf',
  'js/relate.js?v=1.53-00452cbc',
  'js/report.js?v=1.53-e4c120e2',
  'js/repwriter.js?v=1.53-a5691d65',
  'js/rulepack.js?v=1.53-3cb44b16',
  'js/rulever.js?v=1.53-bab684ef',
  'js/rxbig.js?v=1.53-f32661c7',
  'js/rxengine.js?v=1.53-641afc4b',
  'js/rxlib.js?v=1.53-e416b847',
  'js/safety.js?v=1.53-dd5095ee',
  'js/search.js?v=1.53-c2801692',
  'js/security.js?v=1.53-bf5337c7',
  'js/setup.js?v=1.53-215cd8c0',
  'js/share.js?v=1.53-7d3e015a',
  'js/sources.js?v=1.53-96e11d79',
  'js/sqlite.js?v=1.53-1f0a62c8',
  'js/storage.js?v=1.53-1899670c',
  'js/textin.js?v=1.53-25c20484',
  'js/tl.js?v=1.53-0aa0b388',
  'js/tlx.js?v=1.53-c2675c04',
  'js/tlx2.js?v=1.53-cb2dad96',
  'js/today.js?v=1.53-ab34fca5',
  'js/tour.js?v=1.53-8dbbf2d6',
  'js/triage.js?v=1.53-b48624cc',
  'js/validate.js?v=1.53-481647ce',
  'js/valmenu.js?v=1.53-b7dee91d',
  'js/vdecay.js?v=1.53-bfca184e',
  'js/vendor/cytoscape.min.js?v=1.53-83e8c54a',
  'js/vendor/enrich-data.js?v=1.53-3c974ff3',
  'js/vendor/js-yaml.min.js?v=1.53-45dc3dd0',
  'js/vendor/jsqr.min.js?v=1.53-41fdad3e',
  'js/vendor/libphonenumber-max.js?v=1.53-49963114',
  'js/vendor/oui-vendors.js?v=1.53-c0e66aaa',
  'js/vendor/world-map.js?v=1.53-417768fe',
  'js/verdict.js?v=1.53-b8ccb240',
  'js/views.js?v=1.53-55cc2bfc',
  'js/vlist.js?v=1.53-b357021a',
  'js/wallet.js?v=1.53-8e6a63b8',
  'js/watch.js?v=1.53-94b854ce',
  'js/webpage.js?v=1.53-90026d66',
  'js/whatsnew.js?v=1.53-16300cd3',
  'js/x509.js?v=1.53-0b97c484',
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
