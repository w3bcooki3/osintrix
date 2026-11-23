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
const BUILD = '1.59-183bcaa3516d';
const FILES = [
  'css/app.css?v=1.59-2bcbbb57',
  'css/design.css?v=1.59-1d15a5ec',
  'css/fonts.css?v=1.59-6b722f46',
  'css/theme.css?v=1.59-c7d9472f',
  'js/ach.js?v=1.59-ee81d8ef',
  'js/activity.js?v=1.59-e422ef29',
  'js/app.js?v=1.59-44aba199',
  'js/areas.js?v=1.59-410e1617',
  'js/auto.js?v=1.59-1ac6d916',
  'js/brand.js?v=1.59-65ed98c3',
  'js/caseents.js?v=1.59-a8985f5b',
  'js/caserules.js?v=1.59-510f59b7',
  'js/certs.js?v=1.59-88e7845f',
  'js/chain.js?v=1.59-9d2efc8a',
  'js/changes.js?v=1.59-048b6413',
  'js/checklist.js?v=1.59-9e83319a',
  'js/cloud.js?v=1.59-38b48729',
  'js/cloudlogs.js?v=1.59-1cc3239b',
  'js/cloudscan.js?v=1.59-c32baedc',
  'js/copilot.js?v=1.59-b02cc75e',
  'js/core.js?v=1.59-3ff5a9f7',
  'js/ctf.js?v=1.59-b0cbbf46',
  'js/cti.js?v=1.59-3792c593',
  'js/data/attack.js?v=1.59-c1562fb4',
  'js/data/cert-guide.js?v=1.59-4398ad03',
  'js/data/cert-samples.js?v=1.59-0299cc85',
  'js/data/changelog.js?v=1.59-144f8987',
  'js/data/cloudguide-pack.js?v=1.59-7f7b86e0',
  'js/data/cloudguide.js?v=1.59-f4e2ee0a',
  'js/data/ctf-cheats.js?v=1.59-a94afc1e',
  'js/data/detection-rules.js?v=1.59-b4a16c10',
  'js/data/detections-pack.js?v=1.59-fbe0bb54',
  'js/data/kev-snapshot.js?v=1.59-00aad734',
  'js/data/notebook-demo.js?v=1.59-d0996dc4',
  'js/data/playbooks-pack.js?v=1.59-47498e78',
  'js/data/query-templates.js?v=1.59-d96de4aa',
  'js/data/reference-pack.js?v=1.59-4c093c4b',
  'js/data/reference.js?v=1.59-232bff13',
  'js/data/sample-osint.js?v=1.59-a8480d68',
  'js/data/tools.js?v=1.59-8fffec7b',
  'js/demo.js?v=1.59-d81efcbb',
  'js/detections.js?v=1.59-94b6a0bb',
  'js/detiq.js?v=1.59-69f04a1f',
  'js/detlab.js?v=1.59-244428c8',
  'js/dupes.js?v=1.59-71c5f741',
  'js/endpoint.js?v=1.59-c4886a1f',
  'js/engine.js?v=1.59-efdd9802',
  'js/evnote.js?v=1.59-127a26a3',
  'js/evtx.js?v=1.59-4993a790',
  'js/extras.js?v=1.59-a685f8cb',
  'js/fbackup.js?v=1.59-54b3d4db',
  'js/footprint.js?v=1.59-c193c308',
  'js/geoloc.js?v=1.59-c6d2c256',
  'js/graph.js?v=1.59-c0422bf7',
  'js/graphiq.js?v=1.59-82531632',
  'js/graphview.js?v=1.59-7db8537c',
  'js/hours.js?v=1.59-3f8fb74b',
  'js/hunts.js?v=1.59-633cf9f9',
  'js/icons.js?v=1.59-5abd540b',
  'js/identity.js?v=1.59-db5bf42e',
  'js/imgx.js?v=1.59-1b67f5a9',
  'js/infra.js?v=1.59-82d1e06d',
  'js/insp.js?v=1.59-1f5ee965',
  'js/integrity.js?v=1.59-0224916c',
  'js/intel.js?v=1.59-594340ee',
  'js/investigate.js?v=1.59-61806a93',
  'js/iprofile.js?v=1.59-a498d5e3',
  'js/keys.js?v=1.59-fac1865b',
  'js/kit.js?v=1.59-30801b09',
  'js/lab.js?v=1.59-5c47b678',
  'js/layouts.js?v=1.59-82c05eda',
  'js/lazy.js?v=1.59-dc1aced0',
  'js/limits.js?v=1.59-00cc2dd4',
  'js/links.js?v=1.59-553e3cb1',
  'js/lookups.js?v=1.59-41e0de86',
  'js/map.js?v=1.59-d7d1ab08',
  'js/mask.js?v=1.59-8bde180c',
  'js/media.js?v=1.59-7db6eda2',
  'js/mentions.js?v=1.59-108404c4',
  'js/meta.js?v=1.59-40dfe377',
  'js/model.js?v=1.59-2ee86688',
  'js/nbexport.js?v=1.59-8b6265ff',
  'js/nlq.js?v=1.59-e5f95f96',
  'js/notebook.js?v=1.59-1138f041',
  'js/notes.js?v=1.59-ee9504f0',
  'js/oldoffice.js?v=1.59-18f81939',
  'js/osint.js?v=1.59-64ddf098',
  'js/pad.js?v=1.59-e32228da',
  'js/parse.js?v=1.59-15518b9f',
  'js/pcap.js?v=1.59-e5ebd345',
  'js/phone.js?v=1.59-75bc4704',
  'js/picx.js?v=1.59-2d164ad7',
  'js/playbooks.js?v=1.59-3b0c63d5',
  'js/qbuild.js?v=1.59-4e62a10c',
  'js/queries.js?v=1.59-bc8b7bda',
  'js/recent.js?v=1.59-760d9ab8',
  'js/regexb.js?v=1.59-b8033bfa',
  'js/relate.js?v=1.59-58d9fe38',
  'js/report.js?v=1.59-e183c3c9',
  'js/repwriter.js?v=1.59-746763e6',
  'js/rulepack.js?v=1.59-3cb44b16',
  'js/rulever.js?v=1.59-bab684ef',
  'js/rxbig.js?v=1.59-9335fc49',
  'js/rxengine.js?v=1.59-641afc4b',
  'js/rxlib.js?v=1.59-e416b847',
  'js/safety.js?v=1.59-afe15fc4',
  'js/savedv.js?v=1.59-95c50a46',
  'js/search.js?v=1.59-e8f214a2',
  'js/security.js?v=1.59-64d74601',
  'js/setup.js?v=1.59-215cd8c0',
  'js/share.js?v=1.59-4baa7d43',
  'js/sightings.js?v=1.59-07677802',
  'js/snapcase.js?v=1.59-0e8dbeb4',
  'js/sources.js?v=1.59-96e11d79',
  'js/sqlite.js?v=1.59-6fe98a76',
  'js/storage.js?v=1.59-2d540953',
  'js/textin.js?v=1.59-25c20484',
  'js/tl.js?v=1.59-1da49f4f',
  'js/tlx.js?v=1.59-c2675c04',
  'js/tlx2.js?v=1.59-cb2dad96',
  'js/today.js?v=1.59-585d812e',
  'js/tour.js?v=1.59-8dbbf2d6',
  'js/trail.js?v=1.59-4b274eb8',
  'js/triage.js?v=1.59-ef00f55a',
  'js/validate.js?v=1.59-481647ce',
  'js/valmenu.js?v=1.59-b7dee91d',
  'js/vault2.js?v=1.59-69644956',
  'js/vdecay.js?v=1.59-bfca184e',
  'js/vendor/cytoscape.min.js?v=1.59-83e8c54a',
  'js/vendor/enrich-data.js?v=1.59-3c974ff3',
  'js/vendor/js-yaml.min.js?v=1.59-45dc3dd0',
  'js/vendor/jsqr.min.js?v=1.59-41fdad3e',
  'js/vendor/libphonenumber-max.js?v=1.59-49963114',
  'js/vendor/oui-vendors.js?v=1.59-c0e66aaa',
  'js/vendor/world-map.js?v=1.59-417768fe',
  'js/verdict.js?v=1.59-b8ccb240',
  'js/views.js?v=1.59-90311d99',
  'js/vimport.js?v=1.59-57ac9464',
  'js/vlist.js?v=1.59-b357021a',
  'js/wallet.js?v=1.59-096410e8',
  'js/watch.js?v=1.59-d11e8d0d',
  'js/webpage.js?v=1.59-90026d66',
  'js/whatsnew.js?v=1.59-16300cd3',
  'js/x509.js?v=1.59-0b97c484',
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
