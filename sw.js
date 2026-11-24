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
const BUILD = '1.69-baacf2374223';
const FILES = [
  'css/app.css?v=1.69-2bcbbb57',
  'css/design.css?v=1.69-ad91b3c2',
  'css/fonts.css?v=1.69-6b722f46',
  'css/theme.css?v=1.69-c7d9472f',
  'js/ach.js?v=1.69-ee81d8ef',
  'js/activity.js?v=1.69-e422ef29',
  'js/app.js?v=1.69-43781ec2',
  'js/areas.js?v=1.69-61f5ce66',
  'js/auto.js?v=1.69-45557b5b',
  'js/brand.js?v=1.69-147ef54b',
  'js/caseents.js?v=1.69-a8985f5b',
  'js/caserules.js?v=1.69-510f59b7',
  'js/certs.js?v=1.69-0325616b',
  'js/chain.js?v=1.69-9d2efc8a',
  'js/changes.js?v=1.69-048b6413',
  'js/chat.js?v=1.69-67802c6b',
  'js/chatnet.js?v=1.69-a8bff96b',
  'js/checklist.js?v=1.69-689352dc',
  'js/cloud.js?v=1.69-38b48729',
  'js/cloudlogs.js?v=1.69-1cc3239b',
  'js/cloudscan.js?v=1.69-c32baedc',
  'js/copilot.js?v=1.69-7689ed4a',
  'js/core.js?v=1.69-25dfa75b',
  'js/ctf.js?v=1.69-b0cbbf46',
  'js/cti.js?v=1.69-3792c593',
  'js/data/attack.js?v=1.69-c1562fb4',
  'js/data/cert-guide.js?v=1.69-4398ad03',
  'js/data/cert-samples.js?v=1.69-0299cc85',
  'js/data/changelog.js?v=1.69-5fec8de9',
  'js/data/cloudguide-pack.js?v=1.69-2a04047d',
  'js/data/cloudguide.js?v=1.69-f4e2ee0a',
  'js/data/ctf-cheats.js?v=1.69-a94afc1e',
  'js/data/detection-rules.js?v=1.69-b4a16c10',
  'js/data/detections-pack.js?v=1.69-ad2d9629',
  'js/data/kev-snapshot.js?v=1.69-00aad734',
  'js/data/notebook-demo.js?v=1.69-d0996dc4',
  'js/data/playbooks-pack.js?v=1.69-160f58cd',
  'js/data/query-templates.js?v=1.69-40f95794',
  'js/data/reference-pack.js?v=1.69-f2040f7f',
  'js/data/reference.js?v=1.69-232bff13',
  'js/data/sample-osint.js?v=1.69-a8480d68',
  'js/data/tools.js?v=1.69-8fffec7b',
  'js/data/tradecraft-pack.js?v=1.69-92145a03',
  'js/demo.js?v=1.69-d81efcbb',
  'js/detections.js?v=1.69-94b6a0bb',
  'js/detiq.js?v=1.69-69f04a1f',
  'js/detlab.js?v=1.69-244428c8',
  'js/dupes.js?v=1.69-71c5f741',
  'js/endpoint.js?v=1.69-c4886a1f',
  'js/engine.js?v=1.69-8825dae9',
  'js/evnote.js?v=1.69-127a26a3',
  'js/evtx.js?v=1.69-4993a790',
  'js/extras.js?v=1.69-8997f432',
  'js/fbackup.js?v=1.69-54b3d4db',
  'js/footprint.js?v=1.69-c193c308',
  'js/geoloc.js?v=1.69-c6d2c256',
  'js/graph.js?v=1.69-421706c2',
  'js/graphiq.js?v=1.69-82531632',
  'js/graphview.js?v=1.69-7db8537c',
  'js/hours.js?v=1.69-3f8fb74b',
  'js/hunts.js?v=1.69-633cf9f9',
  'js/icons.js?v=1.69-5abd540b',
  'js/identity.js?v=1.69-cd8ad8b4',
  'js/imgx.js?v=1.69-1b67f5a9',
  'js/infra.js?v=1.69-cf014584',
  'js/insp.js?v=1.69-8295cb06',
  'js/integrity.js?v=1.69-f0edee55',
  'js/intel.js?v=1.69-4497f73b',
  'js/investigate.js?v=1.69-5d709011',
  'js/iprofile.js?v=1.69-b11bf1e4',
  'js/keys.js?v=1.69-fac1865b',
  'js/kit.js?v=1.69-30801b09',
  'js/lab.js?v=1.69-db23c41e',
  'js/layouts.js?v=1.69-9bbd7e62',
  'js/lazy.js?v=1.69-67d9a913',
  'js/limits.js?v=1.69-00cc2dd4',
  'js/links.js?v=1.69-553e3cb1',
  'js/lookups.js?v=1.69-41e0de86',
  'js/map.js?v=1.69-d7d1ab08',
  'js/mask.js?v=1.69-db107ec6',
  'js/media.js?v=1.69-16bd0ea3',
  'js/mentions.js?v=1.69-108404c4',
  'js/meta.js?v=1.69-40dfe377',
  'js/model.js?v=1.69-9a9fc6d5',
  'js/nbexport.js?v=1.69-8b6265ff',
  'js/nlq.js?v=1.69-54ac5807',
  'js/notebook.js?v=1.69-1138f041',
  'js/notes.js?v=1.69-ee9504f0',
  'js/oldoffice.js?v=1.69-18f81939',
  'js/opsec.js?v=1.69-483a73ba',
  'js/osint.js?v=1.69-cdf4550f',
  'js/pad.js?v=1.69-cc74fa8a',
  'js/parse.js?v=1.69-634ff840',
  'js/pcap.js?v=1.69-c7fa940a',
  'js/persona.js?v=1.69-2d8751cc',
  'js/phone.js?v=1.69-75bc4704',
  'js/picx.js?v=1.69-2d164ad7',
  'js/playbooks.js?v=1.69-3b0c63d5',
  'js/qbuild.js?v=1.69-4e62a10c',
  'js/queries.js?v=1.69-2487f89c',
  'js/recent.js?v=1.69-760d9ab8',
  'js/regexb.js?v=1.69-b8033bfa',
  'js/relate.js?v=1.69-ed2f3c71',
  'js/report.js?v=1.69-e183c3c9',
  'js/repwriter.js?v=1.69-746763e6',
  'js/rulepack.js?v=1.69-3cb44b16',
  'js/rulever.js?v=1.69-bab684ef',
  'js/rxbig.js?v=1.69-9335fc49',
  'js/rxengine.js?v=1.69-641afc4b',
  'js/rxlib.js?v=1.69-e416b847',
  'js/safety.js?v=1.69-73b19224',
  'js/savedv.js?v=1.69-95c50a46',
  'js/search.js?v=1.69-86681ed4',
  'js/security.js?v=1.69-64d74601',
  'js/setup.js?v=1.69-215cd8c0',
  'js/share.js?v=1.69-4baa7d43',
  'js/sightings.js?v=1.69-07677802',
  'js/snapcase.js?v=1.69-0e8dbeb4',
  'js/sources.js?v=1.69-96e11d79',
  'js/sqlite.js?v=1.69-ef1b18ef',
  'js/stash.js?v=1.69-82ca377c',
  'js/storage.js?v=1.69-0f7940b1',
  'js/stylo.js?v=1.69-ecc2ea63',
  'js/textin.js?v=1.69-25c20484',
  'js/tiover.js?v=1.69-3d72afca',
  'js/tl.js?v=1.69-1da49f4f',
  'js/tlx.js?v=1.69-c2675c04',
  'js/tlx2.js?v=1.69-cb2dad96',
  'js/today.js?v=1.69-585d812e',
  'js/tour.js?v=1.69-8dbbf2d6',
  'js/tradecraft.js?v=1.69-013c53ee',
  'js/trail.js?v=1.69-65d3e408',
  'js/triage.js?v=1.69-ef00f55a',
  'js/validate.js?v=1.69-481647ce',
  'js/valmenu.js?v=1.69-b7dee91d',
  'js/vault2.js?v=1.69-69644956',
  'js/vdecay.js?v=1.69-bfca184e',
  'js/vendor/cytoscape.min.js?v=1.69-83e8c54a',
  'js/vendor/enrich-data.js?v=1.69-3c974ff3',
  'js/vendor/js-yaml.min.js?v=1.69-45dc3dd0',
  'js/vendor/jsqr.min.js?v=1.69-41fdad3e',
  'js/vendor/libphonenumber-max.js?v=1.69-49963114',
  'js/vendor/oui-vendors.js?v=1.69-c0e66aaa',
  'js/vendor/world-map.js?v=1.69-417768fe',
  'js/verdict.js?v=1.69-b8ccb240',
  'js/views.js?v=1.69-789299ce',
  'js/vimport.js?v=1.69-57ac9464',
  'js/vlist.js?v=1.69-fda3ee50',
  'js/wallet.js?v=1.69-096410e8',
  'js/watch.js?v=1.69-d11e8d0d',
  'js/webpage.js?v=1.69-b20e2b51',
  'js/whatsnew.js?v=1.69-16300cd3',
  'js/x509.js?v=1.69-0b97c484',
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
