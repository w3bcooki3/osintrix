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
const BUILD = '1.75-93b9cddb081c';
const FILES = [
  'css/app.css?v=1.75-2d59f678',
  'css/design.css?v=1.75-dd949ebf',
  'css/fonts.css?v=1.75-6b722f46',
  'css/theme.css?v=1.75-c7d9472f',
  'js/ach.js?v=1.75-ee81d8ef',
  'js/activity.js?v=1.75-e422ef29',
  'js/aigen.js?v=1.75-3747efdd',
  'js/app.js?v=1.75-0064b6f5',
  'js/areas.js?v=1.75-9c2190c0',
  'js/auto.js?v=1.75-45557b5b',
  'js/brand.js?v=1.75-1e492c5c',
  'js/browserp.js?v=1.75-0ada2439',
  'js/caseents.js?v=1.75-e75bba30',
  'js/caserules.js?v=1.75-510f59b7',
  'js/certs.js?v=1.75-0325616b',
  'js/chain.js?v=1.75-9d2efc8a',
  'js/changes.js?v=1.75-048b6413',
  'js/chat.js?v=1.75-930a4a15',
  'js/chatnet.js?v=1.75-4196bf20',
  'js/checklist.js?v=1.75-689352dc',
  'js/clean.js?v=1.75-ad6e4f35',
  'js/cloud.js?v=1.75-38b48729',
  'js/cloudlogs.js?v=1.75-1cc3239b',
  'js/cloudscan.js?v=1.75-c32baedc',
  'js/company.js?v=1.75-7272ce70',
  'js/copilot.js?v=1.75-7689ed4a',
  'js/core.js?v=1.75-25dfa75b',
  'js/ctf.js?v=1.75-b0cbbf46',
  'js/cti.js?v=1.75-3792c593',
  'js/data/attack.js?v=1.75-c1562fb4',
  'js/data/cert-guide.js?v=1.75-4398ad03',
  'js/data/cert-samples.js?v=1.75-0299cc85',
  'js/data/changelog.js?v=1.75-1a4c5981',
  'js/data/cloudguide-pack.js?v=1.75-2a04047d',
  'js/data/cloudguide.js?v=1.75-f4e2ee0a',
  'js/data/ctf-cheats.js?v=1.75-a94afc1e',
  'js/data/detection-rules.js?v=1.75-b4a16c10',
  'js/data/detections-pack.js?v=1.75-ad2d9629',
  'js/data/kev-snapshot.js?v=1.75-00aad734',
  'js/data/notebook-demo.js?v=1.75-d0996dc4',
  'js/data/playbooks-pack.js?v=1.75-418a4c63',
  'js/data/query-templates.js?v=1.75-40f95794',
  'js/data/reference-pack.js?v=1.75-f2040f7f',
  'js/data/reference.js?v=1.75-232bff13',
  'js/data/sample-osint.js?v=1.75-a8480d68',
  'js/data/tools.js?v=1.75-8fffec7b',
  'js/data/tradecraft-pack.js?v=1.75-92145a03',
  'js/demo.js?v=1.75-d81efcbb',
  'js/detections.js?v=1.75-f3ea6cc1',
  'js/detiq.js?v=1.75-69f04a1f',
  'js/detlab.js?v=1.75-244428c8',
  'js/docfx.js?v=1.75-1dcf0e07',
  'js/dupes.js?v=1.75-71c5f741',
  'js/endpoint.js?v=1.75-c4886a1f',
  'js/engine.js?v=1.75-b6651914',
  'js/evnote.js?v=1.75-127a26a3',
  'js/evtx.js?v=1.75-4993a790',
  'js/extras.js?v=1.75-420d613e',
  'js/fbackup.js?v=1.75-54b3d4db',
  'js/footprint.js?v=1.75-c193c308',
  'js/forensic.js?v=1.75-134f55ec',
  'js/geoloc.js?v=1.75-c6d2c256',
  'js/graph.js?v=1.75-421706c2',
  'js/graphiq.js?v=1.75-82531632',
  'js/graphview.js?v=1.75-7db8537c',
  'js/hours.js?v=1.75-3f8fb74b',
  'js/hunts.js?v=1.75-2daafca7',
  'js/icons.js?v=1.75-30e2e357',
  'js/identity.js?v=1.75-cd8ad8b4',
  'js/imgx.js?v=1.75-1b67f5a9',
  'js/infra.js?v=1.75-cf014584',
  'js/insp.js?v=1.75-4f5a36e1',
  'js/integrity.js?v=1.75-f0edee55',
  'js/intel.js?v=1.75-6864d371',
  'js/investigate.js?v=1.75-1dfc5a32',
  'js/iprofile.js?v=1.75-b11bf1e4',
  'js/keys.js?v=1.75-fac1865b',
  'js/kit.js?v=1.75-cc299683',
  'js/lab.js?v=1.75-d511e96c',
  'js/layouts.js?v=1.75-9bbd7e62',
  'js/lazy.js?v=1.75-67d9a913',
  'js/limits.js?v=1.75-00cc2dd4',
  'js/links.js?v=1.75-db45c411',
  'js/lookups.js?v=1.75-41e0de86',
  'js/map.js?v=1.75-d7d1ab08',
  'js/mask.js?v=1.75-db107ec6',
  'js/media.js?v=1.75-16bd0ea3',
  'js/mentions.js?v=1.75-108404c4',
  'js/meta.js?v=1.75-b028e95b',
  'js/model.js?v=1.75-9a9fc6d5',
  'js/nbexport.js?v=1.75-4172a531',
  'js/nblinks.js?v=1.75-96603141',
  'js/nlq.js?v=1.75-54ac5807',
  'js/notebook.js?v=1.75-0e7d96a3',
  'js/notes.js?v=1.75-8433759c',
  'js/oldoffice.js?v=1.75-fa7b3a3c',
  'js/opsec.js?v=1.75-afec60c5',
  'js/osint.js?v=1.75-69cfd61e',
  'js/pad.js?v=1.75-cc74fa8a',
  'js/parse.js?v=1.75-bcb52967',
  'js/pcap.js?v=1.75-c7fa940a',
  'js/persona.js?v=1.75-2d8751cc',
  'js/phone.js?v=1.75-75bc4704',
  'js/picx.js?v=1.75-2d164ad7',
  'js/playbooks.js?v=1.75-66eddb74',
  'js/qbuild.js?v=1.75-4e62a10c',
  'js/queries.js?v=1.75-2487f89c',
  'js/recent.js?v=1.75-760d9ab8',
  'js/regexb.js?v=1.75-b8033bfa',
  'js/relate.js?v=1.75-ed2f3c71',
  'js/report.js?v=1.75-e183c3c9',
  'js/repwriter.js?v=1.75-746763e6',
  'js/rulepack.js?v=1.75-3cb44b16',
  'js/rulever.js?v=1.75-bab684ef',
  'js/rxbig.js?v=1.75-9335fc49',
  'js/rxengine.js?v=1.75-641afc4b',
  'js/rxlib.js?v=1.75-481ff43a',
  'js/safety.js?v=1.75-73b19224',
  'js/savedv.js?v=1.75-95c50a46',
  'js/search.js?v=1.75-86681ed4',
  'js/security.js?v=1.75-64d74601',
  'js/setup.js?v=1.75-215cd8c0',
  'js/share.js?v=1.75-4baa7d43',
  'js/sightings.js?v=1.75-07677802',
  'js/snapcase.js?v=1.75-0e8dbeb4',
  'js/sources.js?v=1.75-96e11d79',
  'js/sqlite.js?v=1.75-ef1b18ef',
  'js/stash.js?v=1.75-82ca377c',
  'js/storage.js?v=1.75-0f7940b1',
  'js/stylo.js?v=1.75-ecc2ea63',
  'js/textin.js?v=1.75-25c20484',
  'js/tiover.js?v=1.75-3d72afca',
  'js/tl.js?v=1.75-1da49f4f',
  'js/tlx.js?v=1.75-c2675c04',
  'js/tlx2.js?v=1.75-cb2dad96',
  'js/today.js?v=1.75-63fd4824',
  'js/tour.js?v=1.75-8dbbf2d6',
  'js/tradecraft.js?v=1.75-013c53ee',
  'js/trail.js?v=1.75-65d3e408',
  'js/triage.js?v=1.75-ef00f55a',
  'js/validate.js?v=1.75-481647ce',
  'js/valmenu.js?v=1.75-b7dee91d',
  'js/vault2.js?v=1.75-69644956',
  'js/vdecay.js?v=1.75-bfca184e',
  'js/vendor/cytoscape.min.js?v=1.75-83e8c54a',
  'js/vendor/enrich-data.js?v=1.75-3c974ff3',
  'js/vendor/js-yaml.min.js?v=1.75-45dc3dd0',
  'js/vendor/jsqr.min.js?v=1.75-41fdad3e',
  'js/vendor/libphonenumber-max.js?v=1.75-49963114',
  'js/vendor/oui-vendors.js?v=1.75-c0e66aaa',
  'js/vendor/world-map.js?v=1.75-417768fe',
  'js/verdict.js?v=1.75-b8ccb240',
  'js/views.js?v=1.75-853d4c40',
  'js/vimport.js?v=1.75-57ac9464',
  'js/vin.js?v=1.75-9bee55ee',
  'js/vlist.js?v=1.75-fda3ee50',
  'js/wallet.js?v=1.75-427ea656',
  'js/watch.js?v=1.75-20a55856',
  'js/webcap.js?v=1.75-9735fae5',
  'js/webpage.js?v=1.75-b20e2b51',
  'js/whatsnew.js?v=1.75-16300cd3',
  'js/x509.js?v=1.75-0b97c484',
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
