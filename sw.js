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
const BUILD = '1.90-af845bc88095';
const FILES = [
  'css/app.css?v=1.90-477e515b',
  'css/design.css?v=1.90-2495d8ec',
  'css/fonts.css?v=1.90-6b722f46',
  'css/theme.css?v=1.90-c7d9472f',
  'js/ach.js?v=1.90-ee81d8ef',
  'js/activity.js?v=1.90-e422ef29',
  'js/aigen.js?v=1.90-3747efdd',
  'js/app.js?v=1.90-b042bd05',
  'js/areas.js?v=1.90-c0271440',
  'js/auto.js?v=1.90-45557b5b',
  'js/blackbook.js?v=1.90-10a6362a',
  'js/brand.js?v=1.90-dfff2db0',
  'js/browserp.js?v=1.90-6f0338f8',
  'js/caseents.js?v=1.90-bc922570',
  'js/caserules.js?v=1.90-510f59b7',
  'js/certs.js?v=1.90-4236af2f',
  'js/chain.js?v=1.90-9d2efc8a',
  'js/changes.js?v=1.90-048b6413',
  'js/chat.js?v=1.90-930a4a15',
  'js/chatnet.js?v=1.90-4196bf20',
  'js/checklist.js?v=1.90-689352dc',
  'js/clean.js?v=1.90-ad6e4f35',
  'js/cloud.js?v=1.90-1d563e80',
  'js/cloudlogs.js?v=1.90-1cc3239b',
  'js/cloudscan.js?v=1.90-c32baedc',
  'js/company.js?v=1.90-7272ce70',
  'js/copilot.js?v=1.90-7689ed4a',
  'js/core.js?v=1.90-8c0d2d22',
  'js/ctf.js?v=1.90-b0cbbf46',
  'js/cti.js?v=1.90-0d64f394',
  'js/data/attack.js?v=1.90-c1562fb4',
  'js/data/blackbook-sealed.js?v=1.90-2588cb10',
  'js/data/cert-guide.js?v=1.90-4398ad03',
  'js/data/cert-samples.js?v=1.90-0299cc85',
  'js/data/changelog.js?v=1.90-e6a53624',
  'js/data/cloudguide-pack.js?v=1.90-2a04047d',
  'js/data/cloudguide.js?v=1.90-f4e2ee0a',
  'js/data/ctf-cheats.js?v=1.90-a94afc1e',
  'js/data/detection-rules.js?v=1.90-b4a16c10',
  'js/data/detections-pack.js?v=1.90-ad2d9629',
  'js/data/kev-snapshot.js?v=1.90-00aad734',
  'js/data/notebook-demo.js?v=1.90-d0996dc4',
  'js/data/playbooks-pack.js?v=1.90-418a4c63',
  'js/data/query-templates.js?v=1.90-40f95794',
  'js/data/reference-pack.js?v=1.90-f2040f7f',
  'js/data/reference.js?v=1.90-232bff13',
  'js/data/sample-osint.js?v=1.90-a8480d68',
  'js/data/tools.js?v=1.90-28eed15a',
  'js/data/tradecraft-pack.js?v=1.90-92145a03',
  'js/demo.js?v=1.90-ea693735',
  'js/detections.js?v=1.90-fffb25c1',
  'js/detiq.js?v=1.90-69f04a1f',
  'js/detlab.js?v=1.90-53b87943',
  'js/docfx.js?v=1.90-1dcf0e07',
  'js/dupes.js?v=1.90-f8d211e0',
  'js/endpoint.js?v=1.90-c4886a1f',
  'js/engine.js?v=1.90-84bdf4df',
  'js/evnote.js?v=1.90-127a26a3',
  'js/evtx.js?v=1.90-4993a790',
  'js/extras.js?v=1.90-5b171af9',
  'js/fbackup.js?v=1.90-54b3d4db',
  'js/footprint.js?v=1.90-c193c308',
  'js/forensic.js?v=1.90-84074270',
  'js/geoloc.js?v=1.90-c6d2c256',
  'js/graph.js?v=1.90-76244793',
  'js/graphiq.js?v=1.90-82531632',
  'js/graphview.js?v=1.90-7db8537c',
  'js/hours.js?v=1.90-3f8fb74b',
  'js/hunts.js?v=1.90-2daafca7',
  'js/icons.js?v=1.90-1a942c10',
  'js/identity.js?v=1.90-cd8ad8b4',
  'js/idkeys.js?v=1.90-e8e3121b',
  'js/imgx.js?v=1.90-1b67f5a9',
  'js/infra.js?v=1.90-cf014584',
  'js/insp.js?v=1.90-fea1a3f2',
  'js/integrity.js?v=1.90-6ec52599',
  'js/intel.js?v=1.90-475c517e',
  'js/investigate.js?v=1.90-e3de8b2e',
  'js/iprofile.js?v=1.90-9d74e2b7',
  'js/keys.js?v=1.90-5a5b701b',
  'js/kit.js?v=1.90-cc299683',
  'js/lab.js?v=1.90-4a980a7d',
  'js/layouts.js?v=1.90-cad58415',
  'js/lazy.js?v=1.90-59967e9f',
  'js/limits.js?v=1.90-00cc2dd4',
  'js/links.js?v=1.90-db45c411',
  'js/lookups.js?v=1.90-41e0de86',
  'js/map.js?v=1.90-8971070b',
  'js/mask.js?v=1.90-db107ec6',
  'js/media.js?v=1.90-16bd0ea3',
  'js/mentions.js?v=1.90-108404c4',
  'js/meta.js?v=1.90-b028e95b',
  'js/model.js?v=1.90-3e4bcd39',
  'js/nbexport.js?v=1.90-4172a531',
  'js/nblinks.js?v=1.90-84be7522',
  'js/nlq.js?v=1.90-54ac5807',
  'js/notebook.js?v=1.90-2ebee365',
  'js/notes.js?v=1.90-670aa292',
  'js/oldoffice.js?v=1.90-fa7b3a3c',
  'js/opsec.js?v=1.90-afec60c5',
  'js/osint.js?v=1.90-d24d2f52',
  'js/pad.js?v=1.90-909dca91',
  'js/parse.js?v=1.90-5ddbeafe',
  'js/pcap.js?v=1.90-e484301b',
  'js/persona.js?v=1.90-7b33a605',
  'js/phone.js?v=1.90-75bc4704',
  'js/picx.js?v=1.90-2d164ad7',
  'js/playbooks.js?v=1.90-66eddb74',
  'js/qbuild.js?v=1.90-4e62a10c',
  'js/queries.js?v=1.90-4bd3aadb',
  'js/recent.js?v=1.90-6d8f62da',
  'js/regexb.js?v=1.90-c1ac2b74',
  'js/relate.js?v=1.90-2aeb9473',
  'js/report.js?v=1.90-e183c3c9',
  'js/repwriter.js?v=1.90-746763e6',
  'js/rulepack.js?v=1.90-3cb44b16',
  'js/rulever.js?v=1.90-bab684ef',
  'js/rxbig.js?v=1.90-9335fc49',
  'js/rxengine.js?v=1.90-641afc4b',
  'js/rxlib.js?v=1.90-481ff43a',
  'js/safety.js?v=1.90-a8cab4b5',
  'js/savedv.js?v=1.90-95c50a46',
  'js/search.js?v=1.90-f5959f1f',
  'js/security.js?v=1.90-eb3d8ab9',
  'js/setup.js?v=1.90-215cd8c0',
  'js/share.js?v=1.90-4baa7d43',
  'js/sightings.js?v=1.90-07677802',
  'js/snapcase.js?v=1.90-0e8dbeb4',
  'js/sources.js?v=1.90-96e11d79',
  'js/sqlite.js?v=1.90-7f3af8f1',
  'js/stash.js?v=1.90-82ca377c',
  'js/storage.js?v=1.90-0f7940b1',
  'js/story.js?v=1.90-ce2ad0ff',
  'js/stylo.js?v=1.90-ecc2ea63',
  'js/templates.js?v=1.90-557da7c8',
  'js/textin.js?v=1.90-25c20484',
  'js/tiover.js?v=1.90-4757c658',
  'js/tl.js?v=1.90-1da49f4f',
  'js/tlx.js?v=1.90-c2675c04',
  'js/tlx2.js?v=1.90-cb2dad96',
  'js/today.js?v=1.90-5d077453',
  'js/tour.js?v=1.90-57aa8d67',
  'js/tradecraft.js?v=1.90-a2e7ab17',
  'js/trail.js?v=1.90-5d4874a3',
  'js/transport.js?v=1.90-e7fbfe5c',
  'js/triage.js?v=1.90-ef00f55a',
  'js/validate.js?v=1.90-4d5e6d00',
  'js/valmenu.js?v=1.90-b7dee91d',
  'js/vault2.js?v=1.90-69644956',
  'js/vdecay.js?v=1.90-bfca184e',
  'js/vendor/cytoscape.min.js?v=1.90-83e8c54a',
  'js/vendor/enrich-data.js?v=1.90-3c974ff3',
  'js/vendor/js-yaml.min.js?v=1.90-45dc3dd0',
  'js/vendor/jsqr.min.js?v=1.90-41fdad3e',
  'js/vendor/libphonenumber-max.js?v=1.90-49963114',
  'js/vendor/oui-vendors.js?v=1.90-c0e66aaa',
  'js/vendor/world-map.js?v=1.90-417768fe',
  'js/verdict.js?v=1.90-86d19267',
  'js/views.js?v=1.90-ea51cd50',
  'js/vimport.js?v=1.90-57ac9464',
  'js/vin.js?v=1.90-b6129634',
  'js/vlist.js?v=1.90-fda3ee50',
  'js/wallet.js?v=1.90-427ea656',
  'js/watch.js?v=1.90-20a55856',
  'js/webcap.js?v=1.90-9735fae5',
  'js/webpage.js?v=1.90-b20e2b51',
  'js/whatsnew.js?v=1.90-b4d4291c',
  'js/x509.js?v=1.90-0b97c484',
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
