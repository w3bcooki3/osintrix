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
const BUILD = '1.54-5efe76fe7572';
const FILES = [
  'css/app.css?v=1.54-2bcbbb57',
  'css/design.css?v=1.54-d231e159',
  'css/fonts.css?v=1.54-6b722f46',
  'css/theme.css?v=1.54-c7d9472f',
  'js/ach.js?v=1.54-ee81d8ef',
  'js/activity.js?v=1.54-7438453f',
  'js/app.js?v=1.54-8f1f0e1d',
  'js/areas.js?v=1.54-bc261c71',
  'js/auto.js?v=1.54-cb17a519',
  'js/brand.js?v=1.54-818b56d9',
  'js/caseents.js?v=1.54-5576b2d8',
  'js/caserules.js?v=1.54-510f59b7',
  'js/certs.js?v=1.54-16bfc0f0',
  'js/chain.js?v=1.54-9d2efc8a',
  'js/changes.js?v=1.54-048b6413',
  'js/checklist.js?v=1.54-7d86951b',
  'js/cloud.js?v=1.54-22a425cf',
  'js/cloudlogs.js?v=1.54-1cc3239b',
  'js/cloudscan.js?v=1.54-c32baedc',
  'js/copilot.js?v=1.54-c63ab18e',
  'js/core.js?v=1.54-7bdecdb9',
  'js/ctf.js?v=1.54-a0fdd8e1',
  'js/cti.js?v=1.54-3792c593',
  'js/data/attack.js?v=1.54-c1562fb4',
  'js/data/cert-guide.js?v=1.54-4398ad03',
  'js/data/cert-samples.js?v=1.54-0299cc85',
  'js/data/changelog.js?v=1.54-15a30abc',
  'js/data/cloudguide-pack.js?v=1.54-7f7b86e0',
  'js/data/cloudguide.js?v=1.54-f4e2ee0a',
  'js/data/ctf-cheats.js?v=1.54-a94afc1e',
  'js/data/detection-rules.js?v=1.54-b4a16c10',
  'js/data/detections-pack.js?v=1.54-fbe0bb54',
  'js/data/kev-snapshot.js?v=1.54-00aad734',
  'js/data/notebook-demo.js?v=1.54-d0996dc4',
  'js/data/playbooks-pack.js?v=1.54-47498e78',
  'js/data/query-templates.js?v=1.54-d96de4aa',
  'js/data/reference-pack.js?v=1.54-4c093c4b',
  'js/data/reference.js?v=1.54-232bff13',
  'js/data/sample-osint.js?v=1.54-a8480d68',
  'js/data/tools.js?v=1.54-8fffec7b',
  'js/demo.js?v=1.54-d81efcbb',
  'js/detections.js?v=1.54-870c9880',
  'js/detiq.js?v=1.54-8accc6ef',
  'js/detlab.js?v=1.54-8e61fc50',
  'js/dupes.js?v=1.54-77aafeeb',
  'js/endpoint.js?v=1.54-c4886a1f',
  'js/engine.js?v=1.54-efdd9802',
  'js/evnote.js?v=1.54-127a26a3',
  'js/evtx.js?v=1.54-4993a790',
  'js/extras.js?v=1.54-a53e5031',
  'js/fbackup.js?v=1.54-54b3d4db',
  'js/footprint.js?v=1.54-c193c308',
  'js/geoloc.js?v=1.54-c6d2c256',
  'js/graph.js?v=1.54-ed700956',
  'js/graphiq.js?v=1.54-82531632',
  'js/hours.js?v=1.54-3f8fb74b',
  'js/hunts.js?v=1.54-40e79704',
  'js/icons.js?v=1.54-dc8ac907',
  'js/identity.js?v=1.54-795f7202',
  'js/imgx.js?v=1.54-37da06c7',
  'js/infra.js?v=1.54-82d1e06d',
  'js/insp.js?v=1.54-435dca78',
  'js/integrity.js?v=1.54-6bd6a56b',
  'js/intel.js?v=1.54-87be7aa8',
  'js/investigate.js?v=1.54-91febe6a',
  'js/kit.js?v=1.54-580ff95a',
  'js/lab.js?v=1.54-dd24b7b4',
  'js/layouts.js?v=1.54-82c05eda',
  'js/lazy.js?v=1.54-dc1aced0',
  'js/limits.js?v=1.54-00cc2dd4',
  'js/links.js?v=1.54-61b0383d',
  'js/lookups.js?v=1.54-a8852adb',
  'js/map.js?v=1.54-3d33ea23',
  'js/mask.js?v=1.54-8bde180c',
  'js/media.js?v=1.54-7db6eda2',
  'js/meta.js?v=1.54-40dfe377',
  'js/model.js?v=1.54-2ee86688',
  'js/nbexport.js?v=1.54-8b6265ff',
  'js/nlq.js?v=1.54-556b5b3a',
  'js/notebook.js?v=1.54-02ce0b58',
  'js/notes.js?v=1.54-88f10397',
  'js/oldoffice.js?v=1.54-18f81939',
  'js/osint.js?v=1.54-a39db509',
  'js/pad.js?v=1.54-76b424fe',
  'js/parse.js?v=1.54-15518b9f',
  'js/pcap.js?v=1.54-4458a5b0',
  'js/phone.js?v=1.54-6ec6eeff',
  'js/picx.js?v=1.54-4a0a1911',
  'js/playbooks.js?v=1.54-1098b072',
  'js/qbuild.js?v=1.54-4e62a10c',
  'js/queries.js?v=1.54-57c58329',
  'js/recent.js?v=1.54-697df5e8',
  'js/regexb.js?v=1.54-0333c8cf',
  'js/relate.js?v=1.54-00452cbc',
  'js/report.js?v=1.54-e4c120e2',
  'js/repwriter.js?v=1.54-a5691d65',
  'js/rulepack.js?v=1.54-3cb44b16',
  'js/rulever.js?v=1.54-bab684ef',
  'js/rxbig.js?v=1.54-f32661c7',
  'js/rxengine.js?v=1.54-641afc4b',
  'js/rxlib.js?v=1.54-e416b847',
  'js/safety.js?v=1.54-dd5095ee',
  'js/search.js?v=1.54-03ad56c3',
  'js/security.js?v=1.54-bf5337c7',
  'js/setup.js?v=1.54-215cd8c0',
  'js/share.js?v=1.54-7d3e015a',
  'js/sources.js?v=1.54-96e11d79',
  'js/sqlite.js?v=1.54-1f0a62c8',
  'js/storage.js?v=1.54-1899670c',
  'js/textin.js?v=1.54-25c20484',
  'js/tl.js?v=1.54-0aa0b388',
  'js/tlx.js?v=1.54-c2675c04',
  'js/tlx2.js?v=1.54-cb2dad96',
  'js/today.js?v=1.54-ab34fca5',
  'js/tour.js?v=1.54-8dbbf2d6',
  'js/triage.js?v=1.54-b48624cc',
  'js/validate.js?v=1.54-481647ce',
  'js/valmenu.js?v=1.54-b7dee91d',
  'js/vault2.js?v=1.54-b55c1283',
  'js/vdecay.js?v=1.54-bfca184e',
  'js/vendor/cytoscape.min.js?v=1.54-83e8c54a',
  'js/vendor/enrich-data.js?v=1.54-3c974ff3',
  'js/vendor/js-yaml.min.js?v=1.54-45dc3dd0',
  'js/vendor/jsqr.min.js?v=1.54-41fdad3e',
  'js/vendor/libphonenumber-max.js?v=1.54-49963114',
  'js/vendor/oui-vendors.js?v=1.54-c0e66aaa',
  'js/vendor/world-map.js?v=1.54-417768fe',
  'js/verdict.js?v=1.54-b8ccb240',
  'js/views.js?v=1.54-9381591d',
  'js/vlist.js?v=1.54-b357021a',
  'js/wallet.js?v=1.54-8e6a63b8',
  'js/watch.js?v=1.54-94b854ce',
  'js/webpage.js?v=1.54-90026d66',
  'js/whatsnew.js?v=1.54-16300cd3',
  'js/x509.js?v=1.54-0b97c484',
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
