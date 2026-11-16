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
const BUILD = '1.42-ade67a447ded';
const FILES = [
  'css/app.css?v=1.42-26577523',
  'css/design.css?v=1.42-8d5a6278',
  'css/fonts.css?v=1.42-6b722f46',
  'css/theme.css?v=1.42-dd4eb1ee',
  'js/ach.js?v=1.42-ee81d8ef',
  'js/activity.js?v=1.42-7438453f',
  'js/app.js?v=1.42-0a2dc2d4',
  'js/areas.js?v=1.42-86ff06fe',
  'js/auto.js?v=1.42-1ba61365',
  'js/brand.js?v=1.42-b5dfa6f6',
  'js/caseents.js?v=1.42-5576b2d8',
  'js/caserules.js?v=1.42-510f59b7',
  'js/certs.js?v=1.42-b0fdd26d',
  'js/chain.js?v=1.42-9d2efc8a',
  'js/cloud.js?v=1.42-75eb197f',
  'js/cloudlogs.js?v=1.42-1cc3239b',
  'js/cloudscan.js?v=1.42-c32baedc',
  'js/copilot.js?v=1.42-dcf2ca7b',
  'js/core.js?v=1.42-687f3315',
  'js/ctf.js?v=1.42-e58e41c6',
  'js/cti.js?v=1.42-3792c593',
  'js/data/attack.js?v=1.42-c1562fb4',
  'js/data/cert-guide.js?v=1.42-4398ad03',
  'js/data/cert-samples.js?v=1.42-0299cc85',
  'js/data/changelog.js?v=1.42-8592a09f',
  'js/data/cloudguide-pack.js?v=1.42-7f7b86e0',
  'js/data/cloudguide.js?v=1.42-f4e2ee0a',
  'js/data/ctf-cheats.js?v=1.42-a94afc1e',
  'js/data/detection-rules.js?v=1.42-b4a16c10',
  'js/data/detections-pack.js?v=1.42-fbe0bb54',
  'js/data/kev-snapshot.js?v=1.42-00aad734',
  'js/data/notebook-demo.js?v=1.42-d0996dc4',
  'js/data/playbooks-pack.js?v=1.42-47498e78',
  'js/data/query-templates.js?v=1.42-d96de4aa',
  'js/data/reference-pack.js?v=1.42-4c093c4b',
  'js/data/reference.js?v=1.42-232bff13',
  'js/data/tools.js?v=1.42-8fffec7b',
  'js/demo.js?v=1.42-d81efcbb',
  'js/detections.js?v=1.42-031c6764',
  'js/detiq.js?v=1.42-8accc6ef',
  'js/detlab.js?v=1.42-8e61fc50',
  'js/dupes.js?v=1.42-77aafeeb',
  'js/engine.js?v=1.42-26a0b723',
  'js/evnote.js?v=1.42-127a26a3',
  'js/evtx.js?v=1.42-4993a790',
  'js/extras.js?v=1.42-24209476',
  'js/fbackup.js?v=1.42-54b3d4db',
  'js/graph.js?v=1.42-b3cee403',
  'js/graphiq.js?v=1.42-82531632',
  'js/hunts.js?v=1.42-05d08eb6',
  'js/icons.js?v=1.42-80a8e704',
  'js/imgx.js?v=1.42-817b1806',
  'js/insp.js?v=1.42-3847540f',
  'js/integrity.js?v=1.42-6109faf6',
  'js/intel.js?v=1.42-87be7aa8',
  'js/investigate.js?v=1.42-91febe6a',
  'js/kit.js?v=1.42-5905c1bf',
  'js/lab.js?v=1.42-943124fe',
  'js/layouts.js?v=1.42-6fd3cff9',
  'js/lazy.js?v=1.42-4dcac7a9',
  'js/links.js?v=1.42-5f3140e4',
  'js/lookups.js?v=1.42-a8852adb',
  'js/map.js?v=1.42-2b71c778',
  'js/media.js?v=1.42-f5cadc50',
  'js/model.js?v=1.42-2ee86688',
  'js/nbexport.js?v=1.42-8b6265ff',
  'js/nlq.js?v=1.42-556b5b3a',
  'js/notebook.js?v=1.42-f5f50964',
  'js/notes.js?v=1.42-88f10397',
  'js/osint.js?v=1.42-0752b23e',
  'js/pad.js?v=1.42-c8b45d98',
  'js/parse.js?v=1.42-24e43461',
  'js/pcap.js?v=1.42-4458a5b0',
  'js/picx.js?v=1.42-1520a91f',
  'js/playbooks.js?v=1.42-8ced2006',
  'js/queries.js?v=1.42-a780bdc3',
  'js/recent.js?v=1.42-697df5e8',
  'js/relate.js?v=1.42-00452cbc',
  'js/report.js?v=1.42-e4c120e2',
  'js/repwriter.js?v=1.42-a5691d65',
  'js/rulepack.js?v=1.42-e123d2e6',
  'js/rulever.js?v=1.42-bab684ef',
  'js/safety.js?v=1.42-26eb43cb',
  'js/search.js?v=1.42-29a48dee',
  'js/security.js?v=1.42-bf5337c7',
  'js/setup.js?v=1.42-49bdf44e',
  'js/share.js?v=1.42-7d3e015a',
  'js/sqlite.js?v=1.42-1f0a62c8',
  'js/storage.js?v=1.42-1899670c',
  'js/tl.js?v=1.42-0aa0b388',
  'js/tlx.js?v=1.42-3800cf36',
  'js/tlx2.js?v=1.42-cb2dad96',
  'js/today.js?v=1.42-ab34fca5',
  'js/tour.js?v=1.42-c9ae1017',
  'js/triage.js?v=1.42-b48624cc',
  'js/validate.js?v=1.42-481647ce',
  'js/vdecay.js?v=1.42-bfca184e',
  'js/vendor/cytoscape.min.js?v=1.42-83e8c54a',
  'js/vendor/enrich-data.js?v=1.42-3c974ff3',
  'js/vendor/js-yaml.min.js?v=1.42-45dc3dd0',
  'js/vendor/jsqr.min.js?v=1.42-41fdad3e',
  'js/vendor/oui-vendors.js?v=1.42-c0e66aaa',
  'js/vendor/world-map.js?v=1.42-417768fe',
  'js/verdict.js?v=1.42-b8ccb240',
  'js/views.js?v=1.42-1bf97acf',
  'js/vlist.js?v=1.42-b357021a',
  'js/watch.js?v=1.42-94b854ce',
  'js/webpage.js?v=1.42-fabb3b2a',
  'js/whatsnew.js?v=1.42-16300cd3',
  'js/x509.js?v=1.42-0b97c484',
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
