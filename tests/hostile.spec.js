// Hostile text everywhere: markup, attribute-breaking quotes, script URLs, right-to-left and
// control characters, template syntax and spreadsheet formulas put into every text field the
// app keeps — then every page, case tab, details panel and edit dialog is opened, before and
// after a refresh. Nothing may run, no markup may appear, no link may carry a script URL.
const { test, expect } = require('@playwright/test');
const { open, noErrors } = require('./helpers');
const fs = require('fs'), path = require('path');
test.setTimeout(240000);
const FX = p => fs.readFileSync(path.join(__dirname, 'fixtures', p), 'utf8');

async function crawler(page, texts = true){
  const check = async where => {
    const r = await page.evaluate(() => ({ x: window.__x, pwn: [...document.querySelectorAll('[id^=pwn], img[src="x"], svg[onload], script:not([src])')].map(e => e.outerHTML.slice(0, 80)),
      on: [...document.querySelectorAll('*')].flatMap(e => [...e.attributes].filter(a => /^on/i.test(a.name)).map(a => e.tagName + ' ' + a.name)).slice(0, 5),
      js: [...document.querySelectorAll('a[href], [src], form[action], iframe')].map(e => e.getAttribute('href') || e.getAttribute('src') || e.getAttribute('action') || '').filter(h => /^\s*(javascript|vbscript|data:text\/html)/i.test(h.replace(/[\u0000- ]/g, ''))).slice(0, 5) }));
    expect(r, where).toEqual({ x: undefined, pwn: [], on: [], js: [] });
  };
  const areas = ['home', 'today', 'cases', 'notes', 'notebook', 'pad', 'toolbox', 'queries', 'detections', 'playbooks', 'feeds', 'decoder', 'reference', 'lab', 'certs', 'cloud', 'ctf', 'security', 'settings', 'trash', 'whatsnew', 'help', 'library'];
  const tabs = ['overview', 'vault', 'entities', 'timeline', 'graph', 'map', 'media', 'infra', 'questions', 'story', 'report'];
  const crawl = async label => {
    for(const a of areas){ await page.evaluate(a => { location.hash = '#/' + a; }, a); await page.waitForTimeout(120); await check(label + ' #/' + a); }
    for(const t of tabs){ await page.evaluate(t => go(caseHash(DB.active, t)), t); await page.waitForTimeout(200); await check(label + ' tab ' + t);
      if(t === 'story') for(const v of ['claims', 'sources', 'reply', 'archive']){ await page.evaluate(v => { UI.stView = v; renderAll(); }, v); await page.waitForTimeout(150); await check(label + ' story ' + v);
        if(texts && v === 'claims') expect(await page.evaluate(() => document.querySelector('#main').textContent), 'a hostile claim is shown as text').toContain('claim <img src=x onerror=window.__x=1>'); }
      if(t === 'infra') for(const v of ['dom', 'money', 'acc']){ await page.evaluate(v => { UI.ivView = v; renderAll(); }, v); await page.waitForTimeout(150); await check(label + ' infra ' + v);
        if(texts && v === 'acc') expect(await page.evaluate(() => document.querySelector('#main').textContent), 'the hostile profile name is shown as text').toContain('<img src=x onerror=window.__x=11>');
        if(texts && v === 'dom') expect(await page.evaluate(() => document.querySelector('#main').textContent), 'the hostile WHOIS organisation is shown as text').toContain('<b id=pwn5>'); } }
    await page.evaluate(() => go(caseHash(DB.active, 'timeline'))); await page.waitForTimeout(200);
    if(texts) expect(await page.evaluate(() => document.querySelector('#main').textContent), 'hostile titles are shown as text').toContain("'><b id=pwn>B</b>");
    // the details panel for records, vault entries and entities
    const sel = await page.evaluate(() => ({ recs: DB.records.filter(r => r.caseId === DB.active).slice(-6).map(r => r.id), ents: (DB.entries || []).filter(e => e.caseId === DB.active).slice(0, 4).map(e => e.id) }));
    await page.evaluate(() => go(caseHash(DB.active, 'timeline')));
    for(const id of sel.recs){ await page.evaluate(id => select('rec', id), id); await page.waitForTimeout(80); await check(label + ' rec ' + id); }
    for(const id of sel.ents){ await page.evaluate(id => selectEntry(id), id); await page.waitForTimeout(80); await check(label + ' entry ' + id); }
    const ents = await page.evaluate(() => [...document.querySelectorAll('[data-act=selEnt]')].slice(0, 8).map(b => b.dataset.id));
    for(const id of ents){ await page.evaluate(id => clickAct('selEnt', id), id); await page.waitForTimeout(80); await check(label + ' ent ' + id); }
    // edit dialogs show the hostile values inside fields, as text
    await page.evaluate(() => caseDlg(true)); await check(label + ' case dialog'); await page.evaluate(() => closeDlg());
    if(sel.ents.length){ await page.evaluate(id => entryDlg(entryById(id)), sel.ents[0]).catch(() => {}); await check(label + ' entry dialog'); await page.evaluate(() => closeDlg()); }
    await page.evaluate(() => srchOpen()); await page.fill('#srQ', 'img src'); await page.waitForTimeout(200); await check(label + ' search'); await page.keyboard.press('Escape');
  };
  return crawl;
}

test('hostile text in every field stays text on every page, panel and dialog — also after a refresh', async ({ page }) => {
  const errs = await open(page, '#/home');
  const prof = JSON.parse(FX('profiles/github-octocat.json')); prof.name = '<img src=x onerror=window.__x=11>'; prof.bio = '"><svg onload=window.__x=12>'; prof.blog = 'javascript:window.__x=13'; prof.company = '=cmd|"/c calc"!A1';
  const whois = FX('infra/whois/' + fs.readdirSync(path.join(__dirname, 'fixtures/infra/whois'))[0]).replace(/(Registrant[^:\n]*:[ \t]*)[^\n]+/i, '$1<b id=pwn5>Evil "Org\'</b>');
  await page.evaluate(({ prof, whois }) => {
    const H = ' <img src=x onerror=window.__x=1> "><svg onload=window.__x=2> \'><b id=pwn>B</b> javascript:window.__x=3 ‮evil‬ \u0000nul {{7*7}}${7*7} </textarea></script><b id=pwn2>x</b> =cmd|"/c calc"!A1 🧑‍💻';
    const TXT = /^(title|body|name|notes|note|text|source|host|label|desc|description|summary|query|q|comment|answer|why|content|alias|handle|code|claim|reason|subject|place|who|what|owner|status_note|context|org|value)$/;
    const seen = new Set();
    const walk = (o, depth) => { if(!o || typeof o !== 'object' || seen.has(o) || depth > 8) return; seen.add(o);
      for(const k of Object.keys(o)){ const v = o[k];
        if(typeof v === 'string' && TXT.test(k) && !/^(id|caseId|type|kind)$/.test(k)) o[k] = v + H;
        else if(k === 'tags' && Array.isArray(v)) v.push('tag' + H);
        else if((k === 'url' || k === 'href' || k === 'link') && typeof v === 'string') o[k] = 'javascript:window.__x=4';
        else if(typeof v === 'object') walk(v, depth + 1); } };
    for(const k of ['cases', 'records', 'entries', 'notes', 'tools', 'queries', 'rules', 'hunts', 'playbooks', 'srcRel']) walk(DB[k], 0);
    const c = DB.cases.find(x => x.id === DB.active);
    for(const r of DB.records.filter(r => r.caseId === DB.active).slice(0, 5)) r.att = [{id:'f-none', name:'evil<img src=x onerror=window.__x=5>".png', type:'image/png', size:10, sha256:'0'.repeat(64)}];
    const add = (title, body) => DB.records.push({id:'hx' + Math.random().toString(36).slice(2), caseId:DB.active, type:'note', title, body, ts:Date.now(), tsRaw:'', tsZone:'', host:'<b id=pwn3>h</b>', source:'"><b id=pwn4>', tags:['<i id=pwn6>t</i>'], ents:extractRich(body), addedBy:'You', addedAt:Date.now(), hash:''});
    add('profile' + H, JSON.stringify(prof)); add('whois' + H, whois);
    add('ioc' + H, 'contact <img src=x onerror=window.__x=6>@evil.test and http://evil.test/"><svg/onload=window.__x=7> and javascript:alert(1) +44 7700 900123 bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq 10.0.0.1"><b id=pwn7>');
    /* the story: claims, a protected source, a reply, archived pages */
    const R = DB.records.filter(r => r.caseId === DB.active), E1 = DB.entries.find(e => e.caseId === DB.active);
    c.claims = [{id:'clx', t:'claim' + H, st:'confirmed', for:R.slice(0, 2).map(r => 'r:' + r.id).concat(['s:srx']), against:[], about:E1 ? [E1.id] : [], note:'note' + H, at:1}];
    c.replies = [{id:'rrx', who:'', name:'who' + H, via:'Email' + H, at:Date.now() - 864e5, due:Date.now() + 864e5, claims:['clx'], st:'answered', resp:'resp' + H, respAt:Date.now()}];
    DB.sources = [{id:'srx', caseId:DB.active, alias:'alias' + H, rel:'A', sealed:'{}', created:1}];
    add('cited' + H, 'see https://evil.test/a?b="><b id=pwn8>x</b> for more');
    DB.archive = {'https://evil.test/a?b="><b': {snap:'https://web.archive.org/web/2026/x"><b id=pwn9>', at:Date.now(), req:Date.now()}};
    mutate('hostile'); }, { prof, whois });
  const crawl = await crawler(page);
  await crawl('before refresh');
  await page.reload(); await expect.poll(() => page.evaluate(() => typeof DB !== 'undefined' && !!document.querySelector('#sidenav .nv'))).toBe(true);
  expect(await page.evaluate(() => DB.records.filter(r => /^hx/.test(r.id)).length)).toBe(4);
  await crawl('after refresh');
  noErrors(errs);
});

test('wrong shapes in stored data (an old version, a hand-edited backup, a damaged copy) never break a page — also after a refresh', async ({ page }) => {
  const errs = await open(page, '#/home');
  // written straight into storage, as an old version or a damaged copy would leave it; this page is told not to save over it
  await page.evaluate(async () => { const copy = JSON.parse(JSON.stringify(DB)); await (async DB => {
    const rs = DB.records.filter(r => r.caseId === DB.active);
    const bad = [null, 5, 'x', [], {}, true, {rel:{}}, [1, 2], {lat:'n', lon:{}}];
    rs.slice(0, 9).forEach((r, i) => { r.geo = bad[i]; r.cred = bad[(i + 1) % 9]; r.tsShift = bad[(i + 2) % 9]; r.att = [{id:'f' + i, name:bad[i], type:bad[(i + 3) % 9], size:bad[(i + 4) % 9], meta:bad[(i + 5) % 9], psig:bad[(i + 6) % 9]}, bad[i]]; });
    rs[9].att = 'nope'; rs[10].tags = [null, 5, {}]; rs[11].ents = [null, {k:5}, {k:'ip', v:null}];
    DB.entries.push({id:'ex1', caseId:DB.active, type:'spaceship', fields:{name:{}, x:5}, tags:'x', notes:{}}, {id:5}, null, {id:'ex2', caseId:DB.active, type:'person', fields:'n'});
    DB.links.push({id:'lx', a:5, b:null}, {id:'ly', a:'ex1', b:'nope', label:{}, conf:'x'}); DB.cases.push({id:'cx', name:{}, code:5});
    DB.srcRel = [1, 2]; DB.phoneCC = {a:1}; DB.hunts = 'x'; DB.autoDone = 5; DB.autoLog = {}; DB.verdicts = DB.verdicts || {};
    DB.trash = [...(DB.trash || []), null, 5, {id:'tx1'}, {id:'tx2', kind:'rule', data:{}}, {id:'tx5', kind:'tool', data:{t:'x'}}, {id:'tx6', kind:'note', data:{n:null}}, {id:'tx7', kind:'entry', data:{e:{}}}, {id:'tx8', kind:'hunt', data:{h:5}}, {id:'tx3', kind:'nope', label:{}, data:'x', at:'yesterday'}, {id:'tx4', kind:'record', label:'r', data:{}}];
    DB.savedAt = Date.now() + 60000; const j = JSON.stringify(DB); TABS.writer = false; clearTimeout(saveT); await IDB.set(STORE_KEY, j); localStorage.setItem(STORE_KEY, j); })(copy); });
  /* the reload is done from here, so the test waits for the new page instead of racing the old one */
  await page.reload(); await expect.poll(() => page.evaluate(() => typeof DB !== 'undefined' && !!document.querySelector('#sidenav .nv'))).toBe(true);
  const crawl = await crawler(page, false);
  await crawl('loaded');
  // restoring broken trash items explains instead of breaking
  await page.evaluate(() => { location.hash = '#/trash'; });
  for(const id of ['tx2', 'tx3', 'tx4', 'tx5', 'tx6', 'tx7', 'tx8']){ await page.evaluate(id => { const b = document.querySelector(`[data-act=trRestore][data-id="${id}"]`); if(b) b.click(); }, id); await page.waitForTimeout(100); }
  // well-formed values are kept as they were; an unknown kind of entry is kept as a document
  expect(await page.evaluate(() => { const e = entryById('ex1'); return e && [e.type, e.tags.includes('was spaceship'), e.fields.x]; })).toEqual(['document', true, '5']);
  expect(await page.evaluate(() => [typeof DB.srcRel, DB.phoneCC, Array.isArray(DB.trash) && DB.trash.every(x => x && typeof x.kind === 'string'), DB.records.every(r => Array.isArray(r.att) && Array.isArray(r.tags))])).toEqual(['object', '', true, true]);
  await page.reload(); await expect.poll(() => page.evaluate(() => typeof DB !== 'undefined' && !!document.querySelector('#sidenav .nv'))).toBe(true);
  await crawl('after refresh');
  noErrors(errs);
});

test('everything kept comes back from a backup and after a refresh: places, grades, source ratings, the phone country, hunts, file details, picture fingerprints and the trash', async ({ page }) => {
  const errs = await open(page, '#/home');
  const want = await page.evaluate(() => {
    const rs = DB.records.filter(r => r.caseId === DB.active);
    rs[0].geo = {kind:'street', verdict:'confirmed', note:'corner shop sign', clues:[{t:'sign "Bäckerei"'}]}; rs[1].cred = '2'; rs[2].tsShift = 3600000;
    rs[3].att = [{id:'f-keep', name:'IMG_0042 é ✓.jpg', type:'image/jpeg', size:1234, sha256:'a'.repeat(64), meta:{fields:[['Camera', 'Pixel 7']], gps:{lat:51.5, lon:-0.12}, taken:1700000000000, at:1}, psig:'ff00,00ff,,1234', dhash:'0f0f0f0f0f0f0f0f'}];
    DB.srcRel = {'twitter.com/x':{rel:'B', at:1}}; DB.phoneCC = 'GB';
    DB.hunts = [{id:'hu-keep', kind:'query', name:'Hunt é', q:'powershell -enc', at:1, seen:[]}];
    trashPut('note', 'gone note ✓', {n:{id:'n-gone', title:'gone', body:'x'}});
    mutate('roundtrip');
    const pick = () => { const r = id => DB.records.find(x => x.id === id); return {geo:r(rs[0].id).geo, cred:r(rs[1].id).cred, shift:r(rs[2].id).tsShift, att:r(rs[3].id).att, srcRel:DB.srcRel, cc:DB.phoneCC, hunts:DB.hunts.map(h => h.name + h.q), trash:DB.trash.map(x => x.label).sort()}; };
    window.__pick = pick; return pick(); });
  // after a refresh
  await page.reload(); await expect.poll(() => page.evaluate(() => typeof DB !== 'undefined' && !!document.querySelector('#sidenav .nv'))).toBe(true);
  const ids = await page.evaluate(() => DB.records.filter(r => r.caseId === DB.active).slice(0, 4).map(r => r.id));
  const read = () => page.evaluate(ids => { const r = id => DB.records.find(x => x.id === id); return {geo:r(ids[0]).geo, cred:r(ids[1]).cred, shift:r(ids[2]).tsShift, att:r(ids[3]).att, srcRel:DB.srcRel, cc:DB.phoneCC, hunts:DB.hunts.map(h => h.name + h.q), trash:DB.trash.map(x => x.label).sort()}; }, ids);
  expect(await read()).toEqual(want);
  // through a backup: export, wipe, import
  const [dl] = await Promise.all([page.waitForEvent('download'), page.evaluate(() => exportEverything(false, true))]);
  await page.evaluate(() => { DB.srcRel = {}; DB.phoneCC = ''; DB.hunts = []; DB.trash = []; for(const r of DB.records){ delete r.geo; delete r.cred; delete r.tsShift; r.att = []; } mutate('wiped'); });
  // the file picker is stood in for (a picker opened from a script can be refused when the machine is busy); the file is the real export
  await page.evaluate(t => { window.pickFile = (a, cb) => cb(t, 'backup.json'); }, fs.readFileSync(await dl.path(), 'utf8')); await page.evaluate(() => clickAct('importAll'));
  await page.click('[data-act=confirmOk]');
  await expect.poll(() => page.evaluate(() => DB.phoneCC)).toBe('GB');
  expect(await read()).toEqual(want);
  await page.reload(); await expect.poll(() => page.evaluate(() => typeof DB !== 'undefined' && !!document.querySelector('#sidenav .nv'))).toBe(true);
  expect(await read()).toEqual(want);
  noErrors(errs);
});

test('every parser takes junk, huge, deeply nested, oddly encoded and pathological input without throwing or hanging; text files in UTF-16, with a byte-order mark or in the old Windows code page read correctly', async ({ page }) => {
  const errs = await open(page, '#/home');
  const r = await page.evaluate(async () => {
    const out = [], rnd = (s => () => (s = (s * 1103515245 + 12345) >>> 0) / 4294967296)(7);
    const T = { empty: '', nul: '\0\0', html: '<img src=x onerror=window.__x=1>"\'>', rtl: '‮ مرحبا 你好 🧑‍💻 \uD800 ￿', bom: '﻿id,name\r\n1,"a""b"\r\n2,"unclosed\r\n',
      longline: 'A'.repeat(1e6), lines: Array.from({ length: 50000 }, (_, i) => 'line ' + i + ' 10.0.0.' + (i % 255)).join('\n'), deepjson: '['.repeat(100000) + ']'.repeat(100000), deepobj: '{"a":'.repeat(20000) + '1' + '}'.repeat(20000), trunc: '{"a":[1,2,{"b":"c',
      digits: '1'.repeat(200000), dots: '1.'.repeat(30000), at: '@'.repeat(40000) + 'x', spaces: ' '.repeat(100000) + 'x', b58: 'QUJD'.repeat(100000), url: 'http://' + 'a.'.repeat(30000) + 'com/' + '%41'.repeat(20000), quotes: '"'.repeat(100000), ctrl: Array.from({ length: 2000 }, (_, i) => String.fromCharCode(i % 32)).join('') };
    const P = { parseLog: t => parseLog(t), logParse: t => logParse(t, 'x.csv'), logJson: t => logParse(t, 'x.json'), extract: t => E.extract(t), extractRich: t => extractRich(t), parseQuery: t => E.parseQuery(t), sigma: t => sigmaParse(t), yara: t => yaraParse(t), nlq: t => nlqParse(t),
      time: t => E.parseTime(t), ua: t => parseUA(t), headers: t => parseHeaders(t), csv: t => csvParse(t), kv: t => kvParse(t), mhtml: t => mhtmlParse(t), web: t => parseWebPage(t), ct: t => ctParse(t), decodeChain: t => decodeChain(t), decodeIds: t => decodeIds(t), cmd: t => cmdDecode(t),
      infra: t => infraParse(t), wallet: t => walletParse(t), profile: t => ftParseJson(t), coords: t => parseCoords(t), geo: t => geoParse(t), cert: t => cxInRecord({ id: 'z', body: t }), dates: t => [ftDate(t), mtDate(t), ifWDate(t)], x5: t => X5.read(t), auto: async t => autoDecode(t.slice(0, 300000)) };
    for(const [n, f] of Object.entries(P)) for(const [k, v] of Object.entries(T)){ const t0 = performance.now(); try{ await f(v); }catch(e){ if(!/^Not |cannot|could not/i.test(e.message)) out.push(n + ' <- ' + k + ': ' + e.message); } const ms = performance.now() - t0; if(ms > 2500) out.push(n + ' <- ' + k + ': ' + Math.round(ms) + ' ms'); }
    const B = { empty: new Uint8Array(0), rnd: Uint8Array.from({ length: 65536 }, () => Math.floor(rnd() * 256)) };
    for(const [k, h] of Object.entries({ png: [137, 80, 78, 71, 13, 10, 26, 10], jpg: [255, 216, 255, 225, 0, 255], pdf: [37, 80, 68, 70], zip: [80, 75, 3, 4], pe: [77, 90], elf: [127, 69, 76, 70], pcap: [212, 195, 178, 161], sqlite: [83, 81, 76, 105, 116, 101], ftyp: [0, 0, 0, 24, 102, 116, 121, 112], tiff: [73, 73, 42, 0, 255, 255, 255, 255], der: [48, 130, 255, 255] }))
      for(const fill of ['r', 0, 255]) B[k + fill] = Uint8Array.from([...h, ...Array.from({ length: 3000 }, () => fill === 'r' ? Math.floor(rnd() * 256) : fill)]);
    const PB = { pcap: b => pcapRead(b), pe: b => peInfo(b), elf: b => elfInfo(b), png: b => pngInfo(b), pdf: b => pdfInfo(b), zip: b => zipInfo(b), meta: b => metaRead(b, 'x', ''), tiff: b => parseTiff(b, 0), x5: b => X5.read(b), pic: b => picSigBlob(new Blob([b])) };
    for(const [n, f] of Object.entries(PB)) for(const [k, v] of Object.entries(B)){ const t0 = performance.now(); try{ await f(v); }catch(e){ if(!/^Not |cannot|could not|truncated/i.test(e.message)) out.push(n + ' <- ' + k + ': ' + e.message); } if(performance.now() - t0 > 2500) out.push(n + ' <- ' + k + ' slow'); }
    // text files written by Windows tools
    const s = 'Zeit,Benutzer,Nachricht\r\n2026-11-02 08:15,jürgen,Anmeldung fehlgeschlagen — 203.0.113.7\r\n';
    const le = new Uint8Array(s.length * 2), be = new Uint8Array(s.length * 2); for(let i = 0; i < s.length; i++){ le[i * 2] = s.charCodeAt(i) & 255; le[i * 2 + 1] = s.charCodeAt(i) >> 8; be[i * 2] = s.charCodeAt(i) >> 8; be[i * 2 + 1] = s.charCodeAt(i) & 255; }
    const u8 = new TextEncoder().encode(s), cp = Uint8Array.from(s.replace('—', '-'), c => c === 'ü' ? 0xfc : c.charCodeAt(0));
    const reads = await Promise.all([new Uint8Array([0xff, 0xfe, ...le]), le, new Uint8Array([0xfe, 0xff, ...be]), be, new Uint8Array([0xef, 0xbb, 0xbf, ...u8]), u8].map(b => fileText(new File([b], 'x.csv'))));
    const cpRead = await fileText(new File([cp], 'x.csv'));
    const rows = logParse(reads[0], 'x.csv').rows;
    return { out, x: window.__x, same: reads.every(t => t === s), cp: cpRead === s.replace('—', '-'), user: rows[0] && Object.values(rows[0]).includes('jürgen') };
  });
  expect(r).toEqual({ out: [], x: undefined, same: true, cp: true, user: true });
  noErrors(errs);
});

test('length limits: every text field has a cap, an oversized paste is cut with a message, a full notebook page takes no more, and oversized saved values are trimmed on load', async ({ page }) => {
  const errs = await open(page, '#/home');
  const unc = [];
  for(const h of ['#/home', '#/notes', '#/toolbox', '#/queries', '#/detections', '#/decoder', '#/lab', '#/certs', '#/pad', '#/settings']){
    await page.evaluate(h => { location.hash = h; }, h); await page.waitForTimeout(150);
    unc.push(...await page.evaluate(() => [...document.querySelectorAll('input, textarea')].filter(e => (e.tagName === 'TEXTAREA' || !/^(file|number|range|checkbox|radio|color|date|datetime-local|time|month|week|hidden|submit|button|reset|image)$/i.test(e.type)) && !(e.maxLength > 0)).map(e => location.hash + ' ' + (e.id || e.name || e.outerHTML.slice(0, 60)))));
  }
  await page.evaluate(() => openCapture()); unc.push(...await page.evaluate(() => [...document.querySelectorAll('#dlg input:not([type=file]):not([type=checkbox]), #dlg textarea')].filter(e => !(e.maxLength > 0)).map(e => 'capture ' + e.id)));
  expect(unc).toEqual([]);
  // a paste far over the cap of a one-line field is cut, and says so
  await page.evaluate(() => closeDlg()); await page.evaluate(() => { location.hash = '#/toolbox'; }); await page.waitForTimeout(200);
  const sel = await page.evaluate(() => { const i = [...document.querySelectorAll('#main input')].find(e => e.type === 'search' || e.type === 'text'); i.id = i.id || 'limT'; return '#' + i.id; });
  await page.focus(sel);
  await page.evaluate(sel => { const el = document.querySelector(sel), dt = new DataTransfer(); dt.setData('text/plain', 'x'.repeat(100000)); el.dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true })); }, sel);
  await expect(page.locator('#toasts, .toast').first()).toContainText('so it was cut');
  await page.keyboard.insertText('y'.repeat(10000)); expect(await page.evaluate(sel => document.querySelector(sel).value.length, sel)).toBe(4096);
  // a notebook page at its cap takes no more typing (deleting still works)
  await page.evaluate(() => { location.hash = '#/notebook'; }); await page.waitForTimeout(200); await page.evaluate(() => NB_ACTS.nbPageNew(DB.nb.sections[0].id)); await expect(page.locator('#nbEd')).toBeVisible();
  expect(await page.evaluate(() => { const ed = $('nbEd'); ed.textContent = 'z'.repeat(LIM.page); const t = new InputEvent('beforeinput', { inputType: 'insertText', data: 'a', bubbles: true, cancelable: true }), d = new InputEvent('beforeinput', { inputType: 'deleteContentBackward', bubbles: true, cancelable: true });
    ed.dispatchEvent(t); ed.dispatchEvent(d); const r = [t.defaultPrevented, d.defaultPrevented]; ed.textContent = 'ok'; return r; })).toEqual([true, false]);
  // stored values far past any cap are trimmed when the workspace loads
  await page.evaluate(() => { const r = DB.records[0]; r.title = 'T'.repeat(50000); r.tags = Array.from({ length: 1000 }, (_, i) => 'tag' + i); DB.cases[0].name = 'N'.repeat(9000); mutate('huge'); });
  await page.waitForTimeout(400);   // let the save land in both stores before the refresh, as a person's would
  await page.reload(); await expect.poll(() => page.evaluate(() => typeof DB !== 'undefined' && !!document.querySelector('#sidenav .nv'))).toBe(true);
  expect(await page.evaluate(() => [DB.records[0].title.length, DB.records[0].tags.length, DB.cases[0].name.length])).toEqual([2000, 200, 500]);
  noErrors(errs);
});

test('two tabs: the second is read-only while the first is open, and takes over saving by itself when the first closes', async ({ page, context }) => {
  const errs = await open(page, '#/home');
  const b = await context.newPage(); await b.goto(page.url());
  await expect.poll(() => b.evaluate(() => typeof DB !== 'undefined' && !!document.querySelector('#sidenav .nv'))).toBe(true);
  expect(await b.evaluate(() => TABS.writer)).toBe(false);
  await expect(b.locator('#rotab')).toBeVisible();
  await page.close();
  await expect.poll(() => b.evaluate(() => TABS.writer)).toBe(true);
  await expect(b.locator('#rotab')).toHaveCount(0);
  await b.evaluate(() => { DB.cases[0].name = 'Taken over'; mutate('rename'); });
  await b.waitForTimeout(400); await b.reload();
  await expect.poll(() => b.evaluate(() => typeof DB !== 'undefined' && !!DB && DB.cases[0].name)).toBe('Taken over');
  noErrors(errs);
});
