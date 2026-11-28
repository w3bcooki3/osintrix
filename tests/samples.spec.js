// The sample data since 1.87: two cases — Op Lantern (an intrusion, and with the OSINT sample the crew behind it) and
// Kestrel Dawn (a journalism case) — example notes for each case and general ones, and Case notes in the Notebook.
// An older workspace still holding the old sample cases gets the new set once, and keeps anything of its own.
const { test, expect } = require('@playwright/test');
const { open, noErrors } = require('./helpers');

test('a new workspace has the two sample cases, the journalism one ready to show every part of Story', async ({ page }) => {
  const errors = await open(page, '#/cases', { legacy: false });
  const r = await page.evaluate(() => { const c = theCase('c-story'), recs = DB.records.filter(x => x.caseId === 'c-story');
    return { cases: DB.cases.map(x => x.id), sample: DB.cases.every(x => x.sample), claims: c.claims.map(x => x.st), replies: c.replies.map(x => x.st), archived: Object.keys(DB.archive || {}).length,
      evidence: recs.filter(x => x.type === 'evidence').length, questions: recs.filter(x => x.type === 'lead').length, vessel: DB.entries.some(e => e.caseId === 'c-story' && e.type === 'vessel' && e.fields.imo === '9074729'),
      links: DB.links.filter(l => l.caseId === 'c-story').length }; });
  expect(r.cases).toEqual(['c-lantern', 'c-story']); expect(r.sample).toBe(true);
  expect(r.claims).toEqual(['confirmed', 'confirmed', 'confirmed', 'unverified', 'disputed']); expect(r.replies).toEqual(['answered', 'waiting', 'declined', 'waiting']);
  expect(r.archived).toBeGreaterThanOrEqual(3); expect(r.evidence).toBeGreaterThan(10); expect(r.questions).toBe(4); expect(r.vessel).toBe(true); expect(r.links).toBeGreaterThan(10);
  await page.evaluate(() => { UI.stView = 'claims'; go('#/case/c-story/story'); });
  await expect(page.locator('.st')).toBeVisible();
  await expect(page.locator('#main')).toContainText('2 of 5 claims ready');                 // some ready to publish, some not, each with its reason
  await expect(page.locator('#main')).toContainText('Disputed');
  for (const t of ['overview', 'timeline', 'graph', 'entities', 'vault', 'map', 'questions', 'report']) { await page.evaluate(t => go('#/case/c-story/' + t), t); await page.waitForTimeout(250); }
  noErrors(errors);
});

test('example notes: a checklist and a written note for each case, two general ones; Case notes in the Notebook link cases, entries and pages', async ({ page }) => {
  const errors = await open(page, '#/notes', { legacy: false });
  const n = await page.evaluate(() => { const by = {}; for (const x of DB.notes) (by[x.caseId || 'general'] = by[x.caseId || 'general'] || []).push(/\[[ x]\]/.test(x.text) ? 'checklist' : 'written'); return by; });
  for (const k of ['c-lantern', 'c-story', 'general']) { expect(n[k], k).toContain('checklist'); expect(n[k], k).toContain('written'); }
  await expect(page.locator('.note-card')).toHaveCount(await page.evaluate(() => DB.notes.length));
  const nb = await page.evaluate(() => { ensureNB(); const bk = DB.nb.books.find(b => b.name === 'Case notes'), secs = new Set(DB.nb.sections.filter(s => s.bookId === bk.id).map(s => s.id)), pages = DB.nb.pages.filter(p => secs.has(p.sectionId));
    const links = pages.flatMap(p => [...p.html.matchAll(/data-wl="([a-z]+):([^"]+)"/g)].map(m => m[1] + ':' + m[2]));
    return { pages: pages.map(p => p.title).sort(), cases: links.filter(l => l.startsWith('case:')).sort(), entries: links.filter(l => l.startsWith('entry:')).length, pageLinks: links.filter(l => l.startsWith('page:')).length,
      allThere: links.every(l => { const [k, id] = l.split(':'); return k === 'case' ? DB.cases.some(c => c.id === id) : k === 'entry' ? DB.entries.some(e => e.id === id) : DB.nb.pages.some(p => p.id === id); }), checks: pages.filter(p => /nb-check/.test(p.html)).length }; });
  expect(nb.pages).toEqual(['Kestrel Dawn — story plan', 'Op Lantern — working notes', 'Right of reply — how we do it']);
  expect(nb.cases).toEqual(['case:c-lantern', 'case:c-story', 'case:c-story']); expect(nb.entries).toBeGreaterThan(4); expect(nb.pageLinks).toBeGreaterThanOrEqual(3);
  expect(nb.allThere).toBe(true); expect(nb.checks).toBe(3);
  noErrors(errors);
});

test('the OSINT sample joins Op Lantern, tied to the intrusion by the server they shared', async ({ page }) => {
  const errors = await open(page, '#/home', { legacy: false, osintSample: true });
  await expect.poll(() => page.evaluate(() => DB.osintSample), { timeout: 15000 }).toBeGreaterThanOrEqual(2);   // 3 once the chats and files are in (1.91), 4 once the logs are (1.92)
  const r = await page.evaluate(() => ({ cases: DB.cases.map(c => c.id), sp: DB.entries.filter(e => e.id.startsWith('sp-')).map(e => e.caseId), bridge: DB.links.filter(l => l.caseId === 'c-lantern' && /resolved to|possibly the same person/.test(l.label)).map(l => l.a + '>' + l.b + ':' + l.conf),
    finding: DB.records.some(x => x.caseId === 'c-lantern' && x.type === 'finding' && /198\.51\.100\.23/.test(x.body) && /not proof/.test(x.body)), scope: /refund scam/.test(theCase('c-lantern').scope) }));
  expect(r.cases).toEqual(['c-lantern', 'c-story']); expect(new Set(r.sp)).toEqual(new Set(['c-lantern']));
  expect(r.bridge).toEqual(expect.arrayContaining(['sp-portal>v-ip2:3', 'v-actor>sp-jan:1'])); expect(r.finding).toBe(true); expect(r.scope).toBe(true);
  noErrors(errors);
});

test('Op Lantern also has chats, pictures and a document, read by the same importers as your own files (1.91)', async ({ page }) => {
  const errors = await open(page, '#/home', { legacy: false, osintSample: true });
  await expect.poll(() => page.evaluate(() => DB.osintSample), { timeout: 20000 }).toBe(4);
  const r = await page.evaluate(() => { const R = DB.records.filter(x => x.caseId === 'c-lantern');
    return { chats: R.filter(x => x.chatnet).map(x => x.chatnet.chat).sort(), authors: R.filter(x => x.chatAuthor).length,
      renamed: R.some(x => x.chatAuthor && x.chatAuthor.names.map(n => n.name).join() === 'n1ghtlamp,lamp'),
      files: R.filter(x => x.att && x.att.length).map(x => x.att[0].name).sort(), gps: R.flatMap(x => x.att || []).filter(a => a.gps).map(a => a.name + ' ' + a.cam),
      geo: R.filter(x => x.geo).map(x => geoOf(x).cands.find(c => c.verdict === 'confirmed').name), places: mapData('c-lantern').pts.length,
      desk: DB.links.some(l => l.a === 'sp-org' && l.b === 'sp-desk') }; });
  expect(r.chats).toEqual(['Deals Hub #refunds', 'HL desk staff', 'Harbourline Refund Desk']);
  expect(r.authors).toBe(8); expect(r.renamed).toBe(true);
  expect(r.files).toEqual(['handbook.docx', 'lind-chrome-profile.zip', 'office-pc2-security.evtx', 'pier.jpg', 'portal.png', 'shop-cloudtrail.json', 'warehouse.jpg']);
  expect(r.gps).toEqual(['pier.jpg Google Pixel 7']);
  expect(r.geo).toEqual(['Sadama street by the old port, Tallinn']); expect(r.places).toBeGreaterThanOrEqual(2); expect(r.desk).toBe(true);
  // the chat network finds the post pushed into several chats, and the file inspector reads the document's history
  await page.evaluate(() => { UI.ivView = 'chats'; go('#/case/c-lantern/infra'); });
  await expect(page.locator('#main')).toContainText('Coordinated pushes');
  await page.evaluate(() => { const x = DB.records.find(y => y.title === 'File: handbook.docx'); attAct('attKit', x.id, x.att[0].id); });
  await expect(page.locator('#main')).toContainText('Deleted text still in the file'); await expect(page.locator('#main')).toContainText('Sadama, Tallinn');
  // added once: running it again changes nothing
  const n = await page.evaluate(async () => { const before = DB.records.length; await sampleExtrasAdd(); return DB.records.length - before; }); expect(n).toBe(0);
  noErrors(errors);
});

test('Op Lantern also has a victim’s browser profile, the shop’s event log and its CloudTrail, read by the readers you use (1.92)', async ({ page }) => {
  const errors = await open(page, '#/home', { legacy: false, osintSample: true });
  await expect.poll(() => page.evaluate(() => DB.osintSample), { timeout: 20000 }).toBe(4);
  const r = await page.evaluate(() => { const R = DB.records.filter(x => x.caseId === 'c-lantern'), tag = t => R.filter(x => (x.tags || []).includes(t));
    return { profile: R.filter(x => x.source === 'browser-profile').map(x => x.title), browser: tag('browser').length, evtx: tag('evtx').length,
      rules: [...new Set(tag('sigma-match').flatMap(x => x.det.map(d => d.title)))].sort(), trail: tag('cloudtrail').map(x => x.title),
      masked: R.some(x => x.source === 'browser-profile' && !/804613/.test(x.body)) && !R.some(x => /804613/.test(x.body)),
      links: DB.links.filter(l => l.caseId === 'c-lantern' && /^sp-(ip1|ip2|portal|shop|petra)$/.test(l.a + '') || /^sp-(ip1|ip2|shop)$/.test(l.b + '')).length,
      ip: R.filter(x => (x.ents || []).some(e => e.v === '198.51.100.23')).length }; });
  expect(r.profile).toEqual(['Browser profile: p.lind@example.net']);
  expect(r.browser).toBeGreaterThan(20); expect(r.evtx).toBeGreaterThan(40);
  expect(r.rules).toEqual(expect.arrayContaining(['Password Spray From Single Source', 'RDP Logon From Public IP Address']));
  expect(r.trail).toContain('GetObject · exports/orders-4400-4800.csv · office-backup · 198.51.100.23');
  expect(r.trail.some(t => /^StopLogging \(AccessDenied\)/.test(t))).toBe(true);
  expect(r.masked).toBe(true);                      // the code her bank texted her is typed into a form, and shown masked
  expect(r.links).toBeGreaterThanOrEqual(5); expect(r.ip).toBeGreaterThan(10);   // the portal's address joins the chat, the event log and the cloud log
  // a workspace that already had 1.91's material gets only the logs, once
  const up = await page.evaluate(async () => { const ids = new Set(DB.entries.filter(e => /^sp-(ip1|ip2|portal|shop|petra)$/.test(e.id)).map(e => e.id));
    DB.records = DB.records.filter(x => !(x.tags || []).some(t => /browser|evtx|cloudtrail/.test(t)) && x.source !== 'browser-profile' && !(x.att && x.att.some(a => /lind-chrome|office-pc2|shop-cloudtrail/.test(a.name))));
    DB.entries = DB.entries.filter(e => !ids.has(e.id)); DB.links = DB.links.filter(l => !ids.has(l.a) && !ids.has(l.b)); DB.osintSample = 3;
    const chats = DB.records.filter(x => x.chatnet).length; await sampleExtrasAdd(); const once = DB.records.length; await sampleExtrasAdd();
    return { flag: DB.osintSample, chats: DB.records.filter(x => x.chatnet).length - chats, logs: DB.records.filter(x => (x.tags || []).includes('cloudtrail')).length, again: DB.records.length - once }; });
  expect(up).toEqual({ flag: 4, chats: 0, logs: 15, again: 0 });
  noErrors(errors);
});

test('the browser-profile reader opens an example profile in one click', async ({ page }) => {
  const errors = await open(page, '#/lab');
  await page.evaluate(() => { UI.labTab = 'brow'; UI.brP = null; renderMain(); });
  await page.getByRole('button', { name: 'Try an example profile' }).click();
  await expect(page.locator('#main')).toContainText('Google Chrome'); await expect(page.locator('#main')).toContainText('p.lind@example.net (Petra Lind)');
  await page.getByRole('button', { name: /Logins & forms/ }).click();
  await expect(page.locator('#main')).toContainText('harbour-line-portal.test'); await expect(page.locator('#brBody code.masked')).toHaveCount(1);
  noErrors(errors);
});

test('an older workspace gets the new sample cases once, after a restore point; old sample cases go only if nothing of yours is in them', async ({ page }) => {
  const errors = await open(page, '#/home', { legacy: false });
  const r = await page.evaluate(() => {
    const old = used => { const d = JSON.parse(JSON.stringify(DB)); const keep = x => x.caseId === 'c-lantern';
      d.cases = d.cases.filter(c => c.id === 'c-lantern'); d.records = d.records.filter(keep); d.entries = d.entries.filter(keep); d.links = d.links.filter(keep);
      d.cases.push({ id: 'c-portal', name: 'Customer portal', created: 1, updated: 2, sample: true }, { id: 'c-lab', name: 'Harbour photo', created: 1, updated: 2, sample: true }, { id: 'c-mine', name: 'My case', created: 1, updated: 2 });
      const rec = (id, c) => ({ id, caseId: c, type: 'evidence', title: id, body: 'x', tags: [], ents: [], addedBy: 'You', addedAt: 1, hash: '' });
      d.records.push(rec('p1', 'c-portal'), rec('lab1', 'c-lab'), rec('m1', 'c-mine')); if (used) d.records.push(rec('mine-in-portal', 'c-portal'));
      d.notes = [{ id: 'n5', caseId: 'c-portal', text: 'old sample note' }, { id: 'my1', caseId: 'c-mine', text: 'mine' }, { id: 'my2', caseId: null, text: 'my general note' }];
      delete d.sampleV; d.sample = true; return d; };
    const out = {}; let snaps = 0; const s0 = snapshot; snapshot = why => { snaps++; return Promise.resolve(); };
    for (const used of [false, true]) { DB = old(used); ensureSample(); const again = JSON.stringify(DB.cases); ensureSample();
      out[used ? 'used' : 'untouched'] = { cases: DB.cases.map(c => c.id).sort(), notes: DB.notes.map(n => n.id).sort(), once: JSON.stringify(DB.cases) === again, story: DB.records.filter(x => x.caseId === 'c-story').length > 10 }; }
    snapshot = s0; out.snaps = snaps; return out; });
  expect(r.untouched.cases).toEqual(['c-lantern', 'c-mine', 'c-story']);
  expect(r.untouched.notes).toEqual(['my1', 'my2', 'n1', 'n2', 'n3', 'n4', 'n6', 'n7', 'n8']);
  expect(r.used.cases).toEqual(['c-lantern', 'c-mine', 'c-portal', 'c-story']);   // your evidence in the old portal case keeps it
  expect(r.untouched.once && r.used.once).toBe(true); expect(r.untouched.story && r.used.story).toBe(true); expect(r.snaps).toBe(2);
  noErrors(errors);
});
