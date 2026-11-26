// Vehicles, ships and aircraft: VIN, IMO number, MMSI, ICAO aircraft address and registration are found in text,
// checked and read offline, become vault entries, graph nodes and inspector facts, and ordinary text gives none.
const { test, expect } = require('@playwright/test');
const { open, noErrors } = require('./helpers');

const REPORT = `Surveillance log 14 Mar.
Subject left in a grey van, VIN 1M8GDM9AXKP042788, then a sedan with VIN: WVWZZZ1JZ3W386752.
Cargo went out on MV Nordic Star, IMO 9074729, MMSI: 636019825 (AIS on until 22:10).
The charter jet, registration N628TS, transponder hex a8 is wrong — ICAO24: a835af is right.
Second aircraft, reg. G-EUPT, Mode S 400a0f.`;

const NOISE = `Build 1M8GDM9AXKP042789 failed (not a VIN: bad check digit, no label).
imo the plan is fine. IMO 9074728 is a typo (bad check digit). Order number 636019825 without a label.
Flew a B-52 sortie? No: an F-16 and a C-130. UTF-8 and SHA-256 are not aircraft. Our jet engine is a tool.
ABCDEFGHJKLMNPRST is just letters. token 5YJ3E1EA7KF31700Z.`;

test('found in text with their checks: VIN by check digit or a label, IMO by check digit, the rest by their label', async ({ page }) => {
  const errors = await open(page, '#/home');
  const r = await page.evaluate(([a, b]) => ({
    good: E.extract(a).filter(e => /^(vin|imo|mmsi|icao24|tail)$/.test(e.k)).map(e => e.k + ':' + e.v),
    bad: E.extract(b).filter(e => /^(vin|imo|mmsi|icao24|tail)$/.test(e.k)).map(e => e.k + ':' + e.v),
    phoneFromMmsi: E.extract(a).some(e => e.k === 'phone')
  }), [REPORT, NOISE]);
  expect(r.good.sort()).toEqual(['icao24:400a0f', 'icao24:a835af', 'imo:9074729', 'mmsi:636019825', 'tail:G-EUPT', 'tail:N628TS',
    'vin:1M8GDM9AXKP042788', 'vin:WVWZZZ1JZ3W386752'].sort());
  expect(r.bad).toEqual([]);
  expect(r.phoneFromMmsi).toBe(false);
  noErrors(errors);
});

test('read offline: maker and year from a VIN, flag from an MMSI, US registration and address from each other', async ({ page }) => {
  const errors = await open(page, '#/home');
  const r = await page.evaluate(() => ({
    vin: TRANSPORT.vinInfo('WVWZZZ1JZ3W386752'), vinNA: TRANSPORT.vinInfo('1M8GDM9AXKP042788'),
    mmsi: TRANSPORT.mmsiInfo('636019825'), sart: TRANSPORT.mmsiInfo('970123456').kind, aton: TRANSPORT.mmsiInfo('992351234'),
    n2h: TRANSPORT.nToIcao('N628TS'), h2n: TRANSPORT.icaoToN(TRANSPORT.nToIcao('N628TS')), first: TRANSPORT.nToIcao('N1'), last: TRANSPORT.icaoToN('adf7c7'),
    notUS: TRANSPORT.icaoToN('400a0f'), uk: TRANSPORT.icaoCountry('400a0f'), tailUK: TRANSPORT.tailCountry('G-EUPT')
  }));
  expect(r.vin).toMatchObject({ maker: 'Volkswagen (Germany)', where: 'Germany', year: '2003', check: false });
  expect(r.vinNA).toMatchObject({ where: 'United States', year: '1989', check: true });
  expect(r.mmsi).toMatchObject({ kind: 'Ship', flag: 'Liberia', open: true });
  expect(r.sart).toMatch(/SART/); expect(r.aton).toMatchObject({ flag: 'United Kingdom' }); expect(r.aton.kind).toMatch(/Aid to navigation/);
  expect(r.n2h).toBe('a835af'); expect(r.h2n).toBe('N628TS'); expect(r.first).toBe('a00001'); expect(r.last).toBe('N99999');
  expect(r.notUS).toBe(null); expect(r.uk).toBe('United Kingdom'); expect(r.tailUK).toBe('United Kingdom');
  noErrors(errors);
});

test('a record mentioning them gives graph nodes and vault entries; the inspector shows what each one says', async ({ page }) => {
  const errors = await open(page, '#/home');
  await page.evaluate(text => {
    DB.cases.push(Object.assign({}, DB.cases[0], { id: 'tx', name: 'Transport' })); DB.active = 'tx';
    DB.records.push({ id: uid('r'), caseId: 'tx', type: 'evidence', title: 'Surveillance log', body: text, tsRaw: '', tsZone: 'explicit', ts: Date.now(), source: '', host: '', tags: [], ents: E.extract(text), answer: '', addedBy: 'You', addedAt: Date.now(), hash: '' });
    mutate('t');
  }, REPORT);
  // every one can go on the graph as a vault entry of the right type, keyed so it joins the record's value
  const made = await page.evaluate(() => {
    const keys = ['vin:1M8GDM9AXKP042788', 'imo:9074729', 'mmsi:636019825', 'icao24:a835af', 'tail:N628TS'];
    return keys.map(k => { const f = entryFor(k); const e = { id: 'x', caseId: 'tx', type: f.type, fields: f.fields }; return [k, f.type, entryKey(e), primary(e)]; });
  });
  expect(made).toEqual([
    ['vin:1M8GDM9AXKP042788', 'vehicle', 'vin:1M8GDM9AXKP042788', '1M8GDM9AXKP042788'],
    ['imo:9074729', 'vessel', 'imo:9074729', '9074729'],
    ['mmsi:636019825', 'vessel', 'mmsi:636019825', '636019825'],
    ['icao24:a835af', 'aircraft', 'icao24:a835af', 'a835af'],
    ['tail:N628TS', 'aircraft', 'tail:N628TS', 'N628TS']]);
  // a vault entry typed by hand in lower case keys the same as the record's value
  expect(await page.evaluate(() => entryKey({ type: 'aircraft', fields: { registration: 'g-eupt' } }))).toBe('tail:G-EUPT');
  expect(await page.evaluate(() => entryKey({ type: 'vehicle', fields: { vin: ' 1m8gdm9axkp042788 ' } }))).toBe('vin:1M8GDM9AXKP042788');

  // build the graph from the evidence: the five kinds are offered and drawn
  await page.evaluate(() => go(caseHash('tx', 'graph')));
  await page.click('[data-act=gBuild]');
  await page.click('[data-act=bgGo]');
  await expect.poll(() => page.evaluate(() => cy ? cy.nodes().map(n => entryKey(entryById(n.id()))).filter(k => /^(vin|imo|mmsi|icao24|tail):/.test(k)).length : 0)).toBe(8);

  // the inspector reads them
  const facts = async key => { await page.evaluate(k => select('ent', k), key); return page.locator('#insp').innerText(); };
  let t = await facts('vin:WVWZZZ1JZ3W386752');
  expect(t).toContain('Volkswagen'); expect(t).toContain('2003'); expect(t).toContain('No check digit');
  t = await facts('mmsi:636019825'); expect(t).toContain('Liberia'); expect(t).toContain('Open-registry flag');
  t = await facts('tail:N628TS'); expect(t).toContain('a835af'); expect(t).toContain('FAA registry');
  t = await facts('icao24:400a0f'); expect(t).toContain('United Kingdom');
  noErrors(errors);
});

test('the vault form takes a ship by IMO number or MMSI and an aircraft by registration or address, and checks each', async ({ page }) => {
  const errors = await open(page, '#/home');
  await page.evaluate(() => entryDlg(null, { type: 'aircraft' }));
  await page.click('#dlg button.primary');                                       // neither given
  await expect(page.locator('#dlg')).toContainText('Give the registration or the ICAO address.');
  await page.fill('#ef-icao24', 'a835ag');
  await page.click('#dlg button.primary');
  await expect(page.locator('#dlg')).toContainText('6 hex characters');
  await page.fill('#ef-icao24', 'A835AF');
  await page.click('#dlg button.primary');
  await expect(page.locator('#dlg form')).toHaveCount(0);
  const e = await page.evaluate(() => { const x = DB.entries[DB.entries.length - 1]; return { type: x.type, key: entryKey(x), name: primary(x) }; });
  expect(e).toEqual({ type: 'aircraft', key: 'icao24:a835af', name: 'A835AF' });

  await page.evaluate(() => entryDlg(null, { type: 'vessel' }));
  await page.fill('#ef-imo', '9074728');
  await page.click('#dlg button.primary');
  await expect(page.locator('#dlg')).toContainText('last digit checks the rest');
  await page.fill('#ef-imo', '9074729'); await page.fill('#ef-name', 'Nordic Star');
  await page.click('#dlg button.primary');
  await expect(page.locator('#dlg form')).toHaveCount(0);
  expect(await page.evaluate(() => entryKey(DB.entries[DB.entries.length - 1]))).toBe('imo:9074729');
  noErrors(errors);
});
