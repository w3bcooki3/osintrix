// Hostile files: every binary reader is fed real files from the fixtures, then the same files damaged on purpose —
// cut short, bytes flipped, length and offset fields set to huge or negative values — plus random bytes and
// decompression bombs (small files that expand to hundreds of megabytes). A reader may say a file cannot be read; it
// must not hang, crash with a programming error, or eat the tab's memory. The mutations are seeded, so a failure
// can be reproduced exactly.
const { test, expect } = require('@playwright/test');
const { open, noErrors } = require('./helpers');
const fs = require('fs'), path = require('path'), zlib = require('zlib');
test.setTimeout(600000);
const FX = p => fs.readFileSync(path.join(__dirname, 'fixtures', p)).toString('base64');

/* the ways a file enters the app, and the fixtures each is fed */
const ENTRIES = {
  lab:   ['docs/redacted-invoice.pdf', 'meta/libreoffice.pdf', 'docs/board-memo.docx', 'docs/payouts.xlsx', 'docs/remittance.msg', 'docs/parcel-notice.eml', 'docs/invoice.iso', 'docs/click-to-view.one', 'docs/scan.rar',
          'office/invoice.doc', 'office/invoice.odt', 'forensic/office365-kit.zip', 'forensic/invoice.pdf.lnk.sample', 'forensic/launcher-w32.exe', 'pics/p01.jpg', 'meta/iphone6-gps.jpg', 'meta/exif-chunk.png',
          'meta/iphone11pro.heic', 'meta/gps.mp4', 'meta/id3.mp3', 'web/shop-capture.warc.gz', 'web/shop-capture.wacz', 'web/claim-airdrop.mhtml', 'web/phish-visit.har', 'sample.pcap'],
  clean: ['clean/persona-photo.jpg', 'clean/screenshot.png', 'clean/sticker.webp', 'clean/statement.pdf', 'clean/notes.docx', 'clean/payments.xlsx'],
  evtx:  ['security-sample.evtx', 'sysmon-sample.evtx'],
  pcap:  ['sample.pcap', 'sample.pcapng', 'tls12-cert.pcap'],
};
const PROGRAMMING = /Cannot read|Cannot set|undefined|is not a function|is not iterable|of null|Maximum call stack|Invalid array length/;

test('every way a file comes in survives damaged and random files: nothing hangs, nothing crashes, a damaged part is named', async ({ page }) => {
  const errors = await open(page, '#/home');
  const report = {};
  // docs/ holds realistic lure samples (a .cmd in a RAR, an HTA in OneNote, an ISO with a shortcut) that stay on the
  // owner's machine and out of the public repository; they're fed in when present. Every other fixture must exist.
  const local = f => f.startsWith('docs/') && !fs.existsSync(path.join(__dirname, 'fixtures', f));
  const skipped = Object.values(ENTRIES).flat().filter(local);
  if (skipped.length) test.info().annotations.push({ type: 'local samples not present', description: [...new Set(skipped)].join(', ') });
  for (const [entry, files] of Object.entries(ENTRIES)) for (const file of files.filter(f => !local(f))) {
    expect(fs.existsSync(path.join(__dirname, 'fixtures', file)), file).toBe(true);
    report[file] = await page.evaluate(async ([entry, name, b64]) => {
      let s = 1234567; const rnd = () => (s = (s * 1103515245 + 12345) % 2147483648) / 2147483648, at = n => Math.floor(rnd() * n);
      const out = {calls:0, slowMs:0, slowest:'', bugs:[], broken:new Set()};
      const b = Uint8Array.from(atob(b64), c => c.charCodeAt(0)), V = [['seed', b], ['empty', new Uint8Array(0)], ['one byte', b.slice(0, 1)]];
      for(const f of [0.1, 0.5, 0.9]) V.push(['cut at ' + f, b.slice(0, Math.floor(b.length * f))]); V.push(['last byte cut', b.slice(0, b.length - 1)]);
      for(const val of [0xffffffff, 0x7fffffff, 0x80000000, 0]) for(let i = 0; i < 5; i++){ const c = b.slice(), o = at(Math.max(1, Math.min(c.length - 4, 4096))); if(c.length >= 4) new DataView(c.buffer).setUint32(o, val, true); V.push(['u32 ' + val.toString(16) + ' at ' + o, c]); }
      for(let i = 0; i < 5; i++){ const c = b.slice(), o = at(Math.max(1, c.length - 4)); if(c.length >= 4) new DataView(c.buffer).setUint32(o, 0xffffffff, true); V.push(['u32 ffffffff deep at ' + o, c]); }
      for(let i = 0; i < 5; i++){ const c = b.slice(); for(let j = 0; j < Math.max(1, c.length / 100); j++) c[at(c.length)] ^= 1 << at(8); V.push(['1% flips #' + i, c]); }
      const r = new Uint8Array(Math.min(b.length, 65536)); for(let i = 0; i < r.length; i++) r[i] = at(256); V.push(['random', r]);
      const head = b.slice(0, Math.min(64, b.length)), m = new Uint8Array(head.length + 200000).fill(0x41); m.set(head); V.push(['header then junk', m]);
      for(const [label, v] of V){ const t = performance.now(); out.calls++;
        try{
          if(entry === 'lab'){ const R = await analyseFile(new File([v], name)); if(!R || typeof R !== 'object') out.bugs.push(label + ': no result'); else for(const x of R.broken || []) out.broken.add(x + ' (' + label + ')'); }
          else if(entry === 'clean'){ const R = await clFile(new File([v], name)); if(R.err && /Cannot read|Cannot set|undefined|is not a function|is not iterable|of null|Maximum call stack|Invalid array length/.test(R.err)) out.bugs.push(label + ': shows “' + R.err + '”'); }
          else if(entry === 'evtx'){ try{ EVTX.parse(v.buffer.slice(v.byteOffset, v.byteOffset + v.byteLength)); }catch(e){ if(/Cannot read|Cannot set|undefined|is not a function|is not iterable|of null|Maximum call stack|Invalid array length/.test(e.message)) out.bugs.push(label + ': shows “' + e.message + '”'); } }
          else if(entry === 'pcap'){ try{ pcapRead(v); }catch(e){ if(/Cannot read|Cannot set|undefined|is not a function|is not iterable|of null|Maximum call stack|Invalid array length/.test(e.message)) out.bugs.push(label + ': shows “' + e.message + '”'); } }
        }catch(e){ out.bugs.push(label + ': threw ' + e.constructor.name + ': ' + e.message); }
        const ms = performance.now() - t; if(ms > out.slowMs){ out.slowMs = Math.round(ms); out.slowest = label; } }
      return {...out, broken:[...out.broken]}; }, [entry, path.basename(file), fs.readFileSync(path.join(__dirname, 'fixtures', file)).toString('base64')]);
  }
  const bad = Object.entries(report).filter(([, r]) => r.bugs.length || r.broken.length || r.slowMs > 4000);
  console.log(JSON.stringify(Object.fromEntries(bad), null, 1));
  for (const [f, r] of Object.entries(report)) {
    expect(r.bugs, f + ': escaped or programming errors').toEqual([]);
    expect(r.broken, f + ': parts that failed to read (each is a reader to make tolerant)').toEqual([]);
    expect(r.slowMs, f + ': slowest (' + r.slowest + ')').toBeLessThan(4000);
  }
  noErrors(errors);
});

test('decompression bombs are stopped: zip, gzip, a WARC inside a WACZ, and a PDF stream', async ({ page }) => {
  const errors = await open(page, '#/home');
  const zeros = Buffer.alloc(300 * 1048576);
  const raw = zlib.deflateRawSync(zeros, { level: 9 }), gz = zlib.gzipSync(zeros, { level: 9 }), fl = zlib.deflateSync(zeros, { level: 9 });
  const zipOf = entries => {   // a plain zip writer: stored names, deflated data
    const parts = [], cd = []; let off = 0;
    for (const [name, data, method, size] of entries) { const n = Buffer.from(name), h = Buffer.alloc(30); h.writeUInt32LE(0x04034b50, 0); h.writeUInt16LE(20, 4); h.writeUInt16LE(method, 8); h.writeUInt32LE(0, 14); h.writeUInt32LE(data.length, 18); h.writeUInt32LE(size, 22); h.writeUInt16LE(n.length, 26);
      parts.push(h, n, data); const c = Buffer.alloc(46); c.writeUInt32LE(0x02014b50, 0); c.writeUInt16LE(20, 4); c.writeUInt16LE(20, 6); c.writeUInt16LE(method, 10); c.writeUInt32LE(data.length, 20); c.writeUInt32LE(size, 24); c.writeUInt16LE(n.length, 28); c.writeUInt32LE(off, 42); cd.push(c, n); off += 30 + n.length + data.length; }
    const cdb = Buffer.concat(cd), e = Buffer.alloc(22); e.writeUInt32LE(0x06054b50, 0); e.writeUInt16LE(entries.length, 8); e.writeUInt16LE(entries.length, 10); e.writeUInt32LE(cdb.length, 12); e.writeUInt32LE(off, 16);
    return Buffer.concat([...parts, cdb, e]); };
  const small = s => Buffer.from(s);
  const office = zipOf([['[Content_Types].xml', small('<Types/>'), 0, 8], ['word/document.xml', raw, 8, zeros.length], ['docProps/core.xml', raw, 8, zeros.length]]);
  const wacz = zipOf([['archive/data.warc.gz', gz, 0, gz.length]]);
  const pdf = Buffer.concat([small('%PDF-1.7\n1 0 obj\n<< /Length ' + fl.length + ' /Filter /FlateDecode >>\nstream\n'), fl, small('\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n')]);
  const B = { office: office.toString('base64'), wacz: wacz.toString('base64'), gz: gz.toString('base64'), pdf: pdf.toString('base64') };
  console.log('bomb sizes KB', Object.fromEntries(Object.entries(B).map(([k, v]) => [k, Math.round(v.length * 0.75 / 1024)])));
  const r = await page.evaluate(async B => {
    const u = k => Uint8Array.from(atob(B[k]), c => c.charCodeAt(0)), heap = () => performance.memory ? performance.memory.usedJSHeapSize : 0, out = {};
    const run = async (name, f) => { const t = performance.now(), h0 = heap(); let res; try{ res = await f(); res = res == null ? 'null' : typeof res === 'object' ? 'object' : String(res).slice(0, 40); }catch(e){ res = e.constructor.name + ': ' + e.message; }
      out[name] = {ms:Math.round(performance.now() - t), mb:Math.round((heap() - h0) / 1048576), res}; };
    await run('office', () => dxOffice(u('office')));
    await run('cleanOffice', () => clOffice(u('office'), {removed:[], kept:[]}));
    await run('zipRead', async () => { const Z = zipOpen(u('office')); return Z.read('word/document.xml', 16 << 20); });
    await run('wacz', () => wcWacz(u('wacz')));
    await run('warcGz', () => wcWarc(u('gz')));
    await run('gunzip', () => wcGunzipMembers(u('gz')));
    await run('inflateAny', () => inflateAny(u('gz')));
    await run('pdf', () => dxPdf(u('pdf')));
    await run('cleanPdf', () => clPdf(u('pdf'), {removed:[], kept:[]}));
    return out; }, B);
  console.log(JSON.stringify(r, null, 1));
  for (const [name, x] of Object.entries(r)) {
    expect(x.ms, name + ' time').toBeLessThan(8000);
    expect(x.mb, name + ' memory kept (MB)').toBeLessThan(120);
    expect(x.res, name + ' result').not.toMatch(/^(TypeError|RangeError|ReferenceError)/);
  }
  noErrors(errors);
});
