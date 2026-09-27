/* ==========================================================================
   Forensics kit engines — all local, all in the browser.
   File structure parsers (ZIP/Office, PDF, PE, ELF), a YARA subset, a Sigma
   subset tester, email header analysis, ID/timestamp decoders, image tools
   (channels, bit planes, LSB, QR), network helpers and generators.
   ========================================================================== */

/* ---------- indicator quality for binary files ---------- */
const CCTLD = new Set('ac ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bm bn bo br bs bt bw by bz ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg er es et eu fi fj fk fm fo fr ga gb gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in io iq ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sk sl sm sn so sr ss st su sv sx sy sz tc td tf tg th tj tk tl tm tn to tr tt tv tw tz ua ug uk us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw'.split(' '));
const COMMON_TLD = new Set('com net org info biz edu gov mil int io co ai app dev xyz top site online store shop tech cloud live news blog club onion example test local email world today link zip mov icu buzz me tv cc ru cn uk de fr nl jp br in au ca us eu'.split(' '));
function goodDomain(d){ const p = d.toLowerCase().split('.'); if(p.length < 2) return false; const tld = p[p.length - 1], sld = p[p.length - 2];
  return (COMMON_TLD.has(tld) || CCTLD.has(tld)) && sld.length >= 3 && /[a-z]{3}/.test(sld) && !/(.)\1{3}/.test(d) && d.length >= 6; }
function fileIocOK(e){
  if(e.k === 'handle' || e.k === 'eventid' || e.k === 'account' || e.k === 'sid' || e.k === 'custom') return false;
  if(e.k === 'domain') return goodDomain(e.v);
  if(e.k === 'email'){ const [l, d] = e.v.split('@'); return l && l.length >= 2 && goodDomain(d || ''); }
  if(e.k === 'url'){ const h = hostOf(e.v); return !!h && (/^\d+\.\d+\.\d+\.\d+$/.test(h) || goodDomain(h)); }
  if(e.k === 'ipv4') return !/^(\d+)\.\1\.\1\.\1$/.test(e.v) && !/^0\./.test(e.v);
  return true;
}
/* a string that looks like language or code, not compressed bytes */
const wordy = s => /[A-Za-z]{4,}/.test(s) && (s.replace(/[A-Za-z0-9 ._\-:/\\@=,()'"]/g, '').length / s.length) < .2;

/* ---------- byte helpers ---------- */
const u16le = (b, o) => b[o] | (b[o + 1] << 8), u32le = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
const u16be = (b, o) => (b[o] << 8) | b[o + 1], u32be = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
const latin1 = (b, s = 0, e = b.length) => { let out = ''; for(let i = s; i < e; i += 8192) out += String.fromCharCode.apply(null, b.subarray(i, Math.min(e, i + 8192))); return out; };
async function inflateRaw(bytes){ return new Uint8Array(await new Response(new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw'))).arrayBuffer()); }
function entropyOf(b){ if(!b.length) return 0; const f = new Array(256).fill(0); for(const x of b) f[x]++; let e = 0; for(const c of f) if(c){ const p = c / b.length; e -= p * Math.log2(p); } return e; }

/* regions of compressed image data — strings found there are noise */
function noiseRanges(b, ext){
  const r = [];
  if(ext === 'png'){ let o = 8; while(o + 8 <= b.length){ const len = u32be(b, o), t = latin1(b, o + 4, o + 8); if(t === 'IDAT') r.push([o + 8, o + 8 + len]); if(t === 'IEND') break; o += 12 + len; } }
  if(ext === 'jpg'){ let o = 2; while(o < b.length - 4){ if(b[o] !== 0xff){ o++; continue; } const m = b[o + 1]; if(m === 0xda){ let e = b.length; for(let i = b.length - 2; i > o; i--) if(b[i] === 0xff && b[i + 1] === 0xd9){ e = i; break; } r.push([o, e]); break; } if(m === 0xd8 || (m >= 0xd0 && m <= 0xd7)){ o += 2; continue; } o += 2 + u16be(b, o + 2); } }
  if(ext === 'gif' || ext === 'mp3' || ext === 'mp4' || ext === 'mkv') r.push([64, b.length]);
  return r;
}

/* ---------- ZIP / Office ---------- */
async function zipInfo(b){
  let eocd = -1; for(let i = b.length - 22; i >= Math.max(0, b.length - 70000); i--) if(u32le(b, i) === 0x06054b50){ eocd = i; break; }
  if(eocd < 0) return null;
  const n = u16le(b, eocd + 10), cdOff = u32le(b, eocd + 16), clen = u16le(b, eocd + 20), comment = latin1(b, eocd + 22, eocd + 22 + clen);
  const files = []; let o = cdOff;
  for(let i = 0; i < n && o + 46 <= b.length && files.length < 3000; i++){
    if(u32le(b, o) !== 0x02014b50) break;
    const flag = u16le(b, o + 8), method = u16le(b, o + 10), dt = u16le(b, o + 12), dd = u16le(b, o + 14), csize = u32le(b, o + 20), size = u32le(b, o + 24), fl = u16le(b, o + 28), xl = u16le(b, o + 30), cl = u16le(b, o + 32), lho = u32le(b, o + 42);
    const name = new TextDecoder().decode(b.subarray(o + 46, o + 46 + fl));
    files.push({name, size, csize, method, enc:!!(flag & 1), date:Date.UTC(((dd >> 9) & 127) + 1980, ((dd >> 5) & 15) - 1, dd & 31, dt >> 11, (dt >> 5) & 63, (dt & 31) * 2), lho});
    o += 46 + fl + xl + cl;
  }
  const read = async name => { const f = files.find(x => x.name === name); if(!f || f.enc) return null; const lh = f.lho; if(u32le(b, lh) !== 0x04034b50) return null;
    const start = lh + 30 + u16le(b, lh + 26) + u16le(b, lh + 28), data = b.subarray(start, start + f.csize);
    try{ return new TextDecoder().decode(f.method === 0 ? data : await inflateRaw(data)); }catch(e){ return null; } };
  const out = {files, comment, encrypted:files.some(f => f.enc)};
  const isOffice = files.some(f => f.name === '[Content_Types].xml');
  if(isOffice){
    const core = await read('docProps/core.xml') || '', app = await read('docProps/app.xml') || '';
    const tag = (x, t) => { const m = x.match(new RegExp('<(?:\\w+:)?' + t + '[^>]*>([^<]*)<')); return m ? m[1] : ''; };
    out.office = {Title:tag(core, 'title'), Subject:tag(core, 'subject'), Author:tag(core, 'creator'), 'Last modified by':tag(core, 'lastModifiedBy'), Created:tag(core, 'created'), Modified:tag(core, 'modified'),
      Printed:tag(core, 'lastPrinted'), Revision:tag(core, 'revision'), Application:tag(app, 'Application') + (tag(app, 'AppVersion') ? ' ' + tag(app, 'AppVersion') : ''), Company:tag(app, 'Company'), Template:tag(app, 'Template'), 'Edit minutes':tag(app, 'TotalTime')};
    out.macros = files.filter(f => /vbaProject\.bin$|\.bas$|macrosheets\//i.test(f.name)).map(f => f.name);
    out.ole = files.filter(f => /oleObject|activeX|embeddings\//i.test(f.name)).map(f => f.name);
    const ext = [];
    for(const f of files.filter(x => /_rels\/.*\.rels$/.test(x.name)).slice(0, 40)){ const x = await read(f.name) || ''; for(const m of x.matchAll(/Target="([^"]+)"[^>]*TargetMode="External"/g)) ext.push([f.name, m[1].replace(/&amp;/g, '&')]); }
    out.external = ext;
  }
  return out;
}
/* ---------- PDF (pdfid-style) ---------- */
function pdfInfo(b){
  const s = latin1(b, 0, Math.min(b.length, 30e6)), count = re => (s.match(re) || []).length;
  const info = {};
  for(const k of ['Title','Author','Subject','Keywords','Creator','Producer','CreationDate','ModDate']){ const m = s.match(new RegExp('/' + k + '\\s*\\(((?:\\\\.|[^\\\\)])*)\\)')) || s.match(new RegExp('/' + k + '\\s*<([0-9A-Fa-f]+)>'));
    if(m){ let v = m[1]; if(/^[0-9A-Fa-f]+$/.test(v) && v.length % 2 === 0 && m[0].includes('<')){ const bytes = v.match(/../g).map(h => parseInt(h, 16)); v = bytes[0] === 0xfe ? new TextDecoder('utf-16be').decode(new Uint8Array(bytes.slice(2))) : String.fromCharCode(...bytes); }
      v = v.replace(/\\\(/g, '(').replace(/\\\)/g, ')'); if(v.charCodeAt(0) === 0xfe && v.charCodeAt(1) === 0xff) v = new TextDecoder('utf-16be').decode(new Uint8Array([...v.slice(2)].map(c => c.charCodeAt(0))));
      const dm = v.match(/^D:(\d{4})(\d{2})?(\d{2})?(\d{2})?(\d{2})?(\d{2})?/); if(dm) v = `${dm[1]}-${dm[2] || '01'}-${dm[3] || '01'} ${dm[4] || '00'}:${dm[5] || '00'}:${dm[6] || '00'}` + v.slice(dm[0].length).replace(/'/g, '');
      info[k] = v.slice(0, 200); } }
  const xmp = s.match(/<x:xmpmeta[\s\S]{0,20000}?<\/x:xmpmeta>/); if(xmp){ const t = (n) => { const m = xmp[0].match(new RegExp('<' + n + '>(?:<rdf:\\w+>\\s*<rdf:li[^>]*>)?([^<]+)')); return m ? m[1].trim() : ''; };
    for(const [k, n] of [['XMP creator tool','xmp:CreatorTool'],['XMP created','xmp:CreateDate'],['XMP author','dc:creator'],['Document ID','xmpMM:DocumentID']]){ const v = t(n); if(v) info[k] = v.slice(0, 200); } }
  const keys = {'/Page':count(/\/Type\s*\/Page\b/g), '/JS':count(/\/JS\b/g), '/JavaScript':count(/\/JavaScript\b/g), '/OpenAction':count(/\/OpenAction\b/g), '/AA':count(/\/AA\b/g), '/Launch':count(/\/Launch\b/g),
    '/EmbeddedFile':count(/\/EmbeddedFile\b/g), '/URI':count(/\/URI\b/g), '/AcroForm':count(/\/AcroForm\b/g), '/XFA':count(/\/XFA\b/g), '/ObjStm':count(/\/ObjStm\b/g), '/Encrypt':count(/\/Encrypt\b/g), 'obj':count(/\bobj\b/g), 'stream':count(/\bstream\b/g)};
  const uris = [...new Set([...s.matchAll(/\/URI\s*\(([^)]{4,400})\)/g)].map(m => m[1]))].slice(0, 50);
  const version = (s.match(/%PDF-(\d\.\d)/) || [])[1] || '', eofs = count(/%%EOF/g);
  return {info, keys, uris, version, updates:Math.max(0, eofs - 1)};
}
/* ---------- PE / ELF ---------- */
const PE_MACHINE = {0x14c:'x86 (i386)', 0x8664:'x64 (AMD64)', 0x1c0:'ARM', 0xaa64:'ARM64', 0x200:'IA-64'};
const PE_SUBSYS = {1:'Native', 2:'Windows GUI', 3:'Windows console', 9:'Windows CE', 10:'EFI application', 14:'Xbox'};
function peInfo(b){
  if(!(b[0] === 0x4d && b[1] === 0x5a)) return null; const pe = u32le(b, 0x3c); if(pe + 24 > b.length || u32le(b, pe) !== 0x4550) return null;
  const mach = u16le(b, pe + 4), nsec = u16le(b, pe + 6), ts = u32le(b, pe + 8), osz = u16le(b, pe + 20), ch = u16le(b, pe + 22), op = pe + 24, magic = u16le(b, op), pe64 = magic === 0x20b;
  const sub = u16le(b, op + 68), ep = u32le(b, op + 16), dd = op + (pe64 ? 112 : 96), impRVA = u32le(b, dd + 8), secT = op + osz;
  const secs = []; for(let i = 0; i < nsec && i < 96; i++){ const s = secT + i * 40; const name = latin1(b, s, s + 8).replace(/\0+$/, ''), vs = u32le(b, s + 8), va = u32le(b, s + 12), rs = u32le(b, s + 16), rp = u32le(b, s + 20);
    secs.push({name, vs, va, rs, rp, ent:entropyOf(b.subarray(rp, Math.min(b.length, rp + rs)))}); }
  const r2o = rva => { const s = secs.find(x => rva >= x.va && rva < x.va + Math.max(x.vs, x.rs)); return s ? rva - s.va + s.rp : -1; };
  const cstr = o => { let e = o; while(e < b.length && b[e] && e - o < 256) e++; return latin1(b, o, e); };
  const imports = []; let io = r2o(impRVA);
  if(impRVA && io > 0) for(let i = 0; i < 400; i++){ const d = io + i * 20; if(d + 20 > b.length) break; const nameRVA = u32le(b, d + 12), thunk = u32le(b, d) || u32le(b, d + 16); if(!nameRVA) break;
    const dll = cstr(r2o(nameRVA)), fns = []; let to = r2o(thunk);
    if(to > 0) for(let k = 0; k < 600; k++){ const lo = u32le(b, to), hi = pe64 ? u32le(b, to + 4) : 0; if(!lo && !hi) break; const ord = pe64 ? (hi & 0x80000000) : (lo & 0x80000000); if(!ord){ const hn = r2o(lo); if(hn > 0) fns.push(cstr(hn + 2)); } else fns.push('#' + (lo & 0xffff)); to += pe64 ? 8 : 4; }
    imports.push({dll, fns}); }
  const SUS = /^(VirtualAlloc(Ex)?|WriteProcessMemory|CreateRemoteThread|NtUnmapViewOfSection|SetWindowsHookEx|GetAsyncKeyState|IsDebuggerPresent|URLDownloadToFile|WinExec|ShellExecute|InternetOpen|CryptEncrypt|OpenProcess|LoadLibrary|GetProcAddress|AdjustTokenPrivileges|RegSetValueEx|CreateService)/;
  const suspicious = [...new Set(imports.flatMap(x => x.fns).filter(f => SUS.test(f)))];
  const packers = secs.map(s => s.name).filter(n => /UPX|aspack|\.petite|MPRESS|\.themida|\.vmp|nsp[0-9]|\.packed/i.test(n));
  return {machine:PE_MACHINE[mach] || '0x' + mach.toString(16), kind:(ch & 0x2000 ? 'DLL' : 'Executable') + (pe64 ? ' · PE32+ (64-bit)' : ' · PE32 (32-bit)'), compiled:ts ? new Date(ts * 1000).toISOString().replace('T', ' ').slice(0, 19) + ' UTC' : '—',
    subsystem:PE_SUBSYS[sub] || sub, entry:'0x' + ep.toString(16), secs, imports, suspicious, packers};
}
function elfInfo(b){
  if(!(b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46)) return null; const is64 = b[4] === 2, le = b[5] === 1, u16 = o => le ? u16le(b, o) : u16be(b, o);
  const T = {1:'Relocatable', 2:'Executable', 3:'Shared object / PIE', 4:'Core dump'}, M = {3:'x86', 62:'x86-64', 40:'ARM', 183:'AArch64', 8:'MIPS', 20:'PowerPC', 243:'RISC-V'};
  const s = latin1(b, 0, Math.min(b.length, 4096)), interp = (s.match(/\/lib[\w/.-]*ld[\w.-]*\.so[\w.]*/) || [])[0] || '';
  return {cls:is64 ? '64-bit' : '32-bit', endian:le ? 'little-endian' : 'big-endian', type:T[u16(16)] || u16(16), machine:M[u16(18)] || u16(18), interp};
}

/* ---------- YARA (subset) ---------- */
function yaraParse(src){
  const rules = [], txt = String(src).replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:"\\])\/\/[^\n]*/g, '$1');
  const heads = [...txt.matchAll(/(?:(?:private|global)\s+)*rule\s+(\w+)(?:\s*:\s*([\w ]+?))?\s*\{/g)];
  heads.forEach((h, k) => { const start = h.index + h[0].length, end = k + 1 < heads.length ? heads[k + 1].index : txt.length; let body = txt.slice(start, end); body = body.slice(0, body.lastIndexOf('}'));
    const sec = n => { const x = body.match(new RegExp('\\b' + n + '\\s*:([\\s\\S]*?)(?=\\b(?:meta|strings|condition)\\s*:|$)')); return x ? x[1] : ''; };
    const strings = []; for(const part of sec('strings').split(/(?=\$\w*\s*=)/)){ const l = part.trim(); const sm = l.match(/^(\$\w*)\s*=\s*([\s\S]+)$/); if(!sm) continue; const [, name, def0] = sm, def = def0.trim();
      let kind, val, mods = '';
      if(def.startsWith('"')){ const q = def.match(/^"((?:\\.|[^"\\])*)"\s*([\s\S]*)$/); if(!q) continue; kind = 'text'; val = q[1].replace(/\\x([0-9a-fA-F]{2})/g, (_, x) => String.fromCharCode(parseInt(x, 16))).replace(/\\n/g, '\n').replace(/\\t/g, '\t').replace(/\\r/g, '\r').replace(/\\(["\\])/g, '$1'); mods = q[2]; }
      else if(def.startsWith('{')){ const q = def.match(/^\{([^}]*)\}\s*([\s\S]*)$/); if(!q) continue; kind = 'hex'; val = q[1]; mods = q[2]; }
      else if(def.startsWith('/')){ const q = def.match(/^\/((?:\\.|[^\/\\])*)\/([is]*)\s*([\s\S]*)$/); if(!q) continue; kind = 're'; val = q[1]; mods = q[2] + ' ' + q[3]; }
      else continue;
      strings.push({name, kind, val, mods:mods.toLowerCase().replace(/\s+/g, ' ')}); }
    rules.push({name:h[1], tags:(h[2] || '').trim(), strings, cond:sec('condition').trim().replace(/\s+/g, ' '), meta:sec('meta')}); });
  return rules;
}
function hexToRe(h){
  const t = h.replace(/\s+/g, ' ').trim(); let out = '', i = 0;
  while(i < t.length){ const c = t[i];
    if(c === ' '){ i++; continue; }
    if(c === '['){ const e = t.indexOf(']', i), r = t.slice(i + 1, e).split('-'); out += `[\\s\\S]{${r[0] || 0},${r.length > 1 ? (r[1] || '') : r[0]}}`; i = e + 1; continue; }
    if(c === '(' || c === ')' || c === '|'){ out += c === '(' ? '(?:' : c; i++; continue; }
    const pair = t.slice(i, i + 2); i += 2;
    if(pair === '??') out += '[\\s\\S]';
    else if(pair[0] === '?') out += '[' + Array.from({length:16}, (_, k) => '\\x' + (k * 16 + parseInt(pair[1], 16)).toString(16).padStart(2, '0')).join('') + ']';
    else if(pair[1] === '?'){ const hi = parseInt(pair[0], 16) * 16; out += '[\\x' + hi.toString(16).padStart(2, '0') + '-\\x' + (hi + 15).toString(16).padStart(2, '0') + ']'; }
    else out += '\\x' + pair.toLowerCase(); }
  return out;
}
function yaraMatchStrings(rule, hay, hayLower){
  const res = {};
  for(const s of rule.strings){ const hits = [];
    try{
      if(s.kind === 'text'){ const nocase = /\bnocase\b/.test(s.mods), wide = /\bwide\b/.test(s.mods), ascii = /\bascii\b/.test(s.mods) || !wide;
        const vars = []; if(ascii) vars.push(s.val); if(wide) vars.push([...s.val].map(c => c + '\0').join(''));
        for(let v of vars){ const H = nocase ? hayLower : hay; if(nocase) v = v.toLowerCase(); if(!v) continue; let p = H.indexOf(v); while(p >= 0 && hits.length < 200){ hits.push(p); p = H.indexOf(v, p + 1); } } }
      else { const re = new RegExp(s.kind === 'hex' ? hexToRe(s.val) : s.val, 'g' + (s.kind === 're' && /i/.test(s.mods.split(' ')[0]) ? 'i' : '') + (s.kind === 're' && /s/.test(s.mods.split(' ')[0]) ? 's' : ''));
        let mm; while((mm = re.exec(hay)) && hits.length < 200){ hits.push(mm.index); if(mm[0] === '') re.lastIndex++; } }
    }catch(e){ res[s.name] = {hits:[], err:e.message}; continue; }
    res[s.name] = {hits}; }
  return res;
}
function yaraEval(rule, S, bytes){
  const toks = rule.cond.match(/\$\w*\*?|#\w+|@\w+(?:\[\d+\])?|0x[0-9a-f]+|\d+(?:KB|MB)?|\.\.|[A-Za-z_][\w.]*|==|!=|<=|>=|[<>()\[\],]|"[^"]*"/gi) || []; let i = 0;
  const peek = () => toks[i], next = () => toks[i++], unsup = w => { throw new Error('Not supported in the browser engine: ' + w); };
  const names = pat => Object.keys(S).filter(n => pat === 'them' ? true : pat.endsWith('*') ? n.startsWith(pat.slice(0, -1)) : n === pat);
  const num = t => /KB$/i.test(t) ? parseInt(t) * 1024 : /MB$/i.test(t) ? parseInt(t) * 1048576 : t.startsWith('0x') ? parseInt(t, 16) : +t;
  const readU = (w, o, be) => { if(o + w > bytes.length) return NaN; let v = 0; for(let k = 0; k < w; k++) v += bytes[o + k] * 2 ** (8 * (be ? w - 1 - k : k)); return v; };
  function value(){ const t = next(); if(t === undefined) unsup('end of condition');
    if(t === '(') { const v = expr(); next(); return v; }
    if(/^#/.test(t)) return (S['$' + t.slice(1)] || {hits:[]}).hits.length;
    if(/^filesize$/i.test(t)) return bytes.length;
    const um = t.match(/^(u?int)(8|16|32)(be)?$/i); if(um){ next(); const o = expr(); next(); return readU(+um[2] / 8, o, !!um[3]); }
    if(/^(0x[0-9a-f]+|\d+(KB|MB)?)$/i.test(t)) return num(t);
    if(t === 'true') return true; if(t === 'false') return false;
    return unsup(t); }
  function atom(){ const t = peek();
    if(t === 'not'){ next(); return !atom(); }
    if(t === '('){ next(); const v = expr(); next(); return cmp(v); }
    if(/^(any|all|none|\d+)$/i.test(t) && toks[i + 1] === 'of'){ next(); next(); let set;
      if(peek() === 'them'){ next(); set = names('them'); } else if(peek() === '('){ next(); set = []; while(peek() && peek() !== ')'){ const n = next(); if(n !== ',') set.push(...names(n)); } next(); } else unsup('of ' + peek());
      const hit = set.filter(n => S[n].hits.length).length; return t === 'any' ? hit > 0 : t === 'all' ? hit === set.length && set.length > 0 : t === 'none' ? hit === 0 : hit >= +t; }
    if(/^\$/.test(t)){ next(); const s = S[t]; if(!s) unsup(t); if(peek() === 'at'){ next(); const o = value(); return s.hits.includes(o); } if(peek() === 'in'){ next(); next(); const a = expr(); next(); const b2 = expr(); next(); return s.hits.some(h => h >= a && h <= b2); } return s.hits.length > 0; }
    if(/^(for|pe|elf|math|hash|cuckoo|magic|dotnet)\b/i.test(t)) unsup(t);
    return cmp(value()); }
  function cmp(v){ const o = peek(); if(['==','!=','<','>','<=','>='].includes(o)){ next(); const w = value(); return o === '==' ? v === w : o === '!=' ? v !== w : o === '<' ? v < w : o === '>' ? v > w : o === '<=' ? v <= w : v >= w; } return v; }
  function and(){ let v = atom(); while(peek() === 'and'){ next(); const w = atom(); v = v && w; } return v; }
  function expr(){ let v = and(); while(peek() === 'or'){ next(); const w = and(); v = v || w; } return v; }
  const r = expr(); if(i < toks.length) unsup(toks[i]); return !!r;
}
function yaraScan(src, bytes){
  const hay = latin1(bytes), low = hay.toLowerCase(), out = [];
  for(const rule of yaraParse(src)){ try{ const S = yaraMatchStrings(rule, hay, low); out.push({rule:rule.name, match:yaraEval(rule, S, bytes), strings:S}); }catch(e){ out.push({rule:rule.name, error:e.message}); } }
  return out;
}

/* ---------- Sigma (subset) against case evidence ---------- */
function sigmaParse(code){
  const lines = String(code).replace(/\t/g, '    ').split('\n'); const det = {}; let inDet = false, detIndent = 0, selIndent = -1, cur = null, curField = null, cond = '';
  const ind = l => l.match(/^ */)[0].length, unq = v => v.trim().replace(/^['"]|['"]$/g, '').replace(/\\\\/g, '\\');
  for(const raw of lines){ if(!raw.trim() || /^\s*#/.test(raw)) continue; const n = ind(raw), l = raw.trim();
    if(/^detection\s*:/.test(l) && n === 0){ inDet = true; detIndent = n; continue; }
    if(!inDet) continue; if(n <= detIndent){ inDet = false; continue; }
    if(/^condition\s*:/.test(l)){ cond = l.replace(/^condition\s*:\s*/, '').replace(/^['"]|['"]$/g, ''); cur = null; continue; }
    if(/^timeframe\s*:/.test(l)) continue;
    const km = l.match(/^([\w.|*-]+)\s*:\s*(.*)$/);
    if(km && selIndent < 0 && !l.startsWith('-')) selIndent = n;
    if(km && n <= selIndent && !l.startsWith('-')){ cur = det[km[1]] = {fields:[], keywords:[]}; curField = null; if(km[2]) cur.keywords.push(unq(km[2])); continue; }
    if(!cur) continue;
    if(l.startsWith('- ') && curField === null){ const v = l.slice(2); const fm = v.match(/^([\w.|*-]+)\s*:\s*(.*)$/); if(fm){ curField = {f:fm[1], vals:fm[2] ? [unq(fm[2])] : []}; cur.fields.push(curField); } else cur.keywords.push(unq(v)); continue; }
    if(l.startsWith('- ') && curField){ curField.vals.push(unq(l.slice(2))); continue; }
    if(km){ curField = {f:km[1], vals:km[2] && km[2] !== '' ? (km[2].startsWith('[') ? km[2].slice(1, -1).split(',').map(unq) : [unq(km[2])]) : []}; cur.fields.push(curField); continue; }
  }
  return {det, cond};
}
function recFields(r){
  const f = {_raw:(r.title + ' ' + r.body).toLowerCase()}; const s = r.body || '';
  for(const m of s.matchAll(/(\w+)=("([^"]*)"|'([^']*)'|(\S+))/g)) f[m[1].toLowerCase()] = (m[3] ?? m[4] ?? m[5] ?? '').toLowerCase();
  const ev = s.match(/EventID[:= ]\s*(\d+)/i); if(ev) f.eventid = ev[1];
  if(r.host) f.computer = r.host.toLowerCase(); f.source = (r.source || '').toLowerCase();
  const P = typeof parseLog === 'function' ? parseLog(r.body) : null;
  if(P){ for(const [k, v] of Object.entries(P.fields)){ const key = k.toLowerCase().replace(/^.*\./, ''); if(f[key] == null) f[key] = String(v).toLowerCase(); }
    const SIG = {'src.ip':'sourceip', 'src.port':'sourceport', 'dst.ip':'destinationip', 'dst.port':'destinationport', user:'user', process:'image', cmd:'commandline', parent:'parentimage', domain:'queryname', url:'url', 'event.id':'eventid', host:'computer', method:'cs-method', status:'sc-status', ua:'c-useragent', file:'targetfilename', hash:'hashes', proto:'protocol', action:'action'};
    for(const [c, sg] of Object.entries(SIG)) if(P.norm[c] != null && f[sg] == null) f[sg] = String(P.norm[c]).toLowerCase(); }
  const alias = {commandline:['cmdline','command'], image:['process','newprocessname'], targetfilename:['filename','file'], destinationip:['dst','dest_ip'], destinationhostname:['queryname','dns'], queryname:['destinationhostname']};
  for(const [k, as] of Object.entries(alias)) if(!f[k]) for(const a of as) if(f[a]){ f[k] = f[a]; break; }
  return f;
}
const sigWild = v => new RegExp('^' + v.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$', 'i');
function sigmaSel(sel, f){
  if(!sel.fields.length && !sel.keywords.length) return false;
  if(sel.keywords.length && !sel.fields.length) return sel.keywords.some(k => f._raw.includes(k.toLowerCase().replace(/\*/g, '')));
  return sel.fields.every(({f:key, vals}) => { const [name, ...mods] = key.split('|'), v = f[name.toLowerCase()];
    if(v === undefined) return mods.includes('contains') ? vals.some(x => f._raw.includes(x.toLowerCase())) && false : false;
    const test = x => { x = String(x).toLowerCase(); if(mods.includes('re')) return new RegExp(x, 'i').test(v); if(mods.includes('contains')) return v.includes(x.replace(/\*/g, '')); if(mods.includes('startswith')) return v.startsWith(x); if(mods.includes('endswith')) return v.endsWith(x); return /[*?]/.test(x) ? sigWild(x).test(v) : v === x; };
    return mods.includes('all') ? vals.every(test) : vals.some(test); });
}
function sigmaEval(parsed, f){
  const toks = parsed.cond.match(/\(|\)|\band\b|\bor\b|\bnot\b|\b(?:1|all|any)\s+of\s+[\w*]+|[\w*]+/gi) || []; let i = 0;
  const sel = n => { const s = parsed.det[n]; if(!s) throw new Error('Unknown selection ' + n); return sigmaSel(s, f); };
  const group = t => { const m = t.match(/^(1|all|any)\s+of\s+([\w*]+)$/i); const pat = m[2], ks = Object.keys(parsed.det).filter(k => pat === 'them' ? true : pat.endsWith('*') ? k.startsWith(pat.slice(0, -1)) : k === pat); return m[1].toLowerCase() === 'all' ? ks.every(sel) : ks.some(sel); };
  const atom = () => { const t = toks[i++]; if(t === '(') { const v = or(); i++; return v; } if(/^not$/i.test(t)) return !atom(); if(/\sof\s/i.test(t)) return group(t); return sel(t); };
  const and = () => { let v = atom(); while(/^and$/i.test(toks[i] || '')){ i++; const w = atom(); v = v && w; } return v; };
  const or = () => { let v = and(); while(/^or$/i.test(toks[i] || '')){ i++; const w = and(); v = v || w; } return v; };
  return or();
}
function testRule(r, caseId){
  const recs = DB.records.filter(x => x.caseId === caseId && x.type !== 'lead');
  if(r.type === 'sigma'){ const p = sigmaParse(r.code); if(!p.cond || !Object.keys(p.det).length) return {error:'Could not read the detection block.'};
    try{ return {hits:recs.filter(x => sigmaEval(p, recFields(x))), total:recs.length}; }catch(e){ return {error:e.message}; } }
  const hits = []; let err = '';
  for(const x of recs){ const b = new TextEncoder().encode(x.title + '\n' + x.body); const res = yaraScan(r.code, b); if(res.some(z => z.error)){ err = res.find(z => z.error).error; break; } if(res.some(z => z.match)) hits.push(x); }
  return err ? {error:err} : {hits, total:recs.length};
}

/* ---------- email headers ---------- */
function parseHeaders(raw){
  const lines = String(raw).replace(/\r/g, '').split('\n'), H = []; let body = false;
  for(const l of lines){ if(body) break; if(!l.trim()){ if(H.length) body = true; continue; } if(/^[ \t]/.test(l) && H.length) H[H.length - 1][1] += ' ' + l.trim(); else { const m = l.match(/^([\w-]+):\s*(.*)$/); if(m) H.push([m[1], m[2]]); } }
  return H;
}
function analyseEmail(raw){
  const H = parseHeaders(raw); if(!H.length) return null;
  const get = n => (H.find(h => h[0].toLowerCase() === n.toLowerCase()) || [])[1] || '', all = n => H.filter(h => h[0].toLowerCase() === n.toLowerCase()).map(h => h[1]);
  const addr = s => ((s.match(/<([^>]+)>/) || [])[1] || (s.match(/[\w.+-]+@[\w.-]+/) || [''])[0]).toLowerCase(), dom = a => (a.split('@')[1] || '').toLowerCase();
  const org = d => d.split('.').slice(-2).join('.');
  const from = addr(get('From')), ret = addr(get('Return-Path')), reply = addr(get('Reply-To')), sender = addr(get('Sender'));
  const auth = all('Authentication-Results').join(' ') + ' ' + all('ARC-Authentication-Results').join(' ');
  const res = k => { const m = auth.match(new RegExp('\\b' + k + '=(\\w+)', 'i')); return m ? m[1].toLowerCase() : ''; };
  const rspf = get('Received-SPF'), spf = res('spf') || (rspf.match(/^(\w+)/) || [])[1] || '', dkim = res('dkim'), dmarc = res('dmarc');
  const dkimSig = get('DKIM-Signature'), dkimD = (dkimSig.match(/\bd=([^;\s]+)/) || [])[1] || '', dkimS = (dkimSig.match(/\bs=([^;\s]+)/) || [])[1] || '';
  const msgid = get('Message-ID'), midDom = ((msgid.match(/@([^>]+)>?/) || [])[1] || '').toLowerCase();
  const hops = all('Received').map(r => { const t = Date.parse((r.split(';').pop() || '').trim().replace(/\s*\([^)]*\)\s*$/, ''));
    const ips = [...r.matchAll(/\[?((?:\d{1,3}\.){3}\d{1,3})\]?/g)].map(m => m[1]).filter(ip => ip.split('.').every(o => +o <= 255));
    return {raw:r, from:((r.match(/\bfrom\s+(\S+)/i) || [])[1] || ''), by:((r.match(/\bby\s+(\S+)/i) || [])[1] || ''), with:((r.match(/\bwith\s+(\S+)/i) || [])[1] || ''), ts:isFinite(t) ? t : null, ips}; }).reverse();
  hops.forEach((h, k) => { h.delay = k && h.ts && hops[k - 1].ts ? (h.ts - hops[k - 1].ts) / 1000 : null; });
  const pub = ip => { const o = ip.split('.').map(Number); if(o[0] === 169 && o[1] === 254 || o[0] === 100 && o[1] >= 64 && o[1] < 128 || o[0] === 0) return false; return !/private|loopback/i.test(E.ipClass(ip)); };
  const origin = hops.find(h => h.ips.some(pub)); const originIP = origin ? origin.ips.find(pub) : (get('X-Originating-IP').match(/[\d.]+/) || [''])[0];
  const flags = [];
  if(reply && dom(reply) && org(dom(reply)) !== org(dom(from))) flags.push(['red', `Reply-To (${reply}) goes to a different domain than From (${from}).`]);
  if(ret && dom(ret) && org(dom(ret)) !== org(dom(from))) flags.push(['amber', `Return-Path domain (${dom(ret)}) differs from From (${dom(from)}) — normal for mailing services, suspicious otherwise.`]);
  if(dkimD && org(dkimD) !== org(dom(from))) flags.push(['amber', `DKIM is signed by ${dkimD}, not the From domain.`]);
  if(midDom && org(midDom) !== org(dom(from))) flags.push(['amber', `Message-ID was generated by ${midDom}, not the From domain.`]);
  for(const [k, v] of [['SPF', spf], ['DKIM', dkim], ['DMARC', dmarc]]) if(v && !/pass|none|neutral/.test(v)) flags.push(['red', `${k} result: ${v}.`]);
  if(!spf && !dkim && !dmarc) flags.push(['amber', 'No authentication results in these headers — cannot tell whether the sender was verified.']);
  const disp = get('From').replace(/<[^>]+>/, '').replace(/"/g, '').trim(); if(disp && /@/.test(disp) && addr(disp) !== from) flags.push(['red', `Display name contains a different address (${disp}).`]);
  hops.forEach(h => { if(h.delay != null && h.delay < -300) flags.push(['amber', `Clock goes backwards between hops (${Math.round(h.delay)} s) — a forged or misconfigured Received header?`]); });
  return {H, from, ret, reply, sender, subject:get('Subject'), date:get('Date'), to:get('To'), msgid, spf, dkim, dmarc, dkimD, dkimS, hops, originIP, mailer:get('X-Mailer') || get('User-Agent'), flags,
    iocs:E.extract(H.map(h => h[1]).join('\n')).filter(e => e.k !== 'handle')};
}

/* ---------- IDs → time ---------- */
const IG_ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
function decodeIds(input){
  let s = String(input || '').trim(); if(!s) return [];
  const out = [], add = (l, ms, note) => { if(isFinite(ms) && ms > 1.1e12 - 5e11 && ms < 2.3e12) out.push([l, ms, note || '']); };
  const u = s.match(/(?:twitter|x)\.com\/[^/]+\/status(?:es)?\/(\d+)/i), dsc = s.match(/discord(?:app)?\.com\/channels\/\d+\/\d+\/(\d+)/i), tt = s.match(/tiktok\.com\/.*\/(?:video|photo)\/(\d+)/i),
    ig = s.match(/instagram\.com\/(?:[\w.]+\/)?(?:p|reel|tv)\/([\w-]{6,})/i), li = s.match(/(?:activity|ugcPost|share)[:\-](\d{15,})/i), yt = s.match(/(?:youtu\.be\/|v=)([\w-]{11})/);
  if(u){ s = u[1]; } if(dsc) s = dsc[1]; if(tt) s = tt[1]; if(li) s = li[1];
  if(ig){ let n = 0n; for(const c of ig[1].slice(0, 11)) n = n * 64n + BigInt(IG_ALPHA.indexOf(c)); add('Instagram post (shortcode ' + ig[1] + ')', Number(n >> 23n) + 1314220021721, 'from URL'); }
  if(yt) out.push(['YouTube video ' + yt[1], NaN, 'YouTube IDs are random — the upload date is only on the page']);
  if(/^\d{9,20}$/.test(s)){ const n = BigInt(s);
    add('X / Twitter post or user (snowflake)', Number(n >> 22n) + 1288834974657, u ? 'from URL' : '');
    add('Discord message, user or server (snowflake)', Number(n >> 22n) + 1420070400000, dsc ? 'from URL' : '');
    add('TikTok video', Number(n >> 32n) * 1000, tt ? 'from URL' : '');
    add('Instagram media ID', Number(n >> 23n) + 1314220021721);
    add('Mastodon post', Number(n >> 16n));
    const bits = n.toString(2); if(bits.length > 41) add('LinkedIn post (activity URN)', parseInt(bits.slice(0, 41), 2), li ? 'from URL' : '');
  }
  if(/^[0-9a-f]{24}$/i.test(s)) add('MongoDB ObjectId', parseInt(s.slice(0, 8), 16) * 1000);
  const uu = s.match(/^([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f])([0-9a-f]{3})-[0-9a-f]{4}-[0-9a-f]{12}$/i);
  if(uu){ const v = +uu[3]; if(v === 1){ const t = BigInt('0x' + uu[4] + uu[2] + uu[1]); add('UUID v1', Number((t - 122192928000000000n) / 10000n)); } else if(v === 7) add('UUID v7', parseInt(uu[1] + uu[2], 16)); else out.push(['UUID v' + v, NaN, 'Version ' + v + ' UUIDs carry no timestamp']); }
  if(/^[0-7][0-9A-HJKMNP-TV-Z]{25}$/i.test(s)){ const A = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; let t = 0; for(const c of s.slice(0, 10).toUpperCase()) t = t * 32 + A.indexOf(c); add('ULID', t); }
  if(/^[0-9A-Za-z]{27}$/.test(s)){ const A = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'; let n = 0n; for(const c of s) n = n * 62n + BigInt(A.indexOf(c)); const t = Number(n >> 128n); add('KSUID', (t + 1400000000) * 1000); }
  return out;
}

/* ---------- network ---------- */
const ip2n = ip => ip.split('.').reduce((a, o) => a * 256 + (+o), 0), n2ip = n => [24, 16, 8, 0].map(s => Math.floor(n / 2 ** s) % 256).join('.');
function subnet(input){
  const m = String(input).trim().match(/^((?:\d{1,3}\.){3}\d{1,3})(?:\s*\/\s*(\d{1,2})|\s+((?:\d{1,3}\.){3}\d{1,3}))?$/); if(!m) return null;
  const ip = m[1]; if(!ip.split('.').every(o => +o <= 255)) return null;
  let bits = m[2] != null ? +m[2] : m[3] ? ip2n(m[3]).toString(2).replace(/0+$/, '').length : 32; if(bits > 32) return null;
  const size = 2 ** (32 - bits), net = Math.floor(ip2n(ip) / size) * size, bc = net + size - 1;
  return {ip, bits, network:n2ip(net), broadcast:n2ip(bc), first:bits >= 31 ? n2ip(net) : n2ip(net + 1), last:bits >= 31 ? n2ip(bc) : n2ip(bc - 1), hosts:bits >= 31 ? size : size - 2,
    mask:n2ip(2 ** 32 - size), wildcard:n2ip(size - 1), cls:E.ipClass(ip), bin:ip.split('.').map(o => (+o).toString(2).padStart(8, '0')).join('.')};
}
let OUI = null;
async function ouiLoad(){ if(OUI) return OUI; if(typeof DecompressionStream === 'undefined') throw new Error('This browser cannot decompress the vendor list');
  const bin = Uint8Array.from(atob(OUI_B64), c => c.charCodeAt(0)), txt = await new Response(new Blob([bin]).stream().pipeThrough(new DecompressionStream('gzip'))).text();
  const [names, rows] = txt.split('\n##\n'), N = names.split('\n'), M = new Map(); for(const r of rows.split('\n')){ const k = r.indexOf(','); M.set(r.slice(0, k), N[+r.slice(k + 1)]); } return (OUI = M); }
async function macVendor(mac){ const h = String(mac).replace(/[^0-9a-f]/gi, '').toUpperCase(); if(h.length < 6) return null; const M = await ouiLoad(); const first = parseInt(h.slice(0, 2), 16);
  return {oui:h.slice(0, 6).match(/../g).join(':'), vendor:M.get(h.slice(0, 6)) || '', local:!!(first & 2), multicast:!!(first & 1), random:!!(first & 2) && !M.get(h.slice(0, 6))}; }
function parseUA(ua){
  const s = String(ua || ''); if(!s.trim()) return null; const r = {browser:'', os:'', device:'Desktop', engine:'', bot:''};
  const tools = [['sqlmap','SQL injection scanner'],['nikto','Web vulnerability scanner'],['nmap','Nmap scripting engine'],['masscan','Masscan'],['zgrab','ZGrab scanner'],['curl','curl command-line'],['Wget','wget'],['python-requests','Python requests'],['python-urllib','Python urllib'],['aiohttp','Python aiohttp'],['Go-http-client','Go HTTP client'],['okhttp','OkHttp (Android/Java)'],['Java/','Java HTTP client'],['libwww-perl','Perl LWP'],['PowerShell','PowerShell Invoke-WebRequest'],['WinHTTP','Windows WinHTTP'],['Postman','Postman'],['Headless','Headless browser'],['HeadlessChrome','Headless Chrome'],['Nuclei','Nuclei scanner'],['Burp','Burp Suite'],['Googlebot','Google crawler'],['bingbot','Bing crawler'],['YandexBot','Yandex crawler'],['facebookexternalhit','Facebook link preview'],['Twitterbot','X/Twitter link preview'],['Slackbot','Slack link preview'],['Discordbot','Discord link preview'],['GPTBot','OpenAI crawler'],['ClaudeBot','Anthropic crawler']];
  for(const [k, l] of tools) if(s.toLowerCase().includes(k.toLowerCase())){ r.bot = l; break; }
  const B = [[/Edg\/([\d.]+)/,'Edge'],[/OPR\/([\d.]+)/,'Opera'],[/SamsungBrowser\/([\d.]+)/,'Samsung Internet'],[/Firefox\/([\d.]+)/,'Firefox'],[/CriOS\/([\d.]+)/,'Chrome (iOS)'],[/Chrome\/([\d.]+)/,'Chrome'],[/Version\/([\d.]+).*Safari/,'Safari'],[/MSIE ([\d.]+)|Trident\/.*rv:([\d.]+)/,'Internet Explorer']];
  for(const [re, n] of B){ const m = s.match(re); if(m){ r.browser = n + ' ' + (m[1] || m[2] || '').split('.')[0]; break; } }
  const O = [[/Windows NT 10\.0/,'Windows 10/11'],[/Windows NT 6\.3/,'Windows 8.1'],[/Windows NT 6\.1/,'Windows 7'],[/Windows NT 6\.0/,'Windows Vista'],[/Windows NT 5\.1/,'Windows XP'],[/Android ([\d.]+)/,'Android'],[/iPhone OS ([\d_]+)/,'iOS'],[/iPad.*OS ([\d_]+)/,'iPadOS'],[/Mac OS X ([\d_.]+)/,'macOS'],[/CrOS/,'ChromeOS'],[/Linux/,'Linux']];
  for(const [re, n] of O){ const m = s.match(re); if(m){ r.os = n + (m[1] && !/Windows/.test(n) ? ' ' + m[1].replace(/_/g, '.') : ''); break; } }
  if(/Mobile|iPhone|Android.*Mobile/.test(s)) r.device = 'Phone'; else if(/iPad|Tablet|Android(?!.*Mobile)/.test(s)) r.device = 'Tablet'; if(r.bot) r.device = 'Automated client';
  r.engine = /Gecko\/\d/.test(s) && /Firefox/.test(s) ? 'Gecko' : /AppleWebKit/.test(s) ? (/Chrome|Edg|OPR/.test(s) ? 'Blink' : 'WebKit') : /Trident/.test(s) ? 'Trident' : '';
  return r;
}

/* ---------- generators ---------- */
function usernameVariants(full, extra){
  const clean = t => t.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/[^a-z0-9 ]/g, '');
  const p = clean(full).split(/\s+/).filter(Boolean); if(!p.length) return [];
  const f = p[0], l = p.length > 1 ? p[p.length - 1] : '', m = p.length > 2 ? p[1] : '', fi = f[0], li = l[0] || '', nums = String(extra || '').split(/[\s,]+/).filter(Boolean);
  const base = l ? [f + l, f + '.' + l, f + '_' + l, f + '-' + l, fi + l, fi + '.' + l, fi + '_' + l, f + li, f + '.' + li, l + f, l + '.' + f, l + '_' + f, l + fi, l + '.' + fi, f, l, fi + li, (m ? f + m[0] + l : ''), (m ? fi + m[0] + l : ''), f + l.slice(0, 3), l.slice(0, 5) + fi]
    : [f, f + '_', 'the' + f, f + 'official', 'real' + f, f + 'x'];
  const set = new Set(base.filter(Boolean));
  for(const b of [...set].slice(0, 12)) for(const n of nums){ set.add(b + n); set.add(b + '_' + n); set.add(b + n.slice(-2)); }
  return [...set].slice(0, 120);
}
function emailVariants(full, domain){
  const d = String(domain || '').trim().toLowerCase().replace(/^@/, ''); if(!d) return [];
  const p = full.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase().replace(/[^a-z ]/g, '').split(/\s+/).filter(Boolean); if(!p.length) return [];
  const f = p[0], l = p[p.length - 1], fi = f[0], li = l[0];
  return [...new Set([`${f}.${l}`, `${f}${l}`, `${fi}${l}`, `${fi}.${l}`, `${f}`, `${f}_${l}`, `${f}-${l}`, `${l}.${f}`, `${l}${f}`, `${l}${fi}`, `${f}${li}`, `${f}.${li}`, `${l}`, `${fi}${li}`].filter(x => x.length > 1))].map(x => x + '@' + d);
}

/* ---------- image tools ---------- */
async function loadImageData(file){
  const url = URL.createObjectURL(file); try{ const img = await new Promise((res, rej) => { const i = new Image(); i.onload = () => res(i); i.onerror = () => rej(new Error('Not an image this browser can open')); i.src = url; });
    const w = img.naturalWidth, h = img.naturalHeight, scale = Math.min(1, 4096 / Math.max(w, h)), c = document.createElement('canvas'); c.width = Math.round(w * scale); c.height = Math.round(h * scale);
    const x = c.getContext('2d', {willReadFrequently:true}); x.drawImage(img, 0, 0, c.width, c.height); return {w, h, scaled:scale < 1, data:x.getImageData(0, 0, c.width, c.height), url}; }
  catch(e){ URL.revokeObjectURL(url); throw e; }
}
function renderPlane(src, ch, bit, canvas){
  const {width:w, height:h, data} = src, out = new ImageData(w, h), o = out.data, idx = {r:0, g:1, b:2, a:3}[ch];
  for(let i = 0; i < data.length; i += 4){
    let v;
    if(ch === 'rgb'){ o[i] = data[i]; o[i + 1] = data[i + 1]; o[i + 2] = data[i + 2]; o[i + 3] = 255; continue; }
    if(ch === 'inv'){ o[i] = 255 - data[i]; o[i + 1] = 255 - data[i + 1]; o[i + 2] = 255 - data[i + 2]; o[i + 3] = 255; continue; }
    if(ch === 'gray') v = (data[i] * .299 + data[i + 1] * .587 + data[i + 2] * .114) | 0; else v = data[i + idx];
    if(bit !== 'all') v = (v >> bit) & 1 ? 255 : 0;
    o[i] = o[i + 1] = o[i + 2] = v; o[i + 3] = 255; }
  canvas.width = w; canvas.height = h; canvas.getContext('2d').putImageData(out, 0, 0);
}
function lsbExtract(src, chans, order){
  const {width:w, height:h, data} = src, bits = [], ci = chans.split('').map(c => ({r:0, g:1, b:2, a:3})[c]), max = 8 * 4096;
  const px = order === 'col' ? (function*(){ for(let x = 0; x < w; x++) for(let y = 0; y < h; y++) yield (y * w + x) * 4; })() : (function*(){ for(let p = 0; p < w * h; p++) yield p * 4; })();
  for(const i of px){ for(const c of ci){ bits.push(data[i + c] & 1); if(bits.length >= max) break; } if(bits.length >= max) break; }
  const bytes = []; for(let i = 0; i + 8 <= bits.length; i += 8) bytes.push(bits.slice(i, i + 8).reduce((a, b) => a * 2 + b, 0));
  const text = String.fromCharCode(...bytes), ok = c => { const k = c.charCodeAt(0); return k === 10 || k === 13 || k === 9 || (k >= 32 && k < 127); };
  let lead = 0; for(const c of text){ if(!ok(c)) break; lead++; }
  const head = text.slice(0, 64), printable = [...head].filter(ok).length / Math.max(1, head.length);
  return {text:lead >= 8 ? text.slice(0, lead) + (lead < text.length ? '\n… (' + (text.length - lead) + ' more bytes that are not text)' : '') : text, printable, lead};
}
function qrDecode(src){
  try{ const r = typeof jsQR === 'function' ? jsQR(src.data, src.width, src.height, {inversionAttempts:'attemptBoth'}) : null; return r ? r.data : null; }catch(e){ return null; }
}
