/* ==========================================================================
   PCAP reader — classic pcap and pcapng, parsed entirely in the browser.
   Link types: Ethernet (+VLAN), raw IP, Linux cooked (SLL / SLL2), BSD loopback.
   Decodes IPv4 / IPv6, TCP / UDP, ARP; reassembles TCP streams; reads DNS,
   DHCP, HTTP/1.x, TLS ClientHello (SNI, ALPN, JA3), certificate names and
   cleartext logins. Encrypted payloads (TLS, SSH, QUIC) stay encrypted — only
   their metadata is shown, because there is no key to decrypt them.
   ========================================================================== */
const PC_PORTS = {20:'FTP data',21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',67:'DHCP',68:'DHCP',69:'TFTP',80:'HTTP',88:'Kerberos',110:'POP3',123:'NTP',135:'MS RPC',137:'NetBIOS',138:'NetBIOS',139:'SMB',143:'IMAP',161:'SNMP',162:'SNMP trap',389:'LDAP',443:'HTTPS',445:'SMB',465:'SMTPS',514:'Syslog',587:'SMTP',636:'LDAPS',853:'DNS over TLS',993:'IMAPS',995:'POP3S',1433:'MS SQL',1883:'MQTT',1900:'SSDP',2525:'SMTP',3306:'MySQL',3389:'RDP',5060:'SIP',5353:'mDNS',5355:'LLMNR',5432:'PostgreSQL',5900:'VNC',5985:'WinRM',5986:'WinRM',6379:'Redis',8080:'HTTP',8000:'HTTP',8443:'HTTPS',9200:'Elasticsearch',27017:'MongoDB'};
const PC_SUS = {4444:'Metasploit default',1337:'common backdoor port',31337:'Back Orifice / elite',6667:'IRC — old botnet C2',6697:'IRC over TLS',9001:'Tor relay',9050:'Tor SOCKS',5555:'Android debug bridge',12345:'NetBus',54321:'common backdoor port',8888:'common C2 / proxy port'};
const PC_LINKS = {0:'BSD loopback',1:'Ethernet',12:'Raw IP',14:'Raw IP',101:'Raw IP',108:'OpenBSD loopback',113:'Linux cooked (SLL)',276:'Linux cooked v2 (SLL2)',228:'Raw IPv4',229:'Raw IPv6',105:'802.11 Wi-Fi',127:'802.11 + radiotap'};
const DNS_T = {1:'A',2:'NS',5:'CNAME',6:'SOA',12:'PTR',15:'MX',16:'TXT',28:'AAAA',33:'SRV',65:'HTTPS',255:'ANY'};
const pcIP4 = (b, o) => b[o] + '.' + b[o + 1] + '.' + b[o + 2] + '.' + b[o + 3];
function pcIP6(b, o){
  const g = []; for(let i = 0; i < 16; i += 2) g.push(((b[o + i] << 8) | b[o + i + 1]).toString(16));
  let bs = -1, bl = 0; for(let i = 0; i < 8;){ if(g[i] === '0'){ let j = i; while(j < 8 && g[j] === '0') j++; if(j - i > bl && j - i > 1){ bs = i; bl = j - i; } i = j; } else i++; }
  return bs < 0 ? g.join(':') : g.slice(0, bs).join(':') + '::' + g.slice(bs + bl).join(':');
}
const pcMac = (b, o) => { let s = ''; for(let i = 0; i < 6; i++) s += (i ? ':' : '') + b[o + i].toString(16).padStart(2, '0'); return s; };
const pcCat = parts => { let n = 0; for(const p of parts) n += p.length; const out = new Uint8Array(n); let o = 0; for(const p of parts){ out.set(p, o); o += p.length; } return out; };
const pcTr = p => p === 6 ? 'TCP' : p === 17 ? 'UDP' : p === 1 ? 'ICMP' : p === 58 ? 'ICMPv6' : p === 47 ? 'GRE' : p === 50 ? 'ESP' : p === 2 ? 'IGMP' : 'IP/' + p;
const pcPriv = ip => !/^Public/.test(E.ipClass(ip) || '');
const pcHP = (ip, p) => (ip.includes(':') ? '[' + ip + ']' : ip) + (p != null ? ':' + p : '');

/* ---------- container formats ---------- */
function pcapRead(b){
  if(b.length < 24) return null;
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength), pk = [], m = dv.getUint32(0, false); let trunc = false;
  if(m === 0x0a0d0d0a){
    const ifs = []; let o = 0, le = true, links = new Set();
    while(o + 12 <= b.length){
      let type = dv.getUint32(o, le);
      if(dv.getUint32(o, false) === 0x0a0d0d0a){ le = dv.getUint32(o + 8, true) === 0x1a2b3c4d; ifs.length = 0; type = 0x0a0d0d0a; }
      const len = dv.getUint32(o + 4, le); if(len < 12 || o + len > b.length){ trunc = o + 12 <= b.length; break; }
      if(type === 1){ const link = dv.getUint16(o + 8, le); let res = 1e6, p = o + 16;
        while(p + 4 <= o + len - 4){ const code = dv.getUint16(p, le), ol = dv.getUint16(p + 2, le); if(code === 0) break; if(code === 9){ const v = b[p + 4]; res = v & 0x80 ? 2 ** (v & 0x7f) : 10 ** v; } p += 4 + ((ol + 3) & ~3); }
        ifs.push({link, res}); links.add(link); }
      else if(type === 6 || type === 2){ const iface = type === 6 ? dv.getUint32(o + 8, le) : dv.getUint16(o + 8, le), hi = dv.getUint32(o + 12, le), lo = dv.getUint32(o + 16, le), cap = dv.getUint32(o + 20, le), orig = dv.getUint32(o + 24, le), I = ifs[iface] || {link:1, res:1e6};
        pk.push({t:(hi * 4294967296 + lo) / I.res * 1000, len:orig, d:b.subarray(o + 28, Math.min(o + 28 + cap, o + len - 4)), link:I.link}); }
      else if(type === 3){ const orig = dv.getUint32(o + 8, le), I = ifs[0] || {link:1}; pk.push({t:0, len:orig, d:b.subarray(o + 12, Math.min(o + 12 + orig, o + len - 4)), link:I.link}); }
      o += len;
    }
    return {fmt:'pcapng', pk, links:[...links], trunc};
  }
  let le, ns;
  if(m === 0xa1b2c3d4){ le = false; ns = false; } else if(m === 0xd4c3b2a1){ le = true; ns = false; } else if(m === 0xa1b23c4d){ le = false; ns = true; } else if(m === 0x4d3cb2a1){ le = true; ns = true; } else return null;
  const link = dv.getUint32(20, le) & 0xffff; let o = 24;
  while(o + 16 <= b.length){ const s = dv.getUint32(o, le), f = dv.getUint32(o + 4, le), cap = dv.getUint32(o + 8, le), orig = dv.getUint32(o + 12, le);
    if(cap > 1048576 || o + 16 + cap > b.length){ trunc = true; break; }
    pk.push({t:s * 1000 + (ns ? f / 1e6 : f / 1000), len:orig, d:b.subarray(o + 16, o + 16 + cap), link}); o += 16 + cap; }
  if(o < b.length && o + 16 > b.length) trunc = true;
  return {fmt:'pcap' + (ns ? ' (ns)' : ''), pk, links:[link], trunc};
}

/* ---------- packet decode ---------- */
function pcDecode(p){
  const b = p.d; let o = 0, et = -1, smac = '', dmac = '';
  switch(p.link){
    case 1: if(b.length < 14) return null; dmac = pcMac(b, 0); smac = pcMac(b, 6); et = (b[12] << 8) | b[13]; o = 14;
      while((et === 0x8100 || et === 0x88a8) && o + 4 <= b.length){ et = (b[o + 2] << 8) | b[o + 3]; o += 4; } break;
    case 12: case 14: case 101: et = (b[0] >> 4) === 6 ? 0x86dd : 0x0800; break;
    case 228: et = 0x0800; break; case 229: et = 0x86dd; break;
    case 113: if(b.length < 16) return null; et = (b[14] << 8) | b[15]; if(((b[4] << 8) | b[5]) === 6) smac = pcMac(b, 6); o = 16; break;
    case 276: if(b.length < 20) return null; et = (b[0] << 8) | b[1]; if(b[11] === 6) smac = pcMac(b, 12); o = 20; break;
    case 0: case 108: { const f = b[0] || b[3]; et = f === 2 ? 0x0800 : (f === 24 || f === 28 || f === 30) ? 0x86dd : -1; o = 4; break; }
    default: return {other:true};
  }
  const r = {smac, dmac};
  if(et === 0x0806){ if(o + 28 <= b.length) r.arp = {op:(b[o + 6] << 8) | b[o + 7], sha:pcMac(b, o + 8), spa:pcIP4(b, o + 14), tpa:pcIP4(b, o + 24)}; return r; }
  let proto, end;
  if(et === 0x0800){ if(o + 20 > b.length) return r; const ihl = (b[o] & 15) * 4, tot = (b[o + 2] << 8) | b[o + 3];
    r.src = pcIP4(b, o + 12); r.dst = pcIP4(b, o + 16); proto = b[o + 9]; r.ttl = b[o + 8];
    end = tot >= ihl ? Math.min(b.length, o + tot) : b.length; const frag = ((b[o + 6] & 0x1f) << 8) | b[o + 7]; o += ihl; if(frag){ r.proto = proto; r.frag = true; return r; } }
  else if(et === 0x86dd){ if(o + 40 > b.length) return r; const plen = (b[o + 4] << 8) | b[o + 5]; proto = b[o + 6]; r.ttl = b[o + 7]; r.src = pcIP6(b, o + 8); r.dst = pcIP6(b, o + 24);
    end = plen ? Math.min(b.length, o + 40 + plen) : b.length; o += 40;
    for(let g = 0; [0, 43, 60, 44, 51].includes(proto) && o + 8 <= end && g < 8; g++){ const nh = b[o], l = proto === 44 ? 8 : proto === 51 ? (b[o + 1] + 2) * 4 : (b[o + 1] + 1) * 8;
      if(proto === 44 && (((b[o + 2] << 8) | b[o + 3]) & 0xfff8)){ r.proto = nh; r.frag = true; return r; } proto = nh; o += l; } }
  else { r.l2 = et; return r; }
  r.proto = proto;
  if(proto === 6 && o + 20 <= end){ r.sp = (b[o] << 8) | b[o + 1]; r.dp = (b[o + 2] << 8) | b[o + 3]; r.seq = ((b[o + 4] << 24) | (b[o + 5] << 16) | (b[o + 6] << 8) | b[o + 7]) >>> 0; r.fl = b[o + 13]; r.pay = b.subarray(Math.min(end, o + (b[o + 12] >> 4) * 4), end); }
  else if(proto === 17 && o + 8 <= end){ r.sp = (b[o] << 8) | b[o + 1]; r.dp = (b[o + 2] << 8) | b[o + 3]; r.pay = b.subarray(o + 8, end); }
  else if(proto === 1 || proto === 58){ r.icmp = b[o]; }
  return r;
}

/* ---------- application protocols ---------- */
function dnsName(b, o){
  const L = []; let end = -1, g = 0;
  while(o < b.length && g++ < 128){ const l = b[o]; if(l === 0){ o++; break; }
    if((l & 0xc0) === 0xc0){ if(end < 0) end = o + 2; o = ((l & 0x3f) << 8) | b[o + 1]; continue; }
    L.push(latin1(b, o + 1, Math.min(b.length, o + 1 + l))); o += 1 + l; }
  return [L.join('.'), end < 0 ? o : end];
}
function dnsParse(b){
  if(b.length < 12) return null; const fl = (b[2] << 8) | b[3], qd = (b[4] << 8) | b[5], an = (b[6] << 8) | b[7]; if(qd > 20 || an > 200) return null;
  let o = 12; const q = [], a = [];
  for(let i = 0; i < qd && o < b.length; i++){ const [n, e] = dnsName(b, o); o = e; q.push({n, type:(b[o] << 8) | b[o + 1]}); o += 4; }
  for(let i = 0; i < an && o + 10 <= b.length; i++){ const [n, e] = dnsName(b, o); o = e; const type = (b[o] << 8) | b[o + 1], rl = (b[o + 8] << 8) | b[o + 9], rd = o + 10; let v = '';
    if(type === 1 && rl === 4) v = pcIP4(b, rd); else if(type === 28 && rl === 16) v = pcIP6(b, rd); else if(type === 5 || type === 2 || type === 12) v = dnsName(b, rd)[0]; else if(type === 15) v = dnsName(b, rd + 2)[0];
    else if(type === 16){ let p = rd; const parts = []; while(p < rd + rl){ const l = b[p]; parts.push(latin1(b, p + 1, Math.min(p + 1 + l, rd + rl))); p += 1 + l; } v = parts.join(''); }
    if(v) a.push({n, type, v}); o = rd + rl; }
  return {id:(b[0] << 8) | b[1], qr:fl >> 15, rc:fl & 15, q, a};
}
function dhcpParse(b){
  if(b.length < 244 || b[236] !== 99 || b[237] !== 130 || b[238] !== 83 || b[239] !== 99) return null;
  const r = {op:b[0], mac:pcMac(b, 28), ip:pcIP4(b, 16) !== '0.0.0.0' ? pcIP4(b, 16) : pcIP4(b, 12) !== '0.0.0.0' ? pcIP4(b, 12) : ''};
  for(let o = 240; o < b.length;){ const c = b[o]; if(c === 255) break; if(c === 0){ o++; continue; } const l = b[o + 1], v = b.subarray(o + 2, o + 2 + l);
    if(c === 12) r.host = latin1(v); else if(c === 53) r.type = ['', 'Discover', 'Offer', 'Request', 'Decline', 'ACK', 'NAK', 'Release', 'Inform'][v[0]] || v[0]; else if(c === 50 && l === 4) r.req = pcIP4(v, 0);
    else if(c === 60) r.vendor = latin1(v); else if(c === 81 && l > 3) r.fqdn = latin1(v, 3); o += 2 + l; }
  return r;
}
const GREASE = v => (v & 0x0f0f) === 0x0a0a && (v >> 8) === (v & 0xff);
function tlsHello(b){
  if(b.length < 48 || b[0] !== 0x16 || b[1] !== 3 || b[5] !== 1) return null;
  const u16 = o => (b[o] << 8) | b[o + 1], ver = u16(9); let o = 9 + 2 + 32; o += 1 + b[o];
  const cl = u16(o), ciphers = []; for(let i = 0; i < cl; i += 2) ciphers.push(u16(o + 2 + i)); o += 2 + cl; o += 1 + b[o];
  const R = {ver, ciphers:ciphers.filter(c => !GREASE(c)), exts:[], groups:[], pf:[], sni:'', alpn:[], sv:[]};
  if(o + 2 > b.length) return R; const eend = Math.min(b.length, o + 2 + u16(o)); o += 2;
  while(o + 4 <= eend){ const t = u16(o), l = u16(o + 2), d = o + 4; if(!GREASE(t)) R.exts.push(t);
    if(t === 0 && l > 5) R.sni = latin1(b, d + 5, Math.min(d + 5 + u16(d + 3), d + l));
    else if(t === 10) for(let i = 0; i < u16(d); i += 2){ const g = u16(d + 2 + i); if(!GREASE(g)) R.groups.push(g); }
    else if(t === 11) for(let i = 0; i < b[d]; i++) R.pf.push(b[d + 1 + i]);
    else if(t === 16){ let p = d + 2; while(p < d + l){ const n = b[p]; R.alpn.push(latin1(b, p + 1, p + 1 + n)); p += 1 + n; } }
    else if(t === 43) for(let i = 0; i < b[d]; i += 2){ const v = u16(d + 1 + i); if(!GREASE(v)) R.sv.push(v); }
    o = d + l; }
  R.ja3s = [ver, R.ciphers.join('-'), R.exts.join('-'), R.groups.join('-'), R.pf.join('-')].join(',');
  R.ja3 = md5(new TextEncoder().encode(R.ja3s));
  return R;
}
const TLS_V = {0x0300:'SSL 3.0', 0x0301:'TLS 1.0', 0x0302:'TLS 1.1', 0x0303:'TLS 1.2', 0x0304:'TLS 1.3'};
function tlsServer(b){
  if(b.length < 48 || b[0] !== 0x16 || b[5] !== 2) return null;
  const u16 = o => (b[o] << 8) | b[o + 1]; let ver = u16(9), o = 9 + 2 + 32; o += 1 + b[o]; const cipher = u16(o); o += 3;
  if(o + 2 <= b.length){ const e = Math.min(b.length, o + 2 + u16(o)); o += 2; while(o + 4 <= e){ const t = u16(o), l = u16(o + 2); if(t === 43 && l === 2) ver = u16(o + 4); o += 4 + l; } }
  /* certificate subject / issuer names — readable only before TLS 1.3 */
  const names = []; if(ver < 0x0304) for(let i = 0, n = Math.min(b.length - 8, 65536); i < n; i++) if(b[i] === 6 && b[i + 1] === 3 && b[i + 2] === 0x55 && b[i + 3] === 4 && b[i + 4] === 3 && /^(12|19|20|22|30)$/.test(String(b[i + 5]))){ const l = b[i + 6]; if(l < 128) names.push(latin1(b, i + 7, i + 7 + l)); }
  return {ver, cipher, names:[...new Set(names)]};
}
function httpHeaders(s, o){ const e = s.indexOf('\r\n\r\n', o); if(e < 0) return null; const H = {}; for(const ln of s.slice(o, e).split('\r\n').slice(1)){ const i = ln.indexOf(':'); if(i > 0) H[ln.slice(0, i).trim().toLowerCase()] = ln.slice(i + 1).trim(); } return {H, body:e + 4}; }
function httpBody(b, s, H, o, stop){
  if(/chunked/i.test(H['transfer-encoding'] || '')){ const out = []; let p = o;
    for(let g = 0; g < 10000 && p < b.length; g++){ const e = s.indexOf('\r\n', p); if(e < 0) break; const n = parseInt(s.slice(p, e).split(';')[0], 16); if(isNaN(n)) break; p = e + 2; if(n === 0){ p += 2; break; } out.push(b.subarray(p, Math.min(b.length, p + n))); p += n + 2; }
    return {body:pcCat(out), end:p}; }
  if(H['content-length'] != null){ const n = parseInt(H['content-length'], 10) || 0; return {body:b.subarray(o, Math.min(b.length, o + n)), end:o + n}; }
  return {body:b.subarray(o, stop), end:stop};
}
function httpParse(cli, srv){
  const cs = latin1(cli), ss = latin1(srv), reqs = [], res = [];
  const RQ = /(?:^|\r\n)(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|PROPFIND|TRACE) (\S+) HTTP\/1\.[01]\r\n/g; let m, guard = 0;
  while((m = RQ.exec(cs)) && guard++ < 2000){ const st = m.index + (m[0].startsWith('\r\n') ? 2 : 0), h = httpHeaders(cs, st); if(!h) break;
    const bd = /^(GET|HEAD|OPTIONS|CONNECT|DELETE|TRACE)$/.test(m[1]) ? {body:new Uint8Array(0), end:h.body} : httpBody(cli, cs, h.H, h.body, cli.length);
    reqs.push({method:m[1], uri:m[2], H:h.H, body:bd.body}); RQ.lastIndex = Math.max(RQ.lastIndex, bd.end - 2); }
  const RS = /(?:^|\r\n)HTTP\/1\.[01] (\d{3})([^\r\n]*)\r\n/g; guard = 0;
  while((m = RS.exec(ss)) && guard++ < 2000){ const st = m.index + (m[0].startsWith('\r\n') ? 2 : 0), h = httpHeaders(ss, st); if(!h) break; const code = +m[1];
    const bd = code < 200 || code === 204 || code === 304 ? {body:new Uint8Array(0), end:h.body} : httpBody(srv, ss, h.H, h.body, (() => { const n = ss.indexOf('\r\nHTTP/1.', h.body); return n < 0 ? srv.length : n; })());
    res.push({code, reason:m[2].trim(), H:h.H, body:bd.body}); RS.lastIndex = Math.max(RS.lastIndex, bd.end - 2); }
  return {reqs, res};
}
const b64s = s => { try{ return atob(s.trim()); }catch(e){ return ''; } };
function credsOf(F, cli, srv){
  const out = [], port = F.srv.port, cs = latin1(cli.subarray(0, 262144)), add = (proto, user, pass, how) => out.push({t:F.first, fid:F.id, proto, cli:F.cli.ip, srv:pcHP(F.srv.ip, port), user, pass, how});
  if(port === 21 || port === 110){ const u = (cs.match(/^USER ([^\r\n]+)/m) || [])[1], p = (cs.match(/^PASS ([^\r\n]*)/m) || [])[1]; if(u || p) add(port === 21 ? 'FTP' : 'POP3', u || '', p || '', 'USER / PASS'); }
  if(port === 143){ const m = cs.match(/^\S+ LOGIN ("[^"]*"|\S+) ("[^"]*"|\S+)/mi); if(m) add('IMAP', m[1].replace(/^"|"$/g, ''), m[2].replace(/^"|"$/g, ''), 'LOGIN');
    const a = cs.match(/AUTHENTICATE PLAIN\s*\r\n([A-Za-z0-9+/=]+)/i); if(a){ const p = b64s(a[1]).split('\0'); add('IMAP', p[1] || '', p[2] || '', 'AUTH PLAIN'); } }
  if(port === 25 || port === 587 || port === 2525){ const pl = cs.match(/AUTH PLAIN(?: |\r\n)([A-Za-z0-9+/=]+)/i); if(pl){ const p = b64s(pl[1]).split('\0'); add('SMTP', p[1] || '', p[2] || '', 'AUTH PLAIN'); }
    const lg = cs.match(/AUTH LOGIN(?: ([A-Za-z0-9+/=]+))?\r\n(?:([A-Za-z0-9+/=]+)\r\n)?([A-Za-z0-9+/=]+)\r\n/i); if(lg){ const u = lg[1] ? b64s(lg[1]) : b64s(lg[2] || ''), p = lg[1] ? b64s(lg[2] || '') : b64s(lg[3]); add('SMTP', u, p, 'AUTH LOGIN'); } }
  if(port === 23){ const t = cs.replace(/\xff[\xfb-\xfe]./g, '').replace(/\xff\xfa[\s\S]*?\xff\xf0/g, ''); if(/[\x20-\x7e]{2,}\r/.test(t)) add('Telnet', '', '', 'Session keystrokes: ' + t.replace(/[^\x20-\x7e\r]/g, '').replace(/\r\n?/g, ' ⏎ ').slice(0, 120)); }
  return out;
}
function snmpCommunity(b){ if(b.length < 8 || b[0] !== 0x30) return null; let o = 1 + (b[1] & 0x80 ? 1 + (b[1] & 0x7f) : 1); if(b[o] !== 2) return null; const v = b[o + 2]; o += 2 + b[o + 1]; if(b[o] !== 4) return null; const l = b[o + 1]; return {ver:v === 0 ? 'v1' : v === 1 ? 'v2c' : 'v3', community:latin1(b, o + 2, o + 2 + l)}; }

/* TCP payload in order, per direction; drops retransmitted bytes */
function pcChunks(F){
  if(F.chunks) return F.chunks;
  const base = [null, null], top = [0, 0], out = [];
  for(const s of F.segs){
    if(s.seq == null){ out.push(s); continue; }
    if(base[s.dir] == null) base[s.dir] = s.seq;
    let rel = (s.seq - base[s.dir] + 4294967296) % 4294967296; if(rel > 2147483648) continue;
    let d = s.d; if(rel + d.length <= top[s.dir]) continue; if(rel < top[s.dir]){ d = d.subarray(top[s.dir] - rel); rel = top[s.dir]; }
    top[s.dir] = rel + d.length; out.push({dir:s.dir, t:s.t, d});
  }
  return F.chunks = out;
}
function pcSide(F, dir, cap = 8 << 20){ const parts = []; let n = 0; for(const c of pcChunks(F)) if(c.dir === dir){ if(n + c.d.length > cap){ parts.push(c.d.subarray(0, cap - n)); break; } parts.push(c.d); n += c.d.length; } return pcCat(parts); }

/* ---------- whole-capture analysis ---------- */
async function pcapAnalyse(file){
  const buf = new Uint8Array(await file.arrayBuffer()), R = pcapRead(buf); if(!R) throw new Error('This is not a pcap or pcapng file');
  const A = {name:file.name, size:file.size, file, fmt:R.fmt, links:R.links, trunc:R.trunc, n:R.pk.length, bytes:0, first:Infinity, last:-Infinity, other:0, frag:0,
    proto:{}, flows:new Map(), hosts:new Map(), dns:[], http:[], tls:[], creds:[], dhcp:[], arp:new Map(), snmp:[], syns:[], ipName:new Map(), findings:[]};
  A.sha256 = await sha256Hex(buf.buffer);
  const H = ip => { let h = A.hosts.get(ip); if(!h){ h = {ip, pk:0, sent:0, recv:0, macs:new Set(), names:new Set(), peers:new Set(), svc:new Set(), ttl:null}; A.hosts.set(ip, h); } return h; };
  const pq = new Map(); let fid = 0;
  for(let i = 0; i < R.pk.length; i++){
    if(i && i % 20000 === 0) await new Promise(r => setTimeout(r));
    const p = R.pk[i], d = pcDecode(p); A.bytes += p.len; if(p.t){ if(p.t < A.first) A.first = p.t; if(p.t > A.last) A.last = p.t; }
    if(!d || d.other){ A.other++; continue; }
    if(d.arp){ A.proto.ARP = (A.proto.ARP || 0) + 1; const k = d.arp.spa; if(k !== '0.0.0.0'){ let s = A.arp.get(k); if(!s){ s = new Set(); A.arp.set(k, s); } s.add(d.arp.sha); } continue; }
    if(!d.src){ A.other++; continue; }
    if(d.frag){ A.frag++; continue; }
    const hs = H(d.src), hd = H(d.dst); hs.pk++; hd.pk++; hs.sent += p.len; hd.recv += p.len; hs.peers.add(d.dst); hd.peers.add(d.src); if(d.smac) hs.macs.add(d.smac); if(hs.ttl == null) hs.ttl = d.ttl;
    const tr = pcTr(d.proto); let label = tr;
    const a = d.src + '|' + (d.sp ?? ''), b2 = d.dst + '|' + (d.dp ?? ''), key = tr + ' ' + (a < b2 ? a + ' ' + b2 : b2 + ' ' + a);
    let F = A.flows.get(key);
    if(!F){ let cli = {ip:d.src, port:d.sp}, srv = {ip:d.dst, port:d.dp};
      const synack = d.proto === 6 && (d.fl & 0x12) === 0x12, wk = d.sp != null && (PC_PORTS[d.sp] || d.sp < 1024) && !(PC_PORTS[d.dp] || d.dp < 1024);
      if(synack || (!(d.proto === 6 && (d.fl & 0x12) === 0x02) && wk)){ [cli, srv] = [srv, cli]; }
      F = {id:++fid, key, tr, proto:d.proto, cli, srv, pk:0, by:0, first:p.t, last:p.t, segs:[], syn:false, rst:false, fin:false, pl:[0, 0]}; A.flows.set(key, F); }
    const dir = d.src === F.cli.ip && d.sp === F.cli.port ? 0 : 1;
    F.pk++; F.by += p.len; F.last = p.t;
    if(d.proto === 6){ if(d.fl & 0x02) F.syn = true; if(d.fl & 0x04) F.rst = true; if(d.fl & 0x01) F.fin = true;
      if((d.fl & 0x12) === 0x02) A.syns.push({t:p.t, src:d.src, dst:d.dst, dp:d.dp}); }
    if(d.pay && d.pay.length){ F.pl[dir] += d.pay.length; if(F.segs.length < 60000) F.segs.push({dir, t:p.t, seq:d.proto === 6 ? d.seq : null, d:d.pay}); }
    if(d.proto === 17 && d.pay){
      const sp = d.sp, dp = d.dp;
      if(sp === 53 || dp === 53 || sp === 5353 || dp === 5353 || sp === 5355 || dp === 5355){ const q = dnsParse(d.pay); if(q && q.q.length){ label = 'DNS';
        const k = F.key + '#' + q.id + q.q[0].n;
        if(!q.qr){ if(!pq.has(k)){ const row = {t:p.t, fid:F.id, cli:d.src, srv:d.dst, name:q.q[0].n, type:DNS_T[q.q[0].type] || q.q[0].type, ans:[], rc:null, mdns:dp === 5353 || dp === 5355}; pq.set(k, row); A.dns.push(row); } }
        else { let row = pq.get(k); if(!row){ row = {t:p.t, fid:F.id, cli:d.dst, srv:d.src, name:q.q[0].n, type:DNS_T[q.q[0].type] || q.q[0].type, ans:[], rc:null, mdns:sp === 5353 || sp === 5355}; A.dns.push(row); }
          row.rc = q.rc; row.rtt = p.t - row.t; for(const x of q.a){ row.ans.push((x.type === 1 || x.type === 28 ? '' : (DNS_T[x.type] || x.type) + ' ') + x.v); if(x.type === 1 || x.type === 28){ let s = A.ipName.get(x.v); if(!s){ s = new Set(); A.ipName.set(x.v, s); } s.add(q.q[0].n.toLowerCase()); } } } } }
      else if((sp === 67 || sp === 68) && (dp === 67 || dp === 68)){ const x = dhcpParse(d.pay); if(x){ label = 'DHCP'; A.dhcp.push({t:p.t, ...x}); } }
      else if(dp === 161 || dp === 162){ const x = snmpCommunity(d.pay); if(x){ label = 'SNMP'; if(!A.snmp.some(s => s.community === x.community && s.cli === d.src)) A.snmp.push({t:p.t, cli:d.src, srv:pcHP(d.dst, dp), ...x}); } }
      else if(dp === 443 || sp === 443) label = 'QUIC';
    }
    if(d.sp != null){ const svc = PC_PORTS[F.srv.port]; if(svc && label === tr) label = svc; }
    A.proto[label] = (A.proto[label] || 0) + 1;
  }
  if(!isFinite(A.first)){ A.first = 0; A.last = 0; }
  /* TCP application layer */
  for(const F of A.flows.values()){
    F.svc = PC_PORTS[F.srv.port] || '';
    if(F.proto !== 6 || !(F.pl[0] || F.pl[1])) continue;
    const cli = pcSide(F, 0), srv = pcSide(F, 1);
    const ch = tlsHello(cli);
    if(ch){ const sh = tlsServer(srv); F.svc = F.srv.port === 443 ? 'HTTPS' : (PC_PORTS[F.srv.port] ? PC_PORTS[F.srv.port] + ' (TLS)' : 'TLS');
      A.tls.push({t:F.first, fid:F.id, cli:F.cli.ip, srv:pcHP(F.srv.ip, F.srv.port), sip:F.srv.ip, sni:ch.sni, alpn:ch.alpn.join(', '), ja3:ch.ja3, ja3s:ch.ja3s, ver:TLS_V[sh ? sh.ver : Math.max(ch.ver, ...ch.sv)] || '', names:sh ? sh.names : [], bytes:F.by});
      if(ch.sni) H(F.srv.ip).names.add(ch.sni.toLowerCase()); continue; }
    if(/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|PROPFIND) \S+ HTTP\/1/.test(latin1(cli, 0, 4096))){
      F.svc = F.srv.port === 80 ? 'HTTP' : 'HTTP (port ' + F.srv.port + ')'; const P = httpParse(cli, srv);
      P.reqs.forEach((q, i) => { const s = P.res[i] || null, host = q.H.host || F.srv.ip, url = /^https?:\/\//i.test(q.uri) ? q.uri : 'http://' + host + (q.uri.startsWith('/') ? '' : '/') + q.uri;
        const row = {t:F.first, fid:F.id, cli:F.cli.ip, srv:pcHP(F.srv.ip, F.srv.port), method:q.method, host, url, ua:q.H['user-agent'] || '', ref:q.H.referer || '', code:s ? s.code : null, ctype:s ? (s.H['content-type'] || '').split(';')[0] : '', enc:s ? s.H['content-encoding'] || '' : '', size:s ? s.body.length : 0, body:s ? s.body : null, disp:s ? s.H['content-disposition'] || '' : '', server:s ? s.H.server || '' : ''};
        A.http.push(row); if(q.H.host) H(F.srv.ip).names.add(q.H.host.toLowerCase().replace(/:\d+$/, ''));
        const au = q.H.authorization || q.H['proxy-authorization'] || ''; if(/^basic /i.test(au)){ const up = b64s(au.slice(6)); const i2 = up.indexOf(':'); A.creds.push({t:F.first, fid:F.id, proto:'HTTP', cli:F.cli.ip, srv:pcHP(F.srv.ip, F.srv.port), user:up.slice(0, i2), pass:up.slice(i2 + 1), how:'Basic auth · ' + host}); }
        if(q.method === 'POST' && q.body.length && q.body.length < 20000){ const bs = latin1(q.body); if(/(^|&)(pass(word)?|pwd|passwd)=/i.test(bs)){ const pr = new URLSearchParams(bs), gv = re => { for(const [k, v] of pr) if(re.test(k)) return v; return ''; };
          A.creds.push({t:F.first, fid:F.id, proto:'HTTP form', cli:F.cli.ip, srv:pcHP(F.srv.ip, F.srv.port), user:gv(/user|login|email|name|uid|account/i), pass:gv(/^(pass(word)?|pwd|passwd)$/i) || gv(/pass|pwd/i), how:'POST ' + url.slice(0, 80)}); } }
        if(/(^|&)(pass(word)?|pwd)=/i.test(q.uri.split('?')[1] || '')) A.creds.push({t:F.first, fid:F.id, proto:'HTTP URL', cli:F.cli.ip, srv:pcHP(F.srv.ip, F.srv.port), user:'', pass:'', how:'Password in the URL · ' + url.slice(0, 90)});
      });
      continue; }
    if(F.srv.port === 53){ let o = 0; while(o + 2 < cli.length){ const l = (cli[o] << 8) | cli[o + 1], q = dnsParse(cli.subarray(o + 2, o + 2 + l)); if(q && q.q.length) A.dns.push({t:F.first, fid:F.id, cli:F.cli.ip, srv:F.srv.ip, name:q.q[0].n, type:(DNS_T[q.q[0].type] || q.q[0].type) + ' (TCP)', ans:[], rc:null}); o += 2 + l; } }
    A.creds.push(...credsOf(F, cli, srv));
    const head = latin1(srv, 0, 8) + latin1(cli, 0, 8); if(/^SSH-/.test(head)) F.svc = 'SSH';
  }
  for(const s of A.snmp) A.creds.push({t:s.t, proto:'SNMP ' + s.ver, cli:s.cli, srv:s.srv, user:'', pass:s.community, how:'Community string'});
  for(const [ip, s] of A.ipName){ const h = A.hosts.get(ip); if(h) for(const n of s) h.names.add(n); }
  for(const x of A.dhcp){ if(x.host){ const ip = x.ip || x.req; if(ip && A.hosts.has(ip)) A.hosts.get(ip).names.add(x.host); } }
  for(const F of A.flows.values()) if(F.srv.port != null && (F.pl[1] || F.syn)) H(F.srv.ip).svc.add((F.tr === 'UDP' ? 'udp/' : '') + F.srv.port);
  for(const F of A.flows.values()) F.svc = F.svc || PC_PORTS[F.srv.port] || (F.srv.port != null ? F.tr.toLowerCase() + '/' + F.srv.port : F.tr);
  A.findings = pcFindings(A); A.flags = pcFlags(A);
  return A;
}
function pcFlags(A){ const parts = []; let n = 0; for(const F of A.flows.values()) for(const s of F.segs){ if(n > 16 << 20) break; parts.push(latin1(s.d)); n += s.d.length; } return findFlags(parts.join('\n')); }
function pcFindings(A){
  const out = [], add = (tone, title, detail, view) => out.push({tone, title, detail, view});
  if(A.creds.length) add('red', `${A.creds.length} cleartext login${A.creds.length === 1 ? '' : 's'} or secret${A.creds.length === 1 ? '' : 's'}`, [...new Set(A.creds.map(c => c.proto))].join(', ') + ' — anyone on the path could read them.', 'creds');
  const sus = [...A.flows.values()].filter(F => PC_SUS[F.srv.port]);
  if(sus.length) add('red', `Traffic on ${[...new Set(sus.map(F => F.srv.port))].length === 1 ? 'a port' : 'ports'} often used by malware`, [...new Set(sus.map(F => F.srv.port + ' (' + PC_SUS[F.srv.port] + ')'))].join(', ') + ' — ' + [...new Set(sus.map(F => pcHP(F.srv.ip, F.srv.port)))].slice(0, 5).join(', '), 'flows');
  const g = new Map(); for(const s of A.syns){ const k = s.src + ' → ' + pcHP(s.dst, s.dp); if(!g.has(k)) g.set(k, []); g.get(k).push(s.t); }
  for(const [k, ts] of g){ if(ts.length < 5) continue; const b = E.beaconOf(ts); if(b && b.regular) add('amber', 'Regular check-ins (possible beacon)', `${k}: ${b.n} connections about every ${b.mean >= 60000 ? (b.mean / 60000).toFixed(1) + ' min' : (b.mean / 1000).toFixed(1) + ' s'}, jitter ${Math.round(b.jitter * 100)}%.`, 'flows'); }
  const bySrc = new Map(); for(const s of A.syns){ let x = bySrc.get(s.src); if(!x){ x = {ports:new Map(), hosts:new Map()}; bySrc.set(s.src, x); } const pk = s.dst; if(!x.ports.has(pk)) x.ports.set(pk, new Set()); x.ports.get(pk).add(s.dp); if(!x.hosts.has(s.dp)) x.hosts.set(s.dp, new Set()); x.hosts.get(s.dp).add(s.dst); }
  for(const [src, x] of bySrc){ for(const [dst, ps] of x.ports) if(ps.size >= 25) add('amber', 'Port scan', `${src} tried ${ps.size} ports on ${dst}.`, 'flows'); for(const [port, hs] of x.hosts) if(hs.size >= 30) add('amber', 'Host sweep', `${src} tried port ${port} on ${hs.size} hosts.`, 'flows'); }
  for(const [ip, macs] of A.arp) if(macs.size > 1) add('red', 'One IP, several MAC addresses', `${ip} was claimed by ${[...macs].join(', ')} — ARP spoofing or a changed device.`, 'hosts');
  const base = new Map(); for(const d of A.dns){ const n = d.name.toLowerCase(), parts = n.split('.'); if(parts.length < 3) continue; const bd = parts.slice(-2).join('.'); let s = base.get(bd); if(!s){ s = new Set(); base.set(bd, s); } s.add(n); }
  for(const [bd, s] of base){ const long = [...s].filter(n => n.split('.')[0].length >= 30); if(s.size >= 30 && long.length >= 10) add('amber', 'Possible DNS tunnelling', `${s.size} different long names under ${bd}, e.g. ${long[0].slice(0, 60)}…`, 'dns'); }
  const nx = A.dns.filter(d => d.rc === 3); if(nx.length >= 20) add('amber', `${nx.length} lookups for names that do not exist`, 'Many failed lookups can mean a DGA or a misconfigured client.', 'dns');
  const exe = A.http.filter(h => h.body && h.body.length > 1 && ((h.body[0] === 0x4d && h.body[1] === 0x5a) || /x-dosexec|x-msdownload|x-executable|octet-stream/i.test(h.ctype) && /\.(exe|dll|scr|ps1|bat|hta|vbs|js|msi)(\?|$)/i.test(h.url)));
  if(exe.length) add('red', 'Program downloaded over plain HTTP', exe.slice(0, 3).map(h => h.url.slice(0, 90)).join(' · '), 'http');
  const ipOnly = A.tls.filter(t => !t.sni && !pcPriv(t.sip)); if(ipOnly.length) add('amber', `${ipOnly.length} TLS connection${ipOnly.length === 1 ? '' : 's'} with no server name`, 'Browsers always send a name; malware and scripts often connect to a bare IP. ' + [...new Set(ipOnly.map(t => t.srv))].slice(0, 4).join(', '), 'tls');
  const old = A.tls.filter(t => /SSL|1\.0|1\.1/.test(t.ver)); if(old.length) add('amber', 'Outdated TLS versions', [...new Set(old.map(t => t.ver + ' to ' + (t.sni || t.srv)))].slice(0, 4).join(', '), 'tls');
  if(A.trunc) add('amber', 'The capture file is cut off', 'The last packet is incomplete — the capture may have been interrupted or the file truncated.', '');
  return out.sort((a, b) => (a.tone === 'red' ? 0 : 1) - (b.tone === 'red' ? 0 : 1));
}

/* ---------- view ---------- */
const PC_TABS = [['sum','Overview'],['flows','Conversations'],['hosts','Hosts'],['dns','DNS'],['http','HTTP'],['tls','TLS'],['creds','Logins']];
const pcT = t => t ? E.fmtFull(Math.floor(t), tz()) + '.' + String(Math.floor(t % 1000)).padStart(3, '0') : '—';
const pcDur = ms => ms < 1000 ? Math.round(ms) + ' ms' : ms < 60000 ? (ms / 1000).toFixed(1) + ' s' : ms < 3600000 ? (ms / 60000).toFixed(1) + ' min' : (ms / 3600000).toFixed(1) + ' h';
function labPcap(){
  const A = UI.pcap;
  if(!A) return `<label class="drop" id="pcDrop" tabindex="0"><input type="file" id="pcIn" accept=".pcap,.pcapng,.cap,.dmp" class="sr">${ico('network')}<b>Drop a packet capture, or click to choose</b>
    <span>.pcap or .pcapng from Wireshark, tcpdump or a firewall — up to 300 MB. Read locally; nothing is uploaded.</span>
    <span class="drop-feat"><i>Conversations</i><i>Hosts &amp; MACs</i><i>DNS</i><i>HTTP &amp; files</i><i>TLS SNI · JA3</i><i>Cleartext logins</i><i>Beacons &amp; scans</i><i>Follow stream</i><i>Flag finder</i></span></label>
    <p class="t3" style="font-size:13px;margin:12px 2px 0">Encrypted traffic (HTTPS, SSH, QUIC, VPN) cannot be decrypted without its keys — you still see who talked to whom, when, how much, and the server name from the TLS handshake.</p>`;
  if(A.busy) return `<div class="card" style="padding:40px;text-align:center">${ico('refresh-cw','sm spin')} Reading ${esc(A.name)}…</div>`;
  if(UI.pcSel) return pcStreamView(A);
  const t = PC_TABS.some(x => x[0] === UI.pcTab) ? UI.pcTab : 'sum', cnt = {flows:A.flows.size, hosts:A.hosts.size, dns:A.dns.length, http:A.http.length, tls:A.tls.length, creds:A.creds.length};
  return `${flagBox(A.flags || [])}<section class="card pc-head"><header><span class="fi-ic">${ico('network')}</span><div style="min-width:0;flex:1"><h3>${esc(A.name)}</h3>
      <p class="t3">${esc(A.fmt)} · ${esc(A.links.map(l => PC_LINKS[l] || 'link type ' + l).join(', '))} · ${A.n.toLocaleString()} packets · ${fmtBytes(A.bytes)} · ${A.first ? pcDur(A.last - A.first) : 'no timestamps'}</p></div>
      <div class="wrap"><button class="btn sm" data-act="pcSave">${ico('plus','sm')}Save to ${esc(theCase().code)}</button><button class="btn sm" data-act="pcEvents">${ico('list-plus','sm')}Send events to timeline</button><button class="btn sm" data-act="pcClear">${ico('x','sm')}Another file</button></div></header></section>
    <nav class="seg pc-tabs" role="tablist">${PC_TABS.map(([k, l]) => `<button role="tab" data-act="pcTab" data-v="${k}" aria-pressed="${t === k}">${l}${cnt[k] != null ? ` <small>${cnt[k].toLocaleString()}</small>` : ''}</button>`).join('')}</nav>
    ${t === 'sum' ? '' : `<div class="pc-filter search-in">${ico('search')}<label class="sr" for="pcq">Filter</label><input id="pcq" class="inp" placeholder="Filter this table…" value="${esc(UI.pcq || '')}"></div>`}
    <div id="pcBody">${pcTable(A, t)}</div>`;
}
function pcRows(rows, q, fn){ q = (q || '').toLowerCase(); const f = q ? rows.filter(r => fn(r).toLowerCase().includes(q)) : rows; return {f, more:f.length > 500 ? `<p class="t3 pc-more">Showing 500 of ${f.length.toLocaleString()} — filter to narrow down.</p>` : ''}; }
const pcTag = (ip) => { const c = E.ipClass(ip) || ''; return /^Public/.test(c) ? ctxChips(ip.includes(':') ? 'ipv6' : 'ipv4', ip) : `<span class="cxt">${esc(c.replace(/ —.*/, ''))}</span>`; };
const pcFollow = id => `<button class="btn xs" data-act="pcFollow" data-v="${id}">${ico('scroll-text','sm')}Follow</button>`;
function pcTable(A, t){
  const q = UI.pcq || '';
  if(t === 'sum'){
    const pr = Object.entries(A.proto).sort((a, b) => b[1] - a[1]), tot = pr.reduce((a, b) => a + b[1], 0) || 1;
    const talk = [...A.hosts.values()].sort((a, b) => (b.sent + b.recv) - (a.sent + a.recv)).slice(0, 8);
    const names = [...new Set([...A.tls.map(x => x.sni), ...A.http.map(x => x.host), ...A.dns.filter(d => !d.mdns).map(d => d.name)].filter(Boolean).map(s => s.toLowerCase().replace(/:\d+$/, '')))];
    return `<div class="pc-grid">
      <section class="card pc-wide"><header><h3>Findings</h3><span class="t3 small">${A.findings.length ? A.findings.length + ' to review' : ''}</span></header><div class="body pc-fbody">${A.findings.length ? `<ul class="pc-finds">${A.findings.map(f => `<li><span class="sev ${f.tone === 'red' ? 'high' : 'med'}">${f.tone === 'red' ? 'High' : 'Medium'}</span><div class="pf-main"><b>${esc(f.title)}</b><p>${esc(f.detail)}</p></div>${f.view ? `<button class="btn xs ghost" data-act="pcTab" data-v="${f.view}">${esc({flows:'Conversations', hosts:'Hosts', dns:'DNS', http:'HTTP', tls:'TLS', creds:'Logins'}[f.view] || 'View')}${ico('chevron-right','sm')}</button>` : ''}</li>`).join('')}</ul>` : `<p class="t3" style="margin:0;font-size:13.5px">Nothing stands out — no cleartext logins, beacons, scans or ports typical of malware.</p>`}</div></section>
      <section class="card"><header><h3>Capture</h3></header><div class="body">
        <div class="kv"><span>First packet</span><b class="mono">${pcT(A.first)}</b></div><div class="kv"><span>Last packet</span><b class="mono">${pcT(A.last)}</b></div>
        <div class="kv"><span>Hosts</span><b>${A.hosts.size.toLocaleString()} (${[...A.hosts.keys()].filter(ip => !pcPriv(ip)).length} public)</b></div><div class="kv"><span>Conversations</span><b>${A.flows.size.toLocaleString()}</b></div>
        ${A.other ? `<div class="kv"><span>Not decoded</span><b>${A.other.toLocaleString()} frames</b></div>` : ''}${A.frag ? `<div class="kv"><span>IP fragments</span><b>${A.frag.toLocaleString()}</b></div>` : ''}
        <div class="kv"><span>SHA-256</span><code style="font-size:11.5px;word-break:break-all">${A.sha256}</code></div></div></section>
      <section class="card"><header><h3>Protocols</h3></header><div class="body">${pr.slice(0, 12).map(([k, v]) => `<div class="pc-bar"><span>${esc(k)}</span><i><b style="width:${Math.max(1, v / tot * 100)}%"></b></i><small>${v.toLocaleString()}</small></div>`).join('')}</div></section>
      <section class="card"><header><h3>Top talkers</h3></header><div class="body">${talk.map(h => `<div class="pc-bar"><span class="mono">${esc(h.ip)}</span><i><b style="width:${Math.max(1, (h.sent + h.recv) / ((talk[0].sent + talk[0].recv) || 1) * 100)}%"></b></i><small>${fmtBytes(h.sent + h.recv)}</small></div>`).join('')}</div></section>
      ${names.length ? `<section class="card pc-wide"><header><h3>Names contacted <small class="t3">${names.length}</small></h3></header><div class="body"><div class="pc-names">${names.slice(0, 120).map(n => `<code>${esc(n)}</code>`).join('')}</div></div></section>` : ''}
    </div>`;
  }
  if(t === 'flows'){ const rows = [...A.flows.values()].sort((a, b) => b.by - a.by), {f, more} = pcRows(rows, q, F => [F.tr, F.svc, F.cli.ip, F.srv.ip, F.srv.port].join(' '));
    return `<div class="tblwrap"><table class="tbl pc-t"><thead><tr><th>Client</th><th>Server</th><th>Service</th><th class="num">Packets</th><th class="num">Bytes</th><th>Start</th><th class="num">Duration</th><th></th></tr></thead><tbody>${f.slice(0, 500).map(F => `<tr${PC_SUS[F.srv.port] ? ' class="bad"' : ''}><td class="mono">${esc(pcHP(F.cli.ip, F.cli.port))}</td><td class="mono">${esc(pcHP(F.srv.ip, F.srv.port))} ${pcTag(F.srv.ip)}</td><td>${esc(F.svc)}${F.rst && !F.pl[1] ? ' <span class="cxt">refused</span>' : ''}</td><td class="num">${F.pk.toLocaleString()}</td><td class="num">${fmtBytes(F.by)}</td><td class="mono small">${pcT(F.first).slice(11)}</td><td class="num">${pcDur(F.last - F.first)}</td><td>${F.pl[0] || F.pl[1] ? pcFollow(F.id) : ''}</td></tr>`).join('')}</tbody></table></div>${more}`; }
  if(t === 'hosts'){ const rows = [...A.hosts.values()].sort((a, b) => (b.sent + b.recv) - (a.sent + a.recv)), {f, more} = pcRows(rows, q, h => [h.ip, ...h.macs, ...h.names, ...h.svc].join(' '));
    return `<div class="tblwrap"><table class="tbl pc-t"><thead><tr><th>Address</th><th>Names</th><th>MAC</th><th>Serves</th><th class="num">Sent</th><th class="num">Received</th><th class="num">Peers</th><th></th></tr></thead><tbody>${f.slice(0, 500).map(h => `<tr><td class="mono">${esc(h.ip)} ${pcTag(h.ip)}</td><td>${[...h.names].slice(0, 4).map(n => `<code>${esc(n)}</code>`).join(' ')}</td><td class="mono small">${[...h.macs].slice(0, 2).map(esc).join('<br>')}</td><td class="small">${[...h.svc].slice(0, 6).map(esc).join(', ')}</td><td class="num">${fmtBytes(h.sent)}</td><td class="num">${fmtBytes(h.recv)}</td><td class="num">${h.peers.size}</td><td><button class="btn xs" data-act="pcFilter" data-v="${esc(h.ip)}" data-t="flows">Conversations</button></td></tr>`).join('')}</tbody></table></div>${more}
      ${A.dhcp.length ? `<h4 class="caps" style="margin:18px 0 8px">DHCP</h4><div class="tblwrap"><table class="tbl pc-t"><thead><tr><th>Time</th><th>Message</th><th>MAC</th><th>Hostname</th><th>Address</th><th>Vendor class</th></tr></thead><tbody>${A.dhcp.slice(0, 300).map(x => `<tr><td class="mono small">${pcT(x.t)}</td><td>${esc(String(x.type || ''))}</td><td class="mono">${esc(x.mac)}</td><td>${esc(x.host || x.fqdn || '')}</td><td class="mono">${esc(x.ip || x.req || '')}</td><td class="small">${esc(x.vendor || '')}</td></tr>`).join('')}</tbody></table></div>` : ''}`; }
  if(t === 'dns'){ const {f, more} = pcRows(A.dns, q, d => [d.name, d.type, d.cli, d.srv, ...d.ans].join(' '));
    return f.length ? `<div class="tblwrap"><table class="tbl pc-t"><thead><tr><th>Time</th><th>Client</th><th>Query</th><th>Type</th><th>Answer</th></tr></thead><tbody>${f.slice(0, 500).map(d => `<tr><td class="mono small">${pcT(d.t)}</td><td class="mono">${esc(d.cli)}</td><td class="mono pc-wrap">${esc(d.name)}${d.mdns ? ' <span class="cxt">local</span>' : ''}</td><td>${esc(String(d.type))}</td><td class="mono small pc-wrap">${d.rc === 3 ? '<span class="cxt red">does not exist</span>' : d.rc ? '<span class="cxt amber">error ' + d.rc + '</span>' : ''}${d.ans.slice(0, 6).map(esc).join('<br>')}${d.rc == null ? '<span class="t3">no reply</span>' : ''}</td></tr>`).join('')}</tbody></table></div>${more}` : pcEmpty('No DNS in this capture.'); }
  if(t === 'http'){ const {f, more} = pcRows(A.http, q, h => [h.method, h.url, h.ua, h.code, h.ctype, h.cli].join(' '));
    return f.length ? `<div class="tblwrap"><table class="tbl pc-t"><thead><tr><th>Time</th><th>Client</th><th>Request</th><th>Status</th><th>Type</th><th class="num">Size</th><th></th></tr></thead><tbody>${f.slice(0, 500).map(h => { const i = A.http.indexOf(h); return `<tr><td class="mono small">${pcT(h.t)}</td><td class="mono">${esc(h.cli)}</td><td class="pc-wrap"><b>${esc(h.method)}</b> <span class="mono">${esc(h.url.slice(0, 160))}</span>${h.ua ? `<div class="t3 small">${esc(h.ua.slice(0, 120))}</div>` : ''}</td><td>${h.code ? `<span class="cxt${h.code >= 400 ? ' amber' : ''}">${h.code}</span>` : '<span class="t3">—</span>'}</td><td class="small">${esc(h.ctype)}</td><td class="num">${h.size ? fmtBytes(h.size) : ''}</td><td class="nowrap">${h.size ? `<button class="btn xs" data-act="pcObj" data-v="${i}">${ico('download','sm')}File</button>` : ''} ${pcFollow(h.fid)}</td></tr>`; }).join('')}</tbody></table></div>${more}` : pcEmpty('No plain HTTP in this capture — web traffic is probably HTTPS (see TLS).'); }
  if(t === 'tls'){ const {f, more} = pcRows(A.tls, q, x => [x.sni, x.srv, x.cli, x.ja3, x.alpn, x.ver, ...x.names].join(' '));
    return f.length ? `<div class="tblwrap"><table class="tbl pc-t"><thead><tr><th>Time</th><th>Client</th><th>Server name (SNI)</th><th>Server</th><th>Version</th><th>ALPN</th><th>JA3</th></tr></thead><tbody>${f.slice(0, 500).map(x => `<tr><td class="mono small">${pcT(x.t)}</td><td class="mono">${esc(x.cli)}</td><td class="mono pc-wrap">${x.sni ? esc(x.sni) : '<span class="cxt amber">none</span>'}${x.names.length ? `<div class="t3 small">certificate: ${x.names.map(esc).join(' · ')}</div>` : ''}</td><td class="mono">${esc(x.srv)} ${pcTag(x.sip)}</td><td>${esc(x.ver)}</td><td class="small">${esc(x.alpn)}</td><td><code class="small" title="${esc(x.ja3s)}">${x.ja3}</code> <button class="iconbtn" data-act="flagCopy" data-v="${x.ja3}" aria-label="Copy JA3">${ico('copy','sm')}</button></td></tr>`).join('')}</tbody></table></div>${more}
      <p class="t3 small" style="margin:10px 2px 0">JA3 fingerprints the client software from its handshake. Search a hash on <a href="https://ja3.zone/" target="_blank" rel="noopener noreferrer">ja3.zone</a> or in your threat intel to spot known malware.</p>` : pcEmpty('No TLS handshakes in this capture.'); }
  if(t === 'creds'){ const show = !!UI.pcShow, {f, more} = pcRows(A.creds, q, c => [c.proto, c.user, c.srv, c.cli, c.how].join(' '));
    return f.length ? `<div class="wrap" style="margin:0 0 10px"><label class="chk"><input type="checkbox" data-act="pcShow" ${show ? 'checked' : ''}> Show secrets</label></div><div class="tblwrap"><table class="tbl pc-t"><thead><tr><th>Time</th><th>Protocol</th><th>Client</th><th>Server</th><th>User</th><th>Secret</th><th>How</th><th></th></tr></thead><tbody>${f.slice(0, 500).map(c => `<tr><td class="mono small">${pcT(c.t)}</td><td><span class="cxt red">${esc(c.proto)}</span></td><td class="mono">${esc(c.cli)}</td><td class="mono">${esc(c.srv)}</td><td class="mono">${esc(c.user)}</td><td class="mono">${c.pass ? (show ? esc(c.pass) : '•'.repeat(Math.min(12, c.pass.length))) : ''}</td><td class="small pc-wrap">${esc(c.how)}</td><td>${c.fid ? pcFollow(c.fid) : ''}</td></tr>`).join('')}</tbody></table></div>${more}` : pcEmpty('No cleartext logins found. Encrypted protocols (HTTPS, SSH, IMAPS…) hide them — as they should.'); }
  return '';
}
const pcEmpty = s => `<div class="card" style="padding:28px;text-align:center" ><p class="t3" style="margin:0">${esc(s)}</p></div>`;
function pcStreamView(A){
  const F = [...A.flows.values()].find(x => x.id === UI.pcSel); if(!F){ UI.pcSel = null; return labPcap(); }
  const hexMode = UI.pcHex, ch = []; let n = 0; const parts = [];
  for(const c of pcChunks(F)){ const last = ch[ch.length - 1]; if(last && last.dir === c.dir) last.parts.push(c.d); else ch.push({dir:c.dir, parts:[c.d]}); }
  for(const c of ch) c.d = pcCat(c.parts);
  for(const c of ch){ if(n > 400000){ parts.push('<div class="t3">… the rest is cut off here — download the stream for all of it.</div>'); break; }
    const d = c.d.subarray(0, 400000 - n); n += d.length;
    parts.push(`<div class="pc-chunk d${c.dir}">${hexMode ? esc(hexdump(d)) : esc(latin1(d).replace(/[^\x09\x0a\x0d\x20-\x7e\xa0-\xff]/g, '·'))}</div>`); }
  const enc = /HTTPS|TLS|SSH/.test(F.svc);
  return `<section class="card"><header><button class="btn sm" data-act="pcBack">${ico('arrow-left','sm')}Back</button><div style="min-width:0;flex:1;margin-left:6px"><h3 class="mono" style="font-size:14.5px">${esc(pcHP(F.cli.ip, F.cli.port))} → ${esc(pcHP(F.srv.ip, F.srv.port))}</h3><p class="t3">${esc(F.tr)} · ${esc(F.svc)} · ${F.pk.toLocaleString()} packets · client sent ${fmtBytes(F.pl[0])}, server sent ${fmtBytes(F.pl[1])} · ${pcT(F.first)}</p></div>
    <div class="wrap"><div class="seg sm"><button data-act="pcHex" data-v="0" aria-pressed="${!hexMode}">Text</button><button data-act="pcHex" data-v="1" aria-pressed="${!!hexMode}">Hex</button></div><button class="btn sm" data-act="pcDlStream" data-v="${F.id}">${ico('download','sm')}Download</button></div></header>
    <div class="body">${enc ? `<p class="note" style="margin:0 0 10px"><span class="ic">${ico('lock','sm')}</span><span>This conversation is encrypted. Without the session keys the content below is ciphertext; the handshake at the start is readable.</span></p>` : ''}
    <div class="pc-legend"><span class="d0">Client</span><span class="d1">Server</span></div><pre class="pc-stream">${parts.join('') || '<span class="t3">No payload.</span>'}</pre></div></section>`;
}
function bindPcap(){
  const inp = $('pcIn'), d = $('pcDrop');
  if(inp){ inp.onchange = () => { if(inp.files[0]) pcLoad(inp.files[0]); }; d.ondragover = e => { e.preventDefault(); d.classList.add('over'); }; d.ondragleave = () => d.classList.remove('over');
    d.ondrop = e => { e.preventDefault(); d.classList.remove('over'); const f = e.dataTransfer.files[0]; if(f) pcLoad(f); }; d.onkeydown = e => { if(e.key === 'Enter' || e.key === ' '){ e.preventDefault(); inp.click(); } }; }
  const q = $('pcq'); if(q) q.oninput = () => { clearTimeout(q.__t); q.__t = setTimeout(() => { UI.pcq = q.value; const b = $('pcBody'); if(b && UI.pcap) b.innerHTML = pcTable(UI.pcap, UI.pcTab || 'sum'); }, 150); };
}
async function pcLoad(f){
  if(f.size > 300 * 1048576) return toast('That capture is over 300 MB — split it with editcap or tshark first');
  UI.pcap = {busy:true, name:f.name}; UI.pcSel = null; UI.pcq = ''; UI.pcTab = 'sum'; renderMain();
  try{ UI.pcap = await pcapAnalyse(f); }catch(e){ UI.pcap = null; toast(e.message && /pcap/.test(e.message) ? e.message : 'Could not read that capture'); }
  renderMain();
}
function pcSummary(A){
  const L = [`Packet capture: ${A.name}`, `SHA-256: ${A.sha256}`, `Format: ${A.fmt}, ${A.n} packets, ${fmtBytes(A.bytes)}`, `From ${pcT(A.first)} to ${pcT(A.last)} (${tz()})`, ''];
  if(A.findings.length){ L.push('Findings:'); for(const f of A.findings) L.push('- ' + f.title + ': ' + f.detail); L.push(''); }
  L.push('Top conversations:'); for(const F of [...A.flows.values()].sort((a, b) => b.by - a.by).slice(0, 25)) L.push(`- ${pcHP(F.cli.ip, F.cli.port)} -> ${pcHP(F.srv.ip, F.srv.port)} ${F.svc} ${F.pk} pkts ${fmtBytes(F.by)}`);
  const pub = [...A.hosts.values()].filter(h => !pcPriv(h.ip)); if(pub.length){ L.push('', 'Public hosts:'); for(const h of pub.slice(0, 80)) L.push(`- ${h.ip}${h.names.size ? ' (' + [...h.names].slice(0, 3).join(', ') + ')' : ''}`); }
  const sn = [...new Set(A.tls.map(t => t.sni).filter(Boolean))]; if(sn.length) L.push('', 'TLS server names:', ...sn.slice(0, 80).map(s => '- ' + s));
  if(A.http.length) L.push('', 'HTTP requests:', ...A.http.slice(0, 60).map(h => `- ${h.method} ${h.url}${h.code ? ' -> ' + h.code : ''}`));
  const ja = [...new Set(A.tls.map(t => t.ja3))]; if(ja.length) L.push('', 'JA3 fingerprints:', ...ja.slice(0, 20).map(j => '- ' + j));
  if(A.creds.length) L.push('', 'Cleartext logins:', ...A.creds.slice(0, 40).map(c => `- ${c.proto} ${c.cli} -> ${c.srv} user "${c.user}"${c.pass ? ' secret "' + c.pass + '"' : ''} (${c.how})`));
  return L.join('\n');
}
async function pcSave(){
  const A = UI.pcap; if(!A || A.busy) return; const cid = DB.active, body = pcSummary(A); let att = null;
  if(A.size <= 50 * 1048576){ try{ att = await storeFile(A.file); }catch(e){} }
  const r = {id:uid('r'), caseId:cid, type:'evidence', title:'Packet capture: ' + A.name, body, tsRaw:A.first ? new Date(A.first).toISOString() : '', tsZone:'explicit', ts:A.first || null, source:'pcap', host:'', tags:['pcap', 'network'], ents:extractRich(body), answer:'', addedBy:'You', addedAt:Date.now(), hash:'', pv:1, att:att ? [att] : []};
  DB.records.push(r); mutate('saved capture ' + A.name); await hashRecords(); renderAll();
  toast('Saved to ' + theCase(cid).code + (att ? ' with the capture file attached' : ' (file over 50 MB — not attached)'), 'Open', () => { UI.sel = {kind:'rec', id:r.id}; UI.inspOpen = true; go(caseHash(cid, 'timeline')); });
}
function pcEvents(){
  const A = UI.pcap; if(!A || A.busy) return; const rows = [], iso = t => t ? new Date(t).toISOString() : '';
  for(const d of A.dns) if(!d.mdns) rows.push({time:iso(d.t), event:'DNS ' + d.type + ' ' + d.name, src:d.cli, dst:d.srv, proto:'dns', query:d.name, answer:d.ans.join(' ')});
  for(const h of A.http) rows.push({time:iso(h.t), event:h.method + ' ' + h.url.slice(0, 90) + (h.code ? ' → ' + h.code : ''), src:h.cli, dst:h.srv, proto:'http', url:h.url, user_agent:h.ua, status:h.code || '', content_type:h.ctype});
  for(const x of A.tls) rows.push({time:iso(x.t), event:'TLS to ' + (x.sni || x.srv), src:x.cli, dst:x.srv, proto:'tls', sni:x.sni, ja3:x.ja3, version:x.ver});
  for(const c of A.creds) rows.push({time:iso(c.t), event:c.proto + ' login ' + (c.user || ''), src:c.cli, dst:c.srv, proto:c.proto.toLowerCase(), user:c.user, how:c.how});
  const seen = new Set(rows.map(r => r.src + '>' + r.dst));
  for(const F of [...A.flows.values()].sort((a, b) => a.first - b.first)) if(F.srv.port != null && !seen.has(F.cli.ip + '>' + pcHP(F.srv.ip, F.srv.port)) && !pcPriv(F.srv.ip)) rows.push({time:iso(F.first), event:F.tr + ' ' + F.svc + ' to ' + pcHP(F.srv.ip, F.srv.port), src:F.cli.ip, dst:pcHP(F.srv.ip, F.srv.port), proto:F.tr.toLowerCase(), bytes:F.by, packets:F.pk});
  if(!rows.length) return toast('No events to send');
  rows.sort((a, b) => a.time < b.time ? -1 : 1);
  const cols = [...new Set(rows.flatMap(r => Object.keys(r)))];
  LOGIMP = {title:'Send capture events to the timeline', caseId:DB.active, name:A.name, fmt:'packet capture', rows, cols, map:{time:'time', title:'event', host:'src', source:'proto'}}; logImportDlg();
}
async function pcObj(i){
  const h = UI.pcap && UI.pcap.http[+i]; if(!h || !h.body) return; let data = h.body;
  if(/gzip|deflate/i.test(h.enc) && typeof DecompressionStream !== 'undefined'){ try{ data = new Uint8Array(await new Response(new Blob([data]).stream().pipeThrough(new DecompressionStream(/gzip/i.test(h.enc) ? 'gzip' : 'deflate'))).arrayBuffer()); }catch(e){} }
  let name = (h.disp.match(/filename\*?=(?:UTF-8'')?"?([^";]+)/i) || [])[1] || decodeURIComponent((h.url.split('?')[0].split('/').pop() || '')) || 'object';
  name = name.replace(/[\\/:*?"<>|]+/g, '_').slice(0, 100) || 'object';
  confirmDlg('Save file from the capture?', `${name} · ${fmtBytes(data.length)} · ${h.ctype || 'unknown type'}. Files taken from network traffic can be malicious — open it only in a safe environment.`, 'Save file', () => download(name, new Blob([data], {type:'application/octet-stream'})), true);
}
function pcDlStream(id){ const A = UI.pcap, F = A && [...A.flows.values()].find(x => x.id === +id); if(!F) return; download(`stream-${F.cli.ip}-${F.cli.port}-${F.srv.ip}-${F.srv.port}.bin`.replace(/:/g, '_'), new Blob(pcChunks(F).map(c => c.d), {type:'application/octet-stream'})); }
const PCAP_ACTS = {
  pcTab:(id, v) => { UI.pcTab = v; UI.pcq = ''; renderMain(); }, pcClear:() => { UI.pcap = null; UI.pcSel = null; renderMain(); },
  pcFollow:(id, v) => { UI.pcSel = +v; UI.pcHex = false; renderMain(); const s = $('main').querySelector('.scroll'); if(s) s.scrollTop = 0; }, pcBack:() => { UI.pcSel = null; renderMain(); }, pcHex:(id, v) => { UI.pcHex = v === '1'; renderMain(); },
  pcShow:() => { UI.pcShow = !UI.pcShow; const b = $('pcBody'); if(b) b.innerHTML = pcTable(UI.pcap, 'creds'); },
  pcFilter:(id, v, el) => { UI.pcTab = el.dataset.t || 'flows'; UI.pcq = v; renderMain(); },
  pcSave:() => pcSave(), pcEvents:() => pcEvents(), pcObj:(id, v) => pcObj(v), pcDlStream:(id, v) => pcDlStream(v)
};
