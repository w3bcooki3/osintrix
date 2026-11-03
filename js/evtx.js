/* ==========================================================================
   Windows event log (.evtx) reader. Runs in the page; nothing is uploaded.
   File header → 64 KB chunks → records of binary XML (BinXML) built from
   templates. Each event comes out flat: the System fields (EventID, Provider,
   Channel, Computer, TimeCreated, …) plus every EventData / UserData field.
   Format notes: libevtx documentation and python-evtx (Apache-2.0) were used
   as references for the structure; this is an independent implementation.
   ========================================================================== */
const EVTX = (() => {
  const td16 = new TextDecoder('utf-16le'), td8 = new TextDecoder('latin1');
  const hex = (n, w) => '0x' + n.toString(16).padStart(w, '0');
  const ft2iso = (lo, hi) => { const t = (hi * 4294967296 + lo) / 1e4 - 11644473600000; return isFinite(t) && t > 0 && t < 4102444800000 ? new Date(t).toISOString() : ''; };

  function parse(buf, opts = {}){
    const u8 = new Uint8Array(buf), dv = new DataView(buf), N = u8.length, max = opts.max || 200000;
    const sig = (o, s) => { for(let i = 0; i < s.length; i++) if(u8[o + i] !== s.charCodeAt(i)) return false; return true; };
    if(N < 4096 || !sig(0, 'ElfFile\0')) throw new Error('Not a Windows event log (.evtx) file');
    const out = {events:[], chunks:0, badChunks:0, badRecords:0, truncated:false};
    const wstr = (o, chars) => { let s = td16.decode(u8.subarray(o, o + chars * 2)); const z = s.indexOf('\0'); return z >= 0 ? s.slice(0, z) : s; };
    for(let cb = 4096; cb + 65536 <= N; cb += 65536){
      if(!sig(cb, 'ElfChnk\0')){ if(u8[cb] || u8[cb + 1]) out.badChunks++; continue; }
      out.chunks++;
      const names = new Map(), tmpls = new Map(), free = Math.min(65536, dv.getUint32(cb + 48, true) || 65536);
      const name = off => { let s = names.get(off); if(s == null){ const o = cb + off; if(o + 8 > N) return '?'; s = wstr(o + 8, dv.getUint16(o + 6, true)); names.set(off, s); } return s; };
      const nameLen = off => 10 + dv.getUint16(cb + off + 6, true) * 2;

      /* value of a known type and size (substitution arrays); without a size, read the self-sized form (value tokens) */
      function value(t, o, size){
        if(t & 0x80){ const bt = t & 0x7f, s = sized(bt);
          if(bt === 1){ return td16.decode(u8.subarray(o, o + size)).split('\0').filter(Boolean).join(', '); }
          if(s){ const parts = []; for(let k = 0; k + s <= size; k += s) parts.push(value(bt, o + k, s)); return parts.join(', '); }
          return ''; }
        switch(t){
          case 0x00: return '';
          case 0x01: return size == null ? wstr(o + 2, dv.getUint16(o, true)) : wstr(o, size >> 1);
          case 0x02: return size == null ? td8.decode(u8.subarray(o + 2, o + 2 + dv.getUint16(o, true))) : td8.decode(u8.subarray(o, o + size)).replace(/\0+$/, '');
          case 0x03: return String(dv.getInt8(o));
          case 0x04: return String(u8[o]);
          case 0x05: return String(dv.getInt16(o, true));
          case 0x06: return String(dv.getUint16(o, true));
          case 0x07: return String(dv.getInt32(o, true));
          case 0x08: return String(dv.getUint32(o, true));
          case 0x09: return dv.getBigInt64(o, true).toString();
          case 0x0a: return dv.getBigUint64(o, true).toString();
          case 0x0b: return String(dv.getFloat32(o, true));
          case 0x0c: return String(dv.getFloat64(o, true));
          case 0x0d: return dv.getUint32(o, true) ? 'true' : 'false';
          case 0x0e: { const n = size == null ? dv.getUint32(o, true) : size, s = size == null ? o + 4 : o; let h = ''; for(let k = 0; k < Math.min(n, 4096); k++) h += u8[s + k].toString(16).padStart(2, '0'); return h.toUpperCase(); }
          case 0x0f: { const p = k => u8[o + k].toString(16).padStart(2, '0'); return '{' + [hex(dv.getUint32(o, true), 8).slice(2), hex(dv.getUint16(o + 4, true), 4).slice(2), hex(dv.getUint16(o + 6, true), 4).slice(2), p(8) + p(9), [10, 11, 12, 13, 14, 15].map(p).join('')].join('-') + '}'; }
          case 0x10: return size === 4 ? String(dv.getUint32(o, true)) : dv.getBigUint64(o, true).toString();
          case 0x11: return ft2iso(dv.getUint32(o, true), dv.getUint32(o + 4, true));
          case 0x12: { const w = k => dv.getUint16(o + k * 2, true), z = n => String(n).padStart(2, '0'); return `${w(0)}-${z(w(1))}-${z(w(3))}T${z(w(4))}:${z(w(5))}:${z(w(6))}.${String(w(7)).padStart(3, '0')}Z`; }
          case 0x13: { const n = u8[o + 1]; let id = 0; for(let k = 2; k < 8; k++) id = id * 256 + u8[o + k]; let s = `S-${u8[o]}-${id}`; for(let k = 0; k < n; k++) s += '-' + dv.getUint32(o + 8 + k * 4, true); return s; }
          case 0x14: return hex(dv.getUint32(o, true), 8);
          case 0x15: return '0x' + dv.getBigUint64(o, true).toString(16).padStart(16, '0');
          case 0x21: return fragment(o, size == null ? N : o + size).node;
          default: return '';
        }
      }
      const sized = t => ({3:1, 4:1, 5:2, 6:2, 7:4, 8:4, 9:8, 10:8, 11:4, 12:8, 13:4, 15:16, 17:8, 18:16, 20:4, 21:8})[t] || 0;
      const valueLen = (t, o) => { const s = sized(t); if(s) return s; if(t === 1) return 2 + dv.getUint16(o, true) * 2; if(t === 2) return 2 + dv.getUint16(o, true); if(t === 0x0e) return 4 + dv.getUint32(o, true); if(t === 0x13) return 8 + u8[o + 1] * 4; if(t === 0x10) return 8; return 0; };

      /* BinXML → a small tree. Text and attribute values are lists of strings and {s:index, o:optional} placeholders. */
      function element(o, inT){
        const tok = u8[o]; let p = o + 1 + (inT ? 2 : 0) + 4; const no = dv.getUint32(p, true); p += 4;
        if(no === p - cb) p += nameLen(no);                       // the name is stored inline, right here
        if(tok & 0x40) p += 4;                                   // attribute list size
        const el = {n:name(no), a:[], c:[]};
        while(p < N){ const t = u8[p] & 0x0f;
          if(t === 0x06){ const ao = dv.getUint32(p + 1, true); p += 5; if(ao === p - cb) p += nameLen(ao); const r = content(p, true, inT); el.a.push([name(ao), r.parts]); p = r.p; continue; }
          if(t === 0x02){ const r = content(p + 1, false, inT); el.c = r.parts; p = r.p + 1; break; }   // children up to the end-element token
          if(t === 0x03){ p += 1; break; }
          throw new Error('bad element at ' + p);
        }
        return {el, p};
      }
      /* attribute value (stops at the next attribute or close) or element children (stops at end element) */
      function content(p, attr, inT){
        const parts = [];
        while(p < N){ const raw = u8[p], t = raw & 0x0f;
          if(attr && (t === 0x06 || t === 0x02 || t === 0x03)) break;
          if(!attr && t === 0x04) break;
          if(t === 0x00 && !attr) break;
          if(t === 0x01){ const r = element(p, inT); parts.push(r.el); p = r.p; continue; }
          if(t === 0x05){ const vt = u8[p + 1]; parts.push(value(vt, p + 2)); p += 2 + valueLen(vt, p + 2); continue; }
          if(t === 0x0d || t === 0x0e){ parts.push({s:dv.getUint16(p + 1, true), o:t === 0x0e}); p += 4; continue; }
          if(t === 0x08){ parts.push(String.fromCharCode(dv.getUint16(p + 1, true))); p += 3; continue; }
          if(t === 0x09){ const eo = dv.getUint32(p + 1, true); p += 5; if(eo === p - cb) p += nameLen(eo); parts.push(({amp:'&', lt:'<', gt:'>', quot:'"', apos:"'"})[name(eo)] || ''); continue; }
          if(t === 0x07){ const n = dv.getUint16(p + 1, true); parts.push(wstr(p + 3, n)); p += 3 + n * 2; continue; }
          if(t === 0x0a){ const po = dv.getUint32(p + 1, true); p += 5; if(po === p - cb) p += nameLen(po); continue; }
          if(t === 0x0b){ p += 3 + dv.getUint16(p + 1, true) * 2; continue; }
          if(t === 0x0c){ const r = instance(p); parts.push(r.node); p = r.p; continue; }
          if(t === 0x0f){ p += 4; continue; }
          throw new Error('unexpected token ' + raw.toString(16) + ' at ' + p);
        }
        return {parts, p};
      }
      function template(off){
        let T = tmpls.get(off); if(T) return T;
        const o = cb + off, len = dv.getUint32(o + 0x14, true), body = o + 0x18;
        const r = content(body, false, true); T = {tree:r.parts, len:0x18 + len}; tmpls.set(off, T); return T;
      }
      /* template instance: header, the template itself when it is defined here, then the substitution values */
      function instance(p){
        const toff = dv.getUint32(p + 6, true); let q = p + 10;
        const T = template(toff); if(toff === q - cb) q += T.len;
        const n = dv.getUint32(q, true); q += 4; const decl = [];
        for(let k = 0; k < n; k++){ decl.push([dv.getUint16(q, true), u8[q + 2]]); q += 4; }
        const vals = decl.map(([size, t]) => { const v = size ? value(t, q, size) : (t === 0 ? null : ''); q += size; return t === 0 ? null : v; });
        return {node:fill(T.tree, vals), p:q};
      }
      function fill(parts, vals){
        const out = [];
        for(const x of parts){
          if(typeof x === 'string'){ out.push(x); continue; }
          if(x.s != null){ const v = vals[x.s]; if(v == null && x.o) continue; if(v != null) out.push(v); continue; }
          if(Array.isArray(x)){ out.push(...fill(x, vals)); continue; }
          if(x.n){ out.push({n:x.n, a:x.a.map(([k, v]) => [k, fill(v, vals)]), c:fill(x.c, vals)}); continue; }
          out.push(x);
        }
        return out;
      }
      function fragment(p, end){
        if((u8[p] & 0x0f) === 0x0f) p += 4;
        const r = content(p, false, false); return {node:r.parts, p:r.p};
      }

      for(let ro = cb + 512; ro + 24 < cb + free; ){
        if(dv.getUint32(ro, true) !== 0x00002a2a) break;
        const size = dv.getUint32(ro + 4, true); if(size < 28 || ro + size > cb + 65536) break;
        try{
          const tree = fragment(ro + 24, ro + size - 4).node;
          const ev = flatten(tree); ev._rec = dv.getBigUint64(ro + 8, true).toString(); ev._written = ft2iso(dv.getUint32(ro + 16, true), dv.getUint32(ro + 20, true));
          out.events.push(ev); if(out.events.length >= max){ out.truncated = true; return out; }
        }catch(e){ out.badRecords++; if(opts.debug && out.badRecords <= 5) console.log('rec', ro, e.message); }
        ro += size;
      }
    }
    return out;
  }

  /* ---------- tree → flat event ---------- */
  const text = parts => (parts || []).map(x => typeof x === 'string' ? x : x && x.n ? text(x.c) : Array.isArray(x) ? text(x) : '').join('');
  const kids = (el, n) => (el.c || []).flat(Infinity).filter(x => x && x.n && (!n || x.n === n));
  const attr = (el, n) => { const a = (el.a || []).find(([k]) => k === n); return a ? text(a[1]) : ''; };
  function flatten(tree){
    const roots = (Array.isArray(tree) ? tree : [tree]).flat(9).filter(x => x && x.n);
    const evt = roots.find(x => x.n === 'Event') || roots[0]; if(!evt) throw new Error('no event');
    const f = {};
    const sys = kids(evt, 'System')[0];
    if(sys) for(const k of kids(sys)){
      switch(k.n){
        case 'Provider': f.Provider = attr(k, 'Name'); if(attr(k, 'EventSourceName')) f.EventSourceName = attr(k, 'EventSourceName'); break;
        case 'TimeCreated': f.TimeCreated = attr(k, 'SystemTime'); break;
        case 'Correlation': if(attr(k, 'ActivityID')) f.ActivityID = attr(k, 'ActivityID'); break;
        case 'Execution': f.ProcessID = attr(k, 'ProcessID'); f.ThreadID = attr(k, 'ThreadID'); break;
        case 'Security': if(attr(k, 'UserID')) f.UserID = attr(k, 'UserID'); break;
        default: f[k.n] = text(k.c);
      }
    }
    const put = (k, v) => { if(v === '' || v == null) return; k = String(k).replace(/[^\w.-]+/g, '_') || 'Data'; let key = k, n = 2; while(f[key] != null && key !== 'EventID') key = k + '_' + n++; f[key] = v; };
    for(const ed of kids(evt, 'EventData')){ let i = 1;
      for(const d of kids(ed)){ if(d.n === 'Data') put(attr(d, 'Name') || 'Data_' + i++, text(d.c)); else if(d.n === 'Binary') put('Binary', text(d.c)); } }
    for(const ud of kids(evt, 'UserData')) for(const top of kids(ud)){ f.UserDataType = top.n; for(const d of kids(top)){ const sub = kids(d); if(sub.length) for(const s of sub) put(s.n, text(s.c)); else put(d.n, text(d.c)); } }
    const ri = kids(evt, 'RenderingInfo')[0]; if(ri){ const m = kids(ri, 'Message')[0]; if(m) put('Message', text(m.c)); }
    return f;
  }
  return {parse};
})();

/* ---------- import into a case, with every Sigma rule run against the events ---------- */
const EVTX_MAX = 20000;
const EVTX_DROP = new Set(['Version', 'Opcode', 'Keywords', 'ThreadID', 'ProcessID', 'Task', '_written', 'EventSourceName']);
const EVTX_KEY = ['TargetUserName', 'IpAddress', 'LogonType', 'Image', 'CommandLine', 'ServiceName', 'ImagePath', 'TaskName', 'QueryName', 'DestinationIp', 'DestinationPort', 'TargetFilename', 'TargetObject', 'ObjectName', 'ShareName', 'ScriptBlockText', 'SubjectUserName', 'param1', 'Message'];
let EVTXIMP = null;
function evtxName(ev){
  const A = typeof refAll === 'function' ? refAll().secs : {}, sec = /sysmon/i.test(ev.Channel || ev.Provider || '') ? A.sysmon : A.win;
  const row = sec && sec.rows.find(r => String(r[0]) === String(ev.EventID)); return row ? row[1] : '';
}
function evtxRow(ev){
  const id = ev.EventID || '', nm = evtxName(ev), bits = [];
  for(const k of EVTX_KEY) if(ev[k] && ev[k] !== '-' && bits.length < 3) bits.push(k === 'LogonType' ? 'logon type ' + ev[k] : k === 'DestinationPort' ? 'port ' + ev[k] : String(ev[k]).replace(/\s+/g, ' ').slice(0, 70));
  const row = {TimeCreated:ev.TimeCreated || ev._written || '', EventID:id, Summary:[id + (nm ? ' · ' + nm : ''), bits.join(' · ')].filter(Boolean).join(' — '), Computer:ev.Computer || '', Channel:ev.Channel || '', Provider:ev.Provider || '', RecordID:ev._rec || ev.EventRecordID || ''};
  for(const [k, v] of Object.entries(ev)) if(!(k in row) && !EVTX_DROP.has(k) && k !== '_rec' && k !== 'EventRecordID' && v !== '' && v !== '-') row[k] = v;
  return row;
}
const evtxKv = row => Object.entries(row).filter(([k, v]) => v !== '' && k !== 'TimeCreated' && k !== 'Summary').map(([k, v]) => { v = String(v).replace(/\s*\n\s*/g, ' '); return k.replace(/\W+/g, '_') + '=' + (/[\s"]/.test(v) ? '"' + v.replace(/"/g, "'") + '"' : v); }).join(' ');
/* Sigma log sources → which Windows events a rule is written for. A rule only runs on events from its source. */
const SIG_CAT = {process_creation:['sysmon:1', 'security:4688'], network_connection:['sysmon:3'], sysmon_status:['sysmon:4', 'sysmon:16'], process_termination:['sysmon:5', 'security:4689'], driver_load:['sysmon:6'], image_load:['sysmon:7'],
  create_remote_thread:['sysmon:8'], raw_access_thread:['sysmon:9'], process_access:['sysmon:10'], file_event:['sysmon:11'], file_change:['sysmon:2'], registry_event:['sysmon:12', 'sysmon:13', 'sysmon:14'], registry_add:['sysmon:12'], registry_delete:['sysmon:12'],
  registry_set:['sysmon:13'], registry_rename:['sysmon:14'], create_stream_hash:['sysmon:15'], pipe_created:['sysmon:17', 'sysmon:18'], wmi_event:['sysmon:19', 'sysmon:20', 'sysmon:21'], dns_query:['sysmon:22'], file_delete:['sysmon:23', 'sysmon:26'],
  clipboard_capture:['sysmon:24'], process_tampering:['sysmon:25'], file_block_executable:['sysmon:27'], ps_script:['powershell:4104'], ps_module:['powershell:4103'], ps_classic_start:['pshost:400'], ps_classic_provider_start:['pshost:600']};
const SIG_SVC = {security:/^security$/i, system:/^system$/i, application:/^application$/i, sysmon:/sysmon/i, powershell:/powershell\/operational/i, 'powershell-classic':/^windows powershell$/i, windefend:/windows defender/i, taskscheduler:/taskscheduler/i,
  'terminalservices-localsessionmanager':/localsessionmanager/i, 'terminalservices-remoteconnectionmanager':/remoteconnectionmanager/i, rdp:/remotedesktop|terminalservices/i, wmi:/wmi-activity/i, bits:/bits-client/i, 'dns-server':/dns-server|^dns server$/i, codeintegrity:/codeintegrity/i, firewall:/firewall/i, smbclient:/smbclient/i, 'ntlm':/ntlm/i, 'appxdeployment-server':/appxdeployment/i};
function sigSource(code){
  const blk = (String(code).match(/^logsource:\s*\n((?:[ \t]+.*\n?)*)/m) || [])[1] || '', g = k => ((blk.match(new RegExp('^\\s+' + k + ':\\s*([\\w-]+)', 'm')) || [])[1] || '').toLowerCase();
  return {product:g('product'), category:g('category'), service:g('service')};
}
const evtxChan = row => /sysmon/i.test(row.Channel) ? 'sysmon' : /^security$/i.test(row.Channel) ? 'security' : /powershell\/operational/i.test(row.Channel) ? 'powershell' : /^windows powershell$/i.test(row.Channel) ? 'pshost' : (row.Channel || '').toLowerCase();
function sigFits(src, row){
  if(src.product && src.product !== 'windows') return false;
  if(src.category){ const want = SIG_CAT[src.category]; if(!want) return false; return want.includes(evtxChan(row) + ':' + row.EventID); }
  if(src.service){ const re = SIG_SVC[src.service]; return re ? re.test(row.Channel || '') : false; }
  return true;
}
/* every Sigma rule against every event it is written for; returns hits per row index */
async function evtxSigma(rows, onProgress){
  ensureRules();
  const rules = DB.rules.filter(r => r.type === 'sigma').map(r => { try{ const p = sigmaParse(r.code), src = sigSource(r.code); return p.cond && Object.keys(p.det).length && (!src.product || src.product === 'windows') ? [r, p, src] : null; }catch(e){ return null; } }).filter(Boolean);
  const F = rows.map(row => recFields({title:row.Summary, body:evtxKv(row), host:row.Computer, source:row.Channel}));
  const hits = new Map(), per = new Map(); let n = 0;
  for(const [r, p, src] of rules){
    for(let i = 0; i < F.length; i++){ if(!sigFits(src, rows[i])) continue; let ok = false; try{ ok = sigmaEval(p, F[i]); }catch(e){ break; }
      if(ok){ (hits.get(i) || hits.set(i, []).get(i)).push(r); per.set(r, (per.get(r) || 0) + 1); } }
    if(++n % 20 === 0){ if(onProgress) onProgress(n / rules.length); await new Promise(res => setTimeout(res, 0)); }
  }
  return {hits, per:[...per.entries()].sort((a, b) => (SEV_ORDER[b[0].severity] || 0) - (SEV_ORDER[a[0].severity] || 0) || b[1] - a[1]), rules:rules.length};
}
function evtxImportFile(f){
  if(f.size > 300 * 1048576) return toast('Event logs over 300 MB are too big to read here — export a filtered log first');
  toast('Reading ' + f.name + '…');
  const fr = new FileReader();
  fr.onload = () => setTimeout(async () => {
    let P; try{ P = EVTX.parse(fr.result); }catch(e){ return toast(e.message || 'That file could not be read'); }
    if(!P.events.length) return toast('No events found in ' + f.name + (P.badRecords ? ' (' + P.badRecords + ' damaged records)' : ''));
    const all = P.events.map(evtxRow).sort((a, b) => String(a.TimeCreated).localeCompare(String(b.TimeCreated)));
    const rows = all.length > EVTX_MAX ? all.slice(-EVTX_MAX) : all;
    EVTXIMP = {caseId:capCase(), name:f.name, size:f.size, total:all.length, rows, P, sig:null, only:false};
    evtxDlg();
    EVTXIMP.sig = await evtxSigma(rows, x => { const b = $('evSigBar'); if(b) b.style.width = Math.round(x * 100) + '%'; });
    if($('evtxDlg')) evtxDlg();
  }, 30);
  fr.readAsArrayBuffer(f);
}
function evtxDlg(){
  const L = EVTXIMP, R = L.rows, c = theCase(L.caseId), sev = s => { const [l, col] = sevOf(s); return `<span class="sevt" style="--c:${col}">${l}</span>`; };
  const ids = countBy(R, r => r.EventID + '|' + (/sysmon/i.test(r.Channel) ? 'Sysmon' : r.Channel)).slice(0, 8);
  const hosts = countBy(R, r => r.Computer).filter(([h]) => h), chans = countBy(R, r => r.Channel).filter(([h]) => h);
  const t0 = R[0].TimeCreated, t1 = R[R.length - 1].TimeCreated, S = L.sig, nHit = S ? S.hits.size : 0;
  const body = `<div class="in evtx" id="evtxDlg">
    <div class="evx-sum"><div><b>${L.total.toLocaleString()}</b><span>events</span></div><div><b>${hosts.length}</b><span>host${hosts.length === 1 ? '' : 's'}</span></div><div><b>${chans.length}</b><span>log${chans.length === 1 ? '' : 's'}</span></div><div><b>${S ? nHit.toLocaleString() : '…'}</b><span>matched a rule</span></div></div>
    <p class="t2 evx-range">${ico('clock','sm')}${esc(E.fmtFull(Date.parse(t0), tz()).slice(0, 16))} → ${esc(E.fmtFull(Date.parse(t1), tz()).slice(0, 16))}${hosts.length ? ' · ' + esc(hosts.slice(0, 3).map(h => h[0]).join(', ')) + (hosts.length > 3 ? '…' : '') : ''}${L.P.badRecords ? ` · <span class="t3">${L.P.badRecords} damaged record${L.P.badRecords > 1 ? 's' : ''} skipped</span>` : ''}</p>
    ${L.total > R.length ? `<p class="note amber"><span class="ic">${ico('triangle-alert','sm')}</span><span>The log has ${L.total.toLocaleString()} events; the latest ${R.length.toLocaleString()} are used. Filter the log in Event Viewer for an earlier period.</span></p>` : ''}
    <div class="evx-cols">
      <section><h4 class="caps">Most frequent events</h4>${ids.map(([k, n]) => { const [id, ch] = k.split('|'), nm = evtxName({EventID:id, Channel:ch}); return `<div class="evx-r"><code>${esc(id)}</code><span>${esc(nm || ch)}</span><b>${n.toLocaleString()}</b></div>`; }).join('')}</section>
      <section><h4 class="caps">Detections</h4>${S ? (S.per.length ? S.per.slice(0, 8).map(([r, n]) => `<div class="evx-r">${sev(r.severity)}<span title="${esc(r.title)}">${esc(r.title)}</span><b>${n.toLocaleString()}</b></div>`).join('') + (S.per.length > 8 ? `<p class="t3 small">and ${S.per.length - 8} more rules</p>` : '')
        : `<p class="t3 small">None of the ${S.rules} Sigma rules matched these events.</p>`) : `<p class="t3 small">Running ${DB.rules.filter(r => r.type === 'sigma').length} Sigma rules…</p><div class="evx-bar"><i id="evSigBar"></i></div>`}</section>
    </div>
    <fieldset class="evx-opt"><legend class="sr">What to import</legend>
      <label><input type="radio" name="evxOnly" value="all"${L.only ? '' : ' checked'}> All ${R.length.toLocaleString()} events</label>
      <label><input type="radio" name="evxOnly" value="hits"${L.only ? ' checked' : ''}${S && nHit ? '' : ' disabled'}> Only the ${S ? nHit.toLocaleString() : ''} events a rule matched</label></fieldset>
    <p class="t3 small">Events go to <b>${esc(c.name)}</b> as evidence, with every field kept. Matches are tagged <code>sigma-match</code> and the rules are linked to the case.</p></div>
    <footer><button class="btn" data-act="dclose">Cancel</button><button class="btn primary" data-act="evtxGo"${S ? '' : ' disabled'}>${ico('upload','sm')}Import</button></footer>`;
  if($('evtxDlg')){ const d = $('evtxDlg').closest('.dlg'); if(d){ d.querySelector('.in.evtx').outerHTML = body.split('</div>\n    <footer>')[0] + '</div>'; d.querySelector('footer').outerHTML = '<footer>' + body.split('<footer>')[1]; return; } }
  openDlg(dhead('Import ' + esc(L.name)) + body, true);
}
async function evtxGo(){
  const L = EVTXIMP; if(!L || !L.sig) return;
  const only = !!document.querySelector('input[name=evxOnly][value=hits]:checked');
  await snapshot('Before importing ' + L.name);
  LOGIMP = {caseId:L.caseId};
  const M = {time:'TimeCreated', title:'Summary', host:'Computer', source:'Channel'}, made = [], linked = new Set();
  L.rows.forEach((row, i) => { const h = L.sig.hits.get(i); if(only && !h) return;
    const r = logRec(row, M, L.name); r.tags = ['imported', 'evtx']; r.body = evtxKv(row); r.ents = extractRich(r.body);
    if(h){ r.tags.push('sigma-match'); r.det = h.map(x => ({id:x.id, title:x.title, sev:x.severity})); for(const x of h) linked.add(x); }
    made.push(r); });
  LOGIMP = null;
  for(const x of linked) if(!x.caseId) x.caseId = L.caseId;
  DB.records.push(...made); EVTXIMP = null; closeDlg();
  mutate('imported ' + made.length + ' events from ' + L.name); await hashRecords(); afterCapture(L.caseId, made.map(r => r.id)); watchNotify(made);
  UI.tlMode = 'events'; UI.facet = {}; UI.pivot = null; UI.q = !only && linked.size ? 'tag:sigma-match' : ''; UI.ast = UI.q ? E.parseQuery(UI.q) : null; go(caseHash(L.caseId, 'timeline'));
  const ids = new Set(made.map(r => r.id));
  toast(`${made.length.toLocaleString()} events imported${linked.size ? ' · ' + linked.size + ' rule' + (linked.size > 1 ? 's' : '') + ' matched' : ''}`, 'Undo', () => { DB.records = DB.records.filter(r => !ids.has(r.id)); mutate('undid event log import'); renderAll(); });
}
