/* ==========================================================================
   Reading a text file the way it was written. Windows tools save text in
   several ways — UTF-8 with or without a byte-order mark, UTF-16 (PowerShell
   "> file", "Unicode text" from Excel, many event-log exports), and the old
   Windows-1252 code page — and reading them all as UTF-8 turns them into
   spaced-out letters or question marks. This picks the right one:
   · a byte-order mark decides it outright
   · without one, zero bytes in every other place mean UTF-16 (which half
     tells little- from big-endian)
   · otherwise UTF-8, and if the bytes are not valid UTF-8, Windows-1252
   ========================================================================== */
function textEncodingOf(u){
  if(u.length >= 3 && u[0] === 0xEF && u[1] === 0xBB && u[2] === 0xBF) return ['utf-8', 3];
  if(u.length >= 2 && u[0] === 0xFF && u[1] === 0xFE) return ['utf-16le', 2];
  if(u.length >= 2 && u[0] === 0xFE && u[1] === 0xFF) return ['utf-16be', 2];
  const n = Math.min(u.length, 8192) & ~1; let ze = 0, zo = 0;
  for(let i = 0; i < n; i += 2){ if(u[i] === 0) ze++; if(u[i + 1] === 0) zo++; }
  const h = n / 2; if(h >= 2){ if(zo > h * .3 && ze < h * .05) return ['utf-16le', 0]; if(ze > h * .3 && zo < h * .05) return ['utf-16be', 0]; }
  return ['', 0];
}
function textFromBytes(b){
  const u = b instanceof Uint8Array ? b : new Uint8Array(b && b.buffer ? b.buffer : b || []);
  const [enc, skip] = textEncodingOf(u);
  if(enc) return new TextDecoder(enc, {ignoreBOM:true}).decode(u.subarray(skip));
  try{ return new TextDecoder('utf-8', {fatal:true, ignoreBOM:true}).decode(u); }catch(e){ return new TextDecoder('windows-1252').decode(u); }
}
async function fileText(f){ return textFromBytes(new Uint8Array(await f.arrayBuffer())); }
