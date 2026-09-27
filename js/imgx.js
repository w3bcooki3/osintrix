/* ==========================================================================
   Image forensics extras — error level analysis and perceptual fingerprints.
   ELA re-saves the picture as JPEG (quality 90) and shows how much each pixel
   changes: areas edited after the last save often recompress differently.
   The difference hash (dHash) survives resizing and re-compression, so it
   finds the same photo among your evidence even when the bytes differ.
   ========================================================================== */
function toCanvas(img){ const c = document.createElement('canvas'); c.width = img.width; c.height = img.height; c.getContext('2d').putImageData(img, 0, 0); return c; }
async function elaOf(src, q = .9, scale = 18){
  const c = toCanvas(src), blob = await new Promise(r => c.toBlob(r, 'image/jpeg', q)), bmp = await createImageBitmap(blob);
  const d = document.createElement('canvas'); d.width = src.width; d.height = src.height; const x = d.getContext('2d', {willReadFrequently:true}); x.drawImage(bmp, 0, 0);
  const re = x.getImageData(0, 0, src.width, src.height).data, a = src.data, out = new ImageData(src.width, src.height), o = out.data; let sum = 0, mx = 0;
  for(let i = 0; i < a.length; i += 4){ const e = (Math.abs(a[i] - re[i]) + Math.abs(a[i + 1] - re[i + 1]) + Math.abs(a[i + 2] - re[i + 2])) / 3; sum += e; if(e > mx) mx = e;
    const v = Math.min(255, e * scale); o[i] = v; o[i + 1] = Math.min(255, v * .75); o[i + 2] = Math.min(255, v * .45); o[i + 3] = 255; }
  return {img:out, mean:sum / (a.length / 4), max:mx};
}
function dhashOf(src){
  const c = toCanvas(src), s = document.createElement('canvas'); s.width = 9; s.height = 8; const x = s.getContext('2d', {willReadFrequently:true}); x.imageSmoothingQuality = 'high'; x.drawImage(c, 0, 0, 9, 8);
  const p = x.getImageData(0, 0, 9, 8).data, g = i => p[i] * .299 + p[i + 1] * .587 + p[i + 2] * .114; let bits = '';
  for(let y = 0; y < 8; y++) for(let xx = 0; xx < 8; xx++){ const i = (y * 9 + xx) * 4; bits += g(i) > g(i + 4) ? '1' : '0'; }
  return BigInt('0b' + bits).toString(16).padStart(16, '0');
}
const hamming = (a, b) => { let n = 0, x = BigInt('0x' + a) ^ BigInt('0x' + b); while(x){ n += Number(x & 1n); x >>= 1n; } return n; };
async function dhashBlob(blob){ try{ const bmp = await createImageBitmap(blob), sc = Math.min(1, 512 / Math.max(bmp.width, bmp.height)), c = document.createElement('canvas'); c.width = Math.max(1, Math.round(bmp.width * sc)); c.height = Math.max(1, Math.round(bmp.height * sc));
  const x = c.getContext('2d', {willReadFrequently:true}); x.drawImage(bmp, 0, 0, c.width, c.height); return dhashOf(x.getImageData(0, 0, c.width, c.height)); }catch(e){ return null; } }
/* fingerprint every image attachment once, then compare */
async function evidenceImages(){
  const out = []; let changed = false;
  for(const r of DB.records) for(const a of (r.att || [])){ if(!/^image\//.test(a.type)) continue;
    if(!a.dhash){ const b = await fileBlob(a.id); if(!b) continue; a.dhash = await dhashBlob(b); changed = true; } if(a.dhash) out.push({r, a}); }
  if(changed) save(); return out;
}
async function similarTo(hash, skipId){ const all = await evidenceImages(); return all.filter(x => x.a.id !== skipId).map(x => ({...x, d:hamming(hash, x.a.dhash)})).filter(x => x.d <= 12).sort((a, b) => a.d - b.d).slice(0, 12); }
function imgxCard(){
  const I = UI.img; if(!I || !I.data) return '';
  if(!I.dhash) I.dhash = dhashOf(I.data);
  if(!I.sim){ I.sim = 'loading'; similarTo(I.dhash).then(s => { I.sim = s; if(UI.route.area === 'lab') { const el = $('imgSim'); if(el) el.innerHTML = simHTML(s); } }); }
  return `<section class="card"><header><h3>${ico('fingerprint','sm')} Fingerprint &amp; look-alikes</h3></header><div class="body">
    <p class="t3" style="margin:0 0 8px;font-size:13px">Perceptual hash (dHash) — stays the same when the picture is resized or re-compressed.</p>
    <code class="mono" style="font-size:14px">${I.dhash}</code>
    <div id="imgSim" style="margin-top:12px">${simHTML(I.sim)}</div></div></section>`;
}
function simHTML(s){
  if(s === 'loading' || !s) return '<span class="t3" style="font-size:13px">Comparing with images in your evidence…</span>';
  if(!s.length) return '<span class="t3" style="font-size:13px">No similar image among your evidence.</span>';
  return `<div class="t3" style="font-size:12.5px;margin-bottom:6px">Similar images in your evidence</div>` + s.map(x => `<button class="li simi" data-act="selRec" data-id="${x.r.id}"><img data-fid="${x.a.id}" alt=""><div class="main2"><b style="font-weight:540;font-size:13.5px">${esc(x.a.name)}</b><small>${esc((theCase(x.r.caseId) || {}).code || '')} · ${x.d === 0 ? 'identical picture' : x.d <= 5 ? 'almost certainly the same picture' : 'looks alike'} (${x.d}/64 bits differ)</small></div></button>`).join('');
}
async function showEla(canvas){
  const I = UI.img; if(!I) return; if(!I.ela){ I.ela = 'busy'; I.ela = await elaOf(I.data); }
  if(I.ela === 'busy') return; canvas.width = I.ela.img.width; canvas.height = I.ela.img.height; canvas.getContext('2d').putImageData(I.ela.img, 0, 0);
  const n = $('elaNote'); if(n) n.innerHTML = `Mean error ${I.ela.mean.toFixed(2)}, max ${Math.round(I.ela.max)}. Bright areas changed most when re-saved. In an untouched JPEG, similar surfaces glow similarly; a region that is much brighter or darker than its neighbours deserves a closer look. Screenshots and PNGs are not JPEGs, so ELA says little about them.`;
}
