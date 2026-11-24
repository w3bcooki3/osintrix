/* What an AI image generator left inside the picture: the prompt, the negative prompt, the model and its hash, LoRAs,
   seed, sampler, steps and size — from AUTOMATIC1111 / Forge / SD.Next ("parameters"), ComfyUI (the workflow JSON),
   NovelAI, InvokeAI, Fooocus and Midjourney (prompt and Job ID), in PNG text chunks, JPEG / WebP EXIF comments or XMP,
   plus the generator a Content Credentials (C2PA) manifest names. The model and LoRA names are leads: a LoRA can be
   trained on one real person's face, and the model hash finds the exact file on Civitai. */
const AIG_C2PA = [[/chatgpt|gpt-4o|gpt-image/i, 'OpenAI ChatGPT image generation'], [/dall[·\-\s]?e/i, 'OpenAI DALL·E'], [/openai/i, 'OpenAI'], [/adobe[_ ]firefly|firefly/i, 'Adobe Firefly'],
  [/microsoft designer|bing image creator|microsoft_designer|azure openai/i, 'Microsoft Designer / Bing Image Creator'], [/google.{0,20}(imagen|gemini)|imagen|gemini/i, 'Google (Imagen / Gemini)'],
  [/meta ai|imagine with meta/i, 'Meta AI'], [/midjourney/i, 'Midjourney'], [/leonardo/i, 'Leonardo.Ai'], [/ideogram/i, 'Ideogram'], [/stability|stable diffusion/i, 'Stability AI']];
const aigNum = v => v == null || v === '' ? '' : String(v);
async function aiGenRead(b){
  if(!(b instanceof Uint8Array)) b = new Uint8Array(b);
  const T = [], str = (a, z) => { let s = ''; for(let i = a; i < z && i < b.length; i++) s += String.fromCharCode(b[i]); return s; };
  // PNG text chunks
  if(b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47){ let o = 8;
    while(o + 12 <= b.length){ const len = ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0, type = str(o + 4, o + 8), d = o + 8; if(len > b.length - o) break;
      if(type === 'tEXt' || type === 'zTXt' || type === 'iTXt'){ const nul = b.indexOf(0, d); if(nul > d && nul < d + 80){ const key = str(d, nul); let v = '';
        try{ if(type === 'tEXt') v = new TextDecoder('latin1').decode(b.subarray(nul + 1, d + len));
          else if(type === 'zTXt') v = new TextDecoder().decode(await decompressCapped(b.subarray(nul + 2, d + len), 'deflate', 8 << 20));
          else { const comp = b[nul + 1], l1 = b.indexOf(0, nul + 3), l2 = b.indexOf(0, l1 + 1), raw = b.subarray(l2 + 1, d + len); v = new TextDecoder().decode(comp ? await decompressCapped(raw, 'deflate', 8 << 20) : raw); } }catch(e){}
        if(v) T.push([key, v]); } }
      if(type === 'IEND') break; o += 12 + len; } }
  // JPEG / WebP: the EXIF UserComment AUTOMATIC1111 writes (UNICODE prefix, UTF-16), and any XMP packet
  const L = b.length > 40e6 ? '' : typeof latin1 === 'function' ? latin1(b, 0, b.length) : str(0, b.length);
  if(L){ let at = L.indexOf('UNICODE\0'); while(at >= 0 && T.length < 40){ const raw = b.subarray(at + 8, Math.min(b.length, at + 8 + 200000)); let best = '';
      for(const enc of ['utf-16be', 'utf-16le']){ const s = new TextDecoder(enc).decode(raw.length % 2 ? raw.subarray(0, raw.length - 1) : raw).split('\u0000')[0]; if(/Steps:|Sampler:|"prompt"|Negative prompt/.test(s)){ best = s; break; } }
      if(best) T.push(['parameters', best]); at = L.indexOf('UNICODE\0', at + 8); }
    const ax = L.indexOf('ASCII\0\0\0'); if(ax >= 0){ const s = L.slice(ax + 8, ax + 60000).split('\0')[0]; if(/Steps:|Sampler:/.test(s)) T.push(['parameters', s]); }
    const x0 = L.indexOf('<x:xmpmeta'), x1 = x0 >= 0 ? L.indexOf('</x:xmpmeta>', x0) : -1;
    if(x0 >= 0 && x1 > x0){ const x = new TextDecoder().decode(b.subarray(x0, x1)); const tag = n => ((x.match(new RegExp('<' + n + '[^>]*>\\s*(?:<rdf:Alt>\\s*<rdf:li[^>]*>)?([\\s\\S]*?)<', 'i')) || [])[1] || (x.match(new RegExp(n + '="([^"]*)"', 'i')) || [])[1] || '').trim();
      const desc = tag('dc:description'), guid = tag('iptcExt:DigitalImageGUID') || tag('Iptc4xmpExt:DigitalImageGUID'), src = tag('Iptc4xmpExt:DigitalSourceType'), cr = tag('dc:creator');
      if(desc) T.push(['Description', desc.replace(/&quot;/g, '"').replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>')]); if(guid) T.push(['DigitalImageGUID', guid]); if(src) T.push(['DigitalSourceType', src]); if(cr && !T.some(t => t[0] === 'Author')) T.push(['XmpCreator', cr]); } }
  const G = {tool:'', prompt:'', negative:'', model:'', modelHash:'', vae:'', loras:[], seed:'', steps:'', sampler:'', scheduler:'', cfg:'', size:'', version:'', jobId:'', author:'', c2pa:'', ai:false, extra:[]};
  const get = k => (T.find(t => t[0].toLowerCase() === k.toLowerCase()) || [])[1] || '';
  // ComfyUI: the prompt graph (what ran) and the UI workflow
  const cp = get('prompt'); let J = null; if(/class_type/.test(cp)){ try{ J = JSON.parse(cp); }catch(e){} }
  if(J){ G.tool = 'ComfyUI'; const N = J, node = id => N[Array.isArray(id) ? id[0] : id] || null, txt = n => { if(!n) return ''; const t = n.inputs && (n.inputs.text ?? n.inputs.text_g ?? n.inputs.prompt); return typeof t === 'string' ? t : Array.isArray(t) ? txt(node(t)) : ''; };
    for(const n of Object.values(N)){ const c = n.class_type || '', I = n.inputs || {};
      if(/CheckpointLoader|UNETLoader|UnetLoader|DiffusersLoader/i.test(c)) G.model = G.model || I.ckpt_name || I.unet_name || I.model_path || '';
      if(/LoraLoader/i.test(c) && I.lora_name) G.loras.push({name:I.lora_name, w:aigNum(I.strength_model ?? I.strength)});
      if(/VAELoader/i.test(c) && I.vae_name) G.vae = I.vae_name;
      if(/KSampler|SamplerCustom/i.test(c)){ G.seed = G.seed || aigNum(Array.isArray(I.seed) ? '' : I.seed ?? I.noise_seed); G.steps = G.steps || aigNum(I.steps); G.cfg = G.cfg || aigNum(I.cfg); G.sampler = G.sampler || I.sampler_name || ''; G.scheduler = G.scheduler || I.scheduler || '';
        if(!G.prompt) G.prompt = txt(node(I.positive)); if(!G.negative) G.negative = txt(node(I.negative)); }
      if(/EmptyLatentImage|EmptySD3LatentImage/i.test(c) && I.width) G.size = I.width + '×' + I.height; }
    if(!G.prompt){ const ts = Object.values(N).filter(n => /CLIPTextEncode/i.test(n.class_type || '')).map(txt).filter(Boolean); G.prompt = ts[0] || ''; G.negative = G.negative || ts[1] || ''; }
    G.extra.push(['Workflow nodes', String(Object.keys(N).length)]); }
  // AUTOMATIC1111, Forge, SD.Next, Fooocus (text form)
  const P = get('parameters');
  if(!J && P && /Steps:\s*\d/.test(P)){ G.tool = G.tool || 'Stable Diffusion WebUI (AUTOMATIC1111 / Forge)'; const lines = P.split('\n'), si = lines.map(l => /^Steps:\s*\d/.test(l)).lastIndexOf(true);
    const head = lines.slice(0, si), ni = head.findIndex(l => /^Negative prompt:/.test(l));
    G.prompt = (ni >= 0 ? head.slice(0, ni) : head).join('\n').trim(); G.negative = ni >= 0 ? head.slice(ni).join('\n').replace(/^Negative prompt:\s*/, '').trim() : '';
    const S = {}; for(const m of lines[si].matchAll(/\s*([\w ()\-/]+?):\s*("(?:[^"\\]|\\.)*"|[^,]*)(?:,|$)/g)) if(m[1]) S[m[1].trim()] = m[2].trim().replace(/^"|"$/g, '');
    G.seed = S.Seed || ''; G.steps = S.Steps || ''; G.sampler = S.Sampler || ''; G.scheduler = S['Schedule type'] || ''; G.cfg = S['CFG scale'] || ''; G.size = (S.Size || '').replace('x', '×'); G.model = S.Model || ''; G.modelHash = S['Model hash'] || ''; G.vae = S.VAE || ''; G.version = S.Version || '';
    if(/forge|^f\d+\.\d/i.test(G.version)) G.tool = 'Stable Diffusion WebUI Forge'; else if(G.version) G.tool = 'Stable Diffusion WebUI (AUTOMATIC1111)'; if(/fooocus/i.test(P)) G.tool = 'Fooocus';
    const lh = S['Lora hashes'] || ''; for(const m of lh.matchAll(/([^:,]+):\s*([0-9a-f]{8,12})/gi)) G.loras.push({name:m[1].trim(), w:'', hash:m[2]});
    for(const k of ['Denoising strength', 'Hires upscale', 'Hires upscaler', 'Face restoration', 'ADetailer model', 'Clip skip']) if(S[k]) G.extra.push([k, S[k]]); }
  if(!J && P && /^\s*\{/.test(P)){ try{ const F = JSON.parse(P); if(F.Prompt != null || F.prompt != null){ G.tool = 'Fooocus'; G.prompt = F.Prompt || F.prompt || ''; G.negative = F['Negative Prompt'] || F.negative_prompt || ''; G.model = F['Base Model'] || F.base_model || ''; G.seed = aigNum(F.Seed ?? F.seed); G.steps = aigNum(F.Steps ?? F.steps); G.sampler = F.Sampler || F.sampler || ''; G.cfg = aigNum(F['Guidance Scale'] ?? F.guidance_scale);
      for(const l of F.LoRAs || F.loras || []) G.loras.push({name:Array.isArray(l) ? l[0] : l.name || String(l), w:Array.isArray(l) ? aigNum(l[1]) : ''}); } }catch(e){} }
  // InvokeAI
  const inv = get('invokeai_metadata'); if(inv){ try{ const I = JSON.parse(inv); G.tool = 'InvokeAI'; G.prompt = I.positive_prompt || ''; G.negative = I.negative_prompt || ''; G.model = (I.model && (I.model.name || I.model.model_name)) || ''; G.modelHash = (I.model && I.model.hash) || '';
    G.seed = aigNum(I.seed); G.steps = aigNum(I.steps); G.cfg = aigNum(I.cfg_scale); G.scheduler = I.scheduler || ''; G.size = I.width ? I.width + '×' + I.height : ''; for(const l of I.loras || []) G.loras.push({name:(l.model && (l.model.name || l.model.model_name)) || l.lora && l.lora.model_name || '', w:aigNum(l.weight)}); }catch(e){} }
  // NovelAI
  const soft = get('Software'), com = get('Comment'), src = get('Source');
  if(/novelai/i.test(soft) || /novelai/i.test(src)){ G.tool = 'NovelAI' + (src ? ' (' + src + ')' : ''); try{ const C = JSON.parse(com); G.prompt = C.prompt || get('Description') || ''; G.negative = C.uc || C.negative_prompt || ''; G.seed = aigNum(C.seed); G.steps = aigNum(C.steps); G.sampler = C.sampler || ''; G.cfg = aigNum(C.scale); G.size = C.width ? C.width + '×' + C.height : ''; }catch(e){ G.prompt = get('Description'); } }
  // Midjourney: the prompt and the Job ID in the description
  const desc = get('Description'); const mj = /Job ID:\s*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i.exec(desc);
  if(mj){ G.tool = 'Midjourney'; G.jobId = mj[1]; G.prompt = G.prompt || desc.slice(0, mj.index).trim(); const v = /--v(?:ersion)?\s+([\d.]+)/.exec(desc); if(v) G.version = 'v' + v[1]; G.author = get('Author') || get('XmpCreator'); }
  else if(G.tool && get('Author')) G.author = get('Author');
  // the IPTC digital source and Content Credentials
  const dst = get('DigitalSourceType'); if(/trainedAlgorithmicMedia/i.test(dst)) G.extra.push(['IPTC digital source', /composite/i.test(dst) ? 'Composite with AI-generated parts' : 'Made by a trained algorithm (AI)']);
  if(L && /c2pa|jumbf/i.test(L) && /jumb|c2pa\.(claim|actions|assertions)/.test(L)){ const win = L.slice(Math.max(0, L.search(/jumb|c2pa\.claim/) - 64), Math.max(0, L.search(/jumb|c2pa\.claim/)) + 400000); const hit = AIG_C2PA.find(([re]) => re.test(win));
    G.c2pa = hit ? hit[1] : 'present'; if(/trainedAlgorithmicMedia/i.test(win)) G.ai = true; }
  G.ai = G.ai || !!G.tool || /trainedAlgorithmicMedia/i.test(dst) || (G.c2pa && G.c2pa !== 'present');
  for(const m of (G.prompt || '').matchAll(/<lora:([^:>]+)(?::([\d.]+))?>/g)) if(!G.loras.some(l => l.name.replace(/\.\w+$/, '') === m[1])) G.loras.push({name:m[1], w:m[2] || ''});
  if(!G.tool && !G.c2pa && !G.extra.length) return null;
  return G;
}
const aigCivitai = q => 'https://civitai.com/search/models?query=' + encodeURIComponent(String(q).replace(/\.(safetensors|ckpt|pt|bin|gguf)$/i, '').replace(/[_-]+/g, ' ').trim());
function aiGenCard(G){
  if(!G) return '';
  const kv = (k, v, mono) => v ? `<div class="kv"><span>${esc(k)}</span>${mono ? `<code>${esc(v)}</code>` : `<b>${esc(v)}</b>`}${v.length < 2000 ? `<button class="iconbtn sm" data-act="flagCopy" data-v="${esc(v)}" aria-label="Copy ${esc(k)}">${ico('copy','sm')}</button>` : ''}</div>` : '';
  const lnk = (t, u) => `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(t)}${ico('arrow-up-right','sm')}</a>`;
  const leads = [];
  if(G.model) leads.push(lnk('Model “' + G.model.replace(/\.(safetensors|ckpt)$/i, '') + '” on Civitai', aigCivitai(G.model)));
  if(G.modelHash && /^[0-9a-f]{8,64}$/i.test(G.modelHash)) leads.push(lnk('Model by hash ' + G.modelHash, 'https://civitai.com/api/v1/model-versions/by-hash/' + G.modelHash));
  for(const l of G.loras.slice(0, 8)) leads.push(lnk('LoRA “' + l.name.replace(/\.\w+$/, '') + '”', l.hash ? 'https://civitai.com/api/v1/model-versions/by-hash/' + l.hash : aigCivitai(l.name)));
  if(G.jobId) leads.push(lnk('Midjourney job ' + G.jobId.slice(0, 8) + '…', 'https://www.midjourney.com/jobs/' + G.jobId));
  return `<section class="card aig" id="aigCard"><header><h3>${ico('sparkles','sm')} AI generation</h3><span class="t3">${esc(G.tool || (G.c2pa ? 'Content Credentials' : 'marked as AI'))}</span></header><div class="body">
    <div class="fx-note red">${G.tool ? `Made with ${esc(G.tool)} — the generator wrote its settings into the file.` : G.c2pa && G.c2pa !== 'present' ? `The Content Credentials name ${esc(G.c2pa)} as the tool that made it.` : 'The file says it was made by an AI model.'} Check the credentials with a C2PA verifier (contentcredentials.org/verify) if they are present.</div>
    ${kv('Prompt', G.prompt)}${kv('Negative prompt', G.negative)}${kv('Model', G.model, true)}${kv('Model hash', G.modelHash, true)}${kv('VAE', G.vae, true)}
    ${G.loras.length ? `<div class="kv"><span>LoRAs</span><span class="wrap">${G.loras.map(l => `<code class="chip sq">${esc(l.name)}${l.w ? ' · ' + esc(l.w) : ''}</code>`).join('')}</span></div>` : ''}
    ${kv('Seed', G.seed, true)}${kv('Steps', G.steps)}${kv('Sampler', [G.sampler, G.scheduler].filter(Boolean).join(' · '))}${kv('CFG scale', G.cfg)}${kv('Size', G.size)}${kv('Version', G.version)}${kv('Midjourney Job ID', G.jobId, true)}${kv('Account / author', G.author)}${kv('Content Credentials', G.c2pa && G.c2pa !== 'present' ? G.c2pa : G.c2pa ? 'present' : '')}
    ${G.extra.map(([k, v]) => kv(k, v)).join('')}
    ${G.loras.length ? '<p class="t3 small" style="margin:8px 0 0">A LoRA is a small add-on trained on a style, an object — or one real person\'s face. A LoRA named after a person is a strong sign of who is being imitated.</p>' : ''}
    ${G.seed && G.model ? '<p class="t3 small" style="margin:6px 0 0">The same model, seed and settings make the same picture again — a way to show this file came from that run.</p>' : ''}
    ${leads.length ? `<div class="pivots" style="margin-top:8px">${leads.join('')}</div>` : ''}
  </div></section>`;
}
