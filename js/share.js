/* ==========================================================================
   Share package — everything someone else needs from a case, in one ZIP:
     • a read-only page (one HTML file, no scripts, loads nothing) with the report,
       relationship map and indicator table, marked with its TLP
     • STIX 2.1 bundle and MISP event of the indicators (for TIPs and SIEMs)
     • the case's detection rules as Sigma .yml and YARA .yar files
     • indicators as CSV, the report as Markdown
     • MANIFEST.txt with a SHA-256 for every file, so the recipient can verify them
   Redaction masks people's details everywhere; machine indicators stay usable.
   ========================================================================== */
const SH_TLP = [['clear', 'TLP:CLEAR', 'Can be shared publicly', '#ffffff', '#111827'], ['green', 'TLP:GREEN', 'Within the community, not public', '#33ff00', '#000000'], ['amber', 'TLP:AMBER', 'Within the recipient\'s organisation', '#ffc000', '#000000'], ['amber+strict', 'TLP:AMBER+STRICT', 'Only within the recipient\'s organisation', '#ffc000', '#000000'], ['red', 'TLP:RED', 'Only the named recipients', '#ff2b2b', '#000000']];
const SH_PARTS = [['page', 'Read-only page', 'One HTML file anyone can open — no scripts, loads nothing from the internet'], ['stix', 'STIX 2.1 bundle', 'For threat-intel platforms (OpenCTI, MISP, Sentinel…)'], ['misp', 'MISP event', 'Import straight into MISP'],
  ['rules', 'Detection rules', 'This case\'s Sigma (.yml) and YARA (.yar) rules'], ['csv', 'Indicators (CSV)', 'Every indicator with its verdict'], ['md', 'Report (Markdown)', 'The report as text']];
const SH_PEOPLE = new Set(['email', 'phone', 'handle', 'social']);
function shareDlg(){
  const c = theCase(), S = UI.share = UI.share || {tlp:'amber', red:true, all:false, parts:{page:true, stix:true, misp:true, rules:true, csv:true, md:false}};
  const items = shareItems(c, S), rules = (DB.rules || []).filter(r => r.caseId === c.id);
  openDlg(dhead('Share ' + c.code) + `<div class="in sh">
    <p class="t2" style="margin:0 0 12px">One ZIP with everything another analyst or team needs. Pick what goes in; a manifest with a SHA-256 for every file lets them check nothing changed.</p>
    <div class="field"><label>Traffic Light Protocol</label><div class="sh-tlp" role="radiogroup" aria-label="TLP">${SH_TLP.map(([k, l, d, bg, fg]) => `<button type="button" role="radio" aria-checked="${S.tlp === k}" data-act="shTlp" data-v="${k}" title="${esc(d)}"><i style="background:${bg};color:${fg}">${esc(l)}</i></button>`).join('')}</div><small class="t3">${esc(SH_TLP.find(x => x[0] === S.tlp)[2])}</small></div>
    <div class="sh-parts">${SH_PARTS.map(([k, l, d]) => { const n = k === 'rules' ? rules.length : k === 'stix' || k === 'misp' || k === 'csv' ? items.length : null;
      return `<label class="sh-p${S.parts[k] && n !== 0 ? ' on' : ''}"><input type="checkbox" data-act="shPart" data-v="${k}" ${S.parts[k] && n !== 0 ? 'checked' : ''} ${n === 0 ? 'disabled' : ''}><div><b>${esc(l)}${n != null ? ` <span class="t3">${n}</span>` : ''}</b><small>${esc(n === 0 ? (k === 'rules' ? 'No rules linked to this case — Detections → From case' : 'No indicators to share') : d)}</small></div></label>`; }).join('')}</div>
    <label class="chk swl"><span class="sw"><input type="checkbox" data-act="shRed" ${S.red ? 'checked' : ''}><span></span></span>Redact personal data — names, emails, phone numbers and handles are masked in the page, report and CSV, and left out of STIX and MISP</label>
    <label class="chk swl"><span class="sw"><input type="checkbox" data-act="shAll" ${S.all ? 'checked' : ''}><span></span></span>Include indicators with no verdict (otherwise only malicious and suspicious)</label></div>
    <footer><span class="t3" style="margin-right:auto">${items.length} indicator${items.length === 1 ? '' : 's'} · ${rules.length} rule${rules.length === 1 ? '' : 's'}</span><button class="btn" data-act="dclose">Cancel</button><button class="btn primary" data-act="shGo">${ico('download','sm')}Download package</button></footer>`);
}
function shareItems(c, S){
  const H = typeof cpHist === 'function' ? cpHist() : new Map();
  return ctiCaseItems(c.id).filter(x => !(S.red && SH_PEOPLE.has(x.k))).map(x => { const key = x.k + ':' + x.v, v = verdictOf(key) || (x.tags || []).find(t => /malicious|suspicious|benign/.test(t)) || '', h = H.get(key);
    return {...x, verdict:v, tlp:S.tlp, tags:[...new Set([...(x.tags || []), c.code])], conf:v === 'malicious' ? 85 : v === 'suspicious' ? 50 : h ? h.score : undefined, desc:cap(x.desc || (h ? 'Live lookups: ' + h.band + ' ' + h.score + '/100' : ''), 500)}; })
    .filter(x => x.verdict !== 'benign' && (S.all || /malicious|suspicious/.test(x.verdict) || (H.get(x.k + ':' + x.v) && /malicious|suspicious/.test(H.get(x.k + ':' + x.v).band))));
}
/* the read-only page: plain HTML and CSS, its own CSP forbids loading or running anything */
function sharePage(c, D, M, tplName, S, items){
  const T = SH_TLP.find(x => x[0] === S.tlp), red = M.red;
  const ban = `<div class="tlp" style="background:#000;color:${T[3]}"><b>${esc(T[1])}</b> — ${esc(T[2])}</div>`;
  const ind = items.length ? `<h2>Indicators</h2><table><tr><th>Kind</th><th>Value</th><th>Verdict</th></tr>${items.map(x => `<tr><td>${esc(E.LABEL[x.k] || x.k)}</td><td class="m">${esc(defang(x.v))}</td><td class="v ${esc(x.verdict || '')}">${esc(x.verdict || '—')}</td></tr>`).join('')}</table><p class="n">Values are defanged ([.] and hxxp) so they cannot be clicked by accident.</p>` : '';
  const body = reportDocHtml(c, D, M, tplName).replace(/<figure><img alt="Relationship map" src="data:image\/svg\+xml;base64,[^"]+"><figcaption>/, () => `<figure>${reportMap(c, D, red)}<figcaption>`);
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">
<meta name="referrer" content="no-referrer"><title>${esc(red(c.name))} — ${esc(T[1])}</title>
<style>
:root{--bg:#f7f8fb;--fg:#111827;--mu:#5b6475;--li:#e3e6ee;--card:#fff;--acc:#4f46e5}
@media (prefers-color-scheme:dark){:root{--bg:#0f1219;--fg:#e8eaf0;--mu:#9aa3b5;--li:#262c38;--card:#161a23;--acc:#8b8cf6}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:920px;margin:0 auto;padding:24px 16px 48px}article{background:var(--card);border:1px solid var(--li);border-radius:14px;padding:28px 32px}
@media (max-width:640px){article{padding:18px 16px}}
h1{font-size:28px;line-height:1.25;margin:0 0 6px}h2{font-size:19px;margin:28px 0 10px;padding-top:12px;border-top:1px solid var(--li)}
.nbx-meta,.n{color:var(--mu);font-size:13px}table{width:100%;border-collapse:collapse;margin:8px 0;font-size:14px;display:block;overflow-x:auto}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--li);vertical-align:top}th{color:var(--mu);font-weight:600;font-size:12.5px;text-transform:uppercase;letter-spacing:.04em}
td.m,.m{font-family:ui-monospace,Consolas,monospace;font-size:13px;overflow-wrap:anywhere}td.v.malicious{color:#e03131;font-weight:600}td.v.suspicious{color:#d97706;font-weight:600}
.nbx-call{border:1px solid color-mix(in srgb,var(--acc) 35%,var(--li));background:color-mix(in srgb,var(--acc) 7%,transparent);border-radius:12px;padding:4px 16px;margin:8px 0}
pre{white-space:pre-wrap;background:color-mix(in srgb,var(--fg) 5%,transparent);padding:10px 12px;border-radius:8px;font-size:12.5px}
figure{margin:12px 0}figure svg{width:100%;height:auto;background:#fff;border:1px solid var(--li);border-radius:10px}figcaption{color:var(--mu);font-size:13px}
.tlp{padding:8px 16px;font:600 13px/1.4 system-ui,sans-serif;text-align:center;letter-spacing:.02em}.tlp b{font-weight:800}
footer{color:var(--mu);font-size:12.5px;text-align:center;margin-top:18px}
@media print{body{background:#fff}article{border:0;padding:0}}
</style></head><body>${ban}<main><article>${body}${ind}</article>
<footer>Read-only copy made with ${esc(BRAND.name)} on ${esc(new Date().toISOString().slice(0, 16).replace('T', ' '))} UTC${S.red ? ' · personal data redacted' : ''}. It does not update.</footer></main>${ban}</body></html>`;
}
function sigmaYaml(r){ const c = String(r.code || ''); return /^\s*title\s*:/m.test(c) ? c : 'title: ' + String(r.title || 'Untitled').replace(/\n/g, ' ') + '\n' + c; }
async function shareGo(){
  const c = theCase(), D = derive(), S = UI.share, tpl = DB.prefs.repT || 'full', tplName = REP_T.find(x => x[0] === tpl)[1], M = reportModel(c, D, tpl, !!S.red), items = shareItems(c, S);
  const base = safeName(c.code + '-' + slug(c.name.split(' — ')[0])).slice(0, 60) || 'case', T = SH_TLP.find(x => x[0] === S.tlp), files = [];
  if(S.parts.page) files.push({name:base + '/' + base + '.html', data:sharePage(c, D, M, tplName, S, items)});
  if(S.parts.stix && items.length) files.push({name:base + '/' + base + '.stix.json', data:JSON.stringify(ctiStix(items, c.code + ' — ' + M.red(c.name), S.tlp), null, 2)});
  if(S.parts.misp && items.length) files.push({name:base + '/' + base + '.misp.json', data:JSON.stringify(ctiMisp(items, c.code + ' — ' + M.red(c.name), S.tlp), null, 2)});
  if(S.parts.csv && items.length) files.push({name:base + '/' + base + '-indicators.csv', data:ctiCsv(items)});
  if(S.parts.md) files.push({name:base + '/' + base + '-report.md', data:reportMdText(c, D, M, tplName)});
  if(S.parts.rules) for(const r of (DB.rules || []).filter(x => x.caseId === c.id)) files.push({name:base + '/rules/' + safeName(slug(r.title)).slice(0, 60) + (r.type === 'yara' ? '.yar' : '.yml'), data:r.type === 'yara' ? r.code : sigmaYaml(r)});
  if(!files.length) return toast('Choose at least one thing to include');
  const enc = new TextEncoder(), sums = await Promise.all(files.map(async f => { const h = await crypto.subtle.digest('SHA-256', enc.encode(f.data)); return [...new Uint8Array(h)].map(b => b.toString(16).padStart(2, '0')).join(''); }));
  const manifest = [`${c.code} — ${M.red(c.name)}`, `${T[1]} — ${T[2]}`, `Made with ${BRAND.name} on ${new Date().toISOString()}${S.red ? ' · personal data redacted' : ''}`, '', 'SHA-256 of each file:', ...files.map((f, i) => sums[i] + '  ' + f.name.slice(base.length + 1)), '',
    'Check on Linux or macOS:  shasum -a 256 -c MANIFEST.txt  (from inside the folder, after removing these notes)', 'Check on Windows:         Get-FileHash <file> -Algorithm SHA256'].join('\n');
  files.push({name:base + '/MANIFEST.txt', data:manifest});
  const blob = nbZip(files), a = document.createElement('a'), u = URL.createObjectURL(blob); a.href = u; a.download = base + '-' + S.tlp.replace('+', '-') + '.zip'; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(u), 4000);
  closeDlg(); auditAdd && auditAdd('shared ' + c.code + ' as ' + T[1] + ' (' + files.length + ' files)'); save(); toast('Share package ready — ' + (files.length - 1) + ' file' + (files.length > 2 ? 's' : '') + ' and a manifest');
}
const SH_ACTS = {
  shareDlg:() => shareDlg(), shGo:() => shareGo(),
  shTlp:(id, v) => { UI.share.tlp = v; shareDlg(); },
  shPart:(id, v, t) => { UI.share.parts[v] = t.checked; shareDlg(); },
  shRed:(id, v, t) => { UI.share.red = t.checked; shareDlg(); },
  shAll:(id, v, t) => { UI.share.all = t.checked; shareDlg(); },
};
