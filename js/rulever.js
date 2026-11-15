/* ==========================================================================
   Rule versions — every save that changes a rule keeps what it replaced
   (last 25). The History tab compares any two versions line by line, and can
   put an old version back in the editor: nothing is overwritten until you
   save, and that save keeps the version it replaces too.
   ========================================================================== */
const RV_MAX = 25;
const rvList = r => (Array.isArray(r.versions) ? r.versions : []).filter(v => v && typeof v.code === 'string' && v.code.length <= 200000 && +v.at).slice(-RV_MAX);
const RV_KEYS = ['title', 'code', 'severity', 'technique', 'desc'];
function rvKeep(r, next){
  if(!RV_KEYS.some(k => String(next[k] ?? '') !== String(r[k] ?? ''))) return;   // a save that changes nothing keeps nothing
  const L = rvList(r), prev = {at:r.modified || r.created || Date.now()}; for(const k of RV_KEYS) prev[k] = String(r[k] ?? '');
  const last = L[L.length - 1]; if(last && RV_KEYS.every(k => last[k] === prev[k])) return;
  r.versions = [...L, prev].slice(-RV_MAX);
}
/* line diff (longest common subsequence); rules are short, so this is plenty */
function rvDiff(a, b){
  const A = String(a).split('\n').slice(0, 1500), B = String(b).split('\n').slice(0, 1500), m = A.length, n = B.length;
  const D = Array.from({length:m + 1}, () => new Uint16Array(n + 1));
  for(let i = m - 1; i >= 0; i--) for(let j = n - 1; j >= 0; j--) D[i][j] = A[i] === B[j] ? D[i + 1][j + 1] + 1 : Math.max(D[i + 1][j], D[i][j + 1]);
  const out = []; let i = 0, j = 0;
  while(i < m && j < n){ if(A[i] === B[j]){ out.push([' ', A[i]]); i++; j++; } else if(D[i + 1][j] >= D[i][j + 1]) out.push(['-', A[i++]]); else out.push(['+', B[j++]]); }
  while(i < m) out.push(['-', A[i++]]); while(j < n) out.push(['+', B[j++]]);
  return out;
}
function rvPane(r, code){
  const now = {at:Date.now(), now:true, title:$('rTitle') ? $('rTitle').value : r.title, code, severity:$('rSev') ? $('rSev').value : r.severity, technique:$('rTech') ? $('rTech').value : r.technique, desc:$('rDesc') ? $('rDesc').value : r.desc};
  const V = [...rvList(r)].reverse(), all = [now, ...V];
  if(!V.length) return `<p class="t2 small">Every save that changes this rule keeps the version it replaces — the last ${RV_MAX}. There are none yet: the first save that changes something starts the history.</p>`;
  const a = Math.min(UI.rvA ?? 1, all.length - 1), b = Math.min(UI.rvB ?? 0, all.length - 1), A = all[Math.max(a, b)], B = all[Math.min(a, b)];
  const D = rvDiff(A.code, B.code), add = D.filter(x => x[0] === '+').length, del = D.filter(x => x[0] === '-').length;
  const meta = RV_KEYS.filter(k => k !== 'code' && String(A[k] || '') !== String(B[k] || '')).map(k => `<li><b>${{title:'Title', severity:'Severity', technique:'Technique', desc:'Description'}[k]}</b>: <del>${esc(A[k] || '—')}</del> → <ins>${esc(B[k] || '—')}</ins></li>`).join('');
  const when = v => v.now ? 'In the editor now' : esc(new Date(v.at).toLocaleString()) + ' <span class="t3">· ' + esc(iAgo(v.at)) + '</span>';
  /* show changed lines with 2 lines of context, folding long unchanged runs */
  const keep = new Set(); D.forEach((x, i) => { if(x[0] !== ' ') for(let k = i - 2; k <= i + 2; k++) keep.add(k); });
  let html = '', fold = 0; D.forEach((x, i) => { if(x[0] === ' ' && !keep.has(i)){ fold++; return; } if(fold){ html += `<div class="rv-f">${fold} unchanged line${fold > 1 ? 's' : ''}</div>`; fold = 0; } html += `<div class="rv-l ${x[0] === '+' ? 'add' : x[0] === '-' ? 'del' : ''}"><span aria-hidden="true">${x[0] === ' ' ? '' : x[0]}</span><code>${esc(x[1]) || ' '}</code></div>`; });
  if(fold) html += `<div class="rv-f">${fold} unchanged line${fold > 1 ? 's' : ''}</div>`;
  return `<p class="t2 small">Every save that changes this rule keeps the version it replaces (the last ${RV_MAX}). Pick two to compare; put an old one back in the editor and save to use it again.</p>
    <table class="rv-t"><thead><tr><th scope="col">Older</th><th scope="col">Newer</th><th scope="col">Version</th><th scope="col"></th></tr></thead><tbody>
    ${all.map((v, i) => `<tr${i === a || i === b ? ' class="on"' : ''}><td><input type="radio" name="rvA" data-act="rvPick" data-v="a:${i}" aria-label="Compare from this version"${i === Math.max(a, b) ? ' checked' : ''}></td><td><input type="radio" name="rvB" data-act="rvPick" data-v="b:${i}" aria-label="Compare to this version"${i === Math.min(a, b) ? ' checked' : ''}></td>
      <td>${when(v)}${!v.now && v.title !== now.title ? `<br><span class="t3">${esc(v.title)}</span>` : ''}</td><td>${v.now ? '' : `<button type="button" class="btn xs" data-act="rvUse" data-v="${i - 1}">${ico('history','sm')}Put in editor</button>`}</td></tr>`).join('')}</tbody></table>
    <div class="rv-sum">${A === B ? 'Same version on both sides.' : `<b class="add">+${add}</b> <b class="del">−${del}</b> line${add + del === 1 ? '' : 's'} from ${A.now ? 'the editor' : esc(iAgo(A.at))} to ${B.now ? 'the editor' : esc(iAgo(B.at))}`}</div>
    ${meta ? `<ul class="rv-m">${meta}</ul>` : ''}${A !== B ? `<div class="rv-d" role="region" aria-label="Line changes">${add + del ? html : '<div class="rv-f">The rule text is the same.</div>'}</div>` : ''}`;
}
const RV_ACTS = {
  rvPick:(id, v) => { const [s, i] = String(v).split(':'); if(s === 'a') UI.rvA = +i; else UI.rvB = +i; dlPaneFill(); },
  rvUse:(id, v) => { const r = DB.rules.find(z => z.id === UI.rule); if(!r) return; const x = [...rvList(r)].reverse()[+v]; if(!x) return;
    const set = (el, val) => { const e = $(el); if(e && val != null){ e.value = val; e.dispatchEvent(new Event('input', {bubbles:true})); e.dispatchEvent(new Event('change', {bubbles:true})); } };
    set('rTitle', x.title); set('rDesc', x.desc); set('rTech', x.technique); set('rSev', x.severity); set('rCode', x.code);
    UI.rvA = 1; UI.rvB = 0; const tb = document.querySelector('form.rx [data-rtab=rule]'); if(tb) tb.click(); const ta = $('rCode'); if(ta) ta.focus({preventScroll:true}); toast('That version is in the editor — save to use it, or Discard changes to go back'); },
};
