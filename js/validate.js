/* ==========================================================================
   Input checks shared by every form.
   - fieldErr() shows a message under the field (not a toast), marks it for
     screen readers and clears itself as soon as the field is edited.
   - clash() finds another item with the same name (case and spacing ignored).
   - copyName() / nextName() give copies and new items distinct names:
     “Report (copy)”, “Report (copy 2)”, “New challenge 3”.
   - softDup() warns once about a likely duplicate; saving again goes ahead.
   ========================================================================== */
const normName = s => String(s == null ? '' : s).normalize('NFKC').trim().replace(/\s+/g, ' ').toLowerCase();
function clash(list, name, key = 'name', selfId){
  const n = normName(name); if(!n) return null;
  return (list || []).find(x => x && x.id !== selfId && normName(typeof key === 'function' ? key(x) : x[key]) === n) || null;
}
function copyName(name, taken){
  const base = String(name || 'Untitled').trim().replace(/\s*\(copy(?: \d+)?\)$/i, '').trim() || 'Untitled', set = new Set([...taken].map(normName));
  let c = base + ' (copy)'; for(let i = 2; set.has(normName(c)); i++) c = `${base} (copy ${i})`; return c;
}
function nextName(base, taken){ const set = new Set([...taken].map(normName)); if(!set.has(normName(base))) return base; for(let i = 2; ; i++){ const c = `${base} ${i}`; if(!set.has(normName(c))) return c; } }
function fieldErr(id, msg){
  const el = typeof id === 'string' ? $(id) : id; if(!el){ toast(msg); return false; }
  const wrap = el.closest('.field') || el.parentElement; let p = [...wrap.children].find(x => x.classList && x.classList.contains('ferr'));
  if(!p){ p = document.createElement('p'); p.className = 'ferr'; p.id = (el.id || 'f' + Math.random().toString(36).slice(2, 8)) + '-err'; p.setAttribute('role', 'alert'); wrap.appendChild(p); }
  p.textContent = msg; el.classList.add('invalid'); el.setAttribute('aria-invalid', 'true'); el.setAttribute('aria-describedby', p.id);
  try{ el.focus({preventScroll:false}); if(el.select && el.type !== 'checkbox' && el.tagName !== 'SELECT') el.select(); }catch(e){}
  const clear = () => { el.classList.remove('invalid'); el.removeAttribute('aria-invalid'); el.removeAttribute('aria-describedby'); p.remove(); el.removeEventListener('input', clear); el.removeEventListener('change', clear); const f = el.closest('form'); if(f) delete f.dataset.dupOk; };
  el.addEventListener('input', clear); el.addEventListener('change', clear);
  return false;
}
function softDup(form, key, id, msg){ if(form.dataset.dupOk === key) return true; fieldErr(id, msg + ' Press Save again to keep both.'); form.dataset.dupOk = key; return false; }

/* value checks: return an error message, or '' when fine */
const RE_EMAIL = /^[^\s@<>()[\]\\,;:"]+@(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const RE_DOMAIN = /^(?=.{1,253}$)(?:\*\.)?(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})\.?$/i;
const isIPv4 = v => /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/.test(v);
const isIPv6 = v => { if(!/^[0-9a-f:.]+$/i.test(v) || !v.includes(':')) return false; try{ new URL('http://[' + v + ']/'); return true; }catch(e){ return false; } };
const CHECK = {
  email:v => RE_EMAIL.test(v) ? '' : 'Enter an email address like name@example.com.',
  domain:v => RE_DOMAIN.test(v.replace(/^https?:\/\//i, '').replace(/\/.*$/, '')) ? '' : 'Enter a domain like example.com — no spaces.',
  ip:v => isIPv4(v) || isIPv6(v) || /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(v) ? '' : 'Enter an IPv4 or IPv6 address, e.g. 203.0.113.7.',
  url:v => E.safeUrl(v) || /^[a-z2-7]{16,56}\.onion(\/|$)/i.test(v) ? '' : 'Enter a full address starting with http:// or https://.',
  mac:v => /^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$|^[0-9a-f]{12}$|^([0-9a-f]{4}\.){2}[0-9a-f]{4}$/i.test(v) ? '' : 'Enter a MAC address like 3c:22:fb:11:22:33.',
  phone:v => /^\+?[\d\s().\-\/]{5,24}$/.test(v) && (v.match(/\d/g) || []).length >= 5 ? '' : 'Enter a phone number with digits, e.g. +47 912 34 567.',
  cve:v => /^CVE-\d{4}-\d{4,}$/i.test(v) ? '' : 'Enter a CVE like CVE-2024-3400.',
  cvss:v => isFinite(+v) && +v >= 0 && +v <= 10 ? '' : 'CVSS is a number from 0 to 10.',
  hash:v => /^([a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})$/i.test(v) ? '' : 'Enter an MD5, SHA-1, SHA-256 or SHA-512 hash (hex).',
  coords:v => { const m = v.match(/^\s*(-?\d+(?:\.\d+)?)\s*[,; ]\s*(-?\d+(?:\.\d+)?)\s*$/); return m && Math.abs(+m[1]) <= 90 && Math.abs(+m[2]) <= 180 ? '' : 'Enter latitude, longitude — e.g. 60.3929, 5.3241.'; },
  date:v => /^\d{4}(-\d{2}(-\d{2})?)?([ T]\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})?)?$/.test(v) && !isNaN(Date.parse(v.length === 4 ? v + '-01-01' : v.length === 7 ? v + '-01' : v)) ? '' : 'Use a date like 2026-09-21 (year-month-day).',
  count:v => /^[\d\s.,]+[kmb]?\+?$/i.test(v) ? '' : 'Enter a number, e.g. 1200 or 1.2k.'
};
/* vault field key → check */
const FIELD_CHECK = {email:'email', domain:'domain', ip:'ip', url:'url', website:'url', mac:'mac', number:'phone', phone:'phone', cve:'cve', cvss:'cvss', hash:'hash', coordinates:'coords', date:'date', created:'date', dob:'date', firstSeen:'date', followers:'count', members:'count', records:'count'};
const LIMITS = {name:120, title:160, short:300, desc:2000, body:20000};
function checkLen(id, v, n, label){ return v.length > n ? fieldErr(id, `${label} is too long — ${v.length} characters, the limit is ${n}.`) : true; }
function checkRegex(id, re, flags){ try{ new RegExp(re, flags); return true; }catch(e){ return fieldErr(id, 'This regular expression has an error: ' + String(e.message).replace(/^Invalid regular expression: /, '')); } }
function nextCaseCode(){
  const y = new Date().getFullYear(), pre = 'TN-' + y + '-', used = new Set(DB.cases.map(c => c.code));
  let n = Math.max(0, ...DB.cases.map(c => (c.code || '').startsWith(pre) ? parseInt(c.code.slice(pre.length), 10) || 0 : 0)) + 1;
  while(used.has(pre + String(n).padStart(3, '0'))) n++; return pre + String(n).padStart(3, '0');
}
/* the browser's own checks (required, type=url, pattern, maxlength) speak through the same inline message */
const fieldLabel = el => { const l = el.id && document.querySelector(`label[for="${CSS.escape(el.id)}"]`); return l ? l.childNodes[0].textContent.trim().replace(/[:*]$/, '') : (el.getAttribute('aria-label') || el.placeholder || 'This field'); };
let INVALID_AT = 0;
document.addEventListener('invalid', ev => {
  ev.preventDefault(); const el = ev.target; if(Date.now() - INVALID_AT < 60) return; INVALID_AT = Date.now();
  const v = el.validity, name = fieldLabel(el);
  fieldErr(el, v.valueMissing ? `${name} is required.` : v.typeMismatch && el.type === 'url' || v.patternMismatch && /https\?/.test(el.pattern || '') ? `${name} must start with http:// or https://.` : v.typeMismatch && el.type === 'email' ? 'Enter an email address like name@example.com.' : v.tooLong ? `${name} is too long.` : v.rangeOverflow || v.rangeUnderflow ? `${name} must be between ${el.min || '…'} and ${el.max || '…'}.` : el.title || el.validationMessage);
}, true);
/* imports: keep the incoming name unless it is taken, then mark it */
function importName(name, taken){ const n = String(name || '').trim().replace(/\s+/g, ' '); const list = [...taken]; return list.some(x => normName(x) === normName(n)) ? nextName(n + ' (imported)', list) : n; }
