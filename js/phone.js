/* ==========================================================================
   Phone numbers, offline — from the public numbering plans (Google's
   libphonenumber data, loaded only when a number is looked at):
   · the country, and whether the number is mobile, landline, VoIP, toll-free,
     premium rate, a personal "follow-me" number or a pager
   · whether it is a valid number in that country's plan at all (a mistyped
     or invented number usually is not), and ranges set aside for films and TV
   · one standard form (E.164), so +44 7700 900123, 07700 900123 and
     0044-7700-900-123 are seen as the same number across cases
   Numbers written without a country code are read with the country you set.
   Nothing is looked up: no carrier, no owner — only what the plan says.
   ========================================================================== */
const PH_TYPE = {MOBILE:['Mobile', ''], FIXED_LINE:['Landline', ''], FIXED_LINE_OR_MOBILE:['Landline or mobile', 'The plan does not tell them apart in this country'], TOLL_FREE:['Toll-free', 'A business or service line'],
  PREMIUM_RATE:['Premium rate', 'Expensive to call — a common scam ending'], SHARED_COST:['Shared cost', ''], VOIP:['VoIP', 'An internet number — often from an app or a virtual-number service, cheap and easy to throw away'],
  PERSONAL_NUMBER:['Personal (follow-me) number', 'Forwards to any phone the owner chooses — hides the real line'], PAGER:['Pager', ''], UAN:['Company number (UAN)', ''], VOICEMAIL:['Voicemail access', '']};
/* numbers set aside for drama and examples: they are never real lines */
const PH_FICTION = [[/^\+447700900\d{3}$/, 'UK drama range (07700 900000–900999)'], [/^\+44(20)?79460\d{3}$/, 'UK drama range (020 7946 0000–0999)'], [/^\+44(113|114|115|116|117|118|121|131|141|151|161|191)4960\d{3}$/, 'UK drama range (01xx 496 0000–0999)'],
  [/^\+44(28)?90180\d{3}$/, 'UK drama range (028 9018 0000–0999)'], [/^\+441632960\d{3}$/, 'UK drama range (01632 960000–960999)'], [/^\+44808157\d{4}$/, 'UK drama range (0808 157 0000–0999)'], [/^\+44909879\d{4}$/, 'UK drama range (0909 879 0000–0999)'],
  [/^\+1\d{3}5550(1\d{2})$/, 'North American fictional range (555-0100 to 555-0199)'], [/^\+61(2|3|7|8)?55501\d{3}$|^\+614917\d{5}$/, 'Australian fictional range'], [/^\+33(1|2|3|4|5)99\d{6}$/, 'French range for fiction (01 99 00 xx xx …)']];
const phCountry = cc => { try{ return new Intl.DisplayNames(['en'], {type:'region'}).of(cc); }catch(e){ return cc; } };
function phoneDefault(){ const c = DB && typeof DB.phoneCC === 'string' ? DB.phoneCC.toUpperCase() : ''; return /^[A-Z]{2}$/.test(c) ? c : ''; }
/* what the plan says about a number; null until the plan data has arrived (it is fetched on first use) */
function phoneInfo(v, cc){
  if(typeof lzHas === 'function' && !lzHas('phone')){ if(typeof lazyNeed === 'function') lazyNeed('phone').then(ok => { if(ok){ PH_C.clear(); const a = document.activeElement; if(!(a && a.matches && a.matches('input, textarea, select'))) renderAll(); } }); return null; }
  if(typeof libphonenumber === 'undefined') return null;
  const raw = String(v || '').trim(), dc = cc === undefined ? phoneDefault() : cc, key = raw + '|' + dc; if(PH_C.has(key)) return PH_C.get(key);
  let s = raw.replace(/^tel:/i, '').replace(/^\s*00(?=[1-9])/, '+').replace(/^\s*\+\s*/, '+'); const intl = s.startsWith('+');
  let p = null; try{ p = libphonenumber.parsePhoneNumberFromString(s, intl ? undefined : dc || undefined); }catch(e){}
  let out;
  if(!p) out = {ok:false, why:(s.match(/\d/g) || []).length < 5 ? 'Not a phone number in any plan' : !intl && !dc ? 'No country code — set the country for numbers written without one' : 'Not a phone number in any plan'};
  else { const e164 = p.number, ty = p.isValid() ? p.getType() : undefined, fic = PH_FICTION.find(([re]) => re.test(e164));
    /* an invalid number still has a country code: name the country it belongs to (the main one, for shared codes like +1 and +7) */
    if(!p.country){ const all = libphonenumber.getCountries().filter(c => libphonenumber.getCountryCallingCode(c) === p.countryCallingCode); const main = all.find(c => ({'1':'US', '7':'RU', '44':'GB', '39':'IT', '47':'NO', '61':'AU', '212':'MA', '262':'RE', '290':'SH', '358':'FI', '590':'GP', '599':'CW'})[p.countryCallingCode] === c) || (all.length === 1 ? all[0] : '');
      if(main) p = Object.assign(Object.create(Object.getPrototypeOf(p)), p, {country:main}); }
    out = {ok:true, e164, valid:p.isValid(), possible:p.isPossible(), cc:p.country || '', country:p.country ? phCountry(p.country) : (p.countryCallingCode === '800' || p.countryCallingCode === '808' || p.countryCallingCode === '870' || p.countryCallingCode === '881' || p.countryCallingCode === '882' || p.countryCallingCode === '883' ? 'International (no country)' : ''),
      code:'+' + p.countryCallingCode, type:ty || '', typeLabel:ty && PH_TYPE[ty] ? PH_TYPE[ty][0] : '', typeNote:ty && PH_TYPE[ty] ? PH_TYPE[ty][1] : '', intlFmt:p.formatInternational(), natFmt:p.formatNational(), assumed:!intl ? dc : '', fiction:fic ? fic[1] : ''}; }
  if(PH_C.size > 5000) PH_C.clear(); PH_C.set(key, out); return out;
}
const PH_C = new Map();
/* the same number written another way, here and in other cases */
function phoneSame(v){
  const me = phoneInfo(v); if(!me || !me.ok) return []; const out = [], seen = new Set();
  for(const [id, g] of typeof globalEnts === 'function' ? globalEnts() : []){ if(!/^phone[|:]/.test(id)) continue; const val = id.replace(/^phone[|:]/, ''); if(val === String(v) || seen.has(val)) continue;
    const o = phoneInfo(val); if(o && o.ok && o.e164 === me.e164){ seen.add(val); out.push({id, v:val, cases:[...g.cases]}); } }
  return out;
}
function phoneSection(v){
  const I = phoneInfo(v);
  if(!I) return `<div class="isec"><h4>The number</h4><p class="t3 small" style="margin:0">Reading the numbering plans…</p></div>`;
  const dc = phoneDefault(), sel = `<label class="ph-dc"><span class="t3 small">Numbers without a country code are read as</span><select data-ph="cc"><option value="">— no country set —</option>${(typeof libphonenumber !== 'undefined' ? libphonenumber.getCountries() : []).map(c => [c, phCountry(c)]).sort((a, b) => a[1].localeCompare(b[1])).map(([c, n]) => `<option value="${c}"${c === dc ? ' selected' : ''}>${esc(n)} (+${libphonenumber.getCountryCallingCode(c)})</option>`).join('')}</select></label>`;
  if(!I.ok) return `<div class="isec"><h4>The number</h4><p class="t2 small" style="margin:0 0 8px">${esc(I.why)}.</p>${sel}</div>`;
  const same = phoneSame(v), flags = [];
  if(I.fiction) flags.push(['red', 'Not a real line: ' + I.fiction]);
  if(!I.valid) flags.push(['amber', I.possible ? `Not a valid number in ${I.country || 'its'} plan — mistyped, invented, or a range not yet in use` : 'Too short or too long for its country — mistyped or invented']);
  if(I.type === 'VOIP' || I.type === 'PERSONAL_NUMBER' || I.type === 'PREMIUM_RATE') flags.push(['amber', I.typeLabel + ' — ' + I.typeNote]);
  return `<div class="isec ph"><h4>The number</h4>${flags.length ? `<div class="wrap" style="margin-bottom:8px">${flags.map(([t, x]) => `<span class="chip sq ${t}">${esc(x)}</span>`).join('')}</div>` : ''}
    <dl class="kv"><dt>Country</dt><dd>${esc(I.country || '—')} <span class="t3">${esc(I.code)}</span>${I.assumed ? ` <span class="t3">(read as ${esc(phCountry(I.assumed))}: written without a country code)</span>` : ''}</dd>
      <dt>Kind</dt><dd>${esc(I.typeLabel || (I.valid ? 'Not stated by the plan' : '—'))}${I.typeNote && !flags.some(f => f[1].startsWith(I.typeLabel)) ? `<div class="t3 small">${esc(I.typeNote)}</div>` : ''}</dd>
      <dt>Standard form</dt><dd class="mono">${esc(I.e164)} <button class="iconbtn sm" data-act="phCopy" data-v="${esc(I.e164)}" aria-label="Copy ${esc(I.e164)}">${ico('copy','sm')}</button></dd>
      <dt>Written as</dt><dd class="mono">${esc(I.intlFmt)}<div class="t3 small">${esc(I.natFmt)} inside ${esc(I.country || 'the country')}</div></dd></dl>
    ${same.length ? `<div class="note amber" style="margin-top:8px"><span class="ic">${ico('link-2','sm')}</span><div><b>The same number, written differently:</b> ${same.slice(0, 6).map(x => `<button class="lnk mono" data-act="phEnt" data-id="${esc(x.id)}">${esc(x.v)}</button> <span class="t3">${x.cases.map(id => (theCase(id) || {}).code).filter(Boolean).join(', ')}</span>`).join('; ')}</div></div>` : ''}
    <p class="t3 small" style="margin:8px 0 6px">From the public numbering plans, in this browser. The plan does not tell you who owns the number or which carrier it is with now — numbers move between carriers.</p>${sel}</div>`;
}
document.addEventListener('change', ev => { const el = ev.target; if(!el || !el.dataset || el.dataset.ph !== 'cc') return; DB.phoneCC = /^[A-Z]{2}$/.test(el.value) ? el.value : ''; PH_C.clear(); mutate('set the country for numbers without a code: ' + (el.value || 'none')); renderAll(); });
const PH_ACTS = {
  phCopy:(id, v) => copyText(v),
  phEnt:id => { if(typeof clickAct === 'function') clickAct('selEnt', id); },
};
