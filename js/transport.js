/* ==========================================================================
   Vehicles, ships and aircraft: the identifiers they carry, checked and read
   offline.
   VIN (vehicle identification number, ISO 3779), IMO ship number, MMSI (the
   radio identity a ship's AIS transmits), ICAO 24-bit aircraft address
   ("Mode S hex") and aircraft registration ("tail number").
   Nothing here is looked up online: makers, flags and countries come from the
   numbering plans themselves, so a value is understood the moment it is found.
   ========================================================================== */
const TRANSPORT = (() => {
  /* ---------- VIN ---------- */
  const VIN_VAL = {A:1,B:2,C:3,D:4,E:5,F:6,G:7,H:8,J:1,K:2,L:3,M:4,N:5,P:7,R:9,S:2,T:3,U:4,V:5,W:6,X:7,Y:8,Z:9};
  const VIN_W = [8,7,6,5,4,3,2,10,0,9,8,7,6,5,4,3,2];
  const vinShape = v => /^[A-HJ-NPR-Z0-9]{17}$/.test(v) && /[A-Z]/.test(v) && /\d/.test(v) && !/^(.)\1+$/.test(v);
  /* the 9th character is a check digit in North America and China; elsewhere makers may leave it out */
  function vinCheck(v){ let s = 0; for(let i = 0; i < 17; i++){ const c = v[i], n = /\d/.test(c) ? +c : VIN_VAL[c]; s += n * VIN_W[i]; } const r = s % 11; return v[8] === (r === 10 ? 'X' : String(r)); }
  /* read with the Forensics kit's decoder (js/vin.js), so the two never disagree */
  function vinInfo(v){ const V = typeof vinDecode === 'function' ? vinDecode(v) : null;
    if(!V) return {maker:null, wmi:String(v).slice(0, 3), where:null, year:null, check:vinCheck(String(v).toUpperCase()), na:/^[1-5]/.test(v), plant:String(v)[10], serial:String(v).slice(11)};
    return {maker:V.maker || null, wmi:V.wmi, where:V.region || null, year:V.years.length ? V.years.slice().reverse().join(' or ') : null, check:V.check.ok, na:V.na, plant:V.plant, serial:V.serial}; }

  /* ---------- IMO ship number ---------- */
  const imoCheck = n => { n = String(n); if(!/^\d{7}$/.test(n)) return false; let s = 0; for(let i = 0; i < 6; i++) s += +n[i] * (7 - i); return s % 10 === +n[6]; };

  /* ---------- MMSI: the first three digits of a ship's number name the flag (ITU maritime identification digits) ---------- */
  const MID = {};
  ('201 Albania|202 Andorra|203 Austria|204 Portugal (Azores)|205 Belgium|206 Belarus|207 Bulgaria|208 Vatican|209 Cyprus|210 Cyprus|211 Germany|212 Cyprus|213 Georgia|214 Moldova|215 Malta|216 Armenia|218 Germany|219 Denmark|220 Denmark|' +
   '224 Spain|225 Spain|226 France|227 France|228 France|229 Malta|230 Finland|231 Faroe Islands|232 United Kingdom|233 United Kingdom|234 United Kingdom|235 United Kingdom|236 Gibraltar|237 Greece|238 Croatia|239 Greece|240 Greece|241 Greece|' +
   '242 Morocco|243 Hungary|244 Netherlands|245 Netherlands|246 Netherlands|247 Italy|248 Malta|249 Malta|250 Ireland|251 Iceland|252 Liechtenstein|253 Luxembourg|254 Monaco|255 Portugal (Madeira)|256 Malta|257 Norway|258 Norway|259 Norway|' +
   '261 Poland|262 Montenegro|263 Portugal|264 Romania|265 Sweden|266 Sweden|267 Slovakia|268 San Marino|269 Switzerland|270 Czechia|271 Turkey|272 Ukraine|273 Russia|274 North Macedonia|275 Latvia|276 Estonia|277 Lithuania|278 Slovenia|279 Serbia|' +
   '301 Anguilla|303 United States (Alaska)|304 Antigua and Barbuda|305 Antigua and Barbuda|306 Netherlands (Caribbean)|307 Aruba|308 Bahamas|309 Bahamas|310 Bermuda|311 Bahamas|312 Belize|314 Barbados|316 Canada|319 Cayman Islands|321 Costa Rica|' +
   '323 Cuba|325 Dominica|327 Dominican Republic|329 Guadeloupe|330 Grenada|331 Greenland|332 Guatemala|334 Honduras|336 Haiti|338 United States|339 Jamaica|341 Saint Kitts and Nevis|343 Saint Lucia|345 Mexico|347 Martinique|348 Montserrat|' +
   '350 Nicaragua|351 Panama|352 Panama|353 Panama|354 Panama|355 Panama|356 Panama|357 Panama|358 Puerto Rico|359 El Salvador|361 Saint Pierre and Miquelon|362 Trinidad and Tobago|364 Turks and Caicos Islands|366 United States|367 United States|' +
   '368 United States|369 United States|370 Panama|371 Panama|372 Panama|373 Panama|374 Panama|375 Saint Vincent and the Grenadines|376 Saint Vincent and the Grenadines|377 Saint Vincent and the Grenadines|378 British Virgin Islands|379 US Virgin Islands|' +
   '401 Afghanistan|403 Saudi Arabia|405 Bangladesh|408 Bahrain|410 Bhutan|412 China|413 China|414 China|416 Taiwan|417 Sri Lanka|419 India|422 Iran|423 Azerbaijan|425 Iraq|428 Israel|431 Japan|432 Japan|434 Turkmenistan|436 Kazakhstan|437 Uzbekistan|' +
   '438 Jordan|440 South Korea|441 South Korea|443 Palestine|445 North Korea|447 Kuwait|450 Lebanon|451 Kyrgyzstan|453 Macao|455 Maldives|457 Mongolia|459 Nepal|461 Oman|463 Pakistan|466 Qatar|468 Syria|470 United Arab Emirates|471 United Arab Emirates|' +
   '472 Tajikistan|473 Yemen|475 Yemen|477 Hong Kong|478 Bosnia and Herzegovina|501 France (Adélie Land)|503 Australia|506 Myanmar|508 Brunei|510 Micronesia|511 Palau|512 New Zealand|514 Cambodia|515 Cambodia|516 Christmas Island|518 Cook Islands|' +
   '520 Fiji|523 Cocos (Keeling) Islands|525 Indonesia|529 Kiribati|531 Laos|533 Malaysia|536 Northern Mariana Islands|538 Marshall Islands|540 New Caledonia|542 Niue|544 Nauru|546 French Polynesia|548 Philippines|553 Papua New Guinea|555 Pitcairn Islands|' +
   '557 Solomon Islands|559 American Samoa|561 Samoa|563 Singapore|564 Singapore|565 Singapore|566 Singapore|567 Thailand|570 Tonga|572 Tuvalu|574 Vietnam|576 Vanuatu|577 Vanuatu|578 Wallis and Futuna|' +
   '601 South Africa|603 Angola|605 Algeria|607 France (Saint Paul and Amsterdam)|608 United Kingdom (Ascension)|609 Burundi|610 Benin|611 Botswana|612 Central African Republic|613 Cameroon|615 Congo|616 Comoros|617 Cabo Verde|618 France (Crozet)|' +
   '619 Côte d’Ivoire|620 Comoros|621 Djibouti|622 Egypt|624 Ethiopia|625 Eritrea|626 Gabon|627 Ghana|629 Gambia|630 Guinea-Bissau|631 Equatorial Guinea|632 Guinea|633 Burkina Faso|634 Kenya|635 France (Kerguelen)|636 Liberia|637 Liberia|638 South Sudan|' +
   '642 Libya|644 Lesotho|645 Mauritius|647 Madagascar|649 Mali|650 Mozambique|654 Mauritania|655 Malawi|656 Niger|657 Nigeria|659 Namibia|660 Réunion|661 Rwanda|662 Sudan|663 Senegal|664 Seychelles|665 Saint Helena|666 Somalia|667 Sierra Leone|' +
   '668 São Tomé and Príncipe|669 Eswatini|670 Chad|671 Togo|672 Tunisia|674 Tanzania|675 Uganda|676 DR Congo|677 Tanzania|678 Zambia|679 Zimbabwe|701 Argentina|710 Brazil|720 Bolivia|725 Chile|730 Colombia|735 Ecuador|740 Falkland Islands|' +
   '745 French Guiana|750 Guyana|755 Paraguay|760 Peru|765 Suriname|770 Uruguay|775 Venezuela').split('|').forEach(x => { MID[x.slice(0, 3)] = x.slice(4); });
  /* flags that register foreign-owned ships for a fee: the flag says little about who runs the ship */
  const OPEN_REG = new Set(['Panama', 'Liberia', 'Marshall Islands', 'Malta', 'Bahamas', 'Antigua and Barbuda', 'Saint Vincent and the Grenadines', 'Cyprus', 'Belize', 'Comoros', 'Togo', 'Sierra Leone', 'Palau', 'Cook Islands', 'Tuvalu', 'Cameroon', 'Gabon', 'Tanzania', 'Moldova', 'Mongolia', 'Saint Kitts and Nevis', 'Barbados', 'Vanuatu']);
  function mmsiInfo(v){ v = String(v); const r = {kind:'Ship', mid:'', flag:null};
    if(v.startsWith('111')){ r.kind = 'Search-and-rescue aircraft'; r.mid = v.slice(3, 6); }
    else if(v.startsWith('970')) { r.kind = 'AIS search-and-rescue transmitter (SART)'; return r; }
    else if(v.startsWith('972')) { r.kind = 'Man-overboard beacon'; return r; }
    else if(v.startsWith('974')) { r.kind = 'Emergency position beacon (EPIRB-AIS)'; return r; }
    else if(v.startsWith('98')){ r.kind = 'Craft carried by a parent ship (a tender or lifeboat)'; r.mid = v.slice(2, 5); }
    else if(v.startsWith('99')){ r.kind = 'Aid to navigation (a buoy, light or beacon)'; r.mid = v.slice(2, 5); }
    else if(v.startsWith('00')){ r.kind = 'Coast station'; r.mid = v.slice(2, 5); }
    else if(v.startsWith('0')){ r.kind = 'Group call (a fleet or company)'; r.mid = v.slice(1, 4); }
    else if(v.startsWith('8')){ r.kind = 'Handheld radio'; r.mid = v.slice(1, 4); }
    else if(/^[2-7]/.test(v)) r.mid = v.slice(0, 3);
    r.flag = MID[r.mid] || null; r.open = !!(r.flag && OPEN_REG.has(r.flag));
    return r; }

  /* ---------- ICAO 24-bit address: blocks allotted to each state of registry ---------- */
  const ICAO_BLOCKS = [
    ['A00000','AFFFFF','United States'],['C00000','C3FFFF','Canada'],['400000','43FFFF','United Kingdom'],['3C0000','3FFFFF','Germany'],['380000','3BFFFF','France'],['300000','33FFFF','Italy'],['340000','37FFFF','Spain'],
    ['480000','487FFF','Netherlands'],['448000','44FFFF','Belgium'],['4B0000','4B7FFF','Switzerland'],['440000','447FFF','Austria'],['4A8000','4AFFFF','Sweden'],['478000','47FFFF','Norway'],['458000','45FFFF','Denmark'],
    ['460000','467FFF','Finland'],['4CA000','4CAFFF','Ireland'],['490000','497FFF','Portugal'],['468000','46FFFF','Greece'],['488000','48FFFF','Poland'],['4B8000','4BFFFF','Turkey'],['508000','50FFFF','Ukraine'],
    ['100000','1FFFFF','Russia'],['780000','7BFFFF','China'],['840000','87FFFF','Japan'],['718000','71FFFF','South Korea'],['800000','83FFFF','India'],['7C0000','7FFFFF','Australia'],['C80000','C87FFF','New Zealand'],
    ['E40000','E7FFFF','Brazil'],['E00000','E3FFFF','Argentina'],['0D0000','0D7FFF','Mexico'],['008000','00FFFF','South Africa'],['738000','73FFFF','Israel'],['896000','896FFF','United Arab Emirates']].map(([a, b, c]) => [parseInt(a, 16), parseInt(b, 16), c]);
  const icaoCountry = h => { const n = parseInt(h, 16); const b = ICAO_BLOCKS.find(([a, z]) => n >= a && n <= z); return b ? b[2] : null; };

  /* ---------- United States: an N-number and its address are one and the same, by the FAA's numbering ----------
     Every N-number from N1 to N99999 (with up to two letters at the end) is counted in a fixed order from A00001,
     so either one gives the other. */
  const NL = 'ABCDEFGHJKLMNPQRSTUVWXYZ', N_BASE = 0xA00001;
  const N_CHILD = [0, 10111, 951, 35, 1];          // the size of a digit's branch, by how many digits come before it
  const N_HEAD = k => k <= 3 ? 601 : 25;           // the number itself and its letter endings, before its longer numbers
  const nShape = n => /^N[1-9]\d{0,4}$|^N[1-9]\d{0,3}[A-HJ-NP-Z]$|^N[1-9]\d{0,2}[A-HJ-NP-Z]{2}$/.test(n);
  function nToIcao(n){ n = String(n).toUpperCase(); if(!nShape(n)) return null;
    const m = n.slice(1).match(/^(\d+)([A-Z]*)$/), D = m[1], L = m[2];
    let off = N_BASE + (+D[0] - 1) * 101711;
    for(let k = 1; k < D.length; k++) off += N_HEAD(k) + +D[k] * N_CHILD[k];
    const k = D.length;
    if(L) off += k <= 3 ? 25 * NL.indexOf(L[0]) + 1 + (L[1] ? NL.indexOf(L[1]) + 1 : 0) : NL.indexOf(L[0]) + 1;
    return off.toString(16); }
  function icaoToN(h){ let v = parseInt(h, 16) - N_BASE; if(!(v >= 0 && v < 9 * 101711)) return null;
    let out = 'N' + (Math.floor(v / 101711) + 1); v %= 101711; let k = 1;
    while(v > 0){
      const head = k < 5 ? N_HEAD(k) : 1;
      if(v < head){ if(k <= 3){ v -= 1; out += NL[Math.floor(v / 25)]; const r = v % 25; if(r) out += NL[r - 1]; } else out += NL[v - 1]; return out; }
      if(k >= 5) return null;
      v -= head; out += Math.floor(v / N_CHILD[k]); v %= N_CHILD[k]; k++; }
    return out; }

  /* ---------- aircraft registration: the prefix is the state of registry ---------- */
  const REG = {N:'United States', C:'Canada', G:'United Kingdom', D:'Germany', F:'France', I:'Italy', EC:'Spain', PH:'Netherlands', OO:'Belgium', HB:'Switzerland', OE:'Austria', SE:'Sweden', LN:'Norway', OY:'Denmark', OH:'Finland',
    EI:'Ireland', CS:'Portugal', SX:'Greece', SP:'Poland', OK:'Czechia', OM:'Slovakia', HA:'Hungary', YR:'Romania', LZ:'Bulgaria', '9A':'Croatia', S5:'Slovenia', YL:'Latvia', ES:'Estonia', LY:'Lithuania', LX:'Luxembourg', TF:'Iceland',
    '9H':'Malta', TC:'Turkey', RA:'Russia', UR:'Ukraine', EW:'Belarus', ER:'Moldova', '4L':'Georgia', EK:'Armenia', '4K':'Azerbaijan', UP:'Kazakhstan', YU:'Serbia', Z3:'North Macedonia', ZA:'Albania', '4O':'Montenegro', E7:'Bosnia and Herzegovina',
    T7:'San Marino', '3A':'Monaco', M:'Isle of Man', B:'China, Taiwan, Hong Kong or Macao', JA:'Japan', HL:'South Korea', VT:'India', VH:'Australia', ZK:'New Zealand', PP:'Brazil', PR:'Brazil', PT:'Brazil', PS:'Brazil', PU:'Brazil',
    LV:'Argentina', XA:'Mexico', XB:'Mexico', XC:'Mexico', ZS:'South Africa', '4X':'Israel', A6:'United Arab Emirates', A7:'Qatar', A9C:'Bahrain', '9K':'Kuwait', A4O:'Oman', HZ:'Saudi Arabia', '9V':'Singapore', '9M':'Malaysia',
    PK:'Indonesia', HS:'Thailand', RP:'Philippines', SU:'Egypt', EP:'Iran', AP:'Pakistan', CC:'Chile', HK:'Colombia', OB:'Peru', YV:'Venezuela', '5Y':'Kenya', '5N':'Nigeria', ET:'Ethiopia', CN:'Morocco', '7T':'Algeria', TS:'Tunisia',
    VPB:'Bermuda', VQB:'Bermuda', VPC:'Cayman Islands', '2':'Guernsey'};
  const NO_DASH = /^(N|JA|HL)/;
  function tailPrefix(t){ t = String(t).toUpperCase();
    if(/^N\d/.test(t)) return 'N';
    if(/^JA[0-9A-Z]{4}$/.test(t)) return 'JA'; if(/^HL\d{4}$/.test(t)) return 'HL';
    const i = t.indexOf('-'); if(i < 1) return null; const p = t.slice(0, i);
    if(p === 'VP' || p === 'VQ') return REG[p + t[i + 1]] ? p + t[i + 1] : null;
    return REG[p] ? p : null; }
  /* a registration as written on the airframe: N, JA and HL marks carry no dash, the rest put one after the prefix */
  function tailOK(t){ t = String(t).toUpperCase(); const p = tailPrefix(t); if(!p) return false;
    if(p === 'N') return nShape(t);
    if(p === 'JA' || p === 'HL') return true;
    const rest = t.slice(t.indexOf('-') + 1); return /^[A-Z0-9]{1,5}$/.test(rest) && (p === 'B' ? /^\d{4,5}$|^[A-Z]{3}$|^[HLMK][A-Z]{2}$/.test(rest) : /[A-Z]/.test(rest)); }
  const tailCountry = t => { const p = tailPrefix(t); return p ? REG[p] : null; };

  return {vinShape, vinCheck, vinInfo, imoCheck, mmsiInfo, icaoCountry, nToIcao, icaoToN, nShape, tailOK, tailCountry, NO_DASH};
})();
